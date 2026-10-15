#!/usr/bin/env python3
"""Prepare a private Armbian image with SSH access; never flashes a device."""
import argparse
import hashlib
import json
import re
import secrets
import shutil
import struct
import subprocess
from pathlib import Path


def debugfs(executable, image, command, write=False):
    args = [str(executable)] + (['-w'] if write else []) + ['-R', command, str(image)]
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout


def quoted(path):
    value = str(path.resolve())
    if any(char in value for char in '\n\r"\\'):
        raise ValueError('Unsupported filesystem path')
    return '"' + value + '"'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--debugfs', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--usb-access', action='store_true',
                        help='Enable a local CDC-ECM USB SSH management link')
    args = parser.parse_args()
    directory = args.work_dir.resolve()
    if directory.exists():
        raise SystemExit('Use a new private work directory; previous images are preserved')
    if any((parent / '.git').exists() for parent in [directory] + list(directory.parents)):
        raise SystemExit('Personalized images contain temporary passwords: keep them outside Git')
    key = args.public_key.read_text().strip()
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?', key):
        raise SystemExit('Expected an Ed25519 public key')
    with args.image.open('rb') as source:
        sector = source.read(512)
    if sector[510:512] != b'\x55\xaa':
        raise SystemExit('Expected a checked MBR image')
    partitions = []
    for index in range(4):
        entry = sector[446 + index * 16:462 + index * 16]
        kind, start, count = entry[4], *struct.unpack('<II', entry[8:16])
        if count:
            partitions.append((kind, start * 512, count * 512))
    if len(partitions) != 1 or partitions[0][0] != 0x83:
        raise SystemExit('Unexpected image partition layout')
    _, offset, size = partitions[0]
    if offset + size != args.image.stat().st_size:
        raise SystemExit('Image boundaries do not match the expected layout')
    directory.mkdir(mode=0o700, parents=True)
    filesystem = directory / 'rootfs.img'
    with args.image.open('rb') as source, filesystem.open('xb') as destination:
        source.seek(offset)
        remaining = size
        while remaining:
            chunk = source.read(min(4 * 1024 * 1024, remaining))
            if not chunk:
                raise SystemExit('Truncated input image')
            destination.write(chunk)
            remaining -= len(chunk)
    filesystem.chmod(0o600)
    release = debugfs(args.debugfs, filesystem, 'cat /etc/armbian-release')
    if 'BOARD=orangepi4-lts' not in release and 'BOARD="orangepi4-lts"' not in release:
        raise SystemExit('Image is not for Orange Pi 4 LTS')
    root_password, user_password = secrets.token_hex(24), secrets.token_hex(24)
    presets = '\n'.join([
        'PRESET_NET_CHANGE_DEFAULTS="0"',
        'PRESET_CONNECT_WIRELESS="n"',
        'SET_LANG_BASED_ON_LOCATION="n"',
        'PRESET_LOCALE="en_US.UTF-8"',
        'PRESET_TIMEZONE="Europe/Moscow"',
        'PRESET_ROOT_PASSWORD="' + root_password + '"',
        'PRESET_USER_NAME="gateway"',
        'PRESET_USER_PASSWORD="' + user_password + '"',
        'PRESET_DEFAULT_REALNAME="Home Gateway"',
        'PRESET_USER_SHELL="bash"',
        '',
    ])
    preset_file = directory / 'firstboot-presets'
    preset_file.write_text(presets)
    preset_file.chmod(0o600)
    password_file = directory / 'initial-passwords.txt'
    password_file.write_text('root: ' + root_password + '\ngateway: ' + user_password + '\n')
    password_file.chmod(0o600)
    public_key_file = directory / 'home-gateway-ssh.pub'
    public_key_file.write_text(key + '\n')
    ssh_config = directory / 'ssh-key-access.conf'
    ssh_config.write_text('PubkeyAuthentication yes\nPasswordAuthentication no\n'
                          'KbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n')
    bootstrap = Path(__file__).with_name('bootstrap_board.sh').resolve()
    commands = [
        'mkdir /root/.ssh',
        'set_inode_field /root/.ssh mode 040700',
        'rm /root/.not_logged_in_yet',
        'write ' + quoted(preset_file) + ' /root/.not_logged_in_yet',
        'set_inode_field /root/.not_logged_in_yet mode 0100600',
        'write ' + quoted(public_key_file) + ' /root/home-gateway-ssh.pub',
        'write ' + quoted(public_key_file) + ' /root/.ssh/authorized_keys',
        'set_inode_field /root/.ssh/authorized_keys mode 0100600',
        'write ' + quoted(ssh_config) + ' /etc/ssh/sshd_config.d/00-home-gateway.conf',
        'write ' + quoted(bootstrap) + ' /root/provisioning.sh',
        'set_inode_field /root/provisioning.sh mode 0100700',
    ]
    for command in commands:
        debugfs(args.debugfs, filesystem, command, write=True)
    if args.usb_access:
        config = debugfs(args.debugfs, filesystem,
                         'cat /boot/config-6.18.44-current-rockchip64')
        if 'CONFIG_USB_CONFIGFS_ECM=y' not in config:
            raise SystemExit('Image kernel has not been checked for CDC-ECM support')
        sources = Path(__file__).parent
        for command in [
            'write ' + quoted(sources / 'usb_access.sh') + ' /usr/local/sbin/home-gateway-usb',
            'set_inode_field /usr/local/sbin/home-gateway-usb mode 0100755',
            'write ' + quoted(sources / 'home-gateway-usb.service') +
            ' /etc/systemd/system/home-gateway-usb.service',
            'write ' + quoted(sources / 'home-gateway-usb.network') +
            ' /etc/systemd/network/10-home-gateway-usb.network',
            'symlink /etc/systemd/system/multi-user.target.wants/home-gateway-usb.service'
            ' /etc/systemd/system/home-gateway-usb.service',
        ]:
            debugfs(args.debugfs, filesystem, command, write=True)
        installed = debugfs(args.debugfs, filesystem, 'cat /usr/local/sbin/home-gateway-usb')
        if installed != (sources / 'usb_access.sh').read_text():
            raise SystemExit('USB service installation verification failed')
    if debugfs(args.debugfs, filesystem, 'cat /root/.ssh/authorized_keys').strip() != key:
        raise SystemExit('Public-key verification failed')
    if debugfs(args.debugfs, filesystem, 'cat /root/.not_logged_in_yet') != presets:
        raise SystemExit('First-boot preset verification failed')
    if 'PasswordAuthentication no' not in debugfs(args.debugfs, filesystem,
                                                 'cat /etc/ssh/sshd_config.d/00-home-gateway.conf'):
        raise SystemExit('SSH config verification failed')
    image = directory / 'orangepi4-lts-personalized.img'
    shutil.copyfile(args.image, image)
    image.chmod(0o600)
    with image.open('r+b') as destination, filesystem.open('rb') as source:
        destination.seek(offset)
        shutil.copyfileobj(source, destination, 4 * 1024 * 1024)
    digest = hashlib.sha256()
    with image.open('rb') as source:
        for chunk in iter(lambda: source.read(4 * 1024 * 1024), b''):
            digest.update(chunk)
    metadata = {'image': str(image), 'sha256': digest.hexdigest(),
                'bytes': image.stat().st_size, 'source_image': str(args.image.resolve()),
                'board': 'Orange Pi 4 LTS', 'ssh_user': 'root', 'normal_user': 'gateway',
                'hostname': 'home-gateway', 'credentials_file': str(password_file),
                'usb_access': args.usb_access,
                'flashed': False}
    (directory / 'image-metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print('Private image prepared and seed files checked; no flash command executed')
    print('Image:', image)
    print('SHA256:', metadata['sha256'])


if __name__ == '__main__':
    main()
