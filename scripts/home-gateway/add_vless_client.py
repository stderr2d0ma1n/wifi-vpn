#!/usr/bin/env python3
"""Add a separate device to the prepared VPS; credentials stay on that server."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.parse
import uuid


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as target:
        target.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('name')
    parser.add_argument('--directory', type=Path, default=Path('/etc/home-vps'))
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', args.name):
        parser.error('Run as root with a simple device name')
    directory = args.directory.resolve()
    if any((p / '.git').exists() for p in (directory, *directory.parents)):
        parser.error('Credentials must stay outside Git')
    server_path = directory / 'server.json'
    original = server_path.read_bytes()
    server = json.loads(original)
    users = server['inbounds'][0]['users']
    if any(user['name'] == args.name for user in users):
        raise SystemExit('Device already exists; inspect its private profile instead of replacing it')
    identity = str(uuid.uuid4())
    users.append({'name': args.name, 'uuid': identity, 'flow': 'xtls-rprx-vision'})
    outbound = json.loads((directory / 'vps-outbound.json').read_text())
    outbound['uuid'] = identity
    tls = outbound['tls']
    query = urllib.parse.urlencode({
        'encryption': 'none', 'security': 'reality', 'sni': tls['server_name'],
        'fp': 'chrome', 'pbk': tls['reality']['public_key'],
        'sid': tls['reality']['short_id'], 'type': 'tcp',
        'flow': outbound['flow'], 'packetEncoding': 'xudp',
    })
    uri = 'vless://{}@{}:{}?{}#{}'.format(identity, outbound['server'],
        outbound['server_port'], query, urllib.parse.quote('Home-NL-' + args.name))
    clients = directory / 'clients'
    clients.mkdir(mode=0o700, exist_ok=True)
    profile = clients / (args.name + '.json')
    link = clients / (args.name + '.txt')
    if profile.exists() or link.exists():
        raise SystemExit('Existing profile needs review')
    fd, candidate = tempfile.mkstemp(prefix='.server-candidate-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as target:
            json.dump(server, target, indent=2)
            target.write('\n')
        checked = subprocess.run(['sing-box', 'check', '-c', candidate], capture_output=True)
        if checked.returncode:
            raise SystemExit('Configuration check failed; private output suppressed')
        private_write(profile, json.dumps(outbound, indent=2) + '\n')
        private_write(link, uri + '\n')
        private_write(clients / ('server-before-' + args.name + '.json'), original.decode())
        status = server_path.stat()
        os.chown(candidate, status.st_uid, status.st_gid)
        os.chmod(candidate, status.st_mode & 0o777)
        os.replace(candidate, server_path)
        try:
            subprocess.run(['systemctl', 'restart', 'home-vps.service'], check=True)
            time.sleep(1)
            subprocess.run(['systemctl', 'is-active', '--quiet', 'home-vps.service'], check=True)
        except Exception:
            server_path.write_bytes(original)
            subprocess.run(['systemctl', 'restart', 'home-vps.service'], check=True)
            raise
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)
    print('Added separate device; private import link: ' + str(link))


if __name__ == '__main__':
    main()
