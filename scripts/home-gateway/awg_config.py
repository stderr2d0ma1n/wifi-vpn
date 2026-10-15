#!/usr/bin/env python3
"""Generate AWG 3.1 server, isolated probe and iPhone credentials on the VPS."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess


def key(command):
    return subprocess.run(['awg', command], check=True, capture_output=True, text=True).stdout.strip()


def public(private):
    return subprocess.run(['awg', 'pubkey'], input=private + '\n', check=True,
                          capture_output=True, text=True).stdout.strip()


def write(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as target:
        target.write(value)


def section(name, values):
    return '[' + name + ']\n' + ''.join(str(k) + ' = ' + str(v) + '\n' for k, v in values.items()) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-ip', required=True)
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not ipaddress.IPv4Address(args.server_ip).is_global or not 1 <= args.port <= 65535:
        parser.error('Run as root with the verified public server IPv4 and UDP port')
    destination = args.output.resolve()
    if any((p / '.git').exists() for p in (destination, *destination.parents)):
        parser.error('Credentials must stay outside Git')
    destination.mkdir(mode=0o700, exist_ok=False)
    # AWG 3.1 defaults follow the official amnezia-client 5.0.3.0 constants.
    protection = {
        'S1': 12 + secrets.randbelow(139), 'S2': 12 + secrets.randbelow(139),
        'S3': 12 + secrets.randbelow(53), 'S4': 12,
        'HeaderProtectionKey': key('genkey'), 'ContentPaddingAddition': '10-100',
        'RekeyAfterTime': '100-120', 'RekeyTimeout': '3-7',
        'RejectAfterTime': '150-180', 'KeepaliveTimeout': '5-15',
        'MaxHandshakeAttempts': '15-20', 'RandomTrailers': 'on', 'DisableCookies': 'on',
    }
    for n in range(4):
        start = n * 1000000000 + 1000000 + secrets.randbelow(800000000)
        protection['H' + str(n + 1)] = str(start) + '-' + str(start + 50000 + secrets.randbelow(50000))
    # Different padded handshake message sizes avoid simple packet-size signatures.
    while len({148 + protection['S1'], 92 + protection['S2'], 64 + protection['S3'], 32 + protection['S4']}) != 4:
        protection['S1'] = 12 + secrets.randbelow(139)
        protection['S2'] = 12 + secrets.randbelow(139)
        protection['S3'] = 12 + secrets.randbelow(53)
    server_private = key('genkey')
    server_public = public(server_private)
    server = section('Interface', dict(PrivateKey=server_private, ListenPort=args.port, **protection))
    clients = {}
    for name, address in [('orange', '10.77.66.2'), ('iphone', '10.77.66.3')]:
        private, preshared = key('genkey'), key('genpsk')
        server += section('Peer', {'PublicKey': public(private), 'PresharedKey': preshared,
                                   'AllowedIPs': address + '/32'})
        parameters = dict(PrivateKey=private, **protection)
        parameters.update(Jc=3, Jmin=10, Jmax=30,
                          I1='<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>')
        peer = {'PublicKey': server_public, 'PresharedKey': preshared,
                'AllowedIPs': '0.0.0.0/0, ::/0', 'Endpoint': args.server_ip + ':' + str(args.port),
                'PersistentKeepalive': '25-35'}
        device_parameters = dict(parameters)
        if name == 'orange':
            # Exclude the underlying UDP socket from the existing sing-box TUN.
            device_parameters['FwMark'] = '0x2024'
        device = section('Interface', device_parameters) + section('Peer', peer)
        native = section('Interface', dict(Address=address + '/32', DNS='1.1.1.1, 1.0.0.1',
                                          MTU=1280, **parameters)) + section('Peer', peer)
        write(destination / (name + '-device.conf'), device)
        write(destination / (name + '.conf'), native)
        clients[name] = {'address': address, 'public_key': public(private)}
    write(destination / 'server-device.conf', server)
    write(destination / 'network.json', json.dumps({'server_address': '10.77.66.1/24',
          'subnet': '10.77.66.0/24', 'mtu': 1280, 'port': args.port,
          'server_ip': args.server_ip, 'clients': clients}, indent=2) + '\n')
    print('Generated separate AWG 3.1 peers. Private configurations remain on the VPS.')


if __name__ == '__main__':
    main()
