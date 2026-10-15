#!/usr/bin/env python3
"""Create private VLESS/REALITY configs on the VPS, without activating services."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid

from build_config import domain


def configs(server_ip, server_name, private_key, public_key, user_id, short_id, port=443):
    server_ip = str(ipaddress.IPv4Address(server_ip))
    if not ipaddress.IPv4Address(server_ip).is_global:
        raise ValueError('Expected the VPS public IPv4 address')
    server_name = domain(server_name)
    if not 1 <= port <= 65535:
        raise ValueError('Invalid listening port')
    server = {
        'log': {'level': 'warn', 'timestamp': True},
        'dns': {'servers': [{'type': 'udp', 'tag': 'dns-public', 'server': '1.1.1.1'}],
                'strategy': 'ipv4_only'},
        'inbounds': [{
            'type': 'vless', 'tag': 'vless-in', 'listen': '0.0.0.0', 'listen_port': port,
            'users': [{'name': 'home-gateway', 'uuid': user_id, 'flow': 'xtls-rprx-vision'}],
            'tls': {'enabled': True, 'server_name': server_name,
                    'reality': {'enabled': True,
                                'handshake': {'server': server_name, 'server_port': 443},
                                'private_key': private_key, 'short_id': [short_id]}},
        }],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}],
        'route': {'rules': [{'ip_is_private': True, 'action': 'reject'}],
                  'final': 'direct', 'default_domain_resolver': {'server': 'dns-public'}},
    }
    outbound = {
        'type': 'vless', 'tag': 'vps', 'server': server_ip, 'server_port': port,
        'uuid': user_id, 'flow': 'xtls-rprx-vision', 'packet_encoding': 'xudp',
        'tls': {'enabled': True, 'server_name': server_name,
                'utls': {'enabled': True, 'fingerprint': 'chrome'},
                'reality': {'enabled': True, 'public_key': public_key, 'short_id': short_id}},
    }
    return server, outbound


def probe_config(outbound, port=18080):
    """Loopback-only SOCKS/HTTP proxy: no TUN, forwarding, or system DNS changes."""
    if not 1024 <= port <= 65535:
        raise ValueError('Invalid local probe port')
    return {
        'log': {'level': 'warn', 'timestamp': True},
        'dns': {'servers': [{'type': 'udp', 'tag': 'dns-vpn', 'server': '1.1.1.1',
                             'detour': 'vps'}], 'strategy': 'ipv4_only'},
        'inbounds': [{'type': 'mixed', 'tag': 'probe', 'listen': '127.0.0.1',
                      'listen_port': port},
                     {'type': 'direct', 'tag': 'dns-probe', 'listen': '127.0.0.1',
                      'listen_port': 1053}],
        'outbounds': [dict(outbound, tag='vps')],
        'route': {'rules': [{'inbound': ['dns-probe'], 'action': 'hijack-dns'}],
                  'final': 'vps', 'default_domain_resolver': {'server': 'dns-vpn'}},
    }


def write_private(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as target:
        json.dump(value, target, indent=2)
        target.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('generate')
    create.add_argument('--server-ip', required=True)
    create.add_argument('--server-name', required=True)
    create.add_argument('--output-dir', type=Path, required=True)
    probe = commands.add_parser('probe')
    probe.add_argument('--outbound', type=Path, required=True)
    probe.add_argument('--output', type=Path, required=True)
    probe.add_argument('--port', type=int, default=18080)
    args = parser.parse_args()
    destination = (args.output_dir if args.command == 'generate' else args.output.parent).resolve()
    if any((parent / '.git').exists() for parent in (destination, *destination.parents)):
        parser.error('Private configurations must stay outside Git working trees')
    if args.command == 'probe':
        write_private(args.output, probe_config(json.loads(args.outbound.read_text()), args.port))
        print('Created loopback-only probe configuration; no service was started')
        return
    # Validate all public inputs before generating credentials or creating files.
    configs(args.server_ip, args.server_name, '', '', str(uuid.uuid4()), '')
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    generated = subprocess.run(['sing-box', 'generate', 'reality-keypair'],
                               check=True, capture_output=True, text=True).stdout
    keys = []
    for label in ['Private', 'Public']:
        match = re.search(r'(?im)^' + label + r'\s*Key:\s*(\S+)', generated)
        if not match:
            raise RuntimeError('Unrecognized sing-box keypair output; private output suppressed')
        keys.append(match.group(1))
    server, outbound = configs(args.server_ip, args.server_name, *keys,
                               str(uuid.uuid4()), secrets.token_hex(8))
    write_private(args.output_dir / 'server.json', server)
    write_private(args.output_dir / 'vps-outbound.json', outbound)
    write_private(args.output_dir / 'probe.json', probe_config(outbound))
    # Validation output must not print configuration contents or credential values.
    for name in ['server.json', 'probe.json']:
        checked = subprocess.run(['sing-box', 'check', '-c', str(args.output_dir / name)],
                                 capture_output=True, text=True)
        if checked.returncode:
            raise RuntimeError('sing-box rejected ' + name + '; inspect privately on the server')
    print('Created and validated private server/client/probe configurations; services unchanged')


if __name__ == '__main__':
    main()
