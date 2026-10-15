#!/usr/bin/env python3
"""Create a small private Xray/Happ JSON profile from an existing VLESS outbound.

No server or network settings are changed. The generated profile routes all
traffic through the existing account; no geodata, sniffing, mux or direct
fallback is configured. Credentials must remain outside Git.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import uuid


def make_profile(outbound):
    if outbound['type'] != 'vless' or not ipaddress.ip_address(outbound['server']).is_global:
        raise ValueError('Expected a public VLESS server')
    uuid.UUID(outbound['uuid'])
    tls = outbound['tls']
    if not tls['enabled'] or not tls['reality']['enabled']:
        raise ValueError('Expected the existing REALITY profile')
    return {
        'remarks': 'Home-NL-iphone-Clean',
        'log': {'loglevel': 'info'},
        'dns': {'servers': ['1.1.1.1', '1.0.0.1'], 'queryStrategy': 'UseIPv4'},
        'inbounds': [
            {'tag': 'socks', 'listen': '127.0.0.1', 'port': 10808,
             'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}},
            {'tag': 'http', 'listen': '127.0.0.1', 'port': 10809,
             'protocol': 'http', 'settings': {}},
        ],
        'outbounds': [{
            'tag': 'proxy', 'protocol': 'vless',
            'settings': {'vnext': [{
                'address': outbound['server'], 'port': outbound['server_port'],
                'users': [{'id': outbound['uuid'], 'encryption': 'none',
                           'flow': outbound.get('flow', '')}],
            }]},
            'streamSettings': {'network': 'tcp', 'security': 'reality',
                'realitySettings': {
                    'serverName': tls['server_name'],
                    'fingerprint': 'chrome',
                    'publicKey': tls['reality']['public_key'],
                    'shortId': tls['reality']['short_id'],
                }},
            'mux': {'enabled': False},
        }],
        'routing': {'domainStrategy': 'AsIs', 'rules': []},
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--outbound', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    destination = args.output.resolve()
    if any((p / '.git').exists() for p in (destination.parent, *destination.parents)):
        parser.error('Private profiles must stay outside Git')
    profile = make_profile(json.loads(args.outbound.read_text()))
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as target:
        json.dump(profile, target, indent=2)
        target.write('\n')
    print('Created private minimal profile; no server settings changed.')
