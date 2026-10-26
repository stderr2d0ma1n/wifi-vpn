#!/usr/bin/env python3
"""Prepare policies, explicitly start a guarded trial, or recover direct routing."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os

from build_config import domain
from gateway_safety import Gateway, atomic, load


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', action='store_true', help='Use only the fixed isolated test profile')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('direct', 'status', 'policy', 'prepare', 'confirm', 'watch'):
        commands.add_parser(name)
    for name in ('rules', 'trial'):
        trial = commands.add_parser(name, help='Owner-approved activation only; automatic rollback until confirmed')
        trial.add_argument('--seconds', type=int, default=180)
    domains = commands.add_parser('domain')
    domains.add_argument('route', choices=['direct', 'vpn', 'remove'])
    domains.add_argument('name')
    clients = commands.add_parser('client')
    clients.add_argument('route', choices=['direct', 'remove'])
    clients.add_argument('ip')
    cidrs = commands.add_parser('cidr')
    cidrs.add_argument('route', choices=['direct', 'vpn', 'remove'])
    cidrs.add_argument('network')
    auto_return = commands.add_parser('auto-return', help='Owner-authorized return to the same confirmed AWG policy')
    auto_return.add_argument('action', choices=('on', 'off', 'status'))
    args = parser.parse_args()
    if os.geteuid():
        parser.error('Run with sudo')
    gateway = Gateway(args.lab)
    with (gateway.settings / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        mode = gateway.mode_path.read_text().strip()
        if args.command == 'status':
            print(json.dumps({'mode': mode, 'service': 'active' if gateway.active() else 'inactive',
                              'fallback_dns_active': gateway.active(gateway.dns_unit),
                              'transport': 'amneziawg' if (gateway.settings / 'awg-outbound.json').exists() else 'vless',
                              'network': gateway.network, 'safety': load(gateway.activation_path, {}),
                              'readiness': load(gateway.settings / 'readiness.json', {}),
                              'auto_return': gateway.auto_return.status(),
                              'direct_client_ips': gateway.policy.get('direct_client_ips', [])}, ensure_ascii=False, indent=2))
            return
        if args.command == 'policy':
            print(json.dumps(gateway.policy, ensure_ascii=False, indent=2))
            return
        if args.command == 'auto-return':
            if args.action == 'on':
                result = gateway.auto_return.enable()
            elif args.action == 'off':
                gateway.auto_return.disable('owner_disabled')
                result = gateway.public()
            else:
                result = gateway.auto_return.status()
            print(json.dumps(result, ensure_ascii=False))
            return
        if args.command == 'prepare':
            candidate = gateway.build('rules')
            gateway.validate(candidate)
            atomic(gateway.settings / 'prepared-awg.json', candidate)
            print(json.dumps({'prepared': True, 'household_mode': mode,
                              'candidate_sha256': hashlib.sha256(json.dumps(candidate, sort_keys=True).encode()).hexdigest()}))
            return
        if args.command == 'direct':
            result = gateway.direct()
        elif args.command in ('rules', 'trial'):
            if not 30 <= args.seconds <= 1800:
                parser.error('Trial confirmation timeout must be 30..1800 seconds')
            result = gateway.rules(args.seconds)
        elif args.command == 'confirm':
            result = gateway.confirm()
        elif args.command == 'watch':
            result = gateway.watch()
        else:
            # Exception edits are staged for the next explicit trial. No restart.
            if args.command == 'domain':
                value, keys = domain(args.name), ('direct_domains', 'vpn_domains')
            elif args.command == 'cidr':
                value, keys = str(ipaddress.IPv4Network(args.network, strict=False)), ('direct_cidrs', 'vpn_cidrs')
            else:
                value, keys = str(ipaddress.IPv4Address(args.ip)), ('direct_client_ips',)
                if ipaddress.IPv4Address(value) not in ipaddress.IPv4Network(gateway.network['lan_cidr']):
                    parser.error('Client must belong to the LAN')
            for key in keys:
                gateway.policy[key] = [item for item in gateway.policy.get(key, []) if item != value]
            if args.route != 'remove':
                gateway.policy[keys[0] if args.route == 'direct' else keys[1]].append(value)
            gateway.validate(gateway.build('rules'))
            atomic(gateway.settings / 'policy.json', gateway.policy)
            print('Policy staged; live household routing unchanged. Revalidate before the next trial.')
            return
        print(json.dumps(result, ensure_ascii=False))
        if args.command == 'direct':
            print('Applied mode: direct')


if __name__ == '__main__':
    main()
