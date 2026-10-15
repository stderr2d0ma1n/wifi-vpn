#!/usr/bin/env python3
"""Generate a sing-box 1.14 gateway config; does not install or change networking."""
import argparse
import copy
import ipaddress
import json
import re
from pathlib import Path


def domain(value):
    value = value.strip().strip('.').lower()
    if not value or any(char in value for char in '/:* @\\'):
        raise ValueError('Expected a domain name without a URL or wildcard')
    result = value.encode('idna').decode('ascii')
    if len(result) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                               for label in result.split('.')):
        raise ValueError('Invalid domain name')
    return result


def build(lan_ip, lan_cidr, interface, upstream_dns, policy, mode='direct', vps=None):
    address = ipaddress.IPv4Address(lan_ip)
    network = ipaddress.IPv4Network(lan_cidr)
    if address not in network or address in (network.network_address, network.broadcast_address):
        raise ValueError('Gateway address must belong to the LAN subnet')
    ipaddress.IPv4Address(upstream_dns)
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface):
        raise ValueError('Invalid interface name')
    suffixes = [domain(x) for x in policy.get('direct_suffixes', [])]
    direct = [domain(x) for x in policy.get('direct_domains', [])]
    vpn = [domain(x) for x in policy.get('vpn_domains', [])]
    if set(direct) & set(vpn):
        raise ValueError('A domain appears in both exception lists')
    clients = [str(ipaddress.IPv4Address(x)) for x in policy.get('direct_client_ips', [])]
    if any(ipaddress.IPv4Address(x) not in network for x in clients):
        raise ValueError('Direct clients must belong to the LAN subnet')
    if mode not in ('direct', 'rules'):
        raise ValueError('Unknown mode')
    if mode == 'rules' and not vps:
        raise ValueError('Rules mode is unavailable until a VPS outbound is configured')
    awg = bool(vps and vps.get('type') == 'direct' and vps.get('bind_interface') == 'awg-home')
    sets = []
    roles = {'direct_domains': [], 'vpn_domains': [], 'direct_ip': [], 'vpn_ip': []}
    if mode == 'rules':
        for entry in policy.get('rule_sets', []):
            tag, path, role = entry['tag'], entry['path'], entry['role']
            if not re.fullmatch(r'[a-z0-9-]+', tag) or role not in roles:
                raise ValueError('Invalid rule-set tag or role')
            if not Path(path).is_absolute() or '..' in Path(path).parts or not path.endswith('.srs'):
                raise ValueError('Expected an absolute binary rule-set path')
            roles[role].append(tag)
            sets.append({'type': 'local', 'tag': tag, 'format': 'binary', 'path': path})
    cidrs = {key: [str(ipaddress.IPv4Network(x, strict=False)) for x in policy.get(key, [])]
             for key in ('direct_cidrs', 'vpn_cidrs')}

    dns_rules = []
    route_rules = [
        {'inbound': ['dns-in'], 'action': 'hijack-dns'},
        {'action': 'sniff'},
        {'protocol': 'dns', 'action': 'hijack-dns'},
        {'ip_is_private': True, 'action': 'route', 'outbound': 'direct'},
        {'ip_version': 6, 'action': 'reject'},
    ]
    if mode == 'rules':
        # Fixed loopback ingress is used only by the local watchdog, always via AWG.
        route_rules.insert(0, {'inbound': ['health-check'], 'action': 'route', 'outbound': 'vps'})
        # Explicit VPN exceptions take precedence over the default .ru/.рф rule.
        if clients:
            route_rules.append({'source_ip_cidr': [x + '/32' for x in clients],
                                'action': 'route', 'outbound': 'direct'})
            dns_rules.append({'source_ip_cidr': [x + '/32' for x in clients],
                              'action': 'route', 'server': 'dns-direct'})
        if vpn:
            route_rules.append({'domain_suffix': vpn, 'action': 'route', 'outbound': 'vps'})
            if not awg:
                dns_rules.append({'domain_suffix': vpn, 'query_type': ['A', 'AAAA'],
                                  'action': 'route', 'server': 'dns-fake'})
            dns_rules.append({'domain_suffix': vpn, 'action': 'route', 'server': 'dns-vpn'})
        if direct:
            route_rules.append({'domain_suffix': direct,
                                'action': 'route', 'outbound': 'direct'})
            dns_rules.append({'domain_suffix': direct,
                              'action': 'route', 'server': 'dns-direct'})
        if roles['vpn_domains']:
            route_rules.append({'rule_set': roles['vpn_domains'], 'action': 'route', 'outbound': 'vps'})
            dns_rules.append({'rule_set': roles['vpn_domains'], 'action': 'route', 'server': 'dns-vpn'})
        if suffixes:
            route_rules.append({'domain_suffix': suffixes, 'action': 'route', 'outbound': 'direct'})
            dns_rules.append({'domain_suffix': suffixes, 'action': 'route', 'server': 'dns-direct'})
        if roles['direct_domains']:
            route_rules.append({'rule_set': roles['direct_domains'], 'action': 'route', 'outbound': 'direct'})
            dns_rules.append({'rule_set': roles['direct_domains'], 'action': 'route', 'server': 'dns-direct'})
        if awg:
            # Real DNS answers permit GeoIP matching, including domains outside .ru.
            route_rules.append({'action': 'resolve', 'server': 'dns-vpn', 'strategy': 'ipv4_only'})
        for key, outbound in [('vpn_cidrs', 'vps'), ('direct_cidrs', 'direct')]:
            if cidrs[key]:
                route_rules.append({'ip_cidr': cidrs[key], 'action': 'route', 'outbound': outbound})
        for role, outbound in [('vpn_ip', 'vps'), ('direct_ip', 'direct')]:
            if roles[role]:
                route_rules.append({'rule_set': roles[role], 'action': 'route', 'outbound': outbound})
        # VLESS does not carry ICMP. Do not silently send foreign ICMP directly.
        if not awg:
            route_rules.append({'network': 'icmp', 'action': 'reject'})
            dns_rules.append({'query_type': ['A', 'AAAA'], 'action': 'route', 'server': 'dns-fake'})

    outbounds = [{'type': 'direct', 'tag': 'direct', 'bind_interface': interface}]
    servers = [{'type': 'udp', 'tag': 'dns-direct', 'server': upstream_dns, 'detour': 'direct'},
               # Keep the mapping engine available when switching back to direct.
               {'type': 'fakeip', 'tag': 'dns-fake',
                'inet4_range': '198.18.0.0/15', 'inet6_range': 'fc00::/18'}]
    if mode == 'rules':
        outbound = copy.deepcopy(vps)
        if awg:
            # auto_redirect assigns its own bypass mark. The oif policy rule
            # selects the AWG table from bind_interface without a custom mark.
            # Also normalize legacy saved outbounds made before this fix.
            outbound.pop('routing_mark', None)
        if not awg and (outbound.get('type') != 'vless' or not outbound.get('server')):
            raise ValueError('Expected a configured VLESS outbound')
        outbound['tag'] = 'vps'
        if not awg:
            outbound['bind_interface'] = interface
        outbounds.append(outbound)
        servers.append({'type': 'udp', 'tag': 'dns-vpn', 'server': '1.1.1.1', 'detour': 'vps'})

    config = {
        'log': {'level': 'warn', 'timestamp': True},
        'dns': {'servers': servers, 'rules': dns_rules,
                'final': 'dns-direct' if mode == 'direct' else 'dns-vpn',
                'strategy': 'ipv4_only', 'reverse_mapping': True},
        'inbounds': [
            {'type': 'direct', 'tag': 'dns-in', 'listen': str(address), 'listen_port': 53},
            {'type': 'tun', 'tag': 'tun-in', 'interface_name': 'home-vpn',
             'address': ['172.29.255.1/30'], 'mtu': 1500, 'auto_route': True,
             'auto_redirect': True, 'include_interface': [interface], 'strict_route': True},
        ],
        'outbounds': outbounds,
        'route': {'rules': route_rules, 'final': 'direct' if mode == 'direct' else 'vps',
                  'default_interface': interface,
                  'default_domain_resolver': {'server': 'dns-direct'}},
        'experimental': {'cache_file': {'enabled': True, 'store_fakeip': True,
                                       'path': '/var/lib/home-gateway/cache.db'}},
    }
    if mode == 'rules':
        config['inbounds'].append({'type': 'mixed', 'tag': 'health-check',
                                   'listen': '127.0.0.1', 'listen_port': 18084})
        if sets:
            config['route']['rule_set'] = sets
        if awg:
            config['inbounds'][1]['mtu'] = 1280
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lan-ip', required=True)
    parser.add_argument('--lan-cidr', required=True)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--upstream-dns', required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--mode', choices=['direct', 'rules'], default='direct')
    parser.add_argument('--vps-outbound', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text())
    vps = json.loads(args.vps_outbound.read_text()) if args.vps_outbound else None
    config = build(args.lan_ip, args.lan_cidr, args.interface, args.upstream_dns,
                   policy, args.mode, vps)
    # Never overwrite an active config or an existing draft by accident.
    with args.output.open('x', encoding='utf-8') as target:
        target.write(json.dumps(config, ensure_ascii=False, indent=2) + '\n')
    args.output.chmod(0o600)


if __name__ == '__main__':
    main()
