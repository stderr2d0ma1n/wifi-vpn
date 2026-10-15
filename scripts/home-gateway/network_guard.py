#!/usr/bin/env python3
"""Apply only this gateway's NAT and forwarding guard; never flush other rules."""
import argparse
import ipaddress
import json
import re
import subprocess
from pathlib import Path


def checked_network(value):
    interface = value['interface']
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface):
        raise ValueError('Invalid interface name')
    network = ipaddress.IPv4Network(value['lan_cidr'])
    address = ipaddress.IPv4Address(value['lan_ip'])
    if address not in network or address in (network.network_address, network.broadcast_address):
        raise ValueError('Invalid gateway address')
    ipaddress.IPv4Address(value['upstream_dns'])
    return interface, str(network)


def nft_script(settings, mode, existing):
    interface, network = checked_network(settings)
    incoming = settings.get('incoming_interface', interface)
    prefix = settings.get('nft_prefix', 'home_gateway')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', incoming) or prefix not in ('home_gateway', 'home_gateway_lab'):
        raise ValueError('Invalid owned network-guard scope')
    if mode not in ('direct', 'rules'):
        raise ValueError('Invalid gateway mode')
    script = []
    direct_clients = [str(ipaddress.IPv4Address(value)) for value in settings.get('direct_client_ips', [])]
    if any(ipaddress.IPv4Address(value) not in ipaddress.IPv4Network(network) for value in direct_clients):
        raise ValueError('Direct client outside LAN')
    for family, table in [('inet', prefix + '_guard'), ('ip', prefix + '_nat')]:
        if (family, table) in existing:
            script.append('delete table ' + family + ' ' + table)
    guard = ''
    bypass = ''
    if mode == 'rules':
        # If sing-box stops, routed clients cannot fall back to the router's WAN.
        guard = ('iifname "' + incoming + '" oifname "' + interface + '" '
                 'ip saddr ' + network + ' ip daddr != ' + network + ' counter drop;')
        if direct_clients:
            addresses = '{ ' + ', '.join(direct_clients) + ' }'
            guard = ('iifname "' + incoming + '" oifname "' + interface + '" '
                     'ip saddr ' + addresses + ' counter accept;\n' + guard)
            # Bypass NFQUEUE/TUN and crypto for consoles/gaming PCs. 0x2024 is
            # sing-box's documented runtime bypass mark in this pinned deployment.
            bypass = ('chain device_bypass { type filter hook prerouting priority -150; policy accept;\n'
                      'iifname "' + incoming + '" ip saddr ' + addresses +
                      ' meta mark set 0x2024 ct mark set 0x2024 counter;\n}\n')
    script += [
        'table inet ' + prefix + '_guard {', bypass, 'chain forward {',
        'type filter hook forward priority -5; policy accept;',
        guard,
        '}',
        '}',
        'table ip ' + prefix + '_nat { chain postrouting {',
        'type nat hook postrouting priority srcnat; policy accept;',
        'iifname "' + incoming + '" oifname "' + interface + '" '
        'ip saddr ' + network + ' ip daddr != ' + network + ' masquerade;',
        '}',
        '}',
    ]
    return '\n'.join(script) + '\n'


def apply(settings, mode):
    interface, _ = checked_network(settings)
    existing = set()
    prefix = settings.get('nft_prefix', 'home_gateway')
    if prefix not in ('home_gateway', 'home_gateway_lab'):
        raise ValueError('Unrecognized network-guard owner')
    for family, table in [('inet', prefix + '_guard'), ('ip', prefix + '_nat')]:
        result = subprocess.run(['nft', 'list', 'table', family, table],
                                capture_output=True, text=True)
        if result.returncode == 0:
            existing.add((family, table))
    script = nft_script(settings, mode, existing)
    subprocess.run(['nft', '--check', '-f', '-'], input=script, text=True, check=True)
    # A single nft transaction replaces the guard without an unprotected gap.
    subprocess.run(['nft', '-f', '-'], input=script, text=True, check=True)
    keys = {'net.ipv4.ip_forward': 1}
    for scope in ['all', 'default', interface]:
        keys['net.ipv4.conf.' + scope + '.send_redirects'] = 0
        keys['net.ipv4.conf.' + scope + '.accept_redirects'] = 0
        keys['net.ipv4.conf.' + scope + '.rp_filter'] = 2
    for key, value in keys.items():
        # Slash syntax preserves dots in interface names.
        parts = key.split('.')
        if '.conf.' in key:
            scope, parameter = key[len('net.ipv4.conf.'):].rsplit('.', 1)
            path = Path('/proc/sys/net/ipv4/conf') / scope / parameter
        else:
            path = Path('/proc/sys').joinpath(*parts)
        path.write_text(str(value) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--mode', choices=['direct', 'rules'])
    parser.add_argument('--mode-file', type=Path)
    args = parser.parse_args()
    mode = args.mode or args.mode_file.read_text().strip()
    settings = json.loads(args.settings.read_text())
    active_policy = args.settings.with_name('active-policy.json')
    if mode == 'rules' and active_policy.exists():
        settings['direct_client_ips'] = json.loads(active_policy.read_text()).get('direct_client_ips', [])
    apply(settings, mode)


if __name__ == '__main__':
    main()
