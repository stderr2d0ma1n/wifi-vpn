#!/usr/bin/env python3
"""Expose the existing isolated AWG peer only to explicitly marked host sockets."""
import argparse
import json
import os
from pathlib import Path
import subprocess

NS = 'home-awg-test'
HOST = 'awg-home'
PEER = 'awg-peer'
MARK = '0x415747'  # Deliberately outside sing-box's auto_redirect marks 0x2023..0x2025.
TABLE = '30477'
HOST_IP = '172.30.254.1'
PEER_IP = '172.30.254.2'
MARKER = Path('/etc/home-gateway/awg-uplink-owned')


def call(*args, check=True, input=None):
    result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=12)
    if check and result.returncode:
        raise RuntimeError('Uplink command failed: ' + ' '.join(args[:4]))
    return result.stdout


def defaults():
    return json.loads(call('ip', '-j', '-4', 'route', 'show', 'default'))


def setup():
    original_defaults = defaults()
    if Path('/sys/class/net/' + HOST).exists() and not MARKER.exists():
        raise RuntimeError('Uplink interface already exists and is not owned')
    if not Path('/run/netns/' + NS).exists():
        raise RuntimeError('AWG namespace missing')
    if not MARKER.exists():
        # Refuse any table/priority collision rather than changing another VPN.
        if call('ip', '-4', 'route', 'show', 'table', TABLE, check=False).strip():
            raise RuntimeError('Routing table already in use')
        rules = json.loads(call('ip', '-j', '-4', 'rule', 'show'))
        if any(row.get('priority') in (8100, 8101) for row in rules):
            raise RuntimeError('Routing priority already in use')
        MARKER.write_text('Owned by home-awg-uplink.service\n')
        MARKER.chmod(0o600)
    if not Path('/sys/class/net/' + HOST).exists():
        call('ip', 'link', 'add', HOST, 'type', 'veth', 'peer', 'name', PEER)
        call('ip', 'link', 'set', PEER, 'netns', NS)
    call('ip', 'address', 'replace', HOST_IP + '/30', 'dev', HOST)
    call('ip', 'link', 'set', HOST, 'mtu', '1280', 'up')
    call('ip', '-n', NS, 'address', 'replace', PEER_IP + '/30', 'dev', PEER)
    call('ip', '-n', NS, 'link', 'set', PEER, 'mtu', '1280', 'up')
    call('ip', 'netns', 'exec', NS, 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1')
    script = '''table inet home_awg_uplink {
 chain forward { type filter hook forward priority -10; policy drop;
  iifname "awg-peer" oifname "awgprobe0" ip saddr 172.30.254.1 accept
  iifname "awgprobe0" oifname "awg-peer" ct state established,related accept
 }
}
table ip home_awg_uplink_nat {
 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
  oifname "awgprobe0" ip saddr 172.30.254.1 masquerade
 }
}
'''
    prefix = ''
    for family, table in [('inet', 'home_awg_uplink'), ('ip', 'home_awg_uplink_nat')]:
        if call('ip', 'netns', 'exec', NS, 'nft', 'list', 'table', family, table, check=False).strip():
            prefix += 'delete table ' + family + ' ' + table + '\n'
    call('ip', 'netns', 'exec', NS, 'nft', '-f', '-', input=prefix + script)
    call('ip', '-4', 'route', 'replace', 'table', TABLE, 'default', 'via', PEER_IP,
         'dev', HOST, 'src', HOST_IP, 'metric', '10')
    call('ip', '-4', 'route', 'replace', 'table', TABLE, 'unreachable', 'default', 'metric', '32760')
    # Idempotently replace only this module's exact rules.
    for priority, match in [('8100', ['fwmark', MARK]), ('8101', ['oif', HOST])]:
        call('ip', '-4', 'rule', 'del', 'priority', priority, *match, 'table', TABLE, check=False)
        call('ip', '-4', 'rule', 'add', 'priority', priority, *match, 'table', TABLE)
    if defaults() != original_defaults:
        raise RuntimeError('Host main default changed unexpectedly')
    verify()


def verify():
    network = json.loads(Path('/etc/home-gateway/network.json').read_text())
    if not any(row.get('gateway') == network['upstream_dns'] and row.get('dev') == network['interface'] for row in defaults()):
        raise RuntimeError('Physical upstream default is missing')
    marked = json.loads(call('ip', '-j', '-4', 'route', 'get', '1.1.1.1', 'mark', MARK))[0]
    if marked.get('dev') != HOST or marked.get('gateway') != PEER_IP:
        raise RuntimeError('AWG marked route is not isolated')
    route = json.loads(call('ip', '-j', '-n', NS, '-4', 'route', 'get', '1.1.1.1'))[0]
    if route.get('dev') != 'awgprobe0':
        raise RuntimeError('Namespace default is not AWG')
    print('Isolated AWG uplink ready; physical host default preserved.')


def teardown():
    if not MARKER.exists():
        return
    for priority, match in [('8100', ['fwmark', MARK]), ('8101', ['oif', HOST])]:
        call('ip', '-4', 'rule', 'del', 'priority', priority, *match, 'table', TABLE, check=False)
    call('ip', '-4', 'route', 'flush', 'table', TABLE, check=False)
    call('ip', 'link', 'delete', HOST, check=False)
    for family, table in [('inet', 'home_awg_uplink'), ('ip', 'home_awg_uplink_nat')]:
        call('ip', 'netns', 'exec', NS, 'nft', 'delete', 'table', family, table, check=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['up', 'down', 'verify'])
    args = parser.parse_args()
    if os.geteuid():
        parser.error('Run as root')
    {'up': setup, 'down': teardown, 'verify': verify}[args.command]()
