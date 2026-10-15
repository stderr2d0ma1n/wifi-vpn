#!/usr/bin/env python3
"""Manage only the dedicated AWG server or isolated namespace probe."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

NS = 'home-awg-test'
CLIENT = 'awgprobe0'
SERVER = 'awgsrv0'
DNS_DIR = Path('/etc/netns') / NS
PROBE = Path('/etc/home-awg-probe')
MARKER = PROBE / 'namespace-owned'
SERVICE_RUNTIME = Path('/run/home-awg-probe')


def run(*args, capture=False):
    result = subprocess.run(args, check=False, capture_output=True, text=True)
    if result.returncode:
        # awg setconf may echo a rejected credential line; never log its output.
        detail = '' if args[0] == 'awg' else ': ' + result.stderr.strip()
        raise RuntimeError('Command failed: ' + args[0] + ' ' + args[1] + detail)
    return result.stdout if capture else None


def baseline():
    return {'mode': Path('/etc/home-gateway/mode').read_text().strip(),
            'config_sha256': hashlib.sha256(Path('/etc/sing-box/config.json').read_bytes()).hexdigest(),
            'resolver_sha256': hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest(),
            'routes': run('ip', '-j', '-4', 'route', 'show', 'table', 'main', capture=True),
            'rules': run('ip', '-j', 'rule', capture=True)}


def wait_socket(interface):
    for _ in range(100):
        if Path('/var/run/amneziawg/' + interface + '.sock').exists():
            return
        time.sleep(0.05)
    raise RuntimeError('AWG control socket did not appear')


def nat(operation):
    network = json.loads(Path('/etc/home-awg/network.json').read_text())
    interface = network['wan_interface']
    rule = ['POSTROUTING', '-s', network['subnet'], '-o', interface, '-m', 'comment',
            '--comment', 'home-awg-only', '-j', 'MASQUERADE']
    exists = subprocess.run(['iptables', '-w', '5', '-t', 'nat', '-C', *rule],
                            capture_output=True).returncode == 0
    if operation == 'add' and not exists:
        run('iptables', '-w', '5', '-t', 'nat', '-A', *rule)
    elif operation == 'remove' and exists:
        run('iptables', '-w', '5', '-t', 'nat', '-D', *rule)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['server-up','server-down','probe-prepare','probe-up','probe-down','verify-baseline'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root')
    if args.action == 'server-up':
        wait_socket(SERVER)
        run('awg', 'setconf', SERVER, '/etc/home-awg/server-device.conf')
        run('ip', 'address', 'replace', '10.77.66.1/24', 'dev', SERVER)
        run('ip', 'link', 'set', 'dev', SERVER, 'mtu', '1280', 'up')
        nat('add')
    elif args.action == 'server-down':
        nat('remove')
    elif args.action == 'probe-prepare':
        original = baseline()
        if original['mode'] not in ('direct', 'rules'):
            raise RuntimeError('Unrecognized household gateway mode')
        if DNS_DIR.exists() and not MARKER.exists():
            raise RuntimeError('Existing namespace DNS directory is not ours')
        if Path('/run/netns/' + NS).exists():
            raise RuntimeError('Namespace already exists; inspect it before starting')
        DNS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        MARKER.write_text('Owned by home-awg-probe.service\n')
        run('ip', 'netns', 'add', NS)
        (DNS_DIR / 'resolv.conf').write_text('nameserver 1.1.1.1\nnameserver 1.0.0.1\n')
        SERVICE_RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
        (SERVICE_RUNTIME / 'baseline.json').write_text(json.dumps(original))
    elif args.action == 'probe-up':
        wait_socket(CLIENT)
        run('awg', 'setconf', CLIENT, str(PROBE / 'orange-device.conf'))
        run('ip', 'link', 'set', 'dev', CLIENT, 'mtu', '1280')
        run('ip', 'link', 'set', 'dev', CLIENT, 'netns', NS)
        run('ip', '-n', NS, 'link', 'set', 'lo', 'up')
        run('ip', '-n', NS, 'address', 'replace', '10.77.66.2/32', 'dev', CLIENT)
        run('ip', '-n', NS, 'link', 'set', CLIENT, 'up')
        run('ip', '-n', NS, 'route', 'replace', 'default', 'dev', CLIENT)
        run('ip', '-n', NS, '-6', 'route', 'replace', 'unreachable', 'default')
        if baseline() != json.loads((SERVICE_RUNTIME / 'baseline.json').read_text()):
            raise RuntimeError('Host gateway baseline changed during probe setup')
    elif args.action == 'probe-down':
        if MARKER.exists() and Path('/run/netns/' + NS).exists():
            run('ip', 'netns', 'delete', NS)
    elif args.action == 'verify-baseline':
        expected = json.loads((SERVICE_RUNTIME / 'baseline.json').read_text())
        if baseline() != expected or expected['mode'] != 'direct':
            raise RuntimeError('Host gateway baseline differs from direct pre-test state')
        print('Host config, mode, routes and policy rules are unchanged.')


if __name__ == '__main__':
    main()
