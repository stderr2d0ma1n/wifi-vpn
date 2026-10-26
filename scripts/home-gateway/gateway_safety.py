#!/usr/bin/env python3
"""Guarded activation, emergency rollback and explicitly authorized AWG return."""
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

from build_config import build
from network_guard import apply as apply_guard
from auto_return import AutoReturn


def atomic(path, value, mode=0o600, group=None):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as output:
            output.write(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2) + '\n')
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        if group is not None:
            os.chown(temporary, 0, grp.getgrnam(group).gr_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(args, check=True, timeout=20):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        # Never echo config validation errors that might contain legacy VLESS credentials.
        raise RuntimeError('Gateway command failed: ' + ' '.join(args[:3]))
    return result


def load(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


def runtime_hashes():
    directory = Path(__file__).parent
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in ('build_config.py', 'gateway_safety.py', 'network_guard.py',
                         'auto_return.py', 'gateway_cli.py', 'awg_uplink.py')}


def decision(mode, activation, probe_ok, now, boot_id):
    """Pure watchdog policy, shared by real and isolated lab profiles."""
    if mode != 'rules':
        return 'idle', 0
    if not activation.get('confirmed'):
        if activation.get('boot_id') != boot_id or now >= activation.get('deadline', 0):
            return 'confirmation_timeout', activation.get('failures', 0)
    failures = 0 if probe_ok else activation.get('failures', 0) + 1
    return ('connectivity_failed' if failures >= 3 else 'observe'), failures


class Gateway:
    def __init__(self, lab=False):
        self.lab = lab
        self.base = Path('/run/home-gateway-lab') if lab else Path('/etc/home-gateway')
        self.settings = self.base / 'settings' if lab else self.base
        self.config = self.base / 'config.json' if lab else Path('/etc/sing-box/config.json')
        self.unit = 'home-gateway-lab.service' if lab else 'sing-box.service'
        self.dns_unit = 'home-gateway-lab-dns.service' if lab else 'home-gateway-fallback-dns.service'
        self.health_port = 18085 if lab else 18084
        self.public_path = self.base / 'control-status.json' if lab else Path('/var/lib/home-gateway-control/status.json')
        self.activation_path = self.settings / 'activation.json'
        self.mode_path = self.settings / 'mode'
        self.network = load(self.settings / 'network.json')
        self.policy = load(self.settings / 'policy.json')
        self.auto_return = AutoReturn(self)

    def check_readiness(self, config):
        if self.lab:
            return
        readiness = load(self.settings / 'readiness.json', {})
        digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        if (not readiness.get('ready') or readiness.get('candidate_sha256') != digest or
                readiness.get('runtime_source_sha256') != runtime_hashes()):
            raise RuntimeError('Candidate needs isolated validation before activation')

    def recovery_fingerprint(self):
        config = self.build('rules')
        self.check_readiness(config)
        material = {'config': config, 'runtime': runtime_hashes(),
                    'safety': load(self.settings / 'safety.json'),
                    'rule_files': {row['path']: hashlib.sha256(Path(row['path']).read_bytes()).hexdigest()
                                   for row in self.policy.get('rule_sets', [])}}
        return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()

    def active(self, unit=None):
        return command(['systemctl', 'is-active', '--quiet', unit or self.unit], check=False).returncode == 0

    def wait_port(self, host, port):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=0.3):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def wait_dns(self):
        return self.wait_port(self.network['lan_ip'], 53)

    def build(self, mode):
        transport = self.settings / 'awg-outbound.json'
        if not transport.exists():
            transport = self.settings / 'vps-outbound.json'
        outbound = load(transport)
        config = build(self.network['lan_ip'], self.network['lan_cidr'], self.network['interface'],
                       self.network['upstream_dns'], self.policy if mode == 'rules' else {}, mode, outbound)
        if self.lab:
            config['log']['level'] = 'info'
            # Manual-TUN lab sockets must bypass the household auto_redirect
            # that may already be active in direct mode after a real trial.
            # This explicit mark is lab-only: the lab itself has auto_redirect
            # disabled. The full namespaced test removes it before enabling it.
            for outbound in config['outbounds']:
                outbound['routing_mark'] = 0x2024
            tun = next(row for row in config['inbounds'] if row['type'] == 'tun')
            tun.update(interface_name='gw-test-tun', address=['172.29.253.1/30'], auto_route=False,
                       auto_redirect=False, include_interface=['gwtest-host'])
            for row in config['inbounds']:
                if row['tag'] == 'health-check':
                    row['listen_port'] = self.health_port
            config['experimental']['cache_file']['path'] = str(self.base / 'data/cache.db')
        return config

    def validate(self, config):
        descriptor, name = tempfile.mkstemp(prefix='validate-', suffix='.json', dir=self.settings)
        try:
            with os.fdopen(descriptor, 'w') as output:
                json.dump(config, output)
            command(['sing-box', 'check', '-c', name])
        finally:
            Path(name).unlink(missing_ok=True)

    def guard(self, mode):
        settings = dict(self.network, direct_client_ips=self.policy.get('direct_client_ips', []) if mode == 'rules' else [])
        apply_guard(settings, mode)

    def public(self, transition=None):
        previous = load(self.public_path, {})
        activation = load(self.activation_path, {})
        previous.update(schema_version=1, mode=self.mode_path.read_text().strip(),
                        checked_at=int(time.time()), service_active=self.active(),
                        fallback_dns_active=self.active(self.dns_unit),
                        confirmation_pending=bool(activation and not activation.get('confirmed') and self.mode_path.read_text().strip() == 'rules'),
                        confirmation_deadline=activation.get('deadline') if not activation.get('confirmed') else None,
                        consecutive_failures=activation.get('failures', 0),
                        auto_return=self.auto_return.status())
        if transition:
            previous['last_transition'] = dict(transition, at=int(time.time()))
        try:
            group = 'sing-box' if self.lab else 'vpn-monitor'
            group_id = grp.getgrnam(group).gr_gid
        except KeyError:
            group, group_id = 'sing-box', grp.getgrnam('sing-box').gr_gid
        if not self.public_path.parent.exists():
            self.public_path.parent.mkdir(mode=0o750)
            os.chown(self.public_path.parent, 0, group_id)
        atomic(self.public_path, previous, 0o640, group)
        return previous

    def cleanup_stale_redirect(self):
        if self.lab:
            return
        # The main service is stopped first. This table is created only by that
        # instance; loopback probes and the AWG namespace do not use it.
        command(['nft', 'delete', 'table', 'inet', 'sing-box'], check=False)
        rules = json.loads(command(['ip', '-j', '-4', 'rule', 'show']).stdout)
        for row in rules:
            if row.get('priority') in (1, 9000, 9001, 9002, 32768) and (
                    row.get('table') in (2022, 2758851448) or row.get('fwmark') in ('0x2023', '0x2024') or row.get('priority') == 9002):
                command(['ip', '-4', 'rule', 'del', 'priority', str(row['priority'])], check=False)

    def direct(self, reason='manual_direct', automatic=False):
        self.auto_return.rollback(reason, automatic, load(self.activation_path, {}))
        config = self.build('direct')
        validated = True
        try:
            self.validate(config)
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            validated = False
        atomic(self.config, config, 0o640, 'sing-box')
        atomic(self.mode_path, 'direct\n')
        # Crucially, direct recovery never rolls back to a broken rules config.
        self.guard('direct')
        command(['systemctl', 'stop', self.dns_unit], check=False)
        recovered = True
        try:
            if not validated:
                raise RuntimeError('Main binary could not validate the direct configuration')
            command(['systemctl', 'restart', self.unit], timeout=25)
            if not self.active() or not self.wait_dns():
                raise RuntimeError('Main service did not start')
        except (RuntimeError, subprocess.TimeoutExpired):
            recovered = False
            try:
                command(['systemctl', 'stop', self.unit], check=False, timeout=25)
            except subprocess.TimeoutExpired:
                command(['systemctl', 'kill', '--kill-whom=all', '--signal=KILL', self.unit], check=False)
            self.cleanup_stale_redirect()
            command(['systemctl', 'start', self.dns_unit])
            if not self.wait_dns():
                raise RuntimeError('Standby DNS did not become ready')
        atomic(self.activation_path, {'confirmed': False, 'failures': 0, 'disabled_at': int(time.time()), 'reason': reason})
        return self.public({'kind': 'automatic_rollback' if automatic else 'direct_selected',
                            'reason': reason, 'kernel_fallback': not recovered})

    def probe(self):
        if not self.active():
            return False
        expected = load(self.settings / 'safety.json')['expected_exit_ip']
        base = ['curl', '--noproxy', '', '-4', '--silent', '--show-error', '--connect-timeout', '3',
                '--max-time', '6', '--max-filesize', '65536', '--socks5-hostname', '127.0.0.1:' + str(self.health_port)]
        try:
            trace = command(base + ['https://www.cloudflare.com/cdn-cgi/trace'], check=False, timeout=8)
            ip = next((line[3:] for line in trace.stdout.splitlines() if line.startswith('ip=')), None)
            if ip and ip != expected:
                return False
            https_ok = trace.returncode == 0 and ip == expected
            if not https_ok:
                alternate = command(base + ['--write-out', '%{http_code}', 'https://www.gstatic.com/generate_204'], check=False, timeout=8)
                https_ok = alternate.returncode == 0 and alternate.stdout.strip() == '204'
            transaction = os.urandom(2)
            query = transaction + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
                dns.settimeout(3)
                dns.connect((self.network['lan_ip'], 53))
                dns.send(query)
                reply = dns.recv(4096)
            flags, _, answers = struct.unpack('!HHH', reply[2:8])
            return https_ok and reply[:2] == transaction and flags & 15 == 0 and answers > 0
        except (OSError, subprocess.TimeoutExpired, struct.error):
            return False

    def probe_uplink(self):
        """Read-only checks of the existing AWG path while household traffic is direct."""
        try:
            command(['python3', '/usr/local/lib/home-gateway/awg_uplink.py', 'verify'])
            expected = load(self.settings / 'safety.json')['expected_exit_ip']
            base = ['curl', '--noproxy', '*', '--interface', 'awg-home', '-4', '--silent', '--show-error',
                    '--connect-timeout', '3', '--max-time', '6', '--max-filesize', '65536']
            trace = command(base + ['https://www.cloudflare.com/cdn-cgi/trace'], check=False, timeout=8)
            if trace.returncode or 'ip=' + expected not in trace.stdout.splitlines():
                return False
            alternate = command(base + ['--output', '/dev/null', '--write-out', '%{http_code}',
                                       'https://www.gstatic.com/generate_204'], check=False, timeout=8)
            if alternate.returncode or alternate.stdout.strip() != '204':
                return False
            for suffix in ([], ['+tcp']):
                dns = command(['ip', 'netns', 'exec', 'home-awg-test', 'dig', '@1.1.1.1',
                               'example.com', 'A', '+short', '+time=3', '+tries=1'] + suffix,
                              check=False, timeout=5)
                answers = []
                for line in dns.stdout.splitlines():
                    try:
                        answers.append(ipaddress.IPv4Address(line))
                    except ValueError:
                        pass
                if dns.returncode or not any(address.is_global for address in answers):
                    return False
            return True
        except (OSError, RuntimeError, subprocess.TimeoutExpired, KeyError):
            return False

    def rules(self, seconds=180, automatic=False):
        if automatic:
            if not self.auto_return.state.get('enabled') or not self.auto_return.matches():
                raise RuntimeError('Automatic return is not authorized for this candidate')
        elif self.auto_return.state.get('enabled'):
            self.auto_return.disable('manual_trial')
        config = self.build('rules')
        self.validate(config)
        self.check_readiness(config)
        if not self.lab:
            command(['systemctl', 'start', 'home-awg-uplink.service'])
            command(['python3', '/usr/local/lib/home-gateway/awg_uplink.py', 'verify'])
            expected = load(self.settings / 'safety.json')['expected_exit_ip']
            preflight = command(['curl','--noproxy','*','--interface','awg-home','-4','--silent','--show-error',
                                 '--connect-timeout','4','--max-time','10','https://www.cloudflare.com/cdn-cgi/trace'], timeout=12)
            if 'ip=' + expected not in preflight.stdout.splitlines():
                raise RuntimeError('AWG preflight failed; household mode was not changed')
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        atomic(self.activation_path, {'confirmed': False, 'deadline': int(time.time()) + seconds,
                                      'boot_id': boot, 'failures': 0, 'started_at': int(time.time())})
        try:
            self.validate(config)
            command(['systemctl', 'stop', self.dns_unit], check=False)
            self.guard('rules')
            atomic(self.settings / 'active-policy.json', self.policy)
            atomic(self.config, config, 0o640, 'sing-box')
            atomic(self.mode_path, 'rules\n')
            command(['systemctl', 'restart', self.unit])
            if (not self.active() or not self.wait_dns() or
                    not self.wait_port('127.0.0.1', self.health_port)):
                raise RuntimeError('Main service listeners did not become ready')
            return self.public({'kind': 'trial_started', 'reason': 'awaiting_confirmation'})
        except Exception:
            self.direct('activation_failed', automatic=True)
            raise

    def confirm(self, automatic=False):
        if automatic and (not self.auto_return.state.get('enabled') or not self.auto_return.matches()):
            raise RuntimeError('Automatic confirmation is not authorized')
        activation = load(self.activation_path, {})
        if not activation.get('confirmed') and int(time.time()) >= activation.get('deadline', 0):
            raise RuntimeError('Trial confirmation deadline expired')
        if self.mode_path.read_text().strip() != 'rules' or not self.probe():
            raise RuntimeError('Cannot confirm an inactive or unhealthy VPN')
        if not activation.get('confirmed') and int(time.time()) >= activation.get('deadline', 0):
            raise RuntimeError('Trial expired during connectivity verification')
        activation.update(confirmed=True, confirmed_at=int(time.time()), failures=0,
                          confirmed_by='auto_return' if automatic else 'owner')
        atomic(self.activation_path, activation)
        return self.public({'kind': 'automatic_return' if automatic else 'trial_confirmed',
                            'reason': 'tunnel_stable' if automatic else 'owner_confirmed'})

    def watch(self):
        mode = self.mode_path.read_text().strip()
        activation = load(self.activation_path, {})
        if mode != 'rules':
            if not self.active() and not self.active(self.dns_unit):
                return self.direct('main_service_failed_while_direct', automatic=True)
            return self.auto_return.watch()
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        # Do not delay an expired trial while waiting for network timeouts.
        action, _ = decision(mode, activation, True, int(time.time()), boot)
        if action == 'confirmation_timeout':
            return self.direct(action, automatic=True)
        probe_ok = self.probe()
        action, failures = decision(mode, activation, probe_ok, int(time.time()), boot)
        activation['failures'] = failures
        atomic(self.activation_path, activation)
        if action in ('confirmation_timeout', 'connectivity_failed'):
            return self.direct(action, automatic=True)
        self.auto_return.active(probe_ok)
        return self.public()
