#!/usr/bin/env python3
"""Test an existing private sing-box VLESS profile with a loopback Xray client.

No TUN, DNS configuration, routes or persistent service are changed. Run on the
Linux gateway as root, so SO_MARK bypasses its existing transparent TUN. Private
configuration and logs exist only in a temporary directory in /run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import tempfile
import time


def udp_dns(port):
    """Authenticate a SOCKS UDP association and validate a synthetic DNS answer."""
    with socket.create_connection(('127.0.0.1', port), timeout=8) as control:
        def receive(count):
            data = b''
            while len(data) < count:
                chunk = control.recv(count - len(data))
                if not chunk:
                    raise OSError('SOCKS control connection closed')
                data += chunk
            return data
        control.sendall(b'\x05\x01\x00')
        if receive(2) != b'\x05\x00':
            raise OSError('SOCKS authentication failed')
        control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
        header = receive(4)
        if header != b'\x05\x00\x00\x01':
            raise OSError('SOCKS UDP association failed')
        reply = receive(6)
        relay_ip = socket.inet_ntoa(reply[:4])
        if relay_ip == '0.0.0.0':
            relay_ip = '127.0.0.1'
        relay_port = struct.unpack('!H', reply[4:])[0]
        transaction = os.urandom(2)
        question = transaction + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x07example\x03com\x00\x00\x01\x00\x01'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(8)
            sock.sendto(b'\x00\x00\x00\x01\x01\x01\x01\x01\x00\x35' + question,
                        (relay_ip, relay_port))
            response = sock.recv(4096)
        if response[:4] != b'\x00\x00\x00\x01':
            raise OSError('Unexpected SOCKS UDP response')
        dns = response[10:]
        if len(dns) < 12 or dns[:2] != transaction or (dns[3] & 15) != 0 or int.from_bytes(dns[6:8], 'big') == 0:
            raise OSError('DNS response did not contain a successful answer')
        return {'success': True, 'transport': 'SOCKS UDP over VLESS',
                'answer_count': int.from_bytes(dns[6:8], 'big')}


def run(binary, outbound_path, port, full_config=None):
    mode_path = Path('/etc/home-gateway/mode')
    config_path = Path('/etc/sing-box/config.json')
    # The installed gateway uses this alternate location on some versions.
    if not config_path.exists():
        config_path = Path('/etc/home-gateway/config.json')
    def baseline():
        return (mode_path.read_bytes(), hashlib.sha256(config_path.read_bytes()).hexdigest(),
                subprocess.check_output(['ip', '-j', 'rule']),
                subprocess.check_output(['ip', '-j', 'route', 'show', 'table', 'main']))
    before = baseline()
    if before[0].strip() != b'direct':
        raise SystemExit('This isolated diagnostic requires home direct mode')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', port))
    if full_config is not None:
        config = json.loads(full_config.read_text())
        proxy = next(o for o in config['outbounds'] if o['protocol'] == 'vless')
        server = proxy['settings']['vnext'][0]['address']
        # Only this temporary diagnostic copy gets Linux-specific routing marks
        # and a single isolated local inbound. The exported iPhone file does not.
        config['inbounds'] = [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
                               'settings': {'auth': 'noauth', 'udp': True}}]
        proxy['streamSettings']['sockopt'] = {'mark': 0x2024}
    else:
        outbound = json.loads(outbound_path.read_text())
        tls = outbound['tls']
        server = outbound['server']
        config = {
            'log': {'loglevel': 'debug'},
            'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
                          'settings': {'auth': 'noauth', 'udp': True}}],
            'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
                'address': outbound['server'], 'port': outbound['server_port'],
                'users': [{'id': outbound['uuid'], 'encryption': 'none',
                           'flow': outbound.get('flow', '')}]}]},
                'streamSettings': {'network': 'tcp', 'security': 'reality',
                    'realitySettings': {'serverName': tls['server_name'],
                        'fingerprint': tls.get('utls', {}).get('fingerprint', 'chrome'),
                        'publicKey': tls['reality']['public_key'],
                        'shortId': tls['reality']['short_id']},
                    'sockopt': {'mark': 0x2024}}}],
        }
    result = {'version': subprocess.check_output([str(binary), 'version'], text=True).splitlines()[0],
              'checks': []}
    with tempfile.TemporaryDirectory(prefix='home-xray-check-', dir='/run') as temp:
        directory = Path(temp)
        path = directory / 'config.json'
        path.write_text(json.dumps(config)); path.chmod(0o600)
        checked = subprocess.run([str(binary), 'run', '-test', '-c', str(path)], capture_output=True)
        if checked.returncode:
            raise SystemExit('Xray config validation failed; private diagnostics suppressed')
        log_path = directory / 'log'
        with log_path.open('w') as log:
            process = subprocess.Popen([str(binary), 'run', '-c', str(path)], stdout=log, stderr=log)
            try:
                for _ in range(30):
                    if process.poll() is not None:
                        raise SystemExit('Xray exited before probe; private log suppressed')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.1)
                for url in ['https://www.cloudflare.com/cdn-cgi/trace',
                            'https://www.gstatic.com/generate_204', 'https://example.com/']:
                    body = directory / 'response'
                    curl = subprocess.run(['curl', '-4', '-sS', '--socks5-hostname',
                        '127.0.0.1:' + str(port), '--connect-timeout', '8', '--max-time', '15',
                        '-o', str(body), '-w', '%{http_code} %{time_total}', url], capture_output=True, text=True)
                    item = {'target': url, 'exit_code': curl.returncode, 'http_time': curl.stdout.strip(),
                            'curl_error': curl.stderr.strip()}
                    if '/cdn-cgi/trace' in url and curl.returncode == 0:
                        trace = dict(line.split('=', 1) for line in body.read_text().splitlines() if '=' in line)
                        item['expected_exit'] = trace.get('ip') == server
                        item['country'] = trace.get('loc')
                    result['checks'].append(item)
                try:
                    result['udp_dns'] = udp_dns(port)
                except OSError as error:
                    result['udp_dns'] = {'success': False, 'error': str(error)}
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
        logs = log_path.read_text(errors='replace').lower()
        result['log_categories'] = {term: logs.count(term) for term in [
            'reality verification failed', 'connection reset', 'i/o timeout',
            'failed to find an available destination', 'processed invalid connection']}
        # Only this process's synthetic test destinations are logged. Never emit
        # arbitrary debug lines or handshake key material.
        error_lines = [line for line in logs.splitlines()
                       if any(term in line for term in ['[error]', '[warning]', 'failed', 'timeout'])]
        result['error_summary'] = [re.sub(r'[a-z0-9_+/=-]{32,}', '[redacted]', line)
                                   for line in error_lines[-5:]]
    result['home_baseline_unchanged'] = before == baseline()
    if not result['home_baseline_unchanged']:
        raise SystemExit('Home baseline changed during isolated check')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--outbound', type=Path)
    inputs.add_argument('--config', type=Path)
    parser.add_argument('--port', type=int, default=18082)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run on the Linux gateway as root')
    if not 1024 <= args.port <= 65535:
        parser.error('Use an unprivileged local port')
    def terminate(signum, frame):
        raise SystemExit('Diagnostic interrupted; cleaning up temporary client')
    signal.signal(signal.SIGTERM, terminate)
    print(json.dumps(run(args.binary.resolve(), args.outbound.resolve() if args.outbound else None,
                         args.port, args.config.resolve() if args.config else None), indent=2))
