#!/usr/bin/env python3
"""Exercise real REALITY TCP and UDP/DNS on loopback, without home network changes."""
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from vps_config import probe_config


def wait_port(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('Test process exited unexpectedly; private logs suppressed')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError('Test listener did not start')


def main():
    mode_file = Path('/etc/home-gateway/mode')
    if mode_file.read_text().strip() != 'direct':
        raise SystemExit('Run this isolated validation only before home VPN activation')
    for port in [18443, 18081, 1053]:
        with socket.socket() as available:
            available.bind(('127.0.0.1', port))
    processes = []
    with tempfile.TemporaryDirectory(prefix='vps-loopback-') as temporary:
        work = Path(temporary)
        try:
            subprocess.run(['python3', str(Path(__file__).with_name('vps_config.py')),
                            'generate', '--server-ip', '1.1.1.1',
                            '--server-name', 'www.microsoft.com',
                            '--output-dir', str(work / 'configs')], check=True)
            server_file = work / 'configs/server.json'
            server = json.loads(server_file.read_text())
            server['inbounds'][0].update(listen='127.0.0.1', listen_port=18443)
            server_file.write_text(json.dumps(server))
            outbound = json.loads((work / 'configs/vps-outbound.json').read_text())
            outbound.update(server='127.0.0.1', server_port=18443)
            probe_file = work / 'configs/probe.json'
            probe_file.write_text(json.dumps(probe_config(outbound, 18081)))
            for config, port in [(server_file, 18443), (probe_file, 18081)]:
                subprocess.run(['sing-box', 'check', '-c', str(config)],
                               check=True, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                with (work / (str(port) + '.log')).open('w') as log:
                    process = subprocess.Popen(['sing-box', 'run', '-c', str(config)],
                                               stdout=log, stderr=log)
                processes.append(process)
                wait_port(port, process)
            subprocess.run(['curl', '-fsS', '--proxy', 'socks5h://127.0.0.1:18081',
                            '--connect-timeout', '10', '--max-time', '30',
                            'https://example.com/', '-o', '/dev/null'], check=True)
            answer = subprocess.run(['dig', '@127.0.0.1', '-p', '1053',
                                     'example.com', 'A', '+short', '+time=10', '+tries=1'],
                                    check=True, capture_output=True, text=True).stdout
            if not any(_is_ip(line) for line in answer.splitlines()):
                raise RuntimeError('DNS over REALITY did not return an IPv4 answer')
            if mode_file.read_text().strip() != 'direct':
                raise RuntimeError('Home mode unexpectedly changed during the test')
            print('REALITY/Vision HTTPS and UDP/DNS passed on loopback; home mode is direct')
        finally:
            for process in reversed(processes):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def _is_ip(value):
    import ipaddress
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


if __name__ == '__main__':
    main()
