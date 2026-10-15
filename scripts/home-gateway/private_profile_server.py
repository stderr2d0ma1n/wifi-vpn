#!/usr/bin/env python3
"""Temporary, token-protected JSON subscription on the private AWG address.

Only used to import a previously checked profile into the owner's phone. Never
bind a public address or print the token/profile in request logs. systemd owns
the 15-minute lifetime and removes the single firewall rule on stop.
"""
import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess

BIND = '10.77.66.1'
PORT = 18087
DIRECTORY = Path('/etc/home-vps/private-import')
PROFILE = Path('/etc/home-vps/clients/iphone-clean.json')
NETWORK = ipaddress.ip_network('10.77.66.0/24')


def firewall(action):
    rule = ['INPUT', '-i', 'awgsrv0', '-s', str(NETWORK), '-d', BIND,
            '-p', 'tcp', '--dport', str(PORT), '-m', 'comment',
            '--comment', 'home-vpn-private-import', '-j', 'ACCEPT']
    exists = subprocess.run(['iptables', '-w', '5', '-C', *rule], capture_output=True).returncode == 0
    if action == 'add' and not exists:
        subprocess.run(['iptables', '-w', '5', '-I', rule[0], '1', *rule[1:]], check=True)
    elif action == 'remove' and exists:
        subprocess.run(['iptables', '-w', '5', '-D', *rule], check=True)


def prepare():
    active = subprocess.run(['systemctl', 'is-active', '--quiet', 'home-vpn-import'], capture_output=True)
    if active.returncode == 0:
        raise SystemExit('Import service is already running; do not rotate its token')
    profile = json.loads(PROFILE.read_text())
    if profile.get('remarks') != 'Home-NL-iphone-Clean':
        raise SystemExit('Expected the separately verified private diagnostic profile')
    DIRECTORY.mkdir(mode=0o700, exist_ok=True)
    if any((p / '.git').exists() for p in (DIRECTORY, *DIRECTORY.parents)):
        raise SystemExit('Private credentials must stay outside Git')
    token = secrets.token_urlsafe(24)
    for name, text in [('token', token), ('url.txt', f'http://{BIND}:{PORT}/{token}/profile.json\n')]:
        # Rotation is explicit and only while this dedicated service is inactive.
        fd = os.open(DIRECTORY / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as target:
            target.write(text)
    print('Prepared private URL file; credentials not printed.')


def serve():
    credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])
    token = (credentials / 'token').read_text().strip()
    expected = '/' + token + '/profile.json'
    # A JSON array is the documented subscription representation. The single
    # object inside is exactly the profile already checked with matching Xray.
    body = json.dumps([json.loads((credentials / 'profile').read_text())],
                      separators=(',', ':'), ensure_ascii=False).encode()

    class Handler(BaseHTTPRequestHandler):
        server_version = 'PrivateProfile'
        sys_version = ''

        def log_message(self, *args):
            pass  # BaseHTTP logs paths, which would disclose the access token.

        def respond(self, send_body):
            permitted = (ipaddress.ip_address(self.client_address[0]) in NETWORK
                         and hmac.compare_digest(self.path, expected))
            if not permitted:
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.send_header('Connection', 'close')
                self.end_headers()
                return
            self.send_response(200)
            for key, value in {
                'Content-Type': 'application/json; charset=utf-8',
                'Content-Length': str(len(body)), 'Cache-Control': 'no-store',
                'Connection': 'close', 'profile-title': 'Home-NL-iphone-Clean',
                'socks-auth-mode': 'from-json', 'http-auth-mode': 'from-json',
            }.items():
                self.send_header(key, value)
            self.end_headers()
            if send_body:
                self.wfile.write(body)
                print('Private profile delivered; path and contents suppressed.', flush=True)

        def do_GET(self):
            self.respond(True)

        def do_HEAD(self):
            self.respond(False)

    server = ThreadingHTTPServer((BIND, PORT), Handler)
    print('Private import endpoint ready on the AWG interface only.', flush=True)
    server.serve_forever(poll_interval=0.5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'firewall-add', 'firewall-remove', 'serve'])
    args = parser.parse_args()
    if args.action != 'serve' and os.geteuid() != 0:
        parser.error('Preparation and firewall ownership require root')
    if args.action == 'prepare':
        prepare()
    elif args.action.startswith('firewall-'):
        firewall(args.action.removeprefix('firewall-'))
    else:
        serve()
