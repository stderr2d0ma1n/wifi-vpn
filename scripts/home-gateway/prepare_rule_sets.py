#!/usr/bin/env python3
"""Download a pinned, validated rule bundle; does not activate gateway policies."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request

SOURCES = [
    ('ru-services', 'direct_domains', 'MetaCubeX/meta-rules-dat', 'sing', 'geo/geosite/category-ru.srs'),
    ('ru-addresses', 'direct_ip', 'MetaCubeX/meta-rules-dat', 'sing', 'geo/geoip/ru.srs'),
    ('blocked-domains', 'vpn_domains', 'runetfreedom/russia-v2ray-rules-dat', 'release', 'sing-box/rule-set-geosite/geosite-ru-blocked.srs'),
    ('blocked-addresses', 'vpn_ip', 'runetfreedom/russia-v2ray-rules-dat', 'release', 'sing-box/rule-set-geoip/geoip-ru-blocked.srs'),
]


def fetch(url, maximum):
    request = urllib.request.Request(url, headers={'User-Agent': 'home-gateway-rules/1'})
    with urllib.request.urlopen(request, timeout=20) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('Rule source exceeds size limit')
    return data


def prepare(destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True, mode=0o755)
    destination.chmod(0o755)
    commits, entries = {}, []
    with tempfile.TemporaryDirectory(prefix='gateway-rules-') as temp:
        for tag, role, repo, branch, source in SOURCES:
            key = repo + '/' + branch
            if key not in commits:
                commits[key] = json.loads(fetch('https://api.github.com/repos/' + repo + '/commits/' + branch, 1_000_000))['sha']
            commit = commits[key]
            url = 'https://raw.githubusercontent.com/' + repo + '/' + commit + '/' + source
            data = fetch(url, 2_000_000)
            if len(data) < 20:
                raise ValueError('Empty rule source')
            binary = Path(temp) / (tag + '.srs')
            binary.write_bytes(data)
            decoded = binary.with_suffix('.json')
            subprocess.run(['sing-box', 'rule-set', 'decompile', str(binary), '--output', str(decoded)], check=True, capture_output=True)
            if decoded.stat().st_size > 30_000_000:
                raise ValueError('Expanded rule source exceeds limit')
            parsed = json.loads(decoded.read_text())
            if not parsed.get('rules'):
                raise ValueError('Rule source has no rules')
            digest = hashlib.sha256(data).hexdigest()
            target = destination / (tag + '-' + digest[:12] + '.srs')
            if not target.exists():
                target.write_bytes(data)
                target.chmod(0o644)
            entries.append({'tag': tag, 'role': role, 'path': str(target), 'bytes': len(data),
                            'sha256': digest, 'source_url': url, 'repo': repo, 'commit': commit})
    manifest = {'schema_version': 1, 'prepared_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'rule_sets': entries}
    temporary = destination / 'manifest.tmp'
    temporary.write_text(json.dumps(manifest, indent=2) + '\n')
    temporary.chmod(0o644)
    temporary.replace(destination / 'manifest.json')
    print(json.dumps(manifest))
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', default='/var/lib/home-gateway-rules')
    prepare(parser.parse_args().destination)
