#!/usr/bin/env python3
"""Inventory, check and export reviewed source files; never uploads anything."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOP_FILES = {'.gitignore', 'README.md', 'AGENTS.md', 'inventory.json'}
SOURCE_DIRS = {'docs', 'instructions', 'configs', 'skills', 'scripts', 'hooks', 'subagents'}
SKIP_PARTS = {'__pycache__', '.venv', 'node_modules', '.DS_Store'}
SECRET_PATTERNS = [
    ('private_key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('provider_token', re.compile(r'\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b')),
    ('literal_secret', re.compile(r'''(?i)(?:["']?(?:api[_-]?key|auth[_-]?token|access[_-]?token|password|client[_-]?secret)["']?)\s*[:=]\s*["']([A-Za-z0-9_./+\-=]{20,})["']''')),
]
INTERNAL = re.compile(r'(?:yandex-team\.ru|mcp\.yandex\.net|api\.eliza\.yandex\.net|/(?:Users|home)/[^/\s]+/)')


def files():
    result = []
    for p in ROOT.rglob('*'):
        rel = p.relative_to(ROOT)
        if rel.parts[0] not in SOURCE_DIRS and str(rel) not in TOP_FILES:
            continue
        if any(part in SKIP_PARTS for part in rel.parts):
            continue
        if p.is_symlink():
            raise ValueError('Export source must not be a symlink: ' + str(rel))
        if p.is_file():
            result.append(p)
    return sorted(result)


def records():
    return [{'path': str(p.relative_to(ROOT)), 'bytes': p.stat().st_size,
             'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in files() if p.name != 'inventory.json' or p.parent != ROOT]


def inventory():
    target = ROOT / 'inventory.json'
    data = json.loads(target.read_text())
    data['files'] = records()
    target.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    print('Inventoried', len(data['files']), 'source files')


def check():
    problems = []
    actual = files()
    ignored = subprocess.run(['git', '-C', str(ROOT), 'check-ignore', '--stdin'],
                             input='\n'.join(str(p.relative_to(ROOT)) for p in actual) + '\n',
                             text=True, capture_output=True)
    # In an unpacked ZIP there need not be a Git repository.
    if ignored.returncode not in (0, 1, 128):
        problems.append('git check-ignore failed')
    if ignored.returncode == 0:
        problems.extend('Export source is ignored by Git: ' + line for line in ignored.stdout.splitlines())
    for p in actual:
        rel = str(p.relative_to(ROOT))
        if p.suffix in {'.zip', '.pem', '.key'} or p.name in {'auth.json', 'preferences.json', '.env'} or '.local.' in p.name:
            problems.append('Forbidden file: ' + rel)
        try:
            content = p.read_text()
        except UnicodeDecodeError:
            problems.append('Unreviewed binary: ' + rel)
            continue
        for label, regex in SECRET_PATTERNS:
            if regex.search(content):
                problems.append(label + ': ' + rel)
        if INTERNAL.search(content):
            problems.append('Internal domain or machine path: ' + rel)
    data = json.loads((ROOT / 'inventory.json').read_text())
    if data.get('files') != records():
        problems.append('Inventory is stale; run inventory')
    if (ROOT / '.git').exists():
        tracked = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z'], capture_output=True, check=True).stdout
        allowed = {str(p.relative_to(ROOT)) for p in actual}
        problems.extend('Tracked file outside export: ' + name for name in tracked.decode().split('\0') if name and name not in allowed)
    if problems:
        raise ValueError('\n'.join(problems))
    print('OK:', len(actual), 'export files; inventory and heuristic content checks passed')


def package():
    check()
    output = ROOT / '.local-only/exports/ai-power-portable.zip'
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for p in files():
            archive.write(p, str(p.relative_to(ROOT)))
    print(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inventory', 'check', 'package'])
    args = parser.parse_args()
    try:
        {'inventory': inventory, 'check': check, 'package': package}[args.action]()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
