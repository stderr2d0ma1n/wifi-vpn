#!/bin/bash
# Owner-requested private client exports. Never place these inside any Git tree.
set -euo pipefail
configuration=${1:?Usage: export_iphone_profiles.sh SSH_CONFIG NEW_PRIVATE_DIRECTORY}
destination=${2:?NEW_PRIVATE_DIRECTORY}
python3 - "$destination" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]).resolve()
if p.exists() or any((q/'.git').exists() for q in (p,*p.parents)):
    raise SystemExit('Use a new private directory outside all Git working trees')
PY
umask 077
mkdir -m 700 "$destination"
ssh -F "$configuration" home-vps 'cat /etc/home-awg/iphone.conf' > "$destination/Home-NL-AmneziaWG.conf.partial"
ssh -F "$configuration" home-vps 'cat /etc/home-vps/clients/iphone.txt' > "$destination/Home-NL-Happ.txt.partial"
python3 - "$destination" <<'PY'
from pathlib import Path
import base64,configparser,ipaddress,sys,urllib.parse,uuid
try:
    p=Path(sys.argv[1])
    c=configparser.ConfigParser(interpolation=None)
    c.read(p/'Home-NL-AmneziaWG.conf.partial')
    for section,key in [('Interface','PrivateKey'),('Interface','HeaderProtectionKey'),('Peer','PublicKey'),('Peer','PresharedKey')]:
        assert len(base64.b64decode(c[section][key],validate=True))==32
    u=urllib.parse.urlsplit((p/'Home-NL-Happ.txt.partial').read_text().strip())
    assert u.scheme=='vless' and ipaddress.IPv4Address(u.hostname).is_global
    uuid.UUID(u.username)
    assert urllib.parse.parse_qs(u.query)['security']==['reality']
except Exception:
    raise SystemExit('Profile validation failed; no credential values printed')
PY
mv "$destination/Home-NL-AmneziaWG.conf.partial" "$destination/Home-NL-AmneziaWG.conf"
mv "$destination/Home-NL-Happ.txt.partial" "$destination/Home-NL-Happ.txt"
chmod 600 "$destination/"*
printf 'Private iPhone profiles saved in: %s\n' "$destination"
