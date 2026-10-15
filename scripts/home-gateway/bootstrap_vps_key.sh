#!/bin/bash
# User-run recovery when a provider did not install the ordered SSH public key.
# The existing password is entered directly into SSH's terminal prompt, never saved.
set -euo pipefail
if [ "$#" -ne 3 ]; then
    echo 'Usage: bootstrap_vps_key.sh PUBLIC_IPV4 PUBLIC_KEY_FILE PINNED_KNOWN_HOSTS' >&2
    exit 2
fi
vps_address=$1
public_key_file=$2
known_hosts_file=$3
test -t 0 || { echo 'Run interactively in Terminal; do not put the password in chat or a file.' >&2; exit 1; }
python3 - "$vps_address" "$public_key_file" <<'PY'
import base64,ipaddress,sys
from pathlib import Path
assert ipaddress.IPv4Address(sys.argv[1]).is_global
lines=Path(sys.argv[2]).read_text().strip().splitlines()
assert len(lines)==1
fields=lines[0].split()
assert len(fields)>=2 and fields[0] in ('ssh-ed25519','ssh-rsa')
base64.b64decode(fields[1],validate=True)
PY
test -s "$known_hosts_file"
ssh-keygen -lf "$public_key_file"
printf '\nВведи существующий root-пароль из письма HOSTKEY в приглашении SSH.\n'
printf 'Символы пароля не отображаются и не сохраняются этим скриптом.\n\n'
ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive \
    -o NumberOfPasswordPrompts=1 -o ConnectTimeout=10 -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$known_hosts_file" "root@$vps_address" '
set -eu
IFS= read -r remote_public_key
umask 077
install -d -m 700 /root/.ssh
if ! grep -qxF -- "$remote_public_key" /root/.ssh/authorized_keys 2>/dev/null; then
    printf "%s\n" "$remote_public_key" >> /root/.ssh/authorized_keys
fi
chmod 600 /root/.ssh/authorized_keys
printf "SSH public key installed.\n"
' < "$public_key_file"
