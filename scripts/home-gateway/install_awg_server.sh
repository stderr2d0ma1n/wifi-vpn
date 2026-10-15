#!/bin/bash
# Install an additional AWG service on the prepared VPS; VLESS stays separate.
set -euo pipefail
test "$(id -u)" -eq 0
sources=$(realpath "${1:?SOURCE_DIR}")
server_address=${2:?PUBLIC_SERVER_IPV4}
test ! -e /etc/home-awg
test ! -e /etc/sysctl.d/70-home-awg.conf
if ip link show awgsrv0 >/dev/null 2>&1; then echo 'Interface already exists' >&2; exit 1; fi
if ss -H -lun 'sport = :443' | read -r _; then echo 'UDP 443 is already used' >&2; exit 1; fi
command -v awg >/dev/null
command -v amneziawg-go >/dev/null
install -d -m 755 /usr/local/lib/home-awg
install -m 644 "$sources/awg_runtime.py" "$sources/awg_config.py" /usr/local/lib/home-awg/
python3 /usr/local/lib/home-awg/awg_config.py --server-ip "$server_address" --output /etc/home-awg
python3 - <<'PY'
import json,re,subprocess
from pathlib import Path
p=Path('/etc/home-awg/network.json')
data=json.loads(p.read_text())
interface=json.loads(subprocess.check_output(['ip','-j','route','get','1.1.1.1']))[0]['dev']
assert re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',interface)
data['wan_interface']=interface
p.write_text(json.dumps(data,indent=2)+'\n')
PY
wan_interface=$(python3 -c 'import json; print(json.load(open("/etc/home-awg/network.json"))["wan_interface"])')
printf 'net.ipv4.ip_forward = 1\n' > /etc/sysctl.d/70-home-awg.conf
sysctl -p /etc/sysctl.d/70-home-awg.conf
ufw allow 443/udp
ufw route allow in on awgsrv0 out on "$wan_interface" from 10.77.66.0/24
install -m 644 "$sources/home-awg.service" /etc/systemd/system/home-awg.service
systemd-analyze verify /etc/systemd/system/home-awg.service
systemctl daemon-reload
systemctl enable --now home-awg.service
sleep 2
systemctl is-active --quiet home-awg.service
ss -H -lun 'sport = :443'
echo 'AWG server installed. Test authenticated packets before using it.'
