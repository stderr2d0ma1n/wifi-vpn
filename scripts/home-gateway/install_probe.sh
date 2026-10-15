#!/bin/bash
# Stage VPS credentials and start only a loopback test service, without mode changes.
set -euo pipefail
if [ "$#" -ne 2 ] || [ "$(id -u)" -ne 0 ]; then
    echo 'Usage (root): install_probe.sh SOURCE_DIR PRIVATE_VPS_OUTBOUND' >&2
    exit 2
fi
sources=$(realpath "$1")
outbound=$(realpath "$2")
test "$(cat /etc/home-gateway/mode)" = direct
test ! -e /etc/home-vps-probe
test ! -e /etc/home-gateway/vps-outbound.json
python3 - "$outbound" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
assert data['type']=='vless' and data['tls']['reality']['enabled']
assert data['tls']['utls']['enabled'] and data['uuid'] and data['server']
assert not data['tls'].get('insecure')
PY
install -d -o root -g sing-box -m 750 /etc/home-vps-probe
python3 "$sources/vps_config.py" probe --outbound "$outbound" \
    --output /etc/home-vps-probe/config.json
sing-box check -c /etc/home-vps-probe/config.json
chown root:sing-box /etc/home-vps-probe/config.json
chmod 640 /etc/home-vps-probe/config.json
install -o root -g root -m 600 "$outbound" /etc/home-gateway/vps-outbound.json
install -m 644 "$sources/home-vps-probe.service" /etc/systemd/system/
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/home-vps-probe.service
systemctl enable --now home-vps-probe.service
ready=false
for attempt in $(seq 1 10); do
    if systemctl is-active --quiet home-vps-probe.service &&
       ss -H -ltn 'sport = :18080' | read -r _ &&
       ss -H -lun 'sport = :1053' | read -r _; then
        ready=true
        break
    fi
    sleep 1
done
test "$ready" = true || { echo 'Loopback probe did not open its test ports' >&2; exit 1; }
sleep 1
systemctl is-active --quiet home-vps-probe.service
test "$(cat /etc/home-gateway/mode)" = direct
echo 'VPS probe active only on 127.0.0.1:18080 and :1053; gateway mode is still direct.'
