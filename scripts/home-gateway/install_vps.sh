#!/bin/bash
# Configure a fresh VPS after official sing-box installation and SSH verification.
# No router or Orange Pi networking is changed by this script.
set -euo pipefail
if [ "$#" -ne 3 ] || [ "$(id -u)" -ne 0 ]; then
    echo 'Usage (root, fresh VPS): install_vps.sh SOURCE_DIR PUBLIC_IPV4 REALITY_SERVER_NAME' >&2
    exit 2
fi
sources=$(realpath "$1")
for command in python3 sing-box systemctl ufw ss; do command -v "$command" >/dev/null; done
test ! -e /etc/home-vps || { echo 'Existing VPS configuration needs separate review' >&2; exit 1; }
test -s /root/.ssh/authorized_keys
getent passwd sing-box >/dev/null
if ss -H -ltn 'sport = :443' | read -r _; then
    echo 'TCP 443 is already in use; review the existing service first' >&2
    exit 1
fi
install -d -m 755 /usr/local/lib/home-gateway-vps
install -m 644 "$sources/build_config.py" "$sources/vps_config.py" /usr/local/lib/home-gateway-vps/
python3 /usr/local/lib/home-gateway-vps/vps_config.py generate \
    --server-ip "$2" --server-name "$3" --output-dir /etc/home-vps
chown root:sing-box /etc/home-vps /etc/home-vps/server.json
chmod 750 /etc/home-vps
chmod 640 /etc/home-vps/server.json
install -m 644 "$sources/home-vps.service" /etc/systemd/system/home-vps.service
systemd-analyze verify /etc/systemd/system/home-vps.service
systemctl daemon-reload
ufw allow 22/tcp
ufw allow 443/tcp
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
systemctl enable --now home-vps.service
ready=false
for attempt in $(seq 1 10); do
    if systemctl is-active --quiet home-vps.service && ss -H -ltn 'sport = :443' | read -r _; then
        ready=true
        break
    fi
    sleep 1
done
test "$ready" = true || { echo 'VPS service did not open TCP 443' >&2; exit 1; }
sleep 1
systemctl is-active --quiet home-vps.service
echo 'VPS service active. Only SSH and authenticated VLESS/REALITY are exposed.'
echo 'Client credentials are root-only in /etc/home-vps/vps-outbound.json; never commit them.'
