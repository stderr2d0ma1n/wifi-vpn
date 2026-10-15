#!/bin/bash
# Initial installation only. Package downloads and router changes are separate.
set -euo pipefail
if [ "$#" -ne 3 ] || [ "$(id -u)" -ne 0 ]; then
    echo 'Usage (root): install_board.sh SOURCE_DIR NETWORK_JSON CHECKED_SING_BOX_DEB' >&2
    exit 2
fi
sources=$(realpath "$1")
settings=$(realpath "$2")
package=$(realpath "$3")
test ! -e /etc/home-gateway/network.json || { echo 'Gateway is already installed' >&2; exit 1; }
test ! -e /etc/sing-box/config.json || { echo 'Existing sing-box config needs separate review' >&2; exit 1; }
for command in python3 nft ip netplan visudo; do command -v "$command" >/dev/null; done
test -e /dev/net/tun
test -f /etc/netplan/10-dhcp-all-interfaces.yaml
python3 - "$sources" "$settings" <<'PY'
import json,sys
sys.path.insert(0,sys.argv[1])
from build_config import build
network=json.load(open(sys.argv[2]))
build(network['lan_ip'],network['lan_cidr'],network['interface'],network['upstream_dns'],{})
if network['interface']!='eth0':raise SystemExit('Review Netplan setup for this interface first')
PY
dpkg -i "$package"
install -d -m 755 /usr/local/lib/home-gateway /etc/systemd/system/sing-box.service.d
install -d -m 700 /etc/home-gateway /var/backups/home-gateway
cp -a /etc/sing-box/config.json /var/backups/home-gateway/sing-box-package-config.json
install -d -o sing-box -g sing-box -m 750 /var/lib/home-gateway
install -m 755 "$sources/gatewayctl.py" /usr/local/lib/home-gateway/gatewayctl.py
install -m 644 "$sources/build_config.py" "$sources/network_guard.py" "$sources/gateway_cli.py" "$sources/gateway_safety.py" /usr/local/lib/home-gateway/
install -m 600 "$settings" /etc/home-gateway/network.json
install -m 600 "$sources/policy.example.json" /etc/home-gateway/policy.json
printf 'direct\n' > /etc/home-gateway/mode
chmod 600 /etc/home-gateway/mode
python3 /usr/local/lib/home-gateway/build_config.py \
    --lan-ip "$(python3 -c 'import json;print(json.load(open("/etc/home-gateway/network.json"))["lan_ip"])')" \
    --lan-cidr "$(python3 -c 'import json;print(json.load(open("/etc/home-gateway/network.json"))["lan_cidr"])')" \
    --interface eth0 \
    --upstream-dns "$(python3 -c 'import json;print(json.load(open("/etc/home-gateway/network.json"))["upstream_dns"])')" \
    --policy /etc/home-gateway/policy.json --mode direct --output /etc/home-gateway/generated.json
install -o root -g sing-box -m 640 /etc/home-gateway/generated.json /etc/sing-box/config.json
sing-box check -c /etc/sing-box/config.json
install -m 644 "$sources/home-gateway-network.service" /etc/systemd/system/
install -m 644 "$sources/sing-box-gateway.conf" /etc/systemd/system/sing-box.service.d/home-gateway.conf
ln -s /usr/local/lib/home-gateway/gatewayctl.py /usr/local/sbin/gatewayctl
printf 'gateway ALL=(root) NOPASSWD: /usr/local/sbin/gatewayctl\n' > /etc/sudoers.d/home-gateway
chmod 440 /etc/sudoers.d/home-gateway
visudo -c -f /etc/sudoers.d/home-gateway
cp -a /etc/netplan /var/backups/home-gateway/netplan-before
python3 - <<'PY'
import json,re
from pathlib import Path
network=json.loads(Path('/etc/home-gateway/network.json').read_text())
router=network['upstream_dns']
mac=Path('/sys/class/net/eth0/address').read_text().strip()
if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac):raise SystemExit('Invalid Ethernet MAC')
text='''network:
  version: 2
  renderer: networkd
  ethernets:
    all-eth-interfaces:
      match:
        name: "eth0"
      macaddress: "%s"
      dhcp4: true
      dhcp6: false
      dhcp4-overrides:
        use-routes: false
        use-dns: false
      nameservers:
        addresses: [%s]
      routes:
        - to: default
          via: %s
          metric: 100
'''%(mac,router,router)
path=Path('/etc/netplan/20-home-gateway.yaml')
with path.open('x') as target:target.write(text)
path.chmod(0o600)
PY
netplan generate
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/home-gateway-network.service
echo 'Installed and checked. Netplan and gateway services have not been started.'
