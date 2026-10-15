#!/bin/bash
# Packet checks in disposable Linux namespaces; run before moving home clients.
set -euo pipefail
test "$(id -u)" -eq 0
test "$(cat /etc/home-gateway/mode)" = direct
sources=$(dirname "$(realpath "$0")")
work=$(mktemp -d)
server_pid=''
saved_config=0
cleanup() {
    [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
    if [ "$saved_config" -eq 1 ]; then
        cp -p "$work/config.json" /etc/sing-box/config.json
        systemctl restart sing-box.service || true
    fi
    for name in hgt-core hgt-client hgt-router hgt-gateway; do
        ip netns delete "$name" 2>/dev/null || true
    done
    ip link delete hgt-main 2>/dev/null || true
    ip link delete hgt-switch 2>/dev/null || true
    rm -rf "$work"
}
# Never remove a pre-existing namespace or interface with our test names.
for name in hgt-core hgt-client hgt-router hgt-gateway; do
    ! ip netns list | awk '{print $1}' | grep -qx "$name" || exit 2
done
for name in hgt-main hgt-switch; do
    ! ip link show "$name" >/dev/null 2>&1 || exit 2
done
trap cleanup EXIT

# Test the actual service with a client whose only route is through its TUN.
ip netns add hgt-core
ip link add hgt-main type veth peer name hgt-peer
ip link set hgt-peer netns hgt-core
ip addr add 192.0.2.1/30 dev hgt-main
ip link set hgt-main up
ip -n hgt-core link set lo up
ip -n hgt-core addr add 192.0.2.2/30 dev hgt-peer
ip -n hgt-core link set hgt-peer up
ip -n hgt-core route add default via 192.0.2.1
cp -p /etc/sing-box/config.json "$work/config.json"
saved_config=1
python3 - <<'PY'
import json
from pathlib import Path
p=Path('/etc/sing-box/config.json');c=json.loads(p.read_text())
for inbound in c['inbounds']:
    if inbound['type']=='tun':inbound['include_interface'].append('hgt-main')
p.write_text(json.dumps(c,indent=2)+'\n')
PY
systemctl restart sing-box.service
sleep 2
gateway_ip=$(python3 -c 'import json;print(json.load(open("/etc/home-gateway/network.json"))["lan_ip"])')
answer=$(ip netns exec hgt-core dig "@$gateway_ip" example.com A +short | head -1)
test -n "$answer"
ip netns exec hgt-core curl --noproxy '*' --fail --silent --show-error \
    --max-time 20 --resolve "example.com:443:$answer" https://example.com/ > "$work/page"
grep -q 'Example Domain' "$work/page"
echo 'PASS: isolated client DNS and HTTPS through the real sing-box service'
cp -p "$work/config.json" /etc/sing-box/config.json
systemctl restart sing-box.service
saved_config=0
ip netns delete hgt-core
ip link delete hgt-main 2>/dev/null || true

# Emulate the one-port topology to test NAT and loss of VPN protection.
ip link add hgt-switch type bridge
ip link set hgt-switch up
for role in client router gateway; do
    ip netns add "hgt-$role"
    ip link add "hgt-$role-br" type veth peer name eth0 netns "hgt-$role"
    ip link set "hgt-$role-br" master hgt-switch
    ip link set "hgt-$role-br" up
    ip -n "hgt-$role" link set lo up
    ip -n "hgt-$role" link set eth0 up
done
ip -n hgt-router addr add 10.200.0.1/24 dev eth0
ip -n hgt-gateway addr add 10.200.0.2/24 dev eth0
ip -n hgt-client addr add 10.200.0.3/24 dev eth0
ip -n hgt-gateway route add default via 10.200.0.1
ip -n hgt-client route add default via 10.200.0.2
ip -n hgt-router addr add 203.0.113.1/32 dev lo
cat > "$work/network.json" <<'JSON'
{"lan_ip":"10.200.0.2","lan_cidr":"10.200.0.0/24","interface":"eth0","upstream_dns":"10.200.0.1"}
JSON
cat > "$work/server.py" <<'PY'
from http.server import BaseHTTPRequestHandler,HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.end_headers()
        self.wfile.write(self.client_address[0].encode())
    def log_message(self,*args):pass
HTTPServer(('203.0.113.1',8081),Handler).serve_forever()
PY
ip netns exec hgt-router python3 "$work/server.py" > "$work/server.log" 2>&1 &
server_pid=$!
ip netns exec hgt-gateway nft add table inet hgt_sentinel
ip netns exec hgt-gateway python3 "$sources/network_guard.py" --settings "$work/network.json" --mode direct
sleep 1
observed=$(ip netns exec hgt-client curl --noproxy '*' --fail --silent --max-time 5 http://203.0.113.1:8081/)
test "$observed" = 10.200.0.2
echo 'PASS: one-port NAT sends replies back through the gateway'
ip netns exec hgt-gateway python3 "$sources/network_guard.py" --settings "$work/network.json" --mode rules
if ip netns exec hgt-client curl --noproxy '*' --fail --silent --max-time 3 http://203.0.113.1:8081/ >/dev/null; then
    echo 'FAIL: traffic escaped the rules-mode guard' >&2; exit 1
fi
ip netns exec hgt-gateway nft list table inet hgt_sentinel >/dev/null
test "$(ip netns exec hgt-gateway cat /proc/sys/net/ipv4/conf/eth0/send_redirects)" = 0
echo 'PASS: rules mode blocks native fallback; unrelated firewall tables survive'
ip netns exec hgt-gateway python3 "$sources/network_guard.py" --settings "$work/network.json" --mode direct
observed=$(ip netns exec hgt-client curl --noproxy '*' --fail --silent --max-time 5 http://203.0.113.1:8081/)
test "$observed" = 10.200.0.2
echo 'PASS: all-direct mode restores connectivity'
