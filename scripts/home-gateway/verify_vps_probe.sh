#!/bin/bash
# Real TCP and UDP/DNS checks through the independent loopback-only VPS probe.
set -euo pipefail
test "$(cat /etc/home-gateway/mode)" = direct
systemctl is-active --quiet sing-box.service
systemctl is-active --quiet home-vps-probe.service
expected_ip=$(python3 -c 'import json; print(json.load(open("/etc/home-gateway/vps-outbound.json"))["server"])')
curl -fsS --proxy socks5h://127.0.0.1:18080 --connect-timeout 10 --max-time 30 \
    https://www.cloudflare.com/cdn-cgi/trace | python3 -c '
import ipaddress,sys
data=dict(line.rstrip().split("=",1) for line in sys.stdin if "=" in line)
if ipaddress.ip_address(data.get("ip", "")) != ipaddress.ip_address(sys.argv[1]):
    raise SystemExit("Unexpected public exit IP")
for key in ["ip","loc","tls"]:
    if key not in data:raise SystemExit("Missing trace field: "+key)
    print(key+"="+data[key])
' "$expected_ip"
curl -fsS --proxy socks5h://127.0.0.1:18080 --connect-timeout 10 --max-time 30 \
    https://example.com/ -o /dev/null
answer=$(dig @127.0.0.1 -p 1053 example.com A +short +time=10 +tries=1)
printf '%s\n' "$answer" | python3 -c '
import ipaddress,sys
addresses=[]
for line in sys.stdin:
    try:addresses.append(ipaddress.IPv4Address(line.strip()))
    except ValueError:pass
if not addresses:raise SystemExit("DNS over VLESS failed")
print("DNS over VLESS: OK")
'
test "$(cat /etc/home-gateway/mode)" = direct
echo 'HTTPS and UDP/DNS passed through the VPS. Home gateway remains in direct mode.'
