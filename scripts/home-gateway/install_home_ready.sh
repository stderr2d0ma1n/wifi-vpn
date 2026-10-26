#!/bin/bash
# Upgrade an existing direct gateway; never invoke trial/rules or restart sing-box.
set -euo pipefail
test "$(id -u)" -eq 0
source_dir=$(realpath "${1:?SOURCE_DIRECTORY}")
public_settings=$(realpath "${2:?PUBLIC_PREPARATION_JSON}")
test "$(cat /etc/home-gateway/mode)" = direct
backup_dir=$(mktemp -d /var/backups/home-gateway/home-ready.XXXXXX)
chmod 700 "$backup_dir"
cp -a /usr/local/lib/home-gateway "$backup_dir/source-before"
cp -a /etc/home-gateway "$backup_dir/settings-before"
cp -a /etc/sing-box/config.json "$backup_dir/main-config-before.json"
for name in gatewayctl.py gateway_cli.py gateway_safety.py auto_return.py awg_uplink.py build_config.py network_guard.py fallback_dns.py prepare_rule_sets.py verify_home_ready.py; do
    install -m 644 "$source_dir/$name" /usr/local/lib/home-gateway/
done
chmod 755 /usr/local/lib/home-gateway/gatewayctl.py
install -d -m 750 -g vpn-monitor /var/lib/home-gateway-control
for name in home-gateway-watchdog.service home-gateway-watchdog.timer home-gateway-fallback-dns.service home-gateway-lab.service home-gateway-lab-dns.service; do
    install -m 644 "$source_dir/$name" /etc/systemd/system/
done
python3 /usr/local/lib/home-gateway/prepare_rule_sets.py
python3 - "$public_settings" <<'PY'
import grp,json,sys
from pathlib import Path
sys.path.insert(0,'/usr/local/lib/home-gateway')
from gateway_safety import Gateway,atomic
settings=json.load(open(sys.argv[1]))
base=Path('/etc/home-gateway')
atomic(base/'awg-outbound.json',{'type':'direct','tag':'vps','bind_interface':'awg-home'})
atomic(base/'safety.json',{'expected_exit_ip':settings['expected_exit_ip']})
policy=json.loads((base/'policy.json').read_text())
policy.setdefault('direct_cidrs',[])
policy.setdefault('vpn_cidrs',[])
policy['direct_client_ips']=sorted(set(policy.get('direct_client_ips',[])+settings.get('direct_client_ips',[])))
manifest=json.loads(Path('/var/lib/home-gateway-rules/manifest.json').read_text())
policy['rule_sets']=[{key:row[key] for key in ('tag','role','path')} for row in manifest['rule_sets']]
atomic(base/'policy.json',policy)
gateway=Gateway()
gateway.validate(gateway.build('rules'))
assert gateway.build('direct')==json.loads(Path('/etc/sing-box/config.json').read_text()),'Direct configuration unexpectedly differs'
atomic('/etc/home-gateway-fallback.json',{'listen':gateway.network['lan_ip'],'lan_cidr':gateway.network['lan_cidr'],
                                      'upstream':gateway.network['upstream_dns']},0o640,'sing-box')
PY
systemd-analyze verify /etc/systemd/system/home-gateway-watchdog.service /etc/systemd/system/home-gateway-fallback-dns.service /etc/systemd/system/home-gateway-lab.service /etc/systemd/system/home-gateway-lab-dns.service
systemctl daemon-reload
# Watch is idle while the current direct service is healthy.
systemctl enable --now home-gateway-watchdog.timer
/usr/local/sbin/gatewayctl prepare
test "$(cat /etc/home-gateway/mode)" = direct
