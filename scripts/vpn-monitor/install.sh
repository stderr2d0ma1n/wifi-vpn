#!/bin/bash
# Install the read-only module; never modify gateway or VPN profiles.
set -euo pipefail
test "$(id -u)" -eq 0
module_source=$(realpath "${1:?SOURCE_DIRECTORY}")
module_config=$(realpath "${2:?PUBLIC_CONFIGURATION_JSON}")
test "$(cat /etc/home-gateway/mode)" = direct
test ! -e /etc/vpn-monitor/config.json
test -f /etc/systemd/system/home-awg-probe.service
command -v python3 >/dev/null
command -v curl >/dev/null
groupadd --system vpn-monitor
useradd --system --gid vpn-monitor --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vpn-monitor
useradd --system --gid vpn-monitor --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vpn-monitor-api
install -d -m 755 /usr/local/lib/vpn-monitor
install -d -m 750 -g vpn-monitor /etc/vpn-monitor /var/lib/vpn-monitor
install -d -m 750 -o vpn-monitor -g vpn-monitor /var/lib/vpn-monitor-updates
install -m 644 "$module_source/monitor.py" "$module_source/manifest.json" /usr/local/lib/vpn-monitor/
install -m 640 -g vpn-monitor "$module_config" /etc/vpn-monitor/config.json
install -m 644 "$module_source"/*.service "$module_source"/*.timer /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/vpn-monitor-*.service /etc/systemd/system/vpn-monitor-*.timer
systemctl daemon-reload
systemctl start vpn-monitor-health.service
systemctl start vpn-monitor-updates.service
systemctl enable --now vpn-monitor-health.timer vpn-monitor-updates.timer vpn-monitor-api.service
python3 /usr/local/lib/home-awg/awg_runtime.py verify-baseline
python3 /usr/local/lib/vpn-monitor/monitor.py status
