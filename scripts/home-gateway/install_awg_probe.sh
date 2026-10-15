#!/bin/bash
# Configure only a new namespace, not the main routing/DNS/forwarding policy.
set -euo pipefail
test "$(id -u)" -eq 0
sources=$(realpath "${1:?SOURCE_DIR}")
private_configuration=$(realpath "${2:?PRIVATE_DEVICE_CONFIGURATION}")
test "$(cat /etc/home-gateway/mode)" = direct
test ! -e /etc/home-awg-probe
test ! -e /run/netns/home-awg-test
test ! -e /etc/netns/home-awg-test
command -v awg >/dev/null
command -v amneziawg-go >/dev/null
install -d -m 700 /etc/home-awg-probe
install -m 600 "$private_configuration" /etc/home-awg-probe/orange-device.conf
install -d -m 755 /usr/local/lib/home-awg
install -m 644 "$sources/awg_runtime.py" /usr/local/lib/home-awg/
install -m 644 "$sources/home-awg-probe.service" /etc/systemd/system/home-awg-probe.service
install -m 644 "$sources/home-awg-probe-network.service" /etc/systemd/system/home-awg-probe-network.service
systemd-analyze verify /etc/systemd/system/home-awg-probe.service /etc/systemd/system/home-awg-probe-network.service
systemctl daemon-reload
# A probe is started on demand and is deliberately not enabled for boot.
systemctl start home-awg-probe.service
python3 /usr/local/lib/home-awg/awg_runtime.py verify-baseline
echo 'AWG test namespace ready. Home gateway remains direct.'
