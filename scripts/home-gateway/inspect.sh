#!/bin/sh
# Read-only preflight for a Linux single-board computer. No passwords or keys.
set -u

section() { printf '\n[%s]\n' "$1"; }
section system
uname -a
test ! -r /etc/os-release || cat /etc/os-release
test ! -r /etc/armbian-release || cat /etc/armbian-release
if test -r /proc/device-tree/model; then
    tr '\000' '\n' < /proc/device-tree/model
fi
section resources
free -h
df -h / /boot 2>/dev/null || true
section network
ip -brief address
ip -4 route
ip -6 route
section network_managers
for service in NetworkManager systemd-networkd networking systemd-resolved sing-box dnsmasq; do
    printf '%s: ' "$service"
    systemctl is-active "$service" 2>/dev/null || true
done
section network_capabilities
test ! -e /dev/net/tun || ls -l /dev/net/tun
for key in net.ipv4.ip_forward net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_redirects; do
    sysctl "$key" 2>/dev/null || true
done
section listeners
ss -lntup 2>/dev/null || true
section ethernet
for path in /sys/class/net/*; do
    interface=${path##*/}
    test "$interface" != lo || continue
    printf '%s: ' "$interface"
    cat "$path/operstate" 2>/dev/null || true
    if command -v ethtool >/dev/null 2>&1; then
        ethtool "$interface" 2>/dev/null | sed -n '/Speed:/p; /Duplex:/p; /Link detected:/p'
    fi
done
section tools
for tool in python3 nft ip curl sing-box; do
    command -v "$tool" || true
done
