#!/bin/bash
# Called by Armbian once, after its unattended first-login setup.
set -eu
key=/root/home-gateway-ssh.pub
test -s "$key"
id gateway >/dev/null
gateway_home=$(getent passwd gateway | cut -d: -f6)
test -n "$gateway_home"
install -d -m 700 /root/.ssh "$gateway_home/.ssh"
install -m 600 "$key" /root/.ssh/authorized_keys
install -m 600 "$key" "$gateway_home/.ssh/authorized_keys"
chown gateway:gateway "$gateway_home/.ssh" "$gateway_home/.ssh/authorized_keys"
hostnamectl set-hostname home-gateway
/usr/sbin/sshd -t
systemctl restart ssh.service
install -d -m 755 /var/lib/home-gateway
touch /var/lib/home-gateway/bootstrap.done
