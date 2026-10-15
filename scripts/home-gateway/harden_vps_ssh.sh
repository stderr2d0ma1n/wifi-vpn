#!/bin/bash
# Run over a separately verified root key SSH connection on the prepared VPS.
set -euo pipefail
test "$(id -u)" -eq 0
test -n "${SSH_CONNECTION:-}" || { echo 'Run through verified key-based SSH' >&2; exit 1; }
test -s /root/.ssh/authorized_keys
configuration=/etc/ssh/sshd_config.d/00-home-vps.conf
test ! -e "$configuration" || { echo 'Existing SSH policy needs review' >&2; exit 1; }
rollback() {
    rm -f "$configuration"
    sshd -t && systemctl reload ssh.service
}
trap rollback ERR
install -d -m 755 /etc/ssh/sshd_config.d
cat > "$configuration" <<'SSH'
# Dedicated administrator key was tested before applying this policy.
PubkeyAuthentication yes
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
SSH
chmod 644 "$configuration"
sshd -t
effective=$(sshd -T)
printf '%s\n' "$effective" | grep -qx 'pubkeyauthentication yes'
printf '%s\n' "$effective" | grep -qx 'passwordauthentication no'
printf '%s\n' "$effective" | grep -qx 'kbdinteractiveauthentication no'
printf '%s\n' "$effective" | grep -Eq '^permitrootlogin (without-password|prohibit-password)$'
systemctl reload ssh.service
trap - ERR
echo 'SSH accepts administrator keys; password and keyboard-interactive SSH are disabled.'
echo 'Verify a second fresh key connection before closing the current session.'
