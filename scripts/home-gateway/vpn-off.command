#!/bin/bash
# User-run emergency button for macOS. Requires the separately installed SSH alias.
set -u
gateway_config=${HOME_GATEWAY_SSH_CONFIG:-"$HOME/.ssh/home-gateway.config"}
printf 'Отключение домашнего VPN через Orange Pi…\n\n'
if ssh -F "$gateway_config" -o ConnectTimeout=8 -o BatchMode=yes \
    home-gateway sudo gatewayctl direct; then
    printf '\nVPN отключён. Интернет идёт напрямую, Orange Pi остаётся шлюзом.\n'
else
    printf '\nНе удалось подключиться к Orange Pi.\n'
    printf 'Открой http://10.0.0.1 → Сеть → DHCP-сервер.\n'
    printf 'Верни шлюз и оба DNS на 10.0.0.1, сохрани и переподключи Wi-Fi.\n'
fi
printf '\nНажми Enter, чтобы закрыть окно. '
read -r _
