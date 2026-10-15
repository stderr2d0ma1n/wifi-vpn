#!/bin/bash
# A local CDC-ECM management link; does not route traffic or expose storage.
set -eu
gadget=/sys/kernel/config/usb_gadget/home_gateway
modprobe libcomposite
if ! mountpoint -q /sys/kernel/config; then
    mount -t configfs none /sys/kernel/config
fi
mkdir -p "$gadget"
if [ -z "$(cat "$gadget/UDC")" ]; then
    printf '0x1d6b\n' > "$gadget/idVendor"
    printf '0x0104\n' > "$gadget/idProduct"
    printf '0x0100\n' > "$gadget/bcdDevice"
    printf '0x0200\n' > "$gadget/bcdUSB"
    mkdir -p "$gadget/strings/0x409" "$gadget/configs/c.1/strings/0x409"
    serial=$(sha256sum /etc/machine-id | cut -c1-24)
    printf '%s\n' "$serial" > "$gadget/strings/0x409/serialnumber"
    printf 'Home Gateway\n' > "$gadget/strings/0x409/manufacturer"
    printf 'Home Gateway USB SSH\n' > "$gadget/strings/0x409/product"
    printf 'USB management\n' > "$gadget/configs/c.1/strings/0x409/configuration"
    printf '0xc0\n' > "$gadget/configs/c.1/bmAttributes"
    printf '2\n' > "$gadget/configs/c.1/MaxPower"
    mkdir -p "$gadget/functions/ecm.usb0"
    suffix=$(printf '%s' "$serial" | sed -E 's/^(.{2})(.{2})(.{2})(.{2}).*/\1:\2:\3:\4/')
    printf '02:%s:01\n' "$suffix" > "$gadget/functions/ecm.usb0/dev_addr"
    printf '02:%s:02\n' "$suffix" > "$gadget/functions/ecm.usb0/host_addr"
    if [ ! -L "$gadget/configs/c.1/ecm.usb0" ]; then
        ln -s "$gadget/functions/ecm.usb0" "$gadget/configs/c.1/ecm.usb0"
    fi
    controller=''
    for attempt in $(seq 1 30); do
        for path in /sys/class/udc/*; do
            [ -e "$path" ] || continue
            controller=$(basename "$path")
            break
        done
        [ -z "$controller" ] || break
        sleep 1
    done
    [ -n "$controller" ] || { echo 'No USB device controller available' >&2; exit 1; }
    printf '%s\n' "$controller" > "$gadget/UDC"
fi
ip link set usb0 up
ip address replace 169.254.77.1/16 dev usb0
