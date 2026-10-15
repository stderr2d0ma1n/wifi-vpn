#!/usr/bin/env python3
"""Read DHCP router/DNS options using DHCPINFORM; does not obtain/change a lease."""
import argparse
import ipaddress
import json
import secrets
import socket
import struct
import time
from pathlib import Path


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return ~total & 65535


def options(data):
    found = {}
    index = 0
    while index < len(data):
        code = data[index]
        index += 1
        if code == 255:
            break
        if code == 0:
            continue
        if index >= len(data):
            break
        size = data[index]
        index += 1
        found[code] = data[index:index + size]
        index += size
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--client-ip', required=True)
    args = parser.parse_args()
    if '/' in args.interface or args.interface in ('', '.', '..'):
        parser.error('Invalid interface')
    address = ipaddress.IPv4Address(args.client_ip)
    mac = bytes.fromhex((Path('/sys/class/net') / args.interface / 'address').read_text().strip().replace(':', ''))
    xid = secrets.randbits(32)
    bootp = struct.pack('!BBBBIHH4s4s4s4s16s64s128s', 1, 1, 6, 0, xid, 0, 0x8000,
                        address.packed, b'\0' * 4, b'\0' * 4, b'\0' * 4,
                        mac + b'\0' * 10, b'\0' * 64, b'\0' * 128)
    payload = bootp + bytes.fromhex('63825363') + bytes([53, 1, 8, 55, 3, 1, 3, 6, 255])
    payload += b'\0' * max(0, 300 - len(payload))
    udp = struct.pack('!HHHH', 68, 67, 8 + len(payload), 0)
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp) + len(payload),
                         0, 0, 64, 17, 0, address.packed, b'\xff' * 4)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    frame = b'\xff' * 6 + mac + b'\x08\x00' + header + udp + payload
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw:
        raw.bind((args.interface, 0))
        raw.settimeout(1)
        raw.send(frame)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                packet = raw.recv(4096)
            except socket.timeout:
                continue
            if len(packet) < 42 or packet[14] >> 4 != 4 or packet[23] != 17:
                continue
            start = 14 + (packet[14] & 15) * 4
            if packet[start:start + 4] != struct.pack('!HH', 67, 68):
                continue
            reply = packet[start + 8:]
            if len(reply) < 240 or reply[0] != 2 or struct.unpack('!I', reply[4:8])[0] != xid:
                continue
            parsed = options(reply[240:])
            if parsed.get(53) != bytes([5]):
                continue
            decode = lambda code: [str(ipaddress.IPv4Address(parsed[code][i:i + 4]))
                                   for i in range(0, len(parsed.get(code, b'')), 4)]
            print(json.dumps({'message': 'DHCPACK to DHCPINFORM', 'router': decode(3),
                              'dns': decode(6), 'server': decode(54)}, indent=2))
            return
    raise SystemExit('No DHCPINFORM reply; router may not support this query')


if __name__ == '__main__':
    main()
