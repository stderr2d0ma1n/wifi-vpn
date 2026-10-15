#!/usr/bin/env python3
"""Independently validate a Rockchip BOOT container against its DDR/UsbPlug inputs."""
import argparse
import struct
from pathlib import Path


def rc4(data):
    # Public Rockchip boot protocol constant, from rockchip-linux/rkdeveloptool.
    key = bytes([124, 78, 3, 4, 85, 5, 9, 7, 45, 44, 123, 56, 23, 13, 23, 17])
    state = list(range(256))
    index = 0
    for position in range(256):
        index = (index + state[position] + key[position % len(key)]) % 256
        state[position], state[index] = state[index], state[position]
    position = index = 0
    output = bytearray()
    for value in data:
        position = (position + 1) % 256
        index = (index + state[position]) % 256
        state[position], state[index] = state[index], state[position]
        output.append(value ^ state[(state[position] + state[index]) % 256])
    return bytes(output)


def checksum(data):
    # Rockchip uses 0x04c10db7 with a zero initial value, rather than IEEE CRC32.
    table = []
    for value in range(256):
        item = value << 24
        for _ in range(8):
            item = ((item << 1) ^ (0x04c10db7 if item & 0x80000000 else 0)) & 0xffffffff
        table.append(item)
    result = 0
    for value in data:
        result = ((result << 8) ^ table[(result >> 24) ^ value]) & 0xffffffff
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--loader', type=Path, required=True)
    parser.add_argument('--ddr', type=Path, required=True)
    parser.add_argument('--usbplug', type=Path, required=True)
    args = parser.parse_args()
    blob = args.loader.read_bytes()
    if blob[:4] != b'BOOT' or len(blob) < 106:
        raise SystemExit('Not a BOOT loader')
    if checksum(blob[:-4]) != struct.unpack_from('<I', blob, len(blob) - 4)[0]:
        raise SystemExit('Rockchip loader CRC mismatch')
    for header_offset, expected_file in [(25, args.ddr), (31, args.usbplug)]:
        count = blob[header_offset]
        entries = struct.unpack_from('<I', blob, header_offset + 1)[0]
        entry_size = blob[header_offset + 5]
        if count != 1 or entry_size != 57 or entries + entry_size > len(blob) - 4:
            raise SystemExit('Unexpected loader entry layout')
        data_offset, size = struct.unpack_from('<II', blob, entries + 45)
        if data_offset + size > len(blob) - 4:
            raise SystemExit('Loader entry exceeds container')
        plain = rc4(blob[data_offset:data_offset + size])
        expected = expected_file.read_bytes()
        if plain[:len(expected)] != expected or any(plain[len(expected):]):
            raise SystemExit('Decoded entry differs from official component: ' + expected_file.name)
        print('Verified complete component:', expected_file.name, len(expected), 'bytes')
    print('BOOT container CRC and RAM payloads passed independent validation')


if __name__ == '__main__':
    main()
