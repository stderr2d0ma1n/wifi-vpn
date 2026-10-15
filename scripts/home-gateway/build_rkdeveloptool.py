#!/usr/bin/env python3
"""Build official Rockchip sources on macOS using an existing libusb installation."""
import argparse
import shutil
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--libusb-prefix', type=Path, required=True)
    args = parser.parse_args()
    if args.build_dir.exists():
        raise SystemExit('Build directory must be new; existing sources are preserved')
    required = ['main.cpp', 'RKComm.cpp', 'RKScan.cpp', 'DefineHeader.h', 'license.txt']
    if any(not (args.source / name).is_file() for name in required):
        raise SystemExit('Expected the official rockchip-linux/rkdeveloptool source tree')
    shutil.copytree(args.source, args.build_dir)
    main_cpp = args.build_dir / 'main.cpp'
    code = main_cpp.read_text()
    # Clang C++ requires compile-time constants for these fixed-size buffers.
    code = code.replace('int nSectorSize = 512;', 'const int nSectorSize = 512;')
    # The upstream pack parser reads one-based LOADER1/LOADER2 into a zero-based
    # array. Normalize the index before copying, as its other entry parsers do.
    needle = '\t\tstrcpy(gOpts.loader[index].name, buf);'
    if code.count(needle) != 1:
        raise SystemExit('Unexpected upstream loader parser; inspect before building')
    code = code.replace(needle, '\t\tindex--;\n' + needle)
    # Modern DDR/UsbPlug components exceed 64 KiB; the old unsigned-short RC4
    # length truncates their encryption. Keep the packer prototype in sync.
    code = code.replace('P_RC4(unsigned char* buf, unsigned short len)',
                        'P_RC4(unsigned char* buf, unsigned int len)')
    main_cpp.write_text(code)
    crc_file = args.build_dir / 'crc.cpp'
    crc_code = crc_file.read_text()
    needle = 'void P_RC4(unsigned char* buf, unsigned short len)'
    if crc_code.count(needle) != 1:
        raise SystemExit('Unexpected upstream RC4 signature; inspect before building')
    crc_code = crc_code.replace(needle, 'void P_RC4(unsigned char* buf, unsigned int len)')
    crc_code = crc_code.replace('unsigned short i,j,t,x;',
                                'unsigned short i,j,t;\n\tunsigned int x;')
    crc_file.write_text(crc_code)
    comm_header = args.build_dir / 'RKComm.h'
    header = comm_header.read_text()
    if '#define CMD_TIMEOUT 0' not in header:
        raise SystemExit('Unexpected upstream USB timeout; inspect before building')
    # The original infinite timeout can hang on a rejected USB transfer.
    comm_header.write_text(header.replace('#define CMD_TIMEOUT 0', '#define CMD_TIMEOUT 10000'))
    (args.build_dir / 'config.h').write_text('#define PACKAGE_VERSION "1.3"\n')
    source_files = sorted(str(p.resolve()) for p in args.build_dir.glob('*.cpp'))
    output = (args.build_dir / 'rkdeveloptool').resolve()
    command = [
        'clang++', '-O2', '-std=c++11', '-fno-strict-aliasing',
        '-D_FILE_OFFSET_BITS=64', '-D_LARGE_FILE',
        '-I' + str(args.build_dir.resolve()),
        '-I' + str((args.libusb_prefix / 'include/libusb-1.0').resolve()),
        '-L' + str((args.libusb_prefix / 'lib').resolve()),
        *source_files, '-lusb-1.0', '-o', str(output),
    ]
    subprocess.run(command, check=True)
    print(output)
    # A build never opens a USB device or flashes storage.


if __name__ == '__main__':
    main()
