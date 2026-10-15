#!/bin/bash
# Reproducible userspace build on an x86_64 Linux VPS. Does not change networking.
set -euo pipefail
test "$(uname -sm)" = 'Linux x86_64'
build_directory=${1:?Usage: build_awg.sh PRIVATE_BUILD_DIRECTORY}
install -d -m 700 "$build_directory"
cd "$build_directory"
download() {
    if [ ! -f "$2" ]; then
        curl -fLsS --connect-timeout 10 --max-time 180 "$1" -o "$2.partial"
        mv "$2.partial" "$2"
    fi
}
download https://go.dev/dl/go1.27.2.linux-amd64.tar.gz go-toolchain.tar.gz
printf '%s\n' 'ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5  go-toolchain.tar.gz' | sha256sum -c -
test -x go/bin/go || tar -xzf go-toolchain.tar.gz
download https://codeload.github.com/amnezia-vpn/amneziawg-go/tar.gz/b5928efb6ca19f0153958460c3d141f04abc5c2e awg-go-source.tar.gz
install -d -m 700 source
test -f source/go.mod || tar -xzf awg-go-source.tar.gz --strip-components=1 -C source
download https://github.com/amnezia-vpn/amneziawg-tools/releases/download/v3.1.20260812/ubuntu-22.04-amneziawg-tools.zip tools.zip
printf '%s\n' '919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56  tools.zip' | sha256sum -c -
download https://codeload.github.com/amnezia-vpn/amneziawg-tools/tar.gz/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843 awg-tools-source.tar.gz
install -d -m 700 output
python3 - <<'PY'
from pathlib import Path
import zipfile
Path('output/awg-amd64').write_bytes(zipfile.ZipFile('tools.zip').read('ubuntu-22.04-amneziawg-tools/awg'))
PY
printf 'package main\n\nconst Version = "v3.1.20260828"\n' > source/version.go
export GOTOOLCHAIN=local CGO_ENABLED=0 GOMAXPROCS=2 GOOS=linux
export PATH="$PWD/go/bin:$PATH"
for architecture in amd64 arm64; do
    (cd source; GOARCH="$architecture" go build -p=2 -trimpath -ldflags='-s -w' -o "../output/amneziawg-go-$architecture" .)
done
chmod 755 output/*
sha256sum output/*
echo 'Built official pinned AWG 3.1 for amd64 and arm64; no network interface was created.'
