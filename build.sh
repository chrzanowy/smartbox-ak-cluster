#!/bin/sh
# Build build/ak_202610081659_hook from the vendor package ak_202610081659 and src/altscreen_ak.c.
# Needs: zig (C compiler + ld.lld), python3. The vendor package is fetched with tools/fetch_vendor.py.
set -eu
cd "$(dirname "$0")"
VER=ak_202610081659
[ -f "vendor/$VER" ] || python3 -I tools/fetch_vendor.py "$VER" vendor
mkdir -p build/vendor-x
tar xf "vendor/$VER" -C build/vendor-x
zig cc -target arm-linux-gnueabi -mcpu=arm926ej_s -marm -fPIC -Os -ffreestanding -fno-stack-protector \
  -fno-builtin -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-exceptions -Wall \
  -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast -c -o build/altscreen_ak.o src/altscreen_ak.c
zig ld.lld -shared --no-rosegment -z norelro -z lazy --hash-style=sysv -soname libSdH.so \
  -z max-page-size=0x10000 -o build/libSdH.so build/altscreen_ak.o
python3 -I tools/build_ak_hook.py build/vendor-x build/libSdH.so build/out
echo "package: build/out/${VER}_hook"
