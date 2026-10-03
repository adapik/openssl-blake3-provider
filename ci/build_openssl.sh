#!/bin/sh
set -eu
VER=$1; PREFIX=$2
[ -x "$PREFIX/bin/openssl" ] && { echo "already built: $PREFIX"; exit 0; }
W=$(mktemp -d); cd "$W"
curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-$VER/openssl-$VER.tar.gz" | tar xz
cd "openssl-$VER"
./Configure --prefix="$PREFIX" --libdir=lib no-docs no-tests "-Wl,-rpath,$PREFIX/lib" >/dev/null
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >/dev/null
make install_sw >/dev/null
LD_LIBRARY_PATH="$PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" DYLD_LIBRARY_PATH="$PREFIX/lib" "$PREFIX/bin/openssl" version
