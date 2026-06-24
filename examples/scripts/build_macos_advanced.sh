#!/bin/bash
#
# Build the advanced macOS x86_64 test binary used by
# examples/hello_x8664_macos_advanced_nodyld.py.
#
# Requires a macOS host with the Xcode command-line tools (clang). The compiled
# binary is dynamically linked against libSystem; the no-dyld example runs it
# without a dynamic linker by stubbing the imports.
#
# Run from the repository root:  ./examples/scripts/build_macos_advanced.sh

set -e

HERE="$(cd "$(dirname "$0")/.." && pwd)"   # examples/
SRC="$HERE/src/macos/x8664_advanced.c"
OUT="$HERE/rootfs/x8664_macos/bin/x8664_advanced"

clang -arch x86_64 -mmacosx-version-min=10.13 -O0 -o "$OUT" "$SRC"

echo "built $OUT"
