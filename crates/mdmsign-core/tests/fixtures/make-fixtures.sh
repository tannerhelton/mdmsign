#!/bin/bash
# Regenerates unsigned.pkg, a tiny unsigned flat package used by the tests.
# Requires macOS (pkgbuild). The output is committed so tests also run on Linux.
set -euo pipefail
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root/usr/local/share/mdmsign-fixture"
printf 'mdmsign test fixture\n' > "$work/root/usr/local/share/mdmsign-fixture/README.txt"
pkgbuild --root "$work/root" --identifier com.example.mdmsign.fixture \
    --version 1.0 --install-location / unsigned.pkg
