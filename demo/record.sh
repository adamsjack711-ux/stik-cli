#!/usr/bin/env bash
# Build stik and record the README demo GIF with vhs. Fully reproducible:
# fictional device data, no live capture, no privileges.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v vhs >/dev/null || { echo "vhs not found — install with: brew install vhs"; exit 1; }

echo "building stik-net…"
go build -o stik-net ./cmd/stik-net

echo "recording demo/stik.gif…"
vhs demo/stik.tape

echo "done → demo/stik.gif"
