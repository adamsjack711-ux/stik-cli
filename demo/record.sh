#!/usr/bin/env bash
# Build stik and record the README demo GIF with vhs. Fully reproducible:
# fictional device data, no live capture, no privileges.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v vhs >/dev/null || { echo "vhs not found — install with: brew install vhs"; exit 1; }

echo "building stik…"
go build -o stik ./cmd/stik

echo "recording demo/stik.gif…"
vhs demo/stik.tape

echo "done → demo/stik.gif"
