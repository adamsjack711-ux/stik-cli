#!/usr/bin/env bash
# Stage the npm package: compile the Go binary into dist/<platform>-<arch>/ and
# pull in the README (with an absolute GIF URL so it renders on npmjs.com) and
# LICENSE.
#
# cgo + libpcap means each target needs a NATIVE build — this script builds for
# the host's GOOS/GOARCH. Multi-platform releases run this once per native
# runner in .github/workflows/release.yml, not via cross-compile.
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(node -p "require('./package.json').version")

GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
# npm dist dirs use Node's process.arch naming (Go amd64 -> Node x64).
case "$GOARCH" in
  amd64) NODE_ARCH=x64 ;;
  arm64) NODE_ARCH=arm64 ;;
  *)     NODE_ARCH="$GOARCH" ;;
esac
DIST="dist/${GOOS}-${NODE_ARCH}"

mkdir -p "$DIST"
echo "building stik-net $VERSION for ${GOOS}/${GOARCH} -> ${DIST}…"
CGO_ENABLED=1 \
  go build -ldflags "-s -w -X main.version=$VERSION" -o "$DIST/stik-net" ../cmd/stik-net

cp ../LICENSE .

# npm renders README.md from a flat package, so rewrite the relative GIF path to
# an absolute raw.githubusercontent URL.
sed 's#demo/stik.gif#https://raw.githubusercontent.com/adamsjack711-ux/stik-cli/main/demo/stik.gif#g' \
  ../README.md > README.md

echo "staged npm/ (${DIST}/stik-net, README.md, LICENSE)"
