#!/usr/bin/env bash
# Stage the npm package: compile the Go binary into dist/<platform>/ and pull in
# the README (with an absolute GIF URL so it renders on npmjs.com) and LICENSE.
#
# cgo + libpcap means each target needs a native build — this script builds for
# the host's darwin/arm64. Add other platforms via CI runners, not cross-compile.
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(node -p "require('./package.json').version")

mkdir -p dist/darwin-arm64
echo "building stik $VERSION for darwin/arm64…"
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -ldflags "-s -w -X main.version=$VERSION" -o dist/darwin-arm64/stik ../cmd/stik

cp ../LICENSE .

# npm renders README.md from a flat package, so rewrite the relative GIF path to
# an absolute raw.githubusercontent URL.
sed 's#demo/stik.gif#https://raw.githubusercontent.com/adamsjack711-ux/stik-cli/main/demo/stik.gif#g' \
  ../README.md > README.md

echo "staged npm/ (dist/darwin-arm64/stik, README.md, LICENSE)"
