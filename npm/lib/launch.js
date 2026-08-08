'use strict';

// Thin Node shim: locate the bundled Go binary for this platform (or a
// STIK_BIN override) and exec it, passing through argv, stdio, and exit code.
// The npm package is just a delivery vehicle for the compiled `stik` binary.

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

function isExecutable(p) {
  try {
    fs.accessSync(p, fs.constants.X_OK);
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function launch(name) {
  const override = process.env[`${name.toUpperCase()}_BIN`];
  const bundled = path.join(
    __dirname,
    '..',
    'dist',
    `${process.platform}-${process.arch}`,
    name
  );

  const bin = [override, bundled].filter(Boolean).find(isExecutable);

  if (!bin) {
    console.error(
      `${name}: no prebuilt binary for ${process.platform}-${process.arch}.`
    );
    console.error(
      'stik ships macOS arm64 and Linux x64/arm64 binaries. On other platforms,'
    );
    console.error(
      'build from source (needs Go 1.26+ and libpcap):'
    );
    console.error(
      '  go install github.com/adamsjack711-ux/stik-cli/cmd/stik@latest'
    );
    console.error(
      `then point ${name.toUpperCase()}_BIN at the resulting binary.`
    );
    process.exit(1);
  }

  const result = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });
  if (result.error) {
    console.error(`${name}: ${result.error.message}`);
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}

module.exports = launch;
