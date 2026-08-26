#!/usr/bin/env node
// Launcher for the `husk` binary shipped in the matching optional platform
// package. stdio is inherited unchanged because this process is what an MCP
// client spawns: any wrapping or buffering of stdout would corrupt the
// JSON-RPC stream.
"use strict";

const { spawnSync } = require("node:child_process");

const PLATFORM_PACKAGES = {
  "linux-x64": "husk-sec-linux-x64",
  "linux-arm64": "husk-sec-linux-arm64",
  "darwin-x64": "husk-sec-darwin-x64",
  "darwin-arm64": "husk-sec-darwin-arm64",
};

function fail(message) {
  process.stderr.write(`husk: ${message}\n`);
  process.exit(1);
}

function resolveBinary() {
  const key = `${process.platform}-${process.arch}`;
  const pkg = PLATFORM_PACKAGES[key];
  if (!pkg) {
    const hint =
      process.platform === "win32"
        ? "husk has no native Windows build; install it inside WSL"
        : "install from source instead: cargo install husk-sec";
    fail(`no prebuilt binary for ${key}. ${hint}`);
  }
  try {
    return require.resolve(`${pkg}/bin/husk`);
  } catch {
    fail(
      `the ${pkg} package is missing. Reinstall husk-sec, or if optional dependencies were skipped, install ${pkg} directly.`,
    );
  }
}

const result = spawnSync(resolveBinary(), process.argv.slice(2), {
  stdio: "inherit",
});

if (result.error) {
  fail(`could not run the husk binary: ${result.error.message}`);
}

// A signalled child has a null status. Report it the way a shell does so
// callers can tell a crash from a clean non-zero exit.
process.exit(result.status === null ? 128 : result.status);
