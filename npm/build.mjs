#!/usr/bin/env node
// Generates the npm package trees for a release: one package per platform
// holding the prebuilt binary, plus the `husk-sec` package that depends on all
// of them optionally and launches whichever one npm installed.
//
// Usage: node npm/build.mjs --version X.Y.Z --binaries <dir> --out <dir>
//
// <dir> must contain <rust-target>/husk for every target below. A missing
// target is fatal: a partially built release must not produce an npm package
// that silently lacks a platform.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MAIN_PACKAGE = "husk-sec";
const MCP_NAME = "io.github.husk-security/husk";

const TARGETS = [
  // The Linux binaries link glibc, so declaring libc keeps npm from installing
  // them on musl systems where they cannot run.
  { rustTarget: "x86_64-unknown-linux-gnu", os: "linux", cpu: "x64", libc: "glibc" },
  { rustTarget: "aarch64-unknown-linux-gnu", os: "linux", cpu: "arm64", libc: "glibc" },
  { rustTarget: "x86_64-apple-darwin", os: "darwin", cpu: "x64" },
  { rustTarget: "aarch64-apple-darwin", os: "darwin", cpu: "arm64" },
];

const SHARED = {
  license: "MIT",
  author: "Erik Frankling",
  homepage: "https://github.com/husk-security/husk",
  repository: { type: "git", url: "git+https://github.com/husk-security/husk.git" },
  bugs: { url: "https://github.com/husk-security/husk/issues" },
};

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error(`bad arguments near ${key ?? "end of input"}`);
    }
    out[key.slice(2)] = value;
  }
  for (const required of ["version", "binaries", "out"]) {
    if (!out[required]) throw new Error(`missing --${required}`);
  }
  if (!/^\d+\.\d+\.\d+$/.test(out.version)) {
    throw new Error(`--version must be X.Y.Z, got ${out.version}`);
  }
  return out;
}

function platformPackageName({ os, cpu }) {
  return `${MAIN_PACKAGE}-${os}-${cpu}`;
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function buildPlatformPackage(target, { version, binaries, out }) {
  const name = platformPackageName(target);
  const binFile = "husk";
  const source = path.join(binaries, target.rustTarget, binFile);
  if (!fs.existsSync(source)) {
    throw new Error(`missing binary for ${target.rustTarget} at ${source}`);
  }

  const dir = path.join(out, name);
  fs.mkdirSync(path.join(dir, "bin"), { recursive: true });
  fs.copyFileSync(source, path.join(dir, "bin", binFile));
  // npm preserves the mode bits it finds; a non-executable binary would make
  // every launch fail with EACCES.
  fs.chmodSync(path.join(dir, "bin", binFile), 0o755);
  fs.copyFileSync(path.join(ROOT, "LICENSE"), path.join(dir, "LICENSE"));
  fs.writeFileSync(
    path.join(dir, "README.md"),
    `# ${name}\n\nThe husk binary for ${target.os} ${target.cpu}. Install [husk-sec](https://www.npmjs.com/package/${MAIN_PACKAGE}) instead of this package directly.\n`,
  );

  writeJson(path.join(dir, "package.json"), {
    name,
    version,
    description: `husk binary for ${target.os} ${target.cpu}`,
    ...SHARED,
    os: [target.os],
    cpu: [target.cpu],
    ...(target.libc ? { libc: [target.libc] } : {}),
    files: ["bin", "LICENSE", "README.md"],
    // Yarn PnP cannot execute a binary inside a zip archive.
    preferUnplugged: true,
  });

  return { name, dir };
}

function buildMainPackage(targets, { version, out }) {
  const dir = path.join(out, MAIN_PACKAGE);
  fs.mkdirSync(path.join(dir, "bin"), { recursive: true });
  fs.copyFileSync(path.join(ROOT, "npm", "shim.cjs"), path.join(dir, "bin", "husk.cjs"));
  fs.copyFileSync(path.join(ROOT, "LICENSE"), path.join(dir, "LICENSE"));
  fs.copyFileSync(path.join(ROOT, "README.md"), path.join(dir, "README.md"));

  const optionalDependencies = Object.fromEntries(
    targets.map((target) => [platformPackageName(target), version]),
  );

  writeJson(path.join(dir, "package.json"), {
    name: MAIN_PACKAGE,
    version,
    description:
      "Local-first developer security scanner with TUI, localhost web UI, and MCP server",
    ...SHARED,
    keywords: ["security", "scanner", "vulnerabilities", "secrets", "supply-chain", "mcp"],
    // Ownership proof for the MCP Registry: it reads this field back from the
    // published tarball and requires it to equal the server name.
    mcpName: MCP_NAME,
    // `husk` is the command a global install puts on PATH. The second name
    // exists so `npx husk-sec` resolves a bin whose name matches the package
    // rather than relying on npx's single-bin fallback.
    bin: { husk: "bin/husk.cjs", "husk-sec": "bin/husk.cjs" },
    files: ["bin", "LICENSE", "README.md"],
    engines: { node: ">=20.19.0" },
    optionalDependencies,
  });

  return { name: MAIN_PACKAGE, dir };
}

function verifyShim(mainDir) {
  const shim = path.join(mainDir, "bin", "husk.cjs");
  const result = spawnSync(process.execPath, ["--check", shim], { stdio: "pipe" });
  if (result.status !== 0) {
    throw new Error(`shim does not parse: ${result.stderr?.toString() ?? ""}`);
  }
}

const args = parseArgs(process.argv.slice(2));
fs.rmSync(args.out, { recursive: true, force: true });
const built = TARGETS.map((target) => buildPlatformPackage(target, args));
const main = buildMainPackage(TARGETS, args);
verifyShim(main.dir);
built.push(main);

for (const { name, dir } of built) {
  process.stdout.write(`${name}\t${dir}\n`);
}
