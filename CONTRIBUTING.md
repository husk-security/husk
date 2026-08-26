# Contributing to husk

husk is a local-first security scanner for developer machines, shipped as one
Rust binary with a CLI, a TUI, a localhost web UI, and an MCP server.

## Build and test

```sh
cargo build --no-default-features
cargo test --no-default-features
```

Those need Rust 1.95 or newer and nothing else. The default `web` feature embeds
a Vite app, so a plain `cargo build` needs `npm --prefix web ci && npm --prefix
web run build` first. [AGENTS.md](AGENTS.md) describes the module layout.

## Pull requests

Open one. CI runs on every pull request and reports what needs fixing.

Scans must stay read-only: parse files statically, and never execute package
managers, install scripts, MCP servers, or repository code.

For a vulnerability in husk itself, do not open a public issue. See
[SECURITY.md](SECURITY.md).

Contributions are licensed under the [MIT License](LICENSE).
