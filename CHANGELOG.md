# Changelog

Notable changes, one line each. Cosmetic work, refactors, dependency bumps and
CI plumbing are deliberately absent: this file is for people deciding whether
to upgrade.

## Unreleased

- Pick a scan folder with your machine's own folder dialog, or keep browsing in Husk's picker
- Say where feedback goes, and link the privacy notice, before you send it
- Filter findings by repo, either from the toolbar or by clicking a project row
- Stop a running scan: the Stop scan button in the web UI, `s` in the TUI

## 0.1.1 - 2026-08-27

- Sign releases with cosign v3 Sigstore bundles

## 0.1.0 - 2026-08-26

First public release. A local-first security scanner for developer machines:
vulnerable and malicious packages across ~68 ecosystems, plaintext secrets,
risky install scripts and git hooks, and unsafe AI/MCP agent configuration.
CLI, TUI, localhost web UI, and an MCP server, in one binary with no account.
