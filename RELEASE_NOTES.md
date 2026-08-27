**A local-first security scanner for developers. One binary, no account.**

The first public release of husk. It scans your machine for compromised
packages, leaked secrets, risky install scripts, and unsafe AI/MCP
configuration, then shows you what to fix.

It runs locally. No login, no account, no telemetry unless you turn it on, and
no file ever leaves your machine. An online scan sends only package names,
versions, and CVE ids to public advisory databases; `--offline` makes zero
network calls.

## Install

```sh
curl -fsSL https://husk-security.dev/install.sh | sh
```

The installer enforces a SHA-256 checksum, verifies the Sigstore signature when
`cosign` is present, installs to `~/.local/bin`, and never uses `sudo`. If
you'd rather read it first, that is the better habit:

```sh
curl -fsSL https://husk-security.dev/install.sh -o husk-install.sh
less husk-install.sh
sh husk-install.sh
```

Linux and macOS, x86_64 and arm64. On Windows, run it inside WSL; there is no
native Windows build yet.

## Try it

```sh
husk scan            # scan this directory
husk tui             # browse the results interactively
husk web             # the same report as a localhost web UI
husk check npm lodash 4.17.20
```

## What it looks at

- **Vulnerable and malicious packages** across ~68 package ecosystems, from npm
  and PyPI through OS package managers to SBOMs, checked against OSV.dev, npm,
  PyPI, and GitHub advisories. CISA KEV and FIRST EPSS sort what is actually
  being exploited to the top.
- **Plaintext secrets** in dotenv files, configs, and shell history, redacted
  before they ever enter a report.
- **Risky automation**: npm lifecycle scripts, git hooks, and GitHub Actions
  workflows that are not SHA-pinned.
- **AI and agent surface**: MCP server configuration, agent permission settings,
  editor extensions, and prompt-injection patterns.

Findings come with a guide entry explaining the risk and, where husk can do it
safely, a reversible fix. `husk fix` is dry-run by default, snapshots every
write, and never executes code from the tree it just scanned.

## Verifying this release

Every archive is signed keyless through Sigstore and carries SLSA build
provenance. There is no signing key to leak: the identity is this repository's
release workflow, recorded in Rekor.

```sh
cosign verify-blob \
  --bundle "husk-v0.1.1-x86_64-unknown-linux-gnu.tar.gz.sigstore.json" \
  --certificate-identity-regexp "^https://github.com/husk-security/husk/\.github/workflows/release\.yml@refs/tags/v" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "husk-v0.1.1-x86_64-unknown-linux-gnu.tar.gz"

gh attestation verify "husk-v0.1.1-x86_64-unknown-linux-gnu.tar.gz" --repo husk-security/husk
```

## Known limits

This is pre-1.0 software with no independent audit, and interfaces can change
between releases. `husk login` and the account commands are placeholders for a
service that is not open yet. Package-manager installs (`npx husk-sec`,
`cargo install husk-sec`) are not published yet; the install script above is the
supported path today.

Bug reports, false positives, and false negatives are all welcome in
[Issues](https://github.com/husk-security/husk/issues) — the accuracy reports
are the most useful thing you can send.
