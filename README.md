<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/husk-lockup-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="assets/husk-lockup-light.svg">
  <img alt="husk" height="80" src="assets/husk-lockup-light.svg">
</picture>

<br>
<br>

**A local-first security scanner for developers. One binary, no account.**

[![CI](https://github.com/husk-security/husk/actions/workflows/ci.yml/badge.svg)](https://github.com/husk-security/husk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Install](#install) · [Quickstart](#quickstart) · [Usage](#usage) · [Commands](#command-reference) · [How it works](#how-it-works)

</div>

husk scans your machine for compromised packages, leaked secrets, risky install
scripts, and unsafe AI/MCP configuration, then shows you what to fix. It runs
locally: no login, no account, no file ever leaves your machine. An online scan
sends only package names, versions, and CVE ids to public advisory databases
(OSV.dev, npm, PyPI, GitHub, CISA KEV / FIRST EPSS); `--offline` makes zero
network calls.

> **Pre-1.0 software without an independent audit.** Interfaces can change
> between releases. Bug reports and questions are welcome in
> [Issues](https://github.com/husk-security/husk/issues).

## Install

husk runs on **Linux and macOS**. On Windows, run it inside
[WSL](https://learn.microsoft.com/windows/wsl/install), where it installs and
behaves exactly as it does on Linux. There is no native Windows build.

Download the latest signed release, verify its checksum, and install it:

```sh
curl -fsSL https://husk-security.dev/install.sh | sh
```

It installs to `~/.local/bin`, overridable with `HUSK_INSTALL_DIR` or
`--install-dir`. If that directory is not already on your `PATH`, it asks before
adding it to your shell's startup file and names the exact file it would change.
Decline, or run it without a terminal, and it prints the one command that adds
it instead. `--no-modify-path` never writes to a startup file at all.

<sub>Prefer not to pipe into a shell? Download `install.sh`, read it, then run
it. Every release is cosign-signed and SLSA-attested; the installer verifies the
SHA-256 checksum (and the signature too, when `cosign` is on your PATH). See
[verifying a release](#verifying-a-release).</sub>

<details>
<summary><b>Other install sources</b></summary>

> | Source | Command |
> | --- | --- |
> | **cargo** | `cargo install husk-sec` |
> | **cargo-binstall** | `cargo binstall husk-sec` |
> | **npm** | `npm install -g husk-sec` |

</details>

<details>
<summary><b>Nix</b></summary>

> Run it without installing anything:
>
> ```sh
> nix run github:husk-security/husk -- scan
> ```
>
> The flake exposes two packages: `husk` (the default, with the localhost web
> UI) and `husk-tui` (the same binary without it, so it needs no Node
> toolchain).
>
> For persistent use, add the flake as an input and put the package in your
> configuration. NixOS:
>
> ```nix
> {
>   inputs.husk.url = "github:husk-security/husk";
>   inputs.husk.inputs.nixpkgs.follows = "nixpkgs";
>
>   outputs = { nixpkgs, husk, ... }: {
>     nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
>       system = "x86_64-linux";
>       modules = [
>         { environment.systemPackages = [ husk.packages.x86_64-linux.husk ]; }
>       ];
>     };
>   };
> }
> ```
>
> Home Manager, with the same input:
>
> ```nix
> home.packages = [ husk.packages.x86_64-linux.husk ];
> ```
>
> If you would rather put it on `PATH` imperatively than declare it,
> `nix profile install github:husk-security/husk` also works.

</details>

## Quickstart

```sh
husk            # print help (no subcommand does nothing else)
husk scan       # one-shot scan of the current directory, plain terminal summary
husk web        # serve the local web UI and open it in your browser
husk tui        # browse the latest scan in the terminal UI
```

`husk` with no subcommand prints help and exits, like git or cargo. The entry
points are `husk scan` (scan and print the report), `husk web` (the local web
UI, opened in your browser), and `husk tui` (the terminal UI).

## Usage

A few of the commands you'll actually run day to day. The full list (every
subcommand and flag) is in the [command reference](#command-reference).

**Scan a directory** and print the findings report:

```console
$ husk scan --offline .
packages: 286  findings: 36  critical: 5  high: 16  medium: 15  low: 0  info: 0

  critical risky-agent-config  AI agent is allowed unrestricted shell access
           .claude/settings.local.json:4
  high     lifecycle-script    Dangerous npm postinstall script
           package.json:6
  high     risky-agent-config  MCP config contains hardcoded secret
           .mcp.json:7
  ...
```

**Vet one package** before you install it (a live OSV.dev lookup):

```console
$ husk check lodash@4.17.20
!! vulnerable npm lodash@4.17.20
   advisory GHSA-35jh-r3h4-6jhm via OSV.dev
   Command Injection in lodash
   Install a fixed version instead, or avoid the dependency until one is available.
```

The version can be an `@version` suffix (split on the last `@`, so
`@scope/pkg@1.2.3` works) or separate arguments: `husk check npm lodash 4.17.20`.
A bare name (`husk check lodash`) assumes npm and checks malware advisories only.

**Protect normal and lockfile installs** with the tracked Safe Chain task in
the Guide. Husk recommends the free, MIT-licensed third-party tool instead of
shipping a weaker package-manager wrapper:

[Review Aikido Safe Chain](https://github.com/AikidoSec/safe-chain)

**Commit a project policy** (block/allow packages, suppress triaged findings,
set the CI threshold); the `.husk/` directory is meant to be committed:

```console
$ husk init
Created ./.husk/policy.toml
  `husk scan` and `husk ci` in this project now read this policy.

$ husk approve npm:lodash          # allow a package; recorded in policy + ledger
```

**Plan safe fixes** (dry-run by default; `--apply` writes them, with backups):

```sh
husk fix                          # show the plan, change nothing
husk fix --apply                  # write the auto-safe fixes
```

**Gate a build** in CI, JSON on stdout, non-zero exit at or above the threshold:

```sh
husk ci                           # exit 1 on high+ findings (see JSON output below)
```

### Environment

husk reads a few environment variables:

| Variable | Effect |
| --- | --- |
| `HUSK_HOME` | State directory (ledger, daemon state, credentials); default `~/.husk`. |
| `HUSK_CACHE_DIR` | Cache directory (reports, scan index); default `~/.cache/husk`. |
| `HUSK_PAGER`, `PAGER` | Pager for long reports (default `less`); an empty value or `cat` disables paging. |
| `NO_COLOR` | Disable ANSI colors in CLI output. |
| `HUSK_TOKEN` | Bearer-token override for cloud commands (CI or one-off use). |

## Command reference

One binary, many subcommands. Run `husk <command> --help` for the full flags
of any of them.

- **`husk scan`**: Scan now and print the findings report
- **`husk status`**: Print the last scan's report without rescanning
- **`husk tui`**: Open the interactive terminal UI on the latest scan
- **`husk web`**: Serve the local web UI on the latest scan
- **`husk check`**: Look up one package's malware/vulnerability verdict
- **`husk ci`**: Scan and gate a build; exit 1 at/above the threshold
- **`husk fix`**: Plan fixes from the latest scan; write them with --apply
- **`husk init`**: Create a committed .husk/policy.toml project policy
- **`husk approve`**: Record an allow/block/suppress decision in the policy
- **`husk policy`**: Show the active project policy and its counts
- **`husk ledger`**: Show or verify the personal trust ledger
- **`husk daemon`**: Scan on an interval; report findings new since last run
- **`husk login`**: Sign in to a husk account (coming soon)
- **`husk logout`**: Delete the credentials stored on this machine
- **`husk account`**: Show the signed-in account and machine link
- **`husk sync`**: Upload the last scan's inventory for retroactive alerts
- **`husk alerts`**: List this account's retroactive alerts
- **`husk telemetry`**: Manage opt-in anonymous telemetry (off by default)
- **`husk feedback`**: Send feedback to the husk developers
- **`husk mcp`**: Run the MCP server, or register it with an AI agent

## JSON output

Several commands emit the full scan report as JSON: `husk scan --json`,
`husk status --json`, `husk tui --json`, and `husk ci` (always JSON). The shape
is identical everywhere; it is the report the local cache stores and every UI
renders. It is plain JSON on stdout: never paged, never colored, safe to pipe
straight into `jq`.

| Field | Type | Meaning |
| --- | --- | --- |
| `api_version` | number | Report-shape version (currently `4`). Bumped when the shape changes; check it before parsing deeply. |
| `generated_at` | string (RFC 3339) | When the scan finished. Reports older than 24 hours are considered stale by the UIs. |
| `roots` | string[] | The directories that were scanned. |
| `context` | object | System context: user, OS/arch, distro, kernel, git identity, detected package managers and dev configs. |
| `packages` | object[] | The package inventory: `{ecosystem, name, version, manifest_path, line}` per discovered coordinate. |
| `projects` | object[] | Discovered projects (the unit of attention); findings join to these via `Finding.project_id`. |
| `summary` | object | The security headline (counts and framing used by the UIs). |
| `findings` | object[] | Open findings. Each has `id`, `title`, `severity` (`critical`/`high`/`medium`/`low`/`info`), `category`, `source`, `path`, `line`, `summary`, `evidence` (pre-redacted), `recommendation`, `references`, `cves`, plus optional `package`, `project_id`, `rule_id`, `confidence`, `priority`, `exploit` (CISA KEV / EPSS), and `fixed_version`. |
| `ignored` | object[] | Findings silenced by project policy or ledger decisions, kept out of `findings`, stats, and scoring. |
| `controls` | object[] | Results from registered guide controls: status, local evidence, and related finding ids. |
| `remediations` | object[] | Typed remediation proposals owned by controls; includes execution class, severity, operation, and related finding ids. |
| `guidance` | object | The assessed Markdown guide: baseline/recommendation items, scan priority, review decisions, and handled percentage. |
| `providers` | object[] | Per intel source: `{name, ok, checked_packages, findings, message}`. `ok: false` means coverage was incomplete. |
| `benchmarks` | object[] | Per-stage timing: `{stage, elapsed_ms, files_checked, bytes_scanned, packages_checked, findings, workers, detail}`. |
| `stats` | object | Totals: `{packages, findings, critical, high, medium, low, info}`. |
| `delta` | object? | What changed since the previous cached scan of the same roots: `{previous_at, previous_score, score, new_count, unchanged_count, resolved_count, resolved}`. Absent on a first scan. |

```sh
husk scan --json | jq -r '.findings[].id'                 # every finding id, worst first
test "$(husk status --json | jq .stats.critical)" -eq 0   # fail a script on any critical
husk ci | jq '.providers[] | select(.ok | not)'           # which intel sources had problems
```

## How it works

- **Local-first.** Scans read files and parse them statically; husk never
  executes what it scans. Results and state stay on your machine; an online scan
  sends only package coordinates and CVE ids to public advisory databases.
- **Package coverage.** Discovery is a pluggable registry spanning ~68 package
  ecosystems (language managers, OS/distro databases, AI/agent/editor surfaces,
  CI/IaC/containers, and CycloneDX/SPDX SBOMs), see
  [`src/scan/targets/`](src/scan/targets/).
- **Exploit-aware.** CISA KEV and FIRST EPSS enrichment sorts actively-exploited
  CVEs to the top instead of dumping an undifferentiated CVE list.
- **State that compounds.** A committed `.husk/policy.toml` (block/allow, suppress,
  CI threshold) travels with your repo; a personal hash-chained trust ledger at
  `~/.husk/ledger.jsonl` records every `approve`. Both are local,
  inspectable, and deletable.
- **Built for agents.** `husk mcp` serves a Model Context Protocol server over
  stdio so AI agents can read findings and trigger scoped scans; `husk mcp install
  <agent>` writes the config. It is listed in the Model Context Protocol
  Registry as `mcp-name: io.github.husk-security/husk`. Agent-facing details
  live in [AGENTS.md](AGENTS.md) and [`integrations/`](integrations/).

## Building from source

Cargo and Rust 1.95 or newer is all you need.

```sh
git clone https://github.com/husk-security/husk
cd husk
cargo build --release --no-default-features
./target/release/husk scan /path/to/your/project
```

The **localhost web UI** is a Vite + React app in [`web/`](web/) that the binary
embeds (via `rust-embed`) under the default `web` Cargo feature. There are two
build paths; pick one:

- **Full build (default feature).** Build the frontend first, then compile. This
  is the only path that needs Node:

  ```sh
  npm --prefix web ci
  npm --prefix web run build      # → web/dist
  cargo build --release           # rust-embed embeds web/dist
  ```

- **CLI/TUI-only (no Node needed).** Drops the web UI entirely; nothing to build
  first:

  ```sh
  cargo build --release --no-default-features
  ```

`web/dist` is generated output and is gitignored. A plain `cargo build` *without*
building the frontend first fails with a clear error pointing you at one of the
two paths above, because the `web` feature requires `web/dist` to exist.

If you already use [Nix](https://nixos.org/), the flake pins the same toolchain:
`nix develop` gives you a shell with it, and `nix build .#husk` (web UI included)
or `nix build .#husk-tui` (Node-free) builds the binary directly. None of it is
required.

Developer documentation (the module layout, the three pluggable registries, and
how to add a scanner) is in [AGENTS.md](AGENTS.md).

<details>
<summary><b>Privacy &amp; trust</b>: what husk reads, what never leaves your machine, how releases are signed</summary>

husk is a security tool, so it holds itself to a higher standard than the things
it scans. Every claim below is enforced by code or CI in this repository.

**What husk reads.** Manifests and lockfiles, package-manager databases,
dotfiles and configs, git hook files, CI workflow files, MCP/agent configs, and
text files (for secret patterns). Scans are **strictly read-only**. husk writes
only its own state, `~/.husk/` (ledger, daemon state, cloud
config) and the cache dir, plain files you can inspect and delete anytime.

**What husk never does.**

- **Never executes what it scans.** No package managers, install scripts, git
  hooks, editor extensions, MCP servers, or repo code; detection is static
  parsing only. The one opt-in, per-invocation exception is `husk fix --apply
  --deps`, which runs *your* package manager's version-pin command, shown to you
  first.
- **Never uploads your files.** During an online scan husk sends **package names,
  versions, and CVE ids only** to public advisory databases (OSV.dev, npm, PyPI,
  GitHub, CISA KEV / FIRST EPSS), never file contents, paths, or secrets.
  `husk scan --offline` makes zero network calls.
- **Never phones home by default.** No account, no login wall; telemetry is off
  until you run `husk telemetry on`, and it honors
  [`DO_NOT_TRACK`](https://consoledonottrack.com) and a
  `HUSK_TELEMETRY_DISABLED` kill switch. All cloud features are opt-in and inert
  until used.
- **Never puts secrets in output.** Secret findings carry short, pre-redacted
  excerpts, not the matched credential.

**Verifiable properties.**

| Claim | Verify |
| --- | --- |
| 100% safe Rust (`#![forbid(unsafe_code)]`) | `grep -rn "forbid(unsafe_code)" src/lib.rs src/main.rs` |
| No proprietary trust path: every verdict comes from a public source queried over TLS; no husk-curated feed or signing root in the scan / `husk check` path | `src/providers.rs`, `src/check.rs` |
| Signed releases (cosign keyless + SLSA provenance, built in CI from the tag) | [verifying a release](#verifying-a-release) |
| Supply-chain-checked deps (cargo-deny / cargo-machete / Dependabot / Scorecard) | [`ci.yml`](.github/workflows/ci.yml), [`scorecard.yml`](.github/workflows/scorecard.yml) |
| Every third-party GitHub Action pinned to a full commit SHA (husk flags actions that aren't) | `grep -rn "uses:" .github/workflows/` |
| Deterministic fixes: no LLM in the remediation apply path | `src/remediation/` |

**About `tst/`.** `tst/` holds **intentionally unsafe fixtures** (fake AWS keys
like `AKIAIOSFODNN7EXAMPLE`, prompt-injection markdown, vulnerable pins) so
husk's detectors can be tested deterministically. They are fake by policy and
excluded from the crates.io package. If your scanner flags them inside this repo,
it's working as intended; so is husk. [`tst/README.md`](tst/README.md) explains
what is in there and why, and `tst/` is out of scope in
[SECURITY.md](SECURITY.md).

Vulnerabilities **in husk itself** go through the private channel in
[SECURITY.md](SECURITY.md), not public issues.

</details>

## Verifying a release

<details>
<summary><b>Release verification details</b></summary>

Every release archive ships a SHA-256 checksum, a **cosign keyless** signature
(Sigstore Fulcio + the Rekor transparency log, no long-lived key to steal), and
a **SLSA build-provenance** attestation, all produced in CI from the tagged
commit. `install.sh` verifies the checksum automatically (and the signature if
`cosign` is present). To verify by hand:

```sh
VERSION="v0.0.1"
TARGET="x86_64-unknown-linux-gnu"          # or aarch64-apple-darwin, etc.
ARCHIVE="husk-${VERSION}-${TARGET}.tar.gz"

# 1. Checksum
sha256sum -c "${ARCHIVE}.sha256"           # macOS: shasum -a 256 -c ...

# 2. cosign signature: pin the workflow identity and the OIDC issuer
cosign verify-blob \
  --certificate "${ARCHIVE}.pem" \
  --signature "${ARCHIVE}.sig" \
  --certificate-identity-regexp "^https://github.com/husk-security/husk/\.github/workflows/release\.yml@refs/tags/v" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${ARCHIVE}"

# 3. SLSA provenance
gh attestation verify "${ARCHIVE}" --repo husk-security/husk
```

A successful run prints `Verified OK`. If the identity or issuer doesn't match,
the signature is rejected; that's the point. The exact release process
is documented in [`.github/workflows/release.yml`](.github/workflows/release.yml).
Publishing requires a stable `vX.Y.Z` tag on a commit reachable from `main`, a
matching version in `Cargo.toml` and `flake.nix`, and an explicitly allowed
human for both the original workflow run and any re-run. The workflow does not
rely on tag protection rules: it rechecks the live remote tag and its `main`
ancestry immediately before publishing. An unauthorized tag can start a run, but
it cannot reach the signing job.

</details>

## Support and license

- **Building and developing**: see [building from source](#building-from-source)
  above and [AGENTS.md](AGENTS.md). New detections ship with fixtures and tests.
- **Contributing**: see [CONTRIBUTING.md](CONTRIBUTING.md) for the build and
  pull-request flow.
- **Getting help**: usage questions, help interpreting findings, concrete bugs,
  and feature requests all go to
  [Issues](https://github.com/husk-security/husk/issues).
- **Security**: report a vulnerability in husk itself privately, per
  [SECURITY.md](SECURITY.md). Never open a public issue for one.
- **License**: [MIT](LICENSE).
