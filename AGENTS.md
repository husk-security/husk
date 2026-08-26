# This repo

This repository contains the open-source `husk` CLI: a local-first Rust security
scanner for developer machines. It ships one binary with the command-line
interface, Ratatui TUI, optional localhost web UI, daemon, project
policy/ledger commands, and MCP server.

The hosted website and any backend service code are not in this repository. The
client-side cloud integrations here are optional and inert until a user signs in
or explicitly enables telemetry.

## What you need installed

- **Rust 1.95 or newer, with Cargo, plus `rustfmt` and `clippy`.** CI pins
  1.95.0. Building on Linux also wants a C toolchain; CI installs
  `build-essential`, `pkg-config`, and `libssl-dev`.
- **Node 24** (CI pins 24.16.0), needed **only** for the default `web` feature,
  which embeds the localhost web UI. `--no-default-features` needs no Node.
- **The hygiene tools CI runs**, if you want to reproduce that gate locally:

  ```sh
  cargo install cargo-deny cargo-machete typos-cli taplo-cli
  ```

  These four are what `deps + repo hygiene` runs in CI. `cargo-nextest` is
  optional and unrelated; it is a faster test runner.

There is no Nix requirement anywhere. CI itself uses a plain Rust toolchain and
plain `cargo`.

## Development commands

- Build the Rust crate quickly: `cargo build --no-default-features`
- Run tests: `cargo test --no-default-features`
- Run faster test loops: `cargo nextest run --no-default-features`
- Run clippy strictly: `cargo clippy --no-default-features --all-targets -- -D warnings`
- Format Rust: `cargo fmt`
- Run the fixture scan: `cargo run --no-default-features -- scan --offline tst --no-home-inventory`
- Run the fixture web UI without opening a browser: `npm --prefix web ci && npm --prefix web run build`, then `cargo run -- web --offline --no-open tst --no-home-inventory`
- Run CI JSON mode: `cargo run --no-default-features -- ci --offline tst --no-home-inventory`

Prefer `cargo run -- ...` over invoking a binary in `target/` directly, so you
never test a stale build.

If you work across sibling git worktrees, point them at one shared build
directory so each does not recompile the whole dependency tree:
`export CARGO_TARGET_DIR="$(dirname "$(pwd)")/.cargo-target"`.

The repository ships no Playwright setup. Where this file suggests driving the
localhost web UI in a browser, install it yourself first with `npx playwright
install`.

## If you use Nix

The flake is a convenience for contributors who already have Nix, not a
requirement for anyone else. It pins everything listed above: Rust, clippy,
rustfmt, Node 24, git, and all five hygiene tools, plus `nixfmt`.

- Enter the shell: `nix develop`, or `direnv allow` once to load it on `cd` (the repo ships an `.envrc`)
- Run any command in this document against the pinned toolchain by prefixing it: `nix develop -c cargo build --no-default-features`
- Format the flake after touching it: `nix develop -c nixfmt flake.nix`
- Build the packaged binary for packaging checks: `nix build .#husk` (full build, web UI included) or `nix build .#husk-tui` (npm-free, no web UI)
- Run the packaged binary for user-path checks: `nix run .#husk -- [args]`

## Current Rust layout

- `src/main.rs`: binary entrypoint.
- `src/lib.rs`: crate root that wires modules together.
- `src/cli/`: clap command surface and dispatch split by command family:
  `mod.rs` owns `Cli`/`Command`, telemetry names, and top-level dispatch;
  `scan.rs` handles scan-shaped commands (`scan`, `tui`, `web`, `ci`,
  `daemon`, `status`); `policy.rs` handles `init`, `approve`, `policy`, and
  `ledger`; `check.rs` handles `check`; `cloud.rs`
  handles account/sync/alerts/telemetry; `fix.rs` and `render.rs` cover their
  named surfaces.
- `src/model.rs`: central report shape shared by CLI, TUI, web, cache, and MCP:
  `ScanReport`, `Finding`, `PackageRef`, `Severity`, `ProviderStatus`,
  `LiveScan`, benchmark rows, project posture, and exploit/score annotations.
- `src/scan/`: staged scanner orchestration, local checks, and package discovery.
  `targets/` is the pluggable `ScanTarget` registry; `checks/` is the pluggable
  finding detector registry.
- `src/rule.rs`, `src/project.rs`, `src/score.rs`: rule metadata, project
  discovery, posture scoring, and final finding/project ordering.
- `src/providers.rs`: online vulnerability provider clients behind the
  `IntelSource` registry.
- `src/prioritize.rs`: CISA KEV and FIRST EPSS exploit annotations.
- `src/policy.rs` and `src/ledger.rs`: committed project policy
  (`<project>/.husk/policy.toml`) and personal hash-chained trust ledger
  (`~/.husk/ledger.jsonl`).
- `src/check.rs`: local single-package OSV verdicts.
- `src/cloud/`: optional auth, inventory sync, alerts, and opt-in anonymous
  telemetry.
- `src/cache.rs`: durable local scan cache.
- `src/tui/`: Ratatui terminal UI — a tabbed app (`mod.rs` shell + nav;
  `theme.rs` palette; `scan.rs`/`guide.rs`/`account.rs` tab bodies) mirroring the
  web UI's tabs. Display order comes from `crate::score` (which owns the finding
  + project ordering); the TUI never re-sorts findings.
- `src/web.rs`: thin localhost Axum server — the JSON API (`/api/live`, `/api/guide`, `/api/account`, …) plus the **embedded `web/dist`** Vite build (via `rust-embed`). No HTML is rendered in Rust. `husk web --dev` serves the API only for front-end HMR development. **Gated behind the default `web` Cargo feature** (`#[cfg(feature = "web")]`); see the feature note below.
- `guides/*.md` + `src/guide/`: human-editable guide content with TOML frontmatter, compiled and validated by `build.rs`, then joined to registered Rust controls, scan evidence, remediation proposals, and local review state. One catalog feeds the scan report, web Guide, TUI, CLI, and MCP.
- `src/remediation/`: typed, reversible remediation proposals and their executor. Markdown never executes code; guide controls own proposal planning and attach stable control/finding ids.
- `web/`: the localhost web UI — a self-contained Vite + React + TS app consuming `@huskdev/ui`/`@huskdev/tokens` (see `web/README.md`). Built to `web/dist/`, which is **gitignored** (build output, not source) and embedded by `web.rs` via rust-embed. After changing `web/src`, rebuild with `npm --prefix web run build` before `cargo build`. When the `web` feature is on, `web/dist` **must exist** — `build.rs` hard-fails with a clear error telling you to build the front-end first (or to use `--no-default-features`); there is no placeholder fallback.

**The `web` Cargo feature (default on).** The whole web UI — the `web` module, the `husk web` subcommand, and the `axum`/`rust-embed` deps — is gated behind the default `web` feature. Two compile options:
- **Default** (`cargo build`): includes the web UI. Build the front-end first (`npm --prefix web ci && npm --prefix web run build`); a bare `cargo build` without `web/dist` fails with a clear error pointing at one of these two paths (the `web` feature requires `web/dist` — there is no placeholder). CI (the `build-web` composite action) and `release.yml` build it before compiling; `web/dist` is never committed.
- **TUI-only** (`cargo build --no-default-features`): drops the web UI entirely — no Node toolchain, no `web/dist` needed. This is what the `husk-tui` Nix package builds (`buildNoDefaultFeatures = true`), so `nix build .#husk-tui` stays npm-free; `nix build .#husk` (the default package) is the full build with the web UI. CI's `build (no web feature)` job guards this path.
- `src/mcp.rs`: `husk mcp` stdio Model Context Protocol server for AI agents (hand-rolled JSON-RPC, one message per line; stdout is protocol-only).
- `integrations/`: per-agent MCP glue, including `plugin/` (one plugin payload
  with a manifest per agent under `.claude-plugin/`, `.codex-plugin/`, and
  `.cursor-plugin/`), the Codex, Cursor, VS Code, Gemini CLI, OpenCode, and
  Claude Desktop snippets, and the shared `husk-agent-guide.md`. Each agent's
  marketplace or extension manifest sits at the repo root:
  `.claude-plugin/marketplace.json`, `.agents/plugins/marketplace.json`,
  `.cursor-plugin/marketplace.json`, `gemini-extension.json`. The skill and
  shared guide mirror each other; update both together whenever CLI subcommands
  or MCP tools change.
- `tests/`: integration tests.
- `tst/`: intentionally unsafe fixtures used to verify detections.

## Development rules

The bare `husk` command prints the top-level help and exits 0, matching
git/cargo/docker: there is no implicit action with no subcommand. The explicit
entry points are `husk scan` (scan and print the report), `husk web` (serve the
localhost web UI and open it in the system browser), and `husk tui` (the
terminal UI). Keep `husk web` and the scan path fast to first output. Long scans
and online provider calls must expose progress through the shared live scan
state used by both the TUI and web UI.

Keep scans read-only. Parse files statically and do not run package managers,
install scripts, editor extensions, MCP servers, git hooks, or untrusted repo
code. When adding scanner behavior, prefer deterministic fixture coverage under
`tst/` and tests under `tests/`.

Scanner stages should expose benchmark rows in the report: elapsed wall time,
checked file count, scanned bytes, package count, finding count, and worker count
where relevant. Prefer ignore-aware parallel traversal, skip expensive/generated
directories early, run independent provider calls concurrently, and keep package
matching pointed toward local indexed intelligence rather than one network round
trip per package.

A benchmark row is pushed *after* the work it names, and every phase the scan
executes carries one. The report also states the wall time no row accounts for;
a phase that grows there is invisible to the split, so a rise in that line is a
bug in the instrumentation rather than an acceptable measurement.

Spawning a process inside a per-finding or per-file loop is the recurring way
this path gets slow: a `git` invocation costs about a millisecond, and a report
can carry hundreds of findings. Ask per repository, not per path.


The TUI and localhost web UI are two front ends over the same `LiveScan` and
`ScanReport`. Product capabilities and surfaced data should stay in lockstep.
Presentation and controls may differ by surface, but a whole feature, finding
field, policy/ledger view, or guide capability should not exist in only one UI.
Deliberate exception: the web "AI agent setup" tab is a web-only onboarding
helper that wraps the `husk mcp install` CLI flow — in a terminal the CLI
command itself is the equivalent surface, so the TUI intentionally has no
matching tab. The same shape applies to feedback: the web Help menu's
Send-feedback dialog wraps the `husk feedback` command, so the TUI has no
dedicated feedback pane (the Account tab names the command).

No TUI or web element may change size or move because dynamic scan content is
long. Progress rows, provider rows, toolbar roots, finding metadata, and detail
panes need stable dimensions and should truncate long paths in the middle or
clip inside a fixed area. Verify UI work with long fixture paths; use Playwright
for web checks when practical.

The TUI is a tabbed app mirroring the web UI structure: a one-line brand header,
a number-prefixed tab bar, a per-tab body, and a one-line contextual keybinding
footer. Navigation is `1`-`3`, `Tab`/`Shift-Tab`, `j`/`k`, and `q`/`Ctrl-C`.
`q` and `Ctrl-C` must restore the terminal immediately. After exit, durable
scrollback should contain only a compact colored session summary.

The Guide tab's `x` opens the fix pane over the body, the terminal half of the
web's "Fix with Husk" card: proposals grouped by the directory the fix runs in,
`space`/`a` selection, `enter` to apply the selection in one run, `PgUp`/`PgDn`
to scroll the change, `esc` to go back. Every line it shows comes from the
server-side `FixPreview`, so no surface computes its own diff or command.

The default `web` Cargo feature includes the web UI, `husk web`, and the
`axum`/`rust-embed` dependencies. It requires the front end to be built first:

```sh
npm --prefix web ci
npm --prefix web run build
cargo build
```

For a TUI-only build that needs no Node toolchain and no `web/dist`, use:

```sh
cargo build --no-default-features
```

The `husk-tui` Nix package builds this TUI-only path; CI and release builds
build `web/dist` before compiling the default-feature binary.

### User-facing text

Never use em dashes (—) or en dashes (–) in text a user sees: CLI output and
`--help`/`about`/`long_help`, TUI, the web UI, error and status messages, and the
guide catalog. They read as machine-generated. Rewrite with a period, comma,
colon, semicolon, or parentheses. Example: `Scanning now — results appear as they
arrive.` becomes `Scanning now. Results appear as they arrive.` A plain hyphen (-)
for ranges, flags, or compound words is fine; the em/en dash is what's banned.

### Comments

Comment only what the code cannot say: non-obvious invariants, domain facts,
and the reasons behind a decision. Do not narrate obvious code, and do not
reference history or process — no "recently split", "kept for the audit",
wave/review numbers, or notes to future reviewers. Doc comments must add
information beyond the signature, not restate it. When a comment is needed,
keep it tight.

### Simplicity

A change must delete more code than it adds, unless it is a bug fix or a test.
An abstraction must pay for itself in immediately removed code — never
introduce one for a hypothetical future. Dumb, readable code beats clever code.

## Adding a scanner, detector, or intel source

husk is a *security* tool: the false-positive / false-negative balance matters
more than raw feature count. **Every detection change ships with a deterministic
fixture and a test.** Almost everything extensible goes through one of three
pluggable registries, each following the same recipe — *one self-contained module
implementing the trait → one registration line → a fixture + unit tests*:

- **A new package ecosystem — the `ScanTarget` registry (`src/scan/targets/`).**
  One module per ecosystem, all built on the shared `support.rs` layer (bounded
  reads, the `Emitter` coordinate sink, line location). For an exact-filename
  manifest, write `pub(super) fn <name>(contents: &str, out: &mut Emitter<'_>)`
  and register it as a `simple("id", &["file.lock"], mylang::parse)` row in
  `default_targets()`. Anything fancier (path-shape detection, sibling-file
  gating, binary DBs) implements the `ScanTarget` trait directly. If OSV covers
  it, add one mapping in `PackageRef::osv_ecosystem` (`src/model.rs`) and verify
  the exact name/version format against the live OSV API (casing and prefixes
  matter). Add a fixture under `tst/ecosystems/<id>/`, then regenerate the golden
  corpus (`HUSK_UPDATE_GOLDEN=1 cargo test --no-default-features --test golden_corpus`)
  and confirm the diff is exactly your new coordinates.
- **A new finding type — the `Check` registry (`src/scan/checks/`).** One module
  per detector; a `Check` declares which files it wants, emits findings, and owns
  its `Rule` catalog entries (`const RULES`) so finding, guide entry, and fix
  text stay joined. Gate cheaply by file type/name in `applies` before parsing.
  Register it in `default_checks()`, and **bump `SCAN_INDEX_VERSION` in
  `src/cache.rs`** — otherwise the per-file cache serves stale findings and your
  detector silently doesn't fire on a rescan.
- **A new advisory source — the `IntelSource` registry (`src/providers.rs`).**
  One struct turning coordinates into findings, registered in `INTEL_SOURCES`.
  Sources run concurrently inside a shared wall-clock budget; a failure must
  degrade to a `ProviderStatus` row, never abort the scan.

**A finding id names the rule and the subject it matched, never the path or the
line.** The scan adds those centrally (`Finding::locate_id`), producing
`subject@path#line`. That id is what a `[[suppress]]` entry in a committed
`.husk/policy.toml` matches by exact string, so putting the location in it by
hand risks two findings sharing an id, which would silence the one the developer
never reviewed. Set `.at(path, line)` and let the id follow. Never use a
finding's id as a dedup or grouping key inside the scan; use the path.

Whatever the registry: emit a `Finding` (`src/model.rs`) with a stable id, clear
title/summary, path/line where applicable, and a **conservative** severity —
reserve critical/high for genuinely dangerous findings. **Keep scans read-only:**
never execute package managers, install scripts, editor extensions, MCP servers,
git hooks, or repo code — parse statically only. Add an integration test under
`tests/` (`mvp.rs`, `mcp.rs`, `cloud_*.rs`) asserting on stable fields (category,
severity, path), not exact prose. If your change adds or alters a finding
category, CLI subcommand, or MCP tool that agents care about, update **both** the
Claude Code skill and `integrations/husk-agent-guide.md` (they mirror each other).

## Adding an ecosystem fixer

Scanning answers "which coordinates are on this machine". Fixing answers "how do
I move one of them to another version inside a real project". That is the
`EcosystemFixer` registry in `src/remediation/ecosystems/`, a deliberate sibling
of `ScanTarget` keyed on the **same ecosystem id**, which is what lets a fix
verify itself by re-running the scanner's own parser at no extra cost.

**One module plus one line in `default_fixers()`.** There is no `match` to hunt.

1. **Confirm the ecosystem is scanned.** Its id must already appear in
   `scan::targets::supported_ecosystems()`; a fixer for coordinates husk cannot
   see is dead code, and `ecosystems::tests::every_fixer_targets_a_scanned_ecosystem`
   fails if you typo the id.
2. **Write `src/remediation/ecosystems/<id>.rs`.** Required: `ecosystem`,
   `program`, `plan`. Defaulted: `probes` (which sibling files the planner needs
   read), `root`, `flavor`, `plan_batch`, `failure_hints`.
3. **Register one line** in `default_fixers()`. The modules are private, so an
   unregistered fixer is never constructed and `-D warnings` turns that into a
   build failure.
4. **Answer the five design questions in the module doc comment**, because they
   are what a reviewer checks:
   - Does a fix edit the **manifest**, the **lockfile**, or the **environment**?
   - How does this ecosystem pin a **transitive** dependency (an override field,
     a constraints file, a `replace` directive, or "it cannot", which is a
     `Blocker`)?
   - Does a **downgrade** use the same mechanism as an upgrade? The compromised
     release is often the newer one, so this is not hypothetical.
   - What makes the fix **stick across a rescan**? That is what
     `Verify::Recoordinate` asserts.
   - What is the **workspace root** versus the lockfile's directory?
5. **Test the ops, not the prose.** Planning is pure over a
   `Workspace::fixture(...)`, so tests need no temporary directory:
   `assert_eq!(plan.recipe.ops, vec![FixOp::SetValue{..}, FixOp::RunTool{..}])`.
   Add one test per `Blocker` the fixer can return; an untested blocker is an
   untested UI state.

Hard rules for a fixer:

- **Planning is pure.** A planner is handed an already-read `Workspace` and an
  already-probed `Toolbox` and returns data. `std::fs` and `std::process` appear
  nowhere under `src/remediation/` except `exec.rs`, `Workspace::read`, and
  `Toolbox::probe`.
- **A blocker is not an error.** `plan` returns `Plan { recipe, blockers }`, so a
  blocked row still shows the command husk would have run, and blockers
  accumulate when they genuinely co-occur.
- **Lifecycle scripts stay off.** A security tool must not execute
  `postinstall` code from the tree it just flagged. Every relock command passes
  `--ignore-scripts` (or the manager's equivalent), and refreshes the lockfile
  without materialising `node_modules` where the manager supports it.
- **Never widen a declared range silently.** If the safe version falls outside
  what the project's dependents allow, that is `Blocker::RangeConflict` with the
  edit spelled out, not a quiet rewrite.
- **Do not add a fixer for an OS package manager.** apt/dnf/pacman/apk/brew
  fixes need root, change machine-global state, and cannot be undone by a file
  snapshot. Those coordinates stay inventory-only and the finding's own
  recommendation carries the command.
- **Never** pipe to a shell, fetch and execute, rotate a credential, or rewrite
  git history. The `FixOp` vocabulary cannot express any of it; keep it that way.
