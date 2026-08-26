# Husk guide for AI agents

Append this file to your project `AGENTS.md` (or a global agents file) so any
coding agent knows how to use the locally installed husk security scanner.
The Claude Code plugin ships the same content as a skill; this copy is for
tools that use plain agent instructions (Codex, OpenCode, and others).

## What husk is

Husk is a developer security scanner installed on this machine. It
scans projects and the home directory for vulnerable/compromised packages
(~68 package ecosystems: npm, PyPI, cargo, Go, OS package managers, editor
extensions, MCP servers, and more), leaked secrets, risky automation (GitHub Actions, git
hooks, install scripts), and AI/MCP config issues. Unless `--offline` is set,
scans send discovered package names and versions to public advisory databases
(OSV.dev, npm, PyPI, GitHub); file contents, paths, and secrets never leave the
machine. Cloud features (account, inventory sync, telemetry) are strictly
opt-in and the scanner is complete without them.

## MCP tools (preferred when the husk MCP server is connected)

The server is started with `husk mcp` (stdio transport) and exposes:

- `husk_status`: summary of the latest cached scan: timestamp, roots,
  severity counts, category counts, provider status. Call this first.
- `husk_findings`: cached findings sorted by severity. Filters:
  `min_severity`, `category`, `path_contains`, `limit` (default 50).
- `husk_packages`: packages discovered in the cached scan with manifest
  paths. Filters: `ecosystem`, `name_contains`, `limit`.
- `husk_fix`: read-only plan of the safe-fixable subset, each item classified
  `auto_safe` / `confirm` / `manual`. Never writes; apply the actual changes
  with your own tools (or `husk fix --apply` for the auto-safe subset).
- `husk_scan`: run a fresh scan of given `paths` (defaults to cwd) and cache
  it. Options: `home`, `offline`, `include_home_inventory` (defaults false
  here, unlike the CLI).
- `husk_policy`: read the committed project policy (`.husk/policy.toml`) for a
  `path`: blocked/allowed package coordinates, suppressed finding ids, and the
  CI threshold. Call it before installing/recommending a dependency to respect
  the team's decisions; no scan needed.
- `husk_ledger`: read the personal trust-ledger history (`~/.husk/ledger.jsonl`)
  of past approve decisions, with a chain-integrity flag, so you don't
  re-flag something the user already triaged. Optional `limit` (default 50).
- `husk_guide`: read scan-backed guidance with baseline/recommendation kind,
  severity, control status, local evidence, finding/remediation ids, steps,
  options, and sources. Progress requires read plus verified/completed/dismissed.
- `husk_guide_update`: mark a guide item `read`/`complete`/`dismiss`/`clear` (optional
  `reason`), persisted to husk's own state file
  (`~/.husk/guide.json`). Edits only husk state; never performs the
  fix.
- `husk_feedback`: send free-text product feedback about husk to the husk
  developers (`message` required, optional `contact` reply email). Sends only
  the message, the contact, and the husk version. Ask the user before sending
  on their behalf.

When the user says "fix these things in the guide": call `husk_guide`
(`status: "action-needed"` first), read each task's steps with `include_steps`
or `task_id`, apply the fix with your normal (user-permissioned) tools, then
call `husk_guide_update` with `action: "complete"`. husk only reads files and
writes its own guide state; it never runs the fix for you.

Workflow: call `husk_status` first. If there is no cached scan or it predates
relevant changes, run `husk_scan` scoped to the project under discussion
rather than a `home: true` scan, which is slow. Then page through results with
`husk_findings` (e.g. `min_severity: "high"`), not by rerunning scans.

## CLI reference (fallback when MCP is not connected)

- `husk scan [PATHS] [--home] [--offline] [--no-home-inventory] [--json]`:
  one-shot scan, prints a summary or full JSON. Always scans fresh and
  refreshes the local cache.
- `husk fix [PATHS] [--offline] [--json] [--only ID] [--deps] [--all]`: plan
  the safe-fixable subset. **Dry-run by default (safe, read-only): prints the
  plan and writes nothing.** `--apply` (or `--yes`, its non-interactive alias)
  writes the auto-safe fixes (for dotenv files only: append to `.gitignore`,
  and generate a values-stripped `<file>.template`; never rotates secrets,
  edits source, or modifies the dotenv file itself). `--apply --deps`
  additionally runs the planned dependency upgrades/downgrades to an advisory's
  safe version via the ecosystem's own package manager
  (`npm`/`pip`/`cargo`/`go`). `--all` applies everything in one shot (implies
  `--yes --deps`). Do NOT run `--apply`, `--yes`, or `--all` from an agent
  session without the user asking; the default dry-run is fine. `--rollback`
  undoes the last apply.
- `husk status [--json]`: print the latest cached report without scanning.
- `husk init [PATH]`: write a committed `<project>/.husk/policy.toml` (the
  team's shared policy: `[packages] block`/`allow` coordinates, `[[suppress]]`
  finding ids, `[ci] fail_on`). Every scan/ci in the project then honors it.
- `husk approve <ecosystem:name[@version]>` (or `--block`, or `--suppress
  <finding-id> [--reason TEXT]`): record a triage decision into the project's
  `.husk/policy.toml` in one command (comment-preserving).
- `husk ledger [--json] [--verify]`: show the personal append-only trust
  ledger (`~/.husk/ledger.jsonl`) of approve decisions over time; `--verify`
  checks the hash chain. Local-only, never networked, deletable.
- `husk policy [show] [--json]`: print the active committed project policy
  (`.husk/policy.toml`): block/allow/suppress counts and the CI threshold. The human scan summary also shows a one-line `policy: … ledger: …` state when a project policy exists or the ledger is non-empty.
- `husk ci [PATHS] [--offline] [--no-home-inventory] [--fail-on-medium]`:
  JSON report on stdout, exits non-zero on high/critical findings. Best for
  scripted checks.
- `husk mcp`: the MCP server itself (stdio); agents connect to this, do not
  run it ad hoc. `husk mcp --selfcheck` validates it can start and exits.
- `husk mcp install <claude-desktop|cursor|vscode|gemini|codex|opencode> [--global]
  [--dry-run]`: idempotently register this MCP server in an agent's config
  (a setup command for humans, not something to run mid-session).
- `husk tui`, `husk web`, `husk daemon`: interactive/long-running; do not run
  these from an agent session.

Optional cloud subcommands (all opt-in; nothing phones home without them):

- `husk login`: account sign-in is coming soon. It currently prints that
  status and exits without starting authentication or making a login request.
- `husk logout` / `husk account`: remove stored credentials or inspect the
  current session. `logout` cannot clear `HUSK_TOKEN`; unset it separately.
  `account` is safe to run and shows backend, machine-link, and telemetry state.
- `husk sync`: upload the package inventory of the current directory to the
  account for retroactive alerts. Until sign-in launches, this requires an
  existing stored credential or `HUSK_TOKEN`.
- `husk alerts [--all] [--json]`: list the account's alerts from the backend
  (default: open only). It has the same existing-credential requirement.
- `husk telemetry <on|off|status [--payload]>`: anonymous daily usage
  telemetry (bucketed counters, no identifier), off by default.
  `status --payload` prints exactly the JSON that would be sent. Never
  turn it on without an explicit user request.
- `husk feedback [MESSAGE] [--contact EMAIL]`: send free-text product feedback
  to the husk developers (reads stdin when no MESSAGE is given). No account
  needed; sends only the message, the optional reply email, and the husk
  version. Only run it when the user asks to send feedback.

For machine-readable output always use `--json` (or `husk ci`). Example
scoped offline check: `husk ci --offline . --no-home-inventory`.

## Reading the output

A report contains `stats` (counts by severity), `findings`, `packages`,
`remediations`, `providers` (online feed status; `ok: false` means that
feed was unreachable, not that the code is safe), and `benchmarks`.

Each finding has: `id`, `title`, `severity` (`critical`, `high`, `medium`,
`low`, `info`), `category` (e.g. `secret`, `vulnerability`, `malware`,
`lifecycle-script`, `risky-agent-config`), `path`/`line`, `summary`,
`evidence`, `recommendation`,
`references`, optionally `package` (`ecosystem:name@version`), and optionally `exploit` (`{kev, epss}`: CISA-KEV / high-EPSS CVEs are sorted to the top; fix first).

Interpretation rules:

- Treat `critical`/`high` as action items; `info` is context, not a problem.
- Severity is conservative by design; do not inflate findings when reporting.
- Husk scans are read-only and may flag intentionally unsafe fixtures (e.g. a
  `tst/` directory of test fixtures); check whether a flagged file is a
  fixture before proposing fixes.
- When fixing a finding, follow its `recommendation` and `references`; never
  delete user files or rotate secrets without telling the user what was found
  and where.
- A missing cached report is normal on a fresh install: run a scan first.
