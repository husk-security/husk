//! Command-line interface: the clap definitions, the top-level [`run`]
//! dispatch, and per-command telemetry bookkeeping. Command bodies live in
//! the submodules.

mod check;
mod cloud;
mod fix;
mod pager;
mod policy;
mod render;
mod scan;

use anyhow::Result;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
#[cfg(feature = "web")]
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "husk")]
#[command(about = "Developer security scanner")]
#[command(version)]
#[command(
    long_about = "A local-first developer security scanner: inventories a machine's \
packages, checks them against public advisories, and flags plaintext secrets, risky \
install scripts, git hooks, CI workflows, and AI/MCP agent config. Run `husk` with no \
subcommand to print this help; `husk scan` scans and `husk tui` opens the terminal UI. \
See the commands below.",
    after_long_help = "Cache vs fresh: `scan` and `ci` always scan fresh; `status` only \
reads the cache; `tui` and `fix` reuse the latest cached report unless --rescan \
is given; `web` starts empty unless --rescan is given.\n\n\
Environment variables and common workflows: https://github.com/husk-security/husk#readme"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Look up one package in OSV.dev and print a malware/vulnerability verdict.
    #[command(
        override_usage = "husk check [OPTIONS] <NAME[@VERSION]>\n       husk check [OPTIONS] <ECOSYSTEM> <NAME[@VERSION]> [VERSION]",
        long_about = "Look up one package in the OSV.dev advisory database and print a verdict. \
The version may be a separate argument or an `@version` suffix on the name (split on the \
last `@`, so `@scope/pkg@1.2.3` works). With a version, malware advisories and \
vulnerabilities for that version both count; without one, only malware advisories do. No \
OSV coverage or a failed lookup yields `unknown` (fail-open). Exit status: 0 if clean or \
unknown, 1 if flagged.",
        after_long_help = "Examples:\n  \
husk check lodash                # bare name: npm assumed, malware advisories only\n  \
husk check lodash@4.17.21        # with a version: malware + vulnerabilities\n  \
husk check npm left-pad 1.3.0    # the same, as separate arguments\n  \
husk check pypi requests 2.19.1\n  \
husk check cargo serde --json    # machine-readable verdict"
    )]
    Check(CheckArgs),
    /// Scan now and print the findings report.
    #[command(
        long_about = "Scan the given paths now (default: the current directory) and print the \
report as text, JSON (--json), or an export (--export); always a fresh scan, never the \
cache. It inventories packages and checks for vulnerable/malicious packages, secrets, risky \
install scripts, git hooks, CI workflows, and AI/MCP config, reading files but never running \
them. Unless --offline, package names and versions go to public advisory databases while \
file contents, paths, and secrets stay local. Exit status is 0 unless the scan itself fails; \
use `husk ci` to gate a build on findings.",
        after_long_help = "Examples:\n  \
husk scan                        # scan the current directory\n  \
husk scan --home                 # audit the whole machine\n  \
husk scan --offline ~/work/api   # no network: local checks only\n  \
husk scan --json | jq '.findings[].id'"
    )]
    Scan(ScanArgs),
    /// Plan fixes for findings from the latest scan; write them with --apply.
    #[command(
        long_about = "Plan typed remediations from scan-backed guide controls and, with --apply, write the \
auto-safe ones (config edits, appending to .gitignore, or generating a values-stripped \
.env template); every edit is backed up under .husk/backups/ and reversible with --rollback. \
Dry-run by default; dependency upgrades/downgrades run your package manager only with --deps \
or --all.",
        after_long_help = "Examples:\n  \
husk fix                         # dry run: show the plan, change nothing\n  \
husk fix --apply                 # write the auto-safe fixes (with backups)\n  \
husk fix --apply --only <ID>     # apply one fix from the plan\n  \
husk fix --rollback              # restore the latest backup"
    )]
    Fix(FixArgs),
    /// Open the interactive terminal UI on the latest scan (--rescan to scan now).
    #[command(
        long_about = "Open the interactive terminal UI on the latest cached report for these \
roots, or scan live with --rescan. When stdout is not a terminal it prints the text report \
instead.",
        after_long_help = "Examples:\n  \
husk tui                         # browse the latest scan of this directory\n  \
husk tui --rescan --home         # rescan the whole machine, watch it live"
    )]
    Tui(ReportArgs),
    /// Serve an empty local web UI (--rescan to scan now).
    #[cfg(feature = "web")]
    #[command(
        long_about = "Serve the report web UI and its JSON API on 127.0.0.1:6789 (override with \
--port). Starts without cached findings, or scans with --rescan, and runs until Ctrl-C.",
        after_long_help = "Examples:\n  \
husk web                         # serve http://127.0.0.1:6789 and open it\n  \
husk web --port 7000 --no-open   # different port, no browser launch\n  \
husk web --rescan --home         # fresh whole-machine scan, watch it live"
    )]
    Web(WebArgs),
    /// Scan now and emit the JSON report; exit 1 at or above the fail threshold.
    #[command(
        long_about = "Scan fresh and print the full JSON report on stdout, with progress \
suppressed. Exit status: 1 if any finding is at or above the failure threshold (default \
high; set via `[ci] fail_on` in .husk/policy.toml, or lowered with --fail-on-medium), else 0.",
        after_long_help = "Examples:\n  \
husk ci                          # gate on high+ findings\n  \
husk ci --fail-on-medium         # stricter gate\n  \
husk ci > husk-report.json       # keep the report as a build artifact"
    )]
    Ci(CiArgs),
    /// Scan on an interval and record findings new since the previous run.
    #[command(
        long_about = "Scan every --interval-secs (default 900), refresh the cache, and print a \
one-line per-cycle summary of findings new and resolved since the previous run (state in \
~/.husk/daemon-state.json). Scans the home directory when no path is given; runs until \
interrupted, or --once for a single cycle.",
        after_long_help = "Examples:\n  \
husk daemon                      # scan the home directory every 15 minutes\n  \
husk daemon --once               # one daemon-style cycle, then exit\n  \
husk daemon --interval-secs 3600 --notify   # hourly, with desktop alerts"
    )]
    Daemon(DaemonArgs),
    /// Create a `.husk/policy.toml` project policy.
    #[command(
        long_about = "Create .husk/policy.toml (allow/block coordinates, suppress finding ids, \
set the CI fail threshold) plus a short README in the given directory. Commit .husk/ so \
`husk scan` and `husk ci` discover it by walking up from the scan roots; refuses to \
overwrite an existing policy.",
        after_long_help = "Examples:\n  \
husk init                        # create .husk/ in the current directory\n  \
husk init ~/work/api             # create it in another project"
    )]
    Init(InitArgs),
    /// Record an allow/block/suppress decision in `.husk/policy.toml`.
    #[command(
        override_usage = "husk approve <ECOSYSTEM:NAME[@VERSION]> [--block]\n       \
husk approve <FINDING_ID> --suppress [--reason <REASON>]",
        long_about = "Append a decision to the nearest `.husk/policy.toml`, found by walking \
up from the current directory (run `husk init` first if the project has none). \
Edits are comment-preserving and idempotent. Each new decision is also appended to \
the personal trust ledger at ~/.husk/ledger.jsonl (local only, never uploaded).",
        after_long_help = "Examples:\n  \
husk approve npm:lodash                    # allow every version of a package\n  \
husk approve npm:lodash@4.17.21 --block    # block one version\n  \
husk approve <FINDING_ID> --suppress --reason \"accepted risk\""
    )]
    Approve(ApproveArgs),
    /// Show or verify the personal trust ledger (`~/.husk/ledger.jsonl`).
    #[command(
        long_about = "Print the personal trust ledger at ~/.husk/ledger.jsonl, the hash-chained \
record of every `husk approve` decision. --verify checks the chain and \
exits non-zero if it is broken; the ledger is local-only and deletable at any time.",
        after_long_help = "Examples:\n  \
husk ledger                      # show every recorded decision\n  \
husk ledger --verify             # check the hash chain for tampering\n  \
husk ledger --json"
    )]
    Ledger(LedgerArgs),
    /// Show the active project policy (`.husk/policy.toml`) and its counts.
    #[command(
        long_about = "Print the project policy that scans of the current directory would \
apply: the allowed/blocked package coordinates, suppressed finding ids, and the CI \
failure threshold. The policy file is found by walking up from the current directory; \
errors if none exists (create one with `husk init`).",
        after_long_help = "Examples:\n  \
husk policy                      # show the active policy and its counts\n  \
husk policy --json"
    )]
    Policy(PolicyArgs),
    /// Print the full findings report from the latest scan, without scanning.
    #[command(
        long_about = "Print the latest cached scan report (the same listing `husk scan` renders) \
without scanning; errors if none exists, and warns on stderr when it is over 24 hours old. \
When logged in, also fetches this account's open retroactive alerts. Exit status: 0, or 1 \
when no cached scan exists.",
        after_long_help = "Examples:\n  \
husk status                      # the full report from the last scan\n  \
husk status | grep -i secret     # grep the cached findings\n  \
husk status --json | jq .stats"
    )]
    Status(StatusArgs),
    /// Account sign-in is coming soon.
    #[command(
        long_about = "Account sign-in is coming soon; running `husk login` makes no network \
request and local scanning stays fully available. HUSK_TOKEN still provides a one-off \
credential to the existing cloud commands.",
        after_long_help = "Examples:\n  \
husk login                       # print the current sign-in availability"
    )]
    Login,
    /// Delete the credentials stored on this machine.
    #[command(
        long_about = "Delete credentials stored on this machine. This does not clear an \
environment-provided HUSK_TOKEN; unset that variable to end the corresponding session.",
        after_long_help = "Examples:\n  husk logout"
    )]
    Logout,
    /// Show the signed-in account, backend, machine link, and telemetry state.
    #[command(after_long_help = "Examples:\n  husk account")]
    Account,
    /// Upload the last scan's package inventory to enable retroactive alerts.
    #[command(
        long_about = "Upload the last cached scan's package inventory (only {ecosystem, name, \
version} triples, no file contents or paths) so the backend can alert you when a version is \
later flagged (see `husk alerts`). Requires a stored credential or HUSK_TOKEN plus a cached \
scan.",
        after_long_help = "Examples:\n  husk scan --home && husk sync"
    )]
    Sync,
    /// List this account's retroactive alerts from the husk backend.
    #[command(
        long_about = "List retroactive alerts: packages from a synced inventory that threat \
intel flagged AFTER they were uploaded (see `husk sync`). Shows open alerts by \
default. Requires an existing stored credential or HUSK_TOKEN while new account sign-in \
is unavailable.",
        after_long_help = "Examples:\n  \
husk alerts                      # open alerts only\n  \
husk alerts --all --json         # everything, machine-readable"
    )]
    Alerts(AlertsArgs),
    /// Manage opt-in anonymous telemetry (off by default; nothing is sent unless enabled).
    #[command(
        long_about = "Manage opt-in anonymous telemetry. Off by default; when enabled, husk \
sends one aggregate summary per completed day: bucketed usage counters with no identifier, \
no paths, and no package or project names.",
        after_long_help = "Examples:\n  \
husk telemetry status            # is it on, and what is pending\n  \
husk telemetry status --payload  # the exact JSON that would be sent\n  \
husk telemetry on\n  \
husk telemetry off               # also deletes all local telemetry state"
    )]
    Telemetry(TelemetryArgs),
    /// Send free-text feedback about husk to the husk developers.
    #[command(
        long_about = "Send free-text feedback to the husk developers. Reads the message from \
the argument, or from stdin when no argument is given. Sends only the message, an optional \
reply email (--contact), and the husk version; nothing else leaves the machine, and no \
account is needed.",
        after_long_help = "Examples:\n  \
husk feedback \"The TUI is great, but scans feel slow on my monorepo\"\n  \
husk feedback --contact dev@example.com \"Found a rough edge in husk fix\"\n  \
git log -1 --format=%s | husk feedback"
    )]
    Feedback(FeedbackArgs),
    /// Run the MCP server on stdio, or register it with an AI agent.
    #[command(
        long_about = "With no subcommand, serve the Model Context Protocol server over stdio \
(JSON-RPC; stdout is protocol-only). Agents normally launch this themselves after \
`husk mcp install <AGENT>` registers it in the agent's config file.",
        after_long_help = "Examples:\n  \
husk mcp install claude-desktop  # register with an agent (project-local)\n  \
husk mcp install codex --global --dry-run\n  \
husk mcp --selfcheck             # verify the server can start"
    )]
    Mcp(McpArgs),
}

#[derive(Clone, Debug, Args)]
struct FeedbackArgs {
    /// The feedback text. Omit it to read the message from stdin.
    #[arg(value_name = "MESSAGE")]
    message: Option<String>,

    /// Optional reply email to include with the feedback.
    #[arg(long, value_name = "EMAIL")]
    contact: Option<String>,
}

#[derive(Clone, Debug, Args)]
struct McpArgs {
    #[command(subcommand)]
    command: Option<McpCommand>,

    /// Validate the server can start (tools + cache reachable) and exit, instead of serving.
    #[arg(long)]
    selfcheck: bool,
}

#[derive(Clone, Debug, Subcommand)]
enum McpCommand {
    /// Register husk's MCP server in an agent's config file (idempotent).
    Install(AgentInstallArgs),
}

#[derive(Clone, Debug, Args)]
struct AgentInstallArgs {
    /// Which agent's config to write.
    #[arg(value_name = "claude-desktop|cursor|vscode|gemini|codex|opencode")]
    agent: String,
    /// Write to the global user config instead of a project-local config.
    #[arg(long)]
    global: bool,
    /// Show what would change without writing anything.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Clone, Debug, Args)]
struct InitArgs {
    /// Project directory to initialize (defaults to the current directory).
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,
}

#[derive(Clone, Debug, Args)]
struct ApproveArgs {
    /// Package coordinate `ecosystem:name[@version]`, or a finding id with `--suppress`.
    #[arg(
        value_name = "TARGET",
        long_help = "A package coordinate `ecosystem:name[@version]` (e.g. npm:lodash or \
npm:lodash@4.17.21), or a finding id when used with `--suppress`."
    )]
    target: String,

    /// Block this coordinate instead of allowing it.
    #[arg(long, conflicts_with = "suppress")]
    block: bool,

    /// Treat TARGET as a finding id to suppress (records a `[[suppress]]` entry).
    #[arg(long)]
    suppress: bool,

    /// Reason to record alongside a `--suppress` entry.
    #[arg(long, requires = "suppress")]
    reason: Option<String>,
}

#[derive(Clone, Debug, Args)]
struct LedgerArgs {
    /// Print the ledger as JSON.
    #[arg(long)]
    json: bool,

    /// Verify the hash chain is intact instead of printing it.
    #[arg(long)]
    verify: bool,
}

#[derive(Clone, Debug, Args)]
struct PolicyArgs {
    /// Print the policy as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Debug, Args)]
struct CheckArgs {
    /// Package: `NAME[@VERSION]`, `ECOSYSTEM NAME[@VERSION]`, or `ECOSYSTEM NAME VERSION`.
    #[arg(
        value_name = "PACKAGE",
        required = true,
        num_args = 1..=3,
        long_help = "The package to check, as 1-3 positional arguments: `NAME` (npm \
assumed), `ECOSYSTEM NAME`, or `ECOSYSTEM NAME VERSION`, e.g. `husk check pypi requests \
2.19.1`. The name may instead carry the version as an `@version` suffix, so `husk check \
lodash@4.17.21` equals `husk check npm lodash 4.17.21`; the split is on the last `@`, so a \
scoped npm name keeps its scope. Passing both a suffix and a VERSION argument is an error. \
Without a version, only malicious-package advisories count."
    )]
    spec: Vec<String>,

    /// Treat advisories newer than HOURS as within cooldown.
    #[arg(
        long,
        value_name = "HOURS",
        default_value_t = crate::check::DEFAULT_COOLDOWN_HOURS,
        long_help = "Mark advisories published within the last HOURS as newly published \
(shown as \"within cooldown\"). Does not change the exit status."
    )]
    cooldown_hours: i64,

    /// Print the verdict as JSON.
    #[arg(long)]
    json: bool,
}

/// Scan-scope flags shared by every scan-shaped command: which paths to scan
/// and how. Output flags (`--json`, `--export`, `--rescan`) live on the
/// commands that actually honor them.
#[derive(Clone, Debug, Args)]
struct ScanScopeArgs {
    /// Paths to scan. Defaults to the current directory.
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Scan the whole home directory instead of only the current directory.
    #[arg(
        long,
        long_help = "Scan the whole home directory instead of only the current directory. \
Takes precedence over any PATH arguments. This is the fullest audit husk can do and \
what `husk sync` expects to have run."
    )]
    home: bool,

    /// Skip all network lookups; local checks still run.
    #[arg(
        long,
        long_help = "Run fully offline: no queries to the public advisory databases (OSV.dev, \
npm, PyPI, GitHub) and no CISA KEV / FIRST EPSS exploit enrichment. Local checks \
(package inventory, secrets, install scripts, git hooks, CI workflows, AI/MCP configs) \
still run in full; advisory-backed vulnerability findings are simply unavailable, so \
an offline report can understate risk."
    )]
    offline: bool,

    /// Do not add known home inventory locations such as editor extensions and MCP configs.
    #[arg(long)]
    no_home_inventory: bool,
}

/// `husk scan` flags: always a fresh scan, printed as text, JSON, or an export.
#[derive(Clone, Debug, Args)]
struct ScanArgs {
    #[command(flatten)]
    scope: ScanScopeArgs,

    /// Print full JSON instead of the text summary.
    #[arg(
        long,
        long_help = "Print the full scan report as JSON instead of the text summary. The \
top-level fields are documented in the JSON output section of the README \
(https://github.com/husk-security/husk#json-output). Never paged, never colored; safe \
to pipe straight into jq."
    )]
    json: bool,

    /// Export findings instead of the text summary (json, csv, md).
    #[arg(
        long,
        value_name = "FORMAT",
        long_help = "Export the open findings to stdout in this format instead of the text \
summary: `json` (the full report, same as --json), `csv` (one row per finding), or \
`md` (a Markdown table)."
    )]
    export: Option<crate::export::ExportFormat>,

    /// Print the text report directly instead of through a pager.
    #[arg(
        long,
        long_help = "Print the text report directly instead of through a pager. On a terminal \
the report is otherwise paged via HUSK_PAGER > PAGER > less (an empty value or `cat` \
also disables paging); off a terminal output is never paged."
    )]
    no_pager: bool,
}

/// Flags for the cache-aware report commands (`tui`; also flattened
/// into `fix`): serve the cached report unless `--rescan` asks for a fresh one.
#[derive(Clone, Debug, Args)]
struct ReportArgs {
    #[command(flatten)]
    scope: ScanScopeArgs,

    /// Print full JSON instead of the text summary.
    #[arg(
        long,
        long_help = "Print JSON instead of the text output: the full scan report, whose \
fields are documented in the JSON output section of the README \
(https://github.com/husk-security/husk#json-output)."
    )]
    json: bool,

    /// Ignore the cached report and scan now.
    #[arg(
        long,
        long_help = "Ignore the cached report and scan now, with the same network behavior \
as `husk scan`. Without it, the latest cached report for the same roots is served \
when one exists."
    )]
    rescan: bool,
}

#[derive(Clone, Debug, Args)]
struct CiArgs {
    #[command(flatten)]
    scope: ScanScopeArgs,

    /// Exit non-zero on medium findings as well as high and critical findings.
    #[arg(long)]
    fail_on_medium: bool,
}

/// `husk fix` flags. Dry-run by default: with no `--apply`/`--yes` it prints the
/// plan and writes nothing.
#[derive(Clone, Debug, Args)]
struct FixArgs {
    #[command(flatten)]
    scan: ReportArgs,

    /// Apply the auto-safe fixes (otherwise this is a dry run that writes nothing).
    #[arg(long, conflicts_with_all = ["dry_run"])]
    apply: bool,

    /// Non-interactive apply of the auto-safe fixes (alias for --apply here).
    #[arg(long, conflicts_with_all = ["dry_run"])]
    yes: bool,

    /// Explicit dry run (the default): show the plan, change nothing.
    #[arg(long, conflicts_with_all = ["apply", "yes"])]
    dry_run: bool,

    /// Only act on the fix with this id (ids are shown in the plan output).
    #[arg(long, value_name = "ID")]
    only: Option<String>,

    /// Also run dependency upgrade/downgrade commands (opt-in).
    #[arg(
        long,
        long_help = "With --apply, also run the dependency upgrade/downgrade commands. \
They execute your package manager, so they are opt-in."
    )]
    deps: bool,

    /// Apply the auto-safe fixes and every dependency change (implies --yes --deps).
    #[arg(
        long,
        conflicts_with_all = ["dry_run"],
        long_help = "Apply everything in one shot: the auto-safe fixes AND every \
dependency upgrade/downgrade (implies --yes --deps). Runs your package manager."
    )]
    all: bool,

    /// Restore files from the latest (or a named) `husk fix` backup, then exit.
    #[arg(long, value_name = "TIMESTAMP", num_args = 0..=1, default_missing_value = "")]
    rollback: Option<String>,
}

#[cfg(feature = "web")]
#[derive(Clone, Debug, Args)]
struct WebArgs {
    #[command(flatten)]
    scope: ScanScopeArgs,

    /// Scan immediately instead of starting with an empty report.
    #[arg(long)]
    rescan: bool,

    /// Address to bind. Defaults to localhost.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    host: IpAddr,

    /// Port to bind.
    #[arg(long, default_value_t = 6789)]
    port: u16,

    /// Do not try to open the localhost web UI in the system browser.
    #[arg(long)]
    no_open: bool,

    /// Dev: serve only the JSON API and don't open a browser.
    #[arg(
        long,
        long_help = "Development mode: serve only the JSON API (no embedded UI) and don't \
open a browser. Run the Vite dev server yourself (`npm --prefix web run dev`)."
    )]
    dev: bool,
}

#[derive(Clone, Debug, Args)]
struct DaemonArgs {
    #[command(flatten)]
    scope: ScanScopeArgs,

    /// Seconds between scans.
    #[arg(long, value_name = "SECONDS", default_value_t = 900)]
    interval_secs: u64,

    /// Run one daemon-style scan and exit.
    #[arg(long)]
    once: bool,

    /// Desktop-notify on findings new since the last scan (Linux).
    #[arg(
        long,
        long_help = "Send a desktop notification for findings that are NEW since the last \
scan (Linux only, via notify-send)."
    )]
    notify: bool,
}

#[derive(Clone, Debug, Args)]
struct StatusArgs {
    /// Print cached report JSON.
    #[arg(
        long,
        long_help = "Print the cached report as JSON. The top-level fields are documented in the \
JSON output section of the README (https://github.com/husk-security/husk#json-output). \
Never paged, never colored; safe to pipe straight into jq."
    )]
    json: bool,

    /// Print the text report directly instead of through a pager.
    #[arg(
        long,
        long_help = "Print the text report directly instead of through a pager. On a terminal \
the report is otherwise paged via HUSK_PAGER > PAGER > less (an empty value or `cat` \
also disables paging); off a terminal output is never paged."
    )]
    no_pager: bool,

    /// Show scan history instead of the latest report.
    #[arg(
        long,
        long_help = "Show scan history: every completed scan grouped per scan target, oldest \
first, with security score, findings, what changed, and the fixes Husk applied. Combine \
with --json for the raw history rows."
    )]
    history: bool,
}

#[derive(Clone, Debug, Args)]
struct AlertsArgs {
    /// Include acknowledged and resolved alerts, not only open ones.
    #[arg(long)]
    all: bool,

    /// Print alerts as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Debug, Args)]
struct TelemetryArgs {
    #[command(subcommand)]
    action: Option<TelemetryAction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
enum TelemetryAction {
    /// Turn anonymous daily telemetry on.
    On,
    /// Turn telemetry off and delete all local telemetry state.
    Off,
    /// Show whether telemetry is on and how many daily reports are pending.
    Status(TelemetryStatusArgs),
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
struct TelemetryStatusArgs {
    /// Print exactly the JSON payload that would be sent.
    #[arg(long)]
    payload: bool,
}

/// git-style grouped command list rendered in the top-level `husk --help`.
///
/// clap 4 lists subcommands in one flat block, so the grouping is a
/// hand-maintained table injected into the help template in place of the
/// `{subcommands}` placeholder. Each row is one command and a one-line
/// description; a test (`every_visible_subcommand_is_categorized`) asserts
/// every non-hidden subcommand appears here exactly once, so a new command
/// cannot silently fall out of the help.
fn categorized_commands() -> String {
    use std::fmt::Write as _;

    let categories: [(&str, &[(&str, &str)]); 6] = [
        (
            "Scan & view",
            &[
                ("scan", "Scan now and print the findings report"),
                ("status", "Print the last scan's report without rescanning"),
                ("tui", "Open the interactive terminal UI on the latest scan"),
                #[cfg(feature = "web")]
                ("web", "Serve the local web UI on the latest scan"),
            ],
        ),
        (
            "Vet & fix",
            &[
                (
                    "check",
                    "Look up one package's malware/vulnerability verdict",
                ),
                ("ci", "Scan and gate a build; exit 1 at/above the threshold"),
                (
                    "fix",
                    "Plan fixes from the latest scan; write them with --apply",
                ),
            ],
        ),
        (
            "Project policy",
            &[
                (
                    "init",
                    "Create a committed .husk/policy.toml project policy",
                ),
                (
                    "approve",
                    "Record an allow/block/suppress decision in the policy",
                ),
                ("policy", "Show the active project policy and its counts"),
                ("ledger", "Show or verify the personal trust ledger"),
            ],
        ),
        (
            "Background",
            &[(
                "daemon",
                "Scan on an interval; report findings new since last run",
            )],
        ),
        (
            "Account",
            &[
                ("login", "Sign in to a husk account (coming soon)"),
                ("logout", "Delete the credentials stored on this machine"),
                ("account", "Show the signed-in account and machine link"),
                (
                    "sync",
                    "Upload the last scan's inventory for retroactive alerts",
                ),
                ("alerts", "List this account's retroactive alerts"),
                (
                    "telemetry",
                    "Manage opt-in anonymous telemetry (off by default)",
                ),
                ("feedback", "Send feedback to the husk developers"),
            ],
        ),
        (
            "Integrations",
            &[("mcp", "Run the MCP server, or register it with an AI agent")],
        ),
    ];

    let width = categories
        .iter()
        .flat_map(|(_, rows)| rows.iter())
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    for (i, (title, rows)) in categories.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let _ = writeln!(out, "{title}:");
        for (name, desc) in rows.iter() {
            let _ = writeln!(out, "  {name:width$}  {desc}");
        }
    }
    out
}

/// The clap command with the grouped-command help template applied. Used for
/// both parsing and the categorization test.
fn cli_command() -> clap::Command {
    let template = format!(
        "{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{}\nOptions:\n{{options}}{{after-help}}",
        categorized_commands()
    );
    Cli::command().help_template(template)
}

pub async fn run() -> Result<()> {
    let matches = cli_command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    // Suppress telemetry uploads before recording the command when this run
    // promises not to touch the network. Events may still spool locally.
    if command_suppresses_telemetry_flush(cli.command.as_ref()) {
        crate::cloud::telemetry::set_offline(true);
    }
    record_command_telemetry(cli.command.as_ref());
    let result = dispatch(cli.command).await;
    // Await any in-flight telemetry upload (bounded by its own deadline)
    // before the runtime is torn down; a detached task would be cancelled
    // mid-request when a short command exits. Runs on the error path too so
    // a failing command still delivers what it spooled.
    crate::cloud::telemetry::settle_flushes().await;
    result
}

async fn dispatch(command: Option<Command>) -> Result<()> {
    match command {
        Some(Command::Check(args)) => check::run_check(args).await?,
        Some(Command::Scan(args)) => scan::run_scan_cmd(args).await?,
        Some(Command::Fix(args)) => fix::run_fix(args).await?,
        Some(Command::Tui(args)) => scan::run_tui(args).await?,
        #[cfg(feature = "web")]
        Some(Command::Web(args)) => scan::run_web(args).await?,
        Some(Command::Ci(args)) => scan::run_ci(args).await?,
        Some(Command::Daemon(args)) => scan::run_daemon(args).await?,
        Some(Command::Login) => cloud::run_login().await?,
        Some(Command::Logout) => cloud::run_logout().await?,
        Some(Command::Account) => cloud::run_account().await?,
        Some(Command::Sync) => cloud::run_sync().await?,
        Some(Command::Alerts(args)) => cloud::run_alerts(args).await?,
        Some(Command::Telemetry(args)) => cloud::run_telemetry(args)?,
        Some(Command::Feedback(args)) => cloud::run_feedback(args).await?,
        Some(Command::Mcp(args)) => match args.command {
            Some(McpCommand::Install(install)) => {
                crate::agent::install(&install.agent, install.global, install.dry_run)?;
            }
            None if args.selfcheck => {
                crate::mcp::selfcheck()?;
            }
            None => {
                crate::mcp::run().await?;
            }
        },
        Some(Command::Init(args)) => policy::run_init(args)?,
        Some(Command::Approve(args)) => policy::run_approve(args)?,
        Some(Command::Ledger(args)) => policy::run_ledger(args)?,
        Some(Command::Policy(args)) => policy::run_policy_show(args)?,
        Some(Command::Status(args)) => scan::run_status(args).await?,
        // Bare `husk` with no subcommand prints the top-level help and exits 0,
        // matching git/cargo/docker. `husk scan`/`web`/`tui` are the entry points.
        None => {
            cli_command().print_long_help()?;
        }
    }

    Ok(())
}

/// Telemetry wire name of a subcommand: the name only, never arguments.
fn command_telemetry_name(command: Option<&Command>) -> &'static str {
    match command {
        None => "default",
        Some(Command::Check(_)) => "check",
        Some(Command::Scan(_)) => "scan",
        Some(Command::Fix(_)) => "fix",
        Some(Command::Tui(_)) => "tui",
        #[cfg(feature = "web")]
        Some(Command::Web(_)) => "web",
        Some(Command::Ci(_)) => "ci",
        Some(Command::Daemon(_)) => "daemon",
        Some(Command::Init(_)) => "init",
        Some(Command::Approve(_)) => "approve",
        Some(Command::Ledger(_)) => "ledger",
        Some(Command::Policy(_)) => "policy",
        Some(Command::Status(_)) => "status",
        Some(Command::Login) => "login",
        Some(Command::Logout) => "logout",
        Some(Command::Account) => "account",
        Some(Command::Sync) => "sync",
        Some(Command::Alerts(_)) => "alerts",
        Some(Command::Telemetry(_)) => "telemetry",
        Some(Command::Feedback(_)) => "feedback",
        Some(Command::Mcp(_)) => "mcp",
    }
}

/// Whether this invocation must suppress the opportunistic telemetry upload.
fn command_suppresses_telemetry_flush(command: Option<&Command>) -> bool {
    match command {
        Some(Command::Login) => !crate::cloud::LOGIN_AVAILABLE,
        Some(Command::Scan(args)) => args.scope.offline,
        Some(Command::Tui(args)) => args.scope.offline,
        Some(Command::Ci(args)) => args.scope.offline,
        #[cfg(feature = "web")]
        Some(Command::Web(args)) => args.scope.offline,
        Some(Command::Daemon(args)) => args.scope.offline,
        _ => false,
    }
}

/// Bump this invocation's `cli.run.<command>` counter, roll any completed
/// day into the pending spool, and start the background upload. Runs on
/// every invocation so report delivery never depends on what the command
/// does; all of it is a no-op unless the user opted in.
fn record_command_telemetry(command: Option<&Command>) {
    if !crate::cloud::telemetry::is_enabled() {
        return;
    }
    crate::cloud::telemetry::bump_one(crate::cloud::telemetry::counters::cli_run(
        command_telemetry_name(command),
    ));
    crate::cloud::telemetry::deliver_in_background();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("arguments should parse")
    }

    /// Every non-hidden subcommand must appear exactly once in the grouped
    /// top-level help, and the grouped list must carry no stale entries, so a
    /// new command cannot silently fall out of `husk --help`.
    #[test]
    fn every_visible_subcommand_is_categorized() {
        let block = categorized_commands();
        let entries: Vec<&str> = block
            .lines()
            .filter_map(|line| line.strip_prefix("  "))
            .map(|row| row.split_whitespace().next().unwrap_or_default())
            .collect();

        for sub in cli_command().get_subcommands() {
            if sub.is_hide_set() || sub.get_name() == "help" {
                continue;
            }
            let name = sub.get_name();
            let count = entries.iter().filter(|entry| **entry == name).count();
            assert_eq!(
                count, 1,
                "subcommand `{name}` should be listed exactly once"
            );
        }

        let mut cmd = cli_command();
        let visible: std::collections::HashSet<&str> = cmd
            .get_subcommands()
            .filter(|s| !s.is_hide_set() && s.get_name() != "help")
            .map(|s| s.get_name())
            .collect();
        for entry in &entries {
            assert!(
                visible.contains(entry),
                "grouped help lists `{entry}`, which is not a visible subcommand"
            );
        }

        // The rendered help must actually contain the grouped block.
        let help = cmd.render_long_help().to_string();
        assert!(help.contains("Scan & view:"));
        assert!(help.contains("Project policy:"));
    }

    /// No user-facing help text may contain an em dash (U+2014) or en dash
    /// (U+2013); they read as machine-generated. This renders the short and
    /// long help for the root command and every subcommand (the same output
    /// the README command reference is generated from) and rejects either
    /// character. See the "User-facing text" rule in AGENTS.md.
    #[test]
    fn help_text_has_no_em_or_en_dashes() {
        fn check(cmd: &mut clap::Command) {
            let name = cmd.get_name().to_string();
            for rendered in [
                cmd.render_help().to_string(),
                cmd.render_long_help().to_string(),
            ] {
                assert!(
                    !rendered.contains('\u{2014}') && !rendered.contains('\u{2013}'),
                    "`husk {name} --help` contains an em/en dash; rewrite it with a \
                     period, comma, colon, semicolon, or parentheses (AGENTS.md: \
                     User-facing text)"
                );
            }
            let subs: Vec<String> = cmd
                .get_subcommands()
                .map(|s| s.get_name().to_string())
                .collect();
            for sub in subs {
                if let Some(inner) = cmd.find_subcommand_mut(&sub) {
                    check(inner);
                }
            }
        }
        check(&mut cli_command());
    }

    #[test]
    fn parses_cloud_account_subcommands() {
        assert!(matches!(
            parse(&["husk", "login"]).command,
            Some(Command::Login)
        ));
        assert!(matches!(
            parse(&["husk", "logout"]).command,
            Some(Command::Logout)
        ));
        assert!(matches!(
            parse(&["husk", "account"]).command,
            Some(Command::Account)
        ));
        assert!(matches!(
            parse(&["husk", "sync"]).command,
            Some(Command::Sync)
        ));
    }

    #[test]
    fn unavailable_login_suppresses_the_telemetry_flush() {
        let cli = parse(&["husk", "login"]);
        assert!(command_suppresses_telemetry_flush(cli.command.as_ref()));
    }

    #[test]
    fn parses_alerts_flags() {
        let Some(Command::Alerts(args)) = parse(&["husk", "alerts"]).command else {
            panic!("expected alerts command");
        };
        assert!(!args.all);
        assert!(!args.json);

        let Some(Command::Alerts(args)) = parse(&["husk", "alerts", "--all", "--json"]).command
        else {
            panic!("expected alerts command");
        };
        assert!(args.all);
        assert!(args.json);
    }

    #[test]
    fn parses_feedback_message_and_contact() {
        let Some(Command::Feedback(args)) = parse(&["husk", "feedback", "love it"]).command else {
            panic!("expected feedback command");
        };
        assert_eq!(args.message.as_deref(), Some("love it"));
        assert_eq!(args.contact, None);

        let Some(Command::Feedback(args)) =
            parse(&["husk", "feedback", "--contact", "dev@example.com"]).command
        else {
            panic!("expected feedback command");
        };
        // No positional message: the command reads stdin at run time.
        assert_eq!(args.message, None);
        assert_eq!(args.contact.as_deref(), Some("dev@example.com"));

        assert_eq!(
            command_telemetry_name(parse(&["husk", "feedback", "hi"]).command.as_ref()),
            "feedback"
        );
    }

    #[test]
    fn parses_telemetry_actions() {
        for (input, expected) in [
            ("on", TelemetryAction::On),
            ("off", TelemetryAction::Off),
            (
                "status",
                TelemetryAction::Status(TelemetryStatusArgs { payload: false }),
            ),
        ] {
            let Some(Command::Telemetry(args)) = parse(&["husk", "telemetry", input]).command
            else {
                panic!("expected telemetry command for {input}");
            };
            assert_eq!(args.action, Some(expected), "telemetry action {input}");
        }

        let Some(Command::Telemetry(args)) =
            parse(&["husk", "telemetry", "status", "--payload"]).command
        else {
            panic!("expected telemetry status command");
        };
        assert_eq!(
            args.action,
            Some(TelemetryAction::Status(TelemetryStatusArgs {
                payload: true
            }))
        );

        let Some(Command::Telemetry(args)) = parse(&["husk", "telemetry"]).command else {
            panic!("expected telemetry command");
        };
        assert_eq!(args.action, None);
    }

    #[test]
    fn rejects_unknown_telemetry_action_and_requires_one() {
        assert!(Cli::try_parse_from(["husk", "telemetry", "bogus"]).is_err());
        assert!(Cli::try_parse_from(["husk", "telemetry", "show"]).is_err());
        // v2 has no install id, so the v1 rotation actions are gone.
        assert!(Cli::try_parse_from(["husk", "telemetry", "reset-id"]).is_err());
        assert!(Cli::try_parse_from(["husk", "telemetry", "reset"]).is_err());
    }

    #[test]
    fn fix_apply_flags_conflict_with_dry_run() {
        assert!(Cli::try_parse_from(["husk", "fix", "--apply", "--dry-run"]).is_err());
        assert!(Cli::try_parse_from(["husk", "fix", "--yes", "--dry-run"]).is_err());
    }

    #[test]
    fn rejects_removed_install_gate_commands() {
        assert!(Cli::try_parse_from(["husk", "gate", "init"]).is_err());
        assert!(Cli::try_parse_from(["husk", "gate", "run", "npm", "--", "install", "x"]).is_err());
        assert!(Cli::try_parse_from(["husk", "install-gate"]).is_err());
        assert!(Cli::try_parse_from(["husk", "gate-run", "npm", "--", "install", "x"]).is_err());
    }

    #[test]
    fn parses_mcp_install() {
        assert!(matches!(
            parse(&["husk", "mcp", "install", "codex", "--global", "--dry-run"]).command,
            Some(Command::Mcp(McpArgs {
                command: Some(McpCommand::Install(AgentInstallArgs {
                    agent,
                    global: true,
                    dry_run: true
                })),
                selfcheck: false
            })) if agent == "codex"
        ));
        assert!(Cli::try_parse_from(["husk", "agent", "install", "codex"]).is_err());
    }

    #[test]
    fn output_flags_exist_only_where_honored() {
        // `scan` is always fresh: no `--rescan`. `--export` is scan-only.
        assert!(Cli::try_parse_from(["husk", "scan", "--rescan"]).is_err());
        assert!(
            parse(&["husk", "scan", "--export", "csv"])
                .command
                .is_some()
        );
        for cmd in ["tui", "fix"] {
            assert!(parse(&["husk", cmd, "--rescan"]).command.is_some());
            assert!(Cli::try_parse_from(["husk", cmd, "--export", "csv"]).is_err());
        }
        // `daemon` and `ci` have fixed output; `status` has no `--tui`.
        assert!(Cli::try_parse_from(["husk", "daemon", "--json"]).is_err());
        assert!(Cli::try_parse_from(["husk", "ci", "--json"]).is_err());
        assert!(Cli::try_parse_from(["husk", "status", "--tui"]).is_err());
    }

    #[test]
    fn policy_has_no_hidden_show_action() {
        assert!(matches!(
            parse(&["husk", "policy"]).command,
            Some(Command::Policy(PolicyArgs { json: false }))
        ));
        assert!(Cli::try_parse_from(["husk", "policy", "show"]).is_err());
    }

    #[test]
    fn telemetry_command_names_are_subcommand_words_only() {
        assert_eq!(command_telemetry_name(None), "default");
        assert_eq!(
            command_telemetry_name(parse(&["husk", "alerts", "--all"]).command.as_ref()),
            "alerts"
        );
        assert_eq!(
            command_telemetry_name(parse(&["husk", "sync"]).command.as_ref()),
            "sync"
        );
    }
}
