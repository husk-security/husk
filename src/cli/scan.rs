//! The scan-shaped command bodies (`husk scan`, `tui`, `web`, `ci`,
//! `status`, `daemon`) plus the scan plumbing they share: turning CLI
//! flags into `ScanOptions`, the cache-or-rescan helper, live-scan waiting, the
//! localhost web bootstrap (behind the `web` feature), the one-time online-scan
//! notice, and the daemon's new-findings desktop notification.

#[cfg(feature = "web")]
use super::WebArgs;
use super::cloud::surface_open_alerts;
use super::pager;
use super::render::{print_report, print_tui_exit_report, render_report_text};
use super::{CiArgs, DaemonArgs, ReportArgs, ScanArgs, ScanScopeArgs, StatusArgs};
use crate::cloud;
use crate::model::{ScanOptions, ScanReport, Severity};
use crate::scan::{new_live_scan, run_scan};
use anyhow::{Context, Result};
use std::io::IsTerminal;
#[cfg(feature = "web")]
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::process::Stdio;
use std::time::{Duration, Instant};

pub(super) async fn run_scan_cmd(args: ScanArgs) -> Result<()> {
    let quiet = args.json || args.export.is_some();
    if !quiet {
        eprintln!("Husk scan: scanning now...");
    }
    let report = run_and_cache_scan(options_from_args(&args.scope, quiet)?).await?;
    if let Some(format) = args.export {
        println!("{}", crate::export::render(format, &report));
        return Ok(());
    }
    if args.json {
        print_report(&report, true)?;
    } else {
        deliver_report(render_report_text(&report), args.no_pager).await?;
    }
    // The one place husk ever asks about telemetry: after a successful
    // interactive scan has printed its results. A no-op off a terminal, in
    // CI, under a kill switch, or once the user has decided.
    cloud::telemetry::prompt_for_consent_if_due();
    Ok(())
}

/// Deliver a rendered report through the pager off the async path.
/// `pager::deliver` blocks until the pager process exits (the user quits
/// `less`), so run it on a blocking thread to avoid holding a Tokio worker.
/// The fail-open-to-plain-stdout behavior is entirely inside `deliver`.
async fn deliver_report(text: String, no_pager: bool) -> Result<()> {
    tokio::task::spawn_blocking(move || pager::deliver(&text, no_pager)).await?;
    Ok(())
}

/// One colored stderr line when the report being served is older than
/// `cache::STALE_REPORT_AFTER_HOURS`; on stderr so greppable/JSON stdout
/// stays untouched. A fresh scan's `generated_at` is now, so this is
/// naturally silent after any rescan.
fn warn_if_stale(report: &ScanReport) {
    if let Some(notice) = crate::cache::stale_notice(report.generated_at, chrono::Utc::now()) {
        eprintln!("{}", crate::term::color_stderr(notice, "33;1"));
    }
}

pub(super) async fn run_tui(args: ReportArgs) -> Result<()> {
    let options = options_from_args(&args.scope, args.json)?;
    if !args.rescan
        && let Some(report) =
            crate::cache::load_latest_report(&normalize_roots_for_cache(&options)?)?
    {
        if std::io::stdout().is_terminal() {
            cloud::telemetry::bump_one(cloud::telemetry::counters::TUI_SESSION);
            crate::tui::run(report.clone())?;
        }
        print_tui_exit_report(&report, false, args.json)?;
        return Ok(());
    }
    let live = new_live_scan(&options)?;
    crate::scan::spawn_scan(options, live.clone());
    if std::io::stdout().is_terminal() {
        cloud::telemetry::bump_one(cloud::telemetry::counters::TUI_SESSION);
        crate::tui::run_live(live.clone(), None)?;
        let snapshot = live
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        print_tui_exit_report(&snapshot.report, snapshot.running, args.json)?;
    } else {
        wait_for_scan(live.clone()).await;
        let report = live
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .report
            .clone();
        print_report(&report, args.json)?;
    }
    Ok(())
}

#[cfg(feature = "web")]
pub(super) async fn run_web(args: WebArgs) -> Result<()> {
    let options = options_from_args(&args.scope, false)?;
    // Serve a cached project report on open: the one for these roots when it
    // exists, else the newest project report of any roots — the UI names the
    // scanned directory and its age, and Rescan targets these roots. Idle (an
    // empty screen) only when no stored project report is readable at all.
    let cached = if args.rescan {
        None
    } else {
        match crate::cache::load_latest_report(&normalize_roots_for_cache(&options)?)? {
            Some(report) => Some(report),
            None => crate::cache::load_any_project_report()?,
        }
    };
    let live = if args.rescan {
        new_live_scan(&options)?
    } else if let Some(report) = cached {
        std::sync::Arc::new(std::sync::RwLock::new(crate::model::LiveScan::finished(
            report,
        )))
    } else {
        std::sync::Arc::new(std::sync::RwLock::new(crate::model::LiveScan::idle(
            options.roots.clone(),
        )))
    };
    // The machine slot opens on the stored machine posture; the top-bar chip
    // reads it and offers the machine scan when there is none yet.
    let machine = match crate::cache::load_machine_report()? {
        Some(report) => std::sync::Arc::new(std::sync::RwLock::new(
            crate::model::LiveScan::finished(report),
        )),
        None => std::sync::Arc::new(std::sync::RwLock::new(crate::model::LiveScan::idle(
            dirs::home_dir().map(|home| vec![home]).unwrap_or_default(),
        ))),
    };
    if args.dev {
        println!("Dev mode: serving the JSON API only.");
        println!(
            "Start the front-end with hot reload: cd web && npm run dev  (http://127.0.0.1:5181)"
        );
    }
    let session = start_scan_web(
        ScanSlots {
            project: live,
            machine,
        },
        options,
        args.host,
        args.port,
        !args.no_open && !args.dev,
        true,
        args.dev,
    )
    .await?;
    cloud::telemetry::bump_one(cloud::telemetry::counters::WEB_SESSION);
    println!("Press Ctrl-C to stop.");
    serve_until_ctrl_c(session).await
}

pub(super) async fn run_ci(args: CiArgs) -> Result<()> {
    let started = Instant::now();
    // Quiet: the output contract is JSON-only, so no notices on stderr either.
    let report = run_scan(options_from_args(&args.scope, true)?).await?;
    cloud::telemetry::record_scan(&report, started.elapsed());
    println!("{}", serde_json::to_string_pretty(&report)?);
    // Failure threshold: default High, overridden by `[ci] fail_on` in a
    // committed `.husk/policy.toml`, and lowered to Medium by --fail-on-medium.
    // An unloadable policy (e.g. an invalid `fail_on` value) is a hard error
    // here: CI must never silently gate on the wrong threshold.
    let mut threshold = Severity::High;
    if let Some(policy) = crate::policy::Policy::discover(&report.roots)?
        && let Some(sev) = policy.ci_fail_on()
    {
        threshold = sev;
    }
    if args.fail_on_medium {
        threshold = threshold.min(Severity::Medium);
    }
    let should_fail = report
        .findings
        .iter()
        .any(|finding| finding.severity >= threshold);
    if should_fail {
        std::process::exit(1);
    }
    // A gate must fail closed: an advisory source that produced no verdict
    // means the vulnerability picture is incomplete, and in a fresh CI
    // environment there is no previous report to carry findings from. Exit 2
    // distinguishes "gate could not check" from "gate found findings".
    let unavailable = report
        .providers
        .iter()
        .filter(|provider| !provider.ok)
        .map(|provider| provider.name.as_str())
        .collect::<Vec<_>>();
    if !unavailable.is_empty() {
        eprintln!(
            "husk ci: advisory source(s) gave no verdict: {}; failing closed (results would be incomplete)",
            unavailable.join(", ")
        );
        std::process::exit(2);
    }
    Ok(())
}

pub(super) async fn run_status(args: StatusArgs) -> Result<()> {
    if args.history {
        let entries = crate::history::load_all();
        if args.json {
            println!("{}", serde_json::to_string_pretty(&entries)?);
        } else {
            print_history(&entries);
        }
        return Ok(());
    }
    let Some(report) = crate::cache::load_any_latest_report()? else {
        anyhow::bail!("no cached Husk scan found; run `husk scan --home` first");
    };
    if args.json {
        print_report(&report, true)?;
        return Ok(());
    }
    warn_if_stale(&report);
    // The same full renderer as `husk scan`, from the cache with zero scanning.
    deliver_report(render_report_text(&report), args.no_pager).await?;
    surface_open_alerts().await;
    Ok(())
}

/// Scan history grouped per roots (most recently scanned group first), each
/// group's scans oldest first with the resolved/new findings under each scan;
/// the CLI counterpart of the web Scan-history tab.
fn print_history(entries: &[crate::history::HistoryEntry]) {
    if entries.is_empty() {
        println!("No scan history yet. It starts with your next scan.");
        return;
    }
    // Group by roots identity, preserving each group's chronological order.
    let mut groups: Vec<(&str, Vec<&crate::history::HistoryEntry>)> = Vec::new();
    for entry in entries {
        match groups.iter_mut().find(|(key, _)| *key == entry.roots_key) {
            Some((_, group)) => group.push(entry),
            None => groups.push((&entry.roots_key, vec![entry])),
        }
    }
    groups.sort_by_key(|(_, group)| std::cmp::Reverse(group.last().map(|e| e.at)));

    for (key, group) in &groups {
        // The roots key is unit-separator-joined sorted paths.
        println!(
            "  {}",
            crate::term::color(key.replace('\u{1f}', " + "), "1;36")
        );
        println!(
            "  {}",
            crate::term::color(
                format!(
                    "{:<17} {:>5} {:>9} {:>5} {:>9} {:>11}",
                    "scan", "score", "findings", "new", "resolved", "husk fixes"
                ),
                "1"
            )
        );
        for entry in group {
            println!(
                "  {:<17} {:>5} {:>9} {:>5} {:>9} {:>11}",
                entry.at.format("%Y-%m-%d %H:%M"),
                entry.score,
                entry.findings,
                if entry.new_count > 0 {
                    format!("+{}", entry.new_count)
                } else {
                    "-".to_string()
                },
                if entry.resolved_count > 0 {
                    format!("-{}", entry.resolved_count)
                } else {
                    "-".to_string()
                },
                if entry.fixes_applied > 0 {
                    entry.fixes_applied.to_string()
                } else {
                    "-".to_string()
                },
            );
            for label in &entry.fixes {
                println!(
                    "  {}",
                    crate::term::color(format!("    ⚙ husk fix applied: {label}"), "36")
                );
            }
            for finding in &entry.resolved {
                println!(
                    "  {}",
                    crate::term::color(
                        format!("    ✓ resolved{}", history_finding_line(finding)),
                        "32"
                    )
                );
            }
            for finding in &entry.new {
                println!(
                    "  {}",
                    crate::term::color(format!("    + new{}", history_finding_line(finding)), "33")
                );
            }
        }
        let (first, last) = (&group[0], &group[group.len() - 1]);
        let resolved: usize = group.iter().map(|e| e.resolved_count).sum();
        let fixes: usize = group.iter().map(|e| e.fixes_applied).sum();
        println!(
            "  {} security score {} → {}/100 across {} scan(s); {} finding(s) resolved, {} husk-applied fix(es)",
            crate::term::color("history:", "1"),
            first.score,
            last.score,
            group.len(),
            resolved,
            fixes
        );
        println!();
    }
}

fn history_finding_line(finding: &crate::history::FindingSummary) -> String {
    let mut line = format!(" [{}] {}", finding.severity, finding.title);
    if let Some(package) = &finding.package {
        line.push_str(&format!(" ({package})"));
    }
    if finding.by_husk {
        line.push_str(" (fixed by husk)");
    }
    line
}

/// A running `husk web` session: the localhost server plus the in-flight scan
/// task (if any). Held together so [`serve_until_ctrl_c`] can shut both down
/// cleanly on Ctrl-C, and, crucially, so the server handle stays alive (its
/// drop would trigger a graceful shutdown).
#[cfg(feature = "web")]
struct ScanWebSession {
    server: crate::web::WebHandle,
    scan: Option<tokio::task::JoinHandle<()>>,
}

/// Serve until the user presses Ctrl-C, then shut everything down promptly and
/// cleanly: abort the in-flight scan and ask the Axum server to drain, bounded
/// by a short deadline so the shell always returns within a second or two. A
/// second Ctrl-C force-exits immediately for the impatient.
#[cfg(feature = "web")]
async fn serve_until_ctrl_c(session: ScanWebSession) -> Result<()> {
    let ScanWebSession {
        mut server, scan, ..
    } = session;
    tokio::signal::ctrl_c().await?;
    println!("\nStopping.");
    if let Some(scan) = scan {
        scan.abort();
    }
    server.trigger_shutdown();
    tokio::select! {
        // Normal case: the server drains its (usually zero) in-flight requests
        // and resolves, typically within milliseconds.
        _ = &mut server.task => {}
        // A second Ctrl-C: force-exit immediately for the impatient.
        _ = tokio::signal::ctrl_c() => std::process::exit(130),
        // Safety cap so the shell always comes back promptly even if a request
        // is slow to drain.
        _ = tokio::time::sleep(Duration::from_secs(2)) => {}
    }
    // Exit the process directly rather than unwind back through `main`: the
    // aborted scan may still hold subprocess-backed blocking threads (context
    // collection) that the runtime's `Drop` would otherwise block on for
    // seconds. We've shut down cleanly, so a prompt exit is correct.
    std::process::exit(0);
}

/// The two live slots a web session serves: the project scan the session
/// targets and the standing machine-posture scan.
#[cfg(feature = "web")]
struct ScanSlots {
    project: crate::model::SharedLiveScan,
    machine: crate::model::SharedLiveScan,
}

#[cfg(feature = "web")]
async fn start_scan_web(
    slots: ScanSlots,
    options: ScanOptions,
    host: IpAddr,
    port: u16,
    open_browser: bool,
    announce: bool,
    dev: bool,
) -> Result<ScanWebSession> {
    let ScanSlots {
        project: live,
        machine,
    } = slots;
    let (will_scan, state_msg) = {
        let l = live
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if l.running {
            (true, "Starting scan now. The UI updates as results arrive.")
        } else if l.finished_at.is_some() {
            (
                false,
                "Showing your last scan. Rescan from the UI to refresh.",
            )
        } else {
            (
                false,
                "No scan is running. Pick a directory in the web UI to start one.",
            )
        }
    };
    let server = crate::web::start_live_with_options(
        live.clone(),
        machine,
        (host, port).into(),
        Some(options.clone()),
        dev,
    )
    .await?;
    let url = format!("http://{}", server.addr);
    if announce {
        println!("Husk web UI: {url}");
        println!("{state_msg}");
    }
    if open_browser {
        try_open_browser(&url, announce);
    }
    let scan = if will_scan {
        Some(crate::scan::spawn_scan(options, live))
    } else {
        None
    };
    Ok(ScanWebSession { server, scan })
}

pub(super) async fn cached_or_scan(options: ScanOptions, rescan: bool) -> Result<ScanReport> {
    let roots = normalize_roots_for_cache(&options)?;
    if !rescan && let Some(report) = crate::cache::load_latest_report(&roots)? {
        return Ok(report);
    }
    run_and_cache_scan(options).await
}

async fn run_and_cache_scan(options: ScanOptions) -> Result<ScanReport> {
    let started = Instant::now();
    let report = run_scan(options).await?;
    let _ = crate::cache::save_latest_report(&report);
    cloud::telemetry::record_scan(&report, started.elapsed());
    Ok(report)
}

pub(super) async fn run_daemon(mut args: DaemonArgs) -> Result<()> {
    if args.notify && !cfg!(target_os = "linux") {
        anyhow::bail!("--notify is currently Linux-only (it uses notify-send)");
    }
    if args.scope.paths.is_empty() && !args.scope.home {
        args.scope.home = true;
    }
    spawn_daemon_telemetry_boundary_flush();
    loop {
        // Refresh the advisory mirror first: a daemon host is exactly where
        // it should stay fresh, and an unchanged index costs one conditional
        // request per ecosystem. Failures are loud, never fatal to the cycle.
        match crate::cache::intel_dir() {
            Ok(dir) => {
                let wanted = crate::intel::sync::wanted_ecosystems(false);
                match crate::intel::sync::sync(&dir, wanted).await {
                    Ok(outcome) => {
                        for (ecosystem, error) in &outcome.failed {
                            eprintln!("warning: intel sync failed for {ecosystem}: {error}");
                        }
                    }
                    Err(err) => eprintln!("warning: intel sync failed: {err:#}"),
                }
            }
            Err(err) => eprintln!("warning: intel cache unavailable: {err:#}"),
        }
        let report = run_and_cache_scan(options_from_args(&args.scope, false)?).await?;
        let cache_path = crate::cache::save_latest_report(&report)?;

        // Diff against the previous run so we surface only findings that are
        // *new* since last time: the local, no-account half of retroactive
        // alerts. A read/parse failure re-baselines rather than alert-storming.
        let prior = crate::daemon::load_state().unwrap_or(None);
        let (next_state, diff) = crate::daemon::reconcile(prior, &report, chrono::Utc::now());
        if let Err(err) = crate::daemon::save_state(&next_state) {
            eprintln!("warning: could not persist daemon state: {err}");
        }

        println!(
            "daemon scan complete: {} findings ({} critical, {} high), {} new, {} resolved since last scan, cache {}",
            report.stats.findings,
            report.stats.critical,
            report.stats.high,
            diff.new_ids.len(),
            diff.resolved_ids.len(),
            cache_path.display()
        );
        // Alert only on genuinely new findings (never on the baseline run).
        if args.notify && !diff.new_ids.is_empty() {
            notify_new_findings(&report, &diff.new_ids);
        }
        if args.once {
            break;
        }
        tokio::time::sleep(Duration::from_secs(args.interval_secs)).await;
    }
    Ok(())
}

/// The daemon may sleep across UTC midnight with a long `--interval`, so it
/// delivers on the window boundary itself: shortly after each UTC midnight,
/// roll the completed day into the pending spool and start the upload.
/// Every step inside is a no-op unless the user opted in (and `--offline`
/// suppresses the network send), so the loop just keeps time.
fn spawn_daemon_telemetry_boundary_flush() {
    tokio::spawn(async {
        loop {
            let now = chrono::Utc::now();
            let next_midnight = (now.date_naive() + chrono::Days::new(1))
                .and_hms_opt(0, 2, 0)
                .expect("00:02:00 is a valid time")
                .and_utc();
            let wait = (next_midnight - now)
                .to_std()
                .unwrap_or(std::time::Duration::from_secs(60));
            tokio::time::sleep(wait).await;
            cloud::telemetry::deliver_in_background();
        }
    });
}

/// Desktop-notify about findings that are NEW since the last daemon scan
/// (worst-severity first), so the alert is signal, not the same list each cycle.
/// Linux-only (`notify-send`); `run_daemon` rejects `--notify` elsewhere.
fn notify_new_findings(report: &ScanReport, new_ids: &[String]) {
    let new_set: std::collections::HashSet<&str> = new_ids.iter().map(String::as_str).collect();
    let mut new_findings: Vec<&crate::model::Finding> = report
        .findings
        .iter()
        .filter(|f| new_set.contains(f.id.as_str()))
        .collect();
    new_findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

    let title = format!(
        "Husk: {} new finding{} since last scan",
        new_ids.len(),
        if new_ids.len() == 1 { "" } else { "s" }
    );
    let mut lines: Vec<String> = new_findings
        .iter()
        .take(3)
        .map(|f| format!("[{}] {}", f.severity.label(), f.title))
        .collect();
    if new_findings.len() > 3 {
        lines.push(format!("…and {} more", new_findings.len() - 3));
    }
    let body = lines.join("\n");
    let _ = ProcessCommand::new("notify-send")
        .arg(title)
        .arg(body)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

async fn wait_for_scan(live: crate::model::SharedLiveScan) {
    while live
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .running
    {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

#[cfg(feature = "web")]
fn try_open_browser(url: &str, announce_failure: bool) {
    let result = if cfg!(target_os = "macos") {
        let mut command = ProcessCommand::new("open");
        command.arg(url);
        spawn_silent(command)
    } else {
        let mut command = ProcessCommand::new("xdg-open");
        command.arg(url);
        spawn_silent(command)
    };

    if announce_failure && result.is_err() {
        eprintln!("Could not open the browser automatically. Open {url} manually.");
    }
}

#[cfg(feature = "web")]
fn spawn_silent(mut command: ProcessCommand) -> std::io::Result<std::process::Child> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// Turn the shared scan-scope flags into `ScanOptions`. `quiet` suppresses the
/// one-time online notice for machine-readable outputs.
pub(super) fn options_from_args(scope: &ScanScopeArgs, quiet: bool) -> Result<ScanOptions> {
    // `--home` is the machine scan: home roots plus the machine-only stages.
    // Everything else is a project scan of exactly the named folders.
    let mut options = if scope.home {
        ScanOptions::machine(dirs::home_dir().context("could not locate home directory")?)
    } else if scope.paths.is_empty() {
        ScanOptions::new(vec![std::env::current_dir()?])
    } else {
        ScanOptions::new(scope.paths.clone())
    };
    options.online = !scope.offline;
    if scope.no_home_inventory {
        options.include_home_inventory = false;
    }
    if options.online {
        maybe_show_online_notice(quiet);
    }
    Ok(options)
}

/// One-time, stderr-only disclosure that an online scan queries third-party
/// public advisory databases. Husk is local-first, but an online scan does send
/// discovered package names + versions to those services, so on the first online
/// scan we say so once, then drop a marker file in `~/.husk` and stay silent
/// forever after. Suppressed in JSON mode so machine-readable output is never
/// corrupted, and best-effort throughout: any IO error just risks showing the
/// note again, never a failed scan.
fn maybe_show_online_notice(quiet: bool) {
    if quiet {
        return;
    }
    let Ok(dir) = crate::paths::husk_home() else {
        return;
    };
    let marker = dir.join(".online_notice_shown");
    if marker.exists() {
        return;
    }
    eprintln!(
        "Note: an online scan checks your dependencies against public advisory databases \
(OSV, npm, PyPI, GitHub, CISA/FIRST). Only package names + versions are sent, never file \
contents, paths, or secrets. Run with --offline to scan using only the local cache."
    );
    if crate::paths::ensure_dir_private(&dir).is_ok() {
        let _ = std::fs::write(&marker, b"");
    }
}

/// The normalized roots a cached report for `options` would be keyed on.
fn normalize_roots_for_cache(options: &ScanOptions) -> Result<Vec<PathBuf>> {
    crate::scan::normalize_roots(options.roots.clone())
}
