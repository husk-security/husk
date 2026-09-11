//! The scanner pipeline: package discovery, local detections, advisory
//! lookups, and report assembly.
//!
//! The pipeline is deliberately **staged** so first output is fast: a quick
//! pass over the priority roots, then **one** filesystem walk (`walk`) that
//! feeds both registries, file-type-routed local detections (the [`checks`]
//! registry) and package discovery (the [`targets`] `ScanTarget` registry),
//! then the online advisory fan-out (`crate::providers`), and finally project
//! attachment, policy application, exploit prioritization, and scoring.
//! Progress streams through the shared [`LiveScan`] that the TUI and web UI
//! poll.
//!
//! Scans are **strictly read-only**: the pipeline never executes package
//! managers, install scripts, git hooks, extensions, or any code it scans.
//!
//! Entry points: [`run_scan`] (one-shot), [`spawn_scan`] (background task over
//! a [`SharedLiveScan`]), [`discover_packages`] (discovery only).

pub(crate) mod agent_paths;
pub mod checks;
pub(crate) mod local;
pub mod targets;
mod walk;

use crate::model::{
    Finding, LiveScan, LiveScanLock, PackageRef, ProgressState, ProviderStatus, ScanOptions,
    ScanReport, SharedLiveScan, StageBenchmark,
};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

pub use targets::supported_ecosystems;
pub use walk::discover_packages;

use walk::WalkMode;

pub async fn run_scan(options: ScanOptions) -> Result<ScanReport> {
    let roots = normalize_roots(options.roots.clone())?;
    let live = Arc::new(RwLock::new(LiveScan::new(roots.clone())));
    run_scan_live(options, live.clone()).await?;
    Ok(live.with_read(|state| state.report.clone()))
}

pub fn new_live_scan(options: &ScanOptions) -> Result<SharedLiveScan> {
    let roots = normalize_roots(options.roots.clone())?;
    Ok(Arc::new(RwLock::new(LiveScan::new(roots))))
}

/// Run a live scan on a background task. The one home for the
/// scan-in-the-background pattern shared by `husk tui`, `husk web`, the bare
/// `husk` onboarding, and the web UI's rescan endpoint: on success the report
/// is cached and a `scan_completed` telemetry event is recorded (a no-op
/// unless the user opted in); on failure the error is surfaced on the shared
/// live state.
pub fn spawn_scan(options: ScanOptions, live: SharedLiveScan) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let started = Instant::now();
        if let Err(err) = run_scan_live(options, live.clone()).await {
            live.with_write(|state| state.fail(err.to_string()));
        } else if !live.with_read(LiveScan::stop_requested) {
            let report = live.with_read(|state| state.report.clone());
            let _ = crate::cache::save_latest_report(&report);
            crate::cloud::telemetry::record_scan(&report, started.elapsed());
        }
    })
}

#[derive(Clone, Copy)]
enum Step {
    Discover = 0,
    LocalFiles = 1,
    HomeInventory = 2,
    Providers = 3,
    Finalize = 4,
}

#[derive(Default)]
struct StageTimings {
    /// The file walks: quick pass + the fused discovery/checks walk.
    walk_ms: u128,
    home_ms: u128,
    providers_ms: u128,
    finalize_ms: u128,
}

fn bench_row(stage: &str, elapsed_ms: u128, detail: impl Into<String>) -> StageBenchmark {
    StageBenchmark {
        stage: stage.to_string(),
        elapsed_ms,
        detail: detail.into(),
        ..StageBenchmark::default()
    }
}

fn file_progress<'a>(
    live: &'a SharedLiveScan,
    step: Step,
    prefix: &'a str,
    estimate: Option<usize>,
) -> impl Fn(&Path, usize) + Send + Sync + 'a {
    move |path, checked| {
        if checked == 1 || checked <= 25 || checked.is_multiple_of(100) {
            // Within-step fraction for the progress bar: the previous run's
            // file count when available, else an asymptotic guess that keeps
            // the bar moving without a known total. Capped below 1: only the
            // stage finishing may complete its share of the bar.
            let fraction = match estimate {
                Some(total) if total > 0 => (checked as f32 / total as f32).min(0.95),
                _ => checked as f32 / (checked as f32 + 1500.0),
            };
            update_step_progress(
                live,
                step,
                fraction,
                format!(
                    "{prefix}checked {checked} files; now {}",
                    compact_path(path, 72)
                ),
            );
        }
    }
}

/// Enriched incremental publishing: every live findings update carries project
/// attribution, projects, and scoring, so both UIs group and order mid-scan
/// findings the same way the final report does (no end-of-scan "teleport").
struct LivePublisher {
    index: crate::project::ProjectIndex,
    started: Instant,
    last_publish_ms: AtomicU64,
}

impl LivePublisher {
    fn publish(&self, live: &SharedLiveScan, mut findings: Vec<Finding>) {
        // Mid-scan ids must be the ids the final report shows, since a UI can
        // offer to suppress a finding before the scan finishes. Every caller
        // hands over a copy, so the pending set stays unlocated for finalize.
        for finding in &mut findings {
            finding.locate_id();
        }
        findings.sort_by_cached_key(finding_key);
        findings.dedup_by(|a, b| finding_key(a) == finding_key(b));
        collapse_advisories(&mut findings);
        live.with_write(|state| {
            let report = state.working();
            report.findings = findings;
            crate::project::apply_projects(report, &self.index);
            report.refresh_stats();
            crate::score::score_report(report);
        });
    }

    /// Throttled union publish for the per-file findings callbacks. `base` is
    /// earlier stages' findings the in-flight pass must not evict from view;
    /// the union converges to plain `publish` once the pass completes.
    fn publish_streamed(&self, live: &SharedLiveScan, base: &[Finding], partial: &[Finding]) {
        let now = self.started.elapsed().as_millis() as u64;
        let last = self.last_publish_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 300
            || self
                .last_publish_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let mut union = Vec::with_capacity(base.len() + partial.len());
        union.extend_from_slice(base);
        union.extend_from_slice(partial);
        self.publish(live, union);
    }
}

pub async fn run_scan_live(mut options: ScanOptions, live: SharedLiveScan) -> Result<()> {
    let setup_started = Instant::now();
    // The walk polls this flag per file; the stage boundaries below poll it
    // between walks. A stop keeps what has already been published.
    options.cancel = live.with_read(LiveScan::cancel_flag);
    let stopped = || {
        options.cancel.load(Ordering::Relaxed) && {
            live.with_write(LiveScan::stop);
            true
        }
    };
    let roots = live.with_read(|state| state.working_ref().roots.clone());
    // Fresh system context for this scan. Collected here (once per scan) rather
    // than in `LiveScan::new`, so cached-report views never pay for the
    // subprocess-backed collection, and on a blocking thread so the
    // subprocess/PATH-stat work never stalls the async executor.
    {
        let context_roots = roots.clone();
        let context =
            tokio::task::spawn_blocking(move || crate::context::collect_context(&context_roots))
                .await
                .unwrap_or_default();
        live.with_write(|state| state.working().context = context);
    }
    // Project discovery up front: one walk whose index every incremental
    // publish (and finalize) reuses, so mid-scan findings already carry their
    // repo/config owner and the UIs can show group headers while scanning.
    let publisher = {
        let index_roots = roots.clone();
        let index = tokio::task::spawn_blocking(move || {
            crate::project::discover_projects(&index_roots, dirs::home_dir().as_deref())
        })
        .await
        .unwrap_or_else(|_| crate::project::discover_projects(&roots, dirs::home_dir().as_deref()));
        LivePublisher {
            index,
            started: Instant::now(),
            last_publish_ms: AtomicU64::new(0),
        }
    };
    // The previous run's file count makes the local-files fraction near-linear
    // on rescans; first scans fall back to the asymptotic guess.
    let local_files_estimate = crate::cache::load_latest_report(&roots)
        .ok()
        .flatten()
        .and_then(|previous| {
            previous
                .benchmarks
                .iter()
                .find(|bench| bench.stage == "scan local files")
                .map(|bench| bench.files_checked)
        })
        .filter(|count| *count > 0);
    let mut timings = StageTimings::default();
    // Setup runs before the first stage and probes the machine with
    // subprocesses, so it is real wall time no other row would show.
    let mut benchmarks = vec![StageBenchmark {
        workers: 1,
        ..bench_row(
            "collect context",
            setup_started.elapsed().as_millis(),
            "system context and project discovery",
        )
    }];

    if stopped() {
        return Ok(());
    }
    let quick_findings = quick_pass_stage(
        &live,
        &options,
        &roots,
        &publisher,
        &mut benchmarks,
        &mut timings,
    );
    if stopped() {
        return Ok(());
    }
    let (packages, mut findings) = files_stage(
        &live,
        &options,
        &roots,
        &publisher,
        &quick_findings,
        local_files_estimate,
        &mut benchmarks,
        &mut timings,
    );
    if stopped() {
        return Ok(());
    }
    let provider_task = spawn_provider_queries(&live, &options, &packages);
    home_inventory_stage(
        &live,
        &options,
        &roots,
        &publisher,
        &mut findings,
        &mut benchmarks,
        &mut timings,
    );
    if stopped() {
        return Ok(());
    }
    // The online stage is one long wait, so a stop asked for during it must
    // not sit until every provider answers: drop the stage's future instead.
    let providers = tokio::select! {
        biased;
        () = wait_for_cancel(&options.cancel) => {
            live.with_write(LiveScan::stop);
            return Ok(());
        }
        providers = provider_stage(
            &live,
            &publisher,
            provider_task,
            &packages,
            &mut findings,
            &mut benchmarks,
            &mut timings,
        ) => providers,
    };
    if stopped() {
        return Ok(());
    }
    finalize_stage(
        &live,
        &options,
        roots,
        &publisher,
        packages,
        findings,
        providers,
        benchmarks,
        &mut timings,
    )
    .await;
    Ok(())
}

fn quick_pass_stage(
    live: &SharedLiveScan,
    options: &ScanOptions,
    roots: &[PathBuf],
    publisher: &LivePublisher,
    benchmarks: &mut Vec<StageBenchmark>,
    timings: &mut StageTimings,
) -> Vec<Finding> {
    let priority_roots = priority_roots(roots);
    let mut quick_findings = Vec::new();

    if !priority_roots.is_empty() {
        update_step(
            live,
            Step::LocalFiles,
            ProgressState::Running,
            format!("quick pass over {}", roots_summary(&priority_roots)),
        );
        let quick_started = Instant::now();
        let quick_result = walk::walk(
            &priority_roots,
            options,
            WalkMode::Checks,
            file_progress(live, Step::LocalFiles, "quick pass ", None),
            |partial| publisher.publish_streamed(live, &[], partial),
        );
        timings.walk_ms += quick_started.elapsed().as_millis();
        quick_findings = quick_result.findings;
        benchmarks.push(StageBenchmark {
            files_checked: quick_result.files_checked,
            bytes_scanned: quick_result.bytes_scanned,
            findings: quick_findings.len(),
            workers: quick_result.workers,
            ..bench_row(
                "quick local pass",
                timings.walk_ms,
                format!(
                    "priority roots: {}; {} cache hits",
                    roots_summary(&priority_roots),
                    quick_result.cache_hits
                ),
            )
        });
        let quick_count = quick_findings.len();
        publisher.publish(live, quick_findings.clone());
        update_step_elapsed(
            live,
            Step::LocalFiles,
            ProgressState::Running,
            format!("quick pass found {quick_count} issues; continuing full scan"),
            timings.walk_ms,
        );
    }
    quick_findings
}

/// The main walk: **one** traversal of the scan roots feeding both registries,
/// package discovery and the local file checks (plus the git-hook scan on
/// every `.git` directory it passes, nested repositories included).
#[allow(clippy::too_many_arguments)]
fn files_stage(
    live: &SharedLiveScan,
    options: &ScanOptions,
    roots: &[PathBuf],
    publisher: &LivePublisher,
    quick_findings: &[Finding],
    estimate: Option<usize>,
    benchmarks: &mut Vec<StageBenchmark>,
    timings: &mut StageTimings,
) -> (Vec<PackageRef>, Vec<Finding>) {
    update_step(
        live,
        Step::Discover,
        ProgressState::Running,
        format!("walking {} root(s)", roots.len()),
    );
    update_step(
        live,
        Step::LocalFiles,
        ProgressState::Running,
        "checking local files",
    );
    let started = Instant::now();
    // One per-file callback ticks both steps; they advance together because
    // they *are* the same walk.
    let discover_tick = file_progress(live, Step::Discover, "", estimate);
    let local_tick = file_progress(live, Step::LocalFiles, "", estimate);
    let result = walk::walk(
        roots,
        options,
        WalkMode::Both,
        |path, checked| {
            discover_tick(path, checked);
            local_tick(path, checked);
        },
        |partial| publisher.publish_streamed(live, quick_findings, partial),
    );
    let elapsed = started.elapsed().as_millis();
    timings.walk_ms += elapsed;

    let mut packages = result.packages;
    packages.sort_by_key(|package| package.key());
    // An unreadable/unparsable manifest is coverage the scan silently lost;
    // surface the count instead of dropping it.
    let detail = if result.warnings.is_empty() {
        "single walk shared with the local file checks".to_string()
    } else {
        format!(
            "single walk shared with the local file checks · {} manifest(s) failed to parse",
            result.warnings.len()
        )
    };
    benchmarks.push(StageBenchmark {
        files_checked: result.files_checked,
        packages_checked: packages.len(),
        workers: result.workers,
        ..bench_row("discover packages", elapsed, detail)
    });
    benchmarks.push(StageBenchmark {
        files_checked: result.files_checked,
        bytes_scanned: result.bytes_scanned,
        findings: result.findings.len(),
        workers: result.workers,
        ..bench_row(
            "scan local files",
            elapsed,
            format!(
                "parallel routed local scan with SQLite index; {} cache hits",
                result.cache_hits
            ),
        )
    });
    live.with_write(|state| {
        let report = state.working();
        report.packages = packages.clone();
        report.refresh_stats();
    });
    update_step_elapsed(
        live,
        Step::Discover,
        ProgressState::Done,
        format!("found {} package versions", packages.len()),
        elapsed,
    );
    publisher.publish(live, result.findings.clone());
    update_step_elapsed(
        live,
        Step::LocalFiles,
        ProgressState::Done,
        format!("{} local findings so far", result.findings.len()),
        timings.walk_ms,
    );
    (packages, result.findings)
}

type ProviderTask = (
    Instant,
    tokio::task::JoinHandle<crate::providers::ProviderResult>,
);

fn spawn_provider_queries(
    live: &SharedLiveScan,
    options: &ScanOptions,
    packages: &[PackageRef],
) -> Option<ProviderTask> {
    if !options.online {
        return None;
    }
    update_step(
        live,
        Step::Providers,
        ProgressState::Running,
        "provider queries started in background",
    );
    let providers_started = Instant::now();
    let packages_for_providers = packages.to_vec();
    Some((
        providers_started,
        tokio::spawn(async move { crate::providers::query_all(&packages_for_providers).await }),
    ))
}

fn home_inventory_stage(
    live: &SharedLiveScan,
    options: &ScanOptions,
    roots: &[PathBuf],
    publisher: &LivePublisher,
    findings: &mut Vec<Finding>,
    benchmarks: &mut Vec<StageBenchmark>,
    timings: &mut StageTimings,
) {
    update_step(
        live,
        Step::HomeInventory,
        ProgressState::Running,
        "checking editor and AI config locations",
    );
    if options.include_home_inventory {
        let mut home_roots = local::home_inventory_roots();
        home_roots.retain(|path| !roots.iter().any(|root| path.starts_with(root)));
        if !home_roots.is_empty() {
            let home_started = Instant::now();
            let home_result = walk::walk(
                &home_roots,
                options,
                WalkMode::Checks,
                file_progress(live, Step::HomeInventory, "", None),
                |partial| publisher.publish_streamed(live, findings, partial),
            );
            timings.home_ms = home_started.elapsed().as_millis();
            let home_findings = home_result.findings.len();
            findings.extend(home_result.findings);
            benchmarks.push(StageBenchmark {
                files_checked: home_result.files_checked,
                bytes_scanned: home_result.bytes_scanned,
                findings: home_findings,
                workers: home_result.workers,
                ..bench_row(
                    "scan home inventory",
                    timings.home_ms,
                    format!(
                        "checked {} known inventory root(s); {} cache hits",
                        home_roots.len(),
                        home_result.cache_hits
                    ),
                )
            });
            publisher.publish(live, findings.clone());
            update_step_elapsed(
                live,
                Step::HomeInventory,
                ProgressState::Done,
                format!("checked {} home inventory path(s)", home_roots.len()),
                timings.home_ms,
            );
        } else {
            benchmarks.push(bench_row(
                "scan home inventory",
                0,
                "no known home inventory paths found",
            ));
            update_step(
                live,
                Step::HomeInventory,
                ProgressState::Done,
                "no known home inventory paths found",
            );
        }
    } else {
        benchmarks.push(bench_row("scan home inventory", 0, "skipped by flag"));
        update_step(
            live,
            Step::HomeInventory,
            ProgressState::Done,
            "skipped by flag",
        );
    }
}

/// Resolves once the scan is asked to stop; never otherwise. Polled rather than
/// notified: a stop is a once-per-scan human action, not a hot path.
async fn wait_for_cancel(cancel: &std::sync::atomic::AtomicBool) {
    while !cancel.load(Ordering::Relaxed) {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}

async fn provider_stage(
    live: &SharedLiveScan,
    publisher: &LivePublisher,
    provider_task: Option<ProviderTask>,
    packages: &[PackageRef],
    findings: &mut Vec<Finding>,
    benchmarks: &mut Vec<StageBenchmark>,
    timings: &mut StageTimings,
) -> Vec<ProviderStatus> {
    let packages_checked = packages.len();
    let mut providers = Vec::new();

    // The local advisory mirror runs on every scan, online or offline: it is
    // the floor under the live queries, and its row states coverage and age
    // plainly (an unsynced mirror on an offline scan is a failed row, never a
    // quiet gap). Matching is read-only SQLite work on the blocking pool.
    let online = provider_task.is_some();
    // Scan-time freshness: pull the OSV delta since the mirror's watermark
    // before matching, so an advisory published minutes ago is in this
    // scan. Bounded so a slow network cannot stall the scan; a timeout is
    // reported as a failed refresh, never silently skipped.
    let fresh = if online {
        if let Some(dir) = crate::intel::dir() {
            let fresh_started = Instant::now();
            let outcome = match tokio::time::timeout(
                std::time::Duration::from_secs(4),
                crate::intel::fresh::refresh(&dir),
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(_) => crate::intel::fresh::FreshOutcome {
                    failed: vec![("all".to_string(), "timed out after 4s".to_string())],
                    ..Default::default()
                },
            };
            let message = if !outcome.failed.is_empty() {
                format!("failed for {} ecosystem(s)", outcome.failed.len())
            } else if outcome.ecosystems == 0 {
                "no local databases yet".to_string()
            } else {
                format!(
                    "{} update(s) across {} ecosystem(s)",
                    outcome.applied, outcome.ecosystems
                )
            };
            benchmarks.push(bench_row(
                "pull osv advisory delta",
                fresh_started.elapsed().as_millis(),
                message,
            ));
            Some(outcome)
        } else {
            None
        }
    } else {
        None
    };
    // Invisible bootstrap: when the mirror has never synced or aged out,
    // fetch the published bundle in the background while providers run and
    // wait for it at the end of the stage. This scan is covered by live
    // queries either way; the mirror is ready for the next one.
    let bundle_task = if online {
        crate::intel::dir().and_then(|dir| {
            let state = crate::intel::load_state(&dir);
            let stale = state.synced_at.is_none_or(|at| {
                (chrono::Utc::now() - at).num_days() >= crate::intel::STALE_AFTER_DAYS
            });
            stale.then(|| {
                tokio::spawn(async move {
                    crate::intel::sync::sync(&dir, crate::intel::sync::wanted_ecosystems(false))
                        .await
                })
            })
        })
    } else {
        None
    };
    let mirror_started = Instant::now();
    let mirror = {
        let packages = packages.to_vec();
        tokio::task::spawn_blocking(move || {
            let dir = crate::intel::dir()?;
            let matched = crate::intel::match_packages(&dir, &packages);
            let row = crate::intel::provider_row(&dir, &matched, online, fresh.as_ref());
            Some((matched, row))
        })
        .await
    };
    match mirror {
        Ok(Some((matched, row))) => {
            benchmarks.push(StageBenchmark {
                packages_checked: matched.checked,
                findings: matched.findings.len(),
                workers: 1,
                ..bench_row(
                    "match local advisory mirror",
                    mirror_started.elapsed().as_millis(),
                    row.message.clone(),
                )
            });
            findings.extend(matched.findings);
            providers.push(row);
            live.with_write(|state| state.working().providers = providers.clone());
            publisher.publish(live, findings.clone());
        }
        // No cache directory: `provider_row` needs one to state anything.
        Ok(None) => {}
        Err(err) => {
            if let Some(row) = mirror_failure_row(&err) {
                benchmarks.push(StageBenchmark {
                    workers: 1,
                    ..bench_row(
                        "match local advisory mirror",
                        mirror_started.elapsed().as_millis(),
                        row.message.clone(),
                    )
                });
                providers.push(row);
                live.with_write(|state| state.working().providers = providers.clone());
            }
        }
    }
    if let Some((providers_started, provider_task)) = provider_task {
        update_step(
            live,
            Step::Providers,
            ProgressState::Running,
            "waiting for provider results",
        );
        let provider_result = match provider_task.await {
            Ok(result) => result,
            Err(err) => crate::providers::ProviderResult {
                findings: Vec::new(),
                statuses: vec![ProviderStatus {
                    name: "provider worker".to_string(),
                    ok: false,
                    checked_packages: packages_checked,
                    findings: 0,
                    message: format!("provider worker failed: {err}"),
                }],
            },
        };
        timings.providers_ms = providers_started.elapsed().as_millis();
        let provider_findings_count = provider_result.findings.len();
        findings.extend(provider_result.findings);
        providers.extend(provider_result.statuses);
        benchmarks.push(StageBenchmark {
            packages_checked,
            findings: provider_findings_count,
            workers: 4,
            ..bench_row(
                "query online providers",
                timings.providers_ms,
                "started after package discovery and overlapped with local scanning",
            )
        });
        live.with_write(|state| state.working().providers = providers.clone());
        publisher.publish(live, findings.clone());
        let warnings = providers.iter().filter(|provider| !provider.ok).count();
        let provider_findings = providers
            .iter()
            .map(|provider| provider.findings)
            .sum::<usize>();
        update_step_elapsed(
            live,
            Step::Providers,
            if warnings == 0 {
                ProgressState::Done
            } else {
                ProgressState::Warning
            },
            format!("{provider_findings} provider findings, {warnings} warning(s)"),
            timings.providers_ms,
        );
    } else {
        benchmarks.push(bench_row(
            "query online providers",
            0,
            "skipped by --offline",
        ));
        providers.push(ProviderStatus {
            name: OFFLINE_PROVIDERS_ROW.to_string(),
            ok: true,
            checked_packages: 0,
            findings: 0,
            message: "skipped because --offline was used".to_string(),
        });
        live.with_write(|state| {
            let report = state.working();
            report.providers = providers.clone();
            report.refresh_stats();
        });
        update_step(
            live,
            Step::Providers,
            ProgressState::Done,
            "skipped by --offline",
        );
    }
    // Let the background bundle bootstrap finish before the stage returns so
    // a one-shot `husk scan` process does not kill the download mid-file.
    // Bounded: a slow bundle server must not hold the report hostage.
    if let Some(task) = bundle_task {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(30), task).await;
    }
    providers
}

/// The mirror row for a mirror pass that never produced one. A panic there
/// is a bug, but dropping the row would leave a report that looks complete
/// while the whole advisory floor is missing from it, so the stage says so
/// instead. A cancelled join is the runtime shutting down on Ctrl-C and the
/// report is discarded anyway: stay quiet.
fn mirror_failure_row(err: &tokio::task::JoinError) -> Option<ProviderStatus> {
    if err.is_cancelled() {
        return None;
    }
    Some(ProviderStatus {
        name: crate::intel::MIRROR_ROW.to_string(),
        ok: false,
        checked_packages: 0,
        findings: 0,
        message: "the local advisory mirror pass failed; this scan has no mirror coverage"
            .to_string(),
    })
}

/// Resolve a spawned task's join result inside the scan pipeline in a
/// **cancellation-safe** way.
///
/// - `Ok(value)` → `Some(value)`.
/// - `Err(cancelled)` → `None`. A cancelled task means the Tokio runtime is
///   shutting down (typically because the user pressed Ctrl-C and the scan task
///   was aborted). This is a clean stop, **not** a bug: the caller should bail
///   out quietly. A user must never see a panic or backtrace on Ctrl-C.
/// - `Err(panic)` → re-raise the panic on this thread. A panic inside the task
///   is a genuine bug and must not be swallowed.
fn join_or_shutdown<T>(result: Result<T, tokio::task::JoinError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(err) if err.is_cancelled() => None,
        Err(err) => std::panic::resume_unwind(err.into_panic()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn finalize_stage(
    live: &SharedLiveScan,
    options: &ScanOptions,
    roots: Vec<PathBuf>,
    publisher: &LivePublisher,
    packages: Vec<PackageRef>,
    mut findings: Vec<Finding>,
    mut providers: Vec<ProviderStatus>,
    mut benchmarks: Vec<StageBenchmark>,
    timings: &mut StageTimings,
) {
    let finalize_started = Instant::now();
    update_step(
        live,
        Step::Finalize,
        ProgressState::Running,
        "sorting findings",
    );
    // The previous stored report for this slot does two jobs below: it donates
    // carried-forward provider findings, and it is the delta base. Loaded
    // once; a missing or unreadable cache means no carry and no delta, never
    // a failed scan.
    let previous = if options.kind == crate::model::ScanKind::Machine {
        crate::cache::load_machine_report()
    } else {
        crate::cache::load_latest_report(&roots)
    }
    .ok()
    .flatten();
    // Turn each detector's rule-and-subject key into the id a user triages.
    // This runs before policy so a `[[suppress]]` entry is matched against the
    // same id the report showed, and before dedup so two distinct matches of
    // one rule survive as two findings.
    for finding in &mut findings {
        finding.locate_id();
    }
    // A provider that produced no verdict this run (its requests failed, or
    // the scan ran offline) has not fixed anything: its previous findings are
    // carried forward for package coordinates still in this scan's inventory.
    // Injected here, after `locate_id` (carried ids are already located), so
    // dedup, policy, scoring, and the delta treat them like fresh findings; a
    // provider outage can then never masquerade as "resolved since last scan".
    if let Some(previous) = &previous {
        let unavailable: Vec<String> = if options.online {
            providers
                .iter()
                .filter(|provider| !provider.ok)
                .map(|provider| provider.name.clone())
                .collect()
        } else {
            // Offline: every real provider from the previous report. Keeping
            // their (patched) rows in this report is what lets a second
            // offline scan carry the same findings again.
            previous
                .providers
                .iter()
                .map(|provider| provider.name.clone())
                .filter(|name| name != OFFLINE_PROVIDERS_ROW)
                .collect()
        };
        let carried = carry_forward_provider_findings(previous, &unavailable, &packages);
        if !carried.is_empty() {
            let mut by_source: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for finding in &carried {
                *by_source.entry(finding.source.clone()).or_default() += 1;
            }
            for row in providers.iter_mut() {
                if let Some(count) = by_source.remove(&row.name) {
                    row.findings += count;
                    row.message = format!(
                        "{}; carried {count} finding(s) from the report of {}",
                        row.message, previous.generated_at
                    );
                }
            }
            // Providers with no row this run (the offline path) get one, so
            // the carried data's provenance stays visible and chainable.
            for (name, count) in by_source {
                providers.push(ProviderStatus {
                    name,
                    ok: false,
                    checked_packages: 0,
                    findings: count,
                    message: format!(
                        "no fresh verdict this run; carried {count} finding(s) from the report of {}",
                        previous.generated_at
                    ),
                });
            }
            findings.extend(carried);
        }
    }
    // Sort by the dedup key so identical findings sit adjacently for
    // `dedup_by`. This is purely a dedup precondition; the user-facing order
    // is owned by `score::score_report` at the end of finalize.
    findings.sort_by_cached_key(finding_key);
    findings.dedup_by(|a, b| finding_key(a) == finding_key(b));
    // Before policy, so the id a user triages is the one surviving row rather
    // than one of the four the feeds happened to raise for it.
    collapse_advisories(&mut findings);

    // Apply the committed project policy (`.husk/policy.toml`), if any: move
    // triaged ids and allowed-package advisories into `ignored` (shown under
    // "Ignored", not dropped), and flag block-listed packages. Project
    // attachment for every finding (including freshly added block findings)
    // happens once, in `project::build_projects` below.
    let mut ignored: Vec<Finding> = Vec::new();
    // Policy discovery walks the filesystem and reads `.husk/policy.toml`, so it
    // runs on a blocking thread rather than stalling the async executor.
    // `findings` moves in and comes back out.
    let joined = {
        let roots = roots.clone();
        let packages = packages.clone();
        tokio::task::spawn_blocking(move || {
            let (ignored, errors) =
                crate::policy::apply_for_roots(&roots, &mut findings, &packages);
            (findings, ignored, errors)
        })
        .await
    };
    let Some((findings_out, policy_ignored, policy_errors)) = join_or_shutdown(joined) else {
        return;
    };
    findings = findings_out;
    ignored.extend(policy_ignored);
    // A malformed `.husk/policy.toml` must never silently fail open: surface a
    // visible finding so the team knows its rules are NOT being enforced.
    for (path, err) in &policy_errors {
        findings.push(crate::policy::load_error_finding(path, err));
    }
    // Personal trust-ledger silences (global across projects) also go to Ignored.
    crate::policy::apply_ledger_ignores(&mut findings, &mut ignored);

    let severity_desc = |a: &Finding, b: &Finding| b.severity.cmp(&a.severity);
    ignored.sort_by(severity_desc);

    // Exploit-aware prioritization (CISA KEV + EPSS): pull actively-exploited /
    // high-probability CVEs to the top so the developer fixes those first. Best-
    // effort and online-only; offline scans skip it.
    if options.online {
        let cves: Vec<String> = {
            let mut seen = HashSet::new();
            findings
                .iter()
                .flat_map(crate::prioritize::finding_cves)
                .filter(|c| seen.insert(c.clone()))
                .collect()
        };
        if !cves.is_empty()
            && let Ok(client) = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(12))
                .user_agent(format!("husk/{}", env!("CARGO_PKG_VERSION")))
                .build()
        {
            let intel = crate::prioritize::fetch_exploit_intel(&client, &cves).await;
            crate::prioritize::prioritize(&mut findings, &intel);
        }
    }

    let context = live.with_read(|state| state.working_ref().context.clone());
    benchmarks.push(StageBenchmark {
        workers: 1,
        findings: findings.len(),
        ..bench_row(
            "finalize report",
            finalize_started.elapsed().as_millis(),
            "sorted, deduplicated, and triaged findings",
        )
    });

    // Everything below is work the report needs before any surface can render
    // it, and it scales with findings and packages rather than with files. Each
    // phase carries its own row: an unmeasured phase is one no benchmark run can
    // catch regressing.
    let scoring_started = Instant::now();
    let mut report = ScanReport::new(roots, packages, findings, providers);
    report.kind = options.kind;
    report.context = context;
    report.ignored = ignored;
    crate::project::apply_projects(&mut report, &publisher.index);
    // Scoring sorts findings + projects worst-first; pure and offline-safe.
    crate::score::score_report(&mut report);
    benchmarks.push(StageBenchmark {
        workers: 1,
        packages_checked: report.packages.len(),
        findings: report.findings.len(),
        ..bench_row(
            "score and attribute",
            scoring_started.elapsed().as_millis(),
            format!("{} project(s)", report.projects.len()),
        )
    });

    let controls_started = Instant::now();
    let (controls, remediations) = crate::guide::control::run(&report);
    benchmarks.push(StageBenchmark {
        workers: 1,
        ..bench_row(
            "run guide controls",
            controls_started.elapsed().as_millis(),
            format!(
                "{} control(s), {} fix proposal(s)",
                controls.len(),
                remediations.len()
            ),
        )
    });
    report.controls = controls;
    report.remediations = remediations;

    let guide_started = Instant::now();
    // A machine scan is its own machine context; a project scan borrows the
    // newest stored machine report so machine-scoped guidance stays truthful.
    let machine_cached = if options.kind == crate::model::ScanKind::Machine {
        None
    } else {
        crate::cache::load_machine_report().ok().flatten()
    };
    report.guidance = crate::guide::assess(
        &report,
        machine_cached.as_ref(),
        &crate::guide::load_state(),
    );
    benchmarks.push(StageBenchmark {
        workers: 1,
        ..bench_row(
            "assess guide",
            guide_started.elapsed().as_millis(),
            format!("{} task(s)", report.guidance.total),
        )
    });

    let record_started = Instant::now();
    // Since-last-scan delta: diff against the previous cached report from the
    // same slot (loaded once at the top of finalize; a machine scan diffs
    // against the last machine report, a project scan against the last report
    // over the same roots). Best-effort: no cache, different roots, or a
    // schema drift just means no delta, never a failed scan.
    if let Some(previous) = &previous {
        report.delta = Some(crate::model::ScanDelta::between(previous, &report));
    }
    // Append a history row, one per completed scan, for every surface, since
    // finalize is the single choke point all of CLI/web/MCP funnel through.
    // Best-effort: history must never fail a scan.
    if options.record_history {
        let _ = crate::history::record_scan(&report);
    }
    benchmarks.push(StageBenchmark {
        workers: 1,
        ..bench_row(
            "record delta and history",
            record_started.elapsed().as_millis(),
            "compared against the previous report",
        )
    });

    report.benchmarks = benchmarks;
    timings.finalize_ms = finalize_started.elapsed().as_millis();
    live.with_write(|state| state.publish(report));
    update_step_elapsed(
        live,
        Step::Finalize,
        ProgressState::Done,
        format!(
            "report ready; stages: walk {}ms, home {}ms, providers {}ms",
            timings.walk_ms, timings.home_ms, timings.providers_ms
        ),
        timings.finalize_ms,
    );
}

/// Stable identity for deduping identical findings within a scan. Package key is
/// The synthetic provider row an offline scan writes in place of real ones.
const OFFLINE_PROVIDERS_ROW: &str = "online providers";

/// The previous report's findings for providers that produced no verdict this
/// run, restricted to package coordinates still present in the current
/// inventory (a bumped or removed dependency must not resurrect its
/// advisories). Sources are matched exactly: local detector findings are
/// never carried, because the local scan always ran.
///
/// The coordinate is matched *at its manifest*, not by name and version alone:
/// a carried finding keeps the previous report's path, so matching the bare key
/// would readmit an advisory pointing at a manifest that has since been deleted
/// (a pruned tree, a removed project, a rolled-back `husk fix` snapshot). Every
/// surface then offers to show a file that is not there.
fn carry_forward_provider_findings(
    previous: &crate::model::ScanReport,
    unavailable: &[String],
    packages: &[PackageRef],
) -> Vec<Finding> {
    if unavailable.is_empty() {
        return Vec::new();
    }
    let current: std::collections::HashSet<(String, &std::path::Path)> = packages
        .iter()
        .map(|package| (package.key(), package.manifest_path.as_path()))
        .collect();
    previous
        .findings
        .iter()
        .chain(previous.ignored.iter())
        .filter(|finding| unavailable.contains(&finding.source))
        .filter(|finding| {
            finding.package.as_ref().is_some_and(|package| {
                current.contains(&(package.key(), package.manifest_path.as_path()))
            })
        })
        .cloned()
        .collect()
}

/// included so two advisories on the same file don't alias.
type FindingKey = (String, Option<String>, Option<usize>, Option<String>);

fn finding_key(f: &Finding) -> FindingKey {
    (
        f.id.clone(),
        f.path.as_ref().map(|p| p.display().to_string()),
        f.line,
        f.package.as_ref().map(|p| p.key()),
    )
}

/// The vulnerability a coordinate finding is about, independent of which feed
/// carried it: the lowest CVE it names, else its advisory id without the feed
/// prefix that makes `osv:GHSA-x` and `pypi:GHSA-x` look like two things.
type AdvisoryKey = (String, Option<String>, String);

fn advisory_key(f: &Finding) -> Option<AdvisoryKey> {
    use crate::rule::Category::{Malware, Vulnerability};
    if !matches!(f.category, Vulnerability | Malware) {
        return None;
    }
    let vulnerability = f.cves.iter().min().cloned().or_else(|| {
        f.rule_id.as_ref().map(|id| {
            id.as_str()
                .rsplit(':')
                .next()
                .unwrap_or_default()
                .to_string()
        })
    })?;
    Some((
        f.package.as_ref()?.key(),
        f.path.as_ref().map(|p| p.display().to_string()),
        vulnerability,
    ))
}

/// One vulnerability reported by several feeds is one problem.
///
/// OSV and a registry's own API each carry both the GHSA and the ecosystem
/// advisory for a CVE, so one vulnerable coordinate arrives four times under
/// four ids. A CVE names the vulnerability itself, so the rows collapse onto it
/// and keep the worst severity any feed assigned, which is the conservative
/// read when two feeds disagree.
///
/// Input must already be sorted by [`finding_key`]: the survivor is the first
/// row of each group, so the sort is what makes the kept id stable across runs.
fn collapse_advisories(findings: &mut Vec<Finding>) {
    let mut kept: Vec<Finding> = Vec::with_capacity(findings.len());
    let mut at: HashMap<AdvisoryKey, usize> = HashMap::new();
    for finding in std::mem::take(findings) {
        let Some(key) = advisory_key(&finding) else {
            kept.push(finding);
            continue;
        };
        match at.get(&key) {
            Some(&index) => merge_advisory(&mut kept[index], finding),
            None => {
                at.insert(key, kept.len());
                kept.push(finding);
            }
        }
    }
    *findings = kept;
}

fn merge_advisory(kept: &mut Finding, other: Finding) {
    kept.severity = kept.severity.max(other.severity);
    if !kept.source.split(", ").any(|name| name == other.source) {
        kept.source = format!("{}, {}", kept.source, other.source);
    }
    kept.cves.extend(other.cves);
    kept.cves.sort();
    kept.cves.dedup();
    kept.references.extend(other.references);
    kept.references.sort();
    kept.references.dedup();
    // The highest safe version covers every advisory in the group, which is the
    // same choice the fix planner makes across a coordinate's advisories.
    if let Some(version) = other.fixed_version
        && kept
            .fixed_version
            .as_ref()
            .is_none_or(|current| crate::version::naive_vercmp(&version, current).is_gt())
    {
        kept.fixed_version = Some(version);
    }
}

fn compact_path(path: &std::path::Path, max_chars: usize) -> String {
    crate::term::truncate_middle(&path.display().to_string(), max_chars)
}

/// Canonicalize and dedupe scan roots (empty input means the current
/// directory); the exact normalization every scan applies, exposed so cache
/// lookups can match a report's recorded roots without building a scan.
pub fn normalize_roots(roots: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let roots = if roots.is_empty() {
        vec![std::env::current_dir()?]
    } else {
        roots
    };

    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for root in roots {
        // A nonexistent or unreadable root is a hard error naming the root,
        // never a silently empty report.
        let canonical = root.canonicalize().map_err(|err| {
            anyhow::anyhow!(
                "scan root {} does not exist or cannot be read ({err})",
                root.display()
            )
        })?;
        if seen.insert(canonical.clone()) {
            normalized.push(canonical);
        }
    }

    Ok(normalized)
}

fn update_step(
    live: &SharedLiveScan,
    step: Step,
    state: ProgressState,
    message: impl Into<String>,
) {
    let message = message.into();
    let step_index = step as usize;
    live.with_write(|live| {
        if let Some(step) = live.steps.get_mut(step_index) {
            if state == ProgressState::Running {
                step.started_at.get_or_insert_with(chrono::Utc::now);
            }
            step.state = state;
            step.message = message.clone();
            let label = step.label.clone();
            live.current_task = format!("{label}: {message}");
        }
    });
}

/// Running-step update that also advances the step's progress fraction.
/// Monotonic per step: the quick pass and the full pass share the local-files
/// step, so a restarted file count must never move the bar backwards.
fn update_step_progress(live: &SharedLiveScan, step: Step, fraction: f32, message: String) {
    let step_index = step as usize;
    live.with_write(|live| {
        if let Some(step) = live.steps.get_mut(step_index) {
            step.state = ProgressState::Running;
            step.started_at.get_or_insert_with(chrono::Utc::now);
            let fraction = fraction.clamp(0.0, 1.0);
            step.fraction = Some(step.fraction.map_or(fraction, |f| f.max(fraction)));
            step.message = message.clone();
            let label = step.label.clone();
            live.current_task = format!("{label}: {message}");
        }
    });
}

fn update_step_elapsed(
    live: &SharedLiveScan,
    step: Step,
    state: ProgressState,
    message: impl Into<String>,
    elapsed_ms: u128,
) {
    let message = message.into();
    let step_index = step as usize;
    live.with_write(|live| {
        if let Some(step) = live.steps.get_mut(step_index) {
            step.state = state;
            step.message = message.clone();
            step.elapsed_ms = Some(elapsed_ms);
            let label = step.label.clone();
            live.current_task = format!("{label}: {message}");
        }
    });
}

fn priority_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    let Ok(current_dir) = std::env::current_dir() else {
        return roots.first().cloned().into_iter().collect();
    };
    let current_dir = current_dir.canonicalize().unwrap_or(current_dir);
    if roots.iter().any(|root| current_dir.starts_with(root)) {
        vec![current_dir]
    } else {
        roots.first().cloned().into_iter().collect()
    }
}

fn roots_summary(roots: &[PathBuf]) -> String {
    roots
        .iter()
        .map(|root| compact_path(root, 48))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    /// A stop raised before the scan starts must end it at the first stage
    /// boundary, leaving the previous view in place rather than a half report.
    #[tokio::test]
    async fn a_stop_request_ends_the_scan_and_keeps_what_was_on_display() {
        let options = ScanOptions::new(vec![PathBuf::from("tst")]);
        let live = new_live_scan(&options).unwrap();
        live.with_write(LiveScan::request_stop);

        run_scan_live(options, live.clone()).await.unwrap();

        let state = live.snapshot();
        assert!(!state.running);
        assert_eq!(state.current_task, "scan stopped");
        assert!(state.report.findings.is_empty());
    }

    /// A coordinate finding as one feed reported it.
    fn advisory(id: &str, source: &str, severity: Severity, cve: &str) -> Finding {
        Finding::new(
            id,
            format!("{id} affects urllib3"),
            severity,
            crate::rule::Category::Vulnerability,
            source,
            Some(PathBuf::from("/p/uv.lock")),
            None,
            "summary",
            None,
            "rec",
        )
        .with_package(crate::model::PackageRef {
            ecosystem: "pypi".to_string(),
            name: "urllib3".to_string(),
            version: "1.26.0".to_string(),
            manifest_path: PathBuf::from("/p/uv.lock"),
            line: None,
        })
        .with_cves([cve.to_string()])
    }

    fn coordinate(ecosystem: &str, name: &str, version: &str) -> PackageRef {
        PackageRef {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: PathBuf::from("/p/Cargo.lock"),
            line: None,
        }
    }

    /// A previous report holding one OSV advisory finding for h2 0.4.15 and
    /// one local detector finding.
    fn previous_with_h2() -> crate::model::ScanReport {
        let mut report = crate::model::ScanReport::empty(vec![PathBuf::from("/p")]);
        report.findings = vec![
            Finding::new(
                "osv:RUSTSEC-2026-0258",
                "RUSTSEC-2026-0258 affects h2",
                Severity::High,
                crate::rule::Category::Vulnerability,
                "OSV.dev",
                Some(PathBuf::from("/p/Cargo.lock")),
                None,
                "s",
                None,
                "r",
            )
            .with_package(coordinate("cargo", "h2", "0.4.15")),
            Finding::new(
                "local-secret",
                "secret",
                Severity::High,
                crate::rule::Category::Secret,
                "Husk secret scanner",
                Some(PathBuf::from("/p/.env")),
                Some(1),
                "s",
                None,
                "r",
            ),
        ];
        report
    }

    #[test]
    fn provider_outage_carries_previous_findings_for_live_coordinates() {
        let previous = previous_with_h2();
        let carried = carry_forward_provider_findings(
            &previous,
            &["OSV.dev".to_string()],
            &[coordinate("cargo", "h2", "0.4.15")],
        );
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].source, "OSV.dev");
    }

    #[test]
    fn a_bumped_coordinate_does_not_resurrect_its_advisory() {
        let previous = previous_with_h2();
        // The dependency moved to the fixed version: nothing to carry.
        let carried = carry_forward_provider_findings(
            &previous,
            &["OSV.dev".to_string()],
            &[coordinate("cargo", "h2", "0.4.17")],
        );
        assert!(carried.is_empty());
    }

    #[test]
    fn a_coordinate_whose_manifest_is_gone_does_not_carry_its_advisory() {
        // The same coordinate is still installed, but the manifest the previous
        // finding names has been deleted (a rolled-back `husk fix` snapshot, a
        // removed project). Carrying it readmits a finding pointing at a file
        // that no longer exists, which every surface then offers to open.
        let previous = previous_with_h2();
        let mut elsewhere = coordinate("cargo", "h2", "0.4.15");
        elsewhere.manifest_path = PathBuf::from("/other/Cargo.lock");
        let carried =
            carry_forward_provider_findings(&previous, &["OSV.dev".to_string()], &[elsewhere]);
        assert!(carried.is_empty());
    }

    #[test]
    fn local_detector_findings_are_never_carried() {
        let previous = previous_with_h2();
        // Even if a caller passes a local source as unavailable, only findings
        // whose package coordinate is in the inventory can carry, and local
        // findings carry no coordinate.
        let carried = carry_forward_provider_findings(
            &previous,
            &["Husk secret scanner".to_string()],
            &[coordinate("cargo", "h2", "0.4.15")],
        );
        assert!(carried.is_empty());
    }

    #[test]
    fn a_healthy_provider_is_not_carried() {
        let previous = previous_with_h2();
        let carried =
            carry_forward_provider_findings(&previous, &[], &[coordinate("cargo", "h2", "0.4.15")]);
        assert!(carried.is_empty());
    }

    #[test]
    fn one_cve_reported_by_two_feeds_under_two_ids_is_one_finding() {
        // OSV and PyPI each carry the GHSA and the PYSEC entry for a CVE, so a
        // single vulnerable coordinate arrives four times.
        let mut findings = vec![
            advisory("osv:GHSA-x", "OSV.dev", Severity::Medium, "CVE-2020-1"),
            advisory("osv:PYSEC-1", "OSV.dev", Severity::High, "CVE-2020-1"),
            advisory("pypi:GHSA-x", "PyPI JSON", Severity::High, "CVE-2020-1"),
            advisory("pypi:PYSEC-1", "PyPI JSON", Severity::High, "CVE-2020-1"),
            advisory("osv:GHSA-y", "OSV.dev", Severity::Low, "CVE-2020-2"),
        ];
        findings.sort_by_cached_key(finding_key);
        collapse_advisories(&mut findings);

        assert_eq!(findings.len(), 2);
        let merged = &findings[0];
        assert_eq!(merged.id, "osv:GHSA-x");
        // Feeds disagree on severity; the worst read is the safe one.
        assert_eq!(merged.severity, Severity::High);
        assert_eq!(merged.source, "OSV.dev, PyPI JSON");
    }

    #[test]
    fn the_same_advisory_in_two_lockfiles_stays_two_findings() {
        // Two files are two edits, so collapsing them would hide one.
        let mut findings = vec![
            advisory("osv:GHSA-x", "OSV.dev", Severity::High, "CVE-2020-1"),
            advisory("osv:GHSA-x", "OSV.dev", Severity::High, "CVE-2020-1"),
        ];
        findings[1].path = Some(PathBuf::from("/p/web/uv.lock"));
        findings.sort_by_cached_key(finding_key);
        collapse_advisories(&mut findings);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn normalize_roots_rejects_a_nonexistent_root() {
        let bogus = PathBuf::from("/no/such/husk-scan-root-x7q9");
        let err = normalize_roots(vec![bogus.clone()]).expect_err("must error");
        let message = format!("{err:#}");
        assert!(
            message.contains("husk-scan-root-x7q9"),
            "error must name the offending root: {message}"
        );
        assert!(
            message.contains("does not exist"),
            "error must say why: {message}"
        );
    }

    #[test]
    fn normalize_roots_canonicalizes_and_dedupes_existing_roots() {
        let dir = tempfile::tempdir().expect("tempdir");
        // The same directory spelled two ways collapses to one canonical root.
        let spelled_twice = dir.path().join(".").join("..").join(
            dir.path()
                .file_name()
                .expect("tempdir has a directory name"),
        );
        let roots =
            normalize_roots(vec![dir.path().to_path_buf(), spelled_twice]).expect("normalize");
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], dir.path().canonicalize().expect("canonicalize"));
    }

    #[tokio::test]
    async fn join_or_shutdown_treats_cancellation_as_a_clean_stop() {
        let handle = tokio::task::spawn(async {
            // Never completes on its own; it can only end by being aborted.
            std::future::pending::<()>().await;
        });
        handle.abort();
        let joined = handle.await;
        assert!(joined.is_err(), "an aborted task yields a JoinError");
        assert_eq!(
            join_or_shutdown(joined),
            None,
            "cancellation must be a clean stop, not a panic"
        );
    }

    #[tokio::test]
    async fn join_or_shutdown_passes_a_value_through() {
        let handle = tokio::task::spawn(async { 42_u32 });
        assert_eq!(join_or_shutdown(handle.await), Some(42));
    }

    #[tokio::test]
    async fn join_or_shutdown_reraises_a_real_panic() {
        let handle = tokio::task::spawn(async { panic!("boom") });
        let joined = handle.await;
        let caught =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| join_or_shutdown(joined)));
        assert!(caught.is_err(), "a task panic must propagate");
    }

    #[tokio::test]
    async fn a_panicking_mirror_pass_still_carries_a_failed_row() {
        let err = tokio::task::spawn_blocking(|| panic!("mirror pass"))
            .await
            .expect_err("a panicking task yields a JoinError");
        let row = mirror_failure_row(&err).expect("a panic must never drop the row");
        assert_eq!(row.name, crate::intel::MIRROR_ROW);
        assert!(!row.ok, "a mirror that did not run is not a healthy row");
        assert_eq!(row.checked_packages, 0);
        assert_eq!(row.findings, 0);
        assert!(
            row.message.contains("mirror pass failed"),
            "message: {}",
            row.message
        );
    }

    #[tokio::test]
    async fn a_cancelled_mirror_pass_reports_nothing() {
        let handle = tokio::task::spawn(std::future::pending::<()>());
        handle.abort();
        let err = handle
            .await
            .expect_err("an aborted task yields a JoinError");
        assert!(
            mirror_failure_row(&err).is_none(),
            "Ctrl-C discards the report; it must not invent a failure"
        );
    }
}
