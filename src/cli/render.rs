//! Terminal report renderers: the full `husk scan` text report and the compact
//! colored TUI exit summary, plus the small formatting helpers they share (the
//! one-line policy + ledger summary, the KEV/EPSS "fix first" line, and
//! severity-colored counts). Pure presentation; the data comes from
//! `crate::scan` and `crate::policy`/`crate::ledger`.

use crate::model::ScanReport;
use crate::term::{color, format_duration, truncate_middle};
use anyhow::Result;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

/// Pure formatter for the one-line policy + ledger summary. `policy_counts`
/// is `Some((blocked, allowed, suppressed))` when a project policy exists.
/// Returns `None` when there is nothing to show (no policy and an empty ledger).
fn format_policy_line(
    policy_counts: Option<(usize, usize, usize)>,
    ledger_count: usize,
) -> Option<String> {
    if policy_counts.is_none() && ledger_count == 0 {
        return None;
    }
    let mut parts = Vec::new();
    if let Some((blocked, allowed, suppressed)) = policy_counts {
        parts.push(format!(
            "policy: {blocked} blocked · {allowed} allowed · {suppressed} suppressed"
        ));
    }
    if ledger_count > 0 {
        parts.push(format!(
            "ledger: {ledger_count} decision{}",
            if ledger_count == 1 { "" } else { "s" }
        ));
    }
    Some(parts.join("   "))
}

/// The since-last-scan line: "since last scan: 3 resolved · 1 new · 12 unchanged
/// · security score 72 → 84/100". `None` when there is no previous scan to compare to,
/// or when nothing changed and the score held (no news is not a headline).
fn format_delta_line(report: &ScanReport) -> Option<String> {
    let delta = report.delta.as_ref()?;
    if delta.resolved_count == 0 && delta.new_count == 0 && delta.previous_score == delta.score {
        return None;
    }
    let mut line = format!(
        "since last scan: {} resolved · {} new · {} unchanged",
        delta.resolved_count, delta.new_count, delta.unchanged_count
    );
    if delta.previous_score != delta.score {
        line.push_str(&format!(
            " · security score {} → {}/100",
            delta.previous_score, delta.score
        ));
    }
    Some(line)
}

/// Coverage line for a clean result: the denominator, so "no findings" reads
/// as verified coverage rather than absence of work.
pub(super) fn format_coverage_line(report: &ScanReport) -> String {
    let files: usize = report.benchmarks.iter().map(|b| b.files_checked).sum();
    let sources = report.providers.len();
    format!(
        "No issues found. Scanned {files} files and {} packages across {sources} intel source{}.",
        report.stats.packages,
        if sources == 1 { "" } else { "s" }
    )
}

/// The "resolved since last scan" section: what the user's own work (or a fix)
/// made go away, in full; the pager (terminal) or the consuming pipe deals
/// with length; the report itself never truncates.
fn write_resolved_section(out: &mut String, report: &ScanReport) {
    let Some(delta) = &report.delta else { return };
    if delta.resolved.is_empty() {
        return;
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "resolved since last scan:");
    for finding in &delta.resolved {
        let _ = writeln!(
            out,
            "  {} {:8} {}",
            color("✓", "32;1"),
            finding.severity.label(),
            finding.title
        );
    }
}

/// "Fix first" line: how many findings are actively exploited (CISA KEV) or
/// high-EPSS. Returns `None` when no exploit intel applies (offline, or no CVEs).
fn exploit_priority_line(report: &ScanReport) -> Option<String> {
    let kev = report
        .findings
        .iter()
        .filter(|f| f.exploit.as_ref().is_some_and(|e| e.kev))
        .count();
    let high_epss = report
        .findings
        .iter()
        .filter(|f| {
            f.exploit.as_ref().is_some_and(|e| {
                !e.kev && e.epss.is_some_and(|p| p >= crate::prioritize::EPSS_HIGH)
            })
        })
        .count();
    if kev == 0 && high_epss == 0 {
        return None;
    }
    let mut parts = Vec::new();
    if kev > 0 {
        parts.push(format!("{kev} actively exploited (CISA KEV)"));
    }
    if high_epss > 0 {
        parts.push(format!("{high_epss} high exploit-probability (EPSS)"));
    }
    Some(format!("⚠ fix first: {}", parts.join(" · ")))
}

/// Build the summary line from the project policy (discovered from the scan
/// roots) and the personal trust ledger. Offline and best-effort; any IO error
/// just omits that part.
fn policy_summary(roots: &[PathBuf]) -> Option<String> {
    let policy_counts = crate::policy::Policy::discover(roots)
        .ok()
        .flatten()
        .map(|p| {
            (
                p.config.packages.block.len(),
                p.config.packages.allow.len(),
                p.config.suppress.len(),
            )
        });
    let ledger_count = crate::ledger::load().map(|e| e.len()).unwrap_or(0);
    format_policy_line(policy_counts, ledger_count)
}

pub(super) fn print_tui_exit_report(report: &ScanReport, running: bool, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    print_compact_tui_exit_report(report, !running);
    Ok(())
}

/// The full `husk scan` text (or `--json`) report for a completed scan,
/// written to stdout directly (no pager). Callers with a pager seam
/// (`husk scan`, `husk status`) use [`render_report_text`] instead.
pub(super) fn print_report(report: &ScanReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    print!("{}", render_report_text(report));
    Ok(())
}

/// Render the complete `husk scan` text report: every finding, no truncation.
/// The same renderer backs `husk scan` and `husk status`, so the cached view
/// and the fresh view are always the same report. ANSI styling follows
/// `term::color`'s stdout-is-a-terminal gate, so a piped report is plain text.
pub(super) fn render_report_text(report: &ScanReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Husk scan complete {}",
        report.generated_at.to_rfc3339()
    );
    let _ = writeln!(
        out,
        "roots: {}",
        report
            .roots
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(
        out,
        "packages: {}  findings: {}  critical: {}  high: {}  medium: {}  low: {}  info: {}",
        report.stats.packages,
        report.stats.findings,
        report.stats.critical,
        report.stats.high,
        report.stats.medium,
        report.stats.low,
        report.stats.info
    );
    if let Some(line) = format_delta_line(report) {
        let _ = writeln!(out, "{line}");
    }
    if let Some(line) = policy_summary(&report.roots) {
        let _ = writeln!(out, "{line}");
    }
    if let Some(line) = exploit_priority_line(report) {
        let _ = writeln!(out, "{line}");
    }
    write_resolved_section(&mut out, report);

    if !report.providers.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "providers:");
        for provider in &report.providers {
            let status = if provider.ok { "ok" } else { "warn" };
            let _ = writeln!(
                out,
                "  {status:4} {:28} checked {:4}  findings {:4}  {}",
                provider.name, provider.checked_packages, provider.findings, provider.message
            );
        }
    }

    if !report.benchmarks.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "benchmarks:");
        for benchmark in &report.benchmarks {
            let _ = writeln!(
                out,
                "  {:24} {:>6}ms  files {:>7}  bytes {:>10}  packages {:>6}  findings {:>5}  workers {:>2}  {}",
                benchmark.stage,
                benchmark.elapsed_ms,
                benchmark.files_checked,
                benchmark.bytes_scanned,
                benchmark.packages_checked,
                benchmark.findings,
                benchmark.workers,
                benchmark.detail
            );
        }
    }

    if report.findings.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", format_coverage_line(report));
        return out;
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "findings:");
    for finding in &report.findings {
        let location = finding
            .path
            .as_ref()
            .map(|path| {
                finding
                    .line
                    .map(|line| format!("{}:{line}", path.display()))
                    .unwrap_or_else(|| path.display().to_string())
            })
            .unwrap_or_else(|| "-".to_string());
        let _ = writeln!(
            out,
            "  {:8} {:14} {}",
            finding.severity.label(),
            finding.category.id(),
            finding.title
        );
        let _ = writeln!(out, "           {location}");
        let _ = writeln!(out, "           {}", finding.summary);
    }

    out
}

fn print_compact_tui_exit_report(report: &ScanReport, complete: bool) {
    let mut categories = BTreeMap::<&str, usize>::new();
    for finding in &report.findings {
        *categories.entry(finding.category.id()).or_default() += 1;
    }
    let provider_warnings = report
        .providers
        .iter()
        .filter(|provider| !provider.ok)
        .count();
    let elapsed = report
        .benchmarks
        .iter()
        .map(|benchmark| benchmark.elapsed_ms)
        .sum::<u128>();
    let roots = report
        .roots
        .iter()
        .map(|root| root.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    println!(
        "{} {}  {}",
        color("Goodbye!", "36;1"),
        color("Husk session summary", "1"),
        if complete {
            color("complete", "32;1")
        } else {
            color("stopped", "33;1")
        }
    );
    println!(
        "  {} {}   {} {}   {} {}",
        color("roots", "90"),
        truncate_middle(&roots, 54),
        color("packages", "90"),
        report.stats.packages,
        color("time", "90"),
        format_duration(elapsed)
    );
    println!(
        "  {} {}   {} {}   {} {}",
        risk_count("critical", report.stats.critical, "31;1"),
        risk_count("high", report.stats.high, "91;1"),
        risk_count("medium", report.stats.medium, "33;1"),
        risk_count("low", report.stats.low, "34;1"),
        risk_count("info", report.stats.info, "90;1"),
        color(format!("total {}", report.stats.findings), "1")
    );
    if let Some(line) = format_delta_line(report) {
        let accent = if report.delta.as_ref().is_some_and(|d| d.new_count > 0) {
            "33"
        } else {
            "32"
        };
        println!("  {}", color(line, accent));
    }
    if report.findings.is_empty() {
        println!("  {}", color(format_coverage_line(report), "32"));
    }
    if let Some(line) = policy_summary(&report.roots) {
        println!("  {}", color(line, "90"));
    }
    if !categories.is_empty() {
        let category_summary = categories
            .iter()
            .map(|(category, count)| format!("{category} {count}"))
            .collect::<Vec<_>>()
            .join("  ");
        println!(
            "  {} {}",
            color("types", "90"),
            truncate_middle(&category_summary, 88)
        );
    }
    if !report.providers.is_empty() {
        println!(
            "  {} {} checked   {} {}",
            color("providers", "90"),
            report.providers.len(),
            color(
                "warnings",
                if provider_warnings == 0 { "32" } else { "33;1" }
            ),
            provider_warnings
        );
    }
}

fn risk_count(label: &str, count: usize, ansi: &str) -> String {
    color(format!("{label} {count}"), ansi)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn delta_line_shows_movement_and_hides_steady_state() {
        use crate::model::ScanDelta;
        let mut report = ScanReport::empty(vec![]);
        assert_eq!(format_delta_line(&report), None, "no previous scan");

        report.delta = Some(ScanDelta {
            previous_at: chrono::Utc::now(),
            previous_score: 72,
            score: 84,
            new_count: 1,
            unchanged_count: 12,
            resolved_count: 3,
            resolved: Vec::new(),
            new: Vec::new(),
        });
        assert_eq!(
            format_delta_line(&report).as_deref(),
            Some("since last scan: 3 resolved · 1 new · 12 unchanged · security score 72 → 84/100")
        );

        // Nothing moved → no line (steady state is not a headline).
        report.delta = Some(ScanDelta {
            previous_at: chrono::Utc::now(),
            previous_score: 84,
            score: 84,
            new_count: 0,
            unchanged_count: 12,
            resolved_count: 0,
            resolved: Vec::new(),
            new: Vec::new(),
        });
        assert_eq!(format_delta_line(&report), None);
    }

    #[test]
    fn coverage_line_states_the_denominator() {
        let mut report = ScanReport::empty(vec![]);
        report.stats.packages = 312;
        report.benchmarks = vec![
            crate::model::StageBenchmark {
                files_checked: 1_000,
                ..Default::default()
            },
            crate::model::StageBenchmark {
                files_checked: 204,
                ..Default::default()
            },
        ];
        report.providers = vec![crate::model::ProviderStatus {
            name: "osv".into(),
            ok: true,
            checked_packages: 0,
            findings: 0,
            message: String::new(),
        }];
        assert_eq!(
            format_coverage_line(&report),
            "No issues found. Scanned 1204 files and 312 packages across 1 intel source."
        );
    }

    #[test]
    fn report_text_lists_every_finding_untruncated() {
        let mut report = ScanReport::empty(vec![]);
        for i in 0..75 {
            report.findings.push(crate::model::Finding::new(
                format!("finding-{i}"),
                format!("Test finding number {i}"),
                Severity::Medium,
                crate::rule::Category::Secret,
                "test",
                None,
                None,
                format!("summary {i}"),
                None,
                "do the thing",
            ));
        }
        report.delta = Some(crate::model::ScanDelta {
            previous_at: chrono::Utc::now(),
            previous_score: 50,
            score: 60,
            new_count: 0,
            unchanged_count: 75,
            resolved_count: 25,
            resolved: (0..25)
                .map(|i| {
                    crate::model::Finding::new(
                        format!("resolved-{i}"),
                        format!("Resolved finding {i}"),
                        Severity::Low,
                        crate::rule::Category::Secret,
                        "test",
                        None,
                        None,
                        "gone",
                        None,
                        "",
                    )
                })
                .collect(),
            new: Vec::new(),
        });

        let text = render_report_text(&report);
        for i in 0..75 {
            assert!(
                text.contains(&format!("Test finding number {i}")),
                "finding {i} missing from report text"
            );
        }
        for i in 0..25 {
            assert!(
                text.contains(&format!("Resolved finding {i}")),
                "resolved finding {i} missing from report text"
            );
        }
        assert!(!text.contains("more findings"), "truncation marker present");
        assert!(!text.contains("more resolved"), "truncation marker present");
    }

    #[test]
    fn policy_line_formatting() {
        assert_eq!(format_policy_line(None, 0), None);
        assert_eq!(
            format_policy_line(None, 1).as_deref(),
            Some("ledger: 1 decision")
        );
        assert_eq!(
            format_policy_line(Some((2, 1, 3)), 0).as_deref(),
            Some("policy: 2 blocked · 1 allowed · 3 suppressed")
        );
        assert_eq!(
            format_policy_line(Some((0, 0, 0)), 5).as_deref(),
            Some("policy: 0 blocked · 0 allowed · 0 suppressed   ledger: 5 decisions")
        );
    }
}
