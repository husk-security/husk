//! The `husk fix` command body: plan the safe-fixable subset of findings and,
//! with `--apply`/`--yes`, apply the auto-safe fixes (plus `--rollback` to
//! restore from a backup). The planning + apply logic lives in `crate::remediation`
//! (pure planner + IO applier); this module is the CLI surface + terminal
//! rendering of the plan and outcome.

use super::FixArgs;
use super::scan::{cached_or_scan, options_from_args};
use crate::term::{color, severity_ansi};
use anyhow::Result;
use std::path::PathBuf;

pub(super) async fn run_fix(args: FixArgs) -> Result<()> {
    use crate::remediation::{self, ActionStatus, ExecutionClass, RemediationOperation};

    // `--rollback [TS]` short-circuits: restore files and exit, no scan.
    if let Some(stamp) = &args.rollback {
        let husk_dir = PathBuf::from(".husk");
        let pick = if stamp.is_empty() {
            None
        } else {
            Some(stamp.as_str())
        };
        let restored = remediation::rollback(&husk_dir, pick)?;
        if args.scan.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "restored": restored }))?
            );
        } else if restored.is_empty() {
            println!("husk fix: nothing to roll back.");
        } else {
            println!("husk fix: restored {} file(s):", restored.len());
            for path in &restored {
                println!("  {path}");
            }
        }
        return Ok(());
    }

    let do_apply = (args.apply || args.yes || args.all) && !args.dry_run;
    let run_deps = args.deps || args.all;
    if !args.scan.json {
        eprintln!(
            "Husk fix: {} ...",
            if do_apply {
                "applying the auto-safe fixes"
            } else {
                "planning (dry run, nothing will change)"
            }
        );
    }
    let report = cached_or_scan(
        options_from_args(&args.scan.scope, args.scan.json)?,
        args.scan.rescan,
    )
    .await?;
    let plan = remediation::plan(&report);

    let mut opts = remediation::ApplyOptions::new(!do_apply);
    opts.only = args.only.clone();
    opts.deps = run_deps;
    if run_deps && !args.scan.json {
        // Package-manager installs can take a while with no other output;
        // announce each one as it starts so the terminal doesn't look frozen.
        opts.on_dep_run = Some(Box::new(|command| {
            eprintln!("  {} {command}", color("running:", "36"));
        }));
    }
    let outcome = remediation::apply(&plan, &opts)?;

    if args.scan.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "plan": plan, "outcome": outcome }))?
        );
        return Ok(());
    }

    if plan.proposals.is_empty() {
        println!();
        if report.findings.is_empty() {
            println!(
                "  {}",
                color(super::render::format_coverage_line(&report), "32;1")
            );
        } else {
            println!("  {}", color("Nothing to fix automatically.", "32;1"));
        }
        return Ok(());
    }
    println!();
    println!(
        "  {}   {}   {}   {}",
        color("husk fix", "1"),
        color(format!("{} auto-safe", plan.auto_safe_count()), "32;1"),
        color(format!("{} to run yourself", plan.confirm_count()), "33;1"),
        color(format!("{} manual", plan.manual_count()), "90;1")
    );
    println!();

    for fix in &plan.proposals {
        let result = outcome.results.iter().find(|r| r.id == fix.id);
        let (class_label, class_ansi) = match fix.class {
            ExecutionClass::AutoSafe => ("auto-safe", "32;1"),
            ExecutionClass::Confirm => ("run-yourself", "33;1"),
            ExecutionClass::Manual => ("manual", "90;1"),
        };
        let sev_ansi = severity_ansi(fix.severity);
        println!(
            "  {} {}  {}",
            color(format!("[{class_label}]"), class_ansi),
            color(&fix.title, "1"),
            color(fix.severity.label(), sev_ansi)
        );
        println!("       {}", color(&fix.reason, "90"));
        match &fix.action {
            RemediationOperation::SetConfigValue { path, key, value } => {
                println!(
                    "       {}",
                    color(format!("set {key}={value} in {}", path.display()), "36")
                );
                if let Some(result) = result {
                    let (marker, ansi) = fix_status_style(&result.status);
                    println!("       {} {}", color(marker, ansi), result.detail);
                }
            }
            RemediationOperation::GitignoreAppend { .. }
            | RemediationOperation::EnvTemplate { .. } => {
                if let Some(result) = result {
                    let (marker, ansi) = fix_status_style(&result.status);
                    println!("       {} {}", color(marker, ansi), result.detail);
                }
            }
            RemediationOperation::DependencyUpdate {
                command,
                manifest_path,
                tool_available,
                blocker,
                ..
            } => {
                println!(
                    "       {}",
                    color(format!("in {}", manifest_path.display()), "90")
                );
                if *tool_available && blocker.is_none() {
                    println!("       {}", color(format!("$ {}", command.join(" ")), "36"));
                }
                // Missing-tool/blocked cases need no extra line: `reason` and
                // `result.detail` already carry the advice.
                if let Some(result) = result {
                    let (marker, ansi) = fix_status_style(&result.status);
                    println!("       {} {}", color(marker, ansi), result.detail);
                }
            }
            RemediationOperation::Manual { steps } => {
                for (i, step) in steps.iter().enumerate() {
                    println!("       {}. {}", i + 1, step.text);
                    for subject in &step.subjects {
                        println!("          {}", color(subject.clone(), "90"));
                    }
                }
            }
        }
    }

    println!();
    if do_apply {
        let applied = outcome
            .results
            .iter()
            .filter(|r| r.status == ActionStatus::Applied)
            .count();
        let skipped = outcome
            .results
            .iter()
            .filter(|r| r.status == ActionStatus::Skipped)
            .count();
        println!(
            "  {} applied {}, already-ok {}.",
            color("done:", "32;1"),
            applied,
            skipped
        );
        if let Some(dir) = &outcome.backup_dir {
            println!(
                "  {} {}   (undo: husk fix --rollback)",
                color("backup:", "90"),
                dir.display()
            );
        }
        // Close the loop: rescan and show the findings the fixes actually made
        // go away, not just "applied N". The pre-fix report is still the cached
        // one, so the fresh scan's delta is exactly the fix's effect. The file
        // index makes this cheap; unchanged files are cache hits.
        if applied > 0 {
            eprintln!();
            eprintln!("Husk fix: verifying. Rescanning to confirm the fixes ...");
            let after = cached_or_scan(options_from_args(&args.scan.scope, true)?, true).await?;
            println!();
            match after.delta.as_ref().filter(|d| d.resolved_count > 0) {
                Some(delta) => {
                    let movement = if delta.previous_score != delta.score {
                        format!(
                            "   security score {} → {}/100",
                            delta.previous_score, delta.score
                        )
                    } else {
                        String::new()
                    };
                    println!(
                        "  {} rescan confirms {} finding(s) resolved{movement}",
                        color("verified:", "32;1"),
                        delta.resolved_count
                    );
                    for finding in delta.resolved.iter().take(10) {
                        println!("    {} {}", color("✓", "32;1"), finding.title);
                    }
                    if delta.resolved_count > 10 {
                        println!("    ... {} more resolved", delta.resolved_count - 10);
                    }
                }
                None => println!(
                    "  {} rescan still shows the findings. The remaining fixes need you.",
                    color("note:", "33;1")
                ),
            }
        }
    } else {
        let would = outcome
            .results
            .iter()
            .filter(|r| r.status == ActionStatus::WouldApply)
            .count();
        if would > 0 {
            println!(
                "  {} husk fix --apply   to apply {} auto-safe fix(es)",
                color("run:", "1"),
                would
            );
        } else {
            println!(
                "  {}",
                color("No auto-safe fixes to apply; the rest need you.", "90")
            );
        }
        let deps = plan
            .proposals
            .iter()
            .filter(|f| matches!(f.action, RemediationOperation::DependencyUpdate { .. }))
            .count();
        if deps > 0 && !args.deps {
            println!(
                "  {} husk fix --apply --deps   to also run {} dependency upgrade/downgrade(s)",
                color("run:", "1"),
                deps
            );
        }
    }
    Ok(())
}

fn fix_status_style(status: &crate::remediation::ActionStatus) -> (&'static str, &'static str) {
    use crate::remediation::ActionStatus;
    match status {
        ActionStatus::WouldApply => ("would:", "36;1"),
        ActionStatus::Applied => ("✓ applied:", "32;1"),
        ActionStatus::Skipped => ("✓ already ok:", "32"),
        ActionStatus::NeedsUser => ("needs you:", "33;1"),
        ActionStatus::Failed => ("✗ failed:", "31;1"),
    }
}
