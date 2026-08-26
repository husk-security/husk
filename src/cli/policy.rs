//! The project-policy and ledger command bodies: `husk init` (create the committed
//! `.husk/policy.toml` project policy), `husk approve` (record an allow/block/
//! suppress decision into the policy and the personal trust ledger),
//! `husk ledger` (view/verify the hash-chained `~/.husk/ledger.jsonl`), and
//! `husk policy` (show the active project policy and its counts).

use super::{ApproveArgs, InitArgs, LedgerArgs, PolicyArgs};
use anyhow::{Context, Result};

pub(super) fn run_init(args: InitArgs) -> Result<()> {
    let policy_path = crate::policy::init_project(&args.path)?;
    let husk_dir = policy_path.parent().unwrap_or(&args.path);
    println!("Created {}", policy_path.display());
    println!(
        "  Committed project policy: block/allow packages, suppress findings, set the CI threshold."
    );
    println!(
        "  Edit {} then `git add {}` to share it with your team.",
        policy_path.display(),
        husk_dir.display()
    );
    println!("  `husk scan` and `husk ci` in this project now read this policy.");
    Ok(())
}

pub(super) fn run_approve(args: ApproveArgs) -> Result<()> {
    use crate::policy::{self, Approval};

    let cwd = std::env::current_dir().context("get current directory")?;
    let Some(policy_file) = policy::discover_file(&cwd) else {
        anyhow::bail!(
            "no `.husk/policy.toml` found from {}; run `husk init` first",
            cwd.display()
        );
    };

    let approval = if args.suppress {
        if args.target.trim().is_empty() {
            anyhow::bail!("a finding id is required with --suppress");
        }
        Approval::Suppress {
            id: args.target.clone(),
            reason: args.reason.clone(),
        }
    } else {
        policy::validate_coordinate(&args.target)?;
        if args.block {
            Approval::Block(args.target.clone())
        } else {
            Approval::Allow(args.target.clone())
        }
    };

    let added = policy::approve(&policy_file, &approval)?;
    let what = match &approval {
        Approval::Allow(c) => format!("allow {c}"),
        Approval::Block(c) => format!("block {c}"),
        Approval::Suppress { id, .. } => format!("suppress {id}"),
    };
    if added {
        // Record the decision in the personal append-only trust ledger (local
        // only, never sent anywhere). A failure here must not fail the approve.
        let (action, target, reason) = match &approval {
            Approval::Allow(c) => ("approve.allow", c.as_str(), None),
            Approval::Block(c) => ("approve.block", c.as_str(), None),
            Approval::Suppress { id, reason } => {
                ("approve.suppress", id.as_str(), reason.as_deref())
            }
        };
        let project = policy_file
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.display().to_string());
        if let Err(err) = crate::ledger::append(action, target, reason, project.as_deref()) {
            eprintln!("note: could not write the trust ledger: {err:#}");
        }
        println!("Recorded `{what}` in {}", policy_file.display());
        println!("  Commit the change to share this decision with your team.");
    } else {
        println!("`{what}` is already in {}", policy_file.display());
    }
    Ok(())
}

pub(super) fn run_ledger(args: LedgerArgs) -> Result<()> {
    let entries = crate::ledger::load()?;

    if args.verify {
        match crate::ledger::verify(&entries) {
            None => {
                println!("Trust ledger intact: {} entries verified.", entries.len());
                return Ok(());
            }
            Some(seq) => anyhow::bail!("trust ledger integrity broken at entry #{seq}"),
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if entries.is_empty() {
        println!("Trust ledger is empty. Decisions you record with `husk approve` appear here.");
        println!(
            "  (Stored only at ~/.husk/ledger.jsonl; never sent anywhere, delete it any time.)"
        );
        return Ok(());
    }
    println!("Personal trust ledger ({} entries):", entries.len());
    for entry in &entries {
        let reason = entry
            .reason
            .as_deref()
            .map(|r| format!("  ({r})"))
            .unwrap_or_default();
        println!(
            "  #{:<3} {}  {}  {}{}",
            entry.seq,
            entry.timestamp.format("%Y-%m-%d %H:%M"),
            entry.action,
            entry.target,
            reason
        );
    }
    Ok(())
}

pub(super) fn run_policy_show(args: PolicyArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("get current directory")?;
    let Some(policy) = crate::policy::Policy::discover(std::slice::from_ref(&cwd))? else {
        if args.json {
            println!("null");
        } else {
            println!("No `.husk/policy.toml` found from {}.", cwd.display());
            println!("  Run `husk init` to create one.");
        }
        return Ok(());
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&policy.config)?);
        return Ok(());
    }

    let cfg = &policy.config;
    println!(
        "Project policy: {}",
        policy.dir.join("policy.toml").display()
    );
    println!(
        "  block:    {} package(s){}",
        cfg.packages.block.len(),
        list_preview(&cfg.packages.block)
    );
    println!(
        "  allow:    {} package(s){}",
        cfg.packages.allow.len(),
        list_preview(&cfg.packages.allow)
    );
    println!("  suppress: {} finding id(s)", cfg.suppress.len());
    println!(
        "  ci.fail_on: {}",
        cfg.ci.fail_on.as_deref().unwrap_or("high (default)")
    );
    Ok(())
}

/// A short `: a, b, c` preview of a string list (empty when the list is empty).
fn list_preview(items: &[String]) -> String {
    if items.is_empty() {
        String::new()
    } else {
        let shown: Vec<&str> = items.iter().take(5).map(String::as_str).collect();
        let more = if items.len() > 5 { ", …" } else { "" };
        format!(": {}{more}", shown.join(", "))
    }
}
