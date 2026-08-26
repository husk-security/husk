//! Proposal-level behaviour: what the guide controls produce from a report, and
//! what the executor does with it end to end. The op vocabulary, the executor's
//! invariants, and each ecosystem's planning live in their own modules' tests.

use super::*;
use crate::model::{Finding, ScanReport};

fn empty_report() -> ScanReport {
    ScanReport::empty(vec![])
}

fn secret_finding(id: &str, path: &str) -> Finding {
    Finding::new(
        id,
        "secret exposed",
        Severity::High,
        crate::rule::Category::Secret,
        "test",
        Some(PathBuf::from(path)),
        Some(1),
        "summary",
        None,
        "rec",
    )
}

fn vuln_finding(name: &str, version: &str, fixed: Option<&str>) -> Finding {
    advisory(&format!("osv:X:{name}@{version}"), name, version, fixed)
}

/// A vulnerability finding with an explicit advisory id, for the cases where
/// two advisories name the same coordinate.
fn advisory(id: &str, name: &str, version: &str, fixed: Option<&str>) -> Finding {
    Finding::new(
        id,
        "vuln",
        Severity::High,
        crate::rule::Category::Vulnerability,
        "OSV.dev",
        None,
        None,
        "summary",
        None,
        "rec",
    )
    .with_package(crate::model::PackageRef {
        ecosystem: "npm".to_string(),
        name: name.to_string(),
        version: version.to_string(),
        manifest_path: PathBuf::from("/proj/package-lock.json"),
        line: None,
    })
    .with_fixed_version(fixed.map(str::to_string))
}

/// A real npm project on disk, so planning resolves a workspace and produces a
/// runnable recipe rather than a `NoManifest` blocker.
fn npm_project(dir: &Path, current: &str, target: &str) -> RemediationPlan {
    std::fs::write(dir.join("package.json"), "{\n  \"name\": \"t\"\n}\n").unwrap();
    let lockfile = dir.join("package-lock.json");
    std::fs::write(&lockfile, "{}").unwrap();

    let mut change = Change::new("lodash", current, target, lockfile);
    change.severity = Severity::High;
    RemediationPlan {
        generated_at: Utc::now(),
        proposals: plan_changes(vec![("npm".to_string(), change)], &Toolbox::everything()),
    }
}

/// A report whose proposals have been produced, the way scan finalization does
/// it. `remediation::plan` deliberately has no fallback that reaches back into
/// the guide registry, so tests run the controls the same way the scan does.
fn planned(report: &mut ScanReport) -> RemediationPlan {
    report.remediations = crate::guide::control::run(report).1;
    plan(report)
}

#[test]
fn every_runnable_program_has_install_advice() {
    // A missing entry would turn "not installed" into an unhelpful catch-all,
    // which is the difference between an actionable state and a dead end.
    for program in plan::PROGRAMS {
        assert_ne!(
            install_advice_for(program),
            install_advice_for("totally-unknown-program"),
            "{program} should have specific advice, not the generic fallback"
        );
    }
}

#[test]
fn every_fixer_program_is_a_known_program() {
    // `Toolbox` probes a fixed list; a fixer naming a binary outside it would
    // always look uninstalled.
    for fixer in ecosystems::default_fixers() {
        for flavor in ["default", "npm", "yarn", "yarn-berry", "pnpm", "bun", "uv"] {
            let ws = Workspace::fixture("/p", "/p/m", flavor, None, &[]);
            let program = fixer.program(&ws);
            assert!(
                plan::PROGRAMS.contains(&program),
                "{} names {program}, which Toolbox never probes",
                fixer.ecosystem()
            );
        }
    }
}

#[test]
fn dependency_proposals_label_upgrade_and_downgrade() {
    let mut report = empty_report();
    report
        .findings
        .push(vuln_finding("lodash", "4.17.20", Some("4.17.21")));
    // A compromised newer release: the safe version is the older one.
    report
        .findings
        .push(vuln_finding("evil", "1.131.51", Some("1.131.50")));

    let titles: Vec<String> = dependency_proposals(&report)
        .into_iter()
        .map(|proposal| proposal.title)
        .collect();
    assert!(titles.contains(&"Upgrade lodash to 4.17.21".to_string()));
    assert!(titles.contains(&"Downgrade evil to 1.131.50".to_string()));
}

#[test]
fn a_coordinate_already_on_the_safe_version_gets_no_proposal() {
    let mut report = empty_report();
    report.findings.push(vuln_finding("no-fix", "1.0.0", None));
    report
        .findings
        .push(vuln_finding("already-safe", "2.0.0", Some("2.0.0")));
    assert!(dependency_proposals(&report).is_empty());
}

#[test]
fn two_advisories_on_one_package_produce_one_proposal_at_the_highest_target() {
    let mut report = empty_report();
    report
        .findings
        .push(advisory("GHSA-a", "lodash", "4.17.19", Some("4.17.20")));
    report
        .findings
        .push(advisory("GHSA-b", "lodash", "4.17.19", Some("4.17.21")));

    let proposals = dependency_proposals(&report);
    assert_eq!(proposals.len(), 1, "one proposal per package coordinate");
    let RemediationOperation::DependencyUpdate { target_version, .. } = &proposals[0].action else {
        panic!("expected a dependency update");
    };
    assert_eq!(target_version, "4.17.21");
    // Both findings are closed by the one proposal, and the explanation admits
    // a choice was made rather than silently taking the higher version.
    assert_eq!(proposals[0].finding_ids.len(), 2);
    assert!(
        proposals[0]
            .recipe
            .explain
            .notes
            .iter()
            .any(|note| note.contains("4.17.20") && note.contains("4.17.21"))
    );
}

#[test]
fn advisories_that_disagree_about_direction_block_rather_than_pick_one() {
    // Taking the highest safe version is the right default, and silently wrong
    // when one advisory wants a newer release and another an older one: no
    // single pin satisfies both, so neither is offered as a click.
    let mut report = empty_report();
    report
        .findings
        .push(advisory("GHSA-a", "lodash", "4.17.19", Some("4.17.21")));
    report
        .findings
        .push(advisory("GHSA-b", "lodash", "4.17.19", Some("4.17.10")));

    let proposals = dependency_proposals(&report);
    assert_eq!(proposals.len(), 1);
    assert!(
        proposals[0]
            .blockers
            .contains(&Blocker::ConflictingTargets {
                targets: vec!["4.17.10".to_string(), "4.17.21".to_string()],
            })
    );
    // A hard stop, so no surface offers a "do it anyway" affordance.
    assert!(proposals[0].overrides.is_empty());
}

#[test]
fn a_surface_acting_on_one_row_gets_the_merged_answer() {
    // Re-planning per finding would bypass the cross-finding merge, and two
    // advisories on one package would then show a different target version
    // depending on which surface was asked.
    let mut report = empty_report();
    report
        .findings
        .push(advisory("GHSA-a", "lodash", "4.17.19", Some("4.17.20")));
    report
        .findings
        .push(advisory("GHSA-b", "lodash", "4.17.19", Some("4.17.21")));
    report.remediations = dependency_proposals(&report);

    let plan = plan(&report);
    for finding_id in ["GHSA-a", "GHSA-b"] {
        let proposal = plan.for_finding(finding_id).next().expect(finding_id);
        assert!(proposal.title.ends_with("4.17.21"));
    }
}

#[test]
fn apply_without_the_deps_flag_never_runs_a_package_manager() {
    let dir = tempfile::tempdir().unwrap();
    let plan = npm_project(dir.path(), "4.17.19", "4.17.21");
    let mut options = ApplyOptions::new(false);
    options.husk_dir = dir.path().join(".husk");

    let outcome = apply(&plan, &options).expect("apply");
    assert_eq!(outcome.results[0].status, ActionStatus::NeedsUser);
    assert!(
        outcome.results[0].detail.contains("--deps"),
        "{}",
        outcome.results[0].detail
    );
    assert!(
        outcome.backup_dir.is_none(),
        "a refused fix writes nothing at all"
    );
}

#[test]
fn dry_run_with_deps_only_previews() {
    let dir = tempfile::tempdir().unwrap();
    let plan = npm_project(dir.path(), "4.17.19", "4.17.21");
    let mut options = ApplyOptions::new(true);
    options.deps = true;
    options.husk_dir = dir.path().join(".husk");

    let outcome = apply(&plan, &options).expect("dry-run apply");
    assert_eq!(outcome.results[0].status, ActionStatus::WouldApply);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        "{\n  \"name\": \"t\"\n}\n",
        "a dry run previews the override without writing it"
    );
}

#[test]
fn dotenv_detection() {
    assert!(is_dotenv_path(Path::new("/p/.env")));
    assert!(is_dotenv_path(Path::new("/p/.env.local")));
    assert!(is_dotenv_path(Path::new("/p/.env.production")));
    assert!(is_dotenv_path(Path::new("/p/.envrc")));
    assert!(!is_dotenv_path(Path::new("/p/src/main.rs")));
    assert!(!is_dotenv_path(Path::new("/p/config.toml")));
}

#[test]
fn a_source_file_secret_is_manual_and_never_gitignored() {
    let mut report = empty_report();
    report.findings.push(secret_finding(
        "secret:aws:/proj/src/app.rs",
        "/proj/src/app.rs",
    ));
    let plan = planned(&mut report);
    assert!(
        plan.proposals.iter().all(|proposal| !matches!(
            proposal.action,
            RemediationOperation::GitignoreAppend { .. }
        )),
        "must never propose .gitignore for a source file"
    );
    assert!(
        plan.proposals
            .iter()
            .all(|proposal| proposal.class == ExecutionClass::Manual)
    );
}

#[test]
fn source_secrets_of_one_kind_collapse_into_one_rotation_carrying_every_finding() {
    let mut report = empty_report();
    for path in ["/proj/src/a.rs", "/proj/src/b.rs", "/proj/lib/c.rs"] {
        report
            .findings
            .push(secret_finding(&format!("secret:aws:{path}"), path));
    }
    let plan = planned(&mut report);
    let rotations: Vec<&RemediationProposal> = plan
        .proposals
        .iter()
        .filter(|proposal| proposal.id.starts_with("rotate:"))
        .collect();
    assert_eq!(rotations.len(), 1, "one rotation job, not one card per key");
    // The join back to the findings a card resolves, which an empty vector
    // silently breaks.
    assert_eq!(rotations[0].finding_ids.len(), 3);
    // One instruction over three locations, not three instructions: every
    // location is named, and the sentence telling the user what to do with them
    // is written once.
    let steps = &rotations[0].recipe.steps;
    let revoke = &steps[0];
    assert_eq!(
        revoke.subjects,
        vec!["/proj/lib/c.rs", "/proj/src/a.rs", "/proj/src/b.rs"]
    );
    assert!(
        steps.iter().all(|step| step
            .subjects
            .iter()
            .all(|subject| !step.text.contains(subject.as_str()))),
        "a subject belongs in the list, never inlined into the instruction"
    );
}

/// The checklist a user reads must not grow a sentence per file. Twenty-two
/// files needing the same treatment is one instruction and twenty-two subjects.
#[test]
fn a_rotation_checklist_is_the_same_length_however_many_files_it_covers() {
    let shape = |count: usize| {
        let mut report = empty_report();
        for i in 0..count {
            let path = format!("/proj/src/f{i:02}.rs");
            report
                .findings
                .push(secret_finding(&format!("secret:aws:{path}"), &path));
        }
        let steps = planned(&mut report)
            .proposals
            .iter()
            .find(|proposal| proposal.id.starts_with("rotate:"))
            .expect("a rotation proposal")
            .recipe
            .steps
            .clone();
        (steps.len(), steps[0].subjects.len())
    };
    assert_eq!([shape(1), shape(3), shape(22)], [(3, 1), (3, 3), (3, 22)]);
}

#[test]
fn secrets_of_different_kinds_stay_separate_rotations() {
    let mut report = empty_report();
    let mut github = secret_finding("secret:gh:/proj/a.rs", "/proj/a.rs");
    github.title = "GitHub token exposed".to_string();
    let mut aws = secret_finding("secret:aws:/proj/b.rs", "/proj/b.rs");
    aws.title = "AWS access key exposed".to_string();
    report.findings.push(github);
    report.findings.push(aws);
    let plan = planned(&mut report);
    let titles: Vec<&str> = plan
        .proposals
        .iter()
        .filter(|proposal| proposal.id.starts_with("rotate:"))
        .map(|proposal| proposal.title.as_str())
        .collect();
    // Two consoles to rotate in, so two cards.
    assert_eq!(titles.len(), 2);
    assert!(titles.iter().any(|title| title.starts_with("GitHub token")));
    assert!(
        titles
            .iter()
            .any(|title| title.starts_with("AWS access key"))
    );
}

/// Git is asked about a whole repository at once, so the answer for one path
/// must not leak into another's: the three states have to stay separable when
/// they arrive as one batch.
#[test]
fn every_dotenv_state_in_one_repository_survives_a_batched_git_query() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().canonicalize().unwrap();
    let git = |args: &[&str]| {
        crate::gitcmd::git_command()
            .args(["-C", &repo.to_string_lossy()])
            .args(args)
            .output()
            .is_ok_and(|out| out.status.success())
    };
    assert!(git(&["init", "--quiet"]), "git init");
    std::fs::write(repo.join(".gitignore"), "ignored/\n").unwrap();
    let mut report = empty_report();
    for sub in ["plain", "ignored", "tracked"] {
        let dotenv = repo.join(sub).join(".env");
        std::fs::create_dir_all(dotenv.parent().unwrap()).unwrap();
        std::fs::write(&dotenv, "API_KEY=value\n").unwrap();
        report.findings.push(secret_finding(
            &format!("env:{sub}"),
            dotenv.to_str().unwrap(),
        ));
    }
    assert!(git(&["add", "tracked/.env"]), "git add");

    let proposals = secret_proposals(&report);
    let repo_name = repo.file_name().unwrap().to_string_lossy().to_string();
    let gitignore_fix = |sub: &str| {
        let title = format!("Keep {repo_name}/{sub}/.env out of git");
        proposals
            .iter()
            .find(|proposal| proposal.title == title)
            .cloned()
    };

    assert_eq!(
        gitignore_fix("plain")
            .expect("a fix for the plain file")
            .class,
        ExecutionClass::AutoSafe
    );
    assert!(
        gitignore_fix("ignored").is_none(),
        "git already ignores it, so there is nothing to add"
    );
    assert_eq!(
        gitignore_fix("tracked")
            .expect("a fix for the tracked file")
            .class,
        ExecutionClass::Manual,
        "ignoring a tracked file changes nothing, so the fix is a checklist"
    );
}

#[test]
fn two_dotenv_files_in_one_repo_get_distinguishable_titles() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().canonicalize().unwrap();
    let git = |args: &[&str]| {
        crate::gitcmd::git_command()
            .args(["-C", &repo.to_string_lossy()])
            .args(args)
            .output()
            .is_ok_and(|out| out.status.success())
    };
    assert!(git(&["init", "--quiet"]), "git init");
    let mut report = empty_report();
    for sub in ["apps/api", "apps/web"] {
        let dotenv = repo.join(sub).join(".env");
        std::fs::create_dir_all(dotenv.parent().unwrap()).unwrap();
        std::fs::write(&dotenv, "API_KEY=value\n").unwrap();
        report.findings.push(secret_finding(
            &format!("env:{sub}"),
            dotenv.to_str().unwrap(),
        ));
    }

    let titles: Vec<String> = secret_proposals(&report)
        .into_iter()
        .map(|proposal| proposal.title)
        .collect();
    let unique: std::collections::BTreeSet<&String> = titles.iter().collect();
    assert_eq!(
        unique.len(),
        titles.len(),
        "each file's fix must be tellable apart: {titles:?}"
    );
    let repo_name = repo.file_name().unwrap().to_string_lossy().to_string();
    for sub in ["apps/api", "apps/web"] {
        assert!(
            titles.contains(&format!("Keep {repo_name}/{sub}/.env out of git")),
            "{titles:?}"
        );
    }
}

#[test]
fn a_dotenv_secret_pairs_an_auto_safe_edit_with_a_manual_rotation() {
    let mut report = empty_report();
    report
        .findings
        .push(secret_finding("env:/proj/.env", "/proj/.env"));
    let plan = planned(&mut report);
    // The credential rotation is always manual; Husk never rotates.
    let rotation = plan
        .proposals
        .iter()
        .find(|proposal| proposal.id.starts_with("rotate:"))
        .expect("a rotation proposal");
    assert_eq!(rotation.class, ExecutionClass::Manual);
    assert!(rotation.recipe.ops.is_empty());
    assert_eq!(rotation.recipe.steps.len(), 3);
}

#[test]
fn env_template_emits_only_validated_keys() {
    let env = "# database\n\
               DATABASE_URL=postgres://user:pass@host/db\n\
               API_KEY=\"sk-secret-value\"\n\
               export TOKEN=abc123\n\
               PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\n\
               secret-body-continuation\n\
               -----END PRIVATE KEY-----\"\n\
               # comment containing another-secret\n\
               NOT-AN-ASSIGNMENT=value\n";
    let template = env_template_from(env);
    assert_eq!(
        template,
        "DATABASE_URL=\n\
         API_KEY=\n\
         export TOKEN=\n\
         PRIVATE_KEY=\n"
    );
    // The template must never contain any of the original secret values.
    assert!(!template.contains("postgres://"));
    assert!(!template.contains("sk-secret-value"));
    assert!(!template.contains("abc123"));
    assert!(!template.contains("secret-body-continuation"));
    assert!(!template.contains("another-secret"));
}

#[test]
fn applying_a_template_leaves_the_dotenv_untouched_and_never_clobbers() {
    let dir = tempfile::tempdir().unwrap();
    let dotenv = dir.path().join(".env");
    std::fs::write(&dotenv, "API_KEY=supersecret\nPORT=8080\n").unwrap();

    let mut report = empty_report();
    report
        .findings
        .push(secret_finding("env", dotenv.to_str().unwrap()));
    let plan = RemediationPlan {
        generated_at: Utc::now(),
        proposals: secret_proposals(&report),
    };
    let mut options = ApplyOptions::new(false);
    options.husk_dir = dir.path().join(".husk");

    let outcome = apply(&plan, &options).unwrap();
    let template = std::fs::read_to_string(dir.path().join(".env.template")).unwrap();
    assert_eq!(template, "API_KEY=\nPORT=\n");
    assert!(
        outcome
            .results
            .iter()
            .any(|result| result.status == ActionStatus::Applied)
    );
    assert_eq!(
        std::fs::read_to_string(&dotenv).unwrap(),
        "API_KEY=supersecret\nPORT=8080\n",
        "the original dotenv is never modified"
    );

    // Re-applying skips rather than clobbering the template a human may have
    // since edited.
    let again = apply(&plan, &options).unwrap();
    assert!(
        again
            .results
            .iter()
            .all(|result| result.status != ActionStatus::Applied)
    );
}

#[test]
fn dry_run_writes_nothing_at_all() {
    let dir = tempfile::tempdir().unwrap();
    let dotenv = dir.path().join(".env");
    std::fs::write(&dotenv, "API_KEY=x\n").unwrap();

    let mut report = empty_report();
    report
        .findings
        .push(secret_finding("env", dotenv.to_str().unwrap()));
    let plan = RemediationPlan {
        generated_at: Utc::now(),
        proposals: secret_proposals(&report),
    };
    let husk_dir = dir.path().join(".husk");
    let options = ApplyOptions {
        dry_run: true,
        husk_dir: husk_dir.clone(),
        ..ApplyOptions::new(true)
    };

    let outcome = apply(&plan, &options).expect("dry-run apply");
    assert!(outcome.dry_run);
    assert!(
        outcome.backup_dir.is_none(),
        "dry-run creates no backup dir"
    );
    assert!(!husk_dir.exists(), "dry-run writes nothing at all");
    assert!(!dir.path().join(".env.template").exists());
}

#[test]
fn a_dependency_write_is_snapshotted_so_rollback_restores_it() {
    // Every write Husk makes is reversible, including the manifest edit that
    // precedes a package-manager run.
    let dir = tempfile::tempdir().unwrap();
    let mut plan = npm_project(dir.path(), "1.0.0", "1.0.5");
    let original = std::fs::read_to_string(dir.path().join("package.json")).unwrap();
    // The relock step needs a real npm, which a test machine may not have, so
    // drop it: the manifest edit is what rollback has to restore.
    plan.proposals[0]
        .recipe
        .ops
        .retain(|op| op.argv().is_none());

    let mut options = ApplyOptions::new(false);
    options.husk_dir = dir.path().join(".husk");
    options.deps = true;

    let outcome = apply(&plan, &options).unwrap();
    assert_eq!(outcome.results[0].status, ActionStatus::Applied);
    assert!(outcome.backup_dir.is_some());
    assert!(
        std::fs::read_to_string(dir.path().join("package.json"))
            .unwrap()
            .contains("overrides")
    );

    rollback(&options.husk_dir, None).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        original,
        "rollback must restore package.json byte-identical"
    );
}

#[test]
fn a_dependency_proposal_shows_both_the_diff_and_the_command_that_matches_it() {
    // The trust surface: a developer who would rather run the package manager
    // themselves must be shown what husk would run, flags and all, and the
    // diff must be the same edit that command makes.
    let dir = tempfile::tempdir().unwrap();
    let plan = npm_project(dir.path(), "1.0.0", "1.0.5");
    let preview = plan.proposals[0].preview.clone().expect("a preview");

    assert_eq!(
        preview.command.as_deref(),
        Some(
            "npm pkg set overrides.lodash=1.0.5 && npm install --package-lock-only --ignore-scripts"
        ),
        "the shown command carries the same --ignore-scripts husk applies"
    );
    assert!(preview.complete, "every op here has a command form");

    let [file] = preview.diff.as_slice() else {
        panic!("one edited file, got {:?}", preview.diff);
    };
    assert_eq!(file.path, dir.path().join("package.json"));
    assert_eq!((file.added, file.removed), (4, 1));
    let added: Vec<&str> = file
        .diff
        .lines()
        .filter_map(|line| line.strip_prefix('+'))
        .map(str::trim)
        .collect();
    assert!(added.contains(&"\"lodash\": \"1.0.5\""), "{added:?}");
}

#[test]
fn the_previewed_bytes_are_the_bytes_apply_writes() {
    // One render, two callers. If these ever diverge the preview is a lie,
    // which is worse than having no preview at all.
    let dir = tempfile::tempdir().unwrap();
    let mut plan = npm_project(dir.path(), "1.0.0", "1.0.5");
    let previewed = plan.proposals[0]
        .preview
        .clone()
        .expect("a preview")
        .diff
        .remove(0);
    plan.proposals[0]
        .recipe
        .ops
        .retain(|op| op.argv().is_none());

    let mut options = ApplyOptions::new(false);
    options.husk_dir = dir.path().join(".husk");
    options.deps = true;
    apply(&plan, &options).unwrap();

    let written = std::fs::read_to_string(dir.path().join("package.json")).unwrap();
    // Byte for byte what `npm pkg set overrides.lodash=1.0.5` writes into the
    // same file, which is the command the preview offers beside this diff.
    assert_eq!(
        written,
        "{\n  \"name\": \"t\",\n  \"overrides\": {\n    \"lodash\": \"1.0.5\"\n  }\n}\n"
    );
    // The diff's own after-side reconstructs the file that was written, so the
    // preview cannot claim one thing and apply another.
    let after: Vec<&str> = previewed
        .diff
        .lines()
        .skip_while(|line| !line.starts_with("@@"))
        .filter(|line| !line.starts_with("@@") && !line.starts_with('-'))
        .map(|line| &line[1..])
        .collect();
    assert_eq!(written.trim_end().lines().collect::<Vec<_>>(), after);
}

#[test]
fn a_gitignore_fix_shows_the_one_line_it_adds_and_the_shell_line_that_adds_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();
    let recipe = op::Recipe::new(
        dir.path().to_path_buf(),
        Safety::SafeEdit,
        Explain::new("x"),
        op::Verify::UserConfirms,
    )
    .op(FixOp::AppendUniqueLine {
        path: dir.path().join(".gitignore"),
        line: ".env".to_string(),
        header: Some("# Added by `husk fix`".to_string()),
    });

    let preview = exec::preview(&recipe).expect("a preview");
    assert_eq!(preview.diff[0].added, 1);
    assert_eq!(preview.diff[0].removed, 0);
    assert_eq!(
        preview.command.as_deref(),
        Some(
            format!(
                "printf '.env\\n' >> {}",
                dir.path().join(".gitignore").display()
            )
            .as_str()
        )
    );
    assert!(preview.complete);
}

fn action(id: &str, status: ActionStatus, detail: &str) -> ActionResult {
    ActionResult {
        id: id.to_string(),
        status,
        detail: detail.to_string(),
        output: None,
    }
}

fn skips(count: usize) -> Vec<ActionResult> {
    (0..count)
        .map(|i| {
            action(
                &format!("skip-{i}"),
                ActionStatus::Skipped,
                "already at a safe version",
            )
        })
        .collect()
}

/// One click on sixteen proposals where only one of them changes anything must
/// report one fix, not sixteen: "already in place" is not a fix, and counting
/// it as one tells the user husk did work it did not do.
#[test]
fn skipped_proposals_are_neither_counted_nor_worded_as_applied() {
    let mut results = vec![action(
        "applied",
        ActionStatus::Applied,
        "updated left-pad to 1.3.0",
    )];
    results.extend(skips(15));

    let tally = ApplyTally::of(&results);
    assert_eq!(tally.applied, 1);
    assert_eq!(tally.skipped, 15);
    assert_eq!(tally.total(), 16);
    assert!(tally.ok(), "a skip is not a failure");

    let message = apply_summary(&results);
    assert!(message.starts_with("Applied 1 fix."), "{message}");
    assert!(message.contains("15 already in place"), "{message}");
    assert!(!message.contains("16"), "{message}");
}

/// A run that changed nothing has nothing to re-verify.
#[test]
fn a_run_that_only_skipped_claims_no_fixes() {
    let results = skips(4);

    let tally = ApplyTally::of(&results);
    assert_eq!(tally.applied, 0);
    assert_eq!(tally.skipped, 4);

    let message = apply_summary(&results);
    assert_eq!(message, "4 already in place.");
}

/// Blocked and failed are separate outcomes, and neither is success.
#[test]
fn unresolved_proposals_are_split_from_failures_and_reported() {
    let results = vec![
        action("applied", ActionStatus::Applied, "updated left-pad"),
        action("blocked", ActionStatus::NeedsUser, "npm is not on PATH"),
        action("failed", ActionStatus::Failed, "lockfile is read-only"),
    ];

    let tally = ApplyTally::of(&results);
    assert_eq!(tally.applied, 1);
    assert_eq!(tally.needs_user, 1);
    assert_eq!(tally.failed, 1);
    assert_eq!(tally.unresolved(), 2);
    assert!(!tally.ok());

    let message = apply_summary(&results);
    assert!(message.contains("Applied 1 fix"), "{message}");
    assert!(message.contains("2 could not run"), "{message}");
    assert!(message.contains("npm is not on PATH"), "{message}");
    assert!(!message.contains("Rescan"), "{message}");
}

/// A single proposal's own detail beats any count.
#[test]
fn a_single_result_reports_its_own_detail() {
    let applied = apply_summary(&[action(
        "one",
        ActionStatus::Applied,
        "added .env to .gitignore",
    )]);
    assert_eq!(applied, "added .env to .gitignore. Rescan to verify.");

    let failed = apply_summary(&[action("one", ActionStatus::Failed, "npm exited with 1")]);
    assert_eq!(failed, "npm exited with 1");

    // The result already asked for a rescan; asking twice in one sentence
    // reads as machine-generated.
    let verified = apply_summary(&[action(
        "one",
        ActionStatus::Applied,
        "wrote .env.template. re-scan to confirm `secrets-out-of-code`",
    )]);
    assert_eq!(
        verified,
        "wrote .env.template. re-scan to confirm `secrets-out-of-code`"
    );

    // Nothing changed, so there is nothing to rescan for.
    let skipped = apply_summary(&[action(
        "one",
        ActionStatus::Skipped,
        "already at a safe version",
    )]);
    assert_eq!(skipped, "already at a safe version");
}

#[test]
fn a_blocked_fix_is_not_ready() {
    // "N fixes ready" is a promise that one click runs them. A range conflict
    // needs a human edit first, so it stays visible and stays uncounted.
    let dir = tempfile::tempdir().unwrap();
    let mut plan = npm_project(dir.path(), "4.17.20", "4.17.21");
    normalize_proposals(&mut plan.proposals);
    assert!(plan.proposals.iter().all(|proposal| proposal.ready));

    for proposal in &mut plan.proposals {
        proposal.blockers.push(Blocker::RangeConflict {
            declared: "=4.17.20".to_string(),
            target: "4.17.21".to_string(),
        });
    }
    normalize_proposals(&mut plan.proposals);
    assert!(plan.proposals.iter().all(|proposal| !proposal.ready));
}

#[test]
fn one_package_pinned_from_two_manifests_is_one_fix() {
    // Go coordinates are read from go.mod and go.sum both, and one `go get`
    // settles either. Two rows would be one package advertised twice.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("go.mod"), "module t\n\ngo 1.24\n").unwrap();
    std::fs::write(dir.path().join("go.sum"), "").unwrap();

    let changes: Vec<(String, Change)> = ["go.mod", "go.sum"]
        .into_iter()
        .map(|manifest| {
            let mut change = Change::new(
                "golang.org/x/text",
                "v0.3.0",
                "v0.3.8",
                dir.path().join(manifest),
            );
            change.severity = Severity::High;
            change.finding_ids = vec![format!("finding:{manifest}")];
            ("go".to_string(), change)
        })
        .collect();

    let mut proposals = plan_changes(changes, &Toolbox::everything());
    assert_eq!(
        proposals.len(),
        2,
        "one proposal per manifest before merging"
    );
    normalize_proposals(&mut proposals);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].finding_ids.len(), 2);
}
