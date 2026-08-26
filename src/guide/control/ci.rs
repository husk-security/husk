//! CI/CD & release controls: GitHub Actions workflow hygiene, the publish
//! path, and the one machine-level probe (a CI runner registered on the
//! workstation).

use super::{
    ControlAssessment, ControlContext, ControlStatus, assessment, evidence, finding_evidence, home,
    matching_rules, project_roots, read_text, rule_control,
};
use std::path::PathBuf;

/// Workflow files under each project root's `.github/workflows`. A bounded
/// read of one named directory per root, never a tree walk.
fn workflow_files(ctx: &ControlContext<'_>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in project_roots(ctx) {
        let Ok(entries) = std::fs::read_dir(root.join(".github/workflows")) else {
            continue;
        };
        files.extend(
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| matches!(ext, "yml" | "yaml"))
                })
                .take(100),
        );
    }
    files.sort();
    files
}

fn workflows_present(ctx: &ControlContext<'_>) -> bool {
    !workflow_files(ctx).is_empty()
}

pub(super) fn injection(ctx: &ControlContext<'_>) -> ControlAssessment {
    rule_control(
        "workflow-injection",
        ctx.report,
        &[
            "gha-pull-request-target",
            "gha-event-injection",
            "gha-curl-shell",
        ],
        workflows_present(ctx),
    )
}

pub(super) fn permissions(ctx: &ControlContext<'_>) -> ControlAssessment {
    rule_control(
        "workflow-permissions",
        ctx.report,
        &["gha-write-all", "gha-missing-permissions"],
        workflows_present(ctx),
    )
}

pub(super) fn pin_actions(ctx: &ControlContext<'_>) -> ControlAssessment {
    rule_control(
        "pin-actions",
        ctx.report,
        &["gha-unpinned-action"],
        workflows_present(ctx),
    )
}

pub(super) fn checkout_credentials(ctx: &ControlContext<'_>) -> ControlAssessment {
    rule_control(
        "checkout-credentials",
        ctx.report,
        &["gha-persist-credentials"],
        workflows_present(ctx),
    )
}

pub(super) fn secret_scope(ctx: &ControlContext<'_>) -> ControlAssessment {
    rule_control(
        "workflow-secret-scope",
        ctx.report,
        &["gha-secrets-inherit"],
        workflows_present(ctx),
    )
}

pub(super) fn self_hosted(ctx: &ControlContext<'_>) -> ControlAssessment {
    rule_control(
        "self-hosted-runner-exposure",
        ctx.report,
        &["gha-self-hosted-fork"],
        workflows_present(ctx),
    )
}

/// A GitHub Actions runner registration directly under home. Supply-chain
/// worms hide runners in dotted directories such as `$HOME/.dev-env/`; the
/// stock install lands in `~/actions-runner/`. Reads only the top level of
/// home, never a walk.
pub(super) fn runner_on_workstation(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "ci-runner-on-workstation";
    let Some(home) = home(ctx) else {
        return assessment(
            ID,
            ControlStatus::Unknown,
            vec![evidence("The home directory could not be determined", None)],
            Vec::new(),
        );
    };
    let Ok(entries) = std::fs::read_dir(home) else {
        return assessment(
            ID,
            ControlStatus::Unknown,
            vec![evidence(
                "The home directory could not be read",
                Some(home.to_path_buf()),
            )],
            Vec::new(),
        );
    };
    let mut hits = Vec::new();
    for entry in entries.flatten().take(1024) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let runner = path.join(".runner");
        let credentials = path.join(".credentials");
        let registered = read_text(&runner)
            .is_some_and(|text| text.contains("agentName") || text.contains("serverUrl"))
            || read_text(&credentials)
                .is_some_and(|text| text.contains("clientId") || text.contains("scheme"))
            || (runner.is_file() && credentials.is_file());
        let name = entry.file_name().to_string_lossy().into_owned();
        if registered {
            hits.push(evidence(
                format!("{name} holds a GitHub Actions runner registration (.runner/.credentials)"),
                Some(path),
            ));
        } else if name == "actions-runner"
            && (path.join("config.sh").is_file() || path.join("run.cmd").is_file())
        {
            hits.push(evidence(
                "The GitHub Actions runner software is installed under home",
                Some(path),
            ));
        }
    }
    if hits.is_empty() {
        assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "No CI runner installation or registration under home",
                None,
            )],
            Vec::new(),
        )
    } else {
        assessment(ID, ControlStatus::Failed, hits, Vec::new())
    }
}

/// Substring lists mirror the `gha-publish-token` / `gha-cache-in-publish`
/// detection in `scan/checks/gh_workflow.rs` (private module, so restated).
fn is_publish_workflow(contents: &str) -> bool {
    [
        "npm publish",
        "pnpm publish",
        "yarn publish",
        "twine upload",
        "uv publish",
        "maturin publish",
        "cargo publish",
        "gh release create",
        "gh release upload",
    ]
    .iter()
    .any(|needle| contents.contains(needle))
}

fn has_provenance_step(contents: &str) -> bool {
    [
        "sigstore/",
        "cosign",
        "actions/attest-build-provenance",
        "--provenance",
        "slsa-github-generator",
    ]
    .iter()
    .any(|needle| contents.contains(needle))
}

/// The best available local proxy for release integrity: husk reads the
/// workflow that publishes; the registry's trusted-publisher registration and
/// 2FA state are server-side and stay out of the verdict.
pub(super) fn release_provenance(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "release-provenance";
    let findings = matching_rules(ctx.report, &["gha-publish-token", "gha-cache-in-publish"]);
    if !findings.is_empty() {
        return assessment(
            ID,
            ControlStatus::Failed,
            findings
                .iter()
                .map(|finding| finding_evidence(finding))
                .collect(),
            findings,
        );
    }
    let mut publish_files = Vec::new();
    for file in workflow_files(ctx) {
        let Some(text) = read_text(&file) else {
            continue;
        };
        if is_publish_workflow(&text) {
            publish_files.push((file, has_provenance_step(&text)));
        }
    }
    if publish_files.is_empty() {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence(
                "No workflow that publishes a package or release was found",
                None,
            )],
            Vec::new(),
        );
    }
    let unattested: Vec<&PathBuf> = publish_files
        .iter()
        .filter(|(_, attested)| !attested)
        .map(|(path, _)| path)
        .collect();
    if unattested.is_empty() {
        assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "Publishing workflows use OIDC-compatible credentials and carry a signing or provenance step",
                None,
            )],
            Vec::new(),
        )
    } else {
        assessment(
            ID,
            ControlStatus::Partial,
            unattested
                .into_iter()
                .map(|path| {
                    evidence(
                        "Publishing workflow has no signing or provenance step",
                        Some(path.clone()),
                    )
                })
                .collect(),
            Vec::new(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::report_with_home;
    use super::*;
    use crate::model::{Finding, ScanReport, Severity};
    use crate::rule::Category;
    use std::fs;

    fn finding(rule: &str) -> Finding {
        let mut finding = Finding::new(
            format!("{rule}:test"),
            rule,
            Severity::High,
            Category::LifecycleScript,
            "test",
            None,
            None,
            "",
            None,
            "",
        );
        finding.rule_id = Some(crate::rule::RuleId::owned(rule));
        finding
    }

    fn report_with_findings(rules: &[&str]) -> ScanReport {
        ScanReport::new(
            Vec::new(),
            Vec::new(),
            rules.iter().map(|rule| finding(rule)).collect(),
            Vec::new(),
        )
    }

    #[test]
    fn workflow_rule_controls_fail_on_findings_and_pass_on_clean_workflows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workflows = dir.path().join(".github/workflows");
        fs::create_dir_all(&workflows).expect("mkdir");
        fs::write(
            workflows.join("ci.yml"),
            "on: push\npermissions:\n  contents: read\n",
        )
        .expect("write");

        let mut report = report_with_home(dir.path());
        report.roots = vec![dir.path().to_path_buf()];
        let ctx = ControlContext { report: &report };
        for (control, id) in [
            (
                injection as fn(&ControlContext<'_>) -> ControlAssessment,
                "workflow-injection",
            ),
            (permissions, "workflow-permissions"),
            (pin_actions, "pin-actions"),
            (checkout_credentials, "checkout-credentials"),
            (secret_scope, "workflow-secret-scope"),
            (self_hosted, "self-hosted-runner-exposure"),
        ] {
            let result = control(&ctx);
            assert_eq!(result.control_id, id);
            assert_eq!(result.status, ControlStatus::Passed, "{id}");
        }

        let mut failing = report_with_findings(&["gha-event-injection"]);
        failing.roots = vec![dir.path().to_path_buf()];
        let ctx = ControlContext { report: &failing };
        assert_eq!(injection(&ctx).status, ControlStatus::Failed);
        assert_eq!(pin_actions(&ctx).status, ControlStatus::Passed);
    }

    #[test]
    fn workflow_controls_are_not_applicable_without_workflows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut report = report_with_home(dir.path());
        report.roots = vec![dir.path().to_path_buf()];
        let ctx = ControlContext { report: &report };
        assert_eq!(permissions(&ctx).status, ControlStatus::NotApplicable);
    }

    #[test]
    fn runner_on_workstation_flags_registrations_and_passes_clean_homes() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("projects")).expect("mkdir");
        let report = report_with_home(dir.path());
        let ctx = ControlContext { report: &report };
        assert_eq!(runner_on_workstation(&ctx).status, ControlStatus::Passed);

        let nest = dir.path().join(".dev-env");
        fs::create_dir_all(&nest).expect("mkdir");
        fs::write(
            nest.join(".runner"),
            r#"{"agentId":1,"agentName":"SHA1HULUD","serverUrl":"https://pipelines.actions.githubusercontent.com/x"}"#,
        )
        .expect("write");
        let result = runner_on_workstation(&ctx);
        assert_eq!(result.status, ControlStatus::Failed);
        assert!(result.evidence[0].summary.contains(".dev-env"));
    }

    #[test]
    fn runner_on_workstation_flags_installed_runner_software() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runner = dir.path().join("actions-runner");
        fs::create_dir_all(&runner).expect("mkdir");
        fs::write(runner.join("config.sh"), "#!/bin/bash\n").expect("write");
        let report = report_with_home(dir.path());
        let ctx = ControlContext { report: &report };
        assert_eq!(runner_on_workstation(&ctx).status, ControlStatus::Failed);
    }

    #[test]
    fn release_provenance_walks_the_status_ladder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workflows = dir.path().join(".github/workflows");
        fs::create_dir_all(&workflows).expect("mkdir");
        let mut report = report_with_home(dir.path());
        report.roots = vec![dir.path().to_path_buf()];

        // No publishing workflow at all.
        fs::write(workflows.join("ci.yml"), "on: push\njobs: {}\n").expect("write");
        let ctx = ControlContext { report: &report };
        assert_eq!(
            release_provenance(&ctx).status,
            ControlStatus::NotApplicable
        );

        // A publish workflow without any provenance step.
        fs::write(
            workflows.join("release.yml"),
            "on: push\npermissions:\n  id-token: write\njobs:\n  pub:\n    steps:\n      - run: npm publish\n",
        )
        .expect("write");
        let result = release_provenance(&ctx);
        assert_eq!(result.status, ControlStatus::Partial);
        assert!(
            result.evidence[0]
                .path
                .as_ref()
                .is_some_and(|p| p.ends_with("release.yml"))
        );

        // The same workflow with provenance attestation.
        fs::write(
            workflows.join("release.yml"),
            "on: push\npermissions:\n  id-token: write\njobs:\n  pub:\n    steps:\n      - run: npm publish --provenance\n",
        )
        .expect("write");
        assert_eq!(release_provenance(&ctx).status, ControlStatus::Passed);

        // A long-lived token finding beats everything.
        let mut failing = report_with_findings(&["gha-publish-token"]);
        failing.roots = vec![dir.path().to_path_buf()];
        let ctx = ControlContext { report: &failing };
        assert_eq!(release_provenance(&ctx).status, ControlStatus::Failed);
    }
}
