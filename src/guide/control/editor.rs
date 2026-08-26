//! Editor & IDE controls: auto-run tasks, Workspace Trust, dev-container host
//! commands, and extension risk.

use super::{
    ControlAssessment, ControlContext, ControlStatus, Evidence, assessment, evidence, home,
    project_roots, read_text, rule_control,
};
use serde_json::Value as JsonValue;
use std::path::{Path, PathBuf};

/// VS Code-family products whose user `settings.json` carries Workspace Trust
/// and automatic-task state.
const EDITOR_PRODUCTS: &[&str] = &["Code", "Cursor", "VSCodium", "Windsurf"];

/// Existing user `settings.json` files across the platform config locations.
/// All three layouts are probed unconditionally; the probes are cheap
/// existence checks and a home copied between platforms still resolves.
fn user_settings_files(ctx: &ControlContext<'_>) -> Vec<(&'static str, PathBuf)> {
    let Some(home) = home(ctx) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for product in EDITOR_PRODUCTS {
        for base in [
            home.join(".config").join(product),
            home.join("Library/Application Support").join(product),
            home.join("AppData/Roaming").join(product),
        ] {
            let path = base.join("User/settings.json");
            if path.is_file() {
                files.push((*product, path));
            }
        }
    }
    files
}

/// User settings.json allows comments and trailing commas, like every
/// VS Code-family JSON file; parse it as JSONC.
fn read_settings(path: &Path) -> Option<JsonValue> {
    crate::scan::checks::util::parse_jsonc(&read_text(path)?)
}

/// VS Code writes flat dotted keys, but a hand-edited file may nest them.
fn setting<'a>(json: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    if let Some(value) = json.get(key) {
        return Some(value);
    }
    let mut cursor = json;
    for segment in key.split('.') {
        cursor = cursor.get(segment)?;
    }
    Some(cursor)
}

pub(super) fn auto_run(ctx: &ControlContext<'_>) -> ControlAssessment {
    let applicable = project_roots(ctx)
        .iter()
        .any(|root| root.join(".vscode").is_dir());
    rule_control(
        "editor-auto-run",
        ctx.report,
        &["editor-auto-run-task"],
        applicable,
    )
}

pub(super) fn workspace_trust(ctx: &ControlContext<'_>) -> ControlAssessment {
    let files = user_settings_files(ctx);
    if files.is_empty() {
        return assessment(
            "workspace-trust",
            ControlStatus::NotApplicable,
            vec![evidence("No editor user settings file was found", None)],
            Vec::new(),
        );
    }
    let mut rows: Vec<Evidence> = Vec::new();
    let (mut ok, mut bad, mut unreadable) = (0usize, 0usize, 0usize);
    for (product, path) in files {
        let Some(json) = read_settings(&path) else {
            unreadable += 1;
            rows.push(evidence(
                format!("{product}: settings file could not be read or parsed"),
                Some(path),
            ));
            continue;
        };
        let trust_on = setting(&json, "security.workspace.trust.enabled")
            .and_then(JsonValue::as_bool)
            != Some(false);
        let tasks_off =
            setting(&json, "task.allowAutomaticTasks").and_then(JsonValue::as_str) == Some("off");
        if trust_on && tasks_off {
            ok += 1;
            rows.push(evidence(
                format!("{product}: Workspace Trust is on and automatic tasks are off"),
                Some(path),
            ));
        } else {
            bad += 1;
            let mut problems = Vec::new();
            if !trust_on {
                problems.push("Workspace Trust is disabled");
            }
            if !tasks_off {
                problems.push("task.allowAutomaticTasks is not \"off\"");
            }
            rows.push(evidence(
                format!("{product}: {}", problems.join("; ")),
                Some(path),
            ));
        }
    }
    let status = if bad == 0 && unreadable == 0 {
        ControlStatus::Passed
    } else if ok > 0 {
        ControlStatus::Partial
    } else if bad > 0 {
        ControlStatus::Failed
    } else {
        ControlStatus::Unknown
    };
    assessment("workspace-trust", status, rows, Vec::new())
}

/// Whether `root` carries a dev-container definition in any spec location:
/// `.devcontainer/devcontainer.json`, `.devcontainer/<dir>/devcontainer.json`,
/// or a top-level `devcontainer.json` / `.devcontainer.json`.
fn has_devcontainer(root: &Path) -> bool {
    if root.join(".devcontainer/devcontainer.json").is_file()
        || root.join(".devcontainer.json").is_file()
        || root.join("devcontainer.json").is_file()
    {
        return true;
    }
    let Ok(entries) = std::fs::read_dir(root.join(".devcontainer")) else {
        return false;
    };
    entries
        .filter_map(Result::ok)
        .take(64)
        .any(|entry| entry.path().join("devcontainer.json").is_file())
}

pub(super) fn devcontainer(ctx: &ControlContext<'_>) -> ControlAssessment {
    let applicable = project_roots(ctx).iter().any(|root| has_devcontainer(root));
    rule_control(
        "devcontainer-host-commands",
        ctx.report,
        &["devcontainer-host-command"],
        applicable,
    )
}

pub(super) fn extension_risk(ctx: &ControlContext<'_>) -> ControlAssessment {
    let applicable = ctx
        .report
        .context
        .dev_configs
        .iter()
        .any(|config| config.present && config.label.contains("extensions"))
        || project_roots(ctx)
            .iter()
            .any(|root| root.join(".vscode").is_dir());
    rule_control(
        "extension-risk",
        ctx.report,
        &[
            "extension-broad-activation",
            "extension-install-script",
            "editor-tooling-repoint",
        ],
        applicable,
    )
}

#[cfg(test)]
mod tests {
    use super::super::report_with_home;
    use super::*;
    use crate::model::Finding;

    fn write_code_settings(home: &Path, contents: &str) {
        let dir = home.join(".config/Code/User");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("settings.json"), contents).unwrap();
    }

    #[test]
    fn workspace_trust_passes_with_trust_on_and_automatic_tasks_off() {
        let dir = tempfile::tempdir().unwrap();
        write_code_settings(
            dir.path(),
            r#"{
                // trust left at its default (on), tasks explicitly off
                "task.allowAutomaticTasks": "off",
            }"#,
        );
        let report = report_with_home(dir.path());
        let out = workspace_trust(&ControlContext { report: &report });
        assert_eq!(out.status, ControlStatus::Passed);
    }

    #[test]
    fn workspace_trust_fails_when_trust_is_disabled_or_tasks_auto_run() {
        let dir = tempfile::tempdir().unwrap();
        write_code_settings(dir.path(), r#"{"security.workspace.trust.enabled": false}"#);
        let report = report_with_home(dir.path());
        let out = workspace_trust(&ControlContext { report: &report });
        assert_eq!(out.status, ControlStatus::Failed);
        assert!(
            out.evidence[0]
                .summary
                .contains("Workspace Trust is disabled")
        );

        let dir = tempfile::tempdir().unwrap();
        write_code_settings(dir.path(), "{}");
        let report = report_with_home(dir.path());
        let out = workspace_trust(&ControlContext { report: &report });
        assert_eq!(out.status, ControlStatus::Failed);
        assert!(out.evidence[0].summary.contains("allowAutomaticTasks"));
    }

    #[test]
    fn workspace_trust_is_partial_across_mixed_editors_and_na_without_settings() {
        let dir = tempfile::tempdir().unwrap();
        write_code_settings(dir.path(), r#"{"task.allowAutomaticTasks": "off"}"#);
        let cursor = dir.path().join(".config/Cursor/User");
        std::fs::create_dir_all(&cursor).unwrap();
        std::fs::write(cursor.join("settings.json"), "{}").unwrap();
        let report = report_with_home(dir.path());
        let out = workspace_trust(&ControlContext { report: &report });
        assert_eq!(out.status, ControlStatus::Partial);

        let empty = tempfile::tempdir().unwrap();
        let report = report_with_home(empty.path());
        let out = workspace_trust(&ControlContext { report: &report });
        assert_eq!(out.status, ControlStatus::NotApplicable);
    }

    #[test]
    fn auto_run_follows_findings_and_vscode_presence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".vscode")).unwrap();
        let mut report = crate::model::ScanReport::empty(vec![dir.path().to_path_buf()]);
        let ctx = ControlContext { report: &report };
        assert_eq!(auto_run(&ctx).status, ControlStatus::Passed);

        report
            .findings
            .push(Finding::from_rule("editor-auto-run-task"));
        let ctx = ControlContext { report: &report };
        assert_eq!(auto_run(&ctx).status, ControlStatus::Failed);

        let bare = tempfile::tempdir().unwrap();
        let report = crate::model::ScanReport::empty(vec![bare.path().to_path_buf()]);
        let ctx = ControlContext { report: &report };
        assert_eq!(auto_run(&ctx).status, ControlStatus::NotApplicable);
    }

    #[test]
    fn devcontainer_control_sees_every_spec_location() {
        for relative in [
            ".devcontainer/devcontainer.json",
            ".devcontainer/rust/devcontainer.json",
            "devcontainer.json",
            ".devcontainer.json",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "{}").unwrap();
            let report = crate::model::ScanReport::empty(vec![dir.path().to_path_buf()]);
            let ctx = ControlContext { report: &report };
            assert_eq!(
                devcontainer(&ctx).status,
                ControlStatus::Passed,
                "missed {relative}"
            );
        }
        let bare = tempfile::tempdir().unwrap();
        let report = crate::model::ScanReport::empty(vec![bare.path().to_path_buf()]);
        let ctx = ControlContext { report: &report };
        assert_eq!(devcontainer(&ctx).status, ControlStatus::NotApplicable);
    }

    #[test]
    fn devcontainer_control_fails_on_host_command_findings() {
        let dir = tempfile::tempdir().unwrap();
        let report = {
            let mut report = crate::model::ScanReport::empty(vec![dir.path().to_path_buf()]);
            report
                .findings
                .push(Finding::from_rule("devcontainer-host-command"));
            report
        };
        let ctx = ControlContext { report: &report };
        assert_eq!(devcontainer(&ctx).status, ControlStatus::Failed);
    }

    #[test]
    fn extension_risk_covers_the_repoint_rule_and_can_pass() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".vscode")).unwrap();
        let mut report = crate::model::ScanReport::empty(vec![dir.path().to_path_buf()]);
        let ctx = ControlContext { report: &report };
        assert_eq!(extension_risk(&ctx).status, ControlStatus::Passed);

        report
            .findings
            .push(Finding::from_rule("editor-tooling-repoint"));
        let ctx = ControlContext { report: &report };
        assert_eq!(extension_risk(&ctx).status, ControlStatus::Failed);

        let bare = tempfile::tempdir().unwrap();
        let report = crate::model::ScanReport::empty(vec![bare.path().to_path_buf()]);
        let ctx = ControlContext { report: &report };
        assert_eq!(extension_risk(&ctx).status, ControlStatus::NotApplicable);
    }
}
