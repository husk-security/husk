//! Registered, read-only checks behind Markdown guide entries.
//!
//! One module per guide domain; this file owns the shared types, the probe
//! helpers every domain reuses, and THE registry. `build.rs` lifts the id out
//! of every registration line below to prove that every guide names a real
//! control and every control backs a guide.

mod agents;
mod ci;
mod deps;
mod editor;
mod env;
mod machine;
mod secrets;
mod source;

use crate::model::{Finding, ScanReport};
use crate::remediation::RemediationProposal;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlStatus {
    Passed,
    Failed,
    Partial,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Evidence {
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Where in `path` the observation sits. Several hits of one rule in a
    /// single file share a summary, so the line is all that separates them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ControlAssessment {
    pub control_id: String,
    pub status: ControlStatus,
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_ids: Vec<String>,
}

pub struct ControlContext<'a> {
    pub report: &'a ScanReport,
}

/// One guide control is two pure Rust functions: observe the current scan and
/// plan typed remediations. Only the remediation executor may write.
pub struct GuideControl {
    pub id: &'static str,
    pub check: fn(&ControlContext<'_>) -> ControlAssessment,
    pub plan: fn(&ControlContext<'_>, &ControlAssessment) -> Vec<RemediationProposal>,
}

/// Guides husk can actually observe. A guide with no entry here declares
/// `verification = "manual"` in its frontmatter instead: husk cannot see the
/// evidence at all (it lives in an online account or a vendor console), so the
/// user resolves it directly rather than being shown a status husk invented.
/// `build.rs` enforces that every guide is in exactly one of those two camps.
///
/// Order mirrors the guide's domain order, which is itself ordered by how many
/// catalogued real-world compromises each domain's controls would have stopped.
static REGISTRY: [GuideControl; 63] = [
    // Dependencies
    control("dependency-cooldown", deps::cooldown, no_fixes),
    control("install-scripts-disabled", deps::install_scripts, no_fixes),
    control("lifecycle-scripts", deps::lifecycle_scripts, no_fixes),
    control("lockfile-present", deps::lockfile_present, no_fixes),
    control("frozen-install", deps::frozen_install, no_fixes),
    control(
        "dependency-security",
        deps::dependency_security,
        deps::dependency_fixes,
    ),
    control("malicious-packages", deps::malicious_packages, no_fixes),
    control("registry-scoping", deps::registry_scoping, no_fixes),
    control("dependency-updates", deps::dependency_updates, no_fixes),
    // Secrets & credentials
    control(
        "secrets-out-of-code",
        secrets::secrets_out_of_code,
        secrets::secret_fixes,
    ),
    control("secrets-in-git-history", secrets::git_history, no_fixes),
    control("npm-token-at-rest", secrets::npm_token, no_fixes),
    control(
        "cloud-credentials-at-rest",
        secrets::cloud_credentials,
        no_fixes,
    ),
    control("publish-tokens-at-rest", secrets::publish_tokens, no_fixes),
    control(
        "git-credentials-plaintext",
        secrets::git_credentials,
        no_fixes,
    ),
    control("kubeconfig-embedded-keys", secrets::kubeconfig, no_fixes),
    control(
        "docker-credential-helper",
        secrets::docker_credentials,
        no_fixes,
    ),
    control(
        "credential-file-permissions",
        secrets::credential_permissions,
        no_fixes,
    ),
    control("secrets-in-shell-rc", secrets::shell_rc, no_fixes),
    control("precommit-secret-scan", secrets::precommit, no_fixes),
    // AI agents & MCP
    control("agent-permissions", agents::permissions, no_fixes),
    control("agent-approval-bypass", agents::approval_bypass, no_fixes),
    control("agent-hooks", agents::hooks, no_fixes),
    control("agent-deny-rules", agents::deny_rules, no_fixes),
    control("agent-pretooluse-guard", agents::pretooluse_guard, no_fixes),
    control(
        "agent-credentials-at-rest",
        agents::credentials_at_rest,
        no_fixes,
    ),
    control("agent-skills", agents::skills, no_fixes),
    control("mcp-safety", agents::mcp_safety, no_fixes),
    control("agent-version-pins", agents::version_pins, no_fixes),
    control("prompt-injection", agents::prompt_injection, no_fixes),
    // Editor & IDE
    control("editor-auto-run", editor::auto_run, no_fixes),
    control("workspace-trust", editor::workspace_trust, no_fixes),
    control("devcontainer-host-commands", editor::devcontainer, no_fixes),
    control("extension-risk", editor::extension_risk, no_fixes),
    // CI/CD & release
    control("workflow-injection", ci::injection, no_fixes),
    control("workflow-permissions", ci::permissions, no_fixes),
    control("pin-actions", ci::pin_actions, no_fixes),
    control("checkout-credentials", ci::checkout_credentials, no_fixes),
    control("workflow-secret-scope", ci::secret_scope, no_fixes),
    control("self-hosted-runner-exposure", ci::self_hosted, no_fixes),
    control(
        "ci-runner-on-workstation",
        ci::runner_on_workstation,
        no_fixes,
    ),
    control("release-provenance", ci::release_provenance, no_fixes),
    // Source control
    control("ssh-key-passphrase", source::ssh_passphrase, no_fixes),
    control("ssh-config-hardening", source::ssh_config, no_fixes),
    control("ssh-file-permissions", source::ssh_permissions, no_fixes),
    control("hardware-backed-ssh-key", source::hardware_key, no_fixes),
    control("git-hooks", source::git_hooks, no_fixes),
    control("git-template-hijack", source::template_hijack, no_fixes),
    control("git-config-execution", source::config_execution, no_fixes),
    control("git-integrity-config", source::integrity_config, no_fixes),
    control("signed-commits", source::signed_commits, no_fixes),
    control("git-client-version", source::client_version, no_fixes),
    control("project-policy", source::project_policy, no_fixes),
    // Local environment
    control("path-hygiene", env::path_hygiene, no_fixes),
    control("docker-socket-exposure", env::docker_socket, no_fixes),
    control("container-image-pinning", env::image_pinning, no_fixes),
    control("dockerignore-coverage", env::dockerignore, no_fixes),
    control("dev-server-binding", env::dev_server_binding, no_fixes),
    control("direnv-auto-exec", env::direnv_auto_exec, no_fixes),
    control(
        "interpreter-injection",
        env::interpreter_injection,
        no_fixes,
    ),
    control("cloud-synced-projects", env::cloud_synced, no_fixes),
    // Machine & identity
    control(
        "full-disk-encryption",
        machine::full_disk_encryption,
        no_fixes,
    ),
    control("sshd-exposure", machine::sshd_exposure, no_fixes),
];

pub fn registry() -> &'static [GuideControl] {
    &REGISTRY
}

const fn control(
    id: &'static str,
    check: fn(&ControlContext<'_>) -> ControlAssessment,
    plan: fn(&ControlContext<'_>, &ControlAssessment) -> Vec<RemediationProposal>,
) -> GuideControl {
    GuideControl { id, check, plan }
}

pub fn run(report: &ScanReport) -> (Vec<ControlAssessment>, Vec<RemediationProposal>) {
    let ctx = ControlContext { report };
    let mut assessments = Vec::new();
    let mut proposals = Vec::new();
    for control in registry() {
        let assessment = (control.check)(&ctx);
        debug_assert_eq!(assessment.control_id, control.id);
        proposals.extend((control.plan)(&ctx, &assessment));
        assessments.push(assessment);
    }
    crate::remediation::normalize_proposals(&mut proposals);
    (assessments, proposals)
}

// ---------------------------------------------------------------------------
// Shared probe helpers
// ---------------------------------------------------------------------------

/// Builds the assessment every control returns, dropping rows that repeat one
/// already in the list.
///
/// Two things make repeats routine rather than exceptional: several intel
/// sources can report the same advisory for the same coordinate, and a finding
/// id is not unique (an advisory id carries no path, a secret-scanner id no
/// line), so one id can stand for several findings. Retaining the first
/// occurrence keeps the incoming order, which is the report's own priority
/// order, so the surfaces stay stable between runs.
pub(super) fn assessment(
    id: &str,
    status: ControlStatus,
    mut evidence: Vec<Evidence>,
    findings: Vec<&Finding>,
) -> ControlAssessment {
    dedup_evidence(&mut evidence);
    let mut seen_ids = HashSet::new();
    ControlAssessment {
        control_id: id.to_string(),
        status,
        evidence,
        finding_ids: findings
            .into_iter()
            .map(|finding| finding.id.clone())
            .filter(|id| seen_ids.insert(id.clone()))
            .collect(),
    }
}

/// Drop rows that repeat one already in the list, keeping the first, and so the
/// incoming order. Used again when a scoped guide item rebuilds the evidence
/// for one slice of a control's findings.
pub(super) fn dedup_evidence(evidence: &mut Vec<Evidence>) {
    let mut seen = HashSet::new();
    evidence.retain(|item| seen.insert((item.summary.clone(), item.path.clone(), item.line)));
}

pub(super) fn evidence(summary: impl Into<String>, path: Option<PathBuf>) -> Evidence {
    Evidence {
        summary: summary.into(),
        path,
        line: None,
    }
}

/// The plain rendering of a finding as evidence, carrying the location that
/// separates two hits of the same rule in one file.
pub(super) fn finding_evidence(finding: &Finding) -> Evidence {
    Evidence {
        summary: finding.title.clone(),
        path: finding.path.clone(),
        line: finding.line,
    }
}

/// The honest answer for a home-relative probe when the report carries no home.
pub(super) fn no_home(id: &str) -> ControlAssessment {
    assessment(
        id,
        ControlStatus::Unknown,
        vec![evidence("The scanned home directory is unknown", None)],
        Vec::new(),
    )
}

pub(super) fn matching_rules<'a>(report: &'a ScanReport, rules: &[&str]) -> Vec<&'a Finding> {
    report
        .findings
        .iter()
        .filter(|finding| {
            finding
                .rule_id
                .as_ref()
                .is_some_and(|id| rules.contains(&id.as_str()))
        })
        .collect()
}

/// The common shape: fail on any finding from `rules`, otherwise pass when the
/// surface exists at all and report not-applicable when it does not.
pub(super) fn rule_control(
    id: &str,
    report: &ScanReport,
    rules: &[&str],
    applicable: bool,
) -> ControlAssessment {
    let findings = matching_rules(report, rules);
    if !findings.is_empty() {
        return assessment(
            id,
            ControlStatus::Failed,
            findings
                .iter()
                .map(|finding| finding_evidence(finding))
                .collect(),
            findings,
        );
    }
    assessment(
        id,
        if applicable {
            ControlStatus::Passed
        } else {
            ControlStatus::NotApplicable
        },
        vec![evidence(
            if applicable {
                "No matching problems were detected"
            } else {
                "No applicable local configuration was found"
            },
            None,
        )],
        Vec::new(),
    )
}

/// The scanned user's home. Read from the report rather than the process, so a
/// test can point every home-level probe at a fixture directory.
pub(super) fn home<'a>(ctx: &'a ControlContext<'_>) -> Option<&'a Path> {
    ctx.report.context.home_dir.as_deref()
}

/// Directories a repo-local probe should look in: discovered project roots,
/// falling back to the scan roots when project discovery found nothing.
pub(super) fn project_roots(ctx: &ControlContext<'_>) -> Vec<PathBuf> {
    if ctx.report.projects.is_empty() {
        return ctx.report.roots.clone();
    }
    ctx.report
        .projects
        .iter()
        .map(|project| project.root.clone())
        .collect()
}

/// Directories a dependency probe should look in: every project root plus every
/// directory the scan actually read a package manifest from.
///
/// A project root is routinely a workspace parent whose manifests all live one
/// or two levels down, so probing roots alone reports a machine full of
/// dependencies as having none. The scan already knows where they are.
pub(super) fn manifest_dirs(ctx: &ControlContext<'_>) -> Vec<PathBuf> {
    let roots = project_roots(ctx);
    let mut dirs: std::collections::BTreeSet<PathBuf> = roots.iter().cloned().collect();
    for package in &ctx.report.packages {
        let Some(dir) = package.manifest_path.parent() else {
            continue;
        };
        if roots.iter().any(|root| dir.starts_with(root)) {
            dirs.insert(dir.to_path_buf());
        }
    }
    dirs.into_iter().collect()
}

/// Read a config file, bounded. Guide probes only ever parse small
/// configuration; a multi-megabyte file at one of these paths is not one.
pub(super) fn read_text(path: &Path) -> Option<String> {
    const MAX: u64 = 512 * 1024;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

pub(super) fn git_output(args: &[&str]) -> Option<String> {
    let output = crate::gitcmd::git_command().args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// Unix permission bits, or `None` where the mode carries no information. A
/// probe that cannot read a meaningful mode reports `Unknown`, never `Passed`.
///
/// `None` covers two cases, and the second is the one that bites: a non-unix
/// platform, and a Windows drive mounted into WSL. DrvFs without the `metadata`
/// option synthesizes 0777 for every file, so `mode & 0o077` is set on a
/// correctly-locked-down credential file and clear on nothing at all. Answering
/// `Unknown` there is the honest result; reporting every file as world-readable
/// would train the user to ignore the control.
pub(super) fn file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if on_synthesized_mode_mount(path) {
            return None;
        }
        Some(std::fs::metadata(path).ok()?.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Whether `path` sits on a mount whose permission bits are synthesized rather
/// than stored. Today that is a Windows drive under WSL's default DrvFs mount.
#[cfg(unix)]
fn on_synthesized_mode_mount(path: &Path) -> bool {
    path.components()
        .map(|component| component.as_os_str())
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair[0] == "mnt" && pair[1].len() == 1)
        && std::path::Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
}

/// Nearest ancestor holding a `.git` entry, i.e. the repository `dir` belongs
/// to. Resolved by walking the path rather than shelling out to `rev-parse`:
/// one spawn per candidate directory dominated the probes that ask this for
/// many directories. `.git` is matched as either a directory or a file so
/// linked worktrees and submodules still resolve.
pub(super) fn git_root(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .find(|ancestor| ancestor.join(".git").exists())
        .map(Path::to_path_buf)
}

pub(super) fn tool_on_path(ctx: &ControlContext<'_>, tool: &str) -> bool {
    ctx.report
        .context
        .package_managers
        .iter()
        .any(|found| found == tool)
}

/// Shell startup files worth reading. They are plain text that both a developer
/// and an attacker write to, so several controls read the same list: exported
/// credentials, persisted permission-bypass flags, redirected registries.
pub(super) fn shell_rc_files(home: &Path) -> Vec<PathBuf> {
    let mut paths = [
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".config/fish/config.fish",
        ".config/fish/fish_variables",
    ]
    .iter()
    .map(|name| home.join(name))
    .filter(|path| path.is_file())
    .collect::<Vec<_>>();
    if let Ok(entries) = std::fs::read_dir(home.join(".config/fish/conf.d")) {
        paths.extend(
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "fish")),
        );
    }
    paths.sort();
    paths
}

pub(super) fn no_fixes(_: &ControlContext<'_>, _: &ControlAssessment) -> Vec<RemediationProposal> {
    Vec::new()
}

#[cfg(test)]
pub(super) fn report_with_home(home: &Path) -> ScanReport {
    let mut report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
    report.context.home_dir = Some(home.to_path_buf());
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(id: &str, title: &str, line: Option<usize>) -> Finding {
        Finding::from_rule("secret-exposed")
            .id(id)
            .title(title)
            .at(PathBuf::from("/repo/src/keys.rs"), line)
    }

    #[test]
    fn repeated_hits_in_one_file_stay_separate_and_identical_rows_collapse() {
        let mut report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let key = "secret:private-key:/repo/src/keys.rs";
        report.findings = vec![
            hit(key, "private key exposed", Some(12)),
            hit(key, "private key exposed", Some(40)),
            hit(key, "private key exposed", Some(12)),
            hit("other:private-key", "AWS access key exposed", Some(12)),
        ];

        let control = rule_control("secrets-out-of-code", &report, &["secret-exposed"], true);

        assert_eq!(control.status, ControlStatus::Failed);
        assert_eq!(control.evidence.len(), 3);
        assert_eq!(
            control
                .evidence
                .iter()
                .map(|item| (item.summary.as_str(), item.line))
                .collect::<Vec<_>>(),
            vec![
                ("private key exposed", Some(12)),
                ("private key exposed", Some(40)),
                ("AWS access key exposed", Some(12)),
            ]
        );
        assert_eq!(
            control.finding_ids,
            vec![key.to_string(), "other:private-key".to_string()]
        );
    }

    /// Two intel sources confirming one advisory for one coordinate is one
    /// problem for the user, not two.
    #[test]
    fn one_advisory_reported_by_two_sources_is_one_row() {
        let mut report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let title = "PYSEC-1 affects requests";
        report.findings = vec![
            hit("osv:PYSEC-1:pypi:requests@2.31.0", title, Some(3)),
            hit("pypi:PYSEC-1:pypi:requests@2.31.0", title, Some(3)),
        ];

        let control = rule_control("secrets-out-of-code", &report, &["secret-exposed"], true);

        assert_eq!(control.evidence.len(), 1);
        assert_eq!(control.finding_ids.len(), 2);
    }
}
