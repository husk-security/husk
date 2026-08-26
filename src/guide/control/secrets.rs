//! Secrets & credentials: finding-backed checks plus at-rest probes over the
//! exact credential files infostealer campaigns harvest by name.

use super::{
    ControlAssessment, ControlContext, ControlStatus, Evidence, assessment, evidence, file_mode,
    git_output, git_root, home, matching_rules, no_home, project_roots, read_text, rule_control,
    shell_rc_files, tool_on_path,
};
use crate::remediation::RemediationProposal;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(super) fn secrets_out_of_code(ctx: &ControlContext<'_>) -> ControlAssessment {
    rule_control(
        "secrets-out-of-code",
        ctx.report,
        &["secret-exposed", "dotenv-untracked"],
        true,
    )
}

pub(super) fn secret_fixes(
    ctx: &ControlContext<'_>,
    _: &ControlAssessment,
) -> Vec<RemediationProposal> {
    crate::remediation::secret_proposals(ctx.report)
}

/// Whether any secret-bearing path was ever committed. Rotation is the real
/// fix; this control exists so the user knows whether history cleanup applies
/// at all.
pub(super) fn git_history(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "secrets-in-git-history";
    // Bounded: a huge repo or finding list must not slow the scan down.
    const MAX_PROBES: usize = 40;

    let findings = matching_rules(ctx.report, &["secret-exposed", "dotenv-untracked"]);
    let mut seen = BTreeSet::new();
    let mut candidates: Vec<PathBuf> = Vec::new();
    for finding in &findings {
        if let Some(path) = &finding.path
            && seen.insert(path.clone())
        {
            candidates.push(path.clone());
        }
    }
    // Top-level `.env*` files at each project root, including ones git ignores
    // today: being ignored now says nothing about whether they were committed
    // before the ignore rule existed.
    let mut env_files = Vec::new();
    for root in project_roots(ctx) {
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                let is_env = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".env"));
                if is_env && path.is_file() && seen.insert(path.clone()) {
                    env_files.push(path);
                }
            }
        }
    }
    env_files.sort();
    candidates.extend(env_files);

    if candidates.is_empty() {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence(
                "No secret findings or .env files exist to check against git history",
                None,
            )],
            Vec::new(),
        );
    }

    let total = candidates.len();
    candidates.truncate(MAX_PROBES);

    let mut roots: BTreeMap<PathBuf, Option<PathBuf>> = BTreeMap::new();
    let mut dirty: Vec<PathBuf> = Vec::new();
    for path in &candidates {
        let Some(parent) = path.parent() else {
            continue;
        };
        let root = roots
            .entry(parent.to_path_buf())
            .or_insert_with(|| git_root(parent))
            .clone();
        let Some(root) = root else { continue };
        let Ok(relative) = path.strip_prefix(&root) else {
            continue;
        };
        let root_arg = root.to_string_lossy();
        let rel_arg = relative.to_string_lossy();
        if git_output(&["-C", &root_arg, "log", "--oneline", "-1", "--", &rel_arg]).is_some() {
            dirty.push(path.clone());
        }
    }

    let mut rows: Vec<Evidence> = dirty
        .iter()
        .map(|path| {
            evidence(
                "This secret-bearing file was committed at least once; the value is recoverable from git history",
                Some(path.clone()),
            )
        })
        .collect();
    if total > MAX_PROBES {
        rows.push(evidence(
            format!(
                "Probed the first {MAX_PROBES} of {total} candidate paths to keep the scan fast"
            ),
            None,
        ));
    }
    if dirty.is_empty() {
        rows.push(evidence(
            format!(
                "None of the {} checked secret-bearing paths appear in git history",
                candidates.len()
            ),
            None,
        ));
        return assessment(ID, ControlStatus::Passed, rows, Vec::new());
    }
    let linked = findings
        .iter()
        .filter(|finding| {
            finding
                .path
                .as_ref()
                .is_some_and(|path| dirty.contains(path))
        })
        .copied()
        .collect();
    assessment(ID, ControlStatus::Failed, rows, linked)
}

/// Keys in an npmrc line that carry a literal credential. A `${NPM_TOKEN}`
/// style env reference is the safe form, not a finding.
fn npmrc_literal_keys(contents: &str) -> Vec<String> {
    let mut keys = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        let sensitive =
            key.ends_with("_authToken") || key.ends_with("_auth") || key.ends_with("_password");
        if sensitive && !value.is_empty() && !value.starts_with("${") {
            keys.push(key.to_string());
        }
    }
    keys
}

pub(super) fn npm_token(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "npm-token-at-rest";
    let mut bad: Vec<Evidence> = Vec::new();
    let mut any = false;
    if let Some(home_dir) = home(ctx) {
        let path = home_dir.join(".npmrc");
        if let Some(contents) = read_text(&path) {
            any = true;
            for key in npmrc_literal_keys(&contents) {
                bad.push(evidence(
                    format!("~/.npmrc stores a literal {key} value in plaintext"),
                    Some(path.clone()),
                ));
            }
        }
    }
    for root in project_roots(ctx) {
        let path = root.join(".npmrc");
        if let Some(contents) = read_text(&path) {
            any = true;
            for key in npmrc_literal_keys(&contents) {
                bad.push(evidence(
                    format!(
                        "Project-local .npmrc stores a literal {key} value; a project file is one git add from being committed"
                    ),
                    Some(path.clone()),
                ));
            }
        }
    }
    if !bad.is_empty() {
        return assessment(ID, ControlStatus::Failed, bad, Vec::new());
    }
    if any {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "npmrc files exist but hold no literal token (env references are fine)",
                None,
            )],
            Vec::new(),
        );
    }
    assessment(
        ID,
        ControlStatus::NotApplicable,
        vec![evidence("No .npmrc file was found", None)],
        Vec::new(),
    )
}

pub(super) fn cloud_credentials(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "cloud-credentials-at-rest";
    let Some(home_dir) = home(ctx) else {
        return no_home(ID);
    };
    let mut bad: Vec<Evidence> = Vec::new();
    let mut good: Vec<Evidence> = Vec::new();
    let mut any = false;

    let aws_credentials = home_dir.join(".aws/credentials");
    if let Some(contents) = read_text(&aws_credentials) {
        any = true;
        let has_static = contents.lines().any(|line| {
            let line = line.trim().to_ascii_lowercase();
            line.starts_with("aws_access_key_id") || line.starts_with("aws_secret_access_key")
        });
        if has_static {
            bad.push(evidence(
                "Static AWS access keys are stored in plaintext; they never expire",
                Some(aws_credentials),
            ));
        }
    }
    let aws_config = home_dir.join(".aws/config");
    if let Some(contents) = read_text(&aws_config) {
        any = true;
        let short_lived = ["sso_session", "sso_start_url", "credential_process"]
            .iter()
            .any(|key| contents.contains(key));
        if short_lived {
            good.push(evidence(
                "AWS config uses SSO or credential_process, so credentials are short-lived",
                Some(aws_config),
            ));
        }
    }
    let adc = home_dir.join(".config/gcloud/application_default_credentials.json");
    if let Some(contents) = read_text(&adc) {
        any = true;
        if contents.contains("\"refresh_token\"") || contents.contains("\"private_key\"") {
            bad.push(evidence(
                "gcloud application-default credentials hold a long-lived token or key in plaintext",
                Some(adc),
            ));
        } else {
            good.push(evidence(
                "gcloud application-default credentials contain no long-lived token",
                Some(adc),
            ));
        }
    }

    if !bad.is_empty() {
        return assessment(ID, ControlStatus::Failed, bad, Vec::new());
    }
    if any {
        if good.is_empty() {
            good.push(evidence(
                "Cloud CLI config exists without static keys on disk",
                None,
            ));
        }
        return assessment(ID, ControlStatus::Passed, good, Vec::new());
    }
    assessment(
        ID,
        ControlStatus::NotApplicable,
        vec![evidence("No AWS or gcloud configuration was found", None)],
        Vec::new(),
    )
}

/// Probes the publish-token files that exist rather than asserting the paths;
/// not every ecosystem documents its credential path.
fn publish_tokens_probe(home_dir: &Path, cargo_home: &Path) -> (Vec<Evidence>, bool) {
    let mut bad: Vec<Evidence> = Vec::new();
    let mut any = false;

    let pypirc = home_dir.join(".pypirc");
    if let Some(contents) = read_text(&pypirc) {
        any = true;
        for line in contents.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim().eq_ignore_ascii_case("password") && !value.trim().is_empty() {
                let kind = if value.trim().starts_with("pypi-") {
                    "a PyPI API token"
                } else {
                    "a password"
                };
                bad.push(evidence(
                    format!(".pypirc stores {kind} in plaintext"),
                    Some(pypirc.clone()),
                ));
                break;
            }
        }
    }

    for name in ["credentials.toml", "credentials"] {
        let path = cargo_home.join(name);
        if let Some(contents) = read_text(&path) {
            any = true;
            let has_token = contents.lines().any(|line| {
                let line = line.trim();
                line.starts_with("token") && line.contains('=')
            });
            if has_token {
                bad.push(evidence(
                    "Cargo registry token stored in plaintext; cargo:libsecret moves it to the OS keychain",
                    Some(path),
                ));
            }
            break;
        }
    }

    let gem = home_dir.join(".gem/credentials");
    if let Some(contents) = read_text(&gem) {
        any = true;
        let what = if contents.contains(":rubygems_api_key:") {
            "a RubyGems API key"
        } else {
            "credentials"
        };
        bad.push(evidence(
            format!(".gem/credentials stores {what} in plaintext"),
            Some(gem),
        ));
    }

    let gh_hosts = home_dir.join(".config/gh/hosts.yml");
    if let Some(contents) = read_text(&gh_hosts) {
        any = true;
        if contents.contains("oauth_token:") {
            bad.push(evidence(
                "GitHub CLI oauth_token stored in plaintext instead of the system keyring",
                Some(gh_hosts),
            ));
        }
    }

    (bad, any)
}

pub(super) fn publish_tokens(ctx: &ControlContext<'_>) -> ControlAssessment {
    let Some(home_dir) = home(ctx) else {
        return no_home("publish-tokens-at-rest");
    };
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir.join(".cargo"));
    publish_tokens_at(home_dir, &cargo_home)
}

fn publish_tokens_at(home_dir: &Path, cargo_home: &Path) -> ControlAssessment {
    const ID: &str = "publish-tokens-at-rest";
    let (bad, any) = publish_tokens_probe(home_dir, cargo_home);
    if !bad.is_empty() {
        return assessment(ID, ControlStatus::Failed, bad, Vec::new());
    }
    if any {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "Publish-token files exist but hold no plaintext token",
                None,
            )],
            Vec::new(),
        );
    }
    assessment(
        ID,
        ControlStatus::NotApplicable,
        vec![evidence(
            "No package-registry credential files were found",
            None,
        )],
        Vec::new(),
    )
}

fn git_credentials_probe(
    home_dir: Option<&Path>,
    helper: Option<&str>,
    xdg_credentials: Option<PathBuf>,
) -> ControlAssessment {
    const ID: &str = "git-credentials-plaintext";
    let mut bad: Vec<Evidence> = Vec::new();
    if let Some(helper) = helper {
        let is_store = helper.lines().any(|line| {
            let line = line.trim();
            line == "store" || line.starts_with("store ")
        });
        if is_store {
            bad.push(evidence(
                "credential.helper is set to store, which git documents as writing passwords unencrypted on disk",
                None,
            ));
        }
    }
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(home_dir) = home_dir {
        files.push(home_dir.join(".git-credentials"));
        files.push(home_dir.join(".config/git/credentials"));
    }
    if let Some(path) = xdg_credentials
        && !files.contains(&path)
    {
        files.push(path);
    }
    for path in files {
        if path.is_file() {
            bad.push(evidence(
                "Plaintext git credential store exists (one user:password line per host)",
                Some(path),
            ));
        }
    }
    if let Some(home_dir) = home_dir {
        let netrc = home_dir.join(".netrc");
        if let Some(contents) = read_text(&netrc)
            && contents.contains("password")
        {
            bad.push(evidence(
                ".netrc contains a plaintext password",
                Some(netrc),
            ));
        }
    }
    if bad.is_empty() {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "No plaintext git credential store was found",
                None,
            )],
            Vec::new(),
        );
    }
    assessment(ID, ControlStatus::Failed, bad, Vec::new())
}

pub(super) fn git_credentials(ctx: &ControlContext<'_>) -> ControlAssessment {
    let helper = git_output(&["config", "--get-all", "credential.helper"]);
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .map(|value| PathBuf::from(value).join("git").join("credentials"));
    git_credentials_probe(home(ctx), helper.as_deref(), xdg)
}

/// A cheap bounded line scan; kubeconfig keys are unique enough that full YAML
/// parsing buys nothing here.
fn kubeconfig_probe(paths: &[PathBuf]) -> ControlAssessment {
    const ID: &str = "kubeconfig-embedded-keys";
    let mut bad: Vec<Evidence> = Vec::new();
    let mut read_any = false;
    let mut exec_seen = false;
    let mut seen = BTreeSet::new();
    for path in paths {
        if !seen.insert(path.clone()) {
            continue;
        }
        let Some(contents) = read_text(path) else {
            continue;
        };
        read_any = true;
        let (mut key, mut cert, mut token) = (false, false, false);
        for line in contents.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("client-key-data:") {
                key |= !value.trim().is_empty();
            } else if let Some(value) = line.strip_prefix("client-certificate-data:") {
                cert |= !value.trim().is_empty();
            } else if let Some(value) = line.strip_prefix("token:") {
                token |= !value.trim().is_empty();
            } else if line == "exec:" {
                exec_seen = true;
            }
        }
        if key {
            bad.push(evidence(
                "client-key-data embeds a base64 private key in the kubeconfig",
                Some(path.clone()),
            ));
        }
        if cert {
            bad.push(evidence(
                "client-certificate-data embeds a client certificate in the kubeconfig",
                Some(path.clone()),
            ));
        }
        if token {
            bad.push(evidence(
                "A static bearer token is embedded in the kubeconfig",
                Some(path.clone()),
            ));
        }
    }
    if !bad.is_empty() {
        return assessment(ID, ControlStatus::Failed, bad, Vec::new());
    }
    if read_any {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                if exec_seen {
                    "kubeconfig users authenticate via an exec credential plugin"
                } else {
                    "No embedded keys or static tokens were found in kubeconfig files"
                },
                None,
            )],
            Vec::new(),
        );
    }
    assessment(
        ID,
        ControlStatus::NotApplicable,
        vec![evidence("No kubeconfig was found", None)],
        Vec::new(),
    )
}

/// `$KUBECONFIG` is a delimited list that kubectl merges, and when it is set
/// the default `~/.kube/config` is not consulted at all. Reading the default
/// path as well would report on a file kubectl is ignoring, and reading only it
/// would miss every file an `exec` credential plugin could hide in.
pub(super) fn kubeconfig(ctx: &ControlContext<'_>) -> ControlAssessment {
    let configured = std::env::var_os("KUBECONFIG")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .filter(|paths| !paths.is_empty());
    let paths = configured.unwrap_or_else(|| {
        home(ctx)
            .map(|home_dir| vec![home_dir.join(".kube/config")])
            .unwrap_or_default()
    });
    kubeconfig_probe(&paths)
}

pub(super) fn docker_credentials(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "docker-credential-helper";
    let Some(home_dir) = home(ctx) else {
        return no_home(ID);
    };
    let path = home_dir.join(".docker/config.json");
    let Some(contents) = read_text(&path) else {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence("No Docker client config was found", None)],
            Vec::new(),
        );
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return assessment(
            ID,
            ControlStatus::Unknown,
            vec![evidence(
                "Docker config.json could not be parsed",
                Some(path),
            )],
            Vec::new(),
        );
    };
    let has_store = json
        .get("credsStore")
        .and_then(|value| value.as_str())
        .is_some_and(|store| !store.is_empty());
    let has_helpers = json
        .get("credHelpers")
        .and_then(|value| value.as_object())
        .is_some_and(|map| !map.is_empty());
    let plaintext_registries: Vec<String> = json
        .get("auths")
        .and_then(|value| value.as_object())
        .map(|auths| {
            auths
                .iter()
                .filter(|(_, entry)| {
                    entry
                        .get("auth")
                        .and_then(|auth| auth.as_str())
                        .is_some_and(|auth| !auth.is_empty())
                })
                .map(|(registry, _)| registry.clone())
                .collect()
        })
        .unwrap_or_default();

    if !plaintext_registries.is_empty() && !has_store && !has_helpers {
        let rows = plaintext_registries
            .iter()
            .map(|registry| {
                evidence(
                    format!(
                        "Login for {registry} is stored base64-encoded in config.json; it decodes straight to user:password"
                    ),
                    Some(path.clone()),
                )
            })
            .collect();
        return assessment(ID, ControlStatus::Failed, rows, Vec::new());
    }
    if !plaintext_registries.is_empty() {
        return assessment(
            ID,
            ControlStatus::Partial,
            vec![evidence(
                format!(
                    "A credential helper is configured, but plaintext auth entries remain for: {}",
                    plaintext_registries.join(", ")
                ),
                Some(path),
            )],
            Vec::new(),
        );
    }
    assessment(
        ID,
        ControlStatus::Passed,
        vec![evidence(
            if has_store || has_helpers {
                "Docker registry logins go through a credential helper"
            } else {
                "No registry logins are stored in config.json"
            },
            Some(path),
        )],
        Vec::new(),
    )
}

pub(super) fn credential_permissions(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "credential-file-permissions";
    let Some(home_dir) = home(ctx) else {
        return no_home(ID);
    };
    let mut paths: Vec<PathBuf> = [
        ".aws/credentials",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".gem/credentials",
        ".git-credentials",
        ".docker/config.json",
        ".kube/config",
        ".cargo/credentials.toml",
        ".claude/.credentials.json",
        ".claude.json",
        ".codex/auth.json",
        ".gemini/oauth_creds.json",
    ]
    .iter()
    .map(|name| home_dir.join(name))
    .collect();
    for root in project_roots(ctx) {
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                let is_env = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".env"));
                if is_env {
                    paths.push(path);
                }
            }
        }
    }

    let mut bad: Vec<Evidence> = Vec::new();
    let mut existing = 0usize;
    let mut mode_unreadable = false;
    for path in paths {
        if !path.is_file() {
            continue;
        }
        existing += 1;
        match file_mode(&path) {
            None => mode_unreadable = true,
            Some(mode) if mode & 0o077 != 0 => bad.push(evidence(
                format!("Mode {mode:03o} lets group or other users read this credential file"),
                Some(path),
            )),
            Some(_) => {}
        }
    }
    if existing == 0 {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence("No credential files were found to check", None)],
            Vec::new(),
        );
    }
    if mode_unreadable {
        return assessment(
            ID,
            ControlStatus::Unknown,
            vec![evidence(
                "File permission bits are not readable on this platform",
                None,
            )],
            Vec::new(),
        );
    }
    if !bad.is_empty() {
        return assessment(ID, ControlStatus::Failed, bad, Vec::new());
    }
    assessment(
        ID,
        ControlStatus::Passed,
        vec![evidence(
            format!("{existing} credential files are readable only by you (mode 600 or tighter)"),
            None,
        )],
        Vec::new(),
    )
}

/// Reads at most the last `max` bytes, dropping a leading partial line after a
/// mid-file seek.
fn read_tail(path: &Path, max: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let truncated = len > max;
    if truncated {
        file.seek(SeekFrom::End(-i64::try_from(max).ok()?)).ok()?;
    }
    let mut buf = Vec::new();
    file.take(max).read_to_end(&mut buf).ok()?;
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if truncated && let Some(pos) = text.find('\n') {
        text = text.split_off(pos + 1);
    }
    Some(text)
}

/// Runs husk's own secret detectors over the file, keeping only
/// `secret-exposed` hits, deduplicated per (pattern, file).
fn secret_hits(
    path: &Path,
    contents: &str,
    where_found: &str,
    seen: &mut BTreeSet<(String, PathBuf)>,
    out: &mut Vec<Evidence>,
) {
    let mut findings = Vec::new();
    crate::scan::checks::run_per_file(path, contents, &mut findings);
    for finding in findings {
        let is_secret = finding
            .rule_id
            .as_ref()
            .is_some_and(|rule| rule.as_str() == "secret-exposed");
        if is_secret && seen.insert((finding.title.clone(), path.to_path_buf())) {
            out.push(evidence(
                format!("{} in {where_found}", finding.title),
                Some(path.to_path_buf()),
            ));
        }
    }
}

fn shell_rc_probe(ctx: &ControlContext<'_>, histfile: Option<PathBuf>) -> ControlAssessment {
    const ID: &str = "secrets-in-shell-rc";
    const HISTORY_TAIL: u64 = 256 * 1024;
    let Some(home_dir) = home(ctx) else {
        return no_home(ID);
    };
    let mut bad: Vec<Evidence> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut scanned = 0usize;
    for path in shell_rc_files(home_dir) {
        let Some(contents) = read_text(&path) else {
            continue;
        };
        scanned += 1;
        secret_hits(
            &path,
            &contents,
            "a shell startup file",
            &mut seen,
            &mut bad,
        );
    }
    let mut histories = vec![
        home_dir.join(".bash_history"),
        home_dir.join(".local/share/fish/fish_history"),
    ];
    if let Some(path) = histfile
        && !histories.contains(&path)
    {
        histories.push(path);
    }
    for path in histories {
        let Some(contents) = read_tail(&path, HISTORY_TAIL) else {
            continue;
        };
        scanned += 1;
        secret_hits(&path, &contents, "shell history", &mut seen, &mut bad);
    }
    if !bad.is_empty() {
        return assessment(ID, ControlStatus::Failed, bad, Vec::new());
    }
    if scanned > 0 {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                format!("No secret patterns found in {scanned} shell startup and history files"),
                None,
            )],
            Vec::new(),
        );
    }
    assessment(
        ID,
        ControlStatus::NotApplicable,
        vec![evidence(
            "No shell startup or history files were found",
            None,
        )],
        Vec::new(),
    )
}

pub(super) fn shell_rc(ctx: &ControlContext<'_>) -> ControlAssessment {
    shell_rc_probe(ctx, std::env::var_os("HISTFILE").map(PathBuf::from))
}

fn git_config_at(dir: &Path, key: &str) -> Option<String> {
    git_output(&["-C", &dir.to_string_lossy(), "config", "--get", key])
}

/// A scanner binary on PATH proves nothing about commits; the check is whether
/// a secret-scanning hook is declared AND actually installed into git.
pub(super) fn precommit(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "precommit-secret-scan";
    const SCANNERS: [&str; 4] = ["gitleaks", "trufflehog", "detect-secrets", "husk"];
    let runs_scanner = |contents: &str| SCANNERS.iter().any(|scanner| contents.contains(scanner));

    let mut wired: Vec<Evidence> = Vec::new();
    let mut partial: Vec<Evidence> = Vec::new();
    let mut any_repo = false;
    for root in project_roots(ctx) {
        if !root.join(".git").exists() {
            continue;
        }
        any_repo = true;

        let config = root.join(".pre-commit-config.yaml");
        let declared = read_text(&config).is_some_and(|contents| runs_scanner(&contents));

        let mut hook_files = vec![
            root.join(".git/hooks/pre-commit"),
            root.join(".husky/pre-commit"),
        ];
        if let Some(hooks_path) = git_config_at(&root, "core.hooksPath") {
            let dir = PathBuf::from(&hooks_path);
            let dir = if dir.is_absolute() {
                dir
            } else {
                root.join(dir)
            };
            hook_files.push(dir.join("pre-commit"));
        }
        let mut hook_installed = false;
        let mut hook_runs_scanner = false;
        for hook in &hook_files {
            if let Some(contents) = read_text(hook) {
                hook_installed = true;
                hook_runs_scanner |= runs_scanner(&contents);
            }
        }

        if (declared && hook_installed) || hook_runs_scanner {
            wired.push(evidence(
                "A secret-scanning pre-commit hook is declared and installed",
                Some(root),
            ));
        } else if declared {
            partial.push(evidence(
                ".pre-commit-config.yaml declares a secret scanner, but no hook is installed (run pre-commit install)",
                Some(config),
            ));
        } else if hook_installed {
            partial.push(evidence(
                "A pre-commit hook is installed, but it does not run a secret scanner",
                Some(root),
            ));
        }
    }

    let on_path = ["gitleaks", "pre-commit"]
        .iter()
        .find(|tool| tool_on_path(ctx, tool))
        .copied();
    if !wired.is_empty() {
        return assessment(ID, ControlStatus::Passed, wired, Vec::new());
    }
    if !partial.is_empty() {
        return assessment(ID, ControlStatus::Partial, partial, Vec::new());
    }
    if let Some(tool) = on_path {
        return assessment(
            ID,
            if any_repo {
                ControlStatus::Partial
            } else {
                ControlStatus::Unknown
            },
            vec![evidence(
                format!(
                    "{tool} is on PATH, but no repository has a secret-scanning hook installed"
                ),
                None,
            )],
            Vec::new(),
        );
    }
    if any_repo {
        return assessment(
            ID,
            ControlStatus::Failed,
            vec![evidence(
                "No secret-scanning pre-commit hook was found in any repository",
                None,
            )],
            Vec::new(),
        );
    }
    assessment(
        ID,
        ControlStatus::NotApplicable,
        vec![evidence("No git repositories were found to check", None)],
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::super::report_with_home;
    use super::*;
    use crate::model::{Finding, ScanReport};

    fn ctx_report(report: &ScanReport) -> ControlContext<'_> {
        ControlContext { report }
    }

    fn secret_finding(path: &Path) -> Finding {
        Finding::from_rule("secret-exposed")
            .id(format!("secret:test:{}", path.display()))
            .at(path.to_path_buf(), Some(1))
    }

    #[test]
    fn secrets_out_of_code_fails_on_secret_findings_and_passes_clean() {
        let dir = tempfile::tempdir().unwrap();
        let mut report = report_with_home(dir.path());
        assert_eq!(
            secrets_out_of_code(&ctx_report(&report)).status,
            ControlStatus::Passed
        );
        report
            .findings
            .push(secret_finding(&dir.path().join("app/config.js")));
        assert_eq!(
            secrets_out_of_code(&ctx_report(&report)).status,
            ControlStatus::Failed
        );
    }

    #[test]
    fn git_history_flags_a_dotenv_that_was_ever_committed() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let git = |args: &[&str]| {
            let ok = crate::gitcmd::git_command()
                .args(["-C", &repo.to_string_lossy()])
                .args(args)
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false);
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "--quiet"]);
        git(&["config", "user.email", "test@example.com"]);
        git(&["config", "user.name", "test"]);
        std::fs::write(repo.join(".env"), "API_KEY=value\n").unwrap();
        git(&["add", ".env"]);
        git(&["commit", "--quiet", "-m", "add env"]);
        // Ignored now, but the value is already in history.
        std::fs::write(repo.join(".gitignore"), ".env\n").unwrap();

        let mut report = report_with_home(dir.path());
        report.roots = vec![repo.clone()];
        let dirty = git_history(&ctx_report(&report));
        assert_eq!(dirty.status, ControlStatus::Failed);
        assert!(
            dirty
                .evidence
                .iter()
                .any(|row| row.path.as_deref() == Some(repo.join(".env").as_path()))
        );

        // A repo whose .env was never committed has clean history.
        let clean_repo = dir.path().join("clean");
        std::fs::create_dir_all(&clean_repo).unwrap();
        let git_clean = |args: &[&str]| {
            assert!(
                crate::gitcmd::git_command()
                    .args(["-C", &clean_repo.to_string_lossy()])
                    .args(args)
                    .output()
                    .map(|out| out.status.success())
                    .unwrap_or(false)
            );
        };
        git_clean(&["init", "--quiet"]);
        std::fs::write(clean_repo.join(".env"), "API_KEY=value\n").unwrap();
        let mut clean_report = report_with_home(dir.path());
        clean_report.roots = vec![clean_repo];
        assert_eq!(
            git_history(&ctx_report(&clean_report)).status,
            ControlStatus::Passed
        );
    }

    #[test]
    fn npm_token_flags_literal_tokens_but_not_env_references() {
        let dir = tempfile::tempdir().unwrap();
        let npmrc = dir.path().join(".npmrc");
        std::fs::write(
            &npmrc,
            "//registry.npmjs.org/:_authToken=npm_abc123def456\n",
        )
        .unwrap();
        let report = report_with_home(dir.path());
        assert_eq!(
            npm_token(&ctx_report(&report)).status,
            ControlStatus::Failed
        );

        std::fs::write(&npmrc, "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n").unwrap();
        assert_eq!(
            npm_token(&ctx_report(&report)).status,
            ControlStatus::Passed
        );

        std::fs::remove_file(&npmrc).unwrap();
        assert_eq!(
            npm_token(&ctx_report(&report)).status,
            ControlStatus::NotApplicable
        );
    }

    #[test]
    fn cloud_credentials_distinguishes_static_keys_from_sso() {
        let dir = tempfile::tempdir().unwrap();
        let aws = dir.path().join(".aws");
        std::fs::create_dir_all(&aws).unwrap();
        std::fs::write(
            aws.join("credentials"),
            "[default]\naws_access_key_id = AKIA000\naws_secret_access_key = x\n",
        )
        .unwrap();
        let report = report_with_home(dir.path());
        assert_eq!(
            cloud_credentials(&ctx_report(&report)).status,
            ControlStatus::Failed
        );

        std::fs::remove_file(aws.join("credentials")).unwrap();
        std::fs::write(
            aws.join("config"),
            "[profile dev]\nsso_session = my-sso\nsso_account_id = 1\n",
        )
        .unwrap();
        assert_eq!(
            cloud_credentials(&ctx_report(&report)).status,
            ControlStatus::Passed
        );

        std::fs::remove_file(aws.join("config")).unwrap();
        assert_eq!(
            cloud_credentials(&ctx_report(&report)).status,
            ControlStatus::NotApplicable
        );
    }

    #[test]
    fn publish_tokens_reports_only_what_exists() {
        let dir = tempfile::tempdir().unwrap();
        let cargo_home = dir.path().join(".cargo");
        assert_eq!(
            publish_tokens_at(dir.path(), &cargo_home).status,
            ControlStatus::NotApplicable
        );

        // A gh hosts file without an oauth_token is a clean, present surface.
        let gh = dir.path().join(".config/gh");
        std::fs::create_dir_all(&gh).unwrap();
        std::fs::write(gh.join("hosts.yml"), "github.com:\n    user: someone\n").unwrap();
        assert_eq!(
            publish_tokens_at(dir.path(), &cargo_home).status,
            ControlStatus::Passed
        );

        std::fs::write(
            dir.path().join(".pypirc"),
            "[pypi]\npassword = pypi-AgEIcHlwaS5vcmc\n",
        )
        .unwrap();
        std::fs::create_dir_all(&cargo_home).unwrap();
        std::fs::write(
            cargo_home.join("credentials.toml"),
            "[registry]\ntoken = \"cio_abc\"\n",
        )
        .unwrap();
        let failed = publish_tokens_at(dir.path(), &cargo_home);
        assert_eq!(failed.status, ControlStatus::Failed);
        assert_eq!(
            failed.evidence.len(),
            2,
            "pypirc token and cargo token: {:?}",
            failed.evidence
        );
    }

    #[test]
    fn git_credentials_probe_flags_store_helper_and_credential_files() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            git_credentials_probe(Some(dir.path()), None, None).status,
            ControlStatus::Passed
        );
        assert_eq!(
            git_credentials_probe(Some(dir.path()), Some("store"), None).status,
            ControlStatus::Failed
        );
        std::fs::write(
            dir.path().join(".git-credentials"),
            "https://user:pass@github.com\n",
        )
        .unwrap();
        assert_eq!(
            git_credentials_probe(Some(dir.path()), None, None).status,
            ControlStatus::Failed
        );
    }

    #[test]
    fn kubeconfig_probe_fails_on_embedded_material_and_passes_exec() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(
            &config,
            "users:\n- name: dev\n  user:\n    client-key-data: LS0tLS1CRUdJTg==\n",
        )
        .unwrap();
        assert_eq!(
            kubeconfig_probe(std::slice::from_ref(&config)).status,
            ControlStatus::Failed
        );

        std::fs::write(
            &config,
            "users:\n- name: dev\n  user:\n    exec:\n      command: aws\n",
        )
        .unwrap();
        assert_eq!(
            kubeconfig_probe(std::slice::from_ref(&config)).status,
            ControlStatus::Passed
        );

        assert_eq!(
            kubeconfig_probe(&[dir.path().join("missing")]).status,
            ControlStatus::NotApplicable
        );
    }

    #[test]
    fn docker_credentials_requires_a_helper_when_auths_hold_values() {
        let dir = tempfile::tempdir().unwrap();
        let docker = dir.path().join(".docker");
        std::fs::create_dir_all(&docker).unwrap();
        let report = report_with_home(dir.path());

        std::fs::write(
            docker.join("config.json"),
            r#"{"auths":{"ghcr.io":{"auth":"dXNlcjpwYXNz"}}}"#,
        )
        .unwrap();
        assert_eq!(
            docker_credentials(&ctx_report(&report)).status,
            ControlStatus::Failed
        );

        std::fs::write(
            docker.join("config.json"),
            r#"{"auths":{},"credsStore":"secretservice"}"#,
        )
        .unwrap();
        assert_eq!(
            docker_credentials(&ctx_report(&report)).status,
            ControlStatus::Passed
        );
    }

    #[cfg(unix)]
    #[test]
    fn credential_permissions_flags_group_readable_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let npmrc = dir.path().join(".npmrc");
        std::fs::write(&npmrc, "registry=https://registry.npmjs.org/\n").unwrap();
        std::fs::set_permissions(&npmrc, std::fs::Permissions::from_mode(0o644)).unwrap();
        let report = report_with_home(dir.path());
        assert_eq!(
            credential_permissions(&ctx_report(&report)).status,
            ControlStatus::Failed
        );

        std::fs::set_permissions(&npmrc, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            credential_permissions(&ctx_report(&report)).status,
            ControlStatus::Passed
        );
    }

    #[test]
    fn shell_rc_probe_runs_the_secret_detectors_over_rc_and_history_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".bashrc"),
            "export AWS_KEY=AKIAQ7ZP3EXAMPLE9K2M\n",
        )
        .unwrap();
        let report = report_with_home(dir.path());
        let failed = shell_rc_probe(&ctx_report(&report), None);
        assert_eq!(failed.status, ControlStatus::Failed);

        std::fs::write(dir.path().join(".bashrc"), "alias ll='ls -l'\n").unwrap();
        assert_eq!(
            shell_rc_probe(&ctx_report(&report), None).status,
            ControlStatus::Passed
        );

        std::fs::write(
            dir.path().join(".bash_history"),
            "curl -H 'x: AKIAQ7ZP3EXAMPLE9K2M'\n",
        )
        .unwrap();
        assert_eq!(
            shell_rc_probe(&ctx_report(&report), None).status,
            ControlStatus::Failed
        );
    }

    #[test]
    fn precommit_requires_an_installed_hook_not_just_a_binary_on_path() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git/hooks")).unwrap();
        let mut report = report_with_home(dir.path());
        report.roots = vec![repo.clone()];
        assert_eq!(
            precommit(&ctx_report(&report)).status,
            ControlStatus::Failed,
            "a bare repo has no hook"
        );

        report.context.package_managers = vec!["gitleaks".to_string()];
        assert_eq!(
            precommit(&ctx_report(&report)).status,
            ControlStatus::Partial,
            "a binary on PATH is not an installed hook"
        );

        std::fs::write(
            repo.join(".pre-commit-config.yaml"),
            "repos:\n  - repo: https://github.com/gitleaks/gitleaks\n    hooks:\n      - id: gitleaks\n",
        )
        .unwrap();
        assert_eq!(
            precommit(&ctx_report(&report)).status,
            ControlStatus::Partial,
            "declared but not installed"
        );

        std::fs::write(
            repo.join(".git/hooks/pre-commit"),
            "#!/bin/sh\nexec pre-commit run --hook-stage pre-commit\n",
        )
        .unwrap();
        assert_eq!(
            precommit(&ctx_report(&report)).status,
            ControlStatus::Passed,
            "declared and installed"
        );

        // A husky hook that itself runs a scanner passes without the framework.
        let husky = dir.path().join("husky-repo");
        std::fs::create_dir_all(husky.join(".git")).unwrap();
        std::fs::create_dir_all(husky.join(".husky")).unwrap();
        std::fs::write(
            husky.join(".husky/pre-commit"),
            "gitleaks protect --staged\n",
        )
        .unwrap();
        let mut husky_report = report_with_home(dir.path());
        husky_report.roots = vec![husky];
        assert_eq!(
            precommit(&ctx_report(&husky_report)).status,
            ControlStatus::Passed
        );
    }
}
