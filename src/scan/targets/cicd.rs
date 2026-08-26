//! CI/CD supply chain. GitHub Actions `uses:` references in workflow and
//! composite-action files → OSV ecosystem `GitHub Actions` (keyed on
//! `owner/repo`). Pairs with the existing workflow misconfig SAST in
//! `scan/local.rs`, which stays responsible for behavioral findings.

use super::ScanTarget;
use super::support::{Emitter, read_text};
use std::path::Path;

pub struct GitHubActionsTarget;

impl ScanTarget for GitHubActionsTarget {
    fn ecosystem_id(&self) -> &'static str {
        "github-actions"
    }

    fn detects(&self, path: &Path) -> bool {
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"))
            .unwrap_or(false);
        if !is_yaml {
            return false;
        }
        let normalized = path.to_string_lossy().replace('\\', "/");
        normalized.contains(".github/workflows/")
            || matches!(super::file_name(path), Some("action.yml" | "action.yaml"))
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        for (idx, raw) in contents.lines().enumerate() {
            let line = raw.trim();
            let Some(spec) = line
                .strip_prefix("uses:")
                .or_else(|| line.strip_prefix("- uses:"))
            else {
                continue;
            };
            let spec = spec.trim().trim_matches('"').trim_matches('\'');
            if let Some((name, version)) = parse_uses(spec) {
                out.pkg(&name, &version, Some(idx + 1));
            }
        }
    }
}

/// `actions/checkout@v4` → (`actions/checkout`, `v4`). Subdirectory actions
/// like `github/codeql-action/analyze@v3` key on the repo `github/codeql-action`
/// (OSV's coordinate granularity). Local (`./`) and docker (`docker://`) uses
/// have no registry coordinate and are skipped.
fn parse_uses(spec: &str) -> Option<(String, String)> {
    if spec.starts_with("./") || spec.starts_with("docker://") {
        return None;
    }
    let (path, version) = spec.split_once('@')?;
    let mut parts = path.splitn(3, '/');
    let (Some(owner), Some(repo)) = (parts.next(), parts.next()) else {
        return None;
    };
    if owner.is_empty() || repo.is_empty() || version.is_empty() {
        return None;
    }
    Some((format!("{owner}/{repo}"), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uses_refs() {
        assert_eq!(
            parse_uses("actions/checkout@v4"),
            Some(("actions/checkout".to_string(), "v4".to_string()))
        );
        assert_eq!(
            parse_uses("github/codeql-action/analyze@v3"),
            Some(("github/codeql-action".to_string(), "v3".to_string()))
        );
        assert_eq!(parse_uses("./.github/actions/local"), None);
        assert_eq!(parse_uses("docker://alpine:3.18"), None);
    }
}
