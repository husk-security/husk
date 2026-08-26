//! GitLab CI components (`.gitlab-ci.yml` `include: - component:`),
//! inventory-only (no OSV ecosystem; useful for surfacing unpinned refs).
//!
//! GitLab CI has no lockfile: the whole coordinate lives in the component
//! address string `<host>/<project-path>/<component-name>@<version>` under
//! the top-level `include:` key.

use super::ScanTarget;
use super::support::{Emitter, read_text, unquote};
use std::path::Path;

pub struct GitLabCiTarget;

impl ScanTarget for GitLabCiTarget {
    fn ecosystem_id(&self) -> &'static str {
        "gitlab-ci"
    }

    /// The CI config path is project-configurable and `include:` recursive,
    /// so YAML under `.gitlab/`, `ci/` and `templates/` is routed here too;
    /// the parse gates on an actual `include:`+`component:` pair, so an
    /// unrelated YAML simply yields nothing.
    fn detects(&self, path: &Path) -> bool {
        if matches!(
            super::file_name(path),
            Some(".gitlab-ci.yml" | ".gitlab-ci.yaml")
        ) {
            return true;
        }
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"))
            .unwrap_or(false);
        if !is_yaml {
            return false;
        }
        let normalized = path.to_string_lossy().replace('\\', "/");
        normalized.contains("/.gitlab/")
            || normalized.starts_with(".gitlab/")
            || normalized.contains("/ci/")
            || normalized.starts_with("ci/")
            || normalized.contains("/templates/")
            || normalized.starts_with("templates/")
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        for found in parse_components(&contents) {
            out.pkg(&found.name, &found.version, Some(found.line));
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Component {
    name: String,
    version: String,
    line: usize,
}

/// Line-based reader for the block-style `include:` block. GitLab does not
/// allow nested top-level keys, so `include:` is reliably a column-0 key;
/// every `component:` value in the block is pulled regardless of `inputs:`
/// sub-blocks. Anchors/aliases/merge keys are not expanded (best-effort).
fn parse_components(contents: &str) -> Vec<Component> {
    let lines: Vec<&str> = contents.lines().collect();
    let mut out = Vec::new();

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if is_column0_key(line, "include") {
            i += 1;
            while i < lines.len() {
                let block_line = lines[i];
                if is_column0_key_any(block_line) {
                    break;
                }
                if let Some((name, version)) = component_on_line(block_line) {
                    out.push(Component {
                        name,
                        version,
                        line: i + 1,
                    });
                }
                i += 1;
            }
            continue;
        }
        i += 1;
    }

    out
}

fn is_column0_key(line: &str, key: &str) -> bool {
    line.strip_prefix(key)
        .is_some_and(|rest| rest.starts_with(':'))
}

/// Any column-0 mapping key ends the include block. Blank/comment lines
/// are not block terminators.
fn is_column0_key_any(line: &str) -> bool {
    if line.is_empty() || line.starts_with(char::is_whitespace) {
        return false;
    }
    let t = line.trim_start();
    if t.starts_with('#') || t.starts_with('-') {
        return false;
    }
    let content = strip_comment(line);
    content.trim_end().ends_with(':') || content.contains(": ")
}

/// Extract a `component:` value from a line: inline list form
/// (`- component: X`) or nested under a `-`.
fn component_on_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    let after_dash = trimmed.strip_prefix("- ").unwrap_or(trimmed);
    let after_dash = after_dash.trim_start();
    let value = after_dash.strip_prefix("component:")?;
    let value = clean_scalar(value);
    if value.is_empty() {
        return None;
    }
    split_coordinate(&value)
}

fn clean_scalar(raw: &str) -> String {
    unquote(strip_comment(raw)).trim().to_string()
}

/// Conservative inline-comment strip: only honors a `#` that follows
/// whitespace (or starts the line).
fn strip_comment(raw: &str) -> &str {
    let bytes = raw.as_bytes();
    let mut prev_ws = true; // start-of-line `#` counts as a comment too
    for (idx, &b) in bytes.iter().enumerate() {
        if b == b'#' && prev_ws {
            return &raw[..idx];
        }
        prev_ws = b == b' ' || b == b'\t';
    }
    raw
}

/// Split `<address>@<version>` on the LAST `@`. The name keeps any
/// `$CI_SERVER_FQDN` variable verbatim. A leading `v` on the version is
/// stripped unconditionally (unlike [`super::support::strip_v`], which
/// requires a digit after the `v`) so non-numeric refs like `vNext` also
/// lose it. No `@` → malformed; skipped.
fn split_coordinate(value: &str) -> Option<(String, String)> {
    let (name, version) = value.rsplit_once('@')?;
    let name = name.trim();
    let version = version.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    let version = version.strip_prefix('v').unwrap_or(version);
    if version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_block_components_and_ignores_other_includes() {
        let yaml = "stages:\n  - build\n\ninclude:\n  - component: gitlab.com/components/sast/sast@2.3.1\n    inputs:\n      stage: test\n  - component: $CI_SERVER_FQDN/my-org/security-components/secret-detection@1.0\n  - component: gitlab.com/components/code-quality/code-quality@e3262fdd0914fa823210cdb79a8c421e2cef79d8\n  - component: gitlab.com/components/container-scanning/container-scanning@~latest\n  - template: Auto-DevOps.gitlab-ci.yml\n  - project: 'my-group/my-shared-ci'\n    ref: main\n    file: '/templates/.deploy.yml'\n  - remote: 'https://gitlab.example.com/raw/main/.before-script.yml'\n\nbuild-job:\n  stage: build\n  script:\n    - echo \"building\"\n";
        let got = parse_components(yaml);
        let coords: Vec<(&str, &str)> = got
            .iter()
            .map(|c| (c.name.as_str(), c.version.as_str()))
            .collect();
        assert_eq!(
            coords,
            vec![
                ("gitlab.com/components/sast/sast", "2.3.1"),
                (
                    "$CI_SERVER_FQDN/my-org/security-components/secret-detection",
                    "1.0"
                ),
                (
                    "gitlab.com/components/code-quality/code-quality",
                    "e3262fdd0914fa823210cdb79a8c421e2cef79d8"
                ),
                (
                    "gitlab.com/components/container-scanning/container-scanning",
                    "~latest"
                ),
            ]
        );
        // template / project / remote includes carry no component coordinate.
        assert!(!coords.iter().any(|(n, _)| n.contains("Auto-DevOps")));
    }

    #[test]
    fn split_coordinate_uses_last_at_and_strips_leading_v() {
        assert_eq!(
            split_coordinate("gitlab.com/components/sast/sast@2.3.1"),
            Some((
                "gitlab.com/components/sast/sast".to_string(),
                "2.3.1".to_string()
            ))
        );
        assert_eq!(
            split_coordinate("host/path@v1.0.0"),
            Some(("host/path".to_string(), "1.0.0".to_string()))
        );
        // No `@` → malformed, skipped.
        assert_eq!(split_coordinate("gitlab.com/components/sast/sast"), None);
    }

    #[test]
    fn clean_scalar_strips_quotes_and_comments() {
        assert_eq!(clean_scalar("  'a/b@1.0'  "), "a/b@1.0");
        assert_eq!(clean_scalar(" a/b@1.0 # pinned"), "a/b@1.0");
        assert_eq!(clean_scalar(" \"a/b@1.0\""), "a/b@1.0");
    }
}
