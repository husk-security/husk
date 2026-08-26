//! pre-commit hooks (`.pre-commit-config.yaml` / `.yml`).
//!
//! The dependency unit is a "hook repo pinned at a `rev`": each entry under the
//! top-level `repos:` sequence carries a `repo:` URL (the coordinate name) and a
//! `rev:` git tag/SHA (the coordinate version). pre-commit has **no separate
//! lockfile**: `rev` *is* the immutable pin (tags/SHAs only; branches/HEAD are
//! unsupported), so real configs are always pinned. `repo: local` (inline hooks)
//! and `repo: meta` (built-in meta hooks) carry no rev and are skipped.
//!
//! This ecosystem is **inventory-only**: there is no OSV/GitHub advisory id for
//! pre-commit (Dependabot/Renovate treat it as a first-class `pre-commit`
//! ecosystem, but OSV has no coverage). The job is to record which hook supply
//! chain a developer trusts and pins. `additional_dependencies:` (pip/npm/go
//! specs installed into a hook's isolated env) are a real transitive surface but
//! belong to PyPI/npm/Go, so they are left out of the inventory coordinate here.
//!
//! Parsing is a hand-rolled, line-oriented, indentation-tracking reader because
//! the workspace forbids a YAML crate; pre-commit configs are highly regular
//! block-style YAML, which this covers; ambiguous structure is skipped rather
//! than guessed (never panic on unexpected input).

use super::support::{Emitter, read_text, unquote};
use super::{ScanTarget, file_name};
use std::path::Path;

pub struct PreCommitTarget;

impl ScanTarget for PreCommitTarget {
    fn ecosystem_id(&self) -> &'static str {
        "pre-commit"
    }

    fn detects(&self, path: &Path) -> bool {
        // Match the canonical config basenames anywhere in the tree, but never
        // the `.pre-commit-hooks.yaml` hook-DEFINITION manifest (no repo/rev),
        // and never clones under `~/.cache/pre-commit/` (double-counting).
        if !matches!(
            file_name(path),
            Some(".pre-commit-config.yaml" | ".pre-commit-config.yml")
        ) {
            return false;
        }
        let normalized = path.to_string_lossy().replace('\\', "/");
        !normalized.contains("/.cache/pre-commit/")
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        for (name, version, line) in parse_config(&contents) {
            out.pkg(&name, &version, Some(line));
        }
    }
}

/// Indentation (count of leading spaces) of `line`. A tab in the indent is
/// illegal YAML; we treat the line as having no usable indent so it is skipped
/// rather than mis-nested. (Deliberately NOT [`super::support::indent_of`],
/// which counts a tab as one column; this module's policy is tabs-as-poison.)
fn indent_of(line: &str) -> Option<usize> {
    let mut n = 0;
    for ch in line.chars() {
        match ch {
            ' ' => n += 1,
            '\t' => return None,
            _ => break,
        }
    }
    Some(n)
}

/// Strip an unquoted trailing ` # ...` comment. Conservative: only cuts at a
/// `#` that is preceded by whitespace and sits outside single/double quotes.
/// rev/repo values effectively never contain `#`, so this is safe enough.
fn strip_inline_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_ws = true; // start-of-string counts as preceded-by-whitespace
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double && prev_ws => return s[..i].trim_end(),
            _ => {}
        }
        prev_ws = b == b' ' || b == b'\t';
    }
    s
}

/// Normalize a repo URL to a stable inventory coordinate: lowercase
/// scheme+host, rewrite `git@host:owner/repo` / `ssh://git@host/...` and a
/// leading `git+` to `https://host/...`, then strip a trailing `.git` and
/// trailing slash. Path case is preserved.
fn normalize_repo_url(raw: &str) -> String {
    let mut url = raw.trim().to_string();

    if let Some(rest) = url.strip_prefix("git+") {
        url = rest.to_string();
    }

    if let Some(rest) = url.strip_prefix("git@") {
        if let Some((host, path)) = rest.split_once(':') {
            url = format!("https://{}/{}", host.to_lowercase(), path);
        }
    } else if let Some(rest) = url.strip_prefix("ssh://git@") {
        if let Some((host, path)) = rest.split_once('/') {
            url = format!("https://{}/{}", host.to_lowercase(), path);
        }
    } else if let Some((scheme, rest)) = url.split_once("://") {
        if let Some((host, path)) = rest.split_once('/') {
            url = format!(
                "{}://{}/{}",
                scheme.to_lowercase(),
                host.to_lowercase(),
                path
            );
        } else {
            url = format!("{}://{}", scheme.to_lowercase(), rest.to_lowercase());
        }
    }

    let trimmed = url.trim_end_matches('/');
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    trimmed.to_string()
}

/// Pure parser over the config text. Returns `(normalized_repo, rev, line)` for
/// every external hook repo that is both `repo:`- and `rev:`-pinned and is not
/// `local`/`meta`. Tolerant: any structural surprise skips the entry.
fn parse_config(contents: &str) -> Vec<(String, String, usize)> {
    let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);

    let lines: Vec<(usize, &str)> = contents
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l))
        .collect();

    // Locate the top-level `repos:` key.
    let mut start = None;
    for (idx, &(_, raw)) in lines.iter().enumerate() {
        if indent_of(raw) == Some(0) && strip_inline_comment(raw).trim() == "repos:" {
            start = Some(idx + 1);
            break;
        }
    }
    let Some(start) = start else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut cur_repo: Option<String> = None;
    let mut cur_rev: Option<String> = None;
    let mut cur_line: usize = 0;
    // Indentation of the dash that opens repo entries (shallowest seen wins).
    let mut dash_indent: Option<usize> = None;

    let flush = |repo: &mut Option<String>,
                 rev: &mut Option<String>,
                 line: usize,
                 out: &mut Vec<(String, String, usize)>| {
        if let (Some(r), Some(v)) = (repo.take(), rev.take()) {
            let lower = r.trim().to_lowercase();
            if lower != "local" && lower != "meta" && !v.trim().is_empty() {
                out.push((normalize_repo_url(&r), unquote(&v).to_string(), line));
            }
        }
        *repo = None;
        *rev = None;
    };

    for &(lineno, raw) in &lines[start..] {
        let no_comment = strip_inline_comment(raw);
        if no_comment.trim().is_empty() {
            continue;
        }
        let Some(indent) = indent_of(raw) else {
            continue;
        };
        // A new zero-indent key ends the `repos:` block.
        if indent == 0 {
            flush(&mut cur_repo, &mut cur_rev, cur_line, &mut out);
            break;
        }

        let trimmed = no_comment.trim_start();

        if let Some(after_dash) = trimmed.strip_prefix("- ").or_else(|| {
            // A lone `-` with keys on following lines is also valid.
            if trimmed == "-" { Some("") } else { None }
        }) {
            // Only treat dashes at the established repos child-indent as repo
            // boundaries (avoids hooks-list dashes nested deeper).
            let this_dash = indent;
            match dash_indent {
                None => dash_indent = Some(this_dash),
                Some(d) if this_dash < d => dash_indent = Some(this_dash),
                _ => {}
            }
            if Some(this_dash) == dash_indent {
                flush(&mut cur_repo, &mut cur_rev, cur_line, &mut out);
                cur_line = lineno;
                // The dash may carry an inline `repo:`/`rev:` key.
                handle_key(
                    after_dash.trim(),
                    lineno,
                    &mut cur_repo,
                    &mut cur_rev,
                    &mut cur_line,
                );
                continue;
            }
            // Deeper dash (e.g. a hook item): ignore for inventory.
            continue;
        }

        // `repo:`/`rev:` keys are matched regardless of exact depth;
        // additional_dependencies specs never start with those keys.
        handle_key(trimmed, lineno, &mut cur_repo, &mut cur_rev, &mut cur_line);
    }

    // Flush a trailing entry at EOF.
    flush(&mut cur_repo, &mut cur_rev, cur_line, &mut out);
    out
}

/// Apply a `key: value` line to the current entry, recording `repo:` and `rev:`.
fn handle_key(
    text: &str,
    lineno: usize,
    cur_repo: &mut Option<String>,
    cur_rev: &mut Option<String>,
    cur_line: &mut usize,
) {
    if let Some(val) = text.strip_prefix("repo:") {
        let v = unquote(val).to_string();
        if !v.is_empty() {
            *cur_repo = Some(v);
            if *cur_line == 0 {
                *cur_line = lineno;
            }
        }
    } else if let Some(val) = text.strip_prefix("rev:") {
        let v = unquote(val).to_string();
        if !v.is_empty() {
            *cur_rev = Some(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: 'v0.4.10'  # autoupdate
    hooks:
      - id: ruff
        args: [--fix]
  - repo: https://github.com/pycqa/flake8.git
    rev: 7.1.0
    hooks:
      - id: flake8
        additional_dependencies:
          - flake8-bugbear==24.4.26
  - repo: local
    hooks:
      - id: run-tests
        entry: pytest
        language: system
  - repo: meta
    hooks:
      - id: check-hooks-apply
"#;

    #[test]
    fn parses_pinned_repos_and_skips_local_meta() {
        let coords = parse_config(SAMPLE);
        assert_eq!(
            coords,
            vec![
                (
                    "https://github.com/pre-commit/pre-commit-hooks".to_string(),
                    "v4.6.0".to_string(),
                    2
                ),
                (
                    "https://github.com/astral-sh/ruff-pre-commit".to_string(),
                    "v0.4.10".to_string(),
                    7
                ),
                (
                    "https://github.com/pycqa/flake8".to_string(),
                    "7.1.0".to_string(),
                    12
                ),
            ]
        );
    }

    #[test]
    fn no_repos_key_yields_nothing() {
        assert!(parse_config("hooks:\n  - id: x\n").is_empty());
    }

    #[test]
    fn normalizes_url_variants() {
        assert_eq!(
            normalize_repo_url("git+https://Github.com/Owner/Repo.git/"),
            "https://github.com/Owner/Repo"
        );
        assert_eq!(
            normalize_repo_url("git@github.com:owner/repo.git"),
            "https://github.com/owner/repo"
        );
    }
}
