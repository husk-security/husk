//! Meson wrap: `subprojects/*.wrap` INI descriptors (Python `configparser`
//! dialect), one dependency each. Inventory-only: no OSV ecosystem (WrapDB
//! names are library slugs, not advisory keys).
//!
//! Version source depends on the wrap *type* (the single section header):
//!   * `[wrap-file]`: `wrapdb_version = <upstream>-<rev>` (best), else
//!     recover from `directory` / `source_filename` / `source_url`.
//!   * `[wrap-git]` / `[wrap-hg]` / `[wrap-svn]`: `revision` (a tag,
//!     a floating `HEAD`/branch, or a 40-hex commit sha).
//!   * `[wrap-redirect]`: indirection to another wrap; not a coordinate.
//!
//! Name = filename stem (`glib.wrap` -> `glib`), authoritative even if
//! `directory=`/`[provide]` disagree.
//! Spec: <https://mesonbuild.com/Wrap-dependency-system-manual.html>.

use super::support::{Emitter, is_commit_sha, path_ends_with, read_text, strip_v};
use super::{ScanTarget, file_name};
use std::path::Path;

pub struct MesonWrapTarget;

impl ScanTarget for MesonWrapTarget {
    fn ecosystem_id(&self) -> &'static str {
        "meson-wrap"
    }

    /// Matches `subprojects/<name>.wrap` directly (excluding the bare
    /// `.wrap`, and anything under `subprojects/packagefiles/` or extracted
    /// `subprojects/<name>/` trees, which are build outputs, not manifests).
    fn detects(&self, path: &Path) -> bool {
        let Some(name) = file_name(path) else {
            return false;
        };
        let Some(stem) = name.strip_suffix(".wrap") else {
            return false;
        };
        !stem.is_empty() && path_ends_with(path, &["subprojects", name])
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(name) = file_name(path).and_then(|n| n.strip_suffix(".wrap")) else {
            return;
        };
        if name.is_empty() {
            return;
        }
        let Some(contents) = read_text(path, out) else {
            return;
        };
        for (n, v) in parse_wrap(name, &contents) {
            out.pkg(&n, &v, None);
        }
    }
}

/// At most one coordinate per `.wrap`; an empty vec means
/// malformed/redirect/no usable section.
fn parse_wrap(stem: &str, contents: &str) -> Vec<(String, String)> {
    let Some(wrap_type) = wrap_type(contents) else {
        return Vec::new();
    };
    if wrap_type == "redirect" {
        return Vec::new();
    }

    let version = match wrap_type.as_str() {
        "git" | "hg" | "svn" => version_from_revision(contents),
        _ => version_from_file(contents),
    }
    .unwrap_or_else(|| "unknown".to_string());

    vec![(stem.to_string(), version)]
}

/// The type suffix of the first `[wrap-*]` section header. Keys before any
/// section are illegal INI (configparser), so a leading key line marks the
/// whole file malformed.
fn wrap_type(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let header = trimmed
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))?;
        return header.trim().strip_prefix("wrap-").map(|t| t.to_string());
    }
    None
}

/// Read a raw `key = value` (or `key : value`) from the INI body. configparser
/// allows both separators and lets values legitimately contain `#`/`;`, so
/// inline comments are never stripped. First match wins (lenient on dupes).
fn ini_value<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') {
            continue;
        }
        let sep = trimmed.find('=').into_iter().chain(trimmed.find(':')).min();
        let Some(idx) = sep else {
            continue;
        };
        let (k, v) = trimmed.split_at(idx);
        if k.trim() == key {
            return Some(v[1..].trim());
        }
    }
    None
}

/// Version for `[wrap-file]`: `wrapdb_version` (best) else recover from
/// `directory`, `source_filename`, then `source_url`.
fn version_from_file(contents: &str) -> Option<String> {
    if let Some(raw) = ini_value(contents, "wrapdb_version") {
        // `<upstream>-<rev>`: take the part before the last `-`.
        if let Some((upstream, _rev)) = raw.rsplit_once('-')
            && !upstream.is_empty()
        {
            return Some(strip_v(upstream).to_string());
        }
        return Some(strip_v(raw).to_string());
    }
    for key in ["directory", "source_filename", "source_url"] {
        if let Some(value) = ini_value(contents, key)
            && let Some(v) = extract_version(value)
        {
            return Some(v);
        }
    }
    None
}

/// Version for `[wrap-git]`/`[wrap-hg]`/`[wrap-svn]` from `revision`.
/// `HEAD`/branch names are floating (unpinned -> `unknown`); a 40-hex sha is
/// commit-pinned (`git+<sha>`); a tag has its leading `v` stripped.
fn version_from_revision(contents: &str) -> Option<String> {
    let revision = ini_value(contents, "revision")?.trim();
    if revision.is_empty() {
        return None;
    }
    if revision.eq_ignore_ascii_case("HEAD") {
        return Some("unknown".to_string());
    }
    if is_commit_sha(revision) {
        return Some(format!("git+{revision}"));
    }
    let candidate = strip_v(revision);
    if candidate.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        Some(candidate.to_string())
    } else {
        // A digit-bearing non-numeric tag (e.g. `OpenSSL_1_1_1w`) is likely a
        // real tag, kept verbatim; digit-less means a floating branch.
        if revision.chars().any(|c| c.is_ascii_digit()) {
            Some(revision.to_string())
        } else {
            Some("unknown".to_string())
        }
    }
}

/// Recover a trailing dotted-numeric version token from a string like
/// `zlib-1.3.1`, `fmt-10.2.1.tar.gz`, or a URL: the last delimiter-split
/// token that starts with an optional `v` then a digit and contains a `.`.
fn extract_version(value: &str) -> Option<String> {
    let basename = value.rsplit('/').next().unwrap_or(value);
    let mut best: Option<String> = None;
    for token in basename.split(['-', '_', ' ', '/']) {
        // Trim archive suffixes repeatedly so compound extensions like
        // `.tar.gz` are fully removed.
        let mut token = token;
        loop {
            let trimmed = [".tar", ".gz", ".tgz", ".zip", ".xz", ".bz2", ".tbz2"]
                .iter()
                .fold(token, |acc, suffix| acc.trim_end_matches(suffix));
            if trimmed == token {
                break;
            }
            token = trimmed;
        }
        let stripped = strip_v(token);
        let mut chars = stripped.chars();
        if chars.next().is_some_and(|c| c.is_ascii_digit()) && stripped.contains('.') {
            best = Some(stripped.to_string());
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapdb_version_takes_precedence() {
        let raw = r#"
[wrap-file]
directory = zlib-1.3.1
source_url = https://zlib.net/fossils/zlib-1.3.1.tar.gz
source_hash = 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
wrapdb_version = 1.3.1-1

[provide]
dependency_names = zlib
"#;
        let out = parse_wrap("zlib", raw);
        assert_eq!(out, vec![("zlib".to_string(), "1.3.1".to_string())]);
    }

    #[test]
    fn git_revision_tag_strips_leading_v() {
        let raw = r#"
[wrap-git]
url = https://github.com/catchorg/Catch2.git
revision = v3.5.2
depth = 1
"#;
        assert_eq!(version_from_revision(raw).as_deref(), Some("3.5.2"));
    }

    #[test]
    fn git_head_is_floating() {
        let raw = "[wrap-git]\nrevision = HEAD\n";
        assert_eq!(version_from_revision(raw).as_deref(), Some("unknown"));
    }

    #[test]
    fn git_commit_sha_is_commit_pinned() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let raw = format!("[wrap-git]\nrevision = {sha}\n");
        assert_eq!(version_from_revision(&raw), Some(format!("git+{sha}")));
    }

    #[test]
    fn plain_wrap_file_recovers_version_from_directory() {
        let raw = r#"
[wrap-file]
directory = sqlite-amalgamation-3.45.1
source_filename = sqlite-amalgamation-3.45.1.zip
"#;
        assert_eq!(version_from_file(raw).as_deref(), Some("3.45.1"));
    }

    #[test]
    fn redirect_yields_no_coordinate() {
        let raw = "[wrap-redirect]\nfilename = subprojects/foo/foo.wrap\n";
        assert!(parse_wrap("foo", raw).is_empty());
    }

    #[test]
    fn keys_before_section_are_malformed() {
        let raw = "directory = zlib-1.3.1\n[wrap-file]\n";
        assert!(wrap_type(raw).is_none());
        assert!(parse_wrap("zlib", raw).is_empty());
    }

    #[test]
    fn value_with_hash_is_not_truncated() {
        // source_url legitimately may not, but hashes are pure hex; ensure we
        // never split on `#` inside a value.
        let raw = "[wrap-file]\nsource_url = https://example.com/x#frag-1.2.3.tar.gz\n";
        assert_eq!(version_from_file(raw).as_deref(), Some("1.2.3"));
    }
}
