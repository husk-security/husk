//! Mint (`Mintfile` -> OSV `SwiftURL`).
//!
//! The `Mintfile` is a plain newline-delimited manifest of Swift CLI tools,
//! one `owner/repo@version` spec per non-comment line. Coordinates are git
//! tags keyed by remote git URL (OSV `SwiftURL`); we reuse the `"swift"` id
//! and normalize to the same scheme-less `github.com/owner/repo` form as the
//! SwiftPM/Carthage targets so all three managers dedupe. Only the literal,
//! case-sensitive `Mintfile` is parsed; `.mint/` is an install cache, not a
//! manifest.
//!
//! Parsing mirrors Mint's own `Mintfile.swift` + `PackageReference.swift`,
//! including the scp/ssh-URL `@` ambiguity. Specs without a pinned SemVer tag
//! (no `@`, a branch ref, or a 40-hex commit SHA) are skipped: they cannot
//! match OSV version ranges.

use super::support::{Emitter, is_commit_sha, strip_v};

struct MintPackage {
    /// Scheme-less, `.git`-less git URL (`github.com/owner/repo`).
    name: String,
    /// SemVer tag with a single leading `v`/`V` stripped.
    version: String,
    /// 1-based source line of the spec.
    line: usize,
}

pub(super) fn mintfile(contents: &str, out: &mut Emitter<'_>) {
    for pkg in parse_mintfile(contents) {
        out.pkg(&pkg.name, &pkg.version, Some(pkg.line));
    }
}

fn parse_mintfile(contents: &str) -> Vec<MintPackage> {
    let body = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    let mut out = Vec::new();
    for (idx, raw) in body.lines().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // A `#` cannot appear in a git repo path, so the inline-comment split
        // is safe.
        let spec = match trimmed.split_once('#') {
            Some((before, _)) => before.trim(),
            None => trimmed,
        };
        if spec.is_empty() {
            continue;
        }
        if let Some(pkg) = parse_spec(spec, idx + 1) {
            out.push(pkg);
        }
    }
    out
}

/// Parse a single package spec, replicating Mint's
/// `PackageReference(package:)`. `None` for unpinned or malformed specs.
fn parse_spec(spec: &str, line: usize) -> Option<MintPackage> {
    let parts: Vec<&str> = spec.split('@').collect();
    let (repo, version) = match parts.as_slice() {
        // No `@`: unpinned (latest tag / default branch).
        [_only] => return None,
        [repo, ver] => {
            // If the second component looks like part of an scp/ssh git URL
            // (contains `:`, e.g. `git@github.com:owner/repo.git`) or the repo
            // already declares an ssh scheme, the `@` belonged to the URL.
            if ver.contains(':') || repo.contains("ssh://") {
                return None;
            }
            (repo.trim(), ver.trim())
        }
        // 3 components: an scp/ssh URL (`git@host:...`) that also carries a
        // `@version`; rejoin the first two as the repo.
        [a, b, ver] => {
            let repo = format!("{}@{}", a.trim(), b.trim());
            return finish(&repo, ver.trim(), line);
        }
        _ => return None,
    };
    finish(repo, version, line)
}

fn finish(repo: &str, version: &str, line: usize) -> Option<MintPackage> {
    if repo.is_empty() || version.is_empty() {
        return None;
    }
    if !is_semver_tag(version) {
        return None;
    }
    Some(MintPackage {
        name: normalize_repo(repo),
        version: strip_v(version).to_string(),
        line,
    })
}

/// Resolve a Mint `repo` value to the canonical scheme-less `host/owner/repo`
/// form (matching the SwiftPM/Carthage normalization), replicating
/// `PackageReference.gitPath`: bare `owner/repo` -> GitHub; a first segment
/// containing `.` is already a host; URL/scp forms have their scheme/prefix
/// stripped. A trailing `.git` is always dropped.
fn normalize_repo(repo: &str) -> String {
    let stripped = repo.trim_end_matches(".git");

    if stripped.contains("://") || stripped.starts_with("git@") {
        return stripped
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_start_matches("git://")
            .trim_start_matches("ssh://")
            .trim_start_matches("git@")
            .replace(':', "/");
    }

    let first_seg = stripped.split('/').next().unwrap_or(stripped);
    if first_seg.contains('.') {
        return stripped.to_string();
    }

    format!("github.com/{stripped}")
}

/// A pinnable SemVer git tag: starts with a digit (optionally after a `v`/`V`)
/// and is not a 40-hex commit SHA; branch names and SHAs cannot match
/// SemVer-ranged advisories.
fn is_semver_tag(version: &str) -> bool {
    !is_commit_sha(version) && strip_v(version).starts_with(|c: char| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# Swift dev tools for this project (managed by Mint)
yonaskolb/XcodeGen@2.18.0
realm/SwiftLint@0.46.1          # pin: matches CI linter version
nicklockwood/SwiftFormat@0.49.1
apple/swift-format@508.0.0

# unpinned / non-coordinate lines below are recorded as present-but-unpinned
SwiftGen/SwiftGen
Quick/Nimble@main
gitlab.com/group/tool@1.0.0
https://example.com/owner/repo.git@v3.1.0
"#;

    #[test]
    fn parses_and_normalizes_pinned_specs() {
        let pkgs = parse_mintfile(SAMPLE);
        let coords: Vec<(&str, &str)> = pkgs
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert_eq!(
            coords,
            vec![
                ("github.com/yonaskolb/XcodeGen", "2.18.0"),
                // inline comment stripped
                ("github.com/realm/SwiftLint", "0.46.1"),
                ("github.com/nicklockwood/SwiftFormat", "0.49.1"),
                ("github.com/apple/swift-format", "508.0.0"),
                // host-prefixed shorthand kept as-is
                ("gitlab.com/group/tool", "1.0.0"),
                // full URL: scheme + trailing `.git` stripped, leading `v` gone
                ("example.com/owner/repo", "3.1.0"),
            ]
        );
        // Each coordinate carries the 1-based line of its spec.
        assert_eq!(pkgs[0].line, 3);
        assert_eq!(pkgs[1].line, 4);
    }

    #[test]
    fn unpinned_and_branch_specs_are_skipped() {
        // No `@` -> unpinned; `@main` -> branch ref. Neither is a coordinate.
        assert!(parse_spec("SwiftGen/SwiftGen", 1).is_none());
        assert!(parse_spec("Quick/Nimble@main", 1).is_none());
    }

    #[test]
    fn scp_ssh_url_without_version_is_not_a_coordinate() {
        // `git@github.com:owner/repo.git` -> 2 components, comp[1] has `:`, so
        // the `@` belongs to the URL, not a version.
        assert!(parse_spec("git@github.com:owner/repo.git", 1).is_none());
    }

    #[test]
    fn scp_ssh_url_with_version_rejoins_and_normalizes() {
        let pkg = parse_spec("git@github.com:owner/repo.git@1.2.3", 1).expect("pinned scp spec");
        assert_eq!(pkg.name, "github.com/owner/repo");
        assert_eq!(pkg.version, "1.2.3");
    }

    #[test]
    fn empty_repo_and_commit_sha_skipped() {
        assert!(parse_spec("@1.2.3", 1).is_none());
        assert!(parse_spec("owner/repo@233a3c01e32b44610fdcd648d6a8603d7befa626", 1).is_none());
    }

    #[test]
    fn version_v_prefix_stripping() {
        assert_eq!(strip_v("v1.2.3"), "1.2.3");
        assert_eq!(strip_v("V0.49.1"), "0.49.1");
        // Not stripped when not followed by a digit (real, non-prefix `v`).
        assert_eq!(strip_v("version"), "version");
        assert_eq!(strip_v("1.2.3"), "1.2.3");
    }
}
