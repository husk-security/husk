//! Carthage (`Cartfile.resolved` -> OSV `SwiftURL`).
//!
//! Carthage has no central registry; OSV `SwiftURL` keys packages by remote
//! git URL, so we reuse the `"swift"` Husk ecosystem id and normalize to the
//! same `github.com/owner/repo` form as the SwiftPM target so both managers
//! dedupe. Only `Cartfile.resolved` carries pins; `Cartfile` /
//! `Cartfile.private` are ranges and are never parsed for versions.
//!
//! Each resolved line is three tokens:
//!
//! ```text
//! github "Alamofire/Alamofire" "5.9.1"
//! git    "https://gitlab.example.com/mobile/CryptoUtils.git" "1.0.3"
//! binary "https://example.com/Frameworks/Closed.json" "2.3.0"
//! ```
//!
//! The VERSION is an exact (possibly `v`-prefixed) SemVer tag or a 40-hex git
//! SHA (branch/commit pins: recorded, but won't match SemVer-ranged
//! advisories). `binary` origins have no git/OSV identity and are recorded
//! inventory-only, keyed by their artifact URL.

use super::support::{Emitter, is_commit_sha, strip_v};

/// Parse a `Cartfile.resolved` body; malformed/partial entries are skipped,
/// not fatal.
pub(super) fn cartfile_resolved(contents: &str, out: &mut Emitter<'_>) {
    for (idx, raw) in contents.lines().enumerate() {
        // Locations/versions are quoted and never contain a `#` in practice,
        // so an unquoted `#` reliably starts a comment.
        let line = match raw.split_once('#') {
            Some((before, _)) => before,
            None => raw,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        let Some((origin, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let origin = origin.trim();
        if !matches!(origin, "github" | "git" | "binary") {
            continue;
        }
        let Some((location, after_loc)) = quoted(rest) else {
            continue;
        };
        let Some((version, _)) = quoted(after_loc) else {
            continue;
        };
        if location.is_empty() || version.is_empty() {
            continue;
        }

        let name = match origin {
            "binary" => location.to_string(),
            _ => normalize_swift_url(location),
        };
        let version = normalize_version(version);
        out.pkg(&name, version, Some(idx + 1));
    }
}

/// First `"..."`-delimited substring plus the remainder. No escape
/// processing: Carthage locations/versions never contain embedded quotes.
fn quoted(s: &str) -> Option<(&str, &str)> {
    let open = s.find('"')?;
    let after_open = &s[open + 1..];
    let close = after_open.find('"')?;
    Some((&after_open[..close], &after_open[close + 1..]))
}

/// Normalize a Carthage location to the canonical `host/owner/repo` git-URL
/// form used by OSV `SwiftURL` (matching the SwiftPM target's normalization):
/// - `owner/repo` shorthand (github) -> `github.com/owner/repo`
/// - `https://host/owner/repo` -> `host/owner/repo`
/// - `git@host:owner/repo` ssh -> `host/owner/repo`
///
/// A trailing `.git` is stripped.
fn normalize_swift_url(location: &str) -> String {
    let stripped = location.trim_end_matches(".git");
    let has_scheme = stripped.contains("://") || stripped.starts_with("git@");
    if !has_scheme {
        return format!("github.com/{stripped}");
    }
    stripped
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("ssh://")
        .trim_start_matches("git@")
        .replace(':', "/")
}

/// A 40-hex git SHA is emitted verbatim; otherwise strip a leading `v`/`V`
/// (Carthage treats tag `v1.2` as version 1.2). `strip_v` only strips
/// v-before-digit, so a tag like `vNext` passes through unchanged.
fn normalize_version(version: &str) -> &str {
    if is_commit_sha(version) {
        return version;
    }
    strip_v(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    const SAMPLE: &str = "# Cartfile.resolved\r\n\
github \"Alamofire/Alamofire\" \"5.9.1\"\r\n\
github \"ReactiveCocoa/ReactiveCocoa\" \"233a3c01e32b44610fdcd648d6a8603d7befa626\"\r\n\
github \"https://enterprise.example.com/ios/InternalKit\" \"v2.4.0\"  # internal\r\n\
git \"https://gitlab.example.com/mobile/CryptoUtils.git\" \"1.0.3\"\r\n\
binary \"https://example.com/Frameworks/MyClosedFramework.json\" \"2.3.0\"\r\n\
\r\n\
git \"git@github.com:apple/swift-nio.git\" \"v2.65.0\"\r\n";

    #[test]
    fn parses_all_origins_and_normalizes() {
        let pkgs = run_parser("swift", SAMPLE, cartfile_resolved);
        let coords: Vec<(&str, &str)> = pkgs
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert_eq!(
            coords,
            vec![
                // github shorthand -> github.com/owner/repo
                ("github.com/Alamofire/Alamofire", "5.9.1"),
                // 40-hex SHA pin emitted verbatim (no `v` strip)
                (
                    "github.com/ReactiveCocoa/ReactiveCocoa",
                    "233a3c01e32b44610fdcd648d6a8603d7befa626"
                ),
                // enterprise full-URL form, leading `v` stripped, comment ignored
                ("enterprise.example.com/ios/InternalKit", "2.4.0"),
                // git URL with trailing .git stripped
                ("gitlab.example.com/mobile/CryptoUtils", "1.0.3"),
                // binary: inventory-only, raw artifact URL kept as the name
                (
                    "https://example.com/Frameworks/MyClosedFramework.json",
                    "2.3.0"
                ),
                // ssh git@ form rewritten to host/owner/repo
                ("github.com/apple/swift-nio", "2.65.0"),
            ]
        );
    }

    #[test]
    fn duplicate_versions_attribute_to_their_own_lines() {
        // Two deps pinned to the same version must each point at their own
        // line, not both at the first occurrence of the version string.
        let input = "github \"a/one\" \"1.2.3\"\n\
github \"b/two\" \"1.2.3\"\n";
        let pkgs = run_parser("swift", input, cartfile_resolved);
        let got: Vec<(&str, Option<usize>)> =
            pkgs.iter().map(|p| (p.name.as_str(), p.line)).collect();
        assert_eq!(
            got,
            vec![("github.com/a/one", Some(1)), ("github.com/b/two", Some(2))]
        );
    }

    #[test]
    fn skips_malformed_and_unknown_lines() {
        // Unknown origin, missing version, and a stray bareword are all skipped.
        let input = "mercurial \"foo/bar\" \"1.0.0\"\n\
github \"only/location\"\n\
github\n\
\n";
        assert!(run_parser("swift", input, cartfile_resolved).is_empty());
    }

    #[test]
    fn commit_sha_detection() {
        assert!(is_commit_sha("233a3c01e32b44610fdcd648d6a8603d7befa626"));
        assert!(!is_commit_sha("5.9.1"));
        assert!(!is_commit_sha("233a3c01")); // too short
    }
}
