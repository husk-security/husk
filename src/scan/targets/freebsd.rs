//! FreeBSD pkg (pkgng), inventory-only (no OSV ecosystem: FreeBSD security
//! is tracked via VuXML/`pkg audit`, keyed on name + version *ranges*).
//!
//! The authoritative registry (`/var/db/pkg/local.sqlite`) is binary SQLite
//! and deliberately out of scope. Parsed static substitutes:
//!   * `pkg-list.txt`: a hand-exported `pkg query '%n %v'` or `'%n-%v'` dump.
//!   * `packagesite.yaml`: the repo catalogue. Misnamed: it is JSON Lines
//!     (one compact JSON manifest per line, the whole file NOT valid
//!     JSON/YAML).
//!   * `+MANIFEST`: one per-installed-package compact JSON object (legacy
//!     pre-sqlite layout).
//!
//! Versions (`PORTVERSION[_PORTREVISION][,PORTEPOCH]`, e.g. `6.1.2_14,1`) are
//! stored verbatim: the `_rev` and `,epoch` suffixes are part of the
//! package's true identity. Detection stays exact-filename only: a bare
//! `name version` text file is far too generic.

use super::support::Emitter;
use serde_json::Value as JsonValue;

/// `packagesite.yaml` is JSON Lines: parse each line independently.
pub(super) fn packagesite_yaml(contents: &str, out: &mut Emitter<'_>) {
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, version)) = parse_manifest_json(line) {
            out.pkg(&name, &version, Some(idx + 1));
        }
    }
}

/// `+MANIFEST`: a single per-installed-package compact JSON manifest.
pub(super) fn plus_manifest(contents: &str, out: &mut Emitter<'_>) {
    if let Some((name, version)) = parse_manifest_json(contents) {
        out.pkg(&name, &version, Some(1));
    }
}

/// `pkg-list.txt`: a hand-exported `pkg query` text dump, one package per line.
pub(super) fn pkg_list_txt(contents: &str, out: &mut Emitter<'_>) {
    for (idx, raw) in contents.lines().enumerate() {
        if let Some((name, version)) = parse_query_line(raw) {
            out.pkg(&name, &version, Some(idx + 1));
        }
    }
}

/// `(name, version)` from a compact JSON pkg manifest: one
/// `packagesite.yaml` line or a whole `+MANIFEST` file. A malformed line is
/// skipped rather than aborting the whole file.
fn parse_manifest_json(text: &str) -> Option<(String, String)> {
    let json: JsonValue = serde_json::from_str(text).ok()?;
    let name = json.get("name")?.as_str()?.trim();
    let version = json.get("version")?.as_str()?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Parse one line of a `pkg query` text export into `(name, version)`.
/// Two supported formats:
///   * `%n %v` → two whitespace-separated tokens, rsplit on the last run.
///   * `%n-%v` → a single canonical pkgname token. Names legitimately contain
///     hyphens and trailing digits (`p5-IO-Socket-SSL`, `python311`), so split
///     on the rightmost `-` whose next char is a digit; FreeBSD versions
///     always start with a digit.
fn parse_query_line(raw: &str) -> Option<(String, String)> {
    let line = raw.trim_end_matches('\r').trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    if line.chars().any(char::is_whitespace) {
        if let Some((name, version)) = line.rsplit_once(char::is_whitespace) {
            let name = name.trim();
            let version = version.trim();
            if !name.is_empty() && !version.is_empty() {
                return Some((name.to_string(), version.to_string()));
            }
        }
        return None;
    }

    split_hyphenated(line)
}

/// Split a canonical FreeBSD pkgname (`name-version`) at the rightmost `-`
/// immediately followed by a digit. No such delimiter -> no version -> skip
/// rather than emit a versionless coordinate.
fn split_hyphenated(token: &str) -> Option<(String, String)> {
    let bytes = token.as_bytes();
    for (i, &b) in bytes.iter().enumerate().rev() {
        if b != b'-' {
            continue;
        }
        if let Some(&next) = bytes.get(i + 1)
            && next.is_ascii_digit()
        {
            let name = &token[..i];
            let version = &token[i + 1..];
            if !name.is_empty() && !version.is_empty() {
                return Some((name.to_string(), version.to_string()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_space_separated_query() {
        let (name, version) = parse_query_line("nginx 1.24.0_1").expect("parsed");
        assert_eq!(name, "nginx");
        // _rev suffix kept verbatim.
        assert_eq!(version, "1.24.0_1");
    }

    #[test]
    fn keeps_epoch_comma_in_space_form() {
        let (name, version) = parse_query_line("openssl 3.0.16,1").expect("parsed");
        assert_eq!(name, "openssl");
        // Comma is PORTEPOCH, not a delimiter; kept verbatim.
        assert_eq!(version, "3.0.16,1");
    }

    #[test]
    fn space_form_name_with_hyphen() {
        let (name, version) = parse_query_line("p5-IO-Socket-SSL 2.085").expect("parsed");
        assert_eq!(name, "p5-IO-Socket-SSL");
        assert_eq!(version, "2.085");
    }

    #[test]
    fn hyphenated_form_simple() {
        let (name, version) = split_hyphenated("nginx-1.24.0_1").expect("parsed");
        assert_eq!(name, "nginx");
        assert_eq!(version, "1.24.0_1");
    }

    #[test]
    fn hyphenated_form_name_with_hyphens_and_digits() {
        // Must split at the LAST '-' followed by a digit, not the first one,
        // and not inside `p5-` or after the trailing letters.
        let (name, version) = split_hyphenated("p5-IO-Socket-SSL-2.085").expect("parsed");
        assert_eq!(name, "p5-IO-Socket-SSL");
        assert_eq!(version, "2.085");
    }

    #[test]
    fn hyphenated_form_epoch() {
        let (name, version) = split_hyphenated("openssl-3.0.16,1").expect("parsed");
        assert_eq!(name, "openssl");
        assert_eq!(version, "3.0.16,1");
    }

    #[test]
    fn hyphenated_no_version_is_skipped() {
        // `python311` has trailing digits but no '-<digit>' boundary.
        assert!(split_hyphenated("python311").is_none());
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        assert!(parse_query_line("").is_none());
        assert!(parse_query_line("   ").is_none());
        assert!(parse_query_line("# exported inventory").is_none());
    }

    #[test]
    fn trims_crlf() {
        let (name, version) = parse_query_line("ffmpeg 6.1.2_14,1\r").expect("parsed");
        assert_eq!(name, "ffmpeg");
        assert_eq!(version, "6.1.2_14,1");
    }

    #[test]
    fn parses_jsonl_manifest_line() {
        // A compact `packagesite.yaml` line: comma in the version (PORTEPOCH)
        // and a comma inside the path must not break JSON parsing.
        let line = r#"{"name":"openssl","origin":"security/openssl","version":"3.0.16,1","path":"All/openssl-3.0.16,1.pkg"}"#;
        let (name, version) = parse_manifest_json(line).expect("parsed");
        assert_eq!(name, "openssl");
        assert_eq!(version, "3.0.16,1");
    }

    #[test]
    fn manifest_missing_version_is_none() {
        assert!(parse_manifest_json(r#"{"name":"nginx"}"#).is_none());
        assert!(parse_manifest_json("not json").is_none());
    }
}
