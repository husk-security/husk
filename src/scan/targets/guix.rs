//! GNU Guix (`manifest.scm`): inventory-only (no OSV ecosystem id; versions
//! are pinned by a channel git commit in `channels.scm`, not the manifest).
//!
//! Inventory lives in quoted spec-string lists passed to
//! `specifications->manifest` / `specifications->packages` /
//! `specification->package`; each spec is `NAME[@VERSION][:OUTPUT]`
//! (`"git@2.41.0"`, `"gcc-toolchain@12:lib"`, `"ripgrep"`).
//!
//! We never evaluate Guile: strip Scheme comments (tracking string state),
//! collect double-quoted tokens scoped to the spec-function argument lists,
//! and filter non-package strings (URLs, SHAs, PGP fingerprints, paths).
//! Versions are usually absent and, when present, a possibly-partial prefix,
//! stored verbatim. Unquoted package variables (`(packages->manifest (list
//! git emacs))`) are invisible to a string scanner and skipped. Detection is
//! the exact filename `manifest.scm` only; blanket-scanning every `.scm`
//! would be a huge false-positive surface.

use super::support::Emitter;

/// Spec-function names whose presence corroborates a real Guix manifest and
/// whose argument list scopes the token extraction.
const SPEC_FUNCS: &[&str] = &[
    "specifications->manifest",
    "specifications->packages",
    "specification->package",
];

/// One parsed spec token: `NAME[@VERSION][:OUTPUT]`.
#[derive(Debug, Clone, PartialEq)]
struct Spec {
    name: String,
    version: Option<String>,
    output: Option<String>,
}

pub(super) fn guix_manifest(src: &str, out: &mut Emitter<'_>) {
    let stripped = strip_comments(src);
    if !SPEC_FUNCS.iter().any(|f| stripped.contains(f)) {
        return;
    }

    let mut specs: Vec<Spec> = Vec::new();
    for func in SPEC_FUNCS {
        for region in spec_func_regions(&stripped, func) {
            for tok in quoted_tokens(region) {
                if !is_spec_token(&tok) {
                    continue;
                }
                if let Some(spec) = parse_spec(&tok) {
                    specs.push(spec);
                }
            }
        }
    }

    // Deduplicate on (name, output), preferring a versioned occurrence.
    // `git` and `git:send-email` are distinct entries.
    let mut chosen: Vec<Spec> = Vec::new();
    for spec in specs {
        if let Some(existing) = chosen
            .iter_mut()
            .find(|c| c.name == spec.name && c.output == spec.output)
        {
            if spec.version.is_some() && existing.version.is_none() {
                existing.version = spec.version;
            }
            continue;
        }
        chosen.push(spec);
    }
    for spec in chosen {
        out.pkg(&spec.name, spec.version.as_deref().unwrap_or(""), None);
    }
}

/// Removes Scheme comments while preserving string contents: `;`-to-EOL,
/// `#| ... |#` blocks, and the rare `#;` datum comment (conservatively
/// treated as line comment; over-stripping a line is safe since spec lists
/// are line-split anyway). A `;` inside a double-quoted string is NOT a
/// comment, so string state and `\` escapes are tracked.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                // Preserve the escaped char verbatim so a `\"` doesn't end the
                // string and a `\\` doesn't swallow a following quote.
                '\\' => {
                    if let Some(escaped) = chars.next() {
                        out.push(escaped);
                    }
                }
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push('"');
            }
            '#' if chars.peek() == Some(&'|') => {
                chars.next();
                let mut prev = ' ';
                for c in chars.by_ref() {
                    if prev == '|' && c == '#' {
                        break;
                    }
                    prev = c;
                }
            }
            '#' if chars.peek() == Some(&';') => skip_to_eol(&mut chars, &mut out),
            ';' => skip_to_eol(&mut chars, &mut out),
            _ => out.push(c),
        }
    }
    out
}

/// Consume up to and including the next newline, emitting only the newline.
fn skip_to_eol(chars: &mut impl Iterator<Item = char>, out: &mut String) {
    for c in chars.by_ref() {
        if c == '\n' {
            out.push('\n');
            break;
        }
    }
}

/// Returns the balanced parenthesized region following each occurrence of
/// `func` in comment-stripped `src`, e.g. the `(list "git@2.41.0" ...)`
/// body for `specifications->manifest`.
fn spec_func_regions<'a>(src: &'a str, func: &str) -> Vec<&'a str> {
    let bytes = src.as_bytes();
    let mut regions = Vec::new();
    let mut search = 0;
    while let Some(rel) = src[search..].find(func) {
        let start = search + rel;
        let mut i = start + func.len();
        while i < bytes.len() && bytes[i] != b'(' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // Track string state so a `(` or `)` inside a quoted token doesn't
        // unbalance the capture.
        let region_start = i;
        let mut depth = 0i32;
        let mut in_string = false;
        let mut j = i;
        while j < bytes.len() {
            let c = bytes[j];
            if in_string {
                if c == b'\\' {
                    j += 2;
                    continue;
                }
                if c == b'"' {
                    in_string = false;
                }
                j += 1;
                continue;
            }
            match c {
                b'"' => in_string = true,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        j += 1;
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        let end = j.min(bytes.len());
        regions.push(&src[region_start..end]);
        search = end.max(start + func.len());
    }
    regions
}

/// Collects every double-quoted string literal in `src`, honoring `\` escapes.
fn quoted_tokens(src: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = src.chars();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut s = String::new();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('r') => s.push('\r'),
                    Some(other) => s.push(other),
                    // Trailing lone backslash at EOF: keep it verbatim.
                    None => s.push('\\'),
                },
                '"' => break,
                other => s.push(other),
            }
        }
        tokens.push(s);
    }
    tokens
}

/// Heuristic: does `tok` look like a Guix package spec rather than a URL, path,
/// commit SHA, PGP fingerprint, or other incidental string?
fn is_spec_token(tok: &str) -> bool {
    let t = tok.trim();
    if t.is_empty() {
        return false;
    }
    // Package specs contain no whitespace (rules out PGP fingerprints).
    if t.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    if t.contains('/') || t.contains("://") {
        return false;
    }
    if t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let name = t.split([':', '@']).next().unwrap_or(t);
    if name.is_empty() {
        return false;
    }
    let first_ok = name
        .chars()
        .next()
        .map(|c| c.is_ascii_alphanumeric())
        .unwrap_or(false);
    if !first_ok {
        return false;
    }
    // A bare token that is purely numeric / dotted-numeric is a version, not a
    // package (e.g. the inferior version arg `"29.4"`).
    if name.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '+' | '.' | '_'))
}

/// Parses one spec token: split the OUTPUT on the FIRST `:`, then the VERSION
/// on the FIRST `@` (Guix names never contain `@`). OUTPUT is metadata, not
/// part of the coordinate.
fn parse_spec(tok: &str) -> Option<Spec> {
    let tok = tok.trim();
    if tok.is_empty() {
        return None;
    }
    let (head, output) = match tok.split_once(':') {
        Some((h, o)) => (h, (!o.is_empty()).then(|| o.to_string())),
        None => (tok, None),
    };
    let (name, version) = match head.split_once('@') {
        Some((n, v)) => (n, (!v.is_empty()).then(|| v.to_string())),
        None => (head, None),
    };
    let name = name.trim().to_lowercase();
    if name.is_empty() {
        return None;
    }
    Some(Spec {
        name,
        version,
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;
    use crate::scan::targets::support::run_parser;

    fn parse_manifest(src: &str) -> Vec<PackageRef> {
        run_parser("guix", src, guix_manifest)
    }

    fn coords(pkgs: &[PackageRef]) -> Vec<(String, String)> {
        pkgs.iter()
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect()
    }

    #[test]
    fn parse_spec_splits_name_version_output() {
        // version + output -> coordinate is gcc-toolchain@12, output dropped.
        let s = parse_spec("gcc-toolchain@12:lib").unwrap();
        assert_eq!(s.name, "gcc-toolchain");
        assert_eq!(s.version.as_deref(), Some("12"));
        assert_eq!(s.output.as_deref(), Some("lib"));

        // Full version, no output.
        let s = parse_spec("git@2.41.0").unwrap();
        assert_eq!(s.name, "git");
        assert_eq!(s.version.as_deref(), Some("2.41.0"));
        assert_eq!(s.output, None);

        // Bare name (the common case): no version.
        let s = parse_spec("ripgrep").unwrap();
        assert_eq!(s.name, "ripgrep");
        assert_eq!(s.version, None);

        // Output only, no version (e.g. git:send-email).
        let s = parse_spec("git:send-email").unwrap();
        assert_eq!(s.name, "git");
        assert_eq!(s.version, None);
        assert_eq!(s.output.as_deref(), Some("send-email"));
    }

    #[test]
    fn is_spec_token_filters_non_packages() {
        assert!(is_spec_token("git@2.41.0"));
        assert!(is_spec_token("font-adobe-source-code-pro"));
        assert!(is_spec_token("gtk+"));
        // URL / path / sha / fingerprint / bare version are not packages.
        assert!(!is_spec_token("https://git.savannah.gnu.org/git/guix.git"));
        assert!(!is_spec_token("/gnu/store/abc"));
        assert!(!is_spec_token("2e1ead7c8b1d29b9f2bc3d4e5f60718293a4b5c6")); // 40 hex
        assert!(!is_spec_token("BBB0 2DDF 2656 54FA"));
        assert!(!is_spec_token("29.4")); // inferior version arg
    }

    #[test]
    fn strip_comments_preserves_strings() {
        let src = r#"(list "a;b" ; this is a comment "not-a-pkg"
       "c")"#;
        let stripped = strip_comments(src);
        // The `;` inside "a;b" is preserved; the trailing comment (incl. the
        // decoy quoted token) is gone.
        assert!(stripped.contains("\"a;b\""));
        assert!(!stripped.contains("not-a-pkg"));
        assert!(stripped.contains("\"c\""));
    }

    #[test]
    fn parses_multiline_spec_manifest() {
        let src = r#"
;; manifest.scm — pass to: guix shell -m manifest.scm
(specifications->manifest
 (list "git@2.41.0"            ; version-pinned (full)
       "python@3.10"           ; partial version prefix
       "ripgrep"               ; unversioned (common)
       "gcc-toolchain@12:lib"  ; version + output -> gcc-toolchain@12
       "emacs-vterm"
       "font-adobe-source-code-pro"))
"#;
        let pkgs = parse_manifest(src);
        let got = coords(&pkgs);
        assert!(got.contains(&("git".into(), "2.41.0".into())));
        assert!(got.contains(&("python".into(), "3.10".into())));
        assert!(got.contains(&("ripgrep".into(), "".into())));
        assert!(got.contains(&("gcc-toolchain".into(), "12".into())));
        assert!(got.contains(&("emacs-vterm".into(), "".into())));
        assert!(got.contains(&("font-adobe-source-code-pro".into(), "".into())));
        assert_eq!(got.len(), 6);
    }

    #[test]
    fn non_guix_scm_yields_nothing() {
        let src = r#"(define (square x) (* x x)) (display "hello")"#;
        let pkgs = parse_manifest(src);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn same_name_distinct_outputs_kept_url_filtered() {
        let src = r#"
(specifications->manifest
 (list "git"
       "git:send-email"
       "https://git.savannah.gnu.org/git/guix.git"))
"#;
        let pkgs = parse_manifest(src);
        let got = coords(&pkgs);
        // git appears twice (distinct outputs); the URL is filtered out.
        assert_eq!(got.iter().filter(|(n, _)| n == "git").count(), 2);
        assert!(!got.iter().any(|(n, _)| n.contains("savannah")));
    }
}
