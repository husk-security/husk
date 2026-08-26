//! Racket (`raco pkg` / `info.rkt` package metadata) -> ecosystem `racket`.
//!
//! OSV id: NONE. Racket has no advisory feed today, so this target is
//! inventory-only (discover coordinates; advisory matching is future work).
//!
//! There is NO lockfile in this ecosystem. `info.rkt` (legacy `info.ss`) is
//! the canonical package-metadata file `raco pkg` reads. It is a Racket
//! S-expression module in the `info` / `setup/infotab` language (NOT TOML or
//! JSON), so it needs a small hand-rolled tokenizer (serde_json/toml are
//! useless on the file itself).
//!
//! What we extract, statically (never evaluating the file: `raco pkg
//! install` runs arbitrary code, so we read but never execute):
//!
//! * the package's OWN version from `(define version "X.Y.Z")` (advisory: the
//!   catalog ignores it, but it's the most reliable version for inventory);
//! * the package's name from `(define collection "name")` when `collection`
//!   is a string, else the enclosing directory name;
//! * dependencies from `(define deps ...)` and `(define build-deps ...)`.
//!
//! Dep entries take a few shapes:
//!   * bare string `"base"`: name only, no version;
//!   * `("rackunit-lib" #:version "1.11")`: `#:version` is a lower-bound (a
//!     floor, NOT an exact pin; there is only ever one installed version);
//!   * deprecated `("draw-lib" "1.18")`: string then string, name + floor;
//!   * quasiquoted `["racket" #:version ,version]`: the `,version` unquote is
//!     a code reference to this package's own `version` define; we resolve it.
//!
//! Bracket forms `[...]` are interchangeable with `(...)`. Package-source
//! names may be git URLs / paths / `name?path=sub`; the catalog key is the
//! leading name token (strip query/fragment/URL path).

use super::support::{Emitter, LineFinder, read_text};
use super::{ScanTarget, file_name};
use std::path::Path;

const ECOSYSTEM: &str = "racket";
/// Racket's default package version when none is declared.
const DEFAULT_VERSION: &str = "0.0";

/// Racket package metadata: `info.rkt` / `info.ss`.
pub struct RacketInfoTarget;

impl ScanTarget for RacketInfoTarget {
    fn ecosystem_id(&self) -> &'static str {
        ECOSYSTEM
    }

    fn detects(&self, path: &Path) -> bool {
        // Only the exact canonical filenames. A `.rkt` file that is not named
        // `info.rkt` is regular Racket source, not package metadata.
        matches!(file_name(path), Some("info.rkt") | Some("info.ss"))
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        if let Some(contents) = read_text(path, out) {
            parse_info(&contents, out);
        }
    }
}

/// Parse a single `info.rkt` into coordinates. Best-effort: tolerate malformed
/// input and emit whatever parsed.
fn parse_info(contents: &str, out: &mut Emitter<'_>) {
    let stripped = strip_comments(contents);

    // A file named `info.rkt` in some other `#lang` is not package metadata.
    if !is_info_module(&stripped) {
        return;
    }

    let own_version = find_define_string(&stripped, "version")
        .or_else(|| find_define_string(&stripped, "pkg-version"));
    let version_str = own_version
        .clone()
        .unwrap_or_else(|| DEFAULT_VERSION.to_string());

    let self_name =
        find_define_string(&stripped, "collection").or_else(|| package_dir_name(out.path()));
    if let Some(name) = self_name {
        let line = super::find_line(contents, "(define collection")
            .or_else(|| super::find_line(contents, "(define version"));
        out.pkg(&name, &version_str, line);
    }

    let mut deps = Vec::new();
    if let Some(list) = find_define_list(&stripped, "deps") {
        deps.extend(parse_dep_list(&list, own_version.as_deref()));
    }
    if let Some(list) = find_define_list(&stripped, "build-deps") {
        deps.extend(parse_dep_list(&list, own_version.as_deref()));
    }

    let mut lines = LineFinder::new(contents);
    for (name, ver) in dedupe_deps(deps) {
        let line = lines.find(&name);
        out.pkg(&name, ver.as_deref().unwrap_or(""), line);
    }
}

/// Confirm the first non-blank, non-comment content names the info language:
/// `#lang info`, `#lang setup/infotab`, or a `(module info ...)` form
/// referencing `info` / `infotab`.
fn is_info_module(stripped: &str) -> bool {
    for raw in stripped.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("#lang") {
            let lang = rest.trim();
            return lang == "info" || lang.starts_with("setup/infotab");
        }
        if line.starts_with("(module") {
            return line.contains("info") || line.contains("infotab");
        }
        // First meaningful content was not a header we recognise.
        return false;
    }
    false
}

/// Strip Racket comments while respecting string literals so a `;` inside a
/// string is not treated as a comment. Handles line `;`, nesting block
/// `#| ... |#`, and datum `#;<datum>` comments. Kept content is copied as
/// whole `&str` spans (never byte-by-byte, so multi-byte UTF-8 survives);
/// removed regions keep their newlines so line positions stay roughly stable.
fn strip_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut keep_from = 0; // start of the current kept span

    while i < n {
        match bytes[i] {
            // String literal: skip over it verbatim (it stays in the kept
            // span), honouring backslash escapes.
            b'"' => {
                i += 1;
                while i < n {
                    match bytes[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            // Line comment `; ... \n`.
            b';' => {
                out.push_str(&src[keep_from..i]);
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
                keep_from = i;
            }
            // Block comment `#| ... |#`, nesting.
            b'#' if i + 1 < n && bytes[i + 1] == b'|' => {
                out.push_str(&src[keep_from..i]);
                let mut depth = 1usize;
                i += 2;
                while i < n && depth > 0 {
                    if bytes[i] == b'#' && i + 1 < n && bytes[i + 1] == b'|' {
                        depth += 1;
                        i += 2;
                    } else if bytes[i] == b'|' && i + 1 < n && bytes[i + 1] == b'#' {
                        depth -= 1;
                        i += 2;
                    } else {
                        if bytes[i] == b'\n' {
                            out.push('\n');
                        }
                        i += 1;
                    }
                }
                keep_from = i;
            }
            // Datum comment `#;`: skip the next datum (one s-expression).
            b'#' if i + 1 < n && bytes[i + 1] == b';' => {
                out.push_str(&src[keep_from..i]);
                i = skip_datum(bytes, i + 2, &mut out);
                keep_from = i;
            }
            _ => i += 1,
        }
    }
    out.push_str(&src[keep_from.min(n)..]);

    out
}

/// Skip a single datum starting at `i` (used by `#;`). Returns the index just
/// past it. Preserves newlines into `out` so line numbers stay aligned.
fn skip_datum(bytes: &[u8], mut i: usize, out: &mut String) -> usize {
    let n = bytes.len();
    while i < n && bytes[i].is_ascii_whitespace() {
        if bytes[i] == b'\n' {
            out.push('\n');
        }
        i += 1;
    }
    if i >= n {
        return i;
    }
    match bytes[i] {
        b'(' | b'[' | b'{' => {
            // Balanced list datum.
            let mut depth = 0i32;
            while i < n {
                match bytes[i] {
                    b'(' | b'[' | b'{' => depth += 1,
                    b')' | b']' | b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    b'"' => {
                        i += 1;
                        while i < n && bytes[i] != b'"' {
                            if bytes[i] == b'\\' {
                                i += 1;
                            }
                            i += 1;
                        }
                    }
                    b'\n' => out.push('\n'),
                    _ => {}
                }
                i += 1;
            }
            i
        }
        b'"' => {
            // String datum.
            i += 1;
            while i < n && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i + 1
        }
        _ => {
            // Atom datum: run to the next delimiter.
            while i < n
                && !bytes[i].is_ascii_whitespace()
                && !matches!(bytes[i], b'(' | b')' | b'[' | b']' | b'{' | b'}')
            {
                i += 1;
            }
            i
        }
    }
}

/// Find `(define <field> "string")` and return the string value.
fn find_define_string(stripped: &str, field: &str) -> Option<String> {
    let needle = format!("(define {field}");
    let start = stripped.find(&needle)? + needle.len();
    let rest = &stripped[start..];
    // The value must be the next string literal before the closing paren.
    let q = rest.find('"')?;
    if let Some(close) = rest.find(')')
        && close < q
    {
        return None;
    }
    let after = &rest[q + 1..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

/// Find `(define <field> <list>)` and return the raw text of the list datum
/// (the balanced `(...)` / `[...]` after the field name, possibly preceded by
/// `'`, `` ` ``, or `(list`).
fn find_define_list(stripped: &str, field: &str) -> Option<String> {
    let needle = format!("(define {field}");
    let start = stripped.find(&needle)? + needle.len();
    let bytes = stripped.as_bytes();
    let mut i = start;
    let n = bytes.len();
    while i < n {
        match bytes[i] {
            b'(' | b'[' | b'{' => break,
            b')' => return None, // closed the define with no list
            _ => i += 1,
        }
    }
    if i >= n {
        return None;
    }
    let datum_start = i;
    let mut depth = 0i32;
    while i < n {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    i += 1;
                    return Some(stripped[datum_start..i].to_string());
                }
            }
            b'"' => {
                i += 1;
                while i < n && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Parse a dep-list datum into (name, optional-version) pairs.
/// `own_version` resolves `,version` unquote references.
fn parse_dep_list(list: &str, own_version: Option<&str>) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let tokens = tokenize(list);
    // Only top-level (depth-1 inside the outer list) elements matter:
    // either a bare String token, or a sub-list `(...)`.
    let mut idx = 0;
    // Skip the outer opening bracket.
    while idx < tokens.len() {
        match &tokens[idx] {
            Token::Open => {
                idx += 1;
                break;
            }
            _ => idx += 1,
        }
    }

    while idx < tokens.len() {
        match &tokens[idx] {
            Token::Str(s) => {
                if let Some(name) = catalog_name(s) {
                    out.push((name, None));
                }
                idx += 1;
            }
            Token::Open => {
                let mut depth = 1i32;
                let mut sub = Vec::new();
                idx += 1;
                while idx < tokens.len() && depth > 0 {
                    match &tokens[idx] {
                        Token::Open => {
                            depth += 1;
                            sub.push(tokens[idx].clone());
                        }
                        Token::Close => {
                            depth -= 1;
                            if depth > 0 {
                                sub.push(tokens[idx].clone());
                            }
                        }
                        other => sub.push(other.clone()),
                    }
                    idx += 1;
                }
                if let Some(dep) = parse_dep_element(&sub, own_version) {
                    out.push(dep);
                }
            }
            Token::Close => break,
            _ => idx += 1,
        }
    }
    out
}

/// Parse one sub-list dep element's tokens into (name, version?).
fn parse_dep_element(sub: &[Token], own_version: Option<&str>) -> Option<(String, Option<String>)> {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    // The first Str token is the dep name.
    let mut i = 0;
    while i < sub.len() {
        if let Token::Str(s) = &sub[i] {
            name = catalog_name(s);
            i += 1;
            break;
        }
        i += 1;
    }
    name.as_ref()?;

    // Scan the rest for `#:version <value>` or a deprecated second string.
    while i < sub.len() {
        match &sub[i] {
            Token::Keyword(k) if k == "version" => {
                if let Some(tok) = sub.get(i + 1) {
                    version = resolve_version(tok, own_version);
                }
                i += 2;
            }
            Token::Keyword(_) => {
                // Other keyword (e.g. #:platform); skip it and its value.
                i += 2;
            }
            Token::Str(s) if version.is_none() => {
                // Deprecated 2-element form: ("name" "version").
                version = Some(s.clone());
                i += 1;
            }
            _ => i += 1,
        }
    }

    name.map(|n| (n, version))
}

/// Resolve a `#:version` value token to a literal string, substituting the
/// package's own version for an `,version` unquote.
fn resolve_version(tok: &Token, own_version: Option<&str>) -> Option<String> {
    match tok {
        Token::Str(s) => Some(s.clone()),
        Token::Unquote(_) => own_version.map(|v| v.to_string()),
        _ => None,
    }
}

/// Derive the catalog/advisory name from a package-source string: strip
/// query/fragment, and for URLs take the last path segment minus `.git`.
fn catalog_name(src: &str) -> Option<String> {
    let s = src.trim();
    if s.is_empty() {
        return None;
    }
    let s = s.split(['?', '#']).next().unwrap_or(s);
    if s.contains("://") || s.contains('/') {
        let seg = s.trim_end_matches('/').rsplit('/').next().unwrap_or(s);
        let seg = seg.strip_suffix(".git").unwrap_or(seg);
        if seg.is_empty() {
            return None;
        }
        return Some(seg.to_string());
    }
    Some(s.to_string())
}

/// The enclosing directory name (the package root dir = the package name).
fn package_dir_name(path: &Path) -> Option<String> {
    path.parent()
        .and_then(file_name)
        .filter(|d| !d.is_empty() && *d != "." && *d != "..")
        .map(|d| d.to_string())
}

/// Dedupe deps by name, preferring an entry that carries a version.
fn dedupe_deps(deps: Vec<(String, Option<String>)>) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    for (name, ver) in deps {
        if let Some(existing) = out.iter_mut().find(|(n, _)| *n == name) {
            if existing.1.is_none() && ver.is_some() {
                existing.1 = ver;
            }
        } else {
            out.push((name, ver));
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Open,
    Close,
    Str(String),
    /// `#:keyword`
    Keyword(String),
    /// `,foo` unquote reference; carries the referenced symbol text.
    Unquote(String),
    Atom(String),
}

/// Tokenize an info S-expression fragment. Brackets `[`/`]`/`{`/`}` are all
/// treated as parens. Quotes `'` and `` ` `` are dropped; `,` introduces an
/// unquote token bound to the following symbol.
fn tokenize(src: &str) -> Vec<Token> {
    let bytes = src.as_bytes();
    let n = bytes.len();
    let mut out = Vec::new();
    let mut i = 0;

    while i < n {
        let b = bytes[i];
        match b {
            b'(' | b'[' | b'{' => {
                out.push(Token::Open);
                i += 1;
            }
            b')' | b']' | b'}' => {
                out.push(Token::Close);
                i += 1;
            }
            b'"' => {
                i += 1;
                let mut s = String::new();
                let mut span_start = i;
                while i < n && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < n {
                        // Copy the pending span, then the escaped char itself
                        // (full char, not a byte, so UTF-8 survives).
                        s.push_str(&src[span_start..i]);
                        let escaped = src[i + 1..].chars().next().unwrap_or('\\');
                        s.push(escaped);
                        i += 1 + escaped.len_utf8();
                        span_start = i;
                        continue;
                    }
                    i += 1;
                }
                s.push_str(&src[span_start..i.min(n)]);
                i += 1; // closing quote
                out.push(Token::Str(s));
            }
            b'\'' | b'`' => {
                // Quote / quasiquote prefix: drop it, the list follows.
                i += 1;
            }
            b',' => {
                // Unquote. May be `,@` splice; treat the same. Read the symbol.
                i += 1;
                if i < n && bytes[i] == b'@' {
                    i += 1;
                }
                let start = i;
                while i < n
                    && !bytes[i].is_ascii_whitespace()
                    && !matches!(bytes[i], b'(' | b')' | b'[' | b']' | b'{' | b'}')
                {
                    i += 1;
                }
                out.push(Token::Unquote(src[start..i].to_string()));
            }
            b'#' if i + 1 < n && bytes[i + 1] == b':' => {
                // Keyword `#:name`.
                i += 2;
                let start = i;
                while i < n
                    && !bytes[i].is_ascii_whitespace()
                    && !matches!(bytes[i], b'(' | b')' | b'[' | b']' | b'{' | b'}')
                {
                    i += 1;
                }
                out.push(Token::Keyword(src[start..i].to_string()));
            }
            _ if b.is_ascii_whitespace() => {
                i += 1;
            }
            _ => {
                let start = i;
                while i < n
                    && !bytes[i].is_ascii_whitespace()
                    && !matches!(bytes[i], b'(' | b')' | b'[' | b']' | b'{' | b'}' | b'"')
                {
                    i += 1;
                }
                out.push(Token::Atom(src[start..i].to_string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"#lang info
(define collection "widget-lib")
(define version "1.4.2")
(define deps
  `("racket-lib" "base"
    ("rackunit-lib" #:version "1.11")
    ["draw-lib" "1.18"]
    ["racket" #:version ,version]))
(define build-deps '("scribble-lib" ("rackunit-typed" #:version "1.2")))
(define pkg-desc "A widget library")
"#;

    #[test]
    fn extracts_version_and_name() {
        let stripped = strip_comments(SAMPLE);
        assert!(is_info_module(&stripped));
        assert_eq!(
            find_define_string(&stripped, "version").as_deref(),
            Some("1.4.2")
        );
        assert_eq!(
            find_define_string(&stripped, "collection").as_deref(),
            Some("widget-lib")
        );
    }

    #[test]
    fn parses_dep_shapes_including_unquote() {
        let stripped = strip_comments(SAMPLE);
        let list = find_define_list(&stripped, "deps").expect("deps list");
        let deps = parse_dep_list(&list, Some("1.4.2"));

        // Bare strings -> name, no version.
        assert!(deps.iter().any(|(n, v)| n == "racket-lib" && v.is_none()));
        assert!(deps.iter().any(|(n, v)| n == "base" && v.is_none()));
        // #:version floor.
        assert!(
            deps.iter()
                .any(|(n, v)| n == "rackunit-lib" && v.as_deref() == Some("1.11"))
        );
        // Deprecated 2-string form.
        assert!(
            deps.iter()
                .any(|(n, v)| n == "draw-lib" && v.as_deref() == Some("1.18"))
        );
        // Unquoted `,version` resolved to the package's own version.
        assert!(
            deps.iter()
                .any(|(n, v)| n == "racket" && v.as_deref() == Some("1.4.2"))
        );
    }

    #[test]
    fn comment_inside_string_not_stripped() {
        let src = r#"(define x "a ; not a comment")"#;
        let out = strip_comments(src);
        assert!(out.contains("; not a comment"));
    }

    #[test]
    fn catalog_name_strips_url_and_query() {
        assert_eq!(catalog_name("foo?path=bar").as_deref(), Some("foo"));
        assert_eq!(
            catalog_name("https://github.com/u/r.git").as_deref(),
            Some("r")
        );
        assert_eq!(catalog_name("base").as_deref(), Some("base"));
    }

    #[test]
    fn non_info_lang_is_skipped() {
        let src = "#lang racket/base\n(define deps '(\"base\"))\n";
        assert!(crate::scan::targets::support::run_parser(ECOSYSTEM, src, parse_info).is_empty());
    }

    #[test]
    fn non_ascii_strings_survive_comment_stripping_and_tokenizing() {
        let src = "(define pkg-desc \"écrit — ✓\") ; café\n";
        let out = strip_comments(src);
        assert!(out.contains("écrit — ✓"));
        assert!(!out.contains("café"));
        let tokens = tokenize("(\"naïve\")");
        assert!(tokens.contains(&Token::Str("naïve".to_string())));
    }
}
