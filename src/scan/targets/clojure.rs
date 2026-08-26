//! Clojure (`deps.edn` / `.cpcache/*.libs` / Leiningen `project.clj`)
//! -> OSV `Maven` ecosystem.
//!
//! Clojure has no native lockfile in the npm/Cargo sense. Three on-disk
//! sources expose Maven coordinates with exact versions:
//!
//! * `.cpcache/<hash>.libs`: the Clojure CLI's resolved lib-map (EDN). This
//!   is the closest thing to a lockfile: it lists the FULL pinned transitive
//!   dependency set with exact `:mvn/version`s. Preferred when present (it is
//!   gitignored by convention, so it may be absent on a fresh checkout).
//! * `deps.edn`: the tools.deps manifest (EDN). Direct deps only, under
//!   `:deps` and each alias's `:extra-deps`/`:override-deps`/`:replace-deps`.
//! * `project.clj`: the Leiningen manifest. This is executable Clojure, not
//!   EDN; we heuristically scan the `:dependencies` (and `:plugins`) vectors.
//!
//! Coordinates map to OSV's `Maven` ecosystem as `group:artifact` + version.
//! A Clojure lib symbol `group/artifact` becomes `group:artifact`; an
//! unqualified symbol `foo` becomes `foo:foo` (the implicit-group rule).

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name};
use std::path::Path;

/// Resolved lib-map: `.cpcache/<hash>.libs`. Needs a struct (unlike the
/// exact-filename registry rows): detection is extension + parent-directory
/// shaped.
pub struct ClojureLibsTarget;

impl ScanTarget for ClojureLibsTarget {
    fn ecosystem_id(&self) -> &'static str {
        "clojure"
    }
    fn detects(&self, path: &Path) -> bool {
        // Require the `.cpcache` parent so unrelated `*.libs` aren't grabbed.
        if path.extension().and_then(|e| e.to_str()) != Some("libs") {
            return false;
        }
        path.parent()
            .and_then(file_name)
            .map(|d| d == ".cpcache")
            .unwrap_or(false)
    }
    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        if let Some(contents) = read_text(path, out) {
            lib_map(&contents, out);
        }
    }
}

/// A single EDN/Clojure lexical token. Whitespace, commas, comments and the
/// `#_` discard form are consumed by the lexer and never surfaced.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    Open(char),   // one of `{ [ (`
    Close(char),  // one of `} ] )`
    Str(String),  // a "..." string literal, contents unescaped-ish
    Atom(String), // symbol / keyword / number / char literal
    DiscardNext,  // `#_`: the next *form* must be dropped
}

/// Lexes Clojure-ish source into tokens. Best-effort and panic-free: malformed
/// input simply yields fewer / partial tokens.
fn lex(src: &str) -> Vec<Token> {
    let bytes = src.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        let c = bytes[i];
        match c {
            // Commas are whitespace in EDN/Clojure.
            b' ' | b'\t' | b'\r' | b'\n' | b',' => i += 1,
            b';' => {
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'{' | b'[' | b'(' => {
                tokens.push(Token::Open(c as char));
                i += 1;
            }
            b'}' | b']' | b')' => {
                tokens.push(Token::Close(c as char));
                i += 1;
            }
            // String literal with escapes. Unescaped runs are copied as str
            // slices (never byte-as-char, which would mangle non-ASCII).
            b'"' => {
                i += 1;
                let mut s = String::new();
                let mut seg = i; // start of the current verbatim run
                while i < n {
                    let b = bytes[i];
                    if b == b'\\' && i + 1 < n {
                        s.push_str(&src[seg..i]);
                        // Keep a minimal escape map; unknown escapes pass the
                        // following char through verbatim.
                        match bytes[i + 1] {
                            b'n' => s.push('\n'),
                            b't' => s.push('\t'),
                            b'r' => s.push('\r'),
                            _ => {
                                // Verbatim char: start the next run at it (so
                                // an escaped `"` cannot terminate the string).
                                i += 1;
                                seg = i;
                                i += src[i..].chars().next().map_or(1, char::len_utf8);
                                continue;
                            }
                        }
                        i += 2;
                        seg = i;
                    } else if b == b'"' {
                        s.push_str(&src[seg..i]);
                        i += 1;
                        seg = i;
                        break;
                    } else {
                        i += 1;
                    }
                }
                // Unterminated string: keep whatever accumulated.
                s.push_str(&src[seg.min(n)..i.min(n)]);
                tokens.push(Token::Str(s));
            }
            // Reader macros beginning with `#`.
            b'#' => {
                if i + 1 < n && bytes[i + 1] == b'_' {
                    tokens.push(Token::DiscardNext);
                    i += 2;
                } else if i + 1 < n && bytes[i + 1] == b'{' {
                    // Set literal `#{...}`: treat the `{` as a generic open so
                    // braces stay balanced; the leading `#` is dropped.
                    i += 1;
                } else if i + 1 < n && bytes[i + 1] == b'"' {
                    // Regex literal `#"..."`: skip the `#`, lex the string.
                    i += 1;
                } else {
                    // Tagged literal (`#inst`, `#uuid`, custom): skip the `#`
                    // and let the following symbol/string lex normally.
                    i += 1;
                }
            }
            // Character literal `\newline`, `\a`, `\,` etc. Consume `\` plus the
            // following run of non-delimiter chars.
            b'\\' => {
                i += 1;
                while i < n && !is_delim(bytes[i]) {
                    i += 1;
                }
            }
            // Keyword or symbol or number: a run of non-delimiter chars.
            _ => {
                let start = i;
                while i < n && !is_delim(bytes[i]) {
                    i += 1;
                }
                if i > start {
                    // Valid slice: we only break on ASCII delimiters.
                    let atom = &src[start..i];
                    tokens.push(Token::Atom(atom.to_string()));
                } else {
                    // Defensive: unknown byte, advance to avoid an infinite loop.
                    i += 1;
                }
            }
        }
    }
    tokens
}

fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t' | b'\r' | b'\n' | b',' | b'{' | b'}' | b'[' | b']' | b'(' | b')' | b'"' | b';'
    )
}

/// A minimal EDN value tree, enough to walk `deps.edn` / `.libs` maps.
#[derive(Debug, Clone, PartialEq)]
enum Edn {
    Map(Vec<(Edn, Edn)>),
    Vec(Vec<Edn>),
    Str(String),
    Sym(String), // symbols, keywords, numbers, etc., kept as raw text
}

impl Edn {
    /// If this is a map, find the value for a keyword key like `:deps`.
    fn map_get(&self, key: &str) -> Option<&Edn> {
        if let Edn::Map(pairs) = self {
            for (k, v) in pairs {
                if let Edn::Sym(s) = k
                    && s == key
                {
                    return Some(v);
                }
            }
        }
        None
    }
}

/// Recursively parses one EDN form starting at `tokens[*pos]`, honoring the
/// `#_` discard marker. Returns `None` at end of input or an unmatched close.
fn parse_form(tokens: &[Token], pos: &mut usize) -> Option<Edn> {
    while let Some(Token::DiscardNext) = tokens.get(*pos) {
        *pos += 1;
        let _ = parse_form(tokens, pos);
    }
    let tok = tokens.get(*pos)?;
    match tok {
        Token::Open('{') => {
            *pos += 1;
            let mut pairs = Vec::new();
            loop {
                // A `#_` at a key position discards the whole key→value PAIR
                // (the common "comment out this dep" pattern); dropping only the
                // key would desync every following pair.
                while let Some(Token::DiscardNext) = tokens.get(*pos) {
                    *pos += 1;
                    let _ = parse_form(tokens, pos); // drop the key form
                    if !matches!(tokens.get(*pos), Some(Token::Close(_)) | None) {
                        let _ = parse_form(tokens, pos); // drop its paired value
                    }
                }
                if let Some(Token::Close(_)) = tokens.get(*pos) {
                    *pos += 1;
                    break;
                }
                let Some(k) = parse_form(tokens, pos) else {
                    break;
                };
                let Some(v) = parse_form(tokens, pos) else {
                    // Unbalanced map: keep what we have.
                    break;
                };
                pairs.push((k, v));
            }
            Some(Edn::Map(pairs))
        }
        Token::Open(_) => {
            *pos += 1;
            let mut items = Vec::new();
            loop {
                if let Some(Token::Close(_)) = tokens.get(*pos) {
                    *pos += 1;
                    break;
                }
                let Some(item) = parse_form(tokens, pos) else {
                    break;
                };
                items.push(item);
            }
            Some(Edn::Vec(items))
        }
        Token::Close(_) => None,
        Token::Str(s) => {
            let v = Edn::Str(s.clone());
            *pos += 1;
            Some(v)
        }
        Token::Atom(a) => {
            let v = Edn::Sym(a.clone());
            *pos += 1;
            Some(v)
        }
        Token::DiscardNext => {
            // Already handled above; defensive.
            *pos += 1;
            parse_form(tokens, pos)
        }
    }
}

/// Parses a complete document and returns its first top-level form.
fn parse_edn(src: &str) -> Option<Edn> {
    let tokens = lex(src);
    let mut pos = 0;
    parse_form(&tokens, &mut pos)
}

/// Converts a Clojure lib symbol to an OSV Maven coordinate `group:artifact`.
///
/// * `group/artifact` -> `group:artifact`
/// * unqualified `foo` -> `foo:foo` (implicit-group rule)
/// * strips a deps.edn `$classifier` suffix from the artifact
fn maven_name(sym: &str) -> Option<String> {
    let sym = sym.trim();
    if sym.is_empty() {
        return None;
    }
    let (group, artifact) = match sym.split_once('/') {
        Some((g, a)) => (g, a),
        None => (sym, sym),
    };
    let artifact = artifact.split('$').next().unwrap_or(artifact);
    if group.is_empty() || artifact.is_empty() {
        return None;
    }
    Some(format!("{group}:{artifact}"))
}

/// Is `s` a usable, pinned Maven version (not a range / `RELEASE` / `LATEST`)?
fn is_pinned_version(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    // Maven ranges look like `[1.0,2.0)`; the soft keywords are unresolved.
    if s.starts_with('[') || s.starts_with('(') {
        return false;
    }
    if s == "RELEASE" || s == "LATEST" {
        return false;
    }
    true
}

/// Extracts `(maven_name, version)` from one dep-map (`sym -> coord-map`),
/// emitting a coordinate for every entry carrying a pinned `:mvn/version`.
/// git/local entries (no `:mvn/version`) are skipped.
fn collect_dep_map(dep_map: &Edn, out: &mut Emitter<'_>) {
    let Edn::Map(pairs) = dep_map else {
        return;
    };
    for (k, v) in pairs {
        let Edn::Sym(lib) = k else {
            continue;
        };
        let Some(version) = v.map_get(":mvn/version") else {
            continue; // git/local coordinate, not Maven-resolvable.
        };
        let Edn::Str(ver) = version else {
            continue;
        };
        if !is_pinned_version(ver) {
            continue;
        }
        if let Some(name) = maven_name(lib) {
            out.pkg(&name, ver.trim(), None);
        }
    }
}

/// Parses a `deps.edn` (or `bb.edn`) into direct Maven coordinates.
pub(super) fn deps_edn(src: &str, out: &mut Emitter<'_>) {
    let Some(root) = parse_edn(src) else {
        return;
    };
    if let Some(deps) = root.map_get(":deps") {
        collect_dep_map(deps, out);
    }
    if let Some(Edn::Map(aliases)) = root.map_get(":aliases") {
        for (_, alias) in aliases {
            for key in [":extra-deps", ":override-deps", ":replace-deps", ":deps"] {
                if let Some(dm) = alias.map_get(key) {
                    collect_dep_map(dm, out);
                }
            }
        }
    }
}

/// Parses a `.cpcache/*.libs` resolved lib-map into the full pinned set.
fn lib_map(src: &str, out: &mut Emitter<'_>) {
    let Some(root) = parse_edn(src) else {
        return;
    };
    // Some CLI versions wrap the map under a `:libs` key; handle both shapes.
    let lib_map = root.map_get(":libs").unwrap_or(&root);
    collect_dep_map(lib_map, out);
}

/// Heuristically scans a Leiningen `project.clj` (executable Clojure, not
/// EDN) for `:dependencies` and `:plugins` vectors. Each inner vector is
/// `[coord "version" ...opts]`.
pub(super) fn project_clj(src: &str, out: &mut Emitter<'_>) {
    let tokens = lex(src);
    let mut i = 0;
    while i < tokens.len() {
        if let Token::Atom(a) = &tokens[i]
            && matches!(
                a.as_str(),
                ":dependencies" | ":managed-dependencies" | ":plugins"
            )
        {
            let mut pos = i + 1;
            if let Some(Edn::Vec(items)) = parse_form(&tokens, &mut pos) {
                for item in &items {
                    if let Some((name, version)) = coord_from_vec(item) {
                        out.pkg(&name, version, None);
                    }
                }
            }
            i = pos;
            continue;
        }
        i += 1;
    }
}

/// Extracts a coordinate from a Leiningen inner vector `[coord "version" ...]`.
/// `coord` may be a symbol (`ring/ring-core`) or, rarely, a string literal.
/// Non-literal coords (a bare symbol var, etc.) are skipped gracefully.
fn coord_from_vec(item: &Edn) -> Option<(String, &str)> {
    let Edn::Vec(parts) = item else {
        return None;
    };
    let coord = parts.first()?;
    let sym = match coord {
        Edn::Sym(s) => s.as_str(),
        Edn::Str(s) => s.as_str(),
        _ => return None,
    };
    let ver = parts.iter().skip(1).find_map(|p| match p {
        Edn::Str(s) => Some(s.as_str()),
        _ => None,
    })?;
    if !is_pinned_version(ver) {
        return None;
    }
    Some((maven_name(sym)?, ver.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    fn coords(src: &str, parse: fn(&str, &mut Emitter<'_>)) -> Vec<(String, String)> {
        run_parser("clojure", src, parse)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect()
    }

    #[test]
    fn lib_map_yields_full_pinned_set() {
        let src = r#"
{org.clojure/clojure {:mvn/version "1.11.1"
                      :deps/manifest :mvn
                      :paths ["/x/clojure-1.11.1.jar"]}
 org.clojure/spec.alpha {:mvn/version "0.3.218"
                         :dependents [org.clojure/clojure]}
 cheshire/cheshire {:mvn/version "5.12.0"}}
"#;
        let got = coords(src, lib_map);
        assert!(got.contains(&("org.clojure:clojure".into(), "1.11.1".into())));
        assert!(got.contains(&("org.clojure:spec.alpha".into(), "0.3.218".into())));
        assert!(got.contains(&("cheshire:cheshire".into(), "5.12.0".into())));
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn deps_edn_direct_and_aliases_skips_git_and_local() {
        let src = r#"
{:paths ["src"]
 :deps {org.clojure/clojure {:mvn/version "1.11.1"}
        cheshire/cheshire   {:mvn/version "5.12.0"}
        io.github.foo/bar   {:git/sha "abc123" :git/tag "v1.0"}
        local/thing         {:local/root "../thing"}}
 :aliases {:dev {:extra-deps {criterium/criterium {:mvn/version "0.4.6"}}}}}
"#;
        let got = coords(src, deps_edn);
        assert!(got.contains(&("org.clojure:clojure".into(), "1.11.1".into())));
        assert!(got.contains(&("cheshire:cheshire".into(), "5.12.0".into())));
        assert!(got.contains(&("criterium:criterium".into(), "0.4.6".into())));
        // git and local entries must be skipped.
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn discard_macro_does_not_shift_pairs() {
        // `#_` drops the next form; if mishandled it shifts key->value pairing.
        let src = r#"{:deps {#_org.clojure/old {:mvn/version "0.0.1"}
                            cheshire/cheshire {:mvn/version "5.12.0"}}}"#;
        let got = coords(src, deps_edn);
        assert_eq!(got, vec![("cheshire:cheshire".into(), "5.12.0".into())]);
    }

    #[test]
    fn project_clj_heuristic_scan() {
        let src = r#"
(defproject my-app "0.1.0-SNAPSHOT"
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [cheshire "5.12.0"]
                 [ring/ring-core "1.11.0" :exclusions [commons-codec]]]
  :plugins [[lein-ring "0.12.6"]])
"#;
        let got = coords(src, project_clj);
        assert!(got.contains(&("org.clojure:clojure".into(), "1.11.1".into())));
        assert!(got.contains(&("cheshire:cheshire".into(), "5.12.0".into())));
        assert!(got.contains(&("ring:ring-core".into(), "1.11.0".into())));
        assert!(got.contains(&("lein-ring:lein-ring".into(), "0.12.6".into())));
    }

    #[test]
    fn unqualified_symbol_expands_to_group_artifact() {
        assert_eq!(maven_name("cheshire").as_deref(), Some("cheshire:cheshire"));
        assert_eq!(
            maven_name("org.clojure/tools.reader").as_deref(),
            Some("org.clojure:tools.reader")
        );
        // classifier stripped.
        assert_eq!(
            maven_name("com.example/lib$natives").as_deref(),
            Some("com.example:lib")
        );
    }

    #[test]
    fn ranges_and_keywords_are_not_pinned() {
        assert!(!is_pinned_version("[1.0,2.0)"));
        assert!(!is_pinned_version("RELEASE"));
        assert!(!is_pinned_version("LATEST"));
        assert!(is_pinned_version("1.11.1"));
        assert!(is_pinned_version("1.2.0-master-SNAPSHOT"));
    }
}
