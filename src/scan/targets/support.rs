//! The shared support layer under every [`ScanTarget`](super::ScanTarget).
//!
//! One tested copy of each parsing idiom the ~100 targets share: the manifest
//! read (bounded, BOM-stripped, lossy, failure-visible), coordinate emission,
//! line location, and the micro-parsers (quote stripping, `v`-stripping,
//! scoped `name@version` splitting, JSONC comment stripping). Target modules
//! keep only their genuine format knowledge.

use crate::model::PackageRef;
use std::fmt::Display;
use std::path::Path;

/// Manifests larger than this are skipped (with a visible warning) instead of
/// being read whole. Real lockfiles and package databases top out in the tens
/// of megabytes; anything bigger is a pathological or crafted file that
/// discovery must stay bounded on. Targets are pointed at paths inside
/// whatever the user scans, including a freshly cloned hostile repository, so
/// every whole-file read goes through this cap.
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

/// Sink for one manifest's coordinates and diagnostics.
///
/// Owns the ecosystem label (from the target's `ecosystem_id`), the manifest
/// path, and the warning channel, so parsers only ever say
/// `out.pkg(name, version, line)`, and a manifest that fails to read or parse
/// is *reported* ("N manifests failed to parse" in the scan benchmarks)
/// instead of silently skipped.
pub struct Emitter<'a> {
    ecosystem: &'a str,
    path: &'a Path,
    out: &'a mut Vec<PackageRef>,
    warnings: &'a mut Vec<String>,
}

impl<'a> Emitter<'a> {
    pub(crate) fn new(
        ecosystem: &'a str,
        path: &'a Path,
        out: &'a mut Vec<PackageRef>,
        warnings: &'a mut Vec<String>,
    ) -> Self {
        Self {
            ecosystem,
            path,
            out,
            warnings,
        }
    }

    /// The manifest being parsed (for sibling-file lookups like os-release).
    pub fn path(&self) -> &Path {
        self.path
    }

    /// Emit one coordinate in the target's primary ecosystem.
    pub fn pkg(&mut self, name: &str, version: &str, line: Option<usize>) {
        let ecosystem = self.ecosystem;
        self.pkg_in(ecosystem, name, version, line);
    }

    /// Emit one coordinate in an explicit ecosystem (multi-ecosystem surfaces:
    /// deno's jsr, SBOM purls, MCP/jupyter npm+pypi, release-qualified distros).
    pub fn pkg_in(&mut self, ecosystem: &str, name: &str, version: &str, line: Option<usize>) {
        self.out.push(PackageRef {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: self.path.to_path_buf(),
            line,
        });
    }

    /// Record that this manifest could not be read or parsed. Surfaces in the
    /// scan report ("N manifests failed to parse"); for a security scanner,
    /// an unreadable lockfile is signal, not noise.
    pub fn warn(&mut self, reason: impl Display) {
        self.warnings
            .push(format!("{}: {reason}", self.path.display()));
    }
}

/// Read a whole file, bounded by [`MAX_MANIFEST_BYTES`]. For the binary
/// package databases that cannot go through [`read_text`]. On failure the
/// reason lands in the warning channel and `None` is returned, never silently.
pub fn read_bytes(path: &Path, out: &mut Emitter<'_>) -> Option<Vec<u8>> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_MANIFEST_BYTES => {
            out.warn(format_args!(
                "manifest is {} bytes (limit {MAX_MANIFEST_BYTES}); skipped",
                meta.len()
            ));
            return None;
        }
        _ => {}
    }
    match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(err) => {
            out.warn(err);
            None
        }
    }
}

/// [`read_bytes`], then BOM stripped and lossily decoded (old system databases
/// carry stray non-UTF-8 bytes).
pub fn read_text(path: &Path, out: &mut Emitter<'_>) -> Option<String> {
    let bytes = read_bytes(path, out)?;
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
    };
    Some(match text.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_string(),
        None => text,
    })
}

/// A target fully described by `(ecosystem, exact filenames, parse fn)`, the
/// common case. Complex targets (path-shape detection, sibling-file gating,
/// binary databases) implement [`ScanTarget`](super::ScanTarget) directly.
pub struct Simple {
    pub ecosystem: &'static str,
    pub files: &'static [&'static str],
    pub parse: fn(&str, &mut Emitter<'_>),
}

impl super::ScanTarget for Simple {
    fn ecosystem_id(&self) -> &'static str {
        self.ecosystem
    }

    fn detects(&self, path: &Path) -> bool {
        super::file_name(path).is_some_and(|name| self.files.contains(&name))
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        if let Some(contents) = read_text(path, out) {
            (self.parse)(&contents, out);
        }
    }
}

/// Incremental line locator for parsers that walk entries in file order.
///
/// `find` searches forward from the previous hit first (lockfile entries are
/// ordered, so the whole file is scanned once in total) and falls back to a
/// full-file search for out-of-order needles.
pub struct LineFinder<'a> {
    contents: &'a str,
    offset: usize,
    line: usize,
}

impl<'a> LineFinder<'a> {
    pub fn new(contents: &'a str) -> Self {
        Self {
            contents,
            offset: 0,
            line: 1,
        }
    }

    /// First 1-based line containing `needle` at or after the previous hit
    /// (full-file fallback otherwise).
    pub fn find(&mut self, needle: &str) -> Option<usize> {
        match self.contents[self.offset..].find(needle) {
            Some(rel) => {
                let pos = self.offset + rel;
                let line = self.line + count_newlines(&self.contents[self.offset..pos]);
                self.offset = pos + needle.len();
                self.line = line + count_newlines(needle);
                Some(line)
            }
            None => super::find_line(self.contents, needle),
        }
    }
}

pub(crate) fn count_newlines(s: &str) -> usize {
    s.bytes().filter(|&b| b == b'\n').count()
}

/// Iterate the `[[package]] name = … version = …` TOML lockfile family
/// (Cargo.lock, poetry.lock, uv.lock, pdm.lock, gleam's manifest.toml),
/// yielding `(name, version, entry)` for every complete entry.
pub fn toml_package_array(toml: &toml::Value) -> impl Iterator<Item = (&str, &str, &toml::Value)> {
    toml.get("package")
        .and_then(|value| value.as_array())
        .map(|entries| entries.as_slice())
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| {
            let name = entry.get("name")?.as_str()?;
            let version = entry.get("version")?.as_str()?;
            Some((name, version, entry))
        })
}

/// Split `name@version` where a leading `@` marks an npm-style scope
/// (`@scope/pkg@1.2.3`). Splits at the *first* `@` after the scope, so
/// annotations that themselves contain `@` stay in the version half.
pub fn split_scoped_at(key: &str) -> Option<(&str, &str)> {
    let scope_end = if key.starts_with('@') {
        key.find('/')?
    } else {
        0
    };
    let at = scope_end + key[scope_end..].find('@')?;
    let (name, version) = (&key[..at], &key[at + 1..]);
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Strip one leading `v`/`V` iff followed by a digit (`v1.2.3` → `1.2.3`).
/// Tags like `version` or a bare `v` pass through unchanged.
pub fn strip_v(version: &str) -> &str {
    match version.strip_prefix(['v', 'V']) {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => version,
    }
}

/// Strip one matching pair of surrounding single or double quotes.
pub fn unquote(s: &str) -> &str {
    let s = s.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = s
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }
    s
}

/// Leading indentation width (spaces and tabs each count 1 column).
pub fn indent_of(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

/// Cut an unquoted ` #` inline comment, then unquote: the YAML-ish
/// `key: "value"  # comment` scalar cleanup.
pub fn clean_value(s: &str) -> &str {
    let mut in_quote: Option<char> = None;
    for (idx, ch) in s.char_indices() {
        match (ch, in_quote) {
            (q @ ('"' | '\''), None) => in_quote = Some(q),
            (q, Some(open)) if q == open => in_quote = None,
            ('#', None) if s[..idx].ends_with(char::is_whitespace) || idx == 0 => {
                return unquote(s[..idx].trim_end());
            }
            _ => {}
        }
    }
    unquote(s.trim())
}

/// A 40-hex string, a full git commit SHA.
pub fn is_commit_sha(s: &str) -> bool {
    is_hex_id(s, 40)
}

/// An exactly-`len` lowercase/uppercase hex identifier.
pub fn is_hex_id(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Allocation-free component-wise path suffix test (`Path::ends_with` with a
/// string-array suffix): separator-agnostic, never matches mid-component.
pub fn path_ends_with(path: &Path, suffix: &[&str]) -> bool {
    let mut components = path.components().rev();
    suffix.iter().rev().all(|want| {
        components
            .next()
            .is_some_and(|got| got.as_os_str() == std::ffi::OsStr::new(want))
    })
}

/// Strip JSONC decorations in one pass: `//…` and `/*…*/` comments plus
/// trailing commas before `}`/`]`, all quote/escape-aware. Used for the
/// JSON-with-comments config family (bun.lock, VS Code / MCP configs).
pub fn strip_jsonc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut in_string = false;
    let mut escaped = false;
    let mut pending_comma = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            out.push_str(&input[i..i + utf8_len(b)]);
            i += utf8_len(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => {
                flush_comma(&mut out, &mut pending_comma);
                in_string = true;
                out.push('"');
                i += 1;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            b',' => {
                // Held until the next significant byte decides whether it was
                // a trailing comma (before } or ]) to drop.
                flush_comma(&mut out, &mut pending_comma);
                pending_comma = true;
                i += 1;
            }
            b'}' | b']' => {
                pending_comma = false;
                out.push(b as char);
                i += 1;
            }
            _ if (b as char).is_whitespace() => {
                out.push(b as char);
                i += 1;
            }
            _ => {
                flush_comma(&mut out, &mut pending_comma);
                out.push_str(&input[i..i + utf8_len(b)]);
                i += utf8_len(b);
            }
        }
    }
    out
}

fn flush_comma(out: &mut String, pending: &mut bool) {
    if std::mem::take(pending) {
        out.push(',');
    }
}

fn utf8_len(first_byte: u8) -> usize {
    match first_byte {
        b if b < 0x80 => 1,
        b if b >= 0xF0 => 4,
        b if b >= 0xE0 => 3,
        b if b >= 0xC0 => 2,
        _ => 1, // continuation byte (lossy input): copy through byte-wise
    }
}

/// Unit-test entry point: run a parse fn against in-memory contents.
#[cfg(test)]
pub(crate) fn run_parser(
    ecosystem: &'static str,
    contents: &str,
    parse: impl Fn(&str, &mut Emitter<'_>),
) -> Vec<PackageRef> {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    let mut emitter = Emitter::new(
        ecosystem,
        Path::new("test-manifest"),
        &mut out,
        &mut warnings,
    );
    parse(contents, &mut emitter);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_scoped_at_handles_scopes_and_rejects_incomplete() {
        assert_eq!(
            split_scoped_at("lodash@4.17.21"),
            Some(("lodash", "4.17.21"))
        );
        assert_eq!(
            split_scoped_at("@types/node@20.1.0"),
            Some(("@types/node", "20.1.0"))
        );
        // First `@` after the scope wins: annotations stay in the version.
        assert_eq!(
            split_scoped_at("pkg@1.0.0(peer@2.0.0)"),
            Some(("pkg", "1.0.0(peer@2.0.0)"))
        );
        assert_eq!(split_scoped_at("@scope/pkg"), None);
        assert_eq!(split_scoped_at("noversion"), None);
        assert_eq!(split_scoped_at("@1.0.0"), None);
        assert_eq!(split_scoped_at("pkg@"), None);
    }

    #[test]
    fn strip_v_requires_a_digit() {
        assert_eq!(strip_v("v1.2.3"), "1.2.3");
        assert_eq!(strip_v("V2.0"), "2.0");
        assert_eq!(strip_v("version"), "version");
        assert_eq!(strip_v("v"), "v");
        assert_eq!(strip_v("1.2.3"), "1.2.3");
    }

    #[test]
    fn unquote_strips_one_matching_pair() {
        assert_eq!(unquote("\"1.2.3\""), "1.2.3");
        assert_eq!(unquote("'x'"), "x");
        assert_eq!(unquote("\"mismatched'"), "\"mismatched'");
        assert_eq!(unquote("plain"), "plain");
        assert_eq!(unquote("\"\""), "");
    }

    #[test]
    fn clean_value_cuts_unquoted_comments_only() {
        assert_eq!(clean_value("1.2.3  # pinned"), "1.2.3");
        assert_eq!(clean_value("\"has # inside\""), "has # inside");
        assert_eq!(clean_value("'v' # note"), "v");
        assert_eq!(clean_value("# all comment"), "");
    }

    #[test]
    fn line_finder_is_incremental_with_full_fallback() {
        let text = "alpha\nbeta\ngamma\nbeta\n";
        let mut finder = LineFinder::new(text);
        assert_eq!(finder.find("beta"), Some(2));
        assert_eq!(finder.find("beta"), Some(4)); // resumes past the first hit
        assert_eq!(finder.find("alpha"), Some(1)); // out of order: full rescan
        assert_eq!(finder.find("missing"), None);
    }

    #[test]
    fn path_ends_with_is_component_wise() {
        assert!(path_ends_with(
            Path::new("/sysroot/var/lib/dpkg/status"),
            &["var", "lib", "dpkg", "status"]
        ));
        // A mid-component string match must not count.
        assert!(!path_ends_with(
            Path::new("/backups/uvvar/lib/dpkg/status"),
            &["var", "lib", "dpkg", "status"]
        ));
        assert!(!path_ends_with(Path::new("status"), &["dpkg", "status"]));
    }

    #[test]
    fn strip_jsonc_removes_comments_and_trailing_commas() {
        let input = r#"{
  // line comment
  "a": "keep // not a comment",
  /* block
     comment */
  "b": [1, 2, 3,],
  "c": "tail", }"#;
        let cleaned = strip_jsonc(input);
        let value: serde_json::Value = serde_json::from_str(&cleaned).expect("valid JSON");
        assert_eq!(value["a"], "keep // not a comment");
        assert_eq!(value["b"][2], 3);
        assert_eq!(value["c"], "tail");
    }

    #[test]
    fn strip_jsonc_preserves_escapes_and_unicode() {
        let input = "{\"k\": \"a\\\"b // ok\", \"u\": \"é—✓\",}";
        let cleaned = strip_jsonc(input);
        let value: serde_json::Value = serde_json::from_str(&cleaned).expect("valid JSON");
        assert_eq!(value["k"], "a\"b // ok");
        assert_eq!(value["u"], "é—✓");
    }

    #[test]
    fn toml_package_array_yields_complete_entries() {
        let toml: toml::Value = toml::from_str(
            r#"
[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "incomplete"
"#,
        )
        .expect("valid toml");
        let entries: Vec<(&str, &str)> = toml_package_array(&toml)
            .map(|(name, version, _)| (name, version))
            .collect();
        assert_eq!(entries, vec![("serde", "1.0.0")]);
    }

    #[test]
    fn emitter_records_warnings_with_path() {
        let mut out = Vec::new();
        let mut warnings = Vec::new();
        let mut emitter = Emitter::new("npm", Path::new("lock.json"), &mut out, &mut warnings);
        emitter.warn("not valid JSON");
        assert_eq!(warnings, vec!["lock.json: not valid JSON".to_string()]);
    }
}
