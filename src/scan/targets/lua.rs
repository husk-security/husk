//! LuaRocks: pinned `luarocks.lock` and the installed rock tree
//! (`lib/luarocks/rocks-<luaver>/<name>/<version>-<rev>/`). Inventory-only:
//! no OSV ecosystem id or advisory feed keyed by rock name.
//!
//! Two sources (the walker hands us files, never directories):
//!   * `luarocks.lock`: a Lua program whose body is `return { ... }`,
//!     mapping dependency-class keys to `name = "version-rev"` tables. Fully
//!     pinned. Parsed with a tiny recursive-descent reader; we never eval
//!     Lua.
//!   * `rock_manifest`: inside every installed rock's version directory; the
//!     `(name, version-rev)` coordinate comes from the *directory names*
//!     alone, the file's contents (checksums) are never parsed.

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name};
use std::path::{Component, Path};

const LOCK_CLASSES: [&str; 3] = ["dependencies", "build_dependencies", "test_dependencies"];

pub struct LuaRocksTarget;

impl ScanTarget for LuaRocksTarget {
    fn ecosystem_id(&self) -> &'static str {
        "luarocks"
    }

    fn detects(&self, path: &Path) -> bool {
        match file_name(path) {
            Some("luarocks.lock") => true,
            // The bare name is too generic to trust outside a rocks tree.
            Some("rock_manifest") => in_rocks_tree(path),
            _ => false,
        }
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        match file_name(path) {
            Some("luarocks.lock") => {
                if let Some(contents) = read_text(path, out) {
                    parse_lock(&contents, out);
                }
            }
            Some("rock_manifest") => {
                if let Some((name, version)) = rock_coordinate(path) {
                    out.pkg(&name, version, None);
                }
            }
            _ => {}
        }
    }
}

/// True if `path` sits under a `rocks-<luaver>/` directory.
fn in_rocks_tree(path: &Path) -> bool {
    path.components().any(|c| match c {
        Component::Normal(seg) => seg
            .to_str()
            .is_some_and(|s| s.strip_prefix("rocks-").is_some_and(is_lua_ver)),
        _ => false,
    })
}

/// A Lua-version tag such as `5.1`, `5.4`: digits and dots only.
fn is_lua_ver(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// A LuaRocks `<version>-<revision>` directory name (`1.13.1-1`, `scm-1`,
/// `2.0.1beta-2`): the revision is the trailing `-<digits>` segment.
fn is_version_rev(s: &str) -> bool {
    match s.rsplit_once('-') {
        Some((upstream, rev)) => {
            !upstream.is_empty() && !rev.is_empty() && rev.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

/// Given `…/rocks-<luaver>/<name>/<version>-<rev>/rock_manifest`, recover the
/// `(name, version-rev)` coordinate purely from the directory names.
fn rock_coordinate(rock_manifest_path: &Path) -> Option<(String, &str)> {
    let version_dir = rock_manifest_path.parent()?;
    let version = file_name(version_dir)?;
    if !is_version_rev(version) {
        return None;
    }
    let name_dir = version_dir.parent()?;
    let name = file_name(name_dir)?;
    if name.is_empty() {
        return None;
    }
    // The name dir must itself live directly under a rocks-<luaver>/ dir.
    let tree = name_dir.parent()?;
    let is_tree = file_name(tree).is_some_and(|s| s.strip_prefix("rocks-").is_some_and(is_lua_ver));
    if !is_tree {
        return None;
    }
    // Rock names are conventionally lowercase; normalize for a stable coord.
    Some((name.to_ascii_lowercase(), version))
}

/// Parse the pinned name→version entries from a `luarocks.lock` body.
fn parse_lock(contents: &str, out: &mut Emitter<'_>) {
    let stripped = strip_lua_comments(contents);
    let mut p = Parser::new(&stripped);
    p.skip_ws();
    if p.peek_word() == Some("return") {
        p.consume_word("return");
    }
    let Some(root) = p.parse_table() else {
        return;
    };

    for (class, value) in &root.entries {
        if !LOCK_CLASSES.contains(&class.as_str()) {
            continue;
        }
        let LuaValue::Table(inner) = value else {
            continue;
        };
        for (name, val) in &inner.entries {
            // LuaRocks deliberately omits the `lua` interpreter from locks.
            if name == "lua" {
                continue;
            }
            let LuaValue::Str(version) = val else {
                continue;
            };
            let line = super::find_line(contents, version);
            out.pkg(&name.to_ascii_lowercase(), version, line);
        }
    }
}

/// Strip Lua comments (`-- line` and `--[[ block ]]`) without touching
/// string contents: double-quoted strings (with `\` escapes) are skipped
/// while scanning.
fn strip_lua_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut seg = 0; // start of the current verbatim run
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            i += 1;
            while i < bytes.len() {
                let c = bytes[i];
                i += 1;
                if c == b'\\' && i < bytes.len() {
                    i += 1;
                } else if c == b'"' {
                    break;
                }
            }
            continue;
        }
        if b == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            out.push_str(&src[seg..i]);
            i += 2;
            if i + 1 < bytes.len() && bytes[i] == b'[' && bytes[i + 1] == b'[' {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b']' && bytes[i + 1] == b']') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            } else {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            seg = i;
            continue;
        }
        i += 1;
    }
    out.push_str(&src[seg..]);
    out
}

/// Only strings and (nested) tables are needed for lock files.
enum LuaValue {
    Str(String),
    Table(LuaTable),
}

/// Ordered `key → value` entries; positional entries get an empty key
/// (tolerated, though lock files don't use them).
struct LuaTable {
    entries: Vec<(String, LuaValue)>,
}

struct Parser<'a> {
    src: &'a str,
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Parser {
            src,
            s: src.as_bytes(),
            i: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    /// Peek the next bareword identifier without consuming it.
    fn peek_word(&self) -> Option<&str> {
        let start = self.i;
        let mut j = start;
        while j < self.s.len() && (self.s[j].is_ascii_alphanumeric() || self.s[j] == b'_') {
            j += 1;
        }
        if j == start {
            None
        } else {
            std::str::from_utf8(&self.s[start..j]).ok()
        }
    }

    fn consume_word(&mut self, word: &str) {
        if self.peek_word() == Some(word) {
            self.i += word.len();
        }
    }

    fn read_ident(&mut self) -> Option<String> {
        let start = self.i;
        while self.i < self.s.len()
            && (self.s[self.i].is_ascii_alphanumeric() || self.s[self.i] == b'_')
        {
            self.i += 1;
        }
        if self.i == start {
            None
        } else {
            std::str::from_utf8(&self.s[start..self.i])
                .ok()
                .map(|s| s.to_string())
        }
    }

    /// Read a double-quoted string, decoding Lua `%q` escapes.
    fn read_string(&mut self) -> Option<String> {
        if self.peek() != Some(b'"') {
            return None;
        }
        self.i += 1;
        let mut out = String::new();
        let mut seg = self.i; // start of the current verbatim run
        while self.i < self.s.len() {
            let c = self.s[self.i];
            match c {
                b'"' => {
                    out.push_str(&self.src[seg..self.i]);
                    self.i += 1;
                    return Some(out);
                }
                b'\\' => {
                    out.push_str(&self.src[seg..self.i]);
                    self.i += 1;
                    let Some(&esc) = self.s.get(self.i) else {
                        seg = self.i;
                        break;
                    };
                    match esc {
                        b'n' => {
                            out.push('\n');
                            self.i += 1;
                        }
                        b't' => {
                            out.push('\t');
                            self.i += 1;
                        }
                        b'r' => {
                            out.push('\r');
                            self.i += 1;
                        }
                        b'0'..=b'9' => {
                            // 1-3 digit decimal byte escape (Lua %q format).
                            let mut val: u32 = 0;
                            let mut n = 0;
                            while n < 3 {
                                match self.s.get(self.i) {
                                    Some(d) if d.is_ascii_digit() => {
                                        val = val * 10 + u32::from(d - b'0');
                                        self.i += 1;
                                        n += 1;
                                    }
                                    _ => break,
                                }
                            }
                            if let Some(ch) = char::from_u32(val) {
                                out.push(ch);
                            }
                        }
                        _ => {
                            // Unknown escape (incl. `\"` and `\\`): the escaped
                            // char passes through verbatim as the start of the
                            // next run, so it can't terminate the string.
                            seg = self.i;
                            self.i += self.src[self.i..].chars().next().map_or(1, char::len_utf8);
                            continue;
                        }
                    }
                    seg = self.i;
                }
                _ => self.i += 1,
            }
        }
        // Unterminated string: keep whatever accumulated.
        out.push_str(&self.src[seg..self.i]);
        Some(out)
    }

    /// Read a `["quoted"]` table key, returning the inner string.
    fn read_bracket_key(&mut self) -> Option<String> {
        if self.peek() != Some(b'[') {
            return None;
        }
        self.i += 1;
        self.skip_ws();
        let key = self.read_string()?;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
        }
        Some(key)
    }

    /// Parse a Lua value (string or nested table); anything else is skipped.
    fn parse_value(&mut self) -> Option<LuaValue> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.read_string().map(LuaValue::Str),
            Some(b'{') => self.parse_table().map(LuaValue::Table),
            _ => None,
        }
    }

    /// Parse a `{ ... }` table. Returns whatever entries were read even if the
    /// input is truncated.
    fn parse_table(&mut self) -> Option<LuaTable> {
        self.skip_ws();
        if self.peek() != Some(b'{') {
            return None;
        }
        self.i += 1;
        let mut entries = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                None => break,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                Some(b',') | Some(b';') => {
                    self.i += 1;
                    continue;
                }
                _ => {}
            }

            let key = match self.peek() {
                Some(b'[') => self.read_bracket_key(),
                Some(b'"') => {
                    // Positional string value, OR rare `"k" = v`; peek for `=`.
                    let s = self.read_string();
                    self.skip_ws();
                    if self.peek() == Some(b'=') {
                        s
                    } else {
                        if let Some(val) = s {
                            entries.push((String::new(), LuaValue::Str(val)));
                        }
                        continue;
                    }
                }
                Some(c) if c.is_ascii_alphabetic() || c == b'_' => {
                    // Bareword: `ident = value` or a positional value.
                    let save = self.i;
                    let ident = self.read_ident();
                    self.skip_ws();
                    if self.peek() == Some(b'=') {
                        ident
                    } else {
                        // Not an assignment; rewind and treat as a value.
                        self.i = save;
                        if let Some(val) = self.parse_value() {
                            entries.push((String::new(), val));
                        } else {
                            self.i += 1; // ensure forward progress
                        }
                        continue;
                    }
                }
                Some(b'{') => {
                    if let Some(t) = self.parse_table() {
                        entries.push((String::new(), LuaValue::Table(t)));
                    }
                    continue;
                }
                _ => {
                    self.i += 1; // skip unexpected byte; keep making progress
                    continue;
                }
            };

            self.skip_ws();
            if self.peek() == Some(b'=') {
                self.i += 1;
            }
            let value = self.parse_value();
            if let (Some(k), Some(v)) = (key, value) {
                entries.push((k, v));
            }
        }
        Some(LuaTable { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_pinned_lock() {
        let body = r#"
return {
   dependencies = {
      luafilesystem = "1.8.0-1",
      penlight = "1.13.1-1",
      ["lua-cjson"] = "2.1.0.10-1",
      lua = "5.4"
   },
   build_dependencies = {
      busted = "2.2.0-1"
   }
}
"#;
        let pkgs = run_parser("luarocks", body, parse_lock);
        let mut got: Vec<(String, String)> = pkgs
            .iter()
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("busted".to_string(), "2.2.0-1".to_string()),
                ("lua-cjson".to_string(), "2.1.0.10-1".to_string()),
                ("luafilesystem".to_string(), "1.8.0-1".to_string()),
                ("penlight".to_string(), "1.13.1-1".to_string()),
            ]
        );
        // `lua` is deliberately excluded from the lock inventory.
        assert!(pkgs.iter().all(|p| p.name != "lua"));
        assert!(pkgs.iter().all(|p| p.ecosystem == "luarocks"));
    }

    #[test]
    fn tolerates_comments_and_trailing_separators() {
        let body = r#"
-- a hand-edited lock
return {
   dependencies = {
      foo = "1.0-1", -- inline note
      bar = "2.0-3";
   };
}
"#;
        let pkgs = run_parser("luarocks", body, parse_lock);
        let mut names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["bar", "foo"]);
    }

    #[test]
    fn rock_tree_coordinate_from_dirs() {
        let p =
            Path::new("/proj/lua_modules/lib/luarocks/rocks-5.4/penlight/1.13.1-1/rock_manifest");
        let (name, version) = rock_coordinate(p).expect("should derive coordinate");
        assert_eq!(name, "penlight");
        assert_eq!(version, "1.13.1-1");
    }

    #[test]
    fn rock_tree_rejects_non_version_dir() {
        // `doc` is not a `<version>-<rev>` directory.
        let p = Path::new("/usr/lib/luarocks/rocks-5.1/penlight/doc/rock_manifest");
        assert!(rock_coordinate(p).is_none());
    }

    #[test]
    fn detection_rules() {
        let t = LuaRocksTarget;
        assert!(t.detects(Path::new("/proj/luarocks.lock")));
        assert!(t.detects(Path::new(
            "/x/lib/luarocks/rocks-5.4/penlight/1.13.1-1/rock_manifest"
        )));
        // A bare rock_manifest outside a rocks-<ver> tree must not match.
        assert!(!t.detects(Path::new("/random/place/rock_manifest")));
        assert!(!t.detects(Path::new("/proj/foo.rockspec")));
    }
}
