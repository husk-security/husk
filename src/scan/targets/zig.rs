//! Zig (`build.zig.zon` → no OSV ecosystem; inventory-only).
//!
//! `build.zig.zon` is ZON (Zig Object Notation): a single top-level anonymous
//! struct literal `.{ ... }`, NOT JSON and NOT TOML, so we hand-roll a tiny
//! line/brace scanner rather than reaching for a parser crate. It is both the
//! manifest *and* the lock: Zig pins dependencies by content hash, so there is
//! no separate lock file. Dependency coordinates come from the `.dependencies`
//! block: the field key is the name, and the version (when present) is encoded
//! in the modern (Zig >= 0.14) `.hash = "name-semver-digest"` string. Legacy
//! (<= 0.13) hashes are bare `1220` + 64 hex multihashes carrying no version.
//!
//! There is currently no OSV ecosystem, PURL type, or central advisory database
//! for Zig packages, so these coordinates are recorded for inventory/SBOM
//! purposes only. The authoritative pin is always the content hash.

use super::find_line;
use super::support::Emitter;

/// `build.zig.zon`: emit every fetched dependency from the `.dependencies`
/// block. (`.zig-cache/` is a build artifact, never a manifest.)
pub(super) fn build_zig_zon(contents: &str, out: &mut Emitter<'_>) {
    for dep in parse_zon_dependencies(contents) {
        let line = find_line(contents, &format!(".{}", dep.name));
        out.pkg(&dep.name, &dep.version, line);
    }
}

/// One emitted dependency coordinate (name + best-available version pin).
struct ZonDep {
    name: String,
    version: String,
}

/// Strip Zig `//` line comments, preserving anything inside double-quoted
/// strings (a `//` can legitimately appear inside a URL).
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else if c == b'"' {
            in_string = true;
        } else if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            return &line[..i];
        }
        i += 1;
    }
    line
}

/// Extract the string value of a `.field = "value"` ZON line, if present.
/// Returns the unescaped-enough-for-our-needs inner contents (we keep escapes
/// verbatim; hashes/urls never contain Zig escapes we care about).
fn field_string_value<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let line = line.trim();
    let key = format!(".{field}");
    let rest = line.strip_prefix(&key)?;
    // Require a real field boundary (`=` or whitespace), so `.path` doesn't
    // match `.paths`.
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    // Take up to the closing quote (ignoring escaped quotes is unnecessary for
    // hashes/urls, but handle the common case anyway).
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Does this trimmed line open a new dependency entry `.<name> = .{`?
/// Returns the dependency name. The key is a bare Zig identifier (no hyphens).
fn dependency_key(line: &str) -> Option<&str> {
    let line = line.trim();
    let rest = line.strip_prefix('.')?;
    let (ident, after) = rest.split_once('=')?;
    let ident = ident.trim();
    if ident.is_empty() || !is_zig_ident(ident) {
        return None;
    }
    if after.trim_start().starts_with(".{") {
        Some(ident)
    } else {
        None
    }
}

/// Bare Zig identifier: ASCII alnum + underscore, not starting with a digit.
fn is_zig_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Derive a version pin from a `.hash` string given the dependency name.
///
/// Modern (Zig >= 0.14): `name-semver-digest` where the digest is the FINAL
/// hyphen-separated token and the semver may itself contain hyphens (pre-release
/// / build metadata). We strip the leading `name-` and the trailing `-digest`.
///
/// Legacy (Zig <= 0.13): bare `1220` + 64 hex multihash, no embedded version;
/// fall back to the hash itself as the pin (content identity is all we have).
fn version_from_hash(hash: &str, name: &str) -> String {
    if is_legacy_multihash(hash) {
        return hash.to_string();
    }
    if let Some((before_digest, _digest)) = hash.rsplit_once('-') {
        let prefix = format!("{name}-");
        if let Some(version) = before_digest.strip_prefix(&prefix)
            && !version.is_empty()
        {
            return version.strip_prefix('v').unwrap_or(version).to_string();
        }
    }
    // Unrecognized hash shape (placeholder/garbage while awaiting `zig build`):
    // never panic; fall back to the raw hash as the pin.
    hash.to_string()
}

/// `1220` + exactly 64 lowercase/uppercase hex chars → legacy sha256 multihash.
fn is_legacy_multihash(hash: &str) -> bool {
    hash.len() == 68 && hash.starts_with("1220") && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Pure parser over ZON text. Walks the `.dependencies = .{ ... }` block and
/// emits one coordinate per fetched (url+hash) dependency; path/local deps are
/// skipped (no remote pin). Tolerates comments, trailing commas, missing or
/// empty `.dependencies`, and malformed entries.
fn parse_zon_dependencies(contents: &str) -> Vec<ZonDep> {
    let mut deps = Vec::new();

    let mut in_dependencies = false;
    let mut deps_depth = 0i32; // brace depth at which the deps block lives
    let mut depth = 0i32;

    let mut cur_name: Option<String> = None;
    let mut cur_depth = 0i32;
    let mut cur_hash: Option<String> = None;
    let mut cur_url: Option<String> = None;
    let mut cur_path: Option<String> = None;

    let finish_dep = |deps: &mut Vec<ZonDep>,
                      name: &str,
                      hash: Option<&str>,
                      url: Option<&str>,
                      path_dep: Option<&str>| {
        // Local/path dependency (no url+hash): skip; no remote pin.
        if path_dep.is_some() && url.is_none() && hash.is_none() {
            return;
        }
        deps.push(ZonDep {
            name: name.to_string(),
            version: match hash {
                Some(h) => version_from_hash(h, name),
                // url without hash, or a bare entry: record as unknown pin.
                None => "unknown".to_string(),
            },
        });
    };

    for raw in contents.lines() {
        let line = strip_comment(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Track entering the dependencies block before we mutate depth below.
        if !in_dependencies
            && (trimmed.starts_with(".dependencies") && trimmed.contains(".{"))
            && trimmed
                .strip_prefix(".dependencies")
                .map(|r| r.trim_start().starts_with('='))
                .unwrap_or(false)
        {
            in_dependencies = true;
            deps_depth = depth + 1; // entries live one level deeper
        }

        if in_dependencies && cur_name.is_none() && depth == deps_depth {
            if let Some(name) = dependency_key(trimmed) {
                cur_name = Some(name.to_string());
                cur_depth = depth + 1;
                cur_hash = None;
                cur_url = None;
                cur_path = None;
            }
        } else if cur_name.is_some() && depth == cur_depth {
            if let Some(v) = field_string_value(trimmed, "hash") {
                cur_hash = Some(v.to_string());
            } else if let Some(v) = field_string_value(trimmed, "url") {
                cur_url = Some(v.to_string());
            } else if let Some(v) = field_string_value(trimmed, "path") {
                cur_path = Some(v.to_string());
            }
        }

        for c in line.chars() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    // Closing the current dependency struct.
                    if let Some(name) = &cur_name
                        && depth < cur_depth
                    {
                        finish_dep(
                            &mut deps,
                            name,
                            cur_hash.as_deref(),
                            cur_url.as_deref(),
                            cur_path.as_deref(),
                        );
                        cur_name = None;
                    }
                    // Closing the dependencies block itself.
                    if in_dependencies && depth < deps_depth {
                        in_dependencies = false;
                    }
                }
                _ => {}
            }
        }
    }

    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modern_and_legacy_and_skips_path() {
        let zon = r#"
        .{
            .name = .my_app,
            .version = "0.3.1",
            .dependencies = .{
                .mime = .{
                    .url = "https://example.com/mime.tar.gz",
                    .hash = "mime-3.0.0-zwmL6wgAADuFwn7grDAQDGJdIim94aDIPa6qO6GT",
                },
                .chameleon = .{
                    .url = "https://example.com/chameleon.tar.gz",
                    .hash = "chameleon-2.1.0-rc.1-Vp9QwL3cAAB1nT2yqk4mXo7eRsBbkZ0aQ",
                    .lazy = true,
                },
                .zig_llm = .{
                    .url = "https://example.com/zig-llm.tar.gz",
                    .hash = "1220145cd26ccbbf94dd8c23c4d66acc4fbf56cec2c876592000732ce6b7481278b9",
                },
                .internal_util = .{
                    .path = "libs/internal_util",
                },
            },
        }
        "#;
        let deps = parse_zon_dependencies(zon);
        // path dep skipped → 3 fetched deps remain.
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "mime");
        assert_eq!(deps[0].version, "3.0.0");
        // semver with interior hyphen (pre-release) preserved.
        assert_eq!(deps[1].name, "chameleon");
        assert_eq!(deps[1].version, "2.1.0-rc.1");
        // legacy multihash carries no version → pin is the hash itself.
        assert_eq!(deps[2].name, "zig_llm");
        assert!(deps[2].version.starts_with("1220"));
    }

    #[test]
    fn handles_no_dependencies() {
        let zon = ".{ .name = .solo, .version = \"1.0.0\" }";
        assert!(parse_zon_dependencies(zon).is_empty());
    }

    #[test]
    fn version_from_hash_variants() {
        assert_eq!(version_from_hash("foo-1.2.3-abcDEF", "foo"), "1.2.3");
        assert_eq!(version_from_hash("foo-v1.2.3-abcDEF", "foo"), "1.2.3");
        let legacy = "1220".to_string() + &"a".repeat(64);
        assert_eq!(version_from_hash(&legacy, "bar"), legacy);
    }
}
