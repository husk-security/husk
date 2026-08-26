//! pnpm catalog (`pnpm-workspace.yaml`) → OSV `npm`.
//!
//! Since pnpm 9.5, a workspace can centralize dependency version specifiers in
//! *catalogs* declared in `pnpm-workspace.yaml` (the single workspace-root
//! config file). Two top-level keys carry them:
//!   * `catalog:`  - the implicit `default` catalog, a `name: spec` mapping.
//!   * `catalogs:` - a map of *named* catalogs, each itself a `name: spec`
//!     mapping (e.g. `react17`, `react18` holding different React pins).
//!
//! Workspace member `package.json` files reference these with the literal
//! specifier `"catalog:"` / `"catalog:<name>"`, a *pointer*, never a version;
//! the resolved version lives only here. The separate `pnpm-lock.yaml` records
//! a resolved snapshot but is a different detector; we own only the
//! *declaration* file to avoid double-counting.
//!
//! Catalog values are arbitrary npm SEMVER SPECIFIERS, not guaranteed pins, so
//! we emit coordinates only for bare exact pins (e.g. `1.2.3`, `=1.2.3`,
//! `v1.2.3`); ranges / aliases / `workspace:` / `catalog:` etc. are skipped;
//! they cannot resolve to a single advisory version statically. Names are
//! emitted verbatim (npm names are already lowercase; scopes preserved).
//!
//! No YAML crate is available, so the small flat block-mapping subset that
//! pnpm-workspace.yaml uses is hand-parsed (indentation-based).

use super::exact_semver_pin;
use super::support::{Emitter, LineFinder, clean_value, indent_of, unquote};

/// Emit the exact-pin catalog entries of a pnpm-workspace.yaml body. The same
/// pin appearing in several catalogs is emitted each time; discovery's global
/// per-(coordinate, manifest) dedup collapses the duplicates.
pub(super) fn catalogs(contents: &str, out: &mut Emitter<'_>) {
    let mut lines = LineFinder::new(contents);
    for (name, version) in parse_catalogs(contents) {
        let line = lines.find(&name);
        out.pkg(&name, &version, line);
    }
}

/// Pure parse helper: extract `(name, version)` exact pins from the
/// `catalog:` / `catalogs:` blocks of a pnpm-workspace.yaml string.
fn parse_catalogs(contents: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    // Block we are currently collecting entries from.
    enum Block {
        /// Other top-level key; ignore its children.
        Other,
        /// Top-level `catalog:`; its direct children are entries.
        DefaultCatalog,
        /// Top-level `catalogs:`; its children are catalog-name headers,
        /// whose grandchildren are entries.
        NamedCatalogs,
    }
    let mut block = Block::Other;
    // Indent of the entries we currently accept (set when we enter a block).
    let mut entry_indent: Option<usize> = None;

    for raw in contents.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "---" || trimmed.starts_with('#') {
            continue;
        }
        // Tabs are invalid YAML indentation; be conservative and skip.
        if raw.starts_with('\t') {
            continue;
        }

        let indent = indent_of(raw);

        if indent == 0 {
            entry_indent = None;
            let key = top_level_key(trimmed);
            block = match key {
                Some("catalog") => {
                    // Inline flow-mapping form: `catalog: { a: 1.0.0, ... }`.
                    if let Some(flow) = inline_flow(trimmed) {
                        for (n, v) in parse_flow(flow) {
                            push_pin(&mut out, &n, &v);
                        }
                        Block::Other
                    } else {
                        Block::DefaultCatalog
                    }
                }
                Some("catalogs") => Block::NamedCatalogs,
                _ => Block::Other,
            };
            continue;
        }

        match block {
            Block::Other => {}
            Block::DefaultCatalog => {
                // Direct children at the first indent we see are entries.
                let depth = *entry_indent.get_or_insert(indent);
                if indent == depth
                    && let Some((name, spec)) = split_entry(trimmed)
                    && let Some(version) = normalize_pin(&spec)
                {
                    push_pin(&mut out, &name, &version);
                }
            }
            Block::NamedCatalogs => {
                // Child = catalog-name header (`react17:` with no value, or an
                // inline flow mapping). Grandchild = entry. We accept any line
                // deeper than the header indent as an entry, which is robust to
                // mixed indent widths in real files.
                if split_entry_value(trimmed).is_some() {
                    if let Some((name, spec)) = split_entry(trimmed)
                        && let Some(version) = normalize_pin(&spec)
                    {
                        push_pin(&mut out, &name, &version);
                    }
                } else if let Some(flow) = inline_flow(trimmed) {
                    // Header with inline flow mapping: `react17: { react: 17.0.2 }`.
                    for (n, v) in parse_flow(flow) {
                        push_pin(&mut out, &n, &v);
                    }
                }
                // A bare `name:` header (no value) is structural; skip it.
            }
        }
    }

    out
}

fn push_pin(out: &mut Vec<(String, String)>, name: &str, version: &str) {
    if !name.is_empty() && !version.is_empty() {
        out.push((name.to_string(), version.to_string()));
    }
}

/// For an indent-0 line `key:` or `key: value`, return the bare key (quotes
/// stripped) when it is a plain mapping key.
fn top_level_key(trimmed: &str) -> Option<&str> {
    let colon = trimmed.find(':')?;
    let key = trimmed[..colon].trim();
    // Defensive: top-level catalog keys are never quoted; a bare match suffices.
    if key.is_empty() { None } else { Some(key) }
}

/// If a line's value is an inline flow mapping `{ ... }`, return the inside.
fn inline_flow(trimmed: &str) -> Option<&str> {
    let colon = trimmed.find(':')?;
    let value = trimmed[colon + 1..].trim();
    let inner = value.strip_prefix('{')?.strip_suffix('}')?;
    Some(inner.trim())
}

/// Parse an inline flow mapping body `a: 1.0.0, b: 2.0.0` into pinned entries.
fn parse_flow(inner: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for part in inner.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, spec)) = split_entry(part)
            && let Some(version) = normalize_pin(&spec)
        {
            out.push((name, version));
        }
    }
    out
}

/// Return the trimmed value half of a `key: value` line iff it has a non-empty
/// value (used to distinguish entries from bare catalog-name headers).
fn split_entry_value(trimmed: &str) -> Option<String> {
    let (_, spec) = split_entry(trimmed)?;
    if spec.is_empty() { None } else { Some(spec) }
}

/// Split a `name: spec` mapping line into `(name, spec)`, stripping a trailing
/// inline comment and surrounding quotes on each side. Returns `None` if there
/// is no `:` separating key and value.
fn split_entry(trimmed: &str) -> Option<(String, String)> {
    // Find the first `:` that is not inside a quoted key. Keys may be quoted
    // (e.g. `"@scope/pkg"`); honor that by skipping over a leading quoted span.
    let bytes = trimmed.as_bytes();
    let colon = if bytes.first() == Some(&b'"') || bytes.first() == Some(&b'\'') {
        let quote = bytes[0] as char;
        let close = trimmed[1..].find(quote)? + 1;
        let rest = &trimmed[close + 1..];
        let rel = rest.find(':')?;
        close + 1 + rel
    } else {
        trimmed.find(':')?
    };

    let name = unquote(trimmed[..colon].trim()).to_string();
    let spec = clean_value(trimmed[colon + 1..].trim()).to_string();
    Some((name, spec))
}

/// Apply the PIN FILTER: keep ONLY a bare exact semver pin, normalized to the
/// advisory key form. Returns `None` for any range / alias / keyword / pointer.
fn normalize_pin(spec: &str) -> Option<String> {
    exact_semver_pin(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coords(input: &str) -> Vec<(String, String)> {
        parse_catalogs(input)
    }

    #[test]
    fn extracts_default_and_named_pins_and_skips_ranges() {
        let input = r#"
packages:
  - "packages/*"
  - "apps/*"

catalog:
  # exact pins — EXTRACT these
  left-pad: 1.3.0
  "@scope/utils": 2.4.1
  # ranges — SKIP
  react: ^18.2.0
  typescript: ~5.4.0
  lodash: "*"

catalogs:
  react17:
    react: 17.0.2          # exact pin — EXTRACT
    react-dom: 17.0.2      # exact pin — EXTRACT
  react18:
    react: ^18.3.1         # range — SKIP
    react-dom: "18.3.1"    # exact pin (quoted) — EXTRACT
  misc:
    semver: =7.5.4         # =exact — EXTRACT as 7.5.4
    aliased: "npm:underscore@1.13.6"   # alias — SKIP by default
    ws-dep: "workspace:*"  # workspace — SKIP

overrides:
  glob: 9.0.0
"#;
        let found = coords(input);
        assert!(found.contains(&("left-pad".to_string(), "1.3.0".to_string())));
        assert!(found.contains(&("@scope/utils".to_string(), "2.4.1".to_string())));
        assert!(found.contains(&("react".to_string(), "17.0.2".to_string())));
        assert!(found.contains(&("react-dom".to_string(), "17.0.2".to_string())));
        assert!(found.contains(&("react-dom".to_string(), "18.3.1".to_string())));
        assert!(found.contains(&("semver".to_string(), "7.5.4".to_string())));

        assert!(
            !found
                .iter()
                .any(|(n, v)| n == "react" && v.starts_with('^'))
        );
        assert!(!found.iter().any(|(n, _)| n == "typescript"));
        assert!(!found.iter().any(|(n, _)| n == "lodash"));
        assert!(!found.iter().any(|(n, _)| n == "aliased"));
        assert!(!found.iter().any(|(n, _)| n == "ws-dep"));

        // `overrides:` block must NOT contribute findings.
        assert!(!found.iter().any(|(n, _)| n == "glob"));

        // Distinct versions of the same name both kept.
        let react_dom: Vec<_> = found.iter().filter(|(n, _)| n == "react-dom").collect();
        assert_eq!(react_dom.len(), 2);
    }

    #[test]
    fn normalize_pin_filter() {
        assert_eq!(normalize_pin("1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(normalize_pin("=1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(normalize_pin("v1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(normalize_pin("2.0.0-rc.1"), Some("2.0.0-rc.1".to_string()));
        assert_eq!(normalize_pin("1.2.3+build.5"), Some("1.2.3".to_string()));
        assert_eq!(normalize_pin("^1.2.3"), None);
        assert_eq!(normalize_pin("~1.2.3"), None);
        assert_eq!(normalize_pin(">=1.2.0"), None);
        assert_eq!(normalize_pin("1.2.x"), None);
        assert_eq!(normalize_pin("1.2"), None);
        assert_eq!(normalize_pin("*"), None);
        assert_eq!(normalize_pin("latest"), None);
        assert_eq!(normalize_pin("1.2.3 || 2.0.0"), None);
        assert_eq!(normalize_pin("npm:underscore@1.13.6"), None);
        assert_eq!(normalize_pin("workspace:*"), None);
        assert_eq!(normalize_pin("catalog:"), None);
        assert_eq!(normalize_pin(""), None);
    }

    #[test]
    fn handles_inline_flow_mapping() {
        let input = r#"
catalog: { react: 18.0.0, foo: ^1.0.0 }
"#;
        let found = coords(input);
        assert!(found.contains(&("react".to_string(), "18.0.0".to_string())));
        assert!(!found.iter().any(|(n, _)| n == "foo"));
    }

    #[test]
    fn empty_and_malformed_degrade_to_zero() {
        assert!(coords("").is_empty());
        assert!(coords("catalog:\n").is_empty());
        assert!(coords("packages:\n  - 'a/*'\n").is_empty());
    }
}
