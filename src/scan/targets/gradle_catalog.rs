//! Gradle version catalog (`*.versions.toml`) → OSV `Maven`.
//!
//! Unlike `gradle.lockfile` ([`super::jvm::gradle_lockfile`], the
//! authoritative *resolved* source), a catalog holds *declared* coordinates
//! (usually pins, but legally ranges, `+` dynamic versions, or rich-version
//! tables) and omits transitives: a best-effort inventory. The coordinate
//! name is the canonical Maven `group:artifact` (case-sensitive); the TOML
//! alias key is an arbitrary handle and must NOT be used as the name.

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name, find_line};
use std::path::Path;
use toml::Value as TomlValue;

pub struct GradleCatalogTarget;

impl ScanTarget for GradleCatalogTarget {
    fn ecosystem_id(&self) -> &'static str {
        "maven"
    }

    fn detects(&self, path: &Path) -> bool {
        // The `.versions.toml` suffix is highly Gradle-specific; the table
        // shape is still validated in `parse`.
        file_name(path).is_some_and(|name| name.ends_with(".versions.toml"))
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        // toml 1.x: a whole document parses as a `Table`
        // (`str::parse::<Value>()` now expects a bare value).
        let Ok(table) = contents.parse::<toml::Table>() else {
            out.warn("version catalog is not valid TOML");
            return;
        };
        for (name, version) in parse_catalog(&TomlValue::Table(table)) {
            let line = find_line(&contents, &name).or_else(|| find_line(&contents, &version));
            out.pkg(&name, &version, line);
        }
    }
}

struct Declared {
    /// Canonical Maven `group:artifact`.
    name: String,
    /// Declared version (may be a range/dynamic spec, not a resolved pin).
    version: String,
}

/// Any `.toml` without the catalog shape (`[versions]`/`[libraries]`/
/// `[plugins]`) yields nothing.
fn parse_catalog(value: &TomlValue) -> Vec<(String, String)> {
    let Some(table) = value.as_table() else {
        return Vec::new();
    };
    let versions_tbl = table.get("versions").and_then(TomlValue::as_table);
    let libraries_tbl = table.get("libraries").and_then(TomlValue::as_table);
    let plugins_tbl = table.get("plugins").and_then(TomlValue::as_table);
    if versions_tbl.is_none() && libraries_tbl.is_none() && plugins_tbl.is_none() {
        return Vec::new();
    }

    let mut version_map: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    if let Some(versions) = versions_tbl {
        for (alias, v) in versions {
            if let Some(resolved) = resolve_version_value(v) {
                version_map.insert(alias.as_str(), resolved);
            }
        }
    }

    let mut out: Vec<(String, String)> = Vec::new();

    if let Some(libraries) = libraries_tbl {
        for lib in libraries.values() {
            if let Some(decl) = resolve_library(lib, &version_map) {
                out.push((decl.name, decl.version));
            }
        }
    }

    if let Some(plugins) = plugins_tbl {
        for plugin in plugins.values() {
            if let Some(decl) = resolve_plugin(plugin, &version_map) {
                out.push((decl.name, decl.version));
            }
        }
    }

    // `[bundles]` carry no coordinates; skipped. Duplicate declarations are
    // fine: discovery dedups globally per (coordinate, manifest).
    out
}

/// Resolve a single `[libraries]` entry: a bare `group:artifact:version`
/// string, or a table with `module = "g:a"` / `group = .. , name = ..`.
fn resolve_library(
    lib: &TomlValue,
    version_map: &std::collections::HashMap<&str, String>,
) -> Option<Declared> {
    if let Some(s) = lib.as_str() {
        let mut parts = s.split(':');
        let (group, artifact, version) = (parts.next()?, parts.next()?, parts.next()?);
        if group.is_empty() || artifact.is_empty() || version.is_empty() {
            return None;
        }
        return Some(Declared {
            name: format!("{group}:{artifact}"),
            version: version.to_string(),
        });
    }

    let table = lib.as_table()?;
    let name = if let Some(module) = table.get("module").and_then(TomlValue::as_str) {
        let mut parts = module.split(':');
        let (group, artifact) = (parts.next()?, parts.next()?);
        if group.is_empty() || artifact.is_empty() {
            return None;
        }
        format!("{group}:{artifact}")
    } else {
        let group = table.get("group").and_then(TomlValue::as_str)?;
        let artifact = table.get("name").and_then(TomlValue::as_str)?;
        if group.is_empty() || artifact.is_empty() {
            return None;
        }
        format!("{group}:{artifact}")
    };

    let version = resolve_table_version(table.get("version"), version_map)?;
    Some(Declared { name, version })
}

/// Resolve the `version` field of a library/plugin table to a single string.
/// Handles the three mutually-exclusive forms: plain string, `version.ref`
/// (nested table with a `ref` key), and a rich-version table.
fn resolve_table_version(
    version: Option<&TomlValue>,
    version_map: &std::collections::HashMap<&str, String>,
) -> Option<String> {
    let version = version?;
    if let Some(s) = version.as_str() {
        return Some(s.to_string());
    }
    let table = version.as_table()?;
    // `version.ref = "alias"` → dotted-key sugar for `version = { ref = "alias" }`.
    if let Some(reference) = table.get("ref").and_then(TomlValue::as_str) {
        return version_map.get(reference).cloned();
    }
    resolve_rich(table)
}

/// Resolve a bare `[versions]` value (string or rich-version table).
fn resolve_version_value(v: &TomlValue) -> Option<String> {
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    resolve_rich(v.as_table()?)
}

/// Pick a single representative version from a rich-version table in priority
/// order `require` > `strictly` > `prefer` (ignore `reject`/`rejectAll`).
fn resolve_rich(table: &toml::map::Map<String, TomlValue>) -> Option<String> {
    for key in ["require", "strictly", "prefer"] {
        if let Some(s) = table.get(key).and_then(TomlValue::as_str) {
            return Some(s.to_string());
        }
    }
    None
}

/// Resolve a `[plugins]` entry to a synthetic Maven marker coordinate
/// `<id>:<id>.gradle.plugin`.
fn resolve_plugin(
    plugin: &TomlValue,
    version_map: &std::collections::HashMap<&str, String>,
) -> Option<Declared> {
    let table = plugin.as_table()?;
    let id = table.get("id").and_then(TomlValue::as_str)?;
    if id.is_empty() {
        return None;
    }
    let version = resolve_table_version(table.get("version"), version_map)?;
    Some(Declared {
        name: format!("{id}:{id}.gradle.plugin"),
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coords(input: &str) -> Vec<(String, String)> {
        let table: toml::Table = input.parse().expect("valid toml in test");
        parse_catalog(&TomlValue::Table(table))
    }

    #[test]
    fn parses_version_catalog() {
        let input = r#"
[versions]
guava = "32.1.2-jre"
spring = "5.3.29"

[libraries]
guava = { module = "com.google.guava:guava", version.ref = "guava" }
spring-core = { group = "org.springframework", name = "spring-core", version.ref = "spring" }
commons-lang3 = "org.apache.commons:commons-lang3:3.12.0"

[plugins]
spring-boot = { id = "org.springframework.boot", version = "3.1.2" }

[bundles]
common = ["guava", "spring-core"]
"#;
        let found = coords(input);
        assert!(found.contains(&(
            "com.google.guava:guava".to_string(),
            "32.1.2-jre".to_string()
        )));
        assert!(found.contains(&(
            "org.springframework:spring-core".to_string(),
            "5.3.29".to_string()
        )));
        assert!(found.contains(&(
            "org.apache.commons:commons-lang3".to_string(),
            "3.12.0".to_string()
        )));
        // Plugin marker artifact.
        assert!(found.contains(&(
            "org.springframework.boot:org.springframework.boot.gradle.plugin".to_string(),
            "3.1.2".to_string()
        )));
    }

    #[test]
    fn handles_rich_version_table() {
        let input = r#"
[versions]
[libraries]
foo = { module = "com.example:foo", version = { strictly = "[1.0,2.0)", prefer = "1.5" } }
bar = { module = "com.example:bar", version = { require = "2.0.0" } }
"#;
        let found = coords(input);
        // require beats strictly; for foo only strictly present.
        assert!(found.contains(&("com.example:foo".to_string(), "[1.0,2.0)".to_string())));
        assert!(found.contains(&("com.example:bar".to_string(), "2.0.0".to_string())));
    }

    #[test]
    fn plugins_only_catalog_is_recognized() {
        // A catalog can legally carry ONLY [plugins]; the shape guard must
        // not skip it before the plugin marker coordinates are emitted.
        let input = r#"
[plugins]
spring-boot = { id = "org.springframework.boot", version = "3.1.2" }
"#;
        let found = coords(input);
        assert_eq!(
            found,
            vec![(
                "org.springframework.boot:org.springframework.boot.gradle.plugin".to_string(),
                "3.1.2".to_string()
            )]
        );
    }

    #[test]
    fn ignores_non_catalog_toml() {
        // A Cargo.toml-shaped file has no [versions]/[libraries] tables.
        let input = r#"
[package]
name = "thing"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#;
        assert!(coords(input).is_empty());
    }

    #[test]
    fn skips_missing_version_ref() {
        // version.ref pointing at a non-existent alias is malformed: skip it.
        let input = r#"
[versions]
[libraries]
broken = { module = "com.example:broken", version.ref = "nope" }
ok = "com.example:ok:1.0.0"
"#;
        let found = coords(input);
        assert!(found.contains(&("com.example:ok".to_string(), "1.0.0".to_string())));
        assert!(!found.iter().any(|(n, _)| n == "com.example:broken"));
    }
}
