//! .NET / JVM. NuGet `packages.lock.json` → OSV `NuGet`; Gradle
//! `gradle.lockfile` → OSV `Maven`.

use super::support::{Emitter, LineFinder};
use serde_json::Value as JsonValue;

/// packages.lock.json (NuGet):
/// `{ "dependencies": { "<framework>": { "<name>": { "resolved": "x" } } } }`.
pub(super) fn nuget_packages_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("packages.lock.json is not valid JSON");
        return;
    };
    let Some(frameworks) = json.get("dependencies").and_then(|v| v.as_object()) else {
        return;
    };
    let mut lines = LineFinder::new(contents);
    for entries in frameworks.values() {
        let Some(entries) = entries.as_object() else {
            continue;
        };
        for (name, entry) in entries {
            let Some(version) = entry.get("resolved").and_then(|v| v.as_str()) else {
                continue;
            };
            // Preserve the registered casing: although NuGet itself is
            // case-insensitive, OSV's NuGet ecosystem matches names
            // CASE-SENSITIVELY (verified against api.osv.dev), so
            // lowercasing here silently drops every NuGet advisory.
            out.pkg(name, version, lines.find(name));
        }
    }
}

/// gradle.lockfile: `group:artifact:version=conf1,conf2` lines. A trailing
/// `empty=...` line lists configurations with no dependencies.
pub(super) fn gradle_lockfile(contents: &str, out: &mut Emitter<'_>) {
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
            continue;
        }
        let coord = line.split('=').next().unwrap_or(line);
        let mut parts = coord.split(':');
        let (Some(group), Some(artifact), Some(version)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if group.is_empty() || artifact.is_empty() || version.is_empty() {
            continue;
        }
        // OSV/Maven coordinate form is `group:artifact`.
        out.pkg(&format!("{group}:{artifact}"), version, Some(idx + 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_gradle_lockfile() {
        let lock = "# Gradle lockfile\n\
                    com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\n\
                    empty=annotationProcessor\n";
        let found: Vec<(String, String)> = run_parser("maven", lock, gradle_lockfile)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(
            found,
            vec![("com.google.guava:guava".to_string(), "31.1-jre".to_string())]
        );
    }

    #[test]
    fn nuget_preserves_registered_casing() {
        // OSV's NuGet ecosystem matches names case-sensitively, so the
        // packages.lock.json casing must be kept verbatim (NOT lowercased).
        let lock = r#"{"version":1,"dependencies":{"net6.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.1"}}}}"#;
        let found: Vec<String> = run_parser("nuget", lock, nuget_packages_lock)
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(found, vec!["Newtonsoft.Json".to_string()]);
    }

    #[test]
    fn malformed_nuget_lock_yields_nothing() {
        assert!(run_parser("nuget", "{not json", nuget_packages_lock).is_empty());
    }
}
