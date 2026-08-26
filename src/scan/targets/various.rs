//! Long-tail language registries that OSV covers directly:
//! Hex (`mix.lock`), Pub (`pubspec.lock`), Swift (`Package.resolved`),
//! CRAN (`renv.lock`), Julia (`Manifest.toml`), Hackage (cabal freeze).

use super::find_line;
use super::support::Emitter;
use serde_json::Value as JsonValue;

/// mix.lock: `  "phoenix": {:hex, :phoenix, "1.6.0", ...},` per entry.
pub(super) fn mix_lock(contents: &str, out: &mut Emitter<'_>) {
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if !line.contains("{:hex,") {
            continue;
        }
        let quoted: Vec<&str> = quoted_tokens(line);
        if let (Some(name), Some(version)) = (quoted.first(), quoted.get(1))
            && !name.is_empty()
            && !version.is_empty()
        {
            out.pkg(name, version, Some(idx + 1));
        }
    }
}

/// pubspec.lock: `packages:` block, one `<name>:` entry with a nested
/// `version: "x"` scalar.
pub(super) fn pubspec_lock(contents: &str, out: &mut Emitter<'_>) {
    let mut in_packages = false;
    let mut current: Option<(String, usize)> = None;
    for (idx, raw) in contents.lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        if !raw.starts_with(' ') {
            in_packages = raw.trim_end() == "packages:";
            current = None;
            continue;
        }
        if !in_packages {
            continue;
        }
        let indent = raw.chars().take_while(|c| *c == ' ').count();
        let trimmed = raw.trim();
        if indent == 2 && trimmed.ends_with(':') {
            current = Some((trimmed.trim_end_matches(':').to_string(), idx + 1));
        } else if let Some(version) = trimmed.strip_prefix("version:")
            && let Some((name, line)) = &current
        {
            let version = version.trim().trim_matches('"').trim_matches('\'');
            if !version.is_empty() {
                out.pkg(name, version, Some(*line));
            }
        }
    }
}

/// Package.resolved (Swift PM): v2 `{"pins": [...]}` or v1
/// `{"object": {"pins": [...]}}`.
pub(super) fn package_resolved(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("Package.resolved is not valid JSON");
        return;
    };
    let pins = json
        .get("pins")
        .or_else(|| json.get("object").and_then(|o| o.get("pins")))
        .and_then(|v| v.as_array());
    let Some(pins) = pins else {
        return;
    };
    for pin in pins {
        let Some(version) = pin
            .get("state")
            .and_then(|s| s.get("version"))
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        // OSV `SwiftURL` is keyed on the repository URL, so prefer the
        // location (scheme/`.git` stripped); fall back to the identity.
        let name = pin
            .get("location")
            .and_then(|v| v.as_str())
            .map(normalize_swift_url)
            .or_else(|| {
                pin.get("identity")
                    .or_else(|| pin.get("package"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            });
        if let Some(name) = name {
            out.pkg(&name, version, None);
        }
    }
}

fn normalize_swift_url(url: &str) -> String {
    url.trim_end_matches(".git")
        .trim_start_matches("https://")
        .trim_start_matches("git@")
        .replace(':', "/")
        .to_string()
}

/// renv.lock (R): `{"Packages": {"<name>": {"Package": …, "Version": …}}}`.
pub(super) fn renv_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("renv.lock is not valid JSON");
        return;
    };
    let Some(entries) = json.get("Packages").and_then(|v| v.as_object()) else {
        return;
    };
    for entry in entries.values() {
        let (Some(name), Some(version)) = (
            entry.get("Package").and_then(|v| v.as_str()),
            entry.get("Version").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        out.pkg(name, version, find_line(contents, name));
    }
}

/// Manifest.toml (Julia, manifest format 2.0): `[[deps.<Name>]]` arrays.
pub(super) fn julia_manifest(contents: &str, out: &mut Emitter<'_>) {
    let Ok(toml) = toml::from_str::<toml::Value>(contents) else {
        out.warn("Manifest.toml is not valid TOML");
        return;
    };
    let Some(deps) = toml.get("deps").and_then(|v| v.as_table()) else {
        return;
    };
    for (name, value) in deps {
        let Some(entries) = value.as_array() else {
            continue;
        };
        for entry in entries {
            if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
                out.pkg(name, version, find_line(contents, name));
            }
        }
    }
}

/// cabal.project.freeze: `constraints:` lists `any.<pkg> ==<ver>,` entries.
pub(super) fn cabal_freeze(contents: &str, out: &mut Emitter<'_>) {
    for (idx, raw) in contents.lines().enumerate() {
        for token in raw.split(',') {
            let token = token.trim().trim_start_matches("constraints:").trim();
            let Some((name, version)) = token.split_once("==") else {
                continue;
            };
            let name = name.trim().trim_start_matches("any.").trim();
            let version = version.trim();
            if !name.is_empty()
                && !name.contains(' ')
                && version.starts_with(|c: char| c.is_ascii_digit())
            {
                out.pkg(name, version, Some(idx + 1));
            }
        }
    }
}

/// Collect the contents of each double-quoted run in `line`, in order.
fn quoted_tokens(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i + 1;
            if let Some(rel) = line[start..].find('"') {
                out.push(&line[start..start + rel]);
                i = start + rel + 1;
                continue;
            }
            break;
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_hex_line() {
        let line = r#"  "phoenix": {:hex, :phoenix, "1.6.0", "abc", [:mix], [], "hexpm"},"#;
        let q = quoted_tokens(line);
        assert_eq!(q.first().copied(), Some("phoenix"));
        assert_eq!(q.get(1).copied(), Some("1.6.0"));
    }

    #[test]
    fn normalizes_swift_url() {
        assert_eq!(
            normalize_swift_url("https://github.com/apple/swift-nio.git"),
            "github.com/apple/swift-nio"
        );
    }

    #[test]
    fn parses_pubspec_lock_block() {
        // The blank line between entries must not end the `packages:` block.
        let lock = "packages:\n  http:\n    dependency: \"direct main\"\n    version: \"0.13.5\"\n\n  path:\n    dependency: transitive\n    version: \"1.8.3\"\nsdks:\n  dart: \">=2.0.0\"\n";
        let found: Vec<(String, String)> = run_parser("pub", lock, pubspec_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(
            found,
            vec![
                ("http".to_string(), "0.13.5".to_string()),
                ("path".to_string(), "1.8.3".to_string()),
            ]
        );
    }

    #[test]
    fn parses_cabal_freeze_constraints() {
        let freeze = "constraints: any.aeson ==2.1.0.0,\n             any.base ==4.17.0.0\n";
        let found: Vec<(String, String)> = run_parser("hackage", freeze, cabal_freeze)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(
            found,
            vec![
                ("aeson".to_string(), "2.1.0.0".to_string()),
                ("base".to_string(), "4.17.0.0".to_string()),
            ]
        );
    }

    #[test]
    fn malformed_json_manifests_yield_nothing() {
        assert!(run_parser("swift", "not json", package_resolved).is_empty());
        assert!(run_parser("cran", "{broken", renv_lock).is_empty());
        assert!(run_parser("julia", "[[deps", julia_manifest).is_empty());
    }
}
