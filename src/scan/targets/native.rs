//! C / C++. Conan (`conan.lock` → OSV `ConanCenter`) and CocoaPods
//! (`Podfile.lock`). CocoaPods has no OSV ecosystem yet, so its coordinates are
//! inventory-only until an advisory source covers it.

use super::support::Emitter;
use serde_json::Value as JsonValue;

/// conan.lock (Conan 2.x): `{ "requires": ["name/version#rev%timestamp", …] }`.
pub(super) fn conan_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("conan.lock is not valid JSON");
        return;
    };
    for section in ["requires", "build_requires", "python_requires"] {
        let Some(entries) = json.get(section).and_then(|v| v.as_array()) else {
            continue;
        };
        for entry in entries {
            let Some(reference) = entry.as_str() else {
                continue;
            };
            if let Some((name, version)) = parse_conan_ref(reference) {
                out.pkg(&name, &version, None);
            }
        }
    }
}

/// `zlib/1.2.13#revision%timestamp` → (`zlib`, `1.2.13`).
fn parse_conan_ref(reference: &str) -> Option<(String, String)> {
    let (name, rest) = reference.split_once('/')?;
    let version = rest.split(['#', '@', '%']).next().unwrap_or(rest).trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Podfile.lock: `PODS:` block, `  - Alamofire (5.6.4)` entries. Subspecs
/// (`AFNetworking/Core`) collapse to the root pod.
pub(super) fn podfile_lock(contents: &str, out: &mut Emitter<'_>) {
    let mut in_pods = false;
    for (idx, raw) in contents.lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        if !raw.starts_with(' ') && !raw.starts_with('-') {
            in_pods = raw.trim_end() == "PODS:";
            continue;
        }
        if !in_pods {
            continue;
        }
        // `  - Alamofire (5.6.4)` or `  - AFNetworking/Core (= 4.0.1)`
        let trimmed = raw.trim().trim_start_matches("- ").trim();
        if let Some((name, version)) = parse_pod_line(trimmed) {
            let root = name.split('/').next().unwrap_or(&name);
            out.pkg(root, &version, Some(idx + 1));
        }
    }
}

/// `Alamofire (5.6.4)` → (`Alamofire`, `5.6.4`). Dependency requirement lines
/// (`(~> 5.0)`, `(= 4.0.1)`) without a bare version are skipped.
fn parse_pod_line(line: &str) -> Option<(String, String)> {
    let (name, rest) = line.split_once(" (")?;
    let version = rest.trim_end_matches(')').trim();
    if version.starts_with(|c: char| c.is_ascii_digit()) {
        Some((name.trim().to_string(), version.to_string()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_conan_ref() {
        assert_eq!(
            parse_conan_ref("zlib/1.2.13#abc123%1234"),
            Some(("zlib".to_string(), "1.2.13".to_string()))
        );
    }

    #[test]
    fn parses_pod_lines() {
        assert_eq!(
            parse_pod_line("Alamofire (5.6.4)"),
            Some(("Alamofire".to_string(), "5.6.4".to_string()))
        );
        assert_eq!(parse_pod_line("AFNetworking (~> 4.0)"), None);
    }

    #[test]
    fn subspecs_collapse_to_the_root_pod() {
        // The blank line between entries must not end the `PODS:` block.
        let lock =
            "PODS:\n  - AFNetworking/Core (4.0.1)\n\n  - AFNetworking/Reachability (4.0.1)\n";
        let found: Vec<(String, String)> = run_parser("cocoapods", lock, podfile_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        // Both subspecs emit the root pod; discovery dedups per manifest.
        assert_eq!(found.len(), 2);
        assert!(
            found
                .iter()
                .all(|(n, v)| n == "AFNetworking" && v == "4.0.1")
        );
    }
}
