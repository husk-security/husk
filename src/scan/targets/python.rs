//! Python / PyPI. requirements.txt pins, poetry.lock, Pipfile.lock, uv.lock,
//! pdm.lock. All resolve to OSV ecosystem `PyPI`.

use super::pep503_name;
use super::support::{Emitter, LineFinder, toml_package_array};
use serde_json::Value as JsonValue;

/// requirements.txt: one `name==version` pin per line.
pub(super) fn requirements_txt(contents: &str, out: &mut Emitter<'_>) {
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("-r ") {
            continue;
        }
        if let Some((name, version)) = split_python_pin(trimmed) {
            out.pkg(&name, &version, Some(idx + 1));
        }
    }
}

/// poetry.lock / uv.lock / pdm.lock share a `[[package]]` array of tables with
/// `name` + `version` keys.
pub(super) fn pep_toml_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(toml) = toml::from_str::<toml::Value>(contents) else {
        out.warn("lockfile is not valid TOML");
        return;
    };
    let mut lines = LineFinder::new(contents);
    for (name, version, _) in toml_package_array(&toml) {
        let line = lines.find(&format!("name = \"{name}\""));
        let name = normalized_python_name(name).unwrap_or_else(|| name.to_ascii_lowercase());
        out.pkg(&name, version, line);
    }
}

/// Pipfile.lock: `default` / `develop` maps of `name -> {"version": "==x"}`.
pub(super) fn pipfile_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("Pipfile.lock is not valid JSON");
        return;
    };
    for section_name in ["default", "develop"] {
        let Some(section) = json.get(section_name).and_then(|value| value.as_object()) else {
            continue;
        };
        for (name, entry) in section {
            let Some(version) = entry.get("version").and_then(|value| value.as_str()) else {
                continue;
            };
            let version = version.trim_start_matches('=');
            if !version.is_empty() {
                out.pkg(
                    &normalized_python_name(name).unwrap_or_else(|| name.to_ascii_lowercase()),
                    version,
                    super::find_line(contents, name),
                );
            }
        }
    }
}

fn split_python_pin(line: &str) -> Option<(String, String)> {
    let without_marker = line.split(';').next()?.trim();
    let without_comment = without_marker.split('#').next()?.trim();
    for operator in ["===", "=="] {
        if let Some((name, version)) = without_comment.split_once(operator) {
            let name = normalized_python_name(name.trim())?;
            let version = version
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            if !version.is_empty() {
                return Some((name, version));
            }
        }
    }
    None
}

fn normalized_python_name(name: &str) -> Option<String> {
    let name = name.split('[').next()?.trim();
    let normalized = pep503_name(name);
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_requirement_pins() {
        assert_eq!(
            split_python_pin("Django[postgres]==2.2.0 # old"),
            Some(("django".to_string(), "2.2.0".to_string()))
        );
    }

    #[test]
    fn names_are_pep503_canonical() {
        assert_eq!(
            split_python_pin("zope.interface==5.0"),
            Some(("zope-interface".to_string(), "5.0".to_string()))
        );
        assert_eq!(
            split_python_pin("Flask_Cors==4.0.0"),
            Some(("flask-cors".to_string(), "4.0.0".to_string()))
        );
        assert_eq!(
            split_python_pin("a__b..c--d==1"),
            Some(("a-b-c-d".to_string(), "1".to_string()))
        );
    }

    #[test]
    fn parses_poetry_style_toml_locks() {
        let lock = "[[package]]\nname = \"Django\"\nversion = \"2.2.0\"\n";
        let found: Vec<(String, String)> = run_parser("pypi", lock, pep_toml_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(found, vec![("django".to_string(), "2.2.0".to_string())]);
    }

    #[test]
    fn parses_pipfile_lock_sections() {
        let lock = r#"{"default":{"requests":{"version":"==2.31.0"}},"develop":{"pytest":{"version":"==8.0.0"}}}"#;
        let found: Vec<(String, String)> = run_parser("pypi", lock, pipfile_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(
            found,
            vec![
                ("requests".to_string(), "2.31.0".to_string()),
                ("pytest".to_string(), "8.0.0".to_string()),
            ]
        );
    }
}
