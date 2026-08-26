//! Rust / Cargo. Cargo.lock → OSV ecosystem `crates.io`.

use super::support::{Emitter, LineFinder, toml_package_array};

/// Cargo.lock: the `[[package]]` array of resolved crates.
pub(super) fn cargo_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(toml) = toml::from_str::<toml::Value>(contents) else {
        out.warn("Cargo.lock is not valid TOML");
        return;
    };
    let mut lines = LineFinder::new(contents);
    for (name, version, _) in toml_package_array(&toml) {
        out.pkg(name, version, lines.find(&format!("name = \"{name}\"")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_cargo_lock_packages() {
        let lock = r#"
version = 3

[[package]]
name = "serde"
version = "1.0.200"

[[package]]
name = "time"
version = "0.1.12"
"#;
        let found: Vec<(String, String, Option<usize>)> = run_parser("cargo", lock, cargo_lock)
            .into_iter()
            .map(|p| (p.name, p.version, p.line))
            .collect();
        assert_eq!(
            found,
            vec![
                ("serde".to_string(), "1.0.200".to_string(), Some(5)),
                ("time".to_string(), "0.1.12".to_string(), Some(9)),
            ]
        );
    }

    #[test]
    fn malformed_lockfile_yields_nothing() {
        assert!(run_parser("cargo", "[[package]\nname = ", cargo_lock).is_empty());
    }
}
