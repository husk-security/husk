//! Homebrew Cellar keg receipts (`INSTALL_RECEIPT.json`): inventory-only
//! (no OSV ecosystem or advisory feed; Homebrew names collide with
//! PyPI/npm/Debian but are unrelated coordinates).
//!
//! Homebrew has no lockfile; the Cellar tree *is* the state. Each installed
//! formula lives at `<prefix>/Cellar/<name>/<pkgversion>/`; a *complete* keg
//! is signalled by its `INSTALL_RECEIPT.json`. The coordinate is encoded in
//! the directory path (version kept verbatim, including any `_<revision>`
//! suffix); the receipt's JSON does NOT store the formula name and is never
//! read; it serves purely as the "keg is complete" marker.

use super::support::Emitter;
use super::{ScanTarget, file_name};
use std::path::Path;

/// Homebrew Cellar keg receipt (`INSTALL_RECEIPT.json`).
pub struct HomebrewCellarTarget;

impl ScanTarget for HomebrewCellarTarget {
    fn ecosystem_id(&self) -> &'static str {
        "homebrew"
    }

    fn detects(&self, path: &Path) -> bool {
        // The `Cellar` ancestor requirement (component-wise) keeps a stray
        // same-named file from being hijacked, while container/chroot roots
        // and any `$HOMEBREW_PREFIX` still trigger.
        file_name(path) == Some("INSTALL_RECEIPT.json")
            && path
                .components()
                .rev()
                .skip(1)
                .any(|c| c.as_os_str() == "Cellar")
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        if let Some((name, version)) = name_and_version_from_path(path) {
            out.pkg(&name, &version, None);
        }
    }
}

/// Extract `(formula_name, pkgversion)` from a
/// `.../Cellar/<name>/<version>/INSTALL_RECEIPT.json` path. The name may
/// legitimately contain `@`/`+` (`openssl@3`). The exact path shape is the
/// only guard (the receipt's JSON is never parsed), so a stray nested
/// `INSTALL_RECEIPT.json` outside that layout must not emit a package.
fn name_and_version_from_path(path: &Path) -> Option<(String, String)> {
    if path.file_name()?.to_str()? != "INSTALL_RECEIPT.json" {
        return None;
    }
    let version_dir = path.parent()?;
    let name_dir = version_dir.parent()?;
    if name_dir.parent()?.file_name()?.to_str()? != "Cellar" {
        return None;
    }

    let version = version_dir.file_name()?.to_str()?.to_string();
    let name = name_dir.file_name()?.to_str()?.to_string();

    if name.is_empty() || version.is_empty() {
        return None;
    }
    // Homebrew formula names are already lowercase; preserve `@`/`+` verbatim.
    Some((name.to_ascii_lowercase(), version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn extracts_name_and_version_from_path() {
        let p = PathBuf::from("/opt/homebrew/Cellar/wget/1.25.0/INSTALL_RECEIPT.json");
        assert_eq!(
            name_and_version_from_path(&p),
            Some(("wget".to_string(), "1.25.0".to_string()))
        );

        // `@`-in-name versioned formula must NOT be split on `@`.
        let p = PathBuf::from("/usr/local/Cellar/openssl@3/3.4.1/INSTALL_RECEIPT.json");
        assert_eq!(
            name_and_version_from_path(&p),
            Some(("openssl@3".to_string(), "3.4.1".to_string()))
        );

        // The `_<revision>` packaging suffix is kept verbatim in the dir name.
        let p = PathBuf::from(
            "/home/linuxbrew/.linuxbrew/Cellar/python@3.12/3.12.7_1/INSTALL_RECEIPT.json",
        );
        assert_eq!(
            name_and_version_from_path(&p),
            Some(("python@3.12".to_string(), "3.12.7_1".to_string()))
        );
    }

    #[test]
    fn rejects_missing_version_dir() {
        let p = PathBuf::from("/opt/homebrew/Cellar/INSTALL_RECEIPT.json");
        assert_eq!(name_and_version_from_path(&p), None);
    }
}
