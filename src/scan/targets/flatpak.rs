//! Flatpak installed apps/runtimes: inventory-only (no OSV ecosystem).
//!
//! Flatpak has no manifest or lock file; an installation is a directory tree
//! (`~/.local/share/flatpak/`, `/var/lib/flatpak/`) laid out as
//! `<root>/{app,runtime}/<ID>/<ARCH>/<BRANCH>/<COMMIT>/metadata`. The
//! directory names are authoritative for the whole coordinate: name = ID
//! (reverse-DNS, verbatim, never lowercase), version = BRANCH verbatim
//! (`stable`, `47`: channel names, not semver; never strip a `v`). There is
//! no version field inside any text file (`metadata`'s `name=` is just the
//! ID). The bare filename `metadata` is extremely generic, so detection
//! requires the full path shape, discriminated by the 64-hex OSTree commit
//! dir. The INI is read (bounded, failure-visible) only to locate a friendly
//! `name=` provenance line; when unreadable the coordinate is still emitted
//! with `line: None`. The binary GVariant `deploy` file and the OSTree
//! `repo/` store are never parsed.

use super::ScanTarget;
use super::support::{Emitter, read_text};
use std::path::Path;

pub struct FlatpakTarget;

impl ScanTarget for FlatpakTarget {
    fn ecosystem_id(&self) -> &'static str {
        "flatpak"
    }

    fn detects(&self, path: &Path) -> bool {
        ref_dirs_from_metadata(path).is_some()
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(coord) = ref_dirs_from_metadata(path) else {
            return;
        };

        // An unreadable/over-cap metadata file warns but does NOT drop the
        // package; the INI only supplies the friendly source line.
        let line = read_text(path, out).and_then(|contents| super::find_line(&contents, "name="));
        out.pkg(&coord.id, &coord.branch, line);
    }
}

/// Only (ID, BRANCH) become the inventory (name, version); kind/arch/commit
/// are validated in [`ref_dirs_from_metadata`] but not stored.
#[derive(Debug, PartialEq, Eq)]
struct RefCoord {
    /// Reverse-DNS application/runtime id, e.g. `org.gnome.Calculator`.
    id: String,
    /// Branch directory: the canonical inventory "version" (`stable`, `47`).
    branch: String,
}

/// Derive the ref coordinate from a
/// `.../{app,runtime}/<ID>/<ARCH>/<BRANCH>/<COMMIT>/metadata` path. Pure path
/// inspection (no I/O) shared by `detects` and `parse`.
fn ref_dirs_from_metadata(path: &Path) -> Option<RefCoord> {
    if super::file_name(path)? != "metadata" {
        return None;
    }
    // Walk up: metadata -> <COMMIT> -> <BRANCH> -> <ARCH> -> <ID> -> <kind>.
    let commit_dir = path.parent()?;
    let branch_dir = commit_dir.parent()?;
    let arch_dir = branch_dir.parent()?;
    let id_dir = arch_dir.parent()?;
    let kind_dir = id_dir.parent()?;

    let commit = super::file_name(commit_dir)?;
    // The 64-hex OSTree checksum is the discriminator that prevents hijacking
    // unrelated `metadata` files.
    if !is_ostree_commit(commit) {
        return None;
    }

    if !matches!(super::file_name(kind_dir)?, "app" | "runtime") {
        return None;
    }

    let id = super::file_name(id_dir)?;
    let arch = super::file_name(arch_dir)?;
    let branch = super::file_name(branch_dir)?;
    if id.is_empty() || arch.is_empty() || branch.is_empty() || id.starts_with('.') {
        return None;
    }

    Some(RefCoord {
        id: id.to_string(),
        branch: branch.to_string(),
    })
}

/// A 64-char lowercase-hex OSTree commit checksum; Flatpak deploy
/// directories are always named this way.
fn is_ostree_commit(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const COMMIT: &str = "9a3c1f7b2d4e6a8c0f1234567890abcdef1234567890abcdef1234567890abe2";

    #[test]
    fn commit_detector_rejects_non_hex_and_uppercase() {
        assert!(is_ostree_commit(COMMIT));
        assert!(!is_ostree_commit("stable"));
        assert!(!is_ostree_commit(&COMMIT.to_uppercase()));
        assert!(!is_ostree_commit(&COMMIT[..63])); // wrong length
    }

    #[test]
    fn derives_coordinate_from_app_path() {
        let path = PathBuf::from(format!(
            "/home/u/.local/share/flatpak/app/org.gnome.Calculator/x86_64/stable/{COMMIT}/metadata"
        ));
        let coord = ref_dirs_from_metadata(&path).expect("matched");
        assert_eq!(coord.id, "org.gnome.Calculator");
        // Branch is the canonical version, kept verbatim.
        assert_eq!(coord.branch, "stable");
    }

    #[test]
    fn derives_coordinate_from_runtime_path_numeric_branch() {
        let rt_commit = "1b2d3e4f5a6b7c8d9e0f1122334455667788990011223344556677889900aaff";
        let path = PathBuf::from(format!(
            "/var/lib/flatpak/runtime/org.gnome.Platform/x86_64/47/{rt_commit}/metadata"
        ));
        let coord = ref_dirs_from_metadata(&path).expect("matched");
        assert_eq!(coord.id, "org.gnome.Platform");
        // Numeric branch preserved literally, no 'v' stripping.
        assert_eq!(coord.branch, "47");
    }

    #[test]
    fn unreadable_metadata_still_emits_coordinate_with_no_line() {
        // The metadata INI only supplies a friendly source line; when it
        // cannot be read (missing/unreadable, or over the read_text 64 MiB
        // cap), the directory-derived coordinate must still be emitted, with
        // line: None, and the failure must land in the warning channel.
        let path = PathBuf::from(format!(
            "/nonexistent-husk-test/app/org.gnome.Calculator/x86_64/stable/{COMMIT}/metadata"
        ));
        let mut packages = Vec::new();
        let mut warnings = Vec::new();
        let mut out =
            crate::scan::targets::Emitter::new("flatpak", &path, &mut packages, &mut warnings);
        FlatpakTarget.parse(&path, &mut out);

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "org.gnome.Calculator");
        assert_eq!(packages[0].version, "stable");
        assert_eq!(packages[0].line, None);
        assert_eq!(warnings.len(), 1, "read failure must be warned, not silent");
    }

    #[test]
    fn rejects_non_flatpak_metadata_paths() {
        // Right filename, wrong context (no app/runtime tree, commit not hex).
        assert!(ref_dirs_from_metadata(Path::new("/etc/some/metadata")).is_none());
        // Looks deep but the kind dir is not app/runtime.
        let path = PathBuf::from(format!(
            "/srv/data/extension/org.x/x86_64/stable/{COMMIT}/metadata"
        ));
        assert!(ref_dirs_from_metadata(&path).is_none());
    }
}
