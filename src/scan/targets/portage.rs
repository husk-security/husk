//! Gentoo Portage installed-package database (`/var/db/pkg/<cat>/<pf>/` VDB).
//!
//! Unlike every other target there is **no single manifest file**: the package
//! coordinates *are* the directory structure. Each installed package lives at
//! `/var/db/pkg/<category>/<PF>/` where `PF = ${PN}-${PVR}`, and every such leaf
//! directory contains a `CONTENTS` file (the installed-file manifest) plus tiny
//! single-line metadata files (`PF`, `CATEGORY`, `PN`, `PV`, `PR`, `SLOT`,
//! `repository`).
//!
//! We anchor detection on the per-package `CONTENTS` file (the one file present
//! in *every* genuine VDB entry) sitting inside a `.../var/db/pkg/<cat>/<pf>/`
//! layout, then read its sibling metadata files to extract the coordinate.
//!
//! There is **no OSV ecosystem** for Gentoo (advisories ship via GLSA, not
//! OSV.dev), so these coordinates are recorded as distro inventory only. The
//! canonical Gentoo identity is the qualified `category/PN` atom (bare PN
//! collides across categories), with the full pinned version `PVR`. The VDB is
//! 100% pinned by construction: every entry is an actually-installed build.

use super::ScanTarget;
use super::support::Emitter;
use std::fs;
use std::path::Path;

pub struct PortageTarget;

impl ScanTarget for PortageTarget {
    fn ecosystem_id(&self) -> &'static str {
        "gentoo"
    }

    /// Match the per-package `CONTENTS` file inside a Gentoo VDB layout, i.e.
    /// `.../var/db/pkg/<category-with-hyphen>/<pf>/CONTENTS`. Cheap: filename +
    /// ancestor-component checks only, no file reads.
    ///
    /// We require the `var/db/pkg` ancestor sequence (so a stray `CONTENTS`
    /// elsewhere never triggers) and a category directory containing a hyphen.
    /// The hyphen requirement also disambiguates from BSD `pkgsrc`, which uses a
    /// one-level `/var/db/pkg/<name-version>/` layout with `+CONTENTS` files.
    fn detects(&self, path: &Path) -> bool {
        is_vdb_contents(path)
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(coord) = path.parent().and_then(parse_package_dir) else {
            return;
        };
        out.pkg(&coord.qualified_name, &coord.full_version, None);
    }
}

/// Cheap structural check: is `path` a `CONTENTS` file inside
/// `.../var/db/pkg/<category-with-hyphen>/<pf>/`?
fn is_vdb_contents(path: &Path) -> bool {
    // Final component must be exactly `CONTENTS` (not `+CONTENTS`, which is BSD
    // pkgsrc, a different ecosystem that also lives under /var/db/pkg).
    if path.file_name().and_then(|n| n.to_str()) != Some("CONTENTS") {
        return false;
    }
    let Some(pkg_dir) = path.parent() else {
        return false;
    };
    let Some(cat_dir) = pkg_dir.parent() else {
        return false;
    };
    // The category directory name must contain a hyphen (e.g. `app-editors`),
    // which Gentoo categories always do and BSD pkgsrc's single-level layout
    // does not have a sibling for.
    let Some(cat_name) = cat_dir.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if !cat_name.contains('-') {
        return false;
    }
    has_vdb_ancestors(cat_dir)
}

/// True if `cat_dir`'s ancestry ends in `.../var/db/pkg` (the VDB root). We walk
/// up looking for three consecutive components `var`, `db`, `pkg`.
fn has_vdb_ancestors(cat_dir: &Path) -> bool {
    let Some(pkg) = cat_dir.parent() else {
        return false;
    };
    if pkg.file_name().and_then(|n| n.to_str()) != Some("pkg") {
        return false;
    }
    let Some(db) = pkg.parent() else {
        return false;
    };
    if db.file_name().and_then(|n| n.to_str()) != Some("db") {
        return false;
    }
    let Some(var) = db.parent() else {
        return false;
    };
    var.file_name().and_then(|n| n.to_str()) == Some("var")
}

/// A resolved Gentoo package coordinate.
struct Coord {
    /// `category/PN`, e.g. `app-editors/vim`: the stable Gentoo identity.
    qualified_name: String,
    /// Full pinned version `PVR`, e.g. `9.1.0496-r1` (the `-r0` revision omitted).
    full_version: String,
}

/// Read the metadata files in a VDB package directory and resolve its
/// coordinate. Prefers the explicit `PN`/`PV`/`PR`/`CATEGORY` files (robust)
/// and falls back to splitting the directory name (`PF`) for very old VDBs.
///
/// Tolerant: any individual unreadable/missing file is filled from the fallback
/// path; returns `None` only when we cannot determine name + version at all.
fn parse_package_dir(pkg_dir: &Path) -> Option<Coord> {
    // The directory name is PF = ${PN}-${PVR}; also serves as the fallback.
    let pf = read_meta(pkg_dir, "PF").or_else(|| {
        pkg_dir
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
    })?;

    let category = read_meta(pkg_dir, "CATEGORY").or_else(|| {
        pkg_dir
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .map(str::to_string)
    })?;

    let (name, full_version) = resolve_name_version(pkg_dir, &pf)?;
    if name.is_empty() || full_version.is_empty() {
        return None;
    }

    Some(Coord {
        qualified_name: format!("{category}/{name}"),
        full_version,
    })
}

fn read_meta(pkg_dir: &Path, file: &str) -> Option<String> {
    let value = fs::read_to_string(pkg_dir.join(file)).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn resolve_name_version(pkg_dir: &Path, pf: &str) -> Option<(String, String)> {
    if let (Some(pn), Some(pv)) = (read_meta(pkg_dir, "PN"), read_meta(pkg_dir, "PV")) {
        let pr = read_meta(pkg_dir, "PR").unwrap_or_else(|| "r0".to_string());
        let full_version = combine_version(&pv, &pr);
        return Some((pn, full_version));
    }
    // Fallback for old VDBs lacking PN/PV: split the PF directory name.
    split_pf(pf)
}

/// Combine a bare version `PV` with a revision `PR` into the full `PVR`. `r0`
/// (the default revision) is omitted from the human-facing version.
fn combine_version(pv: &str, pr: &str) -> String {
    if pr.is_empty() || pr == "r0" {
        pv.to_string()
    } else {
        format!("{pv}-{pr}")
    }
}

/// Split a `PF` string (`${PN}-${PVR}`) into `(PN, PVR)` using the PMS rule:
/// the boundary is the FIRST `-`-separated segment (scanning left to right)
/// that *starts with a digit* and whose join with all following segments is a
/// valid full version. Package names may themselves contain hyphens and `+`
/// (e.g. `gtk+-3`, `libsigc++-2.10`), so a naive last-hyphen split is wrong.
fn split_pf(pf: &str) -> Option<(String, String)> {
    let segments: Vec<&str> = pf.split('-').collect();
    for i in 1..segments.len() {
        let seg = segments[i];
        if !seg.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            continue;
        }
        let candidate = segments[i..].join("-");
        if is_full_version(&candidate) {
            let name = segments[..i].join("-");
            if !name.is_empty() {
                return Some((name, candidate));
            }
        }
    }
    None
}

/// Validate that `s` matches the PMS full-version grammar (hand-written, no
/// regex):
///   version  := number ('.' number)* [letter] (suffix)* ['-r' integer]
///   suffix   := ('_alpha'|'_beta'|'_pre'|'_rc'|'_p') [0-9]*  (may chain)
fn is_full_version(s: &str) -> bool {
    // Peel off an optional `-rN` revision tail first.
    let core = match s.split_once("-r") {
        Some((head, rev)) if !rev.is_empty() && rev.bytes().all(|b| b.is_ascii_digit()) => head,
        Some(_) => return false, // `-r` present but malformed revision
        None => s,
    };
    is_version_core(core)
}

/// Validate the version core (everything before any `-rN` revision):
/// `number('.'number)* [letter] (suffix)*`.
fn is_version_core(core: &str) -> bool {
    if core.is_empty() {
        return false;
    }
    // Split numeric dotted prefix from the optional letter+suffix tail at the
    // first `_` (suffix marker) or the trailing single letter.
    let (numeric_part, tail) = match core.find('_') {
        Some(idx) => (&core[..idx], &core[idx..]),
        None => (core, ""),
    };

    if !is_dotted_number_with_optional_letter(numeric_part) {
        return false;
    }
    if tail.is_empty() {
        return true;
    }
    are_suffixes(tail)
}

/// `number('.'number)* [single lowercase letter]`.
fn is_dotted_number_with_optional_letter(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let digits_dots = match s.as_bytes().last() {
        Some(&b) if b.is_ascii_lowercase() => &s[..s.len() - 1],
        _ => s,
    };
    if digits_dots.is_empty() {
        return false;
    }
    digits_dots
        .split('.')
        .all(|comp| !comp.is_empty() && comp.bytes().all(|b| b.is_ascii_digit()))
}

/// A chain of `_(alpha|beta|pre|rc|p)[0-9]*` suffixes, e.g. `_alpha1_p2`.
fn are_suffixes(mut tail: &str) -> bool {
    const KINDS: [&str; 5] = ["alpha", "beta", "pre", "rc", "p"];
    while !tail.is_empty() {
        let Some(rest) = tail.strip_prefix('_') else {
            return false;
        };
        // Match the longest kind keyword that prefixes `rest`. Check longer
        // keywords first so `pre`/`p` and `alpha`/etc. resolve correctly.
        let mut matched: Option<&str> = None;
        for kind in KINDS {
            if rest.starts_with(kind) && matched.is_none_or(|m| kind.len() > m.len()) {
                matched = Some(kind);
            }
        }
        let Some(kind) = matched else {
            return false;
        };
        let after_kind = &rest[kind.len()..];
        // Optional trailing digits, then either end or the next `_suffix`.
        let digit_end = after_kind.find('_').unwrap_or(after_kind.len());
        let (digits, remainder) = after_kind.split_at(digit_end);
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        tail = remainder;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_simple_pf() {
        assert_eq!(
            split_pf("vim-9.1.0496-r1"),
            Some(("vim".to_string(), "9.1.0496-r1".to_string()))
        );
    }

    #[test]
    fn splits_pf_without_revision() {
        assert_eq!(
            split_pf("openssl-3.3.1"),
            Some(("openssl".to_string(), "3.3.1".to_string()))
        );
    }

    #[test]
    fn splits_name_with_hyphen_and_plus() {
        // Package names may contain hyphens and `+`; the version-anchored split
        // must keep them in the name.
        assert_eq!(
            split_pf("gtk+-2.24.33"),
            Some(("gtk+".to_string(), "2.24.33".to_string()))
        );
        assert_eq!(
            split_pf("foo-bar-2.0"),
            Some(("foo-bar".to_string(), "2.0".to_string()))
        );
    }

    #[test]
    fn splits_digit_in_name() {
        // `libgit2-1.7.2`: the `2` in the name is not a version boundary.
        assert_eq!(
            split_pf("libgit2-1.7.2"),
            Some(("libgit2".to_string(), "1.7.2".to_string()))
        );
    }

    #[test]
    fn validates_versions() {
        assert!(is_full_version("9.1.0496-r1"));
        assert!(is_full_version("3.3.1"));
        assert!(is_full_version("1.2b"));
        assert!(is_full_version("1.0_alpha1_p2"));
        assert!(is_full_version("2.0_rc1"));
        assert!(is_full_version("1.0_p20240101"));
        assert!(!is_full_version("not-a-version"));
        assert!(!is_full_version("1.2-rx"));
        assert!(!is_full_version(""));
    }

    #[test]
    fn combines_version_omitting_r0() {
        assert_eq!(combine_version("3.3.1", "r0"), "3.3.1");
        assert_eq!(combine_version("9.1.0496", "r1"), "9.1.0496-r1");
    }

    #[test]
    fn detects_vdb_contents_layout() {
        let p = Path::new("/var/db/pkg/app-editors/vim-9.1.0496-r1/CONTENTS");
        assert!(is_vdb_contents(p));
        // BSD pkgsrc uses `+CONTENTS` and a flat layout; must not match.
        assert!(!is_vdb_contents(Path::new("/var/db/pkg/vim-9.1/+CONTENTS")));
        assert!(!is_vdb_contents(Path::new("/home/me/proj/CONTENTS")));
        // Category dir without a hyphen must not match.
        assert!(!is_vdb_contents(Path::new(
            "/var/db/pkg/editors/vim-9.1/CONTENTS"
        )));
    }
}
