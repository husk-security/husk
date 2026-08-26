//! Upstream `version-semver.go`: Semver 2.0.0 ordering, shared by every
//! ecosystem whose versions are semver (crates.io, npm, Go, Hex, ...).

use super::BigDigits;
use super::semverlike::{SemverLikeVersion, parse_semver_like_version};
use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub struct SemverVersion(pub(super) SemverLikeVersion);

pub(super) fn parse(str: &str) -> SemverVersion {
    SemverVersion(parse_semver_like_version(str, 3))
}

impl SemverVersion {
    pub(super) fn cmp(&self, other: &SemverVersion) -> Ordering {
        let diff = self.0.components.cmp_components(&other.0.components);
        if diff != Ordering::Equal {
            return diff;
        }
        compare_build_components(&self.0.build, &other.0.build)
    }
}

/// Remove build metadata per Semver 2.0.0 item 10.
fn remove_build_metadata(str: &str) -> &str {
    str.split('+').next().unwrap_or(str)
}

pub(super) fn compare_build_components(a: &str, b: &str) -> Ordering {
    let a = remove_build_metadata(a);
    let b = remove_build_metadata(b);
    // The spec doesn't say to exclude the hyphen from the compare, but
    // node-semver does, so upstream follows it.
    let a = a.strip_prefix('-').unwrap_or(a);
    let b = b.strip_prefix('-').unwrap_or(b);

    // Versions with a prerelease are less than those without (item 9).
    if a.is_empty() && !b.is_empty() {
        return Ordering::Greater;
    }
    if !a.is_empty() && b.is_empty() {
        return Ordering::Less;
    }
    compare_semver_build_components(
        &a.split('.').collect::<Vec<_>>(),
        &b.split('.').collect::<Vec<_>>(),
    )
}

fn compare_semver_build_components(a: &[&str], b: &[&str]) -> Ordering {
    let min_len = a.len().min(b.len());
    for i in 0..min_len {
        let ai = BigDigits::parse(a[i]);
        let bi = BigDigits::parse(b[i]);
        let compare = match (ai, bi) {
            // 1. Only-digit identifiers compare numerically.
            (Some(ai), Some(bi)) => ai.cmp(&bi),
            // 2. Identifiers with letters or hyphens compare lexically.
            (None, None) => a[i].cmp(b[i]),
            // 3. Numeric identifiers have lower precedence.
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
        };
        if compare != Ordering::Equal {
            return compare;
        }
    }
    // 4. More pre-release fields wins when all preceding ones are equal.
    a.len().cmp(&b.len())
}
