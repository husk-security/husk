//! Upstream `version-hackage.go`: Hackage (Haskell) ordering; unlimited
//! numeric components, no build suffix allowed, longer wins on ties.

use super::semver::compare_build_components;
use super::semverlike::{SemverLikeVersion, parse_semver_like_version};
use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub struct HackageVersion(SemverLikeVersion);

pub(super) fn parse(str: &str) -> Option<HackageVersion> {
    let v = parse_semver_like_version(str, -1);
    // Technically reachable through the semver-like parser; invalid here.
    if !v.build.is_empty() {
        return None;
    }
    Some(HackageVersion(v))
}

impl HackageVersion {
    pub(super) fn cmp(&self, other: &HackageVersion) -> Ordering {
        let diff = self.0.components.cmp_components(&other.0.components);
        if diff != Ordering::Equal {
            return diff;
        }
        let diff =
            compare_build_components(&self.0.build.to_lowercase(), &other.0.build.to_lowercase());
        if diff != Ordering::Equal {
            return diff;
        }
        self.0.components.len().cmp(&other.0.components.len())
    }
}
