//! Upstream `version-pub.go`: Pub (Dart) ordering; semver with build
//! metadata as a final lexical tiebreak.

use super::semver::compare_build_components;
use super::semverlike::{SemverLikeVersion, parse_semver_like_version};
use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub struct PubVersion(SemverLikeVersion);

pub(super) fn parse(str: &str) -> PubVersion {
    PubVersion(parse_semver_like_version(str, 3))
}

impl PubVersion {
    pub(super) fn cmp(&self, other: &PubVersion) -> Ordering {
        let diff = self.0.components.cmp_components(&other.0.components);
        if diff != Ordering::Equal {
            return diff;
        }
        let diff = compare_build_components(&self.0.build, &other.0.build);
        if diff != Ordering::Equal {
            return diff;
        }
        let a_build = self.0.build.split_once('+').map(|(_, b)| b).unwrap_or("");
        let b_build = other.0.build.split_once('+').map(|(_, b)| b).unwrap_or("");
        a_build.cmp(b_build)
    }
}
