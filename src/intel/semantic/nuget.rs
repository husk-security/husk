//! Upstream `version-nuget.go`: NuGet ordering; four numeric components and
//! case-insensitive prerelease comparison.
//!
//! See <https://learn.microsoft.com/en-us/nuget/concepts/package-versioning>

use super::semver::compare_build_components;
use super::semverlike::{SemverLikeVersion, parse_semver_like_version};
use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub struct NuGetVersion(SemverLikeVersion);

pub(super) fn parse(str: &str) -> NuGetVersion {
    NuGetVersion(parse_semver_like_version(str, 4))
}

impl NuGetVersion {
    pub(super) fn cmp(&self, other: &NuGetVersion) -> Ordering {
        let diff = self.0.components.cmp_components(&other.0.components);
        if diff != Ordering::Equal {
            return diff;
        }
        compare_build_components(&self.0.build.to_lowercase(), &other.0.build.to_lowercase())
    }
}
