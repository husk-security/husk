//! Upstream `version-cran.go`: CRAN (R) ordering; two-plus non-negative
//! integers separated by periods or dashes, longer wins on equal prefixes.

use super::{BigDigits, Components};
use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub struct CranVersion(Components);

pub(super) fn parse(str: &str) -> Option<CranVersion> {
    // Upstream treats an empty version string as valid, for now.
    if str.is_empty() {
        return Some(CranVersion(Components::default()));
    }
    // Dashes and periods carry the same weight.
    let normalized = str.replace('-', ".");
    let mut components = Vec::new();
    for part in normalized.split('.') {
        components.push(BigDigits::parse(part)?);
    }
    Some(CranVersion(Components(components)))
}

impl CranVersion {
    pub(super) fn cmp(&self, other: &CranVersion) -> Ordering {
        let diff = self.0.cmp_components(&other.0);
        if diff != Ordering::Equal {
            return diff;
        }
        // Equal only with the same number of components; longer is greater.
        self.0.len().cmp(&other.0.len())
    }
}
