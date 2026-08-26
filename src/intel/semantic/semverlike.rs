//! Upstream `version-semver-like.go`: a version that is *like* a Semantic
//! Version, except with potentially unlimited numeric components and a
//! leading `v`.

use super::{BigDigits, Components, is_ascii_digit};

#[derive(Clone, Debug)]
pub(super) struct SemverLikeVersion {
    #[allow(dead_code)]
    pub(super) leading_v: bool,
    pub(super) components: Components,
    pub(super) build: String,
    #[allow(dead_code)]
    pub(super) original: String,
}

pub(super) fn parse_semver_like_version(line: &str, max_components: isize) -> SemverLikeVersion {
    let v = parse_semver_like(line);
    let (components, build) = fetch_components_and_build(&v, max_components);
    SemverLikeVersion {
        leading_v: v.leading_v,
        components,
        build,
        original: v.original,
    }
}

fn fetch_components_and_build(
    v: &SemverLikeVersion,
    max_components: isize,
) -> (Components, String) {
    if max_components == -1 || v.components.len() <= max_components as usize {
        return (v.components.clone(), v.build.clone());
    }
    let max = max_components as usize;
    let components = Components(v.components.0[..max].to_vec());
    let mut build = v.build.clone();
    for extra in &v.components.0[max..] {
        build.push('.');
        build.push_str(&extra.digits_string());
    }
    (components, build)
}

impl BigDigits {
    /// The decimal rendering upstream produces with `%d` when folding excess
    /// components into the build string.
    pub(crate) fn digits_string(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }
        let mut rendered = String::new();
        if self.is_negative() {
            rendered.push('-');
        }
        rendered.push_str(self.digits());
        rendered
    }
}

fn parse_semver_like(line: &str) -> SemverLikeVersion {
    let original = line.to_string();
    let leading_v = line.starts_with('v');
    let line = line.strip_prefix('v').unwrap_or(line);

    let mut components = Vec::new();
    let mut current = String::new();
    let mut found_build = false;

    for c in line.chars() {
        if found_build {
            current.push(c);
            continue;
        }
        if is_ascii_digit(c) {
            current.push(c);
            continue;
        }
        // Terminate the component being parsed, if any. Upstream ignores the
        // conversion error here, appending a nil big.Int that compares as
        // zero; an empty current between separators appends nothing.
        if !current.is_empty() {
            components.push(BigDigits::parse(&current).unwrap_or_else(BigDigits::zero));
            current = String::new();
        }
        if c == '.' {
            continue;
        }
        found_build = true;
        current = c.to_string();
    }

    if !found_build && !current.is_empty() {
        components.push(BigDigits::parse(&current).unwrap_or_else(BigDigits::zero));
        current = String::new();
    }

    SemverLikeVersion {
        leading_v,
        components: Components(components),
        build: current,
        original,
    }
}
