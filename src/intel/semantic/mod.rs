//! Ecosystem-native version parsing and comparison for OSV matching.
//!
//! A Rust port of Google's `osv-scalibr/semantic` package (Apache-2.0,
//! Copyright Google LLC; see the license note in the repository), kept
//! behaviorally identical and validated against the upstream project's own
//! test fixtures under `tst/semantic/`. Where upstream uses `big.Int`,
//! this port compares normalized decimal digit strings, which is equivalent
//! for the arbitrary-precision integers version strings contain.
//!
//! One comparator family serves many ecosystems (the same aliasing as
//! upstream's `Parse`): Semver covers crates.io/npm/Go/Hex and friends,
//! Debian covers Ubuntu, Red Hat covers the RPM distros, Alpine covers the
//! apk distros.

mod alpine;
mod cran;
mod debian;
mod hackage;
mod maven;
mod nuget;
mod packagist;
mod pubver;
mod pypi;
mod redhat;
mod rubygems;
mod semver;
mod semverlike;

use std::cmp::Ordering;

/// A parsed, comparable version in one ecosystem's ordering.
#[derive(Clone, Debug)]
pub enum Version {
    Alpine(alpine::AlpineVersion),
    Cran(cran::CranVersion),
    Debian(debian::DebianVersion),
    Hackage(hackage::HackageVersion),
    Maven(maven::MavenVersion),
    NuGet(nuget::NuGetVersion),
    Packagist(packagist::PackagistVersion),
    Pub(pubver::PubVersion),
    PyPI(pypi::PyPIVersion),
    RedHat(redhat::RedHatVersion),
    RubyGems(rubygems::RubyGemsVersion),
    Semver(semver::SemverVersion),
}

/// Compare two version strings under `ecosystem`'s rules. `None` means the
/// ecosystem is unsupported or a version failed to parse; callers treat that
/// as "not locally evaluable", never as a verdict.
pub fn compare_str(ecosystem: &str, a: &str, b: &str) -> Option<Ordering> {
    let left = parse(a, ecosystem)?;
    let right = parse(b, ecosystem)?;
    compare(&left, &right)
}

fn compare(a: &Version, b: &Version) -> Option<Ordering> {
    match (a, b) {
        (Version::Alpine(a), Version::Alpine(b)) => Some(a.cmp(b)),
        (Version::Cran(a), Version::Cran(b)) => Some(a.cmp(b)),
        (Version::Debian(a), Version::Debian(b)) => Some(a.cmp(b)),
        (Version::Hackage(a), Version::Hackage(b)) => Some(a.cmp(b)),
        (Version::Maven(a), Version::Maven(b)) => Some(a.cmp(b)),
        (Version::NuGet(a), Version::NuGet(b)) => Some(a.cmp(b)),
        (Version::Packagist(a), Version::Packagist(b)) => Some(a.cmp(b)),
        (Version::Pub(a), Version::Pub(b)) => Some(a.cmp(b)),
        (Version::PyPI(a), Version::PyPI(b)) => Some(a.cmp(b)),
        (Version::RedHat(a), Version::RedHat(b)) => Some(a.cmp(b)),
        (Version::RubyGems(a), Version::RubyGems(b)) => Some(a.cmp(b)),
        (Version::Semver(a), Version::Semver(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

/// Compare two strings under Semver 2.0.0 ordering (the SEMVER range type
/// in OSV records). Total: the semver-like parser accepts any string.
pub fn compare_semver_str(a: &str, b: &str) -> std::cmp::Ordering {
    semver::parse(a).cmp(&semver::parse(b))
}

/// Parse a version for an OSV ecosystem name (a release suffix like
/// `Debian:12` is ignored, as upstream). `None` for unsupported ecosystems
/// or unparseable versions.
pub fn parse(str: &str, ecosystem: &str) -> Option<Version> {
    let ecosystem = ecosystem.split(':').next().unwrap_or(ecosystem);
    Some(match ecosystem {
        "AlmaLinux" | "Mageia" | "openEuler" | "openSUSE" | "Red Hat" | "Rocky Linux" | "SUSE" => {
            Version::RedHat(redhat::parse(str))
        }
        "Alpaquita"
        | "Alpine"
        | "BellSoft Hardened Containers"
        | "Chainguard"
        | "MinimOS"
        | "Wolfi" => Version::Alpine(alpine::parse(str)?),
        "Bitnami"
        | "Bioconductor"
        | "ConanCenter"
        | "crates.io"
        | "Docker Hardened Images"
        | "GHC"
        | "Go"
        | "Hex"
        | "Julia"
        | "npm"
        | "SwiftURL" => Version::Semver(semver::parse(str)),
        "CRAN" => Version::Cran(cran::parse(str)?),
        "Debian" | "Ubuntu" => Version::Debian(debian::parse(str)?),
        "Hackage" => Version::Hackage(hackage::parse(str)?),
        "Maven" => Version::Maven(maven::parse(str)),
        "NuGet" => Version::NuGet(nuget::parse(str)),
        "Packagist" => Version::Packagist(packagist::parse(str)),
        "Pub" => Version::Pub(pubver::parse(str)),
        "PyPI" => Version::PyPI(pypi::parse(str)?),
        "RubyGems" => Version::RubyGems(rubygems::parse(str)),
        _ => return None,
    })
}

/// An arbitrary-precision non-negative (or signed) decimal integer as its
/// normalized digit string: sign-aware, leading zeros stripped. Ordering is
/// numeric, matching `big.Int` for base-10 inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BigDigits {
    negative: bool,
    digits: String,
}

impl BigDigits {
    pub(crate) fn zero() -> Self {
        BigDigits {
            negative: false,
            digits: "0".to_string(),
        }
    }

    /// Parse like Go's `big.Int.SetString(str, 10)`: optional sign, then
    /// only ASCII digits, at least one.
    pub(crate) fn parse(str: &str) -> Option<Self> {
        let (negative, rest) = match str.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, str.strip_prefix('+').unwrap_or(str)),
        };
        if rest.is_empty() || !rest.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let digits = rest.trim_start_matches('0');
        let digits = if digits.is_empty() { "0" } else { digits };
        Some(BigDigits {
            negative: negative && digits != "0",
            digits: digits.to_string(),
        })
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.digits == "0"
    }

    pub(crate) fn is_negative(&self) -> bool {
        self.negative
    }

    pub(crate) fn digits(&self) -> &str {
        &self.digits
    }
}

impl Ord for BigDigits {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => return Ordering::Greater,
            (true, false) => return Ordering::Less,
            _ => {}
        }
        let magnitude = self
            .digits
            .len()
            .cmp(&other.digits.len())
            .then_with(|| self.digits.cmp(&other.digits));
        if self.negative {
            magnitude.reverse()
        } else {
            magnitude
        }
    }
}

impl PartialOrd for BigDigits {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Upstream's `components`: a list of big integers compared pairwise with
/// missing entries as zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Components(pub(crate) Vec<BigDigits>);

impl Components {
    pub(crate) fn fetch(&self, n: usize) -> BigDigits {
        self.0.get(n).cloned().unwrap_or_else(BigDigits::zero)
    }

    pub(crate) fn cmp_components(&self, other: &Components) -> Ordering {
        let count = self.0.len().max(other.0.len());
        for i in 0..count {
            let diff = self.fetch(i).cmp(&other.fetch(i));
            if diff != Ordering::Equal {
                return diff;
            }
        }
        Ordering::Equal
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

pub(crate) fn fetch<'a>(slice: &'a [&'a str], i: usize, def: &'a str) -> &'a str {
    slice.get(i).copied().unwrap_or(def)
}

pub(crate) fn is_ascii_digit(c: char) -> bool {
    c.is_ascii_digit()
}

#[cfg(test)]
mod fixtures {
    use std::cmp::Ordering;

    /// Run one upstream fixture file: each non-comment line is
    /// `<a> <op> <b>` where `<op>` is `<`, `=`, or `>`.
    pub(super) fn run(ecosystem: &str, file: &str) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tst/semantic")
            .join(file);
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
        let mut checked = 0;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            let mut parts = line.split(' ');
            let (Some(a), Some(op), Some(b)) = (parts.next(), parts.next(), parts.next()) else {
                panic!("malformed fixture line: {line}");
            };
            let expected = match op {
                "<" => Ordering::Less,
                "=" => Ordering::Equal,
                ">" => Ordering::Greater,
                _ => panic!("unknown comparator in fixture line: {line}"),
            };
            let actual = super::compare_str(ecosystem, a, b)
                .unwrap_or_else(|| panic!("failed to compare: {line}"));
            assert_eq!(actual, expected, "{ecosystem}: {line}");
            // Antisymmetry, same as the upstream harness.
            let reversed = super::compare_str(ecosystem, b, a)
                .unwrap_or_else(|| panic!("failed to compare reversed: {line}"));
            assert_eq!(reversed, expected.reverse(), "{ecosystem} reversed: {line}");
            checked += 1;
        }
        assert!(checked > 0, "no fixture lines in {file}");
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::run;

    #[test]
    fn semver_fixtures() {
        run("crates.io", "semver-versions.txt");
    }

    #[test]
    fn pypi_fixtures() {
        run("PyPI", "pypi-versions.txt");
        run("PyPI", "pypi-versions-generated.txt");
    }

    #[test]
    fn debian_fixtures() {
        run("Debian", "debian-versions.txt");
        run("Debian", "debian-versions-generated.txt");
    }

    #[test]
    fn alpine_fixtures() {
        run("Alpine", "alpine-versions.txt");
        run("Alpine", "alpine-versions-generated.txt");
    }

    #[test]
    fn maven_fixtures() {
        run("Maven", "maven-versions.txt");
        run("Maven", "maven-versions-generated.txt");
    }

    #[test]
    fn redhat_fixtures() {
        run("Red Hat", "redhat-versions.txt");
    }

    #[test]
    fn rubygems_fixtures() {
        run("RubyGems", "rubygems-versions.txt");
        run("RubyGems", "rubygems-versions-generated.txt");
    }

    #[test]
    fn packagist_fixtures() {
        run("Packagist", "packagist-versions.txt");
        run("Packagist", "packagist-versions-generated.txt");
    }

    #[test]
    fn nuget_fixtures() {
        run("NuGet", "nuget-versions.txt");
    }

    #[test]
    fn cran_fixtures() {
        run("CRAN", "cran-versions.txt");
        run("CRAN", "cran-versions-generated.txt");
    }

    #[test]
    fn pub_fixtures() {
        run("Pub", "pub-versions.txt");
    }

    #[test]
    fn hackage_fixtures() {
        run("Hackage", "hackage-versions.txt");
    }
}
