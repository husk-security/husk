//! Install-hardening check: an `.npmrc` that does not disable npm lifecycle
//! scripts leaves `npm install` free to run arbitrary pre/post-install code,
//! the primary supply-chain attack vector. This is an
//! **Exposure** finding (the attack surface is present the moment you install),
//! so it is never demoted by project inactivity.
//!
//! This is the worked "add a new check" example: one module + one line in
//! `default_checks()` + a fixture + a test. The category derives from the rule.

use super::{Check, CheckContext};
use crate::model::{Finding, Severity};
use crate::rule::{Category, Rule, RuleId};
use std::borrow::Cow;

pub struct NpmScripts;

static RULES: &[Rule] = &[Rule {
    id: RuleId::lit("npmrc-ignore-scripts"),
    title: Cow::Borrowed("npm install scripts are not disabled"),
    category: Category::InstallHardening,
    default_severity: Severity::Medium,
    rationale: Cow::Borrowed(
        "Without `ignore-scripts=true`, `npm install` runs arbitrary pre/post-install \
         scripts from every dependency, the main supply-chain execution vector.",
    ),
}];

impl Check for NpmScripts {
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn applies(&self, ctx: &CheckContext) -> bool {
        ctx.file_name() == ".npmrc"
    }
    fn run(&self, ctx: &CheckContext, out: &mut Vec<Finding>) {
        if ignore_scripts_enabled(ctx.contents) {
            return;
        }
        out.push(
            Finding::from_rule("npmrc-ignore-scripts")
                .id("npmrc-ignore-scripts")
                .source("Husk npm config scanner")
                .at(ctx.path.to_path_buf(), None)
                .summary(
                    "This .npmrc does not set `ignore-scripts=true`, so installs can run \
                     arbitrary dependency lifecycle scripts.",
                )
                .recommend("Add `ignore-scripts=true` to this .npmrc (or your global ~/.npmrc)."),
        );
    }
}

/// True if the npmrc sets `ignore-scripts` to a truthy value.
fn ignore_scripts_enabled(contents: &str) -> bool {
    let mut enabled = None;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some((key, val)) = line.split_once('=')
            && key.trim() == "ignore-scripts"
        {
            let v = val.trim().trim_matches('"').to_ascii_lowercase();
            enabled = Some(v == "true" || v == "1" || v == "yes");
        }
    }
    enabled.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn run(contents: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let ctx = CheckContext::new(Path::new("/x/.npmrc"), contents);
        if NpmScripts.applies(&ctx) {
            NpmScripts.run(&ctx, &mut out);
        }
        out
    }

    #[test]
    fn flags_npmrc_without_ignore_scripts() {
        assert_eq!(run("registry=https://example.com\n").len(), 1);
        assert_eq!(run("ignore-scripts=true\n").len(), 0);
        assert_eq!(run("# ignore-scripts=true (commented)\n").len(), 1);
        assert_eq!(run("ignore-scripts = \"1\"\n").len(), 0);
        assert_eq!(run("ignore-scripts=true\nignore-scripts=false\n").len(), 1);
        assert_eq!(run("ignore-scripts=false\nignore-scripts=yes\n").len(), 0);
    }

    #[test]
    fn finding_carries_the_rule_and_category() {
        let f = &run("foo=bar\n")[0];
        assert_eq!(f.rule_id.as_ref().unwrap().as_str(), "npmrc-ignore-scripts");
        assert_eq!(f.category, Category::InstallHardening);
    }
}
