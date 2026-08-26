//! Editor-extension `package.json` risks (broad activation + risky install
//! scripts).

use super::util::{dangerous_command_reason, find_line, path_contains, trim_evidence};
use super::{Check, CheckContext};
use crate::model::{Finding, Severity};
use crate::rule::{Category, Rule, RuleId};
use serde_json::Value as JsonValue;
use std::borrow::Cow;

pub struct Extension;

static RULES: &[Rule] = &[
    Rule {
        id: RuleId::lit("extension-broad-activation"),
        title: Cow::Borrowed("Extension activates broadly"),
        category: Category::RiskyAgentConfig,
        default_severity: Severity::Medium,
        rationale: Cow::Borrowed(
            "An extension that activates on startup or for every file runs its \
             code unconditionally, widening the attack surface.",
        ),
    },
    Rule {
        id: RuleId::lit("extension-install-script"),
        title: Cow::Borrowed("Extension install script is risky"),
        category: Category::LifecycleScript,
        default_severity: Severity::High,
        rationale: Cow::Borrowed(
            "An editor extension that runs network/download/exec behavior in an \
             install script is a code-execution vector.",
        ),
    },
];

impl Check for Extension {
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn applies(&self, ctx: &CheckContext) -> bool {
        ctx.file_name() == "package.json" && path_contains(ctx.path, "extensions")
    }
    fn run(&self, ctx: &CheckContext, out: &mut Vec<Finding>) {
        let path = ctx.path;
        let contents = ctx.contents;
        let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
            return;
        };
        let publisher = json
            .get("publisher")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let name = json
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");

        if json
            .get("activationEvents")
            .and_then(|value| value.as_array())
            .map(|events| {
                events.iter().any(|event| {
                    event
                        .as_str()
                        .map(|event| event == "*" || event == "onStartupFinished")
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
        {
            out.push(
                Finding::from_rule("extension-broad-activation")
                    .id(format!("extension-activation:{name}"))
                    .source("Husk extension scanner")
                    .at(path.to_path_buf(), find_line(contents, "activationEvents"))
                    .summary(format!(
                        "{publisher}.{name} activates without a narrow user action or file type trigger."
                    ))
                    .recommend(
                        "Review the extension source and permissions, or remove it if it is not needed.",
                    ),
            );
        }

        if let Some(scripts) = json.get("scripts").and_then(|value| value.as_object()) {
            for script_name in ["preinstall", "install", "postinstall"] {
                let Some(command) = scripts.get(script_name).and_then(|value| value.as_str())
                else {
                    continue;
                };
                if let Some(reason) = dangerous_command_reason(command) {
                    out.push(
                        Finding::from_rule("extension-install-script")
                            .id(format!("extension-script:{script_name}"))
                            .source("Husk extension scanner")
                            .at(path.to_path_buf(), find_line(contents, script_name))
                            .summary(format!(
                                "{publisher}.{name} defines an install script with risky behavior."
                            ))
                            .evidence(format!("{reason}: {}", trim_evidence(command)))
                            .recommend(
                                "Remove the extension or inspect the package before allowing it to run install scripts.",
                            ),
                    );
                }
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
        let ctx = CheckContext::new(
            Path::new("/home/u/.vscode/extensions/foo/package.json"),
            contents,
        );
        if Extension.applies(&ctx) {
            Extension.run(&ctx, &mut out);
        }
        out
    }

    #[test]
    fn flags_star_activation() {
        let f = run(r#"{"name":"foo","publisher":"bar","activationEvents":["*"]}"#);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].category, Category::RiskyAgentConfig);
    }

    #[test]
    fn requires_extensions_path() {
        let ctx = CheckContext::new(Path::new("/x/package.json"), "{}");
        assert!(!Extension.applies(&ctx));
    }
}
