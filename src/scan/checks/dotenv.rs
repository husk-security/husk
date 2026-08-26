//! Plaintext `.env`-style files.

use super::{Check, CheckContext};
use crate::model::{Finding, Severity};
use crate::rule::{Category, Rule, RuleId};
use std::borrow::Cow;
use std::path::Path;

pub struct Dotenv;

static RULES: &[Rule] = &[Rule {
    id: RuleId::lit("dotenv-untracked"),
    title: Cow::Borrowed("Plaintext environment file"),
    category: Category::Secret,
    default_severity: Severity::Medium,
    rationale: Cow::Borrowed(
        "Credentials in a plaintext .env are easy to leak into git history, \
         backups, or a shared screen.",
    ),
}];

fn is_env_file(file_name: &str) -> bool {
    file_name == ".env"
        || file_name.starts_with(".env.")
        || file_name.ends_with(".env")
        || file_name.contains(".env.")
}

impl Check for Dotenv {
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn applies(&self, ctx: &CheckContext) -> bool {
        is_env_file(ctx.file_name())
    }
    fn run(&self, ctx: &CheckContext, out: &mut Vec<Finding>) {
        let path: &Path = ctx.path;
        let contents = ctx.contents;
        let name = ctx.file_name();
        if name.ends_with(".example") || name.ends_with(".sample") || name.contains("template") {
            return;
        }

        let assignments = contents
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty()
                    && !trimmed.starts_with('#')
                    && trimmed.contains('=')
                    && !trimmed.contains("example")
                    && !trimmed.contains("changeme")
            })
            .count();

        if assignments > 0 {
            out.push(
                Finding::from_rule("dotenv-untracked")
                    .id("env")
                    .source("Husk env scanner")
                    .at(path.to_path_buf(), None)
                    .summary(format!(
                        "{assignments} environment assignments are stored in a plaintext .env-style file."
                    ))
                    .recommend(
                        "Keep local .env files out of git, restrict permissions, and migrate durable credentials to a vault.",
                    ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn run(name: &str, contents: &str) -> Vec<Finding> {
        let p = format!("/x/{name}");
        let ctx = CheckContext::new(Path::new(&p), contents);
        let mut out = Vec::new();
        if Dotenv.applies(&ctx) {
            Dotenv.run(&ctx, &mut out);
        }
        out
    }

    #[test]
    fn flags_populated_env_and_skips_templates() {
        assert_eq!(run(".env", "API_KEY=abc123\n").len(), 1);
        assert_eq!(run(".env.example", "API_KEY=abc123\n").len(), 0);
        assert_eq!(run(".env", "# only comments\n").len(), 0);
        assert_eq!(run(".env", "API_KEY=abc\n")[0].category, Category::Secret);
    }
}
