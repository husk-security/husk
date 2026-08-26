//! Broad secret scanning: the one check that runs on every text file (no
//! filename gate).

use super::util::{line_for_offset, redact};
use super::{Check, CheckContext};
use crate::model::{Finding, Severity};
use crate::rule::{Category, Confidence, Rule, RuleId};
use regex::Regex;
use std::borrow::Cow;
use std::sync::OnceLock;

pub struct Secrets;

static RULES: &[Rule] = &[Rule {
    id: RuleId::lit("secret-exposed"),
    title: Cow::Borrowed("Secret exposed in plaintext"),
    category: Category::Secret,
    default_severity: Severity::Critical,
    rationale: Cow::Borrowed(
        "A live credential in plaintext on disk is one stolen laptop or one \
         leaked backup away from account takeover.",
    ),
}];

struct SecretRule {
    name: &'static str,
    regex: Regex,
    severity: Severity,
}

/// Compiled once; the registry is shared across the whole parallel walk.
///
/// **Order is load-bearing.** A match is skipped when an earlier rule already
/// claimed those bytes (see `run`), so the most specific pattern must come
/// first: every Anthropic key also matches the broader OpenAI `sk-` shape, and
/// reporting a leaked Anthropic key as an OpenAI one is worse than useless when
/// the reader has to decide which console to rotate in.
fn secret_rules() -> &'static [SecretRule] {
    static COMPILED: OnceLock<Vec<SecretRule>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let spec: [(&'static str, &str, Severity); 13] = [
            (
                "Anthropic admin key",
                r"\bsk-ant-admin[0-9]{2}-[A-Za-z0-9_-]{32,}\b",
                Severity::Critical,
            ),
            (
                "Anthropic API key",
                r"\bsk-ant-api[0-9]{2}-[A-Za-z0-9_-]{32,}\b",
                Severity::Critical,
            ),
            (
                "AWS access key",
                r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
                Severity::Critical,
            ),
            (
                "GitHub token",
                r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b",
                Severity::Critical,
            ),
            (
                "Stripe live secret key",
                r"\bsk_live_[A-Za-z0-9]{16,}\b",
                Severity::Critical,
            ),
            (
                "OpenAI API key",
                r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b",
                Severity::High,
            ),
            (
                "Slack token",
                r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
                Severity::High,
            ),
            (
                "Hugging Face token",
                r"\bhf_[A-Za-z0-9]{32,}\b",
                Severity::High,
            ),
            (
                "Perplexity API key",
                r"\bpplx-[A-Za-z0-9]{32,}\b",
                Severity::High,
            ),
            // The three registry publish tokens rate Critical, not High: each
            // one is publish rights to everything the account owns, so one
            // stolen token can republish a maintainer's entire catalog.
            (
                "npm publish token",
                r"\bnpm_[A-Za-z0-9]{30,}\b",
                Severity::Critical,
            ),
            (
                "PyPI publish token",
                r"\bpypi-[A-Za-z0-9_-]{40,}\b",
                Severity::Critical,
            ),
            (
                "RubyGems API key",
                r"\brubygems_[a-f0-9]{48}\b",
                Severity::Critical,
            ),
            (
                "private key",
                r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
                Severity::Critical,
            ),
        ];
        spec.into_iter()
            .filter_map(|(name, pat, severity)| {
                Regex::new(pat).ok().map(|regex| SecretRule {
                    name,
                    regex,
                    severity,
                })
            })
            .collect()
    })
}

/// Provider-agnostic fallback: a `…key/token/secret/password = "value"`
/// assignment whose quoted value is long and high-entropy. Catches keys with
/// no fixed prefix (e.g. a UUID-shaped access key) that the signature rules
/// above can never know about. Unlike those rules this one only fires when
/// the value does NOT look synthetic; a keyword match alone is far too common
/// in ordinary code to report on low-entropy values. Matches quoted,
/// slash-free values only, so URLs and slash-carrying base64 are skipped.
fn generic_assignment_regex() -> &'static Regex {
    static COMPILED: OnceLock<Regex> = OnceLock::new();
    COMPILED.get_or_init(|| {
        Regex::new(
            r#"(?i)\b[a-z0-9_]*(?:key|token|secret|password|passwd|credential)s?["']?\s*[:=]\s*["'`]([A-Za-z0-9+=_-]{16,120})["'`]"#,
        )
        .expect("generic secret assignment regex compiles")
    })
}

impl Check for Secrets {
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn applies(&self, _ctx: &CheckContext) -> bool {
        true
    }
    fn run(&self, ctx: &CheckContext, out: &mut Vec<Finding>) {
        let path = ctx.path;
        let contents = ctx.contents;
        let test_path = is_test_or_fixture_path(path);
        // Byte ranges an earlier, more specific rule already reported. Provider
        // prefixes nest (`sk-ant-api03-…` is also an `sk-…`), so without this
        // one leaked key is reported twice under two different provider names.
        let mut claimed: Vec<std::ops::Range<usize>> = Vec::new();
        for rule in secret_rules() {
            for mat in rule.regex.find_iter(contents) {
                if claimed
                    .iter()
                    .any(|range| mat.start() < range.end && range.start < mat.end())
                {
                    continue;
                }
                claimed.push(mat.range());
                let line = line_for_offset(contents, mat.start());
                // Demote obvious non-secrets: a synthetic/low-entropy value
                // (`ghp_abcdef…`, 36 repeated chars) or a match inside a test /
                // fixture file is almost always sample data, not a real leak.
                let confidence = if looks_synthetic(mat.as_str()) || test_path {
                    Confidence::Tentative
                } else {
                    Confidence::Firm
                };
                let mut finding = Finding::from_rule("secret-exposed")
                    .id(format!("secret:{}", rule.name.replace(' ', "-")))
                    .title(format!("{} exposed", rule.name))
                    .severity(rule.severity)
                    .source("Husk secret scanner")
                    .at(path.to_path_buf(), Some(line))
                    .summary(format!(
                        "A value matching the {} pattern is present in plaintext.",
                        rule.name
                    ))
                    .evidence(redact(mat.as_str()))
                    .recommend("Move the secret into a vault or environment-specific secret store and rotate it if it was ever committed or shared.")
                    .confidence(confidence);
                finding
                    .references
                    .push("https://github.com/gitleaks/gitleaks".to_string());
                out.push(finding);
            }
        }

        for caps in generic_assignment_regex().captures_iter(contents) {
            let value = caps.get(1).expect("value group").as_str();
            // Only high-entropy values; and skip anything a signature rule
            // already matched so the same token isn't reported twice. A
            // digit-free value is a word phrase ("husk-admin-dev-password"),
            // not a machine-generated key; all-letter passphrases are missed.
            if looks_synthetic(value)
                || !value.bytes().any(|byte| byte.is_ascii_digit())
                || secret_rules().iter().any(|rule| rule.regex.is_match(value))
            {
                continue;
            }
            let offset = caps.get(1).expect("value group").start();
            let line = line_for_offset(contents, offset);
            let confidence = if test_path {
                Confidence::Tentative
            } else {
                Confidence::Firm
            };
            let mut finding = Finding::from_rule("secret-exposed")
                .id("secret:generic-api-key")
                .title("API key or secret exposed")
                .severity(Severity::High)
                .source("Husk secret scanner")
                .at(path.to_path_buf(), Some(line))
                .summary("A key/token/secret/password assignment holds a high-entropy value in plaintext.")
                .evidence(redact(value))
                .recommend("Move the secret into a vault or environment-specific secret store and rotate it if it was ever committed or shared.")
                .confidence(confidence);
            finding
                .references
                .push("https://github.com/gitleaks/gitleaks".to_string());
            out.push(finding);
        }
    }
}

/// True if the file path looks like test/fixture/example/mock code, where a
/// secret-shaped string is far more likely sample data than a real credential.
fn is_test_or_fixture_path(path: &std::path::Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.contains(".test.")
        || name.contains(".spec.")
        || name.contains("fixture")
        || name.contains("example")
        || name.contains("sample")
        || name.contains("mock")
        || [
            "/test/",
            "/tests/",
            "/__tests__/",
            "/__mocks__/",
            "/fixtures/",
            "/testdata/",
            "/e2e/",
            "/spec/",
            "/examples/",
        ]
        .iter()
        .any(|seg| lower.contains(seg))
}

/// True when a matched secret value is obviously synthetic: a long run of one
/// repeated character, a sequential alphabet/digit run, or a well-known
/// placeholder body, i.e. test data, not a real credential. Entropy-based with
/// cheap structural shortcuts; deliberately conservative (real high-entropy
/// tokens never trip it).
fn looks_synthetic(matched: &str) -> bool {
    // Strip the provider prefix (`ghp_`, `sk-`, `AKIA`, …): the entropy lives
    // in the random body, not the fixed scheme.
    let body = matched
        .split_once('_')
        .map(|(_, b)| b)
        .or_else(|| matched.split_once('-').map(|(_, b)| b))
        .unwrap_or(matched);
    let core: &str = if body.len() >= 8 { body } else { matched };

    // A single character repeated many times (e.g. "c".repeat(36)).
    if let Some(first) = core.chars().next()
        && core.len() >= 12
        && core.chars().all(|c| c == first)
    {
        return true;
    }
    // Known placeholder bodies.
    let lower = core.to_ascii_lowercase();
    if lower.contains("abcdefghij")
        || lower.contains("0123456789")
        || lower.contains("1234567890")
        || lower.contains("xxxxxxxx")
        || lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("redact")
    {
        return true;
    }
    // Low Shannon entropy ⇒ not a real random token.
    shannon_bits_per_char(core) < 3.0
}

/// Shannon entropy in bits per character (0 for empty/uniform strings).
fn shannon_bits_per_char(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
    }
    let len = s.chars().count() as f64;
    -counts
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn run_at(p: &str, contents: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        Secrets.run(&CheckContext::new(Path::new(p), contents), &mut out);
        out
    }
    fn run(contents: &str) -> Vec<Finding> {
        run_at("/x/app.ts", contents)
    }

    #[test]
    fn detects_real_github_token_firmly() {
        // A high-entropy token in app code is a Firm match.
        let f = run("const t = \"ghp_R8kQ2mZ7vP1nX4wL9sT0bC3dE6fG5hJ8kM2qY7zA\";\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id.as_ref().unwrap().as_str(), "secret-exposed");
        assert_eq!(f[0].category, Category::Secret);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].confidence, Confidence::Firm);
    }

    #[test]
    fn synthetic_placeholder_token_is_tentative() {
        // A sequential-alphabet token is a synthetic placeholder, not a leak.
        let f = run("redact(\"ghp_abcdefghijklmnopqrstuvwxyz1234567890\")\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, Confidence::Tentative);
    }

    #[test]
    fn repeated_char_token_is_tentative() {
        let f = run("const t = \"ghp_cccccccccccccccccccccccccccccccccccc\";\n");
        assert_eq!(f[0].confidence, Confidence::Tentative);
    }

    #[test]
    fn real_token_in_test_file_is_tentative() {
        // Even a high-entropy match in a *.test.ts is demoted (likely fixture).
        let f = run_at(
            "/repo/test/runner.test.ts",
            "const t = \"ghp_R8kQ2mZ7vP1nX4wL9sT0bC3dE6fG5hJ8kM2qY7zA\";\n",
        );
        assert_eq!(f[0].confidence, Confidence::Tentative);
    }

    #[test]
    fn clean_file_has_no_findings() {
        assert!(run("let x = 1;\n").is_empty());
    }

    #[test]
    fn generic_key_assignment_with_high_entropy_value_is_found() {
        // A UUID-shaped key has no provider prefix a signature rule could know.
        let f = run("const ACCESS_KEY = \"ffa38132-bd58-4cfa-82b0-407139d6a045\";\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "API key or secret exposed");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].confidence, Confidence::Firm);
    }

    #[test]
    fn generic_key_assignment_with_placeholder_value_is_skipped() {
        // Low-entropy / placeholder values must not fire the generic rule at
        // all; keyword assignments are far too common in ordinary code.
        assert!(run("const API_KEY = \"your-api-key-goes-here-example\";\n").is_empty());
        assert!(run("apiKey: \"xxxxxxxxxxxxxxxxxxxx\",\n").is_empty());
        // Digit-free word phrases are dev placeholders, not generated keys.
        assert!(run("adminPassword: \"husk-admin-dev-password\"\n").is_empty());
        assert!(run("masterkey: \"husk-local-dev-zitadel-masterkey\"\n").is_empty());
    }

    #[test]
    fn generic_rule_does_not_double_report_signature_matches() {
        // An OpenAI-prefixed value assigned to a key var fires only the
        // signature rule, not the generic one on top.
        let f = run("const OPENAI_KEY = \"sk-R8kQ2mZ7vP1nX4wL9sT0bC3dE6fG5hJ8kM2qY7zA\";\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "OpenAI API key exposed");
    }

    #[test]
    fn generic_match_in_test_file_is_tentative() {
        let f = run_at(
            "/repo/test/form.test.tsx",
            "const ACCESS_KEY = \"ffa38132-bd58-4cfa-82b0-407139d6a045\";\n",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, Confidence::Tentative);
    }
}
