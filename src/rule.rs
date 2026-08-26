//! The `Rule` registry: the single join point of the project-posture model.
//!
//! A [`Rule`] is the reusable *definition* of a problem (modeled on SARIF's
//! `reportingDescriptor`): a [`Finding`](crate::model::Finding) references a
//! [`RuleId`]; Markdown guide items aggregate related rule ids and registered
//! controls attach scan evidence and typed remediation proposals.
//!
//! Static catalog rules are `&'static` (declared as `const RULES` inside each
//! [`Check`](crate::scan::checks::Check) module and collected here). The
//! catalog supplies detector metadata; reports carry `Finding.rule_id`
//! references. Dynamic advisory
//! findings (`osv:…`/`cve:…`/`amo:…` ids) have no catalog entry.
//!
//! Two invariants the rest of the crate leans on: a finding's *family* is its
//! `rule_id`, and every
//! finding carries a typed [`Category`] (`Finding.category`); there is no
//! parallel free-text category plane.

use crate::model::Severity;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Stable identifier for a rule. Catalog ids are kebab-case literals
/// (`"npm-postinstall"`); external advisory ids are prefixed
/// (`"osv:GHSA-…"`, `"cve:CVE-…"`, `"amo:<guid>"`) so they share one namespace.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RuleId(pub Cow<'static, str>);

impl RuleId {
    /// Const constructor for the static catalog (`RuleId::lit("npm-postinstall")`).
    pub const fn lit(s: &'static str) -> RuleId {
        RuleId(Cow::Borrowed(s))
    }
    pub fn owned(s: impl Into<String>) -> RuleId {
        RuleId(Cow::Owned(s.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The rule family: the authoritative, typed category every finding carries
/// (`Finding.category`). Serialized as the stable kebab id.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    // EXPOSURE: point-in-time, always actionable, activity-invariant.
    Secret,
    Malware,
    Typosquat,
    RiskyAgentConfig,
    PromptInjection,
    ExposedConfig,
    /// npm ignore-scripts / registry-pinning / min-package-age. Exposure: the
    /// attack surface is present the moment you `npm install`.
    InstallHardening,
    /// A package on the committed project policy's block list.
    Policy,
    // AMBIENT: only matters if the code is actually run.
    Vulnerability,
    Package,
    LifecycleScript,
    /// Escape hatch: fail-safe to Exposure (a miscategorized finding screams).
    Other,
}

/// Whether a category's risk is point-in-time (always actionable) or ambient
/// (only matters if the code runs, so it's demoted by project inactivity).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskClass {
    Exposure,
    Ambient,
}

impl Category {
    /// One rule, zero exceptions. Exposure is activity-invariant; Ambient is
    /// demoted by project activity (see `crate::score`).
    pub const fn risk_class(self) -> RiskClass {
        use Category::*;
        match self {
            Secret | Malware | Typosquat | RiskyAgentConfig | PromptInjection | ExposedConfig
            | InstallHardening | Policy | Other => RiskClass::Exposure,
            Vulnerability | Package | LifecycleScript => RiskClass::Ambient,
        }
    }

    /// Stable kebab wire id (matches the serde rename).
    pub fn id(self) -> &'static str {
        use Category::*;
        match self {
            Secret => "secret",
            Malware => "malware",
            Typosquat => "typosquat",
            RiskyAgentConfig => "risky-agent-config",
            PromptInjection => "prompt-injection",
            ExposedConfig => "exposed-config",
            InstallHardening => "install-hardening",
            Policy => "policy",
            Vulnerability => "vulnerability",
            Package => "package",
            LifecycleScript => "lifecycle-script",
            Other => "other",
        }
    }

    pub fn label(self) -> &'static str {
        use Category::*;
        match self {
            Secret => "secrets",
            Malware => "malware",
            Typosquat => "typosquats",
            RiskyAgentConfig => "agent config",
            PromptInjection => "prompt injection",
            ExposedConfig => "host config",
            InstallHardening => "install hardening",
            Policy => "policy blocked",
            Vulnerability => "vulnerable dependencies",
            Package => "packages",
            LifecycleScript => "lifecycle scripts",
            Other => "other",
        }
    }

    /// Parses a category string leniently: the canonical kebab ids plus every
    /// legacy pre-api-v3 alias, so cached reports and old filter arguments keep
    /// working. Anything unknown → `Other` (→ Exposure fail-safe, so a
    /// miscategorized finding never demotes by accident). Use
    /// [`Category::parse_strict`] where a typo must error instead.
    pub fn parse_lenient(s: &str) -> Category {
        Self::parse_strict(s).unwrap_or(Category::Other)
    }

    /// Parses a canonical id or known legacy alias; `None` for anything else.
    pub fn parse_strict(s: &str) -> Option<Category> {
        Some(match s {
            "secret" | "secrets" => Category::Secret,
            "malware" => Category::Malware,
            "typosquat" => Category::Typosquat,
            "risky-agent-config" | "agent-config" | "ai-config" | "mcp" | "mcp-config"
            | "extension" => Category::RiskyAgentConfig,
            "prompt-injection" => Category::PromptInjection,
            "exposed-config" | "host-config" | "config" => Category::ExposedConfig,
            "install-hardening" => Category::InstallHardening,
            "policy" => Category::Policy,
            "vulnerability" | "advisory" | "cve" => Category::Vulnerability,
            "package" | "inventory" => Category::Package,
            "npm-script" | "lifecycle" | "lifecycle-script" | "automation" | "git-hook" | "ci"
            | "github-actions" => Category::LifecycleScript,
            "other" => Category::Other,
            _ => return None,
        })
    }
}

/// Serde helper for `Finding.category`: deserializes any category string
/// leniently (canonical ids + legacy pre-v3 aliases) so cached reports and
/// per-file scan-index entries written by older builds keep loading.
pub fn deserialize_category_lenient<'de, D>(deserializer: D) -> Result<Category, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = <std::borrow::Cow<str> as serde::Deserialize>::deserialize(deserializer)?;
    Ok(Category::parse_lenient(&s))
}

/// Detector confidence, wired into scoring (a *tentative* secret match should
/// not scream).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    #[default]
    Firm,
    Tentative,
}

/// The reusable definition of a problem. SARIF `reportingDescriptor`.
/// Serialize-only (has `&'static str` fields; Rust never reads rules back).
#[derive(Clone, Debug, serde::Serialize)]
pub struct Rule {
    pub id: RuleId,
    pub title: Cow<'static, str>,
    pub category: Category,
    pub default_severity: Severity,
    pub rationale: Cow<'static, str>,
}

fn catalog() -> &'static HashMap<&'static str, &'static Rule> {
    static CATALOG: OnceLock<HashMap<&'static str, &'static Rule>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let mut map = HashMap::new();
        for check in crate::scan::checks::default_checks() {
            for rule in check.rules() {
                map.insert(rule.id.as_str(), rule);
            }
        }
        // Walk-scope rules that don't belong to a per-file `Check` (the git-hook
        // scan runs on `.git` dirs collected during the walk).
        for rule in crate::scan::local::RULES {
            map.insert(rule.id.as_str(), rule);
        }
        map
    })
}

/// `None` for unknown or external ids; never synthesizes.
pub fn lookup_static(id: &RuleId) -> Option<&'static Rule> {
    catalog().get(id.as_str()).copied()
}

/// The full static catalog, sorted by id for stable output.
pub fn default_rules() -> Vec<&'static Rule> {
    let mut rules: Vec<&'static Rule> = catalog().values().copied().collect();
    rules.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[Category] = &[
        Category::Secret,
        Category::Malware,
        Category::Typosquat,
        Category::RiskyAgentConfig,
        Category::PromptInjection,
        Category::ExposedConfig,
        Category::InstallHardening,
        Category::Policy,
        Category::Vulnerability,
        Category::Package,
        Category::LifecycleScript,
        Category::Other,
    ];

    #[test]
    fn category_id_matches_serde_wire_form() {
        // `Category::id()` promises to match the serde kebab rename; this is
        // the drift guard that keeps the promise honest.
        for cat in ALL {
            let wire = serde_json::to_string(cat).expect("serialize");
            assert_eq!(wire, format!("\"{}\"", cat.id()), "{cat:?}");
        }
    }

    #[test]
    fn category_parses_canonical_ids_and_legacy_aliases() {
        for cat in ALL {
            assert_eq!(Category::parse_strict(cat.id()), Some(*cat), "{cat:?}");
        }
        // Pre-api-v3 aliases stay parseable (cached reports keep loading).
        assert_eq!(
            Category::parse_strict("ai-config"),
            Some(Category::RiskyAgentConfig)
        );
        assert_eq!(
            Category::parse_strict("automation"),
            Some(Category::LifecycleScript)
        );
        assert_eq!(
            Category::parse_strict("extension"),
            Some(Category::RiskyAgentConfig)
        );
        assert_eq!(Category::parse_strict("nonsense"), None);
        // Lenient parse fail-safes to Other (Exposure; a miscategorized
        // finding screams rather than being demoted).
        assert_eq!(Category::parse_lenient("nonsense"), Category::Other);
    }

    #[test]
    fn catalog_includes_walk_scope_rules() {
        // The git-hook rule lives in scan::local (not a per-file Check) and
        // must still be reachable through the catalog/`/api/rules`.
        assert!(lookup_static(&RuleId::lit("git-hook")).is_some());
    }
}
