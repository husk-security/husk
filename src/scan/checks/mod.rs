//! The `Check` registry: a third pluggable registry isomorphic to
//! [`ScanTarget`](crate::scan::targets) and
//! `IntelSource` (`crate::providers`). Adding a new finding type is
//! one module + one line in [`default_checks`] + one fixture + one test.
//!
//! Each check owns its `Rule` catalog entries (`const RULES` in its module)
//! and stays strictly read-only on the hot walk.

use crate::model::Finding;
use crate::rule::Rule;
use std::path::Path;

mod agent_config;
mod container;
mod dotenv;
mod editor_config;
mod extension;
mod gh_workflow;
mod mcp_config;
mod npm_scripts;
mod package_json;
mod pkgbuild;
mod prompt_injection;
mod secrets;
pub(crate) mod util;

/// Everything a per-file [`Check`] reads. Borrowed, allocation-free on the hot
/// walk.
pub struct CheckContext<'a> {
    pub path: &'a Path,
    pub contents: &'a str,
}

impl<'a> CheckContext<'a> {
    pub fn new(path: &'a Path, contents: &'a str) -> Self {
        Self { path, contents }
    }
    pub fn file_name(&self) -> &str {
        self.path.file_name().and_then(|n| n.to_str()).unwrap_or("")
    }
}

/// A pluggable finding detector. Error-isolated: a detector must never panic and
/// an empty result allocates nothing (`run` writes into a passed sink).
pub trait Check: Send + Sync {
    /// The rules this check can emit, collected into the global rule registry.
    fn rules(&self) -> &'static [Rule];
    /// Cheap gate (filename/keyword only): decides whether `run` is worth it.
    fn applies(&self, ctx: &CheckContext) -> bool;
    /// Static, read-only analysis. Appends findings to `out`.
    fn run(&self, ctx: &CheckContext, out: &mut Vec<Finding>);
}

/// THE registry: one line to add a check.
pub fn default_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(secrets::Secrets),
        Box::new(dotenv::Dotenv),
        Box::new(npm_scripts::NpmScripts),
        Box::new(package_json::PackageJson),
        Box::new(extension::Extension),
        Box::new(pkgbuild::Pkgbuild),
        Box::new(gh_workflow::GithubWorkflow),
        Box::new(prompt_injection::PromptInjection),
        Box::new(mcp_config::McpConfig),
        Box::new(agent_config::AgentConfig),
        Box::new(editor_config::EditorConfig),
        Box::new(container::Container),
    ]
}

/// The per-file checks, built once (the registry is rebuilt per call otherwise,
/// which is wasteful on a hot walk over a large tree).
fn per_file_checks() -> &'static [Box<dyn Check>] {
    use std::sync::OnceLock;
    static CHECKS: OnceLock<Vec<Box<dyn Check>>> = OnceLock::new();
    CHECKS.get_or_init(default_checks)
}

/// Run every per-file check whose `applies` gate passes, appending findings.
/// Error-isolated per check: a panicking detector degrades to empty, never
/// failing the scan.
pub fn run_per_file(path: &Path, contents: &str, out: &mut Vec<Finding>) {
    let ctx = CheckContext::new(path, contents);
    for check in per_file_checks() {
        if check.applies(&ctx) {
            let mut local = Vec::new();
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                check.run(&ctx, &mut local);
            }));
            if res.is_ok() {
                out.append(&mut local);
            }
        }
    }
}
