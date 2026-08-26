//! Pluggable per-ecosystem scan targets.
//!
//! A [`ScanTarget`] encapsulates one ecosystem's "files on disk → package
//! coordinates" knowledge. Detection + static parsing only: a target must
//! never execute anything (the read-only scanner invariant). Shared parsing
//! machinery (the bounded manifest read, the [`Emitter`] sink, line location,
//! text micro-helpers) lives in [`support`]; modules keep only format
//! knowledge.
//!
//! Adding a new ecosystem is a local change:
//! - **Exact-filename manifests** (the common case): write one
//!   `pub(super) fn my_lock(contents: &str, out: &mut Emitter<'_>)` in a new
//!   module and register it as a `simple("eco", &["my.lock"], …)` row in
//!   [`default_targets`].
//! - **Anything fancier** (path-shape / sibling-file / binary detection):
//!   implement [`ScanTarget`] directly and register with `Box::new(...)`.
//!
//! If the ecosystem has an OSV/GitHub advisory id, also add the mapping in
//! [`crate::model::PackageRef::osv_ecosystem`]. The provider fan-out then
//! queries the new coordinates automatically; no edits to `providers.rs`.
//! The full-corpus behavior lock is `tests/golden_corpus.rs`: add a fixture
//! under `tst/ecosystems/<id>/` and regenerate the snapshot deliberately.

use crate::model::PackageRef;
use std::path::{Path, PathBuf};

pub mod support;

pub use support::Emitter;

pub(crate) mod oci;

mod apk;
mod bazel;
mod bower;
mod browser_chrome;
mod browser_firefox;
mod buf;
mod bun;
mod cabal_plan;
mod carthage;
mod chocolatey;
mod cicd;
mod claude_plugin;
mod clojure;
mod conda;
mod cpanfile;
mod crystal;
mod deno;
mod dlang;
mod docker;
mod dpkg;
mod elm;
mod erlang;
mod flatpak;
mod freebsd;
mod gitlab_ci;
mod gleam;
mod golang;
mod gradle_catalog;
mod guix;
mod haxe;
mod helm;
mod homebrew;
mod huggingface;
mod jetbrains;
mod jupyter;
mod jvm;
mod k8s_operator;
mod lua;
mod mcp;
mod meson;
mod mint;
mod native;
mod nim;
mod nixflake;
mod node;
mod ollama;
mod opam;
mod openai_gpt;
mod pacman;
mod paket;
mod perl;
mod pnpm_workspace;
mod portage;
mod precommit;
mod purescript;
mod python;
mod racket;
mod rpm_db;
mod rpm_manifest;
mod ruby_php;
mod rust;
mod sbom;
mod scala;
mod scoop;
mod shopify;
mod snap;
mod spack;
mod stack;
mod terraform;
mod various;
mod vcpkg;
mod vimplugin;
mod vscode_ext;
mod winget;
mod wordpress;
mod zig;

/// One ecosystem's detection + parsing knowledge. Stateless and `Send + Sync`
/// so a single registry can be shared across the parallel directory walk.
pub trait ScanTarget: Send + Sync {
    /// Canonical lowercase ecosystem id, e.g. `"npm"`, `"nuget"`.
    fn ecosystem_id(&self) -> &'static str;

    /// Does this target apply to `path`? Cheap filename/extension dispatch
    /// only; never read file contents here.
    fn detects(&self, path: &Path) -> bool;

    /// Parse `path`, emitting coordinates into `out`. Static parse only, and
    /// infallible by contract: emit whatever parsed; report read/format
    /// failures through [`Emitter::warn`] instead of dropping them.
    fn parse(&self, path: &Path, out: &mut Emitter<'_>);
}

/// A target fully described by `(ecosystem, exact filenames, parse fn)`: one
/// registry row instead of a struct + three trait methods.
fn simple(
    ecosystem: &'static str,
    files: &'static [&'static str],
    parse: fn(&str, &mut Emitter<'_>),
) -> Box<dyn ScanTarget> {
    Box::new(support::Simple {
        ecosystem,
        files,
        parse,
    })
}

/// The default set of scan targets, wired in one place. Adding an ecosystem is
/// a single line here plus its module.
pub fn default_targets() -> Vec<Box<dyn ScanTarget>> {
    vec![
        // JavaScript / Node
        simple(
            "npm",
            &["package-lock.json", "npm-shrinkwrap.json"],
            node::package_lock,
        ),
        simple("npm", &["yarn.lock"], node::yarn_lock),
        simple("npm", &["pnpm-lock.yaml"], node::pnpm_lock),
        // Python
        simple(
            "pypi",
            &[
                "requirements.txt",
                "requirements-dev.txt",
                "requirements-prod.txt",
            ],
            python::requirements_txt,
        ),
        simple(
            "pypi",
            &["poetry.lock", "uv.lock", "pdm.lock"],
            python::pep_toml_lock,
        ),
        simple("pypi", &["Pipfile.lock"], python::pipfile_lock),
        // Rust
        simple("cargo", &["Cargo.lock"], rust::cargo_lock),
        // Go
        simple("go", &["go.sum"], golang::go_sum),
        simple("go", &["go.mod"], golang::go_mod),
        // .NET / JVM
        simple("nuget", &["packages.lock.json"], jvm::nuget_packages_lock),
        simple(
            "maven",
            &["gradle.lockfile", "buildscript-gradle.lockfile"],
            jvm::gradle_lockfile,
        ),
        // Ruby / PHP
        simple(
            "rubygems",
            &["Gemfile.lock", "gems.locked"],
            ruby_php::gemfile_lock,
        ),
        simple("packagist", &["composer.lock"], ruby_php::composer_lock),
        // Long-tail languages routed through OSV
        simple("hex", &["mix.lock"], various::mix_lock),
        simple("pub", &["pubspec.lock"], various::pubspec_lock),
        simple("swift", &["Package.resolved"], various::package_resolved),
        simple("cran", &["renv.lock"], various::renv_lock),
        simple("julia", &["Manifest.toml"], various::julia_manifest),
        simple("hackage", &["cabal.project.freeze"], various::cabal_freeze),
        // C / C++ (no OSV advisory feed yet; inventory + future feed)
        simple("conan", &["conan.lock"], native::conan_lock),
        simple("cocoapods", &["Podfile.lock"], native::podfile_lock),
        // CI/CD supply chain
        Box::new(cicd::GitHubActionsTarget),
        // Functional / niche language ecosystems
        Box::new(opam::OpamTarget),
        Box::new(clojure::ClojureLibsTarget),
        simple("clojure", &["deps.edn", "bb.edn"], clojure::deps_edn),
        simple("clojure", &["project.clj"], clojure::project_clj),
        Box::new(lua::LuaRocksTarget),
        simple("nimble", &["nimble.lock"], nim::nimble_lock),
        simple("dub", &["dub.selections.json"], dlang::dub_selections),
        Box::new(conda::CondaMetaTarget),
        simple("conda", &["pixi.lock"], conda::pixi_lock),
        simple("elm", &["elm.json"], elm::elm_json),
        simple("shards", &["shard.lock"], crystal::shard_lock),
        simple("zig", &["build.zig.zon"], zig::build_zig_zon),
        // Deno resolves npm deps against the npm registry (jsr coordinates are
        // emitted under their own "jsr" id inside the parser).
        simple("npm", &["deno.lock"], deno::deno_lock),
        // Bun resolves against the npm registry too; only the text lockfile,
        // never the binary `bun.lockb`.
        simple("npm", &["bun.lock"], bun::bun_lock),
        simple("hex", &["rebar.lock"], erlang::rebar_lock),
        Box::new(gleam::GleamTarget),
        simple("maven", &["build.sbt.lock"], scala::dependency_lock),
        simple("maven", &["lock.sbt"], scala::lock_sbt),
        Box::new(bazel::BazelMavenTarget),
        simple("swift", &["Cartfile.resolved"], carthage::cartfile_resolved),
        simple("cpan", &["cpanfile.snapshot"], perl::cpanfile_snapshot),
        simple("hackage", &["stack.yaml.lock"], stack::stack_yaml_lock),
        Box::new(vcpkg::VcpkgStatusTarget),
        simple("vcpkg", &["vcpkg.json"], vcpkg::vcpkg_json),
        simple("purescript", &["spago.lock"], purescript::spago_lock),
        simple("nuget", &["paket.lock"], paket::paket_lock),
        Box::new(gradle_catalog::GradleCatalogTarget),
        // AI agent / editor extension surfaces
        Box::new(mcp::McpTarget),
        Box::new(vscode_ext::VsCodeExtensionTarget),
        Box::new(claude_plugin::ClaudePluginTarget),
        Box::new(ollama::OllamaTarget),
        Box::new(jetbrains::JetBrainsPluginTarget),
        // OS / system package managers
        Box::new(dpkg::DpkgTarget),
        Box::new(apk::AlpineApkTarget),
        Box::new(pacman::PacmanTarget),
        Box::new(homebrew::HomebrewCellarTarget),
        simple("nix", &["flake.lock"], nixflake::flake_lock),
        Box::new(snap::SnapTarget),
        Box::new(flatpak::FlatpakTarget),
        Box::new(portage::PortageTarget),
        // Infrastructure as code / CI / containers
        Box::new(gitlab_ci::GitLabCiTarget),
        simple(
            "terraform",
            &[".terraform.lock.hcl"],
            terraform::terraform_lock,
        ),
        Box::new(helm::HelmLockTarget),
        simple("helm", &["Chart.yaml"], helm::chart_yaml),
        Box::new(docker::DockerfileTarget),
        Box::new(docker::ComposeTarget),
        Box::new(precommit::PreCommitTarget),
        // Windows / BSD package managers
        Box::new(chocolatey::ChocolateyNuspecTarget),
        Box::new(scoop::ScoopTarget),
        Box::new(winget::WingetTarget),
        simple("rpm", &["rpm-manifest.txt"], rpm_manifest::rpm_manifest_txt),
        simple("rpm", &["packages.txt"], rpm_manifest::rpm_packages_txt),
        Box::new(rpm_db::RpmSqliteTarget),
        Box::new(rpm_db::RpmNdbTarget),
        Box::new(rpm_db::RpmBdbTarget),
        simple("freebsd", &["packagesite.yaml"], freebsd::packagesite_yaml),
        simple("freebsd", &["+MANIFEST"], freebsd::plus_manifest),
        simple("freebsd", &["pkg-list.txt"], freebsd::pkg_list_txt),
        // HPC / functional distros
        simple("spack", &["spack.lock"], spack::spack_lock),
        simple("guix", &["manifest.scm"], guix::guix_manifest),
        // Web / build tooling
        simple("bower", &[".bower.json"], bower::bower_json),
        Box::new(meson::MesonWrapTarget),
        simple("buf", &["buf.lock"], buf::buf_lock),
        simple("buf", &["buf.yaml"], buf::buf_yaml),
        // Mint shares the Swift ecosystem id (OSV `SwiftURL`) with the SwiftPM
        // and Carthage targets, so coordinates from all three managers dedupe.
        simple("swift", &["Mintfile"], mint::mintfile),
        Box::new(haxe::HaxeTarget),
        Box::new(racket::RacketInfoTarget),
        Box::new(cabal_plan::CabalPlanTarget),
        Box::new(cpanfile::CpanfileTarget),
        // npm workspace catalogs (`.yml` matched defensively only;
        // pnpm canonically uses `.yaml`)
        simple(
            "npm",
            &["pnpm-workspace.yaml", "pnpm-workspace.yml"],
            pnpm_workspace::catalogs,
        ),
        // SBOM ingestion (CycloneDX + SPDX -> per-purl coordinates)
        Box::new(sbom::SbomTarget),
        // AI / web surfaces
        Box::new(huggingface::HuggingFaceTarget),
        // lazy.nvim's lockfile is committed into dotfiles repos, so it turns
        // up far from ~/.config/nvim; the distinctive basename is enough.
        simple("vim-plugin", &["lazy-lock.json"], vimplugin::lazy_lock),
        Box::new(wordpress::WordPressTarget),
        Box::new(jupyter::JupyterTarget),
        Box::new(browser_chrome::BrowserChromeTarget),
        Box::new(browser_firefox::FirefoxAddonTarget),
        Box::new(k8s_operator::K8sOperatorTarget),
        Box::new(shopify::ShopifyThemeTarget),
        Box::new(shopify::ShopifyAppTarget),
        simple("openai-gpt", &["ai-plugin.json"], openai_gpt::ai_plugin),
    ]
}

/// Run every applicable target against `path`, collecting coordinates.
/// Parsing errors for one target never abort discovery for the others; they
/// land in `warnings` and surface as a scan diagnostic.
pub fn discover_from_file(
    targets: &[Box<dyn ScanTarget>],
    path: &Path,
    out: &mut Vec<PackageRef>,
    warnings: &mut Vec<String>,
) {
    for target in targets.iter().filter(|t| t.detects(path)) {
        let mut emitter = Emitter::new(target.ecosystem_id(), path, out, warnings);
        target.parse(path, &mut emitter);
    }
}

/// The distinct ecosystem ids the default registry can detect, sorted. Powers
/// "what does Husk understand?" surfaces and guards against regressions.
pub fn supported_ecosystems() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = default_targets().iter().map(|t| t.ecosystem_id()).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

pub(crate) fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

/// First 1-based line containing `needle`, for "jump to source" UX. One
/// substring search plus a newline count, not a per-line scan. Parsers that
/// look up many needles in file order should use [`support::LineFinder`].
pub(crate) fn find_line(contents: &str, needle: &str) -> Option<usize> {
    let pos = contents.find(needle)?;
    Some(support::count_newlines(&contents[..pos]) + 1)
}

/// PEP 503 PyPI name normalization: lowercase and collapse runs of `-`, `_`,
/// and `.` to a single `-`.
pub(crate) fn pep503_name(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_sep = false;
    for ch in lower.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
                prev_sep = true;
            }
        } else {
            out.push(ch);
            prev_sep = false;
        }
    }
    out.trim_matches('-').to_string()
}

/// Validate an exact npm/semver pin and return advisory-key form.
///
/// Accepted: `X.Y.Z[-pre][+build]`, optionally prefixed by one leading `=` or
/// `v`/`V`. Build metadata is dropped. Ranges, tags, aliases, wildcards, and
/// partial versions return `None`.
pub(crate) fn exact_semver_pin(spec: &str) -> Option<String> {
    let spec = spec.trim();
    let s = spec.strip_prefix('=').unwrap_or(spec);
    let s = s
        .strip_prefix('v')
        .or_else(|| s.strip_prefix('V'))
        .unwrap_or(s);

    if s.is_empty() || s.contains([' ', '\t', '|', '^', '~', '>', '<', '*', '/', ':', '@']) {
        return None;
    }

    let without_build = s.split_once('+').map(|(core, _)| core).unwrap_or(s);
    let (core, pre) = match without_build.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (without_build, None),
    };

    let mut parts = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    for part in [major, minor, patch] {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }

    if let Some(pre) = pre
        && (pre.is_empty()
            || !pre
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
    {
        return None;
    }

    Some(without_build.to_string())
}

/// Strip a known path suffix (forward-slash form) from `path`, returning the
/// system root before it. Used by host-DB targets to locate sibling files like
/// `/etc/os-release` relative to a database at `var/lib/dpkg/status`.
pub(crate) fn sysroot_before(path: &Path, suffix: &str) -> Option<PathBuf> {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let root = normalized.strip_suffix(suffix)?;
    Some(PathBuf::from(root))
}

/// Read `<sysroot>/etc/os-release` and return `(ID, VERSION_ID)`, both
/// lowercased and unquoted. `None` if the file is absent or lacks either key
/// (in which case a distro target falls back to its bare, inventory-only id).
pub(crate) fn os_release(sysroot: &Path) -> Option<(String, String)> {
    let text = std::fs::read_to_string(sysroot.join("etc/os-release")).ok()?;
    let mut id = None;
    let mut version_id = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("ID=") {
            id = Some(unquote_shell(value));
        } else if let Some(value) = line.strip_prefix("VERSION_ID=") {
            version_id = Some(unquote_shell(value));
        }
    }
    Some((id?.to_ascii_lowercase(), version_id?))
}

/// Unquote an os-release shell-style scalar (`"22.04"` / `'12'` / `12`).
fn unquote_shell(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}
