//! Container build and dev-server configuration risks: the Docker socket or
//! privileged mode handed to a compose service, base images on mutable
//! references, secrets baked into image layers, and dev servers listening on
//! every interface.

use super::util::{
    find_line, is_compose_name, is_dockerfile_name, line_for_offset, looks_secretish, redact,
    trim_evidence,
};
use super::{Check, CheckContext};
use crate::model::{Finding, Severity};
use crate::rule::{Category, Rule, RuleId};
use regex::Regex;
use std::borrow::Cow;
use std::sync::OnceLock;

pub struct Container;

static RULES: &[Rule] = &[
    Rule {
        id: RuleId::lit("docker-socket-mount"),
        title: Cow::Borrowed("Docker socket is mounted into a container"),
        category: Category::ExposedConfig,
        default_severity: Severity::High,
        rationale: Cow::Borrowed(
            "A process with /var/run/docker.sock can ask the daemon for a privileged container, which is root on the host.",
        ),
    },
    Rule {
        id: RuleId::lit("compose-privileged"),
        title: Cow::Borrowed("Compose service runs privileged or with admin capabilities"),
        category: Category::ExposedConfig,
        default_severity: Severity::High,
        rationale: Cow::Borrowed(
            "privileged: true and SYS_ADMIN erase the container boundary; code in the service can reach the host.",
        ),
    },
    Rule {
        id: RuleId::lit("image-unpinned"),
        title: Cow::Borrowed("Container base image is not pinned to a digest"),
        category: Category::InstallHardening,
        default_severity: Severity::Medium,
        rationale: Cow::Borrowed(
            "A tag is a mutable reference the publisher can move; only an @sha256 digest guarantees the same image.",
        ),
    },
    Rule {
        id: RuleId::lit("dockerfile-secret"),
        title: Cow::Borrowed("Secret in a Dockerfile ARG or ENV"),
        category: Category::Secret,
        default_severity: Severity::High,
        rationale: Cow::Borrowed(
            "Build arguments and environment variables persist in the final image; anyone who pulls it can read them.",
        ),
    },
    Rule {
        id: RuleId::lit("dev-server-all-interfaces"),
        title: Cow::Borrowed("Dev server listens on all interfaces"),
        category: Category::ExposedConfig,
        default_severity: Severity::Medium,
        rationale: Cow::Borrowed(
            "A dev server bound to 0.0.0.0 serves unauthenticated code execution to everyone on the local network.",
        ),
    },
];

fn is_vite_config_name(name: &str) -> bool {
    name.strip_prefix("vite.config.")
        .is_some_and(|ext| matches!(ext, "js" | "ts" | "mjs" | "mts" | "cjs" | "cts"))
}

fn vite_host_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\bhost\s*:\s*(true|["']0\.0\.0\.0["']|["']::["'])"#).expect("valid regex")
    })
}

impl Check for Container {
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn applies(&self, ctx: &CheckContext) -> bool {
        let name = ctx.file_name();
        is_dockerfile_name(name)
            || is_compose_name(name)
            || name == "package.json"
            || is_vite_config_name(name)
    }
    fn run(&self, ctx: &CheckContext, out: &mut Vec<Finding>) {
        let name = ctx.file_name();
        if is_dockerfile_name(name) {
            dockerfile_images(ctx, out);
            dockerfile_secrets(ctx, out);
        } else if is_compose_name(name) {
            compose_socket(ctx, out);
            compose_privileged(ctx, out);
            compose_images(ctx, out);
        } else if name == "package.json" {
            package_scripts(ctx, out);
        } else if is_vite_config_name(name) {
            vite_config(ctx, out);
        }
    }
}

fn compose_socket(ctx: &CheckContext, out: &mut Vec<Finding>) {
    for (idx, line) in ctx.contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.contains("/var/run/docker.sock") {
            continue;
        }
        out.push(
            Finding::from_rule("docker-socket-mount")
                .id("docker-socket-mount")
                .source("Husk container scanner")
                .at(ctx.path.to_path_buf(), Some(idx + 1))
                .summary(
                    "The service mounts /var/run/docker.sock; anything inside it can instruct the Docker daemon, which is root on the host.",
                )
                .evidence(trim_evidence(trimmed))
                .recommend(
                    "Remove the socket mount. If a tool genuinely needs the daemon API, front it with a filtering socket proxy.",
                ),
        );
        return; // one finding per file
    }
}

/// `privileged: true`, plus `cap_add` of `SYS_ADMIN`/`ALL` not compensated by a
/// `cap_drop` of `ALL`. Capability lists are tracked file-wide, not
/// per-service, which is deliberately conservative for a local dev scanner.
fn compose_privileged(ctx: &CheckContext, out: &mut Vec<Finding>) {
    let contents = ctx.contents;
    if let Some(line) = find_line(contents, "privileged: true") {
        out.push(
            Finding::from_rule("compose-privileged")
                .id("compose-privileged")
                .source("Husk container scanner")
                .at(ctx.path.to_path_buf(), Some(line))
                .summary("privileged: true disables container isolation entirely; the service can reach host devices and kernel interfaces.")
                .recommend("Remove privileged: true and grant only the specific capability the service needs."),
        );
    }

    let (mut in_add, mut in_drop) = (false, false);
    let (mut added_admin_line, mut dropped_all) = (None, false);
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if let Some(item) = trimmed.strip_prefix('-') {
            let cap = item.trim().trim_matches('"').trim_matches('\'');
            if in_add && (cap.eq_ignore_ascii_case("SYS_ADMIN") || cap.eq_ignore_ascii_case("ALL"))
            {
                added_admin_line.get_or_insert(idx + 1);
            }
            if in_drop && cap.eq_ignore_ascii_case("ALL") {
                dropped_all = true;
            }
            continue;
        }
        in_add = trimmed.starts_with("cap_add:");
        in_drop = trimmed.starts_with("cap_drop:");
    }
    if let Some(line) = added_admin_line
        && !dropped_all
    {
        out.push(
            Finding::from_rule("compose-privileged")
                .id("compose-cap-add")
                .source("Husk container scanner")
                .at(ctx.path.to_path_buf(), Some(line))
                .summary("cap_add grants SYS_ADMIN or ALL with no cap_drop: [ALL]; that capability set is equivalent to a privileged container.")
                .recommend("Drop all capabilities with cap_drop: [ALL] and add back only the ones the service needs."),
        );
    }
}

/// Why a registry reference is not truly pinned, or `None` when it carries an
/// `@sha256:` digest.
fn unpinned_reason(reference: &str) -> Option<String> {
    if reference.contains("@sha256:") {
        return None;
    }
    // The tag lives after the last `:` that follows the last `/` (a registry
    // port like `reg:5000/img` is not a tag separator).
    let name_start = reference.rfind('/').map(|idx| idx + 1).unwrap_or(0);
    Some(match reference[name_start..].split_once(':') {
        None => format!("{reference} has no tag, so every pull resolves the mutable latest tag."),
        Some((_, "latest")) => format!("{reference} tracks the mutable latest tag."),
        Some((_, tag)) => {
            format!(
                "{reference} pins the {tag} tag, which the publisher can move; only a digest is immutable."
            )
        }
    })
}

fn push_unpinned(ctx: &CheckContext, reference: &str, line: usize, out: &mut Vec<Finding>) {
    let Some(summary) = unpinned_reason(reference) else {
        return;
    };
    out.push(
        Finding::from_rule("image-unpinned")
            .id(format!("image-unpinned:{reference}"))
            .source("Husk container scanner")
            .at(ctx.path.to_path_buf(), Some(line))
            .summary(summary)
            .recommend(
                "Pin the image to a digest (name:tag@sha256:...) and let update automation bump it deliberately.",
            ),
    );
}

/// `FROM` references. Line-oriented on purpose: `targets/docker.rs` owns the
/// faithful parse (continuations, ARG substitution) for inventory; this check
/// only needs the overwhelmingly common single-line form and skips anything it
/// cannot judge (unresolved `$VAR` references).
fn dockerfile_images(ctx: &CheckContext, out: &mut Vec<Finding>) {
    let mut stages: Vec<String> = Vec::new();
    for (idx, line) in ctx.contents.lines().enumerate() {
        let mut tokens = line.split_whitespace();
        if !tokens
            .next()
            .is_some_and(|first| first.eq_ignore_ascii_case("FROM"))
        {
            continue;
        }
        let rest: Vec<&str> = tokens.collect();
        let mut rest = rest.as_slice();
        while rest.first().is_some_and(|tok| tok.starts_with("--")) {
            rest = &rest[1..];
        }
        let Some(reference) = rest.first().copied() else {
            continue;
        };
        if let Some(pos) = rest.iter().position(|tok| tok.eq_ignore_ascii_case("AS"))
            && let Some(stage) = rest.get(pos + 1)
        {
            stages.push(stage.to_ascii_lowercase());
        }
        if reference.contains('$')
            || reference.eq_ignore_ascii_case("scratch")
            || stages.contains(&reference.to_ascii_lowercase())
        {
            continue;
        }
        push_unpinned(ctx, reference, idx + 1, out);
    }
}

/// `image:` scalars under a top-level `services:` map, mirroring the gating in
/// `targets/docker.rs` so a k8s manifest's `image:` keys are never misread.
fn compose_images(ctx: &CheckContext, out: &mut Vec<Finding>) {
    let mut in_services = false;
    for (idx, line) in ctx.contents.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let top_level = line.len() == trimmed.len();
        if top_level {
            in_services = trimmed.starts_with("services:");
            continue;
        }
        if !in_services {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("image:") {
            let reference = value.trim().trim_matches('"').trim_matches('\'');
            if reference.is_empty() || reference.contains('$') {
                continue;
            }
            push_unpinned(ctx, reference, idx + 1, out);
        }
    }
}

/// Secret-shaped literals on `ARG`/`ENV` lines. `RUN --mount=type=secret` is
/// the documented alternative and never produces such a line, so a Dockerfile
/// using it correctly is never flagged.
fn dockerfile_secrets(ctx: &CheckContext, out: &mut Vec<Finding>) {
    for (idx, line) in ctx.contents.lines().enumerate() {
        let mut tokens = line.split_whitespace();
        let Some(first) = tokens.next() else { continue };
        if !first.eq_ignore_ascii_case("ENV") && !first.eq_ignore_ascii_case("ARG") {
            continue;
        }
        let rest = line[line.find(first).unwrap_or(0) + first.len()..].trim();
        for (key, value) in env_pairs(rest) {
            let lower_key = key.to_ascii_lowercase();
            let named_like_secret = ["key", "token", "secret", "password", "passwd", "credential"]
                .iter()
                .any(|marker| lower_key.contains(marker));
            if !named_like_secret || !looks_secretish(value) {
                continue;
            }
            out.push(
                Finding::from_rule("dockerfile-secret")
                    .id(format!("dockerfile-secret:{key}"))
                    .source("Husk container scanner")
                    .at(ctx.path.to_path_buf(), Some(idx + 1))
                    .summary(format!(
                        "{first} {key} carries a secret-shaped value; build arguments and environment variables persist in the final image."
                    ))
                    .evidence(redact(value))
                    .recommend(
                        "Deliver build-time secrets with RUN --mount=type=secret, which never enters a layer, and rotate this value if the image was ever pushed.",
                    ),
            );
        }
    }
}

/// `KEY=value` pairs (and the legacy `ENV KEY value` form) from the remainder
/// of an ENV/ARG instruction.
fn env_pairs(rest: &str) -> Vec<(&str, &str)> {
    let mut pairs: Vec<(&str, &str)> = rest
        .split_whitespace()
        .filter_map(|token| token.split_once('='))
        .map(|(key, value)| (key, value.trim_matches('"').trim_matches('\'')))
        .collect();
    if pairs.is_empty() {
        // Legacy space-separated form: everything after the key is the value.
        let mut words = rest.splitn(2, char::is_whitespace);
        if let (Some(key), Some(value)) = (words.next(), words.next()) {
            pairs.push((key, value.trim().trim_matches('"').trim_matches('\'')));
        }
    }
    pairs
}

/// A `--host` that binds every interface: `--host 0.0.0.0`, `--host=::`, or a
/// bare `--host` (which vite and friends treat as listen-on-all).
fn script_binds_all_interfaces(script: &str) -> bool {
    let tokens: Vec<&str> = script.split_whitespace().collect();
    for (idx, token) in tokens.iter().enumerate() {
        if let Some(value) = token.strip_prefix("--host=") {
            if value.is_empty() || value == "0.0.0.0" || value == "::" {
                return true;
            }
        } else if *token == "--host" {
            match tokens.get(idx + 1) {
                None => return true,
                Some(next) if next.starts_with('-') || matches!(*next, "&&" | "||" | ";" | "|") => {
                    return true;
                }
                Some(&"0.0.0.0") | Some(&"::") => return true,
                _ => {}
            }
        }
    }
    false
}

fn package_scripts(ctx: &CheckContext, out: &mut Vec<Finding>) {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(ctx.contents) else {
        return;
    };
    let Some(scripts) = json.get("scripts").and_then(|value| value.as_object()) else {
        return;
    };
    for (name, script) in scripts {
        let Some(script) = script.as_str() else {
            continue;
        };
        if !script_binds_all_interfaces(script) {
            continue;
        }
        out.push(
            Finding::from_rule("dev-server-all-interfaces")
                .id(format!("dev-server-all-interfaces:{name}"))
                .source("Husk container scanner")
                .at(ctx.path.to_path_buf(), find_line(ctx.contents, "--host"))
                .summary(format!(
                    "The {name} script starts a dev server on all interfaces; everyone on the local network can reach it."
                ))
                .evidence(trim_evidence(script))
                .recommend(
                    "Remove the --host flag so the server binds 127.0.0.1; bind wider only briefly when a device test needs it.",
                ),
        );
    }
}

fn vite_config(ctx: &CheckContext, out: &mut Vec<Finding>) {
    let Some(mat) = vite_host_re().find(ctx.contents) else {
        return;
    };
    out.push(
        Finding::from_rule("dev-server-all-interfaces")
            .id("dev-server-all-interfaces")
            .source("Husk container scanner")
            .at(
                ctx.path.to_path_buf(),
                Some(line_for_offset(ctx.contents, mat.start())),
            )
            .summary(
                "server.host exposes the Vite dev server on all interfaces; everyone on the local network can reach it.",
            )
            .evidence(trim_evidence(mat.as_str()))
            .recommend(
                "Delete the host setting so Vite binds 127.0.0.1; bind wider only briefly when a device test needs it.",
            ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn run_at(path: &str, contents: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let ctx = CheckContext::new(Path::new(path), contents);
        if Container.applies(&ctx) {
            Container.run(&ctx, &mut out);
        }
        out
    }

    fn rule_ids(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .map(|finding| finding.rule_id.as_ref().unwrap().as_str())
            .collect()
    }

    #[test]
    fn wired_into_catalog() {
        // Fails until the check is registered in `default_checks()`, which is
        // what populates the rule catalog `Finding::from_rule` reads.
        let finding = Finding::from_rule("image-unpinned");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.category, Category::InstallHardening);
    }

    #[test]
    fn compose_socket_mount_is_flagged() {
        let yaml =
            "services:\n  app:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n";
        let f = run_at("/p/docker-compose.yml", yaml);
        assert!(rule_ids(&f).contains(&"docker-socket-mount"));
        // A commented mount is not a mount.
        let commented = "services:\n  app:\n    volumes: []\n    #  - /var/run/docker.sock:/var/run/docker.sock\n";
        assert!(
            !rule_ids(&run_at("/p/docker-compose.yml", commented)).contains(&"docker-socket-mount")
        );
    }

    #[test]
    fn compose_privileged_and_uncompensated_cap_add_are_flagged() {
        let yaml = "services:\n  a:\n    privileged: true\n  b:\n    cap_add:\n      - SYS_ADMIN\n";
        let findings = run_at("/p/compose.yaml", yaml);
        let ids = rule_ids(&findings);
        assert_eq!(
            ids.iter().filter(|id| **id == "compose-privileged").count(),
            2
        );

        let compensated =
            "services:\n  b:\n    cap_drop:\n      - ALL\n    cap_add:\n      - SYS_ADMIN\n";
        assert!(run_at("/p/compose.yaml", compensated).is_empty());
    }

    #[test]
    fn dockerfile_unpinned_variants() {
        let df = "\
FROM node
FROM node:latest
FROM node:20-alpine AS build
FROM build
FROM scratch
FROM ghcr.io/distroless/nodejs@sha256:3d1d2c8e3f5b9a7c6e4d2b1a0f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6
FROM node:$VER
";
        let f = run_at("/p/Dockerfile", df);
        let unpinned: Vec<&Finding> = f
            .iter()
            .filter(|finding| finding.rule_id.as_ref().unwrap().as_str() == "image-unpinned")
            .collect();
        // Implicit tag, :latest, and a mutable tag; stage ref, scratch, digest,
        // and unresolved $VER are all skipped.
        assert_eq!(unpinned.len(), 3);
        assert!(unpinned[0].summary.contains("no tag"));
        assert!(unpinned[1].summary.contains("latest tag"));
        assert!(unpinned[2].summary.contains("20-alpine"));
    }

    #[test]
    fn compose_image_unpinned_only_under_services() {
        let yaml = "services:\n  web:\n    image: nginx:latest\n";
        assert!(rule_ids(&run_at("/p/docker-compose.yml", yaml)).contains(&"image-unpinned"));
        let pinned = "services:\n  web:\n    image: nginx:1.27@sha256:3d1d2c8e3f5b9a7c6e4d2b1a0f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6\n";
        assert!(run_at("/p/docker-compose.yml", pinned).is_empty());
        // The filename gate keeps this off k8s and CI yaml entirely.
        assert!(run_at("/p/deployment.yaml", yaml).is_empty());
    }

    #[test]
    fn dockerfile_secret_literal_is_flagged_and_redacted() {
        let df = "ENV DEPLOY_TOKEN=q7wX2mZ9pL4kR8vN1tY6bC3dE5\n";
        let f = run_at("/p/Dockerfile", df);
        let ids = rule_ids(&f);
        assert!(ids.contains(&"dockerfile-secret"));
        let finding = f
            .iter()
            .find(|finding| finding.rule_id.as_ref().unwrap().as_str() == "dockerfile-secret")
            .unwrap();
        assert!(
            !finding
                .evidence
                .as_ref()
                .unwrap()
                .contains("q7wX2mZ9pL4kR8vN1tY6bC3dE5")
        );
    }

    #[test]
    fn dockerfile_plain_config_and_secret_mounts_are_not_flagged() {
        // A version pin is not a secret, and the documented secret-mount path
        // produces no ARG/ENV literal to flag.
        let df = "ARG NODE_VERSION=20.11.1\nENV PORT=3000\nRUN --mount=type=secret,id=npmrc npm ci\nFROM node:20@sha256:3d1d2c8e3f5b9a7c6e4d2b1a0f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6\n";
        assert!(!rule_ids(&run_at("/p/Dockerfile", df)).contains(&"dockerfile-secret"));
    }

    #[test]
    fn package_script_host_variants() {
        assert!(script_binds_all_interfaces("vite --host 0.0.0.0"));
        assert!(script_binds_all_interfaces("vite --host"));
        assert!(script_binds_all_interfaces("vite --host --port 3000"));
        assert!(script_binds_all_interfaces("vite --host && echo up"));
        assert!(script_binds_all_interfaces("next dev --host=::"));
        assert!(!script_binds_all_interfaces("vite --host 127.0.0.1"));
        assert!(!script_binds_all_interfaces("vite --port 3000"));

        let json = r#"{"scripts": {"dev": "vite --host 0.0.0.0", "build": "vite build"}}"#;
        let f = run_at("/p/package.json", json);
        assert_eq!(rule_ids(&f), vec!["dev-server-all-interfaces"]);
    }

    #[test]
    fn vite_config_host_is_flagged() {
        let ts = "export default {\n  server: { host: true },\n};\n";
        assert_eq!(
            rule_ids(&run_at("/p/vite.config.ts", ts)),
            vec!["dev-server-all-interfaces"]
        );
        let quoted = "export default { server: { host: '0.0.0.0' } };\n";
        assert_eq!(run_at("/p/vite.config.mts", quoted).len(), 1);
        let localhost = "export default { server: { host: 'localhost' } };\n";
        assert!(run_at("/p/vite.config.ts", localhost).is_empty());
    }

    #[test]
    fn applies_gate() {
        for name in [
            "/p/Dockerfile",
            "/p/app.Dockerfile",
            "/p/Containerfile",
            "/p/docker-compose.yml",
            "/p/compose.override.yaml",
            "/p/package.json",
            "/p/vite.config.ts",
        ] {
            assert!(
                Container.applies(&CheckContext::new(Path::new(name), "")),
                "{name}"
            );
        }
        for name in ["/p/values.yaml", "/p/main.rs", "/p/vite.config.json"] {
            assert!(
                !Container.applies(&CheckContext::new(Path::new(name), "")),
                "{name}"
            );
        }
    }
}
