//! Docker / OCI base images (`Dockerfile` / `Containerfile` `FROM`, compose
//! `image:`) → inventory-only ecosystem `oci`.
//!
//! Container image references are *not* a package manager and have **no OSV
//! ecosystem**: OSV covers the packages *inside* an image, not the image
//! coordinate. We extract the coordinate so it can be reported and later
//! matched against typosquat / advisory / attestation sources.
//!
//! Coordinate shape (canonical Docker/containerd form):
//!   name    = `<registry>/<repository>` with default-registry (`docker.io`)
//!             and `library/` namespace normalization.
//!   version = `@sha256:...` digest if present (the only truly pinned form),
//!             else the literal tag, else implicit `latest` (unpinned).

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name, oci::parse_reference};
use crate::scan::checks::util::{is_compose_name, is_dockerfile_name};
use std::collections::HashSet;
use std::path::Path;

/// `Dockerfile` / `Containerfile` and their `*.Dockerfile` / `Dockerfile.*`
/// variants: each `FROM` carries a full image reference.
pub struct DockerfileTarget;

impl ScanTarget for DockerfileTarget {
    fn ecosystem_id(&self) -> &'static str {
        "oci"
    }

    fn detects(&self, path: &Path) -> bool {
        file_name(path).is_some_and(is_dockerfile_name)
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        emit_refs(path, out, parse_dockerfile);
    }
}

/// Docker Compose files. Only `image:` scalars under a top-level `services:`
/// map are trusted, to avoid mis-ingesting k8s/CI `image:` keys.
pub struct ComposeTarget;

impl ScanTarget for ComposeTarget {
    fn ecosystem_id(&self) -> &'static str {
        "oci"
    }

    fn detects(&self, path: &Path) -> bool {
        file_name(path).is_some_and(is_compose_name)
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        emit_refs(path, out, parse_compose);
    }
}

/// Identical coordinates repeated within one file are deduped globally by
/// discovery, per coordinate + manifest.
fn emit_refs(path: &Path, out: &mut Emitter<'_>, parse: fn(&str) -> Vec<(String, String, usize)>) {
    let Some(contents) = read_text(path, out) else {
        return;
    };
    for (name, version, line) in parse(&contents) {
        out.pkg(&name, &version, Some(line));
    }
}

/// Assemble logical lines, honoring the `\` line-continuation char (or the
/// override from a `# escape=` parser directive on the first line). Full-line
/// `#` comments are dropped, including inside a pending continuation, which
/// Docker strips before joining (`FROM \` / `# comment` / `node:20` is one
/// instruction). Each logical line carries the 1-based source line it starts
/// on, so instructions report their own line, not the first line that merely
/// mentions the same text (a comment, an ARG).
fn logical_lines(contents: &str) -> Vec<(String, usize)> {
    let mut escape = '\\';
    if let Some(first) = contents.lines().find(|l| !l.trim().is_empty()) {
        let t = first.trim();
        if let Some(val) = t
            .strip_prefix("# escape=")
            .or_else(|| t.strip_prefix("#escape="))
        {
            match val.trim() {
                "`" => escape = '`',
                "\\" => escape = '\\',
                _ => {}
            }
        }
    }

    let mut out = Vec::new();
    let mut pending = String::new();
    let mut pending_start = 1;
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim_end_matches(['\r', '\n']);
        // Comments never contribute text and never end a continuation.
        if line.trim_start().starts_with('#') {
            continue;
        }
        if pending.is_empty() {
            pending_start = idx + 1;
        }
        if let Some(stripped) = line.strip_suffix(escape) {
            pending.push_str(stripped);
            pending.push(' ');
        } else {
            pending.push_str(line);
            out.push((std::mem::take(&mut pending), pending_start));
        }
    }
    if !pending.trim().is_empty() {
        out.push((pending, pending_start));
    }
    out
}

/// Resolve `${NAME}`, `${NAME:-default}`, `${NAME:+alt}` and `$NAME` against
/// the ARG-default map. Unknown variables are left literal (caller treats a ref
/// still containing `$` as unresolved).
fn substitute_args(input: &str, args: &[(String, Option<String>)]) -> String {
    let lookup = |name: &str| -> Option<String> {
        args.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone().unwrap_or_default())
    };
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(braced) = after.strip_prefix('{') {
            // ${...} form, kept literal if unclosed.
            if let Some(close) = braced.find('}') {
                out.push_str(&resolve_braced(&braced[..close], &lookup));
                rest = &braced[close + 1..];
                continue;
            }
        } else if after.starts_with(|c: char| c.is_alphabetic() || c == '_') {
            let end = after
                .char_indices()
                .find(|(_, c)| !(c.is_alphanumeric() || *c == '_'))
                .map(|(i, _)| i)
                .unwrap_or(after.len());
            let name = &after[..end];
            match lookup(name) {
                Some(v) => out.push_str(&v),
                None => {
                    out.push('$');
                    out.push_str(name);
                }
            }
            rest = &after[end..];
            continue;
        }
        out.push('$');
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Resolve the inner text of a `${...}` expression supporting `:-` / `:+`.
fn resolve_braced(inner: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    if let Some((name, default)) = inner.split_once(":-") {
        return lookup(name)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| default.to_string());
    }
    if let Some((name, alt)) = inner.split_once(":+") {
        return match lookup(name) {
            Some(v) if !v.is_empty() => alt.to_string(),
            _ => String::new(),
        };
    }
    match lookup(inner) {
        Some(v) => v,
        None => format!("${{{inner}}}"),
    }
}

/// Extract `(canonical_name, version, line_number)` for every registry-pulled
/// base image in a Dockerfile. Skips `scratch` and intra-file stage aliases.
fn parse_dockerfile(contents: &str) -> Vec<(String, String, usize)> {
    let logical = logical_lines(contents);
    let mut args: Vec<(String, Option<String>)> = Vec::new();
    let mut stages: HashSet<String> = HashSet::new();
    let mut seen_from = false;
    let mut out = Vec::new();

    for (logical_line, start_line) in &logical {
        let mut tokens = logical_line.split_whitespace();
        let Some(first) = tokens.next() else { continue };
        let instr = first.to_ascii_uppercase();

        // Only ARGs before the first FROM are usable in FROM interpolation.
        if instr == "ARG" && !seen_from {
            if let Some(decl) = tokens.next() {
                let (name, val) = match decl.split_once('=') {
                    Some((n, v)) => (n.to_string(), Some(unquote_all(v).to_string())),
                    None => (decl.to_string(), None),
                };
                args.push((name, val));
            }
            continue;
        }

        if instr != "FROM" {
            continue;
        }
        seen_from = true;

        // Skip leading `--platform=...` (or any `--flag`) options.
        let rest: Vec<&str> = tokens.collect();
        let mut rest = rest.as_slice();
        while rest.first().is_some_and(|t| t.starts_with("--")) {
            rest = &rest[1..];
        }
        let Some(raw_ref) = rest.first().copied() else {
            continue;
        };

        // Capture an `AS <stage>` alias for later stage-reference filtering.
        if let Some(pos) = rest.iter().position(|t| t.eq_ignore_ascii_case("AS"))
            && let Some(stage) = rest.get(pos + 1)
        {
            stages.insert(stage.to_ascii_lowercase());
        }

        let resolved = substitute_args(raw_ref, &args);

        // `FROM scratch` → no image. `FROM <prior-stage>` → intra-file alias.
        if resolved.eq_ignore_ascii_case("scratch") {
            continue;
        }
        if stages.contains(&resolved.to_ascii_lowercase()) {
            continue;
        }

        if let Some((name, version)) = parse_reference(&resolved) {
            out.push((name, version, *start_line));
        }
    }
    out
}

/// Strip surrounding quotes (both kinds, repeated); deliberately looser than
/// [`super::support::unquote`], which strips exactly one matching pair.
fn unquote_all(s: &str) -> &str {
    s.trim_matches('"').trim_matches('\'')
}

/// `image:` scalars under a top-level `services:` map. Only `${VAR:-default}`
/// defaults are resolved; bare vars stay unresolved (no `.env` context).
fn parse_compose(contents: &str) -> Vec<(String, String, usize)> {
    let mut out = Vec::new();
    let mut in_services = false;
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();

        if !in_services {
            if indent == 0 && trimmed.starts_with("services:") {
                in_services = true;
            }
            continue;
        }

        if indent == 0 && !trimmed.starts_with("services:") {
            in_services = false;
            continue;
        }

        if let Some(val) = trimmed.strip_prefix("image:") {
            let val = unquote_all(val.trim());
            let resolved = resolve_compose_interp(val);
            if let Some((name, version)) = parse_reference(&resolved) {
                out.push((name, version, idx + 1));
            }
        }
    }
    out
}

/// Resolve compose `${VAR:-default}` to its default; leave bare `${VAR}` /
/// `${VAR:?msg}` unresolved (so `parse_reference` drops them). `$$` → `$`.
fn resolve_compose_interp(input: &str) -> String {
    let input = input.replace("$$", "\u{0}"); // protect literal `$`
    let resolved = substitute_args(&input, &[]);
    resolved.replace('\u{0}', "$")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dockerfile_resolves_arg_and_digest() {
        let df = "\
# syntax=docker/dockerfile:1
ARG NODE_VERSION=20.11.1

FROM node:${NODE_VERSION}-bookworm-slim AS builder
RUN npm ci

FROM gcr.io/distroless/nodejs20-debian12@sha256:3d1d2c8e3f5b9a7c6e4d2b1a0f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6 AS runtime
COPY --from=builder /app /app

FROM scratch
FROM builder
";
        let pkgs = parse_dockerfile(df);
        // node (ARG resolved) + distroless (digest); scratch + stage alias skipped.
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].0, "docker.io/library/node");
        assert_eq!(pkgs[0].1, "20.11.1-bookworm-slim");
        assert_eq!(pkgs[1].0, "gcr.io/distroless/nodejs20-debian12");
        assert_eq!(
            pkgs[1].1,
            "sha256:3d1d2c8e3f5b9a7c6e4d2b1a0f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6"
        );
    }

    #[test]
    fn from_line_is_reported_even_when_the_ref_appears_earlier() {
        // A comment (or any earlier line) mentioning the same image reference
        // must not steal the provenance: the FROM instruction's own line wins.
        let df = "\
# based on node:20-alpine
ARG NOTE=node:20-alpine

FROM node:20-alpine
";
        let pkgs = parse_dockerfile(df);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].0, "docker.io/library/node");
        assert_eq!(pkgs[0].2, 4, "provenance anchors to the FROM line");

        // A FROM spanning a continuation reports the line it starts on.
        let continued = "\
FROM \\
  node:20-alpine
";
        let pkgs = parse_dockerfile(continued);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].2, 1);
    }

    #[test]
    fn comments_inside_continuations_are_stripped_not_joined() {
        // Docker removes full-line comments BEFORE joining continuations, so a
        // comment between `FROM \` and the image must neither terminate the
        // logical line nor leak its text into the joined instruction.
        let df = "\
FROM \\
# picking the slim variant
  node:20-alpine AS base
RUN apk add --no-cache \\
    # tools the healthcheck needs
    curl \\
    ca-certificates
FROM postgres:16
";
        let pkgs = parse_dockerfile(df);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].0, "docker.io/library/node");
        assert_eq!(pkgs[0].1, "20-alpine");
        assert_eq!(pkgs[0].2, 1, "provenance anchors to the FROM line");
        assert_eq!(pkgs[1].0, "docker.io/library/postgres");
        assert_eq!(pkgs[1].1, "16");
    }

    #[test]
    fn compose_only_under_services() {
        let yaml = "\
services:
  web:
    image: nginx:1.27-alpine
  db:
    image: \"postgres:16\"
  app:
    build: .
";
        let pkgs = parse_compose(yaml);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].0, "docker.io/library/nginx");
        assert_eq!(pkgs[0].1, "1.27-alpine");
        assert_eq!(pkgs[1].0, "docker.io/library/postgres");
        assert_eq!(pkgs[1].1, "16");

        // No `services:` map → no false positives (e.g. a k8s manifest).
        let k8s = "spec:\n  containers:\n    - image: evil:latest\n";
        assert!(parse_compose(k8s).is_empty());
    }

    #[test]
    fn filename_matching() {
        assert!(is_dockerfile_name("Dockerfile"));
        assert!(is_dockerfile_name("dockerfile"));
        assert!(is_dockerfile_name("Dockerfile.prod"));
        assert!(is_dockerfile_name("app.Dockerfile"));
        assert!(is_dockerfile_name("Containerfile"));
        assert!(!is_dockerfile_name("Manifest.toml"));
        assert!(is_compose_name("docker-compose.yml"));
        assert!(is_compose_name("compose.yaml"));
        assert!(is_compose_name("docker-compose.prod.yml"));
        assert!(!is_compose_name("values.yaml"));
    }

    #[test]
    fn substitute_args_variants() {
        let args = vec![
            ("VER".to_string(), Some("1.2".to_string())),
            ("EMPTY".to_string(), Some(String::new())),
        ];
        assert_eq!(substitute_args("node:$VER", &args), "node:1.2");
        assert_eq!(substitute_args("node:${VER}", &args), "node:1.2");
        assert_eq!(substitute_args("node:${MISSING:-20}", &args), "node:20");
        assert_eq!(substitute_args("node:${EMPTY:-20}", &args), "node:20");
        assert_eq!(substitute_args("x:${VER:+alt}", &args), "x:alt");
        // Unknown vars stay literal; stray `$` and unclosed braces untouched.
        assert_eq!(substitute_args("node:$NOPE", &args), "node:$NOPE");
        assert_eq!(substitute_args("node:${NOPE}", &args), "node:${NOPE}");
        assert_eq!(substitute_args("a$1b", &args), "a$1b");
        assert_eq!(substitute_args("tail$", &args), "tail$");
        assert_eq!(substitute_args("x${open", &args), "x${open");
    }
}
