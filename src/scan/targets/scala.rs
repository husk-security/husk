//! Scala / sbt (`build.sbt.lock` from sbt-dependency-lock, fallback
//! `lock.sbt` from sbt-lock) → OSV `Maven`.
//!
//! sbt has no built-in lockfile; resolution happens at build time via
//! coursier. When a lock plugin is in use, however, two on-disk formats carry
//! the fully-resolved transitive closure as Maven coordinates:
//!
//! * `build.sbt.lock`: JSON produced by sbt-dependency-lock
//!   (stringbean/software.purpledragon). Has `lockVersion`, `timestamp`,
//!   `configurations`, and a `dependencies` array of `{org, name, version,
//!   artifacts, configurations}`. The `name` field already includes any Scala
//!   binary-version suffix (`_2.13`, `_3`, `_sjs1_2.13`, …), so the Maven key
//!   is simply `org:name`. This is the preferred, unambiguous target.
//! * `lock.sbt`: Scala-DSL file from the older sbt-lock plugin (tkawachi)
//!   containing `dependencyOverrides ++= Seq("org" % "name" % "version", …)`.
//!   Single `%` (suffixes already baked in). Only treated as a lock when it
//!   actually contains `dependencyOverrides`, so it is not confused with other
//!   `*.sbt` source files.
//!
//! Maven/OSV package key is `groupId:artifactId` and the Scala binary-version
//! suffix is PART of the artifactId and is preserved verbatim. Versions are
//! used as-is (no `v` strip, no lowercasing, no semver normalization).

use super::find_line;
use super::support::Emitter;
use serde_json::Value as JsonValue;

/// Parse a `build.sbt.lock` JSON document into Maven coordinates.
///
/// Tolerant: a future `lockVersion`, a missing `dependencies` array, or a dep
/// missing `org`/`name`/`version` simply yields fewer (or no) packages rather
/// than an error.
pub(super) fn dependency_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("build.sbt.lock is not valid JSON");
        return;
    };
    let Some(deps) = json.get("dependencies").and_then(JsonValue::as_array) else {
        return;
    };
    for dep in deps {
        let (Some(org), Some(name), Some(version)) = (
            dep.get("org").and_then(JsonValue::as_str),
            dep.get("name").and_then(JsonValue::as_str),
            dep.get("version").and_then(JsonValue::as_str),
        ) else {
            continue;
        };
        if org.is_empty() || name.is_empty() || version.is_empty() {
            continue;
        }
        let coord = format!("{org}:{name}");
        let line = find_line(contents, &format!("\"{name}\""));
        out.pkg(&coord, version, line);
    }
}

/// Parse a `lock.sbt` (`dependencyOverrides ++= Seq(...)`) into Maven
/// coordinates by scanning for `"org" % "name" % "version"` triples.
///
/// Only triples joined by a single `%` are accepted (the generated file never
/// uses `%%`, since the Scala suffix is already baked into `name`). Emits
/// nothing if the file does not look like a real lock (no `dependencyOverrides`).
pub(super) fn lock_sbt(contents: &str, out: &mut Emitter<'_>) {
    if !contents.contains("dependencyOverrides") {
        return;
    }
    for (idx, raw) in contents.lines().enumerate() {
        // A dependency line looks like: "org" % "name" % "version"[ % "conf"],
        let line = raw.trim();
        // Reject `%%` (cross-version) usage which cannot yield a correct Maven
        // key here, and skip lines without the sbt `%` operator entirely.
        if line.contains("%%") || !line.contains('%') {
            continue;
        }
        let literals = quoted_literals(line);
        let (Some(org), Some(name), Some(version)) =
            (literals.first(), literals.get(1), literals.get(2))
        else {
            continue;
        };
        if org.is_empty() || name.is_empty() || version.is_empty() {
            continue;
        }
        // Version literal must contain a digit so config names ("compile",
        // "test") in a 4th slot are never mistaken for a coordinate.
        if !version.chars().any(|c| c.is_ascii_digit()) {
            continue;
        }
        out.pkg(&format!("{org}:{name}"), version, Some(idx + 1));
    }
}

/// Extract the contents of every double-quoted string literal on a line, in
/// order. No escape handling needed: Maven coordinates never contain quotes.
/// (Kept local: `support::unquote` strips one surrounding pair, it cannot
/// enumerate multiple literals on one line.)
fn quoted_literals(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else {
            break;
        };
        out.push(&after[..end]);
        rest = &after[end + 1..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_build_sbt_lock_json() {
        let contents = r#"{
          "lockVersion": 1,
          "timestamp": "2026-06-19T10:15:00.000Z",
          "configurations": ["compile", "test"],
          "dependencies": [
            { "org": "org.apache.commons", "name": "commons-lang3", "version": "3.14.0",
              "configurations": ["compile"] },
            { "org": "com.typesafe.akka", "name": "akka-actor_2.13", "version": "2.6.21",
              "configurations": ["compile"] }
          ]
        }"#;
        let found = run_parser("maven", contents, dependency_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect::<Vec<_>>();
        assert_eq!(
            found,
            vec![
                (
                    "org.apache.commons:commons-lang3".to_string(),
                    "3.14.0".to_string()
                ),
                // Scala binary-version suffix preserved as part of artifactId.
                (
                    "com.typesafe.akka:akka-actor_2.13".to_string(),
                    "2.6.21".to_string()
                ),
            ]
        );
    }

    #[test]
    fn tolerates_missing_dependencies_and_bad_entries() {
        assert!(run_parser("maven", "{}", dependency_lock).is_empty());
        assert!(run_parser("maven", "not json", dependency_lock).is_empty());
        let partial = r#"{ "dependencies": [ { "org": "a", "name": "b" } ] }"#;
        assert!(run_parser("maven", partial, dependency_lock).is_empty());
    }

    #[test]
    fn parses_lock_sbt_overrides() {
        let contents = r#"dependencyOverrides ++= Seq(
          "org.apache.commons" % "commons-lang3" % "3.14.0",
          "com.typesafe.akka" % "akka-actor_2.13" % "2.6.21" % "compile"
        )"#;
        let found = run_parser("maven", contents, lock_sbt)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect::<Vec<_>>();
        assert_eq!(
            found,
            vec![
                (
                    "org.apache.commons:commons-lang3".to_string(),
                    "3.14.0".to_string()
                ),
                (
                    "com.typesafe.akka:akka-actor_2.13".to_string(),
                    "2.6.21".to_string()
                ),
            ]
        );
    }

    #[test]
    fn ignores_non_lock_sbt_and_cross_version() {
        // No `dependencyOverrides` -> not a lock file.
        let src = r#"libraryDependencies += "org.typelevel" %% "cats-core" % "2.10.0""#;
        assert!(run_parser("maven", src, lock_sbt).is_empty());
        // `%%` lines inside a lock are skipped (cannot form a correct key).
        let mixed = "dependencyOverrides ++= Seq(\n  \"o\" %% \"n\" % \"1.0\"\n)";
        assert!(run_parser("maven", mixed, lock_sbt).is_empty());
    }
}
