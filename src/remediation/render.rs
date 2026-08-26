//! What a fix would do, computed once.
//!
//! Every op except [`FixOp::RunTool`] decides its whole result from the file's
//! current text, so one pure function answers three questions at once: what
//! the executor writes, whether there is anything to write, and what the user
//! is shown. Computing them separately is how a preview comes to disagree with
//! what applying actually does, so [`super::exec`] renders through here too.
//!
//! Two things reach a surface. The **diff** is what Husk would change on disk.
//! The **command** is the equivalent a developer can run themselves, which is
//! the point of showing it: a fix you can read as a command is a fix you can
//! check. Each fragment of that command is exact for the op it came from, and
//! an op with no faithful one-liner contributes none, so a shown command never
//! paraphrases what Husk does.

use super::op::{DocFormat, FixOp};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};
use std::path::{Path, PathBuf};

/// How a fix reads before it runs, planned server-side so the CLI, TUI, web
/// and MCP cannot show four different answers.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FixPreview {
    /// One entry per file Husk would rewrite. Empty when the fix only runs a
    /// program, which is the tier that cannot be previewed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diff: Vec<FileDiff>,
    /// The same fix as something to run by hand, carrying the flags Husk
    /// applies (a relock that skips lifecycle scripts shows
    /// `--ignore-scripts`). `None` when no op has a faithful command form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The directory `command` must run in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    /// Whether `command` alone lands the user where Husk would. False means
    /// the diff carries edits no command expresses, and the surface has to say
    /// so rather than implying the one-liner is the whole fix.
    pub complete: bool,
}

/// What one file would look like afterwards.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileDiff {
    pub path: PathBuf,
    /// Unified diff of the file's current bytes against the fix's. A surface
    /// renders it by line prefix (`+`, `-`, space, or an `@@` hunk header), so
    /// no surface implements diff logic and the text pastes into a review
    /// unchanged.
    pub diff: String,
    pub added: usize,
    pub removed: usize,
    /// The file does not exist yet, so every line is new.
    pub created: bool,
}

/// Lines of context kept either side of a change. Two is enough to place a
/// one-line edit without turning a card into a file viewer.
const CONTEXT: usize = 2;

/// Cap on rendered diff lines. A generated file can be long, and a fix card is
/// not a file viewer; the elision is shown rather than silently dropped.
const MAX_LINES: usize = 200;

/// Cap on the file size a diff is computed over. Above it the preview is
/// dropped: nothing about a multi-megabyte file reads usefully in a card.
pub const MAX_DIFF_BYTES: usize = 512 * 1024;

/// What an op resolves to against the file as it currently reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rendered {
    /// The file should end up holding exactly these bytes, plus what to report
    /// once it does.
    Write { contents: String, detail: String },
    /// Already true on disk, and why there is nothing to do.
    Satisfied(String),
    /// The op runs a program, whose result is not knowable in advance.
    Command,
}

/// Why an op cannot be resolved against the file in front of it.
///
/// Typed rather than prose so the executor and the preview refuse for the same
/// reasons; [`super::plan::Blocker`] is deliberately not reused, because that
/// is a *planning* outcome and these are facts about the file right now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenderError {
    /// The file moved under a plan made against its old bytes.
    Stale {
        path: PathBuf,
        expect: String,
        start: usize,
        end: usize,
    },
    /// The document could not be edited: it does not parse, or the key path
    /// does not fit its shape.
    Edit { path: PathBuf, cause: String },
    /// The file the op edits is not there.
    Missing { path: PathBuf },
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenderError::Stale {
                path,
                expect,
                start,
                end,
            } => write!(
                f,
                "{} changed since this fix was planned (expected `{expect}` at bytes \
                 {start}..{end}). Re-scan and try again",
                display_name(path)
            ),
            RenderError::Edit { path, cause } => {
                write!(f, "could not edit {}: {cause}", path.display())
            }
            RenderError::Missing { path } => {
                write!(f, "could not read {}: it is not there", path.display())
            }
        }
    }
}

/// Resolve `op` against `existing`, the file's current text (`None` when the
/// file does not exist, which is the only legitimate empty document).
///
/// Pure: it neither reads nor writes. The bytes it returns are the bytes the
/// executor writes and the bytes the diff is computed from.
pub fn render(op: &FixOp, existing: Option<&str>) -> Result<Rendered, RenderError> {
    match op {
        FixOp::AppendUniqueLine { path, line, header } => {
            let existing = existing.unwrap_or_default();
            if existing.lines().any(|candidate| candidate.trim() == line) {
                return Ok(Rendered::Satisfied(format!(
                    "{} already contains `{line}`",
                    display_name(path)
                )));
            }
            let mut contents = existing.to_string();
            if !contents.is_empty() && !contents.ends_with('\n') {
                contents.push('\n');
            }
            if contents.is_empty()
                && let Some(header) = header
            {
                contents.push_str(header);
                contents.push('\n');
            }
            contents.push_str(line);
            contents.push('\n');
            Ok(Rendered::Write {
                contents,
                detail: format!("appended `{line}` to {}", path.display()),
            })
        }

        FixOp::CreateFile { path, contents } => {
            if existing.is_some() {
                return Ok(Rendered::Satisfied(format!(
                    "{} already exists",
                    display_name(path)
                )));
            }
            Ok(Rendered::Write {
                contents: contents.clone(),
                detail: format!("wrote {}", display_name(path)),
            })
        }

        FixOp::SetValue {
            path,
            format,
            key,
            value,
        } => {
            let existing = existing.unwrap_or_default();
            let contents =
                set_value(format, existing, key, value).map_err(|error| RenderError::Edit {
                    path: path.clone(),
                    cause: format!("{error:#}"),
                })?;
            if contents == existing {
                return Ok(Rendered::Satisfied(format!(
                    "{} already sets {} to {value}",
                    display_name(path),
                    key.join(".")
                )));
            }
            Ok(Rendered::Write {
                contents,
                detail: format!("set {} to {value} in {}", key.join("."), display_name(path)),
            })
        }

        FixOp::ReplaceSpan {
            path,
            start,
            end,
            expect,
            replacement,
        } => {
            let Some(existing) = existing else {
                return Err(RenderError::Missing { path: path.clone() });
            };
            let found = existing.get(*start..*end);
            if found == Some(replacement.as_str()) {
                return Ok(Rendered::Satisfied(format!(
                    "{} already reads `{replacement}` there",
                    display_name(path)
                )));
            }
            if found != Some(expect.as_str()) {
                return Err(RenderError::Stale {
                    path: path.clone(),
                    expect: expect.clone(),
                    start: *start,
                    end: *end,
                });
            }
            let mut contents = String::with_capacity(existing.len());
            contents.push_str(&existing[..*start]);
            contents.push_str(replacement);
            contents.push_str(&existing[*end..]);
            Ok(Rendered::Write {
                contents,
                detail: format!(
                    "replaced `{expect}` with `{replacement}` in {}",
                    display_name(path)
                ),
            })
        }

        FixOp::RunTool { .. } => Ok(Rendered::Command),
    }
}

/// The shell one-liner that does what `op` does, when one exists that does it
/// **exactly**.
///
/// Exactness is the whole point: a developer who runs what Husk shows must end
/// up where Husk would have put them, so an approximation is worse than
/// nothing. A byte-range edit and a generated file have no honest one-liner,
/// and the diff beside the command carries them instead.
///
/// `manager` is the program the recipe relocks with. A manifest edit is shown
/// as *that* manager's command, because a project's package manager is the one
/// tool its developer is certain to have.
pub fn shell_equivalent(
    op: &FixOp,
    existing: Option<&str>,
    manager: Option<&str>,
) -> Option<String> {
    match op {
        FixOp::RunTool { program, args, .. } => Some(
            std::iter::once(program.as_str())
                .chain(args.iter().map(String::as_str))
                .map(shell_quote)
                .collect::<Vec<_>>()
                .join(" "),
        ),

        // Taken from the rendered bytes rather than re-derived, so the append
        // carries whatever husk's own append would: the header on an empty
        // file, the newline a truncated last line is missing.
        FixOp::AppendUniqueLine { path, .. } => {
            let Ok(Rendered::Write { contents, .. }) = render(op, existing) else {
                return None;
            };
            let suffix = contents.strip_prefix(existing.unwrap_or_default())?;
            Some(format!(
                "printf '{}' >> {}",
                printf_format(suffix),
                shell_quote(&path.to_string_lossy())
            ))
        }

        // A `pkg set` edits package.json and nothing else, and its dot path
        // cannot address a key segment that contains a dot.
        FixOp::SetValue {
            path,
            format: DocFormat::Json,
            key,
            value,
        } => {
            let package_json = path.file_name().is_some_and(|name| name == "package.json");
            let addressable = key.iter().all(|segment| !segment.contains(['.', '[']));
            (package_json && addressable).then(|| {
                format!(
                    "{} {}",
                    pkg_set(manager),
                    shell_quote(&format!("{}={value}", key.join(".")))
                )
            })
        }

        FixOp::SetValue { .. } | FixOp::ReplaceSpan { .. } | FixOp::CreateFile { .. } => None,
    }
}

/// The subcommand that writes one `package.json` key, for the manager the
/// project actually uses.
///
/// Bun ships its own (`bun pm pkg`), and a bun-only machine need not have npm
/// on it at all. Neither yarn line has an equivalent, so a yarn project is
/// shown npm's: it rewrites package.json and touches neither the lockfile nor
/// node_modules, and yarn is itself distributed through npm.
fn pkg_set(manager: Option<&str>) -> &'static str {
    match manager {
        Some("bun") => "bun pm pkg set",
        _ => "npm pkg set",
    }
}

/// The change between two versions of one file.
pub fn file_diff(path: &Path, before: Option<&str>, after: &str) -> FileDiff {
    let created = before.is_none();
    let text = TextDiff::from_lines(before.unwrap_or_default(), after);

    let (mut added, mut removed) = (0, 0);
    for change in text.iter_all_changes() {
        match change.tag() {
            ChangeTag::Insert => added += 1,
            ChangeTag::Delete => removed += 1,
            ChangeTag::Equal => {}
        }
    }

    // Headers included so the output is a complete unified diff: surfaces hand
    // it to a diff parser rather than splitting lines themselves.
    let name = path.display().to_string();
    let mut diff = text
        .unified_diff()
        .context_radius(CONTEXT)
        .missing_newline_hint(false)
        .header(if created { "/dev/null" } else { &name }, &name)
        .to_string();

    // A generated file can be long and a fix card is not a file viewer, so the
    // tail is dropped rather than rendered. Counts above are of the whole
    // change, so a truncated diff still reports honestly.
    if diff.lines().count() > MAX_LINES {
        let kept: Vec<&str> = diff.lines().take(MAX_LINES).collect();
        diff = format!("{}\n@@ diff truncated @@\n", kept.join("\n"));
    }

    FileDiff {
        path: path.to_path_buf(),
        diff,
        added,
        removed,
        created,
    }
}

/// Quote `token` for a POSIX shell, leaving a plain word alone so the common
/// command stays readable.
fn shell_quote(token: &str) -> String {
    let bare = |ch: char| ch.is_ascii_alphanumeric() || "._/=@:+-,^".contains(ch);
    if !token.is_empty() && token.chars().all(bare) {
        return token.to_string();
    }
    format!("'{}'", token.replace('\'', r"'\''"))
}

/// A single-quoted `printf` format string that emits `text` byte for byte.
fn printf_format(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '%' => out.push_str("%%"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\'' => out.push_str(r"'\''"),
            _ => out.push(ch),
        }
    }
    out
}

/// Set one key in a structured document, preserving as much of the original as
/// each format's editor allows.
fn set_value(format: &DocFormat, existing: &str, key: &[String], value: &str) -> Result<String> {
    anyhow::ensure!(!key.is_empty(), "empty key path");
    match format {
        DocFormat::Json => {
            let mut doc: serde_json::Value = if existing.trim().is_empty() {
                serde_json::json!({})
            } else {
                serde_json::from_str(existing).context("parse JSON")?
            };
            let mut node = &mut doc;
            for segment in &key[..key.len() - 1] {
                let object = node
                    .as_object_mut()
                    .with_context(|| format!("`{segment}`'s parent is not a JSON object"))?;
                node = object
                    .entry(segment.as_str())
                    .or_insert_with(|| serde_json::json!({}));
            }
            node.as_object_mut()
                .with_context(|| format!("`{}` is not a JSON object", key.join(".")))?
                .insert(
                    key[key.len() - 1].clone(),
                    serde_json::Value::String(value.to_string()),
                );
            let mut text = serde_json::to_string_pretty(&doc)?;
            text.push('\n');
            Ok(text)
        }
        // Line-oriented on purpose: Husk has no YAML serialiser and adding one
        // would reformat the user's whole workspace file on every write.
        DocFormat::YamlBlock => set_yaml_block(existing, key, value),
        DocFormat::KeyValue => {
            anyhow::ensure!(key.len() == 1, "key-value files have no nested keys");
            let key = &key[0];
            let desired = format!("{key}={value}");
            // Replace every active definition with one canonical line, so a
            // duplicate key cannot leave the old value winning.
            let is_key = |line: &str| {
                !line.trim_start().starts_with('#')
                    && line
                        .split_once('=')
                        .is_some_and(|(candidate, _)| candidate.trim() == key)
            };
            let mut next = String::new();
            let mut inserted = false;
            for line in existing.lines() {
                if is_key(line) {
                    if !inserted {
                        next.push_str(&desired);
                        next.push('\n');
                        inserted = true;
                    }
                } else {
                    next.push_str(line);
                    next.push('\n');
                }
            }
            if !inserted {
                next.push_str(&desired);
                next.push('\n');
            }
            Ok(next)
        }
    }
}

/// Insert or replace `key[0]` -> `key[1]: value` in a two-level YAML mapping,
/// touching only the affected lines.
fn set_yaml_block(existing: &str, key: &[String], value: &str) -> Result<String> {
    anyhow::ensure!(
        key.len() == 2,
        "YAML block edits support exactly `<section>.<entry>`"
    );
    let (section, entry) = (&key[0], &key[1]);
    let header = format!("{section}:");
    let line = format!("  \"{entry}\": \"{value}\"");

    let mut out: Vec<String> = Vec::new();
    let mut in_section = false;
    let mut wrote = false;
    for raw in existing.lines() {
        if in_section {
            let indented = raw.starts_with(' ') || raw.starts_with('\t');
            if !indented && !raw.trim().is_empty() {
                // The section ended without the entry: append it before
                // leaving.
                if !wrote {
                    out.push(line.clone());
                    wrote = true;
                }
                in_section = false;
            } else if let Some((name, _)) = raw.split_once(':')
                && name.trim().trim_matches(['"', '\'']) == entry
            {
                out.push(line.clone());
                wrote = true;
                continue;
            }
        } else if raw.trim() == header {
            in_section = true;
        }
        out.push(raw.to_string());
    }
    if !wrote {
        if !in_section {
            out.push(header);
        }
        out.push(line);
    }
    let mut text = out.join("\n");
    text.push('\n');
    Ok(text)
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append(header: Option<&str>) -> FixOp {
        FixOp::AppendUniqueLine {
            path: PathBuf::from("/proj/.gitignore"),
            line: ".env".into(),
            header: header.map(str::to_string),
        }
    }

    fn written(op: &FixOp, existing: Option<&str>) -> String {
        match render(op, existing) {
            Ok(Rendered::Write { contents, .. }) => contents,
            other => panic!("expected a write, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_file_and_an_empty_one_are_the_same_document() {
        assert_eq!(written(&append(None), None), ".env\n");
        assert_eq!(written(&append(None), Some("")), ".env\n");
        // A file that exists keeps its contents; only the header case differs.
        assert_eq!(
            written(&append(Some("# note")), Some("a\n")),
            "a\n.env\n",
            "a header belongs to a file husk is creating, not to one it appends to"
        );
    }

    #[test]
    fn an_already_satisfied_op_writes_nothing() {
        assert!(matches!(
            render(&append(None), Some("node_modules/\n.env\n")),
            Ok(Rendered::Satisfied(_))
        ));
    }

    #[test]
    fn replace_span_refuses_bytes_that_moved() {
        let op = FixOp::ReplaceSpan {
            path: PathBuf::from("/proj/requirements.txt"),
            start: 0,
            end: 5,
            expect: "5.6.0".into(),
            replacement: "5.6.1".into(),
        };
        assert!(matches!(
            render(&op, Some("9.9.9\n")),
            Err(RenderError::Stale { .. })
        ));
        assert!(matches!(
            render(&op, None),
            Err(RenderError::Missing { .. })
        ));
        assert_eq!(written(&op, Some("5.6.0\n")), "5.6.1\n");
    }

    #[test]
    fn the_shown_command_writes_the_same_bytes_as_the_edit() {
        // The trust claim the command box makes: what husk would do and what
        // the user is invited to run are the same change.
        let op = append(Some("# Added by `husk fix`"));
        assert_eq!(
            shell_equivalent(&op, Some("node_modules/\n"), None).unwrap(),
            "printf '.env\\n' >> /proj/.gitignore"
        );
        assert_eq!(
            shell_equivalent(&op, None, None).unwrap(),
            "printf '# Added by `husk fix`\\n.env\\n' >> /proj/.gitignore",
            "the header is part of the bytes, so it is part of the command"
        );
        // A file whose last line has no newline gets one from husk; the
        // one-liner has to carry it too or the two results differ.
        assert_eq!(
            shell_equivalent(&op, Some("a"), None).unwrap(),
            "printf '\\n.env\\n' >> /proj/.gitignore"
        );
    }

    #[test]
    fn only_package_json_gets_the_pkg_set_command() {
        let set = |path: &str, key: &[&str]| FixOp::SetValue {
            path: PathBuf::from(path),
            format: DocFormat::Json,
            key: key.iter().map(|k| (*k).to_string()).collect(),
            value: "4.17.21".into(),
        };
        assert_eq!(
            shell_equivalent(
                &set("/proj/package.json", &["overrides", "lodash"]),
                None,
                Some("npm")
            ),
            Some("npm pkg set overrides.lodash=4.17.21".to_string())
        );
        // A dotted package name is not addressable by a `pkg set` dot path,
        // and a wrong command is worse than none.
        assert_eq!(
            shell_equivalent(
                &set("/proj/package.json", &["overrides", "lodash.merge"]),
                None,
                Some("npm")
            ),
            None
        );
        assert_eq!(
            shell_equivalent(
                &set("/proj/other.json", &["overrides", "lodash"]),
                None,
                Some("npm")
            ),
            None
        );
    }

    #[test]
    fn a_manifest_edit_is_shown_as_the_projects_own_managers_command() {
        // A bun-only machine need not have npm on it, so telling its owner to
        // run npm is a command they cannot run. Bun ships `bun pm pkg`.
        let op = FixOp::SetValue {
            path: PathBuf::from("/proj/package.json"),
            format: DocFormat::Json,
            key: vec!["overrides".into(), "minimist".into()],
            value: "1.2.6".into(),
        };
        assert_eq!(
            shell_equivalent(&op, None, Some("bun")).unwrap(),
            "bun pm pkg set overrides.minimist=1.2.6"
        );
        // Neither yarn line has one, so those projects fall back to npm's,
        // which edits package.json and nothing else.
        for manager in [Some("yarn"), Some("npm"), None] {
            assert_eq!(
                shell_equivalent(&op, None, manager).unwrap(),
                "npm pkg set overrides.minimist=1.2.6"
            );
        }
    }

    #[test]
    fn a_tool_command_keeps_the_safety_flags_husk_passes() {
        let op = FixOp::RunTool {
            program: "npm".into(),
            args: vec!["install".into(), "--ignore-scripts".into()],
            cwd: PathBuf::from("/proj"),
            purpose: super::super::op::ToolPurpose::Required,
        };
        assert_eq!(
            shell_equivalent(&op, None, Some("npm")).unwrap(),
            "npm install --ignore-scripts"
        );
    }

    #[test]
    fn a_one_line_append_diffs_to_one_added_line() {
        let diff = file_diff(
            Path::new("/proj/.gitignore"),
            Some("node_modules/\n"),
            "node_modules/\n.env\n",
        );
        assert_eq!(diff.added, 1);
        assert_eq!(diff.removed, 0);
        assert!(!diff.created);
        assert!(diff.diff.contains("+.env"));
        assert!(diff.diff.contains(" node_modules/"));
    }

    #[test]
    fn a_long_file_elides_unchanged_distance_rather_than_scrolling_it() {
        let before: String = (0..80).map(|n| format!("line {n}\n")).collect();
        let after = before
            .replace("line 0\n", "line zero\n")
            .replace("line 79\n", "line seventy-nine\n");
        let diff = file_diff(Path::new("/proj/f"), Some(&before), &after);
        assert_eq!((diff.added, diff.removed), (2, 2));
        // Two separate hunks, so the 76 untouched lines between them are not
        // in the output at all.
        let hunks = diff.diff.lines().filter(|l| l.starts_with("@@")).count();
        assert_eq!(hunks, 2);
        assert!(!diff.diff.contains("line 40"));
    }

    #[test]
    fn set_value_json_creates_nested_keys_and_is_idempotent() {
        let out = set_value(
            &DocFormat::Json,
            "{\"name\":\"app\"}",
            &["overrides".into(), "lodash".into()],
            "4.17.21",
        )
        .unwrap();
        assert!(out.contains("\"lodash\": \"4.17.21\""));
        let again = set_value(
            &DocFormat::Json,
            &out,
            &["overrides".into(), "lodash".into()],
            "4.17.21",
        )
        .unwrap();
        assert_eq!(
            out, again,
            "re-setting the same value must not churn a file"
        );
    }

    #[test]
    fn key_value_collapses_duplicate_active_definitions() {
        let out = set_value(
            &DocFormat::KeyValue,
            "# note\nignore-scripts=false\nregistry=x\nignore-scripts=false\n",
            &["ignore-scripts".into()],
            "true",
        )
        .unwrap();
        assert_eq!(out, "# note\nignore-scripts=true\nregistry=x\n");
    }

    #[test]
    fn yaml_block_edits_touch_only_the_entry_line() {
        // pnpm-workspace.yaml carries the whole workspace definition; a
        // round-trip through a serialiser would reformat all of it.
        let existing = "packages:\n  - 'apps/*'\n\noverrides:\n  \"left-pad\": \"1.3.0\"\n";
        let out =
            set_yaml_block(existing, &["overrides".into(), "lodash".into()], "4.17.21").unwrap();
        assert!(out.contains("  - 'apps/*'"));
        assert!(out.contains("\"left-pad\": \"1.3.0\""));
        assert!(out.contains("\"lodash\": \"4.17.21\""));

        // Replacing an existing entry rewrites that line only.
        let replaced =
            set_yaml_block(&out, &["overrides".into(), "left-pad".into()], "1.3.1").unwrap();
        assert!(replaced.contains("\"left-pad\": \"1.3.1\""));
        assert!(!replaced.contains("\"left-pad\": \"1.3.0\""));

        // No section yet: one gets appended.
        let fresh = set_yaml_block(
            "packages:\n  - '.'\n",
            &["overrides".into(), "a".into()],
            "1",
        )
        .unwrap();
        assert!(fresh.contains("overrides:\n  \"a\": \"1\""));
    }
}
