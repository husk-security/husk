//! Shared, allocation-light helpers for the [`Check`](super::Check) detectors.
//! Also used by the file-walk code in `scan/local.rs` (e.g. `scan_git_hooks`
//! reuses [`dangerous_command_reason`]).

use std::path::Path;

/// True if any path component equals `needle` (e.g. `extensions`, `.claude`).
pub fn path_contains(path: &Path, needle: &str) -> bool {
    path.components()
        .any(|component| component.as_os_str().to_string_lossy() == needle)
}

/// Classify a shell/script command by the riskiest behavior it exhibits.
pub fn dangerous_command_reason(command: &str) -> Option<&'static str> {
    let lower = command.to_ascii_lowercase();
    if lower.contains("curl ") || lower.contains("wget ") || lower.contains("invoke-webrequest") {
        Some("downloads code or data from the network")
    } else if lower.contains("base64") || lower.contains("frombase64string") {
        Some("decodes embedded content")
    } else if lower.contains("eval(") || lower.contains("node -e") || lower.contains("python -c") {
        Some("executes inline code")
    } else if lower.contains("child_process") || lower.contains("spawn(") || lower.contains("exec(")
    {
        Some("spawns child processes")
    } else if lower.contains(".ssh") || lower.contains(".aws") || lower.contains(".npmrc") {
        Some("references credential locations")
    } else if lower.contains("chmod +x") && (lower.contains("/tmp") || lower.contains("$tmp")) {
        Some("creates an executable in a temporary directory")
    } else {
        None
    }
}

/// Heuristic: does a string look like a hardcoded secret value?
pub fn looks_secretish(value: &str) -> bool {
    let value = value.trim();
    value.len() >= 16
        && (value.contains("sk-")
            || value.starts_with("gh")
            || value.starts_with("xox")
            || value.starts_with("AKIA")
            || value
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .count()
                > 24)
}

/// 1-based line number for a byte offset into `contents`.
pub fn line_for_offset(contents: &str, offset: usize) -> usize {
    contents[..offset.min(contents.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

/// 1-based line number of the first line containing `needle`.
pub fn find_line(contents: &str, needle: &str) -> Option<usize> {
    contents
        .lines()
        .position(|line| line.contains(needle))
        .map(|idx| idx + 1)
}

/// Mask a secret down to its last four characters, enough to recognise which
/// key a finding is about and no more.
///
/// Evidence is not private: it lands in `scan --json`, in the cached report,
/// and in whatever a user pastes into a bug report. So the disclosure has to
/// be small in absolute terms *and* small relative to the value: showing four
/// characters of a 20-character key already leaks a fifth of it, which is why
/// anything shorter is masked entirely. The length gate counts characters, not
/// bytes, so a short multi-byte value cannot buy itself a partial reveal.
pub fn redact(value: &str) -> String {
    let length = value.chars().count();
    if length <= 20 {
        return "<redacted>".to_string();
    }
    let tail = value.chars().skip(length - 4).collect::<String>();
    format!("...{tail}")
}

/// Collapse whitespace and clip to at most 160 bytes for compact evidence
/// display, cutting on a char boundary so non-ASCII evidence never panics.
pub fn trim_evidence(value: &str) -> String {
    let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() > 160 {
        let mut end = 160;
        while !collapsed.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &collapsed[..end])
    } else {
        collapsed
    }
}

/// The single source line containing `offset`, trimmed for evidence.
pub fn snippet_at(contents: &str, offset: usize) -> String {
    let line_start = contents[..offset.min(contents.len())]
        .rfind('\n')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let line_end = contents[offset.min(contents.len())..]
        .find('\n')
        .map(|idx| offset + idx)
        .unwrap_or(contents.len());
    trim_evidence(&contents[line_start..line_end])
}

/// True for a full 40-char hex commit SHA (a pinned GitHub Action ref).
pub fn is_full_sha(reference: &str) -> bool {
    reference.len() == 40 && reference.chars().all(|ch| ch.is_ascii_hexdigit())
}

/// `Dockerfile` / `Containerfile` and their `*.Dockerfile` / `Dockerfile.*`
/// variants.
pub fn is_dockerfile_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "dockerfile"
        || lower == "containerfile"
        || lower.starts_with("dockerfile.")
        || lower.ends_with(".dockerfile")
}

/// `compose` / `docker-compose` base names with a `.yml`/`.yaml` extension,
/// including dotted overrides (`docker-compose.override.yml`).
pub fn is_compose_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some(stem) = lower
        .strip_suffix(".yml")
        .or_else(|| lower.strip_suffix(".yaml"))
    else {
        return false;
    };
    stem == "compose"
        || stem == "docker-compose"
        || stem.starts_with("compose.")
        || stem.starts_with("docker-compose.")
}

/// tasks.json, devcontainer.json, and VS Code settings.json are
/// JSON-with-comments in practice: `//` and `/* */` comments plus trailing
/// commas are all accepted by the editors that read them. Strip those
/// (string-aware) before handing the text to serde_json.
pub fn parse_jsonc(contents: &str) -> Option<serde_json::Value> {
    serde_json::from_str(&strip_jsonc(contents)).ok()
}

fn strip_jsonc(contents: &str) -> String {
    // Pass 1: drop comments, tracking string state so `//` inside a value
    // (an URL, a Windows path) survives.
    let mut stripped = String::with_capacity(contents.len());
    let mut chars = contents.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            stripped.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                stripped.push(ch);
            }
            '/' => match chars.peek() {
                Some('/') => {
                    while chars.peek().is_some_and(|next| *next != '\n') {
                        chars.next();
                    }
                }
                Some('*') => {
                    chars.next();
                    let mut prev = '\0';
                    for next in chars.by_ref() {
                        if prev == '*' && next == '/' {
                            break;
                        }
                        prev = next;
                    }
                }
                _ => stripped.push(ch),
            },
            _ => stripped.push(ch),
        }
    }
    // Pass 2: drop a comma whose next non-whitespace character closes the
    // container, again string-aware.
    let mut cleaned = String::with_capacity(stripped.len());
    let mut pending = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for ch in stripped.chars() {
        if in_string {
            cleaned.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if !pending.is_empty() {
            if ch.is_whitespace() {
                pending.push(ch);
                continue;
            }
            if matches!(ch, '}' | ']') {
                cleaned.extend(pending.chars().skip(1));
            } else {
                cleaned.push_str(&pending);
            }
            pending.clear();
        }
        match ch {
            ',' => pending.push(ch),
            '"' => {
                in_string = true;
                cleaned.push(ch);
            }
            _ => cleaned.push(ch),
        }
    }
    cleaned.push_str(&pending);
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_evidence_clips_long_ascii_with_ellipsis() {
        let long = "x".repeat(500);
        let trimmed = trim_evidence(&long);
        assert_eq!(trimmed, format!("{}...", "x".repeat(160)));
    }

    #[test]
    fn trim_evidence_never_panics_on_multibyte_evidence() {
        // The clip must land on a char boundary: a mid-char byte slice panics,
        // and the panic isolation around checks then silently drops the file's
        // findings.
        let long = "é".repeat(200); // 2 bytes per char: byte 160 is a boundary…
        let trimmed = trim_evidence(&long);
        assert!(trimmed.ends_with("..."));
        assert!(trimmed.len() <= 163);
        let odd = format!("a{}", "€".repeat(120)); // …and here it is not.
        let trimmed = trim_evidence(&odd);
        assert!(trimmed.ends_with("..."));
        assert!(trimmed.is_char_boundary(trimmed.len() - 3));
    }

    #[test]
    fn redact_reveals_only_a_short_tail_of_a_long_value() {
        // A real GitHub PAT: the prefix identifies the kind of key, and the
        // evidence must not carry it.
        let token = "ghp_R8kQ2mZ7vP1nX4wL9sT0bC3dE6fG5hJ8kM2qY7zA";
        assert_eq!(redact(token), "...Y7zA");
        // Short enough that four characters would be a meaningful fraction.
        assert_eq!(redact("sk-1234567890abcdef"), "<redacted>");
        assert_eq!(redact(""), "<redacted>");
    }

    #[test]
    fn redact_counts_characters_not_bytes() {
        // 14 chars, 42 bytes: a byte-length gate would treat this as long
        // enough to reveal part of, and could also slice mid-character.
        let value = "パスワード秘密鍵値設定情報用";
        assert_eq!(value.chars().count(), 14);
        assert_eq!(redact(value), "<redacted>");
        // Above the gate, the tail is four whole characters.
        let long = "パスワード秘密鍵値設定情報用xyz1234ABCD";
        assert_eq!(redact(long), "...ABCD");
    }

    #[test]
    fn trim_evidence_collapses_whitespace_and_keeps_short_values() {
        assert_eq!(trim_evidence("a\t b\n  c"), "a b c");
    }

    #[test]
    fn strip_jsonc_preserves_strings_that_look_like_comments() {
        let json = parse_jsonc(r#"{"url":"https://x.invalid/a//b","glob":"/*"} // tail"#).unwrap();
        assert_eq!(json["url"], "https://x.invalid/a//b");
        assert_eq!(json["glob"], "/*");
    }
}
