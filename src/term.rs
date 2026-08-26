//! Small terminal-text primitives shared by the CLI and TUI.
//!
//! One home for ANSI coloring (gated on the target stream being a terminal,
//! so pipes and redirects always get plain text), the severity color map for
//! plain-terminal output, and the truncation/duration formatters every
//! surface uses. The TUI's richer ratatui palette lives in
//! `crate::tui::theme`; this module is for raw `print!`-style output.

use crate::model::Severity;
use std::fmt::Display;
use std::io::IsTerminal;

/// Wrap `value` in an ANSI style for stdout, or return it plain when stdout
/// is not a terminal (pipes and redirects never see escape codes) or the
/// user opted out via `NO_COLOR`.
pub fn color(value: impl Display, ansi: &str) -> String {
    if std::io::stdout().is_terminal() && !no_color() {
        format!("\x1b[{ansi}m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}

/// [`color`], gated on stderr instead.
pub fn color_stderr(value: impl Display, ansi: &str) -> String {
    if std::io::stderr().is_terminal() && !no_color() {
        format!("\x1b[{ansi}m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}

/// The `NO_COLOR` convention (<https://no-color.org>): any non-empty value
/// disables ANSI styling, regardless of the stream being a terminal.
fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

pub fn severity_ansi(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "31;1",
        Severity::High => "91;1",
        Severity::Medium => "33;1",
        Severity::Low => "34;1",
        Severity::Info => "90;1",
    }
}

/// `1234` → `"1.2s"`, `321` → `"321ms"`.
pub fn format_duration(ms: u128) -> String {
    if ms >= 1000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{ms}ms")
    }
}

/// Shorten `value` to at most `max_chars` by replacing the middle with
/// `...`, the standard treatment for long paths, which keep their most
/// identifying parts at both ends. The result never exceeds `max_chars`;
/// widths too narrow for a meaningful middle split fall back to end
/// truncation so fixed TUI/CLI areas can never overflow.
pub fn truncate_middle(value: &str, max_chars: usize) -> String {
    let len = value.chars().count();
    if len <= max_chars {
        return value.to_string();
    }
    if max_chars < 8 {
        return truncate_end(value, max_chars);
    }
    let keep = max_chars.saturating_sub(3);
    let head = keep / 2;
    let tail = keep - head;
    let start = value.chars().take(head).collect::<String>();
    let skip = len - tail;
    let end = value.chars().skip(skip).collect::<String>();
    format!("{start}...{end}")
}

/// Shorten `value` to at most `max_chars`, replacing the tail with `…`.
/// The result never exceeds `max_chars` (a zero width yields an empty
/// string).
pub fn truncate_end(value: &str, max_chars: usize) -> String {
    let len = value.chars().count();
    if len <= max_chars {
        return value.to_string();
    }
    if max_chars == 0 {
        return String::new();
    }
    let keep = max_chars.saturating_sub(1);
    format!("{}…", value.chars().take(keep).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_middle_keeps_both_ends() {
        assert_eq!(truncate_middle("short", 20), "short");
        let long = "/home/user/projects/very/deep/path/file.txt";
        let out = truncate_middle(long, 20);
        assert_eq!(out.chars().count(), 20);
        assert!(out.starts_with("/home/us"));
        assert!(out.ends_with("file.txt"));
        assert!(out.contains("..."));
        // Below the middle-split minimum, output is still bounded (end-cut).
        let narrow = truncate_middle(long, 7);
        assert_eq!(narrow.chars().count(), 7);
        assert!(narrow.ends_with('…'));
        assert_eq!(truncate_middle(long, 0), "");
    }

    #[test]
    fn truncate_middle_is_char_safe() {
        let unicode = "ααααααααααααααααββββββββββββββββ";
        let out = truncate_middle(unicode, 10);
        assert_eq!(out.chars().count(), 10);
    }

    #[test]
    fn truncate_end_appends_ellipsis() {
        assert_eq!(truncate_end("short", 10), "short");
        assert_eq!(truncate_end("a-long-title", 8), "a-long-…");
        // Always bounded, even at tiny widths.
        assert_eq!(truncate_end("a-long-title", 2), "a…");
        assert_eq!(truncate_end("a-long-title", 1), "…");
        assert_eq!(truncate_end("a-long-title", 0), "");
    }

    #[test]
    fn formats_durations() {
        assert_eq!(format_duration(45), "45ms");
        assert_eq!(format_duration(1500), "1.5s");
    }
}
