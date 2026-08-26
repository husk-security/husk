//! Pager delivery for long text reports (`husk scan`, `husk status`).
//!
//! The convention every mature CLI follows (git, gh, systemctl): when stdout
//! is an interactive terminal, pipe long output through a pager so nothing is
//! truncated and nothing floods the screen; when stdout is a pipe or file,
//! write the full plain text straight through so `husk scan | grep X` just
//! works. The pager resolves as `HUSK_PAGER` > `PAGER` > `less`; `--no-pager`,
//! an empty value, or `cat` disables it. Everything fails open: if the pager
//! cannot be spawned, the report is printed plainly instead; a broken pager
//! must never eat a security report.

use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

/// Print `text` to stdout, through a pager when appropriate (see module docs).
pub(super) fn deliver(text: &str, no_pager: bool) {
    let command = pager_command(
        no_pager,
        std::io::stdout().is_terminal(),
        std::env::var("HUSK_PAGER").ok().as_deref(),
        std::env::var("PAGER").ok().as_deref(),
    );
    match command {
        Some(argv) => page(text, &argv),
        None => write_plain(text),
    }
}

/// Decide whether to page and with what, from explicit inputs only (the
/// testable seam). Returns the pager argv, or `None` for plain stdout.
///
/// `None` when: `--no-pager` was passed, stdout is not a terminal, or the
/// winning environment value (`HUSK_PAGER` over `PAGER`) is empty or `cat`.
/// With no environment override the default is `less`; [`page`] supplies
/// `LESS=FRX` (quit if it fits, keep colors, no screen clear) when the user
/// has not set their own `LESS`.
fn pager_command(
    no_pager: bool,
    is_tty: bool,
    husk_pager: Option<&str>,
    pager: Option<&str>,
) -> Option<Vec<String>> {
    if no_pager || !is_tty {
        return None;
    }
    match husk_pager.or(pager) {
        Some(value) => {
            let argv: Vec<String> = value.split_whitespace().map(str::to_string).collect();
            if argv.is_empty() || argv[0] == "cat" {
                return None;
            }
            Some(argv)
        }
        None => Some(vec!["less".to_string()]),
    }
}

/// Spawn the pager and feed it `text` on stdin; fall back to plain stdout if
/// it cannot be spawned. A write error (the user quit `less` mid-stream) is
/// deliberately ignored; that is the pager working as intended.
fn page(text: &str, argv: &[String]) {
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]).stdin(Stdio::piped());
    // Match git's treatment of less: sensible flags unless the user set their
    // own. F = don't page when it fits on one screen, R = pass ANSI colors
    // through, X = don't clear the screen on exit.
    if argv[0] == "less" && std::env::var_os("LESS").is_none() {
        command.env("LESS", "FRX");
    }
    let Ok(mut child) = command.spawn() else {
        write_plain(text);
        return;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(text.as_bytes());
    }
    let _ = child.wait();
}

/// Write `text` to stdout directly. A `BrokenPipe` (e.g. `husk scan | head`)
/// is the reader's prerogative, not an error.
fn write_plain(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::pager_command;

    #[test]
    fn never_pages_without_a_terminal_or_with_no_pager() {
        assert_eq!(pager_command(false, false, None, None), None, "piped");
        assert_eq!(pager_command(true, true, None, None), None, "--no-pager");
        assert_eq!(pager_command(true, false, None, None), None);
    }

    #[test]
    fn defaults_to_less_on_a_terminal() {
        assert_eq!(
            pager_command(false, true, None, None),
            Some(vec!["less".to_string()])
        );
    }

    #[test]
    fn respects_pager_env_and_husk_pager_precedence() {
        assert_eq!(
            pager_command(false, true, None, Some("more")),
            Some(vec!["more".to_string()])
        );
        assert_eq!(
            pager_command(false, true, None, Some("less -S +F")),
            Some(vec!["less".to_string(), "-S".to_string(), "+F".to_string()])
        );
        // HUSK_PAGER wins over PAGER.
        assert_eq!(
            pager_command(false, true, Some("bat"), Some("more")),
            Some(vec!["bat".to_string()])
        );
    }

    #[test]
    fn empty_or_cat_pager_disables_paging() {
        assert_eq!(pager_command(false, true, None, Some("")), None);
        assert_eq!(pager_command(false, true, None, Some("cat")), None);
        assert_eq!(pager_command(false, true, Some(""), Some("more")), None);
    }
}
