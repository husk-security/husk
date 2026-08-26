//! Shared knowledge of coding-agent runtime subtrees.
//!
//! Coding agents keep their private chat transcripts, tool logs, and session
//! state under a home dir (`~/.claude/projects`, `~/.cursor/logs`, …). Two scan
//! stages must agree on exactly which subtrees those are: the directory walk
//! prunes them from descent, and the prompt-injection check skips stray files
//! inside them. Keeping the home/runtime-dir lists in one place stops the two
//! sites from drifting apart (a divergence would silently re-expose private
//! chat history to the scanner).

use std::ffi::OsStr;
use std::path::Path;

/// Agent home directories whose runtime subtrees hold private session state.
const AGENT_HOMES: &[&str] = &[".claude", ".cursor", ".codex", ".windsurf", ".gemini"];

/// Runtime subdirectories under an agent home that carry chat transcripts,
/// tool logs, or session/history state rather than instruction/config an agent
/// re-reads.
const RUNTIME_DIRS: &[&str] = &[
    "projects",
    "shell-snapshots",
    "todos",
    "statsig",
    "logs",
    "history",
    "sessions",
    "ide",
];

/// True when `path` passes through a known agent runtime subtree, i.e. some
/// adjacent path pair is (`<agent home>`, `<runtime dir>`). Scoped to those
/// homes so an ordinary `~/projects` is never matched.
pub(crate) fn in_agent_runtime_subtree(path: &Path) -> bool {
    // Keep EVERY component (including non-UTF8 ones) so positional adjacency is
    // preserved. Dropping non-UTF8 components would splice their neighbors
    // together; e.g. `.claude/<non-UTF8>/projects` would look like an adjacent
    // (`.claude`, `projects`) pair and mis-prune. The home/runtime names are all
    // ASCII, so a non-UTF8 component simply equals none of them and acts as a
    // non-matching boundary via a plain `OsStr` comparison.
    let components: Vec<&OsStr> = path.components().map(|c| c.as_os_str()).collect();
    components.windows(2).any(|pair| {
        AGENT_HOMES.iter().any(|home| pair[0] == OsStr::new(home))
            && RUNTIME_DIRS.iter().any(|dir| pair[1] == OsStr::new(dir))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn matches_runtime_subtrees_only_under_agent_homes() {
        assert!(in_agent_runtime_subtree(&PathBuf::from(
            "/home/u/.claude/projects/foo/chat.md"
        )));
        assert!(in_agent_runtime_subtree(&PathBuf::from(
            "/home/u/.cursor/logs/session.txt"
        )));
        // A similarly-named dir NOT under an agent home stays eligible.
        assert!(!in_agent_runtime_subtree(&PathBuf::from(
            "/home/u/projects/foo/README.md"
        )));
        // A runtime-dir name directly under a non-agent home is not matched.
        assert!(!in_agent_runtime_subtree(&PathBuf::from(
            "/home/u/work/logs/app.log"
        )));
    }

    #[test]
    fn agent_config_files_stay_scannable() {
        // The prune is for private session state only. An agent's own settings
        // file is where malware persists (a `SessionStart` hook), so it must
        // never fall inside the pruned set.
        for path in [
            "/home/u/.claude/settings.json",
            "/home/u/.claude/settings.local.json",
            "/home/u/.cursor/mcp.json",
        ] {
            assert!(
                !in_agent_runtime_subtree(&PathBuf::from(path)),
                "{path} is config and must stay scannable"
            );
        }
    }

    // A non-UTF8 component between the agent home and the runtime dir must break
    // adjacency; it must NOT be dropped and let `.claude` / `projects` be
    // treated as neighbors. Unix-only: only there can a path hold invalid UTF-8.
    #[cfg(unix)]
    #[test]
    fn non_utf8_component_breaks_adjacency() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let mut path = PathBuf::from("/home/u/.claude");
        path.push(OsStr::from_bytes(b"\xff\xfe")); // invalid UTF-8 component
        path.push("projects");
        path.push("chat.md");
        assert!(
            !in_agent_runtime_subtree(&path),
            "a non-UTF8 component must not splice `.claude` and `projects` together"
        );

        // A genuinely adjacent pair still matches even when an unrelated non-UTF8
        // component sits elsewhere in the path.
        let mut ok = PathBuf::from("/home/u");
        ok.push(OsStr::from_bytes(b"\xff")); // invalid UTF-8, harmless here
        ok.push(".claude");
        ok.push("projects");
        ok.push("chat.md");
        assert!(in_agent_runtime_subtree(&ok));
    }
}
