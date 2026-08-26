//! A hardened, strictly read-only `git` subprocess builder.
//!
//! Husk inspects git state (commit-signing config, repo top-level, tracked /
//! ignored status) by shelling out to `git`. It must be **read-only toward the
//! scanned repository and immune to an inherited git environment**: a scanner
//! that mutates `.git/config` on scan is unacceptable.
//!
//! Hazards this closes:
//!
//! 1. **Inherited repo-redirection env.** `git` hooks run with `GIT_DIR` (and
//!    friends) set, and that environment can leak into a `husk` invoked from a
//!    hook or an agent/MCP harness. With `GIT_DIR` set, even `git -C <dir> …`
//!    ignores `<dir>` for repo discovery and operates on the inherited repo
//!    instead, so husk would read (or, via any write-capable command, mutate)
//!    the *wrong* repository's `.git`, including the shared config of a repo
//!    that uses linked worktrees. Clearing these variables forces git to act on
//!    exactly the repo husk points at.
//! 2. **Opportunistic writes.** `GIT_OPTIONAL_LOCKS=0` tells git not to take
//!    optional locks or refresh/write state during otherwise-read operations.
//! 3. **Inherited config overrides.** `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`,
//!    and the `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<n>` / `GIT_CONFIG_VALUE_<n>`
//!    family let the environment inject arbitrary config into every `git`
//!    invocation. Left in place, an attacker-controlled env could feed husk
//!    bogus commit-signing / safe-directory / alias settings and skew what
//!    `git config --get` reports. Clearing `GIT_CONFIG_COUNT` neutralizes the
//!    whole indexed key/value mechanism (git only reads `KEY_<i>`/`VALUE_<i>`
//!    for `i < GIT_CONFIG_COUNT`), and clearing the two path overrides stops a
//!    redirected global/system config file.
//!
//! Husk only ever runs read subcommands (`config --get`, `rev-parse`,
//! `ls-files`, `check-ignore`); this builder guarantees they stay read-only and
//! correctly scoped no matter what environment husk was launched in.

use std::process::Command;

/// Git environment variables that redirect repository discovery or inject
/// configuration. Cleared so a husk-launched `git` always operates on the repo
/// it explicitly targets with the config on disk, never state leaked in from a
/// hook / parent process. Clearing `GIT_CONFIG_COUNT` disables the entire
/// indexed `GIT_CONFIG_KEY_<n>` / `GIT_CONFIG_VALUE_<n>` override family, so
/// those unbounded per-index names need not be enumerated.
const REDIRECT_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
];

/// A `git` [`Command`] scrubbed of repo-redirection environment and pinned to
/// never take optional locks: the only way husk should ever invoke git.
pub(crate) fn git_command() -> Command {
    let mut command = Command::new("git");
    for name in REDIRECT_ENV {
        command.env_remove(name);
    }
    command.env("GIT_OPTIONAL_LOCKS", "0");
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn scrubs_redirection_env_and_disables_optional_locks() {
        let command = git_command();
        let overrides: Vec<(&OsStr, Option<&OsStr>)> = command.get_envs().collect();

        // Every redirection variable is explicitly cleared (value `None`).
        for name in REDIRECT_ENV {
            let entry = overrides
                .iter()
                .find(|(key, _)| *key == OsStr::new(name))
                .unwrap_or_else(|| panic!("{name} must be scrubbed"));
            assert!(entry.1.is_none(), "{name} must be removed, not set");
        }

        // Optional locks are disabled so read commands never write.
        let lock = overrides
            .iter()
            .find(|(key, _)| *key == OsStr::new("GIT_OPTIONAL_LOCKS"))
            .expect("GIT_OPTIONAL_LOCKS is set");
        assert_eq!(lock.1, Some(OsStr::new("0")));
    }
}
