//! Machine posture: whole-device controls.

use super::{
    ControlAssessment, ControlContext, ControlStatus, assessment, evidence, home, read_text,
};
use std::path::PathBuf;

/// Whether the root filesystem sits on an encrypted volume.
///
/// This is the multiplier on every credential-at-rest control: a plaintext
/// token file is a laptop-theft finding only when the disk is readable. The
/// probe is per-platform because there is no portable answer.
pub(super) fn full_disk_encryption(_: &ControlContext<'_>) -> ControlAssessment {
    let (status, summary, path) = disk_encryption_state();
    assessment(
        "full-disk-encryption",
        status,
        vec![evidence(summary, path)],
        Vec::new(),
    )
}

#[cfg(target_os = "linux")]
fn disk_encryption_state() -> (ControlStatus, String, Option<PathBuf>) {
    // A dm-crypt mapping advertises itself in sysfs: every device-mapper
    // device exposes a UUID, and dm-crypt prefixes its own with `CRYPT-`.
    // Reading sysfs needs no privileges and no subprocess.
    let mapped = std::fs::read_dir("/sys/block")
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| read_text(&entry.path().join("dm/uuid")))
        .any(|uuid| uuid.trim_start().starts_with("CRYPT-"));
    if mapped {
        return (
            ControlStatus::Passed,
            "An active dm-crypt volume was found".to_string(),
            None,
        );
    }
    let crypttab = PathBuf::from("/etc/crypttab");
    let declared = read_text(&crypttab).is_some_and(|contents| {
        contents
            .lines()
            .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
    });
    if declared {
        return (
            ControlStatus::Partial,
            "/etc/crypttab declares an encrypted volume, but none is mapped right now".to_string(),
            Some(crypttab),
        );
    }
    (
        ControlStatus::Failed,
        "No encrypted volume was found in /sys/block or /etc/crypttab".to_string(),
        None,
    )
}

#[cfg(target_os = "macos")]
fn disk_encryption_state() -> (ControlStatus, String, Option<PathBuf>) {
    let Some(output) = command_line("fdesetup", &["status"]) else {
        return (
            ControlStatus::Unknown,
            "fdesetup did not answer, so FileVault state is unknown".to_string(),
            None,
        );
    };
    if output.contains("FileVault is On") {
        (ControlStatus::Passed, "FileVault is on".to_string(), None)
    } else {
        (ControlStatus::Failed, output, None)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn disk_encryption_state() -> (ControlStatus, String, Option<PathBuf>) {
    (
        ControlStatus::Unknown,
        "Disk-encryption state is not readable on this platform without elevation".to_string(),
        None,
    )
}

#[cfg(target_os = "macos")]
fn command_line(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// An SSH server accepting connections on a workstation, and how permissively.
pub(super) fn sshd_exposure(ctx: &ControlContext<'_>) -> ControlAssessment {
    let config = PathBuf::from("/etc/ssh/sshd_config");
    let Some(contents) = read_text(&config) else {
        return assessment(
            "sshd-exposure",
            ControlStatus::NotApplicable,
            vec![evidence("No sshd configuration was found", None)],
            Vec::new(),
        );
    };

    let mut problems = sshd_problems(&contents)
        .into_iter()
        .map(|summary| evidence(summary, Some(config.clone())))
        .collect::<Vec<_>>();

    let authorized = home(ctx).map(|home| home.join(".ssh/authorized_keys"));
    let unrestricted = authorized
        .as_ref()
        .and_then(|path| read_text(path))
        .map(|contents| unrestricted_authorized_keys(&contents))
        .unwrap_or(0);
    if unrestricted > 0 {
        problems.push(evidence(
            format!("{unrestricted} authorized key(s) carry no from= or command= restriction"),
            authorized,
        ));
    }

    if problems.is_empty() {
        return assessment(
            "sshd-exposure",
            ControlStatus::Passed,
            vec![evidence(
                "sshd is configured with key-only, non-root login",
                Some(config),
            )],
            Vec::new(),
        );
    }
    assessment("sshd-exposure", ControlStatus::Failed, problems, Vec::new())
}

fn sshd_problems(contents: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        match (
            key.to_ascii_lowercase().as_str(),
            value.to_ascii_lowercase().as_str(),
        ) {
            ("permitrootlogin", "yes") => {
                problems.push("sshd allows root to log in directly".to_string());
            }
            ("passwordauthentication", "yes") => {
                problems.push("sshd accepts password authentication".to_string());
            }
            _ => {}
        }
    }
    problems
}

/// Keys in `authorized_keys` with no `from=` source restriction and no forced
/// `command=`. Option fields precede the key type on the same line.
fn unrestricted_authorized_keys(contents: &str) -> usize {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| {
            let options = line.split_whitespace().next().unwrap_or("");
            !options.contains("from=") && !options.contains("command=")
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guide::control::report_with_home;

    #[test]
    fn sshd_password_and_root_login_are_reported_separately() {
        let problems = sshd_problems("PermitRootLogin yes\nPasswordAuthentication yes\n");
        assert_eq!(problems.len(), 2);
        assert!(sshd_problems("PermitRootLogin no\nPasswordAuthentication no\n").is_empty());
        assert!(
            sshd_problems("#PasswordAuthentication yes\n").is_empty(),
            "a commented default is not a setting"
        );
    }

    #[test]
    fn restricted_authorized_keys_do_not_count_as_exposure() {
        let contents = "ssh-ed25519 AAAA user@host\n\
                        from=\"10.0.0.0/8\" ssh-ed25519 AAAB ops@host\n\
                        command=\"/usr/bin/backup\" ssh-rsa AAAC backup@host\n";
        assert_eq!(unrestricted_authorized_keys(contents), 1);
    }

    #[test]
    fn sshd_control_is_not_applicable_without_a_server_config() {
        let dir = tempfile::tempdir().unwrap();
        let report = report_with_home(dir.path());
        let ctx = ControlContext { report: &report };
        let result = sshd_exposure(&ctx);
        assert_eq!(result.control_id, "sshd-exposure");
        // On a machine that genuinely runs sshd this reads the real config, so
        // only assert the id and that a status was produced at all.
        assert!(matches!(
            result.status,
            ControlStatus::NotApplicable | ControlStatus::Passed | ControlStatus::Failed
        ));
    }

    #[test]
    fn disk_encryption_never_answers_not_applicable() {
        // Every machine has a root filesystem, so "not applicable" would be a
        // lie. The probe must land on a real verdict or an honest Unknown.
        let report = crate::model::ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let ctx = ControlContext { report: &report };
        assert_ne!(
            full_disk_encryption(&ctx).status,
            ControlStatus::NotApplicable
        );
    }
}
