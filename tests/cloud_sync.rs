//! Offline tests for the cloud inventory sync + alerts client
//! (`src/cloud/sync.rs`): payload shaping, response parsing, machine-id
//! discovery ordering, and the machine-id cache. No test touches the
//! network; live behavior is covered by the platform integration run
//! against a local backend.

use chrono::{TimeZone, Utc};
use husk::cloud::sync::{
    AlertStateFilter, MAX_SYNC_PACKAGES, MachineInfo, build_inventory_payload,
    candidate_machine_ids, parse_alerts_response, read_cached_machine_id, write_cached_machine_id,
};
use husk::model::{PackageRef, Severity};
use std::path::PathBuf;

fn package(ecosystem: &str, name: &str, version: &str) -> PackageRef {
    package_at(ecosystem, name, version, "/home/dev/project/package.json")
}

fn package_at(ecosystem: &str, name: &str, version: &str, manifest: &str) -> PackageRef {
    PackageRef {
        ecosystem: ecosystem.to_string(),
        name: name.to_string(),
        version: version.to_string(),
        manifest_path: PathBuf::from(manifest),
        line: None,
    }
}

fn machine(id: &str, created_at_hour: Option<u32>) -> MachineInfo {
    MachineInfo {
        id: id.to_string(),
        created_at: created_at_hour
            .map(|hour| Utc.with_ymd_and_hms(2026, 6, 13, hour, 0, 0).unwrap()),
    }
}

#[test]
fn payload_dedupes_normalizes_and_sorts() {
    let packages = vec![
        // Same coordinates from two manifests collapse to one row.
        package_at("npm", "left-pad", "1.3.0", "/home/dev/a/package.json"),
        package_at("npm", "left-pad", "1.3.0", "/home/dev/b/package.json"),
        // Whitespace is trimmed and ecosystems are lowercased.
        package(" NPM ", " left-pad ", " 1.3.0 "),
        package("pypi", "requests", "2.31.0"),
        package("cargo", "serde", "1.0.203"),
        // Same name, different version: two distinct rows.
        package("npm", "left-pad", "1.2.0"),
    ];

    let payload = build_inventory_payload(&packages);
    let rows: Vec<(String, String, String)> = payload
        .into_iter()
        .map(|p| (p.ecosystem, p.name, p.version))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("cargo".into(), "serde".into(), "1.0.203".into()),
            ("npm".into(), "left-pad".into(), "1.2.0".into()),
            ("npm".into(), "left-pad".into(), "1.3.0".into()),
            ("pypi".into(), "requests".into(), "2.31.0".into()),
        ]
    );
}

#[test]
fn payload_drops_entries_the_backend_would_reject() {
    let packages = vec![
        package("npm", "ok-package", "1.0.0"),
        // Empty after trim.
        package("npm", "no-version", "   "),
        package("", "no-ecosystem", "1.0.0"),
        // Control characters.
        package("npm", "bad\tname", "1.0.0"),
        // Oversized name (backend limit is 512 chars).
        package("npm", &"x".repeat(513), "1.0.0"),
        // Oversized version (backend limit is 128 chars).
        package("npm", "long-version", &"9".repeat(129)),
    ];

    let payload = build_inventory_payload(&packages);
    assert_eq!(payload.len(), 1);
    assert_eq!(payload[0].name, "ok-package");
}

#[test]
fn payload_caps_at_backend_limit() {
    let packages: Vec<PackageRef> = (0..MAX_SYNC_PACKAGES + 10)
        .map(|n| package("npm", "generated", &format!("1.0.{n}")))
        .collect();
    let payload = build_inventory_payload(&packages);
    assert_eq!(payload.len(), MAX_SYNC_PACKAGES);
}

/// Mirrors the backend's `GET /api/v1/alerts` JSON, including fractional
/// timestamps, a `references` jsonb array, and one alert with `null`
/// references (a NULL jsonb column) plus an unknown field a newer backend
/// might add.
const ALERTS_FIXTURE: &str = r#"{
  "alerts": [
    {
      "id": "6f9619ff-8b86-d011-b42d-00c04fc964ff",
      "machine_id": "0b51cb2f-9f72-4b1a-9e36-1f6e9c6f1a01",
      "machine_name": "dev-laptop",
      "intel_entry_id": "7c4a8d09-ca37-42d8-9c2f-aa5be6b3c001",
      "ecosystem": "npm",
      "name": "left-pad",
      "version": "1.3.0",
      "state": "open",
      "severity": "critical",
      "verdict": "malware",
      "summary": "Compromised release exfiltrates npm tokens.",
      "references": ["https://example.com/advisory"],
      "first_seen_at": "2026-06-12T08:30:00.123456Z",
      "updated_at": "2026-06-12T09:00:00Z"
    },
    {
      "id": "9bd87d1a-5566-4cbb-a571-3c2f1e2b4d02",
      "machine_id": "0b51cb2f-9f72-4b1a-9e36-1f6e9c6f1a01",
      "machine_name": "dev-laptop",
      "intel_entry_id": "1f1e9c6f-aa5b-4e6b-8c2f-7c4a8d09c002",
      "ecosystem": "pypi",
      "name": "requets",
      "version": "0.0.1",
      "state": "acked",
      "severity": "high",
      "verdict": "typosquat",
      "summary": "Typosquat of requests.",
      "references": null,
      "first_seen_at": "2026-06-11T22:00:00Z",
      "updated_at": "2026-06-12T07:15:00Z",
      "remediation_hint": "added by a future backend"
    }
  ]
}"#;

#[test]
fn alerts_parse_from_backend_fixture() {
    let alerts = parse_alerts_response(ALERTS_FIXTURE).expect("fixture parses");
    assert_eq!(alerts.len(), 2);

    let first = &alerts[0];
    assert_eq!(first.id, "6f9619ff-8b86-d011-b42d-00c04fc964ff");
    assert_eq!(first.machine_name, "dev-laptop");
    assert_eq!(first.ecosystem, "npm");
    assert_eq!(first.name, "left-pad");
    assert_eq!(first.version, "1.3.0");
    assert_eq!(first.state, "open");
    assert_eq!(first.verdict, "malware");
    assert_eq!(first.severity_level(), Severity::Critical);
    assert_eq!(first.references, vec!["https://example.com/advisory"]);
    assert_eq!(
        first.first_seen_at,
        Utc.with_ymd_and_hms(2026, 6, 12, 8, 30, 0).unwrap()
            + chrono::Duration::microseconds(123_456)
    );

    let second = &alerts[1];
    assert_eq!(second.state, "acked");
    assert_eq!(second.severity_level(), Severity::High);
    // Null references and unknown extra fields are tolerated.
    assert!(second.references.is_empty());
}

#[test]
fn alerts_parse_rejects_non_alert_json() {
    assert!(parse_alerts_response("not json").is_err());
    assert!(parse_alerts_response(r#"{"alerts": [{"id": "missing-fields"}]}"#).is_err());
}

#[test]
fn candidate_order_is_cache_then_newest_machine() {
    let machines = vec![
        machine("aaaaaaaa-0000-0000-0000-000000000001", Some(8)),
        machine("bbbbbbbb-0000-0000-0000-000000000002", Some(12)),
        machine("cccccccc-0000-0000-0000-000000000003", None),
    ];
    let ordered = candidate_machine_ids(Some("eeeeeeee-0000-0000-0000-000000000005"), &machines);
    assert_eq!(
        ordered,
        vec![
            // The locally cached id first.
            "eeeeeeee-0000-0000-0000-000000000005",
            // Then machines newest-created first; unknown created_at last.
            "bbbbbbbb-0000-0000-0000-000000000002",
            "aaaaaaaa-0000-0000-0000-000000000001",
            "cccccccc-0000-0000-0000-000000000003",
        ]
    );
}

#[test]
fn candidate_order_dedupes_and_drops_unsafe_ids() {
    let machines = vec![
        machine("aaaaaaaa-0000-0000-0000-000000000001", Some(9)),
        machine("../../../etc/passwd", Some(10)),
    ];
    // The cached id duplicates a listed machine and must not repeat; the
    // traversal-shaped machine id is dropped outright.
    let ordered = candidate_machine_ids(Some("aaaaaaaa-0000-0000-0000-000000000001"), &machines);
    assert_eq!(ordered, vec!["aaaaaaaa-0000-0000-0000-000000000001"]);
}

#[test]
fn machine_id_cache_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let husk_home = dir.path().join(".husk");

    // Nothing cached yet, even before the directory exists.
    assert_eq!(read_cached_machine_id(&husk_home), None);

    let first = "0b51cb2f-9f72-4b1a-9e36-1f6e9c6f1a01";
    write_cached_machine_id(&husk_home, first).expect("write cache");
    assert_eq!(read_cached_machine_id(&husk_home).as_deref(), Some(first));

    // Overwrites replace the previous id.
    let second = "9bd87d1a-5566-4cbb-a571-3c2f1e2b4d02";
    write_cached_machine_id(&husk_home, second).expect("rewrite cache");
    assert_eq!(read_cached_machine_id(&husk_home).as_deref(), Some(second));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&husk_home)
            .expect("husk home metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "~/.husk must be created 0700");
    }
}

#[test]
fn machine_id_cache_rejects_garbage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let husk_home = dir.path().to_path_buf();

    // Not JSON at all.
    std::fs::write(husk_home.join("machine.json"), "definitely not json").expect("write");
    assert_eq!(read_cached_machine_id(&husk_home), None);

    // Valid JSON, but an id that must never reach a request path.
    std::fs::write(
        husk_home.join("machine.json"),
        r#"{"machine_id": "../../../etc/passwd"}"#,
    )
    .expect("write");
    assert_eq!(read_cached_machine_id(&husk_home), None);

    // Writing an implausible id is refused outright.
    assert!(write_cached_machine_id(&husk_home, "not a uuid!").is_err());
}

#[test]
fn alert_state_filter_maps_to_wire_values() {
    for (filter, wire) in [
        (AlertStateFilter::Open, "open"),
        (AlertStateFilter::All, "all"),
    ] {
        assert_eq!(filter.as_str(), wire);
        assert_eq!(filter.to_string(), wire);
    }
    assert_eq!(AlertStateFilter::default(), AlertStateFilter::Open);
}
