//! Golden-corpus snapshot: package discovery over the entire `tst/` fixture
//! corpus, locked byte-for-byte.
//!
//! Every registered [`ScanTarget`] runs against the committed fixtures; the
//! discovered `(ecosystem, name, version, manifest)` quadruples are snapshotted
//! sorted into `tests/golden/targets-corpus.txt`. Any parser change that alters
//! any coordinate from any fixture shows up as a diff against that file;
//! refactors must keep it byte-identical, and deliberate parser bug-fixes must
//! update it in the same commit (explained in the commit message).
//!
//! Regenerate after a deliberate change with:
//!
//! ```sh
//! HUSK_UPDATE_GOLDEN=1 cargo test --test golden_corpus
//! ```

use husk::scan::discover_packages;
use std::fmt::Write as _;

mod common;
use common::fixture_root;

#[test]
fn corpus_snapshot_is_stable() {
    let root = fixture_root();
    let packages =
        discover_packages(std::slice::from_ref(&root)).expect("discover packages over tst/");

    let mut lines: Vec<String> = packages
        .iter()
        .map(|p| {
            // Paths relative to tst/ with forward slashes, so the snapshot is
            // identical across machines and operating systems.
            let manifest = p
                .manifest_path
                .strip_prefix(&root)
                .unwrap_or(&p.manifest_path)
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            format!("{}\t{}\t{}\t{}", p.ecosystem, p.name, p.version, manifest)
        })
        .collect();
    lines.sort();
    lines.dedup();

    let mut snapshot = String::with_capacity(lines.len() * 64);
    for line in &lines {
        writeln!(snapshot, "{line}").expect("write snapshot line");
    }

    let golden_path = common::crate_root().join("tests/golden/targets-corpus.txt");

    if std::env::var_os("HUSK_UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(golden_path.parent().expect("golden dir"))
            .expect("create tests/golden");
        std::fs::write(&golden_path, &snapshot).expect("write golden snapshot");
        return;
    }

    let expected = std::fs::read_to_string(&golden_path)
        .expect("read tests/golden/targets-corpus.txt (regenerate with HUSK_UPDATE_GOLDEN=1)");
    if expected != snapshot {
        // A readable diff beats a 2,000-line assert_eq dump.
        let expected_set: std::collections::BTreeSet<&str> = expected.lines().collect();
        let actual_set: std::collections::BTreeSet<&str> = snapshot.lines().collect();
        let missing: Vec<&&str> = expected_set.difference(&actual_set).collect();
        let added: Vec<&&str> = actual_set.difference(&expected_set).collect();
        panic!(
            "golden corpus drifted: {} coordinates missing, {} added\n\
             -- missing (in golden, not discovered) --\n{}\n\
             -- added (discovered, not in golden) --\n{}\n\
             If this change is deliberate, regenerate with HUSK_UPDATE_GOLDEN=1 \
             and explain the delta in the commit message.",
            missing.len(),
            added.len(),
            missing.iter().map(|s| **s).collect::<Vec<_>>().join("\n"),
            added.iter().map(|s| **s).collect::<Vec<_>>().join("\n"),
        );
    }
}
