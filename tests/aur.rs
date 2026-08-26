//! AUR / Arch coverage: the PKGBUILD scanner must flag the unsafe `tst/PKGBUILD`
//! fixture. PKGBUILDs run arbitrary shell during `makepkg`, so installing an AUR
//! package is code execution, the developer-machine surface CI/CD tools miss.

use husk::model::ScanOptions;
use husk::scan::run_scan;

mod common;
use common::fixture_root;

#[tokio::test]
async fn pkgbuild_scanner_flags_unsafe_aur_package() {
    common::isolate();

    let mut options = ScanOptions::new(vec![fixture_root()]);
    options.online = false;
    options.include_home_inventory = false;

    let report = run_scan(options).await.expect("scan fixture");

    let pkgbuild_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.source == "Husk PKGBUILD scanner")
        .collect();

    // The fixture trips: curl|bash (download-and-run), ~/.ssh + ~/.aws +
    // base64 (credential exfil), plaintext-HTTP + pastebin source=.
    assert!(
        pkgbuild_findings.len() >= 2,
        "expected multiple PKGBUILD findings, got {}: {:?}",
        pkgbuild_findings.len(),
        pkgbuild_findings
            .iter()
            .map(|f| &f.title)
            .collect::<Vec<_>>()
    );
    assert!(
        pkgbuild_findings
            .iter()
            .any(|f| f.title == "Risky PKGBUILD build step"),
        "expected a risky-build-step finding"
    );
    assert!(
        pkgbuild_findings
            .iter()
            .any(|f| f.title == "PKGBUILD fetches from an untrusted source"),
        "expected an untrusted-source finding"
    );
    assert!(
        pkgbuild_findings
            .iter()
            .all(|f| f.category == husk::rule::Category::LifecycleScript
                && f.path.as_ref().is_some_and(|p| p.ends_with("PKGBUILD")))
    );
}
