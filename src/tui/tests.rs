//! TestBackend renders of every tab against a fixed report fixture: the TUI's
//! screenshot tests. Each test renders through the real `prepare` → `draw`
//! path into an in-memory buffer and asserts on the visible text, so a layout
//! or content regression fails red instead of waiting for a human eyeball.
//! (No network, no filesystem: the Guide assessment runs against a default
//! user state, never the developer's real store.)

use super::*;
use crate::model::{
    ExploitInfo, Finding, PackageRef, ProviderStatus, ScanStats, Severity, SystemContext,
};
use chrono::TimeZone;
use ratatui::backend::TestBackend;
use std::path::PathBuf;

/// A small, fully deterministic report: one critical vulnerability (with
/// package, exploit intel, and a reference), one high secret finding, one
/// one provider.
fn fixture_report() -> ScanReport {
    let mut report = ScanReport::empty(vec![PathBuf::from("/home/dev/proj")]);
    report.generated_at = chrono::Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
    report.context = SystemContext {
        user: Some("dev".to_string()),
        home_dir: None,
        current_dir: None,
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        distro: Some("Debian GNU/Linux 12".to_string()),
        kernel: Some("6.1.0-18-amd64".to_string()),
        git_name: Some("Ada Dev".to_string()),
        git_email: Some("ada@example.com".to_string()),
        package_managers: vec!["npm".to_string(), "cargo".to_string()],
        dev_configs: vec![],
        scan_roots: vec![],
    };
    let mut vuln = Finding::new(
        "osv:lodash",
        "Vulnerable dependency lodash 4.17.20",
        Severity::Critical,
        crate::rule::Category::Vulnerability,
        "osv.dev",
        Some(PathBuf::from("/home/dev/proj/package-lock.json")),
        None,
        "Prototype pollution allows remote code execution.",
        None,
        "Upgrade lodash to a patched release.",
    );
    vuln.package = Some(PackageRef {
        ecosystem: "npm".to_string(),
        name: "lodash".to_string(),
        version: "4.17.20".to_string(),
        manifest_path: PathBuf::from("/home/dev/proj/package-lock.json"),
        line: None,
    });
    // A safe target version so `dependency_fix` produces a plan and the
    // Scan detail's `fix`/`install`/`status` lines are actually exercised.
    vuln.fixed_version = Some("4.17.21".to_string());
    vuln.exploit = Some(ExploitInfo {
        kev: true,
        epss: Some(0.97),
    });
    vuln.references = vec!["https://osv.dev/GHSA-example".to_string()];
    let secret = Finding::new(
        "secret:env",
        "Plaintext credential in .env",
        Severity::High,
        crate::rule::Category::Secret,
        "husk",
        Some(PathBuf::from("/home/dev/proj/.env")),
        Some(3),
        "A live-looking credential sits unencrypted on disk.",
        Some("AWS_SECRET_ACCESS_KEY=****".to_string()),
        "Move the secret into a manager and rotate it.",
    );
    report.findings = vec![vuln, secret];
    report.stats = ScanStats::from_findings(12, &report.findings);
    report.providers = vec![ProviderStatus {
        name: "osv.dev".to_string(),
        ok: true,
        checked_packages: 12,
        findings: 1,
        message: String::new(),
    }];
    // Scan finalization is what attaches proposals; the TUI renders what the
    // report carries rather than re-planning its own.
    report.remediations = crate::guide::control::run(&report).1;
    report
}

/// Render one tab through the real `prepare` → `draw` path and return the
/// buffer as plain text (rows joined by `\n`).
fn render(tab: Tab, width: u16, height: u16) -> String {
    render_with(tab, width, height, |_| {})
}

/// [`render`] with a hook that drives the app (selection, keys) after the first
/// `prepare` and before the draw.
fn render_with(tab: Tab, width: u16, height: u16, drive: impl FnOnce(&mut TuiApp)) -> String {
    let mut app = TuiApp::new(LiveScan::finished(fixture_report()));
    app.tab = tab;
    let area = Rect::new(0, 0, width, height);
    let body = shell_rows(area)[2];
    // Assess the Guide against a fixed (empty) user state; the cache then stays
    // fresh, so the `prepare` below never reads the developer's real store.
    app.guide
        .prepare_with(&app.live.report, body, crate::guide::UserState::default);
    app.prepare(area);
    drive(&mut app);
    app.guide
        .prepare_with(&app.live.report, body, crate::guide::UserState::default);
    app.prepare(area);
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| draw(frame, &app, Some("http://127.0.0.1:44333")))
        .unwrap();
    let buffer = terminal.backend().buffer().clone();
    let mut out = String::new();
    for y in buffer.area.top()..buffer.area.bottom() {
        for x in buffer.area.left()..buffer.area.right() {
            out.push_str(buffer[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

fn assert_contains(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            haystack.contains(needle),
            "expected {needle:?} in rendered buffer:\n{haystack}"
        );
    }
}

#[test]
fn shell_renders_brand_tabbar_and_footer_on_every_tab() {
    for tab in Tab::ALL {
        let text = render(tab, 140, 36);
        assert_contains(
            &text,
            &[
                "husk",
                "developer security scanner",
                "Guide",
                "Scan",
                "Account",
                "1-3/Tab switch",
                "q quit",
                "web: http://127.0.0.1:44333",
                "providers: osv.dev",
            ],
        );
    }
}

#[test]
fn header_stale_badge_gates_on_age_and_running() {
    // The fixture report is dated 2026-01-02, far past the freshness window,
    // so the rendered header carries the badge...
    let text = render(Tab::Scan, 160, 36);
    assert_contains(&text, &["⚠ last scan:", "Run `husk scan` to refresh"]);

    // ...but never while a scan is rebuilding the report, and never for a
    // fresh one.
    let mut app = TuiApp::new(LiveScan::finished(fixture_report()));
    assert!(stale_badge(&app).is_some(), "old report gets a badge");
    app.live.running = true;
    assert!(stale_badge(&app).is_none(), "no badge mid-scan");

    let mut fresh = fixture_report();
    fresh.generated_at = chrono::Utc::now();
    let app = TuiApp::new(LiveScan::finished(fresh));
    assert!(stale_badge(&app).is_none(), "fresh report gets no badge");
}

#[test]
fn scan_tab_renders_findings_table_context_and_detail() {
    let text = render(Tab::Scan, 160, 48);
    assert_contains(
        &text,
        &[
            // Progress panel.
            "Progress",
            "scanned",
            "12 packages",
            "complete",
            // System context panel.
            "System Context",
            "Welcome, Ada Dev",
            "Debian GNU/Linux 12",
            "npm, cargo",
            // Findings list: column header and both rows. Guidance has its own tab.
            "Open issues 2 · C1 H1",
            "severity",
            "project",
            "location",
            "critical",
            "high",
            "lodash",
            ".env",
            // Detail panel for the selected (first) finding.
            "Details",
            "Why this matters",
            "What to do",
            "References",
            // Typed dependency remediation is still available inline.
            "Upgrade lodash to 4.17.21",
            // Scan footer affordance.
            "u fix dep",
        ],
    );
}

#[test]
fn guide_tab_renders_checklist_and_detail() {
    let text = render(Tab::Guide, 140, 36);
    assert_contains(
        &text,
        &[
            "Security checklist",
            "To do",
            "Handled",
            "Ignored",
            "All",
            "group: Priority",
            "Tasks ·",
            "to do",
            "How to",
            "STEPS",
            "f filter · g group",
        ],
    );
}

/// The Guide's fix pane, the terminal half of the web's "Fix with Husk" card:
/// grouped rows with their selection state, and, for a row Husk cannot run, the
/// typed blocker's own words rather than prose the TUI invented.
#[test]
fn guide_fix_pane_renders_rows_selection_and_blocked_reasons() {
    /// Walk to the first task with fixes, then open the pane.
    fn open_fix(app: &mut TuiApp, body: Rect) {
        for _ in 0..200 {
            app.guide
                .prepare_with(&app.live.report, body, crate::guide::UserState::default);
            if app.guide.fix.summary().is_some() {
                break;
            }
            app.guide.select_next();
        }
        app.guide.fix.open();
    }

    let body = shell_rows(Rect::new(0, 0, 140, 40))[2];
    let text = render_with(Tab::Guide, 140, 40, |app| open_fix(app, body));

    // The pane is a fixed grid, so a long path or a long blocker degrades by
    // truncation rather than by pushing the layout around.
    for (width, height) in [(60, 18), (40, 12)] {
        let body = shell_rows(Rect::new(0, 0, width, height))[2];
        let narrow = render_with(Tab::Guide, width, height, |app| open_fix(app, body));
        assert_eq!(narrow.lines().count(), height as usize);
        for line in narrow.lines() {
            assert_eq!(line.chars().count(), width as usize);
        }
    }

    assert_contains(
        &text,
        &[
            "Fix with husk",
            "selected",
            "Fixes",
            "What it changes",
            // The dependency fix the fixture plans, and why one key cannot take
            // it: the fixture's manifest is not on disk.
            "Upgrade lodash to 4.17.21",
            "there is no package.json to hold the change",
            "space select",
            "enter apply",
        ],
    );
}

#[test]
fn account_tab_renders_connection_and_machine_cards() {
    let text = render(Tab::Account, 120, 36);
    assert_contains(
        &text,
        &[
            "Cloud connection",
            "Account sign-in: coming soon",
            "Report an issue",
            "https://github.com/husk-security/husk/issues/new",
            "This machine",
            "Ada Dev",
            "Debian GNU/Linux 12",
            "6.1.0-18-amd64 · x86_64",
        ],
    );
}

/// Every tab must render without panicking at small sizes too (the shell and
/// panels degrade by truncation, never by overflow).
#[test]
fn all_tabs_render_at_narrow_sizes() {
    for (width, height) in [(60, 18), (40, 12)] {
        for tab in Tab::ALL {
            let text = render(tab, width, height);
            assert_eq!(text.lines().count(), height as usize);
        }
    }

    let account = render(Tab::Account, 60, 18);
    assert_contains(&account, &["Report an issue"]);
}

/// The keyboard model: number keys and Tab/BackTab cycle; j/k clamp to the
/// findings list on the Scan tab.
#[test]
fn tab_switching_and_selection_keys() {
    use crossterm::event::{KeyEvent, KeyEventKind, KeyEventState};

    let key = |code: KeyCode| {
        Event::Key(KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        })
    };
    let mut app = TuiApp::new(LiveScan::finished(fixture_report()));
    assert!(matches!(app.tab, Tab::Scan), "Scan is the default tab");

    handle_event(&mut app, key(KeyCode::Char('1')));
    assert!(matches!(app.tab, Tab::Guide));
    handle_event(&mut app, key(KeyCode::Tab));
    assert!(matches!(app.tab, Tab::Scan));
    handle_event(&mut app, key(KeyCode::BackTab));
    assert!(matches!(app.tab, Tab::Guide));
    handle_event(&mut app, key(KeyCode::Char('3')));
    assert!(matches!(app.tab, Tab::Account));
    handle_event(&mut app, key(KeyCode::Char('4')));
    assert!(matches!(app.tab, Tab::Account), "`4` is a no-op");

    // j/k on the Scan tab move the selection, clamped to the two findings.
    app.tab = Tab::Scan;
    handle_event(&mut app, key(KeyCode::Char('j')));
    handle_event(&mut app, key(KeyCode::Char('j')));
    handle_event(&mut app, key(KeyCode::Char('j')));
    let second = app.scan.selected_finding(&app.live.report).unwrap();
    assert_eq!(second.id, "secret:env", "selection clamps at the last row");
    handle_event(&mut app, key(KeyCode::Char('k')));
    let first = app.scan.selected_finding(&app.live.report).unwrap();
    assert_eq!(first.id, "osv:lodash");

    // q asks to quit.
    assert!(handle_event(&mut app, key(KeyCode::Char('q'))));
}

/// Windows terminals deliver Press AND Release for every keystroke; only
/// Press may act, or every key double-fires (j moves two rows, Tab skips a
/// tab) and a Release `q` would quit the app.
#[test]
fn non_press_key_events_are_ignored() {
    use crossterm::event::{KeyEvent, KeyEventKind, KeyEventState};

    let key = |code: KeyCode, kind: KeyEventKind| {
        Event::Key(KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind,
            state: KeyEventState::NONE,
        })
    };
    let mut app = TuiApp::new(LiveScan::finished(fixture_report()));
    assert!(matches!(app.tab, Tab::Scan));

    for kind in [KeyEventKind::Release, KeyEventKind::Repeat] {
        assert!(
            !handle_event(&mut app, key(KeyCode::Char('q'), kind)),
            "{kind:?} q must not quit"
        );
        handle_event(&mut app, key(KeyCode::Tab, kind));
        assert!(matches!(app.tab, Tab::Scan), "{kind:?} Tab must not switch");
        handle_event(&mut app, key(KeyCode::Char('j'), kind));
    }
    let first = app.scan.selected_finding(&app.live.report).unwrap();
    assert_eq!(
        first.id, "osv:lodash",
        "non-Press j must not move selection"
    );

    // The matching Press still works.
    handle_event(&mut app, key(KeyCode::Tab, KeyEventKind::Press));
    assert!(matches!(app.tab, Tab::Account));
}

#[test]
fn tab_from_index_wraps_and_roundtrips() {
    for (i, tab) in Tab::ALL.into_iter().enumerate() {
        assert_eq!(Tab::from_index(i).index(), tab.index());
        assert_eq!(tab.next().prev().index(), tab.index());
    }
    // Out-of-range wraps instead of silently defaulting.
    assert_eq!(Tab::from_index(Tab::ALL.len()).index(), 0);
}

#[test]
fn report_key_tracks_staleness() {
    let report = fixture_report();
    let mut changed = fixture_report();
    assert!(report_key(&report) == report_key(&changed));
    changed.findings.pop();
    assert!(report_key(&report) != report_key(&changed));
}

#[test]
fn compact_list_caps_with_overflow_marker() {
    let values: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
    assert_eq!(compact_list(&[], 3), "none detected");
    assert_eq!(compact_list(&values, 3), "a, b, c");
    assert_eq!(compact_list(&values, 2), "a, b +1");
}

#[test]
fn progress_bar_is_always_width_plus_brackets() {
    for percent in [0, 37, 50, 100, 250] {
        let bar = progress_bar(percent, 10);
        assert_eq!(bar.chars().count(), 12, "bar {bar:?} at {percent}%");
    }
    assert_eq!(progress_bar(0, 4), "[░░░░]");
    assert_eq!(progress_bar(50, 4), "[██░░]");
    assert_eq!(progress_bar(100, 4), "[████]");
}

/// The consent pane renders over the body with the shared copy and both
/// explicit choices, whatever tab is underneath.
#[test]
fn consent_pane_renders_question_and_choices_over_the_body() {
    let text = render_with(Tab::Scan, 100, 30, |app| {
        app.consent = Some(consent::Pane::default());
    });
    assert_contains(
        &text,
        &[
            "Share anonymous usage data with Husk?",
            "[ No ]",
            "[ Yes ]",
            "husk telemetry off",
        ],
    );
    // The footer teaches the pane's keys while it is open.
    assert_contains(&text, &["y yes", "n no"]);
}

/// Opening the pane persists the asked state immediately: an unanswered pane
/// (quit mid-pane) is a recorded decline, never a future re-prompt.
#[test]
fn opening_the_consent_pane_records_a_decline_before_any_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let telemetry = crate::cloud::telemetry::Telemetry::at(dir.path());
    assert_eq!(telemetry.consent(), crate::cloud::TelemetryConsent::Unset);
    let _pane = consent::Pane::open(&telemetry);
    assert_eq!(
        telemetry.consent(),
        crate::cloud::TelemetryConsent::Disabled,
        "rendering the ask must already count as asked-and-declined"
    );
}

/// Key semantics: `y` accepts; `n`/Esc decline; Enter takes the focused
/// choice, which starts on No; arrows move focus.
#[test]
fn consent_pane_keys_answer_and_move_focus() {
    use super::consent::{Outcome, Pane};
    let answered = |mut pane: Pane, code| matches!(pane.handle_key(code), Outcome::Answered(true));
    let declined = |mut pane: Pane, code| matches!(pane.handle_key(code), Outcome::Answered(false));

    assert!(answered(Pane::default(), KeyCode::Char('y')));
    assert!(declined(Pane::default(), KeyCode::Char('n')));
    assert!(declined(Pane::default(), KeyCode::Esc));
    assert!(
        declined(Pane::default(), KeyCode::Enter),
        "default focus is No, so a bare Enter declines"
    );

    let mut pane = Pane::default();
    assert!(matches!(pane.handle_key(KeyCode::Right), Outcome::Open));
    assert!(
        matches!(pane.handle_key(KeyCode::Enter), Outcome::Answered(true)),
        "Enter after moving focus takes Yes"
    );
}

/// Answering through the app records the decision and closes the pane; the
/// pane consumes the key so nothing underneath acts on it.
#[test]
fn answering_yes_through_the_app_enables_telemetry_and_closes_the_pane() {
    let dir = tempfile::tempdir().expect("tempdir");
    let telemetry = crate::cloud::telemetry::Telemetry::at(dir.path());
    let mut app = TuiApp::new(LiveScan::finished(fixture_report()));
    app.telemetry = Some(telemetry.clone());
    app.consent = Some(consent::Pane::open(&telemetry));

    assert!(app.consume_consent_key(KeyCode::Char('y')));
    assert!(app.consent.is_none(), "an answer closes the pane");
    assert_eq!(telemetry.consent(), crate::cloud::TelemetryConsent::Enabled);

    // With the pane closed the handler no longer consumes keys.
    assert!(!app.consume_consent_key(KeyCode::Char('y')));
}

/// The trigger predicate: only the running-to-finished transition of a clean
/// scan opens the ask.
#[test]
fn consent_trigger_is_the_clean_scan_completion_transition() {
    let finished = LiveScan::finished(fixture_report());
    assert!(consent::scan_just_completed(true, &finished));
    assert!(
        !consent::scan_just_completed(false, &finished),
        "an already-finished report (cached open) is not the trigger"
    );
    let mut failed = LiveScan::finished(fixture_report());
    failed.error = Some("scan failed".to_string());
    assert!(
        !consent::scan_just_completed(true, &failed),
        "a failed scan never asks"
    );
    let mut running = LiveScan::finished(fixture_report());
    running.running = true;
    assert!(!consent::scan_just_completed(true, &running));
}
