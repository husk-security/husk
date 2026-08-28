//! The Ratatui terminal UI: a tabbed app (Guide / Scan / Account)
//! mirroring the web UI's structure, driven by the same shared
//! [`LiveScan`] state, so progress and results are
//! identical across both surfaces. One deliberate asymmetry: the web-only
//! "AI agent setup" tab is an onboarding helper that wraps `husk mcp install`;
//! in a terminal that CLI command *is* the flow, so it has no TUI tab.

use crate::model::{LiveScan, LiveScanLock, ScanReport, SharedLiveScan};
use crate::term::truncate_middle;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};
use std::io::{self, Stdout};
use std::time::{Duration, Instant};

mod account;
mod consent;
mod fix;
mod guide;
mod scan;
mod source;
#[cfg(test)]
mod tests;
mod theme;

/// The top-level views: the terminal mirror of the web app's tab bar
/// (`web/src/App.tsx`), minus the web-only "AI agent setup" onboarding tab
/// (its terminal equivalent is the `husk mcp install` command itself).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
enum Tab {
    Guide,
    Scan,
    Account,
}

impl Tab {
    const ALL: [Tab; 3] = [Tab::Guide, Tab::Scan, Tab::Account];

    fn label(self) -> &'static str {
        match self {
            Tab::Guide => "Guide",
            Tab::Scan => "Scan",
            Tab::Account => "Account",
        }
    }

    fn index(self) -> usize {
        self as usize
    }

    fn from_index(i: usize) -> Tab {
        Tab::ALL[i % Tab::ALL.len()]
    }

    fn next(self) -> Tab {
        Tab::from_index(self.index() + 1)
    }

    fn prev(self) -> Tab {
        Tab::from_index(self.index() + Tab::ALL.len() - 1)
    }
}

pub fn run(report: ScanReport) -> Result<()> {
    run_live(
        std::sync::Arc::new(std::sync::RwLock::new(LiveScan::finished(report))),
        None,
    )
}

/// Restores the terminal (raw mode + alternate screen + cursor) on drop, so
/// cleanup runs even if `run_app` panics and unwinds. The TUI exit rule
/// requires that `q` and Ctrl-C restore the terminal immediately; a panic
/// must restore it too.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
    }
}

pub fn run_live(live: SharedLiveScan, web_url: Option<String>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_app(&mut terminal, live, web_url);
    drop(terminal);
    result
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    live: SharedLiveScan,
    web_url: Option<String>,
) -> Result<()> {
    let mut app = TuiApp::new(live.snapshot());
    let mut last_live_refresh = Instant::now();
    let mut needs_draw = true;
    loop {
        if app.live.running && last_live_refresh.elapsed() >= Duration::from_millis(160) {
            app.update_live(live.snapshot());
            last_live_refresh = Instant::now();
            needs_draw = true;
        }

        if app.scan.poll_dep_fix() || app.guide.fix.poll() {
            needs_draw = true;
        }

        if needs_draw {
            // Explicit update-then-render: `prepare` refreshes the active tab's
            // view-model (cached rows, selection clamping) so the draw pass can
            // take the app immutably.
            let size = terminal.size()?;
            app.prepare(Rect::new(0, 0, size.width, size.height));
            terminal.draw(|frame| draw(frame, &app, web_url.as_deref()))?;
            needs_draw = false;
        }

        // Wait one frame for input, then drain everything already queued (a
        // paste or held-down key) so a burst coalesces into a single redraw.
        // When nothing can change without input (scan complete, no dep fix in
        // flight), stretch the wait so an idle session stops burning wakeups.
        let timeout = if app.live.running || app.scan.dep_fix_running() || app.guide.fix.running() {
            Duration::from_millis(16)
        } else {
            Duration::from_millis(250)
        };
        if event::poll(timeout)? {
            loop {
                if handle_event(&mut app, event::read()?) {
                    return Ok(());
                }
                needs_draw = true;
                if !event::poll(Duration::from_millis(0))? {
                    break;
                }
            }
        }
    }
}

/// Apply one terminal event to the app. Returns `true` when the user asked to
/// quit. A resize needs no bookkeeping here: the caller redraws after any
/// event and the immediate-mode `draw` re-lays the UI against the new size.
fn handle_event(app: &mut TuiApp, event: Event) -> bool {
    if let Event::Key(key) = event {
        // Windows terminals deliver Press AND Release events (crossterm 0.29
        // enables the full event stream there); acting on both double-fires
        // every keystroke (j moves two rows, Tab skips a tab).
        if key.kind != KeyEventKind::Press {
            return false;
        }
        // `q` and Ctrl-C restore the terminal whatever is on screen, so they are
        // settled before any pane gets a say.
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            _ => {}
        }
        if app.consume_consent_key(key.code) {
            return false;
        }
        if app.consume_fix_key(key.code) {
            return false;
        }
        if app.source.is_open() {
            // The pane is scrolled with the same j/k the list underneath uses,
            // so it must answer first or the selection would move behind it.
            if app.source.handle_key(key.code) {
                return false;
            }
        }
        match key.code {
            KeyCode::Esc => return true,
            KeyCode::Tab => app.tab = app.tab.next(),
            KeyCode::BackTab => app.tab = app.tab.prev(),
            KeyCode::Char(c @ '1'..='3') => app.tab = Tab::from_index(c as usize - '1' as usize),
            KeyCode::Down | KeyCode::Char('j') => app.select_next(),
            KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
            KeyCode::Left | KeyCode::Char('h') => app.guide_opt_move(-1),
            KeyCode::Right | KeyCode::Char('l') => app.guide_opt_move(1),
            KeyCode::Char('f') => app.guide_cycle_filter(),
            KeyCode::Char('g') => app.guide_cycle_grouping(),
            KeyCode::Char('x') => app.guide_open_fix(),
            KeyCode::Char('o') => app.open_source(),
            KeyCode::Char('u') => app.start_dep_fix(false),
            // Shift-U: the PEP 668 opt-in, mirroring the web "upgrade anyway"
            // button. Deliberately its own key, never a fallback for `u`:
            // writing into a distro-managed Python is the user's call.
            KeyCode::Char('U') => app.start_dep_fix(true),
            KeyCode::Home => app.select_home(),
            KeyCode::End => app.select_end(),
            _ => {}
        }
    }
    false
}

/// The four fixed shell rows: brand header, tab bar, body, footer. Shared by
/// `TuiApp::prepare` (which needs the body rect before rendering) and `draw`.
fn shell_rows(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // brand header
            Constraint::Length(1), // tab bar
            Constraint::Min(0),    // body
            Constraint::Length(1), // footer
        ])
        .split(area)
}

/// One `label: value` line: the muted bold label padded to `label_width`,
/// then the pre-styled value. The shape every field list in the app uses
/// (Scan context/detail panels, the Account tab).
fn field_line(label: &'static str, label_width: usize, value: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<label_width$}"), theme::label()),
        value,
    ])
}

/// A heading inside a detail pane.
fn detail_section(label: &'static str) -> Line<'static> {
    Line::from(Span::styled(
        label,
        theme::muted().add_modifier(Modifier::BOLD),
    ))
}

/// Columns [`detail_field`] spends on its label, so a caller can truncate the
/// value to what is left.
const DETAIL_LABEL_WIDTH: usize = 9;

/// One `label: value` line in a detail pane, at the shared label width.
fn detail_field(label: &'static str, value: String, color: Color) -> Line<'static> {
    field_line(
        label,
        DETAIL_LABEL_WIDTH,
        Span::styled(value, Style::default().fg(color)),
    )
}

fn draw(frame: &mut Frame<'_>, app: &TuiApp, web_url: Option<&str>) {
    let rows = shell_rows(frame.area());
    draw_header(frame, rows[0], app);
    draw_tabbar(frame, rows[1], app.tab);
    match app.tab {
        Tab::Scan => scan::draw(frame, app, rows[2]),
        Tab::Guide => guide::draw(frame, app, rows[2]),
        Tab::Account => account::draw(frame, &app.live.report, rows[2]),
    }
    source::draw(frame, &app.source, rows[2]);
    if let Some(pane) = &app.consent {
        consent::draw(frame, rows[2], pane);
    }
    draw_footer(frame, rows[3], app, web_url);
}

/// Brand row: wordmark + a one-line descriptor, plus a stale-scan badge when
/// the report on display is older than the freshness window (the TUI mirror of
/// the CLI's stderr warning and the web UI's banner).
fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let mut spans = vec![
        Span::styled(" husk", theme::accent()),
        Span::styled("   ·  developer security scanner", theme::muted()),
    ];
    if let Some(notice) = stale_badge(app) {
        spans.push(Span::styled(format!("   ⚠ {notice}"), theme::warn()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// The stale-scan badge text, or `None` while a scan is running (its report is
/// being rebuilt right now) or the report is fresh.
fn stale_badge(app: &TuiApp) -> Option<String> {
    if app.live.running {
        return None;
    }
    crate::cache::stale_notice(app.live.report.generated_at, chrono::Utc::now())
}

/// The tab strip, number-prefixed for keyboard discoverability; the active tab
/// is the one bright-white, underlined item (hue stays reserved for severity).
fn draw_tabbar(frame: &mut Frame<'_>, area: Rect, active: Tab) {
    let mut spans = Vec::new();
    for (i, tab) in Tab::ALL.iter().enumerate() {
        let style = if *tab == active {
            theme::accent().add_modifier(Modifier::UNDERLINED)
        } else {
            theme::muted()
        };
        spans.push(Span::styled(format!("  {} ", i + 1), theme::label()));
        spans.push(Span::styled(tab.label(), style));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Contextual keybinding footer + live provider status.
fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &TuiApp, web_url: Option<&str>) {
    let providers = app
        .live
        .report
        .providers
        .iter()
        .map(|provider| {
            if provider.ok {
                provider.name.clone()
            } else {
                format!("{} warning", provider.name)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let nav = match app.tab {
        _ if app.consent.is_some() => {
            "y yes · n no · left/right choose · enter confirm · esc no · q quit"
        }
        _ if app.source.is_open() => "j/k scroll · PgUp/PgDn page · esc back · q quit",
        Tab::Guide if app.guide.fix.is_open() => {
            "j/k move · space select · a all · enter apply · PgUp/PgDn scroll · esc back · q quit"
        }
        Tab::Guide => {
            "1-3/Tab switch · j/k move · h/l option · f filter · g group · x fix · q quit"
        }
        Tab::Scan => "1-3/Tab switch · j/k move · o open file · u fix dep · q quit",
        Tab::Account => "1-3/Tab switch · j/k move · q quit",
    };
    let footer = format!(
        "{nav}   web: {}   providers: {providers}",
        web_url.unwrap_or("run `husk web`"),
    );
    frame.render_widget(
        Paragraph::new(truncate_middle(
            &footer,
            area.width.saturating_sub(1) as usize,
        ))
        .style(theme::muted()),
        area,
    );
}

/// The top-level app state: the active tab, the live scan snapshot, and one
/// owned view-model per stateful tab. Each tab's `State` carries its own
/// selection/cache and is mutated only in `prepare` / key handlers, keeping
/// the update/render split explicit.
struct TuiApp {
    tab: Tab,
    live: LiveScan,
    /// Scan tab: cached findings table, selection, one-key dep fix.
    scan: scan::State,
    /// Guide tab: cached assessment + grouped view, selection, filter/grouping.
    guide: guide::State,
    /// The read-only source pane, open over whichever tab opened it.
    source: source::State,
    /// The one-time telemetry consent pane, open only between a scan
    /// finishing inside this session and the user's answer.
    consent: Option<consent::Pane>,
    /// Telemetry state access for the consent pane; `None` only when the husk
    /// home directory cannot be resolved (then the pane never opens).
    telemetry: Option<crate::cloud::telemetry::Telemetry>,
}

impl TuiApp {
    fn new(live: LiveScan) -> Self {
        let scan = scan::State::new(&live.report);
        Self {
            tab: Tab::Scan,
            live,
            scan,
            guide: guide::State::default(),
            source: source::State::default(),
            consent: None,
            telemetry: crate::cloud::telemetry::Telemetry::from_default_dir().ok(),
        }
    }

    /// `u` on the Scan tab: run the selected finding's dependency
    /// upgrade/downgrade (when the advisory names a safe version). `force` is
    /// shift-U, the PEP 668 opt-in.
    fn start_dep_fix(&mut self, force: bool) {
        if self.tab == Tab::Scan {
            self.scan.start_dep_fix(&self.live.report, force);
        }
    }

    /// Refresh the active tab's view-model against the current terminal size:
    /// the explicit update step before rendering, so state mutation never
    /// hides inside a `draw_*` function.
    fn prepare(&mut self, area: Rect) {
        let body = shell_rows(area)[2];
        match self.tab {
            Tab::Scan => self.scan.prepare(&self.live, body),
            Tab::Guide => self.guide.prepare(&self.live.report, body),
            _ => {}
        }
    }

    fn select_next(&mut self) {
        match self.tab {
            Tab::Guide => self.guide.select_next(),
            _ => self.scan.move_down(),
        }
    }

    fn select_prev(&mut self) {
        match self.tab {
            Tab::Guide => self.guide.select_prev(),
            _ => self.scan.move_up(),
        }
    }

    fn select_home(&mut self) {
        match self.tab {
            Tab::Guide => self.guide.select_home(),
            _ => self.scan.select_home(),
        }
    }

    fn select_end(&mut self) {
        match self.tab {
            Tab::Guide => self.guide.select_end(),
            _ => self.scan.select_end(),
        }
    }

    /// Cycle the Guide list filter, mirroring the web view's tabs.
    fn guide_cycle_filter(&mut self) {
        if self.tab == Tab::Guide {
            self.guide.cycle_filter();
        }
    }

    /// Cycle the Guide grouping, mirroring the web view's group-by control.
    fn guide_cycle_grouping(&mut self) {
        if self.tab == Tab::Guide {
            self.guide.cycle_grouping();
        }
    }

    /// Move the Guide detail pane's option selection left/right (h/l).
    fn guide_opt_move(&mut self, delta: i64) {
        if self.tab == Tab::Guide {
            self.guide.opt_move(delta);
        }
    }

    /// `x` on the Guide tab: open the fix pane for the selected task.
    fn guide_open_fix(&mut self) {
        if self.tab == Tab::Guide {
            self.guide.fix.open();
        }
    }

    /// `o` on the Scan tab: show the selected finding's file, read-only.
    /// Husk reads the file itself rather than launching an editor over a tree
    /// it has just flagged.
    fn open_source(&mut self) {
        if self.tab != Tab::Scan {
            return;
        }
        if let Some(finding) = self.scan.selected_finding(&self.live.report) {
            self.source.open(finding);
        }
    }

    /// Hand a key to the Guide's fix pane while it is showing. True when the
    /// pane took it, so the app's own bindings never fire underneath it.
    fn consume_fix_key(&mut self, code: KeyCode) -> bool {
        self.tab == Tab::Guide
            && self.guide.fix.is_open()
            && self.guide.fix.handle_key(code, &self.live)
    }

    fn update_live(&mut self, live: LiveScan) {
        let was_running = self.live.running;
        self.live = live;
        self.scan.update_report(&self.live.report);
        if consent::scan_just_completed(was_running, &self.live) {
            self.maybe_open_consent();
        }
    }

    /// Open the consent pane if the one-time ask is due right now. Opening
    /// persists the asked state immediately (see [`consent::Pane::open`]).
    fn maybe_open_consent(&mut self) {
        if self.consent.is_some() {
            return;
        }
        let Some(telemetry) = &self.telemetry else {
            return;
        };
        if consent::due(telemetry) {
            self.consent = Some(consent::Pane::open(telemetry));
        }
    }

    /// Hand a key to the consent pane while it is showing. The pane is modal:
    /// it consumes every key it sees (`q`/Ctrl-C are settled before this).
    fn consume_consent_key(&mut self, code: KeyCode) -> bool {
        let Some(pane) = &mut self.consent else {
            return false;
        };
        match pane.handle_key(code) {
            consent::Outcome::Open => {}
            consent::Outcome::Answered(enabled) => {
                if let Some(telemetry) = &self.telemetry {
                    consent::Pane::record(telemetry, enabled);
                }
                self.consent = None;
            }
        }
        true
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ReportKey {
    generated_at_ms: i64,
    findings: usize,
    guidance: usize,
}

fn report_key(report: &ScanReport) -> ReportKey {
    ReportKey {
        generated_at_ms: report.generated_at.timestamp_millis(),
        findings: report.findings.len(),
        guidance: report.guidance.total,
    }
}

/// The person to greet / attribute this machine to: git identity first, then
/// the OS user. Shared by the Scan context panel and the Account tab.
fn display_user(context: &crate::model::SystemContext) -> &str {
    context
        .git_name
        .as_deref()
        .or(context.user.as_deref())
        .unwrap_or("developer")
}

fn git_identity(report: &ScanReport) -> String {
    match (&report.context.git_name, &report.context.git_email) {
        (Some(name), Some(email)) => format!("{name} <{email}>"),
        (Some(name), None) => name.clone(),
        (None, Some(email)) => email.clone(),
        _ => "not configured".to_string(),
    }
}

fn compact_list(values: &[String], max: usize) -> String {
    if values.is_empty() {
        return "none detected".to_string();
    }
    let shown = values.iter().take(max).cloned().collect::<Vec<_>>();
    if values.len() > max {
        format!("{} +{}", shown.join(", "), values.len() - max)
    } else {
        shown.join(", ")
    }
}

fn progress_bar(percent: usize, width: usize) -> String {
    let filled = (percent.min(100) * width) / 100;
    format!(
        "[{}{}]",
        "█".repeat(filled),
        "░".repeat(width.saturating_sub(filled))
    )
}
