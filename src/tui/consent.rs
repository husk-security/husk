//! The one-time telemetry consent pane: the TUI's version of the CLI's
//! post-scan prompt, shown over the body when the first successful scan
//! completes inside the TUI and the decision is still due.
//!
//! The asked state is persisted as declined the moment the pane opens, not
//! when a key is pressed: quitting mid-pane counts as asked-and-declined, so
//! the user is never prompted again and telemetry stays off unless Yes is
//! chosen explicitly.

use crate::cloud::telemetry::{
    CONSENT_DETAIL, CONSENT_OFF_HINT, CONSENT_QUESTION, Telemetry, consent_due_now,
};
use crate::model::LiveScan;
use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use super::theme;

/// What one key did to the pane. The pane is modal: every key is consumed
/// while it is open (the shell settles `q`/Ctrl-C before the pane sees keys).
pub(super) enum Outcome {
    /// The pane stays open (focus moved, or the key meant nothing).
    Open,
    /// The user answered; `true` is yes. The pane closes.
    Answered(bool),
}

/// The open pane: which choice holds focus. Focus starts on No, so a bare
/// Enter declines, matching the CLI prompt's `[y/N]` default.
#[derive(Default)]
pub(super) struct Pane {
    focus_yes: bool,
}

/// Whether the pane should open now: the shared consent decision against the
/// real terminal and environment (never under CI, `DO_NOT_TRACK`,
/// `HUSK_TELEMETRY_DISABLED`, or once any surface has asked).
pub(super) fn due(telemetry: &Telemetry) -> bool {
    use std::io::IsTerminal;
    consent_due_now(
        telemetry,
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    )
}

/// True when this `update_live` tick is the moment a scan finished cleanly:
/// the trigger for the one-time ask.
pub(super) fn scan_just_completed(was_running: bool, live: &LiveScan) -> bool {
    was_running && !live.running && live.error.is_none()
}

impl Pane {
    /// Open the pane and persist the asked state immediately: the decision on
    /// disk becomes declined before the user answers, so an unanswered pane
    /// (quit, crash) is a recorded no rather than a future re-prompt. Yes
    /// upgrades the record; the write is best-effort because the pane must
    /// never block the UI on a state-dir error.
    pub(super) fn open(telemetry: &Telemetry) -> Self {
        let _ = telemetry.disable();
        Self::default()
    }

    /// Apply one key. `y`/`n` answer directly; arrows and Tab move focus;
    /// Enter takes the focused choice; Esc declines.
    pub(super) fn handle_key(&mut self, code: KeyCode) -> Outcome {
        match code {
            KeyCode::Char('y') | KeyCode::Char('Y') => Outcome::Answered(true),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => Outcome::Answered(false),
            KeyCode::Enter => Outcome::Answered(self.focus_yes),
            KeyCode::Left
            | KeyCode::Right
            | KeyCode::Tab
            | KeyCode::Char('h')
            | KeyCode::Char('l') => {
                self.focus_yes = !self.focus_yes;
                Outcome::Open
            }
            _ => Outcome::Open,
        }
    }

    /// Record the answer. Declined is already on disk from [`Pane::open`], so
    /// only yes writes again.
    pub(super) fn record(telemetry: &Telemetry, enabled: bool) {
        if enabled {
            let _ = telemetry.enable();
        }
    }
}

/// Fixed pane dimensions: the copy is static, so the box never resizes or
/// moves because of scan content.
const PANE_WIDTH: u16 = 64;
const PANE_HEIGHT: u16 = 9;

/// Draw the pane centered over `body`, clamped to it on small terminals.
pub(super) fn draw(frame: &mut Frame<'_>, body: Rect, pane: &Pane) {
    let width = PANE_WIDTH.min(body.width);
    let height = PANE_HEIGHT.min(body.height);
    let area = Rect::new(
        body.x + (body.width.saturating_sub(width)) / 2,
        body.y + (body.height.saturating_sub(height)) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::muted())
        .title(Span::styled(" telemetry ", theme::accent()));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let choice = |label: &'static str, focused: bool| {
        let style = if focused {
            theme::accent().add_modifier(ratatui::style::Modifier::REVERSED)
        } else {
            theme::muted()
        };
        Span::styled(label, style)
    };
    let lines = vec![
        Line::from(Span::styled(CONSENT_QUESTION, theme::accent())),
        Line::from(""),
        Line::from(Span::styled(CONSENT_DETAIL, theme::muted())),
        Line::from(Span::styled(CONSENT_OFF_HINT, theme::muted())),
        Line::from(""),
        Line::from(vec![
            Span::raw("   "),
            choice("[ No ]", !pane.focus_yes),
            Span::raw("   "),
            choice("[ Yes ]", pane.focus_yes),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false }),
        inner,
    );
}
