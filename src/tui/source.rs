//! The source pane: the file a finding sits in, read-only, over the Scan body.
//!
//! Husk shows the file rather than handing it to `$EDITOR`, because an editor
//! opens with the tree's own plugins, formatters, and language servers, and
//! this is a file the scanner has just called dangerous. A pane keeps the whole
//! surface read-only, which is the promise the scan itself makes.
//!
//! Terminal half of the web UI's source panel: both render the token classes
//! [`crate::highlight`] produces, so neither surface colours a line its own way.

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};

use super::theme;
use crate::highlight::{self, Excerpt};
use crate::model::Finding;
use crate::term::truncate_middle;

/// Rows a page key moves. Keeps a couple of lines of overlap at a typical pane
/// height, so a page turn never hides the line the reader was on.
const PAGE: isize = 15;

/// Rows of context kept above the flagged line when the pane opens. What sits
/// above a finding is usually why it is a finding.
const LEAD: usize = 6;

#[derive(Default)]
pub(super) struct State {
    pane: Option<Pane>,
    scroll: usize,
}

struct Pane {
    /// `path:line`, the same location string the findings list shows.
    title: String,
    /// The excerpt, or the reason there isn't one (unreadable, binary, huge).
    /// A failure is content, not a closed pane: "why can't I see it" is an
    /// answer the reader needs on screen.
    body: Result<Excerpt, String>,
}

impl State {
    pub(super) fn is_open(&self) -> bool {
        self.pane.is_some()
    }

    /// `o`: read the selected finding's file. A finding with no location (an
    /// advisory against a coordinate no manifest placed) has nothing to open,
    /// and the key does nothing rather than opening an empty pane.
    pub(super) fn open(&mut self, finding: &Finding) {
        let Some((path, line)) = finding.location() else {
            return;
        };
        let focus = line.map(|line| line as u32);
        let body = highlight::excerpt(path, focus, highlight::RADIUS)
            .map_err(|err| format!("{err:#}"))
            .inspect(|excerpt| {
                self.scroll = focus_row(excerpt).saturating_sub(LEAD);
            });
        self.pane = Some(Pane {
            title: match line {
                Some(line) => format!("{}:{line}", path.display()),
                None => path.display().to_string(),
            },
            body,
        });
    }

    pub(super) fn close(&mut self) {
        self.pane = None;
        self.scroll = 0;
    }

    /// One key of the pane's own model. False means the key was not the pane's,
    /// and the app's normal handling should see it.
    pub(super) fn handle_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Down | KeyCode::Char('j') => self.scroll_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_by(-1),
            KeyCode::PageDown => self.scroll_by(PAGE),
            KeyCode::PageUp => self.scroll_by(-PAGE),
            KeyCode::Home => self.scroll = 0,
            KeyCode::Esc | KeyCode::Char('o') => self.close(),
            _ => return false,
        }
        true
    }

    fn scroll_by(&mut self, delta: isize) {
        let last = match self.pane.as_ref().map(|pane| &pane.body) {
            Some(Ok(excerpt)) => excerpt.lines.len().saturating_sub(1),
            _ => 0,
        };
        self.scroll = self.scroll.saturating_add_signed(delta).min(last);
    }
}

/// Index of the flagged line within the excerpt, or the top when the finding
/// named no line (the excerpt then starts at the file's first line).
fn focus_row(excerpt: &Excerpt) -> usize {
    let Some(focus) = excerpt.focus else {
        return 0;
    };
    excerpt
        .lines
        .iter()
        .position(|line| line.number == focus)
        .unwrap_or(0)
}

pub(super) fn draw(frame: &mut Frame<'_>, state: &State, area: Rect) {
    let Some(pane) = &state.pane else {
        return;
    };
    let width = area.width as usize;
    // The pane covers the body it is drawn over; without this the rows the
    // pane does not fill keep whatever the tab painted underneath.
    frame.render_widget(Clear, area);

    let title = format!(
        " {} ",
        truncate_middle(&pane.title, width.saturating_sub(4))
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .title(Span::styled(title, theme::accent()))
        .padding(Padding::new(1, 1, 0, 0));

    let body = match &pane.body {
        // Never wrapped: a wrapped source line reflows every row beneath it as
        // the pane scrolls, and the gutter would stop meaning line numbers.
        Ok(excerpt) => rows(excerpt),
        Err(message) => vec![
            Line::from(Span::styled(message.clone(), theme::warn())),
            Line::from(""),
            Line::from(Span::styled(
                "esc to go back".to_string(),
                Style::default().fg(theme::FG_SUBTLE),
            )),
        ],
    };
    frame.render_widget(
        Paragraph::new(body)
            .block(block)
            .scroll((state.scroll as u16, 0)),
        area,
    );
}

/// The excerpt as styled rows: a line-number gutter, a marker on the flagged
/// line, then the tokens.
fn rows(excerpt: &Excerpt) -> Vec<Line<'static>> {
    excerpt
        .lines
        .iter()
        .map(|line| {
            let flagged = excerpt.focus == Some(line.number);
            let mut spans = vec![
                Span::styled(
                    format!("{:>5}{} ", line.number, if flagged { "›" } else { " " }),
                    if flagged {
                        theme::accent()
                    } else {
                        Style::default().fg(theme::FG_SUBTLE)
                    },
                ),
                Span::styled("│ ".to_string(), Style::default().fg(theme::BORDER)),
            ];
            spans.extend(
                line.tokens
                    .iter()
                    .map(|token| Span::styled(token.text.clone(), theme::token(token.class))),
            );
            let row = Line::from(spans);
            if flagged {
                row.style(Style::default().bg(theme::SCAN_SELECTION_BG))
            } else {
                row
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use crate::rule::Category;

    fn finding(path: Option<std::path::PathBuf>, line: Option<usize>) -> Finding {
        Finding::new(
            "id",
            "title",
            Severity::High,
            Category::Secret,
            "test",
            path,
            line,
            "summary",
            None,
            "do something",
        )
    }

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.json");
        let body = (1..=200)
            .map(|n| format!("  \"k{n}\": {n},\n"))
            .collect::<String>();
        std::fs::write(&path, body).unwrap();
        (dir, path)
    }

    #[test]
    fn opening_shows_the_flagged_line_with_context_above_it() {
        let (_dir, path) = fixture();
        let mut state = State::default();
        state.open(&finding(Some(path), Some(100)));
        assert!(state.is_open());

        let Some(Ok(excerpt)) = state.pane.as_ref().map(|pane| &pane.body) else {
            panic!("expected an excerpt");
        };
        assert_eq!(excerpt.focus, Some(100));
        assert_eq!(state.scroll, focus_row(excerpt) - LEAD);
        assert!(excerpt.lines.iter().any(|line| line.number == 100));
    }

    #[test]
    fn a_finding_with_no_location_does_not_open_a_pane() {
        let mut state = State::default();
        state.open(&finding(None, None));
        assert!(!state.is_open());
    }

    #[test]
    fn an_unreadable_file_opens_the_pane_on_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = State::default();
        state.open(&finding(Some(dir.path().join("gone.toml")), Some(3)));
        assert!(matches!(
            state.pane.as_ref().map(|pane| &pane.body),
            Some(Err(_))
        ));
    }

    #[test]
    fn scrolling_stops_at_both_ends_and_esc_closes() {
        let (_dir, path) = fixture();
        let mut state = State::default();
        state.open(&finding(Some(path), Some(100)));

        state.scroll = 0;
        assert!(state.handle_key(KeyCode::Up));
        assert_eq!(state.scroll, 0, "cannot scroll above the first line");

        for _ in 0..40 {
            state.handle_key(KeyCode::PageDown);
        }
        let Some(Ok(excerpt)) = state.pane.as_ref().map(|pane| &pane.body) else {
            panic!("expected an excerpt");
        };
        assert_eq!(state.scroll, excerpt.lines.len() - 1);

        assert!(!state.handle_key(KeyCode::Char('z')), "not the pane's key");
        assert!(state.handle_key(KeyCode::Esc));
        assert!(!state.is_open());
        assert_eq!(state.scroll, 0);
    }
}
