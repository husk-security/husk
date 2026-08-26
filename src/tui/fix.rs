//! The fix surface: what a fix would change, the command that changes the same
//! thing by hand, and the selection that applies several at once.
//!
//! Every line here is rendered from the server-side
//! [`FixPreview`](crate::remediation::render::FixPreview) the web renders, so
//! the two surfaces cannot describe one fix differently. The pane decides which
//! planned proposals to send, never what they contain.
//!
//! Terminal shape of `web/src/features/guide/Remediation.tsx`: proposals
//! grouped by the directory the fix runs in, selection defaulting to everything
//! Husk can run right now, blocked rows kept on screen with their reason.

use std::collections::{BTreeMap, BTreeSet};

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use super::{DETAIL_LABEL_WIDTH as FIELD_WIDTH, ReportKey, detail_field, detail_section, theme};
use crate::guide::AssessedTask;
use crate::model::{LiveScan, ScanReport};
use crate::remediation::render::FixPreview;
use crate::remediation::{ActionResult, ActionStatus, ExecutionClass, RemediationProposal};
use crate::term::{truncate_end, truncate_middle};

/// Diff lines one file contributes to the pane before the rest is elided. The
/// pane scrolls, so this is generous; what was dropped is still stated.
const PANE_DIFF_LINES: usize = 60;

/// Transcript lines a finished run shows. A package manager can print hundreds.
const OUTPUT_LINES: usize = 12;

/// What a fix would change and the command that changes the same thing by hand,
/// laid out for a column `width` characters wide.
///
/// A terminal has no copy button, so the command matters more here than in the
/// browser: it is the escape hatch for a developer who would rather run it
/// themselves. Paths around it are middle-truncated; the command itself never
/// is, because a command you cannot read whole is a command you cannot check.
pub(super) fn preview_lines(
    preview: &FixPreview,
    max_diff_lines: usize,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for file in &preview.diff {
        lines.push(Line::from(""));
        lines.push(detail_section(if file.created {
            "New file"
        } else {
            "Change"
        }));
        let counts = format!(" (+{} -{})", file.added, file.removed);
        lines.push(detail_field(
            "file",
            format!(
                "{}{counts}",
                truncate_middle(
                    &file.path.display().to_string(),
                    width.saturating_sub(FIELD_WIDTH + counts.len()),
                )
            ),
            theme::IDENT,
        ));
        // Coloured by line prefix, which is the unified diff format's own
        // contract, so no surface parses a diff. The `---`/`+++` header names
        // the file the line above already names, so it is not repeated.
        let body = || {
            file.diff
                .lines()
                .filter(|line| !line.starts_with("---") && !line.starts_with("+++"))
        };
        let total = body().count();
        for line in body().take(max_diff_lines) {
            let color = match line.as_bytes().first() {
                Some(b'+') => theme::OK,
                Some(b'-') => theme::ERR,
                Some(b'@') => theme::FG_SUBTLE,
                _ => theme::FG_MUTED,
            };
            lines.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(color),
            )));
        }
        if total > max_diff_lines {
            lines.push(Line::from(Span::styled(
                format!("  {} more lines not shown", total - max_diff_lines),
                Style::default().fg(theme::FG_SUBTLE),
            )));
        }
    }
    if let Some(command) = &preview.command {
        lines.push(Line::from(""));
        lines.push(detail_section("Or run this yourself"));
        lines.push(Line::from(Span::styled(
            command.clone(),
            Style::default().fg(theme::FG),
        )));
        if let Some(cwd) = &preview.cwd {
            lines.push(detail_field(
                "in",
                truncate_middle(
                    &cwd.display().to_string(),
                    width.saturating_sub(FIELD_WIDTH),
                ),
                theme::FG_SUBTLE,
            ));
        }
        if !preview.complete {
            lines.push(Line::from(Span::styled(
                "The change above is not part of this command. Make it too, or let husk apply both."
                    .to_string(),
                Style::default().fg(theme::FG_SUBTLE),
            )));
        }
    }
    lines
}

/// The fix pane's view-model: the selected task's proposals, which of them are
/// selected, and the state of a run. Mutated only in [`State::prepare`] and the
/// key handlers so [`draw`] can take it immutably.
#[derive(Default)]
pub(super) struct State {
    open: bool,
    /// Proposal ids the user turned off. Selection defaults to everything Husk
    /// can run right now, so this holds departures from that, not the selection.
    deselected: BTreeSet<String>,
    /// Cursor into `rows.flat`.
    cursor: usize,
    /// First line of the preview column that is visible.
    preview_scroll: usize,
    /// The PEP 668 opt-in, mirroring shift-U on the Scan tab.
    allow_break: bool,
    rows: Option<Rows>,
    /// The selected proposal's preview, rebuilt in `prepare` so `draw` renders
    /// a fixed list of lines and the scroll can be clamped against its length.
    preview: Vec<Line<'static>>,
    run: Run,
    /// The last run's result per proposal id.
    results: BTreeMap<String, ActionResult>,
    /// One line summarising the last run, shown in the pane header.
    message: Option<String>,
}

/// The selected task's proposals, grouped for display.
struct Rows {
    key: (ReportKey, String),
    proposals: Vec<RemediationProposal>,
    /// Fix directory to proposal indices, so several packages in one workspace
    /// read as one decision rather than N unrelated ones.
    sections: Vec<(String, Vec<usize>)>,
    /// The sections flattened, so the cursor indexes proposals rather than
    /// group headers.
    flat: Vec<usize>,
}

#[derive(Default)]
enum Run {
    #[default]
    Idle,
    Running {
        count: usize,
        rx: std::sync::mpsc::Receiver<Vec<ActionResult>>,
    },
    Done,
}

impl State {
    pub(super) fn is_open(&self) -> bool {
        self.open
    }

    /// Whether a run is in flight, so the event loop keeps its fast poll while
    /// a package manager works.
    pub(super) fn running(&self) -> bool {
        matches!(self.run, Run::Running { .. })
    }

    /// Rebuild against the selected task, then clamp the cursor and the preview
    /// scroll. Switching task or rescanning starts from a clean selection: one
    /// made against packages that may no longer be there is worse than none.
    pub(super) fn prepare(
        &mut self,
        report: &ScanReport,
        key: ReportKey,
        task: Option<&AssessedTask>,
        body: Rect,
    ) {
        let want = task.map(|task| (key, task.id.clone()));
        if self.rows.as_ref().map(|rows| rows.key.clone()) != want {
            self.rows = want.map(|key| {
                let ids = task
                    .map(|task| task.remediation_ids.as_slice())
                    .unwrap_or(&[]);
                build(report, key, ids)
            });
            self.deselected.clear();
            self.results.clear();
            self.message = None;
            self.cursor = 0;
            self.preview_scroll = 0;
        }
        if self.rows.as_ref().map(|rows| rows.flat.len()).unwrap_or(0) == 0 {
            self.open = false;
        }
        let len = self.rows.as_ref().map(|rows| rows.flat.len()).unwrap_or(0);
        self.cursor = self.cursor.min(len.saturating_sub(1));
        // The same split `draw` uses, so paths are truncated to the column they
        // land in rather than to a guess.
        let width = layout(body).2.width.saturating_sub(4) as usize;
        self.preview = self
            .selected_proposal()
            .map(|proposal| self.proposal_lines(proposal, width))
            .unwrap_or_default();
        // Clamped against the unwrapped length: wrapping only makes the
        // rendered column longer, so this can never scroll past the end.
        self.preview_scroll = self
            .preview_scroll
            .min(self.preview.len().saturating_sub(1));
    }

    fn proposals(&self) -> &[RemediationProposal] {
        self.rows
            .as_ref()
            .map(|rows| rows.proposals.as_slice())
            .unwrap_or(&[])
    }

    fn selected_proposal(&self) -> Option<&RemediationProposal> {
        let rows = self.rows.as_ref()?;
        rows.proposals.get(*rows.flat.get(self.cursor)?)
    }

    /// Whether Husk can run this proposal as things stand: the server's own
    /// `ready`, plus the rows the reader's opt-in has just unblocked.
    fn runnable(&self, proposal: &RemediationProposal) -> bool {
        proposal.ready
            || (self.allow_break
                && !proposal.overrides.is_empty()
                && proposal.class != ExecutionClass::Manual)
    }

    fn is_selected(&self, proposal: &RemediationProposal) -> bool {
        self.runnable(proposal) && !self.deselected.contains(&proposal.id)
    }

    fn selected_ids(&self) -> Vec<String> {
        self.proposals()
            .iter()
            .filter(|proposal| self.is_selected(proposal))
            .map(|proposal| proposal.id.clone())
            .collect()
    }

    /// Open the pane, when the selected task has anything to show.
    pub(super) fn open(&mut self) {
        if self.rows.as_ref().is_some_and(|rows| !rows.flat.is_empty()) {
            self.open = true;
        }
    }

    pub(super) fn close(&mut self) {
        self.open = false;
    }

    fn move_cursor(&mut self, delta: i64) {
        let len = self.rows.as_ref().map(|rows| rows.flat.len()).unwrap_or(0);
        if len == 0 {
            return;
        }
        self.cursor = (self.cursor as i64 + delta).clamp(0, len as i64 - 1) as usize;
        self.preview_scroll = 0;
    }

    fn toggle(&mut self) {
        let Some(proposal) = self.selected_proposal() else {
            return;
        };
        if !self.runnable(proposal) {
            return;
        }
        let id = proposal.id.clone();
        if !self.deselected.remove(&id) {
            self.deselected.insert(id);
        }
    }

    /// Select everything runnable, or clear the selection when it is already
    /// whole.
    fn toggle_all(&mut self) {
        if self.selected_ids().is_empty() {
            self.deselected.clear();
        } else {
            self.deselected = self
                .proposals()
                .iter()
                .map(|proposal| proposal.id.clone())
                .collect();
        }
    }

    /// Take (or drop) the one opt-in Husk offers, then re-plan nothing: the
    /// flag is an input to the apply request, and the blocked rows it clears
    /// become selectable because [`State::runnable`] asks the typed
    /// `overrides`, never prose.
    fn toggle_override(&mut self) {
        self.allow_break = !self.allow_break;
    }

    fn scroll_preview(&mut self, delta: i64) {
        let max = self.preview.len().saturating_sub(1) as i64;
        self.preview_scroll = (self.preview_scroll as i64 + delta).clamp(0, max) as usize;
    }

    /// Apply every selected proposal in one run: one lock, one backup snapshot,
    /// one rollback point, exactly as the web's one button does.
    ///
    /// Refused while a scan runs, matching `POST /api/remediation/apply`: the
    /// plan on screen was computed against the tree that scan is walking, so
    /// editing it now would leave the landing report part pre-fix and part
    /// post-fix.
    fn apply(&mut self, live: &LiveScan) {
        if self.running() {
            return;
        }
        if live.running {
            self.message =
                Some("A scan is running. Wait for it to finish, then apply.".to_string());
            return;
        }
        let selected: Vec<RemediationProposal> = self
            .proposals()
            .iter()
            .filter(|proposal| self.is_selected(proposal))
            .cloned()
            .map(|proposal| {
                if self.allow_break {
                    crate::remediation::with_break_system_packages(proposal)
                } else {
                    proposal
                }
            })
            .collect();
        if selected.is_empty() {
            return;
        }
        let count = selected.len();
        // Ledger targets keyed by proposal id, so an entry names what it fixed.
        let targets: BTreeMap<String, String> = selected
            .iter()
            .map(|proposal| {
                (
                    proposal.id.clone(),
                    proposal
                        .finding_ids
                        .first()
                        .cloned()
                        .unwrap_or_else(|| proposal.id.clone()),
                )
            })
            .collect();
        let deps = selected.iter().any(|proposal| {
            matches!(
                proposal.action,
                crate::remediation::RemediationOperation::DependencyUpdate { .. }
            )
        });
        let generated_at = live.report.generated_at;
        let (tx, rx) = std::sync::mpsc::channel();
        // A package manager can take a while and must not freeze the UI.
        std::thread::spawn(move || {
            let plan = crate::remediation::RemediationPlan {
                generated_at,
                proposals: selected,
            };
            let mut options = crate::remediation::ApplyOptions::new(false);
            options.deps = deps;
            let results = match crate::remediation::apply(&plan, &options) {
                Ok(outcome) => outcome.results,
                Err(error) => vec![ActionResult {
                    id: String::new(),
                    status: ActionStatus::Failed,
                    detail: format!("{error:#}"),
                    output: None,
                }],
            };
            // The ledger records what husk changed, so an already-satisfied
            // proposal leaves no entry.
            for result in results
                .iter()
                .filter(|result| result.status == ActionStatus::Applied)
            {
                let target = targets.get(&result.id).unwrap_or(&result.id);
                let _ = crate::ledger::append(
                    "remediation.apply",
                    target,
                    Some(result.detail.as_str()),
                    None,
                );
            }
            let _ = tx.send(results);
        });
        self.run = Run::Running { count, rx };
        self.message = None;
    }

    /// Collect a finished run, if one arrived. True when the state changed, so
    /// the caller redraws.
    pub(super) fn poll(&mut self) -> bool {
        let Run::Running { rx, .. } = &self.run else {
            return false;
        };
        let Ok(results) = rx.try_recv() else {
            return false;
        };
        self.message = Some(crate::remediation::apply_summary(&results));
        self.results = results
            .into_iter()
            .map(|result| (result.id.clone(), result))
            .collect();
        self.run = Run::Done;
        true
    }

    /// One key of the pane's own model. False means the key was not the pane's,
    /// and the app's normal handling should see it.
    pub(super) fn handle_key(&mut self, code: crossterm::event::KeyCode, live: &LiveScan) -> bool {
        use crossterm::event::KeyCode;
        match code {
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Char(' ') => self.toggle(),
            KeyCode::Char('a') => self.toggle_all(),
            KeyCode::Char('U') => self.toggle_override(),
            KeyCode::Enter => self.apply(live),
            KeyCode::PageDown => self.scroll_preview(8),
            KeyCode::PageUp => self.scroll_preview(-8),
            KeyCode::Esc | KeyCode::Char('x') => self.close(),
            _ => return false,
        }
        true
    }

    /// The Guide detail pane's entry to the fix pane: what is on offer and how
    /// to get at it. `None` when the task has nothing Husk can do.
    pub(super) fn summary(&self) -> Option<Vec<Line<'static>>> {
        let rows = self.rows.as_ref()?;
        if rows.flat.is_empty() {
            return None;
        }
        let blocked = rows
            .proposals
            .iter()
            .filter(|proposal| !proposal.blockers.is_empty())
            .count();
        let mut note = format!(
            "{} {} husk can take",
            rows.flat.len(),
            if rows.flat.len() == 1 { "fix" } else { "fixes" }
        );
        if blocked > 0 {
            note.push_str(&format!(", {blocked} blocked"));
        }
        Some(vec![
            Line::from(""),
            detail_section("Fix with husk"),
            Line::from(Span::styled(note, Style::default().fg(theme::FG))),
            Line::from(Span::styled(
                "press x to see the change and apply it".to_string(),
                Style::default().fg(theme::FG_SUBTLE),
            )),
        ])
    }

    /// The preview column for one proposal: why, what stops it, what it
    /// changes, and what the last run said.
    fn proposal_lines(&self, proposal: &RemediationProposal, width: usize) -> Vec<Line<'static>> {
        let mut lines = vec![
            Line::from(Span::styled(proposal.title.clone(), theme::accent())),
            Line::from(Span::styled(
                proposal.reason.clone(),
                Style::default().fg(theme::FG_MUTED),
            )),
        ];
        for blocker in &proposal.blockers {
            lines.push(Line::from(""));
            lines.push(detail_field("blocked", blocker.render(), theme::BUSY));
        }
        if !proposal.overrides.is_empty() {
            lines.push(Line::from(Span::styled(
                if self.allow_break {
                    "shift-U is on: this will run with pip --break-system-packages.".to_string()
                } else {
                    "press shift-U to allow it anyway (writes into the system Python).".to_string()
                },
                Style::default().fg(theme::BUSY),
            )));
        }
        if proposal.class == ExecutionClass::Manual {
            lines.push(Line::from(""));
            lines.push(detail_section("Steps"));
            for (i, step) in proposal.recipe.steps.iter().enumerate() {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{}. ", i + 1),
                        Style::default().fg(theme::FG_SUBTLE),
                    ),
                    Span::styled(step.text.clone(), Style::default().fg(theme::FG)),
                ]));
                // One line each, ellipsized in the middle: a subject list is
                // read by scanning down it, so a path that wraps costs more
                // than the characters it saves, and both ends of a path are
                // what tell two of them apart.
                for subject in &step.subjects {
                    lines.push(Line::from(Span::styled(
                        format!(
                            "   {}",
                            crate::term::truncate_middle(subject, width.saturating_sub(3))
                        ),
                        Style::default().fg(theme::FG_MUTED),
                    )));
                }
            }
        }
        if let Some(preview) = &proposal.preview {
            lines.extend(preview_lines(preview, PANE_DIFF_LINES, width));
        }
        if let Some(result) = self.results.get(&proposal.id) {
            lines.push(Line::from(""));
            lines.push(detail_section("Result"));
            lines.push(detail_field(
                "status",
                result.detail.clone(),
                match result.status {
                    ActionStatus::Applied | ActionStatus::Skipped => theme::OK,
                    ActionStatus::NeedsUser | ActionStatus::WouldApply => theme::BUSY,
                    ActionStatus::Failed => theme::ERR,
                },
            ));
            if let Some(output) = &result.output {
                let total = output.lines().count();
                for line in output.lines().take(OUTPUT_LINES) {
                    lines.push(Line::from(Span::styled(
                        line.to_string(),
                        Style::default().fg(theme::FG_MUTED),
                    )));
                }
                if total > OUTPUT_LINES {
                    lines.push(Line::from(Span::styled(
                        format!("  {} more lines not shown", total - OUTPUT_LINES),
                        Style::default().fg(theme::FG_SUBTLE),
                    )));
                }
            }
        }
        lines
    }
}

/// The task's proposals, grouped by the directory the fix runs in. Report order
/// is kept (it is severity-ordered), so the pane never re-sorts a plan.
fn build(report: &ScanReport, key: (ReportKey, String), ids: &[String]) -> Rows {
    let wanted: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
    let proposals: Vec<RemediationProposal> = report
        .remediations
        .iter()
        .filter(|proposal| wanted.contains(proposal.id.as_str()))
        .cloned()
        .collect();
    let mut sections: Vec<(String, Vec<usize>)> = Vec::new();
    for (index, proposal) in proposals.iter().enumerate() {
        let label = proposal.recipe.scope.display().to_string();
        match sections.iter_mut().find(|(seen, _)| *seen == label) {
            Some((_, members)) => members.push(index),
            None => sections.push((label, vec![index])),
        }
    }
    let flat = sections
        .iter()
        .flat_map(|(_, members)| members.iter().copied())
        .collect();
    Rows {
        key,
        proposals,
        sections,
        flat,
    }
}

/// The pane's fixed grid: a two-line header over a rows/preview split. Shared
/// by [`State::prepare`] (which truncates paths to the preview column) and
/// [`draw`].
fn layout(area: Rect) -> (Rect, Rect, Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(area);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(rows[1]);
    (rows[0], cols[0], cols[1])
}

pub(super) fn draw(frame: &mut Frame<'_>, state: &State, area: Rect) {
    let (header, list, preview) = layout(area);
    draw_header(frame, state, header);
    draw_list(frame, state, list);

    // Says where in a long change the reader is, so scrolling is visibly a
    // move through the whole thing rather than content appearing from nowhere.
    let title = if state.preview_scroll > 0 {
        format!("What it changes  ·  from line {}", state.preview_scroll + 1)
    } else {
        "What it changes".to_string()
    };
    frame.render_widget(
        Paragraph::new(state.preview.clone())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(theme::BORDER))
                    .title(title)
                    .padding(ratatui::widgets::Padding::new(1, 1, 0, 0)),
            )
            // Wrapped, never clipped: a command you cannot read whole is a
            // command you cannot check, and that is the point of showing it.
            .wrap(Wrap { trim: false })
            .scroll((state.preview_scroll as u16, 0)),
        preview,
    );
}

fn draw_header(frame: &mut Frame<'_>, state: &State, area: Rect) {
    let proposals = state.proposals();
    let blocked = proposals
        .iter()
        .filter(|proposal| !proposal.blockers.is_empty())
        .count();
    let selected = state.selected_ids().len();
    let width = area.width as usize;

    let mut headline = vec![
        Span::styled("Fix with husk", theme::accent()),
        Span::styled(
            format!(
                "   {} {} · {selected} selected",
                proposals.len(),
                if proposals.len() == 1 { "fix" } else { "fixes" }
            ),
            theme::muted(),
        ),
    ];
    if blocked > 0 {
        headline.push(Span::styled(
            format!(" · {blocked} blocked"),
            Style::default().fg(theme::BUSY),
        ));
    }

    let overridable = proposals
        .iter()
        .filter(|proposal| !proposal.overrides.is_empty())
        .count();
    let status = match (&state.run, &state.message) {
        (Run::Running { count, .. }, _) => Line::from(Span::styled(
            format!("applying {count}..."),
            Style::default().fg(theme::BUSY),
        )),
        (_, Some(message)) => Line::from(Span::styled(
            truncate_end(message, width),
            Style::default().fg(theme::FG),
        )),
        _ if overridable > 0 => Line::from(Span::styled(
            truncate_end(
                &format!(
                    "[{}] shift-U: also fix {overridable} PEP 668 package(s) with pip \
                     --break-system-packages. A virtualenv or pipx stays the safer route.",
                    if state.allow_break { "x" } else { " " }
                ),
                width,
            ),
            Style::default().fg(theme::BUSY),
        )),
        _ => Line::from(Span::styled(
            "Selected fixes run as one apply: one backup, one rollback point.".to_string(),
            Style::default().fg(theme::FG_SUBTLE),
        )),
    };
    frame.render_widget(Paragraph::new(vec![Line::from(headline), status]), area);
}

fn draw_list(frame: &mut Frame<'_>, state: &State, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .title("Fixes");
    let Some(rows) = state.rows.as_ref() else {
        frame.render_widget(Paragraph::new("").block(block), area);
        return;
    };
    let width = area.width.saturating_sub(2) as usize;

    let mut items: Vec<ListItem> = Vec::new();
    let mut selected_row = None;
    let mut cursor = 0usize;
    for (label, members) in &rows.sections {
        items.push(ListItem::new(Line::from(Span::styled(
            format!(
                "▾ {}  ·  {}",
                truncate_middle(label, width.saturating_sub(8)),
                members.len()
            ),
            theme::label(),
        ))));
        for &index in members {
            if cursor == state.cursor {
                selected_row = Some(items.len());
            }
            items.push(row(state, &rows.proposals[index], width));
            cursor += 1;
        }
    }
    let mut list_state = ListState::default();
    list_state.select(selected_row);
    frame.render_stateful_widget(
        List::new(items).block(block).highlight_style(
            Style::default()
                .bg(theme::SELECTION_BG)
                .add_modifier(Modifier::BOLD),
        ),
        area,
        &mut list_state,
    );
}

/// One proposal row: its selection box and title, plus, for a blocked row, the
/// reason on a second line. Both lines are truncated to the column, so a row is
/// one or two lines whatever the prose behind it says.
fn row(state: &State, proposal: &RemediationProposal, width: usize) -> ListItem<'static> {
    let (mark, mark_color) = if state.is_selected(proposal) {
        ("[x] ", theme::FG)
    } else if state.runnable(proposal) {
        ("[ ] ", theme::FG_SUBTLE)
    } else if proposal.class == ExecutionClass::Manual {
        ("(i) ", theme::FG_SUBTLE)
    } else {
        ("[!] ", theme::BUSY)
    };
    let title_width = width.saturating_sub(4).max(8);
    let mut lines = vec![Line::from(vec![
        Span::styled(mark, Style::default().fg(mark_color)),
        Span::styled(
            truncate_end(&proposal.title, title_width),
            Style::default().fg(theme::severity(proposal.severity)),
        ),
    ])];
    // The reason is the whole value of a blocked row, so it is on the row
    // rather than only in the pane beside it.
    if let Some(blocker) = proposal.blockers.first() {
        lines.push(Line::from(Span::styled(
            format!("    {}", truncate_end(&blocker.render(), title_width)),
            Style::default().fg(theme::FG_SUBTLE),
        )));
    }
    ListItem::new(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use crate::remediation::op::{Explain, FixOp, Recipe, Safety, Verify};
    use crate::remediation::plan::Blocker;
    use std::path::PathBuf;

    fn proposal(id: &str, scope: &str, blockers: Vec<Blocker>) -> RemediationProposal {
        let recipe = Recipe::new(
            PathBuf::from(scope),
            Safety::SafeEdit,
            Explain::new("because"),
            Verify::UserConfirms,
        )
        .op(FixOp::AppendUniqueLine {
            path: PathBuf::from(scope).join(".gitignore"),
            line: ".env".into(),
            header: None,
        });
        RemediationProposal {
            id: id.to_string(),
            control_id: "secrets-out-of-code".to_string(),
            finding_ids: vec![format!("finding:{id}")],
            title: format!("fix {id}"),
            severity: Severity::High,
            class: ExecutionClass::AutoSafe,
            reason: "because".to_string(),
            action: crate::remediation::RemediationOperation::GitignoreAppend {
                secret_path: PathBuf::from(scope).join(".env"),
            },
            preview: crate::remediation::exec::preview(&recipe),
            recipe,
            overrides: crate::remediation::plan::overrides_for(&blockers).unwrap_or_default(),
            ready: blockers.is_empty(),
            blockers,
        }
    }

    fn state(proposals: Vec<RemediationProposal>) -> State {
        let mut report = ScanReport::empty(Vec::new());
        let ids: Vec<String> = proposals.iter().map(|p| p.id.clone()).collect();
        report.remediations = proposals;
        State {
            rows: Some(build(
                &report,
                (super::super::report_key(&report), "t".into()),
                &ids,
            )),
            ..State::default()
        }
    }

    #[test]
    fn selection_defaults_to_everything_husk_can_run() {
        let state = state(vec![
            proposal("a", "/proj", Vec::new()),
            proposal(
                "b",
                "/proj",
                vec![Blocker::ToolMissing {
                    program: "npm".into(),
                }],
            ),
        ]);
        assert_eq!(state.selected_ids(), vec!["a".to_string()]);
    }

    /// A blocked row stays on screen with its reason; it is never quietly
    /// dropped, and toggling cannot select it.
    #[test]
    fn a_blocked_row_cannot_be_selected_and_says_why() {
        let mut state = state(vec![proposal(
            "b",
            "/proj",
            vec![Blocker::ToolMissing {
                program: "npm".into(),
            }],
        )]);
        state.toggle();
        assert!(state.selected_ids().is_empty());
        let text = row(&state, &state.proposals()[0], 60);
        let rendered = format!("{text:?}");
        assert!(rendered.contains("npm is not installed"), "{rendered}");
    }

    /// The one opt-in Husk offers clears exactly the blocker it names, and it
    /// is decided by the typed `overrides`, never by matching prose.
    #[test]
    fn the_pep_668_opt_in_makes_only_its_own_rows_runnable() {
        let mut state = state(vec![
            proposal("managed", "/proj", vec![Blocker::ExternallyManaged]),
            proposal(
                "missing",
                "/proj",
                vec![Blocker::ToolMissing {
                    program: "pip".into(),
                }],
            ),
        ]);
        assert!(state.selected_ids().is_empty());
        state.toggle_override();
        assert_eq!(state.selected_ids(), vec!["managed".to_string()]);
    }

    #[test]
    fn proposals_group_by_the_directory_the_fix_runs_in() {
        let state = state(vec![
            proposal("a", "/one", Vec::new()),
            proposal("b", "/two", Vec::new()),
            proposal("c", "/one", Vec::new()),
        ]);
        let rows = state.rows.as_ref().unwrap();
        assert_eq!(rows.sections.len(), 2);
        assert_eq!(rows.sections[0].0, "/one");
        assert_eq!(rows.sections[0].1.len(), 2);
        // The cursor walks proposals in section order, never group headers.
        assert_eq!(rows.flat.len(), 3);
    }

    /// The command box is the terminal's escape hatch, so the pane renders it
    /// whole rather than cutting it to the column.
    #[test]
    fn the_command_is_rendered_in_full() {
        let state = state(vec![proposal("a", "/proj", Vec::new())]);
        let preview = state.proposals()[0].preview.as_ref().unwrap();
        let command = preview.command.clone().unwrap();
        let lines = preview_lines(preview, 8, 80);
        let rendered: String = lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.to_string())
            .collect();
        assert!(rendered.contains(&command), "{rendered}");
        assert!(rendered.contains("+.env"), "the diff is shown too");
    }

    #[test]
    fn a_long_diff_elides_with_a_visible_marker() {
        let mut proposal = proposal("a", "/proj", Vec::new());
        let preview = proposal.preview.as_mut().unwrap();
        preview.diff[0].diff = (0..40).map(|n| format!("+line {n}\n")).collect();
        let rendered: String = preview_lines(preview, 8, 80)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.to_string())
            .collect();
        assert!(rendered.contains("32 more lines not shown"), "{rendered}");
        assert!(!rendered.contains("line 39"), "the tail is not rendered");
    }
}
