//! The Guide tab: the security checklist. Terminal mirror of the web Guide
//! view (`web/src/features/guide/Guide.tsx`), backed by the same
//! `crate::guide` JSON catalog the web API serves, so the two stay in
//! lockstep with zero duplicated content.
//!
//! Navigation-only: per-task done/dismiss state is read from the shared
//! `~/.husk/guide.json` store, so anything ticked off in the web UI is
//! reflected here.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use super::{ReportKey, fix, theme};
use crate::guide::{self, AssessedTask, Bucket, GuideStatus};
use crate::model::ScanReport;

/// The list filter, same slices as the web Guide's tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(super) enum Filter {
    #[default]
    Todo,
    Done,
    Dismissed,
    All,
}

impl Filter {
    fn next(self) -> Self {
        match self {
            Filter::Todo => Filter::Done,
            Filter::Done => Filter::Dismissed,
            Filter::Dismissed => Filter::All,
            Filter::All => Filter::Todo,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Filter::Todo => "To do",
            // Covers what husk verified as well as what the user marked done,
            // so it must not claim the user did all of it.
            Filter::Done => "Handled",
            Filter::Dismissed => "Ignored",
            Filter::All => "All",
        }
    }

    /// Which slice a task falls in, taken from the server-computed bucket so
    /// the rows in a tab and the number on that tab can never disagree.
    fn matches(self, bucket: Bucket) -> bool {
        match self {
            Filter::Todo => bucket == Bucket::Todo,
            Filter::Done => bucket == Bucket::Done,
            Filter::Dismissed => bucket == Bucket::Ignored,
            Filter::All => true,
        }
    }
}

/// How the task list is grouped: the same four views the web Guide offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(super) enum Grouping {
    /// Priority tiers: do next / when you get to it.
    #[default]
    Priority,
    /// The catalog's categories (Accounts, Device, Secrets…).
    Category,
    /// Effort buckets parsed from the estimates: quick wins / half-hour / projects.
    Effort,
    /// Progressive disclosure: only the top five next actions.
    Focus,
}

impl Grouping {
    fn next(self) -> Self {
        match self {
            Grouping::Priority => Grouping::Category,
            Grouping::Category => Grouping::Effort,
            Grouping::Effort => Grouping::Focus,
            Grouping::Focus => Grouping::Priority,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Grouping::Priority => "Priority",
            Grouping::Category => "Category",
            Grouping::Effort => "Effort",
            Grouping::Focus => "Focus",
        }
    }
}

/// `(category index, item index)` into `GuideReport::categories`: an owned
/// reference into the cached assessment, so the built view can persist across
/// frames without borrowing from itself.
type TaskIdx = (usize, usize);

/// The Guide tab's view-model: filter/grouping/selection plus the cached
/// assessment and the grouped list built from it. Mutated only in
/// [`State::prepare`] and the key handlers so [`draw`] can take it immutably.
#[derive(Default)]
pub(super) struct State {
    /// Selected row (index into the flattened task list).
    selected: usize,
    filter: Filter,
    grouping: Grouping,
    /// Selected option in the detail pane; `None` = the recommended one.
    opt: Option<usize>,
    /// Cached assessment + the grouped view built from it. The assessment is
    /// re-run only when the scan report changes (`assess` walks the whole
    /// catalog); the view is rebuilt only when the report, filter, or grouping
    /// changes, never per frame.
    cache: Option<Cache>,
    /// The selected task's fixes: what each would change, and the selection
    /// that applies several at once.
    pub(super) fix: fix::State,
}

struct Cache {
    key: ReportKey,
    report: guide::GuideReport,
    view: View,
}

/// The grouped, flattened task list for one `(filter, grouping)` pair.
struct View {
    filter: Filter,
    grouping: Grouping,
    /// Labeled sections in display order; items are indices into the report.
    sections: Vec<(String, Vec<TaskIdx>)>,
    /// The sections flattened, so selection indexes tasks rather than headers.
    flat: Vec<TaskIdx>,
}

impl State {
    /// Refresh the view-model: re-assess only when the scan report changes,
    /// rebuild the grouped view only when report/filter/grouping changed, then
    /// clamp row and option selection. All mutation happens here so [`draw`]
    /// can take an immutable app.
    pub(super) fn prepare(&mut self, scan_report: &ScanReport, body: Rect) {
        self.prepare_with(scan_report, body, guide::load_state);
    }

    /// [`State::prepare`] with an injectable user-state source, so tests can
    /// assess against a fixed state instead of the developer's real store.
    pub(super) fn prepare_with(
        &mut self,
        scan_report: &ScanReport,
        body: Rect,
        load_state: impl FnOnce() -> guide::UserState,
    ) {
        let key = super::report_key(scan_report);
        let report_stale = self.cache.as_ref().map(|c| c.key != key).unwrap_or(true);
        if report_stale {
            // The TUI shows one report at a time; machine-scoped items borrow
            // the stored machine posture when this report is a project scan.
            let machine = if scan_report.kind == crate::model::ScanKind::Machine {
                None
            } else {
                crate::cache::load_machine_report().ok().flatten()
            };
            let report = guide::assess(scan_report, machine.as_ref(), &load_state());
            let view = build_view(&report, self.filter, self.grouping);
            self.cache = Some(Cache { key, report, view });
        } else {
            let cache = self.cache.as_mut().expect("cache checked above");
            if cache.view.filter != self.filter || cache.view.grouping != self.grouping {
                cache.view = build_view(&cache.report, self.filter, self.grouping);
            }
        }

        let cache = self.cache.as_ref().expect("cache refreshed above");
        self.selected = self.selected.min(cache.view.flat.len().saturating_sub(1));

        let task = cache
            .view
            .flat
            .get(self.selected)
            .map(|&(cat, item)| &cache.report.categories[cat].items[item]);

        // Clamp the option selection into the selected task's options; when no
        // option was chosen yet, land on the recommended one.
        let (opt_len, opt_rec) = task
            .map(|task| {
                let rec = task.options.iter().position(|o| o.recommended).unwrap_or(0);
                (task.options.len(), rec)
            })
            .unwrap_or((0, 0));
        let opt_idx = self.opt.unwrap_or(opt_rec).min(opt_len.saturating_sub(1));
        self.opt = (opt_len > 0).then_some(opt_idx);

        self.fix.prepare(scan_report, key, task, body);
    }

    fn len(&self) -> usize {
        self.cache
            .as_ref()
            .map(|cache| cache.view.flat.len())
            .unwrap_or(0)
    }

    /// The `(category title, task)` pair at the selected row, if any.
    fn selected_task(&self) -> Option<(&str, &AssessedTask)> {
        let cache = self.cache.as_ref()?;
        let &(cat, item) = cache.view.flat.get(self.selected)?;
        let category = &cache.report.categories[cat];
        Some((category.title.as_str(), &category.items[item]))
    }

    pub(super) fn select_next(&mut self) {
        self.selected = (self.selected + 1).min(self.len().saturating_sub(1));
        self.opt = None;
    }

    pub(super) fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
        self.opt = None;
    }

    pub(super) fn select_home(&mut self) {
        self.selected = 0;
        self.opt = None;
    }

    pub(super) fn select_end(&mut self) {
        self.selected = self.len().saturating_sub(1);
        self.opt = None;
    }

    /// Cycle the list filter; resets the row/option selection into the new slice.
    pub(super) fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
        self.selected = 0;
        self.opt = None;
    }

    /// Cycle the grouping; resets the row/option selection.
    pub(super) fn cycle_grouping(&mut self) {
        self.grouping = self.grouping.next();
        self.selected = 0;
        self.opt = None;
    }

    /// Move the detail pane's option selection left/right (h/l).
    pub(super) fn opt_move(&mut self, delta: i64) {
        let opt_len = self
            .selected_task()
            .map(|(_, task)| task.options.len())
            .unwrap_or(0);
        if opt_len == 0 {
            return;
        }
        let max = opt_len - 1;
        let current = self.opt.unwrap_or(0).min(max) as i64;
        self.opt = Some((current + delta).clamp(0, max as i64) as usize);
    }
}

/// Partition the filtered, priority-sorted tasks into labeled sections for the
/// active grouping. Section order is fixed per grouping; items keep their
/// priority order within each section. Empty sections are dropped.
fn build_sections(
    report: &guide::GuideReport,
    flat: &[TaskIdx],
    grouping: Grouping,
) -> Vec<(String, Vec<TaskIdx>)> {
    let task = |&(cat, item): &TaskIdx| &report.categories[cat].items[item];
    let pick = |pred: &dyn Fn(&TaskIdx) -> bool| -> Vec<TaskIdx> {
        flat.iter().copied().filter(|idx| pred(idx)).collect()
    };
    let mut sections: Vec<(String, Vec<TaskIdx>)> = match grouping {
        Grouping::Priority => guide::TIERS
            .iter()
            .map(|(tier, label)| (label.to_string(), pick(&|idx| task(idx).tier == *tier)))
            .collect(),
        Grouping::Category => report
            .categories
            .iter()
            .enumerate()
            .map(|(cat, c)| (c.title.clone(), pick(&|&(tcat, _)| tcat == cat)))
            .collect(),
        Grouping::Effort => [
            ("quick", "Quick wins: under 15 min"),
            ("medium", "Half-hour jobs"),
            ("project", "Projects: an afternoon"),
        ]
        .iter()
        .map(|(bucket, label)| (label.to_string(), pick(&|idx| task(idx).effort == *bucket)))
        .collect(),
        Grouping::Focus => {
            let top: Vec<_> = flat.iter().copied().take(5).collect();
            vec![(format!("Next up: top {} of {}", top.len(), flat.len()), top)]
        }
    };
    sections.retain(|(_, items)| !items.is_empty());
    sections
}

/// Build the grouped view from the cached report. Like the web view, this
/// filters to the active tab's slice, sorts by server-computed priority, then
/// flattens the active grouping so selection indexes tasks rather than headers.
fn build_view(report: &guide::GuideReport, filter: Filter, grouping: Grouping) -> View {
    let mut flat: Vec<TaskIdx> = report
        .categories
        .iter()
        .enumerate()
        .flat_map(|(cat, category)| {
            category
                .items
                .iter()
                .enumerate()
                .filter(|(_, item)| filter.matches(item.bucket))
                .map(move |(item, _)| (cat, item))
        })
        .collect();
    flat.sort_by_key(|&(cat, item)| -report.categories[cat].items[item].priority);

    let sections = build_sections(report, &flat, grouping);
    let flat = sections
        .iter()
        .flat_map(|(_, items)| items.iter().copied())
        .collect();
    View {
        filter,
        grouping,
        sections,
        flat,
    }
}

pub(super) fn draw(frame: &mut Frame<'_>, app: &super::TuiApp, area: Rect) {
    // The fix pane takes the whole body: a diff and a shell command need the
    // width, and the checklist is one key away.
    if app.guide.fix.is_open() {
        fix::draw(frame, &app.guide.fix, area);
        return;
    }
    let cache = app.guide.cache.as_ref().expect("prepare runs before draw");
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    draw_list(frame, cache, app.guide.selected, cols[0]);
    draw_detail(
        frame,
        app.guide.selected_task(),
        app.guide.opt.unwrap_or(0),
        &app.guide.fix,
        cols[1],
    );
}

fn draw_list(frame: &mut Frame<'_>, cache: &Cache, selected: usize, area: Rect) {
    let report = &cache.report;
    let view = &cache.view;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    let pct = report.percent as usize;
    let bar_width = (rows[0].width as usize).saturating_sub(18).clamp(8, 40);

    let todo = report.todo;
    let count = |f: Filter| match f {
        Filter::Todo => todo,
        Filter::Done => report.done,
        Filter::Dismissed => report.ignored,
        Filter::All => report.total,
    };
    let mut tabs: Vec<Span> = vec![];
    for f in [Filter::Todo, Filter::Done, Filter::Dismissed, Filter::All] {
        if !tabs.is_empty() {
            // Tight enough that all four counts still fit the list column at an
            // 80-column terminal, where the pane is 46 wide.
            tabs.push(Span::styled(" · ", Style::default().fg(theme::FG_SUBTLE)));
        }
        let style = if f == view.filter {
            theme::accent().add_modifier(Modifier::BOLD)
        } else {
            theme::muted()
        };
        tabs.push(Span::styled(format!("{} {}", f.label(), count(f)), style));
    }
    tabs.push(Span::styled(
        "   group: ",
        Style::default().fg(theme::FG_SUBTLE),
    ));
    tabs.push(Span::styled(view.grouping.label(), theme::accent()));

    // This meter measures review, not security: an item counts once it has
    // been read and then verified, marked done, or ignored. Never label it as
    // a percentage secure.
    let header = vec![
        Line::from(Span::styled("Security checklist", theme::accent())),
        Line::from(Span::styled(
            format!(
                "Review progress: {}/{} handled",
                report.handled, report.total
            ),
            theme::muted(),
        )),
        Line::from(vec![
            Span::styled(super::progress_bar(pct, bar_width), theme::accent()),
            Span::styled(format!(" {pct}% reviewed"), theme::muted()),
        ]),
        Line::from(tabs),
    ];
    frame.render_widget(Paragraph::new(header), rows[0]);

    // Interleave section headers with the task rows. Selection indexes tasks
    // only, so map the selected task index to its rendered row.
    let width = rows[1].width.saturating_sub(2) as usize;
    let mut items: Vec<ListItem> = Vec::new();
    let mut selected_row = None;
    let mut task_idx = 0usize;
    for (label, tasks) in &view.sections {
        items.push(ListItem::new(Line::from(Span::styled(
            format!("▾ {}  ·  {}", label.to_uppercase(), tasks.len()),
            theme::label(),
        ))));
        for &(cat, item) in tasks {
            if task_idx == selected {
                selected_row = Some(items.len());
            }
            let category = &report.categories[cat];
            items.push(ListItem::new(row(
                &category.title,
                &category.items[item],
                width,
            )));
            task_idx += 1;
        }
    }
    let mut list_state = ListState::default();
    list_state.select(selected_row);
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER))
                .title(format!("Tasks · {todo} to do")),
        )
        .highlight_style(
            Style::default()
                .bg(theme::SELECTION_BG)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(list, rows[1], &mut list_state);
}

/// One task row, mirroring the web row: status marker, then title + category
/// in fixed-width columns.
fn row(category: &str, task: &AssessedTask, width: usize) -> Line<'static> {
    let (glyph, color) = marker(task.status);
    let text_width = width.saturating_sub(2).max(8);
    let cat_width = (text_width / 3).min(category.chars().count());
    let title_width = text_width.saturating_sub(cat_width + 1).max(8);
    let title_style = if matches!(task.status, GuideStatus::Verified | GuideStatus::Completed) {
        Style::default().fg(theme::FG_SUBTLE)
    } else {
        Style::default().fg(theme::FG)
    };
    Line::from(vec![
        Span::styled(format!("{glyph} "), Style::default().fg(color)),
        Span::styled(
            format!(
                "{:<title_width$}",
                crate::term::truncate_end(&task.title, title_width)
            ),
            title_style,
        ),
        Span::styled(
            format!(
                " {:<cat_width$}",
                crate::term::truncate_end(category, cat_width)
            ),
            Style::default().fg(theme::FG_SUBTLE),
        ),
    ])
}

fn marker(status: GuideStatus) -> (&'static str, Color) {
    match status {
        GuideStatus::Verified | GuideStatus::Completed => ("✓", theme::INFO),
        GuideStatus::ActionNeeded => ("!", theme::BUSY),
        GuideStatus::Recommended => ("○", theme::FG_SUBTLE),
        GuideStatus::Dismissed => ("-", theme::FG_SUBTLE),
        GuideStatus::Unknown => ("?", theme::FG_SUBTLE),
    }
}

fn draw_detail(
    frame: &mut Frame<'_>,
    selected: Option<(&str, &AssessedTask)>,
    opt_idx: usize,
    fix: &fix::State,
    area: Rect,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .title("How to")
        .padding(ratatui::widgets::Padding::new(1, 1, 0, 0));

    let Some((category, task)) = selected else {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Pick a task to see how to do it.",
                Style::default().fg(theme::FG_SUBTLE),
            ))
            .block(block),
            area,
        );
        return;
    };

    let mut lines = vec![
        Line::from(Span::styled(category.to_uppercase(), theme::label())),
        Line::from(Span::styled(task.title.clone(), theme::accent())),
    ];

    lines.push(Line::from(Span::styled(
        status_label(task.status).to_string(),
        Style::default().fg(marker(task.status).1),
    )));
    // Never let a manual guide read as an unfinished check: husk has no way to
    // observe it, so say so instead of implying a pending verification.
    if task.verification == guide::Verification::Manual {
        lines.push(Line::from(Span::styled(
            "husk can't check this, confirm it yourself".to_string(),
            Style::default().fg(theme::FG_SUBTLE),
        )));
    }
    lines.push(Line::from(""));

    // The lede, as in the web detail view. Capped at a fixed number of lines so
    // a long `why` cannot push the problem and the steps out of the pane.
    let why = wrapped(&task.why, area.width.saturating_sub(4).max(8) as usize, 3);
    if !why.is_empty() {
        for line in why {
            lines.push(Line::from(Span::styled(line, theme::muted())));
        }
        lines.push(Line::from(""));
    }

    if !task.problem.is_empty() {
        lines.push(Line::from(Span::styled(
            task.problem.clone(),
            Style::default().fg(theme::FG),
        )));
    }

    // The fix comes before the how-to, as in the web view: a task husk can act
    // on is the cheap win and must not be buried under the manual steps.
    lines.extend(fix.summary().unwrap_or_default());

    let selected_opt = task.options.get(opt_idx);
    if !task.options.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "OPTIONS  (h/l switch)",
            theme::label(),
        )));
        for (i, opt) in task.options.iter().enumerate() {
            let active = i == opt_idx;
            let mark = if active { "▸ " } else { "  " };
            let name_style = if active {
                theme::accent().add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::FG)
            };
            let mut spans = vec![
                Span::styled(mark, theme::accent()),
                Span::styled(opt.name.clone(), name_style),
            ];
            if opt.recommended {
                spans.push(Span::styled(
                    "  recommended",
                    Style::default().fg(theme::INFO),
                ));
            }
            lines.push(Line::from(spans));
            lines.push(Line::from(Span::styled(
                format!("    {}", opt.note),
                theme::muted(),
            )));
        }
    }

    // Steps for the chosen option, same fallback chain as the web: an option's
    // own steps if authored; the task-level steps for the recommended option
    // (whose steps they are); never another option's steps.
    let steps: &[guide::Step] = match selected_opt {
        None => &task.steps,
        Some(opt) if !opt.steps.is_empty() => &opt.steps,
        Some(opt) if opt.recommended => &task.steps,
        Some(_) => &[],
    };
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("STEPS", theme::label())));
    if steps.is_empty() {
        let name = selected_opt.map(|o| o.name.as_str()).unwrap_or_default();
        lines.push(Line::from(Span::styled(
            format!("Husk doesn't have step-by-step instructions for {name} yet."),
            theme::muted(),
        )));
        if let Some(url) = selected_opt.and_then(|o| o.url.clone()) {
            lines.push(Line::from(Span::styled(
                format!("Follow its own setup guide: {url}"),
                Style::default().fg(theme::FG_SUBTLE),
            )));
        }
    }
    for (i, step) in steps.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(
                format!("{}. ", i + 1),
                Style::default().fg(theme::FG_SUBTLE),
            ),
            Span::styled(step.text.clone(), Style::default().fg(theme::FG)),
        ]));
        if let Some(cmd) = &step.command {
            lines.push(Line::from(Span::styled(
                format!("   $ {cmd}"),
                theme::muted(),
            )));
        }
    }

    if !task.sources.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("SOURCES", theme::label())));
        for src in &task.sources {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{}: ", src.title),
                    Style::default().fg(theme::FG_SUBTLE),
                ),
                Span::styled(src.url.clone(), theme::muted()),
            ]));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Word-wrap `text` to `width` columns, at most `max` lines, ellipsizing the
/// last line when the text does not fit. The caller gets a block whose height
/// never depends on the content, which is what keeps a long lede from moving
/// everything below it.
fn wrapped(text: &str, width: usize, max: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current = word.to_string();
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.len() > max {
        let overflow = lines.split_off(max.saturating_sub(1)).join(" ");
        lines.push(crate::term::truncate_end(&overflow, width));
    }
    for line in &mut lines {
        *line = crate::term::truncate_end(line, width);
    }
    lines
}

fn status_label(status: GuideStatus) -> &'static str {
    match status {
        GuideStatus::Verified => "verified by husk, nothing to do",
        GuideStatus::Completed => "you marked this done",
        GuideStatus::ActionNeeded => "action needed",
        GuideStatus::Recommended => "recommended",
        GuideStatus::Dismissed => "ignored",
        GuideStatus::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every task lands in exactly one of the three tabs, so the tab counts
    /// (taken straight from the report's bucket totals) describe the rows the
    /// tab actually shows.
    #[test]
    fn every_bucket_belongs_to_exactly_one_tab() {
        for bucket in [Bucket::Todo, Bucket::Done, Bucket::Ignored] {
            let tabs = [Filter::Todo, Filter::Done, Filter::Dismissed]
                .into_iter()
                .filter(|filter| filter.matches(bucket))
                .count();
            assert_eq!(tabs, 1, "{bucket:?} must appear in exactly one tab");
            assert!(Filter::All.matches(bucket));
        }
    }

    #[test]
    fn filter_and_grouping_cycles_visit_every_variant() {
        assert_eq!(
            Filter::default().next().next().next().next(),
            Filter::default()
        );
        assert_eq!(
            Grouping::default().next().next().next().next(),
            Grouping::default()
        );
    }

    /// The AGENTS.md fixed-size rule for the Guide row: the rendered row width
    /// must not change with title/category content.
    #[test]
    fn row_width_is_constant_across_content() {
        let task = |title: &str, status: GuideStatus| AssessedTask {
            status,
            title: title.to_string(),
            ..sample_task()
        };
        let width = 72;
        let render_width = |t: &AssessedTask, category: &str| -> usize {
            row(category, t, width)
                .spans
                .iter()
                .map(|span| span.content.chars().count())
                .sum()
        };
        let base = render_width(&task("Short", GuideStatus::Recommended), "Device");
        for (t, cat) in [
            (
                task(
                    "A very long task title that will definitely be truncated by the row",
                    GuideStatus::Recommended,
                ),
                "Device",
            ),
            (task("Done item", GuideStatus::Verified), "Device"),
            (task("Ignored item", GuideStatus::Dismissed), "Device"),
        ] {
            assert_eq!(render_width(&t, cat), base, "row width shifted");
        }
    }

    /// The AGENTS.md fixed-size rule for the detail pane's lede: however long
    /// the guide's `why` is, it occupies the same bounded block.
    #[test]
    fn the_lede_stays_inside_a_bounded_block() {
        let long = "Without a lockfile every install resolves floating ranges to \
                    whatever was published minutes ago, which is how a sabotaged \
                    release reaches a machine that never asked for it, on a tree \
                    nobody reviewed."
            .to_string();
        for width in [12usize, 29, 40, 120] {
            for text in ["", "Short one.", long.as_str()] {
                let lines = wrapped(text, width, 3);
                assert!(lines.len() <= 3, "lede grew to {} lines", lines.len());
                for line in &lines {
                    assert!(line.chars().count() <= width, "lede line overflowed");
                }
            }
        }
        assert!(wrapped("", 40, 3).is_empty());
        assert!(
            wrapped(&long, 29, 3)[2].ends_with('…'),
            "a lede that does not fit must say so"
        );
    }

    fn sample_task() -> AssessedTask {
        AssessedTask {
            id: "t".to_string(),
            category: "Device".to_string(),
            kind: guide::GuideKind::Baseline,
            verification: guide::Verification::Automatic,
            scope: guide::Scope::Machine,
            severity: crate::model::Severity::Low,
            title: String::new(),
            why: String::new(),
            problem: String::new(),
            estimate: String::new(),
            steps: vec![],
            options: vec![],
            sources: vec![],
            solution: guide::Solution {
                name: String::new(),
                url: String::new(),
                husk: false,
            },
            status: GuideStatus::Recommended,
            control_status: Some(guide::control::ControlStatus::Unknown),
            read: false,
            handled: false,
            priority: 0,
            bucket: Bucket::Todo,
            tier: guide::Tier::Later,
            effort: "quick".to_string(),
            evidence: vec![],
            finding_ids: vec![],
            remediation_ids: vec![],
            decision: None,
            reason: None,
        }
    }
}
