//! The Scan tab: the dense findings workspace (progress + system context
//! across the top, the findings table as the primary surface bottom-left, the
//! selected-finding detail bottom-right), plus the [`State`] view-model that
//! backs it (cached rows, scrolling, selection, the one-key dependency fix).
//!
//! The report arrives score-ordered; this module applies the same top-level
//! project-vs-config split as the web Scan view, then keeps KEV and severity
//! ordering within each domain.

use crate::model::{Finding, LiveScan, ProgressState, ScanReport, Severity};
use crate::term::{truncate_end, truncate_middle};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use std::collections::HashMap;

use super::{ReportKey, TuiApp, detail_field, detail_section, fix, report_key, theme};

/// The Scan tab's fixed grid: a 75/25 horizontal split, each column stacked as
/// a fixed-height top panel over the flexible main panel. Shared by
/// [`State::prepare`] (which needs the list geometry before rendering) and
/// [`draw`].
struct ScanLayout {
    progress: Rect,
    findings: Rect,
    context: Rect,
    detail: Rect,
}

fn layout(area: Rect) -> ScanLayout {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(75), Constraint::Percentage(25)])
        .split(area);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(10)])
        .split(columns[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(10)])
        .split(columns[1]);
    ScanLayout {
        progress: left[0],
        findings: left[1],
        context: right[0],
        detail: right[1],
    }
}

/// The Scan tab's view-model: the cached findings table, its
/// scrolling/selection, the dependency-fix plan for the selected finding, and
/// the one-key fix state. Mutated only in [`State::prepare`] and the key
/// handlers so [`draw`] can take it immutably.
pub(super) struct State {
    selected: usize,
    scroll: usize,
    /// Cached rows (rebuilt when the report or width changes).
    view: CachedFindings,
    /// Dependency-fix plan for the selected finding, computed in `prepare` so
    /// `draw` never touches the filesystem (planning probes `PATH`).
    fix_plan: Option<FixPlan>,
    /// One-key dependency fix (`u`) state: idle, the running command, or the
    /// finished outcome, keyed by the planned fix id it belongs to.
    dep_fix: DepFix,
    /// One-line scan-history rollup for the header (None until two scans of
    /// these roots exist). Cached per report so `draw` never reads disk.
    trend: Option<String>,
}

/// The cached `dependency_fix` plan for one `(report, selected)` pair.
struct FixPlan {
    key: (ReportKey, usize),
    plan: Option<crate::remediation::RemediationProposal>,
}

/// State of the Scan tab's one-key dependency upgrade/downgrade.
enum DepFix {
    Idle,
    Running {
        id: String,
        rx: std::sync::mpsc::Receiver<crate::remediation::ActionResult>,
    },
    Done {
        id: String,
        ok: bool,
        message: String,
    },
}

impl State {
    pub(super) fn new(report: &ScanReport) -> Self {
        Self {
            selected: 0,
            scroll: 0,
            view: CachedFindings::new(report, 100),
            fix_plan: None,
            dep_fix: DepFix::Idle,
            trend: history_trend(report),
        }
    }

    /// Refresh the view-model against the current body size: rebuild the
    /// cached rows when the width changed, clamp scroll so the selection stays
    /// visible, and re-plan the selected finding's dependency fix. All
    /// mutation happens here so [`draw`] can take an immutable app.
    pub(super) fn prepare(&mut self, live: &LiveScan, body: Rect) {
        let grid = layout(body);
        let list_width = grid.findings.width.saturating_sub(4) as usize;
        let body_height = grid.findings.height.saturating_sub(2) as usize;
        self.ensure_view_width(&live.report, list_width);
        self.ensure_selected_visible(body_height);
        self.refresh_fix_plan(&live.report);
    }

    /// Rebuild the cached rows after a live-scan refresh delivered a new
    /// report, and clamp the selection into the new row set.
    pub(super) fn update_report(&mut self, report: &ScanReport) {
        if self.view.key != report_key(report) {
            self.view = CachedFindings::new(report, self.view.width);
            self.trend = history_trend(report);
        }
        self.clamp_selection();
    }

    fn ensure_view_width(&mut self, report: &ScanReport, width: usize) {
        if self.view.width != width {
            self.view = CachedFindings::new(report, width);
            self.clamp_selection();
        }
    }

    fn clamp_selection(&mut self) {
        self.selected = self.selected.min(self.view.rows.len().saturating_sub(1));
        self.scroll = self.scroll.min(self.selected);
    }

    pub(super) fn move_down(&mut self) {
        self.selected = (self.selected + 1).min(self.view.rows.len().saturating_sub(1));
    }

    pub(super) fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub(super) fn select_home(&mut self) {
        self.selected = 0;
        self.scroll = 0;
    }

    pub(super) fn select_end(&mut self) {
        self.selected = self.view.rows.len().saturating_sub(1);
    }

    fn ensure_selected_visible(&mut self, body_height: usize) {
        let finding_rows = self.finding_window_height(body_height);
        if finding_rows == 0 {
            self.scroll = self.selected;
            return;
        }
        if self.selected < self.scroll {
            self.scroll = self.selected;
        }
        if self.selected >= self.scroll + finding_rows {
            self.scroll = self.selected + 1 - finding_rows;
        }
    }

    /// Non-selectable rows that prefix the findings window: the per-project
    /// posture summary, the Resolved and Ignored summaries, and the column
    /// header.
    fn prefix_len(&self) -> usize {
        self.view.projects.len() + self.view.resolved.len() + self.view.ignored.len() + 1
    }

    fn finding_window_height(&self, body_height: usize) -> usize {
        body_height.saturating_sub(self.prefix_len()).max(1)
    }

    fn visible_items(&self, body_height: usize) -> Vec<ListItem<'static>> {
        let finding_rows = self.finding_window_height(body_height);
        let start = self.scroll.min(self.view.rows.len());
        let end = (start + finding_rows).min(self.view.rows.len());
        let mut items = Vec::with_capacity(self.prefix_len() + end.saturating_sub(start));
        items.extend(self.view.projects.iter().cloned());
        items.extend(self.view.resolved.iter().cloned());
        items.extend(self.view.ignored.iter().cloned());
        items.push(ListItem::new(self.view.header.clone()));
        items.extend(self.view.rows[start..end].iter().map(FindingRow::list_item));
        items
    }

    fn local_selected_index(&self) -> usize {
        self.prefix_len() + self.selected.saturating_sub(self.scroll)
    }

    pub(super) fn selected_finding<'r>(&self, report: &'r ScanReport) -> Option<&'r Finding> {
        self.view
            .rows
            .get(self.selected)
            .and_then(|row| report.findings.get(row.finding_index))
    }

    /// Look up the selected finding's proposal when the report or the selection
    /// changed; otherwise keep the cached one (the lookup walks the report, so
    /// it must not run per frame).
    ///
    /// The proposal comes from the report's own plan rather than being
    /// re-derived here, so the TUI cannot disagree with the CLI or the web
    /// about a package two advisories both name.
    fn refresh_fix_plan(&mut self, report: &ScanReport) {
        let key = (self.view.key, self.selected);
        if self.fix_plan.as_ref().is_some_and(|cache| cache.key == key) {
            return;
        }
        let plan = self.selected_finding(report).and_then(|finding| {
            crate::remediation::plan(report)
                .for_finding(&finding.id)
                .find(|proposal| {
                    matches!(
                        proposal.action,
                        crate::remediation::RemediationOperation::DependencyUpdate { .. }
                    )
                })
                .cloned()
        });
        self.fix_plan = Some(FixPlan { key, plan });
    }

    fn fix_plan(&self) -> Option<&crate::remediation::RemediationProposal> {
        self.fix_plan.as_ref().and_then(|cache| cache.plan.as_ref())
    }

    /// Whether a dependency fix is actively running on its worker thread,
    /// used to gate the event loop's fast poll interval (only `Running` needs
    /// the 16ms wakeup; `Done` can settle back to the slow idle poll).
    pub(super) fn dep_fix_running(&self) -> bool {
        matches!(self.dep_fix, DepFix::Running { .. })
    }

    /// `u`: run the selected finding's dependency upgrade/downgrade (when the
    /// advisory names a safe version) on a worker thread; package managers
    /// can take a while and must not freeze the UI.
    pub(super) fn start_dep_fix(&mut self, report: &ScanReport, force: bool) {
        if matches!(self.dep_fix, DepFix::Running { .. }) {
            return;
        }
        let Some(finding) = self.selected_finding(report) else {
            return;
        };
        let finding_id = finding.id.clone();
        // Events can arrive in a burst (j then u before a redraw), so refresh
        // the plan for the *current* selection rather than trusting the cache.
        self.refresh_fix_plan(report);
        let Some(planned) = self.fix_plan().cloned() else {
            return;
        };
        let planned = if force {
            crate::remediation::with_break_system_packages(planned)
        } else {
            planned
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let id = planned.id.clone();
        let generated_at = report.generated_at;
        let failed_id = id.clone();
        std::thread::spawn(move || {
            // The same executor the CLI and web use, so every surface shares one
            // lock, one backup snapshot, and one rollback point.
            let mut options = crate::remediation::ApplyOptions::new(false);
            options.only = Some(planned.id.clone());
            options.deps = true;
            let plan = crate::remediation::RemediationPlan {
                generated_at,
                proposals: vec![planned],
            };
            let result = match crate::remediation::apply(&plan, &options) {
                Ok(outcome) => outcome.results.into_iter().next(),
                Err(error) => Some(crate::remediation::ActionResult {
                    id: failed_id,
                    status: crate::remediation::ActionStatus::Failed,
                    detail: format!("{error:#}"),
                    output: None,
                }),
            };
            let Some(result) = result else {
                return;
            };
            if result.status == crate::remediation::ActionStatus::Applied {
                // Mirror the web button: remediations compound on the ledger.
                let _ = crate::ledger::append(
                    "dependency.update",
                    &finding_id,
                    Some(result.detail.as_str()),
                    None,
                );
            }
            let _ = tx.send(result);
        });
        self.dep_fix = DepFix::Running { id, rx };
    }

    /// Collect a finished dependency-fix result, if one arrived. Returns true
    /// when the state changed (so the caller redraws).
    pub(super) fn poll_dep_fix(&mut self) -> bool {
        if let DepFix::Running { id, rx } = &self.dep_fix
            && let Ok(result) = rx.try_recv()
        {
            self.dep_fix = DepFix::Done {
                id: id.clone(),
                ok: result.status == crate::remediation::ActionStatus::Applied,
                message: result.detail,
            };
            return true;
        }
        false
    }
}

/// The header's all-time trend rollup: posture movement, scans, resolved, and
/// husk-applied fixes; `None` until two scans of these roots exist (one point
/// is not a trend). Mirrors the web Scan-history tab's headline.
fn history_trend(report: &ScanReport) -> Option<String> {
    let entries = crate::history::load(&report.roots);
    if entries.len() < 2 {
        return None;
    }
    let (first, last) = (&entries[0], &entries[entries.len() - 1]);
    let resolved: usize = entries.iter().map(|e| e.resolved_count).sum();
    let fixes: usize = entries.iter().map(|e| e.fixes_applied).sum();
    let mut line = format!(
        "  {}→{}/100 over {} scans",
        first.score,
        last.score,
        entries.len()
    );
    if resolved > 0 {
        line.push_str(&format!(" · {resolved} resolved"));
    }
    if fixes > 0 {
        line.push_str(&format!(" · {fixes} husk fixes"));
    }
    Some(line)
}

pub(super) fn draw(frame: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let grid = layout(area);
    let body_height = grid.findings.height.saturating_sub(2) as usize;

    let live = &app.live;
    let report = &live.report;
    let spinner = spinner(live.running);
    let percent = progress_percent(live);
    let progress_width = grid.progress.width.saturating_sub(4) as usize;
    let context_width = grid.context.width.saturating_sub(4) as usize;

    let context = context_lines(report, context_width);
    frame.render_widget(
        Paragraph::new(context)
            .block(
                Block::default()
                    .title("System Context")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        grid.context,
    );

    let running_accent = if live.running { theme::BUSY } else { theme::OK };
    let mut brand_line = vec![
        Span::raw("scanned  "),
        Span::styled(
            format!("{} packages", report.stats.packages),
            Style::default().fg(theme::IDENT),
        ),
    ];
    if let Some(delta) = &report.delta {
        if delta.resolved_count > 0 {
            brand_line.push(Span::styled(
                format!("  ✓{} resolved", delta.resolved_count),
                Style::default().fg(theme::OK),
            ));
        }
        if delta.new_count > 0 {
            brand_line.push(Span::styled(
                format!("  +{} new", delta.new_count),
                Style::default().fg(theme::BUSY),
            ));
        }
    }
    if let Some(trend) = &app.scan.trend {
        brand_line.push(Span::styled(
            trend.clone(),
            Style::default().fg(theme::IDENT),
        ));
    }
    let header = vec![
        Line::from(brand_line),
        Line::from(vec![
            stat("C", report.stats.critical, Severity::Critical),
            Span::raw("  "),
            stat("H", report.stats.high, Severity::High),
            Span::raw("  "),
            stat("M", report.stats.medium, Severity::Medium),
            Span::raw("  "),
            stat("L", report.stats.low, Severity::Low),
            Span::raw("  "),
            stat("I", report.stats.info, Severity::Info),
        ]),
        Line::from(vec![
            Span::styled(
                if live.running {
                    format!("{spinner} scanning")
                } else {
                    "complete".to_string()
                },
                Style::default()
                    .fg(running_accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {}",
                truncate_middle(&live.current_task, progress_width.saturating_sub(14))
            )),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:>3}% ", percent),
                Style::default()
                    .fg(theme::IDENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                super::progress_bar(percent, progress_width.saturating_sub(7).clamp(8, 32)),
                Style::default().fg(running_accent),
            ),
        ]),
        compact_progress_line(live, progress_width),
    ];
    frame.render_widget(
        Paragraph::new(header)
            .block(Block::default().title("Progress").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        grid.progress,
    );

    let items = if app.scan.view.rows.is_empty() {
        // Clean list: keep the Resolved and Ignored blocks visible (fixing
        // everything is exactly when they matter, and the web surface shows
        // Ignored unconditionally) and state the coverage, not just absence.
        let mut items = app.scan.view.resolved.clone();
        items.extend(app.scan.view.ignored.iter().cloned());
        items.push(ListItem::new(if live.running {
            "No findings yet; scanning...".to_string()
        } else {
            let files: usize = report.benchmarks.iter().map(|b| b.files_checked).sum();
            format!(
                "No issues found. Scanned {files} files and {} packages",
                report.stats.packages
            )
        }));
        items
    } else {
        app.scan.visible_items(body_height)
    };
    let mut state = ListState::default();
    if !app.scan.view.rows.is_empty() {
        state.select(Some(app.scan.local_selected_index()));
    }
    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(
                    "Open issues {} · C{} H{}",
                    report.stats.findings, report.stats.critical, report.stats.high
                ))
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .bg(theme::SCAN_SELECTION_BG)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(list, grid.findings, &mut state);

    let detail = app
        .scan
        .selected_finding(report)
        .map(|finding| {
            detail_lines(
                report,
                finding,
                app.scan.fix_plan(),
                &app.scan.dep_fix,
                grid.detail.width.saturating_sub(2) as usize,
            )
        })
        .unwrap_or_else(|| {
            vec![Line::from(if live.running {
                "No findings yet. Husk is still scanning and will update this list as results arrive."
            } else {
                "No vulnerabilities, secrets, risky automation, extension, or AI config issues were found in the scanned paths."
            })]
        });
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::default().title("Details").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        grid.detail,
    );
}

pub(super) struct CachedFindings {
    key: ReportKey,
    width: usize,
    header: Line<'static>,
    projects: Vec<ListItem<'static>>,
    resolved: Vec<ListItem<'static>>,
    ignored: Vec<ListItem<'static>>,
    rows: Vec<FindingRow>,
}

impl CachedFindings {
    fn new(report: &ScanReport, width: usize) -> Self {
        let indices = sorted_display_indices(report);
        let roots: HashMap<&crate::model::ProjectId, &std::path::Path> = report
            .projects
            .iter()
            .map(|project| (&project.id, project.root.as_path()))
            .collect();
        // "project/subfolder": the same label the web Scan view's folder
        // dividers show, folded into this column since the TUI table has no
        // room for a separate per-block header row.
        let owner_labels: Vec<String> = indices
            .iter()
            .map(|&index| owner_label(report, &report.findings[index], &roots))
            .collect();
        let severity_width = 8usize;
        let owner_width = measured_column_width(owner_labels.iter().map(String::as_str), 8, 32);
        let category_width = measured_column_width(
            indices
                .iter()
                .map(|index| report.findings[*index].category.id()),
            8,
            14,
        );
        let fixed_columns = severity_width + owner_width + category_width + 5;
        let remaining = width.saturating_sub(fixed_columns);
        let title_width = remaining
            .saturating_mul(42)
            .checked_div(100)
            .unwrap_or(0)
            .clamp(18, 64);
        let path_width = remaining.saturating_sub(title_width).max(10);

        let rows = indices
            .into_iter()
            .zip(owner_labels)
            .map(|(finding_index, owner)| {
                FindingRow::new(
                    finding_index,
                    &report.findings[finding_index],
                    &owner,
                    severity_width,
                    owner_width,
                    category_width,
                    title_width,
                    path_width,
                )
            })
            .collect();

        Self {
            key: report_key(report),
            width,
            header: list_header(
                severity_width,
                owner_width,
                category_width,
                title_width,
                path_width,
            ),
            projects: project_summary_items(&report.projects, width),
            resolved: report
                .delta
                .as_ref()
                .map(|delta| {
                    status_summary_items(
                        "Resolved since last scan",
                        &delta.resolved,
                        theme::OK,
                        width,
                    )
                })
                .unwrap_or_default(),
            ignored: status_summary_items("Ignored", &report.ignored, theme::FG_SUBTLE, width),
            rows,
        }
    }
}

struct FindingRow {
    finding_index: usize,
    severity: Severity,
    line: Line<'static>,
}

impl FindingRow {
    #[allow(clippy::too_many_arguments)]
    fn new(
        finding_index: usize,
        finding: &Finding,
        owner: &str,
        severity_width: usize,
        owner_width: usize,
        category_width: usize,
        title_width: usize,
        path_width: usize,
    ) -> Self {
        let location = finding_location(finding);
        let line = Line::from(vec![
            Span::styled(
                format!(
                    "{:<width$}",
                    finding.severity.label(),
                    width = severity_width
                ),
                Style::default()
                    .fg(theme::severity(finding.severity))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                format!(
                    "{:<width$}",
                    truncate_end(owner, owner_width),
                    width = owner_width
                ),
                Style::default().fg(theme::IDENT),
            ),
            Span::raw(" "),
            Span::styled(
                format!(
                    "{:<width$}",
                    truncate_end(finding.category.id(), category_width),
                    width = category_width
                ),
                Style::default().fg(theme::FG_MUTED),
            ),
            Span::raw(" "),
            Span::raw(format!(
                "{:<width$}",
                truncate_end(&finding.title, title_width),
                width = title_width
            )),
            Span::raw(" "),
            Span::raw(truncate_middle(&location, path_width)),
        ]);
        Self {
            finding_index,
            severity: finding.severity,
            line,
        }
    }

    fn list_item(&self) -> ListItem<'static> {
        ListItem::new(self.line.clone()).style(Style::default().fg(theme::severity(self.severity)))
    }
}

fn context_lines(report: &ScanReport, width: usize) -> Vec<Line<'static>> {
    let distro = report
        .context
        .distro
        .clone()
        .unwrap_or_else(|| report.context.os.clone());
    let kernel = report
        .context
        .kernel
        .as_deref()
        .map(|kernel| format!("{kernel} · {}", report.context.arch))
        .unwrap_or_else(|| report.context.arch.clone());
    let visible_configs = report
        .context
        .dev_configs
        .iter()
        .filter(|config| config.present)
        .count();
    let welcome = format!("Welcome, {}", super::display_user(&report.context));
    vec![
        Line::from(vec![
            Span::styled("Husk", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(
                truncate_middle(&welcome, width.saturating_sub(6)),
                Style::default()
                    .fg(theme::IDENT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        context_field("os", distro, theme::OK, width),
        context_field("kernel", kernel, theme::LINK, width),
        context_field("git", super::git_identity(report), theme::BUSY, width),
        context_field(
            "tools",
            super::compact_list(&report.context.package_managers, 7),
            theme::TOOLS,
            width,
        ),
        context_field(
            "configs",
            format!("{visible_configs} visible"),
            theme::CONFIGS,
            width,
        ),
        context_field("scan", roots_text(report), theme::IDENT, width),
    ]
}

fn context_field(label: &'static str, value: String, color: Color, width: usize) -> Line<'static> {
    const LABEL_WIDTH: usize = 7;
    super::field_line(
        label,
        LABEL_WIDTH,
        Span::styled(
            truncate_middle(&value, width.saturating_sub(LABEL_WIDTH)),
            Style::default().fg(color),
        ),
    )
}

fn roots_text(report: &ScanReport) -> String {
    report
        .roots
        .iter()
        .map(|root| root.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn finding_location(finding: &Finding) -> String {
    finding
        .path
        .as_ref()
        .map(|path| {
            finding
                .line
                .map(|line| format!("{}:{line}", path.display()))
                .unwrap_or_else(|| path.display().to_string())
        })
        .or_else(|| finding.package.as_ref().map(|package| package.key()))
        .unwrap_or_else(|| "-".to_string())
}

/// The project-posture summary that prefixes the findings list: the same data
/// the web Scan view leads with (projects needing attention + per-project
/// category rollup + activity), presented as a top summary (a per-surface
/// affordance the parity rule allows).
fn project_summary_items(
    projects: &[crate::model::Project],
    width: usize,
) -> Vec<ListItem<'static>> {
    use crate::model::ProjectBucket;
    let needs: Vec<&crate::model::Project> = projects
        .iter()
        .filter(|p| {
            p.posture
                .as_ref()
                .map(|po| po.bucket == ProjectBucket::NeedsAttention)
                .unwrap_or(false)
        })
        .collect();
    if projects.is_empty() {
        return Vec::new();
    }
    let dormant = projects.len().saturating_sub(needs.len());
    let mut items = vec![ListItem::new(Line::from(Span::styled(
        format!("Projects needing attention ({})", needs.len()),
        Style::default()
            .fg(theme::IDENT)
            .add_modifier(Modifier::BOLD),
    )))];
    let name_width = width.saturating_sub(40).clamp(8, 28);
    for p in needs.iter().take(6) {
        let mut spans = vec![
            Span::styled(
                format!(
                    "{:<width$}",
                    truncate_end(&p.name, name_width),
                    width = name_width
                ),
                Style::default().fg(theme::IDENT),
            ),
            Span::raw(" "),
            Span::styled(
                format!("{:<9} ", p.activity.label()),
                Style::default().fg(theme::activity(p.activity)),
            ),
        ];
        for c in p.rollup.by_category.iter().take(3) {
            let color = if c.act_count > 0 {
                theme::severity(c.worst_severity)
            } else {
                theme::FG_SUBTLE
            };
            spans.push(Span::styled(
                format!("{} {} ", c.subjects, c.category.label()),
                Style::default().fg(color),
            ));
        }
        items.push(ListItem::new(Line::from(spans)));
    }
    if needs.len() > 6 {
        items.push(ListItem::new(Line::from(Span::styled(
            format!("+{} more needing attention", needs.len() - 6),
            Style::default().fg(theme::FG_SUBTLE),
        ))));
    }
    if dormant > 0 {
        items.push(ListItem::new(Line::from(Span::styled(
            format!("+{dormant} dormant (ambient info only)"),
            Style::default().fg(theme::FG_SUBTLE),
        ))));
    }
    items.push(ListItem::new(Line::from("")));
    items
}

/// A capped, dimmed summary block for the Ignored finding group:
/// non-selectable prefix rows, same fixed-size pattern as the project summary
/// (take a few, then "+N more"), so a long list can never grow the panel.
fn status_summary_items(
    label: &str,
    findings: &[Finding],
    accent: Color,
    width: usize,
) -> Vec<ListItem<'static>> {
    if findings.is_empty() {
        return Vec::new();
    }
    let mut items = vec![ListItem::new(Line::from(Span::styled(
        format!("{label} ({})", findings.len()),
        Style::default().fg(accent).add_modifier(Modifier::BOLD),
    )))];
    let title_width = width.saturating_sub(20).clamp(8, 48);
    for finding in findings.iter().take(4) {
        items.push(ListItem::new(Line::from(vec![
            Span::styled(
                format!("{:<8}", finding.severity.label()),
                Style::default().fg(theme::FG_SUBTLE),
            ),
            Span::styled(
                truncate_end(&finding.title, title_width),
                Style::default().fg(theme::FG_SUBTLE),
            ),
        ])));
    }
    if findings.len() > 4 {
        items.push(ListItem::new(Line::from(Span::styled(
            format!("+{} more", findings.len() - 4),
            Style::default().fg(theme::FG_SUBTLE),
        ))));
    }
    items.push(ListItem::new(Line::from("")));
    items
}

/// Display order for the findings table: two top-level domains (scanned
/// project findings first, then the synthetic "System & user config" project;
/// completely different kinds of work, never interleaved), each a flat
/// severity-sorted list (KEV first, then critical → high → …), never split
/// per project. Matches the web Scan list's sectioning. The stable sort keeps
/// `crate::score`'s worst-first order within each severity.
fn sorted_display_indices(report: &ScanReport) -> Vec<usize> {
    let config_ids: std::collections::HashSet<&crate::model::ProjectId> = report
        .projects
        .iter()
        .filter(|p| p.kind == crate::model::ProjectKind::ConfigLocation)
        .map(|p| &p.id)
        .collect();
    let mut indices: Vec<usize> = (0..report.findings.len()).collect();
    indices.sort_by(|&a, &b| {
        let fa = &report.findings[a];
        let fb = &report.findings[b];
        // Unowned findings fall back to the config domain, mirroring
        // `crate::project::apply_projects`' attachment fallback.
        let config = |f: &Finding| {
            f.project_id
                .as_ref()
                .map(|id| config_ids.contains(id))
                .unwrap_or(true)
        };
        let kev = |f: &Finding| f.exploit.as_ref().map(|e| e.kev).unwrap_or(false);
        config(fa)
            .cmp(&config(fb))
            .then_with(|| kev(fb).cmp(&kev(fa)))
            .then_with(|| fb.severity.cmp(&fa.severity))
    });
    indices
}

/// The subfolder a finding lives in, relative to its project root: the file's
/// directory capped at two path segments, the same rule the web Scan view
/// uses to cluster and label rows ([`src/features/scan/Scan.tsx`]'s
/// `subfolderOf`). Empty for root-level findings, unowned findings, or a path
/// that doesn't sit under the project root.
fn finding_folder(
    finding: &Finding,
    roots: &HashMap<&crate::model::ProjectId, &std::path::Path>,
) -> String {
    let Some(root) = finding.project_id.as_ref().and_then(|id| roots.get(id)) else {
        return String::new();
    };
    let path = finding
        .path
        .as_deref()
        .or_else(|| finding.package.as_ref().map(|p| p.manifest_path.as_path()));
    let Some(path) = path else {
        return String::new();
    };
    let Ok(rel) = path.strip_prefix(root) else {
        return String::new();
    };
    rel.parent()
        .into_iter()
        .flat_map(|dir| dir.components())
        .take(2)
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// The display name of the project a finding belongs to, via the
/// `Finding.project_id` → `report.projects` join (the same join the web Scan
/// view renders). "system" for findings with no known project.
fn finding_owner<'a>(report: &'a ScanReport, finding: &Finding) -> &'a str {
    report
        .project_of(finding)
        .map(|p| p.name.as_str())
        .unwrap_or("system")
}

/// "project/subfolder" (or just "project" at the project root): the label
/// the findings table's project column renders.
fn owner_label(
    report: &ScanReport,
    finding: &Finding,
    roots: &HashMap<&crate::model::ProjectId, &std::path::Path>,
) -> String {
    let owner = finding_owner(report, finding);
    let folder = finding_folder(finding, roots);
    if folder.is_empty() {
        owner.to_string()
    } else {
        format!("{owner}/{folder}")
    }
}

fn list_header(
    severity_width: usize,
    owner_width: usize,
    category_width: usize,
    title_width: usize,
    path_width: usize,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{:<width$}", "severity", width = severity_width),
            theme::label(),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{:<width$}", "project", width = owner_width),
            theme::label(),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{:<width$}", "type", width = category_width),
            theme::label(),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{:<width$}", "issue", width = title_width),
            theme::label(),
        ),
        Span::raw(" "),
        Span::styled(truncate_end("location", path_width), theme::label()),
    ])
}

fn measured_column_width<'a>(
    values: impl Iterator<Item = &'a str>,
    min_width: usize,
    max_width: usize,
) -> usize {
    values
        .map(|value| value.chars().count())
        .max()
        .unwrap_or(min_width)
        .clamp(min_width, max_width)
}

fn compact_progress_line(live: &LiveScan, width: usize) -> Line<'static> {
    let done = live
        .steps
        .iter()
        .filter(|step| matches!(step.state, ProgressState::Done | ProgressState::Warning))
        .count();
    let warnings = live
        .steps
        .iter()
        .filter(|step| step.state == ProgressState::Warning)
        .count();
    let current = live
        .steps
        .iter()
        .find(|step| step.state == ProgressState::Running)
        .or_else(|| {
            live.steps
                .iter()
                .rev()
                .find(|step| step.state != ProgressState::Pending)
        })
        .map(|step| step.label.as_str())
        .unwrap_or("ready");
    Line::from(vec![
        Span::styled(
            format!("{done}/{}", live.steps.len()),
            Style::default().fg(theme::IDENT),
        ),
        Span::raw(" stages"),
        Span::styled(
            format!("  {warnings} warnings  "),
            Style::default().fg(if warnings == 0 {
                theme::OK
            } else {
                theme::BUSY
            }),
        ),
        Span::raw(truncate_middle(current, width.saturating_sub(24))),
    ])
}

/// Stage weights ≈ typical share of scan wall time, indexed like
/// `LiveScan::default_steps` (discover, local files, home inventory,
/// providers, finalize). Mirrored by `progressPercent` in
/// `web/src/features/scan/Scan.tsx`; keep the two in lockstep.
const STEP_WEIGHTS: [f32; 5] = [10.0, 45.0, 10.0, 25.0, 10.0];

fn progress_percent(live: &LiveScan) -> usize {
    if live.steps.is_empty() {
        return if live.running { 0 } else { 100 };
    }
    let mut total = 0.0f32;
    let mut done = 0.0f32;
    for (i, step) in live.steps.iter().enumerate() {
        let weight = STEP_WEIGHTS.get(i).copied().unwrap_or(10.0);
        total += weight;
        done += weight
            * match step.state {
                ProgressState::Done | ProgressState::Warning => 1.0,
                ProgressState::Pending => 0.0,
                // A running step interpolates by its published fraction; steps
                // with no countable work (network waits) ease on elapsed time
                // instead, so the bar never freezes mid-stage.
                ProgressState::Running => step
                    .fraction
                    .unwrap_or_else(|| {
                        let elapsed_s = step
                            .started_at
                            .map(|t| (chrono::Utc::now() - t).num_milliseconds().max(0) as f32)
                            .unwrap_or(0.0)
                            / 1000.0;
                        (1.0 - (-elapsed_s / 8.0).exp()) * 0.9
                    })
                    .clamp(0.0, 1.0),
            };
    }
    ((done * 100.0 / total) as usize).min(100)
}

fn spinner(running: bool) -> &'static str {
    if !running {
        return " ";
    }
    const FRAMES: [&str; 4] = ["|", "/", "-", "\\"];
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    FRAMES[((millis / 120) as usize) % FRAMES.len()]
}

fn stat(label: &str, value: usize, severity: Severity) -> Span<'static> {
    Span::styled(
        format!("{label} {value}"),
        Style::default()
            .fg(theme::severity(severity))
            .add_modifier(Modifier::BOLD),
    )
}

fn detail_lines(
    report: &ScanReport,
    finding: &Finding,
    plan: Option<&crate::remediation::RemediationProposal>,
    dep_fix: &DepFix,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            finding.title.clone(),
            Style::default()
                .fg(theme::severity(finding.severity))
                .add_modifier(Modifier::BOLD),
        )),
        detail_chips(finding),
        Line::from(""),
        detail_section("Why this matters"),
        Line::from(finding.summary.clone()),
        Line::from(""),
        detail_section("Where"),
    ];

    if let Some(path) = &finding.path {
        let location = finding
            .line
            .map(|line| format!("{}:{line}", path.display()))
            .unwrap_or_else(|| path.display().to_string());
        lines.push(detail_field("location", location, theme::FG));
    }
    if let Some(project) = report.project_of(finding) {
        lines.push(detail_field(
            "project",
            project.root.display().to_string(),
            theme::IDENT,
        ));
    }
    if let Some(evidence) = &finding.evidence {
        lines.push(detail_field("evidence", evidence.clone(), theme::BUSY));
    }
    if let Some(package) = &finding.package {
        lines.push(detail_field(
            "package",
            format!("{} {}@{}", package.ecosystem, package.name, package.version),
            theme::OK,
        ));
    }
    // Exploit-in-the-wild intel (mirrors the web UI's KEV/EPSS badges): KEV is
    // the strongest danger signal, EPSS is the exploit-probability percentile.
    if let Some(exploit) = &finding.exploit {
        if exploit.kev {
            lines.push(detail_field(
                "exploited",
                "actively exploited · CISA KEV".to_string(),
                theme::ERR,
            ));
        }
        if let Some(epss) = exploit.epss {
            lines.push(detail_field(
                "EPSS",
                format!("{}% exploit probability", (epss * 100.0).round() as u32),
                theme::BUSY,
            ));
        }
    }
    lines.push(Line::from(""));
    lines.push(detail_section("What to do"));
    lines.push(Line::from(finding.recommendation.clone()));
    // One-key dependency fix (mirrors the web detail's upgrade/downgrade
    // button): shown when the advisory names a safe version husk can pin to.
    // The plan was computed in `prepare` (planning probes `PATH`).
    if let Some(planned) = plan {
        match planned.blockers.first() {
            // Known up front not to work as one key: say why, and what to do
            // instead of offering a doomed `u`. Whether an opt-in exists is a
            // typed question, so rewording a message cannot silently remove the
            // shift-U affordance.
            Some(blocker) => {
                let hint = if !planned.overrides.is_empty() {
                    "needs you (or press shift-U to upgrade anyway)"
                } else {
                    "needs you"
                };
                lines.push(detail_field(
                    "fix",
                    format!("{} - {hint}", planned.title),
                    theme::BUSY,
                ));
                lines.push(detail_field("blocked", blocker.render(), theme::BUSY));
            }
            None => lines.push(detail_field(
                "fix",
                format!("{} - press u", planned.title),
                theme::OK,
            )),
        }
        if let Some(preview) = &planned.preview {
            lines.extend(fix::preview_lines(preview, DIFF_LINES, width));
        }
        match dep_fix {
            DepFix::Running { id, .. } if *id == planned.id => {
                lines.push(detail_field(
                    "status",
                    "running...".to_string(),
                    theme::BUSY,
                ));
            }
            DepFix::Done { id, ok, message } if *id == planned.id => {
                lines.push(detail_field(
                    "status",
                    message.clone(),
                    if *ok { theme::OK } else { theme::ERR },
                ));
            }
            _ => {}
        }
    }
    if !finding.references.is_empty() {
        lines.push(Line::from(""));
        lines.push(detail_section("References"));
        for reference in finding.references.iter().take(4) {
            lines.push(Line::from(Span::styled(
                reference.clone(),
                Style::default().fg(theme::LINK),
            )));
        }
    }
    lines
}

/// Diff lines the narrow Scan detail pane shows before eliding the rest. The
/// Guide's fix pane is where a whole diff is read.
const DIFF_LINES: usize = 8;

fn detail_chips(finding: &Finding) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {} ", finding.severity.label()),
            Style::default()
                .fg(theme::severity(finding.severity))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!(" {} ", finding.category.id()),
            Style::default().fg(theme::IDENT),
        ),
        Span::raw("  "),
        Span::styled(
            finding.source.clone(),
            Style::default().fg(theme::FG_SUBTLE),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProgressStep;

    fn steps(states: &[ProgressState]) -> Vec<ProgressStep> {
        states
            .iter()
            .map(|state| {
                let mut step = ProgressStep::new("step");
                step.state = state.clone();
                step
            })
            .collect()
    }

    #[test]
    fn progress_percent_interpolates_weighted_steps() {
        let mut live = LiveScan::finished(ScanReport::empty(vec![]));
        live.steps.clear();
        assert_eq!(progress_percent(&live), 100, "finished, no steps");
        live.running = true;
        assert_eq!(progress_percent(&live), 0, "running, no steps yet");

        live.steps = steps(&[
            ProgressState::Done,
            ProgressState::Running,
            ProgressState::Pending,
            ProgressState::Pending,
            ProgressState::Pending,
        ]);
        // Running with neither fraction nor started_at contributes nothing.
        assert_eq!(progress_percent(&live), 10);

        // The running local-files step interpolates by its fraction.
        live.steps[1].fraction = Some(0.5);
        assert_eq!(progress_percent(&live), 32); // 10 + 45 * 0.5

        // A fraction never claims more than the step's full weight.
        live.steps[1].fraction = Some(7.0);
        assert_eq!(progress_percent(&live), 55);

        live.steps = steps(&[
            ProgressState::Done,
            ProgressState::Done,
            ProgressState::Done,
            ProgressState::Warning,
            ProgressState::Done,
        ]);
        assert_eq!(progress_percent(&live), 100, "warnings still complete");
    }

    #[test]
    fn measured_column_width_clamps_to_bounds() {
        assert_eq!(measured_column_width([].into_iter(), 8, 24), 8);
        assert_eq!(measured_column_width(["abc"].into_iter(), 8, 24), 8);
        assert_eq!(
            measured_column_width(["a".repeat(30).as_str()].into_iter(), 8, 24),
            24
        );
        assert_eq!(
            measured_column_width(["short", "a-longer-name"].into_iter(), 8, 24),
            13
        );
    }

    use crate::model::{ExploitInfo, Project, ProjectId, ProjectKind};
    use std::path::PathBuf;

    fn finding(path: &str, severity: Severity, project: &ProjectId) -> Finding {
        let mut f = Finding::new(
            "id",
            "title",
            severity,
            crate::rule::Category::Secret,
            "source",
            Some(PathBuf::from(path)),
            None,
            "summary",
            None,
            "recommendation",
        );
        f.project_id = Some(project.clone());
        f
    }

    fn project(root: &str) -> Project {
        let root = PathBuf::from(root);
        Project {
            id: ProjectId::from_root(&root),
            root,
            name: "proj".into(),
            kind: ProjectKind::GitRepo,
            submodule_of: None,
            git: None,
            last_modified: None,
            activity: crate::model::Activity::Active,
            ecosystems: Vec::new(),
            package_count: 0,
            rollup: crate::model::ProjectRollup::default(),
            posture: None,
        }
    }

    #[test]
    fn folder_is_capped_at_two_segments() {
        let p = project("/repo");
        let mut roots = HashMap::new();
        roots.insert(&p.id, p.root.as_path());
        let f = finding(
            "/repo/tst/.github/workflows/ci.yml",
            Severity::Medium,
            &p.id,
        );
        assert_eq!(finding_folder(&f, &roots), "tst/.github");

        let root_level = finding("/repo/README.md", Severity::Medium, &p.id);
        assert_eq!(finding_folder(&root_level, &roots), "");
    }

    #[test]
    fn severity_orders_the_flat_list_across_projects() {
        let a = project("/repo-a");
        let b = project("/repo-b");
        let mut report = ScanReport::empty(Vec::new());
        // Report order: high in a, critical in b, medium in a. Display must be
        // severity-first, never regrouped by project.
        let mut high = finding("/repo-a/x.rs", Severity::High, &a.id);
        high.id = "high".into();
        let mut critical = finding("/repo-b/x.rs", Severity::Critical, &b.id);
        critical.id = "critical".into();
        let mut medium = finding("/repo-a/y.rs", Severity::Medium, &a.id);
        medium.id = "medium".into();
        report.findings = vec![high, critical, medium];
        report.projects = vec![a, b];

        let ids: Vec<&str> = sorted_display_indices(&report)
            .into_iter()
            .map(|i| report.findings[i].id.as_str())
            .collect();
        assert_eq!(ids, vec!["critical", "high", "medium"]);
    }

    #[test]
    fn config_findings_form_a_trailing_section() {
        let repo = project("/repo");
        let mut config = project("/home/#husk-config");
        config.kind = ProjectKind::ConfigLocation;
        let mut report = ScanReport::empty(Vec::new());
        // A critical config finding must not interleave ahead of project
        // findings; the domains stay separate, severity sorts within each.
        let mut cfg_critical = finding("/home/.claude/x.json", Severity::Critical, &config.id);
        cfg_critical.id = "cfg".into();
        let mut repo_low = finding("/repo/x.rs", Severity::Low, &repo.id);
        repo_low.id = "repo".into();
        report.findings = vec![cfg_critical, repo_low];
        report.projects = vec![repo, config];

        let ids: Vec<&str> = sorted_display_indices(&report)
            .into_iter()
            .map(|i| report.findings[i].id.as_str())
            .collect();
        assert_eq!(ids, vec!["repo", "cfg"]);
    }

    #[test]
    fn kev_sorts_ahead_of_higher_severity() {
        let p = project("/repo");
        let mut report = ScanReport::empty(Vec::new());
        let mut medium = finding("/repo/a/x.rs", Severity::Medium, &p.id);
        medium.id = "medium".into();
        let mut kev_low = finding("/repo/z/x.rs", Severity::Low, &p.id);
        kev_low.id = "kev".into();
        kev_low.exploit = Some(ExploitInfo {
            kev: true,
            epss: None,
        });
        report.findings = vec![medium, kev_low];
        report.projects = vec![p];

        let indices = sorted_display_indices(&report);
        assert_eq!(report.findings[indices[0]].id, "kev");
    }
}
