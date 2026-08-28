//! The Account tab: "this machine" + cloud-connection status. Terminal mirror
//! of `web/src/features/account/Account.tsx`. Account sign-in is not available
//! yet, so this view is informational.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use super::theme;
use crate::model::ScanReport;

pub(super) fn draw(frame: &mut Frame<'_>, report: &ScanReport, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .margin(1)
        .split(area);
    draw_connection(frame, cols[0]);
    draw_machine(frame, report, cols[1]);
}

fn card(title: &'static str) -> Block<'static> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .padding(ratatui::widgets::Padding::new(1, 1, 1, 1))
}

fn draw_connection(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "Account sign-in: coming soon",
            theme::accent(),
        )),
        Line::from(""),
        Line::from(Span::styled("Report an issue", theme::label())),
        Line::from(Span::styled(
            "https://github.com/husk-security/husk/issues/new",
            theme::accent().add_modifier(ratatui::style::Modifier::UNDERLINED),
        )),
        Line::from(""),
        Line::from(Span::styled("Send feedback", theme::label())),
        Line::from(Span::styled(
            "husk feedback \"Your message\"",
            theme::accent(),
        )),
        Line::from(Span::styled(
            "Stored by Husk so the team can read and reply: husk-security.dev/legal/privacy",
            theme::muted(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Husk works fully without an account. Existing sessions remain usable.",
            theme::muted(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(card("Cloud connection"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_machine(frame: &mut Frame<'_>, report: &ScanReport, area: Rect) {
    let ctx = &report.context;
    let user = super::display_user(ctx).to_string();
    let system = ctx.distro.clone().unwrap_or_else(|| ctx.os.clone());
    let kernel = ctx
        .kernel
        .as_deref()
        .map(|kernel| format!("{kernel} · {}", ctx.arch))
        .unwrap_or_else(|| ctx.arch.clone());
    let lines = vec![
        field("user", user),
        field("system", system),
        field("kernel / arch", kernel),
        field("git identity", super::git_identity(report)),
        field("dev tools", super::compact_list(&ctx.package_managers, 8)),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(card("This machine"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn field(label: &'static str, value: String) -> Line<'static> {
    super::field_line(
        label,
        14,
        Span::styled(value, Style::default().fg(theme::FG)),
    )
}
