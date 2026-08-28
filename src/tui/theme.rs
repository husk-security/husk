//! Centralized TUI palette: the terminal analogue of the `@huskdev/tokens`
//! brand tokens (github.com/husk-security/husk-ui), the source of truth for
//! husk's colors.
//!
//! Brand rule: the UI is **monochrome**; the only "CTA"/accent is bright white;
//! **hue is reserved for severity** (and the single cool info hue). Everything
//! structural is a shade of gray. Keep this the one place colors are defined so
//! every tab stays consistent and a future theme/degradation pass has a single
//! seam.

use ratatui::style::{Color, Modifier, Style};

use crate::highlight::Class;
use crate::model::{Activity, Severity};

// ── structural neutrals ────────────────────────────────────────────────────
/// Primary foreground (default terminal fg).
pub(super) const FG: Color = Color::White;
/// Secondary text.
pub(super) const FG_MUTED: Color = Color::Gray;
/// Tertiary / labels / hints.
pub(super) const FG_SUBTLE: Color = Color::DarkGray;
/// Borders and rules.
pub(super) const BORDER: Color = Color::DarkGray;
/// The accent / active / "CTA": intentionally white, never a hue.
pub(super) const ACCENT: Color = Color::White;
/// Selection background for the active row (Guide list).
pub(super) const SELECTION_BG: Color = Color::Rgb(38, 40, 46);
/// Selection background for the Scan findings list. Consolidating this with
/// [`SELECTION_BG`] is a visual-design decision, not a refactor.
pub(super) const SCAN_SELECTION_BG: Color = Color::DarkGray;

// ── state / affordance accents ──────────────────────────────────────────────
/// Positive state: scan complete, fix applied, satisfied recommendation.
pub(super) const OK: Color = Color::Green;
/// In-progress / caution state: running scans, warnings, evidence.
pub(super) const BUSY: Color = Color::Yellow;
/// Failure / strongest-danger accent: actively exploited, failed fix.
pub(super) const ERR: Color = Color::Red;
/// Identifier accent: package counts, project/owner names, the welcome line.
pub(super) const IDENT: Color = Color::Cyan;
/// URLs and references.
pub(super) const LINK: Color = Color::Blue;
/// The Scan context panel's per-field accents (tools / configs rows).
pub(super) const TOOLS: Color = Color::Magenta;
/// See [`TOOLS`].
pub(super) const CONFIGS: Color = Color::LightRed;

/// A muted, bold label (field names, column headers, section titles).
pub(super) fn label() -> Style {
    Style::default().fg(FG_SUBTLE).add_modifier(Modifier::BOLD)
}

/// Accent text: the one bold-white emphasis.
pub(super) fn accent() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub(super) fn muted() -> Style {
    Style::default().fg(FG_MUTED)
}

/// Caution text: the stale-scan badge and similar "look at this" nudges.
pub(super) fn warn() -> Style {
    Style::default().fg(BUSY).add_modifier(Modifier::BOLD)
}

// ── severity (the only place hue is allowed) ───────────────────────────────
/// Brand severity hues (the `@huskdev/tokens` severity palette, dark-theme
/// values). Critical/high are hot, medium is the brand amber, low is
/// desaturated warm, and info is the one cool hue in the system.
pub(super) fn severity(sev: Severity) -> Color {
    match sev {
        Severity::Critical => Color::Rgb(0xF1, 0x44, 0x45), // #F14445
        Severity::High => Color::Rgb(0xFA, 0x6E, 0x1D),     // #FA6E1D
        Severity::Medium => Color::Rgb(0xEA, 0xB5, 0x32),   // #EAB532
        Severity::Low => Color::Rgb(0xB0, 0x9C, 0x74),      // #B09C74
        Severity::Info => Color::Rgb(0x92, 0xA7, 0xBD),     // #92A7BD
    }
}

/// The single cool "info" hue, used for verified/satisfied affordances.
pub(super) const INFO: Color = Color::Rgb(0x92, 0xA7, 0xBD);

/// Project-activity accent: live projects get a signal color, inactive ones
/// stay in the structural gray so they recede.
pub(super) fn activity(activity: Activity) -> Color {
    match activity {
        Activity::Active => Color::Green,
        Activity::Recent => Color::Cyan,
        Activity::Dormant | Activity::Abandoned => FG_SUBTLE,
    }
}

// ── source tokens ──────────────────────────────────────────────────────────
/// One syntax token's style, for the source pane.
///
/// Two hues, neither of them a severity colour: the brand rule keeps hue for
/// severity and the findings list behind the pane is graded by it, so the name
/// side (`IDENT`) and the value side (`OK`) are the only ones a reader cannot
/// mistake for a rating. Grey, weight, and italic carry the rest. The web
/// `SourceView` maps the same classes onto the same split.
pub(super) fn token(class: Class) -> Style {
    match class {
        Class::Comment => Style::default()
            .fg(FG_SUBTLE)
            .add_modifier(Modifier::ITALIC),
        Class::Key => Style::default().fg(IDENT).add_modifier(Modifier::BOLD),
        Class::Keyword => Style::default().fg(FG).add_modifier(Modifier::BOLD),
        Class::Str => Style::default().fg(OK),
        Class::Num => Style::default().fg(FG),
        Class::Punct => Style::default().fg(FG_SUBTLE),
        Class::Plain => Style::default().fg(FG_MUTED),
    }
}

#[cfg(test)]
mod tests {
    /// The palette rule is machine-checked: raw `Color::` literals may appear
    /// only in this file. Every other TUI module must go through the theme, so
    /// the brand's "monochrome + severity-only hue" invariant has one seam.
    #[test]
    fn colors_are_defined_only_in_theme() {
        let sources = [
            ("mod.rs", include_str!("mod.rs")),
            ("account.rs", include_str!("account.rs")),
            ("consent.rs", include_str!("consent.rs")),
            ("fix.rs", include_str!("fix.rs")),
            ("guide.rs", include_str!("guide.rs")),
            ("scan.rs", include_str!("scan.rs")),
            ("source.rs", include_str!("source.rs")),
            ("tests.rs", include_str!("tests.rs")),
        ];
        for (name, source) in sources {
            assert!(
                !source.contains("Color::"),
                "src/tui/{name} uses a raw `Color::` literal; define it in src/tui/theme.rs instead"
            );
        }
    }
}
