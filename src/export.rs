//! Report export formats for `husk scan --export`. Mirrors the web Scan export
//! (JSON / CSV / Markdown). The web builds these client-side from the on-screen
//! filtered view; this renders the whole report's open findings (`report.findings`).

use crate::model::{Finding, ScanReport};

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum ExportFormat {
    Json,
    Csv,
    Md,
}

pub fn render(format: ExportFormat, report: &ScanReport) -> String {
    match format {
        ExportFormat::Json => json(report),
        ExportFormat::Csv => csv(&report.findings),
        ExportFormat::Md => markdown(report),
    }
}

fn pkg_str(f: &Finding) -> String {
    f.package
        .as_ref()
        .map(|p| format!("{}:{}@{}", p.ecosystem, p.name, p.version))
        .unwrap_or_default()
}

fn loc_str(f: &Finding) -> String {
    match (&f.path, f.line) {
        (Some(p), Some(l)) => format!("{}:{l}", p.display()),
        (Some(p), None) => p.display().to_string(),
        _ => String::new(),
    }
}

fn json(report: &ScanReport) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "generated_at": report.generated_at,
        "roots": report.roots,
        "count": report.findings.len(),
        "findings": report.findings,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

/// Characters that make a spreadsheet treat the rest of a cell as a formula.
/// Tab and carriage return are included because Excel skips leading whitespace
/// before deciding, so `\t=cmd|...` evaluates just as `=cmd|...` does.
const FORMULA_LEAD: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// RFC-4180 quoting (comma, quote, or newline; inner quotes doubled), plus
/// formula neutralisation.
///
/// Finding titles, package names, and paths come from advisory text and
/// lockfile contents, so an attacker chooses them. Excel, Sheets, and
/// LibreOffice all evaluate a cell that opens with [`FORMULA_LEAD`] on import,
/// quoted or not, which would turn a husk export into code execution on the
/// machine of whoever opens it. A leading apostrophe is the neutraliser rather
/// than a leading tab: the tab is itself a formula lead-in in Excel, and it
/// silently changes the value for every non-spreadsheet consumer of the CSV,
/// whereas the apostrophe is the documented "this cell is text" prefix.
fn csv_cell(s: &str) -> String {
    let s = if s.starts_with(FORMULA_LEAD) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn csv(findings: &[Finding]) -> String {
    let mut out = String::from("severity,category,title,package,location,source,summary\n");
    for f in findings {
        let cells = [
            f.severity.label().to_string(),
            f.category.id().to_string(),
            f.title.clone(),
            pkg_str(f),
            loc_str(f),
            f.source.clone(),
            f.summary.clone(),
        ];
        out.push_str(
            &cells
                .iter()
                .map(|c| csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out
}

fn markdown(report: &ScanReport) -> String {
    let esc = |s: &str| s.replace('|', "\\|");
    let mut out = format!(
        "# Husk scan report\n\n_{} finding(s) · generated {}_\n\n\
         | Severity | Type | Issue | Package | Location |\n\
         | --- | --- | --- | --- | --- |\n",
        report.findings.len(),
        report.generated_at.to_rfc3339(),
    );
    for f in &report.findings {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            f.severity.label(),
            esc(f.category.id()),
            esc(&f.title),
            esc(&pkg_str(f)),
            esc(&loc_str(f)),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn csv_quotes_commas_and_quotes() {
        let f = Finding::new(
            "id",
            "a, \"tricky\" title",
            Severity::High,
            crate::rule::Category::Vulnerability,
            "test",
            None,
            None,
            "sum",
            None,
            "rec",
        );
        let out = csv(std::slice::from_ref(&f));
        let data_line = out.lines().nth(1).unwrap();
        assert!(
            data_line.contains("\"a, \"\"tricky\"\" title\""),
            "{data_line}"
        );
    }

    #[test]
    fn csv_neutralises_spreadsheet_formulas() {
        // The classic DDE payload: attacker-chosen advisory text that Excel
        // would otherwise execute when the exported report is opened.
        let f = Finding::new(
            "id",
            "=cmd|' /C calc'!A0",
            Severity::High,
            crate::rule::Category::Vulnerability,
            "test",
            None,
            None,
            "=HYPERLINK(\"http://evil\",\"click\")",
            None,
            "rec",
        );
        let out = csv(std::slice::from_ref(&f));
        let data_line = out.lines().nth(1).unwrap();
        assert!(data_line.contains("'=cmd|' /C calc'!A0"), "{data_line}");
        // Neutralised first, then RFC-4180 quoted, so the prefix stays inside
        // the quotes where the spreadsheet reads it.
        assert!(
            data_line.contains("\"'=HYPERLINK(\"\"http://evil\"\",\"\"click\"\")\""),
            "{data_line}"
        );
        for cell in ["=", "+x", "-x", "@x", "\tx", "\rx"] {
            assert!(
                csv_cell(cell).starts_with('\''),
                "{cell:?} must not stay executable"
            );
        }
        // Ordinary cells are untouched.
        assert_eq!(csv_cell("critical"), "critical");
        assert_eq!(csv_cell("npm:lodash@4.17.20"), "npm:lodash@4.17.20");
    }

    #[test]
    fn markdown_escapes_pipes_and_has_a_header() {
        let f = Finding::new(
            "id",
            "pipe | title",
            Severity::Low,
            crate::rule::Category::Secret,
            "test",
            None,
            None,
            "sum",
            None,
            "rec",
        );
        let mut report = ScanReport::empty(vec![]);
        report.findings = vec![f];
        let out = markdown(&report);
        assert!(out.starts_with("# Husk scan report"));
        assert!(out.contains("pipe \\| title"));
    }
}
