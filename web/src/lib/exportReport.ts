// Client-side Scan export. The web exports the CURRENT on-screen view (the
// findings left after the active severity/category/ecosystem filters), so the
// formatting has to happen here where the filter state lives; not on the
// server, which only knows the full report. The CLI mirrors these formats in
// Rust (`husk scan --export`) over the whole report.
import type { Finding, ScanReport } from "./api";

export type ExportFormat = "json" | "csv" | "md";

export const EXPORT_LABEL: Record<ExportFormat, string> = {
  json: "JSON",
  csv: "CSV",
  md: "Markdown",
};
const EXT: Record<ExportFormat, string> = {
  json: "json",
  csv: "csv",
  md: "md",
};
const MIME: Record<ExportFormat, string> = {
  json: "application/json",
  csv: "text/csv",
  md: "text/markdown",
};

const pkgStr = (f: Finding) =>
  f.package
    ? `${f.package.ecosystem}:${f.package.name}@${f.package.version}`
    : "";
const locStr = (f: Finding) =>
  f.path ? `${f.path}${f.line ? `:${f.line}` : ""}` : "";

// RFC-4180: quote a cell containing a comma, quote, or newline; double inner quotes.
const csvCell = (s: string) =>
  /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;

function toCSV(findings: Finding[]): string {
  const head = [
    "severity",
    "category",
    "title",
    "package",
    "location",
    "source",
    "summary",
  ];
  const rows = findings.map((f) =>
    [f.severity, f.category, f.title, pkgStr(f), locStr(f), f.source, f.summary]
      .map((c) => csvCell(String(c ?? "")))
      .join(","),
  );
  return [head.join(","), ...rows].join("\n");
}

function toMarkdown(findings: Finding[], report?: ScanReport): string {
  const when = report?.generated_at ?? new Date().toISOString();
  const esc = (s: string) => s.replace(/\|/g, "\\|");
  return [
    "# Husk scan report",
    "",
    `_${findings.length} finding(s) · generated ${when}_`,
    "",
    "| Severity | Type | Issue | Package | Location |",
    "| --- | --- | --- | --- | --- |",
    ...findings.map(
      (f) =>
        `| ${f.severity} | ${esc(f.category)} | ${esc(f.title)} | ${esc(
          pkgStr(f),
        )} | ${esc(locStr(f))} |`,
    ),
  ].join("\n");
}

function toJSON(findings: Finding[], report?: ScanReport): string {
  return JSON.stringify(
    {
      generated_at: report?.generated_at,
      roots: report?.roots,
      count: findings.length,
      findings,
    },
    null,
    2,
  );
}

function render(
  fmt: ExportFormat,
  findings: Finding[],
  report?: ScanReport,
): string {
  if (fmt === "json") return toJSON(findings, report);
  if (fmt === "csv") return toCSV(findings);
  return toMarkdown(findings, report);
}

/** Build the chosen format from the given (already filtered) findings and
 *  trigger a browser download of `husk-scan-<date>.<ext>`. */
export function downloadReport(
  fmt: ExportFormat,
  findings: Finding[],
  report?: ScanReport,
) {
  const text = render(fmt, findings, report);
  const date = (report?.generated_at ?? new Date().toISOString()).slice(0, 10);
  const blob = new Blob([text], { type: MIME[fmt] });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `husk-scan-${date}.${EXT[fmt]}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
