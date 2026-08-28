import {
  cn,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@huskdev/ui";
import { useRef } from "react";
import {
  type Finding,
  type SourceToken,
  type TokenClass,
  useSource,
} from "@/lib/api";
import { shortPath } from "@/lib/path";

/** The file a finding sits in, and the line inside it when known. Mirrors the
 *  Rust `Finding::location`, which is also the server's allowlist for
 *  `/api/source`: anything this returns is readable, anything else is refused. */
export function locationOf(f: Finding): { path: string; line?: number } | null {
  if (f.path) return { path: f.path, line: f.line };
  if (f.package?.manifest_path) {
    return { path: f.package.manifest_path, line: f.package.line };
  }
  return null;
}

/** Two hues, neither of them a severity colour: the findings list this panel
 *  sits next to grades by hue, so accent (the name side) and success (the
 *  value side) are the only ones a reader cannot mistake for a rating. Weight
 *  and grey carry the rest. Mirrored by the TUI palette in `tui/theme.rs`. */
const TOKEN: Record<TokenClass, string> = {
  key: "text-accent font-semibold",
  keyword: "text-fg font-semibold",
  str: "text-success",
  num: "text-fg",
  comment: "text-fg-subtle italic",
  punct: "text-fg-subtle",
  plain: "text-fg-muted",
};

/** Rows of context kept above the first flagged line. Mirrors the TUI pane's
 *  `LEAD`: what sits above a finding is usually why it is a finding. */
const LEAD = 6;

/** Each token paired with the column it starts at. That column is a stable
 *  key where the array index is not: re-reading an edited file reflows the
 *  tokens on a line, and React would then keep the wrong spans. */
function keyed(tokens: SourceToken[]): [string, SourceToken][] {
  let col = 0;
  return tokens.map((token) => {
    const at = col;
    col += token.text.length;
    return [`c${at}`, token];
  });
}

/** The flagged file, read-only, syntax highlighted, over the page. Browser half
 *  of the TUI's source pane (`o` on the Scan tab), which also opens over the
 *  body; both render the same server-side tokens.
 *
 *  Husk shows the file rather than opening it in an editor: an editor loads the
 *  tree's own plugins and language servers, and this is a file the scanner has
 *  just called dangerous. */
export function SourceView({
  path,
  lines,
  open,
  onOpenChange,
}: {
  path: string;
  /** Every line this file was flagged on, ascending. The window is read
   *  around the first; the rest are marked wherever they land inside it. */
  lines: number[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const line = lines[0];
  const source = useSource(path || undefined, line);
  const flaggedLines = new Set(lines);
  const shown = source.data?.lines ?? [];
  // Flagged lines the window does not reach: a file leaking a key on line 3
  // and another on line 900 must not look like it only leaked once.
  const offscreen = shown.length
    ? lines.filter(
        (at) => at < shown[0].number || at > shown[shown.length - 1].number,
      ).length
    : 0;

  // Open on the finding, not on the top of the window. A ref callback fires
  // exactly when the flagged row mounts, and scrolling the container itself
  // (rather than scrollIntoView) keeps the page around it still.
  const box = useRef<HTMLDivElement>(null);
  const openOn = (row: HTMLDivElement | null) => {
    if (!row || !box.current) return;
    box.current.scrollTop = Math.max(
      0,
      row.offsetTop - LEAD * row.offsetHeight,
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {/* Wider than the widest dialog size the kit ships: source is the one
          thing here read a line at a time, and wrapping it would be lying
          about where the flagged column sits. */}
      <DialogContent size="lg" className="max-w-5xl">
        <DialogTitle>Source</DialogTitle>
        <DialogDescription
          className="truncate font-mono text-[11px]"
          title={path}
        >
          {shortPath(path)}
          {lines.length ? `:${lines.join(",")}` : ""}
          {source.data
            ? ` · ${source.data.lines.length} of ${source.data.total_lines} lines`
            : ""}
        </DialogDescription>

        {/* Fixed height whatever the file is: a long excerpt must not grow the
            dialog, and a long line must scroll here rather than widen it. */}
        <div
          ref={box}
          className="mt-2 h-[65vh] overflow-auto rounded-md border border-border bg-surface"
        >
          {source.isPending && (
            <p className="p-3 text-[12px] text-fg-subtle">Reading file...</p>
          )}
          {source.isError && (
            <p className="p-3 text-[12px] text-warning">
              {source.error instanceof Error
                ? source.error.message
                : "Could not read this file."}
            </p>
          )}
          {source.data && (
            <pre className="w-max min-w-full py-1 font-mono text-[11.5px] leading-[1.55]">
              {source.data.lines.map((row) => {
                const flagged = flaggedLines.has(row.number);
                return (
                  <div
                    key={row.number}
                    ref={row.number === line ? openOn : undefined}
                    className={cn(
                      "flex border-l-2",
                      flagged
                        ? "border-danger bg-danger-tint"
                        : "border-transparent",
                    )}
                  >
                    {/* Sticky so the numbers stay readable while a long line is
                        scrolled sideways. */}
                    <span
                      className={cn(
                        "sticky left-0 w-12 shrink-0 select-none pr-3 text-right tabular-nums",
                        // The gutter must stay opaque: it sits over the line
                        // while a long one is scrolled sideways under it.
                        flagged
                          ? "bg-surface-raised text-danger"
                          : "bg-surface text-fg-subtle",
                      )}
                    >
                      {row.number}
                    </span>
                    <code className="pr-3">
                      {keyed(row.tokens).map(([key, token]) => (
                        <span key={key} className={TOKEN[token.class]}>
                          {token.text}
                        </span>
                      ))}
                    </code>
                  </div>
                );
              })}
            </pre>
          )}
        </div>
        {offscreen > 0 && (
          <p className="mt-1 text-[10.5px] tabular-nums text-fg-subtle">
            + {offscreen} more flagged {offscreen === 1 ? "line" : "lines"}{" "}
            outside this window
          </p>
        )}
      </DialogContent>
    </Dialog>
  );
}
