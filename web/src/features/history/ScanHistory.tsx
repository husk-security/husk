import { Card, cn, EmptyState } from "@huskdev/ui";
import {
  ArrowDownRight,
  ArrowUpRight,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  Folder,
  History as HistoryIcon,
  Minus,
  Wrench,
} from "lucide-react";
import { useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  type HistoryEntry,
  type HistoryFinding,
  useHistory,
  useScanFinishedAt,
} from "@/lib/api";
import { groupByLabel, runsOf } from "@/lib/collapse";
import { SEV_TEXT } from "../scan/severity";

// Fixed stacking order, critical anchored to the baseline; position encodes
// severity rank, so identity never rides on hue alone (the severity ramp's
// adjacent warm hues are too close for deutan vision; the legend, tooltips,
// and the feed below carry the labels).
const SEV_KEYS = ["critical", "high", "medium", "low", "info"] as const;
type SevKey = (typeof SEV_KEYS)[number];
const SEV_LABEL: Record<SevKey, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const dateLabel = (iso: string) =>
  new Date(iso).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
const timeLabel = (iso: string) =>
  new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

/** One scan target set (the normalized roots of a scan) and its scans,
 *  oldest first; the grouping unit of the Scan history tab. */
interface RepoGroup {
  key: string;
  /** Compact display name: the roots' basenames joined with " + ". */
  label: string;
  paths: string[];
  entries: HistoryEntry[];
}

/** Group history rows per scan target, most recently scanned group first.
 *  `roots_key` is the sorted roots joined on a unit separator. */
function groupByRoots(entries: HistoryEntry[]): RepoGroup[] {
  const map = new Map<string, HistoryEntry[]>();
  for (const e of entries) {
    const list = map.get(e.roots_key);
    if (list) list.push(e);
    else map.set(e.roots_key, [e]);
  }
  const tail = (p: string, segments: number) =>
    p
      .replace(/[/\\]+$/, "")
      .split(/[/\\]/)
      .filter(Boolean)
      .slice(-segments)
      .join("/") || p;
  const groups = Array.from(map.entries()).map(([key, list]) => {
    const paths = key.split("\u001f");
    const label = paths.map((p) => tail(p, 1)).join(" + ");
    return { key, label, paths, entries: list };
  });
  // Two targets can share a basename (two checkouts both named "app");
  // colliding labels grow a parent segment so every chip stays unique.
  const seen = new Map<string, number>();
  for (const g of groups) seen.set(g.label, (seen.get(g.label) ?? 0) + 1);
  for (const g of groups) {
    if ((seen.get(g.label) ?? 0) > 1) {
      g.label = g.paths.map((p) => tail(p, 2)).join(" + ");
    }
  }
  groups.sort(
    (a, b) =>
      +new Date(b.entries[b.entries.length - 1].at) -
      +new Date(a.entries[a.entries.length - 1].at),
  );
  return groups;
}

/** Width of a DOM node, tracked via ResizeObserver; the charts render in
 *  pixel coordinates (no viewBox scaling), so strokes and dots stay crisp. */
function useMeasuredWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const node = ref.current;
    if (!node) return;
    const observer = new ResizeObserver(() =>
      setWidth(node.getBoundingClientRect().width),
    );
    observer.observe(node);
    setWidth(node.getBoundingClientRect().width);
    return () => observer.disconnect();
  }, []);
  return { ref, width };
}

/** The Scan history tab: every completed scan, grouped per scan target;
 *  score trend and findings composition for the selected target, and a
 *  per-scan feed where each scan expands into exactly what changed (the
 *  vulnerabilities patched and the findings that appeared). */
export function ScanHistory() {
  const history = useHistory(useScanFinishedAt().data);
  const groups = useMemo(
    () => groupByRoots(history.data ?? []),
    [history.data],
  );
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const group = groups.find((g) => g.key === selectedKey) ?? groups[0];

  // Only before the very first response: rendering nothing collapses the
  // scroll pane, which throws the reader back to the top. A refetch keeps the
  // previous history on screen and never trips this.
  if (history.isPending) return null;
  if (!group) {
    return (
      <div className="px-6 py-8">
        <EmptyState
          icon={<HistoryIcon className="size-8 text-fg-subtle" />}
          title="No scan history yet"
          description="History starts with your next scan. Every completed scan adds an entry: security score, findings, what changed, and the fixes Husk applied."
        />
      </div>
    );
  }

  const first = group.entries[0];
  const last = group.entries[group.entries.length - 1];
  const resolvedTotal = group.entries.reduce((n, e) => n + e.resolved_count, 0);
  const fixesTotal = group.entries.reduce((n, e) => n + e.fixes_applied, 0);
  const huskResolvedTotal = group.entries.reduce(
    (n, e) => n + e.husk_resolved,
    0,
  );

  return (
    <div className="flex flex-col gap-4 px-6 pt-5 pb-8">
      <header>
        <h1 className="text-[15px] font-medium text-fg">Scan history</h1>
        <p className="text-[12.5px] text-fg-muted">
          Every completed scan, grouped per scan target. Scores and trends grade
          the selected target only, not your whole machine. Click a scan to see
          what changed.
        </p>
      </header>

      {/* Target picker: one chip per scanned roots set, latest-scanned first. */}
      {groups.length > 1 && (
        <div className="flex flex-wrap items-center gap-1.5">
          {groups.map((g) => (
            <button
              key={g.key}
              type="button"
              onClick={() => setSelectedKey(g.key)}
              aria-pressed={g.key === group.key}
              title={g.paths.join("\n")}
              className={cn(
                "flex max-w-72 items-center gap-1.5 rounded-full border px-3 py-1 text-[12.5px] transition-colors focus-ring",
                g.key === group.key
                  ? "border-border-strong bg-surface text-fg"
                  : "border-border bg-bg text-fg-muted hover:bg-surface hover:text-fg",
              )}
            >
              <Folder size={13} className="shrink-0 text-fg-subtle" />
              <span className="truncate">{g.label}</span>
              <span className="shrink-0 text-[11px] text-fg-subtle tabular-nums">
                {g.entries.length}
              </span>
            </button>
          ))}
        </div>
      )}

      {/* Which paths the selected group covers, in full. */}
      <p
        className="truncate text-[11.5px] text-fg-subtle"
        title={group.paths.join("\n")}
      >
        {group.paths.join(" · ")}
      </p>

      {/* Hero tiles: the value headline for the selected target. A single
          scan has no movement to headline, so the tiles say what starts
          counting when instead of claiming zeros and "steady". */}
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <StatTile
          icon={<CheckCheck size={14} />}
          label="Findings resolved"
          value={resolvedTotal}
          hint={
            huskResolvedTotal > 0
              ? `${huskResolvedTotal} confirmed from Husk fixes`
              : group.entries.length < 2
                ? "counted from your next scan"
                : "since the first scan"
          }
        />
        <StatTile
          icon={<Wrench size={14} />}
          label="Fixes applied by Husk"
          value={fixesTotal}
          hint="one-click and CLI applies"
        />
        <ScoreTile
          first={first.score}
          last={last.score}
          single={group.entries.length < 2}
        />
      </div>

      {group.entries.length < 2 ? (
        <p className="rounded-lg border border-border bg-surface px-4 py-3 text-[13px] text-fg-muted">
          Trends appear after your next scan; one point isn't a trend yet.
        </p>
      ) : (
        <>
          <ChartCard
            title="Security score"
            subtitle="this target, 0-100, higher is safer"
          >
            <ScoreChart points={group.entries} />
          </ChartCard>
          <ChartCard
            title="Findings by severity"
            subtitle="open findings at each scan"
            legend={
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                {SEV_KEYS.map((k) => (
                  <span
                    key={k}
                    className="flex items-center gap-1.5 text-[11px] text-fg-muted"
                  >
                    <span
                      className={cn("size-2 rounded-[2px]", SEV_TEXT[k])}
                      style={{ backgroundColor: "currentcolor" }}
                    />
                    {SEV_LABEL[k]}
                  </span>
                ))}
              </div>
            }
          >
            <SeverityBars points={group.entries} />
          </ChartCard>
        </>
      )}

      <Feed key={group.key} entries={group.entries} />
    </div>
  );
}

function StatTile({
  icon,
  label,
  value,
  hint,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  hint: string;
}) {
  return (
    <Card className="px-4 py-3">
      <span className="flex items-center gap-1.5 text-[11px] tracking-wider text-fg-muted uppercase">
        <span className="text-fg-subtle">{icon}</span>
        {label}
      </span>
      <b className="mt-1 block text-2xl tabular-nums">{value}</b>
      <span className="text-[11.5px] text-fg-subtle">{hint}</span>
    </Card>
  );
}

/** Score movement tile: first → latest, tinted by direction (a UI-state tint,
 *  not a severity; score isn't a finding). With a single scan there is no
 *  movement, so the tile shows the score alone and says so. */
function ScoreTile({
  first,
  last,
  single,
}: {
  first: number;
  last: number;
  single?: boolean;
}) {
  const up = last > first;
  const flat = last === first;
  return (
    <Card className="px-4 py-3">
      <span className="flex items-center gap-1.5 text-[11px] tracking-wider text-fg-muted uppercase">
        <span className="text-fg-subtle">
          <HistoryIcon size={14} />
        </span>
        Security score
      </span>
      <span className="mt-1 flex items-baseline gap-1.5">
        <b className="text-2xl tabular-nums">{last}</b>
        <span className="text-[13px] text-fg-subtle">/100</span>
        {!single && (
          <span
            className={cn(
              "flex items-center gap-0.5 text-[12.5px] tabular-nums",
              up ? "text-success" : flat ? "text-fg-subtle" : "text-warning",
            )}
          >
            {up ? (
              <ArrowUpRight size={13} />
            ) : flat ? (
              <Minus size={13} />
            ) : (
              <ArrowDownRight size={13} />
            )}
            {flat ? "unchanged" : `from ${first}`}
          </span>
        )}
      </span>
      <span className="text-[11.5px] text-fg-subtle">
        {single
          ? "one scan of this target so far"
          : up
            ? "this target is safer than at its first scan"
            : flat
              ? "steady since this target's first scan"
              : "new findings or new checks since this target's first scan"}
      </span>
    </Card>
  );
}

function ChartCard({
  title,
  subtitle,
  legend,
  children,
}: {
  title: string;
  subtitle: string;
  legend?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <Card className="px-4 py-3">
      <div className="mb-2 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <span className="text-[13px] font-medium text-fg">
          {title}{" "}
          <span className="font-normal text-fg-subtle">· {subtitle}</span>
        </span>
        {legend}
      </div>
      {children}
    </Card>
  );
}

// Shared chart geometry: fixed height, left gutter for the y labels, a
// hover band per point driving one tooltip.
const CHART_H = 150;
const PAD_L = 30;
const PAD_R = 10;
const PAD_T = 8;
const PAD_B = 20;

function useHover() {
  const [hover, setHover] = useState<number | null>(null);
  return { hover, setHover };
}

/** Tooltip pinned above a chart x position, clamped into the container. */
function ChartTip({
  x,
  width,
  children,
}: {
  x: number;
  width: number;
  children: React.ReactNode;
}) {
  return (
    <div
      className="pointer-events-none absolute top-1 z-10 max-w-56 -translate-x-1/2 rounded-md border border-border bg-surface-raised px-2.5 py-1.5 text-[11.5px] shadow-md"
      style={{ left: Math.max(90, Math.min(x, width - 90)) }}
    >
      {children}
    </div>
  );
}

/** The husk-upgrade note for a point, when the producing version changed;
 *  so a score step after an upgrade reads as "new checks", not regression. */
function versionNote(points: HistoryEntry[], i: number): string | null {
  return i > 0 && points[i].husk_version !== points[i - 1].husk_version
    ? `husk ${points[i].husk_version}: new checks may change counts`
    : null;
}

function ScoreChart({ points }: { points: HistoryEntry[] }) {
  const { ref, width } = useMeasuredWidth<HTMLDivElement>();
  const { hover, setHover } = useHover();

  const plotW = Math.max(0, width - PAD_L - PAD_R);
  const plotH = CHART_H - PAD_T - PAD_B;
  // Fixed 0-100 domain: the score is bounded and the honest zero keeps a
  // 62→65 wiggle from rendering as a mountain.
  const x = (i: number) =>
    PAD_L +
    (points.length === 1 ? plotW / 2 : (i / (points.length - 1)) * plotW);
  const y = (score: number) => PAD_T + (1 - score / 100) * plotH;
  const path = points
    .map(
      (p, i) =>
        `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(p.score).toFixed(1)}`,
    )
    .join(" ");
  // One hover handler on the (role="img") svg; nearest point to the cursor.
  const hoverAt = (mx: number) => {
    const step = points.length === 1 ? plotW : plotW / (points.length - 1);
    setHover(
      Math.max(0, Math.min(points.length - 1, Math.round((mx - PAD_L) / step))),
    );
  };

  return (
    <div ref={ref} className="relative" style={{ height: CHART_H }}>
      {width > 0 && (
        <svg
          width={width}
          height={CHART_H}
          role="img"
          aria-label={`Security score over ${points.length} scans, from ${points[0].score} to ${points[points.length - 1].score} out of 100`}
          onMouseMove={(e) => hoverAt(e.nativeEvent.offsetX)}
          onMouseLeave={() => setHover(null)}
        >
          {/* Recessive grid + y labels. */}
          {[0, 50, 100].map((v) => (
            <g key={v}>
              <line
                x1={PAD_L}
                x2={width - PAD_R}
                y1={y(v)}
                y2={y(v)}
                className="text-border"
                stroke="currentColor"
                strokeWidth={1}
              />
              <text
                x={PAD_L - 6}
                y={y(v) + 3.5}
                textAnchor="end"
                className="text-fg-subtle"
                fill="currentColor"
                fontSize={10}
              >
                {v}
              </text>
            </g>
          ))}
          <path
            d={path}
            fill="none"
            className="text-accent"
            stroke="currentColor"
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
          />
          {points.map((p, i) => (
            <circle
              key={p.at}
              cx={x(i)}
              cy={y(p.score)}
              r={hover === i ? 4.5 : 3}
              className="text-accent"
              fill="currentColor"
              // 2px surface ring so overlapping-adjacent dots stay separable.
              stroke="var(--surface)"
              strokeWidth={2}
            />
          ))}
          {/* Selective direct labels: first and latest only. */}
          {[0, points.length - 1].map((i) => (
            <text
              key={points[i].at}
              x={x(i)}
              y={y(points[i].score) - 8}
              textAnchor={i === 0 ? "start" : "end"}
              className="text-fg-muted"
              fill="currentColor"
              fontSize={10.5}
            >
              {points[i].score}
            </text>
          ))}
          {/* Crosshair on hover. */}
          {hover !== null && (
            <line
              x1={x(hover)}
              x2={x(hover)}
              y1={PAD_T}
              y2={CHART_H - PAD_B}
              className="text-border-strong"
              stroke="currentColor"
              strokeWidth={1}
              strokeDasharray="3 3"
            />
          )}
          {/* x labels: first and latest date. */}
          <text
            x={PAD_L}
            y={CHART_H - 5}
            className="text-fg-subtle"
            fill="currentColor"
            fontSize={10}
          >
            {dateLabel(points[0].at)}
          </text>
          <text
            x={width - PAD_R}
            y={CHART_H - 5}
            textAnchor="end"
            className="text-fg-subtle"
            fill="currentColor"
            fontSize={10}
          >
            {dateLabel(points[points.length - 1].at)}
          </text>
        </svg>
      )}
      {hover !== null && (
        <ChartTip x={x(hover)} width={width}>
          <b className="tabular-nums">{points[hover].score}/100</b>
          <span className="text-fg-muted">
            {" "}
            · {timeLabel(points[hover].at)}
          </span>
          {versionNote(points, hover) && (
            <span className="block text-fg-subtle">
              {versionNote(points, hover)}
            </span>
          )}
        </ChartTip>
      )}
    </div>
  );
}

function SeverityBars({ points }: { points: HistoryEntry[] }) {
  const { ref, width } = useMeasuredWidth<HTMLDivElement>();
  const { hover, setHover } = useHover();

  const plotW = Math.max(0, width - PAD_L - PAD_R);
  const plotH = CHART_H - PAD_T - PAD_B;
  const maxTotal = Math.max(1, ...points.map((p) => p.findings));
  const band = plotW / points.length;
  const barW = Math.max(4, Math.min(28, band * 0.6));
  const xMid = (i: number) => PAD_L + band * i + band / 2;

  return (
    <div ref={ref} className="relative" style={{ height: CHART_H }}>
      {width > 0 && (
        <svg
          width={width}
          height={CHART_H}
          role="img"
          aria-label={`Findings by severity across ${points.length} scans`}
          onMouseMove={(e) =>
            setHover(
              Math.max(
                0,
                Math.min(
                  points.length - 1,
                  Math.floor((e.nativeEvent.offsetX - PAD_L) / band),
                ),
              ),
            )
          }
          onMouseLeave={() => setHover(null)}
        >
          {[0, maxTotal].map((v) => (
            <g key={v}>
              <line
                x1={PAD_L}
                x2={width - PAD_R}
                y1={PAD_T + (1 - v / maxTotal) * plotH}
                y2={PAD_T + (1 - v / maxTotal) * plotH}
                className="text-border"
                stroke="currentColor"
                strokeWidth={1}
              />
              <text
                x={PAD_L - 6}
                y={PAD_T + (1 - v / maxTotal) * plotH + 3.5}
                textAnchor="end"
                className="text-fg-subtle"
                fill="currentColor"
                fontSize={10}
              >
                {v}
              </text>
            </g>
          ))}
          {points.map((p, i) => {
            // Stack from the baseline up, 2px surface gaps between segments.
            let yCursor = PAD_T + plotH;
            return (
              <g key={p.at} opacity={hover === null || hover === i ? 1 : 0.45}>
                {SEV_KEYS.map((k) => {
                  const count = p[k];
                  if (count === 0) return null;
                  const h = Math.max(2, (count / maxTotal) * plotH - 2);
                  yCursor -= h + 2;
                  return (
                    <rect
                      key={k}
                      x={xMid(i) - barW / 2}
                      y={yCursor + 2}
                      width={barW}
                      height={h}
                      rx={1.5}
                      className={SEV_TEXT[k]}
                      fill="currentColor"
                    />
                  );
                })}
              </g>
            );
          })}
          <text
            x={PAD_L}
            y={CHART_H - 5}
            className="text-fg-subtle"
            fill="currentColor"
            fontSize={10}
          >
            {dateLabel(points[0].at)}
          </text>
          <text
            x={width - PAD_R}
            y={CHART_H - 5}
            textAnchor="end"
            className="text-fg-subtle"
            fill="currentColor"
            fontSize={10}
          >
            {dateLabel(points[points.length - 1].at)}
          </text>
        </svg>
      )}
      {hover !== null && (
        <ChartTip x={xMid(hover)} width={width}>
          <b>{timeLabel(points[hover].at)}</b>
          <span className="text-fg-muted">
            {" "}
            · {points[hover].findings} finding
            {points[hover].findings === 1 ? "" : "s"}
          </span>
          <span className="mt-0.5 block">
            {SEV_KEYS.filter((k) => points[hover][k] > 0).map((k) => (
              <span key={k} className="mr-2 inline-flex items-center gap-1">
                <span
                  className={cn("size-1.5 rounded-full", SEV_TEXT[k])}
                  style={{ backgroundColor: "currentcolor" }}
                />
                <span className="tabular-nums">{points[hover][k]}</span>{" "}
                <span className="text-fg-muted">{SEV_LABEL[k]}</span>
              </span>
            ))}
          </span>
        </ChartTip>
      )}
    </div>
  );
}

/** Per-scan feed, newest first; every raw row (no daily collapse), which also
 *  makes it the charts' accessible table view. Each scan expands into what
 *  changed: the vulnerabilities patched and the findings that appeared. */
function Feed({ entries }: { entries: HistoryEntry[] }) {
  const newestFirst = [...entries].reverse();
  const [openAt, setOpenAt] = useState<string | null>(null);
  // A scan that changed nothing and a neighbour that changed nothing are one
  // statement over two timestamps. Only neighbours merge, and only when the
  // whole row and its drill-down are identical, so a collapsed run says exactly
  // what each of its members said.
  const quiet = (e: HistoryEntry) =>
    e.new_count === 0 && e.resolved_count === 0 && e.fixes_applied === 0;
  const runs = runsOf(newestFirst, (e) =>
    quiet(e)
      ? `quiet|${e.score}|${e.findings}|${e.packages}|${e.husk_version}|${SEV_KEYS.map((k) => e[k]).join("/")}`
      : e.at,
  );
  return (
    <Card className="px-0 py-0">
      <span className="block border-b border-border px-4 py-2.5 text-[13px] font-medium text-fg">
        Every scan{" "}
        <span className="font-normal text-fg-subtle">
          · {entries.length} recorded · click a scan for details
        </span>
      </span>
      <ul>
        {runs.map((run) => {
          const e = run[0];
          const oldest = run[run.length - 1];
          // `entries` is oldest-first; the previous scan is one further down
          // the reversed list.
          const prev = newestFirst[newestFirst.indexOf(oldest) + 1];
          const upgraded = prev && prev.husk_version !== e.husk_version;
          const open = openAt === e.at;
          return (
            <li key={e.at} className="border-t border-border first:border-0">
              <button
                type="button"
                onClick={() => setOpenAt(open ? null : e.at)}
                aria-expanded={open}
                className={cn(
                  "flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 text-left transition-colors focus-ring",
                  open ? "bg-surface" : "hover:bg-surface",
                )}
              >
                <span className="shrink-0 text-fg-subtle">
                  {open ? (
                    <ChevronDown size={13} />
                  ) : (
                    <ChevronRight size={13} />
                  )}
                </span>
                <span className="w-28 shrink-0 text-[12px] text-fg-subtle">
                  {run.length > 1
                    ? `${timeLabel(oldest.at)} to ${timeLabel(e.at)}`
                    : timeLabel(e.at)}
                </span>
                <span className="w-16 shrink-0 text-[12.5px] tabular-nums">
                  {e.score}
                  <span className="text-fg-subtle">/100</span>
                </span>
                <span className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1 text-[12.5px]">
                  {e.new_count > 0 && (
                    <span className="text-warning tabular-nums">
                      +{e.new_count} new
                    </span>
                  )}
                  {e.resolved_count > 0 && (
                    <span className="text-success tabular-nums">
                      ✓ {e.resolved_count} resolved
                    </span>
                  )}
                  {e.fixes_applied > 0 && (
                    <span className="flex items-center gap-1 rounded-full border border-border bg-surface px-2 py-0.5 text-[11px] text-fg-muted tabular-nums">
                      <Wrench size={11} />
                      {e.fixes_applied} Husk fix
                      {e.fixes_applied === 1 ? "" : "es"}
                    </span>
                  )}
                  {quiet(e) && (
                    <span className="text-fg-subtle tabular-nums">
                      {run.length > 1 ? `${run.length} scans, ` : ""}no change
                    </span>
                  )}
                  {upgraded && (
                    <span className="text-[11px] text-fg-subtle">
                      husk {e.husk_version}: new checks may change counts
                    </span>
                  )}
                </span>
                <span className="shrink-0 text-[12px] text-fg-subtle tabular-nums">
                  {e.findings} open
                </span>
              </button>
              {open && <ScanDetail entry={e} />}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

/** What one scan changed: severity composition, then the resolved and new
 *  findings by name; the drill-down the feed row expands into. */
function ScanDetail({ entry }: { entry: HistoryEntry }) {
  const resolved = entry.resolved ?? [];
  const added = entry.new ?? [];
  const fixes = entry.fixes ?? [];
  const changed =
    entry.new_count > 0 || entry.resolved_count > 0 || entry.fixes_applied > 0;
  // Rows written by older husk versions carry counts but no detail lists.
  const detailMissing =
    changed &&
    resolved.length === 0 &&
    added.length === 0 &&
    fixes.length === 0;

  return (
    <div className="flex flex-col gap-3 border-t border-border bg-surface px-4 py-3 pl-10">
      <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px] text-fg-subtle">
        {SEV_KEYS.filter((k) => entry[k] > 0).map((k) => (
          <span key={k} className="inline-flex items-center gap-1">
            <span
              className={cn("size-1.5 rounded-full", SEV_TEXT[k])}
              style={{ backgroundColor: "currentcolor" }}
            />
            <span className="tabular-nums">{entry[k]}</span> {SEV_LABEL[k]}
          </span>
        ))}
        <span className="tabular-nums">{entry.packages} packages scanned</span>
        <span>husk {entry.husk_version}</span>
      </span>

      {fixes.length > 0 && (
        <div>
          <span className="flex items-center gap-1.5 text-[12px] font-medium text-fg">
            <Wrench size={11} className="shrink-0 text-fg-subtle" />
            Fixes Husk applied in this window ({entry.fixes_applied})
          </span>
          <ul className="mt-1 flex flex-col gap-0.5">
            {/* A label can repeat (same package fixed in two manifests). */}
            {groupByLabel(fixes, (label) => label).map(({ label, items }) => (
              <li
                key={label}
                className="truncate font-mono text-[12px] text-fg-muted"
                title={label}
              >
                {label}
                {items.length > 1 ? ` ×${items.length}` : ""}
              </li>
            ))}
          </ul>
        </div>
      )}
      {resolved.length > 0 && (
        <FindingList
          title={`Resolved since previous scan (${entry.resolved_count})`}
          note={
            entry.resolved_count > resolved.length
              ? `showing the worst ${resolved.length}`
              : undefined
          }
          items={resolved}
          tone="success"
        />
      )}
      {added.length > 0 && (
        <FindingList
          title={`New in this scan (${entry.new_count})`}
          note={
            entry.new_count > added.length
              ? `showing the worst ${added.length}`
              : undefined
          }
          items={added}
          tone="warning"
        />
      )}
      {detailMissing && (
        <p className="text-[12px] text-fg-subtle">
          Detail wasn't recorded for this scan (older Husk version). Newer scans
          list exactly what changed and what Husk fixed.
        </p>
      )}
      {fixes.length > 0 &&
        entry.new_count === 0 &&
        entry.resolved_count === 0 && (
          <p className="text-[12px] text-fg-subtle">
            Findings were unchanged since the previous scan of this target;
            fixes show as resolved findings once a later scan confirms them.
          </p>
        )}
      {!changed && (
        <p className="text-[12px] text-fg-subtle">
          Nothing changed since the previous scan of this target.
        </p>
      )}
    </div>
  );
}

function FindingList({
  title,
  note,
  items,
  tone,
}: {
  title: string;
  note?: string;
  items: HistoryFinding[];
  tone: "success" | "warning";
}) {
  return (
    <div>
      <span
        className={cn(
          "text-[12px] font-medium",
          tone === "success" ? "text-success" : "text-warning",
        )}
      >
        {tone === "success" ? "✓ " : "+ "}
        {title}
        {note && <span className="font-normal text-fg-subtle"> · {note}</span>}
      </span>
      <ul className="mt-1 flex flex-col gap-0.5">
        {items.map((f) => (
          <li
            key={f.id}
            className="flex min-w-0 items-center gap-2 text-[12.5px]"
          >
            <span
              className={cn(
                "w-14 shrink-0 text-[11px] uppercase tracking-wide",
                SEV_TEXT[f.severity],
              )}
            >
              {f.severity}
            </span>
            <span className="min-w-0 flex-1 truncate text-fg" title={f.title}>
              {f.title}
            </span>
            {f.package && (
              <span
                className="max-w-48 shrink-0 truncate font-mono text-[11.5px] text-fg-muted"
                title={f.package}
              >
                {f.package}
              </span>
            )}
            {f.by_husk && (
              <span className="flex shrink-0 items-center gap-1 rounded-full border border-border bg-bg px-2 py-0.5 text-[10.5px] text-fg-muted">
                <Wrench size={10} />
                Fixed by Husk
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
