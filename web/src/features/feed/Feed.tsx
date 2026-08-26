import {
  Button,
  cn,
  DataTable,
  type DataTableColumn,
  EmptyState,
  TableScroll,
} from "@huskdev/ui";
import { ListTree, X } from "lucide-react";
import { useMemo, useState } from "react";
import { type ScanReport, type Severity, useLive, useMachine } from "@/lib/api";
import { PathLabel } from "@/lib/path";
import { useResizableDetail } from "@/lib/useResizableDetail";
import {
  FilterMenu,
  type Group,
  GroupDetail,
  groupFindings,
  SearchBox,
  useIgnoreState,
} from "../scan/Scan";
import { SEV_TEXT, SeverityBadge } from "../scan/severity";

const RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};
/** Rows with nothing wrong sort below every severity. */
const CLEAN = 5;

// One screenful of rows at a time: a home-wide scan carries tens of thousands
// of packages, and every one of them in the DOM is a frozen tab.
const PAGE = 200;

interface Row {
  key: string;
  severity?: Severity;
  what: string;
  where: string;
  detail: string;
  path?: string;
  /** Set on a finding row; the detail pane shows this finding's group. */
  findingId?: string;
}

const coord = (p: { ecosystem: string; name: string; version: string }) =>
  `${p.ecosystem}/${p.name}@${p.version}`;

/** Both scans flattened into one list: a row per finding, then a row per
 *  package no finding mentions. Ordered by severity alone. No project,
 *  category, or path grouping, which is the whole point of this view. */
function buildRows(reports: (ScanReport | undefined)[]): Row[] {
  const rows = new Map<string, Row>();
  const flagged = new Set<string>();
  for (const report of reports) {
    for (const f of report?.findings ?? []) {
      if (f.package) flagged.add(coord(f.package));
      rows.set(f.id, {
        key: f.id,
        severity: f.severity,
        what: f.package ? `${f.package.name} ${f.package.version}` : f.title,
        where: f.package?.ecosystem ?? f.category,
        detail: f.package ? f.title : f.summary,
        path: f.path ?? f.package?.manifest_path,
        findingId: f.id,
      });
    }
  }
  for (const report of reports) {
    for (const p of report?.packages ?? []) {
      const key = coord(p);
      if (flagged.has(key) || rows.has(key)) continue;
      rows.set(key, {
        key,
        what: `${p.name} ${p.version}`,
        where: p.ecosystem,
        detail: "no known issues",
      });
    }
  }
  return [...rows.values()].sort(
    (a, b) =>
      (a.severity ? RANK[a.severity] : CLEAN) -
      (b.severity ? RANK[b.severity] : CLEAN),
  );
}

/** Every field the row puts on screen, so a search reads as narrowing the
 *  visible list rather than querying something invisible. */
const haystack = (r: Row) =>
  `${r.what} ${r.where} ${r.detail} ${r.path ?? ""}`.toLowerCase();

function tally<K>(rows: Row[], key: (r: Row) => K | undefined) {
  const counts = new Map<K, number>();
  for (const r of rows) {
    const k = key(r);
    if (k !== undefined) counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return counts;
}

const COLUMNS: DataTableColumn<Row>[] = [
  {
    key: "severity",
    header: "Severity",
    className: "w-[7.5rem] whitespace-nowrap",
    cell: (r) =>
      r.severity ? (
        <SeverityBadge severity={r.severity} />
      ) : (
        <span className="text-fg-subtle">clean</span>
      ),
  },
  {
    key: "what",
    header: "Item",
    cell: (r) => (
      // The width lives on the content, not the cell: an auto-layout table
      // grows its column to whatever the longest row holds otherwise.
      <span className="block w-[16rem] truncate text-fg" title={r.what}>
        {r.what}
      </span>
    ),
  },
  {
    key: "where",
    header: "Source",
    className: "w-[7rem] whitespace-nowrap",
    cell: (r) => <span className="text-fg-muted">{r.where}</span>,
  },
  {
    key: "detail",
    header: "Detail",
    cell: (r) => (
      <span className="flex w-[24rem] min-w-0 flex-col gap-0.5">
        <span className="truncate text-fg-muted" title={r.detail}>
          {r.detail}
        </span>
        {r.path && <PathLabel path={r.path} />}
      </span>
    ),
  },
];

/** A package no finding mentions: the coordinate and the fact that nothing is
 *  known against it. There is nothing to fix, so no fix actions. */
function CleanDetail({ row }: { row: Row }) {
  return (
    <div className="min-w-0">
      <h2 className="text-base font-semibold leading-snug [overflow-wrap:anywhere]">
        {row.what}
      </h2>
      <p className="mt-1 text-[12.5px] text-fg-subtle">{row.where}</p>
      <p className="mt-3.5 text-[13.5px] leading-relaxed text-fg">
        No advisory matched this package in the last scan. Nothing to fix here.
      </p>
    </div>
  );
}

/** The feed: every dependency and every issue on this machine in one list,
 *  worst first. The Scan and Projects views answer "what is wrong where"; this
 *  one answers "what is on this computer at all". */
export function Feed({
  onOpenGuide,
}: {
  onOpenGuide?: (taskId: string) => void;
} = {}) {
  const live = useLive();
  const machine = useMachine();
  const rows = useMemo(
    () => buildRows([machine.data?.report, live.data?.report]),
    [machine.data?.report, live.data?.report],
  );
  const [shown, setShown] = useState(PAGE);
  const [selected, setSelected] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [sev, setSev] = useState<Severity | null>(null);
  const [source, setSource] = useState<string | null>(null);

  // Search runs first, so every menu's counts describe the set the query left,
  // and each menu counts over the slice its own value does not constrain.
  const searched = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q === "" ? rows : rows.filter((r) => haystack(r).includes(q));
  }, [rows, query]);
  const bySev =
    sev === null ? searched : searched.filter((r) => r.severity === sev);
  const visible =
    source === null ? bySev : bySev.filter((r) => r.where === source);
  const sevOptions = useMemo(() => {
    const counts = tally(searched, (r) => r.severity);
    return (Object.keys(RANK) as Severity[])
      .filter((id) => counts.get(id))
      .map((id) => ({
        id,
        label: id,
        count: counts.get(id) ?? 0,
        dot: SEV_TEXT[id],
      }));
  }, [searched]);
  const sourceOptions = useMemo(() => {
    const counts = tally(bySev, (r) => r.where);
    return [...counts]
      .sort((a, b) => b[1] - a[1])
      .map(([id, count]) => ({ id, label: id, count }));
  }, [bySev]);
  const filtered = query.trim() !== "" || sev !== null || source !== null;

  // Both scans' findings behave as one report here, the same way the rows do,
  // so a feed row opens the same group detail (and ignore state) the Scan and
  // Projects tabs show.
  const merged = useMemo(
    () => ({
      findings: [
        ...(machine.data?.report?.findings ?? []),
        ...(live.data?.report?.findings ?? []),
      ],
      ignored: [
        ...(machine.data?.report?.ignored ?? []),
        ...(live.data?.report?.ignored ?? []),
      ],
    }),
    [machine.data?.report, live.data?.report],
  );
  const ignore = useIgnoreState(merged);
  const groupOf = useMemo(() => {
    const byFinding = new Map<string, Group>();
    for (const g of groupFindings(merged.findings))
      for (const f of g.items) byFinding.set(f.id, g);
    return byFinding;
  }, [merged.findings]);

  const { containerRef, dragging, detailStyle, handle } = useResizableDetail({
    minList: 320,
  });
  const selectedRow = rows.find((r) => r.key === selected);
  const detailGroup = selectedRow?.findingId
    ? groupOf.get(selectedRow.findingId)
    : undefined;

  if (!live.data && !machine.data) {
    return (
      <div className="mx-auto w-full max-w-2xl px-6 pt-16">
        <EmptyState
          icon={<ListTree size={24} />}
          title="Nothing scanned yet"
          description="Run a scan and everything Husk finds shows up here, worst first."
        />
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={cn(
        "flex min-w-0 flex-col lg:h-full lg:flex-row",
        dragging && "cursor-col-resize select-none",
      )}
    >
      <div className="min-w-0 flex-1 lg:overflow-auto">
        <div className="flex min-w-0 flex-col gap-4 px-6 py-5">
          <p className="text-[13px] text-fg-muted">
            <span className="tabular-nums text-fg">{visible.length}</span>{" "}
            {filtered ? `of ${rows.length} items` : "items"} from the machine
            and folder scans, sorted by severity.
          </p>

          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <SearchBox
              value={query}
              onChange={setQuery}
              placeholder="Search items"
            />
            <FilterMenu
              label="All severities"
              value={sev}
              options={sevOptions}
              onChange={(id) => setSev((id as Severity) ?? null)}
            />
            <FilterMenu
              label="All sources"
              value={source}
              options={sourceOptions}
              onChange={setSource}
            />
            {filtered && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setQuery("");
                  setSev(null);
                  setSource(null);
                }}
              >
                <X size={13} /> Clear
              </Button>
            )}
          </div>
          {/* The columns are fixed-width by design, so a narrow list pane
              scrolls the table instead of squeezing the path out of it. */}
          <TableScroll>
            <DataTable
              columns={COLUMNS}
              rows={visible.slice(0, shown)}
              rowKey={(r) => r.key}
              onRowClick={(r) => setSelected(r.key)}
              isRowSelected={(r) => r.key === selected}
            />
          </TableScroll>
          {shown < visible.length && (
            <button
              type="button"
              onClick={() => setShown((n) => n + PAGE)}
              className="w-fit rounded-md border border-border bg-bg px-3 py-1.5 text-[12px] text-fg transition-colors hover:bg-surface focus-ring"
            >
              Show {Math.min(PAGE, visible.length - shown)} more
            </button>
          )}
        </div>
      </div>

      {handle}

      <div className="min-w-0 lg:overflow-auto" style={detailStyle}>
        {detailGroup ? (
          <div className="px-6 py-7">
            <GroupDetail
              key={detailGroup.items[0]?.id ?? detailGroup.title}
              g={detailGroup}
              isMuted={ignore.isMuted}
              muteIds={ignore.muteIds}
              unmuteIds={ignore.unmuteIds}
              busy={ignore.busy}
              muteMsg={ignore.muteMsg}
              onOpenGuide={onOpenGuide}
            />
          </div>
        ) : selectedRow ? (
          <div className="px-6 py-7">
            <CleanDetail row={selectedRow} />
          </div>
        ) : (
          <p className="p-8 text-center text-[13px] text-fg-subtle">
            Select an item.
          </p>
        )}
      </div>
    </div>
  );
}
