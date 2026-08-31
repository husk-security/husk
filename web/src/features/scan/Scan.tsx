import {
  Badge,
  Button,
  cn,
  EmptyState,
  Input,
  PageHeader,
  Spinner,
} from "@huskdev/ui";
import {
  BookOpen,
  ChevronDown,
  Download,
  Hexagon,
  RotateCw,
  Search,
  Sparkles,
  Square,
  TriangleAlert,
  X,
} from "lucide-react";
import {
  type KeyboardEvent,
  type ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { AI_AGENT_USAGE_DOCS_URL } from "@/features/agent-setup/AgentSetup";
import { advisoryLinks } from "@/features/guide/proposals";
import {
  type Activity,
  type Project as ApiProject,
  type CategoryRollup,
  type Finding,
  type LiveScan as LiveScanData,
  type PostureSummary,
  type ProjectBucket,
  type ScanDelta,
  type ScanReport,
  type Severity,
  useLive,
  useMachine,
  useMachineRescan,
  useMuteFinding,
  usePolicyStatus,
  useRescan,
  useRules,
  useStopScan,
  useUnmuteFinding,
} from "@/lib/api";
import { groupByLabel } from "@/lib/collapse";
import {
  type EcosystemFamily,
  ecosystemFamily,
  FAMILY_ORDER,
} from "@/lib/ecosystems";
import {
  downloadReport,
  EXPORT_LABEL,
  type ExportFormat,
} from "@/lib/exportReport";
import { PathLabel, Places, shortPath } from "@/lib/path";
import { useResizableDetail } from "@/lib/useResizableDetail";
import { DirPicker } from "./DirPicker";
import { locationOf, SourceView } from "./SourceView";
import { SEV_TEXT, SeverityBadge } from "./severity";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};
const loc = (f: Finding) =>
  f.path ? `${shortPath(f.path)}${f.line ? `:${f.line}` : ""}` : null;

/** The file the source dialog opens for one affected row, and every line
 *  flagged inside it. A coordinate row can span several lockfiles; the first is
 *  the one that opens, and the dialog prints the path it read. */
function sourceTarget(items: Finding[]) {
  const places = items
    .map(locationOf)
    .filter((p): p is { path: string; line?: number } => !!p);
  const first = places[0];
  if (!first) return null;
  const lines = places
    .filter((p) => p.path === first.path && p.line)
    .map((p) => p.line as number);
  return { path: first.path, lines: [...new Set(lines)].sort((a, b) => a - b) };
}

/** The distinct files a set of findings sits in. */
const manifests = (items: Finding[]) => [
  ...new Set(
    items
      .map((f) => f.path ?? f.package?.manifest_path)
      .filter((p): p is string => !!p),
  ),
];

const groupDomId = (key: string) =>
  `scan-group-${key.replace(/[^A-Za-z0-9_-]/g, "-")}`;

type Exploit = { kev: boolean; epss?: number };

// A run of findings of the same kind (title) in the same project. The Scan view
// shows one row per group; collapsing thousands of near-identical findings into
// a handful of actionable, countable entries (the Linear/Sentry pattern).
export type Group = {
  key: string;
  severity: Severity;
  title: string;
  category: string;
  owner: string;
  /** Subfolder within the owning project ("" = project root / unknown). */
  folder: string;
  source: string;
  ecosystem?: string;
  exploit?: Exploit;
  items: Finding[];
};

// Group on the server-assigned project id (joins to `report.projects`); the
// server attaches one to every finding, so "system" only covers a malformed row.
const ownerOf = (f: Finding) => f.project_id ?? "system";

// One row per subject, straight off the server, which counted the same subjects
// into `CategoryRollup.subjects`. Deriving it here again is how the list and the
// headline came to disagree; the fallback only covers a pre-`subject` report.
const groupKeyOf = (f: Finding) =>
  f.subject ??
  (f.package
    ? `${ownerOf(f)} ${f.category} ${f.package.ecosystem}:${f.package.name}`
    : `${ownerOf(f)} ${f.title}`);

// A coordinate group of >1 finding is labeled by its package, not one arbitrary
// advisory; everything else keeps its finding title.
const groupLabel = (g: Group) =>
  g.items.length > 1 && g.items[0].package ? g.items[0].package.name : g.title;

// The subfolder a finding lives in, relative to its project root: the file's
// directory capped at two path segments (`web`, `packages/foo`, `tst/npm-app`).
// "" for root-level findings or when the path doesn't sit under the root.
function subfolderOf(path: string, root: string): string {
  const prefix = root.endsWith("/") ? root : `${root}/`;
  if (!path.startsWith(prefix)) return "";
  const segs = path.slice(prefix.length).split("/");
  segs.pop(); // the file itself
  return segs.slice(0, 2).join("/");
}

// The worst exploit signal across a group: KEV wins, else the highest EPSS.
function worstExploit(
  a: Exploit | undefined,
  b: Finding["exploit"],
): Exploit | undefined {
  if (!b) return a;
  if (!a) return { kev: b.kev, epss: b.epss };
  return {
    kev: a.kev || b.kev,
    epss: Math.max(a.epss ?? 0, b.epss ?? 0) || undefined,
  };
}

// The subject already separates two subfolders of one project; `folderOf` only
// labels the row (main list only, where a project path is on screen to hang it
// off).
export function groupFindings(
  findings: Finding[],
  folderOf?: (f: Finding) => string,
): Group[] {
  const map = new Map<string, Group>();
  for (const f of findings) {
    const owner = ownerOf(f);
    const folder = folderOf?.(f) ?? "";
    const key = groupKeyOf(f);
    const g = map.get(key);
    if (g) {
      g.items.push(f);
      if (RANK[f.severity] < RANK[g.severity]) g.severity = f.severity;
      g.exploit = worstExploit(g.exploit, f.exploit);
      if (!g.ecosystem && f.package) g.ecosystem = f.package.ecosystem;
    } else {
      map.set(key, {
        key,
        severity: f.severity,
        title: f.title,
        category: f.category,
        owner,
        folder,
        source: f.source,
        ecosystem: f.package?.ecosystem,
        exploit: f.exploit
          ? { kev: f.exploit.kev, epss: f.exploit.epss }
          : undefined,
        items: [f],
      });
    }
  }
  // Most-dangerous-first: KEV, then severity, then biggest groups.
  return Array.from(map.values()).sort(
    (a, b) =>
      Number(b.exploit?.kev ?? false) - Number(a.exploit?.kev ?? false) ||
      RANK[a.severity] - RANK[b.severity] ||
      b.items.length - a.items.length,
  );
}

// Human label for a server project: the ~-relative path, or its given name
// (config/host project).
function projectLabel(p: ApiProject): string {
  if (p.kind === "config-location") return p.name;
  return shortPath(p.root);
}

// A project's worth of current, filtered finding groups. The server already
// owns project ordering and the active/dormant posture decision; this view
// model only joins those projects to the rows the current filters kept.
const SMALL_PROJECT = 10;
type ProjectGroup = {
  owner: string;
  displayPath: string;
  bucket: ProjectBucket;
  activity: Activity;
  byCategory: CategoryRollup[];
  groups: Group[];
  defaultShown: number;
  hasKev: boolean;
};

const ACTIVITY_LABEL: Record<Activity, string> = {
  active: "active",
  recent: "recent",
  dormant: "dormant",
  abandoned: "abandoned",
};

function ActivityPill({ activity }: { activity: Activity }) {
  return (
    <span
      className={cn(
        "shrink-0 rounded-full border px-1.5 py-px text-[9.5px] tracking-wide",
        activity === "active"
          ? "border-success/40 text-success"
          : "border-border text-fg-subtle",
      )}
    >
      {ACTIVITY_LABEL[activity]}
    </span>
  );
}

function projectView(
  owner: string,
  displayPath: string,
  bucket: ProjectBucket,
  activity: Activity,
  byCategory: CategoryRollup[],
  groups: Group[],
  sevAll: boolean,
): ProjectGroup {
  const items = [...groups].sort(
    (a, b) =>
      Number(b.exploit?.kev ?? false) - Number(a.exploit?.kev ?? false) ||
      RANK[a.severity] - RANK[b.severity] ||
      b.items.length - a.items.length,
  );
  const criticalCount = items.filter(
    (group) => group.severity === "critical",
  ).length;
  return {
    owner,
    displayPath,
    bucket,
    activity,
    byCategory,
    groups: items,
    defaultShown: !sevAll
      ? items.length
      : items.length <= SMALL_PROJECT
        ? items.length
        : criticalCount,
    hasKev: items.some((group) => group.exploit?.kev),
  };
}

// Preserve the server's project order exactly: needs-attention first, then
// rank score, recency, and name (see score.rs). Any malformed/older report rows
// that do not join still get a final fallback project instead of disappearing.
function buildProjects(
  groups: Group[],
  sevAll: boolean,
  serverProjects: ApiProject[],
): ProjectGroup[] {
  const byOwner = new Map<string, Group[]>();
  for (const group of groups) {
    const owned = byOwner.get(group.owner) ?? [];
    owned.push(group);
    byOwner.set(group.owner, owned);
  }

  const projects: ProjectGroup[] = [];
  for (const project of serverProjects) {
    const owned = byOwner.get(project.id);
    if (!owned?.length) continue;
    projects.push(
      projectView(
        project.id,
        projectLabel(project),
        project.posture?.bucket ?? "needs-attention",
        project.activity,
        project.rollup.by_category ?? [],
        owned,
        sevAll,
      ),
    );
    byOwner.delete(project.id);
  }

  for (const [owner, owned] of byOwner) {
    projects.push(
      projectView(
        owner,
        owner === "system" ? "System & user config" : shortPath(owner),
        "needs-attention",
        "recent",
        [],
        owned,
        sevAll,
      ),
    );
  }
  return projects;
}

// Where a row lives, always shown under the title: the file itself (with the
// line for a single hit), the shared manifest for a package group, or
// project-path/subfolder when the group spans files.
function whereLabel(g: Group, projectPath: (owner: string) => string): string {
  const f = g.items[0];
  const p = f.path ?? f.package?.manifest_path;
  if (p && (g.items.length === 1 || f.package)) {
    const line = g.items.length === 1 && f.path && f.line ? `:${f.line}` : "";
    return `${shortPath(p)}${line}`;
  }
  const base = projectPath(g.owner);
  return g.folder ? `${base}/${g.folder}` : base;
}

// Short, scannable category labels for the per-project rollup line.
const CATEGORY_LABEL: Record<string, string> = {
  secret: "secrets",
  malware: "malware",
  typosquat: "typosquats",
  "risky-agent-config": "agent config",
  "prompt-injection": "prompt injection",
  "exposed-config": "host config",
  "install-hardening": "install hardening",
  vulnerability: "vulnerable dependencies",
  package: "packages",
  "lifecycle-script": "lifecycle",
  other: "other",
};
const categoryLabel = (id: string) => CATEGORY_LABEL[id] ?? id;

/** Fine-grained age for the header timestamp. `husk web` serves the cached
 *  report on startup, so "when is this from" must be readable at a glance —
 *  minutes here, unlike the coarse hours/days of the stale banner. The exact
 *  local datetime lives in the element's tooltip. */
function scannedAgo(generatedAt: string): string {
  const mins = Math.max(
    0,
    Math.floor((Date.now() - new Date(generatedAt).getTime()) / 60_000),
  );
  if (mins < 1) return "scanned just now";
  if (mins < 120) return `scanned ${mins} minute${mins === 1 ? "" : "s"} ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `scanned ${hours} hours ago`;
  return `scanned ${Math.floor(hours / 24)} days ago`;
}

/** One compartment of the left dashboard: a bordered box with an eyebrow
 *  header and an optional right-hand control. Every section uses it, so the
 *  pane reads as distinct panels instead of a scroll of loose rows. */
function Panel({
  title,
  count,
  action,
  collapsible = false,
  defaultOpen = true,
  disabled = false,
  className,
  children,
  "data-tour": dataTour,
}: {
  title: string;
  count?: number;
  /** Rendered at the right of the header; a sibling of the collapse toggle,
   *  never nested inside it, so it acts without also collapsing the panel. */
  action?: ReactNode;
  collapsible?: boolean;
  defaultOpen?: boolean;
  /** Nothing to show: the header stays (the compartment must stay visible even
   *  at zero) but it no longer opens. */
  disabled?: boolean;
  className?: string;
  children: ReactNode;
  "data-tour"?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const shown = collapsible ? open && !disabled : true;
  const heading = (
    <>
      <span className="text-[11.5px] uppercase tracking-wider text-fg-muted">
        {title}
      </span>
      {count !== undefined && (
        <span className="text-[12px] tabular-nums text-fg-subtle">{count}</span>
      )}
    </>
  );
  return (
    <section
      data-tour={dataTour}
      className={cn(
        "min-w-0 overflow-hidden rounded-lg border border-border bg-surface",
        className,
      )}
    >
      <div
        className={cn(
          "flex items-center gap-2 px-3.5 py-2",
          shown && "border-b border-border",
        )}
      >
        {collapsible ? (
          <button
            type="button"
            onClick={() => !disabled && setOpen((o) => !o)}
            aria-expanded={shown}
            disabled={disabled}
            className="flex min-w-0 flex-1 items-center gap-1.5 text-left transition-colors hover:text-fg focus-ring disabled:cursor-default"
          >
            <ChevronDown
              size={13}
              className={cn(
                "shrink-0 text-fg-subtle transition-transform",
                !shown && "-rotate-90",
                disabled && "opacity-40",
              )}
            />
            {heading}
          </button>
        ) : (
          <div className="flex min-w-0 flex-1 items-center gap-1.5">
            {heading}
          </div>
        )}
        {action}
      </div>
      {shown && <div className="px-3.5 py-2.5">{children}</div>}
    </section>
  );
}

/** One number in the Overview panel. */
function Stat({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: ReactNode;
  sub?: string;
  tone?: string;
}) {
  return (
    <div className="min-w-0">
      <p className="truncate text-[10.5px] uppercase tracking-wider text-fg-subtle">
        {label}
      </p>
      <p className={cn("mt-0.5 text-lg tabular-nums", tone ?? "text-fg")}>
        {value}
      </p>
      {sub && <p className="truncate text-[11px] text-fg-subtle">{sub}</p>}
    </div>
  );
}

/** The state of the scan as numbers: what needs attention, what is open, what
 *  is being exploited right now, and which way the score moved. Report-wide
 *  truth — unlike the Filters panel, nothing here reacts to the filters. */
function Overview({
  summary,
  delta,
  openCount,
  exploited,
  report,
  running,
  idle,
}: {
  summary?: PostureSummary;
  delta?: ScanDelta;
  openCount: number;
  exploited: number;
  report?: ScanReport;
  running?: boolean;
  idle: boolean;
}) {
  const files = (report?.benchmarks ?? []).reduce(
    (n, b) => n + b.files_checked,
    0,
  );
  const coverage = files
    ? `Scanned ${files.toLocaleString()} files and ${(report?.stats.packages ?? 0).toLocaleString()} packages`
    : null;
  return (
    <Panel title="Overview">
      {!summary && (
        <p className="text-[13px] text-fg-subtle">
          {running
            ? "Scanning. Results appear as they arrive."
            : idle
              ? "Nothing scanned yet."
              : "No summary available for this scan."}
        </p>
      )}
      {summary && (
        <>
          <div className="grid grid-cols-2 gap-x-4 gap-y-3 @xl:grid-cols-4">
            <Stat
              label="Need attention"
              value={
                <>
                  {summary.projects_needing_attention}
                  <span className="text-fg-subtle">
                    /{summary.projects_total}
                  </span>
                </>
              }
              sub={summary.projects_total === 1 ? "project" : "projects"}
            />
            <Stat label="Open findings" value={openCount} sub="unresolved" />
            <Stat
              label="Exploited"
              value={exploited}
              sub="CISA KEV"
              tone={exploited > 0 ? "text-severity-critical" : undefined}
            />
            {delta && (
              <Stat
                label="Security score"
                value={
                  <>
                    {delta.previous_score !== delta.score && (
                      <span className="text-fg-subtle">
                        {delta.previous_score} →{" "}
                      </span>
                    )}
                    {delta.score}
                    <span className="text-fg-subtle">/100</span>
                  </>
                }
                sub={
                  delta.resolved_count > 0
                    ? `${delta.resolved_count} resolved since last scan`
                    : undefined
                }
              />
            )}
          </div>

          {summary.by_category.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1 border-t border-border pt-2.5">
              {summary.by_category.map((c) => (
                <span
                  key={c.category}
                  className="whitespace-nowrap text-[11.5px] text-fg-muted"
                >
                  <span className="tabular-nums text-fg">{c.subjects}</span>{" "}
                  {categoryLabel(c.category)}
                </span>
              ))}
            </div>
          )}

          {coverage && (
            <p className="mt-2 text-[11px] text-fg-subtle">{coverage}</p>
          )}
        </>
      )}
    </Panel>
  );
}

/** Free-text filter over the finding rows. Matches what the row itself shows
 *  (title, package, location) plus the type, so a search reads as narrowing
 *  the list on screen rather than querying something invisible. */
export function SearchBox({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
}) {
  return (
    <div className="relative min-w-0 flex-1 @xl:max-w-64">
      <Search
        size={14}
        aria-hidden
        className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-fg-subtle"
      />
      <Input
        type="text"
        value={value}
        aria-label={placeholder}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="pl-8"
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange("")}
          aria-label="Clear search"
          className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded-full p-0.5 text-fg-subtle transition-colors hover:text-fg focus-ring"
        >
          <X size={12} />
        </button>
      )}
    </div>
  );
}

type FilterOption = {
  id: string;
  label: string;
  count: number;
  /** Severity hue class; renders the filled marker that carries the level. */
  dot?: string;
  mono?: boolean;
};

/** A menu button per filter axis: closed it names the current value, open it
 *  lists every option with its live count. `groups` sections the list (the
 *  ecosystem families) without changing what an option is. */
export function FilterMenu({
  label,
  value,
  options,
  groups,
  onChange,
}: {
  label: string;
  value: string | null;
  options: FilterOption[];
  groups?: { family: string; options: FilterOption[] }[];
  onChange: (id: string | null) => void;
}) {
  const [open, setOpen] = useState(false);
  const active = options.find((o) => o.id === value);
  const pick = (id: string | null) => {
    onChange(id);
    setOpen(false);
  };
  const row = (o: FilterOption) => (
    <button
      key={o.id}
      type="button"
      onClick={() => pick(o.id === value ? null : o.id)}
      aria-pressed={o.id === value}
      className={cn(
        "flex w-full items-center gap-2 px-3 py-1.5 text-left text-[13.5px] transition-colors hover:bg-surface-raised focus-ring",
        o.id === value ? "bg-accent-subtle text-fg" : "text-fg-muted",
      )}
    >
      {o.dot && (
        <Hexagon
          size={9}
          strokeWidth={2}
          fill="currentColor"
          className={cn("shrink-0", o.dot)}
        />
      )}
      <span className={cn("min-w-0 flex-1 truncate", o.mono && "font-mono")}>
        {o.label}
      </span>
      <span className="shrink-0 text-[11px] tabular-nums text-fg-subtle">
        {o.count}
      </span>
    </button>
  );

  return (
    <div className="relative shrink-0">
      <Button
        variant="secondary"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        disabled={options.length === 0}
      >
        {active?.dot && (
          <Hexagon
            size={9}
            strokeWidth={2}
            fill="currentColor"
            className={cn("shrink-0", active.dot)}
          />
        )}
        <span className={cn(active?.mono && "font-mono")}>
          {active?.label ?? label}
        </span>
        <ChevronDown size={13} />
      </Button>
      {open && options.length > 0 && (
        <>
          {/* Click-away backdrop (below the menu, above the page). */}
          <button
            type="button"
            aria-hidden
            tabIndex={-1}
            className="fixed inset-0 z-10 cursor-default"
            onClick={() => setOpen(false)}
          />
          <div className="absolute left-0 z-20 mt-1 max-h-80 w-56 overflow-y-auto rounded-lg border border-border bg-surface py-1 shadow-lg">
            <button
              type="button"
              onClick={() => pick(null)}
              aria-pressed={value === null}
              className={cn(
                "flex w-full items-center px-3 py-1.5 text-left text-[13.5px] transition-colors hover:bg-surface-raised focus-ring",
                value === null ? "text-fg" : "text-fg-muted",
              )}
            >
              {label}
            </button>
            {groups
              ? groups.map((g) => (
                  <div
                    key={g.family}
                    className="mt-1 border-t border-border pt-1 first:border-0"
                  >
                    <p className="px-3 py-1 text-[10.5px] uppercase tracking-wider text-fg-subtle">
                      {g.family}
                    </p>
                    {g.options.map(row)}
                  </div>
                ))
              : options.map(row)}
          </div>
        </>
      )}
    </div>
  );
}

/** Lifted ignore state: clicking Ignore/Restore moves a finding between the Open
 *  list and the Ignored panel INSTANTLY; no rescan. The policy+ledger write
 *  still fires (a later rescan confirms it); `override` is the optimistic overlay
 *  and `persisted`/`report.ignored` are the server truth it agrees with once the
 *  policy-status refetches. Lifted to the Scan level so the list and the panel both react. */
export function useIgnoreState(
  report?: Pick<ScanReport, "findings" | "ignored">,
) {
  const mute = useMuteFinding();
  const unmute = useUnmuteFinding();
  const policyStatus = usePolicyStatus();
  const persisted = useMemo(
    () => new Set(policyStatus.data?.policy?.suppressed.map((s) => s.id) ?? []),
    [policyStatus.data],
  );
  const [override, setOverride] = useState<Map<string, boolean>>(new Map());
  const [muteMsg, setMuteMsg] = useState<string | null>(null);
  const busy = mute.isPending || unmute.isPending;

  const scanIgnored = useMemo(() => report?.ignored ?? [], [report?.ignored]);
  const scanIgnoredIds = useMemo(
    () => new Set(scanIgnored.map((f) => f.id)),
    [scanIgnored],
  );
  const isMuted = (id: string) =>
    override.get(id) ?? (persisted.has(id) || scanIgnoredIds.has(id));
  const setFlag = (ids: string[], val: boolean) =>
    setOverride((prev) => {
      const next = new Map(prev);
      for (const id of ids) next.set(id, val);
      return next;
    });

  const muteIds = async (ids: string[]) => {
    const fresh = ids.filter((id) => !isMuted(id));
    if (fresh.length === 0) return;
    setFlag(fresh, true); // optimistic → moves to Ignored now
    setMuteMsg(null);
    try {
      await mute.mutateAsync({ ids: fresh, reason: "ignored from web" });
      setMuteMsg(`Ignored ${fresh.length}, written to policy + ledger.`);
    } catch {
      setFlag(fresh, false); // revert → back to Open
      setMuteMsg("Couldn't write the policy. Is this a writable project?");
    }
  };
  const unmuteIds = async (ids: string[]) => {
    const targets = ids.filter((id) => isMuted(id));
    if (targets.length === 0) return;
    setFlag(targets, false); // optimistic → moves back to Open
    setMuteMsg(null);
    try {
      await unmute.mutateAsync({ ids: targets });
      setMuteMsg(`Restored ${targets.length}, removed from policy.`);
    } catch {
      setFlag(targets, true); // revert
      setMuteMsg("Couldn't write the policy.");
    }
  };

  // Every finding we know about (open at scan time + ignored at scan time),
  // deduped, then partitioned by current (optimistic) ignore state.
  const all = useMemo(() => {
    const map = new Map<string, Finding>();
    for (const f of [...(report?.findings ?? []), ...scanIgnored]) {
      const key = `${f.id}|${f.path ?? ""}|${f.line ?? ""}|${
        f.package ? `${f.package.ecosystem}:${f.package.name}` : ""
      }`;
      if (!map.has(key)) map.set(key, f);
    }
    return [...map.values()];
  }, [report?.findings, scanIgnored]);

  // Predicate inlined (not a shared closure) so the dep arrays reference exactly
  // the sets read: an id's override wins, else policy/ledger + scan-time ignored.
  const openFindings = useMemo(
    () =>
      all.filter(
        (f) =>
          !(
            override.get(f.id) ??
            (persisted.has(f.id) || scanIgnoredIds.has(f.id))
          ),
      ),
    [all, override, persisted, scanIgnoredIds],
  );
  const ignoredFindings = useMemo(
    () =>
      all.filter(
        (f) =>
          override.get(f.id) ??
          (persisted.has(f.id) || scanIgnoredIds.has(f.id)),
      ),
    [all, override, persisted, scanIgnoredIds],
  );

  return {
    isMuted,
    muteIds,
    unmuteIds,
    busy,
    muteMsg,
    openFindings,
    ignoredFindings,
  };
}

/** What can be done with the rows the toolbar left on screen: exporting them as
 *  JSON / CSV / Markdown. Disabled when nothing is showing. */
function ActionsMenu({
  findings,
  report,
}: {
  findings: Finding[];
  report?: ScanReport;
}) {
  const [open, setOpen] = useState(false);
  const disabled = findings.length === 0;
  const pick = (fmt: ExportFormat) => {
    downloadReport(fmt, findings, report);
    setOpen(false);
  };
  return (
    <div className="relative">
      <Button
        variant="secondary"
        disabled={disabled}
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        title={disabled ? "Nothing on screen to act on" : undefined}
      >
        Actions <ChevronDown size={13} />
      </Button>
      {open && !disabled && (
        <>
          {/* Click-away backdrop (below the menu, above the page). */}
          <button
            type="button"
            aria-hidden
            tabIndex={-1}
            className="fixed inset-0 z-10 cursor-default"
            onClick={() => setOpen(false)}
          />
          <div className="absolute right-0 z-20 mt-1 w-44 overflow-hidden rounded-lg border border-border bg-surface shadow-lg">
            <p className="px-3 pt-2 pb-1 text-[10.5px] uppercase tracking-wider text-fg-subtle">
              Export {findings.length} shown
            </p>
            {(["json", "csv", "md"] as ExportFormat[]).map((fmt) => (
              <button
                key={fmt}
                type="button"
                onClick={() => pick(fmt)}
                className="flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] text-fg-muted transition-colors hover:bg-surface-raised hover:text-fg focus-ring"
              >
                <Download size={13} className="shrink-0" />
                {EXPORT_LABEL[fmt]}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

export function Scan({
  onOpenGuide,
  source = "project",
  demo,
  repo: repoProp,
  onRepo,
}: {
  /** Open a Guide task. Scan is the evidence; the Guide is where a finding is
   *  acted on, so every finding detail offers this route. */
  onOpenGuide?: (taskId: string) => void;
  /** Which live slot to render: the folder scan or the standing machine scan.
   *  Same view either way; the machine scan has fixed roots (home), so its
   *  mode hides the folder picker and rescans through the machine endpoint. */
  source?: "project" | "machine";
  /** The repo (project) filter. Lifted when the inventory table above the list
   *  drives it; internal otherwise. */
  repo?: string | null;
  onRepo?: (id: string | null) => void;
  /** Canned sample data shown instead of live results (the first-run tour
   *  with no scan yet). Purely presentational; actions still hit the API. */
  demo?: LiveScanData;
} = {}) {
  const live = useLive();
  const machineLive = useMachine();
  const machineMode = source === "machine" && !demo;
  const ld = demo ?? (machineMode ? machineLive.data : live.data);
  const report = ld?.report;
  const running = ld?.running;
  // Idle: the server is up but no scan has been started or loaded from cache
  // (`husk web` waits for a directory pick).
  const idle = !!ld && !ld.running && !ld.finished_at;
  const [query, setQuery] = useState("");
  const [sev, setSev] = useState<Severity | "all">("all");
  const [cat, setCat] = useState<string | null>(null);
  const [eco, setEco] = useState<string | null>(null);
  const [ownRepo, setOwnRepo] = useState<string | null>(null);
  const repo = repoProp ?? ownRepo;
  const setRepo = onRepo ?? setOwnRepo;
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  // Each project owns its reveal/collapse state so a large repo cannot bury
  // the next one. All projects themselves remain visible in server order.
  const [shownCount, setShownCount] = useState<Record<string, number>>({});
  const [collapsedProjects, setCollapsedProjects] = useState<Set<string>>(
    () => new Set(),
  );
  const rescan = useRescan();
  const machineRescan = useMachineRescan();
  const stopScan = useStopScan(machineMode);
  // The folder the next scan targets. Always the project slot's root, even in
  // machine mode: the machine scan's home root must never leak into it.
  const [scanDir, setScanDir] = useState("");
  const currentRoot = (demo ?? live.data)?.report?.roots?.[0] ?? "";
  useEffect(() => {
    if (currentRoot) setScanDir(currentRoot);
  }, [currentRoot]);
  // Pick a folder → remember it and immediately rescan it.
  const pickDir = (path: string) => {
    setScanDir(path);
    rescan.mutate([path]);
  };
  // Plain Rescan reuses the current target (or the server's roots if unset);
  // the machine scan's roots are decided server-side.
  const startRescan = () =>
    machineMode
      ? machineRescan.mutate()
      : rescan.mutate(scanDir.trim() ? [scanDir.trim()] : undefined);
  const rescanPending = machineMode
    ? machineRescan.isPending
    : rescan.isPending;

  // Resizable list|detail split; same behavior as the Guide view.
  const { containerRef, dragging, detailStyle, handle } = useResizableDetail({
    // The list can go a bit narrower here than in the Guide (denser rows).
    minList: 320,
  });

  // Changing a filter produces different project sections, so their local view
  // state starts fresh.
  // biome-ignore lint/correctness/useExhaustiveDependencies: reset is keyed on the filter values, not the setters.
  useEffect(() => {
    setShownCount({});
    setCollapsedProjects(new Set());
  }, [query, sev, cat, eco, repo]);

  const showMore = (owner: string, total: number, fallback: number) =>
    setShownCount((previous) => ({
      ...previous,
      [owner]: Math.min((previous[owner] ?? fallback) + PAGE, total),
    }));
  const showLess = (owner: string) =>
    setShownCount((previous) => {
      const next = { ...previous };
      delete next[owner];
      return next;
    });
  const toggleProject = (owner: string) =>
    setCollapsedProjects((previous) => {
      const next = new Set(previous);
      if (next.has(owner)) next.delete(owner);
      else next.add(owner);
      return next;
    });

  // Lifted ignore state: Open/Ignored repartition instantly on click (no rescan).
  const {
    isMuted,
    muteIds,
    unmuteIds,
    busy: ignoreBusy,
    muteMsg,
    openFindings,
    ignoredFindings,
  } = useIgnoreState(report);

  // The Projects tab is the repos in the scan. Machine-wide config findings
  // (no owning project, or one of the config locations) are the Scan tab's
  // subject, so they never enter this list or its counts.
  const visibleOpen = useMemo(() => {
    if (source === "machine") return openFindings;
    const config = new Set(
      (report?.projects ?? [])
        .filter((p) => p.kind === "config-location")
        .map((p) => p.id),
    );
    return openFindings.filter(
      (f) => f.project_id && !config.has(f.project_id),
    );
  }, [openFindings, report?.projects, source]);
  // Solved = gone since the previous scan, straight off the server's delta:
  // verified evidence from a rescan, never an optimistic local claim.
  const solvedFindings = useMemo(
    () => report?.delta?.resolved ?? [],
    [report?.delta?.resolved],
  );
  const solvedGroups = useMemo(
    () => groupFindings(solvedFindings),
    [solvedFindings],
  );

  // Subfolder lookup for the main list: finding path (or its manifest) made
  // relative to the owning project's root.
  const folderOf = useMemo(() => {
    const rootById = new Map(
      (report?.projects ?? []).map((p) => [p.id, p.root]),
    );
    return (f: Finding) => {
      const root = f.project_id ? rootById.get(f.project_id) : undefined;
      const path = f.path ?? f.package?.manifest_path;
      return root && path ? subfolderOf(path, root) : "";
    };
  }, [report?.projects]);

  const groups = useMemo(
    () => groupFindings(visibleOpen, folderOf),
    [visibleOpen, folderOf],
  );
  // Search runs first, so every menu's counts describe the set the query left.
  const searched = useMemo(() => matching(groups, query), [groups, query]);
  const bySev =
    sev === "all" ? searched : searched.filter((g) => g.severity === sev);
  const byCat = cat === null ? bySev : bySev.filter((g) => g.category === cat);
  const byEco = eco === null ? byCat : byCat.filter((g) => g.ecosystem === eco);
  const byRepo = repo === null ? byEco : byEco.filter((g) => g.owner === repo);
  const shown = byRepo;

  // Each menu counts groups over the slice its own value does not constrain, so
  // picking one option never hides the counts you would switch to.
  const sevOptions = useMemo(() => {
    const counts = tally(searched, (g) => g.severity);
    return ORDER.filter((id) => counts.get(id)).map((id) => ({
      id,
      label: id,
      count: counts.get(id) ?? 0,
      dot: SEV_TEXT[id],
    }));
  }, [searched]);
  const catOptions = useMemo(() => {
    const counts = tally(bySev, (g) => g.category);
    return [...counts]
      .sort((a, b) => b[1] - a[1])
      .map(([id, count]) => ({ id, label: categoryLabel(id), count }));
  }, [bySev]);
  const ecoGroups = useMemo(() => ecosystemOptions(byCat), [byCat]);

  // Join the filtered groups to report.projects. That array is already sorted
  // by the backend's project posture logic; the frontend must not re-invent it.
  const allProjects = useMemo(
    () => buildProjects(shown, sev === "all", report?.projects ?? []),
    [shown, sev, report?.projects],
  );
  const projects = useMemo(
    () => allProjects.filter((project) => project.bucket === "needs-attention"),
    [allProjects],
  );
  const dormantProjects = useMemo(
    () => allProjects.filter((project) => project.bucket === "dormant"),
    [allProjects],
  );
  const projectOrderedGroups = useMemo(
    () => allProjects.flatMap((project) => project.groups),
    [allProjects],
  );

  // The detail pane can show a solved group too (clicked in the Solved panel).
  const openDetail = projectOrderedGroups.find((g) => g.key === selectedKey);
  const solvedDetail = solvedGroups.find((g) => g.key === selectedKey);
  const detail = openDetail ?? solvedDetail ?? projectOrderedGroups[0];
  const detailSolved = !openDetail && !!solvedDetail;

  // Arrow-key navigation over the finding rows, matching the Guide tab. The
  // navigable set is exactly the rows currently on screen (collapsed projects
  // and paged-away rows excluded); the DormantBucket keeps its own open state,
  // so its rows aren't walked here.
  const listRef = useRef<HTMLDivElement>(null);
  const navigableKeys = useMemo(() => {
    const keys: string[] = [];
    for (const project of projects) {
      if (collapsedProjects.has(project.owner)) continue;
      const count = Math.min(
        shownCount[project.owner] ?? project.defaultShown,
        project.groups.length,
      );
      for (const g of project.groups.slice(0, count)) keys.push(g.key);
    }
    return keys;
  }, [projects, collapsedProjects, shownCount]);

  const selectGroup = (key: string) => {
    setSelectedKey(key);
    listRef.current?.focus({ preventScroll: true });
  };
  const moveSelection = (delta: -1 | 1) => {
    if (navigableKeys.length === 0) return;
    const current = detail ? navigableKeys.indexOf(detail.key) : -1;
    const base = current >= 0 ? current : 0;
    const next = Math.max(0, Math.min(navigableKeys.length - 1, base + delta));
    setSelectedKey(navigableKeys[next]);
  };
  const handleListKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      moveSelection(1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      moveSelection(-1);
    }
  };
  // Keep the selected row scrolled into view as arrows move it.
  useEffect(() => {
    if (!selectedKey) return;
    document
      .getElementById(groupDomId(selectedKey))
      ?.scrollIntoView({ block: "nearest" });
  }, [selectedKey]);

  const projectPath = useMemo(() => {
    const byId = new Map(
      (report?.projects ?? []).map((p) => [p.id, projectLabel(p)]),
    );
    return (owner: string) => byId.get(owner) ?? shortPath(owner);
  }, [report?.projects]);

  const repoOptions = useMemo(() => {
    const counts = tally(byEco, (g) => g.owner);
    return [...counts]
      .sort((a, b) => b[1] - a[1])
      .map(([id, count]) => ({
        id,
        label: projectPath(id),
        count,
        mono: true,
      }));
  }, [byEco, projectPath]);

  const exploited = groups.filter((g) => g.exploit?.kev).length;

  // Advisory sources that produced no verdict this scan (failed requests, or
  // carried-forward rows from an offline run).
  const failedProviders = (report?.providers ?? []).filter((p) => !p.ok).length;

  // Counts come from the live Open set (not report.stats) so ignoring a finding
  // decrements its pill instantly, in lockstep with it leaving the list.
  const openCounts = useMemo(() => {
    const c: Record<string, number> = { all: visibleOpen.length };
    for (const f of visibleOpen) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [visibleOpen]);
  const filtered =
    query.trim() !== "" ||
    sev !== "all" ||
    cat !== null ||
    eco !== null ||
    repo !== null;
  const clearFilters = () => {
    setQuery("");
    setSev("all");
    setCat(null);
    setEco(null);
    setRepo(null);
  };

  // Nothing fetched yet (first paint; a large report can take a moment to
  // arrive): a plain spinner. Rendering the normal view here would show an
  // all-clear summary with zero findings until the data lands.
  if (!ld) {
    return (
      <div className="grid h-full place-items-center p-10">
        <Spinner className="size-6 text-fg-subtle" />
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
      {/* LEFT pane: all scan content + the findings list, scrolling on its own;
          the same full-height resizable panel the Guide uses. `@container` so the
          inner layout responds to THIS pane's width (it's resizable), not the
          viewport; otherwise the severity grid breaks when the pane is narrow. */}
      <div className="@container min-w-0 flex-1 lg:overflow-auto">
        <div className="px-6 pt-7 pb-5">
          <PageHeader
            className="flex-col [&>div:last-child]:w-full [&>div:last-child]:min-w-0 @3xl:flex-row @3xl:[&>div:last-child]:w-auto"
            title={
              <span className="flex items-center gap-2.5">
                {running && <Spinner className="size-5 text-accent-text" />}
                {machineMode ? "Scan the machine" : "Scan a project"}
                {!running &&
                  !idle &&
                  (report?.delta?.resolved_count ?? 0) > 0 && (
                    <span className="text-xl font-medium text-accent-text">
                      <span className="tabular-nums">
                        {report?.delta?.resolved_count}
                      </span>{" "}
                      resolved since last scan
                    </span>
                  )}
                {!running && !idle && !demo && report?.generated_at && (
                  <span
                    className="text-[13px] font-normal text-fg-subtle"
                    title={new Date(report.generated_at).toLocaleString()}
                  >
                    {scannedAgo(report.generated_at)}
                  </span>
                )}
                {!running && !idle && failedProviders > 0 && (
                  <span className="flex items-center gap-1 text-[13px] font-medium text-warning">
                    <TriangleAlert size={13} /> incomplete advisory data
                  </span>
                )}
                {demo && <Badge variant="neutral">sample data</Badge>}
              </span>
            }
            actions={
              <div
                data-tour="scan-actions"
                className="flex w-full min-w-0 flex-wrap items-center gap-2 @3xl:w-auto @3xl:flex-nowrap"
              >
                {!machineMode && (
                  <DirPicker
                    current={scanDir}
                    disabled={running || rescan.isPending}
                    onPick={pickDir}
                  />
                )}
                {/* One control slot: while a scan runs it stops that scan,
                    otherwise it starts one. */}
                {running ? (
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => stopScan.mutate()}
                    disabled={stopScan.isPending}
                  >
                    <Square size={13} fill="currentColor" />
                    {stopScan.isPending ? "Stopping…" : "Stop scan"}
                  </Button>
                ) : (
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={startRescan}
                    disabled={rescanPending}
                  >
                    <RotateCw
                      size={14}
                      className={cn(rescanPending && "animate-spin")}
                    />
                    {rescanPending
                      ? "Scanning…"
                      : idle
                        ? machineMode
                          ? "Scan machine"
                          : "Scan"
                        : "Rescan"}
                  </Button>
                )}
              </div>
            }
          />

          {/* Degraded-scan warning: an advisory source that produced no
          verdict must never read as a clean result. The scan carries the last
          known findings forward; this banner is what says so. */}
          {failedProviders > 0 && !running && !idle && (
            <div className="mt-4 flex items-start gap-2.5 rounded-lg border border-warning/40 bg-warning-tint px-3.5 py-2.5">
              <TriangleAlert
                size={16}
                className="mt-0.5 shrink-0 text-warning"
              />
              <p className="text-[13px] leading-relaxed text-fg">
                <b className="font-semibold">{failedProviders}</b> advisory
                source{failedProviders === 1 ? "" : "s"} gave no verdict during
                this scan; vulnerability results are carried from the last
                successful scan where possible and may be incomplete.
              </p>
            </div>
          )}

          {/* Actively-exploited callout: the "fix these first" promise made visible. */}
          {exploited > 0 && (
            <div className="mt-4 flex items-start gap-2.5 rounded-lg border border-severity-critical/40 bg-severity-critical-tint px-3.5 py-2.5">
              <Hexagon
                size={16}
                className="mt-0.5 shrink-0 text-severity-critical"
              />
              <p className="text-[13px] leading-relaxed text-fg">
                <b className="font-semibold">{exploited}</b> finding
                {exploited === 1 ? " is" : "s are"} actively exploited in the
                wild (CISA KEV).
              </p>
            </div>
          )}

          <div className="mt-5 grid gap-3">
            <Overview
              summary={report?.summary}
              delta={report?.delta}
              openCount={openCounts.all ?? 0}
              exploited={exploited}
              report={report}
              running={running}
              idle={idle}
            />

            <div className="grid gap-3 @2xl:grid-cols-2">
              <IgnoredPanel
                findings={ignoredFindings}
                onRestore={unmuteIds}
                busy={ignoreBusy}
              />

              <SolvedPanel
                findings={solvedFindings}
                selectedKey={detail?.key ?? null}
                onSelect={setSelectedKey}
              />
            </div>

            {/* One toolbar: search, then a menu per axis, then the actions
                that operate on whatever the toolbar left on screen. */}
            <div
              data-tour="scan-filters"
              className="flex min-w-0 flex-wrap items-center gap-2"
            >
              <SearchBox
                value={query}
                onChange={setQuery}
                placeholder="Search findings"
              />
              <FilterMenu
                label="All severities"
                value={sev === "all" ? null : sev}
                options={sevOptions}
                onChange={(id) => setSev((id as Severity) ?? "all")}
              />
              <FilterMenu
                label="All types"
                value={cat}
                options={catOptions}
                onChange={setCat}
              />
              {ecoGroups.length > 0 && (
                <FilterMenu
                  label="All languages"
                  value={eco}
                  options={ecoGroups.flatMap((g) => g.options)}
                  groups={ecoGroups}
                  onChange={setEco}
                />
              )}
              {repoOptions.length > 1 && (
                <FilterMenu
                  label="All repos"
                  value={repo}
                  options={repoOptions}
                  onChange={setRepo}
                />
              )}
              {filtered && (
                <Button variant="ghost" onClick={clearFilters}>
                  <X size={14} /> Clear
                </Button>
              )}
              <div className="ml-auto">
                <ActionsMenu
                  findings={shown.flatMap((g) => g.items)}
                  report={report}
                />
              </div>
            </div>
          </div>
        </div>

        {/* The findings list is its own compartment: a header that says how much
            of the scan is on screen, then the project sections. */}
        <div className="flex items-baseline justify-between gap-3 border-t border-border px-6 pt-3 pb-1">
          <span className="text-[10.5px] uppercase tracking-wider text-fg-muted">
            Findings
          </span>
          <span className="text-[11px] tabular-nums text-fg-subtle">
            {shown.length === groups.length
              ? `${groups.length} ${groups.length === 1 ? "group" : "groups"}`
              : `${shown.length} of ${groups.length} groups`}
          </span>
        </div>

        <div
          ref={listRef}
          role="listbox"
          tabIndex={0}
          aria-label="Findings"
          aria-activedescendant={detail ? groupDomId(detail.key) : undefined}
          onKeyDown={handleListKeyDown}
          className="px-3 pt-1 pb-5 focus:outline-none"
        >
          {shown.length === 0 ? (
            <EmptyState
              title={
                running
                  ? "Still scanning…"
                  : idle
                    ? machineMode
                      ? "No machine scan yet"
                      : "No scan yet"
                    : (openCounts.all ?? 0) === 0
                      ? "No issues found"
                      : "Nothing matches these filters"
              }
              description={
                running
                  ? "Findings stream in as Husk works through this machine."
                  : idle
                    ? machineMode
                      ? "Hit Scan machine above to check this machine's standing posture."
                      : "Use the folder picker above to choose what to scan, then hit Scan."
                    : (openCounts.all ?? 0) === 0
                      ? // The denominator: a clean result is verified coverage,
                        // not absence of work.
                        `Scanned ${(report?.benchmarks ?? []).reduce((n, b) => n + b.files_checked, 0).toLocaleString()} files and ${report?.stats.packages ?? 0} packages. All clear.`
                      : "Clear the search or the filters to see the rest."
              }
            />
          ) : (
            <div className="min-w-0">
              {projects.map((project) => (
                <ProjectSection
                  key={project.owner}
                  project={project}
                  shown={shownCount[project.owner] ?? project.defaultShown}
                  collapsed={collapsedProjects.has(project.owner)}
                  onShowMore={() =>
                    showMore(
                      project.owner,
                      project.groups.length,
                      project.defaultShown,
                    )
                  }
                  onShowLess={() => showLess(project.owner)}
                  onToggleCollapse={() => toggleProject(project.owner)}
                  selectedKey={detail?.key ?? null}
                  onSelectGroup={selectGroup}
                  projectPath={projectPath}
                />
              ))}
              {dormantProjects.length > 0 && (
                <DormantBucket
                  projects={dormantProjects}
                  shownCount={shownCount}
                  collapsedProjects={collapsedProjects}
                  onShowMore={showMore}
                  onShowLess={showLess}
                  onToggleCollapse={toggleProject}
                  selectedKey={detail?.key ?? null}
                  onSelectGroup={selectGroup}
                  projectPath={projectPath}
                />
              )}
            </div>
          )}
        </div>
      </div>

      {handle}

      {/* RIGHT pane: the resizable finding detail, scrolling on its own. */}
      <div
        data-tour="scan-detail"
        className="min-w-0 lg:overflow-auto"
        style={detailStyle}
      >
        {detail ? (
          <div className="px-6 py-7">
            <GroupDetail
              key={detail.items[0]?.id ?? detail.title}
              g={detail}
              solved={detailSolved}
              isMuted={isMuted}
              muteIds={muteIds}
              unmuteIds={unmuteIds}
              busy={ignoreBusy}
              muteMsg={muteMsg}
              onOpenGuide={onOpenGuide}
            />
          </div>
        ) : (
          <p className="p-8 text-center text-[13px] text-fg-subtle">
            Select a finding.
          </p>
        )}
      </div>
    </div>
  );
}

/** Findings silenced by project policy or the personal ledger (`report.ignored`),
 *  grouped like the main list and collapsed by default. Always shown (even at 0)
 *  so the Open / Ignored / Solved split is visible. Restore a group or the lot
 *  (best-effort: removes any `[[suppress]]` policy entry). */
function IgnoredPanel({
  findings,
  onRestore,
  busy,
}: {
  findings: Finding[];
  onRestore: (ids: string[]) => void;
  busy: boolean;
}) {
  const groups = useMemo(() => groupFindings(findings), [findings]);
  const empty = findings.length === 0;
  return (
    <Panel
      title="Ignored"
      count={findings.length}
      collapsible
      defaultOpen={false}
      disabled={empty}
      action={
        !empty && (
          <button
            type="button"
            onClick={() => onRestore(findings.map((f) => f.id))}
            disabled={busy}
            className="shrink-0 rounded-full border border-border bg-surface px-2 py-0.5 text-[11.5px] text-fg-muted transition-colors hover:bg-surface-raised hover:text-fg focus-ring disabled:opacity-60"
          >
            Restore all
          </button>
        )
      }
    >
      <ul className="-my-1">
        {groups.map((g) => (
          <li
            key={g.key}
            className="flex items-center gap-2 border-t border-border py-2 first:border-0"
          >
            <SeverityBadge severity={g.severity} className="w-24 shrink-0" />
            <span className="min-w-0 flex-1 truncate text-[12.5px] text-fg-muted">
              {groupLabel(g)}
            </span>
            {g.items.length > 1 && (
              <span className="shrink-0 rounded-full border border-border bg-surface-raised px-1.5 py-0.5 text-[10.5px] tabular-nums text-fg-muted">
                ×{g.items.length}
              </span>
            )}
            <button
              type="button"
              onClick={() => onRestore(g.items.map((f) => f.id))}
              disabled={busy}
              className="shrink-0 text-[11px] text-fg-subtle underline decoration-border-strong underline-offset-2 hover:text-fg disabled:opacity-60"
            >
              {g.items.length > 1 ? "restore all" : "restore"}
            </button>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/** Findings that are gone since the previous scan (the report delta): the value
 *  the user's work created, kept visible.
 *  Always shown (even at 0) so the Open / Ignored / Solved split is visible.
 *  Rows are clickable and open in the detail pane (read-only there). */
function SolvedPanel({
  findings,
  selectedKey,
  onSelect,
}: {
  findings: Finding[];
  selectedKey: string | null;
  onSelect: (key: string) => void;
}) {
  const groups = useMemo(() => groupFindings(findings), [findings]);
  const empty = findings.length === 0;
  return (
    <Panel
      title="Solved"
      count={findings.length}
      collapsible
      defaultOpen={false}
      disabled={empty}
    >
      <ul className="-my-1">
        {groups.map((g) => (
          <li key={g.key} className="border-t border-border first:border-0">
            <button
              type="button"
              onClick={() => onSelect(g.key)}
              aria-pressed={g.key === selectedKey}
              className={cn(
                "flex w-full items-center gap-2 rounded-md px-1.5 py-2 text-left transition-colors focus-ring",
                g.key === selectedKey
                  ? "bg-accent-subtle"
                  : "hover:bg-surface-raised",
              )}
            >
              <SeverityBadge severity={g.severity} className="w-24 shrink-0" />
              <span className="min-w-0 flex-1 truncate text-[12.5px] text-fg-muted line-through decoration-border-strong">
                {groupLabel(g)}
              </span>
              {g.items.length > 1 && (
                <span className="shrink-0 rounded-full border border-border bg-surface-raised px-1.5 py-0.5 text-[10.5px] tabular-nums text-fg-muted">
                  ×{g.items.length}
                </span>
              )}
            </button>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/** Small mono chip badging which ecosystem a package/finding belongs to. */
function EcosystemChip({ id, className }: { id: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border border-border bg-surface-raised px-2 py-0.5 font-mono text-[11px] text-fg-muted",
        className,
      )}
    >
      {id}
    </span>
  );
}

/** KEV / EPSS exploit badges. KEV (actively exploited) is the strongest danger
 *  signal, so it carries the critical hue; EPSS is a neutral probability chip. */
function ExploitBadges({ exploit }: { exploit: Exploit }) {
  return (
    <>
      {exploit.kev && (
        <span className="inline-flex items-center gap-1 rounded-full border border-severity-critical/40 bg-severity-critical-tint px-2 py-0.5 text-[11px] text-severity-critical">
          <Hexagon size={11} /> actively exploited · CISA KEV
        </span>
      )}
      {exploit.epss !== undefined && (
        <span className="inline-flex items-center rounded-full border border-border bg-surface-raised px-2 py-0.5 text-[11px] tabular-nums text-fg-muted">
          EPSS {Math.round(exploit.epss * 100)}%
        </span>
      )}
    </>
  );
}

/** Group counts per key, for the filter menus. */
function tally<T>(groups: Group[], key: (g: Group) => T | undefined) {
  const counts = new Map<T, number>();
  for (const g of groups) {
    const k = key(g);
    if (k !== undefined) counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return counts;
}

/** Ecosystem options sectioned by family, in the catalog's family order. */
function ecosystemOptions(groups: Group[]) {
  const counts = tally(groups, (g) => g.ecosystem);
  const byFamily = new Map<EcosystemFamily, FilterOption[]>();
  for (const [id, count] of counts) {
    const family = ecosystemFamily(id);
    const list = byFamily.get(family) ?? [];
    list.push({ id, label: id, count, mono: true });
    byFamily.set(family, list);
  }
  const out: { family: EcosystemFamily; options: FilterOption[] }[] = [];
  for (const family of FAMILY_ORDER) {
    const options = byFamily.get(family);
    if (options) {
      options.sort((a, b) => b.count - a.count);
      out.push({ family, options });
    }
  }
  return out;
}

/** Text search over a row's own visible identity: its label, title, type,
 *  package coordinate, and the paths underneath it. All terms must match, so
 *  typing narrows monotonically. */
function matching(groups: Group[], query: string): Group[] {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return groups;
  return groups.filter((g) => {
    const haystack = [
      groupLabel(g),
      g.title,
      g.category,
      categoryLabel(g.category),
      g.ecosystem ?? "",
      g.folder,
      ...g.items.map((f) =>
        [f.path, f.package?.name, f.package?.manifest_path]
          .filter(Boolean)
          .join(" "),
      ),
    ]
      .join(" ")
      .toLowerCase();
    return terms.every((t) => haystack.includes(t));
  });
}

const PAGE = 50;

/** One project in the canonical server order. Small projects show all rows;
 * large ones start with critical rows and page independently in batches of 50. */
function ProjectSection({
  project,
  shown,
  collapsed,
  onShowMore,
  onShowLess,
  onToggleCollapse,
  selectedKey,
  onSelectGroup,
  projectPath,
}: {
  project: ProjectGroup;
  shown: number;
  collapsed: boolean;
  onShowMore: () => void;
  onShowLess: () => void;
  onToggleCollapse: () => void;
  selectedKey: string | null;
  onSelectGroup: (key: string) => void;
  projectPath: (owner: string) => string;
}) {
  const total = project.groups.length;
  const visible = collapsed ? 0 : Math.min(shown, total);
  const rows = project.groups.slice(0, visible);
  const remaining = total - visible;
  const expanded = visible > project.defaultShown;

  return (
    <section className="mt-2 min-w-0 first:mt-0">
      <button
        type="button"
        onClick={onToggleCollapse}
        aria-expanded={!collapsed}
        className="flex w-full min-w-0 flex-col gap-1 rounded-md px-3 py-2 text-left transition-colors hover:bg-surface focus-ring @3xl:flex-row @3xl:items-center @3xl:gap-2"
      >
        <span className="flex w-full min-w-0 items-center gap-2 @3xl:w-auto @3xl:flex-1">
          <ChevronDown
            size={13}
            className={cn(
              "shrink-0 text-fg-subtle transition-transform",
              collapsed && "-rotate-90",
            )}
          />
          <PathLabel
            path={project.displayPath}
            className="text-[12px] font-medium"
          />
          <ActivityPill activity={project.activity} />
          {project.hasKev && (
            <Hexagon
              size={11}
              className="shrink-0 text-severity-critical"
              aria-label="actively exploited finding in this project"
            />
          )}
        </span>

        {project.byCategory.length > 0 && (
          <span className="flex min-w-0 flex-wrap gap-x-2.5 gap-y-0.5 pl-5 @3xl:ml-auto @3xl:max-w-[58%] @3xl:justify-end @3xl:pl-0">
            {project.byCategory.map((category) => (
              <span
                key={category.category}
                className={cn(
                  "whitespace-nowrap text-[10px] tabular-nums",
                  category.act_count > 0
                    ? SEV_TEXT[category.worst_severity]
                    : "text-fg-subtle",
                )}
              >
                {category.subjects} {categoryLabel(category.category)}
              </span>
            ))}
          </span>
        )}
      </button>

      {rows.map((group) => (
        <GroupRow
          key={group.key}
          g={group}
          where={whereLabel(group, projectPath)}
          selected={group.key === selectedKey}
          onSelect={() => onSelectGroup(group.key)}
        />
      ))}

      {!collapsed && (remaining > 0 || expanded) && (
        <div className="flex flex-wrap items-center gap-1.5 px-3 py-1">
          {remaining > 0 && (
            <button
              type="button"
              onClick={onShowMore}
              className="flex items-center gap-1.5 rounded-md px-2 py-1 text-[12px] text-fg-muted transition-colors hover:bg-surface hover:text-fg focus-ring"
            >
              <ChevronDown size={13} />
              Show {Math.min(PAGE, remaining)} more
              {remaining > PAGE ? ` of ${remaining}` : ""}
            </button>
          )}
          {expanded && (
            <button
              type="button"
              onClick={onShowLess}
              className="rounded-md px-2 py-1 text-[12px] text-fg-subtle transition-colors hover:bg-surface hover:text-fg focus-ring"
            >
              Show less
            </button>
          )}
        </div>
      )}
    </section>
  );
}

/** Ambient-only projects stay counted and reachable but start collapsed so
 * active work remains the primary scan scope. */
function DormantBucket({
  projects,
  shownCount,
  collapsedProjects,
  onShowMore,
  onShowLess,
  onToggleCollapse,
  selectedKey,
  onSelectGroup,
  projectPath,
}: {
  projects: ProjectGroup[];
  shownCount: Record<string, number>;
  collapsedProjects: Set<string>;
  onShowMore: (owner: string, total: number, fallback: number) => void;
  onShowLess: (owner: string) => void;
  onToggleCollapse: (owner: string) => void;
  selectedKey: string | null;
  onSelectGroup: (key: string) => void;
  projectPath: (owner: string) => string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <section className="mt-3 min-w-0 border-t border-border pt-1">
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
        className="flex w-full min-w-0 items-start gap-2 rounded-md px-3 py-2 text-left text-[12px] leading-relaxed text-fg-subtle transition-colors hover:bg-surface hover:text-fg focus-ring"
      >
        <ChevronDown
          size={13}
          className={cn(
            "mt-0.5 shrink-0 transition-transform",
            !open && "-rotate-90",
          )}
        />
        <span className="min-w-0">
          {projects.length} dormant{" "}
          {projects.length === 1 ? "project" : "projects"}: ambient info, low
          priority
        </span>
      </button>

      {open &&
        projects.map((project) => (
          <ProjectSection
            key={project.owner}
            project={project}
            shown={shownCount[project.owner] ?? project.defaultShown}
            collapsed={collapsedProjects.has(project.owner)}
            onShowMore={() =>
              onShowMore(
                project.owner,
                project.groups.length,
                project.defaultShown,
              )
            }
            onShowLess={() => onShowLess(project.owner)}
            onToggleCollapse={() => onToggleCollapse(project.owner)}
            selectedKey={selectedKey}
            onSelectGroup={onSelectGroup}
            projectPath={projectPath}
          />
        ))}
    </section>
  );
}

function GroupRow({
  g,
  where,
  selected,
  onSelect,
}: {
  g: Group;
  /** The row's location: file path (with line) or project/subfolder. */
  where: string;
  selected: boolean;
  onSelect: () => void;
}) {
  const n = g.items.length;
  return (
    <button
      type="button"
      id={groupDomId(g.key)}
      role="option"
      onClick={onSelect}
      aria-selected={selected}
      className={cn(
        "flex w-full min-w-0 items-center gap-2.5 rounded-md px-3 py-2 text-left transition-colors focus-ring",
        selected ? "bg-accent-subtle" : "hover:bg-surface",
      )}
    >
      <SeverityBadge severity={g.severity} className="w-24 shrink-0" />
      <span className="min-w-0 flex-1">
        <span className="flex min-w-0 items-center gap-2">
          <span className="truncate text-[13px] text-fg">{groupLabel(g)}</span>
          {g.exploit?.kev && (
            <Hexagon
              size={12}
              className="shrink-0 text-severity-critical"
              aria-label="actively exploited (CISA KEV)"
            />
          )}
        </span>
        {/* Four lockfiles under sibling directories share every character up to
            the directory name; clipping the end of the path is what turns them
            into four identical rows. The head gives way instead. */}
        <PathLabel path={where} />
      </span>
      {g.ecosystem && <EcosystemChip id={g.ecosystem} className="shrink-0" />}
      {n > 1 && (
        <span className="shrink-0 rounded-full border border-border bg-surface-raised px-1.5 py-0.5 text-[10.5px] tabular-nums text-fg-muted">
          ×{n}
        </span>
      )}
    </button>
  );
}

const AFFECTED_CAP = 50;

/** "Fix with AI": open the docs section on handing a finding to your coding
 *  agent. The one-time MCP wiring lives on the "AI agent setup" tab. */
function AiFix() {
  return (
    <Button
      variant="secondary"
      size="sm"
      onClick={() =>
        window.open(AI_AGENT_USAGE_DOCS_URL, "_blank", "noreferrer")
      }
    >
      <Sparkles size={14} /> Fix with AI
    </Button>
  );
}

export function GroupDetail({
  g,
  solved,
  isMuted,
  muteIds,
  unmuteIds,
  busy,
  muteMsg,
  onOpenGuide,
}: {
  g: Group;
  /** Already resolved since the previous scan; read-only. */
  solved?: boolean;
  // Ignore state is lifted to Scan so Open/Ignored repartition instantly.
  isMuted: (id: string) => boolean;
  muteIds: (ids: string[]) => void;
  unmuteIds: (ids: string[]) => void;
  busy: boolean;
  muteMsg: string | null;
  onOpenGuide?: (taskId: string) => void;
}) {
  const first = g.items[0];
  const n = g.items.length;
  const pkg = first.package;
  // A coordinate group's items are advisories that share one path, so list them
  // by title; everything else lists by file location.
  const isCoord = n > 1 && !!pkg;
  // One advisory reaching a coordinate through four lockfiles is one row, not
  // four: repeating the sentence hid the manifest that told them apart, and
  // gave the reader four ignore links where ignoring any one left its twins.
  const entries = useMemo(() => {
    const rows = isCoord ? g.items : g.items.filter((f) => f.path);
    return groupByLabel(rows, (f) => (isCoord ? f.title : (loc(f) ?? "")));
  }, [g.items, isCoord]);
  // Resolve the guide task that fixes this finding via the rule→guide join
  // (Finding.rule_id → Rule.guide_task). Lets us deep-link to its fix page.
  const rules = useRules();
  const guideTask = useMemo(() => {
    // Local detectors stamp a rule_id that joins to a Guide task.
    for (const f of g.items) {
      const task = f.rule_id
        ? rules.data?.find((r) => r.id === f.rule_id)?.guide_task
        : undefined;
      if (task) return task;
    }
    // Provider vuln/malware findings carry no rule_id (and synthesized advisory
    // rules aren't served by /api/rules), but they're all dependency issues;
    // point them at the same Guide task Rust maps synthesized rules to.
    return g.items.some((f) => f.package) ? "scan-dependencies" : undefined;
  }, [g.items, rules.data]);
  const allMuted = g.items.every((f) => isMuted(f.id));
  const groupIds = g.items.map((f) => f.id);
  // One dialog for the whole list, not one per row.
  const [showing, setShowing] = useState<ReturnType<typeof sourceTarget>>(null);

  return (
    <div className="min-w-0">
      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        <SeverityBadge severity={g.severity} />
        <Badge>{g.category}</Badge>
        {solved && <Badge variant="neutral">solved</Badge>}
        {g.exploit && <ExploitBadges exploit={g.exploit} />}
      </div>
      <h2 className="text-base font-semibold leading-snug [overflow-wrap:anywhere]">
        {groupLabel(g)}
      </h2>

      {/* Scan shows the evidence; the Guide is where it gets acted on, so the
          primary action here is the route to the task that fixes this, not a
          fix button of its own. A solved group is read-only. */}
      {!solved && (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {/* Never a dead end: with no task mapped for this finding the button
              still opens the checklist rather than disappearing. */}
          {onOpenGuide && (
            <Button size="sm" onClick={() => onOpenGuide(guideTask ?? "")}>
              <BookOpen size={14} />
              {guideTask ? "Fix this in the Guide" : "Open the Guide"}
            </Button>
          )}
          <Button
            variant="secondary"
            size="sm"
            onClick={() => (allMuted ? unmuteIds(groupIds) : muteIds(groupIds))}
            disabled={busy}
          >
            {busy
              ? allMuted
                ? "Restoring…"
                : "Ignoring…"
              : allMuted
                ? n > 1
                  ? "Restore all"
                  : "Restore"
                : n > 1
                  ? "Ignore all"
                  : "Ignore"}
          </Button>
          <AiFix />
          {muteMsg && (
            <span className="text-[11.5px] leading-snug text-fg-subtle">
              {muteMsg}
            </span>
          )}
        </div>
      )}

      <p className="mt-3.5 text-[13.5px] leading-relaxed text-fg">
        {first.summary}
      </p>

      {pkg && (
        <p className="mt-3 flex flex-wrap items-center gap-1.5">
          <EcosystemChip id={pkg.ecosystem} />
          <span className="font-mono text-[12px] text-fg [overflow-wrap:anywhere]">
            {pkg.name}
            <span className="text-fg-subtle">@{pkg.version}</span>
          </span>
        </p>
      )}

      <p className="mt-4 text-[10.5px] tracking-wide text-fg-subtle">
        Flagged by
      </p>
      <p className="mt-1 text-[12.5px] text-fg-muted [overflow-wrap:anywhere]">
        {first.source}
      </p>

      <p className="mt-4 text-[10.5px] tracking-wide text-fg-subtle">
        What to do
      </p>
      <p className="mt-1.5 text-[13.5px] leading-relaxed text-fg">
        {first.recommendation}
      </p>

      {entries.length > 0 && (
        <>
          <p className="mt-4 text-[10.5px] tracking-wide text-fg-subtle">
            {isCoord ? "Advisories" : "Affected"}
            {/* The rows on screen, so the heading counts what the reader can
                count. */}
            {entries.length > 1 ? ` · ${entries.length}` : ""}
          </p>
          <ul className="mt-1.5 grid gap-0.5">
            {entries.slice(0, AFFECTED_CAP).map((entry) => {
              const ids = entry.items.map((f) => f.id);
              const muted = entry.items.every((f) => isMuted(f.id));
              // Only a coordinate row drops its locations from the shared
              // sentence; a location row already is its location.
              const where = isCoord ? manifests(entry.items) : [];
              const at = sourceTarget(entry.items);
              // An advisory row is about a vulnerability as well as a file, so
              // it also links out to the advisory page describing it.
              const advisories = isCoord ? advisoryLinks(entry.items) : [];
              return (
                <li key={entry.label} className="flex items-start gap-2">
                  <span className="min-w-0 flex-1">
                    <span
                      className={cn(
                        "block font-mono text-[11.5px] leading-relaxed [overflow-wrap:anywhere]",
                        muted
                          ? "text-fg-subtle line-through decoration-border-strong"
                          : "text-fg-muted",
                      )}
                    >
                      {entry.label}
                    </span>
                    {where.length > 1 && (
                      <Places at={where.map((path) => ({ path }))} />
                    )}
                  </span>
                  {/* Reading the file in-app is the whole point: handing it to
                      an editor would load the flagged tree's own plugins. */}
                  {at && (
                    <button
                      type="button"
                      data-tour="show-file"
                      onClick={() => setShowing(at)}
                      className="shrink-0 text-[10px] text-fg-subtle underline decoration-border-strong underline-offset-2 hover:text-fg"
                      title={`Show ${at.path}`}
                    >
                      Show file
                    </button>
                  )}
                  {advisories.map((advisory) => (
                    <a
                      key={advisory.id}
                      href={advisory.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="shrink-0 font-mono text-[10px] text-fg-subtle underline decoration-border-strong underline-offset-2 hover:text-fg"
                      title={advisory.url}
                    >
                      {advisory.id}
                    </a>
                  ))}
                  {!solved && (
                    <button
                      type="button"
                      onClick={() => (muted ? unmuteIds(ids) : muteIds(ids))}
                      disabled={busy}
                      className="shrink-0 text-[10px] text-fg-subtle underline decoration-border-strong underline-offset-2 hover:text-fg disabled:opacity-60"
                      title={
                        muted ? "Restore this entry" : "Ignore just this entry"
                      }
                    >
                      {muted ? "Restore" : "Ignore"}
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
          {entries.length > AFFECTED_CAP && (
            <p className="mt-1.5 text-[11px] tabular-nums text-fg-subtle">
              + {entries.length - AFFECTED_CAP} more; use “Ignore all” above to
              cover them.
            </p>
          )}
        </>
      )}

      <SourceView
        open={!!showing}
        onOpenChange={(o) => !o && setShowing(null)}
        path={showing?.path ?? ""}
        lines={showing?.lines ?? []}
      />
    </div>
  );
}
