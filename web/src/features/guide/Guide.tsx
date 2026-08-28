import {
  Badge,
  Button,
  Card,
  Checkbox,
  CommandBlock,
  cn,
  PageHeader,
} from "@huskdev/ui";
import { ArrowLeft, Check, Hexagon, RotateCcw, Wrench } from "lucide-react";
import {
  type KeyboardEvent,
  type ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  type GuideAction,
  type GuideBucket,
  type GuideTask,
  useGuide,
  useGuideAction,
  useLive,
} from "@/lib/api";
import { groupByLabel } from "@/lib/collapse";
import { Places } from "@/lib/path";
import { Prose } from "@/lib/prose";
import { useResizableDetail } from "@/lib/useResizableDetail";

import { proposalsKey } from "./proposals";
import { Remediation } from "./Remediation";

type Filter = GuideBucket | "all";

/** Slice membership comes from the server's bucket, the same split its tab
 *  counts are computed from, so a tab can never show a different number of
 *  rows than its own count. */
const matches = (t: GuideTask, filter: Filter): boolean =>
  filter === "all" || t.bucket === filter;

/** Evidence rows painted before the reader asks for the rest. One task carries
 *  close to five hundred, which is a finding dump rather than something anyone
 *  reads; the server has already sorted them worst first, so the head of the
 *  list is the part that earns its space. */
const EVIDENCE_PREVIEW = 10;

type SectionedTask = GuideTask & { category: string };
type Section = { id: string; label: string; items: SectionedTask[] };

// Priority tiers: the heading text every surface prints (mirrors `TIERS` in
// `src/guide/mod.rs`; change both together) plus a filled-hexagon importance
// meter in the same visual language as the Scan severity badge (3 hexes,
// filled count = urgency).
const TIER_META: Record<
  string,
  { label: string; filled: number; tone: string }
> = {
  next: {
    label: "Do next: highest impact",
    filled: 2,
    tone: "text-severity-high",
  },
  later: {
    label: "When you get to it",
    filled: 1,
    tone: "text-severity-medium",
  },
  done: { label: "Handled", filled: 0, tone: "text-severity-info" },
  ignored: { label: "Ignored", filled: 0, tone: "text-fg-subtle" },
};

/** Priority section header: importance meter, then the heading and its count.
 *  The words carry the meaning; the meter only reinforces it. */
function TierHeader({ id, count }: { id: string; count: number }) {
  const meta = TIER_META[id] ?? {
    label: id,
    filled: 0,
    tone: "text-fg-subtle",
  };
  return (
    <p className="flex items-center gap-2 px-3 pt-3 pb-1.5">
      <span className="inline-flex items-center gap-0.5" aria-hidden="true">
        {[0, 1, 2].map((i) => (
          <Hexagon
            key={i}
            size={9}
            strokeWidth={2}
            fill={i < meta.filled ? "currentColor" : "none"}
            className={i < meta.filled ? meta.tone : "text-border-strong"}
          />
        ))}
      </span>
      <span className="text-[12px] font-medium tracking-wide text-fg-muted">
        {meta.label}
      </span>
      <span className="tabular-nums text-[11px] text-fg-subtle">{count}</span>
    </p>
  );
}

const taskDomId = (id: string) =>
  `guide-task-${id.replace(/[^A-Za-z0-9_-]/g, "-")}`;

/** How long a row collapses out of the list before its action is sent. Must
 *  stay >= the row's own transition duration, or the server answer removes the
 *  row before the exit has played. */
const EXIT_MS = 220;
const UNDO_MS = 6000;
const exitMs = () =>
  window.matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : EXIT_MS;

export function Guide({
  category,
  onOpenCategory,
  targetId,
  onTargetConsumed,
}: {
  // The category title this view is scoped to, from the sidebar. `null` is the
  // unscoped list every category rolls up into.
  category?: string | null;
  onOpenCategory?: (title: string) => void;
  // When set (from a Scan finding's "Open fix guide"), select this task and
  // widen the filter so it's visible even if it's not in the current slice.
  targetId?: string | null;
  onTargetConsumed?: () => void;
} = {}) {
  const guide = useGuide();
  const guideAction = useGuideAction();
  const live = useLive();
  const listRef = useRef<HTMLDivElement>(null);
  const [filter, setFilter] = useState<Filter>("todo");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // A checkbox only ever selects. Nothing is written to the server until the
  // selection bar acts, so ticking a row can never make it vanish.
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  // Rows whose action is already committed but which are still on screen,
  // collapsing out.
  const [leaving, setLeaving] = useState<Set<string>>(new Set());
  const [undo, setUndo] = useState<{ ids: string[]; label: string } | null>(
    null,
  );
  const undoTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(
    () => () => {
      if (undoTimer.current) clearTimeout(undoTimer.current);
    },
    [],
  );

  // Resizable split between the task list and the detail/steps pane. Below
  // `lg` there is no split: the two panes are one column, so they become two
  // views of it and `openDetail` says which one is showing.
  const { containerRef, isDesktop, dragging, detailStyle, handle } =
    useResizableDetail();
  const [openDetail, setOpenDetail] = useState(false);
  const stacked = !isDesktop;
  const detailRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!targetId) return;
    setFilter("all");
    setSelectedId(targetId);
    setOpenDetail(true);
    onTargetConsumed?.();
  }, [targetId, onTargetConsumed]);

  const flat = useMemo(
    () =>
      (guide.data?.categories ?? []).flatMap((c) =>
        c.items.map((it) => ({ ...it, category: c.title })),
      ),
    [guide.data],
  );
  // What the row promises: fixes one click runs, and separately the ones that
  // need a human edit first. The server decides which is which (`ready`), so a
  // badge cannot advertise a fix the task itself then refuses.
  const fixCounts = useMemo(() => {
    const ready = new Set<string>();
    const blocked = new Set<string>();
    for (const proposal of live.data?.report.remediations ?? []) {
      if (proposal.ready) ready.add(proposal.id);
      else if (proposal.action.kind === "dependency_update")
        blocked.add(proposal.id);
    }
    return (task: GuideTask) => ({
      ready: task.remediation_ids.filter((id) => ready.has(id)).length,
      blocked: task.remediation_ids.filter((id) => blocked.has(id)).length,
    });
  }, [live.data]);
  // Sort by server-computed priority (desc): open advice first, then done,
  // then ignored. This ordering is deliberate; keep it.
  const scoped = useMemo(
    () => (category ? flat.filter((t) => t.category === category) : flat),
    [flat, category],
  );
  const visible = useMemo(
    () =>
      scoped
        .filter((t) => matches(t, filter))
        .sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0)),
    [scoped, filter],
  );
  // Priority tiers, worst first. Items keep their priority order inside each
  // tier; empty tiers are dropped.
  const sections = useMemo<Section[]>(
    () =>
      (["next", "later", "done", "ignored"] as const)
        .map((tier) => ({
          id: tier,
          label: TIER_META[tier].label,
          items: visible.filter((t) => t.tier === tier),
        }))
        .filter((s) => s.items.length > 0),
    [visible],
  );

  // The tasks actually shown, which keyboard navigation and selection resolve
  // against.
  const navigable = sections.flatMap((s) => s.items);

  // Resolve against the NAVIGABLE set, not all tasks: otherwise switching
  // filters/view modes could leave the detail pane (and its action buttons)
  // pointed at a task that is hidden from the current list.
  const selected =
    navigable.find((t) => t.id === selectedId) ?? navigable[0] ?? null;

  useEffect(() => {
    if (!selectedId) return;
    document
      .getElementById(taskDomId(selectedId))
      ?.scrollIntoView({ block: "nearest" });
  }, [selectedId]);

  // Swapping one stacked view for the other keeps whatever scroll offset the
  // previous one left behind, which lands the reader in the middle of the view
  // they just asked for. Move them to its head, and back to their own row when
  // they return.
  useEffect(() => {
    if (!stacked) return;
    if (openDetail) detailRef.current?.scrollIntoView({ block: "start" });
    else if (selectedId)
      document
        .getElementById(taskDomId(selectedId))
        ?.scrollIntoView({ block: "center" });
  }, [stacked, openDetail, selectedId]);

  const selectTask = (id: string) => {
    setSelectedId(id);
    setOpenDetail(true);
    listRef.current?.focus({ preventScroll: true });
  };

  const moveSelection = (delta: -1 | 1) => {
    if (navigable.length === 0) return;
    const current = selected
      ? navigable.findIndex((t) => t.id === selected.id)
      : -1;
    const base = current >= 0 ? current : 0;
    const next = Math.max(0, Math.min(navigable.length - 1, base + delta));
    setSelectedId(navigable[next].id);
  };

  const toggleChecked = (id: string) =>
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (!next.delete(id)) next.add(id);
      return next;
    });

  const checked = flat.filter((t) => selectedIds.has(t.id));
  // Nothing to mark done or ignore when the whole selection is already out of
  // the to-do slice; restoring it is the only move left.
  const allHandled =
    checked.length > 0 && checked.every((t) => t.bucket !== "todo");

  /** Apply one action to every checked task, letting the rows collapse out
   *  first so none of them disappears under the pointer. `clear` is itself the
   *  undo of the other two, so it offers no undo of its own. */
  const applyToChecked = (action: GuideAction, label: string) => {
    const ids = [...selectedIds];
    if (ids.length === 0) return;
    setSelectedIds(new Set());
    setLeaving(new Set(ids));
    // Swap the bar's contents at the same moment the rows start leaving, so it
    // never blinks out between the two states.
    setUndo(
      action === "clear" ? null : { ids, label: `${ids.length} ${label}` },
    );
    setTimeout(async () => {
      try {
        for (const id of ids) await guideAction.mutateAsync({ id, action });
      } finally {
        setLeaving(new Set());
      }
      if (action !== "clear")
        undoTimer.current = setTimeout(() => setUndo(null), UNDO_MS);
    }, exitMs());
  };

  const undoLast = async () => {
    const ids = undo?.ids ?? [];
    setUndo(null);
    for (const id of ids)
      await guideAction.mutateAsync({ id, action: "clear" });
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

  const g = guide.data;
  // Every number here comes from the server's one partition: `todo + done +
  // ignored === total`. Recomputing any of them locally is how the tabs came
  // to add up to less than "All".

  // A category slice has no server-side partition, so it counts its own rows.
  // The unscoped view never does: those four numbers stay the server's.
  const bucketCount = (bucket: GuideBucket) =>
    category
      ? scoped.filter((t) => t.bucket === bucket).length
      : (g?.[bucket] ?? 0);

  // What the roll-up shows instead of a wall of rows: one line per category,
  // its open count and the single worst thing in it, as the way into that
  // category's own view.
  const summary = (g?.categories ?? []).map((c) => {
    const open = c.items
      .filter((t) => t.bucket === "todo")
      .sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
    return { title: c.title, open: open.length, worst: open[0]?.title ?? null };
  });

  const FILTERS: { id: Filter; label: string; count: number }[] = [
    { id: "todo", label: "To do", count: bucketCount("todo") },
    // Most of this slice is what husk verified, not what the user did.
    { id: "done", label: "Handled", count: bucketCount("done") },
    { id: "ignored", label: "Ignored", count: bucketCount("ignored") },
    {
      id: "all",
      label: "All",
      count: category ? scoped.length : (g?.total ?? 0),
    },
  ];

  // The roll-up is an overview, not a second copy of every list: the totals,
  // then one row per category as the way into it. Tasks are worked in the
  // category views, so no rows are shown here.
  if (!category) {
    return (
      <div className="@container min-w-0 px-6 pt-7 pb-8">
        <PageHeader title="Security checklist" lede="" />
        <div className="mt-4 grid grid-cols-2 gap-2 @md:grid-cols-4">
          {FILTERS.map((f) => (
            <div
              key={f.id}
              className="min-w-0 rounded-lg border border-border bg-surface px-3 py-2.5"
            >
              <span className="block text-[11px] tracking-wider text-fg-muted">
                {f.label}
              </span>
              <b
                className={cn(
                  "mt-1 block text-xl tabular-nums",
                  f.id === "todo" && f.count > 0 && "text-severity-high",
                )}
              >
                {f.count}
              </b>
            </div>
          ))}
        </div>
        <div
          data-tour="guide-list"
          className="mt-4 grid gap-1.5 @2xl:grid-cols-2"
        >
          {summary.map((c) => (
            <button
              key={c.title}
              type="button"
              onClick={() => onOpenCategory?.(c.title)}
              className="min-w-0 rounded-lg border border-border bg-surface px-3 py-2 text-left transition-colors hover:bg-surface-raised focus-ring"
            >
              <span className="flex items-baseline gap-2">
                <span className="min-w-0 flex-1 truncate text-[13px] text-fg">
                  {c.title}
                </span>
                <span
                  className={cn(
                    "shrink-0 tabular-nums text-[12px]",
                    c.open > 0 ? "text-severity-high" : "text-fg-subtle",
                  )}
                >
                  {c.open}
                </span>
              </span>
              <span className="mt-0.5 block truncate text-[11.5px] text-fg-subtle">
                {c.worst ?? "nothing open"}
              </span>
            </button>
          ))}
        </div>
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
      <div
        hidden={stacked && openDetail}
        className="@container min-w-0 flex-1 lg:overflow-auto"
      >
        <div className="border-b border-border px-6 pt-7 pb-5">
          <PageHeader title={category ?? "Security checklist"} lede="" />
          {/* Review progress (the handled/total meter) lives in the persistent
              Tasks bar up top, not here. */}
          {/* Status overview that doubles as the filter; same card pattern as
              the Scan severity grid. */}
          <div className="mt-4 grid grid-cols-2 gap-2 @md:grid-cols-4">
            {FILTERS.map((f) => {
              const active = filter === f.id;
              return (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => setFilter(f.id)}
                  aria-pressed={active}
                  className={cn(
                    "min-w-0 rounded-lg border px-3 py-2.5 text-left transition-colors focus-ring",
                    active
                      ? "border-border-strong bg-accent-subtle"
                      : "border-border bg-surface hover:bg-surface-raised",
                  )}
                >
                  <span className="block text-[11px] tracking-wider text-fg-muted">
                    {f.label}
                  </span>
                  {/* A count of unread checklist items is not a severity, so it
                      takes no severity hue. */}
                  <b className="mt-1 block text-xl tabular-nums">{f.count}</b>
                </button>
              );
            })}
          </div>
        </div>

        {(selectedIds.size > 0 || undo) && (
          <div className="sticky top-0 z-10 flex items-center gap-2 border-b border-border bg-bg px-3 py-2">
            {selectedIds.size > 0 ? (
              <>
                <span className="mr-auto tabular-nums text-[12px] text-fg-muted">
                  {selectedIds.size} selected
                </span>
                {allHandled ? (
                  <Button
                    size="sm"
                    onClick={() => applyToChecked("clear", "restored")}
                  >
                    <RotateCcw size={13} /> Restore
                  </Button>
                ) : (
                  <>
                    <Button
                      size="sm"
                      onClick={() => applyToChecked("done", "marked done")}
                    >
                      <Check size={14} /> Mark done
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => applyToChecked("dismiss", "ignored")}
                    >
                      Ignore
                    </Button>
                  </>
                )}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelectedIds(new Set())}
                >
                  Clear
                </Button>
              </>
            ) : (
              <>
                <span className="mr-auto text-[12px] text-fg-muted">
                  {undo?.label}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={leaving.size > 0}
                  onClick={undoLast}
                >
                  <RotateCcw size={13} /> Undo
                </Button>
              </>
            )}
          </div>
        )}

        <div
          ref={listRef}
          role="listbox"
          tabIndex={0}
          data-tour="guide-list"
          aria-label="Guide tasks"
          aria-activedescendant={selected ? taskDomId(selected.id) : undefined}
          onKeyDown={handleListKeyDown}
          className="px-3 py-2 focus:outline-none"
        >
          {visible.length === 0 ? (
            <Card className="m-3 flex items-center gap-2 px-4 py-4 text-[13.5px] text-fg-muted">
              <Check size={16} className="text-severity-info" />
              {filter === "todo"
                ? "Nothing left to do. Nice."
                : "Nothing here under this filter."}
            </Card>
          ) : (
            sections.map((s) => (
              <div
                key={s.id}
                className="mt-2 border-t border-border pt-1 first:mt-0 first:border-0 first:pt-0"
              >
                <TierHeader id={s.id} count={s.items.length} />
                {s.items.map((t) => (
                  <TaskRow
                    key={t.id}
                    t={t}
                    fixes={fixCounts(t)}
                    active={t.id === selected?.id}
                    checked={selectedIds.has(t.id)}
                    leaving={leaving.has(t.id)}
                    onCheck={() => toggleChecked(t.id)}
                    onClick={() => selectTask(t.id)}
                  />
                ))}
              </div>
            ))
          )}
        </div>
      </div>

      {handle}

      <div
        ref={detailRef}
        hidden={stacked && !openDetail}
        className="min-w-0 lg:overflow-auto"
        style={detailStyle}
      >
        {selected ? (
          <Detail
            key={selected.id}
            t={selected}
            onBack={stacked ? () => setOpenDetail(false) : undefined}
            onIgnore={() =>
              guideAction.mutate({ id: selected.id, action: "dismiss" })
            }
          />
        ) : (
          <p className="p-8 text-center text-[13px] text-fg-subtle">
            Pick a task to see how to do it.
          </p>
        )}
      </div>
    </div>
  );
}

function TaskRow({
  t,
  fixes,
  active,
  checked,
  leaving,
  onCheck,
  onClick,
}: {
  t: GuideTask & { category: string };
  /** Fixes one click runs, and fixes listed inside but not runnable yet. */
  fixes: { ready: number; blocked: number };
  active: boolean;
  checked: boolean;
  /** Committed, collapsing out of the list. */
  leaving: boolean;
  onCheck: () => void;
  onClick: () => void;
}) {
  const done = t.bucket === "done";
  const dismissed = t.bucket === "ignored";

  return (
    <div
      id={taskDomId(t.id)}
      role="option"
      aria-selected={active}
      tabIndex={-1}
      onClick={onClick}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onClick();
        }
      }}
      className={cn(
        "flex cursor-default items-center gap-3 overflow-hidden rounded-md px-3 transition-all duration-200 ease-out motion-reduce:transition-none",
        // A stable ceiling: rows are single-line, so this only ever bounds the
        // collapse, never clips content.
        leaving ? "max-h-0 py-0 opacity-0" : "max-h-12 py-2",
        active ? "bg-accent-subtle" : "hover:bg-surface",
      )}
    >
      <Checkbox
        checked={checked}
        className="cursor-default!"
        onCheckedChange={onCheck}
        aria-label={`Select ${t.title}`}
      />

      <div className="flex min-w-0 flex-1 cursor-default items-center gap-2 text-left">
        <span
          className={cn(
            "min-w-0 flex-1 truncate text-[13.5px]",
            (dismissed || done) &&
              "text-fg-subtle line-through decoration-border-strong",
          )}
        >
          {t.title}
        </span>
        {/* Its own child, so the title gives way to it rather than shunting it
            off the row. A phone has no width to spare for it at all, and the
            detail names the category anyway. */}
        <span className="hidden shrink-0 text-[10px] text-fg-subtle sm:inline">
          {t.category}
        </span>
        {fixes.ready > 0 && !done && !dismissed && (
          <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-accent bg-accent-subtle px-2 py-0.5 text-[10.5px] text-fg">
            <Wrench size={10} />
            {fixes.ready} {fixes.ready === 1 ? "fix" : "fixes"} ready
          </span>
        )}
        {fixes.blocked > 0 && !done && !dismissed && (
          <span
            className="shrink-0 rounded-full border border-border px-2 py-0.5 text-[10.5px] text-fg-subtle"
            title="Listed inside, but each needs an edit before Husk can run it"
          >
            {fixes.blocked} blocked
          </span>
        )}
      </div>

      {/* The checkbox now means "selected", so resolution needs its own mark.
          Husk verifying something and the user deciding it are different
          claims, and only one of them says the reader did anything. */}
      {done && (
        <span className="flex shrink-0 items-center gap-1 text-[11px] text-severity-info">
          <Check size={13} /> {t.decision === "completed" ? "done" : "verified"}
        </span>
      )}
      {dismissed && (
        <span className="shrink-0 text-[11px] text-fg-subtle">ignored</span>
      )}
    </div>
  );
}

function Detail({
  t,
  onBack,
  onIgnore,
}: {
  t: GuideTask & { category: string };
  /** Set only where the list is a separate view, which is the only place the
   *  reader can be stranded in a task with no route back to it. */
  onBack?: () => void;
  onIgnore: () => void;
}) {
  const action = useGuideAction();
  const dismissed = t.bucket === "ignored";

  // Opening a task is what reading it means. Recording it per rendered row
  // marked the whole list read the moment it painted, which is not a thing the
  // reader ever did.
  useEffect(() => {
    if (!t.read) action.mutate({ id: t.id, action: "read" });
  }, [t.id, t.read, action.mutate]);

  // Every fix this task can take, exactly as the server planned it. The task
  // owns them through `remediation_ids`, so a dependency upgrade is an ordinary
  // entry on this to-do rather than a separate destination.
  const live = useLive();
  const proposals = useMemo(() => {
    const ids = new Set(t.remediation_ids);
    return (live.data?.report.remediations ?? []).filter((proposal) =>
      ids.has(proposal.id),
    );
  }, [t.remediation_ids, live.data]);

  // Which option's how-to is showing. Default to the recommended one (whose
  // steps are the task-level `steps`). Detail is keyed by task id, so this
  // resets when you switch tasks.
  const hasOptions = t.options.length > 0;
  const [optIdx, setOptIdx] = useState(() => {
    const r = t.options.findIndex((o) => o.recommended);
    return r >= 0 ? r : 0;
  });
  const selectedOpt = hasOptions ? t.options[optIdx] : undefined;

  // Order is the server's; expanding only paints more of the same list. Rows
  // that say the same thing about different files are one observation over
  // several places, so they arrive as one card carrying the list of places.
  const [allEvidence, setAllEvidence] = useState(false);
  const observed = useMemo(
    () => groupByLabel(t.evidence, (row) => row.summary),
    [t.evidence],
  );
  const shownEvidence = allEvidence
    ? observed
    : observed.slice(0, EVIDENCE_PREVIEW);

  // Steps for the chosen option: its own if authored, otherwise the task-level
  // steps that belong to the recommended option, otherwise none.
  const optSteps = !hasOptions
    ? t.steps
    : selectedOpt?.steps?.length
      ? selectedOpt.steps
      : selectedOpt?.recommended
        ? t.steps
        : [];

  return (
    <div>
      {/* Identity and actions ride at the top of the pane: acting on a task
          must never require scrolling past its steps and sources. */}
      <div className="sticky top-0 z-10 border-b border-border bg-bg px-6 py-3.5">
        {onBack && (
          <Button
            variant="ghost"
            size="sm"
            className="-ml-2 mb-1"
            onClick={onBack}
          >
            <ArrowLeft size={14} /> Back to checklist
          </Button>
        )}
        <p className="truncate text-[10.5px] tracking-wide text-fg-subtle">
          {t.category} · {t.kind === "baseline" ? "essential" : "optional"} ·{" "}
          {t.severity} impact · {controlLabel(t)}
          {dismissed && " · ignored"}
        </p>
        {/* Two lines are always reserved, so a one-line title leaves the
            buttons below it exactly where the previous task put them. */}
        <h2 className="mt-0.5 line-clamp-2 min-h-[2lh] text-balance text-[17px] font-semibold leading-snug tracking-tight">
          {t.title}
        </h2>
        {/* Only a task the user decided about can be un-decided. A task husk
            verified was never their doing, so offering to "mark it not done"
            would promise to undo something that never happened; they can still
            mark it done or ignore it explicitly. */}
        <div className="mt-2.5 flex items-center gap-2">
          {t.decision ? (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => action.mutate({ id: t.id, action: "clear" })}
            >
              <RotateCcw size={13} />{" "}
              {t.decision === "completed" ? "Mark not done" : "Restore"}
            </Button>
          ) : (
            <>
              <Button
                size="sm"
                onClick={() => action.mutate({ id: t.id, action: "done" })}
              >
                <Check size={14} /> Mark done
              </Button>
              <Button variant="ghost" size="sm" onClick={onIgnore}>
                Ignore
              </Button>
            </>
          )}
        </div>
      </div>

      <div className="px-6 pt-5 pb-6">
        {/* The lede. Catalog entries are authored so `problem` does not restate
            `why`, which leaves the paragraph incoherent on its own if the stake
            above it is missing. It rides in the scrolling body rather than the
            sticky header: the header repeats over every item and has to stay
            one compact block. */}
        <p className="text-[15px] leading-relaxed text-fg">
          <Prose text={t.why} />
        </p>
        <p className="mt-2.5 text-[14px] leading-relaxed text-fg-muted">
          <Prose text={t.problem} />
        </p>

        {/* The fix comes before the evidence for it: an item Husk can act on is a
          cheap, high-value win, and burying the button under a long list of
          matched advisories is what made it feel like a separate feature.
          Keyed by the proposals themselves so a rescan that changes them starts
          from a clean selection, rather than one made against packages that may
          no longer be there. */}
        <Remediation key={proposalsKey(proposals)} proposals={proposals} />

        {t.evidence.length > 0 && (
          <Section
            label="What Husk checked"
            action={
              observed.length > EVIDENCE_PREVIEW && (
                <div className="flex shrink-0 items-center gap-2.5">
                  <span className="tabular-nums text-[11px] text-fg-subtle">
                    {shownEvidence.length} of {observed.length}
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setAllEvidence(!allEvidence)}
                  >
                    {allEvidence ? "Show fewer" : "Show all"}
                  </Button>
                </div>
              )
            }
          >
            <div className="grid gap-2">
              {shownEvidence.map((group) => (
                <Card key={group.label} className="min-w-0 px-3.5 py-2.5">
                  {/* Advisory summaries carry unbreakable tokens like
                      `org.apache.logging.log4j:log4j-core`, which push the card
                      past the pane unless they are allowed to break. */}
                  <p className="wrap-anywhere text-[12.5px] leading-snug text-fg-muted">
                    <Prose text={group.label} />
                  </p>
                  <Places at={group.items} />
                </Card>
              ))}
            </div>
          </Section>
        )}

        {hasOptions && (
          <Section label="Options">
            <div className="grid gap-2">
              {t.options.map((o, i) => {
                const active = i === optIdx;
                return (
                  // biome-ignore lint/a11y/useSemanticElements: card wraps an interactive docs link, which can't nest inside a native <button>.
                  <div
                    key={o.name}
                    role="button"
                    tabIndex={0}
                    aria-pressed={active}
                    onClick={() => setOptIdx(i)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setOptIdx(i);
                      }
                    }}
                    className={cn(
                      "cursor-default rounded-md border px-3.5 py-2.5 transition-colors",
                      active
                        ? "border-accent bg-accent-subtle"
                        : "border-border hover:bg-surface",
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-[13.5px]">{o.name}</span>
                      {o.recommended && (
                        <Badge variant="accent">recommended</Badge>
                      )}
                      {o.url && (
                        <a
                          href={o.url}
                          target="_blank"
                          rel="noreferrer"
                          onClick={(event) => event.stopPropagation()}
                          className="ml-auto shrink-0 text-[11px] text-fg-muted underline decoration-border-strong underline-offset-2 hover:text-fg"
                        >
                          docs ↗
                        </a>
                      )}
                    </div>
                    <p className="mt-1 text-[12.5px] leading-snug text-fg-muted">
                      <Prose text={o.note} />
                    </p>
                  </div>
                );
              })}
            </div>
          </Section>
        )}

        <Section label="Steps">
          {optSteps.length > 0 ? (
            <ol className="grid gap-3">
              {optSteps.map((s, i) => (
                <li
                  key={`${s.text}|${s.command ?? ""}`}
                  className="grid grid-cols-[22px_minmax(0,1fr)] gap-3"
                >
                  <span className="mt-0.5 grid size-[22px] place-items-center rounded-full bg-accent-subtle tabular-nums text-[11px]">
                    {i + 1}
                  </span>
                  <div className="min-w-0">
                    <p className="text-[13.5px] leading-relaxed text-fg">
                      <Prose text={s.text} />
                      {s.platform && (
                        <span className="ml-1.5 text-[10.5px] text-fg-subtle">
                          ({s.platform})
                        </span>
                      )}
                    </p>
                    {s.command && (
                      <CommandBlock
                        command={s.command}
                        prompt={!/^https?:\/\//.test(s.command)}
                        className="mt-2"
                      />
                    )}
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <Card className="px-4 py-3 text-[13px] leading-relaxed text-fg-muted">
              Husk doesn't have step-by-step instructions for{" "}
              <span className="text-fg">{selectedOpt?.name}</span> yet. Follow{" "}
              {selectedOpt?.url ? (
                <a
                  href={selectedOpt.url}
                  target="_blank"
                  rel="noreferrer"
                  className="underline decoration-border-strong underline-offset-2 hover:text-fg"
                >
                  its own setup guide
                </a>
              ) : (
                "its own setup guide"
              )}
              , or pick the recommended option above for detailed steps.
            </Card>
          )}
        </Section>

        {t.sources.length > 0 && (
          <Section label="Sources">
            <ul className="grid gap-1.5">
              {t.sources.map((src) => (
                <li key={src.url}>
                  <a
                    href={src.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[12px] text-fg-muted underline decoration-border-strong underline-offset-2 hover:text-fg"
                  >
                    {src.title}
                  </a>
                </li>
              ))}
            </ul>
          </Section>
        )}
      </div>
    </div>
  );
}

function controlLabel(task: GuideTask): string {
  // A manual guide was never checked, so it must not borrow the vocabulary of
  // a check. Say plainly that this one is on the reader.
  if (task.verification === "manual")
    return "husk can't check this, confirm it yourself";
  switch (task.control_status) {
    case "passed":
      return "verified";
    case "failed":
      return "needs action";
    case "partial":
      return "partly configured";
    case "not-applicable":
      return "may not apply";
    default:
      // A machine-scoped task verifies against the machine report; an unknown
      // control there means no machine scan has assessed it yet.
      return task.scope === "machine" && task.control_status === "unknown"
        ? "run a machine scan to verify"
        : "needs review";
  }
}

/** A titled block of the detail pane. Anything acting on the block sits in the
 *  header beside the title, where it is reachable before the block is scrolled
 *  rather than buried under however many rows it controls. */
function Section({
  label,
  action,
  children,
}: {
  label?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="mt-6">
      {(label || action) && (
        <div className="mb-2.5 flex min-h-7 items-center justify-between gap-3">
          <p className="truncate text-[15px] font-medium text-fg">{label}</p>
          {action}
        </div>
      )}
      {children}
    </div>
  );
}
