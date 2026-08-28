import {
  AppShell,
  cn,
  LogoLockup,
  Sidebar,
  SidebarFooter,
  SidebarGroup,
  SidebarHeader,
  SidebarItem,
  SidebarNav,
  useCloseDrawer,
} from "@huskdev/ui";
import {
  BookOpen,
  Bot,
  ChevronRight,
  CircleHelp,
  ExternalLink,
  FileText,
  FolderGit2,
  GraduationCap,
  History as HistoryIcon,
  LogIn,
  MessageSquare,
  PanelLeftClose,
  PanelLeftOpen,
  Radar,
  TriangleAlert,
  UserRound,
  X,
} from "lucide-react";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { Account } from "@/features/account/Account";
import { AgentSetup } from "@/features/agent-setup/AgentSetup";
import { Feed } from "@/features/feed/Feed";
import { FeedbackDialog } from "@/features/feedback/Feedback";
import { Guide } from "@/features/guide/Guide";
import { ScanHistory } from "@/features/history/ScanHistory";
import { Inventory, Projects } from "@/features/projects/Projects";
import { Scan } from "@/features/scan/Scan";
import { DEMO_LIVE } from "@/features/tutorial/demoLive";
import { Tutorial, tutorialUnseen } from "@/features/tutorial/Tutorial";
import {
  type LiveScan,
  progressPercent,
  useAccount,
  useGuide,
  useLive,
  useMachine,
  useRescan,
  useTelemetryConsent,
  useTelemetryConsentAnswer,
} from "@/lib/api";
import { useIsDesktop } from "@/lib/useIsDesktop";

const DISCORD_URL = "https://discord.gg/uHSU48wAYy";

type TabId =
  | "guide"
  | "scan"
  | "feed"
  | "projects"
  | "history"
  | "agent-setup"
  | "account";

// Two steps, in order: Scan is the evidence, Guide is the single to-do list and
// the only place a fix is taken. Something Husk can fix in one click is an
// ordinary Guide item, not a destination of its own. The Guide entry expands
// into one child per catalog category, so a category is a destination rather
// than a filter buried in the list.
const NAV: { id: TabId; label: string; icon: ReactNode }[] = [
  { id: "scan", label: "Machine", icon: <Radar size={15} /> },
  { id: "projects", label: "Projects", icon: <FolderGit2 size={15} /> },
  { id: "history", label: "Scan history", icon: <HistoryIcon size={15} /> },
  { id: "guide", label: "All tasks", icon: <BookOpen size={15} /> },
];
const NAV_TAIL: { id: TabId; label: string; icon: ReactNode }[] = [
  { id: "agent-setup", label: "AI agent setup", icon: <Bot size={15} /> },
];

const ALL_TABS: TabId[] = [
  "scan",
  "feed",
  "projects",
  "history",
  "guide",
  "agent-setup",
  "account",
];

export default function App() {
  const [tab, setTab] = useState<TabId>(() => {
    const stored = localStorage.getItem("husk-tab");
    return (ALL_TABS.includes(stored as TabId) ? stored : "scan") as TabId;
  });
  useEffect(() => {
    localStorage.setItem("husk-tab", tab);
  }, [tab]);

  // Icon-only collapse is a sticky user preference, but only takes visual
  // effect on desktop (see useIsDesktop). Persist the intent regardless.
  const [collapsePref, setCollapsePref] = useState(
    () => localStorage.getItem("husk-nav-collapsed") === "1",
  );
  useEffect(() => {
    localStorage.setItem("husk-nav-collapsed", collapsePref ? "1" : "0");
  }, [collapsePref]);
  const isDesktop = useIsDesktop();
  const collapsed = collapsePref && isDesktop;

  // Deep-link target for the Guide tab: set when a Scan finding's "Open fix
  // guide" button is clicked, consumed (cleared) once Guide has selected it.
  const [guideTarget, setGuideTarget] = useState<string | null>(null);
  const [guideCategory, setGuideCategory] = useState<string | null>(null);
  const guide = useGuide();
  // A deep link opens the category the task lives in: the roll-up is an
  // overview and carries no rows to select.
  const openGuide = (taskId: string) => {
    setGuideTarget(taskId);
    setGuideCategory(
      guide.data?.categories.find((c) => c.items.some((t) => t.id === taskId))
        ?.title ?? null,
    );
    setTab("guide");
  };
  const openTasks = () => {
    setGuideCategory(null);
    setTab("guide");
  };
  const openCategory = (title: string) => {
    setGuideCategory(title);
    setTab("guide");
  };

  const machineScan = useMachine();

  // First-run product tour: auto-opens once, rerunnable from the TopBar.
  const [tutorialOpen, setTutorialOpen] = useState(tutorialUnseen);
  const openTutorial = () => {
    setTab("scan");
    setTutorialOpen(true);
  };
  // The tour always runs over the same sample project, so every step it
  // describes (a finding, its detail, the Show file action) is on screen
  // whatever this machine's own scan holds. It is labeled "sample data" and
  // disappears with the tour.
  const scanDemo = tutorialOpen ? DEMO_LIVE : undefined;
  const machineProjects =
    (scanDemo ?? machineScan.data)?.report?.projects ?? [];

  return (
    <AppShell
      mobileBrand={<LogoLockup className="h-5 w-auto" />}
      sidebar={
        <NavSidebar
          tab={tab}
          setTab={setTab}
          guideCategory={guideCategory}
          onOpenTasks={openTasks}
          onOpenCategory={openCategory}
          collapsed={collapsed}
          showToggle={isDesktop}
          onToggle={() => setCollapsePref((c) => !c)}
        />
      }
    >
      {/* The shell's main area is a fixed-height column: a persistent top bar
          (scan progress + todos, reachable from every view) over a scrolling
          content pane. */}
      <div className="flex h-full flex-col">
        <Tutorial
          open={tutorialOpen}
          onClose={() => setTutorialOpen(false)}
          onNavigate={setTab}
        />
        <TopBar
          tab={tab}
          onOpenTab={setTab}
          onOpenTasks={openTasks}
          onOpenTutorial={openTutorial}
        />
        <StaleScanBanner />
        <TelemetryConsentCard />
        <div className="min-h-0 flex-1 overflow-y-auto">
          {tab === "scan" && (
            <div className="flex min-w-0 flex-col lg:h-full">
              <Inventory projects={machineProjects} />
              <div className="min-h-0 flex-1">
                <Scan
                  onOpenGuide={openGuide}
                  source="machine"
                  demo={scanDemo}
                />
              </div>
            </div>
          )}
          {tab === "feed" && <Feed onOpenGuide={openGuide} />}
          {tab === "projects" && (
            <Projects onOpenGuide={openGuide} demo={scanDemo} />
          )}
          {tab === "history" && <ScanHistory />}
          {tab === "guide" && (
            <Guide
              key={guideCategory ?? "all"}
              category={guideCategory}
              onOpenCategory={openCategory}
              targetId={guideTarget}
              onTargetConsumed={() => setGuideTarget(null)}
            />
          )}
          {tab === "agent-setup" && <AgentSetup />}
          {tab === "account" && <Account />}
        </div>
      </div>
    </AppShell>
  );
}

/** The left navigation column. Collapses to an icon-only rail (`collapsed`):
 *  the width shrinks to the icon gutter, labels are hidden, items center their
 *  icon and gain a `title`/`aria-label` tooltip, and the header swaps the
 *  wordmark for the brand mark. Icons stay clickable in both states. A toggle
 *  button (desktop only) flips between the two. */
function NavSidebar({
  tab,
  setTab,
  guideCategory,
  onOpenTasks,
  onOpenCategory,
  collapsed,
  showToggle,
  onToggle,
}: {
  tab: TabId;
  setTab: (t: TabId) => void;
  guideCategory: string | null;
  onOpenTasks: () => void;
  onOpenCategory: (title: string) => void;
  collapsed: boolean;
  showToggle: boolean;
  onToggle: () => void;
}) {
  const guide = useGuide();
  // The design-system primitives bake in fixed widths/paddings (w-60, px-5,
  // px-3) and @huskdev/ui's `cn` does NOT tailwind-merge, so a conflicting
  // class can't override them. Inline style wins unconditionally, so the
  // collapsed dimensional overrides go through `style`.
  const collapsedNoPad = collapsed
    ? { paddingLeft: 0, paddingRight: 0 }
    : undefined;

  // The categories are a second level under the Guide entry, so they show only
  // while that section is the one being used. Everywhere else the rail is the
  // top-level destinations and nothing more.
  const expanded = tab === "guide";

  const item = (n: { id: TabId; label: string; icon: ReactNode }) => {
    const isGuide = n.id === "guide";
    return (
      <SidebarItem
        key={n.id}
        as="button"
        type="button"
        icon={n.icon}
        active={tab === n.id && (!isGuide || guideCategory === null)}
        onClick={() => (isGuide ? onOpenTasks() : setTab(n.id))}
        title={collapsed ? n.label : undefined}
        aria-label={collapsed ? n.label : undefined}
        aria-expanded={isGuide && !collapsed ? expanded : undefined}
        className={cn("w-full", collapsed ? "justify-center" : "text-left")}
        style={collapsedNoPad}
      >
        {!collapsed && <span className="flex-1 truncate">{n.label}</span>}
        {!collapsed && isGuide && (
          <ChevronRight
            size={13}
            aria-hidden="true"
            className={cn(
              "shrink-0 text-fg-subtle transition-transform",
              expanded && "rotate-90",
            )}
          />
        )}
      </SidebarItem>
    );
  };

  // Open work per category, from the same partition the Tasks meter counts.
  const categories = (guide.data?.categories ?? []).map((c) => ({
    title: c.title,
    open: c.items.filter((t) => t.bucket === "todo").length,
  }));

  return (
    <Sidebar
      className="transition-[width] duration-200"
      style={collapsed ? { width: "4rem" } : undefined}
    >
      <SidebarHeader
        className={cn(collapsed && "justify-center")}
        style={collapsedNoPad}
      >
        {!collapsed && <LogoLockup className="h-6 w-auto" />}
        {showToggle && (
          <button
            type="button"
            onClick={onToggle}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-pressed={collapsed}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className={cn(
              "grid size-8 shrink-0 place-items-center rounded-md text-fg-subtle transition-colors hover:bg-surface hover:text-fg focus-ring",
              !collapsed && "ml-auto",
            )}
          >
            {collapsed ? (
              <PanelLeftOpen size={16} />
            ) : (
              <PanelLeftClose size={16} />
            )}
          </button>
        )}
      </SidebarHeader>
      <SidebarNav>
        <SidebarGroup>
          {/* Feed is a second level under Scan: the same scan data with no
              grouping at all, so it belongs to that section rather than
              standing beside it. */}
          {NAV.flatMap((n) =>
            n.id === "scan" && !collapsed && (tab === "scan" || tab === "feed")
              ? [
                  item(n),
                  <SidebarItem
                    key="feed"
                    as="button"
                    type="button"
                    active={tab === "feed"}
                    onClick={() => setTab("feed")}
                    className="w-full pl-9 text-left"
                  >
                    <span className="flex-1 truncate text-[13px]">Feed</span>
                  </SidebarItem>,
                ]
              : [item(n)],
          )}
          {/* The icon rail has no room for a second level, so the categories
              fold away with the labels and the roll-up stands in for them. */}
          {!collapsed &&
            expanded &&
            categories.map((c) => (
              <SidebarItem
                key={c.title}
                as="button"
                type="button"
                active={tab === "guide" && guideCategory === c.title}
                onClick={() => onOpenCategory(c.title)}
                className="w-full pl-9 text-left"
              >
                <span className="flex-1 truncate text-[13px]">{c.title}</span>
                {c.open > 0 && (
                  <span className="shrink-0 tabular-nums text-[11px] text-fg-subtle">
                    {c.open}
                  </span>
                )}
              </SidebarItem>
            ))}
          {NAV_TAIL.map(item)}
        </SidebarGroup>
      </SidebarNav>
      <HelpMenu collapsed={collapsed} />
      <SidebarFooter style={{ padding: 0 }}>
        <SidebarProfile
          active={tab === "account"}
          collapsed={collapsed}
          onOpen={() => setTab("account")}
        />
      </SidebarFooter>
    </Sidebar>
  );
}

function HelpMenu({ collapsed }: { collapsed: boolean }) {
  const [open, setOpen] = useState(false);
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const closeOnOutsideClick = (event: MouseEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", closeOnOutsideClick);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("mousedown", closeOnOutsideClick);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [open]);

  const primaryLinks = [
    {
      label: "Docs",
      href: "https://husk-security.dev/docs",
      icon: <FileText size={15} />,
    },
    {
      label: "GitHub",
      href: "https://github.com/husk-security/husk",
      icon: <GithubGlyph />,
    },
    {
      label: "Report an issue",
      href: "https://github.com/husk-security/husk/issues/new",
      icon: <ExternalLink size={15} />,
    },
  ];

  return (
    <div
      ref={containerRef}
      className="relative shrink-0 border-t border-border"
    >
      <button
        type="button"
        data-tour="help-button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={collapsed ? "Help" : undefined}
        title={collapsed ? "Help" : undefined}
        onClick={() => setOpen((value) => !value)}
        className={cn(
          "flex w-full items-center gap-3 py-3 text-left font-sans text-fg-muted transition-colors hover:bg-surface hover:text-fg focus-ring",
          collapsed ? "justify-center px-0" : "px-4",
        )}
      >
        <CircleHelp size={17} className="shrink-0 text-fg-subtle" />
        <span
          className={cn("min-w-0 flex-1 text-[13px]", collapsed && "hidden")}
        >
          Help
        </span>
        {!collapsed && (
          <ChevronRight size={15} className="shrink-0 text-fg-subtle" />
        )}
      </button>

      {open && (
        <div
          role="menu"
          aria-label="Help"
          className="absolute bottom-0 left-[calc(100%+0.5rem)] z-50 w-56 overflow-hidden rounded-lg border border-border bg-surface-raised py-1 shadow-overlay"
        >
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              setFeedbackOpen(true);
            }}
            data-tour="feedback-item"
            className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left text-[13px] text-fg-muted transition-colors hover:bg-surface hover:text-fg focus-ring"
          >
            <span className="shrink-0 text-fg-subtle">
              <MessageSquare size={15} />
            </span>
            <span className="min-w-0 flex-1">Send feedback</span>
          </button>
          <div className="my-1 border-t border-border" />
          {primaryLinks.map((link) => (
            <a
              key={link.label}
              href={link.href}
              target="_blank"
              rel="noreferrer noopener"
              role="menuitem"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2.5 px-3 py-2.5 text-[13px] text-fg-muted transition-colors hover:bg-surface hover:text-fg focus-ring"
            >
              <span className="shrink-0 text-fg-subtle">{link.icon}</span>
              <span className="min-w-0 flex-1">{link.label}</span>
              <ExternalLink size={13} className="shrink-0 text-fg-subtle" />
            </a>
          ))}
          <div className="my-1 border-t border-border" />
          {[
            ["Discord", DISCORD_URL],
            ["LinkedIn", "https://www.linkedin.com/company/huskdev/"],
            ["X", "https://x.com/HuskHQ"],
          ].map(([label, href]) => (
            <a
              key={label}
              href={href}
              target="_blank"
              rel="noreferrer noopener"
              role="menuitem"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2 px-3 py-2.5 text-[13px] text-fg-muted transition-colors hover:bg-surface hover:text-fg focus-ring"
            >
              <span className="min-w-0 flex-1">{label}</span>
              <ExternalLink size={13} className="shrink-0 text-fg-subtle" />
            </a>
          ))}
        </div>
      )}
      <FeedbackDialog open={feedbackOpen} onOpenChange={setFeedbackOpen} />
    </div>
  );
}

function GithubGlyph() {
  return (
    <svg
      viewBox="0 0 16 16"
      aria-hidden="true"
      className="size-[15px]"
      fill="currentColor"
    >
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}

/** The one-time telemetry consent card: shown after a scan has completed
 *  successfully while the decision was never made on any surface (CLI, TUI,
 *  or here). Mirrors `src/cloud/telemetry.rs::CONSENT_QUESTION`/`_DETAIL`/
 *  `_OFF_HINT`; keep the copy in sync. Non-blocking and dismissible; nothing
 *  is ever pre-checked, and dismissing counts as "no" so the card never
 *  returns. The server owns the decision of whether the ask is due. */
function TelemetryConsentCard() {
  const live = useLive();
  const machine = useMachine();
  const consent = useTelemetryConsent();
  const answer = useTelemetryConsentAnswer();

  if (!consent.data?.ask_due) return null;
  // Only over completed results: never while scanning, never on the idle
  // empty state, never after a failed scan. Either slot counts; the first
  // scan a fresh install runs in the web UI is usually the machine one.
  const finished = (ld?: LiveScan) =>
    !!ld && !ld.running && !!ld.finished_at && !ld.error;
  if (!finished(live.data) && !finished(machine.data)) return null;

  return (
    <div
      role="status"
      className="flex shrink-0 flex-wrap items-center gap-2.5 border-b border-border bg-surface px-4 py-2.5 text-[12.5px] text-fg"
    >
      <div className="min-w-0 flex-1 basis-64">
        <span className="font-medium">
          Share anonymous usage data with Husk?
        </span>{" "}
        <span className="text-fg-muted">
          No account, no identifier: just daily aggregate counts, never file
          paths or package names. Turn off anytime:{" "}
          <code className="font-mono text-[12px]">husk telemetry off</code>
        </span>
      </div>
      <button
        type="button"
        onClick={() => answer.mutate(true)}
        disabled={answer.isPending}
        className="shrink-0 rounded-md border border-border bg-fg px-2.5 py-1 text-[12px] font-medium text-bg transition-opacity hover:opacity-90 focus-ring disabled:opacity-60"
      >
        Enable
      </button>
      <button
        type="button"
        onClick={() => answer.mutate(false)}
        disabled={answer.isPending}
        className="shrink-0 rounded-md border border-border bg-bg px-2.5 py-1 text-[12px] text-fg transition-colors hover:bg-surface focus-ring disabled:opacity-60"
      >
        No thanks
      </button>
      <button
        type="button"
        onClick={() => answer.mutate(false)}
        disabled={answer.isPending}
        aria-label="Dismiss"
        title="Dismiss"
        className="grid size-7 shrink-0 place-items-center rounded-md text-fg-subtle transition-colors hover:bg-surface hover:text-fg focus-ring disabled:opacity-60"
      >
        <X size={14} />
      </button>
    </div>
  );
}

/** Mirrors `cache::STALE_REPORT_AFTER_HOURS` in the Rust CLI; keep in sync. */
const STALE_AFTER_MS = 24 * 60 * 60 * 1000;

/** Human age for the stale banner: hours until two full days, then days;
 *  the same coarse granularity as the CLI/TUI warning. */
function formatAge(ms: number): string {
  const hours = Math.floor(ms / 3_600_000);
  if (hours < 48) return `${hours} hours`;
  return `${Math.floor(hours / 24)} days`;
}

/** Dismissible warning shown when the served report is older than a day;
 *  the web mirror of the CLI's stderr warning and the TUI's header badge.
 *  Dismissal is remembered per report (keyed on `generated_at`), so a newer
 *  report that goes stale warns again. */
function StaleScanBanner() {
  const live = useLive();
  const rescan = useRescan();
  const [dismissed, setDismissed] = useState(() =>
    localStorage.getItem("husk-stale-dismissed"),
  );

  const ld = live.data;
  // Nothing to warn about while scanning (the report is being rebuilt) or
  // before any scan exists (idle has its own empty state).
  if (!ld || ld.running || !ld.finished_at) return null;
  const generatedAt = ld.report.generated_at;
  const age = Date.now() - new Date(generatedAt).getTime();
  if (!(age > STALE_AFTER_MS) || dismissed === generatedAt) return null;

  return (
    <div
      role="status"
      className="flex shrink-0 items-center gap-2.5 border-b border-border bg-warning-tint px-4 py-2 text-[12.5px] text-fg"
    >
      <TriangleAlert size={14} className="shrink-0 text-warning" />
      <span className="min-w-0 flex-1">
        Last scan was {formatAge(age)} ago; the findings below may be out of
        date.
      </span>
      <button
        type="button"
        onClick={() => rescan.mutate(undefined)}
        disabled={rescan.isPending}
        className="shrink-0 rounded-md border border-border bg-bg px-2.5 py-1 text-[12px] text-fg transition-colors hover:bg-surface focus-ring disabled:opacity-60"
      >
        {rescan.isPending ? "Starting…" : "Rescan now"}
      </button>
      <button
        type="button"
        onClick={() => {
          localStorage.setItem("husk-stale-dismissed", generatedAt);
          setDismissed(generatedAt);
        }}
        aria-label="Dismiss"
        title="Dismiss"
        className="grid size-7 shrink-0 place-items-center rounded-md text-fg-subtle transition-colors hover:bg-surface hover:text-fg focus-ring"
      >
        <X size={14} />
      </button>
    </div>
  );
}

/** Persistent bar above every view: what the scan is doing (left) and
 *  checklist completion (right), each a shortcut back to its tab.
 *
 *  The scan half is a progress bar only while there is progress to report. A
 *  finished scan has no percentage worth showing, and a full green bar over a
 *  page of critical findings reads as "you are fine", so it is replaced by the result
 *  the reader actually wants: how much was found, and how much of it is
 *  critical. */
function TopBar({
  tab,
  onOpenTab,
  onOpenTasks,
  onOpenTutorial,
}: {
  tab: TabId;
  onOpenTab: (t: TabId) => void;
  onOpenTasks: () => void;
  onOpenTutorial: () => void;
}) {
  const live = useLive();
  const guide = useGuide();

  // `progressPercent` interpolates within the running pipeline step, so the bar
  // climbs continuously through long stages instead of parking at a step
  // boundary. Before the first /api/live response we have no state at all, and
  // idle is `husk web` with no scan started yet: both are 0%, never "complete".
  const ld = live.data;
  const running = ld?.running ?? false;
  const idle = !!ld && !ld.running && !ld.finished_at;
  const finished = !!ld && !running && !idle;
  const stats = ld?.report.stats;

  // Tasks: review progress, not a security score. Take the server's own
  // `percent` so this bar and the Guide page can never round differently.
  const g = guide.data;
  const taskPct = g?.percent ?? 0;

  return (
    <div className="flex shrink-0 items-center gap-3 border-b border-border bg-bg px-4 py-2.5">
      <MachineChip active={tab === "scan"} onOpen={() => onOpenTab("scan")} />
      {finished ? (
        <ScanResult
          label="Projects"
          findings={stats?.findings ?? 0}
          critical={stats?.critical ?? 0}
          active={tab === "projects"}
          onClick={() => onOpenTab("projects")}
        />
      ) : (
        <ProgressBar
          label="Projects"
          pct={!ld || idle ? 0 : Math.round(progressPercent(ld))}
          active={tab === "projects"}
          onClick={() => onOpenTab("projects")}
          hint={!ld ? "…" : running ? "scanning…" : "no scan yet"}
        />
      )}
      <ProgressBar
        label="Tasks"
        pct={taskPct}
        active={tab === "guide"}
        onClick={onOpenTasks}
        hint={
          g
            ? taskPct >= 100
              ? "all reviewed"
              : `${g.handled}/${g.total} handled`
            : "…"
        }
      />
      <button
        type="button"
        onClick={onOpenTutorial}
        data-tour="tour-button"
        title="Show the tour"
        aria-label="Show the tour"
        className="grid size-8 shrink-0 place-items-center rounded-md text-fg-subtle transition-colors hover:bg-surface hover:text-fg focus-ring"
      >
        <GraduationCap size={16} />
      </button>
    </div>
  );
}

/** The standing machine-posture slot in the top bar. It renders in the same two
 *  shapes as the project scan slot so the two read as one control in every
 *  state; the scan action itself lives in the Scan view both slots open. */
function MachineChip({
  active,
  onOpen,
}: {
  active: boolean;
  onOpen: () => void;
}) {
  const machine = useMachine();
  const md = machine.data;
  const running = md?.running ?? false;
  const finished = !!md && !running && !!md.finished_at;

  return (
    <div data-tour="machine-chip" className="flex min-w-0 flex-1">
      {finished ? (
        <ScanResult
          label="Machine"
          findings={md.report.stats?.findings ?? 0}
          critical={md.report.stats?.critical ?? 0}
          active={active}
          onClick={onOpen}
        />
      ) : (
        <ProgressBar
          label="Machine"
          pct={!md || !running ? 0 : Math.round(progressPercent(md))}
          active={active}
          onClick={onOpen}
          hint={!md ? "…" : running ? "scanning…" : "no scan yet"}
        />
      )}
    </div>
  );
}

function ScanResult({
  label,
  findings,
  critical,
  active,
  onClick,
}: {
  label: string;
  findings: number;
  critical: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active ? "true" : undefined}
      className={cn(
        "flex min-w-0 flex-1 items-center gap-2.5 rounded-md border px-3 py-1.5 text-left transition-colors focus-ring",
        active
          ? "border-border-strong bg-surface"
          : "border-border bg-bg hover:bg-surface",
      )}
    >
      <span className="shrink-0 text-[12px] text-fg">{label}</span>
      <span className="min-w-0 flex-1 truncate text-[12px] text-fg-muted">
        <span className="tabular-nums text-fg">{findings}</span>{" "}
        {findings === 1 ? "finding" : "findings"}
        {critical > 0 && (
          <span className="text-severity-critical">
            {" · "}
            <span className="tabular-nums">{critical}</span> critical
          </span>
        )}
      </span>
    </button>
  );
}

/** A labeled progress bar that fills left-to-right and goes green at 100%.
 *  The whole row is a button that navigates to the relevant tab. */
function ProgressBar({
  label,
  pct,
  hint,
  active,
  onClick,
}: {
  label: string;
  pct: number;
  hint: string;
  active: boolean;
  onClick: () => void;
}) {
  const clamped = Math.max(0, Math.min(100, pct));
  const done = clamped >= 100;

  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active ? "true" : undefined}
      aria-label={`${label}: ${clamped}% (${hint})`}
      className={cn(
        "group flex min-w-0 flex-1 items-center gap-2.5 rounded-md border px-3 py-1.5 transition-colors focus-ring",
        active
          ? "border-border-strong bg-surface"
          : "border-border bg-bg hover:bg-surface",
      )}
    >
      <span
        className={cn(
          "flex shrink-0 items-center gap-1.5 text-[12px]",
          done ? "text-success" : "text-fg-muted",
        )}
      >
        <span className="text-fg">{label}</span>
      </span>
      <span
        className="relative h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-border"
        role="progressbar"
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <span
          className={cn(
            "absolute inset-y-0 left-0 rounded-full transition-[width,background-color] duration-500 ease-out",
            done ? "bg-success" : "bg-accent",
          )}
          style={{ width: `${clamped}%` }}
        />
      </span>
      <span
        className={cn(
          "shrink-0 text-[11.5px] tabular-nums",
          done ? "text-success" : "text-fg-muted",
        )}
      >
        {clamped}%
      </span>
      <span className="hidden shrink-0 text-[11px] text-fg-subtle sm:inline">
        {hint}
      </span>
    </button>
  );
}

/** Account entry at the sidebar foot: the signed-in profile, or a Sign in
 *  affordance when logged out. Replaces both the old "Account" nav item and the
 *  footer blurb. */
function SidebarProfile({
  active,
  collapsed,
  onOpen,
}: {
  active: boolean;
  collapsed: boolean;
  onOpen: () => void;
}) {
  const closeDrawer = useCloseDrawer();
  const account = useAccount();
  const a = account.data;
  const connected = a?.connected && a.account;
  const name = a?.account?.display_name || a?.account?.email || "";
  const initial = name.trim().charAt(0).toUpperCase() || "?";
  const label = connected ? name : "Account: sign-in coming soon";

  return (
    <button
      type="button"
      onClick={() => {
        onOpen();
        closeDrawer();
      }}
      aria-current={active ? "page" : undefined}
      title={collapsed ? label : undefined}
      aria-label={collapsed ? label : undefined}
      className={cn(
        "flex w-full items-center gap-3 py-3 text-left font-sans transition-colors focus-ring",
        collapsed ? "justify-center px-0" : "px-4",
        active ? "bg-accent-subtle" : "hover:bg-surface",
      )}
    >
      {connected ? (
        <span className="grid size-7 shrink-0 place-items-center rounded-full bg-accent-subtle text-[12px] text-fg">
          {initial}
        </span>
      ) : (
        <LogIn size={16} className="shrink-0 text-fg-subtle" />
      )}
      <span className={cn("min-w-0 flex-1", collapsed && "hidden")}>
        {connected ? (
          <>
            <span className="block truncate text-[13px] text-fg">{name}</span>
            <span className="block truncate text-[11px] text-fg-subtle">
              {a?.account?.tier ? `${a.account.tier} · signed in` : "signed in"}
            </span>
          </>
        ) : (
          <>
            <span className="block text-[13px] text-fg">Account</span>
            <span className="block text-[11px] text-fg-subtle">
              sign-in coming soon
            </span>
          </>
        )}
      </span>
      {connected && !collapsed && (
        <UserRound size={14} className="shrink-0 text-fg-subtle" />
      )}
    </button>
  );
}
