import { Button, cn } from "@huskdev/ui";
import {
  BookOpen,
  Bot,
  FileCode,
  FolderSearch,
  GraduationCap,
  MessageSquare,
  Radar,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";

const SEEN_KEY = "husk-tutorial-seen";

/** Should the tutorial auto-open on this launch? True only the first time. */
export function tutorialUnseen(): boolean {
  return localStorage.getItem(SEEN_KEY) !== "1";
}

/** Tabs the tour can force the app onto. */
export type TourTab = "scan" | "projects" | "guide" | "agent-setup";

type Step = {
  icon: ReactNode;
  title: string;
  body: ReactNode;
  /** Force this tab before anchoring, so the feature is actually on screen. */
  tab?: TourTab;
  /** `data-tour` id of the element to spotlight; centered card when absent. */
  target?: string;
  /** `data-tour` id of a collapsed control to open, so `target` is on screen. */
  expand?: string;
};

const STEPS: Step[] = [
  {
    icon: <ShieldCheck size={16} />,
    title: "Welcome to Husk",
    body: (
      <>
        Husk scans this machine for security issues: vulnerable dependencies,
        leaked secrets, risky AI configs and more. Scans run locally; online
        checks send package names and versions to public advisory databases,
        never file contents.
      </>
    ),
  },
  {
    icon: <FolderSearch size={16} />,
    title: "Pick a folder and scan",
    tab: "projects",
    target: "scan-actions",
    body: (
      <>
        Choose the folder you want checked, then press Scan to start. Nothing
        runs until you do, and results stream in here as Husk works.
      </>
    ),
  },
  {
    icon: <Radar size={16} />,
    title: "Slice the findings",
    tab: "projects",
    target: "scan-filters",
    body: (
      <>
        The scan results land here, grouped by project and sorted worst first.
        Filter through the findings by severity, type, and language using the
        chips in the Filters panel.
      </>
    ),
  },
  {
    icon: <Wrench size={16} />,
    title: "The detailed view",
    tab: "projects",
    target: "scan-detail",
    body: (
      <>
        The detail pane shows what a finding means and where it came from. Scan
        never changes anything on this machine. When you want to act on a
        finding, "Fix this in the Guide" takes you to the task that covers it,
        and "Fix with AI" hands it to your coding agent instead.
      </>
    ),
  },
  {
    icon: <FileCode size={16} />,
    title: "Read the flagged file",
    tab: "projects",
    target: "show-file",
    body: (
      <>
        Every affected file has a "Show file" action. It opens the file
        read-only, syntax highlighted, scrolled to the flagged line, so you can
        judge a finding without opening the flagged tree in your editor.
      </>
    ),
  },
  {
    icon: <BookOpen size={16} />,
    title: "The Guide",
    tab: "guide",
    target: "guide-list",
    body: (
      <>
        One checklist for this machine, worst first. Each task explains why it
        matters, and the ones Husk can fix itself say so on the row. Open a task
        and apply its fixes in one go: thirty vulnerable packages are one
        decision, grouped by the project they live in. Everything else is
        copy-paste steps, or hand it to your coding agent.
      </>
    ),
  },
  {
    icon: <Bot size={16} />,
    title: "Fix with AI",
    tab: "agent-setup",
    target: "agent-setup",
    body: (
      <>
        Wire up the coding agent of your choice, then just ask it to fix a
        finding: it reads the finding over MCP, applies the fix, and verifies
        it. Fix with AI on any finding links to the examples.
      </>
    ),
  },
  {
    icon: <MessageSquare size={16} />,
    title: "Tell us what is off",
    target: "feedback-item",
    expand: "help-button",
    body: (
      <>
        Something confusing, broken, or great? Send feedback from the Help menu,
        or run <code className="font-mono">husk feedback</code> in a terminal. A
        wrong finding is worth reporting: false positives are bugs.
      </>
    ),
  },
  {
    icon: <GraduationCap size={16} />,
    title: "Rerun this tour any time",
    target: "tour-button",
    body: (
      <>
        That is the whole loop: scan to see what is here, then work the Guide.
        This button replays the tour whenever you want a refresher.
      </>
    ),
  },
];

const CARD_W = 360;
const GAP = 12; // spotlight padding + card offset

type Anchor = {
  rect: DOMRect;
  /** Below/above the target when there is room; tall targets (full-height
   *  panes) get the card overlaid inside their top edge instead. */
  place: "below" | "above" | "inside";
  /** Glide from the previous position (the move onto a new step) or land
   *  instantly (a correction while the target's own content settles). */
  animate: boolean;
};

/**
 * The first-run product tour, as a spotlight walkthrough: each step forces
 * the relevant tab, dims everything except the feature it talks about, and
 * anchors an arrowed card next to it. Auto-opens once (localStorage-gated,
 * see `tutorialUnseen`), skippable at every step (button or Escape),
 * rerunnable from the TopBar's graduation-cap button.
 */
export function Tutorial({
  open,
  onClose,
  onNavigate,
}: {
  open: boolean;
  onClose: () => void;
  onNavigate: (tab: TourTab) => void;
}) {
  const [step, setStep] = useState(0);
  const [anchor, setAnchor] = useState<Anchor | null>(null);
  const s = STEPS[step];

  const close = () => {
    localStorage.setItem(SEEN_KEY, "1");
    setStep(0);
    onClose();
  };

  // Force the step's tab, then find + measure its target. The target may
  // still be mounting after a tab switch, so retry across animation frames.
  // biome-ignore lint/correctness/useExhaustiveDependencies: `close` is stable in behavior; re-running on it would re-measure needlessly.
  useEffect(() => {
    if (!open) return;
    if (s.tab) onNavigate(s.tab);
    // A target inside a closed menu has no box to spotlight, so open it first.
    const opener = s.expand
      ? document.querySelector<HTMLElement>(`[data-tour="${s.expand}"]`)
      : null;
    if (opener?.getAttribute("aria-expanded") === "false") opener.click();
    let raf = 0;
    let tries = 0;
    let placed = "";
    const commit = (rect: DOMRect, animate: boolean) => {
      const spaceBelow = window.innerHeight - rect.bottom;
      setAnchor({
        rect,
        place:
          spaceBelow >= 260 ? "below" : rect.top >= 260 ? "above" : "inside",
        animate,
      });
    };
    const measure = () => {
      const el = s.target
        ? document.querySelector(`[data-tour="${s.target}"]`)
        : null;
      if (el) {
        el.scrollIntoView({ block: "nearest" });
        const rect = el.getBoundingClientRect();
        const key = `${rect.top}|${rect.left}|${rect.width}|${rect.height}`;
        // Glide the moment the target exists, so a step never stalls waiting
        // for its pane to finish settling. Everything the target does after
        // that (a list filling in, a pane finishing its layout) is followed
        // without a transition: re-aiming a 300ms glide mid-flight is the
        // drift, not the glide itself.
        if (key !== placed) {
          const first = placed === "";
          placed = key;
          commit(rect, first);
        }
      } else if (!s.target) {
        setAnchor(null);
        return;
      }
      // Finding the target is not the end of the job: it keeps moving for a few
      // frames while the pane it lives in settles, and content that renders
      // above it changes its offset. Trusting the first frame parks the
      // spotlight where the target used to be.
      if (tries < 60) {
        tries += 1;
        raf = requestAnimationFrame(measure);
      } else if (!el) {
        setAnchor(null);
      }
    };
    raf = requestAnimationFrame(measure);
    const remeasure = () => {
      tries = 0;
      raf = requestAnimationFrame(measure);
    };
    window.addEventListener("resize", remeasure);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", remeasure);
      window.removeEventListener("keydown", onKey);
      // Leave the menu as the step found it (it closes itself on an outside
      // click, so only close what is still open).
      if (opener?.getAttribute("aria-expanded") === "true") opener.click();
    };
  }, [open, step, s.tab, s.target, s.expand, onNavigate]);

  if (!open) return null;

  const r = anchor?.rect ?? null;
  // Card position: under (or over) the target, horizontally centered on it
  // and clamped to the viewport. Without a target: dead center.
  const cardLeft = r
    ? Math.max(
        GAP,
        Math.min(
          r.left + r.width / 2 - CARD_W / 2,
          window.innerWidth - CARD_W - GAP,
        ),
      )
    : 0;
  const arrowLeft = r
    ? Math.max(20, Math.min(r.left + r.width / 2 - cardLeft - 6, CARD_W - 32))
    : 0;

  return (
    <div className="fixed inset-0 z-[100]" role="dialog" aria-modal="true">
      {/* Scrim. With a target the spotlight's box-shadow does the dimming and
          this stays transparent (it still eats clicks); otherwise it dims. */}
      <div className={cn("absolute inset-0", !r && "bg-black/60")} />
      {r && (
        <div
          className={cn(
            "absolute rounded-lg ring-2 ring-accent",
            anchor?.animate && "transition-all duration-300",
          )}
          style={{
            left: r.left - 6,
            top: r.top - 6,
            width: r.width + 12,
            height: r.height + 12,
            boxShadow: "0 0 0 9999px rgba(0,0,0,0.6)",
          }}
        />
      )}

      <div
        className={cn(
          "absolute rounded-xl border border-border-strong bg-bg p-4 shadow-2xl",
          anchor?.animate && "transition-all duration-300",
        )}
        style={
          r
            ? {
                left: cardLeft,
                width: CARD_W,
                maxWidth: `calc(100vw - ${GAP * 2}px)`,
                ...(anchor?.place === "below"
                  ? { top: r.bottom + GAP + 8 }
                  : anchor?.place === "above"
                    ? { bottom: window.innerHeight - r.top + GAP + 8 }
                    : // "inside": pinned near the tall pane's top edge.
                      { top: Math.max(r.top + 20, GAP) }),
              }
            : {
                left: "50%",
                top: "50%",
                transform: "translate(-50%, -50%)",
                width: CARD_W,
                maxWidth: `calc(100vw - ${GAP * 2}px)`,
              }
        }
      >
        {r && anchor?.place !== "inside" && (
          <span
            className={cn(
              "absolute size-3 rotate-45 border-border-strong bg-bg",
              anchor?.place === "below"
                ? "-top-1.5 border-t border-l"
                : "-bottom-1.5 border-r border-b",
            )}
            style={{ left: arrowLeft }}
          />
        )}
        <p className="flex items-center gap-2 text-[14px] font-semibold text-fg">
          <span className="text-accent">{s.icon}</span>
          {s.title}
        </p>
        <p className="mt-2 text-[13px] leading-relaxed text-fg-muted">
          {s.body}
        </p>
        <div className="mt-4 flex items-center gap-3">
          <span className="flex items-center gap-1.5" aria-hidden>
            {STEPS.map((st, i) => (
              <span
                key={st.title}
                className={cn(
                  "size-1.5 rounded-full transition-colors",
                  i === step ? "bg-accent" : "bg-border-strong",
                )}
              />
            ))}
          </span>
          <span className="flex-1" />
          {step < STEPS.length - 1 && (
            <Button variant="ghost" size="sm" onClick={close}>
              Skip
            </Button>
          )}
          {step > 0 && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setStep(step - 1)}
            >
              Back
            </Button>
          )}
          {step === STEPS.length - 1 ? (
            <Button size="sm" onClick={close}>
              Done
            </Button>
          ) : (
            <Button size="sm" onClick={() => setStep(step + 1)}>
              Next
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
