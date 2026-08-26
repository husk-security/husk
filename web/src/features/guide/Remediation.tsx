import { Badge, Button, Card, Checkbox, cn } from "@huskdev/ui";
import { Check, TriangleAlert, X } from "lucide-react";
import { useMemo, useState } from "react";
import { SeverityBadge } from "@/features/scan/severity";
import {
  type Finding,
  type RemediationProposal,
  useApplyRemediation,
  useLive,
  useToolAvailability,
} from "@/lib/api";
import { PathLabel } from "@/lib/path";
import { Prose } from "@/lib/prose";
import { CommandList, DiffList, StepList, Transcript } from "./FixPreview";
import {
  advisoryLinks,
  applySentence,
  commandsOf,
  type DependencyCard as DependencyCardModel,
  diffsOf,
  intentOf,
  isActionable,
  type ProposalCard as ProposalCardModel,
  planCards,
  type RunnableRow,
  resolveRow,
  stepsOf,
} from "./proposals";

/** Width an apply control is given wherever it appears. Confirming swaps one
 *  button for two, and the slot is sized for the wider of them so nothing
 *  around it reflows mid-decision. */
const ACTION_SLOT = "min-w-[7.5rem]";
const ROW_ACTION_SLOT = "min-w-[5.5rem]";

/** The one place in the web UI where a fix is taken. Every card states what
 *  applying would do before it offers to do it: the files Husk rewrites, the
 *  program it then runs, and the one-liner that does the same by hand. All of
 *  it comes from the server's plan; the browser picks which proposal ids to
 *  send, never what they contain. */
export function Remediation({
  proposals,
}: {
  proposals: RemediationProposal[];
}) {
  const findings = useFindingIndex();
  const tools = useToolAvailability();
  const apply = useApplyAndVerify();
  // PEP 668 is a decision about one workspace's Python, so the override belongs
  // to the card holding those rows rather than to the whole task.
  const [allowBreak, setAllowBreak] = useState<Set<string>>(new Set());

  const cards = useMemo(() => planCards(proposals), [proposals]);
  // Runnability is resolved once, here, so a card and the section-wide apply
  // cannot disagree about which rows Husk can take.
  const resolved = useMemo(
    () =>
      cards.map((card) => ({
        card,
        rows:
          card.kind === "dependency"
            ? card.rows.map((row) =>
                resolveRow(
                  row,
                  tools.data?.[row.tool],
                  allowBreak.has(card.key),
                ),
              )
            : [],
      })),
    [cards, tools.data, allowBreak],
  );

  if (cards.length === 0) return null;

  const takeable = (entry: (typeof resolved)[number]): string[] =>
    entry.card.kind === "dependency"
      ? entry.rows.filter((row) => row.runnable).map((row) => row.proposal.id)
      : isActionable(entry.card.proposal)
        ? [entry.card.proposal.id]
        : [];
  const everything = resolved.flatMap(takeable);
  // A single card's own button already applies everything in it, so a second
  // control meaning the same thing appears only once there are several cards.
  const sweeping =
    resolved.filter((entry) => takeable(entry).length > 0).length > 1;
  const overriding = resolved.some((entry) =>
    entry.rows.some((row) => row.runnable && row.overridable),
  );

  return (
    <div className="mt-6">
      <div className="mb-2.5 flex flex-wrap items-center gap-2">
        <p className="min-w-0 flex-1 text-[15px] font-medium text-fg">
          Fix with Husk
        </p>
        {sweeping && (
          <Apply
            label={`Apply all ${everything.length}`}
            enabled={everything.length > 0}
            state={apply.stateOf("all")}
            onRun={() => apply.run("all", everything, overriding)}
          />
        )}
      </div>
      {apply.message && (
        <p className="mb-2.5 text-[12px] text-fg-muted">{apply.message}</p>
      )}
      <div className="grid gap-3">
        {resolved.map(({ card, rows }) =>
          card.kind === "dependency" ? (
            <DependencyCard
              key={card.key}
              card={card}
              rows={rows}
              findings={findings}
              apply={apply}
              allowBreak={allowBreak.has(card.key)}
              onAllowBreak={(on) =>
                setAllowBreak((prev) => {
                  const next = new Set(prev);
                  if (on) next.add(card.key);
                  else next.delete(card.key);
                  return next;
                })
              }
            />
          ) : (
            <ProposalCard key={card.key} card={card} apply={apply} />
          ),
        )}
      </div>
      {apply.output && <Transcript text={apply.output} />}
    </div>
  );
}

/** Findings by id, so a package row can name the advisories that justify it
 *  instead of a count of opaque ids. */
function useFindingIndex(): Map<string, Finding> {
  const report = useLive().data?.report;
  return useMemo(
    () => new Map((report?.findings ?? []).map((f) => [f.id, f])),
    [report],
  );
}

/** What one apply control is doing: idle, running the batch it was clicked
 *  for, or held because another one is. */
type ApplyState = "ready" | "running" | "waiting";

/** Apply a batch. Deliberately no rescan afterwards: the executor verifies
 *  each proposal on disk itself (re-parse after edit), a full scan of the
 *  roots takes minutes, and the report catches up on the user's next rescan.
 *
 *  A scan already in flight counts as busy: the server rejects applies while
 *  one runs, since the plan on screen is about to change underneath it.
 *
 *  One instance serves the whole section, so applying a single row holds every
 *  other control rather than letting two batches race for one manifest. */
function useApplyAndVerify() {
  const apply = useApplyRemediation();
  const scanning = useLive().data?.running === true;
  // Which control was clicked, so only that one reports progress.
  const [scope, setScope] = useState<string | null>(null);
  const busy = apply.isPending || scanning;
  return {
    message: apply.data?.message,
    output: apply.data?.results
      .map((result) => result.output)
      .filter((text) => !!text)
      .join("\n"),
    stateOf: (key: string): ApplyState =>
      !busy ? "ready" : scope === key ? "running" : "waiting",
    run: (key: string, ids: string[], allowSystemPackages = false) => {
      if (ids.length === 0) return;
      setScope(key);
      apply.mutate({ ids, allow_system_packages: allowSystemPackages });
    },
  };
}

type ApplyControl = ReturnType<typeof useApplyAndVerify>;

/** An apply control, always above the change it would make so a long diff never
 *  pushes it off screen. Rendered only where there is something to apply: a fix
 *  already true on disk gets no button at all. */
function Apply({
  label,
  enabled,
  state,
  compact,
  onRun,
}: {
  label: string;
  enabled: boolean;
  state: ApplyState;
  compact?: boolean;
  onRun: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const slot = cn(
    "flex shrink-0 items-center justify-end gap-1.5",
    compact ? ROW_ACTION_SLOT : ACTION_SLOT,
  );
  if (state !== "ready") {
    return (
      <span className={slot}>
        <Button size="sm" loading={state === "running"} disabled>
          {state === "running" ? "Applying..." : label}
        </Button>
      </span>
    );
  }
  if (confirming) {
    return (
      <span className={slot}>
        <Button
          variant="secondary"
          size="sm"
          aria-label={`Cancel ${label}`}
          onClick={() => setConfirming(false)}
        >
          <X size={14} />
        </Button>
        <Button
          size="sm"
          aria-label={`Confirm ${label}`}
          onClick={() => {
            setConfirming(false);
            onRun();
          }}
        >
          <Check size={14} /> Confirm
        </Button>
      </span>
    );
  }
  return (
    <span className={slot}>
      <Button size="sm" disabled={!enabled} onClick={() => setConfirming(true)}>
        {label}
      </Button>
    </span>
  );
}

function Header({
  children,
  action,
}: {
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start gap-2 px-3.5 py-3">
      <div className="min-w-0 flex-1">{children}</div>
      {action}
    </div>
  );
}

function Note({ children }: { children: React.ReactNode }) {
  return (
    <p className="flex items-start gap-1.5 px-3.5 pb-2.5 text-[11.5px] leading-snug text-severity-medium">
      <TriangleAlert size={13} className="mt-0.5 shrink-0" />
      <span>{children}</span>
    </p>
  );
}

/** The line that settles what a click does, before either block below it is
 *  read. Absent only when a fix has no preview, which is a fix with no button. */
function Intent({ proposals }: { proposals: RemediationProposal[] }) {
  const sentence = applySentence(intentOf(proposals));
  if (!sentence) return null;
  return (
    <p className="mt-1.5 text-[12px] leading-relaxed text-fg-muted">
      {sentence}
    </p>
  );
}

/** One package manager, one directory, one run. */
function DependencyCard({
  card,
  rows,
  findings,
  apply,
  allowBreak,
  onAllowBreak,
}: {
  card: DependencyCardModel;
  rows: RunnableRow[];
  findings: Map<string, Finding>;
  apply: ApplyControl;
  allowBreak: boolean;
  onAllowBreak: (on: boolean) => void;
}) {
  const runnable = rows.filter((row) => row.runnable);
  const overridable = rows.filter((row) => row.overridable);
  const blocked = rows.length - runnable.length;
  const missingTools = [
    ...new Set(rows.filter((row) => row.toolMissing).map((row) => row.tool)),
  ];
  // A row button and a card button that do the same thing are one button too
  // many, so rows get their own only once the card holds more than one.
  const perRow = runnable.length > 1;
  const proposals = (runnable.length > 0 ? runnable : rows).map(
    (row) => row.proposal,
  );
  const edits = diffsOf(proposals);

  return (
    <Card className="min-w-0 px-0 py-0">
      <Header
        action={
          runnable.length > 0 ? (
            <Apply
              label={perRow ? `Apply ${runnable.length}` : "Apply"}
              enabled
              state={apply.stateOf(card.key)}
              onRun={() =>
                apply.run(
                  card.key,
                  runnable.map((row) => row.proposal.id),
                  runnable.some((row) => row.overridable),
                )
              }
            />
          ) : undefined
        }
      >
        <div className="flex items-center gap-2">
          <Badge>{card.ecosystem}</Badge>
          <PathLabel path={card.workspace} className="text-[11.5px]" />
        </div>
        <p className="mt-1.5 text-[11.5px] text-fg-subtle">
          {rows.length} {rows.length === 1 ? "package" : "packages"}
          {blocked > 0 && `, ${blocked} blocked`}
        </p>
        <Intent proposals={proposals} />
      </Header>

      {overridable.length > 0 && (
        <label className="flex cursor-pointer items-start gap-2 px-3.5 pb-2.5 text-[11.5px] leading-snug text-severity-medium">
          <Checkbox
            checked={allowBreak}
            onCheckedChange={(on) => onAllowBreak(on === true)}
            className="mt-px shrink-0"
          />
          <span>
            Use pip's <code>--break-system-packages</code> for the{" "}
            {overridable.length} PEP 668{" "}
            {overridable.length === 1 ? "package" : "packages"}. This writes
            into the system Python your distro manages and is not undone by a
            rescan; a virtualenv or pipx stays safer.
          </span>
        </label>
      )}
      {missingTools.length > 0 && (
        <Note>
          {missingTools.join(", ")} not installed, so Husk cannot run this here.
        </Note>
      )}

      <ul className="max-h-64 overflow-y-auto border-t border-border">
        {rows.map((row) => (
          <PackageRow
            key={row.proposal.id}
            row={row}
            findings={findings}
            apply={perRow ? apply : undefined}
          />
        ))}
      </ul>

      <CommandList
        commands={commandsOf(proposals)}
        alternative={edits.length > 0}
      />
      <DiffList files={edits} />
    </Card>
  );
}

function PackageRow({
  row,
  findings,
  apply,
}: {
  row: RunnableRow;
  findings: Map<string, Finding>;
  apply?: ApplyControl;
}) {
  const { proposal, blocker } = row;
  const { current_version, target_version, name } = proposal.action;
  const matched = (proposal.finding_ids ?? [])
    .map((id) => findings.get(id))
    .filter((finding) => finding !== undefined);
  const advisories = advisoryLinks(matched);
  // An identifier says which vulnerability; the summary says what it is, which
  // is what decides whether a row is worth taking now.
  const detail = blocker ?? matched[0]?.summary;
  const versions = `${current_version} → ${target_version}`;
  return (
    <li className="flex items-start gap-2.5 border-b border-border px-3.5 py-2 last:border-b-0">
      <span className="min-w-0 flex-1">
        <span className="flex items-baseline gap-2">
          <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-fg">
            {name}
          </span>
          <SeverityBadge
            severity={proposal.severity}
            className="shrink-0 max-sm:hidden"
          />
        </span>
        {/* The version pair is the change itself, so it gets its own line
            rather than competing with a long package name for one. */}
        <span
          className="block truncate font-mono text-[11px] tabular-nums text-fg-muted"
          title={versions}
        >
          {versions}
        </span>
        {/* The blocker is why the row cannot run, and that outranks the
            advisory behind it, so only one of the two gets this line. */}
        {detail && (
          <span
            className={cn(
              "block truncate text-[10.5px] leading-snug",
              blocker ? "text-severity-medium" : "text-fg-subtle",
            )}
            title={detail}
          >
            <Prose text={detail} />
          </span>
        )}
        {advisories.length > 0 && (
          // Every advisory is reachable rather than counted, and a package
          // carrying twenty scrolls inside this box instead of growing the row.
          <span className="mt-0.5 flex max-h-[2.4rem] flex-wrap gap-1 overflow-y-auto overscroll-contain">
            {advisories.map((advisory) => (
              <a
                key={advisory.id}
                href={advisory.url}
                target="_blank"
                rel="noreferrer noopener"
                className="rounded border border-border px-1 font-mono text-[10px] leading-[1.5] text-fg-subtle hover:text-fg"
              >
                {advisory.id}
              </a>
            ))}
          </span>
        )}
      </span>
      {apply && row.runnable && (
        <Apply
          label="Apply"
          enabled
          compact
          state={apply.stateOf(proposal.id)}
          onRun={() => apply.run(proposal.id, [proposal.id], row.overridable)}
        />
      )}
    </li>
  );
}

/** A file edit or a piece of advice: one proposal, one card. */
function ProposalCard({
  card,
  apply,
}: {
  card: ProposalCardModel;
  apply: ApplyControl;
}) {
  const proposal = card.proposal;
  const actionable = isActionable(proposal);
  const edits = diffsOf([proposal]);
  return (
    <Card className="min-w-0 px-0 py-0">
      <Header
        action={
          actionable ? (
            <Apply
              label="Apply"
              enabled
              state={apply.stateOf(card.key)}
              onRun={() => apply.run(card.key, [proposal.id])}
            />
          ) : undefined
        }
      >
        <p
          className="truncate text-[13.5px] font-medium"
          title={proposal.title}
        >
          {proposal.title}
        </p>
        <p className="mt-1 text-[12px] leading-relaxed text-fg-muted">
          <Prose text={proposal.reason} />
        </p>
        <Intent proposals={[proposal]} />
      </Header>
      <CommandList
        commands={commandsOf([proposal])}
        alternative={edits.length > 0}
      />
      <DiffList files={edits} />
      {!actionable && <StepList steps={stepsOf(proposal)} />}
    </Card>
  );
}
