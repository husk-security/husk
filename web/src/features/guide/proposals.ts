import {
  type DependencyProposal,
  type FileDiff,
  type Finding,
  type FixStep,
  isDependencyProposal,
  isOverridableBlocker,
  type RemediationProposal,
  type Severity,
  type ToolStatus,
  workspaceOf,
} from "@/lib/api";

const RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** The manual steps a proposal carries. A `manual` action holds them inline;
 *  any other kind that resolves to nothing Husk can do carries them on the
 *  recipe, which the wire type does not model because the browser never reads
 *  the rest of it. */
type WithRecipeSteps = { recipe?: { steps?: FixStep[] } };
export function stepsOf(proposal: RemediationProposal): FixStep[] {
  if (proposal.action.kind === "manual") return proposal.action.steps;
  return (
    (proposal as RemediationProposal & WithRecipeSteps).recipe?.steps ?? []
  );
}

/** Whether applying would change anything. The server plans no operation for a
 *  fix already true on disk, so it arrives as `class: "manual"` with no
 *  preview: offering to apply it would be offering a no-op. */
export function isActionable(proposal: RemediationProposal): boolean {
  const preview = proposal.preview;
  if (proposal.class === "manual" || !preview) return false;
  return !!preview.command || (preview.diff?.length ?? 0) > 0;
}

/** Identity of the fixes on screen: which proposals exist and what each one
 *  would run. A selection is only meaningful against a specific set of
 *  proposals, so the card is remounted when this changes and kept otherwise.
 *  The report's `generated_at` is rewritten on every incremental publish, so
 *  keying on that instead discarded the selection roughly every 700ms for the
 *  length of a scan. */
export function proposalsKey(proposals: RemediationProposal[]): string {
  return proposals
    .map((proposal) => `${proposal.id}|${proposal.preview?.command ?? ""}`)
    .join("\n");
}

/** A command exactly as the server rendered it, never composed here. */
export interface PlannedCommand {
  command: string;
  cwd?: string;
  /** False when the diff carries edits this command does not express. */
  complete: boolean;
}

/** Every distinct command across a set of proposals, in planned order.
 *  Deduplicated on the text alone: two proposals resolving to the same
 *  one-liner are one thing to run. */
export function commandsOf(proposals: RemediationProposal[]): PlannedCommand[] {
  const seen = new Map<string, PlannedCommand>();
  for (const proposal of proposals) {
    const preview = proposal.preview;
    if (!preview?.command || seen.has(preview.command)) continue;
    seen.set(preview.command, {
      command: preview.command,
      cwd: preview.cwd,
      complete: preview.complete,
    });
  }
  return [...seen.values()];
}

/** Every file a set of proposals would rewrite. Entries are listed, never
 *  merged: merging two diffs of one file is diff logic, and that lives on the
 *  server. */
export function diffsOf(
  proposals: RemediationProposal[],
): { key: string; file: FileDiff }[] {
  return proposals.flatMap((proposal) =>
    (proposal.preview?.diff ?? []).map((file) => ({
      key: `${proposal.id}|${file.path}`,
      file,
    })),
  );
}

/** What applying would actually do, split the way Husk does it: file edits are
 *  written by Husk itself, and only a dependency update also runs a program.
 *  This is what lets a card say which of the two a click performs, instead of
 *  showing a diff and a command and leaving the reader to guess. */
export interface FixIntent {
  /** Distinct files the fix rewrites, in plan order. */
  files: { path: string; created: boolean }[];
  /** What Apply runs: the exact argv when every proposal shares one, otherwise
   *  the distinct programs behind them. Empty when nothing is run. */
  runs: string[];
}

/** An argv rendered for reading. Joined only when every token is a bare shell
 *  word, so an argument needing quotes is never shown as if it did not; the
 *  copyable block carries the server's quoted form either way. */
const runLabel = (argv: string[]): string =>
  argv.every((token) => /^[\w.@:/=+,^-]+$/.test(token))
    ? argv.join(" ")
    : argv[0];

export function intentOf(proposals: RemediationProposal[]): FixIntent {
  const files = new Map<string, { path: string; created: boolean }>();
  for (const { file } of diffsOf(proposals)) {
    if (!files.has(file.path)) {
      files.set(file.path, { path: file.path, created: file.created });
    }
  }
  const argvs = proposals.flatMap((proposal) =>
    proposal.action.kind === "dependency_update"
      ? [proposal.action.command]
      : [],
  );
  const runs = [...new Set(argvs.map(runLabel))];
  const programs = [...new Set(argvs.map((argv) => argv[0]).filter(Boolean))];
  return {
    files: [...files.values()],
    runs: runs.length === 1 ? runs : programs,
  };
}

const fileName = (path: string): string => path.split(/[/\\]/).pop() || path;

/** Join for prose, not for a machine: "a", "a and b", "a, b and c". */
const list = (items: string[]): string =>
  items.length > 1
    ? `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`
    : (items[0] ?? "");

/** The one line a card leads with. It names the two halves of an apply in the
 *  order they happen, so "does the button edit the file or run the command" is
 *  answered before either block is read. */
export function applySentence({ files, runs }: FixIntent): string | null {
  const names = list(files.map((file) => fileName(file.path)));
  const verb = files.every((file) => file.created)
    ? "creates"
    : files.some((file) => file.created)
      ? "writes"
      : "edits";
  if (files.length > 0 && runs.length > 0) {
    return `Apply ${verb} ${names}, then runs ${list(runs)}.`;
  }
  if (files.length > 0) return `Apply ${verb} ${names}.`;
  if (runs.length > 0) return `Apply runs ${list(runs)}.`;
  return null;
}

/** One advisory a package is affected by, and where to read it. */
export interface AdvisoryLink {
  id: string;
  url: string;
}

/** Pages that describe an advisory rather than merely mention it. Preferred
 *  over an arbitrary reference so a link lands somewhere readable. */
const AUTHORITATIVE =
  /^https:\/\/(nvd\.nist\.gov|github\.com\/advisories|osv\.dev)\//;

const canonicalUrl = (id: string): string => {
  if (id.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (id.startsWith("GHSA-")) return `https://github.com/advisories/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
};

/** The advisory id a finding was raised under, without the feed that carried
 *  it: `osv:GHSA-x` and `pypi:GHSA-x` are one advisory seen twice. */
const advisoryId = (finding: Finding): string | undefined =>
  finding.rule_id?.split(":").pop();

/** The distinct vulnerabilities behind a set of findings, each linked to a page
 *  describing it.
 *
 *  Keyed by CVE where there is one, because a CVE names the vulnerability
 *  itself: two feeds reporting it under their own advisory ids are one thing
 *  wrong with the package, and counting them twice overstates the risk. URLs
 *  come from the finding's own `references`; the canonical hosts are only used
 *  when the server carried no link naming that identifier. */
export function advisoryLinks(findings: Finding[]): AdvisoryLink[] {
  const links = new Map<string, AdvisoryLink>();
  for (const finding of findings) {
    const ids = finding.cves?.length ? finding.cves : [advisoryId(finding)];
    for (const id of ids) {
      if (!id || links.has(id)) continue;
      const naming = finding.references.filter((url) =>
        url.toUpperCase().includes(id.toUpperCase()),
      );
      links.set(id, {
        id,
        url:
          naming.find((url) => AUTHORITATIVE.test(url)) ??
          naming[0] ??
          canonicalUrl(id),
      });
    }
  }
  return [...links.values()];
}

export interface DependencyRow {
  proposal: DependencyProposal;
  /** The package-manager binary, straight off the planned argv. */
  tool: string;
  /** A structural reason the one-click cannot work here. */
  blocker?: string;
  actionable: boolean;
}

/** A row with the live answer to whether Husk can take it right now. */
export interface RunnableRow extends DependencyRow {
  toolMissing: boolean;
  overridable: boolean;
  runnable: boolean;
}

/** Resolve a row against the tool probe and the user's PEP 668 decision.
 *
 *  Unknown tool availability counts as present: the scan-time snapshot on the
 *  proposal already answered this, and the live probe only ever upgrades it. */
export function resolveRow(
  row: DependencyRow,
  probed: ToolStatus | undefined,
  allowBreak: boolean,
): RunnableRow {
  const toolMissing =
    probed?.available === false ||
    (probed === undefined && !row.proposal.action.tool_available);
  const overridable = !!row.blocker && isOverridableBlocker(row.blocker);
  return {
    ...row,
    toolMissing,
    overridable,
    runnable:
      row.actionable &&
      !toolMissing &&
      (!row.blocker || (overridable && allowBreak)),
  };
}

/** Dependency updates that share one package-manager run: same directory, same
 *  ecosystem. Two ecosystems in one project are two decisions and two cards. */
export interface DependencyCard {
  kind: "dependency";
  key: string;
  workspace: string;
  ecosystem: string;
  severity: Severity;
  rows: DependencyRow[];
}

/** One fix that is not a dependency update. */
export interface ProposalCard {
  kind: "proposal";
  key: string;
  proposal: RemediationProposal;
  severity: Severity;
}

export type FixCard = DependencyCard | ProposalCard;

const worst = (severities: Severity[]): Severity =>
  severities.reduce((a, b) => (RANK[b] < RANK[a] ? b : a));

interface Bucket {
  workspace: string;
  ecosystem: string;
  rows: DependencyRow[];
}

export function planCards(proposals: RemediationProposal[]): FixCard[] {
  const deps = new Map<string, Bucket>();
  const cards: FixCard[] = [];

  for (const proposal of proposals) {
    if (!isDependencyProposal(proposal)) {
      cards.push({
        kind: "proposal",
        key: proposal.id,
        proposal,
        severity: proposal.severity,
      });
      continue;
    }
    const workspace = workspaceOf(proposal);
    const ecosystem = proposal.action.ecosystem;
    // A path may hold whatever a filename may, so the parts travel with the
    // bucket rather than being parsed back out of its key.
    const key = `${ecosystem} ${workspace}`;
    const bucket = deps.get(key) ?? { workspace, ecosystem, rows: [] };
    bucket.rows.push({
      proposal,
      tool: proposal.action.command[0] ?? "",
      blocker: proposal.action.blocker,
      actionable: isActionable(proposal),
    });
    deps.set(key, bucket);
  }

  for (const [key, bucket] of deps) {
    cards.push({
      kind: "dependency",
      key,
      workspace: bucket.workspace,
      ecosystem: bucket.ecosystem,
      severity: worst(bucket.rows.map((row) => row.proposal.severity)),
      rows: bucket.rows.sort(
        (a, b) =>
          RANK[a.proposal.severity] - RANK[b.proposal.severity] ||
          a.proposal.action.name.localeCompare(b.proposal.action.name),
      ),
    });
  }
  const label = (card: FixCard) =>
    card.kind === "dependency"
      ? `${card.ecosystem} ${card.workspace}`
      : card.proposal.title;
  return cards.sort(
    (a, b) =>
      RANK[a.severity] - RANK[b.severity] || label(a).localeCompare(label(b)),
  );
}
