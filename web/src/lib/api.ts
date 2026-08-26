// Typed client for the Rust backend (`husk web`). In dev these go through the
// Vite proxy to the `husk web --dev` server; in prod they hit the same origin.
import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

/** A non-2xx reply from the husk server. Every `/api/*` failure carries a real
 *  HTTP status and an `{ error }` body; this surfaces both. */
export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function raise(url: string, res: Response): Promise<never> {
  let detail = "";
  try {
    detail = ((await res.json()) as { error?: string }).error ?? "";
  } catch {
    // Non-JSON error body; fall back to the status line.
  }
  throw new HttpError(res.status, detail || `${url} → HTTP ${res.status}`);
}

async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) await raise(url, res);
  return res.json() as Promise<T>;
}
async function postJSON<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    cache: "no-store",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) await raise(url, res);
  return res.json() as Promise<T>;
}

// ---- types (mirror the Rust serde shapes) --------------------------------

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ScanReport {
  api_version?: number;
  generated_at: string;
  roots: string[];
  context: SystemContext;
  packages: { ecosystem: string; name: string; version: string }[];
  /** The project-posture index (unit of attention). */
  projects?: Project[];
  summary?: PostureSummary;
  findings: Finding[];
  /** Findings silenced by policy/ledger; shown under "Ignored", not dropped. */
  ignored?: Finding[];
  providers: { name: string; ok: boolean; findings: number }[];
  benchmarks: {
    stage: string;
    elapsed_ms: number;
    files_checked: number;
    workers: number;
    detail: string;
  }[];
  stats: Record<string, number>;
  /** What changed since the previous cached scan of the same roots. */
  delta?: ScanDelta;
  controls?: ControlAssessment[];
  remediations?: RemediationProposal[];
  guidance?: GuideReport;
}

export interface ScanDelta {
  previous_at: string;
  /** Posture score (0-100) of the previous / this scan. */
  previous_score: number;
  score: number;
  new_count: number;
  unchanged_count: number;
  /** Total findings gone since the previous scan (`resolved` is capped). */
  resolved_count: number;
  resolved: Finding[];
  /** The new findings themselves, worst-first (same cap as `resolved`). */
  new?: Finding[];
}

// ---- project-posture model -------------------------------------------------

export type Action = "act" | "attend" | "track" | "ambient";
export type ProjectKind =
  | "git-repo"
  | "submodule"
  | "directory"
  | "config-location";
export type Activity = "active" | "recent" | "dormant" | "abandoned";
export type ProjectBucket = "needs-attention" | "dormant";

export interface CategoryRollup {
  category: string;
  /** Raw findings: one package can carry a dozen advisories. */
  count: number;
  /** Distinct subjects, and therefore rows. What a category label names. */
  subjects: number;
  worst_severity: Severity;
  act_count: number;
}
export interface ProjectRollup {
  by_severity: Record<string, number>;
  by_category: CategoryRollup[];
  worst_severity?: Severity;
}
export interface ProjectPosture {
  bucket: ProjectBucket;
  rank_score: number;
  worst_action: Action;
  act: number;
  attend: number;
  track: number;
  ambient: number;
}
export interface GitInfo {
  branch?: string;
  head_sha?: string;
  head_date?: string;
  shallow?: boolean;
  /** GitHub only: the cloud correlation key. */
  owner_repo?: string;
  remote_host?: string;
  /** The `origin` url exactly as the repo's config spells it. */
  remote_url?: string;
}
export interface Project {
  id: string;
  root: string;
  name: string;
  kind: ProjectKind;
  submodule_of?: string;
  git?: GitInfo;
  last_modified?: string;
  activity: Activity;
  ecosystems: string[];
  package_count: number;
  rollup: ProjectRollup;
  posture?: ProjectPosture;
}
export interface PostureSummary {
  projects_total: number;
  projects_needing_attention: number;
  by_category: CategoryRollup[];
  act: number;
  attend: number;
  track: number;
  ambient: number;
}
export interface SystemContext {
  user?: string;
  git_name?: string;
  git_email?: string;
  os?: string;
  distro?: string;
  kernel?: string;
  arch?: string;
  package_managers?: string[];
  dev_configs?: { present: boolean }[];
  scan_roots?: string[];
}
export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  source: string;
  path?: string;
  line?: number;
  summary: string;
  evidence?: string;
  recommendation: string;
  references: string[];
  package?: {
    ecosystem: string;
    name: string;
    version: string;
    manifest_path?: string;
  };
  /** The project this finding belongs to (joins to `report.projects`). */
  project_id?: string;
  /** What this finding is about. Findings sharing it are one row, and the
   *  server counts them the same way in `CategoryRollup.subjects`. */
  subject?: string;
  rule_id?: string;
  /** Structured CVE ids (normalized upper-case), when the finding has any. */
  cves?: string[];
  /** Project-aware scoring output. */
  priority?: {
    action: Action;
    score: number;
    risk_class: "exposure" | "ambient";
    demoted_by?: string;
  };
  /** Exploit-in-the-wild intel (CISA KEV / FIRST EPSS) for this finding's CVEs,
   *  when known. Drives the "fix these first" ordering. */
  exploit?: { kev: boolean; epss?: number };
  /** The safe version the advisory names; enables the one-click
   *  upgrade/downgrade button. */
  fixed_version?: string;
}
export interface LiveScan {
  report: ScanReport;
  running: boolean;
  current_task: string;
  /** When the report in `report` finished. A running scan with this set is a
   *  rescan: the results on screen are the previous scan's, held there until
   *  the new report lands, so this is what tells them apart from live ones.
   *  `!running && !finished_at` is the idle state (the server is up and waiting
   *  for the user to pick a directory). */
  finished_at?: string | null;
  steps: {
    label: string;
    state: string;
    message?: string;
    elapsed_ms?: number;
    /** Within-step completion (0..1) while running; drives the progress bar. */
    fraction?: number | null;
    /** When the step entered "running"; eases the bar during network waits. */
    started_at?: string | null;
  }[];
  error?: string;
}

// Weighted scan progress, mirroring `src/tui/scan.rs::progress_percent`; the
// two front ends must show the same bar (lockstep rule). Weights ≈ typical
// share of scan wall time per pipeline step (discover, local files, home
// inventory, providers, finalize).
const STEP_WEIGHTS = [10, 45, 10, 25, 10];
export function progressPercent(ld: LiveScan): number {
  if (!ld.steps?.length) return ld.running ? 0 : 100;
  let total = 0;
  let done = 0;
  ld.steps.forEach((step, i) => {
    const weight = STEP_WEIGHTS[i] ?? 10;
    total += weight;
    if (step.state === "done" || step.state === "warning") {
      done += weight;
    } else if (step.state === "running") {
      // Interpolate by the published fraction; steps with no countable work
      // (network waits) ease on elapsed time instead, so the bar keeps moving.
      const eased = step.started_at
        ? (1 -
            Math.exp(
              -Math.max(0, Date.now() - Date.parse(step.started_at)) / 8000,
            )) *
          0.9
        : 0;
      done += weight * Math.min(1, Math.max(0, step.fraction ?? eased));
    }
  });
  return Math.min(100, (done / total) * 100);
}

// ---- guide -----------------------------------------------------------------

export type GuideStatus =
  | "action-needed"
  | "recommended"
  | "verified"
  | "completed"
  | "dismissed"
  | "unknown";
/** Which list slice a task is in. The server owns this split, so tab counts,
 *  category counts, and the rows in a tab are all derived from one partition. */
export type GuideBucket = "todo" | "done" | "ignored";
export type ControlStatus =
  | "passed"
  | "failed"
  | "partial"
  | "unknown"
  | "not-applicable";
/** `manual` guides have no control and never carry a `control_status`. */
export type Verification = "automatic" | "manual";
export interface ControlAssessment {
  control_id: string;
  status: ControlStatus;
  evidence: { summary: string; path?: string; line?: number }[];
  finding_ids?: string[];
}
export type RemediationOperation =
  | { kind: "set_config_value"; path: string; key: string; value: string }
  | { kind: "gitignore_append"; secret_path: string }
  | { kind: "env_template"; secret_path: string }
  | {
      kind: "dependency_update";
      ecosystem: string;
      name: string;
      current_version: string;
      target_version: string;
      manifest_path: string;
      command: string[];
      tool_available: boolean;
      tool_advice?: string;
      blocker?: string;
    }
  | { kind: "manual"; steps: FixStep[] };
/** One instruction plus every place it applies to. N places needing the same
 *  treatment is one instruction and a list of N places, never N copies of the
 *  sentence with a path swapped into the middle of each. */
export interface FixStep {
  text: string;
  subjects?: string[];
}
export interface FileDiff {
  path: string;
  /** Unified diff, rendered once by the server and parsed by gitdiff-parser
   *  in the browser. Nothing here interprets the format itself. */
  diff: string;
  added: number;
  removed: number;
  created: boolean;
}
/** What a fix would do, rendered once by the server. The browser never
 *  computes a diff or composes a command: it shows what it was given, and the
 *  apply request still carries only the proposal id. */
export interface FixPreview {
  diff?: FileDiff[];
  command?: string;
  cwd?: string;
  /** False when the diff carries edits no command expresses, so the UI must
   *  not imply the one-liner is the whole fix. */
  complete: boolean;
}
export interface RemediationProposal {
  id: string;
  control_id: string;
  finding_ids?: string[];
  title: string;
  severity: Severity;
  class: "auto_safe" | "confirm" | "manual";
  reason: string;
  action: RemediationOperation;
  preview?: FixPreview;
  /** One click runs this right now. The only thing "N fixes ready" counts. */
  ready?: boolean;
}
export interface Step {
  text: string;
  command?: string;
  platform?: string;
}
export interface Opt {
  name: string;
  recommended: boolean;
  note: string;
  url?: string;
  /** Steps for this specific option. Empty for options without authored
   *  steps; the UI then shows note + link, never another option's steps. */
  steps?: Step[];
}
export interface Source {
  title: string;
  url: string;
}
export interface GuideTask {
  id: string;
  category: string;
  kind: "baseline" | "recommendation";
  severity: Severity;
  title: string;
  why: string;
  problem: string;
  estimate: string;
  steps: Step[];
  options: Opt[];
  sources: Source[];
  solution: { name: string; url: string; husk: boolean };
  status: GuideStatus;
  verification: Verification;
  /** Which report verifies this task: the machine posture or a project scan. */
  scope: "machine" | "project" | "project-ecosystem";
  /** Absent for `manual` guides: husk ran no check, so it reports no result. */
  control_status?: ControlStatus;
  read: boolean;
  handled: boolean;
  priority: number;
  bucket: GuideBucket;
  tier: "next" | "later" | "done" | "ignored";
  effort: "quick" | "medium" | "project";
  evidence: { summary: string; path?: string; line?: number }[];
  finding_ids: string[];
  remediation_ids: string[];
  decision?: "completed" | "dismissed";
  user_state?: string;
  reason?: string;
}
export interface GuideCategory {
  id: string;
  title: string;
  items: GuideTask[];
}
export interface GuideReport {
  generated_at: string;
  categories: GuideCategory[];
  total: number;
  /** The three buckets partition `total`. Never recount them client-side. */
  todo: number;
  done: number;
  ignored: number;
  /** Read and then resolved. Review progress, not a security score. */
  handled: number;
  percent: number;
  verified: number;
  completed: number;
}

export interface AccountStatus {
  connected: boolean;
  backend_url: string;
  account?: {
    email: string;
    email_verified: boolean;
    display_name?: string;
    tier: string;
  };
  detail?: string;
}

// ---- hooks -----------------------------------------------------------------

const liveQuery = {
  queryKey: ["live"],
  queryFn: () => getJSON<LiveScan>("/api/live"),
  // Poll fast while a scan runs; keep a slow idle poll (never `false`) so the
  // UI self-heals; a rescan started here or from the CLI is picked up without
  // a manual refresh, instead of permanently freezing on the finished report.
  refetchInterval: (q: { state: { data?: LiveScan } }) =>
    q.state.data?.running ? 700 : 10_000,
};

export const useLive = () => useQuery(liveQuery);

/** The machine-posture slot: the standing "how is this machine doing" scan,
 *  independent of whichever folder the session targets. */
const machineQuery = {
  queryKey: ["machine"],
  queryFn: () => getJSON<LiveScan>("/api/machine"),
  refetchInterval: (q: { state: { data?: LiveScan } }) =>
    q.state.data?.running ? 700 : 10_000,
};

export const useMachine = () => useQuery(machineQuery);

/** Start the machine scan (`POST /api/machine/rescan`); roots are always the
 *  home directory, decided server-side. */
export const useMachineRescan = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => postJSON<LiveScan>("/api/machine/rescan", {}),
    onSuccess: (live) => {
      qc.setQueryData(["machine"], live);
      qc.invalidateQueries({ queryKey: ["machine"] });
      qc.invalidateQueries({ queryKey: ["guide"] });
    },
  });
};

/** When the most recent scan finished, or null while one runs (and before the
 *  first scan). Selected out of the live query so a view that only cares about
 *  scan completion re-renders once per scan, not on every 700ms poll. */
export const useScanFinishedAt = () =>
  useQuery({ ...liveQuery, select: (l: LiveScan) => l.finished_at ?? null });

/** Telemetry consent state (`GET /api/telemetry/consent`): the same on-disk
 *  state the CLI prompt and TUI pane share, so no surface ever re-asks. */
export interface TelemetryConsent {
  state: "unset" | "enabled" | "disabled";
  /** True while the one-time consent card should show: never decided (and no
   *  environment kill switch active server-side). */
  ask_due: boolean;
}

const telemetryConsentQuery = {
  queryKey: ["telemetry-consent"],
  queryFn: () => getJSON<TelemetryConsent>("/api/telemetry/consent"),
};

export const useTelemetryConsent = () => useQuery(telemetryConsentQuery);

/** Record the explicit consent answer. Both buttons and the dismiss X go
 *  through here (`enable: false` for the latter two), so any interaction
 *  persists the asked state and the card never returns. */
export const useTelemetryConsentAnswer = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (enable: boolean) =>
      postJSON<TelemetryConsent>("/api/telemetry/consent", { enable }),
    onSuccess: (consent) => {
      qc.setQueryData(["telemetry-consent"], consent);
    },
  });
};

/** Kick off a fresh scan (`POST /api/rescan`) and pick the live state straight
 *  back up; the live query then polls fast until it finishes. */
export const useRescan = () => {
  const qc = useQueryClient();
  return useMutation({
    // Pass a directory to re-target the scan; omit it to reuse the current roots.
    mutationFn: (roots?: string[]) =>
      postJSON<LiveScan>("/api/rescan", roots?.length ? { roots } : {}),
    onSuccess: (live) => {
      qc.setQueryData(["live"], live);
      qc.invalidateQueries({ queryKey: ["live"] });
    },
  });
};

export interface DirsView {
  path: string;
  parent: string | null;
  dirs: { name: string; path: string }[];
}

/** Browse the local filesystem one level at a time for the directory picker.
 *  `path = null` lists the home directory. */
export const useDirs = (path: string | null) =>
  useQuery({
    queryKey: ["dirs", path],
    queryFn: () =>
      getJSON<DirsView>(
        path ? `/api/dirs?path=${encodeURIComponent(path)}` : "/api/dirs",
      ),
  });

export const useGuide = (reportKey?: string) =>
  useQuery({
    queryKey: ["guide", reportKey ?? ""],
    queryFn: () => getJSON<GuideReport>("/api/guide"),
  });

/** Finding-to-guide join for the original Scan UI, derived from the live
 * scan-backed guide evidence instead of the removed rule metadata endpoint. */
export interface Rule {
  id: string;
  guide_task?: string;
}
export const useRules = () => {
  const live = useLive();
  const guide = useGuide(live.data?.report.generated_at);
  const data = useMemo(() => {
    const tasks = (guide.data?.categories ?? []).flatMap(
      (category) => category.items,
    );
    const byFinding = new Map(
      tasks.flatMap((task) =>
        task.finding_ids.map((id) => [id, task.id] as const),
      ),
    );
    const byRule = new Map<string, Rule>();
    for (const finding of live.data?.report.findings ?? []) {
      const task = byFinding.get(finding.id);
      if (finding.rule_id && task)
        byRule.set(finding.rule_id, { id: finding.rule_id, guide_task: task });
    }
    return [...byRule.values()];
  }, [guide.data, live.data]);
  return { data };
};

/** A resolved or new finding compacted into a history row; enough to say
 *  which vulnerability changed (mirrors the Rust `history::FindingSummary`). */
export interface HistoryFinding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  /** `name@version`, for package/advisory findings. */
  package?: string;
  path?: string;
  /** Resolved findings only: the resolution matched a husk-executed fix. */
  by_husk?: boolean;
}

/** One completed scan, summarized; a row of `~/.husk/history.jsonl`
 *  (mirrors the Rust `history::HistoryEntry`). */
export interface HistoryEntry {
  v: number;
  at: string;
  roots_key: string;
  /** Husk version that produced the scan; a score drop right after an
   *  upgrade usually means new detections shipped, not a worse machine. */
  husk_version: string;
  score: number;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  packages: number;
  new_count: number;
  resolved_count: number;
  resolved_by_category?: Record<string, number>;
  /** The resolved findings themselves (worst-first, capped at 50). */
  resolved?: HistoryFinding[];
  /** The findings that appeared in this scan (same cap). */
  new?: HistoryFinding[];
  /** Husk-executed fixes (ledger) between the previous scan and this one. */
  fixes_applied: number;
  /** What those fixes were ("name (eco)" for dependency updates); absent on
   *  rows written by older Husk versions. */
  fixes?: string[];
  /** Resolved findings confirmed to be husk fixes (ledger target match). */
  husk_resolved: number;
}

/** Scan history across all scanned roots, oldest first (the Scan-history tab
 *  groups by `roots_key`). A row is appended only when a scan *finishes*, so
 *  this is keyed on `finished_at` (from `useScanFinishedAt`): one refetch per
 *  completed scan, none while one runs. Keying it on the report's
 *  `generated_at` instead would rekey on every live publish mid-scan, and each
 *  rekey starts a fresh pending query, which blanks the tab. `keepPreviousData`
 *  holds the rendered history across the one key change that does happen, so
 *  the tab never unmounts and the reader keeps their scroll position. */
export const useHistory = (finishedAt?: string | null) =>
  useQuery({
    queryKey: ["history", finishedAt ?? ""],
    queryFn: () => getJSON<HistoryEntry[]>("/api/history"),
    placeholderData: keepPreviousData,
  });

export const useAccount = () =>
  useQuery({
    queryKey: ["account"],
    queryFn: () => getJSON<AccountStatus>("/api/account"),
  });

// Map of agent id (the `husk mcp install <id>` arg) → whether husk's MCP
// server is already registered in that agent's local config.
export const useAgents = () =>
  useQuery({
    queryKey: ["agents"],
    queryFn: () => getJSON<Record<string, boolean>>("/api/agents"),
  });

// ---- policy status (project policy + personal trust ledger) ----------------

export interface LedgerEntry {
  seq: number;
  timestamp: string;
  action: string;
  target: string;
  reason?: string;
  project?: string;
  prev_hash: string;
  hash: string;
}
export interface PolicyStatus {
  policy: {
    dir: string;
    blocked: string[];
    allowed: string[];
    suppressed: { id: string; reason?: string }[];
    ci_fail_on: string;
  } | null;
  ledger: { count: number; intact: boolean; recent: LedgerEntry[] };
}

export const usePolicyStatus = () =>
  useQuery({
    queryKey: ["policy"],
    queryFn: () => getJSON<PolicyStatus>("/api/policy"),
  });

// ---- device-flow login (in-UI, no CLI) -------------------------------------

interface LoginStartResp {
  user_code: string;
  verification_uri_complete: string;
  device_code: string;
  interval: number;
  expires_in: number;
}
interface LoginPollResp {
  status: "pending" | "slow_down" | "approved" | "denied" | "expired";
}

export type LoginPhase =
  | "idle"
  | "starting"
  | "waiting"
  | "approved"
  | "denied"
  | "expired"
  | "error";

export interface DeviceLogin {
  phase: LoginPhase;
  userCode?: string;
  verificationUrl?: string;
  error?: string;
  start: () => Promise<void>;
  reset: () => void;
}

/** Drives the RFC 8628 device-authorization login entirely in the browser:
 *  start → open the approval URL + show the code → poll until approved, at which
 *  point credentials are stored locally and the account query is refreshed. No
 *  CLI command is ever required. */
export function useDeviceLogin(): DeviceLogin {
  const qc = useQueryClient();
  const [phase, setPhase] = useState<LoginPhase>("idle");
  const [userCode, setUserCode] = useState<string>();
  const [verificationUrl, setVerificationUrl] = useState<string>();
  const [error, setError] = useState<string>();
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clear = useCallback(() => {
    if (timer.current) {
      clearTimeout(timer.current);
      timer.current = null;
    }
  }, []);

  // Stop polling if the component unmounts mid-flow.
  useEffect(() => clear, [clear]);

  const reset = useCallback(() => {
    clear();
    setPhase("idle");
    setError(undefined);
    setUserCode(undefined);
    setVerificationUrl(undefined);
  }, [clear]);

  const start = useCallback(async () => {
    clear();
    setError(undefined);
    setPhase("starting");
    let s: LoginStartResp;
    try {
      s = await postJSON<LoginStartResp>("/api/login/start", {});
    } catch (e) {
      // An HttpError means the local server answered but the Husk backend
      // call failed (502). The backend errors are verbose (DNS/HTTP detail)
      // and not user-actionable; keep the message concise (the full reason
      // is in the server logs). Anything else: the local server is gone.
      setError(
        e instanceof HttpError
          ? "Couldn't reach the Husk backend. Check your connection."
          : "Couldn't start sign-in. Is `husk web` still running?",
      );
      setPhase("error");
      return;
    }
    setUserCode(s.user_code);
    setVerificationUrl(s.verification_uri_complete);
    setPhase("waiting");
    window.open(s.verification_uri_complete, "_blank", "noopener,noreferrer");

    // Self-scheduling poll (setTimeout, not setInterval) so we can honour the
    // RFC 8628 `slow_down` backoff by lengthening the delay between polls.
    let delayMs = Math.max(2, s.interval) * 1000;
    const poll = async () => {
      let r: LoginPollResp;
      try {
        r = await postJSON<LoginPollResp>("/api/login/poll", {
          device_code: s.device_code,
        });
      } catch (e) {
        if (e instanceof HttpError) {
          // The Husk backend rejected the poll (502 + { error }): terminal.
          clear();
          setError(e.message);
          setPhase("error");
        } else {
          timer.current = setTimeout(poll, delayMs); // transient; retry
        }
        return;
      }
      switch (r.status) {
        case "approved":
          clear();
          setPhase("approved");
          qc.invalidateQueries({ queryKey: ["account"] });
          qc.invalidateQueries({ queryKey: ["policy"] });
          break;
        case "denied":
          clear();
          setPhase("denied");
          break;
        case "expired":
          clear();
          setPhase("expired");
          break;
        case "slow_down":
          delayMs += 5000;
          timer.current = setTimeout(poll, delayMs);
          break;
        default: // pending
          timer.current = setTimeout(poll, delayMs);
      }
    };
    timer.current = setTimeout(poll, delayMs);
  }, [clear, qc]);

  return { phase, userCode, verificationUrl, error, start, reset };
}

// ---- mute a finding (writes a policy suppress + ledger entry) --------------

export interface MuteResult {
  message: string;
  muted: number;
  policy_dir: string;
}

/** Mute one or more findings in a single request: persists `[[suppress]]`
 *  entries to the project policy and records them on the trust ledger. Refreshes
 *  the policy status; a rescan applies it. */
export const useMuteFinding = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { ids: string[]; reason?: string }) =>
      postJSON<MuteResult>("/api/finding/mute", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policy"] });
    },
  });
};

/** Unmute one or more findings: removes their `[[suppress]]` policy entries and
 *  records it on the ledger. The inverse of useMuteFinding; rescan applies it. */
export const useUnmuteFinding = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { ids: string[] }) =>
      postJSON<MuteResult>("/api/finding/unmute", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policy"] });
    },
  });
};

// ---- send feedback ---------------------------------------------------------

/** Send free-text product feedback. The Rust server validates the message and
 *  forwards it to the Husk backend with context "web"; the browser never talks
 *  to the backend directly. */
export const useSendFeedback = () =>
  useMutation({
    mutationFn: (body: { message: string; contact?: string }) =>
      postJSON<{ sent: boolean }>("/api/feedback", body),
  });

// ---- typed remediation ------------------------------------------------------

export interface ApplyRemediationResult {
  /** Nothing failed and nothing is still waiting on the user. */
  ok: boolean;
  /** Proposals that changed something. A proposal that found its change already
   *  in place is `skipped`, never this, so `applied > 0` is the honest test for
   *  "anything happened" (and for whether a rescan has anything to verify). */
  applied: number;
  skipped: number;
  needs_user: number;
  failed: number;
  message: string;
  results: {
    id: string;
    status: string;
    detail: string;
    /** Verbatim transcript of whatever the proposal ran, including the
     *  shell's own error when the program is not on PATH. */
    output?: string;
  }[];
}

/** Apply a selection of server-planned proposals in ONE request. The server
 *  runs them under a single lock, into a single backup snapshot, so
 *  `husk fix --rollback` undoes the whole click. Never send one request per
 *  proposal: concurrent applies collide on the fix lock, and sequential ones
 *  leave N rollback points where the user made one decision. */
export const useApplyRemediation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { ids: string[]; allow_system_packages?: boolean }) =>
      postJSON<ApplyRemediationResult>("/api/remediation/apply", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["live"] });
      qc.invalidateQueries({ queryKey: ["guide"] });
      qc.invalidateQueries({ queryKey: ["policy"] });
    },
  });
};

export interface ToolStatus {
  available: boolean;
  advice?: string;
}

/** A dependency-update proposal narrowed to its action, so callers can read
 *  `manifest_path`/`blocker` without re-narrowing the union at every use. */
export type DependencyProposal = RemediationProposal & {
  action: Extract<RemediationOperation, { kind: "dependency_update" }>;
};

export const isDependencyProposal = (
  proposal: RemediationProposal,
): proposal is DependencyProposal =>
  proposal.action.kind === "dependency_update";

/** The workspace a dependency fix runs in: the manifest's directory, which is
 *  also the directory the package manager is invoked from. This is a *display*
 *  grouping read off the server's own plan, not a re-planning step; the browser
 *  never decides what is fixable, what the target version is, or how findings
 *  merge into a proposal. */
export const workspaceOf = (proposal: DependencyProposal): string =>
  proposal.action.manifest_path.replace(/[/\\][^/\\]*$/, "") || "/";

/** PEP 668 is the one blocker husk lets the user knowingly override (pip's
 *  `--break-system-packages`).
 *
 *  This matches on the blocker's prose because the server has no typed blocker
 *  yet. It is the ONLY place in the web UI that does so; when
 *  `RemediationOperation::DependencyUpdate` grows a typed blocker, delete this
 *  and read the field. */
export const isOverridableBlocker = (blocker: string): boolean =>
  /PEP 668|externally.managed/i.test(blocker);

export const useToolAvailability = () => {
  const live = useLive();
  // Proposals carry a scan-time snapshot; it is correct at scan time and is the
  // only source when the endpoint has not answered yet.
  const snapshot = useMemo(() => {
    const tools: Record<string, ToolStatus> = {};
    for (const proposal of live.data?.report.remediations ?? []) {
      if (proposal.action.kind !== "dependency_update") continue;
      const tool = proposal.action.command[0];
      if (!tool) continue;
      tools[tool] = {
        available: proposal.action.tool_available,
        advice: proposal.action.tool_advice,
      };
    }
    return tools;
  }, [live.data]);

  // A user who installs npm mid-session because husk told them to should see
  // the one-click become available without re-running a whole scan, so the live
  // PATH check refreshes on its own and wins over the snapshot.
  const live_tools = useQuery({
    queryKey: ["remediation-tools"],
    queryFn: () =>
      getJSON<Record<string, ToolStatus>>("/api/remediation/tools"),
    staleTime: 60_000,
    refetchInterval: 60_000,
    refetchOnWindowFocus: true,
  });

  const data = useMemo(
    () => ({ ...snapshot, ...(live_tools.data ?? {}) }),
    [snapshot, live_tools.data],
  );
  return { data };
};

export type GuideAction = "read" | "done" | "complete" | "dismiss" | "clear";
export const useGuideAction = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      id: string;
      action: GuideAction;
      reason?: string;
    }) =>
      postJSON<GuideReport>("/api/guide/task", {
        ...body,
        action: body.action === "done" ? "complete" : body.action,
      }),
    onSuccess: (data) => qc.setQueriesData({ queryKey: ["guide"] }, data),
  });
};
