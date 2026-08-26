import type { Finding, LiveScan, Severity } from "@/lib/api";

// Sample data rendered behind the first-run tour when no real scan has run
// yet, so the Scan view the tour describes isn't an empty page. Never sent
// anywhere and clearly labeled "sample data" in the header.

const ROOT = "/home/you/projects/demo-app";

const finding = (f: Partial<Finding> & { id: string }): Finding => ({
  title: "",
  severity: "medium" as Severity,
  category: "vulnerability",
  source: "OSV.dev",
  summary: "",
  recommendation: "",
  references: [],
  project_id: "demo-app",
  ...f,
});

const FINDINGS: Finding[] = [
  finding({
    id: "demo-vuln-1",
    title: "GHSA-35jh-r3h4-6jhm affects lodash (CVE-2021-23337)",
    severity: "critical",
    path: `${ROOT}/package-lock.json`,
    line: 42,
    summary:
      "lodash before 4.17.21 is vulnerable to command injection via the template function.",
    recommendation:
      "Upgrade to a fixed version, remove the package, or confirm the advisory does not apply to this local use.",
    package: { ecosystem: "npm", name: "lodash", version: "4.17.20" },
    exploit: { kev: true, epss: 0.42 },
    fixed_version: "4.17.21",
  }),
  finding({
    id: "demo-vuln-2",
    title: "GHSA-29mw-wpgm-hmr9 affects lodash (CVE-2020-28500)",
    severity: "high",
    path: `${ROOT}/package-lock.json`,
    line: 42,
    summary:
      "lodash before 4.17.21 is vulnerable to ReDoS via the toNumber, trim and trimEnd functions.",
    recommendation: "Upgrade to a fixed version.",
    package: { ecosystem: "npm", name: "lodash", version: "4.17.20" },
    fixed_version: "4.17.21",
  }),
  finding({
    id: "demo-secret",
    title: "OpenAI API key exposed",
    severity: "high",
    category: "secret",
    source: "husk",
    path: `${ROOT}/.env`,
    line: 3,
    summary: "A value matching the OpenAI API key pattern is in plaintext.",
    recommendation:
      "Rotate the key, move it to a secret store, and keep .env out of version control.",
  }),
  finding({
    id: "demo-ai-config",
    title: "Prompt-injection phrase in AI-readable content",
    severity: "medium",
    category: "risky-agent-config",
    source: "husk",
    path: `${ROOT}/README.md`,
    line: 88,
    summary:
      "AI-readable content contains the phrase 'ignore all previous instructions'.",
    recommendation:
      "Review the file and remove instructions aimed at AI agents rather than humans.",
  }),
  finding({
    id: "demo-install",
    title: "npm install scripts are not disabled",
    severity: "medium",
    category: "install-hardening",
    source: "husk",
    path: `${ROOT}/.npmrc`,
    summary:
      "Packages can run arbitrary code at install time via lifecycle scripts.",
    recommendation:
      "Set ignore-scripts=true in .npmrc and allowlist the few packages that need scripts.",
  }),
];

const BY_CATEGORY = [
  {
    category: "vulnerability",
    count: 2,
    subjects: 2,
    worst_severity: "critical" as Severity,
    act_count: 2,
  },
  {
    category: "secret",
    count: 1,
    subjects: 1,
    worst_severity: "high" as Severity,
    act_count: 1,
  },
  {
    category: "risky-agent-config",
    count: 1,
    subjects: 1,
    worst_severity: "medium" as Severity,
    act_count: 0,
  },
  {
    category: "install-hardening",
    count: 1,
    subjects: 1,
    worst_severity: "medium" as Severity,
    act_count: 0,
  },
];

export const DEMO_LIVE: LiveScan = {
  running: false,
  current_task: "scan complete",
  finished_at: new Date().toISOString(),
  steps: [
    "discover packages",
    "scan local files",
    "scan home inventory",
    "query online providers",
    "finalize report",
  ].map((label) => ({ label, state: "done" })),
  report: {
    generated_at: new Date().toISOString(),
    roots: [ROOT],
    context: {},
    packages: [],
    findings: FINDINGS,
    providers: [],
    benchmarks: [],
    stats: { findings: 5, critical: 1, high: 2, medium: 2, low: 0, info: 0 },
    summary: {
      projects_total: 1,
      projects_needing_attention: 1,
      by_category: BY_CATEGORY,
      act: 3,
      attend: 2,
      track: 0,
      ambient: 0,
    },
    projects: [
      {
        id: "demo-app",
        root: ROOT,
        name: "demo-app",
        kind: "git-repo",
        activity: "active",
        ecosystems: ["npm"],
        package_count: 214,
        rollup: {
          by_severity: { critical: 1, high: 2, medium: 2 },
          by_category: BY_CATEGORY,
          worst_severity: "critical",
        },
        posture: {
          bucket: "needs-attention",
          rank_score: 1,
          worst_action: "act",
          act: 3,
          attend: 2,
          track: 0,
          ambient: 0,
        },
      },
    ],
  },
};
