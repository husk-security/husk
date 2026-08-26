import {
  Badge,
  DataTable,
  type DataTableColumn,
  EmptyState,
  SeverityBadge,
} from "@huskdev/ui";
import { FolderGit2 } from "lucide-react";
import {
  type Activity,
  type LiveScan,
  type Project,
  type ProjectKind,
  useLive,
} from "@/lib/api";
import { PathLabel } from "@/lib/path";
import { Scan } from "../scan/Scan";

const KIND_LABEL: Record<ProjectKind, string> = {
  "git-repo": "Git repo",
  submodule: "Submodule",
  directory: "Directory",
  "config-location": "System config",
};

// Dormant and abandoned are the ambient-risk end of the scale, so they read as
// muted rather than as a state worth acting on.
const ACTIVITY_CLASS: Record<Activity, string> = {
  active: "text-fg",
  recent: "text-fg-muted",
  dormant: "text-fg-subtle",
  abandoned: "text-fg-subtle",
};

/** Where the project came from: the correlation key when Husk has one, the
 *  bare host otherwise. The full url is the `title` because a remote is long
 *  and this column has to keep its width. */
function Remote({ project }: { project: Project }) {
  const git = project.git;
  const remote = git?.owner_repo ?? git?.remote_host;
  if (!remote) {
    return <span className="text-fg-subtle">local only</span>;
  }
  return (
    <span className="block truncate" title={git?.remote_url ?? remote}>
      {remote}
    </span>
  );
}

/** The project's own finding count, worst severity first. `rollup` is computed
 *  server-side, so this never re-derives what the report already states. */
function Findings({ project }: { project: Project }) {
  const total = project.rollup.by_severity?.findings ?? 0;
  const worst = project.rollup.worst_severity;
  if (!total || !worst) {
    return <span className="text-fg-subtle">clean</span>;
  }
  return (
    <span className="flex items-center gap-2">
      <SeverityBadge severity={worst} />
      <span className="tabular-nums text-fg-muted">{total}</span>
    </span>
  );
}

const COLUMNS: DataTableColumn<Project>[] = [
  {
    key: "project",
    header: "Project",
    cell: (p) => (
      <span className="flex min-w-0 flex-col gap-0.5">
        <span className="truncate font-sans text-fg">{p.name}</span>
        <PathLabel path={p.root} />
      </span>
    ),
    // A fixed width, not a cap: the path column must not resize itself around
    // whatever the longest discovered root happens to be.
    className: "w-[22rem]",
  },
  {
    key: "kind",
    header: "Type",
    // Every short label in this table stays on one line: a wrapped cell makes
    // its row taller than its neighbours, which is content deciding layout.
    className: "whitespace-nowrap",
    cell: (p) => (
      <span className="flex items-center gap-1.5">
        <span className="text-fg-muted">{KIND_LABEL[p.kind]}</span>
        {p.git?.shallow && <Badge>shallow</Badge>}
      </span>
    ),
  },
  {
    key: "branch",
    header: "Branch",
    cell: (p) => (
      <span
        className="block truncate text-fg-muted"
        title={[p.git?.branch, p.git?.head_sha].filter(Boolean).join(" @ ")}
      >
        {p.git?.branch ?? "-"}
      </span>
    ),
    className: "max-w-[10rem]",
  },
  {
    key: "remote",
    header: "Remote",
    cell: (p) => <Remote project={p} />,
    className: "max-w-[16rem]",
  },
  {
    key: "activity",
    header: "Activity",
    className: "whitespace-nowrap",
    cell: (p) => (
      <span className={ACTIVITY_CLASS[p.activity]}>{p.activity}</span>
    ),
  },
  {
    key: "packages",
    header: "Packages",
    numeric: true,
    cell: (p) => (
      <span title={p.ecosystems.join(", ") || undefined}>
        {p.package_count}
      </span>
    ),
  },
  {
    key: "findings",
    header: "Findings",
    className: "whitespace-nowrap",
    cell: (p) => <Findings project={p} />,
  },
];

/** The inventory: one row per project the scan discovered (a folder scan's or
 *  the machine's), with the
 *  identity that makes it a project (git remote, branch, activity) rather than
 *  a path. Row order is the server's project order. */
export function Inventory({ projects }: { projects: Project[] }) {
  if (projects.length === 0) return null;
  return (
    <details open className="shrink-0 border-b border-border px-6 py-4">
      <summary className="cursor-pointer font-sans text-[13px] text-fg-muted focus-ring">
        {projects.length} {projects.length === 1 ? "project" : "projects"} in
        this scan
      </summary>
      {/* Capped so a home-wide scan's inventory scrolls instead of pushing the
          findings below the fold. */}
      <div className="mt-3 max-h-56 overflow-y-auto">
        <DataTable columns={COLUMNS} rows={projects} rowKey={(p) => p.id} />
      </div>
    </details>
  );
}

/** The project half of Husk: pick a folder, scan it, and see both what is in
 *  it (the inventory) and what is wrong with it (the findings). The Scan tab
 *  is the machine's standing posture and never scans a folder. */
export function Projects({
  onOpenGuide,
  demo,
}: {
  onOpenGuide?: (taskId: string) => void;
  demo?: LiveScan;
} = {}) {
  const live = useLive();
  const projects = (demo ?? live.data)?.report?.projects ?? [];

  if (!live.data && !demo) {
    return (
      <div className="mx-auto w-full max-w-2xl px-6 pt-16">
        <EmptyState
          icon={<FolderGit2 size={24} />}
          title="No folder scanned yet"
          description="Pick a folder and Husk will list the repos, submodules, and packages it finds."
        />
      </div>
    );
  }

  return (
    <div className="flex min-w-0 flex-col lg:h-full">
      <Inventory projects={projects} />
      <div className="min-h-0 flex-1">
        <Scan onOpenGuide={onOpenGuide} source="project" demo={demo} />
      </div>
    </div>
  );
}
