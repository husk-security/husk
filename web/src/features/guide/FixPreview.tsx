import { CommandBlock, cn } from "@huskdev/ui";
import { TriangleAlert } from "lucide-react";
import { useMemo } from "react";
import { Diff as DiffView, Hunk, parseDiff } from "react-diff-view";
import "react-diff-view/style/index.css";
import type { FileDiff, FixStep } from "@/lib/api";
import { PathLabel, Places, shortPath } from "@/lib/path";
import { Prose } from "@/lib/prose";
import type { PlannedCommand } from "./proposals";

/** Height the change area is capped at. Past it the diff scrolls inside
 *  itself, so a card is the same size whether a fix touches one line or two
 *  hundred and the controls above it never move off screen. */
const CHANGE_MAX = "max-h-72";

function Section({
  label,
  aside,
  children,
}: {
  label: string;
  aside?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="border-t border-border px-3.5 py-2.5">
      <div className="mb-1.5 flex items-baseline gap-2">
        <span className="text-[11px] uppercase tracking-[0.08em] text-fg-subtle">
          {label}
        </span>
        {aside && (
          <span className="min-w-0 flex-1 truncate font-mono text-[10.5px] text-fg-subtle">
            {aside}
          </span>
        )}
      </div>
      {children}
    </div>
  );
}

/** The one-liner form of a fix.
 *
 *  `alternative` says which of the two things it is. When the fix also rewrites
 *  a file, Husk performs that edit itself and this command is the hand
 *  equivalent of the whole fix, for someone who would rather do it in their own
 *  terminal. When there is no edit, applying and running this are the same act,
 *  and the label says so rather than implying a second, different action. */
export function CommandList({
  commands,
  alternative,
}: {
  commands: PlannedCommand[];
  alternative: boolean;
}) {
  if (commands.length === 0) return null;
  const cwd = commands[0].cwd;
  const sameCwd = commands.every((entry) => entry.cwd === cwd);
  const partial = alternative && commands.some((entry) => !entry.complete);
  return (
    <Section
      label={alternative ? "Or run it yourself" : "What Apply runs"}
      aside={sameCwd && cwd ? `in ${shortPath(cwd)}` : undefined}
    >
      <div className={cn("grid gap-1.5 overflow-y-auto", CHANGE_MAX)}>
        {commands.map((entry) => (
          <div key={entry.command} className="min-w-0">
            {/* The library block is single-line, and a command you cannot read
                whole is one you cannot check, which is the point of showing it,
                so it wraps here instead. It wraps at spaces only: breaking mid
                token would split a version or a path into something that is not
                the command. The wrap hangs, because `pre-wrap` swallows the
                space it breaks at, so a line ending `bun install` above one
                starting `--ignore-scripts` reads as the single token `bun
                install--ignore-scripts`.

                The wrap is capped at three lines and scrolls past them: the
                block belongs to a card whose height cannot follow the length of
                whatever command the plan happens to hold. */}
            <CommandBlock
              command={entry.command}
              className="px-3 py-2 text-[12px] [&_code]:max-h-[3.25rem] [&_code]:min-w-0 [&_code]:whitespace-pre-wrap [&_code]:pl-4 [&_code]:-indent-4"
            />
            {!sameCwd && entry.cwd && (
              <p className="mt-1 truncate font-mono text-[10.5px] text-fg-subtle">
                in {shortPath(entry.cwd)}
              </p>
            )}
          </div>
        ))}
      </div>
      {partial && (
        <p className="mt-2 flex items-start gap-1.5 rounded-md border border-border bg-surface px-2.5 py-2 text-[11.5px] leading-snug text-severity-medium">
          <TriangleAlert size={13} className="mt-0.5 shrink-0" />
          <span>
            Copying this is not the whole fix: it does not make the edit below.
            Apply does both.
          </span>
        </p>
      )}
    </Section>
  );
}

/** The files a fix rewrites. `file.diff` is a unified diff the server rendered
 *  once; react-diff-view parses it and nothing here interprets the format. */
export function DiffList({
  files,
}: {
  files: { key: string; file: FileDiff }[];
}) {
  if (files.length === 0) return null;
  return (
    <Section label="What Apply edits">
      <div className={cn("grid gap-2 overflow-y-auto", CHANGE_MAX)}>
        {files.map(({ key, file }) => (
          <FileDiffView key={key} file={file} />
        ))}
      </div>
    </Section>
  );
}

function FileDiffView({ file }: { file: FileDiff }) {
  const parsed = useMemo(() => parseDiff(file.diff)[0], [file.diff]);
  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <div className="flex items-center gap-2 bg-surface px-2.5 py-1.5">
        <PathLabel path={file.path} />
        {file.created && (
          <span className="shrink-0 text-[10.5px] text-fg-subtle">
            new file
          </span>
        )}
        <span className="shrink-0 font-mono text-[10.5px] tabular-nums">
          <span className="text-success">+{file.added}</span>{" "}
          <span className="text-danger">-{file.removed}</span>
        </span>
      </div>
      {/* Long lines scroll inside this box; nothing outside it moves. */}
      <div className="husk-diff overflow-x-auto border-t border-border">
        <DiffView
          viewType="unified"
          diffType={parsed?.type ?? "modify"}
          hunks={parsed?.hunks ?? []}
        >
          {(rendered) =>
            rendered.map((hunk) => <Hunk key={hunk.content} hunk={hunk} />)
          }
        </DiffView>
      </div>
    </div>
  );
}

/** Steps a person takes, because Husk will not.
 *
 *  A step's places are a list under it, not a sentence each: the instruction is
 *  written once and the column of paths is what the reader scans. The list
 *  scrolls inside itself past a few entries, so a step covering twenty files is
 *  the same height as one covering two. */
export function StepList({ steps }: { steps: FixStep[] }) {
  if (steps.length === 0) return null;
  return (
    <Section label="Steps">
      {/* A step often names an absolute path, which has no break opportunity
          the browser will take on its own. */}
      <ol className="grid list-decimal gap-1.5 pl-4 text-[12px] leading-relaxed text-fg-muted marker:text-fg-subtle">
        {steps.map((step) => (
          <li key={step.text} className="min-w-0 [overflow-wrap:anywhere]">
            <Prose text={step.text} />
            <Places
              at={(step.subjects ?? []).map((path) => ({ path }))}
              className="rounded-md border border-border bg-surface px-2 py-1.5"
            />
          </li>
        ))}
      </ol>
    </Section>
  );
}

/** The program's own output, unstyled and unsummarized. Fixed height so a
 *  hundred lines of npm noise cannot push the page around. */
export function Transcript({ text }: { text: string }) {
  return (
    <Section label="Output">
      <div className="max-h-44 overflow-auto rounded-lg border border-border bg-surface">
        <pre className="w-max min-w-full whitespace-pre px-2.5 py-2 font-mono text-[11px] leading-[1.55] text-fg-muted">
          {text}
        </pre>
      </div>
    </Section>
  );
}
