import { cn } from "@huskdev/ui";

/** Collapse $HOME to `~` so the meaningful tail of a path survives. */
export const shortPath = (p: string): string =>
  p.replace(/^\/home\/[^/]+/, "~").replace(/^\/Users\/[^/]+/, "~");

/** Split a path so a label can truncate in the middle: the head is allowed to
 *  ellipsize, the tail never does. Paths distinguish themselves by their last
 *  segments, so clipping the end turns six sibling directories into six
 *  identical-looking rows. */
export const splitTail = (p: string, segments = 2): [string, string] => {
  const parts = shortPath(p).split("/");
  const cut = Math.max(1, parts.length - segments);
  return [parts.slice(0, cut).join("/"), parts.slice(cut).join("/")];
};

/** The only way a path is written in the UI. The tail is capped rather than
 *  fixed, because a single segment can be longer than its column. Anything
 *  reaching for a plain `truncate` on a path is choosing to delete the part
 *  that tells two rows apart. */
export function PathLabel({
  path,
  className,
}: {
  path: string;
  className?: string;
}) {
  const [head, tail] = splitTail(path);
  return (
    <span
      className={cn("flex min-w-0 flex-1 font-mono text-[11px]", className)}
      title={path}
    >
      <span className="truncate text-fg-subtle">{head}</span>
      <span className="max-w-[70%] shrink-0 truncate text-fg-muted">
        /{tail}
      </span>
    </span>
  );
}

/** The places one statement applies to.
 *
 *  A statement that holds in forty files is written once with this under it,
 *  never once per file. The column scrolls past a few entries, so its height
 *  does not follow the number of places. The line is what tells two findings in
 *  one file apart, so it never gives way; the path head ellipsizes instead. */
export function Places({
  at,
  className,
}: {
  at: { path?: string; line?: number }[];
  className?: string;
}) {
  const places = at.filter((p) => p.path);
  if (places.length === 0) return null;
  return (
    <div
      className={cn("mt-1 grid max-h-36 gap-0.5 overflow-y-auto", className)}
    >
      {places.map(({ path, line }) => (
        <p
          key={`${path}|${line ?? ""}`}
          className="flex w-fit min-w-0 max-w-full items-baseline"
        >
          <PathLabel path={path as string} />
          {line !== undefined && (
            <span className="shrink-0 font-mono text-[11px] tabular-nums text-fg-muted">
              :{line}
            </span>
          )}
        </p>
      ))}
    </div>
  );
}
