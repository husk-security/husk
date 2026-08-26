/** Group items by the line they would each render.
 *
 *  N items rendering one identical line are one line and a list of N subjects.
 *  Repeating the line hides the only part that varies and multiplies every
 *  control attached to it: a user who ignores one of five identical rows
 *  watches four twins survive. First-seen order is kept, so the caller's
 *  ordering decides the output. */
export function groupByLabel<T>(
  items: T[],
  label: (item: T) => string,
): { label: string; items: T[] }[] {
  const out: { label: string; items: T[] }[] = [];
  const at = new Map<string, number>();
  for (const item of items) {
    const key = label(item);
    const index = at.get(key);
    if (index === undefined) {
      at.set(key, out.length);
      out.push({ label: key, items: [item] });
    } else out[index].items.push(item);
  }
  return out;
}

/** The sequence form of {@link groupByLabel}: where position carries meaning,
 *  only neighbours may merge, so a quiet week collapses into one row without
 *  pretending two distant entries were one event. */
export function runsOf<T>(items: T[], signature: (item: T) => string): T[][] {
  const out: T[][] = [];
  let last: string | null = null;
  for (const item of items) {
    const key = signature(item);
    if (key === last && out.length > 0) out[out.length - 1].push(item);
    else out.push([item]);
    last = key;
  }
  return out;
}
