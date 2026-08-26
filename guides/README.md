# Contributing a guide item

Guide prose lives here as Markdown. TOML frontmatter carries the small amount
of structured metadata the product needs; `build.rs` validates and compiles the
catalog at build time.

## The rule that decides whether an item belongs here

**An item belongs in the guide only if husk can observe its state on this
machine, or it remediates something husk actually found.** Everything else is
advice, and advice does not go in a checklist that claims to know your posture.

That rule has one deliberate exception: an item whose absence causes the
incidents the rest of the catalog mitigates, but which lives in an online
account rather than on disk. Those declare `verification = "manual"`, carry no
control, and are resolved by the user alone. There is exactly one today.
`build.rs` enforces the either-or, and a guide test keeps the manual count from
creeping.

A control that can never return `passed` is not a control. Do not ship a
`baseline` backed by one.

## Format

Each file declares a stable `id` (matching the filename), `category`, `kind`
(`baseline` or `recommendation`), realistic impact `severity`, a registered Rust
`control` (or `verification = "manual"`), `estimate`, solution metadata, and any
`related_rules`. The body uses:

- `#` for the title and `>` for the short reason it matters
- plain prose for the problem
- `## Steps` with numbered Markdown steps and optional `command` fences
- optional `## Options` / `### Option [recommended]`
- `## Sources` with normal Markdown links

## Scope

`scope` says how many tasks the item is once the scan says what is on the
machine. It defaults to `machine`: one item, one task.

- `machine`: one task. Encrypting the disk is one job however many projects
  sit on it.
- `project`: one task per project the control found something in.
- `project-ecosystem`: one task per (project, ecosystem) pair.

Choose anything but `machine` only when the split names work a reader would
genuinely do at separate times: upgrading Python dependencies in one repository
and Go dependencies in another are two jobs, and one checkbox over both can
never honestly be ticked. A split that does not name separate work multiplies
the list into noise, which is worse than the checkbox it replaced.

A scoped item splits along the findings its control attached, so it needs a
control (`verification = "manual"` cannot be scoped) whose failing evidence is
its findings. With nothing found it stays one row.

## Writing

Terse and technical. Name the file, the key, and the exact value: `.npmrc`
`min-release-age`, never "configure your package manager appropriately". Cite a
real incident when it changes what the reader should do, not as background
colour. No "Done means ..." sentence, no restating the `>` line as the first
body sentence, no step that says to review something carefully. Skip
`## Options` unless several tools genuinely compete.

Never use an em dash or en dash anywhere a user can see it.

### Length

**Aim for 100 words. 150 is a hard ceiling.** Everything after the closing
`+++` counts, `## Sources` included:

```sh
awk 'n>=2{print} /^\+\+\+$/{n++}' guides/<id>.md | wc -w
```

Count it that way, because that is what the reader reads. An earlier pass used
a counter that skipped the sources block and reported a mean of 129 when the
real figure was 142, with 24 files over the ceiling it claimed were under it.

If an item genuinely cannot say its thing in 150 words, it is two items or it is
the wrong item. Split it rather than squeezing the prose.

## The control

The matching entry in `src/guide/control/<domain>.rs` observes the scan and
returns `passed`, `failed`, `partial`, `unknown`, or `not-applicable`, with
local evidence. `unknown` means husk could not read the artifact, never that the
probe is unwritten. Its planner may return typed proposals from
`src/remediation/`. Markdown never contains executable logic.

An item counts as handled only after it has been read and is either verified by
its control, manually completed, or dismissed with an optional reason. Baseline
and recommendation items share one progress denominator; their kind, severity,
and evidence-driven priority remain distinct.
