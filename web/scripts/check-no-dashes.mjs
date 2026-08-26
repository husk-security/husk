#!/usr/bin/env node
// Fail if an em dash (U+2014) or en dash (U+2013) reaches the shipped web
// UI. These read as machine-generated; use a period, comma, colon, semicolon, or
// parentheses instead (see AGENTS.md: "User-facing text"). A plain hyphen (-) for
// ranges or compound words is allowed.
//
// It scans the BUILT bundle in web/dist, not the source, on purpose: the bundler
// strips developer comments (which may use dashes freely) and compiles JSX text
// and HTML entities like `&mdash;` down to real characters, so this catches every
// user-visible dash while never flagging a code comment. Run after `npm run
// build`: `node scripts/check-no-dashes.mjs`.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const DIST = new URL("../dist/", import.meta.url).pathname;
const DASH = /[—–]/;

if (!existsSync(DIST)) {
  console.error(
    "check-no-dashes: web/dist not found; run `npm run build` first (the guard scans the built bundle).",
  );
  process.exit(1);
}

function walk(dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) files.push(...walk(p));
    else files.push(p);
  }
  return files;
}

const hits = [];
for (const file of walk(DIST)) {
  const text = readFileSync(file, "utf8");
  if (!DASH.test(text)) continue;
  for (const m of text.matchAll(/.{0,30}[—–].{0,30}/g)) {
    hits.push(`${file}: …${m[0].replace(/\n/g, " ")}…`);
  }
}

if (hits.length > 0) {
  console.error(
    "Em/en dash in the shipped web UI (use . , : ; or parentheses; see AGENTS.md):",
  );
  for (const h of hits) console.error("  " + h);
  process.exit(1);
}
console.log("check-no-dashes: no em/en dashes in the built web UI");
