# husk web UI

The localhost web UI for `husk web` — a [Vite](https://vite.dev) + React 19 +
TypeScript app, styled with Tailwind v4 and the shared **[`@huskdev/ui`]** design
system so it looks like one product with the Husk cloud dashboard.

The Rust binary embeds the built `dist/` (via `rust-embed`) and serves it from
`src/web.rs`, so the shipped `husk` is a single self-contained binary — no Node,
no network, no external assets at runtime. This is behind the default **`web`
Cargo feature**; `cargo build --no-default-features` produces a TUI-only binary
that doesn't include this app at all.

[`@huskdev/ui`]: https://www.npmjs.com/package/@huskdev/ui

## Architecture

- **All UI lives here.** Rust renders no HTML — `web.rs` only serves this app's
  build and the JSON API it calls.
- **Components + tokens come from `@huskdev/ui` / `@huskdev/tokens`** (never
  re-implemented locally), so the design stays in lockstep with the platform.
- **The API** is `husk web`'s `/api/*` endpoints (`/api/live`, `/api/guide`,
  `/api/account`, `/api/rescan`, `/api/policy`, …). Types live in
  `src/lib/api.ts`. The UI reads the scan through `/api/live` (its `report`
  field embeds the full `ScanReport`); failures come back as real HTTP status
  codes with an `{ error }` body.

```
src/
├── App.tsx              app shell + sidebar nav (Guide / Scan / Account / …)
├── main.tsx             entry
├── app.css             tokens + Tailwind + brand fonts (Fontsource Geist)
├── lib/api.ts           typed fetch hooks for the husk JSON API
└── features/            one folder per view (scan, guide, account, …)
```

## Develop

The front-end talks to a running `husk` for live data. Two terminals:

```sh
# 1. the API only (no embedded UI), default :6789
husk web --dev            # from the repo root, or: cargo run -- web --dev

# 2. the Vite dev server with HMR (proxies /api → :6789)
npm install               # first time
npm run dev               # http://127.0.0.1:5181
```

## Quality gate

Run before committing (CI enforces all of these):

```sh
npm run typecheck         # tsc -b --noEmit
npm run lint              # biome check .   (format + lint)
npm run build             # tsc -b && vite build  → dist/
npx react-doctor@latest src   # aim 100/100
```

## Build & ship

`dist/` is **gitignored** — it's build output, not source. The default-feature
Rust build embeds whatever is in `dist/` at compile time, so it must be built
first; `build.rs` fails with an actionable error if it's missing:

```sh
npm --prefix web ci && npm --prefix web run build   # produce web/dist
cargo build                                          # embeds it
```

CI (the `build-web` composite action) and `release.yml` build `dist/` before
compiling, so released binaries always carry a fresh UI. Building with
`cargo build --no-default-features` skips the web UI entirely and needs no Node
toolchain.
