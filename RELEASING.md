# Releasing husk

Four commands. Everything else is the tag's job.

```sh
cargo release 0.1.2 --execute --no-confirm
```

Bumps the version in `Cargo.toml`, `Cargo.lock`, `flake.nix`, `server.json`
(three fields), and the four agent plugin manifests, promotes the `## Unreleased`
changelog section to this version, and commits. It does not push, tag, or publish.

```sh
git push -u origin release/0.1.2
gh pr create --fill && gh pr merge --squash
```

```sh
git fetch origin main && git tag -a v0.1.2 origin/main -m "husk 0.1.2" && git push origin v0.1.2
```

The tag is the release. Pushing it builds four targets, signs them with cosign
and SLSA provenance, publishes the GitHub Release, then npm (five packages),
crates.io, and the MCP Registry. All through OIDC: there is no publishing token
anywhere.

## Why the tag is pushed by hand

Every publishing job checks that both `github.actor` and
`github.triggering_actor` are a maintainer, and re-checks on any re-run. That
is the publication boundary. A tag pushed by a bot skips publishing entirely,
and one created through the Releases API is lightweight, so GitHub credits it
to whoever authored the underlying commit instead of the tagger.

## What the changelog is

One line per notable change, written in the pull request that made it, under
`## Unreleased`. Cosmetic work, refactors and dependency bumps get no entry;
nothing enforces that, because the judgement is the point (see `AGENTS.md`).

The GitHub release body is that version's `CHANGELOG.md` section, verbatim.
Nothing else: install instructions and what husk is live in the README, and
repeating them per release only creates copies that go stale on their own.

To reword an entry, edit `CHANGELOG.md` in the release pull request.

## When it goes wrong

`cargo release` refuses if a version count drifts, for example a new
`packages[]` entry in `server.json`. Fix the count in `release.toml`.

The tag is validated before anything publishes: exact `vX.Y.Z`, all six files
agreeing, reachable from `origin/main`, still pointing at the same commit
mid-run, and a matching `## X.Y.Z` changelog section.

Publishing is idempotent. A version already on npm or crates.io is skipped, so
re-running a partly failed release is safe. Once a version is published
anywhere it is spent: yank, then cut the next patch. Before anything publishes,
deleting and re-tagging costs nothing.
