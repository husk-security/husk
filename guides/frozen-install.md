+++
id = "frozen-install"
category = "Dependencies"
kind = "baseline"
severity = "high"
control = "frozen-install"
estimate = "10 min"
solution_name = "npm ci and frozen install flags"
solution_url = "https://docs.npmjs.com/cli/v11/commands/npm-ci"
solution_husk = false
related_rules = []
+++

# Use frozen installs in CI and Dockerfiles

> npm install re-resolves and rewrites the very lockfile it is supposed to enforce.

A committed lockfile is only a control if installs fail on drift. `npm install` re-resolves ranges and rewrites the lock, so a CI job running it during a package's malicious window pulls the compromise past a clean lockfile.

## Steps

1. JavaScript: `pnpm install --frozen-lockfile`, `yarn install --immutable`, `bun install --frozen-lockfile`, or:
   ```command
npm ci
   ```
2. Python: `uv sync --locked`, or hash-pinned pip.
   ```command
pip install --require-hashes -r requirements.txt
   ```
3. Elsewhere: `bundle install --deployment`, `cargo build --locked`, `go build -mod=readonly`.

## Sources

- [npm ci reference](https://docs.npmjs.com/cli/v11/commands/npm-ci)
- [chalk and debug compromise (Aikido)](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
