+++
id = "dependency-cooldown"
category = "Dependencies"
kind = "baseline"
severity = "high"
control = "dependency-cooldown"
estimate = "10 min"
solution_name = "Package manager cooldown settings"
solution_url = "https://cooldowns.dev/"
solution_husk = false
related_rules = []
+++

# Set a dependency cooldown

> Malicious versions are caught in hours. A cooldown means you never install them.

Compromised releases are pulled within hours: chalk and debug (2025) were live for two and a half. A week's cooldown blocks the whole class, transitives included, with no threat feed. Cargo, Go, Composer, Maven, and NuGet have no native support yet.

## Steps

1. npm: days, in `.npmrc`.
   ```command
npm config set min-release-age 7
   ```
2. pnpm 11+: `minimumReleaseAge: 10080` (minutes, default 1440) in `pnpm-workspace.yaml`. yarn: `npmMinimalAgeGate: 10080` in `.yarnrc.yml`. bun: `[install] minimumReleaseAge` in `bunfig.toml`. deno: `minimumDependencyAge` in `deno.json`.
3. uv: `exclude-newer = "7 days"` in `uv.toml` or `[tool.uv]`; `exclude-newer-package` exempts a single security fix.

## Sources

- [Dependency cooldown settings for every package manager](https://cooldowns.dev/)
- [Ledger connect-kit incident report](https://www.ledger.com/blog/security-incident-report)
