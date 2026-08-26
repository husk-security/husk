+++
id = "install-scripts-disabled"
category = "Dependencies"
kind = "baseline"
severity = "high"
control = "install-scripts-disabled"
estimate = "5 min"
solution_name = "ignore-scripts / allowScripts / onlyBuiltDependencies"
solution_url = "https://docs.npmjs.com/cli/v11/using-npm/config#ignore-scripts"
solution_husk = false
related_rules = ["npmrc-ignore-scripts"]
+++

# Disable dependency install scripts

> One compromised dependency's install script runs with your shell and your files.

npm runs every dependency's preinstall/install/postinstall/prepare at install time, where most registry-compromise payloads execute. npm 12 (July 2026) ships them off by default behind an `allowScripts` allowlist; older npm, yarn, and bun run them freely. Disabling them does not stop payloads that run at require() time.

## Steps

1. npm 11 and older, and anything reading npmrc:
   ```command
npm config set ignore-scripts true
   ```
2. pnpm: allowlist genuine build needs via `onlyBuiltDependencies` in `pnpm-workspace.yaml`.
3. npm 12+: keep the default; approve exceptions with `npm approve-scripts --allow-scripts-pending`, committed in `package.json`.
4. Native builds stop; run one deliberately: `npm rebuild <pkg>`.

## Sources

- [npm 12 install-time security defaults (GitHub changelog)](https://github.blog/changelog/2026-07-08-npm-install-time-security-and-gat-bypass2fa-deprecation/)
- [node-ipc protestware ran at import time (Snyk)](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/)
