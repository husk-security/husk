+++
id = "project-policy"
category = "Source control"
kind = "recommendation"
severity = "low"
control = "project-policy"
estimate = "10 min"
solution_name = "Husk project policy (husk init)"
solution_url = ""
solution_husk = true
related_rules = []
+++

# Commit your triage decisions to the repo

> Triage decisions kept in one head are lost at turnover and unenforceable in CI.

A committed `.husk/policy.toml` records blocked and allowed packages, suppressed findings, and the CI failure threshold, so every clone and pipeline enforces the same decisions.

## Steps

1. Generate and commit the policy file.
   ```command
husk init
   ```
2. Record later decisions with `husk approve` rather than hand-editing.

## Sources

- [Andrew Nesbitt: the fragmented world of dependency policy](https://nesbitt.io/2026/03/19/the-fragmented-world-of-dependency-policy.html)
