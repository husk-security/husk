+++
id = "git-hooks"
category = "Source control"
kind = "baseline"
severity = "high"
control = "git-hooks"
estimate = "10 min"
solution_name = "Husk scan (git hooks)"
solution_url = ""
solution_husk = true
related_rules = ["git-hook"]
+++

# Audit every git hook in your repos

> A planted git hook runs shell code with your privileges on every commit, merge, or checkout.

A repository executes hooks from four places, not one: `.git/hooks`, the `core.hooksPath` target, and the in-repo `.githooks/` and `.husky/` conventions a prepare or postinstall script activates after clone. `.git/hooks` is where people look, so that is not where implants go.

## Steps

1. List every hook across all four locations.
   ```command
husk scan
   ```
2. Read each hook as the shell script it is; delete any your team did not install (a husky hook holds only the shim and your commands).

## Sources

- [githooks(5)](https://git-scm.com/docs/githooks)
