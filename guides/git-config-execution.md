+++
id = "git-config-execution"
category = "Source control"
kind = "baseline"
severity = "high"
control = "git-config-execution"
estimate = "10 min"
solution_name = "Husk scan (repo git config)"
solution_url = ""
solution_husk = true
related_rules = []
+++

# Check .git/config for command-executing keys

> Keys in a repo-local git config run commands on an ordinary git status, before you read any code.

Git refuses to honour exactly three keys from a repo-local `.git/config`: `safe.bareRepository`, `safe.directory`, and `uploadpack.packObjectsHook`. Everything else in a cloned config is honoured, including `core.fsmonitor`, `core.pager`, `diff.external`, `!` aliases, credential helpers, and clean and smudge filters, all of which run commands.

## Steps

1. Scan all checkouts.
   ```command
husk scan
   ```
2. Unset any you did not set.
   ```command
for k in core.fsmonitor core.pager diff.external; do git config --file .git/config --unset $k; done
   ```

## Sources

- [Sonar: Claude Code arbitrary code execution](https://www.sonarsource.com/blog/claude-arbitrary-code-execution/)
