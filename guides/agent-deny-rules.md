+++
id = "agent-deny-rules"
category = "AI agents & MCP"
kind = "baseline"
severity = "high"
control = "agent-deny-rules"
estimate = "5 min"
solution_name = "Claude Code permissions.deny block"
solution_url = "https://code.claude.com/docs/en/permissions"
solution_husk = false
related_rules = []
+++

# Deny agents your credential files

> Every 2026 agent campaign made the assistant read .env, ~/.ssh, and ~/.aws; a deny rule refuses.

`permissions.deny` blocks a read even when you would have clicked yes; four rules close the harvested paths. Limit: deny rules cover the Read tool and Bash `cat`/`head`/`sed`, but not a Python script the agent writes that opens the file itself.

## Steps

1. Open your user settings.
   ```command
$EDITOR ~/.claude/settings.json
   ```
2. Add all four rules to `permissions.deny`: `Read(./.env*)`, `Read(~/.ssh/**)`, `Read(~/.aws/**)`, `Read(~/.npmrc)`.
3. Confirm coverage.
   ```command
husk scan
   ```

## Sources

- [Claude Code permissions reference](https://code.claude.com/docs/en/permissions)
