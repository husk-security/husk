+++
id = "agent-hooks"
category = "AI agents & MCP"
kind = "baseline"
severity = "critical"
control = "agent-hooks"
estimate = "10 min"
solution_name = "Husk scan (agent hooks)"
solution_url = ""
solution_husk = true
related_rules = ["agent-hook-command", "agent-credential-helper"]
+++

# Delete agent hooks you did not write

> A hooks block in a cloned repo runs shell commands with your privileges before you type anything.

Claude Code runs `hooks` entries and `apiKeyHelper` as shell on agent events. A `SessionStart` hook committed to a repo's `.claude/settings.json` re-infects on every clone with no `npm install`, so removing the package changes nothing. The trust dialog covers a project `settings.json` but not `settings.local.json`.

## Steps

1. List every configured hook and credential helper.
   ```command
husk scan
   ```
2. Delete any hook or `apiKeyHelper` you did not write; in review, read a committed `hooks` block as the shell script it is.
3. Keep your own hooks in the gitignored `.claude/settings.local.json`.

## Sources

- [Sonar: Mini Shai-Hulud targets AI coding agents](https://www.sonarsource.com/blog/mini-shai-hulud-targets-ai-coding-agents/)
- [Claude Code hooks reference](https://code.claude.com/docs/en/hooks)
