+++
id = "agent-permissions"
category = "AI agents & MCP"
kind = "baseline"
severity = "critical"
control = "agent-permissions"
estimate = "10 min"
solution_name = "Husk scan (agent permissions)"
solution_url = ""
solution_husk = true
related_rules = ["agent-unrestricted-shell", "agent-dangerous-shell", "agent-broad-read", "agent-broad-write"]
+++

# Scope agent allow rules to the project

> One injected prompt turns a broad allowlist into arbitrary shell.

`permissions.allow` entries in `.claude/settings.json` run without asking on every prompt, including a poisoned one. `Bash(*)` is unrestricted shell; `Read` or `Write` on `~`, `/`, or a `..` path reaches everything outside the repo. Claude Code never auto-approves `curl` or `wget` (the exfiltration path); an allow rule re-adds them.

## Steps

1. List the flagged allow rules.
   ```command
husk scan
   ```
2. Replace each wildcard with the narrowest working rule: `Bash(npm test:*)` not `Bash(*)`, `Read(src/**)` not `Read(~/)`. Delete `Bash(curl *)` and `Bash(wget *)`.
3. Add a `PreToolUse` deny hook. `karanb192/claude-code-hooks` (MIT) blocks credential reads and dangerous commands, even under `--dangerously-skip-permissions`; `/plugin install security-guidance@claude-plugins-official` reviews what it lets through. Both match on regexes, so obfuscation defeats them.

## Sources

- [Claude Code permissions reference](https://code.claude.com/docs/en/permissions)
- [OWASP LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
