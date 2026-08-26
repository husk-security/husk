+++
id = "agent-pretooluse-guard"
category = "AI agents & MCP"
kind = "recommendation"
severity = "high"
control = "agent-pretooluse-guard"
estimate = "15 min"
solution_name = "Claude Code PreToolUse hook"
solution_url = "https://code.claude.com/docs/en/hooks"
solution_husk = false
related_rules = []
+++

# Gate agent tool calls before they run

> Injection arrives in what the agent reads, not in what you type.

Poisoned instructions reach the model through file contents, web fetches, tool output, and MCP responses, so the gate that matters is `PreToolUse` on `Read` and `Bash`. It returns `hookSpecificOutput.permissionDecision: "deny"` and holds even under `--dangerously-skip-permissions`. `PostToolUse` cannot block anything: the tool has already run. Both tools below match on regexes, so obfuscation defeats them; they catch agent accidents, not a determined adversary.

## Steps

1. Install a blocking hook. `karanb192/claude-code-hooks` (MIT) denies credential reads and destructive commands out of the box.
   ```command
git clone https://github.com/karanb192/claude-code-hooks
   ```
2. Add a reviewing layer with `/plugin install security-guidance@claude-plugins-official`. It comments on tool calls instead of denying them, so the two do different jobs.
3. Confirm what is registered.
   ```command
husk scan
   ```

## Sources

- [Claude Code hooks reference](https://code.claude.com/docs/en/hooks)
- [karanb192/claude-code-hooks](https://github.com/karanb192/claude-code-hooks)
