+++
id = "agent-credentials-at-rest"
category = "AI agents & MCP"
kind = "baseline"
severity = "high"
control = "agent-credentials-at-rest"
estimate = "5 min"
solution_name = "Keys out of agent settings files"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Keep agent keys out of settings files

> s1ngularity was the first campaign to loot AI-CLI credential files; the 2026 worms enumerate them by name.

A literal `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` in a settings `env` block is a live key for an account that can run code on your machine, sitting in a file that is routinely committed, synced, and shared as a project template. File modes on the credential stores themselves are "Make credential files readable only by you".

## Steps

1. Search your agent settings files for a literal key value.
   ```command
grep -l "ANTHROPIC_API_KEY\|CLAUDE_CODE_OAUTH_TOKEN" ~/.claude/settings*.json ~/.codex/settings*.json 2>/dev/null
   ```
2. Move any literal key out of the `env` block (export at launch or use the OS keychain), then rotate the key that was stored there.

## Sources

- [Wiz: the Nx s1ngularity attack](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)
