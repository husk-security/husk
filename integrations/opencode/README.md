# Husk for OpenCode

OpenCode is configured through `opencode.json` and plain `AGENTS.md` rules.

## 1. Register the MCP server

The easy path: `husk mcp install` writes the entry for you (idempotent, add
`--global` for `~/.config/opencode/opencode.json`, `--dry-run` to preview):

```sh
husk mcp install opencode
```

Or merge this into your project `opencode.json` or global
`~/.config/opencode/opencode.json` by hand:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "husk": {
      "type": "local",
      "command": ["husk", "mcp"],
      "enabled": true
    }
  }
}
```

Requires `husk` on `PATH`.

No husk binary yet? Use `"command": ["npx", "-y", "husk-sec", "mcp"]` instead.
That resolves husk through npm on every start, so prefer the installed binary
once you have one.

## 2. Teach OpenCode how to use husk

Append the shared guide to your project `AGENTS.md` or the global
`~/.config/opencode/AGENTS.md`:

```sh
cat integrations/husk-agent-guide.md >> AGENTS.md
```
