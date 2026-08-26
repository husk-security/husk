# Husk for Gemini CLI

Gemini CLI reads MCP servers from `settings.json` and instructions from
`GEMINI.md` files.

**Quick path:** `husk mcp install gemini` writes step 1 for you (add
`--global` for `~/.gemini/settings.json`, `--dry-run` to preview). Then do step 2.

## 1. Register the MCP server

Merge this into your project `.gemini/settings.json` or the global
`~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "husk": {
      "command": "husk",
      "args": ["mcp"]
    }
  }
}
```

Requires `husk` on `PATH`. Verify with `/mcp` inside Gemini CLI.

No husk binary yet? Use `"command": "npx"` with `"args": ["-y", "husk-sec", "mcp"]`
instead. That resolves husk through npm on every start, so prefer the installed
binary once you have one.

## 2. Teach Gemini how to use husk

Append the shared guide to your project `GEMINI.md` or the global
`~/.gemini/GEMINI.md`:

```sh
cat integrations/husk-agent-guide.md >> GEMINI.md
```
