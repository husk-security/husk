# Husk for Cursor

Cursor reads MCP servers from `mcp.json` and project rules from `AGENTS.md`.

**Quick path:** `husk mcp install cursor` writes step 1 for you (add
`--global` for `~/.cursor/mcp.json`, `--dry-run` to preview). Then do step 2.

## 1. Register the MCP server

Merge this into your project `.cursor/mcp.json` or the global
`~/.cursor/mcp.json`:

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

Requires `husk` on `PATH`. Enable the server in Cursor Settings → MCP if it is
not picked up automatically.

No husk binary yet? Use `"command": "npx"` with `"args": ["-y", "husk-sec", "mcp"]`
instead. That resolves husk through npm on every start, so prefer the installed
binary once you have one.

## 2. Teach Cursor how to use husk

Append the shared guide to your project `AGENTS.md` (or the global
`~/.cursor/AGENTS.md`):

```sh
cat integrations/husk-agent-guide.md >> AGENTS.md
```
