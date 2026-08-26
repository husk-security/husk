# Husk for Claude Desktop

Claude Desktop is the reference MCP client. It reads MCP servers from
`claude_desktop_config.json`.

**Quick path:** `husk mcp install claude-desktop` writes step 1 for you
(`--dry-run` to preview). Restart Claude Desktop afterwards.

## 1. Register the MCP server

Edit the config (Settings → Developer → Edit Config, or directly):

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

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

Requires `husk` on `PATH` (use an absolute path to the binary if Claude Desktop
does not inherit your shell `PATH`). Restart Claude Desktop to load the server.

No husk binary yet? Use `"command": "npx"` with `"args": ["-y", "husk-sec", "mcp"]`
instead. That resolves husk through npm on every start, so prefer the installed
binary once you have one.

## 2. Teach Claude how to use husk

The husk MCP server ships its own usage instructions, which Claude Desktop
picks up automatically; no separate guide file is required. For a richer
system prompt, paste `integrations/husk-agent-guide.md` into a Project's custom
instructions; Claude Desktop has no per-workspace `AGENTS.md`.
