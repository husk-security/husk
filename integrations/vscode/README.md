# Husk for VS Code (Copilot agent mode)

VS Code reads MCP servers from `mcp.json` and agent instructions from
`.github/copilot-instructions.md`. MCP requires agent mode (Copilot Chat set to
**Agent**).

**Quick path:** `husk mcp install vscode` writes step 1 for you (`--dry-run`
to preview). Then do step 2.

## 1. Register the MCP server

Add this to your workspace `.vscode/mcp.json` (or run **MCP: Add Server** from
the Command Palette for a global entry):

```json
{
  "servers": {
    "husk": {
      "type": "stdio",
      "command": "husk",
      "args": ["mcp"]
    }
  }
}
```

Requires `husk` on `PATH`. Start the server from the `mcp.json` CodeLens or the

No husk binary yet? Use `"command": "npx"` with `"args": ["-y", "husk-sec", "mcp"]`
instead. That resolves husk through npm on every start, so prefer the installed
binary once you have one.
**MCP: List Servers** command.

## 2. Teach Copilot how to use husk

Append the shared guide to `.github/copilot-instructions.md`:

```sh
mkdir -p .github && cat integrations/husk-agent-guide.md >> .github/copilot-instructions.md
```

Ensure `github.copilot.chat.codeGeneration.useInstructionFiles` is enabled in
settings so the file is loaded.
