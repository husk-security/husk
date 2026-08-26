# Husk for OpenAI Codex

Codex reads MCP servers from `~/.codex/config.toml` and instructions from
`AGENTS.md` files. Wire husk up with the two steps below, plus an optional
`/husk-audit` prompt.

## 1. Register the MCP server

Add to `~/.codex/config.toml` (or run
`codex mcp add husk -- husk mcp`):

```toml
[mcp_servers.husk]
command = "husk"
args = ["mcp"]
```

Requires `husk` on `PATH`.

No husk binary yet? Use `command = "npx"` with `args = ["-y", "husk-sec", "mcp"]`
instead. That resolves husk through npm on every start, so prefer the installed
binary once you have one.

## 2. Teach Codex how to use husk

Append the shared guide to your global `~/.codex/AGENTS.md` or a project
`AGENTS.md`:

```sh
cat integrations/husk-agent-guide.md >> ~/.codex/AGENTS.md
```

## Optional: a /husk-audit prompt

Codex supports custom prompts in `~/.codex/prompts/`. Install the bundled one:

```sh
mkdir -p ~/.codex/prompts
cp integrations/codex/prompts/husk-audit.md ~/.codex/prompts/
```

Then run `/husk-audit` inside Codex.
