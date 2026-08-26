# Agent integrations

Husk exposes a Model Context Protocol server over stdio via `husk mcp`. Any
MCP-capable agent (Claude Code, Codex, OpenCode, Cursor, Zed, ...) can connect
to the locally installed husk and read scan results or trigger scoped scans.
Nothing here talks to a network service; the MCP server only reads the local
scan cache and runs local scans.

This directory holds the per-agent glue. All of it lives in this repo, in this
single place, because every integration is a thin wrapper around the same two
things: the `husk mcp` command and one shared usage guide.

| Directory | Agent | Mechanism |
| --- | --- | --- |
| `plugin/` | Claude Code, Codex, Cursor | One plugin, three manifests over the same payload: `.mcp.json` registers the MCP server and `skills/using-husk/` teaches the agent the CLI and MCP output. The per-agent manifests are `.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`, and `.cursor-plugin/plugin.json`; each agent's marketplace index lives at the repo root. |
| `codex/` | OpenAI Codex | `config.toml` MCP snippet, `AGENTS.md` guide, optional `/husk-audit` prompt. |
| `opencode/` | OpenCode | `opencode.json` MCP snippet plus the `AGENTS.md` guide. |
| `cursor/` | Cursor | `.cursor/mcp.json` MCP snippet plus the `AGENTS.md` guide. |
| `vscode/` | VS Code (Copilot agent mode) | `.vscode/mcp.json` MCP snippet plus the `.github/copilot-instructions.md` guide. |
| `claude-desktop/` | Claude Desktop | `claude_desktop_config.json` MCP snippet; the MCP server's own instructions cover usage. |
| `gemini-cli/` | Gemini CLI | `settings.json` MCP snippet plus the `GEMINI.md` guide. |
| `husk-agent-guide.md` | any | The shared canonical guide. The Claude skill mirrors this content; when you change one, change both. |

## Installing from this repository

The plugin ships config, not the scanner. Its MCP server runs `npx -y husk-sec
mcp`, so it needs Node and resolves husk from npm on every start. Install husk
and put it on `PATH` for the better path, then check with `husk mcp
--selfcheck`, which exits 0 when the server is reachable. The MCP config
snippets below all invoke `husk` directly and require it on `PATH`.

Four agents install husk straight from the git repository, no registry entry
needed. All four resolve the repository over git, so they need it to be public
(a local path or any git URL works during development).

| Agent | Install command | Manifest |
| --- | --- | --- |
| Claude Code | `/plugin marketplace add husk-security/husk` then `/plugin install husk@husk` | `.claude-plugin/marketplace.json` |
| Codex | `codex plugin marketplace add husk-security/husk` then `codex plugin add husk@husk` | `.agents/plugins/marketplace.json` |
| Gemini CLI | `gemini extensions install https://github.com/husk-security/husk` | `gemini-extension.json` |
| Any of the 70+ agents `skills` supports | `npx skills add husk-security/husk` | reads `.claude-plugin/marketplace.json` |

Cursor reads `.cursor-plugin/marketplace.json` the same way, but installs go
through a marketplace Cursor has accepted; husk is not listed in one.

## Distribution

Husk ships three things: MCP config snippets, one plugin with a manifest per
agent, and the shared agent guide. Agents without a plugin manifest consume the
snippets the same way: an MCP server entry in their own config file (`mcp.json`
/ `config.toml` / `opencode.json` / `claude_desktop_config.json` /
`settings.json`) and instructions in a per-tool guide file (`AGENTS.md` /
`GEMINI.md` / `.github/copilot-instructions.md`). `husk mcp install` writes the
first for you.

Shipping a manifest makes husk installable from this repository. It does not
list husk in any gallery or directory.

## `husk mcp install`

For the JSON/TOML-config agents, `husk mcp install <agent>` writes the MCP
server entry for you instead of hand-copying snippets. It is idempotent (re-runs
are a no-op) and preserves any other config in the file:

```
husk mcp install cursor            # writes ./.cursor/mcp.json
husk mcp install vscode            # writes ./.vscode/mcp.json
husk mcp install gemini --global   # writes ~/.gemini/settings.json
husk mcp install claude-desktop    # writes the Claude Desktop config
husk mcp install codex             # appends [mcp_servers.husk] to ~/.codex/config.toml
husk mcp install opencode          # writes ./opencode.json (mcp.husk)
```

Add `--dry-run` to print what would be written without touching anything, and
`--global` to target the user-level config instead of the project. `husk mcp
--selfcheck` verifies the server can start and reports the cache state. You
still teach the agent how to use husk via its instruction file (`AGENTS.md` /
`GEMINI.md` / `.github/copilot-instructions.md`) or, for MCP-native clients, the
server's own `instructions` and the `husk://agent-guide` resource.
