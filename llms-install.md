# Installing husk and its MCP server

This file is written for an AI coding agent with shell access. Follow it top to
bottom to install husk and register its Model Context Protocol server. Every
command is copy-pasteable and needs no interactive input.

## What husk is

husk is a defensive, local-first security scanner for developer machines. It
reads files statically and reports vulnerable dependencies, leaked secrets,
risky install scripts and git hooks, and unsafe AI agent configuration. It never
executes what it scans, requires no account, and sends nothing to a network
service unless the user explicitly signs in or opts into telemetry.

The MCP server exposes the same scan results to an agent over stdio.

## Prerequisites

- Linux or macOS. On Windows, work inside WSL and follow the Linux path; there
  is no native Windows build.
- A POSIX shell. Node, Nix, and Cargo each unlock one of the options below, but
  none of them is needed for the installer path.
- No API key, no account, no configuration file.

## Step 1: install the binary

Pick the first option that works in the environment you are in.

### Option A: npm (no prior install)

If Node.js 20.19 or newer is available, husk needs no install step at all:

```sh
npx -y husk-sec scan
```

The `husk-sec` package is a launcher whose optional dependencies carry the
prebuilt binary for each platform, so npm downloads only the one that matches.
To put `husk` on `PATH` instead of running it once, use `npm install -g
husk-sec`.

This is the zero-install path, and it is the one to prefer when the environment
already has Node. Every other option gives the same binary.

### Option B: install script

```sh
curl -fsSL https://husk-security.dev/install.sh | sh
```

Installs to `~/.local/bin` by default. Override with `HUSK_INSTALL_DIR` or
`--install-dir`. The script verifies the release SHA-256 checksum, and verifies
the cosign signature as well when `cosign` is on `PATH`. It downloads only the
release archive, its checksum, and its signature.

If the install directory is not already on `PATH`, the installer asks before
adding it to the shell startup file, naming the exact file it would change.
Running without a terminal, as an agent normally does, declines automatically
and prints the command instead. Pass `--no-modify-path` to guarantee it never
writes to a startup file. Apply the printed command yourself, or invoke husk by
its absolute path for the rest of the session.

### Option C: Nix

Run it once, installing nothing:

```sh
nix run github:husk-security/husk -- scan
```

The flake exposes `husk` (default, includes the localhost web UI) and
`husk-tui` (the same binary without it, needing no Node toolchain).

**If `/etc/NIXOS` exists, stop and ask the user before installing.** A NixOS
machine is configured declaratively, so an imperative install is usually the
wrong thing to leave behind. Ask whether they want husk added to their
configuration (`environment.systemPackages`, or `home.packages` under Home
Manager, with `inputs.husk.url = "github:husk-security/husk"` and the package
at `husk.packages.<system>.husk`), or whether `nix run` for this session is
enough. Then do what they say. On any other system, continue without asking.

To put it on `PATH` imperatively:

```sh
nix profile install github:husk-security/husk
```

### Option D: build from source

Requires Cargo and Rust 1.95 or newer.

```sh
git clone https://github.com/husk-security/husk
cd husk
cargo build --release --no-default-features
```

The binary is at `target/release/husk`. `--no-default-features` drops the
localhost web UI, which is the only part that needs Node. For the full build,
run `npm --prefix web ci && npm --prefix web run build` first, then
`cargo build --release`.

If Nix is available, `nix build .#husk` builds the same binary from the clone
without a Rust toolchain on the host. It is not required.

## Step 2: verify the install

```sh
husk --version
husk mcp --selfcheck
```

`husk --version` prints the version. `husk mcp --selfcheck` starts the MCP
server, confirms it can initialize, and reports the local scan cache state. Both
must exit 0 before continuing. If `husk` is not found, the install directory is
not on `PATH`.

## Step 3: register the MCP server

The server is the local subprocess `husk mcp`, speaking MCP over stdio. It takes
no arguments, no environment variables, and no credentials.

### Preferred: let husk write the config

```sh
husk mcp install cursor            # writes ./.cursor/mcp.json
husk mcp install vscode            # writes ./.vscode/mcp.json
husk mcp install gemini            # writes ./.gemini/settings.json
husk mcp install claude-desktop    # writes the Claude Desktop config
husk mcp install codex             # appends [mcp_servers.husk] to ~/.codex/config.toml
husk mcp install opencode          # writes ./opencode.json (mcp.husk)
```

Add `--global` to target the user-level config instead of the project, and
`--dry-run` to print the change without writing. The command is idempotent and
preserves any other content in the file.

Claude Code is not one of these targets; `husk mcp install claude-code` fails.
Use Claude Code's own writer instead, or the plugin, which the user types:

```sh
claude mcp add husk -s user -- husk mcp
```

```text
/plugin marketplace add husk-security/husk
/plugin install husk@husk
```

### Manual: the config shapes

For Cursor (`.cursor/mcp.json`), Claude Desktop (`claude_desktop_config.json`),
and Gemini CLI (`.gemini/settings.json`):

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

VS Code (`.vscode/mcp.json`) uses a different key and requires the type:

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

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.husk]
command = "husk"
args = ["mcp"]
```

OpenCode (`opencode.json`, or `~/.config/opencode/opencode.json` globally):

```json
{
  "mcp": {
    "husk": {
      "type": "local",
      "command": ["husk", "mcp"],
      "enabled": true
    }
  }
}
```

Use an absolute path to the binary instead of `husk` when the client does not
inherit the user's shell `PATH`. Claude Desktop in particular often does not.

If husk was not installed as a binary, replace `"command": "husk", "args":
["mcp"]` with `"command": "npx", "args": ["-y", "husk-sec", "mcp"]` in any of
the shapes above. That is what the bundled plugin manifests use, because they
cannot assume husk is already on `PATH`. It costs an npm resolution on every
start, so prefer the installed binary when there is one.

Claude Code users can skip all of this and install the plugin, which registers
the MCP server and a usage skill:

```
/plugin marketplace add husk-security/husk
/plugin install husk@husk
```

Per-agent notes live under `integrations/` in the repository.

## Step 4: confirm the server is reachable

Restart the client, then confirm the `husk` server is connected and its tools
are listed. The tools are:

| Tool | What it returns |
| --- | --- |
| `husk_status` | Scan cache state and summary counts |
| `husk_findings` | Findings, filterable by severity and category |
| `husk_packages` | Discovered package coordinates by ecosystem |
| `husk_fix` | Available safe remediations |
| `husk_scan` | Runs a scoped scan |
| `husk_policy` | The committed project policy for a path |
| `husk_ledger` | The personal trust ledger history |
| `husk_guide` | The security checklist catalog |
| `husk_guide_update` | Marks a checklist item done or dismissed |

A first scan populates the cache:

```sh
husk scan
```

## Teaching the agent to use husk

The MCP server ships its own `instructions` and a `husk://agent-guide` resource,
which MCP-native clients pick up automatically. For clients that read a project
instruction file instead, append the shared guide:

```sh
cat integrations/husk-agent-guide.md >> AGENTS.md
```

Gemini CLI reads `GEMINI.md` and VS Code Copilot reads
`.github/copilot-instructions.md`; the same content applies.

## Troubleshooting

- `husk: command not found`: the install directory is not on `PATH`. Use the
  absolute path, or run the command the installer printed in step 1.
- The client shows the server as failed: run `husk mcp --selfcheck` directly. It
  reports the reason on stderr. `husk mcp` writes protocol messages to stdout
  only, so anything else on stdout means a wrapper script is interfering.
- Tools return empty results: no scan has run yet. Run `husk scan`, or call
  `husk_scan`.
