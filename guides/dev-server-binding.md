+++
id = "dev-server-binding"
category = "Local environment"
kind = "baseline"
severity = "medium"
control = "dev-server-binding"
estimate = "5 min"
solution_name = "Bind 127.0.0.1 (drop --host)"
solution_url = ""
solution_husk = false
related_rules = ["dev-server-all-interfaces"]
+++

# Bind dev servers to 127.0.0.1

> A dev server on 0.0.0.0 serves unauthenticated code execution to everyone on the coffee-shop network.

MCP Inspector (CVE-2025-49596) listened on `0.0.0.0:6277` with no auth; with DNS rebinding, any website you visited got RCE. In a `package.json` script a bare `--host` means all interfaces, not localhost.

## Steps

1. Delete `--host` from dev scripts and `host:` from `vite.config.*`; the default is loopback.
2. Remove or rebind `OLLAMA_HOST` in the shell rc.
   ```command
export OLLAMA_HOST=127.0.0.1:11434
   ```
3. Bind wide only for a device test; a tunnel is public until its process dies.

## Sources

- [Oligo: MCP Inspector RCE (CVE-2025-49596)](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596)
