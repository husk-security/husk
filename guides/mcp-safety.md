+++
id = "mcp-safety"
category = "AI agents & MCP"
kind = "baseline"
severity = "high"
control = "mcp-safety"
estimate = "10 min"
solution_name = "Husk scan (MCP configs)"
solution_url = ""
solution_husk = true
related_rules = ["mcp-shell-wrapper", "mcp-plaintext-http", "mcp-root-fs", "mcp-hardcoded-secret"]
+++

# Review every MCP server entry

> An MCP server entry is a command your machine runs with your privileges on every agent start.

Four shapes in a config are risky: a shell-wrapped launch (`sh -c`, `&&`, pipes), a remote server over plaintext `http://`, a filesystem server scoped to `/` or `~`, and a pasted token. Tool descriptions arrive over `tools/list` at runtime and never touch disk, so a clean config does not clear a malicious server.

## Steps

1. Review every flagged entry.
   ```command
husk scan
   ```
2. Launch servers as a direct binary with args, not through a shell; use `https://` or loopback only; scope filesystem servers to the project directory.
3. Move inline tokens to an environment variable or keychain; delete servers you do not recognize.

## Sources

- [MCP specification 2025-11-25: security best practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)
