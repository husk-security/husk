+++
id = "agent-version-pins"
category = "AI agents & MCP"
kind = "baseline"
severity = "high"
control = "agent-version-pins"
estimate = "10 min"
solution_name = "Exact-version pins (npx @x.y.z / uvx ==x.y.z)"
solution_url = ""
solution_husk = false
related_rules = ["mcp-unpinned-npx"]
+++

# Pin MCP server versions

> postmark-mcp shipped 15 clean versions, then v1.0.16 BCC'd every email to the attacker.

`npx -y <pkg>` in an MCP config fetches and runs the latest published version on every agent start; every unpinned config picked up the postmark-mcp backdoor on its next restart. An exact pin turns a rug-pull into an update you review.

## Steps

1. Find the floating entries.
   ```command
husk scan
   ```
2. Append an exact version to each npm-based server, e.g. `"args": ["-y", "@modelcontextprotocol/server-filesystem@2026.6.1"]`. No `@latest`, no ranges.
3. Pin Python servers the same way.
   ```command
uvx --from mcp-server-git==0.6.2 mcp-server-git
   ```
4. Before bumping a pin, check the new version first.
   ```command
husk check npm <package> <version>
   ```

## Sources

- [Koi: the postmark-mcp backdoor](https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft)
