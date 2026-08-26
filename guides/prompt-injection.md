+++
id = "prompt-injection"
category = "AI agents & MCP"
kind = "baseline"
severity = "high"
control = "prompt-injection"
estimate = "10 min"
solution_name = "Husk scan (prompt injection)"
solution_url = ""
solution_husk = true
related_rules = ["prompt-injection-phrase", "prompt-hidden-unicode"]
+++

# Check agent instruction files for planted text

> TrapDoor packages plant poisoned CLAUDE.md and .cursorrules files into your own project.

Packages have shipped that write a poisoned `CLAUDE.md` or `.cursorrules` into your project, so the next agent session runs a fake "security scan" that harvests SSH keys and tokens. Husk matches known injection phrases and the hidden characters U+202D, U+202E, U+200B, and U+2060, but not the Unicode Tags block or variation selectors, so a clean scan is not proof.

## Steps

1. Scan, and open anything flagged in an editor that renders control characters.
   ```command
husk scan
   ```
2. Diff `CLAUDE.md`, `AGENTS.md`, and `.cursorrules` in review; delete instruction files you did not create, packages have no business writing them.

## Sources

- [Socket: TrapDoor](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates)
