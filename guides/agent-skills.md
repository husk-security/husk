+++
id = "agent-skills"
category = "AI agents & MCP"
kind = "recommendation"
severity = "high"
control = "agent-skills"
estimate = "15 min"
solution_name = "Husk scan (installed skills and plugins)"
solution_url = ""
solution_husk = true
related_rules = []
+++

# Audit installed agent skills and plugins

> Snyk found critical issues in 13.4% of 3,984 published skills; the payload is never in the manifest.

A skill is code your agent runs under a consent you gave once. The payload is never in the `SKILL.md`: it points at a bundled `.sh`, `.py`, or `.js` that fetches a script or pipes base64 into bash.

## Steps

1. Scan what is installed.
   ```command
husk scan
   ```
2. Delete anything you do not recognize; for the rest, read the scripts `SKILL.md` invokes, not just the markdown.
3. Re-review after every update: an approved skill keeps its permissions when its code changes.

## Sources

- [Snyk: the ClawHub malicious skills campaign](https://snyk.io/articles/clawdhub-malicious-campaign-ai-agent-skills/)
- [Snyk: ToxicSkills audit](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)
