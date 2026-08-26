+++
id = "dependency-updates"
category = "Dependencies"
kind = "recommendation"
severity = "medium"
control = "dependency-updates"
estimate = "15 min"
solution_name = "Dependabot or Renovate, with a cooldown"
solution_url = "https://docs.github.com/en/code-security/dependabot"
solution_husk = false
related_rules = []
+++

# Automate dependency updates

> Known-vulnerable is the default state of software left alone.

Dependabot or Renovate turns upgrades into small reviewable PRs. Give the bot the same release-age cooldown as your installs, or update PRs become a fast lane around it.

## Steps

1. Commit `.github/dependabot.yml` with an entry per ecosystem and `cooldown: default-days: 7` under each.
2. Or Renovate: `"minimumReleaseAge": "7 days"` in `renovate.json`.

## Sources

- [Dependabot version updates](https://docs.github.com/en/code-security/dependabot)
