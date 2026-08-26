+++
id = "secrets-out-of-code"
category = "Secrets & credentials"
kind = "baseline"
severity = "critical"
control = "secrets-out-of-code"
scope = "project"
estimate = "15 min"
solution_name = "husk scan / husk fix"
solution_url = ""
solution_husk = true
related_rules = ["secret-exposed", "dotenv-untracked"]
+++

# Keep secrets out of source code

> A committed key stays in every clone and every fork, forever.

Deleting the line, or rewriting history, only hides the old value. Rotation is what protects you, because every clone and fork made before the deletion still has it.

## Steps

1. Find them.
   ```command
husk scan
   ```
2. Gitignore secret files and move values into the environment; `husk fix --apply` writes the gitignore and a value-free `.env.template`, never source rewrites.
   ```command
printf '.env\n.env.*\n*.pem\n*.key\n' >> .gitignore
   ```
   ```command
husk fix --apply
   ```
3. Rotate anything ever committed, then work the git-history item.

## Sources

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Sourcegraph security update, August 2023](https://sourcegraph.com/blog/security-update-august-2023)
