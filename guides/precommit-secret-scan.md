+++
id = "precommit-secret-scan"
category = "Secrets & credentials"
kind = "recommendation"
severity = "medium"
control = "precommit-secret-scan"
estimate = "10 min"
solution_name = "gitleaks via the pre-commit framework"
solution_url = "https://github.com/gitleaks/gitleaks"
solution_husk = false
related_rules = []
+++

# Block secrets at commit time

> A pushed secret is scraped from a public repo within minutes; a hook stops it one step earlier.

After the push, rotation is the only fix. Sourcegraph (2023) merged a live site-admin token in a PR that review and automation both missed. Installing the scanner binary is not the control; the hook installed in each repo is.

## Steps

1. Declare the gitleaks hook, pinning `rev` to a full commit SHA (a tag can be moved).
   ```command
cat > .pre-commit-config.yaml <<'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: <full-commit-sha>
    hooks:
      - id: gitleaks
EOF
   ```
2. Install it into `.git/hooks/pre-commit`, then scan existing history once.
   ```command
pre-commit install
gitleaks git -v .
   ```
3. On a real find, rotate first, then work the git-history item.

## Sources

- [gitleaks](https://github.com/gitleaks/gitleaks)
- [Sourcegraph security update, August 2023](https://sourcegraph.com/blog/security-update-august-2023)
