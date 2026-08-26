+++
id = "workflow-permissions"
category = "CI/CD & release"
kind = "baseline"
severity = "high"
control = "workflow-permissions"
estimate = "10 min"
solution_name = "permissions: contents: read"
solution_url = "https://docs.github.com/en/actions/reference/security/secure-use"
solution_husk = false
related_rules = ["gha-write-all", "gha-missing-permissions"]
+++

# Set least-privilege workflow permissions

> Without a permissions: key the GITHUB_TOKEN inherits the repository default, which is often full write.

Without a `permissions:` key the `GITHUB_TOKEN` inherits the repository default, which is often full write. Every step, including third-party actions and anything an injection reaches, holds those scopes: pushing commits, editing releases, approving PRs. `write-all` is the loud version; declaring nothing is the common one.

## Steps

1. Add a top-level read-only default to every workflow.
   ```command
permissions:
  contents: read
   ```
2. Grant extra scopes per job, only where used (`id-token: write` in the publish job, `pull-requests: write` for a commenter).
3. Set the repository default (Settings, Actions, Workflow permissions) to "Read repository contents" so a forgotten key fails safe.

## Sources

- [GitHub Docs: Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [OpenSSF Scorecard: Token-Permissions](https://github.com/ossf/scorecard/blob/main/docs/checks.md#token-permissions)
