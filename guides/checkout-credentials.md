+++
id = "checkout-credentials"
category = "CI/CD & release"
kind = "baseline"
severity = "medium"
control = "checkout-credentials"
estimate = "10 min"
solution_name = "persist-credentials: false"
solution_url = "https://docs.zizmor.sh/audits/#artipacked"
solution_husk = false
related_rules = ["gha-persist-credentials"]
+++

# Stop checkout persisting the workflow token

> actions/checkout writes the GITHUB_TOKEN into .git/config by default, where any later step or uploaded artifact can read it.

A job that uploads its checkout directory as an artifact publishes a live token, and Artifacts v4 are downloadable while the job is still running. The persisted token is also what post-checkout third-party code reads first.

## Steps

1. Disable persistence on every checkout.
   ```command
- uses: actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955 # v5.0.0
  with:
    persist-credentials: false
   ```
2. Never upload the workspace wholesale: no `path: .` or `path: ${{ github.workspace }}` on `actions/upload-artifact`; name the files you mean.
3. Give a step that must push its own credential in that step's `env:`, not via `.git/config`.

## Sources

- [Unit 42: ArtiPACKED, GitHub artifacts leak tokens](https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/)
- [zizmor: artipacked audit](https://docs.zizmor.sh/audits/#artipacked)
