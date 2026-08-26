+++
id = "pin-actions"
category = "CI/CD & release"
kind = "baseline"
severity = "high"
control = "pin-actions"
estimate = "15 min per repo"
solution_name = "pinact (rewrites tags to SHAs)"
solution_url = "https://github.com/suzuki-shunsuke/pinact"
solution_husk = false
related_rules = ["gha-unpinned-action"]
+++

# Pin every action to a full commit SHA

> A version tag is a movable pointer; moving it was the entire tj-actions attack.

In March 2025 every `tj-actions/changed-files` tag, v1.0.0 through v45.0.7, was repointed at one commit that scraped the runner's memory for secrets and printed them into the public build log; about 23,000 repos ran it without changing a line. A SHA pin is the only immutable reference.

## Steps

1. Pin each third-party action to its 40-character commit SHA, version as a comment.
   ```command
uses: actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955 # v5.0.0
   ```
2. Rewrite a whole repo's tags to SHAs in one pass.
   ```command
pinact run
   ```
3. Add `github-actions` to Dependabot or Renovate so pins update through reviewable PRs.

## Sources

- [StepSecurity: tj-actions/changed-files compromised](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised)
- [GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)
