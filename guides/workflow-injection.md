+++
id = "workflow-injection"
category = "CI/CD & release"
kind = "baseline"
severity = "critical"
control = "workflow-injection"
estimate = "20 min"
solution_name = "env: indirection + pull_request trigger"
solution_url = "https://securitylab.github.com/resources/github-actions-untrusted-input/"
solution_husk = false
related_rules = ["gha-pull-request-target", "gha-event-injection", "gha-curl-shell"]
+++

# Keep untrusted input out of run: blocks

> GitHub substitutes `${{ }}` into the shell script before it runs, so a PR title or branch name becomes command injection.

GitHub substitutes `${{ }}` into the shell script before it runs, so any attacker-controllable field (`github.event.*`, `github.head_ref`) in a `run:` block executes as code. `pull_request_target` escalates it: the workflow holds base-repo secrets while a `ref:` on the PR head checks out fork code.

## Steps

1. Bind untrusted fields to `env:` and reference them as quoted shell variables.
   ```command
env:
  TITLE: ${{ github.event.pull_request.title }}
run: echo "$TITLE"
   ```
2. Use `pull_request` for fork code; run privileged follow-ups in a separate `workflow_run` stage with no head checkout.
3. Replace `curl | bash` with download, checksum verify, then execute.

## Sources

- [GitHub Security Lab: Untrusted input in Actions](https://securitylab.github.com/resources/github-actions-untrusted-input/)
- [GitHub Security Lab: Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
