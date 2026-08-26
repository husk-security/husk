+++
id = "self-hosted-runner-exposure"
category = "CI/CD & release"
kind = "recommendation"
severity = "high"
control = "self-hosted-runner-exposure"
estimate = "30 min"
solution_name = "Ephemeral runners + strict fork approval"
solution_url = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners"
solution_husk = false
related_rules = ["gha-self-hosted-fork"]
+++

# Keep self-hosted runners away from fork PRs

> A fork PR on a persistent self-hosted runner is code execution on your infrastructure.

The PyTorch takeover (2024) began with a merged typo fix: as a "previous contributor" the attacker's next fork PR ran automatically on persistent runners, yielding a write-scoped token from another job's `.git/config`. The decisive setting is fork-PR approval, which is server-side and invisible to husk.

## Steps

1. Set Settings, Actions, Fork pull request workflows to "Require approval for all outside collaborators".
2. Do not attach self-hosted runners to public repos; where unavoidable, run them ephemeral and isolated.
   ```command
./config.sh --ephemeral
   ```
3. Keep `pull_request` jobs on GitHub-hosted runners; reserve self-hosted for trusted-branch work.

## Sources

- [John Stawinski: PyTorch supply chain attack](https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/)
