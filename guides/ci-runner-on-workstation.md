+++
id = "ci-runner-on-workstation"
category = "CI/CD & release"
kind = "baseline"
severity = "high"
control = "ci-runner-on-workstation"
estimate = "5 min"
solution_name = "Remove the runner registration"
solution_url = "https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/remove-runners"
solution_husk = false
related_rules = []
+++

# Unregister CI runners on your laptop

> A runner registration turns your machine into remote-code-execution infrastructure for anyone who can trigger a workflow.

Supply-chain worms install a self-hosted runner under your home directory and push a workflow that runs attacker-controlled input on it. The registration survives removing the package that created it.

## Steps

1. Look for runner directories.
   ```command
ls -d ~/actions-runner ~/.dev-env 2>/dev/null
   ```
2. If you did not install it, revoke it under the repo or org Settings, Actions, Runners, then delete the directory without running its scripts.
3. Treat the machine as compromised at install time: rotate npm, GitHub, and cloud credentials that were present.

## Sources

- [Datadog Security Labs: Shai-Hulud 2.0](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
