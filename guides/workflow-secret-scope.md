+++
id = "workflow-secret-scope"
category = "CI/CD & release"
kind = "baseline"
severity = "high"
control = "workflow-secret-scope"
estimate = "15 min"
solution_name = "Named per-secret passing"
solution_url = "https://docs.zizmor.sh/audits/#secrets-inherit"
solution_husk = false
related_rules = ["gha-secrets-inherit"]
+++

# Pass secrets by name, never the whole context

> secrets: inherit or toJSON(secrets) hands every repository secret to code you did not write.

Supply-chain worms have committed a workflow file into every repo their stolen tokens could reach, exfiltrating `${{ toJSON(secrets) }}` on push. In reusable workflows, `secrets: inherit` gives a compromised callee everything the caller has.

## Steps

1. Replace `secrets: inherit` in reusable-workflow calls with the individual secrets the callee needs.
   ```command
secrets:
  npm-token: ${{ secrets.NPM_TOKEN }}
   ```
2. Remove `toJSON(secrets)` and bare `${{ secrets }}` from every `env:` block; reference `secrets.NAME` per step.
3. Audit `.github/workflows/` for files you did not author; a workflow nobody on the team added is an indicator of compromise.

## Sources

- [Unit 42: npm supply chain attack (Shai-Hulud)](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [zizmor: secrets-inherit audit](https://docs.zizmor.sh/audits/#secrets-inherit)
