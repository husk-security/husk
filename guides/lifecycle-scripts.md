+++
id = "lifecycle-scripts"
category = "Dependencies"
kind = "recommendation"
severity = "medium"
control = "lifecycle-scripts"
estimate = "10 min"
solution_name = "package.json lifecycle script review"
solution_url = "https://docs.npmjs.com/cli/v11/using-npm/scripts"
solution_husk = false
related_rules = ["npm-lifecycle-script"]
+++

# Keep lifecycle scripts out of your own packages

> A preinstall or postinstall in your package runs on every machine that installs it.

The `preinstall`, `install`, `postinstall`, and `prepare` slots are what a compromised publish fills, and what hardened consumers refuse to run.

## Steps

1. Move build work to `prepack` (runs at publish, not install); delete anything fetching or executing remote code.
2. Confirm the finding clears.
   ```command
husk scan
   ```

## Sources

- [npm scripts and lifecycle hooks](https://docs.npmjs.com/cli/v11/using-npm/scripts)
- [Shai-Hulud npm supply chain attack (Wiz)](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
