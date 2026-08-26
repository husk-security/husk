+++
id = "git-template-hijack"
category = "Source control"
kind = "baseline"
severity = "critical"
control = "git-template-hijack"
estimate = "5 min"
solution_name = "git config --global --unset"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Check global git config for planted hooks

> A hijacked init.templateDir re-infects the machine on every future git init and clone.

A global `init.templateDir` makes git copy that directory's hooks into every repo you create or clone, so cleaning your repos does not remove it. A global `core.hooksPath` is the same persistence without the copy step.

## Steps

1. Print both keys; expect no output.
   ```command
git config --global --get init.templateDir
git config --global --get core.hooksPath
   ```
2. If set, read the hooks to learn what ran, then remove the key.
   ```command
git config --global --unset init.templateDir
   ```

## Sources

- [Socket: SANDWORM_MODE](https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning)
