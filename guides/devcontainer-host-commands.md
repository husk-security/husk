+++
id = "devcontainer-host-commands"
category = "Editor & IDE"
kind = "baseline"
severity = "high"
control = "devcontainer-host-commands"
estimate = "5 min"
solution_name = "Dev Container lifecycle reference"
solution_url = "https://containers.dev/implementors/json_reference/"
solution_husk = false
related_rules = ["devcontainer-host-command"]
+++

# Check devcontainer.json for host commands

> initializeCommand executes on your machine, not in the container.

The spec runs `initializeCommand` before any container exists, so container isolation does not apply: a cloned repo's `.devcontainer/devcontainer.json` is host code execution in a file shaped like sandbox config. `onCreateCommand` and `postCreateCommand` do run inside the container, but they run automatically and can fetch and execute anything.

## Steps

1. Scan for `initializeCommand`, and for create commands that fetch, decode, or
   eval.
   ```command
husk scan
   ```
2. Read `.devcontainer/devcontainer.json` before reopening a cloned repo, as you
   would a shell script.
3. Remove any `initializeCommand` you did not write; run needed host-side
   setup by hand where you can see it.

## Sources

- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
