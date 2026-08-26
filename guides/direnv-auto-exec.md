+++
id = "direnv-auto-exec"
category = "Local environment"
kind = "baseline"
severity = "high"
control = "direnv-auto-exec"
estimate = "5 min"
solution_name = "direnv allow list review"
solution_url = "https://direnv.net/man/direnv.1.html"
solution_husk = false
related_rules = []
+++

# Review the .envrc files you have allowed

> An allowed .envrc is arbitrary shell that direnv executes every time you enter the directory.

`direnv allow` records one file per approved `.envrc` under `~/.local/share/direnv/allow/`. An approval is standing permission to run that shell script every time you `cd` in; a benign one is still an execution surface.

## Steps

1. List approvals.
   ```command
cat ~/.local/share/direnv/allow/*
   ```
2. Read a repo's `.envrc` as the shell script it is before allowing; revoke with `direnv deny <dir>`.
3. Editing an allowed file re-triggers the prompt; a prompt you did not cause means read the diff first.

## Sources

- [direnv manual](https://direnv.net/man/direnv.1.html)
