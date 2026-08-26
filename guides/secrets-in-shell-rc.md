+++
id = "secrets-in-shell-rc"
category = "Secrets & credentials"
kind = "baseline"
severity = "high"
control = "secrets-in-shell-rc"
estimate = "15 min"
solution_name = "Runtime injection (op run) + HISTCONTROL"
solution_url = "https://developer.1password.com/docs/cli/secrets-environment-variables/"
solution_husk = false
related_rules = []
+++

# Keep secrets out of shell rc files and history

> An exported secret lands in every child process's environment and in /proc/<pid>/environ.

An `export API_KEY=...` in `.bashrc` is readable from every child process's environment and from `/proc/<pid>/environ`. Fish's `set -Ux` persists values to `~/.config/fish/fish_variables` in plaintext. Inline secrets also live on in history files, which get backed up and synced.

## Steps

1. Look for exported values.
   ```command
grep -nE "(KEY|TOKEN|SECRET|PASSWORD)=" ~/.bashrc ~/.zshrc ~/.config/fish/fish_variables 2>/dev/null
   ```
2. Move each value into a manager and inject per command, not per shell.
   ```command
op run --env-file=.env -- npm run dev
   ```
3. Set `HISTCONTROL=ignorespace` so a leading space skips recording; delete the lines, clear those history entries, and rotate the values.

## Sources

- [bash(1): HISTCONTROL](https://man7.org/linux/man-pages/man1/bash.1.html)
- [fish: universal variables](https://fishshell.com/docs/current/language.html#variables-universal)
- [Wiz: the Nx s1ngularity supply chain attack](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)
