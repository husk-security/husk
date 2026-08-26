+++
id = "git-client-version"
category = "Source control"
kind = "baseline"
severity = "high"
control = "git-client-version"
estimate = "5 min"
solution_name = "System package manager"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Upgrade git past the clone-RCE fixes

> An old git executes attacker code during the clone itself, before you open anything.

CVE-2024-32002 is code execution during `git clone`, via submodule and symlink confusion on case-insensitive filesystems; CVE-2024-32004 and CVE-2024-32465 cover the same class, including repositories that arrived as a zip. Fixed in 2.45.1 and backported to 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, and 2.44.1.

## Steps

1. Check the installed version.
   ```command
git --version
   ```
2. If below the fix for its line, upgrade (`brew upgrade git`, `apt install git`).

## Sources

- [GitHub: securing Git, addressing 5 new vulnerabilities](https://github.blog/open-source/git/securing-git-addressing-5-new-vulnerabilities/)
