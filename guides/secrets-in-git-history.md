+++
id = "secrets-in-git-history"
category = "Secrets & credentials"
kind = "baseline"
severity = "critical"
control = "secrets-in-git-history"
estimate = "30 min"
solution_name = "git-filter-repo"
solution_url = "https://github.com/newren/git-filter-repo"
solution_husk = false
related_rules = []
+++

# Rotate secrets that are in git history

> Deleting a secret from the worktree leaves it readable in every past commit.

Rotation is what protects you; rewriting history is only cleanup, because old clones, forks, and mirrors keep the value. The Internet Archive (2024) was breached again weeks after a leak because its tokens were never rotated.

## Steps

1. Rotate every committed credential at the provider. Do this first.
2. Put `OLDVALUE==>REDACTED` lines in `replacements.txt`, rewrite, force-push, and have collaborators re-clone.
   ```command
git filter-repo --replace-text replacements.txt
git push --force --all --tags
   ```
3. On GitHub, ask support to purge cached views and check forks; the rewrite does not reach them.

## Sources

- [GitHub: Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [Internet Archive breached again through stolen access tokens](https://www.bleepingcomputer.com/news/security/internet-archive-breached-again-through-stolen-access-tokens/)
