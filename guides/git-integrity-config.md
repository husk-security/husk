+++
id = "git-integrity-config"
category = "Source control"
kind = "baseline"
severity = "low"
control = "git-integrity-config"
estimate = "5 min"
solution_name = "git config --global"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Turn on git object integrity checking

> Without fsckObjects, git stores malformed objects and malicious .gitmodules files without complaint.

All three fsck scopes (`transfer`, `fetch`, `receive`) default to false, so git stores malformed objects and malicious `.gitmodules` files without complaint. Setting `transfer.fsckObjects` covers fetch and receive at once. `http.sslVerify false`, a remote on `http://` or `git://`, and a `user:token@` credential in a remote URL fail the same check.

## Steps

1. Enable integrity checking for all transfers.
   ```command
git config --global transfer.fsckObjects true
   ```
2. Remove both wildcard overrides; they re-open CVE-2022-39253 and CVE-2022-24765. List specific directories instead.
   ```command
git config --global --unset-all protocol.file.allow
git config --global --unset-all safe.directory
   ```
3. Move credentials from remote URLs into a helper, then rotate the token.

## Sources

- [GitHub: git security vulnerabilities announced](https://github.blog/open-source/git/git-security-vulnerabilities-announced/)
