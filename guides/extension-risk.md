+++
id = "extension-risk"
category = "Editor & IDE"
kind = "baseline"
severity = "medium"
control = "extension-risk"
estimate = "10 min"
solution_name = "husk extension findings"
solution_url = ""
solution_husk = true
related_rules = ["extension-broad-activation", "extension-install-script", "editor-tooling-repoint"]
+++

# Review flagged editor extensions

> A verified extension with millions of installs can turn malicious in one update.

A verified publisher with 2.2M installs is not a signal: Nx Console v18.95.0 (CVE-2026-48027) was malicious and live for about 18 minutes. Behaviour is: activation on `*` or `onStartupFinished`, an install script, and workspace settings that repoint your interpreter, a tool binary, or terminal environment at repo files.

## Steps

1. Scan and open the extension findings.
   ```command
husk scan
   ```
2. Uninstall flagged extensions you do not use; for the rest, confirm the
   activation events and install scripts match what the extension is for.

## Sources

- [CVE-2026-48027 (Nx Console)](https://nvd.nist.gov/vuln/detail/CVE-2026-48027)
