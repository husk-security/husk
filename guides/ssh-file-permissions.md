+++
id = "ssh-file-permissions"
category = "Source control"
kind = "baseline"
severity = "medium"
control = "ssh-file-permissions"
estimate = "2 min"
solution_name = "chmod"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Lock down ~/.ssh file permissions

> A writable ssh config is command injection; a readable private key is credential theft.

A writable config lets any local user or process plant a `ProxyCommand` that executes on your next connection. OpenSSH refuses a private key readable by others, which presents as "my key stopped working" rather than a warning.

## Steps

1. Restore owner-only modes.
   ```command
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_* ~/.ssh/config
   ```
2. Public keys and `known_hosts` can stay world readable.

## Sources

- [ssh(1), FILES](https://man.openbsd.org/ssh#FILES)
