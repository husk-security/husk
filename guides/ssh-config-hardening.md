+++
id = "ssh-config-hardening"
category = "Source control"
kind = "baseline"
severity = "high"
control = "ssh-config-hardening"
estimate = "5 min"
solution_name = "OpenSSH client configuration"
solution_url = "https://man.openbsd.org/ssh_config"
solution_husk = false
related_rules = []
+++

# Remove unsafe directives from ~/.ssh/config

> One config line can accept a MITM host key or hand your agent to every server you touch.

`StrictHostKeyChecking no`, `UserKnownHostsFile /dev/null`, and `CheckHostIP no` accept unknown and changed host keys. `ForwardAgent yes` lets anyone reaching the agent socket on the remote host sign with your local keys. `PermitLocalCommand` with `LocalCommand` makes the config itself run a command on connect. `ForwardX11Trusted yes` belongs in the same list.

## Steps

1. Accept new hosts but still reject changed keys.
   ```command
StrictHostKeyChecking accept-new
   ```
2. Delete `ForwardAgent yes`, especially under `Host *`; multi-hop wants `ProxyJump`, no agent on the intermediate host.
3. Delete any `PermitLocalCommand` or `LocalCommand` line you did not write.

## Sources

- [ssh_config(5)](https://man.openbsd.org/ssh_config)
