+++
id = "sshd-exposure"
category = "Machine & identity"
kind = "baseline"
severity = "medium"
control = "sshd-exposure"
estimate = "10 min"
solution_name = "Disable sshd, or key-only with no root login"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Do not run an SSH server on a workstation

> Most developers do not know sshd is listening with a password prompt.

Distributions and remote-development setups enable `sshd` with `PasswordAuthentication yes`, making your laptop a credential-guessing target on every network you join.

## Steps

1. Check what it accepts.
   ```command
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|port'
   ```
2. If unneeded, disable the service rather than firewalling around it.
   ```command
sudo systemctl disable --now sshd
   ```
3. If needed: `PasswordAuthentication no`, `PermitRootLogin no`, `KbdInteractiveAuthentication no`, then restart. Restrict `~/.ssh/authorized_keys` entries with `from="<cidr>"`, and `command="..."` for single-purpose keys.

## Sources

- [sshd_config(5)](https://man.openbsd.org/sshd_config)
- [Mozilla OpenSSH security guidelines](https://infosec.mozilla.org/guidelines/openssh)
