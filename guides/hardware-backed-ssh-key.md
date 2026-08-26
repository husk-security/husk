+++
id = "hardware-backed-ssh-key"
category = "Source control"
kind = "recommendation"
severity = "medium"
control = "hardware-backed-ssh-key"
estimate = "15 min"
solution_name = "ssh-keygen ed25519-sk (FIDO2)"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Move SSH to a hardware-backed key

> A FIDO2 key signs only on touch; malware that copies your files still cannot authenticate.

`sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` are hardware backed; plain `ssh-ed25519` is sound software; `ssh-rsa`, `ssh-dss`, and `ecdsa-sha2-*` are weak. A key generated `no-touch-required` loses the physical presence that makes it phishing resistant.

## Steps

1. Generate a resident key requiring PIN plus touch (OpenSSH 8.2+).
   ```command
ssh-keygen -t ed25519-sk -O resident -O verify-required
   ```
2. Register the new `.pub` with GitHub and your servers, remove old public keys from every `authorized_keys` and account, and delete the old private keys.

## Sources

- [Yubico: Securing SSH with FIDO2](https://developers.yubico.com/SSH/Securing_SSH_with_FIDO2.html)
