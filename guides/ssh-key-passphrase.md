+++
id = "ssh-key-passphrase"
category = "Source control"
kind = "baseline"
severity = "high"
control = "ssh-key-passphrase"
estimate = "5 min"
solution_name = "ssh-keygen -p"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Put a passphrase on every SSH private key

> An unencrypted private key is a portable credential: whoever copies the file has your access.

To check a key by hand, derive its public half: an encrypted key prompts for its passphrase, an unencrypted one does not. Do not infer encryption by grepping the armored file.

## Steps

1. Encrypt in place; the public key is unchanged.
   ```command
ssh-keygen -p -a 100 -f ~/.ssh/id_ed25519
   ```
2. Load into the agent with a timeout.
   ```command
ssh-add -t 1h ~/.ssh/id_ed25519
   ```

## Sources

- [OpenSSH PROTOCOL.key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)
