+++
id = "signed-commits"
category = "Source control"
kind = "recommendation"
severity = "low"
control = "signed-commits"
estimate = "15 min"
solution_name = "SSH commit signing (git 2.34+)"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Sign commits so authorship is verifiable

> Anyone can commit under your name; a signature is the local proof it was you.

Provenance, not prevention: a compromised account signs happily. A non-standard `gpg.program` is a persistence mechanism, not a signing setup. Vigilant mode and required-signature rulesets are server-side, invisible to husk.

## Steps

1. Sign with your existing SSH key.
   ```command
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
   ```
2. Point `gpg.ssh.allowedSignersFile` at an `email pubkey` list and upload the key to GitHub as a Signing Key.

## Sources

- [GitHub: about commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
