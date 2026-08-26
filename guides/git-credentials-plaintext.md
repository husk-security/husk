+++
id = "git-credentials-plaintext"
category = "Secrets & credentials"
kind = "baseline"
severity = "critical"
control = "git-credentials-plaintext"
estimate = "10 min"
solution_name = "Platform keychain credential helper"
solution_url = "https://git-scm.com/doc/credential-helpers"
solution_husk = false
related_rules = []
+++

# Stop git storing passwords in plaintext

> credential.helper store writes every git password unencrypted to disk.

`git-credential-store` keeps one `https://user:token@host` line per remote in `~/.git-credentials`, protected only by filesystem permissions. `~/.netrc` is the same for older tooling.

## Steps

1. Check what is configured and where.
   ```command
git config --show-origin --get-all credential.helper
   ```
2. Switch to the keychain helper (`osxkeychain` on macOS, `manager` on Windows).
   ```command
git config --global credential.helper libsecret
   ```
3. Delete the plaintext stores and rotate the tokens they held.
   ```command
rm -f ~/.git-credentials ~/.config/git/credentials
   ```

## Sources

- [git-credential-store(1)](https://git-scm.com/docs/git-credential-store)
