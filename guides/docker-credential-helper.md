+++
id = "docker-credential-helper"
category = "Secrets & credentials"
kind = "baseline"
severity = "high"
control = "docker-credential-helper"
estimate = "10 min"
solution_name = "docker-credential-helpers"
solution_url = "https://github.com/docker/docker-credential-helpers"
solution_husk = false
related_rules = []
+++

# Move docker login into a credential helper

> The auth entries in ~/.docker/config.json base64-decode straight to user:password.

Without a helper, `docker login` saves each registry login to `~/.docker/config.json` as a base64 `auth` value, which decodes straight back to user and password. That token is push access to your images.

## Steps

1. Check the current state.
   ```command
jq '{auths: .auths | keys, credsStore, credHelpers}' ~/.docker/config.json
   ```
2. Install docker-credential-helpers and point config.json at your keychain (`osxkeychain` on macOS, `wincred` on Windows, `pass` for headless Linux), then log out and back in.
   ```command
"credsStore": "secretservice"
   ```
   ```command
docker logout && docker login
   ```
3. Rotate any registry token that sat in the file; treat it as read.

## Sources

- [docker login: credential stores](https://docs.docker.com/reference/cli/docker/login/)
- [docker/docker-credential-helpers](https://github.com/docker/docker-credential-helpers)
