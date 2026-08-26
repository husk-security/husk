+++
id = "publish-tokens-at-rest"
category = "Secrets & credentials"
kind = "baseline"
severity = "critical"
control = "publish-tokens-at-rest"
estimate = "20 min"
solution_name = "OS keychain credential providers"
solution_url = "https://doc.rust-lang.org/cargo/reference/registry-authentication.html"
solution_husk = false
related_rules = []
+++

# Keep registry publish tokens off disk

> One stolen file is publish rights to everything you maintain.

Cargo (`~/.cargo/credentials.toml`), PyPI (`~/.pypirc`), RubyGems (`~/.gem/credentials`), and the GitHub CLI (`hosts.yml`) all default to long-lived plaintext tokens. Ultralytics (2024) was hit a second time through a stale, unrevoked PyPI token. Moving releases off tokens entirely is "Publish with OIDC, not a long-lived token".

## Steps

1. Point Cargo at the OS keychain (`cargo:macos-keychain` / `cargo:wincred` on those platforms) in `~/.cargo/config.toml`, then log in again.
   ```command
[registry]
global-credential-providers = ["cargo:libsecret"]
   ```
2. Delete the `password` line from `~/.pypirc`; remove `~/.gem/credentials` unless actively publishing; scope keys on rubygems.org.
3. Re-authenticate the GitHub CLI so the token lands in the system keyring, not `hosts.yml`.
   ```command
gh auth logout && gh auth login
   ```

## Sources

- [Cargo: registry authentication](https://doc.rust-lang.org/cargo/reference/registry-authentication.html)
- [PyPI: Ultralytics attack analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)
