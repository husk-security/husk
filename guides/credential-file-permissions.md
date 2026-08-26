+++
id = "credential-file-permissions"
category = "Secrets & credentials"
kind = "baseline"
severity = "medium"
control = "credential-file-permissions"
estimate = "5 min"
solution_name = "chmod 600 on credential files"
solution_url = "https://docs.npmjs.com/cli/v11/configuring-npm/npmrc"
solution_husk = false
related_rules = []
+++

# Make credential files readable only by you

> A group- or world-readable credential file is open to every other account and process on the machine.

`~/.npmrc`, `~/.aws/credentials`, `~/.kube/config`, the AI agent token stores (`~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`), and project `.env` files should be mode `600`. Almost nothing warns you otherwise; npm alone documents a required mode.

## Steps

1. List the usual suspects.
   ```command
ls -l ~/.npmrc ~/.aws/credentials ~/.kube/config ~/.netrc ~/.docker/config.json ~/.claude/.credentials.json ~/.codex/auth.json ~/.gemini/oauth_creds.json 2>/dev/null
   ```
2. Tighten each file, its parent directory, and project `.env` files.
   ```command
chmod 600 ~/.npmrc ~/.claude/.credentials.json ~/.codex/auth.json 2>/dev/null; chmod 700 ~/.aws ~/.kube
find . -maxdepth 2 -name ".env*" -type f -exec chmod 600 {} +
   ```

## Sources

- [npm docs: npmrc file security](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc)
