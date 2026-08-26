+++
id = "cloud-synced-projects"
category = "Local environment"
kind = "recommendation"
severity = "medium"
control = "cloud-synced-projects"
estimate = "10 min"
solution_name = "Project trees outside synced folders"
solution_url = ""
solution_husk = false
related_rules = ["secret-exposed", "dotenv-untracked"]
+++

# Keep project trees out of cloud-synced folders

> Everything in a synced tree, untracked files included, uploads the moment it is written.

A `.env` there is already on a third party's servers and in their version history. On macOS, iCloud can redirect Desktop and Documents, so a project you never put in a sync folder can still be syncing.

## Steps

1. Re-clone outside the synced area, or use the provider's ignore mechanism.
   ```command
git clone <url> ~/code/proj && rm -rf ~/Dropbox/proj
   ```
2. Rotate the secret and purge the provider's version history; local deletion keeps old versions.

## Sources

- [Dropbox: ignored files](https://help.dropbox.com/sync/ignored-files)
