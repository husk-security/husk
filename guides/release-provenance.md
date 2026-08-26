+++
id = "release-provenance"
category = "CI/CD & release"
kind = "baseline"
severity = "high"
control = "release-provenance"
estimate = "30 min"
solution_name = "OIDC trusted publishing + provenance"
solution_url = "https://docs.npmjs.com/trusted-publishers/"
solution_husk = false
related_rules = ["gha-publish-token", "gha-cache-in-publish"]
+++

# Publish with OIDC, not a long-lived token

> A stored registry token publishes for whoever steals it.

Adopting OIDC changes nothing until the legacy tokens are revoked: Ultralytics (2024) shipped a second malicious PyPI wave on a stale token that predated its Trusted Publishing adoption. Husk reads the publishing workflow; it cannot see the registry's Trusted Publisher registration.

## Steps

1. Register the publishing workflow as a Trusted Publisher (npm, PyPI, crates.io) and grant it OIDC permissions.
   ```command
permissions:
  id-token: write
  contents: read
   ```
2. Revoke every stored registry token (`NPM_TOKEN`, `PYPI_API_TOKEN`, `CARGO_REGISTRY_TOKEN`); npm needs CLI >= 11.5.1 for OIDC.
3. Publish with `npm publish --provenance` and disable caching in the publish job: cache poisoning has produced valid SLSA Build L3 provenance (CVE-2026-45321).

## Sources

- [npm Docs: Trusted publishing](https://docs.npmjs.com/trusted-publishers/)
- [PyPI Docs: Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
