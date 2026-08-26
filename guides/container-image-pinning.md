+++
id = "container-image-pinning"
category = "Local environment"
kind = "baseline"
severity = "medium"
control = "container-image-pinning"
estimate = "10 min per repo"
solution_name = "Digest pins + Renovate pinDigests"
solution_url = "https://docs.renovatebot.com/docker/"
solution_husk = false
related_rules = ["image-unpinned"]
+++

# Pin base images to a digest

> A tag is a mutable reference the publisher can move; only an @sha256 digest pulls the same image every time.

An `@sha256:` digest is the only immutable reference. A tag, including `:latest` and the implicit one, is a pointer the publisher can move at any time.

## Steps

1. Resolve the digest the tag points at.
   ```command
docker buildx imagetools inspect node:22-bookworm
   ```
2. Pin it, keeping the tag for readability.
   ```command
FROM node:22-bookworm@sha256:<digest>
   ```
3. Let Renovate (`docker:pinDigests`) or Dependabot bump the digest as a reviewed PR, so pinned never means frozen.

## Sources

- [Docker build best practices: pin base image versions](https://docs.docker.com/build/building/best-practices/)
