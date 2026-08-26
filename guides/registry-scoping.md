+++
id = "registry-scoping"
category = "Dependencies"
kind = "baseline"
severity = "high"
control = "registry-scoping"
estimate = "10 min"
solution_name = "Single trusted index + scoped registries"
solution_url = "https://pip.pypa.io/en/stable/cli/pip_install/"
solution_husk = false
related_rules = []
+++

# Scope registries to a single trusted index

> One extra package index lets a public package shadow every internal name you install.

pip's own documentation calls `--extra-index-url` unsafe: all indexes are equal candidates (dependency confusion). torchtriton (2022) outranked PyTorch's own nightly index this way. A corporate mirror proxying the public index is fine as the single index, https only.

## Steps

1. pip: one `index-url`, never `extra-index-url`.
   ```command
pip config set global.index-url https://mirror.example.com/simple
   ```
2. npm: leave `registry` alone; scope private packages in `.npmrc`: `@yourorg:registry=https://npm.example.com`.
3. Confirm `[source.crates-io] replace-with` in `.cargo/config.toml` and `GOPROXY` in `~/.config/go/env` point only where you expect, never at `http://`.

## Sources

- [pip install: extra-index-url is unsafe (dependency confusion)](https://pip.pypa.io/en/stable/cli/pip_install/)
- [PyTorch torchtriton compromise postmortem](https://pytorch.org/blog/compromised-nightly-dependency/)
