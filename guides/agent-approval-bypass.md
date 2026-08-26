+++
id = "agent-approval-bypass"
category = "AI agents & MCP"
kind = "baseline"
severity = "critical"
control = "agent-approval-bypass"
estimate = "5 min"
solution_name = "Remove bypass modes and persisted skip-permissions flags"
solution_url = "https://code.claude.com/docs/en/permissions"
solution_husk = false
related_rules = ["agent-permission-bypass"]
+++

# Never persist an approval bypass

> Nx s1ngularity (Aug 2025) drove developers' own AI CLIs with skip-permissions flags and stole 2,349 credentials from 1,079 machines.

The approval prompt is the last control before an injected instruction executes. Three configurations remove it: `permissions.defaultMode: "bypassPermissions"` in a Claude settings file; `approval_policy = "never"` with `sandbox_mode = "danger-full-access"` in `~/.codex/config.toml`; and `--dangerously-skip-permissions`, `--yolo`, or `--trust-all-tools` persisted in a shell alias or Makefile.

## Steps

1. Scan agent settings, the Codex config, shell rc files, and Makefiles.
   ```command
husk scan
   ```
2. Delete the `defaultMode` line and both Codex keys; remove the flags from aliases and Makefiles.
3. For unattended runs, use a container or VM with no real credentials mounted.

## Sources

- [Wiz: the Nx s1ngularity attack](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)
