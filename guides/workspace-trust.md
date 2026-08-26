+++
id = "workspace-trust"
category = "Editor & IDE"
kind = "baseline"
severity = "high"
control = "workspace-trust"
estimate = "5 min"
solution_name = "VS Code Workspace Trust"
solution_url = "https://code.visualstudio.com/docs/editing/workspaces/workspace-trust"
solution_husk = false
related_rules = []
+++

# Keep Workspace Trust on and automatic tasks off

> One user setting is all that separates a malicious clone from code execution.

Automatic tasks never run in an untrusted workspace, regardless of any task setting. That guarantee holds only while `security.workspace.trust.enabled` stays on and you do not trust folders reflexively.

## Steps

1. Delete this line from your user `settings.json` if present.
   ```command
"security.workspace.trust.enabled": false
   ```
2. Set automatic tasks to off in the same file.
   ```command
"task.allowAutomaticTasks": "off"
   ```
3. Stay in Restricted Mode on a new clone until you have read `.vscode/`,
   `.devcontainer/`, and any agent config it ships.

## Sources

- [VS Code: Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust)
