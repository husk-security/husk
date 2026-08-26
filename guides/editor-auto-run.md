+++
id = "editor-auto-run"
category = "Editor & IDE"
kind = "baseline"
severity = "critical"
control = "editor-auto-run"
estimate = "5 min"
solution_name = "VS Code task.allowAutomaticTasks"
solution_url = "https://code.visualstudio.com/docs/debugtest/tasks"
solution_husk = false
related_rules = ["editor-auto-run-task"]
+++

# Stop the editor running tasks on folder open

> A cloned repo can execute a shell command the moment you open the folder.

A `.vscode/tasks.json` task with `"runOn": "folderOpen"` is the mechanism, and `"hide": true` with a `"presentation"` block makes it show nothing. Hijacked npm packages have planted one with the payload disguised as a `.woff2` font. JetBrains has an equivalent in `options/trusted-paths.xml`; husk does not read it.

## Steps

1. Scan for folderOpen tasks.
   ```command
husk scan
   ```
2. Turn automatic tasks off in your user `settings.json`.
   ```command
"task.allowAutomaticTasks": "off"
   ```

## Sources

- [JFrog: hijacked npm packages planting VS Code tasks](https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/)
- [VS Code: Tasks, runOptions](https://code.visualstudio.com/docs/debugtest/tasks)
