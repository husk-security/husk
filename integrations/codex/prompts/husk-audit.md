Audit this machine and the current project with the husk security scanner.

1. If the husk MCP server is connected, call `husk_status`; otherwise run
   `husk status --json`. If there is no cached scan, run a scoped scan of the
   current project (`husk_scan` with the project path, or
   `husk ci --offline . --no-home-inventory`).
2. List critical and high findings with their paths and recommendations.
3. Check `husk_guide` (or the report's `guidance`) for evidence-backed open
   baseline and recommendation items relevant to this project.
4. Do not change any files yet; report what you found and ask which fixes to
   apply.
