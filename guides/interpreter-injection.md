+++
id = "interpreter-injection"
category = "Local environment"
kind = "baseline"
severity = "high"
control = "interpreter-injection"
estimate = "10 min"
solution_name = "Remove preload hooks"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Remove interpreter preload hooks

> One environment variable or one .pth file runs planted code in every node or python process.

`NODE_OPTIONS=--require x.js` preloads into every node process; `PYTHONSTARTUP` runs a file at REPL start; a `PYTHONPATH` entry inside a repo or world-writable directory resolves imports there first; a `sitecustomize.py` or import-carrying `.pth` file in `site-packages` executes at interpreter start. Husk checks a project's `.venv`, not system-wide `site-packages`.

## Steps

1. Unset anything you did not set.
   ```command
env | grep -E 'NODE_OPTIONS|PYTHONSTARTUP|PYTHONPATH'
   ```
2. `_virtualenv.pth`, `distutils-precedence.pth`, and `easy-install.pth` are standard; any other `.pth` with an `import` line is suspect.
   ```command
ls .venv/lib/python*/site-packages/ | grep -E '\.pth$|sitecustomize|usercustomize'
   ```
3. A planted hook means code already ran: rotate every credential those processes could read.

## Sources

- [Python site module: .pth processing](https://docs.python.org/3/library/site.html)
