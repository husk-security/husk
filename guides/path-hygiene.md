+++
id = "path-hygiene"
category = "Local environment"
kind = "baseline"
severity = "high"
control = "path-hygiene"
estimate = "5 min"
solution_name = "Absolute, user-owned PATH entries"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Remove writable and relative PATH entries

> With `.` in PATH, you cd into a hostile repo, type `ls`, and run their binary.

The shell resolves `.`, `..`, empty elements, and relative entries against the current directory (CWE-426/427), so you `cd` into a hostile repo, type `ls`, and run their binary. A world- or group-writable entry, or one owned by another user, lets any process shadow a real tool.

## Steps

1. Spot `.`, blanks, and relative paths.
   ```command
tr ':' '\n' <<<"$PATH"
   ```
2. Remove the bad element; a trailing `:` alone adds the current directory.
   ```command
grep -n "PATH=" ~/.bashrc ~/.zshrc ~/.profile
   ```
3. Drop a writable entry or tighten it: `chmod go-w <dir>`.

## Sources

- [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
