+++
id = "lockfile-present"
category = "Dependencies"
kind = "baseline"
severity = "high"
control = "lockfile-present"
estimate = "5 min"
solution_name = "Native lockfiles"
solution_url = "https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json"
solution_husk = false
related_rules = []
+++

# Keep a lockfile next to every manifest

> Without a lockfile, every install resolves floating ranges to whatever was published minutes ago.

colors.js (2022) shipped a sabotaged 1.4.44-liberty-2; every project with `^1.4.0` and no lockfile jumped to it on the next install. An uncommitted lockfile protects one machine: teammates and CI re-resolve every range anyway. One exception: Rust libraries omit `Cargo.lock` by design; binaries keep it.

## Steps

1. Run one install; keep the generated lock (`package-lock.json`, `pnpm-lock.yaml`, `uv.lock`, `Gemfile.lock`, `go.sum`).
   ```command
npm install --package-lock-only
   ```
2. Remove lockfile names from `.gitignore` if present, then commit the lock.
   ```command
git add package-lock.json && git commit -m "commit lockfile"
   ```
3. Make installs obey it with a frozen install; a lockfile CI re-resolves is decoration.

## Sources

- [colors.js and faker.js sabotage (Sonatype)](https://www.sonatype.com/blog/npm-libraries-colors-and-faker-sabotaged-in-protest-by-their-maintainer-what-to-do-now)
- [package-lock.json reference](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json)
