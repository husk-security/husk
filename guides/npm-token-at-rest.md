+++
id = "npm-token-at-rest"
category = "Secrets & credentials"
kind = "baseline"
severity = "critical"
control = "npm-token-at-rest"
estimate = "10 min"
solution_name = "npm Trusted Publishing / granular tokens"
solution_url = "https://docs.npmjs.com/trusted-publishers"
solution_husk = false
related_rules = []
+++

# Get the npm token out of .npmrc

> A plaintext _authToken is publish rights to every package you own.

npm stores login tokens as plaintext `//registry.npmjs.org/:_authToken=` lines. A token in a project-local `.npmrc` is one `git add` from being committed.

## Steps

1. See what is stored.
   ```command
grep -h "_authToken\|_auth\|_password" ~/.npmrc .npmrc 2>/dev/null
   ```
2. Revoke standing tokens on npmjs.com (Access Tokens); publish from CI via Trusted Publishing (OIDC). If a local token is unavoidable, use an env reference injected per command.
   ```command
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
   ```
3. Log out when not actively publishing.
   ```command
npm logout
   ```

## Sources

- [npm docs: npmrc](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc)
- [Datadog Security Labs: Shai-Hulud 2.0](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
