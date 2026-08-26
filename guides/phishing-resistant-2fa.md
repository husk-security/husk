+++
id = "phishing-resistant-2fa"
category = "Machine & identity"
kind = "baseline"
severity = "high"
verification = "manual"
estimate = "30 min"
solution_name = "Two hardware security keys on every publish account"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Add a hardware key to every publish account

> A compromised maintainer account is this catalog's most common root cause.

OTP and push prompts relay in real time. A WebAuthn credential is origin-bound: the browser refuses to sign for the wrong domain, so a relay gets nothing. Twelve catalogued registry compromises began with a phished maintainer.

## Steps

1. Register two hardware keys on GitHub, npm, PyPI, and crates.io (a key cannot be cloned, so one means lockout); store the second elsewhere.
2. Remove SMS and email as recovery fallbacks, not only as factors; a relayable fallback makes the key decorative.

## Sources

- [npm: configuring two-factor authentication](https://docs.npmjs.com/configuring-two-factor-authentication)
- [ESLint postmortem for malicious package publishes](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/)
