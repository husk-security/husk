+++
id = "malicious-packages"
category = "Dependencies"
kind = "baseline"
severity = "critical"
control = "malicious-packages"
scope = "project-ecosystem"
estimate = "30 min"
solution_name = "Remove, rotate, block (husk scan + husk approve --block)"
solution_url = "https://osv.dev/"
solution_husk = true
related_rules = []
+++

# Remove malicious packages, then rotate

> A malicious package is not a vulnerability: an attacker already ran code on your machine.

A CVE means upgrade; malware means remove and rotate, never upgrade, because hostile code already ran at install or import time. torchtriton (2022) exfiltrated `$HOME/.ssh`, `.gitconfig`, and the first thousand files under `$HOME` over DNS.

## Steps

1. Remove the coordinate and reinstall from a clean lockfile.
2. Rotate everything an install script could reach: npm tokens, SSH keys, cloud credentials, `.env` values.
3. Block it in the committed project policy:
   ```command
husk approve npm:bad-package --block
   ```

## Sources

- [PyTorch torchtriton compromise postmortem](https://pytorch.org/blog/compromised-nightly-dependency/)
- [OSV.dev malicious package records](https://osv.dev/)
