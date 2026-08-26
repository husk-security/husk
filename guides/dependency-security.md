+++
id = "dependency-security"
category = "Dependencies"
kind = "baseline"
severity = "critical"
control = "dependency-security"
scope = "project-ecosystem"
estimate = "10 min"
solution_name = "husk scan (OSV + KEV/EPSS)"
solution_url = "https://osv.dev/"
solution_husk = true
related_rules = []
+++

# Fix vulnerable dependencies, exploited ones first

> A dependency that was clean at install becomes a known-exploited CVE without you touching anything.

Two CVEs exploited in the wild outrank forty theoretical ones. Findings are sorted by CISA KEV membership and EPSS score, so work them top down.

## Steps

1. Scan; read findings top down.
   ```command
husk scan
   ```
2. Upgrade to the fixed version the finding names; a compromised newer release means downgrade instead.
3. Record accepted risk in the committed project policy:
   ```command
husk approve <finding-id> --suppress --reason "not reachable"
   ```

## Sources

- [OSV.dev vulnerability database](https://osv.dev/)
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
