# Security policy

husk is a security tool, so we hold its own security to a high bar. Thank you for
helping keep husk and its users safe.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Instead, use either of these private channels:

1. **GitHub Security Advisories (preferred).** Open a private report at
   <https://github.com/husk-security/husk/security/advisories/new>. This keeps
   the report confidential and lets us collaborate on a fix in a private fork.
2. **Email.** Write to **erik.frankling@frankling.se** with the details. If you
   want to encrypt the report, say so and we will exchange a key.

Please include, as far as you can:

- the husk version (`husk --version`) and how it was installed;
- the operating system and architecture;
- a clear description of the issue and its impact;
- step-by-step reproduction (a minimal repro or proof-of-concept is ideal);
- any logs, stack traces, or scan output that help.

You will get an acknowledgement within **3 business days**. We aim to give an
initial assessment within **7 days** and to ship a fix or a clear mitigation plan
as quickly as the severity warrants. We will keep you updated throughout and
credit you in the advisory and release notes unless you prefer to stay anonymous.

We follow **coordinated disclosure**: please give us a reasonable window to
release a fix before any public write-up. We will not pursue legal action against
good-faith research that respects users' privacy and data.

## Scope

In scope:

- the husk CLI, TUI, localhost web UI, and MCP server (this repository);
- the bundled integrations under `integrations/`;
- the release pipeline and the way releases are signed and verified.

Out of scope:

- **everything under `tst/`.** That directory is husk's fixture corpus: a
  deliberately unsafe developer machine (fake credentials, knowingly vulnerable
  version pins, a prompt-injection payload, and a GitHub Actions workflow built
  entirely from anti-patterns), checked in so husk's detectors can be tested
  deterministically. It is unsafe on purpose and nothing in it executes. See
  [tst/README.md](tst/README.md), which explains the two files that most often
  prompt a report. Findings in `tst/` are not vulnerabilities in husk;
- vulnerabilities in third-party dependencies that are not exploitable through
  husk (please still tell us so we can update; report them to the relevant
  project too);
- the cloud platform backend, which lives in a separate repository.

## Supported versions

husk is pre-1.0 and ships from a single line of development. Security fixes land
on the latest released version; please upgrade before reporting.

| Version | Supported |
| ------- | --------- |
| latest release | ✅ |
| older releases | ❌ (upgrade to latest) |

## Verifying a release

Every husk release is built in CI from a tagged commit and signed — there is no
hand-uploaded binary. Verify what you run:

- each archive ships a SHA-256 checksum, a **cosign** keyless signature
  (Sigstore Fulcio + the Rekor transparency log), and a **SLSA build-provenance**
  attestation;
- full verification instructions are in the
  [Verifying a release](README.md#verifying-a-release) section of the README.

If a download fails verification, **do not run it** — report it through the
private channels above.

## A note on findings husk reports

husk reports potential security issues it finds on your machine. A finding from
husk is not a vulnerability in husk itself. For help interpreting findings, open
a regular issue — that is not a security report.
