# Security policy

Sovrasign Verify, and the engine it is built on, decide whether a signed document can be trusted,
so a flaw in them can let a forgery pass as genuine. We take every report seriously and thank
everyone who reports one responsibly.

## What is in scope

- The engine (`core/`): verification, signing, the PAdES and revision rules, identity binding,
  trust lists, timestamps.
- Sovrasign Verify (`sovrasign-verify/`), the engine's verifier page (`web/verifier/`) and the
  command-line verifier (`signpdf verify`).
- The format description (`spec/envelope-format.md`) and its test files: a rule that lets a
  forged or altered document verify is a vulnerability even if the code follows it.
- This repository's build and release pipeline (workflows, the verifier mirror, the trust-list
  archive).

The highest severity goes to anything that makes a verifier accept a forged signature, identity,
signing time or history, or a document changed after signing, **even when it is only exploitable
offline**: the open verifier is the product. `docs/SECURITY_MODEL.md` lists the attacks the
engine defends against and the residual risks it accepts; a report that one of those defences
fails is in scope.

Out of scope here: weaknesses of PDF viewers this code does not control, attacks needing a
compromised operating system or a trust list the verifier's user chose to edit, and the rest of
the hosted Sovrasign service (its apps, accounts and servers). Report those to
[security@sovrasign.com](mailto:security@sovrasign.com).

## How to report

Use GitHub's **private vulnerability reporting**: the "Report a vulnerability" button under this
repository's **Security** tab. It opens a private advisory only the maintainers see. If you cannot
use it, write to [security@sovrasign.com](mailto:security@sovrasign.com). Please include the
affected version or commit, the steps or a document that reproduces the problem, and what an
attacker gains.

Please do not open a public issue, pull request or discussion for a vulnerability, and do not
test against other people's documents or services.

## What happens next

| Step | Target |
| --- | --- |
| Acknowledgement | within 2 business days |
| First assessment (severity, affected versions) | within 7 days |
| Fix | as fast as the severity requires; we keep you informed |
| Disclosure | coordinated: 90 days after the report by default, sooner when the fix ships, later by agreement |

Every fixed vulnerability gets a **GitHub Security Advisory**, with a **CVE id** when it is
eligible under the CVE rules (GitHub, a CVE Numbering Authority, assigns it) and, for the Rust
crates once they are published on crates.io, a **RustSec advisory**. The hosted service is patched before the advisory is published. Reporters
are credited in the advisory unless they prefer not to be.

## Safe harbour

We (Sovrasign LLC, which maintains this repository) will not take legal action against, or ask
anyone to take action against, people who research and report vulnerabilities in good faith
under this policy: who avoid privacy violations, data destruction and service disruption, test
only against documents and systems they own or are allowed to test, and follow the coordinated
disclosure above before disclosing it.

## Supported versions

Security fixes go into `main` and the next release. Until the first stable release of the
document format (`spec/envelope-format.md`), only the latest `main` is supported.
