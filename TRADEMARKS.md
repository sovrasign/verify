# Trademark policy

Version 1. Sovrasign LLC, a Washington limited liability company in the United States ("we"),
owns the names and logos this policy covers.

The code, the format description and the test files in this repository are open: anyone may use,
change and share them under their licences (`LICENSE-MIT`, `LICENSE-APACHE` and the files listed
in `REUSE.toml`). Those licences cover the code and the texts. They give **no** right to use our
names or logos beyond describing where the code comes from (the Apache License, section 6). This
policy says how you may use them, so that people can always tell our software from a fork, and a
verification result from a claim.

## The names and logos it covers

- **Sovrasign** and **Sovrasign Verify**;
- the Sovrasign logo (the "S" symbol and the "sovrasign" wordmark), and the icons made from them;
- **SignPDF**, the working name of the signing engine's crates in this repository, for as long as
  we use it. Other, unrelated projects use similar names (for example `signpdf` packages on npm and
  PyPI); this policy is not about them.

## What you may do without asking

- **Say what your software is based on**, in plain text, in its description, documentation and
  about screen: for example "based on Sovrasign Verify", "a fork of Sovrasign Verify" or "uses the
  SignPDF engine".
- **Refer to us by name** in articles, talks, books, reviews, comparisons and teaching material,
  and link to us.
- **Say that your software reads or checks the envelope format** described in
  `spec/envelope-format.md`, if it does. Passing the published test files
  (`core/signpdf-core/tests/corpus/` and `core/signpdf-core/tests/attack/`) is how to show it.
- **Pass on unmodified copies** of this repository or of our builds, keeping their original names
  and licences.

Use our names as words, not as logos, and no more than you need to say what is true.

## What you may not do

- **Name your product, fork or service** "Sovrasign", "Sovrasign Verify" or "SignPDF", or a name
  that could be confused with them (for example "Sovrasign Pro", "OpenSovrasign", "Sovra Sign",
  "SignPDF+"). This also applies to domain names, app-store listings, package names and
  social-media accounts.
- **Use our logos**, or a logo that looks like them, for your product, fork or site.
- **Present a modified build as ours**, or distribute a modified build under our names. A fork of
  the verifier page must change its title, name and logo before it is published.
- **Claim that a document was "verified by Sovrasign"**, or show a Sovrasign seal or badge, when
  your software produced the result with its own code or its own trust list. A fork's
  verification reports must carry the fork's own name. (Our verifier reports which trust list and
  which identity providers it relied on, so a fork with its own trust list cannot pass its results
  off as ours.)
- **Imitate our sites, emails or signing pages**, or use our names in a way that could make people
  think they are dealing with us.
- **Suggest that we endorse**, partner with or certify you when we do not.

## Asking for permission

For any other use, or if you are not sure, open an issue in this repository or write to
[legal@sovrasign.com](mailto:legal@sovrasign.com) before you use our names or logos. We aim to
answer within 7 days.

## Reporting misuse

A fake verifier, or a site, email or page that imitates ours, is a security problem for everyone
who relies on the real one: report it to [security@sovrasign.com](mailto:security@sovrasign.com)
or through this repository's Security tab, as `SECURITY.md` explains. Report other misuse of our
names or logos to [legal@sovrasign.com](mailto:legal@sovrasign.com).

## Changes

We may change this policy. The version in this repository's default branch applies; earlier
versions stay in its history.
