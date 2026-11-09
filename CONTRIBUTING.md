# Contributing to Sovrasign Verify

Thank you for helping. This code decides whether a signed document can be trusted, so changes to
it are held to a few rules that keep that decision sound.

## How changes arrive here

This repository is published from Sovrasign's development repository: each release arrives as
one snapshot commit. Issues and pull requests are welcome here. An accepted pull request is
applied in the development repository, with your authorship and sign-off kept, and comes back in
the next snapshot; we close the pull request with a link to that commit.

**Security issues never go in a public issue or pull request:** see [SECURITY.md](SECURITY.md).

## Sign off your commits (DCO)

Every commit must carry a `Signed-off-by:` line with your name and email, which certifies the
[Developer Certificate of Origin](https://developercertificate.org): that you wrote the change or
have the right to submit it under the project's licences. `git commit -s` adds the line. A check
(`.github/workflows/dco.yml`) refuses a pull request with a commit that lacks it; fix one with
`git commit --amend -s` or `git rebase --signoff`. No contributor licence agreement is needed:
contributions come in under the same licences as the project goes out. Unless you say otherwise,
a contribution you submit for inclusion is licensed under both the MIT licence and the Apache
License 2.0 (code), CC BY 4.0 (the format description) or CC0 1.0 (test files), as the file it
changes, without any other terms.

## Licences

- Code: MIT OR Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`).
- The format description (`spec/`): CC BY 4.0.
- The test files (`spec/vectors/`, `core/signpdf-core/tests/corpus/`,
  `core/signpdf-core/tests/attack/`): CC0 1.0.

`REUSE.toml` records which licence covers which files. The names Sovrasign and SignPDF and their
logos are not licensed by any of these (README.md, "Licences").

## Build and test

Besides the tools under "Build" in the README: cargo-vet (`cargo install cargo-vet --locked`)
and Python 3.

```sh
cd core
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all                  # the engine, the compatibility corpus, the attack vectors
cargo vet --locked                # every dependency audited (docs/SUPPLY_CHAIN.md)
cargo run -p signpdf-cli -- demo  # a two-signer flow; its PDFs go to core/demo-out/
cd ..
python3 scripts/vet-critical.py   # no unaudited crate on the signing and verification path
python3 scripts/check-workflows.py
sh scripts/build-verifier.sh && node web/verifier/smoke.mjs core/demo-out/signed-final.pdf
sh scripts/build-sovrasign-verify.sh
```

## Rules for changes to verification

- **Every change that affects verification comes with a regression test** that fails without it.
  A new attack class also gets a row in `docs/SECURITY_MODEL.md` and, when a file can show it, a
  test document in `core/signpdf-core/tests/attack/` (`tests/attack/README.md`).
- **Documents that verified keep verifying.** The compatibility corpus (`tests/corpus/`) runs on
  every `cargo test`; a stable version's fixtures are never regenerated. A change to what a
  document may contain is a new envelope schema version (`docs/SECURITY_MODEL.md`).
- **The format description moves with the code.** A change to the format, the verification rules
  or the finding codes updates `spec/envelope-format.md` in the same pull request
  (`tests/format_spec.rs` checks the versions and codes).
- A change to a verification rule needs a written rationale in the pull request, and answers: what
  can an attacker do with it, which security-critical paths it touches, and whether documents
  signed before it still verify.
- **Sovrasign Verify only words what the engine decides.** `sovrasign-verify/words.js` turns the
  engine's report into plain language; it never accepts what the engine refused.

Changes to the security-critical paths (`core/signpdf-core/src/{workflow,pades,xref,trust,oidc,
timestamp,ltv,algorithms,ink}.rs`, `core/signpdf-wasm`, `web/verifier`, `sovrasign-verify`,
`.github/workflows`) get an extra review. New dependencies on the signing and verification path
need a `cargo vet` audit (`docs/SUPPLY_CHAIN.md`).

## Response times

We aim to answer issues and pull requests within 7 days.
