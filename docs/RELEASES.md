# Releases, the verifier mirror and archives

How the browser verifier is built and published, how anyone can check that a published build is
the code in this repository, and what is archived so that documents stay verifiable for years.
The workflows below do nothing while the repository is private (each checks
`github.event.repository.private`).

## 1. The verifier mirror and reproducible builds

`.github/workflows/pages.yml` builds on every push to `main` that touches the engine, the verifier
or the specification:

1. `scripts/build-wasm-reproducible.sh` builds the WebAssembly module with the pinned toolchain
   (`scripts/wasm-toolchain`), `SOURCE_DATE_EPOCH` from the commit and remapped paths: the same
   commit gives the same bytes on any machine. Its output is
   `core/target/wasm-repro/out/signpdf_verifier.wasm`, with `SHA256SUMS`.
2. `scripts/build-pages-site.sh` writes the page with the integrity hash of every script and
   module (`scripts/sri.mjs`), the module as `signpdf_wasm.wasm`, the specification and test
   vectors as a tarball with fixed metadata, `BUILD.md` (the repository, commit, toolchain, epoch
   and rebuild commands) and `SHA256SUMS` over every file.
3. The site is deployed to GitHub Pages: hosting that does not depend on the service that signed
   a document, so the verifier stays reachable if the service's own verifier is not.

To check a published build: check out the commit its `BUILD.md` names, run
`scripts/build-wasm-reproducible.sh --container`, and compare the SHA-256 of
`signpdf_verifier.wasm` with the one of `signpdf_wasm.wasm` in the site's `SHA256SUMS`.
`gh attestation verify <file> --repo <the repository BUILD.md names>` checks any file of the
site against its signed provenance.

## 2. Archives

Two things must outlive any service built on the engine: the verifier of each period, and the
trust list it used.

- **Verifier builds.** The `archive` job of `pages.yml` makes a GitHub release
  `verifier-<date>-<commit>` for every build it publishes: the site as a tarball, `SHA256SUMS`
  and the Sigstore provenance bundle. It then asks Software Heritage
  (archive.softwareheritage.org, the long-term archive of public source code) to save the
  repository.
- **Trust lists.** `.github/workflows/trust-archive.yml` fetches the signed trust list every 6
  hours from the repository variable `TRUST_LIST_URL`, checks its detached JWS against the pinned
  trust-list keys (`tools/archive/trust-list-keys.json`, the keys every client pins and the
  `next_keys` they committed) and commits each new sequence to the `trust-history` branch as
  `trust-lists/<sequence>.json` and `.jws`, with `index.tsv`. A list that does not verify, or a
  sequence that comes back with other content, fails the run: that is an alert, never archived.
  `tools/archive/trust_archive.py` uses only the Python standard library.

## 3. Repository checks (OpenSSF Scorecard)

OpenSSF Scorecard (`.github/workflows/scorecard.yml`) grades the repository's security practices
every week. What the repository does for each check:

| Check | What does it |
| --- | --- |
| Dangerous-Workflow | no `pull_request_target`, no untrusted input in `run:` (`scripts/check-workflows.py`) |
| Binary-Artifacts | no executables committed (PDF and DER fixtures are data) |
| Branch-Protection, Code-Review | a ruleset on `main`: pull requests, required checks, no force push |
| Dependency-Update-Tool | `.github/dependabot.yml` |
| Signed-Releases, Packaging | each verifier release carries a Sigstore provenance bundle (§2) |
| Token-Permissions | read-only by default; write only in the jobs that publish (`scripts/check-workflows.py`) |
| Vulnerabilities | `cargo audit` and `cargo vet` (`docs/SUPPLY_CHAIN.md`) |
| Fuzzing | ClusterFuzzLite (`.clusterfuzzlite/`, a nightly batch and on pull requests) |
| Pinned-Dependencies | every action pinned to a commit (`scripts/check-workflows.py`), the Rust image by digest |
| SAST | CodeQL on every pull request and push (`.github/workflows/codeql.yml`) |
| Security-Policy | `SECURITY.md` |
| License | `LICENSE-MIT`, `LICENSE-APACHE`, `REUSE.toml` |
