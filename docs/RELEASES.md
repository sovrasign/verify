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
  `tools/archive/trust_archive.py` uses only the Python standard library. With the same variable
  set, the Pages build (`scripts/build-pages-site.sh`) makes the mirror's page follow that list:
  `trust-list.js` pins the same keys, and the page takes a list only when its signature verifies
  under them (the key-chain rule), so a provider key rotated out of its JWKS stays trusted.

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

## 4. Engine versions

Two numbers, kept apart:

| Number | Where | What it versions | Who reads it |
| --- | --- | --- | --- |
| **Engine version** (`0.3.0`) | `[workspace.package] version` in `core/Cargo.toml`; `signpdf_version` in the WebAssembly module and the FFI; tags `core-v<version>` | The software: the five crates in `core/` (`signpdf-core`, `-auth`, `-cli`, `-ffi`, `-wasm`) and the browser verifier built from them, one version for all | People and programs choosing a build, reading a changelog, pinning a dependency |
| **Envelope schema version** (`schema_version`, `11`) | `SCHEMA_VERSION` in `signpdf-core`; inside each signed document's envelope | The document format: what a signed PDF holds and the rules it was made under ([spec/](../spec/)) | Verifiers: a document's own number says which rules check it |

They move independently. A new schema version always comes with a new engine minor version (a
build has to learn to verify it), but most engine versions change no schema version, and an old
document keeps its schema version forever: a newer engine verifies it by that version's rules
(`docs/SECURITY_MODEL.md` §8). The verifier release name (`verifier-<date>-<commit>`, §2) names a
build of the verifier page, not either number.

### What the engine version means

[Semantic Versioning](https://semver.org/) with the usual pre-1.0 reading, the public API being
the crates' Rust API, the FFI and WebAssembly exports, the CLI's arguments and JSON report, and
**what verifies**:

- **Minor** (`0.3.0` -> `0.4.0`): any change to what verifies or how (a schema version added or
  retired, a check added, tightened or relaxed, a trust-list rule), and any breaking API change.
- **Patch** (`0.3.0` -> `0.3.1`): everything else: fixes and changes that leave every verification
  result, the compatibility corpus and the API as they were (performance, error wording, signing
  side only, documentation, dependency updates that change no result).
- **1.0.0** comes with the first hosted release, when the schema versions stop being experimental
  (`docs/SECURITY_MODEL.md` §8). From then on a major version is needed to stop verifying a
  schema version that stable documents use, which the compatibility promise rules out in
  practice, or to break the API; minor and patch keep their meaning.

The crates are not published to crates.io: the source is the public repository,
`github.com/sovrasign/verify`, and its tags.

### The rule and its check

A change to what verifies, or how, is at least a minor version, and the compatibility corpus must
pass unchanged (an entry in the changelog says why when it cannot, which is only allowed for
experimental schema versions). `scripts/check-engine-version.py`, one of the release checks,
enforces the first half: when a file that decides verification (its
`VERIFICATION_FILES`: the engine's source, the WebAssembly entry points, the corpus and its
expected reports, the test vectors, the verifier page's trust-list handling and the pinned
trust-list keys) differs from the nearest `core-v*` tag, the version must be at least one minor
version above that tag's, with a changelog entry. The corpus tests (`cargo test`, the `wasm`
part) enforce the second. A patch release is a judgement the check cannot make; the pull request
says why nothing that verifies changed.

### The changelog

[CHANGELOG.md](../CHANGELOG.md) has one entry per engine version, newest first, written for
someone deciding whether to upgrade: what verifies differently, which schema versions it verifies
and signs, API changes, and security fixes with their advisory IDs. Between releases:

- The first verification change after a tag raises the minor version and adds
  `## [<version>] - unreleased`; later changes before the next tag add to that entry and need no
  further bump.
- A change that needs no bump but that users would notice (a fix, an API addition) adds a line
  to the open entry, or opens a patch entry when there is none.

### Releasing a version

1. On a branch: replace `unreleased` with the date (UTC) in `CHANGELOG.md`; run
   the checks (`scripts/check-engine-version.py` checks the version against the last tag).
2. Merge into `main` as usual, then tag the merge commit, annotated, and push the tag:
   `git tag -a core-v0.3.0 -m "SignPDF engine 0.3.0"` and `git push origin core-v0.3.0`. The check
   fails if a tag names another version than its commit's `core/Cargo.toml`. It needs the whole
   history (CI checks out with `fetch-depth: 0`); in a shallow clone it fails.
3. Publish the tagged commit to the public repository (a pull request of the snapshot there; the
   engine's tests run on it). After that pull request is merged, tag its merge commit there with
   the same annotated tag, `core-v<version>`, and create a GitHub release from it whose notes are
   the changelog entry. The public tag is what a third party pins; the development repository's
   tag is what the version check reads.
4. The next verification change opens the next `unreleased` entry.

A version is never re-tagged: a mistake in a released version is fixed by the next one.
