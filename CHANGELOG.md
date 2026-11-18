# Changelog

The SignPDF engine: the Rust crates in `core/` (`signpdf-core`, `signpdf-cli`, `signpdf-ffi`,
`signpdf-wasm`, `signpdf-auth`), which share one version, and the browser verifier built from them.
The Flutter app in `app/` has its own version.

A change to what verifies, or how, is at least a minor version, and the compatibility corpus
(`core/signpdf-core/tests/corpus/`) must pass unchanged except where a version's entry says why.
`scripts/check-engine-version.py` (one of the release checks) fails when a file that decides
verification changed since the last `core-v<version>` tag without that bump. How a version is
released: [docs/RELEASES.md](docs/RELEASES.md) §4.

While a version is being prepared its heading says `unreleased`; tagging it gives it a date.

## [0.3.0] - unreleased

- RSA signatures (identity-provider tokens, TSA certificates) are verified with rsa 0.10.0, the
  stable release, instead of its release candidate 0.10.0-rc.19. It fixes RUSTSEC-2023-0071 (a
  timing side channel in private-key operations, which the engine never performs outside its
  tests) and checks a signature's length and range before the public-key operation. What
  verifies is unchanged: the compatibility corpus passes as before.

## [0.2.0] - 2026-11-15

The first tagged version of the engine.

**Verifies** envelope schema versions 3 to 11 (every one in the compatibility corpus) and signs
version 11. Versions 1 and 2 (June 2026 development formats) are refused, and so is any version
newer than 11, with "unsupported version": the build cannot tell whether such a document is valid.
All of these versions are experimental until the first hosted release; see
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) §8 for what each one adds.

Since the untagged 0.1.0 development builds, which verified fewer versions under the same number:

- Schema 10: the preparing host may choose the document-ID stamp's word and colour; the verifier
  redraws the stamp from the prepared terms.
- Schema 11: the signature box shows the signer's drawing (or email) large, with the details in
  one small row under it, and the document-ID stamp's box is measured from Helvetica's glyph
  widths, so a long ID stays inside it.
- The engine reports this version (`signpdf_version` in the WebAssembly module and the FFI).

## 0.1.0

Development builds, never tagged: every engine build up to 2026-11-14 said 0.1.0, whatever schema
versions it read. A document's own `schema_version` says which rules it was made under.
