# Envelope schema compatibility corpus

Signed documents made by earlier builds of the engine, one directory per build, grouped by the
envelope schema version they carry:

```
corpus/
  v3/
    2026-10-17-9192802/   main at the start of the hosted-service work
    2026-10-26-6a5e26b/   adds a filled dropdown and a PAdES B-T signature timestamp
    2026-10-27-7a0326c/   adds the signature-timestamp policy: required and none
    2026-10-27-a14ed87/   adds local dates, date formats, consent records and a service link
    2026-10-27-22a9d80/   adds validation data and document timestamps (PAdES B-LTA), and an
                          envelope without signature timestamps sealed by a document timestamp
  v4/
    2026-10-27-f1cdbea/   assurance levels: slots state min_level (Bob's asks for an
                          organization identity, L3, filled by one), and an envelope whose
                          signature timestamps are optional
  v5/
    2026-10-27-c906265/   several documents per envelope: the v4 documents, plus an envelope of
                          three documents combined into one PDF with a documents index, signed by
                          two signers with fields in several of them (prepared-documents.pdf,
                          signed-documents.pdf)
  v6/
    2026-10-27-51aa0a7/   signers' drawings in their records: the v5 documents with Alice's
                          signature typed (the glyph outlines of her name in the engine's test
                          font, filled) and Bob's drawn (pen strokes)
  v7/
    2026-10-30-72004c0/   number fields and the 'verify at' stamp: the v6 documents with a number
                          field Bob fills (12500, kept as 12500.00, drawn "12 500,00") and
                          verify.example.com on every document-ID stamp; the reports carry
                          each finding's stable code
    2026-11-02-176e807/   the v7 documents written the way many-signer envelopes needed:
                          the envelope attachment compressed (/FlateDecode) and each signature's
                          placeholder sized to its CMS (2048 hex characters, not 16384)
  v8/
    2026-11-07-d13a087/   checks on text fields, amounts and formula fields: the v7 documents
                          with Bob's email field (typed Legal@Bob.EXAMPLE, kept as
                          Legal@bob.example, at most 80 characters), his EIN (kept as
                          12-3456789, drawn masked ••-•••6789), a purchase order matching the
                          preparer's pattern PO-\d{4}-\d{3} with her own check message, the fee
                          in euros (drawn "EUR 12 500,00"), and a formula total: the seats he
                          types (3) times the fee, plus the numbers of his copy format (a
                          dropdown) and of how his copy is sent (a radio group read by its
                          name), computed at signing as 37500.00 and drawn "EUR 37 500,00".
                          (Version 8 is experimental: this set replaced 2026-11-07-4c62f18,
                          made before formula fields.)
  v9/
    2026-11-08-d042bca/   initials from the slot's name (initials_rule name-v1): the v8 documents
                          with the signers named "Alice Example" and "Bob Builder", so the
                          initials fields of the envelope of several documents hold AE and BB
                          (their addresses alone would give A and B)
  newer/
    schema-v1000.pdf      a sound document whose envelope claims version 1000
```

Each build directory holds what that build's `signpdf demo` wrote (`prepared.pdf`,
`signed-by-alice.pdf`, `signed-final.pdf`, and from 2026-10-27 `prepared-no-timestamps.pdf` and
`signed-no-timestamps.pdf`, and from 2026-10-27-22a9d80 `signed-ltv.pdf` and
`sealed-no-timestamps.pdf`, from v4 `signed-optional-timestamps.pdf`, and from v5
`prepared-documents.pdf` and `signed-documents.pdf`) plus one decline (`declined.pdf`), each with
the verification report **that build** produced (`*.report.json`), a `trust.json` pinning the
test-issuer keys embedded in the documents (and, from 2026-10-26, the demo's test TSA, whose
signature timestamp dates Bob's signature; from 2026-10-27-22a9d80 the test root CA that issued
it), and `SOURCE.txt` with the commit, toolchain and commands.

`tests/schema_versions.rs` runs on every `cargo test` and checks, for every document:

- this build reaches the same verdict as the build that made it (same validity, same revisions,
  same signers, fingerprints, times and identity results). Reports from before assurance levels
  give `assurance`; it is compared as the level this build computes for the same identity:
  `consumer` (an account at the test issuer) is L2, `enterprise` L3;
- it verifies against the pinned keys in `trust.json`, without the insecure dev opt-in;
- under that `trust.json` with every issuer requiring trusted time (as a service's own email-code
  provider does), each revision a trusted timestamp covers stays trusted and each one nothing
  covers waits for one (`no-trusted-time`); the envelope sealed by one document timestamp is
  valid, every revision bounded by it;
- every revision's envelope decodes into today's model and encodes back to the same JSON (nothing
  the signatures covered is lost);
- a half-signed document can be finished, and a prepared one declined, by this build, and the
  envelope keeps its version;
- every supported version (`OLDEST_SCHEMA_VERSION..=SCHEMA_VERSION`) has fixtures;
- the current version's fixtures include a filled dropdown field and a trusted PAdES B-T
  signature timestamp (the demo writes both since 2026-10-26), and signed envelopes of every
  `signature_timestamps` policy: `required` (the demo's NDA since 2026-10-27, both signatures
  timestamped; its decline, made without a TSA, has none and a warning), `none`
  (`*-no-timestamps.pdf`) and `optional` (the v3 sets before 7a0326c, which state no policy, and
  from v4 `signed-optional-timestamps.pdf`);
- and, from v4, assurance levels: an L1 slot filled by an account sign-in (L2) and a slot asking
  for an organization identity (`min_level` L3, `required_methods` [organization]) filled by one
  (L3, its basis naming the organization);
- and the signer evidence the demo writes since 2026-10-27-a14ed87: a date-signed field holding the
  signer's local date (drawn `DD/MM/YYYY`), a date the signer picked (drawn `MM/DD/YYYY`), each
  signer's UTC offset (+09:00 and -05:00), their consent to an e-sign disclosure (one to a French
  translation, with the English reference hash) and the preparer's service link;
- and, since 2026-10-27-22a9d80, a completed document sealed at PAdES B-LTA (validation data for
  its signature timestamps, with an OCSP response from the demo's test CA, then a document
  timestamp) and an envelope without signature timestamps sealed by one document timestamp
  (PAdES B-T); this build can add another document timestamp to the sealed one;
- and, from v5, a signed envelope of several documents whose index is part of the prepared terms,
  with signers' fields in more than one of its documents; this build can cut each of its
  documents out as a convenience copy;
- and, from v6, a typed signature and a drawn one, each kept in its signer's record, redrawn by
  the verifier byte for byte and reported as `typed` and `drawn`;
- and, from v7, a filled number field and a document-ID stamp with a 'verify at' address; and,
  for reports that carry them (from v7), the same finding codes as the build that made them;
- and, from v8, text fields with a sealed format, length rule and owner message, an identifier
  drawn masked and a number in a currency (`tests/r17_text_formats.rs`);
- and, from v9, an envelope that names its initials rule (`name-v1`) with initials stamps of the
  slot names (`AE`, `BB`) where the addresses would give other letters (`tests/initials_name.rs`).

`newer/schema-v1000.pdf` is used by the FFI tests, the WASM tests and `web/verifier/versions.mjs`
to check that a document from a newer build is refused with the "unsupported version" error
(code 16) rather than reported as invalid.

## EU DSS

`dss.json` records what EU DSS, the European Commission's validation library, says about every
PDF here: the PAdES format of each signature, its indication, and each timestamp
(`tools/dss-check/run.sh`, nightly). After adding a fixture set, run
`tools/dss-check/run.sh --update` and commit the new `dss.json` with it.

## Rules

Every version up to and including 9 is **experimental** (`docs/SECURITY_MODEL.md` §8): until the
first hosted release, when an experimental version's format changes, delete its fixture sets and
make new ones from the commit with the change. From the first hosted release, versions are
stable and the rules below apply to them.

- **Never edit or regenerate a stable version's fixture.** They record what a past build wrote;
  regenerating them with a new build would stop testing compatibility. A fixture that stops
  verifying means the engine broke old documents: fix the engine.
- **Every new schema version adds fixtures**, made by the commit that introduces it (commit the
  version bump first, then run the script on that commit and commit the fixtures).

## Adding fixtures

```bash
scripts/make-schema-corpus.sh <commit> <yyyy-mm-dd>-<short-sha>
```

The script builds that commit's CLI in a temporary git worktree, runs the demo and the decline,
and writes `corpus/v<N>/<label>/`. It refuses to overwrite an existing directory. On Windows, set
`TMPDIR` and `CARGO_TARGET_DIR` to a short path (the 260-character path limit breaks the build in
a deep temporary folder):

```bash
TMPDIR=C:/tmp CARGO_TARGET_DIR=C:/tmp/target scripts/make-schema-corpus.sh 9192802 2026-10-17-9192802
```

`newer/schema-v1000.pdf` is written by
`cargo test -p signpdf-core --test schema_versions -- --ignored write_newer_version_fixture`
(only when missing).

## Licence

The files in this directory are dedicated to the public domain under CC0 1.0
(`LICENSES/CC0-1.0.txt`, `REUSE.toml`), so that anyone can use them as test vectors
(`spec/envelope-format.md` §12). The attack corpus is in `../attack/`.
