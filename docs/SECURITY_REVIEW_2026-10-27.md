# Security review: verification, timestamps and the increment audit (2026-10-27)

Reviewed 2026-10-27 against the engine of that day (lopdf 0.42.0), by reading the code; nothing was
built or run for this review. Scope: what the engine promises in
[`SECURITY_MODEL.md`](SECURITY_MODEL.md): signature and CMS checks, the revision replay and its
object-level audits (`pades::audit_increment`, `pades::audit_ltv_increment`), identity tokens and
the trust store, timestamps and validation data (`timestamp.rs`, `ltv.rs`), schema versions,
signing by increment, and the WASM and FFI boundaries. The fix of the
[load-filter review](SECURITY_REVIEW_LOAD_FILTER.md) was checked; that review was not redone.

**Verdict.** Three findings break promises of the security model and must be fixed before the
first hosted release: two in how the audits read a revision (findings 1 and 2), one in how a
timestamp's chain is checked (finding 3). One more is hardening (finding 4). Each section names
the regression test its fix should add.

**Status (2026-10-27): all four fixed.** Each fix came with regression tests that fail on the
engine as it was and pass after the fix:
- finding 1: `tests/xref_differential.rs`
  and `xref::tests`;
- finding 2: `tests/dangling_ref.rs`;
- finding 3: `tests/tsa_ca_checks.rs`;
- finding 4: `tests/form_field.rs`.

What the fixes leave open is in [`SECURITY_MODEL.md`](SECURITY_MODEL.md) §7.

| # | Severity | Finding | Status |
| --- | --- | --- | --- |
| 1 | Critical | The audits read cross-reference entries differently from PDF viewers | Fixed |
| 2 | High | An object the previous revision refers to but does not define can be defined later | Fixed |
| 3 | High | A timestamp's chain is not checked for CA constraints | Fixed |
| 4 | Low | A signer's revision may add a form field other than its signature | Fixed |

## 1. (critical) The audits read cross-reference entries differently from viewers

The audits compare two lopdf parses. lopdf 0.42.0 reads an increment's cross-reference in two
ways that PDF viewers do not:

- **Free entries are dropped.** The classic-table parser keeps only `n` entries
  (`parser/mod.rs`, `xref()`), the stream parser skips type 0 (`parser_aux.rs`), and
  `Xref::merge` keeps an older entry when the newer section has none. An increment that marks an
  existing object free leaves it defined for the engine. Viewers follow the specification: the
  object is free, a reference to it is `null` (pdf.js 6.4.299: `XRef.readXRefTable` stores the
  free entry, `getEntry` returns `null`).
- **Duplicate entries.** When one table lists an object number twice, lopdf keeps the **last**
  entry (`Xref::insert` overwrites); pdf.js keeps the **first** (`this.#entries[first + i] ??=
  entry`).

So an increment can list a changed object twice (first at a new body, then at the old one), or
mark an object free, and the audits see no change, while pdf.js shows the new body or nothing.

- **In a signer's revision** (`audit_increment`): a later signer with a modified client changes
  page content, an image, or an earlier signer's annotation, in what pdf.js-based viewers show,
  and verification reports the document valid.
- **After the last signature** (`audit_ltv_increment`): anyone holding a finished document appends
  a document timestamp (an untrusted authority leaves the document valid, by design) whose
  cross-reference does the same. The audit never sees the new bodies, since lopdf does not load
  them, so nothing is "unexplained".

The security model's §2 promises ("Content streams, resources, the page tree, and existing
annotations or signatures cannot change"; "no other object changes" after a signature) do not
hold until this is fixed.

**Fix.** Do not rely on lopdf's reading of an increment's cross-reference. In both audits, parse
the increment's own cross-reference section and accept only the form the engine writes: one
section whose `/Prev` is the previous revision's `startxref`, no `/XRefStm`, only in-use entries
(and the `0 65535 f` head), each object number at most once, each entry pointing inside the
increment at `N G obj` for that number, and entries for objects of the previous revision only
where the audit allows a change (catalog, form, pages, DSS). Tests: a duplicate entry and a free
entry, each in a signer's revision and in a document-timestamp increment.

**Follow-up (a later fix).** The fix's model of what viewers read looked for `N G obj` at the exact byte
of an entry's offset. Readers skip whitespace and comments there first, and Microsoft Print to
PDF points every entry at the line feed before its object, so every document printed that way
was refused as ambiguous. The model now skips exactly what pdf.js, PDFium and lopdf skip, and
still requires the entry's own number, generation and `obj` after it (`xref::object_header_at`,
[`SECURITY_MODEL.md`](SECURITY_MODEL.md) §2).

**Follow-up (review of that later fix, defect 1, high).** Checking where entry `N` points was not enough:
lopdf files each object under the number of the header it finds, not the entry's number (the
later entry wins), and fills an object it cannot parse at its entry from any object stream that
lists it, unnamed by any entry. So lopdf's copy of `N` could come from a spare entry leading to a
second `N 0 obj`, from such an object stream, or (for a compressed object) from the last of two
listings of `N` in its object stream, where viewers read the entry's index. The audits then
compared a copy viewers never show: a later signer with a modified client could change a page
the preparer did not rewrite, and the document verified. Now, for every object an increment
rewrites, no other entry may lead to a copy of it or of its object stream, its object stream must
list it once in a header every reader splits alike, and reading it through its own entry must
give lopdf's copy; every object the increments list must likewise be read from its own entry in
the new revision (`pades::EntryReader`, `xref::object_header_number_at`,
`xref::object_stream_numbers`). Tests: `xref_differential`, a signer's revision rewriting page 2
behind each of the three copies, which verified before.

## 2. (high) An object referred to but not defined can be defined later

`audit_increment` treats an object absent from the previous revision's parse as new, and new
objects are allowed. The load-filter fix refuses one way an object can be absent (listed in the
cross-reference but unreadable). An object that the previous revision **refers to but never
defines** (no entry, or a free one) is absent too, and viewers treat the reference as `null`.

A preparer can upload a source whose page lists `/Annots [99 0 R]` without an object 99: every
viewer shows the page normally and the others sign it. If the preparer (or someone colluding with
them) signs later, their revision defines 99 as an annotation drawn over the page. The page and
its `/Annots` array do not change, 99 is "new", and the added-annotation checks never see it (the
array did not grow). The same attack class and preconditions as load-filter finding 1.

**Fix.** Collect the object numbers the previous revision refers to (objects and trailer) without
defining them, and refuse a revision that defines one. Number the objects the engine adds above
every referenced number too (today `max_id + 1`, from the cross-reference), so that an honest
revision never fills such a reference by accident. Tests: a dangling annotation reference, and
one whose entry is free.

## 3. (high) A timestamp's chain is not checked for CA constraints

`timestamp::verify_tsa_signature` builds the TSA chain from signatures and validity periods only.
It checks no `basicConstraints` (`cA`), no `keyUsage` `keyCertSign`, no path length and no
extended-key-usage nesting. The TSA certificate needs the timestamping EKU but not as the only,
critical one RFC 3161 §2.3 requires, and the token's ESS signing-certificate attribute is not
compared with it.

So any end-entity certificate under a trusted anchor can act as an issuing CA. The bundled anchor,
DigiCert Trusted Root G4, also issues code-signing certificates that organizations buy. With one,
anyone can certify a timestamping key of their own and make timestamps with any `genTime` inside
that certificate's validity, which the engine reports as trusted. Trusted time then proves
nothing: key windows and `requires_trusted_time` (§3, the protection against a stolen
identity-provider key), envelope expiry, and the "existed before" time all accept a backdated
timestamp.

**Fix.** Every certificate used as an issuer: `basicConstraints` `cA = TRUE` and its path length
respected; `keyUsage` with `keyCertSign` when present. The TSA certificate: the timestamping EKU,
critical and alone. Check the ESS `signing-certificate` or `signing-certificate-v2` attribute
against the signer certificate. Apply the same issuer rules to OCSP delegation (`ltv.rs`). Test: a
test root, an end-entity certificate under it, and a TSA certificate signed by that end-entity
key; the timestamp must not be trusted.

## 4. (low) A signer's revision may add a form field other than its signature

`audit_increment` checks that the form gains one field and the revision adds one signature
widget, but not that the field is that widget. A signer's revision can add any new field object
(with `/AA` actions, for example) and leave its widget outside the form. `audit_ltv_increment`
already requires the exact field.

**Fix.** Require the new `/Fields` entry to be the reference of the added signature widget.

## Checked and sound

- ByteRange and gap checks, whole-file coverage, one boundary per revision; the canonical-CMS
  check (signed attributes exactly content type, message digest and the ESS binding).
- Identity tokens: algorithm allow-list, key by `kid`, bounded RSA keys, `aud`, `exp`/`nbf`, the
  nonce binding to key and document, verified email (Microsoft consumer tenant and `xms_edov`),
  the `{tenantid}` template limited to hex and dashes.
- Trust store: key and audience matched in the same issuer entry; the narrowest window binds; the
  end of a window needs trusted time; merging only narrows. Sound as written; finding 3 is what
  undermines trusted time.
- The load-filter fix is correct for the case it names; findings 1 and 2 are the general cases.
- WASM signing: keys behind handles, never accepted as input, wiped when used, at most 8;
  randomness only from `crypto.getRandomValues`, failing closed. FFI: null and length checks,
  `catch_unwind` on every entry point.
- Signing by increment (`increment.rs`): the head's length and SHA-256 checked both ways.
- Schema versions: the version is read and refused before anything else.
