# SignPDF security model (envelope schema v9)

This document describes what a SignPDF verification proves, what it relies on, and how each
known attack is defeated. It reflects the code in `core/signpdf-core` (`workflow.rs`, `pades.rs`,
`trust.rs`, `oidc.rs`, `algorithms.rs`, `timestamp.rs`, `ltv.rs`, `initials.rs`).

## 1. What a document contains

A SignPDF document is an ordinary PDF that grows by **incremental updates**, one per action:

| Revision | Written by | Contains | Signed by |
| --- | --- | --- | --- |
| 0 | preparer | the source bytes, a visible document-id stamp, the **envelope** (title, signer slots + identity policies, fields, policy, preparer identity token, audit entry) | the preparer's ephemeral key (PAdES) |
| 1..n | each signer / decliner | one signature field (visible at the signer's field, or invisible), the signer's field values drawn as read-only annotations, the updated envelope (one new signature record, with the signer's UTC offset when the host gave it, and one audit entry, with the signer's consent to electronic records when the host recorded it) | that participant's ephemeral key (PAdES) |
| after any of these | a host (the service, or an app) | optionally validation data (the DSS: certificates, OCSP responses, CRLs), then one **document timestamp** (`/DocTimeStamp`, an invisible signature field) | a time-stamp authority (RFC 3161 token over the whole file before it) |

Every signature is PAdES baseline (`/SubFilter /ETSI.CAdES.detached`, ECDSA P-256 / SHA-256,
ESS `signing-certificate-v2`), optionally B-T (an RFC 3161 `signature-time-stamp`). Whether
signer revisions carry one is the envelope's `signature_timestamps` policy (§4); the preparer's
revision never does. Document timestamps and validation data (§4, "Document timestamps and
validation data") take a document to PAdES B-LT and B-LTA; they change nothing the signatures
cover and never carry an envelope.

Each participant's **identity** is an OpenID Connect ID token whose `nonce` is
`SHA-256(ephemeral public key ‖ document digest)`: the token is stapled to exactly one key and
one document, and is archived (with the JWK that signed it) in the envelope.

The envelope may also carry a **service link** (`service_link`): an `https` URL the preparer
sets so that a viewer can open the envelope in the service that sent it. It is outside the
prepared terms and never decides validity (§2, "Service link").

**Several documents.** An envelope of several documents signs one PDF that combines them
(`documents::combine`: their pages one after the other, in the order the preparer chose), and
the envelope carries a **documents index** (`documents`, from schema version 5): for each
document its name, its first page and page count in the combined PDF, and the SHA-256 of the file
it was made from. Every signer signs the whole combination, so one revision per signer covers
every document; the index is a prepared term (§2, "Documents index"). The largest envelope, all
its documents together, is 50 MB (`documents::MAX_ENVELOPE_BYTES`, counted in MiB): combine
refuses a larger total and prepare a larger source (code 17 on the FFI and WASM ABIs), because a
phone browser signs within its memory budget up to that size.

## 2. What `verify` checks

`workflow::verify(pdf, &TrustStore)` returns `integrity_ok`, `identities_trusted` and the
headline `valid = integrity_ok && identities_trusted`.

**Integrity** (`integrity_ok`) requires all of:

1. **Every signature is sound and canonical.** The `ByteRange` is bounds-checked, starts at 0, and
   its gap is exactly this signature's `/Contents` hex string (lowercase, zero-padded). The CMS
   digest and ECDSA signature verify. The CMS must be byte-for-byte the structure SignPDF emits,
   so no unsigned CMS field (content type, algorithm identifiers, embedded certificate) can be
   altered. Every digest of the document the verifier compares (each signed range, the source,
   each revision a record names, the report's) is computed from the bytes; it hashes the document
   once and computes each of them from SHA-256 states kept along the way
   (`digest::DocumentDigests`), which gives the same values as hashing each range on its own.
2. **The last signature or document timestamp covers the whole file.** Any byte appended
   after it (an unsigned incremental update) makes the document invalid. Every signature and
   document timestamp ends one revision; the first is the preparer's signature, and no two end
   at the same byte.
3. **Revision 0 is the preparer's.** The first signature's key is the envelope's
   `created_by_pubkey`; the source bytes hash to `source_digest`; the preparer's additions are
   limited to the document-id stamp and one signature field; the preparer's ID token verifies
   at preparation time and is bound to their key and the source digest. A documents index, when
   there is one, covers the source's pages in order (see "Documents index" below).
4. **Every later revision is exactly one participant's action**, replayed against its
   predecessor:
   - the envelope's prepared terms (title, documents index, slots and their identity policies,
     fields, policy, preparer identity) are unchanged, the signature-timestamp policy (§4)
     included;
   - exactly one pending slot became signed/declined, bound to this revision's signing key;
   - exactly one signature record and one audit entry were appended, and earlier ones are
     unchanged;
   - only that signer's empty fields were filled (a decline fills none), and their answers
     follow the field rules: every date is written `YYYY-MM-DD`, and every *date signed* field
     holds the signer's local date at signing (§4, "Local dates");
   - the record was applied to exactly the previous signed revision (`signed_prefix_len` and
     `doc_digest`), so nothing was slipped in between signatures;
   - the signer was entitled to act (sequential order with ties, not after a decline, not
     after expiry);
   - at the PDF object level (`pades::audit_increment`) the increment only adds objects. The
     catalog may only gain an AcroForm, the AcroForm may only gain one field, which must be the
     signature widget the revision adds to a page, and pages may only append annotations. The
     added annotations must be exactly the signer's signature widget at their field and
     read-only texts matching their field values. Content streams, resources, the page tree, and
     existing annotations or signatures cannot change, and neither can an object the previous
     revision lists but the engine could not read there. Images over 64 KiB are compared by
     their SHA-256 rather than their bytes, which is as strict (see
     [`SECURITY_REVIEW_LOAD_FILTER.md`](SECURITY_REVIEW_LOAD_FILTER.md)).
   - **what the increment defines is read from its own bytes** (`xref.rs`), because the PDF
     library the engine parses with reads a cross-reference differently from viewers (free
     entries, a number listed twice, hybrid sections). Each increment must be in the form
     SignPDF writes:
     - one classic table chained by `/Prev`, with in-use entries only, each number once;
     - each entry points at its own object inside the increment, and the increment holds
       nothing else;
     - the trailer's `/Root`, `/Info` and `/ID` are unchanged.

     An increment may list an object of the previous revision only if the audit compares it
     (catalog, form, pages), and only if viewers and the engine read that object's previous
     definition from the same place. At an entry's offset, readers skip PDF whitespace (NUL,
     TAB, LF, FF, CR, SPACE) and comments before `N G obj`: pdf.js, PDFium and lopdf all do,
     and Microsoft Print to PDF relies on it (each entry points at the line feed before its
     object). The audit mirrors exactly that skip (`xref::object_header_at`); then the entry's
     own number and generation and the keyword `obj` must follow. Anything else makes the
     object ambiguous: viewers refuse an entry that leads to another object's header or to no
     header (they rebuild the cross-reference instead), and a header only some readers accept
     (a sign, a decimal point) may be read differently. The same place is not enough: lopdf
     files an object under the number of the header it finds, not the entry's, and fills an
     object it cannot read at its entry from any object stream that lists it, so its copy can
     come from elsewhere. So no other entry may lead to a copy of the object (or of the object
     stream holding it), an object stream must list it once in a header every reader splits
     alike, and reading the object through its own entry must give lopdf's copy
     (`pades::EntryReader`). The same holds for every object an increment lists, in the new
     revision. A new object may not take a number the
     previous revision refers to without defining it: viewers treat such a reference as
     `null`, so filling it later would add to what they show. The engine numbers its own
     objects above every number the document lists or refers to. See
     [`SECURITY_REVIEW_2026-10-27.md`](SECURITY_REVIEW_2026-10-27.md), findings 1, 2 and 4.
   - **what the added annotations draw is what the engine draws.** The verifier redraws each
     field value from the envelope, and the signature box from the *verified* identity (email,
     key code, signing time, provider), and compares the content streams byte for byte. An
     annotation may carry only the entries the engine writes: no action, no transform, no
     filter, and no font but the standard one. A signature without a box draws nothing. The
     signer's drawing in the left part of the box is held to the ink rule: **pen strokes or
     filled paths, nothing else** (`ink::is_ink`, `ink::is_filled_paths`). Strokes are `m`/`l`
     polylines stroked with the engine's pen; a typed signature is closed `m`/`l`/`c` paths filled
     once (nonzero winding) in the engine's one colour, inside a clip to the drawing area; every
     point, control points included, lies in the area, within the path and point limits. No text,
     font, image, XObject, transform or other colour can appear there. From envelope schema
     version 6 the signer's record keeps the drawing (`drawing`, drawn strokes or typed paths)
     and the verifier redraws it and compares byte for byte, so the box shows exactly the
     recorded drawing or none; a record may keep one only for a signed revision with a visible
     box, within the limits. Before version 6 records keep none, and the area may hold nothing
     or pen strokes.
   - **number fields** (schema version 7) hold either nothing or a canonical decimal with
     exactly the field's decimal places, within its range (`NumberFormat::check`), and are drawn
     in the style sealed in the field; the document-ID stamp shows the `verify_at` address of the
     prepared terms, when there is one, and nothing else.
   - **text and multi-line fields with checks** (schema version 8) hold either nothing or the
     canonical form of a value that has the field's sealed `value_format` (email, phone, amount,
     postal code, IBAN, US SSN or EIN, or a custom pattern matched in linear time) and is within
     its `length` (`FieldCheck::holds`); US identifiers are drawn masked (the envelope keeps the
     whole value: masking hides it from a reader of the page, not from someone who opens the
     file). The owner's `check_message` is a sealed term that never decides validity.
   - **formula fields** (schema version 8) hold what their sealed formula computes from the
     values of the revision (the signer's own and earlier signers'), rounded to the field's
     decimal places: the verifier computes every one of the signer's formulas again with the same
     exact decimal arithmetic and rejects a difference (`formula_mismatch`), and redraws the
     value. Preparation lets a formula read only fields of its own signer or of a signer who
     signs before, so a later signer cannot change a total someone already signed.
   - **initials stamps** (schema version 9) hold the letters the envelope's `initials_rule`
     (`name-v1`, `spec/envelope-format.md` §4.6) derives from the slot's sealed `name` and the
     verified email address; the verifier redraws each stamp with those letters, so a stamp with
     other letters fails the byte-for-byte comparison below.
   - the signer's ID token verifies at the signing time, is bound to the record's key and
     digest, and satisfies the slot's identity policy.
5. **What follows a signature without being one** is one document timestamp and, before it,
   validation data, replayed against the revision before them (`pades::audit_ltv_increment`):
   - the token's message imprint is the hash of everything outside its `/Contents` (with the
     digest algorithm the token names: SHA-256, SHA-384 or SHA-512), `/Contents` is lowercase hex
     holding the token and zero padding only, and `/SubFilter` is `/ETSI.RFC3161`;
   - the catalog may only gain or change `/DSS`; the DSS may only gain entries in `/Certs`,
     `/OCSPs` and `/CRLs` (no `/VRI`, nothing else), keeps every entry it had, and each new entry
     is a new, unfiltered stream holding a certificate, a successful OCSP response or a CRL;
   - the form gains exactly one field, an invisible signature widget on a page (the page may
     only gain that annotation), whose value is the new `/DocTimeStamp` dictionary, carrying only
     `/Type`, `/Filter`, `/SubFilter`, `/ByteRange` and `/Contents`;
   - no other object changes, and no other object is added: in particular no attachment, so a
     document timestamp can never bring a new envelope with it;
   - each increment's cross-reference is read from its bytes and held to the same form and
     rules as a signer's (item 4); the DSS dictionary may be listed too.
   A timestamp the verifier does not trust leaves the document valid (it is reported); a broken
   one, or anything outside these rules, makes it invalid. A signer may sign after a document
   timestamp: their record names the length of the file they signed, timestamp included.
6. **The audit log** is hash-chained and every entry is signed by a known participant key. An
   entry's hash covers `seq|action|actor_fingerprint|at|details|prev_hash`, followed, for a
   signer's entry that records their consent to electronic records, by `|` and
   `esign-consent=<version>;lang=<tag>;sha256=<hex>[;ref-sha256=<hex>];at=<UTC time>` (see
   "Consent to electronic records" below). The preparer's entry carries no consent.

**Consent to electronic records** (`esign_consent` in a signer's audit entry). A host that showed
the signer a disclosure (for the US ESIGN Act and UETA consumer consent, or the EU and UK
equivalents) passes what the signer agreed to: the disclosure's version id, the language shown,
the SHA-256 of the text shown, the SHA-256 of the reference text when a translation was shown,
and the time. The signer's key signs the entry, so the record cannot be added, changed or
removed afterwards, and anyone with the published text can recompute its hash. The engine checks
only the record's form (version `[a-z0-9.-]`, a lower-case language tag, 64-hex hashes, a UTC
time ending in `Z`): which disclosures exist and which one a signer must see is the host's
business. A record dated after the signature (beyond the 5-minute leeway, against the trusted
signing time when there is one) is reported as a warning: the consent time is the host's clock
and the signing time may be the device's. The verification report gives each revision's record
(`esign_consent`).

**Documents index** (`documents`, schema version 5). Prepare and the verifier (in the preparer's
revision) check that the index has 1 to 20 entries, each with a name of 1 to 200 characters
without control or bidirectional-control characters, at least one page and a lower-case hex
SHA-256, the first starting at page index 0 and each where the previous one ends, covering every
page of the source (the page tree cannot change in later revisions, so it covers every revision).
An index that does not match the pages is an integrity failure. The index is a prepared term: a
signer who changes, removes or adds one fails verification. Each entry's `source_digest` is the
preparer's statement of which file the document was made from: the combined PDF is a new file,
so the verifier cannot recompute it; a person holding the original file can compare its SHA-256.

A **convenience copy** of one document (`documents::extract`) is a new PDF: that document's pages
as they look in the envelope (field values, signature boxes and form fields drawn as read-only
stamps), and a banner strip added above its first page saying it is document *n* of the envelope
and that the combined PDF is what was signed. It carries no signature, envelope or form, so it
proves nothing on its own; its file name says "convenience copy - verify the combined file".

**Service link.** `service_link` is set at preparation and kept by every signing, but it is not
one of the prepared terms: it is not something signers agree to, and whether it is present, dead
or changed never affects validity. The verifier reports the **preparer's** link
(`report.service_link`) only when it is an `https` URL with a DNS or IPv4 host and no user name or
password (`workflow::check_service_link`), and when a later revision changed it, reports a
warning and ignores the change, so a signer cannot send later readers elsewhere. Hosts show the
reported link with its host name, never the field of the final envelope.

**Identity trust** (`identities_trusted`): for the preparer and every signer, the issuer
(`iss`, or the Microsoft `{tenantid}` template matched against `tid`) and the **RFC 7638
thumbprint of the archived JWK** must be pinned in the verifier's `TrustStore`. An archived key
is attacker-controlled data: without this anchor anyone could mint a key, sign a token claiming
`iss: https://accounts.google.com`, and archive the key next to it. When the pinned key has a
validity window, or its issuer requires trusted time (§3), trusted time evidence must also place
the signature inside the window (§4, "Trusted time for key windows").

## 3. Trust anchors (`TrustStore`)

```json
{
  "issuers": [
    { "issuer": "https://accounts.google.com", "name": "Google",
      "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
      "keys": [ { "kty": "RSA", "kid": "…", "n": "…", "e": "AQAB" } ],
      "audiences": [ "261636994061-….apps.googleusercontent.com" ] },
    { "issuer": "https://id.example.com", "name": "Example email-code provider",
      "requires_trusted_time": true, "kind": "email-code",
      "keys": [
        { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "kid": "…",
          "not_before": "2026-11-01T00:00:00Z", "not_after": "2027-11-01T00:08:00Z",
          "first_seen": "2026-10-25T09:00:00Z" },
        { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "kid": "…",
          "not_before": "2027-11-01T00:00:00Z" } ],
      "audiences": [ "example-signing" ] }
  ],
  "tsa_anchors": [ "<base64 DER certificate>" ],
  "tsa_distrusted": [
    { "cert_sha256": "<hex SHA-256 of a TSA chain certificate>",
      "distrusted_after": "2027-03-01T00:00:00Z", "name": "Example TSA" } ],
  "allow_insecure_dev_issuer": false,
  "algorithm_policy": {
    "version": 2,
    "algorithms": [
      { "algorithm": "SHA-256" }, { "algorithm": "SHA-384" }, { "algorithm": "SHA-512" },
      { "algorithm": "ECDSA-P256" },
      { "algorithm": "RSA-PKCS1-v1_5", "min_key_bits": 2048, "not_after": "2030-12-31T00:00:00Z" } ] }
}
```

- **Applications (`audiences`).** A provider issues ID tokens to every website and app its users
  sign in to, and each of those can request any `nonce`. A token is therefore accepted only when
  its `aud` is an application listed for the issuer; an empty list accepts none. The well-known
  store lists SignPDF's own Google and Microsoft registrations (Apple has none yet). Stores
  saved before this rule are upgraded when loaded. `signpdf trust add-audience` trusts another
  application, such as an organization's own registration: do that only for an application that
  runs the SignPDF signing ceremony, because any other one could sign as its users.
- **Who a signature names.** Always the email address the provider verified. An account whose
  email the provider did not verify (or that has none) can neither prepare nor sign, and the
  verifier rejects such a record. The token's `name` claim is a profile name its holder types;
  it is never shown as the signer.
- **Key history.** `add_jwks` merges newly published keys and never forgets old ones, so a
  document signed under a since-rotated key still verifies anywhere that saw the key while it
  was published. Refresh regularly (`signpdf trust refresh`, the app's *Fetch current provider
  keys*, or the browser verifier's equivalent). An organization can distribute one curated
  `trust.json` to all its verifiers.
- **Key validity windows.** A pinned key may carry, next to its JWK members (RFC 3339 UTC times):
  `not_before` (its issuer began signing with it), `not_after` (its issuer stopped: a planned
  rotation, set to the switch time plus the token lifetime and some clock skew) and
  `distrusted_after` (it may have been compromised from then: the last known-good time). A token
  signed by the key counts only when trusted time evidence (§4) shows the signature was made by
  `not_after` and by `distrusted_after`, and neither the token's `iat` nor that evidence predates
  `not_before` (5 minutes' skew allowed at the start only). `first_seen` and `last_seen` record
  when the store saw the key published; they never decide anything. A key's window comes from
  the trust store only: window members in the JWK a document archives are ignored. When the same
  key is pinned under several matching entries, the narrowest window applies.
- **Issuers that require trusted time** (`requires_trusted_time`). Every token from such an
  issuer, whatever its key's window, counts only with trusted time evidence inside the window.
  Set it for an issuer whose key, if stolen, could mint tokens for any address and date them at
  will (`iat` is written by the key holder), such as a signing service's own email-code
  provider: without it, a thief could sign "before" a distrust date long after it.
- **Merging and editing.** `merge` (and `add_jwks`) never widens a window: a key both stores pin
  keeps the later start and the earlier ends, and an issuer either store requires trusted time
  for requires it. An issuer may publish windows in its own JWKS, next to each key's members;
  `add_published_jwks` (used by `signpdf trust refresh`, `trust add-jwks` and the FFI and WASM
  `signpdf_trust_add_jwks`) keeps them under the same rule. `TrustStore::set_key_window` and `set_requires_trusted_time` (`signpdf trust
  window`, `signpdf trust require-time`) replace them, for an operator correcting a store. A
  store with an unreadable window time is refused when loaded, and fails closed if built in code.
- **What a sign-in shows** (`kind`), from which the verifier computes each signature's assurance
  level (§5): `email-code` (control of the inbox, shown by a one-time code: L1, whatever the
  provider's tokens claim), `account` (an account provider: L2, and L3 for an organization
  identity it asserts, a Google Workspace `hd` or a Microsoft Entra organizational `tid`) or
  `organization` (an organization's own provider for its signers: L3). Without a `kind`, Google,
  Microsoft and Apple are `account` providers, and any other issuer counts as `email-code`, the
  least a verified email shows. When several matching entries state a kind, the one that shows
  least wins, and `merge` keeps the lower of two. `TrustStore::set_issuer_kind`
  (`signpdf trust kind`) sets it. A signing service's own email-code provider should be listed as
  `email-code` explicitly.
- **Algorithm policy** (`algorithm_policy`, `algorithms.rs`): which digest and signature
  algorithms the verifier accepts, from which key size, and until when (§4, "Algorithm
  policy"). Without one, the engine's built-in policy (version 1) applies: SHA-256, SHA-384,
  SHA-512, ECDSA P-256 and RSA PKCS #1 v1.5 from 2048 bits, with no end dates. A policy in the
  trust list replaces it; it can only restrict what the engine implements (a rule naming an
  algorithm the engine does not implement is ignored). `merge` keeps the policy with the higher
  `version`, and an unreadable one is refused when the store is loaded.
  `TrustStore::set_algorithm_policy` (`signpdf trust algorithm-policy`) sets it. Every report
  names the policy it applied (`algorithm_policy`: `version`, `source` `trust-list` or
  `builtin`, and `checked_at`, the verifier's time when the policy has end dates).
- **TSA anchors**: DigiCert Trusted Root G4 is bundled
  (SHA-256 `552F7BDCF1A7AF9E6CE672017F4F12ABF77240C78E761AC203D1D9D20AC89988`).
- **Dev issuer.** `https://issuer.test` (tests, the CLI `--email` login) is accepted only with
  `allow_insecure_dev_issuer`, which is never persisted or merged, and every report produced with
  it carries an `INSECURE` warning.

## 4. Time

A signature's time comes from one of two sources (`time_source`):

- **`tsa`**: a PAdES B-T signature timestamp whose TSA CMS signature, certificate and validity,
  and chain to a trusted anchor all verify. The token is inside the signed bytes, so it predates
  the timestamp. The timestamp's `genTime` is therefore a sound upper bound on the signing
  moment: it rescues honest signers with skewed clocks and exposes a backdated `signed_at`.

  What each certificate of the chain may do is checked (`timestamp::issuer_problem`), so that
  no end-entity certificate under an anchor can act as an issuing CA:
  - every certificate that issues another on the way to the anchor, anchors included, must be
    a certificate authority: `basicConstraints` critical with `cA`, and its path length
    respected;
  - an issuer that lists key usages must allow `keyCertSign`;
  - an issuer that lists extended key usages must allow timestamping;
  - the TSA certificate's extended key usage must be `id-kp-timeStamping` alone, marked
    critical (RFC 3161 §2.3);
  - an ESS `signing-certificate(-v2)` attribute in the token must name the certificate that
    signed (a token without one is accepted, see §7);
  - only a certificate authority may delegate OCSP signing.
- **`device`**: the signer's self-asserted clock, used otherwise. The verifier still rejects a
  signing time earlier than the token's `iat`.

**A distrusted authority.** A timestamp authority whose key may have been compromised is
distrusted from a time with a `tsa_distrusted` entry (`trust::TsaDistrust`: the SHA-256 of a
certificate of its chain, the TSA's own, an intermediate or an anchor, and `distrusted_after`):
a timestamp whose chain holds that certificate and whose `genTime` is **at or after** that time
is not trusted (`TimestampStatus::distrusted_after`, warning `tsa_distrusted`), and earlier ones
still count. Anchors are roots that many authorities share, so this distrusts one authority
without the others, and only from a time. `genTime` is the authority's own claim: a thief with
the key can still date a token earlier, so `distrusted_after` is the earliest time the key may
have been exposed, and a hosted service re-stamps the documents whose trusted time came from the
authority after it. Merging stores keeps the earlier time.

Unsigned or untrusted timestamps are reported but **never used as a clock**. The legacy
`timestamp_token` over the pre-signing document only proves when the document existed, so it is
reported as `document_timestamp` and never used for token validity.

### Trusted "existed before" time

Every timestamp at or after a signature in the file covers it: a later signature signs the bytes
before it, and a document timestamp covers the whole file before it. The earliest **trusted** one
(the revision's own signature timestamp, a later revision's, or a document timestamp) therefore
proves the signature existed by its time. Each revision of the report gives it as
`existed_before` (`time`, `source`: `signature`, `later-signature` or `document`, the `revision`
or `document_timestamp` it is, and the authority's name), and the identity token's `iat` as
`token_issued_at`, the earliest possible signing time (stated by the provider, not trusted).
`time_source` stays `device` for a signature dated by its device clock: `existed_before` bounds
that time, it does not replace it. For an envelope whose policy is `none`, the document timestamp
a hosted service adds when it ends is that bound for every signature ("all signatures in this
document existed before …"); before then a revision has none ("no trusted timestamp yet").

| Used for | How |
| --- | --- |
| Key validity windows | the only evidence held against `not_after` and `distrusted_after` (§3, below) |
| Envelope expiry | a revision whose signing time (trusted signature timestamp, or device clock) is after `policy.expiry` is not lapsed when `existed_before` shows it existed by the expiry |
| Token validity (`iat` ≤ time ≤ `exp`) | not used: a document timestamp may come days after the 5-minute token expired |

### Trusted time for key windows

| The pinned key / issuer | No trusted time covers the signature | Trusted time *t* covers it |
| --- | --- | --- |
| no window, issuer does not require trusted time | `trusted` | `trusted` |
| issuer requires trusted time, or the key has `not_after` / `distrusted_after` | `no-trusted-time` | `trusted` when *t* ≤ `not_after` and *t* ≤ `distrusted_after`; else `distrusted-key` (after `distrusted_after`) or `outside-key-window` (after `not_after`) |
| `not_before` | `outside-key-window` when `iat` is earlier (beyond 5 minutes) | also `outside-key-window` when *t* is earlier |

None of these is an integrity failure: the identity is not trusted, and the report says why.
When every untrusted identity is `no-trusted-time`, the report sets `trusted_time_pending`: the
document is sound and becomes valid once a trusted timestamp is added before the keys' windows
end (a hosted service accepts such an in-progress revision; viewers show "no trusted timestamp
yet" rather than "not trusted"). A host that rotates or plans to distrust such a key adds a
document timestamp to every open envelope holding a signature by it, before the key's window
ends (a rotation sweep), so those signatures stay inside it; signatures made after the sweep use
the next key and are dated by the next timestamp.

### Algorithm policy

Algorithms weaken over the decades an agreement is kept (RSA-2048, which the large identity
providers sign their tokens with, is on NIST's deprecation path around 2030), so the verifier
reads which ones it accepts from its trust list (§3) instead of hard-coded rules. Each piece of
evidence is judged on the algorithms it relies on:

| Evidence | Algorithms | When the policy refuses them |
| --- | --- | --- |
| A preparer's or signer's PAdES signature, its signature record and audit entry, the document, nonce and audit-chain digests | ECDSA P-256, SHA-256 | the revision fails (integrity): "the signature cannot be relied on" |
| An identity token | ES256 (ECDSA P-256, SHA-256), or RS256 (RSA with the key's modulus size, SHA-256) | `identity_trust` `algorithm-not-accepted` |
| An RFC 3161 timestamp | its imprint's digest, the authority's signature (algorithm, key size, digest) and each certificate signature on the way to the anchor | the timestamp is not trusted: it neither dates nor covers anything |

This table is also the engine's **cryptographic inventory**: every algorithm a verification
relies on (the ephemeral signer keys are P-256; Windows keeps a saved identity under DPAPI, which
no verification depends on). It is reviewed with the trust list's policy, at least yearly, and a
new primitive (a longer digest, ML-DSA keys) comes only with a new schema version.

An algorithm the policy does not name, or a key smaller than its `min_key_bits`, is refused
outright. An algorithm with a `not_after` is accepted while the verifier's time is before it.
After it, evidence relying on the algorithm counts only when a **trusted timestamp that itself
counts** shows the evidence existed by `not_after`: the revision's `existed_before` for a
signature or a token, and for a timestamp the earliest later timestamp that counts. The
timestamps are judged from the end of the file back, so a document whose timestamps are renewed
before each algorithm ends (a document timestamp over everything, made with algorithms still
accepted: the PAdES B-LTA archive principle) keeps verifying, while the newest timestamp must be
acceptable at the verifier's time. Such a rescue is reported as a warning.

The verifier's time is the device clock (`verify`), or the time the host gives
(`workflow::verify_at`; the browser verifier passes the page's time to `signpdf_verify_at`).
Nothing else in a verification depends on it, and a verifier without a clock (the WASM module
called through `signpdf_verify`) counts every end date as passed. With the built-in policy,
which has no end dates, no verification depends on the verifier's time.

### Signature-timestamp policy

The envelope's `policy.signature_timestamps` says whether signer revisions carry a PAdES B-T
signature timestamp. The preparer sets it, and as a prepared term it holds for the envelope's
whole life: a revision that changes it fails verification (§2). A hosted service sets it from
the sender's plan when the envelope is sent; a later change of plan does not change it.

| Value | Signing (`sign`, `sign_with`, `sign_for_timestamp`) | Adding a timestamp afterwards (`signature_timestamp_digest`, `embed_signature_timestamp`) | Verification |
| --- | --- | --- | --- |
| `required` | every signer revision (signed or declined) is made with room for a timestamp; `sign_with` adds it at once | allowed on the last signer revision | a signer revision without one is valid, dated by the device clock, with a warning (the time-stamp authority may have been unreachable) |
| `optional` | the host decides: `sign` makes no room, `sign_with` and `sign_for_timestamp` do | allowed on the last signer revision | no policy warning either way |
| `none` | no room; `sign_with` with a timestamper and `sign_for_timestamp` are refused before anything is signed | refused, so no host asks an authority for one | a signer revision that carries one anyway is valid, dated by it if trusted, with a warning |

The increment forms of the last two steps (`increment_signature_timestamp_digest`,
`embed_increment_signature_timestamp`), for a host that holds the signed document as the
document it signed and the increment `sign_for_timestamp_increment` returned, apply the same
rules without joining them: the policy is read from the signed document's envelope (the preparer's,
which no revision may change), which must exist, so the increment is a signer's revision. The
increment is not parsed as a PDF: its last `/ByteRange` must belong to a signature dictionary in
the exact form the engine writes, with `/Contents` right after it, and that signature must
verify over the document and the increment, cover both to the end and carry no
timestamp yet. Only that signature's `/Contents`, outside its signed range, is written. A crafted
increment can at worst produce a document that fails verification, which every verifier, the
service's upload check included, then reports.

`optional` is the default and is not written into the envelope, so envelopes that state no
policy keep their exact JSON. The FFI and WASM exports apply the same rules (refusals are code
10, workflow). A departure from the policy is a warning, never an integrity failure: a signature
timestamp is an unsigned attribute that does not change what was signed, and a trusted one is
true time evidence whichever policy asked for it.

Under `none`, signing times come from the signer's device clock, bounded below by the token's
`iat`. A hosted service gives such an envelope one trusted document timestamp when it ends
instead (below). It proves that every signature existed by then: it is each revision's
`existed_before`, and the trusted time key windows are judged against (above).

### Document timestamps and validation data

A **document timestamp** (`workflow::prepare_document_timestamp` and
`embed_document_timestamp` for an asynchronous authority, `add_document_timestamp` for a
synchronous one) is an RFC 3161 token over the whole file before it, in its own increment. A
host adds one when an envelope reaches a final state (the only trusted time of an envelope
whose policy is `none`), after validation data, or to renew older timestamps; and may add one to
an envelope still open (after a time-stamp authority outage, or before an identity provider's key
rotates), which the next signer then signs. It is allowed whatever the signature-timestamp
policy. The increment holds no date, so the same input always gives the same output. Nothing is
timestamped on top of a document that fails its integrity check.

**Validation data** keeps timestamps verifiable after their authorities' OCSP responders and CRLs
are gone (PAdES B-LT). `workflow::revocation_targets` names, for every certificate of a trusted
timestamp's TSA chain but the anchor that the document holds no evidence for yet, the
certificate, its issuer, the OCSP and CRL addresses the certificate names, and a ready OCSP
request (SHA-1 `CertID`, as every responder answers; SHA-1 identifies, it signs nothing). The
host fetches the answers and passes them to `workflow::add_validation_data`, which checks each
against those chains before it writes anything, and adds every chain certificate (anchors
included). A document timestamp must follow: validation data no timestamp covers is an unsigned
change.

Evidence is checked, never taken on trust (`ltv.rs`): an OCSP response must be successful, answer
for exactly the certificate, and be signed by its issuer or by a responder the issuer delegated
(`id-kp-OCSPSigning`, valid when it signed); a CRL must be issued and signed by the certificate's
issuer, with no critical extension (no delta, partitioned or indirect CRLs). Then, for each
trusted timestamp, made at time *t*:

| What the DSS says about a chain certificate | Verdict |
| --- | --- |
| revoked at or before *t* | the timestamp is not trusted (`validation: revoked`), whatever else the DSS holds |
| revoked after *t* | the timestamp holds; a warning says when the certificate was revoked |
| good, in evidence produced at or after *t*, or valid over a period including *t* (`thisUpdate` to `nextUpdate`) | `good` |
| nothing that covers *t* | `none` |

A timestamp's `validation` is `complete` when every chain certificate is in the DSS and every one
but the anchor is `good`, `incomplete` otherwise; the report lists each certificate (`chain`).

The report's `pades_level` sums this up for the whole document: `B-T` when every signature has
trusted time evidence (its own signature timestamp, or a later trusted timestamp, which proves it
existed by then), `B-LT` when, in addition, that evidence's validation is `complete`, and `B-LTA`
when, in addition, every addition of validation data ends with a trusted document timestamp. An
envelope with signature timestamps sealed at completion (validation data for them, then a
document timestamp) is `B-LTA`; an envelope whose policy is `none`, with its one document
timestamp, is `B-T`, and reaches `B-LTA` when renewed (validation data for that timestamp, then
another).

### Local dates

Every time in the envelope is UTC. A date the engine writes, the **signing date**, is the
signer's local date: the host passes the signer's UTC offset (`utc_offset_minutes` in the sign
request, from the device: `-new Date().getTimezoneOffset()` in a browser), the engine moves its
UTC signing time by it, and the signature record keeps it (`utc_offset`, `+HH:MM` or `-HH:MM`,
between `-12:00` and `+14:00`). Without an offset the date is the UTC date, as before; that is a
day off near midnight for signers far from UTC. The report gives the offset and the signer's
local time (`utc_offset`, `local_signed_at`).

| Field | The signer gives | The engine writes | The verifier checks |
| --- | --- | --- | --- |
| date (`signing_date` absent) | any date, `YYYY-MM-DD`, or nothing | the local signing date when left empty | the value is a real date written `YYYY-MM-DD` |
| date signed (`"signing_date": true`) | nothing (a value is refused) | the local signing date, always | the value is the local date of `signed_at` at the record's offset (UTC without one) |

A date field's `date_format` (`YYYY-MM-DD`, the default, `DD/MM/YYYY`, `MM/DD/YYYY`,
`DD.MM.YYYY`, `DD-MM-YYYY`, `YYYY/MM/DD` or `YYYY.MM.DD`) says how its value is drawn, whatever
the signer's locale, so every party reads the same text; the value stays `YYYY-MM-DD`. Both
`date_format` and `signing_date` are prepared terms. The offset, like the clock, is what the
signer's device says: it is evidence of the date the signer saw, not of where they were, and it
is not checked against the timestamp (a signer whose device is set to the wrong zone gets that
zone's date).

## 5. Identity policy rules

- Every identity needs an email the provider verified (`email_verified`), whatever its slot asks
  for; `required_email` then matches it exactly. Microsoft personal (MSA) accounts count as verified.
  Microsoft organizational accounts count only with the tenant-verified `xms_edov` claim.
- **Assurance levels.** The verifier computes each identity's level, L1 to L5, and the basis it
  rests on, from the token and what its trust store says about the issuer (`kind`, §3); the
  report gives `level` and `basis` (`[{"method", "issuer", "organization"?}]`) for every identity
  it can rely on. A sign-in with an `email-code` provider, or a token whose `acr` is
  `urn:signpdf:acr:email-otp` whoever issued it, is L1 (`email-code`). An `account` provider's
  identity is L2 (`account`), or L3 (`organization`) when the provider asserts an organization:
  `hd` (Google Workspace) or a Microsoft `tid` other than the consumer tenant `9188040d-…`. An
  `organization` provider's identities are L3. L4 (an identity document checked) and L5 (a
  qualified signature) need attestations and certificate chains that later schema versions add;
  this build computes L1–L3. The level is never taken from the slot or the sender.
- **Slot requirements.** A slot requires `min_level` (default L1: any verified identity) and
  optionally `required_methods` (evidence its basis must contain, e.g. `organization`). Prepare
  refuses a slot no signature this build checks could fill (L4, L5, `phone`, `id-document`,
  `qualified`). Sign refuses an identity below its slot, computing the level as a verifier with
  no trust store does (Google, Microsoft and Apple are account providers, any other issuer an
  email-code provider). The verifier checks again with its own trust store: an anchored identity
  below its slot is reported `insufficient-level` (not valid; not an integrity failure, because it
  depends on the verifier's trust store). Schema version 3's `min_assurance` maps to levels:
  `consumer`, which accepted every verified identity, is L1; `enterprise` is L3.
- **`required_domain`** for an organization identity is checked against the IdP-vouched domain:
  `hd` must equal it. For Entra the slot must also pin `required_tenant`, because Entra does not
  verify the `email` domain.
- `required_subject` pins a slot to one stable account (`sub`).
- Verification reports *weak* slot policies, such as no issuer restriction or nothing pinned
  about who may sign, as warnings.

## 6. Attack coverage

The attacks a file can show are also published as test vectors, each with the verdict and
finding codes a verifier must give it (`core/signpdf-core/tests/attack/`, checked by
`tests/attack_vectors.rs`; `spec/envelope-format.md` §12).

| Attack | Defense | Regression test |
| --- | --- | --- |
| Forged identity with a self-made key | pinned issuer keys | `workflow_e2e::identity_forged_with_a_self_made_key_is_not_trusted` |
| Token issued to another application, with an attacker-chosen `nonce` (any site with "Sign in with Google") | trusted applications per issuer (`audiences`), SignPDF's own by default | `identity_e2e::a_token_issued_to_another_application_does_not_sign_as_its_user`, `…does_not_prepare_as_its_user` |
| Profile name set to someone else's name or email | signer named by verified email only | `identity_e2e::the_profile_name_is_not_shown_as_the_signer` |
| Email the provider did not verify (e.g. set by a tenant admin) | verified email required to prepare, sign and verify | `identity_e2e::an_unverified_email_can_neither_prepare_nor_sign`, `…a_work_account_needs_a_tenant_verified_email` |
| Another name, time or provider written in one's own signature box; a field drawn with another value | the verifier redraws from the verified identity and the recorded values and compares | `identity_e2e::a_signature_box_showing_another_name_fails_verification`, `pades::appearance_tests` |
| Text, an image, a font or another colour hidden in the drawing area; a typed signature that shows other paths than its record keeps | only pen strokes or filled paths in one colour, clipped to the area, pass the ink rule; from v6 the box must be the engine's rendering of the recorded drawing | `ink::tests::only_filled_paths_in_one_colour_count_as_typed`, `typed_signatures::a_box_that_shows_other_than_the_recorded_drawing_fails`, `…a_record_cannot_keep_a_drawing_the_signer_could_not_show` |
| An action, another font or a transform hidden in an added annotation | only the entries the engine writes are allowed | `pades::appearance_tests::annotations_built_differently_from_the_engine_s_are_reported` |
| Unsigned update after the last signature (incremental saving) | whole-file coverage | `security_e2e::unsigned_update_after_last_signature_is_detected`, `page_content_replaced_after_signing_is_detected` |
| Envelope edited in transit before a signer signs | sign-time integrity check + `signed_prefix_len` chain | `signer_refuses_a_tampered_document`, `signature_over_an_unsigned_in_transit_edit_is_detected` |
| Malicious signer changing terms, other slots, others' fields, history | revision replay | `malicious_signer_*` |
| Content change hidden in a signer's own revision (shadow attack) | object-level increment audit | `content_change_inside_a_signers_own_revision_is_detected` |
| Content change through an object the engine cannot see in the earlier revision (an object stream claiming to be an image, a damaged object other readers tolerate) | only image XObjects are filtered when parsing; an object listed but unreadable before cannot be redefined | `pades::large_image_tests::page_content_hidden_in_an_image_like_object_stream_cannot_be_swapped`, `…an_object_unreadable_before_cannot_be_redefined`, `…filter_keeps_every_object_lopdf_loads` |
| A large image swapped for a stream equal to its digest | a filtered stream keeps its real `/Length`, so it never equals another stream | `pades::large_image_tests::a_small_stream_equal_to_the_digest_is_still_a_modification` |
| Signature wrapping / ByteRange games | ByteRange bounds and exact gap | `absurd_byte_range_does_not_panic`, mutation tests |
| CMS malleability | canonical-CMS requirement | `pades_e2e::signatures_are_canonical_pades_baseline` |
| Forged timestamp reviving an expired token | TSA signature + chain + anchor | `forged_signature_timestamp_is_not_trusted`, `untrusted_timestamp_is_never_used_as_a_clock` |
| A "TSA" certified by an end-entity certificate under a trusted anchor (backdated trusted time) | CA constraints on every issuer; timestamping EKU alone and critical; ESS attribute checked; only a CA delegates OCSP | `tsa_ca_checks::*`, `timestamp::tests::the_ess_attribute_must_name_the_signing_certificate` |
| A change viewers see but the audit does not, through an increment's cross-reference (an object listed twice, a free entry, an ambiguous earlier definition, a second copy lopdf reads instead) | each increment's cross-reference read from its bytes, in SignPDF's form only | `xref_differential::*`, `xref::tests` |
| A reference the earlier revision left undefined, filled by a later revision | such numbers may not be defined later; the engine numbers above them | `dangling_ref::*` |
| A signer's revision adding a form field other than its signature | the new field must be the added signature widget | `form_field::*` |
| A signer changes the signature-timestamp policy (to add a timestamp the envelope does not take, or to drop a required one) | the policy is a prepared term | `timestamp_policy::a_signer_cannot_change_the_policy` |
| A host timestamps an envelope whose policy is `none` | every engine step refuses (core, FFI, WASM); a timestamp forced in with low-level calls is reported | `timestamp_policy::no_signature_timestamps_means_none_is_made_or_added`, `…a_timestamp_forced_onto_an_envelope_that_takes_none_is_reported`, `ffi_an_envelope_without_timestamps_is_never_timestamped` |
| A modified client writes another date in a *date signed* field, or rewrites the UTC offset | the verifier recomputes the local date from `signed_at` and the recorded offset, and checks the offset's form | `local_dates::a_date_signed_field_with_another_date_fails_verification`, `…a_rewritten_utc_offset_fails_verification` |
| A signer changes how dates are drawn, or turns a date into a date-signed field | `date_format` and `signing_date` are prepared terms | `local_dates::date_terms_are_part_of_the_prepared_terms` |
| A consent record added, changed or removed after the signer's entry was sealed, or rewritten by a later signer | the entry hash covers it and the log is append-only | `esign_consent::a_consent_changed_after_it_was_sealed_fails_verification`, `…a_later_signer_cannot_rewrite_an_earlier_consent` |
| A signer renames, removes or reorders the documents of a combined envelope (the index), to change what a document is said to be | the index is a prepared term | `documents::a_signer_cannot_change_the_index` |
| A preparing client writes an index that does not match the pages (a document said to end elsewhere, or a gap) | prepare refuses it; the verifier checks it against the source's pages | `documents::prepare_refuses_an_index_that_does_not_cover_the_pdf`, `…an_index_that_does_not_match_the_pages_fails_verification` |
| A document name that shows as something else (bidirectional controls, line breaks) | refused at combine, prepare and verification | `documents::tests::names_are_checked` |
| A combined source that drags another document's signature along (broken, or passed off as covering the combination) | combine refuses signed, certified and encrypted documents | `documents::combine_refuses_what_it_cannot_combine` |
| A hostile document in a combination (loops in its page tree or outline, references to objects it does not have, deep nesting) | bounded, iterative walks; a missing object becomes `null` and never points into another document | `documents::hostile_inputs_are_refused_or_combined_without_panicking`, `documents::tests::dangling_references_become_null`, `…deep_nesting_does_not_overflow_the_stack` |
| A signer points the service link at a phishing page | only the preparer's link is reported; a change is a warning | `service_link::a_signer_who_changes_the_link_leaves_the_document_valid_and_the_change_ignored`, `…a_link_a_signer_adds_is_not_reported` |
| A link that hides its host (`https://sign.example.com@phishing.example`), or not `https` | refused at preparation, never reported | `service_link::prepare_refuses_a_link_that_is_not_a_plain_https_url` |
| Microsoft personal account passing as enterprise; Entra email spoofing | consumer-tenant rule, `xms_edov`, tenant pinning | `oidc::tests::microsoft_*`, `entra_identity_needs_pinned_tenant_for_domain_slots` |
| A slot's level claimed rather than shown: an email-code sign-in in a slot that asks for an account or an organization | the verifier computes the level from the token and its own trust store (`kind`); the engine refuses to sign below the slot; the verifier reports `insufficient-level` | `assurance_levels::an_organization_identity_reaches_l3`, `…a_token_from_an_email_code_counts_as_one_wherever_it_is_from`, `…a_slot_requiring_evidence_needs_it_in_the_basis` |
| A slot no signature could fill (L4, L5, a phone code before attestations exist) | refused at preparation | `assurance_levels::prepare_refuses_a_slot_no_signature_could_fill` |
| An identity provider's token signed with a key or algorithm that no longer proves anything | the trust list's algorithm policy: minimum key size, end dates, and only a trusted timestamp from before an end date keeps older evidence | `algorithm_policy::a_short_rsa_key_is_refused`, `…past_its_end_an_rsa_token_counts_only_under_an_earlier_timestamp`, `algorithms::tests::*` |
| A timestamp whose algorithm has ended, used to date or rescue anything | it counts only if a later timestamp that counts covers it; judged from the end of the file back | `algorithm_policy::a_timestamp_relying_on_an_ended_algorithm_is_no_evidence`, `workflow::tests::a_later_timestamp_keeps_one_whose_algorithm_has_ended` |
| A timestamp authority's key stolen: tokens dated at will | `tsa_distrusted` in the trust store: from `distrusted_after` its timestamps are not trusted time, other authorities under the same root still count | `tsa_distrust::a_stamp_before_the_distrust_counts_and_one_at_or_after_it_does_not`, `…one_authority_is_distrusted_without_the_others_under_the_same_root`, the shared vectors `spec/vectors/tsa-distrust/` |
| A trust-list key stolen: a forged list with a huge `sequence` that would shut real lists out | the key-chain rule (`trust_list`): the first real list signed by the next key in the pinned chain wins over any sequence, the old key's lists are then refused, and only the chain's last key can pre-commit more keys | `trust_list_rotation::every_vector_case_holds` (`spec/vectors/trust-list-rotation.json`, also run by the app, the verifier module and the hosted service's clients) |
| Token lifting/replay to another key or document | nonce binding | `ffi_token_bound_to_one_document_cannot_sign_another` |
| Crash on hostile input | bounds checks, `catch_unwind` at the FFI | `ffi_garbage_input_never_crashes_the_host`, `robustness.rs`, `core/fuzz` |
| A document from a newer engine build, signed or judged by an older one (terms it does not know dropped or misread) | version check before anything else is parsed; refused with "unsupported version" (code 16), never signed, never reported invalid | `schema_versions::a_newer_version_is_neither_verified_nor_signed`, `ffi_a_document_from_a_newer_build_is_refused_with_its_own_code`, `signpdf-wasm` `a_document_from_a_newer_build_asks_for_a_reload` |
| Revision chain moved to an older version (downgrade) | version is part of the prepared terms; a newer-then-older chain fails | `schema_versions::a_revision_cannot_move_a_document_to_an_older_version` |
| Old documents broken by a new engine build | compatibility corpus verified on every test run | `schema_versions::every_corpus_document_gets_the_verdict_its_build_gave` and the rest of `schema_versions.rs` |
| An envelope, a page change or anything else slipped in with a document timestamp (anyone can get one from an authority) | only validation data and one invisible timestamp field may follow a signature; no other object may be added or changed | `ltv::a_new_envelope_cannot_ride_along_with_a_document_timestamp`, `…page_content_cannot_change_under_a_document_timestamp`, `…the_catalog_may_only_gain_validation_data`, `…an_annotation_cannot_ride_along_with_a_document_timestamp` |
| Junk, or anything but certificates, OCSP responses and CRLs, in the validation data; earlier evidence removed | each new DSS entry must parse as its kind; entries are append-only; no `/VRI` | `ltv::the_validation_data_holds_only_certificates_ocsp_responses_and_crls`, `…validation_data_cannot_be_removed_or_extended_with_other_entries` |
| Validation data appended without a document timestamp, or changed under one | whole-file coverage; the token's imprint | `ltv::unsigned_validation_data_after_a_document_timestamp_is_detected`, `…bytes_under_a_document_timestamp_cannot_change` |
| Forged revocation evidence (another CA's response, a responder the issuer did not delegate) | OCSP/CRL signature, `CertID` and delegation checks; refused before it is written | `ltv::only_evidence_about_the_document_s_timestamps_goes_in`, `ltv::tests::ocsp_responses_are_checked`, `…a_delegated_responder_must_be_the_issuer_s_and_allowed_to_sign_ocsp` |
| A timestamp from an authority whose certificate was revoked before it | revocation evidence in the DSS makes it untrusted | `ltv::a_tsa_revoked_before_the_timestamp_proves_nothing` |
| A stolen identity-provider key signs after it was distrusted, writing an `iat` from before | `distrusted_after` is judged against trusted time only, never `iat` or the device clock | `trusted_time::a_distrusted_key_vouches_only_for_signatures_stamped_before_the_cut_off`, `trust::tests::the_end_of_a_window_is_judged_against_trusted_time_only` |
| A retired key used after its rotation | `not_after` against trusted time | `trusted_time::a_retired_key_vouches_only_for_signatures_stamped_before_its_end` |
| A token from an email-code provider's key counted with no independent time at all | `requires_trusted_time`: `no-trusted-time` until a trusted timestamp covers the signature | `trusted_time::an_issuer_that_requires_trusted_time_is_trusted_once_the_envelope_is_stamped` |
| A key window widened by the document (members added to the archived JWK) or by merging another store | windows come from the trust store only; merging only narrows | `trusted_time::a_key_window_is_the_trust_store_s_never_the_document_s`, `trust::tests::merging_narrows_windows_and_never_widens_them` |
| An untrusted timestamp passed off as the "existed before" time | only trusted timestamps count | `trusted_time::an_untrusted_timestamp_is_no_evidence` |
| Browser-launch command injection (Windows) | `rundll32 url.dll,FileProtocolHandler`, http(s) only | `signpdf-auth` `only_http_urls_are_launched` |

## 7. Residual risks and limits

- **The IdP is a trusted third party**. A breached or coerced provider, or a taken-over
  account, can sign as its users. Pinning prevents forgery by *others* but not by the provider.
- **Key distribution.** A verifier is only as good as its `trust.json`. Keys fetched over TLS at
  refresh time are trusted from then on (trust-on-refresh). Documents signed with a key that a
  verifier never saw before it was rotated out report `unknown-key`.
- **Device clock.** Without a trusted signature timestamp, "token valid at signing time" relies
  on the signer's clock (bounded below by the token's `iat`). Envelopes whose policy is
  `signature_timestamps = none` rely on it by design (§4). Their trusted bound is the document
  timestamp added when they end: for a signer who signed days earlier, the bound is days wide.
- **Key windows are as good as the trust store.** Key-window checks never use the verifier's
  clock, so they cannot tell whether a key's end has passed: an identity without trusted time stays
  `no-trusted-time`, even when the window ended long ago and no timestamp can now come in time.
  The start of a window is checked against the token's `iat`, which the key holder writes; that
  is enough because a key cannot be stolen before it exists. Windows a verifier never received
  (a stale `trust.json`) are not applied.
- **Revocation is judged from the document only.** The verifier never fetches: a timestamp's
  TSA chain is checked against the evidence in the document's DSS, and without any it is trusted
  as before (chain to an anchor). There is no freshness policy beyond "the evidence speaks for the
  timestamp's time" (§4), a delegated OCSP responder's own revocation is not checked, and only
  the timestamp algorithms are supported (RSA PKCS#1 v1.5 with SHA-2, ECDSA P-256); evidence
  signed otherwise is not used. The newest document timestamp's own chain has no evidence until
  the next renewal adds it.
- **A timestamp token is the authority's.** Nothing covers the token of the last timestamp
  (a document timestamp, or the last signature's timestamp): the parts of its CMS that the
  authority's signature does not cover (version numbers, the list of digest algorithms, the
  certificates it carries) can be changed. The document's SHA-256 then changes; either the token
  no longer verifies and the timestamp is reported untrusted, or the change is to a field no
  check depends on and nothing else changes. No signature's verdict changes either way, and a
  later document timestamp covers the token (`robustness::mutated_sealed_documents_…`).
- **Other tools' long-term validation is not accepted.** A DSS with `/VRI` entries, or
  validation data added without a document timestamp after it (as some PDF editors do), fails
  SignPDF's stricter rules (§2).
- **Approval, not certification, signatures.** Third-party PDF viewers apply their own
  modification-detection policies. SignPDF's own verifier enforces the stricter rules in §2.
- **A drawn or typed signature is decoration.** It is supplied by the signer, drawn beside the
  verified caption (`Signed by:`, email, key code), and proves nothing about who signed. A typed
  signature is the outlines of whatever name the signer typed: the typed text is **not a claim**,
  the engine never records it as text, and nothing checks it against the verified identity. The
  verifier makes sure the drawing is pen strokes or filled paths in one colour that stay in their
  area, and from schema version 6 that it is the one the signer's record keeps; the report says
  `drawn` or `typed` from the record. The glyph outlines are made on the signer's device from a
  font the host ships, so the document embeds no font, and the outlines follow a simple layout
  (no shaping): scripts that need shaping are refused rather than drawn wrongly.
- **Rendering is part of the format.** Because the verifier compares what is drawn with what the
  engine draws, a change to the engine's rendering makes documents signed before it fail. A test
  pins the exact output (`pades::appearance_tests::the_rendering_is_pinned`); to change how
  something is drawn, keep the old rendering and accept either.
- **A sign-in can be talked out of someone.** An attacker can start a real SignPDF sign-in for
  their own key, send the victim the link, and ask for the address the browser ends on (a
  "can't reach 127.0.0.1" page): that address lets the attacker finish the sign-in and sign as
  the victim. No check in a serverless design stops this; the app warns, during every sign-in,
  never to send anyone an address from the browser.
- **The dev identity provider vouches for anyone.** It is accepted only through an explicit
  opt-in that release builds of the app and the browser verifier do not offer.
- **The certificate of completion is a summary, not proof.** It is an unsigned page that anyone
  can produce; it says so in its first line.
- **A consent record is the host's word.** The engine proves that the signer's key sealed the
  record and that nobody changed it since; it cannot prove that the disclosure was shown, or that
  the hash is that of a published text. The host's own records (and the published texts) carry
  that.
- **The UTC offset is the device's.** Like the device clock, it is self-reported. A date-signed
  field shows the date the signer's device was on; it is not a location claim.
- **The service link is the preparer's choice.** It is checked to be a plain `https` URL, not to
  belong to any particular service: a viewer shows its host name so that the reader can judge it.
- **Characters the font lacks.** Field values and names are drawn with the built-in Helvetica
  font, which covers Western European text (the WinAnsi range). Any other character is drawn,
  and recorded in the annotation's `/Contents`, as `?`; the envelope keeps the value as typed,
  and that is what the verification report shows. The verifier accepts two renditions of a value
  in `/Contents`: the current one, and the one written before accented characters were drawn
  (every non-ASCII character as `?`), so that older documents still verify. A verifier older
  than this change rejects a new document whose field values contain accented characters.
- **Mutations that lopdf tolerates.** Verification parses with `lopdf`; structurally broken
  PDFs are rejected, never accepted.
  - An object the cross-reference lists but lopdf cannot read cannot be redefined by a later
    revision.
  - A reference inside such an unreadable object is not seen, so it does not reserve its number
    against a later revision.
  - The source document itself may be read differently by lopdf and by viewers. A revision may
    not rewrite an object whose earlier definition is ambiguous that way.
  - An object a viewer finds only by rebuilding a broken cross-reference is not covered. pdf.js
    does that when it meets a broken entry: it scans the whole file for object headers, including
    the bytes inside the objects of later increments. Keeping such scans from finding anything in
    an increment's objects is a known follow-up.
- **Timestamp tokens without an ESS attribute are accepted.** RFC 3161 asks every token to name
  its signing certificate in an ESS `signing-certificate(-v2)` attribute. The verifier refuses a
  token whose attribute names another certificate, but accepts one without the attribute,
  because the experimental test documents lack it. The chain and purpose checks (§4) are what
  keep a certificate from acting as a TSA.
- **Review of 2026-10-27.** Its four engine findings are fixed, each with a test that fails on
  the engine as it was ([`SECURITY_REVIEW_2026-10-27.md`](SECURITY_REVIEW_2026-10-27.md)).
- **A document's source digest is the preparer's word.** In an envelope of several documents,
  each `source_digest` says which file the document was made from; the combined PDF cannot
  prove it, since combining writes a new file. Anyone holding the original can compare its
  SHA-256, and combining is deterministic for one engine build (the same files in the same
  order give the same bytes), but a later build may combine differently.
- **What combining drops.** A combined PDF keeps each page as it is drawn, its annotations,
  forms (a repeated top-level field name is renamed), layers and attachments, but not
  document-level scripts and actions, page-level actions, tags (the logical structure, used by
  screen readers), XMP metadata, page labels, article threads, XFA forms or usage rights (which
  unlock features of one maker's viewer). A document that
  needs them should be sent in an envelope of its own.
- **A convenience copy is not signed.** It shows what the envelope shows, with a banner; only the
  combined PDF verifies.
- **Large images are not kept when parsing.** To sign a 50 MB document in a phone browser, the
  engine replaces the bytes of image XObjects over 64 KiB by a placeholder, or by their SHA-256
  where revisions are compared. No check reads image bytes; the review of this filter, its
  findings and its tests are in [`SECURITY_REVIEW_LOAD_FILTER.md`](SECURITY_REVIEW_LOAD_FILTER.md).

## 8. Envelope schema versions

The envelope carries a `schema_version`. Browsers, servers and native apps may run different
engine builds at the same time, and from the first hosted release a signed document must stay
verifiable for as long as anyone keeps it. The engine's rules are in
`core/signpdf-core/src/schema.rs`.

| Version | Written by | Status in this build |
| --- | --- | --- |
| 1, 2 | June 2026 development builds | experimental, refused |
| 3 | October 2026 | experimental, verified and signed (`OLDEST_SCHEMA_VERSION` = 3): a slot's requirement is `min_assurance` (`consumer`, `enterprise`), read as `min_level` L1 or L3 and written back as it was |
| 4 | from 27 October 2026 | experimental, verified and signed: `min_level` (L1–L5) and `required_methods` replace `min_assurance`; refuses a documents index |
| 5 | from 27 October 2026 | experimental, verified and signed: version 4 with the optional `documents` index of an envelope of several documents; refuses a recorded drawing (a drawn signature's strokes are shown, not recorded; a typed one is refused) |
| 6 | from 27 October 2026 | experimental, verified and signed: version 5 whose signature records keep the signer's drawing (`drawing`: pen strokes or a typed signature's filled paths), which the verifier redraws; refuses number fields and a `verify_at` address |
| 7 | from 30 October 2026 | experimental, verified and signed: version 6 with number fields (`field_type` `number` and their `number_format`: decimal places, range, drawing style) and the optional `verify_at` address, which the document-ID stamp draws on a second line |
| 8 | from 7 November 2026 | experimental, verified and signed: version 7 with checks on text fields (`value_format`, `length`, `check_message`), a currency in number formats, and formula fields; its initials stamps are the letters of the verified email address |
| 9 | from 8 November 2026 | experimental, written by prepare (`SCHEMA_VERSION` = 9): version 8 with the required `initials_rule` (`name-v1`): initials stamps are the letters of the slot's name, which the preparer signs, else of the verified email address (`spec/envelope-format.md` §4.6) |
| newer | a later build | refused with "unsupported version" (see below) |

**Experimental until the first hosted release.** No document written before that release
needs to verify later. Until then the current version may change in place,
`OLDEST_SCHEMA_VERSION` may rise, and the corpus fixtures of an experimental version are replaced
when its format changes. The hosted release fixes its version as the first **stable** one. From
then on:

1. **Every stable version from `OLDEST_SCHEMA_VERSION` to `SCHEMA_VERSION` verifies, forever.** A
   new version adds a decoder and an encoder. It never removes a stable one, and never raises
   `OLDEST_SCHEMA_VERSION` above it.
2. **Each version keeps its own rules.** Anything that decides whether a version-`n` document is
   valid stays as it was for version `n`. That covers the JSON shape, the strings that signature
   records and audit entries sign (`record_signing_payload`, the audit-entry payload), the
   prepared terms compared between revisions, and how fields and signature boxes are drawn
   (§7, "Rendering is part of the format"). A decoder maps its version into the in-memory model
   **without loss**: anything it dropped would escape the revision-chain comparison in §2.
3. **Any change to a stable version's shape or to what a revision may contain is a new
   version.** An older build then refuses the document instead of misreading it. (Version 3 grew
   in place during October 2026, with `policy.signature_timestamps` and then with the date terms
   of fields, the signer's UTC offset, the consent record in audit entries and the service link.
   That was acceptable only because it is experimental: a build from before a change ignores the
   new terms, so it may drop them when it signs, and it cannot recompute the hash of an audit
   entry that records a consent. Hosts upgrade their signing pages and servers together.)

These hold already, for every version:

4. **An envelope keeps its version for life.** Sign and decline write the envelope back in the
   version it was prepared with, so a newer build can finish a document an older build prepared
   (an envelope in flight during an upgrade). The version is part of the prepared terms. A
   revision that changes it fails verification, and so does a chain in which a newer-version
   revision is followed by an older one.
5. **A build never signs a newer version.** Writing back an envelope with terms it does not know
   could drop them. Prepare (on a document that already carries an envelope), sign, decline,
   verify, read-envelope and the certificate refuse it with
   `SignPdfError::UnsupportedSchemaVersion`, before reading anything but the version number.
   That is code **16** on the FFI (`SIGNPDF_ERR_UNSUPPORTED_VERSION`) and on the WASM ABI
   (`ERR_UNSUPPORTED_VERSION`). Verification does not report such a document as invalid, since
   the build cannot judge it. The app tells the user to update; the browser verifier and the
   signing page tell them to reload the page; `signpdf verify` exits with status 3.

**Compatibility corpus.** `core/signpdf-core/tests/corpus/v<N>/` holds documents made by a
build of each supported version, each with that build's own verification report. Their reports
from before assurance levels give `assurance` (`consumer`, `enterprise`); the corpus check reads
it as the level today's verifier computes for the same identity (the test issuer is an account
provider, so `consumer` is L2 and `enterprise` L3). The v9 set, 2026-11-08-d042bca, has the
documents of the v8 set with the signers named in their slots, so their initials stamps come from
the names (`AE`, `BB`). The v8 set, 2026-11-07-d13a087, has the documents of the v7 sets with
checked text fields, an amount in a currency and a formula field. The second v7 set,
2026-11-02-176e807, has the v7 documents written the way many-signer envelopes needed: the
envelope attachment compressed and each signature's placeholder sized to its CMS. The first v7
set, 2026-10-30-72004c0, has the
documents of the v6 set with a number field Bob fills (`12500` kept as `12500.00`, drawn
`12 500,00`) and the 'verify at' address `verify.example.com` on every document-ID stamp; its
reports carry the findings' codes, which later builds must reproduce. The v6 set,
2026-10-27-51aa0a7, has the
documents of the v5 set
with Alice's signature typed (the glyph outlines of her name, filled) and Bob's drawn, both kept
in their records. The v5 set, 2026-10-27-c906265, has the documents of
the v4 set and an envelope of three documents combined into one PDF, with signers' fields in two
of them (`prepared-documents.pdf`, `signed-documents.pdf`). The v4 set, 2026-10-27-f1cdbea, has the
documents of the last v3 set with `min_level` slots (Bob's asks for an organization identity, L3,
and is filled by one) and an envelope whose signature timestamps are `optional`. Before it, there
were five v3 sets: main at 9192802; 6a5e26b, whose documents add a filled dropdown and a PAdES B-T
signature timestamp; and 7a0326c, whose documents state each `signature_timestamps` policy
(`required` with both signatures timestamped and a decline without one, and `none`; the earlier
sets state none, so `optional`); and 2026-10-27-a14ed87, whose documents add a date-signed field
drawn `DD/MM/YYYY`, a date the signer picked drawn `MM/DD/YYYY`, each signer's UTC offset and
consent to electronic records, and a service link; and 2026-10-27-22a9d80, whose documents add
validation data and document timestamps after the last signature (PAdES B-LTA, with the demo's
test TSA now issued by a test root CA that answers OCSP for it) and an envelope without signature
timestamps sealed by one document timestamp. The current version's fixtures must cover all of
these. On every `cargo test`, `tests/schema_versions.rs` checks that
this build:

- reaches the same verdicts;
- verifies the documents against pinned keys;
- decodes every revision losslessly;
- can still finish and decline them.

`web/verifier/versions.mjs` runs the corpus through the built browser module. Fixtures of a
stable version are never regenerated.

**Adding a version `n+1`:**

1. Add a `v<n+1>` decoder and encoder in `schema.rs`. If `n` is stable, keep `v<n>`'s and keep
   every version-specific rule (point 2) selectable by `env.schema_version`. If `n` is
   experimental, it may instead be dropped: raise `OLDEST_SCHEMA_VERSION` and delete
   `corpus/v<n>/`.
2. Set `SCHEMA_VERSION = n+1`.
3. Commit, then run `scripts/make-schema-corpus.sh <that commit> <date>-<sha>` and commit the
   new `corpus/v<n+1>/` fixtures (`the_corpus_covers_every_supported_version` fails until then).
4. Update the table above, and mark the version stable if this is the hosted release.
