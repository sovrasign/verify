# SignPDF envelope format

**Status:** experimental until the first hosted release (§13.1); open items in §14.
**Envelope schema version:** 9 (the newest this specification describes).
**Oldest supported version:** 3.
**Specification revision:** 9.0 (2026-11-08).
**Licence:** this text is licensed under CC BY 4.0 (`LICENSES/CC-BY-4.0.txt`); the test vectors
it refers to are CC0 (`LICENSES/CC0-1.0.txt`).
**Copyright:** 2026 Sovrasign LLC and contributors.

This document says what a SignPDF document is and how to verify one, so that anyone can write
a verifier without reading the reference implementation. Until the open items of §14 are done,
a few low-level rules (the canonical CMS encoding, the PDF object rules and the drawing of field
values) are given by `docs/SECURITY_MODEL.md` §2 and the reference implementation. That is the
Rust crate `signpdf-core` in this repository (`core/signpdf-core`); where this text and the code
disagree, the disagreement is a bug to report (`SECURITY.md` for anything that could make a
verifier accept a forgery).

The specification is versioned with the envelope schema: its major revision number is the
newest schema version it describes, and `core/signpdf-core/tests/format_spec.rs` fails when the
engine's `SCHEMA_VERSION`, `OLDEST_SCHEMA_VERSION` or catalogue of finding codes moves without
this text.

## Contents

1. Conventions
2. Overview
3. Document structure
4. The envelope
5. Identity binding
6. Signature records and the audit log
7. Revision rules
8. Time
9. Trust lists
10. The verification algorithm
11. The verification report and its findings
12. Test vectors
13. Versioning
14. Open items

Appendix A: finding codes.

## 1. Conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY and OPTIONAL are to be
read as described in RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

- **Hex** is lower-case hexadecimal without a prefix. **Base64** is RFC 4648 §4 with padding;
  **base64url** is RFC 4648 §5 without padding.
- **SHA-256(x)** is the hex SHA-256 of the bytes `x`. `‖` is byte concatenation.
- **Times** are RFC 3339 strings. Times the engine writes are UTC and end in `Z`.
- A **revision** is the PDF as it was after one signature or document timestamp: the file's
  first *n* bytes, where *n* is the end of that signature's second byte range.
- **Prepared terms** are the envelope members that no revision after the preparer's may change
  (§4.2).

### 1.1 Normative references

- ISO 32000-2 (PDF 2.0), incremental updates and signature fields.
- ETSI EN 319 142-1 (PAdES baseline signatures, B-B, B-T, B-LT, B-LTA).
- RFC 5652 (CMS), RFC 5035 (ESS `signing-certificate-v2`), RFC 3161 (time-stamp protocol),
  RFC 6960 (OCSP), RFC 5280 (certificates and CRLs).
- OpenID Connect Core 1.0 (ID tokens), RFC 7515 (JWS), RFC 7517 (JWK), RFC 7638 (JWK
  thumbprints), RFC 7518 (ES256, RS256).
- FIPS 186-5 / SEC 1 (ECDSA P-256, uncompressed SEC1 public keys).
- `docs/SECURITY_MODEL.md` §2 to §5 of this repository, for the detailed PDF object-level rules
  of a revision (§7.3 here) until they are moved into this text (§14). Where this specification
  refers to it, the referenced lists are normative.

### 1.2 Conformance

A **conforming verifier** implements §10 and reaches, for every test vector of §12, the verdict
its expected file states (`valid`, `integrity_ok`, `identities_trusted`, or a refusal for
`outcome: error`). It SHOULD report the same finding codes. A **conforming writer** produces
documents that a conforming verifier reports valid under a trust list pinning the identities it
used. A verifier that cannot read a document's schema version MUST refuse it (§13.2) and MUST
NOT report it invalid.

## 2. Overview

A SignPDF document is an ordinary PDF that grows by incremental updates, one per action. Each
action is a PAdES signature by a fresh, single-use ("ephemeral") ECDSA P-256 key. Who held that
key is shown by an OpenID Connect ID token from an identity provider, whose `nonce` binds the
token to the key and to the exact bytes signed (§5). The token and the provider's public key are
archived in the document, so verification needs no network. A JSON **envelope**, attached to the
PDF and rewritten by each revision, carries the terms (signers, fields, policy), one record per
signature and a hash-chained audit log.

| Revision | Written by | Adds |
| --- | --- | --- |
| 0 | the preparer | a visible document-ID stamp, one signature field, the envelope (title, signer slots and their identity policies, fields, policy, the preparer's identity and audit entry) |
| 1 to *n* | one signer or decliner each | one signature field (visible at the signer's primary signature field, or invisible), the signer's field values drawn as read-only annotations, the envelope with one new signature record and one new audit entry |
| after any of them | a host | optionally validation data (a `/DSS`), then one document timestamp |

A verifier checks four things: every signature is sound and the last one covers the whole file;
each revision is exactly the action it claims to be (§7); each identity is anchored in the
verifier's trust list (§9); and the envelope's rules (order, expiry, identity policies, audit
chain) hold.

## 3. Document structure

### 3.1 Signatures

1. Every signature field value MUST be a PAdES baseline signature: `/Filter /Adobe.PPKLite`,
   `/SubFilter /ETSI.CAdES.detached`, a CMS `SignedData` over the field's `/ByteRange`, signed
   with ECDSA P-256 and SHA-256, carrying the ESS `signing-certificate-v2` attribute and a
   self-issued certificate for the ephemeral key.
2. The CMS MUST be byte for byte the structure the reference writer emits for the same key,
   digest, certificate and signing time (a canonical form), so that no unsigned CMS field
   (content type, algorithm identifiers, the embedded certificate) can be altered. A verifier
   MUST reject any other encoding (`signature_altered`).
3. A writer MUST NOT add an RFC 3161 `signature-time-stamp` unsigned attribute (PAdES B-T) to a
   signature unless the envelope's `policy.signature_timestamps` allows it (§8.2), and MUST NOT
   add one to the preparer's signature. A signer revision that departs from the policy is not an
   integrity failure (a timestamp is an unsigned attribute and does not change what was signed):
   a verifier reports it with a warning, `timestamp_unexpected` or `timestamp_missing` (§8.2).
4. `/ByteRange` MUST be four non-negative integers `[0 a b c]` within the file, and the gap
   between `a` and `b` MUST be exactly the field's `/Contents` hex string, delimiters included:
   lower-case hex, the DER signature followed by zero padding only (`signature_malformed`).
5. The last signature or document timestamp MUST cover the whole file (`b + c` = file length).
   Bytes after it are an unsigned update (`unsigned_changes`).
6. Signatures and document timestamps end distinct revisions, in file order. The first MUST be
   the preparer's.

### 3.2 The envelope attachment

Each revision that adds a signature (not a document timestamp) embeds a new copy of the
envelope as an embedded-file stream: `/Type /EmbeddedFile`, `/Subtype /application#2Fjson`,
with a file specification whose file name is `signpdf-envelope.json` and `/AFRelationship
/Data`. The engine does not reference it from the catalog's `/Names` or `/AF`, so that the
catalog does not change between revisions; a verifier MUST find it by its file specification.
The **envelope of a revision** is the copy that revision added. A document timestamp MUST NOT
add one.

The envelope is UTF-8 JSON (RFC 8259). Its members are listed in §4; a verifier MUST read
`schema_version` before anything else (§13.2).

### 3.3 Incremental updates

Each revision after the first is one incremental update in the form the reference writer
produces: one classic cross-reference table chained by `/Prev`, with in-use entries only, each
object number once, each entry pointing at its own object inside the increment, and nothing else
in the increment; the trailer's `/Root`, `/Info` and `/ID` unchanged. The detailed rules (which
earlier objects an increment may list, how a reader finds an object at its entry, object
streams, numbers left undefined) are those of `docs/SECURITY_MODEL.md` §2 item 4 ("what the
increment defines is read from its own bytes"). A verifier MUST read each increment's
cross-reference from its bytes, not through a PDF library's repaired view of the file.

### 3.4 Document timestamps and validation data

After any revision, a host MAY add validation data and then one document timestamp:

- the document timestamp is an invisible signature widget whose value is a `/DocTimeStamp`
  dictionary with only `/Type`, `/Filter`, `/SubFilter /ETSI.RFC3161`, `/ByteRange` and
  `/Contents`; its token's message imprint is the hash of everything outside its `/Contents`;
- the catalog may only gain or change `/DSS`; the DSS may only gain entries in `/Certs`,
  `/OCSPs` and `/CRLs` (no `/VRI`), keeps every entry it had, and each new entry is a new,
  unfiltered stream holding one certificate, one successful OCSP response or one CRL;
- nothing else may be added or changed.

The full list is `docs/SECURITY_MODEL.md` §2 item 5. A signer MAY sign after a document
timestamp; their record's `signed_prefix_len` then includes it.

## 4. The envelope

### 4.1 Members (schema version 9)

| Member | Type | Prepared term | Meaning |
| --- | --- | --- | --- |
| `schema_version` | integer | yes | §13 |
| `envelope_id` | string | yes | the envelope's identifier, chosen by the preparer |
| `title` | string | yes | non-empty |
| `created_by` | string | yes | the preparer's name as the host gave it (display only) |
| `created_at` | string | yes | RFC 3339 preparation time (device clock) |
| `created_by_pubkey` | string | yes | base64 uncompressed SEC1 P-256 public key of the preparer's ephemeral key |
| `created_by_id_token` | string | yes | the preparer's ID token (compact JWS) |
| `created_by_idp_jwk` | string | yes | the JWK (JSON text) that signed it |
| `created_by_issuer`, `created_by_email`, `created_by_audience` | string | yes | mirrors of the token's `iss`, verified `email` and the `aud` it was accepted for |
| `source_digest` | string | yes | SHA-256 of the source PDF |
| `source_len` | integer | yes | its length: revision 0 begins with exactly these bytes |
| `documents` | array | yes | from version 5, OPTIONAL: the documents index (§4.5); omitted when empty |
| `signers` | array of slot | yes, except `status`, `public_key` and `fingerprint` | §4.3 |
| `fields` | array of field | yes, except `value` | §4.4 |
| `policy` | object | yes | `signing_order` (`sequential` or `parallel`), `allowed_signature_types` (array of strings), OPTIONAL `expiry` (RFC 3339), OPTIONAL `signature_timestamps` (`required` or `none`; absent means `optional`, §8.2) |
| `signatures` | array of record | no (append-only) | §6.1 |
| `audit_log` | array of entry | no (append-only) | §6.2 |
| `service_link` | string | **no** | OPTIONAL `https` URL that opens the envelope in the service that sent it (§7.5) |
| `verify_at` | string | yes | from version 7, OPTIONAL: a short verifier address (no scheme, 40 characters at most) the document-ID stamp draws as "Verify at …" |
| `initials_rule` | string | yes | from version 9, REQUIRED: the rule that derives the letters stamped in a signer's further initials fields (§4.6); `name-v1` is the only value. Absent before version 9, where the email rule applies |

A writer MUST NOT add members this table does not list for its version. A reader MUST decode a
supported version **without loss**: every member it does not understand is an error, never
silently dropped, because a dropped member would escape the comparison of prepared terms.

### 4.2 Prepared terms

The prepared terms are: `schema_version`, `envelope_id`, `title`, every `created_*` member,
`source_digest`, `source_len`, `documents`, `policy` (including `signature_timestamps`),
`verify_at`, `initials_rule`, each slot's members except `status`, `public_key` and `fingerprint`, and each
field's members except `value`. Revision 0 sets them; every later revision MUST carry them
unchanged (`terms_changed`).

### 4.3 Signer slots

| Member | Meaning |
| --- | --- |
| `id` | unique among slots, non-empty |
| `name`, `handle`, `role` | display text from the preparer (`handle` is usually an email); never evidence of who signed. From version 9, `name` is also what the initials stamps are derived from (§4.6) |
| `order` | 1-based; with `sequential`, every pending slot sharing the lowest `order` may act |
| `status` | `pending`, `signed` or `declined` |
| `identity_policy` | §5.3 |
| `public_key`, `fingerprint` | set when the slot is filled: the signer's ephemeral key and its fingerprint (§6.1) |

### 4.4 Fields

A field has `id`, `field_type`, `page` (0-based), `rect` (`x`, `y`, `w`, `h` in PDF points,
origin bottom-left), `assigned_signer` (a slot `id`), `required`, and OPTIONAL `value`,
`label`, `group`, `options`, `date_format`, `signing_date` (omitted when false),
`number_format` and, from version 8, `value_format`, `length`, `check_message` and `formula`.
`field_type` is one of `signature`, `initials`, `date`, `text`, `multiline`, `checkbox`, `radio`,
`dropdown`, from version 7, `number` and, from version 8, `formula`.

- A field's `value` is written only by the revision of its assigned signer, once, and only for
  that signer's empty fields (`field_tampered`). A decline fills none.
- `date`: `YYYY-MM-DD` whatever `date_format` (`YYYY-MM-DD`, `DD/MM/YYYY`, `MM/DD/YYYY`,
  `DD.MM.YYYY`, `DD-MM-YYYY`, which only change what is drawn). A `signing_date` field holds the
  signer's local date at signing: `signed_at` moved by the record's `utc_offset` (§6.1).
- `checkbox` and `radio`: `true` or `false`; at most one `true` per radio `group`, all of one
  group assigned to one signer.
- `dropdown`: one of `options`.
- `number`: a canonical decimal with exactly `number_format.decimals` places, within
  `number_format.min` and `max` when given; drawn in `number_format.style`. From version 8,
  `number_format.currency` (OPTIONAL, an ISO 4217 code) makes it an amount: `decimals` MUST be
  the currency's minor unit, and the value is drawn after the code (`EUR 12 500,00`).
- `text` and `multiline`, from version 8: OPTIONAL `value_format` `{kind, currency?, country?,
  pattern?}` with `kind` one of `email`, `phone`, `amount` (with `currency`), `postal_code`
  (with `country`, ISO 3166-1 alpha-2), `iban`, `us_ssn`, `us_ein` and `pattern` (with
  `pattern`, a restricted regular expression of at most 200 characters that the whole value
  must match: no back-references or look-around, matched in linear time; the grammar is that of
  the reference `pattern.rs`). No kind takes another's parameter, and no other member is
  allowed. OPTIONAL `length` `{min?, max?}` (at least one, 0 to 2000, `max` at least 1 and not
  below `min`), counted in Unicode scalar values on the stored value. A non-empty value MUST be
  the canonical form the format gives it (`+33612345678`, `SW1A 1AA`, `123-45-6789`, an email
  with its domain in lower case), within the length; an empty value is no answer. The value is
  drawn as its format shows it: `us_ssn` as `•••-••-` and `us_ein` as `••-•••` followed by the
  last four digits (the envelope keeps the whole value), `iban` in groups of four, `amount`
  after its currency code; other kinds as stored.
- Any field with a check (a `value_format`, a `length` or a `number_format`), from version 8:
  OPTIONAL `check_message`, 1 to 200 characters without control characters, the preparer's own
  message shown to a signer whose value is refused. It is a prepared term but never decides
  whether a value or a document is valid. A `formula` field has none.
- `formula`, from version 8: REQUIRED `formula` `{expr, map}` and `number_format` (`decimals`,
  `style`, OPTIONAL `currency`; no `min` or `max`). `expr` is a formula of at most 2000 bytes in
  the language of the reference `formula.rs` (numbers, `{reference}`, `+ - * /`, comparisons,
  `sum`, `min`, `max`, `round`, `if`, `and`, `or`, `not`; exact decimal arithmetic, a quotient
  kept to 18 places rounded half up). A reference names a field by `id` (a `number`, a
  `checkbox`, a `dropdown` or another `formula`) or, when no field has that id, a radio `group`
  by its name. `map` (always written, `{}` when empty) gives, for each dropdown (by id) and radio
  group (by name) the formula reads, a decimal number for every one of its options (a radio
  option by its `label`), and nothing else. Every field a formula reads MUST be filled by the
  formula's own signer or, under a sequential policy, by a signer of a lower `order`; formulas
  MUST NOT read each other in a loop. The signer gives no value: when they sign, the value is
  computed from the revision's values (an empty number, an unanswered dropdown or radio group:
  0; a checkbox: 1 when `true`, else 0; a formula: its stored value), rounded half up to
  `number_format.decimals`, stored canonically and drawn like a `number`. The verifier computes
  every formula of the signer's revision again and rejects a value that differs
  (`formula_mismatch`).
- `signature` and `initials`: a signer's first signature field (their *primary* one: their
  first `signature` field, else their first `initials` field) is backed by their signature
  record and keeps no value; further ones get an engine-drawn stamp. A further `signature` field
  holds `<verified email> - Sig <first 8 hex digits of the signing key's fingerprint>`; a
  further `initials` field holds the letters of the envelope's initials rule (§4.6). The
  verifier derives both again and rejects any other value (`stamp_mismatch`).

**Rendering is part of the format.** The verifier redraws every field value, the document-ID
stamp and each signature box from the envelope and the verified identity, and compares the
content streams byte for byte (§7.3). The drawing rules are therefore normative; today they are
defined by the reference implementation (`pades.rs`, `ink.rs`, `numbers.rs`, `dates.rs`) and the
test vectors (§14).

### 4.5 Documents index (version 5 and later)

When present, `documents` has 1 to 20 entries, in order, each with `name` (1 to 200 characters,
no control or bidirectional-control characters), `first_page` (0-based), `page_count` (at least
1) and `source_digest` (SHA-256 of that document's own file before combination, a statement the
verifier cannot recompute). The first entry starts at page 0, each next one where the previous
one ends, and together they cover every page of the source (otherwise the preparer's revision
is not valid: `preparer_revision_invalid`).

### 4.6 Initials (version 9 and later: `initials_rule`)

The letters in a signer's further `initials` fields are derived from the slot's `name` (a
prepared term, so the preparer's signature covers it and a signer cannot change it) and the
email address the signer's identity provider verified (§5.2). The ID token's own `name` claim
is a profile name the account holder types and is never used. The envelope names the rule:

**`name-v1`** (the only rule of version 9):

1. Cut the slot's `name` into words at white space (Unicode `White_Space`). Leave out every word
   holding `@` and every word without a letter (Unicode `Alphabetic`).
2. While two words or more are left: leave out a first word that is a title (`MR`, `MRS`, `MS`,
   `MX`, `DR`, `PROF`, `MME`, `MLLE`) and a last word that is a generational suffix (`JR`,
   `SR`, `II`, `III`, `IV`), each compared after removing `.` and `,` and mapping to capitals.
3. Take the first and the last word (one word: that word); each gives its first letter
   (`Alphabetic`) mapped to capitals (Unicode's full case mapping, so `ß` gives `SS`). No
   Unicode normalization is applied: a letter followed by a combining accent gives the bare
   letter.
4. Every character of the result must be one the stamp font draws (WinAnsiEncoding, the
   Helvetica encoding of every engine-drawn text). A character outside it is replaced by its
   base letter when it is a Latin letter with a diacritic of Latin Extended-A (U+0100 to
   U+017F, for example `Ł` → `L`, `Ő` → `O`), U+0218 to U+021B (`Ș` `ș` → `S`, `Ț` `ț` → `T`),
   U+01A0, U+01A1 (`Ơ` → `O`), U+01AF, U+01B0 (`Ư` → `U`) or U+1EA0 to U+1EF9 (the Vietnamese
   letters: `A` up to U+1EB7, `E` to U+1EC7, `I` to U+1ECB, `O` to U+1EE3, `U` to U+1EF1, `Y`
   to U+1EF9); the reference table is `fold` in `core/signpdf-core/src/initials.rs`. If any
   character is still not drawable (another script), the name gives no letters.
5. When the name gives no letters (or none is left), use the verified email address: split the
   part before its first `@` at every character that is neither a letter nor a digit
   (Unicode `Alphabetic` or `Numeric`), take the first and last of the non-empty parts, each
   giving its first letter or digit mapped as in steps 3 and 4 (a part whose character cannot be
   drawn gives nothing). When that gives nothing either, the letters are `?`.

So `Felix Fairfax` gives `FF`, `Jean-Luc Picard` `JP`, `Ludwig van Beethoven` `LB`,
`Dr. Jane Smith Jr.` `JS`, `Madonna` `M`, `Łukasz Nowak` `LN`, and `Иван Петров` with
`ivan.petrov@example.com` gives `IP`. A writer MUST stamp, and a verifier MUST expect, exactly
these letters; `spec/vectors/initials-name-v1.json` holds the test vectors (§12.5).

**Before version 9** (no `initials_rule`): the letters come from the verified email address
alone: the first and last of the non-empty parts of the part before its first `@`, split at
every character that is neither a letter nor a digit, each giving its first letter or digit in
capitals (no font restriction); nothing gives `?`. These versions' documents keep that rule.

## 5. Identity binding

### 5.1 Keys and fingerprints

Each action uses a fresh P-256 key. Its public key is written base64 (uncompressed SEC1, 65
bytes); its **fingerprint** is SHA-256 of those 65 bytes.

### 5.2 The ID token

The preparer and every signer present an OpenID Connect ID token (compact JWS, ES256 or RS256)
whose `nonce` claim is:

```
nonce = SHA-256( SEC1 public key bytes ‖ ASCII bytes of the hex document digest )
```

where the document digest is `source_digest` for the preparer and the record's `doc_digest`
(§6.1) for a signer. A token with another `nonce` MUST be rejected: it is not bound to this key
and these bytes. The token MUST carry `email` and `email_verified: true` (Microsoft
organizational accounts: the `xms_edov` claim), its `aud` MUST be an application the verifier's
trust list allows for its issuer (§9), and it MUST have been valid (`iat` ≤ signing time ≤ `exp`,
with the reference implementation's 5-minute leeway) at the signing time of the revision. The
token and the JWK that signed it are archived in the envelope; the JWK is attacker-controlled
data until §9 anchors it.

### 5.3 Identity policies

A slot's `identity_policy` has OPTIONAL `allowed_issuers` (issuer strings, a Microsoft issuer
MAY contain `{tenantid}`, matched against `tid`), `required_email` (case-insensitive),
`required_domain`, `required_tenant`, `required_subject`, `min_level` (`L1` to `L5`, default
`L1`) and `required_methods` (`email-code`, `account`, `organization`, `phone`, …). The rules
are those of `docs/SECURITY_MODEL.md` §5: the verifier computes each identity's assurance level
from the token and its own trust list, never from the envelope; an identity below its slot is
not valid (`identity_insufficient_level`). Version 3 envelopes carry `min_assurance` instead (`consumer` reads as
L1, `enterprise` as L3) and a decoder MUST write it back as it was.

## 6. Signature records and the audit log

### 6.1 Signature records

Each signer revision appends one record:

| Member | Meaning |
| --- | --- |
| `kind` | `signed` or `declined` |
| `signer_id` | the slot it fills |
| `fingerprint`, `public_key` | the revision's ephemeral key (§5.1) |
| `algorithm` | `ECDSA_P256_SHA256` |
| `signed_at` | RFC 3339 signing time (device clock) |
| `timestamp_token` | OPTIONAL, legacy: base64 RFC 3161 token over the document before signing; reported, never used as a clock |
| `doc_digest` | SHA-256 of the file as the signer received it: the previous revision's bytes, `signed_prefix_len` long |
| `signed_prefix_len` | that length |
| `signature` | base64 DER ECDSA signature by the ephemeral key over the record payload below |
| `revision` | 0-based index of this record among the signature records (the first signer's is 0) |
| `id_token`, `idp_jwk`, `idp_issuer`, `idp_subject`, `idp_email`, `idp_audience` | the signer's token, the JWK that signed it, and mirrors of `iss`, `sub`, the verified `email` and the `aud` accepted |
| `utc_offset` | OPTIONAL `±HH:MM` between `-12:00` and `+14:00`: the signer's offset as the host reported it |
| `drawing` | from version 6, OPTIONAL: `{"kind": "drawn", "strokes": …}` or `{"kind": "typed", "paths": …}`, what the box shows beside the caption (§7.3) |

The record payload, signed by the ephemeral key, is the UTF-8 string:

```
signpdf-pades-rec-v2|<envelope_id>|<kind>|<signer_id>|<fingerprint>|<revision>|<doc_digest>|<signed_prefix_len>|<signed_at>
```

The record's key MUST be the key of the PAdES signature that ends its revision, and the slot's
`public_key` and `fingerprint` MUST be set to it.

### 6.2 The audit log

The log is append-only: each revision adds exactly one entry (the preparer's `prepared`, a
signer's `signed` or `declined`) and MUST NOT change earlier ones (`audit_log_rewritten`). An
entry has `seq`, `action`, `actor_fingerprint`, `actor_name`, `at`, `details`, `prev_hash`,
`entry_hash`, `signature` and OPTIONAL `esign_consent`.

```
content    = seq "|" action "|" actor_fingerprint "|" at "|" details "|" prev_hash
             [ "|" consent ]
consent    = "esign-consent=" version ";lang=" lang ";sha256=" hex [ ";ref-sha256=" hex ] ";at=" time
entry_hash = SHA-256(UTF-8 content)
signature  = base64 DER ECDSA signature of the ASCII entry_hash by the actor's key
```

`prev_hash` is the previous entry's `entry_hash`, or the string `GENESIS` for the first entry.
Every entry MUST be signed by a key the envelope knows (the preparer's `created_by_pubkey` or a
filled slot's key); an unsigned entry or an unknown actor breaks the chain (`audit_log_broken`).
The consent record's members are limited to characters needing no escaping: `version`
`[a-z0-9][a-z0-9.-]{0,63}`, `lang` a lower-case BCP 47 tag of 35 characters at most, 64-hex
hashes and a UTC time ending in `Z`; a malformed record is reported.

## 7. Revision rules

### 7.1 The preparer's revision (revision 0)

The first signature's key MUST be `created_by_pubkey`; the file MUST begin with `source_len`
bytes whose SHA-256 is `source_digest`; the preparer's additions MUST be limited to the
document-ID stamp and one signature field; the preparer's token MUST verify at `created_at` and
be bound (§5.2) to `created_by_pubkey` and `source_digest`; every slot MUST be `pending`, the
log MUST hold one `prepared` entry and no records; a documents index MUST match the pages (§4.5).
The prepared terms MUST follow the rules a conforming preparer enforces: a non-empty `title`; at
least one slot; slot `id`s non-empty and unique, `order` 1 or more, no `public_key` or
`fingerprint`; field `id`s unique, each field assigned to a known slot, on a page of the source
and within its visible area, with no `value`; field settings that suit the field's type (§4.4);
each radio group held by one slot with one `required` setting and at least two distinctly
labelled options; formulas that read only number inputs of the same or an earlier signer,
without loops; a usable `service_link` and `verify_at`. A preparer also refuses an expiry
already past and an identity policy it cannot fill; a verifier does not re-check those.

### 7.2 Signer revisions

Each later signed revision MUST be exactly one participant's action, replayed against the
envelope of the revision before it:

1. the prepared terms are unchanged (§4.2);
2. exactly one pending slot became `signed` or `declined`, bound to this revision's key;
3. exactly one record and one audit entry were appended; earlier ones are unchanged; the
   record's `idp_issuer`, `idp_subject` and `idp_email` are the verified token's `iss`, `sub`
   and `email`, and the entry's `actor_name` is that email and its `details` the reference
   writer's sentence (`<email> signed (revision <n>); verified as <email> via <iss>`, or
   `<email> declined to sign[ (<reason>)]; verified as <email> via <iss>`);
4. only that signer's empty fields were filled (§4.4);
5. the record's `signed_prefix_len` is the length of the previous revision, and `doc_digest`
   its SHA-256 (`unsigned_insertion` otherwise: something was slipped in between signatures);
6. the signer was entitled to act: in order (`sequential`: a slot of the lowest pending
   `order`), not after a decline, not after `policy.expiry` (§8);
7. the signer's token satisfies §5.2 and the slot's identity policy (§5.3);
8. the PDF increment holds only what §7.3 allows.

### 7.3 What a signer's increment may add

The increment only adds objects. The catalog may only gain an AcroForm, the AcroForm may only
gain one field (the signer's signature widget, on a page), and pages may only gain annotations.
The added annotations MUST be exactly the signer's signature widget and read-only texts drawing
their field values (every field of the signer that shows something has exactly one, and a
field that shows nothing has none), carrying only the entries the reference writer writes (no action, no
transform, no filter, no font but the standard one). Content streams, resources, the page tree,
and existing annotations or signatures MUST NOT change (`forbidden_change`). The verifier
redraws each annotation from the envelope and the *verified* identity (email, key code, signing
time, provider) and compares byte for byte. In the signature box's drawing area only the ink
rule holds: pen strokes, or (typed) closed filled paths in the engine's one colour, clipped to
the area; from version 6 the box MUST show exactly the record's `drawing`, or nothing. The
complete rules are `docs/SECURITY_MODEL.md` §2 item 4.

### 7.4 Envelope state

An envelope is **complete** when every slot is `signed`, and **declined** (void) when any slot
is `declined`; no revision may follow a decline. An envelope keeps its `schema_version` for
life (§13.1).

### 7.5 The service link

`service_link` is not a prepared term and never decides validity. A verifier reports the
preparer's link only when it is an `https` URL with a DNS or IPv4 host, no user name or password,
and 512 bytes at most; when a later revision changed it, the verifier MUST ignore the change and
warn (`service_link_changed`).

## 8. Time

### 8.1 Signing time

A revision's signing time is the `genTime` of its trusted signature timestamp (`time_source`
`tsa`), else the record's `signed_at` (`device`). A timestamp is **trusted** when its TSA's CMS
signature, certificate and chain to an anchor of the verifier's trust list verify, with the
certificate-authority constraints of `docs/SECURITY_MODEL.md` §4. Untrusted timestamps are
reported but MUST NOT be used as a clock.

Every trusted timestamp at or after a signature (its own, a later signature's, a document
timestamp) proves it existed by that time; the earliest is the revision's `existed_before`. It
is the only evidence held against a key's `not_after` and `distrusted_after` (§9.1) and against
`policy.expiry`.

### 8.2 The signature-timestamp policy

`policy.signature_timestamps`: `optional` (absent; the host decides), `required` (every signer
revision is made with room for a timestamp; one the host could not add is accepted with a
`timestamp_missing` warning) or `none` (no signer revision may carry one; one forced in is
reported). The policy is a prepared term.

### 8.3 Algorithm policy

Digest and signature algorithms, key sizes and end dates come from the trust list's
`algorithm_policy`, or the built-in policy (version 1: SHA-256, SHA-384, SHA-512, ECDSA P-256,
RSA PKCS #1 v1.5 from 2048 bits, no end dates). Evidence relying on an algorithm past its end
counts only under an earlier trusted timestamp that does not itself rely on an ended algorithm.

## 9. Trust lists

### 9.1 The trust store (`trust.json`)

A trust store is a JSON object:

| Member | Meaning |
| --- | --- |
| `issuers` | array of `{issuer, name, jwks_uri?, keys, audiences, requires_trusted_time?, kind?}`; `keys` are JWKs (RFC 7517) that MAY carry `not_before`, `not_after`, `distrusted_after` (RFC 3339) and the informational `first_seen`, `last_seen`; `audiences` are the applications (`aud`) accepted for the issuer, an empty list accepting none; `kind` is `email-code`, `account` or `organization` |
| `tsa_anchors` | array of base64 DER certificates: the roots of trusted time-stamp authorities |
| `tsa_distrusted` | OPTIONAL array of `{cert_sha256, distrusted_after, name?}`: a timestamp whose chain holds the certificate with that SHA-256 (hex of its DER) and whose `genTime` is at or after `distrusted_after` (RFC 3339) is **not trusted** (warning `tsa_distrusted`); earlier ones still are. A chain certificate matches when its DER, or its other valid encoding (an ECDSA signature `(r, s)` as `(r, n - s)`), has that SHA-256; a certificate whose outer `signatureAlgorithm` differs from `tbsCertificate.signature` is refused. Merging two stores keeps the earlier time |
| `allow_insecure_dev_issuer` | MUST be `false` in any list used for real documents |
| `algorithm_policy` | OPTIONAL, §8.3 |

An identity is **trusted** when its issuer (or the Microsoft `{tenantid}` template matched
against `tid`) is listed and the RFC 7638 thumbprint of the archived JWK equals that of a key
pinned for it. When the key has a window, or the issuer `requires_trusted_time`, trusted time
(§8.1) MUST place the signature inside the window; without such time the identity is
`no-trusted-time`, which is not an integrity failure. A key's window comes from the trust store
only; window members in an archived JWK MUST be ignored. Merging two stores never widens a
window. The full rules are `docs/SECURITY_MODEL.md` §3.

### 9.2 The signed trust list

A trust-list publisher (the hosted service) publishes its store as a **signed trust list**: the
trust store members above plus `type` (`sovrasign-trust-list`), `schema` (2), `sequence`
(strictly increasing), `issued_at`, `expires_at` (30 days later), `publisher`, `cells` and
`next_keys` (the JWKs of the next trust-list keys, committed in advance, in order). The signature is a
JWS (RFC 7515) with ES256 and a **detached payload**: `base64url(header) ".." base64url(sig)`,
the payload being the exact bytes of `trust.json`; the header's `kid` is the RFC 7638 thumbprint
of the trust-list key. A client pins the trust-list public keys at build time and MUST check the
signature before using a list.

The pinned keys are a **key chain**, in order: the key in use, then its pre-committed
successors. A client MUST apply the key-chain rule (reference: `signpdf_core::trust_list`):

1. A list signed by a key outside the chain is refused (`unknown_key`).
2. The signing key's **position in the chain decides first**: a list signed by a key later in
   the chain than the key of the list held is taken whatever its `sequence`; once it is held, a
   list signed by an earlier key is refused (`older_key`).
3. Under the same key, a lower `sequence` than the list held is refused (`older`).
4. Only a list signed by the chain's **last** key extends the chain: its `next_keys` not yet in
   it are appended, in order. `next_keys` of a list signed by any other key add nothing, so the
   key in use can neither rewrite nor withdraw its successors. The chain only grows: a
   pre-committed key that is itself compromised is removed by new pins.
5. A client that keeps the chain between runs keeps each extension with the thumbprint of the
   key that made it, and replays them on its pins when it loads: an extension counts only when
   its key is then the chain's last, so a build with new pins drops what an older chain added.

A list of a newer `schema` than the client reads is refused (`newer_schema`). Layout 2 adds
`tsa_distrusted` and this rule. An expired list MAY still be used; the verifier then reports
that an unknown key may be due to a stale list. The history of every published list is archived
in the repository's `trust-history` branch (`trust-lists/<sequence>.json` and `.jws`, §12.3).

## 10. The verification algorithm

Given a PDF and a trust store, a conforming verifier:

1. Finds every signature and document timestamp, in file order. None: `no_signatures`.
2. Reads the envelope of the last signed revision, reads only its `schema_version`, and refuses
   a version newer than it supports (§13.2) before parsing anything else.
3. Checks every signature and document timestamp (§3.1, §3.4) and that the last covers the
   whole file.
4. Checks revision 0 (§7.1), then each later revision in order against the one before it
   (§7.2, §7.3), and each document-timestamp increment (§3.4).
5. Checks the audit log (§6.2) and every signature record (§6.1).
6. Evaluates time (§8) and each identity against the trust store (§9.1) and its slot (§5.3).
7. Reports: `integrity_ok` is true when steps 1 to 5 found nothing and the order, expiry and
   identity-policy rules hold; `identities_trusted` when every identity is trusted;
   `valid = integrity_ok && identities_trusted`.

A verifier MUST NOT stop at the first finding when it can go on safely: the report lists every
finding it can establish. It MUST treat any input it cannot parse as invalid (or refuse it),
never crash, and bound its memory and recursion.

## 11. The verification report and its findings

The reference report (`VerificationReport`, JSON) has the verdicts `valid`, `integrity_ok`,
`identities_trusted`, `trusted_time_pending`; `document_sha256`, `original_len`; `complete`,
`declined`, `audit_ok`, `order_ok`; `preparer` and `signatures` (one status per revision: kind,
slot, key fingerprint, signing time and its source, `existed_before`, identity, `identity_trust`,
`level`, `basis`); `messages` and `warnings` (English); `findings`; `service_link`;
`document_timestamps`; `validation_data`; `pades_level` (`B-B`, `B-T`, `B-LT`, `B-LTA`);
`algorithm_policy`; and the final `envelope`.

Each **finding** is `{code, severity, signer?, revision?, text}`. `severity` is `error` (the
document is not valid or an identity not trusted) or `warning` (the verdict does not change).
Codes are stable: a code is never renamed or reused, and a new kind of finding gets a new code.
Appendix A lists every code of this version: the report's findings (severity `error` or
`warning`), then the codes the engine uses for its own errors, refused field values and formula
fields, which are not findings of a report. A conforming verifier SHOULD use these codes, so that
hosts can translate them.

## 12. Test vectors

The test vectors are released under CC0 1.0 so that anyone can copy them into their own tests.

### 12.1 Compatibility corpus

`core/signpdf-core/tests/corpus/v<N>/<date>-<commit>/`: documents written by a build of each
supported schema version, each with that build's report (`*.report.json`), the `trust.json`
pinning its test keys, and `SOURCE.txt` (commit, toolchain, commands). A conforming verifier
MUST reach the stored verdict (`valid`, `integrity_ok`, `identities_trusted`) for every document
under its set's `trust.json`; from version 7 the reports carry finding codes, which it SHOULD
reproduce. `newer/schema-v1000.pdf` is a sound document whose envelope claims version 1000: a
verifier MUST refuse it as unsupported (§13.2), not report it invalid.

### 12.2 Attack corpus

`core/signpdf-core/tests/attack/`: one document per attack class of
`docs/SECURITY_MODEL.md` §6 that a file can show, with `<name>.expected.json` (`outcome`
`report` or `error`, the three verdicts, and the sorted `errors` and `warnings` codes) and one
`trust.json` for all of them. `control-two-signers.pdf` is an honest document that MUST verify
as valid under that `trust.json`, so every other failure is the attack's.

### 12.3 Archives

Every published verifier build is archived as a release with its hashes and rebuild steps
(`.github/workflows/pages.yml`), and every signed trust list in the `trust-history` branch
(`.github/workflows/trust-archive.yml`); both are also offered to Software Heritage
(`docs/RELEASES.md`). A document can so be checked years later with the verifier and
the trust list of its time.

### 12.4 Trust-list vectors

`spec/vectors/trust-list-rotation.json` (made by `spec/vectors/make-trust-list-vectors.mjs`):
public trust-list keys, lists signed with them, and cases (pins, then steps with the expected
outcome and the sequence held at the end) for the key-chain rule of §9.2: a forged high
sequence from the old key then the new key's real list (taken), a key outside the chain
(refused), the old key's list replayed after a rotation (refused), keys pre-committed by the
last key (followed), an update with new pins. `spec/vectors/tsa-distrust/`: a completed envelope
with one document timestamp and four trust stores distrusting its authority from after, at and
before the stamp's time (or not at all), with the expected verdicts (`expected.json`): the stamp
counts before `distrusted_after` and not at or after it. A conforming client and verifier MUST
reproduce every outcome.

### 12.5 Initials vectors

`spec/vectors/initials-name-v1.json`: cases of the `name-v1` rule (§4.6), each a slot name, a
verified email address and the letters a writer stamps and a verifier expects (names with
titles and suffixes, particles, hyphens, accents inside and outside WinAnsiEncoding, other
scripts, no name). A conforming writer, verifier and any page that shows the letters before
signing MUST give the same letters for every case.

## 13. Versioning

### 13.1 Rules

The rules are those of `docs/SECURITY_MODEL.md` §8. In short: an envelope keeps its version for
life; a build never signs a newer version; every **stable** version from the oldest supported
to the newest verifies forever, each under its own rules; any change to a stable version's shape
or to what a revision may contain is a new version. Versions up to and including 9 are
**experimental** until the first hosted release fixes its version as the first stable one; an
experimental version may change in place and its corpus fixtures are then replaced.

| Version | Adds |
| --- | --- |
| 3 | the first supported version: `min_assurance`, `policy.signature_timestamps`, field date terms, `utc_offset`, consent records, `service_link` |
| 4 | `min_level` and `required_methods` replace `min_assurance` |
| 5 | the `documents` index |
| 6 | `drawing` in signature records |
| 7 | `number` fields with `number_format`, and `verify_at` |
| 8 | `value_format`, `length` and `check_message` on fields, `number_format.currency`, and `formula` fields |
| 9 | `initials_rule` (`name-v1`): initials stamps from the slot's name instead of the verified email address |

### 13.2 Unknown versions

A reader MUST read `schema_version` before anything else. For a version newer than it
supports it MUST refuse the document as unsupported (the reference engine's error
`unsupported_version`, code 16 on its FFI and WebAssembly interfaces), MUST NOT report it invalid, and MUST NOT sign, decline or
re-prepare it. A version older than the oldest supported one is refused likewise.

### 13.3 This specification

Revision `N.m` describes schema version `N`; `m` counts editorial and clarifying changes that
change no verdict. A change that would change a verdict for any existing document is a new
schema version (§13.1) and a new major revision.

## 14. Open items

Before this specification is final:

1. Move the object-level rules of `docs/SECURITY_MODEL.md` §2 items 4 and 5 (cross-reference
   form, allowed changes, the ink rule) into §3.3 and §7.3.
2. Specify the drawing of field values, the document-ID stamp and signature boxes (fonts,
   positions, number formatting) precisely enough to reproduce byte for byte, with one test
   vector per field type and style.
3. Give the canonical CMS encoding (§3.1 item 2) as an annotated DER template.
4. Publish a JSON Schema for each envelope version, generated from the decoders.
5. Have an independent implementation (for example a small Python verifier on pyHanko) run
   against the test vectors in CI.

## Appendix A: finding codes

Generated from `core/signpdf-core/src/messages.rs` (`CODES`); `tests/format_spec.rs` checks that
every code there is listed here.

### Findings that make a document invalid (52 codes)

| Code | English fallback |
| --- | --- |
| `no_signatures` | The document carries no signatures: it was never prepared for signing. |
| `signature_malformed` | A signature in the document is malformed. |
| `document_changed` | The document was changed after it was signed. |
| `signature_invalid` | A signature does not match the document. |
| `signature_altered` | A signature's unsigned parts were altered. |
| `document_timestamp_malformed` | A document timestamp is malformed. |
| `document_timestamp_changed` | The document was changed after a document timestamp was added. |
| `document_timestamp_invalid` | A document timestamp is not valid. |
| `revisions_overlap` | Two signatures cover the same version of the document. |
| `timestamp_before_preparer` | A document timestamp comes before the preparer's signature. |
| `unsigned_changes` | Changes were added after the last signature. |
| `envelope_unreadable` | A version of the document has no readable signing record. |
| `audit_log_broken` | The document's audit log is broken. |
| `signature_record_inconsistent` | A signer's record does not match their signature. |
| `signature_count_mismatch` | The number of signatures does not match the signing record. |
| `identities_not_trusted` | The document is intact, but one or more identities are not trusted by this verifier. |
| `trusted_time_pending` | The document is intact; one or more identities count only once a trusted timestamp covers their signature. |
| `preparer_revision_invalid` | The preparer's version of the document is not valid. |
| `preparer_identity_failed` | The preparer's identity could not be verified. |
| `document_id_stamp_mismatch` | The document ID stamp is not the one the engine draws. |
| `terms_changed` | The prepared terms (title, documents, signers, fields or policy) were changed. |
| `signed_after_decline` | A signature was added after the envelope was declined. |
| `record_mismatch` | A signer's record was rewritten or does not belong to their signature. |
| `slot_tampered` | A signer's slot was changed by someone else, or filled twice. |
| `out_of_order` | A signer signed before their turn. |
| `field_tampered` | A field was filled or changed by someone who may not. |
| `field_value_invalid` | A field holds a value its rules do not allow. |
| `formula_mismatch` | A formula field does not hold what its formula computes. |
| `record_malformed` | A signer's record holds evidence in the wrong form. |
| `audit_log_rewritten` | The audit log was rewritten, or does not record the signer's action. |
| `unsigned_insertion` | Unsigned changes were inserted before a signature. |
| `revision_digest_mismatch` | A signer's record names another version of the document. |
| `signer_not_recorded` | A signature has no record in the signing envelope. |
| `forbidden_change` | A version of the document changed something it may not change. |
| `unexpected_annotation` | A version of the document added something to a page that it may not. |
| `audit_failed` | A version of the document could not be checked. |
| `signature_box_mismatch` | A signature box does not show what the engine draws for the verified signer. |
| `drawing_mismatch` | A drawn or typed signature does not match the signer's record. |
| `stamp_mismatch` | A signature or initials stamp does not match the verified signer. |
| `identity_failed` | A signer's identity could not be verified. |
| `signing_time_unreadable` | A signing time cannot be read. |
| `signed_after_expiry` | A signature was made after the envelope expired. |
| `algorithm_refused` | A signature relies on an algorithm that is no longer accepted. |
| `identity_unknown_issuer` | The identity provider that vouched for this person is not trusted by this verifier. |
| `identity_unknown_key` | The identity provider's key is not one this verifier knows. |
| `identity_untrusted_audience` | The sign-in was made for an application this verifier does not trust. |
| `identity_no_trusted_time` | This identity counts only once a trusted timestamp covers the signature. |
| `identity_outside_key_window` | The identity provider's key was not valid when the signature was made. |
| `identity_distrusted_key` | The identity provider's key is no longer trusted. |
| `identity_algorithm_not_accepted` | The sign-in relies on an algorithm that is no longer accepted. |
| `identity_insufficient_level` | The identity does not meet the level the signer's slot requires. |
| `identity_not_trusted` | An identity is not trusted by this verifier. |

### Warnings (11 codes)

| Code | English fallback |
| --- | --- |
| `algorithm_accepted_by_timestamp` | An algorithm is accepted only because a trusted timestamp shows it was used in time. |
| `service_link_unusable` | The link back to the sending service is not usable and is not shown. |
| `service_link_changed` | A signer changed the link back to the sending service; the change is ignored. |
| `timestamp_missing` | A signature has no timestamp although the envelope requires one: its time is the signer's device clock. |
| `timestamp_unexpected` | A signature carries a timestamp although the envelope takes none. |
| `tsa_certificate_revoked_later` | A time-stamp authority's certificate was revoked after the timestamp; the timestamp still holds. |
| `slot_policy_weak` | A signer's slot accepts identities that are easy to obtain. |
| `insecure_dev_trust` | This verification trusts a test identity provider: never use this setting for real documents. |
| `consent_after_signature` | A signer's consent to electronic records is dated after their signature. |
| `timestamp_algorithm` | A timestamp relies on an algorithm the algorithm policy limits. |
| `tsa_distrusted` | A timestamp comes from a time-stamp authority the trust list distrusts from that time: it is not used as trusted time. |

### Engine errors (10 codes)

| Code | English fallback |
| --- | --- |
| `workflow` | The document's signing rules refuse this request. |
| `verification` | The document failed verification. |
| `identity` | The sign-in was not accepted. |
| `document` | The PDF, or the signing record in it, could not be read or written. |
| `timestamp` | A timestamp could not be obtained or checked. |
| `crypto` | A cryptographic operation failed. |
| `keystore` | The key store could not be used. |
| `too_large` | The documents are larger than an envelope may be (50 MB). |
| `unsupported_version` | This document was made by a newer version: update the app or reload the page. |
| `io` | A file could not be read or written. |

### Refused field values (16 codes)

| Code | English fallback |
| --- | --- |
| `invalid_email` | Enter an email address. |
| `invalid_phone` | Enter a phone number in international form. |
| `invalid_number` | Enter a number. |
| `too_many_decimals` | Too many decimal places. |
| `below_minimum` | The number is below the minimum. |
| `above_maximum` | The number is above the maximum. |
| `negative_amount` | The amount cannot be negative. |
| `invalid_postal_code` | Enter a postal code. |
| `unsupported_country` | This country's postal codes cannot be checked. |
| `invalid_iban` | Enter an IBAN. |
| `iban_checksum` | The IBAN's check digits are wrong: check for a typo. |
| `invalid_us_ssn` | Enter a Social Security number. |
| `invalid_us_ein` | Enter an Employer Identification Number. |
| `too_short` | Too short. |
| `too_long` | Too long. |
| `pattern_mismatch` | This value does not have the expected form. |

### Formula fields (13 codes)

Computing a formula from a signer's values (severity `value`), then the formula itself, refused
when a document is prepared (severity `refusal`).

| Code | English fallback |
| --- | --- |
| `division_by_zero` | This total cannot be computed: it divides by zero. |
| `number_too_large` | This total cannot be computed: a number is too large. |
| `formula_syntax` | The formula cannot be read. |
| `formula_too_long` | The formula is too long. |
| `formula_too_deep` | The formula is nested too deeply. |
| `formula_unknown_function` | The formula uses a function that does not exist. |
| `formula_arguments` | A function in the formula has the wrong arguments. |
| `formula_type` | The formula mixes up numbers and conditions. |
| `formula_unknown_field` | The formula reads a field that does not exist. |
| `formula_loop` | Formulas read each other in a loop. |
| `formula_input_type` | The formula reads a field that holds no number. |
| `formula_later_input` | The formula reads a field that a later signer fills. |
| `formula_map` | An option the formula reads has no number. |
