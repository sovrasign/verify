# Security review: the image load filter (2026-10-27)

Reviewed 2026-10-27 (lopdf 0.42.0). Scope: the lopdf load filter that a change of 2026-10-26
added to `core/signpdf-core/src/pades.rs` (`load_for_inspection`), everything that parses a
document through it, and what it changes for the increment audit (`audit_increment`). The other
half of that change (dropping the parse before the output is built, allocating the output once)
changes no output byte and is covered by the existing signing and corpus tests.

**Verdict.** Keep the filter, with the two fixes below, which are part of the same change as this
review. The review found one serious problem: an object stream that also claimed `/Subtype
/Image` was filtered, so its objects vanished from the engine's view (and only the engine's),
which let a sender who also signs later change page content in their own revision without the
audit seeing it (finding 1). With the fixes, the filter changes only the bytes of image XObjects
over 64 KiB, which no engine decision reads, and the audit compares those images as strictly as
it compares bytes, assuming only what the signatures already assume (SHA-256 is collision
resistant).

## 1. What the filter does

PDF documents are large because of their images (scans, photos). Before the filter, every parse kept
every image's bytes, and verifying an increment holds two parses at once; signing a 50 MB
document peaked at 5.1x its size in WebAssembly, where memory never shrinks. `load_for_inspection`
parses like `Document::load_mem`, except that, as lopdf reads each object, the content of every
image XObject over 64 KiB (`LARGE_IMAGE`) is replaced:

| Mode | Replaced by | Used by |
| --- | --- | --- |
| `ImageBytes::Drop` | a 22-byte placeholder | `pades_sign_with`, `embed_attachment`, `stamp_document_id`, `read_attachment` (so `read_envelope`), `pades_verify`, `page_geometry` |
| `ImageBytes::Digest` | the SHA-256 of the bytes (32 bytes) | `audit_increment`, which compares objects between two revisions |

Result on a 50 MB document (the memory check of the browser signing module):
reading, page geometry and verification peak at 1.05-1.07x the document, signing at 2.1x. With
the filter disabled the same check measures 2.05x, 3.06x and 3.06x and fails.

## 2. What must hold

For the filter to be invisible to every security decision:

1. **Same document.** A filtered parse has exactly the objects, numbers and trailer of a plain
   lopdf parse; only the content of large image XObjects differs. Otherwise the engine judges a
   different document from the one other PDF readers show.
2. **Same comparisons.** Where revisions are compared, a digest compares as strictly as the
   bytes.
3. **No decision reads a replaced content**, and no replaced content is ever written out.
4. **Signatures do not depend on the parse.** Digests and signatures are over the raw bytes.

## 3. Findings

### Finding 1 (high, fixed): object streams claiming to be images were not unpacked

The filter tested only `/Subtype /Image`. lopdf runs the filter on every top-level object
*before* it unpacks object streams (`/Type /ObjStm`), so an object stream whose dictionary also
carried `/Subtype /Image` and whose content was over 64 KiB had its content replaced, failed to
unpack, and was dropped with every object in it. Other PDF readers decide what an object stream
is by `/Type` and the cross-reference, ignore the stray `/Subtype`, and unpack it normally.
Property 1 did not hold.

**Impact.** `audit_increment` treats an object that is absent from the previous revision as new,
and new objects are allowed. So:

1. A sender uploads a source document in which one ordinary-looking object, for example a
   page's `/Contents` array, sits in such an object stream. The engine prepares it without
   complaint (it never needs that object) and every viewer shows the page normally.
2. Other participants sign what they see.
3. The sender, also a later signer, writes their own signing revision with a modified engine,
   redefining that array to point at new page content.
4. The audit compares only the objects it saw in the previous revision: the array was not among
   them, so its redefinition passed as a new object. The verifier reported the document valid
   while every viewer showed the new content: a shadow attack, which the audit exists to stop.

`page_content_hidden_in_an_image_like_object_stream_cannot_be_swapped` reproduces this: before the
fix the audit reported nothing about the swapped array. Other consequences were milder: a hidden
catalog or page tree made `page_geometry` see no pages (a refusal), and scans over every object
(`pades_verify` looking for signature dictionaries, `read_attachment` looking for file
specifications) missed what other readers see.

**Exposure.** Engine builds from the filter's merge (2026-10-26) up to this fix. These are
pre-release builds and their documents are experimental; a host that pinned one of them should
move to this fix.

**Fix.** Two independent changes:

- The filter touches only image XObjects: `/Subtype /Image` with no `/Type` or `/Type /XObject`
  (`is_image_xobject`). Object streams, cross-reference streams and embedded files keep their
  bytes whatever else their dictionary claims, so the filter can no longer change which objects
  exist. Test: `an_object_stream_claiming_to_be_an_image_is_still_unpacked`.
- The audit refuses the general case: an object that the previous revision's cross-reference
  lists (in use, directly or in an object stream) but that lopdf could not read there may not be
  defined by the next revision ("could not be read in the previous revision and was redefined").
  This also covers objects lopdf fails to read for reasons unrelated to the filter (a damaged
  object other readers tolerate). The engine numbers the objects it adds above every number of
  the previous revision, so its own revisions never do this. Test:
  `an_object_unreadable_before_cannot_be_redefined`.

### Finding 2 (low, fixed): an attachment could be read as the placeholder

`read_attachment` returns the bytes of an embedded-file stream from a `Drop` parse. An embedded
file's `/Subtype` is its MIME type, and the engine writes it from the host's `mime`, so an
attachment the engine itself embedded with the MIME type `Image`, over 64 KiB, came back as
`image bytes not loaded`; so did any stream without `/Type` that claims `/Subtype /Image`. The
only attachment read today is the envelope (JSON), which then failed to decode, so nothing was
accepted that should not have been, but the function returned a wrong value without an error.

**Fix.** Embedded files (`/Type /EmbeddedFile`) are never filtered (finding 1's predicate), and
`read_attachment` refuses a stream that claims to be an image XObject instead of returning its
placeholder. Test: `attachments_are_never_read_as_a_placeholder`.

### Hardening (no defect)

- **A filtered parse is read-only by type.** `load_for_inspection` returns `Inspected`, which
  dereferences to the parsed `Document` but never gives out `&mut Document`. Every lopdf writer
  takes `&mut self`, so a filtered parse can be neither changed nor saved. The engine already
  built its output only from the input bytes and from dictionaries copied out of the parse
  (catalog, form, page dictionaries); a dictionary can never contain a stream (streams are
  indirect objects), so no replaced content can reach the output.
- **The real length is the engine's rule.** A filtered stream's dictionary keeps `/Length` set
  to the real length; lopdf already did this, the filter now sets it itself (section 4).
- **Comment corrected.** The filter's first version said a stream with an indirect `/Length` keeps its bytes. lopdf
  resolves an indirect length while it parses when it can, so such streams are filtered too;
  only one whose length cannot be resolved then is read later, in full. The filter's equivalence
  test includes this case.

## 4. Why the digest comparison is as strict as the bytes

`audit_increment` decides whether an object changed by comparing lopdf objects (`==`). A
stream's equality covers its dictionary, its content and two flags; for a stream read with a
known length, lopdf records the content's length as `/Length`.

- A filtered stream has `/Length` over 64 KiB and 22 or 32 bytes of content. A stream read in
  full has `/Length` equal to its content's length. So a filtered stream never equals an
  unfiltered one, whatever their bytes: a revision cannot replace a large image by a small stream
  whose bytes are the digest (`a_small_stream_equal_to_the_digest_is_still_a_modification`, with
  an honest and a misleading `/Length`), and a filtered stream never compares equal to its own
  bytes (`filter_keeps_every_object_lopdf_loads`).
- Two filtered streams are equal only if their dictionaries, hence their lengths, are equal and
  their SHA-256 digests are equal. Two different byte strings with the same digest are a SHA-256
  collision (about 2^128 work, none known). The signatures already rely on the same property:
  each signs a SHA-256 digest of the document.
- Images of 64 KiB or less are compared byte for byte, as before.

## 5. What the filter does not touch

- **Signatures and document digests.** `pades_verify` takes the signature dictionaries
  (`/ByteRange`, `/Contents`) from the parse and computes the CMS digest over the raw input bytes
  the byte range names. The envelope's `source_digest` and each record's `doc_digest` are SHA-256
  over raw bytes (`workflow.rs`).
- **Appearance streams.** The audit reads the bytes of every appearance stream an increment adds
  and compares them with what the engine draws. They must be form XObjects, which the filter
  never touches at any size; an appearance stream that claims `/Subtype /Image` holds only a
  digest in the audit's parse, and `annotation_shape` reports it as "not a form XObject", which
  fails verification (`appearance_streams_keep_their_bytes_or_are_reported`).
- **`Drop` parses** read dictionaries and arrays only: the trailer, catalog, form, page
  dictionaries and their inherited boxes, file specifications, signature dictionaries. Finding 2
  was the one stream content read, now guarded.
- **Encrypted documents.** lopdf ignores the filter for them (they are parsed as before).

## 6. lopdf's filter contract, pinned

The filter relies on how lopdf 0.42 calls it: once per top-level object as it is read, before
object streams are unpacked, keeping the object as the filter left it and dropping it only when
the filter returns `None` (it never does); then once per object unpacked from an object stream,
keeping the returned copy. Objects in object streams are parsed as direct objects, never streams.
A lopdf upgrade could change any of this, so `filter_keeps_every_object_lopdf_loads` checks
property 1 directly: for every document of the compatibility corpus, the fixtures and the probe
documents of this review (large images, signed, indirect `/Length`, an object stream claiming
`/Subtype /Image`, image-like attachments, an image-like appearance stream), in both modes, the
filtered parse has the same object numbers, trailer and objects as `Document::load_mem`, except
the large image XObjects, whose dictionary is unchanged and whose content is the placeholder or
the digest.

## 7. What remains

- **Parser differences that do not involve the filter** remain as before
  ([`SECURITY_MODEL.md`](SECURITY_MODEL.md) §7, "Mutations that lopdf tolerates"); finding 1's
  audit rule closes the part where lopdf fails to read an object the cross-reference lists.
  Objects a reader finds only by rebuilding a broken cross-reference are not covered.
- **Memory still to win.** Signing peaks at 2.1x because the input and the signed output are
  both in WebAssembly memory; a sign call that returns only the increment would bring it near
  1.1x. Preparing peaks at about 3x (the input, the stamped copy and the signed copy); it is not
  on the signer's path.

## 8. Tests added

In `core/signpdf-core/src/pades.rs`, module `large_image_tests`:

| Test | Checks |
| --- | --- |
| `filter_keeps_every_object_lopdf_loads` | property 1 over the corpus, the fixtures and the probe documents |
| `an_object_stream_claiming_to_be_an_image_is_still_unpacked` | finding 1, the parse |
| `page_content_hidden_in_an_image_like_object_stream_cannot_be_swapped` | finding 1, the attack |
| `an_object_unreadable_before_cannot_be_redefined` | finding 1, the general audit rule |
| `attachments_are_never_read_as_a_placeholder` | finding 2 |
| `appearance_streams_keep_their_bytes_or_are_reported` | section 5, appearance streams |

Already there with the filter: `large_images_are_compared_by_digest_and_never_kept` and
`a_small_stream_equal_to_the_digest_is_still_a_modification`. The memory check of the browser
signing module holds the memory result in place (budgets: 1.3x the document to read or verify, 2.4x to sign).
