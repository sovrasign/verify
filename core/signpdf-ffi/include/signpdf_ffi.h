/* SignPDF engine — C ABI (ticket P0-9).
 *
 * Generated/maintained by hand to match `core/signpdf-ffi/src/lib.rs`. Any non-Rust front-end
 * (Flutter via dart:ffi, or a plain C/C++/C# host) can link the `signpdf-ffi` shared library and
 * call these functions. All workflow flows are exposed: Verify, Prepare, Sign, plus the
 * certificate of completion and trust-store helpers.
 *
 * Memory contract: functions that return data fill a caller-owned `SignPdfBuffer`. On success
 * (code == SIGNPDF_OK) the buffer holds UTF-8 JSON (verify/read_envelope/ephemeral identity/trust
 * store) or raw PDF bytes (prepare/sign/certificate); on error it holds a UTF-8 message. Release
 * every returned buffer exactly once with `signpdf_buffer_free`.
 *
 * Robustness: no Rust panic ever unwinds into the host; a panic is reported as SIGNPDF_ERR_PANIC.
 * Key custody: ephemeral private keys stay inside the library behind opaque, single-use handles.
 */
#ifndef SIGNPDF_FFI_H
#define SIGNPDF_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SIGNPDF_OK 0
#define SIGNPDF_ERR_INPUT 1
#define SIGNPDF_ERR_ENGINE 2
#define SIGNPDF_ERR_ENCODE 3
#define SIGNPDF_ERR_DECODE 4
#define SIGNPDF_ERR_PANIC 5
/* Engine errors by category. The message in the buffer is the engine's own, in English; the code
 * lets a host explain the failure in the user's language. SIGNPDF_ERR_ENGINE remains for engine
 * errors outside these categories. */
#define SIGNPDF_ERR_WORKFLOW 10     /* the document's workflow rules refuse the request */
#define SIGNPDF_ERR_VERIFICATION 11 /* the document failed verification */
#define SIGNPDF_ERR_IDENTITY 12     /* the identity token was not accepted */
#define SIGNPDF_ERR_DOCUMENT 13     /* the PDF or its envelope could not be read or written */
#define SIGNPDF_ERR_TIMESTAMP 14    /* a signature timestamp could not be obtained or validated */
#define SIGNPDF_ERR_CRYPTO 15       /* a cryptographic operation or a key store failed */
#define SIGNPDF_ERR_UNSUPPORTED_VERSION 16 /* made by a newer SignPDF: update the app; nothing was
                                            * signed and the document was not judged */
#define SIGNPDF_ERR_TOO_LARGE 17 /* the document, or an envelope's documents together, are over
                                  * 50 MB: nothing was combined or prepared */

/* An owned byte buffer handed across the boundary. Free with signpdf_buffer_free. */
typedef struct SignPdfBuffer {
  uint8_t *ptr;
  size_t len;
  size_t cap;
} SignPdfBuffer;

/* Engine version (semver) into `out`. Always returns SIGNPDF_OK. */
int32_t signpdf_version(SignPdfBuffer *out);

/* Verify against the well-known trust store (issuers without pinned keys — identities report
 * `unknown-key`). Prefer signpdf_verify_with_trust with a refreshed store. */
int32_t signpdf_verify(const uint8_t *pdf_ptr, size_t pdf_len, SignPdfBuffer *out);

/* Verify signatures, the revision chain, audit log, order and identities against the JSON
 * TrustStore in `trust` (NULL/empty = well-known store). On SIGNPDF_OK `out` holds the JSON
 * VerificationReport (its `valid` field is the headline result; `integrity_ok` ignores trust). */
int32_t signpdf_verify_with_trust(const uint8_t *pdf_ptr, size_t pdf_len, const uint8_t *trust_ptr,
                                  size_t trust_len, SignPdfBuffer *out);

/* Verify (as signpdf_verify_with_trust) and return a certificate-of-completion PDF (raw bytes). */
int32_t signpdf_completion_certificate(const uint8_t *pdf_ptr, size_t pdf_len,
                                       const uint8_t *trust_ptr, size_t trust_len,
                                       SignPdfBuffer *out);

/* The well-known trust store (Google/Microsoft/Apple issuers + bundled TSA anchor) as JSON. */
int32_t signpdf_trust_well_known(SignPdfBuffer *out);

/* Pin a JWKS ({"keys":[...]}) for `issuer` in a JSON trust store (NULL/empty = well-known),
 * keeping previously pinned keys. On SIGNPDF_OK `out` holds the updated trust store JSON. */
int32_t signpdf_trust_add_jwks(const uint8_t *trust_ptr, size_t trust_len, const uint8_t *issuer_ptr,
                               size_t issuer_len, const uint8_t *jwks_ptr, size_t jwks_len,
                               SignPdfBuffer *out);

/* Page geometry as JSON: [{index, media_box, crop_box, rotate, annotations:[{subtype,
 * field_type?, rect}]}]; boxes are [x1,y1,x2,y2] in default user space (pt, bottom-left,
 * unrotated). */
int32_t signpdf_page_geometry(const uint8_t *pdf_ptr, size_t pdf_len, SignPdfBuffer *out);

/* Read the embedded SignPDF envelope as JSON. */
int32_t signpdf_read_envelope(const uint8_t *pdf_ptr, size_t pdf_len, SignPdfBuffer *out);

/* Combine several documents into the one PDF an envelope of several documents signs.
 * `manifest_json` is {"documents": [{"name": "NDA.pdf", "len": <bytes>}, ...]}; `data` holds the
 * documents' PDFs one after the other, in that order. On SIGNPDF_OK `out` holds the length of the
 * index JSON (4 bytes, big-endian), the index JSON {"documents": [{"name", "first_page",
 * "page_count", "source_digest"}, ...]} (pass it as the PrepareRequest's "documents"), then the
 * combined PDF. SIGNPDF_ERR_DECODE: the manifest does not parse or add up. SIGNPDF_ERR_WORKFLOW:
 * more than 20 documents, a bad name, a file that is not a PDF, is encrypted or signed.
 * SIGNPDF_ERR_TOO_LARGE: over 50 MB together. */
int32_t signpdf_combine_documents(const uint8_t *manifest_ptr, size_t manifest_len,
                                  const uint8_t *data_ptr, size_t data_len, SignPdfBuffer *out);

/* Intake: images as one PDF on the device, one page per image (every page of a multi-page TIFF),
 * fitted to A4 or US Letter. `manifest_json` is {"paper": "a4"|"letter", "images": [{"len":
 * <bytes>, "margin": <points>}, ...]}; `data` holds the image files (JPEG or TIFF; decode other
 * formats to JPEG first) one after the other. On SIGNPDF_OK `out` holds the length of a JSON
 * summary (4 bytes, big-endian), the summary {"pages": [...]}, then the PDF.
 * SIGNPDF_ERR_DECODE: the manifest does not parse or add up. SIGNPDF_ERR_WORKFLOW: a message
 * starting with not_an_image, unsupported_image, unreadable_image, too_many_pages or
 * too_many_pixels. */
int32_t signpdf_images_to_pdf(const uint8_t *manifest_ptr, size_t manifest_len,
                              const uint8_t *data_ptr, size_t data_len, SignPdfBuffer *out);

/* What a chosen PDF needs before it can be prepared. On SIGNPDF_OK `out` holds UTF-8 JSON
 * {"encryption": "none"|"restrictions"|"open_password"|"certificate", "pdfa": "2b"|null,
 * "layers", "hidden_layers", "pages"}. SIGNPDF_ERR_WORKFLOW: "unreadable_pdf: ...". */
int32_t signpdf_source_info(const uint8_t *pdf_ptr, size_t pdf_len, SignPdfBuffer *out);

/* A PDF with an open password, decrypted with `password` (UTF-8) and saved again without
 * encryption. On SIGNPDF_OK `out` holds the PDF. SIGNPDF_ERR_WORKFLOW: a message starting with
 * wrong_password, not_encrypted, no_open_password, certificate_encryption or unreadable_pdf. */
int32_t signpdf_decrypt(const uint8_t *pdf_ptr, size_t pdf_len, const uint8_t *password_ptr,
                        size_t password_len, SignPdfBuffer *out);

/* A convenience copy of document `index` (0-based) of an envelope of several documents: its pages
 * only, with a banner above the first saying it is a copy and that the combined PDF is what was
 * signed. On SIGNPDF_OK `out` holds the copy's PDF bytes. SIGNPDF_ERR_WORKFLOW: the envelope has
 * no documents index, or no such document. */
int32_t signpdf_extract_document(const uint8_t *pdf_ptr, size_t pdf_len, size_t index,
                                 SignPdfBuffer *out);

/* A typed signature: the glyph outlines of `name` (UTF-8, normalized to NFC) set in `font` (the
 * bytes of a TrueType or OpenType font file the app ships). On SIGNPDF_OK `out` holds UTF-8 JSON,
 * the paths to send as the SignRequest's "typed_signature" (filled in the signer's box and kept in
 * their signature record; the PDF carries no font and no text for it). SIGNPDF_ERR_WORKFLOW, with
 * a message for the signer: an empty or too long name, a script the engine cannot lay out, a
 * character the font does not draw, too detailed, or a font that cannot be read.
 * SIGNPDF_ERR_DECODE: `name` is not UTF-8. */
int32_t signpdf_typed_signature(const uint8_t *font_ptr, size_t font_len, const uint8_t *name_ptr,
                                size_t name_len, SignPdfBuffer *out);

/* Prepare a source PDF: embed the workflow envelope, sign it as the preparer, return the PDF.
 * `request_json` is a UTF-8 JSON PrepareRequest; `identity_json` is {"handle":"…"} from
 * signpdf_new_ephemeral_identity (or, for dev tools, a full Identity).
 * On SIGNPDF_OK `out` holds the raw prepared PDF bytes (binary, not JSON).
 * SIGNPDF_ERR_DECODE: a JSON argument failed to parse. SIGNPDF_ERR_ENGINE: engine rejected it. */
int32_t signpdf_prepare(const uint8_t *pdf_ptr, size_t pdf_len, const uint8_t *request_ptr,
                        size_t request_len, const uint8_t *identity_ptr, size_t identity_len,
                        SignPdfBuffer *out);

/* Sign (or decline) a prepared PDF and return the updated PDF. Arguments as signpdf_prepare
 * (with a SignRequest). On SIGNPDF_OK `out` holds the raw signed PDF bytes (binary).
 * Signature timestamps follow the envelope's policy.signature_timestamps (absent = "optional"):
 * under "required" the signature is made with room for one, which the host adds with
 * signpdf_timestamp_request and signpdf_add_timestamp; under "none" there is none. */
int32_t signpdf_sign(const uint8_t *pdf_ptr, size_t pdf_len, const uint8_t *request_ptr,
                     size_t request_len, const uint8_t *identity_ptr, size_t identity_len,
                     SignPdfBuffer *out);

/* signpdf_sign with room for a PAdES B-T signature timestamp (same arguments; consumes the key
 * handle). The result is already a complete B-B signature. Refused with SIGNPDF_ERR_WORKFLOW,
 * before anything is signed, when the envelope's policy is signature_timestamps = "none". */
int32_t signpdf_sign_for_timestamp(const uint8_t *pdf_ptr, size_t pdf_len,
                                   const uint8_t *request_ptr, size_t request_len,
                                   const uint8_t *identity_ptr, size_t identity_len,
                                   SignPdfBuffer *out);

/* The RFC 3161 TimeStampReq (DER) for the last signer revision's signature timestamp: POST it to
 * the time-stamp authority with Content-Type: application/timestamp-query. Refused with
 * SIGNPDF_ERR_WORKFLOW under signature_timestamps = "none". Needs no key. */
int32_t signpdf_timestamp_request(const uint8_t *pdf_ptr, size_t pdf_len, SignPdfBuffer *out);

/* Embed the authority's TimeStampResp (the DER body of its HTTP response) as that signature
 * timestamp. On SIGNPDF_OK `out` holds the PDF (same length, now PAdES B-T).
 * SIGNPDF_ERR_TIMESTAMP: not a granted token over this signature. Needs no key. */
int32_t signpdf_add_timestamp(const uint8_t *pdf_ptr, size_t pdf_len, const uint8_t *response_ptr,
                              size_t response_len, SignPdfBuffer *out);

/* Increments. A signature only appends bytes to the PDF (the increment); the signed document is
 * the PDF followed by them. For a host that stores or uploads increments. */

/* signpdf_sign returning only the increment (binary). Same arguments and errors. */
int32_t signpdf_sign_increment(const uint8_t *pdf_ptr, size_t pdf_len, const uint8_t *request_ptr,
                               size_t request_len, const uint8_t *identity_ptr,
                               size_t identity_len, SignPdfBuffer *out);

/* signpdf_sign_for_timestamp returning only the increment (binary). */
int32_t signpdf_sign_for_timestamp_increment(const uint8_t *pdf_ptr, size_t pdf_len,
                                             const uint8_t *request_ptr, size_t request_len,
                                             const uint8_t *identity_ptr, size_t identity_len,
                                             SignPdfBuffer *out);

/* signpdf_timestamp_request for a document held apart: `head` (the PDF that was signed) and
 * `increment` (what signpdf_sign_for_timestamp_increment returned). Same result and refusals. */
int32_t signpdf_increment_timestamp_request(const uint8_t *head_ptr, size_t head_len,
                                            const uint8_t *increment_ptr, size_t increment_len,
                                            SignPdfBuffer *out);

/* signpdf_add_timestamp for a document held apart. On SIGNPDF_OK `out` holds the new increment,
 * the same length (only the signature's /Contents changes). */
int32_t signpdf_increment_add_timestamp(const uint8_t *head_ptr, size_t head_len,
                                        const uint8_t *increment_ptr, size_t increment_len,
                                        const uint8_t *response_ptr, size_t response_len,
                                        SignPdfBuffer *out);

/* For the holder of a document whose head moved: the bytes of the PDF after the client's head,
 * `head_json` = UTF-8 JSON {"len": <bytes>, "sha256": "<hex>"}. On SIGNPDF_OK `out` holds those
 * bytes (empty when the head did not move). SIGNPDF_ERR_WORKFLOW when the head is not a revision
 * of this PDF (the client then fetches the whole document). */
int32_t signpdf_increment_after(const uint8_t *pdf_ptr, size_t pdf_len, const uint8_t *head_ptr,
                                size_t head_len, SignPdfBuffer *out);

/* For the client: check that `increment` extends `head` (the revision it holds) into the announced
 * document `expected_json` ({"len", "sha256"}), hashing the head in place. On SIGNPDF_OK `out`
 * holds the new head as the same JSON; SIGNPDF_ERR_WORKFLOW when the lengths do not add up, the
 * increment was cut short or the digest differs. */
int32_t signpdf_check_increment(const uint8_t *head_ptr, size_t head_len,
                                const uint8_t *increment_ptr, size_t increment_len,
                                const uint8_t *expected_ptr, size_t expected_len,
                                SignPdfBuffer *out);

/* Mint an ephemeral signing key stapled to one document (federated keyless flow), kept inside
 * the library. Call BEFORE the OIDC login. On SIGNPDF_OK `out` holds UTF-8 JSON:
 *   { "identity": { "handle": "…", "public_b64": "…", "fingerprint": "…" },
 *     "nonce": "<hex>", "doc_digest": "<hex>" }
 * Send `nonce` in the OIDC authorization request; then pass {"handle": …} plus the resulting
 * id_token/idp_jwk (inside a SignRequest/PrepareRequest) to signpdf_sign/signpdf_prepare. The
 * handle is consumed by its first successful use. */
int32_t signpdf_new_ephemeral_identity(const uint8_t *pdf_ptr, size_t pdf_len, SignPdfBuffer *out);

/* Discard an unused ephemeral key by handle (UTF-8). Always SIGNPDF_OK for a valid pointer. */
int32_t signpdf_discard_ephemeral(const uint8_t *handle_ptr, size_t handle_len);

/* Release a buffer returned by this library (no-op on a zeroed buffer). */
void signpdf_buffer_free(SignPdfBuffer buf);

/* Return a fresh zeroed buffer (convenience). */
SignPdfBuffer signpdf_buffer_new(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SIGNPDF_FFI_H */
