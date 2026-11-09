//! C-ABI FFI bridge that exposes the SignPDF engine to non-Rust front-ends (ticket P0-9).
//!
//! The Flutter app (and any other platform adapter) loads the compiled shared library
//! (`signpdf_ffi.dll` / `libsignpdf_ffi.so` / `libsignpdf_ffi.dylib`) and calls these `extern "C"`
//! functions through `dart:ffi`. The boundary is deliberately tiny and language-agnostic:
//!
//! * Inputs are raw byte buffers (`ptr` + `len`) — no Rust types leak across the boundary.
//! * Outputs are returned in a caller-owned [`SignPdfBuffer`]; on success it holds the payload
//!   (UTF-8 JSON, or raw PDF bytes for prepare/sign/certificate), on failure a UTF-8 error
//!   message. The caller distinguishes the two by the returned status code and **must** release
//!   the buffer with [`signpdf_buffer_free`].
//! * **No panic crosses the boundary**: every entry point runs under `catch_unwind` and reports
//!   [`SIGNPDF_ERR_PANIC`] instead of aborting the host process on a malformed input.
//! * **Private keys stay in Rust.** [`signpdf_new_ephemeral_identity`] keeps the ephemeral
//!   signing key in an in-process registry and hands the host an opaque, single-use `handle`;
//!   prepare/sign accept `{"handle": "…"}` in place of a key-carrying `Identity`.
//! * **Signature timestamps (PAdES B-T)** are added in steps around the host's own HTTP call to
//!   the time-stamp authority: [`signpdf_sign_for_timestamp`] (or [`signpdf_sign`] on an envelope
//!   whose policy requires timestamps), then [`signpdf_timestamp_request`] and
//!   [`signpdf_add_timestamp`], which need no key. The envelope's `signature_timestamps` policy is
//!   enforced: an envelope that takes none is never timestamped.
//! * **Increments.** A signature only appends bytes. [`signpdf_sign_increment`] and
//!   [`signpdf_sign_for_timestamp_increment`] return just those, and the `signpdf_increment_*`
//!   timestamp steps take the document and the increment apart, for a host that stores or uploads
//!   increments. When the head moved, a holder answers with [`signpdf_increment_after`] and the
//!   client checks the answer with [`signpdf_check_increment`].
//! * **Several documents.** [`signpdf_combine_documents`] combines documents into the one PDF an
//!   envelope of several documents signs, with its documents index (for the prepare request), and
//!   [`signpdf_extract_document`] cuts a convenience copy of one of them out of an envelope.
//! * **Typed signatures.** [`signpdf_typed_signature`] turns a typed name into the glyph outlines
//!   of a font the app ships, for the sign request's `typed_signature`; the PDF carries filled
//!   paths, never the font or the name as text.
//! * **Intake.** [`signpdf_images_to_pdf`] turns photos, scans and image files (JPEG, and TIFF
//!   with every page) into one PDF on the device; [`signpdf_source_info`] says what a chosen PDF
//!   needs (an open password, a PDF/A claim, layers) and [`signpdf_decrypt`] removes an open
//!   password with the password the person typed. Refusals are [`SIGNPDF_ERR_WORKFLOW`] with a
//!   message that starts with a stable code (`wrong_password: …`; `signpdf_core::intake`).

use std::collections::HashMap;
use std::os::raw::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::Mutex;

use serde::Deserialize;
use signpdf_core::crypto::{sha256_hex, KeyPair};
use signpdf_core::documents::wire;
use signpdf_core::intake;
use signpdf_core::{
    check_increment, combine_documents, completion_certificate, compute_nonce,
    embed_increment_signature_timestamp, embed_signature_timestamp, extract_document,
    increment_after, increment_signature_timestamp_digest, prepare, read_envelope, sign,
    sign_for_timestamp, sign_for_timestamp_increment, sign_increment, signature_timestamp_digest,
    timestamp, typed_signature, verify, Head, Identity, PrepareRequest, SignPdfError, SignRequest,
    TrustStore,
};

/// Status codes returned by every fallible FFI function.
pub const SIGNPDF_OK: c_int = 0;
/// A required input pointer was null or otherwise invalid.
pub const SIGNPDF_ERR_INPUT: c_int = 1;
/// The engine returned an error (the out-buffer holds a UTF-8 message). Most engine errors are
/// reported with one of the category codes below (`SIGNPDF_ERR_WORKFLOW` and following); this
/// one remains for the rest (I/O, the ephemeral-key registry).
pub const SIGNPDF_ERR_ENGINE: c_int = 2;
/// Serializing the result to JSON failed (the out-buffer holds a UTF-8 message).
pub const SIGNPDF_ERR_ENCODE: c_int = 3;
/// A JSON input argument (request, identity or trust store) could not be parsed.
pub const SIGNPDF_ERR_DECODE: c_int = 4;
/// The engine panicked (a bug or a pathological input); the host process was protected.
pub const SIGNPDF_ERR_PANIC: c_int = 5;

// Engine errors by category. The out-buffer holds the engine's own message, which is English;
// the code lets a host explain the failure in the user's language.

/// The document's workflow rules refuse the request (wrong signer, out of turn, a missing
/// field, an expired envelope…).
pub const SIGNPDF_ERR_WORKFLOW: c_int = 10;
/// The document failed verification.
pub const SIGNPDF_ERR_VERIFICATION: c_int = 11;
/// The identity token was not accepted.
pub const SIGNPDF_ERR_IDENTITY: c_int = 12;
/// The PDF, or the envelope embedded in it, could not be read or written.
pub const SIGNPDF_ERR_DOCUMENT: c_int = 13;
/// A signature timestamp could not be obtained or validated.
pub const SIGNPDF_ERR_TIMESTAMP: c_int = 14;
/// A cryptographic operation or a key store failed.
pub const SIGNPDF_ERR_CRYPTO: c_int = 15;
/// The document was made by a newer version of SignPDF: its envelope schema version is newer
/// than this engine understands. Nothing was signed, and the document was not judged valid or
/// invalid. Tell the user to update the app (or, in a browser, reload the page).
pub const SIGNPDF_ERR_UNSUPPORTED_VERSION: c_int = 16;
/// The document, or an envelope's documents together, are larger than an envelope may be (50 MB,
/// `signpdf_core::MAX_ENVELOPE_BYTES`). Nothing was combined or prepared. Tell the user to remove
/// a document or make one smaller.
pub const SIGNPDF_ERR_TOO_LARGE: c_int = 17;

/// An owned byte buffer handed across the FFI boundary.
///
/// The memory is allocated by Rust and **must** be released by calling [`signpdf_buffer_free`];
/// the caller must not free it with `free()`/`delete`.
#[repr(C)]
pub struct SignPdfBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl SignPdfBuffer {
    fn from_vec(mut v: Vec<u8>) -> Self {
        let buf = SignPdfBuffer {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            cap: v.capacity(),
        };
        // Ownership transfers to the caller; `signpdf_buffer_free` reconstitutes and drops it.
        std::mem::forget(v);
        buf
    }

    fn empty() -> Self {
        SignPdfBuffer {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Write a result vector into the caller-provided out-buffer slot (if non-null).
fn write_out(out: *mut SignPdfBuffer, v: Vec<u8>) {
    if !out.is_null() {
        // SAFETY: `out` is non-null and the caller guarantees it points at writable storage for
        // one `SignPdfBuffer` (callers pass `&mut SignPdfBuffer`).
        unsafe { ptr::write(out, SignPdfBuffer::from_vec(v)) };
    }
}

/// Borrow an input buffer as a slice, or `None` if the pointer is null.
///
/// # Safety
/// `ptr` must either be null or point at `len` initialized, immutable bytes that outlive the call.
unsafe fn input_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        if len == 0 {
            // A zero-length input is represented as an empty slice, not an error.
            Some(&[])
        } else {
            None
        }
    } else {
        Some(slice::from_raw_parts(ptr, len))
    }
}

/// The outcome of an FFI operation before it is written to the out-buffer.
type FfiResult = std::result::Result<Vec<u8>, (c_int, String)>;

/// Run `f`, converting its result (or a panic) into a status code + out-buffer payload.
fn guarded(out: *mut SignPdfBuffer, f: impl FnOnce() -> FfiResult) -> c_int {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(bytes)) => {
            write_out(out, bytes);
            SIGNPDF_OK
        }
        Ok(Err((code, msg))) => {
            write_out(out, msg.into_bytes());
            code
        }
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            write_out(out, format!("internal error (panic): {msg}").into_bytes());
            SIGNPDF_ERR_PANIC
        }
    }
}

/// An engine error as its category code and message.
fn engine_err(e: SignPdfError) -> (c_int, String) {
    let code = match &e {
        SignPdfError::Workflow(_) => SIGNPDF_ERR_WORKFLOW,
        SignPdfError::Verification(_) => SIGNPDF_ERR_VERIFICATION,
        SignPdfError::Oidc(_) => SIGNPDF_ERR_IDENTITY,
        SignPdfError::Pades(_)
        | SignPdfError::Container(_)
        | SignPdfError::Encoding(_)
        | SignPdfError::Serde(_) => SIGNPDF_ERR_DOCUMENT,
        SignPdfError::Timestamp(_) => SIGNPDF_ERR_TIMESTAMP,
        SignPdfError::Crypto(_) | SignPdfError::Keystore(_) => SIGNPDF_ERR_CRYPTO,
        SignPdfError::UnsupportedSchemaVersion { .. } => SIGNPDF_ERR_UNSUPPORTED_VERSION,
        SignPdfError::TooLarge(_) => SIGNPDF_ERR_TOO_LARGE,
        SignPdfError::Io(_) => SIGNPDF_ERR_ENGINE,
    };
    (code, e.to_string())
}

/// An error of the bridge itself (the ephemeral-key registry), outside the engine's categories.
fn registry_err(msg: &str) -> (c_int, String) {
    (SIGNPDF_ERR_ENGINE, msg.to_string())
}

fn encode_err(e: impl ToString) -> (c_int, String) {
    (SIGNPDF_ERR_ENCODE, e.to_string())
}

/// # Safety
/// See [`input_slice`].
unsafe fn required<'a>(
    ptr: *const u8,
    len: usize,
    label: &str,
) -> Result<&'a [u8], (c_int, String)> {
    input_slice(ptr, len).ok_or_else(|| (SIGNPDF_ERR_INPUT, format!("null {label} pointer")))
}

/// Parse a required JSON input argument into `T`.
///
/// # Safety
/// `ptr`/`len` must describe a valid byte range (or `ptr` null with `len` 0).
unsafe fn parse_json_arg<T: serde::de::DeserializeOwned>(
    ptr: *const u8,
    len: usize,
    label: &str,
) -> Result<T, (c_int, String)> {
    let bytes = input_slice(ptr, len)
        .ok_or_else(|| (SIGNPDF_ERR_DECODE, format!("null {label} pointer")))?;
    serde_json::from_slice::<T>(bytes)
        .map_err(|e| (SIGNPDF_ERR_DECODE, format!("invalid {label} JSON: {e}")))
}

/// Parse an optional trust-store JSON argument (null/empty = the well-known store).
///
/// # Safety
/// See [`input_slice`].
unsafe fn parse_trust(ptr: *const u8, len: usize) -> Result<TrustStore, (c_int, String)> {
    match input_slice(ptr, len) {
        None | Some([]) => Ok(TrustStore::well_known()),
        // Through the store's own parser, which upgrades stores saved by older versions.
        Some(bytes) => TrustStore::from_json_bytes(bytes)
            .map_err(|e| (SIGNPDF_ERR_DECODE, format!("invalid trust store JSON: {e}"))),
    }
}

// --- ephemeral key registry ----------------------------------------------------------------

/// Ephemeral signing keys minted for the host, by opaque handle. The private scalar never leaves
/// Rust; `SigningKey` zeroizes on drop when a key is used or discarded.
fn registry() -> &'static Mutex<HashMap<String, KeyPair>> {
    static REG: std::sync::OnceLock<Mutex<HashMap<String, KeyPair>>> = std::sync::OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The key argument of prepare/sign: an ephemeral handle, or (legacy/dev) a full identity.
///
/// `Full` is tried first: an `Identity` also has a (person) `handle` field, but only it carries
/// `secret_b64`, so a key-handle object never deserializes as `Full`.
#[derive(Deserialize)]
#[serde(untagged)]
enum KeyArg {
    Full(Identity),
    Handle { handle: String },
}

/// Resolve a key argument, run `f` with the key, and consume a handle only on success (so a host
/// can retry after a recoverable error such as a wrong slot assertion).
fn with_key(arg: KeyArg, f: impl FnOnce(&KeyPair) -> FfiResult) -> FfiResult {
    match arg {
        KeyArg::Full(identity) => {
            let kp = identity.key_pair().map_err(engine_err)?;
            f(&kp)
        }
        KeyArg::Handle { handle } => {
            let kp = registry()
                .lock()
                .map_err(|_| registry_err("key registry poisoned"))?
                .remove(&handle)
                .ok_or_else(|| registry_err("unknown or already-used ephemeral identity handle"))?;
            let result = f(&kp);
            if result.is_err() {
                if let Ok(mut reg) = registry().lock() {
                    reg.insert(handle, kp);
                }
            }
            result
        }
    }
}

// --- exported functions --------------------------------------------------------------------

/// Write the engine version (the crate's semver) into `out`. Always returns [`SIGNPDF_OK`]; useful
/// as a smoke test that the library is loaded and the ABI matches.
///
/// # Safety
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_version(out: *mut SignPdfBuffer) -> c_int {
    guarded(out, || Ok(env!("CARGO_PKG_VERSION").as_bytes().to_vec()))
}

/// Write the catalogue of stable message codes into `out`, as JSON `[{"code", "severity", "en"},
/// ...]` (`signpdf_core::messages::CODES`): the codes of the verification report's `findings`, of
/// engine errors (`signpdf_core::SignPdfError::code`) and of refused field values. Hosts translate
/// by code and fall back to `en`. Always [`SIGNPDF_OK`].
///
/// # Safety
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_message_codes(out: *mut SignPdfBuffer) -> c_int {
    guarded(out, || {
        Ok(signpdf_core::messages::catalogue_json().into_bytes())
    })
}

/// Verify a PDF against the **well-known** trust store (Google/Microsoft/Apple issuers, but no
/// pinned keys — so identities report `unknown-key` until the host supplies a populated store via
/// [`signpdf_verify_with_trust`]). On [`SIGNPDF_OK`] the out-buffer holds the JSON
/// `VerificationReport`.
///
/// # Safety
/// `pdf_ptr`/`pdf_len` must describe a valid byte range (or `pdf_ptr` may be null with `pdf_len`
/// 0); `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_verify(
    pdf_ptr: *const u8,
    pdf_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    signpdf_verify_with_trust(pdf_ptr, pdf_len, ptr::null(), 0, out)
}

/// Verify all signatures, the revision chain, audit log, order and identities of a PDF against
/// the JSON `TrustStore` in `trust_ptr` (null/empty = the well-known store).
///
/// On [`SIGNPDF_OK`] the out-buffer holds the JSON `VerificationReport` (whose `valid` field is
/// the headline result). On error it holds a UTF-8 message.
///
/// # Safety
/// Each `*_ptr`/`*_len` pair must describe a valid byte range (or a null pointer with 0 length);
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_verify_with_trust(
    pdf_ptr: *const u8,
    pdf_len: usize,
    trust_ptr: *const u8,
    trust_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let trust = parse_trust(trust_ptr, trust_len)?;
        let report = verify(pdf, &trust).map_err(engine_err)?;
        serde_json::to_vec(&report).map_err(encode_err)
    })
}

/// Verify a PDF against `trust` (as in [`signpdf_verify_with_trust`]) and return a **certificate of
/// completion** PDF (raw bytes) summarizing the verdict, identities, and audit trail.
///
/// # Safety
/// See [`signpdf_verify_with_trust`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_completion_certificate(
    pdf_ptr: *const u8,
    pdf_len: usize,
    trust_ptr: *const u8,
    trust_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let trust = parse_trust(trust_ptr, trust_len)?;
        completion_certificate(pdf, &trust).map_err(engine_err)
    })
}

/// Write the well-known trust store (issuers without pinned keys, plus the bundled TSA anchor) as
/// JSON — the starting point a host refreshes with each issuer's published JWKS.
///
/// # Safety
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_trust_well_known(out: *mut SignPdfBuffer) -> c_int {
    guarded(out, || {
        TrustStore::well_known()
            .to_json()
            .map(String::into_bytes)
            .map_err(encode_err)
    })
}

/// Pin every key of a JWKS (`{"keys": [...]}`) for `issuer` in a JSON trust store (null/empty =
/// the well-known store), keeping previously pinned keys. On [`SIGNPDF_OK`] the out-buffer holds
/// the updated trust store JSON. Hosts call this with JWKS they fetched themselves over TLS. A
/// validity window the issuer publishes next to a key (`not_before`, `not_after`,
/// `distrusted_after`) is kept, and only ever narrows a key already pinned; an unreadable one is
/// refused with [`SIGNPDF_ERR_DECODE`].
///
/// # Safety
/// Each `*_ptr`/`*_len` pair must describe a valid byte range (or a null pointer with 0 length);
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_trust_add_jwks(
    trust_ptr: *const u8,
    trust_len: usize,
    issuer_ptr: *const u8,
    issuer_len: usize,
    jwks_ptr: *const u8,
    jwks_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let mut store = parse_trust(trust_ptr, trust_len)?;
        let issuer =
            String::from_utf8_lossy(required(issuer_ptr, issuer_len, "issuer")?).to_string();
        let jwks: signpdf_core::PublishedJwks = parse_json_arg(jwks_ptr, jwks_len, "JWKS")?;
        store
            .add_published_jwks(&issuer, &jwks)
            .map_err(|e| (SIGNPDF_ERR_DECODE, e.to_string()))?;
        store.to_json().map(String::into_bytes).map_err(encode_err)
    })
}

/// Page geometry of a PDF as JSON: `[{index, media_box, crop_box, rotate, annotations}]`, boxes
/// as normalised `[x1, y1, x2, y2]` in default user space (points, origin bottom-left,
/// unrotated) — the space field rectangles use. The field editor converts screen positions with
/// this, so the engine (not the renderer) is the authority on where a field lands.
///
/// # Safety
/// See [`signpdf_verify`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_page_geometry(
    pdf_ptr: *const u8,
    pdf_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let pages = signpdf_core::pades::page_geometry(pdf).map_err(engine_err)?;
        serde_json::to_vec(&pages).map_err(encode_err)
    })
}

/// Combine several documents into the one PDF an envelope of several documents signs, with its
/// index (`signpdf_core::combine_documents`).
///
/// Inputs: a UTF-8 JSON manifest `{"documents": [{"name": "NDA.pdf", "len": <bytes>}, …]}`
/// and one buffer holding the documents' PDFs one after the other, in the manifest's order (the
/// lengths add up to the buffer's). On [`SIGNPDF_OK`] the out-buffer holds the length of the
/// index JSON as 4 bytes (big-endian), the index JSON `{"documents": [{"name", "first_page",
/// "page_count", "source_digest"}, …]}`, then the combined PDF. Pass the index as the
/// `documents` of the [`PrepareRequest`] that prepares that PDF. One document comes back as it
/// was. Refused with [`SIGNPDF_ERR_DECODE`] (a manifest that does not parse or add up),
/// [`SIGNPDF_ERR_WORKFLOW`] (more than 20 documents, a name, a file that is not a PDF, is
/// encrypted or signed) and [`SIGNPDF_ERR_TOO_LARGE`] (over 50 MB together).
///
/// # Safety
/// Each `*_ptr`/`*_len` pair must describe a valid byte range (or a null pointer with 0 length);
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_combine_documents(
    manifest_ptr: *const u8,
    manifest_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let manifest: wire::Manifest = parse_json_arg(manifest_ptr, manifest_len, "manifest")?;
        let data = required(data_ptr, data_len, "documents")?;
        let docs = wire::split(&manifest, data).map_err(|e| (SIGNPDF_ERR_DECODE, e))?;
        let combined = combine_documents(&docs).map_err(engine_err)?;
        wire::frame(&combined).map_err(encode_err)
    })
}

/// A convenience copy of one document of an envelope of several (`signpdf_core::extract_document`):
/// only that document's pages, as they look in `pdf` (a prepared or signed envelope), with a
/// banner above its first page saying it is a copy and that the combined PDF is what was signed.
/// `index` is 0-based in the envelope's `documents`. On [`SIGNPDF_OK`] the out-buffer holds the
/// copy's PDF bytes; name the file with the envelope's document name followed by "(convenience
/// copy - verify the combined file)" (`signpdf_core::convenience_copy_name`). Refused with
/// [`SIGNPDF_ERR_WORKFLOW`] for an envelope without a documents index or an index out of range.
///
/// # Safety
/// See [`signpdf_verify`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_extract_document(
    pdf_ptr: *const u8,
    pdf_len: usize,
    index: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        extract_document(pdf, index).map_err(engine_err)
    })
}

/// A typed signature (`signpdf_core::typed_signature`): the glyph outlines of `name` (UTF-8,
/// normalized to NFC by the host) set in `font` (the bytes of a TrueType or OpenType font file the
/// app ships). On [`SIGNPDF_OK`] the out-buffer holds UTF-8 JSON, the paths to send as the
/// [`SignRequest`]'s `typed_signature`. Refused with [`SIGNPDF_ERR_WORKFLOW`] and a message for
/// the signer when the name is empty or too long, uses a script the engine cannot lay out
/// (Arabic, Hebrew, the Indic scripts…), has a character the font does not draw (offer another
/// font, or drawing), or is too detailed, or when the font cannot be read;
/// [`SIGNPDF_ERR_DECODE`] when `name` is not UTF-8.
///
/// # Safety
/// Each `*_ptr`/`*_len` pair must describe a valid byte range (or a null pointer with 0 length);
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_typed_signature(
    font_ptr: *const u8,
    font_len: usize,
    name_ptr: *const u8,
    name_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let font = required(font_ptr, font_len, "font")?;
        let name = required(name_ptr, name_len, "name")?;
        let name = std::str::from_utf8(name).map_err(|_| {
            (
                SIGNPDF_ERR_DECODE,
                "the typed name is not UTF-8 text".to_string(),
            )
        })?;
        let paths = typed_signature(font, name).map_err(|e| (SIGNPDF_ERR_WORKFLOW, e))?;
        serde_json::to_vec(&paths).map_err(encode_err)
    })
}

/// Images as one PDF on the device (`signpdf_core::intake::images_to_pdf`): one page per image,
/// every page of a multi-page TIFF, fitted to A4 or US Letter. `manifest` is UTF-8 JSON
/// `{"paper": "a4" | "letter", "images": [{"len": <bytes>, "margin": <points>}, …]}` and `data`
/// the image files (JPEG or TIFF; decode other formats to JPEG first) one after the other. On
/// [`SIGNPDF_OK`] the out-buffer holds the length of a JSON summary (4 bytes, big-endian), the
/// summary `{"pages": [...]}`, then the PDF. [`SIGNPDF_ERR_DECODE`]: the manifest does not parse
/// or add up. [`SIGNPDF_ERR_WORKFLOW`]: a message starting with `not_an_image`,
/// `unsupported_image`, `unreadable_image`, `too_many_pages` or `too_many_pixels`.
///
/// # Safety
/// See [`signpdf_verify`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_images_to_pdf(
    manifest_ptr: *const u8,
    manifest_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let manifest: intake::wire::Manifest =
            parse_json_arg(manifest_ptr, manifest_len, "manifest")?;
        let data = required(data_ptr, data_len, "images")?;
        let images = intake::wire::split(&manifest, data).map_err(|e| (SIGNPDF_ERR_DECODE, e))?;
        let made = intake::images_to_pdf(&images, manifest.paper)
            .map_err(|e| (SIGNPDF_ERR_WORKFLOW, e.to_string()))?;
        Ok(intake::wire::frame(&made))
    })
}

/// What a chosen PDF needs before it can be prepared (`signpdf_core::intake::source_info`). On
/// [`SIGNPDF_OK`] the out-buffer holds UTF-8 JSON `{"encryption": "none" | "restrictions" |
/// "open_password" | "certificate", "pdfa": "2b" | null, "layers", "hidden_layers", "pages"}`.
/// [`SIGNPDF_ERR_WORKFLOW`]: `unreadable_pdf: …`.
///
/// # Safety
/// See [`signpdf_verify`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_source_info(
    pdf_ptr: *const u8,
    pdf_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let info = intake::source_info(pdf).map_err(|e| (SIGNPDF_ERR_WORKFLOW, e.to_string()))?;
        serde_json::to_vec(&info).map_err(encode_err)
    })
}

/// A PDF with an open password decrypted with `password` (UTF-8) and saved again without
/// encryption (`signpdf_core::intake::decrypt`). On [`SIGNPDF_OK`] the out-buffer holds the PDF.
/// [`SIGNPDF_ERR_WORKFLOW`]: a message starting with `wrong_password`, `not_encrypted`,
/// `no_open_password`, `certificate_encryption` or `unreadable_pdf`. [`SIGNPDF_ERR_DECODE`]: the
/// password is not UTF-8.
///
/// # Safety
/// See [`signpdf_verify`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_decrypt(
    pdf_ptr: *const u8,
    pdf_len: usize,
    password_ptr: *const u8,
    password_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let password = input_slice(password_ptr, password_len).unwrap_or(&[]);
        let password = std::str::from_utf8(password).map_err(|_| {
            (
                SIGNPDF_ERR_DECODE,
                "the password is not UTF-8 text".to_string(),
            )
        })?;
        intake::decrypt(pdf, password).map_err(|e| (SIGNPDF_ERR_WORKFLOW, e.to_string()))
    })
}

/// Read the embedded SignPDF envelope (signers, fields, policy, audit log) as JSON.
///
/// On [`SIGNPDF_OK`] the out-buffer holds the JSON-serialized `Envelope`; on error a UTF-8 message
/// (e.g. when the PDF carries no SignPDF envelope).
///
/// # Safety
/// See [`signpdf_verify`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_read_envelope(
    pdf_ptr: *const u8,
    pdf_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let env = read_envelope(pdf).map_err(engine_err)?;
        serde_json::to_vec(&env).map_err(encode_err)
    })
}

/// Prepare a source PDF for signing: embed the workflow envelope (signers, fields, policy, signed
/// audit entry), sign it as the preparer, and return the prepared PDF.
///
/// Inputs: the source PDF bytes, a UTF-8 JSON [`PrepareRequest`], and the preparer's key as UTF-8
/// JSON — `{"handle": "…"}` from [`signpdf_new_ephemeral_identity`] (preferred), or a full
/// [`Identity`]. On [`SIGNPDF_OK`] the out-buffer holds the **raw prepared PDF bytes** (binary). On
/// [`SIGNPDF_ERR_DECODE`] a request/identity argument failed to parse; on [`SIGNPDF_ERR_ENGINE`]
/// the engine rejected the request — both write a UTF-8 message.
///
/// # Safety
/// Each `*_ptr`/`*_len` pair must describe a valid byte range (or the pointer may be null with a 0
/// length); `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_prepare(
    pdf_ptr: *const u8,
    pdf_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    identity_ptr: *const u8,
    identity_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let request: PrepareRequest = parse_json_arg(request_ptr, request_len, "prepare request")?;
        let key: KeyArg = parse_json_arg(identity_ptr, identity_len, "identity")?;
        with_key(key, |kp| prepare(pdf, &request, kp).map_err(engine_err))
    })
}

/// Sign (or decline) a prepared PDF as a particular signer and return the updated PDF.
///
/// Inputs: the prepared PDF bytes, a UTF-8 JSON [`SignRequest`], and the signer's key as in
/// [`signpdf_prepare`]. On [`SIGNPDF_OK`] the out-buffer holds the **raw signed PDF bytes**
/// (binary). Error semantics match [`signpdf_prepare`].
///
/// Signature timestamps follow the envelope's `policy.signature_timestamps` (absent means
/// `optional`): under `required` the signature is made with room for one, which the host then adds
/// with [`signpdf_timestamp_request`] and [`signpdf_add_timestamp`]; under `optional` the host
/// that wants one signs with [`signpdf_sign_for_timestamp`] instead; under `none` there is none.
///
/// # Safety
/// See [`signpdf_prepare`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_sign(
    pdf_ptr: *const u8,
    pdf_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    identity_ptr: *const u8,
    identity_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let request: SignRequest = parse_json_arg(request_ptr, request_len, "sign request")?;
        let key: KeyArg = parse_json_arg(identity_ptr, identity_len, "identity")?;
        with_key(key, |kp| sign(pdf, kp, &request).map_err(engine_err))
    })
}

/// [`signpdf_sign`] with room for a PAdES B-T signature timestamp, which the host adds next with
/// [`signpdf_timestamp_request`] and [`signpdf_add_timestamp`] (its own HTTP client posts the
/// request to the time-stamp authority). Same arguments; the key handle is consumed here. On
/// [`SIGNPDF_OK`] the out-buffer holds the signed PDF bytes, already a complete B-B signature.
///
/// The envelope's `policy.signature_timestamps` decides: under `required`, [`signpdf_sign`] also
/// leaves this room; under `none` this call is refused with [`SIGNPDF_ERR_WORKFLOW`] before
/// anything is signed (the handle stays usable for [`signpdf_sign`]).
///
/// # Safety
/// See [`signpdf_prepare`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_sign_for_timestamp(
    pdf_ptr: *const u8,
    pdf_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    identity_ptr: *const u8,
    identity_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let request: SignRequest = parse_json_arg(request_ptr, request_len, "sign request")?;
        let key: KeyArg = parse_json_arg(identity_ptr, identity_len, "identity")?;
        with_key(key, |kp| {
            sign_for_timestamp(pdf, kp, &request).map_err(engine_err)
        })
    })
}

/// The RFC 3161 request for a signature timestamp of the PDF's last revision, which must be a
/// signer revision that is valid, covers the whole file and has no timestamp yet. On
/// [`SIGNPDF_OK`] the out-buffer holds a DER `TimeStampReq` over the SHA-256 of the signature
/// value: POST it to the time-stamp authority with `Content-Type: application/timestamp-query`.
/// Refused with [`SIGNPDF_ERR_WORKFLOW`] when the envelope's policy is
/// `signature_timestamps = none`, so no timestamp is ever requested for such an envelope.
///
/// # Safety
/// See [`signpdf_verify`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_timestamp_request(
    pdf_ptr: *const u8,
    pdf_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        signature_timestamp_digest(pdf)
            .map(|digest| timestamp::build_request(&digest))
            .map_err(engine_err)
    })
}

/// Embed the time-stamp authority's answer to [`signpdf_timestamp_request`] (the DER
/// `TimeStampResp` body of its HTTP response) as the last revision's signature timestamp. Needs
/// no key. Refused with [`SIGNPDF_ERR_TIMESTAMP`] unless the authority granted a token over that
/// signature value, and with [`SIGNPDF_ERR_WORKFLOW`] as [`signpdf_timestamp_request`] is. On
/// [`SIGNPDF_OK`] the out-buffer holds the PDF bytes, same length, now PAdES B-T.
///
/// # Safety
/// Each `*_ptr`/`*_len` pair must describe a valid byte range (or a null pointer with 0 length);
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_add_timestamp(
    pdf_ptr: *const u8,
    pdf_len: usize,
    response_ptr: *const u8,
    response_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let response = required(response_ptr, response_len, "timestamp response")?;
        let digest = signature_timestamp_digest(pdf).map_err(engine_err)?;
        let token = timestamp::parse_response(response, &digest).map_err(engine_err)?;
        embed_signature_timestamp(pdf, &token.token_der).map_err(engine_err)
    })
}

/// [`signpdf_sign`], returning only the **increment**: the bytes the signature appends to the
/// PDF (the signed document is the PDF followed by them). Same arguments and errors. For a host
/// that stores or uploads increments, and never needs the signed document in memory.
///
/// # Safety
/// See [`signpdf_prepare`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_sign_increment(
    pdf_ptr: *const u8,
    pdf_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    identity_ptr: *const u8,
    identity_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let request: SignRequest = parse_json_arg(request_ptr, request_len, "sign request")?;
        let key: KeyArg = parse_json_arg(identity_ptr, identity_len, "identity")?;
        with_key(key, |kp| {
            sign_increment(pdf, kp, &request).map_err(engine_err)
        })
    })
}

/// [`signpdf_sign_for_timestamp`], returning only the increment, as [`signpdf_sign_increment`]
/// does. Add the timestamp with [`signpdf_increment_timestamp_request`] and
/// [`signpdf_increment_add_timestamp`].
///
/// # Safety
/// See [`signpdf_prepare`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_sign_for_timestamp_increment(
    pdf_ptr: *const u8,
    pdf_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    identity_ptr: *const u8,
    identity_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let request: SignRequest = parse_json_arg(request_ptr, request_len, "sign request")?;
        let key: KeyArg = parse_json_arg(identity_ptr, identity_len, "identity")?;
        with_key(key, |kp| {
            sign_for_timestamp_increment(pdf, kp, &request).map_err(engine_err)
        })
    })
}

/// [`signpdf_timestamp_request`] for a document held apart: `head` (the PDF that was signed) and
/// `increment` (what [`signpdf_sign_for_timestamp_increment`] returned). Same result and
/// refusals; neither input is copied into a whole document.
///
/// # Safety
/// Each `*_ptr`/`*_len` pair must describe a valid byte range (or a null pointer with 0 length);
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_increment_timestamp_request(
    head_ptr: *const u8,
    head_len: usize,
    increment_ptr: *const u8,
    increment_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let head = required(head_ptr, head_len, "head")?;
        let increment = required(increment_ptr, increment_len, "increment")?;
        increment_signature_timestamp_digest(head, increment)
            .map(|digest| timestamp::build_request(&digest))
            .map_err(engine_err)
    })
}

/// [`signpdf_add_timestamp`] for a document held apart, as
/// [`signpdf_increment_timestamp_request`]. On [`SIGNPDF_OK`] the out-buffer holds the new
/// **increment**, the same length (only the signature's `/Contents` changes).
///
/// # Safety
/// Each `*_ptr`/`*_len` pair must describe a valid byte range (or a null pointer with 0 length);
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_increment_add_timestamp(
    head_ptr: *const u8,
    head_len: usize,
    increment_ptr: *const u8,
    increment_len: usize,
    response_ptr: *const u8,
    response_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let head = required(head_ptr, head_len, "head")?;
        let increment = required(increment_ptr, increment_len, "increment")?;
        let response = required(response_ptr, response_len, "timestamp response")?;
        let digest = increment_signature_timestamp_digest(head, increment).map_err(engine_err)?;
        let token = timestamp::parse_response(response, &digest).map_err(engine_err)?;
        embed_increment_signature_timestamp(head, increment, &token.token_der).map_err(engine_err)
    })
}

/// For the holder of a document whose head moved: the bytes of `pdf` after the client's head,
/// given as UTF-8 JSON `{"len": <bytes>, "sha256": "<hex>"}`. On [`SIGNPDF_OK`] the out-buffer
/// holds those bytes (empty when the head did not move). Refused with [`SIGNPDF_ERR_WORKFLOW`]
/// when the head is not a revision of `pdf` (longer, another digest, not ending a revision): the
/// client then fetches the whole document.
///
/// # Safety
/// Each `*_ptr`/`*_len` pair must describe a valid byte range (or a null pointer with 0 length);
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_increment_after(
    pdf_ptr: *const u8,
    pdf_len: usize,
    head_ptr: *const u8,
    head_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let head: Head = parse_json_arg(head_ptr, head_len, "head")?;
        increment_after(pdf, &head)
            .map(<[u8]>::to_vec)
            .map_err(engine_err)
    })
}

/// For the client: check that `increment` (what the holder sent) extends `head` (the revision
/// the client holds) into the announced document `expected` (UTF-8 JSON `{"len", "sha256"}`),
/// hashing the head in place. On [`SIGNPDF_OK`] the out-buffer holds the new head as the same
/// JSON. Refused with [`SIGNPDF_ERR_WORKFLOW`] when the lengths do not add up, the increment was
/// cut short or the digest differs.
///
/// # Safety
/// Each `*_ptr`/`*_len` pair must describe a valid byte range (or a null pointer with 0 length);
/// `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_check_increment(
    head_ptr: *const u8,
    head_len: usize,
    increment_ptr: *const u8,
    increment_len: usize,
    expected_ptr: *const u8,
    expected_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let head = required(head_ptr, head_len, "head")?;
        let increment = required(increment_ptr, increment_len, "increment")?;
        let expected: Head = parse_json_arg(expected_ptr, expected_len, "expected head")?;
        let new_head = check_increment(head, increment, &expected).map_err(engine_err)?;
        serde_json::to_vec(&new_head).map_err(encode_err)
    })
}

/// Mint a fresh **ephemeral signing key** stapled to one document, for the federated (keyless)
/// flow.
///
/// The host calls this *before* logging in to the OIDC provider. It generates a throwaway P-256
/// key **kept inside Rust**, hashes the document, and derives the OIDC `nonce` that binds the key
/// to the document. On [`SIGNPDF_OK`] the out-buffer holds UTF-8 JSON:
///
/// ```json
/// { "identity": { "handle": "<opaque>", "public_b64": "…", "fingerprint": "…" },
///   "nonce": "<hex>", "doc_digest": "<hex>" }
/// ```
///
/// The host then:
/// 1. runs the OIDC Authorization Code flow, sending `nonce` in the authorization request;
/// 2. on success, passes the resulting `id_token` + provider `idp_jwk` inside a
///    [`SignRequest`]/[`PrepareRequest`], together with `{"handle": …}`, to
///    [`signpdf_sign`]/[`signpdf_prepare`] — the handle is consumed by the first successful use;
/// 3. calls [`signpdf_discard_ephemeral`] if it abandons the flow.
///
/// # Safety
/// `pdf_ptr`/`pdf_len` must describe a valid byte range (or `pdf_ptr` may be null with `pdf_len`
/// 0); `out` must point at writable storage for one [`SignPdfBuffer`].
#[no_mangle]
pub unsafe extern "C" fn signpdf_new_ephemeral_identity(
    pdf_ptr: *const u8,
    pdf_len: usize,
    out: *mut SignPdfBuffer,
) -> c_int {
    guarded(out, || {
        let pdf = required(pdf_ptr, pdf_len, "pdf")?;
        let key = KeyPair::generate();
        let doc_digest = sha256_hex(pdf);
        let nonce = compute_nonce(&key.public_sec1(), &doc_digest);
        let handle = signpdf_core::crypto::random_id();
        let payload = serde_json::json!({
            "identity": {
                "handle": handle,
                "public_b64": key.public_b64(),
                "fingerprint": key.fingerprint(),
            },
            "nonce": nonce,
            "doc_digest": doc_digest,
        });
        registry()
            .lock()
            .map_err(|_| registry_err("key registry poisoned"))?
            .insert(handle, key);
        serde_json::to_vec(&payload).map_err(encode_err)
    })
}

/// Discard an unused ephemeral key by handle (UTF-8). Returns [`SIGNPDF_OK`] whether or not the
/// handle existed.
///
/// # Safety
/// `handle_ptr`/`handle_len` must describe a valid byte range (or a null pointer with 0 length).
#[no_mangle]
pub unsafe extern "C" fn signpdf_discard_ephemeral(
    handle_ptr: *const u8,
    handle_len: usize,
) -> c_int {
    let Some(bytes) = input_slice(handle_ptr, handle_len) else {
        return SIGNPDF_ERR_INPUT;
    };
    let handle = String::from_utf8_lossy(bytes).to_string();
    let _ = catch_unwind(|| {
        if let Ok(mut reg) = registry().lock() {
            reg.remove(&handle);
        }
    });
    SIGNPDF_OK
}

/// Release a [`SignPdfBuffer`] returned by any function in this library.
///
/// Safe to call on an empty/zeroed buffer (no-op). Must be called exactly once per returned buffer.
///
/// # Safety
/// `buf` must be a buffer produced by this library and not previously freed.
#[no_mangle]
pub unsafe extern "C" fn signpdf_buffer_free(buf: SignPdfBuffer) {
    if !buf.ptr.is_null() {
        drop(Vec::from_raw_parts(buf.ptr, buf.len, buf.cap));
    }
}

/// Convenience for callers that prefer to receive a fresh zeroed buffer to fill.
#[no_mangle]
pub extern "C" fn signpdf_buffer_new() -> SignPdfBuffer {
    SignPdfBuffer::empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panics_are_contained() {
        let mut out = SignPdfBuffer::empty();
        let code = guarded(&mut out, || panic!("boom"));
        assert_eq!(code, SIGNPDF_ERR_PANIC);
        let msg = unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec();
        unsafe { signpdf_buffer_free(out) };
        assert!(String::from_utf8(msg).unwrap().contains("boom"));
    }
}
