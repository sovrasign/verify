//! Browser signing (feature `signing`): prepare and sign a document in the page, with the
//! participant's **ephemeral signing key kept inside WASM memory**.
//!
//! The flow is the native apps' federated, keyless one, over the same raw ABI as the verifier
//! exports:
//!
//! 1. [`signpdf_new_ephemeral_identity`] generates a fresh P-256 key for one document and returns
//!    only its public half, an opaque `handle`, and the OIDC `nonce` that binds the key to the
//!    document (`SHA-256(pubkey ‖ doc digest)`).
//! 2. The page signs the user in with their identity provider, sending that `nonce`.
//! 3. [`signpdf_prepare`] / [`signpdf_sign`] take the request JSON (with the ID token and the
//!    provider's JWK) and `{"handle": "…"}`. The engine checks the token, its nonce binding and
//!    the signer slot exactly as on native builds. A successful call consumes the handle and
//!    drops the key, which zeroizes its scalar (`ecdsa::SigningKey` is `ZeroizeOnDrop`); a failed
//!    call keeps it so the page can retry (a wrong slot assertion, an expired token).
//! 4. [`signpdf_discard_ephemeral`] drops a key the page no longer needs.
//!
//! **Signature timestamps (PAdES B-T)** take two more steps, because the engine's timestamper is
//! synchronous and a TSA request from a page is an asynchronous `fetch`:
//! [`signpdf_sign_for_timestamp`] signs (consuming the key) with room for a timestamp,
//! [`signpdf_timestamp_request`] returns the RFC 3161 request for that signature, and after the
//! page has POSTed it to the TSA, [`signpdf_add_timestamp`] embeds the response. The last two
//! need no key: a TSA sees only a hash of the signature value, and a failed TSA call can be
//! retried without signing in again.
//!
//! The envelope's `policy.signature_timestamps` decides (read it with [`signpdf_read_envelope`];
//! absent means `optional`). Under `required`, [`signpdf_sign`] already leaves room for the
//! timestamp, so the page signs and then runs the two TSA steps. Under `optional` the page
//! chooses [`signpdf_sign_for_timestamp`] or [`signpdf_sign`]. Under `none`,
//! [`signpdf_sign_for_timestamp`], [`signpdf_timestamp_request`] and [`signpdf_add_timestamp`] are
//! refused with `ERR_WORKFLOW` (the key stays usable for [`signpdf_sign`]), so a page never asks a
//! TSA for a timestamp such an envelope does not take.
//!
//! **Increments.** A signature only appends bytes to the document, and the hosted service takes
//! only those (the increment) on upload, so [`signpdf_sign_increment`] and
//! [`signpdf_sign_for_timestamp_increment`] return just the increment, and
//! [`signpdf_increment_timestamp_request`] / [`signpdf_increment_add_timestamp`] take the document
//! and the increment apart. The module then never holds the signed document beside the input: a
//! 50 MB document signs at about its own size in memory instead of twice it. When the head moved
//! (someone signed meanwhile), the page fetches only the bytes after the revision it holds and
//! checks them with [`signpdf_check_increment`] before it signs on top. The whole-document
//! exports remain.
//!
//! **Several documents.** A sender whose documents never leave the device combines them with
//! [`signpdf_combine_documents`] (the combined PDF after its documents index) and passes the index
//! as the prepare request's `documents`; [`signpdf_extract_document`] cuts a convenience copy of
//! one document out of an envelope. Hosts that combine on a server send the combined PDF instead.
//!
//! **Local dates and consent.** The page puts the signer's UTC offset in the sign request
//! (`"utc_offset_minutes": -new Date().getTimezoneOffset()`), so the dates the engine writes are
//! the signer's local date, and, when it showed the signer an e-sign disclosure, the consent
//! record (`"esign_consent"`), which the engine writes into the signer's audit entry. See
//! `docs/FFI_BRIDGE.md` ("Local dates, consent and the link back to the service").
//!
//! **Typed signatures.** When the signer picks *Type*, the page loads the font they chose (one of
//! the handwriting-style fonts it ships) and [`signpdf_typed_signature`] turns the name into the
//! glyph outlines of that font, here in the module, so the page needs no font library. The page
//! passes the result as the sign request's `typed_signature`; the engine fills the outlines in the
//! signer's box and keeps them in their signature record. The PDF never carries the font or the
//! name as text: the typed name is decoration, not a claim (the caption beside it names the
//! verified signer).
//!
//! **Intake.** Before a document is prepared, the sender's page turns images into a PDF with
//! [`signpdf_images_to_pdf`] (JPEG as it is, TIFF with every page, without decoding a pixel; the
//! page decodes other formats to JPEG itself), asks [`signpdf_source_info`] what a chosen PDF needs
//! (an open password, a PDF/A claim, layers), removes an open password with
//! [`signpdf_decrypt`] and the password the sender typed, and hashes what it uploads with
//! [`signpdf_sha256`]. Refusals are `ERR_WORKFLOW` with a message that starts with a stable code
//! (`wrong_password: …`, `unsupported_image: …`; see `signpdf_core::intake`).
//!
//! Prepare and sign take a key handle only, never the `Identity` JSON (with `secret_b64`) that the
//! FFI still accepts for development. WASM linear memory is readable by any script on the page,
//! so "only in WASM memory" is a containment rule, not an isolation boundary; see
//! `docs/spikes/p0-browser-signing.md`.
//!
//! **Keys across a redirect.** A sign-in in a window keeps the page, and this module, alive. When
//! the browser blocks that window, and on phones, the page goes to the identity provider itself
//! (a top-level redirect) and comes back, which unloads the module. For that one case
//! [`signpdf_export_ephemeral`] lets the key out (consuming its handle) and
//! [`signpdf_import_ephemeral`] takes it back for the same document after the redirect. The
//! signing page's engine worker script (`sealEphemeral` / `unsealEphemeral`) is
//! the only caller: it seals the scalar with AES-GCM under a non-extractable WebCrypto key the
//! page keeps in IndexedDB, so the page and its storage only ever hold sealed bytes, and wipes
//! its own copy. The host keeps the sealed key for at most a few minutes (the hosted signer page:
//! 10) and deletes it on first use. This is no new exposure: the scalar lives in the worker,
//! where the WASM memory that held it is anyway; the strict CSP is what protects both.
//!
//! On `wasm32` this module imports two functions from the page (module `signpdf_host`):
//! `random_fill(ptr, len) -> i32` (fill with `crypto.getRandomValues`, 0 on success) and
//! `now_ms() -> f64` (`Date.now()`). Native builds (the unit tests) use the OS instead.

use std::cell::RefCell;
use std::collections::HashMap;

use serde::Deserialize;
use signpdf_core::crypto::{random_id, sha256_hex, KeyPair};
use signpdf_core::documents::wire;
use signpdf_core::intake;
use signpdf_core::{
    check_increment, combine_documents, compute_nonce, embed_increment_signature_timestamp,
    embed_signature_timestamp, extract_document, increment_signature_timestamp_digest, prepare,
    read_envelope, sign, sign_for_timestamp, sign_for_timestamp_increment, sign_increment,
    signature_timestamp_digest, timestamp, typed_signature, Head, PrepareRequest, SignRequest,
};

use crate::{bytes, engine_err, finish, ERR_DECODE, ERR_ENGINE, ERR_WORKFLOW};

/// How many unused ephemeral keys one page may hold at once. A signing ceremony needs one; the
/// cap only stops a buggy page from accumulating keys.
const MAX_KEYS: usize = 8;

thread_local! {
    /// Ephemeral keys by opaque handle. Boxed so the scalar stays at one heap address while the
    /// map grows (a move would leave an un-wiped copy behind).
    static KEYS: RefCell<HashMap<String, Box<KeyPair>>> = RefCell::new(HashMap::new());
}

/// The page's clock and entropy source (wasm32 only).
#[cfg(target_arch = "wasm32")]
pub(crate) mod host {
    #[link(wasm_import_module = "signpdf_host")]
    extern "C" {
        #[link_name = "random_fill"]
        fn host_random_fill(ptr: *mut u8, len: usize) -> i32;
        #[link_name = "now_ms"]
        fn host_now_ms() -> f64;
    }

    /// Fill `buf` from the page's `crypto.getRandomValues`.
    pub fn fill(buf: &mut [u8]) -> bool {
        // SAFETY: `buf` is a valid, writable region of this module's memory.
        buf.is_empty() || unsafe { host_random_fill(buf.as_mut_ptr(), buf.len()) } == 0
    }

    /// Seconds since the Unix epoch from the page's `Date.now()`.
    pub fn now_unix() -> i64 {
        // SAFETY: a plain import call with no arguments.
        (unsafe { host_now_ms() } / 1000.0).floor() as i64
    }
}

/// Make the page's clock the engine's clock (idempotent). Prepare and sign read it to check the
/// ID token's lifetime and to date the audit entry; verification never does.
fn use_host_clock() {
    #[cfg(target_arch = "wasm32")]
    signpdf_core::set_wasm_clock(host::now_unix);
}

/// The key argument of prepare/sign. Only a handle: `deny_unknown_fields` turns an `Identity`
/// (which carries `secret_b64`) into a decode error instead of a silently ignored field.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyHandle {
    handle: String,
}

fn parse_json<T: serde::de::DeserializeOwned>(
    json: &[u8],
    label: &str,
) -> Result<T, (i32, String)> {
    serde_json::from_slice(json).map_err(|e| (ERR_DECODE, format!("invalid {label} JSON: {e}")))
}

/// Run `f` with the key behind `handle`; consume (and wipe) it only on success.
fn with_key(
    handle_json: &[u8],
    f: impl FnOnce(&KeyPair) -> Result<Vec<u8>, (i32, String)>,
) -> Result<Vec<u8>, (i32, String)> {
    let KeyHandle { handle } = parse_json(handle_json, "key handle").map_err(|(c, m)| {
        (
            c,
            format!(
                "{m} (the browser signer takes only {{\"handle\": \"…\"}}, never a private key)"
            ),
        )
    })?;
    let key = KEYS
        .with(|k| k.borrow_mut().remove(&handle))
        .ok_or_else(|| {
            (
                ERR_ENGINE,
                "unknown or already-used ephemeral key handle".to_string(),
            )
        })?;
    let result = f(&key);
    if result.is_err() {
        KEYS.with(|k| k.borrow_mut().insert(handle, key));
    }
    // On success `key` drops here and `SigningKey` zeroizes its scalar.
    result
}

/// Room for one more key, or the cap's error.
fn room_for_a_key() -> Result<(), (i32, String)> {
    if KEYS.with(|k| k.borrow().len()) >= MAX_KEYS {
        return Err((
            ERR_ENGINE,
            format!("too many unused ephemeral keys (max {MAX_KEYS}); discard some first"),
        ));
    }
    Ok(())
}

/// Keep `key` under a new handle for `pdf`: the JSON of [`signpdf_new_ephemeral_identity`].
fn register(key: Box<KeyPair>, pdf: &[u8]) -> Result<Vec<u8>, (i32, String)> {
    let doc_digest = sha256_hex(pdf);
    let nonce = compute_nonce(&key.public_sec1(), &doc_digest);
    let handle = random_id();
    let payload = serde_json::json!({
        "identity": {
            "handle": handle,
            "public_b64": key.public_b64(),
            "fingerprint": key.fingerprint(),
        },
        "nonce": nonce,
        "doc_digest": doc_digest,
    });
    KEYS.with(|k| k.borrow_mut().insert(handle, key));
    serde_json::to_vec(&payload).map_err(|e| (ERR_ENGINE, e.to_string()))
}

/// Mint an ephemeral signing key bound to one document. Result: UTF-8 JSON
/// `{"identity": {"handle", "public_b64", "fingerprint"}, "nonce", "doc_digest"}`; send `nonce`
/// in the identity provider's authorization request.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_new_ephemeral_identity(pdf_ptr: *const u8, pdf_len: usize) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    finish((|| {
        room_for_a_key()?;
        register(Box::new(KeyPair::generate()), pdf)
    })())
}

/// Let the key behind `{"handle": "…"}` out of the module, **for a sign-in that leaves the page**
/// (a top-level redirect to the identity provider, when the browser blocks the sign-in window,
/// and on phones): the redirect unloads the page and this module's memory with it. Result: the
/// key's private scalar (base64, UTF-8). The handle is consumed, so the key is in the module
/// or outside it, never both.
///
/// Only the signing page's engine worker script calls this (`sealEphemeral`): it
/// seals the scalar at once with AES-GCM under a **non-extractable** `CryptoKey` that the page
/// keeps in IndexedDB, wipes its copy, and gives the page only the sealed bytes. After the
/// redirect, [`signpdf_import_ephemeral`] takes the key back in a new module. See "Keys across a
/// redirect" in the module documentation.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_export_ephemeral(key_ptr: *const u8, key_len: usize) -> i32 {
    let key = bytes(key_ptr, key_len);
    finish(with_key(key, |kp| Ok(kp.secret_b64().into_bytes())))
}

/// Take back a key that [`signpdf_export_ephemeral`] let out, for one document: the PDF and the
/// scalar (base64, UTF-8). Result: the JSON of [`signpdf_new_ephemeral_identity`] with a new
/// handle. Its `nonce` equals the one sent to the identity provider exactly when the key and the
/// document are the ones that nonce was made for, so the page compares the two before it signs
/// (and the engine checks the ID token's nonce against the key and the document when it signs).
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_import_ephemeral(
    pdf_ptr: *const u8,
    pdf_len: usize,
    secret_ptr: *const u8,
    secret_len: usize,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    let secret = bytes(secret_ptr, secret_len);
    finish((|| {
        room_for_a_key()?;
        let secret = std::str::from_utf8(secret)
            .map_err(|_| (ERR_DECODE, "the key is not base64 text".to_string()))?;
        let key = KeyPair::from_secret_b64(secret)
            .map_err(|e| (ERR_DECODE, format!("not an ephemeral key: {e}")))?;
        register(Box::new(key), pdf)
    })())
}

/// Drop (and wipe) an unused ephemeral key. Always succeeds, whether or not the handle existed.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_discard_ephemeral(
    handle_ptr: *const u8,
    handle_len: usize,
) -> i32 {
    let handle = String::from_utf8_lossy(bytes(handle_ptr, handle_len)).to_string();
    KEYS.with(|k| k.borrow_mut().remove(&handle));
    finish(Ok(Vec::new()))
}

/// Number of ephemeral keys currently held (a page or test can check that none is left over).
#[no_mangle]
pub extern "C" fn signpdf_ephemeral_count() -> i32 {
    KEYS.with(|k| k.borrow().len()) as i32
}

/// Prepare a source PDF: embed the envelope and sign it as the preparer. Inputs: the PDF, a JSON
/// `PrepareRequest` (with the preparer's ID token) and `{"handle": "…"}`. Result: the prepared
/// PDF bytes.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_prepare(
    pdf_ptr: *const u8,
    pdf_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    let request = bytes(request_ptr, request_len);
    let key = bytes(key_ptr, key_len);
    use_host_clock();
    finish((|| {
        let request: PrepareRequest = parse_json(request, "prepare request")?;
        with_key(key, |kp| prepare(pdf, &request, kp).map_err(engine_err))
    })())
}

/// Sign (or decline) a prepared PDF. Inputs: the PDF, a JSON `SignRequest` (with the signer's ID
/// token; the slot is resolved from the identity) and `{"handle": "…"}`. Result: the signed PDF
/// bytes (one new incremental revision). On an envelope whose policy requires signature
/// timestamps, the signature has room for one: add it with [`signpdf_timestamp_request`] and
/// [`signpdf_add_timestamp`].
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_sign(
    pdf_ptr: *const u8,
    pdf_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    let request = bytes(request_ptr, request_len);
    let key = bytes(key_ptr, key_len);
    use_host_clock();
    finish((|| {
        let request: SignRequest = parse_json(request, "sign request")?;
        with_key(key, |kp| sign(pdf, kp, &request).map_err(engine_err))
    })())
}

/// [`signpdf_sign`] with room for a PAdES B-T signature timestamp, which the page adds next with
/// [`signpdf_timestamp_request`] and [`signpdf_add_timestamp`]. Same inputs; the key is consumed
/// here. Result: the signed PDF bytes, already a complete B-B signature. Refused with
/// `ERR_WORKFLOW` before anything is signed (the key is kept) when the envelope takes no
/// signature timestamps.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_sign_for_timestamp(
    pdf_ptr: *const u8,
    pdf_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    let request = bytes(request_ptr, request_len);
    let key = bytes(key_ptr, key_len);
    use_host_clock();
    finish((|| {
        let request: SignRequest = parse_json(request, "sign request")?;
        with_key(key, |kp| {
            sign_for_timestamp(pdf, kp, &request).map_err(engine_err)
        })
    })())
}

/// [`signpdf_sign`], returning only the **increment**: the bytes the signature appends to the PDF.
/// The signed document is the PDF followed by them; a page that uploads only the increment never
/// builds it, and the module never holds a second copy of the document (signing a 50 MB document
/// peaks at about its size in memory instead of twice it). Same inputs, key and errors as
/// [`signpdf_sign`]; on an envelope that requires signature timestamps, add one with
/// [`signpdf_increment_timestamp_request`] and [`signpdf_increment_add_timestamp`].
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_sign_increment(
    pdf_ptr: *const u8,
    pdf_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    let request = bytes(request_ptr, request_len);
    let key = bytes(key_ptr, key_len);
    use_host_clock();
    finish((|| {
        let request: SignRequest = parse_json(request, "sign request")?;
        with_key(key, |kp| {
            sign_increment(pdf, kp, &request).map_err(engine_err)
        })
    })())
}

/// [`signpdf_sign_for_timestamp`], returning only the increment, as [`signpdf_sign_increment`]
/// does. Add the timestamp with [`signpdf_increment_timestamp_request`] and
/// [`signpdf_increment_add_timestamp`].
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_sign_for_timestamp_increment(
    pdf_ptr: *const u8,
    pdf_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    let request = bytes(request_ptr, request_len);
    let key = bytes(key_ptr, key_len);
    use_host_clock();
    finish((|| {
        let request: SignRequest = parse_json(request, "sign request")?;
        with_key(key, |kp| {
            sign_for_timestamp_increment(pdf, kp, &request).map_err(engine_err)
        })
    })())
}

/// [`signpdf_timestamp_request`] for a document held apart: `head`, the PDF that was signed, and
/// `increment`, what [`signpdf_sign_for_timestamp_increment`] returned. Neither is copied into a
/// whole document. Same result (a DER `TimeStampReq`) and refusals.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_increment_timestamp_request(
    head_ptr: *const u8,
    head_len: usize,
    increment_ptr: *const u8,
    increment_len: usize,
) -> i32 {
    let head = bytes(head_ptr, head_len);
    let increment = bytes(increment_ptr, increment_len);
    finish(
        increment_signature_timestamp_digest(head, increment)
            .map(|digest| timestamp::build_request(&digest))
            .map_err(engine_err),
    )
}

/// [`signpdf_add_timestamp`] for a document held apart, as
/// [`signpdf_increment_timestamp_request`]: embeds the TSA's answer and returns the new
/// **increment**, the same length (only the signature's `/Contents` changes).
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_increment_add_timestamp(
    head_ptr: *const u8,
    head_len: usize,
    increment_ptr: *const u8,
    increment_len: usize,
    response_ptr: *const u8,
    response_len: usize,
) -> i32 {
    let head = bytes(head_ptr, head_len);
    let increment = bytes(increment_ptr, increment_len);
    let response = bytes(response_ptr, response_len);
    finish((|| {
        let digest = increment_signature_timestamp_digest(head, increment).map_err(engine_err)?;
        let token = timestamp::parse_response(response, &digest).map_err(engine_err)?;
        embed_increment_signature_timestamp(head, increment, &token.token_der).map_err(engine_err)
    })())
}

/// When the head moved: check that `increment` (the bytes after the revision the page holds, as
/// the service sends them) extends `head` (that revision) into the document the service announced,
/// `expected` (JSON `{"len": <bytes>, "sha256": "<hex>"}`). The head is hashed in place, never
/// copied. Result: the new head as the same JSON. Refused with `ERR_WORKFLOW` when the lengths do
/// not add up, the increment was cut short or the digest differs: fetch the whole document then.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_check_increment(
    head_ptr: *const u8,
    head_len: usize,
    increment_ptr: *const u8,
    increment_len: usize,
    expected_ptr: *const u8,
    expected_len: usize,
) -> i32 {
    let head = bytes(head_ptr, head_len);
    let increment = bytes(increment_ptr, increment_len);
    let expected = bytes(expected_ptr, expected_len);
    finish((|| {
        let expected: Head = parse_json(expected, "expected head")?;
        let new_head = check_increment(head, increment, &expected).map_err(engine_err)?;
        serde_json::to_vec(&new_head).map_err(|e| (ERR_ENGINE, e.to_string()))
    })())
}

/// The RFC 3161 request for a signature timestamp of the PDF's last revision, which must be a
/// signer revision that is valid, covers the whole file and has no timestamp yet. Result: a DER
/// `TimeStampReq` over the SHA-256 of the signature value; POST it to the TSA with
/// `Content-Type: application/timestamp-query`. Refused with `ERR_WORKFLOW` when the envelope's
/// policy is `signature_timestamps = none`.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_timestamp_request(pdf_ptr: *const u8, pdf_len: usize) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    finish(
        signature_timestamp_digest(pdf)
            .map(|digest| timestamp::build_request(&digest))
            .map_err(engine_err),
    )
}

/// Embed the TSA's answer to [`signpdf_timestamp_request`] (the DER `TimeStampResp` body of its
/// HTTP response) as the last signature's signature timestamp. Refused unless the TSA granted a
/// token over that signature value. Result: the PDF bytes, same length, now PAdES B-T.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_add_timestamp(
    pdf_ptr: *const u8,
    pdf_len: usize,
    response_ptr: *const u8,
    response_len: usize,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    let response = bytes(response_ptr, response_len);
    finish((|| {
        let digest = signature_timestamp_digest(pdf).map_err(engine_err)?;
        let token = timestamp::parse_response(response, &digest).map_err(engine_err)?;
        embed_signature_timestamp(pdf, &token.token_der).map_err(engine_err)
    })())
}

/// The embedded envelope (signers, fields, policy, audit log) as JSON, so the page can show who
/// still has to sign.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_read_envelope(pdf_ptr: *const u8, pdf_len: usize) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    finish((|| {
        let env = read_envelope(pdf).map_err(engine_err)?;
        serde_json::to_vec(&env).map_err(|e| (ERR_ENGINE, e.to_string()))
    })())
}

/// Page geometry as JSON (`[{index, media_box, crop_box, rotate, annotations}]`, boxes in PDF
/// user space), the space field rectangles use.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_page_geometry(pdf_ptr: *const u8, pdf_len: usize) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    finish((|| {
        let pages = signpdf_core::pades::page_geometry(pdf).map_err(engine_err)?;
        serde_json::to_vec(&pages).map_err(|e| (ERR_ENGINE, e.to_string()))
    })())
}

/// Combine several documents into the one PDF an envelope of several documents signs, with its
/// index, for a sender whose documents never leave the device. `manifest` is UTF-8 JSON
/// `{"documents": [{"name": "NDA.pdf", "len": <bytes>}, …]}` and `data` the documents' PDFs one
/// after the other, in that order. Result: the length of the index JSON as 4 bytes (big-endian),
/// the index JSON `{"documents": [{"name", "first_page", "page_count", "source_digest"}, …]}`,
/// then the combined PDF; pass the index as the prepare request's `documents`. Refused with
/// `ERR_DECODE`, `ERR_WORKFLOW` or `ERR_TOO_LARGE` (over 50 MB together). Needs about three
/// times the documents' size in memory.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_combine_documents(
    manifest_ptr: *const u8,
    manifest_len: usize,
    data_ptr: *const u8,
    data_len: usize,
) -> i32 {
    let manifest = bytes(manifest_ptr, manifest_len);
    let data = bytes(data_ptr, data_len);
    finish((|| {
        let manifest: wire::Manifest = parse_json(manifest, "manifest")?;
        let docs = wire::split(&manifest, data).map_err(|e| (ERR_DECODE, e))?;
        let combined = combine_documents(&docs).map_err(engine_err)?;
        wire::frame(&combined).map_err(|e| (ERR_ENGINE, e.to_string()))
    })())
}

/// A convenience copy of document `index` (0-based) of an envelope of several: only its pages,
/// with a banner above the first saying it is a copy and that the combined PDF is what was
/// signed. Result: the copy's PDF. Refused with `ERR_WORKFLOW` for an envelope without a
/// documents index or an index out of range.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_extract_document(
    pdf_ptr: *const u8,
    pdf_len: usize,
    index: u32,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    finish(extract_document(pdf, index as usize).map_err(engine_err))
}

/// A typed signature: the glyph outlines of `name` (UTF-8, normalized to NFC by the page:
/// `name.normalize("NFC")`) set in `font` (the bytes of a TrueType or OpenType font file).
/// Result: UTF-8 JSON, the paths to send as the sign request's `typed_signature`: an array of
/// closed outlines, each `[x, y]` (its start, then straight lines) or `[x1, y1, x2, y2, x, y]`
/// (cubic curves), in font units scaled to 100 per em, y pointing down. Refused with
/// `ERR_WORKFLOW` and a message for the signer when the name is empty or too long, uses a script
/// the engine cannot lay out (Arabic, Hebrew, the Indic scripts…), has a character the font does
/// not draw (offer another font, or drawing), or is too detailed; `ERR_DECODE` when `name` is not
/// UTF-8. Needs no key and no clock.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_typed_signature(
    font_ptr: *const u8,
    font_len: usize,
    name_ptr: *const u8,
    name_len: usize,
) -> i32 {
    let font = bytes(font_ptr, font_len);
    let name = bytes(name_ptr, name_len);
    finish((|| {
        let name = std::str::from_utf8(name)
            .map_err(|_| (ERR_DECODE, "the typed name is not UTF-8 text".to_string()))?;
        let paths = typed_signature(font, name).map_err(|e| (ERR_WORKFLOW, e))?;
        serde_json::to_vec(&paths).map_err(|e| (ERR_ENGINE, e.to_string()))
    })())
}

/// Images as one PDF, one page per image (every page of a multi-page TIFF), fitted to the paper
/// (`signpdf_core::intake::images_to_pdf`). `manifest` is UTF-8 JSON `{"paper": "a4" | "letter",
/// "images": [{"len": <bytes>, "margin": <points>}, …]}` and `data` the image files one after
/// the other, in that order: JPEG or TIFF (other formats are decoded by the page and given as
/// JPEG). Result: the length of a JSON summary as 4 bytes (big-endian), the summary
/// `{"pages": [<pages of each image>, …]}`, then the PDF. Refused with `ERR_DECODE` (a manifest
/// that does not add up) or `ERR_WORKFLOW` with a message starting with the intake code
/// (`not_an_image`, `unsupported_image`, `unreadable_image`, `too_many_pages`, `too_many_pixels`).
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_images_to_pdf(
    manifest_ptr: *const u8,
    manifest_len: usize,
    data_ptr: *const u8,
    data_len: usize,
) -> i32 {
    let manifest = bytes(manifest_ptr, manifest_len);
    let data = bytes(data_ptr, data_len);
    finish((|| {
        let manifest: intake::wire::Manifest = parse_json(manifest, "manifest")?;
        let images = intake::wire::split(&manifest, data).map_err(|e| (ERR_DECODE, e))?;
        let made = intake::images_to_pdf(&images, manifest.paper)
            .map_err(|e| (ERR_WORKFLOW, e.to_string()))?;
        Ok(intake::wire::frame(&made))
    })())
}

/// What a chosen PDF needs before it can be prepared (`signpdf_core::intake::source_info`).
/// Result: UTF-8 JSON `{"encryption": "none" | "restrictions" | "open_password" | "certificate",
/// "pdfa": "2b" | null, "layers", "hidden_layers", "pages"}`. Refused with `ERR_WORKFLOW`
/// (`unreadable_pdf: …`).
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_source_info(pdf_ptr: *const u8, pdf_len: usize) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    finish((|| {
        let info = intake::source_info(pdf).map_err(|e| (ERR_WORKFLOW, e.to_string()))?;
        serde_json::to_vec(&info).map_err(|e| (ERR_ENGINE, e.to_string()))
    })())
}

/// A PDF with an open password, decrypted with `password` (UTF-8) and saved again without
/// encryption (`signpdf_core::intake::decrypt`). Result: the PDF. Refused with `ERR_WORKFLOW`
/// and a message starting with `wrong_password`, `not_encrypted`, `no_open_password`,
/// `certificate_encryption` or `unreadable_pdf`; `ERR_DECODE` when the password is not UTF-8.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_decrypt(
    pdf_ptr: *const u8,
    pdf_len: usize,
    password_ptr: *const u8,
    password_len: usize,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    let password = bytes(password_ptr, password_len);
    finish((|| {
        let password = std::str::from_utf8(password)
            .map_err(|_| (ERR_DECODE, "the password is not UTF-8 text".to_string()))?;
        intake::decrypt(pdf, password).map_err(|e| (ERR_WORKFLOW, e.to_string()))
    })())
}

/// The SHA-256 of `data` as 64 lowercase hex characters (UTF-8): the digest the service records
/// for an upload and for the images it was made from, so the page hashes documents with the
/// engine rather than its own code.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_sha256(data_ptr: *const u8, data_len: usize) -> i32 {
    let data = bytes(data_ptr, data_len);
    finish(Ok(sha256_hex(data).into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{signpdf_verify, OK};
    use signpdf_core::oidc::testing::shared_es256;
    use signpdf_core::TrustStore;

    const ISSUER: &str = "https://issuer.test";
    const AUDIENCE: &str = "signpdf-wasm-test";

    fn result() -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(crate::signpdf_result_ptr(), crate::signpdf_result_len())
                .to_vec()
        }
    }

    fn json_result() -> serde_json::Value {
        serde_json::from_slice(&result()).unwrap()
    }

    /// What a page gets from the identity provider for `email`, bound to `nonce`.
    fn login(email: &str, nonce: &str) -> (String, String) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let iss = shared_es256();
        let token = iss.mint(serde_json::json!({
            "iss": ISSUER, "sub": format!("u|{email}"), "aud": AUDIENCE,
            "iat": now - 5, "exp": now + 600,
            "email": email, "email_verified": true, "name": email, "nonce": nonce,
        }));
        (token, serde_json::to_string(&iss.jwk()).unwrap())
    }

    /// `signpdf_new_ephemeral_identity` over the ABI: `(handle JSON, nonce)`.
    fn new_key(pdf: &[u8]) -> (Vec<u8>, String) {
        assert_eq!(
            unsafe { signpdf_new_ephemeral_identity(pdf.as_ptr(), pdf.len()) },
            OK
        );
        let v = json_result();
        let handle = serde_json::json!({ "handle": v["identity"]["handle"] });
        (
            serde_json::to_vec(&handle).unwrap(),
            v["nonce"].as_str().unwrap().to_string(),
        )
    }

    fn call3(
        f: unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize) -> i32,
        a: &[u8],
        b: &[u8],
        c: &[u8],
    ) -> i32 {
        unsafe {
            f(
                a.as_ptr(),
                a.len(),
                b.as_ptr(),
                b.len(),
                c.as_ptr(),
                c.len(),
            )
        }
    }

    fn signer(id: &str, email: &str, order: u32) -> serde_json::Value {
        serde_json::json!({
            "id": id, "name": email, "handle": email, "role": "Signer", "order": order,
            "identity_policy": {
                "allowed_issuers": [ISSUER], "required_email": email, "min_level": "L1",
            },
        })
    }

    fn field(id: &str, signer: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id, "field_type": "signature", "page": 0,
            "rect": { "x": 72.0, "y": 100.0, "w": 180.0, "h": 40.0 },
            "assigned_signer": signer, "required": true,
        })
    }

    #[test]
    fn two_signer_flow_over_the_abi_wipes_every_key() {
        let source = signpdf_core::container::make_sample_pdf("WASM signing test");
        let before = signpdf_ephemeral_count();

        let (key, nonce) = new_key(&source);
        let (id_token, idp_jwk) = login("preparer@example.com", &nonce);
        let request = serde_json::json!({
            "title": "WASM NDA",
            "signers": [signer("s1", "alice@example.com", 1), signer("s2", "bob@example.com", 2)],
            "fields": [field("f1", "s1"), field("f2", "s2")],
            "policy": { "signing_order": "sequential", "allowed_signature_types": ["PAdES"] },
            "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
            "allowed_issuers": [ISSUER],
        });
        let request = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            call3(signpdf_prepare, &source, &request, &key),
            OK,
            "{:?}",
            String::from_utf8_lossy(&result())
        );
        let prepared = result();

        // The handle is single-use.
        assert_ne!(call3(signpdf_prepare, &source, &request, &key), OK);

        let mut doc = prepared;
        for email in ["alice@example.com", "bob@example.com"] {
            let (key, nonce) = new_key(&doc);
            let (id_token, idp_jwk) = login(email, &nonce);
            let req = serde_json::to_vec(&serde_json::json!({
                "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
                "allowed_issuers": [ISSUER],
            }))
            .unwrap();
            assert_eq!(
                call3(signpdf_sign, &doc, &req, &key),
                OK,
                "{}",
                String::from_utf8_lossy(&result())
            );
            doc = result();
        }
        assert_eq!(
            signpdf_ephemeral_count(),
            before,
            "a used key was left behind"
        );

        let mut trust = TrustStore::empty();
        trust.add_jwks(ISSUER, &shared_es256().jwks());
        trust.add_audience(ISSUER, AUDIENCE);
        let trust = trust.to_json().unwrap().into_bytes();
        let code = unsafe { signpdf_verify(doc.as_ptr(), doc.len(), trust.as_ptr(), trust.len()) };
        assert_eq!(code, OK);
        let report = json_result();
        assert_eq!(report["valid"], true, "{report:#}");
        assert_eq!(report["complete"], true);
    }

    /// The browser's two-step B-T signature over the ABI, with the engine's test TSA.
    #[test]
    fn two_step_timestamp_over_the_abi() {
        use signpdf_core::timestamp::testing::TestTsa;

        let source = signpdf_core::container::make_sample_pdf("WASM B-T test");
        let (key, nonce) = new_key(&source);
        let (id_token, idp_jwk) = login("preparer@example.com", &nonce);
        let request = serde_json::to_vec(&serde_json::json!({
            "title": "WASM B-T",
            "signers": [signer("s1", "alice@example.com", 1)],
            "fields": [field("f1", "s1")],
            "policy": { "signing_order": "sequential", "allowed_signature_types": ["PAdES"] },
            "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
            "allowed_issuers": [ISSUER],
        }))
        .unwrap();
        assert_eq!(call3(signpdf_prepare, &source, &request, &key), OK);
        let prepared = result();

        let (key, nonce) = new_key(&prepared);
        let handle: serde_json::Value = serde_json::from_slice(&key).unwrap();
        let (id_token, idp_jwk) = login("alice@example.com", &nonce);
        let req = serde_json::to_vec(&serde_json::json!({
            "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
            "allowed_issuers": [ISSUER],
        }))
        .unwrap();
        assert_eq!(
            call3(signpdf_sign_for_timestamp, &prepared, &req, &key),
            OK,
            "{}",
            String::from_utf8_lossy(&result())
        );
        let signed = result();
        let handle = handle["handle"].as_str().unwrap().to_string();
        assert!(
            !KEYS.with(|k| k.borrow().contains_key(&handle)),
            "the first step consumes the key"
        );

        let code = unsafe { signpdf_timestamp_request(signed.as_ptr(), signed.len()) };
        assert_eq!(code, OK);
        let tsa = TestTsa::new();
        let response = tsa.respond(&result()).unwrap();

        // A response for another signature is refused.
        let wrong = tsa
            .respond(&signpdf_core::timestamp::build_request(&[1u8; 32]))
            .unwrap();
        let add = |pdf: &[u8], resp: &[u8]| unsafe {
            signpdf_add_timestamp(pdf.as_ptr(), pdf.len(), resp.as_ptr(), resp.len())
        };
        assert_eq!(add(&signed, &wrong), crate::ERR_TIMESTAMP);
        assert_eq!(add(&signed, b"not a response"), crate::ERR_TIMESTAMP);

        assert_eq!(
            add(&signed, &response),
            OK,
            "{}",
            String::from_utf8_lossy(&result())
        );
        let stamped = result();
        assert_eq!(stamped.len(), signed.len());
        // Only once.
        assert_ne!(add(&stamped, &response), OK);

        let mut trust = TrustStore::empty();
        trust.add_jwks(ISSUER, &shared_es256().jwks());
        trust.add_audience(ISSUER, AUDIENCE);
        trust.add_tsa_anchor(&tsa.cert_der());
        let trust = trust.to_json().unwrap().into_bytes();
        let code =
            unsafe { signpdf_verify(stamped.as_ptr(), stamped.len(), trust.as_ptr(), trust.len()) };
        assert_eq!(code, OK);
        let report = json_result();
        assert_eq!(report["valid"], true, "{report:#}");
        assert_eq!(report["complete"], true);
        assert_eq!(report["signatures"][0]["time_source"], "tsa", "{report:#}");
        assert_eq!(report["signatures"][0]["timestamp"]["trusted"], true);
    }

    /// Prepare a one-signer document over the ABI with `signature_timestamps` = `policy`
    /// (`None` leaves it out).
    fn prepared_with_policy(policy: Option<&str>) -> Vec<u8> {
        let source = signpdf_core::container::make_sample_pdf("WASM timestamp policy");
        let (key, nonce) = new_key(&source);
        let (id_token, idp_jwk) = login("preparer@example.com", &nonce);
        let mut request = serde_json::json!({
            "title": "WASM policy",
            "signers": [signer("s1", "alice@example.com", 1)],
            "fields": [field("f1", "s1")],
            "policy": { "signing_order": "sequential", "allowed_signature_types": ["PAdES"] },
            "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
            "allowed_issuers": [ISSUER],
        });
        if let Some(p) = policy {
            request["policy"]["signature_timestamps"] = serde_json::json!(p);
        }
        let request = serde_json::to_vec(&request).unwrap();
        assert_eq!(call3(signpdf_prepare, &source, &request, &key), OK);
        result()
    }

    /// Alice's key and sign request for `pdf`.
    fn alice(pdf: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (key, nonce) = new_key(pdf);
        let (id_token, idp_jwk) = login("alice@example.com", &nonce);
        let req = serde_json::to_vec(&serde_json::json!({
            "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
            "allowed_issuers": [ISSUER],
        }))
        .unwrap();
        (key, req)
    }

    fn verify_with(
        pdf: &[u8],
        tsa: &signpdf_core::timestamp::testing::TestTsa,
    ) -> serde_json::Value {
        let mut trust = TrustStore::empty();
        trust.add_jwks(ISSUER, &shared_es256().jwks());
        trust.add_audience(ISSUER, AUDIENCE);
        trust.add_tsa_anchor(&tsa.cert_der());
        let trust = trust.to_json().unwrap().into_bytes();
        let code = unsafe { signpdf_verify(pdf.as_ptr(), pdf.len(), trust.as_ptr(), trust.len()) };
        assert_eq!(code, OK);
        json_result()
    }

    #[test]
    fn the_envelope_timestamp_policy_over_the_abi() {
        use signpdf_core::timestamp::testing::TestTsa;
        let tsa = TestTsa::new();
        let request_of = |pdf: &[u8]| unsafe {
            let code = signpdf_timestamp_request(pdf.as_ptr(), pdf.len());
            (code, result())
        };
        let add = |pdf: &[u8], resp: &[u8]| unsafe {
            let code = signpdf_add_timestamp(pdf.as_ptr(), pdf.len(), resp.as_ptr(), resp.len());
            (code, result())
        };

        // `required`: signpdf_sign leaves room, the page adds the timestamp.
        let prepared = prepared_with_policy(Some("required"));
        assert_eq!(
            unsafe { signpdf_read_envelope(prepared.as_ptr(), prepared.len()) },
            OK
        );
        assert_eq!(json_result()["policy"]["signature_timestamps"], "required");
        let (key, req) = alice(&prepared);
        assert_eq!(call3(signpdf_sign, &prepared, &req, &key), OK);
        let signed = result();
        let (code, tsq) = request_of(&signed);
        assert_eq!(code, OK, "{}", String::from_utf8_lossy(&tsq));
        let (code, stamped) = add(&signed, &tsa.respond(&tsq).unwrap());
        assert_eq!(code, OK, "{}", String::from_utf8_lossy(&stamped));
        assert_eq!(stamped.len(), signed.len());
        let report = verify_with(&stamped, &tsa);
        assert_eq!(report["valid"], true, "{report:#}");
        assert_eq!(report["signatures"][0]["time_source"], "tsa");

        // `none`: every timestamp step is refused; the key survives for a plain signature.
        let prepared = prepared_with_policy(Some("none"));
        let (key, req) = alice(&prepared);
        let count = signpdf_ephemeral_count();
        assert_eq!(
            call3(signpdf_sign_for_timestamp, &prepared, &req, &key),
            crate::ERR_WORKFLOW
        );
        assert!(String::from_utf8_lossy(&result()).contains("takes no signature timestamps"));
        assert_eq!(signpdf_ephemeral_count(), count, "the refusal kept the key");
        assert_eq!(call3(signpdf_sign, &prepared, &req, &key), OK);
        let signed = result();
        assert_eq!(request_of(&signed).0, crate::ERR_WORKFLOW);
        let digest = signpdf_core::pades::signature_timestamp_digest(&signed).unwrap();
        let response = tsa
            .respond(&signpdf_core::timestamp::build_request(&digest))
            .unwrap();
        assert_eq!(add(&signed, &response).0, crate::ERR_WORKFLOW);
        let report = verify_with(&signed, &tsa);
        assert_eq!(report["valid"], true, "{report:#}");
        assert_eq!(report["signatures"][0]["time_source"], "device");

        // No policy stated: optional, not written into the envelope.
        let prepared = prepared_with_policy(None);
        assert_eq!(
            unsafe { signpdf_read_envelope(prepared.as_ptr(), prepared.len()) },
            OK
        );
        assert!(json_result()["policy"]
            .get("signature_timestamps")
            .is_none());
        // The preparer's revision is never timestamped.
        assert_eq!(request_of(&prepared).0, crate::ERR_WORKFLOW);
    }

    fn call2(
        f: unsafe extern "C" fn(*const u8, usize, *const u8, usize) -> i32,
        a: &[u8],
        b: &[u8],
    ) -> i32 {
        unsafe { f(a.as_ptr(), a.len(), b.as_ptr(), b.len()) }
    }

    /// A typed signature made over the ABI fills the signer's box and is recorded as typed.
    #[test]
    fn typed_signature_over_the_abi() {
        use signpdf_core::ink::typed::testing::font;

        let font = font();
        assert_eq!(
            call2(signpdf_typed_signature, &font, "Alice Ex".as_bytes()),
            OK
        );
        let paths = json_result();
        assert!(paths.as_array().is_some_and(|p| !p.is_empty()), "{paths}");
        // Refused: no glyph for a digit, a script that needs shaping, not UTF-8, not a font.
        for (font, name, code) in [
            (&font[..], "Alice 2".as_bytes(), ERR_WORKFLOW),
            (&font[..], "بa".as_bytes(), ERR_WORKFLOW),
            (&font[..], &[0xff, 0xfe][..], ERR_DECODE),
            (&b"not a font"[..], "Alice".as_bytes(), ERR_WORKFLOW),
        ] {
            assert_eq!(call2(signpdf_typed_signature, font, name), code);
        }

        let source = signpdf_core::container::make_sample_pdf("WASM typed signature");
        let (key, nonce) = new_key(&source);
        let (id_token, idp_jwk) = login("preparer@example.com", &nonce);
        let request = serde_json::to_vec(&serde_json::json!({
            "title": "WASM typed",
            "signers": [signer("s1", "alice@example.com", 1)],
            "fields": [field("f1", "s1")],
            "policy": { "signing_order": "sequential", "allowed_signature_types": ["PAdES"] },
            "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
            "allowed_issuers": [ISSUER],
        }))
        .unwrap();
        assert_eq!(call3(signpdf_prepare, &source, &request, &key), OK);
        let prepared = result();

        let (key, nonce) = new_key(&prepared);
        let (id_token, idp_jwk) = login("alice@example.com", &nonce);
        let req = serde_json::to_vec(&serde_json::json!({
            "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
            "allowed_issuers": [ISSUER], "typed_signature": paths,
        }))
        .unwrap();
        assert_eq!(
            call3(signpdf_sign, &prepared, &req, &key),
            OK,
            "{}",
            String::from_utf8_lossy(&result())
        );
        let signed = result();

        let mut trust = TrustStore::empty();
        trust.add_jwks(ISSUER, &shared_es256().jwks());
        trust.add_audience(ISSUER, AUDIENCE);
        let trust = trust.to_json().unwrap().into_bytes();
        let code =
            unsafe { signpdf_verify(signed.as_ptr(), signed.len(), trust.as_ptr(), trust.len()) };
        assert_eq!(code, OK);
        let report = json_result();
        assert_eq!(report["valid"], true, "{report:#}");
        assert_eq!(report["signatures"][0]["drawing"], "typed");
        assert_eq!(
            report["envelope"]["signatures"][0]["drawing"]["paths"],
            paths
        );
    }

    /// A signed increment, a B-T increment and a head that moved, over the ABI.
    #[test]
    fn increments_over_the_abi() {
        use signpdf_core::timestamp::testing::TestTsa;
        let tsa = TestTsa::new();

        // Alice signs by increment: the page appends it (or uploads it alone).
        let prepared = prepared_with_policy(None);
        let (key, req) = alice(&prepared);
        assert_eq!(
            call3(signpdf_sign_increment, &prepared, &req, &key),
            OK,
            "{}",
            String::from_utf8_lossy(&result())
        );
        let increment = result();
        assert!(increment.len() < 64 * 1024 && !increment.starts_with(b"%PDF"));
        let signed = signpdf_core::appended(&prepared, &increment);
        assert_eq!(verify_with(&signed, &tsa)["valid"], true);

        // The same with a signature timestamp, all three steps on (head, increment).
        let (key, req) = alice(&prepared);
        assert_eq!(
            call3(signpdf_sign_for_timestamp_increment, &prepared, &req, &key),
            OK
        );
        let increment = result();
        assert_eq!(
            call2(signpdf_increment_timestamp_request, &prepared, &increment),
            OK,
            "{}",
            String::from_utf8_lossy(&result())
        );
        let response = tsa.respond(&result()).unwrap();
        let wrong = tsa
            .respond(&signpdf_core::timestamp::build_request(&[1u8; 32]))
            .unwrap();
        let add =
            |inc: &[u8], resp: &[u8]| call3(signpdf_increment_add_timestamp, &prepared, inc, resp);
        assert_eq!(add(&increment, &wrong), crate::ERR_TIMESTAMP);
        assert_eq!(
            add(&increment, &response),
            OK,
            "{}",
            String::from_utf8_lossy(&result())
        );
        let stamped = result();
        assert_eq!(stamped.len(), increment.len());
        let report = verify_with(&signpdf_core::appended(&prepared, &stamped), &tsa);
        assert_eq!(report["valid"], true, "{report:#}");
        assert_eq!(report["signatures"][0]["time_source"], "tsa");
        // Only once.
        assert_ne!(
            call2(signpdf_increment_timestamp_request, &prepared, &stamped),
            OK
        );

        // `none`: the increment steps are refused like the whole-document ones.
        let none = prepared_with_policy(Some("none"));
        let (key, req) = alice(&none);
        assert_eq!(
            call3(signpdf_sign_for_timestamp_increment, &none, &req, &key),
            crate::ERR_WORKFLOW
        );
        assert_eq!(call3(signpdf_sign_increment, &none, &req, &key), OK);
        let plain = result();
        assert_eq!(
            call2(signpdf_increment_timestamp_request, &none, &plain),
            crate::ERR_WORKFLOW
        );

        // The head moved: the page held `prepared`, the service announces `signed`.
        let announced = serde_json::to_vec(&signpdf_core::Head::of(&signed)).unwrap();
        let tail = &signed[prepared.len()..];
        assert_eq!(
            call3(signpdf_check_increment, &prepared, tail, &announced),
            OK
        );
        assert_eq!(json_result()["len"], signed.len());
        let cut = &tail[..tail.len() - 1];
        assert_eq!(
            call3(signpdf_check_increment, &prepared, cut, &announced),
            crate::ERR_WORKFLOW
        );
        assert!(String::from_utf8_lossy(&result()).contains("fetch the whole document"));
        assert_eq!(
            call3(signpdf_check_increment, &prepared, tail, b"{\"len\": 1}"),
            ERR_DECODE
        );
    }

    #[test]
    fn a_private_key_is_never_accepted() {
        let source = signpdf_core::container::make_sample_pdf("no secrets");
        let identity = signpdf_core::Identity::generate("Mallory", "m@example.com");
        let key = serde_json::to_vec(&identity).unwrap();
        let code = call3(signpdf_sign, &source, b"{}", &key);
        assert_eq!(code, ERR_DECODE);
        assert!(String::from_utf8_lossy(&result()).contains("never a private key"));
    }

    #[test]
    fn a_document_from_a_newer_build_is_never_signed() {
        // Its envelope claims schema version 1000 (see signpdf-core/tests/schema_versions.rs).
        let newer = include_bytes!("../../signpdf-core/tests/corpus/newer/schema-v1000.pdf");
        let expect = |what: &str, code: i32| {
            let msg = String::from_utf8_lossy(&result()).to_string();
            assert_eq!(code, crate::ERR_UNSUPPORTED_VERSION, "{what}: {msg}");
            assert!(msg.contains("reload the page"), "{what}: {msg}");
        };

        let (key, nonce) = new_key(newer);
        let (id_token, idp_jwk) = login("alice@example.com", &nonce);
        let sign_req = serde_json::json!({
            "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
            "allowed_issuers": [ISSUER],
        });
        expect(
            "sign",
            call3(
                signpdf_sign,
                newer,
                &serde_json::to_vec(&sign_req).unwrap(),
                &key,
            ),
        );
        let mut decline = sign_req.clone();
        decline["decline"] = serde_json::json!(true);
        expect(
            "decline",
            call3(
                signpdf_sign,
                newer,
                &serde_json::to_vec(&decline).unwrap(),
                &key,
            ),
        );

        let (key, nonce) = new_key(newer);
        let (id_token, idp_jwk) = login("preparer@example.com", &nonce);
        let prep_req = serde_json::json!({
            "title": "Overwrite a newer document",
            "signers": [signer("s1", "alice@example.com", 1)],
            "fields": [field("f1", "s1")],
            "policy": { "signing_order": "sequential", "allowed_signature_types": ["PAdES"] },
            "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
            "allowed_issuers": [ISSUER],
        });
        expect(
            "prepare",
            call3(
                signpdf_prepare,
                newer,
                &serde_json::to_vec(&prep_req).unwrap(),
                &key,
            ),
        );

        expect("read envelope", unsafe {
            signpdf_read_envelope(newer.as_ptr(), newer.len())
        });
    }

    #[test]
    fn a_failed_sign_keeps_the_key_and_discard_wipes_it() {
        let source = signpdf_core::container::make_sample_pdf("retry");
        let (key, _) = new_key(&source);
        let count = signpdf_ephemeral_count();
        // Not a prepared document: the engine refuses, the key survives for a retry.
        assert_ne!(call3(signpdf_sign, &source, b"{}", &key), OK);
        assert_eq!(signpdf_ephemeral_count(), count);
        let handle: serde_json::Value = serde_json::from_slice(&key).unwrap();
        let h = handle["handle"].as_str().unwrap().as_bytes();
        assert_eq!(
            unsafe { signpdf_discard_ephemeral(h.as_ptr(), h.len()) },
            OK
        );
        assert_eq!(signpdf_ephemeral_count(), count - 1);
    }

    /// A sign-in that leaves the page: the key goes out before the redirect and comes back after
    /// it, for the same document only, and signs with the token made for the first nonce.
    #[test]
    fn a_key_survives_a_redirect_for_its_document_only() {
        let prepared = prepared_with_policy(None);
        assert_eq!(
            unsafe { signpdf_new_ephemeral_identity(prepared.as_ptr(), prepared.len()) },
            OK
        );
        let minted = json_result();
        let nonce = minted["nonce"].as_str().unwrap().to_string();
        let key =
            serde_json::to_vec(&serde_json::json!({ "handle": minted["identity"]["handle"] }))
                .unwrap();
        let count = signpdf_ephemeral_count();

        // Out: the scalar, and the handle is gone.
        assert_eq!(
            unsafe { signpdf_export_ephemeral(key.as_ptr(), key.len()) },
            OK
        );
        let secret = result();
        assert_eq!(signpdf_ephemeral_count(), count - 1);
        assert_ne!(
            unsafe { signpdf_export_ephemeral(key.as_ptr(), key.len()) },
            OK,
            "a handle is let out once"
        );
        assert_ne!(call3(signpdf_sign, &prepared, b"{}", &key), OK);

        // Back for another document: another nonce, so the token made for this one never fits.
        let other = signpdf_core::container::make_sample_pdf("another document");
        let import = |pdf: &[u8], secret: &[u8]| unsafe {
            signpdf_import_ephemeral(pdf.as_ptr(), pdf.len(), secret.as_ptr(), secret.len())
        };
        assert_eq!(import(&other, &secret), OK);
        let wrong = json_result();
        assert_ne!(wrong["nonce"], nonce.as_str());
        let h = wrong["identity"]["handle"].as_str().unwrap().as_bytes();
        unsafe { signpdf_discard_ephemeral(h.as_ptr(), h.len()) };

        // Not a key at all.
        assert_eq!(import(&prepared, b"not a key"), ERR_DECODE);
        assert_eq!(import(&prepared, &[0xff, 0xfe]), ERR_DECODE);

        // Back for its document: the same nonce and public key, and it signs.
        assert_eq!(import(&prepared, &secret), OK);
        let back = json_result();
        assert_eq!(back["nonce"], nonce.as_str());
        assert_eq!(
            back["identity"]["public_b64"],
            minted["identity"]["public_b64"]
        );
        assert_eq!(back["doc_digest"], minted["doc_digest"]);
        let key = serde_json::to_vec(&serde_json::json!({ "handle": back["identity"]["handle"] }))
            .unwrap();
        let (id_token, idp_jwk) = login("alice@example.com", &nonce);
        let req = serde_json::to_vec(&serde_json::json!({
            "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
            "allowed_issuers": [ISSUER],
        }))
        .unwrap();
        assert_eq!(
            call3(signpdf_sign_increment, &prepared, &req, &key),
            OK,
            "{}",
            String::from_utf8_lossy(&result())
        );
        assert!(!result().is_empty());
        assert_eq!(signpdf_ephemeral_count(), count - 1, "signing consumed it");
    }

    /// A sender combines two documents on the device, prepares the combination with its index,
    /// and cuts a convenience copy of the second one.
    #[test]
    fn several_documents_over_the_abi() {
        let a = signpdf_core::container::make_sample_pdf("First document");
        let b = signpdf_core::container::make_sample_pdf("Second document");
        let manifest = serde_json::to_vec(&serde_json::json!({
            "documents": [{"name": "First.pdf", "len": a.len()}, {"name": "Second.pdf", "len": b.len()}],
        }))
        .unwrap();
        let mut data = a.clone();
        data.extend_from_slice(&b);
        assert_eq!(call2(signpdf_combine_documents, &manifest, &data), OK);
        let framed = result();
        let len = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
        let index: serde_json::Value = serde_json::from_slice(&framed[4..4 + len]).unwrap();
        let combined = framed[4 + len..].to_vec();
        assert_eq!(index["documents"][1]["first_page"], 1);

        let (key, nonce) = new_key(&combined);
        let (id_token, idp_jwk) = login("preparer@example.com", &nonce);
        let mut second = field("f2", "s1");
        second["page"] = 1.into();
        let request = serde_json::to_vec(&serde_json::json!({
            "title": "Two documents",
            "signers": [signer("s1", "alice@example.com", 1)],
            "fields": [field("f1", "s1"), second],
            "policy": { "signing_order": "sequential", "allowed_signature_types": ["PAdES"] },
            "id_token": id_token, "idp_jwk": idp_jwk, "audience": AUDIENCE,
            "allowed_issuers": [ISSUER],
            "documents": index["documents"],
        }))
        .unwrap();
        assert_eq!(
            call3(signpdf_prepare, &combined, &request, &key),
            OK,
            "{}",
            String::from_utf8_lossy(&result())
        );
        let prepared = result();
        assert_eq!(
            unsafe { signpdf_read_envelope(prepared.as_ptr(), prepared.len()) },
            OK
        );
        assert_eq!(json_result()["documents"], index["documents"]);

        assert_eq!(
            unsafe { signpdf_extract_document(prepared.as_ptr(), prepared.len(), 1) },
            OK
        );
        let copy = result();
        assert_eq!(signpdf_core::pades::page_geometry(&copy).unwrap().len(), 1);
        assert_eq!(
            unsafe { signpdf_extract_document(prepared.as_ptr(), prepared.len(), 9) },
            crate::ERR_WORKFLOW
        );

        // A manifest that does not add up; documents over 50 MB together.
        assert_eq!(
            call2(signpdf_combine_documents, &manifest, &a),
            crate::ERR_DECODE
        );
        let mut big = b"%PDF-1.7\n".to_vec();
        big.resize(26 * 1024 * 1024, b' ');
        let manifest = serde_json::to_vec(&serde_json::json!({
            "documents": [{"name": "1.pdf", "len": big.len()}, {"name": "2.pdf", "len": big.len()}],
        }))
        .unwrap();
        let mut data = big.clone();
        data.extend_from_slice(&big);
        assert_eq!(
            call2(signpdf_combine_documents, &manifest, &data),
            crate::ERR_TOO_LARGE
        );
    }

    /// Intake over the ABI: a JPEG and a TIFF as one PDF, an open password removed, a hash.
    #[test]
    fn intake_over_the_abi() {
        // A JPEG header (SOF0 2 x 2 RGB) and an uncompressed 1 x 1 grey TIFF.
        let jpeg: Vec<u8> = vec![
            0xFF, 0xD8, 0xFF, 0xC0, 0, 17, 8, 0, 2, 0, 2, 3, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0,
            0xFF, 0xD9,
        ];
        let tags: [(u16, u16, u32); 8] = [
            (256, 3, 1),
            (257, 3, 1),
            (258, 3, 8),
            (259, 3, 1),
            (262, 3, 1),
            (273, 4, 0),
            (277, 3, 1),
            (279, 4, 1),
        ];
        let data_at = 8 + 2 + tags.len() * 12 + 4;
        let mut tiff = b"II*\0\x08\0\0\0".to_vec();
        tiff.extend_from_slice(&(tags.len() as u16).to_le_bytes());
        for (tag, kind, v) in tags {
            let v = if tag == 273 { data_at as u32 } else { v };
            tiff.extend_from_slice(&tag.to_le_bytes());
            tiff.extend_from_slice(&kind.to_le_bytes());
            tiff.extend_from_slice(&1u32.to_le_bytes());
            tiff.extend_from_slice(&v.to_le_bytes());
        }
        tiff.extend_from_slice(&0u32.to_le_bytes());
        tiff.push(0x80);
        let manifest = serde_json::to_vec(&serde_json::json!({
            "paper": "letter",
            "images": [{"len": jpeg.len(), "margin": 18}, {"len": tiff.len(), "margin": 0}],
        }))
        .unwrap();
        let mut data = jpeg.clone();
        data.extend_from_slice(&tiff);
        assert_eq!(
            call2(signpdf_images_to_pdf, &manifest, &data),
            OK,
            "{}",
            String::from_utf8_lossy(&result())
        );
        let framed = result();
        let len = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
        let summary: serde_json::Value = serde_json::from_slice(&framed[4..4 + len]).unwrap();
        assert_eq!(summary["pages"], serde_json::json!([1, 1]));
        let pdf = framed[4 + len..].to_vec();
        assert_eq!(signpdf_core::pades::page_geometry(&pdf).unwrap().len(), 2);

        // A PNG is the page's to decode.
        let manifest = serde_json::to_vec(&serde_json::json!({ "images": [{"len": 8}] })).unwrap();
        assert_eq!(
            call2(signpdf_images_to_pdf, &manifest, b"\x89PNG\r\n\x1a\n"),
            crate::ERR_WORKFLOW
        );
        assert!(String::from_utf8_lossy(&result()).starts_with("not_an_image:"));

        // Source info and decrypt on a plain PDF.
        assert_eq!(unsafe { signpdf_source_info(pdf.as_ptr(), pdf.len()) }, OK);
        assert_eq!(json_result()["encryption"], "none");
        assert_eq!(call2(signpdf_decrypt, &pdf, b"x"), crate::ERR_WORKFLOW);
        assert!(String::from_utf8_lossy(&result()).starts_with("not_encrypted:"));

        assert_eq!(unsafe { signpdf_sha256(b"abc".as_ptr(), 3) }, OK);
        assert_eq!(
            String::from_utf8(result()).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
