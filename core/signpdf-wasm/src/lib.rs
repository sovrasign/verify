//! SignPDF's offline verifier, compiled to WebAssembly for a zero-install browser page
//! (`web/verifier/`). Recipients can verify a signed PDF without installing anything and without
//! uploading it anywhere: the document never leaves the browser.
//!
//! The module exports a tiny C-style ABI (no wasm-bindgen, so no generated JS glue and no extra
//! build tooling): the host allocates input buffers with [`signpdf_alloc`], calls an operation
//! that returns a status code, then reads the result bytes via [`signpdf_result_ptr`] /
//! [`signpdf_result_len`]. Status `0` = success (the result is the payload); anything else = the
//! result is a UTF-8 error message.
//!
//! The default build is **verify-only** and imports nothing: verification needs neither
//! randomness nor a clock (the page passes its time to [`signpdf_verify_at`], for the trust
//! list's algorithm policy). The `signing` feature adds prepare/sign with an ephemeral key kept in
//! WASM memory (see [`signing`]); that build imports `random_fill` and `now_ms` from the page.

use std::cell::RefCell;

use signpdf_core::{
    completion_certificate, verify, verify_at, PublishedJwks, SignPdfError, TrustStore,
};

#[cfg(feature = "signing")]
pub mod signing;

/// Success.
pub const OK: i32 = 0;
/// The engine rejected the input (the result holds a UTF-8 message).
pub const ERR_ENGINE: i32 = 2;
/// A JSON argument could not be parsed (the result holds a UTF-8 message).
pub const ERR_DECODE: i32 = 4;

// Engine errors by category, as in the FFI (`signpdf-ffi`), so a page can explain a refusal in
// the user's language. Used by the signing exports; verification keeps reporting `ERR_ENGINE`.

/// The document's workflow rules refuse the request (wrong signer, out of turn, expired…).
pub const ERR_WORKFLOW: i32 = 10;
/// The document failed verification.
pub const ERR_VERIFICATION: i32 = 11;
/// The identity token was not accepted.
pub const ERR_IDENTITY: i32 = 12;
/// The PDF, or the envelope embedded in it, could not be read or written.
pub const ERR_DOCUMENT: i32 = 13;
/// A signature timestamp could not be obtained or validated.
pub const ERR_TIMESTAMP: i32 = 14;
/// A cryptographic operation failed.
pub const ERR_CRYPTO: i32 = 15;

thread_local! {
    static RESULT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn set_result(bytes: Vec<u8>) {
    RESULT.with(|r| *r.borrow_mut() = bytes);
}

/// An engine error as its category code and message.
#[cfg_attr(not(feature = "signing"), allow(dead_code))]
fn engine_err(e: SignPdfError) -> (i32, String) {
    let code = match &e {
        SignPdfError::Workflow(_) => ERR_WORKFLOW,
        SignPdfError::Verification(_) => ERR_VERIFICATION,
        SignPdfError::Oidc(_) => ERR_IDENTITY,
        SignPdfError::Pades(_)
        | SignPdfError::Container(_)
        | SignPdfError::Encoding(_)
        | SignPdfError::Serde(_) => ERR_DOCUMENT,
        SignPdfError::Timestamp(_) => ERR_TIMESTAMP,
        SignPdfError::Crypto(_) | SignPdfError::Keystore(_) => ERR_CRYPTO,
        // The page must reload: the document was made by a newer engine (PR #22).
        SignPdfError::UnsupportedSchemaVersion { .. } => ERR_UNSUPPORTED_VERSION,
        SignPdfError::TooLarge(_) => ERR_TOO_LARGE,
        SignPdfError::Io(_) => ERR_ENGINE,
    };
    (code, e.to_string())
}

fn finish(outcome: Result<Vec<u8>, (i32, String)>) -> i32 {
    match outcome {
        Ok(bytes) => {
            set_result(bytes);
            OK
        }
        Err((code, msg)) => {
            set_result(msg.into_bytes());
            code
        }
    }
}

/// # Safety
/// `ptr` must point at `len` readable bytes (or `len` must be 0).
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 || ptr.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

fn trust_from(json: &[u8]) -> Result<TrustStore, (i32, String)> {
    if json.is_empty() {
        return Ok(TrustStore::well_known());
    }
    // Through the store's own parser, which upgrades stores saved by older versions.
    TrustStore::from_json_bytes(json).map_err(|e| (ERR_DECODE, format!("invalid trust store: {e}")))
}

/// The document was made by a newer version of SignPDF: its envelope schema version is newer than
/// this module understands, so it was neither verified nor rejected. The page should reload to
/// get the current module. Same code as the FFI's `SIGNPDF_ERR_UNSUPPORTED_VERSION`.
pub const ERR_UNSUPPORTED_VERSION: i32 = 16;

/// The document, or an envelope's documents together, are larger than an envelope may be (50 MB).
/// Nothing was combined or prepared. Same code as the FFI's `SIGNPDF_ERR_TOO_LARGE`.
pub const ERR_TOO_LARGE: i32 = 17;

/// A verification error: [`ERR_UNSUPPORTED_VERSION`] for a document from a newer build, otherwise
/// [`ERR_ENGINE`].
fn verify_err(e: signpdf_core::SignPdfError) -> (i32, String) {
    let code = match &e {
        signpdf_core::SignPdfError::UnsupportedSchemaVersion { .. } => ERR_UNSUPPORTED_VERSION,
        _ => ERR_ENGINE,
    };
    (code, e.to_string())
}

/// Allocate `len` bytes for the host to write an input into. Free with [`signpdf_free`].
#[no_mangle]
pub extern "C" fn signpdf_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// Free a buffer obtained from [`signpdf_alloc`] with the same `len`.
///
/// # Safety
/// `ptr`/`len` must come from one [`signpdf_alloc`] call.
#[no_mangle]
pub unsafe extern "C" fn signpdf_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
    }
}

/// Pointer to the bytes produced by the last operation.
#[no_mangle]
pub extern "C" fn signpdf_result_ptr() -> *const u8 {
    RESULT.with(|r| r.borrow().as_ptr())
}

/// Length of the bytes produced by the last operation.
#[no_mangle]
pub extern "C" fn signpdf_result_len() -> usize {
    RESULT.with(|r| r.borrow().len())
}

/// Engine version.
#[no_mangle]
pub extern "C" fn signpdf_version() -> i32 {
    finish(Ok(env!("CARGO_PKG_VERSION").as_bytes().to_vec()))
}

/// The envelope schema versions this build reads and signs, as JSON `{"oldest": N, "newest": M}`
/// (`signpdf_core::schema::OLDEST_SCHEMA_VERSION` and `SCHEMA_VERSION`). A host can compare them
/// with a document's version before the user starts, instead of after the engine refuses it
/// with [`ERR_UNSUPPORTED_VERSION`] (a cached page module older than the document).
#[no_mangle]
pub extern "C" fn signpdf_schema_versions() -> i32 {
    let versions = serde_json::json!({
        "oldest": signpdf_core::schema::OLDEST_SCHEMA_VERSION,
        "newest": signpdf_core::SCHEMA_VERSION,
    });
    finish(Ok(versions.to_string().into_bytes()))
}

/// The catalogue of stable message codes (`signpdf_core::messages::CODES`), as JSON
/// `[{"code", "severity", "en"}, ...]`: every verification finding's `code` (the report's
/// `findings`), every engine error's and every refused field value's. A page translates by code
/// and falls back to `en`.
#[no_mangle]
pub extern "C" fn signpdf_message_codes() -> i32 {
    finish(Ok(signpdf_core::messages::catalogue_json().into_bytes()))
}

/// Verify a PDF against a JSON trust store (empty = well-known store). Result: the JSON
/// `VerificationReport`.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_verify(
    pdf_ptr: *const u8,
    pdf_len: usize,
    trust_ptr: *const u8,
    trust_len: usize,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    let trust = bytes(trust_ptr, trust_len);
    finish((|| {
        let trust = trust_from(trust)?;
        let report = verify(pdf, &trust).map_err(verify_err)?;
        serde_json::to_vec(&report).map_err(|e| (ERR_ENGINE, e.to_string()))
    })())
}

/// [`signpdf_verify`], judging the algorithm policy's end dates (`not_after`, in the trust list)
/// at the page's time: `now` is the time in seconds since the Unix epoch, as ASCII digits
/// (`String(Math.floor(Date.now() / 1000))`). Without it ([`signpdf_verify`]) the module has no
/// clock, and every end date counts as passed. Result: the JSON `VerificationReport`.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_verify_at(
    pdf_ptr: *const u8,
    pdf_len: usize,
    trust_ptr: *const u8,
    trust_len: usize,
    now_ptr: *const u8,
    now_len: usize,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    let trust = bytes(trust_ptr, trust_len);
    let now = bytes(now_ptr, now_len);
    finish((|| {
        let trust = trust_from(trust)?;
        let now = std::str::from_utf8(now)
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .ok_or_else(|| {
                (
                    ERR_DECODE,
                    "the time must be whole seconds since the Unix epoch".to_string(),
                )
            })?;
        let report = verify_at(pdf, &trust, now).map_err(verify_err)?;
        serde_json::to_vec(&report).map_err(|e| (ERR_ENGINE, e.to_string()))
    })())
}

/// Verify and render a certificate-of-completion PDF. Result: the PDF bytes.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_certificate(
    pdf_ptr: *const u8,
    pdf_len: usize,
    trust_ptr: *const u8,
    trust_len: usize,
) -> i32 {
    let pdf = bytes(pdf_ptr, pdf_len);
    let trust = bytes(trust_ptr, trust_len);
    finish((|| {
        let trust = trust_from(trust)?;
        completion_certificate(pdf, &trust).map_err(verify_err)
    })())
}

/// Check a signer's entry against a field's sealed rules, with the rules the engine applies at
/// signing and the verifier applies afterwards (envelope schema version 8), so a page gives
/// instant feedback that matches them.
///
/// `field` is the field's JSON: a whole field of the envelope, or just its `field_type` with
/// `value_format`, `length`, `number_format` and `check_message` (`signpdf_core::FieldRules`).
/// `value` is the signer's entry, UTF-8 (canonical numbers: the page reads the signer's locale).
///
/// Result (status `0`), JSON: `{"ok": true, "canonical": "...", "display": "..."}` with what the
/// envelope will store and what the page will draw (an SSN masked), or
/// `{"ok": false, "error_code": "invalid_email", "check_message": "..."}` with the stable code
/// of the refusal (`signpdf_core::FormatError::code`, catalogued in [`signpdf_message_codes`])
/// and the field's own message when it has one, which the page shows instead of the standard
/// one. An empty entry is `ok` and stored empty: whether the field must be answered is the
/// page's check. Status [`ERR_DECODE`] for JSON or UTF-8 that cannot be read, `10` for rules the
/// engine would refuse at preparation (an unknown currency, a refused pattern...).
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_check_value(
    field_ptr: *const u8,
    field_len: usize,
    value_ptr: *const u8,
    value_len: usize,
) -> i32 {
    let field = bytes(field_ptr, field_len);
    let value = bytes(value_ptr, value_len);
    finish(check_value(field, value))
}

/// The work of [`signpdf_check_value`].
fn check_value(field: &[u8], value: &[u8]) -> Result<Vec<u8>, (i32, String)> {
    let rules: signpdf_core::FieldRules =
        serde_json::from_slice(field).map_err(|e| (ERR_DECODE, format!("invalid field: {e}")))?;
    let value = std::str::from_utf8(value)
        .map_err(|_| (ERR_DECODE, "the value is not UTF-8".to_string()))?;
    let check = rules
        .check()
        .map_err(|e| (ERR_WORKFLOW, format!("the field {e}")))?;
    let result = match check.check(value) {
        Ok(canonical) => serde_json::json!({
            "ok": true,
            "display": check.display(&canonical),
            "canonical": canonical,
        }),
        Err(e) => {
            let mut refused = serde_json::json!({"ok": false, "error_code": e.code()});
            if let Some(message) = &rules.check_message {
                refused["check_message"] = serde_json::json!(message);
            }
            refused
        }
    };
    Ok(result.to_string().into_bytes())
}

/// Compute formula fields for a page's live display, with the rules the engine applies at signing
/// and the verifier applies afterwards (envelope schema version 8), so the total a signer sees is
/// the one that will be drawn and sealed.
///
/// `fields` is a JSON array of envelope fields (the envelope's `fields`: the values of earlier
/// signers' fields, formula results included, are read from them). `values` is a JSON object of
/// the signer's current entries by field id, as the envelope stores them: canonical numbers, a
/// dropdown's option, `true` or `false` for a checkbox or a radio option; empty for none. They
/// override the fields' own values. Every formula field without a stored value is computed; an
/// input left empty counts as 0.
///
/// Result (status `0`), JSON: `{"ok": true, "values": {"<id>": "1250.00"}, "display": {"<id>":
/// "EUR 1 250,00"}}` with every formula field's value as the envelope stores it and as the page
/// draws it, or `{"ok": false, "field": "<id>", "error_code": "division_by_zero"}` with the
/// formula field that cannot be computed and the stable code (catalogued in
/// [`signpdf_message_codes`]). Status [`ERR_DECODE`] for JSON or UTF-8 that cannot be read.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_compute_formulas(
    fields_ptr: *const u8,
    fields_len: usize,
    values_ptr: *const u8,
    values_len: usize,
) -> i32 {
    let fields = bytes(fields_ptr, fields_len);
    let values = bytes(values_ptr, values_len);
    finish(compute_formulas(fields, values))
}

/// The work of [`signpdf_compute_formulas`].
fn compute_formulas(fields: &[u8], values: &[u8]) -> Result<Vec<u8>, (i32, String)> {
    let fields: Vec<signpdf_core::Field> =
        serde_json::from_slice(fields).map_err(|e| (ERR_DECODE, format!("invalid fields: {e}")))?;
    let given: std::collections::BTreeMap<String, String> = if values.is_empty() {
        Default::default()
    } else {
        serde_json::from_slice(values).map_err(|e| (ERR_DECODE, format!("invalid values: {e}")))?
    };
    let computed = signpdf_core::compute_formula_fields(&fields, &given, |f| f.value.is_none());
    let result = match computed {
        Ok(computed) => {
            let mut values = serde_json::Map::new();
            let mut display = serde_json::Map::new();
            for f in fields
                .iter()
                .filter(|f| f.field_type == signpdf_core::FieldType::Formula)
            {
                let Some(v) = computed.get(&f.id).or(f.value.as_ref()) else {
                    continue;
                };
                let drawn = f.number_format.clone().unwrap_or_default().display(v);
                values.insert(f.id.clone(), serde_json::json!(v));
                display.insert(f.id.clone(), serde_json::json!(drawn));
            }
            serde_json::json!({"ok": true, "values": values, "display": display})
        }
        Err(e) => serde_json::json!({"ok": false, "field": e.field, "error_code": e.code}),
    };
    Ok(result.to_string().into_bytes())
}

/// The well-known trust store as JSON (issuers + bundled TSA anchor, no pinned keys).
#[no_mangle]
pub extern "C" fn signpdf_well_known_trust() -> i32 {
    finish(
        TrustStore::well_known()
            .to_json()
            .map(String::into_bytes)
            .map_err(|e| (ERR_ENGINE, e.to_string())),
    )
}

/// Pin a provider's JWKS (`{"keys": [...]}`) for `issuer` in a trust store. Result: the updated
/// trust store JSON. Lets the page pin keys it fetched itself over TLS. A validity window the
/// issuer publishes next to a key is kept, and only ever narrows a key already pinned.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_trust_add_jwks(
    trust_ptr: *const u8,
    trust_len: usize,
    issuer_ptr: *const u8,
    issuer_len: usize,
    jwks_ptr: *const u8,
    jwks_len: usize,
) -> i32 {
    let trust = bytes(trust_ptr, trust_len);
    let issuer = String::from_utf8_lossy(bytes(issuer_ptr, issuer_len)).to_string();
    let jwks = bytes(jwks_ptr, jwks_len);
    finish((|| {
        let mut store = trust_from(trust)?;
        let jwks: PublishedJwks =
            serde_json::from_slice(jwks).map_err(|e| (ERR_DECODE, format!("invalid JWKS: {e}")))?;
        store
            .add_published_jwks(&issuer, &jwks)
            .map_err(|e| (ERR_DECODE, e.to_string()))?;
        store
            .to_json()
            .map(String::into_bytes)
            .map_err(|e| (ERR_ENGINE, e.to_string()))
    })())
}

/// Merge the trust store `other` into the trust store `base` (`TrustStore::merge`): issuers,
/// keys, audiences and TSA anchors are united, and key windows, distrust and issuer kinds only
/// ever narrow, so `base`'s decisions stand. The page puts the keys it holds itself over the
/// signed trust list it follows. The insecure dev flag is never turned on by merging. Result: the
/// merged trust store JSON.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_trust_merge(
    base_ptr: *const u8,
    base_len: usize,
    other_ptr: *const u8,
    other_len: usize,
) -> i32 {
    let base = bytes(base_ptr, base_len);
    let other = bytes(other_ptr, other_len);
    finish((|| {
        let mut store = trust_from(base)?;
        store.merge(&trust_from(other)?);
        store
            .to_json()
            .map(String::into_bytes)
            .map_err(|e| (ERR_ENGINE, e.to_string()))
    })())
}

/// Take a signed trust list under the key-chain accept rule (`signpdf_core::trust_list`): the
/// input `client` is `{"pins": [public P-256 JWKs, the key in use first], "state": {...}}` (the
/// `state` a previous call returned, or absent), then the list's exact bytes and its detached
/// JWS. Result: `{"outcome": "ok" | "older" | "older_key" | "unknown_key" | ..., "sequence": the
/// held list's or null, "state": {...}}`; keep `state` for the next call.
///
/// # Safety
/// Pointer/length pairs must describe readable memory.
#[no_mangle]
pub unsafe extern "C" fn signpdf_trust_list_consider(
    client_ptr: *const u8,
    client_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    jws_ptr: *const u8,
    jws_len: usize,
) -> i32 {
    use signpdf_core::trust_list::{public_p256, ClientState, TrustListClient};
    let client = bytes(client_ptr, client_len);
    let payload = String::from_utf8_lossy(bytes(payload_ptr, payload_len)).to_string();
    let jws = String::from_utf8_lossy(bytes(jws_ptr, jws_len)).to_string();
    finish((|| {
        let v: serde_json::Value = serde_json::from_slice(client)
            .map_err(|e| (ERR_DECODE, format!("invalid client state: {e}")))?;
        let pins = v["pins"]
            .as_array()
            .map(|a| a.iter().filter_map(public_p256).collect::<Vec<_>>())
            .unwrap_or_default();
        let state: ClientState = match v.get("state") {
            Some(s) if !s.is_null() => serde_json::from_value(s.clone())
                .map_err(|e| (ERR_DECODE, format!("invalid client state: {e}")))?,
            _ => ClientState::default(),
        };
        let mut c = TrustListClient::load(pins, &state);
        let outcome = if payload.is_empty() {
            signpdf_core::trust_list::Outcome::Ok
        } else {
            c.consider(&payload, &jws)
        };
        serde_json::to_vec(&serde_json::json!({
            "outcome": outcome.as_str(),
            "sequence": c.sequence(),
            "state": c.state(),
        }))
        .map_err(|e| (ERR_ENGINE, e.to_string()))
    })())
}

// --- entropy for wasm32-unknown-unknown ---------------------------------------------------
//
// wasm32-unknown-unknown has no OS entropy source, and getrandom's own browser backends
// (`js` / `wasm_js`) go through wasm-bindgen, whose generated glue this module deliberately does
// without. So getrandom 0.4, the only generation in the dependency graph, gets a "custom"
// backend (selected by `--cfg getrandom_backend="custom"` in core/.cargo/config.toml):
//
// * verify-only build: a backend that always fails. Verification never draws randomness, and
//   the module keeps importing nothing from the page.
// * `signing` build: the page's `crypto.getRandomValues` through the `random_fill` import. A
//   missing or failing import is an error, never a fallback to weak randomness.

#[cfg(all(target_arch = "wasm32", not(feature = "signing")))]
mod entropy {
    /// getrandom 0.4 custom backend (selected by `--cfg getrandom_backend="custom"`):
    /// verification never needs randomness.
    #[no_mangle]
    unsafe extern "Rust" fn __getrandom_v03_custom(
        _dest: *mut u8,
        _len: usize,
    ) -> Result<(), getrandom04::Error> {
        Err(getrandom04::Error::UNSUPPORTED)
    }
}

#[cfg(all(target_arch = "wasm32", feature = "signing"))]
mod entropy {
    use crate::signing::host;

    /// The host's `random_fill` reported a failure.
    const HOST_FAILED: u16 = 1;

    /// getrandom 0.4 custom backend (selected by `--cfg getrandom_backend="custom"`): the page's
    /// `crypto.getRandomValues`.
    #[no_mangle]
    unsafe extern "Rust" fn __getrandom_v03_custom(
        dest: *mut u8,
        len: usize,
    ) -> Result<(), getrandom04::Error> {
        // SAFETY: getrandom hands over `len` writable bytes at `dest`.
        let buf = std::slice::from_raw_parts_mut(dest, len);
        if host::fill(buf) {
            Ok(())
        } else {
            Err(getrandom04::Error::new_custom(HOST_FAILED))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result() -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(signpdf_result_ptr(), signpdf_result_len()).to_vec() }
    }

    #[test]
    fn well_known_trust_and_add_jwks_roundtrip() {
        assert_eq!(signpdf_well_known_trust(), OK);
        let trust = result();
        let jwks = br#"{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"k"}]}"#;
        let iss = b"https://idp.test";
        let code = unsafe {
            signpdf_trust_add_jwks(
                trust.as_ptr(),
                trust.len(),
                iss.as_ptr(),
                iss.len(),
                jwks.as_ptr(),
                jwks.len(),
            )
        };
        assert_eq!(code, OK);
        let store: TrustStore = serde_json::from_slice(&result()).unwrap();
        assert_eq!(store.issuers.len(), 4);
    }

    #[test]
    fn merging_keeps_the_keys_of_both_stores_and_the_narrower_window() {
        // A list that still pins a key a provider no longer publishes, with an end, and the page's
        // own store holding the same key without one and a key of its own.
        let list = br#"{"type":"sovrasign-trust-list","schema":2,"sequence":3,"issuers":[{"issuer":"https://idp.test","name":"IdP","audiences":["app"],"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"old","not_after":"2030-01-01T00:00:00Z"}]}],"tsa_anchors":[]}"#;
        let own = br#"{"issuers":[{"issuer":"https://idp.test","name":"IdP","audiences":["app"],"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"old"},{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0","y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps","kid":"new"}]}],"tsa_anchors":[],"allow_insecure_dev_issuer":true}"#;
        let code =
            unsafe { signpdf_trust_merge(list.as_ptr(), list.len(), own.as_ptr(), own.len()) };
        assert_eq!(code, OK, "{}", String::from_utf8_lossy(&result()));
        let merged: serde_json::Value = serde_json::from_slice(&result()).unwrap();
        let keys = merged["issuers"][0]["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2, "{merged}");
        assert_eq!(
            keys[0]["not_after"], "2030-01-01T00:00:00Z",
            "the list's end stands"
        );
        assert_eq!(
            merged["allow_insecure_dev_issuer"], false,
            "never turned on by merging"
        );
        // Garbage is refused, not merged.
        let bad = b"{";
        let code =
            unsafe { signpdf_trust_merge(list.as_ptr(), list.len(), bad.as_ptr(), bad.len()) };
        assert_eq!(code, ERR_DECODE);
    }

    #[test]
    fn a_document_from_a_newer_build_asks_for_a_reload() {
        // Its envelope claims schema version 1000 (see signpdf-core/tests/schema_versions.rs).
        let pdf = include_bytes!("../../signpdf-core/tests/corpus/newer/schema-v1000.pdf");
        for op in [signpdf_verify, signpdf_certificate] {
            let code = unsafe { op(pdf.as_ptr(), pdf.len(), std::ptr::null(), 0) };
            assert_eq!(code, ERR_UNSUPPORTED_VERSION);
            let msg = String::from_utf8(result()).unwrap();
            assert!(msg.contains("reload the page"), "{msg}");
        }
    }

    #[test]
    fn schema_versions_are_reported() {
        assert_eq!(signpdf_schema_versions(), OK);
        let v: serde_json::Value = serde_json::from_slice(&result()).unwrap();
        assert_eq!(v["oldest"], signpdf_core::schema::OLDEST_SCHEMA_VERSION);
        assert_eq!(v["newest"], signpdf_core::SCHEMA_VERSION);
    }

    #[test]
    fn message_codes_are_listed() {
        assert_eq!(signpdf_message_codes(), OK);
        let v: serde_json::Value = serde_json::from_slice(&result()).unwrap();
        assert_eq!(
            v.as_array().unwrap().len(),
            signpdf_core::messages::CODES.len()
        );
    }

    #[test]
    fn verify_at_takes_the_page_time() {
        let pdf = include_bytes!("../../signpdf-core/tests/corpus/newer/schema-v1000.pdf");
        let call = |now: &[u8]| unsafe {
            signpdf_verify_at(
                pdf.as_ptr(),
                pdf.len(),
                std::ptr::null(),
                0,
                now.as_ptr(),
                now.len(),
            )
        };
        assert_eq!(call(b"1893456000"), ERR_UNSUPPORTED_VERSION);
        for bad in [&b""[..], b"soon", b"1.5"] {
            assert_eq!(call(bad), ERR_DECODE);
        }
        let junk = b"not a pdf";
        let now = b"1893456000";
        let code = unsafe {
            signpdf_verify_at(
                junk.as_ptr(),
                junk.len(),
                std::ptr::null(),
                0,
                now.as_ptr(),
                now.len(),
            )
        };
        assert_eq!(code, ERR_ENGINE);
    }

    #[test]
    fn verify_reports_engine_errors_for_non_pdfs() {
        let junk = b"not a pdf";
        let code = unsafe { signpdf_verify(junk.as_ptr(), junk.len(), std::ptr::null(), 0) };
        assert_eq!(code, ERR_ENGINE);
        assert!(!result().is_empty());
    }
}
