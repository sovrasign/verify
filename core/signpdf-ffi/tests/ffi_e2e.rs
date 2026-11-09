//! Exercises the C-ABI boundary the way a non-Rust front-end (Flutter/dart:ffi) would: build a
//! real signed PDF with the engine, then call the exported `extern "C"` functions over raw
//! pointers and parse the JSON they hand back.
//!
//! Identity is federated: the `identity` argument is the host's **ephemeral signing key** (an
//! `Identity`-shaped JSON key carrier), while the verified ID token + JWK travel inside the
//! request JSON. The bundled `oidc::testing::TestIssuer` stands in for a real provider.

use std::ptr;

use signpdf_core::crypto::sha256_hex;
use signpdf_core::oidc::{compute_nonce, testing::shared_es256, IdentityPolicy};
use signpdf_core::timestamp::testing::TestTsa;
use signpdf_core::workflow::{PrepareRequest, SignRequest, SignerSpec};
use signpdf_core::{
    container, prepare, sign, Field, FieldType, Identity, Policy, Rect, SigningOrder,
    TimestampPolicy, TrustStore,
};
use signpdf_ffi::{
    signpdf_add_timestamp, signpdf_buffer_free, signpdf_check_increment, signpdf_combine_documents,
    signpdf_completion_certificate, signpdf_discard_ephemeral, signpdf_extract_document,
    signpdf_increment_add_timestamp, signpdf_increment_after, signpdf_increment_timestamp_request,
    signpdf_message_codes, signpdf_new_ephemeral_identity, signpdf_prepare, signpdf_read_envelope,
    signpdf_sign, signpdf_sign_for_timestamp, signpdf_sign_for_timestamp_increment,
    signpdf_sign_increment, signpdf_timestamp_request, signpdf_trust_well_known,
    signpdf_typed_signature, signpdf_verify, signpdf_verify_with_trust, signpdf_version,
    SignPdfBuffer, SIGNPDF_ERR_DECODE, SIGNPDF_ERR_ENGINE, SIGNPDF_ERR_IDENTITY, SIGNPDF_ERR_INPUT,
    SIGNPDF_ERR_PANIC, SIGNPDF_ERR_TIMESTAMP, SIGNPDF_ERR_TOO_LARGE,
    SIGNPDF_ERR_UNSUPPORTED_VERSION, SIGNPDF_ERR_WORKFLOW, SIGNPDF_OK,
};

const ISSUER: &str = "https://issuer.test";
const AUDIENCE: &str = "signpdf-test";

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Mint an ID token for `email` carrying `nonce`, returning `(id_token, idp_jwk_json)`.
fn mint(email: &str, nonce: &str) -> (String, String) {
    let issuer = shared_es256();
    let now = now_unix();
    let claims = serde_json::json!({
        "iss": ISSUER,
        "sub": format!("user|{email}"),
        "aud": AUDIENCE,
        "iat": now - 5,
        "exp": now + 3600,
        "email": email,
        "email_verified": true,
        "name": email,
        "nonce": nonce,
    });
    (
        issuer.mint(claims),
        serde_json::to_string(&issuer.jwk()).unwrap(),
    )
}

fn consumer_policy(email: &str) -> IdentityPolicy {
    IdentityPolicy {
        allowed_issuers: vec![ISSUER.to_string()],
        required_email: Some(email.to_string()),
        ..Default::default()
    }
}

fn sig_field(id: &str, signer: &str) -> Field {
    Field {
        id: id.to_string(),
        field_type: FieldType::Signature,
        page: 0,
        rect: Rect {
            x: 72.0,
            y: 120.0,
            w: 200.0,
            h: 48.0,
        },
        assigned_signer: signer.to_string(),
        required: true,
        value: None,
        label: None,
        group: None,
        options: None,
        date_format: None,
        signing_date: false,
        number_format: None,
        value_format: None,
        length: None,
        check_message: None,
        formula: None,
    }
}

/// The two-signer NDA prepare request, with the preparer token bound to `preparer`'s key and
/// `pdf` (the source document).
fn nda_request(pdf: &[u8], preparer: &Identity) -> PrepareRequest {
    let kp = preparer.key_pair().unwrap();
    let (id_token, idp_jwk) = mint(
        "preparer@example.com",
        &compute_nonce(&kp.public_sec1(), &sha256_hex(pdf)),
    );
    PrepareRequest {
        title: "FFI NDA".to_string(),
        signers: vec![
            SignerSpec {
                id: "s1".into(),
                name: "Alice".into(),
                handle: "alice@example.com".into(),
                role: "Disclosing Party".into(),
                order: 1,
                identity_policy: consumer_policy("alice@example.com"),
            },
            SignerSpec {
                id: "s2".into(),
                name: "Bob".into(),
                handle: "bob@example.com".into(),
                role: "Receiving Party".into(),
                order: 2,
                identity_policy: consumer_policy("bob@example.com"),
            },
        ],
        fields: vec![sig_field("f1", "s1"), sig_field("f2", "s2")],
        policy: Policy {
            signing_order: SigningOrder::Sequential,
            allowed_signature_types: vec!["PAdES".into()],
            expiry: None,
            ..Default::default()
        },
        id_token,
        idp_jwk,
        audience: AUDIENCE.to_string(),
        allowed_issuers: vec![ISSUER.to_string()],
        service_link: None,
        documents: Vec::new(),
        verify_at: None,
    }
}

/// A sign request for `email` using `signer`'s ephemeral key, bound to `pdf`.
fn sign_request(email: &str, signer: &Identity, pdf: &[u8], signer_id: &str) -> SignRequest {
    let kp = signer.key_pair().unwrap();
    let (id_token, idp_jwk) = mint(email, &compute_nonce(&kp.public_sec1(), &sha256_hex(pdf)));
    SignRequest {
        signer_id: signer_id.into(),
        id_token,
        idp_jwk,
        audience: AUDIENCE.to_string(),
        allowed_issuers: vec![ISSUER.to_string()],
        ..Default::default()
    }
}

/// Produce a fully-signed two-signer PDF using the real engine.
fn signed_pdf() -> Vec<u8> {
    let preparer = Identity::generate("Alice (preparer)", "preparer@example.com");
    let alice = Identity::generate("Alice", "alice@example.com");
    let bob = Identity::generate("Bob", "bob@example.com");

    let pdf = container::make_sample_pdf("FFI boundary test document");
    let preparer_key = preparer.key_pair().unwrap();
    let prepared = prepare(&pdf, &nda_request(&pdf, &preparer), &preparer_key).unwrap();

    let alice_key = alice.key_pair().unwrap();
    let after_alice = sign(
        &prepared,
        &alice_key,
        &sign_request("alice@example.com", &alice, &prepared, "s1"),
    )
    .unwrap();

    let bob_key = bob.key_pair().unwrap();
    sign(
        &after_alice,
        &bob_key,
        &sign_request("bob@example.com", &bob, &after_alice, "s2"),
    )
    .unwrap()
}

/// A trust store pinning the shared test issuer's key, as JSON.
fn trust_json() -> Vec<u8> {
    let mut t = TrustStore::empty();
    t.add_jwks(ISSUER, &shared_es256().jwks());
    t.add_audience(ISSUER, AUDIENCE);
    t.to_json().unwrap().into_bytes()
}

/// Verify over the C ABI against the pinned test trust store.
fn verify_trusted(pdf: &[u8]) -> serde_json::Value {
    let trust = trust_json();
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe {
        signpdf_verify_with_trust(
            pdf.as_ptr(),
            pdf.len(),
            trust.as_ptr(),
            trust.len(),
            &mut out,
        )
    };
    assert_eq!(code, SIGNPDF_OK);
    serde_json::from_slice(&take(out)).unwrap()
}

/// Read a returned buffer's bytes out as an owned Vec, then free it.
fn take(buf: SignPdfBuffer) -> Vec<u8> {
    let bytes = if buf.ptr.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(buf.ptr, buf.len).to_vec() }
    };
    unsafe { signpdf_buffer_free(buf) };
    bytes
}

#[test]
fn ffi_version_smoke() {
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe { signpdf_version(&mut out) };
    assert_eq!(code, SIGNPDF_OK);
    let v = String::from_utf8(take(out)).unwrap();
    assert!(!v.is_empty(), "version string should be non-empty");
}

#[test]
fn ffi_message_codes_list_the_catalogue() {
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe { signpdf_message_codes(&mut out) };
    assert_eq!(code, SIGNPDF_OK);
    let codes: serde_json::Value = serde_json::from_slice(&take(out)).unwrap();
    let codes = codes.as_array().unwrap();
    assert_eq!(codes.len(), signpdf_core::messages::CODES.len());
    assert!(codes
        .iter()
        .any(|c| c["code"] == "document_changed" && c["severity"] == "error"));
}

#[test]
fn ffi_verify_reports_valid_over_the_c_abi() {
    let pdf = signed_pdf();
    let report = verify_trusted(&pdf);
    assert_eq!(report["valid"], serde_json::Value::Bool(true), "{report}");
    assert_eq!(report["complete"], serde_json::Value::Bool(true));
    assert_eq!(report["signatures"].as_array().unwrap().len(), 2);
}

#[test]
fn ffi_default_verify_uses_well_known_store_and_does_not_trust_dev_identities() {
    let pdf = signed_pdf();
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe { signpdf_verify(pdf.as_ptr(), pdf.len(), &mut out) };
    assert_eq!(code, SIGNPDF_OK);
    let report: serde_json::Value = serde_json::from_slice(&take(out)).unwrap();
    assert_eq!(report["integrity_ok"], serde_json::Value::Bool(true));
    assert_eq!(report["valid"], serde_json::Value::Bool(false));
}

#[test]
fn ffi_well_known_trust_store_and_certificate() {
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(unsafe { signpdf_trust_well_known(&mut out) }, SIGNPDF_OK);
    let store: TrustStore = serde_json::from_slice(&take(out)).unwrap();
    assert_eq!(store.issuers.len(), 3);
    assert!(!store.tsa_anchors.is_empty());

    let pdf = signed_pdf();
    let trust = trust_json();
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe {
        signpdf_completion_certificate(
            pdf.as_ptr(),
            pdf.len(),
            trust.as_ptr(),
            trust.len(),
            &mut out,
        )
    };
    assert_eq!(code, SIGNPDF_OK);
    let cert = take(out);
    assert!(lopdf::Document::load_mem(&cert).is_ok());
}

#[test]
fn ffi_trust_add_jwks_pins_keys_and_makes_identities_trusted() {
    let issuer = ISSUER.as_bytes();
    let jwks = serde_json::to_vec(&shared_es256().jwks()).unwrap();
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe {
        signpdf_ffi::signpdf_trust_add_jwks(
            ptr::null(),
            0,
            issuer.as_ptr(),
            issuer.len(),
            jwks.as_ptr(),
            jwks.len(),
            &mut out,
        )
    };
    assert_eq!(code, SIGNPDF_OK);
    let trust = take(out);
    let mut store: TrustStore = serde_json::from_slice(&trust).unwrap();
    assert_eq!(store.issuers.len(), 4, "well-known three + the test issuer");
    // Pinned keys trust no application yet; the host names the one it trusts in the store JSON.
    assert!(store.issuers[3].audiences.is_empty());
    store.add_audience(ISSUER, AUDIENCE);
    let trust = store.to_json().unwrap().into_bytes();

    let pdf = signed_pdf();
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe {
        signpdf_verify_with_trust(
            pdf.as_ptr(),
            pdf.len(),
            trust.as_ptr(),
            trust.len(),
            &mut out,
        )
    };
    assert_eq!(code, SIGNPDF_OK);
    let report: serde_json::Value = serde_json::from_slice(&take(out)).unwrap();
    assert_eq!(report["valid"], serde_json::Value::Bool(true));
}

#[test]
fn ffi_garbage_input_never_crashes_the_host() {
    // Truncations of a signed PDF at many offsets must yield an error or an invalid report, never
    // a panic across the C ABI (which would abort the app).
    let pdf = signed_pdf();
    for cut in (0..pdf.len()).step_by(pdf.len() / 40 + 1) {
        let slice = &pdf[..cut];
        let mut out = SignPdfBuffer {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let code = unsafe { signpdf_verify(slice.as_ptr(), slice.len(), &mut out) };
        let body = take(out);
        if code == SIGNPDF_OK {
            let report: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(report["valid"], serde_json::Value::Bool(false));
        }
        // The timestamp steps read the same untrusted bytes.
        let (code, _) = ffi_pdf_call(signpdf_timestamp_request, slice);
        assert_ne!(code, SIGNPDF_ERR_PANIC, "timestamp request at {cut}");
        let (code, _) = ffi_trust_call(signpdf_add_timestamp, slice, &pdf[cut / 2..cut]);
        assert_ne!(code, SIGNPDF_ERR_PANIC, "add timestamp at {cut}");
    }
}

#[test]
fn ffi_verify_detects_tampering_over_the_c_abi() {
    let mut pdf = signed_pdf();
    // Flip a byte inside the signed content.
    pdf[20] ^= 0xFF;
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe { signpdf_verify(pdf.as_ptr(), pdf.len(), &mut out) };
    // The call succeeds (a report was produced) but the report is not valid.
    assert_eq!(code, SIGNPDF_OK);
    let report: serde_json::Value = serde_json::from_slice(&take(out)).unwrap();
    assert_eq!(report["valid"], serde_json::Value::Bool(false));
}

#[test]
fn ffi_read_envelope_exposes_signers() {
    let pdf = signed_pdf();
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe { signpdf_read_envelope(pdf.as_ptr(), pdf.len(), &mut out) };
    assert_eq!(code, SIGNPDF_OK);
    let env: serde_json::Value = serde_json::from_slice(&take(out)).unwrap();
    assert_eq!(env["title"], "FFI NDA");
    assert_eq!(env["signers"].as_array().unwrap().len(), 2);
}

#[test]
fn ffi_null_pointer_is_rejected() {
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    // Non-zero length with a null pointer is an input error.
    let code = unsafe { signpdf_verify(ptr::null(), 16, &mut out) };
    assert_eq!(code, SIGNPDF_ERR_INPUT);
    let msg = String::from_utf8(take(out)).unwrap();
    assert!(
        msg.contains("null"),
        "expected a null-pointer message: {msg}"
    );
}

/// Call `signpdf_prepare`/`signpdf_sign` over the C ABI with JSON arguments and return the
/// `(status, payload)` pair, mirroring exactly what the Dart bindings do.
fn ffi_call(
    f: unsafe extern "C" fn(
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
        *mut SignPdfBuffer,
    ) -> i32,
    pdf: &[u8],
    request_json: &[u8],
    identity_json: &[u8],
) -> (i32, Vec<u8>) {
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe {
        f(
            pdf.as_ptr(),
            pdf.len(),
            request_json.as_ptr(),
            request_json.len(),
            identity_json.as_ptr(),
            identity_json.len(),
            &mut out,
        )
    };
    (code, take(out))
}

#[test]
fn ffi_prepare_sign_verify_full_cycle_over_the_c_abi() {
    // Drive the entire workflow through the JSON C-ABI surface — the exact path the Flutter app
    // takes: serialize the request (with its ID token) + ephemeral key to JSON, hand the bytes
    // across, get PDF bytes back.
    let preparer = Identity::generate("Alice (preparer)", "preparer@example.com");
    let alice = Identity::generate("Alice", "alice@example.com");
    let bob = Identity::generate("Bob", "bob@example.com");

    // Prepare.
    let pdf = container::make_sample_pdf("FFI prepare/sign cycle");
    let req_json = serde_json::to_vec(&nda_request(&pdf, &preparer)).unwrap();
    let preparer_json = serde_json::to_vec(&preparer).unwrap();
    let (code, prepared) = ffi_call(signpdf_prepare, &pdf, &req_json, &preparer_json);
    assert_eq!(code, SIGNPDF_OK, "prepare should succeed");
    assert!(prepared.starts_with(b"%PDF"), "prepared payload is a PDF");

    // Sign as Alice (auto-resolves to s1).
    let s1_json =
        serde_json::to_vec(&sign_request("alice@example.com", &alice, &prepared, "s1")).unwrap();
    let alice_json = serde_json::to_vec(&alice).unwrap();
    let (code, after_alice) = ffi_call(signpdf_sign, &prepared, &s1_json, &alice_json);
    assert_eq!(code, SIGNPDF_OK, "alice sign should succeed");

    // Sign as Bob (auto-resolves to s2).
    let s2_json =
        serde_json::to_vec(&sign_request("bob@example.com", &bob, &after_alice, "s2")).unwrap();
    let bob_json = serde_json::to_vec(&bob).unwrap();
    let (code, after_bob) = ffi_call(signpdf_sign, &after_alice, &s2_json, &bob_json);
    assert_eq!(code, SIGNPDF_OK, "bob sign should succeed");

    // Verify the fully-signed result over the C ABI.
    let report = verify_trusted(&after_bob);
    assert_eq!(report["valid"], serde_json::Value::Bool(true));
    assert_eq!(report["complete"], serde_json::Value::Bool(true));
    assert_eq!(report["signatures"].as_array().unwrap().len(), 2);
}

#[test]
fn ffi_prepare_rejects_malformed_request_json() {
    let alice = Identity::generate("Alice", "alice@example.com");
    let alice_json = serde_json::to_vec(&alice).unwrap();
    let pdf = container::make_sample_pdf("bad json");
    let (code, msg) = ffi_call(signpdf_prepare, &pdf, b"{ not json", &alice_json);
    assert_eq!(code, SIGNPDF_ERR_DECODE);
    let msg = String::from_utf8(msg).unwrap();
    assert!(
        msg.contains("prepare request"),
        "expected a decode message naming the bad argument: {msg}"
    );
}

#[test]
fn ffi_sign_wrong_asserted_signer_is_engine_error() {
    // Valid token (resolves to s1), but the asserted signer id is wrong -> engine (not decode)
    // error that names the bad assertion.
    let preparer = Identity::generate("Alice (preparer)", "preparer@example.com");
    let alice = Identity::generate("Alice", "alice@example.com");
    let pdf = container::make_sample_pdf("unknown signer");
    let req_json = serde_json::to_vec(&nda_request(&pdf, &preparer)).unwrap();
    let preparer_json = serde_json::to_vec(&preparer).unwrap();
    let (_, prepared) = ffi_call(signpdf_prepare, &pdf, &req_json, &preparer_json);

    let bogus = serde_json::to_vec(&sign_request(
        "alice@example.com",
        &alice,
        &prepared,
        "does-not-exist",
    ))
    .unwrap();
    let alice_json = serde_json::to_vec(&alice).unwrap();
    let (code, msg) = ffi_call(signpdf_sign, &prepared, &bogus, &alice_json);
    assert_eq!(code, SIGNPDF_ERR_WORKFLOW);
    let msg = String::from_utf8(msg).unwrap();
    assert!(
        msg.contains("does-not-exist"),
        "expected an engine error mentioning the bad signer id: {msg}"
    );
}

#[test]
fn ffi_ephemeral_identity_binds_token_to_one_document() {
    // The federated keyless path the Flutter host takes: mint an ephemeral identity for the exact
    // document, log in carrying its nonce, then sign with that identity over the ABI.
    let preparer = Identity::generate("Alice (preparer)", "preparer@example.com");
    let pdf = container::make_sample_pdf("ephemeral identity binding");
    let req_json = serde_json::to_vec(&nda_request(&pdf, &preparer)).unwrap();
    let preparer_json = serde_json::to_vec(&preparer).unwrap();
    let (code, prepared) = ffi_call(signpdf_prepare, &pdf, &req_json, &preparer_json);
    assert_eq!(code, SIGNPDF_OK);

    // Host asks the engine for an ephemeral identity bound to the prepared document.
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code =
        unsafe { signpdf_new_ephemeral_identity(prepared.as_ptr(), prepared.len(), &mut out) };
    assert_eq!(code, SIGNPDF_OK);
    let v: serde_json::Value = serde_json::from_slice(&take(out)).unwrap();

    // doc_digest is over exactly the bytes we passed; nonce = H(ephemeral_pubkey ‖ doc_digest).
    assert_eq!(v["doc_digest"].as_str().unwrap(), sha256_hex(&prepared));
    // The private key never crosses the boundary: the host only gets a handle + public key.
    assert!(v["identity"].get("secret_b64").is_none());
    let pubkey =
        signpdf_core::crypto::b64_decode_pub(v["identity"]["public_b64"].as_str().unwrap())
            .unwrap();
    let expected_nonce = compute_nonce(&pubkey, v["doc_digest"].as_str().unwrap());
    assert_eq!(v["nonce"].as_str().unwrap(), expected_nonce);
    let handle = v["identity"]["handle"].as_str().unwrap().to_string();
    let identity_json = serde_json::to_vec(&serde_json::json!({ "handle": handle })).unwrap();

    // Log in (mint stands in for the provider) carrying that nonce, then sign with the SAME
    // ephemeral identity — proving the helper's output drives a real signature.
    let (id_token, idp_jwk) = mint("alice@example.com", v["nonce"].as_str().unwrap());
    let req = SignRequest {
        signer_id: "s1".into(),
        id_token: id_token.clone(),
        idp_jwk: idp_jwk.clone(),
        audience: AUDIENCE.to_string(),
        allowed_issuers: vec![ISSUER.to_string()],
        ..Default::default()
    };
    let (code, signed) = ffi_call(
        signpdf_sign,
        &prepared,
        &serde_json::to_vec(&req).unwrap(),
        &identity_json,
    );
    assert_eq!(
        code,
        SIGNPDF_OK,
        "signing with the ephemeral identity should succeed: {}",
        String::from_utf8_lossy(&signed)
    );

    // The handle is single-use: it was consumed by the successful signature.
    let (code, msg) = ffi_call(
        signpdf_sign,
        &prepared,
        &serde_json::to_vec(&req).unwrap(),
        &identity_json,
    );
    assert_eq!(code, SIGNPDF_ERR_ENGINE);
    assert!(String::from_utf8_lossy(&msg).contains("handle"));
}

#[test]
fn ffi_token_bound_to_one_document_cannot_sign_another() {
    let preparer = Identity::generate("Alice (preparer)", "preparer@example.com");
    let preparer_json = serde_json::to_vec(&preparer).unwrap();
    let alice = Identity::generate("Alice", "alice@example.com");
    let alice_json = serde_json::to_vec(&alice).unwrap();

    let pdf = container::make_sample_pdf("doc one");
    let (_, prepared) = ffi_call(
        signpdf_prepare,
        &pdf,
        &serde_json::to_vec(&nda_request(&pdf, &preparer)).unwrap(),
        &preparer_json,
    );
    let req =
        serde_json::to_vec(&sign_request("alice@example.com", &alice, &prepared, "s1")).unwrap();

    let other = container::make_sample_pdf("a different document");
    let (_, other_prepared) = ffi_call(
        signpdf_prepare,
        &other,
        &serde_json::to_vec(&nda_request(&other, &preparer)).unwrap(),
        &preparer_json,
    );
    let (code, _) = ffi_call(signpdf_sign, &other_prepared, &req, &alice_json);
    assert_eq!(
        code, SIGNPDF_ERR_IDENTITY,
        "a token bound to one document must not sign another"
    );
}

#[test]
fn ffi_failed_use_keeps_the_handle_and_discard_removes_it() {
    let preparer = Identity::generate("Alice (preparer)", "preparer@example.com");
    let pdf = container::make_sample_pdf("retry");
    let (_, prepared) = ffi_call(
        signpdf_prepare,
        &pdf,
        &serde_json::to_vec(&nda_request(&pdf, &preparer)).unwrap(),
        &serde_json::to_vec(&preparer).unwrap(),
    );
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    unsafe { signpdf_new_ephemeral_identity(prepared.as_ptr(), prepared.len(), &mut out) };
    let v: serde_json::Value = serde_json::from_slice(&take(out)).unwrap();
    let handle = v["identity"]["handle"].as_str().unwrap().to_string();
    let id_json = serde_json::to_vec(&serde_json::json!({ "handle": handle })).unwrap();
    let (id_token, idp_jwk) = mint("alice@example.com", v["nonce"].as_str().unwrap());
    let mut req = SignRequest {
        signer_id: "wrong-slot".into(),
        id_token,
        idp_jwk,
        audience: AUDIENCE.to_string(),
        allowed_issuers: vec![ISSUER.to_string()],
        ..Default::default()
    };
    // A recoverable error (bad slot assertion) does not burn the handle...
    let (code, _) = ffi_call(
        signpdf_sign,
        &prepared,
        &serde_json::to_vec(&req).unwrap(),
        &id_json,
    );
    assert_eq!(code, SIGNPDF_ERR_WORKFLOW);
    req.signer_id = "s1".into();
    // ...but discarding it does.
    unsafe { signpdf_discard_ephemeral(handle.as_ptr(), handle.len()) };
    let (code, msg) = ffi_call(
        signpdf_sign,
        &prepared,
        &serde_json::to_vec(&req).unwrap(),
        &id_json,
    );
    assert_eq!(code, SIGNPDF_ERR_ENGINE);
    assert!(String::from_utf8_lossy(&msg).contains("handle"));
}

#[test]
fn ffi_page_geometry_reports_pages_in_user_space() {
    let pdf = container::make_sample_pdf("geometry");
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe { signpdf_ffi::signpdf_page_geometry(pdf.as_ptr(), pdf.len(), &mut out) };
    assert_eq!(code, SIGNPDF_OK);
    let pages: serde_json::Value = serde_json::from_slice(&take(out)).unwrap();
    assert_eq!(pages[0]["index"], 0);
    assert_eq!(pages[0]["rotate"], 0);
    assert_eq!(
        pages[0]["crop_box"],
        serde_json::json!([0.0, 0.0, 612.0, 792.0])
    );
}

/// Call `signpdf_typed_signature` with a font and a name.
fn ffi_typed(font: &[u8], name: &[u8]) -> (i32, Vec<u8>) {
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe {
        signpdf_typed_signature(
            font.as_ptr(),
            font.len(),
            name.as_ptr(),
            name.len(),
            &mut out,
        )
    };
    (code, take(out))
}

#[test]
fn ffi_typed_signature_is_filled_and_recorded() {
    use signpdf_core::ink::typed::testing::font;

    let font = font();
    let (code, paths) = ffi_typed(&font, "Alice Example".as_bytes());
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&paths));
    let paths: signpdf_core::InkPaths = serde_json::from_slice(&paths).unwrap();

    let preparer = Identity::generate("Alice (preparer)", "preparer@example.com");
    let alice = Identity::generate("Alice", "alice@example.com");
    let pdf = container::make_sample_pdf("FFI typed signature");
    let prepared = prepare(
        &pdf,
        &nda_request(&pdf, &preparer),
        &preparer.key_pair().unwrap(),
    )
    .unwrap();
    let mut request = sign_request("alice@example.com", &alice, &prepared, "s1");
    request.typed_signature = Some(paths.clone());
    let signed = sign(&prepared, &alice.key_pair().unwrap(), &request).unwrap();
    let report = verify_trusted(&signed);
    assert_eq!(report["integrity_ok"], true, "{report:#}");
    assert_eq!(report["signatures"][0]["drawing"], "typed");
    let recorded: signpdf_core::InkPaths =
        serde_json::from_value(report["envelope"]["signatures"][0]["drawing"]["paths"].clone())
            .unwrap();
    assert_eq!(recorded, paths);

    // What cannot be typed is refused with a reason, never a crash.
    let (code, message) = ffi_typed(&font, "Alice 2".as_bytes());
    assert_eq!(code, SIGNPDF_ERR_WORKFLOW);
    assert!(String::from_utf8_lossy(&message).contains("'2'"));
    assert_eq!(ffi_typed(&font, &[0xff]).0, SIGNPDF_ERR_DECODE);
    assert_eq!(ffi_typed(b"not a font", b"Alice").0, SIGNPDF_ERR_WORKFLOW);
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe { signpdf_typed_signature(ptr::null(), 4, b"Al".as_ptr(), 2, &mut out) };
    take(out);
    assert_eq!(code, SIGNPDF_ERR_INPUT);
}

// --- envelope schema versions ----------------------------------------------------------------

/// A file from the engine's schema-version corpus (`signpdf-core/tests/corpus/`).
fn corpus_file(path: &str) -> Vec<u8> {
    let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../signpdf-core/tests/corpus")
        .join(path);
    std::fs::read(&full).unwrap_or_else(|e| panic!("{}: {e}", full.display()))
}

/// Call a `(pdf, out)` export.
fn ffi_pdf_call(
    f: unsafe extern "C" fn(*const u8, usize, *mut SignPdfBuffer) -> i32,
    pdf: &[u8],
) -> (i32, Vec<u8>) {
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe { f(pdf.as_ptr(), pdf.len(), &mut out) };
    (code, take(out))
}

/// Call a `(pdf, trust, out)` export.
fn ffi_trust_call(
    f: unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut SignPdfBuffer) -> i32,
    pdf: &[u8],
    trust: &[u8],
) -> (i32, Vec<u8>) {
    let mut out = SignPdfBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe {
        f(
            pdf.as_ptr(),
            pdf.len(),
            trust.as_ptr(),
            trust.len(),
            &mut out,
        )
    };
    (code, take(out))
}

#[test]
fn ffi_a_document_from_a_newer_build_is_refused_with_its_own_code() {
    // Its envelope claims schema version 1000. Every operation answers "update the app", never
    // "invalid", and nothing is signed.
    let newer = corpus_file("newer/schema-v1000.pdf");
    let expect = |what: &str, (code, msg): (i32, Vec<u8>)| {
        let msg = String::from_utf8(msg).unwrap();
        assert_eq!(code, SIGNPDF_ERR_UNSUPPORTED_VERSION, "{what}: {msg}");
        assert!(msg.contains("schema version 1000"), "{what}: {msg}");
        assert!(msg.contains("update the app"), "{what}: {msg}");
    };

    expect("verify", ffi_pdf_call(signpdf_verify, &newer));
    expect(
        "verify with trust",
        ffi_trust_call(signpdf_verify_with_trust, &newer, &trust_json()),
    );
    expect(
        "certificate",
        ffi_trust_call(signpdf_completion_certificate, &newer, &trust_json()),
    );
    expect("read envelope", ffi_pdf_call(signpdf_read_envelope, &newer));

    let alice = Identity::generate("Alice", "alice@example.com");
    let alice_json = serde_json::to_vec(&alice).unwrap();
    let req = sign_request("alice@example.com", &alice, &newer, "");
    expect(
        "sign",
        ffi_call(
            signpdf_sign,
            &newer,
            &serde_json::to_vec(&req).unwrap(),
            &alice_json,
        ),
    );
    let decline = SignRequest {
        decline: true,
        ..req
    };
    expect(
        "decline",
        ffi_call(
            signpdf_sign,
            &newer,
            &serde_json::to_vec(&decline).unwrap(),
            &alice_json,
        ),
    );

    let preparer = Identity::generate("Preparer", "preparer@example.com");
    expect(
        "prepare",
        ffi_call(
            signpdf_prepare,
            &newer,
            &serde_json::to_vec(&nda_request(&newer, &preparer)).unwrap(),
            &serde_json::to_vec(&preparer).unwrap(),
        ),
    );
}

#[test]
fn ffi_verifies_corpus_documents() {
    // Every fixture set of every supported version (`v<N>/<label>/`).
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../signpdf-core/tests/corpus");
    let mut sets = Vec::new();
    for version in std::fs::read_dir(&root).unwrap() {
        let version = version.unwrap().path();
        let name = version.file_name().unwrap().to_string_lossy().to_string();
        if !name.starts_with('v') || !version.is_dir() {
            continue;
        }
        for set in std::fs::read_dir(&version).unwrap() {
            let label = set.unwrap().file_name().to_string_lossy().to_string();
            sets.push(format!("{name}/{label}"));
        }
    }
    assert!(!sets.is_empty(), "no corpus fixture sets");
    for set in sets {
        let trust = corpus_file(&format!("{set}/trust.json"));
        let pdf = corpus_file(&format!("{set}/signed-final.pdf"));
        let (code, out) = ffi_trust_call(signpdf_verify_with_trust, &pdf, &trust);
        assert_eq!(code, SIGNPDF_OK, "{set}: {}", String::from_utf8_lossy(&out));
        let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(report["valid"], true, "{set}: {}", report["messages"]);
        assert_eq!(report["complete"], true, "{set}");
        let version: u64 = set[1..set.find('/').unwrap()].parse().unwrap();
        assert_eq!(report["envelope"]["schema_version"], version, "{set}");
    }
}

// --- signature timestamps ------------------------------------------------------------------

/// The NDA prepared with `policy` as its `signature_timestamps`.
fn prepared_with_timestamps(policy: TimestampPolicy) -> Vec<u8> {
    let preparer = Identity::generate("Alice (preparer)", "preparer@example.com");
    let pdf = container::make_sample_pdf("FFI timestamp policy");
    let mut req = nda_request(&pdf, &preparer);
    req.policy.signature_timestamps = policy;
    prepare(&pdf, &req, &preparer.key_pair().unwrap()).unwrap()
}

/// An ephemeral key for `pdf` over the ABI, and Alice's sign request bound to it.
fn alice_with_ephemeral_key(pdf: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (code, out) = ffi_pdf_call(signpdf_new_ephemeral_identity, pdf);
    assert_eq!(code, SIGNPDF_OK);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let (id_token, idp_jwk) = mint("alice@example.com", v["nonce"].as_str().unwrap());
    let req = SignRequest {
        id_token,
        idp_jwk,
        audience: AUDIENCE.to_string(),
        allowed_issuers: vec![ISSUER.to_string()],
        ..Default::default()
    };
    (
        serde_json::to_vec(&req).unwrap(),
        serde_json::to_vec(&serde_json::json!({ "handle": v["identity"]["handle"] })).unwrap(),
    )
}

/// The host's TSA round trip: `signpdf_timestamp_request`, the test TSA, `signpdf_add_timestamp`.
fn timestamp_over_the_abi(pdf: &[u8], tsa: &TestTsa) -> (i32, Vec<u8>) {
    let (code, request) = ffi_pdf_call(signpdf_timestamp_request, pdf);
    if code != SIGNPDF_OK {
        return (code, request);
    }
    let response = tsa.respond(&request).unwrap();
    ffi_trust_call(signpdf_add_timestamp, pdf, &response)
}

fn trust_with_tsa(tsa: &TestTsa) -> Vec<u8> {
    let mut t = TrustStore::empty();
    t.add_jwks(ISSUER, &shared_es256().jwks());
    t.add_audience(ISSUER, AUDIENCE);
    t.add_tsa_anchor(&tsa.cert_der());
    t.to_json().unwrap().into_bytes()
}

fn timestamp_warnings(report: &serde_json::Value) -> Vec<String> {
    report["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w.as_str())
        .filter(|w| w.contains("signature timestamp"))
        .map(String::from)
        .collect()
}

#[test]
fn ffi_required_timestamps_are_added_after_signpdf_sign() {
    let prepared = prepared_with_timestamps(TimestampPolicy::Required);
    let tsa = TestTsa::new();
    let trust = trust_with_tsa(&tsa);

    // signpdf_sign leaves room under `required`; the host's TSA round trip needs no key.
    let (req, key) = alice_with_ephemeral_key(&prepared);
    let (code, signed) = ffi_call(signpdf_sign, &prepared, &req, &key);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&signed));
    let (code, out) = ffi_trust_call(signpdf_verify_with_trust, &signed, &trust);
    assert_eq!(code, SIGNPDF_OK);
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(
        timestamp_warnings(&report).len(),
        1,
        "{}",
        report["warnings"]
    );

    let (code, stamped) = timestamp_over_the_abi(&signed, &tsa);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&stamped));
    assert_eq!(stamped.len(), signed.len());
    let (code, out) = ffi_trust_call(signpdf_verify_with_trust, &stamped, &trust);
    assert_eq!(code, SIGNPDF_OK);
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["valid"], true, "{}", report["messages"]);
    assert_eq!(report["signatures"][0]["time_source"], "tsa");
    assert_eq!(report["signatures"][0]["timestamp"]["trusted"], true);
    assert!(timestamp_warnings(&report).is_empty());

    // Only once, and only a token over this signature value.
    let (code, _) = timestamp_over_the_abi(&stamped, &tsa);
    assert_ne!(code, SIGNPDF_OK);
    let wrong = tsa
        .respond(&signpdf_core::timestamp::build_request(&[3u8; 32]))
        .unwrap();
    let (code, _) = ffi_trust_call(signpdf_add_timestamp, &signed, &wrong);
    assert_eq!(code, SIGNPDF_ERR_TIMESTAMP);
}

#[test]
fn ffi_optional_timestamps_use_signpdf_sign_for_timestamp() {
    let prepared = prepared_with_timestamps(TimestampPolicy::Optional);
    let tsa = TestTsa::new();
    let (req, key) = alice_with_ephemeral_key(&prepared);
    let (code, signed) = ffi_call(signpdf_sign_for_timestamp, &prepared, &req, &key);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&signed));
    let (code, stamped) = timestamp_over_the_abi(&signed, &tsa);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&stamped));
    let (_, out) = ffi_trust_call(signpdf_verify_with_trust, &stamped, &trust_with_tsa(&tsa));
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["valid"], true, "{}", report["messages"]);
    assert_eq!(report["signatures"][0]["time_source"], "tsa");

    // The preparer's revision is never timestamped.
    let (code, msg) = ffi_pdf_call(signpdf_timestamp_request, &prepared);
    assert_eq!(
        code,
        SIGNPDF_ERR_WORKFLOW,
        "{}",
        String::from_utf8_lossy(&msg)
    );
}

#[test]
fn ffi_an_envelope_without_timestamps_is_never_timestamped() {
    let prepared = prepared_with_timestamps(TimestampPolicy::None);
    let tsa = TestTsa::new();
    let (req, key) = alice_with_ephemeral_key(&prepared);

    // Refused before anything is signed: the handle survives for a plain signature.
    let (code, msg) = ffi_call(signpdf_sign_for_timestamp, &prepared, &req, &key);
    assert_eq!(code, SIGNPDF_ERR_WORKFLOW);
    assert!(
        String::from_utf8_lossy(&msg).contains("takes no signature timestamps"),
        "{}",
        String::from_utf8_lossy(&msg)
    );
    let (code, signed) = ffi_call(signpdf_sign, &prepared, &req, &key);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&signed));

    // No timestamp request is ever made for it, and none is added.
    let (code, _) = ffi_pdf_call(signpdf_timestamp_request, &signed);
    assert_eq!(code, SIGNPDF_ERR_WORKFLOW);
    let digest = signpdf_core::pades::signature_timestamp_digest(&signed).unwrap();
    let response = tsa
        .respond(&signpdf_core::timestamp::build_request(&digest))
        .unwrap();
    let (code, _) = ffi_trust_call(signpdf_add_timestamp, &signed, &response);
    assert_eq!(code, SIGNPDF_ERR_WORKFLOW);

    let report = verify_trusted(&signed);
    assert_eq!(report["valid"], true, "{}", report["messages"]);
    assert_eq!(report["signatures"][0]["time_source"], "device");
    assert_eq!(report["envelope"]["policy"]["signature_timestamps"], "none");
}

#[test]
fn ffi_local_dates_consent_and_service_link_travel_as_json() {
    // What a host writes: a date-signed field drawn day first and a link back to the service in
    // the prepare request; the signer's UTC offset and consent in the sign request.
    let preparer = Identity::generate("Alice (preparer)", "preparer@example.com");
    let pdf = container::make_sample_pdf("FFI local dates");
    let mut prepare_json = serde_json::to_value(nda_request(&pdf, &preparer)).unwrap();
    prepare_json["fields"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": "signed-on", "field_type": "date", "page": 0,
            "rect": {"x": 72.0, "y": 300.0, "w": 200.0, "h": 40.0},
            "assigned_signer": "s1", "required": true,
            "date_format": "DD/MM/YYYY", "signing_date": true,
        }));
    prepare_json["service_link"] = serde_json::json!("https://sign.example.com/e/ffi");
    let (code, prepared) = ffi_call(
        signpdf_prepare,
        &pdf,
        &serde_json::to_vec(&prepare_json).unwrap(),
        &serde_json::to_vec(&preparer).unwrap(),
    );
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&prepared));

    let (req, key) = alice_with_ephemeral_key(&prepared);
    let mut req: serde_json::Value = serde_json::from_slice(&req).unwrap();
    req["utc_offset_minutes"] = serde_json::json!(-330);
    req["esign_consent"] = serde_json::json!({
        "version": "esd-1", "lang": "en", "sha256": "ab".repeat(32),
        "at": "2026-10-01T09:14:03Z",
    });
    let (code, signed) = ffi_call(
        signpdf_sign,
        &prepared,
        &serde_json::to_vec(&req).unwrap(),
        &key,
    );
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&signed));

    let report = verify_trusted(&signed);
    assert_eq!(report["valid"], true, "{}", report["messages"]);
    assert_eq!(report["service_link"], "https://sign.example.com/e/ffi");
    let alice = &report["signatures"][0];
    assert_eq!(alice["utc_offset"], "-05:30");
    let local = alice["local_signed_at"].as_str().unwrap();
    assert!(local.ends_with("-05:30"), "{local}");
    assert_eq!(alice["esign_consent"]["version"], "esd-1");
    let field = report["envelope"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "signed-on")
        .unwrap();
    assert_eq!(field["value"].as_str(), local.get(..10));

    // A value for a date-signed field, or an offset out of range, is a workflow error.
    for (name, value) in [
        ("utc_offset_minutes", serde_json::json!(900)),
        (
            "field_values",
            serde_json::json!([["signed-on", "2026-01-01"]]),
        ),
    ] {
        let (req, key) = alice_with_ephemeral_key(&prepared);
        let mut req: serde_json::Value = serde_json::from_slice(&req).unwrap();
        req[name] = value;
        let (code, msg) = ffi_call(
            signpdf_sign,
            &prepared,
            &serde_json::to_vec(&req).unwrap(),
            &key,
        );
        assert_eq!(
            code,
            SIGNPDF_ERR_WORKFLOW,
            "{}",
            String::from_utf8_lossy(&msg)
        );
        // The refusal keeps the key; the host discards it.
        let handle = key_handle(&key);
        let code = unsafe { signpdf_discard_ephemeral(handle.as_ptr(), handle.len()) };
        assert_eq!(code, SIGNPDF_OK);
    }
}

/// The handle inside a `{"handle": …}` key argument.
fn key_handle(key: &[u8]) -> Vec<u8> {
    let v: serde_json::Value = serde_json::from_slice(key).unwrap();
    v["handle"].as_str().unwrap().as_bytes().to_vec()
}

#[test]
fn ffi_a_trust_store_that_requires_trusted_time_waits_for_the_completion_timestamp() {
    // A host's trust store (JSON) for a provider whose tokens count only with trusted time, as a
    // service's own email-code provider: the envelope without signature timestamps waits for the
    // document timestamp added when it ends, and is then valid, each revision bounded by it.
    let prepared = prepared_with_timestamps(TimestampPolicy::None);
    let (req, key) = alice_with_ephemeral_key(&prepared);
    let (code, signed) = ffi_call(signpdf_sign, &prepared, &req, &key);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&signed));
    let tsa = TestTsa::new();
    let mut store = TrustStore::from_json_bytes(&trust_json()).unwrap();
    store.add_tsa_anchor(&tsa.cert_der());
    let mut trust: serde_json::Value = serde_json::from_str(&store.to_json().unwrap()).unwrap();
    trust["issuers"][0]["requires_trusted_time"] = serde_json::json!(true);
    let trust = trust.to_string().into_bytes();

    let (code, report) = ffi_trust_call(signpdf_verify_with_trust, &signed, &trust);
    assert_eq!(code, SIGNPDF_OK);
    let report: serde_json::Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(report["valid"], false);
    assert_eq!(report["integrity_ok"], true);
    assert_eq!(report["trusted_time_pending"], true);
    assert_eq!(report["signatures"][0]["identity_trust"], "no-trusted-time");
    assert!(report["signatures"][0].get("existed_before").is_none());

    let sealed = signpdf_core::add_document_timestamp(&signed, &tsa).unwrap();
    let (code, report) = ffi_trust_call(signpdf_verify_with_trust, &sealed, &trust);
    assert_eq!(code, SIGNPDF_OK);
    let report: serde_json::Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(report["valid"], true, "{}", report["messages"]);
    assert!(report.get("trusted_time_pending").is_none());
    let alice = &report["signatures"][0];
    assert_eq!(alice["identity_trust"], "trusted");
    assert_eq!(alice["time_source"], "device");
    assert_eq!(alice["existed_before"]["source"], "document");
    assert_eq!(alice["existed_before"]["document_timestamp"], 1);
    assert!(alice["token_issued_at"]
        .as_str()
        .is_some_and(|t| t.ends_with('Z')));

    // A window that ended before the timestamp: outside it.
    let mut windowed: serde_json::Value = serde_json::from_slice(&trust).unwrap();
    windowed["issuers"][0]["keys"][0]["not_after"] = serde_json::json!("2020-01-01T00:00:00Z");
    let windowed = windowed.to_string().into_bytes();
    let (code, report) = ffi_trust_call(signpdf_verify_with_trust, &sealed, &windowed);
    assert_eq!(code, SIGNPDF_OK);
    let report: serde_json::Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(report["valid"], false);
    assert_eq!(
        report["signatures"][0]["identity_trust"],
        "outside-key-window"
    );

    // An unreadable window is refused as input, not judged.
    let mut broken: serde_json::Value = serde_json::from_slice(&trust).unwrap();
    broken["issuers"][0]["keys"][0]["distrusted_after"] = serde_json::json!("soon");
    let broken = broken.to_string().into_bytes();
    let (code, _) = ffi_trust_call(signpdf_verify_with_trust, &sealed, &broken);
    assert_ne!(code, SIGNPDF_OK);
}

#[test]
fn ffi_increments_sign_timestamp_and_travel() {
    let tsa = TestTsa::new();
    let prepared = prepared_with_timestamps(TimestampPolicy::Optional);

    // A plain signature, returned as the increment only.
    let (req, key) = alice_with_ephemeral_key(&prepared);
    let (code, increment) = ffi_call(signpdf_sign_increment, &prepared, &req, &key);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&increment));
    assert!(!increment.starts_with(b"%PDF") && increment.len() < 64 * 1024);
    let signed = signpdf_core::appended(&prepared, &increment);
    assert_eq!(verify_trusted(&signed)["valid"], true);

    // With a signature timestamp: the increment and the document stay apart.
    let (req, key) = alice_with_ephemeral_key(&prepared);
    let (code, increment) = ffi_call(signpdf_sign_for_timestamp_increment, &prepared, &req, &key);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&increment));
    let (code, request) =
        ffi_trust_call(signpdf_increment_timestamp_request, &prepared, &increment);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&request));
    let response = tsa.respond(&request).unwrap();
    let (code, stamped) = ffi_call(
        signpdf_increment_add_timestamp,
        &prepared,
        &increment,
        &response,
    );
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&stamped));
    assert_eq!(stamped.len(), increment.len());
    let full = signpdf_core::appended(&prepared, &stamped);
    let (_, out) = ffi_trust_call(signpdf_verify_with_trust, &full, &trust_with_tsa(&tsa));
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["valid"], true, "{}", report["messages"]);
    assert_eq!(report["signatures"][0]["time_source"], "tsa");

    // The head moved: the holder sends what follows the client's revision, the client checks it.
    let client_head = serde_json::to_vec(&signpdf_core::Head::of(&prepared)).unwrap();
    let (code, tail) = ffi_trust_call(signpdf_increment_after, &signed, &client_head);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&tail));
    assert_eq!(tail, &signed[prepared.len()..]);
    let announced = serde_json::to_vec(&signpdf_core::Head::of(&signed)).unwrap();
    let (code, out) = ffi_call(signpdf_check_increment, &prepared, &tail, &announced);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&out));
    let new_head: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(new_head["len"], signed.len());
    assert_eq!(new_head["sha256"], sha256_hex(&signed));

    // A head the holder does not have, and a transfer cut short.
    let stranger = serde_json::to_vec(&signpdf_core::Head::of(b"%PDF-1.7 not this one")).unwrap();
    let (code, msg) = ffi_trust_call(signpdf_increment_after, &signed, &stranger);
    assert_eq!(
        code,
        SIGNPDF_ERR_WORKFLOW,
        "{}",
        String::from_utf8_lossy(&msg)
    );
    let (code, _) = ffi_call(
        signpdf_check_increment,
        &prepared,
        &tail[..tail.len() - 1],
        &announced,
    );
    assert_eq!(code, SIGNPDF_ERR_WORKFLOW);
    let (code, _) = ffi_trust_call(signpdf_increment_after, &signed, b"not json");
    assert_eq!(code, SIGNPDF_ERR_DECODE);
}

#[test]
fn ffi_documents_are_combined_prepared_and_cut_out() {
    let a = container::make_sample_pdf("First document");
    let b = container::make_sample_pdf("Second document");
    let manifest = serde_json::json!({
        "documents": [{"name": "First.pdf", "len": a.len()}, {"name": "Second.pdf", "len": b.len()}]
    })
    .to_string();
    let mut data = a.clone();
    data.extend_from_slice(&b);
    let (code, framed) = ffi_trust_call(signpdf_combine_documents, manifest.as_bytes(), &data);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&framed));
    let len = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
    let index: serde_json::Value = serde_json::from_slice(&framed[4..4 + len]).unwrap();
    assert_eq!(index["documents"][1]["name"], "Second.pdf");
    assert_eq!(index["documents"][1]["first_page"], 1);
    assert_eq!(index["documents"][0]["source_digest"], sha256_hex(&a));
    let combined = &framed[4 + len..];

    // The index goes into the prepare request's JSON as `documents`.
    let preparer = Identity::generate("Alice (preparer)", "preparer@example.com");
    let mut request = serde_json::to_value(nda_request(combined, &preparer)).unwrap();
    request["documents"] = index["documents"].clone();
    request["fields"][1]["page"] = 1.into();
    let (code, prepared) = ffi_call(
        signpdf_prepare,
        combined,
        request.to_string().as_bytes(),
        serde_json::to_string(&preparer).unwrap().as_bytes(),
    );
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&prepared));
    let (code, env) = ffi_pdf_call(signpdf_read_envelope, &prepared);
    assert_eq!(code, SIGNPDF_OK);
    let env: serde_json::Value = serde_json::from_slice(&env).unwrap();
    assert_eq!(env["schema_version"], signpdf_core::SCHEMA_VERSION);
    assert_eq!(env["documents"], index["documents"]);

    let extract = |pdf: &[u8], i: usize| {
        let mut out = SignPdfBuffer {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let code = unsafe { signpdf_extract_document(pdf.as_ptr(), pdf.len(), i, &mut out) };
        (code, take(out))
    };
    let (code, copy) = extract(&prepared, 1);
    assert_eq!(code, SIGNPDF_OK, "{}", String::from_utf8_lossy(&copy));
    assert_eq!(signpdf_core::pades::page_geometry(&copy).unwrap().len(), 1);
    let (code, _) = extract(&prepared, 2);
    assert_eq!(code, SIGNPDF_ERR_WORKFLOW);
    let (code, _) = extract(b"not a pdf", 0);
    assert_ne!(code, SIGNPDF_OK);

    // A manifest that does not add up, and documents over 50 MB together.
    let (code, msg) = ffi_trust_call(signpdf_combine_documents, manifest.as_bytes(), &a);
    assert_eq!(
        code,
        SIGNPDF_ERR_DECODE,
        "{}",
        String::from_utf8_lossy(&msg)
    );
    let (code, _) = ffi_trust_call(signpdf_combine_documents, b"{}", &data);
    assert_eq!(code, SIGNPDF_ERR_DECODE);
    let mut big = b"%PDF-1.7\n".to_vec();
    big.resize(26 * 1024 * 1024, b' ');
    let manifest = serde_json::json!({
        "documents": [{"name": "Scan 1.pdf", "len": big.len()}, {"name": "Scan 2.pdf", "len": big.len()}]
    })
    .to_string();
    let mut data = big.clone();
    data.extend_from_slice(&big);
    let (code, msg) = ffi_trust_call(signpdf_combine_documents, manifest.as_bytes(), &data);
    assert_eq!(
        code,
        SIGNPDF_ERR_TOO_LARGE,
        "{}",
        String::from_utf8_lossy(&msg)
    );
    assert!(String::from_utf8_lossy(&msg).contains("50 MB"));
}
