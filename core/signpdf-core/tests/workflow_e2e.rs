//! End-to-end workflow tests: the Phase 1 exit criterion lives here.
//!
//! Every signer (and the preparer) authenticates with a federated identity. These tests drive
//! the engine the way the host will: generate an ephemeral signing key, mint an ID token bound
//! to that key and the document via the OIDC `nonce`, and let the engine resolve the matching
//! signer slot. The shared `oidc::testing::TestIssuer` stands in for a real provider, and the
//! verifier's trust store pins exactly its key.

mod common;

use common::*;
use signpdf_core::workflow::SignRequest;
use signpdf_core::{
    container, pades_verify, prepare, sign, verify, FieldType, SignerStatus, SigningOrder,
    TrustStore,
};

#[test]
fn full_two_signer_ordered_flow_verifies() {
    let pdf = container::make_sample_pdf("Mutual NDA between Alice and Bob");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();

    let (alice_key, alice_req) = signer_request("alice@example.com", &prepared, "s1");
    let after_alice = sign(&prepared, &alice_key, &alice_req).unwrap();

    let (bob_key, bob_req) = signer_request("bob@example.com", &after_alice, "s2");
    let after_bob = sign(&after_alice, &bob_key, &bob_req).unwrap();

    let report = verify(&after_bob, &trust()).unwrap();
    assert!(
        report.valid,
        "report should be valid: {:?}",
        report.messages
    );
    assert!(report.integrity_ok && report.identities_trusted);
    assert!(report.complete && !report.declined);
    assert!(report.audit_ok && report.order_ok);
    // The preparer's revision is reported separately; one entry per signer.
    let preparer = report.preparer.as_ref().unwrap();
    assert!(preparer.valid, "{}", preparer.detail);
    assert_eq!(preparer.idp_email, "preparer@example.com");
    assert_eq!(report.signatures.len(), 2);
    assert!(report
        .signatures
        .iter()
        .all(|s| s.valid && s.identity_trust == "trusted"));
    assert_eq!(report.signatures[0].idp_email, "alice@example.com");
    assert_eq!(report.signatures[1].idp_email, "bob@example.com");

    let env = report.envelope.unwrap();
    assert_eq!(env.signatures.len(), 2);
    assert!(env.signers.iter().all(|s| s.status == SignerStatus::Signed));
    assert_eq!(
        env.signer("s1").unwrap().fingerprint.as_deref(),
        Some(alice_key.fingerprint().as_str())
    );
    assert_eq!(
        env.signer("s2").unwrap().fingerprint.as_deref(),
        Some(bob_key.fingerprint().as_str())
    );
}

#[test]
fn prepared_document_is_signed_by_the_preparer() {
    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();
    let sigs = pades_verify(&prepared).unwrap();
    assert_eq!(sigs.len(), 1);
    assert!(sigs[0].is_valid() && sigs[0].covers_to_eof);
    assert_eq!(sigs[0].sub_filter, "ETSI.CAdES.detached");
    let report = verify(&prepared, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert!(!report.complete);
}

#[test]
fn verification_requires_a_trust_anchor() {
    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();
    let (alice_key, alice_req) = signer_request("alice@example.com", &prepared, "s1");
    let signed = sign(&prepared, &alice_key, &alice_req).unwrap();

    // An empty trust store: intact, but no identity is anchored.
    let report = verify(&signed, &TrustStore::empty()).unwrap();
    assert!(report.integrity_ok, "{:?}", report.messages);
    assert!(!report.identities_trusted && !report.valid);
    assert_eq!(report.signatures[0].identity_trust, "unknown-issuer");

    // The explicit insecure dev opt-in accepts it, with a loud warning.
    let report = verify(&signed, &TrustStore::insecure_dev()).unwrap();
    assert!(report.valid);
    assert!(report.warnings.iter().any(|w| w.contains("INSECURE")));
}

/// Critical #1: an attacker mints their own key, claims the trusted issuer, and archives that key
/// next to the forged token. The token verifies against the archived key — but the key is not
/// pinned, so the identity is not trusted.
#[test]
fn identity_forged_with_a_self_made_key_is_not_trusted() {
    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();

    let forger = signpdf_core::oidc::testing::TestIssuer::es256();
    let (key, forged_req) = signer_request_with(&forger, "alice@example.com", &prepared, "s1");
    let signed = sign(&prepared, &key, &forged_req).unwrap();

    let report = verify(&signed, &trust()).unwrap();
    assert!(
        report.integrity_ok,
        "cryptographically consistent: {:?}",
        report.messages
    );
    assert!(!report.valid, "a forged identity must not verify");
    assert_eq!(report.signatures[0].identity_trust, "unknown-key");
}

#[test]
fn signing_without_timestamp_reports_device_time() {
    let pdf = container::make_sample_pdf("No-timestamp NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();

    let (alice_key, alice_req) = signer_request("alice@example.com", &prepared, "s1");
    let signed = sign(&prepared, &alice_key, &alice_req).unwrap();

    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid);
    let alice = &report.signatures[0];
    assert!(alice.timestamp.is_none());
    assert_eq!(alice.time_source, "device");
}

#[test]
fn out_of_order_signing_is_rejected() {
    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();

    let (bob_key, bob_req) = signer_request("bob@example.com", &prepared, "s2");
    let err = sign(&prepared, &bob_key, &bob_req).unwrap_err();
    assert!(err.to_string().contains("out of order"), "{err}");
}

#[test]
fn equal_orders_may_sign_in_any_order() {
    let pdf = container::make_sample_pdf("Board resolution");
    let (preparer_key, req) = prepare_request(
        &pdf,
        vec![
            spec("s1", "Alice", "alice@example.com", 1),
            spec("s2", "Bob", "bob@example.com", 1),
            spec("s3", "Carol", "carol@example.com", 2),
        ],
        vec![],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();

    // Carol (order 2) cannot go before both order-1 signers.
    let (k, r) = signer_request("carol@example.com", &prepared, "");
    assert!(sign(&prepared, &k, &r).is_err());

    let (k, r) = signer_request("bob@example.com", &prepared, "");
    let d1 = sign(&prepared, &k, &r).unwrap();
    let (k, r) = signer_request("alice@example.com", &d1, "");
    let d2 = sign(&d1, &k, &r).unwrap();
    let (k, r) = signer_request("carol@example.com", &d2, "");
    let d3 = sign(&d2, &k, &r).unwrap();

    let report = verify(&d3, &trust()).unwrap();
    assert!(
        report.valid && report.order_ok && report.complete,
        "{:?}",
        report.messages
    );
}

#[test]
fn identity_not_matching_any_slot_is_rejected() {
    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();

    let (mallory_key, mallory_req) = signer_request("mallory@example.com", &prepared, "");
    let err = sign(&prepared, &mallory_key, &mallory_req).unwrap_err();
    assert!(err
        .to_string()
        .contains("does not match any pending signer slot"));
}

#[test]
fn tampering_with_document_bytes_is_detected() {
    let pdf = container::make_sample_pdf("Original contract text");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();

    let (alice_key, alice_req) = signer_request("alice@example.com", &prepared, "s1");
    let mut signed = sign(&prepared, &alice_key, &alice_req).unwrap();

    let needle = b"contract";
    let pos = signed
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("original content text is present");
    signed[pos] ^= 0xFF;

    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid && !report.integrity_ok);
    assert!(
        report.messages.iter().any(|m| m.contains("digest")),
        "{:?}",
        report.messages
    );
}

#[test]
fn declining_is_signed_attributable_and_voids_the_envelope() {
    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();

    let (alice_key, mut alice_req) = signer_request("alice@example.com", &prepared, "s1");
    alice_req.decline = true;
    alice_req.reason = Some("terms unacceptable".into());
    let declined = sign(&prepared, &alice_key, &alice_req).unwrap();

    // The decline is its own PAdES revision.
    assert_eq!(pades_verify(&declined).unwrap().len(), 2);

    let report = verify(&declined, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert!(report.declined && !report.complete);
    let d = &report.signatures[0];
    assert_eq!(d.kind, "declined");
    assert_eq!(
        d.idp_email, "alice@example.com",
        "the decliner's identity is verified"
    );
    assert_eq!(
        report.envelope.unwrap().signer("s1").unwrap().status,
        SignerStatus::Declined
    );

    // Nobody can sign a void envelope.
    let (bob_key, bob_req) = signer_request("bob@example.com", &declined, "s2");
    let err = sign(&declined, &bob_key, &bob_req).unwrap_err();
    assert!(err.to_string().contains("void"), "{err}");
}

#[test]
fn parallel_policy_allows_any_order() {
    let pdf = container::make_sample_pdf("Parallel form");
    let (preparer_key, mut req) = two_signer_request(&pdf);
    req.policy.signing_order = SigningOrder::Parallel;
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();

    let (bob_key, bob_req) = signer_request("bob@example.com", &prepared, "s2");
    let after_bob = sign(&prepared, &bob_key, &bob_req).unwrap();
    let (alice_key, alice_req) = signer_request("alice@example.com", &after_bob, "s1");
    let after_alice = sign(&after_bob, &alice_key, &alice_req).unwrap();

    let report = verify(&after_alice, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert!(report.complete);
}

#[test]
fn field_values_are_drawn_on_the_page_and_dates_autofill() {
    let pdf = container::make_sample_pdf("Order form");
    let (preparer_key, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![
            sig_field("sig", "s1", 0),
            field("price", "s1", FieldType::Text, 0, 300.0),
            field("date", "s1", FieldType::Date, 0, 360.0),
            checkbox("agree", "s1", 420.0, "I agree to the terms"),
        ],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();
    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    r.field_values = vec![
        ("price".into(), "EUR 12,500".into()),
        ("agree".into(), "yes".into()),
    ];
    let signed = sign(&prepared, &k, &r).unwrap();

    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    let env = report.envelope.unwrap();
    let date = env.fields.iter().find(|f| f.id == "date").unwrap();
    assert_eq!(
        date.value.as_deref().map(str::len),
        Some(10),
        "YYYY-MM-DD autofill"
    );

    // The values are visible annotations on the page.
    let doc = lopdf::Document::load_mem(&signed).unwrap();
    let texts: Vec<String> = doc
        .objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .filter(|d| matches!(d.get(b"Subtype"), Ok(lopdf::Object::Name(n)) if n == b"FreeText"))
        .filter_map(|d| match d.get(b"Contents") {
            Ok(lopdf::Object::String(s, _)) => Some(String::from_utf8_lossy(s).to_string()),
            _ => None,
        })
        .collect();
    assert!(texts.contains(&"EUR 12,500".to_string()), "{texts:?}");
    assert!(
        texts.contains(&"[X] I agree to the terms".to_string()),
        "{texts:?}"
    );
    assert_eq!(texts.len(), 3);
}

#[test]
fn required_field_must_be_filled() {
    let pdf = container::make_sample_pdf("Form");
    let (preparer_key, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![field("name", "s1", FieldType::Text, 0, 300.0)],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let err = sign(&prepared, &k, &r).unwrap_err();
    assert!(err.to_string().contains("required field name"));
}

#[test]
fn prepare_validates_the_request() {
    let pdf = container::make_sample_pdf("NDA");
    let base = || two_signer_request(&pdf);

    let (k, mut r) = base();
    r.signers[1].id = "s1".into();
    assert!(prepare(&pdf, &r, &k)
        .unwrap_err()
        .to_string()
        .contains("duplicate signer"));

    let (k, mut r) = base();
    r.signers[0].order = 0;
    assert!(prepare(&pdf, &r, &k)
        .unwrap_err()
        .to_string()
        .contains("1-based"));

    let (k, mut r) = base();
    r.fields[0].page = 7;
    assert!(prepare(&pdf, &r, &k)
        .unwrap_err()
        .to_string()
        .contains("page"));

    let (k, mut r) = base();
    r.fields[1].id = "f1".into();
    assert!(prepare(&pdf, &r, &k)
        .unwrap_err()
        .to_string()
        .contains("duplicate field"));

    let (k, mut r) = base();
    r.policy.expiry = Some("2001-01-01T00:00:00Z".into());
    assert!(prepare(&pdf, &r, &k)
        .unwrap_err()
        .to_string()
        .contains("past"));

    let (k, mut r) = base();
    r.policy.expiry = Some("next tuesday".into());
    assert!(prepare(&pdf, &r, &k)
        .unwrap_err()
        .to_string()
        .contains("RFC 3339"));
}

#[test]
fn future_expiry_allows_signing() {
    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, mut req) = two_signer_request(&pdf);
    req.policy.expiry = Some("2099-01-01T00:00:00Z".into());
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign(&prepared, &k, &r).unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);
}

#[test]
fn completion_certificate_is_a_pdf_naming_the_document_hash() {
    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign(&prepared, &k, &r).unwrap();

    let cert = signpdf_core::completion_certificate(&signed, &trust()).unwrap();
    assert!(lopdf::Document::load_mem(&cert).is_ok());
    let hash = signpdf_core::crypto::sha256_hex(&signed);
    assert!(
        cert.windows(hash.len()).any(|w| w == hash.as_bytes()),
        "certificate names the signed PDF's SHA-256"
    );
    let says_so = b"A summary, not proof";
    assert!(
        cert.windows(says_so.len()).any(|w| w == says_so),
        "the certificate says up front that it proves nothing by itself"
    );
}

#[test]
fn sign_request_defaults_deserialize() {
    // Hosts may omit any SignRequest field.
    let r: SignRequest = serde_json::from_str("{}").unwrap();
    assert!(r.signer_id.is_empty() && !r.decline);
}

/// PAdES B-T: a signature timestamp from a TSA the verifier trusts becomes the signing clock.
#[test]
fn trusted_signature_timestamp_is_the_signing_clock() {
    use signpdf_core::sign_with;
    use signpdf_core::timestamp::testing::TestTsa;

    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();
    let tsa = TestTsa::new();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign_with(&prepared, &k, &r, Some(&tsa)).unwrap();

    // Trusted TSA: the timestamp is the clock.
    let mut t = trust();
    t.add_tsa_anchor(&tsa.cert_der());
    let report = verify(&signed, &t).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    let s = &report.signatures[0];
    let ts = s.timestamp.as_ref().expect("B-T timestamp present");
    assert_eq!(ts.kind, "signature");
    assert!(ts.verified && ts.signature_valid && ts.trusted);
    assert_eq!(s.time_source, "tsa");

    // Untrusted TSA: still a valid signature, but the device clock is used.
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid);
    let s = &report.signatures[0];
    assert!(!s.timestamp.as_ref().unwrap().trusted);
    assert_eq!(s.time_source, "device");
}

/// PAdES B-T in two steps, as the browser signer does it (its TSA request is an async `fetch`):
/// sign with room for a timestamp, ask the TSA for the signature value's hash, embed the token.
/// The key is needed only for the first step.
#[test]
fn two_step_signature_timestamp_matches_the_one_step_result() {
    use signpdf_core::timestamp::{build_request, parse_response, testing::TestTsa};
    use signpdf_core::{embed_signature_timestamp, sign_for_timestamp, signature_timestamp_digest};

    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();
    let tsa = TestTsa::new();
    let mut t = trust();
    t.add_tsa_anchor(&tsa.cert_der());

    // Step 1: a complete B-B signature with room for a timestamp.
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign_for_timestamp(&prepared, &k, &r).unwrap();
    let report = verify(&signed, &t).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert!(report.signatures[0].timestamp.is_none());

    // Step 2: the TSA round trip and the embedding, without the key.
    let digest = signature_timestamp_digest(&signed).unwrap();
    let response = tsa.respond(&build_request(&digest)).unwrap();
    let token = parse_response(&response, &digest).unwrap().token_der;
    let stamped = embed_signature_timestamp(&signed, &token).unwrap();
    assert_eq!(
        stamped.len(),
        signed.len(),
        "the timestamp goes in the reserved room"
    );

    let report = verify(&stamped, &t).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    let s = &report.signatures[0];
    let ts = s.timestamp.as_ref().expect("B-T timestamp present");
    assert!(ts.verified && ts.signature_valid && ts.trusted, "{ts:?}");
    assert_eq!(s.time_source, "tsa");

    // Once only, and only a token over this signature value.
    assert!(signature_timestamp_digest(&stamped).is_err());
    assert!(embed_signature_timestamp(&stamped, &token).is_err());
    let other = tsa.respond(&build_request(&[7u8; 32])).unwrap();
    let other = parse_response(&other, &[7u8; 32]).unwrap().token_der;
    assert!(embed_signature_timestamp(&signed, &other).is_err());

    // Nothing may follow the signature being timestamped.
    let (k2, r2) = signer_request("bob@example.com", &stamped, "");
    let done = sign_for_timestamp(&stamped, &k2, &r2).unwrap();
    let mut appended = signed.clone();
    appended.extend_from_slice(b"\n% trailing bytes\n");
    assert!(embed_signature_timestamp(&appended, &token).is_err());

    // The next signer builds on the B-T revision; both timestamps stay valid.
    let digest2 = signature_timestamp_digest(&done).unwrap();
    let token2 = parse_response(&tsa.respond(&build_request(&digest2)).unwrap(), &digest2)
        .unwrap()
        .token_der;
    let done = embed_signature_timestamp(&done, &token2).unwrap();
    let report = verify(&done, &t).unwrap();
    assert!(report.valid && report.complete, "{:?}", report.messages);
    for s in &report.signatures {
        assert_eq!(s.time_source, "tsa");
    }
}

/// A forged (unsigned) timestamp is reported as such and never used as a clock.
#[test]
fn forged_signature_timestamp_is_not_trusted() {
    use signpdf_core::pades::Timestamper;
    use signpdf_core::sign_with;

    struct Forger;
    impl Timestamper for Forger {
        fn timestamp(&self, digest: &[u8; 32]) -> signpdf_core::Result<Vec<u8>> {
            let b64 =
                signpdf_core::timestamp::testing::mint_timestamp(digest, "2026-01-01T00:00:00Z", 9);
            signpdf_core::crypto::b64_decode_pub(&b64)
        }
    }

    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign_with(&prepared, &k, &r, Some(&Forger)).unwrap();
    let report = verify(&signed, &signpdf_core::TrustStore::well_known()).unwrap();
    let s = &report.signatures[0];
    let ts = s.timestamp.as_ref().unwrap();
    assert!(ts.verified, "imprint matches");
    assert!(!ts.signature_valid && !ts.trusted, "but nobody signed it");
    assert_eq!(s.time_source, "device");
}

/// E1: page geometry resolves inherited MediaBox/Rotate and clips the CropBox to the MediaBox.
#[test]
fn page_geometry_resolves_inheritance_rotation_and_crop() {
    let pdf = container::make_sample_pdf("Geometry");
    let g = signpdf_core::pades::page_geometry(&pdf).unwrap();
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].media_box, [0.0, 0.0, 612.0, 792.0]);
    assert_eq!(g[0].crop_box, g[0].media_box);
    assert_eq!(g[0].rotate, 0);

    // Pages node carries /Rotate -270 (== 90) and an A4 MediaBox; the page has a CropBox that
    // pokes outside the MediaBox and must be clipped.
    let pdf = append_object_override(
        &pdf,
        2,
        "<< /Type /Pages /Kids [3 0 R] /Count 1 /Rotate -270 /MediaBox [595 842 0 0] >>",
    );
    let pdf = append_object_override(
        &pdf,
        3,
        "<< /Type /Page /Parent 2 0 R /CropBox [10 20 700 800] /Annots [6 0 R] \
         /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    );
    let pdf = append_object_override(
        &pdf,
        6,
        "<< /Type /Annot /Subtype /Widget /FT /Tx /Rect [300 400 100 380] /T (name) >>",
    );
    let g = signpdf_core::pades::page_geometry(&pdf).unwrap();
    assert_eq!(g[0].media_box, [0.0, 0.0, 595.0, 842.0]);
    assert_eq!(g[0].crop_box, [10.0, 20.0, 595.0, 800.0]);
    assert_eq!(g[0].rotate, 90);
    assert_eq!(g[0].annotations.len(), 1);
    assert_eq!(g[0].annotations[0].rect, [100.0, 380.0, 300.0, 400.0]);
    assert_eq!(g[0].annotations[0].field_type.as_deref(), Some("Tx"));
}

/// E2: a field must lie on the visible part of its page.
#[test]
fn prepare_rejects_fields_outside_the_page() {
    let pdf = container::make_sample_pdf("NDA");
    let (k, mut r) = two_signer_request(&pdf);
    r.fields[0].rect.y = 780.0; // 780 + 40 > 792
    let err = prepare(&pdf, &r, &k).unwrap_err().to_string();
    assert!(err.contains("outside page 1"), "{err}");

    let (k, mut r) = two_signer_request(&pdf);
    r.fields[0].rect.x = -5.0;
    assert!(prepare(&pdf, &r, &k).is_err());
}

/// E4: every signature/initials field gets an appearance — the primary signature field holds
/// the PAdES box; the others get stamps derived from the verified identity.
#[test]
fn every_signature_and_initials_field_is_stamped() {
    let pdf = container::make_sample_pdf("Initial every page");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![
            field("ini1", "s1", FieldType::Initials, 0, 60.0),
            sig_field("sig", "s1", 0),
            field("ini2", "s1", FieldType::Initials, 0, 200.0),
            field("sig2", "s1", FieldType::Signature, 0, 260.0),
        ],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign(&prepared, &k, &r).unwrap();

    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    let env = report.envelope.unwrap();
    let value = |id: &str| {
        env.fields
            .iter()
            .find(|f| f.id == id)
            .unwrap()
            .value
            .clone()
    };
    // The first *Signature* field is primary (even though an Initials field comes first).
    assert_eq!(value("sig"), None);
    // Initials come from the slot's name (rule `name-v1`): "Alice" gives one letter.
    assert_eq!(value("ini1").as_deref(), Some("A"));
    assert_eq!(value("ini2").as_deref(), Some("A"));
    let code = &k.fingerprint()[..8];
    assert_eq!(
        value("sig2"),
        Some(format!("alice@example.com - Sig {code}"))
    );
}

/// E4: a signer cannot put arbitrary text in their own stamp fields.
#[test]
fn forged_stamp_is_rejected() {
    let pdf = container::make_sample_pdf("Initials");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![
            sig_field("sig", "s1", 0),
            field("ini", "s1", FieldType::Initials, 0, 200.0),
        ],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed =
        signpdf_core::workflow::testing::sign_malicious(&prepared, &k, &r, false, &|env| {
            env.fields.iter_mut().find(|f| f.id == "ini").unwrap().value = Some("CEO".into());
        })
        .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid);
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("stamp in field 'ini'")),
        "{:?}",
        report.messages
    );
}

/// E5: labels are part of the prepared terms.
#[test]
fn field_labels_are_part_of_the_prepared_terms() {
    let pdf = container::make_sample_pdf("Labels");
    let mut company = field("company", "s1", FieldType::Text, 0, 300.0);
    company.label = Some("Company name".into());
    company.required = false;
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![sig_field("sig", "s1", 0), company],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    assert_eq!(
        signpdf_core::read_envelope(&prepared).unwrap().fields[1]
            .label
            .as_deref(),
        Some("Company name")
    );
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed =
        signpdf_core::workflow::testing::sign_malicious(&prepared, &k, &r, false, &|env| {
            env.fields[1].label = Some("Amount you owe".into());
        })
        .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid);
    assert!(report.messages.iter().any(|m| m.contains("prepared terms")));
}

// --- checkboxes and radio groups -----------------------------------------------------------

/// The `/Contents` of every field annotation in `pdf`, read the way a viewer reads a PDF text
/// string: UTF-16BE after its byte-order mark, plain bytes otherwise.
fn field_texts(pdf: &[u8]) -> Vec<String> {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    let mut texts: Vec<String> = doc
        .objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .filter(|d| matches!(d.get(b"Subtype"), Ok(lopdf::Object::Name(n)) if n == b"FreeText"))
        .filter_map(|d| match d.get(b"Contents") {
            Ok(lopdf::Object::String(s, _)) => Some(match s.strip_prefix(&[0xFE, 0xFF]) {
                Some(utf16) => String::from_utf16(
                    &utf16
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| u16::from_be_bytes(*pair))
                        .collect::<Vec<_>>(),
                )
                .unwrap(),
                None => String::from_utf8_lossy(s).to_string(),
            }),
            _ => None,
        })
        .collect();
    texts.sort();
    texts
}

/// A document with a signature, an optional checkbox and a required three-way radio group.
fn choice_document() -> Vec<u8> {
    let pdf = container::make_sample_pdf("Delivery");
    let mut newsletter = checkbox("news", "s1", 300.0, "Send me the newsletter");
    newsletter.required = false;
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![
            sig_field("sig", "s1", 0),
            newsletter,
            radio("post", "s1", "Delivery", "By post", 400.0),
            radio("mail", "s1", "Delivery", "By email (PDF)", 460.0),
            radio("hand", "s1", "Delivery", "In person", 520.0),
        ],
        SigningOrder::Sequential,
    );
    prepare(&pdf, &req, &pk).unwrap()
}

#[test]
fn prepare_requires_checkbox_and_radio_captions() {
    let pdf = container::make_sample_pdf("Captions");
    let signers = || vec![spec("s1", "Alice", "alice@example.com", 1)];
    let try_fields = |fields: Vec<signpdf_core::Field>| {
        let (pk, req) = prepare_request(&pdf, signers(), fields, SigningOrder::Sequential);
        prepare(&pdf, &req, &pk)
            .map(|_| ())
            .map_err(|e| e.to_string())
    };

    let err = try_fields(vec![field("c", "s1", FieldType::Checkbox, 0, 300.0)]).unwrap_err();
    assert!(err.contains("checkbox c needs a label"), "{err}");
    let err = try_fields(vec![checkbox("c", "s1", 300.0, "   ")]).unwrap_err();
    assert!(err.contains("checkbox c needs a label"), "{err}");

    let err = try_fields(vec![
        radio("a", "s1", "G", "", 300.0),
        radio("b", "s1", "G", "B", 360.0),
    ])
    .unwrap_err();
    assert!(err.contains("radio option a needs a label"), "{err}");

    try_fields(vec![checkbox("c", "s1", 300.0, "I agree")]).unwrap();
}

#[test]
fn prepare_validates_radio_groups() {
    let pdf = container::make_sample_pdf("Groups");
    let signers = || {
        vec![
            spec("s1", "Alice", "alice@example.com", 1),
            spec("s2", "Bob", "bob@example.com", 2),
        ]
    };
    let try_fields = |fields: Vec<signpdf_core::Field>| {
        let (pk, req) = prepare_request(&pdf, signers(), fields, SigningOrder::Sequential);
        prepare(&pdf, &req, &pk)
            .map(|_| ())
            .map_err(|e| e.to_string())
    };

    let err = try_fields(vec![radio("a", "s1", "G", "A", 300.0)]).unwrap_err();
    assert!(err.contains("needs at least two options"), "{err}");

    let mut ungrouped = radio("a", "s1", "G", "A", 300.0);
    ungrouped.group = None;
    let err = try_fields(vec![ungrouped, radio("b", "s1", "G", "B", 360.0)]).unwrap_err();
    assert!(err.contains("radio option a needs a group"), "{err}");

    let err = try_fields(vec![
        radio("a", "s1", "G", "A", 300.0),
        radio("b", "s2", "G", "B", 360.0),
    ])
    .unwrap_err();
    assert!(err.contains("split between signers"), "{err}");

    let mut optional = radio("b", "s1", "G", "B", 360.0);
    optional.required = false;
    let err = try_fields(vec![radio("a", "s1", "G", "A", 300.0), optional]).unwrap_err();
    assert!(err.contains("mixes required and optional"), "{err}");

    let err = try_fields(vec![
        radio("a", "s1", "G", "Yes", 300.0),
        radio("b", "s1", "G", "Yes", 360.0),
    ])
    .unwrap_err();
    assert!(err.contains("two options labelled 'Yes'"), "{err}");

    let mut grouped_text = field("t", "s1", FieldType::Text, 0, 300.0);
    grouped_text.group = Some("G".into());
    let err = try_fields(vec![grouped_text]).unwrap_err();
    assert!(err.contains("only radio options are grouped"), "{err}");

    // Two groups, one per signer, are fine.
    try_fields(vec![
        radio("a", "s1", "G", "A", 300.0),
        radio("b", "s1", "G", "B", 360.0),
        radio("c", "s2", "H", "A", 420.0),
        radio("d", "s2", "H", "B", 480.0),
    ])
    .unwrap();
}

#[test]
fn checkbox_and_radio_answers_are_drawn_and_verified() {
    let prepared = choice_document();
    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    r.field_values = vec![("mail".into(), "on".into())];
    let signed = sign(&prepared, &k, &r).unwrap();

    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    let env = report.envelope.unwrap();
    let value = |id: &str| {
        env.fields
            .iter()
            .find(|f| f.id == id)
            .unwrap()
            .value
            .clone()
    };
    // Every choice is recorded, including the ones left unselected.
    assert_eq!(value("mail").as_deref(), Some("true"));
    assert_eq!(value("post").as_deref(), Some("false"));
    assert_eq!(value("hand").as_deref(), Some("false"));
    assert_eq!(value("news").as_deref(), Some("false"));

    assert_eq!(
        field_texts(&signed),
        vec![
            "( ) By post",
            "( ) In person",
            "(o) By email (PDF)",
            "[ ] Send me the newsletter",
        ]
    );
}

#[test]
fn sign_enforces_choice_rules() {
    let prepared = choice_document();
    let attempt = |values: &[(&str, &str)]| {
        let (k, mut r) = signer_request("alice@example.com", &prepared, "");
        r.field_values = values
            .iter()
            .map(|(id, v)| (id.to_string(), v.to_string()))
            .collect();
        sign(&prepared, &k, &r)
            .map(|_| ())
            .map_err(|e| e.to_string())
    };

    let err = attempt(&[("post", "true"), ("mail", "true")]).unwrap_err();
    assert!(
        err.contains("more than one option of radio group 'Delivery'"),
        "{err}"
    );

    let err = attempt(&[("news", "true")]).unwrap_err();
    assert!(
        err.contains("required radio group 'Delivery' has no option selected"),
        "{err}"
    );

    let err = attempt(&[("post", "maybe")]).unwrap_err();
    assert!(err.contains("takes true or false"), "{err}");

    // Deselecting one option and choosing another is a single choice.
    attempt(&[("post", "false"), ("hand", "true"), ("news", "yes")]).unwrap();
}

#[test]
fn required_checkbox_must_be_ticked() {
    let pdf = container::make_sample_pdf("Consent");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![checkbox("agree", "s1", 300.0, "I have read the terms")],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();

    for answer in [None, Some("false")] {
        let (k, mut r) = signer_request("alice@example.com", &prepared, "");
        r.field_values = answer
            .map(|v| ("agree".to_string(), v.to_string()))
            .into_iter()
            .collect();
        let err = sign(&prepared, &k, &r).unwrap_err().to_string();
        assert!(
            err.contains("required checkbox agree was not ticked"),
            "{err}"
        );
    }

    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    r.field_values = vec![("agree".into(), "true".into())];
    let signed = sign(&prepared, &k, &r).unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);
    assert_eq!(field_texts(&signed), vec!["[X] I have read the terms"]);
}

/// A signing client that ignores the rules is caught by the verifier.
#[test]
fn verifier_rejects_choices_the_engine_would_refuse() {
    let prepared = choice_document();
    let sign_tampered = |tamper: &dyn Fn(&mut signpdf_core::Envelope)| {
        let (k, mut r) = signer_request("alice@example.com", &prepared, "");
        r.field_values = vec![("mail".into(), "true".into())];
        let signed =
            signpdf_core::workflow::testing::sign_malicious(&prepared, &k, &r, false, tamper)
                .unwrap();
        let report = verify(&signed, &trust()).unwrap();
        assert!(!report.valid);
        report.messages.join(" | ")
    };
    let set = |env: &mut signpdf_core::Envelope, id: &str, v: &str| {
        env.fields.iter_mut().find(|f| f.id == id).unwrap().value = Some(v.into());
    };

    let messages = sign_tampered(&|env| set(env, "post", "true"));
    assert!(
        messages.contains("more than one option of radio group 'Delivery'"),
        "{messages}"
    );

    let messages = sign_tampered(&|env| set(env, "mail", "false"));
    assert!(
        messages.contains("required radio group 'Delivery' has no option selected"),
        "{messages}"
    );

    // The drawn answer must be the recorded one: here the page shows the newsletter box
    // unticked while the envelope claims it was ticked.
    let messages = sign_tampered(&|env| set(env, "news", "true"));
    assert!(
        messages.contains("does not match the signer's field values"),
        "{messages}"
    );
}

/// The group is part of the prepared terms: an option cannot be moved to another group.
#[test]
fn radio_groups_are_part_of_the_prepared_terms() {
    let prepared = choice_document();
    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    r.field_values = vec![("mail".into(), "true".into())];
    let signed =
        signpdf_core::workflow::testing::sign_malicious(&prepared, &k, &r, false, &|env| {
            env.fields
                .iter_mut()
                .find(|f| f.id == "post")
                .unwrap()
                .group = Some("Other".into());
        })
        .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid);
    assert!(report.messages.iter().any(|m| m.contains("prepared terms")));
}

// --- dropdowns -------------------------------------------------------------------------------

/// A document with a signature box and a "Country" dropdown for Alice.
fn dropdown_document(required: bool) -> Vec<u8> {
    let pdf = container::make_sample_pdf("Order");
    let mut country = dropdown("country", "s1", 300.0, &["France", "Deutschland", "España"]);
    country.required = required;
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![sig_field("sig", "s1", 0), country],
        SigningOrder::Sequential,
    );
    prepare(&pdf, &req, &pk).unwrap()
}

#[test]
fn prepare_validates_dropdown_options() {
    let pdf = container::make_sample_pdf("Order");
    let try_prepare = |f: signpdf_core::Field| {
        let (pk, req) = prepare_request(
            &pdf,
            vec![spec("s1", "Alice", "alice@example.com", 1)],
            vec![sig_field("sig", "s1", 0), f],
            SigningOrder::Sequential,
        );
        prepare(&pdf, &req, &pk)
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    let with = |options: &[&str]| dropdown("d", "s1", 300.0, options);

    assert!(try_prepare(with(&["Yes", "No"])).is_ok());

    let mut none = with(&["Yes", "No"]);
    none.options = None;
    let err = try_prepare(none).unwrap_err();
    assert!(err.contains("dropdown d needs a list of options"), "{err}");

    let err = try_prepare(with(&["Only"])).unwrap_err();
    assert!(err.contains("needs between 2 and 50 options"), "{err}");
    let many: Vec<String> = (0..51).map(|i| format!("Option {i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let err = try_prepare(with(&many)).unwrap_err();
    assert!(err.contains("needs between 2 and 50 options"), "{err}");

    for bad in [
        &["Yes", ""][..],
        &["Yes", " No"],
        &["Yes", &"x".repeat(121)],
    ] {
        let err = try_prepare(with(bad)).unwrap_err();
        assert!(err.contains("empty, padded or over-long option"), "{err}");
    }
    let err = try_prepare(with(&["Yes", "No\nMaybe"])).unwrap_err();
    assert!(err.contains("control character"), "{err}");
    let err = try_prepare(with(&["Yes", "No", "Yes"])).unwrap_err();
    assert!(err.contains("lists 'Yes' twice"), "{err}");

    // Only dropdowns have options.
    let mut text = field("t", "s1", FieldType::Text, 0, 300.0);
    text.options = Some(vec!["a".into(), "b".into()]);
    let err = try_prepare(text).unwrap_err();
    assert!(err.contains("only dropdowns have them"), "{err}");
}

#[test]
fn dropdown_choice_is_checked_drawn_and_verified() {
    let prepared = dropdown_document(true);

    // Not one of the options, and nothing at all for a required dropdown.
    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    r.field_values = vec![("country".into(), "Italia".into())];
    let err = sign(&prepared, &k, &r).unwrap_err().to_string();
    assert!(
        err.contains("takes one of its options, not 'Italia'"),
        "{err}"
    );
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let err = sign(&prepared, &k, &r).unwrap_err().to_string();
    assert!(
        err.contains("required field country was not filled"),
        "{err}"
    );

    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    r.field_values = vec![("country".into(), "España".into())];
    let signed = sign(&prepared, &k, &r).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_eq!(field_texts(&signed), vec!["España"]);
}

#[test]
fn an_optional_dropdown_may_be_left_empty() {
    let prepared = dropdown_document(false);
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign(&prepared, &k, &r).unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);
    assert!(field_texts(&signed).is_empty());
}

/// A signing client that writes a value of its own, or changes the list, is caught by the verifier.
#[test]
fn verifier_rejects_a_dropdown_value_outside_its_options() {
    let prepared = dropdown_document(true);
    let sign_tampered = |tamper: &dyn Fn(&mut signpdf_core::Envelope)| {
        let (k, mut r) = signer_request("alice@example.com", &prepared, "");
        r.field_values = vec![("country".into(), "France".into())];
        let signed =
            signpdf_core::workflow::testing::sign_malicious(&prepared, &k, &r, false, tamper)
                .unwrap();
        let report = verify(&signed, &trust()).unwrap();
        assert!(!report.valid);
        report.messages.join(" | ")
    };
    let country = |env: &mut signpdf_core::Envelope, edit: &dyn Fn(&mut signpdf_core::Field)| {
        edit(env.fields.iter_mut().find(|f| f.id == "country").unwrap());
    };

    let messages = sign_tampered(&|env| country(env, &|f| f.value = Some("Italia".into())));
    assert!(
        messages.contains("holds 'Italia', which is not one of its options"),
        "{messages}"
    );

    // Adding the wanted value to the list changes the prepared terms.
    let messages = sign_tampered(&|env| {
        country(env, &|f| {
            f.options.as_mut().unwrap().push("Italia".into());
            f.value = Some("Italia".into());
        })
    });
    assert!(messages.contains("prepared terms"), "{messages}");
}

// --- multi-line text and hand-drawn signatures ---------------------------------------------

/// The content of every appearance stream (form XObject) in `pdf`.
fn appearance_streams(pdf: &[u8]) -> Vec<String> {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    doc.objects
        .values()
        .filter_map(|o| o.as_stream().ok())
        .filter(|s| matches!(s.dict.get(b"Subtype"), Ok(lopdf::Object::Name(n)) if n == b"Form"))
        .map(|s| String::from_utf8_lossy(&s.content).to_string())
        .collect()
}

/// A document with a signature box and a 200 × 40 pt multi-line field for Alice.
fn notes_document() -> Vec<u8> {
    let pdf = container::make_sample_pdf("Notes");
    let mut notes = field("notes", "s1", FieldType::Multiline, 0, 300.0);
    notes.required = false;
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![sig_field("sig", "s1", 0), notes],
        SigningOrder::Sequential,
    );
    prepare(&pdf, &req, &pk).unwrap()
}

#[test]
fn multiline_text_is_wrapped_drawn_and_verified() {
    let prepared = notes_document();
    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    let text =
        "Deliver to the back door.\r\nCall 555 0100 on arrival, and ask for the site manager.";
    r.field_values = vec![("notes".into(), text.into())];
    let signed = sign(&prepared, &k, &r).unwrap();

    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    let env = report.envelope.unwrap();
    let stored = env.fields.iter().find(|f| f.id == "notes").unwrap();
    assert_eq!(
        stored.value.as_deref(),
        Some("Deliver to the back door.\nCall 555 0100 on arrival, and ask for the site manager."),
        "line breaks are stored as plain \\n"
    );

    // The annotation records the text with its line break...
    assert!(
        field_texts(&signed)
            .iter()
            .any(|t| t.starts_with("Deliver to the back door.\nCall 555 0100")),
        "{:?}",
        field_texts(&signed)
    );
    // ...and the page shows it on three lines: the break, plus one wrap of the long second line.
    let drawn = appearance_streams(&signed)
        .into_iter()
        .find(|s| s.contains("(Deliver to the back door.) Tj"))
        .expect("the multi-line appearance");
    assert_eq!(drawn.matches(" Tj\nT*").count(), 3, "{drawn}");
    assert!(
        drawn.contains("/Helv 10 Tf"),
        "fits at the default size: {drawn}"
    );
}

#[test]
fn multiline_text_shrinks_before_it_is_refused() {
    let prepared = notes_document();
    let attempt = |text: &str| {
        let (k, mut r) = signer_request("alice@example.com", &prepared, "");
        r.field_values = vec![("notes".into(), text.to_string())];
        sign(&prepared, &k, &r).map_err(|e| e.to_string())
    };

    // Five short lines do not fit a 40 pt field at 10 pt, but do at a smaller size.
    let signed = attempt("one\ntwo\nthree\nfour\nfive").unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);
    let drawn = appearance_streams(&signed)
        .into_iter()
        .find(|s| s.contains("(five) Tj"))
        .expect("all five lines are drawn");
    assert!(!drawn.contains("/Helv 10 Tf"), "{drawn}");

    // Too much text for the field is refused, never cut off.
    let err = attempt(&"line\n".repeat(30)).unwrap_err();
    assert!(err.contains("does not fit in field notes"), "{err}");
    let err = attempt(&"x".repeat(2001)).unwrap_err();
    assert!(err.contains("holds at most 2000 characters"), "{err}");
}

#[test]
fn a_drawn_signature_is_shown_beside_the_verified_identity() {
    let prepared = notes_document();
    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    // Two strokes and a dot, in the drawing surface's own units (y pointing down).
    r.drawn_signature = Some(vec![
        vec![[0.0, 40.0], [30.0, 0.0], [60.0, 40.0]],
        vec![[70.0, 10.0], [120.0, 35.0]],
        vec![[130.0, 20.0]],
    ]);
    let signed = sign(&prepared, &k, &r).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);

    let streams = appearance_streams(&signed);
    let signature_box = streams
        .iter()
        .find(|s| s.contains("(alice@example.com) Tj"))
        .expect("the signer's signature appearance");
    // The verified caption is still there, in full...
    assert!(signature_box.contains("(Signed by:) Tj"));
    assert!(signature_box.contains("via "), "{signature_box}");
    // ...and the ink is drawn: three stroked paths with a round pen.
    assert!(signature_box.contains("1 J\n1 j\n"), "{signature_box}");
    assert_eq!(signature_box.matches(" m\n").count(), 3, "{signature_box}");
    assert_eq!(
        signature_box.matches("\nS\n").count(),
        4,
        "frame + 3 strokes: {signature_box}"
    );
    // The drawing stays inside the left part of the 200 x 40 box.
    for line in signature_box
        .lines()
        .filter(|l| l.ends_with(" m") || l.ends_with(" l"))
    {
        let mut n = line
            .split(' ')
            .map(|v| v.parse::<f32>().unwrap_or(f32::NAN));
        let (x, y) = (n.next().unwrap(), n.next().unwrap());
        assert!(
            (4.0..=80.0).contains(&x) && (3.0..=37.0).contains(&y),
            "{line}"
        );
    }

    // Without a drawing the box has the caption only.
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let plain = sign(&prepared, &k, &r).unwrap();
    let plain_box = appearance_streams(&plain)
        .into_iter()
        .find(|s| s.contains("(alice@example.com) Tj"))
        .unwrap();
    assert!(!plain_box.contains("1 J"), "{plain_box}");
}

#[test]
fn a_bad_drawn_signature_is_refused() {
    let prepared = notes_document();
    let attempt = |ink: Vec<Vec<[f32; 2]>>| {
        let (k, mut r) = signer_request("alice@example.com", &prepared, "");
        r.drawn_signature = Some(ink);
        sign(&prepared, &k, &r)
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    let err = attempt(vec![vec![]]).unwrap_err();
    assert!(err.contains("drawn signature is empty"), "{err}");
    let err = attempt(vec![vec![[0.0, f32::NAN]]]).unwrap_err();
    assert!(err.contains("invalid coordinates"), "{err}");
    let err = attempt(vec![vec![[1.0, 1.0]; 5001]]).unwrap_err();
    assert!(err.contains("too detailed"), "{err}");
    let err = attempt(vec![vec![[1.0, 1.0]]; 201]).unwrap_err();
    assert!(err.contains("too detailed"), "{err}");
}

/// A drawing needs a signature box to go in: without one, or on a decline, it is left out.
#[test]
fn a_drawn_signature_is_ignored_without_a_signature_box() {
    let pdf = container::make_sample_pdf("No box");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    for decline in [false, true] {
        let (k, mut r) = signer_request("alice@example.com", &prepared, "");
        r.decline = decline;
        r.drawn_signature = Some(vec![vec![[0.0, 0.0], [10.0, 10.0]]]);
        let out = sign(&prepared, &k, &r).unwrap();
        let report = verify(&out, &trust()).unwrap();
        assert!(report.integrity_ok, "{:?}", report.messages);
        assert!(appearance_streams(&out).iter().all(|s| !s.contains("1 J")));
    }
}

// --- text beyond ASCII ---------------------------------------------------------------------

/// Accented Latin text (the WinAnsi range of the built-in font) is drawn as typed, in the
/// signer's name, in field values and in captions. A character from another script is still
/// drawn as `?`, while the envelope keeps what was typed.
#[test]
fn accented_text_is_drawn_recorded_and_verified() {
    let pdf = container::make_sample_pdf("Bestellung");
    let mut notes = field("notes", "s1", FieldType::Multiline, 0, 360.0);
    notes.required = false;
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Jürgen Müller", "juergen@example.com", 1)],
        vec![
            sig_field("sig", "s1", 0),
            field("city", "s1", FieldType::Text, 0, 300.0),
            notes,
            checkbox("agree", "s1", 420.0, "Geprüft – einverstanden"),
        ],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, mut r) = signer_request_named(
        signpdf_core::oidc::testing::shared_es256(),
        "Jürgen Müller",
        "juergen@example.com",
        &prepared,
        "",
    );
    r.field_values = vec![
        ("city".into(), "Düsseldorf, Königsallee 5 (山田)".into()),
        ("notes".into(), "Façade côté rue.\nPrix : 1 250 €".into()),
        ("agree".into(), "yes".into()),
    ];
    let signed = sign(&prepared, &k, &r).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);

    // The envelope keeps exactly what was typed, whatever the font can draw.
    let env = report.envelope.unwrap();
    let value = |id: &str| {
        let field = env.fields.iter().find(|f| f.id == id).unwrap();
        field.value.clone().unwrap()
    };
    assert_eq!(value("city"), "Düsseldorf, Königsallee 5 (山田)");
    assert_eq!(value("notes"), "Façade côté rue.\nPrix : 1 250 €");

    // The annotations record what is drawn: accents kept, the two Japanese characters as `?`.
    assert_eq!(
        field_texts(&signed),
        [
            "Düsseldorf, Königsallee 5 (??)",
            "Façade côté rue.\nPrix : 1 250 €",
            "[X] Geprüft – einverstanden",
        ]
    );

    // The page shows them through the WinAnsi-encoded font: one escaped byte per accented
    // character, in streams that stay plain ASCII.
    let streams = appearance_streams(&signed);
    assert!(streams.iter().all(|s| s.is_ascii()));
    for drawn in [
        // The signature box names the signer by verified email, never by the profile name.
        "(juergen@example.com) Tj",
        "(D\\374sseldorf, K\\366nigsallee 5 \\(??\\)) Tj",
        "(Fa\\347ade c\\364t\\351 rue.) Tj",
        "(Prix : 1 250 \\200) Tj",
        "(Gepr\\374ft \\226 einverstanden) Tj",
    ] {
        assert!(
            streams.iter().any(|s| s.contains(drawn)),
            "{drawn} in {streams:#?}"
        );
    }

    assert!(
        streams.iter().all(|s| !s.contains("J\\374rgen")),
        "the profile name is drawn nowhere on the page"
    );

    // The signature dictionary names the signer by verified email too, for the viewer's
    // signature panel.
    let doc = lopdf::Document::load_mem(&signed).unwrap();
    let names: Vec<&[u8]> = doc
        .objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .filter(|d| matches!(d.get(b"Type"), Ok(lopdf::Object::Name(n)) if n == b"Sig"))
        .filter_map(|d| match d.get(b"Name") {
            Ok(lopdf::Object::String(s, _)) => Some(s.as_slice()),
            _ => None,
        })
        .collect();
    assert!(
        names.contains(&"juergen@example.com".as_bytes()),
        "{:?}",
        names
            .iter()
            .map(|n| String::from_utf8_lossy(n))
            .collect::<Vec<_>>()
    );

    // The certificate of completion shows the recipient's name, as the preparer wrote it, with
    // the accents.
    let certificate = signpdf_core::completion_certificate(&signed, &trust()).unwrap();
    let text = String::from_utf8_lossy(&certificate).to_string();
    assert!(text.contains("J\\374rgen M\\374ller"), "certificate text");
    assert!(lopdf::Document::load_mem(&certificate).is_ok());
}

/// Text that needs no other encoding is written byte for byte as before, so documents without
/// accents are unchanged by the wider character range.
#[test]
fn ascii_text_is_written_as_plain_literal_strings() {
    let pdf = container::make_sample_pdf("Plain");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![
            sig_field("sig", "s1", 0),
            field("price", "s1", FieldType::Text, 0, 300.0),
        ],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    r.field_values = vec![("price".into(), "EUR 12,500 (net)".into())];
    let signed = sign(&prepared, &k, &r).unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);
    let raw = String::from_utf8_lossy(&signed).to_string();
    assert!(raw.contains("/Contents (EUR 12,500 \\(net\\))"), "literal");
    assert!(raw.contains("/Name (alice@example.com)"), "literal name");
    assert!(!raw.contains("<FEFF"), "no UTF-16 string is needed");
}

/// The envelope is stored compressed, so a changed byte inside it usually leaves bytes
/// that no longer inflate. The verifier still reports what the signatures show (the document was
/// changed after signing) instead of refusing the file as no SignPDF document, and signing it is
/// refused for its integrity.
#[test]
fn a_damaged_compressed_envelope_is_reported_as_a_change() {
    let pdf = container::make_sample_pdf("NDA");
    let (preparer_key, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &preparer_key).unwrap();
    let find = |needle: &[u8], from: usize| {
        from + prepared[from..]
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap()
    };
    let filter = find(b"/Filter /FlateDecode", 0);
    let content = find(b"stream\n", filter) + 7;
    let mut damaged = prepared.clone();
    damaged[content + 20] ^= 0x55;

    let report = verify(&damaged, &trust()).unwrap();
    assert!(
        !report.valid && !report.integrity_ok,
        "{:?}",
        report.messages
    );
    assert!(report.envelope.is_none());

    let (key, sign_req) = signer_request("alice@example.com", &damaged, "s1");
    let err = sign(&damaged, &key, &sign_req).unwrap_err().to_string();
    assert!(err.contains("integrity"), "{err}");
}
