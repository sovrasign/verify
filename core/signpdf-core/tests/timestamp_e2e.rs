//! RFC 3161 timestamp parsing/verification against a *real* DigiCert response fixture.
//!
//! `tests/fixtures/tsa_digicert_response.der` is a genuine `TimeStampResp` fetched from
//! `http://timestamp.digicert.com` over a fixed digest (see below). Committing it lets us test
//! real-world token parsing with no network at test time. A live round-trip is exercised
//! separately by the CLI.

use signpdf_core::timestamp::{self, TimestampToken};

/// SHA-256 of the bytes `b"signpdf-timestamp-fixture-v1"` — the imprint inside the fixture.
const FIXTURE_DIGEST: [u8; 32] = [
    0x82, 0xa4, 0x77, 0x92, 0x5f, 0x1e, 0xe6, 0xb8, 0x5f, 0x71, 0x44, 0x3e, 0x8c, 0x63, 0xe3, 0x69,
    0x02, 0xb8, 0x89, 0x35, 0x62, 0x65, 0xb4, 0xad, 0x13, 0x8e, 0xf1, 0xe5, 0xd6, 0x11, 0xd9, 0xa1,
];

const DIGICERT_RESPONSE: &[u8] = include_bytes!("fixtures/tsa_digicert_response.der");

#[test]
fn parses_real_digicert_response() {
    let token = timestamp::parse_response(DIGICERT_RESPONSE, &FIXTURE_DIGEST)
        .expect("a granted DigiCert response must parse");

    // genTime normalized to RFC 3339; serial present.
    assert!(
        token.info.gen_time.ends_with('Z') && token.info.gen_time.contains('T'),
        "unexpected genTime: {}",
        token.info.gen_time
    );
    assert!(
        token.info.gen_time.starts_with("20"),
        "genTime year looks wrong: {}",
        token.info.gen_time
    );
    assert!(!token.info.serial_hex.is_empty());
    assert!(!token.token_der.is_empty());
}

#[test]
fn verify_token_rejects_a_different_digest() {
    let token = timestamp::parse_response(DIGICERT_RESPONSE, &FIXTURE_DIGEST).unwrap();
    let mut wrong = FIXTURE_DIGEST;
    wrong[0] ^= 0xFF;
    assert!(
        timestamp::verify_token(&token.token_der, &wrong).is_err(),
        "a token must not verify against a different document digest"
    );
}

#[test]
fn parse_response_rejects_imprint_mismatch() {
    let mut wrong = FIXTURE_DIGEST;
    wrong[31] ^= 0x01;
    assert!(timestamp::parse_response(DIGICERT_RESPONSE, &wrong).is_err());
}

#[test]
fn stored_token_roundtrips_through_base64() {
    let token = timestamp::parse_response(DIGICERT_RESPONSE, &FIXTURE_DIGEST).unwrap();
    let b64 = token.to_base64();
    let restored = TimestampToken::from_base64(&b64, &FIXTURE_DIGEST).unwrap();
    assert_eq!(restored.token_der, token.token_der);
    assert_eq!(restored.info, token.info);
}

fn gen_time_unix(token: &TimestampToken) -> i64 {
    time::OffsetDateTime::parse(
        &token.info.gen_time,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp()
}

#[test]
fn real_tsa_signature_verifies_but_is_untrusted_without_anchor() {
    let token = timestamp::parse_response(DIGICERT_RESPONSE, &FIXTURE_DIGEST).unwrap();
    let sig = timestamp::verify_tsa_signature(&token.token_der, &[], gen_time_unix(&token));
    assert!(
        sig.signature_valid,
        "DigiCert CMS signature must verify: {}",
        sig.detail
    );
    assert!(!sig.trusted, "no anchors configured, so not trusted");
    assert!(!sig.tsa_name.is_empty());
}

#[test]
fn real_tsa_chains_to_an_anchor_from_its_own_chain() {
    let token = timestamp::parse_response(DIGICERT_RESPONSE, &FIXTURE_DIGEST).unwrap();
    let certs = timestamp::token_certificates(&token.token_der);
    assert!(!certs.is_empty(), "DigiCert includes its certificate chain");
    // Trust each certificate of the embedded chain in turn: the signer must chain to it.
    for anchor in &certs {
        let sig = timestamp::verify_tsa_signature(
            &token.token_der,
            std::slice::from_ref(anchor),
            gen_time_unix(&token),
        );
        assert!(sig.trusted, "should chain to embedded cert: {}", sig.detail);
    }
}

#[test]
fn bundled_digicert_root_anchors_the_real_tsa() {
    let token = timestamp::parse_response(DIGICERT_RESPONSE, &FIXTURE_DIGEST).unwrap();
    let store = signpdf_core::trust::TrustStore::well_known();
    let sig = timestamp::verify_tsa_signature(
        &token.token_der,
        &store.tsa_anchor_ders(),
        gen_time_unix(&token),
    );
    assert!(sig.signature_valid && sig.trusted, "{}", sig.detail);
}

#[test]
fn synthetic_unsigned_token_is_not_a_valid_tsa_signature() {
    use signpdf_core::crypto::b64_decode_pub;
    let b64 = timestamp::testing::mint_timestamp(&FIXTURE_DIGEST, "2026-01-01T00:00:00Z", 1);
    let der = b64_decode_pub(&b64).unwrap();
    // The imprint checks out...
    assert!(timestamp::verify_token(&der, &FIXTURE_DIGEST).is_ok());
    // ...but nobody signed it.
    let sig = timestamp::verify_tsa_signature(&der, &[], 1_767_225_600);
    assert!(!sig.signature_valid && !sig.trusted);
}

#[test]
fn tampered_tst_info_breaks_the_tsa_signature() {
    let token = timestamp::parse_response(DIGICERT_RESPONSE, &FIXTURE_DIGEST).unwrap();
    let mut der = token.token_der.clone();
    // Flip a byte of the imprint inside TSTInfo (the digest bytes appear verbatim).
    let pos = der
        .windows(FIXTURE_DIGEST.len())
        .position(|w| w == FIXTURE_DIGEST)
        .unwrap();
    der[pos] ^= 0x01;
    let sig = timestamp::verify_tsa_signature(&der, &[], gen_time_unix(&token));
    assert!(!sig.signature_valid);
}

#[test]
fn request_for_document_matches_manual_digest() {
    let (digest, request) = timestamp::request_for_document(b"signpdf-timestamp-fixture-v1");
    assert_eq!(digest, FIXTURE_DIGEST);
    assert!(request.starts_with(&[0x30])); // DER SEQUENCE
}

#[test]
fn test_tsa_issues_signed_tokens_that_chain_to_its_certificate() {
    let tsa = timestamp::testing::TestTsa::new();
    let der = tsa.stamp(&FIXTURE_DIGEST, "2026-06-01T12:00:00Z");
    let info = timestamp::verify_token(&der, &FIXTURE_DIGEST).unwrap();
    assert_eq!(info.gen_time, "2026-06-01T12:00:00Z");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let sig = timestamp::verify_tsa_signature(&der, &[tsa.cert_der()], now);
    assert!(sig.signature_valid && sig.trusted, "{}", sig.detail);
    let untrusted = timestamp::verify_tsa_signature(&der, &[], now);
    assert!(untrusted.signature_valid && !untrusted.trusted);
}
