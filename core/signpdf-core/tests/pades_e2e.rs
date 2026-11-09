//! End-to-end tests for the PAdES signing path (incremental update + detached CMS).
//!
//! These exercise the same code the CLI `pades-sign` / `pades-verify` commands use and
//! that pyHanko independently validates as Acrobat-class signatures.

use signpdf_core::container::make_sample_pdf;
use signpdf_core::crypto::KeyPair;
use signpdf_core::{pades_sign, pades_verify, EmbeddedFile, SignAppearance};

fn appearance(name: &str) -> SignAppearance {
    SignAppearance {
        name: name.to_string(),
        reason: Some("testing".into()),
        location: None,
        page_index: 0,
        rect: Some([72.0, 700.0, 300.0, 740.0]),
        caption: None,
        ink: None,
    }
}

#[test]
fn signatures_are_canonical_pades_baseline() {
    let pdf = make_sample_pdf("canonical");
    let alice = KeyPair::generate();
    let signed = pades_sign(&pdf, &alice, &appearance("Alice"), None).unwrap();
    let r = &pades_verify(&signed).unwrap()[0];
    assert!(r.is_valid());
    assert!(
        r.canonical,
        "SignPDF's own CMS must pass the canonical-form check"
    );
    assert_eq!(r.sub_filter, "ETSI.CAdES.detached");

    // Altering an unsigned CMS field (the eContentType OID id-data 1.2.840.113549.1.7.1 ->
    // ...0.7.1) leaves the ECDSA signature valid but breaks canonical form.
    let oid_hex = b"06092a864886f70d010701";
    let pos = signed
        .windows(oid_hex.len())
        .position(|w| w == oid_hex)
        .expect("eContentType OID in /Contents hex");
    let mut tampered = signed.clone();
    tampered[pos + 17] = b'0';
    let r = &pades_verify(&tampered).unwrap()[0];
    assert!(r.signature_valid && !r.canonical);
}

#[test]
fn single_pades_signature_roundtrips() {
    let pdf = make_sample_pdf("PAdES single-signature e2e");
    let alice = KeyPair::generate();

    let signed = pades_sign(&pdf, &alice, &appearance("Alice"), None).unwrap();
    assert!(signed.starts_with(b"%PDF-"));
    // Original bytes are preserved verbatim (true incremental update).
    assert_eq!(&signed[..pdf.len()], &pdf[..]);

    let results = pades_verify(&signed).unwrap();
    assert_eq!(results.len(), 1);
    let r = &results[0];
    assert!(r.digest_matches, "digest must match");
    assert!(r.signature_valid, "CMS signature must verify");
    assert!(r.covers_to_eof, "single signature covers the whole file");
    assert!(r.is_valid());
    assert!(r.signer_cn.contains("Alice"));
}

#[test]
fn stacked_signatures_preserve_earlier_one() {
    let pdf = make_sample_pdf("PAdES multi-signature e2e");
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();

    let after_alice = pades_sign(&pdf, &alice, &appearance("Alice"), None).unwrap();
    let after_bob = pades_sign(&after_alice, &bob, &appearance("Bob"), None).unwrap();

    // Alice's signed bytes are still present unchanged inside the twice-signed file.
    assert_eq!(&after_bob[..after_alice.len()], &after_alice[..]);

    let results = pades_verify(&after_bob).unwrap();
    assert_eq!(results.len(), 2, "both signatures must be present");
    assert!(
        results.iter().all(|r| r.is_valid()),
        "both signatures must validate after stacking"
    );

    let bob_sig = results
        .iter()
        .find(|r| r.signer_cn.contains("Bob"))
        .expect("Bob's signature present");
    assert!(
        bob_sig.covers_to_eof,
        "the last signer covers the whole file"
    );

    let alice_sig = results
        .iter()
        .find(|r| r.signer_cn.contains("Alice"))
        .expect("Alice's signature present");
    assert!(
        !alice_sig.covers_to_eof,
        "the earlier signer no longer covers the appended update"
    );
}

#[test]
fn tampering_breaks_the_signature() {
    let pdf = make_sample_pdf("PAdES tamper e2e");
    let alice = KeyPair::generate();
    let mut signed = pades_sign(&pdf, &alice, &appearance("Alice"), None).unwrap();

    // Flip a byte inside the first signed span.
    signed[200] ^= 0xFF;

    // A parse failure on the corrupted file is also a valid detection, so only
    // assert when verification still produced results.
    if let Ok(results) = pades_verify(&signed) {
        assert!(
            results.iter().any(|r| !r.is_valid()),
            "a modified signed span must invalidate the signature"
        );
    }
}

#[test]
fn invisible_signature_is_supported() {
    let pdf = make_sample_pdf("PAdES invisible e2e");
    let alice = KeyPair::generate();
    let app = SignAppearance {
        name: "Invisible Signer".into(),
        rect: None,
        ..SignAppearance::default()
    };

    let signed = pades_sign(&pdf, &alice, &app, None).unwrap();
    let results = pades_verify(&signed).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].is_valid());
}

fn sample_envelope_file(payload: &[u8]) -> EmbeddedFile {
    EmbeddedFile {
        name: "signpdf-envelope.json".into(),
        data: payload.to_vec(),
        mime: "application/json".into(),
        relationship: "Data".into(),
        description: "test envelope".into(),
    }
}

fn captioned_appearance(name: &str) -> SignAppearance {
    use signpdf_core::SignatureCaption;
    SignAppearance {
        name: name.to_string(),
        reason: Some("testing".into()),
        location: None,
        page_index: 0,
        rect: Some([72.0, 680.0, 320.0, 760.0]),
        caption: Some(SignatureCaption {
            signer_name: name.to_string(),
            code: "deadbeef".into(),
            signed_at: "2026-06-24 18:00 UTC".into(),
            issuer: "google".into(),
        }),
        ink: None,
    }
}

#[test]
fn embedded_attachment_roundtrips_and_is_signature_covered() {
    use signpdf_core::pades::{embed_attachment, read_attachment};

    let pdf = make_sample_pdf("PAdES embed e2e");
    let alice = KeyPair::generate();

    // Plain (prepare-style) embed with no signature.
    let prepared = embed_attachment(&pdf, &sample_envelope_file(br#"{"v":1}"#)).unwrap();
    let read = read_attachment(&prepared, "signpdf-envelope.json").unwrap();
    assert_eq!(read, br#"{"v":1}"#);

    // Sign with a new (larger) envelope embedded in the signature's increment.
    let signed = pades_sign(
        &prepared,
        &alice,
        &appearance("Alice"),
        Some(&sample_envelope_file(br#"{"v":2,"signed":true}"#)),
    )
    .unwrap();

    // The latest envelope is the one embedded at signing time.
    let latest = read_attachment(&signed, "signpdf-envelope.json").unwrap();
    assert_eq!(latest, br#"{"v":2,"signed":true}"#);

    // And that signature validates over a ByteRange that includes the embedded envelope.
    let results = pades_verify(&signed).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].is_valid());
    assert!(results[0].covers_to_eof);

    // Tampering with the embedded envelope must break the covering signature.
    let needle = b"signed";
    let pos = signed
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("envelope bytes are present in the file");
    let mut tampered = signed.clone();
    tampered[pos] ^= 0xFF;
    if let Ok(res) = pades_verify(&tampered) {
        assert!(
            res.iter().any(|r| !r.is_valid()),
            "altering the embedded envelope must invalidate the signature"
        );
    }
}

#[test]
fn visible_signature_appearance_is_drawn_and_still_verifies() {
    let pdf = make_sample_pdf("PAdES visible appearance e2e");
    let alice = KeyPair::generate();

    let signed = pades_sign(&pdf, &alice, &captioned_appearance("Alice Example"), None).unwrap();

    // The signature still verifies over its ByteRange.
    let results = pades_verify(&signed).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].is_valid());

    // A visible appearance form XObject with the caption text was written and the widget
    // references it via /AP.
    let text = String::from_utf8_lossy(&signed);
    assert!(text.contains("/Subtype /Form"), "appearance form missing");
    assert!(text.contains("/AP"), "widget has no /AP reference");
    assert!(text.contains("Signed by:"), "caption label missing");
    assert!(
        text.contains("Alice Example"),
        "signer name missing from caption"
    );
    assert!(
        text.contains("deadbeef"),
        "verification code missing from caption"
    );

    // The result re-parses as a PDF.
    lopdf::Document::load_mem(&signed).expect("signed PDF with appearance must re-parse");
}

#[test]
fn document_id_stamp_is_visible_and_signs_then_verifies() {
    use signpdf_core::stamp_document_id;

    let pdf = make_sample_pdf("PAdES doc-id stamp e2e");
    let label = "SignPDF Document abc123def456";

    let stamped = stamp_document_id(&pdf, label).unwrap();

    // The stamp annotation and its label are present, and the file re-parses.
    let text = String::from_utf8_lossy(&stamped);
    assert!(text.contains("/Subtype /Stamp"), "stamp annotation missing");
    assert!(text.contains(label), "document id label missing");
    lopdf::Document::load_mem(&stamped).expect("stamped PDF must re-parse");

    // A signature applied over the stamped document covers it and verifies.
    let alice = KeyPair::generate();
    let signed = pades_sign(&stamped, &alice, &appearance("Alice"), None).unwrap();
    let results = pades_verify(&signed).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].is_valid());
    assert!(results[0].covers_to_eof);

    // Tampering with the now-signature-covered document id must break verification.
    let needle = b"abc123def456";
    let pos = signed
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("document id bytes are present");
    let mut tampered = signed.clone();
    tampered[pos] ^= 0xFF;
    if let Ok(res) = pades_verify(&tampered) {
        assert!(
            res.iter().any(|r| !r.is_valid()),
            "altering the signature-covered document id must invalidate the signature"
        );
    }
}
