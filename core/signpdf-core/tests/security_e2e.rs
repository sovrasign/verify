//! Attack regressions. Each test plays an adversary — an intermediary with the file in transit,
//! or a malicious signer — and asserts that verification (and, where relevant, signing) rejects
//! the result. The verifier pins the honest test issuer's key (`common::trust()`).

mod common;

use common::*;
use signpdf_core::pades::{self, EmbeddedFile};
use signpdf_core::workflow::{testing::sign_malicious, ENVELOPE_NAME};
use signpdf_core::{
    container, prepare, read_envelope, sign, verify, FieldType, Level, SigningOrder,
};

fn envelope_file(env: &signpdf_core::Envelope) -> EmbeddedFile {
    EmbeddedFile {
        name: ENVELOPE_NAME.into(),
        data: serde_json::to_vec(env).unwrap(),
        mime: "application/json".into(),
        relationship: "Data".into(),
        description: "tampered".into(),
    }
}

/// A two-signer document fully signed by Alice and Bob.
fn completed() -> Vec<u8> {
    let pdf = container::make_sample_pdf("Pay Bob EUR 100");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let a = sign(&prepared, &k, &r).unwrap();
    let (k, r) = signer_request("bob@example.com", &a, "");
    sign(&a, &k, &r).unwrap()
}

/// Critical #2: an unsigned incremental update appended after the final signature (here: a new
/// envelope that drops a signer and renames the document) must be detected, even though every
/// PAdES signature still validates over its own range.
#[test]
fn unsigned_update_after_last_signature_is_detected() {
    let done = completed();
    let mut env = read_envelope(&done).unwrap();
    env.title = "Pay Mallory EUR 1,000,000".into();
    let tampered = pades::embed_attachment(&done, &envelope_file(&env)).unwrap();

    // The tampered envelope is what a naive reader would display...
    assert_eq!(read_envelope(&tampered).unwrap().title, env.title);
    // ...but verification refuses it.
    let report = verify(&tampered, &trust()).unwrap();
    assert!(!report.valid && !report.integrity_ok);
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("appended after the last signature")),
        "{:?}",
        report.messages
    );
}

/// Content overlays appended after the last signature (shadow/incremental-saving attack).
#[test]
fn page_content_replaced_after_signing_is_detected() {
    let done = completed();
    // Redefine the page content stream (object 5 in the sample PDF).
    let content = "BT /F1 24 Tf 72 700 Td (Pay Mallory) Tj ET";
    let body = format!(
        "<< /Length {} >>\nstream\n{content}\nendstream",
        content.len()
    );
    let tampered = append_object_override(&done, 5, &body);
    let report = verify(&tampered, &trust()).unwrap();
    assert!(!report.valid);
    assert!(report.messages.iter().any(|m| m.contains("appended")));
}

/// A tampered document is refused at signing time, so an honest signer never countersigns it.
#[test]
fn signer_refuses_a_tampered_document() {
    let pdf = container::make_sample_pdf("NDA");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();

    // In transit, someone loosens Bob's slot so anyone can fill it.
    let mut env = read_envelope(&prepared).unwrap();
    env.signers[1].identity_policy = Default::default();
    let tampered = pades::embed_attachment(&prepared, &envelope_file(&env)).unwrap();

    let (k, r) = signer_request("alice@example.com", &tampered, "");
    let err = sign(&tampered, &k, &r).unwrap_err();
    assert!(err.to_string().contains("refusing to sign"), "{err}");
}

/// Critical #3: even if a careless signer signs on top of an unsigned in-transit edit, the
/// verifier detects that the signer's revision did not build on the previous signed revision.
#[test]
fn signature_over_an_unsigned_in_transit_edit_is_detected() {
    let pdf = container::make_sample_pdf("NDA");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();

    let mut env = read_envelope(&prepared).unwrap();
    env.signers[1].identity_policy = Default::default();
    let tampered = pades::embed_attachment(&prepared, &envelope_file(&env)).unwrap();

    let (k, r) = signer_request("alice@example.com", &tampered, "s1");
    let signed = sign_malicious(&tampered, &k, &r, true, &|_| {}).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid);
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("prepared terms") || m.contains("unsigned changes were inserted")),
        "{:?}",
        report.messages
    );
}

#[test]
fn malicious_signer_cannot_change_the_prepared_terms() {
    let pdf = container::make_sample_pdf("NDA");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
        env.title = "A different agreement".into();
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid);
    assert!(
        report.messages.iter().any(|m| m.contains("prepared terms")),
        "{:?}",
        report.messages
    );
}

#[test]
fn malicious_signer_cannot_loosen_a_later_slot() {
    let pdf = container::make_sample_pdf("NDA");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
        env.signers[1].identity_policy = Default::default();
    })
    .unwrap();
    assert!(!verify(&signed, &trust()).unwrap().valid);
}

#[test]
fn malicious_signer_cannot_fill_another_signers_field() {
    let pdf = container::make_sample_pdf("Order");
    let (pk, req) = prepare_request(
        &pdf,
        vec![
            spec("s1", "Alice", "alice@example.com", 1),
            spec("s2", "Bob", "bob@example.com", 2),
        ],
        vec![field("bob_price", "s2", FieldType::Text, 0, 300.0)],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
        env.fields[0].value = Some("EUR 1".into());
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid);
    assert!(
        report.messages.iter().any(|m| m.contains("another signer")),
        "{:?}",
        report.messages
    );
}

#[test]
fn malicious_signer_cannot_rewrite_history() {
    let done = completed();
    // Bob re-signs nothing new but rewrites Alice's audit entry text in his revision.
    let pdf = container::make_sample_pdf("Pay Bob EUR 100");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let a = sign(&prepared, &k, &r).unwrap();
    let (k, r) = signer_request("bob@example.com", &a, "");
    let b = sign_malicious(&a, &k, &r, false, &|env| {
        env.audit_log[1].details = "Alice agreed to pay Bob EUR 1,000,000".into();
    })
    .unwrap();
    let report = verify(&b, &trust()).unwrap();
    assert!(!report.valid);
    assert!(!report.audit_ok || report.messages.iter().any(|m| m.contains("audit log")));
    // Sanity: the honest version of the same flow verifies.
    assert!(verify(&done, &trust()).unwrap().valid);
}

#[test]
fn malicious_signer_cannot_claim_a_slot_their_identity_does_not_fit() {
    let pdf = container::make_sample_pdf("NDA");
    let (pk, mut req) = two_signer_request(&pdf);
    req.signers[0].identity_policy = level_policy("alice@example.com", Level::L1);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    // Alice signs, then edits the record to claim Bob's slot.
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
        env.signatures[0].signer_id = "s2".into();
    })
    .unwrap();
    assert!(!verify(&signed, &trust()).unwrap().valid);
}

/// A malicious signer smuggles a page-content change into their own signed revision: the PAdES
/// signature covers it, but the revision audit rejects modifications outside the allow-list.
#[test]
fn content_change_inside_a_signers_own_revision_is_detected() {
    let pdf = container::make_sample_pdf("Pay Bob EUR 100");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let content = "BT /F1 24 Tf 72 700 Td (Pay Bob EUR 900) Tj ET";
    let body = format!(
        "<< /Length {} >>\nstream\n{content}\nendstream",
        content.len()
    );
    let edited = append_object_override(&prepared, 5, &body);
    let (k, r) = signer_request("alice@example.com", &edited, "");
    let signed = sign_malicious(&edited, &k, &r, true, &|_| {}).unwrap();

    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid);
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("object 5 0 was modified")),
        "{:?}",
        report.messages
    );
}

/// Critical #8: a corrupt ByteRange must yield an invalid report, never a panic.
#[test]
fn absurd_byte_range_does_not_panic() {
    let done = completed();
    let needle = b"/ByteRange [";
    let pos = done
        .windows(needle.len())
        .rposition(|w| w == needle)
        .unwrap()
        + needle.len();
    let mut bad = done.clone();
    // Overwrite the last signature's second-range length with a huge value (same width).
    bad[pos + 33..pos + 43].copy_from_slice(b"9999999999");
    let report = verify(&bad, &trust()).unwrap();
    assert!(!report.valid);
}

/// RUSTSEC-2026-0187: deeply nested PDF objects overflowed lopdf's parser stack (< 0.42). A stack
/// overflow cannot be caught by `catch_unwind`, so it would abort the host app; the verifier must
/// instead reject such input.
#[test]
fn deeply_nested_objects_do_not_overflow_the_stack() {
    let depth = 200_000;
    let mut pdf = b"%PDF-1.7\n1 0 obj\n".to_vec();
    pdf.extend(std::iter::repeat_n(b'[', depth));
    pdf.extend(std::iter::repeat_n(b']', depth));
    pdf.extend_from_slice(
        b"\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n",
    );
    // Run on a thread with a modest stack, like an app worker isolate would have.
    let handle = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || verify(&pdf, &trust()).map(|r| r.valid).unwrap_or(false))
        .unwrap();
    assert!(!handle.join().expect("verifier must not crash"));
}
