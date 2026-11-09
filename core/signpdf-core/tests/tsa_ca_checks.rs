//! Regression tests for finding 3 of `docs/SECURITY_REVIEW_2026-10-27.md`: a timestamp's chain
//! is checked for what each certificate may do. Every certificate that issues another on the way
//! to the anchor must be a certificate authority (`basicConstraints` critical with `cA`, its path
//! length respected, `keyCertSign` when it lists key usages); the TSA certificate's extended key
//! usage must be timestamping alone, marked critical (RFC 3161 §2.3); and only a certificate
//! authority may delegate OCSP signing.

use signpdf_core::ltv::check_ocsp;
use signpdf_core::ltv::testing::{TestCa, TestStatus};
use signpdf_core::timestamp::verify_tsa_signature;

fn now() -> (i64, String) {
    let t = time::OffsetDateTime::now_utc();
    (
        t.unix_timestamp(),
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    )
}

/// The timestamp a TSA issued under `root` makes: whether it is trusted, and why not.
fn trusted(tsa: &signpdf_core::timestamp::testing::TestTsa, root: &TestCa) -> (bool, String) {
    let (unix, rfc3339) = now();
    let token = tsa.stamp(&[1u8; 32], &rfc3339);
    let sig = verify_tsa_signature(&token, &[root.cert_der()], unix);
    (sig.trusted, sig.detail)
}

/// The review's case: an end-entity certificate under a trusted root (a code-signing
/// certificate, say) signs a TSA certificate for a key of its holder's own.
#[test]
fn an_end_entity_certificate_cannot_make_a_trusted_tsa() {
    let root = TestCa::new("Test Root");
    let end_entity = root.issue_subordinate("Test Code Signing", false);
    let tsa = end_entity
        .issue_tsa("Self-made TSA")
        .with_intermediate(&end_entity.cert_der());
    let (ok, detail) = trusted(&tsa, &root);
    assert!(!ok, "a TSA issued by an end-entity certificate is trusted");
    assert!(detail.contains("may not issue certificates"), "{detail}");
}

/// The same chain through a real subordinate CA is trusted.
#[test]
fn a_tsa_under_a_subordinate_ca_is_trusted() {
    let root = TestCa::new("Test Root");
    let sub = root.issue_subordinate("Test Issuing CA", true);
    let tsa = sub.issue_tsa("Test TSA").with_intermediate(&sub.cert_der());
    let (ok, detail) = trusted(&tsa, &root);
    assert!(ok, "{detail}");
}

/// A root that allows no CA below it cannot vouch for a TSA through a subordinate CA.
#[test]
fn the_path_length_constraint_is_respected() {
    let root = TestCa::with_path_len("Test Root", 0);
    let sub = root.issue_subordinate("Test Issuing CA", true);
    let tsa = sub.issue_tsa("Test TSA").with_intermediate(&sub.cert_der());
    let (ok, detail) = trusted(&tsa, &root);
    assert!(!ok);
    assert!(detail.contains("path length"), "{detail}");
    // Directly under that root, the TSA is fine.
    let (ok, detail) = trusted(&root.issue_tsa("Test TSA"), &root);
    assert!(ok, "{detail}");
}

/// The TSA certificate's timestamping purpose must be alone and critical.
#[test]
fn a_tsa_certificate_with_other_purposes_is_refused() {
    let root = TestCa::new("Test Root");
    let (ok, detail) = trusted(&root.issue_tsa_with_loose_eku("Loose TSA"), &root);
    assert!(!ok);
    assert!(detail.contains("timestamping alone"), "{detail}");
}

/// Only a certificate authority may delegate OCSP signing: an OCSP response from a responder an
/// end-entity certificate "delegated" is not evidence.
#[test]
fn an_end_entity_certificate_cannot_delegate_ocsp_signing() {
    let root = TestCa::new("Test Root");
    let end_entity = root.issue_subordinate("Test Code Signing", false);
    let tsa = end_entity.issue_tsa("Self-made TSA");
    let tsa_cert = tsa.cert_der();
    let responder = end_entity.issue_ocsp_responder();
    let response = end_entity.ocsp_response_by(&responder, &tsa_cert, TestStatus::Good);
    let result = check_ocsp(&response, &tsa_cert, &end_entity.cert_der());
    assert!(
        result
            .as_ref()
            .is_err_and(|e| e.contains("may not delegate OCSP signing")),
        "{result:?}"
    );
    // A CA's delegated responder is accepted.
    let sub = root.issue_subordinate("Test Issuing CA", true);
    let tsa_cert = sub.issue_tsa("Test TSA").cert_der();
    let responder = sub.issue_ocsp_responder();
    let response = sub.ocsp_response_by(&responder, &tsa_cert, TestStatus::Good);
    assert!(check_ocsp(&response, &tsa_cert, &sub.cert_der()).is_ok());
}
