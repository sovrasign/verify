//! The algorithm policy the verifier reads from its trust list: which digest and signature
//! algorithms it accepts, until when, and under which timestamp.
//!
//! - Without a policy in the trust list, the engine's built-in one applies (every implemented
//!   algorithm, RSA from 2048 bits, no end dates); the report names the policy it applied.
//! - An algorithm the policy does not accept makes the evidence relying on it worthless: a
//!   signature (integrity), an identity token (`algorithm-not-accepted`), a timestamp (not
//!   trusted).
//! - Past an algorithm's `not_after`, evidence relying on it counts only when a trusted timestamp,
//!   itself acceptable, shows it existed by then.
//!
//! See docs/SECURITY_MODEL.md §4 and `signpdf_core::algorithms`.

mod common;

use common::*;
use signpdf_core::oidc::testing::TestIssuer;
use signpdf_core::timestamp::testing::TestTsa;
use signpdf_core::{
    container, embed_document_timestamp, prepare, prepare_document_timestamp, sign, verify,
    verify_at, AlgorithmPolicy, TrustStore,
};

const DAY: i64 = 86_400;

fn rfc3339(t: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(t)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// The built-in policy as version 2, with `edit` applied.
fn policy(edit: impl FnOnce(&mut AlgorithmPolicy)) -> AlgorithmPolicy {
    let mut p = AlgorithmPolicy::builtin();
    p.version = 2;
    edit(&mut p);
    p
}

/// `policy` with `algorithm` ending at `end`.
fn ending(algorithm: &str, end: i64) -> AlgorithmPolicy {
    policy(|p| {
        p.algorithms
            .iter_mut()
            .find(|r| r.algorithm == algorithm)
            .unwrap()
            .not_after = Some(rfc3339(end))
    })
}

/// The test trust store plus `rsa`'s key, a TSA, and `algorithms`.
fn trust_with(rsa: &TestIssuer, tsa: &TestTsa, algorithms: Option<AlgorithmPolicy>) -> TrustStore {
    let mut t = trust();
    t.add_jwks(ISSUER, &rsa.jwks());
    t.add_tsa_anchor(&tsa.cert_der());
    t.set_algorithm_policy(algorithms).unwrap();
    t
}

/// A one-signer document signed by Alice with an RS256 token from `rsa`.
fn signed_with_rsa(rsa: &TestIssuer) -> Vec<u8> {
    let pdf = container::make_sample_pdf("Lease");
    let (key, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![sig_field("f1", "s1", 0)],
        signpdf_core::SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &key).unwrap();
    let (k, r) = signer_request_with(rsa, "alice@example.com", &prepared, "");
    sign(&prepared, &k, &r).unwrap()
}

/// `pdf` with a document timestamp from `tsa` dated `at`.
fn stamped_at(pdf: &[u8], tsa: &TestTsa, at: i64) -> Vec<u8> {
    let (prepared, digest) = prepare_document_timestamp(pdf).unwrap();
    embed_document_timestamp(&prepared, &tsa.stamp(&digest, &rfc3339(at))).unwrap()
}

#[test]
fn the_report_names_the_policy_it_applied() {
    let pdf = container::make_sample_pdf("NDA");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let report = verify(&prepared, &trust()).unwrap();
    assert!(report.valid);
    assert_eq!(report.algorithm_policy.version, 1);
    assert_eq!(report.algorithm_policy.source, "builtin");
    assert_eq!(report.algorithm_policy.checked_at, "");

    let now = now_unix();
    let mut t = trust();
    t.set_algorithm_policy(Some(ending("RSA-PKCS1-v1_5", now + 365 * DAY)))
        .unwrap();
    let report = verify_at(&prepared, &t, now).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_eq!(report.algorithm_policy.version, 2);
    assert_eq!(report.algorithm_policy.source, "trust-list");
    assert_eq!(report.algorithm_policy.checked_at, rfc3339(now));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["algorithm_policy"]["source"], "trust-list");
}

#[test]
fn a_signature_algorithm_the_policy_drops_is_worth_nothing() {
    let pdf = container::make_sample_pdf("NDA");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let mut t = trust();
    t.set_algorithm_policy(Some(policy(|p| {
        p.algorithms.retain(|r| r.algorithm != "ECDSA-P256")
    })))
    .unwrap();
    let report = verify(&prepared, &t).unwrap();
    assert!(!report.valid && !report.integrity_ok);
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("cannot be relied on") && m.contains("ECDSA-P256")),
        "{:?}",
        report.messages
    );
}

#[test]
fn a_short_rsa_key_is_refused() {
    let rsa = TestIssuer::rs256();
    let tsa = TestTsa::new();
    let signed = signed_with_rsa(&rsa);
    assert!(
        verify(&signed, &trust_with(&rsa, &tsa, None))
            .unwrap()
            .valid
    );
    let strict = policy(|p| {
        p.algorithms
            .iter_mut()
            .find(|r| r.algorithm == "RSA-PKCS1-v1_5")
            .unwrap()
            .min_key_bits = Some(3072)
    });
    let report = verify(&signed, &trust_with(&rsa, &tsa, Some(strict))).unwrap();
    assert!(report.integrity_ok && !report.valid);
    assert_eq!(
        report.signatures[0].identity_trust,
        "algorithm-not-accepted"
    );
    assert!(report.signatures[0].level.is_none());
    assert!(
        report.messages.iter().any(|m| m.contains("2048-bit")),
        "{:?}",
        report.messages
    );
}

#[test]
fn past_its_end_an_rsa_token_counts_only_under_an_earlier_timestamp() {
    let rsa = TestIssuer::rs256();
    let tsa = TestTsa::new();
    let now = now_unix();
    let end = now + 30 * DAY;
    let trust = trust_with(&rsa, &tsa, Some(ending("RSA-PKCS1-v1_5", end)));
    let signed = signed_with_rsa(&rsa);

    // Before the end, nothing else is needed.
    let report = verify_at(&signed, &trust, now).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert!(report.warnings.iter().all(|w| !w.contains("RSA")));

    // After it, the token alone proves nothing (the preparer's ES256 token still counts).
    let later = end + DAY;
    let report = verify_at(&signed, &trust, later).unwrap();
    assert!(report.integrity_ok && !report.valid && !report.trusted_time_pending);
    assert_eq!(report.preparer.as_ref().unwrap().identity_trust, "trusted");
    assert_eq!(
        report.signatures[0].identity_trust,
        "algorithm-not-accepted"
    );
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("signer 's1'") && m.contains("no trusted timestamp")),
        "{:?}",
        report.messages
    );
    // A verifier without a clock counts every end date as passed.
    let mut no_clock = trust.clone();
    no_clock
        .set_algorithm_policy(Some(ending("RSA-PKCS1-v1_5", now - DAY)))
        .unwrap();
    assert!(!verify(&signed, &no_clock).unwrap().valid);

    // A document timestamp from before the end keeps it, with a warning that says so.
    let sealed = stamped_at(&signed, &tsa, now + DAY);
    let report = verify_at(&sealed, &trust, later).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_eq!(report.signatures[0].identity_trust, "trusted");
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("signer 's1'") && w.contains("RSA-PKCS1-v1_5")),
        "{:?}",
        report.warnings
    );

    // One from after the end does not.
    let late = stamped_at(&signed, &tsa, end + 3600);
    let report = verify_at(&late, &trust, later).unwrap();
    assert_eq!(
        report.signatures[0].identity_trust,
        "algorithm-not-accepted"
    );
}

#[test]
fn a_timestamp_relying_on_an_ended_algorithm_is_no_evidence() {
    // The test TSA signs with ECDSA P-256 and SHA-256. With SHA-256 ended and nothing later to
    // keep the timestamp, it no longer dates anything.
    let rsa = TestIssuer::rs256();
    let tsa = TestTsa::new();
    let now = now_unix();
    let sealed = stamped_at(&signed_with_rsa(&rsa), &tsa, now + DAY);
    let mut trust = trust_with(&rsa, &tsa, None);
    let report = verify(&sealed, &trust).unwrap();
    assert!(report.valid && report.document_timestamps[0].timestamp.is_trusted());
    assert_eq!(report.pades_level, "B-T");

    trust
        .set_algorithm_policy(Some(ending("SHA-256", now + 10 * DAY)))
        .unwrap();
    let report = verify_at(&sealed, &trust, now + 20 * DAY).unwrap();
    let doc = &report.document_timestamps[0].timestamp;
    assert!(!doc.is_trusted());
    assert!(doc.detail.contains("SHA-256"), "{}", doc.detail);
    assert!(report.signatures[0].existed_before.is_none());
    // Everything rests on SHA-256 here, so nothing holds.
    assert!(!report.valid && !report.integrity_ok);
}
