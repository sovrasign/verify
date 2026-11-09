//! Trusted time for signatures that carry no timestamp of their own, and key validity windows.
//!
//! - Every revision's report gives the earliest trusted timestamp covering it (`existed_before`):
//!   its own signature timestamp, a later signature's, or a document timestamp, such as the one a
//!   hosted service adds when an envelope whose policy is `signature_timestamps = none` ends. The
//!   identity token's `iat` is reported as the lower bound (`token_issued_at`).
//! - A trust store can give an issuer's keys validity windows (`not_before`, `not_after`,
//!   `distrusted_after`) and require trusted time for an issuer's tokens. The end of a window is
//!   judged against `existed_before` only: never the device clock, never the token's own `iat`.
//!
//! See docs/SECURITY_MODEL.md §3 and §4.

mod common;

use common::*;
use signpdf_core::crypto::KeyPair;
use signpdf_core::oidc::testing::{shared_es256, TestIssuer};
use signpdf_core::timestamp::testing::TestTsa;
use signpdf_core::trust::jwk_thumbprint;
use signpdf_core::{
    add_document_timestamp, container, embed_document_timestamp, prepare,
    prepare_document_timestamp, sign, sign_with, verify, KeyWindow, SignatureStatus,
    TimestampPolicy, TrustStore, VerificationReport,
};

const HOUR: i64 = 3600;

fn rfc3339(t: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(t)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn unix(s: &str) -> i64 {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .unwrap()
        .unix_timestamp()
}

/// The test identity provider, `tsa` as the timestamp anchor.
fn trust_with(tsa: &TestTsa) -> TrustStore {
    let mut t = trust();
    t.add_tsa_anchor(&tsa.cert_der());
    t
}

/// [`trust_with`], with the test provider's tokens counting only with trusted time (as for a
/// service's own email-code provider).
fn requiring_time(tsa: &TestTsa) -> TrustStore {
    let mut t = trust_with(tsa);
    t.set_requires_trusted_time(ISSUER, true).unwrap();
    t
}

/// [`trust_with`], with `window` on the shared test key.
fn with_window(tsa: &TestTsa, window: KeyWindow) -> TrustStore {
    let mut t = trust_with(tsa);
    let tp = jwk_thumbprint(&shared_es256().jwk()).unwrap();
    t.set_key_window(ISSUER, &tp, window).unwrap();
    t
}

/// A two-signer NDA prepared with `policy`.
fn prepared(policy: TimestampPolicy) -> Vec<u8> {
    let pdf = container::make_sample_pdf("Mutual NDA");
    let (key, mut req) = two_signer_request(&pdf);
    req.policy.signature_timestamps = policy;
    prepare(&pdf, &req, &key).unwrap()
}

/// `pdf` signed by `email` (with a token from `issuer`), with a signature timestamp from `tsa`
/// when given.
fn signed_with_key(pdf: &[u8], issuer: &TestIssuer, email: &str, tsa: Option<&TestTsa>) -> Vec<u8> {
    let (key, req) = signer_request_with(issuer, email, pdf, "");
    match tsa {
        Some(t) => sign_with(pdf, &key, &req, Some(t)).unwrap(),
        None => sign(pdf, &key, &req).unwrap(),
    }
}

fn signed_by(pdf: &[u8], email: &str, tsa: Option<&TestTsa>) -> Vec<u8> {
    signed_with_key(pdf, shared_es256(), email, tsa)
}

/// `pdf` with a document timestamp from `tsa` dated `at` (Unix seconds).
fn stamped_at(pdf: &[u8], tsa: &TestTsa, at: i64) -> Vec<u8> {
    let (prepared, digest) = prepare_document_timestamp(pdf).unwrap();
    embed_document_timestamp(&prepared, &tsa.stamp(&digest, &rfc3339(at))).unwrap()
}

/// A Free envelope (no signature timestamps) that Alice and Bob signed.
fn free_completed() -> Vec<u8> {
    let p = prepared(TimestampPolicy::None);
    let alice = signed_by(&p, "alice@example.com", None);
    signed_by(&alice, "bob@example.com", None)
}

fn revisions(report: &VerificationReport) -> Vec<&SignatureStatus> {
    report.preparer.iter().chain(&report.signatures).collect()
}

fn assert_valid(report: &VerificationReport) {
    assert!(
        report.valid && !report.trusted_time_pending,
        "{:?} / {:?}",
        report.messages,
        report.warnings
    );
}

/// Intact, every identity waiting for a trusted timestamp.
fn assert_pending(report: &VerificationReport) {
    assert!(report.integrity_ok, "{:?}", report.messages);
    assert!(!report.valid && !report.identities_trusted);
    assert!(report.trusted_time_pending, "{:?}", report.messages);
    assert!(
        report.messages.iter().any(|m| m.contains("none does yet")),
        "{:?}",
        report.messages
    );
}

// --- the trusted "existed before" time ------------------------------------------------------

#[test]
fn free_signatures_existed_before_the_completion_timestamp() {
    let tsa = TestTsa::new();
    let done = free_completed();
    let report = verify(&done, &trust_with(&tsa)).unwrap();
    // Before it ends: device times only, no trusted bound yet; the test issuer needs none.
    assert_valid(&report);
    for s in revisions(&report) {
        assert_eq!(s.time_source, "device");
        assert!(s.existed_before.is_none(), "{s:?}");
        assert!(!s.token_issued_at.is_empty());
        assert!(unix(&s.token_issued_at) <= unix(&s.signed_at), "{s:?}");
    }

    let sealed = add_document_timestamp(&done, &tsa).unwrap();
    let report = verify(&sealed, &trust_with(&tsa)).unwrap();
    assert_valid(&report);
    let stamp = &report.document_timestamps[0].timestamp;
    for s in revisions(&report) {
        // The signing time stays the device's; the completion stamp bounds it from above.
        assert_eq!(s.time_source, "device");
        let e = s.existed_before.as_ref().expect("a trusted bound");
        assert_eq!(e.source, "document");
        assert_eq!(e.document_timestamp, Some(1));
        assert_eq!(e.revision, None);
        assert_eq!(e.time, stamp.time);
        assert_eq!(e.tsa_name, stamp.tsa_name);
        assert!(unix(&s.token_issued_at) <= unix(&e.time));
    }
}

#[test]
fn a_signature_timestamp_bounds_its_own_revision_and_every_earlier_one() {
    let tsa = TestTsa::new();
    let p = prepared(TimestampPolicy::Required);
    let alice = signed_by(&p, "alice@example.com", Some(&tsa));
    let done = signed_by(&alice, "bob@example.com", Some(&tsa));
    let report = verify(&done, &trust_with(&tsa)).unwrap();
    assert_valid(&report);
    let preparer = report.preparer.as_ref().unwrap();
    let e = preparer.existed_before.as_ref().unwrap();
    assert_eq!(
        (e.source.as_str(), e.revision),
        ("later-signature", Some(1))
    );
    for s in &report.signatures {
        assert_eq!(s.time_source, "tsa");
        let e = s.existed_before.as_ref().unwrap();
        assert_eq!(
            (e.source.as_str(), e.revision),
            ("signature", Some(s.index))
        );
        assert_eq!(e.time, s.timestamp.as_ref().unwrap().time);
    }
}

#[test]
fn a_signature_made_while_the_authority_was_down_is_bounded_by_the_next_one() {
    let tsa = TestTsa::new();
    let p = prepared(TimestampPolicy::Required);
    // Both authorities down for Alice: she signs on device time (a policy warning).
    let alice = signed_by(&p, "alice@example.com", None);
    let report = verify(&alice, &requiring_time(&tsa)).unwrap();
    assert_pending(&report);
    assert_eq!(report.signatures[0].identity_trust, "no-trusted-time");

    let done = signed_by(&alice, "bob@example.com", Some(&tsa));
    let report = verify(&done, &requiring_time(&tsa)).unwrap();
    assert_valid(&report);
    let e = report.signatures[0].existed_before.as_ref().unwrap();
    assert_eq!(
        (e.source.as_str(), e.revision),
        ("later-signature", Some(2))
    );
    assert_eq!(report.signatures[0].time_source, "device");
}

#[test]
fn the_earliest_trusted_timestamp_is_the_bound() {
    let tsa = TestTsa::new();
    let now = now_unix();
    let done = free_completed();
    // Two document timestamps whose times run backwards (authorities with different clocks):
    // both cover every signature, and the earlier time is the tighter bound.
    let first = stamped_at(&done, &tsa, now + 2 * HOUR);
    let second = stamped_at(&first, &tsa, now + HOUR);
    let report = verify(&second, &trust_with(&tsa)).unwrap();
    assert_valid(&report);
    for s in revisions(&report) {
        let e = s.existed_before.as_ref().unwrap();
        assert_eq!(e.document_timestamp, Some(2), "{s:?}");
        assert_eq!(unix(&e.time), now + HOUR);
    }
}

#[test]
fn an_untrusted_timestamp_is_no_evidence() {
    let anchored = TestTsa::new();
    let stranger = TestTsa::new();
    let sealed = add_document_timestamp(&free_completed(), &stranger).unwrap();
    let report = verify(&sealed, &requiring_time(&anchored)).unwrap();
    for s in revisions(&report) {
        assert!(s.existed_before.is_none(), "{s:?}");
        assert_eq!(s.identity_trust, "no-trusted-time");
    }
    assert_pending(&report);
}

// --- issuers that require trusted time ------------------------------------------------------

#[test]
fn an_issuer_that_requires_trusted_time_is_trusted_once_the_envelope_is_stamped() {
    let tsa = TestTsa::new();
    let trust = requiring_time(&tsa);

    // The preparer's own token needs it too.
    let p = prepared(TimestampPolicy::None);
    let report = verify(&p, &trust).unwrap();
    assert_pending(&report);
    assert_eq!(
        report.preparer.as_ref().unwrap().identity_trust,
        "no-trusted-time"
    );

    // An envelope still open: sound, waiting for its timestamp ("no trusted timestamp yet").
    let alice = signed_by(&p, "alice@example.com", None);
    let report = verify(&alice, &trust).unwrap();
    assert_pending(&report);
    assert!(revisions(&report)
        .iter()
        .all(|s| s.identity_trust == "no-trusted-time" && !s.valid));
    assert!(report
        .messages
        .iter()
        .any(|m| m.starts_with("signer 's1': ") && m.contains("no trusted timestamp")));

    // Completed, then stamped at its end.
    let done = signed_by(&alice, "bob@example.com", None);
    assert_pending(&verify(&done, &trust).unwrap());
    let sealed = add_document_timestamp(&done, &tsa).unwrap();
    let report = verify(&sealed, &trust).unwrap();
    assert_valid(&report);
    assert!(revisions(&report)
        .iter()
        .all(|s| s.identity_trust == "trusted" && s.valid));
    assert_eq!(report.pades_level, "B-T");

    // A declined envelope is stamped at its end too.
    let (k, mut r) = signer_request("alice@example.com", &p, "");
    r.decline = true;
    let declined = sign(&p, &k, &r).unwrap();
    assert_pending(&verify(&declined, &trust).unwrap());
    let report = verify(&add_document_timestamp(&declined, &tsa).unwrap(), &trust).unwrap();
    assert_valid(&report);
    assert!(report.declined);
}

#[test]
fn paid_signatures_carry_their_own_trusted_time() {
    let tsa = TestTsa::new();
    let p = prepared(TimestampPolicy::Required);
    let alice = signed_by(&p, "alice@example.com", Some(&tsa));
    // Alice's timestamp also covers the preparer's revision before it; Bob has not signed.
    let report = verify(&alice, &requiring_time(&tsa)).unwrap();
    assert_valid(&report);
    assert!(!report.complete);
}

#[test]
fn a_pending_identity_does_not_hide_another_problem() {
    let tsa = TestTsa::new();
    let mut trust = requiring_time(&tsa);
    // Bob signs with a key the store has never seen.
    let stranger = TestIssuer::es256();
    let p = prepared(TimestampPolicy::None);
    let alice = signed_by(&p, "alice@example.com", None);
    let done = signed_with_key(&alice, &stranger, "bob@example.com", None);
    let report = verify(&done, &trust).unwrap();
    assert!(report.integrity_ok && !report.valid);
    assert!(
        !report.trusted_time_pending,
        "an unknown key is not a matter of time"
    );
    assert_eq!(report.signatures[1].identity_trust, "unknown-key");
    assert!(report
        .messages
        .iter()
        .any(|m| m.contains("not anchored in the verifier's trust store")));

    // With the key pinned, only time is missing.
    trust.add_jwks(ISSUER, &stranger.jwks());
    assert_pending(&verify(&done, &trust).unwrap());
}

// --- key validity windows ---------------------------------------------------------------------

#[test]
fn a_retired_key_vouches_only_for_signatures_stamped_before_its_end() {
    let tsa = TestTsa::new();
    let now = now_unix();
    let trust = with_window(
        &tsa,
        KeyWindow {
            not_after: Some(rfc3339(now + HOUR)),
            ..Default::default()
        },
    );
    let done = free_completed();

    // No trusted time yet: it may still come in time.
    let report = verify(&done, &trust).unwrap();
    assert_pending(&report);
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains(&rfc3339(now + HOUR))),
        "{:?}",
        report.messages
    );

    // Stamped before the key's end: trusted.
    assert_valid(&verify(&stamped_at(&done, &tsa, now + HOUR / 2), &trust).unwrap());
    assert_valid(&verify(&stamped_at(&done, &tsa, now + HOUR), &trust).unwrap());

    // Stamped after it: nothing shows the signatures were made while the key was in use.
    let late = verify(&stamped_at(&done, &tsa, now + 2 * HOUR), &trust).unwrap();
    assert!(late.integrity_ok && !late.valid && !late.trusted_time_pending);
    assert!(revisions(&late)
        .iter()
        .all(|s| s.identity_trust == "outside-key-window"));
    assert!(
        late.messages
            .iter()
            .any(|m| m.contains("stopped signing with the key")),
        "{:?}",
        late.messages
    );
}

#[test]
fn a_distrusted_key_vouches_only_for_signatures_stamped_before_the_cut_off() {
    let tsa = TestTsa::new();
    let now = now_unix();
    let trust = with_window(
        &tsa,
        KeyWindow {
            distrusted_after: Some(rfc3339(now + HOUR)),
            ..Default::default()
        },
    );
    let done = free_completed();
    assert_pending(&verify(&done, &trust).unwrap());
    assert_valid(&verify(&stamped_at(&done, &tsa, now + HOUR / 2), &trust).unwrap());
    let late = verify(&stamped_at(&done, &tsa, now + 2 * HOUR), &trust).unwrap();
    assert!(late.integrity_ok && !late.valid && !late.trusted_time_pending);
    assert!(revisions(&late)
        .iter()
        .all(|s| s.identity_trust == "distrusted-key"));

    // A signature timestamp from before the cut-off is evidence too.
    let p = prepared(TimestampPolicy::Required);
    let alice = signed_by(&p, "alice@example.com", Some(&tsa));
    let done = signed_by(&alice, "bob@example.com", Some(&tsa));
    assert_valid(&verify(&done, &trust).unwrap());
}

#[test]
fn a_key_not_yet_in_use_vouches_for_nothing() {
    let tsa = TestTsa::new();
    let now = now_unix();
    let trust = with_window(
        &tsa,
        KeyWindow {
            not_before: Some(rfc3339(now + HOUR)),
            ..Default::default()
        },
    );
    // The tokens say they were issued an hour before the key was in use.
    let report = verify(&free_completed(), &trust).unwrap();
    assert!(report.integrity_ok && !report.valid && !report.trusted_time_pending);
    assert!(revisions(&report)
        .iter()
        .all(|s| s.identity_trust == "outside-key-window"));
}

#[test]
fn a_rotation_sweep_keeps_open_envelopes_inside_the_old_key_s_window() {
    // An email-code provider rotates from K1 to K2: K1's window ends an hour from now. A Free
    // envelope still open then holds signatures with no trusted time, so before K1's end the
    // service adds a document timestamp to it (the rotation sweep). Signers after the switch use
    // K2, and the completion stamp, much later, dates them.
    let tsa = TestTsa::new();
    let now = now_unix();
    let k1 = shared_es256();
    let k2 = TestIssuer::es256();
    let mut trust = requiring_time(&tsa);
    trust.add_jwks(ISSUER, &k2.jwks());
    trust
        .set_key_window(
            ISSUER,
            &jwk_thumbprint(&k1.jwk()).unwrap(),
            KeyWindow {
                not_after: Some(rfc3339(now + HOUR)),
                ..Default::default()
            },
        )
        .unwrap();

    let p = prepared(TimestampPolicy::None);
    let alice = signed_with_key(&p, k1, "alice@example.com", None);

    // Without the sweep, the completion stamp comes after K1's end: the preparer and Alice
    // cannot be shown to have signed while K1 was in use.
    let unswept = signed_with_key(&alice, &k2, "bob@example.com", None);
    let report = verify(&stamped_at(&unswept, &tsa, now + 3 * HOUR), &trust).unwrap();
    assert!(!report.valid);
    assert_eq!(
        report.preparer.as_ref().unwrap().identity_trust,
        "outside-key-window"
    );
    assert_eq!(report.signatures[0].identity_trust, "outside-key-window");
    assert_eq!(report.signatures[1].identity_trust, "trusted");

    // With the sweep: a document timestamp before K1's end, then Bob signs the stamped file.
    let swept = stamped_at(&alice, &tsa, now + HOUR / 2);
    assert_valid(&verify(&swept, &trust).unwrap());
    let done = signed_with_key(&swept, &k2, "bob@example.com", None);
    let report = verify(&done, &trust).unwrap();
    assert_pending(&report);
    assert_eq!(report.signatures[0].identity_trust, "trusted");
    assert_eq!(report.signatures[1].identity_trust, "no-trusted-time");

    let sealed = stamped_at(&done, &tsa, now + 3 * HOUR);
    let report = verify(&sealed, &trust).unwrap();
    assert_valid(&report);
    // Each revision is bounded by the first stamp after it.
    let bounds: Vec<Option<u32>> = revisions(&report)
        .iter()
        .map(|s| s.existed_before.as_ref().unwrap().document_timestamp)
        .collect();
    assert_eq!(bounds, [Some(1), Some(1), Some(2)]);
}

#[test]
fn a_key_window_is_the_trust_store_s_never_the_document_s() {
    // The archived JWK is the signer's data: window members in it change nothing.
    let tsa = TestTsa::new();
    let now = now_unix();
    let trust = with_window(
        &tsa,
        KeyWindow {
            not_after: Some(rfc3339(now + HOUR)),
            ..Default::default()
        },
    );
    let p = prepared(TimestampPolicy::None);
    let key = KeyPair::generate();
    let (_, mut req) = signer_request("alice@example.com", &p, "");
    let (token, _) = mint(
        "alice@example.com",
        &signpdf_core::compute_nonce(&key.public_sec1(), &signpdf_core::crypto::sha256_hex(&p)),
    );
    let mut jwk = serde_json::to_value(shared_es256().jwk()).unwrap();
    jwk["not_after"] = serde_json::json!(rfc3339(now + 100 * HOUR));
    req.id_token = token;
    req.idp_jwk = jwk.to_string();
    let alice = sign(&p, &key, &req).unwrap();
    let report = verify(&stamped_at(&alice, &tsa, now + 2 * HOUR), &trust).unwrap();
    assert_eq!(report.signatures[0].identity_trust, "outside-key-window");
}

// --- what the certificate of completion says ------------------------------------------------

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn the_certificate_bounds_device_times_by_the_completion_timestamp() {
    let tsa = TestTsa::new();
    let done = free_completed();
    let trust = requiring_time(&tsa);

    // Before the envelope ends: device clocks, no trusted timestamp yet.
    let open = signpdf_core::completion_certificate(&done, &trust).unwrap();
    assert!(contains(&open, "NOT YET VERIFIED"));
    assert!(contains(&open, "confirmed"), "device times are called so");
    assert!(!contains(&open, "existed"));

    // Sealed: every signature existed before the completion timestamp.
    let sealed = add_document_timestamp(&done, &tsa).unwrap();
    let cert = signpdf_core::completion_certificate(&sealed, &trust).unwrap();
    assert!(contains(&cert, "VALID - intact"));
    assert!(contains(&cert, "existed"));
    assert!(contains(&cert, "confirmed"));
    assert!(!contains(&cert, "NOT YET VERIFIED"));
}
