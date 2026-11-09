//! The envelope's signature-timestamp policy (`policy.signature_timestamps`): `required` (every
//! signer revision is signed with room for a PAdES B-T signature timestamp, which the host adds),
//! `optional` (the default: the host decides) and `none` (no signature timestamps; the engine
//! refuses to make or add one). The preparer fixes it, so it holds for the envelope's whole life.

mod common;

use common::*;
use signpdf_core::crypto::KeyPair;
use signpdf_core::pades;
use signpdf_core::timestamp::{build_request, parse_response, testing::TestTsa};
use signpdf_core::workflow::{self, PrepareRequest};
use signpdf_core::{
    container, embed_signature_timestamp, prepare, read_envelope, sign, sign_for_timestamp,
    sign_with, signature_timestamp_digest, verify, Policy, SignPdfError, TimestampPolicy,
    TrustStore, VerificationReport,
};

/// A two-signer NDA prepared with `policy`.
fn prepared_with(policy: TimestampPolicy) -> Vec<u8> {
    let pdf = container::make_sample_pdf("Timestamp policy NDA");
    let (key, mut req) = two_signer_request(&pdf);
    req.policy.signature_timestamps = policy;
    prepare(&pdf, &req, &key).unwrap()
}

/// The test trust store plus `tsa` as a timestamp anchor.
fn trust_with(tsa: &TestTsa) -> TrustStore {
    let mut t = trust();
    t.add_tsa_anchor(&tsa.cert_der());
    t
}

/// The two steps a host runs after signing with room for a timestamp.
fn add_timestamp(pdf: &[u8], tsa: &TestTsa) -> signpdf_core::Result<Vec<u8>> {
    let digest = signature_timestamp_digest(pdf)?;
    let response = tsa.respond(&build_request(&digest))?;
    let token = parse_response(&response, &digest)?.token_der;
    embed_signature_timestamp(pdf, &token)
}

fn timestamp_warnings(report: &VerificationReport) -> Vec<&String> {
    report
        .warnings
        .iter()
        .filter(|w| w.contains("signature timestamp"))
        .collect()
}

fn assert_refused(result: signpdf_core::Result<impl std::fmt::Debug>, what: &str) {
    match result {
        Err(SignPdfError::Workflow(msg)) => assert!(
            msg.contains("takes no signature timestamps"),
            "{what}: unexpected message {msg}"
        ),
        other => panic!("{what}: expected a refusal, got {other:?}"),
    }
}

#[test]
fn optional_is_the_default_and_is_not_written_into_the_envelope() {
    assert_eq!(
        Policy::default().signature_timestamps,
        TimestampPolicy::Optional
    );
    let prepared = prepared_with(TimestampPolicy::Optional);
    let raw = pades::read_attachment(&prepared, workflow::ENVELOPE_NAME).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    // Envelopes that state no policy keep their exact JSON.
    assert!(
        json["policy"].get("signature_timestamps").is_none(),
        "{}",
        json["policy"]
    );

    for (policy, text) in [
        (TimestampPolicy::Required, "required"),
        (TimestampPolicy::None, "none"),
    ] {
        let raw = pades::read_attachment(&prepared_with(policy), workflow::ENVELOPE_NAME).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(json["policy"]["signature_timestamps"], text);
        assert_eq!(policy.as_str(), text);
    }

    // A policy this build does not know is not read as another one.
    let parsed: Result<Policy, _> = serde_json::from_value(serde_json::json!({
        "signing_order": "sequential", "allowed_signature_types": ["PAdES"],
        "signature_timestamps": "sometimes",
    }));
    assert!(parsed.is_err());
}

#[test]
fn the_prepare_request_json_carries_the_policy() {
    // What the browser and FFI hosts send: the policy is part of the request JSON.
    let pdf = container::make_sample_pdf("JSON request");
    let (key, req) = two_signer_request(&pdf);
    let mut json = serde_json::to_value(&req).unwrap();
    json["policy"]["signature_timestamps"] = serde_json::json!("none");
    let req: PrepareRequest = serde_json::from_value(json).unwrap();
    let prepared = prepare(&pdf, &req, &key).unwrap();
    assert_eq!(
        read_envelope(&prepared)
            .unwrap()
            .policy
            .signature_timestamps,
        TimestampPolicy::None
    );
}

#[test]
fn required_signing_leaves_room_and_the_host_adds_the_timestamp() {
    let prepared = prepared_with(TimestampPolicy::Required);
    let tsa = TestTsa::new();
    let t = trust_with(&tsa);

    // `sign` (no timestamper) makes a complete B-B signature with room for a timestamp.
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign(&prepared, &k, &r).unwrap();
    let report = verify(&signed, &t).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert!(report.signatures[0].timestamp.is_none());
    assert_eq!(report.signatures[0].time_source, "device");
    // Until the host adds it, the verifier says the time is the device's.
    let warnings = timestamp_warnings(&report);
    assert_eq!(warnings.len(), 1, "{:?}", report.warnings);
    assert!(
        warnings[0].contains("signer 's1'") && warnings[0].contains("device clock"),
        "{warnings:?}"
    );

    // The host's two steps need no key; the result has the same length and is B-T.
    let stamped = add_timestamp(&signed, &tsa).unwrap();
    assert_eq!(stamped.len(), signed.len());
    let report = verify(&stamped, &t).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_eq!(report.signatures[0].time_source, "tsa");
    assert!(
        timestamp_warnings(&report).is_empty(),
        "{:?}",
        report.warnings
    );

    // Bob's host has a synchronous TSA client: one step.
    let (k, r) = signer_request("bob@example.com", &stamped, "");
    let done = sign_with(&stamped, &k, &r, Some(&tsa)).unwrap();
    let report = verify(&done, &t).unwrap();
    assert!(report.valid && report.complete, "{:?}", report.messages);
    assert!(report.signatures.iter().all(|s| s.time_source == "tsa"));
    assert!(timestamp_warnings(&report).is_empty());
}

#[test]
fn a_decline_takes_the_policy_too() {
    let tsa = TestTsa::new();

    let prepared = prepared_with(TimestampPolicy::Required);
    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    r.decline = true;
    let declined = add_timestamp(&sign(&prepared, &k, &r).unwrap(), &tsa).unwrap();
    let report = verify(&declined, &trust_with(&tsa)).unwrap();
    assert!(report.valid && report.declined, "{:?}", report.messages);
    assert_eq!(report.signatures[0].kind, "declined");
    assert_eq!(report.signatures[0].time_source, "tsa");

    let prepared = prepared_with(TimestampPolicy::None);
    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    r.decline = true;
    assert_refused(
        sign_with(&prepared, &k, &r, Some(&tsa)),
        "timestamped decline",
    );
    let declined = sign(&prepared, &k, &r).unwrap();
    assert!(verify(&declined, &trust()).unwrap().valid);
}

#[test]
fn no_signature_timestamps_means_none_is_made_or_added() {
    let prepared = prepared_with(TimestampPolicy::None);
    let tsa = TestTsa::new();
    let t = trust_with(&tsa);
    let (k, r) = signer_request("alice@example.com", &prepared, "");

    // A host offering a timestamp is refused before anything is signed.
    assert_refused(sign_with(&prepared, &k, &r, Some(&tsa)), "sign_with");
    assert_refused(sign_for_timestamp(&prepared, &k, &r), "sign_for_timestamp");

    // Signing without one works; the time is the device clock, and that is no deviation.
    let signed = sign(&prepared, &k, &r).unwrap();
    let report = verify(&signed, &t).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert!(report.signatures[0].timestamp.is_none());
    assert_eq!(report.signatures[0].time_source, "device");
    assert!(
        timestamp_warnings(&report).is_empty(),
        "{:?}",
        report.warnings
    );

    // Nor can one be added afterwards, so no host asks a time-stamp authority for one.
    assert_refused(signature_timestamp_digest(&signed), "digest");
    let digest = pades::signature_timestamp_digest(&signed).unwrap();
    let token = parse_response(&tsa.respond(&build_request(&digest)).unwrap(), &digest)
        .unwrap()
        .token_der;
    assert_refused(embed_signature_timestamp(&signed, &token), "embed");

    // The second signer the same way.
    let (k, r) = signer_request("bob@example.com", &signed, "");
    let done = sign(&signed, &k, &r).unwrap();
    let report = verify(&done, &t).unwrap();
    assert!(report.valid && report.complete, "{:?}", report.messages);
    assert!(report.signatures.iter().all(|s| s.time_source == "device"));
}

#[test]
fn a_timestamp_forced_onto_an_envelope_that_takes_none_is_reported() {
    // A modified client that makes room and adds a timestamp with the low-level PAdES calls,
    // which do not read the envelope. The timestamp still dates the signature truthfully, so the
    // document stays valid; the departure from the policy is a warning.
    let prepared = prepared_with(TimestampPolicy::None);
    let tsa = TestTsa::new();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed =
        workflow::testing::sign_redrawn(&prepared, &k, &r, &|o| o.reserve_timestamp = true)
            .unwrap();
    let digest = pades::signature_timestamp_digest(&signed).unwrap();
    let token = parse_response(&tsa.respond(&build_request(&digest)).unwrap(), &digest)
        .unwrap()
        .token_der;
    let stamped = pades::embed_signature_timestamp(&signed, &token).unwrap();

    let report = verify(&stamped, &trust_with(&tsa)).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_eq!(report.signatures[0].time_source, "tsa");
    let warnings = timestamp_warnings(&report);
    assert_eq!(warnings.len(), 1, "{:?}", report.warnings);
    assert!(warnings[0].contains("takes none"), "{:?}", report.warnings);
}

#[test]
fn a_signer_cannot_change_the_policy() {
    // The policy is part of the prepared terms: a signer who switches a `none` envelope to
    // `optional` (to add a timestamp the sender's terms do not take) or a `required` one to
    // `none` breaks the revision chain.
    for (from, to) in [
        (TimestampPolicy::None, TimestampPolicy::Optional),
        (TimestampPolicy::Required, TimestampPolicy::None),
    ] {
        let prepared = prepared_with(from);
        let (k, r) = signer_request("alice@example.com", &prepared, "");
        let forged = workflow::testing::sign_malicious(&prepared, &k, &r, false, &|env| {
            env.policy.signature_timestamps = to
        })
        .unwrap();
        let report = verify(&forged, &trust()).unwrap();
        assert!(!report.integrity_ok, "{from:?} -> {to:?} was accepted");
        assert!(
            report.messages.iter().any(|m| m.contains("prepared terms")),
            "{:?}",
            report.messages
        );
    }
}

#[test]
fn the_preparer_revision_takes_no_signature_timestamp() {
    for policy in [TimestampPolicy::Optional, TimestampPolicy::Required] {
        let prepared = prepared_with(policy);
        match signature_timestamp_digest(&prepared) {
            Err(SignPdfError::Workflow(msg)) => assert!(msg.contains("preparer"), "{msg}"),
            other => panic!("{policy:?}: expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn optional_leaves_the_choice_to_the_host() {
    let prepared = prepared_with(TimestampPolicy::Optional);
    let tsa = TestTsa::new();
    let t = trust_with(&tsa);

    // Without a timestamper: no room, no timestamp, no warning.
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let plain = sign(&prepared, &k, &r).unwrap();
    let report = verify(&plain, &t).unwrap();
    assert!(report.valid);
    assert!(timestamp_warnings(&report).is_empty());

    // With one, at once or afterwards.
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let report = verify(&sign_with(&prepared, &k, &r, Some(&tsa)).unwrap(), &t).unwrap();
    assert_eq!(report.signatures[0].time_source, "tsa");
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let later = add_timestamp(&sign_for_timestamp(&prepared, &k, &r).unwrap(), &tsa).unwrap();
    let report = verify(&later, &t).unwrap();
    assert_eq!(report.signatures[0].time_source, "tsa");
    assert!(timestamp_warnings(&report).is_empty());
}

#[test]
fn a_refused_timestamp_does_not_need_a_new_key() {
    // The refusal comes before the identity is checked or anything is signed, so the same key
    // and sign-in can sign without a timestamp (the browser and FFI hosts keep the key on error).
    let prepared = prepared_with(TimestampPolicy::None);
    let key = KeyPair::generate();
    let (_, mut r) = signer_request("alice@example.com", &prepared, "");
    let (token, jwk) = mint(
        "alice@example.com",
        &signpdf_core::compute_nonce(
            &key.public_sec1(),
            &signpdf_core::crypto::sha256_hex(&prepared),
        ),
    );
    r.id_token = token;
    r.idp_jwk = jwk;
    assert_refused(sign_for_timestamp(&prepared, &key, &r), "first try");
    let signed = sign(&prepared, &key, &r).unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);
}
