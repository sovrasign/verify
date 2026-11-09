//! Assurance levels (L1–L5) and the basis they rest on.
//!
//! - The verifier computes every identity's level from the token and what its trust store says
//!   about the issuer ([`TrustStore::issuer_kind`]): an email-code provider is L1, an account
//!   provider L2, an organization identity L3. The slot's requirement is never taken for it.
//! - A slot requires a level (`min_level`) and evidence (`required_methods`). The engine refuses
//!   to sign below them; the verifier reports a signature below them as `insufficient-level`.
//! - Prepare refuses a slot no signature this build checks could fill (L4, L5, phone, ...).
//!
//! See docs/SECURITY_MODEL.md §3.

mod common;

use common::*;
use signpdf_core::crypto::{sha256_hex, KeyPair};
use signpdf_core::oidc::testing::shared_es256;
use signpdf_core::oidc::ACR_EMAIL_OTP;
use signpdf_core::workflow::{PrepareRequest, SignRequest, SignerSpec};
use signpdf_core::{
    compute_nonce, container, prepare, read_envelope, sign, verify, IssuerKind, Level, Method,
    SigningOrder, TrustStore,
};

/// A sign request for `email` with a token carrying `extra` claims (an `hd`, an `acr`...).
fn request_with(pdf: &[u8], email: &str, extra: serde_json::Value) -> (KeyPair, SignRequest) {
    let key = KeyPair::generate();
    let now = now_unix();
    let mut claims = serde_json::json!({
        "iss": ISSUER, "sub": format!("user|{email}"), "aud": AUDIENCE,
        "iat": now - 5, "exp": now + 3600,
        "email": email, "email_verified": true,
        "nonce": compute_nonce(&key.public_sec1(), &sha256_hex(pdf)),
    });
    for (k, v) in extra.as_object().unwrap() {
        claims[k] = v.clone();
    }
    let req = SignRequest {
        id_token: shared_es256().mint(claims),
        idp_jwk: serde_json::to_string(&shared_es256().jwk()).unwrap(),
        audience: AUDIENCE.into(),
        allowed_issuers: vec![ISSUER.into()],
        ..Default::default()
    };
    (key, req)
}

/// A one-signer document whose slot for `email` requires `level` and `methods`.
fn prepared_for(email: &str, level: Level, methods: Vec<Method>) -> Vec<u8> {
    let pdf = container::make_sample_pdf("Statement of work");
    let mut signer = spec("s1", "Signer", email, 1);
    signer.identity_policy.min_level = level;
    signer.identity_policy.required_methods = methods;
    let (key, req) = prepare_request(
        &pdf,
        vec![signer],
        vec![sig_field("f1", "s1", 0)],
        SigningOrder::Sequential,
    );
    prepare(&pdf, &req, &key).unwrap()
}

/// [`trust`], with the test issuer recorded as `kind`.
fn trust_as(kind: IssuerKind) -> TrustStore {
    let mut t = trust();
    t.set_issuer_kind(ISSUER, Some(kind)).unwrap();
    t
}

#[test]
fn every_identity_has_a_computed_level_and_basis() {
    let pdf = container::make_sample_pdf("NDA");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign(&prepared, &k, &r).unwrap();

    // The test issuer stands in for an account provider.
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    for s in report.preparer.iter().chain(&report.signatures) {
        assert_eq!(s.level, Some(Level::L2), "{s:?}");
        assert_eq!(s.basis.len(), 1);
        assert_eq!(s.basis[0].method, Method::Account);
        assert_eq!(s.basis[0].issuer, ISSUER);
    }
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["signatures"][0]["level"], "L2");
    assert_eq!(json["signatures"][0]["basis"][0]["method"], "account");
    assert!(json["signatures"][0].get("assurance").is_none());

    // The same document, to a verifier whose trust store knows the issuer as an email-code
    // provider: L1, and still valid (the slot asks for L1).
    let report = verify(&signed, &trust_as(IssuerKind::EmailCode)).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_eq!(report.signatures[0].level, Some(Level::L1));
    assert_eq!(report.signatures[0].basis[0].method, Method::EmailCode);
    assert_eq!(
        report.signatures[0].basis[0].describe(),
        format!("email confirmed with a one-time code from {ISSUER}")
    );

    // An identity the verifier does not trust shows no level.
    let report = verify(&signed, &TrustStore::empty()).unwrap();
    assert!(report.signatures[0].level.is_none() && report.signatures[0].basis.is_empty());
}

#[test]
fn an_organization_identity_reaches_l3() {
    let prepared = prepared_for(
        "dana@contoso.example",
        Level::L3,
        vec![Method::Organization],
    );
    // A consumer account is L2: the engine refuses it for the L3 slot, and says why.
    let (k, r) = request_with(&prepared, "dana@contoso.example", serde_json::json!({}));
    let err = sign(&prepared, &k, &r).unwrap_err().to_string();
    assert!(
        err.contains("cannot fill its slot") && err.contains("L2 (Account)"),
        "{err}"
    );
    // A Workspace account of the organization is L3.
    let (k, r) = request_with(
        &prepared,
        "dana@contoso.example",
        serde_json::json!({ "hd": "contoso.example" }),
    );
    let signed = sign(&prepared, &k, &r).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    let s = &report.signatures[0];
    assert_eq!(s.level, Some(Level::L3));
    assert_eq!(s.basis[0].method, Method::Organization);
    assert_eq!(s.basis[0].organization.as_deref(), Some("contoso.example"));

    // A verifier that counts the issuer as an email-code provider does not accept it there.
    let report = verify(&signed, &trust_as(IssuerKind::EmailCode)).unwrap();
    assert!(report.integrity_ok && !report.valid && !report.trusted_time_pending);
    assert_eq!(report.signatures[0].identity_trust, "insufficient-level");
    assert_eq!(report.signatures[0].level, Some(Level::L1));
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("signer 's1'") && m.contains("L1 (Email)") && m.contains("L3")),
        "{:?}",
        report.messages
    );
}

#[test]
fn a_token_from_an_email_code_counts_as_one_wherever_it_is_from() {
    // The slot asks for an account sign-in; the token says it came from an email code.
    let prepared = prepared_for("erin@example.com", Level::L2, vec![]);
    let (k, r) = request_with(
        &prepared,
        "erin@example.com",
        serde_json::json!({ "acr": ACR_EMAIL_OTP }),
    );
    let err = sign(&prepared, &k, &r).unwrap_err().to_string();
    assert!(err.contains("L1 (Email)"), "{err}");
    // An account sign-in fills it.
    let (k, r) = request_with(&prepared, "erin@example.com", serde_json::json!({}));
    let signed = sign(&prepared, &k, &r).unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);
    // ...unless the verifier counts the issuer as an email-code provider.
    let report = verify(&signed, &trust_as(IssuerKind::EmailCode)).unwrap();
    assert_eq!(report.signatures[0].identity_trust, "insufficient-level");
}

#[test]
fn a_slot_requiring_evidence_needs_it_in_the_basis() {
    let prepared = prepared_for("finn@example.com", Level::L1, vec![Method::Account]);
    let (k, r) = request_with(&prepared, "finn@example.com", serde_json::json!({}));
    let signed = sign(&prepared, &k, &r).unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);
    // An organization identity is not an account sign-in in the basis.
    let report = verify(&signed, &trust_as(IssuerKind::Organization)).unwrap();
    assert_eq!(report.signatures[0].level, Some(Level::L3));
    assert_eq!(report.signatures[0].identity_trust, "insufficient-level");
    assert!(
        report.messages.iter().any(|m| m.contains("account")),
        "{:?}",
        report.messages
    );
}

#[test]
fn prepare_refuses_a_slot_no_signature_could_fill() {
    let pdf = container::make_sample_pdf("NDA");
    for (level, methods, what) in [
        (Level::L4, vec![], "L4"),
        (Level::L5, vec![], "L5"),
        (Level::L1, vec![Method::Phone], "phone"),
        (Level::L2, vec![Method::IdDocument], "id-document"),
        (Level::L1, vec![Method::Qualified], "qualified"),
    ] {
        let mut signer = spec("s1", "Signer", "gus@example.com", 1);
        signer.identity_policy.min_level = level;
        signer.identity_policy.required_methods = methods;
        let (key, req) = prepare_request(&pdf, vec![signer], vec![], SigningOrder::Sequential);
        let err = prepare(&pdf, &req, &key).unwrap_err().to_string();
        assert!(
            err.contains("cannot be filled") && err.contains(what),
            "{err}"
        );
    }
}

#[test]
fn a_prepare_request_may_still_name_the_version_3_requirement() {
    // Hosts written for version 3 send `min_assurance`: read as the level it stood for, and
    // written as `min_level` in today's version.
    let pdf = container::make_sample_pdf("NDA");
    let (key, mut req) = two_signer_request(&pdf);
    let mut json = serde_json::to_value(&req).unwrap();
    for (i, assurance) in ["enterprise", "consumer"].iter().enumerate() {
        let policy = json["signers"][i]["identity_policy"]
            .as_object_mut()
            .unwrap();
        policy.remove("min_level");
        policy.insert("min_assurance".into(), (*assurance).into());
    }
    req = serde_json::from_value::<PrepareRequest>(json.clone()).unwrap();
    assert_eq!(req.signers[0].identity_policy.min_level, Level::L3);
    assert_eq!(req.signers[1].identity_policy.min_level, Level::L1);
    let prepared = prepare(&pdf, &req, &key).unwrap();
    let env = read_envelope(&prepared).unwrap();
    assert_eq!(env.schema_version, signpdf_core::SCHEMA_VERSION);
    assert_eq!(env.signers[0].identity_policy.min_level, Level::L3);
    // Both names at once are refused.
    json["signers"][0]["identity_policy"]["min_level"] = "L3".into();
    let err = serde_json::from_value::<SignerSpec>(json["signers"][0].clone()).unwrap_err();
    assert!(err.to_string().contains("both"), "{err}");
}
