//! Impersonation regressions: each test replays an attack that used to produce a document a
//! default verifier called valid, and checks that it no longer does.
//!
//! * a sign-in token issued to **another application** signing as its user;
//! * the provider's **profile name** (which the account holder types) shown as the signer;
//! * an email the provider **did not verify** reported as the identity.

mod common;

use common::*;
use serde_json::json;
use signpdf_core::crypto::{sha256_hex, KeyPair};
use signpdf_core::oidc::{compute_nonce, testing::shared_es256};
use signpdf_core::workflow::{PrepareRequest, SignRequest, SignerSpec};
use signpdf_core::{
    container, prepare, sign, verify, FieldType, IdentityPolicy, Policy, SigningOrder, TrustStore,
};

fn jwk_json() -> String {
    serde_json::to_string(&shared_es256().jwk()).unwrap()
}

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

/// A sign request whose token carries exactly `claims` (plus the binding nonce), obtained
/// through application `audience`.
fn request_with(pdf: &[u8], audience: &str, claims: serde_json::Value) -> (KeyPair, SignRequest) {
    let key = KeyPair::generate();
    let now = now_unix();
    let mut all = json!({
        "iss": ISSUER, "aud": audience, "iat": now - 5, "exp": now + 3600,
        "nonce": compute_nonce(&key.public_sec1(), &sha256_hex(pdf)),
    });
    for (claim, value) in claims.as_object().unwrap() {
        all[claim] = value.clone();
    }
    let request = SignRequest {
        id_token: shared_es256().mint(all),
        idp_jwk: jwk_json(),
        audience: audience.into(),
        allowed_issuers: vec![ISSUER.into()],
        ..Default::default()
    };
    (key, request)
}

/// Any website where the victim "signs in with the provider" receives a genuine token for them,
/// with whatever nonce the site asked for. Such a token must not sign a document: only tokens
/// issued to an application the verifier trusts count.
#[test]
fn a_token_issued_to_another_application_does_not_sign_as_its_user() {
    let pdf = container::make_sample_pdf("Lease");
    let (pk, req) = two_signer_request(&pdf); // slot s1 requires alice@example.com
    let prepared = prepare(&pdf, &req, &pk).unwrap();

    // The attacker holds the key; Alice only signed in to the attacker's own app.
    let (attacker_key, request) = request_with(
        &prepared,
        "evil-app.example",
        json!({ "sub": "user|alice", "email": "alice@example.com", "email_verified": true }),
    );
    // The signing engine has no trust store, so it still produces the file...
    let forged = sign(&prepared, &attacker_key, &request).unwrap();

    // ...which a verifier that trusts the provider for its own application rejects.
    let report = verify(&forged, &trust()).unwrap();
    assert!(!report.valid);
    assert!(!report.identities_trusted);
    let status = &report.signatures[0];
    assert!(!status.valid);
    assert_eq!(status.identity_trust, "untrusted-audience");
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("application 'evil-app.example'")),
        "{:?}",
        report.messages
    );

    // Pinning the provider's key alone trusts no application at all.
    let mut keys_only = TrustStore::empty();
    keys_only.add_jwks(ISSUER, &shared_es256().jwks());
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let genuine = sign(&prepared, &k, &r).unwrap();
    let report = verify(&genuine, &keys_only).unwrap();
    assert!(!report.valid);
    assert_eq!(report.signatures[0].identity_trust, "untrusted-audience");
    assert_eq!(
        report.preparer.as_ref().unwrap().identity_trust,
        "untrusted-audience"
    );

    // A verifier may trust another application explicitly (an organization's own registration).
    let mut extended = trust();
    extended.add_audience(ISSUER, "evil-app.example");
    assert!(verify(&forged, &extended).unwrap().valid);
}

/// The same holds for the preparer: a document "prepared by" someone through another
/// application is not attributed to them.
#[test]
fn a_token_issued_to_another_application_does_not_prepare_as_its_user() {
    let pdf = container::make_sample_pdf("Offer");
    let key = KeyPair::generate();
    let now = now_unix();
    let token = shared_es256().mint(json!({
        "iss": ISSUER, "sub": "user|ceo", "aud": "evil-app.example",
        "iat": now - 5, "exp": now + 3600,
        "email": "ceo@example.com", "email_verified": true,
        "nonce": compute_nonce(&key.public_sec1(), &sha256_hex(&pdf)),
    }));
    let request = PrepareRequest {
        title: "Offer".into(),
        signers: vec![spec("s1", "Bob", "bob@example.com", 1)],
        fields: vec![],
        policy: Policy {
            signing_order: SigningOrder::Sequential,
            allowed_signature_types: vec!["PAdES".into()],
            expiry: None,
            ..Default::default()
        },
        id_token: token,
        idp_jwk: jwk_json(),
        audience: "evil-app.example".into(),
        allowed_issuers: vec![ISSUER.into()],
        service_link: None,
        documents: Vec::new(),
        verify_at: None,
    };
    let prepared = prepare(&pdf, &request, &key).unwrap();
    let report = verify(&prepared, &trust()).unwrap();
    assert!(!report.valid);
    assert_eq!(
        report.preparer.unwrap().identity_trust,
        "untrusted-audience"
    );
}

/// The `name` claim is a profile name the account holder chooses. It must not appear where a
/// reader looks for who signed: the signature box, the stamps, the audit log.
#[test]
fn the_profile_name_is_not_shown_as_the_signer() {
    let pdf = container::make_sample_pdf("Board resolution");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Witness", "mallory@example.com", 1)],
        vec![
            sig_field("sig", "s1", 0),
            field("sig2", "s1", FieldType::Signature, 0, 300.0),
            field("ini", "s1", FieldType::Initials, 0, 400.0),
        ],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (key, request) = request_with(
        &prepared,
        AUDIENCE,
        json!({
            "sub": "user|mallory", "email": "mallory@example.com", "email_verified": true,
            "name": "ceo@bigcorp.example",
        }),
    );
    let signed = sign(&prepared, &key, &request).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);

    let streams = appearance_streams(&signed);
    let signature_box = streams
        .iter()
        .find(|s| s.contains("(Signed by:) Tj"))
        .expect("the signature box");
    assert!(
        signature_box.contains("(mallory@example.com) Tj"),
        "{signature_box}"
    );
    assert!(
        streams.iter().all(|s| !s.contains("bigcorp")),
        "the profile name is drawn nowhere"
    );

    let env = report.envelope.unwrap();
    let value = |id: &str| {
        let field = env.fields.iter().find(|f| f.id == id).unwrap();
        field.value.clone().unwrap()
    };
    assert!(value("sig2").starts_with("mallory@example.com - Sig "));
    // Initials come from the name the preparer gave the slot (rule `name-v1`), never from the
    // profile name.
    assert_eq!(value("ini"), "W");
    let entry = env.audit_log.last().unwrap();
    assert_eq!(entry.actor_name, "mallory@example.com");
    assert!(!entry.details.contains("bigcorp"), "{}", entry.details);
}

/// Without a provider-verified email there is no identity to report: such an account can
/// neither prepare nor sign, even where the slot asks for nothing.
#[test]
fn an_unverified_email_can_neither_prepare_nor_sign() {
    let pdf = container::make_sample_pdf("Offer");
    let open_slot = || SignerSpec {
        id: "s1".into(),
        name: "Anyone".into(),
        handle: String::new(),
        role: String::new(),
        order: 1,
        identity_policy: IdentityPolicy::default(), // pins nothing
    };

    // Preparing.
    let prepare_as = |email_claims: serde_json::Value| {
        let key = KeyPair::generate();
        let now = now_unix();
        let mut claims = json!({
            "iss": ISSUER, "sub": "user|attacker", "aud": AUDIENCE,
            "iat": now - 5, "exp": now + 3600,
            "nonce": compute_nonce(&key.public_sec1(), &sha256_hex(&pdf)),
        });
        for (claim, value) in email_claims.as_object().unwrap() {
            claims[claim] = value.clone();
        }
        let request = PrepareRequest {
            title: "Offer".into(),
            signers: vec![open_slot()],
            fields: vec![],
            policy: Policy {
                signing_order: SigningOrder::Sequential,
                allowed_signature_types: vec!["PAdES".into()],
                expiry: None,
                ..Default::default()
            },
            id_token: shared_es256().mint(claims),
            idp_jwk: jwk_json(),
            audience: AUDIENCE.into(),
            allowed_issuers: vec![ISSUER.into()],
            service_link: None,
            documents: Vec::new(),
            verify_at: None,
        };
        prepare(&pdf, &request, &key).map_err(|e| e.to_string())
    };
    let err =
        prepare_as(json!({ "email": "ceo@victim.example", "email_verified": false })).unwrap_err();
    assert!(
        err.contains("has not verified the email address 'ceo@victim.example'"),
        "{err}"
    );
    let err = prepare_as(json!({ "email": "ceo@victim.example" })).unwrap_err();
    assert!(err.contains("has not verified the email address"), "{err}");
    let err = prepare_as(json!({})).unwrap_err();
    assert!(err.contains("gave no email address"), "{err}");
    let prepared =
        prepare_as(json!({ "email": "preparer@example.com", "email_verified": true })).unwrap();

    // Signing, on the slot that pins nothing.
    let sign_as = |email_claims: serde_json::Value| {
        let mut claims = json!({ "sub": "user|attacker" });
        for (claim, value) in email_claims.as_object().unwrap() {
            claims[claim] = value.clone();
        }
        let (key, request) = request_with(&prepared, AUDIENCE, claims);
        sign(&prepared, &key, &request).map_err(|e| e.to_string())
    };
    let err =
        sign_as(json!({ "email": "judge@court.example", "email_verified": false })).unwrap_err();
    assert!(
        err.contains("has not verified the email address 'judge@court.example'"),
        "{err}"
    );
    let err = sign_as(json!({})).unwrap_err();
    assert!(err.contains("gave no email address"), "{err}");

    let signed =
        sign_as(json!({ "email": "someone@example.com", "email_verified": true })).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_eq!(report.signatures[0].idp_email, "someone@example.com");
}

/// A Microsoft work account whose email the tenant did not verify cannot sign at all, and one
/// whose domain the tenant verified (`xms_edov`) can.
#[test]
fn a_work_account_needs_a_tenant_verified_email() {
    const TENANT: &str = "11111111-2222-3333-4444-555555555555";
    const TEMPLATE: &str = "https://login.microsoftonline.com/{tenantid}/v2.0";
    let issuer = format!("https://login.microsoftonline.com/{TENANT}/v2.0");
    let pdf = container::make_sample_pdf("Contract");
    let (pk, req) = prepare_request(
        &pdf,
        vec![SignerSpec {
            id: "s1".into(),
            name: "Anyone at work".into(),
            handle: String::new(),
            role: String::new(),
            order: 1,
            identity_policy: IdentityPolicy {
                allowed_issuers: vec![TEMPLATE.into()],
                ..Default::default()
            },
        }],
        vec![],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let attempt = |extra: serde_json::Value| {
        let key = KeyPair::generate();
        let now = now_unix();
        let mut claims = json!({
            "iss": issuer, "tid": TENANT, "sub": "oid-1", "aud": AUDIENCE,
            "iat": now - 5, "exp": now + 3600,
            "email": "alice@victim.example",
            "nonce": compute_nonce(&key.public_sec1(), &sha256_hex(&prepared)),
        });
        for (claim, value) in extra.as_object().unwrap() {
            claims[claim] = value.clone();
        }
        let request = SignRequest {
            id_token: shared_es256().mint(claims),
            idp_jwk: jwk_json(),
            audience: AUDIENCE.into(),
            allowed_issuers: vec![TEMPLATE.into()],
            ..Default::default()
        };
        sign(&prepared, &key, &request)
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    let err = attempt(json!({})).unwrap_err();
    assert!(err.contains("has not verified the email address"), "{err}");
    attempt(json!({ "xms_edov": true })).expect("a tenant-verified domain is accepted");
}

/// A modified signing client can record its own verified identity in the envelope and still
/// write somebody else's name in its signature box. The verifier redraws the box from the
/// verified identity and compares.
#[test]
fn a_signature_box_showing_another_name_fails_verification() {
    let pdf = container::make_sample_pdf("Lease");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();

    let redrawn = |change: &dyn Fn(&mut signpdf_core::SignOptions<'_>)| {
        let (k, r) = signer_request("alice@example.com", &prepared, "");
        let signed =
            signpdf_core::workflow::testing::sign_redrawn(&prepared, &k, &r, change).unwrap();
        verify(&signed, &trust()).unwrap()
    };

    // Untouched, the document verifies.
    assert!(redrawn(&|_| {}).valid);

    // Another person's email, a friendlier time, a grander provider: each is caught.
    type Change<'a> = &'a dyn Fn(&mut signpdf_core::SignatureCaption);
    let cases: [(&str, Change<'_>); 3] = [
        ("name", &|c| c.signer_name = "bob@example.com".into()),
        ("time", &|c| c.signed_at = "2020-01-01 00:00 UTC".into()),
        ("provider", &|c| c.issuer = "government-id".into()),
    ];
    for (what, change) in cases {
        let report = redrawn(&|opts| change(opts.appearance.caption.as_mut().unwrap()));
        assert!(!report.valid, "{what}");
        assert!(
            report
                .messages
                .iter()
                .any(|m| m.contains("signature box does not show what the engine draws")),
            "{what}: {:?}",
            report.messages
        );
    }

    // A box where the slot has none (an invisible signature made visible elsewhere).
    let report = redrawn(&|opts| opts.appearance.rect = Some([300.0, 300.0, 500.0, 340.0]));
    assert!(!report.valid);
}
