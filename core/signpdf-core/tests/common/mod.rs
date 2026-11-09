//! Shared helpers for the integration tests: a pinned test identity provider, request builders,
//! and a trust store that pins exactly that provider's key.
#![allow(dead_code)]

use signpdf_core::crypto::{sha256_hex, KeyPair};
use signpdf_core::oidc::{compute_nonce, testing::shared_es256, testing::TestIssuer};
use signpdf_core::workflow::{PrepareRequest, SignRequest, SignerSpec};
use signpdf_core::{
    Field, FieldType, IdentityPolicy, Level, Policy, Rect, SigningOrder, TrustStore,
};

pub const ISSUER: &str = "https://issuer.test";
pub const AUDIENCE: &str = "signpdf-test";

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Mint an ID token for `email` carrying `nonce` with `issuer`, returning `(id_token, jwk_json)`.
pub fn mint_with(issuer: &TestIssuer, email: &str, nonce: &str) -> (String, String) {
    mint_named(issuer, email, email, nonce)
}

/// [`mint_with`], with a display `name` of its own instead of the email.
pub fn mint_named(issuer: &TestIssuer, name: &str, email: &str, nonce: &str) -> (String, String) {
    let now = now_unix();
    let claims = serde_json::json!({
        "iss": ISSUER,
        "sub": format!("user|{email}"),
        "aud": AUDIENCE,
        "iat": now - 5,
        "exp": now + 3600,
        "email": email,
        "email_verified": true,
        "name": name,
        "nonce": nonce,
    });
    (
        issuer.mint(claims),
        serde_json::to_string(&issuer.jwk()).unwrap(),
    )
}

/// Mint with the shared (pinned) test issuer.
pub fn mint(email: &str, nonce: &str) -> (String, String) {
    mint_with(shared_es256(), email, nonce)
}

/// A trust store that pins the shared test issuer's key for the test application (and nothing
/// else).
pub fn trust() -> TrustStore {
    let mut t = TrustStore::empty();
    t.add_jwks(ISSUER, &shared_es256().jwks());
    t.add_audience(ISSUER, AUDIENCE);
    t
}

pub fn consumer_policy(email: &str) -> IdentityPolicy {
    IdentityPolicy {
        allowed_issuers: vec![ISSUER.to_string()],
        required_email: Some(email.to_string()),
        ..Default::default()
    }
}

pub fn level_policy(email: &str, level: Level) -> IdentityPolicy {
    IdentityPolicy {
        min_level: level,
        ..consumer_policy(email)
    }
}

pub fn field(id: &str, signer: &str, ty: FieldType, page: u32, y: f64) -> Field {
    Field {
        id: id.to_string(),
        field_type: ty,
        page,
        rect: Rect {
            x: 72.0,
            y,
            w: 200.0,
            h: 40.0,
        },
        assigned_signer: signer.to_string(),
        required: true,
        value: None,
        label: None,
        group: None,
        options: None,
        date_format: None,
        signing_date: false,
        number_format: None,
        value_format: None,
        length: None,
        check_message: None,
        formula: None,
    }
}

pub fn sig_field(id: &str, signer: &str, page: u32) -> Field {
    field(id, signer, FieldType::Signature, page, 120.0)
}

/// A checkbox with the caption drawn beside it.
pub fn checkbox(id: &str, signer: &str, y: f64, caption: &str) -> Field {
    Field {
        label: Some(caption.to_string()),
        ..field(id, signer, FieldType::Checkbox, 0, y)
    }
}

/// One option of radio group `group`.
pub fn radio(id: &str, signer: &str, group: &str, caption: &str, y: f64) -> Field {
    Field {
        label: Some(caption.to_string()),
        group: Some(group.to_string()),
        ..field(id, signer, FieldType::Radio, 0, y)
    }
}

/// A dropdown offering `options`.
pub fn dropdown(id: &str, signer: &str, y: f64, options: &[&str]) -> Field {
    Field {
        options: Some(options.iter().map(|o| o.to_string()).collect()),
        ..field(id, signer, FieldType::Dropdown, 0, y)
    }
}

pub fn spec(id: &str, name: &str, email: &str, order: u32) -> SignerSpec {
    SignerSpec {
        id: id.into(),
        name: name.into(),
        handle: email.into(),
        role: "Party".into(),
        order,
        identity_policy: consumer_policy(email),
    }
}

/// A prepare request for `signers`/`fields`, with the preparer token bound to a fresh key.
pub fn prepare_request(
    pdf: &[u8],
    signers: Vec<SignerSpec>,
    fields: Vec<Field>,
    order: SigningOrder,
) -> (KeyPair, PrepareRequest) {
    let key = KeyPair::generate();
    let (id_token, idp_jwk) = mint(
        "preparer@example.com",
        &compute_nonce(&key.public_sec1(), &sha256_hex(pdf)),
    );
    let req = PrepareRequest {
        title: "Mutual NDA".to_string(),
        signers,
        fields,
        policy: Policy {
            signing_order: order,
            allowed_signature_types: vec!["PAdES".into()],
            expiry: None,
            ..Default::default()
        },
        id_token,
        idp_jwk,
        audience: AUDIENCE.to_string(),
        allowed_issuers: vec![ISSUER.to_string()],
        service_link: None,
        documents: Vec::new(),
        verify_at: None,
    };
    (key, req)
}

/// The standard two-signer sequential NDA request.
pub fn two_signer_request(pdf: &[u8]) -> (KeyPair, PrepareRequest) {
    prepare_request(
        pdf,
        vec![
            spec("s1", "Alice", "alice@example.com", 1),
            spec("s2", "Bob", "bob@example.com", 2),
        ],
        vec![sig_field("f1", "s1", 0), sig_field("f2", "s2", 0)],
        SigningOrder::Sequential,
    )
}

/// An ephemeral signer key plus a sign request for `email` bound to `pdf`.
pub fn signer_request(email: &str, pdf: &[u8], signer_id: &str) -> (KeyPair, SignRequest) {
    signer_request_with(shared_es256(), email, pdf, signer_id)
}

pub fn signer_request_with(
    issuer: &TestIssuer,
    email: &str,
    pdf: &[u8],
    signer_id: &str,
) -> (KeyPair, SignRequest) {
    signer_request_named(issuer, email, email, pdf, signer_id)
}

/// [`signer_request_with`] for a signer whose provider reports the display `name`.
pub fn signer_request_named(
    issuer: &TestIssuer,
    name: &str,
    email: &str,
    pdf: &[u8],
    signer_id: &str,
) -> (KeyPair, SignRequest) {
    let key = KeyPair::generate();
    let (id_token, idp_jwk) = mint_named(
        issuer,
        name,
        email,
        &compute_nonce(&key.public_sec1(), &sha256_hex(pdf)),
    );
    let req = SignRequest {
        signer_id: signer_id.into(),
        id_token,
        idp_jwk,
        audience: AUDIENCE.to_string(),
        allowed_issuers: vec![ISSUER.to_string()],
        ..Default::default()
    };
    (key, req)
}

/// Append a raw incremental update that redefines object `id` with `body` (an attacker's edit).
pub fn append_object_override(pdf: &[u8], id: u32, body: &str) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    let prev = {
        let pos = pdf.windows(9).rposition(|w| w == b"startxref").unwrap();
        let tail = std::str::from_utf8(&pdf[pos + 9..]).unwrap();
        tail.split_whitespace().next().unwrap().to_string()
    };
    let mut out = pdf.to_vec();
    let off = out.len();
    out.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
    let xref = out.len();
    out.extend_from_slice(
        format!(
            "xref\n{id} 1\n{off:010} 00000 n \ntrailer\n<< /Size {} /Root {} 0 R /Prev {prev} >>\nstartxref\n{xref}\n%%EOF\n",
            doc.max_id + 1,
            root.0
        )
        .as_bytes(),
    );
    out
}
