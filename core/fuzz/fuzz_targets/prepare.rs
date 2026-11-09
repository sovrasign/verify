//! Preparing an arbitrary source document (what an upload gives the preparer): must never panic.
//! The preparer's ID token is minted by the test issuer for the input's digest, so the input
//! reaches the PDF parsing, stamping and signing code rather than stopping at the token check.
#![no_main]
use libfuzzer_sys::fuzz_target;
use signpdf_core::crypto::{sha256_hex, KeyPair};
use signpdf_core::oidc::{compute_nonce, testing::shared_es256};
use signpdf_core::workflow::{PrepareRequest, SignerSpec};
use signpdf_core::{prepare, IdentityPolicy, Policy};

/// The device's private scalar: 32 bytes of 0x11, a valid P-256 scalar.
const DEVICE_KEY: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";

fuzz_target!(|data: &[u8]| {
    if !data.starts_with(b"%PDF-") {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // A fixed device key (not KeyPair::generate), so the token's nonce is the same for the same
    // input on every run (the signing time still varies).
    let key = KeyPair::from_secret_b64(DEVICE_KEY).unwrap();
    let issuer = shared_es256();
    let token = issuer.mint(serde_json::json!({
        "iss": "https://issuer.test",
        "sub": "user|preparer",
        "aud": "fuzz",
        "iat": now - 5,
        "exp": now + 3600,
        "email": "preparer@example.com",
        "email_verified": true,
        "nonce": compute_nonce(&key.public_sec1(), &sha256_hex(data)),
    }));
    let req = PrepareRequest {
        title: "Fuzzed".into(),
        signers: vec![SignerSpec {
            id: "s1".into(),
            name: "Signer".into(),
            handle: "signer@example.com".into(),
            role: "Party".into(),
            order: 1,
            identity_policy: IdentityPolicy::default(),
        }],
        fields: vec![],
        policy: Policy::default(),
        id_token: token,
        idp_jwk: serde_json::to_string(&issuer.jwk()).unwrap(),
        audience: "fuzz".into(),
        allowed_issuers: vec!["https://issuer.test".into()],
        service_link: None,
        documents: vec![],
        verify_at: None,
    };
    let _ = prepare(data, &req, &key);
});
