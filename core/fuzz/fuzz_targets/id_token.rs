//! ID-token (JWS) parsing and validation over arbitrary input: must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use signpdf_core::{verify_id_token, Jwk, Jwks, Validation};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Split the input into a token and a JWK document on the first newline.
    let (token, jwk) = s.split_once('\n').unwrap_or((s, "{}"));
    let keys = serde_json::from_str::<Jwk>(jwk)
        .map(|k| vec![k])
        .unwrap_or_default();
    let v = Validation::new(vec!["https://issuer.test".into()], "aud", 0);
    let _ = verify_id_token(token, &Jwks { keys }, &v);
    let _ = signpdf_core::peek_issuer(token);
});
