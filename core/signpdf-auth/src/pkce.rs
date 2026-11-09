//! PKCE (RFC 7636) and random-token helpers for the Authorization Code flow.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// A PKCE code verifier/challenge pair (`S256` method).
#[derive(Debug, Clone)]
pub struct Pkce {
    /// The high-entropy secret kept by the client and replayed at the token endpoint.
    pub verifier: String,
    /// `BASE64URL(SHA256(verifier))` — sent in the authorization request.
    pub challenge: String,
}

/// `len` random bytes, base64url-encoded without padding (URL-safe, unreserved characters only).
pub fn random_token(len: usize) -> String {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("OS random number generator failed");
    B64URL.encode(buf)
}

/// Generate a fresh PKCE pair. The verifier is 32 random bytes (43 base64url chars, well within
/// RFC 7636's 43–128 range); the challenge is the `S256` transform of its ASCII bytes.
pub fn generate_pkce() -> Pkce {
    let verifier = random_token(32);
    let challenge = s256_challenge(&verifier);
    Pkce {
        verifier,
        challenge,
    }
}

/// The RFC 7636 `S256` code-challenge transform: `BASE64URL(SHA256(ASCII(verifier)))`.
pub fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    B64URL.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_is_url_safe_and_long_enough() {
        let p = generate_pkce();
        assert!(p.verifier.len() >= 43, "verifier too short: {}", p.verifier);
        assert!(p.verifier.len() <= 128);
        assert!(p
            .verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')));
    }

    #[test]
    fn challenge_matches_known_rfc7636_vector() {
        // The canonical example from RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            s256_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn random_tokens_are_unique() {
        assert_ne!(random_token(16), random_token(16));
    }
}
