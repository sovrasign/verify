//! Cryptographic services for the SignPDF engine.
//!
//! v1 uses NIST P-256 ECDSA (SHA-256) — a curve/algorithm pair supported by the PAdES
//! ecosystem and by Adobe Acrobat — implemented in pure Rust (no OpenSSL/C toolchain).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::error::{Result, SignPdfError};

/// Algorithm identifier recorded in signature records.
pub const ALGORITHM: &str = "ECDSA_P256_SHA256";

/// SHA-256 over `data`, hex-encoded (hashed in chunks: [`crate::digest::sha256`]).
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(crate::digest::sha256(data))
}

/// The OS CSPRNG, as the infallible RNG that key generation takes. Like the rand_core 0.6
/// `OsRng` it replaces, it panics if the OS cannot provide randomness.
pub(crate) fn os_rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}

/// A fresh P-256 signing key from the OS CSPRNG.
pub(crate) fn generate_signing_key() -> SigningKey {
    use p256::elliptic_curve::Generate;
    SigningKey::generate_from_rng(&mut os_rng())
}

/// Fill `buf` from the OS CSPRNG (panics if the OS cannot provide randomness).
pub(crate) fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS random number generator failed");
}

/// A random lowercase-hex identifier (128 bits).
pub fn random_id() -> String {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes);
    hex::encode(bytes)
}

/// Fingerprint of a base64-encoded SEC1 public key (hex SHA-256 of the raw key bytes).
pub fn fingerprint_of_public(public_b64: &str) -> Result<String> {
    Ok(sha256_hex(&b64_decode(public_b64)?))
}

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>> {
    B64.decode(s)
        .map_err(|e| SignPdfError::Encoding(e.to_string()))
}

/// Standard-alphabet base64 encode (public helper for hosts and tests).
pub fn b64_encode_pub(bytes: &[u8]) -> String {
    b64_encode(bytes)
}

/// Standard-alphabet base64 decode (public helper for hosts and tests).
pub fn b64_decode_pub(s: &str) -> Result<Vec<u8>> {
    b64_decode(s)
}

/// A P-256 signing key pair plus the convenience accessors the engine needs.
pub struct KeyPair {
    signing: SigningKey,
}

impl KeyPair {
    /// Generate a fresh key pair using the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            signing: generate_signing_key(),
        }
    }

    /// Reconstruct a key pair from a base64-encoded 32-byte private scalar.
    pub fn from_secret_b64(secret_b64: &str) -> Result<Self> {
        let bytes = b64_decode(secret_b64)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignPdfError::Crypto("private key must be 32 bytes".into()))?;
        let field = p256::FieldBytes::from(arr);
        let signing =
            SigningKey::from_bytes(&field).map_err(|e| SignPdfError::Crypto(e.to_string()))?;
        Ok(Self { signing })
    }

    /// Base64 of the 32-byte private scalar (store this in a secure keystore).
    pub fn secret_b64(&self) -> String {
        let scalar: [u8; 32] = self.signing.to_bytes().into();
        b64_encode(&scalar)
    }

    /// Base64 of the uncompressed SEC1 public key.
    pub fn public_b64(&self) -> String {
        b64_encode(&self.public_sec1())
    }

    /// Raw uncompressed SEC1 public key bytes (`0x04 ‖ x ‖ y`), the form hashed by the
    /// OIDC key/document binding [`crate::oidc::compute_nonce`].
    pub fn public_sec1(&self) -> Vec<u8> {
        let vk: &VerifyingKey = self.signing.verifying_key();
        vk.to_sec1_point(false).as_bytes().to_vec()
    }

    /// Hex SHA-256 fingerprint of the public key (links a PAdES signature to its envelope
    /// record; its first 8 hex digits are the human-comparable verification code).
    pub fn fingerprint(&self) -> String {
        sha256_hex(&self.public_sec1())
    }

    /// Sign `payload`, returning a base64 DER ECDSA signature.
    pub fn sign(&self, payload: &[u8]) -> String {
        let sig: Signature = self.signing.sign(payload);
        b64_encode(sig.to_der().as_bytes())
    }

    /// The raw P-256 signing key, for the PAdES CMS / X.509 builders.
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

/// Verify a base64 DER ECDSA signature over `payload` against a base64 SEC1 public key.
pub fn verify(public_b64: &str, payload: &[u8], signature_b64: &str) -> Result<()> {
    let pub_bytes = b64_decode(public_b64)?;
    let vk = VerifyingKey::from_sec1_bytes(&pub_bytes)
        .map_err(|e| SignPdfError::Crypto(e.to_string()))?;
    let der = b64_decode(signature_b64)?;
    let sig = Signature::from_der(&der).map_err(|e| SignPdfError::Crypto(e.to_string()))?;
    vk.verify(payload, &sig)
        .map_err(|_| SignPdfError::Verification("signature does not verify".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = KeyPair::generate();
        let msg = b"hello signpdf";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public_b64(), msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails() {
        let kp = KeyPair::generate();
        let sig = kp.sign(b"original");
        assert!(verify(&kp.public_b64(), b"tampered", &sig).is_err());
    }

    #[test]
    fn secret_roundtrip_preserves_identity() {
        let kp = KeyPair::generate();
        let restored = KeyPair::from_secret_b64(&kp.secret_b64()).unwrap();
        assert_eq!(kp.public_b64(), restored.public_b64());
        assert_eq!(kp.fingerprint(), restored.fingerprint());
    }

    #[test]
    fn fingerprint_matches_public_key() {
        let kp = KeyPair::generate();
        assert_eq!(
            kp.fingerprint(),
            fingerprint_of_public(&kp.public_b64()).unwrap()
        );
    }
}
