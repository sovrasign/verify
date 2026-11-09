//! Identity and keystore abstraction.
//!
//! v1 identities are self-generated P-256 key pairs. In production the private key lives
//! in the platform secure keystore (Keychain / Android Keystore / DPAPI), exposed through
//! the [`KeyStore`] trait. [`FileKeyStore`] is a development implementation that persists
//! the identity as JSON on disk; it is **not** a secure store and is intended for tests
//! and the reference CLI only.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::KeyPair;
use crate::error::Result;

/// A persisted self-signed identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    pub handle: String,
    /// Base64 of the 32-byte private scalar.
    pub secret_b64: String,
    /// Base64 SEC1 public key.
    pub public_b64: String,
    /// Hex SHA-256 fingerprint of the public key.
    pub fingerprint: String,
}

impl Identity {
    /// Create a brand-new identity with a freshly generated key pair.
    pub fn generate(name: &str, handle: &str) -> Self {
        let kp = KeyPair::generate();
        Self {
            name: name.to_string(),
            handle: handle.to_string(),
            secret_b64: kp.secret_b64(),
            public_b64: kp.public_b64(),
            fingerprint: kp.fingerprint(),
        }
    }

    /// Reconstruct the underlying key pair (loads the private scalar).
    pub fn key_pair(&self) -> Result<KeyPair> {
        KeyPair::from_secret_b64(&self.secret_b64)
    }
}

/// Storage backend for the local identity's private key material.
pub trait KeyStore {
    fn save_identity(&self, identity: &Identity) -> Result<()>;
    fn load_identity(&self) -> Result<Identity>;
}

/// Development keystore that writes the identity to a JSON file. Not secure.
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl KeyStore for FileKeyStore {
    fn save_identity(&self, identity: &Identity) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, serde_json::to_vec_pretty(identity)?)?;
        Ok(())
    }

    fn load_identity(&self) -> Result<Identity> {
        let bytes = std::fs::read(&self.path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_key_pair_roundtrip() {
        let id = Identity::generate("Alice", "alice@example.com");
        let kp = id.key_pair().unwrap();
        assert_eq!(kp.public_b64(), id.public_b64);
        assert_eq!(kp.fingerprint(), id.fingerprint);
    }
}
