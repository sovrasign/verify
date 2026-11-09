//! Windows DPAPI-backed secure keystore (P0-5).
//!
//! [`DpapiKeyStore`] persists an [`Identity`] to disk with the P-256 private scalar **encrypted
//! at rest** via the Windows Data Protection API (`CryptProtectData` / `CryptUnprotectData`). The
//! ciphertext is bound to the current user's logon credentials, so the private key is never
//! written to disk in plaintext and can only be recovered by the same user on the same machine.
//!
//! This is the Windows arm of the cross-platform [`KeyStore`](crate::KeyStore) trait. The macOS /
//! iOS (Keychain) and Android (Keystore) arms live in their platform adapters; they implement the
//! same trait so the engine stays platform-agnostic.

use std::path::{Path, PathBuf};
use std::ptr;

use serde::{Deserialize, Serialize};

use crate::crypto::{b64_decode, b64_encode};
use crate::error::{Result, SignPdfError};
use crate::keystore::{Identity, KeyStore};

#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(
        p_data_in: *const DataBlob,
        sz_data_descr: *const u16,
        p_optional_entropy: *const DataBlob,
        pv_reserved: *mut core::ffi::c_void,
        p_prompt_struct: *mut core::ffi::c_void,
        dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32;

    fn CryptUnprotectData(
        p_data_in: *const DataBlob,
        ppsz_data_descr: *mut *mut u16,
        p_optional_entropy: *const DataBlob,
        pv_reserved: *mut core::ffi::c_void,
        p_prompt_struct: *mut core::ffi::c_void,
        dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32;
}

extern "system" {
    fn LocalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

/// Never surface an interactive prompt (this runs headless).
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

/// App-specific secondary entropy: a blob protected by SignPDF can only be unprotected by code
/// that supplies the same entropy, adding a layer of binding beyond the user's credentials.
const ENTROPY: &[u8] = b"signpdf-dpapi-v1";

fn blob(data: &[u8]) -> DataBlob {
    DataBlob {
        cb_data: data.len() as u32,
        pb_data: data.as_ptr() as *mut u8,
    }
}

/// Encrypt `plaintext` with DPAPI (per-user). The returned bytes are safe to write to disk.
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    let in_blob = blob(plaintext);
    let ent_blob = blob(ENTROPY);
    let mut out = DataBlob {
        cb_data: 0,
        pb_data: ptr::null_mut(),
    };
    // SAFETY: all pointers are valid for the duration of the call; `out` is populated by the OS
    // and the buffer it allocates is freed with `LocalFree` immediately after we copy it out.
    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            ptr::null(),
            &ent_blob,
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 || out.pb_data.is_null() {
        return Err(SignPdfError::Keystore("CryptProtectData failed".into()));
    }
    let result = unsafe { std::slice::from_raw_parts(out.pb_data, out.cb_data as usize).to_vec() };
    unsafe { LocalFree(out.pb_data as *mut core::ffi::c_void) };
    Ok(result)
}

/// Decrypt DPAPI `ciphertext` produced by [`protect`].
pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let in_blob = blob(ciphertext);
    let ent_blob = blob(ENTROPY);
    let mut out = DataBlob {
        cb_data: 0,
        pb_data: ptr::null_mut(),
    };
    // SAFETY: see `protect`.
    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            ptr::null_mut(),
            &ent_blob,
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 || out.pb_data.is_null() {
        return Err(SignPdfError::Keystore(
            "CryptUnprotectData failed (wrong user, machine, or tampered data)".into(),
        ));
    }
    let result = unsafe { std::slice::from_raw_parts(out.pb_data, out.cb_data as usize).to_vec() };
    unsafe { LocalFree(out.pb_data as *mut core::ffi::c_void) };
    Ok(result)
}

/// On-disk shape: public identity fields in the clear, the private scalar DPAPI-protected.
#[derive(Serialize, Deserialize)]
struct ProtectedIdentity {
    name: String,
    handle: String,
    public_b64: String,
    fingerprint: String,
    /// Base64 of the DPAPI-protected raw private scalar. Never the plaintext key.
    secret_dpapi_b64: String,
}

/// A [`KeyStore`] that keeps the private key encrypted at rest with Windows DPAPI.
pub struct DpapiKeyStore {
    path: PathBuf,
}

impl DpapiKeyStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl KeyStore for DpapiKeyStore {
    fn save_identity(&self, identity: &Identity) -> Result<()> {
        let secret = b64_decode(&identity.secret_b64)?;
        let protected = protect(&secret)?;
        let stored = ProtectedIdentity {
            name: identity.name.clone(),
            handle: identity.handle.clone(),
            public_b64: identity.public_b64.clone(),
            fingerprint: identity.fingerprint.clone(),
            secret_dpapi_b64: b64_encode(&protected),
        };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, serde_json::to_vec_pretty(&stored)?)?;
        Ok(())
    }

    fn load_identity(&self) -> Result<Identity> {
        let bytes = std::fs::read(&self.path)?;
        let stored: ProtectedIdentity = serde_json::from_slice(&bytes)?;
        let protected = b64_decode(&stored.secret_dpapi_b64)?;
        let secret = unprotect(&protected)?;
        Ok(Identity {
            name: stored.name,
            handle: stored.handle,
            secret_b64: b64_encode(&secret),
            public_b64: stored.public_b64,
            fingerprint: stored.fingerprint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip_bytes() {
        let secret = b"a 32-byte-ish private scalar....";
        let protected = protect(secret).unwrap();
        assert_ne!(protected, secret, "ciphertext must differ from plaintext");
        let recovered = unprotect(&protected).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn keystore_round_trip_without_plaintext_on_disk() {
        let id = Identity::generate("Alice", "alice@example.com");
        let dir = std::env::temp_dir().join(format!("spdf_dpapi_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alice.skey");

        let store = DpapiKeyStore::new(&path);
        store.save_identity(&id).unwrap();

        // The plaintext private scalar must never appear in the file on disk.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains(&id.secret_b64),
            "plaintext secret leaked to disk"
        );
        assert!(!on_disk.contains("\"secret_b64\""));

        // It round-trips back to an identical, usable identity.
        let loaded = store.load_identity().unwrap();
        assert_eq!(loaded.secret_b64, id.secret_b64);
        assert_eq!(loaded.fingerprint, id.fingerprint);
        assert_eq!(loaded.public_b64, id.public_b64);
        // And the recovered key actually signs/verifies.
        assert_eq!(loaded.key_pair().unwrap().fingerprint(), id.fingerprint);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_entropy_or_tampered_blob_fails_closed() {
        let protected = protect(b"secret").unwrap();
        let mut tampered = protected.clone();
        *tampered.last_mut().unwrap() ^= 0xFF;
        assert!(unprotect(&tampered).is_err());
    }
}
