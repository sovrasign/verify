//! Full document verification over arbitrary bytes: must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use signpdf_core::{verify, TrustStore};

fuzz_target!(|data: &[u8]| {
    let _ = verify(data, &TrustStore::insecure_dev());
});
