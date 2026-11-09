//! Envelope JSON (every schema version's decoder) over arbitrary bytes: must never panic, and
//! what it accepts must write back and read back to the same envelope.
#![no_main]
use libfuzzer_sys::fuzz_target;
use signpdf_core::schema::{decode_envelope, encode_envelope};

fuzz_target!(|data: &[u8]| {
    let Ok(env) = decode_envelope(data) else {
        return;
    };
    let bytes = encode_envelope(&env).expect("an envelope that decoded must encode");
    let back = decode_envelope(&bytes).expect("an encoded envelope must decode");
    assert_eq!(back, env, "envelope changed in a write and read");
});
