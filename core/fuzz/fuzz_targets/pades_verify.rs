//! PAdES signature parsing (ByteRange / Contents / CMS) and revision auditing: must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = signpdf_core::pades_verify(data);
    // Audit the data against each of its own prefixes ending at an %%EOF marker.
    let mut start = 0;
    while let Some(pos) = data[start..].windows(5).position(|w| w == b"%%EOF") {
        let end = start + pos + 5;
        let _ = signpdf_core::audit_increment(&data[..end], data);
        start = end;
    }
});
