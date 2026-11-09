//! The cross-reference reader (`xref::read_increments`, `xref::viewer_xref` and the object-header
//! checks) on untrusted bytes: must never panic. The `verify` target reaches it too, but only
//! behind a parseable document; this one feeds it directly.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    signpdf_core::fuzz_xref(data);
});
