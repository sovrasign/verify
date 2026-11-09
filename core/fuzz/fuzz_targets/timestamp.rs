//! RFC 3161 response/token parsing and TSA signature checks, and the long-term validation material
//! read from a document's DSS (OCSP responses, CRLs, certificates): must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use signpdf_core::{ltv, timestamp};

fuzz_target!(|data: &[u8]| {
    let digest = [0u8; 32];
    let _ = timestamp::parse_response(data, &digest);
    let _ = timestamp::verify_token(data, &digest);
    let _ = timestamp::verify_tsa_signature(data, &[], 0);
    let _ = timestamp::token_certificates(data);
    let _ = timestamp::token_imprint(data);
    let _ = ltv::is_ocsp_response(data);
    let _ = ltv::is_crl(data);
    let _ = ltv::is_certificate(data);
    let _ = ltv::check_ocsp(data, data, data);
    let _ = ltv::check_crl(data, data, data);
    let _ = ltv::ocsp_urls(data);
    let _ = ltv::crl_urls(data);
    let _ = ltv::assess_chain(
        &[data.to_vec(), data.to_vec()],
        &[],
        &[data.to_vec()],
        &[data.to_vec()],
        0,
    );
});
