//! The optional link back to the service that sent an envelope ("open in ..."): set by the
//! preparer, kept in the envelope **outside the prepared terms**, so it never decides whether a
//! document is valid. The verifier reports the preparer's link, and only a usable one; a later
//! revision that changes it is ignored and named in a warning.

mod common;

use common::*;
use signpdf_core::workflow::testing::sign_malicious;
use signpdf_core::workflow::{check_service_link, MAX_SERVICE_LINK_LEN};
use signpdf_core::{container, prepare, read_envelope, sign, verify, VerificationReport};

const LINK: &str = "https://sign.example.com/envelopes/8f2c?from=pdf#activity";

fn prepared_with(link: Option<&str>) -> signpdf_core::Result<Vec<u8>> {
    let pdf = container::make_sample_pdf("Service link");
    let (key, mut req) = two_signer_request(&pdf);
    req.service_link = link.map(str::to_string);
    prepare(&pdf, &req, &key)
}

fn link_warnings(report: &VerificationReport) -> Vec<&String> {
    report
        .warnings
        .iter()
        .filter(|w| w.contains("service link"))
        .collect()
}

#[test]
fn the_preparers_link_is_kept_and_reported() {
    let prepared = prepared_with(Some(LINK)).unwrap();
    assert_eq!(
        read_envelope(&prepared).unwrap().service_link.as_deref(),
        Some(LINK)
    );
    let report = verify(&prepared, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_eq!(report.service_link.as_deref(), Some(LINK));

    // Signing carries it forward unchanged.
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let after_alice = sign(&prepared, &k, &r).unwrap();
    let (k, r) = signer_request("bob@example.com", &after_alice, "");
    let done = sign(&after_alice, &k, &r).unwrap();
    assert_eq!(
        read_envelope(&done).unwrap().service_link.as_deref(),
        Some(LINK)
    );
    let report = verify(&done, &trust()).unwrap();
    assert!(report.valid && report.complete, "{:?}", report.messages);
    assert_eq!(report.service_link.as_deref(), Some(LINK));
    assert!(link_warnings(&report).is_empty(), "{:?}", report.warnings);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["service_link"], LINK);
}

#[test]
fn without_a_link_nothing_is_written_or_reported() {
    let prepared = prepared_with(None).unwrap();
    let raw = signpdf_core::pades::read_attachment(&prepared, "signpdf-envelope.json").unwrap();
    assert!(!String::from_utf8(raw).unwrap().contains("service_link"));
    let report = verify(&prepared, &trust()).unwrap();
    assert_eq!(report.service_link, None);
    assert!(serde_json::to_value(&report)
        .unwrap()
        .get("service_link")
        .is_none());
}

#[test]
fn a_signer_who_changes_the_link_leaves_the_document_valid_and_the_change_ignored() {
    // The link is outside the prepared terms: changing it is not a breach of what was agreed,
    // but nobody is sent where a signer pointed it.
    let prepared = prepared_with(Some(LINK)).unwrap();
    for forged in [Some("https://phishing.example/login"), None] {
        let (k, r) = signer_request("alice@example.com", &prepared, "");
        let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
            env.service_link = forged.map(str::to_string);
        })
        .unwrap();
        let report = verify(&signed, &trust()).unwrap();
        assert!(report.valid, "{:?}", report.messages);
        assert_eq!(report.service_link.as_deref(), Some(LINK));
        let warnings = link_warnings(&report);
        assert_eq!(warnings.len(), 1, "{:?}", report.warnings);
        assert!(warnings[0].contains("signer 's1' changed"), "{warnings:?}");
    }
}

#[test]
fn a_link_a_signer_adds_is_not_reported() {
    let prepared = prepared_with(None).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
        env.service_link = Some("https://phishing.example/login".into());
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_eq!(report.service_link, None);
    assert_eq!(link_warnings(&report).len(), 1, "{:?}", report.warnings);
}

#[test]
fn prepare_refuses_a_link_that_is_not_a_plain_https_url() {
    let long = format!("https://example.com/{}", "a".repeat(MAX_SERVICE_LINK_LEN));
    for bad in [
        "http://sign.example.com/e/1",
        "HTTPS://sign.example.com/e/1",
        "javascript:alert(1)",
        "https://",
        "https:///e/1",
        "https://sign.example.com@phishing.example/e/1",
        "https://user:pass@sign.example.com/e/1",
        "https://sign.example.com:0/e",
        "https://sign.example.com:99999/e",
        "https://sign.example.com:/e",
        "https://sign..example.com/e",
        "https://-sign.example.com/e",
        "https://sign_example.com/e",
        "https://[::1]/e",
        "https://sign.example.com/e 1",
        "https://sign.example.com/e\n1",
        "https://sign.exämple.com/e",
        "https://sign.example.com/<script>",
        "https://sign.example.com\\@phishing.example",
        "",
        long.as_str(),
    ] {
        assert!(check_service_link(bad).is_err(), "{bad:?} was accepted");
        let err = prepared_with(Some(bad)).unwrap_err().to_string();
        assert!(err.contains("service link"), "{bad:?}: {err}");
    }
    for good in [
        LINK,
        "https://sign.example.com",
        "https://sign.example.com/",
        "https://127.0.0.1:8443/e/1",
        "https://xn--bcher-kva.example/e/%C3%A9?q=a&b=c",
        "https://SIGN.Example.com/e/1",
    ] {
        assert_eq!(check_service_link(good), Ok(()), "{good:?}");
        prepared_with(Some(good)).unwrap();
    }
}
