//! Envelope schema version 7: number fields (a canonical value with the field's decimal places,
//! within its range, drawn in its sealed style), the 'verify at' address on the document-ID
//! stamp, and the stable codes of the verification findings.

mod common;

use common::*;
use signpdf_core::messages::{self, Severity};
use signpdf_core::workflow::testing::sign_malicious;
use signpdf_core::{
    container, prepare, read_envelope, sign, verify, Field, FieldType, NumberFormat, NumberStyle,
    SignPdfError, SigningOrder, VerificationReport,
};

/// A number field of Alice's at height `y`.
fn number(id: &str, y: f64, format: Option<NumberFormat>) -> Field {
    Field {
        number_format: format,
        label: Some("Amount".into()),
        ..field(id, "s1", FieldType::Number, 0, y)
    }
}

fn fee_format() -> NumberFormat {
    NumberFormat {
        decimals: 2,
        min: Some("0".into()),
        max: Some("1000000".into()),
        style: NumberStyle::SpaceComma,
        currency: None,
    }
}

/// A one-signer document for Alice with a signature field and `fields`, naming `verify_at`.
fn prepared_with(fields: Vec<Field>, verify_at: Option<&str>) -> signpdf_core::Result<Vec<u8>> {
    let pdf = container::make_sample_pdf("Version 7");
    let mut all = vec![sig_field("sig", "s1", 0)];
    all.extend(fields);
    let (key, mut req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        all,
        SigningOrder::Sequential,
    );
    req.verify_at = verify_at.map(str::to_string);
    prepare(&pdf, &req, &key)
}

fn alice_signs(pdf: &[u8], values: &[(&str, &str)]) -> signpdf_core::Result<Vec<u8>> {
    let (key, mut req) = signer_request("alice@example.com", pdf, "s1");
    req.field_values = values
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    sign(pdf, &key, &req)
}

/// Every message and warning of `report` has exactly one finding, with a catalogued code of the
/// right severity and the same text.
fn assert_findings_match(report: &VerificationReport) {
    let errors: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .map(|f| f.text.as_str())
        .collect();
    let warnings: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .map(|f| f.text.as_str())
        .collect();
    assert_eq!(errors, report.messages, "{report:#?}");
    assert_eq!(warnings, report.warnings, "{report:#?}");
    for f in &report.findings {
        let c = messages::lookup(&f.code).unwrap_or_else(|| panic!("{} is not catalogued", f.code));
        assert_eq!(c.severity, f.severity, "{}", f.code);
    }
}

fn has_code(report: &VerificationReport, code: &str) -> bool {
    report.findings.iter().any(|f| f.code == code)
}

#[test]
fn a_number_is_stored_canonically_and_drawn_in_the_sealed_style() {
    let prepared = prepared_with(vec![number("fee", 300.0, Some(fee_format()))], None).unwrap();
    assert!(read_envelope(&prepared).unwrap().schema_version >= 7);
    let signed = alice_signs(&prepared, &[("fee", "12500.5")]).unwrap();
    let env = read_envelope(&signed).unwrap();
    let fee = env.fields.iter().find(|f| f.id == "fee").unwrap();
    assert_eq!(fee.value.as_deref(), Some("12500.50"));
    // Drawn "12 500,50", whatever the signer's locale.
    assert!(
        signed.windows(9).any(|w| w == b"12 500,50"),
        "the drawn number is not in the sealed style"
    );
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_findings_match(&report);
}

#[test]
fn an_optional_number_may_stay_empty_and_a_required_one_may_not() {
    let optional = Field {
        required: false,
        ..number("fee", 300.0, Some(fee_format()))
    };
    let prepared = prepared_with(vec![optional], None).unwrap();
    let signed = alice_signs(&prepared, &[]).unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);

    let prepared = prepared_with(vec![number("fee", 300.0, Some(fee_format()))], None).unwrap();
    let err = alice_signs(&prepared, &[]).unwrap_err().to_string();
    assert!(err.contains("required field fee"), "{err}");
}

#[test]
fn values_outside_the_format_are_refused_with_their_code() {
    let prepared = prepared_with(vec![number("fee", 300.0, Some(fee_format()))], None).unwrap();
    for (value, code) in [
        ("12.345", "too_many_decimals"),
        ("-1", "below_minimum"),
        ("1000000.01", "above_maximum"),
        ("1 250,50", "invalid_number"),
        ("twelve", "invalid_number"),
    ] {
        let err = alice_signs(&prepared, &[("fee", value)]).unwrap_err();
        assert!(matches!(err, SignPdfError::Workflow(_)), "{value}: {err}");
        assert_eq!(err.code(), "workflow");
        let text = err.to_string();
        assert!(text.contains(&format!("({code})")), "{value}: {text}");
        assert!(
            text.contains("2 decimal places from 0 to 1000000"),
            "{text}"
        );
    }
}

#[test]
fn prepare_checks_number_formats() {
    let refused = |fields: Vec<Field>, needle: &str| {
        let err = prepared_with(fields, None).unwrap_err().to_string();
        assert!(err.contains(needle), "{err}");
    };
    refused(vec![number("n", 300.0, None)], "needs a number format");
    refused(
        vec![number(
            "n",
            300.0,
            Some(NumberFormat {
                decimals: 9,
                ..Default::default()
            }),
        )],
        "decimal places",
    );
    refused(
        vec![number(
            "n",
            300.0,
            Some(NumberFormat {
                min: Some("5".into()),
                max: Some("1".into()),
                ..Default::default()
            }),
        )],
        "minimum is above its maximum",
    );
    let text_with_format = Field {
        number_format: Some(fee_format()),
        ..field("t", "s1", FieldType::Text, 0, 300.0)
    };
    refused(vec![text_with_format], "only number fields");
}

#[test]
fn a_number_a_modified_client_did_not_canonicalize_fails_verification() {
    let prepared = prepared_with(vec![number("fee", 300.0, Some(fee_format()))], None).unwrap();
    let (key, mut req) = signer_request("alice@example.com", &prepared, "s1");
    req.field_values = vec![("fee".into(), "12".into())];
    let signed = sign_malicious(&prepared, &key, &req, false, &|env| {
        let f = env.fields.iter_mut().find(|f| f.id == "fee").unwrap();
        f.value = Some("12.0".into()); // one decimal place: not the field's two
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.integrity_ok);
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("number field fee holds '12.0'")),
        "{:?}",
        report.messages
    );
    assert!(has_code(&report, "field_value_invalid"), "{report:#?}");
    let f = report
        .findings
        .iter()
        .find(|f| f.code == "field_value_invalid")
        .unwrap();
    assert_eq!(f.signer.as_deref(), Some("s1"));
    assert_eq!(f.revision, Some(1));
    assert_findings_match(&report);
}

#[test]
fn the_document_id_stamp_names_the_verify_at_address() {
    let prepared = prepared_with(vec![], Some("verify.example.com")).unwrap();
    let env = read_envelope(&prepared).unwrap();
    assert_eq!(env.verify_at.as_deref(), Some("verify.example.com"));
    assert!(
        prepared
            .windows(28)
            .any(|w| w == b"Verify at verify.example.com"),
        "the stamp does not draw the address"
    );
    let signed = alice_signs(&prepared, &[]).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);

    // Without an address, the stamp is the one-line stamp of every earlier version.
    let plain = prepared_with(vec![], None).unwrap();
    assert!(!plain.windows(9).any(|w| w == b"Verify at"));
    assert!(
        verify(&alice_signs(&plain, &[]).unwrap(), &trust())
            .unwrap()
            .valid
    );
}

#[test]
fn verify_at_addresses_are_short_host_names() {
    for good in [
        "verify.example.com",
        "example.com/verify",
        "xn--bcher-kva.example/v",
    ] {
        prepared_with(vec![], Some(good)).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for bad in [
        "https://verify.example.com",
        "Verify.Example.com",
        "localhost",
        "verify .example.com",
        "example.com/Verify?x=1",
        "a-very-long-host-name-for-a-verifier.example.com",
        "",
    ] {
        let err = prepared_with(vec![], Some(bad)).unwrap_err().to_string();
        assert!(err.contains("'verify at' address"), "{bad}: {err}");
    }
}

#[test]
fn a_signer_cannot_change_the_verify_at_address() {
    let prepared = prepared_with(vec![], Some("verify.example.com")).unwrap();
    let (key, req) = signer_request("alice@example.com", &prepared, "s1");
    let signed = sign_malicious(&prepared, &key, &req, false, &|env| {
        env.verify_at = Some("evil.example.com".into());
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.integrity_ok);
    assert!(has_code(&report, "terms_changed"), "{report:#?}");
    assert_findings_match(&report);
}

#[test]
fn findings_carry_stable_codes() {
    let prepared = prepared_with(vec![], None).unwrap();
    let signed = alice_signs(&prepared, &[]).unwrap();

    // One byte changed after signing.
    let mut tampered = signed.clone();
    tampered[20] ^= 0xFF;
    let report = verify(&tampered, &trust()).unwrap();
    assert!(has_code(&report, "document_changed"), "{report:#?}");
    assert_findings_match(&report);

    // Bytes appended after the last signature.
    let mut appended = signed.clone();
    appended.extend_from_slice(b"\n% unsigned\n");
    let report = verify(&appended, &trust()).unwrap();
    assert!(has_code(&report, "unsigned_changes"), "{report:#?}");
    assert_findings_match(&report);

    // An identity provider this verifier does not trust.
    let report = verify(&signed, &signpdf_core::TrustStore::default()).unwrap();
    assert!(report.integrity_ok && !report.valid);
    assert!(has_code(&report, "identity_unknown_issuer"), "{report:#?}");
    assert!(has_code(&report, "identities_not_trusted"), "{report:#?}");
    let preparer = report
        .findings
        .iter()
        .find(|f| f.code == "identity_unknown_issuer" && f.revision == Some(0))
        .unwrap();
    assert!(
        preparer.text.starts_with("preparer identity:"),
        "{preparer:?}"
    );
    assert_findings_match(&report);

    // The JSON a host reads.
    let json = serde_json::to_value(&report).unwrap();
    let first = &json["findings"][0];
    assert!(
        first["code"].is_string() && first["severity"] == "error",
        "{first}"
    );
}
