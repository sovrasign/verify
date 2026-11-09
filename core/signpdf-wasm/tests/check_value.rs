//! `signpdf_check_value`: a page's instant check of a signer's entry gives the engine's answer
//! (envelope schema version 8), in the verify-only module as in the signer's.

use signpdf_wasm::{
    signpdf_check_value, signpdf_result_len, signpdf_result_ptr, ERR_DECODE, ERR_WORKFLOW, OK,
};

/// Run the export and return its status and result text.
fn check(field: &str, value: &str) -> (i32, String) {
    // SAFETY: both slices are live for the call.
    let status =
        unsafe { signpdf_check_value(field.as_ptr(), field.len(), value.as_ptr(), value.len()) };
    // SAFETY: the export just set the result buffer, which lives until the next call.
    let result =
        unsafe { std::slice::from_raw_parts(signpdf_result_ptr(), signpdf_result_len()).to_vec() };
    (status, String::from_utf8(result).unwrap())
}

fn json(field: &str, value: &str) -> serde_json::Value {
    let (status, text) = check(field, value);
    assert_eq!(status, OK, "{text}");
    serde_json::from_str(&text).unwrap()
}

#[test]
fn accepted_values_come_back_canonical_with_their_drawing() {
    for (field, value, canonical, display) in [
        (
            r#"{"field_type": "text", "value_format": {"kind": "email"}}"#,
            " Alice@Example.COM ",
            "Alice@example.com",
            "Alice@example.com",
        ),
        (
            r#"{"field_type": "text", "value_format": {"kind": "us_ssn"}}"#,
            "123456789",
            "123-45-6789",
            "•••-••-6789",
        ),
        (
            r#"{"field_type": "text", "value_format": {"kind": "amount", "currency": "EUR"}}"#,
            "1250.5",
            "1250.50",
            "EUR 1250.50",
        ),
        (
            r#"{"field_type": "text", "value_format": {"kind": "pattern", "pattern": "PO-\\d{4}"}}"#,
            "PO-2026",
            "PO-2026",
            "PO-2026",
        ),
        (
            r#"{"field_type": "number", "number_format": {"decimals": 2, "style": "1 234,5", "currency": "EUR"}}"#,
            "12500",
            "12500.00",
            "EUR 12 500,00",
        ),
        // A field without rules keeps the entry as typed.
        (
            r#"{"field_type": "text"}"#,
            " as typed ",
            " as typed ",
            " as typed ",
        ),
        // An empty entry is no answer.
        (
            r#"{"field_type": "text", "value_format": {"kind": "iban"}}"#,
            "  ",
            "",
            "",
        ),
    ] {
        let v = json(field, value);
        assert_eq!(v["ok"], true, "{field} {value}: {v}");
        assert_eq!(v["canonical"], canonical, "{field}");
        assert_eq!(v["display"], display, "{field}");
    }
}

#[test]
fn refused_values_give_the_stable_code_and_the_owner_message() {
    let v = json(
        r#"{"field_type": "text", "value_format": {"kind": "postal_code", "country": "FR"}, "check_message": "Five digits, as on your letters."}"#,
        "7500",
    );
    assert_eq!(v["ok"], false);
    assert_eq!(v["error_code"], "invalid_postal_code");
    assert_eq!(v["check_message"], "Five digits, as on your letters.");

    let v = json(r#"{"field_type": "multiline", "length": {"min": 3}}"#, "ab");
    assert_eq!(v["error_code"], "too_short");
    assert!(v.get("check_message").is_none());

    let v = json(
        r#"{"field_type": "text", "value_format": {"kind": "pattern", "pattern": "[A-Z]+"}}"#,
        "abc",
    );
    assert_eq!(v["error_code"], "pattern_mismatch");

    // A whole field of the envelope works as well as its rules alone.
    let v = json(
        r#"{"id": "f1", "field_type": "text", "page": 0, "rect": {"x": 1, "y": 1, "w": 9, "h": 9},
            "assigned_signer": "s1", "required": true, "value_format": {"kind": "us_ein"}}"#,
        "123-456789",
    );
    assert_eq!(v["error_code"], "invalid_us_ein");
}

#[test]
fn rules_the_engine_would_refuse_are_an_error() {
    for field in [
        r#"{"field_type": "text", "value_format": {"kind": "amount"}}"#,
        r#"{"field_type": "text", "value_format": {"kind": "pattern", "pattern": "(a)\\1"}}"#,
        r#"{"field_type": "text", "length": {"min": 4, "max": 2}}"#,
    ] {
        let (status, text) = check(field, "x");
        assert_eq!(status, ERR_WORKFLOW, "{field}: {text}");
    }
    for field in [
        "not json",
        r#"{"value_format": {"kind": "email"}}"#,
        r#"{"field_type": "text", "value_format": {"kind": "ssn"}}"#,
    ] {
        let (status, text) = check(field, "x");
        assert_eq!(status, ERR_DECODE, "{field}: {text}");
    }
    let field = r#"{"field_type": "text"}"#;
    // SAFETY: both slices are live for the call.
    let status = unsafe { signpdf_check_value(field.as_ptr(), field.len(), [0xFFu8].as_ptr(), 1) };
    assert_eq!(status, ERR_DECODE);
}
