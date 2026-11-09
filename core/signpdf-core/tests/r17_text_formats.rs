//! Envelope schema version 8: validation formats on text fields (email, phone, amount, postal
//! code, IBAN, US SSN and EIN, custom patterns), length rules and the owner's check message,
//! and a currency on number formats. Each is checked at preparation, at signing (the value is
//! stored canonically or refused with its stable code) and by the verifier; US identifiers are
//! drawn masked.

mod common;

use common::*;
use signpdf_core::schema::{decode_envelope, encode_envelope};
use signpdf_core::workflow::testing::sign_malicious;
use signpdf_core::{
    container, prepare, read_envelope, sign, verify, Field, FieldType, LengthRule, NumberFormat,
    NumberStyle, SigningOrder, TrustStore, ValueFormat, ValueFormatKind, VerificationReport,
    SCHEMA_VERSION,
};

/// A text field of Alice's at height `y` with `format`.
fn text(id: &str, y: f64, format: Option<ValueFormat>) -> Field {
    Field {
        value_format: format,
        label: Some(id.to_string()),
        ..field(id, "s1", FieldType::Text, 0, y)
    }
}

fn kind(kind: ValueFormatKind) -> Option<ValueFormat> {
    Some(ValueFormat::of(kind))
}

fn amount(currency: &str) -> Option<ValueFormat> {
    Some(ValueFormat {
        currency: Some(currency.into()),
        ..ValueFormat::of(ValueFormatKind::Amount)
    })
}

fn postal(country: &str) -> Option<ValueFormat> {
    Some(ValueFormat {
        country: Some(country.into()),
        ..ValueFormat::of(ValueFormatKind::PostalCode)
    })
}

fn pattern(p: &str) -> Option<ValueFormat> {
    Some(ValueFormat {
        pattern: Some(p.into()),
        ..ValueFormat::of(ValueFormatKind::Pattern)
    })
}

/// One field of every kind, plus a length rule and a currency number.
fn every_kind() -> Vec<Field> {
    vec![
        Field {
            length: Some(LengthRule {
                min: None,
                max: Some(40),
            }),
            check_message: Some("Use the address where you read your mail.".into()),
            ..text("email", 170.0, kind(ValueFormatKind::Email))
        },
        text("phone", 215.0, kind(ValueFormatKind::Phone)),
        text("deposit", 260.0, amount("EUR")),
        text("zip", 305.0, postal("GB")),
        text("iban", 350.0, kind(ValueFormatKind::Iban)),
        text("ssn", 395.0, kind(ValueFormatKind::UsSsn)),
        text("ein", 440.0, kind(ValueFormatKind::UsEin)),
        text("po", 485.0, pattern(r"PO-\d{4}-\d{3}")),
        Field {
            length: Some(LengthRule {
                min: Some(2),
                max: Some(10),
            }),
            ..text("nick", 530.0, None)
        },
        Field {
            label: Some("Fee".into()),
            number_format: Some(NumberFormat {
                decimals: 2,
                style: NumberStyle::SpaceComma,
                currency: Some("EUR".into()),
                ..Default::default()
            }),
            ..field("fee", "s1", FieldType::Number, 0, 575.0)
        },
    ]
}

/// The entries Alice types into [`every_kind`] and what the envelope stores.
const ENTRIES: &[(&str, &str, &str)] = &[
    ("email", "  Alice@Example.COM ", "Alice@example.com"),
    ("phone", "+33 6 12 34 56 78", "+33612345678"),
    ("deposit", "1250.5", "1250.50"),
    ("zip", "sw1a1aa", "SW1A 1AA"),
    (
        "iban",
        "gb82 west 1234 5698 7654 32",
        "GB82WEST12345698765432",
    ),
    ("ssn", "123456789", "123-45-6789"),
    ("ein", "12-3456789", "12-3456789"),
    ("po", "PO-2026-118", "PO-2026-118"),
    ("nick", "Ali", "Ali"),
    ("fee", "12500", "12500.00"),
];

/// A one-signer document for Alice with a signature field and `fields`.
fn prepared_with(fields: Vec<Field>) -> signpdf_core::Result<Vec<u8>> {
    let pdf = container::make_sample_pdf("Version 8");
    let mut all = vec![sig_field("sig", "s1", 0)];
    all.extend(fields);
    let (key, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        all,
        SigningOrder::Sequential,
    );
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

fn has_code(report: &VerificationReport, code: &str) -> bool {
    report.findings.iter().any(|f| f.code == code)
}

/// `s` as the engine writes a non-ASCII annotation text: UTF-16BE hex with its byte-order mark.
fn utf16_hex(s: &str) -> Vec<u8> {
    let mut out = String::from("<FEFF");
    for unit in s.encode_utf16() {
        out.push_str(&format!("{unit:04X}"));
    }
    out.push('>');
    out.into_bytes()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn entries() -> Vec<(&'static str, &'static str)> {
    ENTRIES.iter().map(|(id, typed, _)| (*id, *typed)).collect()
}

#[test]
fn every_kind_is_stored_canonically_and_verifies() {
    let prepared = prepared_with(every_kind()).unwrap();
    let env = read_envelope(&prepared).unwrap();
    // Text checks are version 8's, and every later version keeps them.
    assert_eq!(env.schema_version, SCHEMA_VERSION);
    const { assert!(SCHEMA_VERSION >= 8) };
    let signed = alice_signs(&prepared, &entries()).unwrap();
    let env = read_envelope(&signed).unwrap();
    for (id, _, stored) in ENTRIES {
        let f = env.fields.iter().find(|f| f.id == *id).unwrap();
        assert_eq!(f.value.as_deref(), Some(*stored), "{id}");
    }
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    // The envelope decodes and encodes back to the same JSON.
    let raw = serde_json::to_vec(&env).unwrap();
    assert_eq!(
        encode_envelope(&decode_envelope(&raw).unwrap()).unwrap(),
        raw
    );
}

#[test]
fn values_are_drawn_as_their_format_shows_them() {
    let prepared = prepared_with(every_kind()).unwrap();
    let signed = alice_signs(&prepared, &entries()).unwrap();
    // US identifiers masked but for their last four digits, the full value in the envelope.
    assert!(
        contains(&signed, &utf16_hex("•••-••-6789")),
        "SSN not masked"
    );
    assert!(
        contains(&signed, &utf16_hex("••-•••6789")),
        "EIN not masked"
    );
    // An IBAN in groups of four, amounts after their currency, a number in its style.
    assert!(contains(&signed, b"(GB82 WEST 1234 5698 7654 32)"));
    assert!(contains(&signed, b"(EUR 1250.50)"));
    assert!(contains(&signed, b"(EUR 12 500,00)"));
    let env = read_envelope(&signed).unwrap();
    let ssn = env.fields.iter().find(|f| f.id == "ssn").unwrap();
    assert_eq!(ssn.value.as_deref(), Some("123-45-6789"));
}

#[test]
fn values_outside_their_format_are_refused_with_their_code() {
    let prepared = prepared_with(every_kind()).unwrap();
    for (id, value, code) in [
        ("email", "alice@localhost", "invalid_email"),
        (
            "email",
            "a@example.com.very-long-domain.example.org",
            "too_long",
        ),
        ("phone", "06 12 34 56 78", "invalid_phone"),
        ("deposit", "-5", "negative_amount"),
        ("deposit", "1.001", "too_many_decimals"),
        ("zip", "SW1A", "invalid_postal_code"),
        ("iban", "GB82WEST12345698765433", "iban_checksum"),
        ("ssn", "666-12-3456", "invalid_us_ssn"),
        ("ein", "00-1234567", "invalid_us_ein"),
        ("po", "PO-26-118", "pattern_mismatch"),
        ("nick", "A", "too_short"),
        ("nick", "Alice Example", "too_long"),
        ("fee", "12.345", "too_many_decimals"),
    ] {
        let mut values = entries();
        values.retain(|(k, _)| *k != id);
        values.push((id, value));
        let err = alice_signs(&prepared, &values).unwrap_err();
        assert_eq!(err.code(), "workflow", "{id} {value}: {err}");
        let text = err.to_string();
        assert!(text.contains(&format!("({code})")), "{id} {value}: {text}");
        if id != "fee" {
            // The refusal does not repeat the value (it may be an identifier drawn masked).
            assert!(!text.contains(value), "{id}: {text}");
        }
    }
}

#[test]
fn an_optional_field_with_a_format_may_stay_empty_and_a_required_one_may_not() {
    let optional = Field {
        required: false,
        ..text("ssn", 300.0, kind(ValueFormatKind::UsSsn))
    };
    let prepared = prepared_with(vec![optional]).unwrap();
    let signed = alice_signs(&prepared, &[("ssn", "  ")]).unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);

    let prepared = prepared_with(vec![text("ssn", 300.0, kind(ValueFormatKind::UsSsn))]).unwrap();
    let err = alice_signs(&prepared, &[]).unwrap_err().to_string();
    assert!(err.contains("required field ssn"), "{err}");
}

#[test]
fn a_multiline_field_takes_a_format_and_a_length() {
    let notes = Field {
        rect: signpdf_core::Rect {
            x: 72.0,
            y: 300.0,
            w: 240.0,
            h: 60.0,
        },
        length: Some(LengthRule {
            min: None,
            max: Some(20),
        }),
        ..field("notes", "s1", FieldType::Multiline, 0, 300.0)
    };
    let prepared = prepared_with(vec![notes]).unwrap();
    let err = alice_signs(&prepared, &[("notes", "line one\nline two is long")])
        .unwrap_err()
        .to_string();
    assert!(err.contains("(too_long)"), "{err}");
    let signed = alice_signs(&prepared, &[("notes", "line one\nline two")]).unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);
}

#[test]
fn a_value_a_modified_client_did_not_check_fails_verification() {
    let prepared = prepared_with(every_kind()).unwrap();
    for (id, bad, code) in [
        // Valid but not canonical: the domain was not lowered.
        ("email", "Alice@Example.COM", "invalid_email"),
        ("ssn", "000-12-3456", "invalid_us_ssn"),
        ("po", "PO-2026-1180", "pattern_mismatch"),
        ("nick", "A", "too_short"),
    ] {
        let (key, mut req) = signer_request("alice@example.com", &prepared, "s1");
        req.field_values = entries()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let signed = sign_malicious(&prepared, &key, &req, false, &|env| {
            let f = env.fields.iter_mut().find(|f| f.id == id).unwrap();
            f.value = Some(bad.into());
        })
        .unwrap();
        let report = verify(&signed, &trust()).unwrap();
        assert!(!report.integrity_ok, "{id}");
        assert!(has_code(&report, "field_value_invalid"), "{report:#?}");
        assert!(
            report.messages.iter().any(|m| m.contains(&format!(
                "field {id} holds a value that does not have its format ({code})"
            ))),
            "{id}: {:?}",
            report.messages
        );
    }
}

#[test]
fn a_signer_cannot_change_a_format_a_length_or_the_owner_message() {
    let prepared = prepared_with(every_kind()).unwrap();
    let tampers: [&dyn Fn(&mut signpdf_core::Envelope); 4] = [
        &|env| {
            let f = env.fields.iter_mut().find(|f| f.id == "po").unwrap();
            f.value_format = pattern(r"PO-.*");
        },
        &|env| {
            let f = env.fields.iter_mut().find(|f| f.id == "nick").unwrap();
            f.length = None;
        },
        &|env| {
            let f = env.fields.iter_mut().find(|f| f.id == "email").unwrap();
            f.check_message = Some("Any address will do.".into());
        },
        &|env| {
            let f = env.fields.iter_mut().find(|f| f.id == "fee").unwrap();
            f.number_format.as_mut().unwrap().currency = Some("USD".into());
        },
    ];
    for tamper in tampers {
        let (key, mut req) = signer_request("alice@example.com", &prepared, "s1");
        req.field_values = entries()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let signed = sign_malicious(&prepared, &key, &req, false, tamper).unwrap();
        let report = verify(&signed, &trust()).unwrap();
        assert!(!report.integrity_ok);
        assert!(has_code(&report, "terms_changed"), "{report:#?}");
    }
}

#[test]
fn the_owner_message_is_sealed_but_never_decides_validity() {
    let prepared = prepared_with(every_kind()).unwrap();
    let env = read_envelope(&prepared).unwrap();
    let email = env.fields.iter().find(|f| f.id == "email").unwrap();
    assert_eq!(
        email.check_message.as_deref(),
        Some("Use the address where you read your mail.")
    );
    let signed = alice_signs(&prepared, &entries()).unwrap();
    assert!(verify(&signed, &trust()).unwrap().valid);
}

#[test]
fn prepare_refuses_bad_specs() {
    let refused = |f: Field, needle: &str| {
        let err = prepared_with(vec![f]).unwrap_err().to_string();
        assert!(err.contains(needle), "{needle}: {err}");
    };
    refused(
        text("a", 300.0, Some(ValueFormat::of(ValueFormatKind::Amount))),
        "needs a currency",
    );
    refused(text("a", 300.0, amount("EURO")), "not an ISO 4217 code");
    refused(text("a", 300.0, amount("eur")), "not an ISO 4217 code");
    refused(
        text(
            "z",
            300.0,
            Some(ValueFormat::of(ValueFormatKind::PostalCode)),
        ),
        "without its country",
    );
    refused(text("z", 300.0, postal("ZZ")), "cannot check");
    refused(
        text("p", 300.0, Some(ValueFormat::of(ValueFormatKind::Pattern))),
        "without its pattern",
    );
    refused(
        text("p", 300.0, pattern(&"a".repeat(201))),
        "longer than 200 characters",
    );
    refused(text("p", 300.0, pattern(r"(a)\1")), "back-reference");
    refused(text("p", 300.0, pattern(r"(?=a)a")), "look-around");
    refused(text("p", 300.0, pattern(r"(\d{100}){100}")), "too complex");
    refused(
        text(
            "e",
            300.0,
            Some(ValueFormat {
                currency: Some("EUR".into()),
                ..ValueFormat::of(ValueFormatKind::Email)
            }),
        ),
        "takes no currency",
    );
    refused(
        Field {
            value_format: kind(ValueFormatKind::Email),
            ..field("d", "s1", FieldType::Date, 0, 300.0)
        },
        "only text and multi-line fields",
    );
    refused(
        Field {
            length: Some(LengthRule {
                min: Some(5),
                max: Some(2),
            }),
            ..text("l", 300.0, None)
        },
        "minimum is above its maximum",
    );
    refused(
        Field {
            length: Some(LengthRule::default()),
            ..text("l", 300.0, None)
        },
        "neither a minimum nor a maximum",
    );
    refused(
        Field {
            length: Some(LengthRule {
                min: None,
                max: Some(0),
            }),
            ..text("l", 300.0, None)
        },
        "maximum is 0",
    );
    refused(
        Field {
            check_message: Some("Fill this in.".into()),
            ..text("m", 300.0, None)
        },
        "no check",
    );
    refused(
        Field {
            check_message: Some("x".repeat(201)),
            ..text("m", 300.0, kind(ValueFormatKind::Email))
        },
        "longer than 200 characters",
    );
    refused(
        Field {
            check_message: Some("line\nbreak".into()),
            ..text("m", 300.0, kind(ValueFormatKind::Email))
        },
        "control character",
    );
    refused(
        Field {
            number_format: Some(NumberFormat {
                decimals: 2,
                currency: Some("JPY".into()),
                ..Default::default()
            }),
            ..field("n", "s1", FieldType::Number, 0, 300.0)
        },
        "JPY amounts keep 0",
    );
    // A check message on a number field (which always has a number format) is accepted.
    prepared_with(vec![Field {
        check_message: Some("A whole number of euros.".into()),
        number_format: Some(NumberFormat::default()),
        ..field("n", "s1", FieldType::Number, 0, 300.0)
    }])
    .unwrap();
}

#[test]
fn the_json_contract() {
    let f = Field {
        length: Some(LengthRule {
            min: Some(2),
            max: Some(80),
        }),
        check_message: Some("Write it as on your bill.".into()),
        ..text("t", 300.0, amount("EUR"))
    };
    let json = serde_json::to_value(&f).unwrap();
    assert_eq!(
        json["value_format"],
        serde_json::json!({"kind": "amount", "currency": "EUR"})
    );
    assert_eq!(json["length"], serde_json::json!({"min": 2, "max": 80}));
    assert_eq!(json["check_message"], "Write it as on your bill.");
    for k in ValueFormatKind::ALL {
        let v = serde_json::to_value(k).unwrap();
        assert_eq!(v, k.as_str());
    }
    // A field without checks writes none of the members (version 7 JSON is unchanged).
    let plain = serde_json::to_value(text("t", 300.0, None)).unwrap();
    for member in ["value_format", "length", "check_message"] {
        assert!(plain.get(member).is_none(), "{member}");
    }
    // Unknown kinds and members are refused, not dropped.
    assert!(serde_json::from_value::<ValueFormat>(serde_json::json!({"kind": "ssn"})).is_err());
    assert!(serde_json::from_value::<ValueFormat>(
        serde_json::json!({"kind": "email", "flags": "i"})
    )
    .is_err());
    assert!(
        serde_json::from_value::<LengthRule>(serde_json::json!({"max": 3, "trim": true})).is_err()
    );
}

/// The newest version-7 corpus set: its documents verify with this build, and a version-7
/// envelope can neither claim nor be written with version-8 terms.
fn v7_set() -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/v7");
    let mut sets: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    sets.sort();
    sets.pop().unwrap()
}

#[test]
fn a_version_7_document_still_verifies() {
    let set = v7_set();
    let trust =
        TrustStore::from_json_bytes(&std::fs::read(set.join("trust.json")).unwrap()).unwrap();
    let pdf = std::fs::read(set.join("signed-final.pdf")).unwrap();
    let report = verify(&pdf, &trust).unwrap();
    assert!(report.integrity_ok, "{:?}", report.messages);
    assert_eq!(report.envelope.as_ref().unwrap().schema_version, 7);
}

#[test]
fn a_version_7_envelope_cannot_hold_version_8_terms() {
    let set = v7_set();
    let pdf = std::fs::read(set.join("signed-final.pdf")).unwrap();
    let env = read_envelope(&pdf).unwrap();
    assert_eq!(env.schema_version, 7);
    let raw = serde_json::to_value(&env).unwrap();
    for (path, value) in [
        ("value_format", serde_json::json!({"kind": "email"})),
        ("length", serde_json::json!({"max": 5})),
        ("check_message", serde_json::json!("Hello.")),
    ] {
        let mut v = raw.clone();
        v["fields"][0][path] = value;
        let err = decode_envelope(&serde_json::to_vec(&v).unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("only version 8"), "{path}: {err}");
    }
    let mut v = raw.clone();
    let fee = v["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|f| f["field_type"] == "number")
        .unwrap();
    fee["number_format"]["currency"] = serde_json::json!("EUR");
    let err = decode_envelope(&serde_json::to_vec(&v).unwrap())
        .unwrap_err()
        .to_string();
    assert!(err.contains("currency"), "{err}");

    let mut env = env;
    env.fields[0].check_message = Some("Hello.".into());
    let err = encode_envelope(&env).unwrap_err().to_string();
    assert!(err.contains("version-7 envelope cannot express"), "{err}");
}

#[test]
fn the_version_8_corpus_has_text_checks_a_masked_identifier_and_a_currency() {
    // A change to how a checked text value is stored or drawn must break a fixture, not a
    // customer's document. `signpdf demo` has Bob fill an email field (stored with its domain in
    // lower case), an EIN (drawn masked), a purchase order matching the preparer's pattern (with
    // an owner message) and a fee in euros (drawn after its code).
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/v8");
    let mut found = false;
    for set in std::fs::read_dir(dir).unwrap() {
        let set = set.unwrap().path();
        if !set.is_dir() {
            continue;
        }
        let trust =
            TrustStore::from_json_bytes(&std::fs::read(set.join("trust.json")).unwrap()).unwrap();
        let pdf = std::fs::read(set.join("signed-final.pdf")).unwrap();
        let report = verify(&pdf, &trust).unwrap();
        assert!(
            report.integrity_ok,
            "{}: {:?}",
            set.display(),
            report.messages
        );
        let env = report.envelope.as_ref().unwrap();
        let field = |id: &str| env.fields.iter().find(|f| f.id == id);
        let email = field("notice-email").expect("an email field");
        assert_eq!(email.value.as_deref(), Some("Legal@bob.example"));
        assert!(email.length.is_some());
        let ein = field("ein").expect("an EIN field");
        assert_eq!(ein.value.as_deref(), Some("12-3456789"));
        assert!(
            contains(&pdf, &utf16_hex("••-•••6789")),
            "the EIN is not masked"
        );
        let po = field("po").expect("a pattern field");
        assert!(po.check_message.is_some());
        let fee = field("fee").expect("a fee field");
        assert_eq!(
            fee.number_format.as_ref().unwrap().currency.as_deref(),
            Some("EUR")
        );
        assert!(contains(&pdf, b"(EUR 12 500,00)"));
        found = true;
    }
    assert!(found, "no version-8 corpus set");
}
