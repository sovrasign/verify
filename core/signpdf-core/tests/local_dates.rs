//! Dates in date fields: stored as `YYYY-MM-DD`, drawn in the format the preparer sealed in the
//! field, and, when the engine fills them, the signer's **local** date (the device clock moved by
//! the UTC offset the host reports), never the UTC date that is a day off near midnight for
//! signers far from UTC. A *date signed* field takes no value from the signer, and the verifier
//! checks it against the signing time and the offset recorded in the signature record.

mod common;

use common::*;
use signpdf_core::dates::{self, DateFormat};
use signpdf_core::workflow::testing::sign_malicious;
use signpdf_core::{
    container, prepare, read_envelope, sign, verify, Field, FieldType, SignPdfError, SigningOrder,
    VerificationReport,
};

/// A one-signer document for Alice with a signature field and `dates`.
fn prepared_with(dates: Vec<Field>) -> Vec<u8> {
    let pdf = container::make_sample_pdf("Local dates");
    let mut fields = vec![sig_field("sig", "s1", 0)];
    fields.extend(dates);
    let (key, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        fields,
        SigningOrder::Sequential,
    );
    prepare(&pdf, &req, &key).unwrap()
}

/// A *date signed* field at height `y`.
fn date_signed(id: &str, y: f64) -> Field {
    Field {
        signing_date: true,
        ..field(id, "s1", FieldType::Date, 0, y)
    }
}

/// A date field the signer picks, drawn in `format`.
fn date_in(id: &str, y: f64, format: Option<DateFormat>) -> Field {
    Field {
        date_format: format,
        ..field(id, "s1", FieldType::Date, 0, y)
    }
}

/// Alice signs `pdf` with `values` at UTC offset `offset` (minutes).
fn alice_signs(
    pdf: &[u8],
    values: &[(&str, &str)],
    offset: Option<i32>,
) -> signpdf_core::Result<Vec<u8>> {
    let (key, mut req) = signer_request("alice@example.com", pdf, "s1");
    req.field_values = values
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    req.utc_offset_minutes = offset;
    sign(pdf, &key, &req)
}

fn value_of(pdf: &[u8], id: &str) -> Option<String> {
    read_envelope(pdf)
        .unwrap()
        .fields
        .into_iter()
        .find(|f| f.id == id)
        .and_then(|f| f.value)
}

/// The `/Contents` of the text annotations drawn on the page.
fn drawn_texts(pdf: &[u8]) -> Vec<String> {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    doc.objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .filter(|d| matches!(d.get(b"Subtype"), Ok(lopdf::Object::Name(n)) if n == b"FreeText"))
        .filter_map(|d| match d.get(b"Contents") {
            Ok(lopdf::Object::String(s, _)) => Some(String::from_utf8_lossy(s).to_string()),
            _ => None,
        })
        .collect()
}

fn assert_valid(report: &VerificationReport) {
    assert!(report.valid, "{:?}", report.messages);
}

fn assert_invalid_with(report: &VerificationReport, needle: &str) {
    assert!(!report.integrity_ok, "expected a failure about {needle}");
    assert!(
        report.messages.iter().any(|m| m.contains(needle)),
        "no message about {needle}: {:?}",
        report.messages
    );
}

#[test]
fn a_date_signed_field_holds_the_signers_local_date() {
    let prepared = prepared_with(vec![date_signed("signed-on", 300.0)]);
    // UTC+14:00 and UTC-12:00 are 26 hours apart: at any instant their dates differ, and at
    // least one of them differs from the UTC date.
    let mut seen = Vec::new();
    for (offset, written) in [(14 * 60, "+14:00"), (-12 * 60, "-12:00")] {
        let signed = alice_signs(&prepared, &[], Some(offset)).unwrap();
        let env = read_envelope(&signed).unwrap();
        let rec = &env.signatures[0];
        assert_eq!(rec.utc_offset.as_deref(), Some(written));
        let local = dates::local_date(&rec.signed_at, offset).unwrap();
        assert_eq!(
            value_of(&signed, "signed-on").as_deref(),
            Some(local.as_str())
        );

        let report = verify(&signed, &trust()).unwrap();
        assert_valid(&report);
        let status = &report.signatures[0];
        assert_eq!(status.utc_offset, written);
        assert_eq!(
            status.local_signed_at,
            dates::local_time(&rec.signed_at, offset).unwrap()
        );
        assert!(status.local_signed_at.ends_with(written));
        seen.push(local);
    }
    assert_ne!(seen[0], seen[1], "the two ends of the offsets in use");
}

#[test]
fn without_an_offset_the_date_is_the_utc_date() {
    let prepared = prepared_with(vec![
        date_signed("signed-on", 300.0),
        date_in("d", 360.0, None),
    ]);
    let signed = alice_signs(&prepared, &[], None).unwrap();
    let env = read_envelope(&signed).unwrap();
    let rec = &env.signatures[0];
    assert_eq!(rec.utc_offset, None);
    let utc = &rec.signed_at[..10];
    assert_eq!(value_of(&signed, "signed-on").as_deref(), Some(utc));
    // An empty date the signer may pick gets the signing date too.
    assert_eq!(value_of(&signed, "d").as_deref(), Some(utc));
    let report = verify(&signed, &trust()).unwrap();
    assert_valid(&report);
    assert!(report.signatures[0].utc_offset.is_empty());
    assert!(report.signatures[0].local_signed_at.is_empty());
}

#[test]
fn an_empty_date_gets_the_local_date_too() {
    let prepared = prepared_with(vec![date_in("d", 300.0, None)]);
    let signed = alice_signs(&prepared, &[("d", "")], Some(-9 * 60 - 30)).unwrap();
    let rec = &read_envelope(&signed).unwrap().signatures[0];
    assert_eq!(rec.utc_offset.as_deref(), Some("-09:30"));
    assert_eq!(
        value_of(&signed, "d"),
        dates::local_date(&rec.signed_at, -570)
    );
    assert_valid(&verify(&signed, &trust()).unwrap());
}

#[test]
fn a_date_signed_field_takes_no_value_from_the_signer() {
    let prepared = prepared_with(vec![date_signed("signed-on", 300.0)]);
    match alice_signs(&prepared, &[("signed-on", "2026-01-01")], Some(60)) {
        Err(SignPdfError::Workflow(m)) => assert!(m.contains("takes no value"), "{m}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_picked_date_is_stored_as_iso_and_drawn_in_the_sealed_format() {
    let ids: Vec<String> = (0..DateFormat::ALL.len())
        .map(|i| format!("d{i}"))
        .collect();
    let fields = DateFormat::ALL
        .iter()
        .zip(&ids)
        .enumerate()
        .map(|(i, (f, id))| date_in(id, 200.0 + 50.0 * i as f64, Some(*f)))
        .collect();
    let prepared = prepared_with(fields);
    let values: Vec<(&str, &str)> = ids.iter().map(|id| (id.as_str(), "2026-01-09")).collect();
    let signed = alice_signs(&prepared, &values, Some(120)).unwrap();
    assert_valid(&verify(&signed, &trust()).unwrap());

    for id in &ids {
        assert_eq!(value_of(&signed, id).as_deref(), Some("2026-01-09"));
    }
    let mut drawn = drawn_texts(&signed);
    drawn.sort();
    let mut expected: Vec<String> = [
        "2026-01-09",
        "09/01/2026",
        "01/09/2026",
        "09.01.2026",
        "09-01-2026",
        "2026/01/09",
        "2026.01.09",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    expected.sort();
    assert_eq!(drawn, expected);
}

#[test]
fn a_picked_date_must_be_written_yyyy_mm_dd() {
    let prepared = prepared_with(vec![date_in(
        "d",
        300.0,
        Some(DateFormat::DayMonthYearSlash),
    )]);
    for bad in ["09/01/2026", "2026-02-30", "tomorrow", "2026-1-9"] {
        match alice_signs(&prepared, &[("d", bad)], None) {
            Err(SignPdfError::Workflow(m)) => assert!(m.contains("YYYY-MM-DD"), "{bad}: {m}"),
            other => panic!("{bad}: expected a refusal, got {other:?}"),
        }
    }
    // Surrounding spaces are not part of the date.
    let signed = alice_signs(&prepared, &[("d", " 2026-01-09 ")], None).unwrap();
    assert_eq!(value_of(&signed, "d").as_deref(), Some("2026-01-09"));
    assert_eq!(drawn_texts(&signed), ["09/01/2026"]);
}

#[test]
fn offsets_outside_the_ones_in_use_are_refused() {
    let prepared = prepared_with(vec![date_signed("signed-on", 300.0)]);
    for offset in [14 * 60 + 1, -12 * 60 - 1, i32::MAX, i32::MIN] {
        match alice_signs(&prepared, &[], Some(offset)) {
            Err(SignPdfError::Workflow(m)) => assert!(m.contains("UTC offset"), "{m}"),
            other => panic!("{offset}: expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn prepare_keeps_date_terms_on_date_fields() {
    let pdf = container::make_sample_pdf("Date terms");
    for bad in [
        Field {
            date_format: Some(DateFormat::Iso),
            ..field("t", "s1", FieldType::Text, 0, 300.0)
        },
        Field {
            signing_date: true,
            ..field("t", "s1", FieldType::Text, 0, 300.0)
        },
    ] {
        let (key, req) = prepare_request(
            &pdf,
            vec![spec("s1", "Alice", "alice@example.com", 1)],
            vec![bad],
            SigningOrder::Sequential,
        );
        let err = prepare(&pdf, &req, &key).unwrap_err().to_string();
        assert!(err.contains("only date fields"), "{err}");
    }
}

#[test]
fn date_terms_are_part_of_the_prepared_terms() {
    let prepared = prepared_with(vec![date_in("d", 300.0, Some(DateFormat::Iso))]);
    // The terms are written as given; an unset format and a false flag are not written.
    let raw = signpdf_core::pades::read_attachment(&prepared, "signpdf-envelope.json").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let d = json["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "d")
        .unwrap();
    assert_eq!(d["date_format"], "YYYY-MM-DD");
    assert!(d.get("signing_date").is_none(), "{d}");

    let tampers: [&dyn Fn(&mut signpdf_core::Envelope); 2] = [
        &|env| env.fields[1].date_format = Some(DateFormat::MonthDayYearSlash),
        &|env| env.fields[1].signing_date = true,
    ];
    for tamper in tampers {
        let (key, req) = signer_request("alice@example.com", &prepared, "s1");
        let signed = sign_malicious(&prepared, &key, &req, false, tamper).unwrap();
        assert_invalid_with(&verify(&signed, &trust()).unwrap(), "prepared terms");
    }
}

#[test]
fn a_date_signed_field_with_another_date_fails_verification() {
    let prepared = prepared_with(vec![date_signed("signed-on", 300.0)]);
    let (key, mut req) = signer_request("alice@example.com", &prepared, "s1");
    req.utc_offset_minutes = Some(14 * 60);
    // A modified client records the date a day earlier than the engine filled in.
    let signed = sign_malicious(&prepared, &key, &req, false, &|env| {
        let f = env.fields.iter_mut().find(|f| f.id == "signed-on").unwrap();
        let d = dates::parse_iso_date(f.value.as_deref().unwrap()).unwrap();
        f.value = Some(dates::iso_date(d.previous_day().unwrap()));
    })
    .unwrap();
    assert_invalid_with(
        &verify(&signed, &trust()).unwrap(),
        "date-signed field 'signed-on'",
    );
}

#[test]
fn a_rewritten_utc_offset_fails_verification() {
    let prepared = prepared_with(vec![date_signed("signed-on", 300.0)]);
    // An offset 26 hours away can never give the same date.
    for (forged, needle) in [
        ("-12:00", "date-signed field 'signed-on'"),
        ("+14:30", "UTC offset"),
        ("Z", "UTC offset"),
    ] {
        let (key, mut req) = signer_request("alice@example.com", &prepared, "s1");
        req.utc_offset_minutes = Some(14 * 60);
        let signed = sign_malicious(&prepared, &key, &req, false, &|env| {
            env.signatures[0].utc_offset = Some(forged.to_string());
        })
        .unwrap();
        assert_invalid_with(&verify(&signed, &trust()).unwrap(), needle);
    }
}

#[test]
fn a_date_that_is_not_a_date_fails_verification() {
    let prepared = prepared_with(vec![date_in("d", 300.0, None)]);
    let (key, req) = signer_request("alice@example.com", &prepared, "s1");
    let signed = sign_malicious(&prepared, &key, &req, false, &|env| {
        env.fields[1].value = Some("31/12/2026".into());
    })
    .unwrap();
    assert_invalid_with(
        &verify(&signed, &trust()).unwrap(),
        "not a date written YYYY-MM-DD",
    );
}

#[test]
fn a_decline_records_the_offset_and_fills_no_date() {
    let prepared = prepared_with(vec![date_signed("signed-on", 300.0)]);
    let (key, mut req) = signer_request("alice@example.com", &prepared, "s1");
    req.decline = true;
    req.utc_offset_minutes = Some(330);
    let declined = sign(&prepared, &key, &req).unwrap();
    assert_eq!(value_of(&declined, "signed-on"), None);
    let report = verify(&declined, &trust()).unwrap();
    assert_valid(&report);
    assert_eq!(report.signatures[0].utc_offset, "+05:30");
}
