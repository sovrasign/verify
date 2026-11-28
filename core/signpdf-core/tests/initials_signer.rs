//! Initials the signer chooses (envelope schema version 12, rule `signer-v1`): the signer's
//! revision keeps 1 to 3 letters in their own signature record, the engine stamps them in their
//! further initials fields, and the verifier checks every stamp against that record
//! (`spec/envelope-format.md` §4.6, `src/initials.rs`).

mod common;

use common::*;
use signpdf_core::initials::InitialsRule;
use signpdf_core::workflow::testing::sign_malicious;
use signpdf_core::{
    container, prepare, read_envelope, sign, verify, FieldType, SigningOrder, VerificationReport,
};

/// A document for one signer named `name` (address `email`) with a signature field and two
/// initials fields, prepared by this build.
fn prepared_for(name: &str, email: &str) -> Vec<u8> {
    let pdf = container::make_sample_pdf("Initial every page");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", name, email, 1)],
        vec![
            sig_field("sig", "s1", 0),
            field("ini1", "s1", FieldType::Initials, 0, 200.0),
            field("ini2", "s1", FieldType::Initials, 0, 260.0),
        ],
        SigningOrder::Sequential,
    );
    prepare(&pdf, &req, &pk).unwrap()
}

/// `prepared` signed by `email` with the initials they chose (`None`: the default).
fn sign_with_initials(prepared: &[u8], email: &str, initials: Option<&str>) -> Vec<u8> {
    let (k, mut r) = signer_request(email, prepared, "");
    r.initials = initials.map(str::to_string);
    sign(prepared, &k, &r).unwrap()
}

/// The stamps of `ini1` and `ini2`, and what the last record keeps.
fn stamps_and_record(pdf: &[u8]) -> (Vec<Option<String>>, Option<String>) {
    let env = read_envelope(pdf).unwrap();
    let stamps = ["ini1", "ini2"]
        .iter()
        .map(|id| {
            env.fields
                .iter()
                .find(|f| f.id == *id)
                .unwrap()
                .value
                .clone()
        })
        .collect();
    (stamps, env.signatures.last().unwrap().initials.clone())
}

fn has_code(report: &VerificationReport, code: &str) -> bool {
    report.findings.iter().any(|f| f.code.as_str() == code)
}

#[test]
fn a_prepared_envelope_lets_its_signers_choose() {
    let prepared = prepared_for("Felix Fairfax", "ffairfax@example.com");
    let env = read_envelope(&prepared).unwrap();
    assert_eq!(env.schema_version, 12);
    assert_eq!(signpdf_core::SCHEMA_VERSION, 12);
    assert_eq!(env.initials_rule, Some(InitialsRule::SignerV1));
    assert!(verify(&prepared, &trust()).unwrap().valid);
}

#[test]
fn the_chosen_letters_are_recorded_stamped_and_verified() {
    let prepared = prepared_for("Ludwig van Beethoven", "ludwig@example.com");
    for letters in ["LvB", "L", "ÉØŒ", "WWW"] {
        let signed = sign_with_initials(&prepared, "ludwig@example.com", Some(letters));
        let (stamps, record) = stamps_and_record(&signed);
        assert_eq!(stamps, vec![Some(letters.into()), Some(letters.into())]);
        assert_eq!(record.as_deref(), Some(letters));
        let report = verify(&signed, &trust()).unwrap();
        assert!(report.valid, "{letters}: {:?}", report.messages);
        assert_eq!(report.signatures[0].initials, letters);
    }
}

#[test]
fn without_a_choice_the_letters_of_the_name_are_recorded() {
    let prepared = prepared_for("Felix Fairfax", "ffairfax@example.com");
    let signed = sign_with_initials(&prepared, "ffairfax@example.com", None);
    let (stamps, record) = stamps_and_record(&signed);
    assert_eq!(stamps, vec![Some("FF".into()), Some("FF".into())]);
    assert_eq!(record.as_deref(), Some("FF"));
    assert!(verify(&signed, &trust()).unwrap().valid);
}

#[test]
fn a_name_without_drawable_letters_needs_a_choice() {
    let prepared = prepared_for("Иван Петров", "1234@example.com");
    let (k, r) = signer_request("1234@example.com", &prepared, "");
    let err = sign(&prepared, &k, &r).unwrap_err().to_string();
    assert!(err.contains("initials"), "{err}");
    let signed = sign_with_initials(&prepared, "1234@example.com", Some("IP"));
    assert_eq!(stamps_and_record(&signed).1.as_deref(), Some("IP"));
    assert!(verify(&signed, &trust()).unwrap().valid);
}

#[test]
fn letters_outside_the_rule_are_refused_at_signing() {
    let prepared = prepared_for("Felix Fairfax", "ffairfax@example.com");
    for letters in [
        "",
        "ABCD",
        "A B",
        "A1",
        "A.",
        "Ł",
        "Ж",
        "E\u{301}",
        "A\u{200B}",
        "ª",
    ] {
        let (k, mut r) = signer_request("ffairfax@example.com", &prepared, "");
        r.initials = Some(letters.into());
        let err = sign(&prepared, &k, &r).unwrap_err().to_string();
        assert!(err.contains("initials"), "{letters:?}: {err}");
    }
}

#[test]
fn nothing_is_recorded_when_nothing_is_stamped() {
    // A signer whose only initials field is their primary one (the signature box), and a
    // decline, keep no letters, whatever the host sends.
    let pdf = container::make_sample_pdf("Box only");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Felix Fairfax", "ffairfax@example.com", 1)],
        vec![field("ini", "s1", FieldType::Initials, 0, 200.0)],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let signed = sign_with_initials(&prepared, "ffairfax@example.com", Some("XYZ"));
    let env = read_envelope(&signed).unwrap();
    assert_eq!(env.signatures[0].initials, None);
    assert!(verify(&signed, &trust()).unwrap().valid);

    let prepared = prepared_for("Felix Fairfax", "ffairfax@example.com");
    let (k, mut r) = signer_request("ffairfax@example.com", &prepared, "");
    r.initials = Some("FXF".into());
    r.decline = true;
    let declined = sign(&prepared, &k, &r).unwrap();
    let (stamps, record) = stamps_and_record(&declined);
    assert_eq!((stamps, record), (vec![None, None], None));
    assert!(verify(&declined, &trust()).unwrap().valid);
}

#[test]
fn a_stamp_that_differs_from_the_record_is_rejected() {
    let prepared = prepared_for("Felix Fairfax", "ffairfax@example.com");
    let (k, mut r) = signer_request("ffairfax@example.com", &prepared, "");
    r.initials = Some("FXF".into());
    let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
        env.fields
            .iter_mut()
            .find(|f| f.id == "ini2")
            .unwrap()
            .value = Some("OK".into());
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid);
    assert!(has_code(&report, "stamp_mismatch"), "{:?}", report.messages);
}

#[test]
fn a_record_outside_the_rule_is_rejected() {
    // A modified signing client writes letters the rule refuses (stamped consistently), drops
    // them, or records them where nothing is stamped.
    let prepared = prepared_for("Felix Fairfax", "ffairfax@example.com");
    let cases: [(&str, Option<&str>); 4] = [
        ("APPROVED", Some("APPROVED")),
        ("N/A", Some("N/A")),
        ("A\u{202E}B", Some("A\u{202E}B")),
        ("", None),
    ];
    for (stamp, record) in cases {
        let (k, r) = signer_request("ffairfax@example.com", &prepared, "");
        let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
            for f in env.fields.iter_mut().filter(|f| f.id.starts_with("ini")) {
                f.value = Some(stamp.into());
            }
            env.signatures.last_mut().unwrap().initials = record.map(str::to_string);
        })
        .unwrap();
        let report = verify(&signed, &trust()).unwrap();
        assert!(!report.valid, "{stamp:?}");
        assert!(
            has_code(&report, "stamp_mismatch"),
            "{stamp:?}: {:?}",
            report.messages
        );
    }

    let pdf = container::make_sample_pdf("Box only");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Felix Fairfax", "ffairfax@example.com", 1)],
        vec![sig_field("sig", "s1", 0)],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("ffairfax@example.com", &prepared, "");
    let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
        env.signatures.last_mut().unwrap().initials = Some("FF".into());
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid);
    assert!(has_code(&report, "stamp_mismatch"), "{:?}", report.messages);
}

#[test]
fn a_later_signer_cannot_change_an_earlier_signer_s_letters() {
    let pdf = container::make_sample_pdf("Two signers");
    let (pk, req) = prepare_request(
        &pdf,
        vec![
            spec("s1", "Alice Example", "alice@example.com", 1),
            spec("s2", "Bob Builder", "bob@example.com", 2),
        ],
        vec![
            sig_field("a-sig", "s1", 0),
            field("a-ini", "s1", FieldType::Initials, 0, 200.0),
            sig_field("b-sig", "s2", 0),
            field("b-ini", "s2", FieldType::Initials, 0, 300.0),
        ],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let after_alice = sign_with_initials(&prepared, "alice@example.com", Some("AmE"));
    // Bob's client rewrites Alice's record and stamp.
    let (k, mut r) = signer_request("bob@example.com", &after_alice, "");
    r.initials = Some("BB".into());
    let signed = sign_malicious(&after_alice, &k, &r, false, &|env| {
        env.signatures[0].initials = Some("XXX".into());
        env.fields
            .iter_mut()
            .find(|f| f.id == "a-ini")
            .unwrap()
            .value = Some("XXX".into());
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid, "{:?}", report.messages);
    // Honestly, each signer's letters are their own.
    let honest = sign_with_initials(&after_alice, "bob@example.com", Some("BB"));
    let report = verify(&honest, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    let letters: Vec<&str> = report
        .signatures
        .iter()
        .map(|s| s.initials.as_str())
        .collect();
    assert_eq!(letters, ["AmE", "BB"]);
}

#[test]
fn a_signer_cannot_take_the_document_back_to_derived_letters() {
    // A signing client that rewrites the envelope as version 11 under name-v1 (so that the
    // letters would come from the slot's name) changes the preparer's terms.
    let prepared = prepared_for("Felix Fairfax", "ffairfax@example.com");
    let (k, r) = signer_request("ffairfax@example.com", &prepared, "");
    let downgraded = sign_malicious(&prepared, &k, &r, false, &|env| {
        env.schema_version = 11;
        env.initials_rule = Some(InitialsRule::NameV1);
        env.signatures.last_mut().unwrap().initials = None;
    })
    .unwrap();
    let report = verify(&downgraded, &trust()).unwrap();
    assert!(!report.valid);
    assert!(has_code(&report, "terms_changed"), "{:?}", report.messages);
}
