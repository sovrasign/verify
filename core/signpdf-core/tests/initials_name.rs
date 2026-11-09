//! Initials from the signer's name (envelope schema version 9, rule `name-v1`): the engine stamps
//! the letters of the name the preparer gave the slot in the signer's further initials fields,
//! names the rule in the envelope, and the verifier derives the same letters again
//! (`spec/envelope-format.md` §4.6, `src/initials.rs`).

mod common;

use common::*;
use signpdf_core::initials::InitialsRule;
use signpdf_core::oidc::testing::shared_es256;
use signpdf_core::workflow::testing::sign_malicious;
use signpdf_core::{container, prepare, read_envelope, sign, verify, FieldType, SigningOrder};

/// A one-signer document whose slot is named `name` (address `email`), with a signature field and
/// two initials fields, prepared and signed by that signer.
fn signed_by(name: &str, email: &str) -> Vec<u8> {
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
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request(email, &prepared, "");
    sign(&prepared, &k, &r).unwrap()
}

fn initials_of(pdf: &[u8]) -> Vec<Option<String>> {
    let env = read_envelope(pdf).unwrap();
    ["ini1", "ini2"]
        .iter()
        .map(|id| {
            env.fields
                .iter()
                .find(|f| f.id == *id)
                .unwrap()
                .value
                .clone()
        })
        .collect()
}

#[test]
fn a_prepared_envelope_names_the_name_rule() {
    let pdf = container::make_sample_pdf("Rule");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Felix Fairfax", "ffairfax@example.com", 1)],
        vec![sig_field("sig", "s1", 0)],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let env = read_envelope(&prepared).unwrap();
    assert_eq!(env.schema_version, 9);
    assert_eq!(env.initials_rule, Some(InitialsRule::NameV1));
}

#[test]
fn initials_come_from_the_slot_name_and_verify() {
    // The address alone would give "F"; the name gives "FF".
    let signed = signed_by("Felix Fairfax", "ffairfax@example.com");
    assert_eq!(
        initials_of(&signed),
        vec![Some("FF".into()), Some("FF".into())]
    );
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
}

#[test]
fn a_name_the_stamp_font_cannot_draw_falls_back_to_the_address() {
    let signed = signed_by("Иван Петров", "ivan.petrov@example.com");
    assert_eq!(
        initials_of(&signed),
        vec![Some("IP".into()), Some("IP".into())]
    );
    assert!(verify(&signed, &trust()).unwrap().valid);
    // A Latin letter the font lacks is drawn as its base letter.
    let signed = signed_by("Łukasz Nowak", "lukasz@example.com");
    assert_eq!(
        initials_of(&signed),
        vec![Some("LN".into()), Some("LN".into())]
    );
    assert!(verify(&signed, &trust()).unwrap().valid);
}

#[test]
fn the_provider_s_profile_name_does_not_choose_the_letters() {
    // The token's `name` is a profile name the account holder types: the slot's name decides.
    let pdf = container::make_sample_pdf("Profile name");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice Martin", "alice@example.com", 1)],
        vec![
            sig_field("sig", "s1", 0),
            field("ini", "s1", FieldType::Initials, 0, 200.0),
        ],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request_named(
        shared_es256(),
        "Chief Executive",
        "alice@example.com",
        &prepared,
        "",
    );
    let signed = sign(&prepared, &k, &r).unwrap();
    let env = read_envelope(&signed).unwrap();
    let ini = env.fields.iter().find(|f| f.id == "ini").unwrap();
    assert_eq!(ini.value.as_deref(), Some("AM"));
    assert!(verify(&signed, &trust()).unwrap().valid);
}

#[test]
fn other_letters_in_an_initials_stamp_are_rejected() {
    let pdf = container::make_sample_pdf("Forged initials");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Felix Fairfax", "ffairfax@example.com", 1)],
        vec![
            sig_field("sig", "s1", 0),
            field("ini", "s1", FieldType::Initials, 0, 200.0),
        ],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    // The letters of the address (the rule of versions 3 to 8), and letters of the signer's own
    // choosing, are both refused under `name-v1`.
    for letters in ["F", "XY"] {
        let (k, r) = signer_request("ffairfax@example.com", &prepared, "");
        let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
            env.fields.iter_mut().find(|f| f.id == "ini").unwrap().value = Some(letters.into());
        })
        .unwrap();
        let report = verify(&signed, &trust()).unwrap();
        assert!(!report.valid, "{letters}");
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code.as_str() == "stamp_mismatch"),
            "{letters}: {:?}",
            report.messages
        );
    }
}

#[test]
fn a_signer_cannot_change_the_rule_or_the_slot_name() {
    let pdf = container::make_sample_pdf("Terms");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Felix Fairfax", "ffairfax@example.com", 1)],
        vec![
            sig_field("sig", "s1", 0),
            field("ini", "s1", FieldType::Initials, 0, 200.0),
        ],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("ffairfax@example.com", &prepared, "");
    let renamed = sign_malicious(&prepared, &k, &r, false, &|env| {
        env.signers[0].name = "Xavier Young".into();
        env.fields.iter_mut().find(|f| f.id == "ini").unwrap().value = Some("XY".into());
    })
    .unwrap();
    let report = verify(&renamed, &trust()).unwrap();
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code.as_str() == "terms_changed"),
        "{:?}",
        report.messages
    );
}
