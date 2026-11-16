//! Envelope schema version 10: the word and colour of the document-ID stamp, chosen by the host
//! that prepares a document. The verifier redraws the stamp from the envelope; the word also
//! names the product in the preparer's signature reason, the signers' one-time certificates and,
//! when the host asks, the certificate of completion. Documents of earlier versions (the corpus
//! in `tests/corpus/`) keep their "SignPDF Document" yellow stamp and verify unchanged.

mod common;

use common::*;
use signpdf_core::workflow::testing::sign_malicious;
use signpdf_core::{
    completion_certificate, completion_certificate_named, container, prepare, read_envelope, sign,
    verify, IdStamp, SigningOrder, StampColor, SCHEMA_VERSION,
};

/// A one-signer document for Alice with a signature field and the stamp `stamp`.
fn prepared_with(stamp: Option<IdStamp>) -> signpdf_core::Result<Vec<u8>> {
    let pdf = container::make_sample_pdf("Version 10");
    let (key, mut req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![sig_field("sig", "s1", 0)],
        SigningOrder::Sequential,
    );
    req.verify_at = Some("verify.example.com".into());
    req.stamp = stamp;
    prepare(&pdf, &req, &key)
}

fn green(word: &str) -> Option<IdStamp> {
    Some(IdStamp {
        word: word.into(),
        color: StampColor::Green,
    })
}

fn alice_signs(pdf: &[u8]) -> Vec<u8> {
    let (key, req) = signer_request("alice@example.com", pdf, "s1");
    sign(pdf, &key, &req).unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// `text` as the hex digits a signature's `/Contents` holds (either case).
fn in_hex(hay: &[u8], text: &str) -> bool {
    let lower: String = text.bytes().map(|b| format!("{b:02x}")).collect();
    contains(hay, lower.as_bytes()) || contains(hay, lower.to_uppercase().as_bytes())
}

#[test]
fn a_chosen_word_and_colour_are_drawn_signed_and_verified() {
    let prepared = prepared_with(green("Example")).unwrap();
    let env = read_envelope(&prepared).unwrap();
    assert_eq!(env.schema_version, SCHEMA_VERSION);
    assert_eq!(env.stamp, green("Example"));
    let id = env.envelope_id.clone();
    assert!(contains(&prepared, format!("(Example {id})").as_bytes()));
    assert!(
        contains(&prepared, b"0.89 0.96 0.9 rg"),
        "the box is not green"
    );
    assert!(!contains(&prepared, b"0.96 0.96 0.86 rg"));
    assert!(!contains(&prepared, b"SignPDF Document"));
    assert!(contains(&prepared, b"/T (Example document ID)"));
    assert!(contains(
        &prepared,
        br"/Reason (Prepared for signing \(Example\))"
    ));
    assert!(in_hex(&prepared, "Example Self-Signed"));

    let signed = alice_signs(&prepared);
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert!(
        !in_hex(&signed, "SignPDF Self-Signed"),
        "a signer certificate names SignPDF"
    );

    // The certificate of completion names the product the host asks for.
    let named = completion_certificate_named(&signed, &trust(), "Example Verify").unwrap();
    assert!(contains(
        &named,
        b"Example Verify Certificate of Completion"
    ));
    assert!(!contains(&named, b"SignPDF"));
    let plain = completion_certificate(&signed, &trust()).unwrap();
    assert!(contains(&plain, b"SignPDF Certificate of Completion"));
    for bad in ["", " Example", "Example\n", "Ex\u{e9}mple", &"x".repeat(41)] {
        assert!(
            completion_certificate_named(&signed, &trust(), bad).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn without_a_choice_the_stamp_is_the_legacy_yellow_one() {
    let prepared = prepared_with(None).unwrap();
    let env = read_envelope(&prepared).unwrap();
    assert_eq!(env.stamp, None);
    assert!(contains(
        &prepared,
        format!("(SignPDF Document {})", env.envelope_id).as_bytes()
    ));
    assert!(contains(&prepared, b"0.96 0.96 0.86 rg"));
    assert!(contains(&prepared, b"/T (SignPDF Document ID)"));
    assert!(contains(
        &prepared,
        br"/Reason (Prepared for signing \(SignPDF\))"
    ));
    let signed = alice_signs(&prepared);
    assert!(in_hex(&signed, "SignPDF Self-Signed"));
    assert!(verify(&signed, &trust()).unwrap().valid);

    // A yellow stamp with a chosen word is a version-10 stamp too.
    let yellow = prepared_with(Some(IdStamp {
        word: "Example".into(),
        color: StampColor::Yellow,
    }))
    .unwrap();
    assert!(contains(&yellow, b"0.96 0.96 0.86 rg"));
    assert!(verify(&alice_signs(&yellow), &trust()).unwrap().valid);
}

#[test]
fn stamp_words_are_short_plain_words() {
    for good in [
        "Example",
        "Example 2",
        "ABC Signing Co",
        "x",
        &"w".repeat(24),
    ] {
        prepared_with(green(good)).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for bad in [
        "",
        " Example",
        "Example ",
        "Two  spaces",
        "Exa-mple",
        "Ex\u{e9}mple",
        "Example)",
        "Line\nbreak",
        &"w".repeat(25),
    ] {
        let err = prepared_with(green(bad)).unwrap_err().to_string();
        assert!(err.contains("stamp word"), "{bad:?}: {err}");
    }
}

#[test]
fn a_signer_cannot_change_the_stamp() {
    let prepared = prepared_with(green("Example")).unwrap();
    for change in [
        green("Other"),
        Some(IdStamp {
            word: "Example".into(),
            color: StampColor::Yellow,
        }),
        None,
    ] {
        let (key, req) = signer_request("alice@example.com", &prepared, "s1");
        let signed = sign_malicious(&prepared, &key, &req, false, &|env| {
            env.stamp = change.clone();
        })
        .unwrap();
        let report = verify(&signed, &trust()).unwrap();
        assert!(!report.integrity_ok, "{change:?}");
        assert!(
            report.findings.iter().any(|f| f.code == "terms_changed"),
            "{change:?}: {report:#?}"
        );
    }
}
