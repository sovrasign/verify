//! Regression tests for the envelope and revision findings of the 2026-11-09 security review
//! (`docs/SECURITY_REVIEW_2026-11-09.md`). Each failed on the code before its fix: a modified
//! preparing or signing client wrote a document the verifier reported valid.

mod common;

use common::*;
use signpdf_core::workflow::testing::{
    added_annotation_problems, prepare_malicious, reseal_last_audit_entry, sign_malicious,
    sign_redrawn,
};
use signpdf_core::{
    container, prepare, sign, verify, Envelope, Field, FieldType, FormulaSpec, NumberFormat,
    SignerStatus, SigningOrder,
};

/// Alice's text field and signature box, then Bob's signature box.
fn with_text_field() -> Vec<u8> {
    let pdf = container::make_sample_pdf("Review");
    let (pk, req) = prepare_request(
        &pdf,
        vec![
            spec("s1", "Alice", "alice@example.com", 1),
            spec("s2", "Bob", "bob@example.com", 2),
        ],
        vec![
            sig_field("f1", "s1", 0),
            field("t1", "s1", FieldType::Text, 0, 600.0),
            field("o1", "s1", FieldType::Text, 0, 500.0),
            sig_field("f2", "s2", 0),
        ],
        SigningOrder::Sequential,
    );
    let mut req = req;
    req.fields[2].required = false;
    prepare(&pdf, &req, &pk).unwrap()
}

/// C1 (1): a signer records a field value but the page shows nothing: the envelope says one
/// thing, every viewer and later signer sees a blank field.
#[test]
fn c1_a_recorded_value_must_be_shown_on_the_page() {
    let prepared = with_text_field();
    let (k, mut r) = signer_request("alice@example.com", &prepared, "s1");
    r.field_values = vec![("t1".into(), "Net 30".into())];
    // The honest client, for reference.
    let honest = sign(&prepared, &k, &r).unwrap();
    let report = verify(&honest, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);

    let hidden = sign_redrawn(&prepared, &k, &r, &|opts| opts.field_texts.clear()).unwrap();
    let report = verify(&hidden, &trust()).unwrap();
    assert!(
        !report.valid,
        "a recorded value the page does not show was accepted"
    );
    assert!(
        report.messages.iter().any(|m| m.contains("t1")),
        "{:?}",
        report.messages
    );
}

/// C1 (2): a text annotation for a field that shows nothing (Alice's empty optional field, or
/// her signature field), with no `/Contents`: its appearance stream was never checked.
#[test]
fn c1_no_text_annotation_on_a_field_that_shows_nothing() {
    let prepared = with_text_field();
    let (k, mut r) = signer_request("alice@example.com", &prepared, "s1");
    r.field_values = vec![("t1".into(), "Net 30".into())];
    let signed = sign(&prepared, &k, &r).unwrap();
    assert!(added_annotation_problems(&prepared, &signed, &|_, _| {}).is_empty());
    for target in ["o1", "f1"] {
        let problems = added_annotation_problems(&prepared, &signed, &|env, added| {
            let shown = added
                .iter()
                .find(|a| a.subtype == "FreeText")
                .expect("the text field's annotation")
                .clone();
            let f = env.fields.iter().find(|f| f.id == target).unwrap();
            let mut forged = shown;
            forged.name = Some(format!("signpdf-field-{target}"));
            forged.rect = [
                f.rect.x as f32,
                f.rect.y as f32,
                (f.rect.x + f.rect.w) as f32,
                (f.rect.y + f.rect.h) as f32,
            ];
            forged.contents = None;
            added.push(forged);
        });
        assert!(
            !problems.is_empty(),
            "{target}: an unchecked text annotation was accepted"
        );
    }
}

/// Alice's text field, Bob's number field, and a signature box each.
fn terms_request() -> (
    Vec<u8>,
    signpdf_core::crypto::KeyPair,
    signpdf_core::PrepareRequest,
) {
    let pdf = container::make_sample_pdf("Terms");
    let (pk, req) = prepare_request(
        &pdf,
        vec![
            spec("s1", "Alice", "alice@example.com", 1),
            spec("s2", "Bob", "bob@example.com", 2),
        ],
        vec![
            sig_field("f1", "s1", 0),
            field("t1", "s1", FieldType::Text, 0, 600.0),
            Field {
                label: Some("Amount".into()),
                number_format: Some(NumberFormat {
                    decimals: 0,
                    ..Default::default()
                }),
                ..field("n2", "s2", FieldType::Number, 0, 500.0)
            },
            sig_field("f2", "s2", 0),
        ],
        SigningOrder::Sequential,
    );
    (pdf, pk, req)
}

/// C2: the verifier holds the prepared terms to the rules `prepare` enforces. A modified
/// preparing client that writes terms `prepare` refuses produces a document that does not
/// verify.
#[test]
fn c2_prepared_terms_are_checked_when_verifying() {
    let (pdf, pk, req) = terms_request();
    let honest = prepare(&pdf, &req, &pk).unwrap();
    let report = verify(&honest, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);

    type Tamper = Box<dyn Fn(&mut Envelope)>;
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "two slots with one id",
            Box::new(|env: &mut Envelope| {
                let mut ceo = env.signers[1].clone();
                ceo.id = "s1".into();
                ceo.order = 1;
                env.signers.push(ceo);
            }),
        ),
        (
            "a pre-filled field",
            Box::new(|env: &mut Envelope| env.fields[1].value = Some("Net 90".into())),
        ),
        (
            "a slot already bound to a key",
            Box::new(|env: &mut Envelope| env.signers[0].fingerprint = Some("ab".repeat(32))),
        ),
        (
            "a formula reading a later signer's field",
            Box::new(|env: &mut Envelope| {
                env.fields.push(Field {
                    label: Some("Twice".into()),
                    number_format: Some(NumberFormat {
                        decimals: 0,
                        ..Default::default()
                    }),
                    formula: Some(FormulaSpec {
                        expr: "{n2} * 2".into(),
                        map: Default::default(),
                    }),
                    ..field("x1", "s1", FieldType::Formula, 0, 400.0)
                })
            }),
        ),
        (
            "two fields with one id",
            Box::new(|env: &mut Envelope| {
                let mut copy = env.fields[1].clone();
                copy.rect.y = 300.0;
                env.fields.push(copy);
            }),
        ),
        (
            "a field of an unknown slot",
            Box::new(|env: &mut Envelope| env.fields[1].assigned_signer = "s9".into()),
        ),
        (
            "an unusable verify-at address",
            Box::new(|env: &mut Envelope| env.verify_at = Some("https://Evil.example/".into())),
        ),
        (
            "no signers",
            Box::new(|env: &mut Envelope| env.signers.clear()),
        ),
    ];
    for (name, tamper) in cases {
        let prepared = prepare_malicious(&pdf, &req, &pk, &*tamper).unwrap();
        let report = verify(&prepared, &trust()).unwrap();
        assert!(!report.valid, "{name}: the prepared terms were accepted");
    }
}

/// C2 (1), the whole attack: Alice fills two slots that share her id, the second one meant
/// for someone else at a higher assurance level, and the document reads complete.
#[test]
fn c2_one_signer_cannot_fill_two_slots_with_one_id() {
    let (pdf, pk, req) = terms_request();
    let prepared = prepare_malicious(&pdf, &req, &pk, &|env| {
        let mut ceo = env.signers[1].clone();
        ceo.id = "s1".into();
        ceo.order = 1;
        ceo.identity_policy = consumer_policy("ceo@example.com");
        env.signers.insert(1, ceo);
    })
    .unwrap();
    let (k, mut r) = signer_request("alice@example.com", &prepared, "s1");
    r.field_values = vec![("t1".into(), "Net 30".into())];
    let signed = sign_malicious(&prepared, &k, &r, true, &|env| {
        let bound = env
            .signers
            .iter()
            .find(|s| s.public_key.is_some())
            .cloned()
            .unwrap();
        for s in env.signers.iter_mut().filter(|s| s.id == "s1") {
            s.status = SignerStatus::Signed;
            s.public_key = bound.public_key.clone();
            s.fingerprint = bound.fingerprint.clone();
        }
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid, "{:?}", report.messages);
}

/// C3: the record's copy of the verified identity (`idp_email`, `idp_subject`) and the audit
/// entry's actor and details are what the verified token says, not what the signing client
/// wrote: a host or the completion certificate shows them.
#[test]
fn c3_the_recorded_identity_is_the_verified_one() {
    let prepared = with_text_field();
    let (k, mut r) = signer_request("alice@example.com", &prepared, "s1");
    r.field_values = vec![("t1".into(), "Net 30".into())];
    type Tamper = Box<dyn Fn(&mut Envelope)>;
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "idp_email",
            Box::new(|env: &mut Envelope| {
                env.signatures.last_mut().unwrap().idp_email = "ceo@victim.example".into()
            }),
        ),
        (
            "idp_subject",
            Box::new(|env: &mut Envelope| {
                env.signatures.last_mut().unwrap().idp_subject = "ceo-subject".into()
            }),
        ),
        (
            "audit actor",
            Box::new(|env: &mut Envelope| {
                env.audit_log.last_mut().unwrap().actor_name = "ceo@victim.example".into()
            }),
        ),
        (
            "audit details",
            Box::new(|env: &mut Envelope| {
                env.audit_log.last_mut().unwrap().details =
                    "ceo@victim.example signed; verified as ceo@victim.example".into()
            }),
        ),
    ];
    for (name, tamper) in cases {
        let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
            tamper(env);
            reseal_last_audit_entry(env, &k);
        })
        .unwrap();
        let report = verify(&signed, &trust()).unwrap();
        assert!(!report.valid, "{name}: a spoofed identity was accepted");
    }
    // Re-sealing alone changes nothing.
    let signed = sign_malicious(&prepared, &k, &r, false, &|env| {
        reseal_last_audit_entry(env, &k)
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
}

/// `pdf` with one increment (in SignPDF's cross-reference form) defining `objects`.
fn append_objects(pdf: &[u8], objects: &[(u32, String)]) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    let pos = pdf.windows(9).rposition(|w| w == b"startxref").unwrap();
    let prev = std::str::from_utf8(&pdf[pos + 9..])
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    let mut out = pdf.to_vec();
    let mut table = String::new();
    for (id, body) in objects {
        table.push_str(&format!(
            "{id} 1
{:010} 00000 n 
",
            out.len()
        ));
        out.extend_from_slice(
            format!(
                "{id} 0 obj
{body}
endobj
"
            )
            .as_bytes(),
        );
    }
    let xref = out.len();
    let size = objects.iter().map(|o| o.0).max().unwrap().max(doc.max_id) + 1;
    out.extend_from_slice(
        format!(
            "xref
{table}trailer
<< /Size {size} /Root {} 0 R /Prev {prev} >>
startxref
{xref}
%%EOF
",
            root.0
        )
        .as_bytes(),
    );
    out
}

/// A1 (closed as not reproducible): a page's `/Annots` rewritten as a chain of references
/// (`200 0 R` naming `201 0 R` naming the array). The review expected the audit to read it as
/// no annotations while viewers draw the one behind it; lopdf follows the chain, so the audit
/// lists the annotation (and checks it like any other). This test keeps it that way. A
/// `/Annots` that is not an array (a string, a dictionary) is ignored by viewers (pdf.js and
/// PDFium read only an array), so it shows nothing the audit misses.
#[test]
fn a1_annotations_behind_a_chain_of_references_are_audited() {
    let pdf = container::make_sample_pdf("Annots");
    let doc = lopdf::Document::load_mem(&pdf).unwrap();
    let (_, page_id) = doc.get_pages().into_iter().next().unwrap();
    let page = doc.get_object(page_id).unwrap().as_dict().unwrap();
    assert!(
        page.get(b"Annots").is_err(),
        "the sample page has no annotations"
    );
    let base = 200;
    let mut body = String::from("<<");
    for (k, v) in page.iter() {
        body.push_str(&format!(
            " /{} {}",
            String::from_utf8_lossy(k),
            pdf_value(v)
        ));
    }
    body.push_str(&format!(" /Annots {base} 0 R >>"));
    let square = "<< /Type /Annot /Subtype /Square /Rect [0 0 600 800] /C [1 0 0] /F 4 >>";
    let after = append_objects(
        &pdf,
        &[
            (page_id.0, body),
            (base, format!("{} 0 R", base + 1)),
            (base + 1, format!("[{} 0 R]", base + 2)),
            (base + 2, square.to_string()),
        ],
    );
    let audit = signpdf_core::pades::audit_increment(&pdf, &after).unwrap();
    assert_eq!(audit.added_annotations.len(), 1, "{:?}", audit.violations);
    assert_eq!(audit.added_annotations[0].subtype, "Square");
}

/// A PDF value as written in a file (enough for a page dictionary's entries).
fn pdf_value(v: &lopdf::Object) -> String {
    use lopdf::Object::*;
    match v {
        Null => "null".into(),
        Boolean(b) => b.to_string(),
        Integer(i) => i.to_string(),
        Real(r) => r.to_string(),
        Name(n) => format!("/{}", std::string::String::from_utf8_lossy(n)),
        String(s, _) => format!("({})", std::string::String::from_utf8_lossy(s)),
        Array(a) => format!(
            "[{}]",
            a.iter().map(pdf_value).collect::<Vec<_>>().join(" ")
        ),
        Dictionary(d) => format!(
            "<<{}>>",
            d.iter()
                .map(|(k, v)| format!(
                    " /{} {}",
                    std::string::String::from_utf8_lossy(k),
                    pdf_value(v)
                ))
                .collect::<std::string::String>()
        ),
        Reference(r) => format!("{} {} R", r.0, r.1),
        Stream(_) => panic!("a stream inside a page dictionary"),
    }
}
