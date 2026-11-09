//! Regression test for finding 4 of `docs/SECURITY_REVIEW_2026-10-27.md`: the field a signer's
//! revision adds to the form must be the signature widget it adds to the page.

mod common;

use common::*;
use signpdf_core::{container, pades, prepare, sign};

/// The sample document's page.
const PAGE: u32 = 3;

/// `pdf` followed by one increment holding `objects` (number, body), in the form the engine
/// writes (so only the audit's object rules can refuse it).
fn with_increment(pdf: &[u8], objects: &[(u32, String)]) -> Vec<u8> {
    let pos = pdf.windows(9).rposition(|w| w == b"startxref").unwrap();
    let prev: usize = String::from_utf8_lossy(&pdf[pos + 9..])
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut out = pdf.to_vec();
    let mut entries: Vec<(u32, usize)> = Vec::new();
    for (n, body) in objects {
        entries.push((*n, out.len()));
        out.extend_from_slice(format!("{n} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    entries.sort();
    let x = out.len();
    out.extend_from_slice(b"xref\n");
    for (n, off) in &entries {
        out.extend_from_slice(format!("{n} 1\n{off:010} 00000 n \n").as_bytes());
    }
    let size = entries.iter().map(|e| e.0).max().unwrap() + 1;
    out.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root 1 0 R /Prev {prev} >>\nstartxref\n{x}\n%%EOF\n")
            .as_bytes(),
    );
    out
}

fn refs(objs: &[lopdf::Object]) -> String {
    objs.iter()
        .map(|o| {
            let (n, g) = o.as_reference().unwrap();
            format!("{n} {g} R ")
        })
        .collect()
}

/// A revision that puts its signature widget on the page but adds another field to the form.
#[test]
fn the_new_field_must_be_the_added_signature_widget() {
    let pdf = container::make_sample_pdf("NDA");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();

    let doc = lopdf::Document::load_mem(&prepared).unwrap();
    let catalog = doc.catalog().unwrap();
    let form_id = catalog.get(b"AcroForm").unwrap().as_reference().unwrap();
    let form = doc.get_object(form_id).unwrap().as_dict().unwrap();
    let fields = form.get(b"Fields").unwrap().as_array().unwrap().clone();
    assert_eq!(
        form.len(),
        2,
        "the prepared form holds /Fields and /SigFlags only"
    );
    let page = doc.get_object((PAGE, 0)).unwrap().as_dict().unwrap();
    let annots = page.get(b"Annots").unwrap().as_array().unwrap().clone();
    let next = doc.max_id + 1;
    let (widget, sig, field) = (next, next + 1, next + 2);

    let page_body = format!(
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R \
         >> >> /Contents 5 0 R /Annots [{}{widget} 0 R] >>",
        refs(&annots)
    );
    assert_eq!(
        lopdf::Document::load_mem(&with_increment(&prepared, &[(PAGE, page_body.clone())]))
            .unwrap()
            .get_object((PAGE, 0))
            .unwrap()
            .as_dict()
            .unwrap()
            .len(),
        page.len(),
        "the rewritten page keeps every entry"
    );
    let base = [
        (PAGE, page_body),
        (
            widget,
            format!(
                "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature2) /Rect [0 0 0 0] \
                 /V {sig} 0 R /P {PAGE} 0 R /F 132 >>"
            ),
        ),
        (sig, "<< /Type /Sig >>".to_string()),
    ];

    // The honest shape: the form gains the widget. The audit's form rule is satisfied.
    let mut honest = base.to_vec();
    honest.push((
        form_id.0,
        format!("<< /Fields [{}{widget} 0 R] /SigFlags 3 >>", refs(&fields)),
    ));
    let audit = pades::audit_increment(&prepared, &with_increment(&prepared, &honest)).unwrap();
    assert!(
        !audit
            .violations
            .iter()
            .any(|v| v.contains("not the signature widget")),
        "{:?}",
        audit.violations
    );

    // The form gains another field instead.
    let mut other = base.to_vec();
    other.push((field, "<< /FT /Tx /T (Extra) >>".to_string()));
    other.push((
        form_id.0,
        format!("<< /Fields [{}{field} 0 R] /SigFlags 3 >>", refs(&fields)),
    ));
    let audit = pades::audit_increment(&prepared, &with_increment(&prepared, &other)).unwrap();
    assert!(
        audit
            .violations
            .iter()
            .any(|v| v.contains("not the signature widget")),
        "{:?}",
        audit.violations
    );
}

/// Every honest signer revision adds its widget as the form's new field.
#[test]
fn honest_signer_revisions_add_their_widget_as_the_field() {
    let pdf = container::make_sample_pdf("NDA");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let a = sign(&prepared, &k, &r).unwrap();
    let audit = pades::audit_increment(&prepared, &a).unwrap();
    assert!(audit.violations.is_empty(), "{:?}", audit.violations);
}
