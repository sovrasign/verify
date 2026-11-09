//! Regression tests for finding 2 of `docs/SECURITY_REVIEW_2026-10-27.md`: a revision may not
//! define an object that the previous revision refers to without defining (no entry, or a free
//! one), and the engine numbers the objects it adds above every referenced number.

mod common;

use common::*;
use signpdf_core::workflow::testing::sign_malicious;
use signpdf_core::{pades, prepare, sign, verify};

/// A one-page document whose page dictionary also holds `page_extra`, followed by `tail`
/// (raw bytes appended after its `%%EOF`, e.g. another cross-reference section).
fn source(page_extra: &str) -> Vec<u8> {
    let content = "BT /F1 24 Tf 72 700 Td (Terms) Tj ET\n";
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R {page_extra} >>"
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        format!(
            "<< /Length {} >>\nstream\n{content}endstream",
            content.len()
        ),
    ];
    let mut buf = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(buf.len());
        buf.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }
    let x = buf.len();
    buf.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
    for off in offsets {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n").as_bytes(),
    );
    buf
}

/// `pdf` with one more section that marks object `num` free.
fn with_free_entry(pdf: &[u8], num: u32) -> Vec<u8> {
    let pos = pdf.windows(9).rposition(|w| w == b"startxref").unwrap();
    let prev: usize = String::from_utf8_lossy(&pdf[pos + 9..])
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut out = pdf.to_vec();
    let x = out.len();
    out.extend_from_slice(
        format!(
            "xref\n{num} 1\n0000000000 00001 f \ntrailer\n<< /Size {} /Root 1 0 R /Prev {prev} >>\n\
             startxref\n{x}\n%%EOF\n",
            num + 1
        )
        .as_bytes(),
    );
    out
}

/// Prepare `src`, then sign it as Alice over `prepared` plus an increment defining `num`: the
/// audit of Alice's revision must refuse the definition.
fn assert_defining_is_refused(src: &[u8], num: u32) {
    let (pk, req) = two_signer_request(src);
    let prepared = prepare(src, &req, &pk).unwrap();
    let edited = append_object_override(&prepared, num, "<< /Type /Annot /Subtype /Text >>");
    let (k, r) = signer_request("alice@example.com", &edited, "");
    let signed = sign_malicious(&edited, &k, &r, true, &|_| {}).unwrap();
    let audit = pades::audit_increment(&prepared, &signed).unwrap();
    assert!(
        audit
            .violations
            .iter()
            .any(|v| v.contains("refers to without defining")),
        "{:?}",
        audit.violations
    );
    assert!(!verify(&signed, &trust()).unwrap().valid);
}

#[test]
fn defining_an_object_the_previous_revision_refers_to_is_refused() {
    assert_defining_is_refused(&source("/Annots [99 0 R]"), 99);
}

#[test]
fn defining_an_object_whose_entry_was_free_is_refused() {
    assert_defining_is_refused(&with_free_entry(&source("/Annots [99 0 R]"), 99), 99);
}

/// The page refers to object 6, the number the engine used to give its first new object: it now
/// numbers its objects above it, so honest revisions never define it and the document verifies.
#[test]
fn the_engine_numbers_its_objects_above_referenced_numbers() {
    let src = source("/Annots [6 0 R]");
    let (pk, req) = two_signer_request(&src);
    let prepared = prepare(&src, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let a = sign(&prepared, &k, &r).unwrap();
    let (k, r) = signer_request("bob@example.com", &a, "");
    let done = sign(&a, &k, &r).unwrap();
    let doc = lopdf::Document::load_mem(&done).unwrap();
    assert!(
        doc.reference_table.get(6).is_none(),
        "no revision defines object 6"
    );
    let report = verify(&done, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
}
