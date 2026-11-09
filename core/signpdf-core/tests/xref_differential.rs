//! Regression tests for finding 1 of `docs/SECURITY_REVIEW_2026-10-27.md`: the increment audits
//! read each increment's cross-reference from its bytes instead of trusting lopdf's reading of
//! it, and refuse
//!
//! * an increment not in the form SignPDF writes: an object number listed twice, a free entry
//!   (in a signer's revision and in a document-timestamp increment);
//! * an entry for an object of the previous revision that the revision may not change, even when
//!   its bytes are unchanged;
//! * a change to an object the previous revision defined ambiguously (lopdf and viewers read
//!   different entries for it);
//! * a change to an object lopdf read from somewhere other than its own entry (a second copy
//!   behind another entry, an object stream no entry names, the last of two listings in its
//!   object stream), in the previous revision or in the new one;
//!
//! while every revision the engine writes passes, generation numbers included.
//!
//! What viewers read is modelled with the whitespace and comments they and lopdf skip between an
//! entry's offset and its `N G obj` (Microsoft Print to PDF points every entry at the line feed
//! before it); an entry that leads to another object, or to none, is still ambiguous.

mod common;

use common::*;
use signpdf_core::{container, pades, prepare, sign, verify};

fn last_startxref(pdf: &[u8]) -> usize {
    let pos = pdf.windows(9).rposition(|w| w == b"startxref").unwrap();
    String::from_utf8_lossy(&pdf[pos + 9..])
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

/// `pdf` with `lines` (cross-reference subsections) added at the top of its last table. The
/// table keeps its offset, so `startxref` still points at it.
fn with_table_lines(pdf: &[u8], lines: &str) -> Vec<u8> {
    let x = last_startxref(pdf);
    assert_eq!(&pdf[x..x + 5], b"xref\n");
    let mut out = pdf[..x + 5].to_vec();
    out.extend_from_slice(lines.as_bytes());
    out.extend_from_slice(&pdf[x + 5..]);
    out
}

/// The offset lopdf reads object `num` from.
fn offset_of(pdf: &[u8], num: u32) -> u32 {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    match doc.reference_table.get(num) {
        Some(lopdf::xref::XrefEntry::Normal { offset, .. }) => *offset,
        other => panic!("object {num}: {other:?}"),
    }
}

/// The sample document's page content stream.
const CONTENT: u32 = 5;
/// The sample document's page.
const PAGE: u32 = 3;

fn prepared() -> Vec<u8> {
    let pdf = container::make_sample_pdf("Pay Bob EUR 100");
    let (pk, req) = two_signer_request(&pdf);
    prepare(&pdf, &req, &pk).unwrap()
}

fn signed_by_alice(prepared: &[u8]) -> Vec<u8> {
    let (k, r) = signer_request("alice@example.com", prepared, "");
    sign(prepared, &k, &r).unwrap()
}

fn completed() -> Vec<u8> {
    let a = signed_by_alice(&prepared());
    let (k, r) = signer_request("bob@example.com", &a, "");
    sign(&a, &k, &r).unwrap()
}

fn has(violations: &[String], needle: &str) -> bool {
    violations.iter().any(|v| v.contains(needle))
}

#[test]
fn honest_revisions_pass() {
    let p = prepared();
    let a = signed_by_alice(&p);
    let audit = pades::audit_increment(&p, &a).unwrap();
    assert!(audit.violations.is_empty(), "{:?}", audit.violations);
    let done = completed();
    let (stamped, _) = pades::prepare_document_timestamp(&done).unwrap();
    let audit = pades::audit_ltv_increment(&done, &stamped).unwrap();
    assert!(audit.violations.is_empty(), "{:?}", audit.violations);
}

#[test]
fn a_signer_revision_listing_a_number_twice_is_refused() {
    let p = prepared();
    let a = signed_by_alice(&p);
    let off = offset_of(&a, CONTENT);
    let bad = with_table_lines(
        &a,
        &format!("{CONTENT} 1\n{off:010} 00000 n \n{CONTENT} 1\n{off:010} 00000 n \n"),
    );
    let audit = pades::audit_increment(&p, &bad).unwrap();
    assert!(
        has(&audit.violations, "not in the form SignPDF writes"),
        "{:?}",
        audit.violations
    );
    assert!(!verify(&bad, &trust()).unwrap().valid);
}

#[test]
fn a_signer_revision_with_a_free_entry_is_refused() {
    let p = prepared();
    let a = signed_by_alice(&p);
    let bad = with_table_lines(&a, &format!("{CONTENT} 1\n0000000000 00001 f \n"));
    let audit = pades::audit_increment(&p, &bad).unwrap();
    assert!(
        has(&audit.violations, "listed as free"),
        "{:?}",
        audit.violations
    );
}

#[test]
fn a_document_timestamp_increment_listing_a_number_twice_is_refused() {
    let done = completed();
    let (stamped, _) = pades::prepare_document_timestamp(&done).unwrap();
    let off = offset_of(&stamped, CONTENT);
    let bad = with_table_lines(
        &stamped,
        &format!("{CONTENT} 1\n{off:010} 00000 n \n{CONTENT} 1\n{off:010} 00000 n \n"),
    );
    let audit = pades::audit_ltv_increment(&done, &bad).unwrap();
    assert!(
        has(&audit.violations, "not in the form SignPDF writes"),
        "{:?}",
        audit.violations
    );
}

#[test]
fn a_document_timestamp_increment_with_a_free_entry_is_refused() {
    let done = completed();
    let (stamped, _) = pades::prepare_document_timestamp(&done).unwrap();
    let bad = with_table_lines(&stamped, &format!("{CONTENT} 1\n0000000000 00001 f \n"));
    let audit = pades::audit_ltv_increment(&done, &bad).unwrap();
    assert!(
        has(&audit.violations, "listed as free"),
        "{:?}",
        audit.violations
    );
}

/// An increment may list only the objects the audit compares (catalog, form, pages, validation
/// data): any other object of the previous revision is refused even when its bytes are the same.
#[test]
fn rewriting_an_object_that_may_not_change_is_refused_even_unchanged() {
    let p = prepared();
    let content = "BT /F1 24 Tf 72 700 Td (Pay Bob EUR 100) Tj ET\n";
    let body = format!(
        "<< /Length {} >>\nstream\n{content}endstream",
        content.len()
    );
    let same = append_object_override(&p, CONTENT, &body);
    // lopdf reads the same object back...
    let old = lopdf::Document::load_mem(&p).unwrap();
    let new = lopdf::Document::load_mem(&same).unwrap();
    assert_eq!(
        old.get_object((CONTENT, 0)).unwrap(),
        new.get_object((CONTENT, 0)).unwrap()
    );
    // ...but the increment rewrote an object it may not touch.
    let audit = pades::audit_increment(&p, &same).unwrap();
    assert!(
        has(&audit.violations, "may not change"),
        "{:?}",
        audit.violations
    );
}

/// A source whose newest table marks its page free: lopdf still reads the page from the older
/// table, a viewer does not. A revision that rewrites the page is refused, since comparing
/// lopdf's two readings would not compare what viewers showed.
#[test]
fn a_change_to_an_ambiguously_defined_object_is_refused() {
    let pdf = container::make_sample_pdf("NDA");
    let prev = last_startxref(&pdf);
    let mut source = pdf.clone();
    let x = source.len();
    source.extend_from_slice(
        format!(
            "xref\n{PAGE} 1\n0000000000 00001 f \ntrailer\n<< /Size 6 /Root 1 0 R /Prev {prev} >>\n\
             startxref\n{x}\n%%EOF\n"
        )
        .as_bytes(),
    );
    let stamped = pades::stamp_document_id(&source, "SignPDF Document test").unwrap();
    let audit = pades::audit_increment(&source, &stamped).unwrap();
    assert!(
        has(&audit.violations, "defined ambiguously"),
        "{:?}",
        audit.violations
    );
    // The same revision over the unambiguous document raises no such problem (a stamp alone
    // still lacks the signature field a revision must add, which is reported separately).
    let stamped = pades::stamp_document_id(&pdf, "SignPDF Document test").unwrap();
    let audit = pades::audit_increment(&pdf, &stamped).unwrap();
    assert!(
        !has(&audit.violations, "ambiguously") && !has(&audit.violations, "cross-reference"),
        "{:?}",
        audit.violations
    );
}

/// A source whose page has generation 1: the engine's tables now carry each object's own
/// generation, so its revisions pass the strict reading and the document verifies.
#[test]
fn objects_with_a_nonzero_generation_keep_it() {
    let pdf = container::make_sample_pdf("NDA");
    let text = String::from_utf8(pdf.clone()).unwrap();
    let page_off = offset_of(&pdf, PAGE);
    let source = text
        .replace(&format!("{PAGE} 0 obj"), &format!("{PAGE} 1 obj"))
        .replace(&format!("{PAGE} 0 R"), &format!("{PAGE} 1 R"))
        .replace(
            &format!("{page_off:010} 00000 n"),
            &format!("{page_off:010} 00001 n"),
        )
        .into_bytes();
    assert_eq!(source.len(), pdf.len());
    let (pk, req) = two_signer_request(&source);
    let p = prepare(&source, &req, &pk).unwrap();
    let tail = &p[last_startxref(&p)..];
    assert!(
        tail.windows(7).any(|w| w == b"00001 n"),
        "the page keeps generation 1 in the table"
    );
    let a = signed_by_alice(&p);
    let (k, r) = signer_request("bob@example.com", &a, "");
    let done = sign(&a, &k, &r).unwrap();
    let report = verify(&done, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
}

// ---- Sources written the way Microsoft Print to PDF writes them --------------------------------

/// Where the objects of a [`print_style`] document were written.
struct Layout {
    /// The start of the gap before each object.
    gap: std::collections::BTreeMap<u32, usize>,
    /// The start of each object's `N 0 obj`.
    header: std::collections::BTreeMap<u32, usize>,
}

/// Cross-reference entries: (object number, offset).
type Entries = Vec<(u32, usize)>;

/// The page, the font and the info dictionary of a [`print_style`] document.
const PRINTED_PAGE: u32 = 3;
const PRINTED_FONT: u32 = 4;
const PRINTED_INFO: u32 = 6;

/// A one-page document written the way Microsoft Print to PDF writes one (a Word document
/// printed to PDF, say): objects from the info dictionary down to the catalog, each after
/// `gap(n)`, and each cross-reference entry pointing at the **start of that gap**, not at its
/// `N 0 obj` (one byte early when the gap is a line feed); table lines ending in CR LF; the
/// page's boxes written as reals. `table` may redirect entries: it receives the layout and the
/// entries `(number, offset)` as written and returns the entries to write.
fn print_style(
    gap: &dyn Fn(u32) -> String,
    table: &dyn Fn(&Layout, Entries) -> Entries,
) -> Vec<u8> {
    let content = "BT /F1 24 Tf 72 700 Td (Mutual NDA, printed) Tj ET\n";
    let objects: Vec<(u32, String)> = vec![
        (
            PRINTED_INFO,
            "<<\n/Producer (A printer driver)\n/Title (Mutual NDA)\n>>".into(),
        ),
        (
            5,
            format!(
                "<<\n/Length {}\n>>\nstream\n{content}endstream",
                content.len()
            ),
        ),
        (
            PRINTED_FONT,
            "<<\n/BaseFont /Helvetica\n/Subtype /Type1\n/Type /Font\n>>".into(),
        ),
        (
            PRINTED_PAGE,
            "<<\n/Contents [ 5 0 R ]\n/CropBox [ 0.0 0.0 612.0 792.0 ]\n\
             /MediaBox [ 0.0 0.0 612.0 792.0 ]\n/Parent 2 0 R\n\
             /Resources << /Font << /F1 4 0 R >> >>\n/Rotate 0\n/Type /Page\n>>"
                .into(),
        ),
        (2, "<<\n/Count 1\n/Kids [ 3 0 R ]\n/Type /Pages\n>>".into()),
        (1, "<<\n/Pages 2 0 R\n/Type /Catalog\n>>".into()),
    ];
    let mut pdf = b"%PDF-1.7\n".to_vec();
    let mut layout = Layout {
        gap: Default::default(),
        header: Default::default(),
    };
    for (n, body) in &objects {
        layout.gap.insert(*n, pdf.len());
        pdf.extend_from_slice(gap(*n).as_bytes());
        layout.header.insert(*n, pdf.len());
        pdf.extend_from_slice(format!("{n} 0 obj\n{body}\nendobj").as_bytes());
    }
    pdf.push(b'\n');
    let entries = table(&layout, layout.gap.iter().map(|(n, o)| (*n, *o)).collect());
    let size = entries.iter().map(|(n, _)| n + 1).max().unwrap();
    let x = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {size}\r\n0000000000 65535 f\r\n").as_bytes());
    for n in 1..size {
        match entries.iter().find(|(m, _)| *m == n) {
            Some((_, off)) => pdf.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes()),
            None => pdf.extend_from_slice(b"0000000000 65535 f\r\n"),
        }
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<<\n/Info {PRINTED_INFO} 0 R\n/Root 1 0 R\n/Size {size}\n>>\n\
             startxref\n{x}\n%%EOF\n"
        )
        .as_bytes(),
    );
    pdf
}

/// The entries as written: each at the start of its gap.
fn as_written(_: &Layout, entries: Entries) -> Entries {
    entries
}

/// The gaps tried: one line feed (what Microsoft Print to PDF writes), every PDF whitespace
/// character, and comments.
const GAPS: [&str; 3] = [
    "\n",
    "\r\n\t\x0c\0 \n",
    "\n% a comment before the object\r\n%%another\r",
];

/// Prepare `source` as the app does (revision 0, then its verification), have both signers
/// sign, and verify the result.
fn prepare_sign_and_verify(source: &[u8]) {
    let (pk, req) = two_signer_request(source);
    let p = prepare(source, &req, &pk).unwrap();
    let report = verify(&p, &trust()).unwrap();
    assert!(report.integrity_ok, "{:?}", report.messages);
    let a = signed_by_alice(&p);
    let (k, r) = signer_request("bob@example.com", &a, "");
    let done = sign(&a, &k, &r).unwrap();
    let report = verify(&done, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
}

/// Microsoft Print to PDF's files: every entry points at whitespace (or comments) just before
/// the right object, where viewers and lopdf skip to it. The document prepares, signs and
/// verifies (the model read at the exact byte, and called every object it rewrites ambiguous).
#[test]
fn entries_pointing_at_whitespace_before_their_object_pass() {
    for gap in GAPS {
        let source = print_style(&|_| gap.to_string(), &as_written);
        prepare_sign_and_verify(&source);
    }
}

/// Entries pointing at the objects themselves, and the page's boxes as reals: the page the
/// engine rewrites keeps its reals (it wrote `612.0` as `612`, which reads back as an integer,
/// so the audit saw the page changed).
#[test]
fn a_page_with_real_boxes_is_rewritten_alike() {
    let source = print_style(&|_| "\n".into(), &|l, _| {
        l.header.iter().map(|(n, o)| (*n, *o)).collect()
    });
    prepare_sign_and_verify(&source);
}

/// The page's entry points at whitespace before **another** object (the font), and lopdf still
/// finds the page through a spare entry. Viewers refuse the page's entry (and rebuild the
/// cross-reference), so a change to the page is refused, whitespace or not.
#[test]
fn an_entry_before_another_object_is_still_ambiguous() {
    for gap in GAPS {
        let source = print_style(&|_| gap.to_string(), &|l, mut e| {
            e.retain(|(n, _)| *n != PRINTED_PAGE);
            e.push((PRINTED_PAGE, l.gap[&PRINTED_FONT]));
            e.push((7, l.header[&PRINTED_PAGE]));
            e
        });
        let doc = lopdf::Document::load_mem(&source).unwrap();
        assert!(doc.objects.contains_key(&(PRINTED_PAGE, 0)));
        refused_as_ambiguous(&source);
    }
}

/// The page's entry points into the body of another object (at whitespace inside the page
/// tree's dictionary): no object header follows, so a change to the page is refused.
#[test]
fn an_entry_into_another_objects_body_is_still_ambiguous() {
    let source = print_style(&|_| "\n".into(), &|l, mut e| {
        e.retain(|(n, _)| *n != PRINTED_PAGE);
        e.push((PRINTED_PAGE, l.header[&2] + "2 0 obj\n<<".len()));
        e.push((7, l.header[&PRINTED_PAGE]));
        e
    });
    refused_as_ambiguous(&source);
}

/// The preparer's revision over `source` is refused: the page was defined ambiguously.
fn refused_as_ambiguous(source: &[u8]) {
    let needle = format!("object {PRINTED_PAGE} 0 was defined ambiguously");
    let stamped = pades::stamp_document_id(source, "SignPDF Document test").unwrap();
    let audit = pades::audit_increment(source, &stamped).unwrap();
    assert!(has(&audit.violations, &needle), "{:?}", audit.violations);
    let (pk, req) = two_signer_request(source);
    let p = prepare(source, &req, &pk).unwrap();
    let report = verify(&p, &trust()).unwrap();
    assert!(!report.integrity_ok);
    assert!(has(&report.messages, &needle), "{:?}", report.messages);
}

/// An incremental update written the same way on top of such a source (it rewrites the page
/// and the info dictionary, its entries at the gaps too): viewers read the page from the
/// update, and the document prepares, signs and verifies.
#[test]
fn an_update_written_the_same_way_on_top_passes() {
    for gap in GAPS {
        let mut source = print_style(&|_| gap.to_string(), &as_written);
        let prev = last_startxref(&source);
        let start = source.windows(8).position(|w| w == b"3 0 obj\n").unwrap();
        let len = source[start..]
            .windows(6)
            .position(|w| w == b"endobj")
            .unwrap()
            + 6;
        let page = source[start..start + len].to_vec();
        let page_gap = source.len();
        source.extend_from_slice(gap.as_bytes());
        source.extend_from_slice(&page);
        let info_gap = source.len();
        source.extend_from_slice(gap.as_bytes());
        source.extend_from_slice(
            format!(
                "{PRINTED_INFO} 0 obj\n<<\n/Producer (A printer driver)\n\
                 /Title (Mutual NDA, revised)\n>>\nendobj\n"
            )
            .as_bytes(),
        );
        let x = source.len();
        source.extend_from_slice(
            format!(
                "xref\n0 1\r\n0000000000 65535 f\r\n{PRINTED_PAGE} 1\r\n{page_gap:010} 00000 n\r\n\
                 {PRINTED_INFO} 1\r\n{info_gap:010} 00000 n\r\ntrailer\n<<\n\
                 /Info {PRINTED_INFO} 0 R\n/Prev {prev}\n/Root 1 0 R\n/Size 7\n>>\n\
                 startxref\n{x}\n%%EOF\n"
            )
            .as_bytes(),
        );
        let doc = lopdf::Document::load_mem(&source).unwrap();
        let info = doc.get_dictionary((PRINTED_INFO, 0)).unwrap();
        assert_eq!(
            info.get(b"Title").unwrap().as_str().unwrap(),
            b"Mutual NDA, revised"
        );
        prepare_sign_and_verify(&source);
    }
}

// ---- Copies lopdf reads from somewhere other than the object's own entry ------------------------
//
// Review of PR #51, defect 1. lopdf files every object under the number of the `N G obj` it finds
// at an entry's offset, not under the entry's number, so another entry leading to a second copy
// of an object gives lopdf that copy; and an object lopdf cannot parse at its own entry is filled
// from any object stream that lists it. Viewers read the object's own entry. The audits compare
// lopdf's copies, so a signer's revision could change what viewers show on a page the audit saw
// unchanged. Each attack below is a modified signing client (it skips the precheck) whose
// revision points page 2 at hidden content; the verifier must refuse it.

/// Page 2 of a [`two_pages`] document.
const PAGE_2: u32 = 6;
/// Page 2's content as viewers show it in the source.
const SHOWN: u32 = 7;
/// Content in the file that no page shows in the source.
const HIDDEN: u32 = 9;

/// Page 2's dictionary, showing content `contents`.
fn page_2(contents: u32) -> String {
    format!(
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F1 4 0 R >> >> /Contents {contents} 0 R >>"
    )
}

fn content_stream(text: &str) -> String {
    let ops = format!("BT /F1 24 Tf 72 700 Td ({text}) Tj ET\n");
    format!("<< /Length {} >>\nstream\n{ops}endstream", ops.len())
}

/// A two-page document with a classic table: page 1 (object 3), page 2 (object 6) written as
/// `page_2_body`, its content [`SHOWN`], and the [`HIDDEN`] content no page uses. `extra` are
/// more entries: (entry number, the bytes the entry points at), which may hold an object of
/// another number.
fn two_pages(page_2_body: &str, extra: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let objects: Vec<(u32, Vec<u8>)> = vec![
        (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
        (
            2,
            b"<< /Type /Pages /Count 2 /Kids [3 0 R 6 0 R] >>".to_vec(),
        ),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
                .to_vec(),
        ),
        (
            4,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        ),
        (5, content_stream("Signatures").into_bytes()),
        (PAGE_2, page_2_body.as_bytes().to_vec()),
        (SHOWN, content_stream("Pay Bob EUR 100").into_bytes()),
        (HIDDEN, content_stream("Pay Bob EUR 1000000").into_bytes()),
    ];
    let mut pdf = b"%PDF-1.7\n".to_vec();
    let mut offsets = std::collections::BTreeMap::new();
    for (n, body) in &objects {
        offsets.insert(*n, pdf.len());
        pdf.extend_from_slice(format!("{n} 0 obj\n").as_bytes());
        pdf.extend_from_slice(body);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    for (n, bytes) in extra {
        offsets.insert(*n, pdf.len());
        pdf.extend_from_slice(bytes);
        pdf.push(b'\n');
    }
    let size = offsets.keys().max().unwrap() + 1;
    let x = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
    for n in 1..size {
        match offsets.get(&n) {
            Some(off) => pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes()),
            None => pdf.extend_from_slice(b"0000000000 65535 f \n"),
        }
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n").as_bytes(),
    );
    pdf
}

/// An object stream (uncompressed) holding `members` (number, body) in that order.
fn object_stream(number: u32, members: &[(u32, String)]) -> Vec<u8> {
    let (mut header, mut packed) = (String::new(), String::new());
    for (n, body) in members {
        header.push_str(&format!("{n} {} ", packed.len()));
        packed.push_str(body);
        packed.push('\n');
    }
    let content = format!("{header}{packed}");
    format!(
        "{number} 0 obj\n<< /Type /ObjStm /N {} /First {} /Length {} >>\nstream\n{content}\n\
         endstream\nendobj",
        members.len(),
        header.len(),
        content.len() + 1
    )
    .into_bytes()
}

/// A two-page document with a cross-reference stream whose page 2 sits in object stream 8:
/// `members` are that stream's objects in order, and page 2's entry names the first one listed
/// as [`PAGE_2`]. Everything else is as in [`two_pages`].
fn two_pages_compressed(members: &[(u32, String)]) -> Vec<u8> {
    let objects: Vec<(u32, Vec<u8>)> = vec![
        (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
        (
            2,
            b"<< /Type /Pages /Count 2 /Kids [3 0 R 6 0 R] >>".to_vec(),
        ),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
                .to_vec(),
        ),
        (
            4,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        ),
        (5, content_stream("Signatures").into_bytes()),
        (SHOWN, content_stream("Pay Bob EUR 100").into_bytes()),
        (HIDDEN, content_stream("Pay Bob EUR 1000000").into_bytes()),
    ];
    // Rows: type, then offset or container, then generation or index.
    let mut rows = std::collections::BTreeMap::<u32, (u8, usize, u16)>::new();
    let mut pdf = b"%PDF-1.7\n".to_vec();
    for (n, body) in &objects {
        rows.insert(*n, (1, pdf.len(), 0));
        pdf.extend_from_slice(format!("{n} 0 obj\n").as_bytes());
        pdf.extend_from_slice(body);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    rows.insert(8, (1, pdf.len(), 0));
    pdf.extend_from_slice(&object_stream(8, members));
    pdf.push(b'\n');
    for (i, (n, _)) in members.iter().enumerate() {
        rows.entry(*n).or_insert((2, 8, u16::try_from(i).unwrap()));
    }
    let xref_id = rows.keys().max().unwrap() + 1;
    let x = pdf.len();
    rows.insert(xref_id, (1, x, 0));
    let mut data = Vec::new();
    for n in 0..=xref_id {
        let (kind, a, b) = rows.get(&n).copied().unwrap_or((0, 0, 0xffff));
        data.push(kind);
        data.extend_from_slice(&u32::try_from(a).unwrap().to_be_bytes());
        data.extend_from_slice(&b.to_be_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "{xref_id} 0 obj\n<< /Type /XRef /Size {} /W [1 4 2] /Root 1 0 R /Length {} >>\nstream\n",
            xref_id + 1,
            data.len()
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(&data);
    pdf.extend_from_slice(format!("\nendstream\nendobj\nstartxref\n{x}\n%%EOF\n").as_bytes());
    pdf
}

/// The text of page `n` (1-based) as lopdf reads it.
fn page_text(pdf: &[u8], n: u32) -> String {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    let page = doc.get_pages()[&n];
    String::from_utf8_lossy(&doc.get_page_content(page).unwrap()).into_owned()
}

/// Prepare `source` and have Alice sign; then Bob's modified client rewrites page 2 to show the
/// [`HIDDEN`] content in the revision it signs. Returns Alice's revision and Bob's.
fn page_2_rewritten_by_bob(source: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (pk, req) = two_signer_request(source);
    let p = prepare(source, &req, &pk).unwrap();
    let report = verify(&p, &trust()).unwrap();
    assert!(report.integrity_ok, "{:?}", report.messages);
    let a = signed_by_alice(&p);
    let (k, r) = signer_request("bob@example.com", &a, "");
    let extra = [(PAGE_2, page_2(HIDDEN).into_bytes())];
    let done =
        signpdf_core::workflow::testing::sign_with_extra_objects(&a, &k, &r, &extra).unwrap();
    // Viewers read page 2 from the newest table: Bob's copy, showing the hidden content.
    let newest = done
        .windows(b"\n6 0 obj".len())
        .rposition(|w| w == b"\n6 0 obj")
        .unwrap();
    assert!(String::from_utf8_lossy(&done[newest..newest + 200])
        .contains(&format!("/Contents {HIDDEN} 0 R")));
    (a, done)
}

/// The verifier refuses Bob's revision, for `reason` (before the fix it verified).
fn bobs_revision_refused(a: &[u8], done: &[u8], reason: &str) {
    let report = verify(done, &trust()).unwrap();
    assert!(
        !report.valid,
        "Bob's revision verified: {:?}",
        report.messages
    );
    assert!(!report.integrity_ok);
    assert!(has(&report.messages, reason), "{:?}", report.messages);
    let audit = pades::audit_increment(a, done).unwrap();
    assert!(has(&audit.violations, reason), "{:?}", audit.violations);
}

/// The control: without a second copy, the audit sees the page change.
#[test]
fn a_page_pointed_at_hidden_content_is_refused() {
    let source = two_pages(&page_2(SHOWN), &[]);
    let (a, done) = page_2_rewritten_by_bob(&source);
    assert!(page_text(&done, 2).contains("EUR 1000000"));
    bobs_revision_refused(&a, &done, "page object 6 was modified");
}

/// A spare entry (8) points at a second, identical `6 0 obj`. lopdf files it under 6, and as the
/// later entry it wins, in every revision: in Bob's revision lopdf still reads the old page 2
/// from it, while viewers read the rewritten page 2 from the newest table. The audit saw no
/// change and the document verified; the second copy now makes page 2 ambiguous.
#[test]
fn a_second_copy_behind_another_entry_is_refused() {
    let shadow = format!("{PAGE_2} 0 obj\n{}\nendobj", page_2(SHOWN)).into_bytes();
    let source = two_pages(&page_2(SHOWN), &[(8, shadow)]);
    let (a, done) = page_2_rewritten_by_bob(&source);
    // lopdf still reads the old page 2 there.
    assert!(page_text(&done, 2).contains("EUR 100)"));
    bobs_revision_refused(&a, &done, "object 6 0 was defined ambiguously");
    let audit = pades::audit_increment(&a, &done).unwrap();
    assert!(
        has(
            &audit.violations,
            "object 6 0 of the revision is not read from its own"
        ),
        "{:?}",
        audit.violations
    );
}

/// Page 2's own entry holds a dictionary viewers read (they skip a key that is not a name) and
/// lopdf cannot parse, so lopdf fills object 6 from an object stream no entry names, where page 2
/// shows the hidden content. Bob's revision writes that copy: lopdf sees no change, viewers see
/// page 2 change from EUR 100 to EUR 1000000.
#[test]
fn a_copy_filled_in_from_an_unnamed_object_stream_is_refused() {
    let unparsable = page_2(SHOWN).replace("/Type /Page ", "/Type /Page 99 ");
    let stream = object_stream(8, &[(PAGE_2, page_2(HIDDEN))]);
    let source = two_pages(&unparsable, &[(8, stream)]);
    let doc = lopdf::Document::load_mem(&source).unwrap();
    assert_eq!(
        doc.get_dictionary((PAGE_2, 0))
            .unwrap()
            .get(b"Contents")
            .unwrap(),
        &lopdf::Object::Reference((HIDDEN, 0)),
        "lopdf reads page 2 from the object stream"
    );
    let (a, done) = page_2_rewritten_by_bob(&source);
    bobs_revision_refused(&a, &done, "object 6 0 was defined ambiguously");
}

/// Page 2 sits in an object stream whose header lists 6 twice. Viewers read the entry's index
/// (the first, showing EUR 100), lopdf keeps the last (showing EUR 1000000), so a revision that
/// writes the last copy changes what viewers show while lopdf sees no change.
#[test]
fn an_object_listed_twice_in_its_object_stream_is_refused() {
    let source = two_pages_compressed(&[(PAGE_2, page_2(SHOWN)), (PAGE_2, page_2(HIDDEN))]);
    let doc = lopdf::Document::load_mem(&source).unwrap();
    assert_eq!(
        doc.get_dictionary((PAGE_2, 0))
            .unwrap()
            .get(b"Contents")
            .unwrap(),
        &lopdf::Object::Reference((HIDDEN, 0)),
        "lopdf keeps the last copy"
    );
    let (a, done) = page_2_rewritten_by_bob(&source);
    bobs_revision_refused(&a, &done, "object 6 0 was defined ambiguously");
}

/// The checks refuse only those copies: a page in an object stream listed once, and a document
/// with a harmless second copy of an object no revision rewrites, prepare, sign and verify, and a
/// rewrite of page 2 there is still seen as a change.
#[test]
fn objects_read_from_their_own_entry_still_pass() {
    let compressed = two_pages_compressed(&[(PAGE_2, page_2(SHOWN))]);
    prepare_sign_and_verify(&compressed);
    let (a, done) = page_2_rewritten_by_bob(&compressed);
    bobs_revision_refused(&a, &done, "page object 6 was modified");

    let font_copy =
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj".to_vec();
    prepare_sign_and_verify(&two_pages(&page_2(SHOWN), &[(8, font_copy)]));
}
