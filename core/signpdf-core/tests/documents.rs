//! Several documents in one envelope (the envelope's `documents` index): combining documents into
//! one PDF, preparing, signing and verifying it, the index as a prepared term, the 50 MB limit
//! on the whole envelope, and convenience copies of one document.

mod common;

use common::{field, prepare_request, sig_field, signer_request, spec, trust};
use lopdf::{Dictionary, Document, Object, ObjectId};
use signpdf_core::crypto::sha256_hex;
use signpdf_core::documents::{self, SourceDocument, MAX_DOCUMENTS, MAX_ENVELOPE_BYTES};
use signpdf_core::workflow::{self, testing, ENVELOPE_NAME};
use signpdf_core::{
    certificate, combine_documents, container, extract_document, pades, prepare, sign, verify,
    EnvelopeDocument, FieldType, SignPdfError, SigningOrder,
};

/// A PDF written object by object (numbered from 1), with a classic cross-reference table.
#[derive(Default)]
struct Pdf {
    objects: Vec<String>,
}

impl Pdf {
    fn add(&mut self, body: impl Into<String>) -> u32 {
        self.objects.push(body.into());
        self.objects.len() as u32
    }

    fn stream(dict: &str, content: &str) -> String {
        format!(
            "<< {dict} /Length {} >>\nstream\n{content}\nendstream",
            content.len() + 1
        )
    }

    fn build(&self, root: u32) -> Vec<u8> {
        let mut buf = b"%PDF-1.6\n".to_vec();
        let mut offsets = Vec::new();
        for (i, body) in self.objects.iter().enumerate() {
            offsets.push(buf.len());
            buf.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
        }
        let xref = buf.len();
        let size = self.objects.len() + 1;
        buf.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
        for off in offsets {
            buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        buf.extend_from_slice(
            format!("trailer\n<< /Size {size} /Root {root} 0 R >>\nstartxref\n{xref}\n%%EOF\n")
                .as_bytes(),
        );
        buf
    }
}

/// "Agreement": two A4 pages whose size and resources are inherited from the page tree, a link
/// and a bookmark to a named destination on page 2, a filled form field with an appearance, an
/// attachment, an open action and a language.
fn agreement() -> Vec<u8> {
    let mut p = Pdf::default();
    p.add(
        "<< /Type /Catalog /Pages 2 0 R /Outlines 10 0 R /Names << /Dests 12 0 R \
         /EmbeddedFiles 13 0 R >> /AcroForm << /Fields [8 0 R] /DA (/Helv 0 Tf 0 g) \
         /DR << /Font << /Helv 5 0 R >> >> >> /OpenAction [3 0 R /Fit] /Lang (en-US) >>",
    );
    p.add(
        "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 595 842] \
         /Resources << /Font << /F1 5 0 R >> >> >>",
    );
    p.add("<< /Type /Page /Parent 2 0 R /Contents 6 0 R /Annots [9 0 R 8 0 R] >>");
    p.add("<< /Type /Page /Parent 2 0 R /Contents 7 0 R >>");
    p.add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    p.add(Pdf::stream(
        "",
        "BT /F1 18 Tf 72 760 Td (Agreement page 1) Tj ET",
    ));
    p.add(Pdf::stream(
        "",
        "BT /F1 18 Tf 72 760 Td (Agreement page 2) Tj ET",
    ));
    p.add(
        "<< /Type /Annot /Subtype /Widget /FT /Tx /T (Name) /V (Alice) /Rect [72 600 272 630] \
         /P 3 0 R /AP << /N 14 0 R >> >>",
    );
    p.add("<< /Type /Annot /Subtype /Link /Rect [72 700 200 720] /Dest (sec2) >>");
    p.add("<< /Type /Outlines /First 11 0 R /Last 11 0 R /Count 1 >>");
    p.add("<< /Title (Section 2) /Parent 10 0 R /Dest (sec2) >>");
    p.add("<< /Names [(sec2) [4 0 R /XYZ 0 800 0]] >>");
    p.add("<< /Names [(terms.txt) 15 0 R] >>");
    p.add(Pdf::stream(
        "/Type /XObject /Subtype /Form /BBox [0 0 200 30] /Resources << /Font << /Helv 5 0 R >> >>",
        "BT /Helv 12 Tf 2 10 Td (Alice) Tj ET",
    ));
    p.add("<< /Type /Filespec /F (terms.txt) /UF (terms.txt) /EF << /F 16 0 R >> >>");
    p.add(Pdf::stream("/Type /EmbeddedFile", "Terms of the agreement"));
    p.build(1)
}

/// "Schedule A": one Letter page shown rotated by 90 degrees, a form field of the same name as
/// the agreement's (without an appearance), an attachment of the same name, a hidden layer, a
/// link whose destination is given as a page number, and a page script.
fn schedule_a() -> Vec<u8> {
    let mut p = Pdf::default();
    p.add(
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] >> \
         /Names << /EmbeddedFiles << /Names [(terms.txt) 8 0 R] >> >> \
         /OCProperties << /OCGs [9 0 R] /D << /OFF [9 0 R] /Order [9 0 R] >> >> >>",
    );
    p.add("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    p.add(
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Rotate 90 /Contents 4 0 R \
         /Resources << /Font << /F1 6 0 R >> /Properties << /L1 9 0 R >> >> \
         /Annots [5 0 R 10 0 R] /AA << /O << /S /JavaScript /JS (app.alert\\('x'\\)) >> >> >>",
    );
    p.add(Pdf::stream(
        "",
        "BT /F1 18 Tf 72 500 Td (Schedule A: fees) Tj ET /OC /L1 BDC BT /F1 9 Tf 72 400 Td \
         (draft note) Tj ET EMC",
    ));
    p.add("<< /Type /Annot /Subtype /Widget /FT /Tx /T (Name) /Rect [72 300 272 330] /P 3 0 R >>");
    p.add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    p.add(Pdf::stream("/Type /EmbeddedFile", "Other terms"));
    p.add("<< /Type /Filespec /F (terms.txt) /EF << /F 7 0 R >> >>");
    p.add("<< /Type /OCG /Name (Draft notes) >>");
    p.add("<< /Type /Annot /Subtype /Link /Rect [72 200 200 220] /A << /S /GoTo /D [0 /Fit] >> >>");
    p.build(1)
}

/// "Schedule B": a modern PDF (cross-reference and object streams).
const REAL_PLAIN: &[u8] = include_bytes!("fixtures/real_plain.pdf");
/// A modern PDF whose form keeps `/Fields` in an object of its own (field `existing_name`).
const REAL_ACROFORM: &[u8] = include_bytes!("fixtures/real_acroform.pdf");

fn three() -> (Vec<u8>, Vec<u8>) {
    (agreement(), schedule_a())
}

fn sources<'a>(a: &'a [u8], b: &'a [u8]) -> Vec<SourceDocument<'a>> {
    vec![
        SourceDocument {
            name: "Agreement.pdf",
            pdf: a,
        },
        SourceDocument {
            name: "Schedule A.pdf",
            pdf: b,
        },
        SourceDocument {
            name: "Schedule B.pdf",
            pdf: REAL_PLAIN,
        },
    ]
}

fn pages(doc: &Document) -> Vec<ObjectId> {
    doc.page_iter().collect()
}

fn dict<'a>(doc: &'a Document, o: &'a Object) -> &'a Dictionary {
    match o {
        Object::Reference(id) => doc.get_dictionary(*id).unwrap(),
        Object::Dictionary(d) => d,
        other => panic!("not a dictionary: {other:?}"),
    }
}

fn catalog(doc: &Document) -> &Dictionary {
    doc.catalog().unwrap()
}

fn text(o: &Object) -> String {
    match o {
        Object::String(s, _) => String::from_utf8_lossy(s).to_string(),
        other => panic!("not a string: {other:?}"),
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn combining_keeps_every_page_in_order_and_says_where_each_document_is() {
    let (a, b) = three();
    let combined = combine_documents(&sources(&a, &b)).unwrap();

    assert_eq!(
        combined.documents,
        vec![
            EnvelopeDocument {
                name: "Agreement.pdf".into(),
                first_page: 0,
                page_count: 2,
                source_digest: sha256_hex(&a),
            },
            EnvelopeDocument {
                name: "Schedule A.pdf".into(),
                first_page: 2,
                page_count: 1,
                source_digest: sha256_hex(&b),
            },
            EnvelopeDocument {
                name: "Schedule B.pdf".into(),
                first_page: 3,
                page_count: 1,
                source_digest: sha256_hex(REAL_PLAIN),
            },
        ]
    );
    documents::check_index(&combined.documents, 4).unwrap();

    // The engine reads the pages as the documents had them.
    let geometry = pades::page_geometry(&combined.pdf).unwrap();
    assert_eq!(geometry.len(), 4);
    assert_eq!(geometry[0].media_box, [0.0, 0.0, 595.0, 842.0], "inherited");
    assert_eq!(geometry[1].media_box, [0.0, 0.0, 595.0, 842.0], "inherited");
    assert_eq!(geometry[2].media_box, [0.0, 0.0, 612.0, 792.0]);
    assert_eq!(geometry[2].rotate, 90);
    let plain = pades::page_geometry(REAL_PLAIN).unwrap();
    assert_eq!(geometry[3].media_box, plain[0].media_box);

    let doc = Document::load_mem(&combined.pdf).unwrap();
    let p = pages(&doc);
    let content = |i: usize| doc.get_page_content(p[i]).unwrap();
    assert!(contains(&content(0), "Agreement page 1"));
    assert!(contains(&content(1), "Agreement page 2"));
    assert!(contains(&content(2), "Schedule A: fees"));
    let original = Document::load_mem(REAL_PLAIN).unwrap();
    assert_eq!(
        content(3),
        original.get_page_content(pages(&original)[0]).unwrap()
    );
    // Resources inherited from the page tree are on the page.
    let page0 = doc.get_dictionary(p[0]).unwrap();
    let resources = dict(&doc, page0.get(b"Resources").unwrap());
    assert!(dict(&doc, resources.get(b"Font").unwrap()).has(b"F1"));

    // A bookmark per document, opening on its first page, holding the document's own.
    let root = catalog(&doc);
    assert_eq!(
        root.get(b"PageMode").unwrap().as_name().unwrap(),
        b"UseOutlines"
    );
    let outlines = dict(&doc, root.get(b"Outlines").unwrap());
    assert_eq!(outlines.get(b"Count").unwrap().as_i64().unwrap(), 3);
    let mut titles = Vec::new();
    let mut item = outlines.get(b"First").ok().cloned();
    let mut first_bookmark = None;
    while let Some(Object::Reference(id)) = item {
        let d = doc.get_dictionary(id).unwrap();
        titles.push(text(d.get(b"Title").unwrap()));
        let dest = d.get(b"Dest").unwrap().as_array().unwrap();
        assert!(p.contains(&dest[0].as_reference().unwrap()));
        first_bookmark.get_or_insert(id);
        item = d.get(b"Next").ok().cloned();
    }
    assert_eq!(
        titles,
        ["Agreement.pdf", "Schedule A.pdf", "Schedule B.pdf"]
    );
    let agreement_bookmark = doc.get_dictionary(first_bookmark.unwrap()).unwrap();
    assert_eq!(
        agreement_bookmark.get(b"Count").unwrap().as_i64().unwrap(),
        -1
    );
    let section = dict(&doc, agreement_bookmark.get(b"First").unwrap());
    assert_eq!(text(section.get(b"Title").unwrap()), "Section 2");
    // Its named destination now names the page itself.
    let dest = section.get(b"Dest").unwrap().as_array().unwrap();
    assert_eq!(dest[0].as_reference().unwrap(), p[1]);

    // Links keep working: the named destination, and the page number of Schedule A's own page.
    let link_on = |page: usize| -> Dictionary {
        let annots = doc.get_dictionary(p[page]).unwrap().get(b"Annots").unwrap();
        annots
            .as_array()
            .unwrap()
            .iter()
            .map(|a| dict(&doc, a).clone())
            .find(|a| a.get(b"Subtype").unwrap().as_name().unwrap() == b"Link")
            .unwrap()
    };
    let dest = link_on(0);
    let dest = dest.get(b"Dest").unwrap().as_array().unwrap();
    assert_eq!(dest[0].as_reference().unwrap(), p[1]);
    let link = link_on(2);
    let action = dict(&doc, link.get(b"A").unwrap());
    let d = action.get(b"D").unwrap().as_array().unwrap();
    assert_eq!(d[0].as_reference().unwrap(), p[2]);

    // One form: the second "Name" field is renamed after its document.
    let form = dict(&doc, root.get(b"AcroForm").unwrap());
    let names: Vec<String> = form
        .get(b"Fields")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|f| text(dict(&doc, f).get(b"T").unwrap()))
        .collect();
    assert_eq!(names, ["Name", "Name (2)"]);
    assert!(dict(&doc, form.get(b"DR").unwrap()).has(b"Font"));

    // Attachments merged, a repeated name made unique.
    let files = dict(
        &doc,
        dict(&doc, root.get(b"Names").unwrap())
            .get(b"EmbeddedFiles")
            .unwrap(),
    );
    let names: Vec<String> = files
        .get(b"Names")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .step_by(2)
        .map(text)
        .collect();
    assert_eq!(names, ["terms.txt", "terms.txt (2)"]);

    // Layers keep their default visibility.
    let layers = dict(&doc, root.get(b"OCProperties").unwrap());
    let ocgs = layers.get(b"OCGs").unwrap().as_array().unwrap();
    assert_eq!(ocgs.len(), 1);
    let off = dict(&doc, layers.get(b"D").unwrap()).get(b"OFF").unwrap();
    assert_eq!(off.as_array().unwrap(), ocgs);

    // What belongs to one document is gone: its open action, page scripts, its language
    // (the documents do not share one).
    for key in [&b"OpenAction"[..], b"Lang", b"StructTreeRoot", b"Metadata"] {
        assert!(!root.has(key), "{}", String::from_utf8_lossy(key));
    }
    assert!(!doc.get_dictionary(p[2]).unwrap().has(b"AA"));
    // No cross-reference or object streams were carried over.
    assert!(doc
        .objects
        .values()
        .all(|o| !matches!(o.type_name(), Ok(b"ObjStm") | Ok(b"XRef"))));
}

#[test]
fn one_document_comes_back_as_it_was() {
    let a = agreement();
    let combined = combine_documents(&[SourceDocument {
        name: "Agreement.pdf",
        pdf: &a,
    }])
    .unwrap();
    assert_eq!(combined.pdf, a);
    assert_eq!(
        combined.documents,
        vec![EnvelopeDocument {
            name: "Agreement.pdf".into(),
            first_page: 0,
            page_count: 2,
            source_digest: sha256_hex(&a),
        }]
    );
}

#[test]
fn combining_is_deterministic() {
    let (a, b) = three();
    let first = combine_documents(&sources(&a, &b)).unwrap();
    let again = combine_documents(&sources(&a, &b)).unwrap();
    assert_eq!(first.pdf, again.pdf);
    let mut reversed = sources(&a, &b);
    reversed.reverse();
    let other = combine_documents(&reversed).unwrap();
    assert_ne!(other.pdf, first.pdf);
    assert_eq!(other.documents[0].name, "Schedule B.pdf");
    assert_eq!(other.documents[2].first_page, 2);
    assert_eq!(other.documents[2].page_count, 2);
}

fn workflow_error(r: signpdf_core::Result<impl std::fmt::Debug>, expected: &str) {
    match r {
        Err(SignPdfError::Workflow(m)) => assert!(m.contains(expected), "{m}"),
        other => panic!("expected a workflow error with '{expected}', got {other:?}"),
    }
}

#[test]
fn combine_refuses_what_it_cannot_combine() {
    let (a, b) = three();
    workflow_error(combine_documents(&[]), "no documents");
    let many: Vec<SourceDocument> = (0..=MAX_DOCUMENTS)
        .map(|_| SourceDocument {
            name: "A.pdf",
            pdf: &a,
        })
        .collect();
    workflow_error(combine_documents(&many), "at most 20 documents");
    let named = |name: &'static str| {
        vec![
            SourceDocument { name, pdf: &a },
            SourceDocument {
                name: "B.pdf",
                pdf: &b,
            },
        ]
    };
    workflow_error(combine_documents(&named("  ")), "needs a name");
    workflow_error(combine_documents(&named("a\nb")), "control character");
    workflow_error(
        combine_documents(&[
            SourceDocument {
                name: "A.pdf",
                pdf: &a,
            },
            SourceDocument {
                name: "notes.docx",
                pdf: b"PK\x03\x04 not a pdf",
            },
        ]),
        "document 2 ('notes.docx') is not a PDF",
    );
    // A signed document (here a prepared envelope, signed by its preparer).
    let (key, req) = common::two_signer_request(&a);
    let prepared = prepare(&a, &req, &key).unwrap();
    workflow_error(
        combine_documents(&[
            SourceDocument {
                name: "Signed.pdf",
                pdf: &prepared,
            },
            SourceDocument {
                name: "B.pdf",
                pdf: &b,
            },
        ]),
        "document 1 ('Signed.pdf') is signed",
    );
    // A document without pages.
    let mut empty = Pdf::default();
    empty.add("<< /Type /Catalog /Pages 2 0 R >>");
    empty.add("<< /Type /Pages /Kids [] /Count 0 >>");
    workflow_error(
        combine_documents(&[
            SourceDocument {
                name: "A.pdf",
                pdf: &a,
            },
            SourceDocument {
                name: "Empty.pdf",
                pdf: &empty.build(1),
            },
        ]),
        "has no pages",
    );
}

#[test]
fn the_50_mb_limit_applies_to_the_documents_together() {
    // Two documents of 26 MB each: neither is too large, together they are. Refused before
    // anything is parsed.
    let mut big = container::make_sample_pdf("Large scan");
    big.resize(26 * 1024 * 1024, b' ');
    let err = combine_documents(&[
        SourceDocument {
            name: "Scan 1.pdf",
            pdf: &big,
        },
        SourceDocument {
            name: "Scan 2.pdf",
            pdf: &big,
        },
    ])
    .unwrap_err();
    assert!(matches!(err, SignPdfError::TooLarge(_)), "{err}");
    assert!(
        err.to_string()
            .contains("the documents together are 52.0 MB"),
        "{err}"
    );
    assert!(err.to_string().contains("50 MB"), "{err}");

    // Prepare refuses a source over the limit before it parses it.
    let mut huge = container::make_sample_pdf("Huge");
    huge.resize(MAX_ENVELOPE_BYTES + 1, b' ');
    let (key, req) = common::two_signer_request(&huge);
    let err = prepare(&huge, &req, &key).unwrap_err();
    assert!(matches!(err, SignPdfError::TooLarge(_)), "{err}");
}

/// The three documents combined and prepared for Alice (her signature on the agreement) and Bob
/// (a text field on Schedule A, his signature on Schedule B), sequentially.
fn prepared_envelope() -> (Vec<u8>, Vec<EnvelopeDocument>) {
    let (a, b) = three();
    let combined = combine_documents(&sources(&a, &b)).unwrap();
    let (key, mut req) = prepare_request(
        &combined.pdf,
        vec![
            spec("s1", "Alice", "alice@example.com", 1),
            spec("s2", "Bob", "bob@example.com", 2),
        ],
        vec![
            sig_field("f1", "s1", 0),
            field("t2", "s2", FieldType::Text, 2, 120.0),
            sig_field("f2", "s2", 3),
        ],
        SigningOrder::Sequential,
    );
    req.documents = combined.documents.clone();
    let prepared = prepare(&combined.pdf, &req, &key).unwrap();
    (prepared, combined.documents)
}

fn signed_envelope() -> (Vec<u8>, Vec<EnvelopeDocument>) {
    let (prepared, index) = prepared_envelope();
    let (ka, ra) = signer_request("alice@example.com", &prepared, "");
    let after_alice = sign(&prepared, &ka, &ra).unwrap();
    let (kb, mut rb) = signer_request("bob@example.com", &after_alice, "");
    rb.field_values = vec![("t2".into(), "Bob Builder Ltd".into())];
    (sign(&after_alice, &kb, &rb).unwrap(), index)
}

#[test]
fn an_envelope_of_several_documents_is_prepared_signed_and_verified() {
    let (prepared, index) = prepared_envelope();
    let env = workflow::read_envelope(&prepared).unwrap();
    assert_eq!(env.schema_version, signpdf_core::SCHEMA_VERSION);
    assert_eq!(env.documents, index);
    assert_eq!(env.document_of_page(2), Some(1));
    assert_eq!(env.document_of_page(4), None);
    assert!(env.audit_log[0].details.contains("(3 documents)"));

    let report = verify(&prepared, &trust()).unwrap();
    assert!(report.integrity_ok, "{:?}", report.messages);

    let (signed, _) = signed_envelope();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert!(report.complete);
    let env = report.envelope.as_ref().unwrap();
    assert_eq!(env.documents, index);
    assert_eq!(
        env.fields
            .iter()
            .find(|f| f.id == "t2")
            .unwrap()
            .value
            .as_deref(),
        Some("Bob Builder Ltd")
    );

    // The certificate of completion lists the documents.
    let cert = certificate::render(&report);
    // (Parentheses are escaped in the page's text strings.)
    for line in [
        "Documents: 3, signed together as one PDF",
        r"1. Agreement.pdf \(pages 1-2; original file SHA-256",
        r"2. Schedule A.pdf \(page 3;",
        r"3. Schedule B.pdf \(page 4;",
    ] {
        assert!(contains(&cert, line), "certificate lacks '{line}'");
    }
}

#[test]
fn prepare_refuses_an_index_that_does_not_cover_the_pdf() {
    let (a, b) = three();
    let combined = combine_documents(&sources(&a, &b)).unwrap();
    let (key, mut req) = common::two_signer_request(&combined.pdf);
    let mut wrong = combined.documents.clone();
    wrong[2].page_count = 2;
    req.documents = wrong;
    workflow_error(
        prepare(&combined.pdf, &req, &key),
        "covers 5 page(s), but the PDF has 4",
    );
    let mut gap = combined.documents.clone();
    gap[1].first_page = 3;
    req.documents = gap;
    workflow_error(prepare(&combined.pdf, &req, &key), "starts at page index 3");
    let mut unnamed = combined.documents.clone();
    unnamed[0].name = String::new();
    req.documents = unnamed;
    workflow_error(prepare(&combined.pdf, &req, &key), "needs a name");
    // An index of one entry names a single document.
    let (key, mut req) = common::two_signer_request(&a);
    req.documents = vec![EnvelopeDocument {
        name: "Agreement.pdf".into(),
        first_page: 0,
        page_count: 2,
        source_digest: sha256_hex(&a),
    }];
    let prepared = prepare(&a, &req, &key).unwrap();
    assert_eq!(
        workflow::read_envelope(&prepared).unwrap().documents.len(),
        1
    );
}

#[test]
fn a_signer_cannot_change_the_index() {
    let (prepared, _) = prepared_envelope();
    let (key, req) = signer_request("alice@example.com", &prepared, "");
    for tamper in [
        (&|e: &mut signpdf_core::Envelope| e.documents[1].name = "Schedule Z.pdf".into())
            as &dyn Fn(&mut signpdf_core::Envelope),
        &|e| e.documents[2].source_digest = "00".repeat(32),
        &|e| e.documents.clear(),
    ] {
        let signed = testing::sign_malicious(&prepared, &key, &req, false, tamper).unwrap();
        let report = verify(&signed, &trust()).unwrap();
        assert!(!report.integrity_ok);
        assert!(
            report
                .messages
                .iter()
                .any(|m| m.contains("prepared terms (title, documents")),
            "{:?}",
            report.messages
        );
    }
}

#[test]
fn an_index_that_does_not_match_the_pages_fails_verification() {
    let (a, b) = three();
    let combined = combine_documents(&sources(&a, &b)).unwrap();
    let (key, mut req) = common::two_signer_request(&combined.pdf);
    req.documents = combined.documents.clone();
    // A modified preparing client writes an index prepare would refuse.
    let prepared = testing::prepare_malicious(&combined.pdf, &req, &key, &|e| {
        e.documents[0].page_count = 1;
    })
    .unwrap();
    let report = verify(&prepared, &trust()).unwrap();
    assert!(!report.integrity_ok);
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("the documents index does not match the document")),
        "{:?}",
        report.messages
    );
}

/// The annotations of `page`, resolved.
fn annotations(doc: &Document, page: ObjectId) -> Vec<Dictionary> {
    match doc.get_dictionary(page).unwrap().get(b"Annots") {
        Ok(a) => a
            .as_array()
            .unwrap()
            .iter()
            .map(|a| dict(doc, a).clone())
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn subtype(a: &Dictionary) -> String {
    String::from_utf8_lossy(a.get(b"Subtype").unwrap().as_name().unwrap()).to_string()
}

fn crop(doc: &Document, page: ObjectId) -> Vec<f32> {
    doc.get_dictionary(page)
        .unwrap()
        .get(b"CropBox")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_float().unwrap())
        .collect()
}

#[test]
fn a_convenience_copy_holds_one_document_marked_as_a_copy() {
    let (signed, index) = signed_envelope();
    let env = workflow::read_envelope(&signed).unwrap();

    // The agreement: its two pages, Alice's signature box and the document id drawn as fixed
    // stamps, a banner strip added above the first page only.
    let copy = extract_document(&signed, 0).unwrap();
    let doc = Document::load_mem(&copy).unwrap();
    let p = pages(&doc);
    assert_eq!(p.len(), 2);
    assert_eq!(crop(&doc, p[0]), [0.0, 0.0, 595.0, 872.0]);
    assert!(
        doc.get_dictionary(p[1]).unwrap().get(b"CropBox").is_err()
            || crop(&doc, p[1]) == [0.0, 0.0, 595.0, 842.0]
    );
    let first = doc.get_page_content(p[0]).unwrap();
    assert!(contains(
        &first,
        "Convenience copy - not the signed original"
    ));
    assert!(contains(
        &first,
        &format!(
            "Document 1 of 3: Agreement.pdf - SignPDF envelope {}",
            env.envelope_id
        )
    ));
    assert!(
        contains(&first, "Agreement page 1"),
        "the page's own content stays"
    );
    assert!(!contains(
        &doc.get_page_content(p[1]).unwrap(),
        "Convenience copy"
    ));
    let kinds: Vec<String> = annotations(&doc, p[0]).iter().map(subtype).collect();
    // The agreement's own link, its form field (with an appearance), the document-id stamp and
    // Alice's visible signature box; her invisible preparer widget is gone.
    assert!(kinds.contains(&"Link".to_string()), "{kinds:?}");
    assert!(kinds.contains(&"Stamp".to_string()), "{kinds:?}");
    assert!(!kinds.contains(&"Widget".to_string()), "{kinds:?}");
    for a in annotations(&doc, p[0]) {
        if subtype(&a) == "Stamp" {
            assert_eq!(a.get(b"F").unwrap().as_i64().unwrap(), 196);
            assert!(a.has(b"AP"));
        }
    }

    // No form, no signature, no envelope, nothing of the other documents.
    let root = catalog(&doc);
    assert!(!root.has(b"AcroForm") && !root.has(b"Names") && !root.has(b"Outlines"));
    assert!(pades::pades_verify(&copy).unwrap().is_empty());
    assert!(pades::read_attachment(&copy, ENVELOPE_NAME).is_err());
    assert!(!contains(&copy, "Schedule A: fees"));
    assert!(workflow::read_envelope(&copy).is_err());

    // Schedule A is shown rotated: its strip goes on the side shown at the top (the left edge of
    // the unrotated page). Bob's text value stays; the field without an appearance is dropped.
    let copy = extract_document(&signed, 1).unwrap();
    let doc = Document::load_mem(&copy).unwrap();
    let p = pages(&doc);
    assert_eq!(p.len(), 1);
    assert_eq!(crop(&doc, p[0]), [-30.0, 0.0, 612.0, 792.0]);
    let kinds: Vec<String> = annotations(&doc, p[0]).iter().map(subtype).collect();
    assert_eq!(kinds, ["Link", "FreeText"], "{kinds:?}");
    assert!(contains(
        &doc.get_page_content(p[0]).unwrap(),
        "Document 2 of 3: Schedule A.pdf"
    ));
    assert_eq!(pades::page_geometry(&copy).unwrap()[0].rotate, 90);

    // Schedule B: Bob's signature box.
    let copy = extract_document(&signed, 2).unwrap();
    let doc = Document::load_mem(&copy).unwrap();
    let kinds: Vec<String> = annotations(&doc, pages(&doc)[0])
        .iter()
        .map(subtype)
        .collect();
    assert_eq!(kinds, ["Stamp"]);

    // Its file name says what it is.
    assert_eq!(
        signpdf_core::convenience_copy_name(&index[1]),
        "Schedule A (convenience copy - verify the combined file).pdf"
    );

    workflow_error(
        extract_document(&signed, 3),
        "no document 4 in this envelope, which has 3",
    );
    let a = agreement();
    let (key, req) = common::two_signer_request(&a);
    let single = prepare(&a, &req, &key).unwrap();
    workflow_error(extract_document(&single, 0), "no document index");
}

#[test]
fn real_world_documents_combine_prepare_and_sign() {
    let combined = combine_documents(&[
        SourceDocument {
            name: "Plain.pdf",
            pdf: REAL_PLAIN,
        },
        SourceDocument {
            name: "Form.pdf",
            pdf: REAL_ACROFORM,
        },
    ])
    .unwrap();
    // The second document's form field survives, in the combined form.
    let doc = Document::load_mem(&combined.pdf).unwrap();
    let form = dict(&doc, catalog(&doc).get(b"AcroForm").unwrap());
    let names: Vec<String> = form
        .get(b"Fields")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|f| text(dict(&doc, f).get(b"T").unwrap()))
        .collect();
    assert_eq!(names, ["existing_name"]);

    let (key, mut req) = prepare_request(
        &combined.pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![sig_field("f1", "s1", 1)],
        SigningOrder::Sequential,
    );
    req.documents = combined.documents.clone();
    let prepared = prepare(&combined.pdf, &req, &key).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign(&prepared, &k, &r).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    // Each document can be cut out again.
    for i in 0..2 {
        let copy = extract_document(&signed, i).unwrap();
        assert_eq!(pades::page_geometry(&copy).unwrap().len(), 1);
    }
}

#[test]
fn the_wire_form_frames_the_index_before_the_pdf() {
    let (a, b) = three();
    let manifest: documents::wire::Manifest = serde_json::from_value(serde_json::json!({
        "documents": [
            {"name": "Agreement.pdf", "len": a.len()},
            {"name": "Schedule A.pdf", "len": b.len()},
        ]
    }))
    .unwrap();
    let mut data = a.clone();
    data.extend_from_slice(&b);
    let docs = documents::wire::split(&manifest, &data).unwrap();
    let combined = combine_documents(&docs).unwrap();
    let framed = documents::wire::frame(&combined).unwrap();
    let len = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
    let index: serde_json::Value = serde_json::from_slice(&framed[4..4 + len]).unwrap();
    assert_eq!(index["documents"][1]["name"], "Schedule A.pdf");
    assert_eq!(index["documents"][1]["first_page"], 2);
    assert_eq!(&framed[4 + len..], combined.pdf.as_slice());

    assert!(documents::wire::split(&manifest, &data[1..]).is_err());
    let mut longer = data.clone();
    longer.push(b'x');
    assert!(documents::wire::split(&manifest, &longer)
        .unwrap_err()
        .contains("add up to"));
}

#[test]
fn hostile_inputs_are_refused_or_combined_without_panicking() {
    let a = agreement();
    // Truncations and byte flips of a valid document: an error or a PDF, never a panic.
    for cut in [10, 100, a.len() / 2, a.len() - 10] {
        let _ = combine_documents(&[
            SourceDocument {
                name: "A.pdf",
                pdf: &a,
            },
            SourceDocument {
                name: "Cut.pdf",
                pdf: &a[..cut],
            },
        ]);
    }
    // A page tree that refers to itself, a dangling reference and an outline that loops.
    let mut p = Pdf::default();
    p.add("<< /Type /Catalog /Pages 2 0 R /Outlines 5 0 R >>");
    p.add("<< /Type /Pages /Kids [3 0 R 2 0 R] /Count 2 >>");
    p.add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 99 0 R >>");
    p.add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    p.add("<< /Type /Outlines /First 6 0 R /Last 6 0 R >>");
    p.add("<< /Title (Loop) /Parent 5 0 R /Next 6 0 R /First 6 0 R /Dest (nowhere) >>");
    let odd = p.build(1);
    let combined = combine_documents(&[
        SourceDocument {
            name: "A.pdf",
            pdf: &a,
        },
        SourceDocument {
            name: "Odd.pdf",
            pdf: &odd,
        },
    ])
    .unwrap();
    assert_eq!(combined.documents[1].page_count, 1);
    let doc = Document::load_mem(&combined.pdf).unwrap();
    let last = *pages(&doc).last().unwrap();
    // The dangling content reference does not point into another document.
    assert_eq!(
        doc.get_dictionary(last).unwrap().get(b"Contents").unwrap(),
        &Object::Null
    );
    // The looping bookmark sits under its document's bookmark, its loops cut and its named
    // destination (which names nothing) gone.
    let outlines = dict(&doc, catalog(&doc).get(b"Outlines").unwrap());
    let odd = dict(&doc, outlines.get(b"Last").unwrap());
    assert_eq!(text(odd.get(b"Title").unwrap()), "Odd.pdf");
    assert_eq!(odd.get(b"Count").unwrap().as_i64().unwrap(), -1);
    let looping = dict(&doc, odd.get(b"First").unwrap());
    assert_eq!(text(looping.get(b"Title").unwrap()), "Loop");
    for key in [&b"Next"[..], b"First", b"Count", b"Dest"] {
        assert!(!looping.has(key), "{}", String::from_utf8_lossy(key));
    }
}

#[test]
fn the_key_for_a_combined_document_is_bound_to_the_combination() {
    // The preparer's sign-in nonce binds the combined PDF, not any one document.
    let (a, b) = three();
    let combined = combine_documents(&sources(&a, &b)).unwrap();
    let (key, mut req) = common::two_signer_request(&a);
    req.documents = combined.documents.clone();
    let err = prepare(&combined.pdf, &req, &key).unwrap_err();
    assert!(err.to_string().contains("nonce"), "{err}");
}

/// xorshift64*, for reproducible mutations without a dependency (as `robustness.rs`).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    /// `doc` with one to three corruptions: a flipped bit, a digit changed (offsets, lengths,
    /// object numbers), a truncation or a deleted slice.
    fn mutate(&mut self, doc: &[u8]) -> Vec<u8> {
        let mut doc = doc.to_vec();
        for _ in 0..1 + self.below(3) {
            if doc.is_empty() {
                break;
            }
            match self.below(4) {
                0 => {
                    let p = self.below(doc.len());
                    doc[p] ^= 1 << self.below(8);
                }
                1 => {
                    let digits: Vec<usize> = (0..doc.len())
                        .filter(|&j| doc[j].is_ascii_digit())
                        .collect();
                    if let Some(&p) = digits.get(self.below(digits.len())) {
                        doc[p] = b'0' + self.below(10) as u8;
                    }
                }
                2 => {
                    let p = self.below(doc.len());
                    doc.truncate(p.max(1));
                }
                _ => {
                    let a = self.below(doc.len());
                    let b = (a + self.below(64)).min(doc.len());
                    doc.drain(a..b);
                }
            }
        }
        doc
    }
}

#[test]
fn mutated_documents_never_panic_combine_or_extract() {
    let (a, b) = three();
    let (signed, _) = signed_envelope();
    let iterations = std::env::var("SIGNPDF_MUTATIONS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(150, |n| n / 10);
    let mut rng = Rng(0xD0C5_0FE1_1EC7);
    for i in 0..iterations {
        let (ma, mb) = (rng.mutate(&a), rng.mutate(&b));
        let outcome = std::panic::catch_unwind(|| combine_documents(&sources(&ma, &mb)));
        match outcome {
            Err(_) => panic!("combine panicked on mutation #{i}"),
            Ok(Ok(combined)) => {
                // Whatever came out is a PDF the engine reads, with the pages its index says.
                let pages = pades::page_geometry(&combined.pdf).unwrap_or_else(|e| {
                    panic!("mutation #{i}: the combination does not parse: {e}")
                });
                documents::check_index(&combined.documents, pages.len() as u32)
                    .unwrap_or_else(|e| panic!("mutation #{i}: {e}"));
            }
            Ok(Err(_)) => {}
        }
        let doc = rng.mutate(&signed);
        let index = rng.below(4);
        if std::panic::catch_unwind(|| extract_document(&doc, index)).is_err() {
            panic!("extract panicked on mutation #{i}");
        }
    }
}

#[test]
fn a_convenience_copy_holds_nothing_of_the_other_documents() {
    // One PDF whose first page links to its second, given an index of two one-page documents:
    // the copy of the first must not carry the second page, even through the link.
    let mut p = Pdf::default();
    p.add("<< /Type /Catalog /Pages 2 0 R >>");
    p.add("<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 612 792] >>");
    p.add(
        "<< /Type /Page /Parent 2 0 R /Contents 5 0 R /Resources << /Font << /F1 7 0 R >> >> \
         /Annots [<< /Type /Annot /Subtype /Link /Rect [72 600 200 620] /Dest [4 0 R /Fit] >>] >>",
    );
    p.add("<< /Type /Page /Parent 2 0 R /Contents 6 0 R /Resources << /Font << /F1 7 0 R >> >> >>");
    p.add(Pdf::stream("", "BT /F1 18 Tf 72 700 Td (First part) Tj ET"));
    p.add(Pdf::stream(
        "",
        "BT /F1 18 Tf 72 700 Td (Second part only) Tj ET",
    ));
    p.add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    let pdf = p.build(1);
    let (key, mut req) = common::two_signer_request(&pdf);
    req.documents = vec![
        EnvelopeDocument {
            name: "First.pdf".into(),
            first_page: 0,
            page_count: 1,
            source_digest: "aa".repeat(32),
        },
        EnvelopeDocument {
            name: "Second.pdf".into(),
            first_page: 1,
            page_count: 1,
            source_digest: "bb".repeat(32),
        },
    ];
    let prepared = prepare(&pdf, &req, &key).unwrap();
    let copy = extract_document(&prepared, 0).unwrap();
    assert!(!contains(&copy, "Second part only"));
    let doc = Document::load_mem(&copy).unwrap();
    assert_eq!(pages(&doc).len(), 1);
    let link = annotations(&doc, pages(&doc)[0])
        .into_iter()
        .find(|a| subtype(a) == "Link")
        .unwrap();
    assert_eq!(
        link.get(b"Dest").unwrap().as_array().unwrap()[0],
        Object::Null
    );
    let copy = extract_document(&prepared, 1).unwrap();
    assert!(contains(&copy, "Second part only") && !contains(&copy, "First part"));
}

#[test]
fn usage_rights_are_dropped_and_a_certified_document_is_refused() {
    let (a, _) = three();
    let with_perms = |perms: &str| {
        let mut p = Pdf::default();
        p.add(format!(
            "<< /Type /Catalog /Pages 2 0 R /Perms << {perms} 5 0 R >> >>"
        ));
        p.add("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        p.add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>");
        p.add(Pdf::stream("", "0 0 1 rg 72 72 100 100 re f"));
        p.add(
            "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached \
             /ByteRange [0 10 20 10] /Contents <00> >>",
        );
        p.build(1)
    };
    // Usage rights unlock a viewer's features; they go, and the document combines.
    let extended = with_perms("/UR3");
    let combined = combine_documents(&[
        SourceDocument {
            name: "A.pdf",
            pdf: &a,
        },
        SourceDocument {
            name: "Form.pdf",
            pdf: &extended,
        },
    ])
    .unwrap();
    assert!(!contains(&combined.pdf, "/Perms") && !contains(&combined.pdf, "adbe.pkcs7"));
    // A certification is a signature of the document's author: refused.
    let certified = with_perms("/DocMDP");
    workflow_error(
        combine_documents(&[
            SourceDocument {
                name: "A.pdf",
                pdf: &a,
            },
            SourceDocument {
                name: "Certified.pdf",
                pdf: &certified,
            },
        ]),
        "document 2 ('Certified.pdf') is certified",
    );
}
