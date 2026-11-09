//! Many signers on one envelope (up to 200).
//!
//! `many_signers_profile` is a local benchmark, ignored by default:
//!
//! ```text
//! cargo test --release -p signpdf-core --test many_signers -- --ignored --nocapture
//! SIGNPDF_SIGNERS=200 cargo test --release ...   # the count (default 200)
//! ```
//!
//! It prepares a document with one signature field a signer (twelve a page, so 17 pages for
//! 200), signs it once per signer in any order, and prints, every 20 revisions, what the last
//! increment holds (its size, of which the embedded envelope) and how long verifying the whole
//! document takes. The default test runs the same flow for a few signers and checks the
//! bounds this benchmark is about, so a regression shows in `cargo test`.

mod common;

use std::time::Instant;

use common::*;
use signpdf_core::{prepare, sign, verify, Field, FieldType, Rect, SigningOrder};

const FIELDS_PER_PAGE: usize = 12;

/// A source PDF with `pages` plain pages.
fn source(pages: usize) -> Vec<u8> {
    let mut objects: Vec<String> = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".into(),
        String::new(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into(),
    ];
    let mut kids = vec![];
    for p in 1..=pages {
        let page_id = objects.len() + 1;
        kids.push(format!("{page_id} 0 R"));
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>",
            page_id + 1
        ));
        let content = format!("BT /F1 18 Tf 72 720 Td (Services agreement, page {p}) Tj ET\n");
        objects.push(format!(
            "<< /Length {} >>\nstream\n{content}endstream",
            content.len()
        ));
    }
    objects[1] = format!(
        "<< /Type /Pages /Kids [{}] /Count {pages} >>",
        kids.join(" ")
    );
    let mut buf: Vec<u8> = b"%PDF-1.7\n".to_vec();
    let mut offsets = vec![];
    for (i, body) in objects.iter().enumerate() {
        offsets.push(buf.len());
        buf.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }
    let xref = buf.len();
    let size = objects.len() + 1;
    buf.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
    for off in offsets {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    buf
}

fn email(i: usize) -> String {
    format!("signer{i}@example.com")
}

/// The document prepared for `n` signers, each with one signature field.
fn prepared(n: usize) -> Vec<u8> {
    let pdf = source(n.div_ceil(FIELDS_PER_PAGE));
    let signers = (0..n)
        .map(|i| spec(&format!("s{i}"), &format!("Signer {i}"), &email(i), 1))
        .collect();
    let fields: Vec<Field> = (0..n)
        .map(|i| Field {
            rect: Rect {
                x: 72.0,
                y: 80.0 + 60.0 * (i % FIELDS_PER_PAGE) as f64,
                w: 200.0,
                h: 40.0,
            },
            ..field(
                &format!("sig-s{i}"),
                &format!("s{i}"),
                FieldType::Signature,
                (i / FIELDS_PER_PAGE) as u32,
                0.0,
            )
        })
        .collect();
    let (key, req) = prepare_request(&pdf, signers, fields, SigningOrder::Parallel);
    prepare(&pdf, &req, &key).unwrap()
}

fn sign_as(pdf: &[u8], i: usize) -> Vec<u8> {
    let (key, req) = signer_request(&email(i), pdf, &format!("s{i}"));
    sign(pdf, &key, &req).unwrap()
}

/// The last envelope embedded in `increment`: its size (`/Params << /Size n >>`) and the bytes
/// it takes in the file (`/Length`, smaller when it is compressed).
fn envelope_bytes(increment: &[u8]) -> (usize, usize) {
    let text = String::from_utf8_lossy(increment);
    let Some(at) = text.rfind("/Type /EmbeddedFile") else {
        return (0, 0);
    };
    let rest = &text[at..];
    let number_after = |key: &str| -> usize {
        rest.find(key)
            .and_then(|k| {
                rest[k + key.len()..]
                    .split(|c: char| !c.is_ascii_digit())
                    .next()?
                    .parse()
                    .ok()
            })
            .unwrap_or(0)
    };
    (number_after("/Size "), number_after("/Length "))
}

/// A revision carries its signer's work, not a copy of everything before it at full
/// size. Thirteen signers (two pages of fields); each revision's envelope is compressed and its
/// signature reserves room for its own CMS (about 2 KB of hex, where 16 KB used to be).
#[test]
fn a_dozen_signers_keep_their_revisions_small() {
    let n = 13;
    let mut pdf = prepared(n);
    for i in 0..n {
        let next = sign_as(&pdf, i);
        let increment = &next[pdf.len()..];
        let (size, stored) = envelope_bytes(increment);
        assert!(stored * 2 < size, "revision {}: {stored} of {size}", i + 1);
        let text = String::from_utf8_lossy(increment);
        let contents = text.rfind("/Contents <").unwrap() + 11;
        let reserved = text[contents..].find('>').unwrap();
        assert!(reserved <= 4096, "revision {}: {reserved}", i + 1);
        // About 12 KB at the 13th signer; 50 KB before.
        assert!(
            increment.len() < 20_000,
            "revision {}: {}",
            i + 1,
            increment.len()
        );
        pdf = next;
    }
    let report = verify(&pdf, &trust()).unwrap();
    assert!(report.valid && report.complete, "{:?}", report.messages);
    assert_eq!(report.signatures.len(), n);
}

#[test]
#[ignore = "a local benchmark: cargo test --release --test many_signers -- --ignored --nocapture"]
fn many_signers_profile() {
    let n: usize = std::env::var("SIGNPDF_SIGNERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let started = Instant::now();
    let mut pdf = prepared(n);
    println!(
        "prepared for {n} signers: {} KB in {:.2} s",
        pdf.len() / 1024,
        started.elapsed().as_secs_f64()
    );
    let mut sign_total = 0.0;
    for i in 0..n {
        let before = pdf.len();
        let started = Instant::now();
        let next = sign_as(&pdf, i);
        sign_total += started.elapsed().as_secs_f64();
        let rev = i + 1;
        if rev % 20 == 0 || rev == n || rev == 1 {
            let inc = &next[before..];
            let started = Instant::now();
            let report = verify(&next, &trust()).unwrap();
            let verify_s = started.elapsed().as_secs_f64();
            assert!(report.valid, "{:?}", report.messages);
            let (size, stored) = envelope_bytes(inc);
            println!(
                "revision {rev:>3}: increment {:>6} B (envelope {size:>6} B, stored in \
                 {stored:>6} B), document {:>6} KB, verified in {verify_s:.2} s, signed in \
                 {:.2} s",
                inc.len(),
                next.len() / 1024,
                sign_total / rev as f64,
            );
        }
        pdf = next;
    }
    println!(
        "{n} signatures in {sign_total:.1} s; the final document is {} KB",
        pdf.len() / 1024
    );
    if let Ok(path) = std::env::var("SIGNPDF_SAVE") {
        std::fs::write(path, &pdf).unwrap();
    }
}

/// Verify a document saved by the benchmark (`SIGNPDF_SAVE=FILE`), from any build, and print the
/// time: `SIGNPDF_VERIFY=FILE cargo test --release --test many_signers -- --ignored --nocapture
/// verify_a_saved_document`.
#[test]
#[ignore = "a local benchmark: needs SIGNPDF_VERIFY"]
fn verify_a_saved_document() {
    let pdf = std::fs::read(std::env::var("SIGNPDF_VERIFY").unwrap()).unwrap();
    // The test issuer's key is made anew in every run: pin the one the document carries.
    let env = signpdf_core::read_envelope(&pdf).unwrap();
    let jwks: signpdf_core::oidc::Jwks =
        serde_json::from_str(&format!("{{\"keys\":[{}]}}", env.created_by_idp_jwk)).unwrap();
    let mut trust = signpdf_core::TrustStore::empty();
    trust.add_jwks(ISSUER, &jwks);
    trust.add_audience(ISSUER, AUDIENCE);
    for _ in 0..2 {
        let started = Instant::now();
        let report = verify(&pdf, &trust).unwrap();
        assert!(report.valid, "{:?}", report.messages);
        println!(
            "{} KB, {} signatures: verified in {:.2} s",
            pdf.len() / 1024,
            report.signatures.len(),
            started.elapsed().as_secs_f64()
        );
    }
}
