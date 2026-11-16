//! The document-ID stamp leaves the first page's own text visible: it goes where the page draws
//! nothing (a footer 36 pt from the bottom, at the left, in the centre or at the right, keeps
//! every letter), and from envelope schema version 11 its box is as wide as the id it draws.
//! Where the stamp sits is not checked by the verifier, so every placement verifies.

mod common;

use common::*;
use signpdf_core::{prepare, read_envelope, sign, verify, SigningOrder};

/// An A4 page with a title and the footer lines `footer` (`x`, `y`, text) in 9 pt Helvetica.
fn page_with_footer(footer: &[(f32, f32, &str)]) -> Vec<u8> {
    let mut content = String::from("BT /F1 24 Tf 72 760 Td (Photo and video consent form) Tj ET\n");
    for (x, y, text) in footer {
        content.push_str(&format!("BT /F1 9 Tf {x} {y} Td ({text}) Tj ET\n"));
    }
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] \
         /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            .to_string(),
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
    let xref = buf.len();
    buf.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for off in offsets {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    buf
}

/// The `/Rect` of the document-ID stamp in `pdf`.
fn stamp_rect(pdf: &[u8]) -> [f32; 4] {
    let text = String::from_utf8_lossy(pdf);
    let at = text.find("/Subtype /Stamp /Rect [").expect("no stamp");
    let rest = &text[at + "/Subtype /Stamp /Rect [".len()..];
    let nums: Vec<f32> = rest[..rest.find(']').unwrap()]
        .split_whitespace()
        .map(|n| n.parse().unwrap())
        .collect();
    [nums[0], nums[1], nums[2], nums[3]]
}

/// The box a 9 pt Helvetica line at (`x`, `y`) inks, generously (0.6 em per letter).
fn footer_box(x: f32, y: f32, text: &str) -> [f32; 4] {
    [
        x,
        y - 0.25 * 9.0,
        x + text.len() as f32 * 0.6 * 9.0,
        y + 0.9 * 9.0,
    ]
}

fn overlaps(a: [f32; 4], b: [f32; 4]) -> bool {
    a[0] < b[2] && b[0] < a[2] && a[1] < b[3] && b[1] < a[3]
}

fn prepare_and_sign(pdf: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (key, mut req) = prepare_request(
        pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![sig_field("sig", "s1", 0)],
        SigningOrder::Sequential,
    );
    req.verify_at = Some("dev.example.com/verify".into());
    let prepared = prepare(pdf, &req, &key).unwrap();
    let (key, req) = signer_request("alice@example.com", &prepared, "s1");
    let signed = sign(&prepared, &key, &req).unwrap();
    (prepared, signed)
}

#[test]
fn the_stamp_never_covers_a_footer() {
    let left = (72.0, 36.0, "Photo and video consent form");
    let centre = (240.0, 36.0, "Reference GAL-2026-0042");
    let right = (482.0, 36.0, "Page 1 of 2");
    for footer in [
        vec![left],
        vec![centre],
        vec![right],
        vec![left, right],
        vec![left, centre, right],
    ] {
        let (prepared, signed) = prepare_and_sign(&page_with_footer(&footer));
        let stamp = stamp_rect(&prepared);
        for (x, y, text) in &footer {
            assert!(
                !overlaps(stamp, footer_box(*x, *y, text)),
                "the stamp {stamp:?} covers '{text}'"
            );
        }
        // Inside the page, clear of the edges.
        assert!(stamp[0] >= 12.0 && stamp[1] >= 12.0 && stamp[2] <= 583.0 && stamp[3] <= 830.0);
        let report = verify(&signed, &trust()).unwrap();
        assert!(report.valid, "{footer:?}: {:?}", report.messages);
    }
}

#[test]
fn an_empty_bottom_keeps_the_stamp_in_the_lower_left_corner() {
    let (prepared, _) = prepare_and_sign(&page_with_footer(&[]));
    let stamp = stamp_rect(&prepared);
    assert_eq!((stamp[0], stamp[1]), (18.0, 18.0));
}

#[test]
fn the_stamp_box_holds_the_whole_id() {
    let (prepared, _) = prepare_and_sign(&page_with_footer(&[]));
    let env = read_envelope(&prepared).unwrap();
    let stamp = stamp_rect(&prepared);
    // Helvetica's widths (1/1000 em) of what the line holds: "SignPDF Document " is 9114 units;
    // hex digits are 556, but for "c" (500) and "f" (278). At 8 pt, plus 4 pt either side.
    let units: u32 = 9114
        + env
            .envelope_id
            .chars()
            .map(|c| match c {
                'c' => 500,
                'f' => 278,
                _ => 556,
            })
            .sum::<u32>();
    let expected = (units as f32 * 8.0 / 1000.0 + 8.0) * 100.0;
    let expected = expected.ceil() / 100.0;
    let width = stamp[2] - stamp[0];
    assert!(
        (width - expected).abs() < 0.02,
        "{}: {width} != {expected}",
        env.envelope_id
    );
}
