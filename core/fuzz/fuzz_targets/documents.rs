//! Combining documents into one envelope and cutting one back out: must never panic. The input
//! is split into two documents at the first `%%SPLIT%%`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use signpdf_core::documents::{combine, extract, SourceDocument};

fuzz_target!(|data: &[u8]| {
    const SPLIT: &[u8] = b"%%SPLIT%%";
    let (a, b) = match data.windows(SPLIT.len()).position(|w| w == SPLIT) {
        Some(i) => (&data[..i], &data[i + SPLIT.len()..]),
        None => (data, &data[..0]),
    };
    let mut docs = vec![SourceDocument {
        name: "a.pdf",
        pdf: a,
    }];
    if !b.is_empty() {
        docs.push(SourceDocument {
            name: "b.pdf",
            pdf: b,
        });
    }
    if let Ok(combined) = combine(&docs) {
        for i in 0..combined.documents.len() {
            let _ = extract(&combined.pdf, i);
        }
    }
    // A document read as an already-combined envelope.
    let _ = extract(data, 0);
});
