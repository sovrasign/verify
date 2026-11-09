//! Deterministic mutation testing (a stable-Rust complement to the cargo-fuzz targets in
//! `core/fuzz`): thousands of corrupted variants of a real signed document must never panic the
//! verifier, and must never verify as valid unless the corruption is a no-op.

mod common;

use common::*;
use signpdf_core::ltv::testing::{TestCa, TestStatus};
use signpdf_core::{
    add_document_timestamp, add_validation_data, container, prepare, revocation_targets, sign,
    sign_with, verify, TrustStore,
};

/// xorshift64* — reproducible without a dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn signed_document() -> Vec<u8> {
    let pdf = container::make_sample_pdf("Robustness corpus");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    sign(&prepared, &k, &r).unwrap()
}

#[test]
fn mutated_documents_never_panic_and_never_verify() {
    let original = signed_document();
    let trust = trust();
    assert!(verify(&original, &trust).unwrap().valid);

    let mut rng = Rng(0x5EED_5EED_1234_5678);
    let iterations = std::env::var("SIGNPDF_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);
    for i in 0..iterations {
        let mut doc = original.clone();
        let n = 1 + rng.below(4);
        for _ in 0..n {
            // An earlier mutation may have left nothing to mutate.
            if doc.is_empty() {
                break;
            }
            match rng.below(5) {
                // flip a random byte
                0 => {
                    let p = rng.below(doc.len());
                    doc[p] ^= 1 << rng.below(8);
                }
                // replace a digit with another digit (targets offsets, ByteRanges, lengths)
                1 => {
                    let digits: Vec<usize> = (0..doc.len())
                        .filter(|&j| doc[j].is_ascii_digit())
                        .collect();
                    if let Some(&p) = digits.get(rng.below(digits.len().max(1))) {
                        doc[p] = b'0' + rng.below(10) as u8;
                    }
                }
                // truncate
                2 => {
                    let p = rng.below(doc.len());
                    doc.truncate(p.max(1));
                }
                // duplicate a slice (an extra incremental-looking chunk)
                3 => {
                    let a = rng.below(doc.len());
                    let b = (a + rng.below(512)).min(doc.len());
                    let chunk = doc[a..b].to_vec();
                    doc.extend_from_slice(&chunk);
                }
                // delete a slice
                _ => {
                    let a = rng.below(doc.len());
                    let b = (a + rng.below(64)).min(doc.len());
                    doc.drain(a..b);
                }
            }
        }
        if doc == original {
            continue;
        }
        // Cut back exactly to the end of an earlier revision: that is the earlier document, whole
        // (here the preparer's), not a corruption, and it may verify as what it is: with fewer
        // signatures than the original.
        let earlier_revision = doc.len() < original.len()
            && original.starts_with(&doc)
            && doc.trim_ascii_end().ends_with(b"%%EOF");
        let outcome = std::panic::catch_unwind(|| verify(&doc, &trust));
        match outcome {
            Err(_) => panic!("verifier panicked on mutation #{i}"),
            Ok(Ok(report)) if earlier_revision => {
                let signed = verify(&original, &trust).unwrap().signatures.len();
                assert!(
                    report.signatures.len() < signed,
                    "mutation #{i}: an earlier revision claims the original's signatures"
                );
            }
            Ok(Ok(report)) => {
                if report.valid {
                    let first = doc
                        .iter()
                        .zip(original.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(doc.len().min(original.len()));
                    let lo = first.saturating_sub(40);
                    panic!(
                        "mutation #{i} still verified as valid (len {} vs {}); first diff at {first}: \
                         original {:?} / mutated {:?}",
                        doc.len(),
                        original.len(),
                        String::from_utf8_lossy(&original[lo..(first + 40).min(original.len())]),
                        String::from_utf8_lossy(&doc[lo..(first + 40).min(doc.len())]),
                    );
                }
            }
            Ok(Err(_)) => {} // rejected outright (unparseable): fine
        }
    }
}

/// A completed document with signature timestamps, validation data and a document timestamp
/// (PAdES B-LTA), and a trust store that trusts its time-stamp authority's root.
fn sealed_document() -> (Vec<u8>, TrustStore) {
    let ca = TestCa::new("SignPDF Test Root");
    let tsa = ca.issue_tsa("SignPDF Test TSA");
    let mut trust = trust();
    trust.add_tsa_anchor(&ca.cert_der());
    let pdf = container::make_sample_pdf("Robustness corpus");
    let (pk, req) = two_signer_request(&pdf);
    let prepared = prepare(&pdf, &req, &pk).unwrap();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let alice = sign_with(&prepared, &k, &r, Some(&tsa)).unwrap();
    let (k, r) = signer_request("bob@example.com", &alice, "");
    let done = sign_with(&alice, &k, &r, Some(&tsa)).unwrap();
    let ocsps: Vec<Vec<u8>> = revocation_targets(&done, &trust)
        .unwrap()
        .iter()
        .map(|t| ca.ocsp_response(&t.cert, TestStatus::Good))
        .collect();
    let with_data = add_validation_data(&done, &trust, &ocsps, &[]).unwrap();
    (add_document_timestamp(&with_data, &tsa).unwrap(), trust)
}

#[test]
fn mutated_sealed_documents_never_panic_and_never_verify_with_trusted_evidence() {
    // Every byte of a sealed document is covered by its last document timestamp, except that
    // timestamp's own token: the authority's CMS, whose unsigned parts (the list of digest
    // algorithms, the certificates it carries, version numbers) can change without touching
    // what any signature or timestamp covers (docs/SECURITY_MODEL.md §7). A change there may
    // leave the document intact; any other change must not, or must at least cost a timestamp
    // its trust.
    let (original, trust) = sealed_document();
    let report = verify(&original, &trust).unwrap();
    assert!(report.valid && report.pades_level == "B-LTA", "{report:?}");
    let last = signpdf_core::pades_verify_all(&original)
        .unwrap()
        .document_timestamps
        .pop()
        .unwrap();
    let token_gap = last.byte_range[1] as usize..last.byte_range[2] as usize;
    let all_trusted = |r: &signpdf_core::VerificationReport| {
        r.signatures
            .iter()
            .all(|s| s.timestamp.as_ref().is_some_and(|t| t.is_trusted()))
            && r.document_timestamps
                .iter()
                .all(|d| d.timestamp.is_trusted())
    };

    let mut rng = Rng(0x0D0C_7157_A11F_0005);
    let iterations = std::env::var("SIGNPDF_MUTATIONS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(60, |n| n / 10);
    for i in 0..iterations {
        let mut doc = original.clone();
        // One byte flip anywhere: in the last revision half of the time, where the validation
        // data and the document timestamp are.
        let from = if rng.below(2) == 0 {
            original.len() * 9 / 10
        } else {
            0
        };
        let p = from + rng.below(doc.len() - from);
        doc[p] ^= 1 << rng.below(8);
        let outcome = std::panic::catch_unwind(|| verify(&doc, &trust));
        match outcome {
            Err(_) => panic!("verifier panicked on mutation #{i} (byte {p})"),
            Ok(Ok(report)) if report.valid && all_trusted(&report) && !token_gap.contains(&p) => {
                panic!(
                    "mutation #{i} (byte {p}) still verified with every timestamp trusted: {:?}",
                    report.pades_level
                )
            }
            _ => {}
        }
    }
}
