//! Increment-only signing and transfer.
//!
//! * `sign_increment` / `sign_for_timestamp_increment` return only the bytes a signature appends,
//!   so a host that uploads only the increment never holds the signed document (in a browser:
//!   about the document's size in memory instead of twice it).
//! * The signature-timestamp steps take the document and the increment apart
//!   (`increment_signature_timestamp_digest`, `embed_increment_signature_timestamp`).
//! * When the head moves, the holder sends only the bytes after the client's revision
//!   (`increment_after`) and the client checks them against the announced head
//!   (`check_increment`) before signing on top.
//! * Signing and verifying hash the document once (`DocumentDigests`); the digests they report and
//!   record are the same as hashing the bytes directly.

mod common;

use common::*;
use signpdf_core::crypto::sha256_hex;
use signpdf_core::timestamp::{build_request, parse_response, testing::TestTsa};
use signpdf_core::{
    appended, check_increment, container, embed_increment_signature_timestamp, increment_after,
    increment_signature_timestamp_digest, prepare, prepare_document_timestamp, read_envelope, sign,
    sign_for_timestamp_increment, sign_increment, signature_timestamp_digest, verify, Head,
    SignPdfError, TimestampPolicy, TrustStore,
};

/// A two-signer NDA prepared with the signature-timestamp `policy`.
fn prepared_with(policy: TimestampPolicy) -> Vec<u8> {
    let pdf = container::make_sample_pdf("Increment NDA");
    let (key, mut req) = two_signer_request(&pdf);
    req.policy.signature_timestamps = policy;
    prepare(&pdf, &req, &key).unwrap()
}

fn prepared() -> Vec<u8> {
    prepared_with(TimestampPolicy::Optional)
}

/// `email` (slot `slot`) signs `pdf`, returning only the increment.
fn signs_increment(pdf: &[u8], email: &str, slot: &str) -> Vec<u8> {
    let (key, req) = signer_request(email, pdf, slot);
    sign_increment(pdf, &key, &req).unwrap()
}

fn trust_with(tsa: &TestTsa) -> TrustStore {
    let mut t = trust();
    t.add_tsa_anchor(&tsa.cert_der());
    t
}

#[test]
fn a_sign_increment_is_what_signing_appends() {
    let doc = prepared();
    let inc = signs_increment(&doc, "alice@example.com", "s1");
    assert!(
        inc.len() < 64 * 1024 && !inc.starts_with(b"%PDF"),
        "the increment holds only the new revision ({} bytes)",
        inc.len()
    );
    assert!(inc.ends_with(b"%%EOF\n"));
    let signed = appended(&doc, &inc);
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    // What the record says it signed is exactly the head it was appended to.
    let env = read_envelope(&signed).unwrap();
    assert_eq!(env.signatures[0].signed_prefix_len, doc.len() as u64);
    assert_eq!(env.signatures[0].doc_digest, sha256_hex(&doc));
    assert_eq!(report.document_sha256, sha256_hex(&signed));

    // Bob signs on top, also by increment; the whole-document form gives the same kind of result.
    let inc2 = signs_increment(&signed, "bob@example.com", "s2");
    let done = appended(&signed, &inc2);
    let report = verify(&done, &trust()).unwrap();
    assert!(report.valid && report.complete, "{:?}", report.messages);

    let (key, req) = signer_request("alice@example.com", &doc, "s1");
    let whole = sign(&doc, &key, &req).unwrap();
    assert!(whole.starts_with(&doc));
    assert!(verify(&whole, &trust()).unwrap().valid);
}

#[test]
fn a_sign_increment_refuses_what_signing_refuses() {
    let doc = prepared();
    // Out of order: Bob before Alice.
    let (key, req) = signer_request("bob@example.com", &doc, "s2");
    assert!(matches!(
        sign_increment(&doc, &key, &req),
        Err(SignPdfError::Workflow(m)) if m.contains("out of order")
    ));
    // A token bound to another document.
    let (key, req) = signer_request("alice@example.com", b"another document", "s1");
    assert!(sign_increment(&doc, &key, &req).is_err());
    // A broken document is never signed.
    let mut broken = doc.clone();
    let at = broken.len() / 2;
    broken[at] ^= 0x20;
    let (key, req) = signer_request("alice@example.com", &broken, "s1");
    assert!(matches!(
        sign_increment(&broken, &key, &req),
        Err(SignPdfError::Workflow(m)) if m.contains("integrity")
    ));
}

/// Sign with room for a timestamp, then add one through the increment-only steps.
fn timestamped_increment(doc: &[u8], tsa: &TestTsa) -> (Vec<u8>, Vec<u8>) {
    let (key, req) = signer_request("alice@example.com", doc, "s1");
    let inc = sign_for_timestamp_increment(doc, &key, &req).unwrap();
    let digest = increment_signature_timestamp_digest(doc, &inc).unwrap();
    // The same imprint as from the whole document.
    assert_eq!(
        digest,
        signature_timestamp_digest(&appended(doc, &inc)).unwrap()
    );
    let response = tsa.respond(&build_request(&digest)).unwrap();
    let token = parse_response(&response, &digest).unwrap().token_der;
    let stamped = embed_increment_signature_timestamp(doc, &inc, &token).unwrap();
    (inc, stamped)
}

#[test]
fn a_signature_timestamp_is_added_to_an_increment() {
    let tsa = TestTsa::new();
    for policy in [TimestampPolicy::Optional, TimestampPolicy::Required] {
        let doc = prepared_with(policy);
        let (inc, stamped) = timestamped_increment(&doc, &tsa);
        assert_eq!(stamped.len(), inc.len(), "only the /Contents changes");
        assert_ne!(stamped, inc);
        let signed = appended(&doc, &stamped);
        let report = verify(&signed, &trust_with(&tsa)).unwrap();
        assert!(report.valid, "{policy:?}: {:?}", report.messages);
        assert_eq!(report.signatures[0].time_source, "tsa");

        // Only once.
        let digest = signature_timestamp_digest(&signed);
        assert!(digest.is_err());
        let again = increment_signature_timestamp_digest(&doc, &stamped).unwrap_err();
        assert!(again.to_string().contains("already has"), "{again}");
    }

    // Under `required`, the plain increment has room too.
    let doc = prepared_with(TimestampPolicy::Required);
    let inc = signs_increment(&doc, "alice@example.com", "s1");
    increment_signature_timestamp_digest(&doc, &inc).unwrap();
}

#[test]
fn the_increment_timestamp_steps_keep_the_envelope_rules() {
    let tsa = TestTsa::new();
    let token_for = |digest: [u8; 32]| {
        let response = tsa.respond(&build_request(&digest)).unwrap();
        parse_response(&response, &digest).unwrap().token_der
    };

    // `none`: refused before anything else, both steps.
    let doc = prepared_with(TimestampPolicy::None);
    let inc = signs_increment(&doc, "alice@example.com", "s1");
    for result in [
        increment_signature_timestamp_digest(&doc, &inc).map(|_| ()),
        embed_increment_signature_timestamp(&doc, &inc, &token_for([7; 32])).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(SignPdfError::Workflow(m)) if m.contains("takes no signature timestamps")
        ));
    }

    let doc = prepared();
    let (key, req) = signer_request("alice@example.com", &doc, "s1");
    let inc = sign_for_timestamp_increment(&doc, &key, &req).unwrap();
    let digest = increment_signature_timestamp_digest(&doc, &inc).unwrap();
    let refused = |head: &[u8], inc: &[u8], what: &str| {
        let e = increment_signature_timestamp_digest(head, inc).unwrap_err();
        assert!(e.to_string().contains(what), "{what}: {e}");
    };

    // The head must be a prepared document: the preparer's own revision is never timestamped.
    let source = container::make_sample_pdf("Increment NDA");
    let preparer_inc = &doc[source.len()..];
    assert!(increment_signature_timestamp_digest(&source, preparer_inc).is_err());

    // Applied to another head, the signature no longer verifies.
    let other = prepared();
    assert!(increment_signature_timestamp_digest(&other, &inc).is_err());
    let mut head = doc.clone();
    head[100] ^= 1;
    refused(&head, &inc, "not valid");

    // A changed signed byte in the increment.
    let mut tampered = inc.clone();
    tampered[20] ^= 1;
    refused(&doc, &tampered, "not valid");

    // A signature that leaves something after it, or an increment cut short.
    let mut longer = inc.clone();
    longer.extend_from_slice(b"% unsigned\n");
    refused(&doc, &longer, "does not cover the whole file");
    refused(&doc, &inc[..inc.len() - 40], "ByteRange");

    // An increment that ends with a document timestamp, not a signature.
    let signed = appended(&doc, &inc);
    let (with_dts, _) = prepare_document_timestamp(&signed).unwrap();
    refused(
        &signed,
        &with_dts[signed.len()..],
        "does not end with a SignPDF signature",
    );

    // Not a PDF increment at all.
    refused(&doc, b"garbage", "does not end with a SignPDF signature");

    // A token over something else is refused, and the increment is unchanged.
    let wrong = embed_increment_signature_timestamp(&doc, &inc, &token_for([1; 32]));
    assert!(
        matches!(wrong, Err(SignPdfError::Timestamp(_))),
        "{wrong:?}"
    );
    let right = embed_increment_signature_timestamp(&doc, &inc, &token_for(digest)).unwrap();
    assert!(
        verify(&appended(&doc, &right), &trust_with(&tsa))
            .unwrap()
            .valid
    );
}

#[test]
fn when_the_head_moves_only_the_increment_travels() {
    // The client opened the prepared envelope; meanwhile Alice signed on the holder's copy.
    let client_head = prepared();
    let alice = signs_increment(&client_head, "alice@example.com", "s1");
    let holder = appended(&client_head, &alice);
    let announced = Head::of(&holder);

    // The client asks for what follows its revision and checks it against the announced head.
    let inc = increment_after(&holder, &Head::of(&client_head)).unwrap();
    assert_eq!(inc, &alice[..]);
    assert_eq!(
        check_increment(&client_head, inc, &announced).unwrap(),
        announced
    );
    let new_head = appended(&client_head, inc);
    assert_eq!(new_head, holder);

    // Bob signs on the new head; the holder accepts his increment on top of its copy.
    let bob = signs_increment(&new_head, "bob@example.com", "s2");
    let done = appended(&holder, &bob);
    let report = verify(&done, &trust()).unwrap();
    assert!(report.valid && report.complete, "{:?}", report.messages);

    // A client still on the prepared revision gets both signers' increments at once.
    let both = increment_after(&done, &Head::of(&client_head)).unwrap();
    assert_eq!(both.len(), alice.len() + bob.len());
    check_increment(&client_head, both, &Head::of(&done)).unwrap();

    // A client whose copy diverged (another envelope) must fetch everything.
    let stranger = prepared();
    let e = increment_after(&done, &Head::of(&stranger)).unwrap_err();
    assert!(e.to_string().contains("fetch the whole document"), "{e}");
    // An increment that does not lead to the announced head is never used.
    let e = check_increment(&stranger, inc, &announced).unwrap_err();
    assert!(e.to_string().contains("fetch the whole document"), "{e}");
}

#[test]
fn verification_reports_the_same_digests_as_hashing_directly() {
    let doc = prepared();
    let signed = appended(&doc, &signs_increment(&doc, "alice@example.com", "s1"));
    let done = appended(&signed, &signs_increment(&signed, "bob@example.com", "s2"));
    for pdf in [&doc, &signed, &done] {
        let report = verify(pdf, &trust()).unwrap();
        assert!(report.valid, "{:?}", report.messages);
        assert_eq!(report.document_sha256, sha256_hex(pdf));
    }
    // Each record's digest is its predecessor's, as hashed directly.
    let env = read_envelope(&done).unwrap();
    assert_eq!(env.signatures[0].doc_digest, sha256_hex(&doc));
    assert_eq!(env.signatures[1].doc_digest, sha256_hex(&signed));
}

/// xorshift64*: reproducible without a dependency.
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

/// Corrupted increments never panic the increment steps, and never take a timestamp unless the
/// corruption left the signature intact (a byte of its own `/Contents` padding, say).
#[test]
fn mutated_increments_never_panic() {
    let tsa = TestTsa::new();
    let doc = prepared();
    let (key, req) = signer_request("alice@example.com", &doc, "s1");
    let inc = sign_for_timestamp_increment(&doc, &key, &req).unwrap();
    let digest = increment_signature_timestamp_digest(&doc, &inc).unwrap();
    let response = tsa.respond(&build_request(&digest)).unwrap();
    let token = parse_response(&response, &digest).unwrap().token_der;
    let announced = Head::of(&appended(&doc, &inc));

    let mut rng = Rng(0x1A2B_3C4D_5E6F_7081);
    let iterations = std::env::var("SIGNPDF_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    for i in 0..iterations {
        let mut m = inc.clone();
        for _ in 0..1 + rng.below(3) {
            if m.is_empty() {
                break;
            }
            match rng.below(4) {
                0 => {
                    let p = rng.below(m.len());
                    m[p] ^= 1 << rng.below(8);
                }
                1 => m.truncate(rng.below(m.len())),
                2 => {
                    let p = rng.below(m.len());
                    m.insert(p, b"[]<>/ 0123456789"[rng.below(16)]);
                }
                _ => {
                    let p = rng.below(m.len());
                    m.remove(p);
                }
            }
        }
        // Must return, never panic; a success must still verify.
        if let Ok(stamped) = embed_increment_signature_timestamp(&doc, &m, &token) {
            let report = verify(&appended(&doc, &stamped), &trust_with(&tsa)).unwrap();
            assert!(
                report.integrity_ok,
                "mutation {i} took a timestamp but does not verify: {:?}",
                report.messages
            );
        }
        let _ = increment_signature_timestamp_digest(&doc, &m);
        assert!(check_increment(&doc, &m, &announced).is_err() || m == inc);
        let _ = increment_after(&appended(&doc, &m), &Head::of(&doc));
    }
}

/// The `/Contents` hex of the last signature in `increment`, as a byte range.
fn contents_gap(increment: &[u8]) -> std::ops::Range<usize> {
    let at = increment
        .windows(11)
        .rposition(|w| w == b"/Contents <")
        .expect("a signature's /Contents")
        + 11;
    let len = increment[at..].iter().position(|b| *b == b'>').unwrap();
    at..at + len
}

/// Found by `mutated_increments_never_panic` (a run in a few failed): a change in the
/// certificate inside the signature's CMS, outside its key, leaves the signature valid and the
/// CMS readable, so embedding a timestamp accepted it, and the verifier then refused the result
/// (the CMS is no longer SignPDF's exact form: the signed ESS attribute names another
/// certificate). Embedding must refuse what the verifier refuses.
#[test]
fn a_timestamp_is_not_embedded_into_a_cms_the_verifier_refuses() {
    use der::{Decode, Encode};
    let tsa = TestTsa::new();
    let doc = prepared();
    let (key, req) = signer_request("alice@example.com", &doc, "s1");
    let inc = sign_for_timestamp_increment(&doc, &key, &req).unwrap();
    let digest = increment_signature_timestamp_digest(&doc, &inc).unwrap();
    let response = tsa.respond(&build_request(&digest)).unwrap();
    let token = parse_response(&response, &digest).unwrap().token_der;
    // The honest increment takes it, for reference.
    let stamped = embed_increment_signature_timestamp(&doc, &inc, &token).unwrap();
    assert!(
        verify(&appended(&doc, &stamped), &trust_with(&tsa))
            .unwrap()
            .integrity_ok
    );

    let gap = contents_gap(&inc);
    let mut cms = hex::decode(&inc[gap.clone()]).unwrap();
    let mut reader = der::SliceReader::new(&cms).unwrap();
    let ci = <cms::content_info::ContentInfo as der::Decode>::decode(&mut reader).unwrap();
    let sd: cms::signed_data::SignedData = ci.content.decode_as().unwrap();
    let cert = match sd.certificates.unwrap().0.iter().next().unwrap() {
        cms::cert::CertificateChoices::Certificate(c) => c.to_der().unwrap(),
        _ => panic!("a certificate"),
    };
    let at = cms.windows(cert.len()).position(|w| w == cert).unwrap();
    // The last byte of the certificate's own signature value: not its key.
    cms[at + cert.len() - 1] ^= 1;
    assert!(x509_cert::Certificate::from_der(&cms[at..at + cert.len()]).is_ok());
    let mut mutated = inc.clone();
    mutated[gap].copy_from_slice(hex::encode(&cms).as_bytes());

    if let Ok(stamped) = embed_increment_signature_timestamp(&doc, &mutated, &token) {
        let report = verify(&appended(&doc, &stamped), &trust_with(&tsa)).unwrap();
        assert!(
            report.integrity_ok,
            "a timestamp was embedded into a CMS the verifier refuses: {:?}",
            report.messages
        );
    }
}
