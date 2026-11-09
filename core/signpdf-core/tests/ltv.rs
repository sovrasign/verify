//! Document timestamps and validation data after the last signature (PAdES B-LT and B-LTA):
//! what a hosted service adds when an envelope reaches a final state, or to keep an older
//! document verifiable, and what may never ride along with them.
//!
//! The time-stamp authorities here are issued by a test root CA (`ltv::testing::TestCa`), which
//! also answers OCSP requests and publishes CRLs for them; the verifier trusts the root.

mod common;

use common::*;
use signpdf_core::ltv::testing::{TestCa, TestStatus, TEST_CRL_URL, TEST_OCSP_URL};
use signpdf_core::pades::{self, Dss, EmbeddedFile};
use signpdf_core::timestamp::testing::TestTsa;
use signpdf_core::workflow::{self, ENVELOPE_NAME};
use signpdf_core::{
    add_document_timestamp, add_validation_data, container, embed_document_timestamp, pades_verify,
    prepare, prepare_document_timestamp, read_envelope, revocation_targets, sign, sign_with,
    verify, TimestampPolicy, TrustStore, VerificationReport,
};

/// A root CA and two TSAs it issued: one for signature timestamps, one for document timestamps.
struct Authorities {
    ca: TestCa,
    signing_tsa: TestTsa,
    document_tsa: TestTsa,
}

fn authorities() -> Authorities {
    let ca = TestCa::new("SignPDF Test Root");
    let signing_tsa = ca.issue_tsa("SignPDF Test TSA 1");
    let document_tsa = ca.issue_tsa("SignPDF Test TSA 2");
    Authorities {
        ca,
        signing_tsa,
        document_tsa,
    }
}

/// The test identity provider and `ca` as the timestamp anchor.
fn trust_with(ca: &TestCa) -> TrustStore {
    let mut t = trust();
    t.add_tsa_anchor(&ca.cert_der());
    t
}

/// A two-signer NDA prepared with `policy`.
fn prepared(policy: TimestampPolicy) -> Vec<u8> {
    let pdf = container::make_sample_pdf("Mutual NDA");
    let (key, mut req) = two_signer_request(&pdf);
    req.policy.signature_timestamps = policy;
    prepare(&pdf, &req, &key).unwrap()
}

/// `pdf` signed by `email`, with a signature timestamp from `tsa` when given.
fn signed_by(pdf: &[u8], email: &str, tsa: Option<&TestTsa>) -> Vec<u8> {
    let (key, req) = signer_request(email, pdf, "");
    match tsa {
        Some(t) => sign_with(pdf, &key, &req, Some(t)).unwrap(),
        None => sign(pdf, &key, &req).unwrap(),
    }
}

/// A completed envelope whose signatures carry timestamps from `a.signing_tsa`.
fn completed_with_timestamps(a: &Authorities) -> Vec<u8> {
    let p = prepared(TimestampPolicy::Required);
    let alice = signed_by(&p, "alice@example.com", Some(&a.signing_tsa));
    signed_by(&alice, "bob@example.com", Some(&a.signing_tsa))
}

/// A completed envelope whose signatures carry no timestamp (`signature_timestamps = none`).
fn completed_without_timestamps() -> Vec<u8> {
    let p = prepared(TimestampPolicy::None);
    let alice = signed_by(&p, "alice@example.com", None);
    signed_by(&alice, "bob@example.com", None)
}

/// OCSP responses from `ca` saying every certificate `targets` names is good.
fn answer_all(ca: &TestCa, pdf: &[u8], trust: &TrustStore) -> Vec<Vec<u8>> {
    revocation_targets(pdf, trust)
        .unwrap()
        .iter()
        .map(|t| ca.ocsp_response(&t.cert, TestStatus::Good))
        .collect()
}

/// What a service does at completion when signatures carry timestamps: validation data for
/// them, then a document timestamp over it (PAdES B-LTA).
fn sealed_with_validation_data(a: &Authorities, done: &[u8]) -> Vec<u8> {
    let trust = trust_with(&a.ca);
    let ocsps = answer_all(&a.ca, done, &trust);
    let with_data = add_validation_data(done, &trust, &ocsps, &[]).unwrap();
    add_document_timestamp(&with_data, &a.document_tsa).unwrap()
}

fn assert_intact(report: &VerificationReport) {
    assert!(
        report.valid && report.integrity_ok,
        "{:?} / {:?}",
        report.messages,
        report.warnings
    );
}

fn assert_broken(report: &VerificationReport, needle: &str) {
    assert!(!report.valid && !report.integrity_ok, "{report:?}");
    assert!(
        report.messages.iter().any(|m| m.contains(needle)),
        "expected a message containing {needle:?}: {:?}",
        report.messages
    );
}

// --- the honest flows ------------------------------------------------------------------------

#[test]
fn an_envelope_without_signature_timestamps_gets_its_trusted_time_from_a_document_timestamp() {
    let a = authorities();
    let done = completed_without_timestamps();
    let sealed = add_document_timestamp(&done, &a.document_tsa).unwrap();
    let report = verify(&sealed, &trust_with(&a.ca)).unwrap();
    assert_intact(&report);
    assert!(report.complete);
    assert_eq!(report.document_timestamps.len(), 1);
    let d = &report.document_timestamps[0];
    assert!(d.valid && d.timestamp.is_trusted(), "{d:?}");
    assert_eq!(d.timestamp.kind, "document");
    assert_eq!(d.timestamp.tsa_name, "SignPDF Test TSA 2");
    assert_eq!(d.after_revision, 2);
    assert_eq!(d.covered_len as usize, sealed.len());
    assert!(!d.added_validation_data);
    // Every signature is now dated by trusted time evidence (PAdES B-T), although none carries
    // a timestamp of its own; their signing times stay the device's (a known limitation).
    assert_eq!(report.pades_level, "B-T");
    assert!(report.signatures.iter().all(|s| s.time_source == "device"));
    // The signatures themselves are unchanged.
    assert_eq!(pades_verify(&sealed).unwrap().len(), 3);
}

#[test]
fn a_document_timestamp_the_verifier_does_not_trust_leaves_the_document_valid() {
    let a = authorities();
    let sealed = add_document_timestamp(&completed_without_timestamps(), &a.document_tsa).unwrap();
    let report = verify(&sealed, &trust()).unwrap();
    assert_intact(&report);
    assert!(!report.document_timestamps[0].timestamp.trusted);
    assert_eq!(report.pades_level, "B-B");
}

#[test]
fn a_timestamped_envelope_is_sealed_with_validation_data_and_a_document_timestamp() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let done = completed_with_timestamps(&a);
    assert_eq!(verify(&done, &trust).unwrap().pades_level, "B-T");

    // What to fetch: the signing TSA's certificate (its root is the anchor, which needs none),
    // with its OCSP responder and CRL, once even though two timestamps rely on it.
    let targets = revocation_targets(&done, &trust).unwrap();
    assert_eq!(targets.len(), 1, "{targets:?}");
    let t = &targets[0];
    assert_eq!(t.subject, "SignPDF Test TSA 1");
    assert_eq!(t.issuer, a.ca.cert_der());
    assert_eq!(t.ocsp_urls, vec![TEST_OCSP_URL.to_string()]);
    assert_eq!(t.crl_urls, vec![TEST_CRL_URL.to_string()]);
    assert!(!t.ocsp_request.is_empty());

    let ocsp = a.ca.ocsp_response(&t.cert, TestStatus::Good);
    let with_data = add_validation_data(&done, &trust, &[ocsp], &[]).unwrap();
    // Validation data alone is an unsigned addition: a document timestamp must cover it.
    assert_broken(
        &verify(&with_data, &trust).unwrap(),
        "appended after the last signature",
    );
    // Nothing is left to fetch.
    assert!(revocation_targets(&with_data, &trust).unwrap().is_empty());

    let sealed = add_document_timestamp(&with_data, &a.document_tsa).unwrap();
    let report = verify(&sealed, &trust).unwrap();
    assert_intact(&report);
    assert_eq!(report.pades_level, "B-LTA");
    let data = report.validation_data.as_ref().unwrap();
    assert_eq!(
        (data.certificates, data.ocsp_responses, data.crls),
        (2, 1, 0)
    );
    for s in &report.signatures {
        let ts = s.timestamp.as_ref().unwrap();
        assert!(ts.is_trusted());
        assert_eq!(ts.validation, "complete", "{ts:?}");
        assert_eq!(ts.chain.len(), 2);
        assert_eq!(ts.chain[0].revocation, "good");
        assert_eq!(ts.chain[0].source, "ocsp");
        assert!(ts.chain[0].in_dss);
        assert_eq!(ts.chain[1].revocation, "anchor");
        assert_eq!(s.time_source, "tsa");
    }
    let d = &report.document_timestamps[0];
    assert!(d.added_validation_data && d.valid);
    // The newest timestamp's own validation data comes with the next renewal.
    assert_eq!(d.timestamp.validation, "incomplete");
}

#[test]
fn a_crl_is_validation_data_too() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let done = completed_with_timestamps(&a);
    let crl = a.ca.crl(&[]);
    let with_data = add_validation_data(&done, &trust, &[], &[crl]).unwrap();
    let sealed = add_document_timestamp(&with_data, &a.document_tsa).unwrap();
    let report = verify(&sealed, &trust).unwrap();
    assert_intact(&report);
    assert_eq!(report.pades_level, "B-LTA");
    let ts = report.signatures[0].timestamp.as_ref().unwrap();
    assert_eq!(ts.chain[0].source, "crl");
}

#[test]
fn a_delegated_ocsp_responder_is_validation_data_too() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let done = completed_with_timestamps(&a);
    let responder = a.ca.issue_ocsp_responder();
    let targets = revocation_targets(&done, &trust).unwrap();
    let ocsp =
        a.ca.ocsp_response_by(&responder, &targets[0].cert, TestStatus::Good);
    let sealed = add_document_timestamp(
        &add_validation_data(&done, &trust, &[ocsp], &[]).unwrap(),
        &a.document_tsa,
    )
    .unwrap();
    assert_eq!(verify(&sealed, &trust).unwrap().pades_level, "B-LTA");
}

#[test]
fn renewing_adds_the_last_timestamp_s_validation_data_and_a_new_document_timestamp() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let sealed = sealed_with_validation_data(&a, &completed_with_timestamps(&a));

    // Years later: the document timestamp's own TSA certificate now needs evidence.
    let targets = revocation_targets(&sealed, &trust).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].subject, "SignPDF Test TSA 2");
    let renewer = a.ca.issue_tsa("SignPDF Test TSA 3");
    let ocsps = answer_all(&a.ca, &sealed, &trust);
    let renewed = add_document_timestamp(
        &add_validation_data(&sealed, &trust, &ocsps, &[]).unwrap(),
        &renewer,
    )
    .unwrap();
    let report = verify(&renewed, &trust).unwrap();
    assert_intact(&report);
    assert_eq!(report.pades_level, "B-LTA");
    assert_eq!(report.document_timestamps.len(), 2);
    assert_eq!(
        report.document_timestamps[0].timestamp.validation,
        "complete"
    );
    assert!(report.document_timestamps[1].added_validation_data);
    let data = report.validation_data.unwrap();
    assert_eq!((data.certificates, data.ocsp_responses), (3, 2));
}

#[test]
fn an_envelope_without_signature_timestamps_reaches_b_lta_when_renewed() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let sealed = add_document_timestamp(&completed_without_timestamps(), &a.document_tsa).unwrap();
    let ocsps = answer_all(&a.ca, &sealed, &trust);
    assert_eq!(ocsps.len(), 1);
    let renewed = add_document_timestamp(
        &add_validation_data(&sealed, &trust, &ocsps, &[]).unwrap(),
        &a.ca.issue_tsa("SignPDF Test TSA 3"),
    )
    .unwrap();
    let report = verify(&renewed, &trust).unwrap();
    assert_intact(&report);
    assert_eq!(report.pades_level, "B-LTA");
}

#[test]
fn an_open_envelope_can_be_timestamped_and_signed_afterwards() {
    // A document timestamp on an envelope still open (queued after a time-stamp authority
    // outage, or before an identity-provider key rotates): the next signer signs on top of it.
    let a = authorities();
    let trust = trust_with(&a.ca);
    let p = prepared(TimestampPolicy::None);
    let stamped_prepared = add_document_timestamp(&p, &a.document_tsa).unwrap();
    let alice = signed_by(&stamped_prepared, "alice@example.com", None);
    let stamped = add_document_timestamp(&alice, &a.document_tsa).unwrap();
    let done = signed_by(&stamped, "bob@example.com", None);
    let report = verify(&done, &trust).unwrap();
    assert_intact(&report);
    assert!(report.complete);
    assert_eq!(report.signatures.len(), 2);
    let after: Vec<u32> = report
        .document_timestamps
        .iter()
        .map(|d| d.after_revision)
        .collect();
    assert_eq!(after, vec![0, 1]);
    // Bob's signature, the last, has no trusted time after it.
    assert_eq!(report.pades_level, "B-B");
    let sealed = add_document_timestamp(&done, &a.document_tsa).unwrap();
    assert_eq!(verify(&sealed, &trust).unwrap().pades_level, "B-T");
}

#[test]
fn a_signature_timestamp_can_no_longer_be_added_once_a_document_timestamp_follows() {
    let a = authorities();
    let p = prepared(TimestampPolicy::Required);
    let (key, req) = signer_request("alice@example.com", &p, "");
    let alice = workflow::sign_for_timestamp(&p, &key, &req).unwrap();
    let stamped = add_document_timestamp(&alice, &a.document_tsa).unwrap();
    assert!(workflow::signature_timestamp_digest(&stamped).is_err());
    let report = verify(&stamped, &trust_with(&a.ca)).unwrap();
    assert_intact(&report);
}

#[test]
fn preparing_a_document_timestamp_is_deterministic_and_two_step() {
    let a = authorities();
    let done = completed_without_timestamps();
    let (one, digest) = prepare_document_timestamp(&done).unwrap();
    let (two, again) = prepare_document_timestamp(&done).unwrap();
    assert_eq!((&one, digest), (&two, again));
    // Until its token is added, the timestamp is empty and the document fails.
    assert_broken(&verify(&one, &trust()).unwrap(), "never added");

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    // A token over other bytes is refused.
    let wrong = a.document_tsa.stamp(&[7u8; 32], &now);
    assert!(embed_document_timestamp(&one, &wrong).is_err());
    let token = a.document_tsa.stamp(&digest, &now);
    let sealed = embed_document_timestamp(&one, &token).unwrap();
    assert_eq!(sealed.len(), one.len());
    assert_intact(&verify(&sealed, &trust_with(&a.ca)).unwrap());
    // Once it has its token there is nothing left to embed into.
    assert!(embed_document_timestamp(&sealed, &token).is_err());
}

#[test]
fn validation_data_is_not_repeated() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let done = completed_with_timestamps(&a);
    let ocsps = answer_all(&a.ca, &done, &trust);
    let once = add_validation_data(&done, &trust, &ocsps, &[]).unwrap();
    // Low level, the same items again add nothing.
    let dss = pades::read_dss(&once).unwrap().unwrap();
    assert_eq!(pades::add_validation_data(&once, &dss).unwrap(), once);

    // After the document timestamp, the same response again adds only what is new: the
    // document timestamp's TSA certificate.
    let sealed = add_document_timestamp(&once, &a.document_tsa).unwrap();
    let again = add_validation_data(&sealed, &trust, &ocsps, &[]).unwrap();
    let more = pades::read_dss(&again).unwrap().unwrap();
    assert_eq!(more.ocsps, dss.ocsps);
    assert_eq!(more.certs.len(), dss.certs.len() + 1);
    assert_eq!(&more.certs[..dss.certs.len()], dss.certs.as_slice());
}

// --- revocation ------------------------------------------------------------------------------

#[test]
fn a_tsa_revoked_before_the_timestamp_proves_nothing() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let done = completed_with_timestamps(&a);
    let targets = revocation_targets(&done, &trust).unwrap();
    let a_day_ago = time::OffsetDateTime::now_utc().unix_timestamp() - 86_400;
    let revoked =
        a.ca.ocsp_response(&targets[0].cert, TestStatus::Revoked(a_day_ago));
    // True evidence goes in, even when it is bad news.
    let sealed = add_document_timestamp(
        &add_validation_data(&done, &trust, &[revoked], &[]).unwrap(),
        &a.document_tsa,
    )
    .unwrap();
    let report = verify(&sealed, &trust).unwrap();
    // The document is intact; the signature timestamps just no longer date the signatures.
    assert_intact(&report);
    for s in &report.signatures {
        let ts = s.timestamp.as_ref().unwrap();
        assert!(!ts.trusted);
        assert_eq!(ts.validation, "revoked");
        assert!(ts.detail.contains("was revoked"), "{}", ts.detail);
        assert_eq!(s.time_source, "device");
    }
    // The document timestamp (another TSA) still gives every signature trusted time.
    assert_eq!(report.pades_level, "B-T");
}

#[test]
fn a_tsa_revoked_after_the_timestamp_still_holds_with_a_warning() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let done = completed_with_timestamps(&a);
    let targets = revocation_targets(&done, &trust).unwrap();
    let in_an_hour = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;
    let crl = a.ca.crl(&[(&targets[0].cert, in_an_hour)]);
    let sealed = add_document_timestamp(
        &add_validation_data(&done, &trust, &[], &[crl]).unwrap(),
        &a.document_tsa,
    )
    .unwrap();
    let report = verify(&sealed, &trust).unwrap();
    assert_intact(&report);
    assert_eq!(report.pades_level, "B-LTA");
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("revoked at") && w.contains("still holds")),
        "{:?}",
        report.warnings
    );
}

#[test]
fn only_evidence_about_the_document_s_timestamps_goes_in() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let done = completed_with_timestamps(&a);
    let target = &revocation_targets(&done, &trust).unwrap()[0];

    // A response about another certificate, from another CA, or that is not OCSP at all.
    let other = a.ca.issue_tsa("Some Other TSA").cert_der();
    let elsewhere = TestCa::new("SignPDF Test Root");
    for (ocsp, why) in [
        (
            a.ca.ocsp_response(&other, TestStatus::Good),
            "another certificate",
        ),
        (
            elsewhere.ocsp_response(&target.cert, TestStatus::Good),
            "a forged signer",
        ),
        (b"not an OCSP response".to_vec(), "garbage"),
    ] {
        let err = add_validation_data(&done, &trust, &[ocsp], &[]).unwrap_err();
        assert!(
            err.to_string().contains("OCSP response 1 is not evidence"),
            "{why}: {err}"
        );
    }
    let err = add_validation_data(&done, &trust, &[], &[elsewhere.crl(&[])]).unwrap_err();
    assert!(err.to_string().contains("CRL 1 is not evidence"), "{err}");

    // Without a trusted timestamp there is nothing to add data for.
    let ocsp = a.ca.ocsp_response(&target.cert, TestStatus::Good);
    let err = add_validation_data(&done, &common::trust(), &[ocsp], &[]).unwrap_err();
    assert!(err.to_string().contains("no timestamp"), "{err}");
}

#[test]
fn nothing_is_added_to_a_broken_document() {
    let a = authorities();
    let done = completed_without_timestamps();
    let mut env = read_envelope(&done).unwrap();
    env.title = "Pay Mallory".into();
    let tampered = pades::embed_attachment(&done, &envelope_file(&env)).unwrap();
    let err = prepare_document_timestamp(&tampered).unwrap_err();
    assert!(
        err.to_string()
            .contains("refusing to add a document timestamp"),
        "{err}"
    );
    let err = add_validation_data(&tampered, &trust_with(&a.ca), &[], &[]).unwrap_err();
    assert!(
        err.to_string().contains("refusing to add validation data"),
        "{err}"
    );
}

// --- attacks: what may never ride along with a document timestamp -----------------------------
//
// Anyone who can reach a time-stamp authority can add a document timestamp, so each of these uses
// the low-level `pades::` calls, which check nothing, to build what an attacker would.

fn envelope_file(env: &signpdf_core::Envelope) -> EmbeddedFile {
    EmbeddedFile {
        name: ENVELOPE_NAME.into(),
        data: serde_json::to_vec(env).unwrap(),
        mime: "application/json".into(),
        relationship: "Data".into(),
        description: "tampered".into(),
    }
}

/// Append a raw incremental update defining `objects` (id, body).
fn append_objects(pdf: &[u8], objects: &[(u32, String)]) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    let prev = {
        let pos = pdf.windows(9).rposition(|w| w == b"startxref").unwrap();
        let tail = std::str::from_utf8(&pdf[pos + 9..]).unwrap();
        tail.split_whitespace().next().unwrap().to_string()
    };
    let mut out = pdf.to_vec();
    let mut xref = String::from("xref\n");
    let mut size = doc.max_id + 1;
    for (id, body) in objects {
        let off = out.len();
        out.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
        xref.push_str(&format!("{id} 1\n{off:010} 00000 n \n"));
        size = size.max(id + 1);
    }
    let at = out.len();
    out.extend_from_slice(
        format!(
            "{xref}trailer\n<< /Size {size} /Root {} 0 R /Prev {prev} >>\nstartxref\n{at}\n%%EOF\n",
            root.0
        )
        .as_bytes(),
    );
    out
}

/// A PDF object written out (enough for the dictionaries these tests rewrite).
fn pdf_text(o: &lopdf::Object) -> String {
    use lopdf::Object::*;
    let name = |n: &[u8]| format!("/{}", std::string::String::from_utf8_lossy(n));
    match o {
        Null => "null".into(),
        Boolean(b) => b.to_string(),
        Integer(i) => i.to_string(),
        Real(r) => r.to_string(),
        Name(n) => name(n),
        String(s, _) => format!("<{}>", hex::encode(s)),
        Reference(r) => format!("{} {} R", r.0, r.1),
        Array(a) => format!("[{}]", a.iter().map(pdf_text).collect::<Vec<_>>().join(" ")),
        Dictionary(d) => format!(
            "<< {} >>",
            d.iter()
                .map(|(k, v)| format!("{} {}", name(k), pdf_text(v)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Stream(_) => panic!("streams are not rewritten here"),
    }
}

fn ids(pdf: &[u8]) -> (lopdf::Document, lopdf::ObjectId, lopdf::ObjectId) {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    let page = *doc.get_pages().get(&1).unwrap();
    (doc, root, page)
}

/// The low-level document timestamp an attacker adds after their change.
fn stamp(pdf: &[u8], a: &Authorities) -> Vec<u8> {
    pades::add_document_timestamp(pdf, &a.document_tsa).unwrap()
}

#[test]
fn a_new_envelope_cannot_ride_along_with_a_document_timestamp() {
    // The latest envelope is found by scanning for attachments, so an envelope added in a
    // document timestamp's increment would be what a naive reader shows.
    let a = authorities();
    let done = completed_without_timestamps();
    let mut env = read_envelope(&done).unwrap();
    env.title = "Pay Mallory EUR 1,000,000".into();
    let forged = stamp(
        &pades::embed_attachment(&done, &envelope_file(&env)).unwrap(),
        &a,
    );
    assert_eq!(read_envelope(&forged).unwrap().title, env.title);
    assert_broken(
        &verify(&forged, &trust_with(&a.ca)).unwrap(),
        "is neither validation data nor the document timestamp",
    );
}

#[test]
fn page_content_cannot_change_under_a_document_timestamp() {
    let a = authorities();
    let done = completed_without_timestamps();
    let (doc, _, page) = ids(&done);
    let content = doc
        .get_object(page)
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"Contents")
        .unwrap()
        .as_reference()
        .unwrap();
    let text = "BT /F1 24 Tf 72 700 Td (Pay Mallory) Tj ET";
    let body = format!("<< /Length {} >>\nstream\n{text}\nendstream", text.len());
    let forged = stamp(&append_objects(&done, &[(content.0, body)]), &a);
    assert_broken(
        &verify(&forged, &trust_with(&a.ca)).unwrap(),
        "was modified",
    );
}

#[test]
fn the_catalog_may_only_gain_validation_data() {
    let a = authorities();
    let done = completed_without_timestamps();
    let (doc, root, _) = ids(&done);
    let catalog = doc.get_object(root).unwrap().as_dict().unwrap();
    let pages = catalog.get(b"Pages").unwrap().as_reference().unwrap();
    let form = catalog.get(b"AcroForm").unwrap().as_reference().unwrap();
    let body = format!(
        "<< /Type /Catalog /Pages {} 0 R /AcroForm {} 0 R /OpenAction << /S /JavaScript /JS \
         (app.alert\\(1\\)) >> >>",
        pages.0, form.0
    );
    let forged = stamp(&append_objects(&done, &[(root.0, body)]), &a);
    assert_broken(
        &verify(&forged, &trust_with(&a.ca)).unwrap(),
        "catalog was modified beyond its validation data",
    );
}

#[test]
fn an_annotation_cannot_ride_along_with_a_document_timestamp() {
    let a = authorities();
    let done = completed_without_timestamps();
    let (doc, _, page) = ids(&done);
    let mut page_dict = doc.get_object(page).unwrap().as_dict().unwrap().clone();
    let note = doc.max_id + 1;
    let mut annots = page_dict
        .get(b"Annots")
        .unwrap()
        .as_array()
        .unwrap()
        .clone();
    annots.push(lopdf::Object::Reference((note, 0)));
    page_dict.set("Annots", lopdf::Object::Array(annots));
    let forged = stamp(
        &append_objects(
            &done,
            &[
                (page.0, pdf_text(&lopdf::Object::Dictionary(page_dict))),
                (
                    note,
                    "<< /Type /Annot /Subtype /FreeText /Rect [72 600 300 640] /Contents (Paid) \
                     >>"
                    .into(),
                ),
            ],
        ),
        &a,
    );
    assert_broken(
        &verify(&forged, &trust_with(&a.ca)).unwrap(),
        "exactly one document timestamp field",
    );
}

#[test]
fn the_validation_data_holds_only_certificates_ocsp_responses_and_crls() {
    let a = authorities();
    let done = completed_without_timestamps();
    let junk = Dss {
        certs: vec![b"<script>not a certificate</script>".to_vec()],
        ..Default::default()
    };
    let forged = stamp(&pades::add_validation_data(&done, &junk).unwrap(), &a);
    assert_broken(
        &verify(&forged, &trust_with(&a.ca)).unwrap(),
        "is not a certificate",
    );
}

#[test]
fn validation_data_cannot_be_removed_or_extended_with_other_entries() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let sealed = sealed_with_validation_data(&a, &completed_with_timestamps(&a));
    let (doc, root, _) = ids(&sealed);
    let dss = doc
        .get_object(root)
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"DSS")
        .unwrap()
        .as_reference()
        .unwrap();
    let current = doc.get_object(dss).unwrap().as_dict().unwrap();
    let certs = current.get(b"Certs").unwrap().as_array().unwrap();
    let refs = |list: &[lopdf::Object]| {
        list.iter()
            .map(|o| {
                let r = o.as_reference().unwrap();
                format!("{} 0 R", r.0)
            })
            .collect::<Vec<_>>()
            .join(" ")
    };

    // An entry dropped.
    let dropped = format!("<< /Type /DSS /Certs [{}] >>", refs(&certs[..1]));
    let forged = stamp(&append_objects(&sealed, &[(dss.0, dropped)]), &a);
    assert_broken(&verify(&forged, &trust).unwrap(), "lost entries");

    // A per-signature /VRI dictionary, which SignPDF does not use.
    let ocsps = current.get(b"OCSPs").unwrap().as_array().unwrap();
    let vri = format!(
        "<< /Type /DSS /Certs [{}] /OCSPs [{}] /VRI << >> >>",
        refs(certs),
        refs(ocsps)
    );
    let forged = stamp(&append_objects(&sealed, &[(dss.0, vri)]), &a);
    assert_broken(&verify(&forged, &trust).unwrap(), "/VRI");

    // The catalog pointed at a new DSS while the old one is rewritten.
    let moved = doc.max_id + 1;
    let mut catalog = doc.get_object(root).unwrap().as_dict().unwrap().clone();
    catalog.set("DSS", lopdf::Object::Reference((moved, 0)));
    let same = format!(
        "<< /Type /DSS /Certs [{}] /OCSPs [{}] >>",
        refs(certs),
        refs(ocsps)
    );
    let forged = stamp(
        &append_objects(
            &sealed,
            &[
                (root.0, pdf_text(&lopdf::Object::Dictionary(catalog))),
                (dss.0, "<< /Type /DSS /Rewritten true >>".into()),
                (moved, same),
            ],
        ),
        &a,
    );
    assert_broken(
        &verify(&forged, &trust).unwrap(),
        &format!("object {} 0 was modified", dss.0),
    );
}

#[test]
fn bytes_under_a_document_timestamp_cannot_change() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let sealed = sealed_with_validation_data(&a, &completed_with_timestamps(&a));
    // Flip a byte inside the OCSP response the document timestamp covers.
    let dss = pades::read_dss(&sealed).unwrap().unwrap();
    let ocsp = &dss.ocsps[0];
    let at = sealed
        .windows(ocsp.len())
        .position(|w| w == ocsp.as_slice())
        .unwrap()
        + ocsp.len() / 2;
    let mut tampered = sealed.clone();
    tampered[at] ^= 1;
    assert_broken(
        &verify(&tampered, &trust).unwrap(),
        "changed after it was made",
    );
}

#[test]
fn unsigned_validation_data_after_a_document_timestamp_is_detected() {
    let a = authorities();
    let trust = trust_with(&a.ca);
    let sealed = add_document_timestamp(&completed_without_timestamps(), &a.document_tsa).unwrap();
    let ocsps = answer_all(&a.ca, &sealed, &trust);
    let unsigned = pades::add_validation_data(
        &sealed,
        &Dss {
            ocsps,
            ..Default::default()
        },
    )
    .unwrap();
    assert_broken(
        &verify(&unsigned, &trust).unwrap(),
        "appended after the last signature or document timestamp",
    );
}
