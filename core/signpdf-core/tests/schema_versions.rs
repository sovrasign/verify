//! Envelope schema versions across builds.
//!
//! * **The compatibility corpus** (`tests/corpus/v<N>/<label>/`): documents made by earlier
//!   builds (see `tests/corpus/README.md`). This build must give each one the verdict the build
//!   that made it gave, verify it against pinned keys, decode every revision's envelope without
//!   losing anything, and still be able to finish a document left half-signed.
//! * **Newer versions**: a document whose envelope is newer than this build is refused by
//!   prepare, sign, decline, verify and the certificate with `UnsupportedSchemaVersion`, never
//!   reported as invalid and never signed.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use signpdf_core::crypto::KeyPair;
use signpdf_core::pades::{self, EmbeddedFile, SignOptions};
use signpdf_core::schema::{self, OLDEST_SCHEMA_VERSION};
use signpdf_core::workflow::{self, ENVELOPE_NAME};
use signpdf_core::{
    completion_certificate, prepare, read_envelope, sign, verify, DateFormat, FieldType, Level,
    Method, SignPdfError, SigningOrder, TimestampPolicy, TrustStore, SCHEMA_VERSION,
};

// --- the corpus ------------------------------------------------------------------------------

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

/// One fixture set: the documents one build made for one schema version.
struct FixtureSet {
    version: u32,
    dir: PathBuf,
}

impl FixtureSet {
    fn name(&self) -> String {
        format!(
            "v{}/{}",
            self.version,
            self.dir.file_name().unwrap().to_string_lossy()
        )
    }

    fn pdfs(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "pdf"))
            .collect();
        v.sort();
        v
    }

    fn pdf(&self, stem: &str) -> Vec<u8> {
        std::fs::read(self.dir.join(format!("{stem}.pdf")))
            .unwrap_or_else(|e| panic!("{}: {stem}.pdf: {e}", self.name()))
    }

    fn trust(&self) -> TrustStore {
        let json = std::fs::read(self.dir.join("trust.json"))
            .unwrap_or_else(|e| panic!("{}: trust.json: {e}", self.name()));
        TrustStore::from_json_bytes(&json).unwrap()
    }
}

fn fixture_sets() -> Vec<FixtureSet> {
    let mut sets = Vec::new();
    for entry in std::fs::read_dir(corpus_root()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let Some(version) = name.strip_prefix('v').and_then(|v| v.parse::<u32>().ok()) else {
            continue;
        };
        for set in std::fs::read_dir(&path).unwrap() {
            let dir = set.unwrap().path();
            if dir.is_dir() {
                sets.push(FixtureSet { version, dir });
            }
        }
    }
    sets.sort_by_key(|s| s.dir.clone());
    sets
}

#[test]
fn the_corpus_covers_every_supported_version() {
    let sets = fixture_sets();
    for v in OLDEST_SCHEMA_VERSION..=SCHEMA_VERSION {
        let n = sets
            .iter()
            .filter(|s| s.version == v && !s.pdfs().is_empty())
            .count();
        assert!(
            n > 0,
            "no corpus fixtures for envelope schema v{v}: run scripts/make-schema-corpus.sh \
             with the commit that introduced it (see tests/corpus/README.md)"
        );
    }
    for s in &sets {
        assert!(
            schema::support(u64::from(s.version)) == schema::VersionSupport::Supported,
            "{}: the corpus holds a version this build does not support; versions are never \
             dropped",
            s.name()
        );
    }
}

#[test]
fn the_newest_version_has_a_dropdown_and_a_signature_timestamp_in_the_corpus() {
    // A format change to a filled dropdown or to a PAdES B-T signature timestamp must break a
    // fixture, not a customer's document: the current version's fixtures
    // cover both. `signpdf demo` (the script's generator) writes both.
    let (mut dropdown, mut timestamp) = (false, false);
    for set in fixture_sets()
        .into_iter()
        .filter(|s| s.version == SCHEMA_VERSION)
    {
        let trust = set.trust();
        for pdf_path in set.pdfs() {
            let report = verify(&std::fs::read(&pdf_path).unwrap(), &trust).unwrap();
            let env = report.envelope.as_ref().unwrap();
            dropdown |= env
                .fields
                .iter()
                .any(|f| f.field_type == FieldType::Dropdown && f.value.is_some());
            // Trusted through the fixture set's pinned TSA, so it dates the signature.
            timestamp |= report
                .signatures
                .iter()
                .any(|s| s.time_source == "tsa" && s.timestamp.as_ref().is_some_and(|t| t.trusted));
        }
    }
    assert!(
        dropdown && timestamp,
        "the v{SCHEMA_VERSION} corpus lacks a filled dropdown ({dropdown}) or a trusted signature \
         timestamp ({timestamp}): add a fixture set from a commit whose demo writes both \
         (scripts/make-schema-corpus.sh)"
    );
}

#[test]
fn the_newest_version_has_every_signature_timestamp_policy_in_the_corpus() {
    // The envelope's `signature_timestamps` policy is part of the prepared terms: the current
    // version's fixtures hold signed envelopes of each value, so a change to how any of them is
    // written or checked breaks a fixture first. `signpdf demo` writes `required` (with both
    // signatures timestamped) and `none`; the earlier fixture sets state no policy (`optional`).
    let mut seen = std::collections::BTreeSet::new();
    for set in fixture_sets()
        .into_iter()
        .filter(|s| s.version == SCHEMA_VERSION)
    {
        let trust = set.trust();
        for pdf_path in set.pdfs() {
            let report = verify(&std::fs::read(&pdf_path).unwrap(), &trust).unwrap();
            if report.signatures.is_empty() {
                continue;
            }
            let policy = report
                .envelope
                .as_ref()
                .unwrap()
                .policy
                .signature_timestamps;
            match policy {
                TimestampPolicy::Required => {
                    // A required timestamp that is missing (a decline signed without a TSA) is a
                    // warning, never a failure.
                    for s in &report.signatures {
                        let missing = report.warnings.iter().any(|w| {
                            w.contains(&format!("signer '{}'", s.signer_id))
                                && w.contains("no signature timestamp")
                        });
                        assert_eq!(
                            s.timestamp.is_none(),
                            missing,
                            "{}: {:?}",
                            pdf_path.display(),
                            report.warnings
                        );
                    }
                }
                TimestampPolicy::None => assert!(
                    report
                        .signatures
                        .iter()
                        .all(|s| s.timestamp.is_none() && s.time_source == "device"),
                    "{}",
                    pdf_path.display()
                ),
                TimestampPolicy::Optional => {}
            }
            seen.insert(policy.as_str());
        }
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        ["none", "optional", "required"],
        "the v{SCHEMA_VERSION} corpus lacks a signed envelope of some signature_timestamps \
         policy: add a fixture set from a commit whose demo writes them \
         (scripts/make-schema-corpus.sh)"
    );
}

#[test]
fn the_newest_version_has_local_dates_consent_and_a_service_link_in_the_corpus() {
    // The signer evidence of hosted signing: a date-signed field holding the signer's local date,
    // a date drawn in a format other than ISO, each signer's UTC offset, a consent to electronic
    // records (one with the reference hash of a translation) and the service link. A format
    // change to any of them must break a fixture first. `signpdf demo` writes all of them.
    let mut seen = std::collections::BTreeSet::new();
    for set in fixture_sets()
        .into_iter()
        .filter(|s| s.version == SCHEMA_VERSION)
    {
        let trust = set.trust();
        for pdf_path in set.pdfs() {
            let report = verify(&std::fs::read(&pdf_path).unwrap(), &trust).unwrap();
            let env = report.envelope.as_ref().unwrap();
            for s in &report.signatures {
                if env
                    .fields
                    .iter()
                    .filter(|f| f.assigned_signer == s.signer_id && f.signing_date)
                    .any(|f| f.value.as_deref() == s.local_signed_at.get(..10))
                {
                    seen.insert("a date-signed field with the local date");
                }
                if !s.utc_offset.is_empty() && s.utc_offset != "+00:00" {
                    seen.insert("a UTC offset");
                }
                if s.esign_consent
                    .as_ref()
                    .is_some_and(|c| c.ref_sha256.is_some())
                {
                    seen.insert("a consent to a translated disclosure");
                }
            }
            if env
                .fields
                .iter()
                .any(|f| f.value.is_some() && f.date_format.is_some_and(|d| d != DateFormat::Iso))
            {
                seen.insert("a date in a sealed format");
            }
            if report.service_link.is_some() {
                seen.insert("a service link");
            }
        }
    }
    assert_eq!(
        seen.len(),
        5,
        "the v{SCHEMA_VERSION} corpus has only {seen:?}: add a fixture set from a commit whose \
         demo writes them all (scripts/make-schema-corpus.sh)"
    );
}

#[test]
fn the_newest_version_has_assurance_levels_in_the_corpus() {
    // Assurance levels (docs/SECURITY_MODEL.md §5): the demo's NDA has an L1 slot that an account
    // sign-in fills (L2) and a slot asking for an organization identity (`min_level` L3,
    // `required_methods` [organization], `required_domain`) that a Google Workspace-style
    // account fills (L3). A change to how either is written or computed must break a fixture.
    let mut seen = std::collections::BTreeSet::new();
    for set in fixture_sets()
        .into_iter()
        .filter(|s| s.version == SCHEMA_VERSION)
    {
        let trust = set.trust();
        for pdf_path in set.pdfs() {
            let report = verify(&std::fs::read(&pdf_path).unwrap(), &trust).unwrap();
            let env = report.envelope.as_ref().unwrap();
            for s in &report.signatures {
                let slot = env.signer(&s.signer_id).unwrap();
                if !report.valid || s.kind != "signed" {
                    continue;
                }
                match (slot.identity_policy.min_level, s.level) {
                    (Level::L1, Some(Level::L2)) => {
                        seen.insert("an L1 slot filled by an account (L2)");
                    }
                    (Level::L3, Some(Level::L3))
                        if slot.identity_policy.required_methods == [Method::Organization]
                            && s.basis[0].organization.is_some() =>
                    {
                        seen.insert("an L3 slot filled by an organization identity");
                    }
                    _ => {}
                }
            }
        }
    }
    assert_eq!(
        seen.len(),
        2,
        "the v{SCHEMA_VERSION} corpus has only {seen:?}: add a fixture set from a commit whose \
         demo has an organization slot (scripts/make-schema-corpus.sh)"
    );
}

#[test]
fn the_newest_version_has_document_timestamps_and_validation_data_in_the_corpus() {
    // What a hosted service adds when envelopes end (docs/SECURITY_MODEL.md §4, "Document
    // timestamps and validation data"): a document sealed at PAdES B-LTA (validation data for its
    // signature timestamps, then a document timestamp over it), and an envelope without signature
    // timestamps sealed by one document timestamp. A change to how either is written or checked
    // must break a fixture first. `signpdf demo` writes both (signed-ltv.pdf,
    // sealed-no-timestamps.pdf).
    let mut seen = std::collections::BTreeSet::new();
    for set in fixture_sets()
        .into_iter()
        .filter(|s| s.version == SCHEMA_VERSION)
    {
        let trust = set.trust();
        for pdf_path in set.pdfs() {
            let report = verify(&std::fs::read(&pdf_path).unwrap(), &trust).unwrap();
            let trusted_document_timestamp = report
                .document_timestamps
                .iter()
                .any(|d| d.valid && d.timestamp.is_trusted());
            if report.pades_level == "B-LTA"
                && report
                    .validation_data
                    .as_ref()
                    .is_some_and(|v| v.ocsp_responses > 0)
                && report.signatures.iter().all(|s| {
                    s.timestamp
                        .as_ref()
                        .is_some_and(|t| t.validation == "complete")
                })
            {
                seen.insert("B-LTA");
            }
            if !report.signatures.is_empty()
                && report.signatures.iter().all(|s| s.timestamp.is_none())
                && trusted_document_timestamp
                && report.pades_level == "B-T"
            {
                seen.insert("sealed by a document timestamp");
            }
        }
    }
    assert_eq!(
        seen.len(),
        2,
        "the v{SCHEMA_VERSION} corpus has only {seen:?}: add a fixture set from a commit whose \
         demo writes signed-ltv.pdf and sealed-no-timestamps.pdf (scripts/make-schema-corpus.sh)"
    );
}

#[test]
fn the_newest_version_has_an_envelope_of_several_documents_in_the_corpus() {
    // Several documents per envelope (docs/SECURITY_MODEL.md §1): an envelope whose source
    // combines documents, with its `documents` index in the prepared terms and signers' fields in
    // several of them, signed by everyone. `signpdf demo` writes it since version 5
    // (signed-documents.pdf). A change to how the index is written or checked must break a
    // fixture first; and every document of the index can still be cut out as a convenience copy.
    let mut found = false;
    for set in fixture_sets()
        .into_iter()
        .filter(|s| s.version == SCHEMA_VERSION)
    {
        let trust = set.trust();
        for pdf_path in set.pdfs() {
            let pdf = std::fs::read(&pdf_path).unwrap();
            let report = verify(&pdf, &trust).unwrap();
            let env = report.envelope.as_ref().unwrap();
            if env.documents.len() < 2 || !report.valid || !report.complete {
                continue;
            }
            let documents_with_fields: std::collections::BTreeSet<usize> = env
                .fields
                .iter()
                .filter_map(|f| env.document_of_page(f.page))
                .collect();
            if documents_with_fields.len() < 2 {
                continue;
            }
            for (i, d) in env.documents.iter().enumerate() {
                let copy = signpdf_core::extract_document(&pdf, i).unwrap();
                assert_eq!(
                    pades::page_geometry(&copy).unwrap().len(),
                    d.page_count as usize,
                    "{}: document {}",
                    pdf_path.display(),
                    i + 1
                );
            }
            found = true;
        }
    }
    assert!(
        found,
        "the v{SCHEMA_VERSION} corpus has no signed envelope of several documents: add a fixture \
         set from a commit whose demo writes signed-documents.pdf (scripts/make-schema-corpus.sh)"
    );
}

#[test]
fn the_newest_version_has_typed_and_drawn_signatures_in_the_corpus() {
    // From version 6 a signer's record keeps their drawing and the verifier redraws it: a change
    // to how a typed signature's filled paths or a drawn one's strokes are written must break a
    // fixture, not a customer's document. `signpdf demo` (the script's generator) has Alice type
    // her signature and Bob draw his.
    let (mut typed, mut drawn) = (false, false);
    for set in fixture_sets()
        .into_iter()
        .filter(|s| s.version == SCHEMA_VERSION)
    {
        let trust = set.trust();
        for pdf_path in set.pdfs() {
            let report = verify(&std::fs::read(&pdf_path).unwrap(), &trust).unwrap();
            let env = report.envelope.as_ref().unwrap();
            for (status, record) in report.signatures.iter().zip(&env.signatures) {
                let kind = record.drawing.as_ref().map(|d| d.kind()).unwrap_or("");
                assert_eq!(status.drawing, kind, "{}", pdf_path.display());
                typed |= kind == "typed";
                drawn |= kind == "drawn";
            }
        }
    }
    assert!(
        typed && drawn,
        "the v{SCHEMA_VERSION} corpus lacks a recorded typed ({typed}) or drawn ({drawn})          signature: add a fixture set from a commit whose demo writes both          (scripts/make-schema-corpus.sh)"
    );
}

#[test]
fn the_newest_version_has_number_fields_and_a_verify_at_stamp_in_the_corpus() {
    // From version 7 a number field keeps a canonical decimal drawn in its sealed style, and the
    // document-ID stamp draws the 'verify at' address: a change to how either is written or drawn
    // must break a fixture, not a customer's document. `signpdf demo` has Bob fill a number field
    // drawn "12 500,00" and names verify.example.com.
    let (mut number, mut verify_at) = (false, false);
    for set in fixture_sets()
        .into_iter()
        .filter(|s| s.version == SCHEMA_VERSION)
    {
        let trust = set.trust();
        for pdf_path in set.pdfs() {
            let pdf = std::fs::read(&pdf_path).unwrap();
            let report = verify(&pdf, &trust).unwrap();
            let env = report.envelope.as_ref().unwrap();
            let filled = env.fields.iter().any(|f| {
                f.field_type == FieldType::Number
                    && f.number_format.is_some()
                    && f.value.as_deref().is_some_and(|v| !v.is_empty())
            });
            if filled && report.integrity_ok {
                number = true;
            }
            if let Some(address) = &env.verify_at {
                let line = format!("Verify at {address}");
                assert!(
                    pdf.windows(line.len()).any(|w| w == line.as_bytes()),
                    "{}: the stamp does not draw {line}",
                    pdf_path.display()
                );
                verify_at |= report.integrity_ok;
            }
        }
    }
    assert!(
        number && verify_at,
        "the v{SCHEMA_VERSION} corpus lacks a filled number field ({number}) or a 'verify at'          stamp ({verify_at}): add a fixture set from a commit whose demo writes both          (scripts/make-schema-corpus.sh)"
    );
}

#[test]
fn the_newest_version_has_initials_from_slot_names_in_the_corpus() {
    // From version 9 the envelope names its initials rule and the further initials fields hold
    // the letters of the slot's name: a change to the rule must break a fixture, not a customer's
    // document. `signpdf demo` names its signers "Alice Example" and "Bob Builder" (whose
    // addresses alone would give "A" and "B") and gives each an initials field besides their
    // signature field in its envelope of several documents.
    let mut seen = std::collections::BTreeSet::new();
    for set in fixture_sets()
        .into_iter()
        .filter(|s| s.version == SCHEMA_VERSION)
    {
        let trust = set.trust();
        for pdf_path in set.pdfs() {
            let report = verify(&std::fs::read(&pdf_path).unwrap(), &trust).unwrap();
            let env = report.envelope.as_ref().unwrap();
            assert!(env.initials_rule.is_some(), "{}", pdf_path.display());
            if !report.valid {
                continue;
            }
            for f in env
                .fields
                .iter()
                .filter(|f| f.field_type == FieldType::Initials)
            {
                if let Some(v) = &f.value {
                    seen.insert(v.clone());
                }
            }
        }
    }
    assert!(
        seen.contains("AE") && seen.contains("BB"),
        "the v{SCHEMA_VERSION} corpus has initials {seen:?}, not AE and BB: add a fixture set          from a commit whose demo names its signers in full (scripts/make-schema-corpus.sh)"
    );
}

/// The verdict fields that must not change between builds, compared where the generating
/// build's report has them (older builds report fewer fields).
const TOP_FIELDS: &[&str] = &[
    "valid",
    "integrity_ok",
    "identities_trusted",
    "complete",
    "declined",
    "audit_ok",
    "order_ok",
    "original_len",
    "document_sha256",
    "service_link",
    "pades_level",
];
const REVISION_FIELDS: &[&str] = &[
    "index",
    "kind",
    "signer_id",
    "actor_fingerprint",
    "signed_at",
    "time_source",
    "valid",
    "idp_email",
    "idp_issuer",
    "identity_trust",
    "level",
    "signature_code",
    "utc_offset",
    "local_signed_at",
    "esign_consent",
    "drawing",
];

/// The assurance level a report made before levels existed (schema version 3) stands for: its
/// two-value `assurance` maps to the level today's verifier computes for the same identity (the
/// corpus documents were signed with the test issuer, an account provider): `consumer` is an
/// account sign-in, L2; `enterprise` an organization identity, L3.
fn level_of_old_report(revision: &serde_json::Value) -> Option<serde_json::Value> {
    match revision.get("assurance")?.as_str()? {
        "consumer" => Some("L2".into()),
        "enterprise" => Some("L3".into()),
        other => panic!("unknown assurance '{other}' in a corpus report"),
    }
}

fn compare(
    what: &str,
    expected: &serde_json::Value,
    actual: &serde_json::Value,
    fields: &[&str],
) -> Vec<String> {
    let mut diffs = Vec::new();
    for f in fields {
        let old_level = (*f == "level")
            .then(|| level_of_old_report(expected))
            .flatten();
        if let Some(e) = expected.get(*f).or(old_level.as_ref()) {
            let a = actual.get(*f).unwrap_or(&serde_json::Value::Null);
            if e != a {
                diffs.push(format!("{what}.{f}: made {e}, now {a}"));
            }
        }
    }
    diffs
}

#[test]
fn every_corpus_document_gets_the_verdict_its_build_gave() {
    let mut checked = 0;
    for set in fixture_sets() {
        for pdf_path in set.pdfs() {
            let name = format!(
                "{}/{}",
                set.name(),
                pdf_path.file_name().unwrap().to_string_lossy()
            );
            let report_path = pdf_path.with_extension("report.json");
            let expected: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&report_path)
                    .unwrap_or_else(|e| panic!("{name}: missing {}: {e}", report_path.display())),
            )
            .unwrap();
            let pdf = std::fs::read(&pdf_path).unwrap();
            // The generating build verified with the insecure dev opt-in; so does this check.
            let report = verify(&pdf, &TrustStore::insecure_dev())
                .unwrap_or_else(|e| panic!("{name}: this build cannot verify it: {e}"));
            let actual = serde_json::to_value(&report).unwrap();

            let mut diffs = compare("report", &expected, &actual, TOP_FIELDS);
            diffs.extend(compare(
                "preparer",
                &expected["preparer"],
                &actual["preparer"],
                REVISION_FIELDS,
            ));
            let (es, as_) = (
                expected["signatures"].as_array().unwrap(),
                actual["signatures"].as_array().unwrap(),
            );
            if es.len() != as_.len() {
                diffs.push(format!(
                    "signatures: made {} revision(s), now {}",
                    es.len(),
                    as_.len()
                ));
            }
            for (i, (e, a)) in es.iter().zip(as_).enumerate() {
                diffs.extend(compare(&format!("signatures[{i}]"), e, a, REVISION_FIELDS));
            }
            if expected["messages"] == serde_json::json!([]) && !report.messages.is_empty() {
                diffs.push(format!("new problems: {:?}", report.messages));
            }
            // From the builds that report them, the findings' codes are stable: the same
            // document gives the same codes, which clients translate.
            if let Some(findings) = expected.get("findings").and_then(|f| f.as_array()) {
                let codes = |f: &[serde_json::Value]| -> Vec<String> {
                    f.iter()
                        .map(|f| f["code"].as_str().unwrap_or_default().to_string())
                        .collect()
                };
                let then = codes(findings);
                let now = codes(actual["findings"].as_array().unwrap());
                if then != now {
                    diffs.push(format!("finding codes were {then:?}, now {now:?}"));
                }
            }
            assert!(
                diffs.is_empty(),
                "{name}: this build's verdict differs from the build that made it:\n  {}",
                diffs.join("\n  ")
            );
            assert_eq!(
                report.envelope.as_ref().unwrap().schema_version,
                set.version,
                "{name}"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "the corpus is empty");
}

#[test]
fn every_corpus_document_verifies_against_pinned_keys() {
    for set in fixture_sets() {
        let trust = set.trust();
        assert!(!trust.allow_insecure_dev_issuer, "{}", set.name());
        for pdf_path in set.pdfs() {
            let name = format!("{}/{}", set.name(), pdf_path.display());
            let report = verify(&std::fs::read(&pdf_path).unwrap(), &trust).unwrap();
            assert!(
                report.valid && report.identities_trusted,
                "{name}: {:?}",
                report.messages
            );
            for s in report.preparer.iter().chain(&report.signatures) {
                assert_eq!(s.identity_trust, "trusted", "{name}");
            }
        }
    }
}

#[test]
fn corpus_documents_take_their_trusted_time_from_the_timestamps_they_carry() {
    // Documents made before key windows existed, judged by a store whose issuers require
    // trusted time (as a service's own email-code provider does): a revision a trusted
    // timestamp covers stays trusted, one nothing covers waits for its timestamp, and the
    // envelope sealed by one document timestamp (no signature timestamps) is valid.
    let mut sealed_free = 0;
    for set in fixture_sets() {
        let mut strict = set.trust();
        for issuer in &mut strict.issuers {
            issuer.requires_trusted_time = true;
        }
        for pdf_path in set.pdfs() {
            let name = format!("{}/{}", set.name(), pdf_path.display());
            let report = verify(&std::fs::read(&pdf_path).unwrap(), &strict).unwrap();
            assert!(report.integrity_ok, "{name}: {:?}", report.messages);
            let revisions: Vec<_> = report.preparer.iter().chain(&report.signatures).collect();
            for s in &revisions {
                let expected = if s.existed_before.is_some() {
                    "trusted"
                } else {
                    "no-trusted-time"
                };
                assert_eq!(s.identity_trust, expected, "{name}: {s:?}");
            }
            let all_covered = revisions.iter().all(|s| s.existed_before.is_some());
            assert_eq!(report.valid, all_covered, "{name}: {:?}", report.messages);
            assert_eq!(report.trusted_time_pending, !all_covered, "{name}");
            if pdf_path.ends_with("sealed-no-timestamps.pdf") {
                assert!(report.valid, "{name}");
                for s in &revisions {
                    assert_eq!(s.time_source, "device", "{name}");
                    let e = s.existed_before.as_ref().unwrap();
                    assert_eq!(
                        (e.source.as_str(), e.document_timestamp),
                        ("document", Some(1)),
                        "{name}"
                    );
                    assert!(!s.token_issued_at.is_empty(), "{name}");
                }
                sealed_free += 1;
            }
        }
    }
    assert!(
        sealed_free > 0,
        "no sealed envelope without signature timestamps in the corpus"
    );
}

#[test]
fn every_corpus_envelope_decodes_without_loss() {
    // Every revision's envelope must decode into this build's model and encode back to the same
    // JSON: anything dropped on the way would escape the revision-chain comparison.
    for set in fixture_sets() {
        for pdf_path in set.pdfs() {
            let pdf = std::fs::read(&pdf_path).unwrap();
            for (i, sig) in pades::pades_verify(&pdf).unwrap().iter().enumerate() {
                let raw = pades::read_attachment(&pdf[..sig.covered_end], ENVELOPE_NAME).unwrap();
                let env = schema::decode_envelope(&raw).unwrap();
                assert_eq!(env.schema_version, set.version);
                let original: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                let again: serde_json::Value =
                    serde_json::from_slice(&schema::encode_envelope(&env).unwrap()).unwrap();
                assert_eq!(
                    original,
                    again,
                    "{} revision {i}: the envelope does not survive decode + encode",
                    pdf_path.display()
                );
            }
        }
    }
}

/// Values for every field `email`'s slot must fill.
fn field_values_for(pdf: &[u8], email: &str) -> Vec<(String, String)> {
    let env = read_envelope(pdf).unwrap();
    let slot = env.signers.iter().find(|s| s.handle == email).unwrap();
    let mut values = Vec::new();
    let mut groups = Vec::new();
    for f in env.fields.iter().filter(|f| f.assigned_signer == slot.id) {
        let value = match f.field_type {
            FieldType::Text | FieldType::Multiline => match &f.value_format {
                None => "Corpus test".to_string(),
                // From version 8: a value of the field's sealed format.
                Some(format) => sample_value(format),
            },
            FieldType::Checkbox => "true".to_string(),
            FieldType::Radio => {
                let group = f.group.clone().unwrap_or_default();
                if groups.contains(&group) {
                    continue;
                }
                groups.push(group);
                "true".to_string()
            }
            FieldType::Dropdown => f.options.as_ref().unwrap()[0].clone(),
            // The smallest value the field takes (its minimum, or zero).
            FieldType::Number => {
                let format = f.number_format.clone().unwrap_or_default();
                format.check(format.min.as_deref().unwrap_or("0")).unwrap()
            }
            // Filled by the engine (a formula field from version 8 is computed).
            FieldType::Signature | FieldType::Initials | FieldType::Date | FieldType::Formula => {
                continue
            }
        };
        values.push((f.id.clone(), value));
    }
    values
}

/// A value of `format` (version 8), for the formats the corpus demos use and a few more.
fn sample_value(format: &signpdf_core::ValueFormat) -> String {
    use signpdf_core::ValueFormatKind as K;
    match format.kind {
        K::Email => "corpus@example.com",
        K::Phone => "+33612345678",
        K::Amount => "1",
        K::PostalCode if format.country.as_deref() == Some("US") => "94105",
        K::PostalCode => panic!("no sample postal code for {:?}", format.country),
        K::Iban => "GB82WEST12345698765432",
        K::UsSsn => "123-45-6789",
        K::UsEin => "12-3456789",
        // The demo's purchase-order pattern.
        K::Pattern if format.pattern.as_deref() == Some(r"PO-\d{4}-\d{3}") => "PO-2026-118",
        K::Pattern => panic!("no sample value for the pattern {:?}", format.pattern),
    }
    .to_string()
}

/// A sign request for Bob on `pdf`: from an organization account of example.com when his slot
/// asks for an organization identity (the v4 demo's), else from a personal one.
fn bob_request(pdf: &[u8]) -> (KeyPair, signpdf_core::SignRequest) {
    let env = read_envelope(pdf).unwrap();
    let slot = env
        .signers
        .iter()
        .find(|s| s.handle == "bob@example.com")
        .unwrap();
    let (key, mut req) = signer_request("bob@example.com", pdf, "");
    if slot.identity_policy.min_level >= Level::L3 {
        let now = now_unix();
        let issuer = signpdf_core::oidc::testing::shared_es256();
        req.id_token = issuer.mint(serde_json::json!({
            "iss": ISSUER, "sub": "user|bob@example.com", "aud": AUDIENCE,
            "iat": now - 5, "exp": now + 3600,
            "email": "bob@example.com", "email_verified": true, "hd": "example.com",
            "nonce": signpdf_core::compute_nonce(
                &key.public_sec1(),
                &signpdf_core::crypto::sha256_hex(pdf),
            ),
        }));
    }
    (key, req)
}

/// The fixture set's pinned keys plus this process's test issuer.
fn trust_with_this_process(set: &FixtureSet) -> TrustStore {
    let mut t = set.trust();
    t.merge(&trust());
    t
}

#[test]
fn half_signed_corpus_documents_can_be_finished_by_this_build() {
    // An envelope prepared and partly signed by an earlier build (in flight while the service
    // upgrades) must be finishable here, and keeps its schema version.
    for set in fixture_sets() {
        let half = set.pdf("signed-by-alice");
        let (bob_key, mut req) = bob_request(&half);
        req.field_values = field_values_for(&half, "bob@example.com");
        let done = sign(&half, &bob_key, &req)
            .unwrap_or_else(|e| panic!("{}: this build cannot finish it: {e}", set.name()));
        let report = verify(&done, &trust_with_this_process(&set)).unwrap();
        assert!(
            report.valid && report.complete,
            "{}: {:?}",
            set.name(),
            report.messages
        );
        assert_eq!(report.signatures.len(), 2);
        assert_eq!(read_envelope(&done).unwrap().schema_version, set.version);
    }
}

#[test]
fn sealed_corpus_documents_can_take_another_document_timestamp() {
    // Renewing an older document's timestamps (validation data was added by an earlier build):
    // this build adds a document timestamp on top, and the result still verifies.
    let mut renewed = 0;
    for set in fixture_sets() {
        let path = set.dir.join("signed-ltv.pdf");
        let Ok(sealed) = std::fs::read(&path) else {
            continue;
        };
        let tsa = signpdf_core::timestamp::testing::TestTsa::new();
        let again = signpdf_core::add_document_timestamp(&sealed, &tsa)
            .unwrap_or_else(|e| panic!("{}: this build cannot renew it: {e}", set.name()));
        let mut trust = set.trust();
        trust.add_tsa_anchor(&tsa.cert_der());
        let report = verify(&again, &trust).unwrap();
        assert!(report.valid, "{}: {:?}", set.name(), report.messages);
        assert_eq!(report.document_timestamps.len(), 2, "{}", set.name());
        assert!(
            report
                .document_timestamps
                .iter()
                .all(|d| d.valid && d.timestamp.is_trusted()),
            "{}",
            set.name()
        );
        renewed += 1;
    }
    assert!(renewed > 0, "no sealed document in the corpus");
}

#[test]
fn prepared_corpus_documents_can_be_declined_by_this_build() {
    for set in fixture_sets() {
        let prepared = set.pdf("prepared");
        let (alice_key, mut req) = signer_request("alice@example.com", &prepared, "");
        req.decline = true;
        let declined = sign(&prepared, &alice_key, &req)
            .unwrap_or_else(|e| panic!("{}: this build cannot decline it: {e}", set.name()));
        let report = verify(&declined, &trust_with_this_process(&set)).unwrap();
        assert!(
            report.valid && report.declined,
            "{}: {:?}",
            set.name(),
            report.messages
        );
        assert_eq!(
            read_envelope(&declined).unwrap().schema_version,
            set.version
        );
    }
}

#[test]
fn a_tampered_corpus_document_fails() {
    // The corpus check means something only if it can fail.
    let set = fixture_sets().into_iter().next().unwrap();
    let mut pdf = set.pdf("signed-final");
    let at = pdf.len() / 3;
    pdf[at] ^= 0x01;
    assert!(!verify(&pdf, &set.trust()).map(|r| r.valid).unwrap_or(false));
}

// --- newer versions --------------------------------------------------------------------------

/// A prepared two-signer document (this build, current version).
fn prepared_now() -> Vec<u8> {
    let pdf = signpdf_core::container::make_sample_pdf("Schema version test");
    let (key, req) = two_signer_request(&pdf);
    prepare(&pdf, &req, &key).unwrap()
}

/// `base` plus a properly signed revision whose envelope claims `version` and carries a term this
/// build does not know: what a newer build's document looks like to this one.
fn with_envelope_version(base: &[u8], version: u64) -> Vec<u8> {
    let raw = pades::read_attachment(base, ENVELOPE_NAME).unwrap();
    let mut env: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    env["schema_version"] = serde_json::json!(version);
    env["terms_from_a_newer_build"] = serde_json::json!({"must_not_be_dropped": true});
    let opts = SignOptions {
        embed: Some(EmbeddedFile {
            name: ENVELOPE_NAME.to_string(),
            data: serde_json::to_vec(&env).unwrap(),
            mime: "application/json".to_string(),
            relationship: "Data".to_string(),
            description: "SignPDF workflow envelope".to_string(),
        }),
        ..Default::default()
    };
    pades::pades_sign_with(base, &KeyPair::generate(), &opts).unwrap()
}

fn assert_newer(result: Result<impl std::fmt::Debug, SignPdfError>, version: u64, what: &str) {
    match result {
        Err(SignPdfError::UnsupportedSchemaVersion { found, newest }) => {
            assert_eq!(found, version, "{what}");
            assert_eq!(newest, SCHEMA_VERSION, "{what}");
        }
        other => panic!("{what}: expected UnsupportedSchemaVersion, got {other:?}"),
    }
}

#[test]
fn a_newer_version_is_neither_verified_nor_signed() {
    let base = prepared_now();
    for version in [u64::from(SCHEMA_VERSION) + 1, 1000] {
        let newer = with_envelope_version(&base, version);
        let what = |op: &str| format!("{op} of a v{version} document");

        assert_newer(read_envelope(&newer), version, &what("read"));
        // Not "invalid": this build cannot judge it.
        assert_newer(
            verify(&newer, &TrustStore::insecure_dev()),
            version,
            &what("verify"),
        );
        assert_newer(
            completion_certificate(&newer, &trust()),
            version,
            &what("certificate"),
        );

        let (alice_key, req) = signer_request("alice@example.com", &newer, "");
        assert_newer(sign(&newer, &alice_key, &req), version, &what("sign"));
        let (alice_key, mut req) = signer_request("alice@example.com", &newer, "");
        req.decline = true;
        assert_newer(sign(&newer, &alice_key, &req), version, &what("decline"));
        // Even without the integrity pre-check, the envelope itself is refused.
        let (alice_key, req) = signer_request("alice@example.com", &newer, "");
        assert_newer(
            workflow::testing::sign_malicious(&newer, &alice_key, &req, true, &|_| {}),
            version,
            &what("sign (no pre-check)"),
        );

        // Re-preparing it would overwrite terms this build does not know.
        let (prep_key, prep_req) = two_signer_request(&newer);
        assert_newer(
            prepare(&newer, &prep_req, &prep_key),
            version,
            &what("prepare"),
        );
    }
}

#[test]
fn the_error_tells_the_user_to_update() {
    let newer = with_envelope_version(&prepared_now(), u64::from(SCHEMA_VERSION) + 1);
    let msg = verify(&newer, &trust()).unwrap_err().to_string();
    assert!(msg.starts_with("unsupported version: "), "{msg}");
    assert!(msg.contains("update the app or reload the page"), "{msg}");
}

#[test]
fn a_revision_cannot_move_a_document_to_an_older_version() {
    // No build writes a newer-version revision followed by an older one (an envelope keeps its
    // version), so such a chain is a downgrade attempt and fails.
    let newer = with_envelope_version(&prepared_now(), u64::from(SCHEMA_VERSION) + 1);
    let back = with_envelope_version(&newer, u64::from(SCHEMA_VERSION));
    let report = verify(&back, &trust()).unwrap();
    assert!(!report.integrity_ok, "{report:?}");
}

/// The checked-in document whose envelope claims version 1000, for the FFI and browser checks
/// (which cannot build one themselves).
const NEWER_FIXTURE: &str = "newer/schema-v1000.pdf";

#[test]
fn the_checked_in_newer_version_document_is_refused() {
    let pdf = std::fs::read(corpus_root().join(NEWER_FIXTURE)).unwrap();
    assert_newer(
        verify(&pdf, &TrustStore::insecure_dev()),
        1000,
        NEWER_FIXTURE,
    );
    // Apart from its version, it is a sound document: only the version stops this build.
    let raw = pades::read_attachment(&pdf, ENVELOPE_NAME).unwrap();
    let mut env: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(env["schema_version"], 1000);
    env["schema_version"] = serde_json::json!(SCHEMA_VERSION);
    let sigs = pades::pades_verify(&pdf).unwrap();
    assert!(sigs.iter().all(|s| s.digest_matches && s.signature_valid));
    assert!(sigs.last().unwrap().covers_to_eof);
}

/// Regenerate the checked-in newer-version document (only if it is missing):
/// `cargo test -p signpdf-core --test schema_versions -- --ignored write_newer_version_fixture`.
#[test]
#[ignore = "writes a fixture; run by hand"]
fn write_newer_version_fixture() {
    let path = corpus_root().join(NEWER_FIXTURE);
    if path.exists() {
        return;
    }
    let pdf = signpdf_core::container::make_sample_pdf("A document from a newer SignPDF");
    let (key, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![sig_field("f1", "s1", 0)],
        SigningOrder::Sequential,
    );
    let prepared = prepare(&pdf, &req, &key).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, with_envelope_version(&prepared, 1000)).unwrap();
}
