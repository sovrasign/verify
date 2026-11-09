//! The attack corpus: one document per attack class of `docs/SECURITY_MODEL.md` §6 that can be
//! shown as a file, each with the verdict and finding codes the verifier must give it
//! (`tests/attack/`, published as CC0 test vectors with the compatibility corpus; see
//! `tests/attack/README.md` and `spec/envelope-format.md` §12).
//!
//! `every_attack_vector_gets_its_expected_verdict` runs on every `cargo test`: it verifies each
//! checked-in document against `tests/attack/trust.json` and compares the verdict and the finding
//! codes with `<name>.expected.json`. The regression tests named in each vector keep testing the
//! defence with fresh documents; these files let anyone else (an independent verifier, an older
//! or newer build) check the same attacks without our test code.
//!
//! The vectors are written by
//! `cargo test -p signpdf-core --test attack_vectors -- --ignored write_attack_vectors`, only when
//! `tests/attack/` holds none (see the README's rules).

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use common::*;
use serde::{Deserialize, Serialize};
use signpdf_core::pades::{self, EmbeddedFile};
use signpdf_core::workflow::{testing::sign_malicious, ENVELOPE_NAME};
use signpdf_core::{
    container, prepare, read_envelope, sign, verify, FieldType, Level, SigningOrder,
    TimestampPolicy, TrustStore, SCHEMA_VERSION,
};

fn attack_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/attack")
}

/// What the verifier must say about one vector (`<name>.expected.json`).
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Expected {
    /// The attack, in a sentence.
    attack: String,
    /// The row of `docs/SECURITY_MODEL.md` §6 it belongs to.
    security_model_row: String,
    /// The regression test that keeps testing the defence with fresh documents.
    regression_test: String,
    /// The envelope schema version of the document's envelope.
    schema_version: u32,
    /// `report`: verification returns a report with the verdict below. `error`: the input is
    /// refused before a report can be made (`error_code`); a verifier must not crash or call it
    /// valid.
    outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(default)]
    valid: bool,
    #[serde(default)]
    integrity_ok: bool,
    #[serde(default)]
    identities_trusted: bool,
    /// The codes of the findings that make the document invalid (`severity` `error`), sorted.
    #[serde(default)]
    errors: Vec<String>,
    /// The codes of the warnings, sorted.
    #[serde(default)]
    warnings: Vec<String>,
}

/// One attack: its name (the file name), the facts above and how to build the document.
struct Vector {
    name: &'static str,
    attack: &'static str,
    row: &'static str,
    test: &'static str,
    build: fn() -> Vec<u8>,
}

fn envelope_file(env: &signpdf_core::Envelope) -> EmbeddedFile {
    EmbeddedFile {
        name: ENVELOPE_NAME.into(),
        data: serde_json::to_vec(env).unwrap(),
        mime: "application/json".into(),
        relationship: "Data".into(),
        description: "tampered".into(),
    }
}

fn nda_prepared() -> Vec<u8> {
    let pdf = container::make_sample_pdf("Pay Bob EUR 100");
    let (pk, req) = two_signer_request(&pdf);
    prepare(&pdf, &req, &pk).unwrap()
}

fn nda_completed() -> Vec<u8> {
    let prepared = nda_prepared();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let a = sign(&prepared, &k, &r).unwrap();
    let (k, r) = signer_request("bob@example.com", &a, "");
    sign(&a, &k, &r).unwrap()
}

/// Alice signs `prepared` and applies `tamper` to the envelope her revision embeds.
fn alice_tampers(prepared: &[u8], tamper: &dyn Fn(&mut signpdf_core::Envelope)) -> Vec<u8> {
    let (k, r) = signer_request("alice@example.com", prepared, "");
    sign_malicious(prepared, &k, &r, false, tamper).unwrap()
}

/// A page-content stream saying `text`, as an object body.
fn content(text: &str) -> String {
    let c = format!("BT /F1 24 Tf 72 700 Td ({text}) Tj ET");
    format!("<< /Length {} >>\nstream\n{c}\nendstream", c.len())
}

const VECTORS: &[Vector] = &[
    Vector {
        name: "control-two-signers",
        attack: "None: an honest envelope signed by Alice then Bob. It shows that trust.json is \
                 enough to verify the documents below, so every failure is the attack's.",
        row: "-",
        test: "workflow_e2e",
        build: nda_completed,
    },
    Vector {
        name: "unsigned-update-new-envelope",
        attack: "An unsigned incremental update after the last signature embeds a new envelope \
                 with another title (what a naive reader would show).",
        row: "Unsigned update after the last signature (V7, incremental saving)",
        test: "security_e2e::unsigned_update_after_last_signature_is_detected",
        build: || {
            let done = nda_completed();
            let mut env = read_envelope(&done).unwrap();
            env.title = "Pay Mallory EUR 1,000,000".into();
            pades::embed_attachment(&done, &envelope_file(&env)).unwrap()
        },
    },
    Vector {
        name: "unsigned-update-page-content",
        attack: "An unsigned incremental update after the last signature redefines the page's \
                 content stream.",
        row: "Unsigned update after the last signature (V7, incremental saving)",
        test: "security_e2e::page_content_replaced_after_signing_is_detected",
        build: || append_object_override(&nda_completed(), 5, &content("Pay Mallory")),
    },
    Vector {
        name: "in-transit-edit-then-signed",
        attack: "Someone loosens Bob's slot in transit (an unsigned update), and Alice's client \
                 signs on top of it without its integrity check.",
        row: "Envelope edited in transit before a signer signs",
        test: "security_e2e::signature_over_an_unsigned_in_transit_edit_is_detected",
        build: || {
            let prepared = nda_prepared();
            let mut env = read_envelope(&prepared).unwrap();
            env.signers[1].identity_policy = Default::default();
            let tampered = pades::embed_attachment(&prepared, &envelope_file(&env)).unwrap();
            let (k, r) = signer_request("alice@example.com", &tampered, "s1");
            sign_malicious(&tampered, &k, &r, true, &|_| {}).unwrap()
        },
    },
    Vector {
        name: "signer-changes-title",
        attack: "A signer's own signed revision changes the title (a prepared term).",
        row: "Malicious signer changing terms, other slots, others' fields, history",
        test: "security_e2e::malicious_signer_cannot_change_the_prepared_terms",
        build: || {
            alice_tampers(&nda_prepared(), &|env| {
                env.title = "A different agreement".into()
            })
        },
    },
    Vector {
        name: "signer-loosens-later-slot",
        attack: "A signer's revision removes the identity policy of the next signer's slot.",
        row: "Malicious signer changing terms, other slots, others' fields, history",
        test: "security_e2e::malicious_signer_cannot_loosen_a_later_slot",
        build: || {
            alice_tampers(&nda_prepared(), &|env| {
                env.signers[1].identity_policy = Default::default()
            })
        },
    },
    Vector {
        name: "signer-fills-another-signers-field",
        attack: "Alice's revision fills the price field assigned to Bob.",
        row: "Malicious signer changing terms, other slots, others' fields, history",
        test: "security_e2e::malicious_signer_cannot_fill_another_signers_field",
        build: || {
            let pdf = container::make_sample_pdf("Order");
            let (pk, req) = prepare_request(
                &pdf,
                vec![
                    spec("s1", "Alice", "alice@example.com", 1),
                    spec("s2", "Bob", "bob@example.com", 2),
                ],
                vec![field("bob_price", "s2", FieldType::Text, 0, 300.0)],
                SigningOrder::Sequential,
            );
            let prepared = prepare(&pdf, &req, &pk).unwrap();
            alice_tampers(&prepared, &|env| env.fields[0].value = Some("EUR 1".into()))
        },
    },
    Vector {
        name: "signer-rewrites-history",
        attack: "Bob's revision rewrites the details of Alice's audit entry.",
        row: "Malicious signer changing terms, other slots, others' fields, history",
        test: "security_e2e::malicious_signer_cannot_rewrite_history",
        build: || {
            let prepared = nda_prepared();
            let (k, r) = signer_request("alice@example.com", &prepared, "");
            let a = sign(&prepared, &k, &r).unwrap();
            let (k, r) = signer_request("bob@example.com", &a, "");
            sign_malicious(&a, &k, &r, false, &|env| {
                env.audit_log[1].details = "Alice agreed to pay Bob EUR 1,000,000".into();
            })
            .unwrap()
        },
    },
    Vector {
        name: "signer-claims-another-slot",
        attack: "Alice signs and edits her record to claim Bob's slot, which asks for Bob.",
        row: "Malicious signer changing terms, other slots, others' fields, history",
        test: "security_e2e::malicious_signer_cannot_claim_a_slot_their_identity_does_not_fit",
        build: || {
            let pdf = container::make_sample_pdf("NDA");
            let (pk, mut req) = two_signer_request(&pdf);
            req.signers[0].identity_policy = level_policy("alice@example.com", Level::L1);
            let prepared = prepare(&pdf, &req, &pk).unwrap();
            alice_tampers(&prepared, &|env| env.signatures[0].signer_id = "s2".into())
        },
    },
    Vector {
        name: "shadow-content-in-own-revision",
        attack: "A signer's own revision (covered by their valid signature) also redefines the \
                 page content: a shadow attack.",
        row: "Content change hidden in a signer's own revision (shadow attack)",
        test: "security_e2e::content_change_inside_a_signers_own_revision_is_detected",
        build: || {
            let edited = append_object_override(&nda_prepared(), 5, &content("Pay Bob EUR 900"));
            let (k, r) = signer_request("alice@example.com", &edited, "");
            sign_malicious(&edited, &k, &r, true, &|_| {}).unwrap()
        },
    },
    Vector {
        name: "byte-range-absurd",
        attack: "The last signature's ByteRange claims a second range far beyond the file.",
        row: "Signature wrapping / ByteRange games",
        test: "security_e2e::absurd_byte_range_does_not_panic",
        build: || {
            let mut bad = nda_completed();
            let needle = b"/ByteRange [";
            let pos = bad
                .windows(needle.len())
                .rposition(|w| w == needle)
                .unwrap()
                + needle.len();
            bad[pos + 33..pos + 43].copy_from_slice(b"9999999999");
            bad
        },
    },
    Vector {
        name: "signature-value-flipped",
        attack: "One hex digit of the last signature's CMS (inside its /Contents) is changed.",
        row: "CMS malleability",
        test: "pades_e2e::signatures_are_canonical_pades_baseline",
        build: || {
            let mut bad = nda_completed();
            let needle = b"/Contents <";
            let pos = bad
                .windows(needle.len())
                .rposition(|w| w == needle)
                .unwrap()
                + needle.len();
            // Somewhere in the middle of the DER, well before the zero padding.
            let at = pos + 400;
            bad[at] = if bad[at] == b'0' { b'1' } else { b'0' };
            bad
        },
    },
    Vector {
        name: "identity-self-made-key",
        attack: "Alice's token claims the trusted issuer but is signed by a key the forger made \
                 and archived next to it.",
        row: "Forged identity with a self-made key (V4)",
        test: "workflow_e2e::identity_forged_with_a_self_made_key_is_not_trusted",
        build: || {
            let prepared = nda_prepared();
            let forger = signpdf_core::oidc::testing::TestIssuer::es256();
            let (key, req) = signer_request_with(&forger, "alice@example.com", &prepared, "s1");
            sign(&prepared, &key, &req).unwrap()
        },
    },
    Vector {
        name: "schema-downgrade",
        attack: "A signer's revision writes the envelope back as an older schema version.",
        row: "Revision chain moved to an older version (downgrade)",
        test: "schema_versions::a_revision_cannot_move_a_document_to_an_older_version",
        build: || alice_tampers(&nda_prepared(), &|env| env.schema_version -= 1),
    },
    Vector {
        name: "signer-changes-timestamp-policy",
        attack: "A signer switches the envelope's signature-timestamp policy from required to \
                 none.",
        row: "A signer changes the signature-timestamp policy",
        test: "timestamp_policy::a_signer_cannot_change_the_policy",
        build: || {
            let pdf = container::make_sample_pdf("Timestamped NDA");
            let (pk, mut req) = two_signer_request(&pdf);
            req.policy.signature_timestamps = TimestampPolicy::Required;
            let prepared = prepare(&pdf, &req, &pk).unwrap();
            alice_tampers(&prepared, &|env| {
                env.policy.signature_timestamps = TimestampPolicy::None
            })
        },
    },
    Vector {
        name: "signer-redirects-service-link",
        attack: "A signer points the service link at a phishing page. The document stays valid \
                 (the link is not a prepared term), the change is a warning and the preparer's \
                 link is the one reported.",
        row: "A signer points the service link at a phishing page",
        test: "service_link::a_signer_who_changes_the_link_leaves_the_document_valid_and_the_change_ignored",
        build: || {
            let pdf = container::make_sample_pdf("Service link");
            let (pk, mut req) = two_signer_request(&pdf);
            req.service_link = Some("https://sign.example.com/e/123".into());
            let prepared = prepare(&pdf, &req, &pk).unwrap();
            alice_tampers(&prepared, &|env| {
                env.service_link = Some("https://phishing.example/login".into())
            })
        },
    },
    Vector {
        name: "hostile-deep-nesting",
        attack: "A PDF of 200,000 nested arrays, which overflowed the stack of an older parser.",
        row: "Crash on hostile input",
        test: "security_e2e::deeply_nested_objects_do_not_overflow_the_stack",
        build: || {
            let depth = 200_000;
            let mut pdf = b"%PDF-1.7\n1 0 obj\n".to_vec();
            pdf.extend(std::iter::repeat_n(b'[', depth));
            pdf.extend(std::iter::repeat_n(b']', depth));
            pdf.extend_from_slice(
                b"\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n",
            );
            pdf
        },
    },
];

/// Run the verifier on `pdf` (on a thread with a small stack, like an app's worker) and describe
/// the result as an [`Expected`] for `v`.
fn judge(v: &Vector, pdf: Vec<u8>, trust: &TrustStore) -> Expected {
    let schema_version = pades::read_attachment(&pdf, ENVELOPE_NAME)
        .ok()
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        .and_then(|env| env["schema_version"].as_u64())
        .map_or(0, |n| n as u32);
    let trust = trust.clone();
    let result = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || verify(&pdf, &trust))
        .unwrap()
        .join()
        .expect("the verifier must not crash");
    let mut e = Expected {
        attack: v.attack.into(),
        security_model_row: v.row.into(),
        regression_test: v.test.into(),
        schema_version,
        outcome: "report".into(),
        error_code: None,
        valid: false,
        integrity_ok: false,
        identities_trusted: false,
        errors: vec![],
        warnings: vec![],
    };
    match result {
        Ok(report) => {
            e.valid = report.valid;
            e.integrity_ok = report.integrity_ok;
            e.identities_trusted = report.identities_trusted;
            let codes = |sev: signpdf_core::messages::Severity| {
                report
                    .findings
                    .iter()
                    .filter(|f| f.severity == sev)
                    .map(|f| f.code.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            };
            e.errors = codes(signpdf_core::messages::Severity::Error);
            e.warnings = codes(signpdf_core::messages::Severity::Warning);
        }
        Err(err) => {
            e.outcome = "error".into();
            e.error_code = Some(err.code().to_string());
        }
    }
    e
}

fn stored_trust() -> TrustStore {
    let json = std::fs::read_to_string(attack_root().join("trust.json")).unwrap();
    TrustStore::from_json(&json).unwrap()
}

#[test]
fn every_attack_vector_gets_its_expected_verdict() {
    let trust = stored_trust();
    let mut failures = vec![];
    for v in VECTORS {
        let pdf =
            std::fs::read(attack_root().join(format!("{}.pdf", v.name))).unwrap_or_else(|e| {
                panic!(
                    "tests/attack/{}.pdf: {e} (see tests/attack/README.md)",
                    v.name
                )
            });
        let expected: Expected = serde_json::from_slice(
            &std::fs::read(attack_root().join(format!("{}.expected.json", v.name))).unwrap(),
        )
        .unwrap();
        let got = judge(v, pdf, &trust);
        if got != expected {
            failures.push(format!(
                "{}: expected {}\n got {}",
                v.name,
                serde_json::to_string(&expected).unwrap(),
                serde_json::to_string(&got).unwrap()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn the_control_is_valid_and_every_attack_is_caught() {
    for v in VECTORS {
        let e: Expected = serde_json::from_slice(
            &std::fs::read(attack_root().join(format!("{}.expected.json", v.name))).unwrap(),
        )
        .unwrap();
        match v.name {
            "control-two-signers" => assert!(e.valid && e.errors.is_empty(), "{e:?}"),
            // The link is outside the prepared terms: valid, with a warning.
            "signer-redirects-service-link" => {
                assert!(e.valid && !e.warnings.is_empty(), "{e:?}")
            }
            _ => assert!(!e.valid, "{}: an attack vector must not verify", v.name),
        }
    }
}

#[test]
fn the_directory_holds_exactly_the_listed_vectors() {
    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(attack_root()).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if let Some(stem) = name.strip_suffix(".pdf") {
            on_disk.insert(stem.to_string());
        }
    }
    let listed: BTreeSet<String> = VECTORS.iter().map(|v| v.name.to_string()).collect();
    assert_eq!(on_disk, listed, "tests/attack/*.pdf and VECTORS differ");
}

/// Writes every vector, its expected verdict and the trust store that pins the test issuer.
/// Refuses when vectors exist: they are test vectors others rely on (README, "Rules").
#[test]
#[ignore]
fn write_attack_vectors() {
    let root = attack_root();
    std::fs::create_dir_all(&root).unwrap();
    let existing = std::fs::read_dir(&root)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .is_ok_and(|e| e.file_name().to_string_lossy().ends_with(".pdf"))
        })
        .count();
    assert_eq!(
        existing, 0,
        "tests/attack already holds vectors: delete them first only if the README's rules allow it"
    );
    let trust = trust();
    std::fs::write(root.join("trust.json"), trust.to_json().unwrap()).unwrap();
    for v in VECTORS {
        let pdf = (v.build)();
        std::fs::write(root.join(format!("{}.pdf", v.name)), &pdf).unwrap();
        let e = judge(v, pdf, &trust);
        match v.name {
            "hostile-deep-nesting" => assert_eq!(e.schema_version, 0),
            "schema-downgrade" => assert_eq!(e.schema_version, SCHEMA_VERSION - 1),
            _ => assert_eq!(e.schema_version, SCHEMA_VERSION, "{}", v.name),
        }
        let mut json = serde_json::to_string_pretty(&e).unwrap();
        json.push('\n');
        std::fs::write(root.join(format!("{}.expected.json", v.name)), json).unwrap();
    }
}
