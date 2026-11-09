//! The signer's consent to electronic records and signatures (US ESIGN and UETA consumer consent,
//! and the EU and UK equivalents) recorded inside the signed PDF: the disclosure version, the
//! language shown, the SHA-256 of the text shown (and of the reference text for a translation)
//! and the time, in the signer's own audit entry, which their key signs and the hash chain
//! covers.

mod common;

use common::*;
use signpdf_core::crypto::{sha256_hex, KeyPair};
use signpdf_core::workflow::testing::sign_malicious;
use signpdf_core::{
    container, prepare, read_envelope, sign, verify, AuditAction, Envelope, EsignConsent,
    SignPdfError, SigningOrder, VerificationReport,
};

fn prepared() -> Vec<u8> {
    let pdf = container::make_sample_pdf("Consent");
    let (key, req) = two_signer_request(&pdf);
    prepare(&pdf, &req, &key).unwrap()
}

/// A consent to version `esd-1` shown in `lang`, given one minute before now.
fn consent(lang: &str) -> EsignConsent {
    let reference = sha256_hex(b"the English reference text of esd-1");
    EsignConsent {
        version: "esd-1".into(),
        lang: lang.into(),
        sha256: if lang == "en" {
            reference.clone()
        } else {
            sha256_hex(format!("the {lang} text of esd-1").as_bytes())
        },
        ref_sha256: (lang != "en").then_some(reference),
        at: rfc3339(now_unix() - 60),
    }
}

fn rfc3339(unix: i64) -> String {
    signpdf_core::dates::utc_rfc3339(unix).unwrap()
}

fn sign_with_consent(
    pdf: &[u8],
    email: &str,
    consent: Option<EsignConsent>,
    decline: bool,
) -> signpdf_core::Result<Vec<u8>> {
    let (key, mut req) = signer_request(email, pdf, "");
    req.esign_consent = consent;
    req.decline = decline;
    sign(pdf, &key, &req)
}

fn assert_invalid_with(report: &VerificationReport, needle: &str) {
    assert!(!report.integrity_ok, "expected a failure about {needle}");
    assert!(
        report.messages.iter().any(|m| m.contains(needle)),
        "no message about {needle}: {:?}",
        report.messages
    );
}

#[test]
fn the_consent_is_in_the_signers_audit_entry_and_its_hash() {
    let en = consent("en");
    let fr = consent("fr");
    let after_alice =
        sign_with_consent(&prepared(), "alice@example.com", Some(en.clone()), false).unwrap();
    let after_bob =
        sign_with_consent(&after_alice, "bob@example.com", Some(fr.clone()), false).unwrap();

    let env = read_envelope(&after_bob).unwrap();
    let entries: Vec<_> = env
        .audit_log
        .iter()
        .filter(|e| e.action == AuditAction::Signed)
        .collect();
    assert_eq!(entries[0].esign_consent.as_ref(), Some(&en));
    assert_eq!(entries[1].esign_consent.as_ref(), Some(&fr));
    // The preparer's entry has none.
    assert_eq!(env.audit_log[0].esign_consent, None);
    // The consent is part of what the entry hash covers, in its canonical form.
    let content = entries[1].canonical_content();
    assert!(
        content.ends_with(&format!(
            "|esign-consent=esd-1;lang=fr;sha256={};ref-sha256={};at={}",
            fr.sha256,
            fr.ref_sha256.as_deref().unwrap(),
            fr.at
        )),
        "{content}"
    );
    assert_eq!(entries[1].entry_hash, sha256_hex(content.as_bytes()));
    assert!(entries[0].canonical_content().ends_with(&format!(
        "|esign-consent=esd-1;lang=en;sha256={};at={}",
        en.sha256, en.at
    )));

    let report = verify(&after_bob, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_eq!(report.signatures[0].esign_consent.as_ref(), Some(&en));
    assert_eq!(report.signatures[1].esign_consent.as_ref(), Some(&fr));
    assert!(report.preparer.as_ref().unwrap().esign_consent.is_none());
    // The JSON a host reads.
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["signatures"][1]["esign_consent"]["version"], "esd-1");
    assert_eq!(json["signatures"][1]["esign_consent"]["lang"], "fr");
}

#[test]
fn a_signer_without_a_recorded_consent_has_none() {
    let signed = sign_with_consent(&prepared(), "alice@example.com", None, false).unwrap();
    let env = read_envelope(&signed).unwrap();
    assert!(env.audit_log.iter().all(|e| e.esign_consent.is_none()));
    // Nothing is written for it, so entries without one keep their exact JSON and hash.
    let raw = signpdf_core::pades::read_attachment(&signed, "signpdf-envelope.json").unwrap();
    assert!(!String::from_utf8(raw).unwrap().contains("esign_consent"));
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert!(report.signatures[0].esign_consent.is_none());
}

#[test]
fn a_decline_records_the_consent_too() {
    let c = consent("de");
    let declined =
        sign_with_consent(&prepared(), "alice@example.com", Some(c.clone()), true).unwrap();
    let env = read_envelope(&declined).unwrap();
    let entry = env.audit_log.last().unwrap();
    assert_eq!(entry.action, AuditAction::Declined);
    assert_eq!(entry.esign_consent.as_ref(), Some(&c));
    let report = verify(&declined, &trust()).unwrap();
    assert!(report.valid && report.declined, "{:?}", report.messages);
    assert_eq!(report.signatures[0].esign_consent.as_ref(), Some(&c));
}

#[test]
fn malformed_consents_are_refused_before_signing() {
    let good = consent("fr");
    let cases: Vec<(&str, EsignConsent)> = vec![
        (
            "disclosure version",
            EsignConsent {
                version: "ESD-1".into(),
                ..good.clone()
            },
        ),
        (
            "disclosure version",
            EsignConsent {
                version: "esd|1".into(),
                ..good.clone()
            },
        ),
        (
            "disclosure version",
            EsignConsent {
                version: String::new(),
                ..good.clone()
            },
        ),
        (
            "language",
            EsignConsent {
                lang: "pt-BR".into(),
                ..good.clone()
            },
        ),
        (
            "language",
            EsignConsent {
                lang: "english".into(),
                ..good.clone()
            },
        ),
        (
            "sha256",
            EsignConsent {
                sha256: "AB".repeat(32),
                ..good.clone()
            },
        ),
        (
            "sha256",
            EsignConsent {
                sha256: "ab".repeat(31),
                ..good.clone()
            },
        ),
        (
            "ref_sha256",
            EsignConsent {
                ref_sha256: Some("not a hash".into()),
                ..good.clone()
            },
        ),
        (
            "consent time",
            EsignConsent {
                at: "2026-11-02T10:14:03+01:00".into(),
                ..good.clone()
            },
        ),
        (
            "consent time",
            EsignConsent {
                at: "2026-11-02".into(),
                ..good.clone()
            },
        ),
        (
            "consent time",
            EsignConsent {
                at: "2026-11-02T09:14:03Z;x=y".into(),
                ..good.clone()
            },
        ),
    ];
    let prepared = prepared();
    for (needle, bad) in cases {
        assert!(bad.validate().is_err(), "{bad:?}");
        match sign_with_consent(&prepared, "alice@example.com", Some(bad.clone()), false) {
            Err(SignPdfError::Workflow(m)) => assert!(m.contains(needle), "{bad:?}: {m}"),
            other => panic!("{bad:?}: expected a refusal, got {other:?}"),
        }
    }
    // Language tags and versions hosts use.
    for (version, lang) in [
        ("esd-1", "pt-br"),
        ("acme.2026-10", "zh-hans"),
        ("7", "ast"),
    ] {
        let ok = EsignConsent {
            version: version.into(),
            lang: lang.into(),
            ..good.clone()
        };
        assert_eq!(ok.validate(), Ok(()), "{ok:?}");
    }
}

/// Re-hash and re-sign the last audit entry with `key`, as a modified client could.
fn reseal_last_entry(env: &mut Envelope, key: &KeyPair) {
    let entry = env.audit_log.last_mut().unwrap();
    entry.entry_hash = sha256_hex(entry.canonical_content().as_bytes());
    entry.signature = Some(key.sign(entry.entry_hash.as_bytes()));
}

#[test]
fn a_consent_changed_after_it_was_sealed_fails_verification() {
    let prepared = prepared();
    // Changed, added or removed after the entry was hashed and signed.
    let tampers: [&dyn Fn(&mut Envelope); 2] = [
        &|env| {
            let entry = env.audit_log.last_mut().unwrap();
            entry.esign_consent.as_mut().unwrap().version = "esd-2".into();
        },
        &|env| env.audit_log.last_mut().unwrap().esign_consent = None,
    ];
    for tamper in tampers {
        let (key, mut req) = signer_request("alice@example.com", &prepared, "");
        req.esign_consent = Some(consent("en"));
        let signed = sign_malicious(&prepared, &key, &req, false, tamper).unwrap();
        assert_invalid_with(&verify(&signed, &trust()).unwrap(), "hash mismatch");
    }
    let (key, req) = signer_request("alice@example.com", &prepared, "");
    let signed = sign_malicious(&prepared, &key, &req, false, &|env| {
        env.audit_log.last_mut().unwrap().esign_consent = Some(consent("en"));
    })
    .unwrap();
    assert_invalid_with(&verify(&signed, &trust()).unwrap(), "hash mismatch");
}

#[test]
fn a_malformed_consent_sealed_by_a_modified_client_fails_verification() {
    let prepared = prepared();
    let (key, req) = signer_request("alice@example.com", &prepared, "");
    let signed = sign_malicious(&prepared, &key, &req, false, &|env| {
        env.audit_log.last_mut().unwrap().esign_consent = Some(EsignConsent {
            version: "esd-1|forged".into(),
            ..consent("en")
        });
        reseal_last_entry(env, &key);
    })
    .unwrap();
    assert_invalid_with(&verify(&signed, &trust()).unwrap(), "disclosure version");
}

#[test]
fn a_later_signer_cannot_rewrite_an_earlier_consent() {
    let after_alice =
        sign_with_consent(&prepared(), "alice@example.com", Some(consent("en")), false).unwrap();
    let (key, req) = signer_request("bob@example.com", &after_alice, "");
    let signed = sign_malicious(&after_alice, &key, &req, false, &|env| {
        let alice_entry = env
            .audit_log
            .iter_mut()
            .find(|e| e.action == AuditAction::Signed)
            .unwrap();
        alice_entry.esign_consent = Some(consent("es"));
    })
    .unwrap();
    assert_invalid_with(
        &verify(&signed, &trust()).unwrap(),
        "audit log was rewritten",
    );
}

#[test]
fn a_consent_dated_after_the_signature_is_a_warning() {
    let late = EsignConsent {
        at: rfc3339(now_unix() + 3600),
        ..consent("en")
    };
    let signed = sign_with_consent(&prepared(), "alice@example.com", Some(late), false).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("signer 's1'") && w.contains("dated after the signature")),
        "{:?}",
        report.warnings
    );
    // One given before signing (with the usual clock leeway) is not.
    let signed =
        sign_with_consent(&prepared(), "alice@example.com", Some(consent("en")), false).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(
        !report.warnings.iter().any(|w| w.contains("consent")),
        "{:?}",
        report.warnings
    );
}

#[test]
fn the_parallel_order_keeps_each_signers_own_consent() {
    let pdf = container::make_sample_pdf("Parallel consent");
    let (key, req) = prepare_request(
        &pdf,
        vec![
            spec("s1", "Alice", "alice@example.com", 1),
            spec("s2", "Bob", "bob@example.com", 1),
        ],
        vec![sig_field("f1", "s1", 0), sig_field("f2", "s2", 0)],
        SigningOrder::Parallel,
    );
    let prepared = prepare(&pdf, &req, &key).unwrap();
    let after_bob =
        sign_with_consent(&prepared, "bob@example.com", Some(consent("it")), false).unwrap();
    let after_alice = sign_with_consent(&after_bob, "alice@example.com", None, false).unwrap();
    let report = verify(&after_alice, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    let by_slot = |id: &str| {
        report
            .signatures
            .iter()
            .find(|s| s.signer_id == id)
            .unwrap()
            .esign_consent
            .clone()
    };
    assert_eq!(by_slot("s2").unwrap().lang, "it");
    assert_eq!(by_slot("s1"), None);
}
