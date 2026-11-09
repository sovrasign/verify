//! Typed signatures: the glyph outlines of a typed name, filled in the signer's box.
//!
//! The drawing is decoration beside the verified caption. From envelope schema version 6 the
//! signer's record keeps it, typed or drawn, and the verifier redraws it: a signer whose box
//! shows anything but exactly the recorded drawing, filled or stroked by the engine's rule,
//! fails verification.

mod common;

use common::*;
use signpdf_core::ink::typed::testing::font;
use signpdf_core::ink::{InkPaths, PathSegment, SignatureDrawing, MAX_TYPED_PATHS};
use signpdf_core::workflow::testing::{sign_malicious, sign_redrawn};
use signpdf_core::{
    container, prepare, read_envelope, sign, typed_signature, verify, SigningOrder, SCHEMA_VERSION,
};

/// A document with a signature box for Alice and one for Bob.
fn prepared() -> Vec<u8> {
    let pdf = container::make_sample_pdf("Typed");
    let (pk, req) = two_signer_request(&pdf);
    prepare(&pdf, &req, &pk).unwrap()
}

fn alice_name() -> InkPaths {
    typed_signature(&font(), "Alice Example").unwrap()
}

/// The form XObjects of `pdf`: the appearance streams.
fn appearance_streams(pdf: &[u8]) -> Vec<String> {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    doc.objects
        .values()
        .filter_map(|o| o.as_stream().ok())
        .filter(|s| matches!(s.dict.get(b"Subtype"), Ok(lopdf::Object::Name(n)) if n == b"Form"))
        .map(|s| String::from_utf8_lossy(&s.content).to_string())
        .collect()
}

fn signature_box(pdf: &[u8], email: &str) -> String {
    appearance_streams(pdf)
        .into_iter()
        .find(|s| s.contains(&format!("({email}) Tj")))
        .expect("the signer's signature box")
}

#[test]
fn a_typed_signature_is_filled_beside_the_verified_identity_and_recorded() {
    const { assert!(SCHEMA_VERSION >= 6) };
    let prepared = prepared();
    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    let paths = alice_name();
    r.typed_signature = Some(paths.clone());
    let signed = sign(&prepared, &k, &r).unwrap();

    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    let alice = &report.signatures[0];
    assert_eq!(alice.drawing, "typed");
    // The record keeps the paths, not the name: the typed text is not a claim.
    let env = report.envelope.as_ref().unwrap();
    let record = &env.signatures[0];
    assert_eq!(
        record.drawing,
        Some(SignatureDrawing::Typed {
            paths: paths.clone()
        })
    );
    let envelope_json = serde_json::to_string(env).unwrap();
    assert!(!envelope_json.contains("Alice Example"), "{envelope_json}");

    // The box: the verified caption, and the outlines filled in one colour, clipped to the
    // drawing area; no text in the drawing, no font but the standard one.
    let shown = signature_box(&signed, "alice@example.com");
    assert!(shown.contains("(Signed by:) Tj"), "{shown}");
    assert!(shown.contains("re\nW\nn\n0.05 0.05 0.30 rg\n"), "{shown}");
    assert!(
        shown.contains(" c\n") && shown.contains("\nh\nf\nQ\n"),
        "{shown}"
    );
    assert_eq!(
        shown.matches("BT\n").count(),
        3,
        "the caption's three rows only"
    );
    assert!(!String::from_utf8_lossy(&signed).contains("/FontFile"));

    // Bob signs on top, drawing his signature: both drawings stay recorded and verified.
    let (k, mut r) = signer_request("bob@example.com", &signed, "");
    r.drawn_signature = Some(vec![vec![[0.0, 10.0], [40.0, 0.0], [80.0, 12.0]]]);
    let done = sign(&signed, &k, &r).unwrap();
    let report = verify(&done, &trust()).unwrap();
    assert!(report.valid && report.complete, "{:?}", report.messages);
    let kinds: Vec<&str> = report
        .signatures
        .iter()
        .map(|s| s.drawing.as_str())
        .collect();
    assert_eq!(kinds, ["typed", "drawn"]);
    let shown = signature_box(&done, "bob@example.com");
    assert!(
        shown.contains("1 J\n1 j\n") && shown.contains("\nS\n"),
        "{shown}"
    );
}

#[test]
fn a_signer_who_adopts_the_caption_alone_draws_and_records_nothing() {
    let prepared = prepared();
    let (k, r) = signer_request("alice@example.com", &prepared, "");
    let signed = sign(&prepared, &k, &r).unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    assert_eq!(report.signatures[0].drawing, "");
    assert_eq!(read_envelope(&signed).unwrap().signatures[0].drawing, None);
}

#[test]
fn a_typed_signature_is_refused_when_it_cannot_be_drawn() {
    let prepared = prepared();
    let attempt = |change: &dyn Fn(&mut signpdf_core::SignRequest)| {
        let (k, mut r) = signer_request("alice@example.com", &prepared, "");
        change(&mut r);
        sign(&prepared, &k, &r).map(|_| ()).unwrap_err().to_string()
    };
    let err = attempt(&|r| {
        r.typed_signature = Some(alice_name());
        r.drawn_signature = Some(vec![vec![[0.0, 0.0], [1.0, 1.0]]]);
    });
    assert!(err.contains("drawn or typed, not both"), "{err}");
    let err = attempt(&|r| r.typed_signature = Some(vec![]));
    assert!(err.contains("typed signature is empty"), "{err}");
    let err = attempt(&|r| {
        r.typed_signature = Some(vec![vec![PathSegment::Curve([1.0; 6])]]);
    });
    assert!(err.contains("must start with a point"), "{err}");
    let err = attempt(&|r| {
        r.typed_signature = Some(vec![
            vec![
                PathSegment::Line([0.0, 0.0]),
                PathSegment::Line([1.0, 1.0])
            ];
            MAX_TYPED_PATHS + 1
        ]);
    });
    assert!(err.contains("too detailed"), "{err}");
    let err = attempt(&|r| {
        r.typed_signature = Some(vec![vec![
            PathSegment::Line([0.0, 0.0]),
            PathSegment::Line([f32::INFINITY, 1.0]),
        ]]);
    });
    assert!(err.contains("invalid coordinates"), "{err}");
}

/// Like a drawn one, a typed signature needs a box: without one, or on a decline, it is left
/// out of the page and of the record.
#[test]
fn a_typed_signature_is_ignored_without_a_signature_box() {
    let pdf = container::make_sample_pdf("No box");
    let (pk, req) = prepare_request(
        &pdf,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        vec![],
        SigningOrder::Sequential,
    );
    let no_box = prepare(&pdf, &req, &pk).unwrap();
    let with_box = prepared();
    for (doc, decline) in [(&no_box, false), (&no_box, true), (&with_box, true)] {
        let (k, mut r) = signer_request("alice@example.com", doc, "");
        r.decline = decline;
        r.typed_signature = Some(alice_name());
        let out = sign(doc, &k, &r).unwrap();
        let report = verify(&out, &trust()).unwrap();
        assert!(report.integrity_ok, "{:?}", report.messages);
        assert!(report.signatures.iter().all(|s| s.drawing.is_empty()));
        assert!(read_envelope(&out)
            .unwrap()
            .signatures
            .iter()
            .all(|r| r.drawing.is_none()));
        assert!(appearance_streams(&out)
            .iter()
            .all(|s| !s.contains(" rg\n0.05")));
    }
}

/// A modified signing client records one drawing and shows another: the verifier redraws the
/// recorded one and the revision fails.
#[test]
fn a_box_that_shows_other_than_the_recorded_drawing_fails() {
    let prepared = prepared();
    let typed = SignatureDrawing::Typed {
        paths: alice_name(),
    };
    let other_name = SignatureDrawing::Typed {
        paths: typed_signature(&font(), "Mallory").unwrap(),
    };
    let strokes = SignatureDrawing::Drawn {
        strokes: vec![vec![[0.0, 10.0], [40.0, 0.0], [80.0, 12.0]]],
    };
    let check = |shown: Option<SignatureDrawing>, recorded: Option<&SignatureDrawing>| {
        let (k, mut r) = signer_request("alice@example.com", &prepared, "");
        match recorded {
            Some(SignatureDrawing::Typed { paths }) => r.typed_signature = Some(paths.clone()),
            Some(SignatureDrawing::Drawn { strokes }) => r.drawn_signature = Some(strokes.clone()),
            None => {}
        }
        let out = sign_redrawn(&prepared, &k, &r, &|opts| {
            opts.appearance.ink = shown.clone()
        })
        .unwrap();
        verify(&out, &trust()).unwrap()
    };
    // The honest client, for reference.
    assert!(check(Some(typed.clone()), Some(&typed)).valid);
    for (shown, recorded) in [
        (Some(other_name.clone()), Some(&typed)),
        (Some(strokes.clone()), Some(&typed)),
        (Some(typed.clone()), Some(&strokes)),
        (None, Some(&typed)),
        (Some(typed.clone()), None),
        (Some(strokes.clone()), None),
    ] {
        let report = check(shown.clone(), recorded);
        assert!(
            !report.valid && !report.integrity_ok,
            "{shown:?} / {recorded:?}"
        );
        assert!(
            report
                .messages
                .iter()
                .any(|m| m.contains("does not show what the engine draws")),
            "{:?}",
            report.messages
        );
    }
}

/// A modified client writes a drawing into a record that cannot have one, or one the engine
/// cannot draw: the verifier refuses the record.
#[test]
fn a_record_cannot_keep_a_drawing_the_signer_could_not_show() {
    let prepared = prepared();
    let set_drawing = |drawing: SignatureDrawing, decline: bool| {
        let (k, mut r) = signer_request("alice@example.com", &prepared, "");
        r.decline = decline;
        let out = sign_malicious(&prepared, &k, &r, false, &move |env| {
            env.signatures.last_mut().unwrap().drawing = Some(drawing.clone());
        })
        .unwrap();
        verify(&out, &trust()).unwrap()
    };
    // A declined revision has no box to show it in.
    let report = set_drawing(
        SignatureDrawing::Typed {
            paths: alice_name(),
        },
        true,
    );
    assert!(!report.valid, "{:?}", report.messages);
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("no signature box to show it")),
        "{:?}",
        report.messages
    );
    // A drawing over the limits.
    let report = set_drawing(
        SignatureDrawing::Typed {
            paths: vec![
                vec![PathSegment::Line([0.0, 0.0]), PathSegment::Line([1.0, 1.0])];
                MAX_TYPED_PATHS + 1
            ],
        },
        false,
    );
    assert!(!report.valid);
    assert!(
        report
            .messages
            .iter()
            .any(|m| m.contains("recorded drawing cannot be drawn")),
        "{:?}",
        report.messages
    );
}

/// A version-5 envelope (prepared by the build before typed signatures, as the corpus keeps it)
/// is finished in version 5: a drawn signature is drawn but not recorded, a typed one refused.
#[test]
fn an_older_envelope_takes_a_drawn_signature_unrecorded_and_refuses_a_typed_one() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/v5/2026-10-27-c906265");
    let prepared = std::fs::read(dir.join("prepared-no-timestamps.pdf")).unwrap();
    assert_eq!(read_envelope(&prepared).unwrap().schema_version, 5);
    let mut trust =
        signpdf_core::TrustStore::from_json_bytes(&std::fs::read(dir.join("trust.json")).unwrap())
            .unwrap();
    trust.merge(&common::trust());

    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    r.typed_signature = Some(alice_name());
    let err = sign(&prepared, &k, &r).unwrap_err().to_string();
    assert!(err.contains("cannot show a typed signature"), "{err}");

    let (k, mut r) = signer_request("alice@example.com", &prepared, "");
    r.drawn_signature = Some(vec![vec![[0.0, 10.0], [40.0, 0.0], [80.0, 12.0]]]);
    let signed = sign(&prepared, &k, &r).unwrap();
    let env = read_envelope(&signed).unwrap();
    assert_eq!(env.schema_version, 5);
    assert!(env.signatures.iter().all(|s| s.drawing.is_none()));
    let report = verify(&signed, &trust).unwrap();
    assert!(report.integrity_ok, "{:?}", report.messages);
    assert!(report.signatures.iter().all(|s| s.drawing.is_empty()));
    assert!(signature_box(&signed, "alice@example.com").contains("1 J\n1 j\n"));
}
