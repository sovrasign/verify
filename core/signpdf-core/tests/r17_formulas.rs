//! Envelope schema version 8: formula fields. A formula field seals its formula, the numbers the
//! options of the dropdowns and radio groups it reads count as, and a number format. Preparation
//! checks the formula, its inputs (known, holding numbers, filled by the same or an earlier
//! signer), the map and loops; signing computes the value (the signer gives none) and draws it in
//! the sealed style; the verifier computes it again and rejects a mismatch (`formula_mismatch`).

mod common;

use std::collections::BTreeMap;

use common::*;
use signpdf_core::messages::{lookup, Severity};
use signpdf_core::schema::{decode_envelope, encode_envelope};
use signpdf_core::workflow::testing::{sign_malicious, sign_malicious_redrawn};
use signpdf_core::{
    compute_formula_fields, container, prepare, read_envelope, sign, verify, Field, FieldType,
    FormulaSpec, NumberFormat, NumberStyle, SigningOrder, VerificationReport,
};

/// A formula field of `signer` computing `expr` with `map`, two decimal places in euros.
fn formula(id: &str, signer: &str, y: f64, expr: &str, map: &[(&str, &[(&str, &str)])]) -> Field {
    Field {
        label: Some(id.to_string()),
        number_format: Some(NumberFormat {
            decimals: 2,
            style: NumberStyle::SpaceComma,
            currency: Some("EUR".into()),
            ..Default::default()
        }),
        formula: Some(FormulaSpec {
            expr: expr.into(),
            map: map
                .iter()
                .map(|(choice, numbers)| {
                    let numbers = numbers
                        .iter()
                        .map(|(o, n)| (o.to_string(), n.to_string()))
                        .collect();
                    (choice.to_string(), numbers)
                })
                .collect(),
        }),
        ..field(id, signer, FieldType::Formula, 0, y)
    }
}

fn number(id: &str, signer: &str, y: f64, decimals: u8) -> Field {
    Field {
        label: Some(id.to_string()),
        required: false,
        number_format: Some(NumberFormat {
            decimals,
            ..Default::default()
        }),
        ..field(id, signer, FieldType::Number, 0, y)
    }
}

fn optional(f: Field) -> Field {
    Field {
        required: false,
        ..f
    }
}

const TOTAL: &str = "{qty} * {price} + if({express} = 1, 15, 0) + {plan} + {Shipping}";
const PLAN: (&str, &[(&str, &str)]) = ("plan", &[("Basic", "0"), ("Pro", "100")]);
const SHIPPING: (&str, &[(&str, &str)]) = ("Shipping", &[("Standard", "0"), ("Overnight", "20")]);

/// Alice's order form: a quantity, a unit price, a checkbox, a dropdown and a radio group, a
/// total that reads all of them and a net amount that reads the total.
fn order_form() -> Vec<Field> {
    vec![
        number("qty", "s1", 160.0, 0),
        number("price", "s1", 200.0, 2),
        optional(checkbox("express", "s1", 240.0, "Express delivery")),
        optional(dropdown("plan", "s1", 260.0, &["Basic", "Pro"])),
        optional(radio("ship-std", "s1", "Shipping", "Standard", 300.0)),
        optional(radio("ship-night", "s1", "Shipping", "Overnight", 320.0)),
        formula("total", "s1", 360.0, TOTAL, &[PLAN, SHIPPING]),
        Field {
            number_format: Some(NumberFormat {
                decimals: 2,
                ..Default::default()
            }),
            ..formula("net", "s1", 420.0, "{total} / 1.2", &[])
        },
    ]
}

/// A one-signer document for Alice with a signature field and `fields`.
fn prepared_with(fields: Vec<Field>) -> signpdf_core::Result<Vec<u8>> {
    prepared_for(
        fields,
        vec![spec("s1", "Alice", "alice@example.com", 1)],
        SigningOrder::Sequential,
    )
}

fn prepared_for(
    fields: Vec<Field>,
    signers: Vec<signpdf_core::workflow::SignerSpec>,
    order: SigningOrder,
) -> signpdf_core::Result<Vec<u8>> {
    let pdf = container::make_sample_pdf("Formulas");
    let mut all: Vec<Field> = signers
        .iter()
        .enumerate()
        .map(|(i, s)| Field {
            rect: signpdf_core::Rect {
                x: 300.0,
                y: 120.0 + 60.0 * i as f64,
                w: 200.0,
                h: 40.0,
            },
            ..sig_field(&format!("sig-{}", s.id), &s.id, 0)
        })
        .collect();
    all.extend(fields);
    let (key, req) = prepare_request(&pdf, signers, all, order);
    prepare(&pdf, &req, &key)
}

fn signs(
    pdf: &[u8],
    email: &str,
    slot: &str,
    values: &[(&str, &str)],
) -> signpdf_core::Result<Vec<u8>> {
    let (key, mut req) = signer_request(email, pdf, slot);
    req.field_values = values
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    sign(pdf, &key, &req)
}

fn alice_signs(pdf: &[u8], values: &[(&str, &str)]) -> signpdf_core::Result<Vec<u8>> {
    signs(pdf, "alice@example.com", "s1", values)
}

fn value_of(pdf: &[u8], id: &str) -> Option<String> {
    let env = read_envelope(pdf).unwrap();
    env.fields.into_iter().find(|f| f.id == id)?.value
}

fn has_code(report: &VerificationReport, code: &str) -> bool {
    report.findings.iter().any(|f| f.code == code)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The refusal of a prepare request with `fields`, which must name `code`.
fn refused(fields: Vec<Field>, code: &str) -> String {
    let err = prepared_with(fields).unwrap_err().to_string();
    assert!(err.contains(code), "expected {code}: {err}");
    err
}

const ORDER: &[(&str, &str)] = &[
    ("qty", "3"),
    ("price", "19.99"),
    ("express", "true"),
    ("plan", "Pro"),
    ("ship-night", "true"),
];

#[test]
fn formulas_are_computed_at_signing_drawn_and_verified() {
    let prepared = prepared_with(order_form()).unwrap();
    let signed = alice_signs(&prepared, ORDER).unwrap();
    // 3 × 19.99 + 15 + 100 + 20, and that total over 1.2 rounded half up (162.475).
    assert_eq!(value_of(&signed, "total").as_deref(), Some("194.97"));
    assert_eq!(value_of(&signed, "net").as_deref(), Some("162.48"));
    // Drawn in the sealed style, after the currency code.
    assert!(contains(&signed, b"(EUR 194,97)"));
    assert!(contains(&signed, b"(162.48)"));
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);
    // The prepared terms carry the formula with its map, and the envelope round-trips.
    let env = read_envelope(&signed).unwrap();
    let total = env.fields.iter().find(|f| f.id == "total").unwrap();
    assert_eq!(total.formula.as_ref().unwrap().expr, TOTAL);
    assert_eq!(
        total.formula.as_ref().unwrap().map["Shipping"]["Overnight"],
        "20"
    );
    let raw = serde_json::to_vec(&env).unwrap();
    assert_eq!(
        encode_envelope(&decode_envelope(&raw).unwrap()).unwrap(),
        raw
    );
}

#[test]
fn checkboxes_count_0_or_1_and_unanswered_choices_count_0() {
    let prepared = prepared_with(order_form()).unwrap();
    let signed = alice_signs(&prepared, &[("qty", "2"), ("price", "5")]).unwrap();
    assert_eq!(value_of(&signed, "total").as_deref(), Some("10.00"));
    assert!(verify(&signed, &trust()).unwrap().valid);
    let signed = alice_signs(
        &prepared,
        &[
            ("qty", "1"),
            ("price", "1"),
            ("express", "true"),
            ("plan", "Basic"),
            ("ship-std", "true"),
        ],
    )
    .unwrap();
    assert_eq!(value_of(&signed, "total").as_deref(), Some("16.00"));
    // An empty number counts as 0.
    let signed = alice_signs(&prepared, &[("price", "4")]).unwrap();
    assert_eq!(value_of(&signed, "total").as_deref(), Some("0.00"));
}

#[test]
fn a_signer_gives_no_value_for_a_formula_field() {
    let prepared = prepared_with(order_form()).unwrap();
    let mut values = ORDER.to_vec();
    values.push(("total", "1.00"));
    let err = alice_signs(&prepared, &values).unwrap_err().to_string();
    assert!(err.contains("computed by its formula"), "{err}");
}

#[test]
fn division_by_zero_is_an_error_at_signing_never_a_drawn_value() {
    let fields = vec![
        number("qty", "s1", 160.0, 0),
        formula("each", "s1", 360.0, "100 / {qty}", &[]),
    ];
    let prepared = prepared_with(fields).unwrap();
    let err = alice_signs(&prepared, &[("qty", "0")])
        .unwrap_err()
        .to_string();
    assert!(err.contains("division_by_zero"), "{err}");
    assert!(err.contains("each"), "{err}");
    let signed = alice_signs(&prepared, &[("qty", "3")]).unwrap();
    assert_eq!(value_of(&signed, "each").as_deref(), Some("33.33"));
}

#[test]
fn a_result_the_client_changed_fails_verification() {
    let prepared = prepared_with(order_form()).unwrap();
    // A modified client records a lower total and draws it to match.
    let (key, mut req) = signer_request("alice@example.com", &prepared, "s1");
    req.field_values = ORDER
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let signed = sign_malicious_redrawn(
        &prepared,
        &key,
        &req,
        &|env| {
            let f = env.fields.iter_mut().find(|f| f.id == "total").unwrap();
            f.value = Some("94.97".into());
        },
        &|opts| {
            for t in opts.field_texts.iter_mut() {
                if t.text == "EUR 194,97" {
                    t.text = "EUR 94,97".into();
                }
            }
        },
    )
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(!report.valid);
    assert!(has_code(&report, "formula_mismatch"), "{report:#?}");
    let finding = report
        .findings
        .iter()
        .find(|f| f.code == "formula_mismatch")
        .unwrap();
    assert!(finding.text.contains("total"), "{}", finding.text);

    // Leaving the result out is no better.
    let signed = sign_malicious(&prepared, &key, &req, false, &|env| {
        let f = env.fields.iter_mut().find(|f| f.id == "net").unwrap();
        f.value = None;
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(has_code(&report, "formula_mismatch"), "{report:#?}");

    // Nor is changing an input after the formula was computed: the total no longer matches.
    let signed = sign_malicious(&prepared, &key, &req, false, &|env| {
        let f = env.fields.iter_mut().find(|f| f.id == "qty").unwrap();
        f.value = Some("4".into());
    })
    .unwrap();
    let report = verify(&signed, &trust()).unwrap();
    assert!(has_code(&report, "formula_mismatch"), "{report:#?}");
}

#[test]
fn a_signer_cannot_change_a_formula_or_its_map() {
    let prepared = prepared_with(order_form()).unwrap();
    let (key, mut req) = signer_request("alice@example.com", &prepared, "s1");
    req.field_values = ORDER
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let tampers: [&dyn Fn(&mut signpdf_core::Envelope); 2] = [
        &|env| {
            let f = env.fields.iter_mut().find(|f| f.id == "total").unwrap();
            f.formula.as_mut().unwrap().expr = "{qty} * {price}".into();
            f.value = Some("59.97".into());
        },
        &|env| {
            let f = env.fields.iter_mut().find(|f| f.id == "total").unwrap();
            let map = &mut f.formula.as_mut().unwrap().map;
            map.get_mut("plan")
                .unwrap()
                .insert("Pro".into(), "0".into());
            f.value = Some("94.97".into());
        },
    ];
    for tamper in tampers {
        let signed = sign_malicious(&prepared, &key, &req, false, tamper).unwrap();
        let report = verify(&signed, &trust()).unwrap();
        assert!(has_code(&report, "terms_changed"), "{report:#?}");
    }
}

#[test]
fn a_formula_reads_an_earlier_signers_fields_but_not_a_later_ones() {
    let signers = || {
        vec![
            spec("s1", "Alice", "alice@example.com", 1),
            spec("s2", "Bob", "bob@example.com", 2),
        ]
    };
    // Bob's total reads Alice's quantity: she signs first.
    let fields = vec![
        number("qty", "s1", 160.0, 0),
        number("rate", "s2", 200.0, 2),
        formula("fee", "s2", 360.0, "{qty} * {rate}", &[]),
    ];
    let prepared = prepared_for(fields, signers(), SigningOrder::Sequential).unwrap();
    let after_alice = signs(&prepared, "alice@example.com", "s1", &[("qty", "4")]).unwrap();
    assert_eq!(value_of(&after_alice, "fee"), None);
    let signed = signs(&after_alice, "bob@example.com", "s2", &[("rate", "2.5")]).unwrap();
    assert_eq!(value_of(&signed, "fee").as_deref(), Some("10.00"));
    let report = verify(&signed, &trust()).unwrap();
    assert!(report.valid, "{:?}", report.messages);

    // Alice's total may not read Bob's rate: he fills it after she has signed.
    let fields = vec![
        number("qty", "s1", 160.0, 0),
        number("rate", "s2", 200.0, 2),
        formula("fee", "s1", 360.0, "{qty} * {rate}", &[]),
    ];
    let err = prepared_for(fields, signers(), SigningOrder::Sequential)
        .unwrap_err()
        .to_string();
    assert!(err.contains("formula_later_input"), "{err}");

    // Under a parallel policy no other signer is earlier.
    let fields = vec![
        number("qty", "s1", 160.0, 0),
        number("rate", "s2", 200.0, 2),
        formula("fee", "s2", 360.0, "{qty} * {rate}", &[]),
    ];
    let err = prepared_for(fields, signers(), SigningOrder::Parallel)
        .unwrap_err()
        .to_string();
    assert!(err.contains("formula_later_input"), "{err}");

    // Nor are signers of the same order, who sign in any order among themselves.
    let fields = vec![
        number("qty", "s1", 160.0, 0),
        formula("fee", "s2", 360.0, "{qty} * 2", &[]),
    ];
    let same_order = vec![
        spec("s1", "Alice", "alice@example.com", 1),
        spec("s2", "Bob", "bob@example.com", 1),
    ];
    let err = prepared_for(fields, same_order, SigningOrder::Sequential)
        .unwrap_err()
        .to_string();
    assert!(err.contains("formula_later_input"), "{err}");
}

#[test]
fn formulas_that_read_each_other_in_a_loop_are_refused() {
    let err = refused(
        vec![
            formula("a", "s1", 160.0, "{b} + 1", &[]),
            formula("b", "s1", 220.0, "{c} + 1", &[]),
            formula("c", "s1", 280.0, "{a} + 1", &[]),
        ],
        "formula_loop",
    );
    assert!(err.contains("a → b → c → a"), "{err}");
    refused(
        vec![formula("a", "s1", 160.0, "{a} + 1", &[])],
        "formula_loop",
    );
}

#[test]
fn prepare_refuses_bad_formula_fields() {
    let base = || order_form();
    let with = |f: Field| {
        let mut fields = base();
        fields.retain(|o| o.id != f.id);
        fields.push(f);
        fields
    };
    // The formula itself.
    refused(
        with(formula("total", "s1", 360.0, "{qty} *", &[])),
        "formula_syntax",
    );
    refused(
        with(formula("total", "s1", 360.0, "pow({qty}, 2)", &[])),
        "formula_unknown_function",
    );
    refused(
        with(formula("total", "s1", 360.0, &"1+".repeat(1001), &[])),
        "formula_too_long",
    );
    refused(
        with(formula("total", "s1", 360.0, "{qty} > 1", &[])),
        "formula_type",
    );
    // Its inputs.
    refused(
        with(formula("total", "s1", 360.0, "{nothing} * 2", &[])),
        "formula_unknown_field",
    );
    let mut fields = base();
    fields.push(Field {
        label: Some("Name".into()),
        ..field("name", "s1", FieldType::Text, 0, 480.0)
    });
    fields.push(formula("x", "s1", 540.0, "{name} * 2", &[]));
    refused(fields, "formula_input_type");
    refused(
        with(formula("total", "s1", 360.0, "{ship-std} * 2", &[])),
        "formula_input_type",
    );
    // Its map: a number for every option, nothing else, decimals only.
    refused(
        with(formula(
            "total",
            "s1",
            360.0,
            TOTAL,
            &[PLAN, ("Shipping", &[("Standard", "0")])],
        )),
        "formula_map",
    );
    refused(
        with(formula(
            "total",
            "s1",
            360.0,
            TOTAL,
            &[PLAN, SHIPPING, ("qty", &[("1", "1")])],
        )),
        "formula_map",
    );
    refused(
        with(formula(
            "total",
            "s1",
            360.0,
            TOTAL,
            &[
                ("plan", &[("Basic", "0"), ("Pro", "100"), ("Gold", "200")]),
                SHIPPING,
            ],
        )),
        "formula_map",
    );
    refused(
        with(formula(
            "total",
            "s1",
            360.0,
            TOTAL,
            &[("plan", &[("Basic", "zero"), ("Pro", "100")]), SHIPPING],
        )),
        "formula_map",
    );
    refused(
        with(formula("total", "s1", 360.0, "{qty}", &[PLAN])),
        "formula_map",
    );
    // The field's own members.
    let mut no_format = formula("total", "s1", 360.0, "{qty}", &[]);
    no_format.number_format = None;
    refused(with(no_format), "needs a number format");
    let mut ranged = formula("total", "s1", 360.0, "{qty}", &[]);
    ranged.number_format.as_mut().unwrap().max = Some("100".into());
    refused(with(ranged), "minimum or maximum");
    let mut no_formula = formula("total", "s1", 360.0, "{qty}", &[]);
    no_formula.formula = None;
    refused(with(no_formula), "needs a formula");
    let mut messaged = formula("total", "s1", 360.0, "{qty}", &[]);
    messaged.check_message = Some("Check the total.".into());
    refused(with(messaged), "check message");
    let mut stray = number("qty", "s1", 160.0, 0);
    stray.formula = Some(FormulaSpec {
        expr: "1".into(),
        map: BTreeMap::new(),
    });
    refused(with(stray), "only formula fields");
}

#[test]
fn the_json_contract() {
    // As the editor writes a formula field: `map` always present ({} when empty), a radio group
    // read by its group name and mapped by its options' captions.
    let json = serde_json::json!([
        {"id": "r1", "field_type": "radio", "page": 0, "rect": {"x": 72, "y": 100, "w": 100, "h": 16},
         "assigned_signer": "s1", "required": false, "label": "Small", "group": "Choice 1"},
        {"id": "r2", "field_type": "radio", "page": 0, "rect": {"x": 72, "y": 120, "w": 100, "h": 16},
         "assigned_signer": "s1", "required": false, "label": "Large", "group": "Choice 1"},
        {"id": "n", "field_type": "number", "page": 0, "rect": {"x": 72, "y": 140, "w": 100, "h": 20},
         "assigned_signer": "s1", "required": false, "number_format": {"decimals": 0}},
        {"id": "f", "field_type": "formula", "page": 0, "rect": {"x": 72, "y": 170, "w": 100, "h": 20},
         "assigned_signer": "s1", "required": false,
         "number_format": {"decimals": 2, "style": "1,234.5", "currency": "USD"},
         "formula": {"expr": "{Choice 1} * {n}", "map": {"Choice 1": {"Small": "1", "Large": "2.5"}}}},
        {"id": "g", "field_type": "formula", "page": 0, "rect": {"x": 72, "y": 200, "w": 100, "h": 20},
         "assigned_signer": "s1", "required": false, "number_format": {"decimals": 0},
         "formula": {"expr": "{f} + 1", "map": {}}}
    ]);
    let fields: Vec<Field> = serde_json::from_value(json).unwrap();
    signpdf_core::check_formula_fields(&fields, |_| Some(1), SigningOrder::Sequential).unwrap();
    let given: BTreeMap<String, String> = [("r2", "true"), ("n", "1000")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let values = compute_formula_fields(&fields, &given, |_| true).unwrap();
    assert_eq!(values["f"], "2500.00");
    assert_eq!(values["g"], "2501");
    // `map` is always written, `{}` when the formula reads no choice.
    let g = serde_json::to_value(&fields[4]).unwrap();
    assert_eq!(
        g["formula"],
        serde_json::json!({"expr": "{f} + 1", "map": {}})
    );
    // The same fields prepared, signed and verified.
    let prepared = prepared_with(
        fields
            .into_iter()
            .map(|f| Field {
                rect: signpdf_core::Rect {
                    y: f.rect.y + 300.0,
                    ..f.rect
                },
                ..f
            })
            .collect(),
    )
    .unwrap();
    let signed = alice_signs(&prepared, &[("r1", "true"), ("n", "3")]).unwrap();
    assert_eq!(value_of(&signed, "f").as_deref(), Some("3.00"));
    assert!(contains(&signed, b"(USD 3.00)"));
    assert!(verify(&signed, &trust()).unwrap().valid);
}

#[test]
fn every_formula_code_is_catalogued() {
    for (code, severity) in [
        ("formula_mismatch", Severity::Error),
        ("division_by_zero", Severity::Value),
        ("number_too_large", Severity::Value),
        ("formula_syntax", Severity::Refusal),
        ("formula_too_long", Severity::Refusal),
        ("formula_too_deep", Severity::Refusal),
        ("formula_unknown_function", Severity::Refusal),
        ("formula_arguments", Severity::Refusal),
        ("formula_type", Severity::Refusal),
        ("formula_unknown_field", Severity::Refusal),
        ("formula_loop", Severity::Refusal),
        (signpdf_core::formula::CODE_INPUT_TYPE, Severity::Refusal),
        (signpdf_core::formula::CODE_LATER_INPUT, Severity::Refusal),
        (signpdf_core::formula::CODE_MAP, Severity::Refusal),
    ] {
        let entry = lookup(code).unwrap_or_else(|| panic!("{code} is not catalogued"));
        assert_eq!(entry.severity, severity, "{code}");
    }
}

#[test]
fn a_version_7_envelope_cannot_hold_a_formula_field() {
    let prepared = prepared_with(order_form()).unwrap();
    let mut env = read_envelope(&prepared).unwrap();
    let mut raw = serde_json::to_value(&env).unwrap();
    raw["schema_version"] = serde_json::json!(7);
    let total = raw["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|f| f["id"] == "total")
        .unwrap();
    total.as_object_mut().unwrap().remove("formula");
    let err = decode_envelope(&serde_json::to_vec(&raw).unwrap())
        .unwrap_err()
        .to_string();
    assert!(err.contains("formula field"), "{err}");
    env.schema_version = 7;
    let err = encode_envelope(&env).unwrap_err().to_string();
    assert!(err.contains("formula"), "{err}");
}

#[test]
fn the_version_8_corpus_has_a_formula_total() {
    // `signpdf demo` has Bob type a number of seats; his total reads them, the annual fee, the
    // copy format (a dropdown) and how the copy is sent (a radio group, read by its name).
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/v8");
    let mut found = false;
    for set in std::fs::read_dir(dir).unwrap() {
        let set = set.unwrap().path();
        if !set.is_dir() {
            continue;
        }
        let pdf = std::fs::read(set.join("signed-final.pdf")).unwrap();
        let env = read_envelope(&pdf).unwrap();
        let Some(total) = env.fields.iter().find(|f| f.id == "total") else {
            continue;
        };
        found = true;
        assert_eq!(total.field_type, FieldType::Formula);
        assert_eq!(total.value.as_deref(), Some("37500.00"));
        let map = &total.formula.as_ref().unwrap().map;
        assert_eq!(map["format"]["Paper"], "25");
        assert_eq!(map["Send my copy"]["By post"], "10");
        assert!(contains(&pdf, b"(EUR 37 500,00)"));
        let trust = signpdf_core::TrustStore::from_json_bytes(
            &std::fs::read(set.join("trust.json")).unwrap(),
        )
        .unwrap();
        let report = verify(&pdf, &trust).unwrap();
        assert!(report.integrity_ok, "{:?}", report.messages);
    }
    assert!(found, "no v8 corpus set has the formula total");
}
