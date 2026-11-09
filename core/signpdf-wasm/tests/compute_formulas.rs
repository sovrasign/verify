//! `signpdf_compute_formulas`: a page's live display of formula fields gives the values the
//! engine will compute, draw and seal when the signer signs (envelope schema version 8), in the
//! verify-only module as in the signer's.

use signpdf_wasm::{
    signpdf_compute_formulas, signpdf_result_len, signpdf_result_ptr, ERR_DECODE, OK,
};

/// Run the export and return its status and result text.
fn compute(fields: &str, values: &str) -> (i32, String) {
    // SAFETY: both slices are live for the call.
    let status = unsafe {
        signpdf_compute_formulas(fields.as_ptr(), fields.len(), values.as_ptr(), values.len())
    };
    // SAFETY: the export just set the result buffer, which lives until the next call.
    let result =
        unsafe { std::slice::from_raw_parts(signpdf_result_ptr(), signpdf_result_len()).to_vec() };
    (status, String::from_utf8(result).unwrap())
}

fn json(fields: &serde_json::Value, values: &str) -> serde_json::Value {
    let (status, text) = compute(&fields.to_string(), values);
    assert_eq!(status, OK, "{text}");
    serde_json::from_str(&text).unwrap()
}

/// An order form as the envelope holds it: Alice's quantity, price, checkbox, dropdown and radio
/// group, and the two formula fields Bob's page shows (one reads the other).
fn fields() -> serde_json::Value {
    let rect = serde_json::json!({"x": 72, "y": 100, "w": 100, "h": 20});
    let f = |id: &str, ty: &str, extra: serde_json::Value| {
        let mut field = serde_json::json!({
            "id": id, "field_type": ty, "page": 0, "rect": rect,
            "assigned_signer": "s1", "required": false,
        });
        for (k, v) in extra.as_object().unwrap() {
            field[k] = v.clone();
        }
        field
    };
    serde_json::json!([
        f(
            "qty",
            "number",
            serde_json::json!({"number_format": {"decimals": 0}})
        ),
        f(
            "price",
            "number",
            serde_json::json!({"number_format": {"decimals": 2}})
        ),
        f(
            "express",
            "checkbox",
            serde_json::json!({"label": "Express"})
        ),
        f(
            "plan",
            "dropdown",
            serde_json::json!({"options": ["Basic", "Pro"]})
        ),
        f(
            "r1",
            "radio",
            serde_json::json!({"label": "Standard", "group": "Choice 1"})
        ),
        f(
            "r2",
            "radio",
            serde_json::json!({"label": "Overnight", "group": "Choice 1"})
        ),
        f(
            "total",
            "formula",
            serde_json::json!({
                "number_format": {"decimals": 2, "style": "1 234,5", "currency": "EUR"},
                "formula": {
                    "expr": "{qty} * {price} + if({express} = 1, 15, 0) + {plan} + {Choice 1}",
                    "map": {
                        "plan": {"Basic": "0", "Pro": "100"},
                        "Choice 1": {"Standard": "0", "Overnight": "20"}
                    }
                }
            })
        ),
        f(
            "net",
            "formula",
            serde_json::json!({
                "number_format": {"decimals": 2},
                "formula": {"expr": "{total} / 1.2", "map": {}}
            })
        ),
    ])
}

#[test]
fn values_and_drawings_match_what_signing_seals() {
    let values = r#"{"qty": "3", "price": "1999.99", "express": "true", "plan": "Pro",
                     "r2": "true", "r1": "false"}"#;
    let out = json(&fields(), values);
    assert_eq!(out["ok"], true, "{out}");
    // 3 × 1999.99 + 15 + 100 + 20, and that over 1.2 (5112.475, rounded half up).
    assert_eq!(out["values"]["total"], "6134.97");
    assert_eq!(out["display"]["total"], "EUR 6 134,97");
    assert_eq!(out["values"]["net"], "5112.48");
    assert_eq!(out["display"]["net"], "5112.48");
}

#[test]
fn empty_inputs_count_as_zero_and_stored_results_are_kept() {
    let out = json(&fields(), "");
    assert_eq!(out["values"]["total"], "0.00");
    assert_eq!(out["values"]["net"], "0.00");
    // A formula an earlier signer's revision already holds is read, not computed again.
    let mut fields = fields();
    fields[6]["value"] = serde_json::json!("120.00");
    let out = json(&fields, "{}");
    assert_eq!(out["values"]["total"], "120.00");
    assert_eq!(out["values"]["net"], "100.00");
}

#[test]
fn errors_name_the_formula_and_a_stable_code() {
    let mut fields = fields();
    fields[7]["formula"]["expr"] = serde_json::json!("{total} / {qty}");
    let out = json(&fields, r#"{"qty": "0", "price": "1"}"#);
    assert_eq!(
        out,
        serde_json::json!({"ok": false, "field": "net", "error_code": "division_by_zero"})
    );
    let out = json(&fields, r#"{"qty": "2", "plan": "Gold"}"#);
    assert_eq!(out["field"], "total");
    assert_eq!(out["error_code"], "formula_map");
    fields[6]["formula"]["expr"] = serde_json::json!("{net} + 1");
    let out = json(&fields, "{}");
    assert_eq!(out["error_code"], "formula_loop");
}

#[test]
fn unreadable_input_is_a_decode_error() {
    assert_eq!(compute("not json", "{}").0, ERR_DECODE);
    assert_eq!(compute(&fields().to_string(), "[1]").0, ERR_DECODE);
}
