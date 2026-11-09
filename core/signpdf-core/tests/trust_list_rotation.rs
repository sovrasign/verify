//! The signed trust list's key-chain accept rule on the shared vectors
//! (`spec/vectors/trust-list-rotation.json`, spec §9.2 and §12.4): a list signed by a key later in
//! the pinned chain wins over any sequence from an earlier key, earlier keys' lists are then
//! refused, keys outside the chain are refused, and only the chain's last key extends it. The
//! Flutter app and the hosted service's clients run the same vectors.

use serde_json::Value;
use signpdf_core::trust_list::{public_p256, ClientState, TrustListClient};
use signpdf_core::Jwk;

const VECTORS: &str = include_str!("../../../spec/vectors/trust-list-rotation.json");

fn pins(v: &Value, names: &Value) -> Vec<Jwk> {
    names
        .as_array()
        .unwrap()
        .iter()
        .map(|n| public_p256(&v["keys"][n.as_str().unwrap()]).expect("a public P-256 key"))
        .collect()
}

#[test]
fn every_vector_case_holds() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 9, "the vectors lost cases");
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mut pinned = pins(&v, &case["pins"]);
        let mut client = TrustListClient::new(pinned.clone());
        let mut saved = ClientState::default();
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            if step["restart"] == true {
                client = TrustListClient::load(pinned.clone(), &saved);
                continue;
            }
            if step.get("update").is_some() {
                pinned = pins(&v, &step["update"]);
                client = TrustListClient::load(pinned.clone(), &saved);
                saved = client.state();
                continue;
            }
            let list = &v["lists"][step["list"].as_str().unwrap()];
            let got = client.consider(
                list["payload"].as_str().unwrap(),
                list["jws"].as_str().unwrap(),
            );
            assert_eq!(
                got.as_str(),
                step["expect"].as_str().unwrap(),
                "{name}: step {i} ({})",
                step["list"]
            );
            saved = client.state();
        }
        assert_eq!(
            client.sequence(),
            case["held"].as_i64(),
            "{name}: the list held"
        );
    }
}

#[test]
fn the_state_round_trips_as_json() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let pinned = pins(&v, &serde_json::json!(["A", "B"]));
    let mut client = TrustListClient::new(pinned.clone());
    let b2 = &v["lists"]["b2"];
    client.consider(b2["payload"].as_str().unwrap(), b2["jws"].as_str().unwrap());
    assert_eq!(
        client.chain().len(),
        4,
        "B, the last pinned key, pre-committed C and D"
    );
    let json = serde_json::to_string(&client.state()).unwrap();
    let back: ClientState = serde_json::from_str(&json).unwrap();
    let again = TrustListClient::load(pinned, &back);
    assert_eq!(again.chain(), client.chain());
    assert_eq!(again.sequence(), Some(2));
    assert_eq!(again.signer_position(), Some(1));
}

#[test]
fn a_private_key_is_never_taken_into_the_chain() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let mut k = v["keys"]["A"].clone();
    k["d"] = "secret".into();
    assert!(public_p256(&k).is_none());
    assert!(public_p256(&serde_json::json!({"kty": "RSA", "n": "x", "e": "AQAB"})).is_none());
}
