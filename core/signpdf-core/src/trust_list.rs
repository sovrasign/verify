//! The **signed trust list** a client follows (`spec/envelope-format.md` §9.2): which published
//! list it believes, under which trust-list key, and how it follows the publisher's key chain.
//!
//! A publisher (a hosted service) signs its trust store as `trust.json` with a trust-list key
//! (a detached ES256 JWS, `trust.json.jws`) and pre-commits the keys that will follow it
//! (`next_keys`). A client pins, at build time, an ordered **key chain**: the key in use first,
//! then its pre-committed successors. The accept rule ([`TrustListClient::consider`]):
//!
//! 1. The list's signature must verify under a key of the chain; any other key is refused
//!    (`unknown_key`: the client cannot follow the publisher and should be updated).
//! 2. **The key's position in the chain decides first**: a list signed by a key later in the
//!    chain than the one that signed the list held wins over any sequence number from an earlier
//!    key; once such a list is held, every list signed by an earlier key is refused
//!    (`older_key`). So a list forged with a stolen key and a huge `sequence` loses to the
//!    publisher's first list signed by the next key, and the stolen key's lists stop counting.
//! 3. Under the same key, the higher `sequence` wins (`older` for a lower one).
//! 4. Only a list signed by the chain's **last** key extends the chain with its `next_keys`;
//!    `next_keys` from any other key add nothing. So the key in use cannot rewrite the keys that
//!    will replace it, and a thief who holds it cannot withdraw them. The chain only grows: a
//!    pre-committed key that is itself compromised is removed by new pins (an app update).
//!
//! The chain's extensions are kept with the list (the `steps` of [`ClientState`]) and replayed
//! from the pins on every load: a step counts only when the key that made it is then the chain's
//! last, so a build with new pins drops what an earlier chain added.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::oidc::Jwk;
use crate::trust::jwk_thumbprint;

/// `type` of a signed trust list.
pub const LIST_TYPE: &str = "sovrasign-trust-list";

/// The newest list layout this build reads. Version 2 adds `tsa_distrusted` and the key-chain
/// accept rule.
pub const LIST_SCHEMA: i64 = 2;

/// Why a list was not taken (or `Ok`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Taken (or the list held, seen again).
    Ok,
    /// Not a detached compact ES256 JWS.
    Malformed,
    /// Signed by a key outside the chain.
    UnknownKey,
    /// The signature does not verify.
    BadSignature,
    /// Not a signed trust list.
    NotAList,
    /// A list layout newer than [`LIST_SCHEMA`].
    NewerSchema,
    /// The same key's list with a lower sequence than the list held.
    Older,
    /// Signed by a key earlier in the chain than the list held.
    OlderKey,
}

impl Outcome {
    /// The stable label (matches the serde form and the other clients' reasons).
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Malformed => "malformed",
            Outcome::UnknownKey => "unknown_key",
            Outcome::BadSignature => "bad_signature",
            Outcome::NotAList => "not_a_list",
            Outcome::NewerSchema => "newer_schema",
            Outcome::Older => "older",
            Outcome::OlderKey => "older_key",
        }
    }
}

/// A list whose signature verified: the parsed list, the header's `kid` and the key.
#[derive(Debug, Clone)]
pub struct Verified {
    pub list: Value,
    pub kid: String,
    pub key: Jwk,
    /// The key's position in the keys it was checked against.
    pub position: usize,
}

fn b64u(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

fn b64u_encode(b: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(b)
}

/// A public P-256 JWK (no private member).
pub fn public_p256(v: &Value) -> Option<Jwk> {
    let o = v.as_object()?;
    if o.get("kty")? != "EC" || o.get("crv")? != "P-256" || o.contains_key("d") {
        return None;
    }
    o.get("x")?.as_str()?;
    o.get("y")?.as_str()?;
    serde_json::from_value(v.clone()).ok()
}

fn names(k: &Jwk, kid: &str) -> bool {
    k.kid.as_deref() == Some(kid) || jwk_thumbprint(k).is_ok_and(|t| t == kid)
}

/// Check the detached JWS `jws` (`header..signature`) over the exact text `payload` against
/// `keys` (in chain order).
pub fn verify_signed(
    payload: &str,
    jws: &str,
    keys: &[Jwk],
) -> std::result::Result<Verified, (Outcome, String)> {
    let parts: Vec<&str> = jws.trim().split('.').collect();
    if parts.len() != 3 || !parts[1].is_empty() {
        return Err((Outcome::Malformed, String::new()));
    }
    let header: Value = match b64u(parts[0]).and_then(|h| serde_json::from_slice(&h).ok()) {
        Some(h) => h,
        None => return Err((Outcome::Malformed, String::new())),
    };
    if header["alg"] != "ES256" {
        return Err((Outcome::Malformed, String::new()));
    }
    let kid = header["kid"].as_str().unwrap_or_default().to_string();
    let Some(position) = keys.iter().position(|k| names(k, &kid)) else {
        return Err((Outcome::UnknownKey, kid));
    };
    let key = keys[position].clone();
    let input = format!("{}.{}", parts[0], b64u_encode(payload.as_bytes()));
    let good = b64u(parts[2])
        .is_some_and(|sig| crate::oidc::verify_es256(&key, input.as_bytes(), &sig).is_ok());
    if !good {
        return Err((Outcome::BadSignature, kid));
    }
    let Ok(list) = serde_json::from_str::<Value>(payload) else {
        return Err((Outcome::NotAList, kid));
    };
    if list["type"] != LIST_TYPE || !list["issuers"].is_array() || !list["sequence"].is_i64() {
        return Err((Outcome::NotAList, kid));
    }
    match list["schema"].as_i64() {
        Some(s) if s <= LIST_SCHEMA => {}
        _ => return Err((Outcome::NewerSchema, kid)),
    }
    Ok(Verified {
        list,
        kid,
        key,
        position,
    })
}

/// One extension of the chain: `keys` appended by the list of the key `by` (its RFC 7638
/// thumbprint), which was then the chain's last.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainStep {
    pub by: String,
    pub keys: Vec<Jwk>,
}

/// What a client keeps between runs: the list held, byte for byte, and the chain's extensions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jws: Option<String>,
    #[serde(default)]
    pub steps: Vec<ChainStep>,
}

#[derive(Debug, Clone)]
struct Held {
    payload: String,
    jws: String,
    list: Value,
    sequence: i64,
    position: usize,
}

/// A client's signed trust list (see the module comment).
#[derive(Debug, Clone)]
pub struct TrustListClient {
    pins: Vec<Jwk>,
    steps: Vec<ChainStep>,
    held: Option<Held>,
}

impl TrustListClient {
    /// A client pinning `pins` (public P-256 JWKs, the key in use first), holding no list.
    pub fn new(pins: Vec<Jwk>) -> Self {
        TrustListClient {
            pins,
            steps: Vec::new(),
            held: None,
        }
    }

    /// A client pinning `pins` that kept `state`: the chain is rebuilt from the pins (each step
    /// only when its key is then the last), then the kept list is checked against it.
    pub fn load(pins: Vec<Jwk>, state: &ClientState) -> Self {
        let mut c = TrustListClient::new(pins);
        for step in &state.steps {
            let chain = c.chain();
            let last = chain.last().and_then(|k| jwk_thumbprint(k).ok());
            if last.as_deref() != Some(step.by.as_str()) {
                break;
            }
            let fresh: Vec<Jwk> = step
                .keys
                .iter()
                .filter(|k| !contains(&chain, k))
                .cloned()
                .collect();
            if !fresh.is_empty() {
                c.steps.push(ChainStep {
                    by: step.by.clone(),
                    keys: fresh,
                });
            }
        }
        if let (Some(p), Some(j)) = (&state.payload, &state.jws) {
            let _ = c.consider(p, j);
        }
        c
    }

    /// What to keep between runs.
    pub fn state(&self) -> ClientState {
        ClientState {
            payload: self.held.as_ref().map(|h| h.payload.clone()),
            jws: self.held.as_ref().map(|h| h.jws.clone()),
            steps: self.steps.clone(),
        }
    }

    /// The key chain: the pins, then every extension in order.
    pub fn chain(&self) -> Vec<Jwk> {
        let mut out = self.pins.clone();
        for s in &self.steps {
            out.extend(s.keys.iter().cloned());
        }
        out
    }

    /// The list held, if any.
    pub fn list(&self) -> Option<&Value> {
        self.held.as_ref().map(|h| &h.list)
    }

    /// The held list's sequence.
    pub fn sequence(&self) -> Option<i64> {
        self.held.as_ref().map(|h| h.sequence)
    }

    /// The position in the chain of the key that signed the list held.
    pub fn signer_position(&self) -> Option<usize> {
        self.held.as_ref().map(|h| h.position)
    }

    /// Take the list `payload` with its detached JWS `jws` when the accept rule allows it.
    pub fn consider(&mut self, payload: &str, jws: &str) -> Outcome {
        let chain = self.chain();
        let v = match verify_signed(payload, jws, &chain) {
            Ok(v) => v,
            Err((o, _)) => return o,
        };
        let sequence = v.list["sequence"].as_i64().unwrap_or(i64::MIN);
        if let Some(h) = &self.held {
            if v.position < h.position {
                return Outcome::OlderKey;
            }
            if v.position == h.position {
                if sequence < h.sequence {
                    return Outcome::Older;
                }
                if sequence == h.sequence {
                    return Outcome::Ok;
                }
            }
        }
        if v.position + 1 == chain.len() {
            let fresh: Vec<Jwk> = v.list["next_keys"]
                .as_array()
                .map(|a| a.iter().filter_map(public_p256).collect::<Vec<_>>())
                .unwrap_or_default()
                .into_iter()
                .fold(Vec::new(), |mut acc: Vec<Jwk>, k| {
                    if !contains(&chain, &k) && !contains(&acc, &k) {
                        acc.push(k);
                    }
                    acc
                });
            if let (false, Ok(by)) = (fresh.is_empty(), jwk_thumbprint(&v.key)) {
                self.steps.push(ChainStep { by, keys: fresh });
            }
        }
        self.held = Some(Held {
            payload: payload.to_string(),
            jws: jws.trim().to_string(),
            list: v.list,
            sequence,
            position: v.position,
        });
        Outcome::Ok
    }
}

fn contains(keys: &[Jwk], k: &Jwk) -> bool {
    let Ok(t) = jwk_thumbprint(k) else {
        return true;
    };
    keys.iter().any(|x| jwk_thumbprint(x).is_ok_and(|y| y == t))
}
