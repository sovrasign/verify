//! Minimal HTTP helpers over `ureq`, plus JWKS/JWT-header utilities.
//!
//! Networking is intentionally confined to this crate (the edge); the core never makes a
//! request. Without the `tls` feature only plain-HTTP endpoints work — enough for the
//! loopback callback and the mock-IdP tests; real https providers need `--features tls`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use serde::Deserialize;

use crate::error::{AuthError, Result};

/// The shared HTTP agent. With the `tls` feature it carries an explicit native-tls connector:
/// ureq 2 does not configure its `native-tls` backend on its own, so without this every https
/// request fails with "no TLS backend is configured".
fn agent() -> &'static ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT.get_or_init(|| {
        let builder = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(20));
        #[cfg(feature = "tls")]
        let builder = match native_tls::TlsConnector::new() {
            Ok(connector) => builder.tls_connector(std::sync::Arc::new(connector)),
            Err(_) => builder,
        };
        builder.build()
    })
}

/// Refuse to talk to an identity provider in the clear. Its discovery document names the token
/// endpoint and its keys are what a verifier pins: over plain http, anyone on the network path
/// could substitute their own. Only this computer itself (the loopback listener, a local test
/// provider) is reached over http.
fn require_secure(url: &str) -> Result<()> {
    let parsed =
        url::Url::parse(url).map_err(|e| AuthError::Config(format!("invalid URL '{url}': {e}")))?;
    let loopback = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => Err(AuthError::Config(format!(
            "refusing an unencrypted connection to {url}: identity providers are reached over https"
        ))),
    }
}

/// `GET url` and parse the body as JSON into `T`.
pub fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T> {
    let body = get_text(url)?;
    serde_json::from_str(&body)
        .map_err(|e| AuthError::Protocol(format!("invalid JSON from {url}: {e}")))
}

/// `GET url` and return the response body as text.
pub fn get_text(url: &str) -> Result<String> {
    require_secure(url)?;
    let resp = agent()
        .get(url)
        .timeout(std::time::Duration::from_secs(20))
        .call()
        .map_err(|e| http_err("GET", url, e))?;
    resp.into_string()
        .map_err(|e| AuthError::Network(format!("reading GET {url} body: {e}")))
}

/// `POST url` with a `application/x-www-form-urlencoded` body and parse the JSON response.
pub fn post_form_json<T: serde::de::DeserializeOwned>(
    url: &str,
    form: &[(&str, &str)],
) -> Result<T> {
    require_secure(url)?;
    let resp = agent()
        .post(url)
        .timeout(std::time::Duration::from_secs(20))
        .send_form(form)
        .map_err(|e| http_err("POST", url, e))?;
    let body = resp
        .into_string()
        .map_err(|e| AuthError::Network(format!("reading POST {url} body: {e}")))?;
    serde_json::from_str(&body)
        .map_err(|e| AuthError::Protocol(format!("invalid JSON from {url}: {e}")))
}

/// Turn a `ureq::Error` into an [`AuthError`], surfacing the provider's error body when present.
fn http_err(method: &str, url: &str, e: ureq::Error) -> AuthError {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            AuthError::Protocol(format!(
                "{method} {url} returned HTTP {code}: {}",
                body.trim()
            ))
        }
        ureq::Error::Transport(t) => {
            AuthError::Network(format!("{method} {url} transport error: {t}"))
        }
    }
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    #[serde(default)]
    kid: Option<String>,
}

/// Read the (unverified) `kid` from a compact-JWS header. The token is fully verified later by
/// the core; this only selects which published key to archive alongside the signature.
pub fn token_kid(token: &str) -> Result<Option<String>> {
    let header_seg = token
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AuthError::Protocol("id_token is not a compact JWS".into()))?;
    let raw = B64URL
        .decode(header_seg.trim_end_matches('='))
        .map_err(|e| AuthError::Protocol(format!("invalid JWT header base64url: {e}")))?;
    let header: JwtHeader = serde_json::from_slice(&raw)
        .map_err(|e| AuthError::Protocol(format!("invalid JWT header JSON: {e}")))?;
    Ok(header.kid)
}

/// Select, from a JWKS JSON document, the single key that signed a token with header `kid` and
/// return it as its own one-key JWK JSON string (the shape the core archives as `idp_jwk`).
pub fn select_jwk(jwks_json: &str, kid: Option<&str>) -> Result<String> {
    let jwks: signpdf_core::Jwks = serde_json::from_str(jwks_json)
        .map_err(|e| AuthError::Protocol(format!("invalid JWKS JSON: {e}")))?;
    let chosen = match kid {
        Some(k) => jwks.keys.into_iter().find(|j| j.kid.as_deref() == Some(k)),
        None if jwks.keys.len() == 1 => jwks.keys.into_iter().next(),
        None => None,
    }
    .ok_or_else(|| AuthError::Protocol("no JWKS key matches the id_token's kid".into()))?;
    serde_json::to_string(&chosen)
        .map_err(|e| AuthError::Protocol(format!("re-encoding selected JWK: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_providers_are_only_reached_over_https() {
        assert!(
            require_secure("https://accounts.google.com/.well-known/openid-configuration").is_ok()
        );
        // This computer itself: the loopback listener and local test providers.
        assert!(require_secure("http://127.0.0.1:8123/keys").is_ok());
        assert!(require_secure("http://localhost:8123/keys").is_ok());
        assert!(require_secure("http://[::1]:8123/keys").is_ok());
        for refused in [
            "http://accounts.google.com/keys",
            "http://127.0.0.1.evil.example/keys",
            "http://localhost.evil.example/keys",
            "ftp://127.0.0.1/keys",
            "not a url",
        ] {
            assert!(require_secure(refused).is_err(), "{refused}");
        }
        assert!(get_text("http://idp.example/keys").is_err());
    }

    // header {"alg":"ES256","kid":"abc"} base64url, payload/sig irrelevant for kid extraction.
    #[test]
    fn token_kid_is_extracted() {
        let header = B64URL.encode(br#"{"alg":"ES256","kid":"abc"}"#);
        let token = format!("{header}.payload.sig");
        assert_eq!(token_kid(&token).unwrap().as_deref(), Some("abc"));
    }

    #[test]
    fn select_jwk_by_kid_and_singleton() {
        let jwks = r#"{"keys":[
            {"kty":"EC","kid":"k1","crv":"P-256","x":"AA","y":"BB"},
            {"kty":"EC","kid":"k2","crv":"P-256","x":"CC","y":"DD"}]}"#;
        let one = select_jwk(jwks, Some("k2")).unwrap();
        assert!(one.contains("\"kid\":\"k2\""));
        assert!(one.contains("\"DD\""));
        assert!(select_jwk(jwks, Some("missing")).is_err());

        let single = r#"{"keys":[{"kty":"EC","kid":"only","crv":"P-256","x":"AA","y":"BB"}]}"#;
        assert!(select_jwk(single, None).unwrap().contains("\"only\""));
    }
}
