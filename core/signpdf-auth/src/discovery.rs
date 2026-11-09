//! OIDC discovery: fetch and validate a provider's `/.well-known/openid-configuration`.

use serde::Deserialize;

use crate::error::{AuthError, Result};
use crate::http;
use crate::providers::ProviderConfig;

/// The subset of OpenID Provider Metadata (OpenID Connect Discovery 1.0) SignPDF needs.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

impl ProviderMetadata {
    /// Fetch and validate discovery metadata for `config`.
    ///
    /// The discovered `issuer` **must** equal the configured issuer (OIDC Discovery §4.3): a
    /// mismatch means the discovery document was tampered with or points at the wrong provider,
    /// so we refuse rather than trust attacker-chosen endpoints.
    pub fn discover(config: &ProviderConfig) -> Result<Self> {
        let url = config.discovery_url();
        let meta: ProviderMetadata = http::get_json(&url)?;
        if !issuer_acceptable(&config.issuer, &meta.issuer) {
            return Err(AuthError::Protocol(format!(
                "discovery issuer '{}' does not match the expected issuer '{}'",
                meta.issuer, config.issuer
            )));
        }
        if meta.authorization_endpoint.is_empty()
            || meta.token_endpoint.is_empty()
            || meta.jwks_uri.is_empty()
        {
            return Err(AuthError::Protocol(
                "discovery document is missing a required endpoint".into(),
            ));
        }
        Ok(meta)
    }

    /// The issuer (or issuer template) tokens from this provider must match. For Microsoft's
    /// multi-tenant authorities this is `https://login.microsoftonline.com/{tenantid}/v2.0`,
    /// which the core matches against each token's own `tid`.
    pub fn token_issuer_pattern(&self) -> &str {
        &self.issuer
    }

    /// Whether the provider advertises PKCE `S256` support (advisory; we always send `S256`).
    pub fn supports_s256(&self) -> bool {
        self.code_challenge_methods_supported.is_empty()
            || self
                .code_challenge_methods_supported
                .iter()
                .any(|m| m == "S256")
    }
}

/// Microsoft's multi-tenant authorities publish an issuer *template* instead of their own URL.
const MICROSOFT_MULTI_TENANT: [&str; 3] = [
    "https://login.microsoftonline.com/common/v2.0",
    "https://login.microsoftonline.com/organizations/v2.0",
    "https://login.microsoftonline.com/consumers/v2.0",
];

/// OIDC Discovery §4.3: the discovered `issuer` must equal the configured one. The single
/// exception is Microsoft's multi-tenant authorities, whose discovery document legitimately
/// returns the `{tenantid}` template (each token then carries its concrete tenant issuer).
pub fn issuer_acceptable(configured: &str, discovered: &str) -> bool {
    let c = configured.trim_end_matches('/');
    let d = discovered.trim_end_matches('/');
    if c == d {
        return true;
    }
    MICROSOFT_MULTI_TENANT.contains(&c) && d == signpdf_core::oidc::MICROSOFT_ISSUER_TEMPLATE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microsoft_common_accepts_only_the_tenant_template() {
        let common = "https://login.microsoftonline.com/common/v2.0";
        assert!(issuer_acceptable(
            common,
            "https://login.microsoftonline.com/{tenantid}/v2.0"
        ));
        assert!(!issuer_acceptable(
            common,
            "https://evil.test/{tenantid}/v2.0"
        ));
        // A non-Microsoft issuer never accepts a template.
        assert!(!issuer_acceptable(
            "https://id.example",
            "https://login.microsoftonline.com/{tenantid}/v2.0"
        ));
        assert!(issuer_acceptable(
            "https://id.example/",
            "https://id.example"
        ));
    }

    #[test]
    fn parses_a_typical_discovery_document() {
        let json = r#"{
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
            "response_types_supported": ["code","token","id_token"],
            "code_challenge_methods_supported": ["plain","S256"]
        }"#;
        let meta: ProviderMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.token_endpoint, "https://oauth2.googleapis.com/token");
        assert!(meta.supports_s256());
    }
}
