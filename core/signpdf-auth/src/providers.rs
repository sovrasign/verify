//! Provider presets: issuer URLs, default scopes, and provider-specific authorization params
//! for the consumer IdPs SignPDF supports out of the box, plus generic enterprise OIDC.
//!
//! A preset never hard-codes endpoints — those come from OIDC discovery (`/.well-known/
//! openid-configuration`) so the crate tracks provider changes automatically. Only the issuer,
//! the relying-party `client_id` (SignPDF's own app registration, or one supplied by the caller),
//! the requested scopes, and any provider quirks live here.

use crate::error::{AuthError, Result};

/// SignPDF's own app registration with a provider — what lets a user sign in without registering
/// anything themselves. Its `client_id` becomes the `aud` of every token minted through it, and
/// it is the only application a verifier's default trust store accepts for that provider: a
/// document signed through any other `client_id` verifies only where that id was trusted
/// explicitly (`signpdf trust add-audience`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinClient {
    /// The registration's `client_id`.
    pub client_id: &'static str,
    /// The registration's secret, for providers whose token endpoint demands one from desktop
    /// clients even with PKCE (Google). It ships inside every copy of the app, so it is not
    /// confidential and authenticates nothing; PKCE is what protects the code exchange.
    pub client_secret: Option<&'static str>,
}

/// A federated identity provider SignPDF can log in against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provider {
    /// Personal Google accounts (`https://accounts.google.com`).
    Google,
    /// Microsoft personal + work/school via the multi-tenant `common` authority.
    Microsoft,
    /// Sign in with Apple (`https://appleid.apple.com`).
    Apple,
    /// Any standards-compliant enterprise OIDC issuer (Okta, Entra single-tenant, Ping, Auth0…).
    Enterprise {
        /// The issuer URL whose `/.well-known/openid-configuration` will be discovered.
        issuer: String,
    },
}

impl Provider {
    /// Parse a CLI/`--oidc` provider name. `enterprise` requires an `issuer`.
    pub fn from_name(name: &str, issuer: Option<String>) -> Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "google" => Ok(Provider::Google),
            "microsoft" | "msft" | "entra" => Ok(Provider::Microsoft),
            "apple" => Ok(Provider::Apple),
            "enterprise" | "oidc" | "custom" => issuer
                .map(|issuer| Provider::Enterprise { issuer })
                .ok_or_else(|| {
                    AuthError::Config(
                        "enterprise provider needs an --issuer (the OIDC issuer URL)".into(),
                    )
                }),
            other => Err(AuthError::Config(format!(
                "unknown provider '{other}' (expected google|microsoft|apple|enterprise)"
            ))),
        }
    }

    /// The OIDC issuer identifier. Discovery is performed at `{issuer}/.well-known/
    /// openid-configuration`, and the discovered/token `issuer` must match this exactly.
    pub fn issuer(&self) -> &str {
        match self {
            Provider::Google => "https://accounts.google.com",
            // The `common` authority lets both personal and work/school accounts sign in; the
            // token's concrete issuer (`…/{tenantid}/v2.0`) is validated against discovery.
            Provider::Microsoft => "https://login.microsoftonline.com/common/v2.0",
            Provider::Apple => "https://appleid.apple.com",
            Provider::Enterprise { issuer } => issuer,
        }
    }

    /// SignPDF's own registration with this provider, if it has one. Apple and enterprise issuers
    /// have none: the caller supplies the `client_id` of their own registration.
    pub fn builtin_client(&self) -> Option<BuiltinClient> {
        match self {
            // Google Cloud "Desktop app" client: loopback redirects on any port. Its secret is kept
            // out of the repository and compiled in from `SIGNPDF_GOOGLE_CLIENT_SECRET` (see
            // build.rs); a build made without it has no built-in Google sign-in.
            Provider::Google => option_env!("SIGNPDF_GOOGLE_CLIENT_SECRET")
                .filter(|secret| !secret.is_empty())
                .map(|secret| BuiltinClient {
                    client_id: signpdf_core::SIGNPDF_GOOGLE_CLIENT_ID,
                    client_secret: Some(secret),
                }),
            // Entra registration for personal + work/school accounts, public client, loopback
            // redirect `/callback`, optional ID-token claims `email` and `xms_edov`.
            Provider::Microsoft => Some(BuiltinClient {
                client_id: signpdf_core::SIGNPDF_MICROSOFT_CLIENT_ID,
                client_secret: None,
            }),
            Provider::Apple | Provider::Enterprise { .. } => None,
        }
    }

    /// [`Self::config`] for `client_id`, or for SignPDF's own registration when none is given.
    pub fn config_or_builtin(&self, client_id: Option<String>) -> Result<ProviderConfig> {
        client_id
            .filter(|id| !id.trim().is_empty())
            .or_else(|| self.builtin_client().map(|c| c.client_id.to_string()))
            .map(|id| self.config(id))
            .ok_or_else(|| {
                AuthError::Config(
                    "this build has no SignPDF registration for this provider; pass --client-id \
                     (your own app registration with the provider)"
                        .into(),
                )
            })
    }

    /// Build a [`ProviderConfig`] for this provider and relying-party `client_id`.
    pub fn config(&self, client_id: impl Into<String>) -> ProviderConfig {
        let client_id = client_id.into();
        // The built-in secret belongs to the built-in client only; a caller's own registration
        // sets `client_secret` itself if its provider wants one.
        let client_secret = self
            .builtin_client()
            .filter(|c| c.client_id == client_id)
            .and_then(|c| c.client_secret)
            .map(str::to_string);
        let scopes = match self {
            // Apple is restrictive: it only reliably returns `email` (and a one-time `name`).
            Provider::Apple => vec!["openid".into(), "email".into()],
            _ => vec!["openid".into(), "email".into(), "profile".into()],
        };
        let extra_auth_params = match self {
            // Force the account chooser so a signer is never silently bound to a cached session.
            Provider::Google => vec![("prompt".into(), "select_account".into())],
            Provider::Microsoft => vec![("prompt".into(), "select_account".into())],
            // Apple requires the response to be delivered as a POST form when `name`/`email`
            // scopes are requested; loopback desktop clients use `response_mode=query` instead.
            Provider::Apple => vec![("response_mode".into(), "query".into())],
            Provider::Enterprise { .. } => Vec::new(),
        };
        ProviderConfig {
            issuer: self.issuer().to_string(),
            client_id,
            client_secret,
            scopes,
            extra_auth_params,
        }
    }
}

/// A fully-resolved login configuration: issuer + relying-party client + scopes + quirks.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// The OIDC issuer (must equal the discovery document's `issuer`).
    pub issuer: String,
    /// The relying-party `client_id` registered with the provider; becomes the token `aud`.
    pub client_id: String,
    /// Sent to the token endpoint alongside the PKCE verifier when set (see
    /// [`BuiltinClient::client_secret`]). `None` for ordinary public clients.
    pub client_secret: Option<String>,
    /// OAuth scopes to request (`openid` is always included by convention).
    pub scopes: Vec<String>,
    /// Provider-specific extra authorization-request parameters (e.g. `prompt=select_account`).
    pub extra_auth_params: Vec<(String, String)>,
}

impl ProviderConfig {
    /// The OIDC discovery document URL for this issuer.
    pub fn discovery_url(&self) -> String {
        let base = self.issuer.trim_end_matches('/');
        format!("{base}/.well-known/openid-configuration")
    }

    /// The space-delimited `scope` parameter value.
    pub fn scope_param(&self) -> String {
        self.scopes.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_carry_expected_issuers() {
        assert_eq!(Provider::Google.issuer(), "https://accounts.google.com");
        assert_eq!(Provider::Apple.issuer(), "https://appleid.apple.com");
        assert!(Provider::Microsoft
            .issuer()
            .contains("login.microsoftonline.com"));
    }

    #[test]
    fn enterprise_requires_issuer() {
        assert!(Provider::from_name("enterprise", None).is_err());
        let p = Provider::from_name("enterprise", Some("https://id.acme.example".into())).unwrap();
        assert_eq!(p.issuer(), "https://id.acme.example");
    }

    #[test]
    fn builtin_clients_cover_google_and_microsoft_only() {
        let microsoft = Provider::Microsoft
            .builtin_client()
            .expect("built-in registration");
        let cfg = Provider::Microsoft.config_or_builtin(None).unwrap();
        assert_eq!(cfg.client_id, microsoft.client_id);
        assert!(cfg.client_secret.is_none());
        // A blank override means "use the built-in one", not an empty client_id.
        assert_eq!(
            Provider::Microsoft
                .config_or_builtin(Some("  ".into()))
                .unwrap()
                .client_id,
            microsoft.client_id
        );

        // Google's registration is usable only in a build that was given its secret.
        match Provider::Google.builtin_client() {
            Some(google) => {
                let cfg = Provider::Google.config_or_builtin(None).unwrap();
                assert_eq!(cfg.client_id, google.client_id);
                assert!(cfg.client_secret.is_some_and(|s| !s.is_empty()));
            }
            None => assert!(Provider::Google.config_or_builtin(None).is_err()),
        }

        let enterprise = Provider::Enterprise {
            issuer: "https://id.acme.example".into(),
        };
        assert!(Provider::Apple.config_or_builtin(None).is_err());
        assert!(enterprise.config_or_builtin(None).is_err());
        assert_eq!(
            enterprise
                .config_or_builtin(Some("rp".into()))
                .unwrap()
                .client_id,
            "rp"
        );
    }

    #[test]
    fn builtin_secret_never_accompanies_another_client() {
        let cfg = Provider::Google
            .config_or_builtin(Some("someone-elses-client".into()))
            .unwrap();
        assert_eq!(cfg.client_id, "someone-elses-client");
        assert!(cfg.client_secret.is_none());
    }

    #[test]
    fn unknown_provider_is_rejected() {
        assert!(Provider::from_name("facebook", None).is_err());
    }

    #[test]
    fn discovery_url_is_well_formed_without_double_slash() {
        let cfg = Provider::Enterprise {
            issuer: "https://id.acme.example/".into(),
        }
        .config("rp-client");
        assert_eq!(
            cfg.discovery_url(),
            "https://id.acme.example/.well-known/openid-configuration"
        );
    }

    #[test]
    fn google_forces_account_selection() {
        let cfg = Provider::Google.config("rp");
        assert!(cfg
            .extra_auth_params
            .iter()
            .any(|(k, v)| k == "prompt" && v == "select_account"));
        assert_eq!(cfg.scope_param(), "openid email profile");
    }
}
