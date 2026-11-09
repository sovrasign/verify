//! Edge OIDC login for SignPDF.
//!
//! This crate is the **edge** half of SignPDF's federated-identity design: it runs the
//! interactive OpenID Connect **Authorization Code + PKCE** flow (RFC 6749/7636) against a
//! provider, captures the redirect on a **loopback** listener (RFC 8252), exchanges the code
//! for an **ID token**, and returns that token together with the provider's signing JWK.
//!
//! Crucially, all *trust* decisions stay in `signpdf-core`: this crate performs the network
//! dance and then asks the core to validate the token offline (signature, `iss`/`aud`/`exp`,
//! and the `nonce == H(pubkey ‖ doc_digest)` key/document binding). The caller computes that
//! `nonce` from the ephemeral signing key and the document digest *before* logging in, so the
//! issued token is cryptographically stapled to exactly one signature.
//!
//! ```no_run
//! use signpdf_auth::{authenticate, Provider, LoginOptions, SystemBrowser};
//! # fn demo(nonce: &str) -> signpdf_auth::Result<()> {
//! // SignPDF's own Google registration; pass `Some(client_id)` to use another one.
//! let config = Provider::Google.config_or_builtin(None)?;
//! let outcome = authenticate(&config, nonce, &SystemBrowser, &LoginOptions::default())?;
//! println!("signed in as {}", outcome.identity.email);
//! // outcome.id_token + outcome.idp_jwk go straight into a core SignRequest.
//! # Ok(()) }
//! ```

mod error;
mod http;

pub mod discovery;
pub mod loopback;
pub mod pkce;
pub mod providers;

use std::process::Command;
use std::time::Duration;

pub use error::{AuthError, Result};
pub use providers::{BuiltinClient, Provider, ProviderConfig};
pub use signpdf_core::VerifiedIdentity;

use discovery::ProviderMetadata;
use loopback::LoopbackServer;

/// Options tuning the loopback flow.
#[derive(Debug, Clone)]
pub struct LoginOptions {
    /// How long to wait for the user to finish signing in. Default 5 minutes.
    pub timeout: Duration,
    /// HTML shown in the browser tab once the redirect is captured.
    pub success_html: String,
}

impl Default for LoginOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            success_html: DEFAULT_SUCCESS_HTML.to_string(),
        }
    }
}

const DEFAULT_SUCCESS_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\">\
<title>SignPDF</title></head><body style=\"font-family:system-ui;text-align:center;margin-top:4rem\">\
<h2>You're signed in.</h2><p>You can close this tab and return to SignPDF.</p></body></html>";

/// The validated result of a login: the ID token, the key that signed it, and who it identifies.
#[derive(Debug, Clone)]
pub struct AuthOutcome {
    /// The raw compact-JWS ID token (goes into the core `SignRequest`/`PrepareRequest`).
    pub id_token: String,
    /// The single JWK (JSON) that signed `id_token`, archived for offline re-verification.
    pub idp_jwk: String,
    /// The token issuer (`iss`).
    pub issuer: String,
    /// The relying-party `client_id` the token's `aud` contains.
    pub audience: String,
    /// The identity, already validated offline by the core (signature + claims + nonce binding).
    pub identity: VerifiedIdentity,
}

/// Launches the system browser at an authorization URL. Implementations must return promptly
/// after handing the URL off (the flow then waits on the loopback listener).
pub trait BrowserOpener {
    /// Open `url` in the user's browser.
    fn open(&self, url: &str) -> Result<()>;
}

/// Opens the platform's default browser via the OS launcher.
pub struct SystemBrowser;

/// Only `http(s)` URLs are ever handed to the OS launcher (a malicious discovery document must
/// not be able to launch `file:` or other handlers).
fn launchable(url: &str) -> Result<()> {
    let parsed =
        url::Url::parse(url).map_err(|e| AuthError::Browser(format!("invalid URL: {e}")))?;
    match parsed.scheme() {
        "https" | "http" => Ok(()),
        other => Err(AuthError::Browser(format!(
            "refusing to open a '{other}:' URL in the browser"
        ))),
    }
}

impl BrowserOpener for SystemBrowser {
    fn open(&self, url: &str) -> Result<()> {
        launchable(url)?;
        let mut command = if cfg!(target_os = "windows") {
            // NOT `cmd /C start "" <url>`: cmd.exe treats `&` (present in every authorization
            // URL) as a command separator, truncating the URL and letting attacker-influenced
            // query text run as commands. The URL protocol handler takes it as one argument.
            let mut c = Command::new("rundll32");
            c.args(["url.dll,FileProtocolHandler", url]);
            c
        } else if cfg!(target_os = "macos") {
            let mut c = Command::new("open");
            c.arg(url);
            c
        } else {
            let mut c = Command::new("xdg-open");
            c.arg(url);
            c
        };
        command
            .spawn()
            .map(|_| ())
            .map_err(|e| AuthError::Browser(e.to_string()))
    }
}

/// Run the full Authorization Code + PKCE loopback flow and return a validated [`AuthOutcome`].
///
/// `nonce` must be the value the caller intends the token to be bound to — typically
/// `signpdf_core::compute_nonce(ephemeral_pubkey_sec1, doc_digest_hex)`. It is sent in the
/// authorization request and re-checked against the issued token, so a token obtained here can
/// only be used to sign that one (key, document) pair.
pub fn authenticate(
    config: &ProviderConfig,
    nonce: &str,
    opener: &dyn BrowserOpener,
    options: &LoginOptions,
) -> Result<AuthOutcome> {
    if config.client_id.trim().is_empty() {
        return Err(AuthError::Config("client_id must not be empty".into()));
    }

    let metadata = ProviderMetadata::discover(config)?;
    let server = LoopbackServer::bind_default()?;
    let pkce = pkce::generate_pkce();
    let state = pkce::random_token(16);

    let authorize_url = build_authorize_url(
        &metadata,
        config,
        server.redirect_uri(),
        &state,
        nonce,
        &pkce.challenge,
    );

    opener.open(&authorize_url)?;
    let code = server.wait_for_code(&state, options.timeout, &options.success_html)?;

    let token_response = exchange_code(
        &metadata,
        config,
        server.redirect_uri(),
        &code,
        &pkce.verifier,
    )?;
    let id_token = token_response
        .id_token
        .ok_or_else(|| AuthError::Protocol("token endpoint did not return an id_token".into()))?;

    finish(config, &metadata, id_token, nonce)
}

/// Build the authorization-request URL (everything after `opener.open`).
fn build_authorize_url(
    metadata: &ProviderMetadata,
    config: &ProviderConfig,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> String {
    let mut url = url::Url::parse(&metadata.authorization_endpoint)
        .expect("authorization_endpoint validated during discovery");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", &config.client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("scope", &config.scope_param());
        q.append_pair("state", state);
        q.append_pair("nonce", nonce);
        q.append_pair("code_challenge", code_challenge);
        q.append_pair("code_challenge_method", "S256");
        for (k, v) in &config.extra_auth_params {
            q.append_pair(k, v);
        }
    }
    url.to_string()
}

#[derive(Debug, serde::Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: Option<String>,
}

/// Exchange the authorization `code` for tokens at the token endpoint.
fn exchange_code(
    metadata: &ProviderMetadata,
    config: &ProviderConfig,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
) -> Result<TokenResponse> {
    let form = token_form(config, redirect_uri, code, code_verifier);
    http::post_form_json(&metadata.token_endpoint, &form)
}

/// The token-request form. Desktop apps are public clients, so PKCE's `code_verifier` is what
/// proves the exchange; a `client_secret` is added only for registrations that carry one.
fn token_form<'a>(
    config: &'a ProviderConfig,
    redirect_uri: &'a str,
    code: &'a str,
    code_verifier: &'a str,
) -> Vec<(&'static str, &'a str)> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", config.client_id.as_str()),
        ("code_verifier", code_verifier),
    ];
    if let Some(secret) = config.client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    form
}

/// Fetch the JWKS, select the signing key, and validate the token offline via the core.
fn finish(
    config: &ProviderConfig,
    metadata: &ProviderMetadata,
    id_token: String,
    nonce: &str,
) -> Result<AuthOutcome> {
    let jwks_text = http::get_text(&metadata.jwks_uri)?;
    let jwks: signpdf_core::Jwks = serde_json::from_str(&jwks_text)
        .map_err(|e| AuthError::Protocol(format!("invalid JWKS JSON: {e}")))?;
    let kid = http::token_kid(&id_token)?;
    let idp_jwk = http::select_jwk(&jwks_text, kid.as_deref())?;

    // For Microsoft multi-tenant authorities the discovered issuer is the `{tenantid}` template;
    // the core matches it against the token's own `tid`.
    let mut validation = signpdf_core::Validation::new(
        vec![metadata.token_issuer_pattern().to_string()],
        config.client_id.clone(),
        now_unix(),
    );
    validation.expected_nonce = Some(nonce.to_string());

    let identity = signpdf_core::verify_id_token(&id_token, &jwks, &validation)
        .map_err(|e| AuthError::Validation(e.to_string()))?;

    Ok(AuthOutcome {
        id_token,
        idp_jwk,
        // The token's concrete issuer (e.g. the tenant-specific Microsoft issuer), which is what
        // signer-slot policies and verifiers compare against.
        issuer: identity.issuer.clone(),
        audience: config.client_id.clone(),
        identity,
    })
}

/// Fetch an issuer's current JWKS (for refreshing a verifier [`signpdf_core::TrustStore`]).
///
/// Uses `jwks_uri` when given, otherwise OIDC discovery at `issuer`. For the Microsoft
/// `{tenantid}` template, discovery runs against the `common` authority.
pub fn fetch_jwks(issuer: &str, jwks_uri: Option<&str>) -> Result<signpdf_core::Jwks> {
    let text = fetch_jwks_text(issuer, jwks_uri)?;
    serde_json::from_str(&text).map_err(|e| AuthError::Protocol(format!("invalid JWKS JSON: {e}")))
}

/// [`fetch_jwks`], keeping the validity window an issuer may publish next to each key.
pub fn fetch_published_jwks(
    issuer: &str,
    jwks_uri: Option<&str>,
) -> Result<signpdf_core::PublishedJwks> {
    let text = fetch_jwks_text(issuer, jwks_uri)?;
    serde_json::from_str(&text).map_err(|e| AuthError::Protocol(format!("invalid JWKS JSON: {e}")))
}

/// The body of an issuer's JWKS, from `jwks_uri` or found by OIDC discovery.
fn fetch_jwks_text(issuer: &str, jwks_uri: Option<&str>) -> Result<String> {
    let uri = match jwks_uri {
        Some(u) => u.to_string(),
        None => {
            let discover_at = if issuer.contains("{tenantid}") {
                issuer.replace("{tenantid}", "common")
            } else {
                issuer.to_string()
            };
            let config = Provider::Enterprise {
                issuer: discover_at,
            }
            .config("signpdf-trust-refresh");
            ProviderMetadata::discover(&config)?.jwks_uri
        }
    };
    http::get_text(&uri)
}

/// Refresh every issuer in `store` that has a `jwks_uri` (or is discoverable), merging newly
/// published keys into its pinned key history, with any validity windows the issuer publishes
/// (they only ever narrow). Returns `(issuer, keys_added or error)` per issuer.
pub fn refresh_trust_store(
    store: &mut signpdf_core::TrustStore,
) -> Vec<(String, std::result::Result<usize, String>)> {
    let targets: Vec<(String, Option<String>)> = store
        .issuers
        .iter()
        .map(|i| (i.issuer.clone(), i.jwks_uri.clone()))
        .collect();
    targets
        .into_iter()
        .map(|(issuer, uri)| {
            let outcome = fetch_published_jwks(&issuer, uri.as_deref())
                .map_err(|e| e.to_string())
                .and_then(|jwks| {
                    store
                        .add_published_jwks(&issuer, &jwks)
                        .map_err(|e| e.to_string())
                });
            (issuer, outcome)
        })
        .collect()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> ProviderMetadata {
        serde_json::from_str(
            r#"{"issuer":"https://issuer.test",
                "authorization_endpoint":"https://issuer.test/authorize",
                "token_endpoint":"https://issuer.test/token",
                "jwks_uri":"https://issuer.test/jwks"}"#,
        )
        .unwrap()
    }

    #[test]
    fn authorize_url_carries_all_required_params() {
        let config = Provider::Google.config("client-123");
        let url = build_authorize_url(
            &meta(),
            &config,
            "http://127.0.0.1:7777/callback",
            "state-abc",
            "nonce-xyz",
            "challenge-789",
        );
        let parsed = url::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q.get("response_type").unwrap(), "code");
        assert_eq!(q.get("client_id").unwrap(), "client-123");
        assert_eq!(
            q.get("redirect_uri").unwrap(),
            "http://127.0.0.1:7777/callback"
        );
        assert_eq!(q.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(q.get("code_challenge").unwrap(), "challenge-789");
        assert_eq!(q.get("nonce").unwrap(), "nonce-xyz");
        assert_eq!(q.get("state").unwrap(), "state-abc");
        assert_eq!(q.get("scope").unwrap(), "openid email profile");
        // Google preset quirk preserved.
        assert_eq!(q.get("prompt").unwrap(), "select_account");
    }

    #[test]
    fn token_form_sends_a_secret_only_for_clients_that_have_one() {
        let field = |form: &[(&str, &str)], name: &str| {
            form.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        };

        let mut config = Provider::Google.config("client-123");
        config.client_secret = Some("not-so-secret".into());
        let form = token_form(
            &config,
            "http://127.0.0.1:7777/callback",
            "code-1",
            "verifier-1",
        );
        assert_eq!(field(&form, "client_secret").unwrap(), "not-so-secret");
        assert_eq!(field(&form, "code_verifier").unwrap(), "verifier-1");
        assert_eq!(field(&form, "client_id").unwrap(), "client-123");

        let public = Provider::Microsoft.config_or_builtin(None).unwrap();
        let form = token_form(
            &public,
            "http://127.0.0.1:7777/callback",
            "code-1",
            "verifier-1",
        );
        assert_eq!(field(&form, "client_secret"), None);
    }

    #[test]
    fn only_http_urls_are_launched() {
        assert!(launchable("https://accounts.google.com/o/oauth2/v2/auth?a=1&b=2").is_ok());
        assert!(launchable("file:///C:/Windows/System32/calc.exe").is_err());
        assert!(launchable("ms-settings:privacy").is_err());
        assert!(launchable("not a url").is_err());
    }

    #[test]
    fn empty_client_id_is_rejected_before_any_network() {
        let config = Provider::Enterprise {
            issuer: "https://id.example".into(),
        }
        .config("");
        let err =
            authenticate(&config, "nonce", &SystemBrowser, &LoginOptions::default()).unwrap_err();
        assert!(matches!(err, AuthError::Config(_)));
    }
}
