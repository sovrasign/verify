//! Error type for the edge OIDC login flow.

use thiserror::Error;

/// Anything that can go wrong while obtaining and locally validating an ID token.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Caller misconfiguration (unknown provider, missing issuer/client_id, …).
    #[error("configuration error: {0}")]
    Config(String),
    /// Low-level transport failure (DNS, connection refused, TLS unavailable, …).
    #[error("network error: {0}")]
    Network(String),
    /// A protocol/well-formedness violation in a provider response (bad JSON, issuer mismatch…).
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The provider actively reported an error (e.g. `access_denied`).
    #[error("provider error: {0}")]
    Provider(String),
    /// The user did not complete sign-in in time.
    #[error("timeout: {0}")]
    Timeout(String),
    /// The token came back but failed offline validation in the core.
    #[error("token validation failed: {0}")]
    Validation(String),
    /// Could not launch the system browser.
    #[error("could not open the system browser: {0}")]
    Browser(String),
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, AuthError>;
