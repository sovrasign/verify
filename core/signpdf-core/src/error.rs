use thiserror::Error;

/// Errors produced by the SignPDF engine.
#[derive(Debug, Error)]
pub enum SignPdfError {
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("invalid container: {0}")]
    Container(String),

    #[error("workflow error: {0}")]
    Workflow(String),

    #[error("verification failed: {0}")]
    Verification(String),

    #[error("PAdES error: {0}")]
    Pades(String),

    #[error("timestamp error: {0}")]
    Timestamp(String),

    #[error("oidc error: {0}")]
    Oidc(String),

    #[error("keystore error: {0}")]
    Keystore(String),

    /// The document, or the documents of an envelope together, are larger than an envelope may
    /// be ([`crate::documents::MAX_ENVELOPE_BYTES`]). Nothing was prepared or combined.
    #[error("too large: {0}")]
    TooLarge(String),

    /// The document's envelope was written by a newer build, with a schema version this build
    /// does not understand. Nothing was signed; verification cannot judge the document either.
    /// Hosts should tell the user to update the app (or reload the page).
    #[error(
        "unsupported version: this document uses envelope schema version {found}, but this \
         build understands versions up to {newest}; update the app or reload the page"
    )]
    UnsupportedSchemaVersion { found: u64, newest: u32 },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl SignPdfError {
    /// A stable code for the kind of error, in `snake_case` (a code of
    /// [`crate::messages::CODES`], of severity `refusal`), which hosts translate. The message
    /// ([`std::fmt::Display`]) stays in English and gives the detail.
    pub fn code(&self) -> &'static str {
        use crate::messages as m;
        let c = match self {
            SignPdfError::Workflow(_) => m::ERR_WORKFLOW,
            SignPdfError::Verification(_) => m::ERR_VERIFICATION,
            SignPdfError::Oidc(_) => m::ERR_IDENTITY,
            SignPdfError::Pades(_)
            | SignPdfError::Container(_)
            | SignPdfError::Encoding(_)
            | SignPdfError::Serde(_) => m::ERR_DOCUMENT,
            SignPdfError::Timestamp(_) => m::ERR_TIMESTAMP,
            SignPdfError::Crypto(_) => m::ERR_CRYPTO,
            SignPdfError::Keystore(_) => m::ERR_KEYSTORE,
            SignPdfError::TooLarge(_) => m::ERR_TOO_LARGE,
            SignPdfError::UnsupportedSchemaVersion { .. } => m::ERR_UNSUPPORTED_VERSION,
            SignPdfError::Io(_) => m::ERR_IO,
        };
        c.code
    }
}

pub type Result<T> = std::result::Result<T, SignPdfError>;
