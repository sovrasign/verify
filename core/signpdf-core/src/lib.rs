//! SignPDF core engine.
//!
//! A serverless, "the document is the database" signing engine. Everything needed to
//! drive a signing workflow — signers, fields, policy, cryptographic signatures and a
//! hash-chained audit log — is carried inside the file itself, so it is fully
//! self-describing as it moves between people with no central server.
//!
//! ## Scope
//! - PAdES baseline digital signatures (`ETSI.CAdES.detached`, P-256 ECDSA), B-B, plus B-T
//!   when the host supplies an RFC 3161 [`pades::Timestamper`]; document timestamps and
//!   validation data (DSS) after a signature for B-LT and B-LTA ([`ltv`]).
//! - **Federated identity**: every participant proves who they are with an OIDC provider; the
//!   ID token is stapled to an ephemeral signing key and the document via the `nonce`
//!   ([`oidc`]). Verifiers anchor identities in a [`trust::TrustStore`] of pinned issuer keys.
//! - **Several documents per envelope**: they are combined into the one PDF everyone signs, with a
//!   documents index in the prepared terms ([`documents`]); 50 MB per envelope.
//! - **Signatures drawn or typed** in the signer's box beside the verified identity: pen strokes,
//!   or the glyph outlines of a typed name as filled paths, never text or an embedded font
//!   ([`ink`]).
//! - **Exact decimals** for number and payment fields: decimal arithmetic with no floating point,
//!   rounded half up, so every device and the verifier compute the same value ([`decimal`]), and
//!   amounts in ISO 4217 minor units ([`currency`]). Validation formats for field values (email,
//!   phone, number, amount, postal code, IBAN, masked identifiers) in [`formats`], and formula
//!   fields' language, evaluated with those decimals, in [`formula`].
//! - **Intake** on the device: images (JPEG, and TIFF with every page) as one PDF, and an open
//!   password removed with the password the person types, so neither an image nor a password
//!   reaches a server ([`intake`]).
//! - **Stable message codes** for every verification finding and engine error, so that hosts
//!   show them in the reader's language ([`messages`]).
//! - Integrity only (no encryption).
//!
//! ## Verification model
//! The preparer signs the prepared document; every signer (and decliner) appends one signed
//! incremental revision. [`workflow::verify`] requires the last signature to cover the whole
//! file and replays each revision against its predecessor — the envelope's prepared terms must
//! be unchanged, exactly one slot may advance, only that signer's fields may be filled, the
//! audit log must be append-only, and the PDF objects may change only within a narrow
//! allow-list ([`pades::audit_increment`]). See `docs/SECURITY_MODEL.md`.
//!
//! The legacy [`container`] append-log remains only for its sample-PDF helper.

pub mod algorithms;
pub mod certificate;
pub mod container;
pub mod crypto;
pub mod currency;
pub mod dates;
pub mod decimal;
pub mod digest;
pub mod documents;
pub mod error;
pub mod formats;
pub mod formula;
pub mod increment;
pub mod initials;
pub mod ink;
pub mod intake;
pub mod keystore;
pub mod ltv;
pub mod messages;
pub mod model;
pub mod numbers;
pub mod oidc;
pub mod pades;
pub mod pattern;
pub mod schema;
pub mod timestamp;
pub mod trust;
pub mod trust_list;
pub mod workflow;
pub(crate) mod xref;

/// The cross-reference reader under fuzzing (the `xref` target of `core/fuzz`). Not an API.
#[doc(hidden)]
pub fn fuzz_xref(data: &[u8]) {
    xref::fuzz(data);
}

#[cfg(windows)]
pub mod dpapi;

pub use error::{Result, SignPdfError};
pub use keystore::{FileKeyStore, Identity, KeyStore};

pub use algorithms::{Algorithm, AlgorithmPolicy, AlgorithmPolicyStatus, AlgorithmRule};
pub use certificate::completion_certificate;
pub use currency::{Currency, PaymentDue, DEFAULT_MAX_PAYMENT_MAJOR_UNITS};
pub use dates::DateFormat;
pub use decimal::{Decimal, DecimalError};
pub use digest::DocumentDigests;
#[cfg(windows)]
pub use dpapi::DpapiKeyStore;
pub use formats::{
    check_length, FieldCheck, Format, FormatError, LengthRule, ValueFormat, ValueFormatKind,
};
pub use formula::{
    check_formula_fields, compute_formula_fields, Formula, FormulaError, FormulaFieldError,
    FormulaSpec,
};
pub use increment::{check_increment, increment_after, Head};
pub use messages::{Finding, MessageCode, Severity};
pub use numbers::{NumberFormat, NumberStyle, MAX_NUMBER_DECIMALS};
pub use pattern::{Pattern, PatternError};
// A signer's drawing: pen strokes or a typed signature's filled paths, and (feature `typed`) the
// glyph outlines of a typed name.
#[cfg(feature = "typed")]
pub use ink::typed::typed_signature;
pub use ink::{InkPaths, PathSegment, SignatureDrawing};
// Several documents in one envelope: combine them into the PDF to prepare, and cut a
// convenience copy of one out of the envelope.
pub use documents::{
    combine as combine_documents, convenience_copy_name, extract as extract_document, Combined,
    SourceDocument, MAX_DOCUMENTS, MAX_ENVELOPE_BYTES,
};
pub use model::{
    AuditAction, AuditEntry, Envelope, EnvelopeDocument, EsignConsent, Field, FieldRules,
    FieldType, Policy, RecordKind, Rect, SignatureRecord, Signer, SignerStatus, SigningOrder,
    TimestampPolicy,
};
pub use oidc::{
    compute_nonce, peek_issuer, verify_id_token, Assessment, Basis, IdentityPolicy, IssuerKind,
    Jwk, Jwks, Level, Method, Validation, VerifiedIdentity,
};
pub use pades::{
    appended, audit_increment, pades_sign, pades_sign_increment, pades_sign_with, pades_verify,
    pades_verify_all, pades_verify_all_with, stamp_document_id, AddedAnnotation, AddedAppearance,
    DocumentTimestampValidation, Dss, EmbeddedFile, FieldMark, FieldText, InkStrokes, PadesScan,
    PadesValidation, SignAppearance, SignOptions, SignatureCaption, Timestamper,
};
pub use timestamp::{TimestampInfo, TimestampToken};
pub use trust::{
    IdentityCheck, IdentityTrust, KeyWindow, PinnedKey, PublishedJwks, SigningTimeEvidence,
    TrustStore, TrustedIssuer, TsaDistrust, SIGNPDF_GOOGLE_CLIENT_ID, SIGNPDF_MICROSOFT_CLIENT_ID,
};
// The signature-timestamp steps of the workflow, which apply the envelope's timestamp policy
// (`pades::signature_timestamp_digest` and `pades::embed_signature_timestamp` do not), and the
// document-timestamp and validation-data steps, which check the document first (the `pades::`
// versions do not).
//
// Signing has whole-document and increment-only forms: `sign_increment` and
// `sign_for_timestamp_increment` return only the bytes the signature appends, and the
// `*_increment_*` timestamp steps take the document and that increment apart.
pub use workflow::{
    add_document_timestamp, add_validation_data, embed_document_timestamp,
    embed_increment_signature_timestamp, embed_signature_timestamp,
    increment_signature_timestamp_digest, prepare, prepare_document_timestamp, read_envelope,
    revocation_targets, sign, sign_for_timestamp, sign_for_timestamp_increment, sign_increment,
    sign_with, signature_timestamp_digest, verify, verify_at, DocumentTimestampStatus,
    ExistedBefore, PrepareRequest, RevocationTarget, SignRequest, SignatureStatus, TimestampStatus,
    ValidationDataSummary, VerificationReport,
};

/// Current envelope schema version. v2 replaced trust-on-first-use with federated (OIDC)
/// identity; v3 adds the preparer signature, signed declines, `source_len`, and revision-chain
/// verification; v4 replaces a slot's two-value `min_assurance` with an assurance level
/// (`min_level`, L1–L5) and `required_methods`; v5 adds the optional `documents` index of an
/// envelope that combines several documents; v6 keeps the signer's drawing (pen strokes or a typed
/// signature's filled paths) in their signature record, and the verifier redraws it; v7 adds number
/// fields with a sealed number format and the 'verify at' address drawn on the document-ID stamp;
/// v8 adds validation formats, length rules and owner messages on text fields and a currency on
/// number formats; v9 names the rule that derives the initials stamped in a signer's further
/// initials fields (`initials_rule`, [`initials`]): from the slot's name, no longer the email.
/// See [`schema`] for the versions this build reads.
pub const SCHEMA_VERSION: u32 = 9;

/// Register the clock the engine reads on `wasm32-unknown-unknown`, which has none of its own
/// (`std::time::SystemTime::now` traps there). The browser signer registers the page's
/// `Date.now()`; the verifier registers nothing (it reads the clock only for the algorithm
/// policy's end dates, and works without one: the page passes its time to `verify_at`). It is
/// the device clock either way, exactly as on native builds: trusted time comes only from RFC
/// 3161 timestamps. The first registration wins; reading the clock before one is registered panics
/// rather than dating a signature 1970.
#[cfg(target_arch = "wasm32")]
pub fn set_wasm_clock(now_unix: fn() -> i64) {
    let _ = util::WASM_CLOCK.set(now_unix);
}

pub(crate) mod util {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    #[cfg(target_arch = "wasm32")]
    pub(crate) static WASM_CLOCK: std::sync::OnceLock<fn() -> i64> = std::sync::OnceLock::new();

    /// Current UTC time from the device clock (on wasm32, the clock the host registered with
    /// [`crate::set_wasm_clock`]).
    fn now_utc() -> OffsetDateTime {
        #[cfg(target_arch = "wasm32")]
        {
            let now = WASM_CLOCK
                .get()
                .expect("no clock registered: call set_wasm_clock")();
            OffsetDateTime::from_unix_timestamp(now).unwrap_or(OffsetDateTime::UNIX_EPOCH)
        }
        #[cfg(not(target_arch = "wasm32"))]
        OffsetDateTime::now_utc()
    }

    /// Current UTC time as an RFC 3339 string (device clock).
    pub fn now_rfc3339() -> String {
        now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
    }

    /// Current UTC time as seconds since the Unix epoch (device clock).
    pub fn now_unix() -> i64 {
        now_utc().unix_timestamp()
    }

    /// The device clock, when there is one: always on native builds; on wasm32, only once the
    /// host registered one ([`crate::set_wasm_clock`]). For a verifier, which works without.
    pub fn try_now_unix() -> Option<i64> {
        #[cfg(target_arch = "wasm32")]
        {
            WASM_CLOCK.get().map(|now| now())
        }
        #[cfg(not(target_arch = "wasm32"))]
        Some(now_unix())
    }

    /// Parse an RFC 3339 timestamp into seconds since the Unix epoch.
    pub fn unix_from_rfc3339(s: &str) -> Option<i64> {
        OffsetDateTime::parse(s, &Rfc3339)
            .ok()
            .map(|t| t.unix_timestamp())
    }

    /// Seconds since the Unix epoch as an RFC 3339 UTC time (`2026-11-03T14:02:11Z`).
    pub fn rfc3339_from_unix(t: i64) -> String {
        OffsetDateTime::from_unix_timestamp(t)
            .ok()
            .and_then(|t| t.format(&Rfc3339).ok())
            .unwrap_or_else(|| t.to_string())
    }

    /// Current UTC time as a PDF date string, e.g. `D:20260623083000Z`.
    pub fn now_pdf_date() -> String {
        let t = now_utc();
        format!(
            "D:{:04}{:02}{:02}{:02}{:02}{:02}Z",
            t.year(),
            t.month() as u8,
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
        )
    }
}
