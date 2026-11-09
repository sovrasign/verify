//! Stable codes for what the engine says: every verification finding (an error that makes a
//! document invalid, or a warning), every engine error and every refused field value.
//!
//! The engine writes its messages in English. Hosts show them in the reader's language by their
//! **code**, which never changes once released: a client keeps one translated sentence per code
//! ([`CODES`] lists them all, with the English sentence a client falls back to) and may show the
//! English detail beside it. A verification report carries one [`Finding`] per message and
//! warning ([`crate::workflow::VerificationReport::findings`]), with the slot and revision it is
//! about; an engine error has [`crate::SignPdfError::code`]; a refused field value has
//! [`crate::FormatError::code`].
//!
//! Rules: a code is `snake_case` ASCII; it is never renamed or reused for another meaning; a new
//! kind of finding gets a new code (clients without a translation for it fall back to `en`).
//! `tests` below check that the catalogue has no duplicates and covers every error variant and
//! format error.

use serde::{Deserialize, Serialize};

/// What a code is about.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// A verification finding that makes the document invalid (or its identities not trusted).
    Error,
    /// A verification finding that does not change the verdict.
    Warning,
    /// An engine error: the operation (prepare, sign, verify...) was refused or failed.
    Refusal,
    /// A field value the engine refuses ([`crate::FormatError`]).
    Value,
}

/// One entry of the catalogue: a stable code, what it is about, and the English sentence a client
/// shows when it has no translation for the code.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct MessageCode {
    pub code: &'static str,
    pub severity: Severity,
    pub en: &'static str,
}

/// One verification finding: the stable code, and the English text the report's `messages` or
/// `warnings` holds for it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    /// A code of [`CODES`].
    pub code: String,
    /// `error` (listed in the report's `messages`) or `warning` (in its `warnings`).
    pub severity: Severity,
    /// The signer slot it is about, when it is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// The signed revision it is about (0 is the preparer's), when it is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u32>,
    /// The English text, exactly as the report's `messages` or `warnings` has it.
    pub text: String,
}

impl Finding {
    /// A finding with `code` (its severity comes from the catalogue entry) and `text`.
    pub fn new(code: &MessageCode, text: impl Into<String>) -> Finding {
        Finding {
            code: code.code.to_string(),
            severity: code.severity,
            signer: None,
            revision: None,
            text: text.into(),
        }
    }

    /// About signer slot `id`.
    pub fn signer(mut self, id: impl Into<String>) -> Finding {
        self.signer = Some(id.into());
        self
    }

    /// About signed revision `index`.
    pub fn revision(mut self, index: u32) -> Finding {
        self.revision = Some(index);
        self
    }

    /// The same finding with `prefix` before its text (`signer 's1': ...`).
    pub(crate) fn prefixed(mut self, prefix: &str) -> Finding {
        self.text = format!("{prefix}{}", self.text);
        self
    }
}

/// The catalogue entry of `code`, if it is one.
pub fn lookup(code: &str) -> Option<&'static MessageCode> {
    CODES.iter().copied().find(|c| c.code == code)
}

macro_rules! catalogue {
    ($( $(#[$doc:meta])* $name:ident = ($code:literal, $severity:ident, $en:literal); )*) => {
        $( $(#[$doc])* pub const $name: &MessageCode =
            &MessageCode { code: $code, severity: Severity::$severity, en: $en }; )*
        /// Every code, in a stable order.
        pub const CODES: &[&MessageCode] = &[$($name),*];
    };
}

catalogue! {
    // ---- Verification: the document as a whole ------------------------------------------------
    NO_SIGNATURES = ("no_signatures", Error,
        "The document carries no signatures: it was never prepared for signing.");
    SIGNATURE_MALFORMED = ("signature_malformed", Error,
        "A signature in the document is malformed.");
    DOCUMENT_CHANGED = ("document_changed", Error,
        "The document was changed after it was signed.");
    SIGNATURE_INVALID = ("signature_invalid", Error,
        "A signature does not match the document.");
    SIGNATURE_ALTERED = ("signature_altered", Error,
        "A signature's unsigned parts were altered.");
    DOCUMENT_TIMESTAMP_MALFORMED = ("document_timestamp_malformed", Error,
        "A document timestamp is malformed.");
    DOCUMENT_TIMESTAMP_CHANGED = ("document_timestamp_changed", Error,
        "The document was changed after a document timestamp was added.");
    DOCUMENT_TIMESTAMP_INVALID = ("document_timestamp_invalid", Error,
        "A document timestamp is not valid.");
    REVISIONS_OVERLAP = ("revisions_overlap", Error,
        "Two signatures cover the same version of the document.");
    TIMESTAMP_BEFORE_PREPARER = ("timestamp_before_preparer", Error,
        "A document timestamp comes before the preparer's signature.");
    UNSIGNED_CHANGES = ("unsigned_changes", Error,
        "Changes were added after the last signature.");
    ENVELOPE_UNREADABLE = ("envelope_unreadable", Error,
        "A version of the document has no readable signing record.");
    AUDIT_LOG_BROKEN = ("audit_log_broken", Error,
        "The document's audit log is broken.");
    SIGNATURE_RECORD_INCONSISTENT = ("signature_record_inconsistent", Error,
        "A signer's record does not match their signature.");
    SIGNATURE_COUNT_MISMATCH = ("signature_count_mismatch", Error,
        "The number of signatures does not match the signing record.");
    IDENTITIES_NOT_TRUSTED = ("identities_not_trusted", Error,
        "The document is intact, but one or more identities are not trusted by this verifier.");
    TRUSTED_TIME_PENDING = ("trusted_time_pending", Error,
        "The document is intact; one or more identities count only once a trusted timestamp covers their signature.");

    // ---- Verification: the preparer's revision ------------------------------------------------
    PREPARER_REVISION_INVALID = ("preparer_revision_invalid", Error,
        "The preparer's version of the document is not valid.");
    PREPARER_IDENTITY_FAILED = ("preparer_identity_failed", Error,
        "The preparer's identity could not be verified.");
    DOCUMENT_ID_STAMP_MISMATCH = ("document_id_stamp_mismatch", Error,
        "The document ID stamp is not the one the engine draws.");

    // ---- Verification: a signer's revision -----------------------------------------------------
    TERMS_CHANGED = ("terms_changed", Error,
        "The prepared terms (title, documents, signers, fields or policy) were changed.");
    SIGNED_AFTER_DECLINE = ("signed_after_decline", Error,
        "A signature was added after the envelope was declined.");
    RECORD_MISMATCH = ("record_mismatch", Error,
        "A signer's record was rewritten or does not belong to their signature.");
    SLOT_TAMPERED = ("slot_tampered", Error,
        "A signer's slot was changed by someone else, or filled twice.");
    OUT_OF_ORDER = ("out_of_order", Error,
        "A signer signed before their turn.");
    FIELD_TAMPERED = ("field_tampered", Error,
        "A field was filled or changed by someone who may not.");
    FIELD_VALUE_INVALID = ("field_value_invalid", Error,
        "A field holds a value its rules do not allow.");
    FORMULA_MISMATCH = ("formula_mismatch", Error,
        "A formula field does not hold what its formula computes.");
    RECORD_MALFORMED = ("record_malformed", Error,
        "A signer's record holds evidence in the wrong form.");
    AUDIT_LOG_REWRITTEN = ("audit_log_rewritten", Error,
        "The audit log was rewritten, or does not record the signer's action.");
    UNSIGNED_INSERTION = ("unsigned_insertion", Error,
        "Unsigned changes were inserted before a signature.");
    REVISION_DIGEST_MISMATCH = ("revision_digest_mismatch", Error,
        "A signer's record names another version of the document.");
    SIGNER_NOT_RECORDED = ("signer_not_recorded", Error,
        "A signature has no record in the signing envelope.");
    FORBIDDEN_CHANGE = ("forbidden_change", Error,
        "A version of the document changed something it may not change.");
    UNEXPECTED_ANNOTATION = ("unexpected_annotation", Error,
        "A version of the document added something to a page that it may not.");
    AUDIT_FAILED = ("audit_failed", Error,
        "A version of the document could not be checked.");
    SIGNATURE_BOX_MISMATCH = ("signature_box_mismatch", Error,
        "A signature box does not show what the engine draws for the verified signer.");
    DRAWING_MISMATCH = ("drawing_mismatch", Error,
        "A drawn or typed signature does not match the signer's record.");
    STAMP_MISMATCH = ("stamp_mismatch", Error,
        "A signature or initials stamp does not match the verified signer.");
    IDENTITY_FAILED = ("identity_failed", Error,
        "A signer's identity could not be verified.");
    SIGNING_TIME_UNREADABLE = ("signing_time_unreadable", Error,
        "A signing time cannot be read.");
    SIGNED_AFTER_EXPIRY = ("signed_after_expiry", Error,
        "A signature was made after the envelope expired.");
    ALGORITHM_REFUSED = ("algorithm_refused", Error,
        "A signature relies on an algorithm that is no longer accepted.");

    // ---- Verification: identities not trusted (one code per trust result) --------------------
    IDENTITY_UNKNOWN_ISSUER = ("identity_unknown_issuer", Error,
        "The identity provider that vouched for this person is not trusted by this verifier.");
    IDENTITY_UNKNOWN_KEY = ("identity_unknown_key", Error,
        "The identity provider's key is not one this verifier knows.");
    IDENTITY_UNTRUSTED_AUDIENCE = ("identity_untrusted_audience", Error,
        "The sign-in was made for an application this verifier does not trust.");
    IDENTITY_NO_TRUSTED_TIME = ("identity_no_trusted_time", Error,
        "This identity counts only once a trusted timestamp covers the signature.");
    IDENTITY_OUTSIDE_KEY_WINDOW = ("identity_outside_key_window", Error,
        "The identity provider's key was not valid when the signature was made.");
    IDENTITY_DISTRUSTED_KEY = ("identity_distrusted_key", Error,
        "The identity provider's key is no longer trusted.");
    IDENTITY_ALGORITHM_NOT_ACCEPTED = ("identity_algorithm_not_accepted", Error,
        "The sign-in relies on an algorithm that is no longer accepted.");
    IDENTITY_INSUFFICIENT_LEVEL = ("identity_insufficient_level", Error,
        "The identity does not meet the level the signer's slot requires.");
    IDENTITY_NOT_TRUSTED = ("identity_not_trusted", Error,
        "An identity is not trusted by this verifier.");

    // ---- Verification: warnings ---------------------------------------------------------------
    ALGORITHM_ACCEPTED_BY_TIMESTAMP = ("algorithm_accepted_by_timestamp", Warning,
        "An algorithm is accepted only because a trusted timestamp shows it was used in time.");
    SERVICE_LINK_UNUSABLE = ("service_link_unusable", Warning,
        "The link back to the sending service is not usable and is not shown.");
    SERVICE_LINK_CHANGED = ("service_link_changed", Warning,
        "A signer changed the link back to the sending service; the change is ignored.");
    TIMESTAMP_MISSING = ("timestamp_missing", Warning,
        "A signature has no timestamp although the envelope requires one: its time is the signer's device clock.");
    TIMESTAMP_UNEXPECTED = ("timestamp_unexpected", Warning,
        "A signature carries a timestamp although the envelope takes none.");
    TSA_CERTIFICATE_REVOKED_LATER = ("tsa_certificate_revoked_later", Warning,
        "A time-stamp authority's certificate was revoked after the timestamp; the timestamp still holds.");
    SLOT_POLICY_WEAK = ("slot_policy_weak", Warning,
        "A signer's slot accepts identities that are easy to obtain.");
    INSECURE_DEV_TRUST = ("insecure_dev_trust", Warning,
        "This verification trusts a test identity provider: never use this setting for real documents.");
    CONSENT_AFTER_SIGNATURE = ("consent_after_signature", Warning,
        "A signer's consent to electronic records is dated after their signature.");
    TIMESTAMP_ALGORITHM = ("timestamp_algorithm", Warning,
        "A timestamp relies on an algorithm the algorithm policy limits.");
    TSA_DISTRUSTED = ("tsa_distrusted", Warning,
        "A timestamp comes from a time-stamp authority the trust list distrusts from that time: it is not used as trusted time.");

    // ---- Engine errors (crate::SignPdfError::code) ---------------------------------------------
    ERR_WORKFLOW = ("workflow", Refusal,
        "The document's signing rules refuse this request.");
    ERR_VERIFICATION = ("verification", Refusal,
        "The document failed verification.");
    ERR_IDENTITY = ("identity", Refusal,
        "The sign-in was not accepted.");
    ERR_DOCUMENT = ("document", Refusal,
        "The PDF, or the signing record in it, could not be read or written.");
    ERR_TIMESTAMP = ("timestamp", Refusal,
        "A timestamp could not be obtained or checked.");
    ERR_CRYPTO = ("crypto", Refusal,
        "A cryptographic operation failed.");
    ERR_KEYSTORE = ("keystore", Refusal,
        "The key store could not be used.");
    ERR_TOO_LARGE = ("too_large", Refusal,
        "The documents are larger than an envelope may be (50 MB).");
    ERR_UNSUPPORTED_VERSION = ("unsupported_version", Refusal,
        "This document was made by a newer version: update the app or reload the page.");
    ERR_IO = ("io", Refusal,
        "A file could not be read or written.");

    // ---- Field values (crate::FormatError::code) -----------------------------------------------
    VALUE_INVALID_EMAIL = ("invalid_email", Value, "Enter an email address.");
    VALUE_INVALID_PHONE = ("invalid_phone", Value, "Enter a phone number in international form.");
    VALUE_INVALID_NUMBER = ("invalid_number", Value, "Enter a number.");
    VALUE_TOO_MANY_DECIMALS = ("too_many_decimals", Value, "Too many decimal places.");
    VALUE_BELOW_MINIMUM = ("below_minimum", Value, "The number is below the minimum.");
    VALUE_ABOVE_MAXIMUM = ("above_maximum", Value, "The number is above the maximum.");
    VALUE_NEGATIVE_AMOUNT = ("negative_amount", Value, "The amount cannot be negative.");
    VALUE_INVALID_POSTAL_CODE = ("invalid_postal_code", Value, "Enter a postal code.");
    VALUE_UNSUPPORTED_COUNTRY = ("unsupported_country", Value, "This country's postal codes cannot be checked.");
    VALUE_INVALID_IBAN = ("invalid_iban", Value, "Enter an IBAN.");
    VALUE_IBAN_CHECKSUM = ("iban_checksum", Value, "The IBAN's check digits are wrong: check for a typo.");
    VALUE_INVALID_US_SSN = ("invalid_us_ssn", Value, "Enter a Social Security number.");
    VALUE_INVALID_US_EIN = ("invalid_us_ein", Value, "Enter an Employer Identification Number.");
    VALUE_TOO_SHORT = ("too_short", Value, "Too short.");
    VALUE_TOO_LONG = ("too_long", Value, "Too long.");
    VALUE_PATTERN_MISMATCH = ("pattern_mismatch", Value, "This value does not have the expected form.");

    // ---- Formula fields (crate::formula::FormulaFieldError::code) -----------------------------
    // Computing a formula from the signer's values (the live display, signing, the verifier).
    VALUE_DIVISION_BY_ZERO = ("division_by_zero", Value,
        "This total cannot be computed: it divides by zero.");
    VALUE_NUMBER_TOO_LARGE = ("number_too_large", Value,
        "This total cannot be computed: a number is too large.");
    // The formula itself, refused when the document is prepared.
    FORMULA_SYNTAX = ("formula_syntax", Refusal, "The formula cannot be read.");
    FORMULA_TOO_LONG = ("formula_too_long", Refusal, "The formula is too long.");
    FORMULA_TOO_DEEP = ("formula_too_deep", Refusal, "The formula is nested too deeply.");
    FORMULA_UNKNOWN_FUNCTION = ("formula_unknown_function", Refusal,
        "The formula uses a function that does not exist.");
    FORMULA_ARGUMENTS = ("formula_arguments", Refusal,
        "A function in the formula has the wrong arguments.");
    FORMULA_TYPE = ("formula_type", Refusal,
        "The formula mixes up numbers and conditions.");
    FORMULA_UNKNOWN_FIELD = ("formula_unknown_field", Refusal,
        "The formula reads a field that does not exist.");
    FORMULA_LOOP = ("formula_loop", Refusal, "Formulas read each other in a loop.");
    FORMULA_INPUT_TYPE = ("formula_input_type", Refusal,
        "The formula reads a field that holds no number.");
    FORMULA_LATER_INPUT = ("formula_later_input", Refusal,
        "The formula reads a field that a later signer fills.");
    FORMULA_MAP = ("formula_map", Refusal,
        "An option the formula reads has no number.");
}

/// The code for an identity that is not trusted, by its trust result
/// ([`crate::IdentityTrust::as_str`]).
pub fn identity_code(trust: &str) -> &'static MessageCode {
    match trust {
        "unknown-issuer" => IDENTITY_UNKNOWN_ISSUER,
        "unknown-key" => IDENTITY_UNKNOWN_KEY,
        "untrusted-audience" => IDENTITY_UNTRUSTED_AUDIENCE,
        "no-trusted-time" => IDENTITY_NO_TRUSTED_TIME,
        "outside-key-window" => IDENTITY_OUTSIDE_KEY_WINDOW,
        "distrusted-key" => IDENTITY_DISTRUSTED_KEY,
        "algorithm-not-accepted" => IDENTITY_ALGORITHM_NOT_ACCEPTED,
        "insufficient-level" => IDENTITY_INSUFFICIENT_LEVEL,
        _ => IDENTITY_NOT_TRUSTED,
    }
}

/// The catalogue as JSON (`[{code, severity, en}, ...]`), for hosts that check their
/// translations cover it.
pub fn catalogue_json() -> String {
    serde_json::to_string(CODES).unwrap_or_else(|_| "[]".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FormatError, SignPdfError};

    #[test]
    fn codes_are_unique_snake_case_with_a_sentence() {
        for (i, c) in CODES.iter().enumerate() {
            assert!(
                !c.code.is_empty()
                    && c.code
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{}",
                c.code
            );
            assert!(c.en.ends_with('.'), "{}", c.code);
            assert!(
                CODES[..i].iter().all(|o| o.code != c.code),
                "{} twice",
                c.code
            );
            assert_eq!(lookup(c.code), Some(*c));
        }
    }

    #[test]
    fn every_engine_error_and_format_error_is_catalogued() {
        let errors = [
            SignPdfError::Crypto(String::new()),
            SignPdfError::Encoding(String::new()),
            SignPdfError::Container(String::new()),
            SignPdfError::Workflow(String::new()),
            SignPdfError::Verification(String::new()),
            SignPdfError::Pades(String::new()),
            SignPdfError::Timestamp(String::new()),
            SignPdfError::Oidc(String::new()),
            SignPdfError::Keystore(String::new()),
            SignPdfError::TooLarge(String::new()),
            SignPdfError::UnsupportedSchemaVersion {
                found: 9,
                newest: 7,
            },
            SignPdfError::Io(std::io::Error::other("x")),
            SignPdfError::Serde(serde_json::from_str::<u8>("x").unwrap_err()),
        ];
        for e in errors {
            let c = lookup(e.code()).unwrap_or_else(|| panic!("{} is not catalogued", e.code()));
            assert_eq!(c.severity, Severity::Refusal);
        }
        for f in [
            FormatError::Email,
            FormatError::Phone,
            FormatError::Number,
            FormatError::TooManyDecimals,
            FormatError::BelowMinimum,
            FormatError::AboveMaximum,
            FormatError::NegativeAmount,
            FormatError::PostalCode,
            FormatError::UnsupportedCountry,
            FormatError::Iban,
            FormatError::IbanChecksum,
            FormatError::UsSsn,
            FormatError::UsEin,
            FormatError::TooShort,
            FormatError::TooLong,
            FormatError::Pattern,
        ] {
            let c = lookup(f.code()).unwrap_or_else(|| panic!("{} is not catalogued", f.code()));
            assert_eq!(c.severity, Severity::Value);
        }
        for t in crate::IdentityTrust::ALL {
            if !t.is_acceptable() {
                assert_ne!(identity_code(t.as_str()), IDENTITY_NOT_TRUSTED, "{t:?}");
            }
        }
    }

    #[test]
    fn the_catalogue_serializes() {
        let json: serde_json::Value = serde_json::from_str(&catalogue_json()).unwrap();
        assert_eq!(json.as_array().unwrap().len(), CODES.len());
        assert_eq!(json[0]["code"], "no_signatures");
        assert_eq!(json[0]["severity"], "error");
    }
}
