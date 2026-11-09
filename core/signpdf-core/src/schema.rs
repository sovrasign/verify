//! Envelope schema versions: which versions this build reads and signs, and how each is decoded
//! into the in-memory [`Envelope`] and encoded back.
//!
//! ## Experimental versions
//!
//! Every version up to and including 9 is **experimental**: no document written before the first
//! hosted release needs to verify later. Until that release, the current version may change in
//! place, [`OLDEST_SCHEMA_VERSION`] may rise, and the corpus fixtures of an experimental version
//! are replaced when its format changes. The first hosted release fixes its version as the first
//! stable one; from then on the rules below hold for good.
//!
//! ## The rules
//!
//! * **Every stable version from [`OLDEST_SCHEMA_VERSION`] to [`SCHEMA_VERSION`] verifies,
//!   forever.** A new version adds a decoder (and an encoder) here; it never removes a stable
//!   one. Each version keeps its own replay rules: anything that decides whether a version-`n`
//!   document is valid (what the signatures and audit entries are computed over, what a revision
//!   may draw) must keep working for version `n` after a newer version changes it.
//! * **Any change to a stable version's shape or rules is a new version.**
//! * **An envelope keeps the version it was prepared with for its whole life.** Signing and
//!   declining write the envelope back in that same version, so a document prepared by an older
//!   build can still be finished by a newer one. A revision that changes the version fails
//!   verification (the version is part of the preparer's pinned terms).
//! * **A build never signs an envelope newer than it understands**, because writing it back
//!   could silently drop terms it does not know. Prepare, sign and decline refuse it with
//!   [`SignPdfError::UnsupportedSchemaVersion`], and so does verification: the build cannot tell
//!   whether such a document is valid, which is not the same as knowing that it is invalid. Hosts
//!   map that error to "update the app" or "reload the page".
//! * Versions below [`OLDEST_SCHEMA_VERSION`] ([`RETIRED_SCHEMA_VERSIONS`]) were experimental
//!   development formats and are refused.
//!
//! The compatibility corpus in `tests/corpus/v<N>/` holds documents signed by the build that
//! wrote each version; `tests/schema_versions.rs` verifies all of them on every test run.
//! See `docs/SECURITY_MODEL.md` §8 for the procedure to add a version.

use serde::Deserialize;

use crate::error::{Result, SignPdfError};
use crate::model::Envelope;
use crate::SCHEMA_VERSION;

/// The oldest envelope schema version this build verifies and signs.
pub const OLDEST_SCHEMA_VERSION: u32 = 3;

/// Experimental formats of June 2026 development builds: v1 used trust on first use, v2 federated
/// identity without a preparer signature. Never accepted.
pub const RETIRED_SCHEMA_VERSIONS: &[u32] = &[1, 2];

const _: () = assert!(OLDEST_SCHEMA_VERSION <= SCHEMA_VERSION);

/// How this build treats a document's envelope schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSupport {
    /// Between [`OLDEST_SCHEMA_VERSION`] and [`SCHEMA_VERSION`]: verified and signed.
    Supported,
    /// Newer than [`SCHEMA_VERSION`]: written by a newer build. Neither verified nor signed here.
    Newer,
    /// Older than [`OLDEST_SCHEMA_VERSION`] (or 0): a retired development format.
    Retired,
}

/// How this build treats envelope schema version `version`.
pub fn support(version: u64) -> VersionSupport {
    if version > u64::from(SCHEMA_VERSION) {
        VersionSupport::Newer
    } else if version < u64::from(OLDEST_SCHEMA_VERSION) {
        VersionSupport::Retired
    } else {
        VersionSupport::Supported
    }
}

/// Read only the `schema_version` of an embedded envelope, without interpreting anything else
/// (a newer version may have a different shape).
pub fn peek_version(bytes: &[u8]) -> Result<u64> {
    #[derive(Deserialize)]
    struct VersionOnly {
        #[serde(default)]
        schema_version: Option<u64>,
    }
    let peek: VersionOnly = serde_json::from_slice(bytes)
        .map_err(|e| SignPdfError::Workflow(format!("embedded envelope is not valid JSON: {e}")))?;
    peek.schema_version.ok_or_else(|| {
        SignPdfError::Workflow(
            "embedded envelope has no schema_version (a non-negative integer)".into(),
        )
    })
}

/// The error for a version newer than this build understands.
pub fn newer_version_error(found: u64) -> SignPdfError {
    SignPdfError::UnsupportedSchemaVersion {
        found,
        newest: SCHEMA_VERSION,
    }
}

/// Decode an embedded envelope of any supported version into the in-memory model.
///
/// Refuses a newer version with [`SignPdfError::UnsupportedSchemaVersion`] and a retired one with
/// a workflow error, before looking at anything but the version number.
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope> {
    let version = peek_version(bytes)?;
    match support(version) {
        VersionSupport::Newer => Err(newer_version_error(version)),
        VersionSupport::Retired => Err(SignPdfError::Workflow(format!(
            "envelope schema version {version} was written by an unreleased development build \
             and is not supported (this build reads versions {OLDEST_SCHEMA_VERSION} to \
             {SCHEMA_VERSION}); re-prepare the source document."
        ))),
        VersionSupport::Supported => match version {
            3 => v3::decode(bytes),
            4 => v4::decode(bytes),
            5 => v5::decode(bytes),
            6 => v6::decode(bytes),
            7 => v7::decode(bytes),
            8 => v8::decode(bytes),
            9 => v9::decode(bytes),
            // `support` and this table must list the same versions.
            v => Err(SignPdfError::Workflow(format!(
                "internal error: no decoder for supported envelope schema version {v}"
            ))),
        },
    }
}

/// Encode `env` in its own schema version (see the module rule: an envelope keeps its version).
pub fn encode_envelope(env: &Envelope) -> Result<Vec<u8>> {
    match env.schema_version {
        3 => v3::encode(env),
        4 => v4::encode(env),
        5 => v5::encode(env),
        6 => v6::encode(env),
        7 => v7::encode(env),
        8 => v8::encode(env),
        9 => v9::encode(env),
        v if support(u64::from(v)) == VersionSupport::Newer => {
            Err(newer_version_error(u64::from(v)))
        }
        v => Err(SignPdfError::Workflow(format!(
            "this build cannot write envelope schema version {v}"
        ))),
    }
}

/// Version 3 (October 2026): federated identity, preparer signature, signed declines,
/// `source_len`, revision-chain verification; since late October, `policy.signature_timestamps`
/// (written only when not `optional`). Experimental. A slot's identity requirement is
/// `min_assurance`: `consumer` (every verified identity) or `enterprise` (an organization
/// identity). Version 4 replaced it with `min_level`; this module maps one to the other, both
/// ways and without loss: `consumer` is `L1` and `enterprise` `L3`
/// ([`crate::oidc::IdentityPolicy::from_min_assurance`]). An envelope with any other level, or
/// with `required_methods`, cannot be written as version 3 (none decodes from it).
mod v3 {
    use super::*;

    pub(super) fn decode(bytes: &[u8]) -> Result<Envelope> {
        let invalid = |e: String| {
            SignPdfError::Workflow(format!("embedded envelope is not a valid v3 envelope: {e}"))
        };
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
        refuse_documents(&value, 3)?;
        refuse_drawings(&value, 3)?;
        refuse_v7_terms(&value, 3)?;
        refuse_v8_terms(&value, 3)?;
        refuse_v9_terms(&value, 3)?;
        for policy in identity_policies(&value) {
            for key in ["min_level", "required_methods"] {
                if policy.get(key).is_some() {
                    return Err(invalid(format!(
                        "a slot's identity policy names '{key}', which version 3 does not have"
                    )));
                }
            }
            if policy.get("min_assurance").is_none() {
                return Err(invalid(
                    "a slot's identity policy has no min_assurance".into(),
                ));
            }
        }
        let env: Envelope = serde_json::from_value(value).map_err(|e| invalid(e.to_string()))?;
        debug_assert_eq!(env.schema_version, 3);
        Ok(env)
    }

    pub(super) fn encode(env: &Envelope) -> Result<Vec<u8>> {
        cannot_hold_documents(env, 3)?;
        cannot_hold_drawings(env, 3)?;
        cannot_hold_v7_terms(env, 3)?;
        cannot_hold_v8_terms(env, 3)?;
        cannot_hold_v9_terms(env, 3)?;
        let mut value = serde_json::to_value(env)?;
        let signers = value
            .get_mut("signers")
            .and_then(|s| s.as_array_mut())
            .map(|a| a.as_mut_slice())
            .unwrap_or_default();
        for (signer, slot) in signers.iter_mut().zip(&env.signers) {
            let assurance = slot.identity_policy.to_min_assurance().ok_or_else(|| {
                SignPdfError::Workflow(format!(
                    "slot '{}' requires {}{}, which a version-3 envelope cannot express",
                    slot.id,
                    slot.identity_policy.min_level,
                    if slot.identity_policy.required_methods.is_empty() {
                        ""
                    } else {
                        " with required methods"
                    }
                ))
            })?;
            if let Some(policy) = signer
                .get_mut("identity_policy")
                .and_then(|p| p.as_object_mut())
            {
                policy.remove("min_level");
                policy.remove("required_methods");
                policy.insert("min_assurance".into(), assurance.into());
            }
        }
        Ok(serde_json::to_vec(&value)?)
    }
}

/// Version 4 (October 2026): version 3 with assurance levels. A slot's identity requirement is
/// `min_level` (`L1` to `L5`, computed by the verifier from the evidence) plus
/// `required_methods` (written only when not empty), instead of `min_assurance`. Experimental.
/// It is version 6 without the `documents` index and the signers' drawings, so it decodes and
/// encodes directly, refusing both both ways.
mod v4 {
    use super::*;

    pub(super) fn decode(bytes: &[u8]) -> Result<Envelope> {
        let value = levels_json(bytes, 4)?;
        refuse_documents(&value, 4)?;
        refuse_drawings(&value, 4)?;
        refuse_v7_terms(&value, 4)?;
        refuse_v8_terms(&value, 4)?;
        refuse_v9_terms(&value, 4)?;
        let env: Envelope = serde_json::from_value(value).map_err(|e| invalid(4, e.to_string()))?;
        debug_assert_eq!(env.schema_version, 4);
        Ok(env)
    }

    pub(super) fn encode(env: &Envelope) -> Result<Vec<u8>> {
        cannot_hold_documents(env, 4)?;
        cannot_hold_drawings(env, 4)?;
        cannot_hold_v7_terms(env, 4)?;
        cannot_hold_v8_terms(env, 4)?;
        cannot_hold_v9_terms(env, 4)?;
        Ok(serde_json::to_vec(env)?)
    }
}

/// Version 5 (October 2026): version 4 with the optional `documents` index of an envelope that
/// combines several documents into one PDF ([`crate::model::EnvelopeDocument`]: name, first page,
/// page count and source digest of each), written only when not empty. Experimental. It is
/// version 6 without the signers' drawings, so it decodes and encodes directly, refusing them
/// both ways. Its signature boxes hold nothing or pen strokes the records do not keep
/// ([`crate::pades::InkRule::Strokes`]).
mod v5 {
    use super::*;

    pub(super) fn decode(bytes: &[u8]) -> Result<Envelope> {
        let value = levels_json(bytes, 5)?;
        refuse_drawings(&value, 5)?;
        refuse_v7_terms(&value, 5)?;
        refuse_v8_terms(&value, 5)?;
        refuse_v9_terms(&value, 5)?;
        let env: Envelope = serde_json::from_value(value).map_err(|e| invalid(5, e.to_string()))?;
        debug_assert_eq!(env.schema_version, 5);
        Ok(env)
    }

    pub(super) fn encode(env: &Envelope) -> Result<Vec<u8>> {
        cannot_hold_drawings(env, 5)?;
        cannot_hold_v7_terms(env, 5)?;
        cannot_hold_v8_terms(env, 5)?;
        cannot_hold_v9_terms(env, 5)?;
        Ok(serde_json::to_vec(env)?)
    }
}

/// Version 6 (October 2026): version 5 whose signature records keep the signer's drawing
/// (`drawing`: pen strokes, or a typed signature's filled paths, [`crate::ink::SignatureDrawing`]),
/// written only when there is one; the verifier redraws it and compares the signature box byte
/// for byte ([`crate::pades::InkRule::Recorded`]). Experimental. It is version 7 without number
/// fields and the 'verify at' address, so it decodes and encodes directly, refusing both both
/// ways.
mod v6 {
    use super::*;

    pub(super) fn decode(bytes: &[u8]) -> Result<Envelope> {
        let value = levels_json(bytes, 6)?;
        refuse_v7_terms(&value, 6)?;
        refuse_v8_terms(&value, 6)?;
        refuse_v9_terms(&value, 6)?;
        let env: Envelope = serde_json::from_value(value).map_err(|e| invalid(6, e.to_string()))?;
        debug_assert_eq!(env.schema_version, 6);
        Ok(env)
    }

    pub(super) fn encode(env: &Envelope) -> Result<Vec<u8>> {
        cannot_hold_v7_terms(env, 6)?;
        cannot_hold_v8_terms(env, 6)?;
        cannot_hold_v9_terms(env, 6)?;
        Ok(serde_json::to_vec(env)?)
    }
}

/// Version 7 (October 2026): version 6 with number fields (`field_type` `number` and their
/// `number_format`: decimal places, range and drawing style, [`crate::numbers::NumberFormat`])
/// and the optional `verify_at` address, which the document-ID stamp draws on a second line
/// ("Verify at <address>"); without it the stamp is version 6's. Experimental. It is version 8
/// without the text-field checks and number currencies, so it decodes and encodes directly,
/// refusing them both ways.
mod v7 {
    use super::*;

    pub(super) fn decode(bytes: &[u8]) -> Result<Envelope> {
        let value = levels_json(bytes, 7)?;
        refuse_v8_terms(&value, 7)?;
        refuse_v9_terms(&value, 7)?;
        let env: Envelope = serde_json::from_value(value).map_err(|e| invalid(7, e.to_string()))?;
        debug_assert_eq!(env.schema_version, 7);
        Ok(env)
    }

    pub(super) fn encode(env: &Envelope) -> Result<Vec<u8>> {
        cannot_hold_v8_terms(env, 7)?;
        cannot_hold_v9_terms(env, 7)?;
        Ok(serde_json::to_vec(env)?)
    }
}

/// Version 8 (November 2026): version 7 with checks on text and multi-line fields (`value_format`:
/// email, phone, amount, postal code, IBAN, US SSN or EIN, or a custom pattern,
/// [`crate::formats::ValueFormat`]; `length`, [`crate::formats::LengthRule`]), the owner's
/// `check_message` on a field with a check, a `currency` in a number format, and formula fields.
/// Experimental. Its initials stamps are the letters of the verified email address
/// ([`crate::initials::email_rule`]). It is version 9 without `initials_rule`, so it decodes and
/// encodes directly, refusing it both ways.
mod v8 {
    use super::*;

    pub(super) fn decode(bytes: &[u8]) -> Result<Envelope> {
        let value = levels_json(bytes, 8)?;
        refuse_v9_terms(&value, 8)?;
        let env: Envelope = serde_json::from_value(value).map_err(|e| invalid(8, e.to_string()))?;
        debug_assert_eq!(env.schema_version, 8);
        Ok(env)
    }

    pub(super) fn encode(env: &Envelope) -> Result<Vec<u8>> {
        cannot_hold_v9_terms(env, 8)?;
        Ok(serde_json::to_vec(env)?)
    }
}

/// Version 9 (November 2026): version 8 with the envelope's `initials_rule`, required: the rule
/// that derives the letters stamped in a signer's further initials fields
/// ([`crate::initials::InitialsRule`]; `name-v1`, from the slot's name). Experimental: it may
/// change in place, or be dropped, before the first hosted release. It is the shape of today's
/// [`Envelope`], so it decodes and encodes directly. Once a version is stable, its module keeps
/// reading and writing its own JSON shape when the model changes, mapping it to and from the new
/// model without losing anything its signatures cover (as [`v3`] does).
mod v9 {
    use super::*;

    pub(super) fn decode(bytes: &[u8]) -> Result<Envelope> {
        let value = levels_json(bytes, 9)?;
        let env: Envelope = serde_json::from_value(value).map_err(|e| invalid(9, e.to_string()))?;
        debug_assert_eq!(env.schema_version, 9);
        if env.initials_rule.is_none() {
            return Err(invalid(9, "it names no 'initials_rule'".into()));
        }
        Ok(env)
    }

    pub(super) fn encode(env: &Envelope) -> Result<Vec<u8>> {
        if env.initials_rule.is_none() {
            return Err(SignPdfError::Workflow(
                "a version-9 envelope names its initials rule, and this one has none".into(),
            ));
        }
        Ok(serde_json::to_vec(env)?)
    }
}

fn invalid(version: u32, e: String) -> SignPdfError {
    SignPdfError::Workflow(format!(
        "embedded envelope is not a valid v{version} envelope: {e}"
    ))
}

/// The JSON of a version-4-or-later envelope, refused when a slot names version 3's
/// `min_assurance`.
fn levels_json(bytes: &[u8], version: u32) -> Result<serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| invalid(version, e.to_string()))?;
    if identity_policies(&value)
        .iter()
        .any(|p| p.get("min_assurance").is_some())
    {
        return Err(invalid(
            version,
            "a slot's identity policy names 'min_assurance', which version 4 replaced with \
             'min_level'"
                .into(),
        ));
    }
    Ok(value)
}

/// Versions before 5 have no `documents` index: a document claiming one is not of its version.
fn refuse_documents(value: &serde_json::Value, version: u32) -> Result<()> {
    if value.get("documents").is_some() {
        return Err(invalid(
            version,
            "it has a 'documents' index, which only version 5 and later have".into(),
        ));
    }
    Ok(())
}

/// What a version before 5 cannot say is never written in it.
fn cannot_hold_documents(env: &Envelope, version: u32) -> Result<()> {
    if env.documents.is_empty() {
        Ok(())
    } else {
        Err(SignPdfError::Workflow(format!(
            "this envelope combines {} documents, which a version-{version} envelope cannot \
             express",
            env.documents.len()
        )))
    }
}

/// Versions before 6 keep no drawing in their signature records: a document claiming one is not
/// of its version.
fn refuse_drawings(value: &serde_json::Value, version: u32) -> Result<()> {
    let records = value
        .get("signatures")
        .and_then(|s| s.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    if records.iter().any(|r| r.get("drawing").is_some()) {
        return Err(invalid(
            version,
            "a signature record keeps a drawing, which only version 6 and later do".into(),
        ));
    }
    Ok(())
}

/// What a version before 6 cannot say is never written in it.
fn cannot_hold_drawings(env: &Envelope, version: u32) -> Result<()> {
    if env.signatures.iter().any(|r| r.drawing.is_some()) {
        Err(SignPdfError::Workflow(format!(
            "a signature record keeps the signer's drawing, which a version-{version} envelope \
             cannot express"
        )))
    } else {
        Ok(())
    }
}

/// Versions before 7 have no number fields and no 'verify at' address: a document claiming either
/// is not of its version.
fn refuse_v7_terms(value: &serde_json::Value, version: u32) -> Result<()> {
    if value.get("verify_at").is_some() {
        return Err(invalid(
            version,
            "it has a 'verify_at' address, which only version 7 and later have".into(),
        ));
    }
    let fields = value
        .get("fields")
        .and_then(|f| f.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    if fields.iter().any(|f| {
        f.get("number_format").is_some()
            || f.get("field_type").and_then(|t| t.as_str()) == Some("number")
    }) {
        return Err(invalid(
            version,
            "it has a number field, which only version 7 and later have".into(),
        ));
    }
    Ok(())
}

/// What a version before 7 cannot say is never written in it.
fn cannot_hold_v7_terms(env: &Envelope, version: u32) -> Result<()> {
    let numbers = env
        .fields
        .iter()
        .any(|f| f.field_type == crate::model::FieldType::Number || f.number_format.is_some());
    if numbers {
        Err(SignPdfError::Workflow(format!(
            "this envelope has a number field, which a version-{version} envelope cannot express"
        )))
    } else if env.verify_at.is_some() {
        Err(SignPdfError::Workflow(format!(
            "this envelope names a 'verify at' address, which a version-{version} envelope              cannot express"
        )))
    } else {
        Ok(())
    }
}

/// The field members version 8 added.
const V8_FIELD_MEMBERS: &[&str] = &["value_format", "length", "check_message", "formula"];

/// Versions before 8 have no text-field checks, owner messages, number currencies or formula
/// fields: a document claiming one is not of its version.
fn refuse_v8_terms(value: &serde_json::Value, version: u32) -> Result<()> {
    let fields = value
        .get("fields")
        .and_then(|f| f.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    for f in fields {
        if f.get("field_type").and_then(|t| t.as_str()) == Some("formula") {
            return Err(invalid(
                version,
                "it has a formula field, which only version 8 and later have".into(),
            ));
        }
        if let Some(member) = V8_FIELD_MEMBERS.iter().find(|m| f.get(**m).is_some()) {
            return Err(invalid(
                version,
                format!("a field has '{member}', which only version 8 and later have"),
            ));
        }
        if f.get("number_format")
            .is_some_and(|n| n.get("currency").is_some())
        {
            return Err(invalid(
                version,
                "a number format names a currency, which only version 8 and later do".into(),
            ));
        }
    }
    Ok(())
}

/// What a version before 8 cannot say is never written in it.
fn cannot_hold_v8_terms(env: &Envelope, version: u32) -> Result<()> {
    let v8 = env.fields.iter().any(|f| {
        f.value_format.is_some()
            || f.length.is_some()
            || f.check_message.is_some()
            || f.formula.is_some()
            || f.field_type == crate::model::FieldType::Formula
            || f.number_format
                .as_ref()
                .is_some_and(|n| n.currency.is_some())
    });
    if v8 {
        Err(SignPdfError::Workflow(format!(
            "this envelope has a field check, owner message, currency or formula, which a              version-{version} envelope cannot express"
        )))
    } else {
        Ok(())
    }
}

/// Versions before 9 name no initials rule (they stamp the email's letters): a document naming
/// one is not of its version.
fn refuse_v9_terms(value: &serde_json::Value, version: u32) -> Result<()> {
    if value.get("initials_rule").is_some() {
        return Err(invalid(
            version,
            "it names an 'initials_rule', which only version 9 and later have".into(),
        ));
    }
    Ok(())
}

/// What a version before 9 cannot say is never written in it.
fn cannot_hold_v9_terms(env: &Envelope, version: u32) -> Result<()> {
    match env.initials_rule {
        Some(rule) => Err(SignPdfError::Workflow(format!(
            "this envelope derives initials by the rule '{}', which a version-{version} envelope              cannot express",
            rule.as_str()
        ))),
        None => Ok(()),
    }
}

/// The identity policies of every slot of an envelope's JSON.
fn identity_policies(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    value
        .get("signers")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|s| s.get("identity_policy")).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_table_matches_the_constants() {
        assert_eq!(
            support(u64::from(SCHEMA_VERSION)),
            VersionSupport::Supported
        );
        assert_eq!(
            support(u64::from(OLDEST_SCHEMA_VERSION)),
            VersionSupport::Supported
        );
        assert_eq!(
            support(u64::from(SCHEMA_VERSION) + 1),
            VersionSupport::Newer
        );
        assert_eq!(support(u64::MAX), VersionSupport::Newer);
        assert_eq!(support(0), VersionSupport::Retired);
        for v in RETIRED_SCHEMA_VERSIONS {
            assert_eq!(support(u64::from(*v)), VersionSupport::Retired);
        }
    }

    #[test]
    fn every_supported_version_has_a_decoder_and_an_encoder() {
        for v in OLDEST_SCHEMA_VERSION..=SCHEMA_VERSION {
            // A minimal envelope: the decoder must get past the version dispatch (an empty
            // object fails on a missing field, not on "no decoder").
            let json = format!(r#"{{"schema_version":{v}}}"#);
            let err = decode_envelope(json.as_bytes()).unwrap_err().to_string();
            assert!(!err.contains("no decoder"), "v{v}: {err}");
            let env = blank(v);
            let bytes = encode_envelope(&env).unwrap();
            assert_eq!(decode_envelope(&bytes).unwrap(), env);
        }
    }

    #[test]
    fn newer_versions_are_refused_before_their_content_is_read() {
        // A future envelope may have any shape; only the version is read.
        let json = format!(
            r#"{{"schema_version":{},"signers":"a shape this build does not know"}}"#,
            SCHEMA_VERSION + 1
        );
        match decode_envelope(json.as_bytes()) {
            Err(SignPdfError::UnsupportedSchemaVersion { found, newest }) => {
                assert_eq!(found, u64::from(SCHEMA_VERSION) + 1);
                assert_eq!(newest, SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
        }
        let huge = br#"{"schema_version":18446744073709551615}"#;
        assert!(matches!(
            decode_envelope(huge),
            Err(SignPdfError::UnsupportedSchemaVersion { .. })
        ));
    }

    #[test]
    fn retired_and_malformed_versions_are_workflow_errors() {
        for v in RETIRED_SCHEMA_VERSIONS.iter().copied().chain([0]) {
            let json = format!(r#"{{"schema_version":{v}}}"#);
            let err = decode_envelope(json.as_bytes()).unwrap_err();
            assert!(
                matches!(&err, SignPdfError::Workflow(m) if m.contains("development build")),
                "v{v}: {err}"
            );
        }
        for bad in [
            &br#"{"title":"no version"}"#[..],
            br#"{"schema_version":"3"}"#,
            br#"{"schema_version":-1}"#,
            br#"{"schema_version":3.5}"#,
            br#"{"schema_version":3,"schema_version":4}"#,
            b"not json",
        ] {
            let err = decode_envelope(bad).unwrap_err();
            assert!(
                matches!(err, SignPdfError::Workflow(_)),
                "{}: {err}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn an_envelope_newer_than_this_build_is_never_encoded() {
        let env = blank(SCHEMA_VERSION + 1);
        assert!(matches!(
            encode_envelope(&env),
            Err(SignPdfError::UnsupportedSchemaVersion { .. })
        ));
    }

    /// A one-slot envelope requiring `policy`, in version `v`.
    fn with_policy(v: u32, policy: crate::oidc::IdentityPolicy) -> Envelope {
        let mut env = blank(v);
        env.signers.push(crate::model::Signer {
            id: "s1".into(),
            name: "Signer".into(),
            handle: "s@example.test".into(),
            role: "signer".into(),
            order: 1,
            status: crate::model::SignerStatus::Pending,
            identity_policy: policy,
            public_key: None,
            fingerprint: None,
        });
        env
    }

    #[test]
    fn version_3_reads_and_writes_min_assurance_as_levels() {
        use crate::oidc::{IdentityPolicy, Level, Method};
        for (assurance, level) in [("consumer", Level::L1), ("enterprise", Level::L3)] {
            let env = with_policy(
                3,
                IdentityPolicy {
                    min_level: level,
                    ..Default::default()
                },
            );
            let bytes = encode_envelope(&env).unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let policy = &json["signers"][0]["identity_policy"];
            assert_eq!(policy["min_assurance"], assurance);
            assert!(policy.get("min_level").is_none(), "{policy}");
            assert_eq!(decode_envelope(&bytes).unwrap(), env);

            // Version 4 writes the level, and refuses the old name.
            let mut v4 = env.clone();
            v4.schema_version = 4;
            let bytes = encode_envelope(&v4).unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                json["signers"][0]["identity_policy"]["min_level"],
                level.as_str()
            );
            assert_eq!(decode_envelope(&bytes).unwrap(), v4);
            let legacy = String::from_utf8(bytes).unwrap().replace(
                &format!(r#""min_level":"{level}""#),
                &format!(r#""min_assurance":"{assurance}""#),
            );
            assert!(decode_envelope(legacy.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("min_assurance"));
        }
        // What version 3 cannot say is never written as version 3.
        for policy in [
            IdentityPolicy {
                min_level: Level::L2,
                ..Default::default()
            },
            IdentityPolicy {
                required_methods: vec![Method::Account],
                ..Default::default()
            },
        ] {
            let err = encode_envelope(&with_policy(3, policy)).unwrap_err();
            assert!(err.to_string().contains("version-3"), "{err}");
        }
        // ...and a version-3 envelope naming version 4's fields is not version 3.
        let env = with_policy(4, IdentityPolicy::default());
        let mut json: serde_json::Value =
            serde_json::from_slice(&encode_envelope(&env).unwrap()).unwrap();
        json["schema_version"] = 3.into();
        let err = decode_envelope(json.to_string().as_bytes()).unwrap_err();
        assert!(err.to_string().contains("min_level"), "{err}");
    }

    #[test]
    fn only_version_5_holds_a_documents_index() {
        let mut env = blank(5);
        env.documents.push(crate::model::EnvelopeDocument {
            name: "Schedule A.pdf".into(),
            first_page: 0,
            page_count: 2,
            source_digest: "ab".repeat(32),
        });
        let bytes = encode_envelope(&env).unwrap();
        assert_eq!(decode_envelope(&bytes).unwrap(), env);
        for v in [3, 4] {
            let mut old = env.clone();
            old.schema_version = v;
            let err = encode_envelope(&old).unwrap_err().to_string();
            assert!(err.contains(&format!("version-{v}")), "{err}");
            let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            json["schema_version"] = v.into();
            let err = decode_envelope(json.to_string().as_bytes()).unwrap_err();
            assert!(err.to_string().contains("'documents'"), "v{v}: {err}");
        }
        // Without an index, version 5 writes version 4's JSON but for the version number.
        let plain = encode_envelope(&blank(5)).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert!(json.get("documents").is_none(), "{json}");
        assert_eq!(
            String::from_utf8(plain)
                .unwrap()
                .replace(r#""schema_version":5"#, r#""schema_version":4"#),
            String::from_utf8(encode_envelope(&blank(4)).unwrap()).unwrap()
        );
    }

    #[test]
    fn only_version_6_keeps_drawings() {
        use crate::ink::{PathSegment, SignatureDrawing};
        let record: crate::model::SignatureRecord = serde_json::from_value(serde_json::json!({
            "signer_id": "s1", "fingerprint": "f", "public_key": "k", "algorithm": "a",
            "signed_at": "t", "doc_digest": "d", "signed_prefix_len": 1, "signature": "s",
            "revision": 1,
        }))
        .unwrap();
        assert_eq!(record.drawing, None);
        let mut env = blank(6);
        for drawing in [
            SignatureDrawing::Typed {
                paths: vec![vec![
                    PathSegment::Line([0.0, 0.0]),
                    PathSegment::Curve([1.0, 2.0, 3.0, 4.0, 5.0, 6.5]),
                ]],
            },
            SignatureDrawing::Drawn {
                strokes: vec![vec![[0.0, 0.0], [1.5, 2.0]]],
            },
        ] {
            env.signatures.push(crate::model::SignatureRecord {
                drawing: Some(drawing),
                ..record.clone()
            });
        }
        env.signatures.push(record.clone());
        let bytes = encode_envelope(&env).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["signatures"][0]["drawing"]["kind"], "typed");
        assert_eq!(json["signatures"][1]["drawing"]["kind"], "drawn");
        assert!(json["signatures"][2].get("drawing").is_none(), "{json}");
        assert_eq!(decode_envelope(&bytes).unwrap(), env);
        for v in [3, 4, 5] {
            let mut old = env.clone();
            old.schema_version = v;
            let err = encode_envelope(&old).unwrap_err().to_string();
            assert!(err.contains(&format!("version-{v}")), "{err}");
            let mut json = json.clone();
            json["schema_version"] = v.into();
            let err = decode_envelope(json.to_string().as_bytes()).unwrap_err();
            assert!(err.to_string().contains("drawing"), "v{v}: {err}");
            // Without drawings, the older versions hold the same records.
            old.signatures.retain(|r| r.drawing.is_none());
            let bytes = encode_envelope(&old).unwrap();
            assert_eq!(decode_envelope(&bytes).unwrap(), old);
        }
        // A drawing of another kind is not a drawing.
        let mut json = json.clone();
        json["signatures"][0]["drawing"] = serde_json::json!({"kind": "image", "png": ""});
        assert!(decode_envelope(json.to_string().as_bytes()).is_err());
    }

    #[test]
    fn only_version_7_holds_number_fields_and_a_verify_at_address() {
        let number: crate::model::Field = serde_json::from_value(serde_json::json!({
            "id": "fee", "field_type": "number", "page": 0,
            "rect": {"x": 0.0, "y": 0.0, "w": 10.0, "h": 10.0},
            "assigned_signer": "s1", "required": true,
            "number_format": {"decimals": 2, "style": "1 234,5"},
        }))
        .unwrap();
        for (what, env) in [
            ("number", {
                let mut env = blank(7);
                env.fields.push(number.clone());
                env
            }),
            ("verify_at", {
                let mut env = blank(7);
                env.verify_at = Some("verify.example.com".into());
                env
            }),
        ] {
            let bytes = encode_envelope(&env).unwrap();
            assert_eq!(decode_envelope(&bytes).unwrap(), env, "{what}");
            for v in [3, 4, 5, 6] {
                let mut old = env.clone();
                old.schema_version = v;
                let err = encode_envelope(&old).unwrap_err().to_string();
                assert!(err.contains(&format!("version-{v}")), "{what} v{v}: {err}");
                let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                json["schema_version"] = v.into();
                let err = decode_envelope(json.to_string().as_bytes()).unwrap_err();
                assert!(err.to_string().contains("version 7"), "{what} v{v}: {err}");
            }
        }
        // Without them, version 7 writes version 6's JSON but for the version number.
        assert_eq!(
            String::from_utf8(encode_envelope(&blank(7)).unwrap())
                .unwrap()
                .replace(r#""schema_version":7"#, r#""schema_version":6"#),
            String::from_utf8(encode_envelope(&blank(6)).unwrap()).unwrap()
        );
    }

    #[test]
    fn only_version_9_names_an_initials_rule_and_it_must() {
        let env = blank(9);
        let bytes = encode_envelope(&env).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["initials_rule"], "name-v1");
        assert_eq!(decode_envelope(&bytes).unwrap(), env);
        for v in 3..=8 {
            let mut old = env.clone();
            old.schema_version = v;
            let err = encode_envelope(&old).unwrap_err().to_string();
            assert!(err.contains(&format!("version-{v}")), "v{v}: {err}");
            let mut json = json.clone();
            json["schema_version"] = v.into();
            let err = decode_envelope(json.to_string().as_bytes()).unwrap_err();
            assert!(err.to_string().contains("initials_rule"), "v{v}: {err}");
        }
        // Version 9 without a rule, or with a rule this build does not know, is not version 9.
        let mut none = env.clone();
        none.initials_rule = None;
        assert!(encode_envelope(&none).is_err());
        let mut json = json.clone();
        json.as_object_mut().unwrap().remove("initials_rule");
        assert!(decode_envelope(json.to_string().as_bytes())
            .unwrap_err()
            .to_string()
            .contains("initials_rule"));
        json["initials_rule"] = "name-v2".into();
        assert!(decode_envelope(json.to_string().as_bytes()).is_err());
        // Without the rule, version 8 writes version 9's JSON but for the version number.
        assert_eq!(
            String::from_utf8(bytes)
                .unwrap()
                .replace(r#""schema_version":9"#, r#""schema_version":8"#)
                .replace(r#","initials_rule":"name-v1""#, ""),
            String::from_utf8(encode_envelope(&blank(8)).unwrap()).unwrap()
        );
    }

    /// An empty envelope of version `v` (built directly: it may not be decodable).
    fn blank(v: u32) -> Envelope {
        let mut env: Envelope = serde_json::from_value(serde_json::json!({
            "schema_version": 3, "envelope_id": "", "title": "", "created_by": "",
            "created_at": "", "source_digest": "", "signers": [], "fields": [],
            "policy": {"signing_order": "sequential", "allowed_signature_types": []},
            "signatures": [], "audit_log": [],
        }))
        .unwrap();
        env.schema_version = v;
        if v >= 9 {
            env.initials_rule = Some(crate::initials::InitialsRule::NameV1);
        }
        env
    }
}
