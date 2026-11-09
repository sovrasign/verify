//! Data model for the self-describing signing envelope.

use serde::{Deserialize, Serialize};

use crate::crypto::{self, sha256_hex};
use crate::dates::DateFormat;
use crate::error::{Result, SignPdfError};
use crate::formats::{FieldCheck, LengthRule, ValueFormat};
use crate::formula::FormulaSpec;
use crate::ink::SignatureDrawing;
use crate::numbers::NumberFormat;
use crate::oidc::IdentityPolicy;

/// A rectangle in PDF user-space points (origin bottom-left).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

/// Kinds of fillable fields a preparer can place on a document.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Signature,
    Initials,
    Date,
    Text,
    /// Text over several lines, wrapped to the field's width (it may contain line breaks).
    Multiline,
    /// A tick box with a caption (the field's `label`) drawn beside it, inside the rectangle.
    Checkbox,
    /// One option of a radio group: at most one field of a `group` can be selected. The option's
    /// caption is the field's `label`.
    Radio,
    /// One choice from the list the preparer wrote (the field's `options`), drawn as text.
    Dropdown,
    /// A number, from envelope schema version 7: stored as a canonical decimal with the decimal
    /// places of the field's `number_format`, checked against its range and drawn in its sealed
    /// style ([`crate::numbers`]).
    Number,
    /// A number computed from other fields by the field's `formula`, from envelope schema version
    /// 8: the signer types nothing; the engine computes it when its signer signs and draws it in
    /// the field's sealed `number_format`, and the verifier computes it again
    /// ([`crate::formula`]).
    Formula,
}

/// A single placed field, optionally filled in by its assigned signer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Field {
    pub id: String,
    pub field_type: FieldType,
    pub page: u32,
    pub rect: Rect,
    /// Id of the signer responsible for this field.
    pub assigned_signer: String,
    pub required: bool,
    /// Value supplied by the signer: the text or date, or `true`/`false` for a checkbox or radio
    /// option (signing answers every one of the signer's). A signer's *primary* signature field is
    /// backed by their cryptographic [`SignatureRecord`] and keeps no value; any further
    /// signature/initials fields of theirs receive an engine-generated stamp derived from the
    /// verified identity (see `workflow::stamp_text`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Label set by the preparer: a placeholder for text fields (e.g. "Company name"), and the
    /// caption drawn beside checkbox and radio fields, for which it is required. Part of the
    /// prepared terms, so it cannot be changed after preparation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Radio fields only: the group this option belongs to. All options of a group belong to the
    /// same signer, and the signer selects at most one of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Dropdown fields only: the choices, in the order shown. Part of the prepared terms; the
    /// signer's value is one of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    /// Date fields only: how the date is drawn on the page (absent: `YYYY-MM-DD`). The value is
    /// stored as `YYYY-MM-DD` whatever the format, and drawn in this format whatever the signer's
    /// locale, so every party reads the same text. Part of the prepared terms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_format: Option<DateFormat>,
    /// Date fields only: a *date signed* field. The engine fills it with the signer's local date
    /// when they sign (see [`crate::dates`]) and the signer gives it no value; the verifier
    /// checks it against the signing time and the UTC offset in the signature record. Without
    /// it a date field takes any date the signer picks, and the local signing date when left
    /// empty. Part of the prepared terms; omitted from the JSON when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub signing_date: bool,
    /// Number fields only, and required for them (envelope schema version 7): the decimal
    /// places, the range and the drawing style of the value ([`NumberFormat`]). Part of the
    /// prepared terms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number_format: Option<NumberFormat>,
    /// Text and multi-line fields only (envelope schema version 8): the format the value must
    /// have ([`ValueFormat`]: email, phone, amount, postal code, IBAN, US SSN or EIN, or a custom
    /// pattern). The envelope stores the value in its canonical form; US identifiers are drawn
    /// masked. Part of the prepared terms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_format: Option<ValueFormat>,
    /// Text and multi-line fields only (envelope schema version 8): how many characters the
    /// stored value may have ([`LengthRule`]). Part of the prepared terms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<LengthRule>,
    /// Fields with a check (a `value_format`, a `length` or a `number_format`), from envelope
    /// schema version 8: the preparer's own message, shown to the signer instead of the standard
    /// one when a value is refused (at most 200 characters,
    /// [`crate::formats::validate_check_message`]). Sealed with the terms; it never decides
    /// whether a value or a document is valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_message: Option<String>,
    /// Formula fields only, and required for them (envelope schema version 8): the formula and
    /// the numbers the options of the dropdowns and radio groups it reads count as
    /// ([`FormulaSpec`]). Part of the prepared terms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formula: Option<FormulaSpec>,
}

impl Field {
    /// The value rules sealed in this field ([`FieldCheck`]), or why they are not valid rules
    /// (an English fragment that follows "field X ..."): [`FieldRules::check`].
    pub fn check(&self) -> std::result::Result<FieldCheck, String> {
        FieldRules {
            field_type: self.field_type,
            value_format: self.value_format.clone(),
            length: self.length,
            number_format: self.number_format.clone(),
            check_message: None,
        }
        .check()
    }
}

/// The members of a field that decide which values it takes, as a host gives them to check a
/// signer's entry before signing (the WebAssembly `signpdf_check_value`): on their own, or as a
/// whole field of the envelope, whose other members are ignored.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct FieldRules {
    pub field_type: FieldType,
    #[serde(default)]
    pub value_format: Option<ValueFormat>,
    #[serde(default)]
    pub length: Option<LengthRule>,
    #[serde(default)]
    pub number_format: Option<NumberFormat>,
    /// The owner's message, which a host shows when a value is refused; it changes nothing here.
    #[serde(default)]
    pub check_message: Option<String>,
}

impl FieldRules {
    /// The rules ready to apply, or why they are not valid rules (an English fragment that
    /// follows "field X ..."). Text and multi-line fields apply their `value_format` and
    /// `length`, number and formula fields their `number_format`; other fields keep the value as given
    /// (their own rules, such as a dropdown's options, are applied by the workflow).
    pub fn check(&self) -> std::result::Result<FieldCheck, String> {
        match self.field_type {
            FieldType::Text | FieldType::Multiline
                if self.value_format.is_some() || self.length.is_some() =>
            {
                if let Some(length) = &self.length {
                    length.validate()?;
                }
                let format = self
                    .value_format
                    .as_ref()
                    .map(ValueFormat::format)
                    .transpose()?;
                Ok(FieldCheck::Text {
                    format,
                    length: self.length,
                })
            }
            FieldType::Number | FieldType::Formula => Ok(FieldCheck::Number(
                self.number_format.clone().unwrap_or_default(),
            )),
            _ => Ok(FieldCheck::None),
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One document of an envelope that combines several into one PDF: an entry of the envelope's
/// `documents` index, in the order the documents appear. The engine signs one PDF; an envelope
/// of several documents signs their combination ([`crate::documents::combine`]), and the index
/// says where each one begins and ends in it, so that hosts can show "Document 2 of 3" and cut
/// a convenience copy of one document ([`crate::documents::extract`]). The index is part of the
/// prepared terms: every signer signs the whole combination and its index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopeDocument {
    /// The document's name as the preparer gave it (a file name or a title): 1 to
    /// [`crate::documents::MAX_DOCUMENT_NAME_CHARS`] characters, no control characters.
    pub name: String,
    /// 0-based index of its first page in the combined PDF (the same numbering as
    /// [`Field::page`]).
    pub first_page: u32,
    /// How many pages it has (at least one). The documents follow each other without gaps and
    /// cover every page of the combined PDF.
    pub page_count: u32,
    /// Hex SHA-256 (lower case) of the document's own PDF as it was before it was combined, so
    /// that the file someone holds can be matched to its part of the envelope. The combined PDF
    /// is a new file: this digest cannot be recomputed from it.
    pub source_digest: String,
}

impl EnvelopeDocument {
    /// The 0-based page indices of this document in the combined PDF.
    pub fn pages(&self) -> std::ops::Range<u32> {
        self.first_page..self.first_page.saturating_add(self.page_count)
    }
}

/// Whether signing must follow the declared order or may happen in parallel.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigningOrder {
    Sequential,
    Parallel,
}

/// Whether the signer revisions of an envelope carry PAdES B-T signature timestamps
/// (`policy.signature_timestamps`). The preparer chooses it and it is part of the prepared terms,
/// so it holds for the envelope's whole life: a hosted service sets it from the sender's plan when
/// the envelope is sent, and a later change of plan does not change it.
///
/// It applies to every signer revision, signed or declined; the preparer's own signature is never
/// timestamped. `docs/SECURITY_MODEL.md` §4 says what each value means for the signing time.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimestampPolicy {
    /// The signer's host decides: with an RFC 3161 time-stamp authority at hand it adds a
    /// signature timestamp, otherwise the signature is dated by the device clock. Envelopes that
    /// state no policy (all of them before the field existed) read as this, and it is not written
    /// out, so their prepared terms keep their exact JSON.
    #[default]
    Optional,
    /// Every signer revision is made with room for a signature timestamp, which the host adds at
    /// once ([`crate::workflow::sign_with`] with a timestamper) or right after
    /// ([`crate::workflow::signature_timestamp_digest`], [`crate::workflow::embed_signature_timestamp`]).
    /// A revision the host could not timestamp (both authorities unreachable) is still a complete
    /// B-B signature dated by the device clock; the verifier accepts it and warns.
    Required,
    /// No signature timestamps: every signature is dated by the signer's device clock, and the
    /// engine refuses to add a timestamp or make room for one. A hosted service gives such an
    /// envelope one document timestamp when it ends instead.
    None,
}

impl TimestampPolicy {
    /// The default, which is not written into the envelope.
    pub fn is_optional(&self) -> bool {
        *self == TimestampPolicy::Optional
    }

    /// The value as written in the envelope JSON.
    pub fn as_str(&self) -> &'static str {
        match self {
            TimestampPolicy::Optional => "optional",
            TimestampPolicy::Required => "required",
            TimestampPolicy::None => "none",
        }
    }
}

/// Policy that governs how the envelope may be signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Policy {
    pub signing_order: SigningOrder,
    pub allowed_signature_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    /// Signature timestamps on signer revisions. Omitted from the JSON when `optional`.
    #[serde(default, skip_serializing_if = "TimestampPolicy::is_optional")]
    pub signature_timestamps: TimestampPolicy,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            signing_order: SigningOrder::Sequential,
            allowed_signature_types: vec!["PAdES".to_string()],
            expiry: None,
            signature_timestamps: TimestampPolicy::Optional,
        }
    }
}

/// Lifecycle status of a signer slot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignerStatus {
    Pending,
    Signed,
    Declined,
}

/// A participant in the signing workflow. Their identity is resolved at sign time from a
/// **federated ID token** that must satisfy [`Signer::identity_policy`]; the ephemeral signing
/// key (`public_key`, `fingerprint`) is recorded when the slot is signed. There is no longer a
/// self-asserted trust-on-first-use identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Signer {
    pub id: String,
    pub name: String,
    /// Email address or other out-of-band handle.
    pub handle: String,
    pub role: String,
    /// 1-based signing order (meaningful when the policy is sequential).
    pub order: u32,
    pub status: SignerStatus,
    /// The federated-identity policy a signer's verified ID token must satisfy to fill this slot.
    #[serde(default)]
    pub identity_policy: IdentityPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// Whether a participant's PAdES-signed revision approves or declines the document.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    #[default]
    Signed,
    /// A decline is also PAdES-signed (by the decliner's ephemeral key, with their identity
    /// token archived) so it is as attributable and tamper-evident as a signature. A declined
    /// envelope is void: no further signatures are accepted.
    Declined,
}

impl RecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Signed => "signed",
            RecordKind::Declined => "declined",
        }
    }
}

/// A cryptographic signature applied by one participant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignatureRecord {
    /// Signed or declined.
    #[serde(default)]
    pub kind: RecordKind,
    pub signer_id: String,
    pub fingerprint: String,
    /// Base64 SEC1 public key, carried so the signature is verifiable offline.
    pub public_key: String,
    pub algorithm: String,
    /// Device-clock signing time (RFC 3339).
    pub signed_at: String,
    /// Optional RFC 3161 timestamp token (base64). `None` when signed offline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_token: Option<String>,
    /// Hex SHA-256 of the document byte prefix this participant signed (ByteRange digest).
    pub doc_digest: String,
    /// Length of that signed prefix, in bytes.
    pub signed_prefix_len: u64,
    /// Base64 DER ECDSA signature over the binding payload.
    pub signature: String,
    /// 0-based revision index (one incremental revision per participant).
    pub revision: u32,
    /// The federated **ID token** (compact JWS) presented by the signer, stapled to this key and
    /// document via `nonce == H(public_key ‖ doc_digest)`. Archived for fully offline re-checks.
    #[serde(default)]
    pub id_token: String,
    /// The exact JWKS key (JSON) that signed `id_token`, so a verifier needs no network access.
    #[serde(default)]
    pub idp_jwk: String,
    /// Convenience mirror of the token's `iss`.
    #[serde(default)]
    pub idp_issuer: String,
    /// The token's stable `sub` (subject).
    #[serde(default)]
    pub idp_subject: String,
    /// The verified email asserted by the provider.
    #[serde(default)]
    pub idp_email: String,
    /// The relying-party `client_id` the token's `aud` was validated against at signing time.
    #[serde(default)]
    pub idp_audience: String,
    /// The signer's UTC offset when they signed, as the host reported it (`+02:00`, `-05:30`,
    /// between `-12:00` and `+14:00`): `signed_at` moved by it is the signer's local time, and
    /// the date in their *date signed* fields. Absent when the host did not say; their dates
    /// are then UTC dates. Evidence only: it is not a claim about where the signer was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utc_offset: Option<String>,
    /// What the signer drew in their signature box, from envelope schema version 6: hand-drawn
    /// pen strokes (`drawn`) or the filled glyph outlines of a typed name (`typed`), exactly as
    /// the engine drew them beside the verified caption, so a verifier can redraw the box and
    /// say which kind it shows. Decoration, never evidence: a typed name is not a claim about
    /// who signed (the caption is). Absent when nothing was drawn (no visible box, a decline, or
    /// a signer who adopted the caption alone), and always before version 6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drawing: Option<SignatureDrawing>,
}

/// Actions recorded in the append-only audit log.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Prepared,
    Sent,
    Opened,
    Signed,
    Declined,
    Verified,
}

impl AuditAction {
    fn as_str(&self) -> &'static str {
        match self {
            AuditAction::Prepared => "prepared",
            AuditAction::Sent => "sent",
            AuditAction::Opened => "opened",
            AuditAction::Signed => "signed",
            AuditAction::Declined => "declined",
            AuditAction::Verified => "verified",
        }
    }
}

/// Hash value used as the predecessor of the first audit entry.
pub const AUDIT_GENESIS: &str = "GENESIS";

/// A signer's consent to use electronic records and signatures (the US ESIGN Act and UETA
/// consumer consent; the equivalent EU and UK notices), as the signing host recorded it when the
/// signer agreed to its disclosure. Written into the signer's audit entry, which their key signs
/// and the hash chain covers, so the signed PDF itself shows which disclosure text they accepted:
/// anyone holding the published text can recompute its hash.
///
/// The engine checks the record's form, not the text: which disclosures exist, and which one a
/// signer must see, is the host's business.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EsignConsent {
    /// The disclosure's version id, e.g. `esd-1`: 1 to 64 characters, lower-case letters,
    /// digits, `.` and `-`, starting with a letter or digit.
    pub version: String,
    /// The language of the text shown (a lower-case BCP 47 tag such as `en`, `fr` or `pt-br`).
    pub lang: String,
    /// SHA-256 (lower-case hex) of the disclosure text shown.
    pub sha256: String,
    /// SHA-256 of the same version's reference text (for example the English one) when the text
    /// shown was a translation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_sha256: Option<String>,
    /// When the signer agreed (RFC 3339, UTC, ending in `Z`).
    pub at: String,
}

impl EsignConsent {
    /// The form written into the audit entry's hashed content, e.g.
    /// `esign-consent=esd-1;lang=fr;sha256=<hex>;ref-sha256=<hex>;at=2026-11-02T09:14:03Z`.
    /// Every value is limited to characters that need no escaping (no `|`, `;` or `=`).
    pub fn canonical(&self) -> String {
        let reference = self
            .ref_sha256
            .as_deref()
            .map(|r| format!(";ref-sha256={r}"))
            .unwrap_or_default();
        format!(
            "esign-consent={};lang={};sha256={}{reference};at={}",
            self.version, self.lang, self.sha256, self.at
        )
    }

    /// Check the record's form (see the field docs). Signing refuses a malformed record and
    /// verification reports one.
    pub fn validate(&self) -> std::result::Result<(), String> {
        let v = &self.version;
        if v.is_empty()
            || v.len() > 64
            || !v.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            || !v
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        {
            return Err(format!(
                "the consent's disclosure version '{v}' is not 1 to 64 lower-case letters, \
                 digits, '.' or '-'"
            ));
        }
        if !is_language_tag(&self.lang) {
            return Err(format!(
                "the consent's language '{}' is not a lower-case language tag such as en or pt-br",
                self.lang
            ));
        }
        let is_sha256 = |h: &str| {
            h.len() == 64
                && h.chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        };
        if !is_sha256(&self.sha256) {
            return Err("the consent's sha256 is not 64 lower-case hex digits".into());
        }
        if self.ref_sha256.as_deref().is_some_and(|r| !is_sha256(r)) {
            return Err("the consent's ref_sha256 is not 64 lower-case hex digits".into());
        }
        let at = &self.at;
        if at.len() > 40
            || !at.ends_with('Z')
            || !at
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '-' | ':' | '.' | 'T' | 'Z'))
            || crate::util::unix_from_rfc3339(at).is_none()
        {
            return Err(format!(
                "the consent time '{at}' is not an RFC 3339 UTC time such as \
                 2026-11-02T09:14:03Z"
            ));
        }
        Ok(())
    }
}

/// A lower-case BCP 47 language tag of the simple kind hosts use: a 2–3 letter language, then
/// optional `-` subtags of 1–8 letters or digits (`en`, `fr`, `pt-br`, `zh-hans`); 35 characters
/// at most.
fn is_language_tag(tag: &str) -> bool {
    let mut parts = tag.split('-');
    let lang_ok = parts
        .next()
        .is_some_and(|l| (2..=3).contains(&l.len()) && l.chars().all(|c| c.is_ascii_lowercase()));
    lang_ok
        && tag.len() <= 35
        && parts.all(|p| {
            (1..=8).contains(&p.len())
                && p.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

/// One entry in the hash-chained, per-actor-signed audit log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEntry {
    pub seq: u32,
    pub action: AuditAction,
    pub actor_fingerprint: String,
    pub actor_name: String,
    pub at: String,
    pub details: String,
    /// Hex SHA-256 of the previous entry's content (or [`AUDIT_GENESIS`]).
    pub prev_hash: String,
    /// Hex SHA-256 of this entry's canonical content (excludes `signature`).
    pub entry_hash: String,
    /// Base64 DER ECDSA signature of `entry_hash` by the actor's key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// A signer's consent to electronic records and signatures, when their host recorded one
    /// (signer and decliner entries only). Part of the hashed content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esign_consent: Option<EsignConsent>,
}

impl AuditEntry {
    /// Canonical, deterministic content string that `entry_hash` is computed over:
    /// `seq|action|actor_fingerprint|at|details|prev_hash`, then `|` and the consent's
    /// [`EsignConsent::canonical`] form when the entry carries one. `prev_hash` is a hex digest
    /// (or [`AUDIT_GENESIS`]) and the consent form starts with `esign-consent=` and holds no `|`,
    /// so the last part always says which of the two shapes an entry has.
    pub fn canonical_content(&self) -> String {
        let mut content = format!(
            "{}|{}|{}|{}|{}|{}",
            self.seq,
            self.action.as_str(),
            self.actor_fingerprint,
            self.at,
            self.details,
            self.prev_hash
        );
        if let Some(consent) = &self.esign_consent {
            content.push('|');
            content.push_str(&consent.canonical());
        }
        content
    }
}

/// The self-describing envelope embedded in the document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub schema_version: u32,
    pub envelope_id: String,
    pub title: String,
    pub created_by: String,
    pub created_at: String,
    /// Base64 SEC1 public key of the preparer, so the preparer's audit entry is verifiable
    /// even when the preparer is not also a signer slot.
    #[serde(default)]
    pub created_by_pubkey: String,
    /// The preparer's federated **ID token** (compact JWS), stapled to `created_by_pubkey` and
    /// the source document via `nonce == H(created_by_pubkey ‖ source_digest)`.
    #[serde(default)]
    pub created_by_id_token: String,
    /// The exact JWKS key (JSON) that signed `created_by_id_token`.
    #[serde(default)]
    pub created_by_idp_jwk: String,
    /// Convenience mirror of the preparer token's `iss`.
    #[serde(default)]
    pub created_by_issuer: String,
    /// The preparer's verified email asserted by the provider.
    #[serde(default)]
    pub created_by_email: String,
    /// The `client_id` the preparer token's `aud` was validated against at preparation time.
    #[serde(default)]
    pub created_by_audience: String,
    /// Hex SHA-256 of the original source document bytes (immutable anchor).
    pub source_digest: String,
    /// Length of the original source document: the prepared PDF begins with exactly these bytes,
    /// so a verifier can confirm `source_digest` and audit everything the preparer added.
    #[serde(default)]
    pub source_len: u64,
    /// The documents the source combines, in order ([`EnvelopeDocument`]), when the preparer
    /// gave an index; empty for an envelope of one document without one. From schema version 5;
    /// omitted from the JSON when empty. Part of the prepared terms.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub documents: Vec<EnvelopeDocument>,
    pub signers: Vec<Signer>,
    pub fields: Vec<Field>,
    pub policy: Policy,
    pub signatures: Vec<SignatureRecord>,
    pub audit_log: Vec<AuditEntry>,
    /// An optional link that opens this envelope in the service that sent it ("open in ..."),
    /// set by the preparer: an `https` URL without user name or password, 512 bytes at most
    /// ([`crate::workflow::check_service_link`]). **Outside the prepared terms**: it is not
    /// something signers agree to and never decides whether the document is valid. The verifier
    /// reports the preparer's link ([`crate::workflow::VerificationReport::service_link`]) and
    /// warns when a later revision changed it; hosts show the reported one, never this field of
    /// a later revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_link: Option<String>,
    /// From envelope schema version 7: the short address of a verifier the preparer names
    /// (`verify.example.com` or `example.com/verify`, no scheme, 40 characters at most:
    /// [`crate::workflow::check_verify_at`]), drawn on the document-ID stamp as "Verify at
    /// <address>" so that a reader of a printed copy knows where to check it. Part of the
    /// prepared terms, and the verifier redraws the stamp from it. Absent: the stamp names only
    /// the document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_at: Option<String>,
    /// From envelope schema version 9, where it is required: the rule that derives the letters
    /// stamped in a signer's further initials fields ([`crate::initials::InitialsRule`], today
    /// only `name-v1`: from the slot's name, else the verified email address). Part of the
    /// prepared terms. Absent (versions 3 to 8): the letters of the verified email address
    /// ([`crate::initials::email_rule`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initials_rule: Option<crate::initials::InitialsRule>,
}

impl Envelope {
    /// The document (an index into [`Envelope::documents`]) that holds 0-based page `page`, when
    /// the envelope has an index and the page is in it.
    pub fn document_of_page(&self, page: u32) -> Option<usize> {
        self.documents
            .iter()
            .position(|d| d.pages().contains(&page))
    }

    /// Find a signer slot by id.
    pub fn signer(&self, id: &str) -> Option<&Signer> {
        self.signers.iter().find(|s| s.id == id)
    }

    /// Mutable signer slot by id.
    pub fn signer_mut(&mut self, id: &str) -> Option<&mut Signer> {
        self.signers.iter_mut().find(|s| s.id == id)
    }

    /// The next signer expected to sign under the current policy, if any remain.
    ///
    /// For sequential policies this is the pending signer with the lowest `order`; for
    /// parallel policies it is any pending signer.
    pub fn next_expected_signer(&self) -> Option<&Signer> {
        self.expected_signers().into_iter().next()
    }

    /// Every pending signer allowed to act now. Sequential policies allow all pending signers
    /// that share the lowest `order` (equal orders sign in any order among themselves); parallel
    /// policies allow every pending signer. Empty once the envelope is complete or declined.
    pub fn expected_signers(&self) -> Vec<&Signer> {
        if self.is_declined() {
            return Vec::new();
        }
        let pending: Vec<&Signer> = self
            .signers
            .iter()
            .filter(|s| s.status == SignerStatus::Pending)
            .collect();
        match self.policy.signing_order {
            SigningOrder::Parallel => pending,
            SigningOrder::Sequential => {
                let Some(min) = pending.iter().map(|s| s.order).min() else {
                    return Vec::new();
                };
                pending.into_iter().filter(|s| s.order == min).collect()
            }
        }
    }

    /// True when every signer slot has signed.
    pub fn is_complete(&self) -> bool {
        !self.signers.is_empty()
            && self
                .signers
                .iter()
                .all(|s| s.status == SignerStatus::Signed)
    }

    /// True when any signer declined (the envelope is then void).
    pub fn is_declined(&self) -> bool {
        self.signers
            .iter()
            .any(|s| s.status == SignerStatus::Declined)
    }

    /// Digest over the canonical JSON of the envelope, used to bind the envelope state
    /// into a section signature.
    pub fn digest(&self) -> Result<String> {
        Ok(sha256_hex(serde_json::to_vec(self)?.as_slice()))
    }

    /// Digest over the envelope's **intent core** — everything except the mutable
    /// `signatures` and `audit_log` lists. A section signature binds this digest, which
    /// avoids the circularity of signing over the signature it is about to produce while
    /// still pinning the title, signer slots (status + bound keys), fields, and policy.
    pub fn core_digest(&self) -> Result<String> {
        let mut core = serde_json::json!({
            "schema_version": self.schema_version,
            "envelope_id": self.envelope_id,
            "title": self.title,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "source_digest": self.source_digest,
            "signers": self.signers,
            "fields": self.fields,
            "policy": self.policy,
        });
        if !self.documents.is_empty() {
            core["documents"] = serde_json::to_value(&self.documents)?;
        }
        Ok(sha256_hex(serde_json::to_vec(&core)?.as_slice()))
    }

    /// Append a new audit entry, chaining it to the previous one and signing it with the
    /// actor's key pair.
    pub fn append_audit(
        &mut self,
        action: AuditAction,
        actor: &crypto::KeyPair,
        actor_name: &str,
        details: &str,
        at: &str,
    ) {
        self.append_audit_with_consent(action, actor, actor_name, details, at, None);
    }

    /// [`Envelope::append_audit`] for a signer's entry that also records their consent to
    /// electronic records and signatures.
    pub fn append_audit_with_consent(
        &mut self,
        action: AuditAction,
        actor: &crypto::KeyPair,
        actor_name: &str,
        details: &str,
        at: &str,
        esign_consent: Option<EsignConsent>,
    ) {
        let seq = self.audit_log.len() as u32;
        let prev_hash = self
            .audit_log
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| AUDIT_GENESIS.to_string());
        let mut entry = AuditEntry {
            seq,
            action,
            actor_fingerprint: actor.fingerprint(),
            actor_name: actor_name.to_string(),
            at: at.to_string(),
            details: details.to_string(),
            prev_hash,
            entry_hash: String::new(),
            signature: None,
            esign_consent,
        };
        entry.entry_hash = sha256_hex(entry.canonical_content().as_bytes());
        entry.signature = Some(actor.sign(entry.entry_hash.as_bytes()));
        self.audit_log.push(entry);
    }

    /// Verify the integrity of the audit log: chain linkage, recomputed hashes, and each
    /// entry's signature.
    pub fn verify_audit_chain(&self) -> Result<()> {
        self.verify_audit_chain_with(&std::collections::HashMap::new())
    }

    /// Like [`Envelope::verify_audit_chain`] but accepts an extra fingerprint→public-key
    /// map (e.g. actors such as the preparer who are not in the signer list).
    ///
    /// Strict: every entry must carry a signature by a key the envelope (or `extra_keys`) knows.
    /// An unsigned entry or one by an unknown actor is an error, not silently accepted.
    pub fn verify_audit_chain_with(
        &self,
        extra_keys: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let mut prev = AUDIT_GENESIS.to_string();
        for (i, entry) in self.audit_log.iter().enumerate() {
            if entry.seq != i as u32 {
                return Err(SignPdfError::Verification(format!(
                    "audit entry {i} has wrong seq {}",
                    entry.seq
                )));
            }
            if entry.prev_hash != prev {
                return Err(SignPdfError::Verification(format!(
                    "audit chain broken at entry {i}"
                )));
            }
            let recomputed = sha256_hex(entry.canonical_content().as_bytes());
            if recomputed != entry.entry_hash {
                return Err(SignPdfError::Verification(format!(
                    "audit entry {i} hash mismatch (content was altered)"
                )));
            }
            let sig = entry.signature.as_ref().ok_or_else(|| {
                SignPdfError::Verification(format!("audit entry {i} is not signed"))
            })?;
            let pubkey = self
                .public_key_for_fingerprint(&entry.actor_fingerprint)
                .or_else(|| extra_keys.get(&entry.actor_fingerprint).cloned())
                .ok_or_else(|| {
                    SignPdfError::Verification(format!(
                        "audit entry {i} was signed by an unknown actor"
                    ))
                })?;
            // The key must actually be the one the fingerprint names.
            if crypto::fingerprint_of_public(&pubkey).ok().as_deref()
                != Some(entry.actor_fingerprint.as_str())
            {
                return Err(SignPdfError::Verification(format!(
                    "audit entry {i} actor key does not match its fingerprint"
                )));
            }
            crypto::verify(&pubkey, entry.entry_hash.as_bytes(), sig).map_err(|_| {
                SignPdfError::Verification(format!("audit entry {i} signature invalid"))
            })?;
            prev = entry.entry_hash.clone();
        }
        Ok(())
    }

    /// Look up a known public key for a fingerprint among signers and signatures.
    pub fn public_key_for_fingerprint(&self, fingerprint: &str) -> Option<String> {
        self.signers
            .iter()
            .find_map(|s| match (&s.fingerprint, &s.public_key) {
                (Some(fp), Some(pk)) if fp == fingerprint => Some(pk.clone()),
                _ => None,
            })
            .or_else(|| {
                self.signatures
                    .iter()
                    .find(|r| r.fingerprint == fingerprint)
                    .map(|r| r.public_key.clone())
            })
    }
}
