//! High-level signing workflow: prepare, sign, and verify.
//!
//! This is the **integrated** workflow: the self-describing envelope (signers, fields,
//! policy, signature records, hash-chained audit log) travels *inside* the PDF as an
//! embedded-file attachment, and every revision is a real **PAdES** signature applied as an
//! incremental update (see [`crate::pades`]):
//!
//! * the **preparer** signs the prepared document (pinning the envelope's *intent* — title, signer
//!   slots and their identity policies, fields, policy — under the preparer's verified identity);
//! * each **signer** (or decliner) appends one signed revision.
//!
//! Because every byte of the final file is covered by the last signature, and each revision is
//! replayed and checked against its predecessor ([`verify`]), the verifier detects: unsigned
//! appended updates, intent tampering between revisions, a signer altering another signer's
//! fields or slot, forged/rewritten audit history, and PDF-level content changes hidden in an
//! incremental update. Identities are re-validated offline and anchored in the verifier's
//! [`TrustStore`].

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::algorithms::{
    Algorithm, AlgorithmPolicy, AlgorithmPolicyStatus, AlgorithmUse, AlgorithmVerdict,
};
use crate::container;
use crate::crypto::{self, sha256_hex, KeyPair};
use crate::dates;
use crate::digest::DocumentDigests;
use crate::documents;
use crate::error::{Result, SignPdfError};
use crate::formats::FieldCheck;
use crate::formula;
use crate::initials::{self, InitialsRule};
use crate::ink::{self, SignatureDrawing};
use crate::ltv;
use crate::messages::{self as m, Finding, MessageCode, Severity};
use crate::model::{
    AuditAction, Envelope, EnvelopeDocument, EsignConsent, Field, FieldType, Policy, RecordKind,
    SignatureRecord, Signer, SignerStatus, TimestampPolicy,
};
use crate::numbers::NumberFormat;
use crate::oidc::{
    self, compute_nonce, Assessment, Basis, IdentityPolicy, Jwks, Level, Validation,
    VerifiedIdentity,
};
use crate::pades::{
    self, AddedAnnotation, Dss, EmbeddedFile, FieldMark, FieldText, InkRule, PadesScan,
    PadesValidation, SignAppearance, SignOptions, SignatureCaption, Timestamper,
};
use crate::schema;
use crate::trust::{IdentityCheck, IdentityTrust, SigningTimeEvidence, TrustStore};
use crate::util::{now_rfc3339, now_unix, rfc3339_from_unix, try_now_unix, unix_from_rfc3339};
use crate::SCHEMA_VERSION;

/// File name of the embedded workflow envelope inside the PDF.
pub const ENVELOPE_NAME: &str = "signpdf-envelope.json";

/// Allowed clock skew when checking token validity against a signing time.
const LEEWAY_SECS: i64 = 300;

/// A signer slot to create at preparation time. The signer's real identity is resolved at sign
/// time from a federated ID token that must satisfy `identity_policy`; only descriptive details,
/// order, and that policy are needed here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerSpec {
    pub id: String,
    pub name: String,
    pub handle: String,
    pub role: String,
    /// 1-based signing order. Equal orders may sign in any order among themselves.
    pub order: u32,
    /// Federated-identity policy the signer's verified ID token must satisfy (email / domain /
    /// issuer / assurance level). Defaults to "any verified identity" (`min_level` L1) when
    /// omitted.
    #[serde(default)]
    pub identity_policy: IdentityPolicy,
}

/// Everything needed to turn a source PDF into a prepared envelope. The preparer authenticates
/// with a federated provider; the host runs the OIDC flow (with `nonce == H(preparer_pubkey ‖
/// source_digest)`) and passes the resulting ID token and its JWK here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrepareRequest {
    pub title: String,
    pub signers: Vec<SignerSpec>,
    #[serde(default)]
    pub fields: Vec<Field>,
    pub policy: Policy,
    /// The preparer's federated ID token (compact JWS).
    #[serde(default)]
    pub id_token: String,
    /// The JWKS key (JSON) that signed `id_token`, archived for offline verification.
    #[serde(default)]
    pub idp_jwk: String,
    /// The relying-party `client_id` the token's `aud` must contain.
    #[serde(default)]
    pub audience: String,
    /// Issuers the preparer token may come from. Empty = trust the token's own issuer.
    #[serde(default)]
    pub allowed_issuers: Vec<String>,
    /// Optional link that opens the envelope in the service sending it ("open in ..."): an
    /// `https` URL ([`check_service_link`]). Kept in the envelope outside the prepared terms
    /// ([`Envelope::service_link`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_link: Option<String>,
    /// For an envelope of several documents, the index of the documents the source combines, as
    /// [`crate::documents::combine`] returns it: prepare checks that it covers every page of the
    /// source in order ([`crate::documents::check_index`]), and it becomes part of the prepared
    /// terms ([`Envelope::documents`]). Empty for an envelope of one document, which may also
    /// carry an index of one entry, to name it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub documents: Vec<EnvelopeDocument>,
    /// Optional short address of a verifier (`verify.example.com`, [`check_verify_at`]), drawn on
    /// the document-ID stamp as "Verify at <address>". Part of the prepared terms
    /// ([`Envelope::verify_at`], envelope schema version 7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_at: Option<String>,
}

/// A request to sign (or decline) a document.
///
/// The signer is **auto-resolved** from the verified ID token; `signer_id` is only an optional
/// assertion that must match the resolved slot. `#[serde(default)]` lets a host omit any field.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SignRequest {
    /// Optional **assertion** of which slot is being signed. Empty means "auto-resolve from the
    /// verified identity"; when set it must match the slot the identity resolves to.
    pub signer_id: String,
    /// `field_id` → value for non-signature fields. Dates are given as `YYYY-MM-DD` (and drawn
    /// in the field's `date_format`). Date fields left empty, and every *date signed* field
    /// (which takes no value), are filled with the signer's local signing date.
    pub field_values: Vec<(String, String)>,
    pub decline: bool,
    /// Optional human-readable reason shown in the signature dictionary (and the audit log).
    pub reason: Option<String>,
    /// Optional RFC 3161 timestamp token (base64) over the **pre-signing document digest**. It
    /// proves the document existed at that time; it is *not* used as the signing clock (a
    /// signature timestamp from [`sign_with`]'s timestamper is).
    pub timestamp_token: Option<String>,
    /// The signer's federated ID token (compact JWS), bound via `nonce == H(pubkey ‖ doc_digest)`.
    pub id_token: String,
    /// The JWKS key (JSON) that signed `id_token`.
    pub idp_jwk: String,
    /// The relying-party `client_id` the token's `aud` must contain.
    pub audience: String,
    /// Extra issuers the token may come from (in addition to per-slot policy). Empty = derive.
    pub allowed_issuers: Vec<String>,
    /// The signer's hand-drawn signature (pen strokes), drawn in their visible signature box
    /// beside the verified identity. Decoration only: it is not checked against anything and
    /// proves nothing about who signed. Ignored when the signer has no visible signature box or
    /// declines. From envelope schema version 6 their signature record keeps it
    /// ([`SignatureRecord::drawing`]).
    pub drawn_signature: Option<ink::InkStrokes>,
    /// The signer's typed signature: the glyph outlines of the name they typed, in the font they
    /// chose, made on their device ([`crate::ink::typed::typed_signature`], feature `typed`).
    /// Filled in their visible signature box beside the verified identity, and kept in their
    /// signature record, like `drawn_signature` (one or the other, not both). Decoration only:
    /// the typed name is not a claim about who signed, and the engine never sees it as text.
    /// Needs an envelope of schema version 6 or later. Ignored when the signer has no visible
    /// signature box or declines.
    pub typed_signature: Option<ink::InkPaths>,
    /// The signer's UTC offset in minutes at the time of signing, from their device (east of
    /// UTC is positive: `120` for UTC+02:00; in a browser, `-new Date().getTimezoneOffset()`).
    /// Dates the engine fills are the signer's local date at this offset, and the signature
    /// record keeps it (`utc_offset`). Between -720 and +840. Without it, dates are UTC dates.
    pub utc_offset_minutes: Option<i32>,
    /// The signer's consent to electronic records and signatures, as the host recorded it when
    /// they agreed to its disclosure: written into the signer's audit entry (signed or
    /// declined). The engine checks its form only ([`EsignConsent::validate`]).
    pub esign_consent: Option<EsignConsent>,
}

/// Outcome of checking an embedded RFC 3161 timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TimestampStatus {
    /// `signature` (PAdES B-T, over the signature value) or `document` (a PAdES document
    /// timestamp over the document, or the legacy token over the pre-signing document digest).
    pub kind: String,
    /// Authority-asserted time (RFC 3339); empty when the token could not be parsed.
    pub time: String,
    /// The token's message imprint matches what it should cover.
    pub verified: bool,
    /// The TSA's CMS signature verifies (and the certificate is a valid timestamping cert).
    pub signature_valid: bool,
    /// The TSA chains to an anchor in the verifier's trust store.
    pub trusted: bool,
    /// TSA certificate common name.
    pub tsa_name: String,
    /// Timestamp token serial number (hex).
    pub serial: String,
    /// Why the timestamp is not trusted, when it is not.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// Long-term validation of the TSA chain from the document's validation data (its DSS):
    /// `complete` (every chain certificate is in the DSS, and each but the anchor has evidence
    /// that it was not revoked when the timestamp was made), `incomplete`, or `revoked` (a chain
    /// certificate was revoked at or before the timestamp, which is then not trusted). Empty when
    /// the document has no validation data, or the timestamp is not trusted for another reason.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub validation: String,
    /// What the validation data says about each certificate of the TSA chain (the TSA's first,
    /// the anchor last), when the document has validation data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<ltv::ChainCertificate>,
    /// The algorithms its trust rests on (the imprint's digest, the authority's signature, the
    /// chain's certificate signatures), for the algorithm policy. Not reported.
    #[serde(skip)]
    pub algorithms: Vec<AlgorithmUse>,
    /// When the verifier's trust store distrusts the authority (a certificate of its chain) from
    /// a time at or before this timestamp: that time (RFC 3339). The timestamp is then not
    /// trusted. Empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub distrusted_after: String,
}

impl TimestampStatus {
    /// Usable as a trusted clock.
    pub fn is_trusted(&self) -> bool {
        self.verified && self.signature_valid && self.trusted
    }
}

/// Per-revision verification outcome (preparer, signer, or decliner).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignatureStatus {
    pub index: u32,
    /// `prepared`, `signed`, or `declined`.
    pub kind: String,
    /// The signer slot this revision fills (empty for the preparer).
    #[serde(default)]
    pub signer_id: String,
    pub actor_fingerprint: String,
    pub signed_at: String,
    /// Where the signing time comes from: `tsa` (trusted signature timestamp) or `device`
    /// (self-asserted clock of the signer's device, not independently confirmed).
    #[serde(default)]
    pub time_source: String,
    /// The identity token's issue time (`iat`, RFC 3339): the signature was made after it. The
    /// identity provider states it, so it is the earliest possible signing time, not a trusted
    /// one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_issued_at: String,
    /// The trusted latest possible signing time: the earliest trusted timestamp covering this
    /// revision (its own signature timestamp, a later revision's, or a document timestamp, such
    /// as the one a hosted service adds when the envelope ends). `None`: no trusted timestamp
    /// yet. Key validity windows are judged against it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existed_before: Option<ExistedBefore>,
    /// Cryptographically valid and consistent, **and** the identity is anchored in the trust
    /// store.
    pub valid: bool,
    pub detail: String,
    /// Signature (B-T) timestamp, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<TimestampStatus>,
    /// Document-existence timestamp supplied at signing (legacy `timestamp_token`), when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_timestamp: Option<TimestampStatus>,
    /// Verified email asserted by the signer's identity provider.
    #[serde(default)]
    pub idp_email: String,
    /// The provider that vouched for the signer (the token `iss`).
    #[serde(default)]
    pub idp_issuer: String,
    /// The assurance level the verifier computed for the identity (`L1` … `L5`), from the token
    /// and what the trust store says about its issuer: set when the identity is trusted (or
    /// accepted through the insecure dev opt-in), and when it is anchored but below its slot's
    /// requirement (`identity_trust` = `insufficient-level`). Never taken from the slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<Level>,
    /// The evidence the level rests on, with who vouched for each piece. Set with `level`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub basis: Vec<Basis>,
    /// How the verifier's trust store regards the identity (`trusted`, `insecure-dev`,
    /// `unknown-issuer`, `unknown-key`, `untrusted-audience`, and for keys with a validity window
    /// or issuers that require trusted time `no-trusted-time`, `outside-key-window`,
    /// `distrusted-key`; `algorithm-not-accepted` when the token relies on an algorithm the
    /// algorithm policy refuses; `insufficient-level` when a signer's computed level or evidence
    /// falls short of the slot: [`IdentityTrust`]), when it was checked.
    #[serde(default)]
    pub identity_trust: String,
    /// Short, human-comparable verification code (first 8 hex of the signer fingerprint). Matches
    /// the `Sig <code>` printed in the visible signature appearance, so a viewer can confirm the
    /// chrome they see corresponds to a cryptographically verified signature.
    #[serde(default)]
    pub signature_code: String,
    /// The signer's UTC offset when signing (`+02:00`), when their host recorded one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub utc_offset: String,
    /// `signed_at` at that offset: the signer's local time (`2026-11-02T11:14:03+02:00`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_signed_at: String,
    /// The signer's consent to electronic records and signatures, recorded in this revision's
    /// audit entry, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esign_consent: Option<EsignConsent>,
    /// What the signer's signature box shows beside the verified caption, from their signature
    /// record (envelope schema version 6 and later): `drawn` (pen strokes) or `typed` (the
    /// outlines of a typed name). Empty when nothing is drawn, and for older versions, which do
    /// not record it. Decoration either way: the caption, not the drawing, says who signed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub drawing: String,
}

/// Trusted evidence that a revision's signature existed by a time: a trusted RFC 3161 timestamp
/// made over it or over bytes that contain it. A timestamp at or after a signature in the file
/// covers that signature (each later signature signs the bytes before it, and a document
/// timestamp covers the whole file before it), so its time is an upper bound on when the
/// signature was made.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ExistedBefore {
    /// The timestamp's time (RFC 3339, as the authority states it).
    pub time: String,
    /// `signature`: the revision's own signature timestamp; `later-signature`: the signature
    /// timestamp of a later revision (`revision`); `document`: a document timestamp
    /// (`document_timestamp`).
    pub source: String,
    /// For `signature` and `later-signature`, the revision whose signature timestamp it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u32>,
    /// For `document`, the document timestamp's 1-based index
    /// ([`DocumentTimestampStatus::index`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_timestamp: Option<u32>,
    /// The time-stamp authority's certificate name.
    pub tsa_name: String,
}

/// A PAdES document timestamp (`/DocTimeStamp`): an RFC 3161 token over the whole document as
/// it was then, added after a signature by a host (at completion, or to renew older timestamps),
/// possibly with validation data (DSS) in the same increments.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DocumentTimestampStatus {
    /// 1-based position among the document's timestamps.
    pub index: u32,
    /// The last signed revision it covers (0 is the preparer's); every earlier one is covered too.
    pub after_revision: u32,
    /// Bytes of the document it covers.
    pub covered_len: u64,
    /// The increments it ends also added validation data (DSS).
    #[serde(default)]
    pub added_validation_data: bool,
    /// Sound, over exactly the bytes before it, and its increments hold only validation data and
    /// itself.
    pub valid: bool,
    /// The timestamp (kind `document`): its time, authority, trust and long-term validation.
    pub timestamp: TimestampStatus,
    /// What is wrong, when it is not valid.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// How much validation data (DSS) a document holds.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ValidationDataSummary {
    pub certificates: usize,
    pub ocsp_responses: usize,
    pub crls: usize,
}

/// Aggregate result of verifying a document.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerificationReport {
    /// Headline verdict: [`VerificationReport::integrity_ok`] **and** every identity is trusted.
    pub valid: bool,
    /// Cryptography, revision chain, audit log, order and expiry all check out (independent of
    /// whether the identity providers are trusted).
    pub integrity_ok: bool,
    /// Every identity (preparer and signers) is anchored in the verifier's trust store.
    pub identities_trusted: bool,
    /// The document is intact, and every identity that is not trusted is waiting only for a
    /// trusted timestamp (`identity_trust` = `no-trusted-time`): its key counts only with
    /// trusted time inside its validity window, and nothing covers its signature yet. Such an
    /// envelope still in progress is sound; a timestamp added before the keys' windows end (a
    /// later signature's, or a document timestamp) makes it valid. Show "no trusted timestamp
    /// yet" rather than "not trusted".
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trusted_time_pending: bool,
    /// Total length of the verified document, in bytes.
    pub original_len: usize,
    /// SHA-256 (hex) of the verified document.
    #[serde(default)]
    pub document_sha256: String,
    /// Every slot has signed.
    pub complete: bool,
    /// A signer declined; the envelope is void.
    #[serde(default)]
    pub declined: bool,
    pub audit_ok: bool,
    pub order_ok: bool,
    /// The preparer's revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preparer: Option<SignatureStatus>,
    /// One entry per signer/decliner revision, in signing order.
    pub signatures: Vec<SignatureStatus>,
    /// Reasons the document is not valid.
    pub messages: Vec<String>,
    /// Non-fatal concerns (permissive slot policies, insecure dev trust, …).
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Every entry of `messages` and `warnings`, in the order they were found, with its stable
    /// code ([`crate::messages`]) and the slot and revision it is about, so that a host can show
    /// it in the reader's language. The English text is the same as in those lists.
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// The link that opens the envelope in the service that sent it, as the preparer set it (a
    /// valid `https` URL), for an "open in ..." button. Never decides validity; a later
    /// revision's change to it is ignored here and reported as a warning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_link: Option<String>,
    /// PAdES document timestamps after the signatures, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub document_timestamps: Vec<DocumentTimestampStatus>,
    /// What the document's validation data (DSS) holds, when it has some.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_data: Option<ValidationDataSummary>,
    /// The PAdES baseline level the document reaches as a whole (ETSI EN 319 142-1): `B-B`;
    /// `B-T` when every signature has trusted time evidence (its own signature timestamp, or a
    /// later timestamp); `B-LT` when, in addition, the validation data holds complete revocation
    /// evidence for those timestamps' TSA chains; `B-LTA` when, in addition, every addition of
    /// validation data is covered by a trusted document timestamp. Empty when integrity failed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pades_level: String,
    /// The algorithm policy the verification applied: its version, whether it came from the
    /// trust list or is the engine's built-in one, and the time its end dates were judged at.
    #[serde(default)]
    pub algorithm_policy: AlgorithmPolicyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Envelope>,
}

impl VerificationReport {
    /// Record a finding that breaks the document's integrity.
    fn fail(&mut self, f: Finding) {
        self.integrity_ok = false;
        self.record(f);
    }

    /// Record a finding that an identity is not trusted.
    fn untrusted(&mut self, f: Finding) {
        self.identities_trusted = false;
        self.record(f);
    }

    /// Record a finding (an error in `messages`, a warning in `warnings`) and its code. Every
    /// entry of `messages` and `warnings` is written here.
    fn record(&mut self, f: Finding) {
        match f.severity {
            Severity::Warning => self.warnings.push(f.text.clone()),
            _ => self.messages.push(f.text.clone()),
        }
        self.findings.push(f);
    }
}

/// The texts of `findings`, joined for a revision's `detail`.
fn joined(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| f.text.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

/// `texts`, each a finding with `code`.
fn coded(
    code: &'static MessageCode,
    texts: impl IntoIterator<Item = String>,
) -> impl Iterator<Item = Finding> {
    texts.into_iter().map(move |t| Finding::new(code, t))
}

/// Read the latest embedded workflow envelope from a prepared/signed document.
///
/// Accepts every schema version this build supports ([`schema::decode_envelope`]); a version
/// newer than this build fails with [`SignPdfError::UnsupportedSchemaVersion`].
///
/// An envelope that is there but cannot be read (compressed bytes that no longer inflate) is a
/// [`SignPdfError::Encoding`]; anything else missing is "not a prepared SignPDF document".
pub fn read_envelope(pdf: &[u8]) -> Result<Envelope> {
    let bytes = pades::read_attachment(pdf, ENVELOPE_NAME).map_err(damaged_or_none)?;
    schema::decode_envelope(&bytes)
}

/// [`read_envelope`] of a revision already parsed.
fn envelope_in(parsed: &pades::ParsedRevision) -> Result<Envelope> {
    let bytes = parsed.attachment(ENVELOPE_NAME).map_err(damaged_or_none)?;
    schema::decode_envelope(&bytes)
}

fn no_envelope() -> SignPdfError {
    SignPdfError::Workflow("not a prepared SignPDF document (no embedded envelope)".into())
}

fn damaged_or_none(e: SignPdfError) -> SignPdfError {
    match e {
        SignPdfError::Encoding(m) => {
            SignPdfError::Encoding(format!("the document's envelope cannot be read: {m}"))
        }
        _ => no_envelope(),
    }
}

// --- prepare -------------------------------------------------------------------------------

/// Refuse a source document that already carries an envelope written by a newer build: this build
/// would overwrite terms it does not understand.
fn refuse_newer_envelope(source_pdf: &[u8]) -> Result<()> {
    let Ok(bytes) = pades::read_attachment(source_pdf, ENVELOPE_NAME) else {
        return Ok(());
    };
    match schema::peek_version(&bytes) {
        Ok(v) if schema::support(v) == schema::VersionSupport::Newer => {
            Err(schema::newer_version_error(v))
        }
        _ => Ok(()),
    }
}

/// Validate a prepare request against the source document.
fn validate_prepare_request(source_pdf: &[u8], request: &PrepareRequest) -> Result<()> {
    let wf = |m: String| Err(SignPdfError::Workflow(m));
    if request.title.trim().is_empty() {
        return wf("a document title is required".into());
    }
    if request.signers.is_empty() {
        return wf("at least one signer is required".into());
    }
    let mut ids: Vec<&str> = Vec::new();
    for s in &request.signers {
        if s.id.trim().is_empty() {
            return wf("every signer needs a non-empty id".into());
        }
        if ids.contains(&s.id.as_str()) {
            return wf(format!("duplicate signer id '{}'", s.id));
        }
        if s.order == 0 {
            return wf(format!(
                "signer '{}' has order 0 (orders are 1-based)",
                s.id
            ));
        }
        if let Err(e) = s.identity_policy.fillable_by_this_build() {
            return wf(format!("signer '{}' cannot be filled: the slot {e}", s.id));
        }
        ids.push(&s.id);
    }
    let geometry = pades::page_geometry(source_pdf)
        .map_err(|e| SignPdfError::Workflow(format!("source PDF cannot be parsed: {e}")))?;
    let pages = geometry.len() as u32;
    documents::check_index(&request.documents, pages)
        .map_err(|e| SignPdfError::Workflow(format!("the documents index is not valid: {e}")))?;
    let mut field_ids: Vec<&str> = Vec::new();
    for f in &request.fields {
        if field_ids.contains(&f.id.as_str()) {
            return wf(format!("duplicate field id '{}'", f.id));
        }
        field_ids.push(&f.id);
        if !ids.contains(&f.assigned_signer.as_str()) {
            return wf(format!(
                "field {} is assigned to unknown signer {}",
                f.id, f.assigned_signer
            ));
        }
        if f.page >= pages {
            return wf(format!(
                "field {} is on page index {} but the document has {pages} page(s)",
                f.id, f.page
            ));
        }
        let r = &f.rect;
        if !(r.w > 0.0 && r.h > 0.0 && r.x.is_finite() && r.y.is_finite()) {
            return wf(format!("field {} has an empty or invalid rectangle", f.id));
        }
        // The field must lie on the visible part of its page (0.5 pt tolerance for rounding).
        let crop = geometry[f.page as usize].crop_box;
        let [x1, y1, x2, y2] = field_rect(f);
        const TOL: f32 = 0.5;
        if x1 < crop[0] - TOL || y1 < crop[1] - TOL || x2 > crop[2] + TOL || y2 > crop[3] + TOL {
            return wf(format!(
                "field {} lies outside page {} (visible area {:?})",
                f.id,
                f.page + 1,
                crop
            ));
        }
        if f.value.is_some() {
            return wf(format!("field {} must not be pre-filled", f.id));
        }
        if f.label.as_deref().is_some_and(|l| l.chars().count() > 120) {
            return wf(format!(
                "field {} has a label longer than 120 characters",
                f.id
            ));
        }
        // A checkbox or radio option is meaningless without the statement it stands for.
        let captioned = f.label.as_deref().is_some_and(|l| !l.trim().is_empty());
        match f.field_type {
            FieldType::Checkbox if !captioned => {
                return wf(format!(
                    "checkbox {} needs a label: the text shown next to the box",
                    f.id
                ));
            }
            FieldType::Radio if !captioned => {
                return wf(format!(
                    "radio option {} needs a label: the text shown next to the button",
                    f.id
                ));
            }
            _ => {}
        }
        match (&f.group, f.field_type) {
            (Some(g), FieldType::Radio) if g.trim().is_empty() || g.chars().count() > 120 => {
                return wf(format!(
                    "radio option {} has an empty or over-long group name",
                    f.id
                ));
            }
            (None, FieldType::Radio) => {
                return wf(format!("radio option {} needs a group", f.id));
            }
            (Some(_), FieldType::Radio) | (None, _) => {}
            (Some(_), _) => {
                return wf(format!(
                    "field {} has a group, but only radio options are grouped",
                    f.id
                ));
            }
        }
        check_options(f).map_err(SignPdfError::Workflow)?;
        match (&f.number_format, f.field_type) {
            (None, FieldType::Number) => {
                return wf(format!(
                    "number field {} needs a number format (its decimal places)",
                    f.id
                ));
            }
            (Some(format), FieldType::Number) => {
                format
                    .validate()
                    .map_err(|e| SignPdfError::Workflow(format!("number field {} {e}", f.id)))?;
            }
            (None, FieldType::Formula) => {
                return wf(format!(
                    "formula field {} needs a number format (its decimal places)",
                    f.id
                ));
            }
            (Some(format), FieldType::Formula) => {
                format
                    .validate()
                    .map_err(|e| SignPdfError::Workflow(format!("formula field {} {e}", f.id)))?;
                // A computed value has no range: the signer could not correct one outside it.
                if format.min.is_some() || format.max.is_some() {
                    return wf(format!(
                        "formula field {} has a minimum or maximum, which only number fields have",
                        f.id
                    ));
                }
            }
            (Some(_), _) => {
                return wf(format!(
                    "field {} has a number format, but only number fields (and formula fields) do",
                    f.id
                ));
            }
            (None, _) => {}
        }
        match (&f.formula, f.field_type) {
            (None, FieldType::Formula) => {
                return wf(format!("formula field {} needs a formula", f.id));
            }
            (Some(_), t) if t != FieldType::Formula => {
                return wf(format!(
                    "field {} has a formula, but only formula fields do",
                    f.id
                ));
            }
            _ => {}
        }
        check_field_rules(f).map_err(SignPdfError::Workflow)?;
        if f.field_type != FieldType::Date && (f.date_format.is_some() || f.signing_date) {
            return wf(format!(
                "field {} has a date format or is marked as the signing date, but only date \
                 fields are",
                f.id
            ));
        }
    }
    // Radio groups: at least two options, one signer, one `required` setting, distinct captions.
    let radios: Vec<&Field> = request
        .fields
        .iter()
        .filter(|f| f.field_type == FieldType::Radio)
        .collect();
    for (i, f) in radios.iter().enumerate() {
        let group = f.group.as_deref().unwrap_or_default();
        let members: Vec<&&Field> = radios
            .iter()
            .filter(|o| o.group.as_deref() == Some(group))
            .collect();
        if members.len() < 2 {
            return wf(format!("radio group '{group}' needs at least two options"));
        }
        let first = members[0];
        if f.assigned_signer != first.assigned_signer {
            return wf(format!(
                "radio group '{group}' is split between signers {} and {}",
                first.assigned_signer, f.assigned_signer
            ));
        }
        if f.required != first.required {
            return wf(format!(
                "radio group '{group}' mixes required and optional options"
            ));
        }
        let caption = f.label.as_deref().map(str::trim);
        if radios[..i].iter().any(|o| {
            o.group.as_deref() == Some(group) && o.label.as_deref().map(str::trim) == caption
        }) {
            return wf(format!(
                "radio group '{group}' has two options labelled '{}'",
                caption.unwrap_or_default()
            ));
        }
    }
    // Formula fields: readable formulas over known number inputs of the same or an earlier
    // signer, every option of a choice they read given a number, no loops.
    formula::check_formula_fields(
        &request.fields,
        |id| request.signers.iter().find(|s| s.id == id).map(|s| s.order),
        request.policy.signing_order,
    )
    .map_err(|e| SignPdfError::Workflow(format!("{e} ({})", e.code)))?;
    if let Some(exp) = &request.policy.expiry {
        let t = unix_from_rfc3339(exp).ok_or_else(|| {
            SignPdfError::Workflow(format!("policy expiry '{exp}' is not an RFC 3339 time"))
        })?;
        if t <= now_unix() {
            return wf(format!("policy expiry {exp} is already in the past"));
        }
    }
    if let Some(link) = &request.service_link {
        check_service_link(link).map_err(SignPdfError::Workflow)?;
    }
    if let Some(address) = &request.verify_at {
        check_verify_at(address).map_err(SignPdfError::Workflow)?;
    }
    Ok(())
}

/// The longest 'verify at' address accepted, in characters.
pub const MAX_VERIFY_AT_LEN: usize = 40;

/// Check a 'verify at' address ([`Envelope::verify_at`]): a short address a reader types, written
/// without a scheme: a DNS name of at least two labels in lower case (`verify.example.com`, an
/// internationalized name in its `xn--` form), optionally followed by a path of lower-case
/// letters, digits, `-`, `.`, `_` and `/` (`example.com/verify`), [`MAX_VERIFY_AT_LEN`]
/// characters at most. The stamp draws it as it is.
pub fn check_verify_at(address: &str) -> std::result::Result<(), String> {
    let bad = |why: &str| {
        Err(format!(
            "the 'verify at' address '{address}' is not usable: {why}"
        ))
    };
    if address.is_empty() || address.len() > MAX_VERIFY_AT_LEN {
        return bad(&format!("it must be 1 to {MAX_VERIFY_AT_LEN} characters"));
    }
    let (host, path) = match address.split_once('/') {
        Some((h, p)) => (h, Some(p)),
        None => (address, None),
    };
    let labels: Vec<&str> = host.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if labels.len() < 2 || !labels.iter().all(label_ok) {
        return bad("write a lower-case host name such as verify.example.com, without https://");
    }
    if let Some(p) = path {
        if !p.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b'_' | b'/')
        }) {
            return bad("its path may hold only lower-case letters, digits, '-', '.', '_' and '/'");
        }
    }
    Ok(())
}

/// The lines of the document-ID stamp of `env`: the document id and, from envelope schema version
/// 7 when the preparer named one, the 'verify at' address. Versions before 7 always draw the
/// first line alone, so their stamps verify unchanged.
pub fn document_id_lines(env: &Envelope) -> Vec<String> {
    let mut lines = vec![format!("SignPDF Document {}", env.envelope_id)];
    if env.schema_version >= 7 {
        if let Some(address) = &env.verify_at {
            lines.push(format!("Verify at {address}"));
        }
    }
    lines
}

/// The longest service link accepted, in bytes.
pub const MAX_SERVICE_LINK_LEN: usize = 512;

/// Check an envelope's service link ([`Envelope::service_link`]): an absolute `https` URL of at
/// most [`MAX_SERVICE_LINK_LEN`] bytes, printable ASCII without spaces (an internationalized
/// host in its `xn--` form), whose host is a DNS name or IPv4 address with an optional port and
/// no user name or password, so the host a viewer is shown is the one the link opens.
pub fn check_service_link(link: &str) -> std::result::Result<(), String> {
    let bad = |why: &str| Err(format!("the service link '{link}' is not usable: {why}"));
    if link.len() > MAX_SERVICE_LINK_LEN {
        return bad(&format!("it is longer than {MAX_SERVICE_LINK_LEN} bytes"));
    }
    if !link.bytes().all(|b| b.is_ascii_graphic())
        || link
            .chars()
            .any(|c| matches!(c, '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}'))
    {
        return bad(
            "it holds a space, a control or non-ASCII character, or one of \" < > \\ ^ ` { | }",
        );
    }
    let Some(rest) = link.strip_prefix("https://") else {
        return bad("it does not start with https:// (in lower case)");
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return bad("it names a user or password before the host");
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if let Some(p) = port {
        if p.is_empty()
            || p.len() > 5
            || !p.bytes().all(|b| b.is_ascii_digit())
            || !(1..=65535).contains(&p.parse::<u32>().unwrap_or(0))
        {
            return bad("its port is not a number from 1 to 65535");
        }
    }
    let labels_ok = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !labels_ok {
        return bad("its host is not a DNS name or an IPv4 address");
    }
    Ok(())
}

/// Prepare a source PDF for signing, returning the prepared document bytes: the source with a
/// visible document-id stamp and the workflow envelope embedded, **signed by the preparer**.
///
/// The preparer authenticates with a federated provider: the host runs the OIDC flow and passes
/// the resulting ID token and its JWK in `request`. `preparer_key` is an **ephemeral** signing
/// key the host generated for this document; the token is stapled to it via the `nonce` binding.
pub fn prepare(
    source_pdf: &[u8],
    request: &PrepareRequest,
    preparer_key: &KeyPair,
) -> Result<Vec<u8>> {
    prepare_inner(source_pdf, request, preparer_key, &|_| {})
}

/// [`prepare`], with `tamper` applied to the envelope before it is embedded and signed (for the
/// tests of a modified preparing client).
fn prepare_inner(
    source_pdf: &[u8],
    request: &PrepareRequest,
    preparer_key: &KeyPair,
    tamper: &dyn Fn(&mut Envelope),
) -> Result<Vec<u8>> {
    if !container::is_pdf(source_pdf) {
        return Err(SignPdfError::Workflow(
            "source document is not a PDF (convert Word to PDF first)".into(),
        ));
    }
    // An envelope, all its documents together, signs within the memory of a phone browser; a
    // larger one is not even parsed.
    documents::check_size(source_pdf.len(), "the source document is")?;
    // Then, before anything else: a document from a newer build is a reason to update, whatever
    // the request says.
    refuse_newer_envelope(source_pdf)?;
    validate_prepare_request(source_pdf, request)?;

    let source_digest = sha256_hex(source_pdf);

    // Authenticate the preparer with their federated ID token (no self-asserted identity).
    let identity = validate_preparer_token(request, preparer_key, &source_digest)?;

    let signers = request
        .signers
        .iter()
        .map(|s| Signer {
            id: s.id.clone(),
            name: s.name.clone(),
            handle: s.handle.clone(),
            role: s.role.clone(),
            order: s.order,
            status: SignerStatus::Pending,
            identity_policy: s.identity_policy.clone(),
            public_key: None,
            fingerprint: None,
        })
        .collect();

    let now = now_rfc3339();
    let mut envelope = Envelope {
        schema_version: SCHEMA_VERSION,
        envelope_id: crypto::random_id(),
        title: request.title.clone(),
        created_by: identity.email.clone(),
        created_at: now.clone(),
        created_by_pubkey: preparer_key.public_b64(),
        created_by_id_token: request.id_token.clone(),
        created_by_idp_jwk: request.idp_jwk.clone(),
        created_by_issuer: identity.issuer.clone(),
        created_by_email: identity.email.clone(),
        created_by_audience: request.audience.clone(),
        source_digest,
        source_len: source_pdf.len() as u64,
        documents: request.documents.clone(),
        signers,
        fields: request.fields.clone(),
        policy: request.policy.clone(),
        signatures: Vec::new(),
        audit_log: Vec::new(),
        service_link: request.service_link.clone(),
        verify_at: request.verify_at.clone(),
        // Every envelope this build prepares is of SCHEMA_VERSION (9), which names its rule.
        initials_rule: Some(InitialsRule::NameV1),
    };
    tamper(&mut envelope);

    let actor_name = display_name(&identity);
    envelope.append_audit(
        AuditAction::Prepared,
        preparer_key,
        &actor_name,
        &format!(
            "prepared '{}'{} for {} signer(s); preparer verified as {} via {}",
            request.title,
            match request.documents.len() {
                0 | 1 => String::new(),
                n => format!(" ({n} documents)"),
            },
            request.signers.len(),
            identity.email,
            identity.issuer,
        ),
        &now,
    );

    // Stamp a visible, read-only SignPDF document id onto the first page, then embed the envelope
    // and sign the result as the preparer, so the envelope's intent is fixed under the preparer's
    // verified identity before any signer sees it.
    let stamped = pades::stamp_document_id_lines(source_pdf, &document_id_lines(&envelope))
        .map_err(|e| SignPdfError::Workflow(format!("stamping document id failed: {e}")))?;
    let opts = SignOptions {
        appearance: SignAppearance {
            name: actor_name,
            reason: Some("Prepared for signing (SignPDF)".to_string()),
            ..Default::default()
        },
        embed: Some(envelope_attachment(&envelope)?),
        ..Default::default()
    };
    pades::pades_sign_with(&stamped, preparer_key, &opts)
        .map_err(|e| SignPdfError::Workflow(format!("preparer signature failed: {e}")))
}

// --- sign ----------------------------------------------------------------------------------

/// Sign (or decline) a document, returning the updated document bytes.
///
/// `signer_key` is an **ephemeral** signing key the host generated for this signature. The
/// signer's identity is **auto-resolved** from the federated ID token in `request` (no
/// self-selection); the token is stapled to `signer_key` and this document via the `nonce`
/// binding, validated, then matched against the signer slots' identity policies.
///
/// The envelope's [`TimestampPolicy`] (`policy.signature_timestamps`, fixed by the preparer)
/// decides about a PAdES B-T signature timestamp:
///
/// * `required`: the signature is made with room for one, as by [`sign_for_timestamp`], and the
///   host adds it next with [`signature_timestamp_digest`] and [`embed_signature_timestamp`]. The
///   result is already a complete B-B signature, which is what stays if no time-stamp authority
///   answers (the verifier then warns that its signing time is the device clock).
/// * `optional` (every envelope that states no policy): a B-B signature with no room for one;
///   [`sign_with`] and [`sign_for_timestamp`] add one.
/// * `none`: a B-B signature with no room for one, dated by the device clock. [`sign_with`] with
///   a timestamper and [`sign_for_timestamp`] are refused.
pub fn sign(pdf: &[u8], signer_key: &KeyPair, request: &SignRequest) -> Result<Vec<u8>> {
    sign_with(pdf, signer_key, request, None)
}

/// [`sign`] with an optional RFC 3161 [`Timestamper`]: when given, the signature carries a PAdES
/// B-T signature timestamp, which verifiers use as a trusted signing clock. Refused on an envelope
/// whose policy is [`TimestampPolicy::None`]; without a timestamper it is [`sign`].
pub fn sign_with(
    pdf: &[u8],
    signer_key: &KeyPair,
    request: &SignRequest,
    timestamper: Option<&dyn Timestamper>,
) -> Result<Vec<u8>> {
    let host = match timestamper {
        Some(t) => HostTimestamp::Now(t),
        None => HostTimestamp::Nothing,
    };
    sign_inner(pdf, signer_key, request, host, true, &|_| {}, &|_| {})
        .map(|increment| pades::appended(pdf, &increment))
}

/// [`sign`] for a host whose RFC 3161 client is asynchronous (the browser signer, where a TSA
/// request is a `fetch`): the signature leaves room for a PAdES B-T signature timestamp that the
/// host adds afterwards. The result is a complete, valid B-B signature. Then:
///
/// 1. [`signature_timestamp_digest`] gives the imprint to timestamp
///    ([`crate::timestamp::build_request`] makes the TSA request);
/// 2. [`embed_signature_timestamp`] adds the token.
///
/// Neither step needs the signing key, which this call consumes like [`sign`]: the hash of the
/// signature value is all a TSA sees, and a failed or slow TSA never requires a new sign-in.
///
/// On an envelope whose policy is `required`, [`sign`] does the same. On one whose policy is
/// [`TimestampPolicy::None`] this is refused before anything is signed: sign with [`sign`].
pub fn sign_for_timestamp(
    pdf: &[u8],
    signer_key: &KeyPair,
    request: &SignRequest,
) -> Result<Vec<u8>> {
    sign_for_timestamp_increment(pdf, signer_key, request)
        .map(|increment| pades::appended(pdf, &increment))
}

/// [`sign`], returning only the increment: the bytes the signature appends to `pdf`. The signed
/// document is `pdf` followed by them ([`pades::appended`]). A host that uploads only the
/// increment, as the hosted service's signing page does, never holds the signed document: in a
/// browser this keeps signing at about the document's size in memory instead of twice it.
pub fn sign_increment(pdf: &[u8], signer_key: &KeyPair, request: &SignRequest) -> Result<Vec<u8>> {
    sign_inner(
        pdf,
        signer_key,
        request,
        HostTimestamp::Nothing,
        true,
        &|_| {},
        &|_| {},
    )
}

/// [`sign_for_timestamp`], returning only the increment, as [`sign_increment`] does. Add the
/// timestamp with [`increment_signature_timestamp_digest`] and
/// [`embed_increment_signature_timestamp`], which take the document and the increment apart.
pub fn sign_for_timestamp_increment(
    pdf: &[u8],
    signer_key: &KeyPair,
    request: &SignRequest,
) -> Result<Vec<u8>> {
    sign_inner(
        pdf,
        signer_key,
        request,
        HostTimestamp::Later,
        true,
        &|_| {},
        &|_| {},
    )
}

/// The SHA-256 imprint that a PAdES B-T signature timestamp of `pdf`'s last revision must carry
/// (the hash of its signature value): the first step of adding a timestamp after
/// [`sign_for_timestamp`], or after [`sign`] on a `required` envelope. Build the TSA request with
/// [`crate::timestamp::build_request`], then add the token with [`embed_signature_timestamp`].
///
/// This is [`pades::signature_timestamp_digest`] with the envelope's rules on top. It is refused
/// when the envelope's policy is [`TimestampPolicy::None`], so a host never asks a time-stamp
/// authority for a timestamp such an envelope does not take, and when the last revision is the
/// preparer's, which is never timestamped. The last signature must be valid, cover the whole file
/// and have no timestamp yet.
pub fn signature_timestamp_digest(pdf: &[u8]) -> Result<[u8; 32]> {
    check_timestamp_allowed(pdf)?;
    pades::signature_timestamp_digest(pdf)
}

/// Add an RFC 3161 signature timestamp (`token`, a DER `TimeStampToken` over
/// [`signature_timestamp_digest`]) to `pdf`'s last revision, which must have been signed with room
/// for one. The output has the same length and only that revision changes, from B-B to B-T. Needs
/// no key.
///
/// This is [`pades::embed_signature_timestamp`] with the envelope's rules on top, as for
/// [`signature_timestamp_digest`].
pub fn embed_signature_timestamp(pdf: &[u8], token: &[u8]) -> Result<Vec<u8>> {
    check_timestamp_allowed(pdf)?;
    pades::embed_signature_timestamp(pdf, token)
}

/// [`signature_timestamp_digest`] for a document held apart: `head`, the document that was
/// signed, and `increment`, the bytes [`sign_for_timestamp_increment`] (or [`sign_increment`] on a
/// `required` envelope) appended to it. Neither is copied into a whole document: a host that
/// uploads only the increment never needs one.
///
/// The same rules apply: refused when the envelope's policy is [`TimestampPolicy::None`] (read
/// from `head`'s envelope, which the preparer fixed), and unless `head` is a prepared document, so
/// the increment's signature is a signer's. The increment must end with a SignPDF signature that
/// is valid over `head` and the increment, covers both to their end and has no timestamp yet
/// ([`pades::increment_signature_timestamp_digest`]).
pub fn increment_signature_timestamp_digest(head: &[u8], increment: &[u8]) -> Result<[u8; 32]> {
    check_timestamp_allowed_after(head)?;
    pades::increment_signature_timestamp_digest(&DocumentDigests::new(head), increment)
}

/// [`embed_signature_timestamp`] for a document held apart, as
/// [`increment_signature_timestamp_digest`]: adds `token` to the signature at the end of
/// `increment` and returns the new increment, the same length. Only the signature's `/Contents`
/// changes, outside its signed range.
pub fn embed_increment_signature_timestamp(
    head: &[u8],
    increment: &[u8],
    token: &[u8],
) -> Result<Vec<u8>> {
    check_timestamp_allowed_after(head)?;
    pades::embed_increment_signature_timestamp(&DocumentDigests::new(head), increment, token)
}

/// Refuse a signature timestamp on a revision appended to `head` that the envelope does not take:
/// any under [`TimestampPolicy::None`]. `head` must carry an envelope (a prepared document), so
/// what is appended to it is a signer's revision, never the preparer's.
fn check_timestamp_allowed_after(head: &[u8]) -> Result<()> {
    let env = read_envelope(head)?;
    if env.policy.signature_timestamps == TimestampPolicy::None {
        return Err(no_timestamps_error());
    }
    Ok(())
}

/// Refuse a signature timestamp the envelope does not take: any under [`TimestampPolicy::None`],
/// and one on the preparer's revision.
fn check_timestamp_allowed(pdf: &[u8]) -> Result<()> {
    let env = read_envelope(pdf)?;
    if env.policy.signature_timestamps == TimestampPolicy::None {
        return Err(no_timestamps_error());
    }
    if env.signatures.is_empty() {
        return Err(SignPdfError::Workflow(
            "the last revision is the preparer's, and only signer revisions take a signature \
             timestamp"
                .into(),
        ));
    }
    Ok(())
}

/// The refusal of a signature timestamp on an envelope whose policy is
/// [`TimestampPolicy::None`].
fn no_timestamps_error() -> SignPdfError {
    SignPdfError::Workflow(
        "this envelope takes no signature timestamps (its policy is signature_timestamps = \
         none): sign without one, and the signing time is the signer's device clock"
            .into(),
    )
}

/// Refuse to `action` on a document whose integrity is broken (identities aside, which need no
/// trust store for this).
fn require_integrity(pdf: &[u8], action: &str) -> Result<()> {
    require_integrity_with(&DocumentDigests::new(pdf), action)
}

/// [`require_integrity`] of the document `digests` hashes, reusing (and filling) its digests.
fn require_integrity_with(digests: &DocumentDigests<'_>, action: &str) -> Result<()> {
    let integrity = verify_inner(digests, &TrustStore::empty(), None)?;
    if integrity.integrity_ok {
        Ok(())
    } else {
        Err(SignPdfError::Workflow(format!(
            "refusing to {action}: the document failed its integrity check ({})",
            integrity.messages.join("; ")
        )))
    }
}

// --- document timestamps and validation data (PAdES B-LT / B-LTA) --------------------------

/// Add a PAdES document timestamp to a SignPDF document, in two steps for a host whose RFC 3161
/// client is asynchronous: this appends the timestamp's increment with room for the token and
/// returns it with the SHA-256 the token must carry ([`crate::timestamp::build_request`] makes the
/// request); [`embed_document_timestamp`] then adds the token. [`add_document_timestamp`] does
/// both with a synchronous [`Timestamper`].
///
/// A document timestamp proves that the whole document, every revision so far, existed at the
/// authority's time. A host adds one when an envelope reaches a final state (the only trusted
/// time of an envelope whose signatures carry none, `signature_timestamps = none`), after
/// validation data ([`add_validation_data`], PAdES B-LTA), or to renew older timestamps. It is
/// allowed whatever the envelope's signature-timestamp policy, and on an envelope still open:
/// the next signer signs the timestamped document.
///
/// Refused when the document fails its integrity check, so nothing is ever timestamped on top of
/// a broken document: everything up to its last signature or document timestamp must verify,
/// and what follows may only be the validation data [`add_validation_data`] added (which this
/// timestamp then covers). The increment holds no date and is the same for the same input.
pub fn prepare_document_timestamp(pdf: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    const ACTION: &str = "add a document timestamp";
    read_envelope(pdf)?;
    let scan =
        pades::pades_verify_all(pdf).map_err(|e| SignPdfError::Verification(e.to_string()))?;
    let last_end = boundaries(&scan).last().map_or(0, |(end, _)| *end);
    if last_end == 0 || last_end > pdf.len() {
        require_integrity(pdf, ACTION)?;
    }
    require_integrity(&pdf[..last_end], ACTION)?;
    let (prepared, digest) = pades::prepare_document_timestamp(pdf)?;
    // What the timestamp will cover after the last signature: only validation data and itself.
    let audit = pades::audit_ltv_increment(&pdf[..last_end], &prepared)?;
    if !audit.violations.is_empty() {
        return Err(SignPdfError::Workflow(format!(
            "refusing to {ACTION}: what follows the last signature is not only validation data              ({})",
            audit.violations.join("; ")
        )));
    }
    Ok((prepared, digest))
}

/// Add the time-stamp authority's token (a DER `TimeStampToken` over the digest
/// [`prepare_document_timestamp`] returned) to the document it prepared. The output has the same
/// length. Refused when the token is for another digest.
pub fn embed_document_timestamp(pdf: &[u8], token: &[u8]) -> Result<Vec<u8>> {
    read_envelope(pdf)?;
    pades::embed_document_timestamp(pdf, token)
}

/// [`prepare_document_timestamp`] then [`embed_document_timestamp`], with a synchronous
/// time-stamp authority.
pub fn add_document_timestamp(pdf: &[u8], timestamper: &dyn Timestamper) -> Result<Vec<u8>> {
    let (prepared, digest) = prepare_document_timestamp(pdf)?;
    let token = timestamper.timestamp(&digest)?;
    embed_document_timestamp(&prepared, &token)
}

/// A certificate of a TSA chain whose revocation status a document's validation data does not
/// hold yet: what a host fetches so that the document's timestamps stay verifiable for the long
/// term (PAdES B-LT). Fetch the OCSP response (POST `ocsp_request` with `Content-Type:
/// application/ocsp-request` to an `ocsp_urls` address) or else the CRL (GET a `crl_urls`
/// address), then pass what came back to [`add_validation_data`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationTarget {
    /// The certificate's subject common name, for logs.
    pub subject: String,
    /// The certificate (DER).
    pub cert: Vec<u8>,
    /// Its issuer's certificate (DER).
    pub issuer: Vec<u8>,
    /// The OCSP responders the certificate names (http or https).
    pub ocsp_urls: Vec<String>,
    /// The CRLs the certificate names (http or https).
    pub crl_urls: Vec<String>,
    /// A DER OCSP request for it ([`ltv::ocsp_request`]).
    pub ocsp_request: Vec<u8>,
}

/// The TSA chains of `scan`'s trusted timestamps (signature and document timestamps), each with
/// the time the timestamp was made.
fn trusted_timestamp_chains(scan: &PadesScan, trust: &TrustStore) -> Vec<(i64, Vec<Vec<u8>>)> {
    use sha2::{Digest, Sha256};
    let mut tokens: Vec<(&[u8], Vec<u8>)> = Vec::new();
    for s in &scan.signatures {
        if let Some(t) = s.signature_timestamp.as_deref() {
            tokens.push((t, Sha256::digest(&s.signature_value).to_vec()));
        }
    }
    for d in scan.document_timestamps.iter().filter(|d| d.is_valid()) {
        if let Ok((_, imprint)) = crate::timestamp::token_imprint(&d.token) {
            tokens.push((&d.token, imprint));
        }
    }
    let mut out = Vec::new();
    for (token, digest) in tokens {
        let Ok(info) = crate::timestamp::verify_token(token, &digest) else {
            continue;
        };
        let Some(when) = unix_from_rfc3339(&info.gen_time) else {
            continue;
        };
        let tsa = trust.verify_tsa(token, when);
        if tsa.trusted {
            out.push((when, tsa.chain));
        }
    }
    out
}

/// What to fetch so that every trusted timestamp of `pdf` (signature and document timestamps)
/// has revocation evidence in its validation data: one [`RevocationTarget`] per TSA chain
/// certificate (anchors aside) that the document's DSS holds no evidence for yet, covering the
/// latest timestamp it vouches for. Empty when there is nothing to fetch. Timestamps the trust
/// store does not trust are left out.
pub fn revocation_targets(pdf: &[u8], trust: &TrustStore) -> Result<Vec<RevocationTarget>> {
    let scan =
        pades::pades_verify_all(pdf).map_err(|e| SignPdfError::Verification(e.to_string()))?;
    let dss = scan.dss.clone().unwrap_or_default();
    // Each certificate, its issuer, and the latest time it vouches for.
    let mut certs: Vec<(Vec<u8>, Vec<u8>, i64)> = Vec::new();
    for (when, chain) in trusted_timestamp_chains(&scan, trust) {
        for pair in chain.windows(2) {
            match certs.iter_mut().find(|(c, _, _)| *c == pair[0]) {
                Some(entry) => entry.2 = entry.2.max(when),
                None => certs.push((pair[0].clone(), pair[1].clone(), when)),
            }
        }
    }
    let mut out = Vec::new();
    for (cert, issuer, when) in certs {
        let covered = dss
            .ocsps
            .iter()
            .filter_map(|o| ltv::check_ocsp(o, &cert, &issuer).ok())
            .chain(
                dss.crls
                    .iter()
                    .filter_map(|c| ltv::check_crl(c, &cert, &issuer).ok()),
            )
            .any(|e| e.covers(when) || matches!(e.state, ltv::RevocationState::Revoked { .. }));
        if covered {
            continue;
        }
        let ocsp_request = ltv::ocsp_request(&cert, &issuer).map_err(SignPdfError::Workflow)?;
        out.push(RevocationTarget {
            subject: ltv::subject_name(&cert),
            ocsp_urls: ltv::ocsp_urls(&cert),
            crl_urls: ltv::crl_urls(&cert),
            ocsp_request,
            cert,
            issuer,
        });
    }
    Ok(out)
}

/// Add validation data for `pdf`'s trusted timestamps (PAdES B-LT): every certificate of their
/// TSA chains, anchors included, and the OCSP responses and CRLs the host fetched for them
/// ([`revocation_targets`]), in one DSS increment. A document timestamp must follow
/// ([`prepare_document_timestamp`]): validation data that no document timestamp covers is an
/// unsigned change, and verification fails until one does.
///
/// Every response and CRL is checked first, and the call fails if one is not about a
/// certificate of those chains or is not signed by its issuer (or, for OCSP, by a responder the
/// issuer delegated), so nothing else ever goes into a document. Data the document already
/// holds is not repeated; when nothing is new, `pdf` comes back unchanged. Refused when the
/// document fails its integrity check or has no timestamp `trust` trusts.
pub fn add_validation_data(
    pdf: &[u8],
    trust: &TrustStore,
    ocsp_responses: &[Vec<u8>],
    crls: &[Vec<u8>],
) -> Result<Vec<u8>> {
    read_envelope(pdf)?;
    require_integrity(pdf, "add validation data")?;
    let scan =
        pades::pades_verify_all(pdf).map_err(|e| SignPdfError::Verification(e.to_string()))?;
    let chains = trusted_timestamp_chains(&scan, trust);
    if chains.is_empty() {
        return Err(SignPdfError::Workflow(
            "the document has no timestamp that the trust store trusts, so there is no \
             validation data to add"
                .into(),
        ));
    }
    let mut add = Dss::default();
    let mut pairs: Vec<(&[u8], &[u8])> = Vec::new();
    for (_, chain) in &chains {
        for c in chain {
            if !add.certs.contains(c) {
                add.certs.push(c.clone());
            }
        }
        for pair in chain.windows(2) {
            pairs.push((&pair[0], &pair[1]));
        }
    }
    // Each item must be evidence about one of those certificates, checked against its issuer.
    type EvidenceCheck = fn(&[u8], &[u8], &[u8]) -> std::result::Result<ltv::Evidence, String>;
    let lists: [(&[Vec<u8>], &str, EvidenceCheck); 2] = [
        (ocsp_responses, "OCSP response", ltv::check_ocsp),
        (crls, "CRL", ltv::check_crl),
    ];
    for (k, (items, what, check)) in lists.into_iter().enumerate() {
        for (n, item) in items.iter().enumerate() {
            let mut why = "it is about no certificate of the document's TSA chains".to_string();
            if !pairs
                .iter()
                .any(|(cert, issuer)| match check(item, cert, issuer) {
                    Ok(_) => true,
                    Err(e) => {
                        why = e;
                        false
                    }
                })
            {
                return Err(SignPdfError::Workflow(format!(
                    "{what} {} is not evidence for this document's timestamps: {why}",
                    n + 1
                )));
            }
            if k == 0 {
                add.ocsps.push(item.clone());
            } else {
                add.crls.push(item.clone());
            }
        }
    }
    pades::add_validation_data(pdf, &add)
}

/// What the host offers for a signature timestamp. The envelope's [`TimestampPolicy`] decides
/// what is used ([`timestamp_plan`]).
#[derive(Clone, Copy)]
enum HostTimestamp<'a> {
    /// Nothing now ([`sign`]).
    Nothing,
    /// Room for a timestamp that the host adds afterwards ([`sign_for_timestamp`]).
    Later,
    /// A synchronous time-stamp authority ([`sign_with`]).
    Now(&'a dyn Timestamper),
}

/// The timestamper to sign with, and whether to leave room for a signature timestamp, for a
/// signer revision of an envelope with `policy` when the host offers `host`.
fn timestamp_plan(
    policy: TimestampPolicy,
    host: HostTimestamp<'_>,
) -> Result<(Option<&dyn Timestamper>, bool)> {
    match (policy, host) {
        (TimestampPolicy::None, HostTimestamp::Nothing) => Ok((None, false)),
        (TimestampPolicy::None, _) => Err(no_timestamps_error()),
        (_, HostTimestamp::Now(t)) => Ok((Some(t), true)),
        (_, HostTimestamp::Later) | (TimestampPolicy::Required, HostTimestamp::Nothing) => {
            Ok((None, true))
        }
        (TimestampPolicy::Optional, HostTimestamp::Nothing) => Ok((None, false)),
    }
}

/// Envelope mutation hook (identity for production signing; tests use it to play a malicious
/// signer).
type EnvelopeHook<'a> = &'a dyn Fn(&mut Envelope);

/// Hook on what gets drawn (identity for production signing; tests use it to play a signing
/// client that draws something other than what the engine would).
type DrawingHook<'a> = &'a dyn Fn(&mut SignOptions<'_>);

/// Sign or decline `pdf`; the result is the increment (see [`sign_increment`]).
///
/// The document is hashed once ([`DocumentDigests`]): the integrity check, the document digest
/// the record carries and the new signature's digest all reuse that pass.
fn sign_inner(
    pdf: &[u8],
    signer_key: &KeyPair,
    request: &SignRequest,
    host_timestamp: HostTimestamp<'_>,
    precheck: bool,
    tamper: EnvelopeHook<'_>,
    redraw: DrawingHook<'_>,
) -> Result<Vec<u8>> {
    let digests = DocumentDigests::new(pdf);
    // 0. Never sign on top of a document whose integrity is already broken (e.g. an unsigned
    //    update slipped in after the last signature, or the envelope was edited in transit).
    if precheck {
        require_integrity_with(&digests, "sign")?;
    }

    let mut env = read_envelope(pdf)?;
    if env.is_declined() {
        return Err(SignPdfError::Workflow(
            "this envelope was declined and is void; no further signatures are accepted".into(),
        ));
    }
    if let Some(exp) = &env.policy.expiry {
        if unix_from_rfc3339(exp).is_some_and(|t| now_unix() > t) {
            return Err(SignPdfError::Workflow(format!(
                "this envelope expired at {exp}"
            )));
        }
    }
    // The envelope's signature-timestamp policy, before anything else is checked: a host that
    // offers a timestamp the envelope does not take learns it at once.
    let (timestamper, reserve_timestamp) =
        timestamp_plan(env.policy.signature_timestamps, host_timestamp)?;
    if let Some(minutes) = request.utc_offset_minutes {
        dates::check_utc_offset_minutes(minutes).map_err(SignPdfError::Workflow)?;
    }
    if let Some(consent) = &request.esign_consent {
        consent.validate().map_err(SignPdfError::Workflow)?;
    }
    let doc_digest = digests.whole_hex();

    // 1. Validate the federated ID token and confirm it is bound to this key + document.
    let identity = validate_signer_token(&env, request, signer_key, &doc_digest)?;

    // 2. Auto-resolve which pending slot this verified identity fills (no self-select).
    let asserted = if request.signer_id.is_empty() {
        None
    } else {
        Some(request.signer_id.as_str())
    };
    let signer_id = resolve_signer_from_token(&env, &identity, asserted)?;

    // 3. Enforce signing order against the resolved slot (equal orders may sign in any order).
    let expected = env.expected_signers();
    if !expected.iter().any(|s| s.id == signer_id) {
        let next = expected
            .iter()
            .map(|s| format!("'{}' (order {})", s.id, s.order))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(SignPdfError::Workflow(format!(
            "out of order: expected {} to sign next",
            if next.is_empty() {
                "nobody".into()
            } else {
                next
            }
        )));
    }

    let now = now_rfc3339();
    let actor_name = display_name(&identity);
    let kind = if request.decline {
        RecordKind::Declined
    } else {
        RecordKind::Signed
    };

    let mut field_texts: Vec<FieldText> = Vec::new();
    let drawing = signer_drawing(request, env.schema_version)?;
    if kind == RecordKind::Signed {
        if let Some(drawing) = &drawing {
            drawing.validate().map_err(SignPdfError::Workflow)?;
        }
        // Apply field values, ensuring they belong to this signer.
        for (fid, val) in &request.field_values {
            let field = env
                .fields
                .iter_mut()
                .find(|f| &f.id == fid)
                .ok_or_else(|| SignPdfError::Workflow(format!("unknown field {fid}")))?;
            if field.assigned_signer != signer_id {
                return Err(SignPdfError::Workflow(format!(
                    "field {fid} is not assigned to signer {signer_id}"
                )));
            }
            if matches!(field.field_type, FieldType::Signature | FieldType::Initials) {
                return Err(SignPdfError::Workflow(format!(
                    "field {fid} is a signature field and takes no value"
                )));
            }
            if field.field_type == FieldType::Formula {
                return Err(SignPdfError::Workflow(format!(
                    "field {fid} is computed by its formula when you sign and takes no value"
                )));
            }
            // Checkbox and radio answers are stored canonically, as `true` or `false`.
            field.value = Some(if is_choice(field) {
                parse_choice(val)
                    .ok_or_else(|| {
                        SignPdfError::Workflow(format!(
                            "field {fid} takes true or false, not '{val}'"
                        ))
                    })?
                    .to_string()
            } else if field.field_type == FieldType::Multiline {
                // Stored with plain line breaks; refused rather than cut off when it is longer
                // than the field can show.
                let text = val.replace("\r\n", "\n").replace('\r', "\n");
                let text = checked_text(field, text.trim_end())?;
                let text = text.as_str();
                if text.chars().count() > pades::MAX_MULTILINE_CHARS {
                    return Err(SignPdfError::Workflow(format!(
                        "field {fid} holds at most {} characters",
                        pades::MAX_MULTILINE_CHARS
                    )));
                }
                let (w, h) = (field.rect.w as f32, field.rect.h as f32);
                let drawn = field.check().map(|c| c.display(text)).unwrap_or_default();
                if pades::layout_multiline(&drawn, w, h).is_none() {
                    return Err(SignPdfError::Workflow(format!(
                        "the text does not fit in field {fid}: shorten it or use fewer lines"
                    )));
                }
                text.to_string()
            } else if field.field_type == FieldType::Dropdown {
                // One of the preparer's choices, or nothing.
                if !val.is_empty() && !is_option(field, val) {
                    return Err(SignPdfError::Workflow(format!(
                        "field {fid} takes one of its options, not '{val}'"
                    )));
                }
                val.clone()
            } else if field.field_type == FieldType::Number {
                // Canonical, with the field's decimal places (the host read the signer's
                // locale), within its range; empty is no answer.
                let format = field.number_format.clone().unwrap_or_default();
                FieldCheck::Number(format.clone()).check(val).map_err(|e| {
                    SignPdfError::Workflow(format!(
                        "field {fid} does not take '{val}' ({}): {}",
                        e.code(),
                        number_rule(&format)
                    ))
                })?
            } else if field.field_type == FieldType::Date {
                // Stored as YYYY-MM-DD; an empty value is the signing date, filled below.
                let date = val.trim();
                if field.signing_date && !date.is_empty() {
                    return Err(SignPdfError::Workflow(format!(
                        "field {fid} is the date of signing, which the engine fills in: it \
                         takes no value"
                    )));
                }
                if !date.is_empty() && dates::parse_iso_date(date).is_none() {
                    return Err(SignPdfError::Workflow(format!(
                        "field {fid} takes a date written YYYY-MM-DD, not '{val}'"
                    )));
                }
                date.to_string()
            } else {
                // Text: canonical when the field has a format (version 8), within its length.
                checked_text(field, val)?
            });
        }
        // Every captioned checkbox and radio option of this signer gets an explicit answer, so
        // a box left unticked is recorded, and drawn, as unticked.
        for f in env
            .fields
            .iter_mut()
            .filter(|f| f.assigned_signer == signer_id && is_choice(f))
        {
            f.value.get_or_insert_with(|| "false".to_string());
        }
        // Date fields left empty, and the date-signed ones, get the signer's local date: the
        // device clock moved by the UTC offset the host reported (the UTC date without one).
        let today = dates::local_date(&now, request.utc_offset_minutes.unwrap_or(0))
            .unwrap_or_else(|| now.get(..10).unwrap_or(&now).to_string());
        for f in env
            .fields
            .iter_mut()
            .filter(|f| f.assigned_signer == signer_id && f.field_type == FieldType::Date)
        {
            if f.signing_date || f.value.as_deref().unwrap_or("").is_empty() {
                f.value = Some(today.clone());
            }
        }
        // The primary signature field carries the PAdES signature box; every other
        // signature/initials field of this signer gets a stamp derived from the verified identity
        // and, for initials, the slot's name under the envelope's initials rule.
        let fingerprint = signer_key.fingerprint();
        let code = fingerprint.get(..8).unwrap_or(&fingerprint).to_string();
        let primary = primary_signature_field(&env, &signer_id).map(|f| f.id.clone());
        let letters = signer_initials(&env, &signer_id, &identity);
        for f in env.fields.iter_mut().filter(|f| {
            f.assigned_signer == signer_id
                && matches!(f.field_type, FieldType::Signature | FieldType::Initials)
                && Some(&f.id) != primary.as_ref()
        }) {
            f.value = Some(stamp_text(f.field_type, &actor_name, &letters, &code));
        }
        // This signer's formula fields, computed from the values now in the envelope (theirs and
        // earlier signers'), in the order the formulas read each other.
        let computed = formula::compute_formula_fields(&env.fields, &BTreeMap::new(), |f| {
            f.assigned_signer == signer_id
        })
        .map_err(|e| SignPdfError::Workflow(format!("{e} ({})", e.code)))?;
        for f in env.fields.iter_mut() {
            if let Some(v) = computed.get(&f.id) {
                f.value = Some(v.clone());
            }
        }
        // Required fields, and one choice at most per radio group.
        check_signer_fields(&env, &signer_id).map_err(SignPdfError::Workflow)?;
        field_texts = env
            .fields
            .iter()
            .filter(|f| f.assigned_signer == signer_id)
            .filter_map(field_text)
            .collect();
    }

    let revision = env.signatures.len() as u32;
    {
        let slot = env.signer_mut(&signer_id).expect("resolved slot exists");
        slot.public_key = Some(signer_key.public_b64());
        slot.fingerprint = Some(signer_key.fingerprint());
        slot.status = match kind {
            RecordKind::Signed => SignerStatus::Signed,
            RecordKind::Declined => SignerStatus::Declined,
        };
    }

    // Record this revision. The cryptographically authoritative signature over the document
    // bytes is the PAdES CMS applied below; this record binds the signer's verified identity and
    // the exact predecessor revision it was applied to.
    let mut record = SignatureRecord {
        kind,
        signer_id: signer_id.clone(),
        fingerprint: signer_key.fingerprint(),
        public_key: signer_key.public_b64(),
        algorithm: crypto::ALGORITHM.to_string(),
        signed_at: now.clone(),
        timestamp_token: request.timestamp_token.clone(),
        doc_digest,
        signed_prefix_len: pdf.len() as u64,
        signature: String::new(),
        revision,
        id_token: request.id_token.clone(),
        idp_jwk: request.idp_jwk.clone(),
        idp_issuer: identity.issuer.clone(),
        idp_subject: identity.subject.clone(),
        idp_email: identity.email.clone(),
        idp_audience: request.audience.clone(),
        utc_offset: request.utc_offset_minutes.map(dates::format_utc_offset),
        // The drawing goes only in the signer's own box: kept when it is drawn there.
        drawing: drawing
            .clone()
            .filter(|_| kind == RecordKind::Signed)
            .filter(|_| primary_signature_field(&env, &signer_id).is_some())
            .filter(|_| records_drawing(env.schema_version)),
    };
    record.signature = signer_key.sign(&record_signing_payload(&env.envelope_id, &record));
    env.signatures.push(record);

    let (action, details) = match kind {
        RecordKind::Signed => (
            AuditAction::Signed,
            format!(
                "{actor_name} signed (revision {revision}); verified as {} via {}",
                identity.email, identity.issuer
            ),
        ),
        RecordKind::Declined => (
            AuditAction::Declined,
            format!(
                "{actor_name} declined to sign{}; verified as {} via {}",
                request
                    .reason
                    .as_deref()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default(),
                identity.email,
                identity.issuer
            ),
        ),
    };
    env.append_audit_with_consent(
        action,
        signer_key,
        &actor_name,
        &details,
        &now,
        request.esign_consent.clone(),
    );
    tamper(&mut env);

    // Apply the PAdES signature, embedding the updated envelope (and drawing field values) in the
    // same increment so the signature's ByteRange covers them.
    let fingerprint = signer_key.fingerprint();
    let code = fingerprint.get(..8).unwrap_or(fingerprint.as_str());
    let appearance = match kind {
        RecordKind::Signed => {
            let mut appearance = appearance_for(
                &env,
                &signer_id,
                &identity,
                request.reason.clone(),
                code,
                &now,
            );
            // The signer's drawing goes only in their own box, beside the verified caption.
            appearance.ink = drawing.filter(|_| appearance.caption.is_some());
            appearance
        }
        RecordKind::Declined => SignAppearance {
            name: actor_name.clone(),
            reason: Some(format!(
                "Declined{}",
                request
                    .reason
                    .as_deref()
                    .map(|r| format!(": {r}"))
                    .unwrap_or_default()
            )),
            ..Default::default()
        },
    };
    let mut opts = SignOptions {
        appearance,
        embed: Some(envelope_attachment(&env)?),
        field_texts,
        timestamper,
        reserve_timestamp,
    };
    redraw(&mut opts);
    pades::pades_sign_increment(&digests, signer_key, &opts)
        .map_err(|e| SignPdfError::Workflow(format!("PAdES signing failed: {e}")))
}

// --- verify --------------------------------------------------------------------------------

/// Verify a SignPDF document: every PAdES signature, the full revision chain (preparer intent,
/// one slot per signer revision, no foreign edits, no unsigned trailing updates), the audit log,
/// signing order, expiry, and every identity — offline, against `trust`.
///
/// [`VerificationReport::valid`] is true only when the document is intact **and** every identity
/// is anchored in `trust`. Use [`TrustStore::insecure_dev`] only for tests and demos.
///
/// The algorithm policy's end dates ([`crate::algorithms`]) are judged at the device clock's
/// time; a WebAssembly verifier without a registered clock treats them all as passed. Use
/// [`verify_at`] to give the time.
pub fn verify(pdf: &[u8], trust: &TrustStore) -> Result<VerificationReport> {
    verify_inner(&DocumentDigests::new(pdf), trust, try_now_unix())
}

/// [`verify`], judging the algorithm policy's end dates at `now_unix` (the verifier's time,
/// seconds since the Unix epoch) instead of the device clock. Nothing else in a verification
/// depends on the verifier's time.
pub fn verify_at(pdf: &[u8], trust: &TrustStore, now_unix: i64) -> Result<VerificationReport> {
    verify_inner(&DocumentDigests::new(pdf), trust, Some(now_unix))
}

/// The algorithm policy a verification applies, and the verifier's time to judge its end dates
/// at (`None`: unknown, every end date counts as passed).
struct Algorithms<'a> {
    policy: &'a AlgorithmPolicy,
    now: Option<i64>,
}

impl Algorithms<'_> {
    /// Judge evidence relying on `uses`, which a trusted timestamp shows existed by
    /// `existed_before`.
    fn judge(&self, uses: &[AlgorithmUse], existed_before: Option<i64>) -> AlgorithmVerdict {
        self.policy.judge(uses, self.now, existed_before)
    }
}

/// What a signer's or the preparer's PAdES signature relies on: ECDSA P-256 over SHA-256 (the
/// engine's canonical CMS), with the document, nonce and audit-chain digests in SHA-256.
const REVISION_ALGORITHMS: [AlgorithmUse; 2] = [
    AlgorithmUse {
        algorithm: Algorithm::EcdsaP256,
        key_bits: None,
    },
    AlgorithmUse {
        algorithm: Algorithm::Sha256,
        key_bits: None,
    },
];

/// One signed revision: the PAdES signature, the envelope it covers, where it starts (the end of
/// the previous signature or document timestamp; 0 for the preparer's), and its time evidence.
struct Revision<'a> {
    pades: &'a PadesValidation,
    env: Envelope,
    start: usize,
    /// For a signer's revision, the audit of its increments ([`pades::audit_revisions`] from
    /// `start` to its end), made while the revisions were parsed for their envelopes.
    audit: Option<Result<pades::IncrementAudit>>,
    /// Its signature timestamp (PAdES B-T), checked, when it has one.
    stamp: Option<TimestampStatus>,
    /// The earliest trusted timestamp covering it, with its Unix time.
    existed_before: Option<(i64, ExistedBefore)>,
}

impl Revision<'_> {
    /// What the trust store needs to judge `token`'s key window for this revision.
    fn time_evidence(&self, token: &str) -> SigningTimeEvidence {
        SigningTimeEvidence {
            issued_at: oidc::peek_issued_at(token),
            existed_before: self.existed_before.as_ref().map(|(t, _)| *t),
        }
    }
}

/// A trusted timestamp at one revision boundary: its Unix time and how to report it for a
/// revision at or before it.
struct TrustedStamp {
    at: i64,
    time: String,
    tsa_name: String,
    /// The revision whose signature timestamp it is, or `None` for a document timestamp.
    revision: Option<u32>,
    /// The document timestamp's 1-based index, for a document timestamp.
    document_timestamp: Option<u32>,
}

impl TrustedStamp {
    fn new(status: &TimestampStatus, revision: Option<u32>, document: Option<u32>) -> Option<Self> {
        if !status.is_trusted() {
            return None;
        }
        Some(TrustedStamp {
            at: unix_from_rfc3339(&status.time)?,
            time: status.time.clone(),
            tsa_name: status.tsa_name.clone(),
            revision,
            document_timestamp: document,
        })
    }

    /// How it is reported for `revision`.
    fn for_revision(&self, revision: u32) -> ExistedBefore {
        let source = match self.revision {
            Some(r) if r == revision => "signature",
            Some(_) => "later-signature",
            None => "document",
        };
        ExistedBefore {
            time: self.time.clone(),
            source: source.into(),
            revision: self.revision,
            document_timestamp: self.document_timestamp,
            tsa_name: self.tsa_name.clone(),
        }
    }
}

/// For each signed revision (in order), the earliest trusted timestamp at or after its signature
/// in the file. `stamps` holds each boundary's trusted timestamp, in file order, with whether the
/// boundary is a signature.
fn existed_before_by_revision(
    stamps: &[(bool, Option<TrustedStamp>)],
) -> Vec<Option<(i64, ExistedBefore)>> {
    let mut out = Vec::new();
    for (p, (is_signature, _)) in stamps.iter().enumerate() {
        if !is_signature {
            continue;
        }
        let revision = out.len() as u32;
        // The earliest in time; on a tie, the first in the file.
        let best = stamps[p..].iter().filter_map(|(_, s)| s.as_ref()).fold(
            None::<&TrustedStamp>,
            |best, s| match best {
                Some(b) if b.at <= s.at => Some(b),
                _ => Some(s),
            },
        );
        out.push(best.map(|s| (s.at, s.for_revision(revision))));
    }
    out
}

/// What ends a revision of the file: a signature, or a document timestamp (indexes into
/// [`PadesScan::signatures`] and [`PadesScan::document_timestamps`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Boundary {
    Signature(usize),
    DocumentTimestamp(usize),
}

/// Every revision boundary of `scan`, in file order, with the offset where it ends.
fn boundaries(scan: &PadesScan) -> Vec<(usize, Boundary)> {
    let mut ends: Vec<(usize, Boundary)> = scan
        .signatures
        .iter()
        .enumerate()
        .map(|(i, s)| (s.covered_end, Boundary::Signature(i)))
        .chain(
            scan.document_timestamps
                .iter()
                .enumerate()
                .map(|(j, d)| (d.covered_end, Boundary::DocumentTimestamp(j))),
        )
        .collect();
    ends.sort_by_key(|(end, _)| *end);
    ends
}

/// Verify the document `digests` hashes. Every digest of the document it checks (the report's,
/// each signature's signed range, the source and each revision a signer recorded) comes from
/// `digests`, so the document is hashed once.
fn verify_inner(
    digests: &DocumentDigests<'_>,
    trust: &TrustStore,
    now: Option<i64>,
) -> Result<VerificationReport> {
    let pdf = digests.bytes();
    // A damaged envelope (its compressed bytes changed) is reported by the signatures that cover
    // it, below; the document is refused only if they do not show the change.
    let final_env = match read_envelope(pdf) {
        Err(e) if !matches!(e, SignPdfError::Encoding(_)) => return Err(e),
        read => read,
    };
    let policy = trust.algorithms();
    let algorithms = Algorithms {
        policy: &policy,
        now,
    };
    let mut report = VerificationReport {
        valid: false,
        integrity_ok: true,
        identities_trusted: true,
        original_len: pdf.len(),
        document_sha256: digests.whole_hex(),
        audit_ok: true,
        order_ok: true,
        algorithm_policy: AlgorithmPolicyStatus {
            version: policy.version,
            source: if trust.algorithm_policy.is_some() {
                "trust-list"
            } else {
                "builtin"
            }
            .into(),
            checked_at: now
                .filter(|_| policy.has_end_dates())
                .map(rfc3339_from_unix)
                .unwrap_or_default(),
        },
        ..Default::default()
    };
    let fail = |report: &mut VerificationReport, f: Finding| report.fail(f);

    let scan = pades::pades_verify_all_with(digests)
        .map_err(|e| SignPdfError::Verification(e.to_string()))?;
    let sigs = &scan.signatures;
    let dss = scan.dss.as_ref();

    // --- Structural rules over the set of signatures. ---
    if sigs.is_empty() {
        fail(
            &mut report,
            Finding::new(
                m::NO_SIGNATURES,
                "document carries no PAdES signatures (the preparer signature is missing)",
            ),
        );
        report.envelope = final_env.ok();
        return Ok(finish(report));
    }
    for (i, s) in sigs.iter().enumerate() {
        if let Some(e) = &s.structure_error {
            fail(
                &mut report,
                Finding::new(
                    m::SIGNATURE_MALFORMED,
                    format!("signature {i} is malformed: {e}"),
                )
                .revision(i as u32),
            );
        } else if !s.digest_matches {
            fail(
                &mut report,
                Finding::new(
                    m::DOCUMENT_CHANGED,
                    format!(
                        "signature {i}: document bytes changed after signing (digest mismatch)"
                    ),
                )
                .revision(i as u32),
            );
        } else if !s.signature_valid {
            fail(
                &mut report,
                Finding::new(
                    m::SIGNATURE_INVALID,
                    format!("signature {i}: CMS signature did not verify"),
                )
                .revision(i as u32),
            );
        } else if !s.canonical {
            fail(
                &mut report,
                Finding::new(
                    m::SIGNATURE_ALTERED,
                    format!(
                        "signature {i}: CMS is not in SignPDF's canonical form (unsigned \
                         signature fields were altered)"
                    ),
                )
                .revision(i as u32),
            );
        }
    }
    for (j, d) in scan.document_timestamps.iter().enumerate() {
        if let Some(e) = &d.structure_error {
            fail(
                &mut report,
                Finding::new(
                    m::DOCUMENT_TIMESTAMP_MALFORMED,
                    format!("document timestamp {} is malformed: {e}", j + 1),
                ),
            );
        } else if !d.digest_matches {
            fail(
                &mut report,
                Finding::new(
                    m::DOCUMENT_TIMESTAMP_CHANGED,
                    format!(
                        "document timestamp {}: document bytes changed after it was made (digest \
                         mismatch)",
                        j + 1
                    ),
                ),
            );
        }
    }
    // Every signature and document timestamp ends one revision; the first is the preparer's
    // signature, and the last must cover the whole file.
    let ends = boundaries(&scan);
    if ends.windows(2).any(|w| w[0].0 >= w[1].0) {
        fail(
            &mut report,
            Finding::new(
                m::REVISIONS_OVERLAP,
                "two signatures cover the same revision",
            ),
        );
    }
    if ends.first().map(|(_, b)| *b) != Some(Boundary::Signature(0)) {
        fail(
            &mut report,
            Finding::new(
                m::TIMESTAMP_BEFORE_PREPARER,
                "a document timestamp comes before the preparer's signature",
            ),
        );
    }
    let last_end = ends.last().map_or(0, |(end, _)| *end);
    if last_end != pdf.len() {
        let after = if scan.document_timestamps.is_empty() {
            "the last signature"
        } else {
            "the last signature or document timestamp"
        };
        fail(
            &mut report,
            Finding::new(
                m::UNSIGNED_CHANGES,
                format!(
                    "{} byte(s) were appended after {after} (unsigned changes)",
                    pdf.len().saturating_sub(last_end)
                ),
            ),
        );
    }
    if !report.integrity_ok {
        // Without sound signatures the revision chain cannot be trusted; stop here.
        report.envelope = final_env.ok();
        return Ok(finish(report));
    }
    let final_env = final_env?;

    // --- Every timestamp, and the trusted time evidence it gives each revision. ---
    let mut sig_stamps: Vec<Option<TimestampStatus>> = sigs
        .iter()
        .map(|s| {
            s.signature_timestamp
                .as_deref()
                .map(|ts| signature_timestamp_status(ts, &s.signature_value, trust, dss))
        })
        .collect();
    let mut doc_stamps: Vec<std::result::Result<TimestampStatus, String>> = scan
        .document_timestamps
        .iter()
        .map(|d| match crate::timestamp::token_imprint(&d.token) {
            Ok((_, imprint)) => Ok(timestamp_check("document", &d.token, &imprint, trust, dss)),
            Err(e) => Err(format!("its token is unreadable: {e}")),
        })
        .collect();
    let doc_sound: Vec<bool> = scan
        .document_timestamps
        .iter()
        .map(|d| d.is_valid())
        .collect();
    let mut timestamp_warnings = Vec::new();
    judge_timestamp_algorithms(
        &doc_sound,
        &ends,
        &mut sig_stamps,
        &mut doc_stamps,
        &algorithms,
        &mut timestamp_warnings,
    );
    for w in timestamp_warnings {
        report.record(Finding::new(m::TIMESTAMP_ALGORITHM, w));
    }
    let mut signatures_seen = 0u32;
    let boundary_stamps: Vec<(bool, Option<TrustedStamp>)> = ends
        .iter()
        .map(|(_, b)| match *b {
            Boundary::Signature(i) => {
                let revision = signatures_seen;
                signatures_seen += 1;
                let stamp = sig_stamps[i]
                    .as_ref()
                    .and_then(|t| TrustedStamp::new(t, Some(revision), None));
                (true, stamp)
            }
            Boundary::DocumentTimestamp(j) => {
                let stamp = match (&doc_stamps[j], scan.document_timestamps[j].is_valid()) {
                    (Ok(t), true) => TrustedStamp::new(t, None, Some(j as u32 + 1)),
                    _ => None,
                };
                (false, stamp)
            }
        })
        .collect();
    let mut existed_before = existed_before_by_revision(&boundary_stamps).into_iter();

    // --- Rebuild the envelope at each signed revision, and audit each signer's increments. ---
    // Each revision is parsed once: for its envelope, then for the audit of the increments after
    // it (the parse of the previous signed revision is kept until then).
    let mut revisions: Vec<Revision> = Vec::with_capacity(sigs.len());
    let mut start = 0;
    let mut previous: Option<pades::ParsedRevision> = None;
    for (end, b) in &ends {
        let Boundary::Signature(i) = *b else {
            start = *end;
            continue;
        };
        let s = &sigs[i];
        let rev_start = start;
        start = *end;
        let parsed = pades::ParsedRevision::parse(&pdf[..s.covered_end]);
        let env = parsed
            .as_ref()
            .map_err(|_| no_envelope())
            .and_then(|p| envelope_in(p));
        let audit = match (&parsed, revisions.is_empty()) {
            (_, true) => None,
            (Ok(cur), false) => Some(match previous.take() {
                Some(prev) if prev.len() == rev_start => pades::audit_revisions(&prev, cur),
                // A document timestamp (or nothing readable) ends the revision before it.
                _ => pades::ParsedRevision::parse(&pdf[..rev_start])
                    .and_then(|prev| pades::audit_revisions(&prev, cur)),
            }),
            // No envelope either: the verification stops below.
            (Err(_), false) => None,
        };
        previous = parsed.ok();
        match env {
            Ok(env) => revisions.push(Revision {
                pades: s,
                env,
                start: rev_start,
                audit,
                stamp: sig_stamps[i].clone(),
                existed_before: existed_before.next().flatten(),
            }),
            Err(e) => {
                fail(
                    &mut report,
                    Finding::new(
                        m::ENVELOPE_UNREADABLE,
                        format!(
                            "revision ending at byte {} has no readable envelope: {e}",
                            s.covered_end
                        ),
                    )
                    .revision(revisions.len() as u32),
                );
                report.envelope = Some(final_env);
                return Ok(finish(report));
            }
        }
    }

    // --- Revision 0: the preparer. ---
    let e0 = revisions[0].env.clone();
    report.preparer = Some(check_preparer_revision(
        digests,
        &revisions[0],
        trust,
        &algorithms,
        &mut report,
    ));

    // The link back to the service: the preparer's, when it is usable. It never decides
    // validity, so a bad one is a warning.
    if let Some(link) = &e0.service_link {
        match check_service_link(link) {
            Ok(()) => report.service_link = Some(link.clone()),
            Err(e) => report.record(Finding::new(
                m::SERVICE_LINK_UNUSABLE,
                format!("{e}; it is not reported"),
            )),
        }
    }

    // --- Revisions 1..n: one signer each. ---
    for k in 1..revisions.len() {
        let status = check_signer_revision(
            digests,
            &e0,
            &revisions[k - 1],
            &revisions[k],
            k,
            trust,
            &algorithms,
            dss,
            &mut report,
        );
        if let Some(w) = timestamp_policy_warning(e0.policy.signature_timestamps, &status) {
            report.record(about(w, &status));
        }
        if revisions[k].env.service_link != revisions[k - 1].env.service_link {
            let w = Finding::new(
                m::SERVICE_LINK_CHANGED,
                format!(
                    "{} changed the envelope's service link, which only the preparer sets: the \
                     change is ignored",
                    revision_name(&status)
                ),
            );
            report.record(about(w, &status));
        }
        report.signatures.push(status);
    }

    // --- Document timestamps, with the validation data their increments add. ---
    let mut dss_spans_trusted = true;
    let mut start = 0;
    for (end, b) in &ends {
        let span_start = std::mem::replace(&mut start, *end);
        let Boundary::DocumentTimestamp(j) = *b else {
            continue;
        };
        let status = check_document_timestamp(
            pdf,
            &scan,
            j,
            span_start,
            &ends,
            doc_stamps[j].clone(),
            &mut report,
        );
        if status.added_validation_data && !status.timestamp.is_trusted() {
            dss_spans_trusted = false;
        }
        report.document_timestamps.push(status);
    }
    if let Some(d) = dss {
        report.validation_data = Some(ValidationDataSummary {
            certificates: d.certs.len(),
            ocsp_responses: d.ocsps.len(),
            crls: d.crls.len(),
        });
    }
    for w in distrusted_tsa_warnings(&report) {
        report.record(w);
    }
    for w in revoked_later_warnings(&report) {
        report.record(w);
    }

    // --- Whole-envelope checks on the final state. ---
    let mut extra_keys: HashMap<String, String> = HashMap::new();
    if let Ok(fp) = crypto::fingerprint_of_public(&final_env.created_by_pubkey) {
        extra_keys.insert(fp, final_env.created_by_pubkey.clone());
    }
    if let Err(e) = final_env.verify_audit_chain_with(&extra_keys) {
        report.audit_ok = false;
        fail(
            &mut report,
            Finding::new(m::AUDIT_LOG_BROKEN, e.to_string()),
        );
    }
    for r in &final_env.signatures {
        let key_matches = crypto::fingerprint_of_public(&r.public_key)
            .map(|f| f == r.fingerprint)
            .unwrap_or(false);
        let record_ok = crypto::verify(
            &r.public_key,
            &record_signing_payload(&final_env.envelope_id, r),
            &r.signature,
        )
        .is_ok();
        if !(key_matches && record_ok) {
            fail(
                &mut report,
                Finding::new(
                    m::SIGNATURE_RECORD_INCONSISTENT,
                    format!("signature record for '{}' is inconsistent", r.signer_id),
                )
                .signer(r.signer_id.clone())
                .revision(r.revision + 1),
            );
        }
    }
    if final_env.signatures.len() + 1 != sigs.len() {
        fail(
            &mut report,
            Finding::new(
                m::SIGNATURE_COUNT_MISMATCH,
                format!(
                    "envelope records {} signature(s) but the PDF carries {} signer signature(s)",
                    final_env.signatures.len(),
                    sigs.len() - 1
                ),
            ),
        );
    }
    for s in &final_env.signers {
        for w in s.identity_policy.weaknesses() {
            report.record(
                Finding::new(
                    m::SLOT_POLICY_WEAK,
                    format!("slot '{}' ({}): {w}", s.id, s.name),
                )
                .signer(s.id.clone()),
            );
        }
    }
    if trust.allow_insecure_dev_issuer {
        report.record(Finding::new(
            m::INSECURE_DEV_TRUST,
            "INSECURE: this verification trusts the bundled dev identity provider; never use \
             this setting for real documents",
        ));
    }

    report.complete = final_env.is_complete();
    report.declined = final_env.is_declined();
    if report.integrity_ok {
        report.pades_level = pades_level(&report, &ends, dss_spans_trusted).into();
    }
    report.envelope = Some(final_env);
    Ok(finish(report))
}

/// Check document timestamp `j` of `scan`, which ends the increments starting at `start`: they
/// may only add validation data and this timestamp ([`pades::audit_ltv_increment`]).
fn check_document_timestamp(
    pdf: &[u8],
    scan: &PadesScan,
    j: usize,
    start: usize,
    ends: &[(usize, Boundary)],
    stamp: std::result::Result<TimestampStatus, String>,
    report: &mut VerificationReport,
) -> DocumentTimestampStatus {
    let d = &scan.document_timestamps[j];
    let signatures_before = ends
        .iter()
        .filter(|(end, b)| *end <= start && matches!(b, Boundary::Signature(_)))
        .count();
    let mut status = DocumentTimestampStatus {
        index: j as u32 + 1,
        after_revision: signatures_before.saturating_sub(1) as u32,
        covered_len: d.covered_end as u64,
        ..Default::default()
    };
    status.timestamp.kind = "document".into();
    if !d.is_valid() {
        // Already reported as an integrity failure.
        status.detail = d
            .structure_error
            .clone()
            .unwrap_or_else(|| "the document changed after it was made".into());
        return status;
    }
    let mut problems: Vec<String> = Vec::new();
    match stamp {
        Ok(t) => status.timestamp = t,
        Err(e) => problems.push(e),
    }
    if start == 0 {
        problems.push("it comes before the preparer's signature".into());
    } else {
        match pades::audit_ltv_increment(&pdf[..start], &pdf[..d.covered_end]) {
            Ok(audit) => {
                problems.extend(audit.violations);
                if audit.document_timestamp.is_some_and(|id| id != d.object_id) {
                    problems.push("it is not the document timestamp its increment added".into());
                }
                status.added_validation_data = audit.dss_changed;
            }
            Err(e) => problems.push(format!("cannot audit its increment: {e}")),
        }
    }
    if problems.is_empty() {
        status.valid = true;
    } else {
        status.detail = problems.join("; ");
        for p in problems {
            report.fail(Finding::new(
                m::DOCUMENT_TIMESTAMP_INVALID,
                format!("document timestamp {}: {p}", status.index),
            ));
        }
    }
    status
}

/// Every timestamp of the report (signature timestamps, then document timestamps), with a name
/// for messages.
fn all_timestamps(report: &VerificationReport) -> Vec<(String, &TimestampStatus)> {
    let mut out = Vec::new();
    for s in report.preparer.iter().chain(&report.signatures) {
        if let Some(t) = &s.timestamp {
            let who = if s.kind == "prepared" {
                "the preparer".to_string()
            } else {
                revision_name(s)
            };
            out.push((format!("the signature timestamp of {who}"), t));
        }
    }
    for d in &report.document_timestamps {
        out.push((format!("document timestamp {}", d.index), &d.timestamp));
    }
    out
}

/// Warnings for timestamps from an authority the trust store distrusts from a time at or before
/// them: they are not used as trusted time.
fn distrusted_tsa_warnings(report: &VerificationReport) -> Vec<Finding> {
    all_timestamps(report)
        .into_iter()
        .filter(|(_, t)| !t.distrusted_after.is_empty())
        .map(|(name, t)| {
            Finding::new(
                m::TSA_DISTRUSTED,
                format!(
                    "{name} ({}, by '{}') comes from a timestamp authority the trust store                      distrusts from {}: it is not used as trusted time",
                    t.time, t.tsa_name, t.distrusted_after
                ),
            )
        })
        .collect()
}

/// Warnings for TSA chain certificates that were revoked after a timestamp they vouch for: the
/// timestamp still holds, but a reader should know.
fn revoked_later_warnings(report: &VerificationReport) -> Vec<Finding> {
    let mut out = Vec::new();
    for (name, t) in all_timestamps(report) {
        for c in &t.chain {
            if c.revocation == "good" && !c.revoked_at.is_empty() {
                out.push(Finding::new(
                    m::TSA_CERTIFICATE_REVOKED_LATER,
                    format!(
                        "the TSA certificate '{}' of {name} was revoked at {}, after the \
                         timestamp ({}): the timestamp still holds",
                        c.subject, c.revoked_at, t.time
                    ),
                ));
            }
        }
    }
    out
}

/// The PAdES baseline level of the whole document (see [`VerificationReport::pades_level`]).
///
/// Each signature's time evidence is its own trusted signature timestamp, or else the first
/// trusted timestamp after it in the file (a later signature's, or a document timestamp): either
/// proves that the signature existed by then. `dss_spans_trusted` says whether every addition of
/// validation data ends with a trusted document timestamp.
fn pades_level(
    report: &VerificationReport,
    ends: &[(usize, Boundary)],
    dss_spans_trusted: bool,
) -> &'static str {
    let revisions: Vec<&SignatureStatus> =
        report.preparer.iter().chain(&report.signatures).collect();
    // The timestamp each boundary carries, in file order.
    let stamps: Vec<(bool, Option<&TimestampStatus>)> = ends
        .iter()
        .map(|(_, b)| match *b {
            Boundary::Signature(i) => (true, revisions.get(i).and_then(|s| s.timestamp.as_ref())),
            Boundary::DocumentTimestamp(j) => (
                false,
                report.document_timestamps.get(j).map(|d| &d.timestamp),
            ),
        })
        .collect();
    let mut evidence: Vec<&TimestampStatus> = Vec::new();
    for (p, (is_signature, _)) in stamps.iter().enumerate() {
        if !is_signature {
            continue;
        }
        let found = stamps[p..]
            .iter()
            .filter_map(|(_, t)| *t)
            .find(|t| t.is_trusted());
        match found {
            Some(t) => evidence.push(t),
            None => return "B-B",
        }
    }
    if !evidence.iter().all(|t| t.validation == "complete") {
        return "B-T";
    }
    if !dss_spans_trusted || report.document_timestamps.is_empty() {
        return "B-LT";
    }
    "B-LTA"
}

/// A signer revision that departs from the envelope's signature-timestamp policy. Never an
/// integrity failure: a timestamp is an unsigned attribute that does not change what was signed,
/// a `required` revision without one is what a host makes when no time-stamp authority answers,
/// and a timestamp on a `none` envelope still dates the signature truthfully.
fn timestamp_policy_warning(policy: TimestampPolicy, status: &SignatureStatus) -> Option<Finding> {
    let who = revision_name(status);
    match (policy, &status.timestamp) {
        (TimestampPolicy::Required, None) => Some(Finding::new(
            m::TIMESTAMP_MISSING,
            format!(
                "{who} has no signature timestamp although the envelope requires one (the \
                 time-stamp authority may have been unreachable): its signing time is the \
                 signer's device clock"
            ),
        )),
        (TimestampPolicy::None, Some(_)) => Some(Finding::new(
            m::TIMESTAMP_UNEXPECTED,
            format!(
                "{who} carries a signature timestamp although the envelope takes none \
                 (signature_timestamps = none)"
            ),
        )),
        _ => None,
    }
}

/// `f`, about the revision of `status` and its slot (when known).
fn about(f: Finding, status: &SignatureStatus) -> Finding {
    let f = f.revision(status.index);
    if status.signer_id.is_empty() {
        f
    } else {
        f.signer(status.signer_id.clone())
    }
}

/// How a warning names a signer revision: `signer 's1'`, or `revision 2` when its slot is unknown.
fn revision_name(status: &SignatureStatus) -> String {
    if status.signer_id.is_empty() {
        format!("revision {}", status.index)
    } else {
        format!("signer '{}'", status.signer_id)
    }
}

/// Derive the headline verdict.
fn finish(mut report: VerificationReport) -> VerificationReport {
    report.valid = report.integrity_ok && report.identities_trusted;
    if report.integrity_ok && !report.identities_trusted {
        let untrusted: Vec<IdentityTrust> = report
            .preparer
            .iter()
            .chain(&report.signatures)
            .filter_map(|s| IdentityTrust::parse(&s.identity_trust))
            .filter(|t| !t.is_acceptable())
            .collect();
        report.trusted_time_pending =
            !untrusted.is_empty() && untrusted.iter().all(|t| *t == IdentityTrust::NoTrustedTime);
        let f = if report.trusted_time_pending {
            Finding::new(
                m::TRUSTED_TIME_PENDING,
                "the document is intact; one or more identities count only once a trusted \
                 timestamp covers their signature, and none does yet",
            )
        } else {
            Finding::new(
                m::IDENTITIES_NOT_TRUSTED,
                "the document is intact, but one or more identities are not anchored in the \
                 verifier's trust store, or do not meet what their slot requires",
            )
        };
        report.record(f);
    }
    report
}

/// Whether a revision signed at `when` (its trusted signature timestamp, or else the signer's
/// device clock) came after the envelope expired at `exp`. A trusted timestamp showing that the
/// signature already existed by then settles it the other way, whatever the device clock says.
fn lapsed(when: i64, existed_before: Option<i64>, exp: i64) -> bool {
    when > exp + LEEWAY_SECS && !existed_before.is_some_and(|t| t <= exp + LEEWAY_SECS)
}

/// An ID token's `iat` as RFC 3339 (empty when it has none).
fn issued_at_rfc3339(token: &str) -> String {
    oidc::peek_issued_at(token)
        .map(crate::util::rfc3339_from_unix)
        .unwrap_or_default()
}

/// Check the preparer's revision: key binding, initial envelope state, the preparer's additions
/// to the source document, and the preparer's identity.
fn check_preparer_revision(
    digests: &DocumentDigests<'_>,
    rev: &Revision,
    trust: &TrustStore,
    algorithms: &Algorithms,
    report: &mut VerificationReport,
) -> SignatureStatus {
    let pdf = digests.bytes();
    let env = &rev.env;
    let fp = sha256_hex(&rev.pades.signer_pubkey_sec1);
    let mut problems: Vec<Finding> = Vec::new();

    if crypto::fingerprint_of_public(&env.created_by_pubkey)
        .ok()
        .as_deref()
        != Some(fp.as_str())
    {
        problems.push(Finding::new(
            m::PREPARER_REVISION_INVALID,
            "the first signature is not the preparer's",
        ));
    }
    if !env.signatures.is_empty()
        || env
            .signers
            .iter()
            .any(|s| s.status != SignerStatus::Pending)
    {
        problems.push(Finding::new(
            m::PREPARER_REVISION_INVALID,
            "the prepared envelope already contains signatures",
        ));
    }
    if env.audit_log.len() != 1
        || env.audit_log[0].action != AuditAction::Prepared
        || env.audit_log[0].actor_fingerprint != fp
    {
        problems.push(Finding::new(
            m::PREPARER_REVISION_INVALID,
            "the prepared envelope's audit log is not a single preparer entry",
        ));
    } else if env.audit_log[0].esign_consent.is_some() {
        problems.push(Finding::new(
            m::PREPARER_REVISION_INVALID,
            "the preparer's audit entry carries a signer's consent record",
        ));
    }
    let src_len = env.source_len as usize;
    if src_len == 0 || src_len > rev.pades.covered_end {
        problems.push(Finding::new(
            m::PREPARER_REVISION_INVALID,
            "the envelope's source length is invalid",
        ));
    } else {
        if digests.prefix_hex(src_len) != env.source_digest {
            problems.push(Finding::new(
                m::PREPARER_REVISION_INVALID,
                "the original source bytes do not match the recorded source digest",
            ));
        }
        match pades::audit_increment(&pdf[..src_len], &pdf[..rev.pades.covered_end]) {
            Ok(audit) => {
                problems.extend(coded(m::FORBIDDEN_CHANGE, audit.violations));
                let mut widgets = 0;
                for a in &audit.added_annotations {
                    problems.extend(coded(
                        m::UNEXPECTED_ANNOTATION,
                        a.shape_problems.iter().cloned(),
                    ));
                    match (a.subtype.as_str(), a.field_type.as_deref()) {
                        ("Widget", Some("Sig")) if a.is_new_object => {
                            widgets += 1;
                            // The preparer's signature has no box: it must draw nothing.
                            if a.rect.iter().any(|v| *v != 0.0) {
                                problems.push(Finding::new(
                                    m::PREPARER_REVISION_INVALID,
                                    "the preparer's signature is not invisible",
                                ));
                            }
                            problems.extend(coded(
                                m::SIGNATURE_BOX_MISMATCH,
                                pades::check_signature_widget(
                                    a,
                                    a.rect,
                                    None,
                                    InkRule::Recorded(None),
                                ),
                            ));
                        }
                        ("Stamp", _)
                            if a.is_new_object && a.name.as_deref() == Some("SignPDFDocID") =>
                        {
                            problems.extend(coded(
                                m::DOCUMENT_ID_STAMP_MISMATCH,
                                pades::check_document_id_stamp_lines(a, &document_id_lines(env)),
                            ));
                        }
                        _ => problems.push(Finding::new(
                            m::UNEXPECTED_ANNOTATION,
                            format!(
                                "the preparer revision added an unexpected '{}' annotation",
                                a.subtype
                            ),
                        )),
                    }
                }
                if widgets != 1 {
                    problems.push(Finding::new(
                        m::PREPARER_REVISION_INVALID,
                        "the preparer revision must add exactly one signature field",
                    ));
                }
                // The documents index covers the source's pages (the page tree cannot change).
                if let Err(e) = documents::check_index(&env.documents, audit.pages) {
                    problems.push(Finding::new(
                        m::PREPARER_REVISION_INVALID,
                        format!("the documents index does not match the document: {e}"),
                    ));
                }
            }
            Err(e) => problems.push(Finding::new(
                m::AUDIT_FAILED,
                format!("cannot audit the preparer revision: {e}"),
            )),
        }
    }
    if env.envelope_id.is_empty() {
        problems.push(Finding::new(
            m::PREPARER_REVISION_INVALID,
            "envelope id is empty",
        ));
    }
    let existed_before = rev.existed_before.as_ref().map(|(t, _)| *t);
    match algorithms.judge(&REVISION_ALGORITHMS, existed_before) {
        AlgorithmVerdict::Accepted => {}
        AlgorithmVerdict::AcceptedByTimestamp(w) => report.record(
            Finding::new(
                m::ALGORITHM_ACCEPTED_BY_TIMESTAMP,
                format!("the preparer's signature: {w}"),
            )
            .revision(0),
        ),
        AlgorithmVerdict::Refused(r) => problems.push(Finding::new(
            m::ALGORITHM_REFUSED,
            format!("the signature cannot be relied on: {r}"),
        )),
    }

    let mut status = SignatureStatus {
        index: 0,
        kind: "prepared".into(),
        actor_fingerprint: fp.clone(),
        signed_at: env.created_at.clone(),
        time_source: "device".into(),
        signature_code: fp.get(..8).unwrap_or(&fp).to_string(),
        timestamp: rev.stamp.clone(),
        existed_before: rev.existed_before.as_ref().map(|(_, e)| e.clone()),
        token_issued_at: issued_at_rfc3339(&env.created_by_id_token),
        ..Default::default()
    };

    // Identity: token signature + nonce binding at preparation time, then trust anchoring.
    match validate_preparer_identity(env) {
        Ok(identity) => {
            status.idp_email = identity.email.clone();
            status.idp_issuer = identity.issuer.clone();
            let t = identity_check(
                trust,
                algorithms,
                &identity,
                (
                    &env.created_by_id_token,
                    &env.created_by_idp_jwk,
                    &env.created_by_audience,
                ),
                rev.time_evidence(&env.created_by_id_token),
                None,
                &mut status,
            );
            if let AlgorithmVerdict::AcceptedByTimestamp(w) = &t.algorithms {
                report.record(
                    Finding::new(
                        m::ALGORITHM_ACCEPTED_BY_TIMESTAMP,
                        format!("the preparer's identity token: {w}"),
                    )
                    .revision(0),
                );
            }
            let t = t.check;
            status.identity_trust = t.trust.as_str().into();
            if !t.trust.is_acceptable() {
                report.untrusted(
                    Finding::new(
                        m::identity_code(t.trust.as_str()),
                        format!("preparer identity: {}", t.reason),
                    )
                    .revision(0),
                );
            }
            if problems.is_empty() {
                status.detail = format!(
                    "preparer signature valid; identity verified as {} via {}",
                    identity.email, identity.issuer
                );
            }
        }
        Err(e) => problems.push(Finding::new(
            m::PREPARER_IDENTITY_FAILED,
            format!("preparer identity did not verify: {e}"),
        )),
    }

    if problems.is_empty() {
        status.valid = IdentityTrust::is_acceptable(trust_from_str(&status.identity_trust));
    } else {
        status.detail = joined(&problems);
        for p in problems {
            report.fail(p.prefixed("preparer revision: ").revision(0));
        }
    }
    status
}

/// Check signer revision `k` (1-based among signatures) against its predecessor.
#[allow(clippy::too_many_arguments)]
fn check_signer_revision(
    digests: &DocumentDigests<'_>,
    e0: &Envelope,
    prev: &Revision,
    cur: &Revision,
    k: usize,
    trust: &TrustStore,
    algorithms: &Algorithms,
    dss: Option<&Dss>,
    report: &mut VerificationReport,
) -> SignatureStatus {
    let fp = sha256_hex(&cur.pades.signer_pubkey_sec1);
    let mut status = SignatureStatus {
        index: k as u32,
        actor_fingerprint: fp.clone(),
        signature_code: fp.get(..8).unwrap_or(&fp).to_string(),
        time_source: "device".into(),
        timestamp: cur.stamp.clone(),
        existed_before: cur.existed_before.as_ref().map(|(_, e)| e.clone()),
        ..Default::default()
    };
    let mut problems: Vec<Finding> = Vec::new();

    let transition = check_transition(e0, &prev.env, &cur.env, &fp);
    let record = match &transition {
        Ok(r) => Some(r.clone()),
        Err(e) => {
            problems.push(e.clone());
            cur.env
                .signatures
                .iter()
                .find(|r| r.fingerprint == fp)
                .cloned()
        }
    };
    if let Some(r) = &record {
        status.kind = r.kind.as_str().into();
        status.signer_id = r.signer_id.clone();
        status.signed_at = r.signed_at.clone();
        status.drawing = r
            .drawing
            .as_ref()
            .map(|d| d.kind().to_string())
            .unwrap_or_default();
        problems.extend(coded(
            m::DRAWING_MISMATCH,
            check_recorded_drawing(&cur.env, r),
        ));
        status.token_issued_at = issued_at_rfc3339(&r.id_token);
        if let Some(offset) = &r.utc_offset {
            status.utc_offset = offset.clone();
            status.local_signed_at = dates::parse_utc_offset(offset)
                .and_then(|m| dates::local_time(&r.signed_at, m))
                .unwrap_or_default();
        }
        status.esign_consent = cur
            .env
            .audit_log
            .iter()
            .rev()
            .find(|e| e.actor_fingerprint == fp)
            .and_then(|e| e.esign_consent.clone());
        // The revision before it ends with the previous signature, or with a document timestamp
        // added after that signature.
        if r.signed_prefix_len as usize != cur.start {
            problems.push(Finding::new(
                m::UNSIGNED_INSERTION,
                format!(
                "was applied to a {}-byte document, not the previous signed revision ({} bytes): \
                 unsigned changes were inserted before it",
                r.signed_prefix_len, cur.start
            ),
            ));
        } else if digests.prefix_hex(cur.start) != r.doc_digest {
            problems.push(Finding::new(
                m::REVISION_DIGEST_MISMATCH,
                "recorded document digest does not match the previous revision",
            ));
        }
    } else {
        status.kind = "signed".into();
        problems.push(Finding::new(
            m::SIGNER_NOT_RECORDED,
            "PAdES signer is not recorded in the envelope",
        ));
    }

    // PDF-level changes in this increment must be limited to this signer's own additions.
    let mut added: Vec<AddedAnnotation> = Vec::new();
    let audit = match &cur.audit {
        Some(audit) => audit,
        None => &Err(SignPdfError::Pades("the revision was not audited".into())),
    };
    match audit {
        Ok(audit) => {
            problems.extend(coded(m::FORBIDDEN_CHANGE, audit.violations.iter().cloned()));
            if let Some(r) = &record {
                problems.extend(coded(
                    m::UNEXPECTED_ANNOTATION,
                    check_added_annotations(&cur.env, r, &audit.added_annotations),
                ));
            }
            added = audit.added_annotations.clone();
        }
        Err(e) => problems.push(Finding::new(
            m::AUDIT_FAILED,
            format!("cannot audit this revision: {e}"),
        )),
    }

    // What the signature relies on, judged by the algorithm policy.
    let existed_before = cur.existed_before.as_ref().map(|(t, _)| *t);
    match algorithms.judge(&REVISION_ALGORITHMS, existed_before) {
        AlgorithmVerdict::Accepted => {}
        AlgorithmVerdict::AcceptedByTimestamp(w) => {
            let f = Finding::new(
                m::ALGORITHM_ACCEPTED_BY_TIMESTAMP,
                format!(
                    "the signature of {}: {w}",
                    record.as_ref().map_or_else(
                        || format!("revision {k}"),
                        |r| format!("signer '{}'", r.signer_id)
                    )
                ),
            )
            .revision(k as u32);
            report.record(match &record {
                Some(r) => f.signer(r.signer_id.clone()),
                None => f,
            });
        }
        AlgorithmVerdict::Refused(r) => problems.push(Finding::new(
            m::ALGORITHM_REFUSED,
            format!("the signature cannot be relied on: {r}"),
        )),
    }

    // The legacy document-existence timestamp of the record, if any.
    if let Some(r) = &record {
        status.document_timestamp = document_timestamp_status(r, trust, dss).map(|mut t| {
            if t.is_trusted() {
                if let AlgorithmVerdict::Refused(why) =
                    algorithms.judge(&t.algorithms, existed_before)
                {
                    t.trusted = false;
                    t.detail = format!("the algorithm policy does not accept it: {why}");
                }
            }
            t
        });
    }

    // Identity: token signature, nonce binding, slot policy, validity at the signing time.
    if let Some(r) = &record {
        let (when, source) = signing_time(r, status.timestamp.as_ref());
        status.time_source = source.into();
        match when {
            Some(t) => match validate_record_identity(e0, r, t) {
                Ok(identity) => {
                    status.idp_email = identity.email.clone();
                    status.idp_issuer = identity.issuer.clone();
                    let tr = identity_check(
                        trust,
                        algorithms,
                        &identity,
                        (&r.id_token, &r.idp_jwk, &r.idp_audience),
                        cur.time_evidence(&r.id_token),
                        e0.signer(&r.signer_id).map(|s| &s.identity_policy),
                        &mut status,
                    );
                    if let AlgorithmVerdict::AcceptedByTimestamp(w) = &tr.algorithms {
                        report.record(
                            Finding::new(
                                m::ALGORITHM_ACCEPTED_BY_TIMESTAMP,
                                format!("signer '{}': the identity token: {w}", r.signer_id),
                            )
                            .signer(r.signer_id.clone())
                            .revision(k as u32),
                        );
                    }
                    let tr = tr.check;
                    status.identity_trust = tr.trust.as_str().into();
                    if !tr.trust.is_acceptable() {
                        report.untrusted(
                            Finding::new(
                                m::identity_code(tr.trust.as_str()),
                                format!("signer '{}': {}", r.signer_id, tr.reason),
                            )
                            .signer(r.signer_id.clone())
                            .revision(k as u32),
                        );
                    }
                    // Stamps in the signer's other signature/initials fields must be exactly
                    // what the engine derives from the *verified* identity (and, for initials,
                    // the slot's name under the prepared initials rule).
                    let code = fp.get(..8).unwrap_or(&fp);
                    let letters = signer_initials(e0, &r.signer_id, &identity);
                    problems.extend(coded(
                        m::SIGNATURE_BOX_MISMATCH,
                        check_signature_box(&cur.env, r, &added, &identity, code),
                    ));
                    let primary = primary_signature_field(&cur.env, &r.signer_id).map(|f| &f.id);
                    for f in cur.env.fields.iter().filter(|f| {
                        f.assigned_signer == r.signer_id
                            && matches!(f.field_type, FieldType::Signature | FieldType::Initials)
                    }) {
                        let expected = (Some(&f.id) != primary && r.kind == RecordKind::Signed)
                            .then(|| {
                                stamp_text(f.field_type, &display_name(&identity), &letters, code)
                            });
                        if f.value != expected {
                            problems.push(Finding::new(
                                m::STAMP_MISMATCH,
                                format!(
                                    "the stamp in field '{}' does not match the verified signer",
                                    f.id
                                ),
                            ));
                        }
                    }
                    if problems.is_empty() {
                        status.detail = format!(
                            "PAdES signature valid; identity verified as {} via {}",
                            identity.email, identity.issuer
                        );
                    }
                }
                Err(e) => problems.push(Finding::new(
                    m::IDENTITY_FAILED,
                    format!("identity verification failed: {e}"),
                )),
            },
            None => problems.push(Finding::new(
                m::SIGNING_TIME_UNREADABLE,
                format!("unparseable signing time '{}'", r.signed_at),
            )),
        }
        let existed_before = cur.existed_before.as_ref().map(|(t, _)| *t);
        if let (Some(exp), Some(t)) = (
            e0.policy.expiry.as_deref().and_then(unix_from_rfc3339),
            when,
        ) {
            if lapsed(t, existed_before, exp) {
                problems.push(Finding::new(
                    m::SIGNED_AFTER_EXPIRY,
                    "signed after the envelope expired",
                ));
            }
        }
        // Consent comes before signing. The consent time is the host's clock and the signing
        // time may be the signer's device clock, so a disagreement is a warning.
        if let (Some(consent), Some(t)) = (&status.esign_consent, when) {
            if unix_from_rfc3339(&consent.at).is_some_and(|c| c > t + LEEWAY_SECS) {
                report.record(
                    Finding::new(
                        m::CONSENT_AFTER_SIGNATURE,
                        format!(
                            "signer '{}': the consent to electronic records ({}) is dated after \
                             the signature",
                            r.signer_id, consent.at
                        ),
                    )
                    .signer(r.signer_id.clone())
                    .revision(k as u32),
                );
            }
        }
    }

    if problems.is_empty() {
        status.valid = trust_from_str(&status.identity_trust).is_acceptable();
    } else {
        status.valid = false;
        status.detail = joined(&problems);
        if problems.iter().any(|p| p.code == m::OUT_OF_ORDER.code) {
            report.order_ok = false;
        }
        let who = record
            .as_ref()
            .map(|r| r.signer_id.clone())
            .unwrap_or_else(|| format!("#{k}"));
        for p in problems {
            let p = p.prefixed(&format!("signer '{who}': ")).revision(k as u32);
            report.fail(match &record {
                Some(r) => p.signer(r.signer_id.clone()),
                None => p,
            });
        }
    }
    status
}

/// The envelope intent a preparer pins: everything except per-signature progress.
fn intent(env: &Envelope) -> serde_json::Value {
    serde_json::json!({
        "schema_version": env.schema_version,
        "envelope_id": env.envelope_id,
        "title": env.title,
        "created_by": env.created_by,
        "created_at": env.created_at,
        "created_by_pubkey": env.created_by_pubkey,
        "created_by_id_token": env.created_by_id_token,
        "created_by_idp_jwk": env.created_by_idp_jwk,
        "created_by_issuer": env.created_by_issuer,
        "created_by_email": env.created_by_email,
        "created_by_audience": env.created_by_audience,
        "source_digest": env.source_digest,
        "source_len": env.source_len,
        "documents": env.documents,
        "policy": env.policy,
        "signers": env.signers.iter().map(|s| serde_json::json!({
            "id": s.id, "name": s.name, "handle": s.handle, "role": s.role,
            "order": s.order, "identity_policy": s.identity_policy,
        })).collect::<Vec<_>>(),
        "fields": env.fields.iter().map(|f| serde_json::json!({
            "id": f.id, "field_type": f.field_type, "page": f.page, "rect": f.rect,
            "assigned_signer": f.assigned_signer, "required": f.required, "label": f.label,
            "group": f.group, "options": f.options, "date_format": f.date_format,
            "signing_date": f.signing_date, "number_format": f.number_format,
            "value_format": f.value_format, "length": f.length,
            "check_message": f.check_message, "formula": f.formula,
        })).collect::<Vec<_>>(),
        "verify_at": env.verify_at,
        "initials_rule": env.initials_rule,
    })
}

/// Validate that `cur` is exactly `prev` plus one signer's action by the key `fp`, with the
/// preparer's intent (`e0`) unchanged. Returns the new record.
fn check_transition(
    e0: &Envelope,
    prev: &Envelope,
    cur: &Envelope,
    fp: &str,
) -> std::result::Result<SignatureRecord, Finding> {
    if intent(cur) != intent(e0) {
        return Err(Finding::new(
            m::TERMS_CHANGED,
            "the envelope's prepared terms (title, documents, slots, fields, policy) were altered",
        ));
    }
    if prev.is_declined() {
        return Err(Finding::new(
            m::SIGNED_AFTER_DECLINE,
            "signed after the envelope was declined (void)",
        ));
    }
    if cur.signatures.len() != prev.signatures.len() + 1
        || cur.signatures[..prev.signatures.len()] != prev.signatures[..]
    {
        return Err(Finding::new(
            m::RECORD_MISMATCH,
            "signature records were rewritten or more than one was added",
        ));
    }
    let rec = cur.signatures.last().expect("len checked").clone();
    if rec.fingerprint != fp {
        return Err(Finding::new(
            m::RECORD_MISMATCH,
            "the new signature record does not belong to this PAdES signer",
        ));
    }
    if rec.revision as usize != prev.signatures.len() {
        return Err(Finding::new(
            m::RECORD_MISMATCH,
            "signature record has the wrong revision index",
        ));
    }
    // Exactly one slot changed: the record's, from pending to signed/declined, bound to `fp`.
    for (p, c) in prev.signers.iter().zip(cur.signers.iter()) {
        if p.id != rec.signer_id {
            if p.status != c.status
                || p.public_key != c.public_key
                || p.fingerprint != c.fingerprint
            {
                return Err(Finding::new(
                    m::SLOT_TAMPERED,
                    format!("signer slot '{}' was modified by another signer", p.id),
                ));
            }
            continue;
        }
        let want = match rec.kind {
            RecordKind::Signed => SignerStatus::Signed,
            RecordKind::Declined => SignerStatus::Declined,
        };
        if p.status != SignerStatus::Pending || c.status != want {
            return Err(Finding::new(
                m::SLOT_TAMPERED,
                format!("slot '{}' was not pending before this revision", p.id),
            ));
        }
        if c.fingerprint.as_deref() != Some(fp)
            || c.public_key
                .as_deref()
                .and_then(|k| crypto::fingerprint_of_public(k).ok())
                .as_deref()
                != Some(fp)
        {
            return Err(Finding::new(
                m::SLOT_TAMPERED,
                format!("slot '{}' is not bound to this signer's key", p.id),
            ));
        }
    }
    if !prev.signers.iter().any(|s| s.id == rec.signer_id) {
        return Err(Finding::new(
            m::SLOT_TAMPERED,
            format!("record names unknown slot '{}'", rec.signer_id),
        ));
    }
    // Signing order, judged against the state before this revision.
    if !prev
        .expected_signers()
        .iter()
        .any(|s| s.id == rec.signer_id)
    {
        return Err(Finding::new(
            m::OUT_OF_ORDER,
            format!(
                "out of order: slot '{}' signed before its turn",
                rec.signer_id
            ),
        ));
    }
    // Field values: only this signer's fields may change, and only from empty.
    for (p, c) in prev.fields.iter().zip(cur.fields.iter()) {
        if p.value != c.value {
            if p.assigned_signer != rec.signer_id {
                return Err(Finding::new(
                    m::FIELD_TAMPERED,
                    format!("field '{}' of another signer was changed", p.id),
                ));
            }
            if p.value.is_some() {
                return Err(Finding::new(
                    m::FIELD_TAMPERED,
                    format!("field '{}' was overwritten", p.id),
                ));
            }
            if rec.kind == RecordKind::Declined {
                return Err(Finding::new(
                    m::FIELD_TAMPERED,
                    "a decline must not fill fields",
                ));
            }
        }
    }
    // The signing client is not trusted to have applied the field rules.
    if let Some(offset) = &rec.utc_offset {
        if dates::parse_utc_offset(offset).is_none() {
            return Err(Finding::new(
                m::RECORD_MALFORMED,
                format!(
                    "the signature record's UTC offset '{offset}' is not +HH:MM or -HH:MM between \
                 -12:00 and +14:00"
                ),
            ));
        }
    }
    if rec.kind == RecordKind::Signed {
        check_signer_formulas(cur, &rec.signer_id)
            .map_err(|e| Finding::new(m::FORMULA_MISMATCH, e))?;
        check_signer_fields(cur, &rec.signer_id)
            .map_err(|e| Finding::new(m::FIELD_VALUE_INVALID, e))?;
        check_signing_dates(cur, &rec).map_err(|e| Finding::new(m::FIELD_VALUE_INVALID, e))?;
    }
    // Audit log: append-only, exactly one entry by this signer.
    if cur.audit_log.len() != prev.audit_log.len() + 1
        || cur.audit_log[..prev.audit_log.len()] != prev.audit_log[..]
    {
        return Err(Finding::new(
            m::AUDIT_LOG_REWRITTEN,
            "the audit log was rewritten",
        ));
    }
    let entry = cur.audit_log.last().expect("len checked");
    let want_action = match rec.kind {
        RecordKind::Signed => AuditAction::Signed,
        RecordKind::Declined => AuditAction::Declined,
    };
    if entry.actor_fingerprint != fp || entry.action != want_action {
        return Err(Finding::new(
            m::AUDIT_LOG_REWRITTEN,
            "the new audit entry does not record this signer's action",
        ));
    }
    if let Some(consent) = &entry.esign_consent {
        consent
            .validate()
            .map_err(|e| Finding::new(m::RECORD_MALFORMED, e))?;
    }
    Ok(rec)
}

/// The signer's *date signed* fields hold their local date at signing: the record's signing time
/// moved by its UTC offset (UTC when it has none), which is between UTC-12:00 and UTC+14:00.
fn check_signing_dates(env: &Envelope, rec: &SignatureRecord) -> std::result::Result<(), String> {
    let offset = rec
        .utc_offset
        .as_deref()
        .map_or(Some(0), dates::parse_utc_offset);
    let expected = offset.and_then(|m| dates::local_date(&rec.signed_at, m));
    for f in env
        .fields
        .iter()
        .filter(|f| f.assigned_signer == rec.signer_id && f.signing_date)
    {
        if f.value.is_none() || f.value != expected {
            return Err(format!(
                "date-signed field '{}' holds {}, not the signer's local date at signing ({})",
                f.id,
                f.value.as_deref().unwrap_or("nothing"),
                expected.as_deref().unwrap_or("unknown")
            ));
        }
    }
    Ok(())
}

/// The annotations a signer's increment may add: one signature widget (at the signer's primary
/// signature field, or invisible) and one read-only text per filled field of theirs (including
/// the engine stamps of their other signature/initials fields).
fn check_added_annotations(
    env: &Envelope,
    rec: &SignatureRecord,
    added: &[AddedAnnotation],
) -> Vec<String> {
    let mut problems = Vec::new();
    let sig_field = primary_signature_field(env, &rec.signer_id);
    let mut widgets = 0;
    let mut seen_fields: Vec<String> = Vec::new();
    for a in added {
        if !a.is_new_object {
            problems.push("an existing annotation was re-attached to a page".into());
            continue;
        }
        problems.extend(a.shape_problems.iter().cloned());
        match (a.subtype.as_str(), a.field_type.as_deref()) {
            ("Widget", Some("Sig")) => {
                widgets += 1;
                let invisible = a.rect.iter().all(|v| *v == 0.0);
                let ok = match (rec.kind, sig_field) {
                    (RecordKind::Signed, Some(f)) => {
                        a.page_index == f.page && rect_eq(a.rect, field_rect(f))
                    }
                    _ => {
                        // No box to fill: the signature must draw nothing. (A visible box is
                        // checked against the verified identity, see `check_signature_box`.)
                        problems.extend(pades::check_signature_widget(
                            a,
                            a.rect,
                            None,
                            InkRule::Recorded(None),
                        ));
                        invisible
                    }
                };
                if !ok {
                    problems.push("the signature appearance is not at the signer's field".into());
                }
            }
            ("FreeText", _) => {
                let field = env
                    .fields
                    .iter()
                    .find(|f| a.name.as_deref() == Some(field_annotation_name(&f.id).as_str()));
                match field {
                    Some(f)
                        if f.assigned_signer == rec.signer_id
                            && rec.kind == RecordKind::Signed
                            && a.page_index == f.page
                            && rect_eq(a.rect, field_rect(f))
                            && contents_match(f, a.contents.as_deref())
                            && !seen_fields.contains(&f.id) =>
                    {
                        seen_fields.push(f.id.clone());
                        // The recorded text is right; so must be what the page shows.
                        if let Some(expected) = field_text(f) {
                            problems.extend(pades::check_field_annotation(a, &expected));
                        }
                    }
                    _ => problems.push(
                        "a text annotation was added that does not match the signer's field values"
                            .into(),
                    ),
                }
            }
            (other, _) => problems.push(format!("an unexpected '{other}' annotation was added")),
        }
    }
    if widgets != 1 {
        problems.push("the revision must add exactly one signature field".into());
    }
    problems
}

/// Check that a signer's visible signature box shows what the engine draws for the *verified*
/// identity: a signing client cannot write another name, time or provider into it.
fn check_signature_box(
    env: &Envelope,
    rec: &SignatureRecord,
    added: &[AddedAnnotation],
    identity: &VerifiedIdentity,
    code: &str,
) -> Vec<String> {
    let Some(field) = primary_signature_field(env, &rec.signer_id) else {
        return Vec::new();
    };
    if rec.kind != RecordKind::Signed {
        return Vec::new();
    }
    let caption = signature_caption(identity, code, &rec.signed_at);
    added
        .iter()
        .filter(|a| a.subtype == "Widget" && a.field_type.as_deref() == Some("Sig"))
        .flat_map(|a| {
            pades::check_signature_widget(a, field_rect(field), Some(&caption), ink_rule(env, rec))
        })
        .collect()
}

/// The annotation that shows the value of field `f` on its page (`None` when nothing is drawn).
/// Signing writes it; verifying recomputes it and compares.
fn field_text(f: &Field) -> Option<FieldText> {
    rendered(f).map(|(text, mark)| FieldText {
        name: field_annotation_name(&f.id),
        page_index: f.page,
        rect: field_rect(f),
        text,
        mark,
        multiline: f.field_type == FieldType::Multiline,
    })
}

/// The caption of a signer's signature box, from what the verifier has checked: the verified
/// email, the signing key's code, the recorded signing time and the provider.
fn signature_caption(identity: &VerifiedIdentity, code: &str, signed_at: &str) -> SignatureCaption {
    SignatureCaption {
        signer_name: display_name(identity),
        code: code.to_string(),
        signed_at: human_time(signed_at),
        issuer: issuer_label(&identity.issuer),
    }
}

/// Whether an annotation's `/Contents` is what the value of field `f` renders to. The legacy
/// rendition (every non-ASCII character as `?`) is what the engine wrote before it drew the
/// WinAnsi range; documents signed then must still verify.
fn contents_match(f: &Field, contents: Option<&str>) -> bool {
    let multiline = f.field_type == FieldType::Multiline;
    match (rendered(f), contents) {
        (Some((text, mark)), Some(contents)) => {
            contents == pades::field_contents(&text, mark, multiline)
                || contents == pades::legacy_field_contents(&text, mark, multiline)
        }
        (None, None) => true,
        _ => false,
    }
}

fn rect_eq(a: [f32; 4], b: [f32; 4]) -> bool {
    a.iter().zip(b.iter()).all(|(x, y)| (x - y).abs() < 0.01)
}

/// The field rectangle as `[x1, y1, x2, y2]`.
fn field_rect(f: &Field) -> [f32; 4] {
    [
        f.rect.x as f32,
        f.rect.y as f32,
        (f.rect.x + f.rect.w) as f32,
        (f.rect.y + f.rect.h) as f32,
    ]
}

/// Annotation `/NM` used for a field's rendered value.
fn field_annotation_name(field_id: &str) -> String {
    format!("signpdf-field-{field_id}")
}

/// The field that carries a signer's visible PAdES signature: their first `Signature` field, or
/// failing that their first `Initials` field. Every *other* signature/initials field of theirs
/// receives an engine-generated stamp ([`stamp_text`]).
fn primary_signature_field<'a>(env: &'a Envelope, signer_id: &str) -> Option<&'a Field> {
    let of_type = |t: FieldType| {
        env.fields
            .iter()
            .find(|f| f.assigned_signer == signer_id && f.field_type == t)
    };
    of_type(FieldType::Signature).or_else(|| of_type(FieldType::Initials))
}

/// The letters stamped in signer `signer_id`'s further initials fields: the envelope's initials
/// rule ([`crate::initials`]) applied to the slot's name (a prepared term) and the verified email.
fn signer_initials(env: &Envelope, signer_id: &str, identity: &VerifiedIdentity) -> String {
    let slot_name = env.signer(signer_id).map_or("", |s| s.name.as_str());
    initials::stamp_initials(env.initials_rule, slot_name, &identity.email)
}

/// The engine-generated stamp drawn in a signer's non-primary signature/initials fields: for an
/// initials field, `initials` ([`signer_initials`]); for a signature field, the verified identity's
/// email address and the signing key's verification code. Both are derived only from what the
/// verifier has, so it can recompute them — a signer cannot put arbitrary text in these boxes.
fn stamp_text(field_type: FieldType, display_name: &str, initials: &str, code: &str) -> String {
    match field_type {
        FieldType::Initials => initials.to_string(),
        _ => format!("{display_name} - Sig {code}"),
    }
}

/// What a number field takes, in words: "a number with 2 decimal places from 0 to 100".
fn number_rule(format: &NumberFormat) -> String {
    let places = match format.decimals {
        0 => "a whole number".to_string(),
        1 => "a number with 1 decimal place".to_string(),
        n => format!("a number with {n} decimal places"),
    };
    match (&format.min, &format.max) {
        (Some(lo), Some(hi)) => format!("{places} from {lo} to {hi}"),
        (Some(lo), None) => format!("{places} of at least {lo}"),
        (None, Some(hi)) => format!("{places} of at most {hi}"),
        (None, None) => places,
    }
}

/// The value checks a preparer seals into field `f` (envelope schema version 8): a
/// `value_format` and a `length` only on text and multi-line fields, and valid; a
/// `check_message` only on a field with a check (a format, a length or a number format).
fn check_field_rules(f: &Field) -> std::result::Result<(), String> {
    let text = matches!(f.field_type, FieldType::Text | FieldType::Multiline);
    if !text && (f.value_format.is_some() || f.length.is_some()) {
        return Err(format!(
            "field {} has a value format or a length rule, but only text and multi-line fields \
             do",
            f.id
        ));
    }
    if let Some(length) = &f.length {
        length
            .validate()
            .map_err(|e| format!("field {} {e}", f.id))?;
    }
    f.check().map_err(|e| format!("field {} {e}", f.id))?;
    if let Some(message) = &f.check_message {
        if f.field_type == FieldType::Formula {
            return Err(format!(
                "field {} has a check message, but it is a formula field, which the signer does                  not fill",
                f.id
            ));
        }
        if f.value_format.is_none() && f.length.is_none() && f.number_format.is_none() {
            return Err(format!(
                "field {} has a check message, but no check (a value format, a length rule or a \
                 number format) to go with it",
                f.id
            ));
        }
        crate::formats::validate_check_message(message)
            .map_err(|e| format!("field {} {e}", f.id))?;
    }
    Ok(())
}

/// A text or multi-line field's entry as the envelope stores it: canonical when the field has a
/// format, within its length rule. The refusal names the value's code but not the value (it may
/// be an identifier the page draws masked).
fn checked_text(field: &Field, input: &str) -> Result<String> {
    let fid = &field.id;
    let check = field
        .check()
        .map_err(|e| SignPdfError::Workflow(format!("field {fid} {e}")))?;
    check.check(input).map_err(|e| {
        SignPdfError::Workflow(format!(
            "field {fid} does not take this value ({}): {}",
            e.code(),
            text_rule(field)
        ))
    })
}

/// What a text field with checks takes, in words: "an email address of at most 80 characters".
fn text_rule(f: &Field) -> String {
    use crate::formats::ValueFormatKind as K;
    let vf = f.value_format.as_ref();
    let what = match vf.map(|v| v.kind) {
        None => "text".to_string(),
        Some(K::Email) => "an email address".into(),
        Some(K::Phone) => "a phone number in international form (+ and the country code)".into(),
        Some(K::Amount) => format!(
            "an amount in {}",
            vf.and_then(|v| v.currency.as_deref())
                .unwrap_or("its currency")
        ),
        Some(K::PostalCode) => format!(
            "a postal code of {}",
            vf.and_then(|v| v.country.as_deref())
                .unwrap_or("its country")
        ),
        Some(K::Iban) => "an IBAN".into(),
        Some(K::UsSsn) => "a US Social Security number".into(),
        Some(K::UsEin) => "a US Employer Identification Number".into(),
        Some(K::Pattern) => "a value matching its pattern".into(),
    };
    match f.length.map(|l| (l.min, l.max)) {
        Some((Some(lo), Some(hi))) => format!("{what} of {lo} to {hi} characters"),
        Some((Some(lo), None)) => format!("{what} of at least {lo} characters"),
        Some((None, Some(hi))) => format!("{what} of at most {hi} characters"),
        _ => what,
    }
}

/// Most choices a dropdown may offer.
pub const MAX_DROPDOWN_OPTIONS: usize = 50;

/// The rules for a field's `options` at preparation: a dropdown has 2 to 50 of them, each a
/// non-empty text of at most 120 characters without surrounding spaces, all different; no other
/// field has any.
fn check_options(f: &Field) -> std::result::Result<(), String> {
    match (&f.options, f.field_type) {
        (None, FieldType::Dropdown) => Err(format!("dropdown {} needs a list of options", f.id)),
        (Some(_), t) if t != FieldType::Dropdown => Err(format!(
            "field {} has options, but only dropdowns have them",
            f.id
        )),
        (None, _) => Ok(()),
        (Some(options), _) => {
            if options.len() < 2 || options.len() > MAX_DROPDOWN_OPTIONS {
                return Err(format!(
                    "dropdown {} needs between 2 and {MAX_DROPDOWN_OPTIONS} options",
                    f.id
                ));
            }
            for (i, o) in options.iter().enumerate() {
                if o.is_empty() || o.trim() != o || o.chars().count() > 120 {
                    return Err(format!(
                        "dropdown {} has an empty, padded or over-long option",
                        f.id
                    ));
                }
                if o.chars().any(char::is_control) {
                    return Err(format!(
                        "dropdown {} has an option with a control character",
                        f.id
                    ));
                }
                if options[..i].contains(o) {
                    return Err(format!("dropdown {} lists '{o}' twice", f.id));
                }
            }
            Ok(())
        }
    }
}

/// Whether `value` is one of the choices of dropdown `f`.
fn is_option(f: &Field, value: &str) -> bool {
    f.options
        .as_deref()
        .is_some_and(|options| options.iter().any(|o| o == value))
}

/// Whether a checkbox or radio value means "selected" (`None` for anything unrecognised).
fn parse_choice(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "x" | "1" | "checked" => Some(true),
        "" | "false" | "no" | "off" | "0" | "unchecked" => Some(false),
        _ => None,
    }
}

/// A radio option, or a checkbox prepared with its caption: answered `true` or `false` and drawn
/// as a mark beside the caption. (Checkboxes from documents prepared before captions became
/// mandatory have no label; they keep their raw value and draw a bare `X`.)
fn is_choice(f: &Field) -> bool {
    match f.field_type {
        FieldType::Radio => true,
        FieldType::Checkbox => f.label.is_some(),
        _ => false,
    }
}

fn is_selected(f: &Field) -> bool {
    f.value.as_deref().and_then(parse_choice) == Some(true)
}

/// The rules a signer's answers satisfy once they have signed: `true`/`false` checkbox and radio
/// values, at most one selected option per radio group, a dropdown value that is one of its
/// options, and every required field answered.
/// Enforced when signing and re-checked by the verifier, which cannot trust the signing client.
fn check_signer_fields(env: &Envelope, signer_id: &str) -> std::result::Result<(), String> {
    let mine = || env.fields.iter().filter(|f| f.assigned_signer == signer_id);
    let selected_in = |group: &Option<String>| {
        mine()
            .filter(|o| o.field_type == FieldType::Radio && &o.group == group && is_selected(o))
            .count()
    };
    for f in mine() {
        let choice = is_choice(f);
        if choice && !matches!(f.value.as_deref(), Some("true" | "false")) {
            return Err(format!("field {} must be answered true or false", f.id));
        }
        let group = f.group.as_deref().unwrap_or_default();
        if f.field_type == FieldType::Radio && selected_in(&f.group) > 1 {
            return Err(format!(
                "more than one option of radio group '{group}' is selected"
            ));
        }
        // The engine fills every date of a signer who signs, as YYYY-MM-DD.
        if f.field_type == FieldType::Date
            && f.value.as_deref().and_then(dates::parse_iso_date).is_none()
        {
            return Err(format!(
                "date field {} holds '{}', not a date written YYYY-MM-DD",
                f.id,
                f.value.as_deref().unwrap_or_default()
            ));
        }
        if f.field_type == FieldType::Number {
            if let Some(v) = f.value.as_deref().filter(|v| !v.is_empty()) {
                let format = f.number_format.clone().unwrap_or_default();
                if format.check(v).as_deref() != Ok(v) {
                    return Err(format!(
                        "number field {} holds '{v}', not {}",
                        f.id,
                        number_rule(&format)
                    ));
                }
            }
        }
        if matches!(f.field_type, FieldType::Text | FieldType::Multiline) {
            let check = f
                .check()
                .map_err(|e| format!("field {} {e}, so its value cannot be checked", f.id))?;
            if let Some(v) = f.value.as_deref() {
                // The value is not repeated: it may be an identifier drawn masked.
                check.holds(v).map_err(|e| {
                    format!(
                        "field {} holds a value that does not have its format ({})",
                        f.id,
                        e.code()
                    )
                })?;
            }
        }
        if f.field_type == FieldType::Dropdown {
            if let Some(v) = f.value.as_deref().filter(|v| !v.is_empty()) {
                if !is_option(f, v) {
                    return Err(format!(
                        "field {} holds '{v}', which is not one of its options",
                        f.id
                    ));
                }
            }
        }
        if !f.required {
            continue;
        }
        match f.field_type {
            // Satisfied by the act of signing.
            FieldType::Signature | FieldType::Initials => {}
            FieldType::Radio if selected_in(&f.group) != 1 => {
                return Err(format!(
                    "required radio group '{group}' has no option selected"
                ));
            }
            FieldType::Radio => {}
            FieldType::Checkbox if choice && !is_selected(f) => {
                return Err(format!("required checkbox {} was not ticked", f.id));
            }
            _ if f.value.as_deref().is_none_or(str::is_empty) => {
                return Err(format!("required field {} was not filled", f.id));
            }
            _ => {}
        }
    }
    Ok(())
}

/// The formula fields of signer `signer_id` hold what their formulas compute from the values of
/// the revision (the signer's own and earlier signers'). The verifier does not trust the signing
/// client's arithmetic: it computes every value again, with the same exact decimals.
fn check_signer_formulas(env: &Envelope, signer_id: &str) -> std::result::Result<(), String> {
    let mine = |f: &Field| f.assigned_signer == signer_id && f.field_type == FieldType::Formula;
    if !env.fields.iter().any(mine) {
        return Ok(());
    }
    let computed = formula::compute_formula_fields(&env.fields, &BTreeMap::new(), mine)
        .map_err(|e| format!("{e} ({}), so its value cannot be checked", e.code))?;
    for f in env.fields.iter().filter(|f| mine(f)) {
        let want = computed.get(&f.id).map(String::as_str);
        if f.value.as_deref() != want {
            return Err(format!(
                "formula field {} holds '{}', but its formula computes '{}'",
                f.id,
                f.value.as_deref().unwrap_or_default(),
                want.unwrap_or_default()
            ));
        }
    }
    Ok(())
}

/// What is drawn for a field's value: the text and, for checkbox and radio fields, the mark drawn
/// before it (`None` = nothing to draw).
fn rendered(f: &Field) -> Option<(String, FieldMark)> {
    if is_choice(f) {
        let selected = parse_choice(f.value.as_deref()?)?;
        let mark = match f.field_type {
            FieldType::Radio => FieldMark::Radio { selected },
            _ => FieldMark::Checkbox { checked: selected },
        };
        return Some((f.label.clone().unwrap_or_default(), mark));
    }
    let v = f.value.as_deref()?.trim();
    let text = match f.field_type {
        FieldType::Checkbox => (parse_choice(v) == Some(true)).then(|| "X".to_string()),
        // Drawn in the format sealed in the field, whatever the signer's locale.
        FieldType::Date if !v.is_empty() => Some(
            dates::parse_iso_date(v)
                .map(|d| f.date_format.unwrap_or_default().format(d))
                .unwrap_or_else(|| v.to_string()),
        ),
        // Drawn in the style sealed in the field, whatever the signer's locale (after its
        // currency code from version 8).
        FieldType::Number | FieldType::Formula if !v.is_empty() => Some(
            f.number_format
                .as_ref()
                .map(|n| n.display(v))
                .unwrap_or_else(|| v.to_string()),
        ),
        // From version 8, a text value with a format is drawn as the format shows it: US
        // identifiers masked, an IBAN in groups, an amount after its currency.
        FieldType::Text | FieldType::Multiline if f.value_format.is_some() && !v.is_empty() => {
            Some(
                f.check()
                    .map(|c| c.display(v))
                    .unwrap_or_else(|_| v.to_string()),
            )
        }
        // Text (and a date that is not YYYY-MM-DD, which no signer revision may hold), and the
        // engine-generated stamps of non-primary signature/initials fields.
        _ => (!v.is_empty()).then(|| v.to_string()),
    }?;
    Some((text, FieldMark::None))
}

// --- timestamps ----------------------------------------------------------------------------

/// Check a PAdES B-T signature timestamp over `signature_value`.
fn signature_timestamp_status(
    token_der: &[u8],
    signature_value: &[u8],
    trust: &TrustStore,
    dss: Option<&Dss>,
) -> TimestampStatus {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(signature_value);
    timestamp_check("signature", token_der, &digest, trust, dss)
}

/// Check the legacy document-existence timestamp of a record, if any.
fn document_timestamp_status(
    rec: &SignatureRecord,
    trust: &TrustStore,
    dss: Option<&Dss>,
) -> Option<TimestampStatus> {
    let b64 = rec.timestamp_token.as_ref()?;
    let (Ok(der), Ok(digest)) = (crypto::b64_decode(b64), hex::decode(&rec.doc_digest)) else {
        return Some(TimestampStatus {
            kind: "document".into(),
            detail: "timestamp token is not decodable".into(),
            ..Default::default()
        });
    };
    Some(timestamp_check("document", &der, &digest, trust, dss))
}

/// Check an RFC 3161 token over `digest`: its imprint, the authority's signature and chain to a
/// trusted anchor, and, when the document has validation data (`dss`), the chain's revocation
/// status when the timestamp was made. A chain certificate revoked by then makes the timestamp
/// untrusted.
fn timestamp_check(
    kind: &str,
    token_der: &[u8],
    digest: &[u8],
    trust: &TrustStore,
    dss: Option<&Dss>,
) -> TimestampStatus {
    match crate::timestamp::verify_token(token_der, digest) {
        Ok(info) => {
            let when = unix_from_rfc3339(&info.gen_time).unwrap_or(i64::MIN);
            let tsa = trust.verify_tsa(token_der, when);
            let mut algorithms = tsa.algorithms;
            // The digest the token's imprint names.
            algorithms.extend(
                crate::timestamp::token_imprint(token_der)
                    .ok()
                    .and_then(|(oid, _)| Algorithm::from_digest_oid(&oid))
                    .map(AlgorithmUse::plain),
            );
            algorithms.sort();
            algorithms.dedup();
            let mut status = TimestampStatus {
                kind: kind.into(),
                time: info.gen_time,
                verified: true,
                signature_valid: tsa.signature_valid,
                trusted: tsa.trusted,
                tsa_name: tsa.tsa_name,
                serial: info.serial_hex,
                detail: tsa.detail,
                algorithms,
                distrusted_after: tsa.distrusted_after.unwrap_or_default(),
                ..Default::default()
            };
            if let (true, Some(dss)) = (tsa.trusted, dss) {
                let a = ltv::assess_chain(&tsa.chain, &dss.certs, &dss.ocsps, &dss.crls, when);
                status.chain = a.certificates;
                status.validation = if let Some(revoked) = a.revoked_before {
                    status.trusted = false;
                    status.detail =
                        format!("{revoked}, before this timestamp was made: it proves nothing");
                    "revoked"
                } else if a.complete {
                    "complete"
                } else {
                    "incomplete"
                }
                .into();
            }
            status
        }
        Err(e) => TimestampStatus {
            kind: kind.into(),
            detail: e.to_string(),
            ..Default::default()
        },
    }
}

/// The time at which a record's ID token validity is judged, and its source.
///
/// A trusted PAdES B-T **signature** timestamp proves the signature existed at `genTime`; since
/// the token is inside the signed bytes it was issued before that, so `genTime` is a sound upper
/// bound for the signing moment — it rescues honest signers with skewed clocks and defeats
/// backdated `signed_at`. Without one, the signer's self-asserted device clock is used.
fn signing_time(
    rec: &SignatureRecord,
    sig_ts: Option<&TimestampStatus>,
) -> (Option<i64>, &'static str) {
    if let Some(ts) = sig_ts.filter(|t| t.is_trusted()) {
        if let Some(t) = unix_from_rfc3339(&ts.time) {
            return (Some(t), "tsa");
        }
    }
    (unix_from_rfc3339(&rec.signed_at), "device")
}

// --- federated-identity helpers ------------------------------------------------------------

/// Wrap a single archived JWK (JSON) into a [`Jwks`] for offline verification.
fn jwks_from_jwk_json(jwk_json: &str) -> Result<Jwks> {
    let jwk: oidc::Jwk = serde_json::from_str(jwk_json)
        .map_err(|e| SignPdfError::Oidc(format!("archived JWK is not valid JSON: {e}")))?;
    Ok(Jwks { keys: vec![jwk] })
}

/// How `trust` regards a (signature-verified) token and the archived key that signed it, given
/// what is known about when the signature was made.
fn token_trust(
    trust: &TrustStore,
    token: &str,
    jwk_json: &str,
    audience: &str,
    time: SigningTimeEvidence,
) -> IdentityCheck {
    let (Ok(iss), Ok(jwk)) = (
        oidc::peek_issuer(token),
        serde_json::from_str::<oidc::Jwk>(jwk_json),
    ) else {
        return IdentityCheck {
            trust: IdentityTrust::UnknownKey,
            reason: "the identity token or its archived key cannot be read".into(),
        };
    };
    trust.check_identity_at(
        &iss,
        oidc::peek_tenant(token).as_deref(),
        audience,
        &jwk,
        time,
    )
}

fn trust_from_str(s: &str) -> IdentityTrust {
    IdentityTrust::parse(s).unwrap_or(IdentityTrust::UnknownKey)
}

/// Compute the key/document `nonce` from a base64 (SEC1) public key and a hex document digest.
fn nonce_for_b64_pubkey(pubkey_b64: &str, doc_digest_hex: &str) -> Result<String> {
    let sec1 = crypto::b64_decode(pubkey_b64)
        .map_err(|e| SignPdfError::Oidc(format!("invalid stored public key: {e}")))?;
    Ok(compute_nonce(&sec1, doc_digest_hex))
}

/// How a verified identity is named wherever a person reads it (signature box, stamps, audit log,
/// certificate): the email address its provider verified. Never the token's `name` claim: that is
/// a profile name the account holder types, so showing it would let anyone sign "as" anybody.
fn display_name(identity: &VerifiedIdentity) -> String {
    identity.email.clone()
}

/// What [`identity_check`] found: how the trust store regards the identity, and how the
/// algorithm policy judged its token (for a warning when a timestamp kept it).
struct IdentityOutcome {
    check: IdentityCheck,
    algorithms: AlgorithmVerdict,
}

/// How far a verifier can rely on a (signature-verified) identity: the trust store's verdict on
/// its token and key ([`token_trust`]); then the algorithm policy's on the token's algorithms;
/// then, for a signer, whether the assurance level computed from the token and the trust store
/// meets the slot's `policy`. Sets the status's level and basis when the identity is anchored
/// (trusted, or accepted by the insecure dev opt-in) and its algorithms accepted.
fn identity_check(
    trust: &TrustStore,
    algorithms: &Algorithms,
    identity: &VerifiedIdentity,
    (token, jwk_json, audience): (&str, &str, &str),
    time: SigningTimeEvidence,
    policy: Option<&IdentityPolicy>,
    status: &mut SignatureStatus,
) -> IdentityOutcome {
    let check = token_trust(trust, token, jwk_json, audience, time);
    if !check.trust.is_acceptable() {
        return IdentityOutcome {
            check,
            algorithms: AlgorithmVerdict::Accepted,
        };
    }
    let uses = serde_json::from_str::<oidc::Jwk>(jwk_json)
        .map(|jwk| oidc::token_algorithms(token, &jwk))
        .unwrap_or_default();
    let verdict = algorithms.judge(&uses, time.existed_before);
    if let AlgorithmVerdict::Refused(why) = &verdict {
        return IdentityOutcome {
            check: IdentityCheck {
                trust: IdentityTrust::AlgorithmNotAccepted,
                reason: format!(
                    "the identity token from {} cannot be relied on: {why}",
                    identity.issuer
                ),
            },
            algorithms: verdict,
        };
    }
    let assessment = assess(trust, identity);
    status.level = Some(assessment.level);
    status.basis = assessment.basis.clone();
    if let Some(Err(why)) = policy.map(|p| assessment.meets(p)) {
        return IdentityOutcome {
            check: IdentityCheck {
                trust: IdentityTrust::InsufficientLevel,
                reason: why,
            },
            algorithms: verdict,
        };
    }
    IdentityOutcome {
        check,
        algorithms: verdict,
    }
}

/// The assurance level of `identity` as `trust` sees its issuer ([`TrustStore::issuer_kind`]).
/// At signing time the engine has no trust store: it uses [`TrustStore::empty`], which knows the
/// well-known account providers and counts any other issuer as an email-code provider.
fn assess(trust: &TrustStore, identity: &VerifiedIdentity) -> Assessment {
    identity.assess(trust.issuer_kind(&identity.issuer, identity.tenant_id.as_deref()))
}

/// Judge every trusted timestamp's algorithms ([`crate::algorithms`]), from the last boundary of
/// the file to the first: a timestamp counts when the policy accepts its algorithms at the
/// verifier's time, or when a later timestamp that counts shows it existed before its
/// algorithms' end dates. One that does not count is marked untrusted, so it neither dates nor
/// covers anything. `doc_sound` says which document timestamps are sound (intact and over the
/// bytes before them); only those cover anything.
fn judge_timestamp_algorithms(
    doc_sound: &[bool],
    ends: &[(usize, Boundary)],
    sig_stamps: &mut [Option<TimestampStatus>],
    doc_stamps: &mut [std::result::Result<TimestampStatus, String>],
    algorithms: &Algorithms,
    notes: &mut Vec<String>,
) {
    // The earliest time of a counting timestamp after the boundary being judged.
    let mut later: Option<i64> = None;
    let mut revision = sig_stamps.len();
    for (_, b) in ends.iter().rev() {
        let (stamp, name, sound) = match *b {
            Boundary::Signature(i) => {
                revision -= 1;
                (
                    sig_stamps[i].as_mut(),
                    format!("the signature timestamp of revision {revision}"),
                    true,
                )
            }
            Boundary::DocumentTimestamp(j) => (
                doc_stamps[j].as_mut().ok(),
                format!("document timestamp {}", j + 1),
                doc_sound[j],
            ),
        };
        let Some(t) = stamp.filter(|t| t.is_trusted() && sound) else {
            continue;
        };
        match algorithms.judge(&t.algorithms, later) {
            AlgorithmVerdict::Accepted => {}
            AlgorithmVerdict::AcceptedByTimestamp(w) => notes.push(format!("{name}: {w}")),
            AlgorithmVerdict::Refused(why) => {
                t.trusted = false;
                t.detail = format!("the algorithm policy does not accept it: {why}");
                continue;
            }
        }
        if let Some(at) = unix_from_rfc3339(&t.time) {
            later = Some(later.map_or(at, |l| l.min(at)));
        }
    }
}

/// Validate the preparer's ID token: signature against the supplied JWK, standard claims, and
/// the `nonce == H(preparer_pubkey ‖ source_digest)` binding to this preparation key + document.
fn validate_preparer_token(
    request: &PrepareRequest,
    preparer_key: &KeyPair,
    source_digest: &str,
) -> Result<VerifiedIdentity> {
    if request.id_token.is_empty() || request.idp_jwk.is_empty() {
        return Err(SignPdfError::Workflow(
            "preparer must authenticate with a federated identity (missing id_token/idp_jwk)"
                .into(),
        ));
    }
    let jwks = jwks_from_jwk_json(&request.idp_jwk)?;
    let allowed = if request.allowed_issuers.is_empty() {
        vec![oidc::peek_issuer(&request.id_token)?]
    } else {
        request.allowed_issuers.clone()
    };
    let mut validation = Validation::new(allowed, request.audience.clone(), now_unix());
    validation.expected_nonce = Some(compute_nonce(&preparer_key.public_sec1(), source_digest));
    let identity = oidc::verify_id_token(&request.id_token, &jwks, &validation)?;
    identity
        .require_verified_email()
        .map_err(SignPdfError::Oidc)?;
    Ok(identity)
}

/// The issuers accepted at sign time: every pending slot's allowed issuers, plus any the request
/// adds. When that union is empty, fall back to the token's own (unverified) issuer.
fn sign_allowed_issuers(env: &Envelope, request: &SignRequest) -> Result<Vec<String>> {
    let mut issuers: Vec<String> = Vec::new();
    for s in env
        .signers
        .iter()
        .filter(|s| s.status == SignerStatus::Pending)
    {
        for iss in &s.identity_policy.allowed_issuers {
            if !issuers.contains(iss) {
                issuers.push(iss.clone());
            }
        }
    }
    for iss in &request.allowed_issuers {
        if !issuers.contains(iss) {
            issuers.push(iss.clone());
        }
    }
    if issuers.is_empty() {
        issuers.push(oidc::peek_issuer(&request.id_token)?);
    }
    Ok(issuers)
}

/// Validate the signer's ID token: signature against the supplied JWK, standard claims, and the
/// `nonce == H(signer_pubkey ‖ doc_digest)` binding to this ephemeral key + document.
fn validate_signer_token(
    env: &Envelope,
    request: &SignRequest,
    signer_key: &KeyPair,
    doc_digest: &str,
) -> Result<VerifiedIdentity> {
    if request.id_token.is_empty() || request.idp_jwk.is_empty() {
        return Err(SignPdfError::Workflow(
            "signer must authenticate with a federated identity (missing id_token/idp_jwk)".into(),
        ));
    }
    let jwks = jwks_from_jwk_json(&request.idp_jwk)?;
    let allowed = sign_allowed_issuers(env, request)?;
    let mut validation = Validation::new(allowed, request.audience.clone(), now_unix());
    validation.expected_nonce = Some(compute_nonce(&signer_key.public_sec1(), doc_digest));
    let identity = oidc::verify_id_token(&request.id_token, &jwks, &validation)?;
    identity
        .require_verified_email()
        .map_err(SignPdfError::Oidc)?;
    Ok(identity)
}

/// Auto-resolve which pending signer slot a verified identity fills (no self-selection). Errors
/// when no slot's policy is satisfied; when several match, an explicit `asserted` slot id must
/// disambiguate.
fn resolve_signer_from_token(
    env: &Envelope,
    identity: &VerifiedIdentity,
    asserted: Option<&str>,
) -> Result<String> {
    // The level as a verifier without a trust store computes it: the well-known providers are
    // account providers, any other issuer an email-code provider (the verifier's trust store
    // decides in the end).
    let assessment = assess(&TrustStore::empty(), identity);
    let pending = || {
        env.signers
            .iter()
            .filter(|s| s.status == SignerStatus::Pending)
            .filter(|s| identity.satisfies(&s.identity_policy).is_ok())
    };
    let matches: Vec<&Signer> = pending()
        .filter(|s| assessment.meets(&s.identity_policy).is_ok())
        .collect();

    match matches.as_slice() {
        [] => Err(SignPdfError::Workflow(
            match pending().find_map(|s| assessment.meets(&s.identity_policy).err()) {
                // The identity is the slot's, but its sign-in is not strong enough.
                Some(why) => format!(
                    "verified identity {} ({}) cannot fill its slot: {why}",
                    identity.email, identity.issuer
                ),
                None => format!(
                    "verified identity {} ({}) does not match any pending signer slot",
                    identity.email, identity.issuer
                ),
            },
        )),
        [only] => {
            if let Some(a) = asserted {
                if a != only.id {
                    return Err(SignPdfError::Workflow(format!(
                        "asserted signer '{a}' does not match the slot your identity resolves to ('{}')",
                        only.id
                    )));
                }
            }
            Ok(only.id.clone())
        }
        many => {
            let a = asserted.ok_or_else(|| {
                SignPdfError::Workflow(format!(
                    "your identity matches {} pending signer slots; specify which one you are signing",
                    many.len()
                ))
            })?;
            if many.iter().any(|s| s.id == a) {
                Ok(a.to_string())
            } else {
                Err(SignPdfError::Workflow(format!(
                    "asserted signer '{a}' is not among the slots your identity can fill"
                )))
            }
        }
    }
}

/// Re-validate a signature record's embedded ID token offline at time `when`: token signature
/// against the archived JWK, standard claims, the key/document `nonce` binding, the resolved
/// slot's identity policy, and that `when` is not before the token was issued.
fn validate_record_identity(
    env: &Envelope,
    rec: &SignatureRecord,
    when: i64,
) -> std::result::Result<VerifiedIdentity, String> {
    if rec.id_token.is_empty() || rec.idp_jwk.is_empty() {
        return Err("signature record carries no federated identity token".to_string());
    }
    let jwks = jwks_from_jwk_json(&rec.idp_jwk).map_err(|e| e.to_string())?;
    let mut validation =
        Validation::new(vec![rec.idp_issuer.clone()], rec.idp_audience.clone(), when);
    validation.leeway_secs = LEEWAY_SECS;
    validation.expected_nonce =
        Some(nonce_for_b64_pubkey(&rec.public_key, &rec.doc_digest).map_err(|e| e.to_string())?);
    let identity =
        oidc::verify_id_token(&rec.id_token, &jwks, &validation).map_err(|e| e.to_string())?;
    if let Some(iat) = oidc::peek_issued_at(&rec.id_token) {
        if when + LEEWAY_SECS < iat {
            return Err("signing time precedes the identity token's issuance (backdated)".into());
        }
    }
    let slot = env
        .signer(&rec.signer_id)
        .ok_or_else(|| format!("unknown slot '{}'", rec.signer_id))?;
    identity.satisfies(&slot.identity_policy)?;
    Ok(identity)
}

/// Re-validate the preparer's ID token offline at preparation time.
fn validate_preparer_identity(env: &Envelope) -> std::result::Result<VerifiedIdentity, String> {
    if env.created_by_id_token.is_empty() || env.created_by_idp_jwk.is_empty() {
        return Err("envelope was prepared without a federated preparer identity".to_string());
    }
    let jwks = jwks_from_jwk_json(&env.created_by_idp_jwk).map_err(|e| e.to_string())?;
    let now = unix_from_rfc3339(&env.created_at)
        .ok_or_else(|| format!("unparseable preparation time '{}'", env.created_at))?;
    let mut validation = Validation::new(
        vec![env.created_by_issuer.clone()],
        env.created_by_audience.clone(),
        now,
    );
    validation.leeway_secs = LEEWAY_SECS;
    validation.expected_nonce = Some(
        nonce_for_b64_pubkey(&env.created_by_pubkey, &env.source_digest)
            .map_err(|e| e.to_string())?,
    );
    let identity = oidc::verify_id_token(&env.created_by_id_token, &jwks, &validation)
        .map_err(|e| e.to_string())?;
    identity.require_verified_email()?;
    if identity.email != env.created_by_email || identity.issuer != env.created_by_issuer {
        return Err("recorded preparer email/issuer do not match the token".into());
    }
    Ok(identity)
}

/// Build the embedded-file attachment carrying the envelope JSON.
fn envelope_attachment(env: &Envelope) -> Result<EmbeddedFile> {
    Ok(EmbeddedFile {
        name: ENVELOPE_NAME.to_string(),
        data: schema::encode_envelope(env)?,
        mime: "application/json".to_string(),
        relationship: "Data".to_string(),
        description: format!("SignPDF workflow envelope: {}", env.title),
    })
}

/// The first envelope schema version whose signature records keep the signer's drawing
/// ([`SignatureRecord::drawing`]) and whose boxes may show a typed signature.
const DRAWING_RECORDED_FROM: u32 = 6;

/// Whether signature records of envelope schema `version` keep the signer's drawing, and so
/// what rule the drawing area of their boxes follows ([`InkRule`]).
fn records_drawing(version: u32) -> bool {
    version >= DRAWING_RECORDED_FROM
}

/// The drawing a sign request brings: pen strokes or a typed signature, not both; a typed one
/// only in an envelope whose version can show and record it.
fn signer_drawing(request: &SignRequest, version: u32) -> Result<Option<SignatureDrawing>> {
    match (&request.drawn_signature, &request.typed_signature) {
        (Some(_), Some(_)) => Err(SignPdfError::Workflow(
            "a signature is drawn or typed, not both: send drawn_signature or typed_signature"
                .into(),
        )),
        (Some(strokes), None) => Ok(Some(SignatureDrawing::Drawn {
            strokes: strokes.clone(),
        })),
        (None, Some(_)) if !records_drawing(version) => Err(SignPdfError::Workflow(format!(
            "this envelope (schema version {version}) was prepared by an older build that cannot \
             show a typed signature: draw the signature instead"
        ))),
        (None, Some(paths)) => Ok(Some(SignatureDrawing::Typed {
            paths: paths.clone(),
        })),
        (None, None) => Ok(None),
    }
}

/// What a signer's box may show in its drawing area: before version 6, nothing or pen strokes;
/// from version 6, exactly the drawing their record keeps.
fn ink_rule<'a>(env: &Envelope, rec: &'a SignatureRecord) -> InkRule<'a> {
    if records_drawing(env.schema_version) {
        InkRule::Recorded(rec.drawing.as_ref())
    } else {
        InkRule::Strokes
    }
}

/// A drawing a signature record keeps must be one the signer could draw: in a version that
/// records drawings, in a signed (not declined) revision, for a signer with a visible box, and
/// within the drawing limits.
fn check_recorded_drawing(env: &Envelope, rec: &SignatureRecord) -> Option<String> {
    let drawing = rec.drawing.as_ref()?;
    if !records_drawing(env.schema_version) {
        return Some(format!(
            "the signature record keeps a drawing, which a version-{} envelope cannot",
            env.schema_version
        ));
    }
    if rec.kind != RecordKind::Signed || primary_signature_field(env, &rec.signer_id).is_none() {
        return Some(
            "the signature record keeps a drawing, but the signer has no signature box to show it"
                .into(),
        );
    }
    drawing
        .validate()
        .err()
        .map(|e| format!("the recorded drawing cannot be drawn: {e}"))
}

/// Deterministic byte string a [`SignatureRecord`]'s self-contained signature is computed over.
/// It does not name the signer's drawing: the revision's PDF signature covers the whole record,
/// and the drawing is decoration, not evidence.
fn record_signing_payload(envelope_id: &str, r: &SignatureRecord) -> Vec<u8> {
    format!(
        "signpdf-pades-rec-v2|{}|{}|{}|{}|{}|{}|{}|{}",
        envelope_id,
        r.kind.as_str(),
        r.signer_id,
        r.fingerprint,
        r.revision,
        r.doc_digest,
        r.signed_prefix_len,
        r.signed_at
    )
    .into_bytes()
}

/// Map a signer's primary signature field (see [`primary_signature_field`]) to a visible PAdES
/// appearance, falling back to an invisible signature when the signer has no such field. When
/// the signature is visible, a caption (`Signed by:` + name + verification code/time/provider)
/// is attached.
fn appearance_for(
    env: &Envelope,
    signer_id: &str,
    identity: &VerifiedIdentity,
    reason: Option<String>,
    code: &str,
    signed_at: &str,
) -> SignAppearance {
    let name = display_name(identity);
    let field = primary_signature_field(env, signer_id);
    let (page_index, rect) = match field {
        Some(f) => (f.page, Some(field_rect(f))),
        None => (0, None),
    };
    let caption = rect.map(|_| signature_caption(identity, code, signed_at));
    SignAppearance {
        name,
        reason,
        location: None,
        page_index,
        rect,
        caption,
        ink: None,
    }
}

/// Render an RFC 3339 timestamp as a compact `YYYY-MM-DD HH:MM UTC` for the visible appearance,
/// returning the original string if it is not in the expected shape.
pub(crate) fn human_time(rfc3339: &str) -> String {
    match (rfc3339.get(0..10), rfc3339.get(11..16)) {
        (Some(date), Some(time)) => format!("{date} {time} UTC"),
        _ => rfc3339.to_string(),
    }
}

/// Reduce an issuer URL to a short, human label for the visible appearance footer (e.g.
/// `https://accounts.google.com` → `google`).
pub(crate) fn issuer_label(issuer: &str) -> String {
    let host = issuer
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(issuer);
    let lower = host.to_ascii_lowercase();
    if lower.contains("google") {
        "google".to_string()
    } else if lower.contains("microsoft") || lower.contains("login.live") {
        "microsoft".to_string()
    } else if lower.contains("apple") {
        "apple".to_string()
    } else {
        host.to_string()
    }
}

/// Adversarial helpers for tests: sign like a **malicious** participant would (skipping the
/// integrity precheck and/or rewriting the envelope before it is signed), to prove the verifier
/// catches it. Compiled only under `#[cfg(test)]` or the `test-issuer` feature.
#[cfg(any(test, feature = "test-issuer"))]
pub mod testing {
    use super::*;

    /// Prepare `source_pdf` like [`prepare`], but apply `tamper` to the envelope right before it
    /// is embedded and signed: a modified preparing client that writes terms prepare refuses.
    pub fn prepare_malicious(
        source_pdf: &[u8],
        request: &PrepareRequest,
        preparer_key: &KeyPair,
        tamper: &dyn Fn(&mut Envelope),
    ) -> Result<Vec<u8>> {
        prepare_inner(source_pdf, request, preparer_key, tamper)
    }

    /// Sign `pdf` like [`sign`], but optionally skip the integrity precheck and apply `tamper` to
    /// the envelope right before it is embedded and signed.
    pub fn sign_malicious(
        pdf: &[u8],
        signer_key: &KeyPair,
        request: &SignRequest,
        skip_precheck: bool,
        tamper: &dyn Fn(&mut Envelope),
    ) -> Result<Vec<u8>> {
        sign_inner(
            pdf,
            signer_key,
            request,
            HostTimestamp::Nothing,
            !skip_precheck,
            tamper,
            &|_| {},
        )
        .map(|increment| pades::appended(pdf, &increment))
    }

    /// Sign `pdf` like [`sign`], but also write `extra` (object number, body) into the
    /// signer's revision, under the signature: a modified signing client that rewrites objects
    /// of the document (a page, say) in the revision it signs.
    pub fn sign_with_extra_objects(
        pdf: &[u8],
        signer_key: &KeyPair,
        request: &SignRequest,
        extra: &[(u32, Vec<u8>)],
    ) -> Result<Vec<u8>> {
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                pades::EXTRA_OBJECTS.with(|e| e.borrow_mut().clear());
            }
        }
        pades::EXTRA_OBJECTS.with(|e| *e.borrow_mut() = extra.to_vec());
        let _clear = Clear;
        sign(pdf, signer_key, request)
    }

    /// Sign `pdf` like [`sign`], but let `redraw` change what is drawn on the page (the
    /// signature box, the field values) after the engine has decided it: a modified signing
    /// client that records one thing and shows another.
    pub fn sign_redrawn(
        pdf: &[u8],
        signer_key: &KeyPair,
        request: &SignRequest,
        redraw: &dyn Fn(&mut SignOptions<'_>),
    ) -> Result<Vec<u8>> {
        sign_inner(
            pdf,
            signer_key,
            request,
            HostTimestamp::Nothing,
            true,
            &|_| {},
            redraw,
        )
        .map(|increment| pades::appended(pdf, &increment))
    }

    /// [`sign_malicious`] and [`sign_redrawn`] together: a modified signing client that records
    /// a value of its own (`tamper`) and draws it to match (`redraw`).
    pub fn sign_malicious_redrawn(
        pdf: &[u8],
        signer_key: &KeyPair,
        request: &SignRequest,
        tamper: &dyn Fn(&mut Envelope),
        redraw: &dyn Fn(&mut SignOptions<'_>),
    ) -> Result<Vec<u8>> {
        sign_inner(
            pdf,
            signer_key,
            request,
            HostTimestamp::Nothing,
            true,
            tamper,
            redraw,
        )
        .map(|increment| pades::appended(pdf, &increment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::testing::TestIssuer;

    const BASE: i64 = 1_700_000_000;

    /// Every message and warning of a report goes through `VerificationReport::record`, which
    /// gives it a finding with a stable code: nothing else in this file writes the two lists.
    #[test]
    fn every_report_message_is_recorded_with_a_code() {
        let source = include_str!("workflow.rs");
        for list in ["messages", "warnings"] {
            let writes = [".push(", ".extend(", ".insert(", " = vec!", ".append("]
                .iter()
                .map(|op| source.matches(&format!("{list}{op}")).count())
                .sum::<usize>();
            // `self.<list>.push(` in `record`, and these lines' own needles are not followed by
            // an opening parenthesis.
            assert_eq!(
                writes, 1,
                "report.{list} is written outside VerificationReport::record"
            );
        }
    }
    const TEST_ISSUER: &str = "https://issuer.test";
    const TEST_AUDIENCE: &str = "signpdf-test";

    fn rfc3339(ts: i64) -> String {
        use time::format_description::well_known::Rfc3339;
        use time::OffsetDateTime;
        OffsetDateTime::from_unix_timestamp(ts)
            .unwrap()
            .format(&Rfc3339)
            .unwrap()
    }

    /// A signed record + matching single-signer envelope; the token is valid in
    /// `[BASE, BASE + 3600]`.
    fn record_at(signed_at_ts: i64) -> (Envelope, SignatureRecord) {
        record_with_email(
            signed_at_ts,
            serde_json::json!({ "email": "alice@example.com", "email_verified": true }),
        )
    }

    /// [`record_at`] with the token's email claims given by `email_claims`.
    fn record_with_email(
        signed_at_ts: i64,
        email_claims: serde_json::Value,
    ) -> (Envelope, SignatureRecord) {
        let key = KeyPair::generate();
        let doc_digest = sha256_hex(b"the signed document bytes");
        let nonce = compute_nonce(&key.public_sec1(), &doc_digest);
        let issuer = TestIssuer::es256();
        let mut claims = serde_json::json!({
            "iss": TEST_ISSUER, "sub": "user|alice", "aud": TEST_AUDIENCE,
            "iat": BASE, "exp": BASE + 3600, "name": "Alice", "nonce": nonce,
        });
        for (claim, value) in email_claims.as_object().expect("an object") {
            claims[claim] = value.clone();
        }
        let id_token = issuer.mint(claims);
        let rec = SignatureRecord {
            kind: RecordKind::Signed,
            signer_id: "s1".into(),
            fingerprint: key.fingerprint(),
            public_key: key.public_b64(),
            algorithm: "ES256".into(),
            signed_at: rfc3339(signed_at_ts),
            timestamp_token: None,
            doc_digest: doc_digest.clone(),
            signed_prefix_len: 25,
            signature: String::new(),
            revision: 0,
            id_token,
            idp_jwk: serde_json::to_string(&issuer.jwk()).unwrap(),
            idp_issuer: TEST_ISSUER.into(),
            idp_subject: "user|alice".into(),
            idp_email: "alice@example.com".into(),
            idp_audience: TEST_AUDIENCE.into(),
            utc_offset: None,
            drawing: None,
        };
        let env = Envelope {
            schema_version: SCHEMA_VERSION,
            envelope_id: "env-test".into(),
            title: "T".into(),
            created_by: "preparer@example.com".into(),
            created_at: rfc3339(BASE),
            created_by_pubkey: String::new(),
            created_by_id_token: String::new(),
            created_by_idp_jwk: String::new(),
            created_by_issuer: String::new(),
            created_by_email: String::new(),
            created_by_audience: String::new(),
            source_digest: doc_digest,
            source_len: 25,
            documents: Vec::new(),
            verify_at: None,
            initials_rule: Some(InitialsRule::NameV1),
            signers: vec![Signer {
                id: "s1".into(),
                name: "Alice".into(),
                handle: "alice@example.com".into(),
                role: "Signer".into(),
                order: 1,
                status: SignerStatus::Signed,
                identity_policy: IdentityPolicy::default(),
                public_key: Some(key.public_b64()),
                fingerprint: Some(key.fingerprint()),
            }],
            fields: vec![],
            policy: Policy::default(),
            signatures: vec![],
            audit_log: vec![],
            service_link: None,
        };
        (env, rec)
    }

    fn trusted_ts(time: i64) -> TimestampStatus {
        TimestampStatus {
            kind: "signature".into(),
            time: rfc3339(time),
            verified: true,
            signature_valid: true,
            trusted: true,
            tsa_name: "TSA".into(),
            serial: "01".into(),
            ..Default::default()
        }
    }

    /// A trusted timestamp at `time` resting on `algorithms`.
    fn stamp_on(time: i64, algorithms: Vec<AlgorithmUse>) -> TimestampStatus {
        TimestampStatus {
            algorithms,
            ..trusted_ts(time)
        }
    }

    #[test]
    fn a_later_timestamp_keeps_one_whose_algorithm_has_ended() {
        // RSA ends at END. Revision 0's signature timestamp (RSA, before END) is followed by a
        // document timestamp (ECDSA), then revision 1's signature timestamp (RSA).
        const END: i64 = BASE + 10 * 86_400;
        let rsa = vec![
            AlgorithmUse::rsa(2048),
            AlgorithmUse::plain(Algorithm::Sha256),
        ];
        let ec = REVISION_ALGORITHMS.to_vec();
        let mut policy = AlgorithmPolicy::builtin();
        policy.version = 9;
        policy
            .algorithms
            .iter_mut()
            .find(|r| r.algorithm == "RSA-PKCS1-v1_5")
            .unwrap()
            .not_after = Some(rfc3339(END));
        let ends = [
            (100, Boundary::Signature(0)),
            (200, Boundary::DocumentTimestamp(0)),
            (300, Boundary::Signature(1)),
        ];
        let judged = |now: i64, doc_time: i64, doc_sound: bool| {
            let mut sig = vec![
                Some(stamp_on(BASE, rsa.clone())),
                Some(stamp_on(BASE + 86_400, rsa.clone())),
            ];
            let mut doc = vec![Ok(stamp_on(doc_time, ec.clone()))];
            let mut warnings = Vec::new();
            let algorithms = Algorithms {
                policy: &policy,
                now: Some(now),
            };
            judge_timestamp_algorithms(
                &[doc_sound],
                &ends,
                &mut sig,
                &mut doc,
                &algorithms,
                &mut warnings,
            );
            let trusted: Vec<bool> = sig
                .iter()
                .map(|t| t.as_ref().unwrap().is_trusted())
                .collect();
            (trusted, doc[0].as_ref().unwrap().is_trusted(), warnings)
        };
        // Before the end, everything counts.
        let (sig, doc, warnings) = judged(END - 60, BASE + 3600, true);
        assert_eq!((sig, doc), (vec![true, true], true));
        assert!(warnings.is_empty(), "{warnings:?}");
        // After it, the RSA stamp that the ECDSA document timestamp covers is kept (with a
        // warning); the last RSA stamp, which nothing later covers, is not.
        let (sig, doc, warnings) = judged(END + 60, BASE + 3600, true);
        assert_eq!((sig, doc), (vec![true, false], true));
        assert!(
            warnings.len() == 1 && warnings[0].contains("revision 0"),
            "{warnings:?}"
        );
        // A covering timestamp from after the end keeps nothing; neither does an unsound one.
        assert_eq!(judged(END + 60, END + 30, true).0, vec![false, false]);
        assert_eq!(judged(END + 60, BASE + 3600, false).0, vec![false, false]);
        // A refused timestamp says why.
        let mut stamp = Some(stamp_on(BASE, rsa.clone()));
        judge_timestamp_algorithms(
            &[],
            &[(1, Boundary::Signature(0))],
            std::slice::from_mut(&mut stamp),
            &mut [],
            &Algorithms {
                policy: &policy,
                now: None,
            },
            &mut Vec::new(),
        );
        let stamp = stamp.unwrap();
        assert!(!stamp.is_trusted());
        assert!(stamp.detail.contains("no clock"), "{}", stamp.detail);
    }

    #[test]
    fn without_timestamp_validation_uses_device_clock() {
        let (env, rec) = record_at(BASE + 1_800);
        let (t, src) = signing_time(&rec, None);
        assert_eq!(src, "device");
        assert!(validate_record_identity(&env, &rec, t.unwrap()).is_ok());

        let (env, rec) = record_at(BASE + 100_000);
        let (t, _) = signing_time(&rec, None);
        let err = validate_record_identity(&env, &rec, t.unwrap()).unwrap_err();
        assert!(
            err.contains("expired"),
            "expected an expiry error, got: {err}"
        );
    }

    #[test]
    fn trusted_signature_timestamp_rescues_and_defeats_backdating() {
        // Device clock far past expiry, trusted TSA inside validity: rescued.
        let (env, rec) = record_at(BASE + 100_000);
        let ts = trusted_ts(BASE + 1_800);
        let (t, src) = signing_time(&rec, Some(&ts));
        assert_eq!(src, "tsa");
        assert!(validate_record_identity(&env, &rec, t.unwrap()).is_ok());

        // Backdated device clock, trusted TSA after expiry: exposed.
        let (env, rec) = record_at(BASE + 1_800);
        let ts = trusted_ts(BASE + 100_000);
        let (t, _) = signing_time(&rec, Some(&ts));
        assert!(validate_record_identity(&env, &rec, t.unwrap()).is_err());
    }

    #[test]
    fn untrusted_timestamp_is_never_used_as_a_clock() {
        // A forged (unsigned/untrusted) TSA token claiming a time inside validity must not revive
        // an expired token.
        let (env, rec) = record_at(BASE + 100_000);
        let mut ts = trusted_ts(BASE + 1_800);
        ts.trusted = false;
        let (t, src) = signing_time(&rec, Some(&ts));
        assert_eq!(src, "device");
        assert!(validate_record_identity(&env, &rec, t.unwrap()).is_err());
    }

    #[test]
    fn trusted_time_decides_expiry_over_the_device_clock() {
        let exp = BASE + 3_600;
        // Device clock before the expiry: in time, whatever comes later.
        assert!(!lapsed(exp - 60, None, exp));
        assert!(!lapsed(exp - 60, Some(exp + 86_400), exp));
        // After it (beyond the leeway): lapsed, unless a trusted timestamp shows the signature
        // already existed by the expiry.
        assert!(lapsed(exp + 3_600, None, exp));
        assert!(lapsed(exp + 3_600, Some(exp + 86_400), exp));
        assert!(!lapsed(exp + 3_600, Some(exp - 60), exp));
        assert!(!lapsed(exp + 3_600, Some(exp + LEEWAY_SECS), exp));
        assert!(!lapsed(exp + LEEWAY_SECS, None, exp));
    }

    #[test]
    fn each_revision_is_bounded_by_the_earliest_trusted_timestamp_at_or_after_it() {
        let stamp = |at: i64, revision: Option<u32>, document: Option<u32>| TrustedStamp {
            at,
            time: rfc3339(at),
            tsa_name: "TSA".into(),
            revision,
            document_timestamp: document,
        };
        // Preparer (no stamp), signer 1 (stamped at 200), document timestamp at 150, signer 2
        // (no stamp), document timestamp at 400.
        let boundaries = vec![
            (true, None),
            (true, Some(stamp(200, Some(1), None))),
            (false, Some(stamp(150, None, Some(1)))),
            (true, None),
            (false, Some(stamp(400, None, Some(2)))),
        ];
        let got = existed_before_by_revision(&boundaries);
        let summary: Vec<_> = got
            .iter()
            .map(|e| {
                let (at, e) = e.as_ref().unwrap();
                (*at, e.source.as_str(), e.revision, e.document_timestamp)
            })
            .collect();
        assert_eq!(
            summary,
            [
                (150, "document", None, Some(1)),
                (150, "document", None, Some(1)),
                (400, "document", None, Some(2)),
            ]
        );
        // A revision with its own stamp and nothing earlier after it.
        let got = existed_before_by_revision(&[
            (true, None),
            (true, Some(stamp(200, Some(1), None))),
            (true, Some(stamp(300, Some(2), None))),
            (true, None),
        ]);
        let sources: Vec<_> = got
            .iter()
            .map(|e| e.as_ref().map(|(_, e)| (e.source.clone(), e.revision)))
            .collect();
        assert_eq!(
            sources,
            [
                Some(("later-signature".to_string(), Some(1))),
                Some(("signature".to_string(), Some(1))),
                Some(("signature".to_string(), Some(2))),
                None,
            ]
        );
    }

    #[test]
    fn signing_time_before_token_issuance_is_backdating() {
        let (env, rec) = record_at(BASE - 10_000);
        let err = validate_record_identity(&env, &rec, BASE - 10_000).unwrap_err();
        assert!(
            err.contains("backdated") || err.contains("not yet valid"),
            "{err}"
        );
    }

    /// The verifier does not rely on the signing client having refused an unverified email: a
    /// record carrying one fails, even on a slot that asks for nothing.
    #[test]
    fn a_record_whose_email_the_provider_did_not_verify_fails_verification() {
        let when = BASE + 1_800;
        for (claims, expected) in [
            (
                serde_json::json!({ "email": "alice@example.com", "email_verified": false }),
                "has not verified the email address 'alice@example.com'",
            ),
            (
                serde_json::json!({ "email": "alice@example.com" }),
                "has not verified the email address",
            ),
            (serde_json::json!({}), "gave no email address"),
            (
                serde_json::json!({ "email": "  ", "email_verified": true }),
                "gave no email address",
            ),
        ] {
            let (env, rec) = record_with_email(when, claims.clone());
            let err = validate_record_identity(&env, &rec, when).unwrap_err();
            assert!(err.contains(expected), "{claims}: {err}");
        }
        let (env, rec) = record_at(when);
        assert!(validate_record_identity(&env, &rec, when).is_ok());
    }

    /// People are named by their verified email; the profile name in the token is ignored.
    #[test]
    fn the_profile_name_never_names_a_signer() {
        let identity = VerifiedIdentity {
            issuer: TEST_ISSUER.into(),
            subject: "user|mallory".into(),
            email: "mallory@example.com".into(),
            email_verified: true,
            hosted_domain: None,
            tenant_id: None,
            name: Some("ceo@bigcorp.example".into()),
            acr: None,
        };
        assert_eq!(display_name(&identity), "mallory@example.com");
    }

    #[test]
    fn checkbox_and_text_rendering() {
        let mut f = Field {
            id: "c".into(),
            field_type: FieldType::Checkbox,
            page: 0,
            rect: crate::model::Rect {
                x: 0.0,
                y: 0.0,
                w: 10.0,
                h: 10.0,
            },
            assigned_signer: "s1".into(),
            required: false,
            value: Some("yes".into()),
            label: None,
            group: None,
            options: None,
            date_format: None,
            signing_date: false,
            number_format: None,
            value_format: None,
            length: None,
            check_message: None,
            formula: None,
        };
        // A checkbox without a caption (prepared by an older version) draws a bare X.
        assert_eq!(rendered(&f), Some(("X".into(), FieldMark::None)));
        f.value = Some("no".into());
        assert_eq!(rendered(&f), None);
        // With its caption, it is drawn whether ticked or not.
        f.label = Some("I agree".into());
        assert_eq!(
            rendered(&f),
            Some(("I agree".into(), FieldMark::Checkbox { checked: false }))
        );
        f.field_type = FieldType::Radio;
        f.value = Some("true".into());
        assert_eq!(
            rendered(&f),
            Some(("I agree".into(), FieldMark::Radio { selected: true }))
        );
        assert_eq!(
            pades::field_contents("By post", FieldMark::Radio { selected: true }, false),
            "(o) By post"
        );
        assert_eq!(
            pades::field_contents("I agree", FieldMark::Checkbox { checked: false }, false),
            "[ ] I agree"
        );
        f.field_type = FieldType::Text;
        f.value = Some("  ".into());
        assert_eq!(rendered(&f), None);
    }

    #[test]
    fn annotation_contents_match_in_the_current_and_the_legacy_rendition() {
        let mut f = Field {
            id: "t".into(),
            field_type: FieldType::Text,
            page: 0,
            rect: crate::model::Rect {
                x: 0.0,
                y: 0.0,
                w: 200.0,
                h: 20.0,
            },
            assigned_signer: "s1".into(),
            required: false,
            value: Some("Jürgen Müller, Zürich".into()),
            label: None,
            group: None,
            options: None,
            date_format: None,
            signing_date: false,
            number_format: None,
            value_format: None,
            length: None,
            check_message: None,
            formula: None,
        };
        // What this version writes for the value...
        assert!(contents_match(&f, Some("Jürgen Müller, Zürich")));
        // ...and what versions wrote before they drew accented characters.
        assert!(contents_match(&f, Some("J?rgen M?ller, Z?rich")));
        // Anything else is a different answer.
        assert!(!contents_match(&f, Some("Jurgen Muller, Zurich")));
        assert!(!contents_match(&f, Some("Jürgen Müller, Zürich!")));
        assert!(!contents_match(&f, None));
        // A field with nothing to draw has no annotation text either.
        f.value = None;
        assert!(contents_match(&f, None));
        assert!(!contents_match(&f, Some("")));
    }

    #[test]
    fn initials_and_stamps() {
        // The rules themselves are tested in `initials`; a stamp is the rule's letters for an
        // initials field, and the address with the key's code for a signature field.
        assert_eq!(
            stamp_text(FieldType::Initials, "bob@example.com", "BB", "abcd1234"),
            "BB"
        );
        assert_eq!(
            stamp_text(FieldType::Signature, "bob@example.com", "BB", "abcd1234"),
            "bob@example.com - Sig abcd1234"
        );
    }
}
