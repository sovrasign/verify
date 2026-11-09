//! OpenID Connect ID-token validation (pure, **no networking**).
//!
//! This module is the in-core security boundary for federated identity. Following the same
//! split the engine already uses for RFC 3161 timestamps — *the caller fetches, the core
//! validates* — the host (Flutter app / CLI / `signpdf-auth`) performs the interactive OIDC
//! flow and hands this module the resulting **ID token** (a compact JWS) plus the provider's
//! **JWKS** key. Everything security-relevant happens here and is fully offline:
//!
//! * verify the JWT signature (ES256 via [`p256`], RS256 via [`rsa`] — both pure Rust),
//! * validate the standard claims (`iss` allow-list, `aud`, `exp`/`nbf`),
//! * enforce the **key/document binding** `nonce == H(pubkey ‖ doc_digest)` that staples the
//!   token to *this* signing key and *this* document (defeats token lifting/replay), and
//! * decide whether the verified identity satisfies a signer slot's [`IdentityPolicy`].
//!
//! Because the JWK that signed the token is archived in the signature record, a third party
//! with only the offline verifier can re-check all of the above without contacting the IdP.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::Pkcs1v15Sign;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, SignPdfError};

fn oidc_err(msg: impl Into<String>) -> SignPdfError {
    SignPdfError::Oidc(msg.into())
}

/// Decode unpadded (or accidentally padded) base64url.
fn b64url(s: &str) -> Result<Vec<u8>> {
    let trimmed = s.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|e| oidc_err(format!("invalid base64url: {e}")))
}

/// An assurance level: how strongly the evidence in a signature identifies the signer. The
/// verifier computes it from the evidence it can check offline (the token, its issuer and its
/// claims, with what the trust store says about the issuer); a slot's requirement is never
/// substituted for it. Ordered `L1 < L2 < … < L5`. Levels are cumulative on evidence, not on
/// method: an account sign-in plus a phone code is L3, an email code plus an identity-document
/// check L4.
///
/// | Level | Name | Evidence |
/// | --- | --- | --- |
/// | L1 | Email | a one-time code sent to the invited address ([`Method::EmailCode`]) |
/// | L2 | Account | a sign-in with an account provider (Google, Microsoft personal, Apple) |
/// | L3 | Strong | an organization identity (Workspace `hd`, an Entra organizational tenant, an organization's own provider), or L1/L2 plus a phone code |
/// | L4 | ID checked | L1–L3 plus an identity-document check |
/// | L5 | Qualified | an eIDAS qualified electronic signature |
///
/// This build computes L1–L3 ([`Level::HIGHEST_COMPUTED`]): the evidence for a phone code, L4
/// and L5 (attestations and qualified certificates) comes with later schema versions. JSON:
/// `"L1"` … `"L5"`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum Level {
    #[default]
    L1,
    L2,
    L3,
    L4,
    L5,
}

impl Level {
    /// Every level, lowest first.
    pub const ALL: [Level; 5] = [Level::L1, Level::L2, Level::L3, Level::L4, Level::L5];

    /// The highest level this build computes from the evidence it checks.
    pub const HIGHEST_COMPUTED: Level = Level::L3;

    /// `L1` … `L5` (the JSON form).
    pub fn as_str(self) -> &'static str {
        match self {
            Level::L1 => "L1",
            Level::L2 => "L2",
            Level::L3 => "L3",
            Level::L4 => "L4",
            Level::L5 => "L5",
        }
    }

    /// The value [`Level::as_str`] gives (`None` for anything else).
    pub fn parse(s: &str) -> Option<Level> {
        Level::ALL.into_iter().find(|l| l.as_str() == s)
    }

    /// The level's name, which names the evidence rather than a grade: `Email`, `Account`,
    /// `Strong`, `ID checked`, `Qualified`.
    pub fn name(self) -> &'static str {
        match self {
            Level::L1 => "Email",
            Level::L2 => "Account",
            Level::L3 => "Strong",
            Level::L4 => "ID checked",
            Level::L5 => "Qualified",
        }
    }
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A kind of evidence about who signed: what a [`Basis`] entry shows, and what a slot may require
/// with [`IdentityPolicy::required_methods`]. JSON: kebab-case (`email-code`, `id-document`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Method {
    /// Control of the invited inbox, shown by a one-time code its provider sent there (L1).
    EmailCode,
    /// A sign-in with an account provider, for a verified email (L2).
    Account,
    /// A sign-in with an organization identity: Google Workspace (`hd`), a Microsoft Entra
    /// organizational tenant, or an organization's own provider (L3).
    Organization,
    /// A code sent to the phone number the sender entered, on top of the sign-in (L3). Carried
    /// by an attestation token, which a later schema version adds.
    Phone,
    /// An identity-document check with liveness, the name matched (L4). Carried by an
    /// attestation token, which a later schema version adds.
    IdDocument,
    /// An eIDAS qualified electronic signature (L5). Needs dual-key records, which a later
    /// schema version adds.
    Qualified,
}

impl Method {
    /// Every method, in ladder order.
    pub const ALL: [Method; 6] = [
        Method::EmailCode,
        Method::Account,
        Method::Organization,
        Method::Phone,
        Method::IdDocument,
        Method::Qualified,
    ];

    /// The JSON form (`email-code`, `account`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Method::EmailCode => "email-code",
            Method::Account => "account",
            Method::Organization => "organization",
            Method::Phone => "phone",
            Method::IdDocument => "id-document",
            Method::Qualified => "qualified",
        }
    }

    /// The value [`Method::as_str`] gives (`None` for anything else).
    pub fn parse(s: &str) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.as_str() == s)
    }

    /// The level this evidence reaches (a phone code counts on top of a sign-in).
    pub fn level(self) -> Level {
        match self {
            Method::EmailCode => Level::L1,
            Method::Account => Level::L2,
            Method::Organization | Method::Phone => Level::L3,
            Method::IdDocument => Level::L4,
            Method::Qualified => Level::L5,
        }
    }

    /// Whether this build can find such evidence in a signature: the sign-in methods. Phone
    /// codes, identity documents and qualified signatures come with later schema versions.
    pub fn checked_by_this_build(self) -> bool {
        matches!(
            self,
            Method::EmailCode | Method::Account | Method::Organization
        )
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a sign-in with an issuer shows about the signer, as a verifier's trust store records it
/// ([`crate::trust::TrustedIssuer::kind`]). JSON: kebab-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IssuerKind {
    /// It confirms control of an email address with a one-time code and nothing more, whatever
    /// its tokens claim (a signing service's own email-code provider): L1.
    EmailCode,
    /// An account provider: a consumer account is L2, an organization identity it asserts
    /// (Google Workspace `hd`, a Microsoft Entra organizational `tid`) L3. Google, Microsoft and
    /// Apple are account providers without being told ([`builtin_issuer_kind`]).
    Account,
    /// An organization's own identity provider, configured for its signers: every identity it
    /// asserts is an organization identity (L3).
    Organization,
}

impl IssuerKind {
    /// Every kind, the one that shows least first.
    pub const ALL: [IssuerKind; 3] = [
        IssuerKind::EmailCode,
        IssuerKind::Account,
        IssuerKind::Organization,
    ];

    /// The JSON form.
    pub fn as_str(self) -> &'static str {
        match self {
            IssuerKind::EmailCode => "email-code",
            IssuerKind::Account => "account",
            IssuerKind::Organization => "organization",
        }
    }

    /// The value [`IssuerKind::as_str`] gives (`None` for anything else).
    pub fn parse(s: &str) -> Option<IssuerKind> {
        IssuerKind::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// What a verifier knows about `iss` without a trust store saying more: the well-known account
/// providers (Google, Microsoft, Apple, and the bundled test issuer that stands in for them) are
/// [`IssuerKind::Account`]. Any other issuer is unknown (`None`) and counts as an email-code
/// provider, the least a verified email shows.
pub fn builtin_issuer_kind(iss: &str, tid: Option<&str>) -> Option<IssuerKind> {
    [
        "https://accounts.google.com",
        MICROSOFT_ISSUER_TEMPLATE,
        "https://appleid.apple.com",
        DEV_ISSUER,
    ]
    .iter()
    .any(|known| issuer_matches(known, iss, tid))
    .then_some(IssuerKind::Account)
}

/// The `acr` a signing service's email-code provider puts in its tokens. A token carrying it
/// shows an email code and never more, whatever its issuer is recorded as.
pub const ACR_EMAIL_OTP: &str = "urn:signpdf:acr:email-otp";

/// One piece of evidence an assurance level rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Basis {
    /// What it shows.
    pub method: Method,
    /// Who vouched for it: the identity provider (the token's `iss`).
    pub issuer: String,
    /// For [`Method::Organization`]: the organization the provider vouched for, its Google
    /// Workspace domain (`hd`) or Microsoft Entra tenant id (`tid`), when the token names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
}

impl Basis {
    /// The evidence in plain words: the method and who vouched for it, never a grade.
    pub fn describe(&self) -> String {
        let by = &self.issuer;
        match (self.method, &self.organization) {
            (Method::EmailCode, _) => format!("email confirmed with a one-time code from {by}"),
            (Method::Account, _) => format!("signed in with an account at {by}"),
            (Method::Organization, Some(org)) => {
                format!("signed in with an organization identity at {by} ({org})")
            }
            (Method::Organization, None) => {
                format!("signed in with an organization identity at {by}")
            }
            (Method::Phone, _) => format!("phone confirmed with a code, attested by {by}"),
            (Method::IdDocument, _) => format!("identity document checked, attested by {by}"),
            (Method::Qualified, _) => {
                format!("qualified electronic signature, certificate by {by}")
            }
        }
    }
}

/// A computed assurance level and the evidence it rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assessment {
    pub level: Level,
    pub basis: Vec<Basis>,
}

impl Assessment {
    /// Whether this meets a slot's [`IdentityPolicy::min_level`] and
    /// [`IdentityPolicy::required_methods`], with a reason when it does not.
    pub fn meets(&self, policy: &IdentityPolicy) -> std::result::Result<(), String> {
        if self.level < policy.min_level {
            return Err(format!(
                "the signer's identity reaches {} ({}), below the {} ({}) the slot requires",
                self.level,
                self.level.name(),
                policy.min_level,
                policy.min_level.name()
            ));
        }
        let missing: Vec<&str> = policy
            .required_methods
            .iter()
            .filter(|m| !self.basis.iter().any(|b| b.method == **m))
            .map(|m| m.as_str())
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "the slot requires evidence the signature does not carry: {}",
                missing.join(", ")
            ));
        }
        Ok(())
    }
}

/// The issuer of the bundled, **untrusted** test identity provider ([`testing::TestIssuer`]) used
/// by tests, the CLI `--email` dev login, and CI. A verifier only accepts it when its
/// [`crate::trust::TrustStore`] explicitly opts in to the insecure dev issuer.
pub const DEV_ISSUER: &str = "https://issuer.test";

/// Microsoft's multi-tenant issuer template. Tokens from the `common` authority carry the concrete
/// tenant in `iss` (`…/{tid}/v2.0`), which must equal the token's own `tid` claim.
pub const MICROSOFT_ISSUER_TEMPLATE: &str = "https://login.microsoftonline.com/{tenantid}/v2.0";

/// The tenant id Microsoft uses for **personal** (MSA) accounts. A `tid` equal to this value does
/// not indicate an organization, so such identities are account identities (L2), not
/// organization ones.
pub const MICROSOFT_CONSUMER_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// True when `iss` is accepted by `pattern`: an exact match (ignoring one trailing `/`), or — for a
/// pattern containing `{tenantid}` — a match where the placeholder equals the token's `tid` claim.
pub fn issuer_matches(pattern: &str, iss: &str, tid: Option<&str>) -> bool {
    let norm = |s: &str| s.trim_end_matches('/').to_string();
    if !pattern.contains("{tenantid}") {
        return norm(pattern) == norm(iss);
    }
    match tid {
        Some(t) if !t.is_empty() && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-') => {
            norm(&pattern.replace("{tenantid}", t)) == norm(iss)
        }
        _ => false,
    }
}

/// The identity requirement a preparer pins onto a signer slot. A signer's verified identity
/// must satisfy this before they may claim the slot.
///
/// JSON input may still name the requirement the way schema version 3 did, `min_assurance`
/// (`consumer`, `enterprise`): it is read as `min_level` `L1` or `L3` and written as
/// `min_level` (see [`IdentityPolicy::from_min_assurance`]). A policy naming both is refused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "IdentityPolicyJson")]
pub struct IdentityPolicy {
    /// Acceptable token issuers (`iss`). Empty means "any issuer the verifier already trusts".
    /// An entry may be an issuer template containing `{tenantid}` (see [`issuer_matches`]).
    #[serde(default)]
    pub allowed_issuers: Vec<String>,
    /// Exact email the signer must control (case-insensitive). Used for consumer slots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_email: Option<String>,
    /// Email domain the signer must belong to (e.g. `contoso.com`). Used for enterprise slots.
    /// For organization identities the domain must also be vouched by the IdP: Google Workspace's
    /// `hd` must equal it, and Microsoft Entra identities must additionally match
    /// [`IdentityPolicy::required_tenant`] (Entra does not verify the `email` claim's domain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_domain: Option<String>,
    /// Microsoft Entra tenant id (`tid`) the signer must belong to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_tenant: Option<String>,
    /// Stable subject (`sub`) the signer's token must carry. Pins the slot to one account even if
    /// the account's email later changes or is reassigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_subject: Option<String>,
    /// The lowest assurance level the signature must reach, as the verifier computes it
    /// ([`Assessment`]). `L1` (the default) accepts every verified identity.
    #[serde(default)]
    pub min_level: Level,
    /// Evidence the signature must carry whatever its level, such as a phone code
    /// ([`Method::Phone`]) on top of the sign-in. Empty by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_methods: Vec<Method>,
}

impl Default for IdentityPolicy {
    fn default() -> Self {
        Self {
            allowed_issuers: Vec::new(),
            required_email: None,
            required_domain: None,
            required_tenant: None,
            required_subject: None,
            min_level: Level::L1,
            required_methods: Vec::new(),
        }
    }
}

/// The JSON form of an [`IdentityPolicy`], which also reads schema version 3's `min_assurance`.
#[derive(Deserialize)]
struct IdentityPolicyJson {
    #[serde(default)]
    allowed_issuers: Vec<String>,
    #[serde(default)]
    required_email: Option<String>,
    #[serde(default)]
    required_domain: Option<String>,
    #[serde(default)]
    required_tenant: Option<String>,
    #[serde(default)]
    required_subject: Option<String>,
    #[serde(default)]
    min_level: Option<Level>,
    #[serde(default)]
    required_methods: Vec<Method>,
    #[serde(default)]
    min_assurance: Option<String>,
}

impl TryFrom<IdentityPolicyJson> for IdentityPolicy {
    type Error = String;

    fn try_from(j: IdentityPolicyJson) -> std::result::Result<Self, String> {
        let min_level = match (j.min_level, j.min_assurance.as_deref()) {
            (Some(_), Some(_)) => {
                return Err(
                    "an identity policy names both min_level and min_assurance (which \
                     min_level replaced); give min_level only"
                        .into(),
                )
            }
            (Some(level), None) => level,
            (None, Some(legacy)) => IdentityPolicy::from_min_assurance(legacy)?,
            (None, None) => Level::L1,
        };
        Ok(IdentityPolicy {
            allowed_issuers: j.allowed_issuers,
            required_email: j.required_email,
            required_domain: j.required_domain,
            required_tenant: j.required_tenant,
            required_subject: j.required_subject,
            min_level,
            required_methods: j.required_methods,
        })
    }
}

impl IdentityPolicy {
    /// The level schema version 3's `min_assurance` stands for. `consumer` accepted every
    /// verified identity, an email code included, so it is `L1`; `enterprise` asked for an
    /// organization identity, `L3`. (A version-3 *identity* is computed afresh like any other:
    /// a consumer account at Google, Microsoft or Apple is `L2`, an organization one `L3`.)
    pub fn from_min_assurance(value: &str) -> std::result::Result<Level, String> {
        match value {
            "consumer" => Ok(Level::L1),
            "enterprise" => Ok(Level::L3),
            other => Err(format!(
                "unknown min_assurance '{other}' (consumer or enterprise; use min_level)"
            )),
        }
    }

    /// The `min_assurance` value of schema version 3 that stands for this policy's level
    /// requirement, when there is one: `L1` is `consumer`, `L3` `enterprise`. Nothing else can
    /// be written in version 3 (nor can `required_methods`).
    pub fn to_min_assurance(&self) -> Option<&'static str> {
        if !self.required_methods.is_empty() {
            return None;
        }
        match self.min_level {
            Level::L1 => Some("consumer"),
            Level::L3 => Some("enterprise"),
            _ => None,
        }
    }

    /// Whether a signature this build makes and checks can ever fill the slot: its level is one
    /// this build computes and every method it requires is one this build finds in a signature.
    /// Preparing a slot that fails this is refused (no signer could fill it).
    pub fn fillable_by_this_build(&self) -> std::result::Result<(), String> {
        if self.min_level > Level::HIGHEST_COMPUTED {
            return Err(format!(
                "requires {} ({}), which needs evidence this version of SignPDF cannot check \
                 (it computes levels up to {})",
                self.min_level,
                self.min_level.name(),
                Level::HIGHEST_COMPUTED
            ));
        }
        if let Some(m) = self
            .required_methods
            .iter()
            .find(|m| !m.checked_by_this_build())
        {
            return Err(format!(
                "requires '{m}' evidence, which this version of SignPDF cannot check yet"
            ));
        }
        Ok(())
    }

    /// Human-readable weaknesses of this policy ("identity theater" checks, V6): constraints so
    /// loose that a signature filling the slot proves little about *who* signed.
    pub fn weaknesses(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.allowed_issuers.is_empty() {
            out.push("accepts any identity provider the verifier trusts".to_string());
        }
        if self.required_email.is_none()
            && self.required_domain.is_none()
            && self.required_subject.is_none()
            && self.required_tenant.is_none()
        {
            out.push(
                "does not pin an email, domain, tenant or subject — any verified identity can fill it"
                    .to_string(),
            );
        }
        if self.required_domain.is_some()
            && self.min_level >= Level::L3
            && self.required_tenant.is_none()
            && self
                .allowed_issuers
                .iter()
                .any(|i| i.contains("microsoftonline"))
        {
            out.push(
                "requires a domain from Microsoft Entra without pinning a tenant; Entra identities \
                 will be rejected until required_tenant is set"
                    .to_string(),
            );
        }
        out
    }
}

/// A JSON Web Key (the public half), as found in a provider JWKS. Only the fields needed to
/// verify ES256 / RS256 are modeled; unknown fields are ignored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    // RSA
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    // EC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// A JSON Web Key Set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    fn find(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(k) => self.keys.iter().find(|j| j.kid.as_deref() == Some(k)),
            None if self.keys.len() == 1 => self.keys.first(),
            None => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// `aud` may be a single string or an array of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, want: &str) -> bool {
        match self {
            Audience::One(a) => a == want,
            Audience::Many(v) => v.iter().any(|a| a == want),
        }
    }
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    /// Microsoft optional claim: the email's domain is verified as owned by the tenant.
    #[serde(default)]
    xms_edov: Option<serde_json::Value>,
    /// Google Workspace hosted domain.
    #[serde(default)]
    hd: Option<String>,
    /// Microsoft Entra tenant id.
    #[serde(default)]
    tid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    /// Authentication context class: how the provider authenticated the user (for example
    /// [`ACR_EMAIL_OTP`]). Only a string `acr` is read; any other form counts as none.
    #[serde(default, deserialize_with = "string_or_none")]
    acr: Option<String>,
}

/// A claim that counts only when it is a string.
fn string_or_none<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Ok(match serde_json::Value::deserialize(d)? {
        serde_json::Value::String(s) => Some(s),
        _ => None,
    })
}

/// Interpret the loosely-typed `email_verified` claim (bool, or string "true"/"false").
fn truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// The validated outcome of an ID token: who the IdP says this is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted_domain: Option<String>,
    /// Microsoft Entra tenant id (`tid`), when the provider asserted one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The token's `acr` (how the provider authenticated the user), when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
}

impl VerifiedIdentity {
    /// The organization the provider asserts this identity belongs to: the Google Workspace
    /// hosted domain (`hd`), or a Microsoft Entra organizational tenant (`tid`, other than the
    /// tenant of personal accounts). `None` for a consumer account.
    pub fn organization(&self) -> Option<&str> {
        if let Some(hd) = self.hosted_domain.as_deref().filter(|h| !h.is_empty()) {
            return Some(hd);
        }
        self.tenant_id
            .as_deref()
            .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case(MICROSOFT_CONSUMER_TENANT))
    }

    /// The assurance level and basis of this identity, for an issuer the verifier knows as
    /// `kind` ([`crate::trust::TrustStore::issuer_kind`]). A token carrying the email-code
    /// `acr` ([`ACR_EMAIL_OTP`]) shows an email code whatever its issuer is recorded as.
    pub fn assess(&self, kind: IssuerKind) -> Assessment {
        let email_code = self.acr.as_deref() == Some(ACR_EMAIL_OTP);
        let organization = self.organization().map(str::to_string);
        let (method, organization) = match kind {
            IssuerKind::EmailCode => (Method::EmailCode, None),
            _ if email_code => (Method::EmailCode, None),
            IssuerKind::Organization => (Method::Organization, organization),
            IssuerKind::Account if organization.is_some() => (Method::Organization, organization),
            IssuerKind::Account => (Method::Account, None),
        };
        let basis = vec![Basis {
            method,
            issuer: self.issuer.clone(),
            organization,
        }];
        Assessment {
            level: basis
                .iter()
                .map(|b| b.method.level())
                .max()
                .unwrap_or_default(),
            basis,
        }
    }

    /// The email domain, lowercased (the part after `@`).
    fn email_domain(&self) -> Option<String> {
        self.email
            .rsplit_once('@')
            .map(|(_, d)| d.to_ascii_lowercase())
    }

    /// True when `self.issuer` is accepted by any entry of `allowed`.
    pub fn issuer_allowed(&self, allowed: &[String]) -> bool {
        allowed
            .iter()
            .any(|p| issuer_matches(p, &self.issuer, self.tenant_id.as_deref()))
    }

    /// SignPDF names people by an email address their provider has verified. An identity without
    /// one (no `email` claim, or an address the provider does not vouch for) names nobody, so it
    /// can neither prepare nor sign, whatever the slot asks for.
    pub fn require_verified_email(&self) -> std::result::Result<(), String> {
        match self.email.trim() {
            "" => Err("the identity provider gave no email address for this account".to_string()),
            email if !self.email_verified => Err(format!(
                "the identity provider has not verified the email address '{email}'"
            )),
            _ => Ok(()),
        }
    }

    /// Decide whether this verified identity's claims allow it to fill a slot governed by
    /// `policy` (issuer, verified email, subject, tenant, email, domain), returning a
    /// human-readable reason when they do not. The slot's level and method requirements depend
    /// on what the verifier's trust store says about the issuer: check them with
    /// [`Assessment::meets`] on [`VerifiedIdentity::assess`].
    pub fn satisfies(&self, policy: &IdentityPolicy) -> std::result::Result<(), String> {
        if !policy.allowed_issuers.is_empty() && !self.issuer_allowed(&policy.allowed_issuers) {
            return Err(format!(
                "issuer '{}' is not allowed for this slot",
                self.issuer
            ));
        }
        self.require_verified_email()?;
        if let Some(sub) = &policy.required_subject {
            if &self.subject != sub {
                return Err("token subject does not match the slot's pinned subject".to_string());
            }
        }
        if let Some(tenant) = &policy.required_tenant {
            if !self
                .tenant_id
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case(tenant))
            {
                return Err(format!(
                    "identity is not from the required tenant '{tenant}'"
                ));
            }
        }
        if let Some(req) = &policy.required_email {
            if !self.email.eq_ignore_ascii_case(req) {
                return Err(format!(
                    "verified email '{}' does not match the slot's required email",
                    self.email
                ));
            }
        }
        if let Some(domain) = &policy.required_domain {
            let want = domain.to_ascii_lowercase();
            if self.email_domain().as_deref() != Some(want.as_str()) {
                return Err(format!(
                    "verified email '{}' is not in the required domain '{}'",
                    self.email, domain
                ));
            }
            // An organization identity must have the domain vouched by the IdP itself, not just
            // appear in the (account-controlled) email claim.
            if self.organization().is_some() {
                if let Some(hd) = &self.hosted_domain {
                    if !hd.eq_ignore_ascii_case(domain) {
                        return Err(format!(
                            "hosted domain '{hd}' does not match the required domain '{domain}'"
                        ));
                    }
                } else if self.tenant_id.is_some() && policy.required_tenant.is_none() {
                    return Err(
                        "a Microsoft Entra identity can only satisfy a domain requirement when the \
                         slot also pins required_tenant"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

/// Parameters the caller supplies to validate a token. `now_unix` is the trusted current time
/// (device clock, or — for after-the-fact verification — the RFC 3161 timestamp's gen-time).
#[derive(Debug, Clone)]
pub struct Validation {
    /// Issuers the verifier is willing to accept at all.
    pub allowed_issuers: Vec<String>,
    /// The relying-party `client_id` the token's `aud` must contain.
    pub audience: String,
    /// Trusted current time, seconds since the Unix epoch.
    pub now_unix: i64,
    /// Allowed clock skew, in seconds.
    pub leeway_secs: i64,
    /// Expected `nonce`. When set, the token's `nonce` must equal it exactly — this is the
    /// key/document binding produced by [`compute_nonce`].
    pub expected_nonce: Option<String>,
}

/// The default clock-skew leeway on a token's `exp` and `nbf`: 2 minutes, so the engine and a
/// service built on it check every live token with the same tolerance. Checks at a signature's
/// claimed time keep their own, wider tolerance (`workflow::LEEWAY_SECS`).
pub const TOKEN_LEEWAY_SECS: i64 = 120;

impl Validation {
    /// Convenience constructor with the [`TOKEN_LEEWAY_SECS`] default leeway and no nonce check.
    pub fn new(allowed_issuers: Vec<String>, audience: impl Into<String>, now_unix: i64) -> Self {
        Self {
            allowed_issuers,
            audience: audience.into(),
            now_unix,
            leeway_secs: TOKEN_LEEWAY_SECS,
            expected_nonce: None,
        }
    }
}

/// The deterministic nonce that binds an ID token to a specific signing key and document:
/// `hex( SHA-256( pubkey_sec1 ‖ doc_digest_hex_ascii ) )`.
///
/// `pubkey_sec1` is the signer's uncompressed SEC1 public key bytes; `doc_digest_hex` is the
/// hex string the signature record stores as `doc_digest`. The host sets the OIDC `nonce` to
/// this value at login; the verifier recomputes it and checks the token echoes it.
pub fn compute_nonce(pubkey_sec1: &[u8], doc_digest_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey_sec1);
    hasher.update(doc_digest_hex.as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify the signature on `signing_input` (`header.payload`) using an EC (ES256) JWK.
pub(crate) fn verify_es256(jwk: &Jwk, signing_input: &[u8], sig: &[u8]) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    if jwk.crv.as_deref() != Some("P-256") {
        return Err(oidc_err("ES256 requires a P-256 key"));
    }
    let x = b64url(
        jwk.x
            .as_deref()
            .ok_or_else(|| oidc_err("EC JWK missing x"))?,
    )?;
    let y = b64url(
        jwk.y
            .as_deref()
            .ok_or_else(|| oidc_err("EC JWK missing y"))?,
    )?;
    if x.len() != 32 || y.len() != 32 {
        return Err(oidc_err("EC JWK coordinates must be 32 bytes"));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let vk = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| oidc_err(format!("bad EC public key: {e}")))?;
    // JWS ES256 signatures are the fixed 64-byte (r ‖ s) form, not DER.
    let signature =
        Signature::from_slice(sig).map_err(|e| oidc_err(format!("bad ES256 signature: {e}")))?;
    vk.verify(signing_input, &signature)
        .map_err(|_| oidc_err("ES256 signature did not verify"))
}

/// Largest RSA modulus accepted in an RS256 JWK, in bits: rsa 0.9's limit. Providers publish
/// 2048-bit keys.
const RS256_MAX_MODULUS_BITS: usize = 4096;
/// Longest base64url `n` accepted before decoding: a 4096-bit modulus is 683 characters, so
/// this leaves room for a few leading zero bytes and nothing more.
const RS256_MAX_N_B64: usize = 1024;
/// Longest base64url `e` accepted before decoding (the largest allowed exponent, 2^33 - 1,
/// takes 7 characters).
const RS256_MAX_E_B64: usize = 16;

/// `bytes` (a big-endian unsigned integer) without its leading zero bytes.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

/// Verify the signature on `signing_input` using an RSA (RS256) JWK.
fn verify_rs256(jwk: &Jwk, signing_input: &[u8], sig: &[u8]) -> Result<()> {
    use rsa::{BoxedUint, RsaPublicKey};

    // A document carries the JWK its ID token is checked with, so `n` and `e` are untrusted
    // until the key is matched to a trusted provider, which happens after this check.
    // crypto-bigint sizes a number by its byte length, leading zeros included, and the key
    // setup costs grow with the square of that size: bound the inputs and strip the zeros
    // before building the key.
    let n = jwk
        .n
        .as_deref()
        .ok_or_else(|| oidc_err("RSA JWK missing n"))?;
    let e = jwk
        .e
        .as_deref()
        .ok_or_else(|| oidc_err("RSA JWK missing e"))?;
    if n.len() > RS256_MAX_N_B64 || e.len() > RS256_MAX_E_B64 {
        return Err(oidc_err("RSA JWK is too large"));
    }
    let (n, e) = (b64url(n)?, b64url(e)?);
    // RFC 7518 §6.3.1.1 asks for the minimal encoding, but some libraries add a leading zero.
    let (n, e) = (strip_leading_zeros(&n), strip_leading_zeros(&e));
    if n.is_empty() || e.is_empty() {
        return Err(oidc_err("bad RSA public key: zero modulus or exponent"));
    }
    if n.len() * 8 > RS256_MAX_MODULUS_BITS {
        return Err(oidc_err("RSA JWK modulus is larger than 4096 bits"));
    }
    // Public values: variable-time decoding leaks nothing secret.
    let key = RsaPublicKey::new_with_max_size(
        BoxedUint::from_be_slice_vartime(n),
        BoxedUint::from_be_slice_vartime(e),
        RS256_MAX_MODULUS_BITS,
    )
    .map_err(|e| oidc_err(format!("bad RSA public key: {e}")))?;
    // As in rsa 0.9 (and RFC 8017 §8.2.2): the signature is exactly as long as the modulus.
    if sig.len() != n.len() {
        return Err(oidc_err("RS256 signature did not verify"));
    }
    let hashed = Sha256::digest(signing_input);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, sig)
        .map_err(|_| oidc_err("RS256 signature did not verify"))
}

/// Validate a compact-serialized ID token against `jwks` and `validation`, returning the
/// verified identity on success.
///
/// Performs, in order: structural parse, algorithm allow-listing (`ES256`/`RS256` only —
/// `none` and unexpected algorithms are rejected), JWK selection by `kid`, signature
/// verification, then claim checks (`iss`, `aud`, `exp`/`nbf`, and the `nonce` binding).
pub fn verify_id_token(
    token: &str,
    jwks: &Jwks,
    validation: &Validation,
) -> Result<VerifiedIdentity> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => {
            return Err(oidc_err(
                "token is not a compact JWS (expected three segments)",
            ))
        }
    };

    let header: JwtHeader = serde_json::from_slice(&b64url(h)?)
        .map_err(|e| oidc_err(format!("invalid JWT header: {e}")))?;

    let jwk = jwks
        .find(header.kid.as_deref())
        .ok_or_else(|| oidc_err("no JWKS key matches the token's kid"))?;

    let signing_input = format!("{h}.{p}");
    let sig = b64url(s)?;
    match header.alg.as_str() {
        "ES256" => {
            if jwk.kty != "EC" {
                return Err(oidc_err("ES256 token selected a non-EC JWK"));
            }
            verify_es256(jwk, signing_input.as_bytes(), &sig)?;
        }
        "RS256" => {
            if jwk.kty != "RSA" {
                return Err(oidc_err("RS256 token selected a non-RSA JWK"));
            }
            verify_rs256(jwk, signing_input.as_bytes(), &sig)?;
        }
        other => return Err(oidc_err(format!("unsupported or unsafe alg '{other}'"))),
    }

    let claims: IdTokenClaims = serde_json::from_slice(&b64url(p)?)
        .map_err(|e| oidc_err(format!("invalid ID token claims: {e}")))?;

    if !validation
        .allowed_issuers
        .iter()
        .any(|p| issuer_matches(p, &claims.iss, claims.tid.as_deref()))
    {
        return Err(oidc_err(format!("issuer '{}' is not accepted", claims.iss)));
    }
    if !claims.aud.contains(&validation.audience) {
        return Err(oidc_err("token audience does not include this client_id"));
    }
    if validation.now_unix > claims.exp + validation.leeway_secs {
        return Err(oidc_err("token has expired"));
    }
    if let Some(nbf) = claims.nbf {
        if validation.now_unix + validation.leeway_secs < nbf {
            return Err(oidc_err("token is not yet valid (nbf)"));
        }
    }
    if let Some(expected) = &validation.expected_nonce {
        match &claims.nonce {
            Some(n) if n == expected => {}
            Some(_) => {
                return Err(oidc_err(
                    "token nonce does not match the key/document binding",
                ))
            }
            None => return Err(oidc_err("token is missing the required nonce binding")),
        }
    }

    let is_microsoft = issuer_matches(
        MICROSOFT_ISSUER_TEMPLATE,
        &claims.iss,
        claims.tid.as_deref(),
    );
    let consumer_tenant = claims
        .tid
        .as_deref()
        .is_some_and(|t| t.eq_ignore_ascii_case(MICROSOFT_CONSUMER_TENANT));
    // Microsoft v2 tokens omit `email_verified`. Personal (MSA) accounts sign in with their email,
    // so it is verified; for organizational tenants we only trust the tenant-verified-domain
    // optional claim `xms_edov` (Entra does not verify the `email` claim otherwise).
    let email_verified = claims.email_verified.as_ref().map(truthy).unwrap_or(false)
        || (is_microsoft && consumer_tenant)
        || claims.xms_edov.as_ref().map(truthy).unwrap_or(false);
    Ok(VerifiedIdentity {
        issuer: claims.iss,
        subject: claims.sub,
        email: claims.email.unwrap_or_default(),
        email_verified,
        hosted_domain: claims.hd,
        tenant_id: claims.tid,
        name: claims.name,
        acr: claims.acr,
    })
}

/// The algorithms an ID token's signature relies on (for the verifier's algorithm policy,
/// [`crate::algorithms`]), from its header and the JWK that verified it: ES256 is ECDSA P-256
/// with SHA-256, RS256 RSA (with the key's modulus size) with SHA-256. Empty when the token
/// names another algorithm (which [`verify_id_token`] refuses).
pub fn token_algorithms(token: &str, jwk: &Jwk) -> Vec<crate::algorithms::AlgorithmUse> {
    use crate::algorithms::{bit_length, Algorithm, AlgorithmUse};
    let alg = token
        .split('.')
        .next()
        .and_then(|h| b64url(h).ok())
        .and_then(|h| serde_json::from_slice::<JwtHeader>(&h).ok())
        .map(|h| h.alg);
    match alg.as_deref() {
        Some("ES256") => vec![
            AlgorithmUse::plain(Algorithm::EcdsaP256),
            AlgorithmUse::plain(Algorithm::Sha256),
        ],
        Some("RS256") => {
            let bits = jwk
                .n
                .as_deref()
                .and_then(|n| b64url(n).ok())
                .map_or(0, |n| bit_length(&n));
            vec![
                AlgorithmUse::rsa(bits),
                AlgorithmUse::plain(Algorithm::Sha256),
            ]
        }
        _ => Vec::new(),
    }
}

/// Read the **unverified** `iss` claim from a compact JWS without checking its signature.
///
/// Only for seeding an issuer allow-list when the caller did not pin one; [`verify_id_token`]
/// still fully verifies the signature and every claim afterwards, and the per-slot
/// [`IdentityPolicy`] re-checks the issuer where it restricts one.
pub fn peek_issuer(token: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct IssOnly {
        iss: String,
    }
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| oidc_err("token is not a compact JWS (expected three segments)"))?;
    let claims: IssOnly = serde_json::from_slice(&b64url(payload)?)
        .map_err(|e| oidc_err(format!("invalid ID token claims: {e}")))?;
    Ok(claims.iss)
}

/// Read the **unverified** `iat` (issued-at) claim, if present. Used only after the token has been
/// fully verified, to bound the earliest possible signing time.
pub fn peek_issued_at(token: &str) -> Option<i64> {
    #[derive(Deserialize)]
    struct IatOnly {
        #[serde(default)]
        iat: Option<i64>,
    }
    let payload = token.split('.').nth(1)?;
    let claims: IatOnly = serde_json::from_slice(&b64url(payload).ok()?).ok()?;
    claims.iat
}

/// Read the **unverified** `tid` claim, if present (for issuer-template trust lookups after the
/// token's signature has been verified).
pub fn peek_tenant(token: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct TidOnly {
        #[serde(default)]
        tid: Option<String>,
    }
    let payload = token.split('.').nth(1)?;
    let claims: TidOnly = serde_json::from_slice(&b64url(payload).ok()?).ok()?;
    claims.tid
}

/// A local, **untrusted** OpenID provider used only by tests, the CLI `demo`, and CI: it mints
/// ID tokens and serves a matching JWKS so the whole federated-identity workflow runs offline.
/// Its `iss` (`https://issuer.test`) is trusted by no real verifier, so it is never a production
/// identity source. Compiled only under `#[cfg(test)]` or the `test-issuer` feature.
#[cfg(any(test, feature = "test-issuer"))]
pub mod testing {
    use super::{Jwk, Jwks};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine as _;
    use rsa::Pkcs1v15Sign;
    use sha2::{Digest, Sha256};

    fn b64url_encode(bytes: &[u8]) -> String {
        B64URL.encode(bytes)
    }

    /// A minimal in-process OpenID provider that mints ID tokens and serves a matching JWKS.
    pub enum TestIssuer {
        Es256 {
            signing: p256::ecdsa::SigningKey,
            kid: String,
        },
        Rs256 {
            private: Box<rsa::RsaPrivateKey>,
            kid: String,
        },
    }

    /// A process-wide ES256 test issuer, so tests (and the CLI dev login) can pin its single key in
    /// a [`crate::trust::TrustStore`] instead of trusting the dev issuer blindly.
    pub fn shared_es256() -> &'static TestIssuer {
        static SHARED: std::sync::OnceLock<TestIssuer> = std::sync::OnceLock::new();
        SHARED.get_or_init(TestIssuer::es256)
    }

    impl TestIssuer {
        /// A fresh ES256 (P-256) issuer.
        pub fn es256() -> Self {
            TestIssuer::Es256 {
                signing: crate::crypto::generate_signing_key(),
                kid: "es-test-1".to_string(),
            }
        }

        /// A fresh RS256 (RSA-2048) issuer — the algorithm Google/Microsoft/Apple use.
        pub fn rs256() -> Self {
            let private = rsa::RsaPrivateKey::new(&mut crate::crypto::os_rng(), 2048).unwrap();
            TestIssuer::Rs256 {
                private: Box::new(private),
                kid: "rs-test-1".to_string(),
            }
        }

        /// The single public JWK for this issuer (suitable as a record's `idp_jwk`).
        pub fn jwk(&self) -> Jwk {
            match self {
                TestIssuer::Es256 { signing, kid } => {
                    let vk = signing.verifying_key();
                    let pt = vk.to_sec1_point(false);
                    Jwk {
                        kty: "EC".into(),
                        kid: Some(kid.clone()),
                        alg: Some("ES256".into()),
                        n: None,
                        e: None,
                        crv: Some("P-256".into()),
                        x: Some(b64url_encode(pt.x().unwrap())),
                        y: Some(b64url_encode(pt.y().unwrap())),
                    }
                }
                TestIssuer::Rs256 { private, kid } => {
                    use rsa::traits::PublicKeyParts;
                    let pubkey = private.to_public_key();
                    Jwk {
                        kty: "RSA".into(),
                        kid: Some(kid.clone()),
                        alg: Some("RS256".into()),
                        n: Some(b64url_encode(&pubkey.n_bytes())),
                        e: Some(b64url_encode(&pubkey.e_bytes())),
                        crv: None,
                        x: None,
                        y: None,
                    }
                }
            }
        }

        /// The JWKS (one key) this issuer publishes.
        pub fn jwks(&self) -> Jwks {
            Jwks {
                keys: vec![self.jwk()],
            }
        }

        /// The JWS `alg` this issuer signs with.
        pub fn alg(&self) -> &'static str {
            match self {
                TestIssuer::Es256 { .. } => "ES256",
                TestIssuer::Rs256 { .. } => "RS256",
            }
        }

        /// The issuer's key id (`kid`).
        pub fn kid(&self) -> String {
            match self {
                TestIssuer::Es256 { kid, .. } | TestIssuer::Rs256 { kid, .. } => kid.clone(),
            }
        }

        /// Mint a signed compact JWS over `claims`.
        pub fn mint(&self, claims: serde_json::Value) -> String {
            let header = serde_json::json!({ "alg": self.alg(), "kid": self.kid(), "typ": "JWT" });
            let signing_input = format!(
                "{}.{}",
                b64url_encode(serde_json::to_vec(&header).unwrap().as_slice()),
                b64url_encode(serde_json::to_vec(&claims).unwrap().as_slice())
            );
            let sig = match self {
                TestIssuer::Es256 { signing, .. } => {
                    use p256::ecdsa::signature::Signer;
                    let s: p256::ecdsa::Signature = signing.sign(signing_input.as_bytes());
                    b64url_encode(&s.to_bytes())
                }
                TestIssuer::Rs256 { private, .. } => {
                    let hashed = Sha256::digest(signing_input.as_bytes());
                    let s = private
                        .sign(Pkcs1v15Sign::new::<Sha256>(), &hashed)
                        .unwrap();
                    b64url_encode(&s)
                }
            };
            format!("{signing_input}.{sig}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

    fn b64url_encode(bytes: &[u8]) -> String {
        B64URL.encode(bytes)
    }

    use super::testing::TestIssuer;

    const ISS: &str = "https://issuer.test";
    const AUD: &str = "signpdf-client-id";
    const NOW: i64 = 1_900_000_000;

    fn base_claims(extra: serde_json::Value) -> serde_json::Value {
        let mut claims = serde_json::json!({
            "iss": ISS,
            "sub": "user-123",
            "aud": AUD,
            "exp": NOW + 300,
            "iat": NOW - 5,
            "email": "bob@contoso.com",
            "email_verified": true,
        });
        if let (Some(base), Some(ext)) = (claims.as_object_mut(), extra.as_object()) {
            for (k, v) in ext {
                base.insert(k.clone(), v.clone());
            }
        }
        claims
    }

    fn validation() -> Validation {
        Validation::new(vec![ISS.to_string()], AUD, NOW)
    }

    #[test]
    fn es256_happy_path_and_assurance() {
        let issuer = TestIssuer::es256();
        let token = issuer.mint(base_claims(serde_json::json!({})));
        let id = verify_id_token(&token, &issuer.jwks(), &validation()).unwrap();
        assert_eq!(id.email, "bob@contoso.com");
        assert!(id.email_verified);
        assert_eq!(id.subject, "user-123");
        assert_eq!(id.organization(), None);
        let account = id.assess(IssuerKind::Account);
        assert_eq!(account.level, Level::L2);
        assert_eq!(
            account.basis,
            [Basis {
                method: Method::Account,
                issuer: ISS.into(),
                organization: None
            }]
        );
        assert_eq!(id.assess(IssuerKind::EmailCode).level, Level::L1);
        assert_eq!(id.assess(IssuerKind::Organization).level, Level::L3);
    }

    #[test]
    fn levels_follow_the_issuer_kind_and_the_tokens_evidence() {
        let issuer = TestIssuer::es256();
        let level = |claims: serde_json::Value, kind: IssuerKind| {
            let token = issuer.mint(base_claims(claims));
            let id = verify_id_token(&token, &issuer.jwks(), &validation()).unwrap();
            let a = id.assess(kind);
            (a.level, a.basis[0].method, a.basis[0].organization.clone())
        };
        let none = serde_json::json!({});
        let hd = serde_json::json!({ "hd": "contoso.com" });
        let otp = serde_json::json!({ "acr": ACR_EMAIL_OTP, "hd": "contoso.com" });
        assert_eq!(
            level(hd.clone(), IssuerKind::Account),
            (
                Level::L3,
                Method::Organization,
                Some("contoso.com".to_string())
            )
        );
        // An email-code provider shows an email code, whatever its tokens claim...
        assert_eq!(
            level(hd, IssuerKind::EmailCode),
            (Level::L1, Method::EmailCode, None)
        );
        // ...and so does a token that says it came from an email code, wherever it is from.
        for kind in IssuerKind::ALL {
            assert_eq!(
                level(otp.clone(), kind),
                (Level::L1, Method::EmailCode, None)
            );
        }
        assert_eq!(
            level(none.clone(), IssuerKind::Organization),
            (Level::L3, Method::Organization, None)
        );
        // An `acr` that is not a string is no `acr`.
        assert_eq!(
            level(serde_json::json!({ "acr": 3 }), IssuerKind::Account).0,
            Level::L2
        );
        let token = issuer.mint(base_claims(serde_json::json!({ "acr": ["x"] })));
        assert!(verify_id_token(&token, &issuer.jwks(), &validation())
            .unwrap()
            .acr
            .is_none());
    }

    #[test]
    fn the_well_known_providers_are_account_providers() {
        for iss in [
            "https://accounts.google.com",
            "https://appleid.apple.com/",
            DEV_ISSUER,
        ] {
            assert_eq!(
                builtin_issuer_kind(iss, None),
                Some(IssuerKind::Account),
                "{iss}"
            );
        }
        let tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        let ms = format!("https://login.microsoftonline.com/{tid}/v2.0");
        assert_eq!(
            builtin_issuer_kind(&ms, Some(tid)),
            Some(IssuerKind::Account)
        );
        assert_eq!(builtin_issuer_kind(&ms, None), None);
        assert_eq!(builtin_issuer_kind("https://id.example.test", None), None);
    }

    #[test]
    fn levels_and_methods_have_stable_names() {
        for l in Level::ALL {
            assert_eq!(Level::parse(l.as_str()), Some(l));
            assert_eq!(serde_json::to_value(l).unwrap(), l.as_str());
        }
        for m in Method::ALL {
            assert_eq!(Method::parse(m.as_str()), Some(m));
            assert_eq!(serde_json::to_value(m).unwrap(), m.as_str());
        }
        for k in IssuerKind::ALL {
            assert_eq!(IssuerKind::parse(k.as_str()), Some(k));
            assert_eq!(serde_json::to_value(k).unwrap(), k.as_str());
        }
        assert!(Level::L1 < Level::L2 && Level::L4 < Level::L5);
        assert_eq!(Method::Phone.level(), Level::L3);
        assert_eq!(Level::L4.name(), "ID checked");
    }

    #[test]
    fn a_policy_reads_the_version_3_requirement_and_refuses_both() {
        let read = |json: serde_json::Value| serde_json::from_value::<IdentityPolicy>(json);
        let p = read(serde_json::json!({ "min_assurance": "enterprise" })).unwrap();
        assert_eq!(p.min_level, Level::L3);
        let p = read(serde_json::json!({ "min_assurance": "consumer" })).unwrap();
        assert_eq!(p, IdentityPolicy::default());
        let p = read(serde_json::json!({})).unwrap();
        assert_eq!(p.min_level, Level::L1);
        let p =
            read(serde_json::json!({ "min_level": "L2", "required_methods": ["phone"] })).unwrap();
        assert_eq!(
            (p.min_level, p.required_methods),
            (Level::L2, vec![Method::Phone])
        );
        for bad in [
            serde_json::json!({ "min_level": "L2", "min_assurance": "consumer" }),
            serde_json::json!({ "min_assurance": "gold" }),
            serde_json::json!({ "min_level": "L6" }),
            serde_json::json!({ "min_level": 2 }),
            serde_json::json!({ "required_methods": ["telepathy"] }),
        ] {
            assert!(read(bad.clone()).is_err(), "{bad}");
        }
        // Written with min_level only.
        let json = serde_json::to_value(IdentityPolicy::default()).unwrap();
        assert_eq!(json["min_level"], "L1");
        assert!(json.get("min_assurance").is_none() && json.get("required_methods").is_none());
    }

    #[test]
    fn a_slot_is_met_by_its_level_and_methods() {
        let a = Assessment {
            level: Level::L2,
            basis: vec![Basis {
                method: Method::Account,
                issuer: ISS.into(),
                organization: None,
            }],
        };
        let policy = |min_level, required_methods| IdentityPolicy {
            min_level,
            required_methods,
            ..Default::default()
        };
        assert!(a.meets(&policy(Level::L1, vec![])).is_ok());
        assert!(a.meets(&policy(Level::L2, vec![Method::Account])).is_ok());
        let low = a.meets(&policy(Level::L3, vec![])).unwrap_err();
        assert!(
            low.contains("L2 (Account)") && low.contains("L3 (Strong)"),
            "{low}"
        );
        let missing = a
            .meets(&policy(Level::L1, vec![Method::Phone]))
            .unwrap_err();
        assert!(missing.contains("phone"), "{missing}");
        // Slots no signature this build checks could fill.
        assert!(policy(Level::L3, vec![Method::Organization])
            .fillable_by_this_build()
            .is_ok());
        assert!(policy(Level::L4, vec![]).fillable_by_this_build().is_err());
        assert!(policy(Level::L1, vec![Method::IdDocument])
            .fillable_by_this_build()
            .is_err());
    }

    #[test]
    fn token_algorithms_come_from_the_header_and_the_key() {
        use crate::algorithms::{Algorithm, AlgorithmUse};
        let es = TestIssuer::es256();
        let token = es.mint(base_claims(serde_json::json!({})));
        assert_eq!(
            token_algorithms(&token, &es.jwk()),
            [
                AlgorithmUse::plain(Algorithm::EcdsaP256),
                AlgorithmUse::plain(Algorithm::Sha256)
            ]
        );
        let rs = TestIssuer::rs256();
        let token = rs.mint(base_claims(serde_json::json!({})));
        assert_eq!(
            token_algorithms(&token, &rs.jwk())[0],
            AlgorithmUse::rsa(2048)
        );
        assert!(token_algorithms("not.a.token", &rs.jwk()).is_empty());
    }

    #[test]
    fn rs256_happy_path() {
        let issuer = TestIssuer::rs256();
        let token = issuer.mint(base_claims(serde_json::json!({})));
        let id = verify_id_token(&token, &issuer.jwks(), &validation()).unwrap();
        assert_eq!(id.email, "bob@contoso.com");
    }

    /// Verify a fresh RSA-2048 token after `edit` changes the JWK's `n`, `e` or the signature.
    fn rs256_with(
        edit: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>),
    ) -> Result<VerifiedIdentity> {
        rs256_by(&TestIssuer::rs256(), edit)
    }

    /// Verify a token from `issuer` after `edit` changes the JWK's `n`, `e` or the signature.
    fn rs256_by(
        issuer: &TestIssuer,
        edit: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>),
    ) -> Result<VerifiedIdentity> {
        let token = issuer.mint(base_claims(serde_json::json!({})));
        let mut jwks = issuer.jwks();
        let (mut n, mut e) = (
            b64url(jwks.keys[0].n.as_deref().unwrap()).unwrap(),
            b64url(jwks.keys[0].e.as_deref().unwrap()).unwrap(),
        );
        let (signing_input, sig) = token.rsplit_once('.').unwrap();
        let mut sig = b64url(sig).unwrap();
        edit(&mut n, &mut e, &mut sig);
        jwks.keys[0].n = Some(b64url_encode(&n));
        jwks.keys[0].e = Some(b64url_encode(&e));
        let token = format!("{signing_input}.{}", b64url_encode(&sig));
        verify_id_token(&token, &jwks, &validation())
    }

    #[test]
    fn rs256_accepts_leading_zeros_in_the_key() {
        // RFC 7518 asks for minimal integers, but some libraries publish a leading 0x00.
        let id = rs256_with(|n, e, _| {
            n.insert(0, 0);
            e.insert(0, 0);
        })
        .unwrap();
        assert_eq!(id.email, "bob@contoso.com");
        // More padding, still within the size limit, is stripped the same way.
        rs256_with(|n, _, _| n.splice(0..0, [0u8; 200]).for_each(drop)).unwrap();
    }

    #[test]
    fn rs256_rejects_a_padded_key_without_doing_the_work() {
        // A hostile document can carry its own JWK. One padded with a megabyte of zeros used to
        // keep the verifier busy for minutes; it is now refused before any arithmetic.
        let started = std::time::Instant::now();
        let err = rs256_with(|n, _, sig| {
            n.splice(0..0, vec![0u8; 1 << 20]).for_each(drop);
            sig.splice(0..0, vec![0u8; 1 << 20]).for_each(drop);
        })
        .unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn rs256_rejects_an_oversize_modulus() {
        // 4104 bits, odd: over rsa 0.9's 4096-bit limit, which the verifier keeps.
        let err = rs256_with(|n, _, _| *n = [vec![0xFF; 512], vec![0x01]].concat()).unwrap_err();
        assert!(err.to_string().contains("4096 bits"), "{err}");
    }

    #[test]
    fn rs256_rejects_a_signature_that_is_not_the_modulus_length() {
        assert!(rs256_with(|_, _, sig| sig.insert(0, 0)).is_err());
        assert!(rs256_with(|_, _, sig| {
            sig.pop();
        })
        .is_err());

        // The case only the verifier's own length rule catches. A 2040-bit key has a 255-byte
        // modulus and signatures; one leading zero byte keeps the signature's value and its
        // 32-limb size, so rsa 0.10 alone would accept it. rsa 0.9 and RFC 8017 §8.2.2 do not.
        let issuer = TestIssuer::Rs256 {
            private: Box::new(rsa::RsaPrivateKey::new(&mut crate::crypto::os_rng(), 2040).unwrap()),
            kid: "rs-test-2040".into(),
        };
        rs256_by(&issuer, |n, _, sig| {
            assert_eq!((n.len(), sig.len()), (255, 255))
        })
        .unwrap();
        let err = rs256_by(&issuer, |_, _, sig| sig.insert(0, 0)).unwrap_err();
        assert!(err.to_string().contains("did not verify"), "{err}");
    }

    #[test]
    fn enterprise_assurance_from_tenant() {
        let issuer = TestIssuer::es256();
        let token = issuer.mint(base_claims(serde_json::json!({ "tid": "tenant-xyz" })));
        let id = verify_id_token(&token, &issuer.jwks(), &validation()).unwrap();
        assert_eq!(id.organization(), Some("tenant-xyz"));
        assert_eq!(id.assess(IssuerKind::Account).level, Level::L3);
    }

    #[test]
    fn rejects_tampered_payload() {
        let issuer = TestIssuer::es256();
        let token = issuer.mint(base_claims(serde_json::json!({})));
        // Flip a claim by re-encoding a different payload while keeping the original signature.
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = b64url_encode(
            serde_json::to_vec(&base_claims(
                serde_json::json!({ "email": "eve@evil.test" }),
            ))
            .unwrap()
            .as_slice(),
        );
        parts[1] = &forged;
        let tampered = parts.join(".");
        assert!(verify_id_token(&tampered, &issuer.jwks(), &validation()).is_err());
    }

    #[test]
    fn rejects_wrong_key() {
        let issuer = TestIssuer::es256();
        let other = TestIssuer::es256();
        let token = issuer.mint(base_claims(serde_json::json!({})));
        // Validate against a JWKS that advertises the same kid but a different key.
        let mut foreign = other.jwks();
        foreign.keys[0].kid = Some(issuer.kid());
        assert!(verify_id_token(&token, &foreign, &validation()).is_err());
    }

    #[test]
    fn rejects_alg_none() {
        let header = b64url_encode(br#"{"alg":"none","kid":"es-test-1"}"#);
        let payload = b64url_encode(
            serde_json::to_vec(&base_claims(serde_json::json!({})))
                .unwrap()
                .as_slice(),
        );
        let forged = format!("{header}.{payload}.");
        let issuer = TestIssuer::es256();
        assert!(verify_id_token(&forged, &issuer.jwks(), &validation()).is_err());
    }

    #[test]
    fn rejects_bad_audience() {
        let issuer = TestIssuer::es256();
        let token = issuer.mint(base_claims(serde_json::json!({ "aud": "someone-else" })));
        let err = verify_id_token(&token, &issuer.jwks(), &validation()).unwrap_err();
        assert!(err.to_string().contains("audience"));
    }

    #[test]
    fn rejects_expired_token() {
        let issuer = TestIssuer::es256();
        let token = issuer.mint(base_claims(serde_json::json!({ "exp": NOW - 1000 })));
        assert!(verify_id_token(&token, &issuer.jwks(), &validation()).is_err());
    }

    #[test]
    fn expiry_and_not_before_have_two_minutes_of_leeway() {
        let issuer = TestIssuer::es256();
        let check = |claims: serde_json::Value| {
            verify_id_token(
                &issuer.mint(base_claims(claims)),
                &issuer.jwks(),
                &validation(),
            )
        };
        assert_eq!(validation().leeway_secs, 120);
        assert!(check(serde_json::json!({ "exp": NOW - 110 })).is_ok());
        assert!(check(serde_json::json!({ "exp": NOW - 130 })).is_err());
        assert!(check(serde_json::json!({ "nbf": NOW + 110 })).is_ok());
        assert!(check(serde_json::json!({ "nbf": NOW + 130 })).is_err());
    }

    #[test]
    fn rejects_untrusted_issuer() {
        let issuer = TestIssuer::es256();
        let token = issuer.mint(base_claims(
            serde_json::json!({ "iss": "https://evil.test" }),
        ));
        assert!(verify_id_token(&token, &issuer.jwks(), &validation()).is_err());
    }

    #[test]
    fn nonce_binding_round_trip() {
        let issuer = TestIssuer::es256();
        let pubkey_sec1 = [0x04u8; 65];
        let doc_digest = "ab".repeat(32);
        let nonce = compute_nonce(&pubkey_sec1, &doc_digest);
        let token = issuer.mint(base_claims(serde_json::json!({ "nonce": nonce.clone() })));

        let mut ok = validation();
        ok.expected_nonce = Some(nonce);
        assert!(verify_id_token(&token, &issuer.jwks(), &ok).is_ok());

        let mut wrong = validation();
        wrong.expected_nonce = Some(compute_nonce(&[0x04u8; 65], &"cd".repeat(32)));
        assert!(verify_id_token(&token, &issuer.jwks(), &wrong).is_err());
    }

    #[test]
    fn missing_nonce_when_required_is_rejected() {
        let issuer = TestIssuer::es256();
        let token = issuer.mint(base_claims(serde_json::json!({})));
        let mut v = validation();
        v.expected_nonce = Some("anything".to_string());
        assert!(verify_id_token(&token, &issuer.jwks(), &v).is_err());
    }

    #[test]
    fn policy_required_email_matches() {
        let id = VerifiedIdentity {
            issuer: ISS.into(),
            subject: "s".into(),
            email: "Bob@Contoso.com".into(),
            email_verified: true,
            hosted_domain: None,
            tenant_id: None,
            name: None,
            acr: None,
        };
        let policy = IdentityPolicy {
            allowed_issuers: vec![ISS.into()],
            required_email: Some("bob@contoso.com".into()),
            required_domain: None,
            required_tenant: None,
            required_subject: None,
            min_level: Level::L1,
            required_methods: vec![],
        };
        assert!(id.satisfies(&policy).is_ok());
    }

    #[test]
    fn policy_rejects_wrong_email_and_unverified() {
        let policy = IdentityPolicy {
            allowed_issuers: vec![],
            required_email: Some("bob@contoso.com".into()),
            required_domain: None,
            required_tenant: None,
            required_subject: None,
            min_level: Level::L1,
            required_methods: vec![],
        };
        let wrong = VerifiedIdentity {
            issuer: ISS.into(),
            subject: "s".into(),
            email: "eve@contoso.com".into(),
            email_verified: true,
            hosted_domain: None,
            tenant_id: None,
            name: None,
            acr: None,
        };
        assert!(wrong.satisfies(&policy).is_err());

        let unverified = VerifiedIdentity {
            email: "bob@contoso.com".into(),
            email_verified: false,
            ..wrong
        };
        assert!(unverified.satisfies(&policy).is_err());
    }

    #[test]
    fn policy_domain_and_assurance() {
        let policy = IdentityPolicy {
            allowed_issuers: vec![],
            required_email: None,
            required_domain: Some("contoso.com".into()),
            required_tenant: None,
            required_subject: None,
            min_level: Level::L3,
            required_methods: vec![],
        };
        let consumer = VerifiedIdentity {
            issuer: ISS.into(),
            subject: "s".into(),
            email: "bob@contoso.com".into(),
            email_verified: true,
            hosted_domain: None,
            tenant_id: None,
            name: None,
            acr: None,
        };
        // Right domain, but the level is too low: a consumer account is L2.
        assert!(consumer.satisfies(&policy).is_ok());
        assert!(consumer.assess(IssuerKind::Account).meets(&policy).is_err());

        let enterprise = VerifiedIdentity {
            hosted_domain: Some("contoso.com".into()),
            ..consumer
        };
        assert!(enterprise.satisfies(&policy).is_ok());
        assert!(enterprise
            .assess(IssuerKind::Account)
            .meets(&policy)
            .is_ok());

        let wrong_domain = VerifiedIdentity {
            email: "bob@other.test".into(),
            ..enterprise
        };
        assert!(wrong_domain.satisfies(&policy).is_err());
    }

    const MS_ORG_TENANT: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";

    fn ms_claims(tid: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut c = base_claims(serde_json::json!({
            "iss": format!("https://login.microsoftonline.com/{tid}/v2.0"),
            "tid": tid,
        }));
        c.as_object_mut().unwrap().remove("email_verified");
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        c
    }

    fn ms_validation() -> Validation {
        Validation::new(vec![MICROSOFT_ISSUER_TEMPLATE.to_string()], AUD, NOW)
    }

    #[test]
    fn issuer_template_matches_only_the_tokens_own_tenant() {
        let t = MICROSOFT_ISSUER_TEMPLATE;
        let iss = format!("https://login.microsoftonline.com/{MS_ORG_TENANT}/v2.0");
        assert!(issuer_matches(t, &iss, Some(MS_ORG_TENANT)));
        // A token claiming a different tenant in `iss` than in `tid` is rejected.
        assert!(!issuer_matches(t, &iss, Some(MICROSOFT_CONSUMER_TENANT)));
        assert!(!issuer_matches(t, &iss, None));
        // Placeholder injection is not possible.
        assert!(!issuer_matches(
            t,
            "https://evil.test/x/v2.0",
            Some("../../evil")
        ));
        assert!(issuer_matches("https://a.test/", "https://a.test", None));
    }

    #[test]
    fn microsoft_personal_account_is_consumer_with_verified_email() {
        let issuer = TestIssuer::es256();
        let token = issuer.mint(ms_claims(MICROSOFT_CONSUMER_TENANT, serde_json::json!({})));
        let id = verify_id_token(&token, &issuer.jwks(), &ms_validation()).unwrap();
        assert_eq!(id.organization(), None, "MSA tenant is not an org");
        assert_eq!(id.assess(IssuerKind::Account).level, Level::L2);
        assert!(id.email_verified, "MSA sign-in email counts as verified");
        assert_eq!(id.tenant_id.as_deref(), Some(MICROSOFT_CONSUMER_TENANT));
    }

    #[test]
    fn microsoft_org_account_needs_edov_for_verified_email() {
        let issuer = TestIssuer::es256();
        let token = issuer.mint(ms_claims(MS_ORG_TENANT, serde_json::json!({})));
        let id = verify_id_token(&token, &issuer.jwks(), &ms_validation()).unwrap();
        assert_eq!(id.organization(), Some(MS_ORG_TENANT));
        assert!(
            !id.email_verified,
            "Entra email is unverified without xms_edov"
        );

        let token = issuer.mint(ms_claims(
            MS_ORG_TENANT,
            serde_json::json!({ "xms_edov": true }),
        ));
        let id = verify_id_token(&token, &issuer.jwks(), &ms_validation()).unwrap();
        assert!(id.email_verified);
    }

    #[test]
    fn entra_identity_needs_pinned_tenant_for_domain_slots() {
        let issuer = TestIssuer::es256();
        let token = issuer.mint(ms_claims(
            MS_ORG_TENANT,
            serde_json::json!({ "xms_edov": true }),
        ));
        let id = verify_id_token(&token, &issuer.jwks(), &ms_validation()).unwrap();
        let mut policy = IdentityPolicy {
            required_domain: Some("contoso.com".into()),
            min_level: Level::L3,
            ..Default::default()
        };
        assert!(
            id.satisfies(&policy).is_err(),
            "domain alone is not enough for Entra"
        );
        policy.required_tenant = Some(MS_ORG_TENANT.into());
        assert!(id.satisfies(&policy).is_ok());
        policy.required_tenant = Some("00000000-0000-0000-0000-000000000000".into());
        assert!(id.satisfies(&policy).is_err());
    }

    #[test]
    fn workspace_hosted_domain_must_match_required_domain() {
        let issuer = TestIssuer::es256();
        // Email in contoso.com but hosted domain of another org.
        let token = issuer.mint(base_claims(serde_json::json!({ "hd": "fabrikam.com" })));
        let id = verify_id_token(&token, &issuer.jwks(), &validation()).unwrap();
        let policy = IdentityPolicy {
            required_domain: Some("contoso.com".into()),
            min_level: Level::L3,
            ..Default::default()
        };
        assert!(id.satisfies(&policy).is_err());
    }

    #[test]
    fn subject_pinning() {
        let issuer = TestIssuer::es256();
        let token = issuer.mint(base_claims(serde_json::json!({})));
        let id = verify_id_token(&token, &issuer.jwks(), &validation()).unwrap();
        let mut policy = IdentityPolicy {
            required_subject: Some("user-123".into()),
            ..Default::default()
        };
        assert!(id.satisfies(&policy).is_ok());
        policy.required_subject = Some("someone-else".into());
        assert!(id.satisfies(&policy).is_err());
    }

    #[test]
    fn permissive_policies_are_flagged() {
        assert_eq!(IdentityPolicy::default().weaknesses().len(), 2);
        let tight = IdentityPolicy {
            allowed_issuers: vec![ISS.into()],
            required_email: Some("a@b.test".into()),
            ..Default::default()
        };
        assert!(tight.weaknesses().is_empty());
    }
}
