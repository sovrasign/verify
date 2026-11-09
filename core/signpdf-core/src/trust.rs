//! Verifier trust anchors: which identity providers (and which of their keys) and which
//! Time-Stamp Authorities a verifier is willing to believe.
//!
//! A signed SignPDF document archives, for every identity token, the exact JWK that signed it so
//! the token can be re-checked offline. That archived key is **attacker-controlled data**: anyone
//! can mint their own key, sign a token claiming `iss: https://accounts.google.com`, and archive
//! that key next to it. Verification is therefore only meaningful against an *independent* trust
//! anchor — this [`TrustStore`] — that pins, per issuer, the key thumbprints the verifier has
//! obtained from the provider itself (e.g. by fetching its JWKS over TLS).
//!
//! Providers rotate keys, so a store keeps **key history**: [`TrustStore::add_jwks`] merges newly
//! fetched keys with the ones already pinned, and a document signed under a since-rotated key
//! still verifies on any verifier that saw that key while it was published.
//!
//! A pinned key may carry a **validity window** ([`KeyWindow`]): when its issuer began and
//! stopped signing with it (`not_before`, `not_after`), and from when it may be compromised
//! (`distrusted_after`). An issuer may also **require trusted time**
//! ([`TrustedIssuer::requires_trusted_time`]): its tokens then count only when a trusted
//! timestamp proves the signature was made inside the key's window. That is the rule for an
//! issuer whose key, if stolen, could mint tokens for any address and date them at will, such as
//! a service's own email-code provider. A token's `iat` is the key holder's word, so the end of a
//! window is only ever judged against trusted time ([`SigningTimeEvidence::existed_before`]),
//! never against the token or the signer's device clock.
//!
//! The bundled test issuer ([`crate::oidc::DEV_ISSUER`]) is trusted only through the explicit,
//! loudly-reported [`TrustStore::allow_insecure_dev_issuer`] opt-in.
//!
//! The store also says **what a sign-in with each issuer shows** ([`TrustedIssuer::kind`]: an
//! email code, an account, an organization identity), from which the verifier computes each
//! signature's assurance level ([`crate::oidc::Level`]), and carries the **algorithm policy**
//! ([`TrustStore::algorithm_policy`], [`crate::algorithms`]): which digest and signature
//! algorithms it accepts, until when, and under which timestamp.
//!
//! A store may also **distrust a timestamp authority from a time** ([`TsaDistrust`],
//! [`TrustStore::tsa_distrusted`]): a timestamp whose chain holds that certificate and whose
//! `genTime` is at or after `distrusted_after` is not trusted ([`TrustStore::verify_tsa`]), for a
//! TSA whose key may have been compromised. The anchors are roots that many authorities share, so
//! removing one would distrust them all, and for every time.

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::algorithms::AlgorithmPolicy;
use crate::error::{Result, SignPdfError};
use crate::oidc::{
    builtin_issuer_kind, issuer_matches, IssuerKind, Jwk, Jwks, DEV_ISSUER,
    MICROSOFT_ISSUER_TEMPLATE,
};
use crate::util::{rfc3339_from_unix, unix_from_rfc3339};

/// Clock tolerance for the start of a key's window, which is judged against the token's own
/// `iat` (the issuer's clock) or a timestamp's time. The end of a window has none: it is judged
/// against trusted time only, and an issuer sets it with its own margin.
const WINDOW_START_LEEWAY_SECS: i64 = 300;

/// DigiCert Trusted Root G4 (self-signed, expires 2038-01-15), the root of DigiCert's public RFC
/// 3161 TSA (`http://timestamp.digicert.com`). SHA-256 fingerprint
/// `552F7BDCF1A7AF9E6CE672017F4F12ABF77240C78E761AC203D1D9D20AC89988`.
pub const DIGICERT_TRUSTED_ROOT_G4: &[u8] =
    include_bytes!("../anchors/digicert_trusted_root_g4.der");

/// The `client_id` of SignPDF's own app registration with Google. Tokens SignPDF obtains from
/// Google carry it as their `aud`.
pub const SIGNPDF_GOOGLE_CLIENT_ID: &str =
    "261636994061-1sqrioo530vjm6j891hbtuehq0kvcoe1.apps.googleusercontent.com";

/// The `client_id` of SignPDF's own app registration with Microsoft (Entra, multi-tenant).
pub const SIGNPDF_MICROSOFT_CLIENT_ID: &str = "75864452-0858-4959-9e2f-92d12b83a1ad";

/// SignPDF's own registrations with a well-known issuer: the applications a verifier trusts for
/// it without being told. Empty for every other issuer (including Apple, where SignPDF has none).
fn builtin_audiences(issuer: &str) -> Vec<String> {
    let is = |known: &str| issuer.trim_end_matches('/') == known;
    if is("https://accounts.google.com") {
        vec![SIGNPDF_GOOGLE_CLIENT_ID.to_string()]
    } else if is(MICROSOFT_ISSUER_TEMPLATE) {
        vec![SIGNPDF_MICROSOFT_CLIENT_ID.to_string()]
    } else {
        Vec::new()
    }
}

/// When an issuer's key may vouch for a signature. Times are RFC 3339 (UTC, e.g.
/// `2027-11-01T00:00:00Z`); an absent bound is open.
///
/// - `not_before`: the issuer began signing with the key then. A token whose `iat` is earlier, or
///   a signature a trusted timestamp places earlier, is refused.
/// - `not_after`: the issuer stopped signing with the key then (a planned rotation; set it with
///   the token lifetime and some clock skew added to the switch time). A token counts only when a
///   trusted timestamp proves its signature existed by then.
/// - `distrusted_after`: the key may have been compromised from then on (the last known-good
///   time). A token counts only when a trusted timestamp proves its signature existed by then.
///
/// The end of a window needs **trusted time** because whoever holds a stolen key can write any
/// `iat` into the tokens it mints, and a signer's device clock says what its owner wants.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyWindow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distrusted_after: Option<String>,
}

impl KeyWindow {
    /// No bound at all.
    pub fn is_open(&self) -> bool {
        self.not_before.is_none() && self.not_after.is_none() && self.distrusted_after.is_none()
    }

    /// Every bound that is set parses as RFC 3339.
    pub fn validate(&self) -> std::result::Result<(), String> {
        for (name, value) in [
            ("not_before", &self.not_before),
            ("not_after", &self.not_after),
            ("distrusted_after", &self.distrusted_after),
        ] {
            if let Some(v) = value {
                if unix_from_rfc3339(v).is_none() {
                    return Err(format!("{name} '{v}' is not an RFC 3339 time"));
                }
            }
        }
        Ok(())
    }

    /// The narrower of `self` and `other`: the later start, the earlier ends. Used when two
    /// sources disagree; never widens a window.
    fn narrowed(&self, other: &KeyWindow) -> KeyWindow {
        KeyWindow {
            not_before: pick(&self.not_before, &other.not_before, |a, b| a >= b),
            not_after: pick(&self.not_after, &other.not_after, |a, b| a <= b),
            distrusted_after: pick(&self.distrusted_after, &other.distrusted_after, |a, b| {
                a <= b
            }),
        }
    }
}

/// One of two optional bounds: the one `keep_a(a, b)` prefers when both parse; an unreadable
/// bound is kept over a readable one (it fails closed when checked).
fn pick(
    a: &Option<String>,
    b: &Option<String>,
    keep_a: impl Fn(i64, i64) -> bool,
) -> Option<String> {
    match (a, b) {
        (None, x) | (x, None) => x.clone(),
        (Some(x), Some(y)) => match (unix_from_rfc3339(x), unix_from_rfc3339(y)) {
            (Some(tx), Some(ty)) => Some(if keep_a(tx, ty) { x } else { y }.clone()),
            (None, _) => Some(x.clone()),
            (_, None) => Some(y.clone()),
        },
    }
}

/// A timestamp authority certificate the verifier stops believing from a time: its key may have
/// been compromised then (`distrusted_after`, RFC 3339, the last known-good time). A timestamp
/// whose chain (the TSA certificate, an intermediate or the anchor) holds the certificate and whose
/// `genTime` is **at or after** that time is not trusted; earlier ones still are.
///
/// `genTime` is the authority's own claim, so whoever holds a stolen TSA key can still date a
/// token before `distrusted_after`: set it to the earliest time the key may have been exposed. A
/// document whose only trusted time came from such a stamp needs a new timestamp from another
/// authority (a hosted service re-stamps them).
///
/// In JSON: `{"cert_sha256": "<64 hex digits>", "distrusted_after": "2027-03-01T00:00:00Z"}`, with
/// an optional informational `name`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TsaDistrust {
    /// SHA-256 of the certificate's DER bytes, hex (either case; written lowercase).
    pub cert_sha256: String,
    /// From when (RFC 3339) the certificate's timestamps are not trusted.
    pub distrusted_after: String,
    /// A label for people (the authority's name). Informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl TsaDistrust {
    /// The certificate hash is 64 hex digits and the time parses as RFC 3339.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.cert_sha256.len() != 64 || !self.cert_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(format!(
                "cert_sha256 '{}' is not a SHA-256 in hex (64 digits)",
                self.cert_sha256
            ));
        }
        if unix_from_rfc3339(&self.distrusted_after).is_none() {
            return Err(format!(
                "distrusted_after '{}' is not an RFC 3339 time",
                self.distrusted_after
            ));
        }
        Ok(())
    }

    fn matches(&self, sha256_hex: &str) -> bool {
        self.cert_sha256.eq_ignore_ascii_case(sha256_hex)
    }
}

/// SHA-256 (lowercase hex) of a certificate's DER bytes, as [`TsaDistrust::cert_sha256`] names it.
pub fn cert_sha256_hex(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A key pinned for an issuer: the public JWK, its validity window, and when the store saw it.
///
/// In JSON it is the JWK's own members with the window's next to them, so a store without
/// windows reads and writes exactly as before:
/// `{"kty":"EC","crv":"P-256","x":"…","y":"…","not_after":"2027-11-01T00:08:00Z"}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedKey {
    #[serde(flatten)]
    pub jwk: Jwk,
    #[serde(flatten)]
    pub window: KeyWindow,
    /// When the store first saw the key published (RFC 3339). Informational only: it never
    /// decides validity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    /// When the store last saw the key published (RFC 3339). Informational only: a key a
    /// provider stopped publishing still vouches for what it signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

impl From<Jwk> for PinnedKey {
    fn from(jwk: Jwk) -> Self {
        PinnedKey {
            jwk,
            window: KeyWindow::default(),
            first_seen: None,
            last_seen: None,
        }
    }
}

impl Deref for PinnedKey {
    type Target = Jwk;
    fn deref(&self) -> &Jwk {
        &self.jwk
    }
}

/// One identity provider the verifier trusts, with the keys pinned for it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TrustedIssuer {
    /// Issuer identifier, or a template containing `{tenantid}` (Microsoft multi-tenant).
    pub issuer: String,
    /// Human label, e.g. `Google`.
    #[serde(default)]
    pub name: String,
    /// Where the provider publishes its keys (used by refresh tooling; never read during verify).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Pinned public keys (current and historical), each with its validity window. Matched by
    /// RFC 7638 thumbprint.
    #[serde(default)]
    pub keys: Vec<PinnedKey>,
    /// The applications (relying-party `client_id`s) whose tokens from this issuer are accepted.
    /// **Empty = none.** A provider issues tokens to every website and app its users sign in to,
    /// and each of those can ask for any `nonce`; without this restriction, any of them could
    /// obtain a token that signs a SignPDF document as its user. A token therefore only counts
    /// when its `aud` is an application the verifier trusts to run the signing ceremony.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// Tokens from this issuer count only when a **trusted timestamp** proves the signature was
    /// made inside the signing key's validity window: the signature's own timestamp, or a later
    /// one (another signature's, or a document timestamp added when the envelope ended). Without
    /// one the identity is reported `no-trusted-time`. Set it for an issuer whose key, if
    /// stolen, could vouch for any address, such as a signing service's own email-code provider:
    /// a thief could otherwise date tokens inside the window long after the key was distrusted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub requires_trusted_time: bool,
    /// What a sign-in with this issuer shows about the signer, from which the verifier computes
    /// the assurance level: `email-code` (L1: control of the inbox, whatever the tokens claim),
    /// `account` (L2; L3 for an organization identity the provider asserts, such as a Google
    /// Workspace domain or a Microsoft Entra organizational tenant) or `organization` (L3: an
    /// organization's own provider for its signers). When absent: `account` for Google,
    /// Microsoft and Apple ([`crate::oidc::builtin_issuer_kind`]), `email-code` for any other
    /// issuer (the least a verified email shows). See [`TrustStore::issuer_kind`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<IssuerKind>,
}

/// A JWKS as an issuer publishes it (`{"keys": [...]}`), read with each key's validity window
/// when it states one next to the key's members (`not_before`, `not_after`,
/// `distrusted_after`), as a signing service's own identity provider does. A provider JWKS
/// without windows reads as one with open windows. See [`TrustStore::add_published_jwks`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PublishedJwks {
    #[serde(default)]
    pub keys: Vec<PinnedKey>,
}

/// The verifier's trust anchors.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TrustStore {
    #[serde(default)]
    pub issuers: Vec<TrustedIssuer>,
    /// Base64 DER X.509 certificates trusted as RFC 3161 Time-Stamp Authority anchors (roots or
    /// intermediates). A timestamp counts as *trusted* only when its signer chains to one of them.
    #[serde(default)]
    pub tsa_anchors: Vec<String>,
    /// **Insecure.** Accept the bundled test issuer ([`DEV_ISSUER`]) with *any* key. For tests, the
    /// CLI `--email` dev login, and demos only; verification reports flag it prominently.
    #[serde(default)]
    pub allow_insecure_dev_issuer: bool,
    /// The algorithm policy: which digest and signature algorithms the verifier accepts, until
    /// when, and under which timestamp ([`crate::algorithms`]). Absent: the engine's built-in
    /// policy ([`AlgorithmPolicy::builtin`]). See [`TrustStore::algorithms`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm_policy: Option<AlgorithmPolicy>,
    /// Timestamp authority certificates distrusted from a time ([`TsaDistrust`]). Absent: none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tsa_distrusted: Vec<TsaDistrust>,
}

/// How a verifier's trust store regards one identity token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityTrust {
    /// Issuer is trusted and the token was signed by one of its pinned keys.
    Trusted,
    /// Accepted only through the insecure dev-issuer opt-in.
    InsecureDev,
    /// The issuer is not in the trust store.
    UnknownIssuer,
    /// The issuer is trusted but the archived signing key is not pinned for it (possible forgery,
    /// or a key the verifier never saw — refresh the store's JWKS).
    UnknownKey,
    /// The issuer is trusted only for other relying parties (`aud`).
    UntrustedAudience,
    /// The key is pinned, but it counts only with a trusted timestamp inside its validity
    /// window (its issuer requires one, or the key has an end), and none covers the signature
    /// yet. A timestamp added before the window ends makes it trusted.
    NoTrustedTime,
    /// The trusted time evidence, or the token's own `iat`, places the signature outside the
    /// key's validity window (after `not_after`, or before `not_before`).
    OutsideKeyWindow,
    /// The key is distrusted (possibly compromised) from a time no trusted timestamp proves the
    /// signature preceded.
    DistrustedKey,
    /// The token relies on an algorithm (or key size) the verifier's algorithm policy does not
    /// accept, or accepts only for tokens a trusted timestamp shows existed before its end date,
    /// and none does ([`crate::algorithms`]).
    AlgorithmNotAccepted,
    /// The identity is anchored, but the assurance level the verifier computes for it is below
    /// the level its slot requires, or it lacks evidence the slot requires (a signature made
    /// outside the engine's rules, or an issuer the verifier's trust store counts as weaker than
    /// the signing host did).
    InsufficientLevel,
}

impl IdentityTrust {
    /// Whether the verification report may count this identity as verified.
    pub fn is_acceptable(self) -> bool {
        matches!(self, IdentityTrust::Trusted | IdentityTrust::InsecureDev)
    }

    /// Short stable label (matches the serde form).
    pub fn as_str(self) -> &'static str {
        match self {
            IdentityTrust::Trusted => "trusted",
            IdentityTrust::InsecureDev => "insecure-dev",
            IdentityTrust::UnknownIssuer => "unknown-issuer",
            IdentityTrust::UnknownKey => "unknown-key",
            IdentityTrust::UntrustedAudience => "untrusted-audience",
            IdentityTrust::NoTrustedTime => "no-trusted-time",
            IdentityTrust::OutsideKeyWindow => "outside-key-window",
            IdentityTrust::DistrustedKey => "distrusted-key",
            IdentityTrust::AlgorithmNotAccepted => "algorithm-not-accepted",
            IdentityTrust::InsufficientLevel => "insufficient-level",
        }
    }

    /// Every value.
    pub const ALL: [IdentityTrust; 10] = [
        IdentityTrust::Trusted,
        IdentityTrust::InsecureDev,
        IdentityTrust::UnknownIssuer,
        IdentityTrust::UnknownKey,
        IdentityTrust::UntrustedAudience,
        IdentityTrust::NoTrustedTime,
        IdentityTrust::OutsideKeyWindow,
        IdentityTrust::DistrustedKey,
        IdentityTrust::AlgorithmNotAccepted,
        IdentityTrust::InsufficientLevel,
    ];

    /// The value [`IdentityTrust::as_str`] gives (`None` for anything else).
    pub fn parse(s: &str) -> Option<IdentityTrust> {
        IdentityTrust::ALL.into_iter().find(|t| t.as_str() == s)
    }

    /// Human explanation for reports.
    pub fn describe(self, issuer: &str) -> String {
        match self {
            IdentityTrust::Trusted => format!("issuer {issuer} and its signing key are pinned"),
            IdentityTrust::InsecureDev => format!(
                "INSECURE: accepted only because the verifier trusts the dev issuer {issuer}"
            ),
            IdentityTrust::UnknownIssuer => {
                format!("identity provider {issuer} is not in the verifier's trust store")
            }
            IdentityTrust::UnknownKey => format!(
                "the key that signed this identity token is not a known key of {issuer} \
                 (forged, or refresh the trust store's JWKS)"
            ),
            IdentityTrust::UntrustedAudience => format!(
                "this sign-in with {issuer} was issued to an application the verifier does not \
                 trust for signing (any website or app can obtain such a token from its users)"
            ),
            IdentityTrust::NoTrustedTime => format!(
                "a token from {issuer} counts only when a trusted timestamp proves the signature \
                 was made inside its key's validity window, and no trusted timestamp covers this \
                 signature yet"
            ),
            IdentityTrust::OutsideKeyWindow => format!(
                "this signature was not made inside the validity window of the {issuer} key that \
                 signed its identity token"
            ),
            IdentityTrust::DistrustedKey => format!(
                "the {issuer} key that signed this identity token is distrusted (it may have been \
                 compromised), and no trusted timestamp proves the signature came before that"
            ),
            IdentityTrust::AlgorithmNotAccepted => format!(
                "the identity token from {issuer} relies on an algorithm the verifier's algorithm \
                 policy does not accept for it"
            ),
            IdentityTrust::InsufficientLevel => format!(
                "the identity from {issuer} does not reach the assurance level, or carry the \
                 evidence, its slot requires"
            ),
        }
    }
}

/// What a verifier knows about when a signature was made, for the signing key's validity window
/// (Unix seconds).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SigningTimeEvidence {
    /// The identity token's `iat`. The key that signed the token asserts it, so it is only held
    /// against the start of the window (a token claiming to predate its own key is refused).
    pub issued_at: Option<i64>,
    /// The earliest trusted timestamp covering the signature: it proves the signature existed by
    /// then. The only evidence held against the end of a window.
    pub existed_before: Option<i64>,
}

/// How the trust store regards one identity token, and why when it is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCheck {
    pub trust: IdentityTrust,
    /// A sentence for the report when [`IdentityTrust::is_acceptable`] is false (empty
    /// otherwise), naming the bound or application at fault.
    pub reason: String,
}

impl IdentityCheck {
    fn new(trust: IdentityTrust, reason: String) -> Self {
        IdentityCheck { trust, reason }
    }

    fn plain(trust: IdentityTrust, issuer: &str) -> Self {
        let reason = if trust.is_acceptable() {
            String::new()
        } else {
            trust.describe(issuer)
        };
        IdentityCheck { trust, reason }
    }
}

/// RFC 7638 JWK thumbprint (base64url SHA-256 over the canonical required members).
pub fn jwk_thumbprint(jwk: &Jwk) -> Result<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let missing = |m: &str| SignPdfError::Oidc(format!("JWK is missing '{m}'"));
    // Members in lexicographic order, no whitespace (RFC 7638 §3.2). Values are base64url/ASCII so
    // JSON string escaping is the identity, but go through serde to be safe.
    let s = |v: &str| serde_json::to_string(v).unwrap_or_default();
    let canonical = match jwk.kty.as_str() {
        "EC" => format!(
            "{{\"crv\":{},\"kty\":\"EC\",\"x\":{},\"y\":{}}}",
            s(jwk.crv.as_deref().ok_or_else(|| missing("crv"))?),
            s(jwk.x.as_deref().ok_or_else(|| missing("x"))?),
            s(jwk.y.as_deref().ok_or_else(|| missing("y"))?),
        ),
        "RSA" => format!(
            "{{\"e\":{},\"kty\":\"RSA\",\"n\":{}}}",
            s(jwk.e.as_deref().ok_or_else(|| missing("e"))?),
            s(jwk.n.as_deref().ok_or_else(|| missing("n"))?),
        ),
        other => return Err(SignPdfError::Oidc(format!("unsupported JWK kty '{other}'"))),
    };
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

impl TrustStore {
    /// A store that trusts nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The well-known consumer providers (Google, Microsoft, Apple) **without any pinned keys**.
    /// Populate keys with [`TrustStore::add_jwks`] (e.g. `signpdf trust refresh`) before use.
    ///
    /// Google and Microsoft are trusted for SignPDF's own app registrations only. Apple has no
    /// audience (SignPDF has no registration there): add one with [`TrustStore::add_audience`].
    pub fn well_known() -> Self {
        let issuer = |issuer: &str, name: &str, jwks: &str| TrustedIssuer {
            issuer: issuer.to_string(),
            name: name.to_string(),
            jwks_uri: Some(jwks.to_string()),
            audiences: builtin_audiences(issuer),
            ..TrustedIssuer::default()
        };
        Self {
            issuers: vec![
                issuer(
                    "https://accounts.google.com",
                    "Google",
                    "https://www.googleapis.com/oauth2/v3/certs",
                ),
                issuer(
                    MICROSOFT_ISSUER_TEMPLATE,
                    "Microsoft",
                    "https://login.microsoftonline.com/common/discovery/v2.0/keys",
                ),
                issuer(
                    "https://appleid.apple.com",
                    "Apple",
                    "https://appleid.apple.com/auth/keys",
                ),
            ],
            tsa_anchors: vec![crate::crypto::b64_encode(DIGICERT_TRUSTED_ROOT_G4)],
            allow_insecure_dev_issuer: false,
            algorithm_policy: None,
            tsa_distrusted: Vec::new(),
        }
    }

    /// **Insecure** store that trusts only the bundled dev issuer, with any key.
    pub fn insecure_dev() -> Self {
        Self {
            allow_insecure_dev_issuer: true,
            ..Self::default()
        }
    }

    /// Parse a store from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        Self::from_json_bytes(json.as_bytes())
    }

    /// Parse a store from JSON bytes. Every host should load stores through this (or
    /// [`TrustStore::from_json`]) rather than deserializing directly, so that stores saved by
    /// older versions are upgraded and unreadable key windows are refused.
    pub fn from_json_bytes(json: &[u8]) -> Result<Self> {
        let mut store: Self = serde_json::from_slice(json)?;
        store.pin_builtin_audiences();
        store.validate()?;
        Ok(store)
    }

    /// The algorithm policy this store applies: its own, or the engine's built-in one.
    pub fn algorithms(&self) -> std::borrow::Cow<'_, AlgorithmPolicy> {
        match &self.algorithm_policy {
            Some(p) => std::borrow::Cow::Borrowed(p),
            None => std::borrow::Cow::Owned(AlgorithmPolicy::builtin()),
        }
    }

    /// Replace the store's algorithm policy (`None`: the engine's built-in one). The policy must
    /// be readable.
    pub fn set_algorithm_policy(&mut self, policy: Option<AlgorithmPolicy>) -> Result<()> {
        if let Some(p) = &policy {
            p.validate().map_err(SignPdfError::Oidc)?;
        }
        self.algorithm_policy = policy;
        Ok(())
    }

    /// What a sign-in with `iss` (with optional `tid`) shows about the signer, from which the
    /// verifier computes its assurance level. The store's entries decide; when several matching
    /// entries state a kind, the one that shows least wins. An issuer no entry states a kind for
    /// is an account provider when it is a well-known one ([`builtin_issuer_kind`]) and an
    /// email-code provider otherwise.
    pub fn issuer_kind(&self, iss: &str, tid: Option<&str>) -> IssuerKind {
        self.issuers
            .iter()
            .filter(|t| issuer_matches(&t.issuer, iss, tid))
            .filter_map(|t| t.kind)
            .min()
            .or_else(|| builtin_issuer_kind(iss, tid))
            .unwrap_or(IssuerKind::EmailCode)
    }

    /// Record what a sign-in with `issuer` shows ([`TrustedIssuer::kind`]); `None` returns it to
    /// the default. The issuer must be in the store.
    pub fn set_issuer_kind(&mut self, issuer: &str, kind: Option<IssuerKind>) -> Result<()> {
        let entry = self
            .entry(issuer)
            .ok_or_else(|| SignPdfError::Oidc(format!("issuer {issuer} is not in the store")))?;
        entry.kind = kind;
        Ok(())
    }

    /// Every key window in the store, and its algorithm policy, are readable. A window that is
    /// not still fails closed when checked, but a store should not get that far.
    pub fn validate(&self) -> Result<()> {
        if let Some(p) = &self.algorithm_policy {
            p.validate()
                .map_err(|e| SignPdfError::Oidc(format!("trust store: {e}")))?;
        }
        for d in &self.tsa_distrusted {
            d.validate().map_err(|e| {
                SignPdfError::Oidc(format!("trust store: distrusted timestamp authority: {e}"))
            })?;
        }
        for i in &self.issuers {
            for k in &i.keys {
                k.window.validate().map_err(|e| {
                    SignPdfError::Oidc(format!(
                        "trust store: key {} of {}: {e}",
                        key_label(k),
                        i.issuer
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Stores saved before audiences became mandatory list none for the well-known providers,
    /// which then meant "any application". Give those entries SignPDF's own registrations, so an
    /// existing store keeps working and stops accepting tokens issued to other applications.
    fn pin_builtin_audiences(&mut self) {
        for entry in self.issuers.iter_mut().filter(|i| i.audiences.is_empty()) {
            entry.audiences = builtin_audiences(&entry.issuer);
        }
    }

    /// Trust tokens that `issuer` issued to the application `client_id` (for an organization's
    /// own app registration, or a provider where SignPDF has none). Returns false when it was
    /// already trusted.
    pub fn add_audience(&mut self, issuer: &str, client_id: &str) -> bool {
        let entry = self.entry_mut(issuer);
        if entry.audiences.iter().any(|a| a == client_id) {
            return false;
        }
        entry.audiences.push(client_id.to_string());
        true
    }

    /// Serialize the store to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Find (or create) the entry for `issuer`.
    fn entry_mut(&mut self, issuer: &str) -> &mut TrustedIssuer {
        let pos = self
            .issuers
            .iter()
            .position(|i| i.issuer.trim_end_matches('/') == issuer.trim_end_matches('/'));
        match pos {
            Some(p) => &mut self.issuers[p],
            None => {
                self.issuers.push(TrustedIssuer {
                    issuer: issuer.to_string(),
                    audiences: builtin_audiences(issuer),
                    ..TrustedIssuer::default()
                });
                self.issuers.last_mut().expect("just pushed")
            }
        }
    }

    /// The entry for `issuer`, when the store has one.
    fn entry(&mut self, issuer: &str) -> Option<&mut TrustedIssuer> {
        self.issuers
            .iter_mut()
            .find(|i| i.issuer.trim_end_matches('/') == issuer.trim_end_matches('/'))
    }

    /// Pin every key of `jwks` for `issuer`, keeping previously pinned keys (key history).
    /// Returns how many keys were newly added. New keys have an open window; the windows of
    /// keys already pinned are not touched.
    pub fn add_jwks(&mut self, issuer: &str, jwks: &Jwks) -> usize {
        let entry = self.entry_mut(issuer);
        let mut added = 0;
        for key in &jwks.keys {
            if pin(entry, PinnedKey::from(sanitize_jwk(key))) {
                added += 1;
            }
        }
        added
    }

    /// Pin every key of a JWKS as an issuer publishes it, with the validity windows it states
    /// next to each key's members ([`PublishedJwks`]): like [`TrustStore::add_jwks`], and a
    /// window only ever narrows a key already pinned. The JWKS comes from the issuer itself (over
    /// TLS), which may end or distrust its own keys; `first_seen` and `last_seen` are the
    /// store's own observations and are not taken from it. Nothing changes when a window is
    /// unreadable. Returns how many keys were newly added.
    pub fn add_published_jwks(&mut self, issuer: &str, jwks: &PublishedJwks) -> Result<usize> {
        for key in &jwks.keys {
            key.window.validate().map_err(|e| {
                SignPdfError::Oidc(format!("JWKS of {issuer}: key {}: {e}", key_label(key)))
            })?;
        }
        let entry = self.entry_mut(issuer);
        let mut added = 0;
        for key in &jwks.keys {
            let published = PinnedKey {
                window: key.window.clone(),
                ..PinnedKey::from(sanitize_jwk(key))
            };
            if pin(entry, published) {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Merge another store into this one (issuers, keys, audiences, TSA anchors). Key windows
    /// only ever narrow: a key both stores pin keeps the later start and the earlier ends of the
    /// two, and an issuer either store requires trusted time for requires it. An issuer's kind
    /// only ever narrows too: when both stores state one, the one that shows less is kept. Of two
    /// algorithm policies, the higher version is kept (each edition replaces the one before); on
    /// a tie, this store's. The insecure flag is only ever turned on explicitly, never by
    /// merging.
    pub fn merge(&mut self, other: &TrustStore) {
        for iss in &other.issuers {
            let entry = self.entry_mut(&iss.issuer);
            for key in &iss.keys {
                pin(entry, key.clone());
            }
            if entry.name.is_empty() {
                entry.name = iss.name.clone();
            }
            if entry.jwks_uri.is_none() {
                entry.jwks_uri = iss.jwks_uri.clone();
            }
            for aud in &iss.audiences {
                if !entry.audiences.contains(aud) {
                    entry.audiences.push(aud.clone());
                }
            }
            entry.requires_trusted_time |= iss.requires_trusted_time;
            entry.kind = match (entry.kind, iss.kind) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        if let Some(theirs) = &other.algorithm_policy {
            let newer = match &self.algorithm_policy {
                Some(ours) => theirs.version > ours.version,
                None => true,
            };
            if newer {
                self.algorithm_policy = Some(theirs.clone());
            }
        }
        for a in &other.tsa_anchors {
            if !self.tsa_anchors.contains(a) {
                self.tsa_anchors.push(a.clone());
            }
        }
        for d in &other.tsa_distrusted {
            self.narrow_tsa_distrust(d.clone());
        }
    }

    /// Add `entry`, or move an existing entry for the same certificate to the earlier of the two
    /// times (a distrust only ever widens; an unreadable time is kept, it fails closed).
    fn narrow_tsa_distrust(&mut self, entry: TsaDistrust) {
        match self
            .tsa_distrusted
            .iter_mut()
            .find(|d| d.matches(&entry.cert_sha256))
        {
            Some(d) => {
                let keep = pick(
                    &Some(d.distrusted_after.clone()),
                    &Some(entry.distrusted_after.clone()),
                    |a, b| a <= b,
                );
                if let Some(t) = keep {
                    d.distrusted_after = t;
                }
                if d.name.is_none() {
                    d.name = entry.name;
                }
            }
            None => self.tsa_distrusted.push(TsaDistrust {
                cert_sha256: entry.cert_sha256.to_ascii_lowercase(),
                ..entry
            }),
        }
    }

    /// Distrust the timestamp authority certificate whose SHA-256 is `cert_sha256` (hex) from
    /// `distrusted_after` (RFC 3339). An entry already there only moves earlier.
    pub fn distrust_tsa(
        &mut self,
        cert_sha256: &str,
        distrusted_after: &str,
        name: Option<String>,
    ) -> Result<()> {
        let entry = TsaDistrust {
            cert_sha256: cert_sha256.to_ascii_lowercase(),
            distrusted_after: distrusted_after.to_string(),
            name,
        };
        entry.validate().map_err(SignPdfError::Oidc)?;
        self.narrow_tsa_distrust(entry);
        Ok(())
    }

    /// The earliest time (Unix seconds) from which the store distrusts timestamps whose chain
    /// holds the certificate `der`, if it does. An unreadable time fails closed (`i64::MIN`).
    pub fn tsa_distrusted_from(&self, der: &[u8]) -> Option<i64> {
        let hash = cert_sha256_hex(der);
        self.tsa_distrusted
            .iter()
            .filter(|d| d.matches(&hash))
            .map(|d| unix_from_rfc3339(&d.distrusted_after).unwrap_or(i64::MIN))
            .min()
    }

    /// Check who signed the timestamp token `token_der` against this store: the authority's
    /// signature and chain to a TSA anchor ([`crate::timestamp::verify_tsa_signature`]), judged
    /// at `gen_time_unix` (the token's `genTime`), and then the distrusted authorities: a chain
    /// certificate distrusted at or before `genTime` makes the timestamp untrusted
    /// ([`crate::timestamp::TsaSignature::distrusted_after`] says from when).
    pub fn verify_tsa(
        &self,
        token_der: &[u8],
        gen_time_unix: i64,
    ) -> crate::timestamp::TsaSignature {
        let mut tsa = crate::timestamp::verify_tsa_signature(
            token_der,
            &self.tsa_anchor_ders(),
            gen_time_unix,
        );
        if !tsa.trusted || self.tsa_distrusted.is_empty() {
            return tsa;
        }
        let hit = tsa
            .chain
            .iter()
            .filter_map(|c| self.tsa_distrusted_from(c).map(|t| (t, c)))
            .filter(|(t, _)| gen_time_unix >= *t)
            .min_by_key(|(t, _)| *t);
        if let Some((from, cert)) = hit {
            let subject = crate::timestamp::certificate_common_name(cert)
                .unwrap_or_else(|| cert_sha256_hex(cert));
            let from = rfc3339_from_unix(from);
            tsa.detail = format!(
                "the trust store distrusts the timestamp authority certificate '{subject}' from \
                 {from} (its key may have been compromised), and this timestamp is dated {}: it \
                 proves nothing",
                rfc3339_from_unix(gen_time_unix)
            );
            tsa.trusted = false;
            tsa.chain.clear();
            tsa.algorithms.clear();
            tsa.distrusted_after = Some(from);
        }
        tsa
    }

    /// Add a TSA trust anchor certificate (DER).
    pub fn add_tsa_anchor(&mut self, cert_der: &[u8]) {
        let b64 = crate::crypto::b64_encode(cert_der);
        if !self.tsa_anchors.contains(&b64) {
            self.tsa_anchors.push(b64);
        }
    }

    /// The decoded TSA anchor certificates (invalid entries are skipped).
    pub fn tsa_anchor_ders(&self) -> Vec<Vec<u8>> {
        self.tsa_anchors
            .iter()
            .filter_map(|b| crate::crypto::b64_decode(b).ok())
            .collect()
    }

    /// Replace the validity window of `issuer`'s pinned key `key` (its RFC 7638 thumbprint, or a
    /// `kid` only that key has). Unlike [`TrustStore::merge`] this may widen a window, so it is
    /// for an operator correcting the store.
    pub fn set_key_window(&mut self, issuer: &str, key: &str, window: KeyWindow) -> Result<()> {
        window.validate().map_err(SignPdfError::Oidc)?;
        let entry = self
            .entry(issuer)
            .ok_or_else(|| SignPdfError::Oidc(format!("issuer {issuer} is not in the store")))?;
        let by_thumbprint: Vec<usize> = (0..entry.keys.len())
            .filter(|&i| jwk_thumbprint(&entry.keys[i]).is_ok_and(|tp| tp == key))
            .collect();
        let found = if by_thumbprint.is_empty() {
            (0..entry.keys.len())
                .filter(|&i| entry.keys[i].kid.as_deref() == Some(key))
                .collect()
        } else {
            by_thumbprint
        };
        match found.as_slice() {
            [i] => {
                entry.keys[*i].window = window;
                Ok(())
            }
            [] => Err(SignPdfError::Oidc(format!(
                "{issuer} has no pinned key with thumbprint or kid '{key}'"
            ))),
            _ => Err(SignPdfError::Oidc(format!(
                "several keys of {issuer} have kid '{key}': name it by its thumbprint"
            ))),
        }
    }

    /// Require (or stop requiring) trusted time for `issuer`'s tokens
    /// ([`TrustedIssuer::requires_trusted_time`]).
    pub fn set_requires_trusted_time(&mut self, issuer: &str, on: bool) -> Result<()> {
        let entry = self
            .entry(issuer)
            .ok_or_else(|| SignPdfError::Oidc(format!("issuer {issuer} is not in the store")))?;
        entry.requires_trusted_time = on;
        Ok(())
    }

    /// Decide how much to trust a token from `iss` (with optional `tid`) for `audience`, signed by
    /// `jwk`, with no time evidence. The token's signature against `jwk` must already have been
    /// verified. A key with an end, or one of an issuer that requires trusted time, gives
    /// [`IdentityTrust::NoTrustedTime`]: use [`TrustStore::check_identity_at`] with the evidence.
    pub fn check_identity(
        &self,
        iss: &str,
        tid: Option<&str>,
        audience: &str,
        jwk: &Jwk,
    ) -> IdentityTrust {
        self.check_identity_at(iss, tid, audience, jwk, SigningTimeEvidence::default())
            .trust
    }

    /// Decide how much to trust a token from `iss` (with optional `tid`) for `audience`, signed by
    /// `jwk`, given what is known about when the signature was made. The token's signature
    /// against `jwk` must already have been verified.
    ///
    /// The key must be pinned for the issuer, the audience trusted, and the signature inside the
    /// key's validity window: every entry of the issuer that pins the key contributes its window
    /// (the narrowest wins), and any of them requiring trusted time requires it.
    pub fn check_identity_at(
        &self,
        iss: &str,
        tid: Option<&str>,
        audience: &str,
        jwk: &Jwk,
        time: SigningTimeEvidence,
    ) -> IdentityCheck {
        let dev = || self.allow_insecure_dev_issuer && issuer_matches(DEV_ISSUER, iss, None);
        let matching: Vec<&TrustedIssuer> = self
            .issuers
            .iter()
            .filter(|t| issuer_matches(&t.issuer, iss, tid))
            .collect();
        if matching.is_empty() {
            let trust = if dev() {
                IdentityTrust::InsecureDev
            } else {
                IdentityTrust::UnknownIssuer
            };
            return IdentityCheck::plain(trust, iss);
        }
        let Ok(tp) = jwk_thumbprint(jwk) else {
            return IdentityCheck::plain(IdentityTrust::UnknownKey, iss);
        };
        let mut audience_ok = false;
        let mut pinned = false;
        let mut window: Option<KeyWindow> = None;
        let mut needs_time = false;
        for t in &matching {
            needs_time |= t.requires_trusted_time;
            // Only applications the verifier trusts for this issuer count (an empty list trusts
            // none): the issuer signs tokens for every app its users sign in to.
            let aud = t.audiences.iter().any(|a| a == audience);
            audience_ok |= aud;
            // A key's window binds wherever it is pinned, whatever the audience.
            for k in t
                .keys
                .iter()
                .filter(|k| jwk_thumbprint(k).is_ok_and(|x| x == tp))
            {
                pinned |= aud;
                window = Some(match window {
                    Some(w) => w.narrowed(&k.window),
                    None => k.window.clone(),
                });
            }
        }
        if !pinned {
            let trust = if dev() {
                IdentityTrust::InsecureDev
            } else if !audience_ok {
                IdentityTrust::UntrustedAudience
            } else {
                IdentityTrust::UnknownKey
            };
            let mut check = IdentityCheck::plain(trust, iss);
            if trust == IdentityTrust::UntrustedAudience {
                check.reason = format!("{}: application '{audience}'", check.reason);
            }
            return check;
        }
        check_window(iss, &window.unwrap_or_default(), needs_time, time)
    }
}

/// Judge a pinned key's window against the time evidence.
fn check_window(
    iss: &str,
    window: &KeyWindow,
    needs_time: bool,
    time: SigningTimeEvidence,
) -> IdentityCheck {
    use IdentityTrust::{DistrustedKey, NoTrustedTime, OutsideKeyWindow, Trusted};
    // An unreadable bound fails closed.
    let bound = |v: &Option<String>| -> std::result::Result<Option<i64>, IdentityCheck> {
        match v {
            None => Ok(None),
            Some(s) => unix_from_rfc3339(s).map(Some).ok_or_else(|| {
                IdentityCheck::new(
                    OutsideKeyWindow,
                    format!(
                        "the trust store's validity window for this {iss} key is unreadable \
                         ('{s}')"
                    ),
                )
            }),
        }
    };
    let (not_before, not_after, distrusted_after) = match (
        bound(&window.not_before),
        bound(&window.not_after),
        bound(&window.distrusted_after),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return e,
    };
    let at = rfc3339_from_unix;

    // The start: neither the token's own issue time nor trusted time may precede it.
    if let Some(nb) = not_before {
        if let Some(iat) = time
            .issued_at
            .filter(|&t| t + WINDOW_START_LEEWAY_SECS < nb)
        {
            return IdentityCheck::new(
                OutsideKeyWindow,
                format!(
                    "the identity token says it was issued at {}, before the {iss} key that \
                     signed it was in use (from {})",
                    at(iat),
                    at(nb)
                ),
            );
        }
        if let Some(t) = time
            .existed_before
            .filter(|&t| t + WINDOW_START_LEEWAY_SECS < nb)
        {
            return IdentityCheck::new(
                OutsideKeyWindow,
                format!(
                    "a trusted timestamp shows the signature existed at {}, before the {iss} key \
                     that signed its identity token was in use (from {})",
                    at(t),
                    at(nb)
                ),
            );
        }
    }

    // The end: only trusted time can show the signature came before it.
    let end = match (not_after, distrusted_after) {
        (Some(a), Some(d)) => Some(a.min(d)),
        (a, d) => a.or(d),
    };
    if !needs_time && end.is_none() {
        return IdentityCheck::new(Trusted, String::new());
    }
    let Some(t) = time.existed_before else {
        let reason = match end {
            Some(e) => format!(
                "the {iss} key that signed this identity token vouches only for signatures a \
                 trusted timestamp shows were made by {}, and no trusted timestamp covers this \
                 signature yet",
                at(e)
            ),
            None => NoTrustedTime.describe(iss),
        };
        return IdentityCheck::new(NoTrustedTime, reason);
    };
    if let Some(d) = distrusted_after.filter(|&d| t > d) {
        return IdentityCheck::new(
            DistrustedKey,
            format!(
                "the {iss} key that signed this identity token is distrusted from {} (it may have \
                 been compromised), and the earliest trusted timestamp covering the signature is \
                 from {}: nothing shows it was signed before",
                at(d),
                at(t)
            ),
        );
    }
    if let Some(a) = not_after.filter(|&a| t > a) {
        return IdentityCheck::new(
            OutsideKeyWindow,
            format!(
                "{iss} stopped signing with the key that signed this identity token at {}, and \
                 the earliest trusted timestamp covering the signature is from {}: nothing shows \
                 it was signed while the key was in use",
                at(a),
                at(t)
            ),
        );
    }
    IdentityCheck::new(Trusted, String::new())
}

/// Pin `key` in `entry`: add it when new, otherwise narrow the pinned key's window to both and
/// widen what the store saw of it. Returns whether it was new.
fn pin(entry: &mut TrustedIssuer, key: PinnedKey) -> bool {
    let Ok(tp) = jwk_thumbprint(&key) else {
        return false;
    };
    match entry
        .keys
        .iter_mut()
        .find(|k| jwk_thumbprint(k).is_ok_and(|x| x == tp))
    {
        Some(k) => {
            k.window = k.window.narrowed(&key.window);
            k.first_seen = pick(&k.first_seen, &key.first_seen, |a, b| a <= b);
            k.last_seen = pick(&k.last_seen, &key.last_seen, |a, b| a >= b);
            false
        }
        None => {
            entry.keys.push(key);
            true
        }
    }
}

/// How messages name a key: its `kid`, or its thumbprint.
fn key_label(k: &PinnedKey) -> String {
    k.kid
        .clone()
        .or_else(|| jwk_thumbprint(k).ok())
        .unwrap_or_else(|| "?".into())
}

/// Keep only the public members the engine understands (drops private members if a careless
/// caller passed a private JWK).
fn sanitize_jwk(k: &Jwk) -> Jwk {
    Jwk {
        kty: k.kty.clone(),
        kid: k.kid.clone(),
        alg: k.alg.clone(),
        n: k.n.clone(),
        e: k.e.clone(),
        crv: k.crv.clone(),
        x: k.x.clone(),
        y: k.y.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::testing::TestIssuer;

    #[test]
    fn rfc7638_example_thumbprint() {
        // RFC 7638 §3.1 example key.
        let jwk = Jwk {
            kty: "RSA".into(),
            kid: Some("2011-04-29".into()),
            alg: Some("RS256".into()),
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".into()),
            e: Some("AQAB".into()),
            crv: None,
            x: None,
            y: None,
        };
        assert_eq!(
            jwk_thumbprint(&jwk).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn pinned_key_is_trusted_and_foreign_key_is_not() {
        let real = TestIssuer::es256();
        let forger = TestIssuer::es256();
        let mut store = TrustStore::empty();
        store.add_jwks("https://idp.test", &real.jwks());
        store.add_audience("https://idp.test", "aud");

        assert_eq!(
            store.check_identity("https://idp.test", None, "aud", &real.jwk()),
            IdentityTrust::Trusted
        );
        assert_eq!(
            store.check_identity("https://idp.test", None, "aud", &forger.jwk()),
            IdentityTrust::UnknownKey
        );
        assert_eq!(
            store.check_identity("https://other.test", None, "aud", &real.jwk()),
            IdentityTrust::UnknownIssuer
        );
    }

    #[test]
    fn dev_issuer_needs_explicit_opt_in() {
        let dev = TestIssuer::es256();
        assert_eq!(
            TrustStore::empty().check_identity(DEV_ISSUER, None, "a", &dev.jwk()),
            IdentityTrust::UnknownIssuer
        );
        assert_eq!(
            TrustStore::insecure_dev().check_identity(DEV_ISSUER, None, "a", &dev.jwk()),
            IdentityTrust::InsecureDev
        );
        // Merging never turns the insecure flag on.
        let mut s = TrustStore::empty();
        s.merge(&TrustStore::insecure_dev());
        assert!(!s.allow_insecure_dev_issuer);
    }

    #[test]
    fn key_history_survives_rotation_and_audiences_restrict() {
        let k1 = TestIssuer::es256();
        let k2 = TestIssuer::es256();
        let mut store = TrustStore::empty();
        assert_eq!(store.add_jwks("https://idp.test", &k1.jwks()), 1);
        assert_eq!(store.add_jwks("https://idp.test", &k1.jwks()), 0);
        assert_eq!(store.add_jwks("https://idp.test/", &k2.jwks()), 1);
        assert_eq!(store.issuers.len(), 1);
        // Pinned keys alone trust no application: the issuer signs tokens for all of them.
        assert_eq!(
            store.check_identity("https://idp.test", None, "x", &k1.jwk()),
            IdentityTrust::UntrustedAudience
        );

        assert!(store.add_audience("https://idp.test/", "my-client"));
        assert!(!store.add_audience("https://idp.test", "my-client"));
        assert_eq!(store.issuers[0].audiences, ["my-client"]);
        assert_eq!(
            store.check_identity("https://idp.test", None, "other", &k1.jwk()),
            IdentityTrust::UntrustedAudience
        );
        assert_eq!(
            store.check_identity("https://idp.test", None, "my-client", &k1.jwk()),
            IdentityTrust::Trusted
        );
    }

    #[test]
    fn microsoft_template_entry_matches_concrete_tenants() {
        let k = TestIssuer::rs256();
        let mut store = TrustStore::well_known();
        store.add_jwks(MICROSOFT_ISSUER_TEMPLATE, &k.jwks());
        let tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        let iss = format!("https://login.microsoftonline.com/{tid}/v2.0");
        assert_eq!(
            store.check_identity(&iss, Some(tid), SIGNPDF_MICROSOFT_CLIENT_ID, &k.jwk()),
            IdentityTrust::Trusted
        );
        // The same Microsoft key over a token issued to any other application proves nothing.
        assert_eq!(
            store.check_identity(&iss, Some(tid), "some-other-app", &k.jwk()),
            IdentityTrust::UntrustedAudience
        );
        assert_eq!(
            store.issuers.len(),
            3,
            "no duplicate entry for the template"
        );
    }

    #[test]
    fn well_known_providers_are_trusted_for_signpdf_s_own_registrations_only() {
        let store = TrustStore::well_known();
        let audiences = |name: &str| {
            store
                .issuers
                .iter()
                .find(|i| i.name == name)
                .unwrap()
                .audiences
                .clone()
        };
        assert_eq!(audiences("Google"), [SIGNPDF_GOOGLE_CLIENT_ID]);
        assert_eq!(audiences("Microsoft"), [SIGNPDF_MICROSOFT_CLIENT_ID]);
        assert!(
            audiences("Apple").is_empty(),
            "no SignPDF registration with Apple"
        );

        let k = TestIssuer::rs256();
        let mut store = store;
        store.add_jwks("https://accounts.google.com", &k.jwks());
        let google =
            |aud: &str| store.check_identity("https://accounts.google.com", None, aud, &k.jwk());
        assert_eq!(google(SIGNPDF_GOOGLE_CLIENT_ID), IdentityTrust::Trusted);
        assert_eq!(
            google("1234-evil.apps.googleusercontent.com"),
            IdentityTrust::UntrustedAudience
        );
    }

    #[test]
    fn stores_saved_before_audiences_were_mandatory_are_upgraded() {
        // What `trust.json` looked like: no audiences anywhere, which meant "any application".
        let old = r#"{
            "issuers": [
                {"issuer": "https://accounts.google.com", "name": "Google", "keys": []},
                {"issuer": "https://login.microsoftonline.com/{tenantid}/v2.0", "keys": [], "audiences": []},
                {"issuer": "https://appleid.apple.com", "keys": []},
                {"issuer": "https://id.acme.example", "keys": [], "audiences": ["acme-signing"]}
            ]
        }"#;
        let store = TrustStore::from_json(old).unwrap();
        let audiences: Vec<&[String]> = store.issuers.iter().map(|i| &i.audiences[..]).collect();
        assert_eq!(audiences[0], [SIGNPDF_GOOGLE_CLIENT_ID]);
        assert_eq!(audiences[1], [SIGNPDF_MICROSOFT_CLIENT_ID]);
        assert!(audiences[2].is_empty());
        assert_eq!(audiences[3], ["acme-signing"], "an explicit choice is kept");
        assert_eq!(TrustStore::from_json_bytes(old.as_bytes()).unwrap(), store);
    }

    #[test]
    fn the_dev_opt_in_accepts_any_application() {
        // The opt-in is insecure by definition; it must not start failing on the audience when a
        // store also happens to list the dev issuer.
        let dev = TestIssuer::es256();
        let mut store = TrustStore::insecure_dev();
        store.add_jwks(DEV_ISSUER, &TestIssuer::es256().jwks());
        assert_eq!(
            store.check_identity(DEV_ISSUER, None, "anything", &dev.jwk()),
            IdentityTrust::InsecureDev
        );
    }

    #[test]
    fn json_roundtrip() {
        let mut s = TrustStore::well_known();
        s.add_jwks("https://idp.test", &TestIssuer::es256().jwks());
        let back = TrustStore::from_json(&s.to_json().unwrap()).unwrap();
        assert_eq!(back, s);
    }

    // --- key validity windows and trusted time ----------------------------------------------

    const IDP: &str = "https://id.example.test";
    const AUD: &str = "signing-app";
    /// 2027-01-01T00:00:00Z
    const T0: i64 = 1_798_761_600;

    fn at(t: i64) -> String {
        rfc3339_from_unix(t)
    }

    /// A store pinning `key` for [`IDP`] and [`AUD`] with `window`.
    fn windowed(key: &TestIssuer, window: KeyWindow, requires_trusted_time: bool) -> TrustStore {
        let mut store = TrustStore::empty();
        store.add_jwks(IDP, &key.jwks());
        store.add_audience(IDP, AUD);
        store.issuers[0].keys[0].window = window;
        store.issuers[0].requires_trusted_time = requires_trusted_time;
        store
    }

    fn evidence(issued_at: Option<i64>, existed_before: Option<i64>) -> SigningTimeEvidence {
        SigningTimeEvidence {
            issued_at,
            existed_before,
        }
    }

    fn check(store: &TrustStore, key: &TestIssuer, time: SigningTimeEvidence) -> IdentityCheck {
        store.check_identity_at(IDP, None, AUD, &key.jwk(), time)
    }

    #[test]
    fn a_key_without_a_window_needs_no_trusted_time() {
        let k = TestIssuer::es256();
        let store = windowed(&k, KeyWindow::default(), false);
        for time in [evidence(None, None), evidence(Some(T0), Some(T0 + 60))] {
            assert_eq!(check(&store, &k, time).trust, IdentityTrust::Trusted);
        }
        assert_eq!(
            store.check_identity(IDP, None, AUD, &k.jwk()),
            IdentityTrust::Trusted
        );
    }

    #[test]
    fn an_issuer_that_requires_trusted_time_counts_only_with_a_timestamp() {
        let k = TestIssuer::es256();
        let store = windowed(&k, KeyWindow::default(), true);
        let none = check(&store, &k, evidence(Some(T0), None));
        assert_eq!(none.trust, IdentityTrust::NoTrustedTime);
        assert!(!none.trust.is_acceptable());
        assert!(
            none.reason.contains("no trusted timestamp"),
            "{}",
            none.reason
        );
        // The token's own issue time proves nothing: its key wrote it.
        assert_eq!(
            store.check_identity(IDP, None, AUD, &k.jwk()),
            IdentityTrust::NoTrustedTime
        );
        let stamped = check(&store, &k, evidence(Some(T0), Some(T0 + 3 * 86_400)));
        assert_eq!(stamped.trust, IdentityTrust::Trusted);
        assert!(stamped.reason.is_empty());
        // The rule is the issuer's, whatever key it signs with.
        let mut store = store;
        let k2 = TestIssuer::es256();
        store.add_jwks(IDP, &k2.jwks());
        assert_eq!(
            check(&store, &k2, evidence(Some(T0), None)).trust,
            IdentityTrust::NoTrustedTime
        );
    }

    #[test]
    fn the_end_of_a_window_is_judged_against_trusted_time_only() {
        let k = TestIssuer::es256();
        let window = KeyWindow {
            not_after: Some(at(T0)),
            ..Default::default()
        };
        let store = windowed(&k, window, false);
        let trust = |time| check(&store, &k, time).trust;
        assert_eq!(
            trust(evidence(None, Some(T0 - 600))),
            IdentityTrust::Trusted
        );
        assert_eq!(trust(evidence(None, Some(T0))), IdentityTrust::Trusted);
        // No leeway at the end: the issuer builds its margin into `not_after`.
        assert_eq!(
            trust(evidence(None, Some(T0 + 1))),
            IdentityTrust::OutsideKeyWindow
        );
        // A key with an end needs trusted time even when its issuer does not ask for it, and a
        // token claiming an early `iat` is no such evidence.
        assert_eq!(
            trust(evidence(Some(T0 - 86_400), None)),
            IdentityTrust::NoTrustedTime
        );
        let late = check(&store, &k, evidence(Some(T0 - 60), Some(T0 + 3600)));
        assert!(
            late.reason.contains(&at(T0)) && late.reason.contains(&at(T0 + 3600)),
            "{}",
            late.reason
        );
        let waiting = check(&store, &k, evidence(None, None));
        assert!(waiting.reason.contains(&at(T0)), "{}", waiting.reason);
    }

    #[test]
    fn a_distrusted_key_counts_only_with_a_timestamp_before_the_cut_off() {
        let k = TestIssuer::es256();
        let window = KeyWindow {
            not_after: Some(at(T0 + 86_400)),
            distrusted_after: Some(at(T0)),
            ..Default::default()
        };
        let store = windowed(&k, window, true);
        assert_eq!(
            check(&store, &k, evidence(None, Some(T0 - 1))).trust,
            IdentityTrust::Trusted
        );
        let after = check(&store, &k, evidence(None, Some(T0 + 60)));
        assert_eq!(after.trust, IdentityTrust::DistrustedKey);
        assert!(after.reason.contains("compromised"), "{}", after.reason);
        // Past both ends, the compromise is what the report names.
        assert_eq!(
            check(&store, &k, evidence(None, Some(T0 + 2 * 86_400))).trust,
            IdentityTrust::DistrustedKey
        );
        // A planned cut-off still in the future can be met by a timestamp added in time.
        let waiting = check(&store, &k, evidence(Some(T0 - 60), None));
        assert_eq!(waiting.trust, IdentityTrust::NoTrustedTime);
        assert!(waiting.reason.contains(&at(T0)), "{}", waiting.reason);
    }

    #[test]
    fn nothing_may_predate_the_start_of_a_window() {
        let k = TestIssuer::es256();
        let window = KeyWindow {
            not_before: Some(at(T0)),
            ..Default::default()
        };
        let store = windowed(&k, window, false);
        let trust = |time| check(&store, &k, time).trust;
        // The start needs no trusted time of its own...
        assert_eq!(trust(evidence(Some(T0 + 60), None)), IdentityTrust::Trusted);
        // ...within a few minutes of clock skew...
        assert_eq!(
            trust(evidence(Some(T0 - 240), None)),
            IdentityTrust::Trusted
        );
        // ...but a token, or a timestamp, from before the key was in use is refused.
        assert_eq!(
            trust(evidence(Some(T0 - 3600), None)),
            IdentityTrust::OutsideKeyWindow
        );
        assert_eq!(
            trust(evidence(Some(T0), Some(T0 - 3600))),
            IdentityTrust::OutsideKeyWindow
        );
    }

    #[test]
    fn an_unreadable_window_fails_closed_and_is_refused_on_load() {
        let k = TestIssuer::es256();
        let window = KeyWindow {
            distrusted_after: Some("last Tuesday".into()),
            ..Default::default()
        };
        let store = windowed(&k, window.clone(), false);
        let c = check(&store, &k, evidence(Some(T0), Some(T0)));
        assert_eq!(c.trust, IdentityTrust::OutsideKeyWindow);
        assert!(c.reason.contains("unreadable"), "{}", c.reason);
        let json = store.to_json().unwrap();
        let err = TrustStore::from_json(&json).unwrap_err().to_string();
        assert!(err.contains("distrusted_after"), "{err}");
        assert!(window.validate().is_err());
        assert!(TrustStore::empty()
            .set_key_window(IDP, "x", window)
            .is_err());
    }

    #[test]
    fn the_narrowest_window_binds_wherever_the_key_is_pinned() {
        // The Microsoft template and a tenant's own entry both match a tenant's token.
        let k = TestIssuer::rs256();
        let tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        let iss = format!("https://login.microsoftonline.com/{tid}/v2.0");
        let mut store = TrustStore::well_known();
        store.add_jwks(MICROSOFT_ISSUER_TEMPLATE, &k.jwks());
        // The tenant's entry trusts no application, yet its distrust of the key still binds.
        store.add_jwks(&iss, &k.jwks());
        store.issuers[3].audiences.clear();
        store.issuers[3].keys[0].window.distrusted_after = Some(at(T0));
        let trust = |existed_before| {
            store
                .check_identity_at(
                    &iss,
                    Some(tid),
                    SIGNPDF_MICROSOFT_CLIENT_ID,
                    &k.jwk(),
                    evidence(None, existed_before),
                )
                .trust
        };
        assert_eq!(trust(Some(T0 - 1)), IdentityTrust::Trusted);
        assert_eq!(trust(Some(T0 + 1)), IdentityTrust::DistrustedKey);
        assert_eq!(trust(None), IdentityTrust::NoTrustedTime);
    }

    #[test]
    fn merging_narrows_windows_and_never_widens_them() {
        let k = TestIssuer::es256();
        let mut mine = windowed(
            &k,
            KeyWindow {
                not_before: Some(at(T0)),
                not_after: Some(at(T0 + 1000)),
                distrusted_after: None,
            },
            false,
        );
        mine.issuers[0].keys[0].first_seen = Some(at(T0 + 10));
        mine.issuers[0].keys[0].last_seen = Some(at(T0 + 20));
        let mut theirs = windowed(
            &k,
            KeyWindow {
                not_before: Some(at(T0 - 500)),
                not_after: Some(at(T0 + 900)),
                distrusted_after: Some(at(T0 + 800)),
            },
            true,
        );
        theirs.issuers[0].keys[0].first_seen = Some(at(T0));
        theirs.issuers[0].keys[0].last_seen = Some(at(T0 + 15));
        mine.merge(&theirs);
        let key = &mine.issuers[0].keys[0];
        assert_eq!(
            key.window,
            KeyWindow {
                not_before: Some(at(T0)),
                not_after: Some(at(T0 + 900)),
                distrusted_after: Some(at(T0 + 800)),
            }
        );
        assert_eq!(key.first_seen, Some(at(T0)));
        assert_eq!(key.last_seen, Some(at(T0 + 20)));
        assert!(mine.issuers[0].requires_trusted_time);
        assert_eq!(mine.issuers[0].keys.len(), 1);

        // Merging a store without windows (or re-adding the JWKS) leaves them as they are.
        let before = mine.clone();
        mine.merge(&windowed(&k, KeyWindow::default(), false));
        assert_eq!(mine.add_jwks(IDP, &k.jwks()), 0);
        assert_eq!(mine, before);

        // A key only the other store pins comes with its window.
        let k2 = TestIssuer::es256();
        let mut other = windowed(&k2, KeyWindow::default(), false);
        other.issuers[0].keys[0].window.not_after = Some(at(T0));
        mine.merge(&other);
        assert_eq!(mine.issuers[0].keys[1].window.not_after, Some(at(T0)));
    }

    #[test]
    fn an_operator_can_set_a_key_window_and_the_trusted_time_rule() {
        let k1 = TestIssuer::es256();
        let k2 = TestIssuer::es256();
        let mut store = windowed(&k1, KeyWindow::default(), false);
        store.add_jwks(IDP, &k2.jwks());
        let tp2 = jwk_thumbprint(&k2.jwk()).unwrap();
        let retire = KeyWindow {
            not_after: Some(at(T0)),
            ..Default::default()
        };
        store.set_key_window(IDP, &tp2, retire.clone()).unwrap();
        assert_eq!(store.issuers[0].keys[1].window, retire);
        assert!(store.issuers[0].keys[0].window.is_open());
        // Both test keys share a kid, so the kid alone names neither.
        let err = store
            .set_key_window(IDP, &k1.kid(), retire.clone())
            .unwrap_err()
            .to_string();
        assert!(err.contains("thumbprint"), "{err}");
        assert!(store.set_key_window(IDP, "nope", retire.clone()).is_err());
        assert!(store
            .set_key_window("https://other.test", &tp2, retire)
            .is_err());
        // Unlike a merge, the operator may widen a window again.
        store
            .set_key_window(IDP, &tp2, KeyWindow::default())
            .unwrap();
        assert!(store.issuers[0].keys[1].window.is_open());

        store.set_requires_trusted_time(IDP, true).unwrap();
        assert!(store.issuers[0].requires_trusted_time);
        store
            .set_requires_trusted_time(&format!("{IDP}/"), false)
            .unwrap();
        assert!(!store.issuers[0].requires_trusted_time);
        assert!(store
            .set_requires_trusted_time("https://other.test", true)
            .is_err());
    }

    #[test]
    fn windows_sit_next_to_the_jwk_members_and_a_store_without_them_is_unchanged() {
        let k = TestIssuer::es256();
        let plain = windowed(&k, KeyWindow::default(), false);
        let json: serde_json::Value = serde_json::from_str(&plain.to_json().unwrap()).unwrap();
        // Exactly the JWK, as before windows existed, down to the member order: hosts that hash
        // a store's JSON to version it see no change.
        assert_eq!(
            json["issuers"][0]["keys"][0],
            serde_json::to_value(k.jwk()).unwrap()
        );
        assert_eq!(
            serde_json::to_string_pretty(&plain.issuers[0].keys[0]).unwrap(),
            serde_json::to_string_pretty(&k.jwk()).unwrap()
        );
        assert!(json["issuers"][0].get("requires_trusted_time").is_none());

        let mut store = windowed(
            &k,
            KeyWindow {
                not_before: Some(at(T0)),
                not_after: Some(at(T0 + 60)),
                distrusted_after: Some(at(T0 + 30)),
            },
            true,
        );
        store.issuers[0].keys[0].first_seen = Some(at(T0 + 1));
        let text = store.to_json().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let key = &json["issuers"][0]["keys"][0];
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["x"], k.jwk().x.unwrap());
        assert_eq!(key["not_before"], at(T0));
        assert_eq!(key["not_after"], at(T0 + 60));
        assert_eq!(key["distrusted_after"], at(T0 + 30));
        assert_eq!(key["first_seen"], at(T0 + 1));
        assert_eq!(json["issuers"][0]["requires_trusted_time"], true);
        assert_eq!(TrustStore::from_json(&text).unwrap(), store);

        // What a published list looks like, members in any order, unknown members ignored.
        let published = format!(
            r#"{{"issuers": [{{"issuer": "{IDP}", "requires_trusted_time": true,
                "audiences": ["{AUD}"],
                "keys": [{{"not_after": "{}", "use": "sig", "kty": "EC", "crv": "P-256",
                          "x": "{}", "y": "{}", "kid": "k1"}}]}}]}}"#,
            at(T0),
            k.jwk().x.unwrap(),
            k.jwk().y.unwrap()
        );
        let store = TrustStore::from_json(&published).unwrap();
        assert_eq!(store.issuers[0].keys[0].window.not_after, Some(at(T0)));
        assert_eq!(
            check(&store, &k, evidence(None, Some(T0 + 1))).trust,
            IdentityTrust::OutsideKeyWindow
        );
    }

    #[test]
    fn a_published_jwks_brings_its_windows_and_only_narrows() {
        let k1 = TestIssuer::es256();
        let k2 = TestIssuer::es256();
        let mut store = windowed(&k1, KeyWindow::default(), false);
        let jwks = |k1_end: &str| -> PublishedJwks {
            serde_json::from_value(serde_json::json!({"keys": [
                {"kty": "EC", "crv": "P-256", "x": k1.jwk().x, "y": k1.jwk().y, "use": "sig",
                 "not_after": k1_end, "first_seen": "1999-01-01T00:00:00Z"},
                {"kty": "EC", "crv": "P-256", "x": k2.jwk().x, "y": k2.jwk().y,
                 "not_before": at(T0)},
            ]}))
            .unwrap()
        };
        assert_eq!(
            store.add_published_jwks(IDP, &jwks(&at(T0 + 600))).unwrap(),
            1
        );
        let keys = &store.issuers[0].keys;
        assert_eq!(keys[0].window.not_after, Some(at(T0 + 600)));
        assert_eq!(keys[0].first_seen, None, "the store's own observation");
        assert_eq!(keys[1].window.not_before, Some(at(T0)));
        // A later JWKS cannot reopen the window.
        store
            .add_published_jwks(IDP, &jwks(&at(T0 + 86_400)))
            .unwrap();
        assert_eq!(
            store.issuers[0].keys[0].window.not_after,
            Some(at(T0 + 600))
        );
        // An unreadable window changes nothing.
        let before = store.clone();
        assert!(store.add_published_jwks(IDP, &jwks("tomorrow")).is_err());
        assert_eq!(store, before);
        // A plain provider JWKS reads as open windows.
        let plain: PublishedJwks =
            serde_json::from_str(&serde_json::to_string(&k2.jwks()).unwrap()).unwrap();
        assert!(plain.keys[0].window.is_open());
    }

    #[test]
    fn every_identity_trust_label_parses_back() {
        for t in [
            IdentityTrust::Trusted,
            IdentityTrust::InsecureDev,
            IdentityTrust::UnknownIssuer,
            IdentityTrust::UnknownKey,
            IdentityTrust::UntrustedAudience,
            IdentityTrust::NoTrustedTime,
            IdentityTrust::OutsideKeyWindow,
            IdentityTrust::DistrustedKey,
            IdentityTrust::AlgorithmNotAccepted,
            IdentityTrust::InsufficientLevel,
        ] {
            assert_eq!(IdentityTrust::parse(t.as_str()), Some(t));
            let json = serde_json::to_string(&t).unwrap();
            assert_eq!(json, format!("\"{}\"", t.as_str()));
            assert!(!t.describe("x").is_empty());
        }
        assert_eq!(IdentityTrust::parse("maybe"), None);
        assert!(!IdentityTrust::AlgorithmNotAccepted.is_acceptable());
        assert!(!IdentityTrust::InsufficientLevel.is_acceptable());
    }

    // --- issuer kinds and the algorithm policy ------------------------------------------------

    #[test]
    fn issuer_kinds_default_to_what_a_verified_email_shows() {
        let mut store = TrustStore::well_known();
        store.add_jwks(IDP, &TestIssuer::es256().jwks());
        let tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        let ms = format!("https://login.microsoftonline.com/{tid}/v2.0");
        assert_eq!(
            store.issuer_kind("https://accounts.google.com", None),
            IssuerKind::Account
        );
        assert_eq!(store.issuer_kind(&ms, Some(tid)), IssuerKind::Account);
        // An issuer the store says nothing about shows an email address, no more.
        assert_eq!(store.issuer_kind(IDP, None), IssuerKind::EmailCode);
        assert_eq!(
            store.issuer_kind("https://elsewhere.test", None),
            IssuerKind::EmailCode
        );
        store
            .set_issuer_kind(IDP, Some(IssuerKind::Organization))
            .unwrap();
        assert_eq!(store.issuer_kind(IDP, None), IssuerKind::Organization);
        // A store can say a well-known provider shows less.
        store
            .set_issuer_kind("https://accounts.google.com", Some(IssuerKind::EmailCode))
            .unwrap();
        assert_eq!(
            store.issuer_kind("https://accounts.google.com", None),
            IssuerKind::EmailCode
        );
        assert!(store.set_issuer_kind("https://nowhere.test", None).is_err());
        // The kind travels in JSON, and only when set.
        let json: serde_json::Value = serde_json::from_str(&store.to_json().unwrap()).unwrap();
        let entry = |iss: &str| {
            json["issuers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["issuer"] == iss)
                .unwrap()
                .clone()
        };
        assert_eq!(entry(IDP)["kind"], "organization");
        assert!(entry("https://appleid.apple.com").get("kind").is_none());
        assert_eq!(
            TrustStore::from_json(&store.to_json().unwrap()).unwrap(),
            store
        );
    }

    #[test]
    fn merging_never_raises_an_issuer_kind() {
        let mut a = TrustStore::empty();
        a.add_jwks(IDP, &TestIssuer::es256().jwks());
        let mut b = a.clone();
        a.set_issuer_kind(IDP, Some(IssuerKind::Organization))
            .unwrap();
        b.set_issuer_kind(IDP, Some(IssuerKind::EmailCode)).unwrap();
        let mut merged = a.clone();
        merged.merge(&b);
        assert_eq!(merged.issuer_kind(IDP, None), IssuerKind::EmailCode);
        let mut merged = b.clone();
        merged.merge(&a);
        assert_eq!(merged.issuer_kind(IDP, None), IssuerKind::EmailCode);
        // A kind only one store states is kept.
        let mut plain = TrustStore::empty();
        plain.add_jwks(IDP, &TestIssuer::es256().jwks());
        plain.merge(&a);
        assert_eq!(plain.issuer_kind(IDP, None), IssuerKind::Organization);
    }

    #[test]
    fn the_algorithm_policy_is_the_trust_lists_or_the_builtin_one() {
        use crate::algorithms::{AlgorithmPolicy, BUILTIN_POLICY_VERSION};
        let mut store = TrustStore::well_known();
        assert_eq!(store.algorithms().version, BUILTIN_POLICY_VERSION);
        assert!(store.algorithm_policy.is_none());
        assert!(!store.to_json().unwrap().contains("algorithm_policy"));

        let mut v5 = AlgorithmPolicy::builtin();
        v5.version = 5;
        v5.algorithms[4].not_after = Some(at(T0));
        store.set_algorithm_policy(Some(v5.clone())).unwrap();
        assert_eq!(store.algorithms().version, 5);
        assert_eq!(
            TrustStore::from_json(&store.to_json().unwrap()).unwrap(),
            store
        );

        // An unreadable policy is refused, when set and when loaded.
        let mut bad = v5.clone();
        bad.algorithms[0].not_after = Some("never".into());
        assert!(store
            .clone()
            .set_algorithm_policy(Some(bad.clone()))
            .is_err());
        let mut json: serde_json::Value = serde_json::from_str(&store.to_json().unwrap()).unwrap();
        json["algorithm_policy"] = serde_json::to_value(&bad).unwrap();
        let err = TrustStore::from_json(&json.to_string())
            .unwrap_err()
            .to_string();
        assert!(err.contains("never"), "{err}");

        // Merging keeps the newer edition, and on a tie this store's.
        let mut v6 = AlgorithmPolicy::builtin();
        v6.version = 6;
        let newer = TrustStore {
            algorithm_policy: Some(v6.clone()),
            ..TrustStore::empty()
        };
        let mut merged = store.clone();
        merged.merge(&newer);
        assert_eq!(merged.algorithm_policy, Some(v6.clone()));
        let mut merged = newer.clone();
        merged.merge(&store);
        assert_eq!(merged.algorithm_policy, Some(v6));
        let mut tie = v5.clone();
        tie.algorithms.clear();
        let mut merged = store.clone();
        merged.merge(&TrustStore {
            algorithm_policy: Some(tie),
            ..TrustStore::empty()
        });
        assert_eq!(merged.algorithm_policy, Some(v5));
        let mut merged = TrustStore::empty();
        merged.merge(&store);
        assert_eq!(merged.algorithm_policy, store.algorithm_policy);
        store.set_algorithm_policy(None).unwrap();
        assert_eq!(store.algorithms().version, BUILTIN_POLICY_VERSION);
    }
}
