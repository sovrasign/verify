//! Reference command-line front-end and verifier for the SignPDF engine.
//!
//! This CLI is the headless wrapper called out in Phase 1 of the implementation plan. It
//! is intended for automated testing and as a free, offline standalone verifier.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;

use signpdf_auth::{authenticate, LoginOptions, Provider, ProviderConfig, SystemBrowser};
use signpdf_core::container;
use signpdf_core::crypto::{sha256_hex, KeyPair};
use signpdf_core::ltv::testing::{TestCa, TestStatus};
use signpdf_core::oidc::{compute_nonce, testing::TestIssuer};
use signpdf_core::pades::Timestamper;
use signpdf_core::timestamp::testing::TestTsa;
use signpdf_core::workflow::{self, PrepareRequest, SignRequest, SignerSpec};
use signpdf_core::{
    add_document_timestamp, add_validation_data, combine_documents, completion_certificate,
    convenience_copy_name, embed_signature_timestamp, extract_document, pades_sign,
    pades_verify_all, prepare, revocation_targets, sign_for_timestamp, sign_with,
    signature_timestamp_digest, typed_signature, verify, AlgorithmPolicy, DateFormat, EsignConsent,
    Field, FieldType, FormulaSpec, Identity, IdentityPolicy, InkPaths, IssuerKind, Jwks,
    LengthRule, Level, Method, NumberFormat, NumberStyle, Policy, Rect, SignAppearance,
    SignPdfError, SigningOrder, SourceDocument, TimestampPolicy, TrustStore, ValueFormat,
    ValueFormatKind, VerificationReport,
};

/// Issuer/audience of the bundled test identity provider the reference CLI uses to simulate a
/// federated login (`--email`). Verifiers only accept it with the explicit, insecure
/// `--insecure-dev-trust` flag; real OIDC provider login uses `--oidc`.
const DEV_ISSUER: &str = signpdf_core::oidc::DEV_ISSUER;
const DEV_AUDIENCE: &str = "signpdf-cli-dev";

/// Exit status for a document made by a newer version of SignPDF (its envelope schema version is
/// newer than this build reads): neither valid nor invalid, the tool needs an update. Every other
/// failure, including an invalid document, exits 1; clap's usage errors exit 2.
const EXIT_UNSUPPORTED_VERSION: u8 = 3;

#[derive(Parser)]
#[command(
    name = "signpdf",
    version,
    about = "Serverless PDF signing — reference CLI"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// How the verifier decides which identity providers (and TSAs) to trust.
#[derive(clap::Args, Clone)]
struct TrustArgs {
    /// Trust store JSON (pinned issuer keys + TSA anchors). Create one with `signpdf trust init`
    /// and keep it current with `signpdf trust refresh`. Defaults to the well-known providers
    /// without pinned keys (identities then report `unknown-key`).
    #[arg(long, value_name = "FILE")]
    trust: Option<PathBuf>,
    /// INSECURE: also trust the bundled dev identity provider used by `--email` logins. For
    /// demos and tests only — anyone can mint dev identities.
    #[arg(long)]
    insecure_dev_trust: bool,
}

impl TrustArgs {
    fn load(&self) -> Result<TrustStore> {
        let mut store = match &self.trust {
            Some(p) => TrustStore::from_json(
                &fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
            )
            .with_context(|| format!("parsing trust store {}", p.display()))?,
            None => TrustStore::well_known(),
        };
        if self.insecure_dev_trust {
            store.allow_insecure_dev_issuer = true;
        }
        Ok(store)
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a self-signed identity (key pair) and write it to a JSON file.
    Keygen {
        #[arg(long)]
        name: String,
        #[arg(long)]
        handle: String,
        #[arg(long, default_value = "identity.json")]
        out: PathBuf,
        /// Store the private key encrypted at rest in the OS secure keystore (Windows DPAPI).
        #[arg(long)]
        secure: bool,
    },
    /// Write a small sample PDF (useful for trying the workflow).
    Sample {
        #[arg(long, default_value = "sample.pdf")]
        out: PathBuf,
        #[arg(long, default_value = "Sample document")]
        text: String,
    },
    /// Prepare a source PDF for signing using a JSON spec (the result is signed by the preparer).
    /// Several `--source` files make an envelope of several documents: they are combined, in
    /// order, into one PDF with a documents index (field pages count across all of them).
    Prepare {
        #[arg(long, required = true)]
        source: Vec<PathBuf>,
        #[arg(long)]
        spec: PathBuf,
        /// Email for the bundled offline dev login (CI/testing). Mutually exclusive with --oidc.
        #[arg(long)]
        email: Option<String>,
        /// Real OIDC provider to log in against: google | microsoft | apple | enterprise.
        /// Runs an interactive browser login; https providers need `--features oidc-tls`.
        #[arg(long)]
        oidc: Option<String>,
        /// Client_id of your own app registration with the provider. Optional for google and
        /// microsoft, which default to SignPDF's own registration.
        #[arg(long)]
        client_id: Option<String>,
        /// Issuer URL to discover for `--oidc enterprise` (the OIDC issuer).
        #[arg(long)]
        issuer: Option<String>,
        /// Mint an organization-federated (enterprise) identity instead of a consumer one
        /// (bundled dev login only; real providers infer assurance from the token).
        #[arg(long)]
        enterprise: bool,
        #[arg(long, default_value = "prepared.pdf")]
        out: PathBuf,
    },
    /// Sign (or decline) a prepared document; the signer slot is auto-resolved from the
    /// federated identity.
    Sign {
        #[arg(long)]
        input: PathBuf,
        /// Email for the bundled offline dev login (CI/testing). Mutually exclusive with --oidc.
        #[arg(long)]
        email: Option<String>,
        /// Real OIDC provider to log in against: google | microsoft | apple | enterprise.
        /// Runs an interactive browser login; https providers need `--features oidc-tls`.
        #[arg(long)]
        oidc: Option<String>,
        /// Client_id of your own app registration with the provider. Optional for google and
        /// microsoft, which default to SignPDF's own registration.
        #[arg(long)]
        client_id: Option<String>,
        /// Issuer URL to discover for `--oidc enterprise` (the OIDC issuer).
        #[arg(long)]
        issuer: Option<String>,
        /// Mint an organization-federated (enterprise) identity instead of a consumer one
        /// (bundled dev login only; real providers infer assurance from the token).
        #[arg(long)]
        enterprise: bool,
        /// Optional assertion of which slot is being signed; when omitted it is auto-resolved.
        #[arg(long, default_value = "")]
        signer: String,
        #[arg(long, default_value = "signed.pdf")]
        out: PathBuf,
        #[arg(long)]
        decline: bool,
        /// Reason shown in the signature (or the decline reason).
        #[arg(long)]
        reason: Option<String>,
        /// Set a non-signature field value: --set field_id=value (repeatable).
        #[arg(long = "set", value_name = "FIELD=VALUE")]
        set: Vec<String>,
        /// RFC 3161 Time-Stamp Authority URL; embeds a PAdES B-T signature timestamp (a trusted
        /// signing clock for verifiers that trust the TSA). Failure aborts the signature.
        #[arg(long, value_name = "URL")]
        tsa_url: Option<String>,
        /// The signer's UTC offset, e.g. +02:00 or -05:30: dates the engine fills are the local
        /// date at this offset, which the signature record keeps. Default: UTC dates.
        #[arg(long, value_name = "+HH:MM", allow_hyphen_values = true)]
        utc_offset: Option<String>,
        /// JSON file with the signer's consent to electronic records and signatures, written
        /// into their audit entry: {"version", "lang", "sha256", "ref_sha256"?, "at"}.
        #[arg(long, value_name = "FILE")]
        esign_consent: Option<PathBuf>,
        /// Type a signature: this name, drawn in the signature box as the glyph outlines of the
        /// font --signature-font names (filled paths, not text; the PDF embeds no font). Needs an
        /// envelope of schema version 6 or later. Decoration: the box's caption names the
        /// verified signer.
        #[arg(long, value_name = "NAME", requires = "signature_font")]
        type_signature: Option<String>,
        /// TrueType or OpenType font file for --type-signature (a handwriting-style face whose
        /// licence allows it).
        #[arg(long, value_name = "FILE", requires = "type_signature")]
        signature_font: Option<PathBuf>,
    },
    /// Interactively sign in to a federated provider and print the verified identity. Useful as a
    /// connectivity/identity preflight; the resulting token is bound to a throwaway nonce and
    /// cannot itself sign a document (each signature logs in inline). Needs `--features oidc-tls`
    /// for https providers.
    Login {
        /// Provider to log in against: google | microsoft | apple | enterprise.
        #[arg(long)]
        oidc: String,
        /// Client_id of your own app registration with the provider. Optional for google and
        /// microsoft, which default to SignPDF's own registration.
        #[arg(long)]
        client_id: Option<String>,
        /// Issuer URL to discover for `--oidc enterprise`.
        #[arg(long)]
        issuer: Option<String>,
    },
    /// Verify every signature, the revision chain, audit log, order, and identities.
    Verify {
        #[arg(long)]
        input: PathBuf,
        /// Emit the full machine-readable report as JSON.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        trust: TrustArgs,
    },
    /// Verify a document and write a certificate-of-completion PDF summarizing the result.
    Certificate {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = "certificate.pdf")]
        out: PathBuf,
        #[command(flatten)]
        trust: TrustArgs,
    },
    /// Manage the verifier trust store (pinned identity-provider keys and TSA anchors).
    Trust {
        #[command(subcommand)]
        cmd: TrustCmd,
    },
    /// Combine several PDFs, in order, into the one PDF an envelope of several documents signs,
    /// and print its documents index (JSON), for a prepare request's `documents`.
    Combine {
        /// A document to add (repeatable, in order). Its file name is its name in the envelope.
        #[arg(long, required = true)]
        input: Vec<PathBuf>,
        #[arg(long, default_value = "combined.pdf")]
        out: PathBuf,
        /// Also write the documents index to this JSON file.
        #[arg(long)]
        index: Option<PathBuf>,
    },
    /// Write a convenience copy of one document of an envelope of several: its pages only, with
    /// a banner saying it is a copy (the combined PDF is what was signed).
    Extract {
        #[arg(long)]
        input: PathBuf,
        /// The document's number in the envelope (1 for the first).
        #[arg(long)]
        document: usize,
        /// Default: the document's name followed by "(convenience copy - verify the combined
        /// file)", next to the input.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the embedded envelope JSON.
    Inspect {
        #[arg(long)]
        input: PathBuf,
    },
    /// Apply a real PAdES signature to a clean PDF (incremental update + CMS).
    PadesSign {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long, default_value = "pades-signed.pdf")]
        out: PathBuf,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        location: Option<String>,
        /// 0-based page index for the signature field.
        #[arg(long, default_value_t = 0)]
        page: u32,
        /// Visible field rectangle "x1,y1,x2,y2" (omit for an invisible signature).
        #[arg(long)]
        rect: Option<String>,
    },
    /// Validate every embedded PAdES signature with the built-in reader.
    PadesVerify {
        #[arg(long)]
        input: PathBuf,
    },
    /// Add a PAdES document timestamp: proof from an RFC 3161 authority that the whole document,
    /// every revision so far, existed then. What a service adds when an envelope ends, above all
    /// when its signatures carry no timestamp of their own.
    Timestamp {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = "timestamped.pdf")]
        out: PathBuf,
        /// RFC 3161 Time-Stamp Authority URL.
        #[arg(long, value_name = "URL")]
        tsa_url: String,
    },
    /// Make the document's timestamps verifiable for the long term (PAdES B-LTA): add the
    /// certificates of their time-stamp authorities' chains and OCSP responses or CRLs showing
    /// none was revoked (fetched from the addresses the certificates name, unless --offline),
    /// then a document timestamp over them. Run it again later to renew.
    Ltv {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = "ltv.pdf")]
        out: PathBuf,
        /// RFC 3161 Time-Stamp Authority URL, for the document timestamp that covers the data.
        #[arg(long, value_name = "URL")]
        tsa_url: String,
        /// An OCSP response (DER) to add, fetched beforehand (repeatable).
        #[arg(long, value_name = "FILE")]
        ocsp: Vec<PathBuf>,
        /// A CRL (DER) to add, fetched beforehand (repeatable).
        #[arg(long, value_name = "FILE")]
        crl: Vec<PathBuf>,
        /// Fetch nothing: add only the certificates and the --ocsp and --crl files.
        #[arg(long)]
        offline: bool,
        #[command(flatten)]
        trust: TrustArgs,
    },
    /// Run the full two-signer ordered flow (Phase 1 exit criterion) plus attack demonstrations.
    Demo {
        /// Directory for the demo artifacts (default: a fresh temp directory).
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// TESTS ONLY: serve an untrusted RFC 3161 Time-Stamp Authority on 127.0.0.1 (the engine's
    /// test TSA, with a fresh key). Prints one JSON line `{"url", "cert_der_b64"}`, then answers
    /// `application/timestamp-query` POSTs until stopped. Its tokens are trusted only by a trust
    /// store that pins its certificate.
    #[command(hide = true)]
    TestTsa {
        /// Port to listen on (0 = any free port).
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Also write the TSA certificate (DER) to this file.
        #[arg(long)]
        cert_out: Option<PathBuf>,
    },
    /// TESTS ONLY: write the engine's test font (a tiny TrueType font made in code, whose glyphs
    /// are plain shapes, not letters) to a file, for checking typed signatures outside Rust.
    #[command(hide = true)]
    TestFont {
        /// The font file to write.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum TrustCmd {
    /// Write the well-known trust store (Google, Microsoft, Apple; DigiCert TSA root) without
    /// pinned keys. Follow with `trust refresh` to pin the providers' current keys.
    Init {
        #[arg(long, default_value = "trust.json")]
        out: PathBuf,
    },
    /// Fetch each issuer's current JWKS (over https: needs `--features oidc-tls`) and pin any new
    /// keys, keeping the history of previously pinned ones.
    Refresh {
        #[arg(long, default_value = "trust.json")]
        file: PathBuf,
    },
    /// Pin the keys of a JWKS file for an issuer (offline alternative to `refresh`).
    AddJwks {
        #[arg(long, default_value = "trust.json")]
        file: PathBuf,
        #[arg(long)]
        issuer: String,
        /// JWKS JSON file (`{"keys": [...]}`).
        #[arg(long)]
        jwks: PathBuf,
    },
    /// Trust sign-ins that an issuer issued to one more application (`client_id`): your
    /// organization's own app registration, or a provider where SignPDF has none (Apple). Only
    /// add an application you know runs the SignPDF signing ceremony: any other website or app
    /// can obtain tokens from its users that would then count as their signatures.
    AddAudience {
        #[arg(long, default_value = "trust.json")]
        file: PathBuf,
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        client_id: String,
    },
    /// Trust a Time-Stamp Authority root/intermediate certificate (DER or PEM).
    AddTsa {
        #[arg(long, default_value = "trust.json")]
        file: PathBuf,
        #[arg(long)]
        cert: PathBuf,
    },
    /// Distrust a Time-Stamp Authority certificate (the TSA's own, an intermediate or an anchor)
    /// from a time (RFC 3339, the last known-good time): its timestamps dated at or after it no
    /// longer count as trusted time. For an authority whose key may have been compromised; the
    /// anchors stay, so other authorities under the same root are unaffected.
    DistrustTsa {
        #[arg(long, default_value = "trust.json")]
        file: PathBuf,
        /// The certificate (DER or PEM).
        #[arg(long, required_unless_present = "sha256")]
        cert: Option<PathBuf>,
        /// Or its SHA-256 (hex).
        #[arg(long, conflicts_with = "cert")]
        sha256: Option<String>,
        #[arg(long)]
        after: String,
        /// A label for people (the authority's name).
        #[arg(long)]
        name: Option<String>,
    },
    /// Set the validity window of one pinned key (replacing its current one; times are RFC
    /// 3339, e.g. 2027-11-01T00:08:00Z). A token signed by the key then counts only when a
    /// trusted timestamp shows the signature was made before `--not-after` (the issuer stopped
    /// signing with it) and `--distrusted-after` (it may have been compromised from then), and
    /// neither the token nor a timestamp predates `--not-before`.
    Window {
        #[arg(long, default_value = "trust.json")]
        file: PathBuf,
        #[arg(long)]
        issuer: String,
        /// The key's RFC 7638 thumbprint, or a `kid` only that key has (`trust show` lists both).
        #[arg(long)]
        key: String,
        #[arg(long)]
        not_before: Option<String>,
        #[arg(long)]
        not_after: Option<String>,
        #[arg(long)]
        distrusted_after: Option<String>,
    },
    /// Count an issuer's tokens only with a trusted timestamp inside the signing key's validity
    /// window (for an issuer whose stolen key could vouch for anyone, such as a service's own
    /// email-code provider). `--off` lifts the rule.
    RequireTime {
        #[arg(long, default_value = "trust.json")]
        file: PathBuf,
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        off: bool,
    },
    /// Record what a sign-in with an issuer shows, from which verifiers compute each signature's
    /// assurance level: `email-code` (L1: a one-time code to the inbox, whatever its tokens
    /// claim; set it for a service's own email-code provider), `account` (L2, or L3 for an
    /// organization identity the provider asserts) or `organization` (L3: an organization's own
    /// provider for its signers). `--clear` returns to the default (`account` for Google,
    /// Microsoft and Apple, `email-code` for any other issuer).
    Kind {
        #[arg(long, default_value = "trust.json")]
        file: PathBuf,
        #[arg(long)]
        issuer: String,
        /// email-code | account | organization
        #[arg(long, required_unless_present = "clear")]
        kind: Option<String>,
        #[arg(long, conflicts_with = "kind")]
        clear: bool,
    },
    /// Set the algorithm policy the store's verifiers apply (a JSON file: `{"version": N,
    /// "algorithms": [{"algorithm": "RSA-PKCS1-v1_5", "min_key_bits": 2048, "not_after":
    /// "2030-12-31T00:00:00Z"}, ...]}`), or `--builtin` to return to the engine's own (every
    /// implemented algorithm, RSA from 2048 bits, no end dates). Evidence relying on an
    /// algorithm past its `not_after` then counts only with a trusted timestamp from before it.
    AlgorithmPolicy {
        #[arg(long, default_value = "trust.json")]
        file: PathBuf,
        #[arg(long, required_unless_present = "builtin")]
        policy: Option<PathBuf>,
        #[arg(long, conflicts_with = "policy")]
        builtin: bool,
    },
    /// Summarize a trust store.
    Show {
        #[arg(long, default_value = "trust.json")]
        file: PathBuf,
    },
}

/// JSON spec consumed by `prepare`.
#[derive(Deserialize)]
struct PrepareSpec {
    title: String,
    signers: Vec<SignerSpecJson>,
    #[serde(default)]
    fields: Vec<Field>,
    #[serde(default = "default_order")]
    signing_order: String,
    /// Optional RFC 3339 deadline after which no further signatures are accepted.
    #[serde(default)]
    expiry: Option<String>,
    /// Signature timestamps on the signer revisions: `optional` (the default: each signer's
    /// `--tsa-url` decides), `required` or `none`.
    #[serde(default)]
    signature_timestamps: TimestampPolicy,
    /// Optional `https` link that opens the envelope in the service that sent it, kept outside
    /// the prepared terms.
    #[serde(default)]
    service_link: Option<String>,
    /// Optional short address of a verifier (`verify.example.com`), drawn on the document-ID
    /// stamp as "Verify at <address>" (part of the prepared terms).
    #[serde(default)]
    verify_at: Option<String>,
}

#[derive(Deserialize)]
struct SignerSpecJson {
    id: String,
    name: String,
    handle: String,
    #[serde(default)]
    role: String,
    order: u32,
    /// Exact email the signer must control. Defaults to `handle` when it looks like an email, so
    /// each slot resolves to a single identity out of the box.
    #[serde(default)]
    required_email: Option<String>,
    /// Email domain the signer must belong to (enterprise slots).
    #[serde(default)]
    required_domain: Option<String>,
    /// Microsoft Entra tenant id the signer must belong to.
    #[serde(default)]
    required_tenant: Option<String>,
    /// Stable `sub` the signer's token must carry.
    #[serde(default)]
    required_subject: Option<String>,
    /// Issuers accepted for this slot. Empty trusts whatever the verifier already accepts.
    #[serde(default)]
    allowed_issuers: Vec<String>,
    /// Require an organization-federated (enterprise) identity for this slot: `min_level` L3.
    #[serde(default)]
    enterprise: bool,
    /// The lowest assurance level the signature must reach (`L1` … `L3`; default `L1`, or `L3`
    /// with `enterprise`).
    #[serde(default)]
    min_level: Option<Level>,
    /// Evidence the signature must carry whatever its level (`email-code`, `account`,
    /// `organization`).
    #[serde(default)]
    required_methods: Vec<Method>,
}

impl SignerSpecJson {
    fn identity_policy(&self) -> IdentityPolicy {
        let required_email = self.required_email.clone().or_else(|| {
            if self.handle.contains('@') {
                Some(self.handle.clone())
            } else {
                None
            }
        });
        IdentityPolicy {
            allowed_issuers: self.allowed_issuers.clone(),
            required_email,
            required_domain: self.required_domain.clone(),
            required_tenant: self.required_tenant.clone(),
            required_subject: self.required_subject.clone(),
            min_level: self.min_level.unwrap_or(if self.enterprise {
                Level::L3
            } else {
                Level::L1
            }),
            required_methods: self.required_methods.clone(),
        }
    }
}

fn default_order() -> String {
    "sequential".to_string()
}

/// Federated-login material the reference CLI synthesizes per signature.
struct DevIdentity {
    id_token: String,
    idp_jwk: String,
}

fn cli_now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Simulate a federated login for the reference CLI: mint an ID token with the bundled test
/// issuer, stapled to `key` and `digest` via the OIDC `nonce`, so prepare/sign run offline
/// end-to-end. Such identities are only accepted by verifiers run with `--insecure-dev-trust`.
fn mint_dev_identity(
    key: &KeyPair,
    digest: &str,
    email: &str,
    enterprise: bool,
) -> Result<DevIdentity> {
    let issuer = TestIssuer::es256();
    let nonce = compute_nonce(&key.public_sec1(), digest);
    let now = cli_now_unix();
    let mut claims = serde_json::json!({
        "iss": DEV_ISSUER,
        "sub": format!("dev|{email}"),
        "aud": DEV_AUDIENCE,
        "iat": now - 5,
        "exp": now + 3600,
        "email": email,
        "email_verified": true,
        "name": email,
        "nonce": nonce,
    });
    if enterprise {
        let domain = email.split('@').nth(1).unwrap_or("example.com");
        claims["hd"] = serde_json::json!(domain);
    }
    Ok(DevIdentity {
        id_token: issuer.mint(claims),
        idp_jwk: serde_json::to_string(&issuer.jwk())?,
    })
}

/// Build a [`SignRequest`] carrying a synthesized dev identity (auto-resolve slot).
fn dev_sign_request(dev: DevIdentity) -> SignRequest {
    SignRequest {
        id_token: dev.id_token,
        idp_jwk: dev.idp_jwk,
        audience: DEV_AUDIENCE.to_string(),
        allowed_issuers: vec![DEV_ISSUER.to_string()],
        ..Default::default()
    }
}

/// How the CLI obtains a verified federated identity for a prepare/sign operation.
enum LoginMethod {
    /// Synthesize an identity offline with the bundled test issuer (CI/dev path, no network).
    Dev { email: String, enterprise: bool },
    /// Run a real OIDC Authorization Code + PKCE browser login against a live provider.
    Oidc { config: ProviderConfig },
}

/// Verified federated material ready to drop into a prepare/sign request.
struct FederatedToken {
    id_token: String,
    idp_jwk: String,
    audience: String,
    allowed_issuers: Vec<String>,
    /// The verified email, for human-readable output.
    email: String,
}

/// Decide which login path the CLI flags select, rejecting ambiguous/incomplete combinations.
fn resolve_login(
    email: Option<String>,
    enterprise: bool,
    oidc: Option<String>,
    client_id: Option<String>,
    issuer: Option<String>,
) -> Result<LoginMethod> {
    match oidc {
        Some(provider) => {
            if email.is_some() {
                return Err(anyhow!(
                    "pass either --oidc (real login) or --email (bundled dev login), not both"
                ));
            }
            let config = Provider::from_name(&provider, issuer)?.config_or_builtin(client_id)?;
            Ok(LoginMethod::Oidc { config })
        }
        None => {
            let email = email.ok_or_else(|| {
                anyhow!(
                    "provide --oidc <provider> for a real login, \
                     or --email <addr> for the bundled offline dev login"
                )
            })?;
            Ok(LoginMethod::Dev { email, enterprise })
        }
    }
}

/// Resolve a [`FederatedToken`] for an ephemeral signing `key` and document `digest`.
///
/// The token is cryptographically stapled to exactly this `(key, document)` pair via the OIDC
/// `nonce`, so it can only ever authorize this one signature — which is why the real OIDC login
/// runs *inline* at prepare/sign time rather than from a cached `login`.
fn obtain_identity(method: &LoginMethod, key: &KeyPair, digest: &str) -> Result<FederatedToken> {
    match method {
        LoginMethod::Dev { email, enterprise } => {
            let dev = mint_dev_identity(key, digest, email, *enterprise)?;
            Ok(FederatedToken {
                id_token: dev.id_token,
                idp_jwk: dev.idp_jwk,
                audience: DEV_AUDIENCE.to_string(),
                allowed_issuers: vec![DEV_ISSUER.to_string()],
                email: email.clone(),
            })
        }
        LoginMethod::Oidc { config } => {
            let nonce = compute_nonce(&key.public_sec1(), digest);
            eprintln!("Opening your browser to sign in via {} …", config.issuer);
            let outcome = authenticate(config, &nonce, &SystemBrowser, &LoginOptions::default())
                .map_err(|e| anyhow!("OIDC login failed: {e}"))?;
            eprintln!(
                "Signed in as {} (issuer {})",
                outcome.identity.email, outcome.issuer
            );
            Ok(FederatedToken {
                id_token: outcome.id_token,
                idp_jwk: outcome.idp_jwk,
                audience: outcome.audience,
                allowed_issuers: vec![outcome.issuer],
                email: outcome.identity.email,
            })
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:?}");
            if is_unsupported_version(&e) {
                ExitCode::from(EXIT_UNSUPPORTED_VERSION)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

/// The engine refused a document from a newer build (see [`EXIT_UNSUPPORTED_VERSION`]).
fn is_unsupported_version(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        matches!(
            c.downcast_ref::<SignPdfError>(),
            Some(SignPdfError::UnsupportedSchemaVersion { .. })
        )
    })
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Keygen {
            name,
            handle,
            out,
            secure,
        } => cmd_keygen(&name, &handle, &out, secure),
        Cmd::Sample { out, text } => {
            fs::write(&out, container::make_sample_pdf(&text))?;
            println!("Wrote sample PDF to {}", out.display());
            Ok(())
        }
        Cmd::Prepare {
            source,
            spec,
            email,
            oidc,
            client_id,
            issuer,
            enterprise,
            out,
        } => {
            let method = resolve_login(email, enterprise, oidc, client_id, issuer)?;
            cmd_prepare(&source, &spec, &method, &out)
        }
        Cmd::Sign {
            input,
            email,
            oidc,
            client_id,
            issuer,
            enterprise,
            signer,
            out,
            decline,
            reason,
            set,
            tsa_url,
            utc_offset,
            esign_consent,
            type_signature,
            signature_font,
        } => {
            let method = resolve_login(email, enterprise, oidc, client_id, issuer)?;
            // The typed signature first: a name the font cannot draw fails before any sign-in.
            let typed_signature = match (type_signature, signature_font) {
                (Some(name), Some(font)) => {
                    let bytes =
                        fs::read(&font).with_context(|| format!("reading {}", font.display()))?;
                    Some(typed_signature(&bytes, &name).map_err(|e| anyhow!("{e}"))?)
                }
                _ => None,
            };
            let utc_offset_minutes = utc_offset
                .as_deref()
                .map(|o| {
                    signpdf_core::dates::parse_utc_offset(o).ok_or_else(|| {
                        anyhow!("--utc-offset takes +HH:MM or -HH:MM, from -12:00 to +14:00")
                    })
                })
                .transpose()?;
            let esign_consent = esign_consent
                .map(|path| -> Result<EsignConsent> {
                    let bytes =
                        fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
                    serde_json::from_slice(&bytes)
                        .with_context(|| format!("{} is not a consent record", path.display()))
                })
                .transpose()?;
            cmd_sign(
                &input,
                &method,
                &signer,
                &out,
                SignChoices {
                    decline,
                    reason,
                    set,
                    tsa_url,
                    utc_offset_minutes,
                    esign_consent,
                    typed_signature,
                },
            )
        }
        Cmd::Login {
            oidc,
            client_id,
            issuer,
        } => cmd_login(&oidc, client_id, issuer),
        Cmd::Verify { input, json, trust } => cmd_verify(&input, json, &trust.load()?),
        Cmd::Certificate { input, out, trust } => {
            let pdf = fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let cert = completion_certificate(&pdf, &trust.load()?)?;
            fs::write(&out, cert)?;
            println!("Wrote certificate of completion to {}", out.display());
            Ok(())
        }
        Cmd::Trust { cmd } => cmd_trust(cmd),
        Cmd::Combine { input, out, index } => cmd_combine(&input, &out, index.as_deref()),
        Cmd::Extract {
            input,
            document,
            out,
        } => cmd_extract(&input, document, out),
        Cmd::Inspect { input } => cmd_inspect(&input),
        Cmd::PadesSign {
            input,
            identity,
            out,
            reason,
            location,
            page,
            rect,
        } => cmd_pades_sign(&input, &identity, &out, reason, location, page, rect),
        Cmd::PadesVerify { input } => cmd_pades_verify(&input),
        Cmd::Timestamp {
            input,
            out,
            tsa_url,
        } => cmd_timestamp(&input, &out, &tsa_url),
        Cmd::Ltv {
            input,
            out,
            tsa_url,
            ocsp,
            crl,
            offline,
            trust,
        } => cmd_ltv(&input, &out, &tsa_url, &ocsp, &crl, offline, &trust.load()?),
        Cmd::Demo { out_dir } => cmd_demo(out_dir),
        Cmd::TestTsa { port, cert_out } => cmd_test_tsa(port, cert_out),
        Cmd::TestFont { out } => {
            fs::write(&out, signpdf_core::ink::typed::testing::font())
                .with_context(|| format!("writing {}", out.display()))?;
            Ok(())
        }
    }
}

/// `signpdf test-tsa`: the engine's test TSA behind a minimal HTTP/1.1 server on 127.0.0.1, for
/// the browser signing tests (the page POSTs the request the engine built, as to a real TSA).
fn cmd_test_tsa(port: u16, cert_out: Option<PathBuf>) -> Result<()> {
    use std::io::Write;
    use std::net::TcpListener;

    let tsa = TestTsa::new();
    if let Some(path) = cert_out {
        fs::write(&path, tsa.cert_der())?;
    }
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let line = serde_json::json!({
        "url": format!("http://{}/", listener.local_addr()?),
        "cert_der_b64": signpdf_core::crypto::b64_encode_pub(&tsa.cert_der()),
    });
    println!("{line}");
    std::io::stdout().flush()?;
    for stream in listener.incoming() {
        // One bad request never stops the server.
        if let Err(e) = stream
            .map_err(anyhow::Error::from)
            .and_then(|s| serve_tsa(&tsa, s))
        {
            eprintln!("test-tsa: {e}");
        }
    }
    Ok(())
}

/// Answer one HTTP request: POST a DER `TimeStampReq`, get a `TimeStampResp`.
fn serve_tsa(tsa: &TestTsa, mut stream: std::net::TcpStream) -> Result<()> {
    use std::io::{BufRead, BufReader, Read, Write};

    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse()?;
            }
        }
    }
    if content_length > 64 * 1024 {
        return Err(anyhow!("request too large"));
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    let (status, content_type, payload) = if !request_line.starts_with("POST ") {
        (
            "405 Method Not Allowed",
            "text/plain",
            b"POST a TimeStampReq\n".to_vec(),
        )
    } else {
        match tsa.respond(&body) {
            Ok(resp) => ("200 OK", "application/timestamp-reply", resp),
            Err(e) => (
                "400 Bad Request",
                "text/plain",
                format!("{e}\n").into_bytes(),
            ),
        }
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        payload.len()
    )?;
    stream.write_all(&payload)?;
    Ok(())
}

fn load_identity(path: &PathBuf, secure: bool) -> Result<Identity> {
    if secure {
        return load_secure_identity(path);
    }
    let bytes = fs::read(path).with_context(|| format!("reading identity {}", path.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(windows)]
fn load_secure_identity(path: &PathBuf) -> Result<Identity> {
    use signpdf_core::{DpapiKeyStore, KeyStore};
    DpapiKeyStore::new(path)
        .load_identity()
        .with_context(|| format!("loading secure identity {}", path.display()))
}

#[cfg(not(windows))]
fn load_secure_identity(_path: &PathBuf) -> Result<Identity> {
    Err(anyhow!(
        "--secure keystore (DPAPI) is only available on Windows in this build"
    ))
}

#[cfg(windows)]
fn save_secure_identity(path: &PathBuf, id: &Identity) -> Result<()> {
    use signpdf_core::{DpapiKeyStore, KeyStore};
    DpapiKeyStore::new(path)
        .save_identity(id)
        .with_context(|| format!("saving secure identity {}", path.display()))
}

#[cfg(not(windows))]
fn save_secure_identity(_path: &PathBuf, _id: &Identity) -> Result<()> {
    Err(anyhow!(
        "--secure keystore (DPAPI) is only available on Windows in this build"
    ))
}

fn cmd_keygen(name: &str, handle: &str, out: &PathBuf, secure: bool) -> Result<()> {
    let id = Identity::generate(name, handle);
    if secure {
        save_secure_identity(out, &id)?;
    } else {
        fs::write(out, serde_json::to_vec_pretty(&id)?)?;
    }
    println!("Identity for {name} <{handle}>");
    println!("  fingerprint: {}", id.fingerprint);
    println!("  written to : {}", out.display());
    if secure {
        println!(
            "  storage    : OS secure keystore (Windows DPAPI) — private key encrypted at rest"
        );
    }
    Ok(())
}

/// The documents of `paths`, read, each named after its file.
fn read_documents(paths: &[PathBuf]) -> Result<Vec<(String, Vec<u8>)>> {
    paths
        .iter()
        .map(|p| {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| p.display().to_string());
            let pdf = fs::read(p).with_context(|| format!("reading {}", p.display()))?;
            Ok((name, pdf))
        })
        .collect()
}

/// Combine `docs` (see [`signpdf_core::combine_documents`]).
fn combine(docs: &[(String, Vec<u8>)]) -> Result<signpdf_core::Combined> {
    let sources: Vec<SourceDocument> = docs
        .iter()
        .map(|(name, pdf)| SourceDocument { name, pdf })
        .collect();
    Ok(combine_documents(&sources)?)
}

fn print_index(documents: &[signpdf_core::EnvelopeDocument]) {
    for (i, d) in documents.iter().enumerate() {
        println!(
            "  {}. {} (pages {}-{})",
            i + 1,
            d.name,
            d.first_page + 1,
            d.first_page + d.page_count
        );
    }
}

fn cmd_combine(inputs: &[PathBuf], out: &Path, index: Option<&Path>) -> Result<()> {
    let combined = combine(&read_documents(inputs)?)?;
    fs::write(out, &combined.pdf)?;
    println!(
        "Combined {} document(s) into {} ({} bytes):",
        combined.documents.len(),
        out.display(),
        combined.pdf.len()
    );
    print_index(&combined.documents);
    let json = serde_json::to_string_pretty(&combined.documents)?;
    match index {
        Some(path) => {
            fs::write(path, json + "\n")?;
            println!("Wrote the documents index to {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn cmd_extract(input: &Path, document: usize, out: Option<PathBuf>) -> Result<()> {
    let pdf = fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let index = document
        .checked_sub(1)
        .ok_or_else(|| anyhow!("--document counts from 1"))?;
    let copy = extract_document(&pdf, index)?;
    let out = match out {
        Some(out) => out,
        None => {
            let env = workflow::read_envelope(&pdf)?;
            let name = convenience_copy_name(&env.documents[index]);
            input
                .parent()
                .map(|dir| dir.join(&name))
                .unwrap_or_else(|| PathBuf::from(name))
        }
    };
    fs::write(&out, copy)?;
    println!(
        "Wrote a convenience copy of document {document} to {} (not signed: verify the combined \
         PDF)",
        out.display()
    );
    Ok(())
}

fn cmd_prepare(
    sources: &[PathBuf],
    spec: &PathBuf,
    method: &LoginMethod,
    out: &PathBuf,
) -> Result<()> {
    let (pdf, documents) = match sources {
        [one] => (
            fs::read(one).with_context(|| format!("reading source {}", one.display()))?,
            Vec::new(),
        ),
        several => {
            let combined = combine(&read_documents(several)?)?;
            println!("Combined {} documents:", combined.documents.len());
            print_index(&combined.documents);
            (combined.pdf, combined.documents)
        }
    };
    let spec: PrepareSpec = serde_json::from_slice(&fs::read(spec)?)?;

    let order = match spec.signing_order.as_str() {
        "parallel" => SigningOrder::Parallel,
        "sequential" => SigningOrder::Sequential,
        other => return Err(anyhow!("unknown signing_order '{other}'")),
    };

    let signers: Vec<SignerSpec> = spec
        .signers
        .iter()
        .map(|s| SignerSpec {
            id: s.id.clone(),
            name: s.name.clone(),
            handle: s.handle.clone(),
            role: s.role.clone(),
            order: s.order,
            identity_policy: s.identity_policy(),
        })
        .collect();
    for s in &signers {
        for w in s.identity_policy.weaknesses() {
            eprintln!("warning: slot '{}' {w}", s.id);
        }
    }

    let preparer_key = KeyPair::generate();
    let token = obtain_identity(method, &preparer_key, &sha256_hex(&pdf))?;

    let request = PrepareRequest {
        title: spec.title,
        signers,
        fields: spec.fields,
        policy: Policy {
            signing_order: order,
            allowed_signature_types: vec!["PAdES".into()],
            expiry: spec.expiry,
            signature_timestamps: spec.signature_timestamps,
        },
        id_token: token.id_token,
        idp_jwk: token.idp_jwk,
        audience: token.audience,
        allowed_issuers: token.allowed_issuers,
        service_link: spec.service_link,
        documents,
        verify_at: spec.verify_at,
    };

    let prepared = prepare(&pdf, &request, &preparer_key)?;
    fs::write(out, &prepared)?;
    println!(
        "Prepared and signed '{}' (preparer {}) -> {}",
        request.title,
        token.email,
        out.display()
    );
    Ok(())
}

/// An RFC 3161 TSA reached over HTTP. The core builds and checks the request/response; this
/// adapter only does the POST.
struct HttpTsa(String);

impl Timestamper for HttpTsa {
    fn timestamp(&self, digest: &[u8; 32]) -> signpdf_core::Result<Vec<u8>> {
        use std::io::Read;
        let tsa_err = |m: String| signpdf_core::SignPdfError::Timestamp(m);
        let request = signpdf_core::timestamp::build_request(digest);
        let resp = ureq::post(&self.0)
            .set("Content-Type", "application/timestamp-query")
            .timeout(std::time::Duration::from_secs(20))
            .send_bytes(&request)
            .map_err(|e| tsa_err(format!("POST to {} failed: {e}", self.0)))?;
        let mut body = Vec::new();
        resp.into_reader()
            .read_to_end(&mut body)
            .map_err(|e| tsa_err(e.to_string()))?;
        Ok(signpdf_core::timestamp::parse_response(&body, digest)?.token_der)
    }
}

/// `signpdf timestamp`: a document timestamp from `tsa_url`.
fn cmd_timestamp(input: &Path, out: &Path, tsa_url: &str) -> Result<()> {
    let pdf = fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let stamped = add_document_timestamp(&pdf, &HttpTsa(tsa_url.to_string()))?;
    fs::write(out, &stamped)?;
    println!(
        "Added a document timestamp from {tsa_url}; wrote {}",
        out.display()
    );
    Ok(())
}

/// GET or POST `url` (http or https, as the build allows), returning the body of a 200 answer.
fn fetch(url: &str, post: Option<(&str, &[u8])>) -> Result<Vec<u8>> {
    use std::io::Read;
    let timeout = std::time::Duration::from_secs(20);
    let resp = match post {
        Some((content_type, body)) => ureq::post(url)
            .set("Content-Type", content_type)
            .timeout(timeout)
            .send_bytes(body),
        None => ureq::get(url).timeout(timeout).call(),
    }
    .map_err(|e| anyhow!("{url}: {e}"))?;
    let mut body = Vec::new();
    // OCSP responses are small; CRLs can be large, but not this large.
    resp.into_reader()
        .take(64 * 1024 * 1024)
        .read_to_end(&mut body)?;
    Ok(body)
}

/// `signpdf ltv`: validation data for the document's timestamps, then a document timestamp.
#[allow(clippy::too_many_arguments)]
fn cmd_ltv(
    input: &Path,
    out: &Path,
    tsa_url: &str,
    ocsp_files: &[PathBuf],
    crl_files: &[PathBuf],
    offline: bool,
    trust: &TrustStore,
) -> Result<()> {
    let pdf = fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let read_all = |files: &[PathBuf]| -> Result<Vec<Vec<u8>>> {
        files
            .iter()
            .map(|f| fs::read(f).with_context(|| format!("reading {}", f.display())))
            .collect()
    };
    let mut ocsps = read_all(ocsp_files)?;
    let mut crls = read_all(crl_files)?;
    if !offline {
        for t in revocation_targets(&pdf, trust)? {
            let ocsp = t.ocsp_urls.iter().find_map(|url| {
                let body = fetch(url, Some(("application/ocsp-request", &t.ocsp_request)))
                    .map_err(|e| eprintln!("  OCSP for {}: {e}", t.subject))
                    .ok()?;
                match signpdf_core::ltv::check_ocsp(&body, &t.cert, &t.issuer) {
                    Ok(_) => Some(body),
                    Err(e) => {
                        eprintln!("  OCSP for {} from {url}: {e}", t.subject);
                        None
                    }
                }
            });
            if let Some(body) = ocsp {
                println!("  OCSP response for {}", t.subject);
                ocsps.push(body);
                continue;
            }
            let crl = t.crl_urls.iter().find_map(|url| {
                let body = fetch(url, None)
                    .map_err(|e| eprintln!("  CRL for {}: {e}", t.subject))
                    .ok()?;
                match signpdf_core::ltv::check_crl(&body, &t.cert, &t.issuer) {
                    Ok(_) => Some(body),
                    Err(e) => {
                        eprintln!("  CRL for {} from {url}: {e}", t.subject);
                        None
                    }
                }
            });
            match crl {
                Some(body) => {
                    println!("  CRL for {}", t.subject);
                    crls.push(body);
                }
                None => eprintln!(
                    "  no revocation evidence for {}: the document will not be B-LT for its \
                     timestamps",
                    t.subject
                ),
            }
        }
    }
    let with_data = add_validation_data(&pdf, trust, &ocsps, &crls)?;
    let sealed = add_document_timestamp(&with_data, &HttpTsa(tsa_url.to_string()))?;
    fs::write(out, &sealed)?;
    let report = verify(&sealed, trust)?;
    println!(
        "Added validation data and a document timestamp from {tsa_url}; wrote {} (PAdES level {})",
        out.display(),
        if report.pades_level.is_empty() {
            "unknown: the document did not verify"
        } else {
            &report.pades_level
        }
    );
    Ok(())
}

/// What `signpdf sign` was asked to do besides who signs: sign or decline, and with what.
struct SignChoices {
    decline: bool,
    reason: Option<String>,
    /// `FIELD=VALUE` pairs.
    set: Vec<String>,
    tsa_url: Option<String>,
    utc_offset_minutes: Option<i32>,
    esign_consent: Option<EsignConsent>,
    /// The glyph outlines of a typed signature.
    typed_signature: Option<InkPaths>,
}

fn cmd_sign(
    input: &PathBuf,
    method: &LoginMethod,
    signer: &str,
    out: &PathBuf,
    choices: SignChoices,
) -> Result<()> {
    let SignChoices {
        decline,
        reason,
        set,
        tsa_url,
        utc_offset_minutes,
        esign_consent,
        typed_signature,
    } = choices;
    let tsa_url = tsa_url.as_deref();
    let bytes = fs::read(input)?;
    let mut field_values = Vec::new();
    for pair in &set {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| anyhow!("--set expects FIELD=VALUE, got '{pair}'"))?;
        field_values.push((k.to_string(), v.to_string()));
    }

    // The envelope's signature-timestamp policy, checked before the sign-in (the engine enforces
    // it again when signing).
    match (
        workflow::read_envelope(&bytes)?.policy.signature_timestamps,
        tsa_url,
    ) {
        (TimestampPolicy::None, Some(_)) => {
            return Err(anyhow!(
                "this envelope takes no signature timestamps (signature_timestamps = none): \
                 sign without --tsa-url"
            ))
        }
        (TimestampPolicy::Required, None) => eprintln!(
            "warning: this envelope requires a signature timestamp; without --tsa-url the \
             signature is dated by this device's clock and verifiers warn about it"
        ),
        _ => {}
    }

    let signer_key = KeyPair::generate();
    let token = obtain_identity(method, &signer_key, &sha256_hex(&bytes))?;

    let req = SignRequest {
        signer_id: signer.to_string(),
        field_values,
        decline,
        reason,
        id_token: token.id_token,
        idp_jwk: token.idp_jwk,
        audience: token.audience,
        allowed_issuers: token.allowed_issuers,
        utc_offset_minutes,
        esign_consent,
        typed_signature,
        ..Default::default()
    };
    let tsa = tsa_url.map(|u| HttpTsa(u.to_string()));
    let updated = sign_with(
        &bytes,
        &signer_key,
        &req,
        tsa.as_ref().map(|t| t as &dyn Timestamper),
    )?;
    fs::write(out, &updated)?;
    let verb = if decline { "Declined" } else { "Signed" };
    let who = if signer.is_empty() {
        token.email.as_str()
    } else {
        signer
    };
    println!("{verb} as '{who}' ({}) -> {}", token.email, out.display());
    if let Some(u) = tsa_url {
        println!("Signature timestamp: RFC 3161 via {u} (PAdES B-T)");
    }
    Ok(())
}

/// Interactive provider login preflight: verify connectivity and which account the user controls.
fn cmd_login(provider_name: &str, client_id: Option<String>, issuer: Option<String>) -> Result<()> {
    let config = Provider::from_name(provider_name, issuer)?.config_or_builtin(client_id)?;
    // A preflight is not bound to any document, so we use a throwaway nonce. Tokens minted here
    // are intentionally NOT reusable to sign — the keyless model staples every token to one
    // (key, document) pair — so this only confirms connectivity and the controlled account.
    let nonce = signpdf_auth::pkce::random_token(32);
    eprintln!("Opening your browser to sign in via {} …", config.issuer);
    let outcome = authenticate(&config, &nonce, &SystemBrowser, &LoginOptions::default())
        .map_err(|e| anyhow!("OIDC login failed: {e}"))?;
    let id = &outcome.identity;
    println!("Signed in.");
    println!("  email    : {}", id.email);
    println!("  verified : {}", id.email_verified);
    println!("  issuer   : {}", outcome.issuer);
    println!("  subject  : {}", id.subject);
    let assessment =
        id.assess(TrustStore::well_known().issuer_kind(&outcome.issuer, id.tenant_id.as_deref()));
    println!(
        "  level    : {} ({}; as a verifier with the well-known trust store counts it)",
        assessment.level,
        assessment.level.name()
    );
    if let Some(hd) = &id.hosted_domain {
        println!("  org      : {hd}");
    }
    if let Some(tid) = &id.tenant_id {
        println!("  tenant   : {tid}");
    }
    println!(
        "\nNote: this preflight token is bound to a throwaway nonce and cannot sign a document. \
         `signpdf sign --oidc {provider_name}` logs in inline for each signature."
    );
    Ok(())
}

fn print_status(label: &str, s: &signpdf_core::SignatureStatus) {
    println!(
        "    [{}] {:<9} {} {}  {}",
        s.index,
        label,
        if s.valid { "OK  " } else { "FAIL" },
        &s.actor_fingerprint[..16.min(s.actor_fingerprint.len())],
        s.detail
    );
    if !s.idp_email.is_empty() {
        println!(
            "         identity : {} via {} ({})",
            s.idp_email, s.idp_issuer, s.identity_trust
        );
    }
    if let Some(level) = s.level {
        let basis: Vec<String> = s.basis.iter().map(|b| b.describe()).collect();
        println!(
            "         level    : {level} {} ({})",
            level.name(),
            basis.join("; ")
        );
    }
    println!(
        "         time     : {} ({})   code: {}",
        s.signed_at,
        if s.time_source == "tsa" {
            "trusted timestamp"
        } else {
            "device clock, not independently confirmed"
        },
        s.signature_code
    );
    if s.time_source != "tsa" {
        println!(
            "         bounds   : after {} (identity token issued), before {}",
            if s.token_issued_at.is_empty() {
                "?"
            } else {
                &s.token_issued_at
            },
            match &s.existed_before {
                Some(e) => format!("{} ({})", e.time, existed_before_source(e)),
                None => "? (no trusted timestamp yet)".into(),
            }
        );
    }
    if !s.local_signed_at.is_empty() {
        println!(
            "         local    : {} (the signer's UTC offset {})",
            s.local_signed_at, s.utc_offset
        );
    }
    if let Some(c) = &s.esign_consent {
        println!(
            "         consent  : e-sign disclosure {} ({}), sha256 {}, agreed {}",
            c.version, c.lang, c.sha256, c.at
        );
    }
    if let Some(ts) = &s.timestamp {
        println!("         timestamp: {}", timestamp_line(ts));
    }
}

/// A key's validity window in words, e.g. `from 2026-11-01T00:00:00Z, until 2027-11-01T00:08:00Z`.
fn window_text(w: &signpdf_core::KeyWindow) -> String {
    let mut parts = Vec::new();
    if let Some(t) = &w.not_before {
        parts.push(format!("in use from {t}"));
    }
    if let Some(t) = &w.not_after {
        parts.push(format!("retired at {t}"));
    }
    if let Some(t) = &w.distrusted_after {
        parts.push(format!("distrusted from {t}"));
    }
    parts.join(", ")
}

/// Which trusted timestamp bounds a revision, e.g. `document timestamp 1 by Acme TSA`.
fn existed_before_source(e: &signpdf_core::workflow::ExistedBefore) -> String {
    let which = match (e.source.as_str(), e.revision, e.document_timestamp) {
        ("document", _, Some(d)) => format!("document timestamp {d}"),
        ("later-signature", Some(r), _) => format!("signature timestamp of revision {r}"),
        _ => "its signature timestamp".to_string(),
    };
    format!(
        "{which} by {}",
        if e.tsa_name.is_empty() {
            "?"
        } else {
            &e.tsa_name
        }
    )
}

/// One line about a timestamp: its time, authority, trust and long-term validation.
fn timestamp_line(ts: &signpdf_core::TimestampStatus) -> String {
    format!(
        "{} by {} ({}){}",
        ts.time,
        if ts.tsa_name.is_empty() {
            "?"
        } else {
            &ts.tsa_name
        },
        if ts.is_trusted() {
            "trusted".to_string()
        } else {
            format!("NOT trusted: {}", ts.detail)
        },
        if ts.validation.is_empty() {
            String::new()
        } else {
            format!(", validation data {}", ts.validation)
        }
    )
}

fn print_report(report: &VerificationReport) {
    println!(
        "Verification: {}",
        if report.valid {
            "VALID"
        } else if report.trusted_time_pending {
            "INTACT, WAITING FOR A TRUSTED TIMESTAMP"
        } else if report.integrity_ok {
            "INTACT, BUT IDENTITIES NOT TRUSTED"
        } else {
            "INVALID"
        }
    );
    println!(
        "  integrity : {}",
        if report.integrity_ok { "ok" } else { "FAILED" }
    );
    println!(
        "  identities: {}",
        if report.identities_trusted {
            "trusted"
        } else if report.trusted_time_pending {
            "trusted once a trusted timestamp covers them (none yet)"
        } else {
            "NOT all trusted"
        }
    );
    println!(
        "  status    : {}",
        if report.declined {
            "declined (void)"
        } else if report.complete {
            "complete"
        } else {
            "signatures outstanding"
        }
    );
    println!(
        "  audit log : {}",
        if report.audit_ok { "ok" } else { "BROKEN" }
    );
    println!(
        "  order     : {}",
        if report.order_ok { "ok" } else { "VIOLATED" }
    );
    println!("  sha256    : {}", report.document_sha256);
    if let Some(link) = &report.service_link {
        println!("  open in   : {link}");
    }
    println!("  revisions :");
    if let Some(p) = &report.preparer {
        print_status("prepared", p);
    }
    for s in &report.signatures {
        print_status(&s.kind, s);
    }
    for d in &report.document_timestamps {
        println!(
            "    [doc {}] covers revisions 0-{}{}: {}{}",
            d.index,
            d.after_revision,
            if d.added_validation_data {
                " and validation data"
            } else {
                ""
            },
            timestamp_line(&d.timestamp),
            if d.valid {
                String::new()
            } else {
                format!("  FAIL: {}", d.detail)
            }
        );
    }
    if let Some(v) = &report.validation_data {
        println!(
            "  validation: {} certificate(s), {} OCSP response(s), {} CRL(s)",
            v.certificates, v.ocsp_responses, v.crls
        );
    }
    if !report.pades_level.is_empty() {
        println!("  PAdES     : {}", report.pades_level);
    }
    if let Some(env) = &report.envelope {
        if !env.documents.is_empty() {
            println!(
                "  documents : {} (signed together as one PDF)",
                env.documents.len()
            );
            for (i, d) in env.documents.iter().enumerate() {
                println!(
                    "    {}. {} (pages {}-{}, original sha256 {})",
                    i + 1,
                    d.name,
                    d.first_page + 1,
                    d.first_page + d.page_count,
                    d.source_digest
                );
            }
        }
        println!("  signers   :");
        for signer in &env.signers {
            println!(
                "    - {} <{}> [{}] order {} {:?}",
                signer.name, signer.handle, signer.id, signer.order, signer.status
            );
        }
    }
    // Each finding with its stable code, which the apps translate.
    for f in &report.findings {
        let kind = match f.severity {
            signpdf_core::Severity::Warning => "warning",
            _ => "problem",
        };
        println!("  {kind} [{}]: {}", f.code, f.text);
    }
}

fn cmd_verify(input: &PathBuf, json: bool, trust: &TrustStore) -> Result<()> {
    let bytes = fs::read(input)?;
    let report = verify(&bytes, trust)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
        if report.trusted_time_pending {
            println!(
                "\nhint: these identities count once a trusted timestamp covers their signature: \
                 add a document timestamp (`signpdf timestamp`) before their keys' windows end."
            );
        } else if report.integrity_ok && !report.identities_trusted {
            println!(
                "\nhint: pass --trust <trust.json> (see `signpdf trust init` / `trust refresh`), or \
                 --insecure-dev-trust for documents signed with the bundled `--email` dev login."
            );
        }
    }
    if report.valid {
        Ok(())
    } else {
        Err(anyhow!("verification failed"))
    }
}

fn read_trust(file: &Path) -> Result<TrustStore> {
    TrustStore::from_json(
        &fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?,
    )
    .with_context(|| format!("parsing {}", file.display()))
}

fn write_trust(file: &Path, store: &TrustStore) -> Result<()> {
    fs::write(file, store.to_json()?)?;
    Ok(())
}

/// Decode a certificate from DER or PEM.
fn cert_der(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = String::from_utf8_lossy(bytes);
    if let Some(start) = text.find("-----BEGIN CERTIFICATE-----") {
        let body: String = text[start + 27..]
            .lines()
            .take_while(|l| !l.starts_with("-----END"))
            .collect();
        return signpdf_core::crypto::b64_decode_pub(body.trim())
            .map_err(|e| anyhow!("invalid PEM certificate: {e}"));
    }
    Ok(bytes.to_vec())
}

fn cmd_trust(cmd: TrustCmd) -> Result<()> {
    match cmd {
        TrustCmd::Init { out } => {
            write_trust(&out, &TrustStore::well_known())?;
            println!(
                "Wrote {} (Google, Microsoft, Apple; DigiCert TSA root). Run `signpdf trust refresh \
                 --file {}` to pin the providers' current keys.",
                out.display(),
                out.display()
            );
        }
        TrustCmd::Refresh { file } => {
            let mut store = read_trust(&file)?;
            for (issuer, outcome) in signpdf_auth::refresh_trust_store(&mut store) {
                match outcome {
                    Ok(n) => println!("  {issuer}: {n} new key(s) pinned"),
                    Err(e) => eprintln!("  {issuer}: refresh failed: {e}"),
                }
            }
            write_trust(&file, &store)?;
        }
        TrustCmd::AddJwks { file, issuer, jwks } => {
            let mut store = if file.exists() {
                read_trust(&file)?
            } else {
                TrustStore::empty()
            };
            // With any validity windows the issuer publishes next to its keys.
            let jwks: signpdf_core::PublishedJwks = serde_json::from_slice(&fs::read(&jwks)?)?;
            let n = store.add_published_jwks(&issuer, &jwks)?;
            write_trust(&file, &store)?;
            println!("Pinned {n} new key(s) for {issuer} in {}", file.display());
        }
        TrustCmd::AddAudience {
            file,
            issuer,
            client_id,
        } => {
            let mut store = read_trust(&file)?;
            if store.add_audience(&issuer, &client_id) {
                write_trust(&file, &store)?;
                println!(
                    "{} now trusts sign-ins issued by {issuer} to application {client_id}",
                    file.display()
                );
            } else {
                println!("{client_id} was already trusted for {issuer}");
            }
        }
        TrustCmd::AddTsa { file, cert } => {
            let mut store = read_trust(&file)?;
            store.add_tsa_anchor(&cert_der(&fs::read(&cert)?)?);
            write_trust(&file, &store)?;
            println!("Added TSA anchor {} to {}", cert.display(), file.display());
        }
        TrustCmd::DistrustTsa {
            file,
            cert,
            sha256,
            after,
            name,
        } => {
            let mut store = read_trust(&file)?;
            let hash = match (cert, sha256) {
                (Some(c), _) => signpdf_core::trust::cert_sha256_hex(&cert_der(&fs::read(&c)?)?),
                (None, Some(h)) => h,
                (None, None) => anyhow::bail!("give --cert or --sha256"),
            };
            store.distrust_tsa(&hash, &after, name)?;
            write_trust(&file, &store)?;
            println!(
                "{}: timestamps whose chain holds TSA certificate {hash} no longer count from {after}",
                file.display()
            );
        }
        TrustCmd::Window {
            file,
            issuer,
            key,
            not_before,
            not_after,
            distrusted_after,
        } => {
            let mut store = read_trust(&file)?;
            let window = signpdf_core::KeyWindow {
                not_before,
                not_after,
                distrusted_after,
            };
            store.set_key_window(&issuer, &key, window.clone())?;
            write_trust(&file, &store)?;
            println!(
                "Key {key} of {issuer}: {}",
                if window.is_open() {
                    "no validity window".to_string()
                } else {
                    window_text(&window)
                }
            );
        }
        TrustCmd::RequireTime { file, issuer, off } => {
            let mut store = read_trust(&file)?;
            store.set_requires_trusted_time(&issuer, !off)?;
            write_trust(&file, &store)?;
            println!(
                "{issuer}: tokens {} a trusted timestamp inside their key's window",
                if off { "no longer need" } else { "now need" }
            );
        }
        TrustCmd::Kind {
            file,
            issuer,
            kind,
            clear,
        } => {
            let mut store = read_trust(&file)?;
            let kind = match (kind, clear) {
                (_, true) => None,
                (Some(k), false) => Some(IssuerKind::parse(&k).ok_or_else(|| {
                    anyhow!("unknown kind '{k}' (email-code, account or organization)")
                })?),
                (None, false) => return Err(anyhow!("give --kind or --clear")),
            };
            store.set_issuer_kind(&issuer, kind)?;
            write_trust(&file, &store)?;
            println!(
                "{issuer}: sign-ins count as {}",
                store.issuer_kind(&issuer, None).as_str()
            );
        }
        TrustCmd::AlgorithmPolicy {
            file,
            policy,
            builtin,
        } => {
            let mut store = read_trust(&file)?;
            let policy = match (policy, builtin) {
                (_, true) => None,
                (Some(p), false) => {
                    Some(serde_json::from_slice::<AlgorithmPolicy>(&fs::read(&p)?)?)
                }
                (None, false) => return Err(anyhow!("give --policy or --builtin")),
            };
            store.set_algorithm_policy(policy)?;
            write_trust(&file, &store)?;
            println!(
                "{}: algorithm policy version {} ({})",
                file.display(),
                store.algorithms().version,
                if store.algorithm_policy.is_some() {
                    "from this trust store"
                } else {
                    "the engine's built-in one"
                }
            );
        }
        TrustCmd::Show { file } => {
            let store = read_trust(&file)?;
            for i in &store.issuers {
                println!(
                    "{} ({}, sign-ins count as {}): {} pinned key(s){}{}",
                    i.issuer,
                    if i.name.is_empty() { "-" } else { &i.name },
                    store.issuer_kind(&i.issuer, None).as_str(),
                    i.keys.len(),
                    if i.audiences.is_empty() {
                        ", no trusted application (add one with `trust add-audience`)".to_string()
                    } else {
                        format!(", applications {:?}", i.audiences)
                    },
                    if i.requires_trusted_time {
                        ", tokens need a trusted timestamp"
                    } else {
                        ""
                    }
                );
                for k in &i.keys {
                    println!(
                        "  {} kid {}{}",
                        signpdf_core::trust::jwk_thumbprint(k).unwrap_or_else(|_| "?".into()),
                        k.kid.as_deref().unwrap_or("-"),
                        if k.window.is_open() {
                            String::new()
                        } else {
                            format!(", {}", window_text(&k.window))
                        }
                    );
                }
            }
            println!("TSA anchors: {}", store.tsa_anchors.len());
            for d in &store.tsa_distrusted {
                println!(
                    "  distrusted from {}: TSA certificate {}{}",
                    d.distrusted_after,
                    d.cert_sha256,
                    d.name
                        .as_deref()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default()
                );
            }
            let policy = store.algorithms();
            println!(
                "Algorithm policy: version {} ({})",
                policy.version,
                if store.algorithm_policy.is_some() {
                    "from this trust store"
                } else {
                    "the engine's built-in one"
                }
            );
            for r in &policy.algorithms {
                println!(
                    "  {}{}{}",
                    r.algorithm,
                    r.min_key_bits
                        .map(|b| format!(", keys from {b} bits"))
                        .unwrap_or_default(),
                    r.not_after
                        .as_deref()
                        .map(|t| format!(", until {t} (later only under an earlier timestamp)"))
                        .unwrap_or_default()
                );
            }
            if store.allow_insecure_dev_issuer {
                println!("WARNING: this store trusts the insecure dev issuer");
            }
        }
    }
    Ok(())
}

fn cmd_inspect(input: &PathBuf) -> Result<()> {
    let bytes = fs::read(input)?;
    let env = workflow::read_envelope(&bytes)
        .map_err(|e| anyhow!("no envelope found (not a prepared SignPDF document): {e}"))?;
    println!("{}", serde_json::to_string_pretty(&env)?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_pades_sign(
    input: &PathBuf,
    identity: &PathBuf,
    out: &PathBuf,
    reason: Option<String>,
    location: Option<String>,
    page: u32,
    rect: Option<String>,
) -> Result<()> {
    let pdf = fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let id = load_identity(identity, false)?;
    let kp = id.key_pair()?;
    let app = SignAppearance {
        name: id.name.clone(),
        reason,
        location,
        page_index: page,
        rect: parse_rect(rect)?,
        caption: None,
        ink: None,
    };
    let signed = pades_sign(&pdf, &kp, &app, None)?;
    fs::write(out, &signed)?;
    println!(
        "PAdES-signed as {} -> {} ({} bytes)",
        id.name,
        out.display(),
        signed.len()
    );
    println!(
        "Validate with: signpdf pades-verify --input {}",
        out.display()
    );
    Ok(())
}

fn cmd_pades_verify(input: &PathBuf) -> Result<()> {
    let pdf = fs::read(input)?;
    let scan = pades_verify_all(&pdf)?;
    let results = scan.signatures;
    if results.is_empty() {
        println!("No PAdES signatures found in {}.", input.display());
        return Ok(());
    }
    let mut all_ok = true;
    println!("Found {} PAdES signature(s):", results.len());
    for r in &results {
        let ok = r.is_valid();
        all_ok &= ok;
        println!("\n  field         : {}", r.field_name);
        println!("  signer (CN)   : {}", r.signer_cn);
        println!("  SubFilter     : {}", r.sub_filter);
        println!("  ByteRange     : {:?}", r.byte_range);
        if let Some(e) = &r.structure_error {
            println!("  structure     : MALFORMED ({e})");
        }
        println!("  digest match  : {}", r.digest_matches);
        println!(
            "  signature     : {}",
            if r.signature_valid {
                "valid"
            } else {
                "INVALID"
            }
        );
        println!(
            "  timestamp     : {}",
            if r.signature_timestamp.is_some() {
                "signature timestamp present (B-T)"
            } else {
                "none (B-B)"
            }
        );
        if r.covers_to_eof {
            println!("  coverage      : whole file");
        } else {
            println!("  coverage      : up to its own update (a later revision follows)");
        }
        println!("  result        : {}", if ok { "VALID" } else { "INVALID" });
    }
    for d in &scan.document_timestamps {
        let ok = d.is_valid();
        all_ok &= ok;
        println!("\n  field         : {} (document timestamp)", d.field_name);
        println!("  ByteRange     : {:?}", d.byte_range);
        if let Some(e) = &d.structure_error {
            println!("  structure     : MALFORMED ({e})");
        }
        println!("  digest match  : {}", d.digest_matches);
        println!("  result        : {}", if ok { "VALID" } else { "INVALID" });
    }
    if let Some(dss) = &scan.dss {
        println!(
            "\n  validation data (DSS): {} certificate(s), {} OCSP response(s), {} CRL(s)",
            dss.certs.len(),
            dss.ocsps.len(),
            dss.crls.len()
        );
    }
    let last_end = results
        .iter()
        .map(|r| r.covered_end)
        .chain(scan.document_timestamps.iter().map(|d| d.covered_end))
        .max()
        .unwrap_or(0);
    if last_end != pdf.len() {
        all_ok = false;
        println!(
            "\n  WARNING: bytes were appended after the last signature or document timestamp \
             (unsigned changes)"
        );
    }
    if all_ok {
        Ok(())
    } else {
        Err(anyhow!("one or more PAdES signatures did not validate"))
    }
}

fn parse_rect(rect: Option<String>) -> Result<Option<[f32; 4]>> {
    let Some(s) = rect else { return Ok(None) };
    let parts: std::result::Result<Vec<f32>, _> =
        s.split(',').map(|p| p.trim().parse::<f32>()).collect();
    let parts = parts.map_err(|e| anyhow!("bad --rect '{s}': {e}"))?;
    if parts.len() != 4 {
        return Err(anyhow!(
            "--rect needs 4 comma-separated numbers: x1,y1,x2,y2"
        ));
    }
    Ok(Some([parts[0], parts[1], parts[2], parts[3]]))
}

fn cmd_demo(out_dir: Option<PathBuf>) -> Result<()> {
    let dir = out_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("signpdf-demo-{}", std::process::id()))
    });
    fs::create_dir_all(&dir)?;
    println!("Demo working directory: {}\n", dir.display());
    let trust = TrustStore::insecure_dev();

    let alice_email = "alice@example.com";
    let bob_email = "bob@example.com";
    println!("Preparer / signer 1 : {alice_email} (dev federated identity, an account: L2)");
    println!(
        "Signer 2            : {bob_email} (dev federated identity, an organization account \
         of example.com: L3)\n"
    );

    let pdf = container::make_sample_pdf("Mutual NDA between Alice and Bob");
    fs::write(dir.join("source.pdf"), &pdf)?;

    let preparer_key = KeyPair::generate();
    let prep_dev = mint_dev_identity(&preparer_key, &sha256_hex(&pdf), alice_email, false)?;
    let request = PrepareRequest {
        title: "Mutual NDA".into(),
        signers: vec![
            SignerSpec {
                id: "s1".into(),
                name: "Alice Example".into(),
                handle: alice_email.into(),
                role: "Disclosing Party".into(),
                order: 1,
                identity_policy: consumer_policy(alice_email),
            },
            SignerSpec {
                id: "s2".into(),
                name: "Bob Builder".into(),
                handle: bob_email.into(),
                role: "Receiving Party".into(),
                order: 2,
                // Bob's slot asks for an organization identity of example.com (L3): his
                // company's Google Workspace account, not a personal one.
                identity_policy: IdentityPolicy {
                    required_domain: Some("example.com".into()),
                    min_level: Level::L3,
                    required_methods: vec![Method::Organization],
                    ..consumer_policy(bob_email)
                },
            },
        ],
        fields: vec![
            demo_field("f1", "s1", FieldType::Signature, 120.0),
            // A "date signed" field: the engine writes Alice's local date, drawn day first.
            Field {
                date_format: Some(DateFormat::DayMonthYearSlash),
                signing_date: true,
                ..demo_field("d1", "s1", FieldType::Date, 180.0)
            },
            demo_field("f2", "s2", FieldType::Signature, 260.0),
            demo_field("t2", "s2", FieldType::Text, 320.0),
            demo_choice(
                "accept",
                FieldType::Checkbox,
                None,
                "I have read and accept this NDA",
                380.0,
            ),
            demo_choice(
                "copy-email",
                FieldType::Radio,
                Some("Send my copy"),
                "By email",
                430.0,
            ),
            demo_choice(
                "copy-post",
                FieldType::Radio,
                Some("Send my copy"),
                "By post",
                408.0,
            ),
            Field {
                rect: Rect {
                    x: 72.0,
                    y: 470.0,
                    w: 240.0,
                    h: 44.0,
                },
                required: false,
                label: Some("Delivery notes".to_string()),
                ..demo_field("notes", "s2", FieldType::Multiline, 470.0)
            },
            Field {
                label: Some("Copy format".to_string()),
                options: Some(vec!["Paper".to_string(), "PDF".to_string()]),
                ..demo_field("format", "s2", FieldType::Dropdown, 530.0)
            },
            // A date Bob picks, drawn month first whatever his locale.
            Field {
                label: Some("Start date".to_string()),
                date_format: Some(DateFormat::MonthDayYearSlash),
                ..demo_field("start", "s2", FieldType::Date, 590.0)
            },
            // An amount Bob types: kept with the two decimal places of euros, at most 1,000,000,
            // drawn "EUR 12 500,00" whatever his locale.
            Field {
                label: Some("Annual fee".to_string()),
                number_format: Some(NumberFormat {
                    decimals: 2,
                    min: Some("0".into()),
                    max: Some("1000000".into()),
                    style: NumberStyle::SpaceComma,
                    currency: Some("EUR".into()),
                }),
                ..demo_field("fee", "s2", FieldType::Number, 650.0)
            },
            // Checks on text fields (schema version 8): an email address stored canonically
            // (its domain in lower case) of at most 80 characters, an employer number drawn
            // masked, and an order reference matching the preparer's own pattern, with the
            // preparer's message for a value it refuses.
            Field {
                label: Some("Notices to (email)".to_string()),
                value_format: Some(ValueFormat::of(ValueFormatKind::Email)),
                length: Some(LengthRule {
                    min: None,
                    max: Some(80),
                }),
                ..demo_text("notice-email", 320.0)
            },
            Field {
                label: Some("Employer ID (EIN)".to_string()),
                value_format: Some(ValueFormat::of(ValueFormatKind::UsEin)),
                ..demo_text("ein", 380.0)
            },
            Field {
                label: Some("Purchase order".to_string()),
                value_format: Some(ValueFormat {
                    pattern: Some(DEMO_ORDER_PATTERN.to_string()),
                    ..ValueFormat::of(ValueFormatKind::Pattern)
                }),
                check_message: Some("Write the order number as PO-2026-123.".to_string()),
                ..demo_text("po", 440.0)
            },
            // A formula field (schema version 8): the number of seats Bob types times the annual
            // fee, plus the delivery cost of the copy format and of how the copy is sent (a
            // dropdown and a radio group, read through the numbers the preparer gave their
            // options). Bob types nothing in it: the engine computes and draws it when he signs,
            // and the verifier computes it again.
            Field {
                label: Some("Seats".to_string()),
                number_format: Some(NumberFormat {
                    decimals: 0,
                    min: Some("1".into()),
                    max: Some("500".into()),
                    ..NumberFormat::default()
                }),
                field_type: FieldType::Number,
                ..demo_text("seats", 500.0)
            },
            Field {
                label: Some("Total".to_string()),
                number_format: Some(NumberFormat {
                    decimals: 2,
                    style: NumberStyle::SpaceComma,
                    currency: Some("EUR".into()),
                    ..NumberFormat::default()
                }),
                formula: Some(FormulaSpec {
                    expr: "{seats} * {fee} + {format} + {Send my copy}".into(),
                    map: [
                        ("format", [("Paper", "25"), ("PDF", "0")]),
                        ("Send my copy", [("By email", "0"), ("By post", "10")]),
                    ]
                    .into_iter()
                    .map(|(choice, numbers)| {
                        let numbers = numbers
                            .into_iter()
                            .map(|(o, n)| (o.to_string(), n.to_string()))
                            .collect();
                        (choice.to_string(), numbers)
                    })
                    .collect(),
                }),
                field_type: FieldType::Formula,
                ..demo_text("total", 560.0)
            },
        ],
        // Every signer revision gets a signature timestamp, as on an envelope a hosted service
        // sends with timestamps (part 4 below shows an envelope that takes none).
        policy: Policy {
            signing_order: SigningOrder::Sequential,
            allowed_signature_types: vec!["PAdES".into()],
            expiry: None,
            signature_timestamps: TimestampPolicy::Required,
        },
        id_token: prep_dev.id_token,
        idp_jwk: prep_dev.idp_jwk,
        audience: DEV_AUDIENCE.to_string(),
        allowed_issuers: vec![DEV_ISSUER.to_string()],
        // Outside the prepared terms: an "open in ..." link back to the sending service.
        service_link: Some(DEMO_SERVICE_LINK.to_string()),
        documents: Vec::new(),
        // Drawn on the document-ID stamp: "Verify at verify.example.com".
        verify_at: Some(DEMO_VERIFY_AT.to_string()),
    };

    let prepared = prepare(&pdf, &request, &preparer_key)?;
    fs::write(dir.join("prepared.pdf"), &prepared)?;
    println!(
        "1. Prepared and preparer-signed the NDA for two sequential signers, with signature \
         timestamps required and a link back to the sending service."
    );

    // The (untrusted) test TSA that timestamps both signatures, issued by a test root CA that
    // also answers for it (OCSP and CRL, part 5). The root is the timestamps' trust anchor,
    // tsa.der.
    let ca = TestCa::new("SignPDF Demo Root");
    let tsa = ca.issue_tsa("SignPDF Demo TSA");
    fs::write(dir.join("tsa.der"), ca.cert_der())?;

    // Alice signs: her slot is auto-resolved from the verified identity (no self-selection). Her
    // signature timestamp is added in one step, as a native app with a synchronous TSA client
    // does.
    // She signs in Tokyo (UTC+09:00) after agreeing to the demo's e-sign disclosure in English.
    let alice_key = KeyPair::generate();
    let alice_dev = mint_dev_identity(&alice_key, &sha256_hex(&prepared), alice_email, false)?;
    let mut alice_req = dev_sign_request(alice_dev);
    alice_req.utc_offset_minutes = Some(9 * 60);
    alice_req.esign_consent = Some(demo_consent("en")?);
    // She types her signature: the glyph outlines of her name, filled in her signature box beside
    // her verified identity. (The demo's font is the engine's test font, whose glyphs are plain
    // shapes; a host ships handwriting-style fonts.)
    alice_req.typed_signature = Some(
        typed_signature(&signpdf_core::ink::typed::testing::font(), "Alice Example")
            .map_err(|e| anyhow!("{e}"))?,
    );
    let after_alice = sign_with(&prepared, &alice_key, &alice_req, Some(&tsa))?;
    fs::write(dir.join("signed-by-alice.pdf"), &after_alice)?;
    println!(
        "2. Alice signed (auto-resolved to slot s1; her date-signed field filled with her local \
         date at UTC+09:00, her consent to the e-sign disclosure recorded, her typed signature \
         drawn as filled outlines) with a signature timestamp from the test TSA (its root: \
         tsa.der)."
    );

    // Bob signing before Alice would be rejected — demonstrate the order guard.
    let bob_key_oo = KeyPair::generate();
    let bob_dev_oo = mint_dev_identity(&bob_key_oo, &sha256_hex(&prepared), bob_email, true)?;
    let out_of_order = sign_with(&prepared, &bob_key_oo, &dev_sign_request(bob_dev_oo), None);
    println!(
        "   (out-of-order attempt by Bob on the fresh doc was correctly {})",
        if out_of_order.is_err() {
            "rejected"
        } else {
            "ALLOWED?!"
        }
    );

    let bob_key = KeyPair::generate();
    let bob_dev = mint_dev_identity(&bob_key, &sha256_hex(&after_alice), bob_email, true)?;
    let mut bob_req = dev_sign_request(bob_dev);
    bob_req.field_values = vec![
        ("t2".into(), "Bob Builder Ltd".into()),
        ("accept".into(), "true".into()),
        ("copy-email".into(), "true".into()),
        (
            "notes".into(),
            "Please send the countersigned copy to our legal team.\nOffice hours: 9 to 5.".into(),
        ),
        ("format".into(), "PDF".into()),
        ("start".into(), "2026-12-01".into()),
        // The canonical form: his page read "12 500" in his locale.
        ("fee".into(), "12500".into()),
        // Stored as Legal@bob.example, 12-3456789 (drawn masked) and as typed.
        ("notice-email".into(), "Legal@Bob.EXAMPLE".into()),
        ("ein".into(), "123456789".into()),
        ("po".into(), "PO-2026-118".into()),
        // The total (formula field "total") is computed: 3 x 12 500,00 + 0 + 0, drawn
        // "EUR 37 500,00".
        ("seats".into(), "3".into()),
    ];
    // Bob also draws his signature; it goes in his signature box, beside his verified identity.
    bob_req.drawn_signature = Some(demo_ink());
    // He signs in New York (UTC-05:00) after agreeing to the French text of the disclosure.
    bob_req.utc_offset_minutes = Some(-5 * 60);
    bob_req.esign_consent = Some(demo_consent("fr")?);
    // Bob's signature timestamp is added in two steps, as the browser signer does: sign with room
    // for it, then embed the token.
    let bob_signed = sign_for_timestamp(&after_alice, &bob_key, &bob_req)?;
    let digest = signature_timestamp_digest(&bob_signed)?;
    let response = tsa.respond(&signpdf_core::timestamp::build_request(&digest))?;
    let token = signpdf_core::timestamp::parse_response(&response, &digest)?.token_der;
    let after_bob = embed_signature_timestamp(&bob_signed, &token)?;
    fs::write(dir.join("signed-final.pdf"), &after_bob)?;
    println!(
        "3. Bob signed, filled his fields and got a signature timestamp from the test TSA in two \
         steps. Document is complete.\n"
    );

    // The demo trusts its own test TSA's root, so both signing times come from the timestamps.
    let mut trust = trust;
    trust.add_tsa_anchor(&ca.cert_der());
    let report = verify(&after_bob, &trust)?;
    print_report(&report);
    let evidence_ok = demo_evidence_ok(&report);
    fs::write(
        dir.join("certificate.pdf"),
        completion_certificate(&after_bob, &trust)?,
    )?;
    println!("\nWrote a certificate of completion to certificate.pdf");

    // Without the insecure dev opt-in, dev identities are (correctly) not trusted.
    let strict = verify(&after_bob, &TrustStore::well_known())?;

    // Tamper demonstration 1: flip one signed byte.
    let mut tampered = after_bob.clone();
    tampered[20] ^= 0xFF;
    let tampered_report = verify(&tampered, &trust)?;
    // Tamper demonstration 2: append an unsigned update that rewrites the envelope.
    let mut env = workflow::read_envelope(&after_bob)?;
    env.title = "A completely different agreement".into();
    let appended = signpdf_core::pades::embed_attachment(
        &after_bob,
        &signpdf_core::EmbeddedFile {
            name: workflow::ENVELOPE_NAME.into(),
            data: serde_json::to_vec(&env)?,
            mime: "application/json".into(),
            relationship: "Data".into(),
            description: "tampered".into(),
        },
    )?;
    let appended_report = verify(&appended, &trust)?;

    println!(
        "\nWithout trusting the dev issuer: {} (identities untrusted ✓)",
        if strict.valid { "VALID?!" } else { "NOT VALID" }
    );
    println!(
        "After flipping one document byte: {} (tamper detected ✓)",
        if tampered_report.valid {
            "VALID?!"
        } else {
            "INVALID"
        }
    );
    println!(
        "After appending an unsigned envelope rewrite: {} (detected ✓)",
        if appended_report.valid {
            "VALID?!"
        } else {
            "INVALID"
        }
    );

    let no_timestamps_ok = demo_no_timestamps(&dir, &pdf, &request, &tsa, &trust)?;
    let ltv_ok = demo_ltv(&dir, &after_bob, &ca, &tsa, &trust)?;
    let documents_ok = demo_documents(&dir, &tsa, &trust)?;

    println!("\nArtifacts written to {}", dir.display());
    let every_time_from_tsa = report.signatures.len() == 2
        && report.signatures.iter().all(|s| s.time_source == "tsa")
        && !report
            .warnings
            .iter()
            .any(|w| w.contains("signature timestamp"));
    if report.valid
        && every_time_from_tsa
        && evidence_ok
        && !strict.valid
        && !tampered_report.valid
        && !appended_report.valid
        && no_timestamps_ok
        && ltv_ok
        && documents_ok
    {
        Ok(())
    } else {
        Err(anyhow!("demo invariants failed"))
    }
}

/// A demo document: `pages` pages of `size` (width, height in points), each titled `title`.
fn demo_pdf(title: &str, pages: usize, size: (u32, u32)) -> Vec<u8> {
    let esc = |s: &str| {
        s.replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)")
    };
    // 1: catalog, 2: page tree, 3: font, then a page and its content per page.
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        format!(
            "<< /Type /Pages /Kids [{}] /Count {pages} /MediaBox [0 0 {} {}] \
             /Resources << /Font << /F1 3 0 R >> >> >>",
            (0..pages)
                .map(|i| format!("{} 0 R", 4 + 2 * i))
                .collect::<Vec<_>>()
                .join(" "),
            size.0,
            size.1
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    for i in 0..pages {
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /Contents {} 0 R >>",
            5 + 2 * i
        ));
        let content = format!(
            "BT /F1 20 Tf 72 {} Td ({}) Tj ET\nBT /F1 11 Tf 72 {} Td (Page {} of {pages}) Tj ET\n",
            size.1 - 92,
            esc(title),
            size.1 - 116,
            i + 1
        );
        objects.push(format!(
            "<< /Length {} >>\nstream\n{content}endstream",
            content.len()
        ));
    }
    let mut buf = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(buf.len());
        buf.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }
    let xref = buf.len();
    buf.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for off in offsets {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    buf
}

/// Demo part 6: an envelope of three documents (a two-page agreement and two schedules, one of
/// them A4), combined into one PDF with a documents index and signed by Alice and Bob in
/// parallel, each with fields in two of the documents and a signature timestamp. Writes
/// `prepared-documents.pdf`, `signed-documents.pdf` and a convenience copy of the second
/// document; returns whether everything behaved.
fn demo_documents(dir: &std::path::Path, tsa: &TestTsa, trust: &TrustStore) -> Result<bool> {
    let alice_email = "alice@example.com";
    let bob_email = "bob@example.com";
    let agreement = demo_pdf("Master services agreement", 2, (612, 792));
    let fees = demo_pdf("Schedule A: fees", 1, (612, 792));
    let processing = demo_pdf("Schedule B: data processing", 2, (595, 842));
    let combined = combine_documents(&[
        SourceDocument {
            name: "Master services agreement.pdf",
            pdf: &agreement,
        },
        SourceDocument {
            name: "Schedule A - fees.pdf",
            pdf: &fees,
        },
        SourceDocument {
            name: "Schedule B - data processing.pdf",
            pdf: &processing,
        },
    ])?;
    let on_page = |field: Field, page: u32| Field { page, ..field };

    let preparer_key = KeyPair::generate();
    let prep_dev = mint_dev_identity(
        &preparer_key,
        &sha256_hex(&combined.pdf),
        alice_email,
        false,
    )?;
    let request = PrepareRequest {
        title: "Services agreement with schedules".into(),
        signers: vec![
            SignerSpec {
                id: "s1".into(),
                name: "Alice Example".into(),
                handle: alice_email.into(),
                role: "Provider".into(),
                order: 1,
                identity_policy: consumer_policy(alice_email),
            },
            SignerSpec {
                id: "s2".into(),
                name: "Bob Builder".into(),
                handle: bob_email.into(),
                role: "Customer".into(),
                order: 1,
                identity_policy: consumer_policy(bob_email),
            },
        ],
        fields: vec![
            // The agreement's second page, the fees schedule, the last page of Schedule B.
            on_page(
                demo_field("alice-sign", "s1", FieldType::Signature, 120.0),
                1,
            ),
            on_page(demo_field("bob-sign", "s2", FieldType::Signature, 200.0), 1),
            on_page(
                demo_field("alice-initials", "s1", FieldType::Initials, 300.0),
                2,
            ),
            on_page(
                demo_field("bob-initials", "s2", FieldType::Initials, 360.0),
                2,
            ),
            on_page(
                Field {
                    label: Some("Customer reference".into()),
                    ..demo_field("bob-ref", "s2", FieldType::Text, 420.0)
                },
                4,
            ),
        ],
        policy: Policy {
            signing_order: SigningOrder::Parallel,
            allowed_signature_types: vec!["PAdES".into()],
            expiry: None,
            signature_timestamps: TimestampPolicy::Required,
        },
        id_token: prep_dev.id_token,
        idp_jwk: prep_dev.idp_jwk,
        audience: DEV_AUDIENCE.to_string(),
        allowed_issuers: vec![DEV_ISSUER.to_string()],
        service_link: Some(DEMO_SERVICE_LINK.to_string()),
        documents: combined.documents.clone(),
        verify_at: Some(DEMO_VERIFY_AT.to_string()),
    };
    let prepared = prepare(&combined.pdf, &request, &preparer_key)?;
    fs::write(dir.join("prepared-documents.pdf"), &prepared)?;

    let bob_key = KeyPair::generate();
    let bob_dev = mint_dev_identity(&bob_key, &sha256_hex(&prepared), bob_email, false)?;
    let mut bob_req = dev_sign_request(bob_dev);
    bob_req.field_values = vec![("bob-ref".into(), "PO-2026-118".into())];
    let after_bob = sign_with(&prepared, &bob_key, &bob_req, Some(tsa))?;
    let alice_key = KeyPair::generate();
    let alice_dev = mint_dev_identity(&alice_key, &sha256_hex(&after_bob), alice_email, false)?;
    let signed = sign_with(
        &after_bob,
        &alice_key,
        &dev_sign_request(alice_dev),
        Some(tsa),
    )?;
    fs::write(dir.join("signed-documents.pdf"), &signed)?;

    let report = verify(&signed, trust)?;
    let index_kept = report
        .envelope
        .as_ref()
        .is_some_and(|e| e.documents == combined.documents);
    let copy = extract_document(&signed, 1)?;
    let copy_name = convenience_copy_name(&combined.documents[1]);
    fs::write(dir.join(&copy_name), &copy)?;
    let copy_ok = signpdf_core::pades::page_geometry(&copy)?.len() == 1
        && signpdf_core::pades::pades_verify(&copy)?.is_empty();
    println!(
        "\n6. Envelope of {} documents ({} pages), combined into one PDF with a documents index, \
         signed by Bob and Alice in parallel: {}{}. Convenience copy of document 2: {copy_name}.",
        combined.documents.len(),
        combined.documents.iter().map(|d| d.page_count).sum::<u32>(),
        if report.valid { "VALID" } else { "INVALID?!" },
        if index_kept { "" } else { " (index LOST?!)" },
    );
    Ok(report.valid && report.complete && index_kept && copy_ok)
}

/// Demo part 4: the NDA prepared with `signature_timestamps = none`. Alice's signature is dated by
/// her device clock, and the engine refuses a signature timestamp. Writes
/// `prepared-no-timestamps.pdf` and `signed-no-timestamps.pdf`; returns whether everything
/// behaved.
fn demo_no_timestamps(
    dir: &std::path::Path,
    source: &[u8],
    paid: &PrepareRequest,
    tsa: &TestTsa,
    trust: &TrustStore,
) -> Result<bool> {
    let alice_email = "alice@example.com";
    let preparer_key = KeyPair::generate();
    let prep_dev = mint_dev_identity(&preparer_key, &sha256_hex(source), alice_email, false)?;
    let request = PrepareRequest {
        policy: Policy {
            signature_timestamps: TimestampPolicy::None,
            ..paid.policy.clone()
        },
        id_token: prep_dev.id_token,
        idp_jwk: prep_dev.idp_jwk,
        ..paid.clone()
    };
    let prepared = prepare(source, &request, &preparer_key)?;
    fs::write(dir.join("prepared-no-timestamps.pdf"), &prepared)?;

    let alice_key = KeyPair::generate();
    let alice_dev = mint_dev_identity(&alice_key, &sha256_hex(&prepared), alice_email, false)?;
    let req = dev_sign_request(alice_dev);
    // A timestamp, at once or afterwards, is refused before anything is signed.
    let refused = sign_with(&prepared, &alice_key, &req, Some(tsa)).is_err()
        && sign_for_timestamp(&prepared, &alice_key, &req).is_err();
    let signed = sign_with(&prepared, &alice_key, &req, None)?;
    let refused = refused && signature_timestamp_digest(&signed).is_err();
    fs::write(dir.join("signed-no-timestamps.pdf"), &signed)?;

    let report = verify(&signed, trust)?;
    let device_time = report
        .signatures
        .iter()
        .all(|s| s.time_source == "device" && s.timestamp.is_none());

    // And with the policy that leaves it to each signer's host (`optional`): Alice's host adds a
    // signature timestamp.
    let optional_key = KeyPair::generate();
    let optional_dev = mint_dev_identity(&optional_key, &sha256_hex(source), alice_email, false)?;
    let optional_request = PrepareRequest {
        policy: Policy {
            signature_timestamps: TimestampPolicy::Optional,
            ..paid.policy.clone()
        },
        id_token: optional_dev.id_token,
        idp_jwk: optional_dev.idp_jwk,
        ..paid.clone()
    };
    let optional = prepare(source, &optional_request, &optional_key)?;
    let alice_key = KeyPair::generate();
    let alice_dev = mint_dev_identity(&alice_key, &sha256_hex(&optional), alice_email, false)?;
    let optional_signed = sign_with(
        &optional,
        &alice_key,
        &dev_sign_request(alice_dev),
        Some(tsa),
    )?;
    fs::write(dir.join("signed-optional-timestamps.pdf"), &optional_signed)?;
    let optional_report = verify(&optional_signed, trust)?;
    let optional_ok = optional_report.valid
        && optional_report
            .signatures
            .iter()
            .all(|s| s.timestamp.is_some());

    println!(
        "\n4. The same NDA prepared with signature timestamps set to none: Alice signed, dated by \
         her device clock; a signature timestamp was {} (prepared-no-timestamps.pdf, \
         signed-no-timestamps.pdf). Prepared with them optional, Alice's host added one \
         (signed-optional-timestamps.pdf).",
        if refused { "refused" } else { "ACCEPTED?!" }
    );
    Ok(refused && device_time && report.valid && optional_ok)
}

/// Demo part 5: what a hosted service adds when envelopes end. The completed NDA gets validation
/// data for its signature timestamps (the TSA's certificate chain and an OCSP response from the
/// test CA) and a document timestamp over it: PAdES B-LTA, `signed-ltv.pdf`. The envelope that
/// takes no signature timestamps gets one document timestamp, its trusted time:
/// `sealed-no-timestamps.pdf`. Returns whether everything behaved.
fn demo_ltv(
    dir: &std::path::Path,
    completed: &[u8],
    ca: &TestCa,
    tsa: &TestTsa,
    trust: &TrustStore,
) -> Result<bool> {
    let targets = revocation_targets(completed, trust)?;
    let ocsps: Vec<Vec<u8>> = targets
        .iter()
        .map(|t| ca.ocsp_response(&t.cert, TestStatus::Good))
        .collect();
    let with_data = add_validation_data(completed, trust, &ocsps, &[])?;
    let sealed = add_document_timestamp(&with_data, tsa)?;
    fs::write(dir.join("signed-ltv.pdf"), &sealed)?;
    let report = verify(&sealed, trust)?;
    println!(
        "\n5. At completion, validation data for the signature timestamps ({} OCSP response(s) \
         from the test CA) and a document timestamp over it: PAdES {} (signed-ltv.pdf).",
        ocsps.len(),
        report.pades_level
    );

    let free = fs::read(dir.join("signed-no-timestamps.pdf"))?;
    let stamped = add_document_timestamp(&free, tsa)?;
    fs::write(dir.join("sealed-no-timestamps.pdf"), &stamped)?;
    let free_report = verify(&stamped, trust)?;
    println!(
        "   The envelope without signature timestamps got one document timestamp: PAdES {} \
         (sealed-no-timestamps.pdf).",
        free_report.pades_level
    );
    // Its signing times stay the device clocks; the document timestamp bounds them. A verifier
    // whose provider needs trusted time (as a service's own email-code provider does) waits for
    // it.
    let bounded = free_report
        .preparer
        .iter()
        .chain(&free_report.signatures)
        .all(|s| {
            s.time_source == "device"
                && s.existed_before
                    .as_ref()
                    .is_some_and(|e| e.source == "document")
        });
    let strict = pinned_requiring_time(&stamped, trust)?;
    let waiting = verify(&free, &strict)?;
    let strict_sealed = verify(&stamped, &strict)?;
    println!(
        "   Every signature existed before {} (the document timestamp). A verifier whose \
         provider needs trusted time: before it, {}; after it, {}.",
        free_report
            .signatures
            .last()
            .and_then(|s| s.existed_before.as_ref())
            .map_or("?", |e| e.time.as_str()),
        if waiting.trusted_time_pending {
            "waiting for a trusted timestamp"
        } else {
            "NOT WAITING?!"
        },
        if strict_sealed.valid {
            "valid"
        } else {
            "NOT VALID?!"
        }
    );

    // Anything else riding along with a document timestamp fails: here an envelope rewrite.
    let mut env = workflow::read_envelope(&sealed)?;
    env.title = "A completely different agreement".into();
    let forged = signpdf_core::pades::add_document_timestamp(
        &signpdf_core::pades::embed_attachment(
            &sealed,
            &signpdf_core::EmbeddedFile {
                name: workflow::ENVELOPE_NAME.into(),
                data: serde_json::to_vec(&env)?,
                mime: "application/json".into(),
                relationship: "Data".into(),
                description: "tampered".into(),
            },
        )?,
        tsa,
    )?;
    let forged_report = verify(&forged, trust)?;
    println!(
        "   An envelope rewrite under a later document timestamp: {} (detected ✓)",
        if forged_report.valid {
            "VALID?!"
        } else {
            "INVALID"
        }
    );
    Ok(report.valid
        && report.pades_level == "B-LTA"
        && free_report.valid
        && free_report.pades_level == "B-T"
        && bounded
        && waiting.trusted_time_pending
        && strict_sealed.valid
        && free_report
            .document_timestamps
            .iter()
            .all(|d| d.timestamp.is_trusted())
        && !forged_report.valid)
}

/// A store that pins the dev identity keys `pdf` embeds (no insecure opt-in), with `trust`'s
/// TSA anchors, and counts the dev issuer's tokens only with trusted time: how a verifier treats
/// a service's own email-code provider.
fn pinned_requiring_time(pdf: &[u8], trust: &TrustStore) -> Result<TrustStore> {
    let env = workflow::read_envelope(pdf)?;
    let mut store = TrustStore {
        tsa_anchors: trust.tsa_anchors.clone(),
        tsa_distrusted: trust.tsa_distrusted.clone(),
        ..TrustStore::empty()
    };
    let jwks =
        std::iter::once(&env.created_by_idp_jwk).chain(env.signatures.iter().map(|r| &r.idp_jwk));
    for jwk in jwks {
        let jwk: signpdf_core::Jwk = serde_json::from_str(jwk)?;
        store.add_jwks(DEV_ISSUER, &Jwks { keys: vec![jwk] });
    }
    store.add_audience(DEV_ISSUER, DEV_AUDIENCE);
    store.set_requires_trusted_time(DEV_ISSUER, true)?;
    Ok(store)
}

/// The demo's link back to the (fictional) service that sent the NDA.
const DEMO_SERVICE_LINK: &str = "https://sign.example.com/envelopes/demo-nda";

/// The demo's 'verify at' address, drawn on its document-ID stamps.
const DEMO_VERIFY_AT: &str = "verify.example.com";

/// The demo's stand-in for an e-sign disclosure, in its English reference text and a French
/// translation.
const DEMO_DISCLOSURE_EN: &str = "SignPDF demo disclosure: you agree to use electronic records \
    and signatures for this document. You may ask the sender for a paper copy.";
const DEMO_DISCLOSURE_FR: &str = "Information de démonstration SignPDF : vous acceptez les \
    documents et signatures électroniques pour ce document. Vous pouvez en demander une copie \
    papier à l'expéditeur.";

/// A signer's consent to the demo disclosure in `lang` (`en` or `fr`), agreed a minute ago.
fn demo_consent(lang: &str) -> Result<EsignConsent> {
    let shown = if lang == "fr" {
        DEMO_DISCLOSURE_FR
    } else {
        DEMO_DISCLOSURE_EN
    };
    let reference = sha256_hex(DEMO_DISCLOSURE_EN.as_bytes());
    Ok(EsignConsent {
        version: "demo-1".to_string(),
        lang: lang.to_string(),
        sha256: sha256_hex(shown.as_bytes()),
        ref_sha256: (lang != "en").then_some(reference),
        at: signpdf_core::dates::utc_rfc3339(cli_now_unix() - 60)
            .ok_or_else(|| anyhow!("the clock is out of range"))?,
    })
}

/// The evidence the demo's signers left: the service link, each signer's local time and consent,
/// and Alice's date-signed field holding her local date. Prints what it found.
fn demo_evidence_ok(report: &VerificationReport) -> bool {
    let Some(env) = &report.envelope else {
        return false;
    };
    let alice = report.signatures.iter().find(|s| s.signer_id == "s1");
    let local_date = alice.and_then(|s| s.local_signed_at.get(..10));
    let d1 = env.fields.iter().find(|f| f.id == "d1");
    let date_ok = d1.is_some_and(|f| f.value.as_deref() == local_date && local_date.is_some());
    let consents_ok = report.signatures.iter().all(|s| s.esign_consent.is_some());
    let fee = env.fields.iter().find(|f| f.id == "fee");
    let number_ok = fee.is_some_and(|f| f.value.as_deref() == Some("12500.00"));
    let value = |id: &str| {
        env.fields
            .iter()
            .find(|f| f.id == id)
            .and_then(|f| f.value.as_deref())
    };
    let text_ok = value("notice-email") == Some("Legal@bob.example")
        && value("ein") == Some("12-3456789")
        && value("po") == Some("PO-2026-118");
    let verify_at_ok = env.verify_at.as_deref() == Some(DEMO_VERIFY_AT);
    let codes_ok = report.findings.len() == report.messages.len() + report.warnings.len();
    let offsets_ok = report.signatures.iter().all(|s| !s.utc_offset.is_empty());
    println!(
        "\nEvidence: Alice's date-signed field holds {} (her local date at {}); consent \
         recorded for {} of {} signers; open-in link {}.",
        d1.and_then(|f| f.value.as_deref()).unwrap_or("nothing"),
        alice.map(|s| s.utc_offset.as_str()).unwrap_or("?"),
        report
            .signatures
            .iter()
            .filter(|s| s.esign_consent.is_some())
            .count(),
        report.signatures.len(),
        report.service_link.as_deref().unwrap_or("MISSING")
    );
    date_ok
        && number_ok
        && text_ok
        && verify_at_ok
        && codes_ok
        && consents_ok
        && offsets_ok
        && report.service_link.as_deref() == Some(DEMO_SERVICE_LINK)
}

/// A consumer-assurance identity policy pinning a slot to one verified email at the dev issuer.
fn consumer_policy(email: &str) -> IdentityPolicy {
    IdentityPolicy {
        allowed_issuers: vec![DEV_ISSUER.to_string()],
        required_email: Some(email.to_string()),
        ..Default::default()
    }
}

fn demo_field(id: &str, signer: &str, field_type: FieldType, y: f64) -> Field {
    Field {
        id: id.to_string(),
        field_type,
        page: 0,
        rect: Rect {
            x: 72.0,
            y,
            w: 220.0,
            h: 40.0,
        },
        assigned_signer: signer.to_string(),
        required: true,
        value: None,
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
    }
}

/// A text field of Bob's in the right-hand column of the demo NDA.
fn demo_text(id: &str, y: f64) -> Field {
    Field {
        rect: Rect {
            x: 330.0,
            y,
            w: 220.0,
            h: 40.0,
        },
        ..demo_field(id, "s2", FieldType::Text, y)
    }
}

/// The custom pattern of the demo's purchase-order field.
const DEMO_ORDER_PATTERN: &str = r"PO-\d{4}-\d{3}";

/// A stand-in for a hand-drawn signature: a looping pen stroke with an underline.
fn demo_ink() -> Vec<Vec<[f32; 2]>> {
    let scrawl = (0..=60)
        .map(|i| {
            let t = i as f32 / 60.0;
            let angle = t * 4.0 * std::f32::consts::TAU;
            [
                t * 150.0 + 12.0 * angle.cos(),
                24.0 - 18.0 * (1.0 - t * 0.6) * angle.sin(),
            ]
        })
        .collect();
    vec![scrawl, vec![[4.0, 52.0], [158.0, 46.0]]]
}

/// A checkbox or radio option for Bob (`s2`): the mark, then its caption.
fn demo_choice(
    id: &str,
    field_type: FieldType,
    group: Option<&str>,
    caption: &str,
    y: f64,
) -> Field {
    Field {
        rect: Rect {
            x: 72.0,
            y,
            w: 240.0,
            h: 16.0,
        },
        label: Some(caption.to_string()),
        group: group.map(str::to_string),
        ..demo_field(id, "s2", field_type, y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live end-to-end PAdES B-T against DigiCert's public RFC 3161 TSA: sign with a signature
    /// timestamp, then verify it is trusted through the bundled DigiCert root and used as the
    /// signing clock. Ignored by default because it requires network egress; run with:
    ///   cargo test -p signpdf-cli -- --ignored live_tsa
    #[test]
    #[ignore]
    fn live_tsa_signature_timestamp_is_trusted_via_bundled_root() {
        let pdf = container::make_sample_pdf("live B-T");
        let pk = KeyPair::generate();
        let prep = mint_dev_identity(&pk, &sha256_hex(&pdf), "alice@example.com", false).unwrap();
        let request = PrepareRequest {
            title: "Live TSA".into(),
            signers: vec![SignerSpec {
                id: "s1".into(),
                name: "Alice".into(),
                handle: "alice@example.com".into(),
                role: String::new(),
                order: 1,
                identity_policy: consumer_policy("alice@example.com"),
            }],
            fields: vec![],
            policy: Policy::default(),
            id_token: prep.id_token,
            idp_jwk: prep.idp_jwk,
            audience: DEV_AUDIENCE.into(),
            allowed_issuers: vec![DEV_ISSUER.into()],
            service_link: None,
            documents: Vec::new(),
            verify_at: None,
        };
        let prepared = prepare(&pdf, &request, &pk).unwrap();
        let k = KeyPair::generate();
        let dev =
            mint_dev_identity(&k, &sha256_hex(&prepared), "alice@example.com", false).unwrap();
        let tsa = HttpTsa("http://timestamp.digicert.com".into());
        let signed = sign_with(&prepared, &k, &dev_sign_request(dev), Some(&tsa)).unwrap();

        let mut trust = TrustStore::well_known();
        trust.allow_insecure_dev_issuer = true;
        let report = verify(&signed, &trust).unwrap();
        assert!(report.valid, "{:?}", report.messages);
        let s = &report.signatures[0];
        let ts = s.timestamp.as_ref().expect("signature timestamp");
        assert!(ts.is_trusted(), "{}", ts.detail);
        assert_eq!(s.time_source, "tsa");
    }

    #[test]
    fn pem_and_der_certificates_decode() {
        let der = signpdf_core::trust::DIGICERT_TRUSTED_ROOT_G4.to_vec();
        assert_eq!(cert_der(&der).unwrap(), der);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            signpdf_core::crypto::b64_encode_pub(&der)
        );
        assert_eq!(cert_der(pem.as_bytes()).unwrap(), der);
    }
}
