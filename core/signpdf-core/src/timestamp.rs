//! RFC 3161 trusted timestamps — the one *optional* online dependency of SignPDF.
//!
//! By design, the **timestamp client lives in the
//! platform-adapter layer, not here**: this module is transport-agnostic so the core engine
//! stays free of any networking and remains trivially portable across the FFI boundary. It
//! provides exactly three things:
//!
//! 1. [`build_request`] / [`request_for_document`] — produce the DER `TimeStampReq` to POST to
//!    a Time-Stamp Authority (`Content-Type: application/timestamp-query`).
//! 2. [`parse_response`] — validate the TSA's `TimeStampResp` and extract the token.
//! 3. [`verify_token`] — re-check a stored token's message imprint and read its `genTime`.
//!
//! The caller (CLI / app) performs the actual HTTP POST. When offline the workflow simply
//! records device time and marks it unverified.
//!
//! ## Scope
//! [`verify_token`] confirms the token's `messageImprint` binds *our* digest and reads the
//! authority's `genTime` — that alone proves nothing, because anyone can build such a structure.
//! [`verify_tsa_signature`] additionally checks the TSA's CMS signature (RSA PKCS#1 v1.5 or ECDSA
//! P-256), the `id-kp-timeStamping` EKU, certificate validity at `genTime`, and that the signer
//! chains to an anchor in the verifier's [`crate::trust::TrustStore`]. Only a timestamp passing
//! both is *trusted* and may be used as a clock by the workflow. The revocation status of the
//! chain (OCSP/CRL) is judged from a document's long-term validation material, in [`crate::ltv`].
//!
//! A small hand-rolled DER reader/writer is used deliberately: real-world `TSTInfo` carries a
//! grab-bag of optional trailing fields (accuracy, ordering, nonce, tsa, extensions) that vary by
//! authority, and walking only the fixed leading fields is more robust than a rigid schema.

use sha2::{Digest, Sha256};

use crate::algorithms::{Algorithm, AlgorithmUse};
use crate::crypto::{b64_decode, b64_encode};
use crate::error::{Result, SignPdfError};

fn ts_err(msg: impl Into<String>) -> SignPdfError {
    SignPdfError::Timestamp(msg.into())
}

// --- DER primitives ----------------------------------------------------------------------

/// A single DER TLV: its tag, the raw bytes of the whole element, and just its value.
pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) der: &'a [u8],
    pub(crate) value: &'a [u8],
}

/// Parse one DER length, returning `(length, header_len)` where `header_len` counts the length
/// octets only. Rejects indefinite-length and absurdly large encodings.
fn read_len(b: &[u8]) -> Result<(usize, usize)> {
    let first = *b.first().ok_or_else(|| ts_err("truncated length"))?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || b.len() < 1 + n {
        return Err(ts_err("unsupported DER length"));
    }
    let mut len = 0usize;
    for &byte in &b[1..1 + n] {
        len = (len << 8) | byte as usize;
    }
    Ok((len, 1 + n))
}

/// Read the single TLV at the start of `b`.
pub(crate) fn read_tlv(b: &[u8]) -> Result<Tlv<'_>> {
    let tag = *b.first().ok_or_else(|| ts_err("truncated TLV"))?;
    let (len, hdr) = read_len(&b[1..])?;
    let start = 1 + hdr;
    let end = start
        .checked_add(len)
        .filter(|&e| e <= b.len())
        .ok_or_else(|| ts_err("TLV overruns buffer"))?;
    Ok(Tlv {
        tag,
        der: &b[..end],
        value: &b[start..end],
    })
}

/// Split the body of a constructed element into its child TLVs.
pub(crate) fn children(body: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let tlv = read_tlv(rest)?;
        let consumed = tlv.der.len();
        out.push(tlv);
        rest = &rest[consumed..];
    }
    Ok(out)
}

/// Encode a DER length.
fn enc_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut bytes = Vec::new();
    let mut m = n;
    while m > 0 {
        bytes.insert(0, (m & 0xff) as u8);
        m >>= 8;
    }
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

/// Encode a DER TLV from a tag and value.
pub(crate) fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(enc_len(value.len()));
    out.extend_from_slice(value);
    out
}

// `AlgorithmIdentifier { id-sha256 }` with parameters ABSENT (RFC 5754 preferred form,
// accepted by DigiCert/Sectigo/freeTSA).
const SHA256_ALGID: &[u8] = &[
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
// id-signedData = 1.2.840.113549.1.7.2
const OID_SIGNED_DATA: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
];
// id-ct-TSTInfo = 1.2.840.113549.1.9.16.1.4
const OID_TST_INFO: &[u8] = &[
    0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
];

const TAG_OCTET_STRING: u8 = 0x04;
const TAG_GENERALIZED_TIME: u8 = 0x18;

// --- public types ------------------------------------------------------------------------

/// The trustworthy facts read out of a timestamp token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampInfo {
    /// Authority-asserted signing time, normalized to RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
    pub gen_time: String,
    /// Token serial number, hex-encoded.
    pub serial_hex: String,
}

/// A verified RFC 3161 timestamp token plus the facts extracted from it.
#[derive(Debug, Clone)]
pub struct TimestampToken {
    /// The raw DER `TimeStampToken` (a CMS `ContentInfo`), retained verbatim for storage and
    /// any future LTV upgrade.
    pub token_der: Vec<u8>,
    pub info: TimestampInfo,
}

impl TimestampToken {
    /// Base64 of the raw token, as stored in [`crate::SignatureRecord::timestamp_token`].
    pub fn to_base64(&self) -> String {
        b64_encode(&self.token_der)
    }

    /// Reconstruct from a stored base64 token, re-verifying its imprint against `expected_digest`.
    pub fn from_base64(token_b64: &str, expected_digest: &[u8]) -> Result<Self> {
        let token_der = b64_decode(token_b64)?;
        let info = verify_token(&token_der, expected_digest)?;
        Ok(Self { token_der, info })
    }
}

// --- request -----------------------------------------------------------------------------

/// Build a DER `TimeStampReq` over a SHA-256 `digest` (with `certReq` set so the token is
/// self-contained).
pub fn build_request(digest: &[u8]) -> Vec<u8> {
    let message_imprint = {
        let mut v = Vec::new();
        v.extend_from_slice(SHA256_ALGID);
        v.extend(tlv(TAG_OCTET_STRING, digest));
        tlv(0x30, &v)
    };
    let mut body = Vec::new();
    body.extend(tlv(0x02, &[0x01])); // version v1
    body.extend(message_imprint);
    body.extend(tlv(0x01, &[0xff])); // certReq TRUE
    tlv(0x30, &body)
}

/// Convenience for adapters: hash `pdf_bytes` and build the matching request. Returns the
/// digest (to re-check the response) and the DER request to POST.
pub fn request_for_document(pdf_bytes: &[u8]) -> ([u8; 32], Vec<u8>) {
    let digest: [u8; 32] = Sha256::digest(pdf_bytes).into();
    let request = build_request(&digest);
    (digest, request)
}

// --- response / token parsing ------------------------------------------------------------

/// Validate a TSA `TimeStampResp` and extract its token, confirming the token's message imprint
/// equals `expected_digest`.
pub fn parse_response(resp_der: &[u8], expected_digest: &[u8]) -> Result<TimestampToken> {
    let resp = read_tlv(resp_der)?;
    let kids = children(resp.value)?;
    let status_info = kids
        .first()
        .ok_or_else(|| ts_err("response missing PKIStatusInfo"))?;
    let status_kids = children(status_info.value)?;
    let status_tlv = status_kids
        .first()
        .ok_or_else(|| ts_err("PKIStatusInfo missing status"))?;
    let status = be_uint(status_tlv.value);
    // 0 = granted, 1 = grantedWithMods. Anything else carries no usable token.
    if status != 0 && status != 1 {
        return Err(ts_err(format!(
            "TSA did not grant the token (status {status})"
        )));
    }
    let token = kids
        .get(1)
        .ok_or_else(|| ts_err("granted response carried no timeStampToken"))?;
    let token_der = token.der.to_vec();
    let info = verify_token(&token_der, expected_digest)?;
    Ok(TimestampToken { token_der, info })
}

/// Re-verify a `TimeStampToken`: confirm its embedded message imprint matches `expected_digest`
/// and return the authority's asserted time.
pub fn verify_token(token_der: &[u8], expected_digest: &[u8]) -> Result<TimestampInfo> {
    let tst = extract_tst_info(token_der)?;
    let fields = children(read_tlv(tst)?.value)?;
    let imprint = fields
        .get(2)
        .ok_or_else(|| ts_err("TSTInfo missing messageImprint"))?;
    let imprint_kids = children(imprint.value)?;
    let hashed = imprint_kids
        .get(1)
        .ok_or_else(|| ts_err("messageImprint missing hashedMessage"))?;
    if hashed.value != expected_digest {
        return Err(ts_err(
            "timestamp message imprint does not match the signed document digest",
        ));
    }
    let serial = fields
        .get(3)
        .ok_or_else(|| ts_err("TSTInfo missing serialNumber"))?;
    let gen_time = fields
        .get(4)
        .filter(|t| t.tag == TAG_GENERALIZED_TIME)
        .ok_or_else(|| ts_err("TSTInfo missing genTime"))?;
    Ok(TimestampInfo {
        gen_time: parse_generalized_time(gen_time.value)?,
        serial_hex: hex::encode(serial.value),
    })
}

/// The message imprint of a `TimeStampToken`: its digest algorithm and the hash it carries.
/// A document timestamp may come from any RFC 3161 authority, so its imprint is checked with
/// the algorithm it names ([`digest_spans`]: SHA-256, SHA-384 or SHA-512).
pub fn token_imprint(token_der: &[u8]) -> Result<(const_oid::ObjectIdentifier, Vec<u8>)> {
    let tst = extract_tst_info(token_der)?;
    let fields = children(read_tlv(tst)?.value)?;
    let imprint = fields
        .get(2)
        .filter(|t| t.tag == 0x30)
        .ok_or_else(|| ts_err("TSTInfo missing messageImprint"))?;
    let kids = children(imprint.value)?;
    let alg = kids
        .first()
        .filter(|t| t.tag == 0x30)
        .ok_or_else(|| ts_err("messageImprint missing hashAlgorithm"))?;
    let oid = children(alg.value)?
        .first()
        .filter(|t| t.tag == 0x06)
        .and_then(|t| const_oid::ObjectIdentifier::from_bytes(t.value).ok())
        .ok_or_else(|| ts_err("messageImprint has no algorithm identifier"))?;
    let hashed = kids
        .get(1)
        .filter(|t| t.tag == TAG_OCTET_STRING)
        .ok_or_else(|| ts_err("messageImprint missing hashedMessage"))?;
    Ok((oid, hashed.value.to_vec()))
}

/// Hash the concatenation of `spans` with the digest algorithm `oid` (SHA-256/384/512), without
/// copying them into one buffer.
pub(crate) fn digest_spans(oid: &const_oid::ObjectIdentifier, spans: &[&[u8]]) -> Option<Vec<u8>> {
    use const_oid::db::rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512};
    fn run<D: Digest>(spans: &[&[u8]]) -> Vec<u8> {
        let mut h = D::new();
        for s in spans {
            h.update(s);
        }
        h.finalize().to_vec()
    }
    if *oid == ID_SHA_256 {
        Some(run::<Sha256>(spans))
    } else if *oid == ID_SHA_384 {
        Some(run::<sha2::Sha384>(spans))
    } else if *oid == ID_SHA_512 {
        Some(run::<sha2::Sha512>(spans))
    } else {
        None
    }
}

/// Walk `ContentInfo → SignedData → EncapsulatedContentInfo` and return the inner `TSTInfo` DER.
fn extract_tst_info(token_der: &[u8]) -> Result<&[u8]> {
    let ci = children(read_tlv(token_der)?.value)?;
    let ct = ci
        .first()
        .ok_or_else(|| ts_err("token missing contentType"))?;
    if ct.der != OID_SIGNED_DATA {
        return Err(ts_err("timestamp token is not CMS SignedData"));
    }
    let content = ci.get(1).ok_or_else(|| ts_err("token missing content"))?; // [0] EXPLICIT
    let signed_data = read_tlv(content.value)?;
    let sd_kids = children(signed_data.value)?;
    // version, digestAlgorithms, encapContentInfo, ...
    let eci = sd_kids
        .get(2)
        .ok_or_else(|| ts_err("SignedData missing encapContentInfo"))?;
    let eci_kids = children(eci.value)?;
    let etype = eci_kids
        .first()
        .ok_or_else(|| ts_err("encapContentInfo missing eContentType"))?;
    if etype.der != OID_TST_INFO {
        return Err(ts_err("encapsulated content is not TSTInfo"));
    }
    let econtent = eci_kids
        .get(1)
        .ok_or_else(|| ts_err("timestamp token has no eContent"))?; // [0] EXPLICIT
    let octet = read_tlv(econtent.value)?;
    if octet.tag != TAG_OCTET_STRING {
        return Err(ts_err("eContent is not an OCTET STRING"));
    }
    Ok(octet.value)
}

/// Big-endian unsigned interpretation of a (small) INTEGER's content octets.
fn be_uint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

/// Convert an ASN.1 GeneralizedTime (`YYYYMMDDHHMMSS[.fff]Z`) into RFC 3339.
fn parse_generalized_time(raw: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(raw).map_err(|_| ts_err("genTime is not ASCII"))?;
    if s.len() < 14 || !s.is_char_boundary(14) {
        return Err(ts_err(format!("unexpected genTime format: {s}")));
    }
    let (date, time) = (&s[..8], &s[8..14]);
    Ok(format!(
        "{}-{}-{}T{}:{}:{}Z",
        &date[0..4],
        &date[4..6],
        &date[6..8],
        &time[0..2],
        &time[2..4],
        &time[4..6],
    ))
}

// --- TSA signature + chain verification ----------------------------------------------------

/// Outcome of checking who signed a timestamp token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TsaSignature {
    /// The CMS signature over the `TSTInfo` verifies against the embedded TSA certificate, the
    /// signed `messageDigest` matches the content, and the certificate is a timestamping cert
    /// valid at `genTime`.
    pub signature_valid: bool,
    /// The TSA certificate chains to an anchor of the verifier's trust store.
    pub trusted: bool,
    /// Subject common name of the TSA certificate, when known.
    pub tsa_name: String,
    /// Human-readable reason when not valid/trusted.
    pub detail: String,
    /// The chain that makes the timestamp trusted, as DER certificates exactly as found (in the
    /// token or the trust store): the TSA certificate first, the trust anchor last. Empty when
    /// the timestamp is not trusted. Long-term validation ([`crate::ltv`]) checks the revocation
    /// status of every certificate in it but the anchor.
    pub chain: Vec<Vec<u8>>,
    /// The algorithms the timestamp's trust rests on: the TSA's signature (its algorithm, key
    /// size and digest) and each certificate signature on the way to the anchor. For the
    /// verifier's algorithm policy ([`crate::algorithms`]). Empty when not trusted.
    pub algorithms: Vec<AlgorithmUse>,
    /// Set when the trust store distrusts a certificate of the chain from a time at or before
    /// `genTime` ([`crate::trust::TsaDistrust`]): that time (RFC 3339). The timestamp is then not
    /// trusted. Only [`crate::trust::TrustStore::verify_tsa`] sets it.
    pub distrusted_after: Option<String>,
}

const OID_KP_TIME_STAMPING: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// Hash `data` with the digest algorithm `oid` (SHA-256/384/512).
pub(crate) fn digest_with(oid: &const_oid::ObjectIdentifier, data: &[u8]) -> Option<Vec<u8>> {
    use const_oid::db::rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512};
    if *oid == ID_SHA_256 {
        Some(Sha256::digest(data).to_vec())
    } else if *oid == ID_SHA_384 {
        Some(sha2::Sha384::digest(data).to_vec())
    } else if *oid == ID_SHA_512 {
        Some(sha2::Sha512::digest(data).to_vec())
    } else {
        None
    }
}

/// The algorithms a signature with algorithm `sig_alg` (and `digest_alg`, which a bare
/// `rsaEncryption` takes its hash from, as CMS permits) by the key in `spki` relies on, as
/// [`verify_with_spki`] checks it: the signature algorithm with its key size, and the digest.
/// Empty for a signature [`verify_with_spki`] does not support.
pub(crate) fn signature_algorithms(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    sig_alg: &const_oid::ObjectIdentifier,
    digest_alg: Option<&const_oid::ObjectIdentifier>,
) -> Vec<AlgorithmUse> {
    use const_oid::db::rfc5912::{
        ECDSA_WITH_SHA_256, ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION,
        SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
    };
    let rsa_hash = if *sig_alg == SHA_256_WITH_RSA_ENCRYPTION {
        Some(ID_SHA_256)
    } else if *sig_alg == SHA_384_WITH_RSA_ENCRYPTION {
        Some(ID_SHA_384)
    } else if *sig_alg == SHA_512_WITH_RSA_ENCRYPTION {
        Some(ID_SHA_512)
    } else if *sig_alg == RSA_ENCRYPTION {
        digest_alg.copied()
    } else {
        None
    };
    if let Some(h) = rsa_hash {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::traits::PublicKeyParts;
        let bits = spki
            .subject_public_key
            .as_bytes()
            .and_then(|k| rsa::RsaPublicKey::from_pkcs1_der(k).ok())
            .map(|k| crate::algorithms::bit_length(&k.n_bytes()));
        let Some(digest) = Algorithm::from_digest_oid(&h) else {
            return Vec::new();
        };
        return vec![
            AlgorithmUse {
                algorithm: Algorithm::RsaPkcs1v15,
                key_bits: Some(bits.unwrap_or(0)),
            },
            AlgorithmUse::plain(digest),
        ];
    }
    if *sig_alg == ECDSA_WITH_SHA_256 {
        return vec![
            AlgorithmUse::plain(Algorithm::EcdsaP256),
            AlgorithmUse::plain(Algorithm::Sha256),
        ];
    }
    Vec::new()
}

/// Verify `signature` over `message` with the public key in `spki`, for signature algorithm
/// `sig_alg` (with `digest_alg` used when `sig_alg` is bare `rsaEncryption`, as CMS permits).
pub(crate) fn verify_with_spki(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    sig_alg: &const_oid::ObjectIdentifier,
    digest_alg: Option<&const_oid::ObjectIdentifier>,
    message: &[u8],
    signature: &[u8],
) -> bool {
    use const_oid::db::rfc5912::{
        ECDSA_WITH_SHA_256, ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION,
        SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
    };
    let Some(key_bytes) = spki.subject_public_key.as_bytes() else {
        return false;
    };
    let rsa_hash = if *sig_alg == SHA_256_WITH_RSA_ENCRYPTION {
        Some(ID_SHA_256)
    } else if *sig_alg == SHA_384_WITH_RSA_ENCRYPTION {
        Some(ID_SHA_384)
    } else if *sig_alg == SHA_512_WITH_RSA_ENCRYPTION {
        Some(ID_SHA_512)
    } else if *sig_alg == RSA_ENCRYPTION {
        digest_alg.copied()
    } else {
        None
    };
    if let Some(h) = rsa_hash {
        use rsa::pkcs1::DecodeRsaPublicKey;
        let Ok(key) = rsa::RsaPublicKey::from_pkcs1_der(key_bytes) else {
            return false;
        };
        let Some(hashed) = digest_with(&h, message) else {
            return false;
        };
        let scheme = if h == ID_SHA_256 {
            rsa::Pkcs1v15Sign::new::<Sha256>()
        } else if h == ID_SHA_384 {
            rsa::Pkcs1v15Sign::new::<sha2::Sha384>()
        } else {
            rsa::Pkcs1v15Sign::new::<sha2::Sha512>()
        };
        return key.verify(scheme, &hashed, signature).is_ok();
    }
    if *sig_alg == ECDSA_WITH_SHA_256 {
        use p256::ecdsa::signature::Verifier;
        let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes) else {
            return false;
        };
        let Ok(sig) = p256::ecdsa::DerSignature::from_bytes(signature) else {
            return false;
        };
        return vk.verify(message, &sig).is_ok();
    }
    false
}

// --- what a certificate may do (docs/SECURITY_REVIEW_2026-10-27.md, finding 3) ---------------

/// `anyExtendedKeyUsage` (RFC 5280 §4.2.1.12).
const OID_ANY_EKU: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.5.29.37.0");
/// ESS `signing-certificate` (RFC 2634): binds the signer certificate by its SHA-1 hash.
const OID_SIGNING_CERTIFICATE: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
/// ESS `signing-certificate-v2` (RFC 5035): the same, with a stated hash (SHA-256 by default).
const OID_SIGNING_CERTIFICATE_V2: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

/// The one extension `oid` of `cert` (`Ok(None)` when absent), or why it cannot be used: a
/// certificate with two instances of an extension is invalid (RFC 5280 §4.2).
fn single_extension(
    cert: &x509_cert::Certificate,
    oid: const_oid::ObjectIdentifier,
) -> std::result::Result<Option<&x509_cert::ext::Extension>, String> {
    let mut found = cert
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .filter(|e| e.extn_id == oid);
    let first = found.next();
    if found.next().is_some() {
        return Err(format!("it carries the extension {oid} twice"));
    }
    Ok(first)
}

/// Why `cert` may not issue the next certificate down a chain, if it may not: it must be a
/// certificate authority (`basicConstraints` present, critical, `cA` true, its path length
/// allowing the `below` CA certificates between it and the end entity), allow `keyCertSign`
/// when it lists key usages, and, when it lists extended key usages and `purpose` is given,
/// allow that purpose (or any). Trust anchors are held to the same rules when they issue.
pub(crate) fn issuer_problem(
    cert: &x509_cert::Certificate,
    below: usize,
    purpose: Option<const_oid::ObjectIdentifier>,
) -> Option<String> {
    use der::Decode;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
    let check = || -> std::result::Result<(), String> {
        let bc = single_extension(cert, const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS)?
            .ok_or("it is not a certificate authority (no basicConstraints)")?;
        let constraints = BasicConstraints::from_der(bc.extn_value.as_bytes())
            .map_err(|_| "its basicConstraints do not decode")?;
        if !constraints.ca {
            return Err("it is not a certificate authority (basicConstraints cA is false)".into());
        }
        if !bc.critical {
            return Err("its basicConstraints are not marked critical".into());
        }
        if constraints
            .path_len_constraint
            .is_some_and(|n| usize::from(n) < below)
        {
            return Err("its path length constraint does not allow this chain".into());
        }
        if let Some(ku) = single_extension(cert, const_oid::db::rfc5280::ID_CE_KEY_USAGE)? {
            let ku = KeyUsage::from_der(ku.extn_value.as_bytes())
                .map_err(|_| "its keyUsage does not decode")?;
            if !ku.key_cert_sign() {
                return Err("its keyUsage does not allow signing certificates".into());
            }
        }
        if let (Some(purpose), Some(eku)) = (
            purpose,
            single_extension(cert, const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE)?,
        ) {
            let eku = ExtendedKeyUsage::from_der(eku.extn_value.as_bytes())
                .map_err(|_| "its extendedKeyUsage does not decode")?;
            if !eku.0.contains(&purpose) && !eku.0.contains(&OID_ANY_EKU) {
                return Err("its extendedKeyUsage does not include the chain's purpose".into());
            }
        }
        Ok(())
    };
    check().err()
}

/// Why `cert` may not sign timestamps, if it may not (RFC 3161 §2.3): its extended key usage
/// must be the timestamping purpose alone, in one extension marked critical, and when it lists
/// key usages they must allow signing (`digitalSignature` or `nonRepudiation`).
fn tsa_certificate_problem(cert: &x509_cert::Certificate) -> Option<String> {
    use der::Decode;
    use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage};
    let check = || -> std::result::Result<(), String> {
        let eku = single_extension(cert, const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE)?
            .ok_or("it has no extended key usage")?;
        let purposes = ExtendedKeyUsage::from_der(eku.extn_value.as_bytes())
            .map_err(|_| "its extended key usage does not decode")?;
        if purposes.0 != [OID_KP_TIME_STAMPING] {
            return Err("its extended key usage is not timestamping alone".into());
        }
        if !eku.critical {
            return Err("its extended key usage is not marked critical".into());
        }
        if let Some(ku) = single_extension(cert, const_oid::db::rfc5280::ID_CE_KEY_USAGE)? {
            let ku = KeyUsage::from_der(ku.extn_value.as_bytes())
                .map_err(|_| "its keyUsage does not decode")?;
            if !ku.digital_signature() && !ku.non_repudiation() {
                return Err("its keyUsage does not allow signing".into());
            }
        }
        Ok(())
    };
    check().err()
}

/// Why the token's ESS signing-certificate attributes (v1 or v2) do not name `signer_der`, the
/// certificate whose key signed it, if they do not: the first certificate each one identifies
/// must be that one, by hash. A token without either attribute passes: the chain and purpose
/// checks are what keep a certificate from acting as a TSA (see `docs/SECURITY_MODEL.md`).
fn ess_problem(signed_attrs: &x509_cert::attr::Attributes, signer_der: &[u8]) -> Option<String> {
    use der::Encode;
    for attr in signed_attrs.iter() {
        let v2 = attr.oid == OID_SIGNING_CERTIFICATE_V2;
        if attr.oid != OID_SIGNING_CERTIFICATE && !v2 {
            continue;
        }
        let names_signer = (|| -> Option<bool> {
            if attr.values.len() != 1 {
                return Some(false);
            }
            let der = attr.values.iter().next()?.to_der().ok()?;
            let outer = read_tlv(&der).ok()?; // SigningCertificate(V2)
            let certs = children(outer.value).ok()?;
            let first_id = children(certs.first()?.value).ok()?.into_iter().next()?;
            let parts = children(first_id.value).ok()?; // ESSCertID(v2)
            let (alg, hash) = match (v2, parts.first()?) {
                (true, p) if p.tag == 0x30 => {
                    let alg = children(p.value).ok()?;
                    let oid = alg.first().filter(|o| o.tag == 0x06)?;
                    let oid = const_oid::ObjectIdentifier::from_bytes(oid.value).ok()?;
                    (Some(oid), parts.get(1)?)
                }
                (true, p) => (Some(const_oid::db::rfc5912::ID_SHA_256), p),
                (false, p) => (None, p),
            };
            if hash.tag != TAG_OCTET_STRING {
                return Some(false);
            }
            let expected = match alg {
                Some(oid) => digest_with(&oid, signer_der)?,
                None => {
                    use sha1::Digest as _;
                    sha1::Sha1::digest(signer_der).to_vec()
                }
            };
            Some(hash.value == expected.as_slice())
        })();
        if names_signer != Some(true) {
            return Some(format!(
                "the token's signing-certificate{} attribute does not name the certificate that \
                 signed it",
                if v2 { "-v2" } else { "" }
            ));
        }
    }
    None
}

/// The subject key identifier extension value of `cert`, if present.
fn subject_key_id(cert: &x509_cert::Certificate) -> Option<Vec<u8>> {
    use der::Decode;
    cert.tbs_certificate()
        .extensions()?
        .iter()
        .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER)
        .and_then(|e| {
            x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(e.extn_value.as_bytes()).ok()
        })
        .map(|ski| ski.0.as_bytes().to_vec())
}

pub(crate) fn cert_valid_at(cert: &x509_cert::Certificate, unix: i64) -> bool {
    let v = cert.tbs_certificate().validity();
    let nb = v.not_before.to_unix_duration().as_secs() as i64;
    let na = v.not_after.to_unix_duration().as_secs() as i64;
    nb <= unix && unix <= na
}

/// Subject common name of a certificate.
/// The subject common name of the DER certificate `der`, when it has one.
pub fn certificate_common_name(der: &[u8]) -> Option<String> {
    cert_common_name(&RawCert::parse(der)?.cert)
}

pub(crate) fn cert_common_name(cert: &x509_cert::Certificate) -> Option<String> {
    let cn = const_oid::db::rfc4519::CN;
    for rdn in cert.tbs_certificate().subject().iter_rdn() {
        for atv in rdn.iter() {
            if atv.oid == cn {
                if let Ok(s) = atv.value.decode_as::<der::asn1::Utf8StringRef>() {
                    return Some(s.as_str().to_string());
                }
                if let Ok(s) = atv.value.decode_as::<der::asn1::PrintableStringRef>() {
                    return Some(s.as_str().to_string());
                }
            }
        }
    }
    None
}

/// A certificate together with the exact DER it was read from.
///
/// x509-cert rewrites some fields when it re-encodes a decoded certificate: validity dates
/// before 2050 written as GeneralizedTime come back as UTCTime (RFC 5280 asks for UTCTime, but
/// such certificates exist). A re-encoding is then not the bytes the issuer signed, so
/// signature checks and anchor matches use these original bytes instead.
pub(crate) struct RawCert {
    pub(crate) cert: x509_cert::Certificate,
    pub(crate) der: Vec<u8>,
}

impl RawCert {
    pub(crate) fn parse(der: &[u8]) -> Option<Self> {
        use der::Decode;
        let cert = x509_cert::Certificate::from_der(der).ok()?;
        Some(Self {
            cert,
            der: der.to_vec(),
        })
    }

    /// The `tbsCertificate` exactly as the issuer signed it.
    fn tbs_der(&self) -> Option<&[u8]> {
        let outer = read_tlv(&self.der).ok()?;
        children(outer.value).ok()?.first().map(|t| t.der)
    }
}

/// Verify that `child` was signed by `issuer`'s key.
pub(crate) fn cert_signed_by(child: &RawCert, issuer: &RawCert) -> bool {
    if child.cert.tbs_certificate().issuer() != issuer.cert.tbs_certificate().subject() {
        return false;
    }
    let Some(tbs) = child.tbs_der() else {
        return false;
    };
    let Some(sig) = child.cert.signature().as_bytes() else {
        return false;
    };
    verify_with_spki(
        issuer.cert.tbs_certificate().subject_public_key_info(),
        &child.cert.signature_algorithm().oid,
        None,
        tbs,
        sig,
    )
}

/// The certificates (the `Certificate` choice) of a timestamp token, with their original bytes,
/// read from `ContentInfo → [0] SignedData → [0] certificates`. Call it on a token that has
/// already decoded as CMS `SignedData`, so the structure is known to be DER.
fn raw_token_certificates(token_der: &[u8]) -> Vec<RawCert> {
    let Ok(ci) = read_tlv(token_der).and_then(|t| children(t.value)) else {
        return Vec::new();
    };
    let Some(Ok(sd)) = ci
        .get(1)
        .map(|content| read_tlv(content.value).and_then(|t| children(t.value)))
    else {
        return Vec::new();
    };
    // version, digestAlgorithms and encapContentInfo come first; certificates is [0] IMPLICIT.
    let Some(Ok(set)) = sd
        .iter()
        .skip(3)
        .find(|t| t.tag == 0xA0)
        .map(|set| children(set.value))
    else {
        return Vec::new();
    };
    set.iter()
        .filter(|c| c.tag == 0x30)
        .filter_map(|c| RawCert::parse(c.der))
        .collect()
}

/// The X.509 certificates (DER, exactly as embedded) carried inside a timestamp token.
pub fn token_certificates(token_der: &[u8]) -> Vec<Vec<u8>> {
    use der::Decode;
    let is_signed_data = cms::content_info::ContentInfo::from_der(token_der).is_ok_and(|ci| {
        ci.content
            .decode_as::<cms::signed_data::SignedData>()
            .is_ok()
    });
    if !is_signed_data {
        return Vec::new();
    }
    raw_token_certificates(token_der)
        .into_iter()
        .map(|c| c.der)
        .collect()
}

/// Check the TSA's CMS signature on `token_der` and whether its certificate chains to one of
/// `anchors` (DER certificates), judging certificate validity at `gen_time_unix`.
pub fn verify_tsa_signature(
    token_der: &[u8],
    anchors: &[Vec<u8>],
    gen_time_unix: i64,
) -> TsaSignature {
    match verify_tsa_signature_inner(token_der, anchors, gen_time_unix) {
        Ok(s) => s,
        Err(detail) => TsaSignature {
            detail,
            ..Default::default()
        },
    }
}

fn verify_tsa_signature_inner(
    token_der: &[u8],
    anchors: &[Vec<u8>],
    gen_time_unix: i64,
) -> std::result::Result<TsaSignature, String> {
    use cms::signed_data::{SignedData, SignerIdentifier};
    use der::asn1::OctetString;
    use der::{Decode, Encode};

    let ci = cms::content_info::ContentInfo::from_der(token_der)
        .map_err(|e| format!("token is not CMS: {e}"))?;
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| format!("token is not SignedData: {e}"))?;
    let tst = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or("token has no TSTInfo")?
        .decode_as::<OctetString>()
        .map_err(|e| format!("TSTInfo is not an OCTET STRING: {e}"))?;

    let certs = raw_token_certificates(token_der);
    let si = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or("timestamp token has no signerInfo (unsigned)")?;

    let signer = certs
        .iter()
        .find(|c| match &si.sid {
            SignerIdentifier::IssuerAndSerialNumber(ias) => {
                *c.cert.tbs_certificate().issuer() == ias.issuer
                    && *c.cert.tbs_certificate().serial_number() == ias.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => {
                subject_key_id(&c.cert).as_deref() == Some(ski.0.as_bytes())
            }
        })
        .ok_or("TSA signing certificate is not included in the token")?;
    let tsa_name = cert_common_name(&signer.cert).unwrap_or_default();

    let signed_attrs = si
        .signed_attrs
        .as_ref()
        .ok_or("signerInfo has no signed attributes")?;
    let expected = digest_with(&si.digest_alg.oid, tst.as_bytes())
        .ok_or("unsupported timestamp digest algorithm")?;
    let md_ok = signed_attrs
        .iter()
        .filter(|a| a.oid == OID_MESSAGE_DIGEST_TS)
        .flat_map(|a| a.values.iter())
        .any(|v| {
            v.decode_as::<OctetString>()
                .map(|os| os.as_bytes() == expected.as_slice())
                .unwrap_or(false)
        });
    let attrs_der = signed_attrs
        .to_der()
        .map_err(|e| format!("encode signed attrs: {e}"))?;
    let sig_ok = verify_with_spki(
        signer.cert.tbs_certificate().subject_public_key_info(),
        &si.signature_algorithm.oid,
        Some(&si.digest_alg.oid),
        &attrs_der,
        si.signature.as_bytes(),
    );
    let mut result = TsaSignature {
        tsa_name,
        ..Default::default()
    };
    // What the timestamp rests on: its messageDigest's hash and the TSA's signature, then each
    // certificate signature on the way to the anchor.
    let mut algorithms = signature_algorithms(
        signer.cert.tbs_certificate().subject_public_key_info(),
        &si.signature_algorithm.oid,
        Some(&si.digest_alg.oid),
    );
    algorithms.extend(Algorithm::from_digest_oid(&si.digest_alg.oid).map(AlgorithmUse::plain));
    if !md_ok {
        result.detail = "TSA signed digest does not match the timestamp content".into();
        return Ok(result);
    }
    if !sig_ok {
        result.detail = "TSA signature does not verify (or uses an unsupported algorithm)".into();
        return Ok(result);
    }
    if let Some(problem) = tsa_certificate_problem(&signer.cert) {
        result.detail = format!("signing certificate is not a timestamping certificate: {problem}");
        return Ok(result);
    }
    if let Some(problem) = ess_problem(signed_attrs, &signer.der) {
        result.detail = problem;
        return Ok(result);
    }
    if !cert_valid_at(&signer.cert, gen_time_unix) {
        result.detail = "TSA certificate was not valid at the asserted time".into();
        return Ok(result);
    }
    result.signature_valid = true;

    // Chain building over the token's certificates plus the anchors, on original bytes (see
    // `RawCert`): an anchor matches only the exact certificate the trust store holds.
    let anchor_certs: Vec<RawCert> = anchors.iter().filter_map(|d| RawCert::parse(d)).collect();
    let mut current = signer;
    let mut chain = vec![current.der.clone()];
    for _ in 0..8 {
        if anchors.contains(&current.der) {
            result.trusted = true;
            result.chain = chain;
            algorithms.sort();
            algorithms.dedup();
            result.algorithms = algorithms;
            return Ok(result);
        }
        let parent = anchor_certs
            .iter()
            .chain(certs.iter())
            .find(|p| p.der != current.der && cert_signed_by(current, p));
        // Whoever issues a certificate on the way up must be allowed to (`chain.len() - 1` CA
        // certificates sit between it and the TSA certificate).
        if let Some(problem) = parent
            .and_then(|p| issuer_problem(&p.cert, chain.len() - 1, Some(OID_KP_TIME_STAMPING)))
        {
            result.detail = format!(
                "a TSA chain certificate ('{}') may not issue certificates: {problem}",
                parent
                    .and_then(|p| cert_common_name(&p.cert))
                    .unwrap_or_default()
            );
            return Ok(result);
        }
        match parent {
            Some(p) if cert_valid_at(&p.cert, gen_time_unix) => {
                algorithms.extend(signature_algorithms(
                    p.cert.tbs_certificate().subject_public_key_info(),
                    &current.cert.signature_algorithm().oid,
                    None,
                ));
                current = p;
                chain.push(p.der.clone());
            }
            Some(_) => {
                result.detail = "a TSA chain certificate was not valid at the asserted time".into();
                return Ok(result);
            }
            None => break,
        }
    }
    result.detail = "TSA certificate does not chain to a trusted timestamp anchor".into();
    Ok(result)
}

// messageDigest signed attribute (1.2.840.113549.1.9.4).
const OID_MESSAGE_DIGEST_TS: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// Test-only construction of synthetic timestamp tokens. Gated behind the `test-issuer` feature
/// (on by default; production can `--no-default-features`).
#[cfg(any(test, feature = "test-issuer"))]
pub mod testing {
    use super::*;

    /// Build a **synthetic** RFC 3161 timestamp token (base64) over `digest` that asserts
    /// `gen_time` (an RFC 3339 string) and `serial`.
    ///
    /// For tests only. The token carries exactly the fields [`super::verify_token`] reads — a
    /// `messageImprint` binding `digest`, a `serialNumber`, and a `genTime` — but is **not** signed
    /// by any real TSA. Because production verification deliberately checks only the imprint and
    /// reads `genTime` (validating the CMS signature/cert chain is a deferred PAdES-LTV item), this
    /// faithfully exercises the trusted-time path, including the TSA-time rescue in `verify`.
    pub fn mint_timestamp(digest: &[u8], gen_time_rfc3339: &str, serial: u8) -> String {
        let message_imprint = {
            let mut v = Vec::new();
            v.extend_from_slice(SHA256_ALGID);
            v.extend(tlv(TAG_OCTET_STRING, digest));
            tlv(0x30, &v)
        };
        let tst_info = {
            let mut v = Vec::new();
            v.extend(tlv(0x02, &[0x01])); // version v1
            v.extend(tlv(0x06, &[0x2b, 0x06, 0x01])); // policy OID 1.3.6.1 (value ignored)
            v.extend(message_imprint);
            v.extend(tlv(0x02, &[serial])); // serialNumber
            v.extend(tlv(
                TAG_GENERALIZED_TIME,
                generalized_time(gen_time_rfc3339).as_bytes(),
            ));
            tlv(0x30, &v)
        };
        let encap_content = {
            let mut v = Vec::new();
            v.extend_from_slice(OID_TST_INFO);
            v.extend(tlv(0xa0, &tlv(TAG_OCTET_STRING, &tst_info))); // [0] EXPLICIT eContent
            tlv(0x30, &v)
        };
        let signed_data = {
            let mut v = Vec::new();
            v.extend(tlv(0x02, &[0x03])); // CMS version v3
            v.extend(tlv(0x31, &[])); // digestAlgorithms (empty SET)
            v.extend(encap_content);
            v.extend(tlv(0x31, &[])); // signerInfos (empty SET)
            tlv(0x30, &v)
        };
        let content_info = {
            let mut v = Vec::new();
            v.extend_from_slice(OID_SIGNED_DATA);
            v.extend(tlv(0xa0, &signed_data)); // [0] EXPLICIT content
            tlv(0x30, &v)
        };
        b64_encode(&content_info)
    }

    /// A local, **untrusted** RFC 3161 Time-Stamp Authority for tests: a P-256 key with a
    /// self-signed `id-kp-timeStamping` certificate that issues genuinely CMS-signed tokens.
    /// Trusting [`TestTsa::cert_der`] in a [`crate::trust::TrustStore`] makes its tokens trusted.
    pub struct TestTsa {
        key: p256::ecdsa::SigningKey,
        cert: x509_cert::Certificate,
        /// Certificates its tokens carry besides its own (intermediates of its chain).
        extra: Vec<x509_cert::Certificate>,
    }

    impl TestTsa {
        /// A fresh TSA.
        pub fn new() -> Self {
            use std::str::FromStr;
            use std::time::Duration;
            use x509_cert::builder::{Builder, CertificateBuilder};
            use x509_cert::ext::pkix::ExtendedKeyUsage;
            let key = crate::crypto::generate_signing_key();
            let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(key.verifying_key())
                .expect("spki");
            let name = x509_cert::name::Name::from_str("CN=SignPDF Test TSA,O=SignPDF Tests")
                .expect("name");
            let mut builder = CertificateBuilder::new(
                crate::pades::SelfSignedLeaf(name),
                x509_cert::serial_number::SerialNumber::from(7u32),
                x509_cert::time::Validity::from_now(Duration::from_secs(3650 * 86400))
                    .expect("validity"),
                spki,
            )
            .expect("builder");
            // RFC 3161 §2.3: the timestamping EKU MUST be critical. x509-cert 0.3 marks an
            // ExtendedKeyUsage non-critical by default, so say so explicitly.
            builder
                .add_extension((true, &ExtendedKeyUsage(vec![OID_KP_TIME_STAMPING])))
                .expect("eku");
            let cert = builder
                .build::<_, p256::ecdsa::DerSignature>(&key)
                .expect("cert");
            Self {
                key,
                cert,
                extra: Vec::new(),
            }
        }

        /// A TSA with this key and certificate: one a test CA issued
        /// ([`crate::ltv::testing::TestCa::issue_tsa`]), for long-term validation tests.
        pub fn with_certificate(
            key: p256::ecdsa::SigningKey,
            cert: x509_cert::Certificate,
        ) -> Self {
            Self {
                key,
                cert,
                extra: Vec::new(),
            }
        }

        /// This TSA, its tokens also carrying `der` (an intermediate certificate of its chain).
        pub fn with_intermediate(mut self, der: &[u8]) -> Self {
            use der::Decode;
            self.extra
                .push(x509_cert::Certificate::from_der(der).expect("intermediate certificate"));
            self
        }

        /// The TSA certificate (DER), to add as a trust anchor.
        pub fn cert_der(&self) -> Vec<u8> {
            use der::Encode;
            self.cert.to_der().expect("cert der")
        }

        /// The TSA certificate re-signed with its validity dates written as GeneralizedTime, as
        /// some CAs encode dates before 2050. x509-cert writes such dates back as UTCTime when
        /// it re-encodes, so only these exact bytes carry a valid signature.
        pub fn cert_der_with_generalized_time(&self) -> Vec<u8> {
            use p256::ecdsa::signature::{SignatureEncoding, Signer};
            let der = self.cert_der();
            let cert = children(read_tlv(&der).expect("cert").value).expect("cert parts");
            let tbs = children(cert[0].value).expect("tbs");
            // tbsCertificate: [0] version, serialNumber, signature, issuer, validity, ...
            assert_eq!(tbs[0].tag, 0xA0, "a v3 certificate");
            let mut body = Vec::new();
            for (i, part) in tbs.iter().enumerate() {
                if i == 4 {
                    body.extend(generalized_validity(part.value));
                } else {
                    body.extend_from_slice(part.der);
                }
            }
            let tbs = tlv(0x30, &body);
            let sig: p256::ecdsa::DerSignature = self.key.sign(&tbs);
            let mut bit_string = vec![0u8]; // no unused bits
            bit_string.extend(sig.to_vec());
            let mut out = tbs;
            out.extend_from_slice(cert[1].der); // signatureAlgorithm
            out.extend(tlv(0x03, &bit_string));
            tlv(0x30, &out)
        }

        /// Issue a signed `TimeStampToken` (DER) over `digest` asserting `gen_time_rfc3339`. Its
        /// signed attributes name the TSA certificate (ESS `signing-certificate-v2`).
        pub fn stamp(&self, digest: &[u8], gen_time_rfc3339: &str) -> Vec<u8> {
            self.stamp_with(digest, gen_time_rfc3339, true)
        }

        /// [`TestTsa::stamp`] without the ESS attribute, as some authorities issue tokens.
        pub fn stamp_without_ess(&self, digest: &[u8], gen_time_rfc3339: &str) -> Vec<u8> {
            self.stamp_with(digest, gen_time_rfc3339, false)
        }

        fn stamp_with(&self, digest: &[u8], gen_time_rfc3339: &str, ess: bool) -> Vec<u8> {
            use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
            use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
            use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
            use der::{Any, Decode, Encode};

            let message_imprint = {
                let mut v = Vec::new();
                v.extend_from_slice(SHA256_ALGID);
                v.extend(tlv(TAG_OCTET_STRING, digest));
                tlv(0x30, &v)
            };
            let tst_info = {
                let mut v = Vec::new();
                v.extend(tlv(0x02, &[0x01]));
                v.extend(tlv(0x06, &[0x2b, 0x06, 0x01]));
                v.extend(message_imprint);
                v.extend(tlv(0x02, &[0x2a]));
                v.extend(tlv(
                    TAG_GENERALIZED_TIME,
                    generalized_time(gen_time_rfc3339).as_bytes(),
                ));
                tlv(0x30, &v)
            };
            let econtent = EncapsulatedContentInfo {
                econtent_type: const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4"),
                econtent: Some(Any::from_der(&tlv(TAG_OCTET_STRING, &tst_info)).expect("econtent")),
            };
            let sha256 = x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ID_SHA_256,
                parameters: None,
            };
            let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: self.cert.tbs_certificate().issuer().clone(),
                serial_number: self.cert.tbs_certificate().serial_number().clone(),
            });
            let mut si =
                SignerInfoBuilder::new(sid, sha256.clone(), &econtent, None).expect("signer info");
            // RFC 3161 §2.4.1: the token names its signing certificate (ESS, here v2).
            if ess {
                si.add_signed_attribute(
                    crate::pades::signing_certificate_v2(&self.cert).expect("ess attribute"),
                )
                .expect("ess attribute");
            }
            let mut builder = SignedDataBuilder::new(&econtent);
            builder
                .add_digest_algorithm(sha256)
                .expect("alg")
                .add_certificate(CertificateChoices::Certificate(self.cert.clone()))
                .expect("cert");
            for c in &self.extra {
                builder
                    .add_certificate(CertificateChoices::Certificate(c.clone()))
                    .expect("intermediate");
            }
            let ci = builder
                .add_signer_info::<p256::ecdsa::SigningKey, p256::ecdsa::DerSignature>(
                    si, &self.key,
                )
                .expect("signer")
                .build()
                .expect("build");
            ci.to_der().expect("token der")
        }
    }

    impl TestTsa {
        /// Answer a DER `TimeStampReq` (SHA-256 imprint) the way an RFC 3161 server does: a
        /// granted `TimeStampResp` whose token covers the request's imprint, dated now.
        pub fn respond(&self, request_der: &[u8]) -> Result<Vec<u8>> {
            let req = read_tlv(request_der)?;
            let kids = children(req.value)?;
            let imprint = kids
                .get(1)
                .filter(|_| req.tag == 0x30)
                .ok_or_else(|| ts_err("not a TimeStampReq"))?;
            let parts = children(imprint.value)?;
            let digest = match parts.as_slice() {
                [alg, hash]
                    if alg.der == SHA256_ALGID
                        && hash.tag == TAG_OCTET_STRING
                        && hash.value.len() == 32 =>
                {
                    hash.value
                }
                _ => return Err(ts_err("the test TSA only stamps SHA-256 imprints")),
            };
            let now = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| ts_err(e.to_string()))?;
            let mut body = tlv(0x30, &tlv(0x02, &[0x00])); // PKIStatusInfo { granted }
            body.extend(self.stamp(digest, &now));
            Ok(tlv(0x30, &body))
        }
    }

    impl Default for TestTsa {
        fn default() -> Self {
            Self::new()
        }
    }

    impl crate::pades::Timestamper for TestTsa {
        fn timestamp(&self, digest: &[u8; 32]) -> crate::Result<Vec<u8>> {
            let now = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .expect("format");
            Ok(self.stamp(digest, &now))
        }
    }

    /// The value of a `Validity` SEQUENCE with each UTCTime (`YYMMDDHHMMSSZ`) rewritten as the
    /// same instant in GeneralizedTime, as a whole DER SEQUENCE.
    fn generalized_validity(value: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for t in children(value).expect("validity") {
            if t.tag == 0x17 {
                let century: &[u8] = if &t.value[..2] < b"50".as_slice() {
                    b"20"
                } else {
                    b"19"
                };
                body.extend(tlv(TAG_GENERALIZED_TIME, &[century, t.value].concat()));
            } else {
                body.extend_from_slice(t.der);
            }
        }
        tlv(0x30, &body)
    }

    /// `der` with every element equal to `from` replaced by `to`, re-encoding the lengths of the
    /// constructed elements around it. Lets a test put a certificate into a token or CMS as
    /// exact bytes, which the CMS builder (it re-encodes) cannot do.
    pub fn replace_element(der: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        if der == from {
            return to.to_vec();
        }
        let Ok(t) = read_tlv(der) else {
            return der.to_vec();
        };
        if t.tag & 0x20 == 0 {
            return der.to_vec(); // primitive: nothing inside to replace
        }
        let Ok(kids) = children(t.value) else {
            return der.to_vec();
        };
        let body: Vec<u8> = kids
            .iter()
            .flat_map(|k| replace_element(k.der, from, to))
            .collect();
        tlv(t.tag, &body)
    }

    /// Convert an RFC 3339 string to an ASN.1 GeneralizedTime body (`YYYYMMDDHHMMSSZ`).
    fn generalized_time(rfc3339: &str) -> String {
        let digits: String = rfc3339
            .chars()
            .filter(|c| c.is_ascii_digit())
            .take(14)
            .collect();
        format!("{digits}Z")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_is_wellformed() {
        let digest = [0xABu8; 32];
        let req = build_request(&digest);
        let top = read_tlv(&req).unwrap();
        assert_eq!(top.tag, 0x30);
        let kids = children(top.value).unwrap();
        assert_eq!(kids.len(), 3, "version, messageImprint, certReq");
        assert_eq!(kids[0].value, &[0x01]); // version v1
        assert_eq!(kids[2].value, &[0xff]); // certReq TRUE
                                            // messageImprint = SEQ { sha256AlgId, OCTET STRING(digest) }
        let mi = children(kids[1].value).unwrap();
        assert_eq!(mi[0].der, SHA256_ALGID);
        assert_eq!(mi[1].tag, TAG_OCTET_STRING);
        assert_eq!(mi[1].value, &digest);
    }

    /// A test TSA, its certificate with GeneralizedTime validity dates, a token from it that
    /// carries exactly those certificate bytes, and a time inside the certificate's validity.
    fn generalized_time_token() -> (testing::TestTsa, Vec<u8>, Vec<u8>, i64) {
        use der::{Decode, Encode};
        let tsa = testing::TestTsa::new();
        let gt_cert = tsa.cert_der_with_generalized_time();
        // A re-encoding is not what the TSA signed: that is what these tests are about.
        let reencoded = x509_cert::Certificate::from_der(&gt_cert)
            .unwrap()
            .to_der()
            .unwrap();
        assert_ne!(reencoded, gt_cert);
        let now = time::OffsetDateTime::now_utc();
        let rfc3339 = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        // Without the ESS attribute: it names the certificate the TSA signed with by hash, and
        // these tests swap in a re-encoding of it.
        let token = tsa.stamp_without_ess(&[7u8; 32], &rfc3339);
        let token = testing::replace_element(&token, &tsa.cert_der(), &gt_cert);
        assert!(
            token.windows(gt_cert.len()).any(|w| w == gt_cert),
            "the token carries the certificate's exact bytes"
        );
        (tsa, gt_cert, token, now.unix_timestamp())
    }

    #[test]
    fn token_certificates_are_returned_as_embedded() {
        let (_, gt_cert, token, _) = generalized_time_token();
        assert_eq!(token_certificates(&token), vec![gt_cert]);
    }

    #[test]
    fn a_generalized_time_anchor_matches_its_exact_bytes() {
        let (_, gt_cert, token, now) = generalized_time_token();
        let sig = verify_tsa_signature(&token, &[gt_cert], now);
        assert!(sig.signature_valid, "{}", sig.detail);
        assert!(sig.trusted, "{}", sig.detail);
    }

    #[test]
    fn a_generalized_time_certificate_is_checked_over_the_bytes_its_issuer_signed() {
        // The token's copy is the TSA certificate re-signed with GeneralizedTime dates: its
        // signature verifies over its original tbsCertificate, not over a re-encoding.
        let (tsa, gt_cert, token, now) = generalized_time_token();
        let issuer = RawCert::parse(&tsa.cert_der()).unwrap();
        assert!(cert_signed_by(&RawCert::parse(&gt_cert).unwrap(), &issuer));

        // A copy whose signature does not cover its bytes does not verify.
        let mut forged = gt_cert.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(!cert_signed_by(&RawCert::parse(&forged).unwrap(), &issuer));

        // The self-signed TSA certificate is no certificate authority: as an anchor it vouches
        // for itself, not for another certificate its key signed (finding 3 of
        // docs/SECURITY_REVIEW_2026-10-27.md).
        let sig = verify_tsa_signature(&token, &[tsa.cert_der()], now);
        assert!(sig.signature_valid, "{}", sig.detail);
        assert!(
            !sig.trusted && sig.detail.contains("may not issue"),
            "{}",
            sig.detail
        );
    }

    /// A token whose ESS attribute names another certificate than the one it carries is refused,
    /// even when that certificate has the same key; one without the attribute is accepted.
    #[test]
    fn the_ess_attribute_must_name_the_signing_certificate() {
        let tsa = testing::TestTsa::new();
        let now = time::OffsetDateTime::now_utc();
        let rfc3339 = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let anchors = [tsa.cert_der()];
        let token = tsa.stamp(&[7u8; 32], &rfc3339);
        let sig = verify_tsa_signature(&token, &anchors, now.unix_timestamp());
        assert!(sig.trusted, "{}", sig.detail);

        let swapped = testing::replace_element(
            &token,
            &tsa.cert_der(),
            &tsa.cert_der_with_generalized_time(),
        );
        let sig = verify_tsa_signature(&swapped, &anchors, now.unix_timestamp());
        assert!(!sig.signature_valid && !sig.trusted);
        assert!(
            sig.detail.contains("signing-certificate-v2"),
            "{}",
            sig.detail
        );

        let plain = tsa.stamp_without_ess(&[7u8; 32], &rfc3339);
        assert!(verify_tsa_signature(&plain, &anchors, now.unix_timestamp()).trusted);
    }

    #[test]
    fn the_test_tsa_marks_its_timestamping_eku_critical() {
        use der::Decode;
        let cert = x509_cert::Certificate::from_der(&testing::TestTsa::new().cert_der()).unwrap();
        let eku = cert
            .tbs_certificate()
            .extensions()
            .unwrap()
            .iter()
            .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE)
            .expect("an EKU");
        assert!(eku.critical, "RFC 3161 §2.3 requires a critical EKU");
    }

    #[test]
    fn generalized_time_to_rfc3339() {
        assert_eq!(
            parse_generalized_time(b"20260623170012Z").unwrap(),
            "2026-06-23T17:00:12Z"
        );
        assert_eq!(
            parse_generalized_time(b"20260623170012.123Z").unwrap(),
            "2026-06-23T17:00:12Z"
        );
        assert!(parse_generalized_time(b"2026").is_err());
    }
}
