//! Long-term validation material (PAdES B-LT): revocation evidence for the certificates of
//! time-stamp authority chains, and how a document's validation data is judged.
//!
//! A timestamp is trusted when its TSA certificate chains to an anchor of the verifier's trust
//! store ([`crate::timestamp::verify_tsa_signature`]). Years later, a verifier also wants to know
//! that no certificate of that chain had been revoked when the timestamp was made, and the
//! authorities that could say so may have changed their addresses or closed. PAdES keeps the
//! answers in the document: its document security store (DSS) holds the chain's certificates and
//! the OCSP responses and CRLs about them ([`crate::pades::Dss`]).
//!
//! The engine stays transport-agnostic, as for timestamps: it tells the host what to fetch
//! ([`crate::workflow::revocation_targets`]: each certificate, its issuer, the OCSP and CRL
//! addresses the certificate names, and a ready OCSP request), checks what the host fetched
//! before it goes into a document ([`check_ocsp`], [`check_crl`]), and judges what a document
//! carries when it is verified ([`assess_chain`]).
//!
//! Evidence is checked, never taken on trust:
//!
//! * an **OCSP response** must be successful, answer for exactly the certificate (its `CertID`:
//!   issuer name hash, issuer key hash and serial number, with SHA-1 or SHA-256), and be signed by
//!   the certificate's issuer or by a responder the issuer delegated (a certificate it issued
//!   with `id-kp-OCSPSigning`, valid when it signed);
//! * a **CRL** must be issued and signed by the certificate's issuer and carry no critical
//!   extension, so delta, partitioned and indirect CRLs, whose scope the engine does not work out,
//!   are not used.
//!
//! Signature algorithms are those of timestamps: RSA PKCS#1 v1.5 with SHA-256/384/512 and ECDSA
//! P-256 with SHA-256. A delegated responder's own revocation status is not checked (responders
//! normally carry `id-pkix-ocsp-nocheck`).
//!
//! The DER is walked by hand (with the reader in [`crate::timestamp`]) rather than decoded into
//! fixed structures: responders and CAs vary in optional fields, and signatures must be checked
//! over the exact bytes that were signed.

use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::timestamp::{
    cert_signed_by, cert_valid_at, children, digest_with, read_tlv, tlv, verify_with_spki, RawCert,
    Tlv,
};

/// What one piece of revocation evidence says about a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationState {
    /// Not revoked when the authority produced the evidence.
    Good,
    /// Revoked at this time (seconds since the epoch).
    Revoked { at: i64 },
    /// The OCSP responder does not know the certificate.
    Unknown,
}

/// Where a piece of evidence comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSource {
    Ocsp,
    Crl,
}

impl EvidenceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceSource::Ocsp => "ocsp",
            EvidenceSource::Crl => "crl",
        }
    }
}

/// A checked OCSP response or CRL about one certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    pub source: EvidenceSource,
    pub state: RevocationState,
    /// When the authority knew the status to be correct (`thisUpdate`), seconds since the epoch.
    pub this_update: i64,
    /// Until when the authority vouches for it (`nextUpdate`), when it says.
    pub next_update: Option<i64>,
}

impl Evidence {
    /// Whether this evidence speaks for the certificate's status at `when`: it was produced at
    /// or after that time (a certificate the authority still calls good then had not been
    /// revoked before), or the authority vouched for its status over a period that includes it
    /// (`thisUpdate` to `nextUpdate`). A revocation always speaks for itself, whenever it was
    /// published.
    pub fn covers(&self, when: i64) -> bool {
        self.this_update >= when
            || self
                .next_update
                .is_some_and(|next| self.this_update <= when && when <= next)
    }
}

// --- certificate parts --------------------------------------------------------------------------

/// The parts of a certificate the revocation checks compare, as the exact bytes the issuer signed.
struct CertParts<'a> {
    /// The serial number's INTEGER content octets.
    serial: &'a [u8],
    /// The issuer `Name`, as a whole DER element.
    issuer: &'a [u8],
    /// The subject `Name`, as a whole DER element.
    subject: &'a [u8],
    /// The `subjectPublicKey` BIT STRING's bits (without the unused-bits octet).
    public_key: &'a [u8],
}

fn cert_parts(der: &[u8]) -> Option<CertParts<'_>> {
    let cert = read_tlv(der).ok().filter(|t| t.tag == 0x30)?;
    let tbs = children(cert.value)
        .ok()?
        .into_iter()
        .next()
        .filter(|t| t.tag == 0x30)?;
    let parts = children(tbs.value).ok()?;
    // tbsCertificate: [0] version (optional), serialNumber, signature, issuer, validity, subject,
    // subjectPublicKeyInfo, ...
    let i = usize::from(parts.first()?.tag == 0xA0);
    let at = |k: usize, tag: u8| parts.get(i + k).filter(|t| t.tag == tag);
    let serial = at(0, 0x02)?.value;
    let issuer = at(2, 0x30)?.der;
    let subject = at(4, 0x30)?.der;
    let spki = at(5, 0x30)?;
    let bits = children(spki.value)
        .ok()?
        .into_iter()
        .nth(1)
        .filter(|t| t.tag == 0x03)?
        .value;
    let public_key = bits.strip_prefix(&[0u8])?;
    Some(CertParts {
        serial,
        issuer,
        subject,
        public_key,
    })
}

/// Whether `der` is one X.509 certificate (and nothing more).
pub fn is_certificate(der: &[u8]) -> bool {
    read_tlv(der).is_ok_and(|t| t.der.len() == der.len())
        && RawCert::parse(der).is_some()
        && cert_parts(der).is_some()
}

/// Whether `cert` carries the extended key usage `oid`.
fn has_eku(cert: &x509_cert::Certificate, oid: &const_oid::ObjectIdentifier) -> bool {
    use der::Decode;
    cert.tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .filter(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE)
        .any(|e| {
            x509_cert::ext::pkix::ExtendedKeyUsage::from_der(e.extn_value.as_bytes())
                .is_ok_and(|eku| eku.0.contains(oid))
        })
}

/// Subject common name of a certificate (DER), for reports.
pub fn subject_name(der: &[u8]) -> String {
    RawCert::parse(der)
        .and_then(|c| crate::timestamp::cert_common_name(&c.cert))
        .unwrap_or_default()
}

/// The http(s) addresses in `cert`'s extension `extn` that `pick` finds.
fn urls_in(
    cert_der: &[u8],
    extn: const_oid::ObjectIdentifier,
    pick: fn(&[u8]) -> Vec<String>,
) -> Vec<String> {
    let Some(cert) = RawCert::parse(cert_der) else {
        return Vec::new();
    };
    let mut out: Vec<String> = cert
        .cert
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .filter(|e| e.extn_id == extn)
        .flat_map(|e| pick(e.extn_value.as_bytes()))
        .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
        .collect();
    out.dedup();
    out
}

fn uri(name: &x509_cert::ext::pkix::name::GeneralName) -> Option<String> {
    match name {
        x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(u) => {
            Some(u.to_string())
        }
        _ => None,
    }
}

/// The OCSP responder addresses `cert` names (authority information access, `id-ad-ocsp`).
pub fn ocsp_urls(cert_der: &[u8]) -> Vec<String> {
    urls_in(
        cert_der,
        const_oid::db::rfc5280::ID_PE_AUTHORITY_INFO_ACCESS,
        |value| {
            use der::Decode;
            x509_cert::ext::pkix::AuthorityInfoAccessSyntax::from_der(value)
                .map(|aia| {
                    aia.0
                        .iter()
                        .filter(|d| d.access_method == const_oid::db::rfc5280::ID_AD_OCSP)
                        .filter_map(|d| uri(&d.access_location))
                        .collect()
                })
                .unwrap_or_default()
        },
    )
}

/// The CRL addresses `cert` names (CRL distribution points, full names).
pub fn crl_urls(cert_der: &[u8]) -> Vec<String> {
    urls_in(
        cert_der,
        const_oid::db::rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS,
        |value| {
            use der::Decode;
            use x509_cert::ext::pkix::name::DistributionPointName;
            x509_cert::ext::pkix::CrlDistributionPoints::from_der(value)
                .map(|cdp| {
                    cdp.0
                        .iter()
                        .filter_map(|dp| match &dp.distribution_point {
                            Some(DistributionPointName::FullName(names)) => Some(names),
                            _ => None,
                        })
                        .flatten()
                        .filter_map(uri)
                        .collect()
                })
                .unwrap_or_default()
        },
    )
}

// --- DER helpers ---------------------------------------------------------------------------------

/// Seconds since the epoch of a DER `UTCTime` (`YYMMDDHHMMSSZ`) or `GeneralizedTime`
/// (`YYYYMMDDHHMMSS[.fff]Z`).
fn der_time(t: &Tlv<'_>) -> Option<i64> {
    let s = std::str::from_utf8(t.value).ok().filter(|s| s.is_ascii())?;
    let s = s.strip_suffix('Z')?;
    let (year, rest) = match t.tag {
        0x17 if s.len() == 12 => {
            let yy: i32 = s[..2].parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &s[2..])
        }
        0x18 if s.len() >= 14 => {
            let fraction = &s[14..];
            let fraction_ok = fraction.is_empty()
                || fraction
                    .strip_prefix('.')
                    .is_some_and(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()));
            if !fraction_ok {
                return None;
            }
            (s[..4].parse().ok()?, &s[4..14])
        }
        _ => return None,
    };
    if !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |k: usize| rest[k..k + 2].parse::<u8>().ok();
    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(n(0)?).ok()?, n(2)?).ok()?;
    Some(
        date.with_hms(n(4)?, n(6)?, n(8)?)
            .ok()?
            .assume_utc()
            .unix_timestamp(),
    )
}

fn oid_of(alg: &Tlv<'_>) -> Option<const_oid::ObjectIdentifier> {
    if alg.tag != 0x30 {
        return None;
    }
    children(alg.value)
        .ok()?
        .first()
        .filter(|t| t.tag == 0x06)
        .and_then(|t| const_oid::ObjectIdentifier::from_bytes(t.value).ok())
}

/// The bits of a DER BIT STRING with no unused bits.
fn bit_string<'a>(t: &Tlv<'a>) -> Option<&'a [u8]> {
    (t.tag == 0x03).then_some(())?;
    t.value.strip_prefix(&[0u8])
}

/// Whether a DER `Extensions` SEQUENCE holds an extension marked critical.
fn has_critical_extension(extensions: &Tlv<'_>) -> bool {
    children(extensions.value).is_ok_and(|exts| {
        exts.iter().any(|e| {
            children(e.value).is_ok_and(|parts| {
                parts
                    .get(1)
                    .is_some_and(|c| c.tag == 0x01 && c.value.iter().any(|b| *b != 0))
            })
        })
    })
}

fn sha1(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}

// --- OCSP ----------------------------------------------------------------------------------------

/// `AlgorithmIdentifier { id-sha1, NULL }`, the CertID hash of RFC 5019 OCSP requests.
const SHA1_ALGID: &[u8] = &[
    0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
];

/// Build a DER `OCSPRequest` for `cert`, issued by `issuer` (RFC 6960, in the RFC 5019 profile
/// every public responder answers: one certificate, a SHA-1 `CertID`, no nonce and no signature).
/// POST it with `Content-Type: application/ocsp-request`; the answer goes to [`check_ocsp`].
pub fn ocsp_request(cert_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>, String> {
    let cert = cert_parts(cert_der).ok_or("the certificate does not parse")?;
    let issuer = cert_parts(issuer_der).ok_or("the issuer certificate does not parse")?;
    if cert.issuer != issuer.subject {
        return Err("the issuer certificate did not issue this certificate".into());
    }
    let mut cert_id = SHA1_ALGID.to_vec();
    cert_id.extend(tlv(0x04, &sha1(cert.issuer)));
    cert_id.extend(tlv(0x04, &sha1(issuer.public_key)));
    cert_id.extend(tlv(0x02, cert.serial));
    let request = tlv(0x30, &tlv(0x30, &cert_id)); // Request { reqCert }
    let tbs_request = tlv(0x30, &tlv(0x30, &request)); // TBSRequest { requestList }
    Ok(tlv(0x30, &tbs_request))
}

/// Who signed an OCSP response.
enum Responder<'a> {
    /// The responder's subject `Name` (whole DER element).
    ByName(&'a [u8]),
    /// SHA-1 of the responder's public key bits.
    ByKey(&'a [u8]),
}

impl Responder<'_> {
    fn is(&self, cert: &CertParts<'_>) -> bool {
        match self {
            Responder::ByName(name) => *name == cert.subject,
            Responder::ByKey(hash) => *hash == sha1(cert.public_key).as_slice(),
        }
    }
}

/// One `SingleResponse`.
struct Single<'a> {
    hash_alg: const_oid::ObjectIdentifier,
    name_hash: &'a [u8],
    key_hash: &'a [u8],
    serial: &'a [u8],
    state: RevocationState,
    this_update: i64,
    next_update: Option<i64>,
}

impl Single<'_> {
    /// Whether this response is about `cert`, issued by `issuer`.
    fn is_about(&self, cert: &CertParts<'_>, issuer: &CertParts<'_>) -> bool {
        let hash = |data: &[u8]| {
            if self.hash_alg == const_oid::db::rfc5912::ID_SHA_1 {
                Some(sha1(data))
            } else {
                digest_with(&self.hash_alg, data)
            }
        };
        self.serial == cert.serial
            && hash(cert.issuer).as_deref() == Some(self.name_hash)
            && hash(issuer.public_key).as_deref() == Some(self.key_hash)
    }
}

/// A successful `BasicOCSPResponse`, read without checking its signature.
struct Basic<'a> {
    /// `tbsResponseData`, exactly as signed.
    tbs: &'a [u8],
    sig_alg: const_oid::ObjectIdentifier,
    signature: &'a [u8],
    /// Certificates the responder included (a delegated responder's own certificate).
    certs: Vec<&'a [u8]>,
    responder: Responder<'a>,
    produced_at: i64,
    responses: Vec<Single<'a>>,
}

fn parse_single<'a>(t: &Tlv<'a>) -> Result<Single<'a>, String> {
    let bad = || "an OCSP SingleResponse is malformed".to_string();
    let parts = children(t.value).map_err(|_| bad())?;
    let cert_id = parts.first().filter(|p| p.tag == 0x30).ok_or_else(bad)?;
    let id = children(cert_id.value).map_err(|_| bad())?;
    let (Some(alg), Some(name_hash), Some(key_hash), Some(serial)) =
        (id.first(), id.get(1), id.get(2), id.get(3))
    else {
        return Err(bad());
    };
    if name_hash.tag != 0x04 || key_hash.tag != 0x04 || serial.tag != 0x02 {
        return Err(bad());
    }
    let hash_alg = oid_of(alg).ok_or_else(bad)?;
    let status = parts.get(1).ok_or_else(bad)?;
    let state = match status.tag {
        0x80 => RevocationState::Good,
        0x82 => RevocationState::Unknown,
        0xA1 => {
            // revoked [1] IMPLICIT RevokedInfo { revocationTime, [0] reason OPTIONAL }
            let info = children(status.value).map_err(|_| bad())?;
            let at = info.first().and_then(der_time).ok_or_else(bad)?;
            RevocationState::Revoked { at }
        }
        _ => return Err(bad()),
    };
    let this_update = parts
        .get(2)
        .filter(|p| p.tag == 0x18)
        .and_then(der_time)
        .ok_or_else(bad)?;
    let mut next_update = None;
    for extra in parts.iter().skip(3) {
        match extra.tag {
            // nextUpdate [0] EXPLICIT GeneralizedTime
            0xA0 => {
                let inner = read_tlv(extra.value).map_err(|_| bad())?;
                next_update = Some(der_time(&inner).ok_or_else(bad)?);
            }
            // singleExtensions [1]
            0xA1 => {}
            _ => return Err(bad()),
        }
    }
    Ok(Single {
        hash_alg,
        name_hash: name_hash.value,
        key_hash: key_hash.value,
        serial: serial.value,
        state,
        this_update,
        next_update,
    })
}

fn basic_response(der: &[u8]) -> Result<Basic<'_>, String> {
    let bad = |what: &str| format!("not an OCSP response ({what})");
    let resp = read_tlv(der)
        .ok()
        .filter(|t| t.tag == 0x30 && t.der.len() == der.len())
        .ok_or_else(|| bad("not one DER SEQUENCE"))?;
    let kids = children(resp.value).map_err(|_| bad("malformed"))?;
    let status = kids
        .first()
        .filter(|t| t.tag == 0x0A)
        .ok_or_else(|| bad("no status"))?;
    if status.value != [0] {
        return Err(format!(
            "the OCSP responder did not answer (status {})",
            status.value.first().copied().unwrap_or(0xff)
        ));
    }
    // responseBytes [0] EXPLICIT ResponseBytes { responseType, response OCTET STRING }
    let bytes = kids
        .get(1)
        .filter(|t| t.tag == 0xA0)
        .and_then(|t| read_tlv(t.value).ok())
        .filter(|t| t.tag == 0x30)
        .and_then(|t| children(t.value).ok())
        .ok_or_else(|| bad("no response bytes"))?;
    let kind = bytes.first().filter(|t| t.tag == 0x06).map(|t| t.value);
    if kind != Some(const_oid::db::rfc6960::ID_PKIX_OCSP_BASIC.as_bytes()) {
        return Err(bad("not a basic OCSP response"));
    }
    let basic = bytes
        .get(1)
        .filter(|t| t.tag == 0x04)
        .and_then(|t| read_tlv(t.value).ok())
        .filter(|t| t.tag == 0x30)
        .ok_or_else(|| bad("no basic response"))?;
    let parts = children(basic.value).map_err(|_| bad("malformed basic response"))?;
    let (Some(tbs), Some(alg), Some(sig)) = (parts.first(), parts.get(1), parts.get(2)) else {
        return Err(bad("incomplete basic response"));
    };
    if tbs.tag != 0x30 {
        return Err(bad("no response data"));
    }
    let sig_alg = oid_of(alg).ok_or_else(|| bad("no signature algorithm"))?;
    let signature = bit_string(sig).ok_or_else(|| bad("no signature"))?;
    let mut certs = Vec::new();
    if let Some(list) = parts.get(3).filter(|t| t.tag == 0xA0) {
        let seq = read_tlv(list.value)
            .ok()
            .filter(|t| t.tag == 0x30)
            .ok_or_else(|| bad("malformed certificates"))?;
        for c in children(seq.value).map_err(|_| bad("malformed certificates"))? {
            certs.push(c.der);
        }
    }

    // ResponseData { [0] version DEFAULT v1, responderID, producedAt, responses, [1] extensions }
    let data = children(tbs.value).map_err(|_| bad("malformed response data"))?;
    let mut i = 0;
    if data.first().is_some_and(|t| t.tag == 0xA0) {
        if data[0].value != [0x02, 0x01, 0x00] {
            return Err(bad("unknown version"));
        }
        i = 1;
    }
    let responder = match data.get(i) {
        Some(t) if t.tag == 0xA1 => Responder::ByName(
            read_tlv(t.value)
                .map_err(|_| bad("malformed responder name"))?
                .der,
        ),
        Some(t) if t.tag == 0xA2 => Responder::ByKey(
            read_tlv(t.value)
                .ok()
                .filter(|k| k.tag == 0x04)
                .ok_or_else(|| bad("malformed responder key"))?
                .value,
        ),
        _ => return Err(bad("no responder id")),
    };
    let produced_at = data
        .get(i + 1)
        .filter(|t| t.tag == 0x18)
        .and_then(der_time)
        .ok_or_else(|| bad("no production time"))?;
    let list = data
        .get(i + 2)
        .filter(|t| t.tag == 0x30)
        .ok_or_else(|| bad("no responses"))?;
    let responses = children(list.value)
        .map_err(|_| bad("malformed responses"))?
        .iter()
        .map(parse_single)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Basic {
        tbs: tbs.der,
        sig_alg,
        signature,
        certs,
        responder,
        produced_at,
        responses,
    })
}

/// Whether `der` is a successful basic OCSP response (its content is not checked here).
pub fn is_ocsp_response(der: &[u8]) -> bool {
    basic_response(der).is_ok()
}

/// Whether `signer` signed `basic`.
fn signed_by(basic: &Basic<'_>, signer: &RawCert) -> bool {
    verify_with_spki(
        signer.cert.tbs_certificate().subject_public_key_info(),
        &basic.sig_alg,
        None,
        basic.tbs,
        basic.signature,
    )
}

/// Check that `basic` was signed by `issuer` (the certificate authority that issued the
/// certificate it is about) or by a responder that authority delegated.
fn check_ocsp_signer(
    basic: &Basic<'_>,
    issuer: &CertParts<'_>,
    issuer_der: &[u8],
) -> Result<(), String> {
    let issuer_cert = RawCert::parse(issuer_der).ok_or("the issuer certificate does not parse")?;
    if basic.responder.is(issuer) {
        return if signed_by(basic, &issuer_cert) {
            Ok(())
        } else {
            Err(
                "the OCSP response's signature does not verify (or uses an unsupported \
                 algorithm)"
                    .into(),
            )
        };
    }
    for der in &basic.certs {
        let (Some(cert), Some(parts)) = (RawCert::parse(der), cert_parts(der)) else {
            continue;
        };
        if !basic.responder.is(&parts) {
            continue;
        }
        if !cert_signed_by(&cert, &issuer_cert) {
            return Err(
                "the OCSP responder's certificate was not issued by the certificate's issuer"
                    .into(),
            );
        }
        // Only a certificate authority delegates (docs/SECURITY_REVIEW_2026-10-27.md, finding 3).
        if let Some(problem) = crate::timestamp::issuer_problem(&issuer_cert.cert, 0, None) {
            return Err(format!(
                "the certificate's issuer may not delegate OCSP signing: {problem}"
            ));
        }
        if !has_eku(&cert.cert, &const_oid::db::rfc5280::ID_KP_OCSP_SIGNING) {
            return Err("the OCSP responder's certificate does not allow OCSP signing".into());
        }
        if !cert_valid_at(&cert.cert, basic.produced_at) {
            return Err(
                "the OCSP responder's certificate was not valid when it signed the response".into(),
            );
        }
        return if signed_by(basic, &cert) {
            Ok(())
        } else {
            Err(
                "the OCSP response's signature does not verify (or uses an unsupported \
                 algorithm)"
                    .into(),
            )
        };
    }
    Err(
        "the OCSP response is signed neither by the certificate's issuer nor by a responder \
         it delegated"
            .into(),
    )
}

/// Check the OCSP response `response` about `cert`, issued by `issuer` (all DER), and return
/// what it says: it must be successful, answer for exactly this certificate and be signed by its
/// issuer or a responder the issuer delegated.
pub fn check_ocsp(response: &[u8], cert: &[u8], issuer: &[u8]) -> Result<Evidence, String> {
    let c = cert_parts(cert).ok_or("the certificate does not parse")?;
    let i = cert_parts(issuer).ok_or("the issuer certificate does not parse")?;
    if c.issuer != i.subject {
        return Err("the issuer certificate did not issue this certificate".into());
    }
    let basic = basic_response(response)?;
    let single = basic
        .responses
        .iter()
        .find(|s| s.is_about(&c, &i))
        .ok_or("the OCSP response does not answer for this certificate")?;
    check_ocsp_signer(&basic, &i, issuer)?;
    Ok(Evidence {
        source: EvidenceSource::Ocsp,
        state: single.state,
        this_update: single.this_update,
        next_update: single.next_update,
    })
}

// --- CRLs ----------------------------------------------------------------------------------------

/// A CRL, read without checking its signature.
struct Crl<'a> {
    /// `tbsCertList`, exactly as signed.
    tbs: &'a [u8],
    sig_alg: const_oid::ObjectIdentifier,
    signature: &'a [u8],
    issuer: &'a [u8],
    this_update: i64,
    next_update: Option<i64>,
    /// Revoked serial numbers (INTEGER content octets) and when.
    revoked: Vec<(&'a [u8], i64)>,
    /// The CRL, or one of its entries, has a critical extension.
    critical: bool,
}

fn parse_crl(der: &[u8]) -> Result<Crl<'_>, String> {
    let bad = |what: &str| format!("not a CRL ({what})");
    let list = read_tlv(der)
        .ok()
        .filter(|t| t.tag == 0x30 && t.der.len() == der.len())
        .ok_or_else(|| bad("not one DER SEQUENCE"))?;
    let parts = children(list.value).map_err(|_| bad("malformed"))?;
    let (Some(tbs), Some(alg), Some(sig)) = (parts.first(), parts.get(1), parts.get(2)) else {
        return Err(bad("incomplete"));
    };
    if tbs.tag != 0x30 || parts.len() != 3 {
        return Err(bad("malformed"));
    }
    let sig_alg = oid_of(alg).ok_or_else(|| bad("no signature algorithm"))?;
    let signature = bit_string(sig).ok_or_else(|| bad("no signature"))?;
    // TBSCertList { version OPTIONAL, signature, issuer, thisUpdate, nextUpdate OPTIONAL,
    //               revokedCertificates OPTIONAL, [0] crlExtensions OPTIONAL }
    let fields = children(tbs.value).map_err(|_| bad("malformed list"))?;
    let mut i = usize::from(fields.first().is_some_and(|t| t.tag == 0x02));
    if fields.get(i).is_none_or(|t| t.tag != 0x30) {
        return Err(bad("no signature algorithm in the list"));
    }
    let issuer = fields
        .get(i + 1)
        .filter(|t| t.tag == 0x30)
        .ok_or_else(|| bad("no issuer"))?
        .der;
    let this_update = fields
        .get(i + 2)
        .and_then(der_time)
        .ok_or_else(|| bad("no thisUpdate"))?;
    i += 3;
    let mut next_update = None;
    if let Some(t) = fields.get(i).filter(|t| t.tag == 0x17 || t.tag == 0x18) {
        next_update = Some(der_time(t).ok_or_else(|| bad("bad nextUpdate"))?);
        i += 1;
    }
    let mut revoked = Vec::new();
    let mut critical = false;
    if let Some(t) = fields.get(i).filter(|t| t.tag == 0x30) {
        for entry in children(t.value).map_err(|_| bad("malformed entries"))? {
            let e = children(entry.value).map_err(|_| bad("malformed entry"))?;
            let serial = e
                .first()
                .filter(|s| s.tag == 0x02)
                .ok_or_else(|| bad("an entry has no serial number"))?;
            let at = e
                .get(1)
                .and_then(der_time)
                .ok_or_else(|| bad("an entry has no revocation date"))?;
            if let Some(ext) = e.get(2) {
                critical |= has_critical_extension(ext);
            }
            revoked.push((serial.value, at));
        }
        i += 1;
    }
    if let Some(t) = fields.get(i) {
        if t.tag != 0xA0 {
            return Err(bad("unexpected field"));
        }
        let exts = read_tlv(t.value).map_err(|_| bad("malformed extensions"))?;
        critical |= has_critical_extension(&exts);
        i += 1;
    }
    if i != fields.len() {
        return Err(bad("unexpected field"));
    }
    Ok(Crl {
        tbs: tbs.der,
        sig_alg,
        signature,
        issuer,
        this_update,
        next_update,
        revoked,
        critical,
    })
}

/// Whether `der` is a CRL (its content is not checked here).
pub fn is_crl(der: &[u8]) -> bool {
    parse_crl(der).is_ok()
}

/// Check the CRL `crl` for `cert`, issued by `issuer` (all DER), and return what it says: it must
/// be issued and signed by the certificate's issuer and be a complete CRL (no critical
/// extension).
pub fn check_crl(crl: &[u8], cert: &[u8], issuer: &[u8]) -> Result<Evidence, String> {
    let c = cert_parts(cert).ok_or("the certificate does not parse")?;
    let i = cert_parts(issuer).ok_or("the issuer certificate does not parse")?;
    if c.issuer != i.subject {
        return Err("the issuer certificate did not issue this certificate".into());
    }
    let list = parse_crl(crl)?;
    if list.issuer != i.subject {
        return Err("the CRL is not from the certificate's issuer".into());
    }
    if list.critical {
        return Err(
            "the CRL has a critical extension (a delta, partitioned or indirect CRL), which \
             the engine does not use"
                .into(),
        );
    }
    let issuer_cert = RawCert::parse(issuer).ok_or("the issuer certificate does not parse")?;
    if !verify_with_spki(
        issuer_cert.cert.tbs_certificate().subject_public_key_info(),
        &list.sig_alg,
        None,
        list.tbs,
        list.signature,
    ) {
        return Err(
            "the CRL's signature does not verify (or uses an unsupported algorithm)".into(),
        );
    }
    let state = list
        .revoked
        .iter()
        .find(|(serial, _)| *serial == c.serial)
        .map_or(RevocationState::Good, |(_, at)| RevocationState::Revoked {
            at: *at,
        });
    Ok(Evidence {
        source: EvidenceSource::Crl,
        state,
        this_update: list.this_update,
        next_update: list.next_update,
    })
}

// --- judging a chain -----------------------------------------------------------------------------

/// What a document's validation data says about one certificate of a TSA chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ChainCertificate {
    /// Subject common name.
    pub subject: String,
    /// SHA-256 of the certificate (hex).
    pub sha256: String,
    /// The document's DSS holds this certificate.
    pub in_dss: bool,
    /// `anchor` (the trust anchor, which needs no revocation evidence), `good` (not revoked when
    /// the timestamp was made), `revoked`, `unknown` (the OCSP responder does not know it) or
    /// `none` (no evidence in the DSS that covers the timestamp's time).
    pub revocation: String,
    /// Where the status comes from: `ocsp` or `crl`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// When the authority knew the status to be correct (`thisUpdate`), RFC 3339.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub checked_at: String,
    /// When the certificate was revoked, for `revoked`, RFC 3339.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revoked_at: String,
}

/// The validation data's verdict on a trusted timestamp's TSA chain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainAssessment {
    /// One entry per chain certificate, TSA first, anchor last.
    pub certificates: Vec<ChainCertificate>,
    /// Every certificate is in the DSS, and every one but the anchor has evidence that it was
    /// not revoked when the timestamp was made (PAdES B-LT for this timestamp).
    pub complete: bool,
    /// A certificate was revoked at or before the timestamp's time: the timestamp proves
    /// nothing. Names the certificate and when.
    pub revoked_before: Option<String>,
    /// A certificate was revoked after the timestamp was made (it still holds, as the
    /// timestamp predates the revocation).
    pub revoked_after: Option<String>,
}

fn rfc3339(unix: i64) -> String {
    crate::dates::utc_rfc3339(unix).unwrap_or_default()
}

/// Judge the TSA `chain` (DER certificates, TSA first, anchor last, as
/// [`crate::timestamp::TsaSignature::chain`] gives it) of a timestamp made at `when`, from a
/// document's validation data (`certs`, `ocsps`, `crls`: the DSS entries, DER).
///
/// For each certificate but the anchor, every OCSP response and CRL in the DSS that checks
/// against it and its issuer ([`check_ocsp`], [`check_crl`]) is considered: a revocation at or
/// before `when` makes the timestamp worthless whatever else says; otherwise the evidence that
/// covers `when` ([`Evidence::covers`]) gives the status, OCSP first.
pub fn assess_chain(
    chain: &[Vec<u8>],
    certs: &[Vec<u8>],
    ocsps: &[Vec<u8>],
    crls: &[Vec<u8>],
    when: i64,
) -> ChainAssessment {
    let mut out = ChainAssessment {
        complete: !chain.is_empty(),
        ..Default::default()
    };
    for (k, cert) in chain.iter().enumerate() {
        let mut entry = ChainCertificate {
            subject: subject_name(cert),
            sha256: hex::encode(Sha256::digest(cert)),
            in_dss: certs.contains(cert),
            ..Default::default()
        };
        out.complete &= entry.in_dss;
        let Some(issuer) = chain.get(k + 1) else {
            entry.revocation = "anchor".into();
            out.certificates.push(entry);
            continue;
        };
        let evidence: Vec<Evidence> = ocsps
            .iter()
            .filter_map(|o| check_ocsp(o, cert, issuer).ok())
            .chain(crls.iter().filter_map(|c| check_crl(c, cert, issuer).ok()))
            .collect();
        let name = if entry.subject.is_empty() {
            "a TSA chain certificate".to_string()
        } else {
            format!("the TSA chain certificate '{}'", entry.subject)
        };
        let revoked = evidence
            .iter()
            .filter_map(|e| match e.state {
                RevocationState::Revoked { at } => Some((at, e)),
                _ => None,
            })
            .min_by_key(|(at, _)| *at);
        let covering = evidence
            .iter()
            .filter(|e| e.covers(when) && !matches!(e.state, RevocationState::Revoked { .. }))
            .max_by_key(|e| {
                (
                    e.source == EvidenceSource::Ocsp,
                    e.state == RevocationState::Good,
                )
            });
        match (revoked, covering) {
            (Some((at, e)), _) if at <= when => {
                entry.revocation = "revoked".into();
                entry.source = e.source.as_str().into();
                entry.checked_at = rfc3339(e.this_update);
                entry.revoked_at = rfc3339(at);
                out.complete = false;
                out.revoked_before
                    .get_or_insert(format!("{name} was revoked at {}", rfc3339(at)));
            }
            (revoked_later, covering) => {
                if let Some((at, _)) = revoked_later {
                    out.revoked_after
                        .get_or_insert(format!("{name} was revoked at {}", rfc3339(at)));
                }
                match covering {
                    Some(e) => {
                        entry.revocation = match e.state {
                            RevocationState::Good => "good",
                            _ => "unknown",
                        }
                        .into();
                        entry.source = e.source.as_str().into();
                        entry.checked_at = rfc3339(e.this_update);
                    }
                    // Evidence of a revocation after the timestamp still shows the certificate
                    // was good when it was made.
                    None if revoked_later.is_some() => {
                        let (_, e) = revoked_later.expect("checked");
                        entry.revocation = "good".into();
                        entry.source = e.source.as_str().into();
                        entry.checked_at = rfc3339(e.this_update);
                    }
                    None => entry.revocation = "none".into(),
                }
                if let Some((at, _)) = revoked_later {
                    entry.revoked_at = rfc3339(at);
                }
                out.complete &= entry.revocation == "good";
            }
        }
        out.certificates.push(entry);
    }
    out
}

/// Test-only certificate authority: a root that issues TSA certificates naming its OCSP
/// responder and CRL, and answers for them. Gated behind the `test-issuer` feature.
#[cfg(any(test, feature = "test-issuer"))]
pub mod testing {
    use std::str::FromStr;

    use der::asn1::Ia5String;
    use der::Encode;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{DerSignature, SigningKey};
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::builder::{Builder, CertificateBuilder};
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
    use x509_cert::ext::pkix::{
        AccessDescription, AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, BasicConstraints,
        CrlDistributionPoints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectKeyIdentifier,
    };
    use x509_cert::ext::ToExtension;
    use x509_cert::name::Name;

    use super::*;
    use crate::timestamp::testing::TestTsa;

    /// The OCSP responder address the test CA writes into the certificates it issues.
    pub const TEST_OCSP_URL: &str = "http://ocsp.ca.test/";
    /// The CRL address the test CA writes into the certificates it issues.
    pub const TEST_CRL_URL: &str = "http://crl.ca.test/root.crl";

    /// What a certificate the test CA issues is for.
    #[derive(Clone, Copy)]
    enum Role {
        /// A certificate authority (the root, or a subordinate one), with an optional path
        /// length constraint.
        Ca(Option<u8>),
        Tsa,
        OcspResponder,
        /// An end-entity certificate with no extended key usage (as a code-signing certificate
        /// bought from a public CA might be): not allowed to issue certificates.
        EndEntity,
        /// A TSA certificate whose timestamping purpose is neither alone nor critical.
        LooseTsa,
    }

    struct Profile {
        issuer: Name,
        subject: Name,
        role: Role,
    }

    impl BuilderProfile for Profile {
        fn get_issuer(&self, _subject: &Name) -> Name {
            self.issuer.clone()
        }

        fn get_subject(&self) -> Name {
            self.subject.clone()
        }

        #[allow(clippy::vec_init_then_push)]
        fn build_extensions(
            &self,
            spk: spki::SubjectPublicKeyInfoRef<'_>,
            issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
            tbs: &x509_cert::TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<x509_cert::ext::Extension>> {
            let subject = tbs.subject();
            let mut ext = Vec::new();
            ext.push(SubjectKeyIdentifier::try_from(spk)?.to_extension(subject, &ext)?);
            ext.push(AuthorityKeyIdentifier::try_from(issuer_spk)?.to_extension(subject, &ext)?);
            let (ca, path_len_constraint) = match self.role {
                Role::Ca(path_len) => (true, path_len),
                _ => (false, None),
            };
            ext.push(
                BasicConstraints {
                    ca,
                    path_len_constraint,
                }
                .to_extension(subject, &ext)?,
            );
            let usage = if ca {
                KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
            } else {
                KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation)
            };
            ext.push(usage.to_extension(subject, &ext)?);
            match self.role {
                Role::Ca(_) | Role::EndEntity => {}
                Role::LooseTsa => {
                    // Timestamping among other purposes, not critical: what RFC 3161 §2.3 forbids.
                    ext.push(
                        ExtendedKeyUsage(vec![
                            const_oid::db::rfc5280::ID_KP_TIME_STAMPING,
                            const_oid::db::rfc5280::ID_KP_CODE_SIGNING,
                        ])
                        .to_extension(subject, &ext)?,
                    );
                }
                Role::Tsa => {
                    // RFC 3161 §2.3: the timestamping EKU must be critical.
                    let mut eku =
                        ExtendedKeyUsage(vec![const_oid::db::rfc5280::ID_KP_TIME_STAMPING])
                            .to_extension(subject, &ext)?;
                    eku.critical = true;
                    ext.push(eku);
                    let uri = |u: &str| {
                        GeneralName::UniformResourceIdentifier(
                            Ia5String::new(u).expect("ascii url"),
                        )
                    };
                    ext.push(
                        AuthorityInfoAccessSyntax(vec![AccessDescription {
                            access_method: const_oid::db::rfc5280::ID_AD_OCSP,
                            access_location: uri(TEST_OCSP_URL),
                        }])
                        .to_extension(subject, &ext)?,
                    );
                    ext.push(
                        CrlDistributionPoints(vec![
                            x509_cert::ext::pkix::crl::dp::DistributionPoint {
                                distribution_point: Some(DistributionPointName::FullName(vec![
                                    uri(TEST_CRL_URL),
                                ])),
                                reasons: None,
                                crl_issuer: None,
                            },
                        ])
                        .to_extension(subject, &ext)?,
                    );
                }
                Role::OcspResponder => ext.push(
                    ExtendedKeyUsage(vec![const_oid::db::rfc5280::ID_KP_OCSP_SIGNING])
                        .to_extension(subject, &ext)?,
                ),
            }
            Ok(ext)
        }
    }

    fn generalized(unix: i64) -> Vec<u8> {
        let t = time::OffsetDateTime::from_unix_timestamp(unix).expect("time in range");
        let s = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            t.year(),
            t.month() as u8,
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        );
        tlv(0x18, s.as_bytes())
    }

    fn now() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }

    /// `AlgorithmIdentifier { ecdsa-with-SHA256 }`.
    const ECDSA_SHA256_ALGID: &[u8] = &[
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    ];

    /// What an OCSP response or CRL from the test CA says about a certificate.
    #[derive(Clone, Copy, Debug)]
    pub enum TestStatus {
        Good,
        Revoked(i64),
        Unknown,
    }

    /// A local, **untrusted** root certificate authority with a P-256 key, for tests and demos.
    pub struct TestCa {
        key: SigningKey,
        name: Name,
        der: Vec<u8>,
        serial: std::cell::Cell<u32>,
    }

    impl TestCa {
        /// A fresh root CA named `CN=<common_name>`, valid from a day ago for ten years.
        pub fn new(common_name: &str) -> Self {
            Self::root(common_name, None)
        }

        /// A root CA whose basic constraints allow at most `path_len` CA certificates below it.
        pub fn with_path_len(common_name: &str, path_len: u8) -> Self {
            Self::root(common_name, Some(path_len))
        }

        fn root(common_name: &str, path_len: Option<u8>) -> Self {
            let key = crate::crypto::generate_signing_key();
            let name = Name::from_str(&format!("CN={common_name},O=SignPDF Tests")).expect("name");
            let ca = Self {
                key,
                name: name.clone(),
                der: Vec::new(),
                serial: std::cell::Cell::new(1),
            };
            let der = ca.issue(&ca.key, name, Role::Ca(path_len));
            Self { der, ..ca }
        }

        /// A certificate this CA issues to a new key, returned as a `TestCa` that signs with that
        /// key: a subordinate CA when `ca`, else an end-entity certificate (not allowed to issue
        /// certificates, though nothing stops its key from signing one).
        pub fn issue_subordinate(&self, common_name: &str, ca: bool) -> TestCa {
            let key = crate::crypto::generate_signing_key();
            let name = Name::from_str(&format!("CN={common_name},O=SignPDF Tests")).expect("name");
            let role = if ca { Role::Ca(None) } else { Role::EndEntity };
            let der = self.issue(&key, name.clone(), role);
            TestCa {
                key,
                name,
                der,
                serial: std::cell::Cell::new(1),
            }
        }

        fn issue(&self, subject_key: &SigningKey, subject: Name, role: Role) -> Vec<u8> {
            let serial = self.serial.get();
            self.serial.set(serial + 1);
            let start = now() - 86_400;
            let time = |unix: i64| {
                der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
                    unix as u64,
                ))
                .map(x509_cert::time::Time::from)
                .expect("time")
            };
            let validity = x509_cert::time::Validity::new(time(start), time(start + 3650 * 86_400));
            let spki =
                x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(subject_key.verifying_key())
                    .expect("spki");
            let builder = CertificateBuilder::new(
                Profile {
                    issuer: self.name.clone(),
                    subject,
                    role,
                },
                x509_cert::serial_number::SerialNumber::from(serial),
                validity,
                spki,
            )
            .expect("builder");
            builder
                .build::<_, DerSignature>(&self.key)
                .expect("certificate")
                .to_der()
                .expect("der")
        }

        /// The root certificate (DER): the trust anchor for the TSAs it issues.
        pub fn cert_der(&self) -> Vec<u8> {
            self.der.clone()
        }

        /// A TSA whose certificate this CA issued (`CN=<common_name>`), naming
        /// [`TEST_OCSP_URL`] and [`TEST_CRL_URL`]. Its tokens carry only its own certificate, so
        /// they are trusted through this CA's certificate as an anchor.
        pub fn issue_tsa(&self, common_name: &str) -> TestTsa {
            use der::Decode;
            let key = crate::crypto::generate_signing_key();
            let subject =
                Name::from_str(&format!("CN={common_name},O=SignPDF Tests")).expect("name");
            let der = self.issue(&key, subject, Role::Tsa);
            TestTsa::with_certificate(key, x509_cert::Certificate::from_der(&der).expect("cert"))
        }

        /// [`TestCa::issue_tsa`], but the certificate lists timestamping beside code signing in a
        /// non-critical extended key usage (RFC 3161 §2.3 asks for timestamping alone, critical).
        pub fn issue_tsa_with_loose_eku(&self, common_name: &str) -> TestTsa {
            use der::Decode;
            let key = crate::crypto::generate_signing_key();
            let subject =
                Name::from_str(&format!("CN={common_name},O=SignPDF Tests")).expect("name");
            let der = self.issue(&key, subject, Role::LooseTsa);
            TestTsa::with_certificate(key, x509_cert::Certificate::from_der(&der).expect("cert"))
        }

        /// A delegated OCSP responder: its key and the certificate this CA issued it.
        pub fn issue_ocsp_responder(&self) -> (SigningKey, Vec<u8>) {
            let key = crate::crypto::generate_signing_key();
            let subject =
                Name::from_str("CN=SignPDF Test OCSP Responder,O=SignPDF Tests").expect("name");
            let der = self.issue(&key, subject, Role::OcspResponder);
            (key, der)
        }

        /// An OCSP response about `cert` (which this CA issued), signed by the CA itself, with
        /// `thisUpdate` a minute ago and `nextUpdate` a week later.
        pub fn ocsp_response(&self, cert: &[u8], status: TestStatus) -> Vec<u8> {
            let at = now() - 60;
            self.ocsp_response_at(cert, status, at, Some(at + 7 * 86_400))
        }

        /// [`Self::ocsp_response`] with chosen times.
        pub fn ocsp_response_at(
            &self,
            cert: &[u8],
            status: TestStatus,
            this_update: i64,
            next_update: Option<i64>,
        ) -> Vec<u8> {
            let ca = cert_parts(&self.der).expect("ca");
            self.signed_ocsp(
                &self.key,
                tlv(0xA2, &tlv(0x04, &sha1(ca.public_key))),
                None,
                cert,
                status,
                this_update,
                next_update,
            )
        }

        /// An OCSP response about `cert` signed by a delegated responder (`responder`: its key
        /// and certificate, from [`Self::issue_ocsp_responder`] or any other), which it
        /// includes.
        pub fn ocsp_response_by(
            &self,
            responder: &(SigningKey, Vec<u8>),
            cert: &[u8],
            status: TestStatus,
        ) -> Vec<u8> {
            let parts = cert_parts(&responder.1).expect("responder");
            let at = now() - 60;
            self.signed_ocsp(
                &responder.0,
                tlv(0xA1, parts.subject),
                Some(&responder.1),
                cert,
                status,
                at,
                Some(at + 7 * 86_400),
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn signed_ocsp(
            &self,
            key: &SigningKey,
            responder_id: Vec<u8>,
            include: Option<&[u8]>,
            cert: &[u8],
            status: TestStatus,
            this_update: i64,
            next_update: Option<i64>,
        ) -> Vec<u8> {
            let c = cert_parts(cert).expect("cert");
            let ca = cert_parts(&self.der).expect("ca");
            let mut cert_id = SHA1_ALGID.to_vec();
            cert_id.extend(tlv(0x04, &sha1(c.issuer)));
            cert_id.extend(tlv(0x04, &sha1(ca.public_key)));
            cert_id.extend(tlv(0x02, c.serial));
            let mut single = tlv(0x30, &cert_id);
            single.extend(match status {
                TestStatus::Good => vec![0x80, 0x00],
                TestStatus::Unknown => vec![0x82, 0x00],
                TestStatus::Revoked(at) => tlv(0xA1, &generalized(at)),
            });
            single.extend(generalized(this_update));
            if let Some(next) = next_update {
                single.extend(tlv(0xA0, &generalized(next)));
            }
            let mut data = responder_id;
            data.extend(generalized(this_update));
            data.extend(tlv(0x30, &tlv(0x30, &single)));
            let tbs = tlv(0x30, &data);
            let sig: DerSignature = key.sign(&tbs);
            let mut basic = tbs;
            basic.extend_from_slice(ECDSA_SHA256_ALGID);
            basic.extend(tlv(0x03, &[&[0u8][..], &sig.to_bytes()].concat()));
            if let Some(c) = include {
                basic.extend(tlv(0xA0, &tlv(0x30, c)));
            }
            let mut bytes = tlv(0x06, const_oid::db::rfc6960::ID_PKIX_OCSP_BASIC.as_bytes());
            bytes.extend(tlv(0x04, &tlv(0x30, &basic)));
            let mut resp = tlv(0x0A, &[0]);
            resp.extend(tlv(0xA0, &tlv(0x30, &bytes)));
            tlv(0x30, &resp)
        }

        /// A CRL from this CA listing `revoked` (certificates it issued, with when), with
        /// `thisUpdate` a minute ago and `nextUpdate` a week later.
        pub fn crl(&self, revoked: &[(&[u8], i64)]) -> Vec<u8> {
            let at = now() - 60;
            let mut list = ECDSA_SHA256_ALGID.to_vec();
            list.extend_from_slice(cert_parts(&self.der).expect("ca").subject);
            list.extend(generalized(at));
            list.extend(generalized(at + 7 * 86_400));
            if !revoked.is_empty() {
                let mut entries = Vec::new();
                for (cert, when) in revoked {
                    let mut e = tlv(0x02, cert_parts(cert).expect("cert").serial);
                    e.extend(generalized(*when));
                    entries.extend(tlv(0x30, &e));
                }
                list.extend(tlv(0x30, &entries));
            }
            let tbs = tlv(0x30, &list);
            let sig: DerSignature = self.key.sign(&tbs);
            let mut out = tbs;
            out.extend_from_slice(ECDSA_SHA256_ALGID);
            out.extend(tlv(0x03, &[&[0u8][..], &sig.to_bytes()].concat()));
            tlv(0x30, &out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn tsa_cert(ca: &TestCa) -> Vec<u8> {
        ca.issue_tsa("SignPDF Test TSA").cert_der()
    }

    #[test]
    fn an_ocsp_request_names_the_certificate() {
        let ca = TestCa::new("SignPDF Test Root");
        let cert = tsa_cert(&ca);
        let req = ocsp_request(&cert, &ca.cert_der()).unwrap();
        // OCSPRequest { TBSRequest { requestList { Request { CertID } } } }
        let tbs = children(read_tlv(&req).unwrap().value).unwrap();
        let list = children(tbs[0].value).unwrap();
        let request = children(list[0].value).unwrap();
        let one = children(request[0].value).unwrap();
        let cert_id = children(one[0].value).unwrap();
        assert_eq!(cert_id[0].der, SHA1_ALGID);
        assert_eq!(cert_id[3].value, cert_parts(&cert).unwrap().serial);
        // Another CA's certificate is not this one's issuer.
        let other = TestCa::new("Another Root");
        assert!(ocsp_request(&cert, &other.cert_der()).is_err());
    }

    #[test]
    fn the_test_tsa_names_its_ocsp_responder_and_crl() {
        let cert = tsa_cert(&TestCa::new("SignPDF Test Root"));
        assert_eq!(ocsp_urls(&cert), vec![TEST_OCSP_URL.to_string()]);
        assert_eq!(crl_urls(&cert), vec![TEST_CRL_URL.to_string()]);
    }

    #[test]
    fn ocsp_responses_are_checked() {
        let ca = TestCa::new("SignPDF Test Root");
        let cert = tsa_cert(&ca);
        let good = ca.ocsp_response(&cert, TestStatus::Good);
        let e = check_ocsp(&good, &cert, &ca.cert_der()).unwrap();
        assert_eq!(e.state, RevocationState::Good);
        assert_eq!(e.source, EvidenceSource::Ocsp);
        assert!(is_ocsp_response(&good));

        let revoked = ca.ocsp_response(&cert, TestStatus::Revoked(1_700_000_000));
        assert_eq!(
            check_ocsp(&revoked, &cert, &ca.cert_der()).unwrap().state,
            RevocationState::Revoked { at: 1_700_000_000 }
        );
        let unknown = ca.ocsp_response(&cert, TestStatus::Unknown);
        assert_eq!(
            check_ocsp(&unknown, &cert, &ca.cert_der()).unwrap().state,
            RevocationState::Unknown
        );

        // A response about another certificate, or one signed by someone else, is no evidence.
        let other_cert = tsa_cert(&ca);
        assert!(check_ocsp(&good, &other_cert, &ca.cert_der()).is_err());
        let forger = TestCa::new("SignPDF Test Root");
        let forged = forger.ocsp_response(&cert, TestStatus::Good);
        assert!(check_ocsp(&forged, &cert, &ca.cert_der()).is_err());
        let mut tampered = good.clone();
        let at = tampered.len() - 80;
        tampered[at] ^= 1;
        assert!(check_ocsp(&tampered, &cert, &ca.cert_der()).is_err());
    }

    #[test]
    fn a_delegated_responder_must_be_the_issuer_s_and_allowed_to_sign_ocsp() {
        let ca = TestCa::new("SignPDF Test Root");
        let cert = tsa_cert(&ca);
        let responder = ca.issue_ocsp_responder();
        let ok = ca.ocsp_response_by(&responder, &cert, TestStatus::Good);
        assert_eq!(
            check_ocsp(&ok, &cert, &ca.cert_der()).unwrap().state,
            RevocationState::Good
        );

        // A certificate without id-kp-OCSPSigning (here the TSA's own) cannot answer for others.
        let tsa = ca.issue_tsa("Another TSA");
        let (key, _) = ca.issue_ocsp_responder();
        let not_allowed = ca.ocsp_response_by(&(key, tsa.cert_der()), &cert, TestStatus::Good);
        assert!(check_ocsp(&not_allowed, &cert, &ca.cert_der()).is_err());

        // A responder another CA issued cannot answer for this one's certificates.
        let elsewhere = TestCa::new("Elsewhere").issue_ocsp_responder();
        let foreign = ca.ocsp_response_by(&elsewhere, &cert, TestStatus::Good);
        assert!(check_ocsp(&foreign, &cert, &ca.cert_der()).is_err());
    }

    #[test]
    fn crls_are_checked() {
        let ca = TestCa::new("SignPDF Test Root");
        let cert = tsa_cert(&ca);
        let other = tsa_cert(&ca);
        let crl = ca.crl(&[(&other, 1_700_000_000)]);
        assert!(is_crl(&crl));
        assert_eq!(
            check_crl(&crl, &cert, &ca.cert_der()).unwrap().state,
            RevocationState::Good
        );
        assert_eq!(
            check_crl(&crl, &other, &ca.cert_der()).unwrap().state,
            RevocationState::Revoked { at: 1_700_000_000 }
        );
        let forged = TestCa::new("SignPDF Test Root").crl(&[]);
        assert!(check_crl(&forged, &cert, &ca.cert_der()).is_err());
        assert!(!is_crl(b"not a crl"));
        assert!(!is_ocsp_response(&crl));
    }

    #[test]
    fn evidence_covers_the_time_it_speaks_for() {
        let e = Evidence {
            source: EvidenceSource::Ocsp,
            state: RevocationState::Good,
            this_update: 1000,
            next_update: Some(2000),
        };
        assert!(e.covers(500)); // produced after
        assert!(e.covers(1500)); // inside its window
        assert!(!e.covers(2500)); // after its window
        let open = Evidence {
            next_update: None,
            ..e
        };
        assert!(open.covers(1000));
        assert!(!open.covers(1001));
    }

    #[test]
    fn a_chain_is_judged_from_the_validation_data() {
        let ca = TestCa::new("SignPDF Test Root");
        let tsa = tsa_cert(&ca);
        let chain = vec![tsa.clone(), ca.cert_der()];
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let certs = chain.clone();

        // Nothing but the certificates: incomplete.
        let a = assess_chain(&chain, &certs, &[], &[], now);
        assert!(!a.complete);
        assert_eq!(a.certificates[0].revocation, "none");
        assert_eq!(a.certificates[1].revocation, "anchor");

        // A good OCSP response: complete.
        let good = ca.ocsp_response(&tsa, TestStatus::Good);
        let a = assess_chain(&chain, &certs, std::slice::from_ref(&good), &[], now);
        assert!(a.complete, "{a:?}");
        assert_eq!(a.certificates[0].revocation, "good");
        assert_eq!(a.certificates[0].source, "ocsp");

        // A CRL does as well; certificates missing from the DSS do not.
        let crl = ca.crl(&[]);
        assert!(assess_chain(&chain, &certs, &[], std::slice::from_ref(&crl), now).complete);
        assert!(!assess_chain(&chain, &[], std::slice::from_ref(&good), &[], now).complete);

        // Evidence from before the timestamp, whose window ended before it, covers nothing.
        let stale = ca.ocsp_response_at(&tsa, TestStatus::Good, now - 3000, Some(now - 2000));
        assert!(!assess_chain(&chain, &certs, &[stale], &[], now).complete);

        // Revoked before the timestamp: worthless, whatever else the DSS says.
        let revoked = ca.ocsp_response(&tsa, TestStatus::Revoked(now - 10));
        let a = assess_chain(&chain, &certs, &[good.clone(), revoked], &[], now);
        assert!(!a.complete);
        assert!(a.revoked_before.is_some());
        assert_eq!(a.certificates[0].revocation, "revoked");

        // Revoked after it: the timestamp holds.
        let later = ca.crl(&[(&tsa, now + 3600)]);
        let a = assess_chain(&chain, &certs, &[], &[later], now);
        assert!(a.revoked_before.is_none());
        assert!(a.revoked_after.is_some());
        assert!(a.complete, "{a:?}");
    }

    #[test]
    fn times_are_read_in_both_encodings() {
        let utc = read_tlv(&[
            0x17, 0x0d, b'2', b'6', b'1', b'0', b'2', b'7', b'1', b'2', b'0', b'0', b'0', b'0',
            b'Z',
        ])
        .unwrap();
        assert_eq!(der_time(&utc), Some(1_793_102_400));
        let gen = tlv(0x18, b"20261027120000.5Z");
        assert_eq!(der_time(&read_tlv(&gen).unwrap()), Some(1_793_102_400));
        let bad = tlv(0x18, b"2026102712000Z");
        assert_eq!(der_time(&read_tlv(&bad).unwrap()), None);
    }
}
