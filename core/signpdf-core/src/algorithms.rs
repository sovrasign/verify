//! The algorithm policy: which digest and signature algorithms a verifier accepts, until when,
//! and under which timestamp.
//!
//! Every piece of evidence in a signed document rests on algorithms: the signers' PAdES
//! signatures (ECDSA P-256 with SHA-256), the document, nonce and audit-chain digests (SHA-256),
//! the identity tokens (ES256, or RS256 with the provider's RSA key) and the RFC 3161 timestamps
//! (their authority's signature and certificate chain, and the digest they cover). Algorithms
//! weaken over the decades a signed agreement is kept: RSA-2048, which the large identity
//! providers sign tokens with, is on NIST's deprecation path around 2030.
//!
//! A verifier therefore reads which algorithms it accepts from its trust list
//! ([`crate::trust::TrustStore::algorithm_policy`]), a versioned [`AlgorithmPolicy`], instead of
//! hard-coded rules. Each [`AlgorithmRule`] names an algorithm, the smallest key it accepts
//! (`min_key_bits`, RSA), and optionally the time after which it no longer proves anything on
//! its own (`not_after`). Evidence that relies on an algorithm past its `not_after` counts only
//! when a **trusted timestamp, itself made with algorithms the policy accepts**, shows that the
//! evidence existed by then: the archive-timestamp principle of PAdES B-LTA, where each renewed
//! timestamp covers all earlier evidence while its own algorithms are strong. An algorithm the
//! policy does not name, or a key smaller than its rule allows, is not accepted at all.
//!
//! The policy only ever restricts what this build implements: a rule naming an algorithm the
//! engine cannot verify (a newer trust list may name ML-DSA) makes nothing acceptable, and is
//! ignored. Without a policy in the trust list, the verifier applies [`AlgorithmPolicy::builtin`]:
//! every implemented algorithm, RSA from 2048 bits, no end dates.
//!
//! The evidence's time is judged against the verifier's own time ("now"), which the host gives
//! ([`crate::workflow::verify_at`]) or the device clock supplies. A verifier without a clock
//! treats every `not_after` as passed: only trusted timestamps then show evidence came in time.

use serde::{Deserialize, Serialize};

use crate::util::{rfc3339_from_unix, unix_from_rfc3339};

/// The version of [`AlgorithmPolicy::builtin`].
pub const BUILTIN_POLICY_VERSION: u32 = 1;

/// An algorithm this build implements, as the policy names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Algorithm {
    /// SHA-256: document, nonce and audit-chain digests, and digests inside signatures.
    Sha256,
    /// SHA-384 (in timestamps and certificate signatures).
    Sha384,
    /// SHA-512 (in timestamps and certificate signatures).
    Sha512,
    /// ECDSA on the NIST P-256 curve: the signers' and preparer's PAdES signatures, ES256
    /// identity tokens, and timestamp authorities with P-256 keys.
    EcdsaP256,
    /// RSA signatures with PKCS #1 v1.5 padding: RS256 identity tokens and most timestamp
    /// authorities and certificate authorities. The key size is the modulus length in bits.
    RsaPkcs1v15,
}

impl Algorithm {
    /// Every algorithm this build implements.
    pub const ALL: [Algorithm; 5] = [
        Algorithm::Sha256,
        Algorithm::Sha384,
        Algorithm::Sha512,
        Algorithm::EcdsaP256,
        Algorithm::RsaPkcs1v15,
    ];

    /// The name a policy uses: `SHA-256`, `SHA-384`, `SHA-512`, `ECDSA-P256`, `RSA-PKCS1-v1_5`.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "SHA-256",
            Algorithm::Sha384 => "SHA-384",
            Algorithm::Sha512 => "SHA-512",
            Algorithm::EcdsaP256 => "ECDSA-P256",
            Algorithm::RsaPkcs1v15 => "RSA-PKCS1-v1_5",
        }
    }

    /// The algorithm a policy names `name` (`None` for one this build does not implement).
    pub fn parse(name: &str) -> Option<Algorithm> {
        Algorithm::ALL.into_iter().find(|a| a.name() == name)
    }

    /// The digest algorithm with this ASN.1 object identifier (SHA-256/384/512).
    pub fn from_digest_oid(oid: &const_oid::ObjectIdentifier) -> Option<Algorithm> {
        use const_oid::db::rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512};
        if *oid == ID_SHA_256 {
            Some(Algorithm::Sha256)
        } else if *oid == ID_SHA_384 {
            Some(Algorithm::Sha384)
        } else if *oid == ID_SHA_512 {
            Some(Algorithm::Sha512)
        } else {
            None
        }
    }
}

/// One algorithm a piece of evidence relies on, with the key size for RSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AlgorithmUse {
    pub algorithm: Algorithm,
    /// The key size in bits (the RSA modulus length), when the algorithm has one that matters.
    pub key_bits: Option<u32>,
}

impl AlgorithmUse {
    /// An algorithm without a key size (a digest, or ECDSA on a fixed curve).
    pub fn plain(algorithm: Algorithm) -> Self {
        AlgorithmUse {
            algorithm,
            key_bits: None,
        }
    }

    /// RSA with a `bits`-bit modulus.
    pub fn rsa(bits: u32) -> Self {
        AlgorithmUse {
            algorithm: Algorithm::RsaPkcs1v15,
            key_bits: Some(bits),
        }
    }

    /// How a report names it: `SHA-256`, `RSA-PKCS1-v1_5 (2048-bit key)`.
    pub fn label(&self) -> String {
        match self.key_bits {
            Some(bits) => format!("{} ({bits}-bit key)", self.algorithm.name()),
            None => self.algorithm.name().to_string(),
        }
    }
}

/// The length in bits of a big-endian unsigned integer (an RSA modulus).
pub fn bit_length(be: &[u8]) -> u32 {
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    match be.get(first) {
        None => 0,
        Some(&top) => (be.len() - first - 1) as u32 * 8 + (8 - top.leading_zeros()),
    }
}

/// What the policy says about one algorithm.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlgorithmRule {
    /// The algorithm's name ([`Algorithm::name`]). A name this build does not implement is
    /// ignored.
    pub algorithm: String,
    /// The smallest key accepted, in bits (for RSA, the modulus length).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_key_bits: Option<u32>,
    /// From this time (RFC 3339) the algorithm proves nothing on its own: evidence relying on
    /// it counts only when a trusted timestamp, made with algorithms the policy accepts, shows
    /// that the evidence existed by then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

/// A versioned algorithm policy, carried by the trust list. See the module documentation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlgorithmPolicy {
    /// The policy's edition: each change publishes a higher number. When two trust stores are
    /// merged, the higher version wins. Reported with every verification.
    pub version: u32,
    /// The accepted algorithms. Anything not listed is refused.
    #[serde(default)]
    pub algorithms: Vec<AlgorithmRule>,
}

/// How the policy judges the algorithms a piece of evidence relies on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmVerdict {
    /// Every algorithm is accepted at the verifier's time.
    Accepted,
    /// An algorithm is past its `not_after`, but a trusted timestamp shows the evidence existed
    /// by then. The text says which, for a warning.
    AcceptedByTimestamp(String),
    /// Not accepted, with the reason.
    Refused(String),
}

impl AlgorithmVerdict {
    /// Whether the evidence counts.
    pub fn is_accepted(&self) -> bool {
        !matches!(self, AlgorithmVerdict::Refused(_))
    }
}

impl Default for AlgorithmPolicy {
    fn default() -> Self {
        AlgorithmPolicy::builtin()
    }
}

impl AlgorithmPolicy {
    /// The policy a verifier applies when its trust list carries none: every algorithm this
    /// build implements, RSA from 2048 bits, and no end dates.
    pub fn builtin() -> Self {
        let rule = |a: Algorithm, min_key_bits: Option<u32>| AlgorithmRule {
            algorithm: a.name().to_string(),
            min_key_bits,
            not_after: None,
        };
        AlgorithmPolicy {
            version: BUILTIN_POLICY_VERSION,
            algorithms: vec![
                rule(Algorithm::Sha256, None),
                rule(Algorithm::Sha384, None),
                rule(Algorithm::Sha512, None),
                rule(Algorithm::EcdsaP256, None),
                rule(Algorithm::RsaPkcs1v15, Some(2048)),
            ],
        }
    }

    /// Every `not_after` reads as RFC 3339 and no algorithm has two rules.
    pub fn validate(&self) -> std::result::Result<(), String> {
        let mut seen: Vec<&str> = Vec::new();
        for r in &self.algorithms {
            if seen.contains(&r.algorithm.as_str()) {
                return Err(format!(
                    "the algorithm policy has two rules for '{}'",
                    r.algorithm
                ));
            }
            seen.push(&r.algorithm);
            if let Some(t) = &r.not_after {
                if unix_from_rfc3339(t).is_none() {
                    return Err(format!(
                        "the algorithm policy's not_after '{t}' for {} is not an RFC 3339 time",
                        r.algorithm
                    ));
                }
            }
        }
        Ok(())
    }

    /// Whether any rule has an end date (only then does a verification need the time).
    pub fn has_end_dates(&self) -> bool {
        self.algorithms.iter().any(|r| r.not_after.is_some())
    }

    /// The rule for `algorithm`.
    pub fn rule(&self, algorithm: Algorithm) -> Option<&AlgorithmRule> {
        self.algorithms
            .iter()
            .find(|r| r.algorithm == algorithm.name())
    }

    /// Judge evidence relying on `uses`, at the verifier's time `now` (`None`: unknown, so every
    /// end date counts as passed), given the earliest trusted timestamp that shows the evidence
    /// existed (`existed_before`, Unix seconds).
    pub fn judge(
        &self,
        uses: &[AlgorithmUse],
        now: Option<i64>,
        existed_before: Option<i64>,
    ) -> AlgorithmVerdict {
        let mut rescued: Vec<String> = Vec::new();
        for u in uses {
            let name = u.algorithm.name();
            let Some(rule) = self.rule(u.algorithm) else {
                return AlgorithmVerdict::Refused(format!(
                    "it relies on {name}, which the algorithm policy (version {}) does not accept",
                    self.version
                ));
            };
            if let (Some(min), Some(bits)) = (rule.min_key_bits, u.key_bits) {
                if bits < min {
                    return AlgorithmVerdict::Refused(format!(
                        "it relies on {name} with a {bits}-bit key, and the algorithm policy \
                         (version {}) accepts {name} keys from {min} bits",
                        self.version
                    ));
                }
            }
            let Some(end_text) = &rule.not_after else {
                continue;
            };
            let Some(end) = unix_from_rfc3339(end_text) else {
                return AlgorithmVerdict::Refused(format!(
                    "the algorithm policy's end date for {name} is unreadable ('{end_text}')"
                ));
            };
            if now.is_some_and(|n| n <= end) {
                continue;
            }
            match existed_before {
                Some(t) if t <= end => rescued.push(format!(
                    "{} is accepted only until {}, and a trusted timestamp shows the evidence \
                     existed at {}",
                    u.label(),
                    rfc3339_from_unix(end),
                    rfc3339_from_unix(t)
                )),
                Some(t) => {
                    return AlgorithmVerdict::Refused(format!(
                        "it relies on {}, which the algorithm policy (version {}) accepts only \
                         until {}, and the earliest trusted timestamp covering it is from {}",
                        u.label(),
                        self.version,
                        rfc3339_from_unix(end),
                        rfc3339_from_unix(t)
                    ))
                }
                None => {
                    return AlgorithmVerdict::Refused(format!(
                        "it relies on {}, which the algorithm policy (version {}) accepts only \
                         until {}{}, and no trusted timestamp shows it existed by then",
                        u.label(),
                        self.version,
                        rfc3339_from_unix(end),
                        if now.is_none() {
                            " (this verifier has no clock, so that date counts as passed)"
                        } else {
                            ""
                        }
                    ))
                }
            }
        }
        rescued.sort();
        rescued.dedup();
        if rescued.is_empty() {
            AlgorithmVerdict::Accepted
        } else {
            AlgorithmVerdict::AcceptedByTimestamp(rescued.join("; "))
        }
    }
}

/// The policy applied by one verification, as the report states it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlgorithmPolicyStatus {
    /// The policy's [`AlgorithmPolicy::version`].
    pub version: u32,
    /// `trust-list` when the verifier's trust store carries the policy, `builtin` when it does
    /// not ([`AlgorithmPolicy::builtin`]).
    pub source: String,
    /// The verifier's time the policy's end dates were judged against (RFC 3339), when the
    /// policy has end dates and the verifier knew its time.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub checked_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2030-01-01T00:00:00Z
    const D: i64 = 1_893_456_000;

    fn dated(alg: Algorithm, not_after: i64) -> AlgorithmPolicy {
        let mut p = AlgorithmPolicy::builtin();
        p.version = 7;
        for r in &mut p.algorithms {
            if r.algorithm == alg.name() {
                r.not_after = Some(rfc3339_from_unix(not_after));
            }
        }
        p
    }

    #[test]
    fn the_builtin_policy_accepts_every_implemented_algorithm_without_dates() {
        let p = AlgorithmPolicy::builtin();
        p.validate().unwrap();
        assert!(!p.has_end_dates());
        for a in Algorithm::ALL {
            assert!(p.rule(a).is_some(), "{}", a.name());
            assert_eq!(Algorithm::parse(a.name()), Some(a));
        }
        let uses = [
            AlgorithmUse::plain(Algorithm::EcdsaP256),
            AlgorithmUse::plain(Algorithm::Sha256),
            AlgorithmUse::rsa(2048),
        ];
        assert_eq!(p.judge(&uses, None, None), AlgorithmVerdict::Accepted);
        let small = p.judge(&[AlgorithmUse::rsa(1024)], Some(D), None);
        assert!(
            matches!(&small, AlgorithmVerdict::Refused(r) if r.contains("1024-bit")),
            "{small:?}"
        );
    }

    #[test]
    fn an_algorithm_the_policy_does_not_name_is_refused() {
        let mut p = AlgorithmPolicy::builtin();
        p.algorithms.retain(|r| r.algorithm != "SHA-512");
        // A name this build does not implement is ignored, and makes nothing acceptable.
        p.algorithms.push(AlgorithmRule {
            algorithm: "ML-DSA-65".into(),
            ..Default::default()
        });
        p.validate().unwrap();
        let v = p.judge(&[AlgorithmUse::plain(Algorithm::Sha512)], Some(D), None);
        assert!(
            matches!(&v, AlgorithmVerdict::Refused(r) if r.contains("SHA-512")),
            "{v:?}"
        );
        assert!(p
            .judge(&[AlgorithmUse::plain(Algorithm::Sha256)], Some(D), None)
            .is_accepted());
    }

    #[test]
    fn past_its_end_an_algorithm_counts_only_under_an_earlier_timestamp() {
        let p = dated(Algorithm::RsaPkcs1v15, D);
        let uses = [
            AlgorithmUse::rsa(2048),
            AlgorithmUse::plain(Algorithm::Sha256),
        ];
        // Before the end, nothing else is needed.
        assert_eq!(
            p.judge(&uses, Some(D - 1), None),
            AlgorithmVerdict::Accepted
        );
        assert_eq!(p.judge(&uses, Some(D), None), AlgorithmVerdict::Accepted);
        // After it, a trusted timestamp from before the end keeps the evidence...
        let kept = p.judge(&uses, Some(D + 86_400), Some(D - 3600));
        assert!(
            matches!(&kept, AlgorithmVerdict::AcceptedByTimestamp(t) if t.contains("RSA")),
            "{kept:?}"
        );
        assert!(kept.is_accepted());
        // ...and one from after it, or none, does not.
        for existed_before in [Some(D + 1), None] {
            let v = p.judge(&uses, Some(D + 86_400), existed_before);
            assert!(
                matches!(&v, AlgorithmVerdict::Refused(r) if r.contains("2030-01-01")),
                "{v:?}"
            );
        }
        // Without a clock, every end date counts as passed.
        assert!(!p.judge(&uses, None, None).is_accepted());
        assert!(p.judge(&uses, None, Some(D - 60)).is_accepted());
        // Other algorithms are not affected.
        assert_eq!(
            p.judge(&[AlgorithmUse::plain(Algorithm::EcdsaP256)], None, None),
            AlgorithmVerdict::Accepted
        );
    }

    #[test]
    fn a_policy_is_refused_when_unreadable() {
        let mut p = AlgorithmPolicy::builtin();
        p.algorithms[0].not_after = Some("soon".into());
        assert!(p.validate().unwrap_err().contains("soon"));
        let mut p = AlgorithmPolicy::builtin();
        p.algorithms.push(p.algorithms[0].clone());
        assert!(p.validate().unwrap_err().contains("two rules"));
        // An unreadable date fails closed when judged.
        let mut p = AlgorithmPolicy::builtin();
        p.algorithms[0].not_after = Some("soon".into());
        assert!(!p
            .judge(&[AlgorithmUse::plain(Algorithm::Sha256)], Some(D), Some(D))
            .is_accepted());
    }

    #[test]
    fn bit_lengths() {
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(bit_length(&[0, 0]), 0);
        assert_eq!(bit_length(&[1]), 1);
        assert_eq!(bit_length(&[0, 0x80, 0]), 16);
        assert_eq!(bit_length(&[0xFF; 256]), 2048);
        assert_eq!(bit_length(&[0x7F; 256]), 2047);
    }

    #[test]
    fn json_shape() {
        let p = dated(Algorithm::RsaPkcs1v15, D);
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["version"], 7);
        assert_eq!(json["algorithms"][4]["algorithm"], "RSA-PKCS1-v1_5");
        assert_eq!(json["algorithms"][4]["min_key_bits"], 2048);
        assert_eq!(json["algorithms"][4]["not_after"], "2030-01-01T00:00:00Z");
        assert!(json["algorithms"][0].get("not_after").is_none());
        let back: AlgorithmPolicy = serde_json::from_value(json).unwrap();
        assert_eq!(back, p);
    }
}
