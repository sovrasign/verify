//! Property tests (proptest) for the three parts of the engine whose inputs are too varied for
//! hand-written examples:
//!
//! 1. **Envelope serialization**: any envelope the model can hold survives JSON and every
//!    envelope schema version that can express it, byte for byte; a version that cannot express
//!    it refuses to write it rather than dropping something.
//! 2. **The routing state machine**: under any signing order, any set of slot orders and any
//!    sequence of attempts to sign or decline, the engine accepts exactly the moves a small
//!    reference model allows, and the verifier's verdict (complete, declined, order) matches the
//!    model's.
//! 3. **Revision replay**: every intermediate document of a signing run is a byte prefix of the
//!    final one, and verifying each prefix gives the same envelope state and the same
//!    per-revision results as replaying the whole chain; changing any byte of the source document
//!    or cutting the file anywhere else fails cleanly.
//!
//! The signing properties run the real engine (key generation, ID tokens, PAdES), so they run
//! fewer cases than the pure ones. `PROPTEST_CASES` raises every count (the nightly run uses it).

mod common;

use common::{prepare_request, signer_request, spec, trust};
use proptest::collection::vec;
use proptest::prelude::*;
use signpdf_core::dates::DateFormat;
use signpdf_core::initials::InitialsRule;
use signpdf_core::ink::{PathSegment, SignatureDrawing};
use signpdf_core::model::{
    AuditAction, AuditEntry, EnvelopeDocument, EsignConsent, RecordKind, SignatureRecord,
};
use signpdf_core::numbers::{NumberFormat, NumberStyle};
use signpdf_core::oidc::{IdentityPolicy, Level, Method};
use signpdf_core::schema::{decode_envelope, encode_envelope};
use signpdf_core::workflow::read_envelope;
use signpdf_core::{
    container, prepare, sign, verify, Envelope, Field, FieldType, Policy, Rect, Signer,
    SignerStatus, SigningOrder, TimestampPolicy,
};

/// The number of cases for the properties that sign: `PROPTEST_CASES` when set, else `default`.
fn signing_cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---- strategies: an arbitrary envelope ----------------------------------------------------------

/// Text of any Unicode scalar values, including quotes, backslashes, controls and non-Latin
/// scripts: what JSON escaping must survive.
fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9 .,@-]{0,24}",
        any::<String>().prop_map(|s| s.chars().take(32).collect()),
        Just("\"quoted\" \\ back\\slash \u{0} \u{1f} \u{2028}".to_string()),
        Just("Ünïcödé — 合同 — عقد — договор".to_string()),
    ]
}

fn opt<T: std::fmt::Debug + Clone + 'static>(
    s: impl Strategy<Value = T> + 'static,
) -> impl Strategy<Value = Option<T>> {
    prop::option::of(s)
}

fn hex64() -> impl Strategy<Value = String> {
    "[0-9a-f]{64}"
}

/// A finite coordinate (JSON has no NaN or infinity).
fn coord() -> impl Strategy<Value = f64> {
    prop_oneof![
        -1.0e6..1.0e6f64,
        Just(0.0),
        Just(-0.0),
        Just(0.1),
        Just(f64::MIN_POSITIVE),
    ]
}

fn rect() -> impl Strategy<Value = Rect> {
    (coord(), coord(), coord(), coord()).prop_map(|(x, y, w, h)| Rect { x, y, w, h })
}

fn field_type() -> impl Strategy<Value = FieldType> {
    prop_oneof![
        Just(FieldType::Signature),
        Just(FieldType::Initials),
        Just(FieldType::Date),
        Just(FieldType::Text),
        Just(FieldType::Multiline),
        Just(FieldType::Checkbox),
        Just(FieldType::Radio),
        Just(FieldType::Dropdown),
        Just(FieldType::Number),
    ]
}

fn date_format() -> impl Strategy<Value = DateFormat> {
    prop_oneof![
        Just(DateFormat::Iso),
        Just(DateFormat::DayMonthYearSlash),
        Just(DateFormat::MonthDayYearSlash),
        Just(DateFormat::DayMonthYearDot),
        Just(DateFormat::DayMonthYearDash),
    ]
}

fn number_format() -> impl Strategy<Value = NumberFormat> {
    (
        0u8..=6,
        opt("-?[0-9]{1,6}"),
        opt("[0-9]{1,6}"),
        prop::sample::select(NumberStyle::ALL.to_vec()),
    )
        .prop_map(|(decimals, min, max, style)| NumberFormat {
            decimals,
            min,
            max,
            style,
            currency: None,
        })
}

fn field() -> impl Strategy<Value = Field> {
    (
        (
            text(),
            field_type(),
            any::<u32>(),
            rect(),
            text(),
            any::<bool>(),
        ),
        (
            opt(text()),
            opt(text()),
            opt(text()),
            opt(vec(text(), 0..4)),
            opt(date_format()),
            any::<bool>(),
            opt(number_format()),
        ),
    )
        .prop_map(
            |(
                (id, field_type, page, rect, assigned_signer, required),
                (value, label, group, options, date_format, signing_date, number_format),
            )| Field {
                id,
                field_type,
                page,
                rect,
                assigned_signer,
                required,
                value,
                label,
                group,
                options,
                date_format,
                signing_date,
                number_format,
                value_format: None,
                length: None,
                check_message: None,
                formula: None,
            },
        )
}

fn level() -> impl Strategy<Value = Level> {
    prop::sample::select(Level::ALL.to_vec())
}

fn identity_policy() -> impl Strategy<Value = IdentityPolicy> {
    (
        vec(text(), 0..3),
        opt(text()),
        opt(text()),
        opt(text()),
        opt(text()),
        level(),
        prop::sample::subsequence(Method::ALL.to_vec(), 0..=3),
    )
        .prop_map(
            |(
                allowed_issuers,
                required_email,
                required_domain,
                required_tenant,
                required_subject,
                min_level,
                required_methods,
            )| IdentityPolicy {
                allowed_issuers,
                required_email,
                required_domain,
                required_tenant,
                required_subject,
                min_level,
                required_methods,
            },
        )
}

fn signer_status() -> impl Strategy<Value = SignerStatus> {
    prop_oneof![
        Just(SignerStatus::Pending),
        Just(SignerStatus::Signed),
        Just(SignerStatus::Declined),
    ]
}

fn signer() -> impl Strategy<Value = Signer> {
    (
        (
            text(),
            text(),
            text(),
            text(),
            any::<u32>(),
            signer_status(),
        ),
        (identity_policy(), opt(text()), opt(text())),
    )
        .prop_map(
            |(
                (id, name, handle, role, order, status),
                (identity_policy, public_key, fingerprint),
            )| {
                Signer {
                    id,
                    name,
                    handle,
                    role,
                    order,
                    status,
                    identity_policy,
                    public_key,
                    fingerprint,
                }
            },
        )
}

/// A finite drawing coordinate.
fn point() -> impl Strategy<Value = [f32; 2]> {
    [-1.0e5..1.0e5f32, -1.0e5..1.0e5f32]
}

fn drawing() -> impl Strategy<Value = SignatureDrawing> {
    prop_oneof![
        vec(vec(point(), 1..5), 0..4).prop_map(|strokes| SignatureDrawing::Drawn { strokes }),
        vec(
            vec(
                prop_oneof![
                    point().prop_map(PathSegment::Line),
                    (point(), point(), point()).prop_map(|(a, b, c)| PathSegment::Curve([
                        a[0], a[1], b[0], b[1], c[0], c[1]
                    ])),
                ],
                1..5
            ),
            0..4
        )
        .prop_map(|paths| SignatureDrawing::Typed { paths }),
    ]
}

fn signature_record() -> impl Strategy<Value = SignatureRecord> {
    (
        (
            prop_oneof![Just(RecordKind::Signed), Just(RecordKind::Declined)],
            text(),
            text(),
            text(),
            text(),
            text(),
            opt(text()),
            hex64(),
            any::<u64>(),
            text(),
            any::<u32>(),
        ),
        (
            text(),
            text(),
            text(),
            text(),
            text(),
            text(),
            opt("[+-][01][0-9]:[0-5][0-9]"),
            opt(drawing()),
        ),
    )
        .prop_map(
            |(
                (
                    kind,
                    signer_id,
                    fingerprint,
                    public_key,
                    algorithm,
                    signed_at,
                    timestamp_token,
                    doc_digest,
                    signed_prefix_len,
                    signature,
                    revision,
                ),
                (
                    id_token,
                    idp_jwk,
                    idp_issuer,
                    idp_subject,
                    idp_email,
                    idp_audience,
                    utc_offset,
                    drawing,
                ),
            )| SignatureRecord {
                kind,
                signer_id,
                fingerprint,
                public_key,
                algorithm,
                signed_at,
                timestamp_token,
                doc_digest,
                signed_prefix_len,
                signature,
                revision,
                id_token,
                idp_jwk,
                idp_issuer,
                idp_subject,
                idp_email,
                idp_audience,
                utc_offset,
                drawing,
            },
        )
}

fn audit_entry() -> impl Strategy<Value = AuditEntry> {
    (
        any::<u32>(),
        prop_oneof![
            Just(AuditAction::Prepared),
            Just(AuditAction::Sent),
            Just(AuditAction::Opened),
            Just(AuditAction::Signed),
            Just(AuditAction::Declined),
            Just(AuditAction::Verified),
        ],
        (text(), text(), text(), text(), text(), hex64()),
        opt(text()),
        opt((
            "[a-z0-9][a-z0-9.-]{0,10}",
            "[a-z]{2}(-[a-z0-9]{2,4})?",
            hex64(),
            opt(hex64()),
            Just("2026-11-02T09:14:03Z".to_string()),
        )),
    )
        .prop_map(
            |(
                seq,
                action,
                (actor_fingerprint, actor_name, at, details, prev_hash, entry_hash),
                signature,
                consent,
            )| {
                AuditEntry {
                    seq,
                    action,
                    actor_fingerprint,
                    actor_name,
                    at,
                    details,
                    prev_hash,
                    entry_hash,
                    signature,
                    esign_consent: consent.map(|(version, lang, sha256, ref_sha256, at)| {
                        EsignConsent {
                            version,
                            lang,
                            sha256,
                            ref_sha256,
                            at,
                        }
                    }),
                }
            },
        )
}

fn policy() -> impl Strategy<Value = Policy> {
    (
        prop_oneof![Just(SigningOrder::Sequential), Just(SigningOrder::Parallel)],
        vec(text(), 0..3),
        opt(text()),
        prop_oneof![
            Just(TimestampPolicy::Optional),
            Just(TimestampPolicy::Required),
            Just(TimestampPolicy::None),
        ],
    )
        .prop_map(
            |(signing_order, allowed_signature_types, expiry, signature_timestamps)| Policy {
                signing_order,
                allowed_signature_types,
                expiry,
                signature_timestamps,
            },
        )
}

fn document() -> impl Strategy<Value = EnvelopeDocument> {
    (text(), any::<u32>(), any::<u32>(), hex64()).prop_map(
        |(name, first_page, page_count, source_digest)| EnvelopeDocument {
            name,
            first_page,
            page_count,
            source_digest,
        },
    )
}

fn envelope() -> impl Strategy<Value = Envelope> {
    (
        (
            3u32..=signpdf_core::SCHEMA_VERSION,
            text(),
            text(),
            text(),
            text(),
            text(),
            text(),
            text(),
            text(),
            text(),
            text(),
        ),
        (
            hex64(),
            any::<u64>(),
            vec(document(), 0..3),
            vec(signer(), 0..4),
            vec(field(), 0..5),
            policy(),
            vec(signature_record(), 0..3),
            vec(audit_entry(), 0..4),
            opt(text()),
            opt(text()),
            opt(Just(InitialsRule::NameV1)),
        ),
    )
        .prop_map(
            |(
                (
                    schema_version,
                    envelope_id,
                    title,
                    created_by,
                    created_at,
                    created_by_pubkey,
                    created_by_id_token,
                    created_by_idp_jwk,
                    created_by_issuer,
                    created_by_email,
                    created_by_audience,
                ),
                (
                    source_digest,
                    source_len,
                    documents,
                    signers,
                    fields,
                    policy,
                    signatures,
                    audit_log,
                    service_link,
                    verify_at,
                    initials_rule,
                ),
            )| Envelope {
                schema_version,
                envelope_id,
                title,
                created_by,
                created_at,
                created_by_pubkey,
                created_by_id_token,
                created_by_idp_jwk,
                created_by_issuer,
                created_by_email,
                created_by_audience,
                source_digest,
                source_len,
                documents,
                signers,
                fields,
                policy,
                signatures,
                audit_log,
                service_link,
                verify_at,
                initials_rule,
            },
        )
}

// ---- 1. envelope serialization ------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The model's own JSON: a round trip gives the same envelope, and writing it again gives the
    /// same bytes (the envelope digest and the prepared terms depend on exact bytes).
    #[test]
    fn envelope_json_round_trips_byte_for_byte(env in envelope()) {
        let json = serde_json::to_vec(&env).unwrap();
        let back: Envelope = serde_json::from_slice(&json).unwrap();
        prop_assert_eq!(&back, &env);
        prop_assert_eq!(serde_json::to_vec(&back).unwrap(), json);
        prop_assert_eq!(back.digest().unwrap(), env.digest().unwrap());
        prop_assert_eq!(back.core_digest().unwrap(), env.core_digest().unwrap());
    }

    /// Every supported schema version either writes the envelope and reads back exactly the same
    /// one, or refuses to write it: never a silent loss. The current version writes everything.
    #[test]
    fn every_schema_version_round_trips_or_refuses(env in envelope(), to in 3u32..=signpdf_core::SCHEMA_VERSION) {
        let mut env = Envelope { schema_version: to, ..env };
        if to == signpdf_core::SCHEMA_VERSION {
            // The current version requires an initials rule.
            env.initials_rule = Some(InitialsRule::NameV1);
        }
        match encode_envelope(&env) {
            Ok(bytes) => {
                let back = decode_envelope(&bytes).unwrap();
                prop_assert_eq!(&back, &env);
                prop_assert_eq!(encode_envelope(&back).unwrap(), bytes);
            }
            Err(e) => {
                prop_assert!(to < signpdf_core::SCHEMA_VERSION, "the current version refused: {}", e);
            }
        }
    }

    /// Decoding arbitrary bytes never panics: it gives an envelope or an error.
    #[test]
    fn decoding_any_bytes_fails_cleanly(bytes in vec(any::<u8>(), 0..512)) {
        let _ = decode_envelope(&bytes);
    }

    /// Decoding a mutated envelope never panics, and what it accepts it writes back unchanged.
    #[test]
    fn decoding_a_mutated_envelope_fails_cleanly(
        env in envelope(),
        at in any::<prop::sample::Index>(),
        byte in any::<u8>(),
    ) {
        let env = Envelope {
            schema_version: signpdf_core::SCHEMA_VERSION,
            initials_rule: Some(InitialsRule::NameV1),
            ..env
        };
        let mut bytes = encode_envelope(&env).unwrap();
        let i = at.index(bytes.len());
        bytes[i] = byte;
        if let Ok(back) = decode_envelope(&bytes) {
            let again = encode_envelope(&back).unwrap();
            prop_assert_eq!(decode_envelope(&again).unwrap(), back);
        }
    }
}

// ---- 2. the routing state machine ---------------------------------------------------------------

/// The reference model of who may act: nobody once someone declined; under a parallel order
/// every pending slot; under a sequential order the pending slots with the lowest order.
fn model_allows(order: SigningOrder, orders: &[u32], status: &[SignerStatus], who: usize) -> bool {
    if status.contains(&SignerStatus::Declined) || status[who] != SignerStatus::Pending {
        return false;
    }
    match order {
        SigningOrder::Parallel => true,
        SigningOrder::Sequential => {
            let lowest = (0..status.len())
                .filter(|&i| status[i] == SignerStatus::Pending)
                .map(|i| orders[i])
                .min();
            lowest == Some(orders[who])
        }
    }
}

fn signing_order() -> impl Strategy<Value = SigningOrder> {
    prop_oneof![Just(SigningOrder::Sequential), Just(SigningOrder::Parallel)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// The model's `expected_signers` agrees with the reference model for any slot states.
    #[test]
    fn expected_signers_match_the_model(
        order in signing_order(),
        slots in vec((1u32..5, signer_status()), 1..8),
    ) {
        let orders: Vec<u32> = slots.iter().map(|s| s.0).collect();
        let status: Vec<SignerStatus> = slots.iter().map(|s| s.1).collect();
        let env = Envelope {
            schema_version: signpdf_core::SCHEMA_VERSION,
            envelope_id: "e".into(),
            title: "t".into(),
            created_by: "p".into(),
            created_at: "2026-10-30T00:00:00Z".into(),
            created_by_pubkey: String::new(),
            created_by_id_token: String::new(),
            created_by_idp_jwk: String::new(),
            created_by_issuer: String::new(),
            created_by_email: String::new(),
            created_by_audience: String::new(),
            source_digest: String::new(),
            source_len: 0,
            documents: vec![],
            signers: slots
                .iter()
                .enumerate()
                .map(|(i, (o, s))| Signer {
                    id: format!("s{i}"),
                    name: format!("Signer {i}"),
                    handle: format!("s{i}@example.com"),
                    role: "Party".into(),
                    order: *o,
                    status: *s,
                    identity_policy: IdentityPolicy::default(),
                    public_key: None,
                    fingerprint: None,
                })
                .collect(),
            fields: vec![],
            policy: Policy { signing_order: order, ..Policy::default() },
            signatures: vec![],
            audit_log: vec![],
            service_link: None,
            verify_at: None,
            initials_rule: Some(InitialsRule::NameV1),
        };
        let expected: Vec<usize> = env
            .expected_signers()
            .iter()
            .map(|s| s.id[1..].parse().unwrap())
            .collect();
        let model: Vec<usize> = (0..status.len())
            .filter(|&i| model_allows(order, &orders, &status, i))
            .collect();
        prop_assert_eq!(expected, model);
        prop_assert_eq!(env.is_complete(), status.iter().all(|s| *s == SignerStatus::Signed));
        prop_assert_eq!(env.is_declined(), status.contains(&SignerStatus::Declined));
    }
}

/// One attempt in a signing run: slot `who` tries to sign, or to decline.
#[derive(Debug, Clone)]
struct Attempt {
    who: usize,
    decline: bool,
}

/// A run: the order, each slot's order number, and the attempts (some of which the engine must
/// refuse).
fn run() -> impl Strategy<Value = (SigningOrder, Vec<u32>, Vec<Attempt>)> {
    (signing_order(), vec(1u32..4, 1..5)).prop_flat_map(|(order, orders)| {
        let n = orders.len();
        let attempt =
            (0..n, prop::bool::weighted(0.12)).prop_map(|(who, decline)| Attempt { who, decline });
        (Just(order), Just(orders), vec(attempt, 1..(2 * n + 2)))
    })
}

fn email(i: usize) -> String {
    format!("signer{i}@example.com")
}

/// The documents of a run: the prepared one, then one per accepted attempt, with the slot states
/// after each.
struct Run {
    docs: Vec<Vec<u8>>,
    states: Vec<Vec<SignerStatus>>,
}

/// Drive the engine through `attempts`, checking each answer against the model.
fn drive(order: SigningOrder, orders: &[u32], attempts: &[Attempt]) -> Result<Run, TestCaseError> {
    let source = container::make_sample_pdf("Property-tested agreement");
    let signers = orders
        .iter()
        .enumerate()
        .map(|(i, o)| spec(&format!("s{i}"), &format!("Signer {i}"), &email(i), *o))
        .collect();
    let (preparer_key, req) = prepare_request(&source, signers, vec![], order);
    let prepared = prepare(&source, &req, &preparer_key)
        .map_err(|e| TestCaseError::fail(format!("prepare: {e}")))?;
    let mut status = vec![SignerStatus::Pending; orders.len()];
    let mut run = Run {
        docs: vec![prepared],
        states: vec![status.clone()],
    };
    for a in attempts {
        let doc = run.docs.last().unwrap();
        let allowed = model_allows(order, orders, &status, a.who);
        let (key, mut sreq) = signer_request(&email(a.who), doc, "");
        sreq.decline = a.decline;
        match sign(doc, &key, &sreq) {
            Ok(next) => {
                prop_assert!(allowed, "the engine accepted {:?} in state {:?}", a, status);
                prop_assert!(next.starts_with(doc), "a revision rewrote earlier bytes");
                status[a.who] = if a.decline {
                    SignerStatus::Declined
                } else {
                    SignerStatus::Signed
                };
                run.docs.push(next);
                run.states.push(status.clone());
            }
            Err(e) => prop_assert!(
                !allowed,
                "the engine refused {:?} in state {:?}: {}",
                a,
                status,
                e
            ),
        }
    }
    Ok(run)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(signing_cases(16)))]

    /// The engine accepts exactly what the model allows, and the verifier's verdict on the final
    /// document is the model's.
    #[test]
    fn routing_follows_the_model((order, orders, attempts) in run()) {
        let run = drive(order, &orders, &attempts)?;
        let last = run.states.last().unwrap();
        let report = verify(run.docs.last().unwrap(), &trust()).unwrap();
        prop_assert!(report.valid, "{:?}", report.messages);
        prop_assert!(report.order_ok);
        prop_assert_eq!(report.complete, last.iter().all(|s| *s == SignerStatus::Signed));
        prop_assert_eq!(report.declined, last.contains(&SignerStatus::Declined));
        prop_assert_eq!(report.signatures.len(), run.docs.len() - 1);
        let env = report.envelope.unwrap();
        let statuses: Vec<SignerStatus> = env.signers.iter().map(|s| s.status).collect();
        prop_assert_eq!(&statuses, last);
    }
}

// ---- 3. revision replay -------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(signing_cases(10)))]

    /// Verifying each revision on its own agrees with replaying the whole chain: the same slot
    /// states, and the same result for every revision they share.
    #[test]
    fn each_prefix_replays_like_the_whole_chain((order, orders, attempts) in run()) {
        let run = drive(order, &orders, &attempts)?;
        let full = verify(run.docs.last().unwrap(), &trust()).unwrap();
        prop_assert!(full.valid, "{:?}", full.messages);
        for (k, (doc, state)) in run.docs.iter().zip(&run.states).enumerate() {
            prop_assert!(run.docs.last().unwrap().starts_with(doc));
            let report = verify(doc, &trust()).unwrap();
            prop_assert!(report.valid, "revision {}: {:?}", k, report.messages);
            prop_assert_eq!(report.signatures.len(), k);
            let statuses: Vec<SignerStatus> = read_envelope(doc)
                .unwrap()
                .signers
                .iter()
                .map(|s| s.status)
                .collect();
            prop_assert_eq!(&statuses, state);
            for (a, b) in report.signatures.iter().zip(&full.signatures) {
                prop_assert_eq!(&a.signer_id, &b.signer_id);
                prop_assert_eq!(&a.kind, &b.kind);
                prop_assert_eq!(&a.actor_fingerprint, &b.actor_fingerprint);
                prop_assert_eq!(a.valid, b.valid);
            }
        }
    }

    /// A change to any byte of the source document, or a cut anywhere that is not the end of a
    /// revision, never passes verification and never panics.
    #[test]
    fn tampering_and_truncation_fail_cleanly(
        (order, orders, attempts) in run(),
        at in any::<prop::sample::Index>(),
        cut in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let run = drive(order, &orders, &attempts)?;
        let last = run.docs.last().unwrap();
        let source_len = read_envelope(last).unwrap().source_len as usize;
        prop_assume!(source_len > 0);

        let mut tampered = last.clone();
        tampered[at.index(source_len)] ^= flip;
        if let Ok(r) = verify(&tampered, &trust()) {
            prop_assert!(!r.valid && !r.integrity_ok, "a changed source byte verified");
        }

        let ends: Vec<usize> = run.docs.iter().map(|d| d.len()).collect();
        let len = cut.index(last.len());
        prop_assume!(!ends.contains(&len));
        if let Ok(r) = verify(&last[..len], &trust()) {
            prop_assert!(!r.valid, "a file cut at {} of {} verified", len, last.len());
        }
    }
}
