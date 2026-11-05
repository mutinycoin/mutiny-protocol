//! Unit tests of the operation envelope (P-LANE-DESIGN-V1 section 14.4, work package WP-P0): the
//! codec rules E1-E7 in both directions, canonical form, the committed public vectors and their
//! generator, the window W, the reference R, the preconditions P, `from_head` and the reuse of
//! `EXPIRY_HORIZON`. TEST-VALUE data only (public seeds, arbitrary hash patterns).
//! This file is declared once at file scope of `op_envelope_v1.rs`; the shared fixture modules are
//! declared at THIS file's scope (a #[path] inside an inline module does not resolve on Linux).
use super::*;
use crate::{NETWORK_ID, anchors::FinalizedAnchor};
use minicbor::Encoder;
use mutiny_crypto_v2::{HybridKey, Role};
use sha2::{Digest, Sha256};

#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;

fn h(n: u8) -> Hash {
    [n; 32]
}
fn parent(height: u64, block: Hash) -> FinalizedAnchor {
    FinalizedAnchor { network: NETWORK_ID, genesis: h(1), fingerprint: h(2), height, block }
}
fn minimal() -> Envelope {
    Envelope { first_height: 101, last_height: 245, reference_height: 100, reference_block: h(0xAB), preconditions: vec![] }
}
fn window(first_height: u64, last_height: u64, reference_height: u64, reference_block: Hash) -> Envelope {
    Envelope { first_height, last_height, reference_height, reference_block, preconditions: vec![] }
}
fn with(preconditions: Vec<Precondition>) -> Envelope {
    Envelope { preconditions, ..minimal() }
}
fn account(award_epoch: u64, share: u64, remaining: u64, claims: u64) -> AwardAccount {
    AwardAccount { award_epoch, share, remaining, claims }
}
fn entitlements(license: Hash, accounts: Vec<AwardAccount>) -> Precondition {
    Precondition::LicenseEntitlements { license, accounts }
}
fn assignment(license: Hash, assignment_sequence: u64, active_worker: Option<Hash>, pending: Option<Hash>) -> Precondition {
    Precondition::LicenseAssignment { license, assignment_sequence, active_worker, pending }
}
fn treasury(treasury: Hash, generation: u64, address: Hash) -> Precondition {
    Precondition::TreasuryHead { treasury, generation, address }
}
/// The design layout of ANY value, valid or not, WITHOUT validation (builds the negative vectors).
/// It shares only `Precondition::encode_into` with `to_bytes`; the minimal vector is additionally
/// pinned to a hand-assembled encoding.
fn unchecked(e: &Envelope) -> Vec<u8> {
    let mut x = Encoder::new(Vec::new());
    x.array(5).unwrap().u8(1).unwrap().u64(e.first_height).unwrap().u64(e.last_height).unwrap();
    x.array(2).unwrap().u64(e.reference_height).unwrap().bytes(&e.reference_block).unwrap();
    x.array(e.preconditions.len() as u64).unwrap();
    for p in &e.preconditions {
        p.encode_into(&mut x);
    }
    x.into_writer()
}

// ---------------------------------------------------------------------------------------------
// Vector set (shared by the generator and the reader).
// ---------------------------------------------------------------------------------------------

fn valid_vectors() -> Vec<(&'static str, Envelope)> {
    vec![
        ("minimal_parent_reference", minimal()),
        ("single_height_window_with_genesis_reference", window(1, 1, 0, h(0x01))),
        ("horizon_boundary_span_10080", window(500, 500 + EXPIRY_HORIZON, 499, h(0x22))),
        (
            "all_three_preconditions",
            Envelope {
                first_height: 1_001,
                last_height: 1_145,
                reference_height: 1_000,
                reference_block: h(0x5A),
                preconditions: vec![
                    entitlements(h(0x31), vec![account(131_072, 50_000, 50_000, 0), account(262_144, 50_000, 39_000, 2)]),
                    assignment(h(0x31), 3, Some(h(0x41)), Some(h(0x42))),
                    treasury(h(0x51), 2, h(0x52)),
                ],
            },
        ),
        (
            "no_live_entitlement_and_detached_license",
            Envelope {
                preconditions: vec![entitlements(h(0x31), vec![]), assignment(h(0x31), 2, None, None)],
                ..window(7, 9, 6, h(0x66))
            },
        ),
        ("integer_widths_four_byte_heights", window(65_536, 75_536, 65_535, h(0x77))),
        (
            "integer_widths_eight_byte_heights_and_amounts",
            Envelope {
                preconditions: vec![entitlements(h(0x09), vec![account(131_072, 4_294_967_296, 255, 23)])],
                ..window(4_294_967_296, 4_294_967_440, 4_294_967_295, h(0x78))
            },
        ),
    ]
}

/// Values that violate exactly one codec rule: (name, rule, value, error).
fn rule_cases() -> Vec<(&'static str, &'static str, Envelope, EnvelopeError)> {
    use EnvelopeError::*;
    let m = minimal();
    vec![
        ("E1_zero_reference_block", "E1", Envelope { reference_block: [0; 32], ..m.clone() }, ZeroReference),
        ("E2_reference_equals_first", "E2", Envelope { reference_height: 101, ..m.clone() }, WindowOrder),
        ("E2_reference_after_first", "E2", Envelope { reference_height: 200, ..m.clone() }, WindowOrder),
        ("E2_first_after_last", "E2", Envelope { first_height: 246, ..m.clone() }, WindowOrder),
        ("E3_span_one_beyond_horizon", "E3", Envelope { last_height: 101 + EXPIRY_HORIZON + 1, ..m.clone() }, Horizon),
        (
            "E4_duplicate_precondition",
            "E4",
            with(vec![assignment(h(3), 1, None, None), assignment(h(3), 1, None, None)]),
            PreconditionOrder,
        ),
        (
            "E4_same_subject_twice_with_different_facts",
            "E4",
            with(vec![entitlements(h(3), vec![]), entitlements(h(3), vec![account(131_072, 10, 10, 0)])]),
            PreconditionOrder,
        ),
        ("E4_tags_descending", "E4", with(vec![treasury(h(5), 1, h(6)), entitlements(h(3), vec![])]), PreconditionOrder),
        (
            "E4_subjects_descending",
            "E4",
            with(vec![assignment(h(4), 1, None, None), assignment(h(3), 1, None, None)]),
            PreconditionOrder,
        ),
        ("E5_zero_license", "E5", with(vec![entitlements([0; 32], vec![])]), ZeroSubject),
        (
            "E5_accounts_equal_epochs",
            "E5",
            with(vec![entitlements(h(3), vec![account(131_072, 10, 10, 0), account(131_072, 10, 10, 0)])]),
            AccountOrder,
        ),
        (
            "E5_accounts_descending",
            "E5",
            with(vec![entitlements(h(3), vec![account(262_144, 10, 10, 0), account(131_072, 10, 10, 0)])]),
            AccountOrder,
        ),
        ("E5_award_epoch_zero", "E5", with(vec![entitlements(h(3), vec![account(0, 10, 10, 0)])]), Account),
        ("E5_share_zero", "E5", with(vec![entitlements(h(3), vec![account(131_072, 0, 0, 0)])]), Account),
        ("E5_remaining_above_share", "E5", with(vec![entitlements(h(3), vec![account(131_072, 10, 11, 0)])]), Account),
        ("E5_claimed_amount_without_claims", "E5", with(vec![entitlements(h(3), vec![account(131_072, 10, 7, 0)])]), Account),
        ("E5_claims_without_claimed_amount", "E5", with(vec![entitlements(h(3), vec![account(131_072, 10, 10, 1)])]), Account),
        ("E5_claims_above_claimed_amount", "E5", with(vec![entitlements(h(3), vec![account(131_072, 10, 7, 4)])]), Account),
        ("E6_zero_license", "E6", with(vec![assignment([0; 32], 1, None, None)]), ZeroSubject),
        ("E6_zero_assignment_sequence", "E6", with(vec![assignment(h(3), 0, None, None)]), ZeroSequence),
        ("E7_zero_treasury", "E7", with(vec![treasury([0; 32], 1, h(6))]), ZeroSubject),
        ("E7_zero_address", "E7", with(vec![treasury(h(5), 1, [0; 32])]), ZeroSubject),
        ("E7_zero_generation", "E7", with(vec![treasury(h(5), 0, h(6))]), ZeroGeneration),
    ]
}

/// Encodings of a valid value in a non-canonical form, or not of the envelope structure at all:
/// (name, bytes, error). Byte offsets refer to the 44-byte minimal vector
/// `85 01 1865 18f5 82 1864 5820 ab..ab 80`.
fn form_cases() -> Vec<(&'static str, Vec<u8>, EnvelopeError)> {
    use EnvelopeError::*;
    let m = minimal().to_bytes().unwrap();
    assert_eq!(m.len(), 44);
    let join = |parts: &[&[u8]]| parts.concat();
    let mut short_hash = m[..9].to_vec();
    short_hash.extend([0x58, 0x1f]);
    short_hash.extend([0xAB; 31]);
    short_hash.push(0x80);
    let mut unknown_tag = m[..43].to_vec();
    unknown_tag.extend([0x81, 0x82, 0x04, 0x58, 0x20]);
    unknown_tag.extend([0x05; 32]);
    let mut wrong_arity = m[..43].to_vec();
    wrong_arity.extend([0x81, 0x83, 0x03, 0x58, 0x20]);
    wrong_arity.extend([0x05; 32]);
    wrong_arity.push(0x01);
    let mut indefinite_bytes = m[..9].to_vec();
    indefinite_bytes.extend([0x5f, 0x58, 0x20]);
    indefinite_bytes.extend([0xAB; 32]);
    indefinite_bytes.extend([0xff, 0x80]);
    vec![
        ("noncanonical_first_height_non_minimal", join(&[&m[..2], &[0x19, 0x00, 0x65], &m[4..]]), NonCanonical),
        ("noncanonical_version_non_minimal", join(&[&m[..1], &[0x18, 0x01], &m[2..]]), NonCanonical),
        ("noncanonical_reference_block_long_length_head", join(&[&m[..9], &[0x59, 0x00, 0x20], &m[11..]]), NonCanonical),
        ("noncanonical_indefinite_outer_array", join(&[&[0x9f], &m[1..], &[0xff]]), NonCanonical),
        ("noncanonical_indefinite_precondition_list", join(&[&m[..43], &[0x9f, 0xff]]), NonCanonical),
        ("noncanonical_indefinite_reference_block", indefinite_bytes, NonCanonical),
        ("codec_version_2", join(&[&m[..1], &[0x02], &m[2..]]), Codec),
        ("codec_outer_array_of_four", join(&[&[0x84], &m[1..43]]), Codec),
        ("codec_negative_first_height", join(&[&m[..2], &[0x20], &m[4..]]), Codec),
        ("codec_reference_block_31_bytes", short_hash, Codec),
        ("codec_unknown_precondition_tag_4", unknown_tag, Codec),
        ("codec_treasury_head_with_three_elements", wrong_arity, Codec),
        ("codec_trailing_byte", join(&[&m, &[0x00]]), Codec),
    ]
}

fn hex_opt(v: &Option<Hash>) -> serde_json::Value {
    v.map(|x| serde_json::Value::String(hex::encode(x))).unwrap_or(serde_json::Value::Null)
}
fn precondition_json(p: &Precondition) -> serde_json::Value {
    match p {
        Precondition::LicenseEntitlements { license, accounts } => serde_json::json!({
            "tag": 1, "kind": "LicenseEntitlements", "license": hex::encode(license),
            "accounts": accounts.iter().map(|a| serde_json::json!([a.award_epoch, a.share, a.remaining, a.claims])).collect::<Vec<_>>(),
        }),
        Precondition::LicenseAssignment { license, assignment_sequence, active_worker, pending } => serde_json::json!({
            "tag": 2, "kind": "LicenseAssignment", "license": hex::encode(license),
            "assignment_sequence": assignment_sequence, "active_worker": hex_opt(active_worker), "pending": hex_opt(pending),
        }),
        Precondition::TreasuryHead { treasury, generation, address } => serde_json::json!({
            "tag": 3, "kind": "TreasuryHead", "treasury": hex::encode(treasury), "generation": generation,
            "address": hex::encode(address),
        }),
    }
}
fn fields_json(e: &Envelope) -> serde_json::Value {
    serde_json::json!({
        "first_height": e.first_height, "last_height": e.last_height,
        "reference_height": e.reference_height, "reference_block": hex::encode(e.reference_block),
        "preconditions": e.preconditions.iter().map(precondition_json).collect::<Vec<_>>(),
    })
}
fn sha256_hex(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
/// The complete vector document. Deterministic: fixed values, sorted JSON keys.
fn vector_document() -> String {
    let valid: Vec<_> = valid_vectors()
        .iter()
        .map(|(name, e)| {
            let raw = e.to_bytes().unwrap();
            serde_json::json!({"name": name, "fields": fields_json(e), "cbor_hex": hex::encode(&raw), "sha256": sha256_hex(&raw)})
        })
        .collect();
    let mut invalid: Vec<_> = rule_cases()
        .iter()
        .map(|(name, rule, e, error)| {
            serde_json::json!({"name": name, "rule": rule, "cbor_hex": hex::encode(unchecked(e)), "error": format!("{error:?}")})
        })
        .collect();
    invalid.extend(form_cases().iter().map(|(name, raw, error)| {
        let rule = if matches!(error, EnvelopeError::NonCanonical) { "canonical form" } else { "structure" };
        serde_json::json!({"name": name, "rule": rule, "cbor_hex": hex::encode(raw), "error": format!("{error:?}")})
    }));
    let document = serde_json::json!({
        "schema": "BUILD8-OPERATION-ENVELOPE-V1-VECTORS",
        "status": "PROPOSED-UNFROZEN",
        "synthetic_only": true,
        "test_value": true,
        "production_authorized": false,
        "note": "Public synthetic data only: no key, signature, chain or production identity. Hashes and heights are arbitrary TEST-VALUE patterns. A decoder must accept every valid vector (exact re-encoding) and refuse every invalid vector with the named error.",
        "design": "qualification/candidate-3/P-LANE-DESIGN-V1.md section 1.a",
        "spec": "spec/OPERATION-ENVELOPE-AND-CONFIRMATION-V1.md",
        "generator": "consensus: BUILD8_EXPORT_OPERATION_ENVELOPE=1 cargo test --offline --locked --lib op_envelope_v1::tests::export_operation_envelope_vectors (create_new: refuses to overwrite; delete the file first)",
        "reader": "consensus: cargo test --offline --locked --lib op_envelope_v1::tests::committed_operation_envelope_vectors_match_the_codec",
        "layout": "Envelope = [1, first_height, last_height, [reference_height, reference_block32], [Precondition...]]; Precondition = [1, license32, [[award_epoch, share, remaining, claims]...]] | [2, license32, assignment_sequence, active_worker32 | null, pending32 | null] | [3, treasury32, generation, address32]",
        "expiry_horizon": EXPIRY_HORIZON,
        "valid": valid,
        "invalid": invalid,
    });
    let mut text = serde_json::to_string_pretty(&document).unwrap();
    text.push('\n');
    text
}
fn vector_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../qualification/operation-envelope-v1-vectors.json")
}
fn hash_field(v: &serde_json::Value) -> Hash {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}
fn optional_hash_field(v: &serde_json::Value) -> Option<Hash> {
    if v.is_null() { None } else { Some(hash_field(v)) }
}
/// Reads the `fields` object independently of the vector builders.
fn envelope_from_fields(f: &serde_json::Value) -> Envelope {
    let u = |v: &serde_json::Value| v.as_u64().unwrap();
    let preconditions = f["preconditions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| match u(&p["tag"]) {
            1 => entitlements(
                hash_field(&p["license"]),
                p["accounts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| account(u(&a[0]), u(&a[1]), u(&a[2]), u(&a[3])))
                    .collect(),
            ),
            2 => assignment(
                hash_field(&p["license"]),
                u(&p["assignment_sequence"]),
                optional_hash_field(&p["active_worker"]),
                optional_hash_field(&p["pending"]),
            ),
            3 => treasury(hash_field(&p["treasury"]), u(&p["generation"]), hash_field(&p["address"])),
            other => panic!("unknown tag {other}"),
        })
        .collect();
    Envelope {
        first_height: u(&f["first_height"]),
        last_height: u(&f["last_height"]),
        reference_height: u(&f["reference_height"]),
        reference_block: hash_field(&f["reference_block"]),
        preconditions,
    }
}

// ---------------------------------------------------------------------------------------------
// Codec (14.4 `envelope_codec_rules_and_vectors`).
// ---------------------------------------------------------------------------------------------

#[test]
fn envelope_codec_rules_and_vectors() {
    // Independent oracle for the layout of design 1.a.1: the minimal vector assembled by hand.
    let expected = format!("8501{}{}82{}5820{}80", "1865", "18f5", "1864", "ab".repeat(32));
    assert_eq!(hex::encode(minimal().to_bytes().unwrap()), expected);
    // Every valid vector: E1-E7 hold, the encoding passes the repository's canonical walker, and
    // decode(encode(v)) == v with exact re-encoding, standalone and inside an enclosing item.
    for (name, e) in valid_vectors() {
        e.validate().unwrap_or_else(|err| panic!("{name}: {err:?}"));
        let raw = e.to_bytes().unwrap();
        crate::blocks::canonical(&raw, MAX_ENVELOPE_BYTES).unwrap_or_else(|err| panic!("{name}: {err:?}"));
        assert_eq!(Envelope::from_bytes(&raw).unwrap(), e, "{name}");
        let mut enclosing = Encoder::new(Vec::new());
        enclosing.array(3).unwrap().u8(9).unwrap().bytes(&[7; 3]).unwrap();
        e.encode(&mut enclosing).unwrap();
        let item = enclosing.into_writer();
        assert_eq!(item[1 + 1 + 4..], raw[..], "{name}: encode() appends exactly to_bytes()");
        assert_eq!(envelope_at(&item, 2), Some(e.clone()), "{name}");
        assert_eq!(envelope_at(&item, 1), None, "{name}: element 1 is not an envelope");
        assert_eq!(envelope_at(&item, 3), None, "{name}: beyond the array");
    }
    // Every single-rule violation is refused by BOTH directions with that rule's error, and
    // `encode` writes nothing for it.
    for (name, rule, e, error) in rule_cases() {
        assert_eq!(e.validate(), Err(error), "{name} ({rule})");
        assert_eq!(e.to_bytes(), Err(error), "{name} ({rule})");
        let mut target = Encoder::new(Vec::new());
        assert_eq!(e.encode(&mut target), Err(error), "{name} ({rule})");
        assert!(target.into_writer().is_empty(), "{name}: nothing written");
        let raw = unchecked(&e);
        crate::blocks::canonical(&raw, MAX_ENVELOPE_BYTES).unwrap_or_else(|err| panic!("{name}: the bytes are canonical CBOR: {err:?}"));
        assert_eq!(Envelope::from_bytes(&raw), Err(error), "{name} ({rule})");
    }
    // Non-canonical forms of valid values, and non-envelope structures.
    for (name, raw, error) in form_cases() {
        assert_eq!(Envelope::from_bytes(&raw), Err(error), "{name}");
    }
    // Oversize: more than the 16 KiB item bound in either direction.
    let many = (1..=2_000u64).map(|k| account(k * 131_072, 9, 9, 0)).collect();
    let big = with(vec![entitlements(h(3), many)]);
    big.validate().unwrap();
    assert_eq!(big.to_bytes(), Err(EnvelopeError::Oversize));
    let raw = unchecked(&big);
    assert!(raw.len() > MAX_ENVELOPE_BYTES);
    assert_eq!(Envelope::from_bytes(&raw), Err(EnvelopeError::Oversize));
}

#[test]
fn expiry_horizon_is_reused_exactly_at_and_one_beyond_the_boundary() {
    // E3 reuses the existing transfer horizon; no new TTL constant exists.
    assert_eq!(EXPIRY_HORIZON, crate::transactions::EXPIRY_HORIZON);
    assert_eq!(EXPIRY_HORIZON, 10_080);
    let at = window(1_000, 1_000 + 10_080, 999, h(4));
    let raw = at.to_bytes().unwrap();
    assert_eq!(Envelope::from_bytes(&raw).unwrap(), at);
    let beyond = window(1_000, 1_000 + 10_081, 999, h(4));
    assert_eq!(beyond.to_bytes(), Err(EnvelopeError::Horizon));
    assert_eq!(Envelope::from_bytes(&unchecked(&beyond)), Err(EnvelopeError::Horizon));
    // The span is measured between the window bounds, not from the reference.
    let old_reference = window(1_000, 1_000 + 10_080, 3, h(4));
    old_reference.validate().unwrap();
}

// ---------------------------------------------------------------------------------------------
// Window W and reference R at inclusion (design 1.a.2).
// ---------------------------------------------------------------------------------------------

#[test]
fn window_admits_exactly_first_through_last() {
    let none = History::default();
    // Envelope [101, 245] referencing its own parent at 100: valid at H = 101 (parent 100) only
    // through the parent shortcut; use a History anchor for later parents.
    let e = minimal();
    assert_eq!(e.check_inclusion(&parent(99, h(0xAB)), &none), Err(EnvelopeError::Future), "H = 100 < first");
    e.check_inclusion(&parent(100, h(0xAB)), &none).unwrap();
    let mut history = History::default();
    history.insert_anchor(100, h(0xAB)).unwrap();
    e.check_inclusion(&parent(150, h(0x10)), &history).unwrap();
    e.check_inclusion(&parent(244, h(0x10)), &history).unwrap();
    assert_eq!(e.check_inclusion(&parent(245, h(0x10)), &history), Err(EnvelopeError::Expired), "H = 246 > last");
    assert_eq!(e.check_inclusion(&parent(10_000, h(0x10)), &history), Err(EnvelopeError::Expired));
    // A single-height window.
    let single = window(1, 1, 0, h(0x01));
    single.check_inclusion(&parent(0, h(0x01)), &none).unwrap();
    assert_eq!(single.check_inclusion(&parent(1, h(0x09)), &none), Err(EnvelopeError::Expired));
    // The window is checked before the reference: an expired envelope reports Expired.
    assert_eq!(single.check_inclusion(&parent(1, h(0x09)), &history), Err(EnvelopeError::Expired));
    // No inclusion height exists after u64::MAX.
    assert_eq!(e.check_inclusion(&parent(u64::MAX, h(0x10)), &history), Err(EnvelopeError::Overflow));
    // Codec invariants are re-checked: an in-memory value violating E1 never passes inclusion.
    let zero = Envelope { reference_block: [0; 32], ..minimal() };
    assert_eq!(zero.check_inclusion(&parent(100, [0; 32]), &none), Err(EnvelopeError::ZeroReference));
}

#[test]
fn reference_parent_shortcut_history_anchor_and_fail_closed() {
    let none = History::default();
    // Parent shortcut: reference == parent height compares with the parent block itself.
    let e = window(51, 60, 50, h(0x50));
    e.check_inclusion(&parent(50, h(0x50)), &none).unwrap();
    assert_eq!(e.check_inclusion(&parent(50, h(0x51)), &none), Err(EnvelopeError::ReferenceNotCanonical));
    // The shortcut decides even if a (hand-built, inconsistent) History claims otherwise.
    let mut lying = History::default();
    lying.insert_anchor(50, h(0x51)).unwrap();
    assert_eq!(e.check_inclusion(&parent(50, h(0x51)), &lying), Err(EnvelopeError::ReferenceNotCanonical));
    e.check_inclusion(&parent(50, h(0x50)), &lying).unwrap();
    // An older reference is accepted only through a matching History anchor.
    let e = window(51, 60, 40, h(0x40));
    let mut history = History::default();
    history.insert_anchor(40, h(0x40)).unwrap();
    e.check_inclusion(&parent(55, h(0x55)), &history).unwrap();
    let mut other = History::default();
    other.insert_anchor(40, h(0x41)).unwrap();
    assert_eq!(e.check_inclusion(&parent(55, h(0x55)), &other), Err(EnvelopeError::ReferenceNotCanonical));
    // An anchor at another height does not help.
    let mut elsewhere = History::default();
    elsewhere.insert_anchor(41, h(0x40)).unwrap();
    assert_eq!(e.check_inclusion(&parent(55, h(0x55)), &elsewhere), Err(EnvelopeError::ReferenceNotCanonical));
    // Empty History: a non-parent reference fails closed.
    assert_eq!(e.check_inclusion(&parent(55, h(0x55)), &none), Err(EnvelopeError::ReferenceNotCanonical));
}

#[test]
fn history_anchor_insertion_refuses_a_conflicting_second_value() {
    let mut history = History::default();
    assert_eq!(history.anchor(7), None);
    history.insert_anchor(7, h(7)).unwrap();
    history.insert_anchor(7, h(7)).unwrap();
    assert_eq!(history.insert_anchor(7, h(8)), Err(crate::Error::Duplicate));
    assert_eq!(history.anchor(7), Some(h(7)), "the first value is kept");
    history.insert_anchor(0, h(9)).unwrap();
    assert_eq!(history.anchor(0), Some(h(9)));
    assert_eq!(history.anchor(8), None);
    // Authority entries and anchors are independent maps.
    let collected: History = std::iter::empty::<(u64, crate::votes_v2::HeightAuthority)>().collect();
    assert_eq!(collected.anchor(7), None);
    assert!(!history.contains_key(&7));
}

#[test]
fn from_head_builds_the_reviewed_window_and_refuses_out_of_range() {
    let head = parent(1_000, h(0x10));
    let e = Envelope::from_head(&head, 1, vec![]).unwrap();
    assert_eq!((e.first_height, e.last_height, e.reference_height, e.reference_block), (1_001, 1_002, 1_000, h(0x10)));
    let e = Envelope::from_head(&head, 144, vec![]).unwrap();
    assert_eq!((e.first_height, e.last_height), (1_001, 1_145), "N = 144: the next block and 144 after it");
    let e = Envelope::from_head(&head, EXPIRY_HORIZON, vec![treasury(h(5), 1, h(6))]).unwrap();
    assert_eq!(e.last_height - e.first_height, EXPIRY_HORIZON);
    assert_eq!(Envelope::from_bytes(&e.to_bytes().unwrap()).unwrap(), e);
    e.check_inclusion(&head, &History::default()).unwrap();
    assert_eq!(Envelope::from_head(&head, 0, vec![]), Err(EnvelopeError::ValidityBlocks));
    assert_eq!(Envelope::from_head(&head, EXPIRY_HORIZON + 1, vec![]), Err(EnvelopeError::ValidityBlocks));
    assert_eq!(Envelope::from_head(&parent(u64::MAX, h(1)), 1, vec![]), Err(EnvelopeError::Overflow));
    assert_eq!(Envelope::from_head(&parent(u64::MAX - 1, h(1)), 1, vec![]), Err(EnvelopeError::Overflow));
    assert_eq!(Envelope::from_head(&parent(5, [0; 32]), 1, vec![]), Err(EnvelopeError::ZeroReference));
    assert_eq!(
        Envelope::from_head(&head, 1, vec![treasury(h(5), 0, h(6))]),
        Err(EnvelopeError::ZeroGeneration),
        "preconditions are validated too"
    );
    assert_eq!(
        Envelope::from_head(&head, 1, vec![treasury(h(5), 1, h(6)), entitlements(h(3), vec![])]),
        Err(EnvelopeError::PreconditionOrder)
    );
}

// ---------------------------------------------------------------------------------------------
// Preconditions P and fact functions (design 1.a.2).
// ---------------------------------------------------------------------------------------------

fn trading_context() -> Context {
    Context { network: NETWORK_ID, genesis: h(1), fingerprint: h(2) }
}

#[test]
fn preconditions_compare_exact_facts_and_report_the_stale_tag() {
    let context = trading_context();
    let mut state = State::default();
    // No award: the facts of any License are the empty list.
    assert_eq!(entitlement_facts(&state, h(3)), entitlements(h(3), vec![]));
    with(vec![entitlements(h(3), vec![])]).check_preconditions(&state, &context).unwrap();
    assert_eq!(
        with(vec![entitlements(h(3), vec![account(131_072, 10, 10, 0)])]).check_preconditions(&state, &context),
        Err(EnvelopeError::Stale(1))
    );
    // No such License: unavailable facts, a stale committed assignment.
    assert_eq!(assignment_facts(&state, h(3)), Err(EnvelopeError::Unavailable(2)));
    assert_eq!(
        with(vec![assignment(h(3), 1, None, None)]).check_preconditions(&state, &context),
        Err(EnvelopeError::Stale(2))
    );
    // Treasury head from the trading records (TEST-VALUE descriptor from a public mnemonic).
    let key = HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap();
    let descriptor = key.public().descriptor(1).unwrap();
    let address = key.public().address_id(1).unwrap();
    let t = h(0x70);
    assert_eq!(treasury_head_facts(&state, &context, t), Err(EnvelopeError::Unavailable(3)));
    for (k, v) in crate::trading_v1::treasury_genesis_records(&context, t, descriptor).unwrap() {
        state.protocol_records.insert(k, v);
    }
    assert_eq!(treasury_head_facts(&state, &context, t), Ok(treasury(t, 1, address)));
    let committed = with(vec![entitlements(h(3), vec![]), treasury(t, 1, address)]);
    committed.check_preconditions(&state, &context).unwrap();
    for (stale, tag) in [
        (with(vec![treasury(t, 2, address)]), 3),
        (with(vec![treasury(t, 1, h(0x71))]), 3),
        (with(vec![treasury(h(0x72), 1, address)]), 3),
        (with(vec![entitlements(h(3), vec![account(131_072, 10, 10, 0)]), treasury(t, 1, address)]), 1),
    ] {
        assert_eq!(stale.check_preconditions(&state, &context), Err(EnvelopeError::Stale(tag)));
    }
    // The head is read in the caller's context; another context never matches.
    let elsewhere = Context { genesis: h(9), ..context.clone() };
    assert_eq!(treasury_head_facts(&state, &elsewhere, t), Err(EnvelopeError::Unavailable(3)));
    assert_eq!(committed.check_preconditions(&state, &elsewhere), Err(EnvelopeError::Stale(3)));
    // Codec invariants are re-checked before any comparison.
    let unordered = with(vec![treasury(t, 1, address), entitlements(h(3), vec![])]);
    assert_eq!(unordered.check_preconditions(&state, &context), Err(EnvelopeError::PreconditionOrder));
}

fn license_book() -> (HybridKey, Vec<crate::license_assignment_v2::Assignment>, Vec<mutiny_crypto_v2::enrollment::Binding>, State) {
    let (owner, assignments, expected, records, _node) = licenses::fixtures();
    let mut state = State::default();
    state.wallets.register(&owner.public().descriptor(1).unwrap()).unwrap();
    state.licenses_v2 =
        crate::license_book_v2::Book::genesis(&assignments, &expected, &records, &state.wallets, h(1), h(2)).unwrap();
    (owner, assignments, expected, state)
}

#[test]
fn assignment_identity_is_the_unsigned_binding_hash() {
    let (_, assignments, _, _) = license_book();
    let mut ids = BTreeSet::new();
    for a in &assignments {
        let unsigned = a.enrollment.binding.bytes().unwrap();
        // Independent oracle: SHA-256(domain || 0x00 || unsigned binding).
        let mut oracle = Sha256::new();
        oracle.update(b"MUTINY-BUILD8-LICENSE-ASSIGNMENT-ID-V2");
        oracle.update([0]);
        oracle.update(&unsigned);
        let expected: Hash = oracle.finalize().into();
        assert_eq!(assignment_id(a).unwrap(), expected);
        assert!(ids.insert(expected), "distinct assignments, distinct ids");
    }
    // Signatures are not part of the identity; every binding field is.
    let mut resigned = assignments[0].clone();
    resigned.enrollment.owner_signature.ed448[0] ^= 1;
    resigned.enrollment.worker_signature[0] ^= 1;
    assert_eq!(assignment_id(&resigned), assignment_id(&assignments[0]));
    let mut changed = assignments[0].clone();
    changed.enrollment.binding.valid_until_height += 1;
    assert_ne!(assignment_id(&changed), assignment_id(&assignments[0]));
    // An invalid binding has no identity.
    let mut invalid = assignments[0].clone();
    invalid.enrollment.binding.assignment_generation = 0;
    assert_eq!(assignment_id(&invalid), Err(EnvelopeError::Codec));
}

#[test]
fn assignment_facts_report_sequence_worker_and_pending_id() {
    let (owner, assignments, expected, mut state) = license_book();
    let context = trading_context();
    let license0 = expected[0].license;
    let license1 = expected[1].license;
    assert_eq!(assignment_facts(&state, license0), Ok(assignment(license0, 1, Some(expected[0].worker_id), None)));
    // Schedule a next-epoch assignment for License 1: the facts name its id as pending.
    let mut next = expected[1].clone();
    next.worker_public = licenses::worker(90);
    next.worker_id = next.derived_worker_id();
    next.assignment_generation = 2;
    next.configuration_generation = 2;
    next.effective_epoch = 2;
    next.valid_until_height = 30;
    let scheduled = licenses::sign(next.clone(), &owner, &assignments[1].node_descriptor, 90);
    let before = with(vec![assignment(license1, 1, Some(expected[1].worker_id), None)]);
    before.check_preconditions(&state, &context).unwrap();
    state.licenses_v2.schedule(scheduled.clone(), h(1), h(2), 2, 1, &state.wallets.clone()).unwrap();
    let pending = assignment_id(&scheduled).unwrap();
    let facts = assignment(license1, 1, Some(expected[1].worker_id), Some(pending));
    assert_eq!(assignment_facts(&state, license1), Ok(facts.clone()));
    assert_eq!(before.check_preconditions(&state, &context), Err(EnvelopeError::Stale(2)), "scheduling stales");
    let during = with(vec![facts]);
    during.check_preconditions(&state, &context).unwrap();
    // Activation moves the sequence and the Worker and clears the pending id.
    state.licenses_v2.activate_due(2).unwrap();
    assert_eq!(assignment_facts(&state, license1), Ok(assignment(license1, 2, Some(next.worker_id), None)));
    assert_eq!(during.check_preconditions(&state, &context), Err(EnvelopeError::Stale(2)), "activation stales");
}

// ---------------------------------------------------------------------------------------------
// Reference heights of a block (design 1.a.3).
// ---------------------------------------------------------------------------------------------

fn body(transactions: Vec<Vec<u8>>, operations: Vec<Vec<u8>>) -> BlockBody {
    BlockBody { height: 9, reward_owner: h(1), fees: 0, transactions, operations }
}

#[test]
fn referenced_heights_reads_only_envelopes_and_skips_malformed_items() {
    let a = carrier::encode(&window(8, 9, 3, h(3)));
    let b = carrier::encode(&window(8, 9, 5, h(5)));
    let same_height = carrier::encode(&window(8, 10, 3, h(3)));
    assert_eq!(carrier::decode(&a), Ok(window(8, 9, 3, h(3))));
    assert_eq!(operation_envelope(&a), Some(window(8, 9, 3, h(3))));
    // A malformed carrier (E1 violated) and items of other kinds contribute nothing.
    let mut broken = a.clone();
    let tail = broken.len() - 33;
    broken[tail..tail + 32].copy_from_slice(&[0; 32]);
    assert_eq!(carrier::decode(&broken), Err(EnvelopeError::ZeroReference));
    assert_eq!(operation_envelope(&broken), None);
    let mut trailing = a.clone();
    trailing.push(0);
    assert_eq!(operation_envelope(&trailing), None);
    let claim_like = vec![0x85, 0x02, 0x17, 0x40, 0x40, 0x40];
    assert_eq!(operation_envelope(&claim_like), None);
    let block = body(vec![a.clone()], vec![b.clone(), broken, same_height, claim_like, a.clone()]);
    assert_eq!(referenced_heights(&block), BTreeSet::from([3, 5]));
    assert_eq!(referenced_heights_in(&[], &[b.clone()]), BTreeSet::from([5]));
    // Unit-test builds recognize the carrier in the transaction list too (no production transaction
    // kind carries an envelope yet: integration test `the_test_only_carrier_is_not_an_item_kind_of_the_library`).
    assert_eq!(referenced_heights_in(&[b.clone()], &[]), BTreeSet::from([5]));
    assert_eq!(transaction_envelope(&b), Some(window(8, 9, 5, h(5))));
    assert_eq!(referenced_heights(&body(vec![], vec![])), BTreeSet::new());
    // The pool-only carrier form executes like the visible form but is never extracted from a block.
    let pool_only = carrier::encode_pool_only(&window(8, 9, 6, h(6)));
    assert!(carrier::is_carrier(&pool_only));
    assert_eq!(carrier::decode(&pool_only), Ok(window(8, 9, 6, h(6))));
    assert_eq!(operation_envelope(&pool_only), None);
    assert_eq!(transaction_envelope(&pool_only), None);
    assert_eq!(referenced_heights(&body(vec![pool_only.clone()], vec![pool_only])), BTreeSet::new());
}

/// AM-4: `State::execute_hybrid_transfers` has no canonical-store History, so a transaction that
/// carries an envelope passes only with its parent as reference; an older reference, another block
/// at the parent height, or a closed window fails closed before the kind's own checks.
#[test]
fn execute_hybrid_transfers_fails_closed_for_an_older_reference() {
    use crate::execution::ExecutionError;
    let state = State::default();
    let parent_block = h(0x20);
    let transfer_body =
        |transactions: Vec<Vec<u8>>| BlockBody { height: 9, reward_owner: h(1), fees: 0, transactions, operations: vec![] };
    let run = |transactions| state.execute_hybrid_transfers(h(1), h(2), parent_block, h(1), &transfer_body(transactions));
    for (case, e) in [
        ("older reference", window(9, 12, 3, h(3))),
        ("parent height, another block", window(9, 12, 8, h(0x21))),
        ("expired window", window(7, 8, 3, h(3))),
        ("future window", window(10, 12, 8, parent_block)),
    ] {
        let result = run(vec![carrier::encode(&e)]);
        assert!(matches!(result, Err(ExecutionError::Codec(crate::Error::WrongAnchor))), "{case}: {:?}", result.err());
    }
    // A parent reference passes the envelope check and then meets the kind's own decoder (the
    // carrier is not a hybrid transaction).
    let result = run(vec![carrier::encode(&window(9, 12, 8, parent_block))]);
    assert!(
        matches!(result, Err(ExecutionError::Transfer(crate::transactions::TxError::Codec))),
        "{:?}",
        result.err()
    );
    // A body without envelope-bearing transactions is unaffected.
    run(vec![]).unwrap();
}

// ---------------------------------------------------------------------------------------------
// Public vectors: generator (refuses to overwrite) and reader of the committed file.
// ---------------------------------------------------------------------------------------------

/// Generator. Writes `qualification/operation-envelope-v1-vectors.json` only when
/// BUILD8_EXPORT_OPERATION_ENVELOPE=1, with create_new (an existing file is never overwritten).
#[test]
fn export_operation_envelope_vectors() {
    if std::env::var("BUILD8_EXPORT_OPERATION_ENVELOPE").as_deref() != Ok("1") {
        return;
    }
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(vector_path())
        .expect("the vector file already exists: delete it explicitly before regenerating")
        .write_all(vector_document().as_bytes())
        .unwrap();
}

/// Reader. The committed file is byte-identical to the generator output, and independently of
/// the builders: every valid vector decodes to its listed fields, re-encodes exactly and has the
/// listed SHA-256; every invalid vector is refused with the listed error.
#[test]
fn committed_operation_envelope_vectors_match_the_codec() {
    let text = std::fs::read_to_string(vector_path()).expect("committed vector file");
    assert_eq!(text, vector_document(), "the committed file is exactly the generator output");
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["synthetic_only"], true);
    assert_eq!(document["production_authorized"], false);
    assert_eq!(document["status"], "PROPOSED-UNFROZEN");
    let valid = document["valid"].as_array().unwrap();
    assert_eq!(valid.len(), valid_vectors().len());
    for v in valid {
        let raw = hex::decode(v["cbor_hex"].as_str().unwrap()).unwrap();
        let decoded = Envelope::from_bytes(&raw).unwrap_or_else(|e| panic!("{}: {e:?}", v["name"]));
        assert_eq!(decoded, envelope_from_fields(&v["fields"]), "{}", v["name"]);
        assert_eq!(decoded.to_bytes().unwrap(), raw, "{}", v["name"]);
        assert_eq!(sha256_hex(&raw), v["sha256"].as_str().unwrap(), "{}", v["name"]);
    }
    let invalid = document["invalid"].as_array().unwrap();
    assert_eq!(invalid.len(), rule_cases().len() + form_cases().len());
    for v in invalid {
        let raw = hex::decode(v["cbor_hex"].as_str().unwrap()).unwrap();
        let error = Envelope::from_bytes(&raw).expect_err(v["name"].as_str().unwrap());
        assert_eq!(format!("{error:?}"), v["error"].as_str().unwrap(), "{}", v["name"]);
    }
}
