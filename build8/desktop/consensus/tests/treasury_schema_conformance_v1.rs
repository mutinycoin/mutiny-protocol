//! Mechanical comparison of `docs/TREASURY-PROOF-OF-CONTROL-SCHEMA-V1.md` and the independent
//! reproduction input list with the identified source and the committed vectors (continuation order,
//! section 7: export the exact definitions from the identified source, repair the prose, mechanically
//! compare source, specification and vectors).
//!
//! Every block between `<!-- BEGIN GENERATED: name -->` and `<!-- END GENERATED: name -->` is
//! regenerated here from the public API, from exact source lines (each must occur in its file), from
//! the encoder and decoder call sequences of `treasury_proof_v1.rs` and from the committed vector
//! files, and must equal the documents byte for byte. Generation itself re-verifies what it prints
//! (intent, AddressID, record hash, context, signatures, ceremony verdicts), so a block cannot describe
//! a value the code does not produce. The perturbation test shows that one changed byte of the
//! document, of a vector file, of a constant or of a pinned source line is reported.
//!
//! Regenerate: `BUILD8_TREASURY_SCHEMA_DOC=<file> BUILD8_TREASURY_INPUTS_DOC=<file> cargo test
//! --offline --locked --test treasury_schema_conformance_v1` writes both documents with every block
//! regenerated and all other text unchanged. SIMULATED / TEST-VALUE; public data only.
use mutiny_consensus_v8::{
    blocks::{GenesisDescriptor, state_root},
    genesis_inputs::Parameters,
    treasury_v1::{Class, Treasury},
    wallet_rotation_v1::Rotation,
};
use crate::{
    treasury_rehearsal_v1::{self as r, CeremonyConfig, Denylist, Expect, TrustedChain},
};
use mutiny_crypto_v2::{
    BOTH_REQUIRED_POLICY_ID, Domain, NETWORK, PROFILE, PublicKey, Role, WALLET_CRYPTO_SUITE_ID,
    treasury_proof_v1::{self as proof, Challenge, Phase},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::fmt::Write as _;

const SCHEMA_PATH: &str = "docs/TREASURY-PROOF-OF-CONTROL-SCHEMA-V1.md";
const DOC: &str = include_str!("../../docs/TREASURY-PROOF-OF-CONTROL-SCHEMA-V1.md");
const INPUTS_DOC: &str = include_str!("../../qualification/candidate-3/TREASURY-INDEPENDENT-REPRODUCTION-INPUTS.md");
const INPUTS_PATH: &str = "qualification/candidate-3/TREASURY-INDEPENDENT-REPRODUCTION-INPUTS.md";
const TOOLING_PATH: &str = "docs/TREASURY-REHEARSAL-TOOLING-V1.md";
const TOOLING_DOC: &str = include_str!("../../docs/TREASURY-REHEARSAL-TOOLING-V1.md");
const V1_PATH: &str = "qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json";
const PREIMAGE_PATH: &str = "qualification/TREASURY-PROOF-OF-CONTROL-PREIMAGE-VECTORS-V1.json";
const CEREMONY_PATH: &str = "qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json";
const ADD_PROOF_PATH: &str = "qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V2-ADDITIONS.json";
const ADD_CEREMONY_PATH: &str = "qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json";
const V1: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json");
const PREIMAGE: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-PREIMAGE-VECTORS-V1.json");
const CEREMONY: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json");
const ADD_PROOF: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V2-ADDITIONS.json");
const ADD_CEREMONY: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json");
const REGISTRY: &str = include_str!("../../spec/DOMAIN-REGISTRY-V1.json");
const FNDSA_LOCK: &str = include_str!("../../qualification/FNDSA-CUSTODY-SOURCE-LOCK-V2.json");
const CANDIDATE_LOCK: &str = include_str!("../../qualification/CRYPTO-CANDIDATE-SOURCE-LOCK-V1.json");
const FROZEN_HEADING: &str = "## 14. Frozen identity (candidate 3)";
/// The result file Cipher writes after the independent reproduction. Until it exists, the documents
/// must not claim a completed reproduction or a qualification (F10).
const RESULT_PATH: &str = "qualification/candidate-3/TREASURY-INDEPENDENT-REPRODUCTION-RESULT-V1.md";
const FORBIDDEN_UNTIL_RESULT: [&str; 8] = [
    "qualified for production",
    "independent reproduction: completed",
    "independent reproduction: passed",
    "independent reproduction: done",
    "independently reproduced",
    "reproduction completed",
    "byte-frozen (final)",
    "production-ready",
];
/// The status paragraph of the tooling document, pinned by its hash in the frozen identity (F10).
const TOOLING_STATUS_START: &str = "Status: ";
const TREASURY_REGISTRY_DOMAINS: [&str; 3] = [
    "MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1",
    "MUTINY-BUILD8-TREASURY-REHEARSAL-CONTEXT-V1",
    "MUTINY-BUILD8-HYBRID-ADDRESS-V1",
];

/// Source files whose exact lines are exported (A.2) or whose identities are recorded (section 14).
const SOURCES: [(&str, &str); 13] = [
    ("crypto-v2/src/lib.rs", include_str!("../../crypto-v2/src/lib.rs")),
    ("crypto-v2/src/treasury_proof_v1.rs", include_str!("../../crypto-v2/src/treasury_proof_v1.rs")),
    ("qualification/openssl-curve448-port/profile_adapter.c", include_str!("../../qualification/openssl-curve448-port/profile_adapter.c")),
    ("consensus/src/lib.rs", include_str!("../src/lib.rs")),
    ("consensus/src/treasury_v1.rs", include_str!("../src/treasury_v1.rs")),
    ("consensus/src/treasury_rehearsal_v1.rs", include_str!("../src/treasury_rehearsal_v1.rs")),
    ("consensus/src/treasury_admission_v1.rs", include_str!("../src/treasury_admission_v1.rs")),
    ("consensus/src/wallet_rotation_v1.rs", include_str!("../src/wallet_rotation_v1.rs")),
    ("consensus/src/wallet_authority_v1.rs", include_str!("../src/wallet_authority_v1.rs")),
    ("consensus/src/state_tree.rs", include_str!("../src/state_tree.rs")),
    ("consensus/src/blocks.rs", include_str!("../src/blocks.rs")),
    ("consensus/src/genesis_inputs.rs", include_str!("../src/genesis_inputs.rs")),
    ("consensus/src/protocol_manifest.rs", include_str!("../src/protocol_manifest.rs")),
];
/// Exact source lines (trimmed) that the definitions are exported from: (file, line, meaning).
const PINS: &[(&str, &str, &str)] = &[
    ("crypto-v2/src/lib.rs", "Self::TreasuryProofOfControl => b\"MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1\",", "proof domain literal"),
    ("crypto-v2/src/lib.rs", "| Self::ContinuityExitOwner | Self::BondCreate | Self::BondUnbond | Self::BondWithdraw | Self::NodeKeyRotateOwner | Self::TreasuryProofOfControl => Role::WalletOwner,", "domain role: WalletOwner"),
    ("crypto-v2/src/lib.rs", "pub const NETWORK: u32 = 0x4d555401;", "network"),
    ("crypto-v2/src/lib.rs", "pub const PROFILE: &str = \"MUTINY-FNDSA1024-PORNIN-20260722-V1\";", "FN-DSA profile literal"),
    ("crypto-v2/src/lib.rs", "pub const WALLET_CRYPTO_SUITE_ID: u16 = 1;", "suite id"),
    ("crypto-v2/src/lib.rs", "pub const BOTH_REQUIRED_POLICY_ID: u8 = 1;", "policy id (BOTH_REQUIRED)"),
    ("crypto-v2/src/lib.rs", "if payload.len() > 1024 * 1024 {", "intent payload limit"),
    ("crypto-v2/src/lib.rs", "h.update(domain.bytes());", "intent: domain bytes"),
    ("crypto-v2/src/lib.rs", "h.update([0]);", "intent: one zero byte"),
    ("crypto-v2/src/lib.rs", "h.update(payload);", "intent: payload, no length prefix"),
    ("crypto-v2/src/lib.rs", "let mut h = Sha512::new();", "intent: SHA-512"),
    ("crypto-v2/src/lib.rs", "|| signature.fndsa[0] != 0x3a", "FN-DSA signature header"),
    ("crypto-v2/src/lib.rs", ".verify(&signature.fndsa, &DOMAIN_NONE, &HASH_ID_RAW, &m)", "FN-DSA verification: raw message, empty context"),
    ("crypto-v2/src/lib.rs", "key.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, &m, &mut sig.fndsa)", "FN-DSA signing: raw message, empty context"),
    ("crypto-v2/src/lib.rs", "|| self.fndsa[0] != 0x0a", "FN-DSA public key header"),
    ("crypto-v2/src/lib.rs", "if raw.len() > 2048 {", "descriptor decode limit"),
    ("crypto-v2/src/lib.rs", "e.array(if wallet { 9 } else { 8 })", "descriptor: 9 items for a wallet key"),
    ("crypto-v2/src/lib.rs", "h.update(b\"MUTINY-BUILD8-HYBRID-ADDRESS-V1\\0\");", "AddressID prefix and zero byte"),
    ("crypto-v2/src/lib.rs", "if unsafe { build8_qual_ed448_public_valid(self.ed448.as_ptr(), 57) } != 1", "descriptor decode validates the Ed448 key"),
    ("crypto-v2/src/treasury_proof_v1.rs", "pub const CHALLENGE_VERSION: u8 = 1;", "challenge version"),
    ("crypto-v2/src/treasury_proof_v1.rs", "pub const CLASS_PRODUCTION: u8 = 1;", "class PRODUCTION"),
    ("crypto-v2/src/treasury_proof_v1.rs", "pub const CLASS_TEST_VALUE: u8 = 2;", "class TEST-VALUE"),
    ("crypto-v2/src/treasury_proof_v1.rs", "pub const SIGNATURE_BYTES: usize = 114 + 1280;", "signature serialization length"),
    ("crypto-v2/src/treasury_proof_v1.rs", "const FIELDS: u64 = 14;", "challenge items"),
    ("crypto-v2/src/treasury_proof_v1.rs", "if raw.is_empty() || raw.len() > 1024 {", "challenge decode limit"),
    ("crypto-v2/src/treasury_proof_v1.rs", "let h = |d: &mut minicbor::Decoder<'_>| -> Result<[u8; 32], ProofError> {", "items 9 to 14 are 32-byte strings"),
    ("crypto-v2/src/treasury_proof_v1.rs", "if d.position() != raw.len() {", "decode order: end of input (D3)"),
    ("crypto-v2/src/treasury_proof_v1.rs", "challenge.check_shape()?;", "decode order: class/phase then zero fields (D4, D5)"),
    ("crypto-v2/src/treasury_proof_v1.rs", "if challenge.encode_unchecked() != raw {", "canonical re-encoding"),
    ("crypto-v2/src/treasury_proof_v1.rs", "ed448: raw[..114].try_into().unwrap(),", "serialization: Ed448 first"),
    ("crypto-v2/src/treasury_proof_v1.rs", "fndsa: raw[114..].try_into().unwrap(),", "serialization: FN-DSA second"),
    ("qualification/openssl-curve448-port/profile_adapter.c", "return ossl_ed448_verify(NULL,intent,intent_length,signature,public_key,NULL,0,0,NULL)==1;", "Ed448: pure (phflag 0), empty context"),
    ("qualification/openssl-curve448-port/profile_adapter.c", "|| !build8_qual_ed448_public_valid(signature,57))return 0;", "Ed448: R decodes and is not of small order"),
    ("qualification/openssl-curve448-port/profile_adapter.c", "int ok=ossl_curve448_point_decode_like_eddsa_and_mul_by_ratio(point,public_key)==C448_SUCCESS;", "Ed448 key check: decode through the 4-isogeny"),
    ("qualification/openssl-curve448-port/profile_adapter.c", "if(ok)ok=!ossl_curve448_point_eq(point,ossl_curve448_point_identity);", "Ed448 key check: refuse points of order 1, 2 or 4"),
    ("consensus/src/lib.rs", "h.update(domain);", "domain_hash: domain"),
    ("consensus/src/lib.rs", "h.update(body);", "domain_hash: body after one zero byte"),
    ("consensus/src/treasury_rehearsal_v1.rs", "const CONTEXT_DOMAIN: &[u8] = b\"MUTINY-BUILD8-TREASURY-REHEARSAL-CONTEXT-V1\";", "rehearsal context domain"),
    ("consensus/src/treasury_rehearsal_v1.rs", "if !(4..=64).contains(&label.len()) || !label.bytes().all(|b| b.is_ascii_graphic()) {", "rehearsal label rule"),
    ("consensus/src/treasury_rehearsal_v1.rs", "Ok(domain_hash(CONTEXT_DOMAIN, label.as_bytes()))", "rehearsal context derivation"),
    ("consensus/src/treasury_rehearsal_v1.rs", "let state = State::from_records(records, root).map_err(|_| Refusal::SuccessionUnproven)?;", "lineage: records must reproduce the trusted StateRoot"),
    ("consensus/src/treasury_rehearsal_v1.rs", "if identity != pinned {", "plan: identity equals the pinned identity"),
    ("consensus/src/treasury_rehearsal_v1.rs", "if plan.network != chain.network || plan.genesis != chain.genesis || plan.fingerprint != chain.fingerprint {", "plan: trusted chain identity"),
    ("consensus/src/treasury_rehearsal_v1.rs", "if chain.height < plan.created_height || chain.height > plan.expiry_height {", "plan: validity window at the trusted height"),
    ("consensus/src/treasury_rehearsal_v1.rs", "if is_genesis_descriptor && approved.genesis_id.is_none() {", "post-freeze: GenesisID mandatory for a descriptor"),
    ("consensus/src/treasury_rehearsal_v1.rs", "if store.store_id() != approved.admission_store_id {", "post-freeze: the approved store"),
    ("consensus/src/treasury_v1.rs", "const RECORD_VERSION: u8 = 2;", "Treasury record version"),
    ("consensus/src/treasury_v1.rs", "pub(crate) const RECORD_TAG: u8 = 60;", "Treasury record tag"),
    ("consensus/src/treasury_admission_v1.rs", "pub const STORE_SCHEMA: &str = \"MUTINY-D2-TREASURY-ADMISSION-STORE-V2\";", "admission store schema"),
    ("consensus/src/treasury_admission_v1.rs", "const WRITE_PRAGMAS: &str = \"PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA;\";", "admission store durability"),
    ("consensus/src/treasury_admission_v1.rs", "mutiny_crypto_v2::fill_os_random(&mut store_id).map_err(|_| Refusal::Store)?;", "admission store id: 32 random bytes"),
    ("consensus/src/wallet_rotation_v1.rs", ".sign(Domain::WalletRotate, &body)", "rotation plan: authorization domain"),
    ("consensus/src/wallet_rotation_v1.rs", ".sign(Domain::WalletRotatePossession, &body)", "rotation plan: possession domain"),
    ("consensus/src/wallet_rotation_v1.rs", "b\"MUTINY-BUILD8-WALLET-ROTATION-ID-V1\",", "rotation plan identity domain"),
    ("consensus/src/wallet_rotation_v1.rs", "if old_generation.checked_add(1) != Some(new_generation) {", "rotation plan: proposed generation = current + 1"),
    ("consensus/src/wallet_rotation_v1.rs", ".is_none_or(|span| span > crate::transactions::EXPIRY_HORIZON)", "rotation plan: window at most the expiry horizon"),
    ("consensus/src/wallet_authority_v1.rs", "domain_hash(b\"MUTINY-BUILD8-WALLET-AUTHORITY-STATE-V1\", &id)", "wallet current-key record key"),
    ("consensus/src/wallet_authority_v1.rs", "domain_hash(b\"MUTINY-BUILD8-WALLET-ADDRESS-STATE-V1\", &address)", "wallet address record key"),
    ("consensus/src/state_tree.rs", "domain_hash(b\"MUTINY-BUILD8-STATE-BRANCH-V2\", &raw)", "state tree: branch"),
    ("consensus/src/state_tree.rs", "d[256] = domain_hash(b\"MUTINY-BUILD8-STATE-EMPTY-V2\", &[]);", "state tree: empty leaf"),
    ("consensus/src/state_tree.rs", "b\"MUTINY-BUILD8-STATE-LEAF-V2\",", "state tree: leaf domain"),
    ("consensus/src/state_tree.rs", "Ok(domain_hash(b\"MUTINY-BUILD8-STATE-V2\", &e.into_writer()))", "state tree: commitment"),
    ("consensus/src/state_tree.rs", "key[depth / 8] & (0x80 >> (depth % 8)) != 0", "state tree: key bits, most significant first"),
    ("consensus/src/blocks.rs", "Ok(domain_hash(b\"MUTINY-BUILD8-GENESIS-ID-V1\", &self.encode()?))", "GenesisID"),
    ("consensus/src/genesis_inputs.rs", "e.array(if self.treasury.is_some() { 5 } else { 4 })", "Parameters: 5 items with a Treasury"),
    ("consensus/src/protocol_manifest.rs", "pub const DOMAIN: &[u8] = b\"MUTINY-BUILD8-PROTOCOL-FINGERPRINT-V1\";", "rule fingerprint domain"),
];
/// Tests the documents name, and the file that must define each.
const CITED_TESTS: &[(&str, &str)] = &[
    ("every_hybrid_intent_domain_rejects_cross_domain_and_role_relabeling", "crypto-v2/src/tests.rs"),
    ("domain_is_registered_unique_nonspending_and_role_bound", "crypto-v2/src/treasury_proof_tests.rs"),
    ("proof_requires_both_components_and_every_binding", "crypto-v2/src/treasury_proof_tests.rs"),
    ("challenge_codec_is_strict_and_canonical", "crypto-v2/src/treasury_proof_tests.rs"),
    ("production_proofs_cannot_be_signed_or_accepted_while_unqualified", "crypto-v2/src/treasury_proof_tests.rs"),
    ("committed_public_vectors_verify_and_negative_vectors_fail", "crypto-v2/src/treasury_proof_tests.rs"),
    ("preimage_vectors_are_exact_and_reproducible_from_the_committed_v1_vectors", "crypto-v2/src/treasury_proof_tests.rs"),
    ("ed448_small_order_keys_are_forgeable_under_rfc8032_and_refused_by_this_port", "crypto-v2/src/treasury_proof_tests.rs"),
    ("proof_additions_v2_small_order_keys_and_multi_defect_probes_hold", "crypto-v2/src/treasury_proof_tests.rs"),
    ("internally_consistent_proofs_that_differ_from_the_trusted_expectation_are_refused", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("r1_a_fabricated_lineage_does_not_reproduce_the_trusted_state_root", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("r2_only_the_pinned_plan_on_the_trusted_chain_at_the_trusted_height_establishes_a_successor", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("an_impostor_successor_is_refused_under_the_rotation_plan_and_under_canonical_lineage", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("first_admission_consumes_the_nonce_durably_and_audits_are_read_only_and_repeatable", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("stores_run_synchronous_extra_and_audit_stores_are_read_only_at_the_sqlite_level", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("a_damaged_admission_row_is_refused_on_read", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("concurrent_admissions_of_one_nonce_admit_exactly_once", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("a_restart_in_separate_processes_keeps_the_nonce_consumed_and_audits_read_only", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("r5_a_replay_into_a_second_store_cannot_pass_the_approved_store", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("r6_a_label_with_a_quote_or_backslash_cannot_change_the_manifest_json", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("r7_admit_and_audit_refuse_an_expectation_of_another_ceremony_on_an_open_store", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("r8_empty_truncated_and_junk_store_files_fail_closed", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("the_frozen_genesis_is_compared_with_the_independently_approved_manifest", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("multi_defect_inputs_are_refused_in_the_normative_order", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("production_context_checking_side_compares_only_the_configured_value_and_never_a_genesis_id", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("the_rehearsal_context_derivation_is_exactly_the_documented_one", "consensus/tests/treasury_ceremony_closure_v1.rs"),
    ("library_controls_cover_every_rejection_reason_and_cannot_emit_production", "consensus/tests/treasury_rehearsal_v1.rs"),
    ("operator_flow_end_to_end_with_negative_controls_admission_and_class_safety", "consensus/tests/treasury_rehearsal_v1.rs"),
    ("treasury_rotation_rehearsal_gen1_to_gen2_with_preserved_reserves_restart_and_retry", "consensus/tests/treasury_rehearsal_rotation_v1.rs"),
    ("a_failure_between_insert_and_commit_admits_nothing_and_consumes_no_nonce", "consensus/src/treasury_admission_v1.rs"),
    ("ceremony_vectors_are_complete_reproducible_and_every_verdict_holds", "consensus/tests/treasury_ceremony_vectors_v1.rs"),
    ("ceremony_additions_v2_state_the_trusted_succession_inputs_and_every_verdict_holds", "consensus/tests/treasury_ceremony_additions_v2.rs"),
    ("one_changed_byte_of_the_document_a_vector_a_constant_or_a_source_line_is_detected", "consensus/tests/treasury_schema_conformance_v1.rs"),
];
const TEST_SOURCES: [(&str, &str); 9] = [
    ("crypto-v2/src/tests.rs", include_str!("../../crypto-v2/src/tests.rs")),
    ("crypto-v2/src/treasury_proof_tests.rs", include_str!("../../crypto-v2/src/treasury_proof_tests.rs")),
    ("consensus/tests/treasury_ceremony_closure_v1.rs", include_str!("treasury_ceremony_closure_v1.rs")),
    ("consensus/tests/treasury_rehearsal_v1.rs", include_str!("treasury_rehearsal_v1.rs")),
    ("consensus/tests/treasury_rehearsal_rotation_v1.rs", include_str!("treasury_rehearsal_rotation_v1.rs")),
    ("consensus/tests/treasury_ceremony_vectors_v1.rs", include_str!("treasury_ceremony_vectors_v1.rs")),
    ("consensus/tests/treasury_ceremony_additions_v2.rs", include_str!("treasury_ceremony_additions_v2.rs")),
    ("consensus/src/treasury_admission_v1.rs", include_str!("../src/treasury_admission_v1.rs")),
    ("consensus/tests/treasury_schema_conformance_v1.rs", include_str!("treasury_schema_conformance_v1.rs")),
];

type Gen<T> = Result<T, String>;

/// Everything the documents are generated from; perturbation tests change one field.
#[derive(Clone)]
struct Inputs {
    domain: Vec<u8>,
    profile: String,
    network: u32,
    v1: String,
    preimage: String,
    ceremony: String,
    add_proof: String,
    add_ceremony: String,
    registry: String,
    sources: Vec<(String, String)>,
}
fn real() -> Inputs {
    Inputs {
        domain: Domain::TreasuryProofOfControl.bytes().to_vec(),
        profile: PROFILE.to_string(),
        network: NETWORK,
        v1: V1.to_string(),
        preimage: PREIMAGE.to_string(),
        ceremony: CEREMONY.to_string(),
        add_proof: ADD_PROOF.to_string(),
        add_ceremony: ADD_CEREMONY.to_string(),
        registry: REGISTRY.to_string(),
        sources: SOURCES.iter().map(|(p, t)| (p.to_string(), t.to_string())).collect(),
    }
}

// ------------------------------------------------------------------------------------ helpers

fn sha(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn wrap(hex_text: &str) -> String {
    hex_text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n")
}
fn parse(text: &str, what: &str) -> Gen<Value> {
    serde_json::from_str(text).map_err(|e| format!("{what}: not JSON ({e})"))
}
fn hexfield(v: &Value, what: &str) -> Gen<Vec<u8>> {
    hex::decode(v.as_str().ok_or_else(|| format!("{what}: missing"))?).map_err(|_| format!("{what}: not hex"))
}
fn h32(v: &Value, what: &str) -> Gen<[u8; 32]> {
    hexfield(v, what)?.try_into().map_err(|_| format!("{what}: not 32 bytes"))
}
fn source<'a>(i: &'a Inputs, path: &str) -> Gen<&'a str> {
    i.sources.iter().find(|(p, _)| p == path).map(|(_, t)| t.as_str()).ok_or_else(|| format!("source {path} not provided"))
}
/// The pinned line exactly (trimmed) in its file, or an error naming it.
fn pinned(i: &Inputs, path: &str, line: &str) -> Gen<()> {
    if source(i, path)?.lines().any(|l| l.trim() == line) { Ok(()) } else { Err(format!("pinned line not found in {path}: {line}")) }
}
/// The decimal number that follows `marker` in a pinned line.
fn number_after(line: &str, marker: &str) -> Gen<u64> {
    let rest = &line[line.find(marker).ok_or_else(|| format!("{marker} not in {line}"))? + marker.len()..];
    let digits: String = rest.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().map_err(|_| format!("no number after {marker} in {line}"))
}
fn literal_in(line: &str) -> Gen<&str> {
    let start = line.find("b\"").ok_or_else(|| format!("no byte literal in {line}"))? + 2;
    let end = start + line[start..].find('"').ok_or("unterminated literal")?;
    Ok(line[start..end].trim_end_matches("\\0"))
}

/// The items of a definite CBOR array: (offset, length, initial bytes, value).
fn items(raw: &[u8]) -> Gen<Vec<(usize, usize, String, Value)>> {
    use minicbor::data::Type;
    let e = |x: minicbor::decode::Error| x.to_string();
    let mut d = minicbor::Decoder::new(raw);
    let n = d.array().map_err(e)?.ok_or("indefinite array")?;
    let mut out = Vec::new();
    for _ in 0..n {
        let start = d.position();
        let (value, payload) = match d.datatype().map_err(e)? {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 => (json!(d.u64().map_err(e)?), 0),
            Type::String => {
                let s = d.str().map_err(e)?;
                (json!(s), s.len())
            }
            Type::Bytes => {
                let b = d.bytes().map_err(e)?;
                (json!(hex::encode(b)), b.len())
            }
            Type::Array if d.probe().array().map_err(e)? == Some(0) => {
                d.array().map_err(e)?;
                (json!([]), 0)
            }
            other => return Err(format!("unexpected CBOR item {other:?}")),
        };
        let end = d.position();
        out.push((start, end - start, hex::encode(&raw[start..end - payload]), value));
    }
    if d.position() != raw.len() {
        return Err("trailing bytes after the array".to_string());
    }
    Ok(out)
}
fn shown(value: &Value, length_hint: Option<&str>) -> String {
    match (value, length_hint) {
        (Value::Number(n), _) => n.to_string(),
        (Value::String(s), Some(hint)) => hint.replace("{}", s),
        (Value::String(s), None) => format!("`{s}`"),
        _ => value.to_string(),
    }
}

/// `.method(argument)` calls in source order for the given methods.
fn calls(body: &str, methods: &[&str]) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for m in methods {
        let pattern = format!(".{m}(");
        let mut from = 0;
        while let Some(at) = body[from..].find(&pattern) {
            let start = from + at + pattern.len();
            let end = start + body[start..].find(')').unwrap_or(0);
            found.push((from + at, m.to_string(), body[start..end].trim().to_string()));
            from = start;
        }
    }
    found.sort();
    found.into_iter().map(|(_, m, a)| (m, a)).collect()
}
fn body<'a>(src: &'a str, start: &str, end: &str) -> Gen<&'a str> {
    let s = src.find(start).ok_or_else(|| format!("not found: {start}"))?;
    let e = s + src[s..].find(end).ok_or_else(|| format!("not found: {end}"))?;
    Ok(&src[s..e])
}
/// Items, types and order of the challenge as the encoder writes them; the decoder must read the same.
fn challenge_layout(i: &Inputs) -> Gen<Vec<(String, String)>> {
    let src = source(i, "crypto-v2/src/treasury_proof_v1.rs")?;
    let enc = calls(body(src, "pub fn encode_unchecked(&self) -> Vec<u8> {", "e.into_writer()")?, &["array", "u8", "u16", "u32", "u64", "str", "bytes"]);
    let (first, rest) = enc.split_first().ok_or("empty encoder")?;
    if first != &("array".to_string(), "FIELDS".to_string()) {
        return Err(format!("encoder starts with {first:?}"));
    }
    let layout: Vec<(String, String)> = rest
        .iter()
        .map(|(m, a)| {
            let name = match a.as_str() {
                "CHALLENGE_VERSION" => "version".to_string(),
                "NETWORK" => "network".to_string(),
                other => other.trim_start_matches('&').trim_start_matches("self.").trim_end_matches(" as u8").to_string(),
            };
            (name, m.clone())
        })
        .collect();
    let dec_src = body(src, "pub fn decode(raw: &[u8]) -> Result<Self, ProofError> {", "if d.position() != raw.len()")?;
    let mut dec: Vec<(usize, String)> = Vec::new();
    for (pattern, kind) in [("d.u8()", "u8"), ("d.u16()", "u16"), ("d.u32()", "u32"), ("d.u64()", "u64"), ("d.str()", "str"), ("h(&mut d)", "bytes")] {
        dec.extend(dec_src.match_indices(pattern).map(|(at, _)| (at, kind.to_string())));
    }
    dec.sort();
    let dec: Vec<String> = dec.into_iter().map(|(_, k)| k).collect();
    let enc_kinds: Vec<String> = layout.iter().map(|(_, k)| k.clone()).collect();
    if dec != enc_kinds {
        return Err(format!("decoder sequence {dec:?} differs from encoder sequence {enc_kinds:?}"));
    }
    let fields = number_after(PINS.iter().find(|p| p.2 == "challenge items").unwrap().1, "u64 =")?;
    if layout.len() as u64 != fields {
        return Err(format!("{} encoder items but FIELDS = {fields}", layout.len()));
    }
    Ok(layout)
}
fn pin_line(meaning: &str) -> &'static str {
    PINS.iter().find(|p| p.2 == meaning).map(|p| p.1).expect("pin")
}

// ---------------------------------------------------------------------------------- blocks

fn gen_constants(i: &Inputs) -> Gen<String> {
    for (path, line, _) in PINS {
        pinned(i, path, line)?;
    }
    let decode_limit = number_after(pin_line("challenge decode limit"), ">")?;
    let descriptor_limit = number_after(pin_line("descriptor decode limit"), ">")?;
    let payload = pin_line("intent payload limit");
    let payload_limit = number_after(payload, ">")? * number_after(payload, "*")?;
    let (lo, hi) = (challenge_size(i, 1)?, challenge_size(i, u64::MAX)?);
    // The role is WalletOwner: a relabelled role makes the committed V1 proof fail.
    let v1 = parse(&i.v1, "V1 vectors")?;
    let k1 = &v1["vectors"][0];
    let (public, _) = PublicKey::decode_descriptor(&hexfield(&k1["descriptor"], "descriptor")?).map_err(|e| format!("{e:?}"))?;
    let challenge = hexfield(&k1["challenge"], "challenge")?;
    let signature = proof::signature_from_bytes(&[hexfield(&k1["ed448_signature"], "ed448")?, hexfield(&k1["fndsa_signature"], "fndsa")?].concat())
        .map_err(|e| format!("{e:?}"))?;
    if public.verify(Domain::TreasuryProofOfControl, &challenge, &signature).is_err() || public.role != Role::WalletOwner {
        return Err("V1 vector d2-vector-k1 does not verify as WalletOwner".into());
    }
    let mut relabelled = public.clone();
    relabelled.role = Role::WalletRecovery;
    if relabelled.verify(Domain::TreasuryProofOfControl, &challenge, &signature).is_ok() {
        return Err("a relabelled role verifies".into());
    }
    let domain = std::str::from_utf8(&i.domain).map_err(|_| "domain not ASCII")?;
    let mut o = String::new();
    o.push_str("| Name | Value | Exported from |\n|---|---|---|\n");
    let _ = writeln!(o, "| Challenge version | `{}` | `treasury_proof_v1::CHALLENGE_VERSION` |", proof::CHALLENGE_VERSION);
    let _ = writeln!(o, "| Network | `0x{:08x}` (u32; CBOR `1a{:08x}`) | `NETWORK` |", i.network, i.network);
    let _ = writeln!(o, "| Domain literal | `{domain}` ({} bytes, ASCII, no terminator) | `Domain::TreasuryProofOfControl.bytes()` |", i.domain.len());
    o.push_str("| Domain role | `WalletOwner` (a key of any other role is refused) | `Domain::role` (A.2); the V1 vector fails under a relabelled role |\n");
    let _ = writeln!(o, "| Wallet crypto suite id | `{WALLET_CRYPTO_SUITE_ID}` (u16) | `WALLET_CRYPTO_SUITE_ID` |");
    let _ = writeln!(o, "| Signature policy | `BOTH_REQUIRED`, id `{BOTH_REQUIRED_POLICY_ID}` (u8) | `BOTH_REQUIRED_POLICY_ID` |");
    let _ = writeln!(o, "| FN-DSA profile literal | `{}` ({} bytes) | `PROFILE` |", i.profile, i.profile.len());
    let _ = writeln!(o, "| Phase | `{}` = Rehearsal, `{}` = Production | `Phase` |", Phase::Rehearsal as u8, Phase::Production as u8);
    let _ = writeln!(
        o,
        "| Class | `{}` = PRODUCTION, `{}` = TEST-VALUE; phase {} requires class {}, phase {} requires class {} | `CLASS_PRODUCTION`, `CLASS_TEST_VALUE`, `Phase::required_class` |",
        proof::CLASS_PRODUCTION,
        proof::CLASS_TEST_VALUE,
        Phase::Rehearsal as u8,
        Phase::Rehearsal.required_class(),
        Phase::Production as u8,
        Phase::Production.required_class()
    );
    let _ = writeln!(o, "| Challenge items | `{}` | `FIELDS` |", challenge_layout(i)?.len());
    let _ = writeln!(o, "| Challenge size | `{lo}` to `{hi}` bytes; the decoder accepts 1 to `{decode_limit}` | encoding; `Challenge::decode` |");
    let _ = writeln!(o, "| Signature serialization | Ed448 `114` bytes then FN-DSA `1280` bytes = `{}` bytes | `SIGNATURE_BYTES`, `signature_to_bytes` |", proof::SIGNATURE_BYTES);
    let _ = writeln!(o, "| Intent payload limit | `{payload_limit}` bytes | `intent` |");
    let _ = writeln!(o, "| Descriptor decode limit | `{descriptor_limit}` bytes | `PublicKey::decode_descriptor` |");
    Ok(o)
}

/// Encoded challenge size for a descriptor stamped with `generation`.
fn challenge_size(i: &Inputs, generation: u64) -> Gen<usize> {
    let v1 = parse(&i.v1, "V1 vectors")?;
    let (public, _) = PublicKey::decode_descriptor(&hexfield(&v1["vectors"][0]["descriptor"], "descriptor")?).map_err(|e| format!("{e:?}"))?;
    let descriptor = public.descriptor(generation).map_err(|e| format!("{e:?}"))?;
    let c = Challenge::new(&descriptor, Phase::Rehearsal, [1; 32], [2; 32], [3; 32], [4; 32]).map_err(|e| format!("{e:?}"))?;
    Ok(c.encode().map_err(|e| format!("{e:?}"))?.len())
}

fn gen_fields(i: &Inputs) -> Gen<String> {
    let layout = challenge_layout(i)?;
    let mut o = String::new();
    o.push_str("| # | Item | CBOR type (encoder call) | Value | Refused when (verifier) |\n|---|---|---|---|---|\n");
    for (n, (name, kind)) in layout.iter().enumerate() {
        let ty = match kind.as_str() {
            "u8" | "u16" | "u32" | "u64" => format!("unsigned integer (`{kind}`)"),
            "str" => "text string (`str`)".to_string(),
            "bytes" => "byte string, 32 bytes (`bytes`)".to_string(),
            other => return Err(format!("unknown encoder call {other}")),
        };
        let (value, refused) = match name.as_str() {
            "version" => (format!("`{}`", proof::CHALLENGE_VERSION), "other value: `Malformed`".to_string()),
            "network" => (format!("`0x{:08x}`", i.network), "other network: `Malformed`".to_string()),
            "phase" => ("`1` Rehearsal or `2` Production".to_string(), "other value: `Malformed`; `2`: `ProductionRefused`".to_string()),
            "class" => ("`2` with phase 1, `1` with phase 2".to_string(), "other: `ClassPhaseMismatch`".to_string()),
            "generation" => ("key version of the descriptor, at least `1`".to_string(), "`0`: `ZeroField`; not the descriptor's: `WrongKeyVersion`".to_string()),
            "suite_id" => (format!("`{WALLET_CRYPTO_SUITE_ID}`"), "other: `WrongProfile`".to_string()),
            "policy_id" => (format!("`{BOTH_REQUIRED_POLICY_ID}` (BOTH_REQUIRED)"), "other: `WrongProfile`".to_string()),
            "profile" => (format!("`{}` ({} bytes)", i.profile, i.profile.len()), "other: `WrongProfile`".to_string()),
            "descriptor_sha256" => ("`SHA-256(descriptor)`".to_string(), "other: `AlteredDescriptor`".to_string()),
            "address_id" => ("AddressID of the descriptor at its generation (A.9)".to_string(), "other: `AlteredDescriptor`".to_string()),
            "treasury_authority" => ("generation-one AddressID of the Treasury".to_string(), "zero: `ZeroField`; not the trusted Treasury: `TreasuryMismatch`".to_string()),
            "treasury_record_sha256" => ("`SHA-256(Treasury record)` (A.10)".to_string(), "zero: `ZeroField`; not the trusted record: `TreasuryMismatch`".to_string()),
            "ceremony_context" => ("ceremony context (section 6)".to_string(), "zero: `ZeroField`; not the expected context: `WrongContext`".to_string()),
            "nonce" => ("32 public bytes, single use".to_string(), "zero: `ZeroField`; already admitted: `Replay`".to_string()),
            other => return Err(format!("item {other} is not described")),
        };
        let _ = writeln!(o, "| {} | `{name}` | {ty} | {value} | {refused} |", n + 1);
    }
    let sizes: Vec<String> = [(1u64, "1 to 23"), (24, "24 to 255"), (256, "256 to 65535"), (65536, "65536 to 4294967295"), (1u64 << 32, "4294967296 or more")]
        .iter()
        .map(|(g, range)| challenge_size(i, *g).map(|s| format!("{s} bytes for generation {range}")))
        .collect::<Gen<_>>()?;
    for (g, expected) in [(23u64, 1u64), (255, 24), (65535, 256), (4294967295, 65536), (u64::MAX, 1 << 32)] {
        if challenge_size(i, g)? != challenge_size(i, expected)? {
            return Err(format!("size boundary at generation {g}"));
        }
    }
    let _ = writeln!(o, "\nEncoded size (`Challenge::encode`): {}.", sizes.join("; "));
    Ok(o)
}

fn gen_appendix(i: &Inputs) -> Gen<String> {
    let v1 = parse(&i.v1, "V1 vectors")?;
    let pre = parse(&i.preimage, "preimage vectors")?;
    let cer = parse(&i.ceremony, "ceremony vectors")?;
    let fn_lock = parse(FNDSA_LOCK, "FN-DSA source lock")?;
    let c_lock = parse(CANDIDATE_LOCK, "candidate source lock")?;
    let domain = std::str::from_utf8(&i.domain).map_err(|_| "domain not ASCII")?;
    let address_prefix = literal_in(pin_line("AddressID prefix and zero byte"))?;
    let context_domain = literal_in(pin_line("rehearsal context domain"))?;
    let rotate = Domain::WalletRotate.bytes();
    let possess = Domain::WalletRotatePossession.bytes();
    let k1v = &v1["vectors"][0];
    let k1p = &pre["vectors"][0];
    if k1v["label_public"] != "d2-vector-k1" || k1p["label_public"] != "d2-vector-k1" {
        return Err("first vector is not d2-vector-k1".into());
    }
    let challenge = hexfield(&k1v["challenge"], "challenge")?;
    let descriptor = hexfield(&k1v["descriptor"], "descriptor")?;
    let ed = hexfield(&k1v["ed448_signature"], "ed448")?;
    let fd = hexfield(&k1v["fndsa_signature"], "fndsa")?;
    let dom4 = hexfield(&k1p["ed448"]["dom4_hex"], "dom4")?;
    if dom4 != b"SigEd448\x00\x00" {
        return Err("dom4 differs".into());
    }
    let mut o = String::new();
    o.push_str("Exported from the source lines of A.2 and from the committed vector files; every value below was recomputed or verified while this block was generated.\n\n");
    // A.1
    o.push_str("### A.1 Literals\n\n| Literal | Bytes | Length | Hex |\n|---|---|---|---|\n");
    let lit = |o: &mut String, name: &str, shown: &str, raw: &[u8]| {
        let _ = writeln!(o, "| {name} | {shown} | {} | `{}` |", raw.len(), hex::encode(raw));
    };
    lit(&mut o, "Proof domain", &format!("`{domain}`"), &i.domain);
    lit(&mut o, "Separator", "one zero byte", &[0]);
    lit(&mut o, "FN-DSA profile", &format!("`{}`", i.profile), i.profile.as_bytes());
    lit(&mut o, "AddressID prefix", &format!("`{address_prefix}`"), address_prefix.as_bytes());
    lit(&mut o, "Rehearsal context domain", &format!("`{context_domain}`"), context_domain.as_bytes());
    lit(&mut o, "Ed448 dom4 (phflag 0, empty context)", "`SigEd448`, then `00` `00`", &dom4);
    lit(&mut o, "Rotation authorization domain", &format!("`{}`", std::str::from_utf8(rotate).unwrap()), rotate);
    lit(&mut o, "Rotation possession domain", &format!("`{}`", std::str::from_utf8(possess).unwrap()), possess);
    // A.2
    o.push_str("\n### A.2 Source lines (each occurs, trimmed, in the named file)\n\n```text\n");
    for (path, line, meaning) in PINS {
        pinned(i, path, line)?;
        let _ = writeln!(o, "{path} [{meaning}]\n    {line}");
    }
    o.push_str("```\n");
    // A.3
    let prefix = [&i.domain[..], &[0u8][..]].concat();
    let preimage = [&prefix[..], &challenge[..]].concat();
    let intent = Sha512::digest(&preimage);
    if hex::encode(intent) != k1v["intent"].as_str().unwrap_or("") || hex::encode(&preimage) != k1p["intent_preimage_hex"].as_str().unwrap_or("") {
        return Err("intent or preimage differs from the vectors".into());
    }
    let _ = write!(
        o,
        "\n### A.3 Intent: the 64 bytes that BOTH signatures cover\n\n```text\nintent = SHA-512( domain ({} bytes) || 0x00 || challenge )\n         no length prefix and no other framing; for a {}-byte challenge the SHA-512 input is {} bytes\ndomain || 0x00 ({} bytes):\n{}\n```\n",
        i.domain.len(),
        challenge.len(),
        preimage.len(),
        prefix.len(),
        wrap(&hex::encode(&prefix))
    );
    // A.4
    let add = parse(&i.add_proof, "proof additions")?;
    let small = add["ed448_small_order"]["keys"].as_array().cloned().ok_or("ed448_small_order")?;
    let small_refused = small.iter().filter(|k| k["repository_key_check"] == "REFUSED" && k["expected"] == "DescriptorInvalid").count();
    let small_forgeable = small.iter().filter(|k| k["plain_rfc8032_ed448_verdict_of_the_forgery"] == "VALID").count();
    if small.len() != 4 || small_refused != 4 || small_forgeable != 4 {
        return Err("the small-order additions do not show 4 refused keys, all 4 forgeable under textbook RFC 8032".into());
    }
    let _ = write!(
        o,
        "\n### A.4 Ed448 component (pure RFC 8032 Ed448)\n\n```text\npublic key 57 bytes; signature 114 bytes = R (57 bytes) || S (57 bytes)\nverify(public key, message = intent (64 bytes), context = empty, phflag = 0)\ndom4 = \"SigEd448\" || 0x00 (phflag) || 0x00 (context length) = {}\nk = SHAKE256(dom4 || R || public key || intent, 114 bytes) as in RFC 8032 section 5.2.7\nthe public key and R must decode (canonical encoding of a curve point) and must NOT be of order 1, 2 or 4:\n  the key check decodes through the 4-isogeny and refuses a point it maps to the identity (A.2, Ed448 key check)\n  textbook RFC 8032 (5.2.3 decoding, 5.2.7 check) accepts R = [s]B, S = s under EVERY such key for EVERY\n  message, since [4]A is the identity (OpenSSL 3.5.7 and the vendored verifier already refuse the order-2\n  and identity encodings at decoding, so they accept it under the two order-4 keys only); every such key\n  is refused when the descriptor is decoded: DescriptorInvalid ({} of {} small-order keys in\n  {ADD_PROOF_PATH}, ed448_small_order; {} of them forgeable under textbook RFC 8032)\n```\n",
        hex::encode(&dom4),
        small_refused,
        small.len(),
        small_forgeable
    );
    // A.5
    if fn_lock["profile"].as_str() != Some(i.profile.as_str()) {
        return Err("FN-DSA source lock names another profile".into());
    }
    let upstream = fn_lock["upstream_commit"].as_str().ok_or("upstream commit")?;
    let c_commit = c_lock["sources"]["c-fn-dsa"]["commit"].as_str().ok_or("c-fn-dsa commit")?;
    let _ = write!(
        o,
        "\n### A.5 FN-DSA component (profile `{}`, n = 1024)\n\n```text\npublic key 1793 bytes = header 0x0a || 1792 bytes\nsignature  1280 bytes = header 0x3a || nonce r (40 bytes) || compressed s2 (1239 bytes)\nhpk = SHAKE256(public key, 64 bytes)\nmu  = SHAKE256(hpk || 0x00 (raw message: no pre-hash) || 0x00 (context length: empty context) || intent, 64 bytes)\nc   = HashToPoint(SHAKE256(r || mu)): 16-bit little-endian samples v, keep v < 61445, coefficient v mod 12289\nthe lattice check itself is the vendored fn-dsa-vrfy (qualification/crypto-v2-sources/rust-fn-dsa-custody-v2)\nsources: rust-fn-dsa upstream {upstream} (custody copy; verification arithmetic unchanged); C reference c-fn-dsa {c_commit}\nthis is a pre-standard draft variant, not FIPS 206 final\n```\n",
        i.profile
    );
    // A.6
    let _ = write!(
        o,
        "\n### A.6 Signature serialization ({} bytes)\n\n| Offset | Length | Content |\n|---|---|---|\n| 0 | 114 | Ed448 signature (R, then S) |\n| 114 | 1280 | FN-DSA signature (header 0x3a first) |\n\nNo header and no length prefix; the order is fixed; any other length (114 alone, 1280 alone) is `Malformed`.\n",
        proof::SIGNATURE_BYTES
    );
    // A.7
    let split = items(&challenge)?;
    let layout = challenge_layout(i)?;
    let expected_items = k1p["challenge_items"].as_array().ok_or("challenge_items")?;
    o.push_str("\n### A.7 Challenge items of the example (V1 vector `d2-vector-k1`)\n\n| # | Item | Offset | Length | CBOR initial bytes | Value |\n|---|---|---|---|---|---|\n");
    for (n, ((off, len, head, value), (name, _))) in split.iter().zip(&layout).enumerate() {
        let e = &expected_items[n];
        if e["offset"] != json!(off) || e["length"] != json!(len) || e["cbor_header"] != json!(head) || &e["value"] != value || e["name"] != json!(name) {
            return Err(format!("challenge item {} differs from the preimage vectors", n + 1));
        }
        let _ = writeln!(o, "| {} | `{name}` | {off} | {len} | `{head}` | {} |", n + 1, shown(value, None));
    }
    // A.8
    let dsplit = items(&descriptor)?;
    let dnames = ["version", "network", "role", "generation", "suite_id", "policy_id", "profile", "ed448_public_key", "fndsa_public_key"];
    let dexpected = k1p["descriptor_items"].as_array().ok_or("descriptor_items")?;
    let _ = write!(o, "\n### A.8 Descriptor of the example ({} bytes, generation 1)\n\n| # | Item | Offset | Length | CBOR initial bytes | Value |\n|---|---|---|---|---|---|\n", descriptor.len());
    if dsplit.len() != dnames.len() {
        return Err("descriptor does not have 9 items".into());
    }
    for (n, ((off, len, head, value), name)) in dsplit.iter().zip(dnames).enumerate() {
        let e = &dexpected[n];
        if e["offset"] != json!(off) || e["length"] != json!(len) || e["cbor_header"] != json!(head) || &e["value"] != value || e["name"] != json!(name) {
            return Err(format!("descriptor item {} differs from the preimage vectors", n + 1));
        }
        let v = match name {
            "ed448_public_key" | "fndsa_public_key" => {
                let raw = hexfield(value, name)?;
                format!("{} bytes, first byte `{:02x}`, SHA-256 `{}`", raw.len(), raw[0], sha(&raw))
            }
            _ => shown(value, None),
        };
        let _ = writeln!(o, "| {} | `{name}` | {off} | {len} | `{head}` | {v} |", n + 1);
    }
    let _ = writeln!(o, "\ndescriptor_sha256 = `{}`", sha(&descriptor));
    // A.9
    let (public, generation) = PublicKey::decode_descriptor(&descriptor).map_err(|e| format!("{e:?}"))?;
    let address = Sha256::digest([address_prefix.as_bytes(), &[0u8][..], &descriptor[..]].concat());
    let derived = public.address_id(generation).map_err(|e| format!("{e:?}"))?;
    if address.as_slice() != &derived[..] || split[9].3 != json!(hex::encode(address)) {
        return Err("AddressID recomputation differs".into());
    }
    let _ = write!(
        o,
        "\n### A.9 AddressID\n\n```text\nAddressID = SHA-256(\"{address_prefix}\" || 0x00 || descriptor)\nexample (item 10 of A.7): {}\n```\n",
        hex::encode(address)
    );
    // A.10
    let record = hexfield(&cer["trusted_configuration"]["treasury_record_hex"], "record")?;
    let k1d = hexfield(&cer["keys"]["K1"]["descriptor_hex"], "K1 descriptor")?;
    let treasury = Treasury::decode(&record).map_err(|e| format!("{e:?}"))?;
    if treasury != Treasury::new(Class::TestValue, k1d.clone()).map_err(|e| format!("{e:?}"))? || treasury.encode().map_err(|e| format!("{e:?}"))? != record {
        return Err("Treasury record is not the TEST-VALUE record of K1".into());
    }
    let rsplit = items(&record)?;
    let record_version = number_after(pin_line("Treasury record version"), "u8 =")?;
    let record_tag = number_after(pin_line("Treasury record tag"), "u8 =")?;
    if rsplit.len() != 4 || rsplit[0].3 != json!(record_version) || rsplit[1].3 != json!(record_tag) || rsplit[2].3 != json!(Class::TestValue as u8) {
        return Err("record items differ".into());
    }
    let record_sha = sha(&record);
    if cer["trusted_configuration"]["treasury_record_sha256"] != json!(record_sha) || hex::encode(r::record_sha256(&treasury).map_err(|e| format!("{e:?}"))?) != record_sha {
        return Err("record hash differs".into());
    }
    let rows = [
        (hex::encode(&record[..1]), "array of 4 items".to_string()),
        (rsplit[0].2.clone(), format!("version {record_version}")),
        (rsplit[1].2.clone(), format!("tag {record_tag}")),
        (rsplit[2].2.clone(), format!("class {} (TEST-VALUE; 1 = PRODUCTION)", Class::TestValue as u8)),
        (rsplit[3].2.clone(), format!("byte string of {} bytes: the descriptor", k1d.len())),
    ];
    let _ = write!(
        o,
        "\n### A.10 Treasury record and record hash (ceremony vectors: Treasury K1 `{}`, TEST-VALUE)\n\n```text\nrecord = CBOR [version, tag, class, generation-one descriptor as a byte string]\n",
        cer["keys"]["K1"]["label_public"].as_str().unwrap_or("")
    );
    for (bytes, meaning) in rows {
        let _ = writeln!(o, "{bytes:<10}{meaning}");
    }
    let _ = write!(o, "record length {}; treasury_record_sha256 = SHA-256(record) =\n{}\n```\n", record.len(), record_sha);
    // A.11
    let label = cer["trusted_configuration"]["ceremony_context_label"].as_str().ok_or("label")?;
    let context = Sha256::digest([context_domain.as_bytes(), &[0u8][..], label.as_bytes()].concat());
    if r::ceremony_context(label).map_err(|e| format!("{e:?}"))?.as_slice() != context.as_slice() || cer["trusted_configuration"]["ceremony_context"] != json!(hex::encode(context)) {
        return Err("rehearsal context recomputation differs".into());
    }
    let _ = write!(
        o,
        "\n### A.11 Rehearsal ceremony context\n\n```text\nceremony_context = SHA-256(\"{context_domain}\" || 0x00 || label), label 4 to 64 bytes, each 0x21..0x7E\nexample label \"{label}\" ({} bytes): {}\n```\n",
        label.len(),
        hex::encode(context)
    );
    // A.12
    let plan = Rotation::decode(&hexfield(&cer["rotation_plan_encoded_hex"], "plan")?).map_err(|e| format!("{e:?}"))?;
    let unsigned = plan.unsigned().map_err(|e| format!("{e:?}"))?;
    if cer["rotation_plan"]["unsigned_body_hex"] != json!(hex::encode(&unsigned)) {
        return Err("rotation plan body differs".into());
    }
    let psplit = items(&unsigned)?;
    let pnames = ["version", "network", "genesis", "fingerprint", "authority", "current_descriptor", "proposed_descriptor", "created_height", "expiry_height"];
    let _ = write!(
        o,
        "\n### A.12 Rotation plan (succession evidence; `wallet_rotation_v1::Rotation`)\n\nUnsigned body of the ceremony-vector plan K1 -> K2 ({} bytes); the authorization (by the current key under `{}`) and the possession (by the proposed key under `{}`) are hybrid signatures over this body with the intent rule of A.3 and the components of A.4 to A.6. The encoded plan is the CBOR array `[1, body as a byte string, authorization Ed448, authorization FN-DSA, possession Ed448, possession FN-DSA]`.\n\n| # | Item | Offset | Length | CBOR initial bytes | Value |\n|---|---|---|---|---|---|\n",
        unsigned.len(),
        std::str::from_utf8(rotate).unwrap(),
        std::str::from_utf8(possess).unwrap()
    );
    if psplit.len() != pnames.len() {
        return Err("plan body does not have 9 items".into());
    }
    for (n, ((off, len, head, value), name)) in psplit.iter().zip(pnames).enumerate() {
        let v = match name {
            "current_descriptor" | "proposed_descriptor" => {
                let raw = hexfield(value, name)?;
                let who = if raw == k1d { "K1" } else if raw == hexfield(&cer["keys"]["K2"]["descriptor_hex"], "K2")? { "K2" } else { "unknown" };
                format!("{who} descriptor ({} bytes)", raw.len())
            }
            _ => shown(value, None),
        };
        let _ = writeln!(o, "| {} | `{name}` | {off} | {len} | `{head}` | {v} |", n + 1);
    }
    // A.13
    let c1 = Challenge::decode(&challenge).map_err(|e| format!("{e:?}"))?;
    let signature = proof::signature_from_bytes(&[ed.clone(), fd.clone()].concat()).map_err(|e| format!("{e:?}"))?;
    let verdict = match c1.verify(&descriptor, &signature) {
        Ok(()) => "VALID (both components verify; computed while generating this block)".to_string(),
        Err(e) => format!("REFUSED {e:?}"),
    };
    let _ = write!(
        o,
        "\n### A.13 Complete public example (V1 vector `d2-vector-k1`)\n\n```text\nchallenge ({} bytes):\n{}\nintent preimage = domain || 0x00 || challenge ({} bytes):\n{}\nintent = SHA-512(intent preimage) (64 bytes):\n{}\nEd448 signature: {} bytes, SHA-256 {}\nFN-DSA signature: {} bytes, header {:02x}, SHA-256 {}\nFN-DSA hpk: {}\nFN-DSA mu:  {}\nverdict: {verdict}\n```\n",
        challenge.len(),
        wrap(&hex::encode(&challenge)),
        preimage.len(),
        wrap(&hex::encode(&preimage)),
        wrap(&hex::encode(intent)),
        ed.len(),
        sha(&ed),
        fd.len(),
        fd[0],
        sha(&fd),
        k1p["fndsa"]["hashed_public_key_shake256_64_hex"].as_str().ok_or("hpk")?,
        k1p["fndsa"]["mu_shake256_64_hex"].as_str().ok_or("mu")?
    );
    // A.14
    let config = CeremonyConfig::rehearsal(i.network, treasury.clone(), label).map_err(|e| format!("{e:?}"))?;
    let addc = parse(&i.add_ceremony, "ceremony additions")?;
    let tc = &addc["trusted_configuration_additions"];
    let chain = TrustedChain {
        network: tc["trusted_chain"]["network"].as_u64().ok_or("network")? as u32,
        genesis: h32(&tc["trusted_chain"]["genesis"], "trusted genesis")?,
        fingerprint: h32(&tc["trusted_chain"]["fingerprint"], "trusted fingerprint")?,
        height: tc["trusted_chain"]["height"].as_u64().ok_or("height")?,
    };
    let pinned = h32(&tc["authorized_plan_identity"], "plan identity")?;
    let plan_config = config.clone().with_trusted_chain(chain).and_then(|c| c.with_authorized_plan(pinned)).map_err(|e| format!("{e:?}"))?;
    let plan_expect = Expect::authorized_rotation(&plan_config, &plan).map_err(|e| format!("{e:?}"))?;
    let verdict_of = |id: &str, expect: &Expect| -> Gen<(String, String)> {
        let p = &cer["proofs"][id];
        let signer = p["signer"].as_str().ok_or("signer")?;
        let d = hexfield(&cer["keys"][signer]["descriptor_hex"], "descriptor")?;
        let raw = hexfield(&p["challenge_hex"], "challenge")?;
        let s = proof::signature_from_bytes(&hexfield(&cer["signatures"][id], "signature")?).map_err(|e| format!("{e:?}"))?;
        let crypto = match Challenge::decode(&raw).and_then(|c| c.verify(&d, &s)) {
            Ok(()) => "VALID".to_string(),
            Err(e) => format!("{e:?}"),
        };
        let ceremony = match r::verify_proof(expect, &d, &raw, &s, &Denylist::default()) {
            Ok(_) => "ACCEPT".to_string(),
            Err(e) => format!("REJECT {e:?}"),
        };
        Ok((crypto, ceremony))
    };
    let p1 = hexfield(&cer["proofs"]["P1"]["challenge_hex"], "P1")?;
    let (p1_crypto, p1_ceremony) = verdict_of("P1", &Expect::genesis_key(&config))?;
    let (p3_crypto, p3_ceremony) = verdict_of("P3_impostor", &plan_expect)?;
    let _ = write!(
        o,
        "\n### A.14 Ceremony example (ceremony vectors)\n\n```text\ntrusted configuration: network 0x{:08x}, phase 1, class 2, Treasury authority {}\n                       record hash {}, context label \"{label}\"\nP1, K1, generation 1 ({} bytes):\n{}\nintent: {}\nverdicts: crypto {p1_crypto}; ceremony (expectation: the record's own key) {p1_ceremony}\ntrusted succession inputs ({ADD_CEREMONY_PATH}): chain genesis {}\n    fingerprint {}, trusted height {}, pinned plan identity {}\nP3, impostor K3, generation 2: crypto {p3_crypto}; ceremony (expectation: the pinned plan K1 -> K2) {p3_ceremony}\n```\n",
        i.network,
        hex::encode(treasury.authority()),
        record_sha,
        p1.len(),
        wrap(&hex::encode(&p1)),
        cer["proofs"]["P1"]["intent_sha512"].as_str().ok_or("P1 intent")?,
        hex::encode(chain.genesis),
        hex::encode(chain.fingerprint),
        chain.height,
        hex::encode(pinned)
    );
    Ok(o)
}

/// S2: the Genesis Parameters and Genesis descriptor layouts, the GenesisID derivation and the example
/// of the ceremony vectors, recomputed from the bytes (section 7.5).
fn gen_genesis(i: &Inputs) -> Gen<String> {
    let add = parse(&i.add_ceremony, "ceremony additions")?;
    let cer = parse(&i.ceremony, "ceremony vectors")?;
    let g = &add["genesis"];
    let parameters = hexfield(&g["parameters_hex"], "parameters")?;
    let raw = hexfield(&g["genesis_descriptor_hex"], "genesis descriptor")?;
    if g["parameters_hex"] != cer["frozen"]["frozen_parameters_hex"] || g["genesis_descriptor_hex"] != cer["frozen"]["genesis_descriptor_hex"] {
        return Err("the additions do not use the frozen inputs of the V1 ceremony vectors".into());
    }
    let id_line = pin_line("GenesisID");
    let id_domain = literal_in(id_line)?;
    let fp_domain = literal_in(pin_line("rule fingerprint domain"))?;
    let decoded = GenesisDescriptor::decode(&raw).map_err(|e| format!("{e:?}"))?;
    let id = decoded.id().map_err(|e| format!("{e:?}"))?;
    let recomputed = Sha256::digest([id_domain.as_bytes(), &[0u8][..], &raw[..]].concat());
    if recomputed.as_slice() != &id[..] || g["genesis_id"] != json!(hex::encode(id)) || cer["frozen"]["genesis_id"] != json!(hex::encode(id)) {
        return Err("GenesisID recomputation differs".into());
    }
    let p = Parameters::decode(&parameters).map_err(|e| format!("{e:?}"))?;
    let rules = p.rules.encode().map_err(|e| format!("{e:?}"))?;
    let fp = Sha256::digest([fp_domain.as_bytes(), &[0u8][..], &rules[..]].concat());
    if fp.as_slice() != &p.rules.fingerprint().map_err(|e| format!("{e:?}"))?[..] || decoded.fingerprint != p.rules.fingerprint().map_err(|e| format!("{e:?}"))? {
        return Err("rule fingerprint differs".into());
    }
    let mut o = String::new();
    let _ = write!(
        o,
        "```text\nParameters (version 3) = CBOR [1, 3, initial_target bstr32, rules bstr, Treasury record bstr]   (version 2: [1, 2, initial_target, rules], no Treasury)\nrules = CBOR [1, network u32, [[name bstr, hash bstr32], ...]]   (names ASCII graphic, strictly increasing)\nrule fingerprint = SHA-256(\"{fp_domain}\" || 0x00 || rules)\nGenesisDescriptor = CBOR [1, network u32, timestamp u64, nonce bstr32, fingerprint bstr32, owner bstr32,\n                          purchase bstr32, Parameters bstr, admission_records [bstr, ...] (strictly increasing), recovery bstr32]\nGenesisID = SHA-256(\"{id_domain}\" || 0x00 || GenesisDescriptor)\n```\n\nExample: the frozen inputs of the ceremony vectors (`frozen` of `{CEREMONY_PATH}`, repeated in `genesis` of `{ADD_CEREMONY_PATH}`).\n\n| # | Parameters item | Offset | Length | CBOR initial bytes | Value |\n|---|---|---|---|---|---|\n"
    );
    let pnames = ["version", "parameters_version", "initial_target", "rules", "treasury_record"];
    let psplit = items(&parameters)?;
    if psplit.len() != pnames.len() {
        return Err("Parameters do not have 5 items".into());
    }
    for (n, ((off, len, head, value), name)) in psplit.iter().zip(pnames).enumerate() {
        let v = match name {
            "rules" => format!("{} bytes, SHA-256 `{}`; fingerprint `{}`", rules.len(), sha(&rules), hex::encode(fp)),
            "treasury_record" => {
                let raw = hexfield(value, name)?;
                format!("{} bytes, SHA-256 `{}` (A.10)", raw.len(), sha(&raw))
            }
            _ => shown(value, None),
        };
        let _ = writeln!(o, "| {} | `{name}` | {off} | {len} | `{head}` | {v} |", n + 1);
    }
    let _ = writeln!(o, "\nParameters: {} bytes, parameters_sha256 = `{}`\n", parameters.len(), sha(&parameters));
    o.push_str("| # | GenesisDescriptor item | Offset | Length | CBOR initial bytes | Value |\n|---|---|---|---|---|---|\n");
    let gnames = ["version", "network", "timestamp", "nonce", "fingerprint", "owner", "purchase", "parameters", "admission_records", "recovery"];
    let gsplit = items(&raw)?;
    if gsplit.len() != gnames.len() {
        return Err("GenesisDescriptor does not have 10 items".into());
    }
    for (n, ((off, len, head, value), name)) in gsplit.iter().zip(gnames).enumerate() {
        let v = match name {
            "parameters" => format!("the Parameters above ({} bytes)", hexfield(value, name)?.len()),
            "fingerprint" => format!("{} (the rule fingerprint)", shown(value, None)),
            _ => shown(value, None),
        };
        let _ = writeln!(o, "| {} | `{name}` | {off} | {len} | `{head}` | {v} |", n + 1);
    }
    let _ = write!(
        o,
        "\n```text\nGenesisDescriptor: {} bytes; SHA-256(GenesisDescriptor) = {} (NOT the GenesisID)\nGenesisID preimage = \"{id_domain}\" || 0x00 || GenesisDescriptor ({} bytes)\nGenesisID = {}\n```\n",
        raw.len(),
        sha(&raw),
        id_domain.len() + 1 + raw.len(),
        hex::encode(id)
    );
    Ok(o)
}

/// S4: the canonical-lineage input (records and StateRoot), the state-tree root definition and the
/// wallet record encodings, with the lineage example of the ceremony additions (section 7.3).
fn gen_lineage(i: &Inputs) -> Gen<String> {
    let add = parse(&i.add_ceremony, "ceremony additions")?;
    let l = &add["canonical_lineage"];
    let rows = |v: &Value| -> Gen<Vec<([u8; 32], Vec<u8>)>> {
        v.as_array().ok_or("records")?.iter().map(|x| Ok((h32(&x["key"], "key")?, hexfield(&x["value"], "value")?))).collect()
    };
    let records = rows(&l["records"])?;
    let fabricated = rows(&l["fabricated_records"])?;
    let root = state_root(&records).map_err(|e| format!("{e:?}"))?;
    if l["state_root"] != json!(hex::encode(root)) || add["trusted_configuration_additions"]["canonical_state_root"] != json!(hex::encode(root)) {
        return Err("lineage records do not reproduce the stated root".into());
    }
    let fab_root = state_root(&fabricated).map_err(|e| format!("{e:?}"))?;
    if l["fabricated_records_state_root"] != json!(hex::encode(fab_root)) || fab_root == root {
        return Err("fabricated root differs from the file or equals the trusted root".into());
    }
    let lit = |meaning: &str| literal_in(pin_line(meaning));
    let mut o = String::new();
    let _ = write!(
        o,
        "```text\ndomain_hash(d, b) = SHA-256(d || 0x00 || b)\nleaf(key, record) = domain_hash(\"{}\", CBOR [2, key bstr32, record bstr])\nbranch(l, r)      = domain_hash(\"{}\", l || r)\nempty[256] = domain_hash(\"{}\", empty); empty[d] = branch(empty[d+1], empty[d+1])\nsubtree(records, d): none -> empty[d]; one record (k, v) -> leaf(k, v) lifted from depth 256 to d with\n  the empty[] siblings; otherwise split by bit d of the key (bit 0 = most significant bit of byte 0;\n  0 = left) and branch(subtree(left, d+1), subtree(right, d+1))\nStateRoot = domain_hash(\"{}\", CBOR [2, count u64, subtree(records, 0) bstr32]); records strictly increasing by key\nwallet records: key domain_hash(\"{}\", authority) -> CBOR [1, 30, authority bstr32, current descriptor bstr]\n                key domain_hash(\"{}\", AddressID) -> CBOR [1, 31, authority bstr32, descriptor of that AddressID bstr]\n```\n\nExample (`canonical_lineage` of `{ADD_CEREMONY_PATH}`): K1 registered, then the plan K1 -> K2 applied.\n\n| Key | Record kind | Record bytes | Record SHA-256 |\n|---|---|---|---|\n",
        lit("state tree: leaf domain")?,
        literal_in(pin_line("state tree: branch"))?,
        literal_in(pin_line("state tree: empty leaf"))?,
        literal_in(pin_line("state tree: commitment"))?,
        lit("wallet current-key record key")?,
        lit("wallet address record key")?,
    );
    for (key, value) in &records {
        let kind = items(value)?.get(1).map(|x| x.3.clone()).ok_or("record kind")?;
        let _ = writeln!(o, "| `{}` | {} | {} | `{}` |", hex::encode(key), kind, value.len(), sha(value));
    }
    let _ = write!(
        o,
        "\n```text\nStateRoot of these {} records (the trusted canonical_state_root) = {}\nthe fabricated records (K3 current, no K1 signature) give      {}\n```\n",
        records.len(),
        hex::encode(root),
        hex::encode(fab_root)
    );
    Ok(o)
}

/// Section 13: every file a second independent reproduction needs (the schema document's own
/// identity is in the reproduction input list and in section 14).
fn gen_final_inputs(i: &Inputs) -> Gen<String> {
    let mut o = String::from("| File | Bytes | SHA-256 | Role |\n|---|---|---|---|\n");
    let _ = writeln!(o, "| `{SCHEMA_PATH}` | see `{INPUTS_PATH}` (whole file) and section 14 (every byte before it) | | the specification |");
    for (path, text, what) in [
        (V1_PATH, &i.v1, "V1 codec and signature vectors (unchanged)"),
        (PREIMAGE_PATH, &i.preimage, "V1 exact preimages and 18 negatives (unchanged)"),
        (CEREMONY_PATH, &i.ceremony, "V1 ceremony vectors (unchanged)"),
        (ADD_PROOF_PATH, &i.add_proof, "V2 additions: Ed448 small-order keys, multi-defect probes"),
        (ADD_CEREMONY_PATH, &i.add_ceremony, "V2 additions: trusted succession inputs, lineage, Genesis verdicts, ceremony-order probes"),
    ] {
        parse(text, path)?;
        let _ = writeln!(o, "| `{path}` | {} | `{}` | {what} |", text.len(), sha(text.as_bytes()));
    }
    Ok(o)
}

/// Bytes of the schema document before the frozen-identity heading (exactly one, the last section).
fn frozen_prefix(doc: &str) -> Gen<&str> {
    let marker = format!("\n{FROZEN_HEADING}\n");
    let hits: Vec<usize> = doc.match_indices(&marker).map(|(at, _)| at).collect();
    if hits.len() != 1 {
        return Err(format!("{} frozen-identity headings", hits.len()));
    }
    if doc[hits[0] + marker.len()..].contains("\n## ") {
        return Err("the frozen-identity section is not the last section".into());
    }
    Ok(&doc[..hits[0] + 1])
}
fn registry_lines(registry: &str) -> String {
    registry
        .split_inclusive('\n')
        .filter(|l| TREASURY_REGISTRY_DOMAINS.iter().any(|d| l.contains(&format!("\"ascii\": \"{d}\""))))
        .collect()
}
/// The reproduction input list without its generated block (its prose), pinned by hash (F10).
fn inputs_prose(inputs_doc: &str) -> Gen<String> {
    let (s, e) = block_bounds(inputs_doc, "reproduction-inputs")?;
    Ok(format!("{}{}", &inputs_doc[..s], &inputs_doc[e..]))
}
/// The status paragraph of the tooling document (from `Status: ` to the first blank line), pinned (F10).
fn tooling_status(tooling_doc: &str) -> Gen<&str> {
    let s = tooling_doc.find(TOOLING_STATUS_START).ok_or("tooling status paragraph not found")?;
    let e = s + tooling_doc[s..].find("\n\n").ok_or("tooling status paragraph not terminated")?;
    Ok(&tooling_doc[s..e + 1])
}
fn gen_frozen(i: &Inputs, schema_doc: &str, inputs_doc: &str, tooling_doc: &str) -> Gen<String> {
    let prefix = frozen_prefix(schema_doc)?;
    let lines = registry_lines(&i.registry);
    let mut o = String::from("| Artifact | Bytes | SHA-256 |\n|---|---|---|\n");
    let _ = writeln!(o, "| `{SCHEMA_PATH}`, every byte before the line `{FROZEN_HEADING}` | {} | `{}` |", prefix.len(), sha(prefix.as_bytes()));
    let prose = inputs_prose(inputs_doc)?;
    let _ = writeln!(o, "| `{INPUTS_PATH}`, every byte outside the generated block `reproduction-inputs` | {} | `{}` |", prose.len(), sha(prose.as_bytes()));
    let status = tooling_status(tooling_doc)?;
    let _ = writeln!(o, "| `{TOOLING_PATH}`, the status paragraph (from `Status:` to the first blank line) | {} | `{}` |", status.len(), sha(status.as_bytes()));
    for (path, text) in [(V1_PATH, &i.v1), (PREIMAGE_PATH, &i.preimage), (CEREMONY_PATH, &i.ceremony), (ADD_PROOF_PATH, &i.add_proof), (ADD_CEREMONY_PATH, &i.add_ceremony)] {
        let _ = writeln!(o, "| `{path}` | {} | `{}` |", text.len(), sha(text.as_bytes()));
    }
    for path in ["crypto-v2/src/treasury_proof_v1.rs", "consensus/src/treasury_rehearsal_v1.rs", "consensus/src/treasury_admission_v1.rs"] {
        let text = source(i, path)?;
        let _ = writeln!(o, "| `{path}` | {} | `{}` |", text.len(), sha(text.as_bytes()));
    }
    let _ = writeln!(
        o,
        "| `spec/DOMAIN-REGISTRY-V1.json`: the {} lines whose `ascii` is `{}`, in file order, each with its LF | {} | `{}` |",
        lines.lines().count(),
        TREASURY_REGISTRY_DOMAINS.join("`, `"),
        lines.len(),
        sha(lines.as_bytes())
    );
    Ok(o)
}
fn gen_inputs(i: &Inputs, schema_doc: &str) -> String {
    let mut o = String::from("| File | Bytes | SHA-256 | Content |\n|---|---|---|---|\n");
    for (path, text, what) in [
        (SCHEMA_PATH, schema_doc, "the specification (whole file)"),
        (V1_PATH, i.v1.as_str(), "V1 codec and signature vectors; public descriptors of the K1/K2 test keys in `descriptor`"),
        (PREIMAGE_PATH, i.preimage.as_str(), "exact preimages per V1 vector and 18 derived negative vectors"),
        (CEREMONY_PATH, i.ceremony.as_str(), "ceremony keys, trusted configuration, rotation plan, 10 proofs, 12 cases, 2 sequences"),
        (ADD_PROOF_PATH, i.add_proof.as_str(), "V2 additions: 4 Ed448 small-order keys with forged proofs, honest control, 10 multi-defect probes"),
        (ADD_CEREMONY_PATH, i.add_ceremony.as_str(), "V2 additions: trusted chain, height and pinned plan, 3 plans, lineage records and root, 14 succession cases, Genesis derivation and 8 verdicts, 7 ceremony-order probes"),
    ] {
        let _ = writeln!(o, "| `{path}` | {} | `{}` | {what} |", text.len(), sha(text.as_bytes()));
    }
    o
}

fn block_bounds(doc: &str, name: &str) -> Gen<(usize, usize)> {
    let begin = format!("<!-- BEGIN GENERATED: {name} -->\n");
    let end = format!("<!-- END GENERATED: {name} -->");
    let b: Vec<usize> = doc.match_indices(&begin).map(|(at, _)| at).collect();
    let e: Vec<usize> = doc.match_indices(&end).map(|(at, _)| at).collect();
    match (b.as_slice(), e.as_slice()) {
        ([b], [e]) if b + begin.len() <= *e => Ok((b + begin.len(), *e)),
        _ => Err(format!("block {name}: {} BEGIN and {} END markers", b.len(), e.len())),
    }
}
fn replace_block(doc: &str, name: &str, content: &str) -> Gen<String> {
    let (s, e) = block_bounds(doc, name)?;
    Ok(format!("{}{}{}", &doc[..s], content, &doc[e..]))
}
fn compare_block(doc: &str, name: &str, generated: Gen<String>, out: &mut Vec<String>) {
    match (block_bounds(doc, name), generated) {
        (Err(e), _) | (_, Err(e)) => out.push(format!("{name}: {e}")),
        (Ok((s, e)), Ok(content)) if doc[s..e] != content => {
            let first = doc[s..e].lines().zip(content.lines()).position(|(a, b)| a != b).unwrap_or(0);
            out.push(format!("{name}: differs from a fresh generation (first differing line {})", first + 1));
        }
        _ => {}
    }
}

fn registry_differences(i: &Inputs) -> Vec<String> {
    let mut out = Vec::new();
    let registry = match parse(&i.registry, "registry") {
        Ok(v) => v,
        Err(e) => return vec![e],
    };
    let listed = registry["domains"].as_array().cloned().unwrap_or_default();
    let entry = |ascii: &str| -> Option<Value> {
        let hits: Vec<&Value> = listed.iter().filter(|e| e["ascii"] == ascii).collect();
        (hits.len() == 1).then(|| hits[0].clone())
    };
    let domain = String::from_utf8_lossy(&i.domain).to_string();
    match entry(&domain) {
        None => out.push(format!("registry: {domain} not registered exactly once")),
        Some(e) => {
            let want = [
                ("length", json!(i.domain.len())),
                ("role", json!("WalletOwner")),
                ("hash", json!("SHA-512")),
                ("suite_id", json!(WALLET_CRYPTO_SUITE_ID)),
                ("policy", json!("BOTH_REQUIRED")),
                ("policy_id", json!(BOTH_REQUIRED_POLICY_ID)),
                ("profile", json!(i.profile)),
                ("profile_length", json!(i.profile.len())),
                ("signature_bytes", json!(proof::SIGNATURE_BYTES)),
                ("signature_serialization", json!("ed448 (114) || fndsa (1280)")),
                ("framing", json!("intent = SHA-512(ascii || 0x00 || body); no length prefix; body at most 1048576 bytes (challenge decoder: 1 to 1024)")),
                ("frozen", json!(false)),
                ("doc", json!(SCHEMA_PATH)),
                ("vectors", json!([V1_PATH, PREIMAGE_PATH, CEREMONY_PATH, ADD_PROOF_PATH, ADD_CEREMONY_PATH])),
            ];
            for (k, v) in want {
                if e[k] != v {
                    out.push(format!("registry: {domain}.{k} is {} not {v}", e[k]));
                }
            }
            let components = e["components"].as_str().unwrap_or("");
            for needle in ["RFC 8032 Ed448, phflag 0, empty context", "raw message (hash identifier 0x00), empty context", "header 0x3a", "both required"] {
                if !components.contains(needle) {
                    out.push(format!("registry: components lacks {needle}"));
                }
            }
            if !e["purpose"].as_str().unwrap_or("").contains("non-spending") {
                out.push("registry: purpose lacks non-spending".into());
            }
        }
    }
    let context_domain = literal_in(pin_line("rehearsal context domain")).unwrap_or("");
    let address_prefix = literal_in(pin_line("AddressID prefix and zero byte")).unwrap_or("");
    for (ascii, hash) in [(context_domain, "SHA-256"), (address_prefix, "SHA-256")] {
        match entry(ascii) {
            None => out.push(format!("registry: {ascii} not registered exactly once")),
            Some(e) => {
                if e["length"] != json!(ascii.len()) || e["hash"] != json!(hash) || e["status"] != json!("PROPOSED-UNFROZEN") {
                    out.push(format!("registry: {ascii} entry differs"));
                }
            }
        }
    }
    out
}

/// F10: a cited function is a test that runs: `#[test]` among the attributes directly above it, no
/// `#[ignore`, and the feature of a feature-gated test file is named in the document.
fn test_attribute_problems(text: &str, name: &str, schema_doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(at) = text.find(&format!("fn {name}(")) else {
        return vec![format!("cited test {name} is not defined")];
    };
    let line_start = text[..at].rfind('\n').map_or(0, |p| p + 1);
    let attributes: Vec<&str> = text[..line_start].lines().rev().map(str::trim).take_while(|l| l.starts_with("#[") || l.starts_with("///")).collect();
    if !attributes.contains(&"#[test]") {
        out.push(format!("cited test {name} does not carry #[test]"));
    }
    if attributes.iter().any(|l| l.starts_with("#[ignore")) {
        out.push(format!("cited test {name} is ignored"));
    }
    if let Some(feature) = text.lines().find_map(|l| l.trim().strip_prefix("#![cfg(feature = \"").and_then(|r| r.strip_suffix("\")]")))
        && !schema_doc.contains(&format!("`{feature}`"))
    {
        out.push(format!("cited test {name} needs feature {feature}, which the document does not name"));
    }
    out
}
fn cited_differences(schema_doc: &str, i: &Inputs) -> Vec<String> {
    let mut out = Vec::new();
    for &(name, file) in CITED_TESTS {
        if !schema_doc.contains(name) {
            out.push(format!("cited test {name} is not named in the document"));
        }
        match TEST_SOURCES.iter().find(|(p, _)| *p == file) {
            Some((_, text)) if text.contains(&format!("fn {name}(")) => out.extend(test_attribute_problems(text, name, schema_doc)),
            _ => out.push(format!("cited test {name} is not defined in {file}")),
        }
    }
    // Vector case, negative and sequence names used by the document exist in the vector files.
    let names = |text: &str, list: &str, key: &str| -> Vec<String> {
        serde_json::from_str::<Value>(text).ok().and_then(|v| v[list].as_array().cloned()).unwrap_or_default().iter().filter_map(|e| e[key].as_str().map(str::to_string)).collect()
    };
    let known: Vec<String> = [
        names(&i.ceremony, "cases", "name"),
        names(&i.ceremony, "sequences", "name"),
        names(&i.preimage, "negative", "name"),
        names(&i.add_proof, "multi_defect_probes", "name"),
        names(&i.add_ceremony, "succession_cases", "name"),
        names(&i.add_ceremony, "ceremony_order_probes", "name"),
    ]
    .concat();
    for cited in [
        "reject_impostor_successor_rotation_plan",
        "reject_impostor_successor_canonical_lineage",
        "reject_wrong_context",
        "reject_wrong_treasury_authority",
        "reject_wrong_class_record",
        "reject_wrong_generation_one_under_plan",
        "reject_wrong_generation_two_as_one",
        "reject_wrong_descriptor",
        "nonce_replay",
        "repeatable_audit",
        "truncated_challenge",
        "extended_challenge",
        "non_canonical_integer_version",
        "indefinite_length_array",
        "profile_as_byte_string",
        "other_network",
        "class_phase_mismatch",
        "zero_nonce",
        "reject_second_validly_signed_plan_not_pinned",
        "reject_plan_of_another_chain_identity",
        "reject_plan_expired_at_the_trusted_height",
        "reject_fabricated_lineage_records",
        "class_phase_mismatch_and_truncated",
        "production_phase_with_an_ed448_only_signature",
        "impostor_with_a_bad_signature",
    ] {
        if !schema_doc.contains(&format!("`{cited}`")) {
            out.push(format!("vector name {cited} is not named in the document"));
        }
        if !known.iter().any(|k| k == cited) {
            out.push(format!("vector name {cited} does not exist in the vector files"));
        }
    }
    out
}

/// Variant names of `pub enum <name> {` in `src`, one per line (doc comments and attributes skipped).
fn variants(src: &str, name: &str) -> Gen<Vec<String>> {
    let header = format!("pub enum {name} {{");
    let start = src.find(&header).ok_or_else(|| format!("enum {name} not found"))? + header.len();
    let end = start + src[start..].find("\n}").ok_or_else(|| format!("end of enum {name} not found"))?;
    Ok(src[start..end]
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with('#'))
        .map(|l| l.split([',', '(']).next().unwrap_or("").trim().to_string())
        .filter(|v| !v.is_empty())
        .collect())
}
/// Backticked spans of a Markdown text.
fn spans(text: &str) -> Vec<&str> {
    text.split('`').skip(1).step_by(2).collect()
}
/// Identifiers in backticks that are not refusal names although they look like one.
const NOT_REFUSALS: [&str; 12] = [
    "GenesisDescriptor",
    "TrustedChain",
    "ApprovedManifest",
    "WalletOwner",
    "WalletRecovery",
    "CeremonyConfig",
    "ExpectedContext",
    "WalletBook",
    "AdmissionStore",
    "PublicKey",
    "TreasuryProofOfControl",
    "TreasuryRotate",
];
/// Every refusal name the documents use (a CamelCase span, or `Proof(X)`) is a variant of `Refusal`
/// or `ProofError` in the source.
fn refusal_name_differences(docs: &[(&str, &str)], i: &Inputs) -> Vec<String> {
    let known = match (
        source(i, "consensus/src/treasury_rehearsal_v1.rs").and_then(|s| variants(s, "Refusal")),
        source(i, "crypto-v2/src/treasury_proof_v1.rs").and_then(|s| variants(s, "ProofError")),
    ) {
        (Ok(a), Ok(b)) if a.len() > 10 && b.len() > 10 => (a, b),
        (Err(e), _) | (_, Err(e)) => return vec![e],
        _ => return vec!["enum variants not found".into()],
    };
    let mut out = Vec::new();
    for (path, text) in docs {
        for span in spans(text) {
            let ok = if let Some(inner) = span.strip_prefix("Proof(").and_then(|s| s.strip_suffix(')')) {
                known.0.iter().any(|v| v == "Proof") && known.1.iter().any(|v| v == inner)
            } else if span.len() > 3
                && span.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && span.chars().all(|c| c.is_ascii_alphabetic())
                && span.chars().any(|c| c.is_ascii_lowercase())
                && span.chars().skip(1).any(|c| c.is_ascii_uppercase())
                && !NOT_REFUSALS.contains(&span)
            {
                known.0.iter().chain(&known.1).any(|v| v == span)
            } else {
                true
            };
            if !ok {
                out.push(format!("{path}: `{span}` is not a variant of Refusal or ProofError"));
            }
        }
    }
    out
}

fn json_keys(v: &Value, out: &mut std::collections::BTreeSet<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                out.insert(k.clone());
                if let ("name", Some(s)) = (k.as_str(), x.as_str()) {
                    out.insert(s.to_string());
                }
                json_keys(x, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| json_keys(x, out)),
        _ => {}
    }
}
/// Every backticked snake_case name with at least four underscores in the documents is a test
/// defined in a test source, or a key or name of a committed vector file (no stale test names).
fn test_name_differences(docs: &[(&str, &str)], i: &Inputs) -> Vec<String> {
    let mut known = std::collections::BTreeSet::new();
    for text in [&i.v1, &i.preimage, &i.ceremony, &i.add_proof, &i.add_ceremony] {
        if let Ok(v) = serde_json::from_str::<Value>(text) {
            json_keys(&v, &mut known);
        }
    }
    let mut out = Vec::new();
    for (path, text) in docs {
        for span in spans(text) {
            let snake = !span.is_empty() && span.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            if snake && span.matches('_').count() >= 4 {
                let test = TEST_SOURCES.iter().any(|(_, t)| t.contains(&format!("fn {span}(")));
                if !test && !known.contains(span) {
                    out.push(format!("{path}: `{span}` is neither a defined test nor a vector name or key"));
                }
            }
        }
    }
    out
}

/// F10: until Cipher's result file exists, no document claims a completed reproduction or a
/// qualification (case-insensitive phrases).
fn status_differences(docs: &[(&str, &str)], result_exists: bool) -> Vec<String> {
    if result_exists {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (path, text) in docs {
        let lower = text.to_ascii_lowercase();
        for phrase in FORBIDDEN_UNTIL_RESULT {
            if lower.contains(phrase) {
                out.push(format!("{path}: \"{phrase}\" while {RESULT_PATH} does not exist"));
            }
        }
    }
    out
}
fn result_exists() -> bool {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(RESULT_PATH).exists()
}

/// Every difference between the documents and a fresh generation (empty when they agree).
fn differences(schema_doc: &str, inputs_doc: &str, i: &Inputs) -> Vec<String> {
    let mut out = Vec::new();
    compare_block(schema_doc, "constants", gen_constants(i), &mut out);
    compare_block(schema_doc, "challenge-fields", gen_fields(i), &mut out);
    compare_block(schema_doc, "genesis-derivation", gen_genesis(i), &mut out);
    compare_block(schema_doc, "lineage-state", gen_lineage(i), &mut out);
    compare_block(schema_doc, "final-inputs", gen_final_inputs(i), &mut out);
    compare_block(schema_doc, "appendix-a", gen_appendix(i), &mut out);
    compare_block(schema_doc, "frozen-identity", gen_frozen(i, schema_doc, inputs_doc, TOOLING_DOC), &mut out);
    out.extend(status_differences(&[(SCHEMA_PATH, schema_doc), (INPUTS_PATH, inputs_doc), (TOOLING_PATH, TOOLING_DOC)], result_exists()));
    compare_block(inputs_doc, "reproduction-inputs", Ok(gen_inputs(i, schema_doc)), &mut out);
    out.extend(registry_differences(i));
    out.extend(cited_differences(schema_doc, i));
    out.extend(refusal_name_differences(&[(SCHEMA_PATH, schema_doc), (INPUTS_PATH, inputs_doc), (TOOLING_PATH, TOOLING_DOC)], i));
    out.extend(test_name_differences(&[(SCHEMA_PATH, schema_doc), (INPUTS_PATH, inputs_doc), (TOOLING_PATH, TOOLING_DOC)], i));
    out
}
/// Both documents with every block regenerated (prose unchanged).
fn regenerate(schema_doc: &str, inputs_doc: &str, i: &Inputs) -> Gen<(String, String)> {
    let mut schema = schema_doc.to_string();
    schema = replace_block(&schema, "constants", &gen_constants(i)?)?;
    schema = replace_block(&schema, "challenge-fields", &gen_fields(i)?)?;
    schema = replace_block(&schema, "genesis-derivation", &gen_genesis(i)?)?;
    schema = replace_block(&schema, "lineage-state", &gen_lineage(i)?)?;
    schema = replace_block(&schema, "final-inputs", &gen_final_inputs(i)?)?;
    schema = replace_block(&schema, "appendix-a", &gen_appendix(i)?)?;
    let frozen = gen_frozen(i, &schema, inputs_doc, TOOLING_DOC)?;
    schema = replace_block(&schema, "frozen-identity", &frozen)?;
    let inputs = replace_block(inputs_doc, "reproduction-inputs", &gen_inputs(i, &schema))?;
    Ok((schema, inputs))
}

#[test]
fn schema_document_and_reproduction_inputs_equal_a_fresh_export_of_the_source_and_vectors() {
    let i = real();
    let schema_out = std::env::var("BUILD8_TREASURY_SCHEMA_DOC");
    let inputs_out = std::env::var("BUILD8_TREASURY_INPUTS_DOC");
    if schema_out.is_ok() || inputs_out.is_ok() {
        let (schema, inputs) = regenerate(DOC, INPUTS_DOC, &i).expect("regeneration");
        if let Ok(path) = schema_out {
            std::fs::write(path, schema).unwrap();
        }
        if let Ok(path) = inputs_out {
            std::fs::write(path, inputs).unwrap();
        }
    }
    let d = differences(DOC, INPUTS_DOC, &i);
    assert!(d.is_empty(), "the documents differ from a fresh export:\n{}", d.join("\n"));
}

/// Change one ASCII alphanumeric byte at or after `at` to another one (the text stays valid UTF-8).
fn flip(text: &str, at: usize) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let pos = (at..bytes.len()).find(|&p| bytes[p].is_ascii_alphanumeric()).expect("an alphanumeric byte");
    bytes[pos] = match bytes[pos] {
        b'0' => b'1',
        b'z' => b'y',
        b'Z' => b'Y',
        b'9' => b'8',
        other => other + 1,
    };
    String::from_utf8(bytes).unwrap()
}

#[test]
fn one_changed_byte_of_the_document_a_vector_a_constant_or_a_source_line_is_detected() {
    let i = real();
    assert!(differences(DOC, INPUTS_DOC, &i).is_empty(), "baseline must agree");
    let detected = |schema: &str, inputs: &str, i: &Inputs, what: &str| assert!(!differences(schema, inputs, i).is_empty(), "not detected: {what}");
    // One byte of the document: inside each generated block, and in the prose (frozen prefix hash).
    for name in ["constants", "challenge-fields", "genesis-derivation", "lineage-state", "final-inputs", "appendix-a", "frozen-identity"] {
        let (s, e) = block_bounds(DOC, name).unwrap();
        detected(&flip(DOC, s + (e - s) / 2), INPUTS_DOC, &i, name);
    }
    detected(&flip(DOC, DOC.find("## 1. Purpose").unwrap() + 3), INPUTS_DOC, &i, "prose");
    let (s, e) = block_bounds(INPUTS_DOC, "reproduction-inputs").unwrap();
    detected(DOC, &flip(INPUTS_DOC, s + (e - s) / 2), &i, "reproduction inputs");
    // One byte of each vector file.
    let at = |text: &str, key: &str| text.find(key).unwrap() + key.len() + 20;
    detected(DOC, INPUTS_DOC, &Inputs { v1: flip(&i.v1, at(&i.v1, "\"challenge\": \"")), ..i.clone() }, "V1 vectors");
    detected(DOC, INPUTS_DOC, &Inputs { preimage: flip(&i.preimage, at(&i.preimage, "\"mu_shake256_64_hex\": \"")), ..i.clone() }, "preimage vectors");
    detected(DOC, INPUTS_DOC, &Inputs { ceremony: flip(&i.ceremony, at(&i.ceremony, "\"treasury_record_hex\": \"")), ..i.clone() }, "ceremony vectors");
    detected(DOC, INPUTS_DOC, &Inputs { add_proof: flip(&i.add_proof, at(&i.add_proof, "\"ed448_signature_hex\": \"")), ..i.clone() }, "proof additions");
    detected(DOC, INPUTS_DOC, &Inputs { add_ceremony: flip(&i.add_ceremony, at(&i.add_ceremony, "\"canonical_state_root\": \"")), ..i.clone() }, "ceremony additions");
    detected(DOC, INPUTS_DOC, &Inputs { registry: i.registry.replace("\"profile_length\": 35", "\"profile_length\": 36"), ..i.clone() }, "registry");
    // F10: the reproduction-input prose, and a status claim made before the result file exists.
    detected(DOC, &flip(INPUTS_DOC, INPUTS_DOC.find("## 2.").unwrap() + 3), &i, "reproduction-input prose");
    assert!(!status_differences(&[(TOOLING_PATH, "Independent reproduction: completed.")], false).is_empty(), "not detected: status claim");
    assert!(status_differences(&[(TOOLING_PATH, "Independent reproduction: completed.")], true).is_empty());
    // F10: a cited test without #[test] or with #[ignore] is reported.
    assert!(test_attribute_problems("#[test]\nfn t_a_b_c_d() {}\n", "t_a_b_c_d", DOC).is_empty());
    assert!(!test_attribute_problems("/// doc\nfn t_a_b_c_d() {}\n", "t_a_b_c_d", DOC).is_empty(), "not detected: missing #[test]");
    assert!(!test_attribute_problems("#[test]\n#[ignore]\nfn t_a_b_c_d() {}\n", "t_a_b_c_d", DOC).is_empty(), "not detected: #[ignore]");
    assert!(!test_attribute_problems("#![cfg(feature = \"x-unnamed-feature\")]\n#[test]\nfn t_a_b_c_d() {}\n", "t_a_b_c_d", DOC).is_empty(), "not detected: feature");
    // One changed constant.
    detected(DOC, INPUTS_DOC, &Inputs { profile: i.profile.replace("20260722", "20260723"), ..i.clone() }, "profile");
    let mut domain = i.domain.clone();
    domain[7] ^= 0x01;
    detected(DOC, INPUTS_DOC, &Inputs { domain, ..i.clone() }, "domain literal");
    detected(DOC, INPUTS_DOC, &Inputs { network: i.network ^ 1, ..i.clone() }, "network");
    // One changed byte of a pinned source line.
    let mut sources = i.sources.clone();
    let rehearsal = sources.iter_mut().find(|(p, _)| p == "consensus/src/treasury_rehearsal_v1.rs").unwrap();
    rehearsal.1 = rehearsal.1.replace("TREASURY-REHEARSAL-CONTEXT-V1\";", "TREASURY-REHEARSAL-CONTEXT-V2\";");
    detected(DOC, INPUTS_DOC, &Inputs { sources: sources.clone(), ..i.clone() }, "pinned source line");
    let mut sources = i.sources.clone();
    let codec = sources.iter_mut().find(|(p, _)| p == "crypto-v2/src/treasury_proof_v1.rs").unwrap();
    codec.1 = codec.1.replace(".u16(self.suite_id)", ".u32(self.suite_id)");
    detected(DOC, INPUTS_DOC, &Inputs { sources, ..i.clone() }, "encoder type");
    // A refusal name in prose that the code does not have.
    assert!(refusal_name_differences(&[(TOOLING_PATH, TOOLING_DOC)], &i).is_empty());
    let renamed = TOOLING_DOC.replace("`UnauthorizedSuccessor`", "`UnauthorisedSuccessor`");
    assert_ne!(renamed, TOOLING_DOC);
    assert!(!refusal_name_differences(&[(TOOLING_PATH, &renamed)], &i).is_empty(), "not detected: renamed refusal");
    // A test name in prose that no test source defines.
    assert!(test_name_differences(&[(TOOLING_PATH, TOOLING_DOC)], &i).is_empty());
    let stale = TOOLING_DOC.replace("`concurrent_admissions_of_one_nonce_admit_exactly_once`", "`concurrent_admissions_of_one_nonce_admit_exactly_twice`");
    assert_ne!(stale, TOOLING_DOC);
    assert!(!test_name_differences(&[(TOOLING_PATH, &stale)], &i).is_empty(), "not detected: stale test name");
}

// Historical V1/V2 software model only. Superseded unrestricted admission is
// compiled in this test crate, never exported by the shipping library graph.
// Only paths required by the isolated frozen model are supplied here.
pub use mutiny_consensus_v8::{domain_hash, blocks, execution, genesis_inputs, protocol_manifest, treasury_v1, wallet_rotation_v1, dividend_state_v1, NETWORK_ID};
pub use mutiny_consensus_v8::Hash;
#[path = "../src/treasury_rehearsal_v1.rs"]
mod treasury_rehearsal_v1;
#[path = "../src/treasury_admission_v1.rs"]
mod treasury_admission_v1;
