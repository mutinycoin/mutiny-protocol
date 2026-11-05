// Unit tests include the shared TEST-VALUE simulator (consensus/tests/support/software_tpm.rs),
// which names this crate by its package name. Test builds only.
#[cfg(test)]
extern crate self as mutiny_consensus_v8;
// The simulator is declared ONCE, here at file scope, for every unit-test module that uses it
// (`use crate::software_tpm;`). A #[path] inside an inline `mod tests { .. }` resolves from
// src/<file stem>/tests/, a directory that does not exist: Linux fails with ENOENT where Windows
// collapses the `..` lexically (build/check-source-paths.pl). Test builds only.
#[cfg(test)]
#[path = "../tests/support/software_tpm.rs"]
pub(crate) mod software_tpm;
pub mod activation;
pub mod activation_attestation_v1;
pub mod assembler_v2;
pub mod admission;
pub mod admission_v2;
pub mod admission_public_v3;
pub mod block_envelope;
pub mod block_envelope_v2;
pub mod blocks;
pub mod body_capacity_v3;
pub mod bond_ops;
pub mod bond_ops_v2;
pub mod bonds;
pub mod bonds_v2;
pub mod penalties_v2;
pub mod canonical_store;
pub mod certificates;
pub mod continuity_v2;
pub mod votes_v2;
pub mod counter_voter_v2;
pub mod continuity_execution;
pub mod coordinator;
pub mod equivocation;
pub mod equivocation_v2;
mod error;
pub mod execution;
mod execution_v2;
pub mod finality;
pub mod finality_v2;
pub mod canonical_store_v2;
pub mod firmware_update;
pub mod freshness;
pub mod genesis;
pub mod genesis_inputs;
pub mod join;
pub mod journal;
pub mod licenses;
pub mod license_assignment_v2;
pub mod license_book_v2;
pub mod liveness;
pub mod membership;
pub mod mempool;
pub mod mempool_v2;
pub mod observations;
pub mod participation;
pub mod pow;
pub mod work_authority_v2;
pub mod proposer;
pub mod protocol_manifest;
pub mod recovery;
pub mod recovery_material;
pub mod reputation;
pub mod rollback;
pub mod rotation;
pub mod state_proof;
pub mod settlement;
mod state_records;
pub mod state_tree;
pub mod provenance;
pub mod tpm;
pub mod transactions;
pub mod transactions_v2;
pub mod wallet_rotation_v1;
pub mod wallet_authority_v1;
pub mod hybrid_transaction_v2;
// F3 (Architect, 2 Oct 2026): v0 `DurableVoter` signing is retired from production. It has a
// separate journal anti-rollback gap and different clock/replay semantics from the supported
// counter-protected signers (`counter_voter`, `counter_voter_v2`). It remains compiled only for its
// explicit historical test fixture under the `legacy-v0-test-fixtures` feature (never default,
// never enabled by the node crate).
#[cfg(feature = "legacy-v0-test-fixtures")]
pub mod voter;
/// True only when the test-only v0 `DurableVoter` fixture module is compiled. Production
/// executables assert this is false (node/src/lib.rs).
pub const LEGACY_V0_TEST_FIXTURES_ENABLED: bool = cfg!(feature = "legacy-v0-test-fixtures");
/// True only when the dividend/License-status test fixture setters are compiled. They are not
/// reachable from block execution, but production executables still assert this is false.
pub const DIVIDEND_TEST_FIXTURES_ENABLED: bool = cfg!(feature = "dividend-test-fixtures");
pub mod voter_actor;
pub mod votes;
pub mod work_issuance;
pub mod worker_session;
pub use error::{Error, Result};
pub const NETWORK_ID: u32 = 0x4d555401;
pub type Hash = [u8; 32];
pub fn domain_hash(domain: &[u8], body: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update([0]);
    h.update(body);
    h.finalize().into()
}
pub mod anchors;
pub mod continuity_keys_v2;
pub mod continuity_exit_v2;
pub mod node_admission_v2;
pub mod membership_v2;
pub mod admission_policy_v2;
pub mod join_v2;
pub mod continuity_key_rotate_v2;
pub mod hardware_rotate_v2;
pub mod recovery_authority_v2;
pub mod retired_continuity_v2;
pub mod node_key_rotate_v2;
pub mod node_key_history_v2;
pub mod node_authority_v2;
pub mod continuity_lifecycle_v2;
pub mod bft;
pub mod bft_store;
pub mod counter_store;
pub mod counter_voter;
pub mod storage_budget;

mod store_schema_v2;
pub mod voter_actor_v2;

pub mod counter_store_v2;
pub mod liveness_v2;

pub mod recovery_genesis_input_v2;
pub mod recovery_loss_v2;
pub mod recovery_replacement_v2;
pub mod recovery_witness_v2;
pub mod recovery_history_index_v2;
pub mod recovery_history_v2;
pub mod recovery_public_v3;
pub mod recovery_transition_v2;
mod recovery_store_v2;
mod parent_context_v2;

pub mod evidence_history_v2;

pub mod trading_v1;

mod trading_host_v1;
pub mod observation_receipt_v2;
pub mod native_units_v1;
pub mod dividends_v1;
pub mod treasury_v1;
pub mod treasury_lineage_v3;
pub mod treasury_rehearsal_v3;
pub mod treasury_admission_v3;
pub mod treasury_continuity_v1;
pub mod treasury_continuity_provider_v1;
pub mod treasury_continuity_owner_v1;
pub mod license_status_v1;
pub mod dividend_state_v1;
pub mod dividend_claim_v1;
pub mod vote_clock_v1;
pub mod holdover_clock_v1;
pub mod op_envelope_v1;
pub mod genesis_v2;
// Candidate 3, Lane A2 (Order of 4 Oct 2026, decisions A4, A5, A7, A8, A11; PROPOSED / UNFROZEN).
pub mod endorsement_identity;
pub mod endorsement_dependencies_v1;
pub mod endorsement_revocation_v1;
pub mod ek_chain;
pub mod x509_syntax;
pub mod attestation_witness;
pub mod test_value_root_alias_v1;
pub mod admission_evidence_v1;
pub mod pcr_profiles;
pub mod admission_scope;
pub mod bond_create_v3;
pub mod funded_rotation_v2;
pub mod trading_offer_v2;
pub mod operation_index_v2;
pub mod submission_v1;
pub mod submission_pool_v1;
mod submission_archive_protection;
mod submission_archive_lookup;
