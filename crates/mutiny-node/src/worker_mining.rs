use ed25519_dalek::SigningKey;
use mutiny_consensus::{authorized_capacity, derive_target, work_units};
use mutiny_crypto::{epoch_seed, mutiny_argon2id, proof_below_target, ticket_salt, ticket_seed};
use mutiny_protocol::ProtocolOperationV1;
use mutiny_worker::endpoint::AuthenticatedWorkerSession;
use mutiny_worker::ledger::{STATUS_CANDIDATE_WIN, STATUS_COMPLETED_NO_WIN, STATUS_INVALID_WIN};
use mutiny_worker::{worker_id, WorkAssignmentV1, RESULT_NO_WIN, RESULT_WIN};

use crate::worker_service::{
    AssignmentDispatchOutcomeV1, PreparedTicketAuthorityV1, WorkerServiceState,
};
use crate::{
    accept_dev_block_with_signer_and_operations, append_difficulty_result,
    apply_scheduled_license_transitions, candidate_protocol_operations, decode32,
    difficulty_observation_enabled, presence, refresh_current_state_root, DevnetState,
    ACTIVATION_DELAY_EPOCHS,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTicketPlanV1 {
    pub authority: PreparedTicketAuthorityV1,
    pub license_index: usize,
    pub operation_fingerprint: Vec<(u16, [u8; 32])>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizeWorkerResultV1 {
    NoWin,
    AcceptedBlock,
}

fn operation_fingerprint(operations: &[ProtocolOperationV1]) -> Vec<(u16, [u8; 32])> {
    operations
        .iter()
        .map(|op| (op.op_type, op.operation_id().0))
        .collect()
}

fn derive_plan_from_prepared_state(
    state: &DevnetState,
    epoch: u64,
    license_index: usize,
    ticket_index: u16,
    mining_signer: &SigningKey,
) -> Result<(CanonicalTicketPlanV1, Vec<ProtocolOperationV1>), String> {
    if state.format_version >= 10 && state.height == 0 {
        return Err("Build 5.4 requires bootstrap-dev to commit Block 1 before mining".into());
    }
    if epoch <= state.tip_epoch && state.height > 0 {
        return Err("candidate epoch must be greater than tip epoch".into());
    }
    if state.height == 0 && epoch < ACTIVATION_DELAY_EPOCHS {
        return Err("bootstrap licenses are not active yet".into());
    }

    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    if !license.is_eligible(epoch) {
        return Err(
            "selected encrypted-custody Mining License is not base-eligible in the candidate epoch"
                .into(),
        );
    }
    if mining_signer.verifying_key().to_bytes() != decode32(&license.mining_public_key)? {
        return Err(
            "provided signing key does not match the current on-chain mining authority".into(),
        );
    }

    let license_id = decode32(&license.license_id)?;
    let operations = candidate_protocol_operations(state, epoch, license_index, mining_signer)?;
    let candidate_eligible =
        presence::candidate_eligible_count(state, epoch, &license_id, &operations)?;
    if candidate_eligible == 0 {
        return Err("candidate participation-eligible count is zero".into());
    }

    let w = work_units(candidate_eligible);
    if ticket_index >= w {
        return Err("ticket index is outside the frozen Pack-A work budget".into());
    }
    let target = derive_target(
        authorized_capacity(candidate_eligible),
        state.difficulty_correction_q32,
    )
    .map_err(|e| e.to_string())?;

    let anchor_entropy = if state.height == 0 {
        decode32(&state.genesis_hash)?
    } else {
        mutiny_crypto::anchor_entropy(
            state.anchor_epoch,
            &decode32(&state.anchor_license_id)?,
            state.anchor_ticket_index,
            &decode32(&state.anchor_argon2_proof)?,
        )
        .0
    };

    let plan = CanonicalTicketPlanV1 {
        authority: PreparedTicketAuthorityV1 {
            parent_block_hash: decode32(&state.tip_hash)?,
            parent_height: state.height,
            target_epoch: epoch,
            license_id,
            ticket_index,
            work_units_for_epoch: w,
            eligible_license_count: candidate_eligible,
            difficulty_c_q32: state.difficulty_correction_q32,
            anchor_entropy,
            target,
        },
        license_index,
        operation_fingerprint: operation_fingerprint(&operations),
    };

    Ok((plan, operations))
}

/// Prepare one exact Pack-A ticket from the current canonical branch.
///
/// This mirrors the pre-ticket portion of `mine_epoch_with_signer`: skipped
/// candidate epochs are committed as empty observations on a clone, scheduled
/// transitions are applied, encrypted mining custody is checked against the
/// current on-chain mining public key, Pack-K candidate operations are built,
/// candidate eligibility is derived, then W_E/target/anchor are frozen into
/// the returned Pack-L authority.
///
/// State mutation is committed only after all preparation checks succeed.
pub fn prepare_canonical_ticket(
    state: &mut DevnetState,
    epoch: u64,
    license_index: usize,
    ticket_index: u16,
    mining_signer: &SigningKey,
) -> Result<CanonicalTicketPlanV1, String> {
    let mut prepared = state.clone();

    if prepared.format_version >= 10 && prepared.height == 0 {
        return Err("Build 5.4 requires bootstrap-dev to commit Block 1 before mining".into());
    }
    if epoch <= prepared.tip_epoch && prepared.height > 0 {
        return Err("candidate epoch must be greater than tip epoch".into());
    }
    if prepared.height == 0 && epoch < ACTIVATION_DELAY_EPOCHS {
        return Err("bootstrap licenses are not active yet".into());
    }

    if prepared.height > 0 {
        while prepared.tip_epoch.saturating_add(1) < epoch {
            let skipped_epoch = prepared.tip_epoch.saturating_add(1);
            prepared.tip_epoch = skipped_epoch;
            apply_scheduled_license_transitions(&mut prepared, skipped_epoch)?;
            if difficulty_observation_enabled(&prepared, skipped_epoch) {
                append_difficulty_result(&mut prepared, false)?;
            }
            refresh_current_state_root(&mut prepared)?;
        }
    }

    apply_scheduled_license_transitions(&mut prepared, epoch)?;
    let (plan, _) = derive_plan_from_prepared_state(
        &prepared,
        epoch,
        license_index,
        ticket_index,
        mining_signer,
    )?;

    *state = prepared;
    Ok(plan)
}

fn assignment_matches_plan(
    plan: &CanonicalTicketPlanV1,
    assignment: &WorkAssignmentV1,
    session: &AuthenticatedWorkerSession,
) -> bool {
    let c = &assignment.core;
    c.session_id == session.session_id
        && c.worker_id == session.worker_id
        && c.node_id == session.node_id
        && c.parent_block_hash == plan.authority.parent_block_hash
        && c.parent_height == plan.authority.parent_height
        && c.target_epoch == plan.authority.target_epoch
        && c.license_id == plan.authority.license_id
        && c.ticket_index == plan.authority.ticket_index
        && c.work_units_for_epoch == plan.authority.work_units_for_epoch
        && c.eligible_license_count == plan.authority.eligible_license_count
        && c.anchor_entropy == plan.authority.anchor_entropy
        && c.target == plan.authority.target
        && c.expires_epoch == plan.authority.target_epoch
        && assignment.ticket_key == assignment.core.ticket_key()
        && assignment.assignment_id == assignment.core.assignment_id()
}

fn validate_result_binding(
    outcome: &AssignmentDispatchOutcomeV1,
    session: &AuthenticatedWorkerSession,
) -> Result<(), String> {
    if !assignment_matches_plan(
        &CanonicalTicketPlanV1 {
            authority: PreparedTicketAuthorityV1 {
                parent_block_hash: outcome.assignment.core.parent_block_hash,
                parent_height: outcome.assignment.core.parent_height,
                target_epoch: outcome.assignment.core.target_epoch,
                license_id: outcome.assignment.core.license_id,
                ticket_index: outcome.assignment.core.ticket_index,
                work_units_for_epoch: outcome.assignment.core.work_units_for_epoch,
                eligible_license_count: outcome.assignment.core.eligible_license_count,
                difficulty_c_q32: 0,
                anchor_entropy: outcome.assignment.core.anchor_entropy,
                target: outcome.assignment.core.target,
            },
            license_index: 0,
            operation_fingerprint: Vec::new(),
        },
        &outcome.assignment,
        session,
    ) {
        return Err("assignment/session binding mismatch".into());
    }

    let result = &outcome.result;
    if result.core.network_id != outcome.assignment.core.network_id
        || result.core.session_id != session.session_id
        || result.core.assignment_id != outcome.assignment.assignment_id
        || result.core.ticket_key != outcome.assignment.ticket_key
        || result.core.worker_id != session.worker_id
    {
        return Err("WORK_RESULT binding mismatch".into());
    }

    if worker_id(
        outcome.assignment.core.network_id,
        &session.worker_public_key,
    ) != session.worker_id
    {
        return Err("authenticated worker public key no longer derives WorkerID".into());
    }

    result
        .verify_worker_signature(&session.worker_public_key)
        .map_err(|e| e.to_string())
}

fn ledger_status(
    worker_state: &WorkerServiceState,
    assignment_id: &[u8; 32],
) -> Result<u8, String> {
    worker_state
        .ledger
        .records
        .iter()
        .find(|r| &r.assignment_id == assignment_id)
        .map(|r| r.status)
        .ok_or_else(|| "assignment is absent from persistent worker budget ledger".into())
}

fn mark_invalid_win(
    worker_state: &mut WorkerServiceState,
    assignment_id: &[u8; 32],
) -> Result<(), String> {
    worker_state
        .ledger
        .update_status_and_persist(
            &worker_state.paths.ledger,
            assignment_id,
            STATUS_INVALID_WIN,
        )
        .map_err(|e| e.to_string())
}

/// Revalidate one worker result against the still-current canonical branch.
///
/// NO_WIN never causes node-side Argon2 recomputation.
/// WIN is independently recomputed exactly once while ledger status remains
/// CANDIDATE_WIN. A false WIN is durably changed to INVALID_WIN before return,
/// so replay of that AssignmentID is rejected before another Argon2 call.
/// A valid WIN is handed only to the existing encrypted-custody block signer.
pub fn finalize_worker_result(
    state: &mut DevnetState,
    worker_state: &mut WorkerServiceState,
    session: &AuthenticatedWorkerSession,
    mining_signer: &SigningKey,
    plan: &CanonicalTicketPlanV1,
    outcome: &AssignmentDispatchOutcomeV1,
) -> Result<FinalizeWorkerResultV1, String> {
    validate_result_binding(outcome, session)?;
    if !assignment_matches_plan(plan, &outcome.assignment, session) {
        return Err("WORK_ASSIGNMENT no longer matches canonical prepared ticket".into());
    }

    let status = ledger_status(worker_state, &outcome.assignment.assignment_id)?;
    match outcome.result.core.result_kind {
        RESULT_NO_WIN => {
            if status != STATUS_COMPLETED_NO_WIN {
                return Err("NO_WIN result does not have COMPLETED_NO_WIN ledger status".into());
            }
            return Ok(FinalizeWorkerResultV1::NoWin);
        }
        RESULT_WIN => {
            if status == STATUS_INVALID_WIN {
                return Err("candidate WIN already invalidated".into());
            }
            if status != STATUS_CANDIDATE_WIN {
                return Err("WIN result does not have CANDIDATE_WIN ledger status".into());
            }
        }
        _ => return Err("unknown WORK_RESULT result kind".into()),
    }

    // Staleness and authority are checked before the expensive Argon2 recomputation.
    if state.height != plan.authority.parent_height
        || decode32(&state.tip_hash)? != plan.authority.parent_block_hash
    {
        return Err("stale worker result: canonical parent changed".into());
    }

    let license = state
        .licenses
        .get(plan.license_index)
        .ok_or("license number out of range")?;
    if !license.is_eligible(plan.authority.target_epoch) {
        return Err("stale worker result: Mining License is no longer base-eligible".into());
    }
    if mining_signer.verifying_key().to_bytes() != decode32(&license.mining_public_key)? {
        return Err("stale worker result: encrypted mining custody no longer matches".into());
    }

    let (fresh_plan, fresh_operations) = derive_plan_from_prepared_state(
        state,
        plan.authority.target_epoch,
        plan.license_index,
        plan.authority.ticket_index,
        mining_signer,
    )?;
    if fresh_plan != *plan {
        return Err("stale worker result: canonical ticket authority changed".into());
    }

    let es = epoch_seed(&plan.authority.anchor_entropy, plan.authority.target_epoch);
    let seed = ticket_seed(
        &es.0,
        &plan.authority.license_id,
        plan.authority.ticket_index,
    );
    let salt = ticket_salt(
        &es.0,
        &plan.authority.license_id,
        plan.authority.ticket_index,
    );
    let proof = mutiny_argon2id(&seed.0, &salt.0).map_err(|e| e.to_string())?;

    if proof.0 != outcome.result.core.argon2_proof
        || !proof_below_target(&proof.0, &plan.authority.target)
    {
        mark_invalid_win(worker_state, &outcome.assignment.assignment_id)?;
        return Err("false WIN proof rejected after independent node recomputation".into());
    }

    accept_dev_block_with_signer_and_operations(
        state,
        plan.authority.target_epoch,
        plan.license_index,
        plan.authority.ticket_index,
        proof.0,
        plan.authority.target,
        Some(mining_signer),
        fresh_operations,
    )?;

    Ok(FinalizeWorkerResultV1::AcceptedBlock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, SigningKey};
    use mutiny_crypto::{block_signing_digest, domains, sha256_domain};
    use mutiny_protocol::{OP_MINING_PRESENCE, PACK_K_DEVNET_ACTIVATION_EPOCH};
    use mutiny_worker::endpoint::node_id_from_public_key;
    use mutiny_worker::ledger::{
        LedgerRecordV1, STATUS_CANDIDATE_WIN, STATUS_COMPLETED_NO_WIN, STATUS_RESERVED,
    };
    use mutiny_worker::{
        WorkAssignmentCoreV1, WorkAssignmentV1, WorkResultCoreV1, WorkResultV1,
        ALGORITHM_PACK_A_ARGON2ID, ALGORITHM_PACK_A_ARGON2ID_V1, RESULT_NO_WIN, RESULT_WIN,
        WORKER_MAGIC_DEVNET,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{
        init_devnet, load_state, refresh_current_state_root, DEVNET_GENESIS_ID_HEX,
        DEVNET_NETWORK_ID, LICENSE_STATUS_ACTIVE, LICENSE_STATUS_REVOKED,
    };

    fn temp_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mutiny-worker-mining-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn mining_key() -> SigningKey {
        SigningKey::from_bytes(&[0xA5; 32])
    }

    fn worker_key() -> SigningKey {
        SigningKey::from_bytes(&[0xB6; 32])
    }

    fn node_key() -> SigningKey {
        SigningKey::from_bytes(&[0xC7; 32])
    }

    fn one_license_state(label: &str) -> (PathBuf, DevnetState, SigningKey) {
        let dir = temp_dir(label);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        let mining = mining_key();

        for (i, license) in state.licenses.iter_mut().enumerate() {
            if i == 0 {
                license.status = LICENSE_STATUS_ACTIVE;
                license.activation_epoch = 0;
                license.suspended_until_epoch = 0;
                license.revocation_epoch = 0;
                license.mining_public_key = hex::encode(mining.verifying_key().to_bytes());
            } else {
                // Canonical permanent-revocation fixture:
                // revoked LicenseRecordV1 strike_weight is frozen/capped at 16.
                license.status = LICENSE_STATUS_REVOKED;
                license.strike_weight = 16;
                license.revocation_epoch = 1;
            }
        }

        // For L=1, A=2. C=2.0 makes the derived target saturate to max,
        // yielding a deterministic practical WIN for the single assigned ticket.
        state.difficulty_correction_q32 = 2u64 << 32;
        refresh_current_state_root(&mut state).unwrap();
        (dir, state, mining)
    }

    fn session(worker: &SigningKey, node: &SigningKey) -> AuthenticatedWorkerSession {
        let worker_public_key = worker.verifying_key().to_bytes();
        AuthenticatedWorkerSession {
            worker_id: worker_id(DEVNET_NETWORK_ID, &worker_public_key),
            worker_public_key,
            node_id: node_id_from_public_key(&node.verifying_key().to_bytes()),
            session_id: [0x71; 32],
            request_id: 0x0102_0304_0506_0708,
        }
    }

    fn assignment_for_plan(
        plan: &CanonicalTicketPlanV1,
        session: &AuthenticatedWorkerSession,
        node: &SigningKey,
    ) -> WorkAssignmentV1 {
        WorkAssignmentV1::new_signed(
            WorkAssignmentCoreV1 {
                network_id: DEVNET_NETWORK_ID,
                session_id: session.session_id,
                assignment_sequence: 1,
                worker_id: session.worker_id,
                node_id: session.node_id,
                parent_block_hash: plan.authority.parent_block_hash,
                parent_height: plan.authority.parent_height,
                target_epoch: plan.authority.target_epoch,
                license_id: plan.authority.license_id,
                ticket_index: plan.authority.ticket_index,
                work_units_for_epoch: plan.authority.work_units_for_epoch,
                eligible_license_count: plan.authority.eligible_license_count,
                anchor_entropy: plan.authority.anchor_entropy,
                target: plan.authority.target,
                expires_epoch: plan.authority.target_epoch,
                algorithm_id: ALGORITHM_PACK_A_ARGON2ID,
                algorithm_version: ALGORITHM_PACK_A_ARGON2ID_V1,
            },
            node,
        )
        .unwrap()
    }

    fn worker_state_with_status(
        dir: &std::path::Path,
        assignment: &WorkAssignmentV1,
        session: &AuthenticatedWorkerSession,
        status: u8,
    ) -> WorkerServiceState {
        let mut state =
            WorkerServiceState::open(dir, DEVNET_NETWORK_ID, WORKER_MAGIC_DEVNET).unwrap();
        let record = LedgerRecordV1 {
            ticket_key: assignment.ticket_key,
            parent_block_hash: assignment.core.parent_block_hash,
            target_epoch: assignment.core.target_epoch,
            license_id: assignment.core.license_id,
            ticket_index: assignment.core.ticket_index,
            work_units_for_epoch: assignment.core.work_units_for_epoch,
            worker_id: session.worker_id,
            session_id: session.session_id,
            assignment_id: assignment.assignment_id,
            assignment_sequence: assignment.core.assignment_sequence,
            status: STATUS_RESERVED,
        };
        assert!(state
            .ledger
            .reserve_and_persist(&state.paths.ledger, record)
            .unwrap());
        state
            .ledger
            .update_status_and_persist(&state.paths.ledger, &assignment.assignment_id, status)
            .unwrap();
        state
    }

    #[test]
    fn canonical_plan_uses_pack_k_candidate_self_presence_and_frozen_target_math() {
        let (dir, mut state, mining) = one_license_state("pack-k-plan");

        state.genesis_hash = DEVNET_GENESIS_ID_HEX.into();
        state.tip_hash = DEVNET_GENESIS_ID_HEX.into();
        state.height = 1;
        state.tip_epoch = PACK_K_DEVNET_ACTIVATION_EPOCH - 1;
        state.anchor_epoch = 0;
        state.anchor_license_id = hex::encode([0u8; 32]);
        state.anchor_ticket_index = 0;
        state.anchor_argon2_proof = state.genesis_hash.clone();

        let plan =
            prepare_canonical_ticket(&mut state, PACK_K_DEVNET_ACTIVATION_EPOCH, 0, 0, &mining)
                .unwrap();

        assert_eq!(plan.authority.eligible_license_count, 1);
        assert_eq!(plan.authority.work_units_for_epoch, work_units(1));
        assert_eq!(
            plan.authority.target,
            derive_target(authorized_capacity(1), 2u64 << 32).unwrap()
        );
        assert!(plan
            .operation_fingerprint
            .iter()
            .any(|(op_type, _)| *op_type == OP_MINING_PRESENCE));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn valid_worker_win_is_recomputed_then_signed_only_by_mining_custody() {
        let (dir, mut state, mining) = one_license_state("valid-win");
        let epoch = ACTIVATION_DELAY_EPOCHS;
        let plan = prepare_canonical_ticket(&mut state, epoch, 0, 0, &mining).unwrap();
        assert_eq!(plan.authority.target, [0xff; 32]);

        let worker = worker_key();
        let node = node_key();
        let session = session(&worker, &node);
        let assignment = assignment_for_plan(&plan, &session, &node);
        let result = mutiny_worker::reference::execute_assignment(
            &assignment,
            &session,
            &node.verifying_key().to_bytes(),
            &worker,
        )
        .unwrap();
        assert_eq!(result.core.result_kind, RESULT_WIN);

        let outcome = AssignmentDispatchOutcomeV1 {
            assignment: assignment.clone(),
            result,
            new_unique_ticket: true,
        };
        let worker_dir = dir.join("worker-ledger-valid");
        let mut worker_state =
            worker_state_with_status(&worker_dir, &assignment, &session, STATUS_CANDIDATE_WIN);

        let before_height = state.height;
        let finalized = finalize_worker_result(
            &mut state,
            &mut worker_state,
            &session,
            &mining,
            &plan,
            &outcome,
        )
        .unwrap();
        assert_eq!(finalized, FinalizeWorkerResultV1::AcceptedBlock);
        assert_eq!(state.height, before_height + 1);

        let block = state.blocks.last().unwrap();
        let header = hex::decode(&block.header).unwrap();
        assert_eq!(header.len(), 272);
        let core: [u8; 208] = header[..208].try_into().unwrap();
        let sig: [u8; 64] = header[208..].try_into().unwrap();
        let digest = block_signing_digest(&core);
        mining
            .verifying_key()
            .verify_strict(&digest.0, &Signature::from_bytes(&sig))
            .unwrap();

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn false_win_is_invalidated_once_and_replay_is_rejected_before_recompute() {
        let (dir, mut state, mining) = one_license_state("false-win");
        let epoch = ACTIVATION_DELAY_EPOCHS;
        let plan = prepare_canonical_ticket(&mut state, epoch, 0, 0, &mining).unwrap();

        let worker = worker_key();
        let node = node_key();
        let session = session(&worker, &node);
        let assignment = assignment_for_plan(&plan, &session, &node);
        let result = WorkResultV1::new_signed(
            WorkResultCoreV1 {
                network_id: DEVNET_NETWORK_ID,
                session_id: session.session_id,
                assignment_id: assignment.assignment_id,
                ticket_key: assignment.ticket_key,
                worker_id: session.worker_id,
                result_kind: RESULT_WIN,
                argon2_proof: [0xAA; 32],
            },
            &worker,
        )
        .unwrap();
        let outcome = AssignmentDispatchOutcomeV1 {
            assignment: assignment.clone(),
            result,
            new_unique_ticket: true,
        };
        let worker_dir = dir.join("worker-ledger-false");
        let mut worker_state =
            worker_state_with_status(&worker_dir, &assignment, &session, STATUS_CANDIDATE_WIN);

        let before_height = state.height;
        let first = finalize_worker_result(
            &mut state,
            &mut worker_state,
            &session,
            &mining,
            &plan,
            &outcome,
        )
        .unwrap_err();
        assert!(first.contains("false WIN proof rejected"));
        assert_eq!(state.height, before_height);
        assert_eq!(
            ledger_status(&worker_state, &assignment.assignment_id).unwrap(),
            STATUS_INVALID_WIN
        );

        let second = finalize_worker_result(
            &mut state,
            &mut worker_state,
            &session,
            &mining,
            &plan,
            &outcome,
        )
        .unwrap_err();
        assert_eq!(second, "candidate WIN already invalidated");
        assert_eq!(state.height, before_height);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn signed_no_win_forfeits_ticket_without_node_argon2_or_block_authority() {
        let (dir, mut state, mining) = one_license_state("no-win");
        let epoch = ACTIVATION_DELAY_EPOCHS;
        let plan = prepare_canonical_ticket(&mut state, epoch, 0, 0, &mining).unwrap();

        let worker = worker_key();
        let node = node_key();
        let session = session(&worker, &node);
        let assignment = assignment_for_plan(&plan, &session, &node);
        let result = WorkResultV1::new_signed(
            WorkResultCoreV1 {
                network_id: DEVNET_NETWORK_ID,
                session_id: session.session_id,
                assignment_id: assignment.assignment_id,
                ticket_key: assignment.ticket_key,
                worker_id: session.worker_id,
                result_kind: RESULT_NO_WIN,
                argon2_proof: [0u8; 32],
            },
            &worker,
        )
        .unwrap();
        let outcome = AssignmentDispatchOutcomeV1 {
            assignment: assignment.clone(),
            result,
            new_unique_ticket: true,
        };
        let worker_dir = dir.join("worker-ledger-nowin");
        let mut worker_state =
            worker_state_with_status(&worker_dir, &assignment, &session, STATUS_COMPLETED_NO_WIN);

        let before_height = state.height;
        let finalized = finalize_worker_result(
            &mut state,
            &mut worker_state,
            &session,
            &mining,
            &plan,
            &outcome,
        )
        .unwrap();
        assert_eq!(finalized, FinalizeWorkerResultV1::NoWin);
        assert_eq!(state.height, before_height);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_parent_rejects_candidate_win_before_block_acceptance() {
        let (dir, mut state, mining) = one_license_state("stale");
        let epoch = ACTIVATION_DELAY_EPOCHS;
        let plan = prepare_canonical_ticket(&mut state, epoch, 0, 0, &mining).unwrap();

        let worker = worker_key();
        let node = node_key();
        let session = session(&worker, &node);
        let assignment = assignment_for_plan(&plan, &session, &node);
        let result = mutiny_worker::reference::execute_assignment(
            &assignment,
            &session,
            &node.verifying_key().to_bytes(),
            &worker,
        )
        .unwrap();
        let outcome = AssignmentDispatchOutcomeV1 {
            assignment: assignment.clone(),
            result,
            new_unique_ticket: true,
        };
        let worker_dir = dir.join("worker-ledger-stale");
        let mut worker_state =
            worker_state_with_status(&worker_dir, &assignment, &session, STATUS_CANDIDATE_WIN);

        state.tip_hash = hex::encode(sha256_domain(domains::GENESIS_ID, &[b"stale-parent"]).0);
        let before_height = state.height;
        let err = finalize_worker_result(
            &mut state,
            &mut worker_state,
            &session,
            &mining,
            &plan,
            &outcome,
        )
        .unwrap_err();
        assert_eq!(err, "stale worker result: canonical parent changed");
        assert_eq!(state.height, before_height);
        assert_eq!(
            ledger_status(&worker_state, &assignment.assignment_id).unwrap(),
            STATUS_CANDIDATE_WIN
        );

        let _ = fs::remove_dir_all(dir);
    }
}
