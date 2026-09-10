use std::net::TcpStream;

use ed25519_dalek::SigningKey;
use mutiny_crypto::{epoch_seed, mutiny_argon2id, proof_below_target, ticket_salt, ticket_seed};
use mutiny_p2p::Frame;
use thiserror::Error;

use crate::endpoint::{node_id_from_public_key, AuthenticatedWorkerSession};
use crate::{
    worker_id, PackLError, WorkAssignmentV1, WorkResultCoreV1, WorkResultV1, MSG_WORK_ASSIGNMENT,
    MSG_WORK_RESULT, RESULT_NO_WIN, RESULT_WIN,
};

#[derive(Debug, Error)]
pub enum ReferenceWorkerError {
    #[error("Pack-L error: {0}")]
    PackL(#[from] PackLError),
    #[error("P2P frame error: {0}")]
    Frame(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("assignment/session mismatch: {0}")]
    Session(&'static str),
}

pub fn execute_assignment(
    assignment: &WorkAssignmentV1,
    session: &AuthenticatedWorkerSession,
    expected_node_public_key: &[u8; 32],
    worker_signing_key: &SigningKey,
) -> Result<WorkResultV1, ReferenceWorkerError> {
    assignment.verify_node_signature(expected_node_public_key)?;

    if node_id_from_public_key(expected_node_public_key) != session.node_id {
        return Err(ReferenceWorkerError::Session("paired NodeID mismatch"));
    }
    if assignment.core.session_id != session.session_id {
        return Err(ReferenceWorkerError::Session("SessionID mismatch"));
    }
    if assignment.core.worker_id != session.worker_id {
        return Err(ReferenceWorkerError::Session("WorkerID mismatch"));
    }
    if assignment.core.node_id != session.node_id {
        return Err(ReferenceWorkerError::Session("NodeID mismatch"));
    }

    let worker_public_key = worker_signing_key.verifying_key().to_bytes();
    if worker_public_key != session.worker_public_key {
        return Err(ReferenceWorkerError::Session(
            "worker signing key does not match authenticated session",
        ));
    }
    if worker_id(assignment.core.network_id, &worker_public_key) != session.worker_id {
        return Err(ReferenceWorkerError::Session(
            "worker signing key does not derive authenticated WorkerID",
        ));
    }

    let es = epoch_seed(
        &assignment.core.anchor_entropy,
        assignment.core.target_epoch,
    );
    let seed = ticket_seed(
        &es.0,
        &assignment.core.license_id,
        assignment.core.ticket_index,
    );
    let salt = ticket_salt(
        &es.0,
        &assignment.core.license_id,
        assignment.core.ticket_index,
    );
    let proof = mutiny_argon2id(&seed.0, &salt.0)
        .map_err(|e| ReferenceWorkerError::Crypto(e.to_string()))?;
    let winning = proof_below_target(&proof.0, &assignment.core.target);

    let core = WorkResultCoreV1 {
        network_id: assignment.core.network_id,
        session_id: session.session_id,
        assignment_id: assignment.assignment_id,
        ticket_key: assignment.ticket_key,
        worker_id: session.worker_id,
        result_kind: if winning { RESULT_WIN } else { RESULT_NO_WIN },
        argon2_proof: if winning { proof.0 } else { [0u8; 32] },
    };

    Ok(WorkResultV1::new_signed(core, worker_signing_key)?)
}

pub fn process_one_assignment(
    stream: &mut TcpStream,
    worker_magic: u32,
    session: &AuthenticatedWorkerSession,
    expected_node_public_key: &[u8; 32],
    worker_signing_key: &SigningKey,
) -> Result<WorkResultV1, ReferenceWorkerError> {
    let frame = Frame::read_from(stream, worker_magic)
        .map_err(|e| ReferenceWorkerError::Frame(format!("{e:?}")))?;
    if frame.message_type != MSG_WORK_ASSIGNMENT {
        return Err(ReferenceWorkerError::Session(
            "expected WORK_ASSIGNMENT message",
        ));
    }
    if frame.request_id == 0 {
        return Err(ReferenceWorkerError::Session(
            "WORK_ASSIGNMENT request_id must be nonzero",
        ));
    }

    let assignment = WorkAssignmentV1::decode(&frame.payload)?;
    let result = execute_assignment(
        &assignment,
        session,
        expected_node_public_key,
        worker_signing_key,
    )?;

    let response = Frame::new(
        worker_magic,
        MSG_WORK_RESULT,
        frame.request_id,
        result.encode(),
    )
    .map_err(|e| ReferenceWorkerError::Frame(format!("{e:?}")))?;
    response
        .write_to(stream)
        .map_err(|e| ReferenceWorkerError::Frame(format!("{e:?}")))?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::AuthenticatedWorkerSession;
    use crate::{
        WorkAssignmentCoreV1, WorkAssignmentV1, ALGORITHM_PACK_A_ARGON2ID,
        ALGORITHM_PACK_A_ARGON2ID_V1,
    };

    const NETWORK: u32 = 0x4D55_5403;

    fn worker_key() -> SigningKey {
        SigningKey::from_bytes(&[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ])
    }

    fn node_key() -> SigningKey {
        SigningKey::from_bytes(&[
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
            54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ])
    }

    fn session(worker: &SigningKey, node: &SigningKey) -> AuthenticatedWorkerSession {
        let worker_public_key = worker.verifying_key().to_bytes();
        AuthenticatedWorkerSession {
            worker_id: worker_id(NETWORK, &worker_public_key),
            worker_public_key,
            node_id: node_id_from_public_key(&node.verifying_key().to_bytes()),
            session_id: [0x71; 32],
            request_id: 0x0102_0304_0506_0708,
        }
    }

    fn assignment(worker: &SigningKey, node: &SigningKey, target: [u8; 32]) -> WorkAssignmentV1 {
        let s = session(worker, node);
        WorkAssignmentV1::new_signed(
            WorkAssignmentCoreV1 {
                network_id: NETWORK,
                session_id: s.session_id,
                assignment_sequence: 1,
                worker_id: s.worker_id,
                node_id: s.node_id,
                parent_block_hash: [0x11; 32],
                parent_height: 7,
                target_epoch: 8,
                license_id: [0x22; 32],
                ticket_index: 0,
                work_units_for_epoch: 2,
                eligible_license_count: 1,
                anchor_entropy: [0x80; 32],
                target,
                expires_epoch: 8,
                algorithm_id: ALGORITHM_PACK_A_ARGON2ID,
                algorithm_version: ALGORITHM_PACK_A_ARGON2ID_V1,
            },
            node,
        )
        .unwrap()
    }

    #[test]
    fn zero_target_is_deterministic_no_win_with_zero_wire_proof() {
        let worker = worker_key();
        let node = node_key();
        let s = session(&worker, &node);
        let a = assignment(&worker, &node, [0u8; 32]);
        let r = execute_assignment(&a, &s, &node.verifying_key().to_bytes(), &worker).unwrap();

        assert_eq!(r.core.result_kind, RESULT_NO_WIN);
        assert_eq!(r.core.argon2_proof, [0u8; 32]);
        r.verify_worker_signature(&worker.verifying_key().to_bytes())
            .unwrap();
    }

    #[test]
    fn max_target_executes_exactly_one_pack_a_argon2_ticket() {
        let worker = worker_key();
        let node = node_key();
        let s = session(&worker, &node);
        let a = assignment(&worker, &node, [0xff; 32]);
        let r = execute_assignment(&a, &s, &node.verifying_key().to_bytes(), &worker).unwrap();

        let es = epoch_seed(&a.core.anchor_entropy, a.core.target_epoch);
        let seed = ticket_seed(&es.0, &a.core.license_id, a.core.ticket_index);
        let salt = ticket_salt(&es.0, &a.core.license_id, a.core.ticket_index);
        let proof = mutiny_argon2id(&seed.0, &salt.0).unwrap();
        let winning = proof_below_target(&proof.0, &a.core.target);

        assert_eq!(r.core.result_kind == RESULT_WIN, winning);
        if winning {
            assert_eq!(r.core.argon2_proof, proof.0);
        } else {
            assert_eq!(r.core.argon2_proof, [0u8; 32]);
        }
        r.verify_worker_signature(&worker.verifying_key().to_bytes())
            .unwrap();
    }

    #[test]
    fn wrong_worker_key_cannot_execute_authenticated_assignment() {
        let worker = worker_key();
        let node = node_key();
        let s = session(&worker, &node);
        let a = assignment(&worker, &node, [0xff; 32]);
        let wrong = SigningKey::from_bytes(&[0xEE; 32]);

        assert!(matches!(
            execute_assignment(&a, &s, &node.verifying_key().to_bytes(), &wrong,),
            Err(ReferenceWorkerError::Session(
                "worker signing key does not match authenticated session"
            ))
        ));
    }
}
