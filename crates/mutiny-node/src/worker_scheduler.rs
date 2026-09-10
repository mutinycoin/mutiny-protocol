use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use mutiny_p2p::Frame;
use mutiny_worker::endpoint::AuthenticatedWorkerSession;
use mutiny_worker::ledger::{
    LedgerRecordV1, STATUS_CANCELLED, STATUS_CANDIDATE_WIN, STATUS_RESERVED, STATUS_SENT,
};
use mutiny_worker::{ticket_key, WorkCancelCoreV1, WorkCancelV1, MSG_WORK_CANCEL};

use crate::worker_mining::CanonicalTicketPlanV1;
use crate::worker_service::WorkerServiceState;

const AUTHZ_MAX_BYTES: u64 = 1_048_576;
const AUTHZ_MAX_PAIRS: usize = 4096;

pub const CANCEL_CANONICAL_PARENT_CHANGED: u8 = 0x01;
pub const CANCEL_TARGET_EPOCH_EXPIRED: u8 = 0x02;
pub const CANCEL_LICENSE_NO_LONGER_ELIGIBLE: u8 = 0x03;
pub const CANCEL_WORKER_AUTHORIZATION_REVOKED: u8 = 0x04;
pub const CANCEL_MINING_CUSTODY_LOST: u8 = 0x05;
pub const CANCEL_NODE_SHUTDOWN: u8 = 0x06;
pub const CANCEL_ADMINISTRATIVE: u8 = 0x07;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerLicenseAuthorizationsV1 {
    by_worker: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
}

impl WorkerLicenseAuthorizationsV1 {
    pub fn empty() -> Self {
        Self {
            by_worker: BTreeMap::new(),
        }
    }

    pub fn is_authorized(&self, worker_id: &[u8; 32], license_id: &[u8; 32]) -> bool {
        self.by_worker
            .get(worker_id)
            .is_some_and(|licenses| licenses.contains(license_id))
    }

    pub fn license_count_for(&self, worker_id: &[u8; 32]) -> usize {
        self.by_worker.get(worker_id).map_or(0, BTreeSet::len)
    }

    pub fn pair_count(&self) -> usize {
        self.by_worker.values().map(BTreeSet::len).sum()
    }
}

pub fn worker_license_authorization_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join("worker")
        .join("authorized-worker-licenses-v1.txt")
}

fn decode_hex32(text: &str, label: &'static str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{label} must be exactly 64 hexadecimal characters"));
    }
    let bytes = hex::decode(text).map_err(|_| format!("{label} contains invalid hex"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{label} must decode to 32 bytes"))
}

/// Assignment authorization file:
///
///     <WorkerID-64hex> <LicenseID-64hex>
///
/// Blank lines and comments are ignored. The same LicenseID may be mapped to
/// multiple WorkerIDs for fault tolerance, but duplicate WorkerID/LicenseID
/// pairs fail closed. Every mapped WorkerID must already be present in the
/// Candidate-4A authentication allowlist.
pub fn load_worker_license_authorizations(
    path: &Path,
    handshake_allowed_workers: &BTreeSet<[u8; 32]>,
) -> Result<WorkerLicenseAuthorizationsV1, String> {
    let meta = fs::metadata(path)
        .map_err(|e| format!("read worker-license authorization metadata: {e}"))?;
    if meta.len() > AUTHZ_MAX_BYTES {
        return Err("worker-license authorization file exceeds 1 MiB".into());
    }

    let text = fs::read_to_string(path)
        .map_err(|e| format!("read worker-license authorization file: {e}"))?;
    let mut out = WorkerLicenseAuthorizationsV1::empty();
    let mut pairs = BTreeSet::new();

    for (line_no, raw) in text.lines().enumerate() {
        let body = raw.split('#').next().unwrap_or("").trim();
        if body.is_empty() {
            continue;
        }
        let parts = body.split_whitespace().collect::<Vec<_>>();
        if parts.len() != 2 {
            return Err(format!(
                "worker-license authorization line {} must contain exactly WorkerID and LicenseID",
                line_no + 1
            ));
        }
        if pairs.len() >= AUTHZ_MAX_PAIRS {
            return Err("worker-license authorization file exceeds 4096 pairs".into());
        }

        let worker_id = decode_hex32(parts[0], "WorkerID")?;
        let license_id = decode_hex32(parts[1], "LicenseID")?;
        if !handshake_allowed_workers.contains(&worker_id) {
            return Err(format!(
                "worker-license authorization line {} references WorkerID absent from authorized-workers-v1.txt",
                line_no + 1
            ));
        }
        if !pairs.insert((worker_id, license_id)) {
            return Err(format!(
                "duplicate WorkerID/LicenseID authorization pair on line {}",
                line_no + 1
            ));
        }
        out.by_worker
            .entry(worker_id)
            .or_default()
            .insert(license_id);
    }

    Ok(out)
}

pub fn load_runtime_worker_license_authorizations(
    data_dir: &Path,
    worker_state: &WorkerServiceState,
) -> Result<WorkerLicenseAuthorizationsV1, String> {
    let path = worker_license_authorization_path(data_dir);
    if !path.exists() {
        return Err("authorized-worker-licenses-v1.txt is required before work assignment".into());
    }
    let authz = load_worker_license_authorizations(&path, &worker_state.allowed_workers)?;
    if authz.pair_count() == 0 {
        return Err("authorized-worker-licenses-v1.txt contains no authorization pairs".into());
    }
    Ok(authz)
}

fn ticket_seen(
    worker_state: &WorkerServiceState,
    plan: &CanonicalTicketPlanV1,
    index: u16,
) -> bool {
    let key = ticket_key(
        worker_state.network_id,
        &plan.authority.parent_block_hash,
        plan.authority.target_epoch,
        &plan.authority.license_id,
        index,
    );
    worker_state
        .ledger
        .records
        .iter()
        .any(|record| record.ticket_key == key)
}

pub fn next_unique_ticket_index(
    worker_state: &WorkerServiceState,
    plan: &CanonicalTicketPlanV1,
) -> Option<u16> {
    (0..plan.authority.work_units_for_epoch).find(|index| !ticket_seen(worker_state, plan, *index))
}

pub fn plan_for_ticket(
    plan: &CanonicalTicketPlanV1,
    ticket_index: u16,
) -> Result<CanonicalTicketPlanV1, String> {
    if ticket_index >= plan.authority.work_units_for_epoch {
        return Err("ticket index is outside frozen Pack-A work budget".into());
    }
    let mut out = plan.clone();
    out.authority.ticket_index = ticket_index;
    Ok(out)
}

/// Return the next new unique TicketKey this authenticated worker is locally
/// authorized to receive. Worker identity does not affect which ticket index
/// exists; it only gates who may perform that already-existing ticket.
pub fn next_unique_plan_for_session(
    authorizations: &WorkerLicenseAuthorizationsV1,
    worker_state: &WorkerServiceState,
    plan: &CanonicalTicketPlanV1,
    session: &AuthenticatedWorkerSession,
) -> Result<Option<CanonicalTicketPlanV1>, String> {
    if !authorizations.is_authorized(&session.worker_id, &plan.authority.license_id) {
        return Err("WorkerID is not locally authorized for this LicenseID".into());
    }
    next_unique_ticket_index(worker_state, plan)
        .map(|index| plan_for_ticket(plan, index))
        .transpose()
}

/// Select an already-issued TicketKey for redundant execution by another
/// locally authorized worker. This never creates a new consensus chance.
pub fn redundant_plan_for_session(
    authorizations: &WorkerLicenseAuthorizationsV1,
    worker_state: &WorkerServiceState,
    plan: &CanonicalTicketPlanV1,
    ticket_index: u16,
    session: &AuthenticatedWorkerSession,
) -> Result<CanonicalTicketPlanV1, String> {
    if !authorizations.is_authorized(&session.worker_id, &plan.authority.license_id) {
        return Err("WorkerID is not locally authorized for this LicenseID".into());
    }
    let selected = plan_for_ticket(plan, ticket_index)?;
    if !ticket_seen(worker_state, &selected, ticket_index) {
        return Err("redundant assignment requires an already-issued TicketKey".into());
    }
    Ok(selected)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignmentLivenessV1 {
    pub canonical_parent_hash: [u8; 32],
    pub current_epoch: u64,
    pub license_eligible: bool,
    pub worker_authorized: bool,
    pub mining_custody_current: bool,
}

pub fn cancellation_reason(record: &LedgerRecordV1, liveness: AssignmentLivenessV1) -> Option<u8> {
    if record.parent_block_hash != liveness.canonical_parent_hash {
        return Some(CANCEL_CANONICAL_PARENT_CHANGED);
    }
    if liveness.current_epoch > record.target_epoch {
        return Some(CANCEL_TARGET_EPOCH_EXPIRED);
    }
    if !liveness.license_eligible {
        return Some(CANCEL_LICENSE_NO_LONGER_ELIGIBLE);
    }
    if !liveness.worker_authorized {
        return Some(CANCEL_WORKER_AUTHORIZATION_REVOKED);
    }
    if !liveness.mining_custody_current {
        return Some(CANCEL_MINING_CUSTODY_LOST);
    }
    None
}

fn cancellable_status(status: u8) -> bool {
    matches!(status, STATUS_RESERVED | STATUS_SENT | STATUS_CANDIDATE_WIN)
}

/// Persist cancellation before sending the unsolicited WORK_CANCEL frame.
/// If transport delivery fails, the local ledger remains fail-closed CANCELLED.
pub fn cancel_assignment_on_stream(
    worker_state: &mut WorkerServiceState,
    stream: &mut TcpStream,
    session: &AuthenticatedWorkerSession,
    node_signing_key: &SigningKey,
    assignment_id: &[u8; 32],
    reason: u8,
) -> Result<WorkCancelV1, String> {
    if !(1..=7).contains(&reason) {
        return Err("unknown Pack-L cancellation reason".into());
    }

    let record = worker_state
        .ledger
        .records
        .iter()
        .find(|record| &record.assignment_id == assignment_id)
        .cloned()
        .ok_or_else(|| "assignment is absent from worker budget ledger".to_string())?;

    if record.session_id != session.session_id || record.worker_id != session.worker_id {
        return Err("cancellation session/WorkerID binding mismatch".into());
    }
    if !cancellable_status(record.status) {
        return Err("assignment is already terminal and cannot be cancelled".into());
    }

    let cancel = WorkCancelV1::new_signed(
        WorkCancelCoreV1 {
            network_id: worker_state.network_id,
            session_id: session.session_id,
            assignment_id: record.assignment_id,
            ticket_key: record.ticket_key,
            reason,
        },
        node_signing_key,
    )
    .map_err(|e| e.to_string())?;

    worker_state
        .ledger
        .update_status_and_persist(&worker_state.paths.ledger, assignment_id, STATUS_CANCELLED)
        .map_err(|e| e.to_string())?;

    let frame = Frame::new(
        worker_state.worker_magic,
        MSG_WORK_CANCEL,
        0,
        cancel.encode(),
    )
    .map_err(|e| format!("construct WORK_CANCEL frame: {e:?}"))?;
    frame
        .write_to(stream)
        .map_err(|e| format!("write WORK_CANCEL frame: {e:?}"))?;
    stream
        .flush()
        .map_err(|e| format!("flush WORK_CANCEL frame: {e}"))?;

    Ok(cancel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mutiny_p2p::Frame;
    use mutiny_worker::endpoint::node_id_from_public_key;
    use mutiny_worker::ledger::{
        LedgerRecordV1, WorkerBudgetLedgerV1, STATUS_CANCELLED, STATUS_RESERVED,
    };
    use mutiny_worker::{
        assignment_id, worker_id, WorkAssignmentCoreV1, WorkCancelV1, ALGORITHM_PACK_A_ARGON2ID,
        ALGORITHM_PACK_A_ARGON2ID_V1, MSG_WORK_CANCEL, WORKER_MAGIC_DEVNET,
    };
    use std::net::{TcpListener, TcpStream};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::worker_mining::CanonicalTicketPlanV1;
    use crate::worker_service::{PreparedTicketAuthorityV1, WorkerServiceState};

    const NETWORK: u32 = 0x4D55_5403;

    fn temp_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mutiny-worker-scheduler-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn worker_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn node_key() -> SigningKey {
        SigningKey::from_bytes(&[0xC7; 32])
    }

    fn session(worker: &SigningKey, node: &SigningKey, sid: u8) -> AuthenticatedWorkerSession {
        let worker_public_key = worker.verifying_key().to_bytes();
        AuthenticatedWorkerSession {
            worker_id: worker_id(NETWORK, &worker_public_key),
            worker_public_key,
            node_id: node_id_from_public_key(&node.verifying_key().to_bytes()),
            session_id: [sid; 32],
            request_id: sid as u64 + 1,
        }
    }

    fn base_plan() -> CanonicalTicketPlanV1 {
        CanonicalTicketPlanV1 {
            authority: PreparedTicketAuthorityV1 {
                parent_block_hash: [0x11; 32],
                parent_height: 776,
                target_epoch: 131_075,
                license_id: [0x22; 32],
                ticket_index: 0,
                work_units_for_epoch: 2,
                eligible_license_count: 1,
                difficulty_c_q32: 2u64 << 32,
                anchor_entropy: [0x80; 32],
                target: [0xff; 32],
            },
            license_index: 0,
            operation_fingerprint: Vec::new(),
        }
    }

    fn reserve_plan(
        state: &mut WorkerServiceState,
        plan: &CanonicalTicketPlanV1,
        session: &AuthenticatedWorkerSession,
        sequence: u64,
    ) -> [u8; 32] {
        let core = WorkAssignmentCoreV1 {
            network_id: NETWORK,
            session_id: session.session_id,
            assignment_sequence: sequence,
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
        };
        let aid = assignment_id(&core);
        let record = LedgerRecordV1 {
            ticket_key: core.ticket_key(),
            parent_block_hash: core.parent_block_hash,
            target_epoch: core.target_epoch,
            license_id: core.license_id,
            ticket_index: core.ticket_index,
            work_units_for_epoch: core.work_units_for_epoch,
            worker_id: session.worker_id,
            session_id: session.session_id,
            assignment_id: aid,
            assignment_sequence: sequence,
            status: STATUS_RESERVED,
        };
        state
            .ledger
            .reserve_and_persist(&state.paths.ledger, record)
            .unwrap();
        aid
    }

    fn authorization_file(
        dir: &Path,
        workers: &[AuthenticatedWorkerSession],
        license_id: [u8; 32],
    ) -> PathBuf {
        let path = worker_license_authorization_path(dir);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut text = String::new();
        for session in workers {
            text.push_str(&hex::encode(session.worker_id));
            text.push(' ');
            text.push_str(&hex::encode(license_id));
            text.push('\n');
        }
        fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn assignment_authorization_mapping_is_fail_closed_and_allows_redundant_workers() {
        let dir = temp_dir("authz");
        let node = node_key();
        let w1 = session(&worker_key(0xA1), &node, 0x31);
        let w2 = session(&worker_key(0xA2), &node, 0x32);
        let plan = base_plan();

        let mut allowed = BTreeSet::new();
        allowed.insert(w1.worker_id);
        allowed.insert(w2.worker_id);
        let path = authorization_file(&dir, &[w1.clone(), w2.clone()], plan.authority.license_id);

        let authz = load_worker_license_authorizations(&path, &allowed).unwrap();
        assert_eq!(authz.pair_count(), 2);
        assert!(authz.is_authorized(&w1.worker_id, &plan.authority.license_id));
        assert!(authz.is_authorized(&w2.worker_id, &plan.authority.license_id));

        fs::write(
            &path,
            format!(
                "{} {}\n{} {}\n",
                hex::encode(w1.worker_id),
                hex::encode(plan.authority.license_id),
                hex::encode(w1.worker_id),
                hex::encode(plan.authority.license_id),
            ),
        )
        .unwrap();
        assert!(load_worker_license_authorizations(&path, &allowed)
            .unwrap_err()
            .contains("duplicate WorkerID/LicenseID"));

        let unknown = [0xEE; 32];
        fs::write(
            &path,
            format!(
                "{} {}\n",
                hex::encode(unknown),
                hex::encode(plan.authority.license_id),
            ),
        )
        .unwrap();
        assert!(load_worker_license_authorizations(&path, &allowed)
            .unwrap_err()
            .contains("absent from authorized-workers-v1.txt"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn two_workers_cannot_create_more_than_w_unique_ticket_keys_and_restart_preserves_budget() {
        let dir = temp_dir("budget");
        let node = node_key();
        let w1 = session(&worker_key(0xA1), &node, 0x41);
        let w2 = session(&worker_key(0xA2), &node, 0x42);
        let plan = base_plan();

        let mut state = WorkerServiceState::open(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap();
        state.allowed_workers.insert(w1.worker_id);
        state.allowed_workers.insert(w2.worker_id);

        let auth_path =
            authorization_file(&dir, &[w1.clone(), w2.clone()], plan.authority.license_id);
        let authz = load_worker_license_authorizations(&auth_path, &state.allowed_workers).unwrap();

        let first = next_unique_plan_for_session(&authz, &state, &plan, &w1)
            .unwrap()
            .unwrap();
        assert_eq!(first.authority.ticket_index, 0);
        assert!(state
            .ledger
            .records
            .iter()
            .all(|r| r.ticket_index != first.authority.ticket_index));
        reserve_plan(&mut state, &first, &w1, 1);

        let second = next_unique_plan_for_session(&authz, &state, &plan, &w2)
            .unwrap()
            .unwrap();
        assert_eq!(second.authority.ticket_index, 1);
        reserve_plan(&mut state, &second, &w2, 2);

        assert!(next_unique_plan_for_session(&authz, &state, &plan, &w1)
            .unwrap()
            .is_none());
        assert_eq!(state.ledger.unique_ticket_count(), 2);

        let redundant = redundant_plan_for_session(&authz, &state, &plan, 0, &w2).unwrap();
        assert_eq!(redundant.authority.ticket_index, 0);
        reserve_plan(&mut state, &redundant, &w2, 3);
        assert_eq!(state.ledger.unique_ticket_count(), 2);

        drop(state);
        let recovered = WorkerServiceState::open(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap();
        assert_eq!(recovered.ledger.unique_ticket_count(), 2);
        assert!(next_unique_ticket_index(&recovered, &plan).is_none());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn cancellation_reason_precedence_is_deterministic() {
        let plan = base_plan();
        let node = node_key();
        let worker = session(&worker_key(0xA1), &node, 0x51);
        let dir = temp_dir("reason");
        let mut state = WorkerServiceState::open(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap();
        let aid = reserve_plan(&mut state, &plan, &worker, 1);
        let record = state
            .ledger
            .records
            .iter()
            .find(|r| r.assignment_id == aid)
            .unwrap()
            .clone();

        let live = AssignmentLivenessV1 {
            canonical_parent_hash: record.parent_block_hash,
            current_epoch: record.target_epoch,
            license_eligible: true,
            worker_authorized: true,
            mining_custody_current: true,
        };
        assert_eq!(cancellation_reason(&record, live), None);

        assert_eq!(
            cancellation_reason(
                &record,
                AssignmentLivenessV1 {
                    canonical_parent_hash: [0x99; 32],
                    ..live
                },
            ),
            Some(CANCEL_CANONICAL_PARENT_CHANGED)
        );
        assert_eq!(
            cancellation_reason(
                &record,
                AssignmentLivenessV1 {
                    current_epoch: record.target_epoch + 1,
                    ..live
                },
            ),
            Some(CANCEL_TARGET_EPOCH_EXPIRED)
        );
        assert_eq!(
            cancellation_reason(
                &record,
                AssignmentLivenessV1 {
                    license_eligible: false,
                    ..live
                },
            ),
            Some(CANCEL_LICENSE_NO_LONGER_ELIGIBLE)
        );
        assert_eq!(
            cancellation_reason(
                &record,
                AssignmentLivenessV1 {
                    worker_authorized: false,
                    ..live
                },
            ),
            Some(CANCEL_WORKER_AUTHORIZATION_REVOKED)
        );
        assert_eq!(
            cancellation_reason(
                &record,
                AssignmentLivenessV1 {
                    mining_custody_current: false,
                    ..live
                },
            ),
            Some(CANCEL_MINING_CUSTODY_LOST)
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn cancellation_is_persisted_before_unsolicited_signed_frame() {
        let dir = temp_dir("cancel-frame");
        let node = node_key();
        let worker = session(&worker_key(0xA1), &node, 0x61);
        let plan = base_plan();
        let mut state = WorkerServiceState::open(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap();
        let aid = reserve_plan(&mut state, &plan, &worker, 1);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            let frame = Frame::read_from(&mut stream, WORKER_MAGIC_DEVNET).unwrap();
            assert_eq!(frame.message_type, MSG_WORK_CANCEL);
            assert_eq!(frame.request_id, 0);
            WorkCancelV1::decode(&frame.payload).unwrap()
        });

        let (mut server_stream, _) = listener.accept().unwrap();
        let cancel = cancel_assignment_on_stream(
            &mut state,
            &mut server_stream,
            &worker,
            &node,
            &aid,
            CANCEL_WORKER_AUTHORIZATION_REVOKED,
        )
        .unwrap();

        assert_eq!(
            state
                .ledger
                .records
                .iter()
                .find(|r| r.assignment_id == aid)
                .unwrap()
                .status,
            STATUS_CANCELLED
        );

        let received = client.join().unwrap();
        assert_eq!(received, cancel);
        assert_eq!(received.core.reason, CANCEL_WORKER_AUTHORIZATION_REVOKED);
        received
            .verify_node_signature(&node.verifying_key().to_bytes())
            .unwrap();

        let recovered = WorkerBudgetLedgerV1::load_recover(&state.paths.ledger, NETWORK).unwrap();
        assert_eq!(
            recovered
                .records
                .iter()
                .find(|r| r.assignment_id == aid)
                .unwrap()
                .status,
            STATUS_CANCELLED
        );

        let _ = fs::remove_dir_all(dir);
    }
}
