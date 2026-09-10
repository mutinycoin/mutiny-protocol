use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use mutiny_p2p::node_id;
use mutiny_worker::endpoint::{initiate_worker_handshake, node_id_from_public_key};
use mutiny_worker::reference::process_one_assignment;
use mutiny_worker::{worker_id, RESULT_NO_WIN, RESULT_WIN, WORKER_MAGIC_DEVNET};
use rand_core::{OsRng, RngCore};

use crate::worker_mining::{
    finalize_worker_result, prepare_canonical_ticket, FinalizeWorkerResultV1,
};
use crate::worker_scheduler::{
    load_runtime_worker_license_authorizations, next_unique_plan_for_session,
};
use crate::worker_service::{
    dispatch_one_prepared_ticket, prepare_runtime_state, DEFAULT_NODE_CAPABILITIES,
};
use crate::{decode32, load_state, save_state, DevnetState, DEVNET_NETWORK_ID};

const REFERENCE_WORKER_CONNECT_RETRIES: usize = 100;
const REFERENCE_WORKER_CONNECT_DELAY_MS: u64 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerRuntimeOutcomeV1 {
    pub worker_id: [u8; 32],
    pub ticket_index: u16,
    pub result_kind: u8,
    pub block_accepted: bool,
    pub canonical_height: u64,
    pub canonical_tip_hash: [u8; 32],
}

fn random_nonzero_u64() -> u64 {
    loop {
        let value = OsRng.next_u64();
        if value != 0 {
            return value;
        }
    }
}

fn random_nonce32() -> [u8; 32] {
    let mut out = [0u8; 32];
    OsRng.fill_bytes(&mut out);
    out
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

pub fn create_reference_worker_key(path: &Path) -> Result<SigningKey, String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create reference-worker key directory: {e}"))?;
        }
    }

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("create reference-worker key file {}: {e}", path.display()))?;
    file.write_all(&seed)
        .map_err(|e| format!("write reference-worker key file: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("sync reference-worker key file: {e}"))?;
    seed.fill(0);

    Ok(key)
}

pub fn load_reference_worker_key(path: &Path) -> Result<SigningKey, String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("read reference-worker key file {}: {e}", path.display()))?;
    if bytes.len() != 32 {
        return Err("reference-worker key file must contain exactly 32 raw seed bytes".into());
    }
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "reference-worker key file must contain exactly 32 raw seed bytes")?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn print_reference_worker_key(path: &Path, key: &SigningKey) {
    let public_key = key.verifying_key().to_bytes();
    println!("Reference worker key file: {}", path.display());
    println!("Reference worker public key: {}", hex::encode(public_key));
    println!(
        "Reference WorkerID: {}",
        hex::encode(worker_id(DEVNET_NETWORK_ID, &public_key))
    );
    println!("Reference worker key scope: operational Pack-L worker only");
    println!("Owner/mining/node authority: NONE");
}

fn connect_with_retry(address: &str) -> Result<TcpStream, String> {
    let mut last = None;
    for _ in 0..REFERENCE_WORKER_CONNECT_RETRIES {
        match TcpStream::connect(address) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                last = Some(error);
                thread::sleep(Duration::from_millis(REFERENCE_WORKER_CONNECT_DELAY_MS));
            }
        }
    }
    Err(format!(
        "connect to worker service {address}: {}",
        last.map_or_else(|| "unknown error".into(), |e| e.to_string())
    ))
}

pub fn run_reference_worker_one(
    connect: &str,
    worker_key: &SigningKey,
    expected_node_public_key: [u8; 32],
    expected_node_id: [u8; 32],
) -> Result<mutiny_worker::WorkResultV1, String> {
    let derived_node_id = node_id_from_public_key(&expected_node_public_key);
    if derived_node_id != expected_node_id {
        return Err("paired node public key does not derive supplied NodeID".into());
    }

    let mut stream = connect_with_retry(connect)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| format!("set reference-worker read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| format!("set reference-worker write timeout: {e}"))?;

    let handshake_request_id = random_nonzero_u64();
    let session = initiate_worker_handshake(
        &mut stream,
        WORKER_MAGIC_DEVNET,
        DEVNET_NETWORK_ID,
        worker_key,
        random_nonce32(),
        1,
        1,
        handshake_request_id,
        expected_node_id,
    )
    .map_err(|e| e.to_string())?;

    let result = process_one_assignment(
        &mut stream,
        WORKER_MAGIC_DEVNET,
        &session,
        &expected_node_public_key,
        worker_key,
    )
    .map_err(|e| e.to_string())?;

    println!(
        "Reference worker authenticated: {}",
        hex::encode(session.worker_id)
    );
    println!(
        "Reference worker SessionID: {}",
        hex::encode(session.session_id)
    );
    println!(
        "Reference worker AssignmentID: {}",
        hex::encode(result.core.assignment_id)
    );
    println!(
        "Reference worker TicketKey: {}",
        hex::encode(result.core.ticket_key)
    );
    println!(
        "Reference worker result: {}",
        match result.core.result_kind {
            RESULT_NO_WIN => "NO_WIN",
            RESULT_WIN => "WIN",
            _ => "UNKNOWN",
        }
    );

    Ok(result)
}

fn preflight_mining_authority(
    state: &DevnetState,
    license_index: usize,
    mining_signer: &SigningKey,
) -> Result<[u8; 32], String> {
    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    let expected = decode32(&license.mining_public_key)?;
    if mining_signer.verifying_key().to_bytes() != expected {
        return Err(
            "encrypted mining signer does not match current on-chain mining authority".into(),
        );
    }
    decode32(&license.license_id)
}

/// Serve exactly one authenticated worker and exactly one already-authorized
/// Pack-A ticket. The bounded lifecycle is deliberate: a WIN changes the
/// canonical parent; a NO_WIN consumes one TicketKey. The next invocation
/// recovers the persistent ledger and can select the next still-unissued
/// ticket without widening W_E.
pub fn serve_one_mining_ticket(
    data_dir: &Path,
    listen: &str,
    target_epoch: u64,
    license_index: usize,
    node_signing_key: &SigningKey,
    mining_signer: &SigningKey,
) -> Result<WorkerRuntimeOutcomeV1, String> {
    let mut state = load_state(data_dir)?;
    let license_id = preflight_mining_authority(&state, license_index, mining_signer)?;

    let mut worker_state = prepare_runtime_state(data_dir, DEVNET_NETWORK_ID, WORKER_MAGIC_DEVNET)
        .map_err(|e| e.to_string())?;
    let authorizations = load_runtime_worker_license_authorizations(data_dir, &worker_state)?;

    let listener = worker_state.bind(listen).map_err(|e| e.to_string())?;
    println!("Pack-L mining worker service listening on {listen}");
    println!("Pack-L mining worker magic: 0x{WORKER_MAGIC_DEVNET:08x}");
    println!(
        "Pack-L mining NodeID: {}",
        hex::encode(node_id(&node_signing_key.verifying_key().to_bytes()).0)
    );
    println!("Pack-L target LicenseID: {}", hex::encode(license_id));
    println!("Pack-L target epoch: {target_epoch}");

    let (mut stream, session) = worker_state
        .accept_one(
            &listener,
            node_signing_key,
            random_nonce32(),
            DEFAULT_NODE_CAPABILITIES,
        )
        .map_err(|e| e.to_string())?;

    if !authorizations.is_authorized(&session.worker_id, &license_id) {
        worker_state.release_session(&session);
        return Err(
            "authenticated WorkerID has zero assignment authority for target LicenseID".into(),
        );
    }

    let mut prepared_state = state.clone();
    let base_plan = prepare_canonical_ticket(
        &mut prepared_state,
        target_epoch,
        license_index,
        0,
        mining_signer,
    )?;
    let plan = next_unique_plan_for_session(&authorizations, &worker_state, &base_plan, &session)?
        .ok_or("all frozen Pack-A TicketKeys for this LicenseID/epoch are already issued")?;

    // The skipped-epoch / scheduled-transition preparation becomes durable
    // before the assignment is emitted. TicketKey persistence itself is then
    // performed by Candidate 4B reserve-before-sign-before-send.
    state = prepared_state;
    save_state(data_dir, &state)?;

    let mut request_id = random_nonzero_u64();
    while request_id == session.request_id {
        request_id = random_nonzero_u64();
    }

    let outcome = dispatch_one_prepared_ticket(
        &mut worker_state,
        &mut stream,
        &session,
        node_signing_key,
        &plan.authority,
        1,
        request_id,
    )
    .map_err(|e| e.to_string())?;

    let finalized = finalize_worker_result(
        &mut state,
        &mut worker_state,
        &session,
        mining_signer,
        &plan,
        &outcome,
    )?;
    save_state(data_dir, &state)?;

    worker_state.release_session(&session);
    let _ = stream.shutdown(std::net::Shutdown::Both);

    let block_accepted = finalized == FinalizeWorkerResultV1::AcceptedBlock;
    println!(
        "Pack-L runtime WorkerID: {}",
        hex::encode(session.worker_id)
    );
    println!(
        "Pack-L runtime ticket index: {}",
        plan.authority.ticket_index
    );
    println!(
        "Pack-L runtime TicketKey: {}",
        hex::encode(outcome.assignment.ticket_key)
    );
    println!(
        "Pack-L runtime result: {}",
        match outcome.result.core.result_kind {
            RESULT_NO_WIN => "NO_WIN",
            RESULT_WIN => "WIN",
            _ => "UNKNOWN",
        }
    );
    println!("Pack-L runtime block accepted: {block_accepted}");
    println!("Pack-L runtime canonical height: {}", state.height);
    println!("Pack-L runtime canonical tip: {}", state.tip_hash);

    Ok(WorkerRuntimeOutcomeV1 {
        worker_id: session.worker_id,
        ticket_index: plan.authority.ticket_index,
        result_kind: outcome.result.core.result_kind,
        block_accepted,
        canonical_height: state.height,
        canonical_tip_hash: decode32(&state.tip_hash)?,
    })
}

pub fn run_reference_worker_one_from_strings(
    connect: &str,
    worker_key_file: &Path,
    expected_node_public_key_hex: &str,
    expected_node_id_hex: &str,
) -> Result<mutiny_worker::WorkResultV1, String> {
    let worker_key = load_reference_worker_key(worker_key_file)?;
    let node_public_key = decode_hex32(expected_node_public_key_hex, "node public key")?;
    let node_id_value = decode_hex32(expected_node_id_hex, "NodeID")?;
    run_reference_worker_one(connect, &worker_key, node_public_key, node_id_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    use mutiny_crypto::block_signing_digest;
    use mutiny_worker::ledger::WorkerBudgetLedgerV1;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{
        init_devnet, load_state, refresh_current_state_root, save_state, ACTIVATION_DELAY_EPOCHS,
        LICENSE_STATUS_ACTIVE, LICENSE_STATUS_REVOKED,
    };

    fn temp_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mutiny-worker-runtime-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn node_key() -> SigningKey {
        SigningKey::from_bytes(&[0xC7; 32])
    }

    fn mining_key() -> SigningKey {
        SigningKey::from_bytes(&[0xA5; 32])
    }

    fn worker_key() -> SigningKey {
        SigningKey::from_bytes(&[0xB6; 32])
    }

    fn prepare_one_license_state(dir: &Path, mining: &SigningKey) -> DevnetState {
        init_devnet(dir, 1, true).unwrap();
        let mut state = load_state(dir).unwrap();

        for (index, license) in state.licenses.iter_mut().enumerate() {
            if index == 0 {
                license.status = LICENSE_STATUS_ACTIVE;
                license.activation_epoch = 0;
                license.suspended_until_epoch = 0;
                license.revocation_epoch = 0;
                license.mining_public_key = hex::encode(mining.verifying_key().to_bytes());
            } else {
                license.status = LICENSE_STATUS_REVOKED;
                license.strike_weight = 16;
                license.revocation_epoch = 1;
            }
        }

        state.difficulty_correction_q32 = 2u64 << 32;
        refresh_current_state_root(&mut state).unwrap();
        save_state(dir, &state).unwrap();
        state
    }

    fn write_worker_authority_files(dir: &Path, worker: &SigningKey, license_id: [u8; 32]) {
        let worker_dir = dir.join("worker");
        fs::create_dir_all(&worker_dir).unwrap();
        let wid = worker_id(DEVNET_NETWORK_ID, &worker.verifying_key().to_bytes());
        fs::write(
            worker_dir.join("authorized-workers-v1.txt"),
            format!("{}\n", hex::encode(wid)),
        )
        .unwrap();
        fs::write(
            worker_dir.join("authorized-worker-licenses-v1.txt"),
            format!("{} {}\n", hex::encode(wid), hex::encode(license_id)),
        )
        .unwrap();
    }

    #[test]
    fn reference_worker_key_file_is_exactly_32_bytes_and_derives_worker_id() {
        let dir = temp_dir("key");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("worker.seed");

        let created = create_reference_worker_key(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 32);
        let loaded = load_reference_worker_key(&path).unwrap();
        assert_eq!(
            created.verifying_key().to_bytes(),
            loaded.verifying_key().to_bytes()
        );

        let wid = worker_id(DEVNET_NETWORK_ID, &loaded.verifying_key().to_bytes());
        assert_ne!(wid, [0u8; 32]);
        assert!(create_reference_worker_key(&path).is_err());

        fs::write(&path, [0u8; 31]).unwrap();
        assert!(load_reference_worker_key(&path).is_err());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn real_tcp_reference_worker_to_node_recompute_to_mining_signature() {
        let dir = temp_dir("e2e");
        fs::create_dir_all(&dir).unwrap();

        let node = node_key();
        let mining = mining_key();
        let worker = worker_key();
        let initial = prepare_one_license_state(&dir, &mining);
        let license_id = decode32(&initial.licenses[0].license_id).unwrap();
        write_worker_authority_files(&dir, &worker, license_id);

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let listen = addr.to_string();

        let server_dir = dir.clone();
        let server_listen = listen.clone();
        let node_for_server = node.clone();
        let mining_for_server = mining.clone();
        let before_height = initial.height;

        let server = thread::spawn(move || {
            serve_one_mining_ticket(
                &server_dir,
                &server_listen,
                ACTIVATION_DELAY_EPOCHS,
                0,
                &node_for_server,
                &mining_for_server,
            )
            .unwrap()
        });

        let expected_node_public_key = node.verifying_key().to_bytes();
        let expected_node_id = node_id_from_public_key(&expected_node_public_key);
        let worker_result =
            run_reference_worker_one(&listen, &worker, expected_node_public_key, expected_node_id)
                .unwrap();
        assert_eq!(worker_result.core.result_kind, RESULT_WIN);

        let outcome = server.join().unwrap();
        assert!(outcome.block_accepted);
        assert_eq!(outcome.canonical_height, before_height + 1);
        assert_eq!(
            outcome.worker_id,
            worker_id(DEVNET_NETWORK_ID, &worker.verifying_key().to_bytes(),)
        );

        let final_state = load_state(&dir).unwrap();
        assert_eq!(final_state.height, before_height + 1);
        let block = final_state.blocks.last().unwrap();
        let header = hex::decode(&block.header).unwrap();
        let core: [u8; 208] = header[..208].try_into().unwrap();
        let sig: [u8; 64] = header[208..].try_into().unwrap();
        let digest = block_signing_digest(&core);
        mining
            .verifying_key()
            .verify(&digest.0, &Signature::from_bytes(&sig))
            .unwrap();

        let ledger_path = dir.join("worker").join("budget-ledger-v1.bin");
        let ledger = WorkerBudgetLedgerV1::load_recover(&ledger_path, DEVNET_NETWORK_ID).unwrap();
        assert_eq!(ledger.unique_ticket_count(), 1);

        let worker_root = dir.join("worker");
        assert!(fs::read_dir(&worker_root)
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| {
                entry
                    .path()
                    .extension()
                    .and_then(|v| v.to_str())
                    .is_none_or(|ext| !ext.eq_ignore_ascii_case("msk"))
            }));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn paired_node_public_key_and_node_id_must_match_before_connect() {
        let worker = worker_key();
        let node = node_key();
        let err = run_reference_worker_one(
            "127.0.0.1:1",
            &worker,
            node.verifying_key().to_bytes(),
            [0x99; 32],
        )
        .unwrap_err();
        assert_eq!(
            err,
            "paired node public key does not derive supplied NodeID"
        );
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerReassignOutcomeV1 {
    pub worker_id: [u8; 32],
    pub ticket_index: u16,
    pub ticket_key: [u8; 32],
    pub result_kind: u8,
    pub block_accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCancelOutcomeV1 {
    pub worker_id: [u8; 32],
    pub ticket_index: u16,
    pub ticket_key: [u8; 32],
    pub cancel_reason: u8,
    pub stale_result_rejected: bool,
}

fn issue_assignment_without_wait(
    worker_state: &mut crate::worker_service::WorkerServiceState,
    stream: &mut TcpStream,
    session: &mutiny_worker::endpoint::AuthenticatedWorkerSession,
    node_signing_key: &SigningKey,
    plan: &crate::worker_mining::CanonicalTicketPlanV1,
    assignment_sequence: u64,
    request_id: u64,
) -> Result<(mutiny_worker::WorkAssignmentV1, bool), String> {
    if request_id == 0 || request_id == session.request_id {
        return Err("WORK_ASSIGNMENT request_id must be fresh and nonzero".into());
    }

    let core = mutiny_worker::WorkAssignmentCoreV1 {
        network_id: worker_state.network_id,
        session_id: session.session_id,
        assignment_sequence,
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
        algorithm_id: mutiny_worker::ALGORITHM_PACK_A_ARGON2ID,
        algorithm_version: mutiny_worker::ALGORITHM_PACK_A_ARGON2ID_V1,
    };

    let record = mutiny_worker::ledger::LedgerRecordV1 {
        ticket_key: core.ticket_key(),
        parent_block_hash: core.parent_block_hash,
        target_epoch: core.target_epoch,
        license_id: core.license_id,
        ticket_index: core.ticket_index,
        work_units_for_epoch: core.work_units_for_epoch,
        worker_id: session.worker_id,
        session_id: session.session_id,
        assignment_id: core.assignment_id(),
        assignment_sequence,
        status: mutiny_worker::ledger::STATUS_RESERVED,
    };

    let new_unique = worker_state
        .ledger
        .reserve_and_persist(&worker_state.paths.ledger, record)
        .map_err(|e| e.to_string())?;

    let assignment = mutiny_worker::WorkAssignmentV1::new_signed(core, node_signing_key)
        .map_err(|e| e.to_string())?;

    let frame = mutiny_p2p::Frame::new(
        worker_state.worker_magic,
        mutiny_worker::MSG_WORK_ASSIGNMENT,
        request_id,
        assignment.encode(),
    )
    .map_err(|e| format!("construct WORK_ASSIGNMENT frame: {e:?}"))?;
    frame
        .write_to(stream)
        .map_err(|e| format!("write WORK_ASSIGNMENT frame: {e:?}"))?;

    worker_state
        .ledger
        .update_status_and_persist(
            &worker_state.paths.ledger,
            &assignment.assignment_id,
            mutiny_worker::ledger::STATUS_SENT,
        )
        .map_err(|e| e.to_string())?;

    Ok((assignment, new_unique))
}

pub fn serve_one_reassigned_ticket(
    data_dir: &Path,
    listen: &str,
    target_epoch: u64,
    license_index: usize,
    ticket_index: u16,
    node_signing_key: &SigningKey,
    mining_signer: &SigningKey,
) -> Result<WorkerReassignOutcomeV1, String> {
    let mut state = load_state(data_dir)?;
    let license_id = preflight_mining_authority(&state, license_index, mining_signer)?;
    let mut worker_state = prepare_runtime_state(data_dir, DEVNET_NETWORK_ID, WORKER_MAGIC_DEVNET)
        .map_err(|e| e.to_string())?;
    let authz = load_runtime_worker_license_authorizations(data_dir, &worker_state)?;
    let listener = worker_state.bind(listen).map_err(|e| e.to_string())?;

    println!("Pack-L redundant worker service listening on {listen}");
    println!("Pack-L redundant target ticket index: {ticket_index}");

    let (mut stream, session) = worker_state
        .accept_one(
            &listener,
            node_signing_key,
            random_nonce32(),
            DEFAULT_NODE_CAPABILITIES,
        )
        .map_err(|e| e.to_string())?;

    if !authz.is_authorized(&session.worker_id, &license_id) {
        worker_state.release_session(&session);
        return Err(
            "authenticated WorkerID has zero assignment authority for target LicenseID".into(),
        );
    }

    let mut prepared = state.clone();
    let canonical_plan = prepare_canonical_ticket(
        &mut prepared,
        target_epoch,
        license_index,
        ticket_index,
        mining_signer,
    )?;
    let plan = crate::worker_scheduler::redundant_plan_for_session(
        &authz,
        &worker_state,
        &canonical_plan,
        ticket_index,
        &session,
    )?;

    state = prepared;
    save_state(data_dir, &state)?;

    let mut request_id = random_nonzero_u64();
    while request_id == session.request_id {
        request_id = random_nonzero_u64();
    }

    let outcome = dispatch_one_prepared_ticket(
        &mut worker_state,
        &mut stream,
        &session,
        node_signing_key,
        &plan.authority,
        1,
        request_id,
    )
    .map_err(|e| e.to_string())?;

    if outcome.new_unique_ticket {
        return Err(
            "redundant TicketKey reassignment unexpectedly created a new unique chance".into(),
        );
    }

    let finalized = finalize_worker_result(
        &mut state,
        &mut worker_state,
        &session,
        mining_signer,
        &plan,
        &outcome,
    )?;
    save_state(data_dir, &state)?;

    worker_state.release_session(&session);
    let _ = stream.shutdown(std::net::Shutdown::Both);

    let block_accepted = finalized == FinalizeWorkerResultV1::AcceptedBlock;
    println!(
        "Pack-L redundant WorkerID: {}",
        hex::encode(session.worker_id)
    );
    println!(
        "Pack-L redundant ticket index: {}",
        plan.authority.ticket_index
    );
    println!(
        "Pack-L redundant TicketKey: {}",
        hex::encode(outcome.assignment.ticket_key)
    );
    println!("Pack-L redundant new unique chance: false");
    println!("Pack-L redundant block accepted: {block_accepted}");

    Ok(WorkerReassignOutcomeV1 {
        worker_id: session.worker_id,
        ticket_index: plan.authority.ticket_index,
        ticket_key: outcome.assignment.ticket_key,
        result_kind: outcome.result.core.result_kind,
        block_accepted,
    })
}

pub fn serve_one_cancelled_ticket(
    data_dir: &Path,
    listen: &str,
    target_epoch: u64,
    license_index: usize,
    cancel_reason: u8,
    node_signing_key: &SigningKey,
    mining_signer: &SigningKey,
) -> Result<WorkerCancelOutcomeV1, String> {
    let mut state = load_state(data_dir)?;
    let license_id = preflight_mining_authority(&state, license_index, mining_signer)?;
    let mut worker_state = prepare_runtime_state(data_dir, DEVNET_NETWORK_ID, WORKER_MAGIC_DEVNET)
        .map_err(|e| e.to_string())?;
    let authz = load_runtime_worker_license_authorizations(data_dir, &worker_state)?;
    let listener = worker_state.bind(listen).map_err(|e| e.to_string())?;

    println!("Pack-L cancellation worker service listening on {listen}");
    println!("Pack-L cancellation reason requested: {cancel_reason}");

    let (mut stream, session) = worker_state
        .accept_one(
            &listener,
            node_signing_key,
            random_nonce32(),
            DEFAULT_NODE_CAPABILITIES,
        )
        .map_err(|e| e.to_string())?;

    if !authz.is_authorized(&session.worker_id, &license_id) {
        worker_state.release_session(&session);
        return Err(
            "authenticated WorkerID has zero assignment authority for target LicenseID".into(),
        );
    }

    let mut prepared = state.clone();
    let base_plan =
        prepare_canonical_ticket(&mut prepared, target_epoch, license_index, 0, mining_signer)?;
    let plan = next_unique_plan_for_session(&authz, &worker_state, &base_plan, &session)?
        .ok_or("all frozen Pack-A TicketKeys for this LicenseID/epoch are already issued")?;

    state = prepared;
    save_state(data_dir, &state)?;

    let mut request_id = random_nonzero_u64();
    while request_id == session.request_id {
        request_id = random_nonzero_u64();
    }

    let (assignment, new_unique) = issue_assignment_without_wait(
        &mut worker_state,
        &mut stream,
        &session,
        node_signing_key,
        &plan,
        1,
        request_id,
    )?;

    crate::worker_scheduler::cancel_assignment_on_stream(
        &mut worker_state,
        &mut stream,
        &session,
        node_signing_key,
        &assignment.assignment_id,
        cancel_reason,
    )?;

    println!(
        "Pack-L cancellation AssignmentID: {}",
        hex::encode(assignment.assignment_id)
    );
    println!(
        "Pack-L cancellation TicketKey: {}",
        hex::encode(assignment.ticket_key)
    );
    println!("Pack-L cancellation persisted before send: true");

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set stale-result read timeout: {e}"))?;

    let frame = mutiny_p2p::Frame::read_from(&mut stream, worker_state.worker_magic)
        .map_err(|e| format!("read post-cancel stale WorkResult: {e:?}"))?;
    if frame.message_type != mutiny_worker::MSG_WORK_RESULT {
        return Err("expected one intentionally stale WORK_RESULT after cancellation".into());
    }
    if frame.request_id != request_id {
        return Err("post-cancel stale WORK_RESULT request_id mismatch".into());
    }

    let result = mutiny_worker::WorkResultV1::decode(&frame.payload).map_err(|e| e.to_string())?;
    result
        .verify_worker_signature(&session.worker_public_key)
        .map_err(|e| e.to_string())?;

    let outcome = crate::worker_service::AssignmentDispatchOutcomeV1 {
        assignment: assignment.clone(),
        result,
        new_unique_ticket: new_unique,
    };

    let stale_error = finalize_worker_result(
        &mut state,
        &mut worker_state,
        &session,
        mining_signer,
        &plan,
        &outcome,
    )
    .expect_err("cancelled WorkResult must never finalize");

    if !stale_error.contains("ledger status") {
        return Err(format!(
            "cancelled stale WorkResult rejected for unexpected reason: {stale_error}"
        ));
    }

    println!("Post-cancel stale WorkResult rejected: {stale_error}");
    println!("Post-cancel stale WorkResult consensus authority: ZERO");

    worker_state.release_session(&session);
    let _ = stream.shutdown(std::net::Shutdown::Both);

    Ok(WorkerCancelOutcomeV1 {
        worker_id: session.worker_id,
        ticket_index: plan.authority.ticket_index,
        ticket_key: assignment.ticket_key,
        cancel_reason,
        stale_result_rejected: true,
    })
}

pub fn run_reference_worker_ignore_cancel_one(
    connect: &str,
    worker_key: &SigningKey,
    expected_node_public_key: [u8; 32],
    expected_node_id: [u8; 32],
) -> Result<(), String> {
    if node_id_from_public_key(&expected_node_public_key) != expected_node_id {
        return Err("paired node public key does not derive supplied NodeID".into());
    }

    let mut stream = connect_with_retry(connect)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| format!("set ignore-cancel read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| format!("set ignore-cancel write timeout: {e}"))?;

    let session = initiate_worker_handshake(
        &mut stream,
        WORKER_MAGIC_DEVNET,
        DEVNET_NETWORK_ID,
        worker_key,
        random_nonce32(),
        1,
        1,
        random_nonzero_u64(),
        expected_node_id,
    )
    .map_err(|e| e.to_string())?;

    let assignment_frame = mutiny_p2p::Frame::read_from(&mut stream, WORKER_MAGIC_DEVNET)
        .map_err(|e| format!("read WORK_ASSIGNMENT: {e:?}"))?;
    if assignment_frame.message_type != mutiny_worker::MSG_WORK_ASSIGNMENT
        || assignment_frame.request_id == 0
    {
        return Err("expected nonzero-request-id WORK_ASSIGNMENT".into());
    }

    let assignment = mutiny_worker::WorkAssignmentV1::decode(&assignment_frame.payload)
        .map_err(|e| e.to_string())?;
    assignment
        .verify_node_signature(&expected_node_public_key)
        .map_err(|e| e.to_string())?;

    let result = mutiny_worker::reference::execute_assignment(
        &assignment,
        &session,
        &expected_node_public_key,
        worker_key,
    )
    .map_err(|e| e.to_string())?;

    let cancel_frame = mutiny_p2p::Frame::read_from(&mut stream, WORKER_MAGIC_DEVNET)
        .map_err(|e| format!("read WORK_CANCEL: {e:?}"))?;
    if cancel_frame.message_type != mutiny_worker::MSG_WORK_CANCEL || cancel_frame.request_id != 0 {
        return Err("expected unsolicited WORK_CANCEL with request_id=0".into());
    }

    let cancel =
        mutiny_worker::WorkCancelV1::decode(&cancel_frame.payload).map_err(|e| e.to_string())?;
    cancel
        .verify_node_signature(&expected_node_public_key)
        .map_err(|e| e.to_string())?;

    if cancel.core.network_id != DEVNET_NETWORK_ID
        || cancel.core.session_id != session.session_id
        || cancel.core.assignment_id != assignment.assignment_id
        || cancel.core.ticket_key != assignment.ticket_key
    {
        return Err("WORK_CANCEL binding mismatch".into());
    }

    let stale_frame = mutiny_p2p::Frame::new(
        WORKER_MAGIC_DEVNET,
        mutiny_worker::MSG_WORK_RESULT,
        assignment_frame.request_id,
        result.encode(),
    )
    .map_err(|e| format!("construct stale WORK_RESULT: {e:?}"))?;
    stale_frame
        .write_to(&mut stream)
        .map_err(|e| format!("write stale WORK_RESULT: {e:?}"))?;

    println!(
        "Reference worker received signed WORK_CANCEL reason: {}",
        cancel.core.reason
    );
    println!(
        "Reference worker verified cancelled AssignmentID: {}",
        hex::encode(cancel.core.assignment_id)
    );
    println!("Reference worker deliberately sent stale signed WorkResult after cancel");
    Ok(())
}

pub fn run_reference_worker_ignore_cancel_one_from_strings(
    connect: &str,
    worker_key_file: &Path,
    expected_node_public_key_hex: &str,
    expected_node_id_hex: &str,
) -> Result<(), String> {
    let worker_key = load_reference_worker_key(worker_key_file)?;
    let node_public_key = decode_hex32(expected_node_public_key_hex, "node public key")?;
    let node_id_value = decode_hex32(expected_node_id_hex, "NodeID")?;
    run_reference_worker_ignore_cancel_one(connect, &worker_key, node_public_key, node_id_value)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedAssignmentLivenessV1 {
    pub canonical_parent_hash: [u8; 32],
    pub current_epoch: u64,
    pub license_eligible: bool,
    pub worker_authorized: bool,
    pub mining_custody_current: bool,
}

fn observe_assignment_liveness(
    data_dir: &Path,
    worker_state: &crate::worker_service::WorkerServiceState,
    session: &mutiny_worker::endpoint::AuthenticatedWorkerSession,
    assignment: &mutiny_worker::WorkAssignmentV1,
    license_index: usize,
    mining_label: &str,
    wallet_passphrase: &crate::SecretPassphrase,
) -> Result<ObservedAssignmentLivenessV1, String> {
    let live_state = load_state(data_dir)?;
    let canonical_parent_hash = decode32(&live_state.tip_hash)?;

    let license_eligible = live_state
        .licenses
        .get(license_index)
        .is_some_and(|license| license.is_eligible(assignment.core.target_epoch));

    let worker_authorized = load_runtime_worker_license_authorizations(data_dir, worker_state)
        .map(|authz| authz.is_authorized(&session.worker_id, &assignment.core.license_id))
        .unwrap_or(false);

    let mining_custody_current = crate::load_mining_key_for_license(
        data_dir,
        &live_state,
        license_index,
        mining_label,
        wallet_passphrase,
    )
    .is_ok();

    Ok(ObservedAssignmentLivenessV1 {
        canonical_parent_hash,
        current_epoch: live_state.tip_epoch,
        license_eligible,
        worker_authorized,
        mining_custody_current,
    })
}

fn select_observed_cancellation_reason(
    record: &mutiny_worker::ledger::LedgerRecordV1,
    observed: ObservedAssignmentLivenessV1,
) -> Option<u8> {
    crate::worker_scheduler::cancellation_reason(
        record,
        crate::worker_scheduler::AssignmentLivenessV1 {
            canonical_parent_hash: observed.canonical_parent_hash,
            current_epoch: observed.current_epoch,
            license_eligible: observed.license_eligible,
            worker_authorized: observed.worker_authorized,
            mining_custody_current: observed.mining_custody_current,
        },
    )
}

pub fn serve_one_lifecycle_watched_ticket(
    data_dir: &Path,
    listen: &str,
    target_epoch: u64,
    license_index: usize,
    node_signing_key: &SigningKey,
    mining_signer: &SigningKey,
    mining_label: &str,
    wallet_passphrase: &crate::SecretPassphrase,
) -> Result<WorkerCancelOutcomeV1, String> {
    let mut state = load_state(data_dir)?;
    let license_id = preflight_mining_authority(&state, license_index, mining_signer)?;

    let mut worker_state = prepare_runtime_state(data_dir, DEVNET_NETWORK_ID, WORKER_MAGIC_DEVNET)
        .map_err(|e| e.to_string())?;
    let initial_authz = load_runtime_worker_license_authorizations(data_dir, &worker_state)?;
    let listener = worker_state.bind(listen).map_err(|e| e.to_string())?;

    println!("Pack-L lifecycle watcher listening on {listen}");
    println!("Pack-L lifecycle watcher cancellation reason source: OBSERVED STATE ONLY");

    let (mut stream, session) = worker_state
        .accept_one(
            &listener,
            node_signing_key,
            random_nonce32(),
            DEFAULT_NODE_CAPABILITIES,
        )
        .map_err(|e| e.to_string())?;

    if !initial_authz.is_authorized(&session.worker_id, &license_id) {
        worker_state.release_session(&session);
        return Err(
            "authenticated WorkerID has zero assignment authority for target LicenseID".into(),
        );
    }

    let mut prepared = state.clone();
    let base_plan =
        prepare_canonical_ticket(&mut prepared, target_epoch, license_index, 0, mining_signer)?;
    let plan = next_unique_plan_for_session(&initial_authz, &worker_state, &base_plan, &session)?
        .ok_or("all frozen Pack-A TicketKeys for this LicenseID/epoch are already issued")?;

    state = prepared;
    save_state(data_dir, &state)?;

    let mut request_id = random_nonzero_u64();
    while request_id == session.request_id {
        request_id = random_nonzero_u64();
    }

    let (assignment, new_unique) = issue_assignment_without_wait(
        &mut worker_state,
        &mut stream,
        &session,
        node_signing_key,
        &plan,
        1,
        request_id,
    )?;

    println!(
        "Pack-L lifecycle watcher AssignmentID: {}",
        hex::encode(assignment.assignment_id)
    );
    println!(
        "Pack-L lifecycle watcher TicketKey: {}",
        hex::encode(assignment.ticket_key)
    );

    let mut selected = None;
    let mut selected_observed = None;

    for _ in 0..400 {
        let record = worker_state
            .ledger
            .records
            .iter()
            .find(|record| record.assignment_id == assignment.assignment_id)
            .cloned()
            .ok_or_else(|| {
                "lifecycle watcher assignment disappeared from persistent ledger".to_string()
            })?;

        let observed = observe_assignment_liveness(
            data_dir,
            &worker_state,
            &session,
            &assignment,
            license_index,
            mining_label,
            wallet_passphrase,
        )?;

        if let Some(reason) = select_observed_cancellation_reason(&record, observed) {
            selected = Some(reason);
            selected_observed = Some(observed);
            break;
        }

        thread::sleep(Duration::from_millis(25));
    }

    let reason = selected.ok_or(
        "no assignment-invalidating lifecycle change was observed within bounded watch window",
    )?;
    let observed = selected_observed.expect("selected reason always has observed liveness");

    println!(
        "Pack-L observed parent_changed: {}",
        observed.canonical_parent_hash != assignment.core.parent_block_hash
    );
    println!(
        "Pack-L observed epoch_expired: {}",
        observed.current_epoch > assignment.core.target_epoch
    );
    println!(
        "Pack-L observed license_eligible: {}",
        observed.license_eligible
    );
    println!(
        "Pack-L observed worker_authorized: {}",
        observed.worker_authorized
    );
    println!(
        "Pack-L observed mining_custody_current: {}",
        observed.mining_custody_current
    );
    println!("Pack-L autonomous cancellation reason: {reason}");

    crate::worker_scheduler::cancel_assignment_on_stream(
        &mut worker_state,
        &mut stream,
        &session,
        node_signing_key,
        &assignment.assignment_id,
        reason,
    )?;

    println!("Pack-L autonomous cancellation persisted before send: true");

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set lifecycle stale-result read timeout: {e}"))?;

    let frame = mutiny_p2p::Frame::read_from(&mut stream, worker_state.worker_magic)
        .map_err(|e| format!("read lifecycle stale WorkResult: {e:?}"))?;
    if frame.message_type != mutiny_worker::MSG_WORK_RESULT {
        return Err("expected intentionally stale WORK_RESULT after lifecycle cancel".into());
    }
    if frame.request_id != request_id {
        return Err("lifecycle stale WORK_RESULT request_id mismatch".into());
    }

    let result = mutiny_worker::WorkResultV1::decode(&frame.payload).map_err(|e| e.to_string())?;
    result
        .verify_worker_signature(&session.worker_public_key)
        .map_err(|e| e.to_string())?;

    let outcome = crate::worker_service::AssignmentDispatchOutcomeV1 {
        assignment: assignment.clone(),
        result,
        new_unique_ticket: new_unique,
    };

    let stale_error = finalize_worker_result(
        &mut state,
        &mut worker_state,
        &session,
        mining_signer,
        &plan,
        &outcome,
    )
    .expect_err("lifecycle-cancelled WorkResult must never finalize");

    if !stale_error.contains("ledger status") {
        return Err(format!(
            "lifecycle-cancelled stale WorkResult rejected for unexpected reason: {stale_error}"
        ));
    }

    println!("Lifecycle stale WorkResult rejected: {stale_error}");
    println!("Lifecycle stale WorkResult consensus authority: ZERO");

    worker_state.release_session(&session);
    let _ = stream.shutdown(std::net::Shutdown::Both);

    Ok(WorkerCancelOutcomeV1 {
        worker_id: session.worker_id,
        ticket_index: plan.authority.ticket_index,
        ticket_key: assignment.ticket_key,
        cancel_reason: reason,
        stale_result_rejected: true,
    })
}

#[cfg(test)]
mod lifecycle_watch_tests {
    use super::*;
    use mutiny_worker::ledger::{LedgerRecordV1, STATUS_SENT};

    fn record() -> LedgerRecordV1 {
        LedgerRecordV1 {
            ticket_key: [0x11; 32],
            parent_block_hash: [0x22; 32],
            target_epoch: 100,
            license_id: [0x33; 32],
            ticket_index: 0,
            work_units_for_epoch: 2,
            worker_id: [0x44; 32],
            session_id: [0x55; 32],
            assignment_id: [0x66; 32],
            assignment_sequence: 1,
            status: STATUS_SENT,
        }
    }

    #[test]
    fn observed_lifecycle_reason_precedence_is_parent_epoch_eligibility_auth_custody() {
        let r = record();

        assert_eq!(
            select_observed_cancellation_reason(
                &r,
                ObservedAssignmentLivenessV1 {
                    canonical_parent_hash: [0x99; 32],
                    current_epoch: 101,
                    license_eligible: false,
                    worker_authorized: false,
                    mining_custody_current: false,
                },
            ),
            Some(crate::worker_scheduler::CANCEL_CANONICAL_PARENT_CHANGED)
        );

        assert_eq!(
            select_observed_cancellation_reason(
                &r,
                ObservedAssignmentLivenessV1 {
                    canonical_parent_hash: r.parent_block_hash,
                    current_epoch: 101,
                    license_eligible: false,
                    worker_authorized: false,
                    mining_custody_current: false,
                },
            ),
            Some(crate::worker_scheduler::CANCEL_TARGET_EPOCH_EXPIRED)
        );

        assert_eq!(
            select_observed_cancellation_reason(
                &r,
                ObservedAssignmentLivenessV1 {
                    canonical_parent_hash: r.parent_block_hash,
                    current_epoch: r.target_epoch,
                    license_eligible: false,
                    worker_authorized: false,
                    mining_custody_current: false,
                },
            ),
            Some(crate::worker_scheduler::CANCEL_LICENSE_NO_LONGER_ELIGIBLE)
        );

        assert_eq!(
            select_observed_cancellation_reason(
                &r,
                ObservedAssignmentLivenessV1 {
                    canonical_parent_hash: r.parent_block_hash,
                    current_epoch: r.target_epoch,
                    license_eligible: true,
                    worker_authorized: false,
                    mining_custody_current: false,
                },
            ),
            Some(crate::worker_scheduler::CANCEL_WORKER_AUTHORIZATION_REVOKED)
        );

        assert_eq!(
            select_observed_cancellation_reason(
                &r,
                ObservedAssignmentLivenessV1 {
                    canonical_parent_hash: r.parent_block_hash,
                    current_epoch: r.target_epoch,
                    license_eligible: true,
                    worker_authorized: true,
                    mining_custody_current: false,
                },
            ),
            Some(crate::worker_scheduler::CANCEL_MINING_CUSTODY_LOST)
        );

        assert_eq!(
            select_observed_cancellation_reason(
                &r,
                ObservedAssignmentLivenessV1 {
                    canonical_parent_hash: r.parent_block_hash,
                    current_epoch: r.target_epoch,
                    license_eligible: true,
                    worker_authorized: true,
                    mining_custody_current: true,
                },
            ),
            None
        );
    }
}
