use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use mutiny_p2p::Frame;
use mutiny_worker::endpoint::{
    accept_worker_handshake, ActiveWorkerRegistry, AuthenticatedWorkerSession, EndpointError,
};
use mutiny_worker::ledger::{
    LedgerError, LedgerRecordV1, WorkerBudgetLedgerV1, STATUS_CANDIDATE_WIN,
    STATUS_COMPLETED_NO_WIN, STATUS_RESERVED, STATUS_SENT,
};
use mutiny_worker::{
    WorkAssignmentCoreV1, WorkAssignmentV1, WorkResultV1, ALGORITHM_PACK_A_ARGON2ID,
    ALGORITHM_PACK_A_ARGON2ID_V1, MSG_WORK_ASSIGNMENT, MSG_WORK_RESULT, RESULT_NO_WIN, RESULT_WIN,
};
use rand_core::RngCore;

const ALLOWLIST_MAX_BYTES: u64 = 1_048_576;
const ALLOWLIST_MAX_ENTRIES: usize = 4096;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum WorkerServiceError {
    Io(std::io::Error),
    Endpoint(EndpointError),
    Ledger(LedgerError),
    PackL(mutiny_worker::PackLError),
    Protocol(&'static str),
    InvalidAllowlist(&'static str),
}

impl fmt::Display for WorkerServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "worker service I/O error: {e}"),
            Self::Endpoint(e) => write!(f, "worker endpoint error: {e}"),
            Self::Ledger(e) => write!(f, "worker ledger error: {e}"),
            Self::PackL(e) => write!(f, "Pack-L error: {e}"),
            Self::Protocol(msg) => write!(f, "worker protocol error: {msg}"),
            Self::InvalidAllowlist(msg) => write!(f, "invalid worker allowlist: {msg}"),
        }
    }
}

impl std::error::Error for WorkerServiceError {}

impl From<std::io::Error> for WorkerServiceError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<EndpointError> for WorkerServiceError {
    fn from(value: EndpointError) -> Self {
        Self::Endpoint(value)
    }
}
impl From<LedgerError> for WorkerServiceError {
    fn from(value: LedgerError) -> Self {
        Self::Ledger(value)
    }
}
impl From<mutiny_worker::PackLError> for WorkerServiceError {
    fn from(value: mutiny_worker::PackLError) -> Self {
        Self::PackL(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerServicePaths {
    pub root: PathBuf,
    pub allowlist: PathBuf,
    pub ledger: PathBuf,
}

pub fn worker_service_paths(data_dir: &Path) -> WorkerServicePaths {
    let root = data_dir.join("worker");
    WorkerServicePaths {
        allowlist: root.join("authorized-workers-v1.txt"),
        ledger: root.join("budget-ledger-v1.bin"),
        root,
    }
}

fn decode_hex32(text: &str) -> Result<[u8; 32], WorkerServiceError> {
    if text.len() != 64 || !text.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(WorkerServiceError::InvalidAllowlist(
            "WorkerID must be exactly 64 hexadecimal characters",
        ));
    }

    fn nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => unreachable!("validated as ASCII hex"),
        }
    }

    let bytes = text.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nibble(bytes[i * 2]) << 4) | nibble(bytes[i * 2 + 1]);
    }
    Ok(out)
}

/// Local operational allowlist format:
/// - UTF-8/ASCII text
/// - one 32-byte WorkerID as 64 hex characters per line
/// - empty lines and lines beginning with '#' are ignored
/// - duplicates fail closed
/// - no private key material is accepted or stored
pub fn load_worker_allowlist(path: &Path) -> Result<BTreeSet<[u8; 32]>, WorkerServiceError> {
    let meta = fs::metadata(path)?;
    if meta.len() > ALLOWLIST_MAX_BYTES {
        return Err(WorkerServiceError::InvalidAllowlist(
            "allowlist exceeds 1 MiB",
        ));
    }

    let text = fs::read_to_string(path)?;
    let mut allowed = BTreeSet::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if allowed.len() >= ALLOWLIST_MAX_ENTRIES {
            return Err(WorkerServiceError::InvalidAllowlist(
                "allowlist exceeds 4096 WorkerIDs",
            ));
        }

        let worker_id = decode_hex32(line)?;
        if !allowed.insert(worker_id) {
            return Err(WorkerServiceError::InvalidAllowlist("duplicate WorkerID"));
        }
    }

    Ok(allowed)
}

#[derive(Debug)]
pub struct WorkerServiceState {
    pub network_id: u32,
    pub worker_magic: u32,
    pub allowed_workers: BTreeSet<[u8; 32]>,
    pub active_workers: ActiveWorkerRegistry,
    pub ledger: WorkerBudgetLedgerV1,
    pub paths: WorkerServicePaths,
}

impl WorkerServiceState {
    /// Open local Pack-L operational state.
    ///
    /// This function creates only `<data-dir>/worker` and the local budget ledger.
    /// It never reads or writes any owner/mining/node identity secret.
    pub fn open(
        data_dir: &Path,
        network_id: u32,
        worker_magic: u32,
    ) -> Result<Self, WorkerServiceError> {
        let paths = worker_service_paths(data_dir);
        fs::create_dir_all(&paths.root)?;

        let allowed_workers = if paths.allowlist.exists() {
            load_worker_allowlist(&paths.allowlist)?
        } else {
            BTreeSet::new()
        };

        let ledger = WorkerBudgetLedgerV1::open_or_create(&paths.ledger, network_id)?;

        Ok(Self {
            network_id,
            worker_magic,
            allowed_workers,
            active_workers: ActiveWorkerRegistry::default(),
            ledger,
            paths,
        })
    }

    pub fn reload_allowlist(&mut self) -> Result<(), WorkerServiceError> {
        self.allowed_workers = load_worker_allowlist(&self.paths.allowlist)?;
        Ok(())
    }

    pub fn bind(&self, listen: &str) -> Result<TcpListener, WorkerServiceError> {
        Ok(TcpListener::bind(listen)?)
    }

    /// Accept exactly one worker TCP connection and perform Pack-L mutual auth.
    ///
    /// The caller supplies:
    /// - the existing decrypted node-identity SigningKey;
    /// - a fresh cryptographically random node_nonce.
    ///
    /// No owner or mining key is accepted by this API.
    ///
    /// On success the returned TcpStream remains the authenticated worker session
    /// transport. The caller must call `release_session` when that connection ends.
    pub fn accept_one(
        &mut self,
        listener: &TcpListener,
        node_signing_key: &SigningKey,
        node_nonce: [u8; 32],
        node_capabilities: u64,
    ) -> Result<(TcpStream, AuthenticatedWorkerSession), WorkerServiceError> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

        let session = accept_worker_handshake(
            &mut stream,
            self.worker_magic,
            self.network_id,
            node_signing_key,
            node_nonce,
            node_capabilities,
            &self.allowed_workers,
            &mut self.active_workers,
        )?;

        Ok((stream, session))
    }

    pub fn release_session(&mut self, session: &AuthenticatedWorkerSession) {
        self.active_workers.release(&session.worker_id);
    }
}

pub const DEFAULT_WORKER_LISTEN: &str = "127.0.0.1:24590";
pub const DEFAULT_NODE_CAPABILITIES: u64 = 0x0000_0000_0000_0001;

fn validate_worker_secret_boundary(root: &Path) -> Result<(), WorkerServiceError> {
    if !root.exists() {
        return Ok(());
    }

    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let path = entry.path();
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let is_msk = path
                .extension()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.eq_ignore_ascii_case("msk"));
            if is_msk {
                return Err(WorkerServiceError::InvalidAllowlist(
                    "worker directory contains forbidden .msk secret material",
                ));
            }
        }
    }
    Ok(())
}

pub fn prepare_runtime_state(
    data_dir: &Path,
    network_id: u32,
    worker_magic: u32,
) -> Result<WorkerServiceState, WorkerServiceError> {
    let mut state = WorkerServiceState::open(data_dir, network_id, worker_magic)?;
    validate_worker_secret_boundary(&state.paths.root)?;

    if !state.paths.allowlist.exists() {
        return Err(WorkerServiceError::InvalidAllowlist(
            "authorized-workers-v1.txt is required before worker service startup",
        ));
    }
    state.reload_allowlist()?;
    if state.allowed_workers.is_empty() {
        return Err(WorkerServiceError::InvalidAllowlist(
            "authorized-workers-v1.txt contains no WorkerIDs",
        ));
    }

    Ok(state)
}

pub fn serve_authenticated_workers_on_listener(
    state: &mut WorkerServiceState,
    listener: &TcpListener,
    node_signing_key: &SigningKey,
    max_connections: Option<u64>,
) -> Result<u64, WorkerServiceError> {
    if max_connections == Some(0) {
        return Err(WorkerServiceError::InvalidAllowlist(
            "--max-connections must be greater than zero",
        ));
    }

    let mut handled = 0u64;
    loop {
        let mut node_nonce = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut node_nonce);

        match state.accept_one(
            listener,
            node_signing_key,
            node_nonce,
            DEFAULT_NODE_CAPABILITIES,
        ) {
            Ok((stream, session)) => {
                println!(
                    "Pack-L worker authenticated: WorkerID={} SessionID={}",
                    hex32(&session.worker_id),
                    hex32(&session.session_id),
                );
                state.release_session(&session);
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            Err(error @ WorkerServiceError::Io(_)) => return Err(error),
            Err(error) => {
                eprintln!("Pack-L worker connection rejected: {error}");
            }
        }

        handled = handled.saturating_add(1);
        if max_connections.is_some_and(|max| handled >= max) {
            break;
        }
    }

    Ok(handled)
}

pub fn serve_authenticated_workers(
    data_dir: &Path,
    network_id: u32,
    worker_magic: u32,
    listen: &str,
    node_signing_key: &SigningKey,
    max_connections: Option<u64>,
) -> Result<u64, WorkerServiceError> {
    let mut state = prepare_runtime_state(data_dir, network_id, worker_magic)?;
    let listener = state.bind(listen)?;

    let node_id = mutiny_worker::endpoint::node_id_from_public_key(
        &node_signing_key.verifying_key().to_bytes(),
    );
    println!("Pack-L worker service listening on {listen}");
    println!("Pack-L worker magic: 0x{worker_magic:08x}");
    println!("Pack-L worker NodeID: {}", hex32(&node_id));
    println!(
        "Pack-L authorized WorkerIDs: {}",
        state.allowed_workers.len()
    );
    println!("Pack-L budget ledger: {}", state.paths.ledger.display());

    let handled = serve_authenticated_workers_on_listener(
        &mut state,
        &listener,
        node_signing_key,
        max_connections,
    )?;

    println!("Pack-L worker connections handled: {handled}");
    Ok(handled)
}

fn hex32(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in value {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedTicketAuthorityV1 {
    pub parent_block_hash: [u8; 32],
    pub parent_height: u64,
    pub target_epoch: u64,
    pub license_id: [u8; 32],
    pub ticket_index: u16,
    pub work_units_for_epoch: u16,
    pub eligible_license_count: u64,
    pub difficulty_c_q32: u64,
    pub anchor_entropy: [u8; 32],
    pub target: [u8; 32],
}

impl PreparedTicketAuthorityV1 {
    fn validate_consensus_math(&self) -> Result<(), WorkerServiceError> {
        if self.eligible_license_count == 0 {
            return Err(WorkerServiceError::Protocol(
                "eligible_license_count must be nonzero",
            ));
        }
        let expected_w = mutiny_consensus::work_units(self.eligible_license_count);
        if self.work_units_for_epoch != expected_w {
            return Err(WorkerServiceError::Protocol(
                "work_units_for_epoch does not match frozen Pack-A work_units",
            ));
        }
        if self.ticket_index >= expected_w {
            return Err(WorkerServiceError::Protocol(
                "ticket_index is outside frozen Pack-A work budget",
            ));
        }
        let expected_target = mutiny_consensus::derive_target(
            mutiny_consensus::authorized_capacity(self.eligible_license_count),
            self.difficulty_c_q32,
        )
        .map_err(|_| WorkerServiceError::Protocol("Pack-A target derivation failed"))?;
        if self.target != expected_target {
            return Err(WorkerServiceError::Protocol(
                "target does not match frozen Pack-A target derivation",
            ));
        }
        Ok(())
    }

    fn assignment_core(
        &self,
        session: &AuthenticatedWorkerSession,
        assignment_sequence: u64,
        network_id: u32,
    ) -> Result<WorkAssignmentCoreV1, WorkerServiceError> {
        self.validate_consensus_math()?;
        Ok(WorkAssignmentCoreV1 {
            network_id,
            session_id: session.session_id,
            assignment_sequence,
            worker_id: session.worker_id,
            node_id: session.node_id,
            parent_block_hash: self.parent_block_hash,
            parent_height: self.parent_height,
            target_epoch: self.target_epoch,
            license_id: self.license_id,
            ticket_index: self.ticket_index,
            work_units_for_epoch: self.work_units_for_epoch,
            eligible_license_count: self.eligible_license_count,
            anchor_entropy: self.anchor_entropy,
            target: self.target,
            expires_epoch: self.target_epoch,
            algorithm_id: ALGORITHM_PACK_A_ARGON2ID,
            algorithm_version: ALGORITHM_PACK_A_ARGON2ID_V1,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentDispatchOutcomeV1 {
    pub assignment: WorkAssignmentV1,
    pub result: WorkResultV1,
    pub new_unique_ticket: bool,
}

pub fn dispatch_one_prepared_ticket(
    state: &mut WorkerServiceState,
    stream: &mut TcpStream,
    session: &AuthenticatedWorkerSession,
    node_signing_key: &SigningKey,
    authority: &PreparedTicketAuthorityV1,
    assignment_sequence: u64,
    request_id: u64,
) -> Result<AssignmentDispatchOutcomeV1, WorkerServiceError> {
    if request_id == 0 {
        return Err(WorkerServiceError::Protocol(
            "WORK_ASSIGNMENT request_id must be nonzero",
        ));
    }
    if request_id == session.request_id {
        return Err(WorkerServiceError::Protocol(
            "WORK_ASSIGNMENT request_id must be fresh from handshake request_id",
        ));
    }

    let core = authority.assignment_core(session, assignment_sequence, state.network_id)?;

    let ticket_key = core.ticket_key();
    let assignment_id = core.assignment_id();

    let record = LedgerRecordV1 {
        ticket_key,
        parent_block_hash: core.parent_block_hash,
        target_epoch: core.target_epoch,
        license_id: core.license_id,
        ticket_index: core.ticket_index,
        work_units_for_epoch: core.work_units_for_epoch,
        worker_id: session.worker_id,
        session_id: session.session_id,
        assignment_id,
        assignment_sequence,
        status: STATUS_RESERVED,
    };

    // Pack-L mandatory order:
    // 1. caller prepared/validated branch authority;
    // 2. reserve TicketKey;
    // 3. atomically persist ledger;
    // 4. only now sign;
    // 5. only then transmit.
    let new_unique_ticket = state
        .ledger
        .reserve_and_persist(&state.paths.ledger, record)?;

    let assignment = WorkAssignmentV1::new_signed(core, node_signing_key)?;

    let frame = Frame::new(
        state.worker_magic,
        MSG_WORK_ASSIGNMENT,
        request_id,
        assignment.encode(),
    )
    .map_err(|e| WorkerServiceError::Endpoint(EndpointError::Frame(format!("{e:?}"))))?;
    frame
        .write_to(stream)
        .map_err(|e| WorkerServiceError::Endpoint(EndpointError::Frame(format!("{e:?}"))))?;

    state.ledger.update_status_and_persist(
        &state.paths.ledger,
        &assignment.assignment_id,
        STATUS_SENT,
    )?;

    let response = Frame::read_from(stream, state.worker_magic)
        .map_err(|e| WorkerServiceError::Endpoint(EndpointError::Frame(format!("{e:?}"))))?;
    if response.message_type != MSG_WORK_RESULT {
        return Err(WorkerServiceError::Protocol("expected WORK_RESULT message"));
    }
    if response.request_id != request_id {
        return Err(WorkerServiceError::Protocol(
            "WORK_RESULT request_id mismatch",
        ));
    }

    let result = WorkResultV1::decode(&response.payload)?;
    if result.core.network_id != state.network_id
        || result.core.session_id != session.session_id
        || result.core.assignment_id != assignment.assignment_id
        || result.core.ticket_key != assignment.ticket_key
        || result.core.worker_id != session.worker_id
    {
        return Err(WorkerServiceError::Protocol("WORK_RESULT binding mismatch"));
    }
    result.verify_worker_signature(&session.worker_public_key)?;

    let status = match result.core.result_kind {
        RESULT_NO_WIN => STATUS_COMPLETED_NO_WIN,
        RESULT_WIN => STATUS_CANDIDATE_WIN,
        _ => {
            return Err(WorkerServiceError::Protocol(
                "unknown WORK_RESULT result kind",
            ))
        }
    };
    state.ledger.update_status_and_persist(
        &state.paths.ledger,
        &assignment.assignment_id,
        status,
    )?;

    Ok(AssignmentDispatchOutcomeV1 {
        assignment,
        result,
        new_unique_ticket,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use mutiny_worker::endpoint::{initiate_worker_handshake, node_id_from_public_key};
    use mutiny_worker::{worker_id, WORKER_MAGIC_DEVNET};

    const NETWORK: u32 = 0x4D55_5403;

    fn temp_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mutiny-worker-service-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

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

    fn worker_id_hex(id: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for b in id {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }

    #[test]
    fn worker_paths_are_operational_and_outside_secret_directory() {
        let data = Path::new("node-a");
        let p = worker_service_paths(data);
        assert_eq!(p.root, PathBuf::from("node-a").join("worker"));
        assert_eq!(
            p.allowlist,
            PathBuf::from("node-a")
                .join("worker")
                .join("authorized-workers-v1.txt")
        );
        assert_eq!(
            p.ledger,
            PathBuf::from("node-a")
                .join("worker")
                .join("budget-ledger-v1.bin")
        );

        for path in [&p.root, &p.allowlist, &p.ledger] {
            let text = path.to_string_lossy().to_ascii_lowercase();
            assert!(!text.contains("secret"));
            assert!(!text.ends_with(".msk"));
        }
    }

    #[test]
    fn allowlist_accepts_comments_and_rejects_duplicates() {
        let dir = temp_dir("allowlist");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("workers.txt");

        let id = [0xAB; 32];
        fs::write(
            &file,
            format!("# Pack L local allowlist\n\n{}\n", worker_id_hex(&id)),
        )
        .unwrap();

        let parsed = load_worker_allowlist(&file).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed.contains(&id));

        fs::write(
            &file,
            format!("{}\n{}\n", worker_id_hex(&id), worker_id_hex(&id)),
        )
        .unwrap();
        assert!(matches!(
            load_worker_allowlist(&file),
            Err(WorkerServiceError::InvalidAllowlist("duplicate WorkerID"))
        ));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn allowlist_rejects_non_hex_and_private_key_like_lines() {
        let dir = temp_dir("allowlist-bad");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("workers.txt");

        fs::write(&file, "not-a-worker-id\n").unwrap();
        assert!(load_worker_allowlist(&file).is_err());

        fs::write(&file, "mining-operatorA-mining3.msk\n").unwrap();
        assert!(load_worker_allowlist(&file).is_err());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn service_open_creates_only_worker_operational_state() {
        let dir = temp_dir("open");
        let state = WorkerServiceState::open(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap();

        assert!(state.paths.root.is_dir());
        assert!(state.paths.ledger.is_file());
        assert!(!state.paths.allowlist.exists());

        let files: Vec<PathBuf> = fs::read_dir(&state.paths.root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files, vec![state.paths.ledger.clone()]);
        assert!(files
            .iter()
            .all(|p| { !p.to_string_lossy().to_ascii_lowercase().ends_with(".msk") }));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn node_crate_bridge_authenticates_worker_over_real_tcp() {
        let dir = temp_dir("tcp");
        let paths = worker_service_paths(&dir);
        fs::create_dir_all(&paths.root).unwrap();

        let worker = worker_key();
        let worker_id_value = worker_id(NETWORK, &worker.verifying_key().to_bytes());
        fs::write(
            &paths.allowlist,
            format!("{}\n", worker_id_hex(&worker_id_value)),
        )
        .unwrap();

        let mut state = WorkerServiceState::open(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap();
        let listener = state.bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let node = node_key();
        let expected_node_id = node_id_from_public_key(&node.verifying_key().to_bytes());

        let server = thread::spawn(move || {
            let (_stream, session) = state.accept_one(&listener, &node, [0x77; 32], 1).unwrap();
            assert!(state.active_workers.contains(&session.worker_id));
            state.release_session(&session);
            assert!(state.active_workers.is_empty());
            session
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let client_session = initiate_worker_handshake(
            &mut client,
            WORKER_MAGIC_DEVNET,
            NETWORK,
            &worker,
            [0x55; 32],
            1,
            2,
            0x0102_0304_0506_0708,
            expected_node_id,
        )
        .unwrap();

        let server_session = server.join().unwrap();
        assert_eq!(client_session, server_session);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn node_crate_bridge_rejects_unlisted_worker() {
        let dir = temp_dir("tcp-reject");
        let mut state = WorkerServiceState::open(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap();
        let listener = state.bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let node = node_key();
        let worker = worker_key();

        let server = thread::spawn(move || {
            let result = state.accept_one(&listener, &node, [0x78; 32], 0);
            matches!(
                result,
                Err(WorkerServiceError::Endpoint(
                    EndpointError::UnauthorizedWorker
                ))
            )
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let _ = client.write_all(&[]);
        let expected_node_id = [0u8; 32];
        let result = initiate_worker_handshake(
            &mut client,
            WORKER_MAGIC_DEVNET,
            NETWORK,
            &worker,
            [0x56; 32],
            0,
            1,
            0x1112_1314_1516_1718,
            expected_node_id,
        );
        assert!(result.is_err());
        assert!(server.join().unwrap());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_prepare_requires_nonempty_allowlist_and_rejects_msk() {
        let dir = temp_dir("runtime-boundary");
        let paths = worker_service_paths(&dir);

        let err = prepare_runtime_state(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap_err();
        assert!(matches!(
            err,
            WorkerServiceError::InvalidAllowlist(
                "authorized-workers-v1.txt is required before worker service startup"
            )
        ));

        fs::write(&paths.allowlist, "# no workers\n").unwrap();
        let err = prepare_runtime_state(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap_err();
        assert!(matches!(
            err,
            WorkerServiceError::InvalidAllowlist("authorized-workers-v1.txt contains no WorkerIDs")
        ));

        let worker = worker_key();
        let id = worker_id(NETWORK, &worker.verifying_key().to_bytes());
        fs::write(&paths.allowlist, format!("{}\n", worker_id_hex(&id))).unwrap();
        fs::write(paths.root.join("forbidden.msk"), b"not a real secret").unwrap();

        let err = prepare_runtime_state(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap_err();
        assert!(matches!(
            err,
            WorkerServiceError::InvalidAllowlist(
                "worker directory contains forbidden .msk secret material"
            )
        ));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_listener_uses_existing_node_identity_and_bounds_connections() {
        let dir = temp_dir("runtime-listener");
        let paths = worker_service_paths(&dir);
        fs::create_dir_all(&paths.root).unwrap();

        let worker = worker_key();
        let worker_id_value = worker_id(NETWORK, &worker.verifying_key().to_bytes());
        fs::write(
            &paths.allowlist,
            format!("{}\n", worker_id_hex(&worker_id_value)),
        )
        .unwrap();

        let mut state = prepare_runtime_state(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap();
        let listener = state.bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let node = node_key();
        let expected_node_id = node_id_from_public_key(&node.verifying_key().to_bytes());

        let server = thread::spawn(move || {
            let handled =
                serve_authenticated_workers_on_listener(&mut state, &listener, &node, Some(1))
                    .unwrap();
            assert_eq!(handled, 1);
            assert!(state.active_workers.is_empty());
            node_id_from_public_key(&node.verifying_key().to_bytes())
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let client_session = initiate_worker_handshake(
            &mut client,
            WORKER_MAGIC_DEVNET,
            NETWORK,
            &worker,
            [0x57; 32],
            1,
            2,
            0x3132_3334_3536_3738,
            expected_node_id,
        )
        .unwrap();

        assert_eq!(client_session.node_id, expected_node_id);
        assert_eq!(server.join().unwrap(), expected_node_id);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_listener_counts_rejected_connection_without_auth_authority() {
        let dir = temp_dir("runtime-reject");
        let paths = worker_service_paths(&dir);
        fs::create_dir_all(&paths.root).unwrap();

        fs::write(
            &paths.allowlist,
            format!("{}\n", worker_id_hex(&[0xAA; 32])),
        )
        .unwrap();
        let mut state = prepare_runtime_state(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap();
        let listener = state.bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let node = node_key();

        let server = thread::spawn(move || {
            serve_authenticated_workers_on_listener(&mut state, &listener, &node, Some(1)).unwrap()
        });

        let client = TcpStream::connect(addr).unwrap();
        drop(client);

        assert_eq!(server.join().unwrap(), 1);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pack_l_assignment_is_persisted_before_send_and_reference_worker_executes() {
        let dir = temp_dir("assignment-e2e");
        let paths = worker_service_paths(&dir);
        fs::create_dir_all(&paths.root).unwrap();

        let worker = worker_key();
        let worker_public_key = worker.verifying_key().to_bytes();
        let worker_id_value = worker_id(NETWORK, &worker_public_key);
        fs::write(
            &paths.allowlist,
            format!("{}\n", worker_id_hex(&worker_id_value)),
        )
        .unwrap();

        let mut state = WorkerServiceState::open(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap();
        state.reload_allowlist().unwrap();

        let listener = state.bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let node = node_key();
        let node_public_key = node.verifying_key().to_bytes();
        let expected_node_id = node_id_from_public_key(&node_public_key);

        let target =
            mutiny_consensus::derive_target(mutiny_consensus::authorized_capacity(1), 2u64 << 32)
                .unwrap();
        assert_eq!(target, [0xff; 32]);

        let authority = PreparedTicketAuthorityV1 {
            parent_block_hash: [0x11; 32],
            parent_height: 776,
            target_epoch: 131_075,
            license_id: [0x22; 32],
            ticket_index: 0,
            work_units_for_epoch: mutiny_consensus::work_units(1),
            eligible_license_count: 1,
            difficulty_c_q32: 2u64 << 32,
            anchor_entropy: [0x80; 32],
            target,
        };

        let ledger_path = paths.ledger.clone();
        let server = thread::spawn(move || {
            let (mut stream, session) = state.accept_one(&listener, &node, [0x79; 32], 1).unwrap();

            let outcome = dispatch_one_prepared_ticket(
                &mut state,
                &mut stream,
                &session,
                &node,
                &authority,
                1,
                0x1112_1314_1516_1718,
            )
            .unwrap();

            assert!(outcome.new_unique_ticket);
            assert_eq!(state.ledger.unique_ticket_count(), 1);
            assert_eq!(state.ledger.records.len(), 1);
            assert_eq!(
                state.ledger.records[0].assignment_id,
                outcome.assignment.assignment_id
            );
            assert_eq!(state.ledger.records[0].status, STATUS_CANDIDATE_WIN);

            state.release_session(&session);
            outcome
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        let client_session = initiate_worker_handshake(
            &mut client,
            WORKER_MAGIC_DEVNET,
            NETWORK,
            &worker,
            [0x59; 32],
            1,
            1,
            0x0102_0304_0506_0708,
            expected_node_id,
        )
        .unwrap();

        let worker_result = mutiny_worker::reference::process_one_assignment(
            &mut client,
            WORKER_MAGIC_DEVNET,
            &client_session,
            &node_public_key,
            &worker,
        )
        .unwrap();

        let outcome = server.join().unwrap();
        assert_eq!(worker_result, outcome.result);
        assert_eq!(outcome.result.core.result_kind, RESULT_WIN);
        outcome
            .result
            .verify_worker_signature(&worker_public_key)
            .unwrap();

        let recovered = WorkerBudgetLedgerV1::load_recover(&ledger_path, NETWORK).unwrap();
        assert_eq!(recovered.unique_ticket_count(), 1);
        assert_eq!(recovered.records[0].status, STATUS_CANDIDATE_WIN);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn prepared_authority_rejects_wrong_w_or_target_before_ticket_reservation() {
        let dir = temp_dir("assignment-math");
        let mut state = WorkerServiceState::open(&dir, NETWORK, WORKER_MAGIC_DEVNET).unwrap();

        let worker = worker_key();
        let worker_public_key = worker.verifying_key().to_bytes();
        let node = node_key();
        let session = AuthenticatedWorkerSession {
            worker_id: worker_id(NETWORK, &worker_public_key),
            worker_public_key,
            node_id: node_id_from_public_key(&node.verifying_key().to_bytes()),
            session_id: [0x72; 32],
            request_id: 1,
        };

        let bad = PreparedTicketAuthorityV1 {
            parent_block_hash: [0x11; 32],
            parent_height: 1,
            target_epoch: 2,
            license_id: [0x22; 32],
            ticket_index: 0,
            work_units_for_epoch: 3,
            eligible_license_count: 1,
            difficulty_c_q32: 1u64 << 32,
            anchor_entropy: [0x80; 32],
            target: [0xff; 32],
        };

        assert!(bad.assignment_core(&session, 1, NETWORK).is_err());
        assert_eq!(state.ledger.unique_ticket_count(), 0);

        state.ledger = WorkerBudgetLedgerV1::load_recover(&state.paths.ledger, NETWORK).unwrap();
        assert_eq!(state.ledger.unique_ticket_count(), 0);

        let _ = fs::remove_dir_all(dir);
    }
}
