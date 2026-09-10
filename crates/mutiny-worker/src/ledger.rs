use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ticket_key, PackLError};

const LEDGER_MAGIC: &[u8; 8] = b"MUTWLDG1";
const LEDGER_VERSION: u16 = 1;
const LEDGER_CHECKSUM_DOMAIN: &[u8] = b"MUTINY-WORKER-BUDGET-LEDGER-V1";
const HEADER_LEN: usize = 8 + 2 + 4 + 8 + 4;
const RECORD_LEN: usize = 32 + 32 + 8 + 32 + 2 + 2 + 32 + 32 + 32 + 8 + 1;
const CHECKSUM_LEN: usize = 32;

pub const STATUS_RESERVED: u8 = 0x01;
pub const STATUS_SENT: u8 = 0x02;
pub const STATUS_COMPLETED_NO_WIN: u8 = 0x03;
pub const STATUS_CANDIDATE_WIN: u8 = 0x04;
pub const STATUS_CANCELLED: u8 = 0x05;
pub const STATUS_INVALID_WIN: u8 = 0x06;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Pack-L error: {0}")]
    PackL(#[from] PackLError),
    #[error("ledger format error: {0}")]
    Format(&'static str),
    #[error("ledger checksum mismatch")]
    Checksum,
    #[error("assignment replay")]
    Replay,
    #[error("assignment not found")]
    AssignmentNotFound,
    #[error("ledger network mismatch")]
    NetworkMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRecordV1 {
    pub ticket_key: [u8; 32],
    pub parent_block_hash: [u8; 32],
    pub target_epoch: u64,
    pub license_id: [u8; 32],
    pub ticket_index: u16,
    pub work_units_for_epoch: u16,
    pub worker_id: [u8; 32],
    pub session_id: [u8; 32],
    pub assignment_id: [u8; 32],
    pub assignment_sequence: u64,
    pub status: u8,
}

impl LedgerRecordV1 {
    pub fn validate(&self, network_id: u32) -> Result<(), LedgerError> {
        if self.ticket_index >= self.work_units_for_epoch {
            return Err(PackLError::OutOfBudget.into());
        }
        if !matches!(
            self.status,
            STATUS_RESERVED
                | STATUS_SENT
                | STATUS_COMPLETED_NO_WIN
                | STATUS_CANDIDATE_WIN
                | STATUS_CANCELLED
                | STATUS_INVALID_WIN
        ) {
            return Err(LedgerError::Format("unknown record status"));
        }
        let expected = ticket_key(
            network_id,
            &self.parent_block_hash,
            self.target_epoch,
            &self.license_id,
            self.ticket_index,
        );
        if self.ticket_key != expected {
            return Err(LedgerError::Format("TicketKey derivation mismatch"));
        }
        Ok(())
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ticket_key);
        out.extend_from_slice(&self.parent_block_hash);
        out.extend_from_slice(&self.target_epoch.to_be_bytes());
        out.extend_from_slice(&self.license_id);
        out.extend_from_slice(&self.ticket_index.to_be_bytes());
        out.extend_from_slice(&self.work_units_for_epoch.to_be_bytes());
        out.extend_from_slice(&self.worker_id);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.assignment_id);
        out.extend_from_slice(&self.assignment_sequence.to_be_bytes());
        out.push(self.status);
    }

    fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        if bytes.len() != RECORD_LEN {
            return Err(LedgerError::Format("wrong record length"));
        }
        let mut p = 0usize;
        fn take<const N: usize>(bytes: &[u8], p: &mut usize) -> [u8; N] {
            let mut out = [0u8; N];
            out.copy_from_slice(&bytes[*p..*p + N]);
            *p += N;
            out
        }
        let value = Self {
            ticket_key: take::<32>(bytes, &mut p),
            parent_block_hash: take::<32>(bytes, &mut p),
            target_epoch: u64::from_be_bytes(take::<8>(bytes, &mut p)),
            license_id: take::<32>(bytes, &mut p),
            ticket_index: u16::from_be_bytes(take::<2>(bytes, &mut p)),
            work_units_for_epoch: u16::from_be_bytes(take::<2>(bytes, &mut p)),
            worker_id: take::<32>(bytes, &mut p),
            session_id: take::<32>(bytes, &mut p),
            assignment_id: take::<32>(bytes, &mut p),
            assignment_sequence: u64::from_be_bytes(take::<8>(bytes, &mut p)),
            status: bytes[p],
        };
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerBudgetLedgerV1 {
    pub network_id: u32,
    pub generation: u64,
    pub records: Vec<LedgerRecordV1>,
}

impl WorkerBudgetLedgerV1 {
    pub fn empty(network_id: u32) -> Self {
        Self {
            network_id,
            generation: 0,
            records: Vec::new(),
        }
    }

    pub fn unique_ticket_count(&self) -> usize {
        self.records
            .iter()
            .map(|r| r.ticket_key)
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub fn assignment_seen(&self, assignment_id: &[u8; 32]) -> bool {
        self.records
            .iter()
            .any(|r| &r.assignment_id == assignment_id)
    }

    pub fn ticket_seen(&self, ticket_key: &[u8; 32]) -> bool {
        self.records.iter().any(|r| &r.ticket_key == ticket_key)
    }

    pub fn encode(&self) -> Result<Vec<u8>, LedgerError> {
        let count: u32 = self
            .records
            .len()
            .try_into()
            .map_err(|_| LedgerError::Format("too many ledger records"))?;

        let mut body = Vec::with_capacity(HEADER_LEN + self.records.len() * RECORD_LEN);
        body.extend_from_slice(LEDGER_MAGIC);
        body.extend_from_slice(&LEDGER_VERSION.to_be_bytes());
        body.extend_from_slice(&self.network_id.to_be_bytes());
        body.extend_from_slice(&self.generation.to_be_bytes());
        body.extend_from_slice(&count.to_be_bytes());

        let mut assignment_ids = BTreeSet::new();
        for record in &self.records {
            record.validate(self.network_id)?;
            if !assignment_ids.insert(record.assignment_id) {
                return Err(LedgerError::Replay);
            }
            record.encode_into(&mut body);
        }

        let mut h = Sha256::new();
        h.update(LEDGER_CHECKSUM_DOMAIN);
        h.update(&body);
        let checksum: [u8; 32] = h.finalize().into();

        let mut out = body;
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        if bytes.len() < HEADER_LEN + CHECKSUM_LEN {
            return Err(LedgerError::Format("ledger file too short"));
        }
        let body_len = bytes.len() - CHECKSUM_LEN;
        let (body, checksum) = bytes.split_at(body_len);

        let mut h = Sha256::new();
        h.update(LEDGER_CHECKSUM_DOMAIN);
        h.update(body);
        let expected: [u8; 32] = h.finalize().into();
        if checksum != expected {
            return Err(LedgerError::Checksum);
        }

        let mut p = 0usize;
        if &body[p..p + 8] != LEDGER_MAGIC {
            return Err(LedgerError::Format("wrong ledger magic"));
        }
        p += 8;

        let version = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        p += 2;
        if version != LEDGER_VERSION {
            return Err(LedgerError::Format("unsupported ledger version"));
        }

        let network_id = u32::from_be_bytes(body[p..p + 4].try_into().unwrap());
        p += 4;
        let generation = u64::from_be_bytes(body[p..p + 8].try_into().unwrap());
        p += 8;
        let count = u32::from_be_bytes(body[p..p + 4].try_into().unwrap()) as usize;
        p += 4;

        let expected_body_len = HEADER_LEN
            .checked_add(
                count
                    .checked_mul(RECORD_LEN)
                    .ok_or(LedgerError::Format("record length overflow"))?,
            )
            .ok_or(LedgerError::Format("body length overflow"))?;
        if body.len() != expected_body_len {
            return Err(LedgerError::Format("record count/length mismatch"));
        }

        let mut records = Vec::with_capacity(count);
        let mut assignment_ids = BTreeSet::new();
        for _ in 0..count {
            let end = p + RECORD_LEN;
            let record = LedgerRecordV1::decode(&body[p..end])?;
            record.validate(network_id)?;
            if !assignment_ids.insert(record.assignment_id) {
                return Err(LedgerError::Replay);
            }
            records.push(record);
            p = end;
        }

        Ok(Self {
            network_id,
            generation,
            records,
        })
    }

    pub fn load(path: &Path, expected_network_id: u32) -> Result<Self, LedgerError> {
        let mut bytes = Vec::new();
        File::open(path)?.read_to_end(&mut bytes)?;
        let value = Self::decode(&bytes)?;
        if value.network_id != expected_network_id {
            return Err(LedgerError::NetworkMismatch);
        }
        Ok(value)
    }

    pub fn load_recover(path: &Path, expected_network_id: u32) -> Result<Self, LedgerError> {
        match Self::load(path, expected_network_id) {
            Ok(v) => Ok(v),
            Err(primary_error) => {
                let prev = companion(path, "prev");
                if prev.exists() {
                    Self::load(&prev, expected_network_id)
                } else {
                    Err(primary_error)
                }
            }
        }
    }

    pub fn open_or_create(path: &Path, network_id: u32) -> Result<Self, LedgerError> {
        if path.exists() || companion(path, "prev").exists() {
            Self::load_recover(path, network_id)
        } else {
            let value = Self::empty(network_id);
            commit_atomic(path, &value.encode()?)?;
            Ok(value)
        }
    }

    /// Reserve-before-send API.
    ///
    /// The record is validated and durably committed before this function returns.
    /// Callers MUST NOT transmit the corresponding WorkAssignmentV1 until this
    /// function has returned Ok.
    pub fn reserve_and_persist(
        &mut self,
        path: &Path,
        record: LedgerRecordV1,
    ) -> Result<bool, LedgerError> {
        record.validate(self.network_id)?;
        if self.assignment_seen(&record.assignment_id) {
            return Err(LedgerError::Replay);
        }

        let was_new_unique_ticket = !self.ticket_seen(&record.ticket_key);

        let mut candidate = self.clone();
        candidate.generation = candidate
            .generation
            .checked_add(1)
            .ok_or(LedgerError::Format("ledger generation overflow"))?;
        candidate.records.push(record);

        let bytes = candidate.encode()?;
        commit_atomic(path, &bytes)?;
        *self = candidate;

        Ok(was_new_unique_ticket)
    }

    pub fn update_status_and_persist(
        &mut self,
        path: &Path,
        assignment_id: &[u8; 32],
        new_status: u8,
    ) -> Result<(), LedgerError> {
        if !matches!(
            new_status,
            STATUS_RESERVED
                | STATUS_SENT
                | STATUS_COMPLETED_NO_WIN
                | STATUS_CANDIDATE_WIN
                | STATUS_CANCELLED
                | STATUS_INVALID_WIN
        ) {
            return Err(LedgerError::Format("unknown status transition"));
        }

        let mut candidate = self.clone();
        let record = candidate
            .records
            .iter_mut()
            .find(|r| &r.assignment_id == assignment_id)
            .ok_or(LedgerError::AssignmentNotFound)?;
        record.status = new_status;
        candidate.generation = candidate
            .generation
            .checked_add(1)
            .ok_or(LedgerError::Format("ledger generation overflow"))?;

        commit_atomic(path, &candidate.encode()?)?;
        *self = candidate;
        Ok(())
    }
}

fn companion(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".");
    os.push(suffix);
    PathBuf::from(os)
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

/// Crash-recoverable replacement protocol for Windows and Unix:
/// 1. write + sync `<ledger>.next`;
/// 2. remove stale `<ledger>.prev`;
/// 3. rename current ledger -> `<ledger>.prev`;
/// 4. rename synced `.next` -> current ledger.
///
/// `load_recover` accepts `.prev` only when the current file is absent/corrupt.
/// An uncommitted `.next` is never treated as authoritative.
fn commit_atomic(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let next = companion(path, "next");
    let prev = companion(path, "prev");

    if next.exists() {
        fs::remove_file(&next)?;
    }
    write_synced(&next, bytes)?;

    if prev.exists() {
        fs::remove_file(&prev)?;
    }
    if path.exists() {
        fs::rename(path, &prev)?;
    }

    if let Err(e) = fs::rename(&next, path) {
        if !path.exists() && prev.exists() {
            let _ = fs::rename(&prev, path);
        }
        return Err(e);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const NETWORK: u32 = 0x4D55_5403;

    fn temp_path(label: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mutiny-pack-l-ledger-{label}-{}-{n}.bin",
            std::process::id()
        ))
    }

    fn record(index: u16, w_e: u16, assignment_tag: u8) -> LedgerRecordV1 {
        let parent = [0x11; 32];
        let license = [0x22; 32];
        let key = ticket_key(NETWORK, &parent, 100, &license, index);
        LedgerRecordV1 {
            ticket_key: key,
            parent_block_hash: parent,
            target_epoch: 100,
            license_id: license,
            ticket_index: index,
            work_units_for_epoch: w_e,
            worker_id: [0x33; 32],
            session_id: [0x44; 32],
            assignment_id: [assignment_tag; 32],
            assignment_sequence: assignment_tag as u64,
            status: STATUS_RESERVED,
        }
    }

    #[test]
    fn empty_ledger_roundtrips() {
        let l = WorkerBudgetLedgerV1::empty(NETWORK);
        let bytes = l.encode().unwrap();
        let d = WorkerBudgetLedgerV1::decode(&bytes).unwrap();
        assert_eq!(d, l);
        assert_eq!(d.unique_ticket_count(), 0);
    }

    #[test]
    fn reserve_is_durable_before_return() {
        let path = temp_path("durable");
        let mut l = WorkerBudgetLedgerV1::open_or_create(&path, NETWORK).unwrap();
        assert!(l.reserve_and_persist(&path, record(0, 2, 1)).unwrap());

        let reloaded = WorkerBudgetLedgerV1::load(&path, NETWORK).unwrap();
        assert_eq!(reloaded.records.len(), 1);
        assert_eq!(reloaded.unique_ticket_count(), 1);
        assert_eq!(reloaded.records[0].status, STATUS_RESERVED);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(companion(&path, "prev"));
    }

    #[test]
    fn redundant_assignment_reuses_ticket_without_new_chance() {
        let path = temp_path("redundant");
        let mut l = WorkerBudgetLedgerV1::open_or_create(&path, NETWORK).unwrap();
        assert!(l.reserve_and_persist(&path, record(0, 2, 1)).unwrap());

        let mut r2 = record(0, 2, 2);
        r2.worker_id = [0x55; 32];
        r2.session_id = [0x66; 32];
        assert!(!l.reserve_and_persist(&path, r2).unwrap());
        assert_eq!(l.records.len(), 2);
        assert_eq!(l.unique_ticket_count(), 1);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(companion(&path, "prev"));
    }

    #[test]
    fn out_of_budget_is_rejected_before_disk_mutation() {
        let path = temp_path("budget");
        let mut l = WorkerBudgetLedgerV1::open_or_create(&path, NETWORK).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            l.reserve_and_persist(&path, record(2, 2, 1)),
            Err(LedgerError::PackL(PackLError::OutOfBudget))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(l.unique_ticket_count(), 0);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn duplicate_assignment_id_is_replay() {
        let path = temp_path("replay");
        let mut l = WorkerBudgetLedgerV1::open_or_create(&path, NETWORK).unwrap();
        l.reserve_and_persist(&path, record(0, 2, 1)).unwrap();

        let mut duplicate = record(1, 2, 1);
        duplicate.assignment_id = [1; 32];
        assert!(matches!(
            l.reserve_and_persist(&path, duplicate),
            Err(LedgerError::Replay)
        ));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(companion(&path, "prev"));
    }

    #[test]
    fn status_transition_is_crash_persistent() {
        let path = temp_path("status");
        let mut l = WorkerBudgetLedgerV1::open_or_create(&path, NETWORK).unwrap();
        l.reserve_and_persist(&path, record(0, 2, 1)).unwrap();
        l.update_status_and_persist(&path, &[1; 32], STATUS_SENT)
            .unwrap();

        let reloaded = WorkerBudgetLedgerV1::load(&path, NETWORK).unwrap();
        assert_eq!(reloaded.records[0].status, STATUS_SENT);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(companion(&path, "prev"));
    }

    #[test]
    fn corrupted_primary_recovers_previous_committed_generation() {
        let path = temp_path("recover");
        let mut l = WorkerBudgetLedgerV1::open_or_create(&path, NETWORK).unwrap();
        l.reserve_and_persist(&path, record(0, 2, 1)).unwrap();
        let generation_one = l.clone();
        l.reserve_and_persist(&path, record(1, 2, 2)).unwrap();

        let mut current = fs::read(&path).unwrap();
        let last = current.len() - 1;
        current[last] ^= 1;
        fs::write(&path, current).unwrap();

        let recovered = WorkerBudgetLedgerV1::load_recover(&path, NETWORK).unwrap();
        assert_eq!(recovered, generation_one);
        assert_eq!(recovered.unique_ticket_count(), 1);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(companion(&path, "prev"));
    }

    #[test]
    fn checksum_tamper_is_rejected_without_previous_file() {
        let path = temp_path("checksum");
        let l = WorkerBudgetLedgerV1::empty(NETWORK);
        fs::write(&path, l.encode().unwrap()).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 1;
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            WorkerBudgetLedgerV1::load_recover(&path, NETWORK),
            Err(LedgerError::Checksum)
        ));

        let _ = fs::remove_file(&path);
    }
}
