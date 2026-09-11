use sha2::{Digest, Sha256};
use std::{
    env, fs,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(crate) const STORAGE_FORMAT_VERSION: u16 = 1;
const META_MAGIC: &[u8; 8] = b"MUTSTG01";
const SNAPSHOT_MAGIC: &[u8; 8] = b"MUTSNP01";
const JOURNAL_MAGIC: &[u8; 8] = b"MUTJRN01";
const META_LEN: usize = 222;
const JOURNAL_LEN: usize = 90;
const SNAPSHOT_HEADER_LEN: usize = 26;
const HASH_LEN: usize = 32;
const RETAIN_GENERATIONS: usize = 2;
const CRASH_ENV: &str = "MUTINY_DEV_STORAGE_CRASH_AFTER";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SnapshotIdentity {
    pub network_id: u32,
    pub genesis_id: [u8; 32],
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub chainwork: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StorageMetaV1 {
    pub network_id: u32,
    pub genesis_id: [u8; 32],
    pub generation: u64,
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub chainwork: [u8; 32],
    pub snapshot_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryAction {
    None,
    RolledBackPrepared,
    FinalizedCommitted,
}

#[derive(Debug)]
pub(crate) struct LoadedSnapshot {
    pub bytes: Vec<u8>,
    pub meta: StorageMetaV1,
    pub recovery: RecoveryAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JournalV1 {
    generation: u64,
    previous_generation: u64,
    snapshot_sha256: [u8; 32],
}

fn storage_dir(dir: &Path) -> PathBuf {
    dir.join("storage")
}
fn state_dir(dir: &Path) -> PathBuf {
    storage_dir(dir).join("state")
}
fn migration_dir(dir: &Path) -> PathBuf {
    storage_dir(dir).join("migrations")
}
fn meta_path(dir: &Path) -> PathBuf {
    storage_dir(dir).join("meta.bin")
}
fn journal_path(dir: &Path) -> PathBuf {
    storage_dir(dir).join("canonical.commit")
}
fn archived_legacy_path(dir: &Path) -> PathBuf {
    migration_dir(dir).join("legacy-state-v59.json")
}
fn snapshot_path(dir: &Path, generation: u64) -> PathBuf {
    state_dir(dir).join(format!("generation-{generation:020}.mst"))
}

pub(crate) fn exists(dir: &Path) -> bool {
    meta_path(dir).exists() || journal_path(dir).exists() || archived_legacy_path(dir).exists()
}

pub(crate) fn reset_for_init(dir: &Path) -> Result<(), String> {
    let path = storage_dir(dir);
    if path.exists() {
        fs::remove_dir_all(&path).map_err(|e| format!("remove {}: {e}", path.display()))?;
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn encode_meta(meta: &StorageMetaV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(META_LEN);
    out.extend_from_slice(META_MAGIC);
    out.extend_from_slice(&STORAGE_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&meta.network_id.to_be_bytes());
    out.extend_from_slice(&meta.genesis_id);
    out.extend_from_slice(&meta.generation.to_be_bytes());
    out.extend_from_slice(&meta.height.to_be_bytes());
    out.extend_from_slice(&meta.tip_hash);
    out.extend_from_slice(&meta.state_root);
    out.extend_from_slice(&meta.chainwork);
    out.extend_from_slice(&meta.snapshot_sha256);
    let digest = sha256(&out);
    out.extend_from_slice(&digest);
    debug_assert_eq!(out.len(), META_LEN);
    out
}

fn decode_meta(bytes: &[u8]) -> Result<StorageMetaV1, String> {
    if bytes.len() != META_LEN {
        return Err(format!("storage meta length {} != {META_LEN}", bytes.len()));
    }
    if &bytes[..8] != META_MAGIC {
        return Err("storage meta magic mismatch".into());
    }
    let version = u16::from_be_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| "storage meta version")?,
    );
    if version != STORAGE_FORMAT_VERSION {
        return Err(format!("unsupported storage format version {version}; this Build 6.0 candidate supports only {STORAGE_FORMAT_VERSION}"));
    }
    let expected = sha256(&bytes[..META_LEN - HASH_LEN]);
    if expected.as_slice() != &bytes[META_LEN - HASH_LEN..] {
        return Err("storage meta checksum mismatch".into());
    }
    let mut genesis_id = [0u8; 32];
    genesis_id.copy_from_slice(&bytes[14..46]);
    let mut tip_hash = [0u8; 32];
    tip_hash.copy_from_slice(&bytes[62..94]);
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(&bytes[94..126]);
    let mut chainwork = [0u8; 32];
    chainwork.copy_from_slice(&bytes[126..158]);
    let mut snapshot_sha256 = [0u8; 32];
    snapshot_sha256.copy_from_slice(&bytes[158..190]);
    Ok(StorageMetaV1 {
        network_id: u32::from_be_bytes(
            bytes[10..14]
                .try_into()
                .map_err(|_| "storage meta NetworkID")?,
        ),
        genesis_id,
        generation: u64::from_be_bytes(
            bytes[46..54]
                .try_into()
                .map_err(|_| "storage meta generation")?,
        ),
        height: u64::from_be_bytes(
            bytes[54..62]
                .try_into()
                .map_err(|_| "storage meta height")?,
        ),
        tip_hash,
        state_root,
        chainwork,
        snapshot_sha256,
    })
}

fn encode_journal(journal: &JournalV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(JOURNAL_LEN);
    out.extend_from_slice(JOURNAL_MAGIC);
    out.extend_from_slice(&STORAGE_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&journal.generation.to_be_bytes());
    out.extend_from_slice(&journal.previous_generation.to_be_bytes());
    out.extend_from_slice(&journal.snapshot_sha256);
    let digest = sha256(&out);
    out.extend_from_slice(&digest);
    debug_assert_eq!(out.len(), JOURNAL_LEN);
    out
}

fn decode_journal(bytes: &[u8]) -> Result<JournalV1, String> {
    if bytes.len() != JOURNAL_LEN {
        return Err(format!(
            "storage journal length {} != {JOURNAL_LEN}",
            bytes.len()
        ));
    }
    if &bytes[..8] != JOURNAL_MAGIC {
        return Err("storage journal magic mismatch".into());
    }
    let version = u16::from_be_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| "storage journal version")?,
    );
    if version != STORAGE_FORMAT_VERSION {
        return Err(format!("unsupported storage journal version {version}"));
    }
    let expected = sha256(&bytes[..JOURNAL_LEN - HASH_LEN]);
    if expected.as_slice() != &bytes[JOURNAL_LEN - HASH_LEN..] {
        return Err("storage journal checksum mismatch".into());
    }
    let mut snapshot_sha256 = [0u8; 32];
    snapshot_sha256.copy_from_slice(&bytes[26..58]);
    Ok(JournalV1 {
        generation: u64::from_be_bytes(
            bytes[10..18]
                .try_into()
                .map_err(|_| "storage journal generation")?,
        ),
        previous_generation: u64::from_be_bytes(
            bytes[18..26]
                .try_into()
                .map_err(|_| "storage journal previous generation")?,
        ),
        snapshot_sha256,
    })
}

fn encode_snapshot(generation: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SNAPSHOT_HEADER_LEN + payload.len() + HASH_LEN);
    out.extend_from_slice(SNAPSHOT_MAGIC);
    out.extend_from_slice(&STORAGE_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    let digest = sha256(&out);
    out.extend_from_slice(&digest);
    out
}

fn decode_snapshot(bytes: &[u8], expected_generation: u64) -> Result<Vec<u8>, String> {
    if bytes.len() < SNAPSHOT_HEADER_LEN + HASH_LEN {
        return Err("storage snapshot truncated".into());
    }
    if &bytes[..8] != SNAPSHOT_MAGIC {
        return Err("storage snapshot magic mismatch".into());
    }
    let version = u16::from_be_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| "storage snapshot version")?,
    );
    if version != STORAGE_FORMAT_VERSION {
        return Err(format!("unsupported storage snapshot version {version}"));
    }
    let generation = u64::from_be_bytes(
        bytes[10..18]
            .try_into()
            .map_err(|_| "storage snapshot generation")?,
    );
    if generation != expected_generation {
        return Err("storage snapshot generation mismatch".into());
    }
    let payload_len = u64::from_be_bytes(
        bytes[18..26]
            .try_into()
            .map_err(|_| "storage snapshot payload length")?,
    );
    let payload_len =
        usize::try_from(payload_len).map_err(|_| "storage snapshot payload length overflow")?;
    let expected_len = SNAPSHOT_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|x| x.checked_add(HASH_LEN))
        .ok_or("storage snapshot length overflow")?;
    if bytes.len() != expected_len {
        return Err(format!(
            "storage snapshot length {} != expected {expected_len}",
            bytes.len()
        ));
    }
    let checksum_offset = expected_len - HASH_LEN;
    let digest = sha256(&bytes[..checksum_offset]);
    if digest.as_slice() != &bytes[checksum_offset..] {
        return Err("storage snapshot checksum mismatch".into());
    }
    Ok(bytes[SNAPSHOT_HEADER_LEN..checksum_offset].to_vec())
}

fn read_all(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(bytes)
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("open {} for durable write: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    file.sync_all()
        .map_err(|e| format!("sync {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("sync directory {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn replace_synced(tmp: &Path, final_path: &Path) -> Result<(), String> {
    fs::rename(tmp, final_path)
        .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), final_path.display()))?;
    if let Some(parent) = final_path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn remove_synced(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_file(path).map_err(|e| format!("remove {}: {e}", path.display()))?;
    }
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn maybe_crash(phase: &str) {
    if env::var(CRASH_ENV).ok().as_deref() == Some(phase) {
        eprintln!("Build 6.0 DEV storage failpoint: aborting after {phase}");
        std::process::abort();
    }
}

fn read_meta_if_present(dir: &Path) -> Result<Option<StorageMetaV1>, String> {
    let path = meta_path(dir);
    if !path.exists() {
        return Ok(None);
    }
    decode_meta(&read_all(&path)?).map(Some)
}

fn verify_snapshot_for_meta(dir: &Path, meta: &StorageMetaV1) -> Result<Vec<u8>, String> {
    let path = snapshot_path(dir, meta.generation);
    let framed = read_all(&path)?;
    if sha256(&framed) != meta.snapshot_sha256 {
        return Err("storage snapshot file hash does not match meta".into());
    }
    decode_snapshot(&framed, meta.generation)
}

fn recover(dir: &Path) -> Result<RecoveryAction, String> {
    fs::create_dir_all(state_dir(dir)).map_err(|e| e.to_string())?;
    fs::create_dir_all(migration_dir(dir)).map_err(|e| e.to_string())?;
    let journal_file = journal_path(dir);
    if !journal_file.exists() {
        return Ok(RecoveryAction::None);
    }
    let journal = decode_journal(&read_all(&journal_file)?)?;
    let meta = read_meta_if_present(dir)?;
    match meta {
        Some(ref m) if m.generation == journal.generation => {
            if m.snapshot_sha256 != journal.snapshot_sha256 {
                return Err("committed storage meta and journal snapshot hashes disagree".into());
            }
            verify_snapshot_for_meta(dir, m)?;
            remove_synced(&journal_file)?;
            Ok(RecoveryAction::FinalizedCommitted)
        }
        Some(ref m) if m.generation == journal.previous_generation => {
            let staged = snapshot_path(dir, journal.generation);
            if staged.exists() {
                let framed = read_all(&staged)?;
                if sha256(&framed) != journal.snapshot_sha256 {
                    return Err("prepared snapshot hash mismatch during rollback".into());
                }
                remove_synced(&staged)?;
            }
            remove_synced(&journal_file)?;
            Ok(RecoveryAction::RolledBackPrepared)
        }
        None if journal.previous_generation == 0 => {
            let staged = snapshot_path(dir, journal.generation);
            if staged.exists() {
                let framed = read_all(&staged)?;
                if sha256(&framed) != journal.snapshot_sha256 {
                    return Err("initial prepared snapshot hash mismatch during rollback".into());
                }
                remove_synced(&staged)?;
            }
            remove_synced(&journal_file)?;
            Ok(RecoveryAction::RolledBackPrepared)
        }
        Some(m) => Err(format!(
            "storage journal/meta generation conflict: meta={}, prepared={}, previous={}",
            m.generation, journal.generation, journal.previous_generation
        )),
        None => Err("storage journal references a previous generation but meta is missing".into()),
    }
}

/// Bind the selected network before recovery can remove a prepared generation
/// or finalize its journal. This reads the existing metadata encoding only.
pub(crate) fn load_snapshot_for_network(
    dir: &Path,
    network_id: u32,
    genesis_id: Option<[u8; 32]>,
    validate_recovery: impl FnOnce(&[u8], &StorageMetaV1) -> Result<(), String>,
) -> Result<Option<LoadedSnapshot>, String> {
    match read_meta_if_present(dir)? {
        Some(meta) => {
            if meta.network_id != network_id || genesis_id.is_some_and(|id| id != meta.genesis_id) {
                return Err(
                    "selected runtime does not match storage identity before recovery".into(),
                );
            }
            if journal_path(dir).exists() {
                let bytes = verify_snapshot_for_meta(dir, &meta)?;
                validate_recovery(&bytes, &meta)?;
            }
        }
        None => {
            if genesis_id.is_some()
                && (journal_path(dir).exists()
                    || archived_legacy_path(dir).exists()
                    || dir.join("state.json").exists())
            {
                return Err(
                    "cannot authenticate selected storage network before recovery or migration"
                        .into(),
                );
            }
        }
    }
    load_snapshot(dir)
}

/// Read only the committed snapshot. Refuse recovery or migration so a command
/// can finish all pre-commit validation without changing the input directory.
pub(crate) fn load_snapshot_read_only(dir: &Path) -> Result<Option<LoadedSnapshot>, String> {
    if journal_path(dir).exists() {
        return Err("bootstrap-mainnet requires clean storage without a pending journal".into());
    }
    let Some(meta) = read_meta_if_present(dir)? else {
        return Ok(None);
    };
    let bytes = verify_snapshot_for_meta(dir, &meta)?;
    Ok(Some(LoadedSnapshot {
        bytes,
        meta,
        recovery: RecoveryAction::None,
    }))
}

pub(crate) fn load_snapshot(dir: &Path) -> Result<Option<LoadedSnapshot>, String> {
    let recovery = recover(dir)?;
    let Some(meta) = read_meta_if_present(dir)? else {
        return Ok(None);
    };
    let bytes = verify_snapshot_for_meta(dir, &meta)?;
    Ok(Some(LoadedSnapshot {
        bytes,
        meta,
        recovery,
    }))
}

pub(crate) fn commit_snapshot(
    dir: &Path,
    payload: &[u8],
    identity: &SnapshotIdentity,
) -> Result<StorageMetaV1, String> {
    let _ = recover(dir)?;
    fs::create_dir_all(state_dir(dir)).map_err(|e| e.to_string())?;
    let previous = read_meta_if_present(dir)?;
    let previous_generation = previous.as_ref().map(|m| m.generation).unwrap_or(0);
    let generation = previous_generation
        .checked_add(1)
        .ok_or("storage generation overflow")?;
    let framed = encode_snapshot(generation, payload);
    let snapshot_sha256 = sha256(&framed);
    let journal = JournalV1 {
        generation,
        previous_generation,
        snapshot_sha256,
    };

    maybe_crash("before-journal");
    let journal_tmp = journal_path(dir).with_extension("commit.tmp");
    write_synced(&journal_tmp, &encode_journal(&journal))?;
    replace_synced(&journal_tmp, &journal_path(dir))?;
    maybe_crash("journal");

    let snapshot = snapshot_path(dir, generation);
    let snapshot_tmp = snapshot.with_extension("mst.tmp");
    write_synced(&snapshot_tmp, &framed)?;
    maybe_crash("snapshot-tmp");
    replace_synced(&snapshot_tmp, &snapshot)?;
    maybe_crash("snapshot");

    let meta = StorageMetaV1 {
        network_id: identity.network_id,
        genesis_id: identity.genesis_id,
        generation,
        height: identity.height,
        tip_hash: identity.tip_hash,
        state_root: identity.state_root,
        chainwork: identity.chainwork,
        snapshot_sha256,
    };
    let meta_tmp = meta_path(dir).with_extension("bin.tmp");
    write_synced(&meta_tmp, &encode_meta(&meta))?;
    maybe_crash("meta-tmp");
    replace_synced(&meta_tmp, &meta_path(dir))?;
    maybe_crash("meta");

    maybe_crash("before-finalize");
    remove_synced(&journal_path(dir))?;
    maybe_crash("finalize");
    prune_old_snapshots(dir, generation)?;
    maybe_crash("prune");
    Ok(meta)
}

fn prune_old_snapshots(dir: &Path, current_generation: u64) -> Result<(), String> {
    let mut generations = Vec::new();
    for entry in fs::read_dir(state_dir(dir)).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(number) = name
            .strip_prefix("generation-")
            .and_then(|x| x.strip_suffix(".mst"))
        {
            if let Ok(generation) = number.parse::<u64>() {
                generations.push((generation, entry.path()));
            }
        }
    }
    generations.sort_by_key(|(generation, _)| *generation);
    let keep_from = generations.len().saturating_sub(RETAIN_GENERATIONS);
    for (generation, path) in generations.into_iter().take(keep_from) {
        if generation != current_generation {
            remove_synced(&path)?;
        }
    }
    Ok(())
}

pub(crate) fn prepare_legacy_migration(
    dir: &Path,
    legacy_root: &Path,
) -> Result<Option<PathBuf>, String> {
    fs::create_dir_all(migration_dir(dir)).map_err(|e| e.to_string())?;
    let archived = archived_legacy_path(dir);
    match (legacy_root.exists(), archived.exists()) {
        (false, false) => Ok(None),
        (false, true) => Ok(Some(archived)),
        (true, false) => {
            fs::rename(legacy_root, &archived).map_err(|e| format!("stage legacy state migration {} -> {}: {e}", legacy_root.display(), archived.display()))?;
            sync_dir(dir)?;
            sync_dir(&migration_dir(dir))?;
            Ok(Some(archived))
        }
        (true, true) => Err("both root legacy state.json and staged Build 5.9 migration source exist; refusing ambiguous migration".into()),
    }
}

pub(crate) fn inspect_meta(dir: &Path) -> Result<Option<StorageMetaV1>, String> {
    if journal_path(dir).exists() {
        return Err("storage recovery is pending; run a state-loading command such as `mutinyd storage-verify` before inspection".into());
    }
    read_meta_if_present(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "mutiny-build60-storage-{tag}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn identity(height: u64) -> SnapshotIdentity {
        SnapshotIdentity {
            network_id: 0x4d55_5403,
            genesis_id: [0x11; 32],
            height,
            tip_hash: [height as u8; 32],
            state_root: [0x22; 32],
            chainwork: [0x33; 32],
        }
    }

    #[test]
    fn meta_roundtrip_fixed_length() {
        let meta = StorageMetaV1 {
            network_id: 7,
            genesis_id: [1; 32],
            generation: 9,
            height: 8,
            tip_hash: [2; 32],
            state_root: [3; 32],
            chainwork: [4; 32],
            snapshot_sha256: [5; 32],
        };
        let bytes = encode_meta(&meta);
        assert_eq!(bytes.len(), META_LEN);
        assert_eq!(decode_meta(&bytes).unwrap(), meta);
    }

    #[test]
    fn snapshot_roundtrip_and_checksum_rejection() {
        let bytes = encode_snapshot(3, b"hello");
        assert_eq!(decode_snapshot(&bytes, 3).unwrap(), b"hello");
        let mut bad = bytes;
        bad[27] ^= 1;
        assert!(decode_snapshot(&bad, 3).is_err());
    }

    #[test]
    fn journal_roundtrip_fixed_length() {
        let journal = JournalV1 {
            generation: 4,
            previous_generation: 3,
            snapshot_sha256: [7; 32],
        };
        let bytes = encode_journal(&journal);
        assert_eq!(bytes.len(), JOURNAL_LEN);
        assert_eq!(decode_journal(&bytes).unwrap(), journal);
    }

    #[test]
    fn commit_and_load_snapshot() {
        let dir = temp_dir("commit");
        let meta = commit_snapshot(&dir, b"state-one", &identity(1)).unwrap();
        assert_eq!(meta.generation, 1);
        let loaded = load_snapshot(&dir).unwrap().unwrap();
        assert_eq!(loaded.bytes, b"state-one");
        assert_eq!(loaded.recovery, RecoveryAction::None);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn prepared_generation_rolls_back_to_previous_meta() {
        let dir = temp_dir("rollback");
        let first = commit_snapshot(&dir, b"one", &identity(1)).unwrap();
        let generation = first.generation + 1;
        let framed = encode_snapshot(generation, b"two");
        let hash = sha256(&framed);
        let journal = JournalV1 {
            generation,
            previous_generation: first.generation,
            snapshot_sha256: hash,
        };
        write_synced(&journal_path(&dir), &encode_journal(&journal)).unwrap();
        write_synced(&snapshot_path(&dir, generation), &framed).unwrap();
        let loaded = load_snapshot(&dir).unwrap().unwrap();
        assert_eq!(loaded.recovery, RecoveryAction::RolledBackPrepared);
        assert_eq!(loaded.bytes, b"one");
        assert!(!snapshot_path(&dir, generation).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn committed_generation_with_leftover_journal_finalizes() {
        let dir = temp_dir("finalize");
        let first = commit_snapshot(&dir, b"one", &identity(1)).unwrap();
        let generation = first.generation + 1;
        let framed = encode_snapshot(generation, b"two");
        let hash = sha256(&framed);
        let journal = JournalV1 {
            generation,
            previous_generation: first.generation,
            snapshot_sha256: hash,
        };
        write_synced(&snapshot_path(&dir, generation), &framed).unwrap();
        let id = identity(2);
        let meta = StorageMetaV1 {
            network_id: id.network_id,
            genesis_id: id.genesis_id,
            generation,
            height: id.height,
            tip_hash: id.tip_hash,
            state_root: id.state_root,
            chainwork: id.chainwork,
            snapshot_sha256: hash,
        };
        write_synced(&meta_path(&dir), &encode_meta(&meta)).unwrap();
        write_synced(&journal_path(&dir), &encode_journal(&journal)).unwrap();
        let loaded = load_snapshot(&dir).unwrap().unwrap();
        assert_eq!(loaded.recovery, RecoveryAction::FinalizedCommitted);
        assert_eq!(loaded.bytes, b"two");
        assert!(!journal_path(&dir).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_meta_fails_closed() {
        let dir = temp_dir("corrupt-meta");
        commit_snapshot(&dir, b"one", &identity(1)).unwrap();
        let path = meta_path(&dir);
        let mut bytes = read_all(&path).unwrap();
        bytes[20] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(load_snapshot(&dir).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_migration_is_resumable_after_root_rename() {
        let dir = temp_dir("legacy");
        let legacy = dir.join("state.json");
        fs::write(&legacy, b"legacy").unwrap();
        let staged = prepare_legacy_migration(&dir, &legacy).unwrap().unwrap();
        assert!(!legacy.exists());
        assert_eq!(fs::read(&staged).unwrap(), b"legacy");
        assert_eq!(
            prepare_legacy_migration(&dir, &legacy).unwrap().unwrap(),
            staged
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn future_storage_version_fails_closed() {
        let meta = StorageMetaV1 {
            network_id: 7,
            genesis_id: [1; 32],
            generation: 9,
            height: 8,
            tip_hash: [2; 32],
            state_root: [3; 32],
            chainwork: [4; 32],
            snapshot_sha256: [5; 32],
        };
        let mut bytes = encode_meta(&meta);
        bytes[8..10].copy_from_slice(&2u16.to_be_bytes());
        assert!(decode_meta(&bytes)
            .unwrap_err()
            .contains("unsupported storage format version"));
    }

    #[test]
    fn missing_referenced_snapshot_fails_closed() {
        let dir = temp_dir("missing-snapshot");
        let meta = commit_snapshot(&dir, b"one", &identity(1)).unwrap();
        fs::remove_file(snapshot_path(&dir, meta.generation)).unwrap();
        assert!(load_snapshot(&dir).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn retains_only_current_and_previous_snapshot() {
        let dir = temp_dir("retention");
        commit_snapshot(&dir, b"one", &identity(1)).unwrap();
        commit_snapshot(&dir, b"two", &identity(2)).unwrap();
        let third = commit_snapshot(&dir, b"three", &identity(3)).unwrap();
        assert_eq!(third.generation, 3);
        assert!(!snapshot_path(&dir, 1).exists());
        assert!(snapshot_path(&dir, 2).exists());
        assert!(snapshot_path(&dir, 3).exists());
        let _ = fs::remove_dir_all(dir);
    }
}
