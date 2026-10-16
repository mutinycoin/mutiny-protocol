//! Streaming, independently replay-verified canonical checkpoint archive.
//! It is not a wallet/voter backup and never exports private custody or pending
//! transactions. No source record is pruned or trusted merely from this archive.
use super::*;
use minicbor::{Decoder, Encoder, data::Type};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
};
const MAGIC: &[u8; 8] = b"B8CHECK2";
#[cfg(test)]
mod manifest_tests {
    use super::*;
    #[test]
    fn full_retention_frontier_and_exact_finalized_anchor_are_required() {
        let genesis = [1; 32];
        let fp = [2; 32];
        let initial = FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis,
            fingerprint: fp,
            height: 0,
            block: [3; 32],
        };
        let finalized = FinalizedAnchor {
            height: 60,
            block: [4; 32],
            ..initial.clone()
        };
        let encode = |anchor: &FinalizedAnchor, frontier: u64| {
            let mut e = Encoder::new(Vec::new());
            e.array(13)
                .unwrap()
                .u8(2)
                .unwrap()
                .u32(crate::NETWORK_ID)
                .unwrap()
                .bytes(&genesis)
                .unwrap()
                .bytes(&fp)
                .unwrap()
                .bytes(&initial.encode())
                .unwrap()
                .u64(60)
                .unwrap()
                .bytes(&[4; 32])
                .unwrap()
                .bytes(&[5; 32])
                .unwrap()
                .bytes(&[6; 32])
                .unwrap()
                .u64(3600)
                .unwrap()
                .u64(7)
                .unwrap()
                .bytes(&anchor.encode())
                .unwrap()
                .u64(frontier)
                .unwrap();
            e.into_writer()
        };
        assert!(decode_manifest(&encode(&finalized, 0)).is_ok());
        assert!(decode_manifest(&encode(&finalized, 1)).is_err());
        assert!(decode_manifest(&encode(&initial, 0)).is_err());
        let mut wrong = finalized.clone();
        wrong.fingerprint = [9; 32];
        assert!(decode_manifest(&encode(&wrong, 0)).is_err());
    }
}
pub(super) fn import_marker(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(".checkpoint-import");
    PathBuf::from(p)
}
#[derive(Debug)]
pub enum CheckpointError {
    Chain(ChainError),
    Io(std::io::Error),
    Invalid,
    Capacity,
}
impl From<ChainError> for CheckpointError {
    fn from(e: ChainError) -> Self {
        Self::Chain(e)
    }
}
impl From<rusqlite::Error> for CheckpointError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Chain(e.into())
    }
}
impl From<Error> for CheckpointError {
    fn from(e: Error) -> Self {
        Self::Chain(e.into())
    }
}
impl From<std::io::Error> for CheckpointError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
type CResult<T> = std::result::Result<T, CheckpointError>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSummary {
    pub tip: Tip,
    pub records: u64,
    pub archive_hash: Hash,
    pub bytes: u64,
    pub retention_frontier: u64,
}
struct Output {
    file: BufWriter<File>,
    hash: Sha256,
    bytes: u64,
    budget: u64,
}
impl Output {
    fn write(&mut self, b: &[u8]) -> CResult<()> {
        self.bytes = self
            .bytes
            .checked_add(b.len() as u64)
            .ok_or(CheckpointError::Capacity)?;
        if self.bytes.checked_add(32).is_none_or(|n| n > self.budget) {
            return Err(CheckpointError::Capacity);
        }
        self.file.write_all(b)?;
        self.hash.update(b);
        Ok(())
    }
    fn frame(&mut self, b: &[u8]) -> CResult<()> {
        let n = u32::try_from(b.len()).map_err(|_| CheckpointError::Capacity)?;
        self.write(&n.to_be_bytes())?;
        self.write(b)
    }
}
struct Input {
    file: BufReader<File>,
    hash: Sha256,
}
impl Input {
    fn read(&mut self, n: usize) -> CResult<Vec<u8>> {
        let mut b = vec![0; n];
        self.file.read_exact(&mut b)?;
        self.hash.update(&b);
        Ok(b)
    }
    fn frame(&mut self, limit: usize) -> CResult<Vec<u8>> {
        let len = u32::from_be_bytes(self.read(4)?.try_into().unwrap()) as usize;
        if len > limit {
            return Err(CheckpointError::Capacity);
        }
        let b = self.read(len)?;
        crate::blocks::canonical(&b, limit)?;
        Ok(b)
    }
}
fn record(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(2)
        .unwrap()
        .bytes(key)
        .unwrap()
        .bytes(value)
        .unwrap();
    e.into_writer()
}
fn recovery_frame(db: &Connection, height: u64) -> CResult<Vec<u8>> {
    let row: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT certificate,losses FROM recovery_overlay WHERE base_height=?1",
            [height.to_be_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((certificate, losses)) = row else {
        return Ok(vec![0xf6]);
    };
    let witness: Option<Vec<u8>> = db
        .query_row(
            "SELECT witness FROM recovery_material WHERE base_height=?1",
            [height.to_be_bytes().as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .bytes(&certificate)
        .unwrap()
        .bytes(&losses)
        .unwrap();
    if let Some(w) = witness {
        e.bytes(&w).unwrap();
    } else {
        e.null().unwrap();
    }
    let raw = e.into_writer();
    crate::blocks::canonical(&raw, 256 * 1024)?;
    Ok(raw)
}
impl CanonicalStore {
    /// A create-new bounded archive from one SQLite read snapshot. The footer
    /// exists only after all rows/root checks; a partial artifact is invalid.
    pub fn export_checkpoint(
        &mut self,
        path: &Path,
        byte_budget: u64,
    ) -> CResult<CheckpointSummary> {
        if self.integrity_halted()? {
            return Err(CheckpointError::Invalid);
        }
        let t = self.db.transaction()?;
        let head = tip(&t)?;
        let n: u64 = t.query_row("SELECT count(*) FROM chain_state", [], |r| r.get(0))?;
        if n > crate::execution::MAX_STATE_RECORDS as u64 {
            return Err(CheckpointError::Capacity);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(13)
            .unwrap()
            .u8(2)
            .unwrap()
            .u32(crate::NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.genesis_anchor.encode())
            .unwrap()
            .u64(head.height)
            .unwrap()
            .bytes(&head.block)
            .unwrap()
            .bytes(&head.root)
            .unwrap()
            .bytes(&head.next_target)
            .unwrap()
            .u64(head.timestamp)
            .unwrap()
            .u64(n)
            .unwrap()
            .bytes(
                &FinalizedAnchor {
                    network: crate::NETWORK_ID,
                    genesis: self.genesis,
                    fingerprint: self.fingerprint,
                    height: head.height,
                    block: head.block,
                }
                .encode(),
            )
            .unwrap()
            .u64(0)
            .unwrap();
        let mut out = Output {
            file: BufWriter::new(OpenOptions::new().write(true).create_new(true).open(path)?),
            hash: Sha256::new(),
            bytes: 0,
            budget: byte_budget,
        };
        out.write(MAGIC)?;
        out.frame(&e.into_writer())?;
        for height in 0..=head.height {
            if height > 0 {
                let raw: Vec<u8> = t.query_row(
                    "SELECT envelope FROM chain_history WHERE height=?1",
                    [height.to_be_bytes().as_slice()],
                    |r| r.get(0),
                )?;
                crate::block_envelope::BlockEnvelope::decode(&raw)?;
                out.frame(&raw)?;
            }
            out.frame(&recovery_frame(&t, height)?)?;
        }
        let mut state_hash = crate::state_tree::StateRootBuilder::default();
        let mut prior = None;
        let mut count = 0;
        {
            let mut q = t.prepare("SELECT key,value FROM chain_state ORDER BY key")?;
            for row in q.query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })? {
                let (key, value) = row?;
                let id: Hash = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| CheckpointError::Invalid)?;
                if prior.is_some_and(|p| p >= id) {
                    return Err(CheckpointError::Invalid);
                }
                prior = Some(id);
                crate::blocks::canonical(&value, 256 * 1024)?;
                let raw = record(&key, &value);
                state_hash.push(id, &value)?;
                out.frame(&raw)?;
                count += 1;
            }
        }
        if count != n || state_hash.finish() != head.root {
            return Err(CheckpointError::Invalid);
        }
        let digest: Hash = out.hash.finalize().into();
        out.file.write_all(&digest)?;
        out.file.flush()?;
        out.file.get_ref().sync_all()?;
        t.commit()?;
        Ok(CheckpointSummary {
            tip: head,
            records: n,
            archive_hash: digest,
            bytes: out.bytes + 32,
            retention_frontier: 0,
        })
    }
}
pub struct CheckpointRestore<'a, V, A> {
    pub archive: &'a Path,
    pub database: &'a Path,
    pub descriptor: &'a GenesisDescriptor,
    pub initial: &'a State,
    pub initial_target: Hash,
    pub physical: &'a BTreeMap<Hash, crate::freshness::PhysicalMember>,
    pub attestation: &'a V,
    pub legacy_recovery: &'a A,
    pub byte_budget: u64,
}
fn decode_manifest(raw: &[u8]) -> CResult<(Hash, Hash, FinalizedAnchor, Tip, u64)> {
    let mut d = Decoder::new(raw);
    let parsed = (|| -> std::result::Result<_, minicbor::decode::Error> {
        let bad = || minicbor::decode::Error::message("checkpoint");
        fn h(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
            d.bytes()?
                .try_into()
                .map_err(|_| minicbor::decode::Error::message("hash"))
        }
        if d.array()? != Some(13) || d.u8()? != 2 || d.u32()? != crate::NETWORK_ID {
            return Err(bad());
        }
        let genesis = h(&mut d)?;
        let fp = h(&mut d)?;
        let anchor = FinalizedAnchor::decode(d.bytes()?).map_err(|_| bad())?;
        let tip = Tip {
            height: d.u64()?,
            block: h(&mut d)?,
            root: h(&mut d)?,
            next_target: h(&mut d)?,
            timestamp: d.u64()?,
        };
        let count = d.u64()?;
        let finalized = FinalizedAnchor::decode(d.bytes()?).map_err(|_| bad())?;
        let expected = FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis,
            fingerprint: fp,
            height: tip.height,
            block: tip.block,
        };
        if finalized != expected || d.u64()? != 0 {
            return Err(bad());
        }
        Ok((genesis, fp, anchor, tip, count))
    })()
    .map_err(|_| CheckpointError::Invalid)?;
    if d.position() != raw.len() {
        return Err(CheckpointError::Invalid);
    }
    Ok(parsed)
}
fn restore_recovery<A: crate::recovery::PhysicalAdmissionVerifier>(
    chain: &mut CanonicalStore,
    raw: &[u8],
    legacy: &A,
) -> CResult<()> {
    if raw == [0xf6] {
        return Ok(());
    }
    let mut d = Decoder::new(raw);
    let values = (|| -> std::result::Result<_, minicbor::decode::Error> {
        if d.array()? != Some(3) {
            return Err(minicbor::decode::Error::message("recovery"));
        }
        let certificate = d.bytes()?.to_vec();
        let losses = d.bytes()?.to_vec();
        let witness = if d.datatype()? == Type::Null {
            d.null()?;
            None
        } else {
            Some(d.bytes()?.to_vec())
        };
        Ok((certificate, losses, witness))
    })()
    .map_err(|_| CheckpointError::Invalid)?;
    if d.position() != raw.len() {
        return Err(CheckpointError::Invalid);
    }
    let certificate = crate::recovery::Certificate::decode(&values.0)?;
    crate::blocks::canonical(&values.1, 64 * 1024)?;
    let mut d = Decoder::new(&values.1);
    let losses = (|| -> std::result::Result<Vec<(Hash, u64)>, minicbor::decode::Error> {
        let bad = || minicbor::decode::Error::message("losses");
        let n = d.array()?.ok_or_else(bad)?;
        if n > 1024 {
            return Err(bad());
        }
        let mut out = Vec::new();
        for _ in 0..n {
            if d.array()? != Some(2) {
                return Err(bad());
            }
            out.push((d.bytes()?.try_into().map_err(|_| bad())?, d.u64()?));
        }
        Ok(out)
    })()
    .map_err(|_| CheckpointError::Invalid)?;
    if let Some(raw) = values.2 {
        chain.accept_admitted_bootstrap_recovery(
            &certificate,
            &crate::recovery_material::RecoveryMaterial::decode(&raw)?,
            &losses,
        )?;
    } else {
        chain.accept_bootstrap_recovery(&certificate, legacy, &losses)?;
    }
    Ok(())
}
pub fn restore_checkpoint<
    V: crate::freshness::PhysicalAttestationVerifier,
    A: crate::recovery::PhysicalAdmissionVerifier,
>(
    input: CheckpointRestore<'_, V, A>,
) -> CResult<(CanonicalStore, CheckpointSummary)> {
    let file = File::open(input.archive)?;
    let length = file.metadata()?.len();
    if length > input.byte_budget || input.database.exists() {
        return Err(CheckpointError::Capacity);
    }
    let mut reader = Input {
        file: BufReader::new(file),
        hash: Sha256::new(),
    };
    if reader.read(8)? != MAGIC {
        return Err(CheckpointError::Invalid);
    }
    let (genesis, fp, anchor, expected, n) = decode_manifest(&reader.frame(1024)?)?;
    if n > crate::execution::MAX_STATE_RECORDS as u64
        || anchor.network != crate::NETWORK_ID
        || genesis != input.descriptor.id()?
        || fp != input.descriptor.fingerprint
        || anchor.height != 0
        || anchor.block
            != input
                .descriptor
                .block_hash(input.initial.root().map_err(ChainError::from)?)?
        || anchor.genesis != genesis
        || anchor.fingerprint != fp
    {
        return Err(CheckpointError::Invalid);
    }
    // Reserve without overwriting another database. Incomplete imports are
    // quarantined by open_trusted_genesis and are never returned to the caller.
    let marker = import_marker(input.database);
    let mut marker_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)?;
    marker_file.write_all(b"INCOMPLETE CHECKPOINT IMPORT\n")?;
    marker_file.sync_all()?;
    drop(marker_file);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(input.database)?;
    {
        let quarantine = Connection::open(input.database)?;
        quarantine.execute_batch("PRAGMA synchronous=FULL;CREATE TABLE checkpoint_import(id INTEGER PRIMARY KEY CHECK(id=1),complete INTEGER NOT NULL);INSERT INTO checkpoint_import VALUES(1,0);")?;
    }
    let mut chain = CanonicalStore::open_genesis_inner(
        input.database,
        input.descriptor,
        input.initial,
        input.initial_target,
        true,
    )?;
    for height in 0..=expected.height {
        if height > 0 {
            let block = BlockEnvelope::decode(&reader.frame(330 * 1024)?)?;
            if block.header.candidate.height != height {
                return Err(CheckpointError::Invalid);
            }
            chain.commit_integrated(&block, input.physical, input.attestation)?;
        }
        restore_recovery(
            &mut chain,
            &reader.frame(256 * 1024)?,
            input.legacy_recovery,
        )?;
    }
    if chain.load()?.0 != expected {
        return Err(CheckpointError::Invalid);
    }
    let mut state_hash = crate::state_tree::StateRootBuilder::default();
    let mut prior = None;
    for _ in 0..n {
        let raw = reader.frame(256 * 1024 + 64)?;
        let mut d = Decoder::new(&raw);
        let (key, value) = (|| -> std::result::Result<(Hash, Vec<u8>), minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("record");
            if d.array()? != Some(2) {
                return Err(bad());
            }
            Ok((
                d.bytes()?.try_into().map_err(|_| bad())?,
                d.bytes()?.to_vec(),
            ))
        })()
        .map_err(|_| CheckpointError::Invalid)?;
        if prior.is_some_and(|p| p >= key) || d.position() != raw.len() {
            return Err(CheckpointError::Invalid);
        }
        prior = Some(key);
        let stored: Vec<u8> = chain.db.query_row(
            "SELECT value FROM chain_state WHERE key=?1",
            [key.as_slice()],
            |r| r.get(0),
        )?;
        if value != stored {
            return Err(CheckpointError::Invalid);
        }
        state_hash.push(key, &value)?;
    }
    let count: u64 = chain
        .db
        .query_row("SELECT count(*) FROM chain_state", [], |r| r.get(0))?;
    if count != n || state_hash.finish() != expected.root {
        return Err(CheckpointError::Invalid);
    }
    let digest: Hash = reader.hash.finalize().into();
    let mut footer = [0; 32];
    reader.file.read_exact(&mut footer)?;
    let mut extra = [0];
    if footer != digest || reader.file.read(&mut extra)? != 0 {
        return Err(CheckpointError::Invalid);
    }
    chain
        .db
        .execute("UPDATE checkpoint_import SET complete=1 WHERE id=1", [])?;
    std::fs::remove_file(marker)?;
    Ok((
        chain,
        CheckpointSummary {
            tip: expected,
            records: n,
            archive_hash: digest,
            bytes: length,
            retention_frontier: 0,
        },
    ))
}
