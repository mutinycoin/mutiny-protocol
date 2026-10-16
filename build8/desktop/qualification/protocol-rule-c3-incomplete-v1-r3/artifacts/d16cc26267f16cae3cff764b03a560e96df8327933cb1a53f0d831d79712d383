//! Bounded per-Worker observation checkpoints; receipts never establish finality.
use crate::{
    Error, Hash, NETWORK_ID, domain_hash,
    pow::{WORK_DOMAIN, WorkAuthority, WorkContext, WorkHeader, meets_target, validate_authority},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
pub const RESULT_MAX: usize = 544;
pub const SUBMISSION_MAX: usize = 41 + RESULT_MAX;
pub const RECEIPT_BODY: usize = 246;
pub const RECEIPT_BYTES: usize = 310;
pub fn result_id(work: &[u8]) -> Hash {
    domain_hash(b"MUTINY-BUILD8-OBSERVATION-RESULT-V1", work)
}
pub fn chain_link(previous: Hash, sequence: u64, result: Hash, accepted: bool, total: u64) -> Hash {
    let mut raw = sequence.to_be_bytes().to_vec();
    raw.extend(previous);
    raw.extend(result);
    raw.push(u8::from(accepted));
    raw.extend(total.to_be_bytes());
    domain_hash(b"MUTINY-BUILD8-OBSERVATION-CHAIN-V1", &raw)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub sequence: u64,
    pub previous: Hash,
    pub work: Vec<u8>,
}
impl Submission {
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = vec![2];
        raw.extend(self.sequence.to_be_bytes());
        raw.extend(self.previous);
        raw.extend(&self.work);
        raw
    }
    pub fn decode(raw: &[u8]) -> crate::Result<Self> {
        if raw.len() < 42 || raw.len() > SUBMISSION_MAX || raw[0] != 2 {
            return Err(Error::Codec);
        }
        let value = Self {
            sequence: u64::from_be_bytes(raw[1..9].try_into().unwrap()),
            previous: raw[9..41].try_into().unwrap(),
            work: raw[41..].to_vec(),
        };
        if value.sequence == 0 {
            return Err(Error::InvalidCounter);
        }
        value.header()?;
        Ok(value)
    }
    pub fn header(&self) -> crate::Result<WorkHeader> {
        let prefix = WORK_DOMAIN.len() + 1;
        if self.sequence == 0
            || self.work.len() <= prefix
            || self.work.len() > RESULT_MAX
            || &self.work[..WORK_DOMAIN.len()] != WORK_DOMAIN
            || self.work[WORK_DOMAIN.len()] != 0
        {
            return Err(Error::Codec);
        }
        let header = WorkHeader::decode(&self.work[prefix..])?;
        if header.work_bytes() != self.work {
            return Err(Error::NonCanonical);
        }
        Ok(header)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub license: Hash,
    pub worker: Hash,
    pub result: Hash,
    pub accepted: bool,
    pub total: u64,
    pub coordinator: Hash,
    pub sequence: u64,
    pub chain: Hash,
    pub signature: [u8; 64],
}
impl Receipt {
    pub fn body(&self) -> Vec<u8> {
        let mut raw = vec![2];
        raw.extend(NETWORK_ID.to_be_bytes());
        for h in [
            self.genesis,
            self.fingerprint,
            self.license,
            self.worker,
            self.result,
        ] {
            raw.extend(h);
        }
        raw.push(u8::from(self.accepted));
        raw.extend(self.total.to_be_bytes());
        raw.extend(self.coordinator);
        raw.extend(self.sequence.to_be_bytes());
        raw.extend(self.chain);
        raw
    }
    pub fn digest(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-OBSERVATION-RECEIPT-V2", &self.body())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = self.body();
        raw.extend(self.signature);
        raw
    }
    pub fn decode(raw: &[u8]) -> crate::Result<Self> {
        if raw.len() != RECEIPT_BYTES
            || raw[0] != 2
            || raw[1..5] != NETWORK_ID.to_be_bytes()
            || raw[165] > 1
        {
            return Err(Error::Codec);
        }
        let h = |n| -> Hash { raw[n..n + 32].try_into().unwrap() };
        let value = Self {
            genesis: h(5),
            fingerprint: h(37),
            license: h(69),
            worker: h(101),
            result: h(133),
            accepted: raw[165] == 1,
            total: u64::from_be_bytes(raw[166..174].try_into().unwrap()),
            coordinator: h(174),
            sequence: u64::from_be_bytes(raw[206..214].try_into().unwrap()),
            chain: h(214),
            signature: raw[246..].try_into().unwrap(),
        };
        if value.sequence == 0
            || value.total > value.sequence
            || value.chain == [0; 32]
            || (value.accepted && value.total == 0)
        {
            return Err(Error::InvalidCounter);
        }
        VerifyingKey::from_bytes(&value.coordinator)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(&value.digest(), &Signature::from_bytes(&value.signature))
            .map_err(|_| Error::BadSignature)?;
        Ok(value)
    }
}
#[derive(Debug)]
pub enum ObservationError {
    Storage(rusqlite::Error),
    Invalid(Error),
    Integrity,
    Context,
    Overflow,
    StaleSequence,
}
impl From<rusqlite::Error> for ObservationError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<Error> for ObservationError {
    fn from(e: Error) -> Self {
        Self::Invalid(e)
    }
}
type Result<T> = std::result::Result<T, ObservationError>;
pub struct ObservationStore {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
}
fn stored(
    db: &Connection,
    worker: Hash,
    genesis: Hash,
    fingerprint: Hash,
) -> Result<Option<(Submission, Receipt)>> {
    let row: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT submission,receipt FROM observation_checkpoint WHERE worker=?1",
            [worker.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(s, r)| {
        let s = Submission::decode(&s)?;
        let r = Receipt::decode(&r)?;
        let header = s.header()?;
        if r.worker != worker
            || header.candidate.worker != worker
            || r.genesis != genesis
            || r.fingerprint != fingerprint
            || header.candidate.genesis != genesis
            || header.candidate.fingerprint != fingerprint
            || header.candidate.license != r.license
            || r.result != result_id(&s.work)
            || r.sequence != s.sequence
            || r.chain != chain_link(s.previous, s.sequence, r.result, r.accepted, r.total)
        {
            return Err(ObservationError::Integrity);
        }
        Ok((s, r))
    })
    .transpose()
}
fn check_next(
    submission: &Submission,
    old: Option<&(Submission, Receipt)>,
) -> Result<Option<Receipt>> {
    let (sequence, chain) = old
        .map(|(_, r)| (r.sequence, r.chain))
        .unwrap_or((0, [0; 32]));
    if submission.sequence == sequence {
        if let Some((s, r)) = old
            && s == submission
        {
            return Ok(Some(r.clone()));
        }
        return Err(ObservationError::Integrity);
    }
    if submission.sequence != sequence.checked_add(1).ok_or(ObservationError::Overflow)?
        || submission.previous != chain
    {
        return Err(ObservationError::StaleSequence);
    }
    Ok(None)
}
impl ObservationStore {
    pub fn open(path: &Path, genesis: Hash, fingerprint: Hash) -> Result<Self> {
        let mut db = Connection::open(path)?;
        let legacy: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='observations')",
            [],
            |r| r.get(0),
        )?;
        if legacy {
            return Err(ObservationError::Integrity);
        } // Never reset old accounting implicitly.
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS observation_meta_v2(id INTEGER PRIMARY KEY CHECK(id=1),genesis BLOB NOT NULL,fingerprint BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS observation_checkpoint(worker BLOB PRIMARY KEY CHECK(length(worker)=32),submission BLOB NOT NULL CHECK(length(submission)<=585),receipt BLOB NOT NULL CHECK(length(receipt)=310));")?;
        let t = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let identity: Option<(Vec<u8>, Vec<u8>)> = t
            .query_row(
                "SELECT genesis,fingerprint FROM observation_meta_v2 WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match identity {
            Some((g, f)) if g == genesis && f == fingerprint => {}
            Some(_) => return Err(ObservationError::Context),
            None => {
                let populated: bool = t.query_row(
                    "SELECT EXISTS(SELECT 1 FROM observation_checkpoint)",
                    [],
                    |r| r.get(0),
                )?;
                if populated {
                    return Err(ObservationError::Integrity);
                }
                t.execute(
                    "INSERT INTO observation_meta_v2 VALUES(1,?1,?2)",
                    params![genesis.as_slice(), fingerprint.as_slice()],
                )?;
            }
        }
        {
            let mut query = t.prepare("SELECT worker FROM observation_checkpoint")?;
            for row in query.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
                let worker: Hash = row?.try_into().map_err(|_| ObservationError::Integrity)?;
                stored(&t, worker, genesis, fingerprint)?;
            }
        }
        t.commit()?;
        Ok(Self {
            db,
            genesis,
            fingerprint,
        })
    }
    pub fn checkpoint(&self, worker: Hash) -> Result<(u64, u64, Hash)> {
        Ok(stored(&self.db, worker, self.genesis, self.fingerprint)?
            .map(|(_, r)| (r.sequence, r.total, r.chain))
            .unwrap_or((0, 0, [0; 32])))
    }
    pub fn total(&self, worker: Hash) -> Result<u64> {
        Ok(self.checkpoint(worker)?.1)
    }
    pub fn retry(&self, worker: Hash, submission: &Submission) -> Result<Option<Receipt>> {
        let header = submission.header()?;
        if header.candidate.worker != worker
            || header.candidate.genesis != self.genesis
            || header.candidate.fingerprint != self.fingerprint
        {
            return Err(ObservationError::Context);
        }
        let old = stored(&self.db, worker, self.genesis, self.fingerprint)?;
        check_next(submission, old.as_ref())
    }
    pub fn accept(
        &mut self,
        submission: &Submission,
        authority: &WorkAuthority,
        signature: &[u8; 64],
        context: &WorkContext,
        signer: &SigningKey,
    ) -> Result<Receipt> {
        let header = submission.header()?;
        let c = &header.candidate;
        let key = signer.verifying_key().to_bytes();
        if c.network != NETWORK_ID
            || c.genesis != self.genesis
            || c.fingerprint != self.fingerprint
            || context.genesis != self.genesis
            || context.fingerprint != self.fingerprint
            || c.worker != context.worker
            || c.license != context.license
            || key != context.coordinator
        {
            return Err(ObservationError::Context);
        }
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = stored(&t, c.worker, self.genesis, self.fingerprint)?;
        if let Some(receipt) = check_next(submission, old.as_ref())? {
            if receipt.coordinator != key {
                return Err(ObservationError::Context);
            }
            t.commit()?;
            return Ok(receipt);
        }
        validate_authority(&header, authority, signature, context)?;
        // Firmware stops on its first found result; a new submission needs a
        // fresh durable ticket. Re-labeling one ticket with a higher observation
        // sequence cannot earn another count without an unbounded result set.
        if let Some((previous, _)) = &old
            && previous.header()?.authority == header.authority
        {
            return Err(ObservationError::StaleSequence);
        }
        if !meets_target(&header.digest(), &c.target) {
            return Err(Error::InvalidCounter.into());
        }
        let total = old
            .as_ref()
            .map(|(_, r)| r.total)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ObservationError::Overflow)?;
        let id = result_id(&submission.work);
        let mut receipt = Receipt {
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            license: c.license,
            worker: c.worker,
            result: id,
            accepted: true,
            total,
            coordinator: key,
            sequence: submission.sequence,
            chain: chain_link(submission.previous, submission.sequence, id, true, total),
            signature: [0; 64],
        };
        receipt.signature = signer.sign(&receipt.digest()).to_bytes();
        t.execute("INSERT INTO observation_checkpoint VALUES(?1,?2,?3) ON CONFLICT(worker) DO UPDATE SET submission=excluded.submission,receipt=excluded.receipt",params![c.worker.as_slice(),submission.encode(),receipt.encode()])?;
        t.commit()?;
        Ok(receipt)
    }
}
