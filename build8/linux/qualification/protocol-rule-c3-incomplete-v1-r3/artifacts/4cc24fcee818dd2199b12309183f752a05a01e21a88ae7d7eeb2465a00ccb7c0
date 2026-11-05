//! Bounded local proposal custody, separate from canonical history and TPM locks.
//! Receipt delivery may follow a successful insert; finality never follows from it.
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{
    Hash,
    blocks::{BlockBody, canonical},
    canonical_store::CanonicalStore,
    coordinator::ObservedWork,
    execution::LicensedExecution,
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    pow::{WorkAuthority, WorkHeader, meets_target},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{collections::BTreeMap, path::Path};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Candidate journal: {e:?}")
}
pub(crate) const MAX_BYTES: usize = 69632; // 64 KiB body plus bounded header/authority/codec overhead.
pub(crate) const MAX_PROPOSALS: usize = 1024; // Existing authenticated-round ingress capacity.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateRecord {
    pub header: WorkHeader,
    pub body: BlockBody,
    pub authority: WorkAuthority,
    pub signature: [u8; 64],
}
impl CandidateRecord {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.header.encode())
            .unwrap()
            .bytes(&self.body.encode().map_err(err)?)
            .unwrap()
            .bytes(&self.authority.envelope(&self.signature))
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_BYTES {
            return Err("Candidate journal record bound".into());
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, MAX_BYTES).map_err(err)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(err)? != Some(4) || d.u8().map_err(err)? != 1 {
            return Err("Candidate journal schema".into());
        }
        let header = WorkHeader::decode(d.bytes().map_err(err)?).map_err(err)?;
        let body = BlockBody::decode(d.bytes().map_err(err)?).map_err(err)?;
        let (authority, signature) =
            WorkAuthority::from_envelope(d.bytes().map_err(err)?).map_err(err)?;
        let value = Self {
            header,
            body,
            authority,
            signature,
        };
        if value.encode()? != raw
            || value.header.authority != value.authority.id()
            || value.header.candidate != value.authority.candidate
            || value.body.height != value.header.candidate.height
            || value.body.root().map_err(err)? != value.header.candidate.body_root
            || !meets_target(&value.header.digest(), &value.header.candidate.target)
        {
            return Err("Candidate journal identity/work mismatch".into());
        }
        Ok(value)
    }
}
pub struct CandidateJournal {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
    budget: usize,
}
impl CandidateJournal {
    pub fn context(&self) -> (Hash, Hash) {
        (self.genesis, self.fingerprint)
    }
    /// Restore only current-height candidates through ordinary executed proposal
    /// ingress. No signature is requested and no counter/lock is changed here.
    pub fn restore_into_voter<V: PhysicalAttestationVerifier>(
        &self,
        chain: &mut CanonicalStore,
        voter: &mut mutiny_consensus_v8::voter_actor::VoterActor,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<usize> {
        if chain.integrity_halted().map_err(err)? {
            return Err("Canonical integrity halt".into());
        }
        let (tip, _) = chain.load_effective().map_err(err)?;
        let mut restored = 0;
        for record in self.records()? {
            if record.header.candidate.height <= tip.height {
                continue;
            }
            voter
                .validate_candidate(
                    chain,
                    mutiny_consensus_v8::voter_actor::Proposal {
                        header: &record.header,
                        body: &record.body,
                        authority: &record.authority,
                        signature: &record.signature,
                    },
                    physical,
                    verifier,
                )
                .map_err(err)?;
            restored += 1;
        }
        Ok(restored)
    }
    pub fn open(path: &Path, genesis: Hash, fingerprint: Hash, byte_budget: usize) -> Result<Self> {
        if byte_budget == 0
            || byte_budget > MAX_BYTES * MAX_PROPOSALS
            || [genesis, fingerprint].contains(&[0; 32])
        {
            return Err("Candidate journal identity/budget".into());
        }
        let mut db = Connection::open(path).map_err(err)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS candidate_identity(id INTEGER PRIMARY KEY CHECK(id=1),genesis BLOB NOT NULL,fingerprint BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS candidates(id BLOB PRIMARY KEY CHECK(length(id)=32),height BLOB NOT NULL CHECK(length(height)=8),raw BLOB NOT NULL);").map_err(err)?;
        let t = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        t.execute(
            "INSERT OR IGNORE INTO candidate_identity VALUES(1,?1,?2)",
            params![genesis.as_slice(), fingerprint.as_slice()],
        )
        .map_err(err)?;
        let identity: (Vec<u8>, Vec<u8>) = t
            .query_row(
                "SELECT genesis,fingerprint FROM candidate_identity WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        if identity != (genesis.to_vec(), fingerprint.to_vec()) {
            return Err("Candidate journal context mismatch".into());
        }
        t.commit().map_err(err)?;
        let journal = Self {
            db,
            genesis,
            fingerprint,
            budget: byte_budget,
        };
        journal.records()?; // Fail on corrupt/oversized persisted custody, never silently reset.
        Ok(journal)
    }
    /// Untrusted stored candidates still require normal canonical execution/BFT
    /// validation when restored into a voter; this is not a certificate API.
    pub fn records(&self) -> Result<Vec<CandidateRecord>> {
        let (count, bytes): (usize, usize) = self
            .db
            .query_row(
                "SELECT count(*),coalesce(sum(length(raw)),0) FROM candidates",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        if count > MAX_PROPOSALS || bytes > self.budget {
            return Err("Candidate journal capacity".into());
        }
        let mut stmt = self
            .db
            .prepare("SELECT id,height,raw FROM candidates ORDER BY id")
            .map_err(err)?;
        let mut rows = stmt.query([]).map_err(err)?;
        let mut out = Vec::with_capacity(count);
        while let Some(row) = rows.next().map_err(err)? {
            let id: Vec<u8> = row.get(0).map_err(err)?;
            let height: Vec<u8> = row.get(1).map_err(err)?;
            let raw: Vec<u8> = row.get(2).map_err(err)?;
            let record = CandidateRecord::decode(&raw)?;
            let c = &record.header.candidate;
            if c.genesis != self.genesis
                || c.fingerprint != self.fingerprint
                || id != record.header.block_hash()
                || height != c.height.to_be_bytes()
            {
                return Err("Candidate journal row mismatch".into());
            }
            out.push(record);
        }
        Ok(out)
    }
    pub fn preserve<V: PhysicalAttestationVerifier>(
        &mut self,
        chain: &mut CanonicalStore,
        observed: &ObservedWork,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<()> {
        if chain.integrity_halted().map_err(err)? {
            return Err("Canonical integrity halt".into());
        }
        let (tip, _) = chain.load_effective().map_err(err)?;
        let (parent, state) = chain.execution_parent(tip.height).map_err(err)?;
        let c = &observed.header.candidate;
        if parent.genesis != self.genesis
            || parent.fingerprint != self.fingerprint
            || c.genesis != self.genesis
            || c.fingerprint != self.fingerprint
        {
            return Err("Candidate journal canonical context".into());
        }
        // A found result at an already finalized height needs its receipt but
        // must not revive a losing branch. No finality conclusion comes from it.
        if c.height <= tip.height {
            return Ok(());
        }
        if tip.height.checked_add(1) != Some(c.height) || c.parent != tip.block {
            return Err("Candidate journal wrong parent".into());
        }
        let issued = observed
            .issued
            .as_ref()
            .ok_or("Current candidate body unavailable")?;
        if !meets_target(&observed.header.digest(), &c.target) {
            return Err("Candidate PoW".into());
        }
        let history = chain.evidence_history(&issued.body).map_err(err)?;
        state
            .execute_with_history(
                LicensedExecution {
                    parent: &parent,
                    header: &observed.header,
                    authority: &issued.authority,
                    signature: &issued.signature,
                    body: &issued.body,
                },
                physical,
                verifier,
                &history,
            )
            .map_err(err)?;
        let record = CandidateRecord {
            header: observed.header.clone(),
            body: issued.body.clone(),
            authority: issued.authority.clone(),
            signature: issued.signature,
        };
        self.persist(&record, tip.height)
    }
    /// Peer proposals carry the same certificate-free candidate as miner ingress.
    /// No fabricated certificate or observation receipt is needed for custody.
    pub fn accept<V: PhysicalAttestationVerifier>(
        &mut self,
        chain: &mut CanonicalStore,
        record: &CandidateRecord,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<()> {
        record.encode()?;
        if chain.integrity_halted().map_err(err)? {
            return Err("Canonical integrity halt".into());
        }
        let (tip, _) = chain.load_effective().map_err(err)?;
        let (parent, state) = chain.execution_parent(tip.height).map_err(err)?;
        let c = &record.header.candidate;
        if parent.genesis != self.genesis
            || parent.fingerprint != self.fingerprint
            || c.genesis != self.genesis
            || c.fingerprint != self.fingerprint
            || tip.height.checked_add(1) != Some(c.height)
            || c.parent != tip.block
        {
            return Err("Candidate journal wrong context/parent".into());
        }
        if !meets_target(&record.header.digest(), &c.target) {
            return Err("Candidate PoW".into());
        }
        let history = chain.evidence_history(&record.body).map_err(err)?;
        state
            .execute_with_history(
                LicensedExecution {
                    parent: &parent,
                    header: &record.header,
                    authority: &record.authority,
                    signature: &record.signature,
                    body: &record.body,
                },
                physical,
                verifier,
                &history,
            )
            .map_err(err)?;
        self.persist(record, tip.height)
    }
    fn persist(&mut self, record: &CandidateRecord, finalized_height: u64) -> Result<()> {
        let c = &record.header.candidate;
        let raw = record.encode()?;
        let id = record.header.block_hash();
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        // Only canonical finality permits reclamation. Pending/locked proposals
        // are never evicted to make room for a newer found result.
        t.execute(
            "DELETE FROM candidates WHERE height<=?1",
            [finalized_height.to_be_bytes().as_slice()],
        )
        .map_err(err)?;
        let old: Option<Vec<u8>> = t
            .query_row(
                "SELECT raw FROM candidates WHERE id=?1",
                [id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(old) = old {
            if old != raw {
                return Err("Candidate journal conflicting bytes".into());
            }
        } else {
            let (count, bytes): (usize, usize) = t
                .query_row(
                    "SELECT count(*),coalesce(sum(length(raw)),0) FROM candidates",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(err)?;
            if count >= MAX_PROPOSALS
                || bytes.checked_add(raw.len()).is_none_or(|n| n > self.budget)
            {
                return Err(
                    "Candidate journal full; retry without dropping existing proposals".into(),
                );
            }
            t.execute(
                "INSERT INTO candidates VALUES(?1,?2,?3)",
                params![id.as_slice(), c.height.to_be_bytes().as_slice(), raw],
            )
            .map_err(err)?;
        }
        t.commit().map_err(err)
    }
    /// Test support: the real storage path (count cap, byte budget, per-record cap, identity) with
    /// the PoW/execution admission checks of `accept` already decided by the caller.
    #[cfg(test)]
    pub(crate) fn persist_for_test(
        &mut self,
        record: &CandidateRecord,
        finalized_height: u64,
    ) -> Result<()> {
        self.persist(record, finalized_height)
    }
    /// Test support: direct access to the table, to model a corrupt or foreign write.
    #[cfg(test)]
    pub(crate) fn db_for_test(&self) -> &Connection {
        &self.db
    }
}
