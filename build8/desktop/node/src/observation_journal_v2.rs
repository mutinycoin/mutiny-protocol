//! Bounded operational receipt checkpoint and candidate outbox candidate.
//! No network publication or canonical mutation. Restoring an old database is
//! not detected by a TPM; authenticated Worker checkpoints must fail on mismatch.
use crate::{
    observation_custody_v2::{Custody, Request},
    work_journal_v2,
    worker_protocol_v2::{self, Incoming, Scope, Submission},
};
use mutiny_consensus_v8::{
    Hash, NETWORK_ID, anchors::FinalizedAnchor, blocks::BlockBody,
    canonical_store_v2::CanonicalStore, observation_receipt_v2::Intent,
    work_authority_v2::Authority,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
type Result<T> = std::result::Result<T, String>;
const APP: i64 = 0x4d4f4a32;
const IDENTITY: &str =
    "CREATE TABLE identity(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL)";
const CHECKPOINTS: &str = "CREATE TABLE checkpoints(worker BLOB PRIMARY KEY CHECK(length(worker)=32),submission BLOB NOT NULL CHECK(length(submission)<=585),receipt BLOB NOT NULL CHECK(length(receipt)=1672),authority BLOB NOT NULL CHECK(length(authority)<=8192),body BLOB NOT NULL CHECK(length(body)<=65536))";
const A2_CHECKPOINTS: &str = "CREATE TABLE checkpoints(worker BLOB PRIMARY KEY CHECK(length(worker)=32),submission BLOB NOT NULL CHECK(length(submission)<=585),receipt BLOB NOT NULL CHECK(length(receipt)=1672),authority BLOB NOT NULL CHECK(length(authority)<=8192),body BLOB NOT NULL CHECK(length(body)<=262150))";
fn storage(_: rusqlite::Error) -> String {
    "Observation storage failure".into()
}
pub struct Journal {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
    descriptor: Vec<u8>,
    body_codec: crate::journal_body_codec_v1::Codec,
}
/// Persisted result/candidate, not permission to send a receipt. The owning
/// BFT ingress must retain it before receipt bytes can leave this component.
pub struct Committed {
    submission: Submission,
    receipt: Vec<u8>,
    authority: Authority,
    body: BlockBody,
    total: u64,
    chain: Hash,
}
impl Committed {
    #[cfg(test)]
    pub(crate) fn same_receipt(&self, other: &Self) -> bool {
        self.receipt == other.receipt
    }
    pub fn sequence(&self) -> u64 {
        self.submission.sequence()
    }
    pub fn total(&self) -> u64 {
        self.total
    }
    pub fn chain(&self) -> Hash {
        self.chain
    }
    pub fn candidate(
        &self,
    ) -> (
        &mutiny_consensus_v8::pow::WorkHeader,
        &Authority,
        &BlockBody,
    ) {
        (self.submission.header(), &self.authority, &self.body)
    }
    pub fn release(self, retained: crate::candidate_journal_v2::Retention) -> Result<Vec<u8>> {
        if !retained.matches(self.submission.header()) {
            return Err("Receipt candidate retention mismatch".into());
        }
        Ok(self.receipt)
    }
    /// Current Worker-channel packet, including the historical public signer
    /// descriptor already authenticated by this persisted observation.
    pub fn release_packet(
        self,
        retained: crate::candidate_journal_v2::Retention,
    ) -> Result<Vec<u8>> {
        if !retained.matches(self.submission.header()) {
            return Err("Receipt candidate retention mismatch".into());
        }
        worker_protocol_v2::receipt_packet(&self.authority.node_descriptor, &self.receipt)
            .map_err(|_| "Receipt transport encoding".into())
    }
}
impl Journal {
    pub(crate) fn uses_a2(&self) -> bool { self.body_codec.is_successor() }
    pub fn matches_issuance(&self, issued: &work_journal_v2::Journal) -> bool {
        self.uses_a2() == issued.uses_a2()
            && issued.matches_context(self.genesis, self.fingerprint, &self.descriptor)
    }
    pub fn open(
        path: &Path,
        genesis: Hash,
        fingerprint: Hash,
        descriptor: &[u8],
        initialize: bool,
    ) -> Result<Self> {
        Self::open_inner(path,genesis,fingerprint,descriptor,initialize,None)
    }
    /// Explicit create-new schema3, preserving historical schema2 and limits.
    pub fn open_a2(
        runtime: &crate::hybrid_runtime_v2::HybridRuntime,
        path: &Path,
        descriptor: &[u8],
        initialize: bool,
    ) -> Result<Self> {
        let (genesis,fingerprint) = runtime.network_context();
        Self::open_inner(path,genesis,fingerprint,descriptor,initialize,Some(runtime))
    }
    fn open_inner(
        path: &Path, genesis: Hash, fingerprint: Hash, descriptor: &[u8],
        initialize: bool, runtime: Option<&crate::hybrid_runtime_v2::HybridRuntime>,
    ) -> Result<Self> {
        let body_codec = match runtime {
            Some(runtime) => crate::journal_body_codec_v1::Codec::successor(runtime)?,
            None => crate::journal_body_codec_v1::Codec::legacy(),
        };
        let expected_version = if body_codec.is_successor() { 3 } else { 2 };
        let expected_app = if body_codec.is_successor() { 0x4d4f4a33 } else { APP };
        let checkpoints = if body_codec.is_successor() { A2_CHECKPOINTS } else { CHECKPOINTS };
        mutiny_consensus_v8::work_authority_v2::node_identity(descriptor)
            .map_err(|_| "Observation Node descriptor")?;
        if genesis == [0; 32] || fingerprint == [0; 32] {
            return Err("Observation context".into());
        }
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(expected_version as u8)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&genesis)
            .unwrap()
            .bytes(&fingerprint)
            .unwrap()
            .bytes(descriptor)
            .unwrap();
        let context = e.into_writer();
        if initialize && body_codec.is_successor() {
            std::fs::OpenOptions::new().write(true).create_new(true).open(path)
                .map_err(|_| "A2 observation journal create-new")?;
        }
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if initialize {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let mut db = Connection::open_with_flags(path, flags).map_err(storage)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(storage)?;
        let app: i64 = db
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(storage)?;
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(storage)?;
        let objects: u64 = db
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .map_err(storage)?;
        if if initialize {
            app != 0 || version != 0 || objects != 0
        } else {
            app != expected_app || version != expected_version || objects != 3
        } {
            return Err("Observation database format".into());
        }
        let page: u64 = db
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .map_err(storage)?;
        let limit = (256u64 * 1024 * 1024)
            .checked_div(page)
            .ok_or("Observation page size")?;
        let used: u64 = db
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .map_err(storage)?;
        if limit < 256 || used > limit {
            return Err("Observation local capacity".into());
        }
        db.pragma_update(None, "max_page_count", limit)
            .map_err(storage)?;
        let applied: u64 = db
            .pragma_query_value(None, "max_page_count", |r| r.get(0))
            .map_err(storage)?;
        if applied != limit {
            return Err("Observation capacity policy".into());
        }
        db.execute_batch(
            "PRAGMA trusted_schema=OFF;PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;",
        )
        .map_err(storage)?;
        let t = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if initialize {
            t.execute_batch(IDENTITY).map_err(storage)?;
            t.execute_batch(checkpoints).map_err(storage)?;
            t.execute("INSERT INTO identity VALUES(1,?1)", [&context])
                .map_err(storage)?;
            t.pragma_update(None, "application_id", expected_app)
                .map_err(storage)?;
            t.pragma_update(None, "user_version", expected_version).map_err(storage)?;
        }
        for (name, sql) in [("identity", IDENTITY), ("checkpoints", checkpoints)] {
            let actual:String=t.query_row("SELECT CASE WHEN length(CAST(sql AS BLOB))<=1024 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name=?1",[name],|r|r.get(0)).map_err(storage)?;
            if actual != sql {
                return Err("Observation schema changed".into());
            }
        }
        let stored:Vec<u8>=t.query_row("SELECT CASE WHEN length(context)<=4096 THEN context ELSE NULL END FROM identity WHERE id=1",[],|r|r.get(0)).map_err(storage)?;
        if stored != context {
            return Err("Observation identity changed".into());
        }
        let count: u64 = t
            .query_row("SELECT count(*) FROM checkpoints", [], |r| r.get(0))
            .map_err(storage)?;
        if count > 4096 {
            return Err("Observation Worker capacity".into());
        }
        t.commit().map_err(storage)?;
        let mut journal = Self {
            db,
            genesis,
            fingerprint,
            descriptor: descriptor.to_vec(),
            body_codec,
        };
        if let Some(runtime) = runtime { journal.refresh_capacities(&runtime.chain)?; }
        let mut q = journal
            .db
            .prepare(
                "SELECT CASE WHEN length(worker)=32 THEN worker ELSE NULL END FROM checkpoints",
            )
            .map_err(storage)?;
        let mut rows = q.query([]).map_err(storage)?;
        while let Some(row) = rows.next().map_err(storage)? {
            let worker: Vec<u8> = row.get(0).map_err(storage)?;
            journal
                .load(
                    worker
                        .try_into()
                        .map_err(|_| "Observation Worker encoding")?,
                )?
                .ok_or("Observation disappeared")?;
        }
        drop(rows);
        drop(q);
        Ok(journal)
    }
    fn refresh_capacities(&mut self,chain: &CanonicalStore) -> Result<()> {
        if !self.body_codec.is_successor() { return Ok(()); }
        let raws = {
            let mut q = self.db.prepare("SELECT CASE WHEN length(authority)<=8192 THEN authority ELSE NULL END FROM checkpoints LIMIT 4097").map_err(storage)?;
            q.query_map([],|r|r.get::<_,Vec<u8>>(0)).map_err(storage)?
                .collect::<std::result::Result<Vec<_>,_>>().map_err(storage)?
        };
        if raws.len() > 4096 { return Err("Observation Worker capacity".into()); }
        let authorities = raws.into_iter().map(|raw|Authority::decode(&raw).map_err(|_| "Stored observation authority".to_string())).collect::<Result<Vec<_>>>()?;
        let parents = authorities.iter().map(|a|a.work.candidate.parent).collect();
        self.body_codec.retain_parents(&parents);
        for authority in authorities { self.body_codec.bind_store(chain,&authority)?; }
        Ok(())
    }
    fn read(
        db: &Connection,
        genesis: Hash,
        fingerprint: Hash,
        descriptor: &[u8],
        body_codec: &crate::journal_body_codec_v1::Codec,
        worker: Hash,
    ) -> Result<Option<Committed>> {
        type Row = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
        let row:Option<Row>=db.query_row("SELECT CASE WHEN length(submission)<=585 THEN submission ELSE NULL END,CASE WHEN length(receipt)=1672 THEN receipt ELSE NULL END,CASE WHEN length(authority)<=8192 THEN authority ELSE NULL END,CASE WHEN length(body)<=?2 THEN body ELSE NULL END FROM checkpoints WHERE worker=?1",params![worker.as_slice(),body_codec.limit()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(storage)?;
        let Some((submission, receipt, a, b)) = row else {
            return Ok(None);
        };
        let authority = Authority::decode(&a).map_err(|_| "Stored observation authority")?;
        let body = body_codec.decode(&authority,&b)?;
        let scope = Scope {
            genesis,
            fingerprint,
            license: authority.work.candidate.license,
            worker,
        };
        let mut wire = vec![3];
        wire.extend(&submission);
        let Incoming::Result(submission) = worker_protocol_v2::decode(&wire, scope)
            .map_err(|_| "Stored observation submission")?
        else {
            return Err("Observation submission type".into());
        };
        let header = submission.header();
        if authority.node_descriptor != descriptor
            || authority.work.candidate != header.candidate
            || authority
                .id()
                .map_err(|_| "Observation authority identity")?
                != header.authority
            || body.height != header.candidate.height
            || body_codec.root(&authority,&body)? != header.candidate.body_root
        {
            return Err("Stored observation context".into());
        }
        let (public, _) = mutiny_crypto_v2::PublicKey::decode_descriptor(descriptor)
            .map_err(|_| "Observation descriptor")?;
        public
            .verify(
                mutiny_crypto_v2::Domain::NodeWork,
                &authority.unsigned().map_err(|_| "Observation work bytes")?,
                &authority.signature,
            )
            .map_err(|_| "Stored work signatures")?;
        let total = u64::from_be_bytes(
            receipt[238..246]
                .try_into()
                .map_err(|_| "Observation total")?,
        );
        let prior = total.checked_sub(1).ok_or("Observation total underflow")?;
        let intent = Intent::accepted(
            header,
            submission.sequence(),
            submission.previous(),
            prior,
            descriptor,
        )
        .map_err(|_| "Stored observation intent")?;
        intent
            .verify(&receipt)
            .map_err(|_| "Stored receipt signatures")?;
        Ok(Some(Committed {
            submission,
            receipt,
            authority,
            body,
            total,
            chain: intent.chain(),
        }))
    }
    pub fn load(&self, worker: Hash) -> Result<Option<Committed>> {
        Self::read(
            &self.db,
            self.genesis,
            self.fingerprint,
            &self.descriptor,
            &self.body_codec,
            worker,
        )
    }
    pub fn matches_checkpoint(&self, worker: Hash, sequence: u64, chain: Hash) -> Result<bool> {
        Ok(match self.load(worker)? {
            Some(c) => c.sequence() == sequence && c.chain == chain,
            None => sequence == 0 && chain == [0; 32],
        })
    }
    /// Owning actor serializes issuance, acceptance and canonical updates.
    /// Only the retained issued authority/body can reach expensive validation.
    pub fn accept(
        &mut self,
        chain: &CanonicalStore,
        issued: &work_journal_v2::Journal,
        custody: &Custody<'_>,
        parent: &FinalizedAnchor,
        timestamp: u64,
        submission: &Submission,
    ) -> Result<Committed> {
        let c = &submission.header().candidate;
        if c.network != NETWORK_ID
            || c.genesis != self.genesis
            || c.fingerprint != self.fingerprint
            || !self.matches_issuance(issued)
        {
            return Err("Observation issuance context".into());
        }
        self.refresh_capacities(chain)?;
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let old = Self::read(
            &t,
            self.genesis,
            self.fingerprint,
            &self.descriptor,
            &self.body_codec,
            c.worker,
        )?;
        let (sequence, previous, total) = match old.as_ref() {
            Some(v) => (v.sequence(), v.chain, v.total),
            None => (0, [0; 32], 0),
        };
        if submission.sequence() == sequence {
            if let Some(old) = old {
                if old.submission == *submission {
                    t.commit().map_err(storage)?;
                    return Ok(old);
                }
            }
            return Err("Conflicting observation retry".into());
        }
        if sequence.checked_add(1) != Some(submission.sequence())
            || previous != submission.previous()
        {
            return Err("Observation checkpoint mismatch".into());
        }
        let (authority, body) = issued.lookup(c.worker)?.ok_or("Missing retained work")?;
        // Preserve the old exact-result retry above even when a later issued
        // ticket was reserved but not finished. New results need their new cap.
        self.body_codec.bind_store(chain,&authority)?;
        if authority.id().map_err(|_| "Issued authority")? != submission.header().authority
            || old
                .as_ref()
                .is_some_and(|v| v.authority.work.ticket_sequence >= authority.work.ticket_sequence)
        {
            return Err("Observation needs a new issued ticket".into());
        }
        if old.is_none() {
            let count: u64 = t
                .query_row("SELECT count(*) FROM checkpoints", [], |r| r.get(0))
                .map_err(storage)?;
            if count >= 4096 {
                return Err("Observation Worker capacity".into());
            }
        }
        let receipt = custody.sign(
            chain,
            Request {
                parent,
                timestamp,
                header: submission.header(),
                authority: &authority,
                body: &body,
                sequence: submission.sequence(),
                previous,
                prior_total: total,
            },
        )?;
        t.execute("INSERT INTO checkpoints VALUES(?1,?2,?3,?4,?5) ON CONFLICT(worker) DO UPDATE SET submission=excluded.submission,receipt=excluded.receipt,authority=excluded.authority,body=excluded.body",params![c.worker.as_slice(),submission.encode(),receipt,authority.encode().map_err(|_|"Observation authority bytes")?,self.body_codec.encode(&authority,&body)?]).map_err(storage)?;
        let committed = Self::read(
            &t,
            self.genesis,
            self.fingerprint,
            &self.descriptor,
            &self.body_codec,
            c.worker,
        )?
        .ok_or("Observation checkpoint missing")?;
        t.commit().map_err(storage)?;
        Ok(committed)
    }
}
