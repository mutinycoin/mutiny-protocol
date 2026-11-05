//! Bounded durable authenticated vote ingress. This is evidence custody, never
//! authority to sign or to replace the TPM-backed local lock journal.
use crate::candidate_journal::CandidateRecord;
use mutiny_consensus_v8::{
    Hash,
    canonical_store::CanonicalStore,
    execution::LicensedExecution,
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    voter_actor,
    votes::{AuthenticatedRound, Vote},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Vote journal: {e:?}")
}
const MAX_VOTES: usize = 100_000;
const MAX_BYTES: usize = 128 * 1024 * 1024;
const MAX_WIRE: usize = 2048;
pub struct VoteJournal {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
}
impl VoteJournal {
    pub fn context(&self) -> (Hash, Hash) {
        (self.genesis, self.fingerprint)
    }
    /// Route durable precommits to certificate construction without test-harness
    /// certificate injection. Unknown proposals remain pending. Full validation
    /// and parent-state quorum checks are repeated before canonical publication.
    pub fn finalize_ready<V: PhysicalAttestationVerifier>(
        &self,
        chain: &mut CanonicalStore,
        proposals: &[CandidateRecord],
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<Option<mutiny_consensus_v8::block_envelope::BlockEnvelope>> {
        if proposals.len() > 1024 {
            return Err("Proposal ingress bound".into());
        }
        let (tip, _) = chain.load_effective().map_err(err)?;
        let height = tip.height.checked_add(1).ok_or("Height exhausted")?;
        let (parent, state) = chain.execution_parent(tip.height).map_err(err)?;
        let current = voter_actor::authority(&parent, &state).map_err(err)?;
        let mut groups: BTreeMap<Hash, BTreeMap<Hash, Vote>> = BTreeMap::new();
        for vote in self.height(height)? {
            // A separately authenticated recovery may replace effective voter
            // authority at the same finalized anchor. Preserve old evidence,
            // but never let its obsolete roots block or certify the successor.
            let d = &vote.decision;
            if d.membership != current.membership
                || d.reputation != current.reputation
                || d.attestation != current.attestation
                || d.parent != current.parent.block
                || d.previous_finalized_anchor != current.parent.id()
            {
                continue;
            }
            if !vote.nil && vote.decision.step == 3 {
                // Multiple valid signature representations by one signer never
                // increase quorum. The journal retains every received record.
                groups
                    .entry(vote.decision.id())
                    .or_default()
                    .entry(vote.node)
                    .or_insert(vote);
            }
        }
        let mut ready = Vec::new();
        for group in groups.into_values() {
            let votes: Vec<_> = group.into_values().collect();
            let block = votes[0].decision.block;
            let Some(proposal) = proposals.iter().find(|p| p.header.block_hash() == block) else {
                continue;
            };
            if let Some(envelope) =
                crate::certificate_assembly::assemble(chain, proposal, &votes, physical, verifier)?
            {
                // Keep at most two different finalized block identities. A
                // conflicting pair must reach the canonical integrity-halt path.
                if ready
                    .iter()
                    .all(|p: &mutiny_consensus_v8::block_envelope::BlockEnvelope| {
                        p.block_hash() != envelope.block_hash()
                    })
                {
                    ready.push(envelope);
                    if ready.len() == 2 {
                        break;
                    }
                }
            }
        }
        let mut published = None;
        for block in ready {
            chain
                .commit_integrated(&block, physical, verifier)
                .map_err(err)?;
            published = Some(block);
        }
        Ok(published)
    }
    pub fn open(path: &Path, genesis: Hash, fingerprint: Hash) -> Result<Self> {
        let mut db = Connection::open(path).map_err(err)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(err)?;
        db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS vote_context(singleton INTEGER PRIMARY KEY CHECK(singleton=1),genesis BLOB NOT NULL,fingerprint BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS received_votes(id BLOB PRIMARY KEY CHECK(length(id)=32),height BLOB NOT NULL CHECK(length(height)=8),wire BLOB NOT NULL);
            CREATE INDEX IF NOT EXISTS received_vote_height ON received_votes(height);").map_err(err)?;
        let t = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let old: Option<(Vec<u8>,Vec<u8>)> = t.query_row(
            "SELECT CASE WHEN length(genesis)=32 THEN genesis END,CASE WHEN length(fingerprint)=32 THEN fingerprint END FROM vote_context WHERE singleton=1",
            [], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(err)?;
        if let Some((g, f)) = old {
            if g != genesis || f != fingerprint {
                return Err("Vote journal context mismatch".into());
            }
        } else {
            t.execute(
                "INSERT INTO vote_context VALUES(1,?1,?2)",
                params![genesis.as_slice(), fingerprint.as_slice()],
            )
            .map_err(err)?;
        }
        t.commit().map_err(err)?;
        Ok(Self {
            db,
            genesis,
            fingerprint,
        })
    }
    /// Every vote is independently validated first. Contradictory valid votes
    /// remain distinct evidence records; the BFT reducer rejects equivocation.
    /// No automatic slashing or vote from this journal is implied.
    pub fn admit<V: PhysicalAttestationVerifier>(
        &mut self,
        chain: &mut CanonicalStore,
        vote: &Vote,
        proposal: Option<&CandidateRecord>,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<bool> {
        let raw = vote.encode();
        if raw.len() > MAX_WIRE {
            return Err("Vote wire bound".into());
        }
        if chain.integrity_halted().map_err(err)? {
            return Err("Canonical integrity halt".into());
        }
        let (tip, _) = chain.load_effective().map_err(err)?;
        let (parent, state) = chain.execution_parent(tip.height).map_err(err)?;
        if parent.genesis != self.genesis || parent.fingerprint != self.fingerprint {
            return Err("Vote canonical context mismatch".into());
        }
        let authority = voter_actor::authority(&parent, &state).map_err(err)?;
        let mut ingress = AuthenticatedRound::new(authority).map_err(err)?;
        if !vote.nil {
            let p = proposal.ok_or("Vote requires executed proposal")?;
            let history = chain.evidence_history(&p.body).map_err(err)?;
            ingress
                .validate_proposal_with_history(
                    &state,
                    LicensedExecution {
                        parent: &parent,
                        header: &p.header,
                        body: &p.body,
                        authority: &p.authority,
                        signature: &p.signature,
                    },
                    physical,
                    verifier,
                    &history,
                )
                .map_err(err)?;
        }
        ingress.observe(vote).map_err(err)?;
        let key: Hash = Sha256::digest(&raw).into();
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let old: Option<Vec<u8>> = t
            .query_row(
                "SELECT CASE WHEN length(wire)<=2048 THEN wire END FROM received_votes WHERE id=?1",
                [key.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(old) = old {
            if old != raw {
                return Err("Vote digest collision".into());
            }
            return Ok(false);
        }
        let (count, bytes): (usize, usize) = t
            .query_row(
                "SELECT count(*),coalesce(sum(length(wire)),0) FROM received_votes",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        if count >= MAX_VOTES || bytes.checked_add(raw.len()).is_none_or(|n| n > MAX_BYTES) {
            return Err(
                "Vote custody capacity: archive qualification required; no evidence evicted".into(),
            );
        }
        t.execute(
            "INSERT INTO received_votes VALUES(?1,?2,?3)",
            params![
                key.as_slice(),
                vote.decision.height.to_be_bytes().as_slice(),
                raw
            ],
        )
        .map_err(err)?;
        t.commit().map_err(err)?;
        Ok(true)
    }
    pub fn height(&self, height: u64) -> Result<Vec<Vote>> {
        let mut q = self.db.prepare("SELECT id,CASE WHEN length(wire)<=2048 THEN wire END FROM received_votes WHERE height=?1 ORDER BY id LIMIT 100001").map_err(err)?;
        let mut result = Vec::new();
        let mut bytes = 0usize;
        for row in q
            .query_map([height.to_be_bytes().as_slice()], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(err)?
        {
            let (key, raw) = row.map_err(err)?;
            let digest: Hash = Sha256::digest(&raw).into();
            let vote = Vote::decode(&raw).map_err(err)?;
            if key != digest
                || vote.decision.height != height
                || vote.decision.genesis != self.genesis
                || vote.decision.fingerprint != self.fingerprint
            {
                return Err("Vote journal row corruption".into());
            }
            bytes = bytes.checked_add(raw.len()).ok_or("Vote byte overflow")?;
            if result.len() >= MAX_VOTES || bytes > MAX_BYTES {
                return Err("Vote journal bounds".into());
            }
            result.push(vote);
        }
        Ok(result)
    }
}
