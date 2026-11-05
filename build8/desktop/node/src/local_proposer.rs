//! Durable local proposer selection. Only the canonical scheduled node may emit
//! this message; proposal signing is separate from TPM Continuity voting.
use crate::{
    candidate_journal::CandidateJournal,
    proposer_cursor::ProposerCursor,
    round_proposal::{MAX_WIRE, RoundProposal},
    vote_journal::VoteJournal,
};
use ed25519_dalek::SigningKey;
use mutiny_consensus_v8::{
    Error, Hash,
    canonical_store::CanonicalStore,
    certificates::{Certificate, Signer},
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    voter_actor::{self, VoterActor},
    votes::Vote,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{collections::BTreeMap, path::Path};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Local proposer: {e:?}")
}
pub struct LocalProposer {
    db: Connection,
    node: Hash,
    key: SigningKey,
    genesis: Hash,
    fingerprint: Hash,
    cursor: ProposerCursor,
}
/// The proposer's selection for one (height, round): the block to offer and its proof-of-lock
/// round. It is the only capability that can produce a NEW signed `RoundProposal`
/// (`RoundProposal::signed` consumes it). Its fields are private and nothing hands one out, so it
/// exists only inside `LocalProposer::propose`, built once, after the selection: a verified proof
/// of lock or the held lock (both offer an existing block again, unchanged), or the lowest-hash
/// candidate eligible under the voter's own qualified clock. No `Clone`: an offer is used once.
pub(crate) struct Offer {
    block: Hash,
    pol_round: Option<u64>,
}
impl Offer {
    pub(crate) fn block(&self) -> Hash {
        self.block
    }
    pub(crate) fn pol_round(&self) -> Option<u64> {
        self.pol_round
    }
}
impl LocalProposer {
    pub fn open(
        path: &Path,
        node: Hash,
        key: SigningKey,
        genesis: Hash,
        fingerprint: Hash,
    ) -> Result<Self> {
        let mut db = Connection::open(path).map_err(err)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(err)?;
        db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS proposer_context(singleton INTEGER PRIMARY KEY CHECK(singleton=1),binding BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS local_proposals(height BLOB NOT NULL CHECK(length(height)=8),round BLOB NOT NULL CHECK(length(round)=8),wire BLOB NOT NULL,PRIMARY KEY(height,round));").map_err(err)?;
        let binding = [
            genesis.as_slice(),
            fingerprint.as_slice(),
            node.as_slice(),
            key.verifying_key().as_bytes(),
        ]
        .concat();
        let t = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let old:Option<Vec<u8>>=t.query_row("SELECT CASE WHEN length(binding)=128 THEN binding END FROM proposer_context WHERE singleton=1",[],|r|r.get(0)).optional().map_err(err)?;
        if let Some(old) = old {
            if old != binding {
                return Err("Proposer custody context mismatch".into());
            }
        } else {
            t.execute("INSERT INTO proposer_context VALUES(1,?1)", [binding])
                .map_err(err)?;
        }
        t.commit().map_err(err)?;
        Ok(Self {
            db,
            node,
            key,
            genesis,
            fingerprint,
            cursor: ProposerCursor::default(),
        })
    }
    pub fn propose<V: PhysicalAttestationVerifier>(
        &mut self,
        chain: &mut CanonicalStore,
        actor: &VoterActor,
        candidates: &mut CandidateJournal,
        received: &VoteJournal,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<Option<RoundProposal>> {
        let (progress, _, _) = actor.progress().map_err(err)?;
        let Some(selected) = self.cursor.selected(chain, progress.round)? else {
            return Ok(None);
        };
        if selected.1 != self.node {
            return Ok(None);
        }
        let (tip, state) = chain.load_effective().map_err(err)?;
        if tip.height.checked_add(1) != Some(actor.height()) {
            return Err("Proposer/voter height mismatch".into());
        }
        let (parent, _) = chain.execution_parent(tip.height).map_err(err)?;
        if parent.genesis != self.genesis || parent.fingerprint != self.fingerprint {
            return Err("Proposer canonical context mismatch".into());
        }
        let authority = voter_actor::authority(&parent, &state).map_err(err)?;
        let control = state
            .membership
            .controls
            .get(&self.node)
            .ok_or("Missing canonical node authentication")?;
        if control.node_authentication != self.key.verifying_key().to_bytes() {
            return Err("Wrong node authentication custody".into());
        }
        let height = actor.height();
        let old:Option<Vec<u8>>=self.db.query_row("SELECT CASE WHEN length(wire)<=512 THEN wire END FROM local_proposals WHERE height=?1 AND round=?2",
            params![height.to_be_bytes().as_slice(),progress.round.to_be_bytes().as_slice()],|r|r.get(0)).optional().map_err(err)?;
        let records = candidates.records()?;
        let mut choice = None;
        if let Some(raw) = old {
            let proposal = RoundProposal::decode(&raw)?;
            proposal.verify_current(chain, selected)?;
            let record = records
                .iter()
                .find(|p| p.header.block_hash() == proposal.block)
                .ok_or("Persisted proposal candidate unavailable")?;
            candidates.accept(chain, record, physical, verifier)?;
            return Ok(Some(proposal));
        }
        // A verified prior-round PoLC is preferred to an older lock; otherwise
        // preserve the local lock. Candidate arrival order is only a pool input.
        let mut groups: BTreeMap<(u64, Hash), BTreeMap<Hash, Vote>> = BTreeMap::new();
        for vote in received.height(height)? {
            let d = &vote.decision;
            if !vote.nil
                && d.step == 2
                && d.round < progress.round
                && d.membership == authority.membership
                && d.reputation == authority.reputation
                && d.attestation == authority.attestation
                && d.previous_finalized_anchor == authority.parent.id()
            {
                groups
                    .entry((d.round, d.id()))
                    .or_default()
                    .entry(vote.node)
                    .or_insert(vote);
            }
        }
        for ((round, _), group) in groups.into_iter().rev() {
            if progress.locked.as_ref().is_some_and(|l| l.round > round) {
                continue;
            }
            let decision = group.values().next().unwrap().decision.clone();
            let cert = Certificate {
                decision: decision.clone(),
                signers: group
                    .into_values()
                    .map(|v| Signer {
                        node: v.node,
                        key_version: v.key_version,
                        signature: v.signature,
                    })
                    .collect(),
            };
            match cert.verify_quorum(&decision, &authority.voters) {
                Ok(()) => {
                    if records
                        .iter()
                        .any(|p| p.header.block_hash() == decision.block)
                    {
                        choice = Some((decision.block, Some(round)));
                        break;
                    }
                }
                Err(Error::NoQuorum) => (),
                Err(e) => return Err(err(e)),
            }
        }
        if choice.is_none() {
            choice = fallback_choice(
                &records,
                progress.locked.as_ref().map(|l| l.block),
                height,
                tip.block,
                &|timestamp| actor.timestamp_status(timestamp).is_eligible(),
            );
        }
        let Some((block, pol_round)) = choice else {
            return Ok(None);
        };
        let record = records
            .iter()
            .find(|p| p.header.block_hash() == block)
            .ok_or("Locked candidate unavailable")?;
        candidates.accept(chain, record, physical, verifier)?;
        // The selection above is the only source of an `Offer`, and an `Offer` is the only way to
        // a new signed proposal (see `round_proposal`).
        let offer = Offer { block, pol_round };
        let proposal = RoundProposal::signed(
            authority.parent,
            progress.round,
            self.node,
            control.generation,
            offer,
            &self.key,
        );
        proposal.verify_current(chain, selected)?;
        let raw = proposal.encode();
        if raw.len() > MAX_WIRE {
            return Err("Proposal bound".into());
        }
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        // Only finalized predecessors can be reclaimed. This journal contains
        // local scheduling messages, not canonical blocks or TPM vote evidence.
        t.execute(
            "DELETE FROM local_proposals WHERE height<=?1",
            [tip.height.to_be_bytes().as_slice()],
        )
        .map_err(err)?;
        let count: usize = t
            .query_row("SELECT count(*) FROM local_proposals", [], |r| r.get(0))
            .map_err(err)?;
        if count >= 4096 {
            return Err("Proposer custody capacity".into());
        }
        // An independent writer cannot overwrite an already selected proposal.
        t.execute(
            "INSERT INTO local_proposals VALUES(?1,?2,?3)",
            params![
                height.to_be_bytes().as_slice(),
                progress.round.to_be_bytes().as_slice(),
                raw
            ],
        )
        .map_err(err)?;
        t.commit().map_err(err)?;
        Ok(Some(proposal))
    }
}

/// The block a proposer offers when no verified PoLC applies: (1) the held lock, UNCHANGED and
/// UNFILTERED (a locked re-proposal keeps its original bytes, timestamp and decision, whatever the
/// clock says now); otherwise (2) the lowest-hash current candidate among those `eligible` under
/// the proposer's own qualified clock (`timestamp <= qualified now`, the voter's comparison).
///
/// Why the filter exists: `pow::validate_timestamp` has no upper bound by design, so a licensed
/// coordinator can produce a valid far-future candidate with a low hash. An honest validator defers
/// it (`vote_clock_v1`), so proposing it every round would end every round in nil. Deferred
/// candidates are not discarded here (the journal is untouched) and become choosable when the
/// clock reaches them. An unqualified clock makes nothing eligible: no new proposal, never a
/// fallback to an unqualified reading.
///
/// What the vote gate does with a locked block in a later round: it is a NEW (round, step) slot,
/// hence a fresh vote, and is judged like any other block (`block.timestamp <= qualified now`).
/// The lock was created under that gate and the qualified clock never goes backwards, so a held
/// lock is normally still eligible; if the clock is unqualified the validator abstains for liveness
/// only and nil votes stay available.
pub(crate) fn fallback_choice(
    records: &[crate::candidate_journal::CandidateRecord],
    locked: Option<Hash>,
    height: u64,
    parent: Hash,
    eligible: &dyn Fn(u64) -> bool,
) -> Option<(Hash, Option<u64>)> {
    if let Some(block) = locked {
        return Some((block, None));
    }
    records
        .iter()
        .filter(|p| p.header.candidate.height == height && p.header.candidate.parent == parent)
        .filter(|p| eligible(p.header.candidate.timestamp))
        .map(|p| (p.header.block_hash(), None))
        .min_by_key(|p| p.0)
}
