//! Coordinator application service joining canonical candidate execution,
//! durable work issuance, and exact-result accounting. The TCP actor serializes
//! canonical changes with these calls and authenticates the Worker first.
use crate::{
    Hash, NETWORK_ID,
    blocks::BlockBody,
    canonical_store::CanonicalStore,
    execution::CandidatePreparation,
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    liveness::WorkGate,
    observations::{ObservationStore, Receipt, Submission},
    pow::{Candidate, WorkHeader},
    work_issuance::{IssueRequest, IssuedWork, WorkIssuanceStore},
};
use ed25519_dalek::SigningKey;
use std::{collections::BTreeMap, path::Path};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Coordinator: {e:?}")
}
pub struct MiningRequest {
    pub worker: Hash,
    pub license: Hash,
    pub body: BlockBody,
    pub timestamp: u64,
    pub now_ms: u64,
    pub unix_ms: u64,
    pub observation_sequence: u64,
    pub observation_chain: Hash,
}
pub struct ObservedWork {
    pub header: WorkHeader,
    pub issued: Option<IssuedWork>,
    pub receipt: Receipt,
}
pub struct Coordinator {
    work: WorkIssuanceStore,
    observations: ObservationStore,
    key: SigningKey,
}
impl Coordinator {
    pub fn open(
        work_path: &Path,
        observation_path: &Path,
        genesis: Hash,
        fingerprint: Hash,
        key: SigningKey,
    ) -> Result<Self> {
        if work_path == observation_path {
            return Err("Separate coordinator stores required".into());
        }
        Ok(Self {
            work: WorkIssuanceStore::open(
                work_path,
                genesis,
                fingerprint,
                key.verifying_key().to_bytes(),
            )?,
            observations: ObservationStore::open(observation_path, genesis, fingerprint)
                .map_err(err)?,
            key,
        })
    }
    pub fn issue<V: PhysicalAttestationVerifier>(
        &mut self,
        chain: &mut CanonicalStore,
        gate: &mut WorkGate,
        request: MiningRequest,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
        final_clock: impl FnOnce() -> Result<(u64, u64)>,
    ) -> Result<(IssuedWork, u64)> {
        let checkpoint = self.observations.checkpoint(request.worker).map_err(err)?;
        if checkpoint.0 != request.observation_sequence || checkpoint.2 != request.observation_chain
        {
            return Err("Worker accounting checkpoint mismatch".into());
        }
        if chain.integrity_halted().map_err(err)? {
            return Err("Canonical integrity halt".into());
        }
        let (tip, _) = chain.load_effective().map_err(err)?;
        let (parent, state) = chain.execution_parent(tip.height).map_err(err)?;
        if parent.block != tip.block {
            return Err("Canonical parent changed".into());
        }
        let height = parent.height.checked_add(1).ok_or("Height exhausted")?;
        let candidate = Candidate {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            parent: parent.block,
            height,
            timestamp: request.timestamp,
            body_root: request.body.root().map_err(err)?,
            state_root: [0; 32],
            license: request.license,
            worker: request.worker,
            target: parent.target,
        };
        let (context, _) = state.work_context(&parent, &candidate).map_err(err)?;
        let history = chain.evidence_history(&request.body).map_err(err)?;
        let (issued, lifetime) = self.work.issue(
            IssueRequest {
                candidate,
                context,
                now_ms: request.now_ms,
                unix_ms: request.unix_ms,
            },
            &self.key,
            gate,
            |ticket, candidate| {
                let prepared = state
                    .prepare_candidate_with_history(
                        CandidatePreparation {
                            parent: &parent,
                            candidate,
                            ticket_sequence: ticket,
                            body: &request.body,
                        },
                        physical,
                        verifier,
                        &history,
                    )
                    .map_err(err)?;
                Ok((prepared.root, request.body))
            },
            || {
                // Revalidate canonical authority before the final qualified
                // reading, so no blocking canonical IO follows that reading.
                let (current, _) = chain.load_effective().map_err(err)?;
                if current != tip || chain.integrity_halted().map_err(err)? {
                    return Err("Canonical parent changed during preparation".into());
                }
                final_clock()
            },
        )?;
        // A changed tip discards the offer, never rolls its durable ticket back.
        let (current, _) = chain.load_effective().map_err(err)?;
        if current != tip || chain.integrity_halted().map_err(err)? {
            return Err("Canonical parent changed during preparation".into());
        }
        Ok((issued, lifetime))
    }
    /// Exact retransmission only: the receipt this coordinator already stored for exactly this
    /// submission, or `None` when the submission is the Worker's next, new result. It never
    /// accepts, credits or signs anything, so it needs no clock (Architect decision V2: exact
    /// stored-receipt retransmission stays available while the clock is unqualified). A submission
    /// that contradicts the stored checkpoint is refused exactly as `result` refuses it.
    pub fn retransmission(
        &self,
        authenticated_worker: Hash,
        raw: &[u8],
    ) -> Result<Option<ObservedWork>> {
        let submission = Submission::decode(raw).map_err(err)?;
        let header = submission.header().map_err(err)?;
        if header.candidate.worker != authenticated_worker {
            return Err("Result Worker mismatch".into());
        }
        let Some(receipt) = self
            .observations
            .retry(authenticated_worker, &submission)
            .map_err(err)?
        else {
            return Ok(None);
        };
        let issued = self
            .work
            .lookup(header.authority, authenticated_worker)
            .ok();
        Ok(Some(ObservedWork {
            header,
            issued,
            receipt,
        }))
    }
    pub fn result(&mut self, authenticated_worker: Hash, raw: &[u8]) -> Result<ObservedWork> {
        if let Some(observed) = self.retransmission(authenticated_worker, raw)? {
            return Ok(observed);
        }
        let submission = Submission::decode(raw).map_err(err)?;
        let header = submission.header().map_err(err)?;
        let issued = self.work.lookup(header.authority, authenticated_worker)?;
        let receipt = self
            .observations
            .accept(
                &submission,
                &issued.authority,
                &issued.signature,
                &issued.context,
                &self.key,
            )
            .map_err(err)?;
        // Caller may submit this candidate to ordinary BFT validation. This
        // receipt alone neither applies state nor overrides a retired parent.
        Ok(ObservedWork {
            header,
            issued: Some(issued),
            receipt,
        })
    }
    pub fn total(&self, worker: Hash) -> Result<u64> {
        self.observations.total(worker).map_err(err)
    }
}
