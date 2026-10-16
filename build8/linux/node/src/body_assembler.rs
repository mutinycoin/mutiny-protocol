//! Production body planning from durable intents and current canonical state.
//! Selection is local policy; every selected body undergoes ordinary execution.
use crate::{operation_pool::OperationPool, worker_coordinator::BodyBuilder};
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    blocks::{BlockBody, operation_kind},
    canonical_store::CanonicalStore,
    execution::{CandidatePreparation, State, WorkParent},
    freshness::{AttestationRefresh, PhysicalAttestationVerifier, PhysicalMember},
    licenses::BindWorker,
    mempool::Mempool,
    participation::ParticipationAck,
    pow::{Candidate, mining_epoch},
    transactions::{Coin, OutPoint},
};
use std::collections::{BTreeMap, BTreeSet};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Body assembly: {e:?}")
}
/// Finite proposer work budget, not a consensus inclusion rule. The canonical
/// body limits still apply independently. Pending intents remain durable.
pub const MAX_PREVIEWS: usize = 128;
pub struct Assembler<V> {
    pub transactions: Mempool,
    pub operations: OperationPool,
    pub physical: BTreeMap<Hash, PhysicalMember>,
    pub verifier: V,
}
impl<V: PhysicalAttestationVerifier> Assembler<V> {
    fn basis(
        &mut self,
        chain: &mut CanonicalStore,
        binding: &BindWorker,
        timestamp: u64,
    ) -> Result<(WorkParent, State, BlockBody)> {
        if chain.integrity_halted().map_err(err)? {
            return Err("Canonical integrity halt".into());
        }
        self.operations.reconcile(chain)?;
        let (head, _) = chain.load().map_err(err)?;
        let (parent, state) = chain.execution_parent(head.height).map_err(err)?;
        if parent.block != head.block
            || self.operations.context() != (parent.genesis, parent.fingerprint)
        {
            return Err("Body parent/context changed".into());
        }
        let mut licenses = state.licenses.clone();
        licenses
            .activate_due(mining_epoch(timestamp, parent.t0).map_err(err)?)
            .map_err(err)?;
        let active = licenses
            .workers
            .get(&binding.worker_id())
            .ok_or("Unknown active Worker")?;
        if &active.binding != binding {
            return Err("Worker assignment changed".into());
        }
        let license = licenses
            .licenses
            .get(&binding.license)
            .ok_or("Unknown license")?;
        let body = BlockBody {
            height: parent.height.checked_add(1).ok_or("Height exhausted")?,
            reward_owner: license.owner,
            fees: 0,
            transactions: Vec::new(),
            operations: Vec::new(),
        };
        Ok((parent, state, body))
    }
    fn preview(
        &self,
        chain: &mut CanonicalStore,
        parent: &WorkParent,
        state: &State,
        binding: &BindWorker,
        timestamp: u64,
        body: &BlockBody,
    ) -> Result<()> {
        let candidate = Candidate {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            parent: parent.block,
            height: body.height,
            timestamp,
            body_root: body.root().map_err(err)?,
            state_root: [0; 32],
            license: binding.license,
            worker: binding.worker_id(),
            target: parent.target,
        };
        let (context, _) = state.work_context(parent, &candidate).map_err(err)?;
        let history = chain.evidence_history(body).map_err(err)?;
        state
            .prepare_candidate_with_history(
                CandidatePreparation {
                    parent,
                    candidate: &candidate,
                    ticket_sequence: context
                        .last_accepted_ticket
                        .checked_add(1)
                        .ok_or("Ticket exhausted")?,
                    body,
                },
                &self.physical,
                &self.verifier,
                &history,
            )
            .map_err(err)?;
        // This ticket is only a pure validation placeholder. Coordinator issuance
        // selects/reserves the real monotonic ticket and recomputes the StateRoot.
        Ok(())
    }
    fn add_transactions(
        &self,
        parent: &WorkParent,
        state: &State,
        body: &mut BlockBody,
    ) -> Result<()> {
        let mut pending = self.transactions.pending().map_err(err)?;
        let mut ordered = BTreeMap::new();
        for tx in pending.drain(..) {
            ordered.insert(tx.id().map_err(err)?, tx);
        }
        let mut coins = state.coins.clone();
        for (id, tx) in ordered.into_iter().take(MAX_PREVIEWS) {
            let Ok(fee) = tx.verify(parent.genesis, parent.fingerprint, body.height, &coins) else {
                continue;
            };
            let Some(fees) = body.fees.checked_add(fee) else {
                continue;
            };
            let raw = tx.encode().map_err(err)?;
            let mut trial = body.clone();
            trial.fees = fees;
            trial.transactions.push(raw);
            if trial.encode().is_err() {
                continue;
            }
            for input in &tx.inputs {
                coins.remove(&input.point);
            }
            for (index, output) in tx.outputs.iter().enumerate() {
                coins.insert(
                    OutPoint {
                        transaction: id,
                        index: index as u32,
                    },
                    Coin {
                        output: output.clone(),
                        created_height: body.height,
                        coinbase: false,
                    },
                );
            }
            *body = trial;
        }
        Ok(())
    }
    fn with_operation(body: &BlockBody, raw: &[u8]) -> Result<BlockBody> {
        let mut trial = body.clone();
        trial.operations.push(raw.to_vec());
        trial.operations.sort();
        trial.normalize_participation().map_err(err)?;
        trial.encode().map_err(err)?;
        Ok(trial)
    }
    /// Reject invalid signatures/state transitions before durable admission.
    /// Receipt means a local intent, never canonical inclusion or a BFT vote.
    pub fn admit_operation(
        &mut self,
        chain: &mut CanonicalStore,
        binding: &BindWorker,
        timestamp: u64,
        raw: &[u8],
    ) -> Result<Hash> {
        if operation_kind(raw).map_err(err)? == 17 {
            return Err("Use equivocation evidence admission".into());
        }
        let (parent, state, mut body) = self.basis(chain, binding, timestamp)?;
        // Reserve the intent's bytes before filling spare space with transfers.
        // In particular, a full transfer pool must not block timely ACK admission.
        body = Self::with_operation(&body, raw)?;
        self.add_transactions(&parent, &state, &mut body)?;
        let trial = body;
        self.preview(chain, &parent, &state, binding, timestamp, &trial)?;
        let (head, _) = chain.load().map_err(err)?;
        if head.height != parent.height || head.block != parent.block {
            return Err("Body parent changed".into());
        }
        self.operations.insert_validated(raw)
    }
    pub fn assemble(
        &mut self,
        chain: &mut CanonicalStore,
        binding: &BindWorker,
        timestamp: u64,
    ) -> Result<BlockBody> {
        let (parent, state, mut body) = self.basis(chain, binding, timestamp)?;
        // Reserve body space for timely evidence and physical liveness before
        // ordinary transactions. This is proposer policy, not a consensus rule
        // requiring inclusion of everything a particular peer happened to see.
        let evidence = chain.pending_equivocations(65536).map_err(err)?;
        let queued = self.operations.pending()?;
        let mut early = evidence;
        let mut later = Vec::new();
        for raw in queued {
            if matches!(operation_kind(&raw).map_err(err)?, 11 | 12) {
                early.push(raw);
            } else {
                later.push(raw);
            }
        }
        let mut visited = BTreeSet::new();
        let mut previews = 0;
        for (phase, operations) in [early, later].into_iter().enumerate() {
            if phase == 1 {
                self.add_transactions(&parent, &state, &mut body)?;
            }
            for raw in operations {
                if !visited.insert(raw.clone()) {
                    continue;
                }
                let kind = operation_kind(&raw).map_err(err)?;
                if kind == 11 && ParticipationAck::decode(&raw).map_err(err)?.height != body.height
                {
                    continue;
                }
                if kind == 12
                    && AttestationRefresh::decode(&raw).map_err(err)?.height != body.height
                {
                    continue;
                }
                if previews == MAX_PREVIEWS {
                    break;
                }
                previews += 1;
                let Ok(trial) = Self::with_operation(&body, &raw) else {
                    continue;
                };
                if self
                    .preview(chain, &parent, &state, binding, timestamp, &trial)
                    .is_ok()
                {
                    body = trial;
                }
            }
        }
        self.preview(chain, &parent, &state, binding, timestamp, &body)?;
        let (head, _) = chain.load().map_err(err)?;
        if head.height != parent.height || head.block != parent.block {
            return Err("Body parent changed".into());
        }
        Ok(body)
    }
}
impl<V: PhysicalAttestationVerifier + Send + 'static> BodyBuilder for Assembler<V> {
    fn admit_current_operation(
        &mut self,
        chain: &mut CanonicalStore,
        timestamp: u64,
        raw: &[u8],
    ) -> Result<Hash> {
        let (tip, _) = chain.load_effective().map_err(err)?;
        let (parent, mut state) = chain.execution_parent(tip.height).map_err(err)?;
        let epoch = mining_epoch(timestamp, parent.t0).map_err(err)?;
        state.licenses.activate_due(epoch).map_err(err)?;
        let binding = state
            .licenses
            .workers
            .iter()
            .find_map(|(worker, record)| {
                state
                    .licenses
                    .active(record.binding.license, *worker, epoch)
                    .ok()
                    .map(|(_, active)| active.binding.clone())
            })
            .ok_or("No canonical active Worker for body validation")?;
        self.admit_operation(chain, &binding, timestamp, raw)
    }
    fn pending_operations(&mut self, chain: &mut CanonicalStore) -> Result<Vec<Vec<u8>>> {
        self.operations.reconcile(chain)?;
        self.operations.pending()
    }
    fn body(
        &mut self,
        chain: &mut CanonicalStore,
        binding: &BindWorker,
        timestamp: u64,
    ) -> Result<BlockBody> {
        self.assemble(chain, binding, timestamp)
    }
}

#[cfg(test)]
#[path = "body_assembler_tests.rs"]
mod tests;
