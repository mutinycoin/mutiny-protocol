//! One serialized owner for mining ingress and canonical/BFT transitions.
//! Both network listeners must share the same Arc<Mutex<IntegratedActor>>.
use crate::{
    candidate_journal::CandidateRecord,
    local_proposer::LocalProposer,
    round_proposal::RoundProposal,
    vote_journal::VoteJournal,
    voter_driver::{Driver, Tick},
    worker_coordinator::{BodyBuilder, JournaledCandidates, WorkerCoordinator},
    worker_protocol::WorkerMessage,
    worker_server::WorkerBackend,
};
use mutiny_consensus_v8::{
    Hash, block_envelope::BlockEnvelope, counter_voter::CounterSigningBackend,
    freshness::PhysicalAttestationVerifier, licenses::BindWorker, voter_actor::VoterActor,
    votes::Vote,
};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Integrated actor: {e:?}")
}
pub struct SigningState<B> {
    pub voter: VoterActor,
    pub backend: B,
    pub proposer: Option<LocalProposer>,
    pub participation: Option<crate::participation_producer::Producer>,
}
pub struct IntegratedActor<V, H, B> {
    pub workers: WorkerCoordinator<V, JournaledCandidates<H>>,
    pub received: VoteJournal,
    pub signing: Option<SigningState<B>>,
    driver: Driver,
    work_probes: crate::work_probes::WorkProbes,
    runtime_fault: Option<String>,
    context: (Hash, Hash),
    incoming_proposal: Option<RoundProposal>,
    advertised_proposal: Option<RoundProposal>,
    proposal_cursor: crate::proposer_cursor::ProposerCursor,
    /// The conservative qualified basis shared with the voter guard and the work coordinator. It is
    /// mandatory (owned by the coordinator): there is no OS-clock fallback for operation admission,
    /// participation or work.
    time: std::sync::Arc<dyn mutiny_consensus_v8::holdover_clock_v1::TimeBasis>,
}
pub struct ActorTick {
    pub proposal: Option<RoundProposal>,
    pub consensus: Tick,
}
impl<
    V: PhysicalAttestationVerifier,
    H: BodyBuilder,
    B: CounterSigningBackend + crate::participation_producer::ParticipationSigner,
> IntegratedActor<V, H, B>
{
    pub fn new(
        mut workers: WorkerCoordinator<V, JournaledCandidates<H>>,
        received: VoteJournal,
        signing: Option<SigningState<B>>,
    ) -> Result<Self> {
        let (tip, _) = workers.chain.load_effective().map_err(err)?;
        let (parent, _) = workers.chain.execution_parent(tip.height).map_err(err)?;
        let context = (parent.genesis, parent.fingerprint);
        let time = workers.time_basis();
        if received.context() != context || workers.hooks.journal.context() != context {
            return Err("Actor journal context mismatch".into());
        }
        Ok(Self {
            workers,
            received,
            signing,
            driver: Driver::default(),
            work_probes: crate::work_probes::WorkProbes::default(),
            runtime_fault: None,
            context,
            incoming_proposal: None,
            advertised_proposal: None,
            proposal_cursor: crate::proposer_cursor::ProposerCursor::default(),
            time,
        })
    }
    /// Whole seconds for admission-time decisions: the floor of the qualified lower bound, `None`
    /// while the clock is unqualified (admission is then withheld, never taken from the OS clock).
    fn admission_seconds(&self) -> Option<u64> {
        self.time.seconds()
    }
    pub fn pause_after_fault(&mut self, reason: String) {
        self.runtime_fault = Some(reason);
    }
    fn available(&self) -> Result<()> {
        if let Some(reason) = &self.runtime_fault {
            return Err(format!("Runtime paused after actor failure: {reason}"));
        }
        Ok(())
    }
    /// The latched runtime fault, if the service has paused this actor.
    pub fn runtime_fault(&self) -> Option<&str> {
        self.runtime_fault.as_deref()
    }
    /// Test support only: model a process restart of the driver's in-memory state (memoised
    /// candidate validation, round timers). Durable state is untouched.
    #[cfg(test)]
    pub(crate) fn restart_driver_for_test(&mut self) {
        self.driver = Driver::default();
    }
    #[cfg(test)]
    pub(crate) fn set_round_delay_for_test(&mut self, delay: std::time::Duration) {
        self.driver.set_round_delay_for_test(delay);
    }
    #[cfg(test)]
    pub(crate) fn set_driver_time_for_test(&mut self, time: std::sync::Arc<std::sync::Mutex<std::time::Instant>>) {
        self.driver.set_time_for_test(time);
    }
    pub fn tick(&mut self, incoming: Option<&RoundProposal>) -> Result<ActorTick> {
        self.available()?;
        if let Some(signing) = self.signing.as_ref() {
            let (progress, _, _) = signing.voter.progress().map_err(err)?;
            if self.incoming_proposal.as_ref().is_some_and(|p| {
                p.parent.height.checked_add(1) != Some(signing.voter.height())
                    || p.round != progress.round
            }) {
                self.incoming_proposal = None;
            }
        }
        let (probe_authority, probe_root) = self.work_basis()?;
        self.work_probes.synchronize(&probe_authority, probe_root);
        if let Some(probe) = self.workers.probe()? {
            self.work_probes
                .begin(probe, &probe_authority, probe_root)?;
        }
        // Worker results held while the clock was unqualified are processed once it is qualified
        // again; until then they stay held and nothing is accepted or credited (decision V2).
        self.workers.process_deferred_results();
        let queued = self.incoming_proposal.clone();
        let w = &mut self.workers;
        if let Some(signing) = self.signing.as_mut() {
            signing
                .voter
                .reconcile(&mut w.chain, &mut signing.backend, &w.physical, &w.verifier)
                .map_err(err)?;
            // Without a qualified clock no participation operation is produced or admitted; it is
            // produced on a later tick, never created and then discarded.
            let admission_time = self.time.seconds();
            if let (Some(producer), Some(timestamp)) =
                (signing.participation.as_mut(), admission_time)
            {
                signing
                    .voter
                    .check_backend(&mut w.chain, &mut signing.backend)
                    .map_err(err)?;
                let operations = producer.produce(
                    &mut w.chain,
                    &mut signing.backend,
                    &w.physical,
                    &w.verifier,
                )?;
                for raw in operations {
                    w.hooks
                        .builder
                        .admit_current_operation(&mut w.chain, timestamp, &raw)?;
                }
            }
            if probe_authority
                .voters
                .get(&signing.voter.node())
                .is_some_and(|v| !v.weight.is_zero())
            {
                let pending = self.work_probes.pending(signing.voter.node());
                if !pending.is_empty() {
                    signing
                        .voter
                        .check_backend(&mut w.chain, &mut signing.backend)
                        .map_err(err)?;
                }
                for (peer, decision) in pending {
                    let signature = mutiny_consensus_v8::liveness::sign_probe(
                        &decision,
                        &probe_authority,
                        probe_root,
                        signing.voter.node(),
                        &mut signing.backend,
                    )
                    .map_err(err)?;
                    self.work_probes.signed(
                        peer,
                        mutiny_consensus_v8::certificates::Certificate {
                            decision,
                            signers: vec![signature],
                        },
                        &probe_authority,
                        probe_root,
                    )?;
                }
            }
            if let Some(proof) = self.work_probes.quorum(&probe_authority)? {
                w.accept_probe(&proof)?;
            }
            let proposal = match signing.proposer.as_mut() {
                Some(local) => local.propose(
                    &mut w.chain,
                    &signing.voter,
                    &mut w.hooks.journal,
                    &self.received,
                    &w.physical,
                    &w.verifier,
                )?,
                None => None,
            };
            let consensus = self.driver.tick(
                &mut w.chain,
                &mut signing.voter,
                &mut signing.backend,
                &w.hooks.journal,
                &mut self.received,
                proposal.as_ref().or(incoming).or(queued.as_ref()),
                &w.physical,
                &w.verifier,
            )?;
            if let Some(p) = proposal.as_ref() {
                self.advertised_proposal = Some(p.clone());
            }
            Ok(ActorTick {
                proposal,
                consensus,
            })
        } else {
            if let Some(proof) = self.work_probes.quorum(&probe_authority)? {
                w.accept_probe(&proof)?;
            }
            let finalized = self.received.finalize_ready(
                &mut w.chain,
                &w.hooks.journal.records()?,
                &w.physical,
                &w.verifier,
            )?;
            Ok(ActorTick {
                proposal: None,
                consensus: Tick {
                    finalized: finalized.map(|b| b.block_hash()),
                    ..Tick::default()
                },
            })
        }
    }
    fn work_basis(&mut self) -> Result<(mutiny_consensus_v8::votes::HeightAuthority, Hash)> {
        let (tip, state) = self.workers.chain.load_effective().map_err(err)?;
        let (parent, _) = self
            .workers
            .chain
            .execution_parent(tip.height)
            .map_err(err)?;
        Ok((
            mutiny_consensus_v8::voter_actor::authority(&parent, &state).map_err(err)?,
            state.root().map_err(err)?,
        ))
    }
    pub fn round_proposal(&mut self, proposal: RoundProposal) -> Result<()> {
        self.available()?;
        let signing = self.signing.as_ref().ok_or("No local voter")?;
        let (progress, _, _) = signing.voter.progress().map_err(err)?;
        if proposal.round != progress.round
            || proposal.parent.height.checked_add(1) != Some(signing.voter.height())
        {
            return Err("Proposal is not current local round".into());
        }
        let selected = self
            .proposal_cursor
            .selected(&mut self.workers.chain, progress.round)?
            .ok_or("Proposer schedule reconstruction pending")?;
        proposal.verify_current(&mut self.workers.chain, selected)?;
        if let Some(old) = self.incoming_proposal.as_ref() {
            if old.parent == proposal.parent && old.round == proposal.round && old != &proposal {
                return Err("Conflicting round proposal; no participation/vote penalty".into());
            }
        }
        self.incoming_proposal = Some(proposal);
        Ok(())
    }
    pub fn candidate(&mut self, candidate: &CandidateRecord) -> Result<()> {
        self.available()?;
        let w = &mut self.workers;
        w.hooks
            .journal
            .accept(&mut w.chain, candidate, &w.physical, &w.verifier)
    }
    pub fn vote(&mut self, vote: &Vote) -> Result<bool> {
        self.available()?;
        let w = &mut self.workers;
        let candidates = w.hooks.journal.records()?;
        let candidate = candidates
            .iter()
            .find(|p| p.header.block_hash() == vote.decision.block);
        self.received
            .admit(&mut w.chain, vote, candidate, &w.physical, &w.verifier)
    }
    pub fn commit(&mut self, block: &BlockEnvelope) -> Result<bool> {
        self.available()?;
        let w = &mut self.workers;
        let accepted = w
            .chain
            .commit_integrated(block, &w.physical, &w.verifier)
            .map_err(err)?;
        if let Some(signing) = self.signing.as_mut() {
            signing
                .voter
                .reconcile(&mut w.chain, &mut signing.backend, &w.physical, &w.verifier)
                .map_err(err)?;
        }
        Ok(accepted)
    }
}
impl<V, H, B> WorkerBackend for IntegratedActor<V, H, B>
where
    V: PhysicalAttestationVerifier + Send + 'static,
    H: BodyBuilder,
    B: CounterSigningBackend + crate::participation_producer::ParticipationSigner + Send + 'static,
{
    fn active(&mut self, worker: Hash) -> Result<BindWorker> {
        self.available()?;
        self.workers.active(worker)
    }
    fn handle(&mut self, worker: Hash, message: WorkerMessage) -> Result<Vec<u8>> {
        self.available()?;
        self.workers.handle(worker, message)
    }
}

impl<V, H, B> crate::peer_server::PeerBackend for IntegratedActor<V, H, B>
where
    V: PhysicalAttestationVerifier + Send + 'static,
    H: BodyBuilder,
    B: CounterSigningBackend + crate::participation_producer::ParticipationSigner + Send + 'static,
{
    fn context(&self) -> (Hash, Hash) {
        self.context
    }
    fn handle(&mut self, peer: Hash, raw: &[u8]) -> Result<crate::peer_server::PeerReply> {
        use serde_json::{Value, json};
        let request: Value = serde_json::from_slice(raw).map_err(err)?;
        let method = request["method"].as_str().ok_or("Peer method required")?;
        let close = method == "end_session";
        let result = (|| -> Result<Value> {
            fn bytes(value: &Value, limit: usize) -> Result<Vec<u8>> {
                let raw = value.as_str().ok_or("Encoded bytes required")?;
                if raw.len() > limit * 2 {
                    return Err("Encoded object bound".into());
                }
                hex::decode(raw).map_err(err)
            }
            match method {
                "end_session" => Ok(json!({"status":"CLOSED"})),
                "status" => {
                    let (tip, state) = self.workers.chain.load_effective().map_err(err)?;
                    let voting_enabled = if let Some(signing) = &self.signing {
                        state
                            .continuity
                            .as_ref()
                            .ok_or("Missing Continuity registry")?
                            .voters()
                            .map_err(err)?
                            .get(&signing.voter.node())
                            .is_some_and(|v| !v.weight.is_zero())
                    } else {
                        false
                    };
                    Ok(
                        json!({"height":tip.height,"block_hash":hex::encode(tip.block),"state_root":hex::encode(tip.root),
                        "genesis_id":hex::encode(self.context.0),"protocol_fingerprint":hex::encode(self.context.1),
                        "integrity_halted":self.workers.chain.integrity_halted().map_err(err)?,"voting_enabled":voting_enabled,
                        "signing_custody":self.signing.is_some(),"runtime_fault":self.runtime_fault}),
                    )
                }
                "get_block" => Ok(
                    json!({"envelope":self.workers.chain.block_bytes(request["height"].as_u64().ok_or("Height required")?).map_err(err)?.map(hex::encode)}),
                ),
                "get_recovery" => Ok(
                    json!({"envelope":self.workers.chain.recovery_envelope(request["height"].as_u64().ok_or("Height required")?).map_err(err)?.map(hex::encode)}),
                ),
                "submit_recovery" => {
                    self.available()?;
                    let raw=bytes(&request["recovery"],mutiny_consensus_v8::canonical_store::recovery_transport::MAX_RECOVERY_ENVELOPE)?;
                    let added = self
                        .workers
                        .chain
                        .accept_recovery_envelope(&raw)
                        .map_err(err)?;
                    Ok(json!({"status":if added{"RECOVERY_COMMITTED"}else{"ALREADY_COMMITTED"}}))
                }
                "state_proof" => {
                    let proof = crate::state_proof_service::respond(
                        &mut self.workers.chain,
                        &bytes(&request["request"], crate::state_proof_service::MAX_REQUEST)?,
                    )
                    .map_err(err)?;
                    Ok(json!({"proof":hex::encode(proof)}))
                }
                "get_work_probe" => {
                    let (authority, root) = self.work_basis()?;
                    self.work_probes.synchronize(&authority, root);
                    Ok(json!({"probe":self.work_probes.own().map(|p|hex::encode(p.encode()))}))
                }
                "queue_work_probe" => {
                    self.available()?;
                    let request = mutiny_consensus_v8::certificates::Decision::decode(&bytes(
                        &request["probe"],
                        2048,
                    )?)
                    .map_err(err)?;
                    let (authority, root) = self.work_basis()?;
                    self.work_probes.queue(peer, request, &authority, root)?;
                    Ok(json!({"status":"QUEUED","signature_created":false}))
                }
                "get_work_response" => {
                    let (authority, root) = self.work_basis()?;
                    self.work_probes.synchronize(&authority, root);
                    Ok(
                        json!({"fragment":self.work_probes.response(peer).map(|p|p.encode().map(hex::encode)).transpose().map_err(err)?}),
                    )
                }
                "submit_work_fragment" => {
                    self.available()?;
                    let fragment = mutiny_consensus_v8::certificates::Certificate::decode(&bytes(
                        &request["fragment"],
                        256 * 1024,
                    )?)
                    .map_err(err)?;
                    let (authority, root) = self.work_basis()?;
                    self.work_probes.receive(&fragment, &authority, root)?;
                    Ok(json!({"status":"FRAGMENT_VALIDATED"}))
                }
                "submit_operation" => {
                    self.available()?;
                    let timestamp = self
                        .admission_seconds()
                        .ok_or("Qualified clock unavailable: operation admission withheld")?;
                    let operation = bytes(&request["operation"], 16384)?;
                    let id = self.workers.hooks.builder.admit_current_operation(
                        &mut self.workers.chain,
                        timestamp,
                        &operation,
                    )?;
                    Ok(json!({"operation_id":hex::encode(id),"status":"PENDING"}))
                }
                "get_operations" => {
                    let offset = request["offset"].as_u64().ok_or("Offset required")?;
                    let height = request["height"].as_u64().ok_or("Height required")?;
                    let (tip, _) = self.workers.chain.load().map_err(err)?;
                    if offset > 4096 || tip.height.checked_add(1) != Some(height) {
                        return Err("Operation cursor/height bound".into());
                    }
                    let operations = self
                        .workers
                        .hooks
                        .builder
                        .pending_operations(&mut self.workers.chain)?;
                    let page: Vec<_> = operations
                        .iter()
                        .skip(offset as usize)
                        .take(16)
                        .map(hex::encode)
                        .collect();
                    Ok(
                        json!({"items":page,"next":offset as usize+page.len(),"complete":offset as usize+page.len()>=operations.len()}),
                    )
                }
                "get_candidates" => {
                    let height = request["height"].as_u64().ok_or("Height required")?;
                    let offset = request["offset"].as_u64().ok_or("Offset required")?;
                    if offset > 1024 {
                        return Err("Candidate cursor bound".into());
                    }
                    let (tip, _) = self.workers.chain.load().map_err(err)?;
                    if tip.height.checked_add(1) != Some(height) {
                        return Err("Candidates require current height".into());
                    }
                    let mut candidates = self.workers.hooks.journal.records()?;
                    candidates.retain(|p| p.header.candidate.height == height);
                    candidates.sort_by_key(|p| p.header.block_hash());
                    let page = candidates
                        .iter()
                        .skip(offset as usize)
                        .take(4)
                        .map(|p| p.encode().map(hex::encode))
                        .collect::<Result<Vec<_>>>()?;
                    Ok(
                        json!({"items":page,"next":offset as usize+page.len(),"complete":offset as usize+page.len()>=candidates.len()}),
                    )
                }
                "get_votes" => {
                    let height = request["height"].as_u64().ok_or("Height required")?;
                    let offset = request["offset"].as_u64().ok_or("Offset required")?;
                    if offset > 100000 {
                        return Err("Vote cursor bound".into());
                    }
                    let (tip, _) = self.workers.chain.load().map_err(err)?;
                    if height < tip.height
                        || height > tip.height.checked_add(1).ok_or("Height exhausted")?
                    {
                        return Err("Vote gossip requires current or last finalized height".into());
                    }
                    let votes = self.received.height(height)?;
                    let page: Vec<_> = votes
                        .iter()
                        .skip(offset as usize)
                        .take(128)
                        .map(|v| hex::encode(v.encode()))
                        .collect();
                    Ok(
                        json!({"items":page,"next":offset as usize+page.len(),"complete":offset as usize+page.len()>=votes.len()}),
                    )
                }
                "get_round_proposal" => Ok(
                    json!({"proposal":self.advertised_proposal.as_ref().map(|p|hex::encode(p.encode()))}),
                ),
                "submit_round_proposal" => {
                    self.round_proposal(RoundProposal::decode(&bytes(
                        &request["proposal"],
                        crate::round_proposal::MAX_WIRE,
                    )?)?)?;
                    Ok(json!({"status":"PROPOSAL_QUEUED"}))
                }
                "submit_candidate" => {
                    let proposal = CandidateRecord::decode(&bytes(&request["candidate"], 69632)?)?;
                    self.candidate(&proposal)?;
                    Ok(
                        json!({"status":"CANDIDATE_STORED","block_hash":hex::encode(proposal.header.block_hash())}),
                    )
                }
                "submit_vote" => {
                    let vote = Vote::decode(&bytes(&request["vote"], 2048)?).map_err(err)?;
                    let added = self.vote(&vote)?;
                    Ok(json!({"status":if added{"VOTE_STORED"}else{"DUPLICATE"}}))
                }
                "submit_block" => {
                    let block = BlockEnvelope::decode(&bytes(
                        &request["envelope"],
                        crate::peer::MAX_FRAME / 2 - 1024,
                    )?)
                    .map_err(err)?;
                    // F4: no receiver-time predicate on finalized-history ingestion.
                    let added = self.commit(&block)?;
                    Ok(
                        json!({"status":if added{"COMMITTED"}else{"ALREADY_FINALIZED"},"block_hash":hex::encode(block.block_hash())}),
                    )
                }
                "submit_transaction" => {
                    self.available()?;
                    let tx = mutiny_consensus_v8::transactions::Transfer::decode(&bytes(
                        &request["transaction"],
                        16384,
                    )?)
                    .map_err(err)?;
                    let status = self.workers.chain.admit(&tx).map_err(err)?;
                    Ok(
                        json!({"transaction_id":hex::encode(tx.id().map_err(err)?),"status":status.text()}),
                    )
                }
                "transaction_status" => {
                    let id: Hash = bytes(&request["transaction_id"], 32)?
                        .try_into()
                        .map_err(|_| "Transaction identity width")?;
                    Ok(
                        json!({"status":self.workers.chain.transaction_status(id).map_err(err)?.map(|s|s.text())}),
                    )
                }
                _ => Err("method not available to peer transport".into()),
            }
        })();
        let response = match result {
            Ok(value) => json!({"id":request["id"],"result":value}),
            Err(error) => json!({"id":request["id"],"error":error}),
        };
        Ok(crate::peer_server::PeerReply {
            payload: serde_json::to_vec(&response).map_err(err)?,
            close,
        })
    }
}
