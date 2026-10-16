//! Candidate hybrid node state owner. No sockets, key generation, signing or
//! production launch. The canonical store must be opened from trusted Genesis.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    assembler_v2::Prepared,
    block_envelope_v2::BlockEnvelope,
    canonical_store_v2::{CanonicalStore, Preparation},
    finality_v2::StoreError,
    hybrid_transaction_v2::Transaction,
    mempool_v2::{Mempool, PoolError, Status},
    submission_pool_v1::{MAX_BYTES, PoolError as SubmissionPoolError, SubmissionPool},
    submission_v1::{Reason, Status as SubmissionStatus, StatusEntry, StatusReport, Submission},
    transactions::TxError,
};
#[derive(Debug)]
pub enum RuntimeError {
    Chain(StoreError),
    Transaction(TxError),
    Pool(PoolError),
    Submission(SubmissionPoolError),
}
impl From<StoreError> for RuntimeError {
    fn from(e: StoreError) -> Self {
        Self::Chain(e)
    }
}
impl From<TxError> for RuntimeError {
    fn from(e: TxError) -> Self {
        Self::Transaction(e)
    }
}
impl From<PoolError> for RuntimeError {
    fn from(e: PoolError) -> Self {
        Self::Pool(e)
    }
}
impl From<SubmissionPoolError> for RuntimeError {
    fn from(e: SubmissionPoolError) -> Self {
        Self::Submission(e)
    }
}
fn system_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
type Result<T> = std::result::Result<T, RuntimeError>;
#[derive(Debug)]
pub enum PendingCache {
    Reconciled,
    Unavailable(StoreError),
}
#[derive(Debug)]
pub struct Installation {
    /// False means the exact canonical block was already installed. Another
    /// certificate representation for that same block does not install it twice.
    pub inserted: bool,
    /// The authenticated block just accepted, which may precede the current tip.
    pub finalized: FinalizedAnchor,
    /// Cache failure cannot undo or disguise successful canonical installation.
    pub pending: PendingCache,
}
/// Public transport copies prepared only by the verified canonical exporter.
/// The service must bind this result to the current admitted session/lease
/// before queue insertion. A page/transport ID itself conveys no authority.
pub struct PreparedHistoryExport {
    page: crate::history_protocol_v1::HistoryPage,
    objects: Vec<PreparedHistoryObject>,
}
pub struct PreparedHistoryObject {
    kind: mutiny_transport_v2::objects::ObjectKind,
    height: u64,
    object_id: Hash,
    bytes: Vec<u8>,
}
impl PreparedHistoryExport {
    pub fn page(&self) -> &crate::history_protocol_v1::HistoryPage { &self.page }
    pub fn objects(&self) -> &[PreparedHistoryObject] { &self.objects }
    pub fn into_parts(self) -> (crate::history_protocol_v1::HistoryPage, Vec<PreparedHistoryObject>) {
        (self.page, self.objects)
    }
}
impl PreparedHistoryObject {
    pub fn kind(&self) -> mutiny_transport_v2::objects::ObjectKind { self.kind }
    pub fn height(&self) -> u64 { self.height }
    pub fn object_id(&self) -> Hash { self.object_id }
    pub fn bytes(&self) -> &[u8] { &self.bytes }
    pub fn into_bytes(self) -> Vec<u8> { self.bytes }
}
pub struct WorkRequest<'a> {
    pub expected_parent: &'a FinalizedAnchor,
    pub license: Hash,
    pub worker: Hash,
    pub timestamp: u64,
    pub ticket: u64,
    pub operations: &'a [Vec<u8>],
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum CandidateJournalKind { Legacy, A2 }
pub struct HybridRuntime {
    pub(crate) chain: CanonicalStore,
    pool: Mempool,
    submissions: SubmissionPool,
    clock: std::sync::Arc<dyn Fn()->u64 + Send + Sync>,
    t0: u64,
    candidate_journals: std::cell::RefCell<Vec<(std::path::PathBuf, usize, CandidateJournalKind)>>,
    genesis: Hash,
    fingerprint: Hash,
}
pub(crate) enum ExistingRuntimeCustody{Chain(std::mem::ManuallyDrop<CanonicalStore>),
    Runtime(std::mem::ManuallyDrop<HybridRuntime>)}
pub(crate) struct ExistingRuntimeRefusal{cause:RuntimeError,custody:ExistingRuntimeCustody}
impl ExistingRuntimeRefusal{pub(crate) fn cause(&self)->&RuntimeError{&self.cause}}
impl HybridRuntime {
    /// Coherent canonical export, bounded by BOTH the peer's advertised budget
    /// and the caller's actual locally reserved queue room (controls excluded).
    /// No queue/socket/channel access occurs while the canonical snapshot lives.
    pub fn prepare_history_export(&self, request: &crate::history_protocol_v1::HistoryRequest,
        local_candidate_bytes: usize, local_candidate_entries: usize) -> Result<PreparedHistoryExport> {
        use crate::history_protocol_v1::{HistoryEntry, HistoryPage, HistoryStatus};
        use mutiny_consensus_v8::canonical_store_v2::HistoryPreparation;
        use mutiny_transport_v2::objects::{ObjectKind, object_id};
        request.validate().map_err(|_| RuntimeError::Chain(StoreError::Invalid(
            mutiny_consensus_v8::Error::Capacity)))?;
        let request_object_id = request.object_id().map_err(|_| RuntimeError::Chain(StoreError::Integrity))?;
        let max_bytes = local_candidate_bytes.min(request.max_candidate_bytes as usize);
        let max_entries = local_candidate_entries.min(request.max_candidate_entries as usize);
        let outcome = if max_bytes == 0 || max_entries == 0 { HistoryPreparation::Busy } else {
            self.chain.prepare_history_page(&request.saved_anchor, request.max_blocks,
                max_bytes, max_entries as u8)?
        };
        let mut page = HistoryPage { request_object_id, status: HistoryStatus::Busy,
            from_anchor: request.saved_anchor.clone(), offered_through_anchor: None,
            observed_tip_anchor: None, entries: Vec::new() };
        let mut objects = Vec::new();
        match outcome {
            HistoryPreparation::Busy => {},
            HistoryPreparation::CheckpointRejected => page.status = HistoryStatus::CheckpointRejected,
            HistoryPreparation::EvidenceUnavailable => page.status = HistoryStatus::EvidenceUnavailable,
            HistoryPreparation::Page(prepared) => {
                page.status = if prepared.objects().is_empty() { HistoryStatus::AtSnapshotTip }
                    else if prepared.through().height < prepared.tip().height { HistoryStatus::More }
                    else { HistoryStatus::Page };
                page.offered_through_anchor = Some(prepared.through().clone());
                page.observed_tip_anchor = Some(prepared.tip().clone());
                for prepared in prepared.into_objects() {
                    let kind = match prepared.kind() { 3 => ObjectKind::CertifiedBlock,
                        7 => ObjectKind::RecoveryEvidence, _ => return Err(StoreError::Integrity.into()) };
                    let height = prepared.height();
                    let bytes = prepared.into_bytes();
                    let object_id = object_id(kind, &bytes).map_err(|_| RuntimeError::Chain(StoreError::Integrity))?;
                    page.entries.push(HistoryEntry { kind, height, object_id,
                        encoded_length: bytes.len() as u32 });
                    objects.push(PreparedHistoryObject { kind, height, object_id, bytes });
                }
            }
        }
        page.validate_for(request).map_err(|_| RuntimeError::Chain(StoreError::Integrity))?;
        Ok(PreparedHistoryExport { page, objects })
    }
    /// SAME existing native canonical view. Cache setup is reversible local
    /// storage only, never canonical/Counter authority or provider qualification.
    /// The original canonical owner is retained before each fallible operation.
    pub(crate) fn from_existing_chain(chain:std::mem::ManuallyDrop<CanonicalStore>,pool:Mempool)
        ->std::result::Result<Self,ExistingRuntimeRefusal>{
        let initialized=(||->Result<_>{
            if chain.halted()?{return Err(StoreError::Halted.into());}
            let(parent,_,_)=chain.execution_parent(0)?;
            let path=pool.cache_path()?.with_extension("submissions.sqlite");
            let submissions=SubmissionPool::open(&path,parent.genesis,parent.fingerprint,MAX_BYTES)?;
            Ok((parent,submissions))
        })();
        let(parent,submissions)=match initialized{Ok(parts)=>parts,Err(cause)=>return Err(ExistingRuntimeRefusal{
            cause,custody:ExistingRuntimeCustody::Chain(chain)})};
        let mut runtime=std::mem::ManuallyDrop::new(Self{
            chain:std::mem::ManuallyDrop::into_inner(chain),pool,submissions,
            clock:std::sync::Arc::new(system_time),t0:parent.t0,
            candidate_journals:std::cell::RefCell::new(Vec::new()),genesis:parent.genesis,fingerprint:parent.fingerprint});
        match runtime.reconcile(){Ok(())=>Ok(std::mem::ManuallyDrop::into_inner(runtime)),
            Err(cause)=>Err(ExistingRuntimeRefusal{cause,custody:ExistingRuntimeCustody::Runtime(runtime)})}
    }
    /// Only after signer stop/join and before native group release. Reversible
    /// caches use their existing RAII semantics; SAME canonical stays retained.
    pub(crate) fn into_existing_chain(self)->std::mem::ManuallyDrop<CanonicalStore>{
        let Self{chain,..}=self;std::mem::ManuallyDrop::new(chain)
    }
    /// Constructor-pinned identity. Fragment dispatch needs no state-tree load.
    pub(crate) fn network_context(&self) -> (Hash, Hash) {
        (self.genesis, self.fingerprint)
    }
    /// Read-only candidate preview. The exact returned bytes still pass the
    /// complete WorkRequest.operations execution before signing or committing.
    #[cfg(feature = "trading-service")]
    pub fn preview_trading(
        &self,
        raw: Vec<u8>,
        policy: &mutiny_consensus_v8::trading_v1::CandidatePolicy,
    ) -> std::result::Result<
        crate::trading_service_v1::AdmissionPreview,
        crate::trading_service_v1::ServiceError,
    > {
        crate::trading_service_v1::preview(&self.chain, raw, policy)
    }
    /// A fully authorized recovery proof changes effective authority at its
    /// parent; it does not finalize a block or confirm a payment.
    pub fn accept_recovery(
        &mut self,
        raw: &[u8],
    ) -> Result<mutiny_consensus_v8::canonical_store_v2::RecoveryAcceptance> {
        Ok(self.chain.accept_recovery_encoded(raw)?)
    }
    pub fn recovery_record(&self, parent_height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.chain.recovery_record(parent_height)?)
    }
    pub fn from_pinned_chain(chain: CanonicalStore, pool: Mempool) -> Result<Self> {
        Self::from_pinned_chain_with_clock(chain, pool, system_time)
    }
    /// The host owns this clock; peer messages cannot set it. TEST-VALUE loopback
    /// tests supply a fixed clock, while ordinary callers use system_time.
    pub fn from_pinned_chain_with_clock(
        chain: CanonicalStore,
        pool: Mempool,
        clock: fn() -> u64,
    ) -> Result<Self> {
        Self::from_pinned_chain_with_time_source(chain,pool,std::sync::Arc::new(clock))
    }
    /// Owned local time source for explicit TEST application processes. This
    /// supports pending-cache epochs only and conveys no voting/UTC eligibility.
    pub fn from_pinned_chain_with_time_source(chain:CanonicalStore,pool:Mempool,
        clock:std::sync::Arc<dyn Fn()->u64 + Send + Sync>)->Result<Self>{
        if chain.halted()? {
            return Err(StoreError::Halted.into());
        }
        let (parent, _, _) = chain.execution_parent(0)?;
        let path = pool.cache_path()?.with_extension("submissions.sqlite");
        let submissions =
            SubmissionPool::open(&path, parent.genesis, parent.fingerprint, MAX_BYTES)?;
        let mut runtime = Self {
            chain,
            pool,
            submissions,
            clock,
            t0: parent.t0,
            candidate_journals: std::cell::RefCell::new(Vec::new()),
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
        };
        runtime.reconcile()?;
        Ok(runtime)
    }
    /// Always derives confirmations and queue basis from local verified history.
    /// There is no peer-supplied confirmed/status/balance mutation API.
    pub fn reconcile(&mut self) -> Result<()> {
        self.chain.reconcile_pool(&mut self.pool)?;
        let epoch = self.epoch()?;
        self.reconcile_submissions(epoch)?;
        Ok(())
    }
    fn epoch(&self) -> Result<u64> {
        mutiny_consensus_v8::pow::mining_epoch((self.clock)(), self.t0)
            .map_err(|e| RuntimeError::Chain(StoreError::Invalid(e)))
    }
    fn reconcile_submissions(&mut self, epoch: u64) -> Result<()> {
        self.chain
            .reconcile_submission_pool(&mut self.submissions, epoch)?;
        // Reversible local retention only: no pending or partial object is moved.
        // Archive errors are explicit cache failures, never a canonical rollback.
        self.submissions.archive_terminal()?;
        // Preserve the old database and its terminal/failed evidence. Copy only
        // complete pending transactions through full new admission, never strip.
        for tx in self.pool.pending()? {
            let raw = tx.encode()?;
            let (a, s, h) = self.chain.submission_context(0, &raw)?;
            match self.submissions.admit(&a, &s, &h, epoch, 0, &raw) {
                Ok(_) | Err(SubmissionPoolError::Conflict) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
    pub fn head(&self) -> Result<FinalizedAnchor> {
        if self.chain.halted()? {
            return Err(StoreError::Halted.into());
        }
        let (head, _) = self.chain.load()?;
        Ok(FinalizedAnchor {
            network: NETWORK_ID,
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            height: head.height,
            block: head.block,
        })
    }
    /// Decode only under the exact locally authenticated historical parent rule.
    /// The bounded untrusted header supplies a lookup hint, never rule authority.
    /// This remains syntax/context inspection; install performs native commit.
    pub(crate) fn decode_envelope(&self, raw: &[u8]) -> Result<BlockEnvelope> {
        let header=BlockEnvelope::untrusted_header(raw).map_err(StoreError::from)?;
        let capacity=self.chain.proposal_body_capacity(&header)?;
        Ok(BlockEnvelope::decode_with_capacity(raw,&capacity).map_err(StoreError::from)?)
    }
    pub fn install(&mut self, raw: &[u8]) -> Result<Installation> {
        let envelope = self.decode_envelope(raw)?;
        let inserted = self.chain.commit(&envelope)?;
        let finalized = envelope.certificate.decision.anchor();
        let pending = match self.reconcile() {
            Ok(()) => PendingCache::Reconciled,
            Err(RuntimeError::Chain(error)) => PendingCache::Unavailable(error),
            Err(RuntimeError::Submission(error)) => {
                PendingCache::Unavailable(StoreError::SubmissionPool(error))
            }
            Err(RuntimeError::Pool(error)) => PendingCache::Unavailable(StoreError::Pool(error)),
            Err(RuntimeError::Transaction(error)) => {
                PendingCache::Unavailable(StoreError::Pool(PoolError::Invalid(error)))
            }
        };
        Ok(Installation {
            inserted,
            finalized,
            pending,
        })
    }
    pub fn admit(&mut self, raw: &[u8]) -> Result<(Hash, Status)> {
        let tx = Transaction::decode(raw)?;
        let (id, status) = self.admit_submission(0, raw)?;
        let (anchor, state, history) = self.chain.submission_context(0, raw)?;
        // A concurrent canonical writer between reconcile and load yields a
        // stale basis at admission, never authority from an old pending cache.
        self.pool
            .admit_with_history(&tx, &anchor, &state, &history)?;
        let status = match status {
            SubmissionStatus::Pending | SubmissionStatus::Unfinalized { .. } => Status::Pending,
            SubmissionStatus::Finalized(_) => Status::Confirmed,
            SubmissionStatus::Expired { .. } => Status::Expired,
            SubmissionStatus::Conflicting {
                reason: Reason::InputSpent,
                ..
            } => Status::InputSpent,
            _ => Status::Rejected,
        };
        Ok((id, status))
    }
    pub fn admit_submission(&mut self, list: u8, raw: &[u8]) -> Result<(Hash, SubmissionStatus)> {
        Submission::decode(list, raw).map_err(SubmissionPoolError::Invalid)?;
        self.reconcile()?;
        let epoch = self.epoch()?;
        let (a, s, h) = self.chain.submission_context(list, raw)?;
        let (id, status) = self.submissions.admit(&a, &s, &h, epoch, list, raw)?;
        if let SubmissionStatus::Finalized(record) = &status {
            if !self.chain.verified_operation_records(id)?.contains(record) {
                return Err(SubmissionPoolError::Integrity.into());
            }
        }
        Ok((id, status))
    }
    /// Always confirms against local execution. A peer report cannot mutate this.
    pub fn submission_status(&mut self, id: Hash) -> Result<SubmissionStatus> {
        let rows = self.chain.verified_operation_records(id)?;
        if let Some(record) = rows.into_iter().next() {
            return Ok(SubmissionStatus::Finalized(record));
        }
        self.reconcile()?;
        let mut status = self.submissions.status(id)?;
        // The verified local lookup above found no execution. An archived cache
        // receipt cannot fill that absence, including a coherently forged receipt.
        if let SubmissionStatus::Finalized(record) = &status {
            // A concurrent canonical writer may have appended the operation
            // between the initial lookup and reconciliation. Authenticate that
            // new result freshly rather than treating a valid append as damage.
            if !self.chain.verified_operation_records(id)?.contains(record) {
                return Err(SubmissionPoolError::Integrity.into());
            }
        }
        if matches!(
            status,
            SubmissionStatus::Pending | SubmissionStatus::Unknown
        ) {
            if let Some(found) = self.unfinalized(&[id])?.remove(&id) {
                status = found;
            }
        }
        Ok(status)
    }
    pub fn status_reports(&mut self, query: &[u8]) -> Result<Vec<Vec<u8>>> {
        let ids = mutiny_consensus_v8::submission_v1::decode_query(query)
            .map_err(SubmissionPoolError::Invalid)?;
        self.reconcile()?;
        let tip = self.head()?;
        let mut out = Vec::new();
        let mut records = self.chain.verified_operation_records_many(&ids)?;
        let mut local = self.submissions.statuses(&ids)?;
        let mut proposals = self.unfinalized(&ids)?;
        for chunk in ids.chunks(32) {
            let mut entries = Vec::new();
            for id in chunk {
                let rows = records.remove(id).unwrap_or_default();
                let cached = local.remove(id).unwrap_or(SubmissionStatus::Unknown);
                if matches!(cached, SubmissionStatus::Finalized(_))
                    && !rows
                        .iter()
                        .any(|r| cached == SubmissionStatus::Finalized(r.clone()))
                {
                    return Err(SubmissionPoolError::Integrity.into());
                }
                let mut status = rows
                    .into_iter()
                    .next()
                    .map(SubmissionStatus::Finalized)
                    .unwrap_or(cached);
                if matches!(
                    status,
                    SubmissionStatus::Pending | SubmissionStatus::Unknown
                ) {
                    if let Some(found) = proposals.remove(id) {
                        status = found;
                    }
                }
                entries.push(StatusEntry { id: *id, status });
            }
            out.push(
                StatusReport {
                    tip_height: tip.height,
                    tip_block: tip.block,
                    entries,
                }
                .encode()
                .map_err(SubmissionPoolError::Invalid)?,
            );
        }
        Ok(out)
    }
    /// Only already verified complete pending bytes are eligible for bounded relay.
    pub fn relay_pending(&mut self) -> Result<Vec<Submission>> {
        self.reconcile()?;
        let tip = self.head()?;
        let (_, state) = self.chain.load()?;
        Ok(self.submissions.pending_at(&tip, &state)?)
    }
    pub fn exact_submission_bytes(&self, id: Hash) -> Result<Option<(u8, Vec<u8>)>> {
        Ok(self.submissions.exact_bytes(id)?)
    }
    /// The owning service reattaches its durable journal at startup. Preservation
    /// and restoration also register it; peer messages cannot choose a disk path.
    pub fn attach_candidate_journal(
        &self,
        journal: &crate::candidate_journal_v2::Journal,
    ) -> Result<()> {
        journal
            .register_runtime(self)
            .map_err(|e| RuntimeError::Chain(StoreError::Assembly(e)))
    }
    pub fn attach_a2_candidate_journal(&self, journal: &crate::candidate_journal_v3::Journal) -> Result<()> {
        journal.register_runtime(self).map_err(|e| RuntimeError::Chain(StoreError::Assembly(e)))
    }
    pub(crate) fn register_candidate_journal(
        &self,
        path: std::path::PathBuf,
        budget: usize,
    ) -> std::result::Result<(), String> {
        self.register_typed_candidate_journal(path, budget, CandidateJournalKind::Legacy)
    }
    pub(crate) fn register_a2_candidate_journal(
        &self, path: std::path::PathBuf, budget: usize,
    ) -> std::result::Result<(), String> {
        self.register_typed_candidate_journal(path, budget, CandidateJournalKind::A2)
    }
    fn register_typed_candidate_journal(
        &self, path: std::path::PathBuf, budget: usize, kind: CandidateJournalKind,
    ) -> std::result::Result<(), String> {
        let mut journals = self.candidate_journals.borrow_mut();
        if let Some((_, old_budget, old_kind)) = journals.iter().find(|(p, _, _)| p == &path) {
            if *old_budget != budget || *old_kind != kind {
                return Err("Candidate status journal binding changed".into());
            }
        } else {
            if journals.len() >= 4 { return Err("Candidate status journal capacity".into()); }
            journals.push((path, budget, kind));
        }
        Ok(())
    }
    fn unfinalized(
        &self,
        ids: &[Hash],
    ) -> Result<std::collections::BTreeMap<Hash, SubmissionStatus>> {
        let mut out = std::collections::BTreeMap::new();
        let journals = self.candidate_journals.borrow().clone();
        for (path, budget, kind) in journals {
            // Each mode reopens its exact local schema; neither selects consensus rules.
            let legacy = if kind == CandidateJournalKind::Legacy {
                Some(crate::candidate_journal_v2::Journal::open(&path, self.genesis, self.fingerprint, budget, false)
                    .map_err(|e| RuntimeError::Chain(StoreError::Assembly(e)))?)
            } else { None };
            let successor = if kind == CandidateJournalKind::A2 {
                Some(crate::candidate_journal_v3::Journal::open(self, &path, budget, false)
                    .map_err(|e| RuntimeError::Chain(StoreError::Assembly(e)))?)
            } else { None };
            let mut cursor = None;
            loop {
                let next = if let Some(journal) = &legacy {
                    journal.next_current(self, cursor)
                } else {
                    successor.as_ref().expect("Selected journal exists").next_current(self, cursor)
                        .map(|r| r.map(|r| crate::candidate_journal_v2::Record {
                            header: r.header, authority: r.authority, body: r.body,
                        }))
                }.map_err(|e| RuntimeError::Chain(StoreError::Assembly(e)))?;
                let Some(record) = next else { break; };
                let block = record.header.block_hash(); cursor = Some(block);
                let capacity = if kind == CandidateJournalKind::A2 {
                    Some(self.chain.proposal_body_capacity(&record.header)?)
                } else { None };
                for (list, items) in [(0, &record.body.transactions), (1, &record.body.operations)] {
                    for raw in items {
                        let identifier = if list == 1 {
                            capacity.as_ref().and_then(|c| c.operation_id(raw).ok())
                                .map(Ok).unwrap_or_else(|| mutiny_consensus_v8::operation_index_v2::operation_id(list, raw))
                        } else { mutiny_consensus_v8::operation_index_v2::operation_id(list, raw) };
                        let Ok((_, id)) = identifier else { continue; };
                        if ids.contains(&id) {
                            out.entry(id).or_insert(SubmissionStatus::Unfinalized {
                                height: record.body.height, block,
                            });
                        }
                    }
                }
            }
        }
        Ok(out)
    }
    /// Complete native preview for the separately bounded A2 queue. The host
    /// supplies work context; peer bytes never select capacity or authority.
    /// This read-only preview neither reconciles ordinary pools nor signs work.
    pub(crate) fn preview_a2_operation(
        &self,
        request: WorkRequest<'_>,
    ) -> Result<Prepared> {
        let capacity = self.chain.body_capacity(request.expected_parent)?;
        if !capacity.allows_a2() || request.operations.len() != 1 {
            return Err(StoreError::Assembly("A2 queue requires selected successor and one item".into()).into());
        }
        capacity.supported_a2_operation(&request.operations[0])
            .map_err(|_| StoreError::Assembly("Unsupported complete A2 carrier".into()))?;
        let prepared = self.chain.prepare_pending(Preparation {
            expected_parent: request.expected_parent,
            pool: &self.submissions,
            license: request.license,
            worker: request.worker,
            timestamp: request.timestamp,
            ticket: request.ticket,
            operations: request.operations,
        })?;
        if prepared.body.operations.as_slice() != request.operations {
            return Err(StoreError::Assembly("A2 preview did not preserve exact item".into()).into());
        }
        Ok(prepared)
    }
    pub fn prepare(&mut self, request: WorkRequest<'_>) -> Result<Prepared> {
        // No cached success flag: every attempt must reconcile successfully.
        self.chain.reconcile_pool(&mut self.pool)?;
        let epoch = mutiny_consensus_v8::pow::mining_epoch(request.timestamp, self.t0)
            .map_err(|e| RuntimeError::Chain(StoreError::Invalid(e)))?;
        self.reconcile_submissions(epoch)?;
        Ok(self.chain.prepare_pending(Preparation {
            expected_parent: request.expected_parent,
            pool: &self.submissions,
            license: request.license,
            worker: request.worker,
            timestamp: request.timestamp,
            ticket: request.ticket,
            operations: request.operations,
        })?)
    }
    pub fn current_authority(
        &self,
        expected_parent: &FinalizedAnchor,
    ) -> Result<mutiny_consensus_v8::votes_v2::HeightAuthority> {
        Ok(self.chain.current_authority(expected_parent)?)
    }
    /// Derive work inputs from this runtime's own exact current canonical parent.
    /// This delegates validation; it exposes neither the store nor signing authority.
    pub fn current_work_context(
        &self, expected_parent: &FinalizedAnchor, license: Hash, worker: Hash, timestamp: u64,
    ) -> Result<(mutiny_consensus_v8::pow::WorkContext, Vec<u8>)> {
        Ok(self.chain.current_work_context(expected_parent, license, worker, timestamp)?)
    }
    /// Obtain the authenticated capacity of this runtime's exact canonical parent.
    /// Envelope encoding still requires subsequent native installation validation.
    pub fn body_capacity(
        &self, expected_parent: &FinalizedAnchor,
    ) -> Result<mutiny_consensus_v8::body_capacity_v3::BodyCapacity> {
        Ok(self.chain.body_capacity(expected_parent)?)
    }
    pub fn confirmed_height(&self, id: Hash) -> Result<Option<u64>> {
        Ok(self.chain.confirmed_height(id)?)
    }
    pub fn proof(&self, request: &[u8]) -> Result<Vec<u8>> {
        Ok(crate::state_proof_service::respond_hybrid(
            &self.chain,
            request,
        )?)
    }
}
#[cfg(test)]
#[path = "history_export_runtime_tests_v1.rs"]
mod history_export_runtime_tests_v1;
#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_consensus_v8::{
        execution::State,
        state_proof::{utxo_key, verify_utxo},
        transactions::OutPoint,
    };
    #[test]
    fn archived_structural_receipt_cannot_confirm_own_unexecuted_chain() {
        use mutiny_consensus_v8::{
            operation_index_v2,
            submission_v1::{StatusEntry, StatusReport},
        };
        use sha2::{Digest, Sha256};
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        assert_eq!(fixture["synthetic_only"], true);
        assert_eq!(fixture["production_authorized"], false);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&fixture["root"]).try_into().unwrap();
        let rows: Vec<_> = fixture["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let state = State::from_records(&rows, root).unwrap();
        let genesis = FinalizedAnchor::decode(&raw(&fixture["genesis"])).unwrap();
        let envelope = BlockEnvelope::decode(&raw(&fixture["envelope"])).unwrap();
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let base = std::env::temp_dir().join(format!(
            "build8-archive-false-finality-{}",
            hex::encode(nonce)
        ));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
        let cache_path = base.join("pool.sqlite");
        let mut runtime = HybridRuntime::from_pinned_chain(
            CanonicalStore::open_trusted_genesis(
                &base.join("chain.sqlite"),
                &genesis,
                &state,
                root,
                1000,
                [255; 32],
            )
            .unwrap(),
            Mempool::open(
                &cache_path,
                genesis.genesis,
                genesis.fingerprint,
                64 * 1024 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        let bytes = &envelope.body.transactions[0];
        let (id, status) = runtime.admit_submission(0, bytes).unwrap();
        assert_eq!(status, SubmissionStatus::Pending);
        let submission = Submission::decode(0, bytes).unwrap();
        let main =
            rusqlite::Connection::open(cache_path.with_extension("submissions.sqlite")).unwrap();
        let terminal = StatusReport {
            tip_height: 0,
            tip_block: genesis.block,
            entries: vec![StatusEntry {
                id,
                status: SubmissionStatus::Expired {
                    last: submission.window().1,
                },
            }],
        }
        .encode()
        .unwrap();
        main.execute("DELETE FROM resources WHERE owner=?1", [id.as_slice()])
            .unwrap();
        main.execute(
            "UPDATE entries SET status=?1 WHERE id=?2",
            rusqlite::params![terminal, id.as_slice()],
        )
        .unwrap();
        assert_eq!(runtime.submissions.archive_terminal().unwrap(), 1);
        // A valid public peer block/receipt supplies membership and signed bytes,
        // but it has NEVER executed in this replica. Rewrite the local checksum
        // too: the checksum cannot stand in for independent canonical execution.
        let record = operation_index_v2::records(
            &envelope.body,
            envelope.certificate.decision.anchor().block,
            &std::collections::BTreeMap::new(),
        )
        .unwrap()
        .into_iter()
        .find(|r| r.op_id == id)
        .unwrap();
        let report = StatusReport {
            tip_height: 1,
            tip_block: record.block,
            entries: vec![StatusEntry {
                id,
                status: SubmissionStatus::Finalized(record.clone()),
            }],
        }
        .encode()
        .unwrap();
        let archive = rusqlite::Connection::open(
            runtime
                .submissions
                .archive_path()
                .join("shard-00000000000000000000.sqlite"),
        )
        .unwrap();
        archive
            .execute(
                "UPDATE entries SET status=?1 WHERE id=?2",
                rusqlite::params![report, id.as_slice()],
            )
            .unwrap();
        let mut digest = Sha256::new();
        digest.update(b"MUTINY-BUILD8-LOCAL-ARCHIVE-SEAL-V1");
        digest.update(genesis.genesis);
        digest.update(genesis.fingerprint);
        let mut q = archive
            .prepare(
                "SELECT id,class,kind,raw,first,last,wire,sig_ok,status FROM entries ORDER BY id",
            )
            .unwrap();
        let mut rows = q.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for c in 0..9 {
                match row.get_ref(c).unwrap() {
                    rusqlite::types::ValueRef::Integer(n) => {
                        digest.update([0]);
                        digest.update(n.to_be_bytes());
                    }
                    rusqlite::types::ValueRef::Blob(b) => {
                        digest.update([1]);
                        digest.update((b.len() as u64).to_be_bytes());
                        digest.update(b);
                    }
                    _ => panic!("fixture column"),
                }
            }
        }
        let seal: Hash = digest.finalize().into();
        main.execute("UPDATE archive_catalog SET seal=?1", [seal.as_slice()])
            .unwrap();
        // The running process remembers exact verified row bytes independently
        // of rewritten disk checksums. Reopen deliberately rebuilds from valid
        // signatures; it still cannot make this foreign receipt canonical.
        assert!(matches!(
            runtime.submissions.status(id),
            Err(SubmissionPoolError::Integrity)
        ));
        drop(rows);
        drop(q);
        drop(archive);
        drop(main);
        drop(runtime);
        let mut runtime = HybridRuntime::from_pinned_chain(
            CanonicalStore::open_trusted_genesis(
                &base.join("chain.sqlite"),
                &genesis,
                &state,
                root,
                1000,
                [255; 32],
            )
            .unwrap(),
            Mempool::open(
                &cache_path,
                genesis.genesis,
                genesis.fingerprint,
                64 * 1024 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            runtime.submissions.status(id).unwrap(),
            SubmissionStatus::Finalized(record)
        );
        assert!(
            runtime
                .chain
                .verified_operation_records(id)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            runtime.submission_status(id),
            Err(RuntimeError::Submission(SubmissionPoolError::Integrity))
        ));
        let query = mutiny_consensus_v8::submission_v1::encode_query(&[id]).unwrap();
        assert!(matches!(
            runtime.status_reports(&query),
            Err(RuntimeError::Submission(SubmissionPoolError::Integrity))
        ));
        assert!(matches!(
            runtime.admit_submission(0, bytes),
            Err(RuntimeError::Submission(SubmissionPoolError::Integrity))
        ));
        assert_eq!(runtime.head().unwrap(), genesis);
        drop(runtime);
        // Retain this coherently forged TEST-VALUE archive as negative evidence.
    }
    #[test]
    fn finalized_install_survives_cache_failure_and_restart_without_false_confirmation() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic_only"], true);
        assert_eq!(f["production_authorized"], false);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let rows: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let state = State::from_records(&rows, root).unwrap();
        let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
        let envelope = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
        let id: Hash = raw(&f["transaction_id"]).try_into().unwrap();
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let base = std::env::temp_dir().join(format!("build8-runtime-v2-{}", hex::encode(nonce)));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
        let chain_path = base.join("chain.sqlite");
        let pool_path = base.join("pool.sqlite");
        let open = || {
            HybridRuntime::from_pinned_chain(
                CanonicalStore::open_trusted_genesis(
                    &chain_path,
                    &genesis,
                    &state,
                    root,
                    1000,
                    [255; 32],
                )
                .unwrap(),
                Mempool::open(
                    &pool_path,
                    genesis.genesis,
                    genesis.fingerprint,
                    64 * 1024 * 1024,
                )
                .unwrap(),
            )
            .unwrap()
        };
        let mut runtime = open();
        let authority = runtime.current_authority(&genesis).unwrap();
        assert_eq!(authority.parent, genesis);
        let (liveness, current_root) = runtime.chain.current_liveness(&genesis).unwrap();
        assert_eq!(liveness.parent, genesis);
        assert_eq!(current_root, root);
        let candidate = &envelope.header.candidate;
        let context = || {
            runtime.chain.current_work_context(
                &genesis,
                candidate.license,
                candidate.worker,
                candidate.timestamp,
            )
        };
        let (work, descriptor) = context().unwrap();
        assert_eq!(work.last_accepted_ticket, 0);
        assert_eq!(
            work.assignment_sequence,
            envelope.authority.work.assignment_sequence
        );
        assert_eq!(descriptor, envelope.authority.node_descriptor);
        assert!(
            runtime
                .chain
                .current_work_context(&genesis, [0; 32], candidate.worker, candidate.timestamp)
                .is_err()
        );
        assert!(
            runtime
                .chain
                .current_work_context(&genesis, candidate.license, [0; 32], candidate.timestamp)
                .is_err()
        );
        assert!(
            runtime
                .chain
                .current_work_context(&genesis, candidate.license, candidate.worker, 999)
                .is_err()
        );

        let round = mutiny_consensus_v8::votes_v2::AuthenticatedRound::new(authority).unwrap();
        assert_eq!(round.height().unwrap(), 1);
        for field in 0..4 {
            let mut wrong = genesis.clone();
            match field {
                0 => wrong.genesis[0] ^= 1,
                1 => wrong.fingerprint[0] ^= 1,
                2 => wrong.block[0] ^= 1,
                _ => wrong.height = 1,
            }
            assert!(runtime.current_authority(&wrong).is_err());
        }
        assert_eq!(runtime.confirmed_height(id).unwrap(), None);
        assert_eq!(
            runtime.submission_status(id).unwrap(),
            SubmissionStatus::Unknown
        );
        assert!(runtime.install(b"untrusted peer status confirmed").is_err());
        assert!(runtime.admit(b"invalid transaction").is_err());
        assert_eq!(runtime.head().unwrap(), genesis);
        let tx = &envelope.body.transactions[0];
        let (admitted, status) = runtime.admit(tx).unwrap();
        assert_eq!(admitted, id);
        assert_eq!(status, Status::Pending);
        assert_eq!(
            runtime.submission_status(id).unwrap(),
            SubmissionStatus::Pending
        );
        assert_eq!(runtime.confirmed_height(id).unwrap(), None);
        let request = || WorkRequest {
            expected_parent: &genesis,
            license: envelope.header.candidate.license,
            worker: envelope.header.candidate.worker,
            timestamp: envelope.header.candidate.timestamp,
            ticket: envelope.authority.work.ticket_sequence,
            operations: &envelope.body.operations,
        };
        runtime.prepare(request()).unwrap();
        let mut invalid = envelope.clone();
        invalid.header.candidate.state_root[0] ^= 1;
        assert!(runtime.install(&invalid.encode().unwrap()).is_err());
        assert_eq!(runtime.head().unwrap(), genesis);
        assert_eq!(runtime.confirmed_height(id).unwrap(), None);
        runtime.prepare(request()).unwrap();
        let corrupt = rusqlite::Connection::open(&pool_path).unwrap();
        corrupt
            .execute_batch("CREATE TABLE unexpected(id INTEGER)")
            .unwrap();
        let installed = runtime.install(&envelope.encode().unwrap()).unwrap();
        assert!(installed.inserted);
        assert!(matches!(installed.pending, PendingCache::Unavailable(_)));
        assert_eq!(runtime.head().unwrap(), installed.finalized);
        assert!(runtime.current_authority(&genesis).is_err());
        assert!(runtime.chain.current_liveness(&genesis).is_err());
        assert!(
            runtime
                .chain
                .current_work_context(
                    &genesis,
                    candidate.license,
                    candidate.worker,
                    candidate.timestamp
                )
                .is_err()
        );

        let authority = runtime.current_authority(&installed.finalized).unwrap();
        assert_eq!(authority.parent, installed.finalized);
        assert_eq!(runtime.confirmed_height(id).unwrap(), Some(1));
        assert!(
            matches!(runtime.submission_status(id).unwrap(),SubmissionStatus::Finalized(record) if record.op_id==id && record.height==1)
        );
        assert!(runtime.prepare(request()).is_err());
        assert!(runtime.admit(tx).is_err());
        // Public state proofs depend only on canonical state, not queue health.
        let point = OutPoint {
            transaction: id,
            index: 0,
        };
        let req = crate::state_proof_service::Request {
            anchor: installed.finalized.clone(),
            key: utxo_key(&point),
            profile: crate::state_proof_service::ProofProfile::Utxo,
        };
        let proof = runtime.proof(&req.encode()).unwrap();
        assert!(
            verify_utxo(
                &proof,
                &installed.finalized,
                envelope.header.candidate.state_root,
                &point,
                [94; 32]
            )
            .unwrap()
            .is_some()
        );
        // No code repairs or deletes the unexpected schema. The test undoes its
        // own injection, then restart must replay/reconcile the durable block.
        corrupt.execute_batch("DROP TABLE unexpected").unwrap();
        drop(corrupt);
        drop(runtime);
        let mut runtime = open();
        assert!(runtime.current_authority(&genesis).is_err());
        let round = mutiny_consensus_v8::votes_v2::AuthenticatedRound::new(
            runtime.current_authority(&installed.finalized).unwrap(),
        )
        .unwrap();
        assert_eq!(round.height().unwrap(), 2);
        assert_eq!(runtime.head().unwrap(), installed.finalized);
        assert_eq!(runtime.pool.status(id).unwrap(), Some(Status::Confirmed));
        let duplicate = runtime.install(&envelope.encode().unwrap()).unwrap();
        assert!(!duplicate.inserted);
        assert!(matches!(duplicate.pending, PendingCache::Reconciled));
        assert!(
            runtime.prepare(request()).is_err(),
            "old parent accepted after restart"
        );
        drop(runtime);
        std::fs::remove_dir_all(base).unwrap();
    }
}
