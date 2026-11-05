//! Candidate-only adapter to the existing authenticated hybrid canonical store.
//! No separate ledger, arbitrary root admission, key custody, broadcast or commit.
//! Compiled only with the SERVICE-ONLY `trading-service` feature, which forwards nothing to
//! consensus: consensus trading validation is always on and never depends on this feature.
//! Host integration supplies the final activation gate.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    canonical_store_v2::CanonicalStore,
    evidence_history_v2::History,
    trading_v1::{
        CandidatePolicy, NativeOperation, NativeReceipt, prepare_batch_with_history, reconcile,
    },
};

#[derive(Debug)]
pub enum ServiceError {
    CanonicalStore,
    Context,
    StaleParent,
    Trading(mutiny_consensus_v8::trading_v1::NativeError),
}
impl From<mutiny_consensus_v8::trading_v1::NativeError> for ServiceError {
    fn from(e: mutiny_consensus_v8::trading_v1::NativeError) -> Self {
        Self::Trading(e)
    }
}
#[derive(Debug)]
pub struct CandidateSubmission {
    parent: FinalizedAnchor,
    parent_root: Hash,
    operation: Hash,
    raw: Vec<u8>,
    proposed_root: Hash,
    fee_atoms: u64,
}
impl CandidateSubmission {
    pub fn parent(&self) -> &FinalizedAnchor {
        &self.parent
    }
    pub fn parent_root(&self) -> Hash {
        self.parent_root
    }
    pub fn operation(&self) -> Hash {
        self.operation
    }
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn proposed_root(&self) -> Hash {
        self.proposed_root
    }
    pub fn fee_atoms(&self) -> u64 {
        self.fee_atoms
    }
}
#[derive(Debug)]
pub enum AdmissionPreview {
    AlreadyApplied(NativeReceipt),
    Pending(CandidateSubmission),
}

/// The authenticated History a trading operation needs for inclusion above `head`: the canonical
/// block hash of the finalized height its envelope references (trading body version 2; Lane P
/// design 1.a.3), read from this store's certified evidence, never from the operation or a peer.
/// The certified decision of the block above the reference names its parent, which is the
/// canonical block at the reference (Genesis included). A reference to the head itself needs no
/// anchor (the parent shortcut).
fn reference_history(
    store: &CanonicalStore,
    head: &FinalizedAnchor,
    wire: &NativeOperation,
) -> Result<History, ServiceError> {
    let mut history = History::default();
    let reference = wire.operation.meta.envelope.reference_height;
    if reference < head.height {
        let child = store
            .canonical_block(reference + 1)
            .map_err(|_| ServiceError::CanonicalStore)?
            .ok_or(ServiceError::CanonicalStore)?;
        history
            .insert_anchor(reference, child.certificate.decision.parent)
            .map_err(|_| ServiceError::CanonicalStore)?;
    }
    Ok(history)
}

/// Uses the hybrid store's verified history and exact persisted state. A preview
/// is not finalized, signed, enqueued or committed. The host must re-execute in
/// ordinary candidate/block validation before installing any value effect.
pub fn preview(
    store: &CanonicalStore,
    raw: Vec<u8>,
    policy: &CandidatePolicy,
) -> Result<AdmissionPreview, ServiceError> {
    if store.halted().map_err(|_| ServiceError::CanonicalStore)? {
        return Err(ServiceError::CanonicalStore);
    }
    let (head, _) = store.load().map_err(|_| ServiceError::CanonicalStore)?;
    let (parent, state, root) = store
        .execution_parent(head.height)
        .map_err(|_| ServiceError::CanonicalStore)?;
    if parent.block != head.block
        || root != head.root
        || state.root().map_err(|_| ServiceError::CanonicalStore)? != root
    {
        return Err(ServiceError::StaleParent);
    }
    let anchor = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        height: parent.height,
        block: parent.block,
    };
    let wire = NativeOperation::decode(&raw)?;
    if wire.operation.meta.context.network != anchor.network
        || wire.operation.meta.context.genesis != anchor.genesis
        || wire.operation.meta.context.fingerprint != anchor.fingerprint
    {
        return Err(ServiceError::Context);
    }
    if let Some(receipt) = reconcile(&state, &raw)? {
        if receipt.height > anchor.height {
            return Err(ServiceError::Context);
        }
        return Ok(AdmissionPreview::AlreadyApplied(receipt));
    }
    let history = reference_history(store, &anchor, &wire)?;
    let prepared = prepare_batch_with_history(
        &state,
        &anchor,
        root,
        &history,
        std::slice::from_ref(&raw),
        policy,
    )?;
    Ok(AdmissionPreview::Pending(CandidateSubmission {
        parent: anchor,
        parent_root: root,
        operation: wire
            .operation
            .id()
            .map_err(|e| ServiceError::Trading(e.into()))?,
        raw,
        proposed_root: prepared.root(),
        fee_atoms: prepared.fee_atoms(),
    }))
}
/// Advisory queue freshness check, never a replacement for atomic block
/// execution. Concurrent commits after this check still require revalidation.
pub fn recheck_parent(
    store: &CanonicalStore,
    submission: &CandidateSubmission,
) -> Result<(), ServiceError> {
    let (head, _) = store.load().map_err(|_| ServiceError::CanonicalStore)?;
    if head.height != submission.parent.height
        || head.block != submission.parent.block
        || head.root != submission.parent_root
    {
        return Err(ServiceError::StaleParent);
    }
    Ok(())
}

/// Current canonical destination resolution. No key custody, signing, listing
/// fee or canonical market entry. Caller durably retains exact unsigned intent
/// before requesting the distinct MUT Treasury wallet's authorization.
pub fn prepare_current_treasury_offer(
    store: &CanonicalStore,
    request: mutiny_consensus_v8::trading_v1::TreasuryOfferRequest,
    policy: &CandidatePolicy,
) -> Result<mutiny_consensus_v8::trading_v1::PreparedTreasuryOffer, ServiceError> {
    if store.halted().map_err(|_| ServiceError::CanonicalStore)? {
        return Err(ServiceError::CanonicalStore);
    }
    let (head, _) = store.load().map_err(|_| ServiceError::CanonicalStore)?;
    let (parent, state, root) = store
        .execution_parent(head.height)
        .map_err(|_| ServiceError::CanonicalStore)?;
    if head.block != parent.block || head.root != root {
        return Err(ServiceError::StaleParent);
    }
    let anchor = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        height: parent.height,
        block: parent.block,
    };
    Ok(mutiny_consensus_v8::trading_v1::prepare_treasury_offer(
        &state, &anchor, root, request, policy,
    )?)
}
/// The expected historical root is read from CanonicalStore, never accepted
/// from the serialized frozen offer. This authenticates historical state, not
/// an off-chain offer creation/publication timestamp.
pub fn verify_archived_treasury_offer(
    store: &CanonicalStore,
    frozen: mutiny_consensus_v8::trading_v1::FrozenTreasuryOffer,
    policy: &CandidatePolicy,
) -> Result<mutiny_consensus_v8::trading_v1::VerifiedFrozenTreasuryOffer, ServiceError> {
    if store.halted().map_err(|_| ServiceError::CanonicalStore)? {
        return Err(ServiceError::CanonicalStore);
    }
    let (parent, state, root) = store
        .execution_parent(frozen.creation_anchor().height)
        .map_err(|_| ServiceError::CanonicalStore)?;
    let anchor = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        height: parent.height,
        block: parent.block,
    };
    Ok(
        mutiny_consensus_v8::trading_v1::verify_frozen_treasury_offer_at_creation(
            frozen, &state, &anchor, root, policy,
        )?,
    )
}

#[cfg(feature = "trading-local-storage-candidate")]
#[path = "trading_storage_v1.rs"]
pub mod local_storage_candidate;

/// Candidate local external-wallet completion coordinator. This module holds no
/// keys and performs no network call, payment, broadcast or canonical commit.
/// SQLite is durability evidence only, not qualified encrypted wallet history.
pub mod completion_candidate {
    use super::*;
    use mutiny_consensus_v8::{
        execution::State,
        op_envelope_v1::{Envelope, EnvelopeError},
        trading_v1 as tr,
        transactions::OutPoint,
    };
    use mutiny_crypto_v2::{Domain, HybridSignature, PublicKey};
    use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
    use std::{collections::BTreeSet, path::Path};

    #[derive(Debug, PartialEq, Eq)]
    pub enum Error {
        Gate,
        Unit,
        Store,
        Stale,
        Context,
        Missing,
        Time,
        Terms,
        Fee,
        Authority,
        Ambiguous,
        Duplicate,
        Bounds,
        Corrupt,
        FiatRecoveryUnspecified,
    }
    pub type Result<T> = std::result::Result<T, Error>;
    fn native<T>(r: tr::NativeResult<T>) -> Result<T> {
        r.map_err(|e| match e {
            tr::NativeError::Gate => Error::Gate,
            tr::NativeError::UnitUnresolved => Error::Unit,
            _ => Error::Terms,
        })
    }
    fn db<T>(r: rusqlite::Result<T>) -> Result<T> {
        r.map_err(|_| Error::Store)
    }
    fn current(store: &CanonicalStore) -> Result<(FinalizedAnchor, State, Hash)> {
        if store.halted().map_err(|_| Error::Store)? {
            return Err(Error::Store);
        }
        let (head, _) = store.load().map_err(|_| Error::Store)?;
        let (p, state, root) = store
            .execution_parent(head.height)
            .map_err(|_| Error::Store)?;
        if p.block != head.block
            || root != head.root
            || state.root().map_err(|_| Error::Store)? != root
        {
            return Err(Error::Stale);
        }
        Ok((
            FinalizedAnchor {
                network: NETWORK_ID,
                genesis: p.genesis,
                fingerprint: p.fingerprint,
                height: p.height,
                block: p.block,
            },
            state,
            root,
        ))
    }
    #[derive(Clone, Debug)]
    pub enum PathChoice {
        Claim([u8; 32]),
        Refund,
        FiatCooperative,
    }
    #[derive(Clone, Debug)]
    pub struct FeeTerms {
        pub inputs: Vec<OutPoint>,
        pub fee: tr::Strikes,
        pub change: tr::Strikes,
        /// The last height of the signed inclusion window (the envelope's `last_height`); the
        /// window opens at the next height and references the head the operation is built on.
        pub expiry: u64,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Purpose {
        Claim,
        Refund,
        BuyerPaymentSent,
        SellerReceiptApproval,
    }
    #[derive(Debug)]
    pub struct WalletRequest {
        pub operation: Hash,
        pub slot: u8,
        pub purpose: Purpose,
        pub descriptor: Vec<u8>,
        pub payload: Vec<u8>,
    }
    /// Read-only correlation data for an already dispatched wallet request.
    /// Distinct from WalletRequest: never authorizes another signing attempt.
    #[derive(Debug)]
    pub struct ApprovalQuery {
        pub operation: Hash,
        pub slot: u8,
        pub purpose: Purpose,
        pub descriptor: Vec<u8>,
        pub payload: Vec<u8>,
    }
    #[derive(Debug, PartialEq, Eq)]
    pub enum Reconciliation {
        Pending,
        /// The exact operation is not applied, but its original canonical lock
        /// is absent. Query the opposing path; never reset or infer a payout.
        LockedOutputUnavailable {
            output: Hash,
        },
        Applied(tr::NativeReceipt),
    }
    fn authority(w: &tr::NativeOperation, slot: u8) -> Result<(Hash, Purpose)> {
        match (&w.operation.action, slot) {
            (tr::Action::Claim { recipient, .. }, 0) => Ok((*recipient, Purpose::Claim)),
            (tr::Action::Refund { owner, .. }, 0) => Ok((*owner, Purpose::Refund)),
            (tr::Action::FiatRelease { buyer, .. }, 0) => Ok((*buyer, Purpose::BuyerPaymentSent)),
            (tr::Action::FiatRelease { seller, .. }, 1) => {
                Ok((*seller, Purpose::SellerReceiptApproval))
            }
            _ => Err(Error::Authority),
        }
    }
    fn lock_id(w: &tr::NativeOperation) -> Result<Hash> {
        match w.operation.action {
            tr::Action::Claim { output, .. }
            | tr::Action::Refund { output, .. }
            | tr::Action::FiatRelease { output, .. } => Ok(output),
            _ => Err(Error::Terms),
        }
    }
    fn slots(w: &tr::NativeOperation) -> usize {
        if matches!(w.operation.action, tr::Action::FiatRelease { .. }) {
            2
        } else {
            1
        }
    }
    fn verify_approval(state: &State, w: &tr::NativeOperation, a: &tr::Approval) -> Result<()> {
        let (owner, _) = authority(w, a.slot)?;
        state
            .wallets
            .authorize(owner, &a.descriptor)
            .map_err(|_| Error::Authority)?;
        let (key, _) = PublicKey::decode_descriptor(&a.descriptor).map_err(|_| Error::Authority)?;
        key.verify(
            Domain::Transaction,
            &w.operation
                .signing_payload(a.slot, &a.descriptor)
                .map_err(|_| Error::Terms)?,
            &a.signature,
        )
        .map_err(|_| Error::Authority)
    }
    /// Validate unsigned completion against *current* authenticated lock and real
    /// fee inputs. Final signed size/fee and state effects use existing preview.
    fn validate(
        store: &CanonicalStore,
        w: &tr::NativeOperation,
        policy: &CandidatePolicy,
    ) -> Result<()> {
        native(policy.check())?;
        let (head, state, _) = current(store)?;
        let m = &w.operation.meta;
        if m.context.network != head.network
            || m.context.genesis != head.genesis
            || m.context.fingerprint != head.fingerprint
        {
            return Err(Error::Context);
        }
        let height = head.height.checked_add(1).ok_or(Error::Time)?;
        // The signed window and the finalized reference at the next height, with the store's
        // canonical anchor for an older reference: the check block execution makes.
        let history = super::reference_history(store, &head, w).map_err(|_| Error::Store)?;
        match m.envelope.check_inclusion(&head, &history) {
            Ok(()) => {}
            Err(EnvelopeError::ReferenceNotCanonical) => return Err(Error::Context),
            Err(_) => return Err(Error::Time),
        }
        let l = native(tr::locked(&state, lock_id(w)?))?;
        if l.context != m.context
            || l.trade != m.trade
            || l.contract != m.contract
            || l.generation != m.generation
            || l.created_height >= height
        {
            return Err(Error::Context);
        }
        let (payer, change) = match (&w.operation.action, &l.kind) {
            (
                tr::Action::Claim {
                    recipient,
                    amount,
                    preimage,
                    change,
                    ..
                },
                tr::NativeLockKind::Hash {
                    condition,
                    refund_height,
                },
            ) => {
                if *recipient != l.recipient
                    || *amount != l.amount
                    || tr::preimage_hash(preimage) != *condition
                {
                    return Err(Error::Terms);
                }
                if height >= *refund_height {
                    return Err(Error::Time);
                }
                (l.recipient, *change)
            }
            (
                tr::Action::Refund {
                    owner,
                    amount,
                    change,
                    ..
                },
                tr::NativeLockKind::Hash { refund_height, .. },
            ) => {
                if *owner != l.sender || *amount != l.amount {
                    return Err(Error::Terms);
                }
                if height < *refund_height {
                    return Err(Error::Time);
                }
                (l.sender, *change)
            }
            (
                tr::Action::FiatRelease {
                    buyer,
                    seller,
                    amount,
                    payment_terms,
                    change,
                    ..
                },
                tr::NativeLockKind::Fiat { terms },
            ) => {
                if *buyer != l.recipient
                    || *seller != l.sender
                    || *amount != l.amount
                    || payment_terms != terms
                {
                    return Err(Error::Terms);
                }
                (l.recipient, *change)
            }
            (_, tr::NativeLockKind::Fiat { .. }) => return Err(Error::FiatRecoveryUnspecified),
            _ => return Err(Error::Terms),
        };
        if w.operation.offer_proof.is_some() || m.fee.0 < 240 || w.inputs.is_empty() {
            return Err(Error::Fee);
        }
        let mut seen = BTreeSet::new();
        let mut total = 0u128;
        for p in &w.inputs {
            if !seen.insert(p) {
                return Err(Error::Duplicate);
            }
            let c = state.coins.get(p).ok_or(Error::Missing)?;
            if c.output.owner != payer {
                return Err(Error::Authority);
            }
            if c.created_height >= height
                || c.coinbase && height.checked_sub(c.created_height).ok_or(Error::Time)? < 100
            {
                return Err(Error::Time);
            }
            total = total
                .checked_add(c.output.atoms as u128)
                .ok_or(Error::Bounds)?;
        }
        if total != change.0 as u128 + m.fee.0 as u128 {
            return Err(Error::Fee);
        }
        for a in &w.operation.approvals {
            verify_approval(&state, w, a)?
        }
        native(w.encode())?;
        Ok(())
    }
    #[cfg(test)]
    fn crash(point: &str) {
        if std::env::var("TRADING_COMPLETION_CRASH").ok().as_deref() == Some(point) {
            std::process::exit(86)
        }
    }
    #[cfg(not(test))]
    fn crash(_: &str) {}
    /// Each lock has one local immutable operation. Ambiguous approval/dispatch
    /// is queried, never reset. A future replacement protocol is not implied.
    pub struct Journal {
        connection: Connection,
        policy: CandidatePolicy,
    }
    struct Row {
        wire: tr::NativeOperation,
        stage: u8,
        requested: u8,
        descriptors: [Option<Vec<u8>>; 2],
    }
    impl Journal {
        // Local storage bridge only. This does not allocate a consensus object
        // or change wallet authorization. The caller encrypts every snapshot
        // before returning a request or submission to an external component.
        #[cfg(feature = "trading-local-storage-candidate")]
        pub(super) fn private_memory(policy: CandidatePolicy) -> Result<Self> {
            let journal = Self::open(Path::new(":memory:"), policy)?;
            db(journal.connection.execute_batch(
                "PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY; PRAGMA trusted_schema=OFF;",
            ))?;
            Ok(journal)
        }
        #[cfg(feature = "trading-local-storage-candidate")]
        pub(super) fn private_row(&self, id: Hash) -> Result<zeroize::Zeroizing<Vec<u8>>> {
            let row = self.row(id)?;
            let wire = zeroize::Zeroizing::new(native(row.wire.encode())?);
            let mut e = minicbor::Encoder::new(Vec::with_capacity(32768));
            e.array(8)
                .unwrap()
                .bytes(b"OFFLINE-LOCAL-COMPLETION-V1")
                .unwrap()
                .bytes(&id)
                .unwrap()
                .bytes(&lock_id(&row.wire)?)
                .unwrap()
                .bytes(&wire)
                .unwrap()
                .u8(row.stage)
                .unwrap()
                .u8(row.requested)
                .unwrap();
            for descriptor in row.descriptors {
                if let Some(d) = descriptor {
                    e.bytes(&d).unwrap();
                } else {
                    e.null().unwrap();
                }
            }
            Ok(zeroize::Zeroizing::new(e.into_writer()))
        }
        #[cfg(feature = "trading-local-storage-candidate")]
        pub(super) fn restore_private_row(&mut self, raw: &[u8]) -> Result<tr::Context> {
            if raw.len() > 32768 {
                return Err(Error::Bounds);
            }
            let mut d = minicbor::Decoder::new(raw);
            if d.array().map_err(|_| Error::Corrupt)? != Some(8)
                || d.bytes().map_err(|_| Error::Corrupt)? != b"OFFLINE-LOCAL-COMPLETION-V1"
            {
                return Err(Error::Corrupt);
            }
            let id: Hash = d
                .bytes()
                .map_err(|_| Error::Corrupt)?
                .try_into()
                .map_err(|_| Error::Corrupt)?;
            let output: Hash = d
                .bytes()
                .map_err(|_| Error::Corrupt)?
                .try_into()
                .map_err(|_| Error::Corrupt)?;
            let wire = d.bytes().map_err(|_| Error::Corrupt)?;
            let stage = d.u8().map_err(|_| Error::Corrupt)?;
            let requested = d.u8().map_err(|_| Error::Corrupt)?;
            let mut ds = [None, None];
            for descriptor in &mut ds {
                if d.datatype().map_err(|_| Error::Corrupt)? == minicbor::data::Type::Null {
                    d.null().map_err(|_| Error::Corrupt)?;
                } else {
                    let v = d.bytes().map_err(|_| Error::Corrupt)?;
                    if v.len() > 4096 {
                        return Err(Error::Bounds);
                    }
                    *descriptor = Some(v.to_vec());
                }
            }
            if d.position() != raw.len() {
                return Err(Error::Corrupt);
            }
            let w = native(tr::NativeOperation::decode(wire))?;
            if w.operation.id().map_err(|_| Error::Corrupt)? != id || lock_id(&w)? != output {
                return Err(Error::Corrupt);
            }
            if (stage == 0) == (w.operation.approvals.len() == slots(&w))
                || requested & 2 != 0 && !w.operation.approvals.iter().any(|a| a.slot == 0)
            {
                return Err(Error::Corrupt);
            }
            // Public hybrid verification on recovered bytes; current canonical
            // wallet ownership is additionally rechecked before each action.
            for a in &w.operation.approvals {
                authority(&w, a.slot)?;
                let (key, _) =
                    PublicKey::decode_descriptor(&a.descriptor).map_err(|_| Error::Authority)?;
                key.verify(
                    Domain::Transaction,
                    &w.operation
                        .signing_payload(a.slot, &a.descriptor)
                        .map_err(|_| Error::Corrupt)?,
                    &a.signature,
                )
                .map_err(|_| Error::Authority)?;
            }
            match self.row(id) {
                Ok(old) => {
                    let mut old_body = old.wire.clone();
                    old_body.operation.approvals.clear();
                    let mut new_body = w.clone();
                    new_body.operation.approvals.clear();
                    if native(old_body.encode())? != native(new_body.encode())?
                        || stage < old.stage
                        || old.stage == 0 && stage > 1
                        || requested & old.requested != old.requested
                    {
                        return Err(Error::Corrupt);
                    }
                    for a in old.wire.operation.approvals {
                        if !w.operation.approvals.contains(&a) {
                            return Err(Error::Corrupt);
                        }
                    }
                    for (i, old_d) in old.descriptors.iter().enumerate() {
                        if old_d.is_some() && old_d != &ds[i] {
                            return Err(Error::Corrupt);
                        }
                    }
                }
                Err(Error::Missing) => {
                    let count: i64 = db(self.connection.query_row(
                        "SELECT COUNT(*) FROM completions",
                        [],
                        |r| r.get(0),
                    ))?;
                    if count >= 256
                        || stage != 0
                        || requested != 0
                        || !w.operation.approvals.is_empty()
                    {
                        return Err(Error::Corrupt);
                    }
                }
                Err(e) => return Err(e),
            }
            let t = db(self.connection.unchecked_transaction())?;
            db(t.execute("INSERT INTO completions VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(id) DO UPDATE SET wire=excluded.wire,stage=excluded.stage,requested=excluded.requested,d0=excluded.d0,d1=excluded.d1",params![id.as_slice(),output.as_slice(),wire,stage,requested,ds[0],ds[1]]))?;
            self.row(id)?;
            if self.private_row(id)?.as_slice() != raw {
                return Err(Error::Corrupt);
            }
            db(t.commit())?;
            Ok(w.operation.meta.context)
        }

        pub fn open(path: &Path, policy: CandidatePolicy) -> Result<Self> {
            native(policy.check())?;
            let c = db(Connection::open(path))?;
            db(c.busy_timeout(std::time::Duration::from_secs(2)))?;
            db(c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;"))?;
            let version: i64 = db(c.pragma_query_value(None, "user_version", |r| r.get(0)))?;
            if version == 0 {
                let n:i64=db(c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",[],|r|r.get(0)))?;
                if n != 0 {
                    return Err(Error::Corrupt);
                }
                db(c.execute_batch("BEGIN IMMEDIATE; CREATE TABLE completions(id BLOB PRIMARY KEY CHECK(length(id)=32),lock_id BLOB UNIQUE NOT NULL CHECK(length(lock_id)=32),wire BLOB NOT NULL CHECK(length(wire)<=16384),stage INTEGER NOT NULL CHECK(stage BETWEEN 0 AND 3),requested INTEGER NOT NULL CHECK(requested BETWEEN 0 AND 3),d0 BLOB,d1 BLOB); PRAGMA user_version=1; COMMIT;"))?;
            } else if version != 1 {
                return Err(Error::Corrupt);
            }
            let check: String = db(c.query_row("PRAGMA quick_check", [], |r| r.get(0)))?;
            if check != "ok" {
                return Err(Error::Corrupt);
            }
            Ok(Self {
                connection: c,
                policy,
            })
        }
        fn row(&self, id: Hash) -> Result<Row> {
            let data = db(self
                .connection
                .query_row(
                    "SELECT lock_id,wire,stage,requested,d0,d1 FROM completions WHERE id=?1",
                    [id.as_slice()],
                    |r| {
                        Ok((
                            r.get::<_, Vec<u8>>(0)?,
                            r.get::<_, Vec<u8>>(1)?,
                            r.get::<_, u8>(2)?,
                            r.get::<_, u8>(3)?,
                            r.get::<_, Option<Vec<u8>>>(4)?,
                            r.get::<_, Option<Vec<u8>>>(5)?,
                        ))
                    },
                )
                .optional())?
            .ok_or(Error::Missing)?;
            let w = native(tr::NativeOperation::decode(&data.1))?;
            if w.operation.id().map_err(|_| Error::Corrupt)? != id
                || data.0 != lock_id(&w)?
                || data.2 > 3
                || data.3 > 3
                || data.3 & !((1u8 << slots(&w)) - 1) != 0
            {
                return Err(Error::Corrupt);
            }
            let ds = [data.4, data.5];
            for (slot, d) in ds.iter().enumerate() {
                if (data.3 & (1 << slot) != 0) != d.is_some()
                    || d.as_ref().is_some_and(|v| v.len() > 4096)
                {
                    return Err(Error::Corrupt);
                }
            }
            for a in &w.operation.approvals {
                if ds.get(a.slot as usize).and_then(|d| d.as_ref()) != Some(&a.descriptor) {
                    return Err(Error::Corrupt);
                }
            }
            if data.2 > 0 && w.operation.approvals.len() != slots(&w) {
                return Err(Error::Corrupt);
            }
            Ok(Row {
                wire: w,
                stage: data.2,
                requested: data.3,
                descriptors: ds,
            })
        }
        /// Recover an already persisted operation after losing prepare's response.
        /// The lock ID comes from the exact original canonical funding operation.
        /// Read-only: no fresh operation, wallet request, signing or dispatch.
        pub fn find_by_locked_output(&self, output: Hash) -> Result<Option<Hash>> {
            let found = db(self
                .connection
                .query_row(
                    "SELECT id FROM completions WHERE lock_id=?1",
                    [output.as_slice()],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional())?;
            let Some(raw) = found else { return Ok(None) };
            let id: Hash = raw.try_into().map_err(|_| Error::Corrupt)?;
            if lock_id(&self.row(id)?.wire)? != output {
                return Err(Error::Corrupt);
            }
            Ok(Some(id))
        }
        pub fn prepare(
            &mut self,
            store: &CanonicalStore,
            funding: &tr::NativeOperation,
            path: PathChoice,
            fees: FeeTerms,
        ) -> Result<Hash> {
            native(self.policy.check())?;
            let (head, state, _) = current(store)?;
            if native(tr::reconcile(&state, &native(funding.encode())?))?.is_none() {
                return Err(Error::Missing);
            }
            if !matches!(
                funding.operation.action,
                tr::Action::HashLock { .. } | tr::Action::FiatLock { .. }
            ) {
                return Err(Error::Terms);
            }
            let output = funding.operation.output_id(0).map_err(|_| Error::Terms)?;
            let l = native(tr::locked(&state, output))?;
            let action = match (path, &l.kind) {
                (PathChoice::Claim(preimage), tr::NativeLockKind::Hash { .. }) => {
                    tr::Action::Claim {
                        output,
                        recipient: l.recipient,
                        amount: l.amount,
                        preimage,
                        change: fees.change,
                    }
                }
                (PathChoice::Refund, tr::NativeLockKind::Hash { .. }) => tr::Action::Refund {
                    output,
                    owner: l.sender,
                    amount: l.amount,
                    change: fees.change,
                },
                (PathChoice::FiatCooperative, tr::NativeLockKind::Fiat { terms }) => {
                    tr::Action::FiatRelease {
                        output,
                        buyer: l.recipient,
                        seller: l.sender,
                        amount: l.amount,
                        payment_terms: *terms,
                        change: fees.change,
                    }
                }
                (_, tr::NativeLockKind::Fiat { .. }) => return Err(Error::FiatRecoveryUnspecified),
                _ => return Err(Error::Terms),
            };
            let w = tr::NativeOperation {
                operation: tr::Operation {
                    meta: tr::Meta {
                        context: l.context,
                        trade: l.trade,
                        contract: l.contract,
                        generation: l.generation,
                        // Trading body version 2: window [head + 1, fees.expiry] referencing the
                        // finalized head this completion is built on (no preconditions).
                        envelope: Envelope {
                            first_height: head.height.checked_add(1).ok_or(Error::Time)?,
                            last_height: fees.expiry,
                            reference_height: head.height,
                            reference_block: head.block,
                            preconditions: vec![],
                        },
                        fee: fees.fee,
                        inputs: fees.inputs.iter().map(tr::native_input_id).collect(),
                    },
                    action,
                    approvals: vec![],
                    offer_proof: None,
                },
                inputs: fees.inputs,
            };
            validate(store, &w, &self.policy)?;
            let id = w.operation.id().map_err(|_| Error::Terms)?;
            let raw = native(w.encode())?;
            let transaction = db(self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate))?;
            let count: i64 =
                db(transaction.query_row("SELECT COUNT(*) FROM completions", [], |r| r.get(0)))?;
            if count >= 256 {
                return Err(Error::Bounds);
            }
            if db(transaction
                .query_row(
                    "SELECT 1 FROM completions WHERE id=?1 OR lock_id=?2",
                    params![id.as_slice(), output.as_slice()],
                    |r| r.get::<_, i64>(0),
                )
                .optional())?
            .is_some()
            {
                return Err(Error::Duplicate);
            }
            db(transaction.execute(
                "INSERT INTO completions(id,lock_id,wire,stage,requested) VALUES(?1,?2,?3,0,0)",
                params![id.as_slice(), output.as_slice(), raw],
            ))?;
            crash("prepare_before_commit");
            db(transaction.commit())?;
            crash("prepare_after_commit");
            Ok(id)
        }
        pub fn request_approval(
            &mut self,
            store: &CanonicalStore,
            id: Hash,
            slot: u8,
            descriptor: Vec<u8>,
        ) -> Result<WalletRequest> {
            let row = self.row(id)?;
            let (owner, purpose) = authority(&row.wire, slot)?;
            if row.stage != 0 || row.requested & (1 << slot) != 0 {
                return Err(Error::Ambiguous);
            }
            if slot == 1 && !row.wire.operation.approvals.iter().any(|a| a.slot == 0) {
                return Err(Error::Authority);
            }
            validate(store, &row.wire, &self.policy)?;
            let (_, state, _) = current(store)?;
            state
                .wallets
                .authorize(owner, &descriptor)
                .map_err(|_| Error::Authority)?;
            PublicKey::decode_descriptor(&descriptor).map_err(|_| Error::Authority)?;
            let payload = row
                .wire
                .operation
                .signing_payload(slot, &descriptor)
                .map_err(|_| Error::Terms)?;
            let transaction = db(self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate))?;
            let changed=db(transaction.execute(if slot==0 {"UPDATE completions SET requested=requested|1,d0=?1 WHERE id=?2 AND requested=?3 AND stage=0 AND wire=?4"}else{"UPDATE completions SET requested=requested|2,d1=?1 WHERE id=?2 AND requested=?3 AND stage=0 AND wire=?4"},params![descriptor,id.as_slice(),row.requested,native(row.wire.encode())?]))?;
            if changed != 1 {
                return Err(Error::Ambiguous);
            }
            crash("request_before_commit");
            db(transaction.commit())?;
            crash("request_after_commit");
            Ok(WalletRequest {
                operation: id,
                slot,
                purpose,
                descriptor,
                payload,
            })
        }
        /// Return only the already-issued immutable request for reconciliation;
        /// this does not grant another signing attempt after a lost response.
        pub fn reconcile_request(&self, id: Hash, slot: u8) -> Result<ApprovalQuery> {
            let row = self.row(id)?;
            let (_, purpose) = authority(&row.wire, slot)?;
            let descriptor = row.descriptors[slot as usize]
                .clone()
                .ok_or(Error::Missing)?;
            let payload = row
                .wire
                .operation
                .signing_payload(slot, &descriptor)
                .map_err(|_| Error::Terms)?;
            Ok(ApprovalQuery {
                operation: id,
                slot,
                purpose,
                descriptor,
                payload,
            })
        }
        pub fn accept_approval(
            &mut self,
            store: &CanonicalStore,
            id: Hash,
            slot: u8,
            signature: HybridSignature,
        ) -> Result<()> {
            let mut row = self.row(id)?;
            authority(&row.wire, slot)?;
            let descriptor = row.descriptors[slot as usize]
                .clone()
                .ok_or(Error::Missing)?;
            let a = tr::Approval {
                slot,
                descriptor,
                signature,
            };
            if let Some(prior) = row.wire.operation.approvals.iter().find(|p| p.slot == slot) {
                return if prior == &a {
                    Ok(())
                } else {
                    Err(Error::Duplicate)
                };
            }
            if row.stage != 0
                || slot == 1 && !row.wire.operation.approvals.iter().any(|p| p.slot == 0)
            {
                return Err(Error::Authority);
            }
            validate(store, &row.wire, &self.policy)?;
            let (_, state, _) = current(store)?;
            verify_approval(&state, &row.wire, &a)?;
            let before = native(row.wire.encode())?;
            row.wire.operation.approvals.push(a);
            row.wire.operation.approvals.sort_by_key(|p| p.slot);
            let raw = native(row.wire.encode())?;
            let signed = row.wire.operation.approvals.len() == slots(&row.wire);
            if signed {
                match super::preview(store, raw.clone(), &self.policy).map_err(|_| Error::Terms)? {
                    AdmissionPreview::Pending(_) => {}
                    AdmissionPreview::AlreadyApplied(_) => return Err(Error::Stale),
                }
            }
            let transaction = db(self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate))?;
            if db(transaction.execute("UPDATE completions SET wire=?1,stage=?2 WHERE id=?3 AND wire=?4 AND stage=0 AND requested=?5",params![raw,u8::from(signed),id.as_slice(),before,row.requested]))?!=1{return Err(Error::Ambiguous)}
            crash("signed_before_commit");
            db(transaction.commit())?;
            crash("signed_after_commit");
            Ok(())
        }
        pub fn signed_bytes(&self, id: Hash) -> Result<Vec<u8>> {
            let row = self.row(id)?;
            if row.stage < 1 {
                return Err(Error::Missing);
            }
            native(row.wire.encode())
        }
        /// Persist first dispatch before returning exact signed bytes. Caller
        /// still performs canonical admission. Retrying is query-only.
        pub fn dispatch(
            &mut self,
            store: &CanonicalStore,
            id: Hash,
        ) -> Result<CandidateSubmission> {
            let row = self.row(id)?;
            if row.stage != 1 {
                return Err(Error::Ambiguous);
            }
            validate(store, &row.wire, &self.policy)?;
            let raw = native(row.wire.encode())?;
            let AdmissionPreview::Pending(submission) =
                super::preview(store, raw.clone(), &self.policy).map_err(|_| Error::Terms)?
            else {
                return Err(Error::Stale);
            };
            let transaction = db(self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate))?;
            if db(transaction.execute(
                "UPDATE completions SET stage=2 WHERE id=?1 AND stage=1 AND wire=?2",
                params![id.as_slice(), raw],
            ))? != 1
            {
                return Err(Error::Ambiguous);
            }
            crash("dispatch_before_commit");
            db(transaction.commit())?;
            crash("dispatch_after_commit");
            Ok(submission)
        }
        pub fn reconcile(&mut self, store: &CanonicalStore, id: Hash) -> Result<Reconciliation> {
            let row = self.row(id)?;
            let (head, state, _) = current(store)?;
            let context = &row.wire.operation.meta.context;
            if context.network != head.network
                || context.genesis != head.genesis
                || context.fingerprint != head.fingerprint
            {
                return Err(Error::Context);
            }
            let receipt = native(tr::reconcile(&state, &native(row.wire.encode())?))?;
            if let Some(receipt) = receipt {
                if row.stage < 1 {
                    return Err(Error::Corrupt);
                }
                db(self.connection.execute(
                    "UPDATE completions SET stage=3 WHERE id=?1",
                    [id.as_slice()],
                ))?;
                Ok(Reconciliation::Applied(receipt))
            } else if row.stage == 3 {
                Err(Error::Corrupt)
            } else {
                let output = lock_id(&row.wire)?;
                match tr::locked(&state, output) {
                    Ok(_) => Ok(Reconciliation::Pending),
                    Err(tr::NativeError::Missing) => {
                        Ok(Reconciliation::LockedOutputUnavailable { output })
                    }
                    Err(_) => Err(Error::Corrupt),
                }
            }
        }
    }
}

/// Offline-only integration candidate. Bitcoin consensus encodings, hashing and
/// secp256k1 verification come from RustBitcoin/libsecp256k1. No keys, signer,
/// socket, RPC or broadcaster are implemented here. Regtest headers are an SPV
/// fixture verifier, not a Mainnet/full-consensus validator or unspent oracle.
#[cfg(feature = "trading-bitcoin-candidate")]
pub mod bitcoin_candidate {
    #[cfg(feature = "trading-local-storage-candidate")]
    use crate::trading_service_v1::local_storage_candidate::{
        StorageContext, StorageKey, legacy_candidate as sealed_storage,
    };

    use super::*;
    use bitcoin::{
        Amount, BlockHash, EcdsaSighashType, Network, OutPoint, ScriptBuf, Transaction, Txid,
        absolute,
        block::Header,
        consensus::{deserialize, serialize},
        hashes::{Hash as _, sha256d},
        opcodes::all::*,
        script::Builder,
        secp256k1::{Message, PublicKey, Secp256k1},
        sighash::SighashCache,
    };
    use minicbor::{Decoder, Encoder};
    use mutiny_consensus_v8::trading_v1 as tr;
    use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::Path,
    };

    const NS: &[u8] = b"MUTINY-BITCOIN-OFFLINE-CANDIDATE-V1";
    const MAX_BYTES: usize = 131_072;
    const MAX_PREVIOUS_TX: usize = 32_768;
    const MAX_INPUTS: usize = 16;
    const MAX_OPERATIONS: i64 = 256;
    const MAX_REVISIONS: u32 = 16;
    const REGTEST: u8 = 3;
    pub const PRODUCTION_ENABLED: bool = false;

    #[derive(Debug, PartialEq, Eq)]
    pub enum Error {
        Gate,
        Unit,
        Codec,
        Bounds,
        Store,
        Context,
        Stale,
        Authority,
        Terms,
        Network,
        Input,
        Output,
        Fee,
        Signature,
        Duplicate,
        Ambiguous,
        State,
        Evidence,
        Deadline,
        Replacement,
        Corrupt,
        Capacity,
        LegacyJournal,
    }
    pub type Result<T> = std::result::Result<T, Error>;
    fn native<T>(r: tr::NativeResult<T>) -> Result<T> {
        r.map_err(|e| match e {
            tr::NativeError::Gate => Error::Gate,
            tr::NativeError::UnitUnresolved => Error::Unit,
            _ => Error::Evidence,
        })
    }
    fn db<T>(r: rusqlite::Result<T>) -> Result<T> {
        r.map_err(|_| Error::Store)
    }
    fn digest(label: &[u8], raw: &[u8]) -> Hash {
        mutiny_consensus_v8::domain_hash(&[NS, b"/", label].concat(), raw)
    }
    fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
        if d.array().map_err(|_| Error::Codec)? != Some(n) {
            return Err(Error::Codec);
        }
        Ok(())
    }
    fn bytes<'a>(d: &mut Decoder<'a>) -> Result<&'a [u8]> {
        d.bytes().map_err(|_| Error::Codec)
    }
    fn fixed(d: &mut Decoder<'_>) -> Result<Hash> {
        bytes(d)?.try_into().map_err(|_| Error::Codec)
    }
    fn uint(d: &mut Decoder<'_>) -> Result<u64> {
        d.u64().map_err(|_| Error::Codec)
    }
    fn tx(raw: &[u8], limit: usize) -> Result<Transaction> {
        if raw.is_empty() || raw.len() > limit {
            return Err(Error::Bounds);
        }
        let t: Transaction = deserialize(raw).map_err(|_| Error::Codec)?;
        if serialize(&t) != raw {
            return Err(Error::Codec);
        }
        Ok(t)
    }
    fn current(
        store: &CanonicalStore,
    ) -> Result<(FinalizedAnchor, mutiny_consensus_v8::execution::State, Hash)> {
        if store.halted().map_err(|_| Error::Store)? {
            return Err(Error::Store);
        }
        let (head, _) = store.load().map_err(|_| Error::Store)?;
        let (p, s, r) = store
            .execution_parent(head.height)
            .map_err(|_| Error::Store)?;
        if p.block != head.block || r != head.root || s.root().map_err(|_| Error::Store)? != r {
            return Err(Error::Stale);
        }
        Ok((
            FinalizedAnchor {
                network: NETWORK_ID,
                genesis: p.genesis,
                fingerprint: p.fingerprint,
                height: p.height,
                block: p.block,
            },
            s,
            r,
        ))
    }

    /// These are explicit fixture assumptions, not cross-chain time conversion
    /// or final numeric economic/confirmation policy. Construction unavailable
    /// outside cfg(test); normal candidate units remain closed.
    #[derive(Clone, Debug)]
    pub struct OfflineSafety {
        mut_blocks: u64,
        bitcoin_blocks: u32,
        confirmations: u32,
    }
    impl OfflineSafety {
        #[cfg(test)]
        pub fn qualification(
            mut_blocks: u64,
            bitcoin_blocks: u32,
            confirmations: u32,
        ) -> Result<Self> {
            if mut_blocks == 0
                || bitcoin_blocks == 0
                || confirmations == 0
                || confirmations > bitcoin_blocks
            {
                return Err(Error::Deadline);
            }
            Ok(Self {
                mut_blocks,
                bitcoin_blocks,
                confirmations,
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct InputCoin {
        pub previous_transaction: Vec<u8>,
        pub index: u32,
        pub public_key: [u8; 33],
    }
    impl InputCoin {
        fn previous(&self) -> Result<(OutPoint, bitcoin::TxOut)> {
            let t = tx(&self.previous_transaction, MAX_PREVIOUS_TX)?;
            let o = t
                .output
                .get(self.index as usize)
                .ok_or(Error::Input)?
                .clone();
            let p = bitcoin::PublicKey::new(
                PublicKey::from_slice(&self.public_key).map_err(|_| Error::Input)?,
            );
            if o.value == Amount::ZERO
                || o.value > Amount::MAX_MONEY
                || o.script_pubkey
                    != ScriptBuf::new_p2wpkh(&p.wpubkey_hash().map_err(|_| Error::Input)?)
            {
                return Err(Error::Input);
            }
            // Previous transaction bytes prove identity/amount binding, not
            // best-chain membership, maturity or current unspent status.
            Ok((
                OutPoint {
                    txid: t.compute_txid(),
                    vout: self.index,
                },
                o,
            ))
        }
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BitcoinTerms {
        pub inputs: Vec<InputCoin>,
        pub recipient: [u8; 33],
        pub refund: [u8; 33],
        pub refund_height: u32,
        pub approved_change: Vec<u8>,
        pub fee_satoshis: u64,
        pub fee_limit_satoshis: u64,
        pub expiry_mut_height: u64,
        pub policy_generation: u64,
    }
    fn lock_script(condition: Hash, terms: &BitcoinTerms) -> Result<ScriptBuf> {
        let recipient = bitcoin::PublicKey::new(
            PublicKey::from_slice(&terms.recipient).map_err(|_| Error::Terms)?,
        );
        let refund = bitcoin::PublicKey::new(
            PublicKey::from_slice(&terms.refund).map_err(|_| Error::Terms)?,
        );
        if recipient == refund || terms.refund_height == 0 || terms.refund_height >= 500_000_000 {
            return Err(Error::Terms);
        }
        // Mature standard primitives only. Claim remains script-spendable after
        // timeout; bounded liveness/monitoring is still required for swap safety.
        Ok(Builder::new()
            .push_opcode(OP_IF)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SHA256)
            .push_slice(condition)
            .push_opcode(OP_EQUALVERIFY)
            .push_key(&recipient)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_int(i64::from(terms.refund_height))
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_key(&refund)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .into_script())
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct TreasurySwapIntent {
        operation: Hash,
        revision: u32,
        replaces: Option<Txid>,
        frozen: Vec<u8>,
        funding: Vec<u8>,
        mut_anchor: FinalizedAnchor,
        mut_root: Hash,
        bitcoin_tip: BlockHash,
        bitcoin_height: u32,
        terms: BitcoinTerms,
        unsigned: Vec<u8>,
        condition: Hash,
        mut_refund_height: u64,
    }
    impl TreasurySwapIntent {
        pub fn operation(&self) -> Hash {
            self.operation
        }
        pub fn revision(&self) -> u32 {
            self.revision
        }
        pub fn intent_hash(&self) -> Result<Hash> {
            Ok(digest(b"intent", &self.encode()?))
        }
        pub fn unsigned_transaction(&self) -> &[u8] {
            &self.unsigned
        }
        pub fn expected_txid(&self) -> Result<Txid> {
            Ok(tx(&self.unsigned, MAX_PREVIOUS_TX)?.compute_txid())
        }
        pub fn frozen_offer(&self) -> Result<tr::FrozenTreasuryOffer> {
            native(tr::FrozenTreasuryOffer::decode(&self.frozen))
        }
        pub fn encode(&self) -> Result<Vec<u8>> {
            let mut e = Encoder::new(Vec::new());
            e.array(18)
                .unwrap()
                .bytes(NS)
                .unwrap()
                .u8(1)
                .unwrap()
                .u8(REGTEST)
                .unwrap()
                .bytes(&self.operation)
                .unwrap()
                .u32(self.revision)
                .unwrap();
            match self.replaces {
                Some(t) => {
                    e.bytes(&t.to_byte_array()).unwrap();
                }
                None => {
                    e.null().unwrap();
                }
            }
            e.bytes(&self.frozen)
                .unwrap()
                .bytes(&self.funding)
                .unwrap()
                .bytes(&self.mut_anchor.encode())
                .unwrap()
                .bytes(&self.mut_root)
                .unwrap()
                .bytes(&self.bitcoin_tip.to_byte_array())
                .unwrap()
                .u32(self.bitcoin_height)
                .unwrap();
            e.array(10)
                .unwrap()
                .array(self.terms.inputs.len() as u64)
                .unwrap();
            for i in &self.terms.inputs {
                e.array(3)
                    .unwrap()
                    .bytes(&i.previous_transaction)
                    .unwrap()
                    .u32(i.index)
                    .unwrap()
                    .bytes(&i.public_key)
                    .unwrap();
            }
            e.bytes(&self.terms.recipient)
                .unwrap()
                .bytes(&self.terms.refund)
                .unwrap()
                .u32(self.terms.refund_height)
                .unwrap()
                .bytes(&self.terms.approved_change)
                .unwrap()
                .u64(self.terms.fee_satoshis)
                .unwrap()
                .u64(self.terms.fee_limit_satoshis)
                .unwrap()
                .u64(self.terms.expiry_mut_height)
                .unwrap()
                .u64(self.terms.policy_generation)
                .unwrap()
                .u8(1)
                .unwrap();
            e.bytes(&self.unsigned)
                .unwrap()
                .bytes(&self.condition)
                .unwrap()
                .u64(self.mut_refund_height)
                .unwrap()
                .bytes(b"FIXED-EXACT-ARCHITECT-CONSIDERATION")
                .unwrap()
                .u8(0)
                .unwrap();
            let raw = e.into_writer();
            if raw.len() > MAX_BYTES {
                return Err(Error::Bounds);
            }
            Ok(raw)
        }
        pub fn decode(raw: &[u8]) -> Result<Self> {
            if raw.len() > MAX_BYTES {
                return Err(Error::Bounds);
            }
            let mut d = Decoder::new(raw);
            array(&mut d, 18)?;
            if bytes(&mut d)? != NS || uint(&mut d)? != 1 {
                return Err(Error::Codec);
            }
            if uint(&mut d)? != u64::from(REGTEST) {
                return Err(Error::Network);
            }
            let operation = fixed(&mut d)?;
            let revision = d.u32().map_err(|_| Error::Codec)?;
            let replaces = if d.datatype().map_err(|_| Error::Codec)? == minicbor::data::Type::Null
            {
                d.null().map_err(|_| Error::Codec)?;
                None
            } else {
                Some(Txid::from_byte_array(fixed(&mut d)?))
            };
            let frozen = bytes(&mut d)?.to_vec();
            let funding = bytes(&mut d)?.to_vec();
            let mut_anchor = FinalizedAnchor::decode(bytes(&mut d)?).map_err(|_| Error::Codec)?;
            let mut_root = fixed(&mut d)?;
            let bitcoin_tip = BlockHash::from_byte_array(fixed(&mut d)?);
            let bitcoin_height = d.u32().map_err(|_| Error::Codec)?;
            array(&mut d, 10)?;
            let n = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
            if n == 0 || n > MAX_INPUTS as u64 {
                return Err(Error::Bounds);
            }
            let mut inputs = Vec::new();
            for _ in 0..n {
                array(&mut d, 3)?;
                inputs.push(InputCoin {
                    previous_transaction: bytes(&mut d)?.to_vec(),
                    index: d.u32().map_err(|_| Error::Codec)?,
                    public_key: bytes(&mut d)?.try_into().map_err(|_| Error::Codec)?,
                });
            }
            let terms = BitcoinTerms {
                inputs,
                recipient: bytes(&mut d)?.try_into().map_err(|_| Error::Codec)?,
                refund: bytes(&mut d)?.try_into().map_err(|_| Error::Codec)?,
                refund_height: d.u32().map_err(|_| Error::Codec)?,
                approved_change: bytes(&mut d)?.to_vec(),
                fee_satoshis: uint(&mut d)?,
                fee_limit_satoshis: uint(&mut d)?,
                expiry_mut_height: uint(&mut d)?,
                policy_generation: uint(&mut d)?,
            };
            if uint(&mut d)? != 1 {
                return Err(Error::Codec);
            }
            let out = Self {
                operation,
                revision,
                replaces,
                frozen,
                funding,
                mut_anchor,
                mut_root,
                bitcoin_tip,
                bitcoin_height,
                terms,
                unsigned: bytes(&mut d)?.to_vec(),
                condition: fixed(&mut d)?,
                mut_refund_height: uint(&mut d)?,
            };
            if bytes(&mut d)? != b"FIXED-EXACT-ARCHITECT-CONSIDERATION"
                || uint(&mut d)? != 0
                || d.position() != raw.len()
                || out.encode()? != raw
            {
                return Err(Error::Codec);
            }
            out.verify_terms()?;
            Ok(out)
        }
        fn verify_terms(&self) -> Result<()> {
            let f = self.frozen_offer()?;
            let a = f.creation_anchor();
            let tr::OfferTerms::HashLinked {
                amount,
                bitcoin_satoshis,
                bitcoin_network,
            } = f.offer().terms
            else {
                return Err(Error::Terms);
            };
            if bitcoin_network != REGTEST {
                return Err(Error::Network);
            }
            if self.operation
                != digest(
                    b"operation",
                    &[
                        a.network.to_be_bytes().as_slice(),
                        &a.genesis,
                        &a.fingerprint,
                        &f.trade(),
                        &f.contract(),
                    ]
                    .concat(),
                )
                || self.mut_anchor.network != a.network
                || self.mut_anchor.genesis != a.genesis
                || self.mut_anchor.fingerprint != a.fingerprint
                || self.mut_anchor.height < a.height
                || self.terms.policy_generation == 0
                || self.revision >= MAX_REVISIONS
                || (self.revision == 0) != self.replaces.is_none()
                || amount.0 == 0
            {
                return Err(Error::Context);
            }
            let w = native(tr::NativeOperation::decode(&self.funding))?;
            let tr::Action::HashLock {
                offer,
                recipient,
                amount: locked,
                condition,
                refund_height,
                ..
            } = w.operation.action
            else {
                return Err(Error::Evidence);
            };
            if w.operation.meta.context != f.offer().context
                || w.operation.meta.trade != f.trade()
                || w.operation.meta.contract != f.contract()
                || offer != native(f.offer_id())?
                || recipient != f.address()
                || locked != amount
                || condition != self.condition
                || refund_height != self.mut_refund_height
                || w.operation
                    .offer_proof
                    .as_ref()
                    .is_none_or(|p| p.offer.body != *f.offer())
            {
                return Err(Error::Terms);
            }
            let expected = build_unsigned(bitcoin_satoshis, self.condition, &self.terms)?;
            if serialize(&expected) != self.unsigned {
                return Err(Error::Output);
            }
            if self.terms.expiry_mut_height <= self.mut_anchor.height
                || self.terms.expiry_mut_height > self.mut_refund_height
            {
                return Err(Error::Deadline);
            }
            Ok(())
        }
        pub fn psbt(&self) -> Result<Vec<u8>> {
            self.verify_terms()?;
            let mut p = bitcoin::psbt::Psbt::from_unsigned_tx(tx(&self.unsigned, MAX_PREVIOUS_TX)?)
                .map_err(|_| Error::Codec)?;
            for (entry, coin) in p.inputs.iter_mut().zip(&self.terms.inputs) {
                entry.non_witness_utxo = Some(tx(&coin.previous_transaction, MAX_PREVIOUS_TX)?);
                entry.witness_utxo = Some(coin.previous()?.1);
                entry.sighash_type = Some(EcdsaSighashType::All.into());
            }
            Ok(p.serialize())
        }
        /// Independent returned-transaction inspection. Strict P2WPKH ALL only;
        /// no arbitrary script/witness acceptance, unknown output or hidden fee.
        pub fn verify_signed(&self, raw: &[u8]) -> Result<(Txid, bitcoin::Wtxid)> {
            self.verify_terms()?;
            let signed = tx(raw, MAX_PREVIOUS_TX)?;
            let mut stripped = signed.clone();
            for i in &mut stripped.input {
                i.witness = bitcoin::Witness::new();
            }
            if serialize(&stripped) != self.unsigned {
                return Err(Error::Output);
            }
            let secp = Secp256k1::verification_only();
            let mut cache = SighashCache::new(&signed);
            for (n, (i, c)) in signed.input.iter().zip(&self.terms.inputs).enumerate() {
                let items: Vec<_> = i.witness.iter().collect();
                if items.len() != 2 || items[1] != c.public_key {
                    return Err(Error::Signature);
                }
                let sig = bitcoin::ecdsa::Signature::from_slice(items[0])
                    .map_err(|_| Error::Signature)?;
                let mut low = sig.signature;
                low.normalize_s();
                if sig.sighash_type != EcdsaSighashType::All
                    || low != sig.signature
                    || sig.to_vec() != items[0]
                {
                    return Err(Error::Signature);
                }
                let prev = c.previous()?.1;
                let hash = cache
                    .p2wpkh_signature_hash(
                        n,
                        &prev.script_pubkey,
                        prev.value,
                        EcdsaSighashType::All,
                    )
                    .map_err(|_| Error::Signature)?;
                let key = PublicKey::from_slice(&c.public_key).map_err(|_| Error::Signature)?;
                secp.verify_ecdsa(
                    &Message::from_digest(hash.to_byte_array()),
                    &sig.signature,
                    &key,
                )
                .map_err(|_| Error::Signature)?;
            }
            Ok((signed.compute_txid(), signed.compute_wtxid()))
        }
    }
    fn build_unsigned(amount: u64, condition: Hash, t: &BitcoinTerms) -> Result<Transaction> {
        if t.inputs.is_empty()
            || t.inputs.len() > MAX_INPUTS
            || t.approved_change.len() > 128
            || t.fee_satoshis > t.fee_limit_satoshis
        {
            return Err(Error::Fee);
        }
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        let mut input = Vec::new();
        for c in &t.inputs {
            let (point, o) = c.previous()?;
            if !seen.insert(point) {
                return Err(Error::Duplicate);
            }
            total = total.checked_add(o.value.to_sat()).ok_or(Error::Bounds)?;
            input.push(bitcoin::TxIn {
                previous_output: point,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            });
        }
        if amount == 0 || total > Amount::MAX_MONEY.to_sat() {
            return Err(Error::Bounds);
        }
        let change = total
            .checked_sub(amount)
            .and_then(|n| n.checked_sub(t.fee_satoshis))
            .ok_or(Error::Fee)?;
        let mut output = vec![bitcoin::TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: lock_script(condition, t)?.to_p2wsh(),
        }];
        if output[0].value < output[0].script_pubkey.minimal_non_dust() {
            return Err(Error::Output);
        }
        let script = ScriptBuf::from_bytes(t.approved_change.clone());
        if !script.is_p2wpkh() {
            return Err(Error::Output);
        }
        if change > 0 {
            if Amount::from_sat(change) < script.minimal_non_dust() {
                return Err(Error::Output);
            }
            output.push(bitcoin::TxOut {
                value: Amount::from_sat(change),
                script_pubkey: script,
            });
        }
        Ok(Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        })
    }

    #[derive(Clone, Debug)]
    struct HeaderEntry {
        header: Header,
        height: u32,
        work: bitcoin::pow::Work,
    }
    /// Bounded pinned-genesis regtest header graph. No Mainnet, testnet or signet
    /// acceptance (signet additionally requires its challenge verification).
    #[derive(Clone, Debug)]
    pub struct RegtestHeaders {
        entries: BTreeMap<BlockHash, HeaderEntry>,
        best: BlockHash,
    }
    impl RegtestHeaders {
        pub fn new() -> Self {
            let h = bitcoin::blockdata::constants::genesis_block(Network::Regtest).header;
            let id = h.block_hash();
            Self {
                entries: BTreeMap::from([(
                    id,
                    HeaderEntry {
                        header: h,
                        height: 0,
                        work: h.work(),
                    },
                )]),
                best: id,
            }
        }
        pub fn tip(&self) -> (BlockHash, u32) {
            (self.best, self.entries[&self.best].height)
        }
        pub fn insert(&mut self, raw: &[u8], now: u32) -> Result<BlockHash> {
            if raw.len() != 80 {
                return Err(Error::Bounds);
            }
            let h: Header = deserialize(raw).map_err(|_| Error::Codec)?;
            let id = h.block_hash();
            if self.entries.contains_key(&id) {
                return Ok(id);
            }
            if self.entries.len() >= 4096 {
                return Err(Error::Capacity);
            }
            let p = self.entries.get(&h.prev_blockhash).ok_or(Error::Evidence)?;
            let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest).header;
            if h.bits != genesis.bits || h.validate_pow(genesis.target()).is_err() {
                return Err(Error::Evidence);
            }
            let mut times = Vec::new();
            let mut ancestor = Some(p);
            for _ in 0..11 {
                let Some(v) = ancestor else { break };
                times.push(v.header.time);
                ancestor = self.entries.get(&v.header.prev_blockhash);
            }
            times.sort_unstable();
            if h.time <= times[times.len() / 2] || u64::from(h.time) > u64::from(now) + 7200 {
                return Err(Error::Evidence);
            }
            let e = HeaderEntry {
                header: h,
                height: p.height.checked_add(1).ok_or(Error::Bounds)?,
                work: p.work + h.work(),
            };
            if e.work > self.entries[&self.best].work {
                self.best = id;
            }
            self.entries.insert(id, e);
            Ok(id)
        }
        fn depth(&self, id: BlockHash) -> Result<u32> {
            let target = self.entries.get(&id).ok_or(Error::Evidence)?;
            let tip = &self.entries[&self.best];
            let mut p = tip;
            while p.height > target.height {
                p = self
                    .entries
                    .get(&p.header.prev_blockhash)
                    .ok_or(Error::Evidence)?;
            }
            if p.header.block_hash() != id {
                return Err(Error::Stale);
            }
            Ok(tip.height - target.height + 1)
        }
        pub fn verify_inclusion(&self, proof: &Inclusion, txid: Txid) -> Result<u32> {
            if proof.total_transactions == 0
                || proof.total_transactions > 1_000_000
                || proof.index >= proof.total_transactions
                || proof.branch.len() > 20
            {
                return Err(Error::Bounds);
            }
            let mut value = txid.to_byte_array();
            let mut index = proof.index;
            let mut width = proof.total_transactions;
            let mut used = 0;
            while width > 1 {
                let sibling = *proof.branch.get(used).ok_or(Error::Evidence)?;
                if index ^ 1 >= width {
                    if sibling != value {
                        return Err(Error::Evidence);
                    }
                } else if sibling == value {
                    return Err(Error::Evidence);
                } // reject mutated duplicate leaves
                let pair = if index & 1 == 0 {
                    [value, sibling]
                } else {
                    [sibling, value]
                };
                value = sha256d::Hash::hash(&pair.concat()).to_byte_array();
                index /= 2;
                width = width.div_ceil(2);
                used += 1;
            }
            if used != proof.branch.len()
                || self
                    .entries
                    .get(&proof.block)
                    .ok_or(Error::Evidence)?
                    .header
                    .merkle_root
                    .to_byte_array()
                    != value
            {
                return Err(Error::Evidence);
            }
            self.depth(proof.block)
        }
    }
    impl Default for RegtestHeaders {
        fn default() -> Self {
            Self::new()
        }
    }
    #[derive(Clone, Debug)]
    pub struct Inclusion {
        pub block: BlockHash,
        pub index: u32,
        pub total_transactions: u32,
        pub branch: Vec<Hash>,
    }

    fn verify_mut_funding(
        store: &CanonicalStore,
        f: &tr::FrozenTreasuryOffer,
        w: &tr::NativeOperation,
        policy: &CandidatePolicy,
    ) -> Result<(FinalizedAnchor, Hash, tr::NativeLock)> {
        native(policy.check())?;
        // Preserve a transient store outage as Store rather than misclassifying
        // it as invalid counterparty evidence through the archive adapter.
        let cap =
            super::verify_archived_treasury_offer(store, f.clone(), policy).map_err(
                |e| match e {
                    super::ServiceError::CanonicalStore => Error::Store,
                    super::ServiceError::StaleParent => Error::Stale,
                    _ => Error::Evidence,
                },
            )?;
        native(cap.verify_funding_binding(w))?;
        let (a, s, r) = current(store)?;
        let receipt = native(tr::reconcile(&s, &native(w.encode())?))?.ok_or(Error::Evidence)?;
        let output = w.operation.output_id(0).map_err(|_| Error::Evidence)?;
        let l = native(tr::locked(&s, output))?;
        if receipt.height > a.height
            || l.created_height != receipt.height
            || l.trade != f.trade()
            || l.contract != f.contract()
            || l.recipient != f.address()
        {
            return Err(Error::Evidence);
        }
        let key = tr::single_fill_key(&w.operation.meta.context, [0; 32], native(f.offer_id())?);
        let (found, record) = native(tr::NativeRecord::decode(
            s.protocol_records
                .get(&tr::record_key(1, key))
                .ok_or(Error::Evidence)?,
        ))?;
        if found != key
            || !matches!(record,tr::NativeRecord::Consumed{trade,contract,..} if trade==f.trade() && contract==f.contract())
        {
            return Err(Error::Evidence);
        }
        Ok((a, r, l))
    }
    fn fresh(
        store: &CanonicalStore,
        intent: &TreasurySwapIntent,
        headers: &RegtestHeaders,
        safety: &OfflineSafety,
        policy: &CandidatePolicy,
    ) -> Result<()> {
        let f = intent.frozen_offer()?;
        let w = native(tr::NativeOperation::decode(&intent.funding))?;
        let (a, _, l) = verify_mut_funding(store, &f, &w, policy)?;
        let tr::NativeLockKind::Hash {
            condition,
            refund_height,
        } = l.kind
        else {
            return Err(Error::Terms);
        };
        if condition != intent.condition
            || refund_height != intent.mut_refund_height
            || a.height >= intent.terms.expiry_mut_height
            || refund_height
                .checked_sub(a.height)
                .is_none_or(|n| n < safety.mut_blocks)
            || intent
                .terms
                .refund_height
                .checked_sub(headers.tip().1)
                .is_none_or(|n| n < safety.bitcoin_blocks)
        {
            return Err(Error::Deadline);
        }
        if headers.depth(intent.bitcoin_tip).is_err() {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Independent dedicated-signer policy input. Populate only from an
    /// Architect-approved exact intent digest and an independently inspected
    /// watch-only input inventory. It neither receives nor generates a key.
    #[derive(Clone, Debug)]
    pub struct SignerAuthorization {
        pub exact_intent_hash: Hash,
        pub approved_inputs: BTreeSet<OutPoint>,
        pub approved_change: Vec<u8>,
        pub policy_generation: u64,
    }
    impl SignerAuthorization {
        pub fn verify(&self, i: &TreasurySwapIntent) -> Result<()> {
            i.verify_terms()?;
            if self.exact_intent_hash != i.intent_hash()?
                || self.approved_change != i.terms.approved_change
                || self.policy_generation != i.terms.policy_generation
            {
                return Err(Error::Authority);
            }
            for c in &i.terms.inputs {
                if !self.approved_inputs.contains(&c.previous()?.0) {
                    return Err(Error::Authority);
                }
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Stage {
        Prepared = 0,
        SignDispatched = 1,
        Signed = 2,
        BroadcastPending = 3,
    }
    impl Stage {
        fn decode(n: i64) -> Result<Self> {
            match n {
                0 => Ok(Self::Prepared),
                1 => Ok(Self::SignDispatched),
                2 => Ok(Self::Signed),
                3 => Ok(Self::BroadcastPending),
                _ => Err(Error::Corrupt),
            }
        }
    }
    #[derive(Debug)]
    pub struct SignRequest {
        pub operation: Hash,
        pub revision: u32,
        pub intent: Vec<u8>,
        pub psbt: Vec<u8>,
    }
    #[derive(Debug)]
    pub struct BroadcastRequest {
        pub operation: Hash,
        pub revision: u32,
        pub txid: Txid,
        pub signed_bytes: Vec<u8>,
    }
    /// Query-only recovery material for a dispatch whose delivery is unknown.
    /// This is not another broadcast permit and never permits another signature.
    #[derive(Debug)]
    pub struct BroadcastReconciliation {
        pub operation: Hash,
        pub revision: u32,
        pub intent_hash: Hash,
        pub txid: Txid,
        pub inputs: Vec<OutPoint>,
        pub signed_bytes: Vec<u8>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CreationAdmission {
        Incomplete,
        Admitted,
    }
    pub struct OperationJournal {
        db: Connection,
        policy: CandidatePolicy,
        #[cfg(feature = "trading-local-storage-candidate")]
        storage: Option<sealed_storage::SnapshotStore>,
    }
    impl OperationJournal {
        fn ensure_storage_healthy(&self) -> Result<()> {
            #[cfg(feature = "trading-local-storage-candidate")]
            if let Some(s) = &self.storage {
                s.healthy().map_err(|_| Error::Store)?;
            }
            Ok(())
        }
        fn persist_storage(&mut self) -> Result<()> {
            #[cfg(feature = "trading-local-storage-candidate")]
            if let Some(s) = &mut self.storage {
                s.persist(&self.db).map_err(|_| Error::Store)?;
            }
            Ok(())
        }
        fn storage_binding(&self, anchor: &FinalizedAnchor) -> Result<()> {
            #[cfg(feature = "trading-local-storage-candidate")]
            if let Some(s) = &self.storage {
                s.matches_anchor(anchor).map_err(|_| Error::Context)?;
            }
            let _ = anchor;
            Ok(())
        }
        #[cfg(feature = "trading-local-storage-candidate")]
        pub fn storage_checkpoint(&self) -> Result<sealed_storage::DurableCheckpoint> {
            self.ensure_storage_healthy()?;
            self.storage
                .as_ref()
                .ok_or(Error::State)?
                .checkpoint()
                .map_err(|_| Error::Store)
        }

        #[cfg(feature = "trading-local-storage-candidate")]
        pub fn create_encrypted(
            paths: &sealed_storage::Paths,
            key: std::sync::Arc<StorageKey>,
            context: StorageContext,
            policy: CandidatePolicy,
        ) -> Result<Self> {
            Self::create_encrypted_kind(
                paths,
                key,
                context,
                policy,
                sealed_storage::JournalKind::BitcoinEngine,
            )
        }
        #[cfg(feature = "trading-local-storage-candidate")]
        fn create_encrypted_kind(
            paths: &sealed_storage::Paths,
            key: std::sync::Arc<StorageKey>,
            context: StorageContext,
            policy: CandidatePolicy,
            kind: sealed_storage::JournalKind,
        ) -> Result<Self> {
            native(policy.check())?;
            let mut out = Self::open(Path::new(":memory:"), policy.clone())?;
            sealed_storage::memory_hardening(&out.db).map_err(|_| Error::Store)?;
            out.storage = Some(
                sealed_storage::SnapshotStore::create(paths, key, &context, kind, &out.db, &policy)
                    .map_err(|_| Error::Store)?,
            );
            Ok(out)
        }
        #[cfg(feature = "trading-local-storage-candidate")]
        pub fn open_encrypted(
            paths: &sealed_storage::Paths,
            key: std::sync::Arc<StorageKey>,
            context: StorageContext,
            minimum: sealed_storage::DurableCheckpoint,
            policy: CandidatePolicy,
        ) -> Result<Self> {
            Self::open_encrypted_kind(
                paths,
                key,
                context,
                minimum,
                policy,
                sealed_storage::JournalKind::BitcoinEngine,
            )
        }
        #[cfg(feature = "trading-local-storage-candidate")]
        fn open_encrypted_kind(
            paths: &sealed_storage::Paths,
            key: std::sync::Arc<StorageKey>,
            context: StorageContext,
            minimum: sealed_storage::DurableCheckpoint,
            policy: CandidatePolicy,
            kind: sealed_storage::JournalKind,
        ) -> Result<Self> {
            native(policy.check())?;
            let mut out = Self::open(Path::new(":memory:"), policy.clone())?;
            out.storage = Some(
                sealed_storage::SnapshotStore::open(
                    paths,
                    key,
                    &context,
                    kind,
                    minimum,
                    &mut out.db,
                    &policy,
                )
                .map_err(|_| Error::Store)?,
            );
            out.validate()?;
            Ok(out)
        }

        pub fn open(path: &Path, policy: CandidatePolicy) -> Result<Self> {
            native(policy.check())?;
            if let Ok(m) = std::fs::metadata(path)
                && m.len() > 128 * 1024 * 1024
            {
                return Err(Error::Capacity);
            }
            let dbh = db(Connection::open(path))?;
            let version: i64 = db(dbh.query_row("PRAGMA user_version", [], |r| r.get(0)))?;
            if version == 0 {
                let exists: bool = db(dbh.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='treasury_creation')",
                    [], |r| r.get(0),
                ))?;
                if exists {
                    let count: i64 = db(dbh.query_row(
                        "SELECT COUNT(*) FROM treasury_creation",
                        [],
                        |r| r.get(0),
                    ))?;
                    if count != 0 {
                        // R3 rows cannot prove that the post-commit head check
                        // finished. Preserve the old journal; never bless those
                        // rows, reset trades, or discard signed bytes on upgrade.
                        return Err(Error::LegacyJournal);
                    }
                }
            } else if version != 1 {
                return Err(Error::LegacyJournal);
            }
            db(dbh.pragma_update(None, "journal_mode", "WAL"))?;
            db(dbh.pragma_update(None, "synchronous", "FULL"))?;
            db(dbh.pragma_update(None, "foreign_keys", "ON"))?;
            db(dbh.pragma_update(None, "max_page_count", 32768))?;
            db(dbh.execute_batch("CREATE TABLE IF NOT EXISTS treasury_creation(operation BLOB PRIMARY KEY,trade BLOB NOT NULL UNIQUE,offer BLOB NOT NULL UNIQUE,frozen BLOB NOT NULL,blocked INTEGER NOT NULL CHECK(blocked IN (0,1))); CREATE TABLE IF NOT EXISTS bitcoin_attempt(operation BLOB NOT NULL REFERENCES treasury_creation(operation), revision INTEGER NOT NULL, intent BLOB NOT NULL, stage INTEGER NOT NULL CHECK(stage BETWEEN 0 AND 3), signed BLOB,txid BLOB,wtxid BLOB,PRIMARY KEY(operation,revision)); CREATE TABLE IF NOT EXISTS reserved_input(point BLOB PRIMARY KEY,operation BLOB NOT NULL REFERENCES treasury_creation(operation)); CREATE TABLE IF NOT EXISTS bitcoin_observation(sequence INTEGER PRIMARY KEY, operation BLOB NOT NULL,revision INTEGER NOT NULL,kind INTEGER NOT NULL,evidence BLOB NOT NULL,FOREIGN KEY(operation,revision) REFERENCES bitcoin_attempt(operation,revision));"))?;
            db(dbh.pragma_update(None, "user_version", 1))?;
            let out = Self {
                db: dbh,
                policy,
                #[cfg(feature = "trading-local-storage-candidate")]
                storage: None,
            };
            out.validate()?;
            Ok(out)
        }
        /// Admit NEW authorizations only against the current canonical head.
        /// Exact prior admissions reconcile after rotation. This is a local
        /// durable creation witness, not a global Byzantine timestamp.
        pub fn record_creation(
            &mut self,
            store: &CanonicalStore,
            frozen: &tr::FrozenTreasuryOffer,
        ) -> Result<Hash> {
            self.ensure_storage_healthy()?;
            self.record_creation_with_recheck(store, frozen, || {
                let (head, _, root) = current(store)?;
                Ok((head, root))
            })
        }
        // Private seam permits fault injection at the durable boundary in tests.
        // Only record_creation supplies this callback in non-test code.
        fn record_creation_with_recheck(
            &mut self,
            store: &CanonicalStore,
            frozen: &tr::FrozenTreasuryOffer,
            recheck: impl FnOnce() -> Result<(FinalizedAnchor, Hash)>,
        ) -> Result<Hash> {
            self.ensure_storage_healthy()?;
            self.storage_binding(frozen.creation_anchor())?;
            let raw = native(frozen.encode())?;
            let a = frozen.creation_anchor();
            let operation = digest(
                b"operation",
                &[
                    a.network.to_be_bytes().as_slice(),
                    &a.genesis,
                    &a.fingerprint,
                    &frozen.trade(),
                    &frozen.contract(),
                ]
                .concat(),
            );
            if let Some((old, blocked)) = db(self
                .db
                .query_row(
                    "SELECT frozen,blocked FROM treasury_creation WHERE operation=?1",
                    [operation.as_slice()],
                    |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
                )
                .optional())?
            {
                if old != raw {
                    return Err(Error::Duplicate);
                }
                if blocked != 0 {
                    return Err(Error::Ambiguous);
                }
                super::verify_archived_treasury_offer(store, frozen.clone(), &self.policy)
                    .map_err(|_| Error::Evidence)?;
                return Ok(operation);
            }
            let (head, _, root) = current(store)?;
            if *a != head || frozen.creation_root() != root {
                return Err(Error::Stale);
            }
            super::verify_archived_treasury_offer(store, frozen.clone(), &self.policy)
                .map_err(|_| Error::Evidence)?;
            let txn = db(self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate))?;
            let count: i64 =
                db(txn.query_row("SELECT COUNT(*) FROM treasury_creation", [], |r| r.get(0)))?;
            if count >= MAX_OPERATIONS {
                return Err(Error::Capacity);
            }
            db(txn.execute(
                "INSERT INTO treasury_creation VALUES(?1,?2,?3,?4,1)",
                params![
                    operation.as_slice(),
                    frozen.trade().as_slice(),
                    native(frozen.offer_id())?.as_slice(),
                    raw
                ],
            ))?;
            db(txn.commit())?;
            self.persist_storage()?;
            // Incomplete is durable BEFORE rechecking the canonical head. Any
            // exception, error or process exit leaves an unusable tombstone.
            // Historical verification alone may never finish this admission.
            let (after, after_root) = recheck()?;
            if after != head || after_root != root {
                return Err(Error::Stale);
            }
            let changed = db(self.db.execute(
                "UPDATE treasury_creation SET blocked=0 WHERE operation=?1 AND blocked=1",
                [operation.as_slice()],
            ))?;
            if changed != 1 {
                return Err(Error::Ambiguous);
            }
            self.persist_storage()?;
            Ok(operation)
        }
        pub fn creation_admission(&self, operation: Hash) -> Result<CreationAdmission> {
            self.ensure_storage_healthy()?;
            let blocked: i64 = db(self.db.query_row(
                "SELECT blocked FROM treasury_creation WHERE operation=?1",
                [operation.as_slice()],
                |r| r.get(0),
            ))?;
            match blocked {
                0 => Ok(CreationAdmission::Admitted),
                1 => Ok(CreationAdmission::Incomplete),
                _ => Err(Error::Corrupt),
            }
        }
        pub fn prepare(
            &mut self,
            store: &CanonicalStore,
            operation: Hash,
            funding: &tr::NativeOperation,
            terms: BitcoinTerms,
            headers: &RegtestHeaders,
            safety: &OfflineSafety,
        ) -> Result<TreasurySwapIntent> {
            self.ensure_storage_healthy()?;
            let frozen = self.creation(operation)?;
            let (a, r, l) = verify_mut_funding(store, &frozen, funding, &self.policy)?;
            let tr::NativeLockKind::Hash {
                condition,
                refund_height,
            } = l.kind
            else {
                return Err(Error::Terms);
            };
            let tr::OfferTerms::HashLinked {
                bitcoin_satoshis, ..
            } = frozen.offer().terms
            else {
                return Err(Error::Terms);
            };
            let unsigned = serialize(&build_unsigned(bitcoin_satoshis, condition, &terms)?);
            let (tip, height) = headers.tip();
            let intent = TreasurySwapIntent {
                operation,
                revision: 0,
                replaces: None,
                frozen: native(frozen.encode())?,
                funding: native(funding.encode())?,
                mut_anchor: a,
                mut_root: r,
                bitcoin_tip: tip,
                bitcoin_height: height,
                terms,
                unsigned,
                condition,
                mut_refund_height: refund_height,
            };
            intent.verify_terms()?;
            fresh(store, &intent, headers, safety, &self.policy)?;
            self.insert_attempt(&intent)?;
            Ok(intent)
        }
        fn creation(&self, operation: Hash) -> Result<tr::FrozenTreasuryOffer> {
            self.ensure_storage_healthy()?;
            let (raw, blocked) = db(self.db.query_row(
                "SELECT frozen,blocked FROM treasury_creation WHERE operation=?1",
                [operation.as_slice()],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
            ))?;
            if blocked != 0 {
                return Err(Error::Stale);
            }
            native(tr::FrozenTreasuryOffer::decode(&raw))
        }
        fn insert_attempt(&mut self, i: &TreasurySwapIntent) -> Result<()> {
            self.ensure_storage_healthy()?;
            let txn = db(self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate))?;
            let latest: Option<i64> = db(txn.query_row(
                "SELECT MAX(revision) FROM bitcoin_attempt WHERE operation=?1",
                [i.operation.as_slice()],
                |r| r.get(0),
            ))?;
            if latest.map_or(0, |n| n + 1) != i64::from(i.revision) {
                return Err(Error::Duplicate);
            }
            for c in &i.terms.inputs {
                let point = serialize(&c.previous()?.0);
                let owner: Option<Vec<u8>> = db(txn
                    .query_row(
                        "SELECT operation FROM reserved_input WHERE point=?1",
                        [&point],
                        |r| r.get(0),
                    )
                    .optional())?;
                if owner.as_ref().is_some_and(|o| o != &i.operation) {
                    return Err(Error::Duplicate);
                }
                db(txn.execute(
                    "INSERT OR IGNORE INTO reserved_input VALUES(?1,?2)",
                    params![point, i.operation.as_slice()],
                ))?;
            }
            db(txn.execute(
                "INSERT INTO bitcoin_attempt VALUES(?1,?2,?3,0,NULL,NULL,NULL)",
                params![i.operation.as_slice(), i.revision, i.encode()?],
            ))?;
            db(txn.commit())?;
            self.persist_storage()?;
            Ok(())
        }
        pub fn reconcile(
            &self,
            operation: Hash,
            revision: u32,
        ) -> Result<(TreasurySwapIntent, Stage, Option<Vec<u8>>)> {
            self.ensure_storage_healthy()?;
            let(raw,stage,signed)=db(self.db.query_row("SELECT intent,stage,signed FROM bitcoin_attempt WHERE operation=?1 AND revision=?2",params![operation.as_slice(),revision],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,i64>(1)?,r.get::<_,Option<Vec<u8>>>(2)?))))?;
            let i = TreasurySwapIntent::decode(&raw)?;
            if i.operation != operation
                || i.revision != revision
                || native(self.creation(operation)?.encode())? != i.frozen
            {
                return Err(Error::Corrupt);
            }
            Ok((i, Stage::decode(stage)?, signed))
        }
        /// Persist dispatch BEFORE the external signer sees a request. A crash
        /// after this commit can only reconcile the same signer OperationID.
        pub fn begin_sign(
            &mut self,
            store: &CanonicalStore,
            operation: Hash,
            revision: u32,
            authorization: &SignerAuthorization,
            headers: &RegtestHeaders,
            safety: &OfflineSafety,
        ) -> Result<SignRequest> {
            self.ensure_storage_healthy()?;
            let (i, stage, _) = self.reconcile(operation, revision)?;
            if stage != Stage::Prepared {
                return Err(Error::Ambiguous);
            }
            authorization.verify(&i)?;
            fresh(store, &i, headers, safety, &self.policy)?;
            if matches!(
                self.funding_status(operation, headers, safety)?,
                FundingStatus::Included { .. }
                    | FundingStatus::FundingConfirmed { .. }
                    | FundingStatus::Conflicted { .. }
            ) {
                return Err(Error::State);
            }
            if self.latest(operation)? != revision {
                return Err(Error::Replacement);
            }
            let request = SignRequest {
                operation,
                revision,
                intent: i.encode()?,
                psbt: i.psbt()?,
            };
            let changed = db(self.db.execute(
                "UPDATE bitcoin_attempt SET stage=1 WHERE operation=?1 AND revision=?2 AND stage=0",
                params![operation.as_slice(), revision],
            ))?;
            if changed != 1 {
                return Err(Error::Ambiguous);
            }
            self.persist_storage()?;
            Ok(request)
        }
        /// Accept a cached response for the exact dispatched operation only.
        /// Repeated identical responses are harmless; changed bytes reject.
        pub fn record_signed(
            &mut self,
            operation: Hash,
            revision: u32,
            raw: &[u8],
        ) -> Result<Txid> {
            self.ensure_storage_healthy()?;
            let (i, stage, prior) = self.reconcile(operation, revision)?;
            let (txid, wtxid) = i.verify_signed(raw)?;
            if let Some(old) = prior {
                if old == raw {
                    return Ok(txid);
                }
                return Err(Error::Duplicate);
            }
            if stage != Stage::SignDispatched {
                return Err(Error::State);
            }
            let changed=db(self.db.execute("UPDATE bitcoin_attempt SET stage=2,signed=?3,txid=?4,wtxid=?5 WHERE operation=?1 AND revision=?2 AND stage=1 AND signed IS NULL",params![operation.as_slice(),revision,raw,txid.to_byte_array().as_slice(),wtxid.to_byte_array().as_slice()]))?;
            if changed != 1 {
                return Err(Error::Ambiguous);
            }
            self.persist_storage()?;
            Ok(txid)
        }
        pub fn broadcast_request(
            &mut self,
            store: &CanonicalStore,
            operation: Hash,
            revision: u32,
            headers: &RegtestHeaders,
            safety: &OfflineSafety,
        ) -> Result<BroadcastRequest> {
            self.ensure_storage_healthy()?;
            let (i, s, raw) = self.reconcile(operation, revision)?;
            if s != Stage::Signed {
                return Err(Error::Ambiguous);
            }
            if self.latest(operation)? != revision {
                return Err(Error::Replacement);
            }
            let raw = raw.ok_or(Error::Corrupt)?;
            let (txid, _) = i.verify_signed(&raw)?;
            fresh(store, &i, headers, safety, &self.policy)?;
            // Any observation of delivery needs reconciliation, not a first
            // dispatch permit. Reorgs also freeze new effects pending recovery.
            if self.funding_status(operation, headers, safety)? != FundingStatus::Unknown {
                return Err(Error::State);
            }
            let changed = db(self.db.execute(
                "UPDATE bitcoin_attempt SET stage=3 WHERE operation=?1 AND revision=?2 AND stage=2",
                params![operation.as_slice(), revision],
            ))?;
            if changed != 1 {
                return Err(Error::Ambiguous);
            }
            self.persist_storage()?;
            Ok(BroadcastRequest {
                operation,
                revision,
                txid,
                signed_bytes: raw,
            })
        }
        /// Available even if funding expired or a store/RPC is unavailable.
        /// Reconcile these exact identifiers externally; no money-moving permit
        /// is returned. A later rebroadcast policy must be reviewed separately.
        pub fn reconcile_broadcast(
            &self,
            operation: Hash,
            revision: u32,
        ) -> Result<BroadcastReconciliation> {
            self.ensure_storage_healthy()?;
            let (i, stage, raw) = self.reconcile(operation, revision)?;
            if stage != Stage::BroadcastPending {
                return Err(Error::State);
            }
            let signed_bytes = raw.ok_or(Error::Corrupt)?;
            let (txid, _) = i.verify_signed(&signed_bytes)?;
            Ok(BroadcastReconciliation {
                operation,
                revision,
                intent_hash: i.intent_hash()?,
                txid,
                inputs: i
                    .terms
                    .inputs
                    .iter()
                    .map(|c| c.previous().map(|p| p.0))
                    .collect::<Result<_>>()?,
                signed_bytes,
            })
        }
        fn latest(&self, op: Hash) -> Result<u32> {
            self.ensure_storage_healthy()?;
            db(self.db.query_row(
                "SELECT MAX(revision) FROM bitcoin_attempt WHERE operation=?1",
                [op.as_slice()],
                |r| r.get(0),
            ))
        }
        /// Explicit fee-only replacement. Same inputs, refund/claim script,
        /// quantity, MUT consideration, frozen destination and OperationID.
        /// No ambiguous/lost signature can be replaced automatically.
        pub fn prepare_replacement(
            &mut self,
            store: &CanonicalStore,
            operation: Hash,
            new_fee: u64,
            headers: &RegtestHeaders,
            safety: &OfflineSafety,
        ) -> Result<TreasurySwapIntent> {
            self.ensure_storage_healthy()?;
            if matches!(
                self.funding_status(operation, headers, safety)?,
                FundingStatus::Included { .. }
                    | FundingStatus::FundingConfirmed { .. }
                    | FundingStatus::Conflicted { .. }
            ) {
                return Err(Error::State);
            }
            let revision = self.latest(operation)?;
            let (mut i, s, raw) = self.reconcile(operation, revision)?;
            if !matches!(s, Stage::Signed | Stage::BroadcastPending) {
                return Err(Error::Ambiguous);
            }
            let old = raw.ok_or(Error::Corrupt)?;
            let (previous, _) = i.verify_signed(&old)?;
            if new_fee <= i.terms.fee_satoshis || new_fee > i.terms.fee_limit_satoshis {
                return Err(Error::Fee);
            }
            i.revision = revision.checked_add(1).ok_or(Error::Bounds)?;
            i.replaces = Some(previous);
            i.terms.fee_satoshis = new_fee;
            let tr::OfferTerms::HashLinked {
                bitcoin_satoshis, ..
            } = i.frozen_offer()?.offer().terms
            else {
                return Err(Error::Terms);
            };
            i.unsigned = serialize(&build_unsigned(bitcoin_satoshis, i.condition, &i.terms)?);
            i.verify_terms()?;
            fresh(store, &i, headers, safety, &self.policy)?;
            self.insert_attempt(&i)?;
            Ok(i)
        }
        fn validate(&self) -> Result<()> {
            self.ensure_storage_healthy()?;
            let integrity: String = db(self.db.query_row("PRAGMA quick_check", [], |r| r.get(0)))?;
            if integrity != "ok" {
                return Err(Error::Corrupt);
            }
            let foreign_violation: bool = db(self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
                [],
                |r| r.get(0),
            ))?;
            if foreign_violation {
                return Err(Error::Corrupt);
            }
            for (table, max_rows, invalid) in [
                (
                    "treasury_creation",
                    MAX_OPERATIONS,
                    "length(operation)!=32 OR length(trade)!=32 OR length(offer)!=32 OR length(frozen)>8192 OR blocked NOT IN (0,1)",
                ),
                (
                    "bitcoin_attempt",
                    MAX_OPERATIONS * MAX_REVISIONS as i64,
                    "length(intent)>131072 OR length(signed)>32768 OR length(txid)!=32 OR length(wtxid)!=32 OR revision<0 OR revision>=16",
                ),
                (
                    "reserved_input",
                    MAX_OPERATIONS * MAX_INPUTS as i64,
                    "length(point)!=36 OR length(operation)!=32",
                ),
                (
                    "bitcoin_observation",
                    MAX_OPERATIONS * MAX_REVISIONS as i64 * 16,
                    "kind<0 OR kind>2 OR length(evidence)>33808",
                ),
            ] {
                // SQL identifiers/predicates are fixed literals above, never
                // caller-supplied. Check lengths before allocating blob values.
                let count: i64 =
                    db(self
                        .db
                        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)))?;
                let invalid: bool = db(self.db.query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {invalid})"),
                    [],
                    |r| r.get(0),
                ))?;
                if count > max_rows {
                    return Err(Error::Capacity);
                }
                if invalid {
                    return Err(Error::Corrupt);
                }
            }
            let mut creation = db(self
                .db
                .prepare("SELECT operation,trade,offer,frozen FROM treasury_creation"))?;
            let rows = db(creation.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            }))?;
            for row in rows {
                let (op, trade, offer, raw) = db(row)?;
                let f = native(tr::FrozenTreasuryOffer::decode(&raw))?;
                self.storage_binding(f.creation_anchor())?;
                let a = f.creation_anchor();
                let expected = digest(
                    b"operation",
                    &[
                        a.network.to_be_bytes().as_slice(),
                        &a.genesis,
                        &a.fingerprint,
                        &f.trade(),
                        &f.contract(),
                    ]
                    .concat(),
                );
                if op != expected || trade != f.trade() || offer != native(f.offer_id())? {
                    return Err(Error::Corrupt);
                }
            }
            let mut statement=db(self.db.prepare("SELECT operation,revision,intent,stage,signed,txid,wtxid FROM bitcoin_attempt ORDER BY operation,revision"))?;
            let rows = db(statement.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                    r.get::<_, Option<Vec<u8>>>(5)?,
                    r.get::<_, Option<Vec<u8>>>(6)?,
                ))
            }))?;
            let mut previous: BTreeMap<Hash, (TreasurySwapIntent, Option<Txid>)> = BTreeMap::new();
            for row in rows {
                let (op, rev, raw, s, signed, tid, wid) = db(row)?;
                let i = TreasurySwapIntent::decode(&raw)?;
                let stage = Stage::decode(s)?;
                if op != i.operation
                    || rev != i.revision
                    || i.frozen != native(self.creation(i.operation)?.encode())?
                {
                    return Err(Error::Corrupt);
                }
                if let Some((old, id)) = previous.get(&i.operation) {
                    i.replacement_of(old, id.ok_or(Error::Corrupt)?)?;
                } else if rev != 0 || i.replaces.is_some() {
                    return Err(Error::Corrupt);
                }
                let id = if let Some(raw) = signed {
                    if !matches!(stage, Stage::Signed | Stage::BroadcastPending) {
                        return Err(Error::Corrupt);
                    }
                    let (t, w) = i.verify_signed(&raw)?;
                    if tid.as_deref() != Some(t.as_byte_array())
                        || wid.as_deref() != Some(w.as_byte_array())
                    {
                        return Err(Error::Corrupt);
                    }
                    Some(t)
                } else {
                    if !matches!(stage, Stage::Prepared | Stage::SignDispatched)
                        || tid.is_some()
                        || wid.is_some()
                    {
                        return Err(Error::Corrupt);
                    }
                    None
                };
                for c in &i.terms.inputs {
                    let owner: Vec<u8> = db(self.db.query_row(
                        "SELECT operation FROM reserved_input WHERE point=?1",
                        [serialize(&c.previous()?.0)],
                        |r| r.get(0),
                    ))?;
                    if owner != i.operation {
                        return Err(Error::Corrupt);
                    }
                }
                previous.insert(i.operation, (i, id));
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum FundingStatus {
        Unknown,
        MempoolUnconfirmed,
        Included { txid: Txid, depth: u32 },
        FundingConfirmed { txid: Txid, depth: u32 },
        Reorged { txid: Txid },
        Conflicted { txid: Txid },
    }
    fn proof_encode(p: &Inclusion) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .bytes(&p.block.to_byte_array())
            .unwrap()
            .u32(p.index)
            .unwrap()
            .u32(p.total_transactions)
            .unwrap()
            .array(p.branch.len() as u64)
            .unwrap();
        for h in &p.branch {
            e.bytes(h).unwrap();
        }
        e.into_writer()
    }
    fn proof_decode(raw: &[u8]) -> Result<Inclusion> {
        if raw.len() > 1024 {
            return Err(Error::Bounds);
        }
        let mut d = Decoder::new(raw);
        array(&mut d, 4)?;
        let block = BlockHash::from_byte_array(fixed(&mut d)?);
        let index = d.u32().map_err(|_| Error::Codec)?;
        let total_transactions = d.u32().map_err(|_| Error::Codec)?;
        let n = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
        if n > 20 {
            return Err(Error::Bounds);
        }
        let mut branch = Vec::new();
        for _ in 0..n {
            branch.push(fixed(&mut d)?);
        }
        let p = Inclusion {
            block,
            index,
            total_transactions,
            branch,
        };
        if d.position() != raw.len() || proof_encode(&p) != raw {
            return Err(Error::Codec);
        }
        Ok(p)
    }
    impl TreasurySwapIntent {
        fn replacement_of(&self, old: &Self, previous: Txid) -> Result<()> {
            let mut expected = old.clone();
            expected.revision = old.revision.checked_add(1).ok_or(Error::Bounds)?;
            expected.replaces = Some(previous);
            expected.terms.fee_satoshis = self.terms.fee_satoshis;
            let tr::OfferTerms::HashLinked {
                bitcoin_satoshis, ..
            } = old.frozen_offer()?.offer().terms
            else {
                return Err(Error::Terms);
            };
            expected.unsigned = serialize(&build_unsigned(
                bitcoin_satoshis,
                old.condition,
                &expected.terms,
            )?);
            if *self != expected || self.terms.fee_satoshis <= old.terms.fee_satoshis {
                return Err(Error::Replacement);
            }
            Ok(())
        }
    }
    impl OperationJournal {
        fn append_observation(
            &mut self,
            operation: Hash,
            revision: u32,
            kind: u8,
            evidence: &[u8],
        ) -> Result<()> {
            self.ensure_storage_healthy()?;
            let txn = db(self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate))?;
            let count: i64 =
                db(txn.query_row("SELECT COUNT(*) FROM bitcoin_observation", [], |r| r.get(0)))?;
            if count >= MAX_OPERATIONS * MAX_REVISIONS as i64 * 16 {
                return Err(Error::Capacity);
            }
            let duplicate:bool=db(txn.query_row("SELECT EXISTS(SELECT 1 FROM bitcoin_observation WHERE operation=?1 AND revision=?2 AND kind=?3 AND evidence=?4)",params![operation.as_slice(),revision,kind,evidence],|r|r.get(0)))?;
            if !duplicate {
                db(txn.execute("INSERT INTO bitcoin_observation(operation,revision,kind,evidence) VALUES(?1,?2,?3,?4)",params![operation.as_slice(),revision,kind,evidence]))?;
            }
            db(txn.commit())?;
            self.persist_storage()?;
            Ok(())
        }
        /// A mempool hint conveys no finality. Exact bytes and signatures still
        /// verify; peer/RPC assertions never become settlement authority.
        pub fn observe_mempool_hint(
            &mut self,
            operation: Hash,
            revision: u32,
            raw: &[u8],
        ) -> Result<()> {
            self.ensure_storage_healthy()?;
            let (i, s, stored) = self.reconcile(operation, revision)?;
            if !matches!(s, Stage::Signed | Stage::BroadcastPending)
                || stored.as_deref() != Some(raw)
            {
                return Err(Error::Evidence);
            }
            i.verify_signed(raw)?;
            self.append_observation(operation, revision, 0, &[])
        }
        pub fn observe_inclusion(
            &mut self,
            operation: Hash,
            revision: u32,
            proof: &Inclusion,
            headers: &RegtestHeaders,
        ) -> Result<()> {
            self.ensure_storage_healthy()?;
            let (i, s, stored) = self.reconcile(operation, revision)?;
            if !matches!(s, Stage::Signed | Stage::BroadcastPending) {
                return Err(Error::Evidence);
            }
            let (tid, _) = i.verify_signed(&stored.ok_or(Error::Evidence)?)?;
            headers.verify_inclusion(proof, tid)?;
            self.append_observation(operation, revision, 1, &proof_encode(proof))
        }
        /// Conflicting spend evidence is SPV under the same valid-chain
        /// assumption, never an RPC boolean. It freezes rather than pays.
        pub fn observe_conflict(
            &mut self,
            operation: Hash,
            revision: u32,
            raw: &[u8],
            proof: &Inclusion,
            headers: &RegtestHeaders,
        ) -> Result<()> {
            self.ensure_storage_healthy()?;
            let (i, _, _) = self.reconcile(operation, revision)?;
            let other = tx(raw, MAX_PREVIOUS_TX)?;
            let original = tx(&i.unsigned, MAX_PREVIOUS_TX)?;
            if other.compute_txid() == original.compute_txid()
                || !other.input.iter().any(|n| {
                    original
                        .input
                        .iter()
                        .any(|o| o.previous_output == n.previous_output)
                })
            {
                return Err(Error::Evidence);
            }
            // An authorized linked replacement is tracked as its own revision,
            // not falsely classified as an unrelated conflicting operation.
            let known: bool = db(self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM bitcoin_attempt WHERE operation=?1 AND txid=?2)",
                params![
                    operation.as_slice(),
                    other.compute_txid().to_byte_array().as_slice()
                ],
                |r| r.get(0),
            ))?;
            if known {
                return Err(Error::Replacement);
            }
            headers.verify_inclusion(proof, other.compute_txid())?;
            let mut e = Encoder::new(Vec::new());
            e.array(2)
                .unwrap()
                .bytes(raw)
                .unwrap()
                .bytes(&proof_encode(proof))
                .unwrap();
            self.append_observation(operation, revision, 2, &e.into_writer())
        }
        /// Derive status against CURRENT best-chain evidence on every query.
        /// Reopening the journal never trusts a persisted "finalized" flag.
        /// Funding confirmation alone is never Treasury conversion COMPLETE.
        pub fn funding_status(
            &self,
            operation: Hash,
            headers: &RegtestHeaders,
            safety: &OfflineSafety,
        ) -> Result<FundingStatus> {
            self.ensure_storage_healthy()?;
            let mut s=db(self.db.prepare("SELECT revision,kind,evidence FROM bitcoin_observation WHERE operation=?1 ORDER BY sequence DESC"))?;
            let rows = db(s.query_map([operation.as_slice()], |r| {
                Ok((
                    r.get::<_, u32>(0)?,
                    r.get::<_, u8>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            }))?;
            let mut hint = false;
            let mut reorg = None;
            let mut included = None;
            let mut conflict = None;
            for row in rows {
                let (rev, kind, raw) = db(row)?;
                let (i, _, signed) = self.reconcile(operation, rev)?;
                match kind {
                    0 => {
                        if !raw.is_empty() {
                            return Err(Error::Corrupt);
                        }
                        hint = true;
                    }
                    1 => {
                        let p = proof_decode(&raw)?;
                        let (tid, _) = i.verify_signed(&signed.ok_or(Error::Corrupt)?)?;
                        match headers.verify_inclusion(&p, tid) {
                            Ok(depth) => {
                                if included.as_ref().is_some_and(|(old, _)| *old != tid) {
                                    return Err(Error::Evidence);
                                }
                                included = Some((tid, depth));
                            }
                            Err(Error::Stale) => {
                                reorg = Some(tid);
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    2 => {
                        let mut d = Decoder::new(&raw);
                        array(&mut d, 2)?;
                        let transaction = tx(bytes(&mut d)?, MAX_PREVIOUS_TX)?;
                        let p = proof_decode(bytes(&mut d)?)?;
                        if d.position() != raw.len() {
                            return Err(Error::Codec);
                        }
                        let original = tx(&i.unsigned, MAX_PREVIOUS_TX)?;
                        if !transaction.input.iter().any(|n| {
                            original
                                .input
                                .iter()
                                .any(|o| o.previous_output == n.previous_output)
                        }) {
                            return Err(Error::Corrupt);
                        }
                        match headers.verify_inclusion(&p, transaction.compute_txid()) {
                            Ok(_) => conflict = Some(transaction.compute_txid()),
                            Err(Error::Stale) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    _ => return Err(Error::Corrupt),
                }
            }
            if let Some(txid) = conflict {
                return Ok(FundingStatus::Conflicted { txid });
            }
            if let Some((txid, depth)) = included {
                return Ok(if depth >= safety.confirmations {
                    FundingStatus::FundingConfirmed { txid, depth }
                } else {
                    FundingStatus::Included { txid, depth }
                });
            }
            if let Some(txid) = reorg {
                return Ok(FundingStatus::Reorged { txid });
            }
            Ok(if hint {
                FundingStatus::MempoolUnconfirmed
            } else {
                FundingStatus::Unknown
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum SpendPath {
        Claim { preimage: Hash },
        Refund,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct VerifiedLockSpend {
        pub txid: Txid,
        pub path: SpendPath,
        pub fee_satoshis: u64,
    }
    impl TreasurySwapIntent {
        /// Narrow independent verification of this exact reviewed script
        /// template. This is not a general Bitcoin Script interpreter. Witness
        /// preimages are not authenticated by a TXID-only inclusion proof;
        /// require this signature/script check and independently valid chain.
        pub fn verify_lock_spend(
            &self,
            funding_txid: Txid,
            raw: &[u8],
        ) -> Result<VerifiedLockSpend> {
            self.verify_terms()?;
            if funding_txid != self.expected_txid()? {
                return Err(Error::Context);
            }
            let t = tx(raw, MAX_PREVIOUS_TX)?;
            let funded = tx(&self.unsigned, MAX_PREVIOUS_TX)?;
            if t.version != bitcoin::transaction::Version::TWO
                || t.input.len() != 1
                || t.output.len() != 1
                || t.input[0].previous_output
                    != (OutPoint {
                        txid: funding_txid,
                        vout: 0,
                    })
                || !t.input[0].script_sig.is_empty()
            {
                return Err(Error::Input);
            }
            let witness: Vec<_> = t.input[0].witness.iter().collect();
            let script = lock_script(self.condition, &self.terms)?;
            let (path, pubkey) = if witness.len() == 4 && witness[2] == [1] {
                let preimage: Hash = witness[1].try_into().map_err(|_| Error::Terms)?;
                if tr::preimage_hash(&preimage) != self.condition {
                    return Err(Error::Terms);
                }
                (SpendPath::Claim { preimage }, self.terms.recipient)
            } else if witness.len() == 3 && witness[1].is_empty() {
                if !t.lock_time.is_block_height()
                    || t.lock_time.to_consensus_u32() < self.terms.refund_height
                    || t.input[0].sequence == bitcoin::Sequence::MAX
                {
                    return Err(Error::Deadline);
                }
                (SpendPath::Refund, self.terms.refund)
            } else {
                return Err(Error::Signature);
            };
            if witness.last().copied() != Some(script.as_bytes()) {
                return Err(Error::Signature);
            }
            let key = bitcoin::PublicKey::new(
                PublicKey::from_slice(&pubkey).map_err(|_| Error::Signature)?,
            );
            if t.output[0].script_pubkey
                != ScriptBuf::new_p2wpkh(&key.wpubkey_hash().map_err(|_| Error::Signature)?)
                || t.output[0].value < t.output[0].script_pubkey.minimal_non_dust()
            {
                return Err(Error::Output);
            }
            let fee = funded.output[0]
                .value
                .to_sat()
                .checked_sub(t.output[0].value.to_sat())
                .ok_or(Error::Fee)?;
            if fee > self.terms.fee_limit_satoshis {
                return Err(Error::Fee);
            }
            let sig =
                bitcoin::ecdsa::Signature::from_slice(witness[0]).map_err(|_| Error::Signature)?;
            let mut low = sig.signature;
            low.normalize_s();
            if sig.sighash_type != EcdsaSighashType::All
                || low != sig.signature
                || sig.to_vec() != witness[0]
            {
                return Err(Error::Signature);
            }
            let hash = SighashCache::new(&t)
                .p2wsh_signature_hash(0, &script, funded.output[0].value, EcdsaSighashType::All)
                .map_err(|_| Error::Signature)?;
            Secp256k1::verification_only()
                .verify_ecdsa(
                    &Message::from_digest(hash.to_byte_array()),
                    &sig.signature,
                    &key.inner,
                )
                .map_err(|_| Error::Signature)?;
            Ok(VerifiedLockSpend {
                txid: t.compute_txid(),
                path,
                fee_satoshis: fee,
            })
        }
        pub fn verify_lock_spend_inclusion(
            &self,
            funding_txid: Txid,
            raw: &[u8],
            proof: &Inclusion,
            headers: &RegtestHeaders,
        ) -> Result<(VerifiedLockSpend, u32)> {
            let spend = self.verify_lock_spend(funding_txid, raw)?;
            let depth = headers.verify_inclusion(proof, spend.txid)?;
            let t = tx(raw, MAX_PREVIOUS_TX)?;
            if t.input[0].sequence != bitcoin::Sequence::MAX
                && (!t.lock_time.is_block_height()
                    || t.lock_time.to_consensus_u32() >= headers.entries[&proof.block].height)
            {
                return Err(Error::Deadline);
            }
            Ok((spend, depth))
        }
    }

    /// Offline evidence and recovery. Every result remains conditional on a
    /// valid Bitcoin chain; this is NOT a replacement for Bitcoin Core consensus
    /// validation. No result grants a signing, broadcast or production permit.
    pub mod recovery {
        use super::*;
        const MAX_BLOCK: usize = 4_000_000;
        const MAX_ARCHIVE: usize = 64 * 1024 * 1024;
        const MAX_BLOCKS: usize = 256;
        const RECOVERY_NS: &[u8] = b"MUTINY-OFFLINE-RECOVERY-EVIDENCE-V1";
        fn fault(_point: &str) {
            #[cfg(test)]
            if std::env::var("RECOVERY_CRASH_PHASE").ok().as_deref() == Some(_point) {
                std::process::exit(86);
            }
        }

        /// Complete transaction and witness commitment validation, plus cheap
        /// structural checks. Script execution, subsidy, deployments, relative
        /// locks and global UTXO validity are deliberately not claimed here.
        fn block(raw: &[u8], headers: &RegtestHeaders) -> Result<bitcoin::Block> {
            if raw.len() < 81 || raw.len() > MAX_BLOCK {
                return Err(Error::Bounds);
            }
            let b: bitcoin::Block = deserialize(raw).map_err(|_| Error::Codec)?;
            if serialize(&b) != raw {
                return Err(Error::Codec);
            }
            if headers
                .entries
                .get(&b.block_hash())
                .is_none_or(|h| h.header != b.header)
                || b.txdata.is_empty()
                || b.weight().to_wu() > 4_000_000
                || !b.txdata[0].is_coinbase()
                || !b.check_merkle_root()
                || !b.check_witness_commitment()
            {
                return Err(Error::Evidence);
            }
            let mut ids = BTreeSet::new();
            let mut inputs = BTreeSet::new();
            for (index, t) in b.txdata.iter().enumerate() {
                if !ids.insert(t.compute_txid())
                    || t.input.is_empty()
                    || t.output.is_empty()
                    || (index != 0 && t.is_coinbase())
                {
                    return Err(Error::Evidence);
                }
                let mut total = 0u64;
                for o in &t.output {
                    total = total.checked_add(o.value.to_sat()).ok_or(Error::Bounds)?;
                    if total > Amount::MAX_MONEY.to_sat() {
                        return Err(Error::Output);
                    }
                }
                if index != 0 {
                    for i in &t.input {
                        if i.previous_output.is_null() || !inputs.insert(i.previous_output) {
                            return Err(Error::Input);
                        }
                    }
                }
            }
            Ok(b)
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum PrevoutState {
            UnspentUnderSpv { at_tip: BlockHash, depth: u32 },
            Spent { transaction: Txid, block: BlockHash },
        }
        /// Bounded durable complete-block cache. Gaps are errors, never evidence
        /// of unspentness. Old branches remain available after a reorg. No RPC
        /// boolean or peer-supplied "validated" flag is accepted.
        pub struct BlockArchive {
            db: Connection,
            #[cfg(feature = "trading-local-storage-candidate")]
            storage: Option<sealed_storage::SnapshotStore>,
        }
        impl BlockArchive {
            fn ensure_storage_healthy(&self) -> Result<()> {
                #[cfg(feature = "trading-local-storage-candidate")]
                if let Some(s) = &self.storage {
                    s.healthy().map_err(|_| Error::Store)?;
                }
                Ok(())
            }
            fn persist_storage(&mut self) -> Result<()> {
                #[cfg(feature = "trading-local-storage-candidate")]
                if let Some(s) = &mut self.storage {
                    s.persist(&self.db).map_err(|_| Error::Store)?;
                }
                Ok(())
            }

            #[cfg(feature = "trading-local-storage-candidate")]
            pub fn storage_checkpoint(&self) -> Result<sealed_storage::DurableCheckpoint> {
                self.ensure_storage_healthy()?;
                self.storage
                    .as_ref()
                    .ok_or(Error::State)?
                    .checkpoint()
                    .map_err(|_| Error::Store)
            }

            #[cfg(feature = "trading-local-storage-candidate")]
            pub fn create_encrypted(
                paths: &sealed_storage::Paths,
                key: std::sync::Arc<StorageKey>,
                context: StorageContext,
                policy: CandidatePolicy,
            ) -> Result<Self> {
                Self::create_encrypted_kind(
                    paths,
                    key,
                    context,
                    policy,
                    sealed_storage::JournalKind::Blocks,
                )
            }
            #[cfg(feature = "trading-local-storage-candidate")]
            fn create_encrypted_kind(
                paths: &sealed_storage::Paths,
                key: std::sync::Arc<StorageKey>,
                context: StorageContext,
                policy: CandidatePolicy,
                kind: sealed_storage::JournalKind,
            ) -> Result<Self> {
                native(policy.check())?;
                let mut out = Self::open(Path::new(":memory:"))?;
                sealed_storage::memory_hardening(&out.db).map_err(|_| Error::Store)?;
                out.storage = Some(
                    sealed_storage::SnapshotStore::create(
                        paths, key, &context, kind, &out.db, &policy,
                    )
                    .map_err(|_| Error::Store)?,
                );
                Ok(out)
            }
            #[cfg(feature = "trading-local-storage-candidate")]
            pub fn open_encrypted(
                paths: &sealed_storage::Paths,
                key: std::sync::Arc<StorageKey>,
                context: StorageContext,
                minimum: sealed_storage::DurableCheckpoint,
                policy: CandidatePolicy,
            ) -> Result<Self> {
                Self::open_encrypted_kind(
                    paths,
                    key,
                    context,
                    minimum,
                    policy,
                    sealed_storage::JournalKind::Blocks,
                )
            }
            #[cfg(feature = "trading-local-storage-candidate")]
            fn open_encrypted_kind(
                paths: &sealed_storage::Paths,
                key: std::sync::Arc<StorageKey>,
                context: StorageContext,
                minimum: sealed_storage::DurableCheckpoint,
                policy: CandidatePolicy,
                kind: sealed_storage::JournalKind,
            ) -> Result<Self> {
                native(policy.check())?;
                let mut out = Self::open(Path::new(":memory:"))?;
                out.storage = Some(
                    sealed_storage::SnapshotStore::open(
                        paths,
                        key,
                        &context,
                        kind,
                        minimum,
                        &mut out.db,
                        &policy,
                    )
                    .map_err(|_| Error::Store)?,
                );
                let (count, size): (i64, i64) = db(out.db.query_row(
                    "SELECT count(*),coalesce(sum(length(raw)),0) FROM recovery_block",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                ))?;
                if count > MAX_BLOCKS as i64 || size > MAX_ARCHIVE as i64 {
                    return Err(Error::Corrupt);
                };
                Ok(out)
            }

            pub fn open(path: &Path) -> Result<Self> {
                let c = db(Connection::open(path))?;
                db(c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF; CREATE TABLE IF NOT EXISTS recovery_block(id BLOB PRIMARY KEY CHECK(length(id)=32), raw BLOB NOT NULL CHECK(length(raw)<=4000000));"))?;
                let good: String = db(c.query_row("PRAGMA integrity_check", [], |r| r.get(0)))?;
                let (count, size): (i64, i64) = db(c.query_row(
                    "SELECT count(*),coalesce(sum(length(raw)),0) FROM recovery_block",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                ))?;
                if good != "ok" || count > MAX_BLOCKS as i64 || size > MAX_ARCHIVE as i64 {
                    return Err(Error::Corrupt);
                }
                Ok(Self {
                    db: c,
                    #[cfg(feature = "trading-local-storage-candidate")]
                    storage: None,
                })
            }
            pub fn insert(&mut self, raw: &[u8], headers: &RegtestHeaders) -> Result<BlockHash> {
                self.ensure_storage_healthy()?;
                let b = block(raw, headers)?;
                let id = b.block_hash();
                let txn = db(self
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate))?;
                let old: Option<Vec<u8>> = db(txn
                    .query_row(
                        "SELECT raw FROM recovery_block WHERE id=?1",
                        [id.to_byte_array().as_slice()],
                        |r| r.get(0),
                    )
                    .optional())?;
                if let Some(old) = old {
                    return if old == raw {
                        Ok(id)
                    } else {
                        Err(Error::Corrupt)
                    };
                }
                let (count, size): (i64, i64) = db(txn.query_row(
                    "SELECT count(*),coalesce(sum(length(raw)),0) FROM recovery_block",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                ))?;
                if count >= MAX_BLOCKS as i64 || size + raw.len() as i64 > MAX_ARCHIVE as i64 {
                    return Err(Error::Capacity);
                }
                db(txn.execute(
                    "INSERT INTO recovery_block(id,raw) VALUES(?1,?2)",
                    params![id.to_byte_array().as_slice(), raw],
                ))?;
                fault("block_before_commit");
                db(txn.commit())?;
                self.persist_storage()?;
                fault("block_after_commit");
                Ok(id)
            }
            pub fn get(&self, id: BlockHash, headers: &RegtestHeaders) -> Result<bitcoin::Block> {
                self.ensure_storage_healthy()?;
                let raw: Vec<u8> = db(self
                    .db
                    .query_row(
                        "SELECT raw FROM recovery_block WHERE id=?1",
                        [id.to_byte_array().as_slice()],
                        |r| r.get(0),
                    )
                    .optional())?
                .ok_or(Error::Evidence)?;
                let b = block(&raw, headers)?;
                if b.block_hash() != id {
                    return Err(Error::Corrupt);
                }
                Ok(b)
            }
            pub fn included(
                &self,
                id: BlockHash,
                transaction: Txid,
                headers: &RegtestHeaders,
            ) -> Result<(Transaction, u32)> {
                self.ensure_storage_healthy()?;
                let depth = headers.depth(id)?;
                let b = self.get(id, headers)?;
                let t = b
                    .txdata
                    .into_iter()
                    .find(|t| t.compute_txid() == transaction)
                    .ok_or(Error::Evidence)?;
                Ok((t, depth))
            }
            /// Scan ALL blocks from creation through current tip, including
            /// later transactions in the creation block. Missing data is closed.
            pub fn prevout(
                &self,
                raw_previous: &[u8],
                vout: u32,
                created: BlockHash,
                headers: &RegtestHeaders,
            ) -> Result<PrevoutState> {
                self.ensure_storage_healthy()?;
                let previous = tx(raw_previous, MAX_PREVIOUS_TX)?;
                if previous.output.get(vout as usize).is_none() {
                    return Err(Error::Input);
                }
                let depth = headers.depth(created)?;
                if headers.entries[&created].height == 0 {
                    return Err(Error::Input);
                }
                let (actual, _) = self.included(created, previous.compute_txid(), headers)?;
                if serialize(&actual) != raw_previous {
                    return Err(Error::Evidence);
                }
                // Eligibility for the NEXT block: next_height - creation >=100.
                if actual.is_coinbase() && depth < 100 {
                    return Err(Error::Deadline);
                }
                let point = OutPoint {
                    txid: previous.compute_txid(),
                    vout,
                };
                let mut ids = Vec::new();
                let mut id = headers.best;
                loop {
                    if ids.len() >= MAX_BLOCKS {
                        return Err(Error::Capacity);
                    }
                    ids.push(id);
                    if id == created {
                        break;
                    }
                    id = headers
                        .entries
                        .get(&id)
                        .ok_or(Error::Evidence)?
                        .header
                        .prev_blockhash;
                }
                let mut seen = false;
                let mut spent = None;
                for id in ids.into_iter().rev() {
                    for t in self.get(id, headers)?.txdata {
                        if t.compute_txid() == point.txid {
                            if seen {
                                return Err(Error::Evidence);
                            }
                            seen = true;
                        } else if t.input.iter().any(|i| i.previous_output == point) {
                            if !seen || spent.is_some() {
                                return Err(Error::Evidence);
                            }
                            spent = Some(PrevoutState::Spent {
                                transaction: t.compute_txid(),
                                block: id,
                            });
                        }
                    }
                }
                Ok(spent.unwrap_or(PrevoutState::UnspentUnderSpv {
                    at_tip: headers.best,
                    depth,
                }))
            }
            pub fn verify_intent_inputs(
                &self,
                intent: &TreasurySwapIntent,
                creation_blocks: &[BlockHash],
                headers: &RegtestHeaders,
                safety: &OfflineSafety,
            ) -> Result<()> {
                self.ensure_storage_healthy()?;
                intent.verify_terms()?;
                if creation_blocks.len() != intent.terms.inputs.len() {
                    return Err(Error::Input);
                }
                for (coin, created) in intent.terms.inputs.iter().zip(creation_blocks) {
                    coin.previous()?;
                    match self.prevout(&coin.previous_transaction, coin.index, *created, headers)? {
                        PrevoutState::UnspentUnderSpv { depth, .. }
                            if depth >= safety.confirmations => {}
                        _ => return Err(Error::Input),
                    }
                }
                Ok(())
            }
        }

        /// Exact funding signatures and covered confirmed-chain input inspection.
        /// This type is intentionally not a full-validation/signing/broadcast token.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct SpvFundingInspection {
            intent_hash: Hash,
            transaction: Txid,
            witness_transaction: bitcoin::Wtxid,
            tip: (BlockHash, u32),
            inputs: Vec<OutPoint>,
        }
        impl SpvFundingInspection {
            pub fn intent_hash(&self) -> Hash {
                self.intent_hash
            }
            pub fn transaction(&self) -> Txid {
                self.transaction
            }
            pub fn witness_transaction(&self) -> bitcoin::Wtxid {
                self.witness_transaction
            }
            pub fn tip(&self) -> (BlockHash, u32) {
                self.tip
            }
            pub fn inputs(&self) -> &[OutPoint] {
                &self.inputs
            }
            pub fn scope(&self) -> &'static str {
                "EXACT_P2WPKH_SIGNATURES_AND_UNSPENT_UNDER_SPV_NO_FULL_VALIDATION_OR_MEMPOOL"
            }
            pub fn recheck(
                &self,
                intent: &TreasurySwapIntent,
                headers: &RegtestHeaders,
            ) -> Result<()> {
                if self.intent_hash != intent.intent_hash()? || self.tip != headers.tip() {
                    return Err(Error::Stale);
                }
                Ok(())
            }
        }
        impl BlockArchive {
            /// Caller may inspect only; neither a fabricated RPC success nor this
            /// SPV result can authorize production funding. Full Bitcoin consensus,
            /// validated UTXO/mempool and durable header integration remain gated.
            pub fn inspect_signed_funding(
                &self,
                intent: &TreasurySwapIntent,
                signed: &[u8],
                creation_blocks: &[BlockHash],
                headers: &RegtestHeaders,
                safety: &OfflineSafety,
            ) -> Result<SpvFundingInspection> {
                let (transaction, witness_transaction) = intent.verify_signed(signed)?;
                self.verify_intent_inputs(intent, creation_blocks, headers, safety)?;
                let inputs = tx(signed, MAX_PREVIOUS_TX)?
                    .input
                    .into_iter()
                    .map(|i| i.previous_output)
                    .collect();
                Ok(SpvFundingInspection {
                    intent_hash: intent.intent_hash()?,
                    transaction,
                    witness_transaction,
                    tip: headers.tip(),
                    inputs,
                })
            }
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct MonitoredSpend {
            pub txid: Txid,
            pub input_index: usize,
            pub path: SpendPath,
        }
        /// Knowledge-only fallback: even a nonstandard or invalid spend may
        /// disclose the exact secret. Never let output policy, signature policy
        /// or chain availability hide it. This does NOT establish a BTC payment
        /// or authorize a MUT claim; BOTH_REQUIRED still applies to that claim.
        pub fn recover_preimage_hint(
            intent: &TreasurySwapIntent,
            raw: &[u8],
        ) -> Result<Option<Hash>> {
            let t = tx(raw, MAX_PREVIOUS_TX)?;
            let point = OutPoint {
                txid: intent.expected_txid()?,
                vout: 0,
            };
            let script = lock_script(intent.condition, &intent.terms)?;
            let mut found = None;
            for i in &t.input {
                if i.previous_output != point || i.witness.last() != Some(script.as_bytes()) {
                    continue;
                }
                for item in i.witness.iter() {
                    if let Ok(secret) = Hash::try_from(item)
                        && tr::preimage_hash(&secret) == intent.condition
                    {
                        found = Some(secret);
                    }
                }
            }
            if found.is_some() {
                intent.verify_terms()?;
            }
            Ok(found)
        }
        /// Verify this contract input, independent of the spender's output/fee
        /// template or its other inputs. All six standard BIP143 ECDSA sighash
        /// modes are understood. Other inputs' scripts still need chain validity.
        /// A recovered secret is knowledge, NOT a spending authorization.
        pub fn monitor_spend(intent: &TreasurySwapIntent, raw: &[u8]) -> Result<MonitoredSpend> {
            let t = tx(raw, MAX_PREVIOUS_TX)?;
            if t.input.is_empty()
                || t.input.len() > MAX_INPUTS
                || t.output.is_empty()
                || t.output.len() > 64
            {
                return Err(Error::Bounds);
            }
            let target = OutPoint {
                txid: intent.expected_txid()?,
                vout: 0,
            };
            let mut points = BTreeSet::new();
            let mut index = None;
            let mut total = 0u64;
            for o in &t.output {
                total = total.checked_add(o.value.to_sat()).ok_or(Error::Bounds)?;
                if total > Amount::MAX_MONEY.to_sat() {
                    return Err(Error::Output);
                }
            }
            for (n, i) in t.input.iter().enumerate() {
                if !points.insert(i.previous_output) {
                    return Err(Error::Input);
                }
                if i.previous_output == target {
                    index = Some(n);
                }
            }
            let n = index.ok_or(Error::Context)?;
            let i = &t.input[n];
            if !i.script_sig.is_empty() {
                return Err(Error::Signature);
            }
            let w: Vec<_> = i.witness.iter().collect();
            let script = lock_script(intent.condition, &intent.terms)?;
            if w.last().copied() != Some(script.as_bytes()) {
                return Err(Error::Signature);
            }
            let (path, key) = if w.len() == 4 && w[2] == [1] {
                let secret: Hash = w[1].try_into().map_err(|_| Error::Terms)?;
                if tr::preimage_hash(&secret) != intent.condition {
                    return Err(Error::Terms);
                }
                (
                    SpendPath::Claim { preimage: secret },
                    intent.terms.recipient,
                )
            } else if w.len() == 3 && w[1].is_empty() {
                if !t.lock_time.is_block_height()
                    || t.lock_time.to_consensus_u32() < intent.terms.refund_height
                    || i.sequence == bitcoin::Sequence::MAX
                {
                    return Err(Error::Deadline);
                }
                (SpendPath::Refund, intent.terms.refund)
            } else {
                return Err(Error::Signature);
            };
            let sig = bitcoin::ecdsa::Signature::from_slice(w[0]).map_err(|_| Error::Signature)?;
            if sig.to_vec() != w[0] {
                return Err(Error::Signature);
            }
            intent.verify_terms()?;
            let value = tx(&intent.unsigned, MAX_PREVIOUS_TX)?.output[0].value;
            let h = SighashCache::new(&t)
                .p2wsh_signature_hash(n, &script, value, sig.sighash_type)
                .map_err(|_| Error::Signature)?;
            // High-S is consensus-valid ECDSA for segwit v0; policy rejection
            // must not suppress secret recovery. Normalize only for verifier.
            let mut normalized = sig.signature;
            normalized.normalize_s();
            Secp256k1::verification_only()
                .verify_ecdsa(
                    &Message::from_digest(h.to_byte_array()),
                    &normalized,
                    &PublicKey::from_slice(&key).map_err(|_| Error::Signature)?,
                )
                .map_err(|_| Error::Signature)?;
            Ok(MonitoredSpend {
                txid: t.compute_txid(),
                input_index: n,
                path,
            })
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum NativeOutcome {
            Locked = 0,
            Claimed = 1,
            Refunded = 2,
        }
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum PairStatus {
            Pending = 0,
            BitcoinIncluded = 1,
            BitcoinClaimed = 2,
            BitcoinRefunded = 3,
            Reorged = 4,
            Conflicted = 5,
            SettledUnderSpv = 6,
            RefundedUnderSpv = 7,
            Disputed = 8,
        }
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Assessment {
            pub operation: Hash,
            pub revision: u32,
            pub trade: Hash,
            pub contract: Hash,
            pub btc_satoshis: u64,
            pub mut_strikes: u64,
            pub treasury: Hash,
            pub generation: u64,
            pub btc_funding: Txid,
            pub btc_spend: Option<Txid>,
            pub mut_terminal: Option<Hash>,
            pub funding_block: Option<BlockHash>,
            pub spending_block: Option<BlockHash>,
            pub funding_fee_satoshis: u64,
            pub mut_funding_fee_strikes: u64,
            pub mut_terminal_fee_strikes: Option<u64>,
            pub bitcoin_tip: BlockHash,
            pub native_anchor: FinalizedAnchor,
            pub native_root: Hash,
            pub native_outcome: NativeOutcome,
            pub status: PairStatus,
        }
        impl Assessment {
            /// Public audit-safe summary, no witness/preimage/private data.
            /// Historical observation only: callers must reconcile anew.
            pub fn encode(&self) -> Vec<u8> {
                let mut e = Encoder::new(Vec::new());
                e.array(25)
                    .unwrap()
                    .bytes(RECOVERY_NS)
                    .unwrap()
                    .u8(1)
                    .unwrap()
                    .bytes(&self.operation)
                    .unwrap()
                    .u32(self.revision)
                    .unwrap()
                    .bytes(&self.trade)
                    .unwrap()
                    .bytes(&self.contract)
                    .unwrap()
                    .u64(self.btc_satoshis)
                    .unwrap()
                    .u64(self.mut_strikes)
                    .unwrap()
                    .bytes(&self.treasury)
                    .unwrap()
                    .u64(self.generation)
                    .unwrap()
                    .bytes(&self.btc_funding.to_byte_array())
                    .unwrap();
                match self.btc_spend {
                    Some(x) => {
                        e.bytes(&x.to_byte_array()).unwrap();
                    }
                    None => {
                        e.null().unwrap();
                    }
                }
                match self.mut_terminal {
                    Some(x) => {
                        e.bytes(&x).unwrap();
                    }
                    None => {
                        e.null().unwrap();
                    }
                }
                e.bytes(&self.bitcoin_tip.to_byte_array())
                    .unwrap()
                    .bytes(&self.native_anchor.encode())
                    .unwrap()
                    .bytes(&self.native_root)
                    .unwrap()
                    .u8(self.native_outcome as u8)
                    .unwrap()
                    .u8(self.status as u8)
                    .unwrap()
                    .bool(false)
                    .unwrap()
                    .str("SPV_VALID_CHAIN_ASSUMPTION_NOT_PRODUCTION_INCOME")
                    .unwrap();
                for b in [self.funding_block, self.spending_block] {
                    match b {
                        Some(x) => {
                            e.bytes(&x.to_byte_array()).unwrap();
                        }
                        None => {
                            e.null().unwrap();
                        }
                    }
                }
                e.u64(self.funding_fee_satoshis)
                    .unwrap()
                    .u64(self.mut_funding_fee_strikes)
                    .unwrap();
                match self.mut_terminal_fee_strikes {
                    Some(x) => {
                        e.u64(x).unwrap();
                    }
                    None => {
                        e.null().unwrap();
                    }
                }
                e.into_writer()
            }
            pub fn decode(raw: &[u8]) -> Result<Self> {
                if raw.is_empty() || raw.len() > 4096 {
                    return Err(Error::Bounds);
                }
                let mut d = Decoder::new(raw);
                array(&mut d, 25)?;
                if bytes(&mut d)? != RECOVERY_NS || uint(&mut d)? != 1 {
                    return Err(Error::Codec);
                }
                let operation = fixed(&mut d)?;
                let revision = d.u32().map_err(|_| Error::Codec)?;
                let trade = fixed(&mut d)?;
                let contract = fixed(&mut d)?;
                let btc_satoshis = uint(&mut d)?;
                let mut_strikes = uint(&mut d)?;
                let treasury = fixed(&mut d)?;
                let generation = uint(&mut d)?;
                let btc_funding = Txid::from_byte_array(fixed(&mut d)?);
                fn optional(d: &mut Decoder<'_>) -> Result<Option<Hash>> {
                    if d.datatype().map_err(|_| Error::Codec)? == minicbor::data::Type::Null {
                        d.null().map_err(|_| Error::Codec)?;
                        Ok(None)
                    } else {
                        Ok(Some(fixed(d)?))
                    }
                }
                let btc_spend = optional(&mut d)?.map(Txid::from_byte_array);
                let mut_terminal = optional(&mut d)?;
                let bitcoin_tip = BlockHash::from_byte_array(fixed(&mut d)?);
                let native_anchor =
                    FinalizedAnchor::decode(bytes(&mut d)?).map_err(|_| Error::Codec)?;
                let native_root = fixed(&mut d)?;
                let native_outcome = match uint(&mut d)? {
                    0 => NativeOutcome::Locked,
                    1 => NativeOutcome::Claimed,
                    2 => NativeOutcome::Refunded,
                    _ => return Err(Error::Codec),
                };
                let status = match uint(&mut d)? {
                    0 => PairStatus::Pending,
                    1 => PairStatus::BitcoinIncluded,
                    2 => PairStatus::BitcoinClaimed,
                    3 => PairStatus::BitcoinRefunded,
                    4 => PairStatus::Reorged,
                    5 => PairStatus::Conflicted,
                    6 => PairStatus::SettledUnderSpv,
                    7 => PairStatus::RefundedUnderSpv,
                    8 => PairStatus::Disputed,
                    _ => return Err(Error::Codec),
                };
                if d.bool().map_err(|_| Error::Codec)?
                    || d.str().map_err(|_| Error::Codec)?
                        != "SPV_VALID_CHAIN_ASSUMPTION_NOT_PRODUCTION_INCOME"
                {
                    return Err(Error::Codec);
                }
                let funding_block = optional(&mut d)?.map(BlockHash::from_byte_array);
                let spending_block = optional(&mut d)?.map(BlockHash::from_byte_array);
                let funding_fee_satoshis = uint(&mut d)?;
                let mut_funding_fee_strikes = uint(&mut d)?;
                let mut_terminal_fee_strikes =
                    if d.datatype().map_err(|_| Error::Codec)? == minicbor::data::Type::Null {
                        d.null().map_err(|_| Error::Codec)?;
                        None
                    } else {
                        Some(uint(&mut d)?)
                    };
                let a = Self {
                    operation,
                    revision,
                    trade,
                    contract,
                    btc_satoshis,
                    mut_strikes,
                    treasury,
                    generation,
                    btc_funding,
                    btc_spend,
                    mut_terminal,
                    bitcoin_tip,
                    native_anchor,
                    native_root,
                    native_outcome,
                    status,
                    funding_block,
                    spending_block,
                    funding_fee_satoshis,
                    mut_funding_fee_strikes,
                    mut_terminal_fee_strikes,
                };
                if d.position() != raw.len() || a.encode() != raw {
                    return Err(Error::Codec);
                }
                Ok(a)
            }
        }
        /// Separate durable evidence journal. Terminal claims/refunds must be
        /// actual canonical operations, never peer notices. No automatic action.
        pub struct RecoveryJournal {
            db: Connection,
            #[cfg(feature = "trading-local-storage-candidate")]
            storage: Option<sealed_storage::SnapshotStore>,
        }
        pub struct RecoveryView<'a> {
            pub operations: &'a OperationJournal,
            pub store: &'a CanonicalStore,
            pub archive: &'a BlockArchive,
            pub headers: &'a RegtestHeaders,
            pub safety: &'a OfflineSafety,
            pub policy: &'a CandidatePolicy,
        }
        impl RecoveryJournal {
            fn ensure_storage_healthy(&self) -> Result<()> {
                #[cfg(feature = "trading-local-storage-candidate")]
                if let Some(s) = &self.storage {
                    s.healthy().map_err(|_| Error::Store)?;
                }
                Ok(())
            }
            fn persist_storage(&mut self) -> Result<()> {
                #[cfg(feature = "trading-local-storage-candidate")]
                if let Some(s) = &mut self.storage {
                    s.persist(&self.db).map_err(|_| Error::Store)?;
                }
                Ok(())
            }
            fn storage_binding(&self, anchor: &FinalizedAnchor) -> Result<()> {
                #[cfg(feature = "trading-local-storage-candidate")]
                if let Some(s) = &self.storage {
                    s.matches_anchor(anchor).map_err(|_| Error::Context)?;
                }
                let _ = anchor;
                Ok(())
            }
            #[cfg(feature = "trading-local-storage-candidate")]
            pub fn storage_checkpoint(&self) -> Result<sealed_storage::DurableCheckpoint> {
                self.ensure_storage_healthy()?;
                self.storage
                    .as_ref()
                    .ok_or(Error::State)?
                    .checkpoint()
                    .map_err(|_| Error::Store)
            }

            #[cfg(feature = "trading-local-storage-candidate")]
            pub fn create_encrypted(
                paths: &sealed_storage::Paths,
                key: std::sync::Arc<StorageKey>,
                context: StorageContext,
                policy: CandidatePolicy,
            ) -> Result<Self> {
                Self::create_encrypted_kind(
                    paths,
                    key,
                    context,
                    policy,
                    sealed_storage::JournalKind::Recovery,
                )
            }
            #[cfg(feature = "trading-local-storage-candidate")]
            fn create_encrypted_kind(
                paths: &sealed_storage::Paths,
                key: std::sync::Arc<StorageKey>,
                context: StorageContext,
                policy: CandidatePolicy,
                kind: sealed_storage::JournalKind,
            ) -> Result<Self> {
                native(policy.check())?;
                let mut out = Self::open(Path::new(":memory:"))?;
                sealed_storage::memory_hardening(&out.db).map_err(|_| Error::Store)?;
                out.storage = Some(
                    sealed_storage::SnapshotStore::create(
                        paths, key, &context, kind, &out.db, &policy,
                    )
                    .map_err(|_| Error::Store)?,
                );
                Ok(out)
            }
            #[cfg(feature = "trading-local-storage-candidate")]
            pub fn open_encrypted(
                paths: &sealed_storage::Paths,
                key: std::sync::Arc<StorageKey>,
                context: StorageContext,
                minimum: sealed_storage::DurableCheckpoint,
                policy: CandidatePolicy,
            ) -> Result<Self> {
                Self::open_encrypted_kind(
                    paths,
                    key,
                    context,
                    minimum,
                    policy,
                    sealed_storage::JournalKind::Recovery,
                )
            }
            #[cfg(feature = "trading-local-storage-candidate")]
            fn open_encrypted_kind(
                paths: &sealed_storage::Paths,
                key: std::sync::Arc<StorageKey>,
                context: StorageContext,
                minimum: sealed_storage::DurableCheckpoint,
                policy: CandidatePolicy,
                kind: sealed_storage::JournalKind,
            ) -> Result<Self> {
                native(policy.check())?;
                let mut out = Self::open(Path::new(":memory:"))?;
                out.storage = Some(
                    sealed_storage::SnapshotStore::open(
                        paths,
                        key,
                        &context,
                        kind,
                        minimum,
                        &mut out.db,
                        &policy,
                    )
                    .map_err(|_| Error::Store)?,
                );
                let n:i64=db(out.db.query_row("SELECT (SELECT count(*) FROM recovery_event)+(SELECT count(*) FROM recovery_assessment)",[],|r|r.get(0)))?;
                if n > 4096 {
                    return Err(Error::Corrupt);
                };
                Ok(out)
            }

            pub fn open(path: &Path) -> Result<Self> {
                let c = db(Connection::open(path))?;
                db(c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;
                  CREATE TABLE IF NOT EXISTS recovery_event(op BLOB NOT NULL CHECK(length(op)=32), revision INTEGER NOT NULL, kind INTEGER NOT NULL, evidence BLOB NOT NULL CHECK(length(evidence)<=32768), UNIQUE(op,revision,kind,evidence));
                  CREATE TABLE IF NOT EXISTS recovery_assessment(op BLOB NOT NULL CHECK(length(op)=32), digest BLOB NOT NULL CHECK(length(digest)=32), raw BLOB NOT NULL CHECK(length(raw)<=4096), PRIMARY KEY(op,digest));"))?;
                let good: String = db(c.query_row("PRAGMA integrity_check", [], |r| r.get(0)))?;
                let n:i64=db(c.query_row("SELECT (SELECT count(*) FROM recovery_event)+(SELECT count(*) FROM recovery_assessment)",[],|r|r.get(0)))?;
                if good != "ok" || n > 4096 {
                    return Err(Error::Corrupt);
                }
                Ok(Self {
                    db: c,
                    #[cfg(feature = "trading-local-storage-candidate")]
                    storage: None,
                })
            }
            fn append(&mut self, op: Hash, rev: u32, kind: u8, raw: &[u8]) -> Result<()> {
                self.ensure_storage_healthy()?;
                if raw.len() > 32768 {
                    return Err(Error::Bounds);
                }
                let t = db(self
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate))?;
                let existing:bool=db(t.query_row("SELECT EXISTS(SELECT 1 FROM recovery_event WHERE op=?1 AND revision=?2 AND kind=?3 AND evidence=?4)",params![op.as_slice(),rev,kind,raw],|r|r.get(0)))?;
                if existing {
                    return Ok(());
                }
                let n:i64=db(t.query_row("SELECT (SELECT count(*) FROM recovery_event)+(SELECT count(*) FROM recovery_assessment)",[],|r|r.get(0)))?;
                if n >= 4096 {
                    return Err(Error::Capacity);
                }
                db(t.execute(
                    "INSERT INTO recovery_event VALUES(?1,?2,?3,?4)",
                    params![op.as_slice(), rev, kind, raw],
                ))?;
                fault("event_before_commit");
                db(t.commit())?;
                self.persist_storage()?;
                fault("event_after_commit");
                Ok(())
            }
            /// Complete blocks provide witness commitment. Reorged disclosures
            /// remain useful knowledge, but cease to be settlement evidence.
            pub fn observe_bitcoin_spend(
                &mut self,
                intent: &TreasurySwapIntent,
                block_id: BlockHash,
                txid: Txid,
                archive: &BlockArchive,
                headers: &RegtestHeaders,
            ) -> Result<MonitoredSpend> {
                self.ensure_storage_healthy()?;
                self.storage_binding(intent.frozen_offer()?.creation_anchor())?;
                let (t, _) = archive.included(block_id, txid, headers)?;
                let m = monitor_spend(intent, &serialize(&t))?;
                let height = headers.entries[&block_id].height;
                if t.input.iter().any(|i| i.sequence != bitcoin::Sequence::MAX)
                    && (!t.lock_time.is_block_height() || t.lock_time.to_consensus_u32() >= height)
                {
                    return Err(Error::Deadline);
                }
                if matches!(m.path, SpendPath::Claim { .. }) {
                    // Persist useful disclosed knowledge BEFORE the settlement
                    // reference. A crash here loses no preimage and grants no
                    // settlement authority. Header pruning cannot erase it.
                    self.observe_preimage_hint(intent, &serialize(&t))?;
                }
                let mut e = Encoder::new(Vec::new());
                e.array(3)
                    .unwrap()
                    .bytes(&intent.intent_hash()?)
                    .unwrap()
                    .bytes(&block_id.to_byte_array())
                    .unwrap()
                    .bytes(&txid.to_byte_array())
                    .unwrap();
                self.append(intent.operation, intent.revision, 0, &e.into_writer())?;
                Ok(m)
            }
            pub fn observe_native_terminal(
                &mut self,
                intent: &TreasurySwapIntent,
                raw: &[u8],
                store: &CanonicalStore,
                policy: &CandidatePolicy,
            ) -> Result<()> {
                self.ensure_storage_healthy()?;
                self.storage_binding(intent.frozen_offer()?.creation_anchor())?;
                native_terminal(intent, Some(raw), store, policy)?;
                self.append(intent.operation, intent.revision, 1, raw)
            }
            pub fn observe_preimage_hint(
                &mut self,
                intent: &TreasurySwapIntent,
                raw: &[u8],
            ) -> Result<Hash> {
                self.ensure_storage_healthy()?;
                self.storage_binding(intent.frozen_offer()?.creation_anchor())?;
                let secret = recover_preimage_hint(intent, raw)?.ok_or(Error::Evidence)?;
                self.append(intent.operation, intent.revision, 2, raw)?;
                Ok(secret)
            }
            /// Returns previously validated knowledge even after a fork drops
            /// the spending block. This is deliberately independent of finality.
            pub fn known_preimages(&self, intent: &TreasurySwapIntent) -> Result<Vec<Hash>> {
                self.ensure_storage_healthy()?;
                self.storage_binding(intent.frozen_offer()?.creation_anchor())?;
                let mut secrets = BTreeSet::new();
                for (kind, raw) in self.events(intent)? {
                    if kind == 2 {
                        secrets.insert(recover_preimage_hint(intent, &raw)?.ok_or(Error::Corrupt)?);
                        continue;
                    }
                    // Chain references (kind 0) and native terminals (kind 1)
                    // cannot override or suppress already disclosed knowledge.
                }
                Ok(secrets.into_iter().collect())
            }
            fn events(&self, i: &TreasurySwapIntent) -> Result<Vec<(u8, Vec<u8>)>> {
                self.ensure_storage_healthy()?;
                let mut s=db(self.db.prepare("SELECT kind,evidence FROM recovery_event WHERE op=?1 AND revision=?2 ORDER BY rowid"))?;
                let rows = db(
                    s.query_map(params![i.operation.as_slice(), i.revision], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    }),
                )?;
                rows.map(db).collect()
            }
            pub fn assess(
                &mut self,
                intent: &TreasurySwapIntent,
                view: RecoveryView<'_>,
            ) -> Result<Assessment> {
                self.ensure_storage_healthy()?;
                self.storage_binding(intent.frozen_offer()?.creation_anchor())?;
                let RecoveryView {
                    operations,
                    store,
                    archive,
                    headers,
                    safety,
                    policy,
                } = view;
                intent.verify_terms()?;
                native(policy.check())?;
                let (stored, stage, signed) =
                    operations.reconcile(intent.operation, intent.revision)?;
                if stored != *intent || !matches!(stage, Stage::Signed | Stage::BroadcastPending) {
                    return Err(Error::State);
                }
                let (funding_txid, _) = intent.verify_signed(&signed.ok_or(Error::State)?)?;
                let mut terminal = None;
                let mut spend = None;
                let mut reorg = false;
                for (kind, raw) in self.events(intent)? {
                    match kind {
                        0 => {
                            let (bid, tid) = spend_reference(intent, &raw)?;
                            match archive.included(bid, tid, headers) {
                                Err(Error::Stale) => reorg = true,
                                Err(e) => return Err(e),
                                Ok((t, depth)) => {
                                    let m = monitor_spend(intent, &serialize(&t))?;
                                    // Prove the exact funding transaction was in
                                    // an earlier block (or earlier in this block).
                                    let funding_block = find_funding_before(
                                        archive,
                                        headers,
                                        bid,
                                        tid,
                                        funding_txid,
                                    )?;
                                    let (funded, fd) =
                                        archive.included(funding_block, funding_txid, headers)?;
                                    intent.verify_signed(&serialize(&funded))?;
                                    if spend.as_ref().is_some_and(|(old, _, _, _)| *old != m) {
                                        return Err(Error::Evidence);
                                    }
                                    spend = Some((m, depth.min(fd), funding_block, bid));
                                }
                            }
                        }
                        1 => {
                            if terminal.as_ref().is_some_and(|old| old != &raw) {
                                return Err(Error::Evidence);
                            }
                            terminal = Some(raw);
                        }
                        2 => {
                            recover_preimage_hint(intent, &raw)?.ok_or(Error::Corrupt)?;
                        }
                        _ => return Err(Error::Corrupt),
                    }
                }
                let (native_outcome, mut_terminal, anchor, root) =
                    native_terminal(intent, terminal.as_deref(), store, policy)?;
                let fs = operations.funding_status(intent.operation, headers, safety)?;
                let mut status = if matches!(fs, FundingStatus::Conflicted { .. }) {
                    PairStatus::Conflicted
                } else if reorg && spend.is_none() || matches!(fs, FundingStatus::Reorged { .. }) {
                    PairStatus::Reorged
                } else {
                    PairStatus::Pending
                };
                if !matches!(status, PairStatus::Conflicted | PairStatus::Reorged)
                    && let Some((m, depth, _, _)) = &spend
                {
                    status = if *depth < safety.confirmations {
                        PairStatus::BitcoinIncluded
                    } else {
                        match (&m.path, native_outcome) {
                            (SpendPath::Claim { .. }, NativeOutcome::Claimed) => {
                                PairStatus::SettledUnderSpv
                            }
                            (SpendPath::Refund, NativeOutcome::Refunded) => {
                                PairStatus::RefundedUnderSpv
                            }
                            (SpendPath::Claim { .. }, NativeOutcome::Refunded)
                            | (SpendPath::Refund, NativeOutcome::Claimed) => PairStatus::Disputed,
                            (SpendPath::Claim { .. }, _) => PairStatus::BitcoinClaimed,
                            (SpendPath::Refund, _) => PairStatus::BitcoinRefunded,
                        }
                    };
                }
                let f = intent.frozen_offer()?;
                let tr::OfferTerms::HashLinked {
                    amount,
                    bitcoin_satoshis,
                    ..
                } = f.offer().terms
                else {
                    return Err(Error::Terms);
                };
                let funding_fee = native(tr::NativeOperation::decode(&intent.funding))?
                    .operation
                    .meta
                    .fee
                    .0;
                let terminal_fee = terminal
                    .as_ref()
                    .map(|raw| {
                        native(tr::NativeOperation::decode(raw)).map(|w| w.operation.meta.fee.0)
                    })
                    .transpose()?;
                let assessment = Assessment {
                    operation: intent.operation,
                    revision: intent.revision,
                    trade: f.trade(),
                    contract: f.contract(),
                    btc_satoshis: bitcoin_satoshis,
                    mut_strikes: amount.0,
                    treasury: f.address(),
                    generation: f.generation(),
                    btc_funding: funding_txid,
                    btc_spend: spend.as_ref().map(|(m, _, _, _)| m.txid),
                    mut_terminal,
                    funding_block: spend.as_ref().map(|(_, _, b, _)| *b),
                    spending_block: spend.as_ref().map(|(_, _, _, b)| *b),
                    funding_fee_satoshis: intent.terms.fee_satoshis,
                    mut_funding_fee_strikes: funding_fee,
                    mut_terminal_fee_strikes: terminal_fee,
                    bitcoin_tip: headers.best,
                    native_anchor: anchor,
                    native_root: root,
                    native_outcome,
                    status,
                };
                self.persist_assessment(&assessment)?;
                Ok(assessment)
            }
            fn persist_assessment(&mut self, a: &Assessment) -> Result<()> {
                self.ensure_storage_healthy()?;
                let raw = a.encode();
                let hash = digest(b"recovery-assessment", &raw);
                let t = db(self
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate))?;
                let old: Option<Vec<u8>> = db(t
                    .query_row(
                        "SELECT raw FROM recovery_assessment WHERE op=?1 AND digest=?2",
                        params![a.operation.as_slice(), hash.as_slice()],
                        |r| r.get(0),
                    )
                    .optional())?;
                if let Some(old) = old {
                    return if old == raw {
                        Ok(())
                    } else {
                        Err(Error::Corrupt)
                    };
                }
                let n:i64=db(t.query_row("SELECT (SELECT count(*) FROM recovery_event)+(SELECT count(*) FROM recovery_assessment)",[],|r|r.get(0)))?;
                if n >= 4096 {
                    return Err(Error::Capacity);
                }
                db(t.execute(
                    "INSERT INTO recovery_assessment VALUES(?1,?2,?3)",
                    params![a.operation.as_slice(), hash.as_slice(), raw],
                ))?;
                db(t.commit())?;
                self.persist_storage()?;
                Ok(())
            }
        }
        fn spend_reference(i: &TreasurySwapIntent, raw: &[u8]) -> Result<(BlockHash, Txid)> {
            let mut d = Decoder::new(raw);
            array(&mut d, 3)?;
            if fixed(&mut d)? != i.intent_hash()? {
                return Err(Error::Context);
            }
            let b = BlockHash::from_byte_array(fixed(&mut d)?);
            let t = Txid::from_byte_array(fixed(&mut d)?);
            let mut e = Encoder::new(Vec::new());
            e.array(3)
                .unwrap()
                .bytes(&i.intent_hash()?)
                .unwrap()
                .bytes(&b.to_byte_array())
                .unwrap()
                .bytes(&t.to_byte_array())
                .unwrap();
            if d.position() != raw.len() || e.into_writer() != raw {
                return Err(Error::Codec);
            }
            Ok((b, t))
        }
        fn find_funding_before(
            a: &BlockArchive,
            h: &RegtestHeaders,
            mut id: BlockHash,
            spend: Txid,
            funding: Txid,
        ) -> Result<BlockHash> {
            for n in 0..MAX_BLOCKS {
                let b = a.get(id, h)?;
                let until = if n == 0 {
                    b.txdata
                        .iter()
                        .position(|t| t.compute_txid() == spend)
                        .ok_or(Error::Evidence)?
                } else {
                    b.txdata.len()
                };
                if b.txdata[..until]
                    .iter()
                    .any(|t| t.compute_txid() == funding)
                {
                    return Ok(id);
                }
                if h.entries[&id].height == 0 {
                    return Err(Error::Evidence);
                }
                id = b.header.prev_blockhash;
            }
            Err(Error::Capacity)
        }
        fn native_terminal(
            i: &TreasurySwapIntent,
            raw: Option<&[u8]>,
            store: &CanonicalStore,
            policy: &CandidatePolicy,
        ) -> Result<(NativeOutcome, Option<Hash>, FinalizedAnchor, Hash)> {
            native(policy.check())?;
            let f = i.frozen_offer()?;
            let funding = native(tr::NativeOperation::decode(&i.funding))?;
            let (tip, state, root) = current(store)?;
            let Some(raw) = raw else {
                let (_, _, l) = verify_mut_funding(store, &f, &funding, policy)?;
                if !matches!(l.kind,tr::NativeLockKind::Hash{condition,refund_height} if condition==i.condition && refund_height==i.mut_refund_height)
                {
                    return Err(Error::Evidence);
                }
                return Ok((NativeOutcome::Locked, None, tip, root));
            };
            let w = native(tr::NativeOperation::decode(raw))?;
            let receipt = native(tr::reconcile(&state, raw))?.ok_or(Error::Evidence)?;
            if receipt.height > tip.height {
                return Err(Error::Evidence);
            }
            // Reconstruct the authenticated state AT inclusion. A later spend of
            // the credited principal does not erase historical Treasury income.
            let (p, s, r) = store
                .execution_parent(receipt.height)
                .map_err(|_| Error::Store)?;
            let a = FinalizedAnchor {
                network: NETWORK_ID,
                genesis: p.genesis,
                fingerprint: p.fingerprint,
                height: p.height,
                block: p.block,
            };
            let creation = super::super::verify_archived_treasury_offer(store, f.clone(), policy)
                .map_err(|_| Error::Evidence)?;
            let op = &w.operation;
            let ctx = &funding.operation.meta;
            if op.meta.context != ctx.context
                || op.meta.trade != ctx.trade
                || op.meta.contract != ctx.contract
                || op.meta.generation != ctx.generation
            {
                return Err(Error::Context);
            }
            let output = funding
                .operation
                .output_id(0)
                .map_err(|_| Error::Evidence)?;
            let outcome = match op.action {
                tr::Action::Claim { preimage, .. } => {
                    if tr::preimage_hash(&preimage) != i.condition {
                        return Err(Error::Terms);
                    }
                    native(tr::verify_treasury_direct_credit(
                        &s, &creation, &funding, &w,
                    ))?;
                    NativeOutcome::Claimed
                }
                tr::Action::Refund {
                    output: locked,
                    owner,
                    amount,
                    ..
                } => {
                    let tr::Action::HashLock {
                        sender,
                        amount: expected,
                        ..
                    } = funding.operation.action
                    else {
                        return Err(Error::Terms);
                    };
                    if locked != output
                        || owner != sender
                        || amount != expected
                        || receipt.height < i.mut_refund_height
                        || s.protocol_records.contains_key(&tr::record_key(0, output))
                    {
                        return Err(Error::Evidence);
                    }
                    let point = mutiny_consensus_v8::transactions::OutPoint {
                        transaction: op.id().map_err(|_| Error::Evidence)?,
                        index: 0,
                    };
                    let c = s.coins.get(&point).ok_or(Error::Evidence)?;
                    if c.output.owner != owner
                        || c.output.atoms != amount.0
                        || c.created_height != receipt.height
                        || c.coinbase
                    {
                        return Err(Error::Evidence);
                    }
                    NativeOutcome::Refunded
                }
                _ => return Err(Error::Terms),
            };
            let funded = native(tr::reconcile(&s, &i.funding))?.ok_or(Error::Evidence)?;
            if funded.height >= receipt.height {
                return Err(Error::Evidence);
            }
            Ok((outcome, Some(receipt.operation), a, r))
        }
        #[derive(Clone, Debug)]
        pub struct CreditEvidence {
            pub anchor: FinalizedAnchor,
            pub root: Hash,
            pub funding: Vec<u8>,
            pub claim: Vec<u8>,
            pub principal: Vec<u8>,
        }
        /// Reconstruct compact evidence at the actual canonical inclusion height,
        /// not the current UTXO view (the Treasury may since spend its proceeds).
        pub fn treasury_credit_evidence(
            i: &TreasurySwapIntent,
            claim_raw: &[u8],
            store: &CanonicalStore,
            policy: &CandidatePolicy,
        ) -> Result<CreditEvidence> {
            let (kind, _, a, root) = native_terminal(i, Some(claim_raw), store, policy)?;
            if kind != NativeOutcome::Claimed {
                return Err(Error::Terms);
            }
            let (_, s, r) = store.execution_parent(a.height).map_err(|_| Error::Store)?;
            if r != root {
                return Err(Error::Stale);
            }
            let funding = native(tr::NativeOperation::decode(&i.funding))?;
            let claim = native(tr::NativeOperation::decode(claim_raw))?;
            let mut tree = mutiny_consensus_v8::state_tree::StateTree::default();
            for (key, value) in s.records().map_err(|_| Error::Store)? {
                tree.insert(key, value).map_err(|_| Error::Evidence)?;
            }
            let proof = |key| {
                tree.proof(a.clone(), key)
                    .encode()
                    .map_err(|_| Error::Evidence)
            };
            let evidence = CreditEvidence {
                anchor: a.clone(),
                root,
                funding: proof(tr::record_key(
                    2,
                    funding.operation.id().map_err(|_| Error::Evidence)?,
                ))?,
                claim: proof(tr::record_key(
                    2,
                    claim.operation.id().map_err(|_| Error::Evidence)?,
                ))?,
                principal: proof(tr::native_input_id(
                    &mutiny_consensus_v8::transactions::OutPoint {
                        transaction: claim.operation.id().map_err(|_| Error::Evidence)?,
                        index: 0,
                    },
                ))?,
            };
            let creation =
                super::super::verify_archived_treasury_offer(store, i.frozen_offer()?, policy)
                    .map_err(|_| Error::Evidence)?;
            native(tr::verify_treasury_credit_proofs(
                &creation,
                &funding,
                &claim,
                tr::TreasuryCreditProofs {
                    funding: &evidence.funding,
                    claim: &evidence.claim,
                    principal: &evidence.principal,
                },
                &a,
                root,
            ))?;
            Ok(evidence)
        }
    }

    /// Separate Architect-controlled watch-only signer journal. The signing
    /// device receives a narrowly validated request; this type has no private
    /// key and exposes no arbitrary Bitcoin signing function. Engine and signer
    /// use different databases. A lost signer response is answered from cache.
    pub struct DedicatedSignerJournal {
        journal: OperationJournal,
    }
    impl DedicatedSignerJournal {
        #[cfg(feature = "trading-local-storage-candidate")]
        pub fn create_encrypted(
            paths: &sealed_storage::Paths,
            key: std::sync::Arc<StorageKey>,
            context: StorageContext,
            policy: CandidatePolicy,
        ) -> Result<Self> {
            Ok(Self {
                journal: OperationJournal::create_encrypted_kind(
                    paths,
                    key,
                    context,
                    policy,
                    sealed_storage::JournalKind::BitcoinSigner,
                )?,
            })
        }
        #[cfg(feature = "trading-local-storage-candidate")]
        pub fn open_encrypted(
            paths: &sealed_storage::Paths,
            key: std::sync::Arc<StorageKey>,
            context: StorageContext,
            minimum: sealed_storage::DurableCheckpoint,
            policy: CandidatePolicy,
        ) -> Result<Self> {
            Ok(Self {
                journal: OperationJournal::open_encrypted_kind(
                    paths,
                    key,
                    context,
                    minimum,
                    policy,
                    sealed_storage::JournalKind::BitcoinSigner,
                )?,
            })
        }
        #[cfg(feature = "trading-local-storage-candidate")]
        pub fn storage_checkpoint(&self) -> Result<sealed_storage::DurableCheckpoint> {
            self.journal.storage_checkpoint()
        }

        pub fn open(path: &Path, policy: CandidatePolicy) -> Result<Self> {
            Ok(Self {
                journal: OperationJournal::open(path, policy)?,
            })
        }
        pub fn record_creation(
            &mut self,
            store: &CanonicalStore,
            frozen: &tr::FrozenTreasuryOffer,
        ) -> Result<Hash> {
            self.journal.record_creation(store, frozen)
        }
        pub fn authorize_request(
            &mut self,
            store: &CanonicalStore,
            raw: &[u8],
            authorization: &SignerAuthorization,
            headers: &RegtestHeaders,
            safety: &OfflineSafety,
        ) -> Result<SignRequest> {
            let i = TreasurySwapIntent::decode(raw)?;
            authorization.verify(&i)?;
            if native(self.journal.creation(i.operation)?.encode())? != i.frozen {
                return Err(Error::Authority);
            }
            fresh(store, &i, headers, safety, &self.journal.policy)?;
            let exists: bool = db(self.journal.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM bitcoin_attempt WHERE operation=?1 AND revision=?2)",
                params![i.operation.as_slice(), i.revision],
                |r| r.get(0),
            ))?;
            if exists {
                let (existing, stage, _) = self.journal.reconcile(i.operation, i.revision)?;
                if existing != i {
                    return Err(Error::Duplicate);
                }
                if stage != Stage::Prepared {
                    return Err(Error::Ambiguous);
                }
            } else {
                if i.revision > 0 {
                    let (old, stage, signed) =
                        self.journal.reconcile(i.operation, i.revision - 1)?;
                    if !matches!(stage, Stage::Signed | Stage::BroadcastPending) {
                        return Err(Error::Ambiguous);
                    }
                    let (tid, _) = old.verify_signed(&signed.ok_or(Error::Ambiguous)?)?;
                    i.replacement_of(&old, tid)?;
                }
                self.journal.insert_attempt(&i)?;
            }
            self.journal.begin_sign(
                store,
                i.operation,
                i.revision,
                authorization,
                headers,
                safety,
            )
        }
        pub fn persist_signature(
            &mut self,
            operation: Hash,
            revision: u32,
            raw: &[u8],
        ) -> Result<Txid> {
            self.journal.record_signed(operation, revision, raw)
        }
        /// Query-only after an ambiguous request. None means unresolved, never
        /// permission to sign again. Device-level monotonic/rollback protection
        /// remains a custody gate; coherent journal rollback is not solved here.
        pub fn cached_response(&self, operation: Hash, revision: u32) -> Result<Option<Vec<u8>>> {
            Ok(self.journal.reconcile(operation, revision)?.2)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use mutiny_consensus_v8::{
            block_envelope_v2::BlockEnvelope,
            canonical_store_v2::Preparation,
            certificates::Decision,
            continuity_v2::{Certificate, Vote},
            execution::State,
            mempool_v2::Mempool,
            pow::{WorkAuthority, WorkHeader},
            work_authority_v2::Authority,
        };
        use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
        use std::path::PathBuf;
        mod licenses {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../desktop/src/wallet_host_fixture_licenses.rs"
            ));
        }
        mod tpm {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../desktop/src/wallet_host_fixture_tpm.rs"
            ));
        }
        use super::recovery::*;
        fn assess(
            r: &mut RecoveryJournal,
            i: &TreasurySwapIntent,
            c: &Campaign,
            a: &BlockArchive,
            h: &RegtestHeaders,
        ) -> Result<Assessment> {
            r.assess(
                i,
                RecoveryView {
                    operations: &c.journal,
                    store: &c.store,
                    archive: a,
                    headers: h,
                    safety: &safety(),
                    policy: &policy(),
                },
            )
        }

        fn full_block(
            headers: &mut RegtestHeaders,
            parent: BlockHash,
            transactions: Vec<Transaction>,
            salt: u32,
        ) -> bitcoin::Block {
            let height = headers.entries[&parent].height + 1;
            let coinbase = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Builder::new()
                        .push_int(height as i64)
                        .push_int(salt as i64)
                        .into_script(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::from_slice(&[[0u8; 32]]),
                }],
                output: vec![bitcoin::TxOut {
                    value: Amount::from_sat(50 * 100_000_000),
                    script_pubkey: ScriptBuf::from_bytes(change_script()),
                }],
            };
            let mut b = bitcoin::Block {
                header: headers.entries[&parent].header,
                txdata: vec![coinbase],
            };
            b.txdata.extend(transactions);
            let commitment =
                bitcoin::Block::compute_witness_commitment(&b.witness_root().unwrap(), &[0; 32]);
            let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            script.extend(commitment.to_byte_array());
            b.txdata[0].output.push(bitcoin::TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(script),
            });
            let id = mine(
                headers,
                parent,
                b.compute_merkle_root().unwrap().to_byte_array(),
                salt,
            );
            b.header = headers.entries[&id].header;
            b
        }
        fn archive_block(
            a: &mut BlockArchive,
            h: &mut RegtestHeaders,
            txs: Vec<Transaction>,
        ) -> bitcoin::Block {
            let b = full_block(h, h.tip().0, txs, 0);
            a.insert(&serialize(&b), h).unwrap();
            b
        }
        fn broad_spend(
            i: &TreasurySwapIntent,
            mode: EcdsaSighashType,
            extra: bool,
            refund: bool,
        ) -> Vec<u8> {
            let mut t = tx(&external_spend(i, refund), MAX_PREVIOUS_TX).unwrap();
            t.output = vec![
                bitcoin::TxOut {
                    value: Amount::from_sat(80000),
                    script_pubkey: ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array(
                        [81; 32],
                    )),
                },
                bitcoin::TxOut {
                    value: Amount::from_sat(5000),
                    script_pubkey: ScriptBuf::from_bytes(change_script()),
                },
            ];
            let index = if extra {
                t.input.insert(
                    0,
                    bitcoin::TxIn {
                        previous_output: OutPoint {
                            txid: Txid::from_byte_array([55; 32]),
                            vout: 1,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: bitcoin::Sequence::MAX,
                        witness: bitcoin::Witness::new(),
                    },
                );
                1
            } else {
                0
            };
            let script = lock_script(i.condition, &i.terms).unwrap();
            let h = SighashCache::new(&t)
                .p2wsh_signature_hash(index, &script, Amount::from_sat(100000), mode)
                .unwrap();
            let sig = bitcoin::ecdsa::Signature {
                signature: Secp256k1::new().sign_ecdsa(
                    &Message::from_digest(h.to_byte_array()),
                    &key(if refund { 3 } else { 2 }),
                ),
                sighash_type: mode,
            }
            .to_vec();
            let w = if refund {
                vec![sig, vec![], script.into_bytes()]
            } else {
                vec![sig, vec![42; 32], vec![1], script.into_bytes()]
            };
            t.input[index].witness = bitcoin::Witness::from_slice(&w);
            serialize(&t)
        }
        fn native_claim(c: &Campaign) -> tr::NativeOperation {
            let point = mutiny_consensus_v8::transactions::OutPoint {
                transaction: [181; 32],
                index: 0,
            };
            let mut op = tr::Operation {
                meta: tr::Meta {
                    context: c.funding.operation.meta.context.clone(),
                    trade: c.frozen.trade(),
                    contract: c.frozen.contract(),
                    generation: 1,
                    created: 2,
                    expiry: 40,
                    fee: tr::Strikes(20000),
                    inputs: vec![tr::native_input_id(&point)],
                },
                action: tr::Action::Claim {
                    output: c.funding.operation.output_id(0).unwrap(),
                    recipient: c.frozen.address(),
                    amount: tr::Strikes(50000),
                    preimage: [42; 32],
                    change: tr::Strikes(80000),
                },
                approvals: vec![],
                offer_proof: None,
            };
            op.approve(0, &c.treasury, 1).unwrap();
            tr::NativeOperation {
                operation: op,
                inputs: vec![point],
            }
        }
        fn spend_native_credit(c: &mut Campaign, claim: &tr::NativeOperation) {
            use mutiny_consensus_v8::{hybrid_transaction_v2::Transaction, transactions_v2 as t};
            let (parent, state, _) = current(&c.store).unwrap();
            let next = parent.height + 1;
            let point = mutiny_consensus_v8::transactions::OutPoint {
                transaction: claim.operation.id().unwrap(),
                index: 0,
            };
            let mut transfer = t::Transfer {
                network: parent.network,
                genesis: parent.genesis,
                fingerprint: parent.fingerprint,
                created_height: next,
                expiry_height: next + 2,
                fee: 20000,
                inputs: vec![t::Input::unsigned(point.clone(), c.treasury.public(), 1).unwrap()],
                outputs: vec![mutiny_consensus_v8::transactions::Output {
                    owner: c.frozen.address(),
                    atoms: 30000,
                }],
            };
            transfer.sign_input(0, &c.treasury).unwrap();
            let mut pool = Mempool::open(
                &c.base.join("spend-credit-pool.sqlite"),
                parent.genesis,
                parent.fingerprint,
                1048576,
            )
            .unwrap();
            c.store.reconcile_pool(&mut pool).unwrap();
            pool.admit(&Transaction::Transfer(transfer), &parent, &state)
                .unwrap();
            let prepared = c
                .store
                .prepare_pending(Preparation {
                    expected_parent: &parent,
                    pool: &pool,
                    license: c.f.license,
                    worker: c.f.worker,
                    timestamp: 1000 + 100 * next,
                    ticket: next,
                    operations: &[],
                })
                .unwrap();
            let envelope = certify_at(prepared, &c.f, &parent, &state, next);
            assert!(c.store.commit(&envelope).unwrap());
            assert!(!current(&c.store).unwrap().1.coins.contains_key(&point));
        }
        #[test]
        fn r4_monitor_all_sighashes_extra_inputs_alternate_outputs_and_fees() {
            let mut c = campaign("r4-broad-monitor");
            let i = intent(&mut c);
            let mut vectors = Vec::new();
            for mode in [
                EcdsaSighashType::All,
                EcdsaSighashType::None,
                EcdsaSighashType::Single,
                EcdsaSighashType::AllPlusAnyoneCanPay,
                EcdsaSighashType::NonePlusAnyoneCanPay,
                EcdsaSighashType::SinglePlusAnyoneCanPay,
            ] {
                for extra in [false, true] {
                    let raw = broad_spend(&i, mode, extra, false);
                    let m = monitor_spend(&i, &raw).unwrap();
                    assert_eq!(m.path, SpendPath::Claim { preimage: [42; 32] });
                    assert_eq!(m.input_index, usize::from(extra));
                    assert!(
                        i.verify_lock_spend(i.expected_txid().unwrap(), &raw)
                            .is_err()
                    );
                    vectors.push(serde_json::json!({"raw":hex::encode(&raw),"input":m.input_index,"sighash":mode as u32,"txid":m.txid.to_string()}));
                    let mut altered = tx(&raw, MAX_PREVIOUS_TX).unwrap();
                    altered.input[m.input_index].previous_output.vout = 1;
                    assert!(monitor_spend(&i, &serialize(&altered)).is_err());
                }
            }
            // High-S is a relay-policy distinction, not a reason to lose a
            // revealed preimage from a consensus-valid v0 witness signature.
            let mut high = tx(
                &broad_spend(&i, EcdsaSighashType::All, false, false),
                MAX_PREVIOUS_TX,
            )
            .unwrap();
            let mut witness: Vec<Vec<u8>> =
                high.input[0].witness.iter().map(|x| x.to_vec()).collect();
            let parsed = bitcoin::ecdsa::Signature::from_slice(&witness[0]).unwrap();
            let mut compact = parsed.signature.serialize_compact();
            let order =
                hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                    .unwrap();
            let mut borrow = 0i16;
            for n in (0..32).rev() {
                let diff = order[n] as i16 - compact[n + 32] as i16 - borrow;
                compact[n + 32] = diff as u8;
                borrow = i16::from(diff < 0);
            }
            witness[0] = bitcoin::ecdsa::Signature {
                sighash_type: EcdsaSighashType::All,
                signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact).unwrap(),
            }
            .to_vec();
            high.input[0].witness = bitcoin::Witness::from_slice(&witness);
            assert_eq!(
                monitor_spend(&i, &serialize(&high)).unwrap().path,
                SpendPath::Claim { preimage: [42; 32] }
            );
            std::fs::write(c.base.join("recovery-vectors.json"),serde_json::to_vec_pretty(&serde_json::json!({"synthetic_only":true,"production":false,"value":100000,"script":hex::encode(lock_script(i.condition,&i.terms).unwrap().as_bytes()),"recipient":hex::encode(i.terms.recipient),"vectors":vectors})).unwrap()).unwrap();
        }
        #[test]
        fn r4_secret_knowledge_survives_invalid_signature_without_payment_authority() {
            let mut c = campaign("r4-secret-hint");
            let (i, _) = signed(&mut c);
            let mut t = tx(
                &broad_spend(&i, EcdsaSighashType::All, true, false),
                MAX_PREVIOUS_TX,
            )
            .unwrap();
            let mut w: Vec<Vec<u8>> = t.input[1].witness.iter().map(|x| x.to_vec()).collect();
            w[0] = vec![1, 2, 3];
            t.input[1].witness = bitcoin::Witness::from_slice(&w);
            let raw = serialize(&t);
            assert!(monitor_spend(&i, &raw).is_err());
            assert_eq!(recover_preimage_hint(&i, &raw).unwrap(), Some([42; 32]));
            let mut r = RecoveryJournal::open(&c.base.join("recovery.sqlite")).unwrap();
            r.observe_preimage_hint(&i, &raw).unwrap();
            drop(r);
            let mut r = RecoveryJournal::open(&c.base.join("recovery.sqlite")).unwrap();
            let a = BlockArchive::open(&c.base.join("blocks.sqlite")).unwrap();
            let h = RegtestHeaders::new();
            assert_eq!(r.known_preimages(&i).unwrap(), vec![[42; 32]]);
            assert_eq!(
                assess(&mut r, &i, &c, &a, &h).unwrap().status,
                PairStatus::Pending
            );
            t.input[1].previous_output.vout = 1;
            assert_eq!(recover_preimage_hint(&i, &serialize(&t)).unwrap(), None);
        }
        #[test]
        fn r4_full_block_witness_merkle_tampering_and_persistence() {
            let mut c = campaign("r4-block-integrity");
            let (i, raw) = signed(&mut c);
            let mut h = RegtestHeaders::new();
            let mut a = BlockArchive::open(&c.base.join("blocks.sqlite")).unwrap();
            let b = full_block(
                &mut h,
                RegtestHeaders::new().tip().0,
                vec![tx(&raw, MAX_PREVIOUS_TX).unwrap()],
                0,
            );
            let mut bad = b.clone();
            bad.txdata[1].input[0].witness = bitcoin::Witness::from_slice(&[vec![1], vec![2]]);
            assert_eq!(bad.txdata[1].compute_txid(), i.expected_txid().unwrap());
            assert!(a.insert(&serialize(&bad), &h).is_err());
            assert_eq!(a.insert(&serialize(&b), &h).unwrap(), b.block_hash());
            assert_eq!(a.insert(&serialize(&b), &h).unwrap(), b.block_hash());
            let mut bad = b.clone();
            bad.txdata[1].output[0].value = Amount::from_sat(1);
            assert!(a.insert(&serialize(&bad), &h).is_err());
            let mut trailing = serialize(&b);
            trailing.push(0);
            assert!(a.insert(&trailing, &h).is_err());
            drop(a);
            let a = BlockArchive::open(&c.base.join("blocks.sqlite")).unwrap();
            assert_eq!(
                a.included(b.block_hash(), i.expected_txid().unwrap(), &h)
                    .unwrap()
                    .0,
                tx(&raw, MAX_PREVIOUS_TX).unwrap()
            );
        }
        #[test]
        fn r4_prevout_complete_scan_gaps_spend_reorg_and_coinbase_maturity() {
            let mut c = campaign("r4-prevout-scan");
            let i = intent(&mut c);
            let prev = tx(&i.terms.inputs[0].previous_transaction, MAX_PREVIOUS_TX).unwrap();
            let mut h = RegtestHeaders::new();
            let mut a = BlockArchive::open(&c.base.join("blocks.sqlite")).unwrap();
            let first = archive_block(&mut a, &mut h, vec![prev.clone()]);
            let gap = full_block(&mut h, first.block_hash(), vec![], 0);
            assert!(
                a.verify_intent_inputs(&i, &[first.block_hash()], &h, &safety())
                    .is_err()
            );
            a.insert(&serialize(&gap), &h).unwrap();
            a.verify_intent_inputs(&i, &[first.block_hash()], &h, &safety())
                .unwrap();
            assert!(
                a.prevout(&serialize(&first.txdata[0]), 0, first.block_hash(), &h)
                    .is_err()
            );
            let spend = tx(&i.unsigned, MAX_PREVIOUS_TX).unwrap();
            let spent = archive_block(&mut a, &mut h, vec![spend.clone()]);
            assert!(
                matches!(a.prevout(&serialize(&prev),0,first.block_hash(),&h).unwrap(),PrevoutState::Spent{transaction,..} if transaction==spend.compute_txid())
            );
            assert!(
                a.verify_intent_inputs(&i, &[first.block_hash()], &h, &safety())
                    .is_err()
            );
            let fork = full_block(&mut h, gap.block_hash(), vec![], 1);
            a.insert(&serialize(&fork), &h).unwrap();
            let fork2 = full_block(&mut h, fork.block_hash(), vec![], 0);
            a.insert(&serialize(&fork2), &h).unwrap();
            assert!(h.depth(spent.block_hash()).is_err());
            a.verify_intent_inputs(&i, &[first.block_hash()], &h, &safety())
                .unwrap();
            let mut altered = prev;
            altered.output[0].value = Amount::from_sat(1);
            assert!(
                a.prevout(&serialize(&altered), 0, first.block_hash(), &h)
                    .is_err()
            );
            for _ in h.tip().1..100 {
                archive_block(&mut a, &mut h, vec![]);
            }
            assert!(matches!(
                a.prevout(&serialize(&first.txdata[0]), 0, first.block_hash(), &h)
                    .unwrap(),
                PrevoutState::UnspentUnderSpv { depth: 100, .. }
            ));
        }
        #[test]
        fn r4_two_leg_receipt_restart_reorg_and_retained_preimage() {
            let mut c = campaign("r4-two-leg");
            let (i, raw) = signed(&mut c);
            let mut h = RegtestHeaders::new();
            let mut a = BlockArchive::open(&c.base.join("blocks.sqlite")).unwrap();
            let funding = archive_block(&mut a, &mut h, vec![tx(&raw, MAX_PREVIOUS_TX).unwrap()]);
            let spending = tx(
                &broad_spend(&i, EcdsaSighashType::SinglePlusAnyoneCanPay, true, false),
                MAX_PREVIOUS_TX,
            )
            .unwrap();
            let spent = archive_block(&mut a, &mut h, vec![spending.clone()]);
            let mut r = RecoveryJournal::open(&c.base.join("recovery.sqlite")).unwrap();
            r.observe_bitcoin_spend(&i, spent.block_hash(), spending.compute_txid(), &a, &h)
                .unwrap();
            assert_eq!(
                assess(&mut r, &i, &c, &a, &h).unwrap().status,
                PairStatus::BitcoinIncluded
            );
            archive_block(&mut a, &mut h, vec![]);
            assert_eq!(
                assess(&mut r, &i, &c, &a, &h).unwrap().status,
                PairStatus::BitcoinClaimed
            );
            let claim = native_claim(&c);
            assert!(
                r.observe_native_terminal(&i, &claim.encode().unwrap(), &c.store, &policy())
                    .is_err()
            );
            commit(&mut c, claim.encode().unwrap());
            r.observe_native_terminal(&i, &claim.encode().unwrap(), &c.store, &policy())
                .unwrap();
            let receipt = assess(&mut r, &i, &c, &a, &h).unwrap();
            assert_eq!(receipt.status, PairStatus::SettledUnderSpv);
            assert_eq!(receipt.treasury, c.frozen.address());
            let proof = treasury_credit_evidence(&i, &claim.encode().unwrap(), &c.store, &policy())
                .unwrap();
            assert_eq!(proof.anchor.height, 2);
            assert_eq!(proof.root, receipt.native_root);
            assert_eq!(receipt.funding_fee_satoshis, 1000);
            assert_eq!(receipt.mut_terminal_fee_strikes, Some(20000));
            assert_eq!(Assessment::decode(&receipt.encode()).unwrap(), receipt);
            let encoded = receipt.encode();
            for n in 0..encoded.len() {
                assert!(Assessment::decode(&encoded[..n]).is_err());
            }
            let mut nonminimal = encoded.clone();
            assert_eq!(nonminimal[0], 0x98);
            assert_eq!(nonminimal[1], 25);
            nonminimal.splice(0..2, [0x99, 0, 25]);
            assert!(Assessment::decode(&nonminimal).is_err());
            let mut trailing = encoded;
            trailing.push(0);
            assert!(Assessment::decode(&trailing).is_err());
            spend_native_credit(&mut c, &claim);
            assert_eq!(assess(&mut r, &i, &c, &a, &h).unwrap(), receipt);
            let later = treasury_credit_evidence(&i, &claim.encode().unwrap(), &c.store, &policy())
                .unwrap();
            assert_eq!(later.principal, proof.principal);
            assert_eq!(later.anchor, proof.anchor);
            assert!(!receipt.encode().windows(32).any(|x| x == [42; 32]));
            std::fs::write(
                c.base.join("audit-receipt.hex"),
                hex::encode(receipt.encode()),
            )
            .unwrap();
            drop(r);
            drop(a);
            let mut r = RecoveryJournal::open(&c.base.join("recovery.sqlite")).unwrap();
            let mut a = BlockArchive::open(&c.base.join("blocks.sqlite")).unwrap();
            assert_eq!(assess(&mut r, &i, &c, &a, &h).unwrap(), receipt);
            let mut fork = full_block(&mut h, funding.block_hash(), vec![], 10);
            a.insert(&serialize(&fork), &h).unwrap();
            for _ in 0..2 {
                fork = full_block(&mut h, fork.block_hash(), vec![], 0);
                a.insert(&serialize(&fork), &h).unwrap();
            }
            assert_eq!(
                assess(&mut r, &i, &c, &a, &h).unwrap().status,
                PairStatus::Reorged
            );
            assert_eq!(r.known_preimages(&i).unwrap(), vec![[42; 32]]);
            assert_eq!(
                c.journal.reconcile(c.operation, 0).unwrap().1,
                Stage::Signed
            );
            drop(a);
            drop(h);
            drop(r);
            let recovered = RecoveryJournal::open(&c.base.join("recovery.sqlite")).unwrap();
            assert_eq!(recovered.known_preimages(&i).unwrap(), vec![[42; 32]]);
        }
        #[test]
        fn r4_refund_observation_requires_exact_timelock_and_conflict_freezes() {
            let mut c = campaign("r4-refund-recovery");
            let (i, raw) = signed(&mut c);
            let mut h = RegtestHeaders::new();
            let mut a = BlockArchive::open(&c.base.join("blocks.sqlite")).unwrap();
            archive_block(&mut a, &mut h, vec![tx(&raw, MAX_PREVIOUS_TX).unwrap()]);
            let refund = tx(
                &broad_spend(&i, EcdsaSighashType::None, true, true),
                MAX_PREVIOUS_TX,
            )
            .unwrap();
            let premature = archive_block(&mut a, &mut h, vec![refund.clone()]);
            let mut r = RecoveryJournal::open(&c.base.join("recovery.sqlite")).unwrap();
            assert_eq!(
                r.observe_bitcoin_spend(&i, premature.block_hash(), refund.compute_txid(), &a, &h),
                Err(Error::Deadline)
            );
            // Separate fork excludes the premature, consensus-invalid fixture.
            let original_parent = premature.header.prev_blockhash;
            let mut b = full_block(&mut h, original_parent, vec![], 1);
            a.insert(&serialize(&b), &h).unwrap();
            for _ in 2..100 {
                b = full_block(&mut h, b.block_hash(), vec![], 0);
                a.insert(&serialize(&b), &h).unwrap();
            }
            let b = archive_block(&mut a, &mut h, vec![refund.clone()]);
            assert_eq!(h.tip().1, 101);
            r.observe_bitcoin_spend(&i, b.block_hash(), refund.compute_txid(), &a, &h)
                .unwrap();
            archive_block(&mut a, &mut h, vec![]);
            assert_eq!(
                assess(&mut r, &i, &c, &a, &h).unwrap().status,
                PairStatus::BitcoinRefunded
            );
            assert!(r.known_preimages(&i).unwrap().is_empty());
            // An externally included conflict freezes; it grants no repayment.
            let mut conflicting = tx(&raw, MAX_PREVIOUS_TX).unwrap();
            conflicting.output[0].value = Amount::from_sat(1);
            let parent = h.tip().0;
            let id = mine(
                &mut h,
                parent,
                conflicting.compute_txid().to_byte_array(),
                0,
            );
            c.journal
                .observe_conflict(
                    c.operation,
                    0,
                    &serialize(&conflicting),
                    &Inclusion {
                        block: id,
                        index: 0,
                        total_transactions: 1,
                        branch: vec![],
                    },
                    &h,
                )
                .unwrap();
            assert_eq!(
                assess(&mut r, &i, &c, &a, &h).unwrap().status,
                PairStatus::Conflicted
            );
        }
        #[test]
        fn r4_bounded_hostile_monitor_input_no_panics() {
            let mut c = campaign("r4-hostile");
            let i = intent(&mut c);
            let raw = broad_spend(&i, EcdsaSighashType::All, true, false);
            for n in 0..1200usize {
                let mut bad = raw.clone();
                if n % 3 == 0 {
                    bad.truncate(n % raw.len());
                } else {
                    let ix = n % bad.len();
                    bad[ix] ^= ((n / 3) % 255 + 1) as u8;
                }
                assert!(
                    std::panic::catch_unwind(|| {
                        let _ = monitor_spend(&i, &bad);
                        let _ = recover_preimage_hint(&i, &bad);
                    })
                    .is_ok()
                );
            }
            assert!(monitor_spend(&i, &vec![0; 32769]).is_err());
        }
        #[test]
        fn r4_both_refunds_canonical_commit_and_cross_leg_dispute() {
            let mut c = campaign_with_deadlines("r4-both-refunds", true, 6, 3);
            let mut terms = terms();
            terms.refund_height = 4;
            terms.expiry_mut_height = 3;
            let assumption = OfflineSafety::qualification(1, 1, 2).unwrap_err();
            assert_eq!(assumption, Error::Deadline);
            let assumption = OfflineSafety::qualification(1, 2, 2).unwrap();
            let mut h = RegtestHeaders::new();
            let i = c
                .journal
                .prepare(&c.store, c.operation, &c.funding, terms, &h, &assumption)
                .unwrap();
            let auth = authorization(&i);
            c.journal
                .begin_sign(&c.store, c.operation, 0, &auth, &h, &assumption)
                .unwrap();
            let raw = external_sign(&i, &auth);
            c.journal.record_signed(c.operation, 0, &raw).unwrap();
            let mut a = BlockArchive::open(&c.base.join("blocks.sqlite")).unwrap();
            let funding = archive_block(&mut a, &mut h, vec![tx(&raw, MAX_PREVIOUS_TX).unwrap()]);
            for _ in 1..4 {
                archive_block(&mut a, &mut h, vec![]);
            }
            let refund = tx(
                &broad_spend(&i, EcdsaSighashType::All, false, true),
                MAX_PREVIOUS_TX,
            )
            .unwrap();
            let b = archive_block(&mut a, &mut h, vec![refund.clone()]);
            archive_block(&mut a, &mut h, vec![]);
            let mut r = RecoveryJournal::open(&c.base.join("recovery.sqlite")).unwrap();
            r.observe_bitcoin_spend(&i, b.block_hash(), refund.compute_txid(), &a, &h)
                .unwrap();
            let sender =
                HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner)
                    .unwrap();
            let point = mutiny_consensus_v8::transactions::OutPoint {
                transaction: c.funding.operation.id().unwrap(),
                index: 1,
            };
            let mut op = tr::Operation {
                meta: tr::Meta {
                    context: c.funding.operation.meta.context.clone(),
                    trade: c.frozen.trade(),
                    contract: c.frozen.contract(),
                    generation: 1,
                    created: 6,
                    expiry: 10,
                    fee: tr::Strikes(20000),
                    inputs: vec![tr::native_input_id(&point)],
                },
                action: tr::Action::Refund {
                    output: c.funding.operation.output_id(0).unwrap(),
                    owner: sender.public().address_id(1).unwrap(),
                    amount: tr::Strikes(50000),
                    change: tr::Strikes(10000),
                },
                approvals: vec![],
                offer_proof: None,
            };
            op.approve(0, &sender, 1).unwrap();
            let refund_native = tr::NativeOperation {
                operation: op,
                inputs: vec![point],
            };
            for _ in 1..5 {
                commit(&mut c, vec![]);
            }
            assert!(
                r.observe_native_terminal(
                    &i,
                    &refund_native.encode().unwrap(),
                    &c.store,
                    &policy()
                )
                .is_err()
            );
            commit(&mut c, refund_native.encode().unwrap());
            r.observe_native_terminal(&i, &refund_native.encode().unwrap(), &c.store, &policy())
                .unwrap();
            let result = assess(&mut r, &i, &c, &a, &h).unwrap();
            assert_eq!(result.status, PairStatus::RefundedUnderSpv);
            assert_eq!(result.native_outcome, NativeOutcome::Refunded);
            drop(r);
            let mut r = RecoveryJournal::open(&c.base.join("recovery.sqlite")).unwrap();
            assert_eq!(assess(&mut r, &i, &c, &a, &h).unwrap(), result);
            let claim = tx(
                &broad_spend(&i, EcdsaSighashType::All, false, false),
                MAX_PREVIOUS_TX,
            )
            .unwrap();
            let claimed = full_block(&mut h, funding.block_hash(), vec![claim.clone()], 12);
            a.insert(&serialize(&claimed), &h).unwrap();
            let mut fork = claimed.clone();
            for _ in 2..7 {
                fork = full_block(&mut h, fork.block_hash(), vec![], 0);
                a.insert(&serialize(&fork), &h).unwrap();
            }
            r.observe_bitcoin_spend(&i, claimed.block_hash(), claim.compute_txid(), &a, &h)
                .unwrap();
            assert_eq!(
                assess(&mut r, &i, &c, &a, &h).unwrap().status,
                PairStatus::Disputed
            );
            assert_eq!(
                c.journal.reconcile(c.operation, 0).unwrap().1,
                Stage::Signed
            );
        }
        #[test]
        fn r4_block_and_recovery_journal_abrupt_commit_boundaries() {
            let mut c = campaign("r4-evidence-crashes");
            let (i, raw) = signed(&mut c);
            let hint = broad_spend(&i, EcdsaSighashType::All, false, false);
            let mut h = RegtestHeaders::new();
            let g = h.tip().0;
            let block = full_block(&mut h, g, vec![tx(&raw, MAX_PREVIOUS_TX).unwrap()], 0);
            for phase in [
                "block_before_commit",
                "block_after_commit",
                "event_before_commit",
                "event_after_commit",
            ] {
                let dir = c.base.join(phase);
                std::fs::create_dir(&dir).unwrap();
                let input = serde_json::json!({"intent":hex::encode(i.encode().unwrap()),"hint":hex::encode(&hint),"block":hex::encode(serialize(&block))});
                std::fs::write(
                    dir.join("input.json"),
                    serde_json::to_vec_pretty(&input).unwrap(),
                )
                .unwrap();
                let result = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "trading_service_v1::bitcoin_candidate::tests::recovery_crash_worker",
                        "--nocapture",
                    ])
                    .env("RECOVERY_CRASH_PHASE", phase)
                    .env("RECOVERY_CRASH_DIR", &dir)
                    .output()
                    .unwrap();
                std::fs::write(dir.join("worker.stdout.log"), result.stdout).unwrap();
                std::fs::write(dir.join("worker.stderr.log"), result.stderr).unwrap();
                assert_eq!(result.status.code(), Some(86));
                let filename = if phase.starts_with("block") {
                    "blocks.sqlite"
                } else {
                    "recovery.sqlite"
                };
                let table = if phase.starts_with("block") {
                    "recovery_block"
                } else {
                    "recovery_event"
                };
                let conn = Connection::open(dir.join(filename)).unwrap();
                let count: i64 = conn
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                assert_eq!(count, i64::from(phase.ends_with("after_commit")));
                drop(conn);
                let mut a = BlockArchive::open(&dir.join("blocks.sqlite")).unwrap();
                a.insert(&serialize(&block), &h).unwrap();
                a.insert(&serialize(&block), &h).unwrap();
                let mut r = RecoveryJournal::open(&dir.join("recovery.sqlite")).unwrap();
                r.observe_preimage_hint(&i, &hint).unwrap();
                r.observe_preimage_hint(&i, &hint).unwrap();
                assert_eq!(r.known_preimages(&i).unwrap(), vec![[42; 32]]);
                let conn = Connection::open(dir.join(filename)).unwrap();
                let count: i64 = conn
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                assert_eq!(count, 1);
            }
        }
        #[test]
        #[ignore = "subprocess-only R4 evidence crash worker"]
        fn recovery_crash_worker() {
            let dir = PathBuf::from(std::env::var_os("RECOVERY_CRASH_DIR").unwrap());
            let phase = std::env::var("RECOVERY_CRASH_PHASE").unwrap();
            let input: serde_json::Value =
                serde_json::from_slice(&std::fs::read(dir.join("input.json")).unwrap()).unwrap();
            let raw = |key: &str| hex::decode(input[key].as_str().unwrap()).unwrap();
            if phase.starts_with("block") {
                let b: bitcoin::Block = deserialize(&raw("block")).unwrap();
                let mut h = RegtestHeaders::new();
                h.insert(&serialize(&b.header), b.header.time).unwrap();
                BlockArchive::open(&dir.join("blocks.sqlite"))
                    .unwrap()
                    .insert(&raw("block"), &h)
                    .unwrap();
            } else {
                let i = TreasurySwapIntent::decode(&raw("intent")).unwrap();
                RecoveryJournal::open(&dir.join("recovery.sqlite"))
                    .unwrap()
                    .observe_preimage_hint(&i, &raw("hint"))
                    .unwrap();
            }
            panic!("crash boundary not reached");
        }

        use super::super::completion_candidate as completion;
        #[cfg(feature = "trading-local-storage-candidate")]
        mod encrypted_r6 {
            use super::*;
            use crate::trading_service_v1::local_storage_candidate::{
                self as local, EncryptedCompletion, StorageContext, StorageKey,
                bitcoin_headers::HeaderStore,
            };
            use zeroize::Zeroizing;
            #[test]
            fn r6_encrypted_completion_ten_abrupt_persistence_boundaries() {
                let c = campaign("r6-storage-crashes");
                let native = native_claim(&c);
                let id = native.operation.id().unwrap();
                let k = key();
                let ctx = context(&c.funding);
                for phase in [
                    "sealed_before_commit",
                    "sealed_after_commit",
                    "completion_prepare_after_inner",
                    "completion_prepare_after_seal",
                    "completion_request_after_inner",
                    "completion_request_after_seal",
                    "completion_approval_after_inner",
                    "completion_approval_after_seal",
                    "completion_dispatch_after_inner",
                    "completion_dispatch_after_seal",
                ] {
                    let dir = c.base.join(phase);
                    std::fs::create_dir(&dir).unwrap();
                    let path = dir.join("encrypted.sqlite");
                    let mut j =
                        EncryptedCompletion::create(&path, &k, ctx.clone(), policy()).unwrap();
                    let min = j.checkpoint().unwrap();
                    let preparing = phase.contains("prepare") || phase.starts_with("sealed_");
                    if !preparing {
                        assert_eq!(
                            j.prepare(
                                &c.store,
                                &c.funding,
                                completion::PathChoice::Claim([42; 32]),
                                completion_fees()
                            )
                            .unwrap(),
                            id
                        );
                    }
                    if phase.contains("approval") || phase.contains("dispatch") {
                        j.request_approval(
                            &c.store,
                            id,
                            0,
                            native.operation.approvals[0].descriptor.clone(),
                        )
                        .unwrap();
                    }
                    if phase.contains("dispatch") {
                        j.accept_approval(
                            &c.store,
                            id,
                            0,
                            native.operation.approvals[0].signature.clone(),
                        )
                        .unwrap();
                    }
                    drop(j);
                    let records: Vec<_> =
                        c.f.state
                            .records()
                            .unwrap()
                            .iter()
                            .map(|(k, v)| vec![hex::encode(k), hex::encode(v)])
                            .collect();
                    let input = serde_json::json!({"root":hex::encode(c.f.state.root().unwrap()),"genesis":hex::encode(c.f.genesis.encode()),"records":records,"canonical_path":c.base.join("canonical.sqlite").to_str().unwrap(),"funding":hex::encode(c.funding.encode().unwrap()),"native":hex::encode(native.encode().unwrap()),"minimum_sequence":min.sequence,"minimum_commitment":hex::encode(min.commitment)});
                    std::fs::write(
                        dir.join("public.json"),
                        serde_json::to_vec_pretty(&input).unwrap(),
                    )
                    .unwrap();
                    let result=std::process::Command::new(std::env::current_exe().unwrap()).args(["--ignored","--exact","trading_service_v1::bitcoin_candidate::tests::encrypted_r6::storage_crash_worker","--nocapture"]).env("TRADING_STORAGE_CRASH",phase).env("TRADING_STORAGE_CASE",&dir).output().unwrap();
                    std::fs::write(dir.join("stdout.log"), result.stdout).unwrap();
                    std::fs::write(dir.join("stderr.log"), result.stderr).unwrap();
                    assert_eq!(result.status.code(), Some(86), "{phase}");
                    let mut j =
                        EncryptedCompletion::open(&path, &k, ctx.clone(), min, policy()).unwrap();
                    let stored = j
                        .find_by_locked_output(c.funding.operation.output_id(0).unwrap())
                        .unwrap();
                    let absent = phase == "sealed_before_commit"
                        || phase == "completion_prepare_after_inner";
                    assert_eq!(stored, if absent { None } else { Some(id) }, "{phase}");
                    if absent {
                        assert_eq!(
                            j.prepare(
                                &c.store,
                                &c.funding,
                                completion::PathChoice::Claim([42; 32]),
                                completion_fees()
                            )
                            .unwrap(),
                            id
                        );
                    }
                    if phase == "completion_request_after_seal" {
                        assert_eq!(j.reconcile_request(id, 0).unwrap().operation, id);
                        assert!(
                            j.request_approval(
                                &c.store,
                                id,
                                0,
                                native.operation.approvals[0].descriptor.clone()
                            )
                            .is_err()
                        );
                    } else if phase == "completion_request_after_inner" {
                        j.request_approval(
                            &c.store,
                            id,
                            0,
                            native.operation.approvals[0].descriptor.clone(),
                        )
                        .unwrap();
                    } else if phase == "completion_approval_after_inner" {
                        assert!(j.signed_bytes(id).is_err());
                        j.accept_approval(
                            &c.store,
                            id,
                            0,
                            native.operation.approvals[0].signature.clone(),
                        )
                        .unwrap();
                    } else if phase == "completion_approval_after_seal" {
                        assert_eq!(
                            j.signed_bytes(id).unwrap().as_slice(),
                            native.encode().unwrap()
                        );
                    } else if phase == "completion_dispatch_after_inner" {
                        j.dispatch(&c.store, id).unwrap();
                    } else if phase == "completion_dispatch_after_seal" {
                        assert_eq!(
                            j.reconcile(&c.store, id).unwrap(),
                            completion::Reconciliation::Pending
                        );
                        assert!(j.dispatch(&c.store, id).is_err());
                    }
                }
            }
            #[test]
            #[ignore = "subprocess entry for ten abrupt persistence boundaries"]
            fn storage_crash_worker() {
                let dir = PathBuf::from(std::env::var_os("TRADING_STORAGE_CASE").unwrap());
                let phase = std::env::var("TRADING_STORAGE_CRASH").unwrap();
                let input: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(dir.join("public.json")).unwrap())
                        .unwrap();
                let raw = |k: &str| hex::decode(input[k].as_str().unwrap()).unwrap();
                let root: Hash = raw("root").try_into().unwrap();
                let records: Vec<_> = input["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| {
                        (
                            hex::decode(r[0].as_str().unwrap())
                                .unwrap()
                                .try_into()
                                .unwrap(),
                            hex::decode(r[1].as_str().unwrap()).unwrap(),
                        )
                    })
                    .collect();
                let state = State::from_records(&records, root).unwrap();
                let genesis = FinalizedAnchor::decode(&raw("genesis")).unwrap();
                let store = CanonicalStore::open_trusted_genesis(
                    Path::new(input["canonical_path"].as_str().unwrap()),
                    &genesis,
                    &state,
                    root,
                    1000,
                    [255; 32],
                )
                .unwrap();
                let funding = tr::NativeOperation::decode(&raw("funding")).unwrap();
                let native = tr::NativeOperation::decode(&raw("native")).unwrap();
                let id = native.operation.id().unwrap();
                let k = key();
                let min = local::Checkpoint {
                    sequence: input["minimum_sequence"].as_u64().unwrap(),
                    commitment: raw("minimum_commitment").try_into().unwrap(),
                };
                let mut j = EncryptedCompletion::open(
                    &dir.join("encrypted.sqlite"),
                    &k,
                    context(&funding),
                    min,
                    policy(),
                )
                .unwrap();
                if phase.contains("prepare") || phase.starts_with("sealed_") {
                    j.prepare(
                        &store,
                        &funding,
                        completion::PathChoice::Claim([42; 32]),
                        completion_fees(),
                    )
                    .unwrap();
                } else if phase.contains("request") {
                    j.request_approval(
                        &store,
                        id,
                        0,
                        native.operation.approvals[0].descriptor.clone(),
                    )
                    .unwrap();
                } else if phase.contains("approval") {
                    j.accept_approval(
                        &store,
                        id,
                        0,
                        native.operation.approvals[0].signature.clone(),
                    )
                    .unwrap();
                } else {
                    j.dispatch(&store, id).unwrap();
                }
                panic!("crash point not reached");
            }

            fn key() -> StorageKey {
                StorageKey::qualification(Zeroizing::new([117; 32])).unwrap()
            }
            fn context(f: &tr::NativeOperation) -> StorageContext {
                let c = &f.operation.meta.context;
                StorageContext {
                    network: c.network,
                    genesis: c.genesis,
                    fingerprint: c.fingerprint,
                    storage: [118; 32],
                    key_generation: 1,
                }
            }
            fn approve(
                j: &mut EncryptedCompletion<'_>,
                c: &Campaign,
                id: Hash,
                slot: u8,
                k: &HybridKey,
            ) {
                let req = j
                    .request_approval(&c.store, id, slot, k.public().descriptor(1).unwrap())
                    .unwrap();
                let sig = k
                    .sign(mutiny_crypto_v2::Domain::Transaction, &req.payload)
                    .unwrap();
                j.accept_approval(&c.store, id, slot, sig).unwrap();
            }
            #[test]
            fn r6_encrypted_claim_public_audit_and_ambiguous_dispatch() {
                let mut c = campaign("r6-native-claim");
                let k = key();
                let ctx = context(&c.funding);
                let path = c.base.join("encrypted.sqlite");
                let mut j = EncryptedCompletion::create(&path, &k, ctx.clone(), policy()).unwrap();
                let minimum = j.checkpoint().unwrap();
                let secret = b"SYNTHETIC PRIVATE NOTE THAT MUST NEVER ENTER PUBLIC AUDIT";
                let note = j.private_note(secret).unwrap();
                let id = j
                    .prepare(
                        &c.store,
                        &c.funding,
                        completion::PathChoice::Claim([42; 32]),
                        completion_fees(),
                    )
                    .unwrap();
                approve(&mut j, &c, id, 0, &c.treasury);
                let signed = j.signed_bytes(id).unwrap();
                let submission = j.dispatch(&c.store, id).unwrap();
                assert_eq!(submission.bytes(), signed.as_slice());
                drop(j);
                let mut j =
                    EncryptedCompletion::open(&path, &k, ctx.clone(), minimum, policy()).unwrap();
                assert_eq!(
                    j.find_by_locked_output(c.funding.operation.output_id(0).unwrap())
                        .unwrap(),
                    Some(id)
                );
                assert_eq!(
                    j.reconcile(&c.store, id).unwrap(),
                    completion::Reconciliation::Pending
                );
                assert!(matches!(
                    j.dispatch(&c.store, id),
                    Err(local::Error::Completion(completion::Error::Ambiguous))
                ));
                drop(j);
                // Actual canonical commit; simulate a lost acknowledgement, no second submission.
                commit(&mut c, signed.to_vec());
                let mut j =
                    EncryptedCompletion::open(&path, &k, ctx.clone(), minimum, policy()).unwrap();
                assert!(matches!(
                    j.reconcile(&c.store, id).unwrap(),
                    completion::Reconciliation::Applied(_)
                ));
                let audit = j.capture_native_audit(&c.store, id).unwrap();
                let public = j.public_export(audit).unwrap();
                assert!(!public.windows(secret.len()).any(|w| w == secret));
                assert!(!public.windows(32).any(|w| w == [42; 32]));
                assert_eq!(j.public_export(note), Err(local::Error::NotPublic));
                let final_checkpoint = j.checkpoint().unwrap();
                drop(j);
                for suffix in ["", "-wal"] {
                    let f = PathBuf::from(format!("{}{suffix}", path.display()));
                    if f.exists() {
                        let b = std::fs::read(f).unwrap();
                        assert!(!b.windows(secret.len()).any(|w| w == secret));
                        assert!(!b.windows(signed.len()).any(|w| w == signed.as_slice()));
                    }
                }
                let j =
                    EncryptedCompletion::open(&path, &k, ctx, final_checkpoint, policy()).unwrap();
                assert_eq!(j.public_export(audit).unwrap(), public);
                assert_eq!(j.read_private_note(note).unwrap().as_slice(), secret);
                std::fs::write(c.base.join("public-audit.cbor"), public).unwrap();
                std::fs::write(c.base.join("public-audit-input.json"),serde_json::to_vec_pretty(&serde_json::json!({"wire":hex::encode(signed.as_slice()),"id":hex::encode(id),"production":false})).unwrap()).unwrap();
            }
            #[test]
            fn r6_encrypted_cooperative_fiat_restart_and_public_evidence() {
                let (mut c, seller) = fiat_campaign("r6-native-fiat");
                let k = key();
                let ctx = context(&c.funding);
                let path = c.base.join("encrypted.sqlite");
                let mut j = EncryptedCompletion::create(&path, &k, ctx.clone(), policy()).unwrap();
                let minimum = j.checkpoint().unwrap();
                assert!(matches!(
                    j.prepare(
                        &c.store,
                        &c.funding,
                        completion::PathChoice::FiatCooperative,
                        completion_fees()
                    ),
                    Err(local::Error::Completion(completion::Error::Missing))
                ));
                drop(j);
                let funding = c.funding.encode().unwrap();
                commit(&mut c, funding);
                let mut j =
                    EncryptedCompletion::open(&path, &k, ctx.clone(), minimum, policy()).unwrap();
                let id = j
                    .prepare(
                        &c.store,
                        &c.funding,
                        completion::PathChoice::FiatCooperative,
                        completion_fees(),
                    )
                    .unwrap();
                assert!(
                    j.request_approval(&c.store, id, 1, seller.public().descriptor(1).unwrap())
                        .is_err()
                );
                drop(j);
                let mut j =
                    EncryptedCompletion::open(&path, &k, ctx.clone(), minimum, policy()).unwrap();
                approve(&mut j, &c, id, 0, &c.treasury);
                assert!(j.signed_bytes(id).is_err());
                drop(j);
                let mut j =
                    EncryptedCompletion::open(&path, &k, ctx.clone(), minimum, policy()).unwrap();
                assert_eq!(
                    j.reconcile_request(id, 0).unwrap().purpose,
                    completion::Purpose::BuyerPaymentSent
                );
                approve(&mut j, &c, id, 1, &seller);
                let wire = j.dispatch(&c.store, id).unwrap().bytes().to_vec();
                drop(j);
                commit(&mut c, wire);
                let mut j = EncryptedCompletion::open(&path, &k, ctx, minimum, policy()).unwrap();
                assert!(matches!(
                    j.reconcile(&c.store, id).unwrap(),
                    completion::Reconciliation::Applied(_)
                ));
                let audit = j.capture_native_audit(&c.store, id).unwrap();
                let public = j.public_export(audit).unwrap();
                assert!(String::from_utf8_lossy(&public).contains("EXTERNAL_PAYMENT_NOT_ASSERTED"));
                std::fs::write(c.base.join("public-audit.cbor"), public).unwrap();
            }
            #[test]
            fn r6_encrypted_refund_exact_boundary_and_claim_exclusion() {
                let mut c = campaign_with_deadlines("r6-native-refund", true, 4, 3);
                let k = key();
                let ctx = context(&c.funding);
                let path = c.base.join("encrypted.sqlite");
                let mut j = EncryptedCompletion::create(&path, &k, ctx.clone(), policy()).unwrap();
                let minimum = j.checkpoint().unwrap();
                let fees = completion::FeeTerms {
                    inputs: vec![mutiny_consensus_v8::transactions::OutPoint {
                        transaction: c.funding.operation.id().unwrap(),
                        index: 1,
                    }],
                    fee: tr::Strikes(20000),
                    change: tr::Strikes(10000),
                    expiry: 8,
                };
                assert!(matches!(
                    j.prepare(
                        &c.store,
                        &c.funding,
                        completion::PathChoice::Refund,
                        fees.clone()
                    ),
                    Err(local::Error::Completion(completion::Error::Time))
                ));
                drop(j);
                commit(&mut c, vec![]);
                commit(&mut c, vec![]);
                let mut j =
                    EncryptedCompletion::open(&path, &k, ctx.clone(), minimum, policy()).unwrap();
                let id = j
                    .prepare(&c.store, &c.funding, completion::PathChoice::Refund, fees)
                    .unwrap();
                let sender =
                    HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner)
                        .unwrap();
                approve(&mut j, &c, id, 0, &sender);
                let wire = j.dispatch(&c.store, id).unwrap().bytes().to_vec();
                drop(j);
                commit(&mut c, wire);
                let mut j = EncryptedCompletion::open(&path, &k, ctx, minimum, policy()).unwrap();
                assert!(matches!(
                    j.reconcile(&c.store, id).unwrap(),
                    completion::Reconciliation::Applied(_)
                ));
                let audit = j.capture_native_audit(&c.store, id).unwrap();
                assert!(!j.public_export(audit).unwrap().is_empty());
                assert!(
                    tr::locked(
                        &current(&c.store).unwrap().1,
                        c.funding.operation.output_id(0).unwrap()
                    )
                    .is_err()
                );
            }
            #[test]
            fn r6_durable_header_forks_reopen_and_recovery_assessment() {
                let mut c = campaign("r6-header-recovery");
                let k = key();
                let ctx = context(&c.funding);
                let path = c.base.join("headers.sqlite");
                let mut hs = HeaderStore::create(&path, &k, ctx.clone(), &policy()).unwrap();
                let minimum = hs.checkpoint().unwrap();
                let (i, raw) = signed(&mut c);
                let mut h = RegtestHeaders::new();
                let mut a = BlockArchive::open(&c.base.join("archive.sqlite")).unwrap();
                let funded =
                    archive_block(&mut a, &mut h, vec![tx(&raw, MAX_PREVIOUS_TX).unwrap()]);
                let confirmed = archive_block(&mut a, &mut h, vec![]);
                for b in [&funded, &confirmed] {
                    hs.insert(&serialize(&b.header), b.header.time).unwrap();
                }
                let tip = hs.headers().unwrap().tip();
                let cp = hs.checkpoint().unwrap();
                assert_eq!(
                    hs.insert(&serialize(&confirmed.header), confirmed.header.time)
                        .unwrap(),
                    confirmed.block_hash()
                );
                assert_eq!(cp, hs.checkpoint().unwrap());
                drop(hs);
                let mut hs = HeaderStore::open(&path, &k, ctx.clone(), minimum, &policy()).unwrap();
                assert_eq!(hs.headers().unwrap().tip(), tip);
                let proof = Inclusion {
                    block: funded.block_hash(),
                    index: 1,
                    total_transactions: 2,
                    branch: vec![funded.txdata[0].compute_txid().to_byte_array()],
                };
                c.journal
                    .observe_inclusion(c.operation, 0, &proof, hs.headers().unwrap())
                    .unwrap();
                let mut r = RecoveryJournal::open(&c.base.join("recovery.sqlite")).unwrap();
                let mut journal = EncryptedCompletion::create(
                    &c.base.join("encrypted.sqlite"),
                    &k,
                    ctx.clone(),
                    policy(),
                )
                .unwrap();
                let reference = journal
                    .capture_treasury_assessment(
                        &mut r,
                        &i,
                        RecoveryView {
                            operations: &c.journal,
                            store: &c.store,
                            archive: &a,
                            headers: hs.headers().unwrap(),
                            safety: &safety(),
                            policy: &policy(),
                        },
                    )
                    .unwrap();
                let assessment =
                    Assessment::decode(&journal.public_export(reference).unwrap()).unwrap();
                assert_ne!(assessment.status, PairStatus::SettledUnderSpv);
                let mut fork = full_block(&mut h, RegtestHeaders::new().tip().0, vec![], 17);
                a.insert(&serialize(&fork), &h).unwrap();
                hs.insert(&serialize(&fork.header), fork.header.time)
                    .unwrap();
                for _ in 0..3 {
                    fork = full_block(&mut h, fork.block_hash(), vec![], 0);
                    a.insert(&serialize(&fork), &h).unwrap();
                    hs.insert(&serialize(&fork.header), fork.header.time)
                        .unwrap();
                }
                assert_ne!(hs.headers().unwrap().tip(), tip);
                let expected = hs.headers().unwrap().tip();
                let end = hs.checkpoint().unwrap();
                drop(hs);
                let mut hs = HeaderStore::open(&path, &k, ctx, end, &policy()).unwrap();
                assert_eq!(hs.headers().unwrap().tip(), expected);
                assert_eq!(
                    assess(&mut r, &i, &c, &a, hs.headers().unwrap())
                        .unwrap()
                        .status,
                    PairStatus::Reorged
                );
                let mut invalid = serialize(&fork.header);
                invalid[0] ^= 1;
                assert!(hs.insert(&invalid, 0).is_err());
                assert!(hs.insert(&invalid[..79], 0).is_err());
            }
        }

        #[cfg(feature = "trading-local-storage-candidate")]
        mod encrypted_r7 {
            use super::*;
            use crate::trading_service_v1::local_storage_candidate::{
                StorageContext, StorageKey,
                legacy_candidate::{DurableCheckpoint, Paths},
            };
            use std::sync::Arc;
            use zeroize::Zeroizing;
            fn key(n: u8) -> Arc<StorageKey> {
                Arc::new(StorageKey::qualification(Zeroizing::new([n; 32])).unwrap())
            }
            fn context(c: &Campaign, n: u8) -> StorageContext {
                let x = &c.funding.operation.meta.context;
                StorageContext {
                    network: x.network,
                    genesis: x.genesis,
                    fingerprint: x.fingerprint,
                    storage: [n; 32],
                    key_generation: 1,
                }
            }
            fn paths(c: &Campaign, label: &str) -> Paths {
                let p = c.base.join(label);
                std::fs::create_dir(&p).unwrap();
                Paths {
                    snapshot: p.join("cipher.sqlite"),
                    nonces: p.join("nonces.sqlite"),
                }
            }
            #[test]
            fn r7_real_engine_signer_archive_recovery_and_canonical_native_settlement() {
                let mut c = campaign_with_funding("r7-real-journals", false);
                let tp = paths(&c, "incomplete-creation");
                let tc = context(&c, 135);
                let tk = key(135);
                let mut incomplete =
                    OperationJournal::create_encrypted(&tp, tk.clone(), tc.clone(), policy())
                        .unwrap();
                let tmin = incomplete.storage_checkpoint().unwrap();
                assert_eq!(
                    incomplete.record_creation_with_recheck(&c.store, &c.frozen, || {
                        let reopened = OperationJournal::open_encrypted(
                            &tp,
                            tk.clone(),
                            tc.clone(),
                            tmin,
                            policy(),
                        )
                        .unwrap();
                        let blocked: i64 = reopened
                            .db
                            .query_row(
                                "SELECT blocked FROM treasury_creation WHERE operation=?1",
                                [c.operation.as_slice()],
                                |r| r.get(0),
                            )
                            .unwrap();
                        assert_eq!(blocked, 1);
                        Err(Error::State)
                    }),
                    Err(Error::State)
                );
                drop(incomplete);
                let mut incomplete =
                    OperationJournal::open_encrypted(&tp, tk, tc, tmin, policy()).unwrap();
                assert_eq!(
                    incomplete.record_creation(&c.store, &c.frozen),
                    Err(Error::Ambiguous)
                );
                drop(incomplete);
                let ep = paths(&c, "engine");
                let sp = paths(&c, "signer");
                let ap = paths(&c, "archive");
                let rp = paths(&c, "recovery");
                let ek = key(131);
                let sk = key(132);
                let ak = key(133);
                let rk = key(134);
                let ec = context(&c, 131);
                let sc = context(&c, 132);
                let ac = context(&c, 133);
                let rc = context(&c, 134);
                let mut engine =
                    OperationJournal::create_encrypted(&ep, ek.clone(), ec.clone(), policy())
                        .unwrap();
                assert_eq!(
                    engine.record_creation(&c.store, &c.frozen).unwrap(),
                    c.operation
                );
                let initial = engine.storage_checkpoint().unwrap();
                let mut stale = OperationJournal::open_encrypted(
                    &ep,
                    ek.clone(),
                    ec.clone(),
                    initial,
                    policy(),
                )
                .unwrap();
                let mut signer =
                    DedicatedSignerJournal::create_encrypted(&sp, sk.clone(), sc.clone(), policy())
                        .unwrap();
                assert_eq!(
                    signer.record_creation(&c.store, &c.frozen).unwrap(),
                    c.operation
                );
                let signer_initial = signer.storage_checkpoint().unwrap();
                c.journal = engine;
                let funding = c.funding.encode().unwrap();
                commit(&mut c, funding);
                let i = intent(&mut c);
                let auth = authorization(&i);
                let headers = RegtestHeaders::new();
                let request = c
                    .journal
                    .begin_sign(&c.store, c.operation, 0, &auth, &headers, &safety())
                    .unwrap();
                let signed_request = signer
                    .authorize_request(&c.store, &request.intent, &auth, &headers, &safety())
                    .unwrap();
                assert_eq!(request.intent, signed_request.intent);
                assert!(
                    stale
                        .prepare(
                            &c.store,
                            c.operation,
                            &c.funding,
                            terms(),
                            &headers,
                            &safety()
                        )
                        .is_err()
                );
                assert!(stale.storage_checkpoint().is_err());
                assert!(stale.reconcile(c.operation, 0).is_err());
                assert!(stale.reconcile_broadcast(c.operation, 0).is_err());
                drop(stale);
                // One synthetic external signature; never an actual Bitcoin RPC/signer call.
                let raw = external_sign(&i, &auth);
                let txid = signer.persist_signature(c.operation, 0, &raw).unwrap();
                drop(signer);
                let mut signer = DedicatedSignerJournal::open_encrypted(
                    &sp,
                    sk.clone(),
                    sc.clone(),
                    signer_initial,
                    policy(),
                )
                .unwrap();
                assert_eq!(
                    signer.cached_response(c.operation, 0).unwrap(),
                    Some(raw.clone())
                );
                assert!(matches!(
                    signer.authorize_request(&c.store, &request.intent, &auth, &headers, &safety()),
                    Err(Error::Ambiguous)
                ));
                c.journal
                    .record_signed(
                        c.operation,
                        0,
                        &signer.cached_response(c.operation, 0).unwrap().unwrap(),
                    )
                    .unwrap();
                let dispatch = c
                    .journal
                    .broadcast_request(&c.store, c.operation, 0, &headers, &safety())
                    .unwrap();
                assert_eq!(dispatch.txid, txid);
                assert_eq!(dispatch.signed_bytes, raw); // Permit only, never broadcast.
                let replacement = OperationJournal::open_encrypted(
                    &ep,
                    ek.clone(),
                    ec.clone(),
                    initial,
                    policy(),
                )
                .unwrap();
                c.journal = replacement;
                assert_eq!(
                    c.journal
                        .reconcile_broadcast(c.operation, 0)
                        .unwrap()
                        .signed_bytes,
                    raw
                );
                assert!(matches!(
                    c.journal
                        .broadcast_request(&c.store, c.operation, 0, &headers, &safety()),
                    Err(Error::Ambiguous)
                ));
                let mut archive =
                    BlockArchive::create_encrypted(&ap, ak.clone(), ac.clone(), policy()).unwrap();
                let mut recovery =
                    RecoveryJournal::create_encrypted(&rp, rk.clone(), rc.clone(), policy())
                        .unwrap();
                let amin = archive.storage_checkpoint().unwrap();
                let rmin = recovery.storage_checkpoint().unwrap();
                let mut headers = RegtestHeaders::new();
                archive_block(
                    &mut archive,
                    &mut headers,
                    vec![tx(&raw, MAX_PREVIOUS_TX).unwrap()],
                );
                let spend = tx(
                    &broad_spend(&i, EcdsaSighashType::NonePlusAnyoneCanPay, true, false),
                    MAX_PREVIOUS_TX,
                )
                .unwrap();
                let spent = archive_block(&mut archive, &mut headers, vec![spend.clone()]);
                archive_block(&mut archive, &mut headers, vec![]);
                recovery
                    .observe_bitcoin_spend(
                        &i,
                        spent.block_hash(),
                        spend.compute_txid(),
                        &archive,
                        &headers,
                    )
                    .unwrap();
                assert_eq!(recovery.known_preimages(&i).unwrap(), vec![[42; 32]]);
                drop(recovery);
                drop(archive);
                let archive = BlockArchive::open_encrypted(&ap, ak, ac, amin, policy()).unwrap();
                let mut recovery =
                    RecoveryJournal::open_encrypted(&rp, rk, rc, rmin, policy()).unwrap();
                assert_eq!(recovery.known_preimages(&i).unwrap(), vec![[42; 32]]);
                let native = native_claim(&c).encode().unwrap();
                commit(&mut c, native.clone());
                recovery
                    .observe_native_terminal(&i, &native, &c.store, &policy())
                    .unwrap();
                let assessment = assess(&mut recovery, &i, &c, &archive, &headers).unwrap();
                assert_eq!(assessment.status, PairStatus::SettledUnderSpv);
                let proof = treasury_credit_evidence(&i, &native, &c.store, &policy()).unwrap();
                assert_eq!(proof.anchor.height, 2);
                let recheck = recovery.storage_checkpoint().unwrap();
                drop(recovery);
                for p in [&ep, &sp, &ap, &rp] {
                    for file in [&p.snapshot, &p.nonces] {
                        let bytes = std::fs::read(file).unwrap();
                        assert!(!bytes.windows(raw.len()).any(|b| b == raw));
                        assert!(!bytes.windows(32).any(|b| b == [42; 32]));
                    }
                }
                std::fs::write(c.base.join("encrypted-integration.json"),serde_json::to_vec_pretty(&serde_json::json!({"operation":hex::encode(c.operation),"txid":txid.to_string(),"native":hex::encode(native),"assessment":hex::encode(assessment.encode()),"recovery_generation":recheck.generation,"nonce_counter":recheck.nonce_counter,"fixture_scope":"SYNTHETIC KEYS; ACTUAL CANONICAL NATIVE; SPV BITCOIN FIXTURES; NO BROADCAST","production":false})).unwrap()).unwrap();
            }
            #[test]
            fn r7_five_abrupt_nonce_and_signed_bytes_boundaries() {
                let mut c = campaign_with_funding("r7-signed-crashes", false);
                let phases = [
                    "nonce_before_commit",
                    "nonce_after_commit",
                    "snapshot_after_encryption",
                    "snapshot_before_commit",
                    "snapshot_after_commit",
                ];
                let ctx = context(&c, 141);
                let k = key(141);
                let mut prepared = vec![];
                for phase in phases {
                    let p = paths(&c, phase);
                    let mut j =
                        OperationJournal::create_encrypted(&p, k.clone(), ctx.clone(), policy())
                            .unwrap();
                    j.record_creation(&c.store, &c.frozen).unwrap();
                    prepared.push((phase, p, j));
                }
                let funding = c.funding.encode().unwrap();
                commit(&mut c, funding);
                let i = intent(&mut c);
                let auth = authorization(&i);
                let raw = external_sign(&i, &auth);
                let headers = RegtestHeaders::new();
                let mut records = vec![];
                for (phase, p, mut j) in prepared {
                    let candidate = j
                        .prepare(
                            &c.store,
                            c.operation,
                            &c.funding,
                            terms(),
                            &headers,
                            &safety(),
                        )
                        .unwrap();
                    assert_eq!(candidate.encode().unwrap(), i.encode().unwrap());
                    j.begin_sign(&c.store, c.operation, 0, &auth, &headers, &safety())
                        .unwrap();
                    let min = j.storage_checkpoint().unwrap();
                    drop(j);
                    let dir = p.snapshot.parent().unwrap();
                    let input = serde_json::json!({"intent":hex::encode(i.encode().unwrap()),"signed":hex::encode(&raw),"generation":min.generation,"commitment":hex::encode(min.commitment),"nonce_counter":min.nonce_counter,"prefix":hex::encode(min.prefix)});
                    std::fs::write(
                        dir.join("public.json"),
                        serde_json::to_vec_pretty(&input).unwrap(),
                    )
                    .unwrap();
                    let result=std::process::Command::new(std::env::current_exe().unwrap()).args(["--ignored","--exact","trading_service_v1::bitcoin_candidate::tests::encrypted_r7::r7_signed_crash_worker","--nocapture"]).env("TRADING_STORAGE_CRASH",phase).env("TRADING_R7_CASE",dir).output().unwrap();
                    std::fs::write(dir.join("stdout.log"), result.stdout).unwrap();
                    std::fs::write(dir.join("stderr.log"), result.stderr).unwrap();
                    assert_eq!(result.status.code(), Some(86), "{phase}");
                    let mut j =
                        OperationJournal::open_encrypted(&p, k.clone(), ctx.clone(), min, policy())
                            .unwrap();
                    let recovered = j.storage_checkpoint().unwrap();
                    let (_, stage, bytes) = j.reconcile(c.operation, 0).unwrap();
                    let durable = phase == "snapshot_after_commit";
                    assert_eq!(
                        stage,
                        if durable {
                            Stage::Signed
                        } else {
                            Stage::SignDispatched
                        }
                    );
                    assert_eq!(bytes, if durable { Some(raw.clone()) } else { None });
                    assert!(
                        j.begin_sign(&c.store, c.operation, 0, &auth, &headers, &safety())
                            .is_err()
                    );
                    if phase == "nonce_before_commit" {
                        assert_eq!(recovered.nonce_counter, min.nonce_counter)
                    } else {
                        assert!(recovered.nonce_counter > min.nonce_counter)
                    }
                    if !durable {
                        j.record_signed(c.operation, 0, &raw).unwrap();
                        assert!(
                            j.storage_checkpoint().unwrap().nonce_counter > recovered.nonce_counter
                        );
                    } // exact cached response; no new signing
                    let end = j.storage_checkpoint().unwrap();
                    drop(j);
                    let j =
                        OperationJournal::open_encrypted(&p, k.clone(), ctx.clone(), end, policy())
                            .unwrap();
                    assert_eq!(j.reconcile(c.operation, 0).unwrap().2, Some(raw.clone()));
                    records.push(serde_json::json!({"phase":phase,"exit":86,"before_counter":min.nonce_counter,"recovered_counter":recovered.nonce_counter,"final_counter":end.nonce_counter,"operation":hex::encode(c.operation),"repeat_signature":false}));
                }
                std::fs::write(
                    c.base.join("crash-results.json"),
                    serde_json::to_vec_pretty(&records).unwrap(),
                )
                .unwrap();
            }
            #[test]
            #[ignore = "R7 abrupt encrypted journal subprocess only"]
            fn r7_signed_crash_worker() {
                let dir = PathBuf::from(std::env::var_os("TRADING_R7_CASE").unwrap());
                let v: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(dir.join("public.json")).unwrap())
                        .unwrap();
                let raw = |name: &str| hex::decode(v[name].as_str().unwrap()).unwrap();
                let i = TreasurySwapIntent::decode(&raw("intent")).unwrap();
                let a = i.frozen_offer().unwrap();
                let a = a.creation_anchor();
                let ctx = StorageContext {
                    network: a.network,
                    genesis: a.genesis,
                    fingerprint: a.fingerprint,
                    storage: [141; 32],
                    key_generation: 1,
                };
                let min = DurableCheckpoint {
                    generation: v["generation"].as_u64().unwrap(),
                    commitment: raw("commitment").try_into().unwrap(),
                    nonce_counter: v["nonce_counter"].as_u64().unwrap(),
                    prefix: raw("prefix").try_into().unwrap(),
                };
                let p = Paths {
                    snapshot: dir.join("cipher.sqlite"),
                    nonces: dir.join("nonces.sqlite"),
                };
                let mut j =
                    OperationJournal::open_encrypted(&p, key(141), ctx, min, policy()).unwrap();
                j.record_signed(i.operation, 0, &raw("signed")).unwrap();
                panic!("expected abrupt boundary");
            }
        }
        fn completion_fees() -> completion::FeeTerms {
            completion::FeeTerms {
                inputs: vec![mutiny_consensus_v8::transactions::OutPoint {
                    transaction: [181; 32],
                    index: 0,
                }],
                fee: tr::Strikes(20000),
                change: tr::Strikes(80000),
                expiry: 40,
            }
        }
        fn wallet_approve(
            j: &mut completion::Journal,
            c: &Campaign,
            id: Hash,
            slot: u8,
            key: &HybridKey,
        ) {
            let request = j
                .request_approval(&c.store, id, slot, key.public().descriptor(1).unwrap())
                .unwrap();
            let signature = key
                .sign(mutiny_crypto_v2::Domain::Transaction, &request.payload)
                .unwrap();
            j.accept_approval(&c.store, id, slot, signature).unwrap();
        }
        #[test]
        fn r5_spv_inspection_to_external_native_wallet_proof_and_reorg() {
            let mut c = campaign("r5-end-to-end");
            let (i, raw) = signed(&mut c);
            let mut h = RegtestHeaders::new();
            let mut a = BlockArchive::open(&c.base.join("blocks.sqlite")).unwrap();
            let previous = tx(&i.terms.inputs[0].previous_transaction, MAX_PREVIOUS_TX).unwrap();
            let created = archive_block(&mut a, &mut h, vec![previous]);
            archive_block(&mut a, &mut h, vec![]);
            let evidence = a
                .inspect_signed_funding(&i, &raw, &[created.block_hash()], &h, &safety())
                .unwrap();
            assert_eq!(evidence.intent_hash(), i.intent_hash().unwrap());
            assert_eq!(evidence.transaction(), i.expected_txid().unwrap());
            assert_eq!(evidence.inputs().len(), 1);
            assert!(evidence.scope().contains("NO_FULL_VALIDATION_OR_MEMPOOL"));
            evidence.recheck(&i, &h).unwrap();
            let mut altered = raw.clone();
            *altered.last_mut().unwrap() ^= 1;
            assert!(
                a.inspect_signed_funding(&i, &altered, &[created.block_hash()], &h, &safety())
                    .is_err()
            );
            let funded = archive_block(&mut a, &mut h, vec![tx(&raw, MAX_PREVIOUS_TX).unwrap()]);
            assert_eq!(evidence.recheck(&i, &h), Err(Error::Stale));
            assert!(
                a.inspect_signed_funding(&i, &raw, &[created.block_hash()], &h, &safety())
                    .is_err()
            );
            let claim_btc = tx(
                &broad_spend(&i, EcdsaSighashType::NonePlusAnyoneCanPay, true, false),
                MAX_PREVIOUS_TX,
            )
            .unwrap();
            let claimed = archive_block(&mut a, &mut h, vec![claim_btc.clone()]);
            archive_block(&mut a, &mut h, vec![]);
            let mut r = RecoveryJournal::open(&c.base.join("recovery.sqlite")).unwrap();
            r.observe_bitcoin_spend(&i, claimed.block_hash(), claim_btc.compute_txid(), &a, &h)
                .unwrap();
            let secret = r.known_preimages(&i).unwrap()[0];
            let path = c.base.join("completion.sqlite");
            let mut j = completion::Journal::open(&path, policy()).unwrap();
            let id = j
                .prepare(
                    &c.store,
                    &c.funding,
                    completion::PathChoice::Claim(secret),
                    completion_fees(),
                )
                .unwrap();
            assert_eq!(
                j.reconcile(&c.store, id).unwrap(),
                completion::Reconciliation::Pending
            );
            wallet_approve(&mut j, &c, id, 0, &c.treasury);
            let signed_native = j.signed_bytes(id).unwrap();
            let submission = j.dispatch(&c.store, id).unwrap();
            assert_eq!(submission.bytes(), signed_native);
            drop(j);
            let mut j = completion::Journal::open(&path, policy()).unwrap();
            assert!(matches!(
                j.dispatch(&c.store, id),
                Err(completion::Error::Ambiguous)
            ));
            assert_eq!(
                j.reconcile(&c.store, id).unwrap(),
                completion::Reconciliation::Pending
            );
            commit(&mut c, signed_native.clone()); // actual canonical execution, simulated lost acknowledgement
            assert!(matches!(
                j.reconcile(&c.store, id).unwrap(),
                completion::Reconciliation::Applied(_)
            ));
            r.observe_native_terminal(&i, &signed_native, &c.store, &policy())
                .unwrap();
            let proof = treasury_credit_evidence(&i, &signed_native, &c.store, &policy()).unwrap();
            assert_eq!(proof.anchor.height, 2);
            assert_eq!(
                assess(&mut r, &i, &c, &a, &h).unwrap().status,
                PairStatus::SettledUnderSpv
            );
            let mut fork = full_block(&mut h, funded.block_hash(), vec![], 12);
            a.insert(&serialize(&fork), &h).unwrap();
            for _ in 0..3 {
                fork = full_block(&mut h, fork.block_hash(), vec![], 0);
                a.insert(&serialize(&fork), &h).unwrap();
            }
            assert_eq!(
                assess(&mut r, &i, &c, &a, &h).unwrap().status,
                PairStatus::Reorged
            );
            assert!(matches!(
                j.dispatch(&c.store, id),
                Err(completion::Error::Ambiguous)
            ));
            assert_eq!(j.signed_bytes(id).unwrap(), signed_native);
            std::fs::write(c.base.join("completion-vector.json"),serde_json::to_vec_pretty(&serde_json::json!({"wire":hex::encode(&signed_native),"operation":hex::encode(id),"request_payload":hex::encode(j.reconcile_request(id,0).unwrap().payload),"scope":evidence.scope(),"production":false})).unwrap()).unwrap();
        }
        #[test]
        fn r5_refund_exact_boundary_and_expired_claim_never_dispatches() {
            let mut c = campaign_with_deadlines("r5-refund", true, 4, 3);
            let sender =
                HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner)
                    .unwrap();
            let mut claim =
                completion::Journal::open(&c.base.join("claim.sqlite"), policy()).unwrap();
            let mut fee = completion_fees();
            fee.expiry = 8;
            let id = claim
                .prepare(
                    &c.store,
                    &c.funding,
                    completion::PathChoice::Claim([42; 32]),
                    fee,
                )
                .unwrap();
            wallet_approve(&mut claim, &c, id, 0, &c.treasury);
            let mut refund =
                completion::Journal::open(&c.base.join("refund.sqlite"), policy()).unwrap();
            let fee = completion::FeeTerms {
                inputs: vec![mutiny_consensus_v8::transactions::OutPoint {
                    transaction: c.funding.operation.id().unwrap(),
                    index: 1,
                }],
                fee: tr::Strikes(20000),
                change: tr::Strikes(10000),
                expiry: 8,
            };
            assert_eq!(
                refund.prepare(
                    &c.store,
                    &c.funding,
                    completion::PathChoice::Refund,
                    fee.clone()
                ),
                Err(completion::Error::Time)
            );
            commit(&mut c, vec![]);
            commit(&mut c, vec![]);
            assert!(matches!(
                claim.dispatch(&c.store, id),
                Err(completion::Error::Time)
            ));
            let rid = refund
                .prepare(&c.store, &c.funding, completion::PathChoice::Refund, fee)
                .unwrap();
            wallet_approve(&mut refund, &c, rid, 0, &sender);
            let raw = refund.dispatch(&c.store, rid).unwrap().bytes().to_vec();
            commit(&mut c, raw);
            assert!(matches!(
                refund.reconcile(&c.store, rid).unwrap(),
                completion::Reconciliation::Applied(_)
            ));
            assert!(claim.dispatch(&c.store, id).is_err());
            assert_eq!(
                claim.reconcile(&c.store, id).unwrap(),
                completion::Reconciliation::LockedOutputUnavailable {
                    output: c.funding.operation.output_id(0).unwrap()
                }
            );
        }
        fn fiat_campaign(label: &str) -> (Campaign, HybridKey) {
            let mut c = campaign_with_funding(label, false);
            let sender =
                HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner)
                    .unwrap();
            let maker = HybridKey::generate(Role::Transport).unwrap();
            let offer = tr::SignedOffer::sign(
                tr::OfferBody {
                    context: c.funding.operation.meta.context.clone(),
                    descriptor: maker.public().descriptor(1).unwrap(),
                    nonce: [212; 32],
                    created: 0,
                    expiry: 40,
                    maker_side: 0,
                    terms: tr::OfferTerms::Fiat {
                        amount: tr::Strikes(50000),
                        payment_terms: [213; 32],
                    },
                },
                &maker,
            )
            .unwrap();
            let o = &mut c.funding.operation;
            o.meta.trade = [214; 32];
            o.meta.contract = [215; 32];
            o.action = tr::Action::FiatLock {
                offer: offer.body.id().unwrap(),
                maker: offer.body.maker().unwrap(),
                seller: sender.public().address_id(1).unwrap(),
                buyer: c.treasury.public().address_id(1).unwrap(),
                amount: tr::Strikes(50000),
                payment_terms: [213; 32],
                change: tr::Strikes(30000),
            };
            o.approvals.clear();
            o.offer_proof = Some(tr::OfferProof::sign(offer, o, &maker).unwrap());
            o.approve(0, &sender, 1).unwrap();
            o.approve(1, &c.treasury, 1).unwrap();
            (c, sender)
        }
        #[test]
        fn r5_fiat_confirmed_deposit_ordered_cooperative_release_and_restart() {
            let (mut c, seller) = fiat_campaign("r5-fiat");
            let path = c.base.join("completion.sqlite");
            let mut j = completion::Journal::open(&path, policy()).unwrap();
            assert_eq!(
                j.prepare(
                    &c.store,
                    &c.funding,
                    completion::PathChoice::FiatCooperative,
                    completion_fees()
                ),
                Err(completion::Error::Missing)
            );
            let raw = c.funding.encode().unwrap();
            commit(&mut c, raw);
            assert_eq!(
                j.prepare(
                    &c.store,
                    &c.funding,
                    completion::PathChoice::Refund,
                    completion_fees()
                ),
                Err(completion::Error::FiatRecoveryUnspecified)
            );
            let id = j
                .prepare(
                    &c.store,
                    &c.funding,
                    completion::PathChoice::FiatCooperative,
                    completion_fees(),
                )
                .unwrap();
            assert!(matches!(
                j.request_approval(&c.store, id, 1, seller.public().descriptor(1).unwrap()),
                Err(completion::Error::Authority)
            ));
            let req = j
                .request_approval(&c.store, id, 0, c.treasury.public().descriptor(1).unwrap())
                .unwrap();
            assert_eq!(req.purpose, completion::Purpose::BuyerPaymentSent);
            assert!(matches!(
                j.request_approval(&c.store, id, 0, req.descriptor.clone()),
                Err(completion::Error::Ambiguous)
            ));
            // Synthetic parties attest a fixture. No external fiat payment/receipt was observed.
            let sig = c
                .treasury
                .sign(mutiny_crypto_v2::Domain::Transaction, &req.payload)
                .unwrap();
            j.accept_approval(&c.store, id, 0, sig.clone()).unwrap();
            drop(j);
            let mut j = completion::Journal::open(&path, policy()).unwrap();
            j.accept_approval(&c.store, id, 0, sig).unwrap();
            assert!(j.signed_bytes(id).is_err());
            assert!(j.dispatch(&c.store, id).is_err());
            let req = j
                .request_approval(&c.store, id, 1, seller.public().descriptor(1).unwrap())
                .unwrap();
            assert_eq!(req.purpose, completion::Purpose::SellerReceiptApproval);
            let wrong = c
                .treasury
                .sign(mutiny_crypto_v2::Domain::Transaction, &req.payload)
                .unwrap();
            assert_eq!(
                j.accept_approval(&c.store, id, 1, wrong),
                Err(completion::Error::Authority)
            );
            let sig = seller
                .sign(mutiny_crypto_v2::Domain::Transaction, &req.payload)
                .unwrap();
            j.accept_approval(&c.store, id, 1, sig).unwrap();
            let wire = j.signed_bytes(id).unwrap();
            let submission = j.dispatch(&c.store, id).unwrap();
            assert_eq!(submission.bytes(), wire);
            commit(&mut c, wire.clone());
            assert!(matches!(
                j.reconcile(&c.store, id).unwrap(),
                completion::Reconciliation::Applied(_)
            ));
            let (_, state, _) = current(&c.store).unwrap();
            assert_eq!(
                state.coins[&mutiny_consensus_v8::transactions::OutPoint {
                    transaction: id,
                    index: 0
                }]
                    .output
                    .owner,
                c.treasury.public().address_id(1).unwrap()
            );
            assert!(tr::locked(&state, c.funding.operation.output_id(0).unwrap()).is_err());
            assert!(matches!(
                j.dispatch(&c.store, id),
                Err(completion::Error::Ambiguous)
            ));
            std::fs::write(c.base.join("fiat-vector.json"),serde_json::to_vec_pretty(&serde_json::json!({"wire":hex::encode(wire),"operation":hex::encode(id),"buyer_payload":hex::encode(j.reconcile_request(id,0).unwrap().payload),"seller_payload":hex::encode(j.reconcile_request(id,1).unwrap().payload),"fiat_truth":"SIMULATED_PARTY_APPROVALS_NO_EXTERNAL_PAYMENT","production":false})).unwrap()).unwrap();
        }
        #[test]
        fn r5_completion_rejects_tamper_wrong_authority_units_fee_and_inputs() {
            let c = campaign("r5-rejections");
            let path = c.base.join("completion.sqlite");
            let mut j = completion::Journal::open(&path, policy()).unwrap();
            assert!(matches!(
                completion::Journal::open(
                    &c.base.join("disabled.sqlite"),
                    tr::CandidatePolicy::disabled()
                ),
                Err(completion::Error::Gate)
            ));
            assert!(matches!(
                completion::Journal::open(
                    &c.base.join("units.sqlite"),
                    tr::CandidatePolicy::nonproduction_unresolved()
                ),
                Err(completion::Error::Unit)
            ));
            assert!(!c.base.join("disabled.sqlite").exists());
            assert!(!c.base.join("units.sqlite").exists());
            for index in 0..6 {
                let mut f = c.funding.clone();
                match index {
                    0 => f.operation.meta.context.network ^= 1,
                    1 => f.operation.meta.context.genesis[0] ^= 1,
                    2 => f.operation.meta.context.fingerprint[0] ^= 1,
                    3 => f.operation.meta.trade[0] ^= 1,
                    4 => f.operation.meta.contract[0] ^= 1,
                    _ => f.operation.meta.generation += 1,
                };
                assert!(
                    j.prepare(
                        &c.store,
                        &f,
                        completion::PathChoice::Claim([42; 32]),
                        completion_fees()
                    )
                    .is_err()
                );
            }
            assert_eq!(
                j.prepare(
                    &c.store,
                    &c.funding,
                    completion::PathChoice::Claim([41; 32]),
                    completion_fees()
                ),
                Err(completion::Error::Terms)
            );
            let mut f = completion_fees();
            f.fee = tr::Strikes(239);
            f.change = tr::Strikes(99761);
            assert_eq!(
                j.prepare(
                    &c.store,
                    &c.funding,
                    completion::PathChoice::Claim([42; 32]),
                    f
                ),
                Err(completion::Error::Fee)
            );
            let mut f = completion_fees();
            f.inputs.push(f.inputs[0].clone());
            assert_eq!(
                j.prepare(
                    &c.store,
                    &c.funding,
                    completion::PathChoice::Claim([42; 32]),
                    f
                ),
                Err(completion::Error::Duplicate)
            );
            // The 240 STRIKE floor never replaces a larger signed native size fee.
            let mut floor =
                completion::Journal::open(&c.base.join("fee-floor.sqlite"), policy()).unwrap();
            let mut floor_terms = completion_fees();
            floor_terms.fee = tr::Strikes(240);
            floor_terms.change = tr::Strikes(99760);
            let floor_id = floor
                .prepare(
                    &c.store,
                    &c.funding,
                    completion::PathChoice::Claim([42; 32]),
                    floor_terms,
                )
                .unwrap();
            let floor_req = floor
                .request_approval(
                    &c.store,
                    floor_id,
                    0,
                    c.treasury.public().descriptor(1).unwrap(),
                )
                .unwrap();
            let floor_sig = c
                .treasury
                .sign(mutiny_crypto_v2::Domain::Transaction, &floor_req.payload)
                .unwrap();
            assert!(
                floor
                    .accept_approval(&c.store, floor_id, 0, floor_sig)
                    .is_err()
            );
            assert!(floor.signed_bytes(floor_id).is_err());
            let id = j
                .prepare(
                    &c.store,
                    &c.funding,
                    completion::PathChoice::Claim([42; 32]),
                    completion_fees(),
                )
                .unwrap();
            let wrong =
                HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner)
                    .unwrap();
            assert!(matches!(
                j.request_approval(&c.store, id, 0, wrong.public().descriptor(1).unwrap()),
                Err(completion::Error::Authority)
            ));
            let req = j
                .request_approval(&c.store, id, 0, c.treasury.public().descriptor(1).unwrap())
                .unwrap();
            let mut payload = req.payload.clone();
            *payload.last_mut().unwrap() ^= 1;
            let sig = c
                .treasury
                .sign(mutiny_crypto_v2::Domain::Transaction, &payload)
                .unwrap();
            assert_eq!(
                j.accept_approval(&c.store, id, 0, sig),
                Err(completion::Error::Authority)
            );
            let valid = c
                .treasury
                .sign(mutiny_crypto_v2::Domain::Transaction, &req.payload)
                .unwrap();
            let mut bad = valid.clone();
            bad.ed448[0] ^= 1;
            assert_eq!(
                j.accept_approval(&c.store, id, 0, bad),
                Err(completion::Error::Authority)
            );
            let mut bad = valid.clone();
            bad.fndsa[0] ^= 1;
            assert_eq!(
                j.accept_approval(&c.store, id, 0, bad),
                Err(completion::Error::Authority)
            );
            j.accept_approval(&c.store, id, 0, valid).unwrap();
            // A parallel local handle receives neither a new approval nor a second dispatch.
            let mut second = completion::Journal::open(&path, policy()).unwrap();
            assert!(matches!(
                second.request_approval(&c.store, id, 0, req.descriptor),
                Err(completion::Error::Ambiguous)
            ));
            j.dispatch(&c.store, id).unwrap();
            assert!(matches!(
                second.dispatch(&c.store, id),
                Err(completion::Error::Ambiguous)
            ));
        }
        #[test]
        fn r5_completion_eight_abrupt_persistence_boundaries() {
            let c = campaign("r5-completion-crashes");
            let native = native_claim(&c);
            let id = native.operation.id().unwrap();
            for phase in [
                "prepare_before_commit",
                "prepare_after_commit",
                "request_before_commit",
                "request_after_commit",
                "signed_before_commit",
                "signed_after_commit",
                "dispatch_before_commit",
                "dispatch_after_commit",
            ] {
                let dir = c.base.join(phase);
                std::fs::create_dir(&dir).unwrap();
                let jp = dir.join("completion.sqlite");
                let mut j = completion::Journal::open(&jp, policy()).unwrap();
                if !phase.starts_with("prepare") {
                    assert_eq!(
                        j.prepare(
                            &c.store,
                            &c.funding,
                            completion::PathChoice::Claim([42; 32]),
                            completion_fees()
                        )
                        .unwrap(),
                        id
                    );
                }
                if phase.starts_with("signed") || phase.starts_with("dispatch") {
                    j.request_approval(&c.store, id, 0, c.treasury.public().descriptor(1).unwrap())
                        .unwrap();
                }
                if phase.starts_with("dispatch") {
                    j.accept_approval(
                        &c.store,
                        id,
                        0,
                        native.operation.approvals[0].signature.clone(),
                    )
                    .unwrap();
                }
                drop(j);
                let records: Vec<_> =
                    c.f.state
                        .records()
                        .unwrap()
                        .iter()
                        .map(|(k, v)| vec![hex::encode(k), hex::encode(v)])
                        .collect();
                let input = serde_json::json!({"root":hex::encode(c.f.state.root().unwrap()),"genesis":hex::encode(c.f.genesis.encode()),"records":records,"canonical_path":c.base.join("canonical.sqlite").to_str().unwrap(),"funding":hex::encode(c.funding.encode().unwrap()),"native":hex::encode(native.encode().unwrap())});
                std::fs::write(
                    dir.join("public.json"),
                    serde_json::to_vec_pretty(&input).unwrap(),
                )
                .unwrap();
                let result = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "trading_service_v1::bitcoin_candidate::tests::completion_crash_worker",
                        "--nocapture",
                    ])
                    .env("TRADING_COMPLETION_CRASH", phase)
                    .env("TRADING_COMPLETION_CASE", &dir)
                    .output()
                    .unwrap();
                std::fs::write(dir.join("stdout.log"), result.stdout).unwrap();
                std::fs::write(dir.join("stderr.log"), result.stderr).unwrap();
                assert_eq!(result.status.code(), Some(86), "{phase}");
                let mut j = completion::Journal::open(&jp, policy()).unwrap();
                let recovered = j
                    .find_by_locked_output(c.funding.operation.output_id(0).unwrap())
                    .unwrap();
                assert_eq!(
                    recovered,
                    if phase == "prepare_before_commit" {
                        None
                    } else {
                        Some(id)
                    },
                    "{phase}"
                );
                assert_eq!(j.find_by_locked_output([0; 32]).unwrap(), None);
                if phase == "prepare_before_commit" {
                    assert_eq!(
                        j.prepare(
                            &c.store,
                            &c.funding,
                            completion::PathChoice::Claim([42; 32]),
                            completion_fees()
                        )
                        .unwrap(),
                        id
                    );
                } else {
                    assert!(
                        j.prepare(
                            &c.store,
                            &c.funding,
                            completion::PathChoice::Claim([42; 32]),
                            completion_fees()
                        )
                        .is_err()
                    );
                }
                if phase == "request_after_commit" {
                    assert!(matches!(
                        j.request_approval(
                            &c.store,
                            id,
                            0,
                            c.treasury.public().descriptor(1).unwrap()
                        ),
                        Err(completion::Error::Ambiguous)
                    ));
                    assert_eq!(j.reconcile_request(id, 0).unwrap().operation, id);
                }
                if phase == "signed_before_commit" {
                    assert!(j.signed_bytes(id).is_err());
                }
                if phase == "signed_after_commit" {
                    assert_eq!(j.signed_bytes(id).unwrap(), native.encode().unwrap());
                }
                if phase == "dispatch_before_commit" {
                    j.dispatch(&c.store, id).unwrap();
                }
                if phase == "dispatch_after_commit" {
                    assert!(matches!(
                        j.dispatch(&c.store, id),
                        Err(completion::Error::Ambiguous)
                    ));
                }
                assert_eq!(
                    j.reconcile(&c.store, id).unwrap(),
                    completion::Reconciliation::Pending
                );
            }
        }
        #[test]
        #[ignore = "subprocess entry; invoked by r5_completion_eight_abrupt_persistence_boundaries"]
        fn completion_crash_worker() {
            let dir = PathBuf::from(std::env::var_os("TRADING_COMPLETION_CASE").unwrap());
            let phase = std::env::var("TRADING_COMPLETION_CRASH").unwrap();
            let input: serde_json::Value =
                serde_json::from_slice(&std::fs::read(dir.join("public.json")).unwrap()).unwrap();
            let raw = |k: &str| hex::decode(input[k].as_str().unwrap()).unwrap();
            let root: Hash = raw("root").try_into().unwrap();
            let records: Vec<_> = input["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    (
                        hex::decode(r[0].as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap(),
                        hex::decode(r[1].as_str().unwrap()).unwrap(),
                    )
                })
                .collect();
            let state = State::from_records(&records, root).unwrap();
            let genesis = FinalizedAnchor::decode(&raw("genesis")).unwrap();
            let store = CanonicalStore::open_trusted_genesis(
                Path::new(input["canonical_path"].as_str().unwrap()),
                &genesis,
                &state,
                root,
                1000,
                [255; 32],
            )
            .unwrap();
            let funding = tr::NativeOperation::decode(&raw("funding")).unwrap();
            let native = tr::NativeOperation::decode(&raw("native")).unwrap();
            let id = native.operation.id().unwrap();
            let mut j =
                completion::Journal::open(&dir.join("completion.sqlite"), policy()).unwrap();
            if phase.starts_with("prepare") {
                j.prepare(
                    &store,
                    &funding,
                    completion::PathChoice::Claim([42; 32]),
                    completion_fees(),
                )
                .unwrap();
            } else if phase.starts_with("request") {
                j.request_approval(
                    &store,
                    id,
                    0,
                    native.operation.approvals[0].descriptor.clone(),
                )
                .unwrap();
            } else if phase.starts_with("signed") {
                j.accept_approval(
                    &store,
                    id,
                    0,
                    native.operation.approvals[0].signature.clone(),
                )
                .unwrap();
            } else {
                j.dispatch(&store, id).unwrap();
            }
            panic!("crash point not reached");
        }

        fn empty() -> HybridSignature {
            HybridSignature {
                ed448: [0; 114],
                fndsa: [0; 1280],
            }
        }
        struct Fixture {
            state: State,
            genesis: FinalizedAnchor,
            coordinator: HybridKey,
            continuity: HybridKey,
            license: Hash,
            worker: Hash,
        }
        fn fixture() -> Fixture {
            let f: serde_json::Value = serde_json::from_str(include_str!(
                "../../qualification/hybrid-canonical-store-public-v1.json"
            ))
            .unwrap();
            assert_eq!(f["synthetic_only"], true);
            assert_eq!(f["production_authorized"], false);
            let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
            let records: Vec<_> = f["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
                .collect();
            let initial =
                State::from_records(&records, raw(&f["root"]).try_into().unwrap()).unwrap();
            let mut state = State {
                coins: initial.coins.clone(),
                wallets: initial.wallets.clone(),
                continuity: initial.continuity.clone(),
                ..Default::default()
            };
            let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
            let (owner, assignments, expected, licenses, coordinator) = licenses::fixtures();
            state
                .wallets
                .register(&owner.public().descriptor(1).unwrap())
                .unwrap();
            let continuity = HybridKey::generate(Role::Continuity).unwrap();
            let old_node = state.continuity.as_ref().unwrap().members[0].node;
            let mut binding = initial
                .membership_v2
                .get(old_node)
                .unwrap()
                .binding()
                .clone();
            binding.node_descriptor = coordinator.public().descriptor(1).unwrap();
            binding.admission.node = mutiny_consensus_v8::node_admission_v2::node_id(
                genesis.genesis,
                &binding.node_descriptor,
            )
            .unwrap();
            binding.admission.continuity_descriptor = continuity.public().descriptor(1).unwrap();
            let ak = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
            let profile = tpm::profile(&ak);
            assert_eq!(binding.admission.profile, profile.encode().unwrap());
            binding.admission.prove_continuity(&continuity).unwrap();
            binding.admission.quote =
                tpm::quote(&ak, &profile, binding.admission.challenge().unwrap());
            binding.admission.authorize(&owner, 1).unwrap();
            binding.sign(&coordinator).unwrap();
            let policy = mutiny_consensus_v8::admission_v2::Policy {
                genesis: genesis.genesis,
                fingerprint: genesis.fingerprint,
                owner_descriptor: owner.public().descriptor(1).unwrap(),
                endorsement_roots: [binding.admission.endorsement_root].into_iter().collect(),
            };
            let admission_expected = mutiny_consensus_v8::admission_v2::Expected {
                node: binding.admission.node,
                hardware_generation: 1,
                key_generation: 1,
                supervised_nonce: binding.admission.supervised_nonce,
            };
            (state.membership_v2, state.continuity_keys_v2) =
                mutiny_consensus_v8::membership_v2::Book::genesis(
                    &binding,
                    &policy,
                    &admission_expected,
                    &state.wallets,
                    mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest,
                )
                .unwrap();
            state.continuity.as_mut().unwrap().members[0].node = binding.admission.node;
            state.licenses_v2 = mutiny_consensus_v8::license_book_v2::Book::genesis(
                &assignments,
                &expected,
                &licenses,
                &state.wallets,
                genesis.genesis,
                genesis.fingerprint,
            )
            .unwrap();
            state.admission_policy_v2 =
                Some(mutiny_consensus_v8::admission_policy_v2::Record::new(policy).unwrap());
            state.wallets.records().expect("fixture wallets");
            state
                .continuity_keys_v2
                .records()
                .expect("fixture continuity keys");
            state
                .membership_v2
                .records(&state.continuity_keys_v2)
                .expect("fixture membership");
            state.licenses_v2.records().expect("fixture licenses");
            state
                .continuity
                .as_ref()
                .unwrap()
                .state_records()
                .expect("fixture continuity");
            let rows = state.records().expect("fixture records");
            State::from_records(&rows, state.root().unwrap()).expect("fixture restore");
            Fixture {
                state,
                genesis,
                coordinator,
                continuity,
                license: licenses[0].id,
                worker: expected[0].worker_id,
            }
        }

        fn certify_at(
            prepared: mutiny_consensus_v8::assembler_v2::Prepared,
            f: &Fixture,
            parent: &FinalizedAnchor,
            state: &State,
            ticket: u64,
        ) -> BlockEnvelope {
            let height = prepared.candidate.height;
            let epoch =
                mutiny_consensus_v8::pow::mining_epoch(prepared.candidate.timestamp, 1000).unwrap();
            let mut book = state.licenses_v2.clone();
            book.activate_due(epoch).unwrap();
            let assignment = book
                .active(prepared.candidate.license, prepared.candidate.worker, epoch)
                .unwrap()
                .0
                .assignment_sequence;
            let mut authority = Authority {
                work: WorkAuthority {
                    candidate: prepared.candidate.clone(),
                    assignment_sequence: assignment,
                    ticket_sequence: ticket,
                    coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(
                        &f.coordinator.public().descriptor(1).unwrap(),
                    )
                    .unwrap(),
                    nonce_start: 0,
                    nonce_end: 100,
                    epoch,
                },
                node_descriptor: f.coordinator.public().descriptor(1).unwrap(),
                signature: empty(),
            };
            authority.sign(&f.coordinator).unwrap();
            let header = WorkHeader {
                candidate: prepared.candidate,
                authority: authority.id().unwrap(),
                nonce: 1,
            };
            assert!(mutiny_consensus_v8::pow::meets_target(
                &header.block_hash(),
                &[255; 32]
            ));
            let height_authority = mutiny_consensus_v8::votes_v2::HeightAuthority::from_state(
                state,
                parent.clone(),
                state.root().unwrap(),
            )
            .unwrap();
            let (node, voter) = height_authority.voters.iter().next().unwrap();
            let decision = Decision {
                network: f.genesis.network,
                genesis: f.genesis.genesis,
                fingerprint: f.genesis.fingerprint,
                purpose: 2,
                height,
                mining_epoch: epoch,
                continuity_period: (height - 1) / 60,
                round: 0,
                step: 3,
                previous_finalized_anchor: parent.id(),
                parent: parent.block,
                block: header.block_hash(),
                state: prepared.execution.root,
                membership: height_authority.membership,
                reputation: height_authority.reputation,
                attestation: height_authority.attestation,
            };
            let mut vote = Vote {
                decision: decision.clone(),
                nil: false,
                node: *node,
                hardware_generation: voter.hardware_generation,
                key_generation: voter.key_generation,
                sequence: height * 10,
                tpm_identity: voter.tpm_identity(),
                profile: voter.profile,
                signature: empty(),
            };
            vote.sign(&f.continuity).unwrap();
            BlockEnvelope {
                header,
                body: prepared.body,
                authority,
                certificate: Certificate {
                    decision,
                    votes: vec![vote],
                },
            }
        }

        fn policy() -> CandidatePolicy {
            CandidatePolicy::native_denomination_locked()
        }
        fn safety() -> OfflineSafety {
            OfflineSafety::qualification(30, 10, 2).unwrap()
        }
        fn path(label: &str) -> PathBuf {
            let base = PathBuf::from(
                std::env::var_os("BITCOIN_TRADING_EVIDENCE_DIR").expect("fresh evidence directory"),
            );
            let p = base.join(label);
            assert!(!p.exists(), "fresh path required: {}", p.display());
            std::fs::create_dir_all(&p).unwrap();
            p
        }
        fn key(n: u8) -> bitcoin::secp256k1::SecretKey {
            bitcoin::secp256k1::SecretKey::from_slice(&[n; 32]).unwrap()
        }
        fn public(n: u8) -> [u8; 33] {
            PublicKey::from_secret_key(&Secp256k1::new(), &key(n)).serialize()
        }
        fn change_script() -> Vec<u8> {
            let p = bitcoin::PublicKey::new(PublicKey::from_slice(&public(1)).unwrap());
            ScriptBuf::new_p2wpkh(&p.wpubkey_hash().unwrap()).into_bytes()
        }
        fn terms() -> BitcoinTerms {
            let previous = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([71; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                }],
                output: vec![bitcoin::TxOut {
                    value: Amount::from_sat(200_000),
                    script_pubkey: ScriptBuf::from_bytes(change_script()),
                }],
            };
            BitcoinTerms {
                inputs: vec![InputCoin {
                    previous_transaction: serialize(&previous),
                    index: 0,
                    public_key: public(1),
                }],
                recipient: public(2),
                refund: public(3),
                refund_height: 100,
                approved_change: change_script(),
                fee_satoshis: 1000,
                fee_limit_satoshis: 5000,
                expiry_mut_height: 40,
                policy_generation: 1,
            }
        }
        /// Explicit test-only external signer. Synthetic scalars only, no
        /// production key API. Independent policy verifies before any signature.
        fn external_sign(i: &TreasurySwapIntent, a: &SignerAuthorization) -> Vec<u8> {
            a.verify(i).unwrap();
            let mut t = tx(i.unsigned_transaction(), MAX_PREVIOUS_TX).unwrap();
            let copy = t.clone();
            let mut cache = SighashCache::new(&copy);
            for (n, c) in i.terms.inputs.iter().enumerate() {
                let prev = c.previous().unwrap().1;
                let hash = cache
                    .p2wpkh_signature_hash(
                        n,
                        &prev.script_pubkey,
                        prev.value,
                        EcdsaSighashType::All,
                    )
                    .unwrap();
                let sig = Secp256k1::new()
                    .sign_ecdsa(&Message::from_digest(hash.to_byte_array()), &key(1));
                let encoded = bitcoin::ecdsa::Signature::sighash_all(sig).to_vec();
                t.input[n].witness = bitcoin::Witness::from_slice(&[encoded, public(1).to_vec()]);
            }
            serialize(&t)
        }
        fn authorization(i: &TreasurySwapIntent) -> SignerAuthorization {
            SignerAuthorization {
                exact_intent_hash: i.intent_hash().unwrap(),
                approved_inputs: i
                    .terms
                    .inputs
                    .iter()
                    .map(|c| c.previous().unwrap().0)
                    .collect(),
                approved_change: i.terms.approved_change.clone(),
                policy_generation: i.terms.policy_generation,
            }
        }
        struct Campaign {
            f: Fixture,
            store: CanonicalStore,
            journal: OperationJournal,
            base: PathBuf,
            frozen: tr::FrozenTreasuryOffer,
            funding: tr::NativeOperation,
            operation: Hash,
            treasury: HybridKey,
        }
        fn commit(c: &mut Campaign, raw: Vec<u8>) {
            let (parent, state, _) = current(&c.store).unwrap();
            let next = parent.height + 1;
            let mut pool = Mempool::open(
                &c.base.join(format!("pool-{next}.sqlite")),
                parent.genesis,
                parent.fingerprint,
                1_048_576,
            )
            .unwrap();
            c.store.reconcile_pool(&mut pool).unwrap();
            let ops = if raw.is_empty() {
                Vec::new()
            } else {
                vec![raw]
            };
            let prepared = c
                .store
                .prepare_pending(Preparation {
                    expected_parent: &parent,
                    pool: &pool,
                    license: c.f.license,
                    worker: c.f.worker,
                    timestamp: 1000 + 100 * next,
                    ticket: next,
                    operations: &ops,
                })
                .unwrap();
            let envelope = certify_at(prepared, &c.f, &parent, &state, next);
            assert!(c.store.commit(&envelope).unwrap());
        }
        fn campaign(label: &str) -> Campaign {
            campaign_with_funding(label, true)
        }
        fn campaign_with_funding(label: &str, fund: bool) -> Campaign {
            campaign_with_deadlines(label, fund, 100, 40)
        }
        fn campaign_with_deadlines(
            label: &str,
            fund: bool,
            refund_height: u64,
            expiry: u64,
        ) -> Campaign {
            let base = path(label);
            let mut f = fixture();
            let sender =
                HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner)
                    .unwrap();
            let treasury =
                HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner)
                    .unwrap();
            let maker = HybridKey::generate(Role::Transport).unwrap();
            let addr = |k: &HybridKey| k.public().address_id(1).unwrap();
            f.state
                .wallets
                .register(&treasury.public().descriptor(1).unwrap())
                .unwrap();
            let next=HybridKey::wallet_restore("letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",Role::WalletOwner).unwrap();
            f.state
                .wallets
                .register(&next.public().descriptor(1).unwrap())
                .unwrap();
            let input = mutiny_consensus_v8::transactions::OutPoint {
                transaction: [180; 32],
                index: 0,
            };
            for (p, owner) in [
                (input.clone(), addr(&sender)),
                (
                    mutiny_consensus_v8::transactions::OutPoint {
                        transaction: [181; 32],
                        index: 0,
                    },
                    addr(&treasury),
                ),
            ] {
                f.state.coins.insert(
                    p,
                    mutiny_consensus_v8::transactions::Coin {
                        output: mutiny_consensus_v8::transactions::Output {
                            owner,
                            atoms: 100_000,
                        },
                        created_height: 0,
                        coinbase: false,
                    },
                );
            }
            let context = tr::Context {
                network: NETWORK_ID,
                genesis: f.genesis.genesis,
                fingerprint: f.genesis.fingerprint,
            };
            for (k, v) in tr::treasury_genesis_records(
                &context,
                [183; 32],
                treasury.public().descriptor(1).unwrap(),
            )
            .unwrap()
            {
                f.state.protocol_records.insert(k, v);
            }
            let store = CanonicalStore::open_trusted_genesis(
                &base.join("canonical.sqlite"),
                &f.genesis,
                &f.state,
                f.state.root().unwrap(),
                1000,
                [255; 32],
            )
            .unwrap();
            let offer = tr::SignedOffer::sign(
                tr::OfferBody {
                    context: context.clone(),
                    descriptor: maker.public().descriptor(1).unwrap(),
                    nonce: [184; 32],
                    created: 0,
                    expiry,
                    maker_side: 1,
                    terms: tr::OfferTerms::HashLinked {
                        amount: tr::Strikes(50_000),
                        bitcoin_satoshis: 100_000,
                        bitcoin_network: REGTEST,
                    },
                },
                &maker,
            )
            .unwrap();
            let prepared = super::super::prepare_current_treasury_offer(
                &store,
                tr::TreasuryOfferRequest {
                    treasury: [183; 32],
                    generation: 1,
                    address: addr(&treasury),
                    trade: [185; 32],
                    contract: [186; 32],
                    offer: offer.clone(),
                    wallet_descriptor: treasury.public().descriptor(1).unwrap(),
                },
                &policy(),
            )
            .unwrap();
            let signature = treasury
                .sign(
                    mutiny_crypto_v2::Domain::Transaction,
                    &prepared.signing_payload().unwrap(),
                )
                .unwrap();
            let frozen = prepared.attach_authorization(signature).unwrap();
            let mut journal =
                OperationJournal::open(&base.join("journal.sqlite"), policy()).unwrap();
            let operation = journal.record_creation(&store, &frozen).unwrap();
            let mut signer =
                DedicatedSignerJournal::open(&base.join("signer.sqlite"), policy()).unwrap();
            assert_eq!(signer.record_creation(&store, &frozen).unwrap(), operation);
            drop(signer);
            let mut o = tr::Operation {
                meta: tr::Meta {
                    context,
                    trade: frozen.trade(),
                    contract: frozen.contract(),
                    generation: 1,
                    created: 1,
                    expiry,
                    fee: tr::Strikes(20_000),
                    inputs: vec![tr::native_input_id(&input)],
                },
                action: tr::Action::HashLock {
                    offer: offer.body.id().unwrap(),
                    maker: offer.body.maker().unwrap(),
                    sender: addr(&sender),
                    recipient: addr(&treasury),
                    amount: tr::Strikes(50_000),
                    condition: tr::preimage_hash(&[42; 32]),
                    refund_height,
                    change: tr::Strikes(30_000),
                },
                approvals: vec![],
                offer_proof: None,
            };
            o.offer_proof = Some(tr::OfferProof::sign(offer, &o, &maker).unwrap());
            o.approve(0, &sender, 1).unwrap();
            o.approve(1, &treasury, 1).unwrap();
            let funding = tr::NativeOperation {
                operation: o,
                inputs: vec![input],
            };
            let mut c = Campaign {
                f,
                store,
                journal,
                base,
                frozen,
                funding,
                operation,
                treasury,
            };
            if fund {
                let raw = c.funding.encode().unwrap();
                commit(&mut c, raw);
            }
            c
        }
        fn intent(c: &mut Campaign) -> TreasurySwapIntent {
            c.journal
                .prepare(
                    &c.store,
                    c.operation,
                    &c.funding,
                    terms(),
                    &RegtestHeaders::new(),
                    &safety(),
                )
                .unwrap()
        }
        fn signed(c: &mut Campaign) -> (TreasurySwapIntent, Vec<u8>) {
            let i = intent(c);
            let a = authorization(&i);
            let request = c
                .journal
                .begin_sign(
                    &c.store,
                    c.operation,
                    0,
                    &a,
                    &RegtestHeaders::new(),
                    &safety(),
                )
                .unwrap();
            assert_eq!(request.operation, c.operation);
            assert_eq!(request.intent, i.encode().unwrap());
            bitcoin::psbt::Psbt::deserialize(&request.psbt).unwrap();
            let raw = external_sign(&i, &a);
            c.journal.record_signed(c.operation, 0, &raw).unwrap();
            (i, raw)
        }
        fn external_spend(i: &TreasurySwapIntent, refund: bool) -> Vec<u8> {
            let secret = if refund { 3 } else { 2 };
            let public = bitcoin::PublicKey::new(PublicKey::from_slice(&public(secret)).unwrap());
            let script = lock_script(i.condition, &i.terms).unwrap();
            let mut t = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: if refund {
                    absolute::LockTime::from_height(i.terms.refund_height).unwrap()
                } else {
                    absolute::LockTime::ZERO
                },
                input: vec![bitcoin::TxIn {
                    previous_output: OutPoint {
                        txid: i.expected_txid().unwrap(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_LOCKTIME_NO_RBF,
                    witness: bitcoin::Witness::new(),
                }],
                output: vec![bitcoin::TxOut {
                    value: Amount::from_sat(99_000),
                    script_pubkey: ScriptBuf::new_p2wpkh(&public.wpubkey_hash().unwrap()),
                }],
            };
            let hash = SighashCache::new(&t)
                .p2wsh_signature_hash(0, &script, Amount::from_sat(100_000), EcdsaSighashType::All)
                .unwrap();
            let sig = bitcoin::ecdsa::Signature::sighash_all(
                Secp256k1::new()
                    .sign_ecdsa(&Message::from_digest(hash.to_byte_array()), &key(secret)),
            )
            .to_vec();
            t.input[0].witness = if refund {
                bitcoin::Witness::from_slice(&[sig, vec![], script.into_bytes()])
            } else {
                bitcoin::Witness::from_slice(&[sig, vec![42; 32], vec![1], script.into_bytes()])
            };
            serialize(&t)
        }
        fn mine(
            headers: &mut RegtestHeaders,
            parent: BlockHash,
            root: Hash,
            time_offset: u32,
        ) -> BlockHash {
            let p = headers.entries[&parent].header;
            let mut h = Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: parent,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array(root),
                time: p.time + 600 + time_offset,
                bits: p.bits,
                nonce: 0,
            };
            while h.validate_pow(h.target()).is_err() {
                h.nonce += 1;
            }
            headers.insert(&serialize(&h), h.time).unwrap()
        }
        #[test]
        fn canonical_funding_exact_psbt_signing_and_lost_response_recovery() {
            let mut c = campaign("exact-recovery");
            let i = intent(&mut c);
            let a = authorization(&i);
            let headers = RegtestHeaders::new();
            assert_eq!(c.store.load().unwrap().0.height, 1);
            assert_eq!(
                c.journal.reconcile(c.operation, 0).unwrap().1,
                Stage::Prepared
            );
            c.journal
                .begin_sign(&c.store, c.operation, 0, &a, &headers, &safety())
                .unwrap();
            let raw = external_sign(&i, &a); // response lost before local persistence
            drop(c.journal);
            c.journal = OperationJournal::open(&c.base.join("journal.sqlite"), policy()).unwrap();
            assert_eq!(
                c.journal
                    .begin_sign(&c.store, c.operation, 0, &a, &headers, &safety())
                    .unwrap_err(),
                Error::Ambiguous
            );
            assert_eq!(
                c.journal
                    .broadcast_request(&c.store, c.operation, 0, &RegtestHeaders::new(), &safety())
                    .unwrap_err(),
                Error::Ambiguous
            );
            let tid = c.journal.record_signed(c.operation, 0, &raw).unwrap();
            assert_eq!(c.journal.record_signed(c.operation, 0, &raw).unwrap(), tid);
            let first = c
                .journal
                .broadcast_request(&c.store, c.operation, 0, &RegtestHeaders::new(), &safety())
                .unwrap();
            drop(c.journal);
            c.journal = OperationJournal::open(&c.base.join("journal.sqlite"), policy()).unwrap();
            let retry = c.journal.reconcile_broadcast(c.operation, 0).unwrap();
            assert_eq!(first.signed_bytes, retry.signed_bytes);
            assert_eq!(first.txid, retry.txid);
            assert!(
                c.journal
                    .prepare(
                        &c.store,
                        c.operation,
                        &c.funding,
                        terms(),
                        &headers,
                        &safety()
                    )
                    .is_err()
            );
            assert_eq!(
                c.journal.reconcile(c.operation, 0).unwrap().1,
                Stage::BroadcastPending
            );
        }
        #[test]
        fn wrong_terms_inputs_outputs_fee_and_signature_fail_closed() {
            let mut c = campaign("adversarial-terms");
            let i = intent(&mut c);
            let a = authorization(&i);
            let raw = external_sign(&i, &a);
            assert!(i.verify_signed(&raw).is_ok());
            for field in 0..10 {
                let mut bad = i.clone();
                match field {
                    0 => bad.operation[0] ^= 1,
                    1 => bad.condition[0] ^= 1,
                    2 => bad.terms.recipient = public(4),
                    3 => bad.terms.refund = public(4),
                    4 => bad.terms.fee_satoshis += 1,
                    5 => bad.terms.fee_satoshis = 6000,
                    6 => bad.terms.policy_generation += 1,
                    7 => bad.terms.inputs[0].index = 1,
                    8 => bad.terms.approved_change[0] ^= 1,
                    _ => bad.mut_anchor.genesis[0] ^= 1,
                }
                assert!(a.verify(&bad).is_err());
            }
            for field in 0..5 {
                let mut bad = tx(&raw, MAX_PREVIOUS_TX).unwrap();
                match field {
                    0 => bad.output[0].value = Amount::from_sat(99_999),
                    1 => bad.output[1].value = Amount::from_sat(99_001),
                    2 => bad.output.push(bad.output[1].clone()),
                    3 => {
                        bad.input[0].witness =
                            bitcoin::Witness::from_slice(&[vec![0; 70], public(1).to_vec()])
                    }
                    _ => bad.input[0].previous_output.vout += 1,
                }
                assert!(i.verify_signed(&serialize(&bad)).is_err());
            }
            let mut wrong = a.clone();
            wrong.approved_inputs.clear();
            assert_eq!(wrong.verify(&i), Err(Error::Authority));
            for field in 0..4 {
                let mut bad = i.clone();
                let mut funding = tr::NativeOperation::decode(&bad.funding).unwrap();
                if let tr::Action::HashLock {
                    amount,
                    recipient,
                    offer,
                    ..
                } = &mut funding.operation.action
                {
                    match field {
                        0 => amount.0 += 1,
                        1 => recipient[0] ^= 1,
                        2 => offer[0] ^= 1,
                        _ => funding.operation.meta.trade[0] ^= 1,
                    }
                }
                bad.funding = funding.encode().unwrap();
                assert!(bad.verify_terms().is_err());
            }
            let mut hidden = raw.clone();
            hidden.push(0);
            assert!(i.verify_signed(&hidden).is_err());
        }
        #[test]
        fn linked_replacement_requires_new_exact_authorization_and_preserves_history() {
            let mut c = campaign("replacement");
            let (i, raw) = signed(&mut c);
            let old = i.verify_signed(&raw).unwrap().0;
            let headers = RegtestHeaders::new();
            let replacement = c
                .journal
                .prepare_replacement(&c.store, c.operation, 2000, &headers, &safety())
                .unwrap();
            assert_eq!(replacement.operation(), i.operation());
            assert_eq!(replacement.replaces, Some(old));
            assert_eq!(replacement.terms.recipient, i.terms.recipient);
            assert_eq!(replacement.frozen, i.frozen);
            assert_eq!(
                c.journal
                    .begin_sign(
                        &c.store,
                        c.operation,
                        1,
                        &authorization(&i),
                        &headers,
                        &safety()
                    )
                    .unwrap_err(),
                Error::Authority
            );
            assert_eq!(
                c.journal
                    .broadcast_request(&c.store, c.operation, 0, &RegtestHeaders::new(), &safety())
                    .unwrap_err(),
                Error::Replacement
            );
            let a = authorization(&replacement);
            c.journal
                .begin_sign(&c.store, c.operation, 1, &a, &headers, &safety())
                .unwrap();
            assert_eq!(
                c.journal
                    .prepare_replacement(&c.store, c.operation, 3000, &headers, &safety())
                    .unwrap_err(),
                Error::Ambiguous
            );
            let new = external_sign(&replacement, &a);
            c.journal.record_signed(c.operation, 1, &new).unwrap();
            assert_ne!(old, replacement.verify_signed(&new).unwrap().0);
            assert_eq!(c.journal.reconcile(c.operation, 0).unwrap().2, Some(raw));
            drop(c.journal);
            OperationJournal::open(&c.base.join("journal.sqlite"), policy()).unwrap();
        }
        #[test]
        fn funding_inclusion_confirmations_reorg_and_conflict_are_not_completion() {
            let mut c = campaign("spv-reorg");
            let (i, raw) = signed(&mut c);
            let tid = i.verify_signed(&raw).unwrap().0;
            let mut headers = RegtestHeaders::new();
            let genesis = headers.tip().0;
            assert_eq!(
                c.journal
                    .funding_status(c.operation, &headers, &safety())
                    .unwrap(),
                FundingStatus::Unknown
            );
            c.journal
                .observe_mempool_hint(c.operation, 0, &raw)
                .unwrap();
            assert_eq!(
                c.journal
                    .funding_status(c.operation, &headers, &safety())
                    .unwrap(),
                FundingStatus::MempoolUnconfirmed
            );
            let block = mine(&mut headers, genesis, tid.to_byte_array(), 0);
            let p = Inclusion {
                block,
                index: 0,
                total_transactions: 1,
                branch: vec![],
            };
            c.journal
                .observe_inclusion(c.operation, 0, &p, &headers)
                .unwrap();
            assert_eq!(
                c.journal
                    .funding_status(c.operation, &headers, &safety())
                    .unwrap(),
                FundingStatus::Included {
                    txid: tid,
                    depth: 1
                }
            );
            mine(&mut headers, block, [81; 32], 0);
            assert_eq!(
                c.journal
                    .funding_status(c.operation, &headers, &safety())
                    .unwrap(),
                FundingStatus::FundingConfirmed {
                    txid: tid,
                    depth: 2
                }
            );
            let mut fork = mine(&mut headers, genesis, [82; 32], 1);
            fork = mine(&mut headers, fork, [83; 32], 1);
            fork = mine(&mut headers, fork, [84; 32], 1);
            assert_eq!(
                c.journal
                    .funding_status(c.operation, &headers, &safety())
                    .unwrap(),
                FundingStatus::Reorged { txid: tid }
            );
            let mut other = tx(&raw, MAX_PREVIOUS_TX).unwrap();
            other.output[1].value = Amount::from_sat(1);
            let other_id = other.compute_txid();
            let conflict = mine(&mut headers, fork, other_id.to_byte_array(), 0);
            let proof = Inclusion {
                block: conflict,
                index: 0,
                total_transactions: 1,
                branch: vec![],
            };
            c.journal
                .observe_conflict(c.operation, 0, &serialize(&other), &proof, &headers)
                .unwrap();
            assert_eq!(
                c.journal
                    .funding_status(c.operation, &headers, &safety())
                    .unwrap(),
                FundingStatus::Conflicted { txid: other_id }
            );
            // SPV fixture confirms header inclusion, not full Bitcoin script consensus.
        }
        #[test]
        fn malformed_headers_merkle_and_mainnet_never_supply_regtest_authority() {
            let mut headers = RegtestHeaders::new();
            let genesis = headers.tip().0;
            let tid = Txid::from_byte_array([91; 32]);
            let block = mine(&mut headers, genesis, tid.to_byte_array(), 0);
            assert!(
                headers
                    .verify_inclusion(
                        &Inclusion {
                            block,
                            index: 0,
                            total_transactions: 1,
                            branch: vec![]
                        },
                        Txid::from_byte_array([92; 32])
                    )
                    .is_err()
            );
            assert!(
                headers
                    .verify_inclusion(
                        &Inclusion {
                            block,
                            index: 1,
                            total_transactions: 1,
                            branch: vec![]
                        },
                        tid
                    )
                    .is_err()
            );
            assert!(
                headers
                    .verify_inclusion(
                        &Inclusion {
                            block,
                            index: 0,
                            total_transactions: 2,
                            branch: vec![[91; 32]]
                        },
                        tid
                    )
                    .is_err()
            );
            let mainnet = bitcoin::blockdata::constants::genesis_block(Network::Bitcoin).header;
            assert!(headers.insert(&serialize(&mainnet), mainnet.time).is_err());
            let mut bad = headers.entries[&block].header;
            bad.time = 0;
            assert!(headers.insert(&serialize(&bad), mainnet.time).is_err());
            assert!(headers.insert(&[0; 81], 0).is_err());
        }
        #[test]
        fn bitcoin_hash_claim_and_refund_verify_native_authority_and_exact_timeout() {
            let mut c = campaign("claim-refund");
            let i = intent(&mut c);
            let tid = i.expected_txid().unwrap();
            let claim = external_spend(&i, false);
            let refund = external_spend(&i, true);
            assert_eq!(
                i.verify_lock_spend(tid, &claim).unwrap().path,
                SpendPath::Claim { preimage: [42; 32] }
            );
            assert_eq!(
                i.verify_lock_spend(tid, &refund).unwrap().path,
                SpendPath::Refund
            );
            let mut bad = tx(&claim, MAX_PREVIOUS_TX).unwrap();
            let mut wit: Vec<Vec<u8>> = bad.input[0].witness.iter().map(|s| s.to_vec()).collect();
            wit[1][0] ^= 1;
            bad.input[0].witness = bitcoin::Witness::from_slice(&wit);
            assert!(i.verify_lock_spend(tid, &serialize(&bad)).is_err());
            let mut bad = tx(&refund, MAX_PREVIOUS_TX).unwrap();
            bad.lock_time = absolute::LockTime::from_height(99).unwrap();
            assert!(i.verify_lock_spend(tid, &serialize(&bad)).is_err());
            bad = tx(&refund, MAX_PREVIOUS_TX).unwrap();
            bad.input[0].sequence = bitcoin::Sequence::MAX;
            assert!(i.verify_lock_spend(tid, &serialize(&bad)).is_err());
            let verified = i.verify_lock_spend(tid, &refund).unwrap();
            let mut headers = RegtestHeaders::new();
            let mut tip = headers.tip().0;
            for _ in 1..100 {
                tip = mine(&mut headers, tip, [96; 32], 0);
            }
            let early = mine(&mut headers, tip, verified.txid.to_byte_array(), 0);
            let proof = Inclusion {
                block: early,
                index: 0,
                total_transactions: 1,
                branch: vec![],
            };
            assert_eq!(
                i.verify_lock_spend_inclusion(tid, &refund, &proof, &headers)
                    .unwrap_err(),
                Error::Deadline
            );
            // Alternative fork places this exact transaction at the first valid
            // absolute-locktime height, then wins by accumulated PoW.
            let alternate = mine(&mut headers, tip, [95; 32], 1);
            let valid = mine(&mut headers, alternate, verified.txid.to_byte_array(), 0);
            let proof = Inclusion {
                block: valid,
                index: 0,
                total_transactions: 1,
                branch: vec![],
            };
            assert!(
                i.verify_lock_spend_inclusion(tid, &refund, &proof, &headers)
                    .is_ok()
            );
        }
        #[test]
        fn canonical_rotation_preserves_recorded_offer_and_rejects_backdated_creation() {
            let mut c = campaign("rotation");
            let next=HybridKey::wallet_restore("letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",Role::WalletOwner).unwrap();
            let point = mutiny_consensus_v8::transactions::OutPoint {
                transaction: [181; 32],
                index: 0,
            };
            let mut rotation = tr::Operation {
                meta: tr::Meta {
                    context: c.frozen.offer().context.clone(),
                    trade: [197; 32],
                    contract: [198; 32],
                    generation: 1,
                    created: 2,
                    expiry: 10,
                    fee: tr::Strikes(20_000),
                    inputs: vec![tr::native_input_id(&point)],
                },
                action: tr::Action::TreasuryRotate {
                    treasury: c.frozen.treasury(),
                    current_generation: 1,
                    current_address: c.frozen.address(),
                    current_descriptor: tr::descriptor_hash(
                        &c.treasury.public().descriptor(1).unwrap(),
                    ),
                    new_generation: 2,
                    new_address: next.public().address_id(1).unwrap(),
                    new_descriptor: next.public().descriptor(1).unwrap(),
                    effective_height: 3,
                    change: tr::Strikes(80_000),
                },
                approvals: vec![],
                offer_proof: None,
            };
            rotation.approve(0, &c.treasury, 1).unwrap();
            commit(
                &mut c,
                tr::NativeOperation {
                    operation: rotation,
                    inputs: vec![point],
                }
                .encode()
                .unwrap(),
            );
            assert_eq!(c.store.load().unwrap().0.height, 2);
            commit(&mut c, vec![]);
            assert_eq!(c.store.load().unwrap().0.height, 3);
            assert_eq!(
                c.journal.record_creation(&c.store, &c.frozen).unwrap(),
                c.operation
            );
            let mut new_journal =
                OperationJournal::open(&c.base.join("new-journal.sqlite"), policy()).unwrap();
            assert_eq!(
                new_journal
                    .record_creation(&c.store, &c.frozen)
                    .unwrap_err(),
                Error::Stale
            );
            let maker = HybridKey::generate(Role::Transport).unwrap();
            let mut body = c.frozen.offer().clone();
            body.created = 3;
            body.nonce = [199; 32];
            body.descriptor = maker.public().descriptor(1).unwrap();
            let new_offer = tr::SignedOffer::sign(body, &maker).unwrap();
            let mut request = tr::TreasuryOfferRequest {
                treasury: c.frozen.treasury(),
                generation: 1,
                address: c.frozen.address(),
                trade: [201; 32],
                contract: [202; 32],
                offer: new_offer,
                wallet_descriptor: c.treasury.public().descriptor(1).unwrap(),
            };
            assert!(
                super::super::prepare_current_treasury_offer(&c.store, request.clone(), &policy())
                    .is_err()
            );
            request.generation = 2;
            request.address = next.public().address_id(1).unwrap();
            request.wallet_descriptor = next.public().descriptor(1).unwrap();
            let prepared =
                super::super::prepare_current_treasury_offer(&c.store, request, &policy()).unwrap();
            let sig = next
                .sign(
                    mutiny_crypto_v2::Domain::Transaction,
                    &prepared.signing_payload().unwrap(),
                )
                .unwrap();
            let new_frozen = prepared.attach_authorization(sig).unwrap();
            new_journal.record_creation(&c.store, &new_frozen).unwrap();
            let i = intent(&mut c);
            assert_eq!(i.frozen_offer().unwrap().generation(), 1);
            assert_eq!(i.frozen_offer().unwrap().address(), c.frozen.address());
            let a = authorization(&i);
            c.journal
                .begin_sign(
                    &c.store,
                    c.operation,
                    0,
                    &a,
                    &RegtestHeaders::new(),
                    &safety(),
                )
                .unwrap();
            c.journal
                .record_signed(c.operation, 0, &external_sign(&i, &a))
                .unwrap();
        }
        #[test]
        fn unsafe_deadline_disabled_unit_and_malformed_codec_reject() {
            let base = path("gates");
            assert_eq!(
                OperationJournal::open(&base.join("disabled.sqlite"), CandidatePolicy::disabled())
                    .err(),
                Some(Error::Gate)
            );
            assert_eq!(
                OperationJournal::open(
                    &base.join("unresolved.sqlite"),
                    CandidatePolicy::nonproduction_unresolved()
                )
                .err(),
                Some(Error::Unit)
            );
            assert!(!base.join("disabled.sqlite").exists());
            assert!(!base.join("unresolved.sqlite").exists());
            let mut c = campaign("deadline");
            let mut t = terms();
            t.refund_height = 5;
            assert_eq!(
                c.journal
                    .prepare(
                        &c.store,
                        c.operation,
                        &c.funding,
                        t,
                        &RegtestHeaders::new(),
                        &safety()
                    )
                    .unwrap_err(),
                Error::Deadline
            );
            let i = intent(&mut c);
            let raw = i.encode().unwrap();
            assert_eq!(TreasurySwapIntent::decode(&raw).unwrap(), i);
            for n in 0..raw.len().min(600) {
                assert!(TreasurySwapIntent::decode(&raw[..n]).is_err());
            }
            let mut trailing = raw.clone();
            trailing.push(0);
            assert!(TreasurySwapIntent::decode(&trailing).is_err());
            let mut mainnet = raw.clone();
            assert_eq!(mainnet[NS.len() + 4], REGTEST);
            mainnet[NS.len() + 4] = 0;
            assert_eq!(
                TreasurySwapIntent::decode(&mainnet).unwrap_err(),
                Error::Network
            );
            let mut nonminimal = vec![0x98, 18];
            nonminimal.extend_from_slice(&raw[1..]);
            assert!(TreasurySwapIntent::decode(&nonminimal).is_err());
            let mut seed = 7u64;
            for n in 0..1000 {
                let mut hostile = vec![0u8; n % 512];
                for b in &mut hostile {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    *b = seed as u8;
                }
                assert!(std::panic::catch_unwind(|| TreasurySwapIntent::decode(&hostile)).is_ok());
            }
        }
        #[test]
        fn independently_export_bitcoin_intent_psbt_and_script_vectors() {
            let mut c = campaign("vectors");
            let (i, raw) = signed(&mut c);
            let (tid, wid) = i.verify_signed(&raw).unwrap();
            let report = serde_json::json!({"schema":"BITCOIN-CANDIDATE-V1-VECTORS","synthetic_only":true,"production":false,
                "intent":hex::encode(i.encode().unwrap()),"intent_hash":hex::encode(i.intent_hash().unwrap()),"unsigned":hex::encode(i.unsigned_transaction()),"signed":hex::encode(raw),
                "txid":tid.to_string(),"wtxid":wid.to_string(),"script":hex::encode(lock_script(i.condition,&i.terms).unwrap().as_bytes()),"condition":hex::encode(i.condition),
                "recipient":hex::encode(i.terms.recipient),"refund":hex::encode(i.terms.refund),"refund_height":i.terms.refund_height,"fee_sat":i.terms.fee_satoshis,"btc_sat":100000,"mut_strikes":50000,"psbt":hex::encode(i.psbt().unwrap())});
            std::fs::write(
                c.base.join("bitcoin-vectors.json"),
                serde_json::to_vec_pretty(&report).unwrap(),
            )
            .unwrap();
        }
        #[test]
        fn dedicated_signer_is_independent_exact_term_and_at_most_once() {
            let mut c = campaign("dedicated-signer");
            let i = intent(&mut c);
            let a = authorization(&i);
            let headers = RegtestHeaders::new();
            let mut signer =
                DedicatedSignerJournal::open(&c.base.join("signer.sqlite"), policy()).unwrap();
            let mut wrong = a.clone();
            wrong.exact_intent_hash[0] ^= 1;
            assert_eq!(
                signer
                    .authorize_request(&c.store, &i.encode().unwrap(), &wrong, &headers, &safety())
                    .unwrap_err(),
                Error::Authority
            );
            let req = signer
                .authorize_request(&c.store, &i.encode().unwrap(), &a, &headers, &safety())
                .unwrap();
            assert_eq!(req.operation, c.operation);
            let raw = external_sign(&i, &a);
            drop(signer);
            let mut signer =
                DedicatedSignerJournal::open(&c.base.join("signer.sqlite"), policy()).unwrap();
            assert_eq!(
                signer
                    .authorize_request(&c.store, &i.encode().unwrap(), &a, &headers, &safety())
                    .unwrap_err(),
                Error::Ambiguous
            );
            assert_eq!(signer.cached_response(c.operation, 0).unwrap(), None);
            signer.persist_signature(c.operation, 0, &raw).unwrap();
            assert_eq!(signer.cached_response(c.operation, 0).unwrap(), Some(raw));
            assert_eq!(
                signer
                    .authorize_request(&c.store, &i.encode().unwrap(), &a, &headers, &safety())
                    .unwrap_err(),
                Error::Ambiguous
            );
        }
        #[test]
        fn journal_tamper_and_missing_input_reservation_reject_on_reopen() {
            let mut c = campaign("corrupt-journal");
            let (i, _) = signed(&mut c);
            db(c.journal.db.execute("DELETE FROM reserved_input", [])).unwrap();
            drop(c.journal);
            assert!(OperationJournal::open(&c.base.join("journal.sqlite"), policy()).is_err());
            let d = Connection::open(c.base.join("journal.sqlite")).unwrap();
            for coin in &i.terms.inputs {
                d.execute(
                    "INSERT INTO reserved_input VALUES(?1,?2)",
                    params![
                        serialize(&coin.previous().unwrap().0),
                        i.operation.as_slice()
                    ],
                )
                .unwrap();
            }
            d.execute("UPDATE bitcoin_attempt SET txid=?1", [[9u8; 32].as_slice()])
                .unwrap();
            drop(d);
            assert!(OperationJournal::open(&c.base.join("journal.sqlite"), policy()).is_err());
        }
        fn reopen_canonical(c: &Campaign) -> CanonicalStore {
            CanonicalStore::open_trusted_genesis(
                &c.base.join("canonical.sqlite"),
                &c.f.genesis,
                &c.f.state,
                c.f.state.root().unwrap(),
                1000,
                [255; 32],
            )
            .unwrap()
        }
        fn set_test_store_halted(c: &Campaign, halted: bool) {
            // Deliberate test-only store outage, never a settlement proof.
            Connection::open(c.base.join("canonical.sqlite"))
                .unwrap()
                .execute("UPDATE integrity_v2 SET halted=?1 WHERE id=1", [halted])
                .unwrap();
        }
        fn assert_incomplete(c: &Campaign, journal: &mut OperationJournal) {
            assert_eq!(
                journal.creation_admission(c.operation).unwrap(),
                CreationAdmission::Incomplete
            );
            assert_eq!(
                journal.record_creation(&c.store, &c.frozen).unwrap_err(),
                Error::Ambiguous
            );
            assert_eq!(
                journal
                    .prepare(
                        &c.store,
                        c.operation,
                        &c.funding,
                        terms(),
                        &RegtestHeaders::new(),
                        &safety()
                    )
                    .unwrap_err(),
                Error::Stale
            );
            let attempts: u32 = journal
                .db
                .query_row("SELECT COUNT(*) FROM bitcoin_attempt", [], |r| r.get(0))
                .unwrap();
            assert_eq!(attempts, 0);
        }
        #[test]
        fn creation_head_advance_preserves_incomplete_admission_across_restart() {
            let mut c = campaign_with_funding("registration-advance", false);
            let store = reopen_canonical(&c);
            let frozen = c.frozen.clone();
            let path = c.base.join("pending.sqlite");
            let mut journal = OperationJournal::open(&path, policy()).unwrap();
            let result = journal.record_creation_with_recheck(&store, &frozen, || {
                commit(&mut c, vec![]);
                let (a, _, root) = current(&store)?;
                Ok((a, root))
            });
            assert_eq!(result.unwrap_err(), Error::Stale);
            // The historical proof is still valid; it must not finish admission.
            super::super::verify_archived_treasury_offer(&c.store, frozen, &policy()).unwrap();
            drop(journal);
            let mut journal = OperationJournal::open(&path, policy()).unwrap();
            assert_incomplete(&c, &mut journal);
        }
        #[test]
        fn creation_store_error_preserves_incomplete_admission_even_after_store_recovers() {
            let c = campaign_with_funding("registration-error", false);
            let path = c.base.join("pending.sqlite");
            let mut journal = OperationJournal::open(&path, policy()).unwrap();
            let result = journal.record_creation_with_recheck(&c.store, &c.frozen, || {
                set_test_store_halted(&c, true);
                let (a, _, root) = current(&c.store)?;
                Ok((a, root))
            });
            assert_eq!(result.unwrap_err(), Error::Store);
            set_test_store_halted(&c, false);
            drop(journal);
            let mut journal = OperationJournal::open(&path, policy()).unwrap();
            assert_incomplete(&c, &mut journal);
            // An independently completed original admission remains valid.
            assert_eq!(
                c.journal.creation_admission(c.operation).unwrap(),
                CreationAdmission::Admitted
            );
        }
        fn signed_with_expiry(c: &mut Campaign, expiry: u64) -> (TreasurySwapIntent, Vec<u8>) {
            let mut t = terms();
            t.expiry_mut_height = expiry;
            let h = RegtestHeaders::new();
            let i = c
                .journal
                .prepare(&c.store, c.operation, &c.funding, t, &h, &safety())
                .unwrap();
            let a = authorization(&i);
            c.journal
                .begin_sign(&c.store, c.operation, 0, &a, &h, &safety())
                .unwrap();
            let raw = external_sign(&i, &a);
            c.journal.record_signed(c.operation, 0, &raw).unwrap();
            (i, raw)
        }
        fn assert_not_dispatched(c: &Campaign, raw: &[u8]) {
            let (_, stage, exact) = c.journal.reconcile(c.operation, 0).unwrap();
            assert_eq!(stage, Stage::Signed);
            assert_eq!(exact.as_deref(), Some(raw));
            assert!(c.journal.reconcile_broadcast(c.operation, 0).is_err());
        }
        #[test]
        fn legacy_registration_rows_never_gain_new_admission_and_signed_bytes_are_retained() {
            let mut c = campaign("legacy-registration");
            let (_, raw) = signed(&mut c);
            let path = c.base.join("journal.sqlite");
            c.journal.db.pragma_update(None, "user_version", 0).unwrap();
            drop(c.journal);
            assert!(matches!(
                OperationJournal::open(&path, policy()),
                Err(Error::LegacyJournal)
            ));
            let db = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
            let (stage, signed): (i64, Vec<u8>) = db
                .query_row(
                    "SELECT stage,signed FROM bitcoin_attempt WHERE revision=0",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(stage, Stage::Signed as i64);
            assert_eq!(signed, raw);
        }
        #[test]
        fn first_dispatch_rechecks_mut_expiry_after_signed_bytes_restart() {
            let mut c = campaign("dispatch-expiry");
            let (i, raw) = signed_with_expiry(&mut c, 2);
            drop(c.journal);
            c.journal = OperationJournal::open(&c.base.join("journal.sqlite"), policy()).unwrap();
            commit(&mut c, vec![]);
            assert_eq!(
                c.journal
                    .broadcast_request(&c.store, c.operation, 0, &RegtestHeaders::new(), &safety())
                    .unwrap_err(),
                Error::Deadline
            );
            assert_not_dispatched(&c, &raw);
            assert_eq!(
                c.journal
                    .begin_sign(
                        &c.store,
                        c.operation,
                        0,
                        &authorization(&i),
                        &RegtestHeaders::new(),
                        &safety()
                    )
                    .unwrap_err(),
                Error::Ambiguous
            );
        }
        #[test]
        fn first_dispatch_rechecks_store_health_and_bitcoin_refund_margin() {
            let mut c = campaign("dispatch-health-margin");
            let (_, raw) = signed(&mut c);
            set_test_store_halted(&c, true);
            assert_eq!(
                c.journal
                    .broadcast_request(&c.store, c.operation, 0, &RegtestHeaders::new(), &safety())
                    .unwrap_err(),
                Error::Store
            );
            assert_not_dispatched(&c, &raw);
            set_test_store_halted(&c, false);
            let mut headers = RegtestHeaders::new();
            let mut tip = headers.tip().0;
            for _ in 0..91 {
                tip = mine(&mut headers, tip, [212; 32], 0);
            }
            assert_eq!(
                c.journal
                    .broadcast_request(&c.store, c.operation, 0, &headers, &safety())
                    .unwrap_err(),
                Error::Deadline
            );
            assert_not_dispatched(&c, &raw);
        }
        #[test]
        fn first_dispatch_rechecks_already_claimed_canonical_mut_funding() {
            let mut c = campaign("dispatch-spent-mut");
            let (_, raw) = signed(&mut c);
            let point = mutiny_consensus_v8::transactions::OutPoint {
                transaction: [181; 32],
                index: 0,
            };
            let mut claim = tr::Operation {
                meta: tr::Meta {
                    context: c.funding.operation.meta.context.clone(),
                    trade: c.frozen.trade(),
                    contract: c.frozen.contract(),
                    generation: 1,
                    created: 2,
                    expiry: 40,
                    fee: tr::Strikes(20_000),
                    inputs: vec![tr::native_input_id(&point)],
                },
                action: tr::Action::Claim {
                    output: c.funding.operation.output_id(0).unwrap(),
                    recipient: c.frozen.address(),
                    amount: tr::Strikes(50_000),
                    preimage: [42; 32],
                    change: tr::Strikes(80_000),
                },
                approvals: vec![],
                offer_proof: None,
            };
            claim.approve(0, &c.treasury, 1).unwrap();
            commit(
                &mut c,
                tr::NativeOperation {
                    operation: claim,
                    inputs: vec![point],
                }
                .encode()
                .unwrap(),
            );
            assert!(
                c.journal
                    .broadcast_request(&c.store, c.operation, 0, &RegtestHeaders::new(), &safety())
                    .is_err()
            );
            assert_not_dispatched(&c, &raw);
        }
        #[test]
        fn first_dispatch_rejects_inclusion_reorg_and_conflicting_input_evidence() {
            let mut c = campaign("dispatch-conflict");
            let (i, raw) = signed(&mut c);
            let mut headers = RegtestHeaders::new();
            let genesis = headers.tip().0;
            let tid = i.expected_txid().unwrap();
            let block = mine(&mut headers, genesis, tid.to_byte_array(), 0);
            c.journal
                .observe_inclusion(
                    c.operation,
                    0,
                    &Inclusion {
                        block,
                        index: 0,
                        total_transactions: 1,
                        branch: vec![],
                    },
                    &headers,
                )
                .unwrap();
            assert_eq!(
                c.journal
                    .broadcast_request(&c.store, c.operation, 0, &headers, &safety())
                    .unwrap_err(),
                Error::State
            );
            let fork = mine(&mut headers, genesis, [213; 32], 1);
            let fork = mine(&mut headers, fork, [214; 32], 0);
            assert_eq!(
                c.journal
                    .broadcast_request(&c.store, c.operation, 0, &headers, &safety())
                    .unwrap_err(),
                Error::State
            );
            let mut other = tx(&raw, MAX_PREVIOUS_TX).unwrap();
            other.output[1].value = Amount::from_sat(1);
            let block = mine(&mut headers, fork, other.compute_txid().to_byte_array(), 0);
            c.journal
                .observe_conflict(
                    c.operation,
                    0,
                    &serialize(&other),
                    &Inclusion {
                        block,
                        index: 0,
                        total_transactions: 1,
                        branch: vec![],
                    },
                    &headers,
                )
                .unwrap();
            assert_eq!(
                c.journal
                    .broadcast_request(&c.store, c.operation, 0, &headers, &safety())
                    .unwrap_err(),
                Error::State
            );
            assert_not_dispatched(&c, &raw);
            // These are bounded SPV fixtures, not full-node UTXO validation.
        }
        #[test]
        fn ambiguous_dispatch_remains_query_only_when_expired_or_store_unavailable() {
            let mut c = campaign("dispatch-ambiguous");
            let (i, raw) = signed_with_expiry(&mut c, 2);
            let dispatched = c
                .journal
                .broadcast_request(&c.store, c.operation, 0, &RegtestHeaders::new(), &safety())
                .unwrap();
            drop(c.journal);
            c.journal = OperationJournal::open(&c.base.join("journal.sqlite"), policy()).unwrap();
            commit(&mut c, vec![]);
            set_test_store_halted(&c, true);
            assert_eq!(
                c.journal
                    .broadcast_request(&c.store, c.operation, 0, &RegtestHeaders::new(), &safety())
                    .unwrap_err(),
                Error::Ambiguous
            );
            let query = c.journal.reconcile_broadcast(c.operation, 0).unwrap();
            assert_eq!(query.signed_bytes, raw);
            assert_eq!(query.txid, dispatched.txid);
            assert_eq!(query.intent_hash, i.intent_hash().unwrap());
            assert_eq!(query.inputs, vec![i.terms.inputs[0].previous().unwrap().0]);
            assert_eq!(
                c.journal
                    .begin_sign(
                        &c.store,
                        c.operation,
                        0,
                        &authorization(&i),
                        &RegtestHeaders::new(),
                        &safety()
                    )
                    .unwrap_err(),
                Error::Ambiguous
            );
        }
        #[test]
        fn abrupt_exit_before_and_after_head_recheck_never_admits_incomplete_creation() {
            let mut c = campaign_with_funding("registration-process-crashes", false);
            let public = serde_json::json!({"synthetic_only":true,"root":hex::encode(c.f.state.root().unwrap()),"genesis":hex::encode(c.f.genesis.encode()),"records":c.f.state.records().unwrap().into_iter().map(|(k,v)|[hex::encode(k),hex::encode(v)]).collect::<Vec<_>>(),"operation":hex::encode(c.operation),"frozen":hex::encode(c.frozen.encode().unwrap()),"canonical_path":c.base.join("canonical.sqlite")});
            for mode in [8, 9] {
                let dir = c.base.join(format!("crash-{mode}"));
                std::fs::create_dir(&dir).unwrap();
                std::fs::write(
                    dir.join("public.json"),
                    serde_json::to_vec(&public).unwrap(),
                )
                .unwrap();
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "trading_service_v1::bitcoin_candidate::tests::crash_worker",
                        "--nocapture",
                    ])
                    .env("BITCOIN_CRASH_CASE", &dir)
                    .env("BITCOIN_CRASH_MODE", mode.to_string())
                    .output()
                    .unwrap();
                std::fs::write(dir.join("worker.stdout.log"), output.stdout).unwrap();
                std::fs::write(dir.join("worker.stderr.log"), output.stderr).unwrap();
                assert_eq!(output.status.code(), Some(86));
                let mut journal =
                    OperationJournal::open(&dir.join("engine.sqlite"), policy()).unwrap();
                assert_incomplete(&c, &mut journal);
            }
            commit(&mut c, vec![]);
            for mode in [8, 9] {
                let mut journal = OperationJournal::open(
                    &c.base.join(format!("crash-{mode}/engine.sqlite")),
                    policy(),
                )
                .unwrap();
                assert_incomplete(&c, &mut journal);
            }
        }

        #[test]
        #[ignore = "subprocess-only abrupt-exit worker"]
        fn crash_worker() {
            let base = PathBuf::from(std::env::var_os("BITCOIN_CRASH_CASE").unwrap());
            let mode: u8 = std::env::var("BITCOIN_CRASH_MODE")
                .unwrap()
                .parse()
                .unwrap();
            let input: serde_json::Value =
                serde_json::from_slice(&std::fs::read(base.join("public.json")).unwrap()).unwrap();
            let raw = |s: &serde_json::Value| hex::decode(s.as_str().unwrap()).unwrap();
            let root: Hash = raw(&input["root"]).try_into().unwrap();
            let genesis = FinalizedAnchor::decode(&raw(&input["genesis"])).unwrap();
            let records: Vec<_> = input["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| (raw(&r[0]).try_into().unwrap(), raw(&r[1])))
                .collect();
            let state = State::from_records(&records, root).unwrap();
            let op: Hash = raw(&input["operation"]).try_into().unwrap();
            let store = CanonicalStore::open_trusted_genesis(
                Path::new(input["canonical_path"].as_str().unwrap()),
                &genesis,
                &state,
                root,
                1000,
                [255; 32],
            )
            .unwrap();
            let mut engine = OperationJournal::open(&base.join("engine.sqlite"), policy()).unwrap();
            let mut signer =
                DedicatedSignerJournal::open(&base.join("signer.sqlite"), policy()).unwrap();
            if mode == 8 || mode == 9 {
                let frozen = tr::FrozenTreasuryOffer::decode(&raw(&input["frozen"])).unwrap();
                engine
                    .record_creation_with_recheck(&store, &frozen, || {
                        if mode == 9 {
                            current(&store).unwrap();
                        }
                        std::process::exit(86);
                    })
                    .unwrap();
                panic!("crash boundary not reached");
            }
            let (i, _, _) = engine.reconcile(op, 0).unwrap();
            let a = authorization(&i);
            let headers = RegtestHeaders::new();
            if mode == 0 {
                std::process::exit(86);
            }
            engine
                .begin_sign(&store, op, 0, &a, &headers, &safety())
                .unwrap();
            if mode == 1 {
                std::process::exit(86);
            }
            signer
                .authorize_request(&store, &i.encode().unwrap(), &a, &headers, &safety())
                .unwrap();
            if mode == 2 {
                std::process::exit(86);
            }
            let signed = external_sign(&i, &a);
            // This file emulates the exact device response, never a new request.
            std::fs::write(base.join("device-response.bin"), &signed).unwrap();
            if mode == 3 {
                std::process::exit(86);
            }
            signer.persist_signature(op, 0, &signed).unwrap();
            if mode == 4 {
                std::process::exit(86);
            }
            engine.record_signed(op, 0, &signed).unwrap();
            if mode == 5 {
                std::process::exit(86);
            }
            let request = engine
                .broadcast_request(&store, op, 0, &headers, &safety())
                .unwrap();
            std::fs::write(base.join("broadcast-bytes.bin"), request.signed_bytes).unwrap();
            // No network broadcast or acknowledgement occurs. Modes 6/7 are
            // two repetitions at the SAME local dispatch-persistence boundary.
            std::process::exit(86);
        }
        #[test]
        fn eight_abrupt_process_boundaries_preserve_exact_operation_and_signature_identity() {
            let mut c = campaign("process-crashes");
            let i = intent(&mut c);
            let a = authorization(&i);
            let op = c.operation;
            drop(c.journal);
            let public = serde_json::json!({"synthetic_only":true,"root":hex::encode(c.f.state.root().unwrap()),"genesis":hex::encode(c.f.genesis.encode()),
                "records":c.f.state.records().unwrap().into_iter().map(|(k,v)|[hex::encode(k),hex::encode(v)]).collect::<Vec<_>>(),"operation":hex::encode(op),"canonical_path":c.base.join("canonical.sqlite")});
            for mode in 0..8u8 {
                let dir = c.base.join(format!("crash-{mode}"));
                std::fs::create_dir(&dir).unwrap();
                std::fs::copy(c.base.join("journal.sqlite"), dir.join("engine.sqlite")).unwrap();
                std::fs::copy(c.base.join("signer.sqlite"), dir.join("signer.sqlite")).unwrap();
                std::fs::write(
                    dir.join("public.json"),
                    serde_json::to_vec(&public).unwrap(),
                )
                .unwrap();
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "trading_service_v1::bitcoin_candidate::tests::crash_worker",
                        "--nocapture",
                    ])
                    .env("BITCOIN_CRASH_CASE", &dir)
                    .env("BITCOIN_CRASH_MODE", mode.to_string())
                    .output()
                    .unwrap();
                std::fs::write(dir.join("worker.stdout.log"), output.stdout).unwrap();
                std::fs::write(dir.join("worker.stderr.log"), output.stderr).unwrap();
                assert_eq!(output.status.code(), Some(86));
                let mut engine =
                    OperationJournal::open(&dir.join("engine.sqlite"), policy()).unwrap();
                let mut signer =
                    DedicatedSignerJournal::open(&dir.join("signer.sqlite"), policy()).unwrap();
                let (_, stage, stored) = engine.reconcile(op, 0).unwrap();
                assert_eq!(
                    stage,
                    match mode {
                        0 => Stage::Prepared,
                        1..=4 => Stage::SignDispatched,
                        5 => Stage::Signed,
                        _ => Stage::BroadcastPending,
                    }
                );
                if mode > 0 {
                    assert_eq!(
                        engine
                            .begin_sign(&c.store, op, 0, &a, &RegtestHeaders::new(), &safety())
                            .unwrap_err(),
                        Error::Ambiguous
                    );
                }
                if mode >= 2 {
                    assert_eq!(
                        signer
                            .authorize_request(
                                &c.store,
                                &i.encode().unwrap(),
                                &a,
                                &RegtestHeaders::new(),
                                &safety()
                            )
                            .unwrap_err(),
                        Error::Ambiguous
                    );
                }
                if mode >= 4 {
                    let cached = signer.cached_response(op, 0).unwrap().unwrap();
                    engine.record_signed(op, 0, &cached).unwrap();
                    let recovered = if mode >= 6 {
                        engine.reconcile_broadcast(op, 0).unwrap().signed_bytes
                    } else {
                        engine
                            .broadcast_request(&c.store, op, 0, &RegtestHeaders::new(), &safety())
                            .unwrap()
                            .signed_bytes
                    };
                    assert_eq!(recovered, cached);
                    if mode >= 5 {
                        assert_eq!(stored, Some(cached));
                    }
                } else {
                    assert!(
                        engine
                            .broadcast_request(&c.store, op, 0, &RegtestHeaders::new(), &safety())
                            .is_err()
                    );
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_consensus_v8::execution::State;
    #[test]
    fn actual_hybrid_store_boundary_rejects_unparsed_trade_without_state_change() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic_only"], true);
        assert_eq!(f["production_authorized"], false);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let records: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let mut state = State::from_records(&records, root).unwrap();
        let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
        // Explicit synthetic enrichment of the trusted test Genesis only.
        // No existing chain import, custody ceremony or live value.
        use mutiny_consensus_v8::{
            trading_v1 as tr,
            transactions::{Coin, OutPoint, Output},
        };
        use mutiny_crypto_v2::{HybridKey, Role};
        let a =
            HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner).unwrap();
        let b =
            HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap();
        // P7 (WP-T4, AM-6): the maker of the hash-lock offer is the sender a (its wallet key); the
        // Treasury freeze offer is made by the Treasury wallet b.
        let maker = &a;
        let addr = |k: &HybridKey| k.public().address_id(1).unwrap();
        state
            .wallets
            .register(&a.public().descriptor(1).unwrap())
            .unwrap();
        state
            .wallets
            .register(&b.public().descriptor(1).unwrap())
            .unwrap();
        // P6 (WP-T3): trading Treasury records exist only under the Genesis MUT Treasury authority
        // T; this synthetic Genesis makes T = addr(b) (TEST-VALUE class).
        state.dividends = mutiny_consensus_v8::dividend_state_v1::DividendState::genesis(
            mutiny_consensus_v8::treasury_v1::Treasury::new(
                mutiny_consensus_v8::treasury_v1::Class::TestValue,
                b.public().descriptor(1).unwrap(),
            )
            .unwrap(),
        );
        let point = OutPoint {
            transaction: [211; 32],
            index: 0,
        };
        state.coins.insert(
            point.clone(),
            Coin {
                output: Output {
                    owner: addr(&a),
                    atoms: 100_000,
                },
                created_height: 0,
                coinbase: false,
            },
        );
        for (k, v) in tr::treasury_genesis_records(
            &tr::Context {
                network: genesis.network,
                genesis: genesis.genesis,
                fingerprint: genesis.fingerprint,
            },
            addr(&b),
            b.public().descriptor(1).unwrap(),
        )
        .unwrap()
        {
            state.protocol_records.insert(k, v);
        }
        let root = state.root().unwrap();
        let dir = std::path::PathBuf::from(
            std::env::var_os("NATIVE_TRADING_EVIDENCE_DIR").expect("fresh test evidence directory"),
        );
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node-store.sqlite");
        assert!(!path.exists());
        let store =
            CanonicalStore::open_trusted_genesis(&path, &genesis, &state, root, 1000, [255; 32])
                .unwrap();
        let before = store.load().unwrap();
        assert!(
            preview(
                &store,
                vec![0],
                &CandidatePolicy::nonproduction_unresolved()
            )
            .is_err()
        );
        assert_eq!(store.load().unwrap(), before);
        let context = tr::Context {
            network: genesis.network,
            genesis: genesis.genesis,
            fingerprint: genesis.fingerprint,
        };
        let body = tr::OfferBody {
            context: context.clone(),
            maker_descriptor: maker.public().descriptor(1).unwrap(),
            maker_wallet: addr(&a),
            destination: addr(&a),
            condition: Some(tr::preimage_hash(&[215; 32])),
            max_fee: tr::Strikes(20_000),
            nonce: [212; 32],
            created: 1,
            expiry: 10,
            maker_side: 0,
            terms: tr::OfferTerms::HashLinked {
                amount: tr::Strikes(50_000),
                bitcoin_satoshis: 10_000,
                bitcoin_network: 3,
            },
        };
        let mut treasury_body = body.clone();
        treasury_body.created = 0;
        treasury_body.maker_side = 1;
        treasury_body.maker_descriptor = b.public().descriptor(1).unwrap();
        treasury_body.maker_wallet = addr(&b);
        treasury_body.destination = addr(&b);
        let request = tr::TreasuryOfferRequest {
            treasury: addr(&b),
            generation: 1,
            address: addr(&b),
            trade: [213; 32],
            contract: [214; 32],
            offer: tr::SignedOffer::sign(treasury_body, &b).unwrap(),
            wallet_descriptor: b.public().descriptor(1).unwrap(),
        };
        assert!(
            prepare_current_treasury_offer(
                &store,
                request.clone(),
                &CandidatePolicy::nonproduction_unresolved()
            )
            .is_err()
        );
        let prepared = prepare_current_treasury_offer(
            &store,
            request,
            &CandidatePolicy::native_denomination_locked(),
        )
        .unwrap();
        let signature = b
            .sign(
                mutiny_crypto_v2::Domain::Transaction,
                &prepared.signing_payload().unwrap(),
            )
            .unwrap();
        let frozen = prepared.attach_authorization(signature).unwrap();
        let encoded_frozen = frozen.encode().unwrap();
        verify_archived_treasury_offer(
            &store,
            tr::FrozenTreasuryOffer::decode(&encoded_frozen).unwrap(),
            &CandidatePolicy::native_denomination_locked(),
        )
        .unwrap();
        assert_eq!(
            store.load().unwrap(),
            before,
            "Treasury creation and historical verification are read-only"
        );
        let offer = tr::SignedOffer::sign(body, maker).unwrap();
        let mut operation = tr::Operation {
            meta: tr::Meta {
                context,
                trade: [213; 32],
                contract: [214; 32],
                generation: 1,
                envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                    first_height: 1,
                    last_height: 10,
                    reference_height: 0,
                    reference_block: genesis.block,
                    preconditions: vec![],
                },
                fee: tr::Strikes(20_000),
                inputs: vec![tr::native_input_id(&point)],
            },
            action: tr::Action::HashLock {
                offer: offer.body.id().unwrap(),
                maker: offer.body.maker().unwrap(),
                sender: addr(&a),
                recipient: addr(&b),
                amount: tr::Strikes(50_000),
                condition: tr::preimage_hash(&[215; 32]),
                refund_height: 20,
                change: tr::Strikes(30_000),
            },
            approvals: vec![],
            offer_proof: None,
        };
        operation.offer_proof = Some(tr::OfferProof::sign(offer, &operation, maker).unwrap());
        operation.approve(0, &a, 1).unwrap();
        operation.approve(1, &b, 1).unwrap();
        let encoded = tr::NativeOperation {
            operation,
            inputs: vec![point],
        }
        .encode()
        .unwrap();
        assert!(matches!(
            preview(
                &store,
                encoded.clone(),
                &CandidatePolicy::nonproduction_unresolved()
            ),
            Err(ServiceError::Trading(tr::NativeError::UnitUnresolved))
        ));
        let preview = preview(
            &store,
            encoded.clone(),
            &CandidatePolicy::native_denomination_locked(),
        )
        .unwrap();
        let AdmissionPreview::Pending(submission) = preview else {
            panic!("not yet applied")
        };
        assert_eq!(submission.bytes(), encoded);
        assert_eq!(submission.fee_atoms(), 20_000);
        assert_ne!(submission.proposed_root(), root);
        recheck_parent(&store, &submission).unwrap();
        assert_eq!(store.load().unwrap(), before, "preview must never commit");
    }
}

/// WP-T1 (trading body version 2; Lane P design 1.a and 5.1): the node's admission preview and its
/// completion coordinator check the signed window and the finalized reference the way block
/// execution does, taking the canonical block hash of an older reference from the store's
/// certified evidence. Real blocks are committed through `CanonicalStore::commit` by the shared
/// consensus test rig. TEST-VALUE only (public BIP39 phrases, random Transport maker keys).
#[cfg(test)]
#[allow(dead_code, unused_imports)]
mod envelope_tests {
    mod licenses {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../desktop/src/wallet_host_fixture_licenses.rs"
        ));
    }
    mod tpm {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../consensus/tests/support/wallet_host_fixture_tpm.rs"
        ));
    }
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../consensus/tests/support/dividend_rig.rs"
    ));
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../consensus/tests/support/trading_rig_v1.rs"
    ));
    use super::{AdmissionPreview, ServiceError, completion_candidate as cc, preview};
    use mutiny_consensus_v8::op_envelope_v1::EnvelopeError;
    use tr::NativeError as N;

    fn lock_action(sender: Hash, recipient: Hash) -> tr::Action {
        tr::Action::HashLock {
            offer: [0; 32],
            maker: [0; 32],
            sender,
            recipient,
            amount: tr::Strikes(50_000),
            condition: tr::preimage_hash(&[42; 32]),
            refund_height: 30,
            change: tr::Strikes(30_000),
        }
    }

    #[test]
    fn preview_takes_an_older_reference_anchor_from_the_store() {
        let (a, b) = (owner_key(), second_key());
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let mut f = fixture();
        let p1 = fund(&mut f, 0x31, aa, 100_000);
        let p2 = fund(&mut f, 0x32, aa, 100_000);
        let mut rig = Rig::new(f, "node-preview");
        advance(&mut rig, 1);
        let signers = [(0, &a, 1), (1, &b, 1)];
        let lock = trade(&rig.f, lock_action(aa, ba), window_at(&rig, 1, 2, 20), 20_000, &[p1], &signers)
            .encode()
            .unwrap();
        let forged = Window { first: 2, last: 20, reference: (1, [0xee; 32]) };
        let forged = trade(&rig.f, lock_action(aa, ba), forged, 20_000, &[p2], &signers).encode().unwrap();
        advance(&mut rig, 2);
        let policy = tr::CandidatePolicy::native_denomination_locked();
        // Without the anchor of height 1 the consensus check fails closed ...
        assert!(matches!(native_verdict(&rig, &[lock.clone()]), Err(N::Envelope(EnvelopeError::ReferenceNotCanonical))));
        // ... the node supplies it from its own canonical store: the operation is admissible.
        let before = rig.chain.load().unwrap();
        match preview(&rig.chain, lock, &policy).unwrap() {
            AdmissionPreview::Pending(s) => {
                assert_eq!((s.parent().height, s.fee_atoms()), (3, 20_000));
            }
            AdmissionPreview::AlreadyApplied(_) => panic!("not applied"),
        }
        // A block hash that is not canonical at that height is refused.
        assert!(matches!(
            preview(&rig.chain, forged, &policy),
            Err(ServiceError::Trading(N::Envelope(EnvelopeError::ReferenceNotCanonical)))
        ));
        assert_eq!(rig.chain.load().unwrap(), before, "previews never commit");
        rig.finish();
    }

    #[test]
    fn completion_window_is_checked_with_the_stores_anchor_at_every_step() {
        let (a, b) = (owner_key(), second_key());
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let mut f = fixture();
        let p_lock = fund(&mut f, 0x41, aa, 100_000);
        let p_lock2 = fund(&mut f, 0x42, aa, 100_000);
        let p_fee = fund(&mut f, 0x43, ba, 100_000);
        let p_fee2 = fund(&mut f, 0x44, ba, 100_000);
        let mut rig = Rig::new(f, "node-completion");
        let signers = [(0, &a, 1), (1, &b, 1)];
        let w = window_at(&rig, 0, 1, 20);
        let lock = trade(&rig.f, lock_action(aa, ba), w, 20_000, &[p_lock], &signers);
        let lock2 = trade(&rig.f, lock_action(aa, ba), w, 20_000, &[p_lock2], &signers);
        rig.step(1, &[lock.encode().unwrap(), lock2.encode().unwrap()]);
        let policy = tr::CandidatePolicy::native_denomination_locked();
        let mut journal = cc::Journal::open(&rig.base.join("completion.sqlite"), policy).unwrap();
        let terms = |input: &OutPoint, expiry: u64| cc::FeeTerms {
            inputs: vec![input.clone()],
            fee: tr::Strikes(20_000),
            change: tr::Strikes(80_000),
            expiry,
        };
        // Built on head 1: windows [2, 10] and [2, 2], both referencing block 1.
        let id = journal.prepare(&rig.chain, &lock, cc::PathChoice::Claim([42; 32]), terms(&p_fee, 10)).unwrap();
        let id2 = journal.prepare(&rig.chain, &lock2, cc::PathChoice::Claim([42; 32]), terms(&p_fee2, 2)).unwrap();
        for id in [id, id2] {
            let request = journal.request_approval(&rig.chain, id, 0, desc(&b, 1)).unwrap();
            let signature = b.sign(mutiny_crypto_v2::Domain::Transaction, &request.payload).unwrap();
            journal.accept_approval(&rig.chain, id, 0, signature).unwrap();
        }
        let wire = tr::NativeOperation::decode(&journal.signed_bytes(id).unwrap()).unwrap();
        let e = &wire.operation.meta.envelope;
        assert_eq!((e.first_height, e.last_height, e.reference_height), (2, 10, 1));
        assert_eq!(e.reference_block, canonical_hash(&rig, 1));
        // The head advances to 3: block 1 is now an older reference, read from the store.
        advance(&mut rig, 2);
        let submission = journal.dispatch(&rig.chain, id).unwrap();
        assert_eq!(submission.parent().height, 3);
        // The second completion's window [2, 2] has passed: refused, nothing dispatched.
        assert_eq!(journal.dispatch(&rig.chain, id2).err(), Some(cc::Error::Time));
        // The dispatched bytes are included in a real block committed by the store.
        let s4 = rig.step(4, &[submission.bytes().to_vec()]);
        let paid = &s4.coins[&OutPoint { transaction: wire.operation.id().unwrap(), index: 0 }];
        assert_eq!((paid.output.owner, paid.output.atoms), (ba, 50_000));
        drop(journal);
        rig.finish();
    }
}
