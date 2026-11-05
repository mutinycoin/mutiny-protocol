//! Candidate wallet replica backed exclusively by full hybrid canonical replay.
//! No peer tip/status claim, legacy chain, private wallet DB or service startup.
//! Phase 7: it is the source of wallet-core's `ChainView` (head, timestamp, epoch origin, state
//! root and state, all from the locally replayed store) and queues authorized payments; drafting,
//! reviewing and signing are wallet-core's.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    block_envelope_v2::BlockEnvelope,
    canonical_store_v2::{CanonicalStore, Head},
    execution::State,
    mempool_v2::Mempool,
    transactions::{MATURITY, OutPoint},
};
use mutiny_crypto_v2::{PublicKey, Role};
use mutiny_wallet_core_v8::{ConfirmationSource, HeadInfo, OperationKind, SignedOperation};
use std::collections::BTreeSet;
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Hybrid wallet validation: {e:?}")
}
pub struct Replica {
    chain: CanonicalStore,
    genesis: Hash,
    fingerprint: Hash,
    /// The chain's epoch origin, read from the store's own Genesis execution parent.
    t0: u64,
    /// The last snapshot `load` read and verified, with the store's change marker at that
    /// moment. Reused only while the marker is unchanged and the snapshot is recent.
    verified: std::cell::RefCell<Option<VerifiedSnapshot>>,
    /// Test observation: how many times the store itself was read and verified.
    #[cfg(test)]
    loads: std::cell::Cell<u64>,
    /// The last verified confirmation answer, for the same identifiers (see `confirmations`).
    confirmed: std::cell::RefCell<Option<VerifiedConfirmations>>,
    /// Test observation: how many times the confirmation replay actually ran.
    #[cfg(test)]
    confirmation_replays: std::cell::Cell<u64>,
}
struct VerifiedConfirmations {
    marker: (i64, u64),
    at: std::time::Instant,
    ids: Vec<Hash>,
    rows: std::collections::BTreeMap<
        Hash,
        Vec<mutiny_consensus_v8::operation_index_v2::OperationRecord>,
    >,
}
/// How long one verified snapshot may be reused at most. A write through SQLite by any
/// connection ends the reuse at once (`CanonicalStore::change_marker`); this limit bounds the
/// only remaining case, a change to the database file that bypasses SQLite.
const VERIFIED_REUSE_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);
struct VerifiedSnapshot {
    marker: (i64, u64),
    at: std::time::Instant,
    anchor: FinalizedAnchor,
    head: Head,
    state: State,
}
/// The local canonical store's verified confirmation index, for `ChainView::with_confirmations`.
pub struct Confirmations(
    std::collections::BTreeMap<Hash, Vec<mutiny_consensus_v8::operation_index_v2::OperationRecord>>,
);
impl ConfirmationSource for Confirmations {
    fn confirmed_height(&self, id: &Hash) -> Option<u64> {
        self.0.get(id)?.first().map(|r| r.height)
    }
    fn command_outcome(
        &self,
        id: &Hash,
    ) -> Option<(u64, mutiny_consensus_v8::bond_ops_v2::CommandOutcome)> {
        let row = self.0.get(id)?.first()?;
        row.command_outcome()
            .ok()
            .flatten()
            .map(|outcome| (row.height, outcome))
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Balance {
    pub anchor: FinalizedAnchor,
    pub total_atoms: u64,
    pub available_atoms: u64,
    pub reserved_atoms: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    ConfirmedAt(u64),
    Unconfirmed(Option<mutiny_consensus_v8::mempool_v2::Status>),
}
impl Replica {
    /// Canonical reference hashes for wallet-held bytes only. Peer hashes are never inserted.
    /// A concurrent canonical-head change makes this snapshot unusable and is refused.
    pub fn wallet_reference_history(
        &self,
        items: &[Vec<u8>],
    ) -> Result<mutiny_consensus_v8::evidence_history_v2::History> {
        let before = self.current_anchor()?;
        let mut references = BTreeSet::new();
        for raw in items {
            let body = mutiny_consensus_v8::blocks::BlockBody {
                height: before.height.checked_add(1).ok_or("Height overflow")?,
                reward_owner: [1; 32],
                fees: 0,
                transactions: vec![raw.clone()],
                operations: vec![raw.clone()],
            };
            references.extend(mutiny_consensus_v8::op_envelope_v1::referenced_heights(
                &body,
            ));
        }
        let mut history = mutiny_consensus_v8::evidence_history_v2::History::default();
        for height in references {
            if height > before.height {
                return Err("Operation reference is not locally canonical".into());
            }
            let block = if height == 0 {
                self.chain.execution_parent(0).map_err(err)?.0.block
            } else {
                self.chain
                    .canonical_block(height)
                    .map_err(err)?
                    .ok_or("Canonical operation reference missing")?
                    .block_hash()
            };
            history.insert_anchor(height, block).map_err(err)?;
        }
        if self.current_anchor()? != before {
            return Err("Canonical head changed while loading wallet references".into());
        }
        Ok(history)
    }
    /// Store construction must start at independently authenticated Genesis.
    /// Its constructor fully reproduces persisted history before returning.
    pub fn from_pinned_chain(chain: CanonicalStore) -> Result<Self> {
        if chain.halted().map_err(err)? {
            return Err("Wallet chain integrity halt".into());
        }
        let (parent, _, _) = chain.execution_parent(0).map_err(err)?;
        Ok(Self {
            chain,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            t0: parent.t0,
            verified: std::cell::RefCell::new(None),
            #[cfg(test)]
            loads: std::cell::Cell::new(0),
            confirmed: std::cell::RefCell::new(None),
            #[cfg(test)]
            confirmation_replays: std::cell::Cell::new(0),
        })
    }
    /// The verified head and state of the local canonical store.
    ///
    /// Reading the store rebuilds and re-verifies the whole state, which is far too slow to
    /// repeat for every widget of every frame. The result is therefore reused, but only while
    /// all of these hold: the integrity halt is clear (checked on every call), the store's
    /// change marker equals the one taken BEFORE that snapshot was read, the marker did not
    /// move while it was being read, and the snapshot is younger than `VERIFIED_REUSE_LIMIT`.
    /// Any write through SQLite, by this connection or another, moves the marker and forces a
    /// full read. Nothing from a peer can enter this path.
    fn load(&self) -> Result<(FinalizedAnchor, Head, State)> {
        if self.chain.halted().map_err(err)? {
            return Err("Wallet chain integrity halt".into());
        }
        let marker = self.chain.change_marker().map_err(err)?;
        if let Some(kept) = self.verified.borrow().as_ref() {
            if kept.marker == marker && kept.at.elapsed() < VERIFIED_REUSE_LIMIT {
                return Ok((kept.anchor.clone(), kept.head.clone(), kept.state.clone()));
            }
        }
        // Drop the old snapshot first: a refused read must not leave it reusable.
        self.verified.borrow_mut().take();
        let (head, state) = self.chain.load().map_err(err)?;
        #[cfg(test)]
        self.loads.set(self.loads.get() + 1);
        if self.chain.halted().map_err(err)? {
            return Err("Wallet chain integrity halt".into());
        }
        let anchor = FinalizedAnchor {
            network: NETWORK_ID,
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            height: head.height,
            block: head.block,
        };
        // Keep it only if nothing was written while it was being read.
        if self.chain.change_marker().map_err(err)? == marker {
            *self.verified.borrow_mut() = Some(VerifiedSnapshot {
                marker,
                at: std::time::Instant::now(),
                anchor: anchor.clone(),
                head: head.clone(),
                state: state.clone(),
            });
        }
        Ok((anchor, head, state))
    }
    /// Test hook: make the kept snapshot older than the reuse limit.
    #[cfg(test)]
    fn expire_verified_for_test(&self) {
        let old = std::time::Instant::now()
            .checked_sub(VERIFIED_REUSE_LIMIT)
            .expect("monotonic clock older than the reuse limit");
        if let Some(kept) = self.verified.borrow_mut().as_mut() {
            kept.at = old;
        }
        if let Some(kept) = self.confirmed.borrow_mut().as_mut() {
            kept.at = old;
        }
    }
    fn snapshot(&self) -> Result<(FinalizedAnchor, State)> {
        self.load().map(|(anchor, _, state)| (anchor, state))
    }
    /// The verified head as wallet-core's `HeadInfo` (anchor, the head block's timestamp, the
    /// chain's epoch origin and the authenticated state root) with its state, from the LOCALLY
    /// replayed canonical store only. Build every `ChainView` from this; never from a peer's claim.
    pub fn verified(&self) -> Result<(HeadInfo, State)> {
        let (anchor, head, state) = self.load()?;
        let info = HeadInfo::new(anchor, head.timestamp, self.t0, head.root)
            .map_err(|refusal| format!("Hybrid wallet validation: {refusal}"))?;
        Ok((info, state))
    }
    /// Query only bounded wallet-held identifiers. Each batch replays our own authenticated
    /// Genesis and checks exact membership and execution outcomes in one stable read snapshot.
    /// A head change across batches refuses the entire result; peer statuses are never consulted.
    pub fn confirmations(&self, ids: &[Hash]) -> Result<Confirmations> {
        if ids.len() > 5120 {
            return Err("Wallet confirmation query exceeds local queue bound".into());
        }
        let before = self.current_anchor()?;
        let unique: Vec<_> = ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        // Each batch below replays the whole canonical history. For the SAME identifiers the
        // answer cannot differ while the store is unchanged, so it is reused under exactly the
        // conditions of `load`: an unmoved change marker, a recent result, and the halt check
        // that `current_anchor` has just made.
        let marker = self.chain.change_marker().map_err(err)?;
        if let Some(kept) = self.confirmed.borrow().as_ref() {
            if kept.marker == marker && kept.ids == unique && kept.at.elapsed() < VERIFIED_REUSE_LIMIT
            {
                return Ok(Confirmations(kept.rows.clone()));
            }
        }
        self.confirmed.borrow_mut().take();
        let mut rows = std::collections::BTreeMap::new();
        for chunk in unique.chunks(64) {
            rows.extend(
                self.chain
                    .verified_operation_records_many(chunk)
                    .map_err(err)?,
            );
        }
        #[cfg(test)]
        self.confirmation_replays.set(self.confirmation_replays.get() + 1);
        if self.current_anchor()? != before {
            return Err("Canonical head changed while verifying wallet outcomes".into());
        }
        if self.chain.change_marker().map_err(err)? == marker {
            *self.confirmed.borrow_mut() = Some(VerifiedConfirmations {
                marker,
                at: std::time::Instant::now(),
                ids: unique,
                rows: rows.clone(),
            });
        }
        Ok(Confirmations(rows))
    }
    /// Bring the payment pool to the verified head (its basis and reservations).
    pub fn reconcile(&self, pool: &mut Mempool) -> Result<()> {
        self.chain.reconcile_pool(pool).map_err(err)
    }
    /// The canonical store's change marker (`CanonicalStore::change_marker`), for an owner that
    /// skips repeating a reconcile while neither the store nor its pool has been written.
    pub fn change_marker(&self) -> Result<(i64, u64)> {
        self.chain.change_marker().map_err(err)
    }
    /// `pending_for_transport` for a caller that has ALREADY reconciled this exact pool at the
    /// current head. The pool itself refuses (stale basis) if that is not true.
    pub fn pending_after_reconcile(&self, pool: &Mempool) -> Result<Vec<Vec<u8>>> {
        let (anchor, state) = self.snapshot()?;
        pool.pending_at(&anchor, &state)
            .map_err(err)?
            .into_iter()
            .map(|tx| tx.encode().map_err(err))
            .collect()
    }
    pub fn current_anchor(&self) -> Result<FinalizedAnchor> {
        self.snapshot().map(|(anchor, _)| anchor)
    }
    /// Untrusted transport provides bounded canonical bytes only. Local PoW,
    /// state execution and parent-weight dual certificate establish authority.
    pub fn accept(&mut self, raw: &[u8]) -> Result<bool> {
        let envelope = BlockEnvelope::decode(raw).map_err(err)?;
        // Own writes never rely on the change marker alone: everything kept is dropped.
        self.verified.get_mut().take();
        self.confirmed.get_mut().take();
        let result = self.chain.commit(&envelope).map_err(err);
        self.verified.get_mut().take();
        self.confirmed.get_mut().take();
        result
    }
    /// Public recovery evidence is independently verified against local history.
    /// Acceptance changes successor authority, not balance or confirmation.
    pub fn accept_recovery(&mut self, raw: &[u8]) -> Result<bool> {
        self.verified.get_mut().take();
        self.confirmed.get_mut().take();
        let result = self
            .chain
            .accept_recovery_encoded(raw)
            .map(|r| r.inserted)
            .map_err(err);
        self.verified.get_mut().take();
        self.confirmed.get_mut().take();
        result
    }
    /// B1 ordered history: the node's sealed canonical adapter borrows this store for one call, so
    /// installs use the same native verification and commit as `accept`, with no second runtime.
    /// Both caches are dropped before and after, on success and on error alike; the caller re-reads
    /// the actual anchor afterwards and never infers from an error whether a commit happened.
    pub fn with_history_verifier<R>(
        &mut self,
        f: impl FnOnce(&mut mutinyd_v8::history_service_v1::CanonicalHistoryVerifier<'_>) -> R,
    ) -> R {
        self.verified.get_mut().take();
        self.confirmed.get_mut().take();
        let result = f(&mut mutinyd_v8::history_service_v1::CanonicalHistoryVerifier::new(&mut self.chain));
        self.verified.get_mut().take();
        self.confirmed.get_mut().take();
        result
    }
    /// Persist exact signed bytes before transport. No receipt from a peer can
    /// enter the canonical confirmation index through this public queue.
    pub fn stage_signed(
        &self,
        pool: &mut mutiny_consensus_v8::mempool_v2::Mempool,
        raw: &[u8],
    ) -> Result<Delivery> {
        let transaction =
            mutiny_consensus_v8::hybrid_transaction_v2::Transaction::decode(raw).map_err(err)?;
        self.chain.reconcile_pool(pool).map_err(err)?;
        let (anchor, state) = self.snapshot()?;
        pool.admit(&transaction, &anchor, &state).map_err(err)?;
        self.delivery(pool, transaction.id().map_err(err)?)
    }
    pub fn pending_for_transport(
        &self,
        pool: &mut mutiny_consensus_v8::mempool_v2::Mempool,
    ) -> Result<Vec<Vec<u8>>> {
        self.chain.reconcile_pool(pool).map_err(err)?;
        let (anchor, state) = self.snapshot()?;
        pool.pending_at(&anchor, &state)
            .map_err(err)?
            .into_iter()
            .map(|tx| tx.encode().map_err(err))
            .collect()
    }
    pub fn delivery(
        &self,
        pool: &mut mutiny_consensus_v8::mempool_v2::Mempool,
        id: Hash,
    ) -> Result<Delivery> {
        self.snapshot()?;
        if let Some(record) = self
            .chain
            .verified_operation_records(id)
            .map_err(err)?
            .first()
        {
            return Ok(Delivery::ConfirmedAt(record.height));
        }
        self.chain.reconcile_pool(pool).map_err(err)?;
        let status = pool.status(id).map_err(err)?;
        if status == Some(mutiny_consensus_v8::mempool_v2::Status::Confirmed) {
            return Err("Pending cache claims confirmation absent from canonical history".into());
        }
        Ok(Delivery::Unconfirmed(status))
    }
    pub fn balance(&self, descriptor: &[u8], reserved: &BTreeSet<OutPoint>) -> Result<Balance> {
        let (key, _) = PublicKey::decode_descriptor(descriptor).map_err(err)?;
        if key.role != Role::WalletOwner {
            return Err("Wrong wallet role".into());
        }
        let (anchor, state) = self.snapshot()?;
        let next = anchor.height.checked_add(1).ok_or("Height overflow")?;
        let mut result = Balance {
            anchor,
            total_atoms: 0,
            available_atoms: 0,
            reserved_atoms: 0,
        };
        for (point, coin) in &state.coins {
            if state
                .wallets
                .authorize(coin.output.owner, descriptor)
                .is_err()
            {
                continue;
            }
            if coin.created_height > result.anchor.height {
                return Err("Invalid coin height".into());
            }
            result.total_atoms = result
                .total_atoms
                .checked_add(coin.output.atoms)
                .ok_or("Balance overflow")?;
            if reserved.contains(point) {
                result.reserved_atoms = result
                    .reserved_atoms
                    .checked_add(coin.output.atoms)
                    .ok_or("Balance overflow")?;
            } else if !coin.coinbase || next - coin.created_height >= MATURITY {
                result.available_atoms = result
                    .available_atoms
                    .checked_add(coin.output.atoms)
                    .ok_or("Balance overflow")?;
            }
        }
        Ok(result)
    }
    /// The response supplies neither its own trusted root nor trusted finality.
    /// A proof for a different local head fails instead of changing the anchor.
    pub fn verify_utxo(
        &self,
        raw: &[u8],
        point: &OutPoint,
        owner: Hash,
    ) -> Result<Option<mutiny_consensus_v8::transactions::Coin>> {
        let (anchor, state) = self.snapshot()?;
        mutiny_consensus_v8::state_proof::verify_utxo(
            raw,
            &anchor,
            state.root().map_err(err)?,
            point,
            owner,
        )
        .map_err(err)
    }
    pub fn verify_wallet_authority(
        &self,
        address_proof: &[u8],
        current_proof: &[u8],
        address: Hash,
    ) -> Result<mutiny_consensus_v8::state_proof::VerifiedWalletAuthority> {
        let (anchor, state) = self.snapshot()?;
        mutiny_consensus_v8::state_proof::verify_wallet_authority(
            address_proof,
            current_proof,
            &anchor,
            state.root().map_err(err)?,
            address,
        )
        .map_err(err)
    }
    /// The post-signing half of the UI submission path: persist an AUTHORIZED payment (a complete
    /// wallet-core `SignedOperation` of kind payment, already verified through consensus code by
    /// `Signer::authorize`) in the payment pool BEFORE success is reported. The canonical head must
    /// still be the reviewed one and the pool must be at it; `Mempool::admit` verifies the
    /// transaction again and reserves its inputs durably. Transport reads the durable queue
    /// separately. A returned id means durably queued, never settled; no broadcast occurs.
    pub fn queue_signed_payment(
        &self,
        pool: &mut Mempool,
        signed: &SignedOperation,
        reviewed: &FinalizedAnchor,
    ) -> Result<Hash> {
        if signed.kind() != OperationKind::Payment || !signed.is_complete() {
            return Err("Only a complete payment enters the payment queue".into());
        }
        self.chain.reconcile_pool(pool).map_err(err)?;
        let (anchor, state) = self.snapshot()?;
        if &anchor != reviewed {
            return Err("Canonical head changed during signing; prepare and review again".into());
        }
        if pool.basis().map_err(err)? != Some((anchor.clone(), state.root().map_err(err)?)) {
            return Err("Pending queue changed; prepare and review again".into());
        }
        let tx = mutiny_consensus_v8::hybrid_transaction_v2::Transaction::decode(signed.bytes())
            .map_err(err)?;
        if tx.id().map_err(err)? != signed.id() {
            return Err("Signed payment identity changed".into());
        }
        pool.admit(&tx, &anchor, &state).map_err(err)?;
        Ok(signed.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_recovery_preserves_balance_until_verified_successor_and_survives_restart() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-recovery-chain-public-v4.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic_only"], true);
        assert_eq!(f["production_authorized"], false);
        assert_eq!(f["physical_tpm"], false);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let rows: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let state = State::from_records(&rows, root).unwrap();
        let genesis = FinalizedAnchor::decode(&raw(&f["genesis_anchor"])).unwrap();
        let target = FinalizedAnchor::decode(&raw(&f["target_anchor"])).unwrap();
        let recovery = raw(&f["recovery1"]);
        let record = mutiny_consensus_v8::recovery_history_v2::Record::decode(
            &recovery,
            state.recovery_authority_v2.as_ref().unwrap(),
        )
        .unwrap();
        let descriptor = &record.policy.owner_descriptor;
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "build8-wallet-public-recovery-{}",
            hex::encode(nonce)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("replica.sqlite");
        let open = || {
            Replica::from_pinned_chain(
                CanonicalStore::open_trusted_genesis(
                    &path, &genesis, &state, root, 1000, [255; 32],
                )
                .unwrap(),
            )
            .unwrap()
        };
        let mut replica = open();
        let mut pool = mutiny_consensus_v8::mempool_v2::Mempool::open(
            &directory.join("outbox.sqlite"),
            genesis.genesis,
            genesis.fingerprint,
            65536,
        )
        .unwrap();
        assert!(replica.accept_recovery(&recovery).is_err());
        assert_eq!(replica.current_anchor().unwrap(), genesis);
        assert!(replica.accept(&raw(&f["block1"])).unwrap());
        let parent = replica.current_anchor().unwrap();
        let before = replica.balance(descriptor, &BTreeSet::new()).unwrap();
        let records = replica.chain.load().unwrap().1.records().unwrap();
        assert!(replica.accept(&raw(&f["block2"])).is_err());
        let mut damaged = recovery.clone();
        damaged.push(0);
        assert!(replica.accept_recovery(&damaged).is_err());
        assert!(replica.accept_recovery(&recovery).unwrap());
        assert_eq!(replica.current_anchor().unwrap(), parent);
        assert_eq!(
            replica.balance(descriptor, &BTreeSet::new()).unwrap(),
            before
        );
        assert_eq!(replica.chain.load().unwrap().1.records().unwrap(), records);
        assert_eq!(
            replica.delivery(&mut pool, [117; 32]).unwrap(),
            Delivery::Unconfirmed(None)
        );
        drop(replica);
        let mut replica = open();
        assert_eq!(
            replica.balance(descriptor, &BTreeSet::new()).unwrap(),
            before
        );
        assert!(!replica.accept_recovery(&recovery).unwrap());
        assert!(replica.accept(&raw(&f["block2"])).unwrap());
        assert_eq!(replica.current_anchor().unwrap(), target);
        assert!(!replica.accept_recovery(&recovery).unwrap());
        let after = replica.balance(descriptor, &BTreeSet::new()).unwrap();
        assert!(after.total_atoms > before.total_atoms);
        assert_eq!(
            replica.delivery(&mut pool, [117; 32]).unwrap(),
            Delivery::Unconfirmed(None)
        );
        drop(replica);
        let replica = open();
        assert_eq!(
            replica.balance(descriptor, &BTreeSet::new()).unwrap(),
            after
        );
        drop(replica);
        drop(pool);
        std::fs::remove_dir_all(directory).unwrap();
    }
    /// A payment plan of the fixture's wallet against this replica's verified view and `reserved`.
    fn plan_payment(
        replica: &Replica,
        me: &mutiny_wallet_core_v8::SignerIdentity,
        amount: u64,
        reserved: &BTreeSet<OutPoint>,
    ) -> std::result::Result<mutiny_wallet_core_v8::OperationPlan, mutiny_wallet_core_v8::Refusal>
    {
        let (head, state) = replica.verified().unwrap();
        let view = mutiny_wallet_core_v8::ChainView::verified(head, &state, reserved).unwrap();
        mutiny_wallet_core_v8::plan(
            &mutiny_wallet_core_v8::OperationRequest::Payment(
                mutiny_wallet_core_v8::PaymentRequest::new([94; 32], amount),
            ),
            &view,
            me,
        )
    }
    /// Ported (phase 7) from the test of the same name, which drove the retired desktop `Draft` and
    /// `Approval`: the same properties through wallet-core's plan, review gate and signer and this
    /// replica's payment queue. Durable before success, nothing pending or reserved after a refused
    /// queueing, a changed operation cannot use another review's approval, a competing payment over
    /// the same coin fails closed, the exact bytes survive a reopen and still verify.
    #[test]
    fn approved_payment_is_durable_before_transport_and_conflicts_fail_closed() {
        use crate::test_support::{TestDir, flow};
        use mutiny_consensus_v8::transactions::{Coin, Output};
        use mutiny_wallet_core_v8::{
            ChainView, KeySigner, OperationRequest, PaymentRequest, Refusal, Signer,
            SignerIdentity, plan, review,
        };
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        assert_eq!(fixture["synthetic_only"], true);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&fixture["root"]).try_into().unwrap();
        let records: Vec<_> = fixture["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let mut state = State::from_records(&records, root).unwrap();
        let mut genesis = FinalizedAnchor::decode(&raw(&fixture["genesis"])).unwrap();
        genesis.block = [77; 32];
        // New isolated synthetic trusted state, never the sealed network Genesis. Public TEST-VALUE
        // key (the all-"abandon" BIP-39 vector) behind wallet-core's TEST-VALUE gate.
        let key = mutiny_crypto_v2::HybridKey::wallet_restore(
            &format!("{}art", "abandon ".repeat(23)),
            Role::WalletOwner,
        )
        .unwrap();
        let me = SignerIdentity::from_public(key.public(), 1, None).unwrap();
        let signer = KeySigner::for_test(key).unwrap();
        let point = OutPoint {
            transaction: [78; 32],
            index: 0,
        };
        state.coins.clear();
        state.coins.insert(
            point.clone(),
            Coin {
                output: Output {
                    owner: me.address(),
                    atoms: 100_000,
                },
                created_height: 0,
                coinbase: false,
            },
        );
        let root = state.root().unwrap();
        let directory = TestDir::new("approved-outbox");
        let chain = CanonicalStore::open_trusted_genesis(
            &directory.file("chain.sqlite"),
            &genesis,
            &state,
            root,
            1000,
            [255; 32],
        )
        .unwrap();
        let replica = Replica::from_pinned_chain(chain).unwrap();
        let pay = |amount| OperationRequest::Payment(PaymentRequest::new([94; 32], amount));
        // Review, every typed check and acknowledgement, approval, authorization: against the
        // pool's reservations at the verified head, as the controller does it.
        let sign = |pool: &mut Mempool, amount: u64| -> (SignedOperation, FinalizedAnchor) {
            replica.reconcile(pool).unwrap();
            let (head, state) = replica.verified().unwrap();
            let reserved = pool.reserved_inputs().unwrap();
            let view = ChainView::verified(head, &state, &reserved).unwrap();
            let planned = plan(&pay(amount), &view, &me).unwrap();
            let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
            let signed = signer.authorize(planned, approval, &view).unwrap();
            (signed, view.anchor().clone())
        };
        let mut tiny = Mempool::open(
            &directory.file("tiny.sqlite"),
            genesis.genesis,
            genesis.fingerprint,
            1,
        )
        .unwrap();
        let (signed, anchor) = sign(&mut tiny, 50_000);
        assert!(
            replica
                .queue_signed_payment(&mut tiny, &signed, &anchor)
                .is_err()
        );
        assert!(replica.pending_for_transport(&mut tiny).unwrap().is_empty());
        assert!(tiny.reserved_inputs().unwrap().is_empty());
        drop(tiny);
        let queue = directory.file("queue.sqlite");
        let mut pool = Mempool::open(&queue, genesis.genesis, genesis.fingerprint, 65536).unwrap();
        {
            // The approval of one review cannot authorize a different operation.
            replica.reconcile(&mut pool).unwrap();
            let (head, state) = replica.verified().unwrap();
            let reserved = pool.reserved_inputs().unwrap();
            let view = ChainView::verified(head, &state, &reserved).unwrap();
            let planned = plan(&pay(50_000), &view, &me).unwrap();
            let changed = plan(&pay(50_001), &view, &me).unwrap();
            let approval = flow::approve(&review(&changed, &view).unwrap(), &view);
            assert_eq!(
                signer.authorize(planned, approval, &view).unwrap_err(),
                Refusal::PlanChanged
            );
        }
        assert!(pool.pending().unwrap().is_empty());
        // Two payments signed over the same coin before either is queued: the first is queued, the
        // competing one fails closed.
        let (competing, competing_anchor) = sign(&mut pool, 30_000);
        let (signed, anchor) = sign(&mut pool, 50_000);
        let expected = signed.id();
        assert_eq!(
            replica
                .queue_signed_payment(&mut pool, &signed, &anchor)
                .unwrap(),
            expected
        );
        assert!(
            replica
                .queue_signed_payment(&mut pool, &competing, &competing_anchor)
                .is_err()
        );
        // Exactly the first payment is queued: its exact signed bytes, its coin reserved.
        let before = replica.pending_for_transport(&mut pool).unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0], signed.bytes());
        assert_eq!(pool.reserved_inputs().unwrap(), BTreeSet::from([point]));
        // The queued coin is reserved: a new plan at the head cannot select it.
        assert!(plan_payment(&replica, &me, 1, &pool.reserved_inputs().unwrap()).is_err());
        drop(pool);
        let mut pool = Mempool::open(&queue, genesis.genesis, genesis.fingerprint, 65536).unwrap();
        assert_eq!(replica.pending_for_transport(&mut pool).unwrap(), before);
        assert_eq!(
            replica.delivery(&mut pool, expected).unwrap(),
            Delivery::Unconfirmed(Some(mutiny_consensus_v8::mempool_v2::Status::Pending))
        );
        let tx =
            mutiny_consensus_v8::hybrid_transaction_v2::Transaction::decode(&before[0]).unwrap();
        tx.verify(
            &mutiny_consensus_v8::hybrid_transaction_v2::Inclusion {
                parent: &genesis,
                history: &mutiny_consensus_v8::evidence_history_v2::History::default(),
            },
            &state,
        )
        .unwrap();
        drop(pool);
        drop(replica);
    }
    /// The verified snapshot is reused only while the store is provably unchanged: every kind
    /// of change, and age alone, forces a full read; an integrity halt refuses at once.
    #[test]
    fn verified_snapshot_is_reused_only_while_the_store_is_unchanged() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic_only"], true);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let records: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let state = State::from_records(&records, root).unwrap();
        let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
        let block = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "build8-wallet-verified-reuse-{}.sqlite",
            hex::encode(nonce)
        ));
        let chain =
            CanonicalStore::open_trusted_genesis(&path, &genesis, &state, root, 1000, [255; 32])
                .unwrap();
        let mut replica = Replica::from_pinned_chain(chain).unwrap();
        assert_eq!(replica.loads.get(), 0);

        // Unchanged store: one real read serves any number of callers, with equal results.
        let (first, first_state) = replica.verified().unwrap();
        let (second, second_state) = replica.verified().unwrap();
        assert_eq!(replica.current_anchor().unwrap(), genesis);
        assert_eq!(replica.loads.get(), 1);
        assert_eq!(first.anchor(), second.anchor());
        assert_eq!(first_state.root().unwrap(), second_state.root().unwrap());

        // Age alone ends the reuse.
        replica.expire_verified_for_test();
        replica.verified().unwrap();
        assert_eq!(replica.loads.get(), 2);
        replica.verified().unwrap();
        assert_eq!(replica.loads.get(), 2);

        // A statement by ANOTHER connection that writes nothing leaves the store, and so the
        // reuse, untouched (SQLite commits no page for an update that changes no byte).
        let other = rusqlite::Connection::open(&path).unwrap();
        other
            .execute("UPDATE integrity_v2 SET halted=halted WHERE id=1", [])
            .unwrap();
        replica.verified().unwrap();
        assert_eq!(replica.loads.get(), 2);
        // Real commits by another connection end the reuse, even when the final content is
        // equal to what was verified before.
        other
            .execute("UPDATE integrity_v2 SET halted=1 WHERE id=1", [])
            .unwrap();
        other
            .execute("UPDATE integrity_v2 SET halted=0 WHERE id=1", [])
            .unwrap();
        replica.verified().unwrap();
        assert_eq!(replica.loads.get(), 3);
        replica.verified().unwrap();
        assert_eq!(replica.loads.get(), 3);

        // A refused own write keeps the old head and still drops the kept snapshot.
        let mut forged = block.clone();
        forged.certificate.votes[0].signature.fndsa[100] ^= 1;
        assert!(replica.accept(&forged.encode().unwrap()).is_err());
        assert_eq!(replica.current_anchor().unwrap(), genesis);
        assert_eq!(replica.loads.get(), 4);

        // An accepted own write is visible to the very next read.
        assert!(replica.accept(&block.encode().unwrap()).unwrap());
        let (head, _) = replica.verified().unwrap();
        assert_eq!(head.anchor().height, 1);
        assert_eq!(replica.loads.get(), 5);
        replica.verified().unwrap();
        assert_eq!(replica.loads.get(), 5);

        // Confirmation answers follow the same rule, per exact set of identifiers.
        let id = mutiny_consensus_v8::transactions_v2::Transfer::decode(&block.body.transactions[0])
            .unwrap()
            .id()
            .unwrap();
        assert_eq!(replica.confirmation_replays.get(), 0);
        let first = replica.confirmations(&[id]).unwrap();
        let second = replica.confirmations(&[id]).unwrap();
        assert_eq!(replica.confirmation_replays.get(), 1);
        assert_eq!(first.confirmed_height(&id), Some(1));
        assert_eq!(second.confirmed_height(&id), Some(1));
        // Other identifiers are never answered from what was kept, and they replace it.
        let unknown = [7u8; 32];
        assert_eq!(
            replica.confirmations(&[unknown]).unwrap().confirmed_height(&unknown),
            None
        );
        assert_eq!(replica.confirmation_replays.get(), 2);
        assert_eq!(
            replica.confirmations(&[id]).unwrap().confirmed_height(&id),
            Some(1)
        );
        assert_eq!(replica.confirmation_replays.get(), 3);
        // Age, and a commit by another connection, each force the replay again.
        replica.expire_verified_for_test();
        replica.confirmations(&[id]).unwrap();
        assert_eq!(replica.confirmation_replays.get(), 4);
        other
            .execute("UPDATE integrity_v2 SET halted=1 WHERE id=1", [])
            .unwrap();
        other
            .execute("UPDATE integrity_v2 SET halted=0 WHERE id=1", [])
            .unwrap();
        assert_eq!(
            replica.confirmations(&[id]).unwrap().confirmed_height(&id),
            Some(1)
        );
        assert_eq!(replica.confirmation_replays.get(), 5);

        // An integrity halt set by another connection refuses immediately; nothing kept is served.
        let loads_before_halt = replica.loads.get();
        let replays_before_halt = replica.confirmation_replays.get();
        other
            .execute("UPDATE integrity_v2 SET halted=1 WHERE id=1", [])
            .unwrap();
        assert!(replica.verified().is_err());
        assert!(replica.current_anchor().is_err());
        assert!(replica.confirmations(&[id]).is_err());
        assert_eq!(replica.loads.get(), loads_before_halt);
        assert_eq!(replica.confirmation_replays.get(), replays_before_halt);
        drop(other);
        drop(replica);
        let _ = std::fs::remove_file(&path);
    }
    #[test]
    fn public_hybrid_chain_drives_balance_and_rejects_forged_confirmation() {
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
        let state = State::from_records(&records, root).unwrap();
        let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
        let block = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "build8-wallet-public-replica-{}.sqlite",
            hex::encode(nonce)
        ));
        assert!(!path.exists());
        let chain =
            CanonicalStore::open_trusted_genesis(&path, &genesis, &state, root, 1000, [255; 32])
                .unwrap();
        let mut replica = Replica::from_pinned_chain(chain).unwrap();
        let transfer =
            mutiny_consensus_v8::transactions_v2::Transfer::decode(&block.body.transactions[0])
                .unwrap();
        let descriptor = &transfer.inputs[0].descriptor;
        let before = replica.balance(descriptor, &BTreeSet::new()).unwrap();
        assert_eq!(before.total_atoms, 100000);
        assert_eq!(before.available_atoms, 100000);
        let reserved = BTreeSet::from([transfer.inputs[0].point.clone()]);
        assert_eq!(
            replica
                .balance(descriptor, &reserved)
                .unwrap()
                .available_atoms,
            0
        );
        // Phase 7: wallet-core plans from the replica's verified view (the retired drafts did).
        let me = mutiny_wallet_core_v8::SignerIdentity::new(descriptor, None).unwrap();
        assert!(plan_payment(&replica, &me, 50000, &reserved).is_err());
        let planned = plan_payment(&replica, &me, 50000, &BTreeSet::new()).unwrap();
        assert_eq!(planned.anchor(), &genesis);
        let queue_path = path.with_extension("queue.sqlite");
        assert!(!queue_path.exists());
        let mut pool = mutiny_consensus_v8::mempool_v2::Mempool::open(
            &queue_path,
            genesis.genesis,
            genesis.fingerprint,
            65536,
        )
        .unwrap();
        let id = transfer.id().unwrap();
        let pending = Delivery::Unconfirmed(Some(mutiny_consensus_v8::mempool_v2::Status::Pending));
        assert_eq!(
            replica
                .stage_signed(&mut pool, &block.body.transactions[0])
                .unwrap(),
            pending
        );
        assert_eq!(
            replica
                .stage_signed(&mut pool, &block.body.transactions[0])
                .unwrap(),
            pending
        );
        drop(pool);
        let mut pool = mutiny_consensus_v8::mempool_v2::Mempool::open(
            &queue_path,
            genesis.genesis,
            genesis.fingerprint,
            65536,
        )
        .unwrap();
        assert_eq!(
            replica.pending_for_transport(&mut pool).unwrap(),
            block.body.transactions
        );
        assert_eq!(pool.reserved_inputs().unwrap(), reserved);
        let tamper = rusqlite::Connection::open(&queue_path).unwrap();
        tamper
            .execute("UPDATE lifecycle_v2 SET status='CONFIRMED'", [])
            .unwrap();
        assert!(replica.delivery(&mut pool, id).is_err());
        tamper
            .execute("UPDATE lifecycle_v2 SET status='PENDING'", [])
            .unwrap();
        drop(tamper);
        let mut forged = block.clone();
        forged.certificate.votes[0].signature.fndsa[100] ^= 1;
        assert!(replica.accept(&forged.encode().unwrap()).is_err());
        assert_eq!(
            replica.balance(descriptor, &BTreeSet::new()).unwrap(),
            before
        );
        assert!(replica.accept(&block.encode().unwrap()).unwrap());
        assert!(!replica.accept(&block.encode().unwrap()).unwrap());
        let after = replica.balance(descriptor, &BTreeSet::new()).unwrap();
        assert_eq!(after.anchor.height, 1);
        assert_eq!(after.total_atoms, 100005000);
        assert_eq!(after.available_atoms, 0);
        assert_eq!(
            replica.delivery(&mut pool, id).unwrap(),
            Delivery::ConfirmedAt(1)
        );
        assert!(replica.pending_for_transport(&mut pool).unwrap().is_empty());
        assert!(pool.reserved_inputs().unwrap().is_empty());
        assert!(plan_payment(&replica, &me, 1, &BTreeSet::new()).is_err());
        let (_, post) = replica.snapshot().unwrap();
        let mut tree = mutiny_consensus_v8::state_tree::StateTree::default();
        for (key, value) in post.records().unwrap() {
            tree.insert(key, value).unwrap();
        }
        let point = OutPoint {
            transaction: transfer.id().unwrap(),
            index: 0,
        };
        let proof = tree.proof(
            after.anchor.clone(),
            mutiny_consensus_v8::state_proof::utxo_key(&point),
        );
        let encoded = proof.encode().unwrap();
        let request = mutinyd_v8::state_proof_service::Request {
            anchor: after.anchor.clone(),
            key: mutiny_consensus_v8::state_proof::utxo_key(&point),
            profile: mutinyd_v8::state_proof_service::ProofProfile::Utxo,
        };
        let served =
            mutinyd_v8::state_proof_service::respond_hybrid(&replica.chain, &request.encode())
                .unwrap();
        assert_eq!(served, encoded);
        assert_eq!(
            replica
                .verify_utxo(&encoded, &point, [94; 32])
                .unwrap()
                .unwrap()
                .output
                .atoms,
            95000
        );
        assert!(replica.verify_utxo(&encoded, &point, [95; 32]).is_err());
        let mut wrong = proof.clone();
        wrong.context = genesis.clone();
        assert!(
            replica
                .verify_utxo(&wrong.encode().unwrap(), &point, [94; 32])
                .is_err()
        );
        let absent = OutPoint {
            transaction: [0; 32],
            index: 0,
        };
        let proof = tree
            .proof(
                after.anchor.clone(),
                mutiny_consensus_v8::state_proof::utxo_key(&absent),
            )
            .encode()
            .unwrap();
        assert!(
            replica
                .verify_utxo(&proof, &absent, [94; 32])
                .unwrap()
                .is_none()
        );
        assert!(replica.verify_utxo(&proof, &point, [94; 32]).is_err());
        let (public, generation) = PublicKey::decode_descriptor(descriptor).unwrap();
        let owner = public.address_id(generation).unwrap();
        let address_proof = tree
            .proof(
                after.anchor.clone(),
                mutiny_consensus_v8::wallet_authority_v1::address_key(owner),
            )
            .encode()
            .unwrap();
        let current_proof = tree
            .proof(
                after.anchor.clone(),
                mutiny_consensus_v8::wallet_authority_v1::current_key(owner),
            )
            .encode()
            .unwrap();
        let authority = replica
            .verify_wallet_authority(&address_proof, &current_proof, owner)
            .unwrap();
        assert_eq!(authority.descriptor(), Some(descriptor.as_slice()));
        assert_eq!(authority.context(), &after.anchor);
        assert!(
            replica
                .verify_wallet_authority(&current_proof, &address_proof, owner)
                .is_err()
        );
        assert!(
            replica
                .verify_wallet_authority(&address_proof, &[], owner)
                .is_err()
        );
        let absent_address = tree
            .proof(
                after.anchor.clone(),
                mutiny_consensus_v8::wallet_authority_v1::address_key([94; 32]),
            )
            .encode()
            .unwrap();
        assert!(
            replica
                .verify_wallet_authority(&absent_address, &[], [94; 32])
                .unwrap()
                .descriptor()
                .is_none()
        );
        assert!(
            replica
                .verify_wallet_authority(&absent_address, &current_proof, [94; 32])
                .is_err()
        );
        drop(replica);
        let chain =
            CanonicalStore::open_trusted_genesis(&path, &genesis, &state, root, 1000, [255; 32])
                .unwrap();
        let restored = Replica::from_pinned_chain(chain).unwrap();
        assert_eq!(
            restored.balance(descriptor, &BTreeSet::new()).unwrap(),
            after
        );
        drop(restored);
        drop(pool);
        std::fs::remove_file(queue_path).unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
