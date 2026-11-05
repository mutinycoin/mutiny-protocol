//! Hash locks in the verified state that this wallet may claim or refund, and the finality of a
//! funding operation (phase 5A).
//!
//! Read-only lookups over the verified `State` (the caller verifies the state root first, see
//! `ChainView::verified`). Consensus has no lock enumerator: locks are found by walking the public
//! `state.protocol_records` map and decoding every native trading record with
//! `NativeRecord::decode`, keeping only records stored under their own key
//! (`trading_v1::record_key(0, id)`). A single lock is read with `trading_v1::locked`; a lock proved
//! by someone else's state proof is checked with `trading_v1::verify_lock_proof`.
//!
//! Timing follows consensus exactly, from the verified head, never from a clock: with H the next
//! block's height and R the refund height, a claim is valid while H < R and a refund once H >= R.
//! Fiat locks (phase 5B) have no hash condition and are not listed here.
use crate::{authorize::SignerIdentity, context::ChainView, refusal::Refusal, units};
use mutiny_consensus_v8::{
    Hash,
    anchors::FinalizedAnchor,
    trading_v1::{self, Action, NativeLock, NativeLockKind, NativeOperation, NativeRecord},
};
use std::fmt;

/// Where an open hash lock stands at the next block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockPhase {
    /// The next block is below the refund height: the recipient may still claim, in blocks up to
    /// `last_claim_height`; the sender must wait.
    ClaimWindow { last_claim_height: u64 },
    /// The refund height is reached: a claim is no longer valid and only the sender may refund.
    RefundWindow { since: u64 },
}

/// One open hash lock as this wallet sees it.
#[derive(Clone, PartialEq, Eq)]
pub struct HashLockEntry {
    /// The lock's identifier (output 0 of the funding operation).
    pub id: Hash,
    pub sender: Hash,
    pub recipient: Hash,
    /// Locked atoms (STRIKES).
    pub amount: u64,
    /// `SHA-256(preimage)`.
    pub condition: Hash,
    pub refund_height: u64,
    /// Height of the block that included the funding operation.
    pub created_height: u64,
    /// Opaque TradeID and ContractHash (Q8) and the trade generation a claim or refund repeats.
    pub trade: Hash,
    pub contract: Hash,
    pub generation: u64,
    /// This wallet's key controls the sender address (it may refund once the refund height is
    /// reached).
    pub this_wallet_sends: bool,
    /// This wallet's key controls the recipient address (it may claim before the refund height).
    pub this_wallet_receives: bool,
    pub phase: LockPhase,
}

impl HashLockEntry {
    /// This wallet may claim it now (with the preimage).
    pub fn may_claim(&self) -> bool {
        self.this_wallet_receives && matches!(self.phase, LockPhase::ClaimWindow { .. })
    }
    /// This wallet may refund it now.
    pub fn may_refund(&self) -> bool {
        self.this_wallet_sends && matches!(self.phase, LockPhase::RefundWindow { .. })
    }
}

impl fmt::Debug for HashLockEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashLockEntry")
            .field("id", &units::short_hex(&self.id))
            .field("amount", &self.amount)
            .field("refund_height", &self.refund_height)
            .field("sends", &self.this_wallet_sends)
            .field("receives", &self.this_wallet_receives)
            .field("phase", &self.phase)
            .finish()
    }
}

fn entry(
    view: &ChainView<'_>,
    me: &SignerIdentity,
    id: Hash,
    lock: &NativeLock,
) -> Result<Option<HashLockEntry>, Refusal> {
    let NativeLockKind::Hash {
        condition,
        refund_height,
    } = lock.kind
    else {
        return Ok(None);
    };
    let context = view.context();
    if lock.context.network != context.network
        || lock.context.genesis != context.genesis
        || lock.context.fingerprint != context.fingerprint
    {
        return Ok(None);
    }
    let next = view.next_height()?;
    let wallets = &view.state().wallets;
    let phase = if next < refund_height {
        LockPhase::ClaimWindow {
            last_claim_height: refund_height - 1,
        }
    } else {
        LockPhase::RefundWindow {
            since: refund_height,
        }
    };
    Ok(Some(HashLockEntry {
        id,
        sender: lock.sender,
        recipient: lock.recipient,
        amount: lock.amount.0,
        condition,
        refund_height,
        created_height: lock.created_height,
        trade: lock.trade,
        contract: lock.contract,
        generation: lock.generation,
        this_wallet_sends: wallets.authorize(lock.sender, me.descriptor()).is_ok(),
        this_wallet_receives: wallets.authorize(lock.recipient, me.descriptor()).is_ok(),
        phase,
    }))
}

/// Every open hash lock of this chain whose sender or recipient this wallet's key controls,
/// ascending by identifier.
pub fn hash_locks(
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<Vec<HashLockEntry>, Refusal> {
    let mut out = Vec::new();
    for (key, raw) in &view.state().protocol_records {
        if !trading_v1::is_candidate_record(raw) {
            continue;
        }
        let Ok((id, NativeRecord::Lock(lock))) = NativeRecord::decode(raw) else {
            continue;
        };
        if trading_v1::record_key(0, id) != *key {
            continue;
        }
        if let Some(found) = entry(view, me, id, &lock)?
            && (found.this_wallet_sends || found.this_wallet_receives)
        {
            out.push(found);
        }
    }
    out.sort_by_key(|found| found.id);
    Ok(out)
}

/// One open hash lock by identifier (`trading_v1::locked`), seen from `me`. A lock that is not in
/// the verified state (never created, or already claimed or refunded) is `LOCK_NOT_FOUND`; a fiat
/// lock is refused as having no hash condition.
pub fn hash_lock(
    view: &ChainView<'_>,
    id: Hash,
    me: &SignerIdentity,
) -> Result<HashLockEntry, Refusal> {
    let lock = trading_v1::locked(view.state(), id).map_err(|_| Refusal::LockNotFound)?;
    entry(view, me, id, &lock)?.ok_or(Refusal::InvalidRequest(
        "not a hash lock of this chain (a fiat lock has no hash condition)",
    ))
}

/// A hash lock proved by a state proof against an anchor and its state root
/// (`trading_v1::verify_lock_proof`). The caller must have verified the anchor and the root
/// itself (for example from its own canonical store): the proof shows only that the lock is in
/// THAT state.
pub fn lock_from_proof(
    raw: &[u8],
    anchor: &FinalizedAnchor,
    root: Hash,
    id: Hash,
) -> Result<NativeLock, Refusal> {
    trading_v1::verify_lock_proof(raw, anchor, root, id)
        .map_err(|_| Refusal::VerificationFailed("the lock proof does not verify"))
}

/// Finality of a funding operation (the native reservation) in the verified chain.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Finality {
    /// Not in the verified chain. A record that is only queued locally, or a host's report that a
    /// proposer put it into a candidate block, is NOT finality.
    NotFinal,
    /// Applied by a certified block of the verified chain at `height`. `lock` is the lock the
    /// operation created (for a hash or fiat lock) and `lock_open` whether it is still unspent.
    Final {
        height: u64,
        lock: Option<Hash>,
        lock_open: bool,
    },
}

impl fmt::Debug for Finality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFinal => f.write_str("NotFinal"),
            Self::Final {
                height,
                lock,
                lock_open,
            } => write!(
                f,
                "Final(height {height}, lock {}, open {lock_open})",
                lock.as_ref()
                    .map_or_else(|| "none".to_string(), |id| units::short_hex(id))
            ),
        }
    }
}

/// Whether this host's own replay-derived index confirms `raw` (any valid completion of the
/// same body) and its receipt agrees. Current lock existence is a separate state fact.
pub fn finality(view: &ChainView<'_>, raw: &[u8]) -> Result<Finality, Refusal> {
    let wire = NativeOperation::decode(raw)
        .map_err(|_| Refusal::Malformed("not a canonical native trading operation"))?;
    let op = &wire.operation;
    let id = op
        .id()
        .map_err(|_| Refusal::Malformed("operation identity"))?;
    let state = view.state();
    let Some(record) = state.protocol_records.get(&trading_v1::record_key(2, id)) else {
        return Ok(Finality::NotFinal);
    };
    let height = match NativeRecord::decode(record) {
        Ok((found, NativeRecord::Applied { height, .. })) if found == id => height,
        _ => {
            return Err(Refusal::Malformed(
                "the receipt record of this operation is not a receipt",
            ));
        }
    };
    let Some(confirmed_height) = view.confirmed_height(&id) else {
        return Ok(Finality::NotFinal);
    };
    if height != confirmed_height {
        return Err(Refusal::Malformed(
            "the receipt height differs from this host's own canonical inclusion",
        ));
    }
    let lock = match op.action {
        Action::HashLock { .. } | Action::FiatLock { .. } => Some(
            op.output_id(0)
                .map_err(|_| Refusal::Malformed("operation identity"))?,
        ),
        _ => None,
    };
    let lock_open = lock.is_some_and(|lock| trading_v1::locked(state, lock).is_ok());
    Ok(Finality::Final {
        height,
        lock,
        lock_open,
    })
}
