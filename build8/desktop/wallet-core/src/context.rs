//! The verified chain facts every plan, review and authorization is computed from.
//!
//! The wallet core never talks to a network and never trusts a peer's claim. A [`ChainView`] is
//! assembled by the host from the LOCALLY replayed canonical store (head, state, timestamps) and
//! the host's own reservations. Every function in this crate that reads the chain takes a
//! `&ChainView`, so a result is a pure function of the view and its other arguments.
use crate::{
    refusal::{ContextField, Refusal},
    units,
};
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    execution::State,
    transactions::OutPoint,
    treasury_v1::{Class, Treasury},
};
use std::{collections::BTreeSet, fmt};

/// What the chain says about itself: the class of its Treasury record. A chain without any
/// Treasury record has declared nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainClass {
    /// The Treasury record is TEST-VALUE class: nothing on this chain has real value.
    TestValue,
    /// The Treasury record is production class.
    Production,
    /// No Treasury record (dividends inactive): the chain does not declare a class.
    Undeclared,
}

impl ChainClass {
    /// Short label used in reviews.
    pub fn label(self) -> &'static str {
        match self {
            Self::TestValue => "TEST-VALUE (nothing on this chain has real value)",
            Self::Production => "production",
            Self::Undeclared => "not declared (the chain has no Treasury record)",
        }
    }
}

/// Network, Genesis and protocol fingerprint of the verified chain.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChainContext {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
}

impl fmt::Debug for ChainContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainContext")
            .field("network", &self.network)
            .field("genesis", &units::short_hex(&self.genesis))
            .field("fingerprint", &units::short_hex(&self.fingerprint))
            .finish()
    }
}

/// The verified head: anchor, block timestamp, the epoch origin `t0`, and the state root.
#[derive(Clone, PartialEq, Eq)]
pub struct HeadInfo {
    anchor: FinalizedAnchor,
    timestamp: u64,
    t0: u64,
    state_root: Hash,
}

impl HeadInfo {
    /// `timestamp` is the head block's timestamp, `t0` the chain's epoch origin and `state_root`
    /// the head's authenticated state root, all from the local canonical store.
    pub fn new(
        anchor: FinalizedAnchor,
        timestamp: u64,
        t0: u64,
        state_root: Hash,
    ) -> Result<Self, Refusal> {
        if anchor.network != NETWORK_ID {
            return Err(Refusal::WrongContext(ContextField::Network));
        }
        if anchor.genesis == [0; 32] {
            return Err(Refusal::WrongContext(ContextField::Genesis));
        }
        if anchor.fingerprint == [0; 32] {
            return Err(Refusal::WrongContext(ContextField::Fingerprint));
        }
        Ok(Self {
            anchor,
            timestamp,
            t0,
            state_root,
        })
    }
    pub fn anchor(&self) -> &FinalizedAnchor {
        &self.anchor
    }
    pub fn height(&self) -> u64 {
        self.anchor.height
    }
    pub fn block(&self) -> Hash {
        self.anchor.block
    }
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn t0(&self) -> u64 {
        self.t0
    }
    pub fn state_root(&self) -> Hash {
        self.state_root
    }
    /// The height a transaction created now would be built for.
    pub fn next_height(&self) -> Result<u64, Refusal> {
        self.anchor.height.checked_add(1).ok_or(Refusal::Overflow)
    }
    /// Mining epoch of the head: `(timestamp - t0) / 60`.
    pub fn epoch(&self) -> Result<u64, Refusal> {
        mutiny_consensus_v8::pow::mining_epoch(self.timestamp, self.t0)
            .map_err(|_| Refusal::Overflow)
    }
    pub fn context(&self) -> ChainContext {
        ChainContext {
            network: self.anchor.network,
            genesis: self.anchor.genesis,
            fingerprint: self.anchor.fingerprint,
        }
    }
}

impl fmt::Debug for HeadInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeadInfo")
            .field("height", &self.anchor.height)
            .field("block", &units::short_hex(&self.anchor.block))
            .field("timestamp", &self.timestamp)
            .field("t0", &self.t0)
            .field("state_root", &units::short_hex(&self.state_root))
            .finish()
    }
}

/// Where the host's verified confirmation index is exposed to the core. Optional: without one the
/// outbox can still tell a payment is included from its output coin, but not an operation whose
/// effects are spent again.
pub trait ConfirmationSource {
    /// The block height at which `id` was confirmed in verified canonical history, if it was.
    fn confirmed_height(&self, id: &Hash) -> Option<u64>;
    /// A command outcome reproduced by the host's own canonical replay, never a peer receipt.
    fn command_outcome(
        &self,
        _id: &Hash,
    ) -> Option<(u64, mutiny_consensus_v8::bond_ops_v2::CommandOutcome)> {
        None
    }
}

/// A read-only view of the verified chain.
pub struct ChainView<'a> {
    head: HeadInfo,
    state: &'a State,
    reserved: &'a BTreeSet<OutPoint>,
    confirmations: Option<&'a dyn ConfirmationSource>,
    history: Option<&'a mutiny_consensus_v8::evidence_history_v2::History>,
}

impl<'a> ChainView<'a> {
    /// Caller contract: `head` and `state` come from the locally executing replica, never from a
    /// network proof server, and `reserved` is the union of every input already committed to a
    /// pending operation (transaction pool and wallet outbox). Use [`Self::verified`] when the state
    /// did not come straight from a store that already authenticated it.
    ///
    /// A transaction does not commit to the VALUE of its inputs, so the fee and the change a review
    /// shows are exactly as truthful as the coins in this view. A view built from anything but the
    /// locally verified canonical state could make a review understate the fee.
    pub fn new(head: HeadInfo, state: &'a State, reserved: &'a BTreeSet<OutPoint>) -> Self {
        Self {
            head,
            state,
            reserved,
            confirmations: None,
            history: None,
        }
    }
    /// [`Self::new`] plus [`Self::verify_state_root`]: refuses a state that does not hash to the head's
    /// state root. Expensive (proportional to the number of state records), so it is a separate
    /// constructor for hosts that did not get the state straight from an authenticated store.
    pub fn verified(
        head: HeadInfo,
        state: &'a State,
        reserved: &'a BTreeSet<OutPoint>,
    ) -> Result<Self, Refusal> {
        let view = Self::new(head, state, reserved);
        view.verify_state_root()?;
        Ok(view)
    }
    /// Attach the host's verified confirmation index.
    pub fn with_confirmations(mut self, source: &'a dyn ConfirmationSource) -> Self {
        self.confirmations = Some(source);
        self
    }
    /// Attach reference anchors obtained from the locally verified canonical store.
    /// Peer-provided anchors must never be passed here.
    pub fn with_history(
        mut self,
        history: &'a mutiny_consensus_v8::evidence_history_v2::History,
    ) -> Self {
        self.history = Some(history);
        self
    }
    pub(crate) fn history(&self) -> mutiny_consensus_v8::evidence_history_v2::History {
        self.history.cloned().unwrap_or_default()
    }
    pub(crate) fn check_envelope(
        &self,
        envelope: &mutiny_consensus_v8::op_envelope_v1::Envelope,
    ) -> Result<(), Refusal> {
        let empty = mutiny_consensus_v8::evidence_history_v2::History::default();
        envelope
            .check_inclusion(self.anchor(), self.history.unwrap_or(&empty))
            .map_err(|error| match error {
                mutiny_consensus_v8::op_envelope_v1::EnvelopeError::Future => {
                    Refusal::WindowNotOpen {
                        created: envelope.first_height,
                        next_height: self.anchor().height.saturating_add(1),
                    }
                }
                mutiny_consensus_v8::op_envelope_v1::EnvelopeError::Expired => {
                    Refusal::WindowClosed {
                        expiry: envelope.last_height,
                        next_height: self.anchor().height.saturating_add(1),
                    }
                }
                _ => Refusal::StaleAuthority,
            })
    }
    /// Recompute the state root and compare it with the head's. Expensive (proportional to the
    /// number of state records), so it is explicit.
    pub fn verify_state_root(&self) -> Result<(), Refusal> {
        let root = self
            .state
            .root()
            .map_err(|_| Refusal::Malformed("state does not hash"))?;
        if root == self.head.state_root {
            Ok(())
        } else {
            Err(Refusal::Malformed("state root does not match the head"))
        }
    }
    pub fn head(&self) -> &HeadInfo {
        &self.head
    }
    pub fn anchor(&self) -> &FinalizedAnchor {
        &self.head.anchor
    }
    pub fn state(&self) -> &'a State {
        self.state
    }
    pub fn state_root(&self) -> Hash {
        self.head.state_root
    }
    pub fn reserved(&self) -> &'a BTreeSet<OutPoint> {
        self.reserved
    }
    pub fn context(&self) -> ChainContext {
        self.head.context()
    }
    pub fn next_height(&self) -> Result<u64, Refusal> {
        self.head.next_height()
    }
    pub fn epoch(&self) -> Result<u64, Refusal> {
        self.head.epoch()
    }
    /// The Treasury record, when dividends are active.
    pub fn treasury(&self) -> Option<&'a Treasury> {
        self.state.dividends.treasury()
    }
    pub fn class(&self) -> ChainClass {
        match self.treasury().map(Treasury::class) {
            Some(Class::TestValue) => ChainClass::TestValue,
            Some(Class::Production) => ChainClass::Production,
            None => ChainClass::Undeclared,
        }
    }
    /// The verified confirmation height of `id`, from the host's index when one was attached.
    pub fn confirmed_height(&self, id: &Hash) -> Option<u64> {
        self.confirmations
            .and_then(|source| source.confirmed_height(id))
    }
    pub fn confirmed_command_outcome(
        &self,
        id: &Hash,
    ) -> Option<(u64, mutiny_consensus_v8::bond_ops_v2::CommandOutcome)> {
        self.confirmations
            .and_then(|source| source.command_outcome(id))
    }
    /// Fail with `WrongContext` unless `network`, `genesis` and `fingerprint` are this chain's.
    pub fn require_context(
        &self,
        network: u32,
        genesis: &Hash,
        fingerprint: &Hash,
    ) -> Result<(), Refusal> {
        let context = self.context();
        if network != context.network {
            return Err(Refusal::WrongContext(ContextField::Network));
        }
        if *genesis != context.genesis {
            return Err(Refusal::WrongContext(ContextField::Genesis));
        }
        if *fingerprint != context.fingerprint {
            return Err(Refusal::WrongContext(ContextField::Fingerprint));
        }
        Ok(())
    }
}

impl fmt::Debug for ChainView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainView")
            .field("head", &self.head)
            .field("class", &self.class())
            .field("reserved_inputs", &self.reserved.len())
            .field("confirmations", &self.confirmations.is_some())
            .finish()
    }
}

/// The Treasury wallet authority and its CURRENT descriptor, when dividends are active.
///
/// A Treasury address is any address the Treasury's current descriptor authorises through the
/// wallet book (every generation of the authority), which is exactly the owner set consensus uses
/// for the dividend reserve backing.
pub(crate) fn treasury_authority(view: &ChainView<'_>) -> Option<(Hash, Vec<u8>)> {
    let treasury = view.treasury()?;
    let authority = treasury.authority();
    let current = view
        .state()
        .wallets
        .current(authority)
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| treasury.descriptor().to_vec());
    Some((authority, current))
}

/// Whether `address` belongs to the Treasury wallet authority (any generation).
pub(crate) fn is_treasury_address(
    view: &ChainView<'_>,
    treasury: &(Hash, Vec<u8>),
    address: &Hash,
) -> bool {
    *address == treasury.0
        || view
            .state()
            .wallets
            .authorize(*address, &treasury.1)
            .is_ok()
}

/// Reserve-aware spending hook (Q15 default): refuse any spend that would leave the Treasury's
/// non-coinbase coins unable to back the outstanding dividend reserve. Consensus computes the same
/// backing for every state root, so a violation would make the whole block invalid.
///
/// `spent` are the coins the operation consumes and `created` the outputs it creates. An operation
/// that spends no Treasury coin cannot reduce the backing and passes without scanning the state.
pub(crate) fn require_reserve_backing(
    view: &ChainView<'_>,
    spent: &BTreeSet<OutPoint>,
    created: &[mutiny_consensus_v8::transactions::Output],
) -> Result<(), Refusal> {
    let Some(treasury) = treasury_authority(view) else {
        return Ok(());
    };
    let coins = &view.state().coins;
    let touches_treasury = spent.iter().any(|point| {
        coins.get(point).is_some_and(|coin| {
            !coin.coinbase && is_treasury_address(view, &treasury, &coin.output.owner)
        })
    });
    if !touches_treasury {
        return Ok(());
    }
    let reserved = view.state().dividends.reserved();
    let mut backing: u128 = 0;
    for (point, coin) in coins {
        if !coin.coinbase
            && !spent.contains(point)
            && is_treasury_address(view, &treasury, &coin.output.owner)
        {
            backing += u128::from(coin.output.atoms);
        }
    }
    for output in created {
        if is_treasury_address(view, &treasury, &output.owner) {
            backing += u128::from(output.atoms);
        }
    }
    if backing < u128::from(reserved) {
        return Err(Refusal::ReserveBackingViolation {
            reserved,
            backing_after: u64::try_from(backing).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(height: u64) -> FinalizedAnchor {
        FinalizedAnchor {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height,
            block: [3; 32],
        }
    }

    #[test]
    fn head_info_rejects_a_foreign_or_unset_context() {
        let mut a = anchor(5);
        assert!(HeadInfo::new(a.clone(), 1000, 1000, [9; 32]).is_ok());
        a.network ^= 1;
        assert_eq!(
            HeadInfo::new(a, 1, 1, [9; 32]),
            Err(Refusal::WrongContext(ContextField::Network))
        );
        let mut a = anchor(5);
        a.genesis = [0; 32];
        assert_eq!(
            HeadInfo::new(a, 1, 1, [9; 32]),
            Err(Refusal::WrongContext(ContextField::Genesis))
        );
        let mut a = anchor(5);
        a.fingerprint = [0; 32];
        assert_eq!(
            HeadInfo::new(a, 1, 1, [9; 32]),
            Err(Refusal::WrongContext(ContextField::Fingerprint))
        );
    }

    #[test]
    fn heights_and_epochs_are_checked() {
        let head = HeadInfo::new(anchor(u64::MAX), 1000 + 125, 1000, [9; 32]).unwrap();
        assert_eq!(head.next_height(), Err(Refusal::Overflow));
        assert_eq!(head.epoch(), Ok(2));
        let before_origin = HeadInfo::new(anchor(1), 5, 1000, [9; 32]).unwrap();
        assert_eq!(before_origin.epoch(), Err(Refusal::Overflow));
    }

    #[test]
    fn view_without_a_treasury_declares_no_class() {
        let state = State::default();
        let reserved = BTreeSet::new();
        let view = ChainView::new(
            HeadInfo::new(anchor(1), 1000, 1000, [9; 32]).unwrap(),
            &state,
            &reserved,
        );
        assert_eq!(view.class(), ChainClass::Undeclared);
        assert!(view.confirmed_height(&[1; 32]).is_none());
        assert!(treasury_authority(&view).is_none());
        assert!(view.require_context(NETWORK_ID, &[1; 32], &[2; 32]).is_ok());
        assert_eq!(
            view.require_context(NETWORK_ID, &[9; 32], &[2; 32]),
            Err(Refusal::WrongContext(ContextField::Genesis))
        );
        assert!(format!("{view:?}").contains("Undeclared"));
    }
}
