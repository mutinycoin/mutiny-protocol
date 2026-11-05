//! Read-only bond lookups over a verified `State` (phase 4).
//!
//! What a wallet needs to plan and review bond operations, read from the canonical state only:
//! the lots it owns (`state.bonds_v2.lots`: status, sequence, principal, the lock-start height B and
//! the finalized unbond height U), the nodes it owns and may bond for (the continuity registry and
//! `membership_v2`), the earliest withdrawal height and whether a lot was burned. Ownership is
//! resolved through the wallet book exactly as consensus resolves it (`WalletBook::authorize`), so
//! a rotated authority still finds the lots and nodes of its original AddressID.
//!
//! Nothing here authenticates the state: the caller verifies the parent state root first (see
//! `ChainView::verified`). Heights are certified blocks, never wall time.
//!
//! The locked timing is taken from consensus (`mutiny_consensus_v8::bonds`) and re-exported under
//! the names the review uses; nothing is re-derived:
//!
//! * minimum principal [`MINIMUM_BOND_ATOMS`] = `bonds::MINIMUM_ATOMS` (100 MUT);
//! * minimum hold [`MINIMUM_HOLD_BLOCKS`] = `bonds::LOCK_HEIGHTS` (259,200 blocks, 4,320 periods);
//! * notice [`NOTICE_BLOCKS`] = `bonds::EVIDENCE_HEIGHTS` (43,200 blocks, 720 periods);
//! * a withdrawal at height W needs `W >= B + 259,200` AND `W >= U + 43,200`
//!   (`bonds::withdrawal_floor`, see [`earliest_withdrawal`]).
use mutiny_consensus_v8::{
    Hash,
    bonds::{EVIDENCE_HEIGHTS, LOCK_HEIGHTS, LotStatus, MINIMUM_ATOMS, withdrawal_floor},
    execution::State,
};
use std::fmt;

/// Minimum bond principal in atoms (`bonds::MINIMUM_ATOMS`, 100 MUT).
pub const MINIMUM_BOND_ATOMS: u64 = MINIMUM_ATOMS;
/// Minimum holding period in certified blocks from the lock-start height B (`bonds::LOCK_HEIGHTS`).
pub const MINIMUM_HOLD_BLOCKS: u64 = LOCK_HEIGHTS;
/// Notice period in certified blocks from the unbond height U (`bonds::EVIDENCE_HEIGHTS`). It is
/// also the window in which equivocation evidence is timely, so a lot stays exposed to burning
/// until U + 43,200.
pub const NOTICE_BLOCKS: u64 = EVIDENCE_HEIGHTS;
/// One ContinuityPeriod in certified blocks. Consensus has no named constant for it: the bond rules
/// state the timing as 4,320 and 720 periods of 60 blocks (`bonds.rs`), and reputation ages bonds in
/// `height / 60` steps. A unit test pins the relation to the consensus constants.
pub const CONTINUITY_PERIOD_BLOCKS: u64 = 60;
/// At most this many locked (Active or Unbonding) lots per node lineage: `bonds_v2::Book::records`
/// refuses a 65th.
pub const MAX_LOCKED_LOTS_PER_LINEAGE: usize = 64;

/// The earliest certified-block height at which a lot with lock start `created` (B) and finalized
/// unbond notice `unbond` (U) may be withdrawn: `max(B + 259,200, U + 43,200)`, computed by
/// consensus' own `bonds::withdrawal_floor`. `None` on arithmetic overflow.
pub fn earliest_withdrawal(created: u64, unbond: u64) -> Option<u64> {
    withdrawal_floor(created, unbond).ok()
}

/// A bond lot as the wallet reads it from verified state.
#[derive(Clone, PartialEq, Eq)]
pub struct LotView {
    pub id: Hash,
    pub node: Hash,
    pub lineage: Hash,
    /// The immutable owner AddressID (the payout goes here).
    pub owner: Hash,
    pub atoms: u64,
    pub status: LotStatus,
    /// The last applied bond operation's sequence (0 after creation).
    pub sequence: u64,
    /// B: the lock-start height (the block that included the creation).
    pub created_height: u64,
    /// U: the block that included the unbond, once one was applied.
    pub unbond_height: Option<u64>,
    /// The withdrawal or burn height, once settled.
    pub settled_height: Option<u64>,
    /// The burning evidence's identifier (all zero unless burned).
    pub evidence: Hash,
}

impl LotView {
    fn of(lot: &mutiny_consensus_v8::bonds_v2::Lot) -> Self {
        let lot = &lot.0;
        Self {
            id: lot.id,
            node: lot.node,
            lineage: lot.lineage,
            owner: lot.owner,
            atoms: lot.atoms,
            status: lot.status,
            sequence: lot.sequence,
            created_height: lot.created_height,
            unbond_height: lot.unbond_height,
            settled_height: lot.settled_height,
            evidence: lot.evidence,
        }
    }

    /// Burned by equivocation evidence: it can never be unbonded or withdrawn.
    pub fn burned(&self) -> bool {
        self.status == LotStatus::Burned
    }

    /// Active or Unbonding: the principal is still held.
    pub fn locked(&self) -> bool {
        matches!(self.status, LotStatus::Active | LotStatus::Unbonding)
    }

    /// The earliest withdrawal height once the notice has started (`None` while Active, and on
    /// overflow).
    pub fn earliest_withdrawal(&self) -> Option<u64> {
        earliest_withdrawal(self.created_height, self.unbond_height?)
    }

    /// The earliest withdrawal height if the notice started at `unbond` (what an unbond included
    /// in block `unbond` would make it).
    pub fn earliest_withdrawal_if_unbonded_at(&self, unbond: u64) -> Option<u64> {
        earliest_withdrawal(self.created_height, unbond)
    }

    /// The last block in which timely equivocation evidence can still burn this lot: U + 43,200
    /// once unbonding. `None` while Active (the exposure is open-ended) or once settled.
    pub fn burn_exposed_until(&self) -> Option<u64> {
        if self.status != LotStatus::Unbonding {
            return None;
        }
        self.unbond_height?.checked_add(NOTICE_BLOCKS)
    }
}

impl fmt::Debug for LotView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LotView")
            .field("id", &crate::units::short_hex(&self.id))
            .field("node", &crate::units::short_hex(&self.node))
            .field("owner", &crate::units::short_hex(&self.owner))
            .field("atoms", &self.atoms)
            .field("status", &self.status)
            .field("sequence", &self.sequence)
            .field("created_height", &self.created_height)
            .field("unbond_height", &self.unbond_height)
            .field("settled_height", &self.settled_height)
            .finish()
    }
}

/// A node as a bond creation sees it: its continuity registry member and its membership control.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeView {
    pub node: Hash,
    pub lineage: Hash,
    /// The node's admitted owner AddressID: a bond for this node must name it as bond owner.
    pub owner: Hash,
    /// The membership control's hardware generation (what a creation must name).
    pub generation: u64,
    /// The continuity registry member's generation (consensus requires both to match).
    pub member_generation: u64,
    pub physical: bool,
    pub eligible: bool,
    /// The lineage is revoked by an applied penalty.
    pub revoked: bool,
    /// A scheduled exit boundary, if any.
    pub exit_boundary: Option<u64>,
    /// Active or Unbonding lots of this lineage.
    pub locked_lots: usize,
}

impl NodeView {
    /// Whether consensus would let a new bond be created for this node at the verified head, as far
    /// as the parent state can tell (same-block evidence can still revoke it).
    pub fn bondable(&self) -> bool {
        self.physical
            && self.eligible
            && !self.revoked
            && self.generation == self.member_generation
            && self.locked_lots < MAX_LOCKED_LOTS_PER_LINEAGE
    }
}

impl fmt::Debug for NodeView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeView")
            .field("node", &crate::units::short_hex(&self.node))
            .field("owner", &crate::units::short_hex(&self.owner))
            .field("generation", &self.generation)
            .field("physical", &self.physical)
            .field("eligible", &self.eligible)
            .field("revoked", &self.revoked)
            .field("exit_boundary", &self.exit_boundary)
            .field("locked_lots", &self.locked_lots)
            .finish()
    }
}

/// One lot by identifier.
pub fn lot(state: &State, id: &Hash) -> Option<LotView> {
    state.bonds_v2.lots.get(id).map(LotView::of)
}

/// Every lot whose owner AddressID the wallet key with `descriptor` controls (resolved through the
/// wallet book as consensus does), in lot-identifier order. Includes settled and burned lots.
pub fn lots_controlled_by(state: &State, descriptor: &[u8]) -> Vec<LotView> {
    state
        .bonds_v2
        .lots
        .values()
        .filter(|lot| state.wallets.authorize(lot.0.owner, descriptor).is_ok())
        .map(LotView::of)
        .collect()
}

/// One node: `None` unless it is both a continuity registry member and has a membership control.
pub fn node(state: &State, node: &Hash) -> Option<NodeView> {
    let registry = state.continuity.as_ref()?;
    let member = registry.members.iter().find(|m| m.node == *node)?;
    let control = state.membership_v2.get(*node)?;
    let locked_lots = state
        .bonds_v2
        .lots
        .values()
        .filter(|lot| lot.0.lineage == member.lineage && lot.0.locked())
        .count();
    Some(NodeView {
        node: *node,
        lineage: member.lineage,
        owner: control.binding().admission.owner,
        generation: control.generation(),
        member_generation: member.generation,
        physical: member.physical,
        eligible: member.eligible,
        revoked: state.penalties_v2.revoked(member.lineage),
        exit_boundary: control.exit_boundary(),
        locked_lots,
    })
}

/// Every registry node whose admitted owner the wallet key with `descriptor` controls (Q16: a wallet
/// bonds only for nodes it owns), in registry order. Includes nodes that are not bondable right
/// now; see [`NodeView::bondable`].
pub fn nodes_controlled_by(state: &State, descriptor: &[u8]) -> Vec<NodeView> {
    let Some(registry) = state.continuity.as_ref() else {
        return Vec::new();
    };
    registry
        .members
        .iter()
        .filter_map(|member| node(state, &member.node))
        .filter(|view| state.wallets.authorize(view.owner, descriptor).is_ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_consensus_v8::{bonds::BondLot, bonds_v2::Lot};

    #[test]
    fn the_locked_timing_is_the_consensus_timing() {
        assert_eq!(MINIMUM_BOND_ATOMS, 10_000_000_000);
        assert_eq!(MINIMUM_HOLD_BLOCKS, 259_200);
        assert_eq!(NOTICE_BLOCKS, 43_200);
        assert_eq!(MINIMUM_HOLD_BLOCKS, 4_320 * CONTINUITY_PERIOD_BLOCKS);
        assert_eq!(NOTICE_BLOCKS, 720 * CONTINUITY_PERIOD_BLOCKS);
        // Both floors apply: the later one binds.
        assert_eq!(earliest_withdrawal(10, 11), Some(10 + 259_200));
        assert_eq!(
            earliest_withdrawal(10, 10 + 259_200),
            Some(10 + 259_200 + 43_200)
        );
        let crossover = 10 + 259_200 - 43_200;
        assert_eq!(earliest_withdrawal(10, crossover), Some(10 + 259_200));
        assert_eq!(
            earliest_withdrawal(10, crossover + 1),
            Some(10 + 259_200 + 1)
        );
        assert_eq!(earliest_withdrawal(u64::MAX, 1), None);
        assert_eq!(earliest_withdrawal(1, u64::MAX), None);
    }

    #[test]
    fn lot_views_report_status_floor_and_exposure() {
        let mut lot = Lot(BondLot {
            id: [1; 32],
            node: [2; 32],
            lineage: [3; 32],
            owner: [4; 32],
            atoms: MINIMUM_ATOMS,
            created_height: 5,
            sequence: 0,
            unbond_height: None,
            settled_height: None,
            status: LotStatus::Active,
            evidence: [0; 32],
        });
        let active = LotView::of(&lot);
        assert!(active.locked() && !active.burned());
        assert_eq!(active.earliest_withdrawal(), None);
        assert_eq!(active.burn_exposed_until(), None);
        assert_eq!(
            active.earliest_withdrawal_if_unbonded_at(6),
            Some(5 + 259_200)
        );
        lot.start_unbond(9, 1).unwrap();
        let unbonding = LotView::of(&lot);
        assert_eq!(unbonding.earliest_withdrawal(), Some(5 + 259_200));
        assert_eq!(unbonding.burn_exposed_until(), Some(9 + 43_200));
        assert!(format!("{unbonding:?}").len() < 400);
    }
}
