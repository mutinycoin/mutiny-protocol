//! Native dividend reservation, award, claim and expiry ledger (pure, integer, deterministic).
//!
//! Authority: ARCHITECT-DECISION-LOCK-RESTART-ORDER-V1 (2 Oct 2026), sections 2 and 3, and
//! specification DIV-001..DIV-016. Status: NATIVE logic only. This module has no wire format,
//! state-record key, StateRoot binding, signature check or Treasury UTXO construction; those
//! are separate gates and no identifier is allocated here.
//!
//! Model. `Ledger` holds the reserved total, the live awards and a processing cursor.
//! Callers apply operations to a tentative copy and commit only after certified finality.
//! Both `advance` and `claim` are atomic: on error the ledger is unchanged.
//!
//! Event processing and claim eligibility are separate clocks. The cursor is monotone and
//! records which expiry and award boundaries were already processed; it advances only through
//! `advance` on canonical parent state. Claim eligibility uses the ACTUAL epoch of the
//! containing block: `E <= epoch < E + CLAIM_WINDOW_EPOCHS`, and the award must still exist
//! (not yet expired by processing). A block whose actual epoch regresses below the cursor
//! processes nothing, so it cannot recreate an award, reopen an expired entitlement or revise
//! a frozen snapshot, and it cannot claim before an award's epoch.
//!
//! Claims are partial and unlimited in number. Replay protection is one counter per
//! (award, License): a claim carries the sequence it expects and executes only when that equals
//! the account's count of earlier claims. No per-claim history is stored, and the counters
//! vanish with the award at expiry.
//!
//! Boundaries are the positive multiples of `AWARD_PERIOD_EPOCHS`. Epoch 0 (Genesis) carries no
//! award. This reading is recorded as an assumption in the evidence record.
use crate::Hash;
use std::collections::{BTreeMap, BTreeSet};

pub const AWARD_PERIOD_EPOCHS: u64 = 131_072;
pub const CLAIM_WINDOW_EPOCHS: u64 = 65_536;
/// Upper bound on accounts per award (decoder/allocation bound, not an economic rule).
pub const MAX_ACCOUNTS_PER_AWARD: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Active,
    Suspended,
    Revoked,
}

/// Caller-supplied canonical License facts at the moment of use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicenseView {
    pub id: Hash,
    pub owner: Hash,
    /// `None` means no validated activation exists: the License is never eligible. Epoch 0 is
    /// the authenticated Genesis Bootstrap activation only; it is never a default.
    pub activation_epoch: Option<u64>,
    pub status: Status,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    pub share: u64,
    pub remaining: u64,
    /// Number of successful claims so far; also the sequence the next claim must carry.
    pub claims: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Award {
    epoch: u64,
    accounts: BTreeMap<Hash, Account>,
}

impl Award {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn deadline(&self) -> u64 {
        self.epoch + CLAIM_WINDOW_EPOCHS
    }
    pub fn account(&self, license: &Hash) -> Option<Account> {
        self.accounts.get(license).copied()
    }
    pub fn accounts(&self) -> usize {
        self.accounts.len()
    }
    pub fn accounts_iter(&self) -> impl Iterator<Item = (&Hash, &Account)> {
        self.accounts.iter()
    }
    /// Structural reconstruction from decoded records; the caller validates against the Ledger.
    pub fn from_parts(epoch: u64, accounts: BTreeMap<Hash, Account>) -> Result<Self, DivError> {
        if epoch == 0
            || epoch % AWARD_PERIOD_EPOCHS != 0
            || accounts.is_empty()
            || accounts.len() > MAX_ACCOUNTS_PER_AWARD
            || epoch.checked_add(CLAIM_WINDOW_EPOCHS).is_none()
        {
            return Err(DivError::Malformed);
        }
        let share = accounts.values().next().map(|a| a.share).ok_or(DivError::Malformed)?;
        if share == 0 || accounts.values().any(|a| a.share != share || a.remaining > a.share) {
            return Err(DivError::Malformed);
        }
        // Every claim pays at least one atom: an untouched account has no claims, a touched one
        // has between one and (share - remaining) of them.
        for a in accounts.values() {
            let paid = a.share - a.remaining;
            if (paid == 0) != (a.claims == 0) || a.claims > paid {
                return Err(DivError::Malformed);
            }
        }
        Ok(Self { epoch, accounts })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DivError {
    Overflow,
    /// The requested epoch precedes the cursor. Finalized state is never rolled back.
    Rewind,
    /// Reserved value exceeds the supplied Treasury balance: backing violated.
    Backing,
    Invariant,
    ZeroAmount,
    UnknownAward,
    NotYetClaimable,
    Expired,
    WrongLicense,
    NotEntitled,
    Revoked,
    /// A suspended License cannot claim now; the entitlement is preserved until ordinary expiry.
    Suspended,
    StaleOwner,
    /// The claim's sequence is below the account's claim count: already used.
    Replay,
    /// The claim's sequence is above the account's claim count: not yet valid.
    Sequence,
    Overdrawn,
    /// Decoded state failed a structural or accounting check.
    Malformed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Expired { award: u64, released: u64 },
    Awarded { award: u64, eligible: u64, share: u64, reserved: u64 },
    /// Boundary crossed with nothing to reserve (N = 0, or the pool is smaller than N).
    NoAward { boundary: u64, eligible: u64, pool: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub award_epoch: u64,
    pub license: Hash,
    /// Owner authority presented by the claim (already signature-verified by the caller).
    pub claimant: Hash,
    pub amount: u64,
    /// Claim number for this (award, License); must equal the account's `claims` counter.
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub paid: u64,
    pub remaining: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    reserved: u64,
    cursor: u64,
    awards: BTreeMap<u64, Award>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn reserved(&self) -> u64 {
        self.reserved
    }
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
    pub fn award(&self, epoch: u64) -> Option<&Award> {
        self.awards.get(&epoch)
    }
    pub fn live_awards(&self) -> usize {
        self.awards.len()
    }
    pub fn awards_iter(&self) -> impl Iterator<Item = &Award> {
        self.awards.values()
    }
    pub fn is_pristine(&self) -> bool {
        self.reserved == 0 && self.cursor == 0 && self.awards.is_empty()
    }
    /// Structural reconstruction; `check_invariants` against the live Treasury backing is a
    /// separate State-level step.
    pub fn from_parts(reserved: u64, cursor: u64, awards: Vec<Award>) -> Result<Self, DivError> {
        let mut map = BTreeMap::new();
        for a in awards {
            if a.deadline() <= cursor || a.epoch > cursor || map.insert(a.epoch, a).is_some() {
                return Err(DivError::Malformed);
            }
        }
        let ledger = Self { reserved, cursor, awards: map };
        ledger.check_invariants(u64::MAX).map_err(|_| DivError::Malformed)?;
        Ok(ledger)
    }

    /// Treasury balance that may contribute to a new pool (balance minus reserves).
    pub fn available(&self, treasury_balance: u64) -> Result<u64, DivError> {
        treasury_balance.checked_sub(self.reserved).ok_or(DivError::Backing)
    }

    /// Process every expiry and award boundary in `(cursor, to_epoch]` chronologically, before
    /// the block at `to_epoch` applies its own transactions, subsidy or fees.
    ///
    /// `treasury_balance` is the canonical balance before that block. No transaction can occur
    /// at skipped epochs, so it is constant across the crossing; reserves and releases are
    /// re-applied at each step. `licenses` is the canonical License set before the block:
    /// eligibility at boundary B is ACTIVE, activation_epoch <= B, not suspended, not revoked.
    pub fn advance(
        &mut self,
        to_epoch: u64,
        treasury_balance: u64,
        licenses: &[LicenseView],
    ) -> Result<Vec<Event>, DivError> {
        if to_epoch < self.cursor {
            return Err(DivError::Rewind);
        }
        let mut next = self.clone();
        let mut events = Vec::new();
        loop {
            let boundary = (next.cursor / AWARD_PERIOD_EPOCHS)
                .checked_add(1)
                .and_then(|k| k.checked_mul(AWARD_PERIOD_EPOCHS))
                .unwrap_or(u64::MAX);
            let expiry = next.awards.values().map(Award::deadline).min().unwrap_or(u64::MAX);
            let t = boundary.min(expiry);
            if t > to_epoch || t == u64::MAX {
                break;
            }
            // Progress guard: a corrupt ledger (expiry at or before the cursor) must fail closed
            // instead of looping.
            if t <= next.cursor {
                return Err(DivError::Invariant);
            }
            // 1. scheduled expiry first.
            let due: Vec<u64> = next
                .awards
                .iter()
                .filter(|(_, a)| a.deadline() <= t)
                .map(|(e, _)| *e)
                .collect();
            for e in due {
                let a = next.awards.remove(&e).ok_or(DivError::Invariant)?;
                let released = a.accounts.values().try_fold(0u64, |s, x| s.checked_add(x.remaining)).ok_or(DivError::Overflow)?;
                next.reserved = next.reserved.checked_sub(released).ok_or(DivError::Invariant)?;
                events.push(Event::Expired { award: e, released });
            }
            // 2. activation is by activation_epoch <= t below; 3. then the snapshot.
            if t == boundary {
                let available = next.available(treasury_balance)?;
                let pool = available / 2;
                let eligible: Vec<&LicenseView> = licenses
                    .iter()
                    .filter(|l| l.status == Status::Active && l.activation_epoch.is_some_and(|a| a <= t))
                    .collect();
                let unique: BTreeSet<Hash> = eligible.iter().map(|l| l.id).collect();
                if unique.len() != eligible.len() {
                    return Err(DivError::Invariant);
                }
                let n = eligible.len() as u64;
                let share = if n == 0 { 0 } else { pool / n };
                let total = share.checked_mul(n).ok_or(DivError::Overflow)?;
                if total == 0 {
                    events.push(Event::NoAward { boundary: t, eligible: n, pool });
                } else {
                    let accounts = eligible
                        .iter()
                        .map(|l| (l.id, Account { share, remaining: share, claims: 0 }))
                        .collect();
                    next.reserved = next.reserved.checked_add(total).ok_or(DivError::Overflow)?;
                    next.awards.insert(t, Award { epoch: t, accounts });
                    events.push(Event::Awarded { award: t, eligible: n, share, reserved: total });
                }
            }
            next.cursor = t;
        }
        next.cursor = to_epoch;
        next.check_invariants(treasury_balance)?;
        *self = next;
        Ok(events)
    }

    /// Read-only claim validation at `epoch`, the ACTUAL epoch of the containing block (never
    /// `max(epoch, cursor)`). `license` is the canonical License record at that moment.
    pub fn check_claim(&self, c: &Claim, epoch: u64, license: &LicenseView) -> Result<(), DivError> {
        if c.amount == 0 {
            return Err(DivError::ZeroAmount);
        }
        let award = self.awards.get(&c.award_epoch).ok_or(DivError::UnknownAward)?;
        if epoch < award.epoch {
            return Err(DivError::NotYetClaimable);
        }
        if epoch >= award.deadline() {
            return Err(DivError::Expired);
        }
        if license.id != c.license {
            return Err(DivError::WrongLicense);
        }
        match license.status {
            Status::Revoked => return Err(DivError::Revoked),
            Status::Suspended => return Err(DivError::Suspended),
            Status::Active => {}
        }
        if c.claimant != license.owner {
            return Err(DivError::StaleOwner);
        }
        let account = award.accounts.get(&c.license).ok_or(DivError::NotEntitled)?;
        if c.sequence < account.claims {
            return Err(DivError::Replay);
        }
        if c.sequence > account.claims {
            return Err(DivError::Sequence);
        }
        if c.amount > account.remaining {
            return Err(DivError::Overdrawn);
        }
        Ok(())
    }

    /// Apply one claim at the block's actual `epoch`, after `advance` for that block. Any
    /// positive amount up to the remaining entitlement is valid; the count of claims is
    /// unrestricted. Atomic: on error the ledger is unchanged.
    pub fn claim(&mut self, c: &Claim, epoch: u64, license: &LicenseView) -> Result<Receipt, DivError> {
        self.check_claim(c, epoch, license)?;
        let award = self.awards.get(&c.award_epoch).ok_or(DivError::Invariant)?;
        let account = award.accounts.get(&c.license).ok_or(DivError::Invariant)?;
        let remaining = account.remaining - c.amount;
        let claims = account.claims.checked_add(1).ok_or(DivError::Overflow)?;
        let reserved = self.reserved.checked_sub(c.amount).ok_or(DivError::Invariant)?;
        let award = self.awards.get_mut(&c.award_epoch).ok_or(DivError::Invariant)?;
        let account = award.accounts.get_mut(&c.license).ok_or(DivError::Invariant)?;
        account.remaining = remaining;
        account.claims = claims;
        self.reserved = reserved;
        Ok(Receipt { paid: c.amount, remaining })
    }

    /// Reserve equals the sum of remaining balances, no account exceeds its share, and the
    /// reserve never exceeds the Treasury balance that backs it.
    pub fn check_invariants(&self, treasury_balance: u64) -> Result<(), DivError> {
        let mut sum = 0u64;
        for a in self.awards.values() {
            for x in a.accounts.values() {
                if x.remaining > x.share {
                    return Err(DivError::Invariant);
                }
                sum = sum.checked_add(x.remaining).ok_or(DivError::Overflow)?;
            }
        }
        if sum != self.reserved {
            return Err(DivError::Invariant);
        }
        if self.reserved > treasury_balance {
            return Err(DivError::Backing);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const P: u64 = AWARD_PERIOD_EPOCHS;
    const W: u64 = CLAIM_WINDOW_EPOCHS;

    fn h(n: u8) -> Hash {
        [n; 32]
    }
    fn lic(n: u8, owner: u8, activation: u64, status: Status) -> LicenseView {
        LicenseView { id: h(n), owner: h(owner), activation_epoch: Some(activation), status }
    }
    fn twelve() -> Vec<LicenseView> {
        (1..=12).map(|i| lic(i, 100 + i, 0, Status::Active)).collect()
    }
    fn claim(award: u64, l: &LicenseView, amount: u64, sequence: u64) -> Claim {
        Claim { award_epoch: award, license: l.id, claimant: l.owner, amount, sequence }
    }

    #[test]
    fn schedule_constants_are_locked() {
        assert_eq!(P, 131_072);
        assert_eq!(W, 65_536);
    }

    #[test]
    fn award_math_floors_pool_then_share_and_reserves_only_the_sum() {
        let mut l = Ledger::new();
        let lics: Vec<_> = (1..=3).map(|i| lic(i, i, 0, Status::Active)).collect();
        let ev = l.advance(P, 1_000_000_007, &lics).unwrap();
        // pool = floor(1_000_000_007 / 2) = 500_000_003; share = floor(pool / 3) = 166_666_667.
        assert_eq!(ev, vec![Event::Awarded { award: P, eligible: 3, share: 166_666_667, reserved: 500_000_001 }]);
        assert_eq!(l.reserved(), 500_000_001);
        // The remainder (2) is not reserved: it stays available.
        assert_eq!(l.available(1_000_000_007).unwrap(), 500_000_006);
        l.check_invariants(1_000_000_007).unwrap();
    }

    #[test]
    fn twelve_equal_shares_and_one_owner_with_three_licenses_has_three_entitlements() {
        let mut lics = twelve();
        for l in lics.iter_mut().take(3) {
            l.owner = h(200);
        }
        let mut l = Ledger::new();
        l.advance(P, 2_400_000_000, &lics).unwrap();
        // pool 1_200_000_000 / 12 = 100_000_000 (10... here exactly 1 MUT each).
        let a = l.award(P).unwrap();
        assert_eq!(a.accounts(), 12);
        for x in &lics {
            assert_eq!(a.account(&x.id).unwrap().share, 100_000_000);
        }
    }

    #[test]
    fn no_eligible_license_means_zero_shares_and_zero_reservation() {
        let mut l = Ledger::new();
        let ev = l.advance(P, 5_000_000_000, &[]).unwrap();
        assert_eq!(ev, vec![Event::NoAward { boundary: P, eligible: 0, pool: 2_500_000_000 }]);
        assert_eq!(l.reserved(), 0);
        assert_eq!(l.live_awards(), 0);
        // Pool smaller than N also reserves nothing.
        let mut l2 = Ledger::new();
        let ev2 = l2.advance(P, 2, &twelve()).unwrap();
        assert!(matches!(ev2[0], Event::NoAward { eligible: 12, pool: 1, .. }));
        assert_eq!(l2.reserved(), 0);
    }

    #[test]
    fn award_boundary_is_exact() {
        let mut l = Ledger::new();
        assert!(l.advance(P - 1, 1_000_000, &twelve()).unwrap().is_empty());
        assert_eq!(l.live_awards(), 0);
        assert_eq!(l.advance(P, 1_000_000, &twelve()).unwrap().len(), 1);
        assert_eq!(l.live_awards(), 1);
        // Re-advancing to the same epoch is idempotent.
        assert!(l.advance(P, 1_000_000, &twelve()).unwrap().is_empty());
        assert_eq!(l.live_awards(), 1);
    }

    #[test]
    fn claim_window_is_closed_open_e_inclusive_deadline_exclusive() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 12_000_000, &lics).unwrap();
        let share = l.award(P).unwrap().account(&h(1)).unwrap().share;
        assert!(share > 3);
        // At E: claimable in the same block as the snapshot.
        assert!(l.claim(&claim(P, &lics[0], 1, 0), P, &lics[0]).is_ok());
        // Last claimable epoch.
        assert!(l.claim(&claim(P, &lics[0], 1, 1), P + W - 1, &lics[0]).is_ok());
        // At the deadline: expired even if the ledger was not advanced yet.
        assert_eq!(l.claim(&claim(P, &lics[0], 1, 2), P + W, &lics[0]), Err(DivError::Expired));
        // Before E (an award cannot exist before its boundary, so use a stale epoch).
        assert_eq!(l.claim(&claim(P, &lics[0], 1, 2), P - 1, &lics[0]), Err(DivError::NotYetClaimable));
        // After advance the expired award is gone and its remainder is released.
        let ev = l.advance(P + W, 12_000_000, &lics).unwrap();
        assert!(matches!(ev[0], Event::Expired { award: a, .. } if a == P));
        assert_eq!(l.reserved(), 0);
        assert_eq!(l.claim(&claim(P, &lics[0], 1, 2), P + W, &lics[0]), Err(DivError::UnknownAward));
    }

    #[test]
    fn expiry_releases_exactly_the_unclaimed_balance_without_redistribution() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 12_000_000, &lics).unwrap();
        let share = l.award(P).unwrap().account(&h(1)).unwrap().share;
        l.claim(&claim(P, &lics[0], share, 0), P + 1, &lics[0]).unwrap();
        let before = l.reserved();
        assert_eq!(before, share * 11);
        let ev = l.advance(P + W, 12_000_000 - share, &lics).unwrap();
        assert_eq!(ev, vec![Event::Expired { award: P, released: share * 11 }]);
        assert_eq!(l.reserved(), 0);
    }

    #[test]
    fn locked_constants_release_every_reserve_before_the_next_boundary() {
        // Window < period, so under the locked constants the existing reserve is always zero
        // when a boundary arrives. The subtraction is still implemented and tested below.
        assert!(W < P);
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 12_000_000, &lics).unwrap();
        assert!(l.reserved() > 0);
        l.advance(2 * P - 1, 12_000_000, &lics).unwrap();
        assert_eq!(l.reserved(), 0);
        assert_eq!(l.live_awards(), 0);
    }

    #[test]
    fn existing_reserve_is_subtracted_from_the_next_pool_when_one_is_live() {
        // Build a live award whose window outlasts the next boundary (impossible with the
        // locked constants; this pins the DIV-002 formula against future constant changes).
        let lics = twelve();
        let mut accounts = BTreeMap::new();
        accounts.insert(h(1), Account { share: 1_000, remaining: 1_000, claims: 0 });
        let live = Award { epoch: 2 * P - 10, accounts };
        assert!(live.deadline() > 2 * P);
        let mut l = Ledger { reserved: 1_000, cursor: 2 * P - 1, awards: BTreeMap::new() };
        l.awards.insert(live.epoch, live);
        // balance 25_000 - reserve 1_000 = 24_000 available; pool 12_000; share 1_000.
        let ev = l.advance(2 * P, 25_000, &lics).unwrap();
        assert_eq!(ev, vec![Event::Awarded { award: 2 * P, eligible: 12, share: 1_000, reserved: 12_000 }]);
        assert_eq!(l.reserved(), 13_000);
        l.check_invariants(25_000).unwrap();
        assert_eq!(l.available(25_000).unwrap(), 12_000);
        assert_eq!(l.available(999), Err(DivError::Backing));
    }

    #[test]
    fn skipped_epochs_process_each_boundary_in_order_and_match_stepwise_execution() {
        let lics = twelve();
        let balance = 7_300_000_011u64;
        let target = 3 * P + 5;
        let mut jump = Ledger::new();
        let ev = jump.advance(target, balance, &lics).unwrap();
        // Order: award P, expiry of P at P+W, award 2P, expiry at 2P+W, award 3P.
        let kinds: Vec<(&str, u64)> = ev
            .iter()
            .map(|e| match e {
                Event::Awarded { award, .. } => ("award", *award),
                Event::Expired { award, .. } => ("expire", *award),
                Event::NoAward { boundary, .. } => ("none", *boundary),
            })
            .collect();
        assert_eq!(kinds, vec![("award", P), ("expire", P), ("award", 2 * P), ("expire", 2 * P), ("award", 3 * P)]);
        // Nothing was claimed, so every award sees the same available balance and equal shares.
        let share = (balance / 2) / 12;
        assert!(ev.iter().filter_map(|e| if let Event::Awarded { share: s, .. } = e { Some(*s) } else { None }).all(|s| s == share));
        assert_eq!(jump.live_awards(), 1);
        assert_eq!(jump.reserved(), share * 12);

        // Same result stepping around every event epoch.
        let mut step = Ledger::new();
        let mut all = Vec::new();
        for e in [P - 1, P, P + W - 1, P + W, 2 * P - 1, 2 * P, 2 * P + W - 1, 2 * P + W, 3 * P, target] {
            all.extend(step.advance(e, balance, &lics).unwrap());
        }
        assert_eq!(all, ev);
        assert_eq!(step, jump);
    }

    #[test]
    fn expired_awards_never_regain_a_claim_window_after_a_gap() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 12_000_000, &lics).unwrap();
        // Chain halts, resumes long after the deadline: the old award is expired at resume.
        l.advance(P + W + 10, 12_000_000, &lics).unwrap();
        assert_eq!(l.claim(&claim(P, &lics[0], 1, 0), P + W + 10, &lics[0]), Err(DivError::UnknownAward));
    }

    #[test]
    fn activation_epoch_gates_eligibility_at_the_boundary() {
        let lics = vec![
            lic(1, 1, 0, Status::Active),
            lic(2, 2, P, Status::Active),     // active exactly at E: included
            lic(3, 3, P + 1, Status::Active), // not yet active at E: excluded
        ];
        let mut l = Ledger::new();
        let ev = l.advance(P, 3_000_000, &lics).unwrap();
        assert!(matches!(ev[0], Event::Awarded { eligible: 2, .. }));
        assert!(l.award(P).unwrap().account(&h(3)).is_none());
        // The late License is included at the next award.
        let ev2 = l.advance(2 * P, 3_000_000, &lics).unwrap();
        assert!(ev2.iter().any(|e| matches!(e, Event::Awarded { eligible: 3, .. })));
    }

    #[test]
    fn suspended_and_revoked_licenses_are_excluded_from_the_snapshot() {
        let mut lics = twelve();
        lics[0].status = Status::Suspended;
        lics[1].status = Status::Revoked;
        let mut l = Ledger::new();
        let ev = l.advance(P, 10_000_000, &lics).unwrap();
        assert!(matches!(ev[0], Event::Awarded { eligible: 10, .. }));
        assert!(l.award(P).unwrap().account(&h(1)).is_none());
        assert!(l.award(P).unwrap().account(&h(2)).is_none());
    }

    #[test]
    fn suspension_after_award_blocks_claims_but_preserves_the_entitlement_until_expiry() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 12_000_000, &lics).unwrap();
        let before = l.clone();
        let mut s = lics[0].clone();
        s.status = Status::Suspended;
        assert_eq!(l.claim(&claim(P, &s, 1, 0), P + 5, &s), Err(DivError::Suspended));
        assert_eq!(l, before, "failed claim must not change the ledger");
        // Backing remains reserved while suspended.
        assert_eq!(l.reserved(), before.reserved());
        // Unsuspension restores access within the unchanged window.
        assert!(l.claim(&claim(P, &lics[0], 1, 0), P + W - 1, &lics[0]).is_ok());
        // Suspension that outlasts the window ends in ordinary expiry and release.
        let mut l2 = before.clone();
        let ev = l2.advance(P + W, 12_000_000, &lics).unwrap();
        assert!(matches!(ev[0], Event::Expired { .. }));
        assert_eq!(l2.reserved(), 0);
    }

    #[test]
    fn revoked_license_cannot_claim_and_paid_amounts_are_not_clawed_back() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 12_000_000, &lics).unwrap();
        let r = l.claim(&claim(P, &lics[0], 10, 0), P + 1, &lics[0]).unwrap();
        assert_eq!(r.paid, 10);
        let paid_state = l.clone();
        let mut revoked = lics[0].clone();
        revoked.status = Status::Revoked;
        assert_eq!(l.claim(&claim(P, &revoked, 1, 1), P + 2, &revoked), Err(DivError::Revoked));
        assert_eq!(l, paid_state);
        // Earlier payment stays reflected: remaining excludes the 10 already paid.
        let share = l.award(P).unwrap().account(&h(1)).unwrap();
        assert_eq!(share.remaining, share.share - 10);
    }

    #[test]
    fn transfer_moves_unclaimed_control_to_the_current_owner_and_keeps_prior_payments() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 12_000_000, &lics).unwrap();
        let share = l.award(P).unwrap().account(&h(1)).unwrap().share;
        // Seller claims part, then the License transfers to a new owner.
        let seller_view = lics[0].clone();
        l.claim(&claim(P, &seller_view, 100, 0), P + 1, &seller_view).unwrap();
        let mut buyer_view = seller_view.clone();
        buyer_view.owner = h(77);
        // Old-owner authority is stale after transfer.
        assert_eq!(l.claim(&claim(P, &seller_view, 1, 1), P + 2, &buyer_view), Err(DivError::StaleOwner));
        // Current owner claims exactly the unclaimed remainder; the seller's 100 is not touched.
        let rest = share - 100;
        let r = l.claim(&claim(P, &buyer_view, rest, 1), P + 3, &buyer_view).unwrap();
        assert_eq!(r, Receipt { paid: rest, remaining: 0 });
        assert_eq!(l.claim(&claim(P, &buyer_view, 1, 2), P + 4, &buyer_view), Err(DivError::Overdrawn));
    }

    #[test]
    fn claims_fail_closed_and_leave_the_ledger_unchanged() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 12_000_000, &lics).unwrap();
        let share = l.award(P).unwrap().account(&h(1)).unwrap().share;
        let snapshot = l.clone();
        let epoch = P + 1;
        let me = &lics[0];
        assert_eq!(l.claim(&claim(P, me, 0, 0), epoch, me), Err(DivError::ZeroAmount));
        assert_eq!(l.claim(&claim(P, me, share + 1, 0), epoch, me), Err(DivError::Overdrawn));
        assert_eq!(l.claim(&claim(P, me, 1, 1), epoch, me), Err(DivError::Sequence));
        assert_eq!(l.claim(&claim(P + 1, me, 1, 0), epoch, me), Err(DivError::UnknownAward));
        let mut wrong = claim(P, me, 1, 0);
        wrong.license = h(2);
        assert_eq!(l.claim(&wrong, epoch, me), Err(DivError::WrongLicense));
        let mut stale = claim(P, me, 1, 0);
        stale.claimant = h(99);
        assert_eq!(l.claim(&stale, epoch, me), Err(DivError::StaleOwner));
        let stranger = lic(50, 50, 0, Status::Active);
        assert_eq!(l.claim(&claim(P, &stranger, 1, 0), epoch, &stranger), Err(DivError::NotEntitled));
        assert_eq!(l, snapshot);
    }

    #[test]
    fn replay_is_rejected_and_partial_claims_sum_exactly() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 12_000_000, &lics).unwrap();
        let share = l.award(P).unwrap().account(&h(1)).unwrap().share;
        let me = &lics[0];
        let c = claim(P, me, 7, 0);
        l.claim(&c, P + 1, me).unwrap();
        let after_first = l.clone();
        assert_eq!(l.claim(&c, P + 1, me), Err(DivError::Replay));
        assert_eq!(l, after_first, "replay has no economic effect");
        // The same sequence cannot be reused for a different amount either.
        assert_eq!(l.claim(&claim(P, me, 9, 0), P + 2, me), Err(DivError::Replay));
        // The next sequence may claim in parts; total never exceeds the share.
        l.claim(&claim(P, me, share - 7, 1), P + 3, me).unwrap();
        assert_eq!(l.award(P).unwrap().account(&h(1)).unwrap().remaining, 0);
        assert_eq!(l.reserved(), share * 11);
        // A fully claimed zero-balance account remains until the deadline.
        assert!(l.award(P).unwrap().account(&h(1)).is_some());
        l.check_invariants(12_000_000).unwrap();
    }

    #[test]
    fn reserve_backing_is_enforced_and_failure_is_atomic() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 12_000_000, &lics).unwrap();
        let snapshot = l.clone();
        // A resumed block whose Treasury balance cannot back the live reserve is a fault.
        assert_eq!(l.advance(P + 10, 1, &lics), Err(DivError::Backing));
        assert_eq!(l, snapshot);
        l.check_invariants(l.reserved()).unwrap();
        assert_eq!(l.check_invariants(l.reserved() - 1), Err(DivError::Backing));
    }

    #[test]
    fn finalized_state_is_never_rolled_back_by_an_earlier_epoch() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P + 100, 12_000_000, &lics).unwrap();
        let snapshot = l.clone();
        assert_eq!(l.advance(P + 99, 12_000_000, &lics), Err(DivError::Rewind));
        assert_eq!(l.advance(P - 1, 12_000_000, &lics), Err(DivError::Rewind));
        assert_eq!(l, snapshot);
    }

    #[test]
    fn tentative_copy_is_discarded_without_touching_the_committed_ledger() {
        let lics = twelve();
        let mut committed = Ledger::new();
        committed.advance(P, 12_000_000, &lics).unwrap();
        let mut tentative = committed.clone();
        tentative.claim(&claim(P, &lics[0], 5, 0), P + 1, &lics[0]).unwrap();
        assert_ne!(tentative, committed);
        drop(tentative);
        assert_eq!(committed.award(P).unwrap().account(&h(1)).unwrap().remaining, committed.award(P).unwrap().account(&h(1)).unwrap().share);
    }

    #[test]
    fn duplicate_license_ids_in_the_snapshot_are_rejected() {
        let mut lics = twelve();
        lics.push(lics[0].clone());
        let mut l = Ledger::new();
        assert_eq!(l.advance(P, 12_000_000, &lics), Err(DivError::Invariant));
        assert_eq!(l, Ledger::new());
    }

    #[test]
    fn extreme_balances_do_not_overflow() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, u64::MAX, &lics).unwrap();
        l.check_invariants(u64::MAX).unwrap();
        let share = (u64::MAX / 2) / 12;
        assert_eq!(l.reserved(), share * 12);
    }

    #[test]
    fn unlimited_partial_claims_then_exact_remainder_with_o1_replay_state() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 1_200_000, &lics).unwrap();
        let share = l.award(P).unwrap().account(&h(1)).unwrap().share;
        assert_eq!(share, 50_000);
        // Far more than eight successful partial claims; amounts vary, none is forced to the rest.
        let mut paid = 0u64;
        for i in 0..40u64 {
            let amount = 1 + i % 7;
            let r = l.claim(&claim(P, &lics[0], amount, i), P + 1 + i, &lics[0]).unwrap();
            paid += amount;
            assert_eq!(r, Receipt { paid: amount, remaining: share - paid });
        }
        assert_eq!(l.award(P).unwrap().account(&h(1)).unwrap().claims, 40);
        // A ninth (or forty-first) otherwise valid claim is not refused for being "too many".
        assert!(l.claim(&claim(P, &lics[0], 1, 40), P + 50, &lics[0]).is_ok());
        paid += 1;
        // Sequence discipline: replay below, gap above; neither changes the ledger.
        let snapshot = l.clone();
        assert_eq!(l.claim(&claim(P, &lics[0], 1, 3), P + 51, &lics[0]), Err(DivError::Replay));
        assert_eq!(l.claim(&claim(P, &lics[0], 1, 42), P + 51, &lics[0]), Err(DivError::Sequence));
        assert_eq!(l, snapshot);
        // Final exact remainder claim, then nothing is left.
        let rest = share - paid;
        let r = l.claim(&claim(P, &lics[0], rest, 41), P + 52, &lics[0]).unwrap();
        assert_eq!((r.paid, r.remaining), (rest, 0));
        assert_eq!(l.claim(&claim(P, &lics[0], 1, 42), P + 53, &lics[0]), Err(DivError::Overdrawn));
        l.check_invariants(u64::MAX).unwrap();
        // Replay state is one counter per account: it does not grow with the number of claims.
        let a = l.award(P).unwrap();
        assert_eq!(a.accounts(), 12);
        assert_eq!(a.account(&h(1)).unwrap().claims, 42);
        assert_eq!(a.account(&h(2)).unwrap().claims, 0);
        // Other Licenses are unaffected by this account's history.
        assert!(l.claim(&claim(P, &lics[1], 1, 0), P + 54, &lics[1]).is_ok());
        // Expiry discards the counters together with the award.
        l.advance(P + W, 1_200_000 - share, &lics).unwrap();
        assert!(l.award(P).is_none());
    }

    #[test]
    fn claim_eligibility_uses_the_actual_block_epoch_and_never_the_cursor() {
        let lics = twelve();
        let mut l = Ledger::new();
        // A forward jump processes the award; the cursor now sits well above E.
        l.advance(P + 100, 12_000_000, &lics).unwrap();
        assert_eq!(l.cursor(), P + 100);
        // A later block whose actual epoch is below E cannot claim, although the cursor is past E.
        assert_eq!(l.claim(&claim(P, &lics[0], 1, 0), P - 1, &lics[0]), Err(DivError::NotYetClaimable));
        assert_eq!(l.claim(&claim(P, &lics[0], 1, 0), 0, &lics[0]), Err(DivError::NotYetClaimable));
        // An actual epoch inside the window is eligible even when it is below the cursor.
        assert!(l.claim(&claim(P, &lics[0], 1, 0), P + 5, &lics[0]).is_ok());
        // Advance past the deadline: expiry is processed once and is final.
        l.advance(P + W + 3, 12_000_000, &lics).unwrap();
        assert!(l.award(P).is_none());
        let frozen = l.clone();
        // A block below the deadline (actual epoch P + W - 1) cannot reopen the expired entitlement.
        assert_eq!(l.claim(&claim(P, &lics[0], 1, 1), P + W - 1, &lics[0]), Err(DivError::UnknownAward));
        assert_eq!(l.claim(&claim(P, &lics[0], 1, 1), P + 10, &lics[0]), Err(DivError::UnknownAward));
        assert_eq!(l, frozen);
    }

    #[test]
    fn epoch_regression_cannot_recreate_expire_or_revise_and_later_deposits_are_not_backdated() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 12_000_000, &lics).unwrap();
        let first = l.award(P).unwrap().clone();
        l.advance(P + 1_000, 12_000_000, &lics).unwrap();
        let before = l.clone();
        // Regressions are refused by the monotone cursor: nothing is recreated or reopened.
        assert_eq!(l.advance(P - 1, 99_000_000, &lics), Err(DivError::Rewind));
        assert_eq!(l.advance(P + 999, 99_000_000, &lics), Err(DivError::Rewind));
        assert_eq!(l, before);
        // A bigger Treasury balance seen at a later block does not rewrite the frozen snapshot.
        l.advance(P + 1_001, 99_000_000, &lics).unwrap();
        assert_eq!(l.award(P).unwrap(), &first);
        // Expiry is permanent: after the deadline no regression revives the award or its reserve.
        l.advance(P + W, 99_000_000, &lics).unwrap();
        assert_eq!(l.reserved(), 0);
        let expired = l.clone();
        assert_eq!(l.advance(P + W - 1, 99_000_000, &lics), Err(DivError::Rewind));
        assert_eq!(l, expired);
    }

    #[test]
    fn missing_activation_is_never_eligible_and_epoch_zero_is_not_a_default() {
        let mut lics = twelve();
        lics[0].activation_epoch = None;
        let mut l = Ledger::new();
        let ev = l.advance(P, 11_000_000, &lics).unwrap();
        assert!(matches!(ev[0], Event::Awarded { eligible: 11, .. }));
        assert!(l.award(P).unwrap().account(&h(1)).is_none());
        // Epoch 0 itself creates no award even when every License has activation 0.
        let mut g = Ledger::new();
        assert!(g.advance(0, 12_000_000, &twelve()).unwrap().is_empty());
        assert_eq!(g.live_awards(), 0);
    }

    #[test]
    fn parts_roundtrip_and_malformed_state_is_rejected() {
        let lics = twelve();
        let mut l = Ledger::new();
        l.advance(P, 1_200_000, &lics).unwrap();
        l.claim(&claim(P, &lics[0], 10, 0), P + 1, &lics[0]).unwrap();
        let awards: Vec<Award> = l.awards_iter().cloned().collect();
        let again = Ledger::from_parts(l.reserved(), l.cursor(), awards.clone()).unwrap();
        assert_eq!(again, l);
        assert!(Ledger::from_parts(l.reserved() + 1, l.cursor(), awards.clone()).is_err());
        assert!(Ledger::from_parts(l.reserved(), P - 1, awards.clone()).is_err());
        assert!(Ledger::from_parts(l.reserved(), P + W, awards.clone()).is_err());
        assert!(Ledger::from_parts(l.reserved(), l.cursor(), vec![awards[0].clone(), awards[0].clone()]).is_err());
        let a = &awards[0];
        let accounts: BTreeMap<Hash, Account> = a.accounts_iter().map(|(k, v)| (*k, *v)).collect();
        assert!(Award::from_parts(P + 1, accounts.clone()).is_err());
        assert!(Award::from_parts(0, accounts.clone()).is_err());
        assert!(Award::from_parts(P, BTreeMap::new()).is_err());
        // Inconsistent claim counters are malformed: paid without a claim, a claim without payment,
        // or more claims than atoms paid.
        let mut bad = accounts.clone();
        bad.get_mut(&h(2)).unwrap().remaining -= 1;
        assert!(Award::from_parts(P, bad).is_err());
        let mut bad = accounts.clone();
        bad.get_mut(&h(2)).unwrap().claims = 1;
        assert!(Award::from_parts(P, bad).is_err());
        let mut bad = accounts.clone();
        bad.get_mut(&h(1)).unwrap().claims = 11;
        assert!(Award::from_parts(P, bad).is_err());
        assert!(Award::from_parts(P, accounts).is_ok());
        assert!(Ledger::new().is_pristine() && !l.is_pristine());
    }
}
