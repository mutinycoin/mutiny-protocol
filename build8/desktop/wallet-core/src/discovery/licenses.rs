//! Read-only lookups of Licenses over a verified `State` (phase 3).
//!
//! Nothing here authenticates the state: the caller verifies the parent state root first (build the
//! `ChainView` with `ChainView::verified`, or from a store that already authenticated it). Nothing
//! here changes anything either.
//!
//! CONTROL is decided exactly as consensus decides dividend-claim authority:
//! `WalletBook::authorize(license.owner, descriptor)`. A wallet that rotated its key therefore still
//! controls every License recorded under one of its OLDER addresses (the book resolves an old address
//! of an authority to that authority's CURRENT descriptor), and a rotated-away key controls none.
//! Enumeration uses the read-only `license_book_v2::Book::licenses` accessor.
use crate::units;
use mutiny_consensus_v8::{
    Hash, dividends_v1::Status, execution::State, license_status_v1::Entry, trading_v1,
};
use std::fmt;

/// A License's dividend standing, as consensus reads it for a claim: at the ledger's processed
/// epoch (the cursor), not at any wall-clock time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    Active,
    /// Suspended while the processed epoch is below `until`; the entitlement is kept until the
    /// award's ordinary expiry, but nothing can be claimed meanwhile.
    Suspended { until: u64 },
    /// Terminal: nothing can be claimed again.
    Revoked,
}

impl Standing {
    pub fn text(self) -> String {
        match self {
            Self::Active => "active".to_string(),
            Self::Suspended { until } => format!("suspended until epoch {until}"),
            Self::Revoked => "revoked".to_string(),
        }
    }
}

/// What the verified state says about one License.
#[derive(Clone, PartialEq, Eq)]
pub struct LicenseInfo {
    pub id: Hash,
    /// Issuance index (0 to 11 for the Genesis bootstrap Licenses).
    pub index: u64,
    /// The recorded owner AddressID (possibly an older address of a rotated wallet).
    pub owner: Hash,
    pub issue_height: u64,
    /// The License generation a sale must name (1 until the first native transfer); `None` when
    /// the transfer record cannot be read.
    pub generation: Option<u64>,
    pub standing: Standing,
    /// The epoch from which the License is dividend-eligible; `None` means never (no validated
    /// activation exists).
    pub dividend_activation_epoch: Option<u64>,
    /// The License has an active Worker (it can mine).
    pub mining: bool,
    /// A Worker assignment is scheduled but not active yet (it blocks a sale, not a claim).
    pub pending_assignment: bool,
}

impl fmt::Debug for LicenseInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LicenseInfo")
            .field("id", &units::short_hex(&self.id))
            .field("index", &self.index)
            .field("owner", &units::short_hex(&self.owner))
            .field("generation", &self.generation)
            .field("standing", &self.standing)
            .field("dividend_activation_epoch", &self.dividend_activation_epoch)
            .field("mining", &self.mining)
            .field("pending_assignment", &self.pending_assignment)
            .finish()
    }
}

/// The standing of `license` at the ledger's processed epoch.
pub fn standing(state: &State, license: &Hash) -> Standing {
    let cursor = state.dividends.ledger().cursor();
    match state.dividends.statuses().effective(license, cursor) {
        Status::Active => Standing::Active,
        Status::Revoked => Standing::Revoked,
        Status::Suspended => match state.dividends.statuses().get(license) {
            Some(Entry::Suspended { until }) => Standing::Suspended { until: *until },
            // `effective` reports a suspension only for a suspension entry; fail closed anyway.
            _ => Standing::Revoked,
        },
    }
}

/// One License by identifier, if the state has it.
pub fn license(state: &State, id: Hash) -> Option<LicenseInfo> {
    let record = state.licenses_v2.license(id)?;
    Some(LicenseInfo {
        id: record.id,
        index: record.index,
        owner: record.owner,
        issue_height: record.issue_height,
        generation: trading_v1::license_generation(state, id).ok(),
        standing: standing(state, &id),
        dividend_activation_epoch: state.licenses_v2.dividend_activation_epoch(id),
        mining: record.active_worker.is_some(),
        pending_assignment: state.licenses_v2.pending_assignment(id).is_some(),
    })
}

/// Whether the key with `descriptor` is the current owner authority of `license`, exactly as
/// consensus resolves it for a claim.
pub fn controls(state: &State, license: Hash, descriptor: &[u8]) -> bool {
    state
        .licenses_v2
        .license(license)
        .is_some_and(|record| state.wallets.authorize(record.owner, descriptor).is_ok())
}

/// Every License the key with `descriptor` controls, in canonical (LicenseID) order, including the
/// Licenses recorded under older addresses of the same wallet authority.
pub fn controlled(state: &State, descriptor: &[u8]) -> Vec<LicenseInfo> {
    state
        .licenses_v2
        .licenses()
        .filter(|record| state.wallets.authorize(record.owner, descriptor).is_ok())
        .filter_map(|record| license(state, record.id))
        .collect()
}
