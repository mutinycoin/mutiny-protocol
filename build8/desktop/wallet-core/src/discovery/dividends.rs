//! Read-only lookups of dividend entitlements over a verified `State` (phase 3).
//!
//! Nothing here authenticates the state (the caller verifies the state root first) and nothing here
//! changes anything. Every figure comes from the dividend ledger of the verified state:
//! `state.dividends.ledger().award(epoch).account(&license)` gives the share, the remaining
//! entitlement and the number of claims already APPLIED, which is also the sequence the next claim
//! must carry. The outbox never contributes to these numbers: a claim that is queued but not yet
//! included changes nothing here; it only marks its (award, License) pair as `Outstanding`.
//!
//! Time basis (D3 timestamp rule): a claim is judged at the epoch of the block that includes it,
//! which is at least the verified head's epoch and has no consensus upper bound. The deadline figure
//! here (`epochs_left_at_most`) is therefore an UPPER bound on the time left, computed from the
//! verified head only, never from the operating-system clock.
use crate::{
    context::ChainView,
    discovery::licenses::{self, LicenseInfo, Standing},
    outbox::resource_key,
    plan::DividendClaimRequest,
    units,
};
use mutiny_consensus_v8::{
    Hash, dividends_v1::CLAIM_WINDOW_EPOCHS, domain_hash, transactions::OutPoint,
};
use std::fmt;

/// Namespace of the outbox resource that stands for one (award, License) claim slot.
pub const CLAIM_SLOT_NAMESPACE: &str = "dividend-claim";

/// The outbox reservation key of the (award, License) pair: while a queued claim holds it, no
/// second claim for the same pair is planned (two unconfirmed claims n and n+1 would only work if a
/// proposer happened to order them, and the protocol has no ordering rule for that). It can never
/// equal a coin's outpoint (see `outbox::resource_key`).
pub fn claim_slot(award_epoch: u64, license: &Hash) -> OutPoint {
    let mut body = Vec::with_capacity(8 + license.len());
    body.extend_from_slice(&award_epoch.to_be_bytes());
    body.extend_from_slice(license);
    resource_key(
        CLAIM_SLOT_NAMESPACE,
        &domain_hash(b"MUTINY-BUILD8-WALLET-DIVIDEND-CLAIM-SLOT-V1", &body),
    )
}

/// Whether a claim on an entitlement could be planned right now, and if not, why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claimability {
    /// A positive amount up to `remaining` can be claimed now.
    Claimable,
    /// A claim for this (award, License) is queued and not yet reconciled: a second one is refused
    /// until it is confirmed, expires or is forgotten.
    Outstanding,
    /// Nothing remains.
    FullyClaimed,
    /// The verified head's epoch is before the award epoch.
    NotYetOpen,
    /// The verified head's epoch is at or past the end of the claim window.
    WindowClosed,
    Suspended {
        until: u64,
    },
    Revoked,
}

/// One License's account in one live award.
#[derive(Clone, PartialEq, Eq)]
pub struct Entitlement {
    pub license: LicenseInfo,
    pub award_epoch: u64,
    pub share: u64,
    pub remaining: u64,
    /// Claims already applied for this (award, License).
    pub claims: u64,
    /// The sequence the next claim must carry (equal to `claims`).
    pub next_sequence: u64,
    /// The last epoch a block including a claim may have (`award_epoch + 65,536 - 1`).
    pub last_epoch: u64,
    /// Epochs from the verified head's epoch to the end of the window: an UPPER bound on what is
    /// left for a claim, because the including block's epoch is at least the head's.
    pub epochs_left_at_most: u64,
    pub claimability: Claimability,
}

impl Entitlement {
    /// The outbox reservation key of this (award, License) pair.
    pub fn slot(&self) -> OutPoint {
        claim_slot(self.award_epoch, &self.license.id)
    }

    /// A request to claim `amount_atoms` of this entitlement, paid to `destination`.
    pub fn request(&self, amount_atoms: u64, destination: Hash) -> DividendClaimRequest {
        DividendClaimRequest::new(self.license.id, self.award_epoch, amount_atoms, destination)
    }

    /// A request for everything that remained when this entitlement was read. The amount is fixed
    /// here, so the review shows the exact figure; if another claim is applied first, planning
    /// refuses it as overdrawn and the person reads the entitlement again.
    pub fn request_all(&self, destination: Hash) -> DividendClaimRequest {
        self.request(self.remaining, destination)
    }
}

impl fmt::Debug for Entitlement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entitlement")
            .field("license", &units::short_hex(&self.license.id))
            .field("award_epoch", &self.award_epoch)
            .field("share", &self.share)
            .field("remaining", &self.remaining)
            .field("claims", &self.claims)
            .field("last_epoch", &self.last_epoch)
            .field("epochs_left_at_most", &self.epochs_left_at_most)
            .field("claimability", &self.claimability)
            .finish()
    }
}

/// The entitlement of `license` in the award of `award_epoch`, if the verified state has that
/// account.
pub fn entitlement(view: &ChainView<'_>, award_epoch: u64, license: Hash) -> Option<Entitlement> {
    let state = view.state();
    let account = state
        .dividends
        .ledger()
        .award(award_epoch)?
        .account(&license)?;
    let info = licenses::license(state, license)?;
    let closes = award_epoch.saturating_add(CLAIM_WINDOW_EPOCHS);
    // A head whose timestamp precedes the epoch origin has no epoch; treat it as the earliest.
    let head_epoch = view.epoch().unwrap_or(0);
    let claimability = match info.standing {
        Standing::Revoked => Claimability::Revoked,
        Standing::Suspended { until } => Claimability::Suspended { until },
        Standing::Active if head_epoch < award_epoch => Claimability::NotYetOpen,
        Standing::Active if head_epoch >= closes => Claimability::WindowClosed,
        Standing::Active if account.remaining == 0 => Claimability::FullyClaimed,
        Standing::Active if view.reserved().contains(&claim_slot(award_epoch, &license)) => {
            Claimability::Outstanding
        }
        Standing::Active => Claimability::Claimable,
    };
    Some(Entitlement {
        license: info,
        award_epoch,
        share: account.share,
        remaining: account.remaining,
        claims: account.claims,
        next_sequence: account.claims,
        last_epoch: closes.saturating_sub(1),
        epochs_left_at_most: closes.saturating_sub(head_epoch),
        claimability,
    })
}

/// Every entitlement of every License the key with `descriptor` controls, in every live award:
/// the soonest deadline first, then License order. One claim covers exactly one (award, License)
/// pair, so a host lists these and lets the person pick one; each claim is its own operation with
/// its own review and approval.
pub fn entitlements(view: &ChainView<'_>, descriptor: &[u8]) -> Vec<Entitlement> {
    let state = view.state();
    let controlled = licenses::controlled(state, descriptor);
    let mut out: Vec<Entitlement> = state
        .dividends
        .ledger()
        .awards_iter()
        .flat_map(|award| {
            controlled
                .iter()
                .filter_map(move |license| entitlement(view, award.epoch(), license.id))
        })
        .collect();
    out.sort_by(|a, b| {
        (a.last_epoch, a.license.id, a.award_epoch).cmp(&(b.last_epoch, b.license.id, b.award_epoch))
    });
    out
}
