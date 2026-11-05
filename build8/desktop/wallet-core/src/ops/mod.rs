//! One file per operation kind. Each implements `OperationHandler` and is registered here.
//!
//! Registration is PRE-WIRED for every kind: each file below exports `handler(kind)`, which returns
//! `None` (the kind is refused as `NOT_IMPLEMENTED`) until the phase that owns the file replaces its
//! content. A phase therefore edits only its own file; `mod.rs` and `lib.rs` do not change. The shared
//! types it needs (kinds, requests, plans, reviews, refusals, signer slots) are frozen in the other
//! modules.
use crate::{
    plan::{OperationHandler, OperationKind},
    refusal::Refusal,
};

pub mod bond;
pub(crate) mod bond_create;
pub mod conditional;
pub mod dividend;
pub mod fiat;
pub mod license_dvp;
pub mod maker;
pub mod payment;
pub mod rotation;
pub(crate) mod select;
pub mod treasury;
pub mod worker_assignment;

/// The handler for an operation kind, or [`Refusal::NotImplemented`] for a kind this build does
/// not have yet.
pub(crate) fn handler(kind: OperationKind) -> Result<&'static dyn OperationHandler, Refusal> {
    let found: Option<&'static dyn OperationHandler> = match kind {
        OperationKind::Payment => Some(&payment::HANDLER),
        OperationKind::MakerOffer => Some(&maker::HANDLER),
        OperationKind::WorkerAssignment => Some(&worker_assignment::HANDLER),
        OperationKind::WalletRotation => rotation::handler(kind),
        OperationKind::DividendClaim => dividend::handler(kind),
        OperationKind::LicenseDvp => license_dvp::handler(kind),
        OperationKind::HashLock
        | OperationKind::ConditionalClaim
        | OperationKind::ConditionalRefund => conditional::handler(kind),
        OperationKind::FiatLock | OperationKind::FiatRelease => fiat::handler(kind),
        OperationKind::BondCreate | OperationKind::BondUnbond | OperationKind::BondWithdraw => {
            bond::handler(kind)
        }
        OperationKind::TreasuryRotate | OperationKind::TreasuryFreezeOffer => {
            treasury::handler(kind)
        }
    };
    let Some(handler) = found else {
        return Err(Refusal::NotImplemented(kind));
    };
    debug_assert_eq!(
        handler.kind(),
        kind,
        "a handler is registered under its own kind"
    );
    Ok(handler)
}

/// The handler that recognises `raw` (unsigned, partial or signed bytes), if any.
pub(crate) fn recognizing(raw: &[u8]) -> Option<&'static dyn OperationHandler> {
    OperationKind::ALL
        .iter()
        .filter_map(|kind| handler(*kind).ok())
        .find(|handler| handler.recognizes(raw))
}

/// Test builds only: every kind whose handler recognises `raw`. For any bytes this wallet
/// produces there is exactly one ([`recognizing`] takes the first in `OperationKind::ALL` order), which
/// the tests prove over every kind.
#[cfg(any(test, feature = "test-value-signing"))]
pub fn recognizing_kinds_for_test(raw: &[u8]) -> Vec<OperationKind> {
    OperationKind::ALL
        .iter()
        .copied()
        .filter(|kind| handler(*kind).is_ok_and(|handler| handler.recognizes(raw)))
        .collect()
}

/// Kinds that have a handler in this build.
pub fn implemented_kinds() -> Vec<OperationKind> {
    OperationKind::ALL
        .iter()
        .copied()
        .filter(|kind| handler(*kind).is_ok())
        .collect()
}
