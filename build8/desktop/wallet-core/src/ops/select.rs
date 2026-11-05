//! Coin selection and spending policy shared by every operation that spends this wallet's coins.
//!
//! Selection reads the verified state only, never a peer. A coin is a candidate when it is not
//! reserved by another pending operation (nor excluded by the caller), is not newer than the head,
//! is a mature coinbase if it is a coinbase, and is controlled by the signer's key through the
//! wallet book exactly as consensus resolves ownership. At most `keep` candidates are retained,
//! largest value first with a stable tie-break by outpoint, so attacker-supplied dust can never hide
//! a spendable large coin; the total of ALL candidates is still reported for exact funds messages.
//!
//! The Treasury hook lives here and in `context::require_reserve_backing`: the Treasury authority
//! spends only through the Treasury profile, and never below the dividend reserve.
use crate::{
    authorize::SignerIdentity,
    context::{ChainView, treasury_authority},
    refusal::Refusal,
};
use mutiny_consensus_v8::transactions::{Coin, MATURITY, OutPoint};
use std::collections::BTreeSet;

/// The retained candidate coins and the totals over all of them.
pub(crate) struct Candidates<'a> {
    /// At most `keep` coins, value descending, then outpoint ascending.
    pub coins: Vec<(&'a OutPoint, &'a Coin)>,
    /// How many coins were candidates in total (may exceed `coins.len()`).
    pub count: usize,
    /// The total value of all candidates.
    pub total: u128,
}

/// Candidate coins for a key with `descriptor`, for an operation included at the next height.
pub(crate) fn candidates<'a>(
    view: &ChainView<'a>,
    descriptor: &[u8],
    keep: usize,
    exclude: &BTreeSet<OutPoint>,
) -> Result<Candidates<'a>, Refusal> {
    let next = view.next_height()?;
    let head = view.anchor().height;
    let state = view.state();
    let mut coins: Vec<(&OutPoint, &Coin)> = Vec::with_capacity(keep);
    let mut count = 0usize;
    let mut total: u128 = 0;
    for (point, coin) in &state.coins {
        if view.reserved().contains(point)
            || exclude.contains(point)
            || coin.created_height > head
            || (coin.coinbase && next - coin.created_height < MATURITY)
            || state
                .wallets
                .authorize(coin.output.owner, descriptor)
                .is_err()
        {
            continue;
        }
        count += 1;
        total += u128::from(coin.output.atoms);
        let at = coins
            .binary_search_by(|(selected_point, selected_coin)| {
                coin.output
                    .atoms
                    .cmp(&selected_coin.output.atoms)
                    .then_with(|| (*selected_point).cmp(point))
            })
            .unwrap_or_else(|at| at);
        if at < keep {
            if coins.len() == keep {
                coins.pop();
            }
            coins.insert(at, (point, coin));
        }
    }
    Ok(Candidates {
        coins,
        count,
        total,
    })
}

/// The Genesis Treasury wallet authority acts (spends its coins, rotates its key: R1) only as the
/// Treasury profile WITH the declared `Authority` role: an ordinary identity is
/// `TREASURY_PROFILE_REQUIRED`, a Treasury identity declared only for a trading Treasury
/// `TREASURY_ROLE_NOT_DECLARED` (fixes of the independent wallet review, MINOR-2).
pub(crate) fn require_profile_for_treasury(
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<(), Refusal> {
    if treasury_authority(view).is_some_and(|(authority, _)| authority == signer.authority()) {
        crate::profile::require_role(signer, crate::profile::TreasuryRole::Authority, None)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::HeadInfo;
    use mutiny_consensus_v8::{
        NETWORK_ID, anchors::FinalizedAnchor, execution::State, transactions::Output,
    };
    use mutiny_crypto_v2::{HybridKey, Role};

    #[test]
    fn candidates_are_filtered_ordered_capped_and_totalled_over_all() {
        let key =
            HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
                .unwrap();
        let descriptor = key.public().descriptor(1).unwrap();
        let owner = key.public().address_id(1).unwrap();
        let mut state = State::default();
        let mut put = |tag: u8, owner: [u8; 32], atoms: u64, created: u64, coinbase: bool| {
            let point = OutPoint {
                transaction: [tag; 32],
                index: 0,
            };
            state.coins.insert(
                point.clone(),
                Coin {
                    output: Output { owner, atoms },
                    created_height: created,
                    coinbase,
                },
            );
            point
        };
        let small = put(1, owner, 10, 1, false);
        let big = put(2, owner, 500, 1, false);
        let tie_low = put(3, owner, 70, 1, false);
        let tie_high = put(4, owner, 70, 1, false);
        let reserved = put(5, owner, 900, 1, false);
        let excluded = put(6, owner, 800, 1, false);
        let young_coinbase = put(7, owner, 700, 50, true);
        let mature_coinbase = put(8, owner, 60, 1, true);
        let stranger = put(9, [0x99; 32], 1_000, 1, false);
        let _ = (&reserved, &excluded, &young_coinbase, &stranger);
        let anchor = FinalizedAnchor {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 100,
            block: [3; 32],
        };
        let held = BTreeSet::from([reserved.clone()]);
        let view = ChainView::new(
            HeadInfo::new(anchor, 1000, 1000, [9; 32]).unwrap(),
            &state,
            &held,
        );
        let skip = BTreeSet::from([excluded.clone()]);

        let all = candidates(&view, &descriptor, 16, &skip).unwrap();
        let order: Vec<&OutPoint> = all.coins.iter().map(|(point, _)| *point).collect();
        // Value descending, equal values by outpoint; the reserved, excluded, young-coinbase and
        // foreign coins are not candidates at all.
        assert_eq!(order, [&big, &tie_low, &tie_high, &mature_coinbase, &small]);
        assert_eq!((all.count, all.total), (5, 500 + 70 + 70 + 60 + 10));

        // A cap keeps the largest but still reports the totals over every candidate.
        let capped = candidates(&view, &descriptor, 2, &skip).unwrap();
        let order: Vec<&OutPoint> = capped.coins.iter().map(|(point, _)| *point).collect();
        assert_eq!(order, [&big, &tie_low]);
        assert_eq!((capped.count, capped.total), (5, 710));

        // Dropping the exclusion brings the excluded coin back.
        let none = candidates(&view, &descriptor, 16, &BTreeSet::new()).unwrap();
        assert_eq!(none.count, 6);
        assert_eq!(*none.coins[0].0, excluded);
    }
}
