//! Ordinary MUT payments end to end on a REAL consensus chain (NATIVE, TEST-VALUE): plan, review,
//! typed acknowledgements, approval, authorization, independent consensus verification, outbox
//! reservation, mempool admission, a block built by the production assembler and certified with real
//! hybrid votes, installed by the canonical store, then outbox reconciliation. Differential checks
//! against consensus for the Treasury reserve.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/rig.rs"]
mod rig;

use mutiny_consensus_v8::{
    hybrid_transaction_v2::Transaction, transactions::OutPoint, transactions_v2::Transfer,
};
use mutiny_wallet_core_v8::*;
use rig::chain::*;
use std::collections::BTreeSet;

fn pay(recipient: [u8; 32], amount: u64) -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(recipient, amount))
}

#[test]
fn payment_plan_review_authorize_verify_queue_block_and_reconcile() {
    let key = wallet_key();
    let me = identity_of(&key);
    let recipient = address_of(&other_key());
    let funding = Funding::plain(0xa1, address_of(&key), 5_000_000);
    let mut h = Harness::new("e2e-pay", 1_200_000, std::slice::from_ref(&funding));
    let signer = KeySigner::for_test(wallet_key()).unwrap();
    let no_reservations = BTreeSet::new();

    // ---- plan, review, approve, authorize
    let (signed, review_text) = {
        let view = h.view(&no_reservations);
        assert_eq!(view.class(), ChainClass::TestValue);
        let planned = plan(&pay(recipient, 1_000_000), &view, &me).unwrap();
        assert_eq!(planned.inputs(), std::slice::from_ref(&funding.point));
        let reviewed = review(&planned, &view).unwrap();

        // The review shows destination, amount, fee, change, conditions, timing and effects.
        assert_eq!(reviewed.amount(), Some(1_000_000));
        let paid: Vec<_> = reviewed
            .destinations()
            .iter()
            .filter(|d| d.role == DestinationRole::Payment)
            .collect();
        assert_eq!(paid.len(), 1);
        assert_eq!(
            (paid[0].address, paid[0].atoms, paid[0].label),
            (recipient, 1_000_000, AddressLabel::External)
        );
        let change: Vec<_> = reviewed
            .destinations()
            .iter()
            .filter(|d| d.role == DestinationRole::Change)
            .collect();
        assert_eq!(change.len(), 1);
        assert_eq!(
            (change[0].address, change[0].label),
            (address_of(&key), AddressLabel::ThisWallet)
        );
        assert_eq!(reviewed.fee().payer, FeePayer::ThisWallet);
        assert_eq!(
            reviewed.fee().size_bytes,
            Some(planned.objects()[0].bytes.len() as u64)
        );
        assert_eq!(
            reviewed.fee().atoms + reviewed.returned() + 1_000_000,
            5_000_000
        );
        assert_eq!(
            reviewed.net_debit(),
            Some(u128::from(1_000_000 + reviewed.fee().atoms))
        );
        assert_eq!(reviewed.timing().created_height, Some(1));
        assert!(reviewed.effects().iter().any(|e| e.irreversible));
        assert_eq!(
            reviewed.acknowledgements(),
            &[
                AckKind::Destination,
                AckKind::Amount,
                AckKind::Fee,
                AckKind::Irreversible
            ]
        );
        let text = reviewed.render_text();
        assert!(text.contains(&hex::encode(recipient)));
        assert!(text.contains("TEST-VALUE chain"));

        let signed = flow::sign(planned, &signer, &view).unwrap();
        (signed, text)
    };
    assert!(!review_text.is_empty());
    assert!(signed.is_complete());
    assert_eq!(signed.kind(), OperationKind::Payment);

    // ---- independent verification through consensus code
    let transaction = Transaction::decode(signed.bytes()).unwrap();
    let Transaction::Transfer(ref transfer) = transaction else {
        panic!("a payment must encode the native Transfer variant")
    };
    assert_eq!(transfer.id().unwrap(), signed.id());
    assert!(transfer.fee >= signed.bytes().len() as u64);
    {
        let state = h.state();
        transfer
            .verify(
                h.genesis().genesis,
                h.genesis().fingerprint,
                1,
                &state.coins,
                &state.wallets,
            )
            .expect("Transfer::verify accepts the wallet's payment");
    }

    // ---- durable queue with input reservations
    let mut outbox = MemoryOutbox::new();
    let mut second_outbox = MemoryOutbox::new();
    {
        let view = h.view(&no_reservations);
        second_outbox.commit(&signed, &view).unwrap();
        assert_eq!(outbox.commit(&signed, &view).unwrap(), signed.id());
        assert_eq!(
            outbox.commit(&signed, &view).unwrap(),
            signed.id(),
            "committing the same bytes again is idempotent"
        );
    }
    assert_eq!(outbox.pending().unwrap().len(), 1);
    let reserved = outbox.reserved().unwrap();
    assert_eq!(reserved, BTreeSet::from([funding.point.clone()]));
    {
        // The queued payment reserves its coin: nothing else is spendable.
        let view = h.view(&reserved);
        assert_eq!(
            plan(&pay(recipient, 1), &view, &me).unwrap_err(),
            Refusal::NothingSpendable
        );
    }

    // ---- the node path: pool admission, then a real block from the production assembler
    h.admit(&transaction)
        .expect("the hybrid mempool admits the wallet's payment");
    assert_eq!(
        h.pool_reserved(),
        reserved,
        "the pool and the outbox reserve the same coin"
    );
    assert_eq!(
        h.assemble_only(),
        vec![signed.bytes().to_vec()],
        "the assembler selects exactly the signed bytes"
    );
    let after = h.step();
    assert_eq!(h.height(), 1);
    let paid = after
        .coins
        .iter()
        .filter(|(_, c)| c.output.owner == recipient)
        .map(|(_, c)| c.output.atoms)
        .sum::<u64>();
    assert_eq!(paid, 1_000_000, "the recipient holds the payment");
    let kept = after
        .coins
        .iter()
        .filter(|(_, c)| !c.coinbase && c.output.owner == address_of(&key))
        .map(|(_, c)| c.output.atoms)
        .sum::<u64>();
    assert_eq!(
        kept,
        5_000_000 - 1_000_000 - transfer.fee,
        "change returned to the wallet"
    );
    assert!(
        !after.coins.contains_key(&funding.point),
        "the funding coin is spent"
    );
    let reward = after
        .coins
        .values()
        .filter(|c| c.coinbase)
        .map(|c| c.output.atoms)
        .sum::<u64>();
    assert_eq!(
        reward,
        100_000_000 + transfer.fee,
        "the fee went to the block producer"
    );

    // ---- reconciliation from verified state
    {
        let confirmations = h.confirmations();
        let none = BTreeSet::new();
        let view = h.view(&none).with_confirmations(&confirmations);
        let report = outbox.reconcile(&view).unwrap();
        assert_eq!(
            report,
            ReconcileReport {
                confirmed: 1,
                expired: 0,
                inputs_spent: 0,
                stranded: 0,
                still_pending: 0,
                pruned: 0,
            }
        );
    }
    assert_eq!(
        outbox.get(&signed.id()).unwrap().unwrap().status,
        OutboxStatus::Confirmed(1)
    );
    assert!(
        outbox.reserved().unwrap().is_empty(),
        "a confirmed record releases its reservation"
    );
    // Without the host's confirmation index the output coin still proves inclusion.
    {
        let none = BTreeSet::new();
        let view = h.view(&none);
        assert_eq!(second_outbox.reconcile(&view).unwrap().confirmed, 1);
        assert_eq!(
            second_outbox.get(&signed.id()).unwrap().unwrap().status,
            OutboxStatus::Confirmed(1)
        );
    }
    h.finish();
}

#[test]
fn a_plan_dies_when_another_spend_of_its_coin_is_included_first() {
    let key = wallet_key();
    let me = identity_of(&key);
    let mut h = Harness::new(
        "e2e-conflict",
        1_200_000,
        &[
            Funding::plain(0xb1, address_of(&key), 2_000_000),
            Funding::plain(0xb2, address_of(&key), 1_000),
        ],
    );
    let signer = KeySigner::for_test(wallet_key()).unwrap();
    let none = BTreeSet::new();

    // Two plans both choose the big coin; the first is signed, admitted and included.
    let (first, second_plan, second_approval) = {
        let view = h.view(&none);
        let first = plan(&pay(address_of(&other_key()), 500_000), &view, &me).unwrap();
        let second = plan(&pay(address_of(&other_key()), 600_000), &view, &me).unwrap();
        assert_eq!(
            first.inputs(),
            second.inputs(),
            "both plans want the same coin"
        );
        let approval = flow::approve(&review(&second, &view).unwrap(), &view);
        (flow::sign(first, &signer, &view).unwrap(), second, approval)
    };
    h.admit(&Transaction::decode(first.bytes()).unwrap())
        .unwrap();
    h.step();

    // At the new head the second plan's coin is gone: its review refuses, its approval is stale.
    let view = h.view(&none);
    assert_eq!(
        review(&second_plan, &view).unwrap_err(),
        Refusal::InputUnavailable
    );
    assert!(matches!(
        signer.authorize(second_plan, second_approval, &view),
        Err(Refusal::StaleHead {
            reviewed: 0,
            current: 1
        })
    ));
    // Re-planning at the new head works and uses the surviving coins.
    let again = plan(&pay(address_of(&other_key()), 500_000), &view, &me).unwrap();
    assert!(!again.inputs().contains(&OutPoint {
        transaction: [0xb1; 32],
        index: 0
    }));
    h.finish();
}

#[test]
fn treasury_reserve_floor_matches_consensus_exactly() {
    // The TEST-VALUE Treasury holds 1,200,000 atoms; the first award boundary reserves half of it.
    let treasury_key = treasury_wallet_key();
    let mut h = Harness::new("e2e-reserve", 1_200_000, &[]);
    let after_award = h.step_at(131_072);
    let reserved = after_award.dividends.reserved();
    assert_eq!(
        reserved, 600_000,
        "an outstanding award reserves half of the backing"
    );

    let identity = identity_of(&treasury_key).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: None,
    });
    let signer = KeySigner::with_identity(
        treasury_wallet_key(),
        identity.clone(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    let recipient = address_of(&other_key());
    let none = BTreeSet::new();

    // An ordinary profile never spends the Treasury.
    {
        let view = h.view(&none);
        let ordinary = identity_of(&treasury_key);
        assert_eq!(
            plan(&pay(recipient, 10_000), &view, &ordinary).unwrap_err(),
            Refusal::TreasuryProfileRequired
        );
    }

    // Learn the fee of this shape, then spend exactly down to the reserve.
    let (good, fee, amount) = {
        let view = h.view(&none);
        let probe = plan(&pay(recipient, 500_000), &view, &identity).unwrap();
        let fee = review(&probe, &view).unwrap().fee().atoms;
        let amount = 1_200_000 - 600_000 - fee; // leaves exactly the reserve as change
        let planned = plan(&pay(recipient, amount), &view, &identity).unwrap();
        assert_eq!(review(&planned, &view).unwrap().fee().atoms, fee);
        let signed = flow::sign(planned, &signer, &view).unwrap();
        (signed, fee, amount)
    };
    // One atom more is refused by the wallet ...
    {
        let view = h.view(&none);
        assert_eq!(
            plan(&pay(recipient, amount + 1), &view, &identity).unwrap_err(),
            Refusal::ReserveBackingViolation {
                reserved: 600_000,
                backing_after: 599_999
            }
        );
    }
    // ... and by consensus, which rejects the equivalent hand-built block body, while it accepts
    // the wallet's own transaction.
    let treasury_address = address_of(&treasury_key);
    let violating = h.hand_signed_transfer(
        &treasury_key,
        h.treasury_coin(),
        fee,
        &[(recipient, amount + 1), (treasury_address, 600_000 - 1)],
    );
    assert!(
        h.execute_as_block(vec![violating.encode().unwrap()])
            .is_err(),
        "consensus rejects spending below the reserve"
    );
    assert!(
        h.execute_as_block(vec![good.bytes().to_vec()]).is_ok(),
        "consensus accepts spending down to the reserve"
    );

    // And the block with the wallet's transaction really installs.
    h.admit(&Transaction::decode(good.bytes()).unwrap())
        .unwrap();
    let state = h.step();
    assert_eq!(state.dividends.reserved(), 600_000);
    let backing: u64 = state
        .coins
        .values()
        .filter(|c| !c.coinbase && c.output.owner == treasury_address)
        .map(|c| c.output.atoms)
        .sum();
    assert_eq!(backing, 600_000);
    h.finish();
}

#[test]
fn a_view_can_prove_that_its_state_hashes_to_the_authenticated_head_root() {
    let key = wallet_key();
    let h = Harness::new(
        "e2e-root",
        1_200_000,
        &[Funding::plain(0xc1, address_of(&key), 1_000_000)],
    );
    let none = BTreeSet::new();
    // The head the store authenticated, with the state it authenticated.
    let head = h.head();
    assert!(ChainView::verified(head.clone(), h.state(), &none).is_ok());
    assert!(h.view(&none).verify_state_root().is_ok());
    // The same state under a different root is refused, as is a state that was edited.
    let wrong_root = HeadInfo::new(
        head.anchor().clone(),
        head.timestamp(),
        head.t0(),
        [0x66; 32],
    )
    .unwrap();
    assert!(matches!(
        ChainView::verified(wrong_root, h.state(), &none),
        Err(Refusal::Malformed(_))
    ));
    let mut edited = h.state().clone();
    edited.coins.clear();
    assert!(matches!(
        ChainView::verified(head, &edited, &none),
        Err(Refusal::Malformed(_))
    ));
    h.finish();
}
