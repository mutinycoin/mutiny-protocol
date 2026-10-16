//! Native wallet-authority rotation end to end on a REAL consensus chain (NATIVE, TEST-VALUE): plan,
//! review (typed check of the new address, acknowledgements, confirmation phrase), approval,
//! authorization by the two-key session, independent verification through the public consensus
//! `hybrid_transaction_v2::Transaction::verify` with current Inclusion/history, outbox reservation of the coins and of the authority's
//! rotation slot, hybrid mempool admission (one pending rotation per authority), a block built by the
//! production assembler and certified with real hybrid votes, installed by the canonical store, and
//! reconciliation. Afterwards the old key is refused by the wallet and by consensus, old addresses
//! keep their coins and are spent by the new key, and a second rotation (generation 2 to 3) works.
//! Also: a rotation paid by another wallet (the D2 rehearsal shape) through public partial
//! approvals; the Treasury authority's rotation (R1) under the Treasury profile with the reserve rule
//! differentially checked against block execution; and atomic signatures binding every funding field.
//! The retired independent rotation/funding carrier is preserved only in external historical evidence.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/rig.rs"]
mod rig;

use flow::approve;
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    dividend_state_v1::DividendState,
    funded_rotation_v2::{
        FundedRotation, PartialRotation, Payer, Slot as NativeSlot, UnsignedRotation,
    },
    hybrid_transaction_v2::Inclusion,
    hybrid_transaction_v2::Transaction,
    transactions::{OutPoint, Output},
    transactions_v2::{Input, Transfer},
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role, rehearsal_keys_v1};
use mutiny_wallet_core_v8::{
    ops::rotation::{self, RotationSigner, combine, rotation_resource},
    *,
};
use rig::chain::*;
use std::collections::BTreeSet;

/// A public TEST-VALUE key derived from a public label (labelled-seed mode: public by construction).
fn new_key(label: &str) -> HybridKey {
    let phrase = rehearsal_keys_v1::label_phrase(label).unwrap();
    HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
}

fn rotate(new: &HybridKey, generation: u64, fee: FeeSource) -> OperationRequest {
    let proposed = new.public().descriptor(generation).unwrap();
    OperationRequest::WalletRotation(
        RotationRequest::new(Blob::new(proposed.clone()), fee)
            .with_restore_verified(rotation::descriptor_fingerprint(&proposed)),
    )
}

fn pay(recipient: Hash, amount: u64) -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(recipient, amount))
}

fn zero() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}

/// Actual tag-25 bundle signed by hand, using the current finalized parent and OLD funding key.
fn hand_bundle(
    h: &Harness,
    current: &HybridKey,
    generation: u64,
    authority: Hash,
    proposed: &HybridKey,
    point: OutPoint,
    fee: u64,
    outputs: Vec<Output>,
) -> Transaction {
    let parent = h.anchor();
    let u = UnsignedRotation {
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        envelope: mutiny_consensus_v8::op_envelope_v1::Envelope::from_head(
            &parent,
            144,
            Vec::new(),
        )
        .unwrap(),
        authority,
        current_descriptor: current.public().descriptor(generation).unwrap(),
        proposed_descriptor: proposed.public().descriptor(generation + 1).unwrap(),
        sponsor: None,
        fee,
        inputs: vec![(point, Payer::RotatingAuthority)],
        outputs,
    };
    let mut p = PartialRotation::new(u);
    p.sign(NativeSlot::Authorize, current).unwrap();
    p.sign(NativeSlot::Possession, proposed).unwrap();
    p.sign(NativeSlot::AuthorityFunding, current).unwrap();
    Transaction::FundedRotation(p.complete().unwrap())
}
fn fee(tx: &Transaction) -> u64 {
    match tx {
        Transaction::Transfer(t) => t.fee,
        Transaction::FundedRotation(t) => t.unsigned.fee,
    }
}
fn partial(raw: &[u8]) -> PartialRotation {
    if let Ok(p) = PartialRotation::decode(raw) {
        return p;
    }
    let f = FundedRotation::decode(raw).unwrap();
    PartialRotation {
        unsigned: f.unsigned,
        authorize: Some(f.authorize),
        possession: Some(f.possession),
        authority_funding: f.authority_funding,
        sponsor_funding: f.sponsor_funding,
    }
}
fn verify(tx: &Transaction, h: &Harness) -> Result<(), mutiny_consensus_v8::transactions::TxError> {
    let none = BTreeSet::new();
    let view = h.view(&none);
    let history = mutiny_consensus_v8::evidence_history_v2::History::default();
    tx.verify(
        &Inclusion {
            parent: view.anchor(),
            history: &history,
        },
        view.state(),
    )
    .map(|_| ())
}
fn held_at(state: &mutiny_consensus_v8::execution::State, owner: Hash) -> u64 {
    state
        .coins
        .values()
        .filter(|coin| !coin.coinbase && coin.output.owner == owner)
        .map(|coin| coin.output.atoms)
        .sum()
}

#[test]
fn rotation_end_to_end_then_the_old_key_is_refused_and_the_new_key_spends() {
    let key = wallet_key();
    let me = identity_of(&key);
    let authority = address_of(&key);
    let new = new_key("w2-e2e-new-gen2");
    let new_descriptor = new.public().descriptor(2).unwrap();
    let new_address = new.public().address_id(2).unwrap();
    let recipient = address_of(&other_key());
    let funding = Funding::plain(0xa1, authority, 5_000_000);
    let kept = Funding::plain(0xa2, authority, 2_000_000);
    let mut h = Harness::new("e2e-rot", 1_200_000, &[funding.clone(), kept.clone()]);
    let none = BTreeSet::new();

    // ---- plan, review, approve, authorize with both keys
    let signed = {
        let view = h.view(&none);
        assert_eq!(view.class(), ChainClass::TestValue);
        let planned = plan(&rotate(&new, 2, FeeSource::RotatingAuthority), &view, &me).unwrap();
        let mut expected = vec![funding.point.clone(), rotation_resource(&authority)];
        expected.sort();
        assert_eq!(
            planned.inputs(),
            expected.as_slice(),
            "the largest coin and the rotation slot"
        );
        let reviewed = review(&planned, &view).unwrap();
        assert!(reviewed.render_text().contains("TEST-VALUE chain"));
        assert_eq!(reviewed.destinations()[0].address, new_address);
        assert_eq!(reviewed.destinations_needing_check(), vec![0]);
        assert!(reviewed.acknowledgements().contains(&AckKind::KeyLoss));
        assert!(reviewed.requires_phrase());
        assert_eq!(
            reviewed.fee().size_bytes,
            Some(
                mutiny_consensus_v8::funded_rotation_v2::signed_len(
                    &partial(&planned.objects()[0].bytes).unsigned
                )
                .unwrap() as u64
            )
        );
        let session =
            RotationSigner::for_test(wallet_key(), me.clone(), new_key("w2-e2e-new-gen2")).unwrap();
        let signed = session
            .authorize(planned, approve(&reviewed, &view), &view)
            .unwrap();
        // The signed bytes explain to the reviewed digest (the digest binds the unsigned form).
        assert_eq!(
            explain(signed.bytes(), &view, &me).unwrap().binding(),
            reviewed.binding()
        );
        signed
    };
    assert!(signed.is_complete());
    assert_eq!(signed.kind(), OperationKind::WalletRotation);

    // ---- independent verification through the PUBLIC consensus API
    let transaction = Transaction::decode(signed.bytes()).unwrap();
    assert_eq!(transaction.id().unwrap(), signed.id());
    let network_fee = fee(&transaction);
    assert_eq!(
        network_fee,
        signed.bytes().len() as u64,
        "the network_fee is exactly the signed size of the whole envelope"
    );
    verify(&transaction, &h)
        .map(|_| ())
        .expect("Transaction::verify accepts the wallet's rotation");

    // ---- the outbox reserves the coin AND the authority's rotation slot
    let mut outbox = MemoryOutbox::new();
    {
        let view = h.view(&none);
        assert_eq!(outbox.commit(&signed, &view).unwrap(), signed.id());
    }
    let reserved = outbox.reserved().unwrap();
    assert_eq!(
        reserved,
        BTreeSet::from([funding.point.clone(), rotation_resource(&authority)])
    );
    {
        // A second rotation of the same authority is refused while this one is pending.
        let view = h.view(&reserved);
        assert_eq!(
            plan(
                &rotate(&new_key("w2-e2e-other"), 2, FeeSource::RotatingAuthority),
                &view,
                &me
            )
            .unwrap_err(),
            Refusal::RotationPending
        );
    }

    // ---- the node path; consensus also holds one pending rotation per authority
    h.admit(&transaction)
        .expect("the hybrid mempool admits the wallet's rotation");
    let competing = hand_bundle(
        &h,
        &key,
        1,
        authority,
        &new_key("w2-e2e-other"),
        kept.point.clone(),
        12_000,
        vec![Output {
            owner: authority,
            atoms: 2_000_000 - 12_000,
        }],
    );
    verify(&competing, &h)
        .map(|_| ())
        .expect("the competing rotation is valid by itself");
    assert!(
        h.admit(&competing).is_err(),
        "the mempool refuses a second pending rotation of the same authority"
    );
    assert_eq!(
        h.pool_reserved(),
        BTreeSet::from([funding.point.clone()]),
        "the pool reserves coins only; the rotation slot is the outbox's resource key"
    );
    assert_eq!(h.assemble_only(), vec![signed.bytes().to_vec()]);
    let after = h.step();
    assert_eq!(h.height(), 1);

    // ---- verified state: generation 2 with the new descriptor; old addresses keep their coins
    assert_eq!(
        after.wallets.current(authority).unwrap(),
        new_descriptor.as_slice()
    );
    assert!(
        after.coins.contains_key(&kept.point),
        "the old address keeps its coin"
    );
    assert!(after.wallets.authorize(authority, &new_descriptor).is_ok());
    assert!(
        after
            .wallets
            .authorize(authority, &descriptor_of(&key, 1))
            .is_err(),
        "the old key lost its authority over the old address"
    );
    assert!(
        after
            .wallets
            .authorize(new_address, &new_descriptor)
            .is_ok()
    );
    let change = &after.coins[&OutPoint {
        transaction: signed.id(),
        index: 0,
    }];
    assert_eq!(change.output.owner, new_address);
    assert_eq!(change.output.atoms, 5_000_000 - network_fee);
    let reward: u64 = after
        .coins
        .values()
        .filter(|coin| coin.coinbase)
        .map(|coin| coin.output.atoms)
        .sum();
    assert_eq!(
        reward,
        100_000_000 + network_fee,
        "the network_fee went to the block producer"
    );

    // ---- reconciliation from verified state: the index, and without it the output coin
    {
        let confirmations = h.confirmations();
        let view = h.view(&none).with_confirmations(&confirmations);
        assert_eq!(outbox.reconcile(&view).unwrap().confirmed, 1);
    }
    assert_eq!(
        outbox.get(&signed.id()).unwrap().unwrap().status,
        OutboxStatus::Confirmed(1)
    );
    assert!(
        outbox.reserved().unwrap().is_empty(),
        "the slot and the coin are released"
    );
    {
        let view = h.view(&none);
        // The included rotation is stale now: it can never be queued again.
        assert_eq!(
            MemoryOutbox::new().commit(&signed, &view).unwrap_err(),
            Refusal::StaleAuthority
        );
        // The default Harness view carries own Genesis replay. The explicit missing-index
        // negative uses the SAME canonical state, with no injected confirmation source.
        let record = outbox.get(&signed.id()).unwrap().unwrap();
        assert_eq!(
            mutiny_wallet_core_v8::outbox::settle(&record, &view).unwrap(),
            Settlement::Confirmed(1)
        );
        let without_index = ChainView::new(h.head(), h.state(), &none);
        assert_eq!(
            mutiny_wallet_core_v8::outbox::settle(&record, &without_index).unwrap(),
            Settlement::InputsSpent
        );
    }

    // ---- the old key is refused: by the wallet ...
    {
        let view = h.view(&none);
        assert_eq!(
            me.check_current(&view).unwrap_err(),
            Refusal::StaleAuthority
        );
        assert_eq!(
            plan(&pay(recipient, 1_000), &view, &me).unwrap_err(),
            Refusal::StaleAuthority
        );
        assert_eq!(
            plan(
                &rotate(&new_key("w2-e2e-other"), 2, FeeSource::RotatingAuthority),
                &view,
                &me
            )
            .unwrap_err(),
            Refusal::StaleAuthority
        );
    }
    // ... and by consensus: a payment signed by the old key fails admission and block execution.
    let old_spend = h.hand_signed_transfer(
        &key,
        kept.point.clone(),
        4_000,
        &[(recipient, 2_000_000 - 4_000)],
    );
    assert!(h.admit(&old_spend).is_err(), "the pool refuses the old key");
    assert!(
        h.execute_as_block(vec![old_spend.encode().unwrap()])
            .is_err(),
        "block execution refuses the old key"
    );

    // ---- the new key spends the OLD address's coin (and the change at the new address)
    let me2 = SignerIdentity::from_public(new.public(), 2, Some(authority)).unwrap();
    let paid = {
        let view = h.view(&none);
        me2.check_current(&view).unwrap();
        let planned = plan(&pay(recipient, 6_000_000), &view, &me2).unwrap();
        assert!(
            planned.inputs().contains(&kept.point),
            "an old-address coin"
        );
        let signer = KeySigner::new_rotated(
            new_key("w2-e2e-new-gen2"),
            2,
            authority,
            SigningGate::test_value().unwrap(),
        )
        .unwrap();
        let paid = flow::sign(planned, &signer, &view).unwrap();
        verify(&Transaction::decode(paid.bytes()).unwrap(), &h)
            .map(|_| ())
            .expect("consensus accepts the new key over the old address");
        paid
    };
    h.admit(&Transaction::decode(paid.bytes()).unwrap())
        .unwrap();
    let after_payment = h.step();
    assert!(!after_payment.coins.contains_key(&kept.point));
    assert_eq!(held_at(&after_payment, recipient), 6_000_000);

    // ---- a second rotation: generation 2 -> 3
    let new3 = new_key("w2-e2e-new-gen3");
    let descriptor3 = new3.public().descriptor(3).unwrap();
    let rotated_again = {
        let view = h.view(&none);
        let planned = plan(&rotate(&new3, 3, FeeSource::RotatingAuthority), &view, &me2).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert!(
            reviewed
                .conditions()
                .iter()
                .any(|c| c.label == "Key generation"
                    && c.detail == "from generation 2 (current key) to generation 3 (new key)")
        );
        let session =
            RotationSigner::for_test(new_key("w2-e2e-new-gen2"), me2.clone(), new3).unwrap();
        session
            .authorize(planned, approve(&reviewed, &view), &view)
            .unwrap()
    };
    h.admit(&Transaction::decode(rotated_again.bytes()).unwrap())
        .unwrap();
    let after_second = h.step();
    assert_eq!(
        after_second.wallets.current(authority).unwrap(),
        descriptor3.as_slice()
    );
    // Every earlier address of the authority now resolves to generation 3 only.
    for address in [authority, new_address] {
        assert!(
            after_second
                .wallets
                .authorize(address, &descriptor3)
                .is_ok()
        );
        assert!(
            after_second
                .wallets
                .authorize(address, &new_descriptor)
                .is_err()
        );
    }
    {
        let view = h.view(&none);
        assert_eq!(
            me2.check_current(&view).unwrap_err(),
            Refusal::StaleAuthority
        );
    }
    h.finish();
}

#[test]
fn a_rotation_paid_by_another_wallet_round_trips_as_partial_approvals_into_a_block() {
    let key = wallet_key();
    let me = identity_of(&key);
    let authority = address_of(&key);
    let payer_key = other_key();
    let payer = identity_of(&payer_key);
    let payer_address = address_of(&payer_key);
    let new = new_key("w2-e2e-cofunded-new");
    let payer_coin = Funding::plain(0xb1, payer_address, 3_000_000);
    // The rotating wallet holds nothing at all (as in the D2 rehearsal, another wallet pays).
    let mut h = Harness::new(
        "e2e-rot-cofund",
        1_200_000,
        std::slice::from_ref(&payer_coin),
    );
    let none = BTreeSet::new();
    let mut outbox = MemoryOutbox::new();

    // 1. The rotating wallet plans, reviews and signs ITS part: the authorization and the possession.
    let (part_rotation, digest, context) = {
        let view = h.view(&none);
        let planned = plan(
            &rotate(&new, 2, FeeSource::OtherWallet(payer.clone())),
            &view,
            &me,
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert_eq!(reviewed.fee().payer, FeePayer::Counterparty(payer_address));
        let session =
            RotationSigner::for_test(wallet_key(), me.clone(), new_key("w2-e2e-cofunded-new"))
                .unwrap();
        let part = session
            .authorize(planned, approve(&reviewed, &view), &view)
            .unwrap();
        // Queued locally: the part holds the authority's rotation slot (and the payer's coin).
        outbox.commit(&part, &view).unwrap();
        (part, reviewed.binding(), view.context())
    };
    assert!(!part_rotation.is_complete());
    assert_eq!(
        part_rotation.missing(),
        &[Requirement {
            slot: Slot::Input(1),
            signer: RequiredSigner::Wallet(payer_address),
            status: RequirementStatus::Counterparty,
        }]
    );
    assert!(
        outbox
            .reserved()
            .unwrap()
            .contains(&rotation_resource(&authority))
    );

    // 2. Exported as a public container (file or QR), imported by the payer.
    let exported = PartialApproval::from_signed(&part_rotation, context)
        .unwrap()
        .export()
        .unwrap();
    let imported = PartialApproval::import(&exported).unwrap();
    assert_eq!(imported.kind(), OperationKind::WalletRotation);

    // 3. The payer reviews (same digest), adopts and signs its funding input.
    let part_funding = {
        let view = h.view(&none);
        let seen = imported.explain_for(&view, &payer).unwrap();
        assert_eq!(seen.binding(), digest, "both wallets review the same bytes");
        assert_eq!(seen.title(), "Pay the fee of a wallet key rotation");
        assert_eq!(seen.fee().payer, FeePayer::ThisWallet);
        assert!(seen.warnings().iter().any(|w| w.code == "FUNDING_BOUND"));
        assert!(
            seen.authorizations()[..2]
                .iter()
                .all(|r| r.status == RequirementStatus::Provided),
            "the rotation's signatures are present and verify"
        );
        let adopted = imported.adopt_for(&view, &payer).unwrap();
        assert_eq!(review(&adopted, &view).unwrap().binding(), digest);
        let signer = KeySigner::for_test(other_key()).unwrap();
        flow::sign(adopted, &signer, &view).unwrap()
    };
    assert!(part_funding.is_complete());
    assert!(
        part_funding.missing().is_empty(),
        "payer adoption retains the existing verified authority proofs"
    );

    // 4. The two parts combine (in either order) into one complete, verified rotation.
    let complete = {
        let view = h.view(&none);
        let complete = combine(&[part_rotation.bytes(), part_funding.bytes()], &view).unwrap();
        let again = combine(&[part_funding.bytes(), part_rotation.bytes()], &view).unwrap();
        assert_eq!(complete.bytes(), again.bytes());
        assert_eq!(
            outbox
                .replace_partial(&part_rotation.id(), &complete, &view)
                .unwrap(),
            complete.id()
        );
        complete
    };
    assert!(complete.is_complete());
    assert_ne!(
        complete.id(),
        part_rotation.id(),
        "partial exchange metadata id differs from canonical unsigned operation id"
    );
    let transaction = Transaction::decode(complete.bytes()).unwrap();
    verify(&transaction, &h)
        .map(|_| ())
        .expect("consensus accepts the co-funded rotation");
    // The rotating part alone is not a block transaction; the payer-completed object is.
    assert!(Transaction::decode(part_rotation.bytes()).is_err());
    assert!(verify(&Transaction::decode(part_funding.bytes()).unwrap(), &h).is_ok());
    // 5. Into a real block; the queued part settles from verified state (same identifier).
    h.admit(&transaction).unwrap();
    let after = h.step();
    assert_eq!(
        after.wallets.current(authority).unwrap(),
        new.public().descriptor(2).unwrap().as_slice()
    );
    assert!(!after.coins.contains_key(&payer_coin.point));
    assert_eq!(
        held_at(&after, payer_address),
        3_000_000 - fee(&transaction),
        "the payer paid the fee and kept its change"
    );
    {
        let confirmations = h.confirmations();
        let view = h.view(&none).with_confirmations(&confirmations);
        let report = outbox.reconcile(&view).unwrap();
        assert_eq!(
            report.confirmed, 1,
            "the payer's change coin of this transaction proves it"
        );
        assert!(outbox.reserved().unwrap().is_empty());
    }
    h.finish();
}

#[test]
fn the_treasury_authority_rotates_under_the_treasury_profile_and_the_reserve_rule_matches_consensus()
 {
    let treasury = treasury_wallet_key();
    let authority = address_of(&treasury);
    let mut h = Harness::new("e2e-rot-treasury", 1_200_000, &[]);
    let after_award = h.step_at(131_072);
    assert_eq!(
        after_award.dividends.reserved(),
        600_000,
        "half of the backing is reserved"
    );
    let new = new_key("w2-e2e-treasury-new");
    let new_address = new.public().address_id(2).unwrap();
    let ordinary = identity_of(&treasury);
    let profiled = ordinary
        .clone()
        .with_treasury_roles_for_test(TreasuryRoles {
            authority: true,
            destination_of: None,
        });
    let none = BTreeSet::new();

    // An ordinary profile never rotates the Treasury.
    {
        let view = h.view(&none);
        assert_eq!(
            plan(
                &rotate(&new, 2, FeeSource::RotatingAuthority),
                &view,
                &ordinary
            )
            .unwrap_err(),
            Refusal::TreasuryProfileRequired
        );
    }

    // Differential reserve rule: a Treasury rotation whose funding takes part of the Treasury away.
    // Since the review fixes a rotation's funding pays nobody but the fee (an output to a stranger
    // is `ROTATION_FUNDING`, below), so the fee is what leaves here. Backing after the block = the
    // change at the NEW address (a Treasury address from inclusion).
    let shaped = |change: u64| {
        hand_bundle(
            &h,
            &treasury,
            1,
            authority,
            &new,
            h.treasury_coin(),
            1_200_000 - change,
            vec![Output {
                owner: new_address,
                atoms: change,
            }],
        )
    };
    {
        let view = h.view(&none);
        let stranger = hand_bundle(
            &h,
            &treasury,
            1,
            authority,
            &new,
            h.treasury_coin(),
            12_000,
            vec![
                Output {
                    owner: new_address,
                    atoms: 600_000,
                },
                Output {
                    owner: address_of(&other_key()),
                    atoms: 588_000,
                },
            ],
        );
        let raw = PartialRotation::new(partial(&stranger.encode().unwrap()).unsigned)
            .encode()
            .unwrap();
        assert_eq!(
            explain(&raw, &view, &profiled).unwrap_err(),
            Refusal::RotationFunding(rotation::REASON_OUTPUT_NOT_FUNDER)
        );
    }
    let unsigned = |transaction: &Transaction| {
        PartialRotation::new(partial(&transaction.encode().unwrap()).unsigned)
            .encode()
            .unwrap()
    };
    let below = shaped(600_000 - 1);
    let exact = shaped(600_000);
    {
        let view = h.view(&none);
        assert_eq!(
            explain(&unsigned(&below), &view, &profiled).unwrap_err(),
            Refusal::ReserveBackingViolation {
                reserved: 600_000,
                backing_after: 599_999
            }
        );
        assert!(explain(&unsigned(&exact), &view, &profiled).is_ok());
    }
    assert!(
        h.execute_as_block(vec![below.encode().unwrap()]).is_err(),
        "consensus rejects a rotation that leaves the reserve unbacked"
    );
    assert!(
        h.execute_as_block(vec![exact.encode().unwrap()]).is_ok(),
        "consensus counts the new address as Treasury backing"
    );

    // The wallet's own Treasury rotation, approved with the Treasury acknowledgement.
    let signed = {
        let view = h.view(&none);
        let planned = plan(
            &rotate(&new, 2, FeeSource::RotatingAuthority),
            &view,
            &profiled,
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert_eq!(reviewed.title(), "Rotate the Treasury wallet key");
        assert!(
            reviewed
                .acknowledgements()
                .contains(&AckKind::TreasuryAuthority)
        );
        for code in ["TREASURY_ROTATION", "TREASURY_FUNDS", "KEY_ROTATION"] {
            assert!(reviewed.warnings().iter().any(|w| w.code == code), "{code}");
        }
        assert!(
            reviewed
                .render_text()
                .contains("Bitcoin custody is separate and untouched")
        );
        // A session declared for the ordinary profile is not the plan's signer.
        let ordinary_session = RotationSigner::for_test(
            treasury_wallet_key(),
            ordinary.clone(),
            new_key("w2-e2e-treasury-new"),
        )
        .unwrap();
        assert_eq!(
            ordinary_session
                .authorize(planned.clone(), approve(&reviewed, &view), &view)
                .unwrap_err(),
            Refusal::NotRequiredSigner(Slot::RotationAuthorization)
        );
        let session = RotationSigner::new(
            treasury_wallet_key(),
            profiled.clone(),
            new_key("w2-e2e-treasury-new"),
            SigningGate::test_value().unwrap(),
            DEFAULT_IDLE_LIMIT,
        )
        .unwrap();
        session
            .authorize(planned, approve(&reviewed, &view), &view)
            .unwrap()
    };
    h.admit(&Transaction::decode(signed.bytes()).unwrap())
        .unwrap();
    let after = h.step();
    assert_eq!(
        after.wallets.current(authority).unwrap(),
        new.public().descriptor(2).unwrap().as_slice()
    );
    assert_eq!(
        after.dividends.reserved(),
        600_000,
        "a rotation alone never changes a reserve"
    );
    assert!(after.treasury_owner_set().contains(&new_address));
    let backing = DividendState::backing(&after.coins, &after.treasury_owner_set()).unwrap();
    assert_eq!(
        backing,
        1_200_000 - fee(&Transaction::decode(signed.bytes()).unwrap())
    );
    assert_eq!(
        after.dividends.treasury().unwrap().descriptor(),
        descriptor_of(&treasury, 1).as_slice(),
        "the Genesis Treasury record never changes"
    );
    h.finish();
}

#[test]
fn atomic_rotation_signatures_bind_funding_and_cannot_be_reused_as_plain_transfers() {
    let key = wallet_key();
    let me = identity_of(&key);
    let authority = address_of(&key);
    let new = new_key("w2-e2e-bound-new");
    let own_coin = Funding::plain(0xc1, authority, 4_000_000);
    let payer_coin = Funding::plain(0xc2, address_of(&other_key()), 3_000_000);
    let mut h = Harness::new(
        "e2e-rot-bound",
        1_200_000,
        &[own_coin.clone(), payer_coin.clone()],
    );
    let none = BTreeSet::new();
    let signed = {
        let view = h.view(&none);
        let planned = plan(&rotate(&new, 2, FeeSource::RotatingAuthority), &view, &me).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        RotationSigner::for_test(wallet_key(), me.clone(), new_key("w2-e2e-bound-new"))
            .unwrap()
            .authorize(planned, approve(&reviewed, &view), &view)
            .unwrap()
    };
    let original = FundedRotation::decode(signed.bytes()).unwrap();
    assert!(verify(&Transaction::FundedRotation(original.clone()), &h).is_ok());
    let mut changed = original.clone();
    changed.unsigned.fee += 1;
    changed.unsigned.outputs[0].atoms -= 1;
    let mut changed_input = original.clone();
    changed_input.unsigned.inputs[0].0 = payer_coin.point.clone();
    let mut changed_destination = original.clone();
    changed_destination.unsigned.outputs[0].owner = authority;
    let mut changed_window = original.clone();
    changed_window.unsigned.envelope.last_height -= 1;
    for altered in [changed, changed_input, changed_destination, changed_window] {
        assert!(verify(&Transaction::FundedRotation(altered.clone()), &h).is_err());
        assert!(h.execute_as_block(vec![altered.encode().unwrap()]).is_err());
    }
    // Funding signatures use the existing Transaction domain with a distinct commitment payload.
    // Copying a genuine funding signature into a standalone Transfer never authorizes that spend.
    let Transaction::Transfer(mut detached) = h.hand_signed_transfer(
        &key,
        own_coin.point.clone(),
        original.unsigned.fee,
        &[(authority, 4_000_000 - original.unsigned.fee)],
    ) else {
        panic!("plain transfer")
    };
    detached.inputs[0].signature = original.authority_funding.clone().unwrap();
    assert!(verify(&Transaction::Transfer(detached.clone()), &h).is_err());
    assert!(
        h.execute_as_block(vec![Transaction::Transfer(detached).encode().unwrap()])
            .is_err()
    );
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &h.view(&none)).unwrap();
    h.admit(&Transaction::decode(signed.bytes()).unwrap())
        .unwrap();
    h.step();
    h = h.restart();
    let confirmations = h.confirmations();
    let view = h.view(&none).with_confirmations(&confirmations);
    assert_eq!(outbox.reconcile(&view).unwrap().confirmed, 1);
    assert!(outbox.reserved().unwrap().is_empty());
    h.finish();
}
