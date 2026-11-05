//! Conditional MUT funding end to end on a REAL consensus chain (NATIVE, TEST-VALUE): a hash lock
//! planned and signed by the sender as a PARTIAL operation, exported, reviewed and co-signed by the
//! recipient through `explain`/`adopt`, completed with the maker's fill signature, verified through
//! `trading_v1::prepare_batch`, queued, included in a block built by the production assembler and
//! certified with real hybrid votes, discovered and reconciled from verified state; then a claim
//! before the refund height, a claim refused AT the refund height, a refund refused before it and
//! accepted from it (also through the one permitted cancellation), a second lock of a consumed
//! offer refused by the wallet and by consensus, and a lock funded by several coins in native input
//! order. The maker is played by the test (the wallet never creates offers, Q7).
#[path = "support/conditional_rig.rs"]
mod conditional_rig;
#[path = "support/conditional_kit.rs"]
mod kit;

use conditional_rig::chain::*;
use mutiny_consensus_v8::{
    trading_v1::{
        self, Action, Meta, NativeError, NativeRecord, Operation, Strikes, native_input_id,
    },
    transactions::{OutPoint, Output},
};
use mutiny_wallet_core_v8::{
    discovery::locks::{self, Finality, LockPhase},
    ops::conditional::{self, MemoryPreimageStore, PreimageStore},
    *,
};
use std::collections::BTreeSet;

fn point(tag: u8) -> OutPoint {
    OutPoint {
        transaction: [tag; 32],
        index: 0,
    }
}

/// Plan, review (with every acknowledgement and the typed phrase) and authorize.
fn sign_plan(
    planned: OperationPlan,
    signer: &KeySigner,
    view: &ChainView<'_>,
) -> (SignedOperation, Review) {
    let reviewed = review(&planned, view).unwrap();
    let approval = kit::approve(&reviewed, view);
    (signer.authorize(planned, approval, view).unwrap(), reviewed)
}

/// The whole multi-party funding of one lock at the chain's current head (`kit::fund_lock`).
#[allow(clippy::too_many_arguments)]
fn fund_lock(
    chain: &TradeChain,
    sender_signer: &KeySigner,
    recipient_signer: &KeySigner,
    maker: &mutiny_crypto_v2::HybridKey,
    offer: &mutiny_consensus_v8::trading_v1::SignedOffer,
    condition: [u8; 32],
    amount: u64,
    refund_height: u64,
) -> kit::Lock {
    kit::fund_lock(
        &chain.view(&BTreeSet::new()),
        sender_signer,
        recipient_signer,
        maker,
        offer,
        condition,
        amount,
        refund_height,
    )
}

#[test]
fn hash_lock_partial_approvals_maker_fill_block_discovery_then_claim_before_the_refund_height() {
    let (sender_key, recipient_key) = (wallet_key(), other_key());
    let (sender, recipient) = (address_of(&sender_key), address_of(&recipient_key));
    let mut chain = TradeChain::new(
        "w5a-e2e-claim",
        &[
            (0xa1, sender, 3_000_000),
            (0xa2, sender, 2_000_000),
            (0xb1, recipient, 200_000),
        ],
    );
    let (me, them) = (identity_of(&sender_key), identity_of(&recipient_key));
    let sender_signer = KeySigner::for_test(wallet_key()).unwrap();
    let recipient_signer = KeySigner::for_test(other_key()).unwrap();
    let maker = other_key();
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&chain.anchor()),
        1,
        500,
        1_000_000,
        1,
        0x31,
    );
    let offer_id = offer.body.id().unwrap();
    let maker_id = offer.body.maker().unwrap();
    // The recipient makes the secret (fresh OS randomness); only its hash travels to the sender.
    let mut recipient_store = MemoryPreimageStore::new();
    let condition = recipient_store.create().unwrap();
    let none = BTreeSet::new();
    let mut sender_outbox = MemoryOutbox::new();

    // ---- the sender plans and signs its own approval: a PARTIAL operation
    let (sender_partial, sender_digest) = {
        let view = chain.view(&none);
        let request = HashLockRequest::new(
            Blob::new(kit::offer_bytes(&offer)),
            recipient,
            1_000_000,
            condition,
            6,
        )
        .with_trade([0x21; 32])
        .with_contract([0x22; 32]);
        let planned = plan(&OperationRequest::HashLock(request), &view, &me).unwrap();
        assert_eq!(planned.kind(), OperationKind::HashLock);
        assert_eq!(
            planned.inputs(),
            &[point(0xa1)],
            "the largest coin of the sender address"
        );
        assert_eq!(
            (planned.validity().created, planned.validity().expiry),
            (1, 4),
            "the window ends two blocks before the refund height, so a claim always has a block"
        );
        let reviewed = review(&planned, &view).unwrap();
        assert!(reviewed.requires_phrase(), "a hash lock is high risk");
        let locked: Vec<_> = reviewed
            .destinations()
            .iter()
            .filter(|d| d.role == DestinationRole::LockedOutput)
            .collect();
        assert_eq!(locked.len(), 1);
        assert_eq!(
            (locked[0].address, locked[0].atoms, locked[0].label),
            (recipient, 1_000_000, AddressLabel::External)
        );
        assert_eq!(reviewed.fee().payer, FeePayer::ThisWallet);
        let size = reviewed.fee().size_bytes.unwrap();
        assert!(reviewed.fee().atoms >= size.max(240));
        assert_eq!(
            reviewed.fee().atoms + reviewed.returned() + 1_000_000,
            3_000_000,
            "inputs equal principal plus change plus fee"
        );
        for ack in [
            AckKind::Destination,
            AckKind::Amount,
            AckKind::Fee,
            AckKind::Conditions,
            AckKind::Irreversible,
            AckKind::ExternalEvidence,
        ] {
            assert!(reviewed.acknowledgements().contains(&ack), "{ack:?}");
        }
        let text = reviewed.render_text();
        assert!(text.contains(&hex::encode(condition)));
        assert!(text.contains(&hex::encode(offer_id)));
        assert!(text.contains("It is final only when a certified block"));
        let digest = reviewed.binding();
        let approval = kit::approve(&reviewed, &view);
        (
            sender_signer.authorize(planned, approval, &view).unwrap(),
            digest,
        )
    };
    assert!(!sender_partial.is_complete());
    assert_eq!(
        sender_partial.missing(),
        &[
            Requirement {
                slot: Slot::Approval(1),
                signer: RequiredSigner::Wallet(recipient),
                status: RequirementStatus::Counterparty,
            },
            Requirement {
                slot: Slot::FillSignature,
                signer: RequiredSigner::Maker(maker_id),
                status: RequirementStatus::Maker,
            },
        ]
    );
    let wire = kit::wire(sender_partial.bytes());
    assert!(
        wire.operation
            .meta
            .inputs
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    for (input, id) in wire.inputs.iter().zip(&wire.operation.meta.inputs) {
        assert_eq!(native_input_id(input), *id);
    }

    // ---- the partial is queued: it reserves its coin AND the offer across plans
    {
        let view = chain.view(&none);
        sender_outbox.commit(&sender_partial, &view).unwrap();
    }
    let reserved = sender_outbox.reserved().unwrap();
    assert_eq!(
        reserved,
        BTreeSet::from([
            point(0xa1),
            resource_key(conditional::OFFER_NAMESPACE, &offer_id)
        ])
    );
    {
        let view = chain.view(&reserved);
        let again = HashLockRequest::new(
            Blob::new(kit::offer_bytes(&offer)),
            recipient,
            1_000_000,
            condition,
            6,
        );
        assert_eq!(
            plan(&OperationRequest::HashLock(again), &view, &me).unwrap_err(),
            Refusal::ReservedInput,
            "the same offer cannot be planned twice"
        );
        let paid = plan(
            &OperationRequest::Payment(PaymentRequest::new(recipient, 2_500_000)),
            &view,
            &me,
        )
        .unwrap_err();
        assert!(
            matches!(paid, Refusal::InsufficientFunds { .. }),
            "the reserved coin is not offered again: {paid:?}"
        );
    }

    // ---- export, then the counterparty reviews (explain) and signs its own approval (adopt)
    let container = {
        let view = chain.view(&none);
        let raw = PartialApproval::from_signed(&sender_partial, view.context())
            .unwrap()
            .export()
            .unwrap();
        PartialApproval::import(&raw).unwrap()
    };
    let recipient_partial = {
        let view = chain.view(&none);
        let seen = container.explain_for(&view, &them).unwrap();
        assert_eq!(seen.binding(), sender_digest, "one operation, one digest");
        assert_eq!(seen.title(), "Approve a hash lock for this wallet");
        assert_eq!(seen.fee().payer, FeePayer::Counterparty(sender));
        let statuses: Vec<RequirementStatus> =
            seen.authorizations().iter().map(|r| r.status).collect();
        assert_eq!(
            statuses,
            [
                RequirementStatus::Provided,
                RequirementStatus::ThisWallet,
                RequirementStatus::ThisWallet
            ]
        );
        let adopted = container.adopt_for(&view, &them).unwrap();
        let (signed, reviewed) = sign_plan(adopted, &recipient_signer, &view);
        assert_eq!(reviewed.binding(), sender_digest);
        signed
    };
    assert!(!recipient_partial.is_complete());
    assert_eq!(
        recipient_partial.missing(),
        &[Requirement {
            slot: Slot::Approval(0),
            signer: RequiredSigner::Wallet(sender),
            status: RequirementStatus::Counterparty,
        }],
        "adoption signs the recipient and maker fill but leaves the sender's separately held approval"
    );
    let recipient_wire = kit::wire(recipient_partial.bytes());
    assert_eq!(recipient_wire.operation.approvals.len(), 1);
    assert_eq!(recipient_wire.operation.approvals[0].slot, 1);
    recipient_wire
        .operation
        .verify_offer(chain.height() + 1)
        .unwrap();

    // ---- an independently supplied maker fill covers the same body and completes idempotently
    let fill = kit::fill_for(sender_partial.bytes(), &offer, &maker);
    let complete = {
        let view = chain.view(&none);
        let complete = conditional::complete(
            &[sender_partial.bytes(), recipient_partial.bytes()],
            Some(&fill),
            &view,
        )
        .unwrap();
        // prepare_batch parity: consensus accepts exactly these bytes as the next block's trade.
        kit::consensus_in(&view, complete.bytes()).unwrap();
        complete
    };
    assert!(complete.is_complete());
    let operation_id = kit::wire(complete.bytes()).operation.id().unwrap();
    assert_eq!(complete.id(), operation_id);
    assert_ne!(
        sender_partial.id(),
        operation_id,
        "a partial has its own id"
    );
    // The partial makes way for the complete operation in the outbox.
    sender_outbox.forget(&sender_partial.id()).unwrap();
    {
        let reserved = sender_outbox.reserved().unwrap();
        assert!(reserved.is_empty());
        let view = chain.view(&reserved);
        assert_eq!(
            sender_outbox.commit(&complete, &view).unwrap(),
            operation_id
        );
        assert_eq!(
            locks::finality(&view, complete.bytes()).unwrap(),
            Finality::NotFinal,
            "queued is not final"
        );
    }

    // ---- a real certified block includes the lock
    let after = chain.step_with(&[complete.bytes().to_vec()]);
    assert_eq!(chain.height(), 1);
    let lock_id = kit::wire(complete.bytes()).operation.output_id(0).unwrap();
    let lock = trading_v1::locked(&after, lock_id).unwrap();
    assert_eq!(
        (
            lock.sender,
            lock.recipient,
            lock.amount,
            lock.created_height
        ),
        (sender, recipient, Strikes(1_000_000), 1)
    );
    assert!(
        !after.coins.contains_key(&point(0xa1)),
        "the funding coin is spent"
    );
    {
        let view = chain.view(&none);
        assert_eq!(
            locks::finality(&view, complete.bytes()).unwrap(),
            Finality::Final {
                height: 1,
                lock: Some(lock_id),
                lock_open: true
            }
        );
        // Host-adapter negative: keep the actual own-Genesis replay source, but deliberately
        // corrupt the accompanying receipt height. This state is NOT a valid canonical state.
        let mut mismatched = after.clone();
        let receipt_key = trading_v1::record_key(2, operation_id);
        let (found, mut receipt) =
            NativeRecord::decode(&mismatched.protocol_records[&receipt_key]).unwrap();
        assert_eq!(found, operation_id);
        let NativeRecord::Applied { height, .. } = &mut receipt else {
            panic!("real inclusion receipt")
        };
        *height += 1;
        mismatched
            .protocol_records
            .insert(receipt_key, receipt.encode(operation_id).unwrap());
        let own = chain.confirmations();
        let hostile = ChainView::new(chain.head(), &mismatched, &none).with_confirmations(&own);
        assert_eq!(
            locks::finality(&hostile, complete.bytes()).unwrap_err(),
            Refusal::Malformed(
                "the receipt height differs from this host's own canonical inclusion"
            )
        );
        // Discovery from verified state: the recipient may claim, the sender waits.
        let theirs = locks::hash_locks(&view, &them).unwrap();
        assert_eq!(theirs.len(), 1);
        assert!(theirs[0].may_claim() && !theirs[0].may_refund());
        assert_eq!(
            theirs[0].phase,
            LockPhase::ClaimWindow {
                last_claim_height: 5
            }
        );
        let mine = locks::hash_locks(&view, &me).unwrap();
        assert!(mine[0].this_wallet_sends && !mine[0].may_refund());
        let report = sender_outbox.reconcile(&view).unwrap();
        assert_eq!(report.confirmed, 1);
        assert_eq!(
            sender_outbox.get(&operation_id).unwrap().unwrap().status,
            OutboxStatus::Confirmed(1)
        );

        // ---- the offer is consumed: a second lock on it is refused by the wallet ...
        let again = HashLockRequest::new(
            Blob::new(kit::offer_bytes(&offer)),
            recipient,
            1_000_000,
            condition,
            8,
        );
        assert_eq!(
            plan(&OperationRequest::HashLock(again), &view, &me).unwrap_err(),
            Refusal::OfferConsumed
        );
        // ... and by consensus (single fill), even with good coins and every signature.
        let second = Operation {
            meta: Meta {
                context: kit::context_of(&chain.anchor()),
                trade: [0x41; 32],
                contract: [0x42; 32],
                generation: 1,
                envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                    first_height: 2,
                    last_height: 4,
                    reference_height: (chain.anchor()).height,
                    reference_block: (chain.anchor()).block,
                    preconditions: Vec::new(),
                },
                fee: Strikes(20_000),
                inputs: vec![native_input_id(&point(0xa2))],
            },
            action: Action::HashLock {
                offer: offer_id,
                maker: maker_id,
                sender,
                recipient,
                amount: Strikes(1_000_000),
                condition,
                refund_height: 8,
                change: Strikes(980_000),
            },
            approvals: vec![],
            offer_proof: None,
        };
        let raw = kit::consensus_signed(
            second,
            vec![point(0xa2)],
            &[(0, &sender_key), (1, &recipient_key)],
            Some((&offer, &maker)),
        );
        assert_eq!(
            kit::consensus_in(&view, &raw).unwrap_err(),
            NativeError::Duplicate
        );
    }

    // ---- the recipient claims before the refund height with its own fee coins
    let mut recipient_outbox = MemoryOutbox::new();
    let claim = {
        let view = chain.view(&none);
        let request = conditional::claim_request(&recipient_store, lock_id, &view).unwrap();
        let planned = plan(&OperationRequest::ConditionalClaim(request), &view, &them).unwrap();
        let (signed, reviewed) = sign_plan(planned, &recipient_signer, &view);
        assert!(reviewed.requires_phrase(), "a claim discloses the preimage");
        for ack in [AckKind::DisclosesPreimage, AckKind::ExternalEvidence] {
            assert!(reviewed.acknowledgements().contains(&ack), "{ack:?}");
        }
        assert!(reviewed.render_text().contains(
            "preimage supplied externally; Bitcoin settlement not verified by this wallet"
        ));
        assert!(signed.is_complete());
        kit::consensus_in(&view, signed.bytes()).unwrap();
        recipient_outbox.commit(&signed, &view).unwrap();
        signed
    };
    let claim_wire = kit::wire(claim.bytes());
    assert_eq!(
        claim_wire.inputs,
        vec![point(0xb1)],
        "the fee comes from separate coins of the recipient address"
    );
    let fee = claim_wire.operation.meta.fee.0;
    let after = chain.step_with(&[claim.bytes().to_vec()]);
    let claim_id = claim_wire.operation.id().unwrap();
    let paid = |index: u32| {
        after.coins[&OutPoint {
            transaction: claim_id,
            index,
        }]
            .output
            .clone()
    };
    assert_eq!(
        paid(0),
        Output {
            owner: recipient,
            atoms: 1_000_000
        },
        "the whole principal"
    );
    assert_eq!(
        paid(1),
        Output {
            owner: recipient,
            atoms: 200_000 - fee
        }
    );
    assert!(
        trading_v1::locked(&after, lock_id).is_err(),
        "the lock is spent"
    );
    {
        let view = chain.view(&none);
        assert_eq!(
            locks::finality(&view, complete.bytes()).unwrap(),
            Finality::Final {
                height: 1,
                lock: Some(lock_id),
                lock_open: false
            }
        );
        assert!(locks::hash_locks(&view, &them).unwrap().is_empty());
        assert_eq!(recipient_outbox.reconcile(&view).unwrap().confirmed, 1);
        assert_eq!(
            recipient_outbox.get(&claim_id).unwrap().unwrap().status,
            OutboxStatus::Confirmed(2)
        );
    }
    chain.finish();
}

#[test]
fn claim_at_the_refund_height_and_refund_before_it_are_refused_and_the_refund_works_from_it() {
    let (sender_key, recipient_key) = (wallet_key(), other_key());
    let (sender, recipient) = (address_of(&sender_key), address_of(&recipient_key));
    let mut chain = TradeChain::new(
        "w5a-e2e-refund",
        &[
            (0xc1, sender, 3_000_000),
            (0xc2, sender, 100_000),
            (0xd1, recipient, 100_000),
        ],
    );
    let (me, them) = (identity_of(&sender_key), identity_of(&recipient_key));
    let sender_signer = KeySigner::for_test(wallet_key()).unwrap();
    let recipient_signer = KeySigner::for_test(other_key()).unwrap();
    let maker = wallet_key();
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&chain.anchor()),
        1,
        500,
        700_000,
        0,
        0x32,
    );
    let mut store = MemoryPreimageStore::new();
    let condition = store.create().unwrap();
    let lock = fund_lock(
        &chain,
        &sender_signer,
        &recipient_signer,
        &maker,
        &offer,
        condition,
        700_000,
        3,
    );
    assert!(lock.complete.is_complete() && !lock.sender_partial.is_complete());
    chain.step_with(&[lock.complete.bytes().to_vec()]);
    let none = BTreeSet::new();
    let context = kit::context_of(&chain.anchor());
    let spend = |parent: mutiny_consensus_v8::anchors::FinalizedAnchor,
                 action: Action,
                 created: u64,
                 expiry: u64,
                 input: u8| Operation {
        meta: Meta {
            context: context.clone(),
            trade: [0x21; 32],
            contract: [0x22; 32],
            generation: 1,
            envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                first_height: created,
                last_height: expiry,
                reference_height: parent.height,
                reference_block: parent.block,
                preconditions: Vec::new(),
            },
            fee: Strikes(10_000),
            inputs: vec![native_input_id(&point(input))],
        },
        action,
        approvals: vec![],
        offer_proof: None,
    };

    // ---- head 1, next block 2 < R = 3: a refund is refused, by the wallet and by consensus
    {
        let view = chain.view(&none);
        assert_eq!(
            plan(
                &OperationRequest::ConditionalRefund(RefundRequest::new(lock.id)),
                &view,
                &me
            )
            .unwrap_err(),
            Refusal::NotYetEligible {
                what: "Refunding this hash lock",
                height: 3
            }
        );
        let early = kit::consensus_signed(
            spend(
                chain.anchor(),
                Action::Refund {
                    output: lock.id,
                    owner: sender,
                    amount: Strikes(700_000),
                    change: Strikes(90_000),
                },
                2,
                10,
                0xc2,
            ),
            vec![point(0xc2)],
            &[(0, &sender_key)],
            None,
        );
        assert_eq!(
            kit::consensus_in(&view, &early).unwrap_err(),
            NativeError::Time
        );
        assert!(locks::hash_locks(&view, &me).unwrap()[0].this_wallet_sends);
    }
    chain.step();

    // ---- head 2, next block 3 == R: a claim is refused, by the wallet and by consensus
    {
        let view = chain.view(&none);
        let request = conditional::claim_request(&store, lock.id, &view).unwrap();
        assert_eq!(
            plan(&OperationRequest::ConditionalClaim(request), &view, &them).unwrap_err(),
            Refusal::WindowClosed {
                expiry: 2,
                next_height: 3
            }
        );
        // The store still holds the preimage: the refusal is the height, not a missing secret.
        assert!(store.preimage(&condition).unwrap().is_some());
        let entry = &locks::hash_locks(&view, &them).unwrap()[0];
        assert!(!entry.may_claim());
        assert_eq!(entry.phase, LockPhase::RefundWindow { since: 3 });
    }

    // ---- the refund: planned directly and through the one permitted cancellation, the same plan
    let refund = {
        let view = chain.view(&none);
        let direct = plan(
            &OperationRequest::ConditionalRefund(RefundRequest::new(lock.id)),
            &view,
            &me,
        )
        .unwrap();
        let cancelled = plan(
            &OperationRequest::Cancel(CancelRequest::new(CancelTarget::HashLockRefund(lock.id))),
            &view,
            &me,
        )
        .unwrap();
        assert_eq!(
            direct.id(),
            cancelled.id(),
            "the cancellation is exactly the refund"
        );
        assert!(locks::hash_locks(&view, &me).unwrap()[0].may_refund());
        let (signed, reviewed) = sign_plan(cancelled, &sender_signer, &view);
        assert!(!reviewed.requires_phrase());
        assert_eq!(reviewed.timing().earliest_height, Some(3));
        assert!(signed.is_complete());
        kit::consensus_in(&view, signed.bytes()).unwrap();
        signed
    };
    let mut outbox = MemoryOutbox::new();
    {
        let view = chain.view(&none);
        outbox.commit(&refund, &view).unwrap();
    }
    let after = chain.step_with(&[refund.bytes().to_vec()]);
    let refund_id = kit::wire(refund.bytes()).operation.id().unwrap();
    assert_eq!(
        after.coins[&OutPoint {
            transaction: refund_id,
            index: 0
        }]
            .output,
        Output {
            owner: sender,
            atoms: 700_000
        },
        "the whole principal returns to the sender"
    );
    assert!(trading_v1::locked(&after, lock.id).is_err());
    {
        let view = chain.view(&none);
        assert_eq!(outbox.reconcile(&view).unwrap().confirmed, 1);
        assert_eq!(
            outbox.get(&refund_id).unwrap().unwrap().status,
            OutboxStatus::Confirmed(3)
        );
        // The claim of a refunded lock is refused by consensus too.
        let late = kit::consensus_signed(
            spend(
                chain.anchor(),
                Action::Claim {
                    output: lock.id,
                    recipient,
                    amount: Strikes(700_000),
                    preimage: [0; 32],
                    change: Strikes(90_000),
                },
                4,
                10,
                0xd1,
            ),
            vec![point(0xd1)],
            &[(0, &recipient_key)],
            None,
        );
        assert_eq!(
            kit::consensus_in(&view, &late).unwrap_err(),
            NativeError::Missing
        );
    }
    chain.finish();
}

#[test]
fn a_claim_built_by_consensus_at_the_refund_height_is_rejected_with_the_time_rule() {
    // The wallet refuses to plan the claim at H == R (above); this pins consensus' side of the same
    // boundary with a claim that carries the right preimage and a valid approval.
    let (sender_key, recipient_key) = (wallet_key(), other_key());
    let (sender, recipient) = (address_of(&sender_key), address_of(&recipient_key));
    let mut chain = TradeChain::new(
        "w5a-e2e-boundary",
        &[(0xe1, sender, 3_000_000), (0xe2, recipient, 100_000)],
    );
    let sender_signer = KeySigner::for_test(wallet_key()).unwrap();
    let recipient_signer = KeySigner::for_test(other_key()).unwrap();
    let maker = other_key();
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&chain.anchor()),
        1,
        500,
        500_000,
        1,
        0x33,
    );
    let preimage = [0x5c; 32];
    let condition = trading_v1::preimage_hash(&preimage);
    let lock = fund_lock(
        &chain,
        &sender_signer,
        &recipient_signer,
        &maker,
        &offer,
        condition,
        500_000,
        3,
    );
    chain.step_with(&[lock.complete.bytes().to_vec()]);
    let parent = chain.anchor();
    let context = kit::context_of(&parent);
    let claim_at = |created: u64| {
        kit::consensus_signed(
            Operation {
                meta: Meta {
                    context: context.clone(),
                    trade: [0x21; 32],
                    contract: [0x22; 32],
                    generation: 1,
                    envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                        first_height: created,
                        last_height: 10,
                        reference_height: parent.height,
                        reference_block: parent.block,
                        preconditions: Vec::new(),
                    },
                    fee: Strikes(10_000),
                    inputs: vec![native_input_id(&point(0xe2))],
                },
                action: Action::Claim {
                    output: lock.id,
                    recipient,
                    amount: Strikes(500_000),
                    preimage,
                    change: Strikes(90_000),
                },
                approvals: vec![],
                offer_proof: None,
            },
            vec![point(0xe2)],
            &[(0, &recipient_key)],
            None,
        )
    };
    let none = BTreeSet::new();
    {
        // Next block 2 < R: consensus accepts the claim.
        let view = chain.view(&none);
        kit::consensus_in(&view, &claim_at(2)).unwrap();
    }
    chain.step();
    {
        // Next block 3 == R: the same claim is outside its window.
        let raw = claim_at(2);
        let history = chain.operation_history(&raw);
        let view = chain.view(&none).with_history(&history);
        assert_eq!(
            trading_v1::prepare_batch_with_history(
                view.state(),
                view.anchor(),
                view.state_root(),
                &history,
                &[raw.clone()],
                &trading_v1::CandidatePolicy::native_denomination_locked()
            )
            .unwrap_err(),
            NativeError::Time
        );
        // The wallet agrees: the claim bytes are refused when explained at this head.
        assert_eq!(
            explain(&raw, &view, &identity_of(&recipient_key)).unwrap_err(),
            Refusal::WindowClosed {
                expiry: 2,
                next_height: 3
            }
        );
    }
    // A real block refuses it as well.
    assert!(chain.try_step_with(&[claim_at(2)]).is_err());
    chain.finish();
}

#[test]
fn a_lock_funded_by_several_coins_lists_them_in_native_input_order_and_is_included() {
    let (sender_key, recipient_key) = (wallet_key(), other_key());
    let sender = address_of(&sender_key);
    let mut funding: Vec<(u8, [u8; 32], u64)> = (0..5u8)
        .map(|index| (0xf1 + index, sender, 300_000))
        .collect();
    funding.push((0xf9, address_of(&recipient_key), 10_000));
    let mut chain = TradeChain::new("w5a-e2e-inputs", &funding);
    let sender_signer = KeySigner::for_test(wallet_key()).unwrap();
    let recipient_signer = KeySigner::for_test(other_key()).unwrap();
    let maker = other_key();
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&chain.anchor()),
        1,
        500,
        1_000_000,
        1,
        0x34,
    );
    let lock = fund_lock(
        &chain,
        &sender_signer,
        &recipient_signer,
        &maker,
        &offer,
        [0x77; 32],
        1_000_000,
        20,
    );
    let wire = kit::wire(lock.complete.bytes());
    assert_eq!(
        wire.inputs.len(),
        4,
        "the fewest coins that cover amount and fee"
    );
    assert!(
        wire.operation
            .meta
            .inputs
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "strictly increasing native input identifiers"
    );
    let ids: Vec<[u8; 32]> = wire.inputs.iter().map(native_input_id).collect();
    assert_eq!(
        ids, wire.operation.meta.inputs,
        "the witness follows the same order"
    );
    let fee = wire.operation.meta.fee.0;
    assert!(fee >= lock.complete.bytes().len() as u64);
    let after = chain.step_with(&[lock.complete.bytes().to_vec()]);
    let change = after.coins[&OutPoint {
        transaction: wire.operation.id().unwrap(),
        index: 1,
    }]
        .output
        .atoms;
    assert_eq!(change, 1_200_000 - 1_000_000 - fee);
    chain.finish();
}

#[test]
fn a_treasury_funded_lock_respects_the_dividend_reserve_like_consensus() {
    // The TEST-VALUE Treasury holds 1,200,000 atoms; the first award boundary reserves half.
    let treasury_key = treasury_wallet_key();
    let recipient_key = other_key();
    let (treasury, recipient) = (address_of(&treasury_key), address_of(&recipient_key));
    let mut chain = TradeChain::new("w5a-e2e-reserve", &[]);
    let after_award = chain.step_at(131_072);
    assert_eq!(after_award.dividends.reserved(), 600_000);
    let refund_height = chain.height() + 10;
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
    let recipient_signer = KeySigner::for_test(other_key()).unwrap();
    let maker = other_key();
    let context = kit::context_of(&chain.anchor());
    let request = |offer: &mutiny_consensus_v8::trading_v1::SignedOffer, amount: u64| {
        OperationRequest::HashLock(HashLockRequest::new(
            Blob::new(kit::offer_bytes(offer)),
            recipient,
            amount,
            [0x66; 32],
            refund_height,
        ))
    };
    let none = BTreeSet::new();
    let big = kit::signed_offer(&maker, context.clone(), 1, 500_000, 700_000, 1, 0x35);
    {
        let view = chain.view(&none);
        // An ordinary profile never funds a lock from the Treasury authority.
        assert_eq!(
            plan(&request(&big, 700_000), &view, &identity_of(&treasury_key)).unwrap_err(),
            Refusal::TreasuryProfileRequired
        );
        // Through the Treasury profile, a lock that leaves less than the reserve is refused.
        let refusal = plan(&request(&big, 700_000), &view, &identity).unwrap_err();
        assert!(
            matches!(refusal, Refusal::ReserveBackingViolation { reserved: 600_000, backing_after } if backing_after < 600_000),
            "{refusal:?}"
        );
        // Consensus rejects the same lock: the post-block state would leave the reserve unbacked.
        let violating = Operation {
            meta: Meta {
                context: context.clone(),
                trade: [0x21; 32],
                contract: [0x22; 32],
                generation: 1,
                envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                    first_height: chain.height() + 1,
                    last_height: refund_height - 1,
                    reference_height: (chain.anchor()).height,
                    reference_block: (chain.anchor()).block,
                    preconditions: Vec::new(),
                },
                fee: Strikes(20_000),
                inputs: vec![native_input_id(&point(0xd1))],
            },
            action: Action::HashLock {
                offer: big.body.id().unwrap(),
                maker: big.body.maker().unwrap(),
                sender: treasury,
                recipient,
                amount: Strikes(700_000),
                condition: [0x66; 32],
                refund_height,
                change: Strikes(480_000),
            },
            approvals: vec![],
            offer_proof: None,
        };
        let raw = kit::consensus_signed(
            violating,
            vec![point(0xd1)],
            &[(0, &treasury_key), (1, &recipient_key)],
            Some((&big, &maker)),
        );
        assert_eq!(
            kit::consensus_in(&view, &raw).unwrap_err(),
            NativeError::Record
        );
    }
    // A lock that keeps the reserve backed is planned (with the Treasury acknowledgement),
    // completed and included in a real block.
    let small = kit::signed_offer(&maker, context, 1, 500_000, 500_000, 1, 0x36);
    {
        let view = chain.view(&none);
        let planned = plan(&request(&small, 500_000), &view, &identity).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert!(
            reviewed
                .warnings()
                .iter()
                .any(|w| w.code == "TREASURY_FUNDS")
        );
        assert!(
            reviewed
                .acknowledgements()
                .contains(&AckKind::TreasuryAuthority)
        );
    }
    let lock = fund_lock(
        &chain,
        &signer,
        &recipient_signer,
        &maker,
        &small,
        [0x66; 32],
        500_000,
        refund_height,
    );
    let after = chain.step_with(&[lock.complete.bytes().to_vec()]);
    assert_eq!(after.dividends.reserved(), 600_000);
    let backing: u64 = after
        .coins
        .values()
        .filter(|c| !c.coinbase && c.output.owner == treasury)
        .map(|c| c.output.atoms)
        .sum();
    assert!(backing >= 600_000, "the reserve stays backed: {backing}");
    chain.finish();
}
