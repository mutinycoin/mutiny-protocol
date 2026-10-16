//! Native kind-24 bonds end to end on a real certified TEST-VALUE chain.
//! Principal and funding are one body. The preserved withdrawal boundary at
//! max(B+259200,U+43200) uses an explicitly synthetic long-height parent; it is
//! lifecycle conformance, not a claim to have certified 259200 blocks.
#[path = "support/bond_support.rs"]
mod bond_support;
#[path = "support/tempdir.rs"]
mod tempdir;
use bond_support::{flow, rigs::chain::*};
use mutiny_consensus_v8::{
    Hash,
    anchors::FinalizedAnchor,
    blocks::BlockBody,
    bond_create_v3::{FundedBondCreate, PartialBondCreate, Slot as NativeSlot, UnsignedBondCreate},
    bond_ops_v2::{Operation, settle_commands},
    bonds::{EVIDENCE_HEIGHTS, LOCK_HEIGHTS, LotStatus, MINIMUM_ATOMS, withdrawal_floor},
    continuity_lifecycle_v2::transition,
    evidence_history_v2::History,
    execution::State,
    op_envelope_v1::Envelope,
    transactions::{OutPoint, Output},
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::{
    discovery::bonds as discovery,
    ops::bond::{lot_resource, stranded_escrow},
    *,
};
use std::collections::BTreeSet;
const PRINCIPAL: u64 = 15_000_000_000;
const FUNDS: u64 = 30_000_000_000;
fn create(node: Hash, nonce: Hash) -> OperationRequest {
    OperationRequest::BondCreate(BondCreateRequest::new(node, 1, PRINCIPAL, nonce))
}
fn unbond(lot: Hash) -> OperationRequest {
    OperationRequest::BondUnbond(BondUnbondRequest::new(lot))
}
fn withdraw(lot: Hash) -> OperationRequest {
    OperationRequest::BondWithdraw(BondWithdrawRequest::new(lot))
}
fn funding_point() -> OutPoint {
    OutPoint {
        transaction: [0xb1; 32],
        index: 0,
    }
}
fn hand_draft(
    chain: &BondChain,
    key: &HybridKey,
    node: Hash,
    nonce: Hash,
    amount: u64,
) -> UnsignedBondCreate {
    let parent = chain.anchor();
    let mut body = UnsignedBondCreate {
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        envelope: Envelope {
            first_height: parent.height + 1,
            last_height: parent.height + 145,
            reference_height: parent.height,
            reference_block: parent.block,
            preconditions: vec![],
        },
        owner: address_of(key),
        owner_descriptor: descriptor_of(key, 1),
        node,
        node_generation: 1,
        nonce,
        principal: amount,
        fee: 0,
        inputs: vec![funding_point()],
        change: Some(Output {
            owner: address_of(key),
            atoms: FUNDS - amount,
        }),
    };
    // Fee and change use the complete two-proof encoding, including its own
    // integer widths. A valid signed control precedes every negative mutation.
    for _ in 0..16 {
        let fee = body.signed_len().unwrap() as u64;
        if body.fee == fee {
            assert_eq!(
                body.principal + body.fee + body.change.as_ref().unwrap().atoms,
                FUNDS
            );
            return body;
        }
        body.fee = fee;
        body.change.as_mut().unwrap().atoms = FUNDS - amount - fee;
    }
    panic!("complete signed-size fee failed to converge")
}
fn seal(body: UnsignedBondCreate, key: &HybridKey) -> Vec<u8> {
    FundedBondCreate::sign(body, key).unwrap().encode().unwrap()
}
#[test]
fn bond_create_unbond_and_withdraw_end_to_end() {
    let key = wallet_key();
    let me = identity_of(&key);
    let owner = address_of(&key);
    let mut chain = BondChain::new("bond-native-e2e", &[(funding_point(), owner, FUNDS)]);
    let signer = KeySigner::for_test(wallet_key()).unwrap();
    let node = chain.node();
    let none = BTreeSet::new();
    let history = History::default();
    {
        let view = chain.view(&none);
        let nodes = discovery::nodes_controlled_by(view.state(), me.descriptor());
        assert_eq!(nodes.len(), 1);
        assert_eq!((nodes[0].node, nodes[0].owner), (node, owner));
        assert!(nodes[0].bondable());
        assert!(
            discovery::nodes_controlled_by(view.state(), &descriptor_of(&other_key(), 1))
                .is_empty()
        );
        assert!(discovery::lots_controlled_by(view.state(), me.descriptor()).is_empty());
    }
    let signed = {
        let view = chain.view(&none);
        let planned = plan(&create(node, [0x42; 32]), &view, &me).unwrap();
        assert_eq!(planned.kind(), OperationKind::BondCreate);
        assert_eq!(planned.objects().len(), 1);
        let p = PartialBondCreate::decode(&planned.objects()[0].bytes).unwrap();
        let u = &p.unsigned;
        assert_eq!(
            planned.validity(),
            &Validity {
                created: u.envelope.first_height,
                expiry: u.envelope.last_height,
                valid_only_at: None,
                bound_to_parent: false
            }
        );
        assert_eq!(u.owner, owner);
        assert_eq!(u.inputs, vec![funding_point()]);
        assert_eq!(u.principal, PRINCIPAL);
        let mut reserved = vec![funding_point(), lot_resource(&u.lot_id())];
        reserved.sort();
        assert_eq!(planned.inputs(), reserved);
        let reviewed = review(&planned, &view).unwrap();
        assert_eq!(reviewed.amount(), Some(PRINCIPAL));
        assert_eq!(reviewed.fee().rule, FeeRule::OneAtomPerEncodedByte);
        assert_eq!(reviewed.fee().payer, FeePayer::ThisWallet);
        assert_eq!(
            reviewed.fee().size_bytes,
            Some(u.signed_len().unwrap() as u64)
        );
        assert_eq!(
            reviewed.fee().atoms + reviewed.returned() + PRINCIPAL,
            FUNDS
        );
        assert_eq!(
            reviewed.net_debit(),
            Some(u128::from(PRINCIPAL) + u128::from(u.fee))
        );
        assert_eq!(
            reviewed.destinations(),
            &[Destination {
                role: DestinationRole::Change,
                address: owner,
                label: AddressLabel::ThisWallet,
                atoms: u.change.as_ref().unwrap().atoms
            }]
        );
        assert!(reviewed.requires_phrase());
        for ack in [
            AckKind::Amount,
            AckKind::Fee,
            AckKind::Conditions,
            AckKind::Irreversible,
        ] {
            assert!(reviewed.acknowledgements().contains(&ack));
        }
        let text = reviewed.render_text();
        for needle in [
            hex::encode(u.lot_id()),
            hex::encode(node),
            hex::encode([0x42; 32]),
            hex::encode(chain.lineage()),
            hex::encode(rotation_fingerprint(&u.owner_descriptor)),
            "B + 259200".into(),
            "U + 43200".into(),
            "actual certified inclusion".into(),
            "approximate".into(),
            "There is no cancel".into(),
            "Burn exposure".into(),
            "TEST-VALUE chain".into(),
        ] {
            assert!(text.contains(&needle), "missing {needle:?} in\n{text}");
        }
        flow::sign(planned, &signer, &view).unwrap()
    };
    assert!(signed.is_complete());
    let full = FundedBondCreate::decode(signed.bytes()).unwrap();
    let lot_id = full.lot_id();
    full.verify(chain.state(), &chain.anchor(), &history)
        .unwrap();
    let mut outbox = MemoryOutbox::new();
    let dir = tempdir::TempDir::new("bond-native-outbox");
    let path = dir.file("outbox.sqlite");
    let context = chain.view(&none).context();
    let mut durable = SqliteOutbox::open(&path, context).unwrap();
    {
        let view = chain.view(&none);
        outbox.commit(&signed, &view).unwrap();
        durable.commit(&signed, &view).unwrap();
    }
    let reserved = outbox.reserved().unwrap();
    assert_eq!(
        reserved,
        BTreeSet::from([funding_point(), lot_resource(&lot_id)])
    );
    {
        let view = chain.view(&reserved);
        assert_eq!(
            plan(&create(node, [0x42; 32]), &view, &me).unwrap_err(),
            Refusal::ReservedInput
        );
        assert_eq!(
            plan(&create(node, [0x43; 32]), &view, &me).unwrap_err(),
            Refusal::NothingSpendable
        );
    }
    let rows = chain.canonical_rows();
    let mut partial = full.as_partial();
    partial.funding = None;
    assert!(chain.try_step(&[partial.encode().unwrap()]).is_err());
    assert_eq!(chain.canonical_rows(), rows);
    partial = full.as_partial();
    partial.create = None;
    assert!(chain.try_step(&[partial.encode().unwrap()]).is_err());
    assert_eq!(chain.canonical_rows(), rows);
    let mut pool = chain.submission_pool();
    assert!(
        chain
            .admit_submission(&mut pool, 1, &partial.encode().unwrap())
            .is_err()
    );
    assert_eq!(
        chain
            .admit_submission(&mut pool, 1, signed.bytes())
            .unwrap(),
        signed.id()
    );
    let after = chain.step_submissions(&mut pool);
    assert_eq!(chain.height(), 1);
    let lot = &after.bonds_v2.lots[&lot_id].0;
    assert_eq!(
        (
            lot.atoms,
            lot.created_height,
            lot.status,
            lot.sequence,
            lot.owner,
            lot.node
        ),
        (PRINCIPAL, 1, LotStatus::Active, 0, owner, node)
    );
    assert!(!after.coins.contains_key(&funding_point()));
    let change = OutPoint {
        transaction: full.id().unwrap(),
        index: 0,
    };
    assert_eq!(
        after.coins[&change].output,
        full.unsigned.change.clone().unwrap()
    );
    assert_eq!(after.coins[&change].created_height, 1);
    assert_eq!(
        stranded_escrow(signed.bytes(), &after),
        None,
        "native funding cannot create independent escrow"
    );
    let records = chain.verified_operations(signed.id());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].op_id, signed.id());
    {
        let confirmations = chain.confirmations();
        let view = chain.view(&none).with_confirmations(&confirmations);
        assert_eq!(outbox.reconcile(&view).unwrap().confirmed, 1);
        assert_eq!(durable.reconcile(&view).unwrap().confirmed, 1);
    }
    assert_eq!(
        outbox.get(&signed.id()).unwrap().unwrap().status,
        OutboxStatus::Confirmed(1)
    );
    drop(durable);
    let reopened = SqliteOutbox::open(&path, context).unwrap();
    assert_eq!(
        reopened.get(&signed.id()).unwrap().unwrap().status,
        OutboxStatus::Confirmed(1)
    );
    drop(reopened);
    drop(pool);
    chain = chain.restart();
    assert_eq!(chain.verified_operations(signed.id()), records);
    {
        let lots = discovery::lots_controlled_by(chain.state(), me.descriptor());
        assert_eq!(lots.len(), 1);
        assert_eq!(lots[0].earliest_withdrawal(), None);
        assert_eq!(
            lots[0].earliest_withdrawal_if_unbonded_at(2),
            Some(1 + LOCK_HEIGHTS)
        );
    }
    // ---- unbond in block 2.
    let floor = withdrawal_floor(1, 2).unwrap();
    assert_eq!(
        floor,
        1 + LOCK_HEIGHTS,
        "an early notice: the minimum hold binds"
    );
    let unbond_signed = {
        let view = chain.view(&none);
        let planned = plan(&unbond(lot_id), &view, &me).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert!(reviewed.requires_phrase());
        assert_eq!(reviewed.fee().rule, FeeRule::None);
        assert_eq!(reviewed.fee().atoms, 0);
        assert!(reviewed.destinations().is_empty());
        let text = reviewed.render_text();
        for needle in [
            format!("Earliest withdrawal: Block {floor} = max(1 + 259200, 2 + 43200)"),
            format!("until block {}", 2 + EVIDENCE_HEIGHTS),
            "carries sequence 1".to_string(),
            "an unbond cannot be cancelled".to_string(),
        ] {
            assert!(text.contains(&needle), "missing {needle:?} in\n{text}");
        }
        flow::sign(planned, &signer, &view).unwrap()
    };
    let unbond_op = Operation::decode(unbond_signed.bytes()).unwrap();
    unbond_op
        .verify_command(
            &chain.anchor(),
            &history,
            &chain.state().wallets,
            &chain.state().bonds_v2.lots[&lot_id],
        )
        .expect("Operation::verify_command accepts the unbond");
    {
        let view = chain.view(&none);
        outbox.commit(&unbond_signed, &view).unwrap();
        assert_eq!(
            outbox.reserved().unwrap(),
            BTreeSet::from([lot_resource(&lot_id)])
        );
    }
    let after = chain.step(&[unbond_signed.bytes().to_vec()]);
    let lot = after.bonds_v2.lots[&lot_id].clone();
    assert_eq!(
        (lot.0.status, lot.0.unbond_height, lot.0.sequence),
        (LotStatus::Unbonding, Some(2), 1)
    );
    {
        let confirmations = chain.confirmations();
        let view = chain.view(&none).with_confirmations(&confirmations);
        assert_eq!(outbox.reconcile(&view).unwrap().confirmed, 1);
        assert_eq!(
            outbox.get(&unbond_signed.id()).unwrap().unwrap().status,
            OutboxStatus::Confirmed(2)
        );
        let lots = discovery::lots_controlled_by(view.state(), me.descriptor());
        assert_eq!(lots[0].earliest_withdrawal(), Some(floor));
        assert_eq!(lots[0].burn_exposed_until(), Some(2 + EVIDENCE_HEIGHTS));
    }

    // ---- a withdrawal now: the wallet and consensus both refuse it.
    let hand_withdraw = |height: u64, parent: &FinalizedAnchor| {
        bond_support::rigs::chain::hand_withdraw(&key, owner, lot_id, 2, height, parent)
    };
    {
        let view = chain.view(&none);
        assert_eq!(
            plan(&withdraw(lot_id), &view, &me).unwrap_err(),
            Refusal::NotYetEligible {
                what: "Withdrawing this lot",
                height: floor
            }
        );
        let early = hand_withdraw(3, &chain.anchor());
        assert!(
            early
                .verify_command(&chain.anchor(), &history, &view.state().wallets, &lot)
                .is_err()
        );
        let mut copy = lot.clone();
        assert!(copy.withdraw(3, 2).is_err(), "Lot::withdraw refuses it too");
        assert_eq!(
            SignedOperation::import(&early.encode().unwrap(), &view).unwrap_err(),
            Refusal::NotYetEligible {
                what: "Withdrawing this lot",
                height: floor
            }
        );
    }
    let early = hand_withdraw(3, &chain.anchor());
    assert!(
        chain.try_step(&[early.encode().unwrap()]).is_err(),
        "a real block refuses the early withdrawal"
    );

    // ---- the withdrawal at exactly the floor, executed by consensus at a synthetic parent.
    let unbonded = chain.state().clone();
    let at_parent = |parent_height: u64| -> (State, FinalizedAnchor, Hash) {
        synthetic_parent(&unbonded, &chain.anchor(), parent_height)
    };
    {
        let (state, anchor, root) = at_parent(floor - 1);
        let head = HeadInfo::new(anchor.clone(), RIG_T0 + 60 * floor, RIG_T0, root).unwrap();
        let view = ChainView::verified(head, &state, &none).unwrap();
        let planned = plan(&withdraw(lot_id), &view, &me).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert_eq!(reviewed.timing().earliest_height, Some(floor));
        assert_eq!(
            reviewed.destinations(),
            &[Destination {
                role: DestinationRole::ProtocolPayout,
                address: owner,
                label: AddressLabel::ThisWallet,
                atoms: PRINCIPAL
            }]
        );
        assert!(reviewed.requires_phrase());
        let signed = flow::sign(planned, &signer, &view).unwrap();
        let op = Operation::decode(signed.bytes()).unwrap();
        op.verify_command(
            &anchor,
            &history,
            &state.wallets,
            &state.bonds_v2.lots[&lot_id],
        )
        .expect("Operation::verify_command accepts the withdrawal at the floor");
        let mut copy = state.bonds_v2.lots[&lot_id].clone();
        assert_eq!(
            copy.withdraw(floor, 2).unwrap(),
            PRINCIPAL,
            "Lot::withdraw agrees"
        );
        let settled = settle_commands(
            &anchor,
            &history,
            &state.wallets,
            &state.bonds_v2,
            &state.penalties_v2,
            std::slice::from_ref(&op),
            &[],
        )
        .expect("consensus settles the withdrawal");
        let payout = OutPoint {
            transaction: op.payout_id().unwrap(),
            index: 0,
        };
        let coin = &settled.payouts[&payout];
        assert_eq!(
            (
                coin.output.owner,
                coin.output.atoms,
                coin.created_height,
                coin.coinbase
            ),
            (owner, PRINCIPAL, floor, false),
            "the payout coin goes to the lot's original owner"
        );
        // The full lifecycle transition the block executor runs for operations 19 and 20.
        let body = BlockBody {
            height: floor,
            reward_owner: owner,
            fees: 0,
            transactions: vec![],
            operations: vec![signed.bytes().to_vec()],
        };
        let lifecycle = transition(&state, &anchor, root, &body)
            .expect("the canonical lifecycle transition accepts the withdrawal");
        assert_eq!(lifecycle.payouts.get(&payout), Some(coin));
        assert_eq!(lifecycle.bonds.lots[&lot_id].0.status, LotStatus::Withdrawn);

        // Synthetic post-state conformance is not a canonical inclusion proof.
        let mut outbox = MemoryOutbox::new();
        outbox.commit(&signed, &view).unwrap();
        let mut post = state.clone();
        post.bonds_v2 = lifecycle.bonds.clone();
        post.coins.extend(lifecycle.payouts.clone());
        post.accounting.slots.last_height = floor;
        let post_anchor = FinalizedAnchor {
            height: floor,
            block: [0x78; 32],
            ..anchor.clone()
        };
        let post_head = HeadInfo::new(
            post_anchor,
            RIG_T0 + 60 * floor + 60,
            RIG_T0,
            post.root().unwrap_or([0x79; 32]),
        )
        .unwrap();
        let post_view = ChainView::new(post_head, &post, &none);
        assert_eq!(outbox.reconcile(&post_view).unwrap().confirmed, 0);
        assert_eq!(
            outbox.get(&signed.id()).unwrap().unwrap().status,
            OutboxStatus::InputsSpent
        );
    }
    // One block earlier: refused by the wallet, by Lot::withdraw, by verify_command and by
    // settle_commands alike.
    {
        let (state, anchor, root) = at_parent(floor - 2);
        let head = HeadInfo::new(anchor.clone(), RIG_T0 + 60 * floor, RIG_T0, root).unwrap();
        let view = ChainView::new(head, &state, &none);
        assert_eq!(
            plan(&withdraw(lot_id), &view, &me).unwrap_err(),
            Refusal::NotYetEligible {
                what: "Withdrawing this lot",
                height: floor
            }
        );
        let op = hand_withdraw(floor - 1, &anchor);
        let lot = &state.bonds_v2.lots[&lot_id];
        assert!(
            op.verify_command(&anchor, &history, &state.wallets, lot)
                .is_err()
        );
        assert!(lot.clone().withdraw(floor - 1, 2).is_err());
        assert!(
            settle_commands(
                &anchor,
                &history,
                &state.wallets,
                &state.bonds_v2,
                &state.penalties_v2,
                std::slice::from_ref(&op),
                &[]
            )
            .is_err()
        );
        assert!(
            SignedOperation::import(&op.encode().unwrap(), &view).is_err(),
            "the wallet refuses the same bytes"
        );
    }
    // ---- a burned lot is never withdrawn (burned through consensus' own `burn_exposed`).
    {
        let (mut state, anchor, _) = at_parent(floor - 1);
        let burned = state
            .bonds_v2
            .burn_exposed(chain.lineage(), 2, 3, [0x0e; 32])
            .unwrap();
        assert_eq!(burned, u128::from(PRINCIPAL));
        let root = state.root().unwrap_or([0x7a; 32]);
        let head = HeadInfo::new(anchor.clone(), RIG_T0 + 60 * floor, RIG_T0, root).unwrap();
        let view = ChainView::new(head, &state, &none);
        assert!(discovery::lot(view.state(), &lot_id).unwrap().burned());
        assert_eq!(
            plan(&withdraw(lot_id), &view, &me).unwrap_err(),
            Refusal::LotBurned
        );
        let op = hand_withdraw(floor, &anchor);
        assert!(
            op.verify_command(
                &anchor,
                &history,
                &state.wallets,
                &state.bonds_v2.lots[&lot_id]
            )
            .is_err()
        );
        assert_eq!(
            SignedOperation::import(&op.encode().unwrap(), &view).unwrap_err(),
            Refusal::LotBurned
        );
    }
    chain.finish();
}

fn rotation_fingerprint(raw: &[u8]) -> Hash {
    mutiny_wallet_core_v8::ops::rotation::descriptor_fingerprint(raw)
}
#[test]
fn a_bond_window_survives_head_advance_but_review_approval_does_not() {
    let key = wallet_key();
    let me = identity_of(&key);
    let mut chain = BondChain::new("bond-window", &[(funding_point(), address_of(&key), FUNDS)]);
    let signer = KeySigner::for_test(wallet_key()).unwrap();
    let none = BTreeSet::new();
    let request = OperationRequest::BondCreate(
        BondCreateRequest::new(chain.node(), 1, PRINCIPAL, [0x51; 32]).with_validity_blocks(1),
    );
    let (planned, approval, mut session) = {
        let view = chain.view(&none);
        let planned = plan(&request, &view, &me).unwrap();
        assert_eq!(
            (planned.validity().created, planned.validity().expiry),
            (1, 2)
        );
        assert_eq!(planned.validity().valid_only_at, None);
        let mut session = PlanSession::new(planned.clone());
        session.present(&view).unwrap();
        let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
        (planned, approval, session)
    };
    let old = chain.anchor();
    chain.step(&[]);
    let mut history = History::default();
    history.insert_anchor(old.height, old.block).unwrap();
    {
        let view = chain.view(&none).with_history(&history);
        session.on_head(&view);
        assert_eq!(session.phase(), PlanPhase::Planned);
        assert!(review(&planned, &view).is_ok());
        assert_eq!(
            signer
                .authorize(planned.clone(), approval, &view)
                .unwrap_err(),
            Refusal::StaleHead {
                reviewed: 0,
                current: 1
            }
        );
    }
    chain.step(&[]);
    let view = chain.view(&none).with_history(&history);
    session.on_head(&view);
    assert_eq!(
        session.phase(),
        PlanPhase::Invalidated(Invalidation::Expired)
    );
    assert!(review(&planned, &view).is_err());
    let again = plan(&request, &view, &me).unwrap();
    assert_eq!((again.validity().created, again.validity().expiry), (3, 4));
    chain.finish();
}
#[test]
fn creation_refusals_agree_with_consensus_block_execution() {
    let key = wallet_key();
    let stranger = other_key();
    let me = identity_of(&key);
    let stranger_point = OutPoint {
        transaction: [0xb2; 32],
        index: 0,
    };
    let chain = BondChain::new(
        "bond-native-refusals",
        &[
            (funding_point(), address_of(&key), FUNDS),
            (stranger_point.clone(), address_of(&stranger), FUNDS),
        ],
    );
    let node = chain.node();
    let none = BTreeSet::new();
    let base = hand_draft(&chain, &key, node, [0x61; 32], PRINCIPAL);
    let control = seal(base.clone(), &key);
    chain
        .execute(vec![], vec![control.clone()])
        .expect("fully signed, size-funded native control executes");
    let view = chain.view(&none);
    assert!(
        SignedOperation::import(&control, &view)
            .unwrap()
            .is_complete()
    );
    type Edit = fn(&mut UnsignedBondCreate);
    // Below-minimum principal is already unrepresentable in the native codec.
    // Exercise the real encoder and wallet preflight instead of fabricating a
    // purportedly signed operation that the public signing API cannot produce.
    let mut below = base.clone();
    below.principal = MINIMUM_ATOMS - 1;
    below.change.as_mut().unwrap().atoms = FUNDS - below.principal - below.fee;
    assert!(below.encode().is_err());
    assert!(FundedBondCreate::sign(below, &key).is_err());
    assert_eq!(
        plan(
            &OperationRequest::BondCreate(BondCreateRequest::new(
                node,
                1,
                MINIMUM_ATOMS - 1,
                [0x61; 32]
            )),
            &view,
            &me
        )
        .unwrap_err(),
        Refusal::BelowMinimumBond {
            minimum: MINIMUM_ATOMS
        }
    );
    let cases: Vec<(&str, Edit)> = vec![
        ("wrong node", |u| u.node = [0x98; 32]),
        ("wrong node generation", |u| u.node_generation += 1),
        ("wrong canonical reference", |u| {
            u.envelope.reference_block[0] ^= 1
        }),
        ("another Genesis", |u| u.genesis[0] ^= 1),
        ("foreign change", |u| {
            u.change.as_mut().unwrap().owner = [0x99; 32]
        }),
        ("principal not conserved", |u| u.principal += 1),
        ("fee below signed size", |u| {
            u.change.as_mut().unwrap().atoms += u.fee - 1;
            u.fee = 1;
        }),
    ];
    let rows = chain.canonical_rows();
    for (label, edit) in cases {
        let mut u = base.clone();
        edit(&mut u);
        let raw = seal(u, &key);
        assert!(
            chain.execute(vec![], vec![raw.clone()]).is_err(),
            "consensus {label}"
        );
        assert_eq!(chain.canonical_rows(), rows);
        assert!(
            SignedOperation::import(&raw, &view).is_err(),
            "wallet {label}"
        );
    }
    let mut foreign = hand_draft(&chain, &stranger, node, [0x62; 32], PRINCIPAL);
    foreign.inputs = vec![stranger_point];
    let foreign = seal(foreign, &stranger);
    assert_eq!(
        plan(&create(node, [0x62; 32]), &view, &identity_of(&stranger)).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::BondOwner)
    );
    assert!(chain.execute(vec![], vec![foreign.clone()]).is_err());
    assert!(SignedOperation::import(&foreign, &view).is_err());
    for flag in ["eligible", "physical"] {
        let mut state = chain.state().clone();
        let member = &mut state.continuity.as_mut().unwrap().members[0];
        if flag == "eligible" {
            member.eligible = false
        } else {
            member.physical = false
        };
        let root = state.root().unwrap_or([0x7b; 32]);
        let view = ChainView::new(
            HeadInfo::new(chain.anchor(), RIG_T0 + 65, RIG_T0, root).unwrap(),
            &state,
            &none,
        );
        assert_eq!(
            plan(&create(node, [0x63; 32]), &view, &me).unwrap_err(),
            Refusal::NodeNotEligible
        );
        assert!(!discovery::node(&state, &node).unwrap().bondable());
        assert!(
            chain
                .execute_on(&state, vec![], vec![control.clone()])
                .is_err()
        );
        assert!(SignedOperation::import(&control, &view).is_err());
    }
    // Both approvals commit every economic and canonical field; a retained signature cannot
    // authorize a changed amount, input, destination, fee, window or reference.
    let full = FundedBondCreate::decode(&control).unwrap();
    for field in 0..6 {
        let mut altered = full.as_partial();
        match field {
            0 => altered.unsigned.principal += 1,
            1 => altered.unsigned.inputs[0].index += 1,
            2 => altered.unsigned.change.as_mut().unwrap().owner[0] ^= 1,
            3 => altered.unsigned.fee += 1,
            4 => altered.unsigned.envelope.last_height -= 1,
            _ => altered.unsigned.envelope.reference_block[0] ^= 1,
        };
        let bytes = altered.encode().unwrap();
        assert!(altered.complete().unwrap().verify_signatures().is_err());
        assert!(chain.execute(vec![], vec![bytes.clone()]).is_err());
        assert!(SignedOperation::import(&bytes, &view).is_err());
    }
    for slot in NativeSlot::ALL {
        let mut partial = full.as_partial();
        match slot {
            NativeSlot::Create => partial.create = None,
            NativeSlot::Funding => partial.funding = None,
        };
        let raw = partial.encode().unwrap();
        assert!(FundedBondCreate::decode(&raw).is_err());
        assert!(chain.execute(vec![], vec![raw.clone()]).is_err());
        let imported = SignedOperation::import(&raw, &view);
        assert!(imported.is_err() || !imported.unwrap().is_complete());
    }
    println!(
        "RETAINED_PUBLIC_BOND_REFUSAL_EVIDENCE={}",
        chain.evidence_directory().display()
    );
    chain.finish();
}
#[test]
fn a_lot_identifier_cannot_be_created_twice() {
    let key = wallet_key();
    let me = identity_of(&key);
    let second = OutPoint {
        transaction: [0xb3; 32],
        index: 0,
    };
    let none = BTreeSet::new();
    let mut chain = BondChain::new(
        "bond-native-twice",
        &[
            (funding_point(), address_of(&key), FUNDS),
            (second.clone(), address_of(&key), FUNDS),
        ],
    );
    let node = chain.node();
    let nonce = [0x71; 32];
    let signer = KeySigner::for_test(wallet_key()).unwrap();
    let first = {
        let view = chain.view(&none);
        flow::sign(
            plan(&create(node, nonce), &view, &me).unwrap(),
            &signer,
            &view,
        )
        .unwrap()
    };
    let mut pool = chain.submission_pool();
    chain.admit_submission(&mut pool, 1, first.bytes()).unwrap();
    chain.step_submissions(&mut pool);
    let rows = chain.canonical_rows();
    assert_eq!(
        chain.admit_submission(&mut pool, 1, first.bytes()).unwrap(),
        first.id(),
        "exact finalized retransmission is idempotent, never a new execution"
    );
    assert!(matches!(
        pool.status(first.id()).unwrap(),
        mutiny_consensus_v8::submission_v1::Status::Finalized(_)
    ));
    assert_eq!(chain.verified_operations(first.id()).len(), 1);
    assert_eq!(chain.canonical_rows(), rows);
    let view = chain.view(&none);
    assert_eq!(
        plan(&create(node, nonce), &view, &me).unwrap_err(),
        Refusal::Replay
    );
    let mut u = hand_draft(&chain, &key, node, nonce, PRINCIPAL);
    u.inputs = vec![second];
    let raw = seal(u, &key);
    assert!(chain.execute(vec![], vec![raw.clone()]).is_err());
    assert_eq!(chain.canonical_rows(), rows);
    assert_eq!(
        SignedOperation::import(&raw, &view).unwrap_err(),
        Refusal::Replay
    );
    assert!(plan(&create(node, [0x72; 32]), &view, &me).is_ok());
    drop(pool);
    chain.finish();
}
