//! The outbox contract (independent verification on commit, reservations, idempotence, capacity,
//! integrity, reconciliation from verified state, no revoke) and the public partial-approval
//! container with its counterparty review. NATIVE, TEST-VALUE; public test keys only.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_consensus_v8::{
    Hash,
    transactions::{Coin, OutPoint, Output},
    transactions_v2::Transfer,
};
use mutiny_wallet_core_v8::*;
use std::collections::BTreeSet;
use synthetic::{World, address, identity, key_a, key_b};

fn pay(recipient: [u8; 32], amount: u64) -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(recipient, amount))
}

/// Two coins so that two payments can be built over disjoint or identical coins.
fn world_with_coins() -> World {
    let mut world = World::with_wallets(100);
    let owner = address(&key_a(), 1);
    world.coin(owner, 5_000_000, 1, false, 1, 0);
    world.coin(owner, 2_000_000, 1, false, 2, 0);
    world
}

fn signed_payment(world: &World, amount: u64) -> (SignedOperation, OperationPlan) {
    let view = world.view();
    let me = identity(&key_a());
    let planned = plan(&pay(address(&key_b(), 1), amount), &view, &me).unwrap();
    let signer = KeySigner::for_test(key_a()).unwrap();
    (
        flow::sign(planned.clone(), &signer, &view).unwrap(),
        planned,
    )
}

fn tampered(signed: &SignedOperation, edit: impl FnOnce(&mut Transfer)) -> SignedOperation {
    let mut transfer = Transfer::decode(signed.bytes()).unwrap();
    edit(&mut transfer);
    match signed {
        SignedOperation::Complete {
            kind,
            id,
            validity,
            reserved,
            ..
        } => SignedOperation::Complete {
            kind: *kind,
            id: *id,
            bytes: transfer.encode().unwrap(),
            validity: *validity,
            reserved: reserved.clone(),
        },
        _ => unreachable!(),
    }
}

#[test]
fn commit_verifies_independently_and_refuses_anything_that_is_not_a_good_signed_payment() {
    let world = world_with_coins();
    let view = world.view();
    let (signed, _) = signed_payment(&world, 1_000_000);
    let mut outbox = MemoryOutbox::new();

    // A flipped signature half, a zeroed half, a wrong identifier, a changed fee: all refused.
    let flipped = tampered(&signed, |t| t.inputs[0].signature.ed448[3] ^= 1);
    assert!(matches!(
        outbox.commit(&flipped, &view),
        Err(Refusal::VerificationFailed(_))
    ));
    let no_half = tampered(&signed, |t| t.inputs[0].signature.fndsa = [0; 1280]);
    assert!(matches!(
        outbox.commit(&no_half, &view),
        Err(Refusal::VerificationFailed(_))
    ));
    let richer = tampered(&signed, |t| {
        t.fee += 1;
        t.outputs[1].atoms -= 1;
    });
    assert!(matches!(
        outbox.commit(&richer, &view),
        Err(Refusal::VerificationFailed(_))
    ));
    let wrong_id = match &signed {
        SignedOperation::Complete {
            kind,
            bytes,
            validity,
            reserved,
            ..
        } => SignedOperation::Complete {
            kind: *kind,
            id: [0xee; 32],
            bytes: bytes.clone(),
            validity: *validity,
            reserved: reserved.clone(),
        },
        _ => unreachable!(),
    };
    assert!(matches!(
        outbox.commit(&wrong_id, &view),
        Err(Refusal::VerificationFailed(_))
    ));
    // A payment is never partial: a value that says so contradicts its own bytes, which are fully
    // signed (completeness is derived from the bytes, never taken from the caller).
    let partial = SignedOperation::Partial {
        kind: OperationKind::Payment,
        id: signed.id(),
        bytes: signed.bytes().to_vec(),
        missing: vec![],
        validity: *signed.validity(),
        reserved: signed.reserved().to_vec(),
    };
    assert!(matches!(
        outbox.commit(&partial, &view),
        Err(Refusal::VerificationFailed(_))
    ));
    // A kind without a handler in this build.
    let foreign = SignedOperation::Complete {
        kind: OperationKind::WalletRotation,
        id: signed.id(),
        bytes: signed.bytes().to_vec(),
        validity: *signed.validity(),
        reserved: vec![],
    };
    let refusal = outbox.commit(&foreign, &view).unwrap_err();
    if ops::implemented_kinds().contains(&OperationKind::WalletRotation) {
        assert_eq!(
            refusal,
            Refusal::VerificationFailed("canonical funded rotation refused")
        );
    } else {
        assert_eq!(
            refusal,
            Refusal::NotImplemented(OperationKind::WalletRotation)
        );
    }
    // Garbage bytes.
    let garbage = SignedOperation::Complete {
        kind: OperationKind::Payment,
        id: [1; 32],
        bytes: vec![1, 2, 3],
        validity: *signed.validity(),
        reserved: vec![],
    };
    assert!(matches!(
        outbox.commit(&garbage, &view),
        Err(Refusal::Malformed(_))
    ));

    // Nothing was queued and nothing is reserved after any refusal.
    assert!(outbox.records().unwrap().is_empty());
    assert!(outbox.reserved().unwrap().is_empty());
    // The genuine bytes go in.
    assert_eq!(outbox.commit(&signed, &view).unwrap(), signed.id());
}

#[test]
fn reservations_conflict_release_on_forget_and_forget_does_not_revoke() {
    let world = world_with_coins();
    let view = world.view();
    let (first, _) = signed_payment(&world, 1_000_000);
    let (second, _) = signed_payment(&world, 1_100_000); // same coin, different payment
    assert_ne!(first.id(), second.id());
    assert_eq!(first.reserved(), second.reserved());

    let mut outbox = MemoryOutbox::new();
    outbox.commit(&first, &view).unwrap();
    assert_eq!(
        outbox.commit(&second, &view).unwrap_err(),
        Refusal::ReservedInput
    );
    assert_eq!(outbox.pending().unwrap().len(), 1);

    // The outbox reports exactly the coin the first payment spends.
    assert_eq!(
        outbox.reserved().unwrap(),
        first.reserved().iter().cloned().collect()
    );

    // Forgetting releases the reservation but does NOT cancel the signed bytes: they are still
    // exactly the bytes that were signed, and a different payment may now take the coin.
    outbox.forget(&first.id()).unwrap();
    assert_eq!(
        outbox.get(&first.id()).unwrap().unwrap().status,
        OutboxStatus::Forgotten
    );
    assert!(outbox.reserved().unwrap().is_empty());
    assert_eq!(
        outbox.get(&first.id()).unwrap().unwrap().bytes,
        first.bytes(),
        "the signed bytes are unchanged"
    );
    outbox.commit(&second, &view).unwrap();
    assert_eq!(
        outbox.commit(&first, &view).unwrap_err(),
        Refusal::ReservedInput,
        "a forgotten record cannot take the coin back"
    );
    outbox.forget(&second.id()).unwrap();
    outbox.commit(&first, &view).unwrap();
    assert_eq!(
        outbox.get(&first.id()).unwrap().unwrap().status,
        OutboxStatus::Queued
    );
    assert_eq!(
        outbox.forget(&[0x99; 32]).unwrap_err(),
        Refusal::UnknownOperation
    );
}

#[test]
fn a_view_that_already_reserves_the_coin_refuses_a_new_commit_but_not_the_same_bytes_again() {
    let world = world_with_coins();
    let (signed, _) = signed_payment(&world, 1_000_000);
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &world.view()).unwrap();
    // The host's view now carries the outbox's own reservations.
    let reserved: BTreeSet<OutPoint> = outbox.reserved().unwrap();
    let with_reservations = World {
        state: world.state.clone(),
        anchor: world.anchor.clone(),
        reserved,
        timestamp: world.timestamp,
    };
    assert_eq!(
        outbox.commit(&signed, &with_reservations.view()).unwrap(),
        signed.id(),
        "idempotent, not re-checked against itself"
    );
    let (other, _) = signed_payment(&world, 1_100_000);
    assert_eq!(
        outbox
            .commit(&other, &with_reservations.view())
            .unwrap_err(),
        Refusal::ReservedInput
    );
}

#[test]
fn capacity_and_integrity_are_enforced() {
    let world = world_with_coins();
    let view = world.view();
    let (a, _) = signed_payment(&world, 1_000_000);
    // A second payment over the other coin only.
    let mut only_second_coin = World::with_wallets(100);
    only_second_coin.coin(address(&key_a(), 1), 2_000_000, 1, false, 2, 0);
    let (b, _) = signed_payment(&only_second_coin, 500_000);

    // Record limit.
    let mut small = MemoryOutbox::with_limits(1, 1 << 20);
    small.commit(&a, &view).unwrap();
    assert_eq!(small.commit(&b, &view).unwrap_err(), Refusal::OutboxFull);
    assert_eq!(
        small.commit(&a, &view).unwrap(),
        a.id(),
        "an existing record is not a new record"
    );
    // Byte limit.
    let mut tiny = MemoryOutbox::with_limits(10, 1000);
    assert_eq!(tiny.commit(&a, &view).unwrap_err(), Refusal::OutboxFull);
    assert!(tiny.records().unwrap().is_empty());

    // Integrity: any change to a stored record is detected on every read.
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&a, &view).unwrap();
    outbox.commit(&b, &view).unwrap();
    assert_eq!(outbox.records().unwrap().len(), 2);
    outbox.corrupt_for_test(&a.id());
    assert_eq!(outbox.get(&a.id()).unwrap_err(), Refusal::OutboxIntegrity);
    assert_eq!(outbox.records().unwrap_err(), Refusal::OutboxIntegrity);
    assert_eq!(outbox.pending().unwrap_err(), Refusal::OutboxIntegrity);
    assert_eq!(outbox.reserved().unwrap_err(), Refusal::OutboxIntegrity);
    assert_eq!(
        outbox.reconcile(&view).unwrap_err(),
        Refusal::OutboxIntegrity
    );
    assert_eq!(
        outbox.forget(&a.id()).unwrap_err(),
        Refusal::OutboxIntegrity
    );
    assert_eq!(
        outbox.commit(&a, &view).unwrap_err(),
        Refusal::OutboxIntegrity,
        "the same id with different bytes is refused"
    );
    assert!(
        outbox.get(&b.id()).is_ok(),
        "an undamaged record still reads"
    );
}

struct Fixed(u64);
impl ConfirmationSource for Fixed {
    fn confirmed_height(&self, _id: &Hash) -> Option<u64> {
        Some(self.0)
    }
}

#[test]
fn reconciliation_reads_verified_state_only() {
    let world = world_with_coins();
    let (signed, _) = signed_payment(&world, 1_000_000);
    let transfer = Transfer::decode(signed.bytes()).unwrap();
    let id = signed.id();
    let queue = || {
        let mut outbox = MemoryOutbox::new();
        outbox.commit(&signed, &world.view()).unwrap();
        outbox
    };

    // Still pending.
    let mut outbox = queue();
    assert_eq!(
        outbox.reconcile(&world.view()).unwrap(),
        ReconcileReport {
            still_pending: 1,
            ..Default::default()
        }
    );
    assert_eq!(
        outbox.get(&id).unwrap().unwrap().status,
        OutboxStatus::Queued
    );
    assert_eq!(outbox.reserved().unwrap().len(), 1);

    // Included: one of its outputs exists as a coin created by it.
    let mut included = World {
        state: world.state.clone(),
        ..World::with_wallets(120)
    };
    for point in signed.reserved() {
        included.state.coins.remove(point);
    }
    included.state.coins.insert(
        OutPoint {
            transaction: id,
            index: 1,
        },
        Coin {
            output: Output {
                owner: transfer.outputs[1].owner,
                atoms: transfer.outputs[1].atoms,
            },
            created_height: 118,
            coinbase: false,
        },
    );
    let mut outbox = queue();
    assert_eq!(outbox.reconcile(&included.view()).unwrap().confirmed, 1);
    assert_eq!(
        outbox.get(&id).unwrap().unwrap().status,
        OutboxStatus::Confirmed(118)
    );
    assert!(outbox.reserved().unwrap().is_empty());

    // Included according to the host's verified confirmation index (outputs already spent again).
    let mut spent_again = World {
        state: world.state.clone(),
        ..World::with_wallets(120)
    };
    for point in signed.reserved() {
        spent_again.state.coins.remove(point);
    }
    let fixed = Fixed(117);
    let mut outbox = queue();
    assert_eq!(
        outbox
            .reconcile(&spent_again.view().with_confirmations(&fixed))
            .unwrap()
            .confirmed,
        1
    );
    assert_eq!(
        outbox.get(&id).unwrap().unwrap().status,
        OutboxStatus::Confirmed(117)
    );

    // Inputs gone with no evidence that this payment spent them: not "confirmed".
    let mut outbox = queue();
    assert_eq!(
        outbox.reconcile(&spent_again.view()).unwrap().inputs_spent,
        1
    );
    assert_eq!(
        outbox.get(&id).unwrap().unwrap().status,
        OutboxStatus::InputsSpent
    );
    assert!(
        outbox.reserved().unwrap().is_empty(),
        "a settled record releases its coins"
    );

    // The window closed without inclusion.
    let mut late = World {
        state: world.state.clone(),
        ..World::with_wallets(245)
    };
    late.reserved.clear();
    let mut outbox = queue();
    assert_eq!(outbox.reconcile(&late.view()).unwrap().expired, 1);
    assert_eq!(
        outbox.get(&id).unwrap().unwrap().status,
        OutboxStatus::Expired
    );

    // A settled record is never revisited.
    assert_eq!(
        outbox.reconcile(&world.view()).unwrap(),
        ReconcileReport::default()
    );
}

#[test]
fn pending_records_are_exactly_the_signed_bytes_for_export() {
    let world = world_with_coins();
    let (signed, _) = signed_payment(&world, 1_000_000);
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &world.view()).unwrap();
    let pending = outbox.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].bytes, signed.bytes());
    assert!(pending[0].complete);
    assert_eq!(pending[0].kind, OperationKind::Payment);
    assert_eq!(pending[0].queued_at_height, 100);
    assert!(pending[0].verify().is_ok());
    assert_eq!(pending[0].checksum().len(), 32);
}

#[test]
fn a_partial_container_carries_public_data_and_lets_the_counterparty_review_it() {
    let world = world_with_coins();
    let view = world.view();
    let (_, planned) = signed_payment(&world, 1_000_000);
    // A partially signed operation of the payment shape: the unsigned bytes with the requirement
    // that the other wallet still has to sign. (Payments are never partial in practice; the
    // container and the counterparty review are kind-agnostic and exercised here with them.)
    let partial = SignedOperation::Partial {
        kind: OperationKind::Payment,
        id: [5; 32],
        bytes: planned.objects()[0].bytes.clone(),
        missing: vec![Requirement {
            slot: Slot::Input(0),
            signer: RequiredSigner::Wallet(address(&key_a(), 1)),
            status: RequirementStatus::Counterparty,
        }],
        validity: *planned.validity(),
        reserved: planned.inputs().to_vec(),
    };
    let container = PartialApproval::from_signed(&partial, view.context()).unwrap();
    let raw = container.export().unwrap();
    let imported = PartialApproval::import(&raw).unwrap();
    assert_eq!(imported, container);
    assert_eq!(imported.to_signed(), partial);
    assert_eq!(imported.kind(), OperationKind::Payment);

    // The owner and a counterparty see the same operation, each from their own side.
    let as_owner = imported.explain_for(&view, &identity(&key_a())).unwrap();
    assert_eq!(
        as_owner.binding(),
        review(&planned, &view).unwrap().binding()
    );
    let as_other = imported.explain_for(&view, &identity(&key_b())).unwrap();
    assert_eq!(
        as_other.binding(),
        as_owner.binding(),
        "one operation, one digest, whoever reads it"
    );
    assert_ne!(as_other.title(), as_owner.title());

    // A container for another chain is refused before anything is explained.
    let mut foreign = World::with_wallets(100);
    foreign.state = world.state.clone();
    foreign.anchor.genesis = [0x61; 32];
    assert_eq!(
        imported
            .explain_for(&foreign.view(), &identity(&key_a()))
            .unwrap_err(),
        Refusal::WrongContext(ContextField::Genesis)
    );
    // And an operation kind this build cannot explain is refused, not guessed.
    let mut other_kind = partial.clone();
    if let SignedOperation::Partial { kind, .. } = &mut other_kind {
        *kind = OperationKind::LicenseDvp;
    }
    let container = PartialApproval::from_signed(&other_kind, view.context()).unwrap();
    assert!(
        PartialApproval::import(&container.export().unwrap()).is_ok(),
        "the container itself is well formed"
    );
    assert_eq!(
        container
            .explain_for(&view, &identity(&key_a()))
            .unwrap_err(),
        Refusal::PartialInvalid("the kind label does not match the operation inside"),
        "a label that disagrees with the bytes is refused"
    );
}

#[test]
fn hostile_containers_are_refused() {
    let world = world_with_coins();
    let (_, planned) = signed_payment(&world, 1_000_000);
    let partial = SignedOperation::Partial {
        kind: OperationKind::Payment,
        id: [5; 32],
        bytes: planned.objects()[0].bytes.clone(),
        missing: vec![],
        validity: *planned.validity(),
        reserved: planned.inputs().to_vec(),
    };
    let raw = PartialApproval::from_signed(&partial, world.view().context())
        .unwrap()
        .export()
        .unwrap();
    // Indefinite-length arrays, wrong tags, empty input, random noise, an unknown version.
    for hostile in [
        vec![],
        vec![0x9f, 0xff],
        vec![0x80],
        vec![0x82, 0x40, 0x40],
        vec![0xff; 64],
        (0..200u8).collect::<Vec<u8>>(),
        [raw.clone(), raw.clone()].concat(),
    ] {
        assert!(PartialApproval::import(&hostile).is_err());
    }
    // Every prefix of a good container is refused.
    for cut in (0..raw.len()).step_by(7) {
        assert!(PartialApproval::import(&raw[..cut]).is_err());
    }
}

/// The same bytes with different claims about them.
fn claim(
    signed: &SignedOperation,
    edit: impl FnOnce(&mut Validity, &mut Vec<OutPoint>),
) -> SignedOperation {
    match signed {
        SignedOperation::Complete {
            kind,
            id,
            bytes,
            validity,
            reserved,
        } => {
            let (mut validity, mut reserved) = (*validity, reserved.clone());
            edit(&mut validity, &mut reserved);
            SignedOperation::Complete {
                kind: *kind,
                id: *id,
                bytes: bytes.clone(),
                validity,
                reserved,
            }
        }
        _ => unreachable!(),
    }
}

#[test]
fn commit_derives_its_metadata_from_the_bytes_and_refuses_a_lie_about_any_field() {
    let world = world_with_coins();
    let view = world.view();
    let (signed, _) = signed_payment(&world, 1_000_000);
    let real = signed.reserved().to_vec();
    assert_eq!(real.len(), 1);
    let spare = OutPoint {
        transaction: [0x77; 32],
        index: 3,
    };
    let mut outbox = MemoryOutbox::new();

    // Every one of these would let a second plan spend the same coin, or settle the record at the
    // wrong time, if the outbox believed the caller instead of the bytes.
    let lies: Vec<(&str, SignedOperation)> = vec![
        ("no reservations", claim(&signed, |_, r| r.clear())),
        (
            "an extra coin",
            claim(&signed, |_, r| r.push(spare.clone())),
        ),
        (
            "another coin instead",
            claim(&signed, |_, r| *r = vec![spare.clone()]),
        ),
        ("a later expiry", claim(&signed, |v, _| v.expiry += 1_000)),
        ("an earlier creation", claim(&signed, |v, _| v.created = 1)),
        (
            "a conditional window",
            claim(&signed, |v, _| v.valid_only_at = Some(150)),
        ),
        (
            "bound to a parent",
            claim(&signed, |v, _| v.bound_to_parent = true),
        ),
    ];
    for (what, lie) in &lies {
        assert!(
            matches!(
                outbox.commit(lie, &view),
                Err(Refusal::VerificationFailed(_))
            ),
            "{what}"
        );
    }
    assert!(outbox.records().unwrap().is_empty());
    assert!(outbox.reserved().unwrap().is_empty());

    // A reordered or repeated claim is the same set: it is accepted and stored as the bytes say.
    let repeated = claim(&signed, |_, r| {
        let again = r.clone();
        r.extend(again);
    });
    assert_eq!(outbox.commit(&repeated, &view).unwrap(), signed.id());
    let record = outbox.get(&signed.id()).unwrap().unwrap();
    assert_eq!(record.reserved, real, "stored as derived, not as claimed");
    assert_eq!(record.validity, *signed.validity());
    assert_eq!(outbox.reserved().unwrap(), real.iter().cloned().collect());
}

#[test]
fn a_confirmed_or_expired_operation_is_refused_when_committed_again_not_reported_as_queued() {
    let world = world_with_coins();
    let (signed, _) = signed_payment(&world, 1_000_000);
    let transfer = Transfer::decode(signed.bytes()).unwrap();
    let id = signed.id();

    // Included: the coin is spent and an output of the payment exists.
    let mut included = World {
        state: world.state.clone(),
        ..World::with_wallets(120)
    };
    for point in signed.reserved() {
        included.state.coins.remove(point);
    }
    included.state.coins.insert(
        OutPoint {
            transaction: id,
            index: 1,
        },
        Coin {
            output: Output {
                owner: transfer.outputs[1].owner,
                atoms: transfer.outputs[1].atoms,
            },
            created_height: 118,
            coinbase: false,
        },
    );
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &world.view()).unwrap();
    assert_eq!(outbox.reconcile(&included.view()).unwrap().confirmed, 1);
    assert!(
        outbox.commit(&signed, &included.view()).is_err(),
        "consensus no longer accepts it: not queued again"
    );
    assert_eq!(
        outbox.get(&id).unwrap().unwrap().status,
        OutboxStatus::Confirmed(118)
    );
    assert!(outbox.reserved().unwrap().is_empty());

    // Expired: the window closed.
    let mut late = World {
        state: world.state.clone(),
        ..World::with_wallets(245)
    };
    late.reserved.clear();
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &world.view()).unwrap();
    assert_eq!(outbox.reconcile(&late.view()).unwrap().expired, 1);
    assert!(outbox.commit(&signed, &late.view()).is_err());
    assert_eq!(
        outbox.get(&id).unwrap().unwrap().status,
        OutboxStatus::Expired
    );
    assert!(outbox.reserved().unwrap().is_empty());
}

#[test]
fn only_open_records_count_against_capacity_and_history_is_trimmed() {
    let world = world_with_coins();
    let view = world.view();
    // Three different payments over the same coin: only one of them can be open at a time.
    let payments: Vec<SignedOperation> = [1_000_000u64, 1_100_000, 1_200_000]
        .iter()
        .map(|amount| signed_payment(&world, *amount).0)
        .collect();

    // A limit of ONE open record never locks anyone out of history.
    let mut outbox = MemoryOutbox::with_limits(1, 1 << 20);
    for (n, payment) in payments.iter().enumerate() {
        outbox.commit(payment, &view).unwrap();
        assert_eq!(outbox.pending().unwrap().len(), 1);
        outbox.forget(&payment.id()).unwrap();
        assert_eq!(outbox.records().unwrap().len(), n + 1, "history is kept");
    }
    // Trim to the most recently queued settled record.
    assert_eq!(outbox.prune_settled(1).unwrap(), 2);
    let kept = outbox.records().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].id, payments[2].id());
    assert_eq!(outbox.prune_settled(1).unwrap(), 0, "nothing more to trim");
    // An open record is never pruned, whatever the limit.
    outbox.commit(&payments[0], &view).unwrap();
    assert_eq!(outbox.prune_settled(0).unwrap(), 1);
    let left = outbox.records().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].status, OutboxStatus::Queued);
    assert_eq!(outbox.reserved().unwrap().len(), 1);

    // Reconciliation trims the history to its limit as it settles records.
    let mut late = World {
        state: world.state.clone(),
        ..World::with_wallets(245)
    };
    late.reserved.clear();
    let mut outbox = MemoryOutbox::new();
    outbox.set_max_settled(1);
    let mut pruned = Vec::new();
    for payment in &payments[..2] {
        outbox.commit(payment, &view).unwrap();
        let report = outbox.reconcile(&late.view()).unwrap();
        assert_eq!(report.expired, 1);
        pruned.push(report.pruned);
    }
    assert_eq!(pruned, [0, 1]);
    let kept = outbox.records().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].id, payments[1].id());
    assert_eq!(DEFAULT_MAX_SETTLED, 1024);
}

#[test]
fn an_outbox_belongs_to_one_chain() {
    let world = world_with_coins();
    let view = world.view();
    let (signed, _) = signed_payment(&world, 1_000_000);
    let mut foreign = World::with_wallets(100);
    foreign.state = world.state.clone();
    foreign.anchor.genesis = [0x61; 32];

    let mut outbox = MemoryOutbox::new();
    // Empty and unbound: nothing to reconcile on any chain; the first commit binds it.
    assert_eq!(
        outbox.reconcile(&foreign.view()).unwrap(),
        ReconcileReport::default()
    );
    outbox.commit(&signed, &view).unwrap();
    let wrong = Refusal::WrongContext(ContextField::Genesis);
    assert_eq!(outbox.reconcile(&foreign.view()).unwrap_err(), wrong);
    assert_eq!(outbox.commit(&signed, &foreign.view()).unwrap_err(), wrong);
    // The refusal changed nothing.
    assert_eq!(outbox.pending().unwrap().len(), 1);
    assert_eq!(
        outbox.reconcile(&view).unwrap().still_pending,
        1,
        "the right chain still works"
    );
}

#[test]
fn a_view_older_than_the_queueing_head_says_nothing_about_a_record() {
    let world = world_with_coins();
    let (signed, _) = signed_payment(&world, 1_000_000);
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &world.view()).unwrap(); // queued at height 100
    // At height 90 the coin does not exist yet. That is not a spent input.
    let older = World::with_wallets(90);
    assert_eq!(
        outbox.reconcile(&older.view()).unwrap(),
        ReconcileReport {
            still_pending: 1,
            ..Default::default()
        }
    );
    assert_eq!(
        outbox.get(&signed.id()).unwrap().unwrap().status,
        OutboxStatus::Queued
    );
    assert_eq!(outbox.reserved().unwrap().len(), 1);
    // At its own head, with the coin gone, it is settled.
    let gone = World {
        state: Default::default(),
        ..World::with_wallets(100)
    };
    assert_eq!(outbox.reconcile(&gone.view()).unwrap().inputs_spent, 1);
}

#[test]
fn imported_signed_bytes_are_verified_before_they_can_be_queued() {
    let world = world_with_coins();
    let view = world.view();
    let (signed, planned) = signed_payment(&world, 1_000_000);

    // Bytes signed elsewhere (an offline signer) come back as the same operation, every field
    // derived from the bytes, and can then be queued like any other.
    let imported = SignedOperation::import(signed.bytes(), &view).unwrap();
    assert_eq!(imported, signed);
    assert_eq!(
        MemoryOutbox::new().commit(&imported, &view).unwrap(),
        signed.id()
    );

    // Unsigned bytes, a damaged signature, noise: refused, never guessed at.
    assert!(matches!(
        SignedOperation::import(&planned.objects()[0].bytes, &view),
        Err(Refusal::Malformed(_))
    ));
    let flipped = tampered(&signed, |t| t.inputs[0].signature.fndsa[5] ^= 1);
    assert!(matches!(
        SignedOperation::import(flipped.bytes(), &view),
        Err(Refusal::VerificationFailed(_))
    ));
    assert_eq!(
        SignedOperation::import(&[1, 2, 3], &view).unwrap_err(),
        Refusal::UnknownOperation
    );
    assert_eq!(
        SignedOperation::import(&[], &view).unwrap_err(),
        Refusal::UnknownOperation
    );
    // Another chain's view, and a view in which the coin is already gone.
    let mut foreign = World::with_wallets(100);
    foreign.state = world.state.clone();
    foreign.anchor.genesis = [0x61; 32];
    assert!(matches!(
        SignedOperation::import(signed.bytes(), &foreign.view()),
        Err(Refusal::WrongContext(_))
    ));
    let spent = World {
        state: Default::default(),
        ..World::with_wallets(100)
    };
    assert!(SignedOperation::import(signed.bytes(), &spent.view()).is_err());
}
