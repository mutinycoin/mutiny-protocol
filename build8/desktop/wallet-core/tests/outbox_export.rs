//! The view-verified export of queued operations (Order W6). `Outbox::export_verified` re-verifies
//! a record against the verified view before releasing its bytes: the bytes and what they commit
//! to, the approval binding recorded by `Outbox::commit_approved`, the status from verified state
//! and every signature through consensus code. `Outbox::pending` (unkeyed checksum only) is not
//! for delivery. Every scenario runs against the in-memory and the durable outbox.
//! NATIVE, TEST-VALUE; public test keys only.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;
#[path = "support/tempdir.rs"]
mod tempdir;

use mutiny_consensus_v8::{
    Hash,
    transactions::{Coin, OutPoint, Output},
    transactions_v2::Transfer,
};
use mutiny_wallet_core_v8::{refusal::ContextField, *};
use synthetic::{World, address, identity, key_a, key_b};

fn pay(recipient: [u8; 32], amount: u64) -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(recipient, amount))
}

/// Key A owns two coins, so two payments can be built over disjoint coins.
fn world_with_coins() -> World {
    let mut world = World::new(100);
    let owner = address(&key_a(), 1);
    world.coin(owner, 5_000_000, 1, false, 1, 0);
    world.coin(owner, 2_000_000, 1, false, 2, 0);
    world
}

/// A payment planned, reviewed, approved and authorized at `world`'s head, with the binding of the
/// approval it was authorized with.
fn approved_payment(world: &World, amount: u64) -> (SignedOperation, ApprovalBinding) {
    let view = world.view();
    let planned = plan(
        &pay(address(&key_b(), 1), amount),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let approval = flow::approve(&reviewed, &view);
    let binding = approval.binding();
    assert_eq!(binding.digest(), reviewed.binding());
    assert_eq!(binding.kind(), OperationKind::Payment);
    let signer = KeySigner::for_test(key_a()).unwrap();
    (signer.authorize(planned, approval, &view).unwrap(), binding)
}

/// A second payment by key A over coins `first` does not use: planned against a view that reserves
/// `first`'s inputs, as a host's view carries its outbox's reservations.
fn approved_payment_avoiding(
    world: &World,
    first: &SignedOperation,
    amount: u64,
) -> (SignedOperation, ApprovalBinding) {
    let reserving = World {
        state: world.state.clone(),
        anchor: world.anchor.clone(),
        reserved: first.reserved().iter().cloned().collect(),
        timestamp: world.timestamp,
    };
    approved_payment(&reserving, amount)
}

/// The two outbox implementations behind one interface, with their test-only store rewrite.
enum Store {
    Memory(MemoryOutbox),
    /// The temporary directory is kept alive with the store.
    Durable {
        outbox: SqliteOutbox,
        _dir: tempdir::TempDir,
    },
}

impl Store {
    fn both(world: &World) -> [Store; 2] {
        let dir = tempdir::TempDir::new("export");
        let durable =
            SqliteOutbox::open(&dir.file("outbox.sqlite"), world.view().context()).unwrap();
        [
            Store::Memory(MemoryOutbox::new()),
            Store::Durable {
                outbox: durable,
                _dir: dir,
            },
        ]
    }
    fn outbox(&mut self) -> &mut dyn Outbox {
        match self {
            Store::Memory(outbox) => outbox,
            Store::Durable { outbox, .. } => outbox,
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Store::Memory(_) => "memory",
            Store::Durable { .. } => "sqlite",
        }
    }
    /// Rewrite a stored record and its checksum, as someone who can rewrite the store could.
    fn rewrite(&mut self, id: &Hash, edit: impl FnOnce(&mut OutboxRecord)) {
        match self {
            Store::Memory(outbox) => outbox.rewrite_for_test(id, edit),
            Store::Durable { outbox, .. } => outbox.rewrite_for_test(id, edit),
        }
    }
}

#[test]
fn an_approved_operation_exports_with_its_binding_and_a_plain_commit_as_not_recorded() {
    let world = world_with_coins();
    let view = world.view();
    let (approved, binding) = approved_payment(&world, 1_000_000);
    let (plain, plain_binding) = approved_payment_avoiding(&world, &approved, 1_500_000);
    assert!(
        approved
            .reserved()
            .iter()
            .all(|point| !plain.reserved().contains(point)),
        "two payments over disjoint coins"
    );
    for mut store in Store::both(&world) {
        let name = store.name();
        let outbox = store.outbox();
        let id = outbox.commit_approved(&approved, &binding, &view).unwrap();
        assert_eq!(id, approved.id());
        let other = outbox.commit(&plain, &view).unwrap();
        let export = outbox.export_verified(&id, &view).unwrap();
        assert_eq!(
            (export.id, export.kind, export.complete, export.verified_at),
            (id, OperationKind::Payment, true, 100),
            "{name}"
        );
        assert_eq!(export.bytes, approved.bytes(), "{name}");
        assert!(export.missing.is_empty());
        assert_eq!(&export.validity, approved.validity());
        assert_eq!(
            export.approval,
            ApprovalEvidence::Recorded(binding.clone()),
            "{name}"
        );
        assert_eq!(
            outbox.get(&id).unwrap().unwrap().approval(),
            Some(&binding),
            "{name}"
        );
        // Queued without a binding: exported, and nothing is claimed about an approval.
        let export = outbox.export_verified(&other, &view).unwrap();
        assert_eq!(export.approval, ApprovalEvidence::NotRecorded, "{name}");
        assert_eq!(outbox.get(&other).unwrap().unwrap().approval(), None);
        // Idempotent under the same binding; the same bytes under another binding, or under their
        // own binding after they were queued without one, are refused.
        assert_eq!(outbox.commit_approved(&approved, &binding, &view), Ok(id));
        assert_eq!(
            outbox.commit(&approved, &view),
            Ok(id),
            "plain commit is unchanged"
        );
        assert_eq!(
            outbox.commit_approved(&approved, &plain_binding, &view),
            Err(Refusal::ApprovalBindingMismatch(
                "the operation is already queued under another approval binding"
            )),
            "{name}"
        );
        assert_eq!(
            outbox.commit_approved(&plain, &plain_binding, &view),
            Err(Refusal::ApprovalBindingMismatch(
                "the operation is already queued under another approval binding"
            )),
            "{name}"
        );
        assert_eq!(
            outbox.export_verified(&[9; 32], &view),
            Err(Refusal::UnknownOperation)
        );
        // pending() still lists both: it is the unkeyed listing, not the export for delivery.
        assert_eq!(outbox.pending().unwrap().len(), 2);
    }
}

#[test]
fn the_binding_survives_a_restart_and_a_record_without_one_keeps_its_old_encoding() {
    let world = world_with_coins();
    let view = world.view();
    let (approved, binding) = approved_payment(&world, 1_000_000);
    let (plain, _) = approved_payment_avoiding(&world, &approved, 1_500_000);
    let dir = tempdir::TempDir::new("export-restart");
    let path = dir.file("outbox.sqlite");
    {
        let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();
        outbox.commit_approved(&approved, &binding, &view).unwrap();
        outbox.commit(&plain, &view).unwrap();
    }
    let outbox = SqliteOutbox::open(&path, view.context()).unwrap();
    assert_eq!(
        outbox
            .export_verified(&approved.id(), &view)
            .unwrap()
            .approval,
        ApprovalEvidence::Recorded(binding)
    );
    assert_eq!(
        outbox.export_verified(&plain.id(), &view).unwrap().approval,
        ApprovalEvidence::NotRecorded
    );
    drop(outbox);
    // The stored metadata: five fields without a binding (exactly the encoding before W6, so the
    // records of an older outbox still verify), six with one.
    let db = rusqlite::Connection::open(&path).unwrap();
    let meta = |id: &Hash| -> Vec<u8> {
        db.query_row(
            "SELECT meta FROM outbox_records_v1 WHERE id=?1",
            [id.as_slice()],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(meta(&plain.id())[0], 0x85, "CBOR array of five");
    assert_eq!(meta(&approved.id())[0], 0x86, "CBOR array of six");
}

#[test]
fn a_binding_that_does_not_fit_the_bytes_is_refused_at_commit() {
    let world = world_with_coins();
    let view = world.view();
    let (first, first_binding) = approved_payment(&world, 1_000_000);
    let (_, second_binding) = approved_payment(&world, 1_500_000);
    // A binding from another chain (another Genesis), and one for a later head than the view.
    let mut foreign = World {
        state: world.state.clone(),
        ..World::new(100)
    };
    foreign.anchor.genesis = [8; 32];
    let (_, foreign_binding) = approved_payment(&foreign, 1_000_000);
    let later = world.advanced();
    let (_, later_binding) = approved_payment(&later, 1_000_000);
    for mut store in Store::both(&world) {
        let name = store.name();
        let outbox = store.outbox();
        assert_eq!(
            outbox.commit_approved(&first, &second_binding, &view),
            Err(Refusal::ApprovalBindingMismatch(
                "the bytes are not the operation the approval was given for"
            )),
            "{name}"
        );
        assert_eq!(
            outbox.commit_approved(&first, &foreign_binding, &view),
            Err(Refusal::WrongContext(ContextField::Genesis)),
            "{name}"
        );
        assert_eq!(
            outbox.commit_approved(&first, &later_binding, &view),
            Err(Refusal::ApprovalBindingMismatch(
                "the approval is for a later head than the verified view"
            )),
            "{name}"
        );
        assert!(
            outbox.records().unwrap().is_empty(),
            "{name}: nothing queued"
        );
        // The right binding is accepted.
        assert!(
            outbox
                .commit_approved(&first, &first_binding, &view)
                .is_ok()
        );
    }
}

#[test]
fn a_rewritten_store_is_refused_at_export_even_with_a_recomputed_checksum() {
    let world = world_with_coins();
    let view = world.view();
    let (first, first_binding) = approved_payment(&world, 1_000_000);
    let (second, second_binding) = approved_payment(&world, 1_500_000);
    for mut store in Store::both(&world) {
        let name = store.name();
        let id = store
            .outbox()
            .commit_approved(&first, &first_binding, &view)
            .unwrap();

        // A signature byte flipped: the bytes still decode and describe the same operation, the
        // binding still fits (it binds the unsigned form), and consensus verification refuses.
        store.rewrite(&id, |record| {
            let mut transfer = Transfer::decode(&record.bytes).unwrap();
            transfer.inputs[0].signature.ed448[7] ^= 1;
            record.bytes = transfer.encode().unwrap();
        });
        let pending = store.outbox().pending().unwrap();
        assert_eq!(
            pending.len(),
            1,
            "{name}: pending() does not notice the rewrite"
        );
        let refused = store.outbox().export_verified(&id, &view).unwrap_err();
        assert_eq!(refused.code(), "VERIFICATION_FAILED", "{name}: {refused:?}");

        // Another validly signed operation's bytes under this record's identifier and metadata:
        // the bytes commit to another identifier.
        store.rewrite(&id, |record| record.bytes = second.bytes().to_vec());
        assert_eq!(
            store.outbox().export_verified(&id, &view),
            Err(Refusal::OutboxIntegrity),
            "{name}"
        );

        // Bytes that are no operation at all.
        store.rewrite(&id, |record| record.bytes = vec![0x80]);
        assert!(
            store.outbox().export_verified(&id, &view).is_err(),
            "{name}"
        );

        // The original bytes back, but the binding of another approval: the wrong approval.
        store.rewrite(&id, |record| {
            record.bytes = first.bytes().to_vec();
            record.set_approval_for_test(Some(second_binding.clone()));
        });
        assert_eq!(
            store.outbox().export_verified(&id, &view),
            Err(Refusal::ApprovalBindingMismatch(
                "the bytes are not the operation the approval was given for"
            )),
            "{name}"
        );

        // Restored exactly: exported again (the control).
        store.rewrite(&id, |record| {
            record.set_approval_for_test(Some(first_binding.clone()))
        });
        assert!(store.outbox().export_verified(&id, &view).is_ok(), "{name}");
    }
}

#[test]
fn a_view_of_another_chain_is_refused() {
    let world = world_with_coins();
    let (signed, binding) = approved_payment(&world, 1_000_000);
    let mut foreign = World {
        state: world.state.clone(),
        ..World::new(100)
    };
    foreign.anchor.genesis = [8; 32];
    for mut store in Store::both(&world) {
        let name = store.name();
        let outbox = store.outbox();
        let id = outbox
            .commit_approved(&signed, &binding, &world.view())
            .unwrap();
        assert_eq!(
            outbox.export_verified(&id, &foreign.view()),
            Err(Refusal::WrongContext(ContextField::Genesis)),
            "{name}"
        );
    }
    // The default export of an outbox that does not know its chain refuses through the recorded
    // binding (and, without one, through consensus verification of the bytes).
    let mut memory = MemoryOutbox::new();
    let id = memory
        .commit_approved(&signed, &binding, &world.view())
        .unwrap();
    let record = memory.get(&id).unwrap().unwrap();
    assert_eq!(
        export::verify_record(&record, &foreign.view()),
        Err(Refusal::WrongContext(ContextField::Genesis))
    );
}

#[test]
fn stale_expired_confirmed_conflicting_and_forgotten_records_say_so() {
    let world = world_with_coins();
    let (signed, binding) = approved_payment(&world, 1_000_000);
    let transfer = Transfer::decode(signed.bytes()).unwrap();
    let id = signed.id();
    let expiry = signed.validity().expiry;
    let at = |height: u64| World {
        state: world.state.clone(),
        ..World::new(height)
    };
    let not = |status| Err(Refusal::NotDeliverable(status));

    // Stale: a view older than the head the record was queued at.
    let stale = at(99);
    // Expired: the window ended.
    let late = at(expiry);
    // Confirmed: one of its outputs exists as a coin it created.
    let mut included = at(120);
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
    // Conflicting: its input was spent by something else.
    let mut spent = at(110);
    for point in signed.reserved() {
        spent.state.coins.remove(point);
    }

    for mut store in Store::both(&world) {
        let name = store.name();
        let outbox = store.outbox();
        outbox
            .commit_approved(&signed, &binding, &world.view())
            .unwrap();
        assert!(outbox.export_verified(&id, &world.view()).is_ok(), "{name}");
        assert_eq!(
            outbox.export_verified(&id, &stale.view()),
            not(DeliveryStatus::Stale {
                queued_at: 100,
                view_height: 99
            }),
            "{name}"
        );
        assert_eq!(
            outbox.export_verified(&id, &late.view()),
            not(DeliveryStatus::Expired {
                expiry,
                next_height: expiry + 1
            }),
            "{name}"
        );
        assert_eq!(
            outbox.export_verified(&id, &included.view()),
            not(DeliveryStatus::Confirmed(118)),
            "{name}"
        );
        assert_eq!(
            outbox.export_verified(&id, &spent.view()),
            not(DeliveryStatus::Conflicting),
            "{name}"
        );
        // The last view before expiry still exports.
        assert!(
            outbox.export_verified(&id, &at(expiry - 1).view()).is_ok(),
            "{name}"
        );
    }

    // A settled or forgotten status refuses (the stored status may refuse, never release): a
    // forgotten record, and a record a reconciliation settled.
    for mut store in Store::both(&world) {
        let name = store.name();
        let outbox = store.outbox();
        outbox
            .commit_approved(&signed, &binding, &world.view())
            .unwrap();
        outbox.forget(&id).unwrap();
        assert_eq!(
            outbox.export_verified(&id, &world.view()),
            not(DeliveryStatus::Forgotten),
            "{name}"
        );
    }
    for mut store in Store::both(&world) {
        let name = store.name();
        let outbox = store.outbox();
        outbox
            .commit_approved(&signed, &binding, &world.view())
            .unwrap();
        assert_eq!(outbox.reconcile(&spent.view()).unwrap().inputs_spent, 1);
        // Even judged at the queueing view, where the coin still exists, it stays refused.
        assert_eq!(
            outbox.export_verified(&id, &world.view()),
            not(DeliveryStatus::Conflicting),
            "{name}"
        );
    }
    let codes: Vec<&str> = [
        DeliveryStatus::Stale {
            queued_at: 1,
            view_height: 0,
        },
        DeliveryStatus::Confirmed(1),
        DeliveryStatus::Expired {
            expiry: 1,
            next_height: 2,
        },
        DeliveryStatus::Conflicting,
        DeliveryStatus::Stranded(1),
        DeliveryStatus::Forgotten,
    ]
    .iter()
    .map(|status| {
        assert!(!status.to_string().is_empty());
        status.code()
    })
    .collect();
    assert_eq!(
        codes,
        [
            "STALE",
            "CONFIRMED",
            "EXPIRED",
            "CONFLICTING",
            "STRANDED",
            "FORGOTTEN"
        ]
    );
}
