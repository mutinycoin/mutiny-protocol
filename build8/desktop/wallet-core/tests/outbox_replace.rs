//! Phase 8 (W1): `Outbox::replace_partial` replaces an OPEN partial record by the complete form of
//! the same operation in one atomic step, in the in-memory and in the durable outbox: a co-funded
//! wallet rotation (the partial and the complete share their identifier) and a hash lock (the
//! complete operation has an identifier of its own). An outbox without its own implementation
//! refuses as `commit` does today, `commit` itself is unchanged, anything that is not the completion
//! of that open partial is refused and changes nothing, and a durable replacement interrupted
//! between its steps (the process dies) leaves the partial or the complete record: never neither,
//! never both. NATIVE, TEST-VALUE; public test keys; the maker is played by the test (Q7).
#[path = "support/conditional_kit.rs"]
mod kit;
#[path = "support/synthetic.rs"]
mod synthetic;
#[path = "support/tempdir.rs"]
mod tempdir;

use mutiny_consensus_v8::{Hash, trading_v1::SignedOffer};
use mutiny_crypto_v2::{HybridKey, Role, rehearsal_keys_v1};
use mutiny_wallet_core_v8::{
    ops::{
        conditional,
        rotation::{self, RotationSigner, combine},
    },
    *,
};
use synthetic::{World, address, identity, key_a, key_b};
use tempdir::TempDir;

const REFUND: u64 = 150;

fn new_key(label: &str) -> HybridKey {
    let phrase = rehearsal_keys_v1::label_phrase(label).unwrap();
    HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
}

/// One operation in parts: the part this wallet queued, the counterparty's part (still partial)
/// and the complete operation.
struct Parts {
    world: World,
    partial: SignedOperation,
    other_part: SignedOperation,
    complete: SignedOperation,
}

/// A rotation of key A funded by key B: the rotating wallet's part, the payer's part and the
/// combined rotation share one identifier.
fn rotation_parts() -> Parts {
    let mut world = World::with_wallets(100);
    world.coin(address(&key_b(), 1), 3_000_000, 1, false, 2, 0);
    let (partial, other_part, complete) = {
        let view = world.view();
        let me = identity(&key_a());
        let payer = identity(&key_b());
        let proposed = new_key("w8-replace-rotation-new")
            .public()
            .descriptor(2)
            .unwrap();
        let request = OperationRequest::WalletRotation(
            RotationRequest::new(
                Blob::new(proposed.clone()),
                FeeSource::OtherWallet(payer.clone()),
            )
            .with_restore_verified(rotation::descriptor_fingerprint(&proposed)),
        );
        let planned = plan(&request, &view, &me).unwrap();
        let session =
            RotationSigner::for_test(key_a(), me, new_key("w8-replace-rotation-new")).unwrap();
        let part_rotation = session
            .authorize(
                planned.clone(),
                kit::approve(&review(&planned, &view).unwrap(), &view),
                &view,
            )
            .unwrap();
        let adopted = adopt(part_rotation.bytes(), &view, &payer).unwrap();
        let part_funding = KeySigner::for_test(key_b())
            .unwrap()
            .authorize(
                adopted.clone(),
                kit::approve(&review(&adopted, &view).unwrap(), &view),
                &view,
            )
            .unwrap();
        let complete = combine(&[part_rotation.bytes(), part_funding.bytes()], &view).unwrap();
        (part_rotation, part_funding, complete)
    };
    Parts {
        world,
        partial,
        other_part,
        complete,
    }
}

/// Head 100; key A holds one 3,000,000 atom coin.
fn lock_world() -> World {
    let mut world = World::with_wallets(100);
    world.coin(address(&key_a(), 1), 3_000_000, 1, false, 1, 0);
    world
}

/// A maker's offer of 1,000,000 atoms on `world`'s chain.
fn lock_offer(world: &World) -> (SignedOffer, HybridKey) {
    let maker = kit::maker_key();
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&world.anchor),
        1,
        1000,
        1_000_000,
        1,
        6,
    );
    (offer, maker)
}

/// A hash lock from key A to key B under `condition`: the sender's part, the recipient's part and
/// the complete operation with the maker's fill, which has its own identifier.
fn lock_parts(world: World, offer: &SignedOffer, maker: &HybridKey, condition: Hash) -> Parts {
    let (partial, other_part, complete) = {
        let view = world.view();
        let request = OperationRequest::HashLock(HashLockRequest::new(
            Blob::new(kit::offer_bytes(offer)),
            address(&key_b(), 1),
            1_000_000,
            condition,
            REFUND,
        ));
        let planned = plan(&request, &view, &identity(&key_a())).unwrap();
        let sender = KeySigner::for_test(key_a())
            .unwrap()
            .authorize(
                planned.clone(),
                kit::approve(&review(&planned, &view).unwrap(), &view),
                &view,
            )
            .unwrap();
        let adopted = adopt(sender.bytes(), &view, &identity(&key_b())).unwrap();
        let recipient = KeySigner::for_test(key_b())
            .unwrap()
            .authorize(
                adopted.clone(),
                kit::approve(&review(&adopted, &view).unwrap(), &view),
                &view,
            )
            .unwrap();
        let fill = kit::fill_for(sender.bytes(), offer, maker);
        let complete =
            conditional::complete(&[sender.bytes(), recipient.bytes()], Some(&fill), &view)
                .unwrap();
        (sender, recipient, complete)
    };
    Parts {
        world,
        partial,
        other_part,
        complete,
    }
}

fn hash_lock_parts() -> Parts {
    let world = lock_world();
    let (offer, maker) = lock_offer(&world);
    lock_parts(world, &offer, &maker, [9; 32])
}

/// Run `check` on a fresh in-memory outbox and on a fresh durable one.
fn with_each_outbox(tag: &str, context: ChainContext, check: impl Fn(&mut dyn Outbox)) {
    check(&mut MemoryOutbox::new());
    let dir = TempDir::new(tag);
    let mut durable = SqliteOutbox::open(&dir.file("outbox.sqlite"), context).unwrap();
    check(&mut durable);
    drop(durable);
    // The durable result reads back the same after a restart.
    let reopened = SqliteOutbox::open(&dir.file("outbox.sqlite"), context).unwrap();
    reopened.records().unwrap();
}

/// An implementation written before `replace_partial` existed, as a host's own outbox may be.
struct OlderOutbox(MemoryOutbox);

impl Outbox for OlderOutbox {
    fn commit(&mut self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<Hash, Refusal> {
        self.0.commit(signed, view)
    }
    fn records(&self) -> Result<Vec<OutboxRecord>, Refusal> {
        self.0.records()
    }
    fn get(&self, id: &Hash) -> Result<Option<OutboxRecord>, Refusal> {
        self.0.get(id)
    }
    fn reconcile(&mut self, view: &ChainView<'_>) -> Result<ReconcileReport, Refusal> {
        self.0.reconcile(view)
    }
    fn forget(&mut self, id: &Hash) -> Result<(), Refusal> {
        self.0.forget(id)
    }
    fn prune_settled(&mut self, keep: usize) -> Result<usize, Refusal> {
        self.0.prune_settled(keep)
    }
}

#[test]
fn an_outbox_without_its_own_replacement_refuses_as_commit_does_today() {
    let parts = rotation_parts();
    let view = parts.world.view();
    let mut outbox = OlderOutbox(MemoryOutbox::new());
    outbox.commit(&parts.partial, &view).unwrap();
    let before = outbox.records().unwrap();
    assert_eq!(
        outbox
            .replace_partial(&parts.partial.id(), &parts.complete, &view)
            .unwrap_err(),
        Refusal::OutboxIntegrity
    );
    assert_eq!(
        outbox.commit(&parts.complete, &view).unwrap_err(),
        Refusal::ReservedInput
    );
    assert_eq!(outbox.records().unwrap(), before);
}

#[test]
fn a_partial_rotation_is_replaced_in_place_by_the_complete_rotation() {
    let parts = rotation_parts();
    let view = parts.world.view();
    assert_ne!(
        parts.complete.id(),
        parts.partial.id(),
        "partial exact-wire identity transitions to the complete native rotation ID"
    );
    with_each_outbox("w8-replace-rotation", view.context(), |outbox| {
        outbox.commit(&parts.partial, &view).unwrap();
        let held = outbox.reserved().unwrap();
        // `commit` is unchanged: other bytes under an open record's identifier are refused.
        assert_eq!(
            outbox.commit(&parts.complete, &view).unwrap_err(),
            Refusal::ReservedInput
        );
        assert_eq!(
            outbox
                .replace_partial(&parts.partial.id(), &parts.complete, &view)
                .unwrap(),
            parts.complete.id()
        );
        let records = outbox.records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].bytes, parts.complete.bytes());
        assert!(records[0].complete && records[0].missing.is_empty());
        assert_eq!(records[0].status, OutboxStatus::Queued);
        assert_eq!(
            outbox.reserved().unwrap(),
            held,
            "the complete record holds exactly what the partial held"
        );
        // Idempotent: the same replacement again, and a commit of the same complete bytes.
        assert_eq!(
            outbox
                .replace_partial(&parts.partial.id(), &parts.complete, &view)
                .unwrap(),
            parts.complete.id()
        );
        assert_eq!(
            outbox.commit(&parts.complete, &view).unwrap(),
            parts.complete.id()
        );
        assert_eq!(outbox.records().unwrap().len(), 1);
    });
}

#[test]
fn a_partial_hash_lock_is_replaced_by_its_completion_under_the_operation_identifier() {
    let parts = hash_lock_parts();
    let view = parts.world.view();
    assert_ne!(
        parts.complete.id(),
        parts.partial.id(),
        "a partial hash lock is identified by its exact bytes"
    );
    with_each_outbox("w8-replace-lock", view.context(), |outbox| {
        outbox.commit(&parts.partial, &view).unwrap();
        let held = outbox.reserved().unwrap();
        // `commit` is unchanged: the completion cannot be queued while the partial holds the coin
        // and the offer.
        assert_eq!(
            outbox.commit(&parts.complete, &view).unwrap_err(),
            Refusal::ReservedInput
        );
        assert_eq!(
            outbox
                .replace_partial(&parts.partial.id(), &parts.complete, &view)
                .unwrap(),
            parts.complete.id()
        );
        assert!(
            outbox.get(&parts.partial.id()).unwrap().is_none(),
            "the partial record is replaced, not kept beside the complete one"
        );
        let record = outbox.get(&parts.complete.id()).unwrap().unwrap();
        assert_eq!(record.bytes, parts.complete.bytes());
        assert!(record.complete && record.missing.is_empty());
        assert_eq!(record.status, OutboxStatus::Queued);
        assert_eq!(outbox.reserved().unwrap(), held);
        assert_eq!(outbox.records().unwrap().len(), 1);
        // A retry after success changes nothing.
        assert_eq!(
            outbox
                .replace_partial(&parts.partial.id(), &parts.complete, &view)
                .unwrap(),
            parts.complete.id()
        );
        assert_eq!(outbox.records().unwrap().len(), 1);
    });
}

#[test]
fn only_the_completion_of_the_same_open_partial_replaces_it_and_a_refusal_changes_nothing() {
    let (offer, maker) = lock_offer(&lock_world());
    let mine = lock_parts(lock_world(), &offer, &maker, [9; 32]);
    // Another operation over the SAME coin, offer and window: only the condition differs.
    let rival = lock_parts(lock_world(), &offer, &maker, [8; 32]);
    assert_eq!(rival.complete.reserved(), mine.complete.reserved());
    assert_eq!(rival.complete.validity(), mine.complete.validity());
    let rotation = rotation_parts();
    let view = mine.world.view();
    let mut late = World::with_wallets(REFUND + 50);
    late.state = mine.world.state.clone();
    with_each_outbox("w8-replace-refusals", view.context(), |outbox| {
        outbox.commit(&mine.partial, &view).unwrap();
        let before = outbox.records().unwrap();
        // No record under that identifier.
        assert_eq!(
            outbox
                .replace_partial(&[0x42; 32], &mine.complete, &view)
                .unwrap_err(),
            Refusal::UnknownOperation
        );
        // Not complete: the counterparty's part.
        assert_eq!(
            outbox
                .replace_partial(&mine.partial.id(), &mine.other_part, &view)
                .unwrap_err(),
            Refusal::OutboxIntegrity
        );
        // The completion of ANOTHER operation over the same coin and offer.
        assert_eq!(
            outbox
                .replace_partial(&mine.partial.id(), &rival.complete, &view)
                .unwrap_err(),
            Refusal::OutboxIntegrity
        );
        // A complete operation of another kind.
        assert_eq!(
            outbox
                .replace_partial(&mine.partial.id(), &rotation.complete, &view)
                .unwrap_err(),
            Refusal::OutboxIntegrity
        );
        // The completion itself, at a head where consensus no longer accepts it.
        assert!(
            outbox
                .replace_partial(&mine.partial.id(), &mine.complete, &late.view())
                .is_err()
        );
        assert_eq!(outbox.records().unwrap(), before, "nothing changed");
        // A forgotten partial is no longer open: there is nothing to replace.
        outbox.forget(&mine.partial.id()).unwrap();
        assert_eq!(
            outbox
                .replace_partial(&mine.partial.id(), &mine.complete, &view)
                .unwrap_err(),
            Refusal::OutboxIntegrity
        );
        // A complete record is not a partial one either.
        outbox.commit(&mine.complete, &view).unwrap();
        assert_eq!(
            outbox
                .replace_partial(&mine.complete.id(), &rival.complete, &view)
                .unwrap_err(),
            Refusal::OutboxIntegrity
        );
        assert_eq!(outbox.records().unwrap().len(), 2);
    });
}

/// A queued partial record exports exactly the container its signing result exports
/// (`PartialApproval::from_record`, which a host's export uses instead of assembling a
/// `SignedOperation` by hand); a record whose checksum fails and a complete record are refused.
#[test]
fn a_queued_partial_record_exports_the_container_of_its_signing_result() {
    let parts = hash_lock_parts();
    let view = parts.world.view();
    let context = view.context();
    let mut outbox = MemoryOutbox::new();
    let id = outbox.commit(&parts.partial, &view).unwrap();
    let record = outbox.get(&id).unwrap().unwrap();
    assert_eq!(
        PartialApproval::from_record(&record, context)
            .unwrap()
            .export()
            .unwrap(),
        PartialApproval::from_signed(&parts.partial, context)
            .unwrap()
            .export()
            .unwrap()
    );
    let mut altered = record.clone();
    altered.validity.expiry += 1;
    assert_eq!(
        PartialApproval::from_record(&altered, context).unwrap_err(),
        Refusal::OutboxIntegrity
    );
    let complete_id = outbox.replace_partial(&id, &parts.complete, &view).unwrap();
    let complete = outbox.get(&complete_id).unwrap().unwrap();
    assert_eq!(
        PartialApproval::from_record(&complete, context).unwrap_err(),
        Refusal::PartialInvalid("a complete operation is not a partial approval")
    );
}

const CRASH_CHILD: &str = "WALLET_CORE_REPLACE_CRASH_CHILD";

/// The child's observer: end the process at the step named in its environment, at once (no
/// destructors, no graceful close of the database).
fn die_at(step: &'static str) {
    let spec = std::env::var(CRASH_CHILD).unwrap_or_default();
    if spec.split('|').next() == Some(step) {
        std::process::exit(86);
    }
}

/// The process dies inside the replacement transaction (after the partial is removed, after the
/// complete record is inserted), right after the commit, and right after the call returned. A
/// restart finds exactly one record with its reservations: the partial in the first two cases,
/// the complete operation in the last two.
#[test]
fn a_durable_replacement_leaves_the_partial_or_the_complete_record_whenever_the_process_dies() {
    if let Ok(spec) = std::env::var(CRASH_CHILD) {
        // ---- child process: queue the partial, replace it, die at the requested step
        let mut fields = spec.splitn(3, '|');
        let (_step, kind, dir) = (
            fields.next().unwrap(),
            fields.next().unwrap(),
            std::path::PathBuf::from(fields.next().unwrap()),
        );
        let parts = if kind == "rotation" {
            rotation_parts()
        } else {
            hash_lock_parts()
        };
        let view = parts.world.view();
        let mut outbox = SqliteOutbox::open(&dir.join("outbox.sqlite"), view.context()).unwrap();
        outbox.commit(&parts.partial, &view).unwrap();
        std::fs::write(dir.join("partial.bin"), parts.partial.bytes()).unwrap();
        std::fs::write(dir.join("complete.bin"), parts.complete.bytes()).unwrap();
        outbox.observe_replacement_for_test(die_at);
        outbox
            .replace_partial(&parts.partial.id(), &parts.complete, &view)
            .unwrap();
        die_at("returned");
        unreachable!("every mode ends the child");
    }

    let context = World::with_wallets(100).view().context();
    for kind in ["rotation", "hash-lock"] {
        for step in [
            "partial-removed",
            "complete-inserted",
            "committed",
            "returned",
        ] {
            let dir = TempDir::new("w8-replace-crash");
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "a_durable_replacement_leaves_the_partial_or_the_complete_record_whenever_the_process_dies",
                    "--test-threads=1",
                ])
                .env(CRASH_CHILD, format!("{step}|{kind}|{}", dir.path().display()))
                .output()
                .unwrap()
                .status;
            assert_eq!(status.code(), Some(86), "the child reached {step} ({kind})");
            let outbox = SqliteOutbox::open(&dir.file("outbox.sqlite"), context)
                .expect("a killed process leaves a valid database");
            let partial = std::fs::read(dir.file("partial.bin")).unwrap();
            let complete = std::fs::read(dir.file("complete.bin")).unwrap();
            // `records` also cross-checks the reservation rows against the open records.
            let records = outbox.records().unwrap();
            assert_eq!(records.len(), 1, "exactly one record ({kind}, {step})");
            let replaced = matches!(step, "committed" | "returned");
            let expected = if replaced { &complete } else { &partial };
            assert_eq!(&records[0].bytes, expected, "{kind}, {step}");
            assert_eq!(records[0].complete, replaced);
            assert_eq!(records[0].status, OutboxStatus::Queued);
            assert_eq!(
                outbox.reserved().unwrap(),
                records[0].reserved.iter().cloned().collect(),
                "the surviving record holds its reservations ({kind}, {step})"
            );
        }
    }
}

#[test]
fn the_replacement_observer_exists_only_behind_the_non_shipping_cfg() {
    const CFG: &str = "#[cfg(any(test, feature = \"test-value-signing\"))]";
    const NOT_CFG: &str = "#[cfg(not(any(test, feature = \"test-value-signing\")))]";
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/outbox_sqlite.rs"),
    )
    .unwrap()
    .replace('\r', "");
    let lines: Vec<&str> = text.lines().collect();
    // The attributes directly above the (only) line containing `needle`.
    let attributes_of = |needle: &str| -> Vec<&str> {
        let found: Vec<usize> = (0..lines.len())
            .filter(|&index| lines[index].contains(needle))
            .collect();
        assert_eq!(found.len(), 1, "{needle}");
        let mut attributes = Vec::new();
        for above in lines[..found[0]].iter().rev() {
            let above = above.trim();
            if above.starts_with("#[") {
                attributes.push(above);
            } else if !above.starts_with("//") {
                break;
            }
        }
        attributes
    };
    // The only way to install an observer is the test-build setter; the field itself is private.
    assert!(attributes_of("pub fn observe_replacement_for_test(").contains(&CFG));
    assert!(!attributes_of("pub fn observe_replacement_for_test(").contains(&NOT_CFG));
    assert!(text.contains("    observer: Observer,\n"));
    assert!(!text.contains("pub observer"));
    assert_eq!(text.matches("observer: Some(").count(), 0);
    assert_eq!(text.matches("self.observer = Some(observer);").count(), 1);
}
