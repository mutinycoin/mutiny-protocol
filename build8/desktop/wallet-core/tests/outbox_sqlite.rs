//! The durable outbox: exact bytes and reservations survive a restart, a failed commit leaves no
//! trace, reconciliation persists, and a damaged or foreign database file is refused. NATIVE,
//! TEST-VALUE; public test keys only.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;
#[path = "support/tempdir.rs"]
mod tempdir;

use mutiny_consensus_v8::{
    transactions::{Coin, OutPoint, Output},
    transactions_v2::Transfer,
};
use mutiny_wallet_core_v8::*;
use rusqlite::Connection;
use synthetic::{World, address, identity, key_a, key_b};
use tempdir::TempDir;

fn pay(recipient: [u8; 32], amount: u64) -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(recipient, amount))
}

fn world() -> World {
    let mut world = World::new(100);
    let owner = address(&key_a(), 1);
    world.coin(owner, 5_000_000, 1, false, 1, 0);
    world.coin(owner, 2_000_000, 1, false, 2, 0);
    world
}

fn signed_payment(world: &World, amount: u64) -> SignedOperation {
    let view = world.view();
    let planned = plan(
        &pay(address(&key_b(), 1), amount),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    flow::sign(planned, &KeySigner::for_test(key_a()).unwrap(), &view).unwrap()
}

fn count(path: &std::path::Path, table: &str) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn tamper(path: &std::path::Path, sql: &str) {
    // An attacker with the file is not bound by the application's foreign-key setting.
    Connection::open(path)
        .unwrap()
        .execute_batch(&format!("PRAGMA foreign_keys = OFF; {sql}"))
        .unwrap();
}

#[test]
fn the_exact_bytes_and_their_reservations_survive_a_restart() {
    let dir = TempDir::new("restart");
    let path = dir.file("outbox.sqlite");
    let world = world();
    let view = world.view();
    let signed = signed_payment(&world, 1_000_000);
    {
        let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();
        assert!(outbox.records().unwrap().is_empty());
        assert_eq!(outbox.commit(&signed, &view).unwrap(), signed.id());
        assert_eq!(
            outbox.commit(&signed, &view).unwrap(),
            signed.id(),
            "idempotent"
        );
        assert_eq!(outbox.records().unwrap().len(), 1);
    }
    // A new process opening the same file sees exactly what was committed.
    let outbox = SqliteOutbox::open(&path, view.context()).unwrap();
    let records = outbox.records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].bytes, signed.bytes());
    assert_eq!(records[0].id, signed.id());
    assert_eq!(records[0].kind, OperationKind::Payment);
    assert_eq!(records[0].status, OutboxStatus::Queued);
    assert!(records[0].complete && records[0].missing.is_empty());
    assert_eq!(records[0].validity, *signed.validity());
    assert_eq!(records[0].queued_at_height, 100);
    assert_eq!(
        outbox.reserved().unwrap(),
        signed.reserved().iter().cloned().collect()
    );
    assert_eq!(outbox.pending().unwrap().len(), 1);
    assert_eq!(
        outbox.get(&signed.id()).unwrap().unwrap().bytes,
        signed.bytes()
    );
    assert!(outbox.get(&[0x42; 32]).unwrap().is_none());
    assert_eq!(count(&path, "outbox_records_v1"), 1);
    assert_eq!(count(&path, "outbox_inputs_v1"), 1);
}

#[test]
fn a_refused_commit_leaves_no_trace_and_a_conflicting_one_is_refused() {
    let dir = TempDir::new("refused");
    let path = dir.file("outbox.sqlite");
    let world = world();
    let view = world.view();
    let first = signed_payment(&world, 1_000_000);
    let second = signed_payment(&world, 1_100_000); // over the same coin
    let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();

    // A payment whose signature does not verify is refused before anything is written.
    let mut transfer = Transfer::decode(first.bytes()).unwrap();
    transfer.inputs[0].signature.ed448[0] ^= 1;
    let forged = SignedOperation::Complete {
        kind: OperationKind::Payment,
        id: first.id(),
        bytes: transfer.encode().unwrap(),
        validity: *first.validity(),
        reserved: first.reserved().to_vec(),
    };
    assert!(matches!(
        outbox.commit(&forged, &view),
        Err(Refusal::VerificationFailed(_))
    ));
    assert_eq!(
        (
            count(&path, "outbox_records_v1"),
            count(&path, "outbox_inputs_v1")
        ),
        (0, 0)
    );

    outbox.commit(&first, &view).unwrap();
    assert_eq!(
        outbox.commit(&second, &view).unwrap_err(),
        Refusal::ReservedInput
    );
    assert_eq!(
        (
            count(&path, "outbox_records_v1"),
            count(&path, "outbox_inputs_v1")
        ),
        (1, 1),
        "the refused commit changed nothing"
    );
    // The identifier of a record is the one its BYTES commit to: a caller claiming the id of the
    // stored record for different bytes is refused, and the stored record is untouched.
    let impostor = SignedOperation::Complete {
        kind: OperationKind::Payment,
        id: first.id(),
        bytes: second.bytes().to_vec(),
        validity: *first.validity(),
        reserved: first.reserved().to_vec(),
    };
    assert!(matches!(
        outbox.commit(&impostor, &view),
        Err(Refusal::VerificationFailed(_))
    ));
    assert_eq!(
        outbox.get(&first.id()).unwrap().unwrap().bytes,
        first.bytes()
    );
    assert_eq!(
        (
            count(&path, "outbox_records_v1"),
            count(&path, "outbox_inputs_v1")
        ),
        (1, 1)
    );
    // A view of another chain cannot commit into this database.
    let mut other = World::new(100);
    other.state = world.state.clone();
    other.anchor.genesis = [0x61; 32];
    assert_eq!(
        outbox.commit(&first, &other.view()).unwrap_err(),
        Refusal::WrongContext(ContextField::Genesis)
    );
}

#[test]
fn forget_releases_reservations_but_never_revokes_and_survives_restart() {
    let dir = TempDir::new("forget");
    let path = dir.file("outbox.sqlite");
    let world = world();
    let view = world.view();
    let first = signed_payment(&world, 1_000_000);
    let second = signed_payment(&world, 1_100_000);
    {
        let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();
        outbox.commit(&first, &view).unwrap();
        outbox.forget(&first.id()).unwrap();
        assert!(outbox.reserved().unwrap().is_empty());
        assert_eq!(
            outbox.get(&first.id()).unwrap().unwrap().status,
            OutboxStatus::Forgotten
        );
        assert_eq!(
            outbox.get(&first.id()).unwrap().unwrap().bytes,
            first.bytes(),
            "the bytes are kept as they were signed"
        );
        outbox.commit(&second, &view).unwrap();
        assert_eq!(
            outbox.commit(&first, &view).unwrap_err(),
            Refusal::ReservedInput,
            "a forgotten record cannot take the coin back"
        );
        assert_eq!(
            outbox.forget(&[0x99; 32]).unwrap_err(),
            Refusal::UnknownOperation
        );
    }
    let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();
    assert_eq!(
        outbox.get(&first.id()).unwrap().unwrap().status,
        OutboxStatus::Forgotten
    );
    assert_eq!(
        outbox.get(&second.id()).unwrap().unwrap().status,
        OutboxStatus::Queued
    );
    outbox.forget(&second.id()).unwrap();
    outbox.commit(&first, &view).unwrap();
    assert_eq!(
        outbox.get(&first.id()).unwrap().unwrap().status,
        OutboxStatus::Queued
    );
    assert_eq!(count(&path, "outbox_inputs_v1"), 1);
}

#[test]
fn reconciliation_is_persistent_and_reads_verified_state_only() {
    let dir = TempDir::new("reconcile");
    let world = world();
    let signed = signed_payment(&world, 1_000_000);
    let transfer = Transfer::decode(signed.bytes()).unwrap();
    let ctx = world.view().context();

    let queue = |name: &str| {
        let path = dir.file(name);
        let mut outbox = SqliteOutbox::open(&path, ctx).unwrap();
        outbox.commit(&signed, &world.view()).unwrap();
        (path, outbox)
    };

    // Pending stays queued.
    let (path, mut outbox) = queue("pending.sqlite");
    assert_eq!(
        outbox.reconcile(&world.view()).unwrap(),
        ReconcileReport {
            still_pending: 1,
            ..Default::default()
        }
    );
    drop(outbox);
    assert_eq!(count(&path, "outbox_inputs_v1"), 1);

    // Confirmed by an output coin; persists across a restart and releases the reservation.
    let mut included = World {
        state: world.state.clone(),
        ..World::new(120)
    };
    for point in signed.reserved() {
        included.state.coins.remove(point);
    }
    included.state.coins.insert(
        OutPoint {
            transaction: signed.id(),
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
    let (path, mut outbox) = queue("confirmed.sqlite");
    assert_eq!(outbox.reconcile(&included.view()).unwrap().confirmed, 1);
    drop(outbox);
    let outbox = SqliteOutbox::open(&path, ctx).unwrap();
    assert_eq!(
        outbox.get(&signed.id()).unwrap().unwrap().status,
        OutboxStatus::Confirmed(118)
    );
    assert!(outbox.reserved().unwrap().is_empty());
    assert_eq!(count(&path, "outbox_inputs_v1"), 0);
    drop(outbox);

    // Expired.
    let mut late = World {
        state: world.state.clone(),
        ..World::new(245)
    };
    late.reserved.clear();
    let (path, mut outbox) = queue("expired.sqlite");
    assert_eq!(outbox.reconcile(&late.view()).unwrap().expired, 1);
    drop(outbox);
    assert_eq!(
        SqliteOutbox::open(&path, ctx)
            .unwrap()
            .get(&signed.id())
            .unwrap()
            .unwrap()
            .status,
        OutboxStatus::Expired
    );

    // Inputs gone with no evidence this payment spent them.
    let mut gone = World {
        state: world.state.clone(),
        ..World::new(120)
    };
    for point in signed.reserved() {
        gone.state.coins.remove(point);
    }
    let (path, mut outbox) = queue("spent.sqlite");
    assert_eq!(outbox.reconcile(&gone.view()).unwrap().inputs_spent, 1);
    drop(outbox);
    assert_eq!(
        SqliteOutbox::open(&path, ctx)
            .unwrap()
            .get(&signed.id())
            .unwrap()
            .unwrap()
            .status,
        OutboxStatus::InputsSpent
    );
}

#[test]
fn limits_are_enforced() {
    let dir = TempDir::new("limits");
    let world = world();
    let view = world.view();
    let first = signed_payment(&world, 1_000_000);
    let mut second_world = World::new(100);
    second_world.coin(address(&key_a(), 1), 2_000_000, 1, false, 2, 0);
    let second = signed_payment(&second_world, 500_000);
    let mut one =
        SqliteOutbox::open_with_limits(&dir.file("one.sqlite"), view.context(), 1, 1 << 20)
            .unwrap();
    one.commit(&first, &view).unwrap();
    assert_eq!(one.commit(&second, &view).unwrap_err(), Refusal::OutboxFull);
    assert_eq!(
        one.commit(&first, &view).unwrap(),
        first.id(),
        "an existing record is not a new record"
    );
    let mut tiny =
        SqliteOutbox::open_with_limits(&dir.file("tiny.sqlite"), view.context(), 10, 1000).unwrap();
    assert_eq!(tiny.commit(&first, &view).unwrap_err(), Refusal::OutboxFull);
    assert!(tiny.records().unwrap().is_empty());
}

#[test]
fn any_damage_to_the_file_is_detected_on_open_and_on_read() {
    let world = world();
    let view = world.view();
    let signed = signed_payment(&world, 1_000_000);
    let ctx = view.context();
    let fresh = |dir: &TempDir, name: &str| {
        let path = dir.file(name);
        let mut outbox = SqliteOutbox::open(&path, ctx).unwrap();
        outbox.commit(&signed, &view).unwrap();
        drop(outbox);
        path
    };
    let dir = TempDir::new("damage");

    // Every one of these edits must be refused when the file is opened again.
    let edits: &[(&str, &str)] = &[
        (
            "raw bytes",
            "UPDATE outbox_records_v1 SET raw = X'01' || substr(raw, 2)",
        ),
        (
            "metadata",
            "UPDATE outbox_records_v1 SET meta = X'8500' || substr(meta, 3)",
        ),
        (
            "checksum",
            "UPDATE outbox_records_v1 SET checksum = zeroblob(32)",
        ),
        (
            "identifier",
            "UPDATE outbox_records_v1 SET id = zeroblob(32)",
        ),
        ("kind", "UPDATE outbox_records_v1 SET kind = 2"),
        (
            "status without releasing",
            "UPDATE outbox_records_v1 SET status = 1, status_height = 7",
        ),
        (
            "status unknown",
            "PRAGMA ignore_check_constraints = ON; UPDATE outbox_records_v1 SET status = 9",
        ),
        ("reservation removed", "DELETE FROM outbox_inputs_v1"),
        (
            "reservation added",
            "INSERT INTO outbox_inputs_v1(txid, idx, record) SELECT zeroblob(32), 5, id FROM outbox_records_v1",
        ),
        ("extra table", "CREATE TABLE sneaky(x)"),
        (
            "extra trigger",
            "CREATE TRIGGER sneaky AFTER INSERT ON outbox_records_v1 BEGIN SELECT 1; END",
        ),
        (
            "extra index",
            "CREATE INDEX sneaky ON outbox_records_v1(kind)",
        ),
        ("application id", "PRAGMA application_id = 1"),
        ("schema version", "PRAGMA user_version = 2"),
        (
            "context",
            "UPDATE outbox_context_v1 SET genesis = zeroblob(32)",
        ),
    ];
    for (index, (what, sql)) in edits.iter().enumerate() {
        let path = fresh(&dir, &format!("damaged-{index}.sqlite"));
        tamper(&path, sql);
        let refusal = SqliteOutbox::open(&path, ctx).expect_err(what);
        assert!(
            matches!(refusal, Refusal::OutboxIntegrity | Refusal::WrongContext(_)),
            "{what}: {refusal:?}"
        );
    }

    // Damage that happens while the outbox is open is caught on the next read.
    let path = fresh(&dir, "live.sqlite");
    let mut outbox = SqliteOutbox::open(&path, ctx).unwrap();
    tamper(
        &path,
        "UPDATE outbox_records_v1 SET raw = X'01' || substr(raw, 2)",
    );
    assert_eq!(outbox.records().unwrap_err(), Refusal::OutboxIntegrity);
    assert_eq!(
        outbox.get(&signed.id()).unwrap_err(),
        Refusal::OutboxIntegrity
    );
    assert_eq!(outbox.reserved().unwrap_err(), Refusal::OutboxIntegrity);
    assert_eq!(
        outbox.commit(&signed, &view).unwrap_err(),
        Refusal::OutboxIntegrity,
        "committing over a damaged record is refused, not papered over"
    );
    assert_eq!(
        outbox.reconcile(&view).unwrap_err(),
        Refusal::OutboxIntegrity
    );
    assert_eq!(
        outbox.prune_settled(0).unwrap_err(),
        Refusal::OutboxIntegrity,
        "a damaged store is reported, never trimmed"
    );
}

#[test]
fn a_database_for_another_chain_or_another_application_is_refused() {
    let dir = TempDir::new("foreign");
    let world = world();
    let ctx = world.view().context();
    let path = dir.file("outbox.sqlite");
    drop(SqliteOutbox::open(&path, ctx).unwrap());

    let mut other_genesis = ctx;
    other_genesis.genesis = [0x61; 32];
    assert_eq!(
        SqliteOutbox::open(&path, other_genesis).unwrap_err(),
        Refusal::WrongContext(ContextField::Genesis)
    );
    let mut other_fingerprint = ctx;
    other_fingerprint.fingerprint = [0x62; 32];
    assert_eq!(
        SqliteOutbox::open(&path, other_fingerprint).unwrap_err(),
        Refusal::WrongContext(ContextField::Fingerprint)
    );
    let mut other_network = ctx;
    other_network.network ^= 1;
    assert_eq!(
        SqliteOutbox::open(&path, other_network).unwrap_err(),
        Refusal::WrongContext(ContextField::Network)
    );

    // Somebody else's SQLite database, and a file that is not a database at all.
    let strange = dir.file("strange.sqlite");
    Connection::open(&strange)
        .unwrap()
        .execute_batch("CREATE TABLE notes(x); INSERT INTO notes VALUES(1)")
        .unwrap();
    assert_eq!(
        SqliteOutbox::open(&strange, ctx).unwrap_err(),
        Refusal::OutboxIntegrity
    );
    let garbage = dir.file("garbage.sqlite");
    std::fs::write(&garbage, vec![0x55u8; 4096]).unwrap();
    assert_eq!(
        SqliteOutbox::open(&garbage, ctx).unwrap_err(),
        Refusal::OutboxIntegrity
    );
    // An empty file is a new database.
    let empty = dir.file("empty.sqlite");
    std::fs::write(&empty, b"").unwrap();
    assert!(
        SqliteOutbox::open(&empty, ctx)
            .unwrap()
            .records()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn debug_output_is_compact() {
    let dir = TempDir::new("debug");
    let world = world();
    let outbox = SqliteOutbox::open(&dir.file("outbox.sqlite"), world.view().context()).unwrap();
    let text = format!("{outbox:?}");
    assert!(
        text.starts_with("SqliteOutbox") && text.len() < 400,
        "{text}"
    );
}

const CRASH_CHILD: &str = "WALLET_CORE_OUTBOX_CRASH_CHILD";

/// End the whole process abruptly (no destructors, no graceful close) right after the commit returned, and
/// separately in the middle of an uncommitted write. A restart sees exactly the committed bytes in
/// the first case and nothing in the second: "exact bytes or nothing".
#[test]
fn a_commit_is_durable_even_if_the_process_dies_and_an_uncommitted_write_leaves_nothing() {
    if let Ok(spec) = std::env::var(CRASH_CHILD) {
        // ---- child process: do the work, then die abruptly
        let (mode, dir) = spec.split_once('|').expect("mode|directory");
        let dir = std::path::PathBuf::from(dir);
        let world = world();
        let view = world.view();
        let path = dir.join("outbox.sqlite");
        if mode == "committed" {
            let signed = signed_payment(&world, 1_000_000);
            let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();
            outbox.commit(&signed, &view).unwrap();
            std::fs::write(dir.join("expected.bin"), signed.bytes()).unwrap();
        } else {
            drop(SqliteOutbox::open(&path, view.context()).unwrap());
            let raw = Connection::open(&path).unwrap();
            raw.execute_batch(
                "BEGIN IMMEDIATE; INSERT INTO outbox_records_v1(id,kind,raw,meta,status,status_height,checksum) \
                 VALUES(zeroblob(32),1,X'01',X'01',0,0,zeroblob(32));",
            )
            .unwrap();
            std::fs::write(dir.join("started.bin"), b"x").unwrap();
        }
        // Die at once: no destructors, no graceful close of the connection. (`exit` rather than
        // `abort` so that no crash dialog or dump is produced on a developer machine.)
        std::process::exit(86);
    }

    let world = world();
    let ctx = world.view().context();
    for mode in ["committed", "uncommitted"] {
        let dir = TempDir::new("crash");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "a_commit_is_durable_even_if_the_process_dies_and_an_uncommitted_write_leaves_nothing", "--test-threads=1"])
            .env(CRASH_CHILD, format!("{mode}|{}", dir.path().display()))
            .output()
            .unwrap()
            .status;
        assert_eq!(
            status.code(),
            Some(86),
            "the child reached its abrupt exit ({mode})"
        );
        let outbox = SqliteOutbox::open(&dir.file("outbox.sqlite"), ctx)
            .expect("a killed process leaves a valid database");
        if mode == "committed" {
            let expected = std::fs::read(dir.file("expected.bin")).unwrap();
            let records = outbox.records().unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].bytes, expected,
                "the exact signed bytes survived the kill"
            );
            assert_eq!(records[0].status, OutboxStatus::Queued);
            assert_eq!(outbox.reserved().unwrap().len(), 1);
        } else {
            assert!(
                dir.file("started.bin").exists(),
                "the child began its write"
            );
            assert!(
                outbox.records().unwrap().is_empty(),
                "an uncommitted write left nothing behind"
            );
            assert!(outbox.reserved().unwrap().is_empty());
        }
    }
}

#[test]
fn a_database_held_by_another_process_is_busy_not_corrupt_and_nothing_is_left_behind() {
    let dir = TempDir::new("busy");
    let path = dir.file("outbox.sqlite");
    let world = world();
    let view = world.view();
    let signed = signed_payment(&world, 1_000_000);
    let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();
    outbox
        .set_busy_timeout(std::time::Duration::from_millis(50))
        .unwrap();
    // Another connection holds the write lock.
    let other = Connection::open(&path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        outbox.commit(&signed, &view).unwrap_err(),
        Refusal::OutboxBusy
    );
    assert_eq!(Refusal::OutboxBusy.code(), "OUTBOX_BUSY");
    other.execute_batch("ROLLBACK").unwrap();
    // The refused attempt changed nothing, and the commit works once the lock is gone.
    assert!(outbox.records().unwrap().is_empty());
    assert_eq!(outbox.commit(&signed, &view).unwrap(), signed.id());
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
fn the_durable_outbox_derives_its_metadata_from_the_bytes_too() {
    let dir = TempDir::new("derived");
    let path = dir.file("outbox.sqlite");
    let world = world();
    let view = world.view();
    let signed = signed_payment(&world, 1_000_000);
    let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();
    let spare = OutPoint {
        transaction: [0x77; 32],
        index: 3,
    };
    for (what, lie) in [
        ("no reservations", claim(&signed, |_, r| r.clear())),
        (
            "another coin",
            claim(&signed, |_, r| *r = vec![spare.clone()]),
        ),
        ("a later expiry", claim(&signed, |v, _| v.expiry += 1_000)),
        (
            "bound to a parent",
            claim(&signed, |v, _| v.bound_to_parent = true),
        ),
    ] {
        assert!(
            matches!(
                outbox.commit(&lie, &view),
                Err(Refusal::VerificationFailed(_))
            ),
            "{what}"
        );
    }
    assert_eq!(
        (
            count(&path, "outbox_records_v1"),
            count(&path, "outbox_inputs_v1")
        ),
        (0, 0),
        "a refused claim leaves nothing behind"
    );
    // A repeated claim is the same set: it is stored as the bytes say.
    let repeated = claim(&signed, |_, r| {
        let again = r.clone();
        r.extend(again);
    });
    outbox.commit(&repeated, &view).unwrap();
    assert_eq!(
        outbox.get(&signed.id()).unwrap().unwrap().reserved,
        signed.reserved()
    );
    assert_eq!(count(&path, "outbox_inputs_v1"), 1);
}

#[test]
fn only_open_records_count_and_the_history_is_trimmed_durably() {
    let dir = TempDir::new("history");
    let path = dir.file("outbox.sqlite");
    let world = world();
    let view = world.view();
    // Three different payments over the same coin: only one of them can be open at a time.
    let payments: Vec<SignedOperation> = [1_000_000u64, 1_100_000, 1_200_000]
        .iter()
        .map(|amount| signed_payment(&world, *amount))
        .collect();
    {
        // A limit of ONE open record never locks anyone out of history.
        let mut outbox = SqliteOutbox::open_with_limits(&path, view.context(), 1, 1 << 20).unwrap();
        for payment in &payments {
            outbox.commit(payment, &view).unwrap();
            outbox.forget(&payment.id()).unwrap();
        }
        assert_eq!(outbox.records().unwrap().len(), 3);
        assert_eq!(outbox.prune_settled(1).unwrap(), 2);
    }
    // The trim is durable: only the most recently queued settled record remains.
    let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();
    let kept = outbox.records().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].id, payments[2].id());
    assert_eq!(count(&path, "outbox_inputs_v1"), 0);
    assert_eq!(outbox.prune_settled(1).unwrap(), 0);
    // An open record is never pruned, whatever the limit.
    outbox.commit(&payments[0], &view).unwrap();
    assert_eq!(outbox.prune_settled(0).unwrap(), 1);
    assert_eq!(outbox.pending().unwrap().len(), 1);
    assert_eq!(
        (
            count(&path, "outbox_records_v1"),
            count(&path, "outbox_inputs_v1")
        ),
        (1, 1)
    );

    // Reconciliation trims the history as it settles records.
    let mut late = World {
        state: world.state.clone(),
        ..World::new(245)
    };
    late.reserved.clear();
    let mut outbox = SqliteOutbox::open(&dir.file("trimmed.sqlite"), view.context()).unwrap();
    outbox.set_max_settled(0);
    outbox.commit(&payments[0], &view).unwrap();
    let report = outbox.reconcile(&late.view()).unwrap();
    assert_eq!((report.expired, report.pruned), (1, 1));
    assert!(outbox.records().unwrap().is_empty());
    assert_eq!(DEFAULT_MAX_SETTLED, 1024);
}

#[test]
fn only_a_regular_file_at_a_real_path_is_a_durable_outbox() {
    let dir = TempDir::new("location");
    let ctx = world().view().context();
    for name in [
        "",
        ":memory:",
        "file:outbox.sqlite",
        "file::memory:?cache=shared",
    ] {
        assert_eq!(
            SqliteOutbox::open(std::path::Path::new(name), ctx).unwrap_err(),
            Refusal::OutboxLocation,
            "{name:?}"
        );
    }
    // A directory, and a file inside a directory that does not exist, cannot be opened.
    assert_eq!(
        SqliteOutbox::open(dir.path(), ctx).unwrap_err(),
        Refusal::OutboxLocation
    );
    assert_eq!(
        SqliteOutbox::open(&dir.path().join("missing").join("outbox.sqlite"), ctx).unwrap_err(),
        Refusal::OutboxLocation
    );
    assert_eq!(Refusal::OutboxLocation.code(), "OUTBOX_LOCATION");
}

#[test]
fn reconciliation_is_for_this_chain_and_this_head_or_later() {
    let dir = TempDir::new("chain");
    let path = dir.file("outbox.sqlite");
    let world = world();
    let view = world.view();
    let signed = signed_payment(&world, 1_000_000);
    let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();
    outbox.commit(&signed, &view).unwrap(); // queued at height 100

    // Another chain's view is refused and changes nothing.
    let mut foreign = World::new(100);
    foreign.state = world.state.clone();
    foreign.anchor.genesis = [0x61; 32];
    assert_eq!(
        outbox.reconcile(&foreign.view()).unwrap_err(),
        Refusal::WrongContext(ContextField::Genesis)
    );
    // An older head (the coin does not exist yet there) says nothing about a record queued later.
    assert_eq!(
        outbox.reconcile(&World::new(90).view()).unwrap(),
        ReconcileReport {
            still_pending: 1,
            ..Default::default()
        }
    );
    assert_eq!(
        outbox.get(&signed.id()).unwrap().unwrap().status,
        OutboxStatus::Queued
    );

    // At its own head with the coin gone it is settled; committing the same bytes again is then
    // refused (consensus no longer accepts them), and the refusal leaves the settled record as it was.
    let gone = World {
        state: Default::default(),
        ..World::new(100)
    };
    assert_eq!(outbox.reconcile(&gone.view()).unwrap().inputs_spent, 1);
    assert!(outbox.commit(&signed, &gone.view()).is_err());
    assert_eq!(
        outbox.get(&signed.id()).unwrap().unwrap().status,
        OutboxStatus::InputsSpent
    );
    assert_eq!(count(&path, "outbox_records_v1"), 1);
}
