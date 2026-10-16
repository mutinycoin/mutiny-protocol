//! Isolated public test identities; no production wallet files or node runtime.
use mutiny_consensus_v8::{
    NETWORK_ID,
    anchors::FinalizedAnchor,
    blocks::BlockBody,
    execution::State,
    funded_rotation_v2::{PartialRotation, Payer, Slot, UnsignedRotation},
    hybrid_transaction_v2::Transaction,
    mempool_v2::{Mempool, PoolError, Status},
    op_envelope_v1::Envelope,
    transactions::{Coin, OutPoint, Output},
    transactions_v2::{Input, Transfer},
};
use mutiny_crypto_v2::{HybridKey, Role};
use std::collections::BTreeSet;
#[test]
fn crash_child_uncommitted_queue_update() {
    let Some(raw) = std::env::var_os("BUILD8_V2_PUBLIC_POOL_CRASH") else {
        return;
    };
    let path = std::path::PathBuf::from(raw);
    let parent = path.parent().unwrap();
    assert!(
        parent
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("build8-v2-pool-")
    );
    assert!(
        parent
            .canonicalize()
            .unwrap()
            .starts_with(std::env::temp_dir().canonicalize().unwrap())
    );
    assert_eq!(path.file_name().unwrap(), "mempool-hybrid-v2.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA cache_size=1; PRAGMA cache_spill=ON; BEGIN IMMEDIATE; UPDATE lifecycle_v2 SET status='REJECTED'; DELETE FROM inputs_v2;").unwrap();
    assert!(
        path.with_file_name("mempool-hybrid-v2.sqlite-journal")
            .metadata()
            .unwrap()
            .len()
            > 512
    );
    std::process::exit(92);
}
fn payment(key: &HybridKey, generation: u64, index: u32, fee: u64) -> Transfer {
    let mut tx = Transfer {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        created_height: 15,
        expiry_height: 17,
        fee,
        inputs: vec![
            Input::unsigned(
                OutPoint {
                    transaction: [8; 32],
                    index,
                },
                key.public(),
                generation,
            )
            .unwrap(),
        ],
        outputs: vec![Output {
            owner: key.public().address_id(generation).unwrap(),
            atoms: 100_000 - fee,
        }],
    };
    tx.sign_input(0, key).unwrap();
    tx
}
#[test]
fn durable_hybrid_admission_rotation_reconciliation_and_capacity_are_atomic() {
    let old =
        HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let new = HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner)
        .unwrap();
    let owner = old.public().address_id(1).unwrap();
    let mut state = State::default();
    for index in 0..2 {
        state.coins.insert(
            OutPoint {
                transaction: [8; 32],
                index,
            },
            Coin {
                output: Output {
                    owner,
                    atoms: 100_000,
                },
                created_height: 1,
                coinbase: false,
            },
        );
    }
    // The funded wallet-rotation bundle (tag 25): the OLD key authorizes the rotation and pays from
    // its own coin; the new key proves possession. Window [15, 17], reference = the basis anchor `a`.
    let mut rotation = PartialRotation::new(UnsignedRotation {
        genesis: [1; 32],
        fingerprint: [2; 32],
        envelope: Envelope {
            first_height: 15,
            last_height: 17,
            reference_height: 14,
            reference_block: [3; 32],
            preconditions: vec![],
        },
        authority: owner,
        current_descriptor: old.public().descriptor(1).unwrap(),
        proposed_descriptor: new.public().descriptor(2).unwrap(),
        sponsor: None,
        fee: 20_000,
        inputs: vec![(
            OutPoint {
                transaction: [8; 32],
                index: 0,
            },
            Payer::RotatingAuthority,
        )],
        outputs: vec![Output {
            owner: new.public().address_id(2).unwrap(),
            atoms: 80_000,
        }],
    });
    rotation.sign(Slot::Authorize, &old).unwrap();
    rotation.sign(Slot::Possession, &new).unwrap();
    rotation.sign(Slot::AuthorityFunding, &old).unwrap();
    let rotating = Transaction::FundedRotation(rotation.complete().unwrap());
    let obsolete = Transaction::Transfer(payment(&old, 1, 1, 5_000));
    let rival = Transaction::Transfer(payment(&old, 1, 1, 6_000));
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base = std::env::temp_dir().join(format!("build8-v2-pool-{}", hex::encode(nonce)));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("mempool-hybrid-v2.sqlite");
    let mut pool = Mempool::open(&path, [1; 32], [2; 32], 64 * 1024 * 1024).unwrap();
    let a = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 14,
        block: [3; 32],
    };
    assert!(matches!(
        pool.admit(&obsolete, &a, &state),
        Err(PoolError::StaleBasis)
    ));
    pool.reconcile(&a, &state, &BTreeSet::new()).unwrap();
    let fault = rusqlite::Connection::open(&path).unwrap();
    fault.execute_batch("CREATE TRIGGER test_failure BEFORE INSERT ON inputs_v2 BEGIN SELECT RAISE(ABORT,'PUBLIC INJECTED STORAGE FAILURE'); END;").unwrap();
    assert!(pool.admit(&obsolete, &a, &state).is_err());
    assert!(pool.status(obsolete.id().unwrap()).is_err());
    fault.execute_batch("DROP TRIGGER test_failure;").unwrap();
    assert_eq!(pool.status(obsolete.id().unwrap()).unwrap(), None);
    assert!(pool.pending().unwrap().is_empty());
    assert!(pool.reserved_inputs().unwrap().is_empty());
    drop(fault);
    assert_eq!(pool.admit(&obsolete, &a, &state).unwrap(), Status::Pending);
    assert_eq!(pool.admit(&obsolete, &a, &state).unwrap(), Status::Pending);
    assert!(matches!(
        pool.admit(&rival, &a, &state),
        Err(PoolError::Conflict)
    ));
    assert_eq!(pool.pending().unwrap().len(), 1);
    assert_eq!(pool.reserved_inputs().unwrap().len(), 1);
    assert_eq!(pool.admit(&rotating, &a, &state).unwrap(), Status::Pending);
    let mut tampered = state.clone();
    tampered.coins.clear();
    assert!(matches!(
        pool.admit(&rival, &a, &tampered),
        Err(PoolError::StaleBasis)
    ));
    assert_eq!(pool.pending().unwrap().len(), 2);
    drop(pool);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crash_child_uncommitted_queue_update",
            "--nocapture",
        ])
        .env("BUILD8_V2_PUBLIC_POOL_CRASH", &path)
        .output()
        .unwrap();
    assert_eq!(
        child.status.code(),
        Some(92),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(Mempool::open(&path, [1; 32], [9; 32], 64 * 1024 * 1024).is_err());
    let mut pool = Mempool::open(&path, [1; 32], [2; 32], 64 * 1024 * 1024).unwrap();
    assert_eq!(pool.pending().unwrap().len(), 2);
    assert_eq!(pool.reserved_inputs().unwrap().len(), 2);
    // Unexpected schema objects and network rebinding fail before any queue
    // mutation. Direct SQL below is deliberate isolated-cache corruption.
    let tamper = rusqlite::Connection::open(&path).unwrap();
    for (install, repair) in [
        (
            "CREATE TRIGGER malicious_delete AFTER DELETE ON inputs_v2 BEGIN UPDATE lifecycle_v2 SET status='CONFIRMED'; END",
            "DROP TRIGGER malicious_delete",
        ),
        (
            "CREATE VIEW counterfeit AS SELECT * FROM lifecycle_v2",
            "DROP VIEW counterfeit",
        ),
        (
            "CREATE INDEX extra_index ON lifecycle_v2(status)",
            "DROP INDEX extra_index",
        ),
        (
            "CREATE TABLE sqliteXhidden(value TEXT)",
            "DROP TABLE sqliteXhidden",
        ),
        (
            "UPDATE context_v2 SET genesis=zeroblob(32)",
            "UPDATE context_v2 SET genesis=x'0101010101010101010101010101010101010101010101010101010101010101'",
        ),
        (
            "UPDATE context_v2 SET fingerprint=zeroblob(32)",
            "UPDATE context_v2 SET fingerprint=x'0202020202020202020202020202020202020202020202020202020202020202'",
        ),
        ("PRAGMA user_version=99", "PRAGMA user_version=2"),
        (
            "PRAGMA application_id=1",
            "PRAGMA application_id=1297435954",
        ),
    ] {
        tamper.execute_batch(install).unwrap();
        assert!(pool.status(obsolete.id().unwrap()).is_err(), "{install}");
        assert!(pool.pending().is_err(), "{install}");
        assert!(pool.basis().is_err(), "{install}");
        assert!(pool.pending_at(&a, &state).is_err(), "{install}");
        assert!(pool.reserved_inputs().is_err(), "{install}");
        assert!(pool.admit(&obsolete, &a, &state).is_err(), "{install}");
        assert!(
            pool.reconcile(&a, &state, &BTreeSet::new()).is_err(),
            "{install}"
        );
        assert!(
            Mempool::open(&path, [1; 32], [2; 32], 64 * 1024 * 1024).is_err(),
            "{install}"
        );
        let n: i64 = tamper
            .query_row(
                "SELECT count(*) FROM lifecycle_v2 WHERE status='PENDING'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 2, "{install}");
        let n: i64 = tamper
            .query_row("SELECT count(*) FROM inputs_v2", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2, "{install}");
        tamper.execute_batch(repair).unwrap();
        assert_eq!(pool.pending_at(&a, &state).unwrap().len(), 2);
    }
    drop(tamper);
    // Reconciliation at the same verified head rebuilds derived reservations.
    let damaged = rusqlite::Connection::open(&path).unwrap();
    damaged.execute_batch("DELETE FROM inputs_v2;").unwrap();
    drop(damaged);
    assert!(pool.reserved_inputs().unwrap().is_empty());
    pool.reconcile(&a, &state, &[obsolete.id().unwrap()].into_iter().collect())
        .unwrap();
    assert_eq!(pool.reserved_inputs().unwrap().len(), 2);
    assert_eq!(
        pool.status(obsolete.id().unwrap()).unwrap(),
        Some(Status::Pending)
    );
    let body = BlockBody {
        height: 15,
        reward_owner: owner,
        fees: 20_000,
        transactions: vec![rotating.encode().unwrap()],
        operations: vec![],
    };
    let executed = state
        .execute_hybrid_transfers([1; 32], [2; 32], a.block, owner, &body)
        .unwrap();
    let mut next = a.clone();
    next.height = 15;
    next.block = [4; 32];
    let confirmed = [rotating.id().unwrap()].into_iter().collect();
    let fault = rusqlite::Connection::open(&path).unwrap();
    fault.execute_batch("CREATE TRIGGER reconcile_failure BEFORE UPDATE ON lifecycle_v2 WHEN NEW.status='REJECTED' BEGIN SELECT RAISE(ABORT,'PUBLIC RECONCILE FAILURE'); END;").unwrap();
    assert!(pool.reconcile(&next, &executed.state, &confirmed).is_err());
    assert!(pool.pending().is_err());
    fault
        .execute_batch("DROP TRIGGER reconcile_failure;")
        .unwrap();
    assert_eq!(pool.pending().unwrap().len(), 2);
    assert_eq!(pool.reserved_inputs().unwrap().len(), 2);
    assert_eq!(pool.admit(&obsolete, &a, &state).unwrap(), Status::Pending);
    drop(fault);
    pool.reconcile(&next, &executed.state, &confirmed).unwrap();
    assert_eq!(
        pool.status(rotating.id().unwrap()).unwrap(),
        Some(Status::Confirmed)
    );
    assert_eq!(
        pool.status(obsolete.id().unwrap()).unwrap(),
        Some(Status::Rejected)
    );
    assert!(pool.reserved_inputs().unwrap().is_empty());
    assert!(pool.pending().unwrap().is_empty());
    assert!(pool.reconcile(&a, &state, &BTreeSet::new()).is_err());
    let mut fork = next.clone();
    fork.block = [5; 32];
    assert!(
        pool.reconcile(&fork, &executed.state, &BTreeSet::new())
            .is_err()
    );
    pool.reconcile(&next, &executed.state, &confirmed).unwrap();
    let current = Transaction::Transfer(payment(&new, 2, 1, 5_000));
    assert_eq!(
        pool.admit(&current, &next, &executed.state).unwrap(),
        Status::Pending
    );
    let mut advanced = executed.state;
    for height in 16..=17 {
        let body = BlockBody {
            height,
            reward_owner: owner,
            fees: 0,
            transactions: vec![],
            operations: vec![],
        };
        advanced = advanced
            .execute_hybrid_transfers([1; 32], [2; 32], next.block, owner, &body)
            .unwrap()
            .state;
        next.height = height;
        next.block = [height as u8; 32];
        pool.reconcile(&next, &advanced, &BTreeSet::new()).unwrap();
    }
    assert_eq!(
        pool.status(current.id().unwrap()).unwrap(),
        Some(Status::Expired)
    );
    assert!(pool.reserved_inputs().unwrap().is_empty());
    drop(pool);
    let limited = base.join("limited.sqlite");
    let mut small = Mempool::open(&limited, [1; 32], [2; 32], 1).unwrap();
    small.reconcile(&a, &state, &BTreeSet::new()).unwrap();
    assert!(matches!(
        small.admit(&obsolete, &a, &state),
        Err(PoolError::Capacity)
    ));
    assert!(small.pending().unwrap().is_empty());
    assert!(small.reserved_inputs().unwrap().is_empty());
    let corrupt = rusqlite::Connection::open(&limited).unwrap();
    corrupt
        .execute("UPDATE basis_v2 SET anchor=zeroblob(1048576)", [])
        .unwrap();
    assert!(small.basis().is_err());
    assert!(small.pending_at(&a, &state).is_err());
    assert!(small.admit(&obsolete, &a, &state).is_err());
    assert!(small.reconcile(&a, &state, &BTreeSet::new()).is_err());
    corrupt
        .execute("UPDATE basis_v2 SET anchor=?1", [a.encode()])
        .unwrap();
    assert!(small.pending_at(&a, &state).unwrap().is_empty());
    corrupt
        .execute_batch("PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    corrupt
        .execute(
            "INSERT INTO lifecycle_v2 VALUES(?1,zeroblob(1048576),'PENDING')",
            [obsolete.id().unwrap().as_slice()],
        )
        .unwrap();
    assert!(small.pending_at(&a, &state).is_err());
    assert!(small.admit(&obsolete, &a, &state).is_err());
    corrupt
        .execute(
            "UPDATE lifecycle_v2 SET raw=?1,status=?2",
            rusqlite::params![obsolete.encode().unwrap(), "X".repeat(1048576)],
        )
        .unwrap();
    assert!(small.status(obsolete.id().unwrap()).is_err());
    assert!(small.admit(&obsolete, &a, &state).is_err());
    corrupt.execute("DELETE FROM lifecycle_v2", []).unwrap();
    corrupt
        .execute("UPDATE context_v2 SET genesis=zeroblob(1048576)", [])
        .unwrap();
    assert!(Mempool::open(&limited, [1; 32], [2; 32], 1).is_err());
    corrupt
        .execute("UPDATE context_v2 SET genesis=?1", [[1u8; 32].as_slice()])
        .unwrap();
    assert!(small.pending_at(&a, &state).unwrap().is_empty());
    drop(corrupt);
    drop(small);
    let foreign = base.join("foreign.sqlite");
    let db = rusqlite::Connection::open(&foreign).unwrap();
    db.execute_batch("CREATE TABLE legacy(value TEXT); INSERT INTO legacy VALUES('PUBLIC TEST');")
        .unwrap();
    drop(db);
    assert!(Mempool::open(&foreign, [1; 32], [2; 32], 1).is_err());
    let db = rusqlite::Connection::open(&foreign).unwrap();
    assert_eq!(
        db.query_row("SELECT value FROM legacy", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "PUBLIC TEST"
    );
    drop(db);
    for p in [path, limited, foreign] {
        std::fs::remove_file(p).unwrap();
    }
    std::fs::remove_dir(base).unwrap();
}
