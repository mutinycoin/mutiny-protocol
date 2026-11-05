use ed25519_dalek::{Signer, SigningKey};
use mutiny_consensus_v8::{
    NETWORK_ID,
    mempool::{Mempool, PoolError, Status},
    transactions::*,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Database(PathBuf);
impl Database {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "build8-mempool-{}-{}.sqlite",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(!p.exists());
        Self(p)
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn sign(tx: &mut Transfer) {
    let key = SigningKey::from_bytes(&[31; 32]);
    for n in 0..tx.inputs.len() {
        tx.inputs[n].signature = key.sign(&tx.signing_digest(n).unwrap()).to_bytes();
    }
}
fn fixture() -> (Transfer, BTreeMap<OutPoint, Coin>) {
    let public_key = SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes();
    let point = OutPoint {
        transaction: [9; 32],
        index: 0,
    };
    let mut tx = Transfer {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        created_height: 101,
        expiry_height: 110,
        inputs: vec![Input {
            point: point.clone(),
            public_key,
            signature: [0; 64],
        }],
        outputs: vec![Output {
            owner: [3; 32],
            atoms: 99_999_000,
        }],
    };
    sign(&mut tx);
    (
        tx,
        BTreeMap::from([(
            point,
            Coin {
                output: Output {
                    owner: address(&public_key),
                    atoms: 100_000_000,
                },
                created_height: 1,
                coinbase: true,
            },
        )]),
    )
}
#[test]
fn transfer_boundaries_signatures_and_value_conservation() {
    let (tx, coins) = fixture();
    let raw = tx.encode().unwrap();
    assert_eq!(Transfer::decode(&raw).unwrap(), tx);
    assert_eq!(tx.verify([1; 32], [2; 32], 101, &coins), Ok(1000));
    assert_eq!(tx.verify([1; 32], [2; 32], 110, &coins), Ok(1000));
    assert_eq!(
        tx.verify([1; 32], [2; 32], 111, &coins),
        Err(TxError::Expired)
    );
    assert_eq!(
        tx.verify([1; 32], [2; 32], 100, &coins),
        Err(TxError::Future)
    );
    let mut early = tx.clone();
    early.created_height = 100;
    sign(&mut early);
    assert_eq!(
        early.verify([1; 32], [2; 32], 100, &coins),
        Err(TxError::Immature)
    );
    let mut bad = tx.clone();
    bad.outputs[0].atoms = 100_000_001;
    sign(&mut bad);
    assert_eq!(
        bad.verify([1; 32], [2; 32], 101, &coins),
        Err(TxError::Conservation)
    );
    let mut bad = tx.clone();
    bad.outputs[0].atoms = 99_999_999;
    sign(&mut bad);
    assert_eq!(bad.verify([1; 32], [2; 32], 101, &coins), Err(TxError::Fee));
    let mut bad = tx.clone();
    bad.inputs[0].signature[0] ^= 1;
    assert_eq!(bad.id(), tx.id());
    assert_eq!(
        bad.verify([1; 32], [2; 32], 101, &coins),
        Err(TxError::Signature)
    );
    assert_eq!(
        tx.verify([0; 32], [2; 32], 101, &coins),
        Err(TxError::Binding)
    );
    let mut duplicate = tx.clone();
    duplicate.inputs.push(duplicate.inputs[0].clone());
    assert_eq!(duplicate.encode(), Err(TxError::Duplicate));
    for n in 0..raw.len() {
        assert!(Transfer::decode(&raw[..n]).is_err());
    }
    let mut trailing = raw;
    trailing.push(0);
    assert!(Transfer::decode(&trailing).is_err());
}
#[test]
fn pending_survives_unrelated_blocks_restart_conflict_and_capacity() {
    let db = Database::new();
    let (tx, coins) = fixture();
    let id = tx.id().unwrap();
    {
        let mut pool =
            Mempool::open(&db.0, [1; 32], [2; 32], tx.encode().unwrap().len() as u64).unwrap();
        assert_eq!(pool.admit(&tx, 101, &coins).unwrap(), Status::Pending);
        assert_eq!(pool.admit(&tx, 101, &coins).unwrap(), Status::Pending);
        let mut conflict = tx.clone();
        conflict.outputs[0].atoms -= 1;
        sign(&mut conflict);
        assert!(matches!(
            pool.admit(&conflict, 101, &coins),
            Err(PoolError::Capacity) | Err(PoolError::Conflict)
        ));
        pool.reconcile(102, [12; 32], &BTreeSet::new(), &coins)
            .unwrap();
        assert_eq!(pool.status(id).unwrap(), Some(Status::Pending));
    }
    let mut pool = Mempool::open(&db.0, [1; 32], [2; 32], 64 * 1024 * 1024).unwrap();
    assert_eq!(pool.pending().unwrap(), vec![tx.clone()]);
    let mut conflict = tx.clone();
    conflict.outputs[0].atoms -= 1;
    sign(&mut conflict);
    assert!(matches!(
        pool.admit(&conflict, 103, &coins),
        Err(PoolError::Conflict)
    ));
    pool.reconcile(103, [13; 32], &BTreeSet::from([id]), &BTreeMap::new())
        .unwrap();
    assert_eq!(pool.status(id).unwrap(), Some(Status::Confirmed));
    assert!(pool.pending().unwrap().is_empty());
    drop(pool);
    assert_eq!(
        Mempool::open(&db.0, [1; 32], [2; 32], 1024)
            .unwrap()
            .status(id)
            .unwrap(),
        Some(Status::Confirmed)
    );
    assert!(matches!(
        Mempool::open(&db.0, [8; 32], [2; 32], 1024),
        Err(PoolError::WrongContext)
    ));
}
#[test]
fn expiry_and_canonical_conflict_are_explicit_terminal_states() {
    for expire in [true, false] {
        let db = Database::new();
        let (tx, coins) = fixture();
        let id = tx.id().unwrap();
        let mut pool = Mempool::open(&db.0, [1; 32], [2; 32], 1024).unwrap();
        pool.admit(&tx, 101, &coins).unwrap();
        let (height, view, status) = if expire {
            (110, coins, Status::Expired)
        } else {
            (102, BTreeMap::new(), Status::InputSpent)
        };
        pool.reconcile(height, [44; 32], &BTreeSet::new(), &view)
            .unwrap();
        assert_eq!(pool.status(id).unwrap(), Some(status));
        pool.reconcile(height, [44; 32], &BTreeSet::new(), &view)
            .unwrap();
        assert!(matches!(
            pool.reconcile(height, [45; 32], &BTreeSet::new(), &view),
            Err(PoolError::Integrity)
        ));
        assert!(matches!(
            pool.reconcile(height - 1, [43; 32], &BTreeSet::new(), &view),
            Err(PoolError::StaleBasis)
        ));
    }
}
