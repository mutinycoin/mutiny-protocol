use mutiny_consensus_v8::{Hash, bft::*};
use primitive_types::U256;
use std::collections::BTreeMap;

/// Public synthetic authenticated-reducer inputs, not a signature/authentication bypass claim.
#[test]
fn review_strict_two_thirds_and_zero_weight_ingress() {
    let mut weights = BTreeMap::new();
    weights.insert([0; 32], U256::zero());
    for node in 1..=3 {
        weights.insert([node; 32], U256::one());
    }
    let mut machine = RoundMachine::new(weights).unwrap();
    let block = [0x91; 32];
    assert_eq!(
        machine.observe_authenticated(0, Step::Precommit, [0; 32], Some(block)),
        Err(BftError::UnknownVoter)
    );
    for node in 1..=2 {
        machine
            .observe_authenticated(0, Step::Precommit, [node; 32], Some(block))
            .unwrap();
    }
    assert_eq!(machine.commit(0, block), Err(BftError::NoQuorum));
    assert_eq!(machine.state().finalized, None);
    machine
        .observe_authenticated(0, Step::Precommit, [3; 32], Some(block))
        .unwrap();
    assert!(machine.commit(0, block).unwrap());
}
fn weights() -> BTreeMap<Hash, U256> {
    (1..=4).map(|n| ([n; 32], U256::one())).collect()
}
#[test]
fn durable_lock_compare_and_swap_prevents_stale_writer_and_restart_unlock() {
    use mutiny_consensus_v8::bft_store::{LockStore, StoreError};
    let path = std::env::temp_dir().join(format!("build8-lockstore-{}.sqlite", std::process::id()));
    assert!(!path.exists());
    let mut first = LockStore::open(&path, [7; 32], 1).unwrap();
    let mut second = LockStore::open(&path, [7; 32], 1).unwrap();
    let (h, r, mut s) = first.load().unwrap();
    assert_eq!((h, r), (1, 0));
    s.locked = Some(Lock {
        round: 0,
        block: [8; 32],
    });
    let r = first.save(h, r, &s).unwrap();
    assert!(matches!(
        second.save(
            h,
            0,
            &LockState {
                round: 0,
                locked: None,
                finalized: None,
                halted: false
            }
        ),
        Err(StoreError::StaleRevision)
    ));
    drop(first);
    drop(second);
    let mut store = LockStore::open(&path, [7; 32], 1).unwrap();
    let (_, loaded_revision, loaded) = store.load().unwrap();
    assert_eq!(loaded_revision, r);
    assert_eq!(loaded, s);
    let mut m = RoundMachine::restore(weights(), loaded).unwrap();
    m.enter_round(1).unwrap();
    assert_eq!(m.prevote(Some([9; 32]), None).unwrap(), Some([8; 32]));
    let r = store.save(1, r, m.state()).unwrap();
    assert!(matches!(store.save(1, r, &s), Err(StoreError::Regression)));
    assert!(matches!(
        store.advance(1, r, [8; 32]),
        Err(StoreError::Regression)
    ));
    for n in 1..=3 {
        vote(&mut m, 0, Step::Precommit, n, Some([8; 32]));
    }
    m.commit(0, [8; 32]).unwrap();
    let r = store.save(1, r, m.state()).unwrap();
    assert_eq!(
        m.prevote(Some([8; 32]), None),
        Err(BftError::AlreadyFinalized)
    );
    store.advance(1, r, [8; 32]).unwrap();
    assert_eq!(store.load().unwrap().0, 2);
    drop(store);
    std::fs::remove_file(path).unwrap();
}
fn vote(m: &mut RoundMachine, r: u64, s: Step, n: u8, b: Option<Hash>) {
    m.observe_authenticated(r, s, [n; 32], b).unwrap();
}
#[test]
fn locked_vote_survives_timeout_restart_and_delayed_round_proofs() {
    let mut m = RoundMachine::new(weights()).unwrap();
    let b = [8; 32];
    for n in 1..=3 {
        vote(&mut m, 0, Step::Prevote, n, Some(b));
    }
    assert_eq!(m.precommit(Some(b)).unwrap(), Some(b));
    vote(&mut m, 0, Step::Precommit, 1, Some(b));
    vote(&mut m, 0, Step::Precommit, 2, Some(b));
    vote(&mut m, 0, Step::Precommit, 4, None);
    assert_eq!(m.commit(0, b), Err(BftError::NoQuorum));
    assert_eq!(m.timeout_precommit().unwrap(), 1);
    let saved = m.state().clone();
    let mut restored = RoundMachine::restore(weights(), saved).unwrap();
    assert_eq!(restored.prevote(Some([9; 32]), None).unwrap(), Some(b));
    // Round1 preserves the old lock and can produce a second proof of the same B.
    for n in 1..=3 {
        vote(&mut restored, 1, Step::Prevote, n, Some(b));
        vote(&mut restored, 1, Step::Precommit, n, Some(b));
    }
    assert_eq!(restored.precommit(Some(b)).unwrap(), Some(b));
    assert!(restored.commit(1, b).unwrap());
    for n in 1..=3 {
        vote(&mut restored, 0, Step::Precommit, n, Some(b));
    }
    assert!(!restored.commit(0, b).unwrap());
    assert_eq!(restored.state().finalized, Some(b));
}
#[test]
fn duplicates_equivocation_denominator_and_step_are_not_weakened() {
    let mut m = RoundMachine::new(weights()).unwrap();
    let b = Some([8; 32]);
    assert_eq!(
        m.observe_authenticated(0, Step::Prevote, [1; 32], b)
            .unwrap(),
        Observation::Added
    );
    assert_eq!(
        m.observe_authenticated(0, Step::Prevote, [1; 32], b)
            .unwrap(),
        Observation::Duplicate
    );
    assert_eq!(
        m.observe_authenticated(0, Step::Prevote, [1; 32], None),
        Err(BftError::Equivocation)
    );
    vote(&mut m, 0, Step::Prevote, 2, b);
    vote(&mut m, 0, Step::Prevote, 3, b);
    assert_eq!(m.timeout_precommit(), Err(BftError::NoQuorum)); // prevotes are not precommits
    vote(&mut m, 0, Step::Precommit, 1, b);
    vote(&mut m, 0, Step::Precommit, 2, b);
    assert_eq!(m.commit(0, [8; 32]), Err(BftError::NoQuorum)); // offline fourth remains in denominator
    vote(&mut m, 0, Step::Precommit, 3, b);
    assert!(m.commit(0, [8; 32]).unwrap());
    assert_eq!(
        m.observe_authenticated(0, Step::Prevote, [0; 32], b),
        Err(BftError::UnknownVoter)
    );
}
#[test]
fn lock_changes_require_a_valid_newer_pol_and_conflicting_finality_halts() {
    let mut m = RoundMachine::new(weights()).unwrap();
    let a = [8; 32];
    let b = [9; 32];
    for n in 1..=3 {
        vote(&mut m, 0, Step::Prevote, n, Some(a));
        vote(&mut m, 0, Step::Precommit, n, Some(a));
    }
    assert_eq!(m.precommit(Some(a)).unwrap(), Some(a));
    m.enter_round(2).unwrap();
    assert_eq!(m.prevote(Some(b), Some(1)), Err(BftError::InvalidProof));
    assert_eq!(m.prevote(Some(b), None).unwrap(), Some(a));
    for n in 1..=3 {
        vote(&mut m, 1, Step::Prevote, n, Some(b));
    }
    assert_eq!(m.prevote(Some(b), Some(1)).unwrap(), Some(b));
    assert!(m.commit(0, a).unwrap());
    // Synthetic Byzantine evidence of a conflicting commit MUST halt, never select it.
    for n in 1..=3 {
        vote(&mut m, 1, Step::Precommit, n, Some(b));
    }
    assert_eq!(m.commit(1, b), Err(BftError::IntegrityHalt));
    assert!(m.state().halted);
    assert_eq!(m.commit(0, a), Err(BftError::IntegrityHalt));
}
