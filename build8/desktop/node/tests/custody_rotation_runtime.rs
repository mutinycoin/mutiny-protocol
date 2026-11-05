//! Recorded public signatures only: no wallet/private owner material on a node.
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor, bft::Step, block_envelope_v2::BlockEnvelope,
    canonical_store_v2::CanonicalStore, continuity_v2::Vote, counter_store::MonotonicCounter,
    counter_voter_v2::CounterSigningBackend, execution::State, mempool_v2::Mempool,
};
use mutiny_crypto_v2::{HybridSignature, PublicKey};
use mutinyd_v8::{
    hybrid_runtime_v2::HybridRuntime,
    hybrid_voter_v2::{CustodyProgress, VotingRuntime},
};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
struct Counter {
    value: u64,
    calls: u64,
    interrupt: bool,
}
struct Recorded {
    counter: Rc<RefCell<Counter>>,
    public: PublicKey,
    votes: Vec<Vote>,
}
impl MonotonicCounter for Recorded {
    fn read(&mut self) -> Result<u64, String> {
        Ok(self.counter.borrow().value)
    }
    fn increment(&mut self) -> Result<(), String> {
        let mut c = self.counter.borrow_mut();
        c.value = c.value.checked_add(1).ok_or("overflow")?;
        if c.interrupt {
            c.interrupt = false;
            return Err("synthetic post-increment interruption".into());
        }
        Ok(())
    }
}
impl CounterSigningBackend for Recorded {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }
    fn sign_vote(&mut self, message: &[u8]) -> Result<HybridSignature, String> {
        self.counter.borrow_mut().calls += 1;
        self.votes
            .iter()
            .find(|v| v.unsigned().unwrap() == message)
            .map(|v| v.signature.clone())
            .ok_or("unrecorded fixture vote".into())
    }
}
#[test]
fn canonical_rotation_activation_failure_and_counter_recovery_preserve_authority() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/custody-rotation-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let root = raw(&f["root"]).try_into().unwrap();
    let rows: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&rows, root).unwrap();
    let envelope = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let old = PublicKey::decode_descriptor(&raw(&f["old_descriptor"]))
        .unwrap()
        .0;
    let new = PublicKey::decode_descriptor(&raw(&f["new_descriptor"]))
        .unwrap()
        .0;
    let prevote = Vote::decode(&raw(&f["prevote"])).unwrap();
    let precommit = Vote::decode(&raw(&f["precommit"])).unwrap();
    let next = Vote::decode(&raw(&f["next_prevote"])).unwrap();
    let node = prevote.node;
    for scenario in [
        "success",
        "activation_failure",
        "activation_failure_after_switch",
        "activation_panic_after_switch",
        "counter_interruption",
        "unrecorded_own",
    ] {
        println!("SYNTHETIC_RUNTIME_ROTATION_SCENARIO={scenario}");
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let base = std::env::temp_dir().join(format!(
            "build8-public-rotation-{scenario}-{}",
            hex::encode(nonce)
        ));
        let chain_path = base.with_extension("chain.sqlite");
        let pool_path = base.with_extension("pool.sqlite");
        let voter_path = base.with_extension("voter.sqlite");
        let open_runtime = || {
            HybridRuntime::from_pinned_chain(
                CanonicalStore::open_trusted_genesis(
                    &chain_path,
                    &genesis,
                    &state,
                    root,
                    1000,
                    [255; 32],
                )
                .unwrap(),
                Mempool::open(
                    &pool_path,
                    genesis.genesis,
                    genesis.fingerprint,
                    64 * 1024 * 1024,
                )
                .unwrap(),
            )
            .unwrap()
        };
        let counter = Rc::new(RefCell::new(Counter {
            value: 100,
            calls: 0,
            interrupt: false,
        }));
        let old_backend = Recorded {
            counter: counter.clone(),
            public: old.clone(),
            votes: vec![prevote.clone(), precommit.clone()],
        };
        let mut voting =
            VotingRuntime::open(open_runtime(), &voter_path, node, Some(100), old_backend).unwrap();
        // Existing behavior test, not about time: a controlled eligible clock (the default is fail-closed).
        voting.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(u64::MAX));
        if scenario != "unrecorded_own" {
            voting.validate_proposal(&envelope).unwrap();
            assert_eq!(
                voting
                    .sign(Step::Prevote, Some(envelope.block_hash()), None)
                    .unwrap(),
                prevote
            );
            voting.observe(&prevote).unwrap();
            assert_eq!(
                voting
                    .sign(Step::Precommit, Some(envelope.block_hash()), None)
                    .unwrap(),
                precommit
            );
        }
        let before = counter.borrow().value;
        let activated = Cell::new(false);
        counter.borrow_mut().interrupt = scenario == "counter_interruption";
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            voting.install_with_rotation(&envelope.encode().unwrap(), |backend, receipt| {
                activated.set(true);
                assert_eq!(receipt.counter(), counter.borrow().value);
                if scenario == "activation_failure" {
                    return Err("synthetic activation rejected".into());
                }
                backend.public = new.clone();
                backend.votes = vec![next.clone()];
                if scenario == "activation_failure_after_switch" {
                    return Err("synthetic failure after switching key".into());
                }
                if scenario == "activation_panic_after_switch" {
                    panic!("synthetic activation unwind after switching key");
                }
                Ok(())
            })
        }));
        let receipt = if scenario == "activation_panic_after_switch" {
            assert!(outcome.is_err());
            None
        } else {
            let receipt = outcome.unwrap().unwrap();
            assert!(receipt.canonical.inserted);
            assert_eq!(receipt.canonical.finalized.height, 1);
            Some(receipt)
        };
        assert_eq!(voting.validator().head().unwrap().height, 1);
        if scenario == "success" {
            assert!(matches!(
                receipt.unwrap().custody,
                CustodyProgress::Ready { next_height: 2 }
            ));
            assert!(activated.get());
            assert_eq!(voting.sign(Step::Prevote, None, None).unwrap(), next);
            let calls = counter.borrow().calls;
            assert_eq!(voting.replay(Step::Prevote).unwrap(), Some(next.clone()));
            assert_eq!(counter.borrow().calls, calls);
            let tip = counter.borrow().value;
            let duplicate = voting
                .install_with_rotation(&envelope.encode().unwrap(), |_, _| {
                    panic!("duplicate activation forbidden")
                })
                .unwrap();
            assert!(!duplicate.canonical.inserted);
            assert!(matches!(
                duplicate.custody,
                CustodyProgress::Ready { next_height: 2 }
            ));
            assert_eq!(counter.borrow().value, tip);
            assert_eq!(counter.borrow().calls, calls);
            drop(voting);
        } else {
            if let Some(receipt) = receipt {
                assert!(matches!(receipt.custody, CustodyProgress::Stopped(_)));
            }
            assert_eq!(activated.get(), scenario.starts_with("activation_"));
            assert!(voting.sign(Step::Prevote, None, None).is_err());
            assert!(voting.replay(Step::Prevote).is_err());
            assert!(voting.reconcile().is_err());
            drop(voting);
            assert_eq!(counter.borrow().value, before + 1);
            let backend = Recorded {
                counter: counter.clone(),
                public: new.clone(),
                votes: vec![next.clone()],
            };
            let resumed =
                VotingRuntime::open_after_rotation(open_runtime(), &voter_path, node, 1, backend);
            if scenario == "unrecorded_own" {
                assert!(resumed.is_err());
                assert_eq!(counter.borrow().calls, 0);
            } else {
                let mut resumed = resumed.unwrap();
                assert_eq!(counter.borrow().value, before + 1);
                assert_eq!(resumed.sign(Step::Prevote, None, None).unwrap(), next);
                drop(resumed);
            }
        }
        for file in [chain_path, pool_path, voter_path] {
            std::fs::remove_file(file).unwrap();
        }
    }
}
