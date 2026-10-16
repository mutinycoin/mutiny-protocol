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
fn recovery_past_rotation_replays_only_durably_reserved_local_votes() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/custody-catchup-public-v1.json"
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
    let first = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let second = BlockEnvelope::decode(&raw(&f["second_envelope"])).unwrap();
    let old = PublicKey::decode_descriptor(&raw(&f["old_descriptor"]))
        .unwrap()
        .0;
    let new = PublicKey::decode_descriptor(&raw(&f["new_descriptor"]))
        .unwrap()
        .0;
    let pv = Vote::decode(&raw(&f["prevote"])).unwrap();
    let pc = Vote::decode(&raw(&f["precommit"])).unwrap();
    let pv2 = Vote::decode(&raw(&f["second_prevote"])).unwrap();
    let pc2 = Vote::decode(&raw(&f["second_precommit"])).unwrap();
    let next = Vote::decode(&raw(&f["next_prevote"])).unwrap();
    let node = pv.node;
    for scenario in [
        "recorded_later_votes",
        "unrecorded_later_votes",
        "rotation_behind_tip",
    ] {
        println!("SYNTHETIC_CATCHUP_SCENARIO={scenario}");
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let base = std::env::temp_dir().join(format!(
            "build8-custody-catchup-{scenario}-{}",
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
            votes: vec![pv.clone(), pc.clone()],
        };
        let new_backend = || Recorded {
            counter: counter.clone(),
            public: new.clone(),
            votes: vec![pv2.clone(), pc2.clone(), next.clone()],
        };
        let mut runtime =
            VotingRuntime::open(open_runtime(), &voter_path, node, Some(100), old_backend).unwrap();
        // Existing behavior test, not about time: a controlled eligible clock (the default is fail-closed).
        runtime.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(u64::MAX));
        runtime.validate_proposal(&first).unwrap();
        assert_eq!(
            runtime
                .sign(Step::Prevote, Some(first.block_hash()), None)
                .unwrap(),
            pv
        );
        runtime.observe(&pv).unwrap();
        assert_eq!(
            runtime
                .sign(Step::Precommit, Some(first.block_hash()), None)
                .unwrap(),
            pc
        );
        if scenario == "rotation_behind_tip" {
            runtime
                .validator()
                .install(&first.encode().unwrap())
                .unwrap();
            runtime
                .validator()
                .install(&second.encode().unwrap())
                .unwrap();
        }
        let activated = Cell::new(false);
        let result = runtime
            .install_with_rotation(&first.encode().unwrap(), |b, _| {
                activated.set(true);
                b.public = new.clone();
                b.votes = vec![pv2.clone(), pc2.clone(), next.clone()];
                Ok(())
            })
            .unwrap();
        assert!(activated.get());
        if scenario == "rotation_behind_tip" {
            assert!(matches!(result.custody, CustodyProgress::Stopped(_)));
            assert_eq!(runtime.validator().head().unwrap().height, 2);
            assert!(runtime.sign(Step::Prevote, None, None).is_err());
            drop(runtime);
            assert!(
                VotingRuntime::open_after_rotation(
                    open_runtime(),
                    &voter_path,
                    node,
                    1,
                    new_backend()
                )
                .is_err()
            );
            assert_eq!(counter.borrow().calls, 2);
        } else {
            assert!(matches!(
                result.custody,
                CustodyProgress::Ready { next_height: 2 }
            ));
            if scenario == "recorded_later_votes" {
                runtime.validate_proposal(&second).unwrap();
                assert_eq!(
                    runtime
                        .sign(Step::Prevote, Some(second.block_hash()), None)
                        .unwrap(),
                    pv2
                );
                runtime.observe(&pv2).unwrap();
                assert_eq!(
                    runtime
                        .sign(Step::Precommit, Some(second.block_hash()), None)
                        .unwrap(),
                    pc2
                );
            }
            runtime
                .validator()
                .install(&second.encode().unwrap())
                .unwrap();
            assert_eq!(runtime.validator().head().unwrap().height, 2);
            drop(runtime);
            let calls = counter.borrow().calls;
            let recovered = VotingRuntime::open_after_rotation(
                open_runtime(),
                &voter_path,
                node,
                1,
                new_backend(),
            );
            assert_eq!(
                counter.borrow().calls,
                calls,
                "recovery must not invoke private signer"
            );
            if scenario == "recorded_later_votes" {
                let mut recovered = recovered.unwrap();
                assert_eq!(recovered.sign(Step::Prevote, None, None).unwrap(), next);
                assert_eq!(next.sequence, 5);
                drop(recovered);
                let calls = counter.borrow().calls;
                let mut resumed =
                    VotingRuntime::open(open_runtime(), &voter_path, node, None, new_backend())
                        .unwrap();
                assert_eq!(resumed.replay(Step::Prevote).unwrap(), Some(next.clone()));
                assert_eq!(counter.borrow().calls, calls);
                drop(resumed);
            } else {
                assert!(recovered.is_err());
            }
        }
        for file in [chain_path, pool_path, voter_path] {
            std::fs::remove_file(file).unwrap();
        }
    }
}
