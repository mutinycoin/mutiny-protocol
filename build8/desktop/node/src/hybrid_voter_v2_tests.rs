//! Public recorded signatures only. This integration test performs no private
//! operation and cannot sign any message absent from its synthetic fixture.
use super::*;
use crate::hybrid_runtime_v2::PendingCache;
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor, canonical_store_v2::CanonicalStore, counter_store::MonotonicCounter,
    execution::State, mempool_v2::Mempool,
};
use mutiny_crypto_v2::{HybridSignature, PublicKey};
use std::{cell::RefCell, rc::Rc};
struct Counter {
    value: u64,
    calls: u64,
    interrupt: bool,
}
struct RecordedBackend {
    counter: Rc<RefCell<Counter>>,
    public: PublicKey,
    votes: Vec<Vote>,
}
impl MonotonicCounter for RecordedBackend {
    fn read(&mut self) -> std::result::Result<u64, String> {
        Ok(self.counter.borrow().value)
    }
    fn increment(&mut self) -> std::result::Result<(), String> {
        let mut c = self.counter.borrow_mut();
        c.value = c.value.checked_add(1).ok_or("overflow")?;
        if c.interrupt {
            c.interrupt = false;
            return Err("synthetic interruption".into());
        }
        Ok(())
    }
}
impl CounterSigningBackend for RecordedBackend {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }
    fn sign_vote(&mut self, message: &[u8]) -> std::result::Result<HybridSignature, String> {
        self.counter.borrow_mut().calls += 1;
        self.votes
            .iter()
            .find(|v| v.unsigned().unwrap() == message)
            .map(|v| v.signature.clone())
            .ok_or("fixture message mismatch".into())
    }
}
#[test]
fn canonical_success_survives_cache_and_custody_faults_and_public_dispatch_reconciles() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-voter-actor-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let root: Hash = raw(&f["root"]).try_into().unwrap();
    let records: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&records, root).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let envelope = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let prevote = Vote::decode(&raw(&f["prevote"])).unwrap();
    let precommit = Vote::decode(&raw(&f["precommit"])).unwrap();
    let node = prevote.node;
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!("build8-voting-runtime-{}", hex::encode(random)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    for scenario in ["post_commit_fault", "public_transport", "unrecorded_own"] {
        let chain_path = base.join(format!("{scenario}-chain.sqlite"));
        let pool_path = base.join(format!("{scenario}-pool.sqlite"));
        let custody_path = base.join(format!("{scenario}-custody.sqlite"));
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
        let runtime = open_runtime();
        let public = runtime.current_authority(&genesis).unwrap().voters[&node]
            .public
            .clone();
        let counter = Rc::new(RefCell::new(Counter {
            value: 100,
            calls: 0,
            interrupt: false,
        }));
        let backend = || RecordedBackend {
            counter: counter.clone(),
            public: public.clone(),
            votes: vec![prevote.clone(), precommit.clone()],
        };
        let mut voter =
            VotingRuntime::open(runtime, &custody_path, node, Some(100), backend()).unwrap();
        // Existing behavior test: not about time. Dedicated coverage: tests/vote_timestamp_guard_v1.rs.
        voter.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(u64::MAX));
        if scenario != "unrecorded_own" {
            let mut candidates = crate::candidate_journal_v2::Journal::open(
                &base.join(format!("{scenario}-candidates.sqlite")),
                genesis.genesis,
                genesis.fingerprint,
                1024 * 1024,
                true,
            )
            .unwrap();
            candidates
                .preserve(
                    &voter.runtime,
                    &crate::candidate_journal_v2::Record {
                        header: envelope.header.clone(),
                        authority: envelope.authority.clone(),
                        body: envelope.body.clone(),
                    },
                )
                .unwrap();
            assert_eq!(
                voter.restore_candidate(&candidates, None).unwrap(),
                Some(envelope.block_hash())
            );
            assert_eq!(
                counter.borrow().calls,
                0,
                "candidate restoration signed a vote"
            );
            assert_eq!(
                counter.borrow().value,
                100,
                "candidate restoration advanced custody"
            );
            assert_eq!(
                voter
                    .sign(Step::Prevote, Some(envelope.block_hash()), None)
                    .unwrap(),
                prevote
            );
            voter.observe(&prevote).unwrap();
            assert_eq!(
                voter
                    .sign(Step::Precommit, Some(envelope.block_hash()), None)
                    .unwrap(),
                precommit
            );
            assert_eq!(
                voter.replay(Step::Precommit).unwrap(),
                Some(precommit.clone())
            );
            assert_eq!(counter.borrow().calls, 2);
        }
        let wire = envelope.encode().unwrap();
        if scenario == "post_commit_fault" {
            let fault = rusqlite::Connection::open(&pool_path).unwrap();
            fault
                .execute_batch("CREATE TABLE injected(value INTEGER)")
                .unwrap();
            counter.borrow_mut().interrupt = true;
            let receipt = voter.install(&wire).unwrap();
            assert!(receipt.canonical.inserted);
            assert!(matches!(
                receipt.canonical.pending,
                PendingCache::Unavailable(_)
            ));
            assert!(matches!(receipt.custody, CustodyProgress::Stopped(_)));
            assert_eq!(voter.validator().head().unwrap().height, 1);
            assert!(voter.replay(Step::Precommit).is_err());
            fault.execute_batch("DROP TABLE injected").unwrap();
            drop(fault);
            let c = counter.borrow().value;
            drop(voter);
            let mut voter =
                VotingRuntime::open(open_runtime(), &custody_path, node, None, backend()).unwrap();
            assert!(voter.replay(Step::Prevote).unwrap().is_none());
            assert_eq!(counter.borrow().value, c);
            assert_eq!(counter.borrow().calls, 2);
            let receipt = voter.install(&wire).unwrap();
            assert!(!receipt.canonical.inserted);
            assert!(matches!(
                receipt.custody,
                CustodyProgress::Ready { next_height: 2 }
            ));
        } else if scenario == "public_transport" {
            assert!(voter.validator().install(&wire).unwrap().inserted);
            // The next signing-path access reconciles public transport progress.
            assert!(voter.replay(Step::Prevote).unwrap().is_none());
            assert_eq!(counter.borrow().calls, 2);
            assert_eq!(voter.validator().head().unwrap().height, 1);
        } else {
            let receipt = voter.install(&wire).unwrap();
            assert!(receipt.canonical.inserted);
            assert!(matches!(receipt.custody, CustodyProgress::Stopped(_)));
            assert_eq!(voter.validator().head().unwrap().height, 1);
            assert_eq!(counter.borrow().calls, 0);
            assert!(voter.sign(Step::Prevote, None, None).is_err());
            drop(voter);
            assert!(
                VotingRuntime::open(open_runtime(), &custody_path, node, None, backend()).is_err()
            );
        }
        // All handles owned by the selected branch have been dropped.
    }
    println!("RETAINED_PUBLIC_VOTER_CUSTODY_EVIDENCE={}",base.display());
}

#[test]
fn bounded_probe_signing_uses_exclusive_actor_without_nv_or_vote_mutation() {
    use mutiny_consensus_v8::liveness_v2::{Fragment, Proof};
    struct ProbeBackend {
        public: PublicKey,
        proof: Proof,
        counter: Rc<RefCell<Counter>>,
    }
    impl MonotonicCounter for ProbeBackend {
        fn read(&mut self) -> std::result::Result<u64, String> {
            Ok(self.counter.borrow().value)
        }
        fn increment(&mut self) -> std::result::Result<(), String> {
            panic!("Probe mutated NV")
        }
    }
    impl CounterSigningBackend for ProbeBackend {
        fn public_key(&self) -> &PublicKey {
            &self.public
        }
        fn sign_vote(&mut self, _: &[u8]) -> std::result::Result<HybridSignature, String> {
            panic!("Probe signed BFT vote")
        }
        fn sign_work_probe(
            &mut self,
            d: &mutiny_consensus_v8::certificates::Decision,
            f: &Fragment,
        ) -> std::result::Result<HybridSignature, String> {
            if *d != self.proof.decision
                || f.unsigned(d).unwrap() != self.proof.fragments[0].unsigned(d).unwrap()
            {
                return Err("Fixture context".into());
            }
            self.counter.borrow_mut().calls += 1;
            Ok(self.proof.fragments[0].signature.clone())
        }
    }
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-work-network-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let root: Hash = raw(&f["root"]).try_into().unwrap();
    let rows: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&rows, root).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let proof = Proof::decode(&raw(&f["proof"])).unwrap();
    let node = proof.fragments[0].node;
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base = std::env::temp_dir().join(format!("build8-probe-signer-{}", hex::encode(nonce)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let chain = CanonicalStore::open_trusted_genesis(
        &base.join("chain.sqlite"),
        &genesis,
        &state,
        root,
        1000,
        [255; 32],
    )
    .unwrap();
    let authority = chain.current_authority(&genesis).unwrap();
    let runtime = HybridRuntime::from_pinned_chain(
        chain,
        Mempool::open(
            &base.join("pool.sqlite"),
            genesis.genesis,
            genesis.fingerprint,
            64 * 1024 * 1024,
        )
        .unwrap(),
    )
    .unwrap();
    let counter = Rc::new(RefCell::new(Counter {
        value: 100,
        calls: 0,
        interrupt: false,
    }));
    let backend = ProbeBackend {
        public: authority.voters[&node].public.clone(),
        proof: proof.clone(),
        counter: counter.clone(),
    };
    let path = base.join("voter.sqlite");
    let mut voter = VotingRuntime::open(runtime, &path, node, Some(100), backend).unwrap();
    let before = voter.actor.progress().unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let mut pool = crate::hybrid_work_probes_v2::WorkProbes::default();
    pool.begin(proof.decision.clone(), &authority, root, 0)
        .unwrap();
    for peer in 1..=3 {
        pool.queue([peer; 32], proof.decision.clone(), &authority, root, 0)
            .unwrap();
    }
    let mut signer = crate::hybrid_probe_dispatch_v2::ProbeSigner::default();
    assert_eq!(signer.tick(&mut voter, &mut pool, 0).unwrap(), 3);
    assert_eq!(signer.tick(&mut voter, &mut pool, 999).unwrap(), 0);
    assert_eq!(signer.tick(&mut voter, &mut pool, 1000).unwrap(), 1);
    assert!(signer.tick(&mut voter, &mut pool, 999).is_err());
    assert_eq!(signer.tick(&mut voter, &mut pool, 2000).unwrap(), 0);
    assert_eq!(counter.borrow().calls, 4);
    assert_eq!(counter.borrow().value, 100);
    assert!(voter.actor.progress().unwrap() == before);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(pool.quorum(&authority, root, 2000).unwrap().unwrap(), proof);
    drop(voter);
    println!("RETAINED_PUBLIC_PROBE_SIGNER_EVIDENCE={}",base.display());
}
