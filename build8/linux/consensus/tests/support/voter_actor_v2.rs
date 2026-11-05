//! Real dual signatures and synthetic counter only; no physical qualification.
use mutiny_consensus_v8::{
    Hash,
    anchors::FinalizedAnchor,
    bft::Step,
    block_envelope_v2::BlockEnvelope,
    canonical_store_v2::CanonicalStore,
    continuity_v2::Certificate,
    counter_store::MonotonicCounter,
    counter_voter_v2::CounterSigningBackend,
    execution::State,
    voter_actor_v2::{ActorError, VoterActor},
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey};
struct Backend<'a> {
    key: &'a HybridKey,
    counter: u64,
    calls: u64,
    interrupt: bool,
    fail_sign: bool,
}
impl MonotonicCounter for Backend<'_> {
    fn read(&mut self) -> Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> Result<(), String> {
        self.counter = self.counter.checked_add(1).ok_or("overflow")?;
        if self.interrupt {
            self.interrupt = false;
            return Err("synthetic post-increment failure".into());
        }
        Ok(())
    }
}
impl CounterSigningBackend for Backend<'_> {
    fn public_key(&self) -> &PublicKey {
        self.key.public()
    }
    fn sign_vote(&mut self, message: &[u8]) -> Result<HybridSignature, String> {
        self.calls += 1;
        if self.fail_sign {
            return Err("synthetic interruption at the signing boundary".into());
        }
        self.key
            .sign(Domain::ContinuityVote, message)
            .map_err(|_| "sign".into())
    }
}
pub fn qualify(
    state: &State,
    genesis: &FinalizedAnchor,
    root: Hash,
    fixture: &BlockEnvelope,
    key: &HybridKey,
) {
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base = std::env::temp_dir().join(format!("build8-hybrid-actor-{}", hex::encode(nonce)));
    let chain_path = base.with_extension("chain.sqlite");
    let voter_path = base.with_extension("voter.sqlite");
    let mut chain =
        CanonicalStore::open_trusted_genesis(&chain_path, genesis, state, root, 1000, [255; 32])
            .unwrap();
    let node = fixture.certificate.votes[0].node;
    let mut backend = Backend {
        key,
        counter: 100,
        calls: 0,
        interrupt: false,
        fail_sign: false,
    };
    let mut actor =
        VoterActor::open(&voter_path, node, Some(100), &mut chain, &mut backend).unwrap();
    // Existing behavior test, not about time: a controlled eligible clock (the default is fail-closed).
    actor.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(u64::MAX));
    assert_eq!(actor.node(), node);
    assert_eq!(actor.height(), 1);
    assert!(actor.progress().unwrap().1.is_none());
    assert!(
        actor
            .timeout_precommit(&chain, &mut backend)
            .unwrap()
            .is_none()
    );
    assert!(chain.canonical_block(0).unwrap().is_none());
    assert!(chain.canonical_block(1).unwrap().is_none());
    // AM-4: evidence_history takes the whole block body (same bounds and height checks).
    let body = |height: u64, operations: Vec<Vec<u8>>| mutiny_consensus_v8::blocks::BlockBody {
        height,
        reward_owner: [0; 32],
        fees: 0,
        transactions: vec![],
        operations,
    };
    assert!(chain.evidence_history(0, &body(0, vec![])).is_err());
    assert!(chain.evidence_history(2, &body(2, vec![])).is_err());
    for operations in [
        vec![vec![0; 16385]],
        vec![vec![0]; 4097],
        vec![vec![0; 16384]; 5],
    ] {
        assert!(chain.evidence_history(1, &body(1, operations)).is_err());
    }
    let mut bad = fixture.clone();
    bad.header.candidate.state_root[0] ^= 1;
    assert!(actor.validate_proposal(&chain, &bad).is_err());
    actor.validate_proposal(&chain, fixture).unwrap();
    let prevote = actor
        .sign(
            &chain,
            Step::Prevote,
            Some(fixture.block_hash()),
            None,
            &mut backend,
        )
        .unwrap();
    assert_eq!(prevote.sequence, 1);
    let mut malformed = prevote.clone();
    malformed.signature.ed448[0] ^= 1;
    assert!(actor.observe(&chain, &malformed, &mut backend).is_err());
    // Malformed own-looking peer input must not poison custody.
    actor.observe(&chain, &prevote, &mut backend).unwrap();
    let precommit = actor
        .sign(
            &chain,
            Step::Precommit,
            Some(fixture.block_hash()),
            None,
            &mut backend,
        )
        .unwrap();
    assert_eq!(precommit.sequence, 2);
    actor.observe(&chain, &precommit, &mut backend).unwrap();
    let block = BlockEnvelope {
        certificate: Certificate {
            decision: precommit.decision.clone(),
            votes: vec![precommit.clone()],
        },
        ..fixture.clone()
    };
    if std::env::var_os("BUILD8_EXPORT_HYBRID_ACTOR_PUBLIC_V1").is_some() {
        let records: Vec<_> = state
            .records()
            .unwrap()
            .iter()
            .map(|(k, v)| serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)}))
            .collect();
        let public = serde_json::json!({"synthetic_only":true,"production_authorized":false,
            "genesis":hex::encode(genesis.encode()),"root":hex::encode(root),"records":records,
            "envelope":hex::encode(block.encode().unwrap()),"prevote":hex::encode(prevote.encode().unwrap()),
            "precommit":hex::encode(precommit.encode().unwrap())});
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/hybrid-voter-actor-public-v1.json");
        assert!(!path.exists());
        std::fs::write(path, serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    }
    let calls = backend.calls;
    let counter = backend.counter;
    drop(actor);
    let mut actor = VoterActor::open(&voter_path, node, None, &mut chain, &mut backend).unwrap();
    assert_eq!(
        actor.replay(&chain, Step::Prevote, &mut backend).unwrap(),
        Some(prevote)
    );
    assert_eq!(
        actor.replay(&chain, Step::Precommit, &mut backend).unwrap(),
        Some(precommit)
    );
    assert_eq!(backend.calls, calls);
    assert_eq!(backend.counter, counter);
    // The chain commit becomes durable before the local counter advance.
    assert!(chain.commit(&block).unwrap());
    assert_eq!(chain.canonical_block(1).unwrap(), Some(block.clone()));
    backend.interrupt = true;
    assert!(actor.reconcile(&mut chain, &mut backend).is_err());
    assert!(actor.progress().is_err());
    assert_eq!(chain.load().unwrap().0.height, 1);
    assert!(!chain.halted().unwrap());
    assert_eq!(backend.calls, calls);
    assert_eq!(backend.counter, counter + 1);
    drop(actor);
    drop(chain);
    let mut chain =
        CanonicalStore::open_trusted_genesis(&chain_path, genesis, state, root, 1000, [255; 32])
            .unwrap();
    let mut actor = VoterActor::open(&voter_path, node, None, &mut chain, &mut backend).unwrap();
    assert_eq!(actor.height(), 2);
    assert_eq!(backend.counter, counter + 1);
    assert!(
        actor
            .replay(&chain, Step::Prevote, &mut backend)
            .unwrap()
            .is_none()
    );
    let next = actor
        .sign(&chain, Step::Prevote, None, None, &mut backend)
        .unwrap();
    assert_eq!(next.sequence, 3);
    drop(actor);
    let mut actor = VoterActor::open(&voter_path, node, None, &mut chain, &mut backend).unwrap();
    assert_eq!(
        actor.replay(&chain, Step::Prevote, &mut backend).unwrap(),
        Some(next)
    );
    drop(actor);
    let absent = base.with_extension("absent.sqlite");
    assert!(VoterActor::open(&absent, node, None, &mut chain, &mut backend).is_err());
    assert!(matches!(
        VoterActor::open(
            &absent,
            node,
            Some(backend.counter),
            &mut chain,
            &mut backend
        ),
        Err(ActorError::Rollback)
    ));
    assert!(!absent.exists());
    let rollback_path = base.with_extension("rollback.sqlite");
    let mut rollback =
        CanonicalStore::open_trusted_genesis(&rollback_path, genesis, state, root, 1000, [255; 32])
            .unwrap();
    assert!(matches!(
        VoterActor::open(&voter_path, node, None, &mut rollback, &mut backend),
        Err(ActorError::Rollback)
    ));
    drop(rollback);
    drop(chain);

    // Valid canonical own signature that was never issued by this local custody:
    // retain finalized history, halt signing, do not silently import sequence10.
    let foreign_chain_path = base.with_extension("foreign-chain.sqlite");
    let foreign_voter_path = base.with_extension("foreign-voter.sqlite");
    let mut chain = CanonicalStore::open_trusted_genesis(
        &foreign_chain_path,
        genesis,
        state,
        root,
        1000,
        [255; 32],
    )
    .unwrap();
    let mut backend = Backend {
        key,
        counter: 500,
        calls: 0,
        interrupt: false,
        fail_sign: false,
    };
    let mut actor = VoterActor::open(
        &foreign_voter_path,
        node,
        Some(500),
        &mut chain,
        &mut backend,
    )
    .unwrap();
    assert!(chain.commit(fixture).unwrap());
    assert!(actor.reconcile(&mut chain, &mut backend).is_err());
    assert!(
        actor
            .sign(&chain, Step::Prevote, None, None, &mut backend)
            .is_err()
    );
    assert_eq!(backend.calls, 0);
    assert_eq!(backend.counter, 501);
    assert_eq!(chain.load().unwrap().0.height, 1);
    assert!(!chain.halted().unwrap());
    drop(actor);
    assert!(VoterActor::open(&foreign_voter_path, node, None, &mut chain, &mut backend).is_err());
    drop(chain);
    for path in [
        chain_path,
        voter_path,
        rollback_path,
        foreign_chain_path,
        foreign_voter_path,
    ] {
        std::fs::remove_file(path).unwrap();
    }
    // Package P-E: the same fixture also proves that a time deferral never clears a genuine halt.
    halt_latch::qualify(state, genesis, root, fixture, key);
}

/// Package P-E: explicit nonfatal time deferral and the halting latch of the hybrid actor.
#[path = "halt_latch_v2.rs"]
pub mod halt_latch;
