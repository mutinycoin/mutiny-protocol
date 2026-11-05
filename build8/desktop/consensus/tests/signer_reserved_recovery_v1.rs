//! F3 (Architect, 2 Oct 2026 19:22 ET): recovery of an irrevocably reserved block vote.
//!
//! A reservation carries a durable marker that the fresh qualified-clock guard passed for exactly
//! the stored decision. Recovery of THAT decision needs no current clock; a different decision in
//! the same slot is a conflicting durable decision; a new slot needs the fresh guard.
//! Controlled clocks, OFFLINE, TEST-VALUE synthetic fixture.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    bft::Step,
    blocks::{BlockBody, state_root},
    continuity_v2::ParentVoter,
    counter_store::MonotonicCounter,
    counter_voter::CounterVoterError,
    counter_voter_v2::{CounterSigningBackend, CounterVoter},
    execution::{State, WorkParent},
    pow::WorkHeader,
    vote_clock_v1::ControlledClock,
    votes::IngressError,
    votes_v2::HeightAuthority,
    work_authority_v2::Authority,
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
use primitive_types::U256;
use std::path::PathBuf;

struct Backend {
    key: HybridKey,
    counter: u64,
    calls: u64,
    fail_sign: bool,
    path: PathBuf,
}
impl MonotonicCounter for Backend {
    fn read(&mut self) -> Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> Result<(), String> {
        self.counter = self.counter.checked_add(1).ok_or("overflow")?;
        Ok(())
    }
}
impl CounterSigningBackend for Backend {
    fn public_key(&self) -> &PublicKey {
        self.key.public()
    }
    fn sign_vote(&mut self, message: &[u8]) -> Result<HybridSignature, String> {
        self.calls += 1;
        if self.fail_sign {
            return Err("injected interruption at the signing boundary".into());
        }
        self.key
            .sign(Domain::ContinuityVote, message)
            .map_err(|_| "sign".to_string())
    }
}
fn backend(label: &str) -> Backend {
    let path = std::env::temp_dir().join(format!(
        "build8-vote-time-{label}-{}.sqlite",
        std::process::id()
    ));
    assert!(!path.exists());
    Backend {
        key: HybridKey::generate(Role::Continuity).unwrap(),
        counter: 100,
        calls: 0,
        fail_sign: false,
        path,
    }
}
fn authority(key: &PublicKey, parent: &WorkParent) -> HeightAuthority {
    let tpm = p256::ecdsa::SigningKey::from_bytes((&[9; 32]).into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    HeightAuthority {
        parent: FinalizedAnchor {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            height: parent.height,
            block: parent.block,
        },
        membership: [6; 32],
        reputation: [7; 32],
        attestation: [8; 32],
        activation_rule: None,
        voters: [(
            [9; 32],
            ParentVoter {
                lineage: [9; 32],
                admitted: true,
                physical: true,
                eligible: true,
                revoked: false,
                hardware_generation: 1,
                key_generation: 1,
                tpm_public: tpm,
                profile: [10; 32],
                public: key.clone(),
                reputation: U256::one(),
            },
        )]
        .into_iter()
        .collect(),
    }
}
fn fixture() -> (State, WorkParent, WorkHeader, Authority, BlockBody) {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/licensed-execution-v2-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let records: Vec<(Hash, Vec<u8>)> = f["parent_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&records, state_root(&records).unwrap()).unwrap();
    let b = &f["blocks"][0];
    let header = WorkHeader::decode(&raw(&b["header"])).unwrap();
    let c = &header.candidate;
    let parent = WorkParent {
        genesis: c.genesis,
        fingerprint: c.fingerprint,
        block: c.parent,
        height: c.height - 1,
        t0: 1000,
        target: c.target,
        ancestor_timestamps: vec![1000],
    };
    (
        state,
        parent,
        header,
        Authority::decode(&raw(&b["authority"])).unwrap(),
        BlockBody::decode(&raw(&b["body"])).unwrap(),
    )
}
/// Reserve an eligible decision, then interrupt at the signing boundary (the reservation is
/// durably committed, the signature is never produced). Returns the reopened parts.
fn interrupted(label: &str, step_proposal: bool) -> (Backend, HeightAuthority, State, WorkParent, WorkHeader, Authority, BlockBody) {
    let (state, parent, header, work, body) = fixture();
    let ts = header.candidate.timestamp;
    let block = header.block_hash();
    let mut b = backend(label);
    let a = authority(b.key.public(), &parent);
    let path = b.path.clone();
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    v.set_vote_clock(ControlledClock::at(ts));
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    b.fail_sign = true;
    let proposal = if step_proposal { Some(block) } else { None };
    let e = v.sign(Step::Prevote, proposal, None, &mut b).unwrap_err();
    assert!(matches!(e, CounterVoterError::Backend), "{e:?}");
    assert_eq!(b.calls, 1);
    // The interrupted signer is poisoned in-process; only a reopen can continue.
    assert!(matches!(v.progress(), Err(CounterVoterError::Poisoned)));
    drop(v);
    b.fail_sign = false;
    (b, a, state, parent, header, work, body)
}

fn reopen(b: &mut Backend, a: &HeightAuthority) -> CounterVoter {
    CounterVoter::open(&b.path.clone(), a.clone(), [9; 32], None, b).unwrap()
}

#[test]
fn reserved_decision_recovers_identically_with_unavailable_or_regressed_clock() {
    for (label, regress) in [("rec-unavailable", false), ("rec-regressed", true)] {
        let (mut b, a, _state, _parent, header, _work, _body) = interrupted(label, true);
        let ts = header.candidate.timestamp;
        let block = header.block_hash();
        let mut v = reopen(&mut b, &a);
        // Clock unavailable (fail-closed default) or regressed far below the block timestamp.
        if regress {
            v.set_vote_clock(ControlledClock::at(ts - 100));
        }
        let (locks, reserved, _) = v.progress().unwrap();
        let reserved = reserved.expect("the reservation survived the interruption");
        assert!(!locks.halted);
        assert_eq!(reserved.signature, zero_signature_for_test());
        assert_eq!(reserved.decision.block, block);
        assert_eq!(reserved.sequence, 1);
        let counter_before = b.counter;
        let recovered = v.replay(Step::Prevote, &mut b).unwrap().unwrap();
        // Exactly the reserved decision, now completely signed: nothing else was created.
        assert_eq!(recovered.unsigned().unwrap(), reserved.unsigned().unwrap());
        assert_eq!(recovered.sequence, 1);
        assert_eq!(v.last_sequence(), 1);
        assert_eq!(b.counter, counter_before + 1, "one commit, no second logical vote");
        assert_eq!(b.calls, 2);
        // Retransmitting the completed signature needs no clock and no counter.
        assert_eq!(v.replay(Step::Prevote, &mut b).unwrap().unwrap(), recovered);
        assert_eq!(b.counter, counter_before + 1);
        assert_eq!(b.calls, 2);
        let path = b.path.clone();
        drop(v);
        std::fs::remove_file(path).unwrap();
    }
}

fn zero_signature_for_test() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}

#[test]
fn sign_path_recovers_the_exact_reserved_decision_after_proposal_is_reexecuted() {
    let (mut b, a, state, parent, header, work, body) = interrupted("rec-sign", true);
    let ts = header.candidate.timestamp;
    let block = header.block_hash();
    let mut v = reopen(&mut b, &a);
    v.set_vote_clock(ControlledClock::at(ts - 100));
    // Recoverable input absence: the proposal is unknown after the restart. This is retried, not
    // a custody failure, and it neither poisons custody nor consumes anything.
    let e = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap_err();
    assert!(matches!(e, CounterVoterError::Ingress(IngressError::UnknownProposal)), "{e:?}");
    assert_eq!(b.calls, 1);
    v.progress().unwrap();
    // Re-execute the proposal under current authority; the regressed clock is still not consulted
    // for the already-authorized decision.
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    assert!(!v.time_status(block).is_eligible());
    let vote = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap();
    assert_eq!(vote.sequence, 1);
    assert_eq!(vote.decision.block, block);
    assert_eq!(v.last_sequence(), 1);
    // A NEW decision in another slot is a fresh vote and still needs the qualified clock.
    v.round_mut().unwrap().observe(&vote).unwrap();
    let e = v.sign(Step::Precommit, Some(block), None, &mut b).unwrap_err();
    assert!(
        matches!(e, CounterVoterError::Ingress(IngressError::FutureTimestamp { .. })),
        "{e:?}"
    );
    assert_eq!(v.last_sequence(), 1);
    v.progress().unwrap();
    let path = b.path.clone();
    drop(v);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn changed_context_or_decision_cannot_use_the_reservation() {
    // Changed signing context (membership differs): the stored custody refuses to open at all.
    let (mut b, a, _state, _parent, _header, _work, _body) = interrupted("rec-context", true);
    let mut other = a.clone();
    other.membership = [0x66; 32];
    assert!(CounterVoter::open(&b.path.clone(), other, [9; 32], None, &mut b).is_err());
    let path = b.path.clone();
    std::fs::remove_file(path).unwrap();

    // Same slot, different decision: a durable NIL prevote is reserved, then the same slot is
    // asked to vote a block. That is a conflicting durable decision, never a clock exemption.
    let (mut b, a, state, parent, header, work, body) = interrupted("rec-conflict", false);
    let block = header.block_hash();
    let mut v = reopen(&mut b, &a);
    v.set_vote_clock(ControlledClock::at(u64::MAX));
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    let calls = b.calls;
    let counter = b.counter;
    let e = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap_err();
    assert!(matches!(e, CounterVoterError::ConflictingVote), "{e:?}");
    // Existing safety response retained: custody is poisoned, nothing was signed or counted.
    assert!(matches!(v.progress(), Err(CounterVoterError::Poisoned)));
    assert_eq!(b.calls, calls);
    assert_eq!(b.counter, counter);
    assert_eq!(v.last_sequence(), 1);
    let path = b.path.clone();
    drop(v);
    // After a reopen, the one reserved decision is still the only one that can be completed.
    let mut v = reopen(&mut b, &a);
    let nil = v.replay(Step::Prevote, &mut b).unwrap().unwrap();
    assert!(nil.nil);
    assert_eq!(v.last_sequence(), 1);
    drop(v);
    std::fs::remove_file(path).unwrap();
}
