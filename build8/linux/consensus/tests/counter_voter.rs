use mutiny_consensus_v8::{
    Hash, NETWORK_ID, anchors::FinalizedAnchor, bft::Step, certificates::Voter,
    counter_store::MonotonicCounter, counter_voter::*, votes::HeightAuthority,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use primitive_types::U256;
#[path = "support/test_dir.rs"]
mod test_dir;
use test_dir::TestDir;
struct Backend {
    key: SigningKey,
    counter: u64,
    calls: u64,
    fail: bool,
}
#[test]
fn replay_nil_prevote_after_later_block_lock_preserves_exact_bytes_and_counter() {
    use mutiny_consensus_v8::{
        blocks::{BlockBody, GenesisDescriptor},
        execution::{State, WorkParent},
        genesis::GenesisIdentity,
        licenses::BindWorker,
        pow::{WorkAuthority, WorkHeader},
        votes::AuthenticatedRound,
    };
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let descriptor = GenesisDescriptor::decode(&raw(&v["descriptor_hex"])).unwrap();
    let identity = GenesisIdentity::new(descriptor.clone()).unwrap();
    let case = &v["cases"][0];
    let bindings: Vec<_> = case["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| BindWorker::decode(&raw(&b["binding_hex"])).unwrap())
        .collect();
    let state = State {
        licenses: identity.bind_workers(&bindings).unwrap(),
        ..State::default()
    };
    let header = WorkHeader::decode(&raw(&case["height1"]["header_hex"])).unwrap();
    let body = BlockBody::decode(&raw(&case["height1"]["body_hex"])).unwrap();
    let (work, signature) =
        WorkAuthority::from_envelope(&raw(&case["height1"]["authority_envelope_hex"])).unwrap();
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: identity.id(),
        fingerprint: descriptor.fingerprint,
        height: 0,
        block: descriptor.block_hash(state.root().unwrap()).unwrap(),
    };
    let work_parent = WorkParent {
        genesis: identity.id(),
        fingerprint: descriptor.fingerprint,
        block: parent.block,
        height: 0,
        t0: descriptor.timestamp,
        target: header.candidate.target,
        ancestor_timestamps: vec![descriptor.timestamp],
    };
    let keys: Vec<_> = (1..=4u8)
        .map(|n| SigningKey::from_bytes((&[n; 32]).into()).unwrap())
        .collect();
    let authority = HeightAuthority {
        parent,
        membership: [7; 32],
        reputation: [8; 32],
        attestation: [9; 32],
        voters: keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                (
                    [i as u8; 32],
                    Voter {
                        key_version: 1,
                        public_key: k
                            .verifying_key()
                            .to_encoded_point(true)
                            .as_bytes()
                            .try_into()
                            .unwrap(),
                        weight: U256::one(),
                    },
                )
            })
            .collect(),
    };
    let dir = TestDir::new("replay-later-lock");
    let path = dir.file("voter.sqlite");
    assert!(dir.is_empty() && !path.exists());
    let mut backend = Backend {
        key: keys[0].clone(),
        counter: 3000,
        calls: 0,
        fail: false,
    };
    let mut voter =
        CounterVoter::open(&path, authority.clone(), [0; 32], Some(3000), &mut backend).unwrap();
    // Existing behavior test: not about time. Dedicated coverage: tests/vote_timestamp_guard_v1.rs.
    voter.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(u64::MAX));
    let nil = voter.sign(Step::Prevote, None, None, &mut backend).unwrap();
    assert!(nil.nil);
    voter.round_mut().unwrap().observe(&nil).unwrap();
    voter
        .round_mut()
        .unwrap()
        .validate_proposal(&state, &work_parent, &header, &work, &signature, &body)
        .unwrap();
    let mut other = AuthenticatedRound::new(authority.clone()).unwrap();
    other
        .validate_proposal(&state, &work_parent, &header, &work, &signature, &body)
        .unwrap();
    for index in 1..4 {
        let mut vote = other
            .prepare_vote(
                [index as u8; 32],
                Step::Prevote,
                Some(header.block_hash()),
                None,
                mutiny_consensus_v8::vote_clock_v1::VoteGate::Fresh(&*mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(u64::MAX)),
            )
            .unwrap();
        let sig: Signature = keys[index].sign_prehash(&vote.signing_digest()).unwrap();
        vote.signature = sig.normalize_s().unwrap_or(sig).to_bytes().into();
        voter.round_mut().unwrap().observe(&vote).unwrap();
    }
    let committed = voter
        .sign(
            Step::Precommit,
            Some(header.block_hash()),
            None,
            &mut backend,
        )
        .unwrap();
    assert!(!committed.nil);
    let counter = backend.counter;
    let calls = backend.calls;
    drop(voter);
    let mut voter =
        CounterVoter::open(&path, authority.clone(), [0; 32], None, &mut backend).unwrap();
    assert_eq!(
        voter.progress().unwrap().0.locked.as_ref().unwrap().block,
        header.block_hash()
    );
    assert_eq!(
        voter.replay(Step::Prevote, &mut backend).unwrap(),
        Some(nil)
    );
    assert_eq!(
        voter.replay(Step::Precommit, &mut backend).unwrap(),
        Some(committed.clone())
    );
    assert_eq!(backend.counter, counter);
    assert_eq!(backend.calls, calls);
    assert_eq!(
        voter.progress().unwrap().0.locked.as_ref().unwrap().block,
        header.block_hash()
    );
    voter
        .round_mut()
        .unwrap()
        .validate_proposal(&state, &work_parent, &header, &work, &signature, &body)
        .unwrap();
    for index in 1..4 {
        let mut vote = committed.clone();
        vote.node = [index as u8; 32];
        let sig: Signature = keys[index].sign_prehash(&vote.signing_digest()).unwrap();
        vote.signature = sig.normalize_s().unwrap_or(sig).to_bytes().into();
        voter.round_mut().unwrap().observe(&vote).unwrap();
    }
    voter
        .round_mut()
        .unwrap()
        .commit(0, header.block_hash())
        .unwrap();
    let mut next = authority;
    next.parent.height = 1;
    next.parent.block = header.block_hash();
    next.reputation = [66; 32];
    next.voters.get_mut(&[0; 32]).unwrap().weight = U256::zero();
    voter.advance(next.clone(), &mut backend).unwrap();
    assert_eq!(voter.height(), 2);
    assert_eq!(backend.counter, counter + 1);
    assert_eq!(backend.calls, calls);
    voter.check_backend(&mut backend).unwrap();
    drop(voter);
    let mut voter = CounterVoter::open(&path, next, [0; 32], None, &mut backend).unwrap();
    voter.check_backend(&mut backend).unwrap();
    assert!(voter.replay(Step::Prevote, &mut backend).unwrap().is_none());
    assert!(voter.sign(Step::Prevote, None, None, &mut backend).is_err());
    assert_eq!(backend.counter, counter + 1);
    assert_eq!(backend.calls, calls);
    drop(voter);
    drop(dir);
}
impl MonotonicCounter for Backend {
    fn read(&mut self) -> Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> Result<(), String> {
        self.counter += 1;
        Ok(())
    }
}
impl CounterSigningBackend for Backend {
    fn public_key(&self) -> [u8; 33] {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }
    fn sign_digest(&mut self, digest: Hash) -> Result<[u8; 64], String> {
        self.calls += 1;
        if self.fail {
            return Err("interrupted signing".into());
        }
        let s: Signature = self.key.sign_prehash(&digest).unwrap();
        Ok(s.normalize_s().unwrap_or(s).to_bytes().into())
    }
}
#[test]
fn quorum_gated_timeout_persists_round_without_signing_or_discarding_reservations() {
    let dir = TestDir::new("timeout-voter");
    let path = dir.file("voter.sqlite");
    assert!(dir.is_empty() && !path.exists());
    let mut backend = Backend {
        key: SigningKey::from_bytes((&[32; 32]).into()).unwrap(),
        counter: 2000,
        calls: 0,
        fail: false,
    };
    let authority = HeightAuthority {
        parent: FinalizedAnchor {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 0,
            block: [3; 32],
        },
        membership: [4; 32],
        reputation: [5; 32],
        attestation: [6; 32],
        voters: [(
            [7; 32],
            Voter {
                key_version: 1,
                public_key: backend.public_key(),
                weight: U256::one(),
            },
        )]
        .into_iter()
        .collect(),
    };
    let mut voter =
        CounterVoter::open(&path, authority.clone(), [7; 32], Some(2000), &mut backend).unwrap();
    assert!(voter.timeout_precommit(&mut backend).is_err());
    assert_eq!(backend.counter, 2000);
    assert_eq!(voter.round_mut().unwrap().machine().state().round, 0);
    let prevote = voter.sign(Step::Prevote, None, None, &mut backend).unwrap();
    voter.round_mut().unwrap().observe(&prevote).unwrap();
    let precommit = voter
        .sign(Step::Precommit, None, None, &mut backend)
        .unwrap();
    voter.round_mut().unwrap().observe(&precommit).unwrap();
    let calls = backend.calls;
    let before = backend.counter;
    assert_eq!(voter.timeout_precommit(&mut backend).unwrap(), 1);
    assert_eq!(backend.counter, before + 1);
    assert_eq!(backend.calls, calls);
    drop(voter);
    let mut resumed = CounterVoter::open(&path, authority, [7; 32], None, &mut backend).unwrap();
    assert_eq!(resumed.round_mut().unwrap().machine().state().round, 1);
    assert!(resumed.timeout_precommit(&mut backend).is_err()); // Old-round quorum is not reusable.
    let vote = resumed
        .sign(Step::Prevote, None, None, &mut backend)
        .unwrap();
    assert_eq!(vote.decision.round, 1);
    drop(resumed);
    drop(dir);
}
#[test]
fn atomic_voter_reservations_signatures_and_disk_rollback_fail_closed() {
    let dir = TestDir::new("counter-voter");
    let path = dir.file("voter.sqlite");
    let backup = dir.file("snapshot.sqlite");
    let mut backend = Backend {
        key: SigningKey::from_bytes((&[31; 32]).into()).unwrap(),
        counter: 1000,
        calls: 0,
        fail: true,
    };
    let public = backend.public_key();
    let authority = || HeightAuthority {
        parent: FinalizedAnchor {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 0,
            block: [3; 32],
        },
        membership: [4; 32],
        reputation: [5; 32],
        attestation: [6; 32],
        voters: [(
            [7; 32],
            Voter {
                key_version: 1,
                public_key: public,
                weight: U256::one(),
            },
        )]
        .into_iter()
        .collect(),
    };
    {
        let mut voter =
            CounterVoter::open(&path, authority(), [7; 32], Some(1000), &mut backend).unwrap();
        std::fs::copy(&path, &backup).unwrap();
        assert!(voter.sign(Step::Prevote, None, None, &mut backend).is_err());
        assert_eq!(backend.counter, 1001);
        assert!(voter.round_mut().is_err());
    }
    backend.fail = false;
    let signed;
    {
        let mut voter =
            CounterVoter::open(&path, authority(), [7; 32], None, &mut backend).unwrap();
        signed = voter.replay(Step::Prevote, &mut backend).unwrap().unwrap();
        assert_eq!(backend.counter, 1002);
        assert_eq!(backend.calls, 2);
        assert_eq!(
            voter.replay(Step::Prevote, &mut backend).unwrap(),
            Some(signed.clone())
        );
        assert_eq!(
            voter.sign(Step::Prevote, None, None, &mut backend).unwrap(),
            signed
        );
        assert_eq!(backend.counter, 1002);
    }
    {
        let mut voter =
            CounterVoter::open(&path, authority(), [7; 32], None, &mut backend).unwrap();
        assert_eq!(
            voter.sign(Step::Prevote, None, None, &mut backend).unwrap(),
            signed
        );
        assert_eq!(backend.calls, 2);
    }
    {
        let mut wrong = authority();
        wrong.membership = [99; 32];
        let mut voter = CounterVoter::open(&path, wrong, [7; 32], None, &mut backend).unwrap();
        assert!(voter.replay(Step::Prevote, &mut backend).is_err());
        assert!(voter.sign(Step::Prevote, None, None, &mut backend).is_err());
        assert_eq!(backend.calls, 2);
    }
    std::fs::copy(&backup, &path).unwrap();
    assert!(CounterVoter::open(&path, authority(), [7; 32], None, &mut backend).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(CounterVoter::open(&path, authority(), [7; 32], Some(1000), &mut backend).is_err());
    assert_eq!(backend.calls, 2);
    drop(dir);
}

#[test]
fn zero_weight_member_keeps_custody_without_obtaining_vote_authority() {
    let dir = TestDir::new("zero-custody");
    let path = dir.file("voter.sqlite");
    assert!(dir.is_empty() && !path.exists());
    let mut backend = Backend {
        key: SigningKey::from_bytes((&[31; 32]).into()).unwrap(),
        counter: 5000,
        calls: 0,
        fail: false,
    };
    let other = SigningKey::from_bytes((&[32; 32]).into()).unwrap();
    let authority = HeightAuthority {
        parent: FinalizedAnchor {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 0,
            block: [3; 32],
        },
        membership: [4; 32],
        reputation: [5; 32],
        attestation: [6; 32],
        voters: [
            (
                [7; 32],
                Voter {
                    key_version: 1,
                    public_key: backend.public_key(),
                    weight: U256::zero(),
                },
            ),
            (
                [8; 32],
                Voter {
                    key_version: 1,
                    public_key: other
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                    weight: U256::one(),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };
    let mut voter =
        CounterVoter::open(&path, authority.clone(), [7; 32], Some(5000), &mut backend).unwrap();
    voter.check_backend(&mut backend).unwrap();
    assert_eq!(voter.node(), [7; 32]);
    assert!(voter.sign(Step::Prevote, None, None, &mut backend).is_err());
    assert_eq!(backend.counter, 5000);
    assert_eq!(backend.calls, 0);
    drop(voter);
    let mut voter = CounterVoter::open(&path, authority, [7; 32], None, &mut backend).unwrap();
    voter.check_backend(&mut backend).unwrap();
    assert!(voter.replay(Step::Prevote, &mut backend).unwrap().is_none());
    assert_eq!(backend.counter, 5000);
    assert_eq!(backend.calls, 0);
    drop(voter);
    drop(dir);
}
