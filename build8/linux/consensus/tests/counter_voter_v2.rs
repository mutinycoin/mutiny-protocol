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
    votes_v2::{AuthenticatedRound, HeightAuthority},
    work_authority_v2::Authority,
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
use primitive_types::U256;
use std::path::PathBuf;
struct Backend {
    key: HybridKey,
    counter: u64,
    calls: u64,
    fail: bool,
    corrupt: bool,
    fail_increment: bool,
    fail_signature_commit: bool,
    path: PathBuf,
}
impl MonotonicCounter for Backend {
    fn read(&mut self) -> Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> Result<(), String> {
        self.counter = self.counter.checked_add(1).ok_or("overflow")?;
        if self.fail_increment {
            self.fail_increment = false;
            return Err("synthetic post-increment interruption".into());
        }
        Ok(())
    }
}
impl CounterSigningBackend for Backend {
    fn public_key(&self) -> &PublicKey {
        self.key.public()
    }
    fn sign_vote(&mut self, message: &[u8]) -> Result<HybridSignature, String> {
        self.calls += 1;
        let db = rusqlite::Connection::open(&self.path).unwrap();
        let (tip, snapshot, pending): (Vec<u8>, Vec<u8>, Option<Vec<u8>>) = db
            .query_row("SELECT tip,snapshot,pending_snapshot FROM voter_migration", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(tip, self.counter.to_be_bytes());
        assert!(pending.is_none());
        assert!(
            snapshot.windows(message.len()).any(|x| x == message),
            "exact unsigned dual-signature message must be durable before private operations"
        );
        if self.fail {
            return Err("synthetic private operation interruption".into());
        }
        let mut s = self
            .key
            .sign(Domain::ContinuityVote, message)
            .map_err(|_| "sign")?;
        if self.corrupt {
            s.fndsa[100] ^= 1;
        }
        if self.fail_signature_commit {
            self.fail_signature_commit = false;
            self.fail_increment = true;
        }
        Ok(s)
    }
}
fn backend(label: &str) -> Backend {
    let path = std::env::temp_dir().join(format!(
        "build8-hybrid-voter-{label}-{}.sqlite",
        std::process::id()
    ));
    assert!(!path.exists());
    Backend {
        key: HybridKey::generate(Role::Continuity).unwrap(),
        counter: 100,
        calls: 0,
        fail: false,
        corrupt: false,
        fail_increment: false,
        fail_signature_commit: false,
        path,
    }
}
fn authority(key: &PublicKey) -> HeightAuthority {
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
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 0,
            block: [3; 32],
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
#[test]
fn unrecorded_valid_own_vote_persists_local_halt_but_bad_signature_does_not() {
    let mut b = backend("local-history");
    let a = authority(b.key.public());
    let path = b.path.clone();
    let context = AuthenticatedRound::new(a.clone()).unwrap().signing_context([9;32]).unwrap();
    assert!(CounterVoter::stored_height(&path,context,&mut b).is_err());
    assert!(!path.exists());
    let mut v = CounterVoter::open(&path,a.clone(),[9;32],Some(100),&mut b).unwrap();
    assert_eq!(CounterVoter::stored_height(&path,context,&mut b).unwrap(),1);
    assert!(v.matches_authority(&a));
    let mut altered = a.clone(); altered.voters.get_mut(&[9;32]).unwrap().reputation=U256::from(2);
    assert!(!v.matches_authority(&altered));
    let vote = v.sign(Step::Prevote,None,None,&mut b).unwrap();
    v.require_local_vote(&vote,&mut b).unwrap();
    let mut bad = vote.clone(); bad.signature.fndsa[0]^=1;
    assert!(v.require_local_vote(&bad,&mut b).is_err());
    v.check_backend(&mut b).unwrap();
    let counter = b.counter; let calls = b.calls;
    let mut missing = vote.clone(); missing.sequence+=1; missing.sign(&b.key).unwrap();
    assert!(matches!(v.require_local_vote(&missing,&mut b),Err(CounterVoterError::ConflictingVote)));
    assert_eq!(b.counter,counter+1); assert_eq!(b.calls,calls);
    assert!(v.replay(Step::Prevote,&mut b).is_err());
    drop(v);
    let mut v = CounterVoter::open(&path,a,[9;32],None,&mut b).unwrap();
    assert!(v.check_backend(&mut b).is_err());
    assert!(v.replay(Step::Prevote,&mut b).is_err());
    assert!(v.sign(Step::Prevote,None,None,&mut b).is_err());
    assert_eq!(b.calls,calls);
    drop(v); std::fs::remove_file(path).unwrap();
}
#[test]
fn hybrid_counter_reservation_restart_exact_replay_fault_and_rollback() {
    let mut b = backend("restart");
    let a = authority(b.key.public());
    let path = b.path.clone();
    b.fail = true;
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    assert!(matches!(
        v.sign(Step::Prevote, None, None, &mut b),
        Err(CounterVoterError::Backend)
    ));
    assert_eq!(b.counter, 101);
    assert_eq!(b.calls, 1);
    assert!(v.sign(Step::Prevote, None, None, &mut b).is_err());
    assert_eq!(b.calls, 1);
    drop(v);
    b.fail = false;
    let old_snapshot = std::fs::read(&path).unwrap();
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], None, &mut b).unwrap();
    let vote = v.replay(Step::Prevote, &mut b).unwrap().unwrap();
    assert_eq!(vote.sequence, 1);
    assert_eq!(b.counter, 102);
    assert_eq!(b.calls, 2);
    assert_eq!(v.replay(Step::Prevote, &mut b).unwrap().unwrap(), vote);
    assert_eq!(v.sign(Step::Prevote, None, None, &mut b).unwrap(), vote);
    assert_eq!(b.counter, 102);
    assert_eq!(b.calls, 2);
    v.round_mut().unwrap().observe(&vote).unwrap();
    assert_eq!(
        v.round_mut().unwrap().observe(&vote).unwrap(),
        mutiny_consensus_v8::bft::Observation::Duplicate
    );
    let mut repeated = vote.clone();
    repeated.sequence += 100;
    repeated.sign(&b.key).unwrap();
    assert!(v.round_mut().unwrap().observe(&repeated).is_err());
    let mut reused = vote.clone();
    reused.decision.step = 3;
    reused.sign(&b.key).unwrap();
    assert!(v.round_mut().unwrap().observe(&reused).is_err());
    let precommit = v.sign(Step::Precommit, None, None, &mut b).unwrap();
    assert_eq!(precommit.sequence, 2);
    v.round_mut().unwrap().observe(&precommit).unwrap();
    assert_eq!(v.timeout_precommit(&mut b).unwrap(), 1);
    assert!(v.replay(Step::Prevote, &mut b).unwrap().is_none());
    let next = v.sign(Step::Prevote, None, None, &mut b).unwrap();
    assert_eq!(next.sequence, 3);
    drop(v);
    let mut wrong = a.clone();
    wrong.membership = [11; 32];
    assert!(CounterVoter::open(&path, wrong, [9; 32], None, &mut b).is_err());
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], None, &mut b).unwrap();
    assert_eq!(v.replay(Step::Prevote, &mut b).unwrap().unwrap(), next);
    drop(v);
    // Deliberate rollback of this disposable synthetic test database only.
    std::fs::write(&path, old_snapshot).unwrap();
    assert!(CounterVoter::open(&path, a, [9; 32], None, &mut b).is_err());
    std::fs::remove_file(&path).unwrap();
}
#[test]
fn partial_signature_never_publishes_and_unsigned_reservation_survives() {
    let mut b = backend("partial");
    let a = authority(b.key.public());
    let path = b.path.clone();
    b.corrupt = true;
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    assert!(v.sign(Step::Prevote, None, None, &mut b).is_err());
    assert_eq!(b.counter, 101);
    drop(v);
    b.corrupt = false;
    let mut v = CounterVoter::open(&path, a, [9; 32], None, &mut b).unwrap();
    let vote = v.replay(Step::Prevote, &mut b).unwrap().unwrap();
    assert_eq!(vote.sequence, 1);
    assert_eq!(b.counter, 102);
    assert_eq!(b.calls, 2);
    drop(v);
    std::fs::remove_file(path).unwrap();
}
#[test]
fn post_counter_increment_interruption_recovers_without_second_increment_or_signature() {
    let mut b = backend("increment");
    let a = authority(b.key.public());
    let path = b.path.clone();
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    b.fail_increment = true;
    assert!(v.sign(Step::Prevote, None, None, &mut b).is_err());
    assert_eq!(b.counter, 101);
    assert_eq!(b.calls, 0);
    drop(v);
    let mut v = CounterVoter::open(&path, a, [9; 32], None, &mut b).unwrap();
    assert_eq!(b.counter, 101);
    assert_eq!(b.calls, 0);
    assert_eq!(
        v.replay(Step::Prevote, &mut b).unwrap().unwrap().sequence,
        1
    );
    assert_eq!(b.counter, 102);
    assert_eq!(b.calls, 1);
    drop(v);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn signed_pending_snapshot_recovers_exact_signature_and_stale_writer_cannot_sign() {
    let mut b = backend("signed-pending");
    let a = authority(b.key.public());
    let path = b.path.clone();
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    let mut stale = CounterVoter::open(&path, a.clone(), [9; 32], None, &mut b).unwrap();
    b.fail_signature_commit = true;
    assert!(v.sign(Step::Prevote, None, None, &mut b).is_err());
    assert_eq!(b.calls, 1);
    assert_eq!(b.counter, 102);
    assert!(stale.sign(Step::Prevote, None, None, &mut b).is_err());
    assert_eq!(b.calls, 1);
    drop(v);
    drop(stale);
    let db = rusqlite::Connection::open(&path).unwrap();
    let pending: Vec<u8> = db
        .query_row("SELECT pending_snapshot FROM voter_migration", [], |r| r.get(0))
        .unwrap();
    drop(db);
    let mut v = CounterVoter::open(&path, a, [9; 32], None, &mut b).unwrap();
    let vote = v.replay(Step::Prevote, &mut b).unwrap().unwrap();
    let encoded = vote.encode().unwrap();
    assert!(pending.windows(encoded.len()).any(|x| x == encoded));
    assert_eq!(b.calls, 1);
    assert_eq!(b.counter, 102);
    drop(v);
    std::fs::remove_file(path).unwrap();
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
#[test]
fn executed_hybrid_block_quorum_advances_sequence_without_legacy_authority() {
    let (state, parent, header, work, body) = fixture();
    let mut b = backend("execute");
    let mut a = authority(b.key.public());
    let path = b.path.clone();
    a.parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        height: parent.height,
        block: parent.block,
    };
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    let block = header.block_hash();
    assert!(v.sign(Step::Prevote, Some(block), None, &mut b).is_err());
    assert_eq!(b.calls, 0);
    drop(v);
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], None, &mut b).unwrap();
    // Existing behavior test: not about time. Dedicated coverage: tests/vote_timestamp_guard_v1.rs.
    v.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(u64::MAX));
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    let vote = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap();
    let mut unexecuted = AuthenticatedRound::new(a.clone()).unwrap();
    assert!(unexecuted.observe(&vote).is_err());
    v.round_mut().unwrap().observe(&vote).unwrap();
    let precommit = v.sign(Step::Precommit, Some(block), None, &mut b).unwrap();
    v.round_mut().unwrap().observe(&precommit).unwrap();
    assert!(v.round_mut().unwrap().commit(0, block).unwrap());
    let envelope = mutiny_consensus_v8::block_envelope_v2::BlockEnvelope {
        header: header.clone(),
        body: body.clone(),
        authority: work.clone(),
        certificate: mutiny_consensus_v8::continuity_v2::Certificate {
            decision: precommit.decision.clone(),
            votes: vec![precommit.clone()],
        },
    };
    let wire = envelope.encode().unwrap();
    assert_eq!(
        mutiny_consensus_v8::block_envelope_v2::BlockEnvelope::decode(&wire).unwrap(),
        envelope
    );
    assert!(mutiny_consensus_v8::block_envelope::BlockEnvelope::decode(&wire).is_err());
    let original = state.root().unwrap();
    let executed = envelope.verify_execute(&state, &parent, &a).unwrap();
    assert_eq!(executed.root, header.candidate.state_root);
    assert_eq!(state.root().unwrap(), original);
    {
        use mutiny_consensus_v8::finality_v2::{FinalityEvidenceStore,StoreError};
        let ledger_path=path.with_extension("hybrid-finality.sqlite");
        let mut ledger=FinalityEvidenceStore::open(&ledger_path,&a.parent).unwrap();
        let history=Default::default();
        assert!(ledger.record(&envelope,&state,&parent,&a,&history).unwrap());
        assert!(!ledger.record(&envelope,&state,&parent,&a,&history).unwrap());
        let mut alternate=envelope.clone();alternate.certificate.decision.round+=1;
        alternate.certificate.votes[0].decision=alternate.certificate.decision.clone();
        alternate.certificate.votes[0].sequence+=1;
        alternate.certificate.votes[0].sign(&b.key).unwrap();
        assert!(!ledger.record(&alternate,&state,&parent,&a,&history).unwrap());
        assert!(!ledger.halted().unwrap());
        let mut conflict=envelope.clone();conflict.header.nonce+=1;
        conflict.certificate.decision.block=conflict.block_hash();
        conflict.certificate.votes[0].decision=conflict.certificate.decision.clone();
        conflict.certificate.votes[0].sequence+=2;
        conflict.certificate.votes[0].sign(&b.key).unwrap();
        let mut invalid=conflict.clone();invalid.certificate.votes[0].signature.ed448[0]^=1;
        assert!(ledger.record(&invalid,&state,&parent,&a,&history).is_err());
        assert!(!ledger.halted().unwrap());
        assert!(ledger.evidence(1,conflict.block_hash()).unwrap().is_none());
        // Unexpected triggers are rejected before inserting any conflicting proof
        // or changing the halt state.
        let fault=rusqlite::Connection::open(&ledger_path).unwrap();
        fault.execute_batch("CREATE TRIGGER injected_halt_failure BEFORE UPDATE OF halted ON integrity_v2 BEGIN SELECT RAISE(ABORT,'synthetic halt write failure'); END;").unwrap();
        assert!(matches!(ledger.record(&conflict,&state,&parent,&a,&history),Err(StoreError::Integrity)));
        assert!(ledger.halted().is_err());
        fault.execute_batch("DROP TRIGGER injected_halt_failure;").unwrap();
        assert!(!ledger.halted().unwrap());
        assert!(ledger.evidence(1,conflict.block_hash()).unwrap().is_none());
        assert_eq!(ledger.anchor(1).unwrap().unwrap().block,envelope.block_hash());
        drop(fault);
        assert!(matches!(ledger.record(&conflict,&state,&parent,&a,&history),Err(StoreError::Halted)));
        assert!(ledger.halted().unwrap());
        assert_eq!(ledger.anchor(1).unwrap().unwrap().block,envelope.block_hash());
        assert_eq!(ledger.evidence(1,envelope.block_hash()).unwrap().unwrap(),envelope);
        assert_eq!(ledger.evidence(1,conflict.block_hash()).unwrap().unwrap(),conflict);
        drop(ledger);
        let mut reopened=FinalityEvidenceStore::open(&ledger_path,&a.parent).unwrap();
        assert!(reopened.halted().unwrap());
        assert!(matches!(reopened.record(&envelope,&state,&parent,&a,&history),Err(StoreError::Halted)));
        drop(reopened);
        let mut wrong=a.parent.clone();wrong.genesis[0]^=1;
        assert!(FinalityEvidenceStore::open(&ledger_path,&wrong).is_err());
        assert!(FinalityEvidenceStore::open(&ledger_path,&a.parent).unwrap().halted().unwrap());
        assert!(FinalityEvidenceStore::open(&path,&a.parent).is_err());
        let corrupt=rusqlite::Connection::open(&ledger_path).unwrap();
        corrupt.execute("UPDATE integrity_v2 SET halted=0 WHERE id=1",[]).unwrap();drop(corrupt);
        assert!(FinalityEvidenceStore::open(&ledger_path,&a.parent).is_err());
        let restore=rusqlite::Connection::open(&ledger_path).unwrap();
        restore.execute("UPDATE integrity_v2 SET halted=1 WHERE id=1",[]).unwrap();drop(restore);
        assert!(FinalityEvidenceStore::open(&ledger_path,&a.parent).unwrap().halted().unwrap());
        for orphan_height in [0u64,2] {
            let corrupt=rusqlite::Connection::open(&ledger_path).unwrap();
            corrupt.execute("INSERT INTO evidence_v2 VALUES(?1,?2,?3)",rusqlite::params![orphan_height.to_be_bytes().as_slice(),envelope.block_hash().as_slice(),envelope.encode().unwrap()]).unwrap();drop(corrupt);
            assert!(FinalityEvidenceStore::open(&ledger_path,&a.parent).is_err());
            let restore=rusqlite::Connection::open(&ledger_path).unwrap();
            restore.execute("DELETE FROM evidence_v2 WHERE height=?1",[orphan_height.to_be_bytes().as_slice()]).unwrap();drop(restore);
        }
        let corrupt=rusqlite::Connection::open(&ledger_path).unwrap();
        corrupt.execute("DELETE FROM integrity_v2 WHERE id=1",[]).unwrap();drop(corrupt);
        assert!(FinalityEvidenceStore::open(&ledger_path,&a.parent).is_err());
        let corrupt=rusqlite::Connection::open(&ledger_path).unwrap();
        corrupt.execute_batch("INSERT INTO integrity_v2 VALUES(1,1);DROP TABLE evidence_v2;").unwrap();drop(corrupt);
        assert!(FinalityEvidenceStore::open(&ledger_path,&a.parent).is_err());
        let inspect=rusqlite::Connection::open(&ledger_path).unwrap();
        assert_eq!(inspect.query_row("SELECT count(*) FROM sqlite_schema WHERE name='evidence_v2'",[],|r|r.get::<_,u64>(0)).unwrap(),0);
        drop(inspect);
        std::fs::remove_file(ledger_path).unwrap();
        assert_eq!(state.root().unwrap(),original);
    }
    for n in 0..wire.len() {
        assert!(mutiny_consensus_v8::block_envelope_v2::BlockEnvelope::decode(&wire[..n]).is_err());
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(mutiny_consensus_v8::block_envelope_v2::BlockEnvelope::decode(&extra).is_err());
    for n in 0..8 {
        let mut bad = envelope.clone();
        match n {
            0 => bad.certificate.votes[0].signature.ed448[0] ^= 1,
            1 => bad.certificate.votes[0].signature.fndsa[0] ^= 1,
            2 => bad.authority.signature.ed448[0] ^= 1,
            3 => bad.authority.signature.fndsa[0] ^= 1,
            4 => bad.certificate.decision.membership[0] ^= 1,
            5 => bad.header.candidate.state_root[0] ^= 1,
            6 => bad.body.reward_owner[0] ^= 1,
            _ => bad.certificate.votes.clear(),
        }
        assert!(
            bad.verify_execute(&state, &parent, &a).is_err(),
            "fault {n}"
        );
    }
    let mut cloud = a.clone();
    cloud.voters.get_mut(&[9; 32]).unwrap().physical = false;
    assert!(envelope.verify_execute(&state, &parent, &cloud).is_err());
    // Capacity fixture is explicitly not claimed to have valid signatures.
    let mut capacity = envelope.clone();
    capacity.certificate.votes.clear();
    for n in 1u32..=1024 {
        let mut vote = precommit.clone();
        vote.node = [0; 32];
        vote.node[28..].copy_from_slice(&n.to_be_bytes());
        capacity.certificate.votes.push(vote);
    }
    let maximum = capacity.encode().unwrap();
    assert!(maximum.len() <= mutiny_consensus_v8::block_envelope_v2::MAX_ENVELOPE_BYTES);
    assert_eq!(
        mutiny_consensus_v8::block_envelope_v2::BlockEnvelope::decode(&maximum).unwrap(),
        capacity
    );
    if std::env::var("BUILD8_EXPORT_HYBRID_ENVELOPE").as_deref() == Ok("1") {
        let member = &a.voters[&[9; 32]];
        let public = serde_json::json!({"schema":"BUILD8-HYBRID-CERTIFIED-ENVELOPE-V2-PUBLIC-V1",
            "synthetic_only":true,"envelope":hex::encode(&wire),"parent_state_root":hex::encode(original),
            "executed_state_root":hex::encode(executed.root),
            "continuity_descriptor":hex::encode(member.public.descriptor(member.key_generation).unwrap()),
            "node":hex::encode([9;32]),"lineage":hex::encode(member.lineage),
            "tpm_public":hex::encode(member.tpm_public),"profile":hex::encode(member.profile),
            "parent_roots":a.roots().map(hex::encode),"weight":"1","maximum_synthetic_signer_count":1024,
            "measured_maximum_signer_envelope_bytes":maximum.len(),
            "derived_envelope_limit":mutiny_consensus_v8::block_envelope_v2::MAX_ENVELOPE_BYTES});
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/hybrid-certified-envelope-v2-public-v1.json");
        assert!(!path.exists());
        std::fs::write(path, serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    }
    let mut next = a.clone();
    next.parent = precommit.decision.anchor();
    next.membership = [12; 32];
    next.reputation = [13; 32];
    next.attestation = [14; 32];
    v.advance(next.clone(), &mut b).unwrap();
    assert_eq!(v.height(), 2);
    assert_eq!(v.last_sequence(), 2);
    let nil = v.sign(Step::Prevote, None, None, &mut b).unwrap();
    assert_eq!(nil.sequence, 3);
    assert!(v.round_mut().unwrap().observe(&vote).is_err());
    drop(v);
    assert!(CounterVoter::open(&path, a, [9; 32], None, &mut b).is_err());
    let mut restarted = CounterVoter::open(&path, next, [9; 32], None, &mut b).unwrap();
    assert_eq!(
        restarted.replay(Step::Prevote, &mut b).unwrap().unwrap(),
        nil
    );
    drop(restarted);
    std::fs::remove_file(path).unwrap();
}
