//! Synthetic software TPM profiles and public BIP39 fixture only.
use mutiny_consensus_v8::{
    recovery_history_v2 as history_record, recovery_replacement_v2 as replacement,
    recovery_witness_v2 as witness,
};
#[path = "support/license_v2.rs"]
mod license_fixture;
struct SyntheticRecoveryCustody<'a> {
    key: &'a mutiny_crypto_v2::HybridKey,
    counter: u64,
    calls: u64,
    journal: std::path::PathBuf,
}
impl mutiny_consensus_v8::counter_store::MonotonicCounter for SyntheticRecoveryCustody<'_> {
    fn read(&mut self) -> std::result::Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> std::result::Result<(), String> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or("synthetic counter overflow")?;
        Ok(())
    }
}
impl mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend for SyntheticRecoveryCustody<'_> {
    fn public_key(&self) -> &mutiny_crypto_v2::PublicKey {
        self.key.public()
    }
    fn sign_vote(
        &mut self,
        message: &[u8],
    ) -> std::result::Result<mutiny_crypto_v2::HybridSignature, String> {
        let db = rusqlite::Connection::open(&self.journal).unwrap();
        let (tip, snapshot, pending): (Vec<u8>, Vec<u8>, Option<Vec<u8>>) = db
            .query_row(
                "SELECT tip,snapshot,pending_snapshot FROM voter_migration",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(tip, self.counter.to_be_bytes());
        assert!(pending.is_none());
        assert!(snapshot.windows(message.len()).any(|x| x == message));
        self.calls += 1;
        self.key
            .sign(mutiny_crypto_v2::Domain::ContinuityVote, message)
            .map_err(|_| "synthetic recovery signer".into())
    }
}
use mutiny_consensus_v8::*;
use mutiny_consensus_v8::{
    admission_v2::{Admission, Expected, Policy},
    anchors::FinalizedAnchor,
    execution::State,
    node_admission_v2::{Binding, node_id},
    recovery::{Anchor, ContinuityState, Member},
    recovery_authority_v2::{Authority, Authorization},
    tpm::{TpmProfile, encode_quote},
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use p256::ecdsa::{Signature, SigningKey, signature::Signer, signature::hazmat::PrehashSigner};
use replacement::Replacement;
use sha2::{Digest, Sha256};
fn blob(x: &[u8]) -> Vec<u8> {
    let mut b = (x.len() as u16).to_be_bytes().to_vec();
    b.extend(x);
    b
}
fn public(k: &SigningKey, restricted: bool) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(0x23u16.to_be_bytes());
    b.extend(0xbu16.to_be_bytes());
    b.extend((if restricted { 0x50472u32 } else { 0x40472u32 }).to_be_bytes());
    b.extend(blob(&[]));
    for x in [0x10u16, 0x18, 0xb, 3, 0x10] {
        b.extend(x.to_be_bytes());
    }
    let p = k.verifying_key().to_encoded_point(false);
    b.extend(blob(p.x().unwrap()));
    b.extend(blob(p.y().unwrap()));
    blob(&b)
}
fn header(kind: u16, signer: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut b = 0xff544347u32.to_be_bytes().to_vec();
    b.extend(kind.to_be_bytes());
    b.extend(blob(signer));
    b.extend(blob(challenge));
    b.extend([0; 25]);
    b
}
fn signature(k: &SigningKey, m: &[u8]) -> Vec<u8> {
    let s: Signature = k.sign(m);
    let r = s.to_bytes();
    let mut b = vec![0, 0x18, 0, 0xb];
    b.extend(blob(&r[..32]));
    b.extend(blob(&r[32..]));
    b
}
fn profile(ak: &SigningKey) -> TpmProfile {
    let identity = SigningKey::from_bytes((&[10u8; 32]).into()).unwrap();
    let voting_public = public(&identity, false);
    let mut signer = vec![0, 0xb];
    signer.extend([11; 32]);
    let mut name = vec![0, 0xb];
    name.extend(Sha256::digest(&voting_public[2..]));
    let mut m = header(0x8017, &signer, &[0, 255, 85, 170]);
    m.extend(blob(&name));
    m.extend(blob(&signer));
    TpmProfile {
        hardware: [12; 32],
        ak_public: public(ak, true),
        voting_public,
        qualified_signer: signer,
        pcr_bitmap: [1, 0, 0],
        pcr_digest: [13; 32],
        certify_signature: signature(ak, &m),
        certify_message: m,
        admission_trust_manifest: [14; 32],
        provenance: None,
    }
}
fn quote(ak: &SigningKey, p: &TpmProfile, c: [u8; 32]) -> Vec<u8> {
    let mut m = header(0x8018, &p.qualified_signer, &c);
    m.extend(1u32.to_be_bytes());
    m.extend(0xbu16.to_be_bytes());
    m.push(3);
    m.extend(p.pcr_bitmap);
    m.extend(blob(&p.pcr_digest));
    encode_quote(&m, &signature(ak, &m)).unwrap()
}

#[test]
fn first_resumed_licensed_block_requires_recovery_and_replacement_hybrid_quorum() {
    let phrase = format!("{}art", "abandon ".repeat(23));
    let owner = HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap();
    let recovery = HybridKey::wallet_restore(&phrase, Role::WalletRecovery).unwrap();
    let old_node = HybridKey::generate(Role::Node).unwrap();
    let old_continuity = HybridKey::generate(Role::Continuity).unwrap();
    let new_node = HybridKey::generate(Role::Node).unwrap();
    let new_continuity = HybridKey::generate(Role::Continuity).unwrap();
    let ak = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let original_profile = profile(&ak);
    let policy = Policy {
        genesis: [1; 32],
        fingerprint: [2; 32],
        owner_descriptor: owner.public().descriptor(1).unwrap(),
        endorsement_roots: [[3; 32]].into_iter().collect(),
    };
    let descriptor = old_node.public().descriptor(1).unwrap();
    let id = node_id(policy.genesis, &descriptor).unwrap();
    let z = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    let mut binding = Binding {
        node_signer: None,
        node_descriptor: descriptor,
        possession: z.clone(),
        admission: Admission {
            genesis: policy.genesis,
            fingerprint: policy.fingerprint,
            node: id,
            hardware_generation: 1,
            key_generation: 1,
            continuity_descriptor: old_continuity.public().descriptor(1).unwrap(),
            profile: original_profile.encode().unwrap(),
            endorsement_root: [3; 32],
            owner: owner.public().address_id(1).unwrap(),
            supervised_nonce: [5; 32],
            quote: vec![],
            possession: z.clone(),
            authorization: z,
        },
    };
    binding.admission.prove_continuity(&old_continuity).unwrap();
    binding.admission.quote = quote(
        &ak,
        &original_profile,
        binding.admission.challenge().unwrap(),
    );
    binding.admission.authorize(&owner, 1).unwrap();
    binding.sign(&old_node).unwrap();
    let mut state = State::default();
    state.wallets.register(&policy.owner_descriptor).unwrap();
    state.admission_policy_v2 = Some(admission_policy_v2::Record::new(policy.clone()).unwrap());
    (state.membership_v2, state.continuity_keys_v2) = membership_v2::Book::genesis(
        &binding,
        &policy,
        &Expected {
            node: id,
            hardware_generation: 1,
            key_generation: 1,
            supervised_nonce: [5; 32],
        },
        &state.wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest,
    )
    .unwrap();
    state.continuity = Some(
        ContinuityState::bootstrap(
            policy.genesis,
            policy.fingerprint,
            Anchor {
                height: 0,
                tip: [19; 32],
                state_root: [0; 32],
                registry_root: [0; 32],
            },
            [20; 32],
            vec![Member {
                lineage: id,
                node: id,
                hardware: original_profile.hardware,
                generation: 1,
                voting_key: tpm::public_key(&original_profile.voting_public, false).unwrap(),
                attestation: original_profile.commitment().unwrap(),
                history: Default::default(),
                physical: true,
                eligible: true,
                genesis_member: true,
            }],
        )
        .unwrap(),
    );
    state.recovery_authority_v2 = Some(Authority {
        genesis: policy.genesis,
        fingerprint: policy.fingerprint,
        descriptor: recovery.public().descriptor(1).unwrap(),
    });
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: policy.genesis,
        fingerprint: policy.fingerprint,
        height: 0,
        block: [19; 32],
    };
    let (license_owner, assignments, expected, licenses, coordinator) = license_fixture::fixtures();
    assert_eq!(license_owner.public(), owner.public());
    state.licenses_v2 = license_book_v2::Book::genesis(
        &assignments,
        &expected,
        &licenses,
        &state.wallets,
        policy.genesis,
        policy.fingerprint,
    )
    .unwrap();
    let root = state.root().unwrap();
    let authority = votes_v2::HeightAuthority::from_state(&state, parent.clone(), root).unwrap();
    let native = SigningKey::from_bytes((&[18u8; 32]).into()).unwrap();
    let mut replacement_profile = original_profile.clone();
    replacement_profile.hardware = [55; 32];
    replacement_profile.voting_public = public(&native, false);
    let mut name = vec![0, 0xb];
    name.extend(Sha256::digest(&replacement_profile.voting_public[2..]));
    let mut certify = header(
        0x8017,
        &replacement_profile.qualified_signer,
        &[0, 255, 85, 170],
    );
    certify.extend(blob(&name));
    certify.extend(blob(&replacement_profile.qualified_signer));
    replacement_profile.certify_signature = signature(&ak, &certify);
    replacement_profile.certify_message = certify;
    binding.node_descriptor = new_node.public().descriptor(1).unwrap();
    binding.admission.node = node_id(policy.genesis, &binding.node_descriptor).unwrap();
    binding.admission.hardware_generation = 2;
    binding.admission.key_generation = 2;
    binding.admission.continuity_descriptor = new_continuity.public().descriptor(2).unwrap();
    binding.admission.profile = replacement_profile.encode().unwrap();
    let mut material = Replacement {
        parent: parent.clone(),
        root,
        membership: authority.membership,
        sequence: 1,
        lineage: id,
        old_node: id,
        old_hardware_generation: 1,
        old_key_generation: 1,
        nonce: [57; 32],
        lost: vec![(id, 1)],
        binding,
        native_possession: [0; 64],
    };
    material.binding.admission.supervised_nonce = material.admission_nonce().unwrap();
    material
        .binding
        .admission
        .prove_continuity(&new_continuity)
        .unwrap();
    material.binding.admission.quote = quote(
        &ak,
        &replacement_profile,
        material.binding.admission.challenge().unwrap(),
    );
    material.binding.admission.authorize(&owner, 1).unwrap();
    material.binding.sign(&new_node).unwrap();
    let sig: Signature = native
        .sign_prehash(&material.native_digest().unwrap())
        .unwrap();
    material.native_possession = sig.normalize_s().unwrap_or(sig).to_bytes().into();
    let recovery_authority = state.recovery_authority_v2.as_ref().unwrap();
    let authorization =
        Authorization::sign(material.intent().unwrap(), recovery_authority, &recovery).unwrap();
    material
        .verify_material(&state, &parent, root, &authorization, false)
        .unwrap();
    let mut tree = state_tree::StateTree::default();
    for (key, raw) in state.records().unwrap() {
        tree.insert(key, raw).unwrap();
    }
    assert_eq!(tree.root(), root);
    let witnesses = witness::Witnesses {
        control: tree.proof(
            parent.clone(),
            domain_hash(b"MUTINY-BUILD8-NODE-CONTROL-KEY-V2", &id),
        ),
        continuity: tree.proof(
            parent.clone(),
            domain_hash(b"MUTINY-BUILD8-CONTINUITY-KEY-STATE-V2", &id),
        ),
    };
    let archive = history_record::Record {
        material: material.clone(),
        authorization: authorization.clone(),
        witnesses: witnesses.clone(),
        policy: policy.clone(),
    };
    let prepared =
        recovery_transition_v2::Prepared::verify(&state, &parent, root, archive, false).unwrap();
    let body = blocks::BlockBody {
        height: 1,
        reward_owner: licenses[0].owner,
        fees: 0,
        transactions: vec![],
        operations: vec![],
    };
    let work_parent = execution::WorkParent {
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        block: parent.block,
        height: 0,
        t0: 1000,
        target: [255; 32],
        ancestor_timestamps: vec![1000],
    };
    let mut candidate = pow::Candidate {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        height: 1,
        parent: parent.block,
        timestamp: 1100,
        body_root: body.root().unwrap(),
        state_root: [0; 32],
        license: licenses[0].id,
        worker: expected[0].worker_id,
        target: work_parent.target,
    };
    let executed = prepared
        .prepare_candidate(
            &state,
            execution::CandidatePreparation {
                parent: &work_parent,
                candidate: &candidate,
                ticket_sequence: 1,
                body: &body,
            },
            &Default::default(),
        )
        .unwrap();
    candidate.state_root = executed.root;
    let mut work = work_authority_v2::Authority {
        work: pow::WorkAuthority {
            candidate: candidate.clone(),
            assignment_sequence: 1,
            ticket_sequence: 1,
            coordinator: expected[0].coordinator,
            nonce_start: 0,
            nonce_end: 100,
            epoch: 1,
        },
        node_descriptor: assignments[0].node_descriptor.clone(),
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    work.sign(&coordinator).unwrap();
    let header = pow::WorkHeader {
        candidate,
        authority: work.id().unwrap(),
        nonce: 1,
    };
    let effective = prepared.authority().unwrap();
    let new_id = material.binding.admission.node;
    let voter = &effective.voters[&new_id];
    let decision = certificates::Decision {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        purpose: 2,
        height: 1,
        mining_epoch: 1,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: header.block_hash(),
        state: executed.root,
        membership: effective.membership,
        reputation: effective.reputation,
        attestation: effective.attestation,
    };
    let mut vote = continuity_v2::Vote {
        decision: decision.clone(),
        nil: false,
        node: new_id,
        hardware_generation: 2,
        key_generation: 2,
        sequence: 1,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    vote.sign(&new_continuity).unwrap();
    let envelope = block_envelope_v2::BlockEnvelope {
        header,
        body,
        authority: work,
        certificate: continuity_v2::Certificate {
            decision,
            votes: vec![vote],
        },
    };
    let wire = envelope.encode().unwrap();
    assert_eq!(
        block_envelope_v2::BlockEnvelope::decode(&wire).unwrap(),
        envelope
    );
    let verified = prepared
        .verify_envelope(&state, &work_parent, &envelope, &Default::default())
        .unwrap();
    assert_eq!(verified.root, executed.root);
    assert!(verified.state.records().unwrap() == executed.state.records().unwrap());
    assert!(!verified.state.recovery_history_v2.is_empty());
    assert_eq!(verified.state.accounting.slots.last_height, 1);
    assert!(verified.state.membership_v2.get(id).is_none());
    assert!(verified.state.membership_v2.get(new_id).is_some());
    assert!(
        envelope
            .verify_execute_from_parent_state(&state, &work_parent, root, &Default::default())
            .is_err()
    );
    let mut bad = envelope.clone();
    bad.certificate.votes[0].sign(&old_continuity).unwrap();
    assert!(
        prepared
            .verify_envelope(&state, &work_parent, &bad, &Default::default())
            .is_err()
    );
    let mut bad = envelope.clone();
    bad.certificate.votes[0].signature.fndsa = [0; 1280];
    assert!(
        prepared
            .verify_envelope(&state, &work_parent, &bad, &Default::default())
            .is_err()
    );
    let mut bad = envelope.clone();
    bad.certificate.votes[0].signature.ed448 = [0; 114];
    assert!(
        prepared
            .verify_envelope(&state, &work_parent, &bad, &Default::default())
            .is_err()
    );
    let mut other = state.clone();
    other.recovery_authority_v2 = None;
    assert!(
        prepared
            .verify_envelope(&other, &work_parent, &envelope, &Default::default())
            .is_err()
    );
    assert_eq!(state.root().unwrap(), root);
    assert!(authority.voters.contains_key(&id));
    assert!(!authority.voters.contains_key(&new_id));
    use mutiny_consensus_v8::canonical_store_v2::CanonicalStore;
    let mut nonce = [0u8; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-recovery-durable-{}.sqlite",
        hex::encode(nonce)
    ));
    assert!(!path.exists());
    let open =
        || CanonicalStore::open_trusted_genesis(&path, &parent, &state, root, 1000, [255; 32]);
    let mut store = open().unwrap();
    let proof_key = state.records().unwrap()[0].0;
    let parent_proof = store
        .state_proof(&parent, proof_key)
        .unwrap()
        .encode()
        .unwrap();
    assert!(store.commit(&envelope).is_err());
    assert!(!store.halted().unwrap());
    for part in 0..2 {
        let mut invalid = prepared.record().clone();
        if part == 0 {
            invalid.authorization.signature.ed448[0] ^= 1;
        } else {
            invalid.authorization.signature.fndsa[0] ^= 1;
        }
        assert!(store.accept_recovery(invalid).is_err());
        assert_eq!(store.load().unwrap().0.root, root);
        assert!(
            store
                .current_authority(&parent)
                .unwrap()
                .voters
                .contains_key(&id)
        );
    }
    assert!(store.accept_recovery(prepared.record().clone()).unwrap());
    assert!(!store.accept_recovery(prepared.record().clone()).unwrap());
    assert!(store.current_node_authority(&parent, id).is_err());
    assert_eq!(
        store
            .current_node_authority(&parent, new_id)
            .unwrap()
            .descriptor(),
        prepared.record().material.binding.node_descriptor
    );
    let custody_path = path.with_extension("voter.sqlite");
    assert!(!custody_path.exists());
    let mut backend = SyntheticRecoveryCustody {
        key: &new_continuity,
        counter: 100,
        calls: 0,
        journal: custody_path.clone(),
    };
    // Uses the existing height-one initialization gate only. Post-Genesis fresh
    // custody and physical TPM provisioning are not claimed by this model test.
    let mut actor = voter_actor_v2::VoterActor::open(
        &custody_path,
        new_id,
        Some(100),
        &mut store,
        &mut backend,
    )
    .unwrap();
    // Existing behavior test: not about time. Dedicated coverage: tests/vote_timestamp_guard_v1.rs.
    actor.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(u64::MAX));
    actor.validate_proposal(&store, &envelope).unwrap();
    let prevote = actor
        .sign(
            &store,
            bft::Step::Prevote,
            Some(envelope.block_hash()),
            None,
            &mut backend,
        )
        .unwrap();
    actor.observe(&store, &prevote, &mut backend).unwrap();
    let precommit = actor
        .sign(
            &store,
            bft::Step::Precommit,
            Some(envelope.block_hash()),
            None,
            &mut backend,
        )
        .unwrap();
    actor.observe(&store, &precommit, &mut backend).unwrap();
    let mut envelope = envelope;
    envelope.certificate.votes = vec![precommit.clone()];
    let calls = backend.calls;
    assert_eq!(calls, 2);
    assert_eq!(
        actor
            .replay(&store, bft::Step::Precommit, &mut backend)
            .unwrap(),
        Some(precommit)
    );
    assert_eq!(backend.calls, calls);
    drop(actor);
    let mut actor =
        voter_actor_v2::VoterActor::open(&custody_path, new_id, None, &mut store, &mut backend)
            .unwrap();
    let mut stale_round = votes_v2::AuthenticatedRound::new(authority.clone()).unwrap();
    assert!(
        store
            .validate_round_proposal(
                &mut stale_round,
                &envelope.header,
                &envelope.authority,
                &envelope.body
            )
            .is_err()
    );
    let mut resumed_round =
        votes_v2::AuthenticatedRound::new(store.current_authority(&parent).unwrap()).unwrap();
    assert_eq!(
        store
            .validate_round_proposal(
                &mut resumed_round,
                &envelope.header,
                &envelope.authority,
                &envelope.body
            )
            .unwrap()
            .root,
        executed.root
    );
    assert!(
        resumed_round
            .observe(&envelope.certificate.votes[0])
            .is_ok()
    );
    assert_eq!(store.load().unwrap().0.root, root);
    assert!(store.load().unwrap().1.records().unwrap() == state.records().unwrap());
    assert_eq!(
        store
            .state_proof(&parent, proof_key)
            .unwrap()
            .encode()
            .unwrap(),
        parent_proof
    );
    let pool_path = path.with_extension("pending.sqlite");
    assert!(!pool_path.exists());
    let mut pool = mempool_v2::Mempool::open(
        &pool_path,
        parent.genesis,
        parent.fingerprint,
        64 * 1024 * 1024,
    )
    .unwrap();
    store.reconcile_pool(&mut pool).unwrap();
    let assembled = store
        .prepare_pending(canonical_store_v2::Preparation {
            expected_parent: &parent,
            pool: &pool,
            license: envelope.header.candidate.license,
            worker: envelope.header.candidate.worker,
            timestamp: envelope.header.candidate.timestamp,
            ticket: envelope.authority.work.ticket_sequence,
            operations: &envelope.body.operations,
        })
        .unwrap();
    assert_eq!(assembled.candidate, envelope.header.candidate);
    assert_eq!(assembled.body, envelope.body);
    assert_eq!(assembled.execution.root, executed.root);
    drop(pool);
    std::fs::remove_file(pool_path).unwrap();
    assert!(
        store
            .current_authority(&parent)
            .unwrap()
            .voters
            .contains_key(&new_id)
    );
    assert!(
        !store
            .current_authority(&parent)
            .unwrap()
            .voters
            .contains_key(&id)
    );
    drop(store);
    let mut store = open().unwrap();
    assert!(
        store
            .current_authority(&parent)
            .unwrap()
            .voters
            .contains_key(&new_id)
    );
    assert_eq!(
        store
            .state_proof(&parent, proof_key)
            .unwrap()
            .encode()
            .unwrap(),
        parent_proof
    );
    assert!(store.commit(&envelope).unwrap());
    actor.reconcile(&mut store, &mut backend).unwrap();
    assert_eq!(actor.height(), 2);
    assert_eq!(backend.calls, calls);
    drop(actor);
    let actor =
        voter_actor_v2::VoterActor::open(&custody_path, new_id, None, &mut store, &mut backend)
            .unwrap();
    assert_eq!(actor.height(), 2);
    drop(actor);
    std::fs::remove_file(custody_path).unwrap();
    assert!(!store.commit(&envelope).unwrap());
    assert!(!store.accept_recovery(prepared.record().clone()).unwrap());
    assert_eq!(store.load().unwrap().0.root, executed.root);
    assert!(store.load().unwrap().1.records().unwrap() == executed.state.records().unwrap());
    drop(store);
    let store = open().unwrap();
    assert_eq!(store.load().unwrap().0.height, 1);
    assert_eq!(store.load().unwrap().0.root, executed.root);
    // Both kinds of liability remain verifiable at the resumed height. The
    // original context must not be overwritten by the recovery-effective one.
    let mut old_a = envelope.certificate.votes[0].clone();
    old_a.node = id;
    old_a.hardware_generation = 1;
    old_a.key_generation = 1;
    old_a.tpm_identity = authority.voters[&id].tpm_identity();
    old_a.profile = authority.voters[&id].profile;
    old_a.decision.membership = authority.membership;
    old_a.decision.reputation = authority.reputation;
    old_a.decision.attestation = authority.attestation;
    old_a.sign(&old_continuity).unwrap();
    let mut old_b = old_a.clone();
    old_b.decision.block[0] ^= 1;
    old_b.sign(&old_continuity).unwrap();
    let old_evidence = equivocation_v2::Evidence::new(old_a, old_b).unwrap();
    let new_a = envelope.certificate.votes[0].clone();
    let mut new_b = new_a.clone();
    new_b.decision.block[0] ^= 1;
    new_b.sign(&new_continuity).unwrap();
    let new_evidence = equivocation_v2::Evidence::new(new_a, new_b).unwrap();
    let inclusion = envelope.certificate.decision.anchor();
    let historical = store
        .evidence_history(
            2,
            // AM-4: the whole block body carrying the two evidence operations.
            &blocks::BlockBody {
                height: 2,
                reward_owner: [0; 32],
                fees: 0,
                transactions: vec![],
                operations: vec![
                    old_evidence.encode().unwrap(),
                    new_evidence.encode().unwrap(),
                ],
            },
        )
        .unwrap();
    assert!(historical.settlement(&old_evidence, &inclusion).is_ok());
    assert!(historical.settlement(&new_evidence, &inclusion).is_ok());
    let original_only: evidence_history_v2::History =
        [(1, authority.clone())].into_iter().collect();
    assert!(original_only.settlement(&old_evidence, &inclusion).is_ok());
    assert!(original_only.settlement(&new_evidence, &inclusion).is_err());
    let mut mixed = new_evidence.clone();
    mixed.a.decision.membership = authority.membership;
    mixed.a.sign(&new_continuity).unwrap();
    mixed = equivocation_v2::Evidence::new(mixed.a, mixed.b).unwrap();
    assert!(historical.settlement(&mixed, &inclusion).is_err());
    drop(store);
    let db = rusqlite::Connection::open(&path).unwrap();
    let bytes: Vec<u8> = db
        .query_row("SELECT record FROM accepted_recovery_v2", [], |r| r.get(0))
        .unwrap();
    db.execute("UPDATE accepted_recovery_v2 SET record=?1", [vec![0u8]])
        .unwrap();
    assert!(open().is_err());
    db.execute("UPDATE accepted_recovery_v2 SET record=?1", [&bytes])
        .unwrap();
    assert!(open().is_ok());
    db.execute(
        "INSERT INTO accepted_recovery_v2 SELECT ?1,commitment,record FROM accepted_recovery_v2",
        [2u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    assert!(open().is_err());
    db.execute(
        "DELETE FROM accepted_recovery_v2 WHERE height=?1",
        [2u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    assert!(open().is_ok());
    db.execute("DELETE FROM accepted_recovery_v2", []).unwrap();
    assert!(open().is_err());
    drop(db);
    std::fs::remove_file(path).unwrap();
    // Build a completely valid ordinary certificate/execution at the same
    // parent, rather than treating a signature over an unexecuted candidate as
    // finality evidence in the recovery/write race.
    let mut ordinary = envelope.clone();
    let ordinary_execution = state
        .prepare_candidate_v2(execution::CandidatePreparation {
            parent: &work_parent,
            candidate: &ordinary.header.candidate,
            ticket_sequence: ordinary.authority.work.ticket_sequence,
            body: &ordinary.body,
        })
        .unwrap();
    ordinary.header.candidate.state_root = ordinary_execution.root;
    ordinary.authority.work.candidate = ordinary.header.candidate.clone();
    ordinary.authority.sign(&coordinator).unwrap();
    ordinary.header.authority = ordinary.authority.id().unwrap();
    let mut v = ordinary.certificate.votes[0].clone();
    v.node = id;
    v.hardware_generation = 1;
    v.key_generation = 1;
    v.tpm_identity = authority.voters[&id].tpm_identity();
    v.profile = authority.voters[&id].profile;
    v.decision.membership = authority.membership;
    v.decision.reputation = authority.reputation;
    v.decision.attestation = authority.attestation;
    v.decision.block = ordinary.block_hash();
    v.decision.state = ordinary_execution.root;
    v.sign(&old_continuity).unwrap();
    ordinary.certificate.decision = v.decision.clone();
    ordinary.certificate.votes = vec![v];
    ordinary
        .verify_execute_from_parent_state(&state, &work_parent, root, &Default::default())
        .unwrap();
    recovery_finality_orders(&state, &parent, root, prepared.record(), &ordinary);
    let post_parent = ordinary.certificate.decision.anchor();
    let post = ordinary_execution.state;
    let post_root = post.root().unwrap();
    let post_authority =
        votes_v2::HeightAuthority::from_state(&post, post_parent.clone(), post_root).unwrap();
    let mut later = material.clone();
    later.parent = post_parent.clone();
    later.root = post_root;
    later.membership = post_authority.membership;
    later.nonce = [83; 32];
    later.binding.admission.supervised_nonce = later.admission_nonce().unwrap();
    later
        .binding
        .admission
        .prove_continuity(&new_continuity)
        .unwrap();
    later.binding.admission.quote = quote(
        &ak,
        &replacement_profile,
        later.binding.admission.challenge().unwrap(),
    );
    later.binding.admission.authorize(&owner, 1).unwrap();
    later.binding.sign(&new_node).unwrap();
    let signature: Signature = native
        .sign_prehash(&later.native_digest().unwrap())
        .unwrap();
    later.native_possession = signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .into();
    let authorization = Authorization::sign(
        later.intent().unwrap(),
        post.recovery_authority_v2.as_ref().unwrap(),
        &recovery,
    )
    .unwrap();
    let mut tree = state_tree::StateTree::default();
    for (key, raw) in post.records().unwrap() {
        tree.insert(key, raw).unwrap();
    }
    let record = history_record::Record {
        material: later,
        authorization,
        policy: policy.clone(),
        witnesses: witness::Witnesses {
            control: tree.proof(
                post_parent.clone(),
                domain_hash(b"MUTINY-BUILD8-NODE-CONTROL-KEY-V2", &id),
            ),
            continuity: tree.proof(
                post_parent.clone(),
                domain_hash(b"MUTINY-BUILD8-CONTINUITY-KEY-STATE-V2", &id),
            ),
        },
    };
    let later_prepared = recovery_transition_v2::Prepared::verify(
        &post,
        &post_parent,
        post_root,
        record.clone(),
        false,
    )
    .unwrap();
    let later_path = std::env::temp_dir().join(format!(
        "build8-recovery-height-two-{}.sqlite",
        hex::encode(nonce)
    ));
    let journal = later_path.with_extension("voter.sqlite");
    assert!(!later_path.exists() && !journal.exists());
    let mut chain =
        CanonicalStore::open_trusted_genesis(&later_path, &parent, &state, root, 1000, [255; 32])
            .unwrap();
    chain.commit(&ordinary).unwrap();
    let commitment = record.material.commitment().unwrap();
    let mut backend = SyntheticRecoveryCustody {
        key: &new_continuity,
        counter: 100,
        calls: 0,
        journal: journal.clone(),
    };
    assert!(
        voter_actor_v2::VoterActor::initialize_recovery(
            &journal,
            new_id,
            &post_parent,
            commitment,
            100,
            &mut chain,
            &mut backend
        )
        .is_err()
    );
    assert!(!journal.exists());
    chain.accept_recovery(record).unwrap();
    for (node, anchor, digest) in [
        (id, post_parent.clone(), commitment),
        (new_id, parent.clone(), commitment),
        (new_id, post_parent.clone(), [0; 32]),
    ] {
        assert!(
            voter_actor_v2::VoterActor::initialize_recovery(
                &journal,
                node,
                &anchor,
                digest,
                100,
                &mut chain,
                &mut backend
            )
            .is_err()
        );
        assert!(!journal.exists());
    }
    assert!(
        voter_actor_v2::VoterActor::open(&journal, new_id, Some(100), &mut chain, &mut backend)
            .is_err()
    );
    assert!(!journal.exists());
    let mut actor = voter_actor_v2::VoterActor::initialize_recovery(
        &journal,
        new_id,
        &post_parent,
        commitment,
        100,
        &mut chain,
        &mut backend,
    )
    .unwrap();
    assert_eq!(actor.height(), 2);
    // Existing behavior test: not about time. Dedicated coverage: tests/vote_timestamp_guard_v1.rs.
    actor.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(u64::MAX));
    let next_parent = execution::WorkParent {
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        block: post_parent.block,
        height: 1,
        t0: 1000,
        target: [255; 32],
        ancestor_timestamps: vec![1000, 1100],
    };
    let mut resumed = ordinary.clone();
    resumed.body.height = 2;
    resumed.header.candidate.height = 2;
    resumed.header.candidate.parent = post_parent.block;
    resumed.header.candidate.timestamp = 1160;
    resumed.header.candidate.body_root = resumed.body.root().unwrap();
    let next = later_prepared
        .prepare_candidate(
            &post,
            execution::CandidatePreparation {
                parent: &next_parent,
                candidate: &resumed.header.candidate,
                ticket_sequence: 2,
                body: &resumed.body,
            },
            &Default::default(),
        )
        .unwrap();
    resumed.header.candidate.state_root = next.root;
    resumed.authority.work.candidate = resumed.header.candidate.clone();
    resumed.authority.work.ticket_sequence = 2;
    resumed.authority.work.epoch = 2;
    resumed.authority.sign(&coordinator).unwrap();
    resumed.header.authority = resumed.authority.id().unwrap();
    actor.validate_proposal(&chain, &resumed).unwrap();
    let prevote = actor
        .sign(
            &chain,
            bft::Step::Prevote,
            Some(resumed.block_hash()),
            None,
            &mut backend,
        )
        .unwrap();
    actor.observe(&chain, &prevote, &mut backend).unwrap();
    let precommit = actor
        .sign(
            &chain,
            bft::Step::Precommit,
            Some(resumed.block_hash()),
            None,
            &mut backend,
        )
        .unwrap();
    actor.observe(&chain, &precommit, &mut backend).unwrap();
    resumed.certificate.decision = precommit.decision.clone();
    resumed.certificate.votes = vec![precommit.clone()];
    let calls = backend.calls;
    let counter = backend.counter;
    assert_eq!(calls, 2);
    drop(actor);
    assert!(
        voter_actor_v2::VoterActor::initialize_recovery(
            &journal,
            new_id,
            &post_parent,
            commitment,
            counter,
            &mut chain,
            &mut backend
        )
        .is_err()
    );
    assert_eq!(backend.counter, counter);
    assert_eq!(backend.calls, calls);
    let mut actor =
        voter_actor_v2::VoterActor::open(&journal, new_id, None, &mut chain, &mut backend).unwrap();
    assert_eq!(
        actor
            .replay(&chain, bft::Step::Precommit, &mut backend)
            .unwrap(),
        Some(precommit)
    );
    chain.commit(&resumed).unwrap();
    actor.reconcile(&mut chain, &mut backend).unwrap();
    assert_eq!(actor.height(), 3);
    assert_eq!(backend.calls, calls);
    assert!(
        chain
            .recovery_initialization_authority(&post_parent, new_id, commitment)
            .is_err()
    );
    drop(actor);
    drop(chain);
    let mut chain =
        CanonicalStore::open_trusted_genesis(&later_path, &parent, &state, root, 1000, [255; 32])
            .unwrap();
    assert_eq!(chain.load().unwrap().0.root, next.root);
    let actor =
        voter_actor_v2::VoterActor::open(&journal, new_id, None, &mut chain, &mut backend).unwrap();
    assert_eq!(actor.height(), 3);
    drop(actor);
    if let Some(path) = std::env::var_os("BUILD8_EXPORT_RECOVERY_CHAIN_V4") {
        use std::io::Write;
        let records: Vec<_> = state.records().unwrap().into_iter().map(|(key, raw)| {
            serde_json::json!({"key": hex::encode(key), "record": hex::encode(raw)})
        }).collect();
        let public = serde_json::json!({
            "schema": "BUILD8-SYNTHETIC-RECOVERY-CHAIN-V4",
            "synthetic_only": true,
            "production_authorized": false,
            "physical_tpm": false,
            "genesis_anchor": hex::encode(parent.encode()),
            "root": hex::encode(root),
            "records": records,
            "timestamp": 1000,
            "target": hex::encode([255; 32]),
            "block1": hex::encode(ordinary.encode().unwrap()),
            "recovery1": hex::encode(chain.recovery_record(1).unwrap().unwrap()),
            "block2": hex::encode(resumed.encode().unwrap()),
            "target_anchor": hex::encode(resumed.certificate.decision.anchor().encode()),
        });
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();
        file.write_all(&serde_json::to_vec_pretty(&public).unwrap()).unwrap();
        file.sync_all().unwrap();
    }
    drop(chain);
    std::fs::remove_file(journal).unwrap();
    std::fs::remove_file(later_path).unwrap();
    println!("SYNTHETIC_RECOVERY_DURABLE_REPLAY_PASS; production=false");
}

fn recovery_finality_orders(
    state: &State,
    parent: &FinalizedAnchor,
    root: Hash,
    record: &history_record::Record,
    ordinary: &block_envelope_v2::BlockEnvelope,
) {
    use canonical_store_v2::CanonicalStore;
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    for mode in 0..3 {
        let path = std::env::temp_dir().join(format!(
            "build8-recovery-race-{}-{mode}.sqlite",
            hex::encode(nonce)
        ));
        assert!(!path.exists());
        let open = || {
            CanonicalStore::open_trusted_genesis(&path, parent, state, root, 1000, [255; 32])
                .unwrap()
        };
        let mut chain = open();
        let recovered = match mode {
            0 => {
                assert!(chain.commit(ordinary).unwrap());
                assert!(chain.accept_recovery(record.clone()).is_err());
                false
            }
            1 => {
                assert!(chain.accept_recovery(record.clone()).unwrap());
                assert!(chain.commit(ordinary).is_err());
                true
            }
            _ => {
                let mut second = open();
                let barrier = std::sync::Barrier::new(2);
                let (recovery_won, ordinary_won) = std::thread::scope(|scope| {
                    let first = scope.spawn(|| {
                        barrier.wait();
                        matches!(chain.accept_recovery(record.clone()), Ok(true))
                    });
                    let second = scope.spawn(|| {
                        barrier.wait();
                        matches!(second.commit(ordinary), Ok(true))
                    });
                    (first.join().unwrap(), second.join().unwrap())
                });
                assert_ne!(
                    recovery_won, ordinary_won,
                    "exactly one authority choice must commit"
                );
                drop(second);
                recovery_won
            }
        };
        assert!(!chain.halted().unwrap());
        drop(chain);
        let chain = open();
        let (head, _) = chain.load().unwrap();
        if recovered {
            assert_eq!(head.height, 0);
            assert_eq!(head.root, root);
            assert!(
                chain
                    .current_authority(parent)
                    .unwrap()
                    .voters
                    .contains_key(&record.material.binding.admission.node)
            );
        } else {
            assert_eq!(head.height, 1);
            assert_eq!(head.root, ordinary.header.candidate.state_root);
        }
        drop(chain);
        std::fs::remove_file(path).unwrap();
    }
}
