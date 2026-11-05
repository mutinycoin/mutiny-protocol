use mutiny_consensus_v8::*;
#[path = "support/license_v2.rs"]
mod license_fixture;
use crate::{
    NETWORK_ID,
    admission_policy_v2::Record,
    admission_v2::{Admission, Expected, Policy},
    anchors::FinalizedAnchor,
    execution::State,
    key_rotation::KeyRotate,
    membership_v2::Book,
    node_admission_v2::{Binding, node_id},
    recovery::{Anchor, ContinuityState, Member},
    tpm::{TpmProfile, encode_quote},
};
use mutiny_consensus_v8::{
    continuity_key_rotate_v2 as key_rotation, retired_continuity_v2 as retired,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};
struct SyntheticCustody<'a> {
    key: &'a HybridKey,
    counter: u64,
    calls: u64,
}
impl crate::counter_store::MonotonicCounter for SyntheticCustody<'_> {
    fn read(&mut self) -> std::result::Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> std::result::Result<(), String> {
        self.counter = self.counter.checked_add(1).ok_or("counter overflow")?;
        Ok(())
    }
}
impl crate::counter_voter_v2::CounterSigningBackend for SyntheticCustody<'_> {
    fn sign_work_probe(
        &mut self,
        d: &crate::certificates::Decision,
        f: &crate::liveness_v2::Fragment,
    ) -> std::result::Result<HybridSignature, String> {
        self.calls += 1;
        self.key
            .sign(
                mutiny_crypto_v2::Domain::ContinuityWorkProbe,
                &f.unsigned(d).map_err(|_| "fixture message")?,
            )
            .map_err(|_| "synthetic probe signer".into())
    }
    fn public_key(&self) -> &mutiny_crypto_v2::PublicKey {
        self.key.public()
    }
    fn sign_vote(&mut self, message: &[u8]) -> std::result::Result<HybridSignature, String> {
        self.calls += 1;
        self.key
            .sign(mutiny_crypto_v2::Domain::ContinuityVote, message)
            .map_err(|_| "synthetic signer".into())
    }
}
fn qualify_custody_rejection(
    before: &crate::votes_v2::HeightAuthority,
    after: &crate::votes_v2::HeightAuthority,
    node: Hash,
    old: &HybridKey,
    new: &HybridKey,
) {
    use crate::counter_voter_v2::CounterVoter;
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-synthetic-rotation-custody-{}.sqlite",
        hex::encode(random)
    ));
    let mut backend = SyntheticCustody {
        key: old,
        counter: 100,
        calls: 0,
    };
    drop(CounterVoter::open(&path, before.clone(), node, Some(100), &mut backend).unwrap());
    let bytes = std::fs::read(&path).unwrap();
    let counter = backend.counter;
    assert!(CounterVoter::open(&path, after.clone(), node, None, &mut backend).is_err());
    backend.key = new;
    // Installing a software key does not silently reinterpret an existing
    // counter snapshot under the new generation. A reviewed migration remains
    // necessary before production custody can resume.
    assert!(CounterVoter::open(&path, after.clone(), node, None, &mut backend).is_err());
    assert_eq!(backend.counter, counter);
    assert_eq!(backend.calls, 0);
    assert!(std::fs::read(&path).unwrap() == bytes);
    std::fs::remove_file(path).unwrap();
}
fn qualify_transition(
    state: &State,
    rotation: &KeyRotate,
    old: &HybridKey,
    new: &HybridKey,
    node_key: &HybridKey,
) {
    use crate::{
        blocks::BlockBody,
        certificates::Decision,
        continuity_lifecycle_v2::transition,
        continuity_v2::Vote,
        equivocation_v2::{Evidence, HistoricalAuthority},
        votes_v2::HeightAuthority,
    };
    let parent = &rotation.parent;
    let node = rotation.binding.admission.node;
    let root = state.root().unwrap();
    let body = BlockBody {
        height: 1,
        reward_owner: [30; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![rotation.encode().unwrap()],
    };
    let prior = state.clone();
    let before = HeightAuthority::from_state(state, parent.clone(), root).unwrap();
    let result = transition(state, parent, root, &body).unwrap();
    assert_eq!(*state, prior);
    assert_eq!(
        result.registry.members,
        state.continuity.as_ref().unwrap().members
    );
    assert_eq!(result.membership.get(node).unwrap().sequence(), 1);
    assert_eq!(result.keys.get(node).unwrap().admission().key_generation, 2);
    assert!(!result.retired.is_empty());
    assert_eq!(result.accounting.freshness[&node].committed_height, 1);
    let mut duplicate = body.clone();
    duplicate.operations.push(rotation.encode().unwrap());
    assert!(transition(state, parent, root, &duplicate).is_err());
    let mut exit = crate::continuity_exit_v2::Exit {
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        height: 1,
        parent_anchor: parent.id(),
        node,
        hardware_generation: 1,
        sequence: 1,
        authorizer: node_key.public().descriptor(1).unwrap(),
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    exit.sign(node_key).unwrap();
    let mut exit_only = body.clone();
    exit_only.operations = vec![exit.encode().unwrap()];
    assert!(transition(state, parent, root, &exit_only).is_ok());
    for operations in [
        vec![rotation.encode().unwrap(), exit.encode().unwrap()],
        vec![exit.encode().unwrap(), rotation.encode().unwrap()],
    ] {
        let conflicting = BlockBody {
            operations,
            ..body.clone()
        };
        assert!(transition(state, parent, root, &conflicting).is_err());
    }
    // Even a genuinely signed native ACK cannot use the rotation's fresh
    // attestation in its own block when parent freshness was absent.
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let mut ack = crate::participation::ParticipationAck {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        node,
        height: 1,
        parent: parent.id(),
        generation: 1,
        signature: [0; 64],
    };
    let native = SigningKey::from_bytes((&[10u8; 32]).into()).unwrap();
    let sig: Signature = native.sign_prehash(&ack.signing_digest()).unwrap();
    ack.signature = sig.normalize_s().unwrap_or(sig).to_bytes().into();
    let mut same_block = body.clone();
    same_block.operations.push(ack.encode());
    assert!(transition(state, parent, root, &same_block).is_err());
    let mut post = state.clone();
    post.accounting = result.accounting;
    post.continuity = Some(result.registry);
    post.membership_v2 = result.membership;
    post.continuity_keys_v2 = result.keys;
    post.retired_continuity_v2 = result.retired;
    let rows = post.records().unwrap();
    let post_root = post.root().unwrap();
    post = State::from_records(&rows, post_root).unwrap();
    assert!(post.records().unwrap() == rows);
    let next_parent = FinalizedAnchor {
        height: 1,
        block: [31; 32],
        ..parent.clone()
    };
    let after = HeightAuthority::from_state(&post, next_parent.clone(), post_root).unwrap();
    assert_eq!(before.voters[&node].public, *old.public());
    assert_eq!(after.voters[&node].public, *new.public());
    qualify_custody_rejection(&before, &after, node, old, new);
    assert_eq!(
        before.voters[&node].weight().unwrap(),
        after.voters[&node].weight().unwrap()
    );
    let make_vote = |authority: &HeightAuthority, key: &HybridKey, sequence: u64| {
        let p = &authority.parent;
        let v = &authority.voters[&node];
        let mut vote = Vote {
            decision: Decision {
                network: NETWORK_ID,
                genesis: p.genesis,
                fingerprint: p.fingerprint,
                purpose: 2,
                height: p.height + 1,
                mining_epoch: 0,
                continuity_period: p.height / 60,
                round: 0,
                step: 3,
                previous_finalized_anchor: p.id(),
                parent: p.block,
                block: [32; 32],
                state: [33; 32],
                membership: authority.membership,
                reputation: authority.reputation,
                attestation: authority.attestation,
            },
            nil: false,
            node,
            hardware_generation: v.hardware_generation,
            key_generation: v.key_generation,
            sequence,
            tpm_identity: v.tpm_identity(),
            profile: v.profile,
            signature: HybridSignature {
                ed448: [0; 114],
                fndsa: [0; 1280],
            },
        };
        vote.sign(key).unwrap();
        vote
    };
    let vote = make_vote(&before, old, 1);
    assert!(vote.verify(parent, before.roots(), &before.voters).is_ok());
    let new_vote = make_vote(&after, new, 2);
    assert!(
        new_vote
            .verify(&next_parent, after.roots(), &after.voters)
            .is_ok()
    );
    let stale = make_vote(&after, old, 3);
    assert!(
        stale
            .verify(&next_parent, after.roots(), &after.voters)
            .is_err()
    );
    let early = make_vote(&before, new, 4);
    assert!(
        early
            .verify(parent, before.roots(), &before.voters)
            .is_err()
    );
    let mut replay = body.clone();
    replay.height = 2;
    assert!(transition(&post, &next_parent, post_root, &replay).is_err());
    let mut missing = post.clone();
    missing.retired_continuity_v2 = Default::default();
    assert!(missing.records().is_err());
    // Retirement preserves E-1 key authority. Timely old-key equivocation
    // revokes the current software-key generation without rewriting history.
    let mut contradictory = vote.clone();
    contradictory.decision.block = [34; 32];
    contradictory.sequence += 1;
    contradictory.sign(old).unwrap();
    let evidence = Evidence::new(vote, contradictory).unwrap();
    let historical = HistoricalAuthority {
        parent,
        roots: before.roots(),
        registry: &before.voters,
    };
    assert!(crate::penalties_v2::Settlement::new(&evidence, &next_parent, &historical).is_ok());
    let evidence_body = BlockBody {
        height: 2,
        operations: vec![evidence.encode().unwrap()],
        ..body.clone()
    };
    let history = [(1, before)].into_iter().collect();
    let settled = crate::continuity_lifecycle_v2::transition_with_history(
        &post,
        &next_parent,
        post_root,
        &evidence_body,
        &history,
    )
    .unwrap();
    assert!(!settled.registry.members[0].eligible);
    assert!(settled.penalties.revoked(node));
    assert!(settled.penalties.tombstoned(node, 1));
    assert_eq!(
        settled.registry.members[0].history.penalties,
        post.continuity.as_ref().unwrap().members[0]
            .history
            .penalties
    );
    assert_eq!(
        settled.keys.get(node).unwrap().admission().key_generation,
        2
    );
    assert_eq!(settled.retired, post.retired_continuity_v2);
    qualify_certified_rotation(state.clone(), rotation, old, new);
}
fn qualify_certified_rotation(
    state: State,
    rotation: &KeyRotate,
    old: &HybridKey,
    new: &HybridKey,
) {
    qualify_certified_replacement(
        state,
        &rotation.parent,
        rotation.binding.admission.node,
        rotation.encode().unwrap(),
        old,
        new,
        1,
    );
}
fn qualify_certified_replacement(
    mut state: State,
    genesis: &FinalizedAnchor,
    node: Hash,
    operation: Vec<u8>,
    old: &HybridKey,
    new: &HybridKey,
    hardware_generation: u64,
) {
    use crate::{
        block_envelope_v2::BlockEnvelope,
        blocks::BlockBody,
        canonical_store_v2::CanonicalStore,
        certificates::Decision,
        continuity_v2::{Certificate, Vote},
        execution::{CandidatePreparation, WorkParent},
        pow::{Candidate, WorkAuthority, WorkHeader},
        votes_v2::HeightAuthority,
        work_authority_v2::Authority,
    };
    let (_, assignments, expected, licenses, coordinator) = license_fixture::fixtures();
    state.licenses_v2 = crate::license_book_v2::Book::genesis(
        &assignments,
        &expected,
        &licenses,
        &state.wallets,
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let genesis = genesis.clone();
    let root = state.root().unwrap();
    let body = BlockBody {
        height: 1,
        reward_owner: licenses[0].owner,
        fees: 0,
        transactions: vec![],
        operations: vec![operation],
    };
    let parent = WorkParent {
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        height: 0,
        block: genesis.block,
        t0: 1000,
        target: [255; 32],
        ancestor_timestamps: vec![1000],
    };
    let mut candidate = Candidate {
        network: NETWORK_ID,
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        height: 1,
        parent: genesis.block,
        timestamp: 1100,
        body_root: body.root().unwrap(),
        state_root: [0; 32],
        license: licenses[0].id,
        worker: expected[0].worker_id,
        target: parent.target,
    };
    let prepared = state
        .prepare_candidate_v2(CandidatePreparation {
            parent: &parent,
            candidate: &candidate,
            ticket_sequence: 1,
            body: &body,
        })
        .unwrap();
    candidate.state_root = prepared.root;
    assert!(!prepared.state.retired_continuity_v2.is_empty());
    let mut work = Authority {
        work: WorkAuthority {
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
    let header = WorkHeader {
        candidate,
        authority: work.id().unwrap(),
        nonce: 1,
    };
    let before = HeightAuthority::from_state(&state, genesis.clone(), root).unwrap();
    let voter = &before.voters[&node];
    let decision = Decision {
        network: NETWORK_ID,
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        purpose: 2,
        height: 1,
        mining_epoch: 1,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: genesis.id(),
        parent: genesis.block,
        block: header.block_hash(),
        state: prepared.root,
        membership: before.membership,
        reputation: before.reputation,
        attestation: before.attestation,
    };
    let mut vote = Vote {
        decision: decision.clone(),
        nil: false,
        node,
        hardware_generation: 1,
        key_generation: 1,
        sequence: 1,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    vote.sign(old).unwrap();
    let envelope = BlockEnvelope {
        header,
        body,
        authority: work,
        certificate: Certificate {
            decision,
            votes: vec![vote],
        },
    };
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-synthetic-key-rotation-{}.sqlite",
        hex::encode(random)
    ));
    let mut chain =
        CanonicalStore::open_trusted_genesis(&path, &genesis, &state, root, 1000, parent.target)
            .unwrap();
    let mut premature = envelope.clone();
    premature.certificate.votes[0].sign(new).unwrap();
    assert!(chain.commit(&premature).is_err());
    assert_eq!(chain.load().unwrap().0.height, 0);
    // Fail after staging both retirement and replacement, at proof-index tip
    // installation. No portion of the rotation may survive the transaction.
    let fault = rusqlite::Connection::open(&path).unwrap();
    fault.execute_batch("CREATE TRIGGER fail_rotation_tip BEFORE UPDATE ON state_merkle_tip BEGIN SELECT RAISE(ABORT,'synthetic rotation failure'); END;").unwrap();
    assert!(chain.commit(&envelope).is_err());
    fault
        .execute_batch("DROP TRIGGER fail_rotation_tip;")
        .unwrap();
    drop(fault);
    let (unchanged, rolled_back) = chain.load().unwrap();
    assert_eq!(unchanged.height, 0);
    assert_eq!(unchanged.root, root);
    assert!(rolled_back.records().unwrap() == state.records().unwrap());
    assert!(rolled_back.retired_continuity_v2.is_empty());
    assert_eq!(
        rolled_back
            .continuity_keys_v2
            .get(node)
            .unwrap()
            .admission()
            .key_generation,
        1
    );
    assert!(chain.commit(&envelope).unwrap());
    assert!(!chain.commit(&envelope).unwrap());
    let (head, installed) = chain.load().unwrap();
    assert_eq!(head.height, 1);
    assert!(installed.records().unwrap() == prepared.state.records().unwrap());
    assert!(chain.execution_parent(0).unwrap().1.records().unwrap() == state.records().unwrap());
    drop(chain);
    let chain =
        CanonicalStore::open_trusted_genesis(&path, &genesis, &state, root, 1000, parent.target)
            .unwrap();
    let (_, restored) = chain.load().unwrap();
    assert!(restored.records().unwrap() == prepared.state.records().unwrap());
    let anchor = FinalizedAnchor {
        height: 1,
        block: envelope.block_hash(),
        ..genesis.clone()
    };
    let after = HeightAuthority::from_state(&restored, anchor, head.root).unwrap();
    assert_eq!(after.voters[&node].public, *new.public());
    assert_eq!(after.voters[&node].hardware_generation, hardware_generation);
    drop(chain);
    std::fs::remove_file(path).unwrap();
}
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
fn synthetic_same_hardware_rotation_requires_new_dual_keys_and_exact_parent_authority() {
    let owner =
        HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let node = HybridKey::generate(Role::Node).unwrap();
    let old = HybridKey::generate(Role::Continuity).unwrap();
    let new = HybridKey::generate(Role::Continuity).unwrap();
    let ak = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let profile = profile(&ak);
    let policy = Policy {
        genesis: [1; 32],
        fingerprint: [2; 32],
        owner_descriptor: owner.public().descriptor(1).unwrap(),
        endorsement_roots: [[3; 32]].into_iter().collect(),
    };
    let descriptor = node.public().descriptor(1).unwrap();
    let id = node_id(policy.genesis, &descriptor).unwrap();
    let make = |key: &HybridKey, generation: u64, nonce: [u8; 32]| {
        let z = HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        };
        let mut b = Binding {
            node_signer: None,
            admission: Admission {
                genesis: policy.genesis,
                fingerprint: policy.fingerprint,
                node: id,
                hardware_generation: 1,
                key_generation: generation,
                continuity_descriptor: key.public().descriptor(generation).unwrap(),
                profile: profile.encode().unwrap(),
                endorsement_root: [3; 32],
                owner: owner.public().address_id(1).unwrap(),
                supervised_nonce: nonce,
                quote: vec![],
                possession: z.clone(),
                authorization: z.clone(),
            },
            node_descriptor: descriptor.clone(),
            possession: z,
        };
        b.admission.prove_continuity(key).unwrap();
        b.admission.quote = quote(&ak, &profile, b.admission.challenge().unwrap());
        b.admission.authorize(&owner, 1).unwrap();
        b.sign(&node).unwrap();
        b
    };
    let original = make(&old, 1, [5; 32]);
    let mut state = State::default();
    state.wallets.register(&policy.owner_descriptor).unwrap();
    state.admission_policy_v2 = Some(Record::new(policy.clone()).unwrap());
    (state.membership_v2, state.continuity_keys_v2) = Book::genesis(
        &original,
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
                hardware: profile.hardware,
                generation: 1,
                voting_key: crate::tpm::public_key(&profile.voting_public, false).unwrap(),
                attestation: profile.commitment().unwrap(),
                history: Default::default(),
                physical: true,
                eligible: true,
                genesis_member: true,
            }],
        )
        .unwrap(),
    );
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: policy.genesis,
        fingerprint: policy.fingerprint,
        height: 0,
        block: [19; 32],
    };
    let mut rotation = KeyRotate {
        parent: parent.clone(),
        nonce: [7; 32],
        sequence: 1,
        old_key_generation: 1,
        binding: make(&new, 2, [6; 32]),
    };
    rotation.binding = make(&new, 2, rotation.admission_nonce().unwrap());
    let root = state.root().unwrap();
    let raw = rotation.encode().unwrap();
    assert_eq!(KeyRotate::decode(&raw).unwrap(), rotation);
    assert!(rotation.verify(&state, &parent, root).is_ok());
    assert!(raw.len() <= 16384);
    for mode in 0..20 {
        let mut bad = rotation.clone();
        match mode {
            0 => bad.parent.height += 1,
            1 => bad.parent.block[0] ^= 1,
            2 => bad.nonce[0] ^= 1,
            3 => bad.sequence += 1,
            4 => bad.old_key_generation += 1,
            5 => bad.binding.admission.hardware_generation += 1,
            6 => bad.binding.admission.authorization.ed448[0] ^= 1,
            7 => bad.binding.admission.authorization.fndsa[0] ^= 1,
            8 => bad.binding.admission.possession.ed448[0] ^= 1,
            9 => bad.binding.admission.possession.fndsa[0] ^= 1,
            10 => bad.binding.possession.ed448[0] ^= 1,
            11 => bad.binding.possession.fndsa[0] ^= 1,
            12 => bad.binding.admission.quote[20] ^= 1,
            13 => bad.binding.admission.profile[20] ^= 1,
            14 => bad.parent.network ^= 1,
            15 => bad.parent.genesis[0] ^= 1,
            16 => bad.parent.fingerprint[0] ^= 1,
            17 => bad.binding.admission.node[0] ^= 1,
            18 => bad.binding.node_descriptor = node.public().descriptor(2).unwrap(),
            _ => bad.sequence = 0,
        }
        assert!(bad.verify(&state, &parent, root).is_err(), "mode {mode}");
    }
    let mut reused = rotation.clone();
    reused.binding = make(&old, 2, reused.admission_nonce().unwrap());
    assert!(reused.verify(&state, &parent, root).is_err());
    let mut inactive = state.clone();
    inactive.continuity.as_mut().unwrap().members[0].eligible = false;
    assert!(
        rotation
            .verify(&inactive, &parent, inactive.root().unwrap())
            .is_err()
    );
    let mut missing = state.clone();
    missing.admission_policy_v2 = None;
    assert!(
        rotation
            .verify(&missing, &parent, missing.root().unwrap())
            .is_err()
    );
    assert!(rotation.verify(&state, &parent, [0; 32]).is_err());
    let mut overflow = rotation.clone();
    overflow.old_key_generation = u64::MAX;
    assert!(overflow.encode().is_err());
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(KeyRotate::decode(&trailing).is_err());
    assert!(KeyRotate::decode(&vec![0; crate::key_rotation::MAX_ROTATION_BYTES + 1]).is_err());
    assert!(crate::retired::Record::decode(&vec![0; crate::retired::MAX_RECORD + 1]).is_err());
    assert_eq!(state.root().unwrap(), root);
    qualify_hardware_rotation_validator(
        &state, &parent, &owner, &node, &new, &old, &profile, &rotation,
    );
    if std::env::var("BUILD8_HARDWARE_VALIDATOR_ONLY").as_deref() == Ok("1") {
        return; // Explicit synthetic validator/public-vector qualification mode.
    }
    qualify_node_rotation(&state, &parent, &owner, &node, &old, &new, &ak, &profile);
    qualify_transition(&state, &rotation, &old, &new, &node);
    let retired = crate::retired::Record {
        binding: original.clone(),
        owner_descriptor: policy.owner_descriptor.clone(),
        retired_height: 1,
        rotation: crate::domain_hash(b"MUTINY-BUILD8-CONTINUITY-KEY-ROTATION-RECORD-V2", &raw),
    };
    let wire = retired.encode().unwrap();
    assert_eq!(crate::retired::Record::decode(&wire).unwrap(), retired);
    let book = crate::retired::Book::default()
        .stage_retire(retired.clone())
        .unwrap();
    assert_eq!(
        crate::retired::Book::from_records(&book.records().unwrap()).unwrap(),
        book
    );
    assert!(book.stage_retire(retired.clone()).is_err());
    assert!(
        book.validate_generations(&[(id, 2)].into_iter().collect(), 1)
            .is_ok()
    );
    assert!(
        book.validate_generations(&[(id, 1)].into_iter().collect(), 1)
            .is_err()
    );
    assert!(
        book.validate_generations(&[(id, 3)].into_iter().collect(), 1)
            .is_err()
    );
    assert!(
        book.validate_generations(&[(id, 2)].into_iter().collect(), 0)
            .is_err()
    );
    assert!(book.validate_generations(&Default::default(), 1).is_err());
    assert!(
        crate::retired::Book::default()
            .validate_generations(&[(id, u64::MAX)].into_iter().collect(), 1)
            .is_err()
    );
    for forbidden in [old.public(), owner.public(), node.public()] {
        assert!(book.reject_reused(forbidden).is_err());
    }
    assert!(book.reject_reused(new.public()).is_ok());
    for mode in 0..6 {
        let mut bad = retired.clone();
        match mode {
            0 => bad.retired_height = 0,
            1 => bad.rotation = [0; 32],
            2 => bad.owner_descriptor = descriptor.clone(),
            3 => bad.binding.admission.authorization.fndsa[0] ^= 1,
            4 => bad.binding.possession.ed448[0] ^= 1,
            _ => bad.binding.admission.quote[20] ^= 1,
        }
        assert!(bad.encode().is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(crate::retired::Record::decode(&trailing).is_err());
    if let Ok(path) = std::env::var("BUILD8_EXPORT_RETIRED_KEY_PUBLIC_V1") {
        use std::io::Write;
        let key = retired.key();
        let root = crate::blocks::state_root(&[(key, wire.clone())]).unwrap();
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .str("BUILD8-SYNTHETIC-RETIRED-KEY-PUBLIC-V1")
            .unwrap()
            .bytes(&key)
            .unwrap()
            .bytes(&wire)
            .unwrap()
            .bytes(&root)
            .unwrap();
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        out.write_all(&e.into_writer()).unwrap();
    }
    // A prior canonical wallet rotation changes the owner descriptor/address,
    // but does not strand this physical node or revive the retired wallet key.
    let next_owner =
        HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let z = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    let mut owner_rotation = crate::wallet_rotation_v1::Rotation {
        network: NETWORK_ID,
        genesis: policy.genesis,
        fingerprint: policy.fingerprint,
        authority: owner.public().address_id(1).unwrap(),
        current: owner.public().descriptor(1).unwrap(),
        proposed: next_owner.public().descriptor(2).unwrap(),
        created_height: 1,
        expiry_height: 10,
        authorization: z.clone(),
        possession: z,
    };
    owner_rotation.sign(&owner, &next_owner).unwrap();
    state
        .wallets
        .apply(&owner_rotation, policy.genesis, policy.fingerprint, 1)
        .unwrap();
    let next_parent = FinalizedAnchor {
        height: 1,
        block: [23; 32],
        ..parent.clone()
    };
    let mut after = rotation.clone();
    after.parent = next_parent.clone();
    after.binding.admission.owner = next_owner.public().address_id(2).unwrap();
    after.binding.admission.supervised_nonce = after.admission_nonce().unwrap();
    after.binding.admission.prove_continuity(&new).unwrap();
    after.binding.admission.quote =
        quote(&ak, &profile, after.binding.admission.challenge().unwrap());
    after.binding.admission.authorize(&next_owner, 2).unwrap();
    after.binding.sign(&node).unwrap();
    // This focused fixture changed wallet authority at height 1 but still had
    // height-zero participation accounting. A mismatched parent must fail even
    // when every rotation signature is valid. Advance the ordinary lifecycle
    // before treating the constructed fixture as height-one parent state.
    assert!(after.verify(&state, &next_parent, state.root().unwrap()).is_err());
    let advanced = crate::continuity_lifecycle_v2::transition(
        &state,
        &parent,
        state.root().unwrap(),
        &crate::blocks::BlockBody {
            height: 1,
            reward_owner: [0; 32],
            fees: 0,
            transactions: vec![],
            operations: vec![],
        },
    ).unwrap();
    state.continuity = Some(advanced.registry);
    state.accounting = advanced.accounting;
    state.membership_v2 = advanced.membership;
    state.continuity_keys_v2 = advanced.keys;
    state.retired_continuity_v2 = advanced.retired;
    state.node_key_history_v2 = advanced.node_history;
    state.penalties_v2 = advanced.penalties;
    state.bonds_v2 = advanced.bonds;
    assert!(advanced.payouts.is_empty());
    assert_eq!(advanced.burned, 0);
    assert!(
        after
            .verify(&state, &next_parent, state.root().unwrap())
            .is_ok()
    );
    let second = crate::retired::Record {
        binding: after.binding.clone(),
        owner_descriptor: next_owner.public().descriptor(2).unwrap(),
        retired_height: 2,
        rotation: [24; 32],
    };
    let twice = book.stage_retire(second.clone()).unwrap();
    assert!(
        twice
            .validate_generations(&[(id, 3)].into_iter().collect(), 2)
            .is_ok()
    );
    assert_eq!(
        crate::retired::Book::from_records(&twice.records().unwrap()).unwrap(),
        twice
    );
    assert!(twice.reject_reused(new.public()).is_err());
    let mut same_height = second.clone();
    same_height.retired_height = 1;
    assert!(
        book.stage_retire(same_height)
            .unwrap()
            .validate_generations(&[(id, 3)].into_iter().collect(), 2)
            .is_err()
    );
    assert!(
        crate::retired::Book::default()
            .stage_retire(second)
            .unwrap()
            .validate_generations(&[(id, 3)].into_iter().collect(), 2)
            .is_err()
    );
    let mut wrong_key = book.records().unwrap();
    let (_, value) = wrong_key.pop_first().unwrap();
    wrong_key.insert([25; 32], value);
    assert!(crate::retired::Book::from_records(&wrong_key).is_err());
    let mut obsolete = after.clone();
    obsolete.binding.admission.owner = owner.public().address_id(1).unwrap();
    obsolete.binding.admission.prove_continuity(&new).unwrap();
    obsolete.binding.admission.quote = quote(
        &ak,
        &profile,
        obsolete.binding.admission.challenge().unwrap(),
    );
    obsolete.binding.admission.authorize(&owner, 1).unwrap();
    obsolete.binding.sign(&node).unwrap();
    assert!(
        obsolete
            .verify(&state, &next_parent, state.root().unwrap())
            .is_err()
    );
    println!(
        "SYNTHETIC_KEY_ROTATION_BYTES={} production=false synthetic_certified_installation=true",
        raw.len()
    );
}
include!("support/node_rotation_v2.rs");
include!("support/hardware_rotation_v2.rs");

#[path = "../../node/src/node_custody_v2.rs"]
mod node_control_custody;
use node_control_custody as node_custody_v2;
#[cfg(target_os = "linux")]
#[path = "../../node/src/node_generation_preparation_v2.rs"]
mod node_generation_preparation_v2;

#[cfg(target_os = "linux")]
#[path = "../../node/src/continuity_generation_store_v2.rs"]
mod continuity_generation_store_v2;

#[path = "../../node/src/work_journal_v2.rs"]
mod work_journal_v2;

#[path = "../../node/src/hybrid_coordinator_v2.rs"]
mod hybrid_coordinator_v2;
#[path = "../../node/src/hybrid_runtime_v2.rs"]
mod hybrid_runtime_v2;
#[path = "../../node/src/state_proof_service.rs"]
mod state_proof_service;
include!("support/hybrid_coordinator_v2.rs");

#[path = "../../node/src/software_coordinator_custody_v2.rs"]
mod software_coordinator_custody_v2;
#[path = "../../node/src/worker_session_custody_v2.rs"]
mod worker_session_custody_v2;
#[path = "../../node/src/worker_current_channel_v2.rs"]
mod worker_current_channel_v2;
#[path = "../../node/src/worker_carrier_v2.rs"]
mod worker_carrier_v2;
#[path = "../../node/src/worker_handshake_io_v2.rs"]
mod worker_handshake_io_v2;
#[path = "../../node/src/worker_pending_budget_v2.rs"]
mod worker_pending_budget_v2;
#[path = "../../node/src/worker_context_router_v2.rs"]
mod worker_context_router_v2;
#[path = "../../node/src/worker_active_connections_v2.rs"]
mod worker_active_connections_v2;
#[path = "../../node/src/worker_protocol_v2.rs"]
mod worker_protocol_v2;
#[path = "../../node/src/observation_custody_v2.rs"]
mod observation_custody_v2;
#[path = "../../node/src/observation_journal_v2.rs"]
mod observation_journal_v2;
#[path = "../../node/src/candidate_journal_v2.rs"]
mod candidate_journal_v2;
include!("support/worker_session_custody_v2.rs");
include!("support/worker_carrier_v2.rs");
include!("support/worker_handshake_io_v2.rs");
