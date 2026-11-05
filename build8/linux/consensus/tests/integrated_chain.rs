//! Full executor/storage/BFT/transaction qualification at the locked physical
//! target. Test authority keys are isolated fixtures, never production admission.
use ed25519_dalek::{Signer, SigningKey as EdKey};
#[path = "../examples/support/external_helper_bridge.rs"]
mod external_helper_bridge;
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    bft::Step,
    block_envelope::BlockEnvelope,
    blocks::*,
    canonical_store::CanonicalStore,
    certificates::{Certificate, Signer as CertSigner},
    execution::*,
    freshness::*,
    mempool::{MAX_PENDING_BYTES, Mempool, Status},
    participation::*,
    pow::*,
    recovery::{Anchor, ContinuityState, Member},
    reputation::History,
    transactions::*,
    votes::HeightAuthority,
    *,
};
use mutiny_consensus_v8::{
    counter_store::MonotonicCounter,
    counter_voter::{CounterSigningBackend, CounterVoter},
    tpm::{PinnedTpmVerifier, TpmProfile},
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Write,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
struct FixtureAttestation;
enum CampaignVerifier {
    Fixture,
    Physical(PinnedTpmVerifier),
}
impl PhysicalAttestationVerifier for CampaignVerifier {
    fn verify(&self, m: &PhysicalMember, c: Hash, e: &[u8]) -> Result<()> {
        match self {
            Self::Fixture => FixtureAttestation.verify(m, c, e),
            Self::Physical(v) => v.verify(m, c, e),
        }
    }
}
enum CampaignSigner {
    Fixture(SigningKey, u64),
    Physical(external_helper_bridge::ExternalHelperBridge),
}
impl MonotonicCounter for CampaignSigner {
    fn read(&mut self) -> std::result::Result<u64, String> {
        match self {
            Self::Fixture(_, n) => Ok(*n),
            Self::Physical(b) => b.read(),
        }
    }
    fn increment(&mut self) -> std::result::Result<(), String> {
        match self {
            Self::Fixture(_, n) => {
                *n += 1;
                Ok(())
            }
            Self::Physical(b) => b.increment(),
        }
    }
}
impl CounterSigningBackend for CampaignSigner {
    fn public_key(&self) -> [u8; 33] {
        match self {
            Self::Fixture(k, _) => k
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            Self::Physical(b) => b.public_key(),
        }
    }
    fn sign_digest(&mut self, d: Hash) -> std::result::Result<[u8; 64], String> {
        match self {
            Self::Fixture(k, _) => Ok(sign(k, d)),
            Self::Physical(b) => b.sign_digest(d),
        }
    }
}
impl CampaignSigner {
    fn evidence(&mut self, challenge: Hash) -> Vec<u8> {
        match self {
            Self::Fixture(..) => challenge.to_vec(),
            Self::Physical(b) => b.quote(challenge).unwrap(),
        }
    }
}
impl PhysicalAttestationVerifier for FixtureAttestation {
    fn verify(&self, _: &PhysicalMember, challenge: Hash, evidence: &[u8]) -> Result<()> {
        if evidence == challenge {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}
fn sign(key: &SigningKey, digest: Hash) -> [u8; 64] {
    let s: Signature = key.sign_prehash(&digest).unwrap();
    s.normalize_s().unwrap_or(s).to_bytes().into()
}
fn mine(header: &mut WorkHeader) {
    let bytes = header.work_bytes();
    let mut base = Sha256::new();
    base.update(&bytes[..bytes.len() - 8]);
    let done = AtomicBool::new(false);
    let answer = AtomicU64::new(0);
    std::thread::scope(|scope| {
        for worker in 0..4u64 {
            let base = &base;
            let done = &done;
            let answer = &answer;
            let target = header.candidate.target;
            scope.spawn(move || {
                let mut nonce = worker;
                while !done.load(Ordering::Relaxed) {
                    let mut hash = base.clone();
                    hash.update(nonce.to_be_bytes());
                    let digest: Hash = Sha256::digest(hash.finalize()).into();
                    if meets_target(&digest, &target) {
                        if !done.swap(true, Ordering::SeqCst) {
                            answer.store(nonce, Ordering::SeqCst);
                        }
                        break;
                    }
                    nonce = nonce.checked_add(4).expect("nonce exhaustion");
                }
            });
        }
    });
    header.nonce = answer.load(Ordering::SeqCst);
    assert!(meets_target(&header.digest(), &header.candidate.target));
}
fn transfer(
    state: &State,
    genesis: Hash,
    fp: Hash,
    coin_height: u64,
    created: u64,
    expiry: u64,
    recipient: u8,
) -> Transfer {
    let owner = EdKey::from_bytes(&[80; 32]);
    let (point, coin) = state
        .coins
        .iter()
        .find(|(_, c)| c.coinbase && c.created_height == coin_height)
        .unwrap();
    let mut tx = Transfer {
        network: NETWORK_ID,
        genesis,
        fingerprint: fp,
        created_height: created,
        expiry_height: expiry,
        inputs: vec![Input {
            point: point.clone(),
            public_key: owner.verifying_key().to_bytes(),
            signature: [0; 64],
        }],
        outputs: vec![Output {
            owner: [recipient; 32],
            atoms: coin.output.atoms - 1000,
        }],
    };
    tx.inputs[0].signature = owner.sign(&tx.signing_digest(0).unwrap()).to_bytes();
    tx
}
#[test]
#[ignore = "explicit release qualification mines 180 blocks at the locked fleet target"]
fn full_chain_three_periods_at_qualified_target() {
    let physical_run = std::env::var_os("BUILD8_PHYSICAL_TPM").is_some();
    let timing_campaign = std::env::var_os("BUILD8_TIMING_CAMPAIGN").is_some();
    assert!(!(physical_run && timing_campaign));
    // Physical evidence is supplied at RUNTIME only (never compiled in). Fixture mode needs no
    // TPM profile at all. Physical mode: BUILD8_PHYSICAL_TPM_PROFILE_FIXTURE=<path>,
    // BUILD8_PHYSICAL_INITIAL_COUNTER=<u64>, and the explicit qualification helper inputs
    // BUILD8_QUALIFICATION_TPM_HELPER=<helper spec JSON> and
    // BUILD8_QUALIFICATION_TPM_CUSTODY_MANIFEST=<custody manifest JSON>.
    let profile: Option<TpmProfile> = if physical_run {
        let path = std::env::var("BUILD8_PHYSICAL_TPM_PROFILE_FIXTURE").expect(
            "PHYSICAL TPM EVIDENCE MISSING: BUILD8_PHYSICAL_TPM_PROFILE_FIXTURE is not set",
        );
        let fixture: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_ne!(fixture["TEST_VALUE"], true, "a TEST_VALUE fixture is not physical evidence");
        let p = TpmProfile::decode(&hex::decode(fixture["profile"].as_str().unwrap()).unwrap())
            .unwrap();
        assert!(!p.is_test_value(), "a TEST-VALUE profile is not physical evidence");
        Some(p)
    } else {
        None
    };
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let mut descriptor =
        GenesisDescriptor::decode(&hex::decode(v["descriptor_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    descriptor.recovery = EdKey::from_bytes(&[4; 32]).verifying_key().to_bytes();
    if physical_run {
        getrandom::getrandom(&mut descriptor.nonce).unwrap();
        descriptor.admission_records = vec![profile.as_ref().unwrap().encode().unwrap()];
    }
    let genesis = descriptor.id().unwrap();
    let fp = descriptor.fingerprint;
    let mut bindings: Vec<_> = v["cases"][0]["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            licenses::BindWorker::decode(&hex::decode(b["binding_hex"].as_str().unwrap()).unwrap())
                .unwrap()
        })
        .collect();
    for (index, binding) in bindings.iter_mut().enumerate() {
        binding.genesis = genesis;
        binding.license = genesis_license(genesis, index as u64).unwrap();
        binding.worker = binding.worker_id();
        binding.owner_signature = EdKey::from_bytes(&[80; 32])
            .sign(&binding.signing_digest(false))
            .to_bytes();
        binding.worker_signature = EdKey::from_bytes(&[10 + index as u8; 32])
            .sign(&binding.signing_digest(true))
            .to_bytes();
    }
    let key = SigningKey::from_bytes((&[17; 32]).into()).unwrap();
    let initial_counter = if physical_run {
        std::env::var("BUILD8_PHYSICAL_INITIAL_COUNTER")
            .unwrap()
            .parse::<u64>()
            .unwrap()
    } else {
        1000
    };
    let mut signer = if physical_run {
        CampaignSigner::Physical(
            external_helper_bridge::ExternalHelperBridge::from_env(Some(initial_counter)).unwrap(),
        )
    } else {
        CampaignSigner::Fixture(key.clone(), 1000)
    };
    assert_eq!(signer.read().unwrap(), initial_counter);
    let custody = match &signer {
        CampaignSigner::Physical(b) => Some(b.manifest.clone()),
        _ => None,
    };
    let mut physical = PhysicalMember {
        node: [3; 32],
        generation: 0,
        continuity_key: key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap(),
        hardware: [4; 32],
        admission_commitment: [5; 32],
        attestation_key: vec![6; 33],
    };
    let verifier = if physical_run {
        let profile = profile.clone().unwrap();
        physical.continuity_key = signer.public_key();
        physical.hardware = profile.hardware;
        physical.admission_commitment = profile.commitment().unwrap();
        physical.attestation_key = profile.ak_public.clone();
        CampaignVerifier::Physical(PinnedTpmVerifier {
            profiles: BTreeMap::from([(physical.admission_commitment, profile)]),
        })
    } else {
        CampaignVerifier::Fixture
    };
    let mut genesis_nonce = [8; 32];
    if physical_run {
        getrandom::getrandom(&mut genesis_nonce).unwrap();
    }
    let genesis_prestate = if physical_run { genesis } else { [7; 32] };
    let proof = signer.evidence(genesis_challenge(
        genesis_prestate,
        genesis_nonce,
        &physical,
    ));
    let fresh = validate_genesis(
        genesis_prestate,
        genesis_nonce,
        &physical,
        &proof,
        &verifier,
    )
    .unwrap();
    let mut initial = State {
        licenses: genesis::GenesisIdentity::new(descriptor.clone())
            .unwrap()
            .bind_workers(&bindings)
            .unwrap(),
        ..State::default()
    };
    initial.continuity = Some(
        ContinuityState::bootstrap(
            genesis,
            fp,
            Anchor {
                height: 0,
                tip: [0; 32],
                state_root: [0; 32],
                registry_root: [0; 32],
            },
            EdKey::from_bytes(&[4; 32]).verifying_key().to_bytes(),
            vec![Member {
                lineage: [9; 32],
                node: physical.node,
                hardware: physical.hardware,
                generation: 0,
                voting_key: physical.continuity_key,
                attestation: physical.admission_commitment,
                history: History::default(),
                physical: true,
                eligible: true,
                genesis_member: true,
            }],
        )
        .unwrap(),
    );
    initial.accounting.freshness.insert(physical.node, fresh);
    let physical = BTreeMap::from([(physical.node, physical)]);
    let m = &physical[&[3; 32]];
    let initial_target: Hash =
        hex::decode("00000350e94ccd16c4d5661eafcd07f2f220b12f07c24ab8f8b90a0f2c131b43")
            .unwrap()
            .try_into()
            .unwrap();
    let directory = std::env::var_os("BUILD8_INTEGRATION_OUTPUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("build8-integrated-{}", std::process::id()))
        });
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("chain.sqlite");
    let mut store =
        CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, initial_target).unwrap();
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("chain.jsonl"))
        .unwrap();
    writeln!(output,"{}",serde_json::json!({"schema":"BUILD8-INTEGRATED-CHAIN-FIXTURE-V1","descriptor":hex::encode(descriptor.encode().unwrap()),
        "initial_records":initial.records().unwrap().into_iter().map(|(k,v)|(hex::encode(k),hex::encode(v))).collect::<Vec<_>>(),"initial_target":hex::encode(initial_target),"physical_evidence_fixture_only":!physical_run,
        "actual_genesis":false,"genesis_evidence":hex::encode(&proof),"genesis_prestate":hex::encode(genesis_prestate),"genesis_nonce":hex::encode(genesis_nonce),"physical_profile":profile.as_ref().map(|p|serde_json::json!({"profile":hex::encode(p.encode().unwrap())})),"custody":custody})).unwrap();
    let coordinator = EdKey::from_bytes(&[90; 32]);
    let mut timestamps = vec![descriptor.timestamp];
    let mut pending = None;
    let mut expiring = None;
    let mut conflicted = None;
    let mut boundary_block = None;
    let mut last_block = None;
    let mut voter: Option<CounterVoter> = None;
    let voter_path = directory.join("voter.sqlite");
    for height in 1..=180u64 {
        let (head, state) = store.load().unwrap();
        assert_eq!(head.height, height - 1);
        let parent = WorkParent {
            genesis,
            fingerprint: fp,
            block: head.block,
            height: head.height,
            t0: descriptor.timestamp,
            target: head.next_target,
            ancestor_timestamps: timestamps.iter().rev().take(11).copied().collect(),
        };
        let anchor = FinalizedAnchor {
            network: NETWORK_ID,
            genesis,
            fingerprint: fp,
            height: head.height,
            block: head.block,
        };
        let mut body = BlockBody {
            height,
            reward_owner: descriptor.owner,
            fees: 0,
            transactions: vec![],
            operations: vec![],
        };
        if if timing_campaign {
            height == 59 || height == 121
        } else {
            height == 60 || height == 120
        } {
            let mut refresh = AttestationRefresh {
                network: NETWORK_ID,
                genesis,
                fingerprint: fp,
                node: m.node,
                generation: 0,
                height,
                parent_anchor: anchor.id(),
                evidence: vec![],
            };
            refresh.evidence = signer.evidence(refresh.challenge());
            body.operations.push(refresh.encode().unwrap());
        }
        // Period totals: 60, 54, 53. No certificate signer subset supplies credit.
        let include_ack = height <= 114
            || if timing_campaign {
                (122..=174).contains(&height)
            } else {
                (121..=173).contains(&height)
            };
        if timing_campaign {
            assert_eq!(
                state.accounting.freshness[&m.node].eligible(m.node, 0, m.continuity_key, height),
                !matches!(height, 120 | 121)
            );
        }
        if include_ack {
            let mut ack = ParticipationAck {
                network: NETWORK_ID,
                genesis,
                fingerprint: fp,
                node: m.node,
                generation: 0,
                height,
                parent: anchor.id(),
                signature: [0; 64],
            };
            ack.signature = signer.sign_digest(ack.signing_digest()).unwrap();
            body.operations.push(ack.encode());
        }
        if height == 101 {
            let tx = transfer(&state, genesis, fp, 1, 101, 110, 21);
            assert_eq!(store.admit(&tx).unwrap(), Status::Pending);
            pending = Some(tx);
        }
        if height == 104 {
            let tx = transfer(&state, genesis, fp, 2, 104, 105, 22);
            assert_eq!(store.admit(&tx).unwrap(), Status::Pending);
            expiring = Some(tx);
        }
        if height == 107 {
            let tx = transfer(&state, genesis, fp, 3, 107, 115, 23);
            assert_eq!(store.admit(&tx).unwrap(), Status::Pending);
            conflicted = Some(tx);
            body.transactions.push(
                transfer(&state, genesis, fp, 3, 107, 115, 24)
                    .encode()
                    .unwrap(),
            );
            body.fees = 1000;
        }
        if height == 103 {
            body.transactions
                .push(pending.as_ref().unwrap().encode().unwrap());
            body.fees = 1000;
        }
        let mut candidate = Candidate {
            network: NETWORK_ID,
            genesis,
            fingerprint: fp,
            parent: head.block,
            height,
            timestamp: descriptor.timestamp
                + if timing_campaign {
                    if height <= 60 {
                        height * 5
                    } else if height <= 120 {
                        300 + (height - 60) * 300
                    } else {
                        18300 + (height - 120) * 60
                    }
                } else {
                    height * 60
                },
            body_root: body.root().unwrap(),
            state_root: [0; 32],
            license: bindings[0].license,
            worker: bindings[0].worker,
            target: head.next_target,
        };
        let prepared = state
            .prepare_candidate(
                CandidatePreparation {
                    parent: &parent,
                    candidate: &candidate,
                    ticket_sequence: height,
                    body: &body,
                },
                &physical,
                &verifier,
            )
            .unwrap();
        candidate.state_root = prepared.root;
        let authority = WorkAuthority {
            candidate: candidate.clone(),
            assignment_sequence: 1,
            ticket_sequence: height,
            coordinator: coordinator.verifying_key().to_bytes(),
            nonce_start: 0,
            nonce_end: u64::MAX,
            epoch: mining_epoch(candidate.timestamp, descriptor.timestamp).unwrap(),
        };
        let authority_signature = coordinator.sign(&authority.id()).to_bytes();
        let mut header = WorkHeader {
            candidate,
            authority: authority.id(),
            nonce: 0,
        };
        mine(&mut header);
        let registry = state.continuity.as_ref().unwrap();
        let (membership, reputation, attestation) = registry.roots().unwrap();
        let height_authority = HeightAuthority {
            parent: anchor,
            membership,
            reputation,
            attestation,
            voters: registry.voters().unwrap(),
        };
        if let Some(v) = voter.as_mut() {
            v.advance(height_authority.clone(), &mut signer).unwrap();
        } else {
            voter = Some(
                CounterVoter::open(
                    &voter_path,
                    height_authority.clone(),
                    m.node,
                    Some(initial_counter),
                    &mut signer,
                )
                .unwrap(),
            );
        }
        if height == 61 || height == 102 {
            drop(voter.take());
            voter = Some(
                CounterVoter::open(&voter_path, height_authority, m.node, None, &mut signer)
                    .unwrap(),
            );
        }
        let round = voter.as_mut().unwrap();
        // Existing behavior test: not about time. Dedicated coverage: tests/vote_timestamp_guard_v1.rs.
        round.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(u64::MAX));
        round
            .round_mut()
            .unwrap()
            .validate_proposal_with_attestation(
                &state,
                LicensedExecution {
                    parent: &parent,
                    header: &header,
                    authority: &authority,
                    signature: &authority_signature,
                    body: &body,
                },
                &physical,
                &verifier,
            )
            .unwrap();
        let prevote = round
            .sign(Step::Prevote, Some(header.block_hash()), None, &mut signer)
            .unwrap();
        round.round_mut().unwrap().observe(&prevote).unwrap();
        let precommit = round
            .sign(
                Step::Precommit,
                Some(header.block_hash()),
                None,
                &mut signer,
            )
            .unwrap();
        round.round_mut().unwrap().observe(&precommit).unwrap();
        round
            .round_mut()
            .unwrap()
            .commit(0, header.block_hash())
            .unwrap();
        let certificate = Certificate {
            decision: precommit.decision.clone(),
            signers: vec![CertSigner {
                node: m.node,
                key_version: 0,
                signature: precommit.signature,
            }],
        };
        let block = BlockEnvelope {
            header,
            body,
            authority,
            authority_signature,
            certificate,
        };
        if height == 60 {
            boundary_block = Some(block.clone());
        }
        if height == 180 {
            last_block = Some(block.clone());
        }
        assert!(
            store
                .commit_integrated(&block, &physical, &verifier)
                .unwrap()
        );
        let (after, post) = store.load().unwrap();
        assert_eq!(after.root, prepared.root);
        assert_eq!(post.root().unwrap(), prepared.root);
        if height <= 60 {
            assert_eq!(block.header.candidate.target, initial_target);
        }
        if height == 60 || height == 120 {
            if timing_campaign {
                let original = primitive_types::U256::from_big_endian(&initial_target);
                let expected = if height == 60 {
                    original / 4
                } else {
                    original / 4 * 4
                };
                assert_eq!(after.next_target, expected.to_big_endian());
            } else {
                assert_eq!(after.next_target, initial_target);
            }
        }
        if height % 60 == 0 {
            let h = &post.continuity.as_ref().unwrap().members[0].history;
            let expected = match height {
                60 => (1, 1, 1, 1),
                120 => (2, 2, 2, 2),
                _ => (2, 3, 0, 2),
            };
            assert_eq!((h.p, h.a, h.s, h.h), expected);
        }
        let pool = Mempool::open(&path, genesis, fp, MAX_PENDING_BYTES).unwrap();
        if height == 101 || height == 102 {
            assert_eq!(
                pool.status(pending.as_ref().unwrap().id().unwrap())
                    .unwrap(),
                Some(Status::Pending)
            );
        }
        if height == 103 {
            assert_eq!(
                pool.status(pending.as_ref().unwrap().id().unwrap())
                    .unwrap(),
                Some(Status::Confirmed)
            );
        }
        if height == 106 {
            assert_eq!(
                pool.status(expiring.as_ref().unwrap().id().unwrap())
                    .unwrap(),
                Some(Status::Expired)
            );
        }
        if height == 107 {
            assert_eq!(
                pool.status(conflicted.as_ref().unwrap().id().unwrap())
                    .unwrap(),
                Some(Status::InputSpent)
            );
        }
        drop(pool);
        writeln!(output,"{}",serde_json::json!({"height":height,"envelope":hex::encode(block.encode().unwrap()),"state_root":hex::encode(after.root),
            "next_target":hex::encode(after.next_target),"anchor":hex::encode(block.certificate.decision.anchor().id()),
            "history":post.continuity.as_ref().unwrap().members[0].history.p})).unwrap();
        output.flush().unwrap();
        timestamps.push(block.header.candidate.timestamp);
        if height == 101 || height == 60 {
            drop(store);
            store =
                CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, initial_target)
                    .unwrap();
        }
        if height % 10 == 0 {
            eprintln!("integrated canonical height {height}: PASS");
        }
    }
    if physical_run || timing_campaign {
        let (head, state) = store.load().unwrap();
        std::fs::write(directory.join("physical-result.json"),serde_json::to_vec_pretty(&serde_json::json!({
            "result":"PASS","height":head.height,"state_root":hex::encode(state.root().unwrap()),
            "block_hash":hex::encode(head.block),"initial_counter":initial_counter,"final_counter":signer.read().unwrap(),
                "physical_tpm_votes":physical_run,"physical_genesis_and_rolling_quotes":physical_run,"period_counts":[60,54,53],
                "timing_clamps_pause_and_freshness_expiry":timing_campaign,
            "actual_genesis":false,"worker_and_owner_keys_fixture_only":true
        })).unwrap()).unwrap();
        return;
    }
    let (before, canonical) = store.load().unwrap();
    let mut alternate = boundary_block.unwrap();
    alternate.certificate.decision.round = 7;
    alternate.certificate.signers[0].signature = sign(
        &key,
        alternate.certificate.decision.signing_digest(m.node, 0),
    );
    assert!(
        !store
            .commit_integrated(&alternate, &physical, &FixtureAttestation)
            .unwrap()
    );
    assert_eq!(store.load().unwrap().0, before);

    // Apply supervised recovery to a separate database copy of the same fully
    // executed history. Historical roots/coins remain unchanged across restart.
    drop(store);
    let recovery_path = directory.join("recovery.sqlite");
    assert!(!recovery_path.exists());
    std::fs::copy(&path, &recovery_path).unwrap();
    store =
        CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, initial_target).unwrap();
    let mut recovered =
        CanonicalStore::open_trusted_genesis(&recovery_path, &descriptor, &initial, initial_target)
            .unwrap();
    let old = canonical.continuity.as_ref().unwrap();
    let replacement = SigningKey::from_bytes((&[18; 32]).into()).unwrap();
    let replacement_public: [u8; 33] = replacement
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    struct TestReplacement([u8; 33]);
    impl recovery::PhysicalAdmissionVerifier for TestReplacement {
        fn verify_replacement(&self, r: &recovery::Recovery) -> Result<()> {
            if r.new_hardware == [14; 32] && r.attestation == [15; 32] && r.new_voting_key == self.0
            {
                Ok(())
            } else {
                Err(Error::UnqualifiedPhysical)
            }
        }
    }
    let losses = vec![(old.members[0].lineage, 0)];
    let recovery_body = recovery::Recovery {
        network: NETWORK_ID,
        genesis,
        fingerprint: fp,
        anchor: Anchor {
            height: before.height,
            tip: before.block,
            state_root: before.root,
            registry_root: old.roots().unwrap().0,
        },
        sequence: 1,
        lineage: old.members[0].lineage,
        old_generation: 0,
        new_node: [13; 32],
        new_hardware: [14; 32],
        attestation: [15; 32],
        new_voting_key: replacement_public,
        operation: 1,
        reason: 1,
        ceremony_commitment: recovery::loss_commitment(&losses).unwrap(),
    };
    let recovery_key = EdKey::from_bytes(&[4; 32]);
    for bad_field in 0..7 {
        let mut b = recovery_body.clone();
        match bad_field {
            0 => b.network ^= 1,
            1 => b.genesis[0] ^= 1,
            2 => b.fingerprint[0] ^= 1,
            3 => b.anchor.tip[0] ^= 1,
            4 => b.sequence = 0,
            5 => b.attestation = [0; 32],
            _ => {}
        }
        let signing_key = if bad_field == 6 {
            EdKey::from_bytes(&[80; 32])
        } else {
            recovery_key.clone()
        };
        let cert = recovery::Certificate {
            signature: signing_key.sign(&b.digest()).to_bytes(),
            body: b,
        };
        assert!(
            recovered
                .accept_bootstrap_recovery(&cert, &TestReplacement(replacement_public), &losses)
                .is_err()
        );
        assert_eq!(recovered.load().unwrap().0, before);
    }
    let recovery_cert = recovery::Certificate {
        signature: recovery_key.sign(&recovery_body.digest()).to_bytes(),
        body: recovery_body,
    };
    assert!(
        recovered
            .accept_bootstrap_recovery(
                &recovery_cert,
                &TestReplacement(replacement_public),
                &losses
            )
            .unwrap()
    );
    assert!(
        !recovered
            .accept_bootstrap_recovery(
                &recovery_cert,
                &TestReplacement(replacement_public),
                &losses
            )
            .unwrap()
    );
    drop(recovered);
    let mut recovered =
        CanonicalStore::open_trusted_genesis(&recovery_path, &descriptor, &initial, initial_target)
            .unwrap();
    assert_eq!(recovered.load().unwrap().0, before);
    let (_, effective) = recovered.load_effective().unwrap();
    assert_eq!(effective.coins, canonical.coins);
    let member = &effective.continuity.as_ref().unwrap().members[0];
    assert_eq!(
        (
            member.history.p,
            member.history.a,
            member.history.s,
            member.history.h
        ),
        (2, 3, 0, 0)
    );
    assert_eq!(member.generation, 1);
    assert_eq!(member.node, [13; 32]);
    let new_physical = PhysicalMember {
        node: member.node,
        generation: member.generation,
        continuity_key: member.voting_key,
        hardware: member.hardware,
        admission_commitment: member.attestation,
        attestation_key: vec![6; 33],
    };
    let replacements = BTreeMap::from([(new_physical.node, new_physical)]);
    let parent = WorkParent {
        genesis,
        fingerprint: fp,
        block: before.block,
        height: 180,
        t0: descriptor.timestamp,
        target: before.next_target,
        ancestor_timestamps: timestamps.iter().rev().take(11).copied().collect(),
    };
    let parent_anchor = FinalizedAnchor {
        network: NETWORK_ID,
        genesis,
        fingerprint: fp,
        height: 180,
        block: before.block,
    };
    let mut refresh = AttestationRefresh {
        network: NETWORK_ID,
        genesis,
        fingerprint: fp,
        node: [13; 32],
        generation: 1,
        height: 181,
        parent_anchor: parent_anchor.id(),
        evidence: vec![],
    };
    refresh.evidence = refresh.challenge().to_vec();
    let body = BlockBody {
        height: 181,
        reward_owner: descriptor.owner,
        fees: 0,
        transactions: vec![],
        operations: vec![refresh.encode().unwrap()],
    };
    let mut candidate = Candidate {
        network: NETWORK_ID,
        genesis,
        fingerprint: fp,
        parent: before.block,
        height: 181,
        timestamp: descriptor.timestamp + 181 * 60,
        body_root: body.root().unwrap(),
        state_root: [0; 32],
        license: bindings[0].license,
        worker: bindings[0].worker,
        target: before.next_target,
    };
    candidate.state_root = effective
        .prepare_candidate(
            CandidatePreparation {
                parent: &parent,
                candidate: &candidate,
                ticket_sequence: 181,
                body: &body,
            },
            &replacements,
            &FixtureAttestation,
        )
        .unwrap()
        .root;
    let authority = WorkAuthority {
        candidate: candidate.clone(),
        assignment_sequence: 1,
        ticket_sequence: 181,
        coordinator: coordinator.verifying_key().to_bytes(),
        nonce_start: 0,
        nonce_end: u64::MAX,
        epoch: 181,
    };
    let authority_signature = coordinator.sign(&authority.id()).to_bytes();
    let mut header = WorkHeader {
        candidate,
        authority: authority.id(),
        nonce: 0,
    };
    mine(&mut header);
    let (membership, reputation, attestation) =
        effective.continuity.as_ref().unwrap().roots().unwrap();
    let decision = certificates::Decision {
        network: NETWORK_ID,
        genesis,
        fingerprint: fp,
        purpose: 2,
        height: 181,
        mining_epoch: 181,
        continuity_period: 3,
        round: 0,
        step: 3,
        previous_finalized_anchor: parent_anchor.id(),
        parent: before.block,
        block: header.block_hash(),
        state: header.candidate.state_root,
        membership,
        reputation,
        attestation,
    };
    let signature = sign(&replacement, decision.signing_digest([13; 32], 1));
    let resumed = BlockEnvelope {
        header,
        body,
        authority,
        authority_signature,
        certificate: Certificate {
            decision,
            signers: vec![CertSigner {
                node: [13; 32],
                key_version: 1,
                signature,
            }],
        },
    };
    assert!(
        recovered
            .commit_integrated(&resumed, &replacements, &FixtureAttestation)
            .unwrap()
    );
    let (resumed_head, resumed_state) = recovered.load().unwrap();
    assert_eq!(resumed_head.height, 181);
    assert_eq!(resumed_state.continuity.as_ref().unwrap().members.len(), 1);
    assert_eq!(resumed_state.accounting.freshness.len(), 1);
    assert!(resumed_state.accounting.freshness[&[13; 32]].eligible(
        [13; 32],
        1,
        replacement_public,
        182
    ));
    // Independent four-physical-voter fixture exercises activation through the
    // same licensed PoW executor and old-set certificate, then restart/recovery.
    let mut activation_initial = initial.clone();
    let mut activation_keys = vec![(m.node, key.clone())];
    for i in 40..43u8 {
        let signing = SigningKey::from_bytes((&[i; 32]).into()).unwrap();
        let public: [u8; 33] = signing
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        activation_initial
            .continuity
            .as_mut()
            .unwrap()
            .members
            .push(Member {
                lineage: [i; 32],
                node: [i; 32],
                hardware: [i + 10; 32],
                generation: 0,
                voting_key: public,
                attestation: [i + 20; 32],
                history: History::default(),
                physical: true,
                eligible: true,
                genesis_member: true,
            });
        activation_initial.accounting.freshness.insert(
            [i; 32],
            FreshnessRecord {
                node: [i; 32],
                generation: 0,
                key: public,
                committed_height: 0,
                evidence_commitment: [i + 30; 32],
            },
        );
        activation_keys.push(([i; 32], signing));
    }
    let activation_path = directory.join("activation.sqlite");
    let mut activation_store = CanonicalStore::open_trusted_genesis(
        &activation_path,
        &descriptor,
        &activation_initial,
        initial_target,
    )
    .unwrap();
    let (a_head, a_state) = activation_store.load().unwrap();
    let a_registry = a_state.continuity.as_ref().unwrap();
    let a_parent = WorkParent {
        genesis,
        fingerprint: fp,
        block: a_head.block,
        height: 0,
        t0: descriptor.timestamp,
        target: initial_target,
        ancestor_timestamps: vec![descriptor.timestamp],
    };
    let a_anchor = FinalizedAnchor {
        network: NETWORK_ID,
        genesis,
        fingerprint: fp,
        height: 0,
        block: a_head.block,
    };
    let (membership, reputation, attestation) = a_registry.roots().unwrap();
    let activation = activation::DecentralizedActivation {
        network: NETWORK_ID,
        genesis,
        fingerprint: fp,
        height: 1,
        parent: a_anchor.id(),
        membership,
        reputation,
    };
    let body = BlockBody {
        height: 1,
        reward_owner: descriptor.owner,
        fees: 0,
        transactions: vec![],
        operations: vec![activation.encode()],
    };
    let mut candidate = Candidate {
        network: NETWORK_ID,
        genesis,
        fingerprint: fp,
        parent: a_head.block,
        height: 1,
        timestamp: descriptor.timestamp + 60,
        body_root: body.root().unwrap(),
        state_root: [0; 32],
        license: bindings[0].license,
        worker: bindings[0].worker,
        target: initial_target,
    };
    candidate.state_root = a_state
        .prepare_candidate(
            CandidatePreparation {
                parent: &a_parent,
                candidate: &candidate,
                ticket_sequence: 1,
                body: &body,
            },
            &BTreeMap::new(),
            &FixtureAttestation,
        )
        .unwrap()
        .root;
    let authority = WorkAuthority {
        candidate: candidate.clone(),
        assignment_sequence: 1,
        ticket_sequence: 1,
        coordinator: coordinator.verifying_key().to_bytes(),
        nonce_start: 0,
        nonce_end: u64::MAX,
        epoch: 1,
    };
    let authority_signature = coordinator.sign(&authority.id()).to_bytes();
    let mut header = WorkHeader {
        candidate,
        authority: authority.id(),
        nonce: 0,
    };
    mine(&mut header);
    let decision = certificates::Decision {
        network: NETWORK_ID,
        genesis,
        fingerprint: fp,
        purpose: 2,
        height: 1,
        mining_epoch: 1,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: a_anchor.id(),
        parent: a_head.block,
        block: header.block_hash(),
        state: header.candidate.state_root,
        membership,
        reputation,
        attestation,
    };
    let signers = activation_keys
        .iter()
        .take(3)
        .map(|(node, k)| CertSigner {
            node: *node,
            key_version: 0,
            signature: sign(k, decision.signing_digest(*node, 0)),
        })
        .collect();
    let activated = BlockEnvelope {
        header,
        body,
        authority,
        authority_signature,
        certificate: Certificate { decision, signers },
    };
    let mut insufficient = activated.clone();
    insufficient.certificate.signers.pop();
    assert!(
        activation_store
            .commit_integrated(&insufficient, &BTreeMap::new(), &FixtureAttestation)
            .is_err()
    );
    assert!(
        activation_store
            .commit_integrated(&activated, &BTreeMap::new(), &FixtureAttestation)
            .unwrap()
    );
    drop(activation_store);
    let mut activation_store = CanonicalStore::open_trusted_genesis(
        &activation_path,
        &descriptor,
        &activation_initial,
        initial_target,
    )
    .unwrap();
    let (a_head, a_state) = activation_store.load().unwrap();
    let registry = a_state.continuity.as_ref().unwrap();
    assert_eq!(registry.mode(), "DECENTRALIZED");
    assert!(!registry.recovery_enabled());
    let mut forbidden = recovery_cert.clone();
    forbidden.body.anchor = Anchor {
        height: a_head.height,
        tip: a_head.block,
        state_root: a_head.root,
        registry_root: registry.roots().unwrap().0,
    };
    forbidden.signature = recovery_key.sign(&forbidden.body.digest()).to_bytes();
    assert!(matches!(
        activation_store.accept_bootstrap_recovery(
            &forbidden,
            &TestReplacement(replacement_public),
            &losses
        ),
        Err(canonical_store::ChainError::Invalid(
            Error::RecoveryDisabled
        ))
    ));
    // Different sufficient signer subsets still name exactly one finalized block.
    let mut other_subset = activated.clone();
    other_subset.certificate.decision.round = 5;
    other_subset.certificate.signers = activation_keys
        .iter()
        .skip(1)
        .map(|(node, k)| CertSigner {
            node: *node,
            key_version: 0,
            signature: sign(
                k,
                other_subset.certificate.decision.signing_digest(*node, 0),
            ),
        })
        .collect();
    assert_eq!(
        other_subset.certificate.decision.anchor().id(),
        activated.certificate.decision.anchor().id()
    );
    assert!(
        !activation_store
            .commit_integrated(&other_subset, &BTreeMap::new(), &FixtureAttestation)
            .unwrap()
    );

    // A second fully valid block at already-finalized height 180 is an integrity
    // violation even in another round. Historical authority is derived from undo
    // records, not supplied by the conflicting certificate.
    let mut conflict = last_block.unwrap();
    conflict.authority.candidate.timestamp += 1;
    conflict.header.candidate.timestamp += 1;
    conflict.authority_signature = coordinator.sign(&conflict.authority.id()).to_bytes();
    conflict.header.authority = conflict.authority.id();
    mine(&mut conflict.header);
    conflict.certificate.decision.block = conflict.block_hash();
    conflict.certificate.decision.round = 1;
    conflict.certificate.signers[0].signature = sign(
        &key,
        conflict.certificate.decision.signing_digest(m.node, 0),
    );
    assert!(
        store
            .commit_integrated(&conflict, &physical, &FixtureAttestation)
            .is_err()
    );
    assert_eq!(store.load().unwrap().0, before);
    let db = rusqlite::Connection::open(&path).unwrap();
    assert!(
        db.query_row("SELECT halted FROM integrity WHERE id=1", [], |r| r
            .get::<_, bool>(0))
            .unwrap()
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM finality_evidence WHERE height=?1",
            [180u64.to_be_bytes().as_slice()],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        2
    );
    eprintln!(
        "INTEGRATED EXECUTOR 180 heights / period totals 60,54,53 / transaction lifecycle / retarget PASS: {}",
        directory.display()
    );
}
