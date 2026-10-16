//! Software-generated TPM wire fixtures exercise the native verifier and store.
//! They are not physical-attestation evidence and are never admitted on a node.
use ed25519_dalek::{Signer, SigningKey as Ed};
use mutiny_consensus_v8::{
    admission::*,
    canonical_store::{CanonicalStore, checkpoint::*},
    execution::State,
    provenance::AdmissionClass,
    recovery::*,
    recovery_material::RecoveryMaterial,
    tpm::TpmProfile,
    *,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
fn blob(raw: &[u8]) -> Vec<u8> {
    let mut v = (raw.len() as u16).to_be_bytes().to_vec();
    v.extend(raw);
    v
}

#[test]
fn complete_genesis_inputs_bind_rules_admission_and_fresh_native_quote() {
    use mutiny_consensus_v8::{
        genesis_inputs::*, licenses::BindWorker, protocol_manifest::RuleManifest,
    };
    let owner = Ed::from_bytes(&[80; 32]);
    let node_key = Ed::from_bytes(&[81; 32]);
    let recovery = Ed::from_bytes(&[82; 32]);
    let ak = SigningKey::from_bytes((&[83; 32]).into()).unwrap();
    let vote = SigningKey::from_bytes((&[84; 32]).into()).unwrap();
    let p = profile(&ak, &vote, [85; 32]);
    let rules = RuleManifest {
        commitments: vec![(b"software-test-rules".to_vec(), [86; 32])],
    };
    let target = [87; 32];
    let input = PhysicalAdmissionInput {
        owner: owner.verifying_key().to_bytes(),
        node_authentication: node_key.verifying_key().to_bytes(),
        endorsement_root: [88; 32],
        profile: p.clone(),
    };
    let params = Parameters {
        initial_target: target,
        rules: rules.clone(),
        treasury: None,
    };
    let descriptor = blocks::GenesisDescriptor {
        timestamp: 1_800_000_000,
        nonce: [89; 32],
        fingerprint: rules.fingerprint().unwrap(),
        owner: transactions::address(&input.owner),
        purchase: [90; 32],
        parameters: params.encode().unwrap(),
        admission_records: vec![input.encode().unwrap()],
        recovery: recovery.verifying_key().to_bytes(),
    };
    assert_eq!(Parameters::decode(&descriptor.parameters).unwrap(), params);
    validate_descriptor(&descriptor, &rules, target).unwrap();
    let gid = descriptor.id().unwrap();
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let mut bindings: Vec<BindWorker> = vectors["cases"][0]["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            BindWorker::decode(&hex::decode(v["binding_hex"].as_str().unwrap()).unwrap()).unwrap()
        })
        .collect();
    for (i, b) in bindings.iter_mut().enumerate() {
        b.genesis = gid;
        b.fingerprint = descriptor.fingerprint;
        b.license = blocks::genesis_license(gid, i as u64).unwrap();
        b.worker = b.worker_id();
        b.owner_signature = owner.sign(&b.signing_digest(false)).to_bytes();
        b.worker_signature = Ed::from_bytes(&[10 + i as u8; 32])
            .sign(&b.signing_digest(true))
            .to_bytes();
    }
    let policy = AdmissionPolicy {
        genesis: gid,
        fingerprint: descriptor.fingerprint,
        authority: input.owner,
        endorsement_roots: [input.endorsement_root].into(),
    };
    let approved = approved(&p, &policy, &owner);
    let node = join::node_id(gid, input.node_authentication);
    let member = freshness::PhysicalMember {
        node,
        generation: 0,
        continuity_key: point(&vote),
        hardware: p.hardware,
        admission_commitment: p.commitment().unwrap(),
        attestation_key: p.ak_public.clone(),
    };
    let nonce = [91; 32];
    let evidence = quote(&p, &ak, freshness::genesis_challenge(gid, nonce, &member));
    let state = initial_state(
        &descriptor,
        &rules,
        target,
        &bindings,
        &approved,
        nonce,
        &evidence,
        mutiny_consensus_v8::genesis_inputs::GenesisProfile::Test,
    )
    .unwrap();
    assert!(state.coins.is_empty());
    assert_eq!(state.licenses.workers.len(), 12);
    assert_eq!(
        state.protocol_records.get(&parameters_key()),
        Some(&descriptor.parameters)
    );
    assert_eq!(
        state.continuity.as_ref().unwrap().weights().unwrap(),
        vec![1.into()]
    );
    let fresh = &state.accounting.freshness[&node];
    assert!(fresh.eligible(node, 0, point(&vote), 1));
    assert!(fresh.eligible(node, 0, point(&vote), 60));
    assert!(!fresh.eligible(node, 0, point(&vote), 61));
    let root = state.root().unwrap();
    if let Some(path) = std::env::var_os("BUILD8_GENESIS_INITIAL_PUBLIC_VECTOR") {
        use std::io::Write;
        let records = state
            .records()
            .unwrap()
            .into_iter()
            .map(|(k, v)| (hex::encode(k), hex::encode(v)))
            .collect::<Vec<_>>();
        let value = serde_json::json!({"schema":"BUILD8-COMPLETE-GENESIS-VECTOR-V1","software_keys_only":true,"physical_attestation_qualified":false,"actual_genesis":false,
            "descriptor":hex::encode(descriptor.encode().unwrap()),"genesis_id":hex::encode(gid),"locked_rules":hex::encode(rules.encode().unwrap()),"qualified_target":hex::encode(target),
            "bindings":bindings.iter().map(|b|hex::encode(b.encode())).collect::<Vec<_>>(),"approved_profile":hex::encode(approved.encode().unwrap()),"supervised_nonce":hex::encode(nonce),"evidence":hex::encode(&evidence),
            "records":records,"state_root":hex::encode(root),"genesis_block":hex::encode(descriptor.block(root).unwrap()),"genesis_block_hash":hex::encode(descriptor.block_hash(root).unwrap())});
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(&serde_json::to_vec_pretty(&value).unwrap())
            .unwrap();
        file.sync_all().unwrap();
    }
    assert_eq!(
        State::from_records(&state.records().unwrap(), root).unwrap(),
        state
    );
    assert_eq!(descriptor.id().unwrap(), gid);
    assert!(
        initial_state(
            &descriptor,
            &rules,
            target,
            &bindings,
            &approved,
            [92; 32],
            &evidence,
            mutiny_consensus_v8::genesis_inputs::GenesisProfile::Test
        )
        .is_err()
    );
    let mut bad = approved.clone();
    bad.signature[0] ^= 1;
    assert!(
        initial_state(
            &descriptor,
            &rules,
            target,
            &bindings,
            &bad,
            nonce,
            &evidence,
            mutiny_consensus_v8::genesis_inputs::GenesisProfile::Test
        )
        .is_err()
    );
    assert!(validate_descriptor(&descriptor, &rules, [0; 32]).is_err());
    let mut wrong_rules = rules.clone();
    wrong_rules.commitments[0].1[0] ^= 1;
    assert!(validate_descriptor(&descriptor, &wrong_rules, target).is_err());
    let mut partial = descriptor.clone();
    partial.parameters = vec![0x80];
    assert!(validate_descriptor(&partial, &rules, target).is_err());
    let mut cloud = descriptor.clone();
    cloud.admission_records.clear();
    assert!(validate_descriptor(&cloud, &rules, target).is_err());
    let mut same_key = input.clone();
    same_key.node_authentication = same_key.owner;
    assert!(same_key.encode().is_err());
}
fn point(key: &SigningKey) -> [u8; 33] {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn public(key: &SigningKey, restricted: bool) -> Vec<u8> {
    let mut b = vec![];
    b.extend(0x23u16.to_be_bytes());
    b.extend(0xbu16.to_be_bytes());
    b.extend(if restricted { 0x50472u32 } else { 0x40472u32 }.to_be_bytes());
    b.extend(blob(&[]));
    for n in [0x10u16, 0x18, 0xb, 3, 0x10] {
        b.extend(n.to_be_bytes());
    }
    let p = key.verifying_key().to_encoded_point(false);
    b.extend(blob(p.x().unwrap()));
    b.extend(blob(p.y().unwrap()));
    blob(&b)
}
fn sign(key: &SigningKey, digest: Hash) -> [u8; 64] {
    let s: Signature = key.sign_prehash(&digest).unwrap();
    s.normalize_s().unwrap_or(s).to_bytes().into()
}
fn tpm_sig(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let s = sign(key, Sha256::digest(message).into());
    let mut v = vec![0, 0x18, 0, 0xb];
    v.extend(blob(&s[..32]));
    v.extend(blob(&s[32..]));
    v
}
fn header(kind: u16, signer: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut v = 0xff544347u32.to_be_bytes().to_vec();
    v.extend(kind.to_be_bytes());
    v.extend(blob(signer));
    v.extend(blob(challenge));
    v.extend([0u8; 16]);
    v.push(1);
    v.extend([0u8; 8]);
    v
}
fn profile(ak: &SigningKey, vote: &SigningKey, hardware: Hash) -> TpmProfile {
    let signer = [vec![0, 0xb], vec![73; 32]].concat();
    let voting = public(vote, false);
    let name = [vec![0, 0xb], Sha256::digest(&voting[2..]).to_vec()].concat();
    let mut message = header(0x8017, &signer, &[0, 255, 85, 170]);
    message.extend(blob(&name));
    message.extend(blob(&signer));
    let p = TpmProfile {
        hardware,
        ak_public: public(ak, true),
        voting_public: voting,
        qualified_signer: signer,
        pcr_bitmap: [0x95, 0x43, 0],
        pcr_digest: [74; 32],
        certify_signature: tpm_sig(ak, &message),
        certify_message: message,
        admission_trust_manifest: [75; 32],
        provenance: None,
    };
    p.verify_certified_key().unwrap();
    p
}
fn approved(p: &TpmProfile, policy: &AdmissionPolicy, authority: &Ed) -> ApprovedProfile {
    let mut a = ApprovedProfile {
        genesis: policy.genesis,
        fingerprint: policy.fingerprint,
        endorsement_root: *policy.endorsement_roots.first().unwrap(),
        profile: p.encode().unwrap(),
        signature: [0; 64],
    };
    a.signature = authority.sign(&a.signing_digest().unwrap()).to_bytes();
    a.verify(policy, AdmissionClass::LegacyTest).unwrap();
    a
}
fn quote(p: &TpmProfile, ak: &SigningKey, challenge: Hash) -> Vec<u8> {
    let mut message = header(0x8018, &p.qualified_signer, &challenge);
    message.extend(1u32.to_be_bytes());
    message.extend(0xbu16.to_be_bytes());
    message.push(3);
    message.extend(p.pcr_bitmap);
    message.extend(blob(&p.pcr_digest));
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&message)
        .unwrap()
        .bytes(&tpm_sig(ak, &message))
        .unwrap();
    e.into_writer()
}
struct Reject;
impl PhysicalAdmissionVerifier for Reject {
    fn verify_replacement(&self, _: &Recovery) -> Result<()> {
        Err(Error::UnqualifiedPhysical)
    }
}
impl freshness::PhysicalAttestationVerifier for Reject {
    fn verify(&self, _: &freshness::PhysicalMember, _: Hash, _: &[u8]) -> Result<()> {
        Err(Error::UnqualifiedPhysical)
    }
}

#[test]
fn native_recovery_material_is_atomic_restartable_and_checkpoint_replayable() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let authority = Ed::from_bytes(&[51; 32]);
    let recovery = Ed::from_bytes(&[64; 32]);
    let owner = Ed::from_bytes(&[80; 32]);
    let mut descriptor = blocks::GenesisDescriptor::decode(
        &hex::decode(v["descriptor_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    descriptor.recovery = recovery.verifying_key().to_bytes();
    let gid = descriptor.id().unwrap();
    let fp = descriptor.fingerprint;
    let mut bindings = Vec::new();
    for (i, value) in v["cases"][0]["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let mut b = licenses::BindWorker::decode(
            &hex::decode(value["binding_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        b.genesis = gid;
        let mut seed = gid.to_vec();
        seed.extend((i as u64).to_be_bytes());
        b.license = domain_hash(b"MUTINY-BUILD8-GENESIS-LICENSE-V1", &seed);
        b.worker = b.worker_id();
        b.owner_signature = owner.sign(&b.signing_digest(false)).to_bytes();
        b.worker_signature = Ed::from_bytes(&[10 + i as u8; 32])
            .sign(&b.signing_digest(true))
            .to_bytes();
        bindings.push(b);
    }
    let policy = AdmissionPolicy {
        genesis: gid,
        fingerprint: fp,
        authority: authority.verifying_key().to_bytes(),
        endorsement_roots: [[77; 32]].into_iter().collect(),
    };
    let old_vote = SigningKey::from_bytes((&[17; 32]).into()).unwrap();
    let old_ak = SigningKey::from_bytes((&[18; 32]).into()).unwrap();
    let new_vote = SigningKey::from_bytes((&[19; 32]).into()).unwrap();
    let new_ak = SigningKey::from_bytes((&[20; 32]).into()).unwrap();
    let old_profile = profile(&old_ak, &old_vote, [21; 32]);
    let new_profile = profile(&new_ak, &new_vote, [22; 32]);
    let old_approved = approved(&old_profile, &policy, &authority);
    let new_approved = approved(&new_profile, &policy, &authority);
    let registry = ContinuityState::bootstrap(
        gid,
        fp,
        Anchor {
            height: 0,
            tip: [0; 32],
            state_root: [0; 32],
            registry_root: [0; 32],
        },
        descriptor.recovery,
        vec![Member {
            lineage: [4; 32],
            node: [5; 32],
            hardware: old_profile.hardware,
            generation: 0,
            voting_key: point(&old_vote),
            attestation: old_profile.commitment().unwrap(),
            history: reputation::History::default(),
            physical: true,
            eligible: true,
            genesis_member: true,
        }],
    )
    .unwrap();
    let mut initial = State {
        licenses: genesis::GenesisIdentity::new(descriptor.clone())
            .unwrap()
            .bind_workers(&bindings)
            .unwrap(),
        continuity: Some(registry),
        admission: AdmissionBook {
            policy: Some(policy),
            profiles: BTreeMap::from([(old_profile.commitment().unwrap(), old_approved)]),
        },
        ..Default::default()
    };
    initial.membership.controls.insert(
        [5; 32],
        membership::NodeControl {
            node: [5; 32],
            generation: 0,
            owner: owner.verifying_key().to_bytes(),
            node_authentication: owner.verifying_key().to_bytes(),
            sequence: 0,
            exit_boundary: None,
            admitted_height: 0,
            admission_boundary: None,
            hardware_since_height: 0,
        },
    );
    initial.accounting.freshness.insert(
        [5; 32],
        freshness::FreshnessRecord {
            node: [5; 32],
            generation: 0,
            key: point(&old_vote),
            committed_height: 0,
            evidence_commitment: [8; 32],
        },
    );
    let path = std::env::temp_dir().join(format!(
        "build8-native-recovery-{}.sqlite",
        std::process::id()
    ));
    assert!(!path.exists());
    let mut store =
        CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, [255; 32]).unwrap();
    let (head, before) = store.load_effective().unwrap();
    let node = Ed::from_bytes(&[63; 32]);
    let losses = [([4; 32], 0)];
    let body = Recovery {
        network: NETWORK_ID,
        genesis: gid,
        fingerprint: fp,
        anchor: Anchor {
            height: head.height,
            tip: head.block,
            state_root: head.root,
            registry_root: before.continuity.as_ref().unwrap().roots().unwrap().0,
        },
        sequence: 1,
        lineage: [4; 32],
        old_generation: 0,
        new_node: join::node_id(gid, node.verifying_key().to_bytes()),
        new_hardware: new_profile.hardware,
        attestation: new_profile.commitment().unwrap(),
        new_voting_key: point(&new_vote),
        operation: 1,
        reason: 1,
        ceremony_commitment: loss_commitment(&losses).unwrap(),
    };
    let certificate = Certificate {
        signature: recovery.sign(&body.digest()).to_bytes(),
        body,
    };
    let mut witness = RecoveryMaterial {
        approved_profile: new_approved.encode().unwrap(),
        node_authentication: node.verifying_key().to_bytes(),
        quote: quote(
            &new_profile,
            &new_ak,
            RecoveryMaterial::challenge(&certificate.body),
        ),
        node_signature: [0; 64],
        possession_signature: [0; 64],
    };
    witness.node_signature = node
        .sign(&witness.node_digest(&certificate.body))
        .to_bytes();
    witness.possession_signature = sign(&new_vote, witness.possession_digest(&certificate.body));
    assert!(
        store
            .accept_bootstrap_recovery(&certificate, &Reject, &losses)
            .is_err()
    );
    let mut bad = witness.clone();
    bad.possession_signature[0] ^= 1;
    assert!(
        store
            .accept_admitted_bootstrap_recovery(&certificate, &bad, &losses)
            .is_err()
    );
    assert_eq!(
        store.load_effective().unwrap().1.records().unwrap(),
        before.records().unwrap()
    );
    assert!(
        store
            .accept_admitted_bootstrap_recovery(&certificate, &witness, &losses)
            .unwrap()
    );
    let expected = store.load_effective().unwrap().1;
    let transport = store.recovery_envelope(0).unwrap().unwrap();
    let decoded =
        canonical_store::recovery_transport::RecoveryEnvelope::decode(&transport).unwrap();
    assert_eq!(decoded.encode().unwrap(), transport);
    let transport_path = path.with_extension("transport.sqlite");
    assert!(!transport_path.exists());
    let mut transported =
        CanonicalStore::open_trusted_genesis(&transport_path, &descriptor, &initial, [255; 32])
            .unwrap();
    let mut invalid =
        canonical_store::recovery_transport::RecoveryEnvelope::decode(&transport).unwrap();
    invalid.witness.possession_signature[0] ^= 1;
    assert!(
        transported
            .accept_recovery_envelope(&invalid.encode().unwrap())
            .is_err()
    );
    assert!(transported.recovery_envelope(0).unwrap().is_none());
    invalid.losses[0].1 += 1;
    assert!(invalid.encode().is_err());
    assert!(transported.accept_recovery_envelope(&transport).unwrap());
    assert!(!transported.accept_recovery_envelope(&transport).unwrap());
    assert_eq!(
        transported.load_effective().unwrap().1.records().unwrap(),
        expected.records().unwrap()
    );
    drop(transported);
    std::fs::remove_file(&transport_path).unwrap();
    assert_eq!(expected.membership.retired[&([5; 32], 0)].reason, 3);
    assert_eq!(
        expected.membership.controls[&certificate.body.new_node].generation,
        1
    );
    assert!(
        expected.accounting.freshness[&certificate.body.new_node].eligible(
            certificate.body.new_node,
            1,
            point(&new_vote),
            1
        )
    );
    drop(store);
    let mut reopened =
        CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, [255; 32]).unwrap();
    assert_eq!(
        reopened.load_effective().unwrap().1.records().unwrap(),
        expected.records().unwrap()
    );
    assert!(
        !reopened
            .accept_admitted_bootstrap_recovery(&certificate, &witness, &losses)
            .unwrap()
    );
    assert!(
        reopened
            .accept_admitted_bootstrap_recovery(&certificate, &bad, &losses)
            .is_err()
    );
    // The replacement material must be usable by ordinary canonical execution,
    // not merely survive as unconsumed metadata in the recovery overlay.
    let (parent, effective) = reopened.execution_parent(0).unwrap();
    let block_body = blocks::BlockBody {
        height: 1,
        reward_owner: descriptor.owner,
        fees: 0,
        transactions: vec![],
        operations: vec![],
    };
    let mut candidate = pow::Candidate {
        network: NETWORK_ID,
        genesis: gid,
        fingerprint: fp,
        parent: parent.block,
        height: 1,
        timestamp: descriptor.timestamp + 60,
        body_root: block_body.root().unwrap(),
        state_root: [0; 32],
        license: bindings[0].license,
        worker: bindings[0].worker,
        target: [255; 32],
    };
    let prepared = effective
        .prepare_candidate(
            execution::CandidatePreparation {
                parent: &parent,
                candidate: &candidate,
                ticket_sequence: 1,
                body: &block_body,
            },
            &BTreeMap::new(),
            &Reject,
        )
        .unwrap();
    // T8: a validator-local physical map or verifier cannot change the acceptance of a
    // policy-bearing state. The caller's map and verifier could only ever be consulted for a
    // physical operation, so three contexts, (a) the committed context, (b) an empty map with a
    // reject-all verifier and (c) a WRONG PhysicalMember map with an ACCEPT-ALL verifier, are
    // compared on the empty block above AND on blocks that carry an attestation refresh (operation
    // 12) of the recovered member: the identical execution root, or the identical error, in all
    // three, and garbage refresh evidence is refused even under (c). The committed records are
    // the only source.
    {
        struct AcceptAll;
        impl freshness::PhysicalAttestationVerifier for AcceptAll {
            fn verify(&self, _: &freshness::PhysicalMember, _: Hash, _: &[u8]) -> Result<()> {
                Ok(())
            }
        }
        fn outcome<V: freshness::PhysicalAttestationVerifier>(
            state: &State,
            input: execution::CandidatePreparation<'_>,
            physical: &BTreeMap<Hash, freshness::PhysicalMember>,
            verifier: &V,
        ) -> std::result::Result<Hash, String> {
            state
                .prepare_candidate(input, physical, verifier)
                .map(|executed| executed.root)
                .map_err(|e| format!("{e:?}"))
        }
        let class = effective.admission_class().unwrap();
        let (committed, committed_verifier) = effective
            .admission
            .physical_context(effective.continuity.as_ref().unwrap(), class)
            .unwrap();
        let mut wrong = committed.clone();
        for member in wrong.values_mut() {
            member.hardware[0] ^= 1;
            member.admission_commitment[0] ^= 1;
        }
        let new_node = certificate.body.new_node;
        assert!(wrong.contains_key(&new_node), "the committed context names the recovered member");
        let three = |body: &blocks::BlockBody, c: &pow::Candidate| {
            let input = || execution::CandidatePreparation {
                parent: &parent,
                candidate: c,
                ticket_sequence: 1,
                body,
            };
            [
                outcome(&effective, input(), &committed, &committed_verifier),
                outcome(&effective, input(), &BTreeMap::new(), &Reject),
                outcome(&effective, input(), &wrong, &AcceptAll),
            ]
        };
        // The empty block: no physical operation.
        let [a, b, c] = three(&block_body, &candidate);
        assert_eq!(a, Ok(prepared.root));
        assert_eq!(b, a, "empty block: (b) empty map + reject-all");
        assert_eq!(c, a, "empty block: (c) wrong map + accept-all");
        // A block carrying an attestation refresh of the recovered member, with the given evidence.
        let mut refresh = freshness::AttestationRefresh {
            network: NETWORK_ID,
            genesis: gid,
            fingerprint: fp,
            node: new_node,
            generation: 1,
            height: 1,
            parent_anchor: anchors::FinalizedAnchor {
                network: NETWORK_ID,
                genesis: gid,
                fingerprint: fp,
                height: parent.height,
                block: parent.block,
            }
            .id(),
            evidence: vec![],
        };
        refresh.evidence = quote(&new_profile, &new_ak, refresh.challenge());
        let refresh_block = |evidence: &[u8]| {
            let mut r = refresh.clone();
            r.evidence = evidence.to_vec();
            let body = blocks::BlockBody {
                height: 1,
                reward_owner: descriptor.owner,
                fees: 0,
                transactions: vec![],
                operations: vec![r.encode().unwrap()],
            };
            let mut c = candidate.clone();
            c.body_root = body.root().unwrap();
            (body, c)
        };
        // A valid refresh: a real state change (the verifier IS consulted), identical in all three.
        let (body, c_valid) = refresh_block(&refresh.evidence);
        let [a, b, c] = three(&body, &c_valid);
        let refreshed = a.clone().expect("the committed context accepts the member's fresh quote");
        assert_ne!(refreshed, prepared.root, "the refresh changed the freshness record");
        assert_eq!(b, a, "valid refresh: (b) empty map + reject-all");
        assert_eq!(c, a, "valid refresh: (c) wrong map + accept-all");
        let executed = effective
            .prepare_candidate(
                execution::CandidatePreparation {
                    parent: &parent,
                    candidate: &c_valid,
                    ticket_sequence: 1,
                    body: &body,
                },
                &committed,
                &committed_verifier,
            )
            .unwrap();
        assert_eq!(executed.state.accounting.freshness[&new_node].committed_height, 1);
        // Garbage evidence: refused in all three contexts with the identical error; a local
        // accept-all verifier and a wrong local map admit nothing.
        let (body, c_bad) = refresh_block(&[1, 2, 3]);
        let [a, b, c] = three(&body, &c_bad);
        assert!(a.is_err(), "the committed context refuses garbage refresh evidence");
        assert_eq!(b, a, "garbage evidence: (b) empty map + reject-all");
        assert_eq!(c, a, "garbage evidence: (c) wrong map + accept-all");
    }
    candidate.state_root = prepared.root;
    let coordinator = Ed::from_bytes(&[90; 32]);
    let work = pow::WorkAuthority {
        candidate: candidate.clone(),
        assignment_sequence: 1,
        ticket_sequence: 1,
        coordinator: coordinator.verifying_key().to_bytes(),
        nonce_start: 0,
        nonce_end: u64::MAX,
        epoch: 1,
    };
    let work_signature = coordinator.sign(&work.id()).to_bytes();
    let header = pow::WorkHeader {
        candidate,
        authority: work.id(),
        nonce: 0,
    };
    let (membership, reputation, attestation) =
        effective.continuity.as_ref().unwrap().roots().unwrap();
    let parent_anchor = anchors::FinalizedAnchor {
        network: NETWORK_ID,
        genesis: gid,
        fingerprint: fp,
        height: 0,
        block: parent.block,
    };
    let decision = certificates::Decision {
        network: NETWORK_ID,
        genesis: gid,
        fingerprint: fp,
        purpose: 2,
        height: 1,
        mining_epoch: 1,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: parent_anchor.id(),
        parent: parent.block,
        block: header.block_hash(),
        state: prepared.root,
        membership,
        reputation,
        attestation,
    };
    let signature = sign(
        &new_vote,
        decision.signing_digest(certificate.body.new_node, 1),
    );
    let block = block_envelope::BlockEnvelope {
        header,
        body: block_body,
        authority: work,
        authority_signature: work_signature,
        certificate: certificates::Certificate {
            decision,
            signers: vec![certificates::Signer {
                node: certificate.body.new_node,
                key_version: 1,
                signature,
            }],
        },
    };
    assert!(
        reopened
            .commit_integrated(&block, &BTreeMap::new(), &Reject)
            .unwrap()
    );
    let expected = reopened.load_effective().unwrap().1;
    if let Ok(destination) = std::env::var("BUILD8_RECOVERY_PUBLIC_VECTOR") {
        use std::io::Write;
        let value = serde_json::json!({"schema":"BUILD8-RECOVERY-TRANSPORT-VECTOR-V1","actual_genesis":false,
            "physical_attestation_qualified":false,"software_keys_only":true,
            "bundle":{"actual_genesis":false,"physical_evidence_fixture_only":true,
                "descriptor":hex::encode(descriptor.encode().unwrap()),
                "initial_target":hex::encode([255;32]),
                "initial_records":initial.records().unwrap().into_iter().map(|(k,v)|(hex::encode(k),hex::encode(v))).collect::<Vec<_>>()},
            "recovery_envelope":hex::encode(&transport),"successor_envelope":hex::encode(block.encode().unwrap()),
            "effective_state_root":hex::encode(expected.root().unwrap())});
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .unwrap();
        file.write_all(&serde_json::to_vec_pretty(&value).unwrap())
            .unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();
    }
    assert_eq!(
        expected.continuity.as_ref().unwrap().members[0].generation,
        1
    );
    let archive = path.with_extension("checkpoint");
    let restored = path.with_extension("restored.sqlite");
    reopened.export_checkpoint(&archive, 1024 * 1024).unwrap();
    let (mut copy, _) = restore_checkpoint(CheckpointRestore {
        archive: &archive,
        database: &restored,
        descriptor: &descriptor,
        initial: &initial,
        initial_target: [255; 32],
        physical: &BTreeMap::new(),
        attestation: &Reject,
        legacy_recovery: &Reject,
        byte_budget: 1024 * 1024,
    })
    .unwrap();
    assert_eq!(
        copy.load_effective().unwrap().1.records().unwrap(),
        expected.records().unwrap()
    );
    drop(copy);
    drop(reopened);
    for p in [path, archive, restored] {
        std::fs::remove_file(p).unwrap();
    }
}
