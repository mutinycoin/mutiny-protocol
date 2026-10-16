// Entirely synthetic native/owner/Node/Continuity material. No hardware access.
fn qualify_hardware_rotation_validator(
    state: &State,
    parent: &FinalizedAnchor,
    owner: &HybridKey,
    node_key: &HybridKey,
    continuity: &HybridKey,
    old_continuity: &HybridKey,
    old_profile: &TpmProfile,
    software_rotation: &KeyRotate,
) {
    use crate::hardware_rotate_v2::HardwareRotate;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let ak = SigningKey::from_bytes((&[17u8; 32]).into()).unwrap();
    let native = SigningKey::from_bytes((&[18u8; 32]).into()).unwrap();
    let mut replacement = profile(&ak);
    replacement.hardware = [55; 32];
    replacement.voting_public = public(&native, false);
    let mut name = vec![0, 0xb];
    name.extend(Sha256::digest(&replacement.voting_public[2..]));
    let mut certified = header(0x8017, &replacement.qualified_signer, &[0, 255, 85, 170]);
    certified.extend(blob(&name));
    certified.extend(blob(&replacement.qualified_signer));
    replacement.certify_signature = signature(&ak, &certified);
    replacement.certify_message = certified;
    let node = state.continuity.as_ref().unwrap().members[0].node;
    let mut rotation = HardwareRotate {
        parent: parent.clone(),
        nonce: [56; 32],
        sequence: 1,
        old_hardware_generation: 1,
        old_key_generation: 1,
        binding: state.membership_v2.get(node).unwrap().binding().clone(),
        native_possession: [0; 64],
    };
    rotation.binding.admission.hardware_generation = 2;
    rotation.binding.admission.key_generation = 2;
    rotation.binding.admission.continuity_descriptor = continuity.public().descriptor(2).unwrap();
    let sign = |r: &mut HardwareRotate, p: &TpmProfile| {
        r.binding.admission.profile = p.encode().unwrap();
        r.binding.admission.supervised_nonce = r.admission_nonce().unwrap();
        r.binding.admission.prove_continuity(continuity).unwrap();
        r.binding.admission.quote = quote(&ak, p, r.binding.admission.challenge().unwrap());
        r.binding.admission.authorize(owner, 1).unwrap();
        r.binding.sign(node_key).unwrap();
        let signature: Signature = native.sign_prehash(&r.native_digest().unwrap()).unwrap();
        r.native_possession = signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into();
    };
    sign(&mut rotation, &replacement);
    let root = state.root().unwrap();
    let raw = rotation.encode().unwrap();
    assert!(HardwareRotate::decode(&raw).unwrap() == rotation);
    assert!(rotation.verify(state, parent, root).is_ok());
    assert!(raw.len() <= 16 * 1024);
    if let Ok(path) = std::env::var("BUILD8_EXPORT_HARDWARE_ROTATION_PUBLIC_V2") {
        use std::io::Write;
        let fixture = serde_json::json!({
            "synthetic_only": true, "production_authorized": false,
            "operation": hex::encode(&raw),
            "admission_nonce": hex::encode(rotation.admission_nonce().unwrap()),
            "native_digest": hex::encode(rotation.native_digest().unwrap()),
            "native_public": hex::encode(crate::tpm::public_key(&replacement.voting_public, false).unwrap()),
            "root": hex::encode(root),
            "records": state.records().unwrap().iter().map(|(key, record)|
                serde_json::json!({"key":hex::encode(key), "record":hex::encode(record)})
            ).collect::<Vec<_>>(),
        });
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(serde_json::to_string_pretty(&fixture).unwrap().as_bytes())
            .unwrap();
        file.sync_all().unwrap();
    }
    assert!(HardwareRotate::decode(&[raw.as_slice(), &[0]].concat()).is_err());
    for n in 0..23 {
        let mut bad = rotation.clone();
        match n {
            0 => bad.parent.block[0] ^= 1,
            1 => bad.parent.height += 1,
            2 => bad.parent.network ^= 1,
            3 => bad.parent.genesis[0] ^= 1,
            4 => bad.parent.fingerprint[0] ^= 1,
            5 => bad.nonce[0] ^= 1,
            6 => bad.sequence += 1,
            7 => bad.old_hardware_generation += 1,
            8 => bad.old_key_generation += 1,
            9 => bad.binding.admission.authorization.ed448[0] ^= 1,
            10 => bad.binding.admission.authorization.fndsa[0] ^= 1,
            11 => bad.binding.admission.possession.ed448[0] ^= 1,
            12 => bad.binding.admission.possession.fndsa[0] ^= 1,
            13 => bad.binding.possession.ed448[0] ^= 1,
            14 => bad.binding.possession.fndsa[0] ^= 1,
            15 => bad.native_possession[0] ^= 1,
            16 => bad.binding.admission.quote[20] ^= 1,
            17 => bad.binding.admission.node[0] ^= 1,
            18 => bad.binding.admission.hardware_generation = 1,
            19 => bad.binding.admission.key_generation = 1,
            20 => bad.old_hardware_generation = u64::MAX,
            21 => bad.old_key_generation = u64::MAX,
            _ => bad.nonce = [0; 32],
        }
        assert!(
            bad.verify(state, parent, root).is_err(),
            "hardware mutation {n}"
        );
    }
    assert!(rotation.verify(state, parent, [0; 32]).is_err());
    let mut same = rotation.clone();
    let mut same_tpm = replacement.clone();
    same_tpm.hardware = old_profile.hardware;
    sign(&mut same, &same_tpm);
    assert!(same.verify(state, parent, root).is_ok());
    // Rich trusted history checks distinguish lineage retention from hardware H.
    let mut historical = state.clone();
    let history = &mut historical.continuity.as_mut().unwrap().members[0].history;
    history.p = 8;
    history.a = 11;
    history.s = 3;
    history.h = 7;
    history.penalties = 19.into();
    for (candidate, expected_h) in [(&rotation, 0), (&same, 7)] {
        let b = crate::blocks::BlockBody {
            height: 1,
            reward_owner: [30; 32],
            fees: 0,
            transactions: vec![],
            operations: vec![candidate.encode().unwrap()],
        };
        let next = crate::continuity_lifecycle_v2::transition(
            &historical,
            parent,
            historical.root().unwrap(),
            &b,
        )
        .unwrap();
        let h = &next.registry.members[0].history;
        assert_eq!(
            (h.p, h.a, h.s, h.h, h.penalties),
            (8, 11, 3, expected_h, 19.into())
        );
    }
    // Actual encrypted Node custody signs only after canonical admission preflight.
    let mut funded = historical.clone();
    let funded_parent = FinalizedAnchor {
        height: 121,
        block: [69; 32],
        ..parent.clone()
    };
    funded.accounting.slots.period = 2;
    funded.accounting.slots.last_height = 121;
    let lot = crate::bonds_v2::Lot(crate::bonds::BondLot {
        id: [70; 32],
        node,
        lineage: node,
        owner: owner.public().address_id(1).unwrap(),
        atoms: crate::bonds::MINIMUM_ATOMS,
        created_height: 1,
        sequence: 0,
        unbond_height: None,
        settled_height: None,
        status: crate::bonds::LotStatus::Active,
        evidence: [0; 32],
    });
    funded.bonds_v2.lots.insert(lot.0.id, lot);
    funded.continuity.as_mut().unwrap().members[0].history.bonds =
        funded.bonds_v2.reputation_lots(node, 121).unwrap();
    let mut funded_rotation = rotation.clone();
    funded_rotation.parent = funded_parent.clone();
    sign(&mut funded_rotation, &replacement);
    let funded_body = crate::blocks::BlockBody {
        height: 122,
        reward_owner: [30; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![funded_rotation.encode().unwrap()],
    };
    let funded_next = crate::continuity_lifecycle_v2::transition(
        &funded,
        &funded_parent,
        funded.root().unwrap(),
        &funded_body,
    )
    .unwrap();
    assert_eq!(funded_next.bonds, funded.bonds_v2);
    assert_eq!(
        funded_next.registry.members[0].history.bonds,
        funded.continuity.as_ref().unwrap().members[0].history.bonds
    );
    assert_eq!(funded_next.registry.members[0].history.bonds[0].age.0, 1);
    assert_eq!(funded_next.registry.members[0].history.penalties, 19.into());
    assert!(funded_next.payouts.is_empty() && funded_next.burned == 0);

    let directory =
        std::env::temp_dir().join(format!("build8-hardware-custody-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("synthetic.sqlite");
    let chain = crate::canonical_store_v2::CanonicalStore::open_trusted_genesis(
        &path, parent, state, root, 1000, [255; 32],
    )
    .unwrap();
    let pins = chain.current_node_authority(parent, node).unwrap();
    let password = "synthetic hardware rotation custody only";
    let encrypted = node_key.seal_for(password, 1, &pins.context()).unwrap();
    let custody = crate::node_control_custody::EncryptedNodeKey::unlock(
        &chain, parent, node, &encrypted, password,
    )
    .unwrap();
    for mutation in 0..9 {
        let mut bad = rotation.clone();
        match mutation {
            0 => bad.binding.admission.authorization.ed448[0] ^= 1,
            1 => bad.binding.admission.authorization.fndsa[0] ^= 1,
            2 => bad.binding.admission.possession.ed448[0] ^= 1,
            3 => bad.binding.admission.possession.fndsa[0] ^= 1,
            4 => bad.binding.admission.quote[0] ^= 1,
            5 => bad.parent.block[0] ^= 1,
            6 => bad.sequence += 1,
            7 => bad.binding.admission.node[0] ^= 1,
            _ => bad.old_hardware_generation += 1,
        }
        let before = bad.clone();
        assert!(
            custody
                .authorize_hardware_rotation(&chain, &mut bad)
                .is_err()
        );
        assert!(bad == before);
    }
    let mut unsigned = rotation.clone();
    unsigned.binding.possession = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    custody
        .authorize_hardware_rotation(&chain, &mut unsigned)
        .unwrap();
    assert_eq!(unsigned.native_possession, [0; 64]);
    assert!(unsigned.verify(state, parent, root).is_err());
    let signature: Signature = native
        .sign_prehash(&unsigned.native_digest().unwrap())
        .unwrap();
    unsigned.native_possession = signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .into();
    assert!(unsigned.verify(state, parent, root).is_ok());
    drop(custody);
    drop(chain);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
    let mut reused = rotation.clone();
    sign(&mut reused, old_profile);
    assert!(matches!(
        reused.verify(state, parent, root),
        Err(Error::Duplicate)
    ));
    let mut cloud = state.clone();
    cloud.continuity.as_mut().unwrap().members[0].eligible = false;
    assert!(
        rotation
            .verify(&cloud, parent, cloud.root().unwrap())
            .is_err()
    );
    // This is a tentative pure transition, not certified installation.
    let body = crate::blocks::BlockBody {
        height: parent.height + 1,
        reward_owner: [30; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![raw.clone()],
    };
    let t = crate::continuity_lifecycle_v2::transition(state, parent, root, &body).unwrap();
    assert_eq!(t.registry.members[0].generation, 2);
    assert_eq!(t.registry.members[0].hardware, replacement.hardware);
    assert_eq!(t.registry.members[0].lineage, node);
    assert_eq!(t.membership.get(node).unwrap().sequence(), 1);
    assert_eq!(t.keys.get(node).unwrap().admission().key_generation, 2);
    assert!(!t.retired.is_empty());
    assert_eq!(
        t.registry.members[0].history,
        state.continuity.as_ref().unwrap().members[0].history
    );
    let freshness = &t.accounting.freshness[&node];
    assert!(!freshness.eligible(node, 2, freshness.key, 1));
    assert!(freshness.eligible(node, 2, freshness.key, 2));
    assert!(freshness.eligible(node, 2, freshness.key, 61));
    assert!(!freshness.eligible(node, 2, freshness.key, 62));
    let materialize = |prior: &State, t: crate::continuity_lifecycle_v2::Transition| {
        let mut post = prior.clone();
        post.accounting = t.accounting;
        post.continuity = Some(t.registry);
        post.membership_v2 = t.membership;
        post.continuity_keys_v2 = t.keys;
        post.retired_continuity_v2 = t.retired;
        post.node_key_history_v2 = t.node_history;
        post.bonds_v2 = t.bonds;
        post.penalties_v2 = t.penalties;
        assert!(t.payouts.is_empty() && t.burned == 0);
        let rows = post.records().unwrap();
        let restored = State::from_records(&rows, post.root().unwrap()).unwrap();
        assert!(restored.records().unwrap() == rows);
        restored
    };
    let post = materialize(state, t);
    // Timely signatures from G1 remain actionable after hardware G2 installs.
    let authority =
        crate::votes_v2::HeightAuthority::from_state(state, parent.clone(), root).unwrap();
    let voter = &authority.voters[&node];
    let mut vote = crate::continuity_v2::Vote {
        decision: crate::certificates::Decision {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            purpose: 2,
            height: 1,
            mining_epoch: 0,
            continuity_period: 0,
            round: 0,
            step: 3,
            previous_finalized_anchor: parent.id(),
            parent: parent.block,
            block: [65; 32],
            state: [66; 32],
            membership: authority.membership,
            reputation: authority.reputation,
            attestation: authority.attestation,
        },
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
    vote.sign(old_continuity).unwrap();
    let mut contradictory = vote.clone();
    contradictory.decision.block = [67; 32];
    contradictory.sequence = 2;
    contradictory.sign(old_continuity).unwrap();
    let evidence = crate::equivocation_v2::Evidence::new(vote, contradictory).unwrap();
    let successor_parent = FinalizedAnchor {
        height: 1,
        block: [68; 32],
        ..parent.clone()
    };
    let evidence_body = crate::blocks::BlockBody {
        height: 2,
        operations: vec![evidence.encode().unwrap()],
        ..body.clone()
    };
    let settled = crate::continuity_lifecycle_v2::transition_with_history(
        &post,
        &successor_parent,
        post.root().unwrap(),
        &evidence_body,
        &[(1, authority)].into_iter().collect(),
    )
    .unwrap();
    assert!(!settled.registry.members[0].eligible);
    assert!(settled.penalties.revoked(node));
    assert!(settled.penalties.tombstoned(node, 1));
    assert!(!settled.penalties.tombstoned(node, 2));
    assert_eq!(settled.registry.members[0].generation, 2);
    assert_eq!(
        settled.registry.members[0].history.penalties,
        post.continuity.as_ref().unwrap().members[0]
            .history
            .penalties
    );
    assert_eq!(settled.retired, post.retired_continuity_v2);
    if let Ok(path) = std::env::var("BUILD8_EXPORT_HARDWARE_STATE_V2") {
        use std::io::Write;
        let fixture = serde_json::json!({
            "synthetic_only":true,"production_authorized":false,"certified_installation":false,
            "operation":hex::encode(&raw),"root":hex::encode(post.root().unwrap()),
            "records":post.records().unwrap().iter().map(|(key,record)|
                serde_json::json!({"key":hex::encode(key),"record":hex::encode(record)})
            ).collect::<Vec<_>>(),
        });
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(serde_json::to_string_pretty(&fixture).unwrap().as_bytes())
            .unwrap();
        file.sync_all().unwrap();
    }
    let replay_parent = FinalizedAnchor {
        height: 1,
        block: [61; 32],
        ..parent.clone()
    };
    let replay = crate::blocks::BlockBody {
        height: 2,
        ..body.clone()
    };
    assert!(
        crate::continuity_lifecycle_v2::transition(
            &post,
            &replay_parent,
            post.root().unwrap(),
            &replay
        )
        .is_err()
    );
    let duplicate = crate::blocks::BlockBody {
        operations: vec![raw.clone(), raw.clone()],
        ..body.clone()
    };
    assert!(crate::continuity_lifecycle_v2::transition(state, parent, root, &duplicate).is_err());
    for operations in [
        vec![raw.clone(), software_rotation.encode().unwrap()],
        vec![software_rotation.encode().unwrap(), raw.clone()],
    ] {
        let collision = crate::blocks::BlockBody {
            operations,
            ..body.clone()
        };
        assert!(
            crate::continuity_lifecycle_v2::transition(state, parent, root, &collision).is_err()
        );
    }
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
    for operations in [
        vec![raw.clone(), exit.encode().unwrap()],
        vec![exit.encode().unwrap(), raw.clone()],
    ] {
        let conflicting = crate::blocks::BlockBody {
            operations,
            ..body.clone()
        };
        assert!(
            crate::continuity_lifecycle_v2::transition(state, parent, root, &conflicting).is_err()
        );
    }
    // Trusted synthetic parent checkpoints isolate the hardware-local boundary
    // rule. They are not a claim that every preceding slot was certified here.
    for (replacement_height, expected_h) in [(6, 1), (7, 0), (60, 0)] {
        let prior_parent = FinalizedAnchor {
            height: replacement_height - 1,
            block: [62; 32],
            ..parent.clone()
        };
        let mut prior = state.clone();
        prior.accounting.slots.last_height = prior_parent.height;
        prior
            .accounting
            .slots
            .bits
            .insert(node, (1u64 << prior_parent.height) - 1);
        prior.accounting.freshness.insert(
            node,
            crate::freshness::FreshnessRecord {
                node,
                generation: 1,
                key: crate::tpm::public_key(&old_profile.voting_public, false).unwrap(),
                committed_height: 0,
                evidence_commitment: [63; 32],
            },
        );
        let mut r = rotation.clone();
        r.parent = prior_parent.clone();
        sign(&mut r, &replacement);
        let old_native = SigningKey::from_bytes((&[10u8; 32]).into()).unwrap();
        let ack_for = |anchor: &FinalizedAnchor, generation: u64, key: &SigningKey| {
            let mut ack = crate::participation::ParticipationAck {
                network: NETWORK_ID,
                genesis: anchor.genesis,
                fingerprint: anchor.fingerprint,
                node,
                height: anchor.height + 1,
                parent: anchor.id(),
                generation,
                signature: [0; 64],
            };
            let signature: Signature = key.sign_prehash(&ack.signing_digest()).unwrap();
            ack.signature = signature
                .normalize_s()
                .unwrap_or(signature)
                .to_bytes()
                .into();
            ack.encode()
        };
        let b = crate::blocks::BlockBody {
            height: replacement_height,
            operations: vec![r.encode().unwrap(), ack_for(&prior_parent, 1, &old_native)],
            ..body.clone()
        };
        let replaced = crate::continuity_lifecycle_v2::transition(
            &prior,
            &prior_parent,
            prior.root().unwrap(),
            &b,
        )
        .unwrap();
        let mut post = materialize(&prior, replaced);
        assert_eq!(post.continuity.as_ref().unwrap().members[0].history.h, 0);
        if replacement_height < 60 {
            post.accounting.slots.last_height = 59;
            post.accounting.slots.bits.insert(node, (1u64 << 59) - 1);
            let parent59 = FinalizedAnchor {
                height: 59,
                block: [64; 32],
                ..parent.clone()
            };
            let boundary = crate::blocks::BlockBody {
                height: 60,
                operations: vec![ack_for(&parent59, 2, &native)],
                ..body.clone()
            };
            let completed = crate::continuity_lifecycle_v2::transition(
                &post,
                &parent59,
                post.root().unwrap(),
                &boundary,
            )
            .unwrap();
            post = materialize(&post, completed);
        }
        let h = &post.continuity.as_ref().unwrap().members[0].history;
        assert_eq!((h.p, h.s, h.a, h.h), (1, 1, 1, expected_h));
    }
    assert_eq!(state.root().unwrap(), root);
    qualify_certified_replacement(
        state.clone(),
        parent,
        node,
        raw.clone(),
        old_continuity,
        continuity,
        2,
    );
    println!(
        "SYNTHETIC_HARDWARE_ROTATION_TRANSITION_PASS bytes={} production=false synthetic_certified_installation=true",
        raw.len()
    );
}
