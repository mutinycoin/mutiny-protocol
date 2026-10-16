use ed25519_dalek::{Signer, SigningKey};
use mutiny_consensus_v8::{Hash, NETWORK_ID, blocks::*, pow::*};
use serde_json::Value;
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../qualification/CANONICAL-WORK-VECTORS-STATE-V2.json"
    ))
    .unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn hash(v: &Value) -> Hash {
    bytes(v).try_into().unwrap()
}
#[test]
fn python_rust_exact_bytes_hashes_offsets_and_targets() {
    assert_exact_work_vectors(fixture());
}
#[test]
fn derived_fleet_target_vectors_match_rust_and_python() {
    let f: Value = serde_json::from_str(include_str!(
        "../../qualification/DERIVED-TARGET-WORK-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let derivation: Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-DIFFICULTY-DERIVATION.json"
    ))
    .unwrap();
    assert_eq!(
        f["vectors"][1]["fields"]["target"],
        derivation["derivation"]["initial_pow_target_hex"]
    );
    assert_exact_work_vectors(f.clone());
    assert_genesis_fixture(f);
}
fn assert_exact_work_vectors(f: Value) {
    for v in f["vectors"].as_array().unwrap() {
        let raw = bytes(&v["cbor_hex"]);
        let h = WorkHeader::decode(&raw).unwrap();
        assert_eq!(h.encode(), raw);
        assert_eq!(h.work_bytes(), bytes(&v["work_hex"]));
        assert_eq!(h.digest(), hash(&v["digest"]));
        assert_eq!(h.block_hash(), hash(&v["block_hash"]));
        assert_eq!(
            h.nonce_offset(),
            v["nonce_offset"].as_u64().unwrap() as usize
        );
        assert_eq!(
            meets_target(&h.digest(), &h.candidate.target),
            v["meets_target"].as_bool().unwrap()
        );
        let mut d = minicbor::Decoder::new(&raw);
        d.array().unwrap();
        for off in v["field_offsets"].as_array().unwrap() {
            assert_eq!(
                d.position() + WORK_DOMAIN.len() + 1,
                off["encoded_offset"].as_u64().unwrap() as usize
            );
            d.skip().unwrap();
        }
        let a = WorkAuthority::decode(&bytes(&v["authority_hex"])).unwrap();
        assert_eq!(a.id(), hash(&v["authority_id"]));
        let (decoded, sig) = WorkAuthority::from_envelope(&bytes(&v["envelope_hex"])).unwrap();
        assert_eq!(decoded, a);
        assert_eq!(sig.as_slice(), bytes(&v["signature"]));
        let body = BlockBody::decode(&bytes(&v["body_hex"])).unwrap();
        if h.candidate.network == NETWORK_ID {
            assert_eq!(body.root().unwrap(), h.candidate.body_root);
        }
    }
    for e in f["target_edges"].as_array().unwrap() {
        assert_eq!(
            meets_target(&hash(&e["hash"]), &hash(&e["target"])),
            e["valid"].as_bool().unwrap()
        );
    }
    assert!(!meets_target(&[0; 32], &[0; 32]));
}
#[test]
fn retarget_vectors_wide_math_and_boundary_heights() {
    let f = fixture();
    for v in f["retarget"].as_array().unwrap() {
        assert_eq!(
            retarget(
                hash(&v["old"]),
                v["start"].as_u64().unwrap(),
                v["end"].as_u64().unwrap()
            )
            .unwrap(),
            hash(&v["next"]),
            "{}",
            v["name"]
        );
    }
    let mut target = [0; 32];
    target[30] = 0x10;
    for h in [0, 1, 2, 10, 11, 59, 60, 61, 120, 121] {
        let actual = target_after_height(h, target, 0, 14400).unwrap();
        if h == 60 || h == 120 {
            assert_eq!(actual, retarget(target, 0, 14400).unwrap());
        } else {
            assert_eq!(actual, target);
        }
    }
    assert!(retarget([0; 32], 0, 3600).is_err());
}
#[test]
fn epoch_mtp_and_early_chain_rules_are_distinct() {
    let t0 = 1800000000;
    for h in [0, 1, 2, 10, 11, 59, 60, 61, 120, 121] {
        let ancestors: Vec<u64> = (h - h.min(11)..h).map(|x| t0 + x * 60).collect();
        assert!(validate_timestamp(h, t0 + h * 60, t0, &ancestors).is_ok());
        if h > 0 {
            assert!(validate_timestamp(h, t0, t0, &ancestors).is_err());
            assert!(validate_timestamp(h, t0 + h * 60, t0, &[]).is_err());
        }
    }
    assert_eq!(mining_epoch(t0 + 59, t0).unwrap(), 0);
    assert_eq!(mining_epoch(t0 + 60, t0).unwrap(), 1);
    assert!(mining_epoch(t0 - 1, t0).is_err());
    // Even-count median is the upper item, without averaging or float arithmetic.
    assert!(validate_timestamp(2, t0 + 60, t0, &[t0, t0 + 60]).is_err());
    assert!(validate_timestamp(2, t0 + 61, t0, &[t0, t0 + 60]).is_ok());
    // No wall-clock bound exists in either direction: far-future and far-past (relative to any
    // receiver clock) timestamps are judged only by the deterministic rules.
    assert!(validate_timestamp(1, t0 + 9000, t0, &[t0]).is_ok());
    assert!(validate_timestamp(1, t0 + 86_400 * 365, t0, &[t0]).is_ok());
}
#[test]
fn window_must_end_at_the_actual_parent_or_the_store_fails_closed() {
    let t0 = 1_800_000_000u64;
    let parent = t0 + 540;
    let window: Vec<u64> = (0..10).map(|x| t0 + x * 60).collect();
    // Window order does not matter: newest-first, oldest-first and rotated all end at the parent.
    let mut reversed = window.clone();
    reversed.reverse();
    let mut rotated = window.clone();
    rotated.rotate_left(3);
    for w in [&window, &reversed, &rotated] {
        assert!(window_ends_at_parent(w, parent));
    }
    // A descendant row inside the window (its maximum exceeds the parent) is rejected.
    let mut with_descendant = window.clone();
    with_descendant.push(parent + 60);
    assert!(!window_ends_at_parent(&with_descendant, parent));
    // The parent row missing from the window (a hole, or a wrong parent) is rejected.
    let without_parent: Vec<u64> = window[..9].to_vec();
    assert!(!window_ends_at_parent(&without_parent, parent));
    // A chain containing a regressing timestamp (the parent is earlier than a prior block) is not
    // a chain built under the rule: the equivalence is not claimed and the window is rejected.
    let regressing = vec![t0, t0 + 600, t0 + 300];
    assert!(!window_ends_at_parent(&regressing, t0 + 300));
    // An empty window never ends at a parent.
    assert!(!window_ends_at_parent(&[], parent));
    // Equal timestamps are fine: the parent is still the maximum.
    assert!(window_ends_at_parent(&[t0, t0 + 60, t0 + 60], t0 + 60));
}
#[test]
fn timestamp_must_not_precede_parent_and_window_order_is_irrelevant() {
    let t0 = 1_800_000_000u64;
    // Parent (newest) is 1000 s ahead of the rest of the window, so the median stays low and a
    // timestamp can be above the median yet before the parent: only the parent rule rejects it.
    let mut window: Vec<u64> = (0..10).map(|x| t0 + x * 60).collect();
    window.push(t0 + 1000);
    let parent = *window.iter().max().unwrap();
    let mut sorted = window.clone();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2];
    assert!(parent > median + 400, "fixture must separate parent from median");
    let before_parent = parent - 1;
    assert!(before_parent > median);
    // Same window in every order must give the same answer (producers order it differently).
    let orders: [Vec<u64>; 3] = [
        window.clone(),
        window.iter().rev().copied().collect(),
        {
            let mut w = window.clone();
            w.rotate_left(4);
            w
        },
    ];
    for w in &orders {
        assert!(validate_timestamp(11, before_parent, t0, w).is_err(), "earlier than parent");
        assert!(validate_timestamp(11, parent, t0, w).is_ok(), "equal to parent is allowed");
        assert!(validate_timestamp(11, parent + 1, t0, w).is_ok());
        // Median-time-past is retained and independent: at or below the median still fails.
        assert!(validate_timestamp(11, median, t0, w).is_err());
        assert!(validate_timestamp(11, median + 1, t0, w).is_err(), "above median, before parent");
    }
    // Early chain (window shorter than 11): heights 1..=10.
    for h in 1..=10u64 {
        let w: Vec<u64> = (0..h).map(|x| t0 + x * 60).collect();
        let parent = *w.last().unwrap();
        // Equal to the parent satisfies the parent rule; whether it passes overall is then the
        // median-time-past rule alone (parent must exceed the upper-middle item).
        assert_eq!(
            validate_timestamp(h, parent, t0, &w).is_ok(),
            parent > t0 + (h / 2) * 60
        );
        assert!(validate_timestamp(h, parent + 1, t0, &w).is_ok());
        assert!(validate_timestamp(h, parent - 1, t0, &w).is_err());
    }
    // Under the rules, a chain's newest window item is always its maximum, so "window maximum"
    // is exactly "the parent's timestamp" for every chain produced by these rules.
    let mut chain = vec![t0];
    let mut seed = 0x9e3779b97f4a7c15u64;
    for h in 1..400u64 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = chain.len().saturating_sub(11);
        let w = &chain[lo..];
        let parent = *chain.last().unwrap();
        let mut s = w.to_vec();
        s.sort_unstable();
        let floor = parent.max(s[s.len() / 2] + 1);
        let ts = floor + (seed >> 60); // 0..=15 s past the floor, ties with the parent included
        assert!(validate_timestamp(h, ts, t0, w).is_ok(), "height {h}");
        assert_eq!(*w.iter().max().unwrap(), parent, "newest is the maximum at height {h}");
        chain.push(ts);
    }
}
fn setup() -> (WorkHeader, WorkAuthority, WorkContext, SigningKey) {
    let f = fixture();
    let v = &f["vectors"][1];
    let h = WorkHeader::decode(&bytes(&v["cbor_hex"])).unwrap();
    let a = WorkAuthority::decode(&bytes(&v["authority_hex"])).unwrap();
    let c = &h.candidate;
    let ctx = WorkContext {
        genesis: c.genesis,
        fingerprint: c.fingerprint,
        parent: c.parent,
        parent_height: 0,
        t0: f["genesis"]["timestamp"].as_u64().unwrap(),
        target: c.target,
        license: c.license,
        worker: c.worker,
        coordinator: a.coordinator,
        assignment_sequence: 1,
        last_accepted_ticket: 0,
        ancestor_timestamps: vec![f["genesis"]["timestamp"].as_u64().unwrap()],
    };
    (h, a, ctx, SigningKey::from_bytes(&[42; 32]))
}
#[test]
fn block_envelope_binds_body_work_and_commit_without_claiming_state_execution() {
    use mutiny_consensus_v8::{block_envelope::BlockEnvelope, certificates::*};
    use p256::ecdsa::{
        Signature as P256Signature, SigningKey as P256Key, signature::hazmat::PrehashSigner,
    };
    use primitive_types::U256;
    use std::collections::BTreeMap;
    let (mut header, authority, context, coordinator) = setup();
    while !meets_target(&header.digest(), &header.candidate.target) {
        header.nonce = header.nonce.checked_add(1).unwrap();
    }
    let f = fixture();
    let body = BlockBody::decode(&bytes(&f["vectors"][1]["body_hex"])).unwrap();
    let owner = body.reward_owner;
    let decision = Decision {
        network: NETWORK_ID,
        genesis: context.genesis,
        fingerprint: context.fingerprint,
        purpose: 2,
        height: 1,
        mining_epoch: 1,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: mutiny_consensus_v8::anchors::FinalizedAnchor {
            network: NETWORK_ID,
            genesis: context.genesis,
            fingerprint: context.fingerprint,
            height: 0,
            block: context.parent,
        }
        .id(),
        parent: context.parent,
        block: header.block_hash(),
        state: header.candidate.state_root,
        membership: [7; 32],
        reputation: [8; 32],
        attestation: [9; 32],
    };
    let key = P256Key::from_bytes((&[1; 32]).into()).unwrap();
    let signature: P256Signature = key
        .sign_prehash(&decision.signing_digest([1; 32], 1))
        .unwrap();
    let signature = signature.normalize_s().unwrap_or(signature);
    let registry = BTreeMap::from([(
        [1; 32],
        Voter {
            key_version: 1,
            weight: U256::one(),
            public_key: key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
        },
    )]);
    let envelope = BlockEnvelope {
        header,
        body,
        authority_signature: coordinator.sign(&authority.id()).to_bytes(),
        authority,
        certificate: Certificate {
            decision: decision.clone(),
            signers: vec![mutiny_consensus_v8::certificates::Signer {
                node: [1; 32],
                key_version: 1,
                signature: signature.to_bytes().into(),
            }],
        },
    };
    let raw = envelope.encode().unwrap();
    assert_eq!(BlockEnvelope::decode(&raw).unwrap(), envelope);
    envelope
        .verify_evidence(&context, owner, &decision, &registry)
        .unwrap();
    for length in [0, 1, raw.len() - 1] {
        assert!(BlockEnvelope::decode(&raw[..length]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(BlockEnvelope::decode(&trailing).is_err());
    let mut bad = envelope.clone();
    bad.body.reward_owner[0] ^= 1;
    assert!(
        bad.verify_evidence(&context, owner, &decision, &registry)
            .is_err()
    );
    let mut bad = envelope.clone();
    bad.header.nonce ^= 1;
    assert!(
        bad.verify_evidence(&context, owner, &decision, &registry)
            .is_err()
    );
    let mut bad = envelope.clone();
    bad.authority_signature[0] ^= 1;
    assert!(
        bad.verify_evidence(&context, owner, &decision, &registry)
            .is_err()
    );
    let mut bad = envelope.clone();
    bad.certificate.signers[0].signature[0] ^= 1;
    assert_eq!(bad.block_hash(), envelope.block_hash());
    assert!(
        bad.verify_evidence(&context, owner, &decision, &registry)
            .is_err()
    );
    let mut wrong = decision.clone();
    wrong.state[0] ^= 1;
    assert!(
        envelope
            .verify_evidence(&context, owner, &wrong, &registry)
            .is_err()
    );
}
#[test]
fn signed_authority_rejects_wrong_bindings_expiry_and_replays() {
    let (h, a, ctx, key) = setup();
    let s = key.sign(&a.id()).to_bytes();
    assert!(validate_authority(&h, &a, &s, &ctx).is_ok());
    for n in 0..14 {
        let mut bad = a.clone();
        match n {
            0 => bad.candidate.network ^= 1,
            1 => bad.candidate.genesis[0] ^= 1,
            2 => bad.candidate.fingerprint[0] ^= 1,
            3 => bad.candidate.worker[0] ^= 1,
            4 => bad.candidate.license[0] ^= 1,
            5 => bad.candidate.parent[0] ^= 1,
            6 => bad.epoch += 1,
            7 => bad.candidate.timestamp += 60,
            8 => bad.assignment_sequence += 1,
            9 => bad.ticket_sequence = 0,
            10 => bad.candidate.height = 0,
            11 => bad.coordinator[0] ^= 1,
            12 => bad.nonce_start = 1,
            13 => bad.candidate.target[0] ^= 1,
            _ => unreachable!(),
        }
        let mut bh = h.clone();
        bh.candidate = bad.candidate.clone();
        bh.authority = bad.id();
        let bs = key.sign(&bad.id()).to_bytes();
        assert!(
            validate_authority(&bh, &bad, &bs, &ctx).is_err(),
            "case {n}"
        );
    }
    let mut altered = h.clone();
    altered.candidate.body_root[0] ^= 1;
    assert!(validate_authority(&altered, &a, &s, &ctx).is_err());
    let mut altered = h.clone();
    altered.candidate.timestamp += 1;
    assert!(validate_authority(&altered, &a, &s, &ctx).is_err());
    let mut bad_sig = s;
    bad_sig[0] ^= 1;
    assert!(validate_authority(&h, &a, &bad_sig, &ctx).is_err());
    let mut exhausted = h;
    exhausted.nonce = u64::MAX;
    assert_eq!(exhausted.next_nonce(u64::MAX), None);
}
#[test]
fn canonical_decoder_and_body_negative_cases() {
    let (h, _, _, _) = setup();
    let raw = h.encode();
    for len in 0..raw.len() {
        assert!(WorkHeader::decode(&raw[..len]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(WorkHeader::decode(&trailing).is_err());
    let mut nonminimal = raw.clone();
    nonminimal.splice(1..2, [0x18, 0x01]);
    assert!(WorkHeader::decode(&nonminimal).is_err());
    for v in [
        vec![0xbf, 0xff],
        vec![0x9f, 0xff],
        vec![0xf9, 0, 0],
        vec![0x18, 1],
        vec![0, 0],
    ] {
        assert!(canonical(&v, 65536).is_err());
    }
    let mut b = BlockBody {
        height: 1,
        reward_owner: [0; 32],
        fees: 0,
        transactions: vec![vec![0x81, 1]],
        operations: vec![],
    };
    let root = b.root().unwrap();
    b.transactions.push(vec![0x81, 2]);
    assert_ne!(root, b.root().unwrap());
    b.transactions.push(vec![0x81, 1]);
    assert!(b.encode().is_err());
    b.transactions.clear();
    b.height = 0;
    assert!(b.encode().is_err());
}
#[test]
fn genesis_derivation_is_acyclic_and_matches_python() {
    assert_genesis_fixture(fixture());
}
fn assert_genesis_fixture(f: Value) {
    let g = &f["genesis"];
    let d = GenesisDescriptor {
        timestamp: g["timestamp"].as_u64().unwrap(),
        nonce: [11; 32],
        fingerprint: hash(&g["fingerprint"]),
        owner: hash(&g["owner"]),
        purchase: [12; 32],
        parameters: bytes(&g["parameters_hex"]),
        admission_records: g["admissions_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect(),
        recovery: [13; 32],
    };
    assert_eq!(d.encode().unwrap(), bytes(&g["descriptor_hex"]));
    assert_eq!(GenesisDescriptor::decode(&d.encode().unwrap()).unwrap(), d);
    assert_eq!(d.id().unwrap(), hash(&g["genesis_id"]));
    let records: Vec<_> = g["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (hash(&r["key"]), bytes(&r["value"])))
        .collect();
    assert_eq!(state_bytes(&records).unwrap(), bytes(&g["state_hex"]));
    assert_eq!(state_root(&records).unwrap(), hash(&g["state_root"]));
    assert_eq!(
        d.block(hash(&g["state_root"])).unwrap(),
        bytes(&g["block_hex"])
    );
    assert_eq!(
        d.block_hash(hash(&g["state_root"])).unwrap(),
        hash(&g["block_hash"])
    );
    for i in 0..12 {
        assert_eq!(
            genesis_license(d.id().unwrap(), i).unwrap(),
            hash(&g["license_ids"][i as usize])
        );
    }
    assert!(genesis_license(d.id().unwrap(), 12).is_err());
    // Changing state changes GenesisBlockHash, not the descriptor-derived GenesisID.
    assert_ne!(d.block_hash([0; 32]).unwrap(), hash(&g["block_hash"]));
    let mut reversed = records.clone();
    reversed.reverse();
    assert!(state_root(&reversed).is_err());
}
