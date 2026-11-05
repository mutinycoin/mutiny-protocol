use ed25519_dalek::{Signer, SigningKey};
use mutiny_consensus_v8::{blocks::*, execution::*, genesis::*, licenses::*, pow::*};
use serde_json::Value;
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn bindings(v: &Value) -> Vec<BindWorker> {
    v["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| BindWorker::decode(&bytes(&b["binding_hex"])).unwrap())
        .collect()
}
fn sign(b: &mut BindWorker, worker_seed: u8) {
    b.owner_signature = SigningKey::from_bytes(&[80; 32])
        .sign(&b.signing_digest(false))
        .to_bytes();
    b.worker_signature = SigningKey::from_bytes(&[worker_seed; 32])
        .sign(&b.signing_digest(true))
        .to_bytes();
}
#[test]
fn independent_two_phase_vectors_and_height_one_work_execution() {
    let v = vectors();
    let descriptor = GenesisDescriptor::decode(&bytes(&v["descriptor_hex"])).unwrap();
    let identity = GenesisIdentity::new(descriptor.clone()).unwrap();
    assert_eq!(hex::encode(identity.id()), v["genesis_id"]);
    assert_eq!(identity.bytes(), bytes(&v["descriptor_hex"]));
    let mut roots = Vec::new();
    for case in v["cases"].as_array().unwrap() {
        let book = identity.bind_workers(&bindings(case)).unwrap();
        assert_eq!(book.licenses.len(), 12);
        assert_eq!(book.workers.len(), 12);
        assert!(book.pending.is_empty());
        let raw = state_bytes(&book.records().unwrap().into_iter().collect::<Vec<_>>()).unwrap();
        assert_eq!(raw, bytes(&case["state_bytes_hex"]));
        let state = State {
            licenses: book,
            ..State::default()
        };
        assert!(state.coins.is_empty());
        let root = state.root().unwrap();
        assert_eq!(
            State::from_records(&state.records().unwrap(), root).unwrap(),
            state
        );
        roots.push(root);
        assert_eq!(hex::encode(root), case["state_root"]);
        assert_eq!(
            descriptor.block(root).unwrap(),
            bytes(&case["genesis_block_hex"])
        );
        let block_hash = descriptor.block_hash(root).unwrap();
        assert_eq!(hex::encode(block_hash), case["genesis_block_hash"]);
        let anchor = mutiny_consensus_v8::anchors::FinalizedAnchor {
            network: mutiny_consensus_v8::NETWORK_ID,
            genesis: identity.id(),
            fingerprint: descriptor.fingerprint,
            height: 0,
            block: block_hash,
        };
        assert_eq!(hex::encode(anchor.id()), case["finalized_anchor_id"]);
        assert_eq!(identity.id(), descriptor.id().unwrap());
        if let Some(work) = case.get("height1") {
            let body = BlockBody::decode(&bytes(&work["body_hex"])).unwrap();
            let header = WorkHeader::decode(&bytes(&work["header_hex"])).unwrap();
            let (authority, signature) =
                WorkAuthority::from_envelope(&bytes(&work["authority_envelope_hex"])).unwrap();
            assert_eq!(header.work_bytes().len(), 350); // qualified length unchanged
            assert!(meets_target(&header.digest(), &header.candidate.target));
            assert_eq!(hex::encode(header.digest()), work["pow_digest"]);
            assert_eq!(hex::encode(header.block_hash()), work["block_hash"]);
            let parent = WorkParent {
                genesis: identity.id(),
                fingerprint: descriptor.fingerprint,
                block: block_hash,
                height: 0,
                t0: descriptor.timestamp,
                target: header.candidate.target,
                ancestor_timestamps: vec![descriptor.timestamp],
            };
            let executed = state
                .execute_licensed(&parent, &header, &authority, &signature, &body)
                .unwrap();
            assert_eq!(hex::encode(executed.root), work["post_state_root"]);
            assert_eq!(hex::encode(executed.coinbase_id), work["coinbase_id"]);
            assert_eq!(executed.state.coins.len(), 1);
            assert_eq!(
                State::from_records(&executed.state.records().unwrap(), executed.root).unwrap(),
                executed.state
            );
            assert_eq!(
                executed.state.coins.values().next().unwrap().output.atoms,
                100_000_000
            );
            let mut unassigned = state.clone();
            unassigned
                .licenses
                .licenses
                .get_mut(&header.candidate.license)
                .unwrap()
                .active_worker = None;
            assert!(
                unassigned
                    .execute_licensed(&parent, &header, &authority, &signature, &body)
                    .is_err()
            );
        }
    }
    assert_ne!(roots[0], roots[1]);
    let mut changed = descriptor.clone();
    changed.timestamp += 1;
    assert!(identity.verify_unchanged(&changed).is_err());
    identity.verify_unchanged(&descriptor).unwrap();
}
#[test]
fn genesis_rejects_missing_duplicate_replayed_or_unauthorized_bindings() {
    let v = vectors();
    let identity =
        GenesisIdentity::new(GenesisDescriptor::decode(&bytes(&v["descriptor_hex"])).unwrap())
            .unwrap();
    let good = bindings(&v["cases"][0]);
    assert!(identity.bind_workers(&good[..11]).is_err());
    for mutation in 0..9 {
        let mut bad = good.clone();
        match mutation {
            0 => {
                bad[0].genesis[0] ^= 1;
                sign(&mut bad[0], 10);
            }
            1 => {
                bad[0].worker[0] ^= 1;
                sign(&mut bad[0], 10);
            }
            2 => {
                bad[0].license[0] ^= 1;
                sign(&mut bad[0], 10);
            }
            3 => bad[0].owner_signature[0] ^= 1,
            4 => bad[0].worker_signature[0] ^= 1,
            5 => bad[1] = bad[0].clone(),
            6 => {
                bad[1].worker_public = bad[0].worker_public;
                bad[1].worker = bad[1].worker_id();
                sign(&mut bad[1], 10);
            }
            7 => {
                bad[0].sequence = 0;
                sign(&mut bad[0], 10);
            }
            8 => {
                bad[0].effective_epoch = 1;
                sign(&mut bad[0], 10);
            }
            _ => unreachable!(),
        }
        assert!(identity.bind_workers(&bad).is_err(), "mutation {mutation}");
    }
    let mut reversed = good.clone();
    reversed.reverse();
    assert_eq!(
        identity.bind_workers(&good).unwrap(),
        identity.bind_workers(&reversed).unwrap()
    );
}
