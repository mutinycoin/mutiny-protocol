//! Funded-parent execution fixture; no premine or real wallet access.
use ed25519_dalek::{Signer, SigningKey};
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    blocks::*,
    bond_ops::BondCreate,
    bonds::MINIMUM_ATOMS,
    execution::*,
    membership::NodeControl,
    recovery::{Anchor, ContinuityState, Member},
    reputation::History,
    transactions::*,
    *,
};
use std::collections::BTreeMap;
struct Reject;
impl freshness::PhysicalAttestationVerifier for Reject {
    fn verify(&self, _: &freshness::PhysicalMember, _: Hash, _: &[u8]) -> Result<()> {
        Err(Error::UnqualifiedPhysical)
    }
}
#[test]
fn funding_consumes_a_real_authorized_transfer_output_and_conserves_principal() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let descriptor =
        GenesisDescriptor::decode(&hex::decode(v["descriptor_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    let identity = genesis::GenesisIdentity::new(descriptor.clone()).unwrap();
    let g = identity.id();
    let fp = descriptor.fingerprint;
    let bindings: Vec<_> = v["cases"][0]["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            licenses::BindWorker::decode(&hex::decode(b["binding_hex"].as_str().unwrap()).unwrap())
                .unwrap()
        })
        .collect();
    let owner = SigningKey::from_bytes(&[61; 32]);
    let public = owner.verifying_key().to_bytes();
    let node = [5; 32];
    let lineage = [6; 32];
    let parent_anchor = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: g,
        fingerprint: fp,
        height: 1,
        block: [7; 32],
    };
    let mut create = BondCreate {
        genesis: g,
        fingerprint: fp,
        height: 2,
        parent_anchor: parent_anchor.id(),
        node,
        generation: 0,
        nonce: [8; 32],
        funding: OutPoint {
            transaction: [0; 32],
            index: 0,
        },
        owner: public,
        signature: [0; 64],
    };
    let input = OutPoint {
        transaction: [9; 32],
        index: 0,
    };
    let mut tx = Transfer {
        network: NETWORK_ID,
        genesis: g,
        fingerprint: fp,
        created_height: 2,
        expiry_height: 3,
        inputs: vec![Input {
            point: input.clone(),
            public_key: public,
            signature: [0; 64],
        }],
        outputs: vec![Output {
            owner: create.escrow_address(),
            atoms: MINIMUM_ATOMS,
        }],
    };
    tx.inputs[0].signature = owner.sign(&tx.signing_digest(0).unwrap()).to_bytes();
    create.funding.transaction = tx.id().unwrap();
    create.signature = owner.sign(&create.signing_digest()).to_bytes();
    let mut state = State {
        licenses: identity.bind_workers(&bindings).unwrap(),
        ..Default::default()
    };
    state.coins.insert(
        input.clone(),
        Coin {
            output: Output {
                owner: address(&public),
                atoms: MINIMUM_ATOMS + 1000,
            },
            created_height: 1,
            coinbase: false,
        },
    );
    state.membership.controls.insert(
        node,
        NodeControl {
            node,
            generation: 0,
            owner: public,
            node_authentication: public,
            sequence: 0,
            exit_boundary: None,
            admitted_height: 0,
            admission_boundary: None,
            hardware_since_height: 0,
        },
    );
    state.continuity = Some(
        ContinuityState::bootstrap(
            g,
            fp,
            Anchor {
                height: 1,
                tip: parent_anchor.block,
                state_root: [0; 32],
                registry_root: [0; 32],
            },
            descriptor.recovery,
            vec![Member {
                lineage,
                node,
                hardware: [10; 32],
                generation: 0,
                voting_key: p256::ecdsa::SigningKey::from_bytes((&[11; 32]).into())
                    .unwrap()
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                attestation: [12; 32],
                history: History::default(),
                physical: true,
                eligible: true,
                genesis_member: true,
            }],
        )
        .unwrap(),
    );
    state.accounting.slots.last_height = 1;
    let body = BlockBody {
        height: 2,
        reward_owner: descriptor.owner,
        fees: 1000,
        transactions: vec![tx.encode().unwrap()],
        operations: vec![create.encode()],
    };
    let parent = WorkParent {
        genesis: g,
        fingerprint: fp,
        block: parent_anchor.block,
        height: 1,
        t0: descriptor.timestamp,
        target: [255; 32],
        ancestor_timestamps: vec![descriptor.timestamp],
    };
    let candidate = pow::Candidate {
        network: NETWORK_ID,
        genesis: g,
        fingerprint: fp,
        parent: parent.block,
        height: 2,
        timestamp: descriptor.timestamp + 120,
        body_root: body.root().unwrap(),
        state_root: [0; 32],
        license: bindings[0].license,
        worker: bindings[0].worker,
        target: parent.target,
    };
    let before = state.root().unwrap();
    let execute = |b: &BlockBody| {
        let mut c = candidate.clone();
        c.body_root = b.root().unwrap();
        state.prepare_candidate(
            CandidatePreparation {
                parent: &parent,
                candidate: &c,
                ticket_sequence: 1,
                body: b,
            },
            &BTreeMap::new(),
            &Reject,
        )
    };
    let next = execute(&body).unwrap().state;
    assert_eq!(state.root().unwrap(), before);
    assert!(!next.coins.contains_key(&input));
    assert!(!next.coins.contains_key(&create.funding));
    assert_eq!(next.bonds.lots[&create.lot_id()].atoms, MINIMUM_ATOMS);
    assert_eq!(next.bonds.lots[&create.lot_id()].lineage, lineage);
    assert_eq!(
        next.coins.values().map(|c| c.output.atoms).sum::<u64>()
            + next.bonds.lots.values().map(|l| l.atoms).sum::<u64>(),
        MINIMUM_ATOMS + 1000 + SUBSIDY
    );
    assert_eq!(
        next.continuity.as_ref().unwrap().members[0].history.bonds[0].atoms,
        MINIMUM_ATOMS
    );
    let restored = State::from_records(&next.records().unwrap(), next.root().unwrap()).unwrap();
    assert_eq!(restored.records().unwrap(), next.records().unwrap());
    assert_eq!(restored.bonds, next.bonds);
    for field in 0..5 {
        let mut bad = create.clone();
        match field {
            0 => bad.owner = SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes(),
            1 => bad.generation += 1,
            2 => bad.funding.index = 1,
            3 => bad.nonce[0] ^= 1,
            _ => bad.signature[0] ^= 1,
        }
        if field < 4 {
            bad.signature = owner.sign(&bad.signing_digest()).to_bytes();
        }
        let mut b = body.clone();
        b.operations = vec![bad.encode()];
        assert!(execute(&b).is_err());
        assert_eq!(state.root().unwrap(), before);
    }
}
