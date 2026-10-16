use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    certificates::Decision,
    equivocation::{Evidence, HistoricalAuthority, Settlement},
    recovery::{Anchor, ContinuityState, Member},
    reputation::History,
    votes::Vote,
    *,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
fn main() {
    let key = SigningKey::from_bytes((&[9; 32]).into()).unwrap();
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 59,
        block: [3; 32],
    };
    let member = Member {
        lineage: [4; 32],
        node: [5; 32],
        hardware: [6; 32],
        generation: 0,
        voting_key: key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap(),
        attestation: [7; 32],
        history: History::default(),
        physical: true,
        eligible: true,
        genesis_member: true,
    };
    let registry = ContinuityState::bootstrap(
        parent.genesis,
        parent.fingerprint,
        Anchor {
            height: 59,
            tip: parent.block,
            state_root: [8; 32],
            registry_root: [9; 32],
        },
        [10; 32],
        vec![member.clone()],
    )
    .unwrap();
    let (membership, reputation, attestation) = registry.roots().unwrap();
    let mut a = Vote {
        nil: false,
        node: member.node,
        key_version: 0,
        signature: [0; 64],
        decision: Decision {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            purpose: 2,
            height: 60,
            mining_epoch: 1,
            continuity_period: 0,
            round: 0,
            step: 2,
            previous_finalized_anchor: parent.id(),
            parent: parent.block,
            block: [11; 32],
            state: [12; 32],
            membership,
            reputation,
            attestation,
        },
    };
    let mut b = a.clone();
    b.decision.block = [13; 32];
    for vote in [&mut a, &mut b] {
        let sig: Signature = key.sign_prehash(&vote.signing_digest()).unwrap();
        vote.signature = sig.normalize_s().unwrap_or(sig).to_bytes().into();
    }
    let proof = Evidence::new(a, b).unwrap();
    proof
        .validate(
            &FinalizedAnchor {
                height: 60,
                block: [14; 32],
                ..parent.clone()
            },
            &HistoricalAuthority {
                parent: parent.clone(),
                registry: registry.clone(),
            },
        )
        .unwrap();
    let record = Settlement {
        evidence: proof.clone(),
        inclusion: 61,
        parent,
        member,
    };
    println!(
        "{}",
        serde_json::json!({"schema":"BUILD8-EQUIVOCATION-VECTORS-V1","software_fixture_only":true,"actual_genesis":false,
        "evidence":hex::encode(proof.encode().unwrap()),"evidence_id":hex::encode(proof.id()),
        "record":hex::encode(record.encode().unwrap()),"record_key":hex::encode(record.key()),
        "registry_records":registry.state_records().unwrap().iter().map(|(k,v)|[hex::encode(k),hex::encode(v)]).collect::<Vec<_>>()})
    );
}
