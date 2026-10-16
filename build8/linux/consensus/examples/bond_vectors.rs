use ed25519_dalek::{Signer, SigningKey};
use mutiny_consensus_v8::{
    NETWORK_ID, anchors::FinalizedAnchor, bond_ops::*, bonds::*, transactions::OutPoint,
};
fn main() {
    let owner = SigningKey::from_bytes(&[61; 32]);
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 59,
        block: [3; 32],
    };
    let mut create = BondCreate {
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        height: 60,
        parent_anchor: parent.id(),
        node: [5; 32],
        generation: 0,
        nonce: [6; 32],
        funding: OutPoint {
            transaction: [7; 32],
            index: 0,
        },
        owner: owner.verifying_key().to_bytes(),
        signature: [0; 64],
    };
    create.signature = owner.sign(&create.signing_digest()).to_bytes();
    let active = BondLot {
        id: create.lot_id(),
        node: create.node,
        lineage: create.node,
        owner: create.owner,
        atoms: MINIMUM_ATOMS,
        created_height: 60,
        sequence: 0,
        unbond_height: None,
        settled_height: None,
        status: LotStatus::Active,
        evidence: [0; 32],
    };
    let u = 60 + LOCK_HEIGHTS;
    let mut command = BondCommand {
        kind: 19,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        height: u,
        parent_anchor: FinalizedAnchor {
            height: u - 1,
            ..parent.clone()
        }
        .id(),
        lot: active.id,
        sequence: 1,
        owner: create.owner,
        signature: [0; 64],
    };
    command.signature = owner.sign(&command.signing_digest().unwrap()).to_bytes();
    let mut notice = active.clone();
    notice.start_unbond(u, 1).unwrap();
    let h = u + EVIDENCE_HEIGHTS;
    let mut withdraw = BondCommand {
        kind: 20,
        height: h,
        parent_anchor: FinalizedAnchor {
            height: h - 1,
            ..parent
        }
        .id(),
        sequence: 2,
        ..command.clone()
    };
    withdraw.signature = owner.sign(&withdraw.signing_digest().unwrap()).to_bytes();
    let mut paid = notice.clone();
    paid.withdraw(h, 2).unwrap();
    let mut burned = BondBook {
        lots: [(notice.id, notice.clone())].into_iter().collect(),
    };
    burned.burn_exposed(create.node, u, h, [9; 32]).unwrap();
    println!(
        "{}",
        serde_json::json!({"schema":"BUILD8-BOND-VECTORS-V2","actual_genesis":false,"fixture_owner_only":true,
        "create":hex::encode(create.encode()),"create_digest":hex::encode(create.signing_digest()),
        "lot_id":hex::encode(create.lot_id()),"escrow":hex::encode(create.escrow_address()),
        "unbond":hex::encode(command.encode().unwrap()),"withdraw":hex::encode(withdraw.encode().unwrap()),
        "payout_id":hex::encode(withdraw.payout_id().unwrap()),
        "active":hex::encode(active.encode().unwrap()),"notice":hex::encode(notice.encode().unwrap()),
        "paid":hex::encode(paid.encode().unwrap()),"burned":hex::encode(burned.lots[&notice.id].encode().unwrap())})
    );
}
