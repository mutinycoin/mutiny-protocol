//! Hybrid bond commands (body version 3, Lane P design 5.1) and the funded BondCreate wire form
//! (operation kind 24, design 2.2) through the public library API. Synthetic public BIP39 fixture
//! keys only; TEST-VALUE. Generator of `qualification/hybrid-bond-public-v1.json`
//! (`BUILD8_EXPORT_HYBRID_BOND=1`; it refuses to overwrite).
use mutiny_consensus_v8::{
    Error, NETWORK_ID,
    anchors::FinalizedAnchor,
    bond_create_v3::{BondError, FundedBondCreate, UnsignedBondCreate},
    bond_ops_v2::{Action, Operation},
    bonds::{BondLot, EVIDENCE_HEIGHTS, LOCK_HEIGHTS, LotStatus, MINIMUM_ATOMS},
    bonds_v2::{Book, Lot},
    evidence_history_v2::History,
    execution::State,
    op_envelope_v1::{Envelope, EnvelopeError, Precondition},
    transactions::{OutPoint, Output},
    wallet_authority_v1::WalletBook,
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, Role};
fn empty() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}
fn parent(height: u64) -> FinalizedAnchor {
    FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height,
        block: [3; 32],
    }
}
/// The single-height window of the block after `p`, referencing `p` itself.
fn window(p: &FinalizedAnchor) -> Envelope {
    Envelope {
        first_height: p.height + 1,
        last_height: p.height + 1,
        reference_height: p.height,
        reference_block: p.block,
        preconditions: vec![],
    }
}
#[test]
fn hybrid_bond_authorization_rotation_domains_and_wire_rejections() {
    let owner =
        HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let next = HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner)
        .unwrap();
    let mut wallets = WalletBook::default();
    let address = wallets
        .register(&owner.public().descriptor(1).unwrap())
        .unwrap();
    let history = History::default();
    let p = parent(LOCK_HEIGHTS);
    let h = p.height + 1;
    let lot = Lot(BondLot {
        id: [4; 32],
        node: [5; 32],
        lineage: [5; 32],
        owner: address,
        atoms: MINIMUM_ATOMS,
        created_height: 1,
        sequence: 0,
        unbond_height: None,
        settled_height: None,
        status: LotStatus::Active,
        evidence: [0; 32],
    });
    let mut op = Operation {
        genesis: p.genesis,
        fingerprint: p.fingerprint,
        envelope: window(&p),
        owner: address,
        authorizer: owner.public().descriptor(1).unwrap(),
        action: Action::Unbond {
            lot: lot.0.id,
            sequence: 1,
        },
        signature: empty(),
    };
    op.sign(&owner).unwrap();
    op.verify_command(&p, &history, &wallets, &lot).unwrap();
    // AM-1(d): the stateless and the state-only halves separately.
    op.verify_signatures().unwrap();
    op.verify_state(&p, &history, &wallets, &lot).unwrap();
    let mut forged = op.clone();
    forged.signature.ed448[0] ^= 1;
    forged.verify_state(&p, &history, &wallets, &lot).unwrap();
    assert_eq!(forged.verify_signatures(), Err(Error::BadSignature));
    assert_eq!(
        op.signing_intent().unwrap().domain,
        Domain::BondUnbond,
        "the command signs its own unsigned body under its own domain"
    );
    assert_eq!(op.signing_intent().unwrap().payload, op.body().unwrap());
    let raw = op.encode().unwrap();
    assert!(raw.len() <= 4096, "the existing 4096-byte command bound holds with the envelope");
    assert_eq!(Operation::decode(&raw).unwrap(), op);
    for n in 0..raw.len() {
        assert!(Operation::decode(&raw[..n]).is_err());
    }
    let mut badraw = raw.clone();
    badraw.push(0);
    assert!(Operation::decode(&badraw).is_err());
    // Each field is bound: the exact refusal, with the cheap context checks before the signature.
    for field in 0..13 {
        let mut bad = op.clone();
        let expected = match field {
            0 => {
                bad.genesis[0] ^= 1;
                Error::WrongGenesis
            }
            1 => {
                bad.fingerprint[0] ^= 1;
                Error::WrongFingerprint
            }
            2 => {
                bad.envelope.last_height += 1;
                Error::BadSignature
            }
            3 => {
                bad.envelope.reference_block[0] ^= 1;
                Error::Envelope(EnvelopeError::ReferenceNotCanonical)
            }
            4 => {
                bad.owner[0] ^= 1;
                Error::WrongGeneration
            }
            5 => {
                bad.authorizer = next.public().descriptor(1).unwrap();
                Error::WrongGeneration
            }
            6 => {
                bad.signature.ed448[0] ^= 1;
                Error::BadSignature
            }
            7 => {
                bad.signature.fndsa[500] ^= 1;
                Error::BadSignature
            }
            8 => {
                bad.action = Action::Unbond {
                    lot: [9; 32],
                    sequence: 1,
                };
                bad.sign(&owner).unwrap();
                Error::WrongAnchor
            }
            9 => {
                bad.action = Action::Unbond {
                    lot: lot.0.id,
                    sequence: 2,
                };
                bad.sign(&owner).unwrap();
                Error::StaleSequence
            }
            10 => {
                bad.action = Action::Withdraw {
                    lot: lot.0.id,
                    sequence: 1,
                };
                bad.sign(&owner).unwrap();
                Error::StaleSequence
            }
            11 => {
                // A window that already closed: re-signed, still refused at the actual height.
                bad.envelope = Envelope {
                    first_height: h - 1,
                    last_height: h - 1,
                    reference_height: h - 2,
                    reference_block: [3; 32],
                    preconditions: vec![],
                };
                bad.sign(&owner).unwrap();
                Error::Envelope(EnvelopeError::Expired)
            }
            _ => {
                bad.envelope = Envelope {
                    first_height: h + 1,
                    last_height: h + 2,
                    reference_height: p.height,
                    reference_block: p.block,
                    preconditions: vec![],
                };
                bad.sign(&owner).unwrap();
                Error::Envelope(EnvelopeError::Future)
            }
        };
        assert_eq!(
            bad.verify_command(&p, &history, &wallets, &lot),
            Err(expected),
            "field {field}"
        );
    }
    // The committed precondition of a command is its lot sequence: an envelope precondition is
    // refused, never carried unchecked.
    let mut conditioned = op.clone();
    conditioned.envelope.preconditions = vec![Precondition::TreasuryHead {
        treasury: [7; 32],
        generation: 1,
        address: [8; 32],
    }];
    assert_eq!(conditioned.body(), Err(Error::Codec));
    assert_eq!(conditioned.sign(&owner), Err(Error::Codec));
    let mut wrong_domain = op.clone();
    wrong_domain.signature = owner
        .sign(Domain::Transaction, &op.body().unwrap())
        .unwrap();
    assert_eq!(
        wrong_domain.verify_command(&p, &history, &wallets, &lot),
        Err(Error::BadSignature)
    );
    let node = HybridKey::generate(Role::Node).unwrap();
    assert!(node.sign(Domain::BondUnbond, &op.body().unwrap()).is_err());
    let mut rotation = Rotation {
        network: NETWORK_ID,
        genesis: p.genesis,
        fingerprint: p.fingerprint,
        authority: address,
        current: owner.public().descriptor(1).unwrap(),
        proposed: next.public().descriptor(2).unwrap(),
        created_height: p.height,
        expiry_height: h,
        authorization: empty(),
        possession: empty(),
    };
    rotation.sign(&owner, &next).unwrap();
    wallets
        .apply(&rotation, p.genesis, p.fingerprint, p.height)
        .unwrap();
    assert_eq!(
        op.verify_command(&p, &history, &wallets, &lot),
        Err(Error::WrongGeneration)
    );
    let old_unbond = raw;
    op.authorizer = next.public().descriptor(2).unwrap();
    op.sign(&next).unwrap();
    op.verify_command(&p, &history, &wallets, &lot).unwrap();
    // The immutable original AddressID owns the lot and receives its payout.
    let mut notice = lot.clone();
    notice.start_unbond(h, 1).unwrap();
    let withdrawal_parent = parent(h + EVIDENCE_HEIGHTS - 1);
    let mut withdraw = op.clone();
    withdraw.envelope = window(&withdrawal_parent);
    withdraw.action = Action::Withdraw {
        lot: lot.0.id,
        sequence: 2,
    };
    withdraw.sign(&next).unwrap();
    withdraw
        .verify_command(&withdrawal_parent, &history, &wallets, &notice)
        .unwrap();
    // One block earlier the notice floor U + 43,200 is not reached: the actual height decides.
    let mut early = withdraw.clone();
    early.envelope = window(&parent(h + EVIDENCE_HEIGHTS - 2));
    early.sign(&next).unwrap();
    assert_eq!(
        early.verify_command(&parent(h + EVIDENCE_HEIGHTS - 2), &history, &wallets, &notice),
        Err(Error::InvalidCounter)
    );
    let id = withdraw.payout_id().unwrap();
    let command_id = withdraw.id().unwrap();
    withdraw.sign(&next).unwrap();
    assert_eq!(id, withdraw.payout_id().unwrap(), "signatures are not part of the payout id");
    assert_eq!(command_id, withdraw.id().unwrap());
    assert_ne!(id, command_id);
    assert_eq!(op.payout_id(), Err(Error::WrongOperation), "an Unbond has no payout");
    // The funded BondCreate (kind 24) of the same owner, signed by its CURRENT key (generation 2)
    // for its immutable generation-1 AddressID. Wire form only here; real-block execution is in
    // consensus/tests/funded_bond_create_v1.rs.
    let unsigned = UnsignedBondCreate {
        genesis: p.genesis,
        fingerprint: p.fingerprint,
        envelope: window(&p),
        owner: address,
        owner_descriptor: next.public().descriptor(2).unwrap(),
        node: [5; 32],
        node_generation: 1,
        nonce: [6; 32],
        principal: MINIMUM_ATOMS,
        fee: 10_000,
        inputs: vec![OutPoint {
            transaction: [7; 32],
            index: 0,
        }],
        change: Some(Output {
            owner: address,
            atoms: 1_000,
        }),
    };
    assert!(unsigned.signed_len().unwrap() <= 10_000);
    let create = FundedBondCreate::sign(unsigned, &next).unwrap();
    create.verify_signatures().unwrap();
    let create_raw = create.encode().unwrap();
    assert_eq!(FundedBondCreate::decode(&create_raw).unwrap(), create);
    // The lot identity derivation is unchanged: [2, NetworkID, genesis, node, owner, nonce].
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(6)
        .unwrap()
        .u8(2)
        .unwrap()
        .u32(NETWORK_ID)
        .unwrap()
        .bytes(&p.genesis)
        .unwrap()
        .bytes(&[5; 32])
        .unwrap()
        .bytes(&address)
        .unwrap()
        .bytes(&[6; 32])
        .unwrap();
    let lot_id = mutiny_consensus_v8::domain_hash(b"MUTINY-BUILD8-BOND-ID-V2", &e.into_writer());
    assert_eq!(create.lot_id(), lot_id);
    // A command is not a create and a create is not a command; the retired version-2 command body
    // and kind 18 no longer decode anywhere.
    assert_eq!(FundedBondCreate::decode(&withdraw.encode().unwrap()), Err(BondError::Codec));
    assert!(create_raw.len() > 4096);
    assert_eq!(Operation::decode(&create_raw), Err(Error::Oversize), "above the command bound");
    assert_eq!(
        mutiny_consensus_v8::blocks::operation_kind(&create_raw),
        Ok(mutiny_consensus_v8::bond_create_v3::OPERATION_KIND)
    );
    if std::env::var("BUILD8_EXPORT_HYBRID_BOND").as_deref() == Ok("1") {
        let value = serde_json::json!({"schema":"BUILD8-SYNTHETIC-HYBRID-BOND-V3","synthetic_only":true,
            "production_authorized":false,"test_value":true,
            "note":"Candidate 3: bond commands use body version 3 (operation envelope, command id and payout id V3, Lane P design 5.1); the create is the funded BondCreate of operation kind 24 (design 2.2). The escrow address and kind 18 are retired. Synthetic TEST-VALUE keys and values only.",
            "parent":hex::encode(p.encode()),"owner_address":hex::encode(address),
            "rotation":hex::encode(rotation.encode().unwrap()),"old_unbond":hex::encode(old_unbond),
            "new_unbond":hex::encode(op.encode().unwrap()),"withdraw":hex::encode(withdraw.encode().unwrap()),
            "withdraw_parent":hex::encode(withdrawal_parent.encode()),"create":hex::encode(&create_raw),
            "lot":hex::encode(lot.encode().unwrap()),"notice":hex::encode(notice.encode().unwrap()),
            "lot_id":hex::encode(lot_id),"withdraw_command_id":hex::encode(command_id),
            "payout":hex::encode(withdraw.payout_id().unwrap())});
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../qualification/hybrid-bond-public-v1.json"),
            )
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&value).unwrap())
            .unwrap();
    }
}
/// Reader of `qualification/hybrid-bond-public-v1.json`: every encoding decodes and re-encodes
/// exactly, the signatures verify, the derived identities match, and the vector's commands are
/// valid against its own parents.
#[test]
fn committed_hybrid_bond_vector_decodes_and_verifies() {
    // Read at run time (not include_str!), so the generator in this same test file still
    // compiles while the file is deleted for regeneration.
    let v: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string("../qualification/hybrid-bond-public-v1.json").unwrap(),
    )
    .unwrap();
    assert_eq!(v["synthetic_only"], true);
    assert_eq!(v["production_authorized"], false);
    let raw = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
    let p = FinalizedAnchor::decode(&raw("parent")).unwrap();
    let address: [u8; 32] = raw("owner_address").try_into().unwrap();
    let rotation = Rotation::decode(&raw("rotation")).unwrap();
    let mut wallets = WalletBook::default();
    wallets.register(&rotation.current).unwrap();
    let old = Operation::decode(&raw("old_unbond")).unwrap();
    let lot = Lot::decode(&raw("lot")).unwrap();
    old.verify_command(&p, &History::default(), &wallets, &lot).unwrap();
    wallets.apply(&rotation, p.genesis, p.fingerprint, p.height).unwrap();
    assert_eq!(
        old.verify_command(&p, &History::default(), &wallets, &lot),
        Err(Error::WrongGeneration)
    );
    let new = Operation::decode(&raw("new_unbond")).unwrap();
    new.verify_command(&p, &History::default(), &wallets, &lot).unwrap();
    let withdraw = Operation::decode(&raw("withdraw")).unwrap();
    let withdraw_parent = FinalizedAnchor::decode(&raw("withdraw_parent")).unwrap();
    let notice = Lot::decode(&raw("notice")).unwrap();
    withdraw
        .verify_command(&withdraw_parent, &History::default(), &wallets, &notice)
        .unwrap();
    assert_eq!(withdraw.payout_id().unwrap().to_vec(), raw("payout"));
    assert_eq!(withdraw.id().unwrap().to_vec(), raw("withdraw_command_id"));
    for op in [&old, &new, &withdraw] {
        assert_eq!(op.owner, address);
        assert_eq!(Operation::decode(&op.encode().unwrap()).unwrap(), *op);
    }
    let create = FundedBondCreate::decode(&raw("create")).unwrap();
    assert_eq!(create.encode().unwrap(), raw("create"));
    create.verify_signatures().unwrap();
    assert_eq!(create.lot_id().to_vec(), raw("lot_id"));
    assert_eq!(create.unsigned.owner, address);
}
#[test]
fn typed_bonds_roundtrip_and_cannot_hide_as_opaque_or_mix_legacy() {
    let lot = Lot(BondLot {
        id: [4; 32],
        node: [5; 32],
        lineage: [5; 32],
        owner: [6; 32],
        atoms: MINIMUM_ATOMS,
        created_height: 1,
        sequence: 0,
        unbond_height: None,
        settled_height: None,
        status: LotStatus::Active,
        evidence: [0; 32],
    });
    let mut state = State::default();
    state.bonds_v2 = Book {
        lots: [(lot.0.id, lot.clone())].into_iter().collect(),
    };
    let root = state.root().unwrap();
    assert_eq!(
        State::from_records(&state.records().unwrap(), root).unwrap(),
        state
    );
    state
        .protocol_records
        .insert([8; 32], lot.encode().unwrap());
    assert!(state.root().is_err());
    state.protocol_records.clear();
    let malformed = vec![0x83, 2, 0x18, 52, 0];
    state.protocol_records.insert([8; 32], malformed);
    assert!(state.root().is_err());
    state.protocol_records.clear();
    let mut legacy = lot.0;
    legacy.owner = ed25519_dalek::SigningKey::from_bytes(&[9; 32])
        .verifying_key()
        .to_bytes();
    state.bonds.lots.insert(legacy.id, legacy);
    assert!(state.root().is_err());
}
