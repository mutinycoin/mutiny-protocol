use mutiny_consensus_v8::{Error, NETWORK_ID, anchors::FinalizedAnchor};
use serde_json::Value;

#[test]
fn finality_survives_restart_and_conflict_halt_never_selects_a_certificate() {
    use mutiny_consensus_v8::{
        certificates::Decision,
        finality::{FinalityError, FinalityLedger},
    };
    let path = std::env::temp_dir().join(format!(
        "build8-anchor-ledger-{}.sqlite",
        std::process::id()
    ));
    assert!(!path.exists());
    let genesis = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 0,
        block: [3; 32],
    };
    let mut d = Decision {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        purpose: 2,
        height: 1,
        mining_epoch: 1,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: genesis.id(),
        parent: genesis.block,
        block: [4; 32],
        state: [5; 32],
        membership: [6; 32],
        reputation: [7; 32],
        attestation: [8; 32],
    };
    {
        let mut ledger = FinalityLedger::open(&path, &genesis).unwrap();
        let mut wrong = d.clone();
        wrong.previous_finalized_anchor = [0; 32];
        assert!(matches!(
            ledger.record_verified(&wrong),
            Err(FinalityError::WrongParent)
        ));
        assert!(ledger.record_verified(&d).unwrap());
        d.round = 1;
        assert!(!ledger.record_verified(&d).unwrap());
    }
    {
        let mut ledger = FinalityLedger::open(&path, &genesis).unwrap();
        assert_eq!(ledger.anchor(1).unwrap().unwrap(), d.anchor());
        d.round = 0;
        assert!(!ledger.record_verified(&d).unwrap());
        let mut conflict = d.clone();
        conflict.block = [99; 32];
        assert!(matches!(
            ledger.record_verified(&conflict),
            Err(FinalityError::IntegrityHalt)
        ));
    }
    {
        let mut ledger = FinalityLedger::open(&path, &genesis).unwrap();
        assert!(matches!(
            ledger.record_verified(&d),
            Err(FinalityError::IntegrityHalt)
        ));
        assert_eq!(ledger.anchor(1).unwrap().unwrap().block, [4; 32]);
    }
    std::fs::remove_file(path).unwrap();
}
#[test]
fn independent_python_bytes_hashes_boundaries_and_context_rejections() {
    let document: Value = serde_json::from_str(include_str!(
        "../../qualification/FINALIZED-ANCHOR-VECTORS.json"
    ))
    .unwrap();
    let mut anchors = Vec::new();
    for vector in document["vectors"].as_array().unwrap() {
        let f = &vector["fields"];
        let h = |name: &str| {
            hex::decode(f[name].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let a = FinalizedAnchor {
            network: f["network"].as_u64().unwrap().try_into().unwrap(),
            genesis: h("genesis"),
            fingerprint: h("fingerprint"),
            height: f["height"].as_u64().unwrap(),
            block: h("block"),
        };
        let raw = hex::decode(vector["cbor_hex"].as_str().unwrap()).unwrap();
        assert_eq!(a.encode(), raw);
        assert_eq!(FinalizedAnchor::decode(&raw).unwrap(), a);
        assert_eq!(hex::encode(a.id()), vector["anchor_id"].as_str().unwrap());
        for length in 0..raw.len() {
            assert!(FinalizedAnchor::decode(&raw[..length]).is_err());
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(FinalizedAnchor::decode(&trailing).is_err());
        let mut nonminimal = raw.clone();
        nonminimal.splice(1..2, [0x18, 1]);
        assert!(FinalizedAnchor::decode(&nonminimal).is_err());
        anchors.push(a);
    }
    for a in &anchors[1..] {
        assert_ne!(a.id(), anchors[0].id());
    }
    assert_eq!(
        anchors[4].validate_context([1; 32], [2; 32]),
        Err(Error::WrongNetwork)
    );
    assert_eq!(
        anchors[5].validate_context([1; 32], [2; 32]),
        Err(Error::WrongGenesis)
    );
    assert_eq!(
        anchors[6].validate_context([1; 32], [2; 32]),
        Err(Error::WrongFingerprint)
    );
    let mut wrong_version = anchors[0].encode();
    wrong_version[1] = 2;
    assert!(FinalizedAnchor::decode(&wrong_version).is_err());
    let mut overflow = anchors[0].encode();
    overflow.splice(2..7, [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
    assert!(FinalizedAnchor::decode(&overflow).is_err());
    assert_eq!(anchors[0].network, NETWORK_ID);
}

#[test]
fn block_identity_commits_body_and_poststate_without_certificate_cycle() {
    use mutiny_consensus_v8::pow::WorkHeader;
    let f: Value = serde_json::from_str(include_str!(
        "../../qualification/CANONICAL-WORK-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let h =
        WorkHeader::decode(&hex::decode(f["vectors"][1]["cbor_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    let original = h.block_hash();
    let mut body = h.clone();
    body.candidate.body_root[0] ^= 1;
    let mut state = h.clone();
    state.candidate.state_root[0] ^= 1;
    assert_ne!(original, body.block_hash());
    assert_ne!(original, state.block_hash());
    // Anchor needs no signature, round or certificate to encode or hash.
    let a = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: h.candidate.genesis,
        fingerprint: h.candidate.fingerprint,
        height: h.candidate.height,
        block: original,
    };
    assert_eq!(FinalizedAnchor::decode(&a.encode()).unwrap().id(), a.id());
}
