//! Synthetic public fixture only; no keys, services or hardware.
use super::*;
#[test]
fn historical_observation_requires_exact_parent_execution_and_both_signatures() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-canonical-store-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let root: Hash = raw(&f["root"]).try_into().unwrap();
    let rows: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&rows, root).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let block = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-observation-history-{}.sqlite",
        hex::encode(nonce)
    ));
    assert!(!path.exists());
    let mut chain =
        CanonicalStore::open_trusted_genesis(&path, &genesis, &state, root, 1000, [255; 32])
            .unwrap();
    let valid = |chain: &CanonicalStore| {
        chain.validate_observation_v2(&block.header, &block.authority, &block.body)
    };
    valid(&chain).unwrap();
    assert_eq!(
        chain.load().unwrap().0.height,
        0,
        "qualification must not install candidate"
    );
    for which in 0..8 {
        let mut header = block.header.clone();
        match which {
            0 => header.candidate.network ^= 1,
            1 => header.candidate.genesis[0] ^= 1,
            2 => header.candidate.fingerprint[0] ^= 1,
            3 => header.candidate.parent[0] ^= 1,
            4 => header.candidate.height = 0,
            5 => header.candidate.height = 2,
            6 => header.candidate.state_root[0] ^= 1,
            _ => header.authority[0] ^= 1,
        }
        assert!(
            chain
                .validate_observation_v2(&header, &block.authority, &block.body)
                .is_err()
        );
    }
    for which in 0..3 {
        let mut authority = block.authority.clone();
        match which {
            0 => authority.signature.ed448.fill(0),
            1 => authority.signature.fndsa.fill(0),
            _ => authority.node_descriptor[0] ^= 1,
        }
        assert!(
            chain
                .validate_observation_v2(&block.header, &authority, &block.body)
                .is_err()
        );
    }
    let mut body = block.body.clone();
    body.transactions.clear();
    assert!(
        chain
            .validate_observation_v2(&block.header, &block.authority, &body)
            .is_err()
    );
    body.operations.push(vec![0; 16385]);
    assert!(
        chain
            .validate_observation_v2(&block.header, &block.authority, &body)
            .is_err()
    );
    assert!(chain.commit(&block).unwrap());
    valid(&chain).unwrap(); // Authenticated historical parent, not current ticket floor.
    assert_eq!(chain.load().unwrap().0.height, 1);
    drop(chain);
    let chain =
        CanonicalStore::open_trusted_genesis(&path, &genesis, &state, root, 1000, [255; 32])
            .unwrap();
    valid(&chain).unwrap();
    chain
        .evidence
        .db
        .execute("UPDATE integrity_v2 SET halted=1 WHERE id=1", [])
        .unwrap();
    assert!(matches!(valid(&chain), Err(StoreError::Halted)));
    drop(chain);
    std::fs::remove_file(path).unwrap();
}
