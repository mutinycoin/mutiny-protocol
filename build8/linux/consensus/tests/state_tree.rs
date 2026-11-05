use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor, state_tree::*};
fn bytes(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn hash(v: &serde_json::Value) -> Hash {
    bytes(v).try_into().unwrap()
}
#[test]
fn independent_python_incremental_full_proofs_and_negatives() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/STATE-TREE-V2-VECTORS-V1.json"
    ))
    .unwrap();
    for (i, d) in v["defaults"].as_array().unwrap().iter().enumerate() {
        assert_eq!(defaults()[i], hash(d));
    }
    let context = FinalizedAnchor::decode(&bytes(&v["context"])).unwrap();
    let mut tree = StateTree::default();
    for op in v["operations"].as_array().unwrap() {
        let k = hash(&op["key"]);
        match op["action"].as_str().unwrap() {
            "insert" => tree.insert(k, bytes(&op["record"])).unwrap(),
            "update" => tree.update(k, bytes(&op["record"])).unwrap(),
            "delete" => tree.remove(&k).unwrap(),
            _ => panic!("operation"),
        }
        assert_eq!(tree.root(), hash(&op["root"]));
        assert_eq!(tree.root(), full_root(&tree.records()).unwrap());
        let mut stream = StateRootBuilder::default();
        for (key, record) in tree.records() {
            stream.push(key, &record).unwrap();
        }
        assert_eq!(tree.root(), stream.finish());
        if op["proof"].is_string() {
            let p = StateProof::decode(&bytes(&op["proof"])).unwrap();
            assert_eq!(tree.proof(context.clone(), p.key), p);
            p.verify(&context, tree.root(), p.key).unwrap();
            let mut wrong = p.clone();
            wrong.count += 1;
            assert!(wrong.verify(&context, tree.root(), p.key).is_err());
            let mut wrong = p.clone();
            wrong.context.height += 1;
            assert!(wrong.verify(&context, tree.root(), p.key).is_err());
            let mut wrong = p.clone();
            wrong.key[0] ^= 128;
            assert!(wrong.verify(&context, tree.root(), p.key).is_err());
            if !p.siblings.is_empty() {
                let mut wrong = p.clone();
                wrong.siblings[0][0] ^= 1;
                assert!(wrong.verify(&context, tree.root(), p.key).is_err());
            }
        }
    }
    for case in v["cases"].as_array().unwrap() {
        let records: Vec<(Hash, Vec<u8>)> = case["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (hash(&r[0]), bytes(&r[1])))
            .collect();
        let expected = hash(&case["root"]);
        assert_eq!(full_root(&records).unwrap(), expected);
        let mut tree = StateTree::default();
        for (k, r) in records.iter().rev() {
            tree.insert(*k, r.clone()).unwrap();
        }
        assert_eq!(tree.root(), expected);
        for raw in case["proofs"].as_array().unwrap() {
            let raw = bytes(raw);
            let p = StateProof::decode(&raw).unwrap();
            assert_eq!(p.encode().unwrap(), raw);
            assert_eq!(tree.proof(context.clone(), p.key), p);
            p.verify(&context, expected, p.key).unwrap();
            let mut wrong = p.clone();
            wrong.record = Some(vec![0]);
            assert!(wrong.verify(&context, expected, p.key).is_err());
            let mut wrong = p.clone();
            wrong.bitmap[0] ^= 128;
            assert!(wrong.verify(&context, expected, p.key).is_err());
            let mut wrong = p.clone();
            wrong.siblings.push([0; 32]);
            assert!(wrong.encode().is_err());
            let mut trailing = raw.clone();
            trailing.push(0);
            assert!(StateProof::decode(&trailing).is_err());
            for cut in [0, 1, raw.len() / 2, raw.len() - 1] {
                assert!(StateProof::decode(&raw[..cut]).is_err());
            }
            let mut version = raw.clone();
            version[1] = 1;
            assert!(StateProof::decode(&version).is_err());
        }
        for (k, _) in &records {
            assert!(tree.insert(*k, vec![0]).is_err());
            tree.remove(k).unwrap();
            assert_eq!(tree.root(), full_root(&tree.records()).unwrap());
            let mut stream = StateRootBuilder::default();
            for (key, record) in tree.records() {
                stream.push(key, &record).unwrap();
            }
            assert_eq!(tree.root(), stream.finish());
        }
        assert_eq!(tree.root(), commitment(0, defaults()[0]).unwrap());
    }
    let mut proof = StateTree::default().proof(context.clone(), [0; 32]);
    proof.bitmap[0] = 128;
    proof.siblings.push(defaults()[1]);
    assert!(proof.encode().is_err());
    assert!(StateProof::decode(&vec![0; MAX_PROOF + 1]).is_err());
    let mut tree = StateTree::default();
    assert!(tree.insert([0; 32], vec![0; MAX_RECORD + 1]).is_err());
    assert!(tree.insert([0; 32], vec![0x18, 0]).is_err());
    assert!(tree.update([0; 32], vec![0]).is_err());
    assert!(tree.remove(&[0; 32]).is_err());
}
