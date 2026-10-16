use mutiny_consensus_v8::{
    NETWORK_ID,
    pow::{Candidate, WorkAuthority, WorkContext, WorkHeader},
    work_authority_v2::{Authority, node_identity},
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, Role};
#[test]
fn node_work_requires_exact_hybrid_role_parent_assignment_and_both_signatures() {
    let key = HybridKey::generate(Role::Node).unwrap();
    let descriptor = key.public().descriptor(1).unwrap();
    let coordinator = node_identity(&descriptor).unwrap();
    let candidate = Candidate {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        parent: [3; 32],
        height: 1,
        timestamp: 1100,
        body_root: [4; 32],
        state_root: [5; 32],
        license: [6; 32],
        worker: [7; 32],
        target: [255; 32],
    };
    let context = WorkContext {
        genesis: candidate.genesis,
        fingerprint: candidate.fingerprint,
        parent: candidate.parent,
        parent_height: 0,
        t0: 1000,
        target: candidate.target,
        license: candidate.license,
        worker: candidate.worker,
        coordinator,
        assignment_sequence: 1,
        last_accepted_ticket: 0,
        ancestor_timestamps: vec![1000],
    };
    let mut authority = Authority {
        work: WorkAuthority {
            candidate: candidate.clone(),
            assignment_sequence: 1,
            ticket_sequence: 1,
            coordinator,
            nonce_start: 0,
            nonce_end: 1000,
            epoch: 1,
        },
        node_descriptor: descriptor.clone(),
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    authority.sign(&key).unwrap();
    let header = WorkHeader {
        candidate,
        authority: authority.id().unwrap(),
        nonce: 10,
    };
    authority.verify(&header, &context, &descriptor).unwrap();
    let raw = authority.encode().unwrap();
    assert_eq!(Authority::decode(&raw).unwrap(), authority);
    assert!(raw.len() < 8192);
    for part in 0..2 {
        let mut bad = authority.clone();
        if part == 0 {
            bad.signature.ed448[0] ^= 1;
        } else {
            bad.signature.fndsa[0] ^= 1;
        }
        assert_eq!(bad.id().unwrap(), authority.id().unwrap());
        assert!(bad.verify(&header, &context, &descriptor).is_err());
    }
    for field in 0..16 {
        let mut bad = authority.clone();
        match field {
            0 => bad.work.candidate.network ^= 1,
            1 => bad.work.candidate.genesis[0] ^= 1,
            2 => bad.work.candidate.fingerprint[0] ^= 1,
            3 => bad.work.candidate.parent[0] ^= 1,
            4 => bad.work.candidate.height += 1,
            5 => bad.work.candidate.license[0] ^= 1,
            6 => bad.work.candidate.worker[0] ^= 1,
            7 => bad.work.candidate.target[0] ^= 1,
            8 => bad.work.assignment_sequence += 1,
            9 => bad.work.ticket_sequence = 0,
            10 => bad.work.epoch += 1,
            11 => bad.work.nonce_start = 11,
            12 => bad.work.nonce_end = 9,
            13 => bad.work.candidate.timestamp = 1000,
            14 => bad.work.candidate.body_root[0] ^= 1,
            _ => bad.work.candidate.state_root[0] ^= 1,
        }
        // Re-sign an otherwise authentic malicious work object: context/field
        // checks, not merely signature failure, must reject it.
        bad.sign(&key).unwrap();
        let mut changed = header.clone();
        changed.authority = bad.id().unwrap();
        assert!(
            bad.verify(&changed, &context, &descriptor).is_err(),
            "field {field}"
        );
    }
    let mut nonce = header.clone();
    nonce.nonce = 1001;
    assert!(authority.verify(&nonce, &context, &descriptor).is_err());
    assert!(
        authority
            .verify(&header, &context, &key.public().descriptor(2).unwrap())
            .is_err()
    );
    let transport = HybridKey::generate(Role::Transport).unwrap();
    assert!(authority.sign(&transport).is_err());
    assert!(node_identity(&transport.public().descriptor(1).unwrap()).is_err());
    assert!(
        key.public()
            .verify(
                Domain::TransportResponder,
                &authority.unsigned().unwrap(),
                &authority.signature
            )
            .is_err()
    );
    assert!(Authority::decode(&authority.work.envelope(&[0; 64])).is_err());
    for n in 0..raw.len() {
        assert!(Authority::decode(&raw[..n]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Authority::decode(&trailing).is_err());
    if std::env::var("BUILD8_EXPORT_HYBRID_WORK").as_deref() == Ok("1") {
        let v = serde_json::json!({"schema":"BUILD8-HYBRID-WORK-AUTHORITY-PUBLIC-V1","synthetic_only":true,
            "wire":hex::encode(raw),"unsigned":hex::encode(authority.unsigned().unwrap()),
            "header":hex::encode(header.encode()),"id":hex::encode(authority.id().unwrap()),
            "coordinator":hex::encode(coordinator),"descriptor":hex::encode(descriptor),
            "ed448_signature":hex::encode(authority.signature.ed448),"fndsa_signature":hex::encode(authority.signature.fndsa)});
        std::fs::write(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../qualification/hybrid-work-authority-public-v1.json"),
            serde_json::to_vec_pretty(&v).unwrap(),
        )
        .unwrap();
    }
}
