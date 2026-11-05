use super::*;
#[test]
fn manifest_image_digest_has_one_explicit_sha512_encoding() {
    let fixture:serde_json::Value=serde_json::from_str(include_str!("../../qualification/release-policy-public-fixture-v1.json")).unwrap();
    let raw=hex::decode(fixture["manifest"].as_str().unwrap()).unwrap();
    Manifest::decode(&raw).unwrap();
    let mut d=minicbor::Decoder::new(&raw);assert_eq!(d.array().unwrap(),Some(16));
    for _ in 0..8 {d.skip().unwrap();}
    let start=d.position();assert_eq!(d.array().unwrap(),Some(2));assert_eq!(d.u8().unwrap(),2);
    let digest=d.bytes().unwrap();assert_eq!(digest.len(),64);let end=d.position();
    for tag in [0,1,3,255] {let mut bad=raw.clone();bad[start+1]=tag;assert!(Manifest::decode(&bad).is_err());}
    for legacy in [true,false] {
        let mut bad=raw[..start].to_vec();
        if !legacy {bad.extend_from_slice(&[0x82,2]);}
        bad.extend_from_slice(&[0x58,32]);bad.extend_from_slice(&digest[..32]);bad.extend_from_slice(&raw[end..]);
        assert!(Manifest::decode(&bad).is_err());
    }
}
#[test]
fn existing_independent_wire_fixture_accepts_all_distinct_pairs() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/release-policy-public-fixture-v1.json"
    ))
    .unwrap();
    let p = hex::decode(f["policy"].as_str().unwrap()).unwrap();
    let m = hex::decode(f["manifest"].as_str().unwrap()).unwrap();
    let a: Vec<_> = f["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| hex::decode(a["bytes"].as_str().unwrap()).unwrap())
        .collect();
    for (i, j) in [(0, 1), (0, 2), (1, 2)] {
        verify_synthetic_release(&p, &m, &[a[i].clone(), a[j].clone()]).unwrap();
    }
    assert!(verify_synthetic_release(&p, &m, &[a[0].clone(), a[0].clone()]).is_err());
    let p = Policy::decode(&p).unwrap();
    let m = Manifest::decode(&m).unwrap();
    let a: Vec<_> = a.iter().map(|a| Approval::decode(a).unwrap()).collect();
    assert!(verify_release(&p, &m, &a, true).is_err());
}
#[test]
fn fresh_encrypted_custodians_public_possession_review_and_quorum() {
    let password = "PUBLIC SYNTHETIC TEST PASSWORD";
    let image = b"SYNTHETIC QUALIFICATION ARTIFACT";
    let mut vaults = Vec::new();
    let mut descriptors = Vec::new();
    for role in 1..=3 {
        let (v, d) = CustodianSession::create_synthetic(role, password).unwrap();
        vaults.push(v);
        descriptors.push(d);
    }
    let policy = combine_synthetic_descriptors(&descriptors, 1).unwrap();
    let p = Policy::decode(&policy).unwrap();
    let m = Manifest {
        network: NETWORK,
        genesis: None,
        fingerprint: [1; 32],
        board: [2; 32],
        application: 2,
        security: 1,
        length: image.len() as u32,
        image: Sha512::digest(image).into(),
        schema_min: 2,
        schema_max: 2,
        policy: p.id().unwrap(),
        policy_generation: 1,
        rollback: 1,
        flags: 0,
    };
    let manifest = m.bytes().unwrap();
    let review = ReleaseReview::from_bytes(&policy, &manifest, image).unwrap();
    let text = review.summary().unwrap();
    for field in [
        "Network:",
        "Genesis compatibility:",
        "ProtocolFingerprint:",
        "Board profile:",
        "Application version:",
        "Security version:",
        "Image length:",
        "Image SHA-512:",
        "INACTIVE_APPLICATION",
        "Storage schema:",
        "ReleasePolicyID:",
        "AntiRollbackGeneration:",
    ] {
        assert!(text.contains(field));
    }
    assert!(review.confirmation().unwrap().starts_with("APPROVE "));
    assert!(ReleaseReview::from_bytes(&policy, &manifest, b"changed image").is_err());
    let sessions: Vec<_> = vaults
        .iter()
        .map(|v| CustodianSession::open_synthetic(password, v).unwrap())
        .collect();
    let approvals: Vec<_> = sessions
        .iter()
        .map(|s| s.approve_review(&review).unwrap())
        .collect();
    for (i, j) in [(0, 1), (0, 2), (1, 2)] {
        verify_synthetic_release(
            &policy,
            &manifest,
            &[approvals[i].clone(), approvals[j].clone()],
        )
        .unwrap();
    }
    assert!(CustodianSession::open_synthetic("wrong password", &vaults[0]).is_err());
    let mut wrong = vaults[0].clone();
    wrong[3] = 2;
    assert!(CustodianSession::open_synthetic(password, &wrong).is_err());
    let mut wrong = descriptors.clone();
    let n = wrong[0].len();
    wrong[0][n - 1] ^= 1;
    assert!(combine_synthetic_descriptors(&wrong, 1).is_err());
    assert!(
        combine_synthetic_descriptors(
            &[
                descriptors[0].clone(),
                descriptors[0].clone(),
                descriptors[2].clone()
            ],
            1
        )
        .is_err()
    );
    let mut no_marker = policy.clone();
    let marker = no_marker.iter().position(|x| *x == 0xf5).unwrap();
    no_marker[marker] = 0xf4;
    assert!(ReleaseReview::from_bytes(&no_marker, &manifest, image).is_err());
    let (next_vault, next_descriptor) = CustodianSession::create_synthetic(1, password).unwrap();
    let mut next_descriptors = descriptors.clone();
    next_descriptors[0] = next_descriptor;
    let next = combine_synthetic_descriptors(&next_descriptors, 2).unwrap();
    let rotation = RotationReview::from_bytes(&policy, &next, [8; 32]).unwrap();
    let next_session = CustodianSession::open_synthetic(password, &next_vault).unwrap();
    let current = vec![
        sessions[0].approve_rotation(&rotation, false).unwrap(),
        sessions[1].approve_rotation(&rotation, false).unwrap(),
    ];
    let proposed = vec![
        next_session.approve_rotation(&rotation, true).unwrap(),
        sessions[1].approve_rotation(&rotation, true).unwrap(),
    ];
    assert_eq!(
        verify_synthetic_rotation(&policy, &next, [8; 32], &current, &proposed).unwrap(),
        next
    );
    assert!(verify_synthetic_rotation(&policy, &next, [8; 32], &current[..1], &proposed).is_err());
    assert!(verify_synthetic_rotation(&policy, &next, [8; 32], &current, &proposed[..1]).is_err());
    assert!(verify_synthetic_rotation(&policy, &next, [9; 32], &current, &proposed).is_err());
    assert!(sessions[0].approve_rotation(&rotation, true).is_err());
    assert!(next_session.approve_rotation(&rotation, false).is_err());
    assert!(RotationReview::from_bytes(&next, &policy, [8; 32]).is_err());
    if std::env::var("BUILD8_EXPORT_PUBLIC_ROTATION").as_deref()==Ok("1") {
        let old=Policy::decode(&policy).unwrap();let new=Policy::decode(&next).unwrap();
        let report=serde_json::json!({"schema":"BUILD8-SYNTHETIC-RELEASE-ROTATION-V1","synthetic":true,"production_authorized":false,
            "old_policy":hex::encode(&policy),"old_id":hex::encode(old.id().unwrap()),"old_generation":old.generation,
            "new_policy":hex::encode(&next),"new_id":hex::encode(new.id().unwrap()),"new_generation":new.generation,
            "fingerprint":hex::encode([8;32]),"rotation_digest":hex::encode(rotation_digest(&old,&new,[8;32]).unwrap()),
            "current_approvals":current.iter().map(hex::encode).collect::<Vec<_>>(),"new_proofs":proposed.iter().map(hex::encode).collect::<Vec<_>>()});
        std::fs::write(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../qualification/release-rotation-public-v1.json"),serde_json::to_string_pretty(&report).unwrap()+"\n").unwrap();
    }
}
