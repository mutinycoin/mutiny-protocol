//! Public synthetic software-TPM fixture; never physical admission evidence.
use mutiny_consensus_v8::{
    Error, NETWORK_ID,
    admission_v2::{Admission, Expected, Policy, VerifiedAdmission},
    blocks::{BlockBody, state_root},
    execution::State,
    wallet_authority_v1::WalletBook,
};
fn admission() -> (VerifiedAdmission, Admission, Policy) {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../qualification/admission-public-v2.json")).unwrap();
    let a =
        Admission::decode(&hex::decode(fixture["admission"].as_str().unwrap()).unwrap()).unwrap();
    let p = Policy::decode(&hex::decode(fixture["policy"].as_str().unwrap()).unwrap()).unwrap();
    let expected = Expected {
        node: a.node,
        hardware_generation: a.hardware_generation,
        key_generation: a.key_generation,
        supervised_nonce: a.supervised_nonce,
    };
    (
        a.verify(&p, &expected, &WalletBook::default(), mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest).unwrap(),
        a,
        p,
    )
}
fn expected(a: &Admission) -> Expected {
    Expected {
        node: a.node,
        hardware_generation: a.hardware_generation,
        key_generation: a.key_generation,
        supervised_nonce: a.supervised_nonce,
    }
}
#[test]
fn verified_context_required_checkpoint_roundtrip_and_atomic_duplicate_rejection() {
    let (verified, a, p) = admission();
    let mut s = State::default();
    assert_eq!(verified.genesis(), a.genesis);
    assert_eq!(verified.fingerprint(), a.fingerprint);
    for (g, f) in [([99; 32], p.fingerprint), (p.genesis, [99; 32])] {
        let mut wrong = p.clone();
        wrong.genesis = g;
        wrong.fingerprint = f;
        assert_eq!(
            s.continuity_keys_v2
                .admit(&a, &wrong, &expected(&a), &WalletBook::default(), mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest),
            Err(Error::WrongAnchor)
        );
        assert!(s.continuity_keys_v2.is_empty());
    }
    s.continuity_keys_v2
        .admit(&a, &p, &expected(&a), &WalletBook::default(), mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest)
        .unwrap();
    assert_eq!(s.continuity_keys_v2.get(a.node).unwrap().admission(), &a);
    let before = s.clone();
    assert_eq!(
        s.continuity_keys_v2
            .admit(&a, &p, &expected(&a), &WalletBook::default(), mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest),
        Err(Error::Duplicate)
    );
    assert_eq!(s, before);
    let records = s.records().unwrap();
    let root = s.root().unwrap();
    assert_eq!(State::from_records(&records, root).unwrap(), s);
    assert!(State::from_records(&records, [0; 32]).is_err());
    let mut wrong_key = records.clone();
    wrong_key[0].0[0] ^= 1;
    assert!(State::from_records(&wrong_key, state_root(&wrong_key).unwrap()).is_err());
    // A forged checkpoint root cannot turn broken retained evidence into a
    // valid typed record; an independently pinned root remains mandatory too.
    let mut corrupt = records.clone();
    let last = corrupt[0].1.len() - 1;
    corrupt[0].1[last] ^= 1;
    assert!(State::from_records(&corrupt, state_root(&corrupt).unwrap()).is_err());
    let mut opaque = State::default();
    opaque.protocol_records = records.into_iter().collect();
    assert!(opaque.records().is_err());
}
#[test]
fn malformed_reserved_record_cannot_hide_in_opaque_state_and_execution_is_fenced() {
    for arity in [2, 3, 4, 5, 6, 7] {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(arity).unwrap().u8(2).unwrap().u8(50).unwrap();
        for _ in 2..arity {
            e.null().unwrap();
        }
        let raw = e.into_writer();
        let mut s = State::default();
        s.protocol_records.insert([51; 32], raw.clone());
        assert!(s.records().is_err(), "opaque arity {arity}");
        let records = vec![([51; 32], raw)];
        assert!(State::from_records(&records, state_root(&records).unwrap()).is_err());
    }
    let (_, a, p) = admission();
    let mut s = State::default();
    s.continuity_keys_v2
        .admit(&a, &p, &expected(&a), &WalletBook::default(), mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest)
        .unwrap();
    let body = BlockBody {
        height: 1,
        reward_owner: [7; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![],
    };
    assert!(
        s.execute_transfers(a.genesis, a.fingerprint, [6; 32], [7; 32], &body)
            .is_err()
    );
    assert!(
        s.execute_hybrid_transfers(a.genesis, a.fingerprint, [6; 32], [7; 32], &body)
            .is_err()
    );
    // The stored record explicitly pins the protocol network.
    let records = s.records().unwrap();
    let mut d = minicbor::Decoder::new(&records[0].1);
    assert_eq!(d.array().unwrap(), Some(5));
    assert_eq!(d.u8().unwrap(), 2);
    assert_eq!(d.u8().unwrap(), 50);
    assert_eq!(d.u32().unwrap(), NETWORK_ID);
}

#[test]
fn voter_authority_comes_from_matching_committed_physical_and_hybrid_records() {
    use mutiny_consensus_v8::{
        anchors::FinalizedAnchor,
        recovery::{Anchor, ContinuityState, Member},
        tpm::{TpmProfile, public_key},
        votes_v2::{AuthenticatedRound, HeightAuthority},
    };
    use primitive_types::U256;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/node-admission-v2-public-v1.json"
    )).unwrap();
    let binding = mutiny_consensus_v8::node_admission_v2::Binding::decode(
        &hex::decode(fixture["binding"].as_str().unwrap()).unwrap()
    ).unwrap();
    let a = binding.admission.clone();
    let p = Policy::decode(&hex::decode(fixture["policy"].as_str().unwrap()).unwrap()).unwrap();
    let verified = a.verify(&p, &expected(&a), &WalletBook::default(), mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest).unwrap();
    let profile = TpmProfile::decode(&a.profile).unwrap();
    let member = Member {
        lineage: [18; 32],
        node: a.node,
        hardware: profile.hardware,
        generation: a.hardware_generation,
        voting_key: public_key(&profile.voting_public, false).unwrap(),
        attestation: profile.commitment().unwrap(),
        history: Default::default(),
        physical: true,
        eligible: true,
        genesis_member: true,
    };
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: p.genesis,
        fingerprint: p.fingerprint,
        height: 0,
        block: [19; 32],
    };
    let mut s = State::default();
    (s.membership_v2, s.continuity_keys_v2) = mutiny_consensus_v8::membership_v2::Book::genesis(
        &binding, &p, &expected(&a), &WalletBook::default(), mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest
    ).unwrap();
    s.continuity = Some(
        ContinuityState::bootstrap(
            p.genesis,
            p.fingerprint,
            Anchor {
                height: 0,
                tip: parent.block,
                state_root: [0; 32],
                registry_root: [0; 32],
            },
            [20; 32],
            vec![member],
        )
        .unwrap(),
    );
    let root = s.root().unwrap();
    let mut missing_controls = s.clone();
    missing_controls.membership_v2 = Default::default();
    assert!(HeightAuthority::from_state(
        &missing_controls, parent.clone(), missing_controls.root().unwrap()
    ).is_err());
    let authority = HeightAuthority::from_state(&s, parent.clone(), root).unwrap();
    assert_eq!(authority.voters.len(), 1);
    assert_eq!(
        authority.voters[&a.node].public,
        verified.continuity().clone()
    );
    assert_eq!(authority.voters[&a.node].weight().unwrap(), U256::one());
    AuthenticatedRound::new(authority.clone()).unwrap();
    if std::env::var("BUILD8_EXPORT_HYBRID_KEY_STATE").as_deref() == Ok("1") {
        let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/hybrid-continuity-key-state-public-v2.json");
        let records:Vec<_>=s.records().unwrap().into_iter().map(|(key,value)|
            serde_json::json!({"key":hex::encode(key),"record":hex::encode(value)})).collect();
        let value = serde_json::json!({"schema":"BUILD8-SYNTHETIC-CONTINUITY-KEY-STATE-V2",
            "synthetic_only":true,"production_authorized":false,"parent":hex::encode(parent.encode()),
            "state_root":hex::encode(root),"records":records,
            "roots":authority.roots().map(hex::encode),"weight":"1",
            "limits":"Synthetic wire evidence; existing physical/history codec remains a candidate bridge; recovery and lifecycle execution are gated."});
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(out)
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&value).unwrap())
            .unwrap();
    }
    let restored = State::from_records(&s.records().unwrap(), root).unwrap();
    assert_eq!(
        HeightAuthority::from_state(&restored, parent.clone(), root)
            .unwrap()
            .roots(),
        authority.roots()
    );
    assert!(HeightAuthority::from_state(&s, parent.clone(), [0; 32]).is_err());
    for field in 0..7 {
        let mut bad = s.clone();
        let m = &mut bad.continuity.as_mut().unwrap().members[0];
        match field {
            0 => m.hardware[0] ^= 1,
            1 => m.generation += 1,
            2 => m.attestation[0] ^= 1,
            3 => m.voting_key[1] ^= 1,
            4 => m.physical = false,
            5 => bad.continuity_keys_v2 = Default::default(),
            _ => bad.continuity.as_mut().unwrap().members.clear(),
        }
        if let Ok(root) = bad.root() {
            assert!(HeightAuthority::from_state(&bad, parent.clone(), root).is_err(), "field {field}");
        }
    }
    let mut bad_parent = parent.clone();
    bad_parent.genesis[0] ^= 1;
    assert!(HeightAuthority::from_state(&s, bad_parent, root).is_err());
    let mut bad_parent = parent.clone();
    bad_parent.height = 1;
    assert!(HeightAuthority::from_state(&s, bad_parent, root).is_err());
    // Zero-weight admitted joiners retain their bound public identity; that
    // identity alone cannot instantiate a positive-weight BFT round.
    let mut zero = s.clone();
    zero.continuity.as_mut().unwrap().members[0].genesis_member = false;
    let zero_authority =
        HeightAuthority::from_state(&zero, parent.clone(), zero.root().unwrap()).unwrap();
    assert_eq!(
        zero_authority.voters[&a.node].weight().unwrap(),
        U256::zero()
    );
    assert!(AuthenticatedRound::new(zero_authority).is_err());
    // An ineligible physical member cannot vote despite valid retained keys.
    let mut revoked = s.clone();
    revoked.continuity.as_mut().unwrap().members[0].eligible = false;
    let auth =
        HeightAuthority::from_state(&revoked, parent.clone(), revoked.root().unwrap()).unwrap();
    assert_eq!(auth.voters[&a.node].weight().unwrap(), U256::zero());
    // A cloud member contributes no authority even with reputation history.
    let mut cloud = s.clone();
    cloud.continuity_keys_v2 = Default::default();
    cloud.membership_v2 = Default::default();
    let m = &mut cloud.continuity.as_mut().unwrap().members[0];
    m.physical = false;
    m.history.p = 100;
    m.history.a = 100;
    assert!(
        HeightAuthority::from_state(&cloud, parent, cloud.root().unwrap())
            .unwrap()
            .voters
            .is_empty()
    );
}
