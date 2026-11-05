use ed25519_dalek::{Signer, SigningKey};
use mutiny_consensus_v8::{recovery::*, reputation::*, *};
use primitive_types::U256;

fn member(i: u8) -> Member {
    Member {
        lineage: [i; 32],
        node: [i + 10; 32],
        hardware: [i + 20; 32],
        generation: 0,
        voting_key: p256::ecdsa::SigningKey::from_bytes((&[i; 32]).into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap(),
        attestation: [3; 32],
        history: History::default(),
        physical: true,
        eligible: true,
        genesis_member: true,
    }
}
fn fixture(n: u8) -> (ContinuityState, SigningKey) {
    let key = SigningKey::from_bytes(&[0x42; 32]); // Public fixture, never production custody.
    let anchor = Anchor {
        height: 0,
        tip: [1; 32],
        state_root: [2; 32],
        registry_root: [3; 32],
    };
    (
        ContinuityState::bootstrap(
            [4; 32],
            [5; 32],
            anchor,
            key.verifying_key().to_bytes(),
            (1..=n).map(member).collect(),
        )
        .unwrap(),
        key,
    )
}
struct TestPhysical;
impl PhysicalAdmissionVerifier for TestPhysical {
    fn verify_replacement(&self, b: &Recovery) -> Result<()> {
        if b.attestation == [6; 32] && b.new_voting_key[0] == 2 {
            Ok(())
        } else {
            Err(Error::UnqualifiedPhysical)
        }
    }
}
fn unsigned(s: &ContinuityState) -> Recovery {
    Recovery {
        network: NETWORK_ID,
        genesis: s.genesis,
        fingerprint: s.fingerprint,
        anchor: s.anchor.clone(),
        sequence: s.sequence() + 1,
        lineage: s.members[0].lineage,
        old_generation: s.members[0].generation,
        new_node: [70; 32],
        new_hardware: [80; 32],
        attestation: [6; 32],
        new_voting_key: [2; 33],
        operation: 1,
        reason: 1,
        ceremony_commitment: loss_commitment(&[(s.members[0].lineage, s.members[0].generation)])
            .unwrap(),
    }
}
fn sign(b: Recovery, k: &SigningKey) -> Certificate {
    let signature = k.sign(&b.digest()).to_bytes();
    Certificate { body: b, signature }
}
fn apply(s: &mut ContinuityState, c: &Certificate) -> Result<()> {
    s.apply_recovery(
        c,
        &TestPhysical,
        &[(c.body.lineage, c.body.old_generation)],
        false,
    )
}

#[test]
fn sole_genesis_loss_recovers_only_registry_hardware() {
    let (mut s, k) = fixture(1);
    s.members[0].history = History {
        p: 100,
        a: 100,
        s: 100,
        h: 100,
        penalties: 50.into(),
        bonds: vec![Bond {
            atoms: 10_000_000_000,
            age: ContinuityPeriod(99),
        }],
    };
    let before = s.clone();
    let c = sign(unsigned(&s), &k);
    apply(&mut s, &c).unwrap();
    assert_eq!(s.members[0].history.h, 0);
    assert_eq!(s.members[0].history.bonds, before.members[0].history.bonds);
    assert_eq!(s.members[0].history.p, 100);
    assert_eq!(s.members[0].history.a, 100);
    assert_eq!(s.members[0].history.penalties, U256::from(50));
    assert_eq!(s.anchor, before.anchor);
    assert_eq!(s.sequence(), 1);
    assert_eq!(s.members[0].generation, 1);
    assert_eq!(apply(&mut s, &c), Err(Error::StaleSequence));
}
#[test]
fn context_replays_and_tampering_fail() {
    let (s, k) = fixture(1);
    for variant in 0..8 {
        let mut b = unsigned(&s);
        match variant {
            0 => b.network ^= 1,
            1 => b.genesis[0] ^= 1,
            2 => b.fingerprint[0] ^= 1,
            3 => b.anchor.tip[0] ^= 1,
            4 => b.sequence = 0,
            5 => b.old_generation = 1,
            6 => b.operation = 2,
            _ => b.anchor.registry_root[0] ^= 1,
        };
        let mut copy = s.clone();
        assert!(apply(&mut copy, &sign(b, &k)).is_err());
        assert_eq!(copy, s);
    }
    let mut c = sign(unsigned(&s), &k);
    c.signature[0] ^= 1;
    assert_eq!(apply(&mut s.clone(), &c), Err(Error::BadSignature));
    let wrong_key = SigningKey::from_bytes(&[0x43; 32]);
    assert_eq!(
        apply(&mut s.clone(), &sign(unsigned(&s), &wrong_key)),
        Err(Error::BadSignature)
    );
}
#[test]
fn cloud_and_unverified_replacement_fail_closed() {
    let (s, k) = fixture(1);
    let mut b = unsigned(&s);
    b.attestation = [0; 32];
    assert_eq!(
        apply(&mut s.clone(), &sign(b, &k)),
        Err(Error::UnqualifiedPhysical)
    );
}
#[test]
fn old_quorum_available_or_existing_finality_forbids_recovery() {
    let (mut s, k) = fixture(4);
    let c = sign(unsigned(&s), &k);
    assert_eq!(apply(&mut s, &c), Err(Error::NormalQuorumAvailable));
    let (mut s, k) = fixture(1);
    let c = sign(unsigned(&s), &k);
    assert_eq!(
        s.apply_recovery(&c, &TestPhysical, &[([1; 32], 0)], true),
        Err(Error::ExistingFinality)
    );
}
#[test]
fn activation_irreversibly_disables_recovery_even_after_concentration() {
    let (mut s, k) = fixture(4);
    s.activate_decentralized(&[0, 1, 2]).unwrap();
    assert_eq!(s.mode(), "DECENTRALIZED");
    assert!(!s.recovery_enabled());
    s.first_period_committed = true;
    s.members[0].history = History {
        p: 100,
        a: 100,
        s: 100,
        h: 100,
        ..Default::default()
    };
    let c = sign(unsigned(&s), &k);
    assert_eq!(apply(&mut s, &c), Err(Error::RecoveryDisabled));
    assert!(!s.metrics().unwrap().survival_redundancy_met);
    assert_eq!(s.mode(), "DECENTRALIZED");
}
#[test]
fn activation_needs_both_old_quorum_and_independent_redundancy() {
    let (mut s, _) = fixture(4);
    assert_eq!(s.activate_decentralized(&[0, 1]), Err(Error::NoQuorum));
    s.members[3].hardware = s.members[0].hardware;
    assert_eq!(s.activate_decentralized(&[0, 1, 2]), Err(Error::Duplicate));
    let (mut s, _) = fixture(3);
    assert_eq!(
        s.activate_decentralized(&[0, 1, 2]),
        Err(Error::RedundancyNotMet)
    );
}
#[test]
fn committed_registry_roots_are_order_independent_and_duplicate_keys_never_add_weight() {
    let (mut s, _) = fixture(4);
    let roots = s.roots().unwrap();
    s.members.reverse();
    assert_eq!(s.roots().unwrap(), roots);
    assert_eq!(s.voters().unwrap().len(), 4);
    s.anchor.tip = [99; 32];
    s.anchor.state_root = [98; 32];
    s.anchor.registry_root = [97; 32];
    assert_eq!(s.roots().unwrap(), roots); // no current-anchor/StateRoot cycle
    s.members[0].history.p = 1;
    s.members[0].history.a = 1;
    s.members[0].history.s = 1;
    s.members[0].history.h = 1;
    let next = s.roots().unwrap();
    assert_eq!(next.0, roots.0);
    assert_ne!(next.1, roots.1);
    assert_eq!(next.2, roots.2);
    s.first_period_committed = true;
    assert_eq!(
        s.voters().unwrap()[&s.members[0].node].weight,
        U256::from(1007)
    );
    assert_ne!(s.roots().unwrap().0, next.0);
    s.members[1].voting_key = s.members[0].voting_key;
    assert_eq!(s.weights(), Err(Error::Duplicate));
}
#[test]
fn provisional_weight_replaced_not_added_and_never_given_to_cloud_or_joiner() {
    let mut h = History::default();
    assert_eq!(
        h.voting_weight(true, true, true, false).unwrap(),
        U256::one()
    );
    assert_eq!(
        h.voting_weight(false, true, true, false).unwrap(),
        U256::zero()
    );
    assert_eq!(
        h.voting_weight(true, true, false, false).unwrap(),
        U256::zero()
    );
    h.complete_period(true).unwrap();
    assert_eq!(
        h.voting_weight(true, true, true, true).unwrap(),
        U256::from(1007)
    );
}
#[test]
fn dynamic_reputation_and_integer_boundaries() {
    let mut h = History {
        p: 100,
        a: 100,
        s: 100,
        h: 100,
        ..Default::default()
    };
    let before = h.score().unwrap();
    h.complete_period(false).unwrap();
    assert_eq!(before - h.score().unwrap(), U256::from(399));
    assert_eq!(h.penalties, U256::zero());
    h.bonds.push(Bond {
        atoms: 10_000_000_000,
        age: ContinuityPeriod(100),
    });
    let before = h.score().unwrap();
    h.bonds.clear();
    assert_eq!(before - h.score().unwrap(), U256::from(101));
    assert_eq!(add(U256::MAX, U256::one()), Err(Error::Overflow));
    let h = History {
        p: u64::MAX,
        a: u64::MAX,
        s: u64::MAX,
        h: u64::MAX,
        penalties: U256::zero(),
        bonds: vec![
            Bond {
                atoms: u64::MAX,
                age: ContinuityPeriod(u64::MAX)
            };
            64
        ],
    };
    assert!(mul(h.score().unwrap(), 3072.into()).unwrap().bits() < 256);
}
#[test]
fn concentration_exact_thirds_and_multiple_losses() {
    assert!(
        !concentration(&[1.into(), 1.into(), 1.into()], 3)
            .unwrap()
            .survival_redundancy_met
    );
    assert!(
        concentration(&[1.into(); 4], 4)
            .unwrap()
            .survival_redundancy_met
    );
    assert!(
        !concentration(&[4.into(), 1.into(), 1.into(), 1.into()], 4)
            .unwrap()
            .survival_redundancy_met
    );
    assert!(
        !concentration(&[7.into(), 1.into(), 1.into(), 1.into()], 4)
            .unwrap()
            .survival_redundancy_met
    );
    assert!(!quorum(&[1.into(); 4], &[0, 1]).unwrap());
    assert!(!quorum(&[1.into(); 3], &[0, 1]).unwrap());
}
#[test]
fn canonical_cbor_and_negative_encodings() {
    let (s, k) = fixture(1);
    let c = sign(unsigned(&s), &k);
    let bytes = c.encode();
    assert_eq!(Certificate::decode(&bytes).unwrap(), c);
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(Certificate::decode(&extra), Err(Error::NonCanonical));
    let mut nonminimal = bytes.clone();
    nonminimal.splice(0..1, [0x98, 2]);
    assert_eq!(Certificate::decode(&nonminimal), Err(Error::NonCanonical));
    let mut indefinite = bytes.clone();
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    assert!(Certificate::decode(&indefinite).is_err());
    assert_eq!(Certificate::decode(&vec![0; 4097]), Err(Error::Oversize));
    for n in 0..bytes.len() {
        assert!(Certificate::decode(&bytes[..n]).is_err());
    }
}
#[test]
fn recovery_domain_is_not_wallet_or_node_domain() {
    let (s, k) = fixture(1);
    let b = unsigned(&s);
    let signature = k
        .sign(&domain_hash(b"MUTINY-BUILD8-WALLET-SPEND-V1", &b.encode()))
        .to_bytes();
    assert_eq!(
        apply(&mut s.clone(), &Certificate { body: b, signature }),
        Err(Error::BadSignature)
    );
}

#[test]
fn canonical_public_fixture_matches_file() {
    let (s, k) = fixture(1);
    let c = sign(unsigned(&s), &k);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qualification/recovery-vector-v1.json");
    if std::env::var_os("BUILD8_WRITE_PUBLIC_VECTOR").is_some() {
        std::fs::write(&path,serde_json::to_vec_pretty(&serde_json::json!({"schema":"BUILD8-PUBLIC-TEST-VECTOR-V1","production_authority":false,"test_signing_seed_hex":"42".repeat(32),"public_key":hex::encode(k.verifying_key().to_bytes()),"body_cbor":hex::encode(c.body.encode()),"signing_digest":hex::encode(c.body.digest()),"signature":hex::encode(c.signature),"certificate_cbor":hex::encode(c.encode())})).unwrap()).unwrap();
    }
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(v["certificate_cbor"], hex::encode(c.encode()));
    assert_eq!(v["signing_digest"], hex::encode(c.body.digest()));
}
