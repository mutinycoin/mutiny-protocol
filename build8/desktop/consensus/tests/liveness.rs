use mutiny_consensus_v8::{
    anchors::FinalizedAnchor, certificates::*, liveness::*, votes::HeightAuthority, *,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use primitive_types::U256;
struct ProbeBackend {
    key: SigningKey,
    calls: u64,
}
impl mutiny_consensus_v8::counter_store::MonotonicCounter for ProbeBackend {
    fn read(&mut self) -> std::result::Result<u64, String> {
        Ok(100)
    }
    fn increment(&mut self) -> std::result::Result<(), String> {
        panic!("Liveness must not increment voting NV counter")
    }
}
impl mutiny_consensus_v8::counter_voter::CounterSigningBackend for ProbeBackend {
    fn public_key(&self) -> [u8; 33] {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }
    fn sign_digest(&mut self, digest: Hash) -> std::result::Result<[u8; 64], String> {
        self.calls += 1;
        let s: Signature = self.key.sign_prehash(&digest).unwrap();
        Ok(s.normalize_s().unwrap_or(s).to_bytes().into())
    }
}
#[test]
fn strict_parent_quorum_replay_delay_expiry_restart_and_run_state() {
    let keys: Vec<_> = (1..=4)
        .map(|n| SigningKey::from_bytes((&[n; 32]).into()).unwrap())
        .collect();
    let authority = HeightAuthority {
        parent: FinalizedAnchor {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 0,
            block: [3; 32],
        },
        membership: [4; 32],
        reputation: [5; 32],
        attestation: [6; 32],
        voters: keys
            .iter()
            .enumerate()
            .map(|(n, k)| {
                (
                    [n as u8; 32],
                    Voter {
                        key_version: 1,
                        public_key: k
                            .verifying_key()
                            .to_encoded_point(true)
                            .as_bytes()
                            .try_into()
                            .unwrap(),
                        weight: U256::one(),
                    },
                )
            })
            .collect(),
    };
    let proof = |decision: Decision, count: usize| Certificate {
        signers: keys
            .iter()
            .take(count)
            .enumerate()
            .map(|(n, k)| {
                let node = [n as u8; 32];
                let s: Signature = k.sign_prehash(&decision.signing_digest(node, 1)).unwrap();
                Signer {
                    node,
                    key_version: 1,
                    signature: s.normalize_s().unwrap_or(s).to_bytes().into(),
                }
            })
            .collect(),
        decision,
    };
    let mut gate = WorkGate::new(authority.clone(), [7; 32], 0).unwrap();
    gate.set_run(true);
    assert_eq!(gate.state(0).unwrap(), WorkState::WaitingQuorum);
    let request = gate.request(0, [8; 32]).unwrap().unwrap();
    let mut backend = ProbeBackend {
        key: keys[0].clone(),
        calls: 0,
    };
    let fragment = sign_probe(&request, &authority, [7; 32], [0; 32], &mut backend).unwrap();
    assert_eq!(backend.calls, 1);
    assert_eq!(
        Certificate {
            decision: request.clone(),
            signers: vec![fragment]
        }
        .verify_quorum(&request, &authority.voters),
        Err(Error::NoQuorum)
    );
    for field in 0..15 {
        let mut bad = request.clone();
        match field {
            0 => bad.network ^= 1,
            1 => bad.genesis[0] ^= 1,
            2 => bad.fingerprint[0] ^= 1,
            3 => bad.purpose = 2,
            4 => bad.height += 1,
            5 => bad.mining_epoch = 1,
            6 => bad.continuity_period = 1,
            7 => bad.round = 1,
            8 => bad.step = 3,
            9 => bad.previous_finalized_anchor[0] ^= 1,
            10 => bad.parent[0] ^= 1,
            11 => bad.block = [0; 32],
            12 => bad.membership[0] ^= 1,
            13 => bad.reputation[0] ^= 1,
            _ => bad.attestation[0] ^= 1,
        }
        assert!(sign_probe(&bad, &authority, [7; 32], [0; 32], &mut backend).is_err());
    }
    assert!(sign_probe(&request, &authority, [99; 32], [0; 32], &mut backend).is_err());
    assert!(sign_probe(&request, &authority, [7; 32], [1; 32], &mut backend).is_err());
    let mut zero = authority.clone();
    zero.voters.get_mut(&[0; 32]).unwrap().weight = U256::zero();
    assert!(sign_probe(&request, &zero, [7; 32], [0; 32], &mut backend).is_err());
    assert_eq!(backend.calls, 1); // Bad context never reaches TPM signing.
    assert!(gate.accept(1, &proof(request.clone(), 2)).is_err());
    gate.accept(2, &proof(request.clone(), 3)).unwrap();
    assert_eq!(gate.state(2).unwrap(), WorkState::Running);
    assert!(gate.request(119999, [9; 32]).unwrap().is_none());
    let second = gate.request(120000, [9; 32]).unwrap().unwrap();
    // Late old proof cannot extend the first issuance's expiration.
    gate.accept(359999, &proof(request.clone(), 3)).unwrap();
    assert_eq!(gate.state(360000).unwrap(), WorkState::WaitingQuorum);
    assert!(gate.accept(360000, &proof(request, 3)).is_err());
    gate.accept(360000, &proof(second.clone(), 3)).unwrap();
    assert_eq!(gate.state(479999).unwrap(), WorkState::Running);
    assert_eq!(gate.state(480000).unwrap(), WorkState::WaitingQuorum);
    let third = gate.request(480000, [10; 32]).unwrap().unwrap();
    let mut wrong = third.clone();
    wrong.purpose = 2;
    wrong.step = 3;
    assert!(gate.accept(480001, &proof(wrong, 3)).is_err());
    gate.accept(480002, &proof(third, 3)).unwrap();
    gate.parent_changed(authority.clone(), [99; 32], 480003)
        .unwrap();
    assert_eq!(gate.state(480003).unwrap(), WorkState::WaitingQuorum);
    assert!(gate.accept(480003, &proof(second, 3)).is_err());
    let mut restart = WorkGate::new(authority, [7; 32], 0).unwrap();
    restart.set_run(true);
    assert_eq!(restart.state(0).unwrap(), WorkState::WaitingQuorum);
    restart.set_run(false);
    assert_eq!(restart.state(1).unwrap(), WorkState::Stopped);
    assert!(restart.state(0).is_err());
}
