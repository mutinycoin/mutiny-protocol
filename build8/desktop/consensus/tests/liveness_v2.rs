use mutiny_consensus_v8::{
    anchors::FinalizedAnchor, continuity_v2::ParentVoter, liveness_v2::*,
    votes_v2::HeightAuthority, *,
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, Role};
use primitive_types::U256;
fn fixture() -> (Vec<HybridKey>, HeightAuthority) {
    let keys: Vec<_> = (0..4)
        .map(|_| HybridKey::generate(Role::Continuity).unwrap())
        .collect();
    let voters = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let n = i as u8 + 1;
            let tpm = p256::ecdsa::SigningKey::from_bytes((&[n; 32]).into()).unwrap();
            (
                [n; 32],
                ParentVoter {
                    lineage: [n; 32],
                    admitted: true,
                    physical: true,
                    eligible: true,
                    revoked: false,
                    hardware_generation: 1,
                    key_generation: 1,
                    tpm_public: tpm
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                    profile: [n; 32],
                    public: k.public().clone(),
                    reputation: U256::one(),
                },
            )
        })
        .collect();
    (
        keys,
        HeightAuthority {
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
            activation_rule: None,
            voters,
        },
    )
}
fn proof(d: certificates::Decision, a: &HeightAuthority, keys: &[HybridKey]) -> Proof {
    let fragments = keys
        .iter()
        .take(3)
        .enumerate()
        .map(|(i, k)| {
            let node = [i as u8 + 1; 32];
            let v = &a.voters[&node];
            let mut f = Fragment {
                node,
                hardware_generation: 1,
                key_generation: 1,
                vote_sequence: 0,
                tpm_identity: v.tpm_identity(),
                profile: v.profile,
                signature: HybridSignature {
                    ed448: [0; 114],
                    fndsa: [0; 1280],
                },
            };
            f.sign(&d, k).unwrap();
            f
        })
        .collect();
    Proof {
        decision: d,
        fragments,
    }
}
#[test]
fn hybrid_probes_require_exact_physical_parent_quorum_and_separate_domain() {
    let (keys, a) = fixture();
    let root = [7; 32];
    let d = WorkGate::new(a.clone(), root, 0)
        .unwrap()
        .request(0, [8; 32])
        .unwrap()
        .unwrap();
    let p = proof(d, &a, &keys);
    p.verify(&a, root).unwrap();
    let raw = p.encode().unwrap();
    assert_eq!(Proof::decode(&raw).unwrap(), p);
    if std::env::var_os("BUILD8_EXPORT_SYNTHETIC_WORK_PROBE_V2").is_some() {
        use std::io::Write;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/work-liveness-hybrid-public-v1.json");
        let rows: Vec<_> = a
            .voters
            .iter()
            .map(|(node, v)| {
                serde_json::json!({
            "node":hex::encode(node),"lineage":hex::encode(v.lineage),
            "descriptor":hex::encode(v.public.descriptor(v.key_generation).unwrap()),
            "hardware_generation":v.hardware_generation,"tpm_public":hex::encode(v.tpm_public),
            "profile":hex::encode(v.profile),"weight":1})
            })
            .collect();
        let fixture = serde_json::json!({"synthetic_only":true,"production_authorized":false,
            "parent":hex::encode(a.parent.encode()),"root":hex::encode(root),
            "roots":a.roots().map(hex::encode),"proof":hex::encode(&raw),"voters":rows});
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        out.write_all(&serde_json::to_vec_pretty(&fixture).unwrap())
            .unwrap();
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Proof::decode(&trailing).is_err());
    assert!(Proof::decode(&vec![0; continuity_v2::MAX_CERTIFICATE_BYTES + 1]).is_err());
    let mut short = p.clone();
    short.fragments.pop();
    assert!(short.verify(&a, root).is_err());
    let mut exact_two_thirds = a.clone();
    exact_two_thirds.voters.remove(&[4; 32]);
    assert!(short.verify(&exact_two_thirds, root).is_err());
    let mut duplicate = p.clone();
    duplicate.fragments[1] = duplicate.fragments[0].clone();
    assert!(duplicate.encode().is_err());
    let mut reversed = p.clone();
    reversed.fragments.reverse();
    assert!(reversed.encode().is_err());
    for field in 0..23 {
        let mut bad = p.clone();
        match field {
            0 => bad.fragments[0].signature.ed448[0] ^= 1,
            1 => bad.fragments[0].signature.fndsa[0] ^= 1,
            2 => bad.fragments[0].node = [9; 32],
            3 => bad.fragments[0].hardware_generation += 1,
            4 => bad.fragments[0].key_generation += 1,
            5 => bad.fragments[0].vote_sequence += 1,
            6 => bad.fragments[0].tpm_identity[0] ^= 1,
            7 => bad.fragments[0].profile[0] ^= 1,
            8 => bad.decision.network ^= 1,
            9 => bad.decision.genesis[0] ^= 1,
            10 => bad.decision.fingerprint[0] ^= 1,
            11 => bad.decision.purpose = 2,
            12 => bad.decision.height += 1,
            13 => bad.decision.parent[0] ^= 1,
            14 => bad.decision.previous_finalized_anchor[0] ^= 1,
            15 => bad.decision.state[0] ^= 1,
            16 => bad.decision.membership[0] ^= 1,
            17 => bad.decision.reputation[0] ^= 1,
            18 => bad.decision.attestation[0] ^= 1,
            19 => bad.decision.mining_epoch = 1,
            20 => bad.decision.round = 1,
            21 => bad.decision.step = 3,
            _ => bad.decision.continuity_period = 1,
        }
        assert!(bad.verify(&a, root).is_err(), "field {field}");
    }
    for flag in 0..5 {
        let mut changed = a.clone();
        let v = changed.voters.get_mut(&[1; 32]).unwrap();
        match flag {
            0 => v.physical = false,
            1 => v.admitted = false,
            2 => v.revoked = true,
            3 => v.eligible = false,
            _ => v.reputation = U256::zero(),
        }
        assert!(p.verify(&changed, root).is_err());
    }
    let f = &p.fragments[0];
    let body = f.unsigned(&p.decision).unwrap();
    assert!(
        keys[0]
            .public()
            .verify(Domain::ContinuityVote, &body, &f.signature)
            .is_err()
    );
    let mut cross = p.clone();
    cross.fragments[0].signature = keys[0].sign(Domain::ContinuityVote, &body).unwrap();
    assert!(cross.verify(&a, root).is_err());
    let wallet = HybridKey::generate(Role::Node).unwrap();
    assert!(cross.fragments[0].sign(&p.decision, &wallet).is_err());
    let mut offline = a.clone();
    offline.voters.get_mut(&[4; 32]).unwrap().reputation = U256::from(100);
    assert!(p.verify(&offline, root).is_err());
    let mut alias = a.clone();
    alias.voters.get_mut(&[4; 32]).unwrap().public = keys[0].public().clone();
    assert!(WorkGate::new(alias, root, 0).is_err());
}
#[test]
fn lease_deadline_replay_restart_parent_change_and_clock_regression_fail_closed() {
    let (keys, a) = fixture();
    let root = [7; 32];
    let mut gate = WorkGate::new(a.clone(), root, 0).unwrap();
    assert_eq!(gate.state(0).unwrap(), WorkState::Stopped);
    gate.set_run(true);
    assert_eq!(gate.state(0).unwrap(), WorkState::WaitingQuorum);
    assert!(gate.request(0, [0; 32]).is_err());
    let p = proof(gate.request(0, [8; 32]).unwrap().unwrap(), &a, &keys);
    assert!(gate.request(REFRESH_MS - 1, [9; 32]).unwrap().is_none());
    gate.accept(REFRESH_MS, &p).unwrap();
    assert_eq!(gate.state(REFRESH_MS).unwrap(), WorkState::Running);
    let ctx = pow::WorkContext {
        genesis: a.parent.genesis,
        fingerprint: a.parent.fingerprint,
        parent: a.parent.block,
        parent_height: 0,
        t0: 0,
        target: [255; 32],
        license: [1; 32],
        worker: [2; 32],
        coordinator: [3; 32],
        assignment_sequence: 1,
        last_accepted_ticket: 0,
        ancestor_timestamps: vec![],
    };
    assert_eq!(
        gate.work_lease(REFRESH_MS, &ctx).unwrap(),
        EXPIRY_MS - REFRESH_MS
    );
    assert!(gate.request(REFRESH_MS, [8; 32]).is_err());
    let later = proof(
        gate.request(REFRESH_MS, [9; 32]).unwrap().unwrap(),
        &a,
        &keys,
    );
    gate.accept(REFRESH_MS + 1, &later).unwrap();
    gate.accept(REFRESH_MS + 2, &p).unwrap();
    assert_eq!(
        gate.work_lease(REFRESH_MS + 2, &ctx).unwrap(),
        EXPIRY_MS - 2
    );
    gate.accept(EXPIRY_MS - 1, &p).unwrap();
    assert!(gate.accept(EXPIRY_MS, &p).is_err());
    assert_eq!(
        gate.state(REFRESH_MS + EXPIRY_MS - 1).unwrap(),
        WorkState::Running
    );
    assert_eq!(
        gate.state(REFRESH_MS + EXPIRY_MS).unwrap(),
        WorkState::WaitingQuorum
    );
    assert!(gate.accept(REFRESH_MS + EXPIRY_MS, &later).is_err());
    let mut restarted = WorkGate::new(a.clone(), root, 0).unwrap();
    restarted.set_run(true);
    assert!(restarted.accept(1, &p).is_err());
    assert_eq!(restarted.state(1).unwrap(), WorkState::WaitingQuorum);
    let again = proof(restarted.request(2, [10; 32]).unwrap().unwrap(), &a, &keys);
    restarted.accept(3, &again).unwrap();
    assert!(restarted.state(2).is_err());
    assert!(restarted.accept(3, &again).is_err());
    assert_eq!(restarted.state(3).unwrap(), WorkState::WaitingQuorum);
    let next = proof(restarted.request(3, [11; 32]).unwrap().unwrap(), &a, &keys);
    restarted.accept(4, &next).unwrap();
    let mut invalid = a.clone();
    invalid.parent.network = 0;
    assert!(restarted.parent_changed(invalid, root, 5).is_err());
    assert_eq!(restarted.state(5).unwrap(), WorkState::WaitingQuorum);
    assert!(restarted.request(5, [12; 32]).is_err());
    assert!(restarted.accept(5, &next).is_err());
    let mut changed = a.clone();
    changed.parent.block = [12; 32];
    changed.parent.height = 1;
    restarted.parent_changed(changed, root, 6).unwrap();
    assert_eq!(restarted.state(6).unwrap(), WorkState::WaitingQuorum);
    assert!(restarted.accept(6, &next).is_err());
    restarted.set_run(false);
    assert_eq!(restarted.state(6).unwrap(), WorkState::Stopped);
    assert!(restarted.parent_changed(a.clone(), root, 5).is_err());
    assert!(restarted.request(6, [13; 32]).is_err());
    restarted.parent_changed(a, root, 6).unwrap();
    assert!(restarted.request(6, [13; 32]).unwrap().is_some());
}
#[test]
fn maximum_proof_encoding_is_bounded_not_a_claim_of_signature_validity() {
    let (keys, a) = fixture();
    let d = WorkGate::new(a.clone(), [7; 32], 0)
        .unwrap()
        .request(0, [8; 32])
        .unwrap()
        .unwrap();
    let mut p = proof(d, &a, &keys);
    let mut f = p.fragments[0].clone();
    f.hardware_generation = u64::MAX;
    f.key_generation = u64::MAX;
    f.vote_sequence = u64::MAX;
    p.fragments = (1u32..=1024)
        .map(|i| {
            let mut v = f.clone();
            v.node = [0; 32];
            v.node[28..].copy_from_slice(&i.to_be_bytes());
            v
        })
        .collect();
    let raw = p.encode().unwrap();
    assert!(raw.len() <= continuity_v2::MAX_CERTIFICATE_BYTES);
    assert_eq!(Proof::decode(&raw).unwrap(), p);
    let mut extra = f;
    extra.node = [255; 32];
    p.fragments.push(extra);
    assert!(p.encode().is_err());
}

struct ProbeBackend {
    key: HybridKey,
    counter: u64,
    calls: u64,
    mode: u8,
}
impl counter_store::MonotonicCounter for ProbeBackend {
    fn read(&mut self) -> std::result::Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> std::result::Result<(), String> {
        panic!("liveness must not increment NV")
    }
}
impl counter_voter_v2::CounterSigningBackend for ProbeBackend {
    fn public_key(&self) -> &mutiny_crypto_v2::PublicKey {
        self.key.public()
    }
    fn sign_vote(&mut self, _: &[u8]) -> std::result::Result<HybridSignature, String> {
        panic!("liveness used vote signer")
    }
    fn sign_work_probe(
        &mut self,
        d: &certificates::Decision,
        f: &Fragment,
    ) -> std::result::Result<HybridSignature, String> {
        self.calls += 1;
        let mut signature = self
            .key
            .sign(Domain::ContinuityWorkProbe, &f.unsigned(d).unwrap())
            .map_err(|_| "sign")?;
        match self.mode {
            1 => signature.fndsa[0] ^= 1,
            2 => self.counter += 1,
            3 => panic!("synthetic post-private-operation panic"),
            _ => {}
        }
        Ok(signature)
    }
}
#[test]
fn counter_owned_probe_signing_preserves_snapshot_and_latches_private_failures() {
    for mode in 0..=3 {
        let (mut keys, a) = fixture();
        let mut backend = ProbeBackend {
            key: keys.remove(0),
            counter: 100,
            calls: 0,
            mode,
        };
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "build8-synthetic-probe-custody-{}.sqlite",
            hex::encode(nonce)
        ));
        let mut voter = counter_voter_v2::CounterVoter::open(
            &path,
            a.clone(),
            [1; 32],
            Some(100),
            &mut backend,
        )
        .unwrap();
        let progress = voter.progress().unwrap();
        let snapshot = std::fs::read(&path).unwrap();
        let d = WorkGate::new(a.clone(), [7; 32], 0)
            .unwrap()
            .request(0, [8; 32])
            .unwrap()
            .unwrap();
        let mut bad = d.clone();
        bad.step = 3;
        assert!(voter.sign_work_probe(&bad, [7; 32], &mut backend).is_err());
        assert_eq!(backend.calls, 0);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            voter.sign_work_probe(&d, [7; 32], &mut backend)
        }));
        if mode == 0 {
            let f = outcome.unwrap().unwrap();
            f.verify(&d, &a, [7; 32]).unwrap();
            assert_eq!(voter.progress().unwrap(), progress);
            assert_eq!(voter.last_sequence(), 0);
            assert_eq!(backend.counter, 100);
            voter.sign_work_probe(&d, [7; 32], &mut backend).unwrap();
            assert_eq!(backend.calls, 2);
        } else {
            if mode == 3 {
                assert!(outcome.is_err());
            } else {
                assert!(outcome.unwrap().is_err());
            }
            backend.mode = 0;
            assert!(voter.sign_work_probe(&d, [7; 32], &mut backend).is_err());
            assert_eq!(backend.calls, 1);
            assert!(voter.progress().is_err());
        }
        assert_eq!(std::fs::read(&path).unwrap(), snapshot);
        drop(voter);
        std::fs::remove_file(path).unwrap();
    }
}

#[path = "../../node/src/hybrid_work_probes_v2.rs"]
mod hybrid_work_probes_v2;
#[test]
fn bounded_exchange_checks_each_partial_and_never_renews_replayed_challenges() {
    use hybrid_work_probes_v2::WorkProbes;
    let (keys, a) = fixture();
    let root = [7; 32];
    let d = WorkGate::new(a.clone(), root, 0)
        .unwrap()
        .request(0, [8; 32])
        .unwrap()
        .unwrap();
    let p = proof(d.clone(), &a, &keys);
    let fragment = |i: usize| Proof {
        decision: d.clone(),
        fragments: vec![p.fragments[i].clone()],
    };
    let mut pool = WorkProbes::default();
    pool.begin(d.clone(), &a, root, 0).unwrap();
    assert!(pool.quorum(&a, root, 0).unwrap().is_none());
    assert!(pool.signed(None, p.clone(), &a, root, 0).is_err());
    let mut invalid = fragment(0);
    invalid.fragments[0].signature.fndsa[0] ^= 1;
    assert!(pool.signed(None, invalid, &a, root, 0).is_err());
    for i in 0..2 {
        pool.signed(None, fragment(i), &a, root, 0).unwrap();
    }
    assert!(pool.quorum(&a, root, 0).unwrap().is_none());
    pool.signed(None, fragment(0), &a, root, 0).unwrap();
    assert!(pool.quorum(&a, root, 0).unwrap().is_none());
    pool.signed(None, fragment(2), &a, root, 0).unwrap();
    assert_eq!(pool.quorum(&a, root, 0).unwrap().unwrap(), p);
    for peer in 1..=32 {
        pool.queue([peer; 32], d.clone(), &a, root, 0).unwrap();
    }
    assert!(pool.queue([33; 32], d.clone(), &a, root, 0).is_err());
    assert!(pool.queue([0; 32], d.clone(), &a, root, 0).is_err());
    let pending = pool.pending([4; 32], &a, root, 0).unwrap();
    assert_eq!(pending.len(), 3);
    pool.signed(Some([1; 32]), fragment(0), &a, root, 0)
        .unwrap();
    assert_eq!(
        pool.response([1; 32], &a, root, 0).unwrap().unwrap(),
        fragment(0)
    );
    let mut new = d.clone();
    new.block = [9; 32];
    assert!(pool.queue([1; 32], new.clone(), &a, root, 999).is_err());
    pool.queue([1; 32], new, &a, root, 1000).unwrap();
    assert!(
        pool.signed(Some([1; 32]), fragment(0), &a, root, 1000)
            .is_err()
    );
    // Repeated identical begin/queue leaves original expiry unchanged.
    pool.begin(d.clone(), &a, root, EXPIRY_MS - 1).unwrap();
    pool.queue([2; 32], d.clone(), &a, root, EXPIRY_MS - 1)
        .unwrap();
    assert!(pool.quorum(&a, root, EXPIRY_MS - 1).unwrap().is_some());
    assert!(pool.quorum(&a, root, EXPIRY_MS).unwrap().is_none());
    assert!(
        pool.response([2; 32], &a, root, EXPIRY_MS)
            .unwrap()
            .is_none()
    );
    assert!(pool.signed(None, fragment(0), &a, root, EXPIRY_MS).is_err());
    pool.queue([33; 32], d.clone(), &a, root, EXPIRY_MS)
        .unwrap();
    assert!(pool.pending([1; 32], &a, root, 0).is_err());
    assert!(
        pool.pending([1; 32], &a, root, EXPIRY_MS)
            .unwrap()
            .is_empty()
    );
    pool.begin(d.clone(), &a, root, EXPIRY_MS).unwrap();
    pool.signed(None, fragment(0), &a, root, EXPIRY_MS).unwrap();
    let mut changed = a.clone();
    changed.parent.block[0] ^= 1;
    assert!(pool.quorum(&changed, root, EXPIRY_MS).unwrap().is_none());
    assert!(
        pool.signed(None, fragment(0), &changed, root, EXPIRY_MS)
            .is_err()
    );
}
