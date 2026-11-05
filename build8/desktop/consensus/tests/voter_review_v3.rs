//! Independent direct-public-API probes. Public deterministic software TEST-VALUE keys only;
//! real counter store, canonical vote/certificate encodings and signature verification.
//! Neither synthetic HeightAuthority nor FinalityLedger replaces canonical block execution.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    bft::Step,
    certificates::{Certificate, Decision, Signer, Voter},
    counter_store::MonotonicCounter,
    counter_voter::{CounterSigningBackend, CounterVoter, CounterVoterError},
    finality::{FinalityError, FinalityLedger},
    votes::HeightAuthority,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use primitive_types::U256;
use std::collections::BTreeMap;
#[path = "support/test_dir.rs"]
mod test_dir;

struct Backend {
    key: SigningKey,
    counter: u64,
    signs: u64,
}
impl MonotonicCounter for Backend {
    fn read(&mut self) -> Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> Result<(), String> {
        self.counter += 1;
        Ok(())
    }
}
impl CounterSigningBackend for Backend {
    fn public_key(&self) -> [u8; 33] {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }
    fn sign_digest(&mut self, digest: Hash) -> Result<[u8; 64], String> {
        self.signs += 1;
        let signature: Signature = self.key.sign_prehash(&digest).unwrap();
        Ok(signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into())
    }
}
fn parent() -> FinalizedAnchor {
    FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 0,
        block: [3; 32],
    }
}
fn registry(public_key: [u8; 33]) -> BTreeMap<Hash, Voter> {
    BTreeMap::from([(
        [7; 32],
        Voter {
            key_version: 1,
            public_key,
            weight: U256::one(),
        },
    )])
}

#[test]
fn direct_counter_request_conflict_burns_nothing_and_reopens_only_original() {
    let dir = test_dir::TestDir::new("review-direct-counter-conflict");
    let path = dir.file("voter.sqlite");
    eprintln!("PRESERVED_PUBLIC_COUNTER_FIXTURE {}", path.display());
    std::mem::forget(dir);
    let mut backend = Backend {
        key: SigningKey::from_bytes((&[31; 32]).into()).unwrap(),
        counter: 4100,
        signs: 0,
    };
    use mutiny_consensus_v8::{
        blocks::{BlockBody, GenesisDescriptor},
        execution::{State, WorkParent},
        genesis::GenesisIdentity,
        licenses::BindWorker,
        pow::{WorkAuthority, WorkHeader},
    };
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let raw = |value: &serde_json::Value| hex::decode(value.as_str().unwrap()).unwrap();
    let descriptor = GenesisDescriptor::decode(&raw(&vectors["descriptor_hex"])).unwrap();
    let identity = GenesisIdentity::new(descriptor.clone()).unwrap();
    let case = &vectors["cases"][0];
    let bindings: Vec<_> = case["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| BindWorker::decode(&raw(&value["binding_hex"])).unwrap())
        .collect();
    let state = State {
        licenses: identity.bind_workers(&bindings).unwrap(),
        ..State::default()
    };
    let header = WorkHeader::decode(&raw(&case["height1"]["header_hex"])).unwrap();
    let body = BlockBody::decode(&raw(&case["height1"]["body_hex"])).unwrap();
    let (work, signature) =
        WorkAuthority::from_envelope(&raw(&case["height1"]["authority_envelope_hex"])).unwrap();
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: identity.id(),
        fingerprint: descriptor.fingerprint,
        height: 0,
        block: descriptor.block_hash(state.root().unwrap()).unwrap(),
    };
    let work_parent = WorkParent {
        genesis: identity.id(),
        fingerprint: descriptor.fingerprint,
        block: parent.block,
        height: 0,
        t0: descriptor.timestamp,
        target: header.candidate.target,
        ancestor_timestamps: vec![descriptor.timestamp],
    };
    let authority = HeightAuthority {
        parent,
        membership: [4; 32],
        reputation: [5; 32],
        attestation: [6; 32],
        voters: registry(backend.public_key()),
    };
    let mut voter =
        CounterVoter::open(&path, authority.clone(), [7; 32], Some(4100), &mut backend).unwrap();
    let original = voter.sign(Step::Prevote, None, None, &mut backend).unwrap();
    voter
        .round_mut()
        .unwrap()
        .validate_proposal(&state, &work_parent, &header, &work, &signature, &body)
        .unwrap();
    let before = (backend.counter, backend.signs);
    assert!(matches!(
        voter.sign(Step::Prevote, Some(header.block_hash()), None, &mut backend),
        Err(CounterVoterError::ConflictingVote)
    ));
    assert_eq!(
        (backend.counter, backend.signs),
        before,
        "caller conflict burns no counter or signature"
    );
    assert!(
        voter.progress().is_err(),
        "live instance is poisoned in memory"
    );
    drop(voter);
    let mut reopened = CounterVoter::open(&path, authority, [7; 32], None, &mut backend).unwrap();
    assert_eq!(
        reopened
            .replay(Step::Prevote, &mut backend)
            .unwrap()
            .unwrap()
            .encode(),
        original.encode()
    );
    assert_eq!((backend.counter, backend.signs), before);
    reopened
        .round_mut()
        .unwrap()
        .validate_proposal(&state, &work_parent, &header, &work, &signature, &body)
        .unwrap();
    assert!(matches!(
        reopened.sign(Step::Prevote, Some(header.block_hash()), None, &mut backend),
        Err(CounterVoterError::ConflictingVote)
    ));
    assert_eq!((backend.counter, backend.signs), before);
}

#[test]
fn direct_finality_invalid_signature_creates_no_evidence_or_halt_but_valid_conflict_does() {
    let dir = test_dir::TestDir::new("review-direct-finality-conflict");
    let path = dir.file("finality.sqlite");
    eprintln!("PRESERVED_PUBLIC_FINALITY_FIXTURE {}", path.display());
    std::mem::forget(dir);
    let key = SigningKey::from_bytes((&[32; 32]).into()).unwrap();
    let public: [u8; 33] = key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let voters = registry(public);
    let parent = parent();
    let decision = Decision {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        purpose: 2,
        height: 1,
        mining_epoch: 0,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: [0x41; 32],
        state: [0x51; 32],
        membership: [4; 32],
        reputation: [5; 32],
        attestation: [6; 32],
    };
    let certify = |decision: Decision| {
        let signature: Signature = key
            .sign_prehash(&decision.signing_digest([7; 32], 1))
            .unwrap();
        Certificate {
            decision,
            signers: vec![Signer {
                node: [7; 32],
                key_version: 1,
                signature: signature
                    .normalize_s()
                    .unwrap_or(signature)
                    .to_bytes()
                    .into(),
            }],
        }
    };
    let first = certify(decision.clone());
    let mut conflict = decision.clone();
    conflict.block = [0x42; 32];
    conflict.state = [0x52; 32];
    conflict.round = 1;
    let valid_conflict = certify(conflict.clone());
    let mut forged = valid_conflict.clone();
    forged.signers[0].signature[0] ^= 1;
    let mut ledger = FinalityLedger::open(&path, &parent).unwrap();
    assert!(
        ledger
            .record_certificate(&first, &decision, &voters)
            .unwrap()
    );
    assert!(matches!(
        ledger.record_certificate(&forged, &conflict, &voters),
        Err(FinalityError::Certificate(_))
    ));
    assert!(!ledger.halted().unwrap());
    assert!(ledger.evidence(1, conflict.block).unwrap().is_none());
    assert!(matches!(
        ledger.record_certificate(&valid_conflict, &conflict, &voters),
        Err(FinalityError::IntegrityHalt)
    ));
    assert!(ledger.halted().unwrap());
    assert_eq!(
        ledger
            .evidence(1, decision.block)
            .unwrap()
            .unwrap()
            .encode()
            .unwrap(),
        first.encode().unwrap()
    );
    assert_eq!(
        ledger
            .evidence(1, conflict.block)
            .unwrap()
            .unwrap()
            .encode()
            .unwrap(),
        valid_conflict.encode().unwrap()
    );
    drop(ledger);
    let mut reopened = FinalityLedger::open(&path, &parent).unwrap();
    assert!(reopened.halted().unwrap());
    assert!(matches!(
        reopened.record_certificate(&first, &decision, &voters),
        Err(FinalityError::IntegrityHalt)
    ));
}
