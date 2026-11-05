use mutiny_consensus_v8::{
    NETWORK_ID,
    anchors::FinalizedAnchor,
    bft::Step,
    continuity_v2::ParentVoter,
    counter_store::MonotonicCounter,
    counter_voter_v2::CounterVoter,
    votes_v2::{AuthenticatedRound, HeightAuthority},
};
use mutiny_crypto_v2::{HybridKey, Role};
use mutinyd_v8::continuity_custody_v2::{EncryptedVoteBackend, Pins};
use std::{cell::Cell, rc::Rc};
struct Counter(Rc<Cell<u64>>);
impl MonotonicCounter for Counter {
    fn read(&mut self) -> Result<u64, String> {
        Ok(self.0.get())
    }
    fn increment(&mut self) -> Result<(), String> {
        self.0.set(self.0.get().checked_add(1).ok_or("overflow")?);
        Ok(())
    }
}
#[test]
fn admitted_zero_weight_custody_does_not_grant_voting_authority() {
    let key = HybridKey::generate(Role::Continuity).unwrap();
    let weighted = HybridKey::generate(Role::Continuity).unwrap();
    let tpm = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let zero = ParentVoter {
        lineage: [7; 32],
        admitted: true,
        physical: true,
        eligible: true,
        revoked: false,
        hardware_generation: 1,
        key_generation: 1,
        tpm_public: tpm,
        profile: [10; 32],
        public: key.public().clone(),
        reputation: 0u64.into(),
    };
    let positive = ParentVoter {
        lineage: [8; 32],
        public: weighted.public().clone(),
        reputation: 1u64.into(),
        ..zero.clone()
    };
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
        activation_rule: None,
        voters: [([7; 32], zero), ([8; 32], positive)].into_iter().collect(),
    };
    let round = AuthenticatedRound::new(authority.clone()).unwrap();
    let pins = Pins::from_round(&round, [7; 32]).unwrap();
    let cipher = key
        .seal_for("public synthetic zero-weight password", 1, &pins.context())
        .unwrap();
    let value = Rc::new(Cell::new(100));
    let mut backend = EncryptedVoteBackend::unlock(
        pins,
        Counter(value.clone()),
        &cipher,
        "public synthetic zero-weight password",
    )
    .unwrap();
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-synthetic-zero-custody-{}.sqlite",
        hex::encode(nonce)
    ));
    let mut voter =
        CounterVoter::open(&path, authority.clone(), [7; 32], Some(100), &mut backend).unwrap();
    assert!(voter.sign(Step::Prevote, None, None, &mut backend).is_err());
    assert_eq!(value.get(), 100);
    drop(voter);
    std::fs::remove_file(path).unwrap();
    for mode in 0..4 {
        let mut invalid = authority.clone();
        let v = invalid.voters.get_mut(&[7; 32]).unwrap();
        match mode {
            0 => v.physical = false,
            1 => v.admitted = false,
            2 => v.revoked = true,
            _ => v.eligible = false,
        }
        let round = AuthenticatedRound::new(invalid).unwrap();
        assert!(Pins::from_round(&round, [7; 32]).is_err());
    }
}
