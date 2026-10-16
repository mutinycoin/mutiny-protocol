use super::*;
use mutiny_consensus_v8::{
    block_envelope::BlockEnvelope,
    blocks::{GenesisDescriptor, state_root},
    execution::State,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
struct Fixture;
impl PhysicalAttestationVerifier for Fixture {
    fn verify(
        &self,
        _: &PhysicalMember,
        challenge: Hash,
        evidence: &[u8],
    ) -> mutiny_consensus_v8::Result<()> {
        if evidence == challenge {
            Ok(())
        } else {
            Err(mutiny_consensus_v8::Error::BadSignature)
        }
    }
}
struct Signer {
    key: SigningKey,
    acks: usize,
    quotes: usize,
}
impl ParticipationSigner for Signer {
    fn public_key(&self) -> [u8; 33] {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }
    fn acknowledgement(&mut self, ack: &ParticipationAck) -> Result<[u8; 64]> {
        self.acks += 1;
        let sig: Signature = self.key.sign_prehash(&ack.signing_digest()).unwrap();
        Ok(sig.normalize_s().unwrap_or(sig).to_bytes().into())
    }
    fn refresh_quote(&mut self, refresh: &AttestationRefresh) -> Result<Vec<u8>> {
        self.quotes += 1;
        Ok(refresh.challenge().to_vec())
    }
}
#[test]
fn rolling_generation_cache_restart_and_zero_weight_participation() {
    let mut lines = include_str!("../../qualification/integration-state-v2-1/chain.jsonl").lines();
    let v: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let descriptor = GenesisDescriptor::decode(&bytes(&v["descriptor"])).unwrap();
    let records: Vec<(Hash, Vec<u8>)> = v["initial_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (bytes(&r[0]).try_into().unwrap(), bytes(&r[1])))
        .collect();
    let mut state = State::from_records(&records, state_root(&records).unwrap()).unwrap();
    let member = state.continuity.as_ref().unwrap().members[0].clone();
    let physical = BTreeMap::from([(
        member.node,
        PhysicalMember {
            node: member.node,
            generation: member.generation,
            continuity_key: member.voting_key,
            hardware: member.hardware,
            admission_commitment: member.attestation,
            attestation_key: vec![6; 33],
        },
    )]);
    let mut random = [0; 8];
    getrandom::getrandom(&mut random).unwrap();
    let dir = std::env::temp_dir().join(format!("build8-participation-{}", hex::encode(random)));
    std::fs::create_dir(&dir).unwrap();
    let target = bytes(&v["initial_target"]).try_into().unwrap();
    let mut chain = CanonicalStore::open_trusted_genesis(
        &dir.join("chain.sqlite"),
        &descriptor,
        &state,
        target,
    )
    .unwrap();
    let path = dir.join("producer.sqlite");
    let gid = descriptor.id().unwrap();
    let fp = descriptor.fingerprint;
    let mut producer = Producer::open(&path, gid, fp, member.node).unwrap();
    let mut signer = Signer {
        key: SigningKey::from_bytes((&[17; 32]).into()).unwrap(),
        acks: 0,
        quotes: 0,
    };
    let first = producer
        .produce(&mut chain, &mut signer, &physical, &Fixture)
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(signer.acks, 1);
    drop(producer);
    let mut producer = Producer::open(&path, gid, fp, member.node).unwrap();
    assert_eq!(
        producer
            .produce(&mut chain, &mut signer, &physical, &Fixture)
            .unwrap(),
        first
    );
    assert_eq!(signer.acks, 1);
    for (i, row) in lines.take(60).enumerate() {
        let row: serde_json::Value = serde_json::from_str(row).unwrap();
        let block = BlockEnvelope::decode(&bytes(&row["envelope"])).unwrap();
        chain
            .commit_integrated(&block, &physical, &Fixture)
            .unwrap();
        let slot = i as u64 + 2;
        let ops = producer
            .produce(&mut chain, &mut signer, &physical, &Fixture)
            .unwrap();
        assert_eq!(ParticipationAck::decode(&ops[0]).unwrap().height, slot);
        assert_eq!(ops.len(), if (50..=60).contains(&slot) { 2 } else { 1 });
        if ops.len() == 2 {
            let refresh = AttestationRefresh::decode(&ops[1]).unwrap();
            assert_eq!(refresh.height, slot);
            assert_eq!(
                refresh.parent_anchor,
                FinalizedAnchor {
                    network: NETWORK_ID,
                    genesis: gid,
                    fingerprint: fp,
                    height: slot - 1,
                    block: block.block_hash()
                }
                .id()
            );
        }
    }
    assert_eq!(signer.acks, 61);
    assert_eq!(signer.quotes, 11);
    let counts = (signer.acks, signer.quotes);
    producer
        .produce(&mut chain, &mut signer, &physical, &Fixture)
        .unwrap();
    assert_eq!((signer.acks, signer.quotes), counts);
    drop(producer);
    drop(chain);
    // Typed zero-weight parent snapshot fixture, not an actual Genesis ceremony.
    state.continuity.as_mut().unwrap().first_period_committed = true;
    assert!(
        state.continuity.as_ref().unwrap().voters().unwrap()[&member.node]
            .weight
            .is_zero()
    );
    let anchor = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: gid,
        fingerprint: fp,
        height: 0,
        block: descriptor.block_hash(state.root().unwrap()).unwrap(),
    };
    let mut producer =
        Producer::open(&dir.join("zero-producer.sqlite"), gid, fp, member.node).unwrap();
    assert_eq!(
        producer
            .produce_parent(&anchor, &state, &mut signer, &physical, &Fixture)
            .unwrap()
            .len(),
        1
    );
    // Parent-state unit fixture: clearing freshness must produce only a refresh,
    // never same-block acknowledgement eligibility. No invalid Genesis is opened.
    state.accounting.freshness.clear();
    let before = signer.acks;
    let ops = producer
        .produce_parent(&anchor, &state, &mut signer, &physical, &Fixture)
        .unwrap();
    assert_eq!(ops.len(), 1);
    assert!(AttestationRefresh::decode(&ops[0]).is_ok());
    assert_eq!(signer.acks, before);
    drop(producer);
    for entry in std::fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        std::fs::remove_file(entry.path()).unwrap();
    }
    std::fs::remove_dir(dir).unwrap();
}
