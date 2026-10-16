//! Explicit fixture replay tool, not a production node or an admission service.
use mutiny_consensus_v8::{
    Error, Hash, Result,
    block_envelope::BlockEnvelope,
    blocks::GenesisDescriptor,
    canonical_store::CanonicalStore,
    execution::State,
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    tpm::{PinnedTpmVerifier, TpmProfile},
};
use std::{collections::BTreeMap, io::BufRead};
struct FixtureEvidence;
enum Evidence {
    Fixture,
    Physical(PinnedTpmVerifier),
}
impl PhysicalAttestationVerifier for Evidence {
    fn verify(&self, m: &PhysicalMember, c: Hash, e: &[u8]) -> Result<()> {
        match self {
            Self::Fixture => FixtureEvidence.verify(m, c, e),
            Self::Physical(v) => v.verify(m, c, e),
        }
    }
}
impl PhysicalAttestationVerifier for FixtureEvidence {
    fn verify(&self, _: &PhysicalMember, challenge: Hash, evidence: &[u8]) -> Result<()> {
        if evidence == challenge {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}
fn raw(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(
        args.len() == 3 || args.len() == 4,
        "qualification_replay chain.jsonl new-output-directory [physical-profile-commitment-hex]"
    );
    let directory = std::path::Path::new(&args[2]);
    std::fs::create_dir(directory).expect("new output directory required");
    let mut lines = std::io::BufReader::new(std::fs::File::open(&args[1]).unwrap()).lines();
    let fixture: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_ne!(
        fixture["actual_genesis"], true,
        "qualification tool cannot seal Genesis"
    );
    let physical_evidence = fixture["physical_evidence_fixture_only"] == false;
    let profile = if physical_evidence {
        // Physical evidence is read from the incoming bundle at runtime (no host profile is
        // compiled in). The profile is fully verified by `decode`; every member must commit to
        // it. Optional operator pin: pass a 64-hex commitment as the fourth argument.
        let p = TpmProfile::decode(&raw(&fixture["physical_profile"]["profile"])).unwrap();
        assert!(!p.is_test_value(), "software test-value profile is not physical evidence");
        let commitment = p.commitment().unwrap();
        if let Some(pin) = args.get(3) {
            assert_eq!(hex::decode(pin).unwrap(), commitment, "physical profile pin mismatch");
        }
        Some(p)
    } else {
        None
    };
    let descriptor = GenesisDescriptor::decode(&raw(&fixture["descriptor"])).unwrap();
    let records: Vec<(Hash, Vec<u8>)> = fixture["initial_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r[0]).try_into().unwrap(), raw(&r[1])))
        .collect();
    let initial = State::from_records(
        &records,
        mutiny_consensus_v8::blocks::state_root(&records).unwrap(),
    )
    .unwrap();
    if let Some(p) = &profile {
        let commitment = p.commitment().unwrap();
        let members = &initial.continuity.as_ref().unwrap().members;
        assert!(!members.is_empty() && members.iter().all(|m| m.attestation == commitment));
    }
    let physical: BTreeMap<_, _> = initial
        .continuity
        .as_ref()
        .unwrap()
        .members
        .iter()
        .map(|m| {
            (
                m.node,
                PhysicalMember {
                    node: m.node,
                    generation: m.generation,
                    continuity_key: m.voting_key,
                    hardware: m.hardware,
                    admission_commitment: m.attestation,
                    attestation_key: profile
                        .as_ref()
                        .map(|p| p.ak_public.clone())
                        .unwrap_or(vec![6; 33]),
                },
            )
        })
        .collect();
    let verifier = if let Some(p) = profile {
        Evidence::Physical(PinnedTpmVerifier {
            profiles: BTreeMap::from([(p.commitment().unwrap(), p)]),
        })
    } else {
        Evidence::Fixture
    };
    if physical_evidence {
        assert_eq!(raw(&fixture["genesis_prestate"]), descriptor.id().unwrap());
        let member = physical.values().next().unwrap();
        let record = mutiny_consensus_v8::freshness::validate_genesis(
            descriptor.id().unwrap(),
            raw(&fixture["genesis_nonce"]).try_into().unwrap(),
            member,
            &raw(&fixture["genesis_evidence"]),
            &verifier,
        )
        .unwrap();
        assert_eq!(
            &record,
            initial.accounting.freshness.get(&member.node).unwrap()
        );
    }
    let target = raw(&fixture["initial_target"]).try_into().unwrap();
    let path = directory.join("chain.sqlite");
    let mut store =
        CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, target).unwrap();
    for line in lines {
        let row: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let block = BlockEnvelope::decode(&raw(&row["envelope"])).unwrap();
        assert!(
            store
                .commit_integrated(&block, &physical, &verifier)
                .unwrap()
        );
        let (head, state) = store.load().unwrap();
        assert_eq!(head.root.as_slice(), raw(&row["state_root"]));
        assert_eq!(head.next_target.as_slice(), raw(&row["next_target"]));
        assert_eq!(state.root().unwrap(), head.root);
        if head.height == 60 || head.height == 101 {
            drop(store);
            store =
                CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, target).unwrap();
        }
    }
    let (head, state) = store.load().unwrap();
    assert_eq!(head.height, 180);
    let report = serde_json::json!({"schema":"BUILD8-NATIVE-INTEGRATED-REPLAY-V1","result":"PASS","height":head.height,
        "block_hash":hex::encode(head.block),"state_root":hex::encode(head.root),"next_target":hex::encode(head.next_target),
        "qualified_periods":state.continuity.unwrap().members[0].history.p,"fixture_only":true,"production_admission":false,
        "physical_tpm_evidence_verified":physical_evidence});
    std::fs::write(
        directory.join("result.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("{report}");
}
