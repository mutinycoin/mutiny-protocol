//! Real physical signatures and counter custody, isolated pre-Genesis context.
//! QUALIFICATION TOOLING ONLY. Every host-specific input is explicit at runtime:
//!   qualification_physical_voter <new-output-dir> <physical-profile-fixture.json>
//!       <helper-spec.json> <custody-manifest.json> <expected-initial-counter>
//! (formats: examples/support/external_helper_bridge.rs). Nothing here is compiled into a node.
#[path = "support/external_helper_bridge.rs"]
mod external_helper_bridge;
use external_helper_bridge::{ExpectedCustody, ExternalHelperBridge, HelperSpec};
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    bft::Step,
    certificates::Voter,
    counter_store::MonotonicCounter,
    counter_voter::{CounterSigningBackend, CounterVoter},
    freshness::*,
    tpm::{PinnedTpmVerifier, TpmProfile},
    votes::HeightAuthority,
    *,
};
use primitive_types::U256;
use serde_json::json;
use std::{collections::BTreeMap, path::PathBuf};
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        6,
        "usage: qualification_physical_voter <new-output-dir> <physical-profile-fixture.json> <helper-spec.json> <custody-manifest.json> <expected-initial-counter>"
    );
    let spec = HelperSpec::load(std::path::Path::new(&args[3])).unwrap();
    let expected = ExpectedCustody::load(std::path::Path::new(&args[4])).unwrap();
    let expected_initial: u64 = args[5].parse().expect("expected initial counter (u64)");
    let directory = PathBuf::from(&args[1]);
    assert!(!directory.exists());
    std::fs::create_dir(&directory).unwrap();
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
    let profile =
        TpmProfile::decode(&hex::decode(fixture["profile"].as_str().unwrap()).unwrap()).unwrap();
    assert!(!profile.is_test_value(), "a TEST-VALUE profile is not physical evidence");
    let mut bridge = ExternalHelperBridge::open(&spec, &expected, Some(expected_initial)).unwrap();
    let mut verifier = PinnedTpmVerifier {
        profiles: BTreeMap::new(),
    };
    let commitment = profile.commitment().unwrap();
    let member = PhysicalMember {
        node: [0x51; 32],
        generation: 0,
        continuity_key: bridge.public_key(),
        hardware: profile.hardware,
        admission_commitment: commitment,
        attestation_key: profile.ak_public.clone(),
    };
    verifier.profiles.insert(commitment, profile);
    let prestate = domain_hash(
        b"MUTINY-BUILD8-GENESIS-DESCRIPTOR-V1",
        b"qualification-only physical signer fixture",
    );
    let mut nonce: Hash = [0; 32];
    getrandom::getrandom(&mut nonce).unwrap();
    let challenge = genesis_challenge(prestate, nonce, &member);
    let evidence = bridge.quote(challenge).unwrap();
    let fresh = validate_genesis(prestate, nonce, &member, &evidence, &verifier).unwrap();
    assert!(
        [1, 60]
            .into_iter()
            .all(|h| fresh.eligible(member.node, 0, member.continuity_key, h))
    );
    assert!(!fresh.eligible(member.node, 0, member.continuity_key, 61));
    let authority = || HeightAuthority {
        parent: FinalizedAnchor {
            network: NETWORK_ID,
            genesis: prestate,
            fingerprint: [0x52; 32],
            height: 0,
            block: [0x53; 32],
        },
        membership: [0x54; 32],
        reputation: [0x55; 32],
        attestation: commitment,
        voters: BTreeMap::from([(
            member.node,
            Voter {
                key_version: 0,
                public_key: member.continuity_key,
                weight: U256::one(),
            },
        )]),
    };
    let initial = bridge.read().unwrap();
    assert_eq!(
        initial, expected_initial,
        "qualification custody already used; preserve history"
    );
    let path = directory.join("voter.sqlite");
    let old = directory.join("before-signing.sqlite");
    let vote = {
        let mut voter =
            CounterVoter::open(&path, authority(), member.node, Some(initial), &mut bridge)
                .unwrap();
        std::fs::copy(&path, &old).unwrap();
        voter.sign(Step::Prevote, None, None, &mut bridge).unwrap()
    };
    let after = bridge.read().unwrap();
    assert_eq!(after, initial + 2);
    {
        let mut restarted =
            CounterVoter::open(&path, authority(), member.node, None, &mut bridge).unwrap();
        assert_eq!(
            restarted
                .sign(Step::Prevote, None, None, &mut bridge)
                .unwrap(),
            vote
        );
        assert_eq!(bridge.read().unwrap(), after);
    }
    assert!(CounterVoter::open(&old, authority(), member.node, None, &mut bridge).is_err());
    let report = json!({"schema":"BUILD8-PHYSICAL-COUNTER-VOTER-QUALIFICATION-V1","result":"PASS",
        "initial_counter":initial,"final_counter":after,"custody":bridge.manifest,
        "genesis_challenge":hex::encode(challenge),"genesis_prestate":hex::encode(prestate),"supervised_nonce":hex::encode(nonce),
        "genesis_evidence":hex::encode(evidence),"freshness_record":hex::encode(fresh.encode()),
        "vote":hex::encode(vote.encode()),"restart_signature_reused":true,"old_snapshot_rejected":true,
        "physical_key_used":true,"actual_genesis":false});
    std::fs::write(
        directory.join("result.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("{report}");
}
