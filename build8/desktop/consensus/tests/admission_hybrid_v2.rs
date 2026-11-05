//! Synthetic software TPM wire fixtures. These keys do NOT qualify hardware.
#[path = "support/license_v2.rs"]
mod license_fixture;
#[path = "support/voter_actor_v2.rs"]
mod actor_fixture;
use mutiny_consensus_v8::{
    admission_v2::*,
    tpm::{TpmProfile, encode_quote},
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};
fn blob(x: &[u8]) -> Vec<u8> {
    let mut b = (x.len() as u16).to_be_bytes().to_vec();
    b.extend(x);
    b
}
fn public(key: &SigningKey, restricted: bool) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(0x23u16.to_be_bytes());
    b.extend(0xbu16.to_be_bytes());
    b.extend((if restricted { 0x50472u32 } else { 0x40472u32 }).to_be_bytes());
    b.extend(blob(&[]));
    for x in [0x10u16, 0x18, 0xb, 3, 0x10] {
        b.extend(x.to_be_bytes());
    }
    let p = key.verifying_key().to_encoded_point(false);
    b.extend(blob(p.x().unwrap()));
    b.extend(blob(p.y().unwrap()));
    blob(&b)
}
fn header(kind: u16, signer: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut b = 0xff544347u32.to_be_bytes().to_vec();
    b.extend(kind.to_be_bytes());
    b.extend(blob(signer));
    b.extend(blob(challenge));
    b.extend([0; 25]);
    b
}
fn signature(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let s: Signature = key.sign(message);
    let raw = s.to_bytes();
    let mut b = vec![0, 0x18, 0, 0xb];
    b.extend(blob(&raw[..32]));
    b.extend(blob(&raw[32..]));
    b
}
#[test]
fn hybrid_join_binds_parent_supervision_and_every_admission_authority() {
    use mutiny_consensus_v8::{NETWORK_ID,admission_policy_v2::Record,execution::State,
        anchors::FinalizedAnchor,node_admission_v2::{Binding,node_id},join_v2::Join};
    let owner=HybridKey::wallet_restore(&format!("{}art","abandon ".repeat(23)),Role::WalletOwner).unwrap();
    let continuity=HybridKey::generate(Role::Continuity).unwrap();let node=HybridKey::generate(Role::Node).unwrap();
    let ak=SigningKey::from_bytes((&[9u8;32]).into()).unwrap();let profile=profile(&ak);
    let node_descriptor=node.public().descriptor(1).unwrap();
    let policy=Policy{genesis:[1;32],fingerprint:[2;32],owner_descriptor:owner.public().descriptor(1).unwrap(),
        endorsement_roots:[[3;32]].into_iter().collect()};
    let zero=HybridSignature{ed448:[0;114],fndsa:[0;1280]};
    let binding=Binding{node_signer:None,admission:Admission{genesis:policy.genesis,fingerprint:policy.fingerprint,
        node:node_id(policy.genesis,&node_descriptor).unwrap(),hardware_generation:1,key_generation:1,
        continuity_descriptor:continuity.public().descriptor(1).unwrap(),profile:profile.encode().unwrap(),
        endorsement_root:[3;32],owner:owner.public().address_id(1).unwrap(),supervised_nonce:[5;32],
        quote:vec![],possession:zero.clone(),authorization:zero.clone()},node_descriptor,possession:zero};
    let parent=FinalizedAnchor{network:NETWORK_ID,genesis:[1;32],fingerprint:[2;32],height:59,block:[8;32]};
    let mut join=Join{parent:parent.clone(),nonce:[7;32],binding};
    join.binding.admission.supervised_nonce=join.admission_nonce().unwrap();
    join.binding.admission.prove_continuity(&continuity).unwrap();
    join.binding.admission.quote=quote(&ak,&profile,join.binding.admission.challenge().unwrap());
    join.binding.admission.authorize(&owner,1).unwrap();join.binding.sign(&node).unwrap();
    let mut state=State::default();state.wallets.register(&policy.owner_descriptor).unwrap();
    state.admission_policy_v2=Some(Record::new(policy).unwrap());let root=state.root().unwrap();
    let raw=join.encode().unwrap();assert!(raw.len()<=16*1024);assert_eq!(Join::decode(&raw).unwrap(),join);
    assert!(join.verify(&state,&parent,root).is_ok());
    for mode in 0..13 {
        let mut bad=join.clone();
        match mode {
            0=>bad.parent.height+=1,1=>bad.parent.block[0]^=1,2=>bad.parent.genesis[0]^=1,
            3=>bad.parent.fingerprint[0]^=1,4=>bad.nonce[0]^=1,5=>bad.binding.admission.supervised_nonce=[5;32],
            6=>bad.binding.admission.authorization.ed448[0]^=1,7=>bad.binding.admission.authorization.fndsa[0]^=1,
            8=>bad.binding.admission.possession.ed448[0]^=1,9=>bad.binding.admission.possession.fndsa[0]^=1,
            10=>bad.binding.possession.ed448[0]^=1,11=>bad.binding.possession.fndsa[0]^=1,
            _=>bad.binding.admission.quote[20]^=1,
        }
        assert!(bad.verify(&state,&parent,root).is_err(),"join mutation {mode}");
    }
    let mut missing=state.clone();missing.admission_policy_v2=None;
    assert!(join.verify(&missing,&parent,missing.root().unwrap()).is_err());
    assert!(join.verify(&state,&parent,[0;32]).is_err());
    let mut overflow=join.clone();overflow.parent.height=u64::MAX;assert!(overflow.encode().is_err());
    let mut trailing=raw.clone();trailing.push(0);assert!(Join::decode(&trailing).is_err());
    println!("HYBRID_JOIN_CODEC_PUBLIC_BYTES={}",raw.len());
}
#[test]
fn hybrid_join_transition_is_atomic_parent_bound_and_zero_weight() {
    use mutiny_consensus_v8::{NETWORK_ID, anchors::FinalizedAnchor, blocks::BlockBody,
        execution::State, admission_policy_v2::Record, node_admission_v2::{Binding,node_id},
        join_v2::Join, membership_v2::Book, recovery::{Anchor,ContinuityState,Member},
        continuity_lifecycle_v2::{transition,Transition}, participation::ParticipationAck};
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let owner=HybridKey::wallet_restore(&format!("{}art","abandon ".repeat(23)),Role::WalletOwner).unwrap();
    let policy=Policy{genesis:[1;32],fingerprint:[2;32],owner_descriptor:owner.public().descriptor(1).unwrap(),
        endorsement_roots:[[3;32]].into_iter().collect()};
    let ak=SigningKey::from_bytes((&[9u8;32]).into()).unwrap();
    let existing_continuity=HybridKey::generate(Role::Continuity).unwrap();
    let existing_node=HybridKey::generate(Role::Node).unwrap();
    let joining_continuity=HybridKey::generate(Role::Continuity).unwrap();
    let joining_node=HybridKey::generate(Role::Node).unwrap();
    let existing_profile=profile(&ak);let joining_profile=profile_identity(&ak,21,22);
    let make_binding=|continuity:&HybridKey,node:&HybridKey,p:&TpmProfile,nonce:[u8;32]| {
        let descriptor=node.public().descriptor(1).unwrap();
        let zero=HybridSignature{ed448:[0;114],fndsa:[0;1280]};
        let mut b=Binding{node_signer:None,admission:Admission{genesis:policy.genesis,fingerprint:policy.fingerprint,
            node:node_id(policy.genesis,&descriptor).unwrap(),hardware_generation:1,key_generation:1,
            continuity_descriptor:continuity.public().descriptor(1).unwrap(),profile:p.encode().unwrap(),
            endorsement_root:[3;32],owner:owner.public().address_id(1).unwrap(),supervised_nonce:nonce,
            quote:vec![],possession:zero.clone(),authorization:zero.clone()},node_descriptor:descriptor,possession:zero};
        b.admission.prove_continuity(continuity).unwrap();b.admission.quote=quote(&ak,p,b.admission.challenge().unwrap());
        b.admission.authorize(&owner,1).unwrap();b.sign(node).unwrap();b
    };
    let initial=make_binding(&existing_continuity,&existing_node,&existing_profile,[5;32]);
    let mut state=State::default();state.wallets.register(&policy.owner_descriptor).unwrap();
    state.admission_policy_v2=Some(Record::new(policy.clone()).unwrap());
    (state.membership_v2,state.continuity_keys_v2)=Book::genesis(&initial,&policy,&Expected{
        node:initial.admission.node,hardware_generation:1,key_generation:1,supervised_nonce:[5;32]},&state.wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest).unwrap();
    state.continuity=Some(ContinuityState::bootstrap(policy.genesis,policy.fingerprint,
        Anchor{height:0,tip:[19;32],state_root:[0;32],registry_root:[0;32]},[20;32],vec![Member{
            lineage:initial.admission.node,node:initial.admission.node,hardware:existing_profile.hardware,generation:1,
            voting_key:mutiny_consensus_v8::tpm::public_key(&existing_profile.voting_public,false).unwrap(),
            attestation:existing_profile.commitment().unwrap(),history:Default::default(),physical:true,
            eligible:true,genesis_member:true}]).unwrap());
    let make_join=|parent:&FinalizedAnchor,p:&TpmProfile| {
        let mut j=Join{parent:parent.clone(),nonce:[7;32],binding:initial.clone()};
        j.binding.admission.node=node_id(policy.genesis,&joining_node.public().descriptor(1).unwrap()).unwrap();
        j.binding=make_binding(&joining_continuity,&joining_node,p,j.admission_nonce().unwrap());j
    };
    let install=|s:&mut State,t:Transition| {
        assert!(t.payouts.is_empty());assert_eq!(t.burned,0);
        s.accounting=t.accounting;s.continuity=Some(t.registry);s.membership_v2=t.membership;
        s.continuity_keys_v2=t.keys;s.bonds_v2=t.bonds;s.penalties_v2=t.penalties;
    };
    let mut cases=Vec::new();
    // Exercise the complete candidate preparation path: all new admission,
    // membership and freshness records must survive payment/work composition.
    {
        use mutiny_consensus_v8::{execution::{WorkParent,CandidatePreparation},pow::WorkHeader,blocks::state_root};
        let f:serde_json::Value=serde_json::from_str(include_str!("../../qualification/licensed-execution-v2-public-v1.json")).unwrap();
        assert_eq!(f["synthetic_only"],true);
        let rows:Vec<_>=f["parent_records"].as_array().unwrap().iter().map(|r|(
            hex::decode(r["key"].as_str().unwrap()).unwrap().try_into().unwrap(),
            hex::decode(r["record"].as_str().unwrap()).unwrap())).collect();
        let mut licensed=state.clone();licensed.licenses_v2=State::from_records(&rows,state_root(&rows).unwrap()).unwrap().licenses_v2;
        let mut candidate=WorkHeader::decode(&hex::decode(f["blocks"][0]["header"].as_str().unwrap()).unwrap()).unwrap().candidate;
        let parent=WorkParent{genesis:candidate.genesis,fingerprint:candidate.fingerprint,block:candidate.parent,
            height:0,t0:1000,target:candidate.target,ancestor_timestamps:vec![1000]};
        let anchor=FinalizedAnchor{network:NETWORK_ID,genesis:parent.genesis,fingerprint:parent.fingerprint,height:0,block:parent.block};
        let join=make_join(&anchor,&joining_profile);let node=join.binding.admission.node;
        let body=BlockBody{height:1,reward_owner:owner.public().address_id(1).unwrap(),fees:0,transactions:vec![],operations:vec![join.encode().unwrap()]};
        candidate.body_root=body.root().unwrap();
        let prepared=licensed.prepare_candidate_v2(CandidatePreparation{parent:&parent,candidate:&candidate,ticket_sequence:1,body:&body}).unwrap();
        assert!(prepared.state.continuity_keys_v2.get(node).is_some());
        assert!(prepared.state.membership_v2.get(node).is_some());
        assert!(prepared.state.accounting.freshness.contains_key(&node));
        assert!(licensed.continuity_keys_v2.get(node).is_none());
        assert_eq!(prepared.root,prepared.state.root().unwrap());
        assert!(State::from_records(&prepared.state.records().unwrap(),prepared.root).unwrap().records().unwrap()==prepared.state.records().unwrap());
    }
    // Explicit synthetic height snapshots test both sides of the existing
    // admission boundary. They do not claim certified production history.
    for height in [59u64,60,61] {
        let mut s=state.clone();s.accounting.slots.last_height=height-1;s.accounting.slots.period=(height-1)/60;
        let mut parent=FinalizedAnchor{network:NETWORK_ID,genesis:policy.genesis,fingerprint:policy.fingerprint,
            height:height-1,block:[19;32]};
        let join=make_join(&parent,&joining_profile);let node=join.binding.admission.node;
        let body=BlockBody{height,reward_owner:[30;32],fees:0,transactions:vec![],operations:vec![join.encode().unwrap()]};
        let before=s.clone();let root=s.root().unwrap();
        let result=transition(&s,&parent,root,&body).unwrap();
        assert_eq!(s,before);assert!(result.keys.get(node).is_some());assert!(result.keys.get(initial.admission.node).is_some());
        let member=result.registry.members.iter().find(|m|m.node==node).unwrap();
        assert_eq!(member.eligible,height==60);assert!(!member.genesis_member);assert_eq!(member.history.p,0);
        assert!(result.registry.weights().unwrap()[result.registry.members.iter().position(|m|m.node==node).unwrap()].is_zero());
        assert!(!result.accounting.slots.bits.contains_key(&node));
        let fresh=&result.accounting.freshness[&node];
        assert!(!fresh.eligible(node,1,member.voting_key,height));
        assert!(fresh.eligible(node,1,member.voting_key,height+1));
        assert!(fresh.eligible(node,1,member.voting_key,height+60));
        assert!(!fresh.eligible(node,1,member.voting_key,height+61));
        let mut duplicate=body.clone();duplicate.operations.push(join.encode().unwrap());
        assert!(transition(&s,&parent,root,&duplicate).is_err());assert_eq!(s,before);
        let mut same_hardware=body.clone();same_hardware.operations=vec![make_join(&parent,&existing_profile).encode().unwrap()];
        assert!(transition(&s,&parent,root,&same_hardware).is_err());
        let mut same_block=body.clone();
        let native=SigningKey::from_bytes((&[21u8;32]).into()).unwrap();
        let make_ack=|p:&FinalizedAnchor| {
            let mut ack=ParticipationAck{network:NETWORK_ID,genesis:p.genesis,fingerprint:p.fingerprint,
                node,height:p.height+1,parent:p.id(),generation:1,signature:[0;64]};
            let sig:Signature=native.sign_prehash(&ack.signing_digest()).unwrap();
            ack.signature=sig.normalize_s().unwrap_or(sig).to_bytes().into();ack.encode()
        };
        same_block.operations.push(make_ack(&parent));
        assert!(transition(&s,&parent,root,&same_block).is_err());
        let mut missing=s.clone();missing.admission_policy_v2=None;
        assert!(transition(&missing,&parent,missing.root().unwrap(),&body).is_err());
        install(&mut s,result);
        let rows=|s:&State|s.records().unwrap().into_iter().map(|(k,v)|serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)})).collect::<Vec<_>>();
        cases.push(serde_json::json!({"height":height,"parent":hex::encode(parent.encode()),"join":hex::encode(join.encode().unwrap()),
            "node":hex::encode(node),"before":rows(&before),"before_root":hex::encode(root),"after":rows(&s),"after_root":hex::encode(s.root().unwrap())}));
        s=State::from_records(&s.records().unwrap(),s.root().unwrap()).unwrap();
        parent.height=height;parent.block=[31;32];
        // Previously signed admission cannot replay in a later block.
        let mut replay=body.clone();replay.height=height+1;
        assert!(transition(&s,&parent,s.root().unwrap(),&replay).is_err());
        if height==59 {
            let mut next=BlockBody{height:60,operations:vec![make_ack(&parent)],..body.clone()};
            assert!(transition(&s,&parent,s.root().unwrap(),&next).is_err()); // still pending in state59
            next.operations.clear();let result=transition(&s,&parent,s.root().unwrap(),&next).unwrap();
            assert!(result.registry.members.iter().find(|m|m.node==node).unwrap().eligible);
            assert_eq!(result.registry.members.iter().find(|m|m.node==node).unwrap().history.p,0);
            install(&mut s,result);parent.height=60;parent.block=[32;32];
            next.height=61;next.operations=vec![make_ack(&parent)];
            let result=transition(&s,&parent,s.root().unwrap(),&next).unwrap();
            assert_eq!(result.accounting.slots.bits[&node],1);
            assert!(result.registry.weights().unwrap()[result.registry.members.iter().position(|m|m.node==node).unwrap()].is_zero());
        } else if height==60 {
            // A boundary join begins at slot61 with zero voting weight. Sixty
            // real signed ACKs close its first period at120; the newly earned
            // history is only in post-state120, never boundary authority119.
            for slot in 61u64..=120 {
                let next=BlockBody{height:slot,operations:vec![make_ack(&parent)],..body.clone()};
                let prior=s.continuity.as_ref().unwrap();
                assert!(prior.weights().unwrap()[prior.members.iter().position(|m|m.node==node).unwrap()].is_zero());
                let result=transition(&s,&parent,s.root().unwrap(),&next).unwrap();
                let member=result.registry.members.iter().find(|m|m.node==node).unwrap();
                assert_eq!(member.history.p,if slot==120 {1} else {0});
                if slot<120 {assert_eq!(result.accounting.slots.bits[&node].count_ones() as u64,slot-60);}
                else {assert!(!result.registry.weights().unwrap()[result.registry.members.iter().position(|m|m.node==node).unwrap()].is_zero());}
                install(&mut s,result);parent.height=slot;parent.block=mutiny_consensus_v8::domain_hash(b"SYNTHETIC-JOIN-PARENT",&slot.to_be_bytes());
            }
            let stale=BlockBody{height:121,operations:vec![make_ack(&parent)],..body.clone()};
            assert!(transition(&s,&parent,s.root().unwrap(),&stale).is_err());
        }
    }
    if let Ok(path)=std::env::var("BUILD8_EXPORT_JOIN_TRANSITION_PUBLIC_V1") {
        use std::io::Write;
        let mut f=std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();
        f.write_all(serde_json::to_string_pretty(&serde_json::json!({"schema":"BUILD8-SYNTHETIC-JOIN-TRANSITION-PUBLIC-V1","production_authorized":false,"cases":cases})).unwrap().as_bytes()).unwrap();
    }
}
fn profile(ak: &SigningKey) -> TpmProfile {
    profile_identity(ak, 10, 12)
}
fn profile_identity(ak: &SigningKey, identity_seed: u8, hardware: u8) -> TpmProfile {
    let identity = SigningKey::from_bytes((&[identity_seed; 32]).into()).unwrap();
    let voting_public = public(&identity, false);
    let mut signer = vec![0, 0xb];
    signer.extend([11; 32]);
    let mut name = vec![0, 0xb];
    name.extend(Sha256::digest(&voting_public[2..]));
    let mut certify_message = header(0x8017, &signer, &[0, 255, 85, 170]);
    certify_message.extend(blob(&name));
    certify_message.extend(blob(&signer));
    let certify_signature = signature(ak, &certify_message);
    TpmProfile {
        hardware: [hardware; 32],
        ak_public: public(ak, true),
        voting_public,
        qualified_signer: signer,
        pcr_bitmap: [1, 0, 0],
        pcr_digest: [13; 32],
        certify_message,
        certify_signature,
        admission_trust_manifest: [14; 32],
        provenance: None,
    }
}
fn quote(ak: &SigningKey, p: &TpmProfile, challenge: [u8; 32]) -> Vec<u8> {
    let mut m = header(0x8018, &p.qualified_signer, &challenge);
    m.extend(1u32.to_be_bytes());
    m.extend(0xbu16.to_be_bytes());
    m.push(3);
    m.extend(p.pcr_bitmap);
    m.extend(blob(&p.pcr_digest));
    encode_quote(&m, &signature(ak, &m)).unwrap()
}
#[test]
fn both_owner_halves_continuity_possession_native_quote_and_supervised_context_required() {
    let owner =
        HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let continuity = HybridKey::generate(Role::Continuity).unwrap();
    let policy = Policy {
        genesis: [1; 32],
        fingerprint: [2; 32],
        owner_descriptor: owner.public().descriptor(1).unwrap(),
        endorsement_roots: [[3; 32]].into_iter().collect(),
    };
    assert_eq!(Policy::decode(&policy.encode().unwrap()).unwrap(), policy);
    let ak = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let profile = profile(&ak);
    profile.verify_certified_key().unwrap();
    let empty = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    let mut a = Admission {
        genesis: [1; 32],
        fingerprint: [2; 32],
        node: [4; 32],
        hardware_generation: 1,
        key_generation: 1,
        continuity_descriptor: continuity.public().descriptor(1).unwrap(),
        profile: profile.encode().unwrap(),
        endorsement_root: [3; 32],
        owner: owner.public().address_id(1).unwrap(),
        supervised_nonce: [5; 32],
        quote: vec![],
        possession: empty.clone(),
        authorization: empty,
    };
    a.prove_continuity(&continuity).unwrap();
    a.quote = quote(&ak, &profile, a.challenge().unwrap());
    a.authorize(&owner, 1).unwrap();
    let expected = Expected {
        node: [4; 32],
        hardware_generation: 1,
        key_generation: 1,
        supervised_nonce: [5; 32],
    };
    let wallets = mutiny_consensus_v8::wallet_authority_v1::WalletBook::default();
    let verified = a.verify(&policy, &expected, &wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest).unwrap();
    // The owner-signed NodeID commits to a separately generated Node role key,
    // and that key proves possession of this exact completed admission.
    let node_key = HybridKey::generate(Role::Node).unwrap();
    let node_descriptor = node_key.public().descriptor(1).unwrap();
    let mut node_admission = a.clone();
    node_admission.node =
        mutiny_consensus_v8::node_admission_v2::node_id(policy.genesis, &node_descriptor).unwrap();
    node_admission.prove_continuity(&continuity).unwrap();
    node_admission.quote = quote(&ak, &profile, node_admission.challenge().unwrap());
    node_admission.authorize(&owner, 1).unwrap();
    let node_expected = Expected {
        node: node_admission.node,
        hardware_generation: 1,
        key_generation: 1,
        supervised_nonce: node_admission.supervised_nonce,
    };
    let mut node_binding = mutiny_consensus_v8::node_admission_v2::Binding {
            node_signer: None,
        admission: node_admission.clone(),
        node_descriptor: node_descriptor.clone(),
        possession: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    node_binding.sign(&node_key).unwrap();
    qualify_membership(
        &node_binding,
        &policy,
        &node_expected,
        &wallets,
        &node_key,
        &owner,
        &continuity,
    );
    let checked = node_binding
        .verify(&policy, &node_expected, &wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest)
        .unwrap();
    assert_eq!(checked.admission().node(), node_admission.node);
    assert_eq!(checked.node_descriptor(), node_descriptor);
    assert_eq!(
        mutiny_consensus_v8::node_admission_v2::Binding::decode(&node_binding.encode().unwrap())
            .unwrap(),
        node_binding
    );
    let encoded_node_binding = node_binding.encode().unwrap();
    for n in 0..encoded_node_binding.len() {
        assert!(
            mutiny_consensus_v8::node_admission_v2::Binding::decode(&encoded_node_binding[..n])
                .is_err()
        );
    }
    let mut trailing = encoded_node_binding.clone();
    trailing.push(0);
    assert!(mutiny_consensus_v8::node_admission_v2::Binding::decode(&trailing).is_err());
    if std::env::var("BUILD8_EXPORT_NODE_ADMISSION").as_deref() == Ok("1") {
        let value = serde_json::json!({"schema":"BUILD8-SYNTHETIC-NODE-ADMISSION-V2",
            "synthetic_only":true,"production_authorized":false,
            "policy":hex::encode(policy.encode().unwrap()),"binding":hex::encode(&encoded_node_binding),
            "node_id":hex::encode(node_admission.node),"challenge":hex::encode(node_admission.challenge().unwrap())});
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../qualification/node-admission-v2-public-v1.json"),
            )
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&value).unwrap())
            .unwrap();
    }
    assert_ne!(
        node_admission.node,
        mutiny_consensus_v8::node_admission_v2::node_id([99; 32], &node_descriptor).unwrap()
    );
    for field in 0..5 {
        let mut bad = node_binding.clone();
        match field {
            0 => bad.possession.ed448[0] ^= 1,
            1 => bad.possession.fndsa[500] ^= 1,
            2 => bad.admission.node[0] ^= 1,
            3 => bad.node_descriptor = node_key.public().descriptor(2).unwrap(),
            _ => {
                bad.possession = node_key
                    .sign(mutiny_crypto_v2::Domain::NodeWork, &bad.body().unwrap())
                    .unwrap()
            }
        }
        assert!(
            bad.verify(&policy, &node_expected, &wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest).is_err(),
            "node binding field {field}"
        );
    }
    assert!(
        mutiny_consensus_v8::node_admission_v2::node_id(
            policy.genesis,
            &owner.public().descriptor(1).unwrap()
        )
        .is_err()
    );
    for kind in 0..4 {
        let mut mixed = node_key.public().clone();
        match kind {
            0 => mixed.ed448 = owner.public().ed448,
            1 => mixed.fndsa = owner.public().fndsa,
            2 => mixed.ed448 = continuity.public().ed448,
            _ => mixed.fndsa = continuity.public().fndsa,
        }
        let mut bad = node_binding.clone();
        bad.node_descriptor = mixed.descriptor(1).unwrap();
        bad.admission.node =
            mutiny_consensus_v8::node_admission_v2::node_id(policy.genesis, &bad.node_descriptor)
                .unwrap();
        bad.admission.prove_continuity(&continuity).unwrap();
        bad.admission.quote = quote(&ak, &profile, bad.admission.challenge().unwrap());
        bad.admission.authorize(&owner, 1).unwrap();
        let expected = Expected {
            node: bad.admission.node,
            hardware_generation: 1,
            key_generation: 1,
            supervised_nonce: bad.admission.supervised_nonce,
        };
        assert!(matches!(
            bad.verify(&policy, &expected, &wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest),
            Err(mutiny_consensus_v8::Error::Duplicate)
        ));
    }
    // A previously valid admission/policy cannot revive a retired owner key.
    let mut rotated_wallets = wallets.clone();
    let authority = rotated_wallets.register(&policy.owner_descriptor).unwrap();
    let successor =
        HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let mut rotation = mutiny_consensus_v8::wallet_rotation_v1::Rotation {
        network: mutiny_consensus_v8::NETWORK_ID,
        genesis: policy.genesis,
        fingerprint: policy.fingerprint,
        authority,
        current: policy.owner_descriptor.clone(),
        proposed: successor.public().descriptor(2).unwrap(),
        created_height: 1,
        expiry_height: 10,
        authorization: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
        possession: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    rotation.sign(&owner, &successor).unwrap();
    rotated_wallets
        .apply(&rotation, policy.genesis, policy.fingerprint, 1)
        .unwrap();
    assert!(matches!(
        a.verify(&policy, &expected, &rotated_wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest),
        Err(mutiny_consensus_v8::Error::WrongGeneration)
    ));

    assert_eq!(verified.node(), a.node);
    assert_eq!(verified.continuity(), continuity.public());
    // Re-authorizing a second node cannot reuse either software key half,
    // the native TPM key or hardware identity. Failure leaves the book intact.
    let mut key_book = mutiny_consensus_v8::continuity_keys_v2::Book::default();
    key_book.admit(&a, &policy, &expected, &wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest).unwrap();
    let before = key_book.clone();
    let mut duplicate = a.clone();
    duplicate.node = [44; 32];
    duplicate.prove_continuity(&continuity).unwrap();
    duplicate.quote = quote(&ak, &profile, duplicate.challenge().unwrap());
    duplicate.authorize(&owner, 1).unwrap();
    let expected_duplicate = Expected {
        node: duplicate.node,
        hardware_generation: 1,
        key_generation: 1,
        supervised_nonce: duplicate.supervised_nonce,
    };
    assert!(matches!(
        key_book.admit(&duplicate, &policy, &expected_duplicate, &wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest),
        Err(mutiny_consensus_v8::Error::Duplicate)
    ));
    assert_eq!(key_book, before);
    // Even with a cached successful verification above, a fresh book cannot
    // admit the old authorization after the owner's canonical rotation.
    let mut stale_book = mutiny_consensus_v8::continuity_keys_v2::Book::default();
    assert!(matches!(
        stale_book.admit(&a, &policy, &expected, &rotated_wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest),
        Err(mutiny_consensus_v8::Error::WrongGeneration)
    ));
    assert!(stale_book.is_empty());
    // Later owner rotation does not erase already-authenticated admission
    // history, but the live admission verifier above rejects retired authority.
    let mut checkpoint = mutiny_consensus_v8::execution::State::default();
    checkpoint.wallets = rotated_wallets;
    checkpoint.continuity_keys_v2 = key_book;
    assert_eq!(
        mutiny_consensus_v8::execution::State::from_records(
            &checkpoint.records().unwrap(),
            checkpoint.root().unwrap()
        )
        .unwrap(),
        checkpoint
    );
    assert_eq!(Admission::decode(&a.encode().unwrap()).unwrap(), a);
    for field in 0..14 {
        let mut bad = a.clone();
        match field {
            0 => bad.genesis[0] ^= 1,
            1 => bad.fingerprint[0] ^= 1,
            2 => bad.node[0] ^= 1,
            3 => bad.hardware_generation += 1,
            4 => bad.key_generation += 1,
            5 => bad.endorsement_root[0] ^= 1,
            6 => bad.owner[0] ^= 1,
            7 => bad.supervised_nonce[0] ^= 1,
            8 => bad.possession.ed448[0] ^= 1,
            9 => bad.possession.fndsa[500] ^= 1,
            10 => bad.authorization.ed448[0] ^= 1,
            11 => bad.authorization.fndsa[500] ^= 1,
            12 => bad.quote[20] ^= 1,
            _ => bad.profile[20] ^= 1,
        }
        assert!(
            bad.verify(&policy, &expected, &wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest).is_err(),
            "field {field}"
        );
    }
    // Even a current owner cannot waive a wrong native TPM challenge or invalid
    // Continuity possession by simply re-signing the enclosing authorization.
    let mut bad = a.clone();
    bad.quote = quote(&ak, &profile, [99; 32]);
    bad.authorize(&owner, 1).unwrap();
    assert!(bad.verify(&policy, &expected, &wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest).is_err());
    let mut bad = a.clone();
    bad.possession.fndsa[700] ^= 1;
    bad.authorize(&owner, 1).unwrap();
    assert!(bad.verify(&policy, &expected, &wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest).is_err());
    let mut bad = a.clone();
    bad.continuity_descriptor = owner.public().descriptor(1).unwrap();
    assert!(bad.body().is_err());
    let mut bad_policy = policy.clone();
    bad_policy.owner_descriptor = continuity.public().descriptor(1).unwrap();
    assert!(bad_policy.encode().is_err());
    for half in 0..2 {
        let mut reused = continuity.public().clone();
        if half == 0 {
            reused.ed448 = owner.public().ed448;
        } else {
            reused.fndsa = owner.public().fndsa;
        }
        let mut bad = a.clone();
        bad.continuity_descriptor = reused.descriptor(1).unwrap();
        bad.authorize(&owner, 1).unwrap();
        assert!(matches!(
            bad.verify(&policy, &expected, &wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest),
            Err(mutiny_consensus_v8::Error::Duplicate)
        ));
    }
    let raw = a.encode().unwrap();
    for n in [0, 1, raw.len() - 1] {
        assert!(Admission::decode(&raw[..n]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Admission::decode(&trailing).is_err());
    if std::env::var("BUILD8_EXPORT_PUBLIC_ADMISSION").as_deref() == Ok("1") {
        let f = serde_json::json!({"schema":"BUILD8-SYNTHETIC-HYBRID-ADMISSION-V2","synthetic":true,"production_authorized":false,
            "policy":hex::encode(policy.encode().unwrap()),"admission":hex::encode(raw),"challenge":hex::encode(a.challenge().unwrap()),
            "warning":"Software TPM wire fixture. No actual physical admission or real TPM qualification is asserted."});
        std::fs::write(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../qualification/admission-public-v2.json"),
            serde_json::to_vec_pretty(&f).unwrap(),
        )
        .unwrap();
    }
}

fn qualify_membership(
    binding: &mutiny_consensus_v8::node_admission_v2::Binding,
    policy: &Policy,
    expected: &Expected,
    wallets: &mutiny_consensus_v8::wallet_authority_v1::WalletBook,
    node_key: &HybridKey,
    owner: &HybridKey,
    continuity_key: &HybridKey,
) {
    use mutiny_consensus_v8::{
        NETWORK_ID,
        anchors::FinalizedAnchor,
        blocks::state_root,
        continuity_exit_v2::Exit,
        execution::State,
        membership_v2::Book,
        recovery::{Anchor, ContinuityState, Member},
        tpm::public_key,
    };
    let mut registered_wallets=wallets.clone();
    registered_wallets.register(&policy.owner_descriptor).unwrap();
    let wallets=&registered_wallets;
    let (book, keys) = Book::genesis(binding, policy, expected, wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest).unwrap();
    let a = &binding.admission;
    let profile = TpmProfile::decode(&a.profile).unwrap();
    let registry = ContinuityState::bootstrap(
        a.genesis,
        a.fingerprint,
        Anchor {
            height: 0,
            tip: [19; 32],
            state_root: [0; 32],
            registry_root: [0; 32],
        },
        [20; 32],
        vec![Member {
            lineage: [18; 32],
            node: a.node,
            hardware: profile.hardware,
            generation: 1,
            voting_key: public_key(&profile.voting_public, false).unwrap(),
            attestation: profile.commitment().unwrap(),
            history: Default::default(),
            physical: true,
            eligible: true,
            genesis_member: true,
        }],
    )
    .unwrap();
    let mut state = State::default();
    state.membership_v2 = book.clone();
    state.continuity_keys_v2 = keys.clone();
    state.continuity = Some(registry.clone());
    book.validate_registry(&registry, &keys).unwrap();
    for field in 0..7 {
        let mut bad = registry.clone();
        match field {
            0 => bad.members[0].generation += 1,
            1 => bad.members[0].hardware[0] ^= 1,
            2 => bad.members[0].voting_key[1] ^= 1,
            3 => bad.members[0].attestation[0] ^= 1,
            4 => bad.members[0].physical = false,
            5 => bad.genesis[0] ^= 1,
            _ => bad.members.clear(),
        }
        assert!(book.validate_registry(&bad, &keys).is_err());
    }
    let records = state.records().unwrap();
    // Registry anchor metadata is reattached from authenticated chain history.
    // Round-trip equality covers canonical records, not transient metadata.
    assert!(State::from_records(&records, state.root().unwrap()).unwrap().records().unwrap() == records);
    let controls = book.records(&keys).unwrap();
    let (control_key, control_raw) = controls.iter().next().unwrap();
    for mode in 0..4 {
        let mut corrupt = records.clone();
        match mode {
            0 => corrupt.retain(|(k, _)| k == control_key), // missing admission
            1 => {
                corrupt
                    .iter_mut()
                    .find(|(k, _)| k == control_key)
                    .unwrap()
                    .0[0] ^= 1
            }
            2 => {
                corrupt
                    .iter_mut()
                    .find(|(k, _)| k == control_key)
                    .unwrap()
                    .1[15] ^= 1
            }
            _ => corrupt
                .iter_mut()
                .find(|(k, _)| k == control_key)
                .unwrap()
                .1
                .push(0),
        }
        assert!(
            state_root(&corrupt)
                .and_then(|root| State::from_records(&corrupt, root))
                .is_err()
        );
    }
    let mut opaque = State::default();
    opaque
        .protocol_records
        .insert(*control_key, control_raw.clone());
    assert!(opaque.records().is_err());
    for arity in [2, 3, 8, 9, 10] {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(arity).unwrap().u8(2).unwrap().u8(51).unwrap();
        for _ in 2..arity {
            e.null().unwrap();
        }
        let bad = vec![(*control_key, e.into_writer())];
        assert!(State::from_records(&bad, state_root(&bad).unwrap()).is_err());
    }
    let mut lifecycle_state = state.clone();
    lifecycle_state.continuity = Some(registry.clone());
    lifecycle_state.wallets=wallets.clone();
    lifecycle_state.admission_policy_v2=Some(mutiny_consensus_v8::admission_policy_v2::Record::new(policy.clone()).unwrap());
    qualify_atomic_canonical_store(lifecycle_state.clone(),continuity_key);
    qualify_funded_bond_execution(lifecycle_state.clone(),wallets,owner);
    qualify_economic_lifecycle(lifecycle_state.clone(),wallets,owner,node_key,continuity_key);
    qualify_rolling_lifecycle(lifecycle_state.clone(), node_key, 60);
    qualify_rolling_lifecycle(lifecycle_state.clone(), node_key, 54);
    qualify_rolling_lifecycle(lifecycle_state, node_key, 53);
    let initial_records = state.records().unwrap();
    let initial_root = state.root().unwrap();
    let mut vectors = Vec::new();
    for key in [node_key, owner] {
        for height in [1u64, 59, 60, 61, 119, 120] {
            let mut registry = registry.clone();
            registry.anchor.height = height - 1;
            let parent = FinalizedAnchor {
                network: NETWORK_ID,
                genesis: a.genesis,
                fingerprint: a.fingerprint,
                height: height - 1,
                block: [19; 32],
            };
            let mut exit = Exit {
                genesis: a.genesis,
                fingerprint: a.fingerprint,
                height,
                parent_anchor: parent.id(),
                node: a.node,
                hardware_generation: 1,
                sequence: 1,
                authorizer: key.public().descriptor(1).unwrap(),
                signature: HybridSignature {
                    ed448: [0; 114],
                    fndsa: [0; 1280],
                },
            };
            exit.sign(key).unwrap();
            let before = book.clone();
            let (scheduled, post) = book
                .apply_exits(
                    &parent,
                    &[exit.clone()],
                    &registry,
                    &registry,
                    wallets,
                    &keys,
                )
                .unwrap();
            let mut scheduled_state = state.clone();
            scheduled_state.membership_v2 = scheduled.clone();
            scheduled.validate_at_height(&post, &keys, height).unwrap();
            if !height.is_multiple_of(60) {
                let deadline = (height + 59) / 60 * 60;
                // An authenticated checkpoint still cannot turn an unprocessed
                // expired exit into valid future voting/participation authority.
                assert!(scheduled.validate_at_height(&post, &keys, deadline).is_err());
                let mut inactive = post.clone();
                inactive.members[0].eligible = false;
                assert!(scheduled.validate_at_height(&inactive, &keys, height).is_err());
            }
            vectors.push(serde_json::json!({
                "height":height,"parent":hex::encode(parent.encode()),"exit":hex::encode(exit.encode().unwrap()),
                "post_eligible":post.members[0].eligible,
                "scheduled_records":scheduled_state.records().unwrap().into_iter().map(|(k,v)|
                    serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)})).collect::<Vec<_>>(),
                "scheduled_root":hex::encode(scheduled_state.root().unwrap())
            }));
            assert_eq!(book, before);
            assert!(registry.members[0].eligible);
            assert_eq!(scheduled.get(a.node).unwrap().sequence(), 1);
            assert_eq!(post.members[0].eligible, !height.is_multiple_of(60));
            assert_eq!(
                scheduled.get(a.node).unwrap().exit_boundary(),
                if height.is_multiple_of(60) {
                    None
                } else {
                    Some((height + 59) / 60 * 60)
                }
            );
            assert!(
                book.apply_exits(
                    &parent,
                    &[exit.clone(), exit.clone()],
                    &registry,
                    &registry,
                    wallets,
                    &keys
                )
                .is_err()
            );
            assert!(
                scheduled
                    .apply_exits(&parent, &[exit], &post, &post, wallets, &keys)
                    .is_err()
            );
            let boundary = (height + 59) / 60 * 60;
            let end = FinalizedAnchor {
                height: boundary - 1,
                ..parent.clone()
            };
            let mut post = post;
            post.anchor.height = boundary - 1;
            let (finished, after) = scheduled
                .apply_exits(&end, &[], &post, &post, wallets, &keys)
                .unwrap();
            assert!(!after.members[0].eligible);
            assert_eq!(finished.get(a.node).unwrap().exit_boundary(), None);
            state.membership_v2 = finished;
            assert!(State::from_records(&state.records().unwrap(), state.root().unwrap()).unwrap().records().unwrap()
                == state.records().unwrap());
        }
    }
    if std::env::var("BUILD8_EXPORT_MEMBERSHIP_V2").as_deref() == Ok("1") {
        let value = serde_json::json!({"schema":"BUILD8-SYNTHETIC-MEMBERSHIP-V2",
            "synthetic_only":true,"production_authorized":false,
            "policy":hex::encode(policy.encode().unwrap()),
            "initial_records":initial_records.into_iter().map(|(k,v)|
                serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)})).collect::<Vec<_>>(),
            "initial_root":hex::encode(initial_root),"vectors":vectors});
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../qualification/hybrid-membership-v2-public-v1.json"),
            )
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&value).unwrap())
            .unwrap();
    }
}

fn qualify_atomic_canonical_store(mut state:mutiny_consensus_v8::execution::State,continuity_key:&HybridKey) {
    use mutiny_consensus_v8::{NETWORK_ID,anchors::FinalizedAnchor,blocks::BlockBody,
        execution::{WorkParent,CandidatePreparation},license_book_v2::Book,canonical_store_v2::CanonicalStore,
        finality_v2::StoreError,pow::{Candidate,WorkAuthority,WorkHeader},work_authority_v2::Authority,
        votes_v2::HeightAuthority,continuity_v2::{Vote,Certificate},certificates::Decision,
        block_envelope_v2::BlockEnvelope,transactions::{OutPoint,Coin,Output},transactions_v2::{Transfer,Input},
        hybrid_transaction_v2::Transaction};
    let (owner,assignments,expected,licenses,coordinator)=license_fixture::fixtures();
    state.licenses_v2=Book::genesis(&assignments,&expected,&licenses,&Default::default(),[1;32],[2;32]).unwrap();
    let point=OutPoint{transaction:[93;32],index:0};
    state.coins.insert(point.clone(),Coin{output:Output{owner:licenses[0].owner,atoms:100000},created_height:0,coinbase:false});
    let mut tx=Transfer{network:NETWORK_ID,genesis:[1;32],fingerprint:[2;32],created_height:1,expiry_height:2,
        fee:5000,inputs:vec![Input::unsigned(point,owner.public(),1).unwrap()],outputs:vec![Output{owner:[94;32],atoms:95000}]};
    tx.sign_input(0,&owner).unwrap();let tx=Transaction::Transfer(tx);let txid=tx.id().unwrap();
    let body=BlockBody{height:1,reward_owner:licenses[0].owner,fees:5000,transactions:vec![tx.encode().unwrap()],operations:vec![]};
    let genesis=FinalizedAnchor{network:NETWORK_ID,genesis:[1;32],fingerprint:[2;32],height:0,block:[3;32]};
    let parent=WorkParent{genesis:genesis.genesis,fingerprint:genesis.fingerprint,height:0,block:genesis.block,t0:1000,
        target:[255;32],ancestor_timestamps:vec![1000]};
    let root=state.root().unwrap();let before=state.records().unwrap();
    let mut c=Candidate{network:NETWORK_ID,genesis:genesis.genesis,fingerprint:genesis.fingerprint,height:1,parent:genesis.block,
        timestamp:1100,body_root:body.root().unwrap(),state_root:[0;32],license:licenses[0].id,worker:expected[0].worker_id,target:parent.target};
    let executed=state.prepare_candidate_v2(CandidatePreparation{parent:&parent,candidate:&c,ticket_sequence:1,body:&body}).unwrap();
    c.state_root=executed.root;
    let mut work=Authority{work:WorkAuthority{candidate:c.clone(),assignment_sequence:1,ticket_sequence:1,coordinator:expected[0].coordinator,
        nonce_start:0,nonce_end:100,epoch:1},node_descriptor:assignments[0].node_descriptor.clone(),signature:HybridSignature{ed448:[0;114],fndsa:[0;1280]}};
    work.sign(&coordinator).unwrap();let header=WorkHeader{candidate:c,authority:work.id().unwrap(),nonce:1};
    let authority=HeightAuthority::from_state(&state,genesis.clone(),root).unwrap();let(node,voter)=authority.voters.iter().next().unwrap();
    let decision=Decision{network:NETWORK_ID,genesis:genesis.genesis,fingerprint:genesis.fingerprint,purpose:2,height:1,mining_epoch:1,
        continuity_period:0,round:0,step:3,previous_finalized_anchor:genesis.id(),parent:genesis.block,block:header.block_hash(),state:executed.root,
        membership:authority.membership,reputation:authority.reputation,attestation:authority.attestation};
    let mut vote=Vote{decision:decision.clone(),nil:false,node:*node,hardware_generation:voter.hardware_generation,key_generation:voter.key_generation,
        sequence:10,tpm_identity:voter.tpm_identity(),profile:voter.profile,signature:HybridSignature{ed448:[0;114],fndsa:[0;1280]}};
    vote.sign(continuity_key).unwrap();
    let envelope=BlockEnvelope{header,body,authority:work,certificate:Certificate{decision,votes:vec![vote]}};
    let mut random=[0;16];mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let path=std::env::temp_dir().join(format!("build8-hybrid-canonical-{}.sqlite",hex::encode(random)));
    if std::env::var_os("BUILD8_EXPORT_CANONICAL_STORE_PUBLIC_V1").is_some() {
        let records:Vec<_>=before.iter().map(|(k,v)|serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)})).collect();
        let fixture=serde_json::json!({"synthetic_only":true,"production_authorized":false,
            "genesis":hex::encode(genesis.encode()),"root":hex::encode(root),"records":records,
            "envelope":hex::encode(envelope.encode().unwrap()),"transaction_id":hex::encode(txid)});
        let out=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../qualification/hybrid-canonical-store-public-v1.json");
        assert!(!out.exists(),"public fixture must not be overwritten");
        std::fs::write(out,serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    }
    actor_fixture::qualify(&state,&genesis,root,&envelope,continuity_key);
    qualify_canonical_process_interruptions(&path,&genesis,&state,root,&envelope);
    let mut chain=CanonicalStore::open_trusted_genesis(&path,&genesis,&state,root,1000,parent.target).unwrap();
    let mut standalone=mutiny_consensus_v8::finality_v2::FinalityEvidenceStore::open(&path,&genesis).unwrap();
    assert!(matches!(standalone.record(&envelope,&state,&parent,&authority,&Default::default()),Err(StoreError::Context)));
    drop(standalone);
    let pool_path=path.with_extension("pool.sqlite");
    let mut pool=mutiny_consensus_v8::mempool_v2::Mempool::open(&pool_path,genesis.genesis,genesis.fingerprint,64*1024*1024).unwrap();
    chain.reconcile_pool(&mut pool).unwrap();pool.admit(&tx,&genesis,&state).unwrap();drop(pool);
    let fault=rusqlite::Connection::open(&path).unwrap();
    fault.execute_batch("CREATE TRIGGER fail_tip BEFORE INSERT ON canonical_v2 WHEN NEW.height<>x'0000000000000000' BEGIN SELECT RAISE(ABORT,'synthetic tip failure');END;").unwrap();
    assert!(matches!(chain.commit(&envelope),Err(StoreError::Integrity)));
    assert!(chain.load().is_err());
    fault.execute_batch("DROP TRIGGER fail_tip;").unwrap();
    let (head,unchanged)=chain.load().unwrap();assert_eq!(head.height,0);assert!(unchanged.records().unwrap()==before);
    assert!(chain.confirmed_height(txid).unwrap().is_none());assert!(!chain.halted().unwrap());
    for table in ["evidence_v2","undo_v2","confirmations_v2"] {
        assert_eq!(fault.query_row(&format!("SELECT count(*) FROM {table}"),[],|r|r.get::<_,u64>(0)).unwrap(),0);
    }
    assert_eq!(fault.query_row("SELECT count(*) FROM finalized_v2",[],|r|r.get::<_,u64>(0)).unwrap(),1);
    drop(fault);
    // Unexpected schema and changed immutable context fail before writes.
    let corrupt=rusqlite::Connection::open(&path).unwrap();
    for (install,repair) in [
        ("CREATE TRIGGER erase_finality AFTER INSERT ON evidence_v2 BEGIN DELETE FROM finalized_v2; END", "DROP TRIGGER erase_finality"),
        ("CREATE VIEW unexpected AS SELECT * FROM canonical_v2", "DROP VIEW unexpected"),
        ("CREATE INDEX extra_idx ON canonical_v2(root)", "DROP INDEX extra_idx"),
        ("CREATE TABLE sqliteXhidden(value TEXT)", "DROP TABLE sqliteXhidden"),
        ("PRAGMA user_version=99", "PRAGMA user_version=3"),
        ("PRAGMA application_id=1", "PRAGMA application_id=1297434162"),
    ] {
        corrupt.execute_batch(install).unwrap();
        assert!(chain.load().is_err(), "{install}");
        assert!(chain.halted().is_err(), "{install}");
        assert!(chain.confirmed_height(txid).is_err(), "{install}");
        assert!(chain.execution_parent(0).is_err(), "{install}");
        assert!(chain.state_proof(&genesis,[0;32]).is_err(), "{install}");
        assert!(chain.rebuild_proof_index(&state).is_err(), "{install}");
        assert!(chain.commit(&envelope).is_err(), "{install}");
        assert!(CanonicalStore::open_trusted_genesis(&path,&genesis,&state,root,1000,parent.target).is_err(), "{install}");
        assert_eq!(corrupt.query_row("SELECT count(*) FROM finalized_v2",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        assert_eq!(corrupt.query_row("SELECT count(*) FROM evidence_v2",[],|r|r.get::<_,u64>(0)).unwrap(),0);
        corrupt.execute_batch(repair).unwrap();
        assert_eq!(chain.load().unwrap().0.height,0);
    }
    corrupt.execute("UPDATE finalized_v2 SET anchor=?1 WHERE height=?2",rusqlite::params![FinalizedAnchor{block:[99;32],..genesis.clone()}.encode(),0u64.to_be_bytes().as_slice()]).unwrap();
    assert!(chain.load().is_err());assert!(chain.commit(&envelope).is_err());
    corrupt.execute("UPDATE finalized_v2 SET anchor=?1 WHERE height=?2",rusqlite::params![genesis.encode(),0u64.to_be_bytes().as_slice()]).unwrap();
    assert_eq!(chain.load().unwrap().0.height,0);
    drop(corrupt);
    let barrier=std::sync::Barrier::new(2);
    let mut left=CanonicalStore::open_trusted_genesis(&path,&genesis,&state,root,1000,parent.target).unwrap();
    let mut right=CanonicalStore::open_trusted_genesis(&path,&genesis,&state,root,1000,parent.target).unwrap();
    let inserted=std::thread::scope(|scope|{
        let a=scope.spawn(||{barrier.wait();left.commit(&envelope).unwrap()});
        let b=scope.spawn(||{barrier.wait();right.commit(&envelope).unwrap()});
        [a.join().unwrap(),b.join().unwrap()]
    });
    drop(left);drop(right);
    assert_eq!(inserted.iter().filter(|x|**x).count(),1);assert!(!chain.commit(&envelope).unwrap());
    let(head,post)=chain.load().unwrap();assert_eq!(head.height,1);assert_eq!(head.root,executed.root);
    assert!(post.records().unwrap()==executed.state.records().unwrap());assert_eq!(chain.confirmed_height(txid).unwrap(),Some(1));
    // The pending database was offline during canonical installation. Its stale
    // basis cannot feed assembly; restart reconciliation preserves CONFIRMED.
    let mut pool=mutiny_consensus_v8::mempool_v2::Mempool::open(&pool_path,genesis.genesis,genesis.fingerprint,64*1024*1024).unwrap();
    let current=FinalizedAnchor{height:1,block:head.block,..genesis.clone()};
    assert!(pool.pending_at(&current,&post).is_err());
    chain.reconcile_pool(&mut pool).unwrap();chain.reconcile_pool(&mut pool).unwrap();
    assert_eq!(pool.status(txid).unwrap(),Some(mutiny_consensus_v8::mempool::Status::Confirmed));
    assert!(pool.pending_at(&current,&post).unwrap().is_empty());assert!(pool.reserved_inputs().unwrap().is_empty());drop(pool);
    assert!(chain.execution_parent(0).unwrap().1.records().unwrap()==before);
    drop(chain);
    let mut chain=CanonicalStore::open_trusted_genesis(&path,&genesis,&state,root,1000,parent.target).unwrap();
    assert_eq!(chain.load().unwrap().0,head);
    let mut conflict=envelope.clone();conflict.header.nonce+=1;conflict.certificate.decision.block=conflict.block_hash();
    conflict.certificate.votes[0].decision=conflict.certificate.decision.clone();conflict.certificate.votes[0].sequence+=1;
    conflict.certificate.votes[0].sign(continuity_key).unwrap();
    let mut invalid=conflict.clone();invalid.certificate.votes[0].signature.fndsa[500]^=1;
    assert!(chain.commit(&invalid).is_err());assert!(!chain.halted().unwrap());
    assert!(matches!(chain.commit(&conflict),Err(StoreError::Halted)));assert!(chain.halted().unwrap());
    assert_eq!(chain.load().unwrap().0,head);assert_eq!(chain.confirmed_height(txid).unwrap(),Some(1));drop(chain);
    let chain=CanonicalStore::open_trusted_genesis(&path,&genesis,&state,root,1000,parent.target).unwrap();assert!(chain.halted().unwrap());drop(chain);
    let corrupt=rusqlite::Connection::open(&path).unwrap();
    let mut forged=envelope.clone();forged.certificate.votes[0].signature.ed448[0]^=1;
    corrupt.execute("UPDATE evidence_v2 SET envelope=?1 WHERE block=?2",rusqlite::params![forged.encode().unwrap(),envelope.block_hash().as_slice()]).unwrap();drop(corrupt);
    assert!(CanonicalStore::open_trusted_genesis(&path,&genesis,&state,root,1000,parent.target).is_err());
    let restore=rusqlite::Connection::open(&path).unwrap();
    restore.execute("UPDATE evidence_v2 SET envelope=?1 WHERE block=?2",rusqlite::params![envelope.encode().unwrap(),envelope.block_hash().as_slice()]).unwrap();drop(restore);
    let corrupt=rusqlite::Connection::open(&path).unwrap();
    corrupt.execute("UPDATE undo_v2 SET previous=x'8100' WHERE previous IS NOT NULL",[]).unwrap();drop(corrupt);
    // Full replay now rejects corrupt undo at startup, before any historical
    // authority query can use the store.
    assert!(CanonicalStore::open_trusted_genesis(&path,&genesis,&state,root,1000,parent.target).is_err());
    std::fs::remove_file(path).unwrap();std::fs::remove_file(pool_path).unwrap();
}

fn qualify_canonical_process_interruptions(base:&std::path::Path,genesis:&mutiny_consensus_v8::anchors::FinalizedAnchor,
    state:&mutiny_consensus_v8::execution::State,root:[u8;32],envelope:&mutiny_consensus_v8::block_envelope_v2::BlockEnvelope) {
    use std::io::BufRead;
    use mutiny_consensus_v8::canonical_store_v2::CanonicalStore;
    let fixture=base.with_extension("public.json");
    let records:Vec<_>=state.records().unwrap().into_iter().map(|(k,v)|serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)})).collect();
    let mut before=0;let mut after=0;
    for delay in [0,16,128,512,1000,2000,4000,8000] {
        let database=base.with_extension(format!("crash-{delay}.sqlite"));assert!(!database.exists());
        let value=serde_json::json!({"synthetic_only":true,"production_authorized":false,
            "database":database.file_name().unwrap().to_str().unwrap(),"genesis":hex::encode(genesis.encode()),
            "root":hex::encode(root),"records":records,"envelope":hex::encode(envelope.encode().unwrap())});
        std::fs::write(&fixture,serde_json::to_vec(&value).unwrap()).unwrap();
        let mut child=std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","crash_child_hybrid_canonical_commit","--nocapture"])
            .env("BUILD8_PUBLIC_CANONICAL_CRASH_FIXTURE",&fixture).stdout(std::process::Stdio::piped()).spawn().unwrap();
        let mut output=std::io::BufReader::new(child.stdout.take().unwrap());
        loop {let mut line=String::new();assert!(output.read_line(&mut line).unwrap()>0,"child exited before commit marker");
            if line.trim()=="BUILD8_CANONICAL_COMMIT_READY"{break;}}
        std::thread::sleep(std::time::Duration::from_millis(delay));
        if let Some(status)=child.try_wait().unwrap(){assert!(status.success());}
        else {child.kill().unwrap();child.wait().unwrap();}
        let mut restored=CanonicalStore::open_trusted_genesis(&database,genesis,state,root,1000,[255;32]).unwrap();
        let(head,post)=restored.load().unwrap();assert!(!restored.halted().unwrap());
        match head.height {
            0=>{before+=1;assert!(post.records().unwrap()==state.records().unwrap());assert!(restored.commit(envelope).unwrap());},
            1=>{after+=1;assert_eq!(head.root,envelope.header.candidate.state_root);assert!(!restored.commit(envelope).unwrap());},
            _=>panic!("partial or unexpected canonical height"),
        }
        assert_eq!(restored.load().unwrap().0.root,envelope.header.candidate.state_root);
        drop(restored);std::fs::remove_file(database).unwrap();
    }
    std::fs::remove_file(fixture).unwrap();
    assert!(before>0 && after>0,"the interruption sample must observe both commit outcomes");
    eprintln!("SYNTHETIC_CANONICAL_PROCESS_INTERRUPTION cases=8 pre_commit={before} post_commit={after} production=false");
}

#[test]
fn crash_child_hybrid_canonical_commit() {
    use std::io::Write;
    use mutiny_consensus_v8::{anchors::FinalizedAnchor,execution::State,canonical_store_v2::CanonicalStore,block_envelope_v2::BlockEnvelope};
    let Some(raw)=std::env::var_os("BUILD8_PUBLIC_CANONICAL_CRASH_FIXTURE") else{return;};
    let fixture=std::path::PathBuf::from(raw).canonicalize().unwrap();
    assert_eq!(fixture.parent().unwrap(),std::env::temp_dir().canonicalize().unwrap());
    let name=fixture.file_name().unwrap().to_str().unwrap();assert!(name.starts_with("build8-hybrid-canonical-")&&name.ends_with(".public.json"));
    assert!(fixture.metadata().unwrap().len()<4*1024*1024);
    let f:serde_json::Value=serde_json::from_slice(&std::fs::read(&fixture).unwrap()).unwrap();
    assert_eq!(f["synthetic_only"],true);assert_eq!(f["production_authorized"],false);
    let filename=f["database"].as_str().unwrap();let relative=std::path::Path::new(filename);
    assert_eq!(relative.components().count(),1);assert!(filename.starts_with("build8-hybrid-canonical-")&&filename.ends_with(".sqlite"));
    let database=fixture.parent().unwrap().join(relative);assert!(!database.exists());
    let raw=|v:&serde_json::Value|hex::decode(v.as_str().unwrap()).unwrap();
    let root:[u8;32]=raw(&f["root"]).try_into().unwrap();
    let rows:Vec<_>=f["records"].as_array().unwrap().iter().map(|r|(raw(&r["key"]).try_into().unwrap(),raw(&r["record"]))).collect();
    let state=State::from_records(&rows,root).unwrap();let genesis=FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let block=BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let mut chain=CanonicalStore::open_trusted_genesis(&database,&genesis,&state,root,1000,[255;32]).unwrap();
    println!("BUILD8_CANONICAL_COMMIT_READY");std::io::stdout().flush().unwrap();
    assert!(chain.commit(&block).unwrap());
}

fn qualify_funded_bond_execution(mut state:mutiny_consensus_v8::execution::State,
    wallets:&mutiny_consensus_v8::wallet_authority_v1::WalletBook,owner:&HybridKey) {
    use mutiny_consensus_v8::{NETWORK_ID,Error,anchors::FinalizedAnchor,blocks::{BlockBody,state_root},
        bonds::MINIMUM_ATOMS,bond_create_v3::{BondError,FundedBondCreate,Slot,UnsignedBondCreate},
        execution::{ExecutionError,State,WorkParent,CandidatePreparation},op_envelope_v1::Envelope,
        transactions::{Coin,OutPoint,Output,SUBSIDY},pow::WorkHeader};
    // Public, conspicuously synthetic fixture supplies only qualified license
    // records; the locally generated physical-admission test state is retained.
    let fixture:serde_json::Value=serde_json::from_str(include_str!("../../qualification/licensed-execution-v2-public-v1.json")).unwrap();
    assert_eq!(fixture["synthetic_only"],true);
    let records:Vec<_>=fixture["parent_records"].as_array().unwrap().iter().map(|r|(
        hex::decode(r["key"].as_str().unwrap()).unwrap().try_into().unwrap(),
        hex::decode(r["record"].as_str().unwrap()).unwrap())).collect();
    state.licenses_v2=State::from_records(&records,state_root(&records).unwrap()).unwrap().licenses_v2;
    state.wallets=wallets.clone();
    let mut candidate=WorkHeader::decode(&hex::decode(fixture["blocks"][0]["header"].as_str().unwrap()).unwrap()).unwrap().candidate;
    let parent=WorkParent{genesis:candidate.genesis,fingerprint:candidate.fingerprint,block:candidate.parent,height:0,t0:1000,
        target:candidate.target,ancestor_timestamps:vec![1000]};
    let anchor=FinalizedAnchor{network:NETWORK_ID,genesis:parent.genesis,fingerprint:parent.fingerprint,height:0,block:parent.block};
    let member=state.continuity.as_ref().unwrap().members[0].clone();
    let point=OutPoint{transaction:[90;32],index:0};let address=owner.public().address_id(1).unwrap();
    state.coins.insert(point.clone(),Coin{output:Output{owner:address,atoms:MINIMUM_ATOMS+20000},created_height:0,coinbase:false});
    // Candidate 3 (Lane P design section 2, Order P1): ONE kind-24 operation consumes the input,
    // locks the principal, returns the change and pays the fee. No separate funding transfer and no
    // escrow output exist; the retired kind 18 is refused by the operation discriminator.
    let unsigned=UnsignedBondCreate{genesis:parent.genesis,fingerprint:parent.fingerprint,
        envelope:Envelope{first_height:1,last_height:1,reference_height:anchor.height,reference_block:anchor.block,preconditions:vec![]},
        owner:address,owner_descriptor:owner.public().descriptor(1).unwrap(),node:member.node,node_generation:1,nonce:[91;32],
        principal:MINIMUM_ATOMS,fee:8000,inputs:vec![point.clone()],change:Some(Output{owner:address,atoms:12000})};
    assert!(unsigned.signed_len().unwrap() as u64<=unsigned.fee,"1 atom per byte of the complete signed operation");
    let create=FundedBondCreate::sign(unsigned,owner).unwrap();
    let change=OutPoint{transaction:create.id().unwrap(),index:0};
    let reward=state.licenses_v2.active(candidate.license,candidate.worker,1).unwrap().0.owner;
    let body=BlockBody{height:1,reward_owner:reward,fees:8000,transactions:vec![],operations:vec![create.encode().unwrap()]};
    candidate.body_root=body.root().unwrap();candidate.state_root=[0;32];
    let before=state.records().unwrap();
    let executed=state.prepare_candidate_v2(CandidatePreparation{parent:&parent,candidate:&candidate,ticket_sequence:1,body:&body}).unwrap();
    let lot=&executed.state.bonds_v2.lots[&create.lot_id()].0;
    assert_eq!((lot.atoms,lot.created_height,lot.owner,lot.node),(MINIMUM_ATOMS,1,address,member.node));
    assert!(!executed.state.coins.contains_key(&point));
    assert_eq!(executed.state.coins[&change],Coin{output:Output{owner:address,atoms:12000},created_height:1,coinbase:false});
    // Coinbase SUBSIDY + 8000 and change 12000; the principal left the UTXO set into the lot.
    assert_eq!(executed.state.coins.values().map(|c|c.output.atoms as u128).sum::<u128>(),(SUBSIDY+20000) as u128);
    assert_eq!(executed.state.accounting.slots.last_height,1);
    assert_eq!(executed.state.continuity.as_ref().unwrap().members[0].history.bonds.len(),1);
    assert!(state.records().unwrap()==before);
    let restored=State::from_records(&executed.state.records().unwrap(),executed.root).unwrap();
    assert!(restored.records().unwrap()==executed.state.records().unwrap());
    if std::env::var_os("BUILD8_EXPORT_FUNDED_CANDIDATE_V1").is_some() {
        let records=|items:Vec<([u8;32],Vec<u8>)>|items.into_iter().map(|(k,v)|
            serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)})).collect::<Vec<_>>();
        let fixture=serde_json::json!({"synthetic_only":true,"production_authorized":false,"test_value":true,
            "note":"Candidate 3: one funded BondCreate (block operation kind 24, Lane P design section 2) replaces the kind-18 create and its separate escrow-funding transfer. Synthetic TEST-VALUE state; not production chain history.",
            "parent":hex::encode(anchor.encode()),"parent_root":hex::encode(state.root().unwrap()),
            "before":records(before.clone()),"after":records(executed.state.records().unwrap()),
            "body":hex::encode(body.encode().unwrap()),"body_root":hex::encode(body.root().unwrap()),
            "post_root":hex::encode(executed.root),"worker":hex::encode(candidate.worker),
            "license":hex::encode(candidate.license),"epoch":1,"ticket_sequence":1});
        let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../qualification/hybrid-funded-candidate-public-v1.json");
        assert!(!path.exists(),"public fixture must not be overwritten");
        std::fs::write(path,serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    }
    for field in 0..5 {
        let resign=|u:UnsignedBondCreate|FundedBondCreate::sign(u,owner).unwrap();
        let (bad,expected)=match field {
            0=>{let mut b=create.clone();b.create.ed448[0]^=1;(b,BondError::Signature(Slot::Create))}
            1=>{let mut b=create.clone();b.funding.fndsa[500]^=1;(b,BondError::Signature(Slot::Funding))}
            2=>{let mut u=create.unsigned.clone();u.node_generation+=1;(resign(u),BondError::Eligibility(Error::UnqualifiedPhysical))}
            3=>{let mut u=create.unsigned.clone();u.inputs[0].index=1;(resign(u),BondError::MissingInput)}
            _=>{let mut b=create.clone();b.unsigned.owner=[92;32];(b,BondError::Authority(Error::WrongGeneration))}
        };
        let mut bad_body=body.clone();bad_body.operations[0]=bad.encode().unwrap();let mut c=candidate.clone();c.body_root=bad_body.root().unwrap();
        let result=state.prepare_candidate_v2(CandidatePreparation{parent:&parent,candidate:&c,ticket_sequence:1,body:&bad_body});
        assert!(matches!(result,Err(ExecutionError::BondCreate(e)) if e==expected),"field {field}");
        assert!(state.records().unwrap()==before);
    }
}

fn qualify_economic_lifecycle(mut state:mutiny_consensus_v8::execution::State,
    wallets:&mutiny_consensus_v8::wallet_authority_v1::WalletBook,owner:&HybridKey,node_key:&HybridKey,continuity_key:&HybridKey) {
    use mutiny_consensus_v8::{NETWORK_ID,anchors::FinalizedAnchor,blocks::BlockBody,
        bonds::{BondLot,LotStatus,MINIMUM_ATOMS,LOCK_HEIGHTS,EVIDENCE_HEIGHTS},bonds_v2::Lot,
        bond_ops_v2::{Action,Operation},op_envelope_v1::Envelope,continuity_v2::Vote,certificates::Decision,equivocation_v2::Evidence,
        continuity_exit_v2::Exit,continuity_lifecycle_v2::{transition,transition_with_history},votes_v2::HeightAuthority};
    use std::collections::BTreeMap;
    let u=1+LOCK_HEIGHTS;let h=u+EVIDENCE_HEIGHTS;
    state.wallets=wallets.clone();
    let registry=state.continuity.as_mut().unwrap();registry.first_period_committed=true;
    let member=&mut registry.members[0];member.history.p=1;member.history.s=1;member.history.h=1;
    member.history.penalties=7.into();let member=member.clone();
    let mut lot=Lot(BondLot{id:[80;32],node:member.node,lineage:member.lineage,owner:owner.public().address_id(1).unwrap(),
        atoms:MINIMUM_ATOMS,created_height:1,sequence:0,unbond_height:None,settled_height:None,status:LotStatus::Active,evidence:[0;32]});
    state.bonds_v2.lots.insert(lot.0.id,lot.clone());
    state.accounting.slots.last_height=u-1;state.accounting.slots.period=(u-1)/60;
    let historical_parent=FinalizedAnchor{network:NETWORK_ID,genesis:registry.genesis,fingerprint:registry.fingerprint,height:u-1,block:[81;32]};
    let historical=HeightAuthority::from_state(&state,historical_parent.clone(),state.root().unwrap()).unwrap();
    let voter=&historical.voters[&member.node];let roots=historical.roots();
    let mut a=Vote{decision:Decision{network:NETWORK_ID,genesis:historical_parent.genesis,fingerprint:historical_parent.fingerprint,
        purpose:2,height:u,mining_epoch:u-1,continuity_period:(u-1)/60,round:1,step:3,
        previous_finalized_anchor:historical_parent.id(),parent:historical_parent.block,block:[82;32],state:[83;32],
        membership:roots[0],reputation:roots[1],attestation:roots[2]},nil:false,node:member.node,
        hardware_generation:1,key_generation:1,sequence:1,tpm_identity:voter.tpm_identity(),profile:voter.profile,
        signature:HybridSignature{ed448:[0;114],fndsa:[0;1280]}};
    a.sign(continuity_key).unwrap();let mut b=a.clone();b.decision.block=[84;32];b.sequence=2;b.sign(continuity_key).unwrap();
    let evidence=Evidence::new(a,b).unwrap();let history=[(u,historical)].into_iter().collect();
    lot.start_unbond(u,1).unwrap();state.bonds_v2.lots.insert(lot.0.id,lot.clone());
    state.accounting.slots.last_height=h-1;state.accounting.slots.period=(h-1)/60;
    let parent=FinalizedAnchor{height:h-1,block:[85;32],..historical_parent};
    let mut command=Operation{genesis:parent.genesis,fingerprint:parent.fingerprint,
        envelope:Envelope{first_height:h,last_height:h,reference_height:parent.height,reference_block:parent.block,preconditions:vec![]},owner:lot.0.owner,
        authorizer:owner.public().descriptor(1).unwrap(),action:Action::Withdraw{lot:lot.0.id,sequence:2},
        signature:HybridSignature{ed448:[0;114],fndsa:[0;1280]}};command.sign(owner).unwrap();
    let mut body=BlockBody{height:h,reward_owner:lot.0.owner,fees:0,transactions:vec![],operations:vec![command.encode().unwrap()]};
    let root=state.root().unwrap();
    let paid=transition(&state,&parent,root,&body).unwrap();assert_eq!(paid.payouts.len(),1);assert!(paid.registry.members[0].eligible);
    body.operations.push(evidence.encode().unwrap());
    assert!(transition(&state,&parent,root,&body).is_err());
    let burned=transition_with_history(&state,&parent,root,&body,&history).unwrap();
    body.operations.reverse();assert_eq!(transition_with_history(&state,&parent,root,&body,&history).unwrap(),burned);
    assert!(burned.payouts.is_empty());assert_eq!(burned.burned,MINIMUM_ATOMS as u128);
    assert!(!burned.registry.members[0].eligible);assert_eq!(burned.registry.members[0].history.penalties,7.into());
    assert!(burned.penalties.tombstoned(member.lineage,1));assert!(!burned.penalties.tombstoned(member.lineage,2));
    assert!(state.continuity.as_ref().unwrap().members[0].eligible);assert_eq!(state.bonds_v2.lots[&lot.0.id],lot);
    qualify_history_envelope(&state,&parent,&body,&history,continuity_key);
    let mut exit=Exit{genesis:parent.genesis,fingerprint:parent.fingerprint,height:h,parent_anchor:parent.id(),node:member.node,
        hardware_generation:1,sequence:1,authorizer:node_key.public().descriptor(1).unwrap(),signature:HybridSignature{ed448:[0;114],fndsa:[0;1280]}};
    exit.sign(node_key).unwrap();body.operations.insert(0,exit.encode().unwrap());
    let result=transition_with_history(&state,&parent,root,&body,&history).unwrap();
    assert!(result.membership.get(member.node).unwrap().exit_boundary().is_none());
    assert_eq!(result.registry.members[0].history.penalties,7.into());
    let mut post=state.clone();post.accounting=result.accounting;post.continuity=Some(result.registry);post.membership_v2=result.membership;
    post.bonds_v2=result.bonds;post.penalties_v2=result.penalties;
    let records=post.records().unwrap();
    let restored=mutiny_consensus_v8::execution::State::from_records(&records,post.root().unwrap()).unwrap();
    assert!(restored.records().unwrap()==records);
    assert!(restored.penalties_v2==post.penalties_v2 && restored.bonds_v2==post.bonds_v2);
    assert!(restored.membership_v2==post.membership_v2 && restored.accounting==post.accounting);
    assert!(restored.continuity.as_ref().unwrap().members==post.continuity.as_ref().unwrap().members);
    let next_parent=FinalizedAnchor{height:h,block:[86;32],..parent};
    let authority=HeightAuthority::from_state(&post,next_parent,post.root().unwrap()).unwrap();
    assert_eq!(authority.voters[&member.node].weight().unwrap(),0.into());
}

fn qualify_history_envelope(state:&mutiny_consensus_v8::execution::State,
    anchor:&mutiny_consensus_v8::anchors::FinalizedAnchor,body:&mutiny_consensus_v8::blocks::BlockBody,
    history:&mutiny_consensus_v8::evidence_history_v2::History,continuity_key:&HybridKey) {
    use mutiny_consensus_v8::{execution::{WorkParent,CandidatePreparation},license_book_v2::Book,
        pow::{Candidate,WorkAuthority,WorkHeader,mining_epoch},work_authority_v2::Authority,
        votes_v2::{HeightAuthority,AuthenticatedRound},continuity_v2::{Vote,Certificate},certificates::Decision,
        block_envelope_v2::BlockEnvelope};
    let (_,assignments,expected,licenses,coordinator)=license_fixture::fixtures();
    let mut state=state.clone();state.licenses_v2=Book::genesis(&assignments,&expected,&licenses,
        &Default::default(),anchor.genesis,anchor.fingerprint).unwrap();
    let mut body=body.clone();body.reward_owner=licenses[0].owner;
    let parent=WorkParent{genesis:anchor.genesis,fingerprint:anchor.fingerprint,block:anchor.block,
        height:anchor.height,t0:1000,target:[255;32],ancestor_timestamps:(0..11).map(|offset|1000+(anchor.height-offset)*60).collect()};
    let mut c=Candidate{network:anchor.network,genesis:anchor.genesis,fingerprint:anchor.fingerprint,
        parent:anchor.block,height:body.height,timestamp:1000+body.height*60,body_root:body.root().unwrap(),
        state_root:[0;32],license:licenses[0].id,worker:expected[0].worker_id,target:parent.target};
    let input=|candidate|CandidatePreparation{parent:&parent,candidate,ticket_sequence:1,body:&body};
    assert!(state.prepare_candidate_v2(input(&c)).is_err());
    let executed=state.prepare_candidate_with_history_v2(input(&c),history).unwrap();c.state_root=executed.root;
    // The assembler must preserve evidence and require authenticated history,
    // even when no ordinary payment is pending.
    let mut nonce=[0;16];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let pool_path=std::env::temp_dir().join(format!("build8-history-assembly-{}.sqlite",hex::encode(nonce)));
    let mut pool=mutiny_consensus_v8::mempool_v2::Mempool::open(&pool_path,anchor.genesis,anchor.fingerprint,64*1024*1024).unwrap();
    pool.reconcile(anchor,&state,&Default::default()).unwrap();
    let request=||mutiny_consensus_v8::assembler_v2::Request{parent:&parent,state:&state,pool:&pool,
        license:c.license,worker:c.worker,timestamp:c.timestamp,ticket:1,operations:&body.operations};
    assert!(mutiny_consensus_v8::assembler_v2::prepare(request()).is_err());
    let prepared=mutiny_consensus_v8::assembler_v2::prepare_with_history(request(),history).unwrap();
    assert_eq!(prepared.candidate,c);assert_eq!(prepared.body,body);
    assert_eq!(prepared.execution.state.records().unwrap(),executed.state.records().unwrap());
    let mut invalid_history=history.clone();let (offense,historical_authority)=history.canonical_entries().next().unwrap();let mut wrong=historical_authority.clone();wrong.parent.block[0]^=1;invalid_history.insert(*offense,wrong);
    assert!(mutiny_consensus_v8::assembler_v2::prepare_with_history(request(),&invalid_history).is_err());
    drop(pool);std::fs::remove_file(pool_path).unwrap();
    let epoch=mining_epoch(c.timestamp,parent.t0).unwrap();
    let mut work=Authority{work:WorkAuthority{candidate:c.clone(),assignment_sequence:1,ticket_sequence:1,
        coordinator:expected[0].coordinator,nonce_start:0,nonce_end:100,epoch},node_descriptor:assignments[0].node_descriptor.clone(),
        signature:HybridSignature{ed448:[0;114],fndsa:[0;1280]}};work.sign(&coordinator).unwrap();
    let header=WorkHeader{candidate:c,authority:work.id().unwrap(),nonce:1};
    let authority=HeightAuthority::from_state(&state,anchor.clone(),state.root().unwrap()).unwrap();
    let (node,voter)=authority.voters.iter().next().unwrap();assert!(!voter.weight().unwrap().is_zero());
    let decision=Decision{network:anchor.network,genesis:anchor.genesis,fingerprint:anchor.fingerprint,purpose:2,
        height:body.height,mining_epoch:epoch,continuity_period:(body.height-1)/60,round:0,step:3,
        previous_finalized_anchor:anchor.id(),parent:anchor.block,block:header.block_hash(),state:executed.root,
        membership:authority.membership,reputation:authority.reputation,attestation:authority.attestation};
    let mut vote=Vote{decision:decision.clone(),nil:false,node:*node,hardware_generation:voter.hardware_generation,
        key_generation:voter.key_generation,sequence:3,tpm_identity:voter.tpm_identity(),profile:voter.profile,
        signature:HybridSignature{ed448:[0;114],fndsa:[0;1280]}};vote.sign(continuity_key).unwrap();
    let envelope=BlockEnvelope{header:header.clone(),body:body.clone(),authority:work.clone(),certificate:Certificate{decision,votes:vec![vote]}};
    let before=state.records().unwrap();
    assert!(envelope.verify_execute(&state,&parent,&authority).is_err());
    let verified=envelope.verify_execute_with_history(&state,&parent,&authority,history).unwrap();
    assert_eq!(envelope.verify_execute_from_parent_state(&state,&parent,state.root().unwrap(),history).unwrap().root,verified.root);
    assert!(envelope.verify_execute_from_parent_state(&state,&parent,[0;32],history).is_err());
    assert_eq!(verified.root,executed.root);assert!(verified.state.records().unwrap()==executed.state.records().unwrap());
    assert!(!verified.state.continuity.as_ref().unwrap().members[0].eligible);
    let mut wrong=history.clone();let (offense,historical_authority)=history.canonical_entries().next().unwrap();let mut bad_authority=historical_authority.clone();bad_authority.parent.block[0]^=1;wrong.insert(*offense,bad_authority);
    assert!(envelope.verify_execute_with_history(&state,&parent,&authority,&wrong).is_err());
    let mut round=AuthenticatedRound::new(authority.clone()).unwrap();
    assert!(round.validate_proposal_with_history(&state,&parent,&header,&work,&body,&wrong).is_err());
    assert!(round.observe(&envelope.certificate.votes[0]).is_err());
    round.validate_proposal_with_history(&state,&parent,&header,&work,&body,history).unwrap();
    round.observe(&envelope.certificate.votes[0]).unwrap();
    let mut invalid=envelope.clone();invalid.certificate.votes[0].signature.fndsa[500]^=1;
    assert!(invalid.verify_execute_with_history(&state,&parent,&authority,history).is_err());
    assert!(state.records().unwrap()==before);
}

fn qualify_rolling_lifecycle(
    mut state: mutiny_consensus_v8::execution::State,
    node_key: &HybridKey,
    credited_slots: u64,
) {
    use mutiny_consensus_v8::{
        NETWORK_ID, anchors::FinalizedAnchor, blocks::BlockBody, continuity_exit_v2::Exit,
        continuity_lifecycle_v2::transition, freshness::PhysicalMember,
        participation::ParticipationAck,
    };
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let registry = state.continuity.as_ref().unwrap();
    let member = registry.members[0].clone();
    let profile = TpmProfile::decode(
        &state
            .continuity_keys_v2
            .get(member.node)
            .unwrap()
            .admission()
            .profile,
    )
    .unwrap();
    let ak = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let identity = SigningKey::from_bytes((&[10u8; 32]).into()).unwrap();
    let physical = PhysicalMember {
        node: member.node,
        generation: 1,
        continuity_key: member.voting_key,
        hardware: member.hardware,
        admission_commitment: member.attestation,
        attestation_key: profile.ak_public.clone(),
    };
    let challenge =
        mutiny_consensus_v8::freshness::genesis_challenge([27; 32], [28; 32], &physical);
    let evidence = quote(&ak, &profile, challenge);
    let verifier = mutiny_consensus_v8::tpm::PinnedTpmVerifier {
        profiles: std::collections::BTreeMap::from([(member.attestation, profile.clone())]),
    };
    let fresh = mutiny_consensus_v8::freshness::validate_genesis(
        [27; 32], [28; 32], &physical, &evidence, &verifier,
    )
    .unwrap();
    state.accounting.freshness.insert(member.node, fresh);
    let mut parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: registry.genesis,
        fingerprint: registry.fingerprint,
        height: 0,
        block: registry.anchor.tip,
    };
    let mut public_cases = Vec::new();
    for height in 1u64..=121 {
        if credited_slots < 60 && height > 60 {
            break;
        }
        let mut ack = ParticipationAck {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            node: member.node,
            height,
            parent: parent.id(),
            generation: 1,
            signature: [0; 64],
        };
        let sig: Signature = identity.sign_prehash(&ack.signing_digest()).unwrap();
        ack.signature = sig.normalize_s().unwrap_or(sig).to_bytes().into();
        let mut body = BlockBody {
            height,
            reward_owner: [30; 32],
            fees: 0,
            transactions: vec![],
            operations: vec![ack.encode()],
        };
        let root = state.root().unwrap();
        if (height - 1) % 60 >= credited_slots {
            body.operations.clear();
        }
        if height == 1 {
            assert!(transition(&state, &parent, [0; 32], &body).is_err());
            let mut wrong = parent.clone();
            wrong.block[0] ^= 1;
            assert!(transition(&state, &wrong, root, &body).is_err());
            let mut invalid = body.clone();
            invalid.fees = 1;
            assert!(transition(&state, &parent, root, &invalid).is_err());
            invalid = body.clone();
            invalid.transactions.push(vec![0x80]);
            assert!(transition(&state, &parent, root, &invalid).is_err());
        }
        if height == 121 {
            // No second refresh: block60's record expired after slot120.
            assert!(transition(&state, &parent, root, &body).is_err());
            body.operations.clear();
            let no_credit = transition(&state, &parent, root, &body).unwrap();
            assert!(no_credit.accounting.slots.bits.is_empty());
            break;
        }
        if height == 60 && credited_slots == 60 {
            let mut refresh = mutiny_consensus_v8::freshness::AttestationRefresh {
                network: NETWORK_ID,
                genesis: parent.genesis,
                fingerprint: parent.fingerprint,
                node: member.node,
                generation: 1,
                height,
                parent_anchor: parent.id(),
                evidence: vec![],
            };
            refresh.evidence = quote(&ak, &profile, refresh.challenge());
            body.operations.insert(0, refresh.encode().unwrap());
            let mut wrong = refresh.clone();
            wrong.parent_anchor = FinalizedAnchor {
                height: 60,
                ..parent.clone()
            }
            .id();
            wrong.evidence = quote(&ak, &profile, wrong.challenge());
            let mut bad = body.clone();
            bad.operations[0] = wrong.encode().unwrap();
            assert!(transition(&state, &parent, root, &bad).is_err());
            let mut stale = state.clone();
            stale.accounting.freshness.remove(&member.node);
            assert!(transition(&stale, &parent, stale.root().unwrap(), &body).is_err());
            let mut exit = Exit {
                genesis: parent.genesis,
                fingerprint: parent.fingerprint,
                height,
                parent_anchor: parent.id(),
                node: member.node,
                hardware_generation: 1,
                sequence: 1,
                authorizer: node_key.public().descriptor(1).unwrap(),
                signature: HybridSignature {
                    ed448: [0; 114],
                    fndsa: [0; 1280],
                },
            };
            exit.sign(node_key).unwrap();
            let mut exiting = body.clone();
            exiting.operations.insert(0, exit.encode().unwrap());
            let result = transition(&state, &parent, root, &exiting).unwrap();
            assert_eq!(result.registry.members[0].history.p, 1);
            assert!(!result.registry.members[0].eligible);
            assert!(state.continuity.as_ref().unwrap().members[0].eligible);
        }
        let result = transition(&state, &parent, root, &body).unwrap();
        let previous_records = state.records().unwrap();
        if height.is_multiple_of(60) {
            assert_eq!(
                result.registry.members[0].history.p,
                if credited_slots >= 54 { height / 60 } else { 0 }
            );
        } else {
            assert_eq!(
                result.accounting.slots.bits[&member.node].count_ones() as u64,
                ((height - 1) % 60 + 1).min(credited_slots)
            );
        }
        state.accounting = result.accounting;
        state.continuity = Some(result.registry);
        state.membership_v2 = result.membership;
        if credited_slots == 60 && [1, 59, 60, 61, 119, 120].contains(&height) {
            let encode_records = |rows: Vec<([u8; 32], Vec<u8>)>| {
                rows.into_iter()
                    .map(|(k, v)| serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)}))
                    .collect::<Vec<_>>()
            };
            public_cases.push(serde_json::json!({"height":height,"parent":hex::encode(parent.encode()),
                "body":hex::encode(body.encode().unwrap()),"before":encode_records(previous_records),
                "before_root":hex::encode(root),"after":encode_records(state.records().unwrap()),
                "after_root":hex::encode(state.root().unwrap())}));
        }
        // Synthetic harness advances an authenticated parent for the next case;
        // this is not a claim of mined/certified hardware history.
        parent.height = height;
        parent.block =
            mutiny_consensus_v8::domain_hash(b"SYNTHETIC-LIFECYCLE-PARENT", &height.to_be_bytes());
        assert_eq!(state.continuity.as_ref().unwrap().anchor.height, height - 1);
        if [59, 60, 119, 120].contains(&height) {
            state = mutiny_consensus_v8::execution::State::from_records(
                &state.records().unwrap(),
                state.root().unwrap(),
            )
            .unwrap();
        }
    }
    if credited_slots == 60
        && std::env::var("BUILD8_EXPORT_ROLLING_LIFECYCLE").as_deref() == Ok("1")
    {
        use std::io::Write;
        let value = serde_json::json!({"schema":"BUILD8-SYNTHETIC-ROLLING-HYBRID-LIFECYCLE-V2",
            "synthetic_only":true,"production_authorized":false,"cases":public_cases});
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../qualification/hybrid-rolling-lifecycle-public-v1.json"),
            )
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&value).unwrap())
            .unwrap();
    }
}
