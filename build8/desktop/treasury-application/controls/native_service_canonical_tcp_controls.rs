//! SOURCE ONLY / UNRUN. Genuine canonical current-generation native TCP funnel.
#[path="../../desktop/src/wallet_host_fixture_licenses.rs"] mod licenses;
#[path="../../consensus/tests/support/wallet_host_fixture_tpm.rs"] mod tpm;
include!("../../consensus/tests/support/dividend_rig.rs");
use super::{directory,local_policy,service_policy,limits,drive,head};
use super::super::{SerializedEndpoint,open_current_testvalue};
use crate::{treasury_admission_v3::AdmissionStore,
    treasury_rehearsal_v3::{CeremonyConfig,TrustedChain,Denylist},
    treasury_continuity_provider_v1::authenticated_wire::PublicPins,
    treasury_continuity_v1::Scope};
use std::{thread,sync::mpsc};
use mutiny_crypto_v2::{rehearsal_keys_v1::Credential,treasury_proof_v1 as proof};
#[test]
fn canonical_current_generation_native_owner_over_tcp_reopens_and_reaudits_exact_history(){
    let(public_tx,public_rx)=mpsc::channel();let(address_tx,address_rx)=mpsc::channel();
    let child=thread::spawn(move||{
        let credential=Credential::from_label("PUBLIC-native-canonical-tcp-k1",1).unwrap();
        let f=fixture_with_treasury(credential.key(),1_200_000);
        let rig=Rig::new(f,"native-canonical-tcp");
        eprintln!("RETAINED_PUBLIC_NATIVE_TCP_CHAIN={}",rig.base.display());
        let config=CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK,
            Treasury::new(Class::TestValue,credential.descriptor().unwrap()).unwrap(),
            "PUBLIC-native-canonical-tcp").unwrap().with_trusted_chain(TrustedChain{
                network:rig.parent.network,genesis:rig.parent.genesis,
                fingerprint:rig.parent.fingerprint,height:rig.parent.height}).unwrap();
        let dir=directory("canonical-admission");
        let id=AdmissionStore::create_native(&dir,&config,local_policy()).unwrap();
        let scope=Scope{network:config.network(),genesis:Some(rig.parent.genesis),
            ceremony_context:config.context().value(),
            treasury_record:crate::treasury_rehearsal_v3::record_sha256(config.treasury()).unwrap(),
            verifier:[121;32],store:id.store_id(),service:[122;32]};
        let client=HybridKey::generate(Role::Transport).unwrap();let server=HybridKey::generate(Role::Transport).unwrap();
        let pins=PublicPins::new(scope,[123;32],client.public().descriptor(1).unwrap(),
            server.public().descriptor(1).unwrap()).unwrap();
        // Normal role/context sealing retains only RAM custody for the
        // exact second startup; no private artifacts are written/printed.
        let encrypted=client.seal_for("PUBLIC NATIVE TCP TEST ONLY",1,&[124;32]).unwrap();
        public_tx.send((config.clone(),pins.clone(),server)).unwrap();
        let address=address_rx.recv().unwrap();
        let mut owner=open_current_testvalue(&dir,id,local_policy(),&rig.chain,config.clone(),
            pins.clone(),client,address,limits(),Denylist::default()).unwrap();
        assert!(!owner.frozen());assert_eq!(owner.startup_refusal(),None);
        let descriptor=credential.descriptor().unwrap();let challenge=owner.issue(&descriptor).unwrap();
        let signature=proof::sign_challenge(credential.key(),&descriptor,&challenge).unwrap();
        owner.admit(&descriptor,&challenge.encode().unwrap(),&signature).unwrap();
        assert_eq!(owner.sequence(),4);assert!(owner.close().is_ok());
        let before=std::fs::read(dir.join("state.sqlite")).unwrap();
        let(key,g)=HybridKey::open_for(Role::Transport,"PUBLIC NATIVE TCP TEST ONLY",&[124;32],&encrypted).unwrap();assert_eq!(g,1);
        let reopened=open_current_testvalue(&dir,id,local_policy(),&rig.chain,config,pins,key,
            address,limits(),Denylist::default()).unwrap();
        assert!(!reopened.frozen());assert_eq!(reopened.startup_refusal(),None);assert_eq!(reopened.sequence(),4);
        assert!(reopened.close().is_ok());assert_eq!(std::fs::read(dir.join("state.sqlite")).unwrap(),before);
        drop(rig);
    });
    let(config,pins,server_key)=public_rx.recv().unwrap();let service=directory("canonical-service");
    let mut endpoint=SerializedEndpoint::create_testvalue("127.0.0.1:0".parse().unwrap(),&config,
        &service,pins,server_key,service_policy(),limits()).unwrap();
    address_tx.send(endpoint.local_addr().unwrap()).unwrap();
    let(_,errors)=drive(&mut endpoint,child,|_,_|{});assert!(errors.is_empty());
    assert_eq!(head(&endpoint).sequence(),4);assert_eq!(head(&endpoint).pending_operation(),None);
    assert!(endpoint.close().is_ok());
}
