//! UNRUN certified TEST chain + native Admission/Service integration. All keys
//! are synthetic and stay RAM-only. No files contain custody envelopes or keys.
#[path="../../desktop/src/wallet_host_fixture_licenses.rs"] mod licenses;
#[path="../../consensus/tests/support/wallet_host_fixture_tpm.rs"] mod tpm;
include!("../../consensus/tests/support/dividend_rig.rs");
use super::{CanonicalOwner,audit_native};
use crate::{treasury_native_service_v1::{Service,Endpoint,Policy},
    treasury_continuity_provider_v1::authenticated_wire::{PublicPins,AuthenticatedProvider,WireTransport},
    treasury_continuity_provider_v1::ProviderError,
    treasury_continuity_v1::Scope,
    treasury_admission_v3::{AdmissionStore,StoreIdentity,LocalStoragePolicy},
    treasury_rehearsal_v3::{CeremonyConfig,TrustedChain,Denylist,Refusal},
    treasury_continuity_owner_v1::Error as OwnerError};
use std::{fs,io::{Read,Cursor,Write},path::PathBuf,num::NonZeroU64,rc::Rc,cell::RefCell,
    os::unix::fs::{DirBuilderExt,OpenOptionsExt}};
use mutiny_crypto_v2::{rehearsal_keys_v1::Credential,treasury_proof_v1 as proof};
fn directory(label:&str)->PathBuf{
    let root=PathBuf::from(std::env::var_os("BUILD8_NATIVE_SQLITE_FIXTURE_ROOT").expect("mandatory native TEST root"));
    assert!(root.is_absolute());let mut salt=[0;32];mutiny_crypto_v2::fill_os_random(&mut salt).unwrap();
    let path=root.join(format!("native-canonical-{label}-{}",hex::encode(salt)));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    eprintln!("RETAINED_PUBLIC_NATIVE_CANONICAL_TREASURY={}",path.display());path
}
fn local()->LocalStoragePolicy{LocalStoragePolicy::new(32*1024*1024,NonZeroU64::new(4_000_000).unwrap()).unwrap()}
fn service_policy()->Policy{Policy::new(32*1024*1024,NonZeroU64::new(4_000_000).unwrap()).unwrap()}
#[derive(Clone)]struct Wire{endpoint:Rc<RefCell<Endpoint>>}
impl WireTransport for Wire{
    fn exchange(&mut self,raw:&[u8])->Result<Box<dyn Read>,ProviderError>{
        let reply=self.endpoint.try_borrow_mut().map_err(|_|ProviderError::Unavailable)?.handle(raw)
            .map_err(|_|ProviderError::Unknown)?;
        Ok(Box::new(Cursor::new(reply)))
    }
}
struct ClientFactory{pins:PublicPins,encrypted:Vec<u8>,endpoint:Rc<RefCell<Endpoint>>}
impl ClientFactory{
    fn open(&self)->AuthenticatedProvider<Wire>{
        // Exact same enrolled TEST pin, using normal role/context custody in RAM.
        // No envelope, password or private key is printed/written/archived.
        let(key,g)=HybridKey::open_for(mutiny_crypto_v2::Role::Transport,"PUBLIC NATIVE TREASURY TEST ONLY",&[91;32],&self.encrypted).unwrap();
        assert_eq!(g,1);AuthenticatedProvider::modeled(self.pins.clone(),key,Wire{endpoint:self.endpoint.clone()}).unwrap()
    }
}
fn client(config:&CeremonyConfig,scope:&Scope)->ClientFactory{
    let key=HybridKey::generate(mutiny_crypto_v2::Role::Transport).unwrap();let server=HybridKey::generate(mutiny_crypto_v2::Role::Transport).unwrap();
    let pins=PublicPins::new(scope.clone(),[92;32],key.public().descriptor(1).unwrap(),server.public().descriptor(1).unwrap()).unwrap();
    let encrypted=key.seal_for("PUBLIC NATIVE TREASURY TEST ONLY",1,&[91;32]).unwrap();drop(key);
    let endpoint=Rc::new(RefCell::new(Endpoint::new(Service::create_native(&directory("service"),config,scope.clone(),service_policy()).unwrap(),pins.clone(),server).unwrap()));
    ClientFactory{pins,encrypted,endpoint}
}
fn config(rig:&Rig,key:&HybridKey,label:&str)->CeremonyConfig{
    CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK,Treasury::new(Class::TestValue,desc(key,1)).unwrap(),label).unwrap()
        .with_trusted_chain(TrustedChain{network:rig.parent.network,genesis:rig.parent.genesis,
            fingerprint:rig.parent.fingerprint,height:rig.parent.height}).unwrap()
}
fn scoped(config:&CeremonyConfig,id:StoreIdentity)->Scope{
    Scope{network:config.network(),genesis:config.trusted_chain().map(|c|c.genesis),
        ceremony_context:config.context().value(),treasury_record:crate::treasury_rehearsal_v3::record_sha256(config.treasury()).unwrap(),
        verifier:[94;32],store:id.store_id(),service:[95;32]}
}
fn funded_rig(key:&HybridKey)->(Rig,OutPoint){
    let mut f=fixture_with_treasury(key,1_200_000);let sponsor=owner_key();
    let fund=OutPoint{transaction:[0xe1;32],index:0};
    f.state.coins.insert(fund.clone(),Coin{output:Output{owner:addr(&sponsor,1),atoms:40_000},created_height:0,coinbase:false});
    let rig=Rig::new(f,"native-treasury-canonical");eprintln!("RETAINED_PUBLIC_CANONICAL_CHAIN={}",rig.base.display());(rig,fund)
}
fn copy(dir:&PathBuf)->PathBuf{
    let dest=directory("stale-admission");let bytes=fs::read(dir.join("state.sqlite")).unwrap();
    let mut file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(dest.join("state.sqlite")).unwrap();
    file.write_all(&bytes).unwrap();file.sync_all().unwrap();dest
}
#[test]
fn genuine_funded_rotation_reopens_current_owner_and_audits_retired_hybrid_proof(){
    let k1=Credential::from_label("PUBLIC-native-canonical-k1",1).unwrap();
    let k2=Credential::from_label("PUBLIC-native-canonical-k2",2).unwrap();
    let(mut rig,fund)=funded_rig(k1.key());let base=config(&rig,k1.key(),"PUBLIC-native-canonical-startup");
    let dir=directory("admission");let id=AdmissionStore::create_native(&dir,&base,local()).unwrap();
    let scope=scoped(&base,id);let clients=client(&base,&scope);
    let mut owner=CanonicalOwner::open_native(&dir,id,local(),&rig.chain,base.clone(),clients.open(),scope.clone(),Denylist::default()).unwrap();
    assert!(!owner.frozen());let d1=k1.descriptor().unwrap();let ch1=owner.issue(&d1).unwrap();
    let stale=copy(&dir);let sig1=proof::sign_challenge(k1.key(),&d1,&ch1).unwrap();
    owner.admit(&d1,&ch1.encode().unwrap(),&sig1).unwrap();assert_eq!(owner.sequence(),4);
    assert!(owner.close().is_ok());
    rig.step(P,&[]);
    let tx=sponsored_rotation(&rig,addr(k1.key(),1),(k1.key(),1),(k2.key(),2),&owner_key(),fund,39_000,1_000);
    rig.pool.admit(&tx,&rig.parent,&rig.state).unwrap();rig.step(P+1,&[]);let rig=rig.restart();
    let cap=rig.chain.treasury_lineage().unwrap();assert_eq!(cap.current_generation(),2);
    assert_eq!(cap.descriptor(1),Some(d1.as_slice()));assert_eq!(cap.descriptor(2),Some(k2.descriptor().unwrap().as_slice()));
    let before=fs::read(stale.join("state.sqlite")).unwrap();
    let mut restored=CanonicalOwner::open_native(&stale,id,local(),&rig.chain,base.clone(),clients.open(),scope.clone(),Denylist::default()).unwrap();
    assert!(restored.frozen());assert_eq!(restored.startup_refusal(),Some(OwnerError::ReconciliationRequired));
    assert_eq!(fs::read(stale.join("state.sqlite")).unwrap(),before);
    assert_eq!(restored.issue(&d1),Err(OwnerError::Frozen));restored.reconcile().unwrap();assert!(!restored.frozen());
    assert_eq!(restored.issue(&d1),Err(OwnerError::Native(Refusal::Proof(proof::ProofError::WrongKeyVersion))));
    let d2=k2.descriptor().unwrap();let ch2=restored.issue(&d2).unwrap();let sig2=proof::sign_challenge(k2.key(),&d2,&ch2).unwrap();
    restored.admit(&d2,&ch2.encode().unwrap(),&sig2).unwrap();assert_eq!(restored.sequence(),8);assert!(restored.close().is_ok());
    let before=fs::read(stale.join("state.sqlite")).unwrap();
    for _ in 0..2{let mut provider=clients.open();
        let proofs=audit_native(&stale,id,local(),&rig.chain,&base,&mut provider,&scope,&Denylist::default()).unwrap();
        assert_eq!(proofs.len(),2);assert_eq!(proofs.iter().map(|p|p.generation).collect::<std::collections::BTreeSet<_>>(),[1,2].into_iter().collect());
        assert_eq!(fs::read(stale.join("state.sqlite")).unwrap(),before);
    }
    drop(rig); // Retain all canonical/service/admission evidence; no cleanup.
}
#[test]
fn canonical_startup_wrong_trusted_store_identity_and_chain_refuse_before_native_write(){
    let key=Credential::from_label("PUBLIC-native-canonical-wrong",1).unwrap();let(rig,_)=funded_rig(key.key());
    let base=config(&rig,key.key(),"PUBLIC-native-canonical-wrong");let dir=directory("admission");
    let id=AdmissionStore::create_native(&dir,&base,local()).unwrap();let scope=scoped(&base,id);let clients=client(&base,&scope);
    let before=fs::read(dir.join("state.sqlite")).unwrap();let wrong=StoreIdentity::from_trusted_id([97;32]).unwrap();
    assert!(matches!(CanonicalOwner::open_native(&dir,wrong,local(),&rig.chain,base.clone(),clients.open(),scope.clone(),Denylist::default()),Err(OwnerError::Context)));
    let mut chain=base.trusted_chain().unwrap();chain.genesis[0]^=1;
    let bad=base.with_trusted_chain(chain).unwrap();
    assert!(matches!(CanonicalOwner::open_native(&dir,id,local(),&rig.chain,bad,clients.open(),scope,Denylist::default()),Err(OwnerError::Context)));
    assert_eq!(fs::read(dir.join("state.sqlite")).unwrap(),before);assert!(matches!(fs::symlink_metadata(dir.join("state.sqlite-journal")), Err(e) if e.kind()==std::io::ErrorKind::NotFound));drop(rig);
}
