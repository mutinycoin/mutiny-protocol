//! UNRUN actual native Store + adopted owning continuity workflow controls.
//! External provider is explicitly private cfg(test) modeled, not authenticated
//! real service/admin isolation. Hybrid proofs and native VFS are actual APIs.
use super::*;
use crate::treasury_admission_v3::{LocalStoragePolicy,StoreIdentity};
use crate::treasury_continuity_provider_v1::{ModeledProvider,Snapshot,AuthenticatedReceipt};
use std::{cell::RefCell,path::{Path,PathBuf},fs,io::Write,num::NonZeroU64,
    os::unix::fs::{DirBuilderExt,OpenOptionsExt}};
thread_local! {
    static BEFORE_CONFIRM:RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}
pub(super) fn before_confirm() {
    if let Some(action)=BEFORE_CONFIRM.with(|slot|slot.borrow_mut().take()){action();}
}
fn directory(label:&str)->PathBuf {
    let root=PathBuf::from(std::env::var_os("BUILD8_NATIVE_SQLITE_FIXTURE_ROOT")
        .expect("mandatory protected PUBLIC TEST fixture root missing"));
    assert!(root.is_absolute());let mut nonce=[0;32];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let path=root.join(format!("treasury-owner-native-{label}-{}",hex::encode(nonce)));
    let mut create=fs::DirBuilder::new();create.mode(0o700);create.create(&path).unwrap();
    eprintln!("RETAINED_PUBLIC_TREASURY_OWNER_NATIVE_FIXTURE={}",path.display());path
}
fn policy()->LocalStoragePolicy {
    LocalStoragePolicy::new(32*1024*1024,NonZeroU64::new(4_000_000).unwrap()).unwrap()
}
struct Fixture {
    dir:PathBuf,config:CeremonyConfig,scope:Scope,expect:Expect,
    key:mutiny_crypto_v2::rehearsal_keys_v1::Credential,
}
fn fixture(label:&str)->(Fixture,Owner<ModeledProvider>) {
    let key=mutiny_crypto_v2::rehearsal_keys_v1::Credential::from_label(label,1).unwrap();
    let config=CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK,
        crate::treasury_v1::Treasury::new(crate::treasury_v1::Class::TestValue,key.descriptor().unwrap()).unwrap(),label).unwrap();
    let expect=Expect::genesis_key(&config);let dir=directory(label);
    let id=AdmissionStore::create_native(&dir,&config,policy()).unwrap();
    let scope=Scope { network:mutiny_crypto_v2::NETWORK,genesis:None,
        ceremony_context:config.context().value(),treasury_record:native::record_sha256(config.treasury()).unwrap(),
        verifier:[71;32],store:id.store_id(),service:[72;32] };
    let store=AdmissionStore::open_native(&dir,&config,id,policy()).unwrap();
    let owner=Owner::new(store,ModeledProvider::new(scope.clone()).unwrap(),scope.clone(),expect.clone(),vec![],Denylist::default()).unwrap();
    assert!(!owner.frozen());(Fixture {dir,config,scope,expect,key},owner)
}
fn copy_to_new_dir(source:&Path,label:&str)->PathBuf {
    let dir=directory(label);let main=dir.join("state.sqlite");let bytes=fs::read(source).unwrap();
    let mut file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(main).unwrap();
    file.write_all(&bytes).unwrap();file.sync_all().unwrap();dir
}
#[test]
fn actual_native_owner_hybrid_confirmed_restore_freezes_then_exact_history_repairs() {
    let (f,mut owner)=fixture("PUBLIC-native-owner-confirmed-restore");let descriptor=f.key.descriptor().unwrap();
    let challenge=owner.issue(&descriptor).unwrap();assert_eq!(owner.sequence(),2);
    let stale=copy_to_new_dir(&f.dir.join("state.sqlite"),"stale-confirmed-restore");
    let bytes=challenge.encode().unwrap();let signature=proof::sign_challenge(f.key.key(),&descriptor,&challenge).unwrap();
    let mut forged=signature.clone();forged.ed448[0]^=1;
    assert!(owner.admit(&descriptor,&bytes,&forged).is_err());assert_eq!(owner.sequence(),2);assert!(!owner.frozen());
    owner.admit(&descriptor,&bytes,&signature).unwrap();assert_eq!(owner.sequence(),4);assert!(!owner.frozen());
    let external=owner.provider.engine.clone();drop(owner);
    let store=AdmissionStore::open_native(&stale,&f.config,StoreIdentity::from_trusted_id(f.scope.store).unwrap(),policy()).unwrap();
    let mut restarted=Owner::new(store,ModeledProvider{engine:external},f.scope,f.expect,vec![],Denylist::default()).unwrap();
    assert!(restarted.frozen());assert_eq!(restarted.sequence(),4);
    assert_eq!(restarted.issue(&descriptor),Err(Error::Frozen));
    assert_eq!(restarted.admit(&descriptor,&bytes,&signature),Err(Error::Frozen));
    restarted.reconcile().unwrap();assert!(!restarted.frozen());assert_eq!(restarted.sequence(),4);
    assert_eq!(restarted.admit(&descriptor,&bytes,&signature),Err(Error::Native(Refusal::Replay)));
    let row=restarted.store.recorded(&challenge.nonce).unwrap().unwrap();
    assert_eq!(row.challenge,bytes);assert_eq!(row.signature,proof::signature_to_bytes(&signature));
    assert_eq!(restarted.store.continuity_records().unwrap().len(),1);
}
struct LoseAck {inner:ModeledProvider,lose_next:bool}
impl Provider for LoseAck {
    fn scope(&self)->&Scope {self.inner.scope()}
    fn current(&mut self,nonce:Hash)->Result<Snapshot,ProviderError>{self.inner.current(nonce)}
    fn transition(&mut self,request:&Request)->Result<AuthenticatedReceipt,ProviderError>{
        let receipt=self.inner.transition(request)?;
        if self.lose_next {self.lose_next=false;Err(ProviderError::Unknown)} else {Ok(receipt)}
    }
}
#[test]
fn actual_native_lost_reservation_ack_retains_external_operation_and_exact_repair() {
    let (f,owner)=fixture("PUBLIC-native-owner-lost-reservation");
    let mut owner=Owner::new(owner.store,LoseAck{inner:owner.provider,lose_next:true},f.scope,f.expect,vec![],Denylist::default()).unwrap();
    let descriptor=f.key.descriptor().unwrap();let before=fs::read(f.dir.join("state.sqlite")).unwrap();
    assert_eq!(owner.issue(&descriptor),Err(Error::Provider(ProviderError::Unknown)));
    assert!(owner.frozen());assert_eq!(owner.provider.inner.engine.sequence(),1);
    assert!(owner.store.continuity_records().unwrap().is_empty());
    assert_eq!(fs::read(f.dir.join("state.sqlite")).unwrap(),before);
    assert_eq!(owner.issue(&descriptor),Err(Error::Frozen));
    owner.reconcile().unwrap();assert!(!owner.frozen());assert_eq!(owner.sequence(),2);
    assert_eq!(owner.store.continuity_records().unwrap().len(),1);
    assert!(!owner.provider.inner.engine.frozen());
}
#[test]
fn actual_native_lost_consumption_ack_never_reissues_terminal_nonce_and_exact_repair() {
    let (f,owner)=fixture("PUBLIC-native-owner-lost-consumption");
    let mut owner=Owner::new(owner.store,LoseAck{inner:owner.provider,lose_next:false},f.scope,f.expect,vec![],Denylist::default()).unwrap();
    let descriptor=f.key.descriptor().unwrap();let challenge=owner.issue(&descriptor).unwrap();let bytes=challenge.encode().unwrap();
    let signature=proof::sign_challenge(f.key.key(),&descriptor,&challenge).unwrap();
    owner.provider.lose_next=true;let before=fs::read(f.dir.join("state.sqlite")).unwrap();
    assert_eq!(owner.admit(&descriptor,&bytes,&signature),Err(Error::Provider(ProviderError::Unknown)));
    assert!(owner.frozen());assert_eq!(owner.provider.inner.engine.sequence(),3);
    assert!(!owner.store.issued(&challenge.nonce).unwrap().unwrap().consumed);
    assert_eq!(fs::read(f.dir.join("state.sqlite")).unwrap(),before);
    assert_eq!(owner.admit(&descriptor,&bytes,&signature),Err(Error::Frozen));
    owner.reconcile().unwrap();assert!(!owner.frozen());assert_eq!(owner.sequence(),4);
    assert!(owner.store.issued(&challenge.nonce).unwrap().unwrap().consumed);
    assert_eq!(owner.admit(&descriptor,&bytes,&signature),Err(Error::Native(Refusal::Replay)));
    assert_eq!(owner.provider.inner.engine.sequence(),4);
}
#[test]
fn exact_byte_substitution_before_confirm_preserves_pending_consumption_and_freeze() {
    let (f,mut owner)=fixture("PUBLIC-native-owner-before-confirm");let descriptor=f.key.descriptor().unwrap();
    let challenge=owner.issue(&descriptor).unwrap();let bytes=challenge.encode().unwrap();
    let signature=proof::sign_challenge(f.key.key(),&descriptor,&challenge).unwrap();
    let path=f.dir.clone();BEFORE_CONFIRM.with(|slot|*slot.borrow_mut()=Some(Box::new(move||{
        let main=path.join("state.sqlite");let exact=fs::read(&main).unwrap();
        fs::rename(&main,path.join("ORIGINAL-PINNED-state.sqlite")).unwrap();
        let mut file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(main).unwrap();
        file.write_all(&exact).unwrap();file.sync_all().unwrap();
    })));
    assert_eq!(owner.admit(&descriptor,&bytes,&signature),Err(Error::Native(Refusal::Store)));
    assert!(owner.frozen());assert_eq!(owner.provider.engine.sequence(),3,
        "ConfirmLocal must not reach service after native target substitution");
    assert!(owner.provider.engine.pending_operation().is_some());
    assert_eq!(owner.issue(&descriptor),Err(Error::Frozen));
    assert!(f.dir.join("state.sqlite").exists()&&f.dir.join("ORIGINAL-PINNED-state.sqlite").exists());
}

#[path="treasury_ceremony_support_v3.rs"]
mod lineage;
#[test]
fn actual_native_retired_generation_needs_exact_historical_expect_for_reconstruction() {
    // Existing qualified PUBLIC TEST helper applies a genuinely both-signed
    // wallet rotation through WalletBook and reproduces the strict StateRoot.
    // This is a trusted TEST state-root fixture, not a certified live chain or
    // physical Treasury/provider qualification. No helper scratch_dir is used.
    let c=lineage::Ceremony::new("PUBLIC-native-owner-retired-lineage");
    let dir=directory("retired-original");let old_expect=Expect::genesis_key(&c.config);
    let id=AdmissionStore::create_native(&dir,&c.config,policy()).unwrap();
    let scope=Scope {network:mutiny_crypto_v2::NETWORK,genesis:None,
        ceremony_context:c.config.context().value(),treasury_record:native::record_sha256(&c.treasury).unwrap(),
        verifier:[71;32],store:id.store_id(),service:[72;32]};
    let store=AdmissionStore::open_native(&dir,&c.config,id,policy()).unwrap();
    let mut owner=Owner::new(store,ModeledProvider::new(scope.clone()).unwrap(),scope.clone(),old_expect.clone(),vec![],Denylist::default()).unwrap();
    let d1=c.k1.descriptor().unwrap();let ch1=owner.issue(&d1).unwrap();let b1=ch1.encode().unwrap();
    let stale=copy_to_new_dir(&dir.join("state.sqlite"),"retired-stale-issued");
    let s1=proof::sign_challenge(c.k1.key(),&d1,&ch1).unwrap();owner.admit(&d1,&b1,&s1).unwrap();
    assert_eq!(owner.sequence(),4);let external=owner.provider.engine.clone();drop(owner);
    let (canonical,records)=c.lineage_config();let current=Expect::canonical_current(&canonical,&records).unwrap();
    assert_eq!(current.generation(),2);
    let store=AdmissionStore::open_native(&dir,&canonical,id,policy()).unwrap();
    let mut owner=Owner::new(store,ModeledProvider{engine:external},scope.clone(),current.clone(),vec![old_expect.clone()],Denylist::default()).unwrap();
    assert!(!owner.frozen());
    assert!(owner.store.verify_issued(&old_expect,&d1,&b1,&s1,&Denylist::default()).is_ok(),
        "exact historical audit remains valid without authorizing fresh retired-key use");
    assert_eq!(owner.issue(&d1),Err(Error::Native(Refusal::Proof(proof::ProofError::WrongKeyVersion))));
    assert_eq!(owner.sequence(),4);assert!(!owner.frozen());
    let d2=c.k2.descriptor().unwrap();let ch2=owner.issue(&d2).unwrap();let b2=ch2.encode().unwrap();
    let s2=proof::sign_challenge(c.k2.key(),&d2,&ch2).unwrap();owner.admit(&d2,&b2,&s2).unwrap();
    assert_eq!(owner.sequence(),8);let external=owner.provider.engine.clone();drop(owner);
    let before=fs::read(stale.join("state.sqlite")).unwrap();
    let store=AdmissionStore::open_native(&stale,&canonical,id,policy()).unwrap();
    let mut missing_history=Owner::new(store,ModeledProvider{engine:external.clone()},scope.clone(),current.clone(),vec![],Denylist::default()).unwrap();
    assert!(missing_history.frozen());assert_eq!(missing_history.reconcile(),Err(Error::History));
    drop(missing_history);assert_eq!(fs::read(stale.join("state.sqlite")).unwrap(),before);
    let store=AdmissionStore::open_native(&stale,&canonical,id,policy()).unwrap();
    let mut owner=Owner::new(store,ModeledProvider{engine:external},scope,current,vec![old_expect],Denylist::default()).unwrap();
    assert!(owner.frozen());owner.reconcile().unwrap();assert!(!owner.frozen());assert_eq!(owner.sequence(),8);
    assert_eq!(owner.store.continuity_records().unwrap().len(),2);
    assert_eq!(owner.admit(&d2,&b2,&s2),Err(Error::Native(Refusal::Replay)));
    assert_eq!(owner.sequence(),8);
}
