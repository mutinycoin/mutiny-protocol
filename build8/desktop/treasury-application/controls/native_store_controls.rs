//! UNRUN actual native Treasury Store controls, no modeled storage substitutes.
//! All keys/ceremonies are existing explicit PUBLIC TEST-VALUE fixtures. No
//! service authentication, production eligibility, physical or powerloss claim.
use super::*;
use std::{cell::{Cell,RefCell},fs,path::PathBuf,os::unix::fs::{DirBuilderExt,OpenOptionsExt}};
thread_local! {
    static BEFORE_EXTERNAL:RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    static BEFORE_COMMIT:RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}
pub(super) fn before_external() { if let Some(action)=BEFORE_EXTERNAL.with(|s|s.borrow_mut().take()){action();} }
pub(super) fn before_commit() { if let Some(action)=BEFORE_COMMIT.with(|s|s.borrow_mut().take()){action();} }
fn directory(label:&str)->PathBuf {
    let root=PathBuf::from(std::env::var_os("BUILD8_NATIVE_SQLITE_FIXTURE_ROOT")
        .expect("mandatory protected PUBLIC TEST fixture root missing"));
    assert!(root.is_absolute());
    let mut nonce=[0;32];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let path=root.join(format!("treasury-native-{label}-{}",hex::encode(nonce)));
    let mut builder=fs::DirBuilder::new();builder.mode(0o700);builder.create(&path).unwrap();
    // Native constructor independently pins/validates ALL actual ancestors,
    // owner/mode/no-follow/EXT-family. This helper never repairs existing paths.
    eprintln!("RETAINED_PUBLIC_TREASURY_NATIVE_FIXTURE={}",path.display());
    path
}
fn policy()->LocalStoragePolicy {
    // TEST resource configuration only; never a product/consensus default.
    LocalStoragePolicy::new(32*1024*1024,NonZeroU64::new(4_000_000).unwrap()).unwrap()
}
fn fixture(label:&str)->(mutiny_crypto_v2::rehearsal_keys_v1::Credential,CeremonyConfig,Denylist) {
    let key=mutiny_crypto_v2::rehearsal_keys_v1::Credential::from_label(label,1).unwrap();
    let descriptor=key.descriptor().unwrap();
    let config=CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK,
        crate::treasury_v1::Treasury::new(crate::treasury_v1::Class::TestValue,descriptor).unwrap(),label).unwrap();
    (key,config,Denylist::default())
}
fn signed(store:&mut AdmissionStore,key:&mutiny_crypto_v2::rehearsal_keys_v1::Credential,
    config:&CeremonyConfig,deny:&Denylist)->(Vec<u8>,Challenge,HybridSignature) {
    let descriptor=key.descriptor().unwrap();
    let challenge=store.issue(&Expect::genesis_key(config),&descriptor,deny).unwrap();
    let signature=proof::sign_challenge(key.key(),&descriptor,&challenge).unwrap();
    (descriptor,challenge,signature)
}
#[test]
fn genuine_native_create_issue_admit_reopen_retains_exact_hybrid_audit() {
    let dir=directory("positive");let (key,config,deny)=fixture("PUBLIC-native-Treasury-positive");
    let id=AdmissionStore::create_native(&dir,&config,policy()).unwrap();
    let mut store=AdmissionStore::open_native(&dir,&config,id,policy()).unwrap();
    let d=store.durability().unwrap();assert_eq!(d.synchronous,3);assert_eq!(d.journal_mode,"delete");
    assert!(!d.query_only&&!d.read_only);
    let (descriptor,challenge,signature)=signed(&mut store,&key,&config,&deny);let bytes=challenge.encode().unwrap();
    assert!(store.admit(&Expect::genesis_key(&config),&descriptor,&bytes,&signature,&deny).is_ok());
    assert_eq!(store.admit(&Expect::genesis_key(&config),&descriptor,&bytes,&signature,&deny),Err(Refusal::Replay));
    assert!(store.close().is_ok());
    let store=AdmissionStore::open_native_read_only(&dir,&config,id,policy()).unwrap();
    let d=store.durability().unwrap();assert!(d.query_only&&d.read_only);assert_eq!(d.journal_mode,"delete");
    let row=store.recorded(&challenge.nonce).unwrap().unwrap();
    assert_eq!(row.challenge,bytes);assert_eq!(row.descriptor,descriptor);
    assert_eq!(row.signature,proof::signature_to_bytes(&signature));
    assert!(store.verify_issued(&Expect::genesis_key(&config),&descriptor,&bytes,&signature,&deny).is_ok());
    assert_eq!(store.continuity_records().unwrap().len(),1);assert!(store.close().is_ok());
}
#[test]
fn wrong_identity_readonly_and_new_only_refuse_without_file_changes() {
    let dir=directory("identity");let (_,config,deny)=fixture("PUBLIC-native-Treasury-identity");
    let id=AdmissionStore::create_native(&dir,&config,policy()).unwrap();
    let before=fs::read(dir.join("state.sqlite")).unwrap();
    let mut wrong=id.store_id();wrong[0]^=0x80;
    assert!(AdmissionStore::open_native(&dir,&config,StoreIdentity::from_trusted_id(wrong).unwrap(),policy()).is_err());
    assert!(AdmissionStore::create_native(&dir,&config,policy()).is_err());
    let mut store=AdmissionStore::open_native_read_only(&dir,&config,id,policy()).unwrap();
    let descriptor=config.treasury().descriptor().to_vec();
    assert_eq!(store.issue(&Expect::genesis_key(&config),&descriptor,&deny),Err(Refusal::Store));
    assert!(store.close().is_ok());assert_eq!(fs::read(dir.join("state.sqlite")).unwrap(),before);
    assert!(!dir.join("state.sqlite-journal").exists());
}
#[test]
fn external_reservation_and_consumption_failure_preserve_local_rows() {
    let dir=directory("external-failure");let (key,config,deny)=fixture("PUBLIC-native-Treasury-external-failure");
    let id=AdmissionStore::create_native(&dir,&config,policy()).unwrap();
    let mut store=AdmissionStore::open_native(&dir,&config,id,policy()).unwrap();
    let calls=Cell::new(0);let descriptor=key.descriptor().unwrap();
    assert_eq!(store.issue_with_reservation(&Expect::genesis_key(&config),&descriptor,&deny,|_,_|{
        calls.set(calls.get()+1);Err(Refusal::Store)
    }),Err(Refusal::Store));
    assert_eq!(calls.get(),1);assert!(store.continuity_records().unwrap().is_empty());
    let (descriptor,challenge,signature)=signed(&mut store,&key,&config,&deny);let bytes=challenge.encode().unwrap();
    assert_eq!(store.admit_with_consumption(&Expect::genesis_key(&config),&descriptor,&bytes,&signature,&deny,|_|{
        calls.set(calls.get()+1);Err(Refusal::Store)
    }),Err(Refusal::Store));
    assert_eq!(calls.get(),2);assert!(!store.issued(&challenge.nonce).unwrap().unwrap().consumed);
    assert!(store.recorded(&challenge.nonce).unwrap().is_none());assert!(store.close().is_ok());
    let mut store=AdmissionStore::open_native(&dir,&config,id,policy()).unwrap();
    assert!(store.admit(&Expect::genesis_key(&config),&descriptor,&bytes,&signature,&deny).is_ok());
    assert!(store.close().is_ok());
    // These calls model a failing external callback, NOT an authenticated live
    // service. Existing continuity-owner uncertainty/reconciliation must qualify
    // with THIS native consumer in a subsequent genuine integration target.
}
fn substitute_exact_public_copy(dir:&Path) {
    let main=dir.join("state.sqlite");let bytes=fs::read(&main).unwrap();
    fs::rename(&main,dir.join("ORIGINAL-PINNED-state.sqlite")).unwrap();
    let mut out=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&main).unwrap();
    use std::io::Write;out.write_all(&bytes).unwrap();out.sync_all().unwrap();
    // Both exact public objects stay retained. Same binding/hash bytes on a
    // different inode must not pass the actual native lifetime boundary.
}
#[test]
fn exact_byte_main_substitution_before_external_use_refuses_provider_call() {
    let dir=directory("before-provider");let (key,config,deny)=fixture("PUBLIC-native-Treasury-before-provider");
    let id=AdmissionStore::create_native(&dir,&config,policy()).unwrap();
    let mut store=AdmissionStore::open_native(&dir,&config,id,policy()).unwrap();
    let (descriptor,challenge,signature)=signed(&mut store,&key,&config,&deny);let bytes=challenge.encode().unwrap();
    let renamed=dir.clone();BEFORE_EXTERNAL.with(|s|*s.borrow_mut()=Some(Box::new(move||substitute_exact_public_copy(&renamed))));
    let calls=Cell::new(0);
    assert_eq!(store.admit_with_consumption(&Expect::genesis_key(&config),&descriptor,&bytes,&signature,&deny,|_|{
        calls.set(calls.get()+1);Ok(())
    }),Err(Refusal::Store));
    assert_eq!(calls.get(),0,"unsafe native object must not reach even the TEST provider callback");
    assert!(store.storage.status().is_err());
    assert!(store.issued(&challenge.nonce).is_err(),"latched native failure denies later output");
    assert!(dir.join("state.sqlite").exists()&&dir.join("ORIGINAL-PINNED-state.sqlite").exists());
}
#[test]
fn substitution_after_external_consumption_before_commit_denies_success_and_stays_latched() {
    let dir=directory("before-commit");let (key,config,deny)=fixture("PUBLIC-native-Treasury-before-commit");
    let id=AdmissionStore::create_native(&dir,&config,policy()).unwrap();
    let mut store=AdmissionStore::open_native(&dir,&config,id,policy()).unwrap();
    let (descriptor,challenge,signature)=signed(&mut store,&key,&config,&deny);let bytes=challenge.encode().unwrap();
    let renamed=dir.clone();BEFORE_COMMIT.with(|s|*s.borrow_mut()=Some(Box::new(move||substitute_exact_public_copy(&renamed))));
    let external_consumed=Cell::new(false);
    assert_eq!(store.admit_with_consumption(&Expect::genesis_key(&config),&descriptor,&bytes,&signature,&deny,|_|{
        external_consumed.set(true);Ok(())
    }),Err(Refusal::Store));
    assert!(external_consumed.get(),"external terminal effect cannot be undone by a local error");
    assert!(store.storage.status().is_err());assert!(store.continuity_records().is_err());
    assert!(dir.join("state.sqlite").exists()&&dir.join("ORIGINAL-PINNED-state.sqlite").exists());
}
#[test]
fn restored_oversized_binding_blob_is_refused_readonly_without_repair() {
    let dir=directory("corrupt-field");let (_,config,_)=fixture("PUBLIC-native-Treasury-corrupt-field");
    let id=AdmissionStore::create_native(&dir,&config,policy()).unwrap();let main=dir.join("state.sqlite");
    // Corruption only in this fresh TEST DB, never any existing store.
    let db=Connection::open(&main).unwrap();
    db.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE store_binding SET context=zeroblob(32768);").unwrap();
    assert!(db.close().is_ok());let before=fs::read(&main).unwrap();
    assert!(AdmissionStore::open_native_read_only(&dir,&config,id,policy()).is_err());
    assert!(AdmissionStore::open_native(&dir,&config,id,policy()).is_err());
    assert_eq!(fs::read(&main).unwrap(),before);assert!(!dir.join("state.sqlite-journal").exists());
}

#[test]
fn each_invalid_signature_half_refuses_before_external_consumption_and_preserves_issuance() {
    let dir=directory("both-halves");let (key,config,deny)=fixture("PUBLIC-native-Treasury-both-halves");
    let id=AdmissionStore::create_native(&dir,&config,policy()).unwrap();
    let mut store=AdmissionStore::open_native(&dir,&config,id,policy()).unwrap();
    let (descriptor,challenge,signature)=signed(&mut store,&key,&config,&deny);
    let bytes=challenge.encode().unwrap();let before=fs::read(dir.join("state.sqlite")).unwrap();
    let calls=Cell::new(0);
    for ed448_half in [true,false] {
        let mut invalid=signature.clone();
        if ed448_half {invalid.ed448[0]^=1;} else {invalid.fndsa[0]^=1;}
        assert!(store.admit_with_consumption(&Expect::genesis_key(&config),&descriptor,&bytes,&invalid,&deny,|_|{
            calls.set(calls.get()+1);Ok(())
        }).is_err());
        assert_eq!(calls.get(),0,"neither invalid half may invoke irreversible external consumption");
        assert!(!store.issued(&challenge.nonce).unwrap().unwrap().consumed);
        assert!(store.recorded(&challenge.nonce).unwrap().is_none());
        assert_eq!(fs::read(dir.join("state.sqlite")).unwrap(),before);
    }
    assert!(store.admit(&Expect::genesis_key(&config),&descriptor,&bytes,&signature,&deny).is_ok());
    assert!(store.close().is_ok());
}
