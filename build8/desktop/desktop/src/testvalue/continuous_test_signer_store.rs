//! EXTERNAL SOURCE ONLY / UNCOMPILED. Private future PUBLIC SOFTWARE TEST campaign.
//! Never imports/opens the old Launch16 context or provisions production custody.
//! DPAPI wraps existing crypto-v2 encrypted role envelopes. No key bytes exported.
//! The durable sequence is a software TEST journal, NOT a TPM/rollback-proof counter.
//! Existing physical CounterStore/MonotonicCounter/permit policy is unchanged.
#![cfg(all(windows, feature = "testvalue-window"))]
use super::image_pin::DatabasePin;
use crate::dpapi_v2::dpapi;
use mutiny_crypto_v2::{Domain, HybridKey, PublicKey, Role};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor, continuity_v2::{Vote, ParentVoter}};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::{cell::Cell,rc::Rc,mem::ManuallyDrop};
#[path="continuous_pinned_sqlite_vfs.rs"] mod pinned_sqlite_vfs;
#[path="continuous_sqlite_close_boundary.rs"] mod sqlite_close_boundary;
pub(crate) use super::image_pin::native_handle_owner;
pub(crate) fn install_sqlite_close_boundary_at_process_entry()->Result<()>{sqlite_close_boundary::install_at_process_entry()}
#[path="continuous_native_sqlite_reconciliation.rs"] pub(crate) mod sqlite_reconciliation;
use pinned_sqlite_vfs::PinnedConnection;
use sha2::{Digest,Sha512};
use std::{collections::BTreeMap,fs::{File,OpenOptions},io::Write,path::Path,os::windows::fs::OpenOptionsExt,os::windows::io::{AsRawHandle,FromRawHandle}};
use windows_sys::Win32::{Storage::FileSystem::{LockFileEx,UnlockFileEx,FILE_FLAG_OPEN_REPARSE_POINT,FILE_SHARE_READ,FILE_SHARE_WRITE,LOCKFILE_EXCLUSIVE_LOCK,LOCKFILE_FAIL_IMMEDIATELY},System::IO::OVERLAPPED};
type Result<T> = std::result::Result<T,String>;
pub(super) const MARKER:&str="MUTINY-W15-NONSHIPPING-SYNTHETIC-SIGNER-CUSTODY-V1";
// PUBLIC TEST value, not a user password or production custody input. DPAPI CurrentUser
// plus exact protected native files are mandatory; plaintext role secrets stay zeroizing.
const TEST_PASSWORD:&str="PUBLIC-W15-SYNTHETIC-ONLY-CUSTODY-NOT-PRODUCTION";
const MAX_ENVELOPE:usize=32768;
const MAX_COMMIT:usize=4096;
const MAX_HEIGHT:u64=384;
const SCHEMAS:[(&str,&str);4]=[
 ("test_signer_context","CREATE TABLE test_signer_context(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL CHECK(length(context)=64),tip INTEGER NOT NULL CHECK(tip>=0))"),
 ("test_signer_keys","CREATE TABLE test_signer_keys(role INTEGER PRIMARY KEY CHECK(role IN (4,6)),envelope BLOB NOT NULL CHECK(length(envelope) BETWEEN 1 AND 32768))"),
 ("test_commit_locks","CREATE TABLE test_commit_locks(height INTEGER PRIMARY KEY CHECK(height BETWEEN 1 AND 384),sequence INTEGER NOT NULL,body BLOB NOT NULL CHECK(length(body) BETWEEN 1 AND 4096),signed BLOB CHECK(signed IS NULL OR length(signed) BETWEEN 1 AND 4096))"),
 ("test_work_locks","CREATE TABLE test_work_locks(ticket INTEGER PRIMARY KEY CHECK(ticket BETWEEN 1 AND 384),height INTEGER NOT NULL CHECK(height BETWEEN 1 AND 384 AND ticket=height),body BLOB NOT NULL CHECK(length(body) BETWEEN 1 AND 8192),signed BLOB CHECK(signed IS NULL OR length(signed) BETWEEN 1 AND 8192))"),
];
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
fn nonzero(h:&Hash)->Result<()>{if *h==[0;32]{Err("TEST signer context empty".into())}else{Ok(())}}
/// Construct only inside the native service AFTER all original public state/store pins
/// have been authenticated. No request codec/ambient path/production boolean reaches it.
#[derive(Clone)] // PUBLIC identity/context only; no private key/ciphertext cloning.
pub(super) struct Binding {
 pub campaign:Hash,pub source:Hash,pub genesis:Hash,pub fingerprint:Hash,
 pub initial_root:Hash,pub original_store_identities:Hash,pub native_custody_identity:Hash,pub native_guard_identity:Hash,
 pub node_descriptor:Vec<u8>,pub continuity_descriptor:Vec<u8>,
}
impl Binding {
 pub(super) fn possession_context(&self)->Result<[u8;64]>{self.context()}
 fn context(&self)->Result<[u8;64]>{
  let mut h=Sha512::new();h.update(MARKER.as_bytes());h.update(mutiny_network());
  for pin in [&self.campaign,&self.source,&self.genesis,&self.fingerprint,&self.initial_root,&self.original_store_identities,&self.native_custody_identity,&self.native_guard_identity]{nonzero(pin)?;h.update(pin);}
  for (raw,role) in [(&self.node_descriptor,Role::Node),(&self.continuity_descriptor,Role::Continuity)]{
   let(p,g)=PublicKey::decode_descriptor(raw).map_err(err)?;
   if p.role!=role||g==0{return Err("TEST signer exact role/generation".into());}
   h.update((raw.len() as u64).to_be_bytes());h.update(raw);
  }Ok(h.finalize().into())
 }
 fn expected(&self,role:Role)->Result<(PublicKey,u64)>{
  PublicKey::decode_descriptor(match role{Role::Node=>&self.node_descriptor,Role::Continuity=>&self.continuity_descriptor,_=>return Err("Synthetic provider role refused".into())}).map_err(err)
 }
}
fn mutiny_network()->[u8;4]{mutiny_crypto_v2::NETWORK.to_be_bytes()}
// Validate the complete caller buffer extent BEFORE any Windows SID API reads it.
fn bounded_sid(user:&[u8])->Result<()> {
 if user.len()<8||user[0]!=1||user[1]>15||user.len()!=8+4*usize::from(user[1]){return Err("Synthetic caller SID pre-read extent".into());}Ok(())
}
/// Only the future NEW synthetic bootstrap invokes this. CREATE_NEW cannot
/// overwrite an existing file or change any existing ACL. Empty-leaf partials
/// remain preserved if subsequent native ancestry/identity checks refuse.
pub(super) fn create_new_private_leaf(path:&Path,user:&[u8])->Result<()> {
 use windows_sys::Win32::{Foundation::{LocalFree,INVALID_HANDLE_VALUE},Security::{Authorization::{ConvertSidToStringSidW,ConvertStringSecurityDescriptorToSecurityDescriptorW,SDDL_REVISION_1},IsValidSid,GetLengthSid,SECURITY_ATTRIBUTES},Storage::FileSystem::{CreateFileW,CREATE_NEW}};
 bounded_sid(user)?;
 if !path.is_absolute()||path.to_str().is_none_or(|s|!s.is_ascii()||s.contains('\0'))||unsafe{IsValidSid(user.as_ptr().cast_mut().cast())}==0||unsafe{GetLengthSid(user.as_ptr().cast_mut().cast())} as usize!=user.len(){return Err("NEW synthetic leaf absolute route/SID bounds".into());}
 let mut sid=std::ptr::null_mut();if unsafe{ConvertSidToStringSidW(user.as_ptr().cast_mut().cast(),&mut sid)}==0{return Err("Synthetic SID text conversion".into());}
 let mut n=0;while n<256&&unsafe{*sid.add(n)}!=0{n+=1;}
 let text=if n<256{String::from_utf16(unsafe{std::slice::from_raw_parts(sid,n)}).map_err(err)}else{Err("Synthetic SID text bound".into())};unsafe{LocalFree(sid.cast());}let text=text?;
 let sddl:Vec<u16>=format!("O:{text}D:P(A;;FA;;;{text})(A;;FA;;;SY)").encode_utf16().chain(Some(0)).collect();
 let mut sd=std::ptr::null_mut();if unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(),SDDL_REVISION_1,&mut sd,std::ptr::null_mut())}==0{return Err("Synthetic NEW protected descriptor".into());}
 let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,lpSecurityDescriptor:sd,bInheritHandle:0};
 let name:Vec<u16>=path.to_str().ok_or("Synthetic path")?.encode_utf16().chain(Some(0)).collect();
 let handle=unsafe{CreateFileW(name.as_ptr(),0xc0000000,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,std::ptr::null_mut())};unsafe{LocalFree(sd);}
 if handle.is_null()||handle==INVALID_HANDLE_VALUE{return Err("Synthetic NEW leaf refused; never repair/overwrite".into());}
 let file=unsafe{File::from_raw_handle(handle)};private_leaf(&file,user)?;file.sync_all().map_err(err)?;drop(file);
 // Ancestry/volume/one-link native check before any encrypted role key write.
 DatabasePin::open(path,user)?.recheck()?;Ok(())
}
/// Lifetime-held byte lock on a separately protected, initialized guard file. SQLite
/// may write its own DB, while a second key-owning certifier cannot acquire this lock.
#[derive(Clone,Copy,PartialEq,Eq)] enum GuardLock {Never,Acquired,Unknown,Released}
struct GuardRecord {next:*mut GuardRecord,file:Option<native_handle_owner::NativeFile>,pin:Option<DatabasePin>,overlap:OVERLAPPED,lock:GuardLock,
 lock_attempted:bool,lock_result:Option<bool>,unlock_attempted:bool,unlock_result:Option<bool>,native_error:u32}
static RETAINED_GUARDS:std::sync::atomic::AtomicPtr<GuardRecord>=std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
fn retain_guard(record:Box<GuardRecord>){
 let raw=Box::into_raw(record);let mut head=RETAINED_GUARDS.load(std::sync::atomic::Ordering::Acquire);
 loop{unsafe{(*raw).next=head;}
  match RETAINED_GUARDS.compare_exchange_weak(head,raw,std::sync::atomic::Ordering::AcqRel,std::sync::atomic::Ordering::Acquire){Ok(_)=>break,Err(now)=>head=now}
 }
}
// Exact records are rooted before native effects and never dereferenced from
// another thread. Retention carries original pin/HANDLE/lock observation.
struct Guard {record:Option<Box<GuardRecord>>,closed:bool,quarantine:Rc<Cell<bool>>,
 #[cfg(test)] unlock_trace:Rc<Cell<(u32,Option<bool>,bool)>>,#[cfg(test)] lost_unlock_ack:bool}
impl Guard {
 fn existing(path:&Path,user:&[u8])->Result<Self>{
  native_handle_owner::require_known()?;
  let record=Box::new(GuardRecord{next:std::ptr::null_mut(),file:None,pin:None,overlap:unsafe{std::mem::zeroed()},lock:GuardLock::Never,
   lock_attempted:false,lock_result:None,unlock_attempted:false,unlock_result:None,native_error:0});
  let mut owner=Self{record:Some(record),closed:false,quarantine:Rc::new(Cell::new(false)),
   #[cfg(test)]unlock_trace:Rc::new(Cell::new((0,None,false))),#[cfg(test)]lost_unlock_ack:false};
  let opened=(||{
   let record=owner.record.as_mut().unwrap();record.pin=Some(DatabasePin::open(path,user)?);
   record.file=Some(native_handle_owner::NativeFile::open(path,0xc0020081,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_FLAG_OPEN_REPARSE_POINT)?);
   let file=record.file.as_ref().unwrap().file()?;
   record.pin.as_ref().unwrap().check_opened(file)?;private_leaf(file,user)?;
   // Record UNKNOWN before LockFileEx so a panic/error cannot release a lock
   // that may have been acquired. Exact lock-violation means no acquisition.
   record.lock=GuardLock::Unknown;record.lock_attempted=true;
   let acquired=unsafe{LockFileEx(file.as_raw_handle(),LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY,0,1,0,&mut record.overlap)}!=0;
   record.lock_result=Some(acquired);
   if !acquired{
    let error=unsafe{windows_sys::Win32::Foundation::GetLastError()};
    record.native_error=error;
    if error==33{record.lock=GuardLock::Never;}else{owner.quarantine.set(true);}
    return Err(format!("Synthetic signer exclusive guard unavailable: native {error}"));
   }record.lock=GuardLock::Acquired;Ok(())
  })();
  match opened{Ok(())=>Ok(owner),Err(primary)=>{let cleanup=owner.close_checked();Err(format!("Synthetic signer guard open refused: {primary}; owned cleanup={cleanup:?}"))}}
 }
 fn native_id_hash(&self)->Result<[u8;32]>{
  native_handle_owner::require_known()?;
  if self.closed{return Err("Synthetic signer guard revoked".into());}
  let pin=self.record.as_ref().and_then(|r|r.pin.as_ref()).ok_or("Synthetic signer original guard pin absent")?;pin.recheck()?;Ok(pin.native_id_hash())
 }
 fn close_checked(&mut self)->Result<()>{
  if self.closed{return Err("Synthetic signer guard cleanup already attempted; no retry".into());}
  self.closed=true;let already_quarantined=self.quarantine.get();
  let closed=(||{
   if self.quarantine.get(){return Err("Synthetic signer guard retained for unknown SQLite outcome".into());}
   let record=self.record.as_mut().ok_or("Synthetic signer guard original record absent")?;
   if record.lock==GuardLock::Unknown{return Err("Synthetic signer guard lock/unlock UNKNOWN; no retry".into());}
   if record.lock==GuardLock::Acquired{
    let raw=record.file.as_ref().ok_or("Synthetic signer guard file absent")?.raw()?;
    record.lock=GuardLock::Unknown;record.unlock_attempted=true;
    let unlocked=unsafe{UnlockFileEx(raw,0,1,0,&mut record.overlap)}!=0;record.unlock_result=Some(unlocked);
    record.native_error=if unlocked{0}else{unsafe{windows_sys::Win32::Foundation::GetLastError()}};
    #[cfg(test)] self.unlock_trace.set((1,Some(unlocked),unlocked&&self.lost_unlock_ack));
    #[cfg(test)] if unlocked&&self.lost_unlock_ack{return Err("MODELED lost successful UnlockFileEx acknowledgment; retained guard record, reported UNKNOWN".into());}
    if !unlocked{return Err(format!("Synthetic signer native unlock UNKNOWN {}",record.native_error));}
    record.lock=GuardLock::Released;
   }
   // Preserve ancestor holds until the guard data HANDLE is proven closed.
   if let Some(file)=record.file.as_mut(){file.close_checked()?;}
   if let Some(pin)=record.pin.as_mut(){pin.close_checked()?;}Ok(())
  })();
  if let Err(primary)=closed{self.quarantine.set(true);if !already_quarantined{native_handle_owner::quarantine();}if let Some(record)=self.record.take(){retain_guard(record);}return Err(primary);}
  self.record.take();Ok(())
 }
 #[cfg(test)] fn native_file_trace(&self)->native_handle_owner::CloseTrace{self.record.as_ref().unwrap().file.as_ref().unwrap().trace()}
 #[cfg(test)] fn model_lost_unlock_ack(&mut self){self.lost_unlock_ack=true;}
}
impl Drop for Guard {fn drop(&mut self){
 // Unknown SQLite/journal close must retain the exclusive native owner. Private
 // keys precede db/guard in Store's field drop order and are already erased.
 if !self.closed{let _=self.close_checked();}
 if let Some(record)=self.record.take(){self.quarantine.set(true);native_handle_owner::quarantine();retain_guard(record);}
}}
#[derive(Clone,Debug,PartialEq,Eq,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JournalPin{pub tip:u64,pub commits:u64,pub works:u64,pub commitment:Hash}
pub(super) struct Keys {pub node:HybridKey,pub continuity:HybridKey}
// Private keys are dropped BEFORE releasing native/exclusive signer ownership.
pub(super) struct Store {keys:Keys,db:PinnedConnection,context:[u8;64],binding:Binding,_lease:DatabasePin,_guard:Guard,
 #[cfg(test)] stop_after_reserve:bool,#[cfg(test)] private_commit_calls:u64,#[cfg(test)] stop_after_work_reserve:bool,#[cfg(test)] private_work_calls:u64}
fn schema(db:&Connection)->Result<()>{
 let (app,version):(i64,i64)=(db.pragma_query_value(None,"application_id",|r|r.get(0)).map_err(err)?,db.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(err)?);
 let count:i64=db.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get(0)).map_err(err)?;
 if app!=0x57534331||version!=1||count!=4{return Err("Synthetic signer initialized exact schema required".into());}
 for(name,expected)in SCHEMAS{
  let actual:String=db.query_row("SELECT CASE WHEN typeof(sql)='text' AND length(CAST(sql AS BLOB))<=1024 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name=?1 AND tbl_name=?1",[name],|r|r.get(0)).map_err(err)?;
  if actual!=expected{return Err("Synthetic signer foreign schema; no migration/repair".into());}
 }Ok(())
}
fn open_existing(path:&Path,user:&[u8],quarantine:Rc<Cell<bool>>)->Result<PinnedConnection>{
 let db=PinnedConnection::open(path,user,false,quarantine)?;
 db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;").map_err(err)?;
 Ok(db)
}
/// Exact confidentiality check on the actual opened handle, in addition to the
/// shared public-DB native identity policy. No existing ACL is ever rewritten.
fn private_leaf(file:&File,user:&[u8])->Result<()>{
 bounded_sid(user)?;
 use windows_sys::Win32::{Foundation::LocalFree,Security::{Authorization::{GetSecurityInfo,SE_FILE_OBJECT},GetLengthSid,IsValidSid,GetSecurityDescriptorControl,GetAclInformation,GetAce,OWNER_SECURITY_INFORMATION,DACL_SECURITY_INFORMATION,ACL_SIZE_INFORMATION,AclSizeInformation,ACCESS_ALLOWED_ACE,SE_DACL_PROTECTED}};
 let(mut owner,mut acl,mut sd)=(std::ptr::null_mut(),std::ptr::null_mut(),std::ptr::null_mut());
 let security_result=unsafe{GetSecurityInfo(file.as_raw_handle(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut owner,std::ptr::null_mut(),&mut acl,std::ptr::null_mut(),&mut sd)};
 struct Allocation(*mut core::ffi::c_void);impl Drop for Allocation{fn drop(&mut self){if !self.0.is_null(){unsafe{LocalFree(self.0);}}}}
 let _allocation=Allocation(sd);
 if security_result!=0{return Err("Synthetic custody actual security read refused".into());}
 if owner.is_null()||acl.is_null()||sd.is_null()||unsafe{IsValidSid(owner)}==0{return Err("Synthetic custody null/invalid native ACL".into());}
 let length=unsafe{GetLengthSid(owner)} as usize;
 if !(8..=68).contains(&length)||unsafe{std::slice::from_raw_parts(owner.cast::<u8>(),length)}!=user{return Err("Synthetic custody owner mismatch".into());}
 let(mut control,mut revision)=(0u16,0u32);
 if unsafe{GetSecurityDescriptorControl(sd,&mut control,&mut revision)}==0||control&SE_DACL_PROTECTED==0{return Err("Synthetic custody requires protected exact2ACE".into());}
 let mut size:ACL_SIZE_INFORMATION=unsafe{std::mem::zeroed()};
 if unsafe{GetAclInformation(acl,(&mut size as *mut ACL_SIZE_INFORMATION).cast(),std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,AclSizeInformation)}==0||size.AceCount!=2{return Err("Synthetic custody requires current user+SYSTEM only".into());}
 let system:&[u8]=&[1,1,0,0,0,0,0,5,18,0,0,0];let(mut user_seen,mut system_seen)=(false,false);
 for n in 0..2{
  let mut raw=std::ptr::null_mut();if unsafe{GetAce(acl,n,&mut raw)}==0||raw.is_null(){return Err("Synthetic custody ACE absent".into());}
  let a=unsafe{&*raw.cast::<ACCESS_ALLOWED_ACE>()};
  if a.Header.AceType!=0||a.Header.AceSize<16||a.Header.AceSize>76||a.Header.AceFlags!=0||a.Mask!=0x1f01ff{return Err("Synthetic custody exact direct full-control ACE required".into());}
  let sid=unsafe{raw.cast::<u8>().add(8)};let count=unsafe{*sid.add(1)} as usize;let len=8+4*count;
  if count>15||8+len!=a.Header.AceSize as usize||unsafe{IsValidSid(sid.cast())}==0||unsafe{GetLengthSid(sid.cast())} as usize!=len{return Err("Synthetic custody ACE SID bounds".into());}
  let sid=unsafe{std::slice::from_raw_parts(sid,len)};
  if sid==user&&!user_seen{user_seen=true;}else if sid==system&&!system_seen{system_seen=true;}else{return Err("Synthetic custody foreign/duplicate principal".into());}
 }if !user_seen||!system_seen{return Err("Synthetic custody missing exact principal".into());}Ok(())
}
fn context_row(db:&Connection,expected:&[u8;64])->Result<u64>{
 schema(db)?;
 let count:i64=db.query_row("SELECT count(*) FROM test_signer_context",[],|r|r.get(0)).map_err(err)?;
 let(context,tip):(Vec<u8>,u64)=db.query_row("SELECT CASE WHEN typeof(context)='blob' AND length(context)=64 THEN context ELSE NULL END,CASE WHEN typeof(tip)='integer' AND tip BETWEEN 0 AND 3840 THEN tip ELSE NULL END FROM test_signer_context WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(err)?;
 if count!=1||context!=expected{return Err("Synthetic signer original context/counter mismatch".into());}
 let max:u64=db.query_row("SELECT COALESCE(MAX(sequence),0) FROM test_commit_locks",[],|r|r.get(0)).map_err(err)?;
 let invalid:i64=db.query_row("SELECT count(*) FROM test_commit_locks WHERE typeof(height)!='integer' OR typeof(sequence)!='integer' OR height NOT BETWEEN 1 AND 384 OR sequence!=height*10 OR typeof(body)!='blob' OR length(body) NOT BETWEEN 1 AND 4096 OR (signed IS NOT NULL AND (typeof(signed)!='blob' OR length(signed) NOT BETWEEN 1 AND 4096))",[],|r|r.get(0)).map_err(err)?;
 let count:u64=db.query_row("SELECT count(*) FROM test_commit_locks",[],|r|r.get(0)).map_err(err)?;
 if max!=tip||invalid!=0||tip%10!=0||count!=tip/10{return Err("Synthetic signer durable journal/counter incoherent or missing original lock".into());}Ok(tip)
}
fn open_key(db:&Connection,b:&Binding,ctx:&[u8;64],role:Role)->Result<HybridKey>{
 let index=match role{Role::Node=>6,Role::Continuity=>4,_=>return Err("Synthetic signer role".into())};
 let sealed:Vec<u8>=db.query_row("SELECT CASE WHEN typeof(envelope)='blob' AND length(envelope) BETWEEN 1 AND 32768 THEN envelope ELSE NULL END FROM test_signer_keys WHERE role=?1",[index],|r|r.get(0)).map_err(err)?;
 let inner=dpapi(&sealed,ctx,false).map_err(err)?;
 let(k,g)=HybridKey::open_for(role,TEST_PASSWORD,ctx,&inner).map_err(err)?;
 let(p,expected_generation)=b.expected(role)?;
 if k.public()!=&p||g!=expected_generation{return Err("Synthetic signer ciphertext descriptor/generation mismatch".into());}
 // Existing domain-separated proof of key possession only, never admission/finality.
 let domain=if role==Role::Node{Domain::NodeAdmissionPossession}else{Domain::ContinuityPossession};
 let proof=k.sign(domain,ctx).map_err(err)?;p.verify(domain,ctx,&proof).map_err(err)?;Ok(k)
}
impl Store {
 /// Caller creates NEW protected custody DB+guard leaves and their authenticated
 /// native IDs first. Never call this on restart or before checking newly owned leaves.
 pub(super) fn initialize_before_h0(path:&Path,guard:&Path,user:&[u8],binding:Binding,node:&HybridKey,continuity:&HybridKey)->Result<Self>{
  let _guard=Guard::existing(guard,user)?;if _guard.native_id_hash()?!=binding.native_guard_identity{return Err("Synthetic original exclusive guard native identity differs".into());}let lease=DatabasePin::open(path,user)?;
  if lease.native_id_hash()!=binding.native_custody_identity{return Err("Synthetic initialized original custody native ID mismatch".into());}
  let leaf=OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path).map_err(err)?;lease.check_opened(&leaf)?;private_leaf(&leaf,user)?;
  if std::fs::metadata(path).map_err(err)?.len()!=0{return Err("NEW empty synthetic custody leaf required; preserve partial".into());}
  let ctx=binding.context()?;
  let mut db=open_existing(path,user,_guard.quarantine.clone())?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
  if tx.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get::<_,i64>(0)).map_err(err)?!=0{return Err("Existing synthetic custody refused initialization".into());}
  for(_,sql)in SCHEMAS{tx.execute_batch(sql).map_err(err)?;}
  tx.execute_batch("PRAGMA application_id=1465074481; PRAGMA user_version=1;").map_err(err)?;
  tx.execute("INSERT INTO test_signer_context VALUES(1,?1,0)",[ctx.as_slice()]).map_err(err)?;
  for(role,key,index)in[(Role::Node,node,6),(Role::Continuity,continuity,4)]{
   let(p,g)=binding.expected(role)?;if key.public()!=&p{return Err("Original generated synthetic key mismatch".into());}
   let inner=key.seal_for(TEST_PASSWORD,g,&ctx).map_err(err)?;
   let protected=dpapi(&inner,&ctx,true).map_err(err)?;
   if protected.len()>MAX_ENVELOPE{return Err("Synthetic encrypted envelope bound".into());}
   tx.execute("INSERT INTO test_signer_keys VALUES(?1,?2)",params![index,protected.as_slice()]).map_err(err)?;
  }tx.commit().map_err(err)?;db.close_checked()?;lease.recheck()?;drop(lease);drop(_guard);
  // Actual existing-only reopen, crypto/DPAPI readback and possession MUST precede
  // public H0 publication. No generated key is recovered from a public descriptor.
  Self::reopen_existing(path,guard,user,binding,0)
 }
 pub(super) fn reopen_existing(path:&Path,guard:&Path,user:&[u8],binding:Binding,own_canonical_height:u64)->Result<Self>{
  let _guard=Guard::existing(guard,user)?;if _guard.native_id_hash()?!=binding.native_guard_identity{return Err("Synthetic original exclusive guard native identity differs".into());}let _lease=DatabasePin::open(path,user)?;
  if _lease.native_id_hash()!=binding.native_custody_identity{return Err("Synthetic original custody native ID mismatch".into());}
  let leaf=OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path).map_err(err)?;_lease.check_opened(&leaf)?;private_leaf(&leaf,user)?;
  let ctx=binding.context()?;
  // Read-only initialized-schema/key/lock preflight BEFORE any writable SQLite
  // handle or PRAGMA journal reconciliation. Missing/empty/foreign leaves refuse.
  let read=PinnedConnection::open(path,user,true,_guard.quarantine.clone())?;
  read.execute_batch("PRAGMA trusted_schema=OFF;").map_err(err)?;let tip=context_row(&read,&ctx)?;
  if own_canonical_height>MAX_HEIGHT||tip<own_canonical_height.checked_mul(10).ok_or("Counter overflow")?{return Err("Retained signer journal behind own canonical history; no reset".into());}
  if read.query_row("SELECT count(*) FROM test_signer_keys",[],|r|r.get::<_,i64>(0)).map_err(err)?!=2{return Err("Exactly original Node/Continuity ciphertexts required".into());}
  let keys=Keys{node:open_key(&read,&binding,&ctx,Role::Node)?,continuity:open_key(&read,&binding,&ctx,Role::Continuity)?};
  read.close_checked()?;_lease.recheck()?;let db=open_existing(path,user,_guard.quarantine.clone())?;if context_row(&db,&ctx)?!=tip{return Err("Synthetic custody changed after preflight".into());}
  _lease.recheck()?;Ok(Self{db,_lease,_guard,context:ctx,keys,binding,#[cfg(test)] stop_after_reserve:false,#[cfg(test)] private_commit_calls:0,#[cfg(test)] stop_after_work_reserve:false,#[cfg(test)] private_work_calls:0})
 }
 /// Reserve the next original Node ticket before private work signing. Exact
 /// retries retain their ticket/body; no restart resets sequence or deletes locks.
 /// Context is derived by the service from its own verified canonical parent.
 pub(super) fn verify_current_parent_voter(&self,voter:&ParentVoter)->Result<()> {
  self.db.status()?;
  self._lease.recheck()?;
  let(public,generation)=self.binding.expected(Role::Continuity)?;
  if voter.public!=public||voter.key_generation!=generation||voter.hardware_generation==0||voter.weight().map_err(err)?.is_zero(){return Err("Retained original continuity provider differs from current authenticated parent voter".into());}
  let proof=self.keys.continuity.sign(Domain::ContinuityPossession,&self.context).map_err(err)?;
  voter.public.verify(Domain::ContinuityPossession,&self.context,&proof).map_err(err)?;Ok(())
 }
 /// Public durable software TEST journal commitment. No envelope, key, password
 /// or DPAPI buffer leaves this method; it is not a hardware monotonic proof.
 pub(super) fn journal_pin(&self)->Result<JournalPin>{
  self.db.status()?;
  self._lease.recheck()?;let tip=context_row(&self.db,&self.context)?;
  let commits:u64=self.db.query_row("SELECT count(*) FROM test_commit_locks",[],|r|r.get(0)).map_err(err)?;
  let works:u64=self.db.query_row("SELECT count(*) FROM test_work_locks",[],|r|r.get(0)).map_err(err)?;
  if commits>MAX_HEIGHT||works>MAX_HEIGHT{return Err("Original journal bounded row count".into());}
  let mut h=sha2::Sha256::new();h.update(b"MUTINY-W15-RETAINED-TEST-JOURNAL-V1");h.update(self.context);h.update(tip.to_be_bytes());
  for (tag,sql,bound) in [(1u8,"SELECT height,sequence,body,signed FROM test_commit_locks ORDER BY height",MAX_COMMIT),(2u8,"SELECT height,ticket,body,signed FROM test_work_locks ORDER BY ticket",8192usize)]{
   let mut statement=self.db.prepare(sql).map_err(err)?;let mut rows=statement.query([]).map_err(err)?;let mut count=0u64;
   while let Some(row)=rows.next().map_err(err)? {
    count+=1;if count>MAX_HEIGHT{return Err("Original journal result bound".into());}
    let height:u64=row.get(0).map_err(err)?;let sequence:u64=row.get(1).map_err(err)?;
    // SQLite typed bounds are checked before allocation; NULL preserves exact
    // before-sign reservation, not a synthesized signature/success.
    let body=row.get_ref(2).map_err(err)?.as_blob().map_err(err)?;
    let signed=row.get_ref(3).map_err(err)?;
    if !(1..=bound).contains(&body.len())||height!=count||sequence!=if tag==1{height*10}else{height}{return Err("Original contiguous journal body/sequence differs".into());}
    h.update([tag]);h.update(height.to_be_bytes());h.update(sequence.to_be_bytes());h.update((body.len()as u64).to_be_bytes());h.update(body);
    match signed{rusqlite::types::ValueRef::Null=>h.update([0]),rusqlite::types::ValueRef::Blob(raw) if (1..=bound).contains(&raw.len())=>{h.update([1]);h.update((raw.len()as u64).to_be_bytes());h.update(raw)},_=>return Err("Original signature journal type/bound".into())}
   }
   if count!=if tag==1{commits}else{works}{return Err("Original journal changed during snapshot".into());}
  }
  self._lease.recheck()?;Ok(JournalPin{tip,commits,works,commitment:h.finalize().into()})
 }
 /// Public original identity/context only. Never exposes envelope or private key.
 /// Same existing possession intents as encrypted reopen. No work/commit lock
 /// is signed here and durable initial journal must remain byte-for-byte same.
 pub(super) fn possession_before_h0(&self)->Result<(Vec<u8>,Vec<u8>)>{
  self.db.status()?;
  let before=self.journal_pin()?;if before.tip!=0||before.commits!=0||before.works!=0{return Err("Fresh initial provider already used; no reset".into());}
  let mut proofs=Vec::new();for(role,domain,key)in[(Role::Node,Domain::NodeAdmissionPossession,&self.keys.node),(Role::Continuity,Domain::ContinuityPossession,&self.keys.continuity)]{
   let(pk,_)=self.binding.expected(role)?;let sig=key.sign(domain,&self.context).map_err(err)?;pk.verify(domain,&self.context,&sig).map_err(err)?;let mut raw=sig.ed448.to_vec();raw.extend_from_slice(&sig.fndsa);proofs.push(raw);
  }if self.journal_pin()?!=before{return Err("Initial possession unexpectedly changed durable journal".into());}Ok((proofs.remove(0),proofs.remove(0)))
 }
 pub(super) fn binding_pin(&self)->Binding{self.binding.clone()}
 pub(super) fn node_descriptor(&self)->&[u8]{&self.binding.node_descriptor}
 pub(super) fn ticket_for_parent(&self,own_height:u64)->Result<u64>{
  self.db.status()?;
  self._lease.recheck()?;context_row(&self.db,&self.context)?;
  let invalid:i64=self.db.query_row("SELECT count(*) FROM test_work_locks WHERE typeof(ticket)!='integer' OR ticket NOT BETWEEN 1 AND 384 OR typeof(height)!='integer' OR height NOT BETWEEN 1 AND 384 OR ticket!=height OR typeof(body)!='blob' OR length(body) NOT BETWEEN 1 AND 8192 OR (signed IS NOT NULL AND (typeof(signed)!='blob' OR length(signed) NOT BETWEEN 1 AND 8192))",[],|r|r.get(0)).map_err(err)?;
  if invalid!=0{return Err("Retained TEST work journal malformed".into());}
  let tip:u64=self.db.query_row("SELECT COALESCE(MAX(ticket),0) FROM test_work_locks",[],|r|r.get(0)).map_err(err)?;
    let count:u64=self.db.query_row("SELECT count(*) FROM test_work_locks",[],|r|r.get(0)).map_err(err)?;
  let next=own_height.checked_add(1).ok_or("Retained work height overflow")?;
  if own_height>MAX_HEIGHT||count!=tip||tip<own_height||tip>next{return Err("Retained work journal behind/ahead own canonical parent; never clear/reset".into());}
  // If tip==next this is the SAME reserved pending ticket, not a new counter.
  // sign_work still compares the entire old unsigned body before returning/signing.
  if next>MAX_HEIGHT{return Err("Bounded TEST work journal exhausted; no reset".into());}Ok(next)
 }
 pub(super) fn sign_work(&mut self,mut authority:mutiny_consensus_v8::work_authority_v2::Authority,header:&mutiny_consensus_v8::pow::WorkHeader,ctx:&mutiny_consensus_v8::pow::WorkContext)->Result<mutiny_consensus_v8::work_authority_v2::Authority>{
  self.db.status()?;
  self._lease.recheck()?;context_row(&self.db,&self.context)?;
  let work=&authority.work;let c=&header.candidate;
  // Exact existing pow::validate_authority_fields checks before the key call.
  // No request-supplied context or ambient clock substitutes the own-parent context.
  if authority.node_descriptor!=self.binding.node_descriptor||c.network!=mutiny_consensus_v8::NETWORK_ID||c.genesis!=self.binding.genesis||c.fingerprint!=self.binding.fingerprint||c.genesis!=ctx.genesis||c.fingerprint!=ctx.fingerprint||c.parent!=ctx.parent||c.height!=ctx.parent_height.checked_add(1).ok_or("Work height overflow")?||c.height==0||c.height>MAX_HEIGHT||c.license!=ctx.license||c.worker!=ctx.worker||c.target!=ctx.target||work.candidate!=*c||authority.id().map_err(err)?!=header.authority||work.coordinator!=ctx.coordinator||work.assignment_sequence!=ctx.assignment_sequence||work.ticket_sequence<=ctx.last_accepted_ticket||work.nonce_start>work.nonce_end||header.nonce<work.nonce_start||header.nonce>work.nonce_end||work.epoch!=mutiny_consensus_v8::pow::mining_epoch(c.timestamp,ctx.t0).map_err(err)?||c.target==[0;32]{return Err("Retained TEST work/current canonical context mismatch".into());}
  mutiny_consensus_v8::pow::validate_timestamp(c.height,c.timestamp,ctx.t0,&ctx.ancestor_timestamps).map_err(err)?;
  let body=authority.unsigned().map_err(err)?;if body.len()>8192{return Err("TEST work body bound".into());}
  let ticket=work.ticket_sequence;
  use rusqlite::OptionalExtension;
  let expected=self.ticket_for_parent(ctx.parent_height)?;
  let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
  let old:Option<(Vec<u8>,Option<Vec<u8>>)>=tx.query_row("SELECT body,signed FROM test_work_locks WHERE ticket=?1",[ticket],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(err)?;
  let cached=if let Some((prior,signed))=old{if prior!=body{return Err("Retained TEST work ticket refuses different body".into());}signed}else{
   if ticket!=expected{return Err("Retained TEST work exact next ticket required".into());}
   tx.execute("INSERT INTO test_work_locks VALUES(?1,?2,?3,NULL)",params![ticket,c.height,&body]).map_err(err)?;None
  };tx.commit().map_err(err)?;
  if let Some(raw)=cached{let a=mutiny_consensus_v8::work_authority_v2::Authority::decode(&raw).map_err(err)?;if a.unsigned().map_err(err)?!=body{return Err("Cached work body mismatch".into());}a.verify(header,ctx,&self.binding.node_descriptor).map_err(err)?;return Ok(a);}
  #[cfg(test)] if self.stop_after_work_reserve{self.stop_after_work_reserve=false;return Err("TEST seam after original durable work reservation, before private operation".into());}
  #[cfg(test)] {self.private_work_calls=self.private_work_calls.checked_add(1).ok_or("TEST work signing call overflow")?;}
  authority.sign(&self.keys.node).map_err(err)?;authority.verify(header,ctx,&self.binding.node_descriptor).map_err(err)?;
  let raw=authority.encode().map_err(err)?;let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
  if tx.execute("UPDATE test_work_locks SET signed=?1 WHERE ticket=?2 AND body=?3 AND signed IS NULL",params![raw,ticket,body]).map_err(err)?!=1{return Err("TEST work signature CAS refusal; no return".into());}tx.commit().map_err(err)?;self._lease.recheck()?;Ok(authority)
 }
 /// Fixed round0, step3 TEST certifier only. Not a general BFT lock/unlock model.
 /// Reserve exact unsigned decision durably BEFORE any signature, and retain every
 /// pending/resolved row across restart. Unconfirmed rows never imply canonical finality.
 pub(super) fn sign_fixed_commit(&mut self,mut vote:Vote,parent:&FinalizedAnchor,roots:[Hash;3],voter:&ParentVoter)->Result<Vote>{
  self.db.status()?;
  self._lease.recheck()?;context_row(&self.db,&self.context)?;
  let original_node=mutiny_consensus_v8::node_admission_v2::node_id(self.binding.genesis,&self.binding.node_descriptor).map_err(err)?;
  if vote.node!=original_node{return Err("Retained fixed TEST vote belongs to a different node lineage".into());}
  let d=&vote.decision;
  if d.round!=0||d.step!=3||d.purpose!=2||d.continuity_period!=(d.height.checked_sub(1).ok_or("Height zero")?)/60||vote.nil||d.height!=parent.height.checked_add(1).ok_or("Height overflow")?||d.height>MAX_HEIGHT||d.genesis!=self.binding.genesis||d.fingerprint!=self.binding.fingerprint||vote.sequence!=d.height*10||vote.hardware_generation!=voter.hardware_generation||vote.key_generation!=voter.key_generation||&voter.public!=self.keys.continuity.public()||voter.weight().map_err(err)?.is_zero(){return Err("Fixed TEST canonical commit/current authority mismatch".into());}
  d.verify_parent(parent).map_err(err)?;
  if [d.membership,d.reputation,d.attestation]!=roots||vote.profile!=voter.profile||vote.tpm_identity!=voter.tpm_identity(){return Err("Fixed TEST authenticated parent context mismatch".into());}
  let body=vote.unsigned().map_err(err)?;if body.len()>MAX_COMMIT{return Err("Commit body bound".into());}
  let height=d.height;let sequence=vote.sequence;
  let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
  use rusqlite::OptionalExtension;
  let old:Option<(Vec<u8>,Option<Vec<u8>>)>=tx.query_row("SELECT body,signed FROM test_commit_locks WHERE height=?1",[height],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(err)?;
  let cached=if let Some((prior,signed))=old{if prior!=body{return Err("Retained TEST commit lock refuses conflicting body".into());}signed}else{
   let tip=context_row(&tx,&self.context)?;if sequence<=tip{return Err("Synthetic durable sequence stale; preserve journal".into());}
   tx.execute("INSERT INTO test_commit_locks VALUES(?1,?2,?3,NULL)",params![height,sequence,&body]).map_err(err)?;
   tx.execute("UPDATE test_signer_context SET tip=?1 WHERE id=1 AND tip<?1",[sequence]).map_err(err)?;None
  };tx.commit().map_err(err)?;
  let registry=BTreeMap::from([(vote.node,voter.clone())]);
  if let Some(raw)=cached{let restored=Vote::decode(&raw).map_err(err)?;if restored.unsigned().map_err(err)?!=body{return Err("Cached TEST vote body mismatch".into());}restored.verify(parent,roots,&registry).map_err(err)?;return Ok(restored);}
  #[cfg(test)] if self.stop_after_reserve{self.stop_after_reserve=false;return Err("TEST seam after durable reservation, before private operation".into());}
  #[cfg(test)] {self.private_commit_calls=self.private_commit_calls.checked_add(1).ok_or("TEST signing call overflow")?;}
  vote.sign(&self.keys.continuity).map_err(err)?;vote.verify(parent,roots,&registry).map_err(err)?;
  let raw=vote.encode().map_err(err)?;
  let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
  if tx.execute("UPDATE test_commit_locks SET signed=?1 WHERE height=?2 AND body=?3 AND signed IS NULL",params![raw,height,body]).map_err(err)?!=1{return Err("TEST signature journal CAS refusal; no return".into());}tx.commit().map_err(err)?;
  self._lease.recheck()?;Ok(vote)
 }
}
#[cfg(test)] #[path="../wallet_host_fixture_licenses.rs"] mod licenses;
#[cfg(test)] #[path="../wallet_host_fixture_tpm.rs"] mod tpm;
#[cfg(test)] mod tests {
 use super::{Binding,Store,create_new_private_leaf};
 use super::{licenses,tpm};
 use super::super::{image_pin::DatabasePin,process_auth::VerifiedProcess};
 include!("../../../consensus/tests/support/dividend_rig.rs");
 fn setup()->(std::path::PathBuf,Vec<u8>,Binding,Fixture){
  super::install_sqlite_close_boundary_at_process_entry().unwrap();
  let mut nonce=[0;16];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
  let root=std::env::temp_dir().join(format!("w15-future-synthetic-provider-{}",hex::encode(nonce)));
  assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
  let user=VerifiedProcess::observe_created_process(std::process::id()).unwrap().user_sid;
  let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");
  create_new_private_leaf(&path,&user).unwrap();create_new_private_leaf(&guard,&user).unwrap();
  let f=fixture();let binding=Binding{campaign:[1;32],source:[2;32],genesis:f.genesis.genesis,fingerprint:f.genesis.fingerprint,initial_root:f.state.root().unwrap(),original_store_identities:[5;32],native_custody_identity:DatabasePin::open(&path,&user).unwrap().native_id_hash(),native_guard_identity:DatabasePin::open(&guard,&user).unwrap().native_id_hash(),node_descriptor:f.coordinator.public().descriptor(1).unwrap(),continuity_descriptor:f.continuity.public().descriptor(1).unwrap()};
  (root,user,binding,f)
 }
 #[test] fn initial_public_possession_uses_existing_domains_and_retains_durable_journal(){
  let(root,user,b,f)=setup();let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");
  let store=Store::initialize_before_h0(&path,&guard,&user,b.clone(),&f.coordinator,&f.continuity).unwrap();let before=store.journal_pin().unwrap();
  let(node,continuity)=store.possession_before_h0().unwrap();assert_eq!(store.journal_pin().unwrap(),before);let intent=b.possession_context().unwrap();
  for(raw,key,domain,other)in [(node,f.coordinator.public(),mutiny_crypto_v2::Domain::NodeAdmissionPossession,mutiny_crypto_v2::Domain::ContinuityPossession),(continuity,f.continuity.public(),mutiny_crypto_v2::Domain::ContinuityPossession,mutiny_crypto_v2::Domain::NodeAdmissionPossession)]{
   assert_eq!(raw.len(),1394);let sig=mutiny_crypto_v2::HybridSignature{ed448:raw[..114].try_into().unwrap(),fndsa:raw[114..].try_into().unwrap()};key.verify(domain,&intent,&sig).unwrap();assert!(key.verify(other,&intent,&sig).is_err());
   let mut bad=intent;bad[0]^=1;assert!(key.verify(domain,&bad,&sig).is_err());let mut corrupt=sig.clone();corrupt.ed448[0]^=1;assert!(key.verify(domain,&intent,&corrupt).is_err());
  }
  assert_eq!(store.journal_pin().unwrap(),before);
  // PRIVATE trusted TEST provider MODEL. Actual exited bootstrap and distinct
  // process existing-only reopening must be observed by native acceptance.
 }
 // Private trusted TEST initial model; [5] store-ID commitment is intentionally
 // not an OwnGenesis/canonical bootstrap proof. Genuine service closure is separate.
 #[test] fn synthetic_roles_roundtrip_exact_context_and_original_native_custody(){
  let(root,user,b,f)=setup();let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");
  let first=Store::initialize_before_h0(&path,&guard,&user,b.clone(),&f.coordinator,&f.continuity).unwrap();
  assert_eq!(first.keys.node.public(),f.coordinator.public());assert_eq!(first.keys.continuity.public(),f.continuity.public());drop(first);
  let before=std::fs::read(&path).unwrap();
  for field in 0..8{let mut changed=b.clone();match field{0=>changed.campaign[0]^=1,1=>changed.source[0]^=1,2=>changed.genesis[0]^=1,3=>changed.fingerprint[0]^=1,4=>changed.initial_root[0]^=1,5=>changed.original_store_identities[0]^=1,6=>changed.native_custody_identity[0]^=1,_=>changed.native_guard_identity[0]^=1};assert!(Store::reopen_existing(&path,&guard,&user,changed,0).is_err());assert_eq!(std::fs::read(&path).unwrap(),before);}
  let resumed=Store::reopen_existing(&path,&guard,&user,b,0).unwrap();assert_eq!(resumed.keys.node.public(),f.coordinator.public());assert_eq!(resumed.keys.continuity.public(),f.continuity.public());drop(resumed);
  // No secret/ciphertext file enters public receipts or source archives; failed
  // and successful private fixtures are retained for explicitly scoped recovery.
 }
 #[test] fn existing_only_missing_empty_and_parallel_certifier_refuse_without_repair(){
  let(root,user,b,f)=setup();let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");
  assert!(Store::reopen_existing(&path,&guard,&user,b.clone(),0).is_err());assert_eq!(std::fs::metadata(&path).unwrap().len(),0);
  assert!(Store::reopen_existing(&root.join("missing.sqlite"),&guard,&user,b.clone(),0).is_err());assert!(matches!(std::fs::metadata(root.join("missing.sqlite")),Err(e) if e.kind()==std::io::ErrorKind::NotFound));
  let first=Store::initialize_before_h0(&path,&guard,&user,b.clone(),&f.coordinator,&f.continuity).unwrap();
  assert!(Store::reopen_existing(&path,&guard,&user,b.clone(),0).is_err());drop(first);
  let before=std::fs::read(&path).unwrap();assert!(Store::reopen_existing(&path,&guard,&user,b,1).is_err());assert_eq!(std::fs::read(&path).unwrap(),before);
 }
 #[test] fn synthetic_pending_commit_survives_reopen_exact_retry_and_conflict_refusal(){
  let(root,user,b,f)=setup();let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");
  let mut store=Store::initialize_before_h0(&path,&guard,&user,b.clone(),&f.coordinator,&f.continuity).unwrap();
  let authority=mutiny_consensus_v8::votes_v2::HeightAuthority::from_state(&f.state,f.genesis.clone(),f.state.root().unwrap()).unwrap();let(node,voter)=authority.voters.iter().next().unwrap();let roots=[authority.membership,authority.reputation,authority.attestation];
  let vote=Vote{decision:Decision{network:f.genesis.network,genesis:f.genesis.genesis,fingerprint:f.genesis.fingerprint,purpose:2,height:1,mining_epoch:0,continuity_period:0,round:0,step:3,previous_finalized_anchor:f.genesis.id(),parent:f.genesis.block,block:[91;32],state:[92;32],membership:roots[0],reputation:roots[1],attestation:roots[2]},nil:false,node:*node,hardware_generation:voter.hardware_generation,key_generation:voter.key_generation,sequence:10,tpm_identity:voter.tpm_identity(),profile:voter.profile,signature:empty()};
  store.stop_after_reserve=true;assert!(store.sign_fixed_commit(vote.clone(),&f.genesis,roots,voter).is_err());assert_eq!(store.private_commit_calls,0);drop(store);
  let mut reopened=Store::reopen_existing(&path,&guard,&user,b,0).unwrap();
  let signed=reopened.sign_fixed_commit(vote.clone(),&f.genesis,roots,voter).unwrap();assert_eq!(reopened.private_commit_calls,1);signed.verify(&f.genesis,roots,&authority.voters).unwrap();
  let raw=signed.encode().unwrap();assert_eq!(reopened.sign_fixed_commit(vote.clone(),&f.genesis,roots,voter).unwrap().encode().unwrap(),raw);assert_eq!(reopened.private_commit_calls,1);
  let before=std::fs::read(&path).unwrap();let mut conflict=vote;conflict.decision.block[0]^=1;assert!(reopened.sign_fixed_commit(conflict,&f.genesis,roots,voter).is_err());assert_eq!(reopened.private_commit_calls,1);assert_eq!(std::fs::read(&path).unwrap(),before);
  // Signature/retained-lock model only. Deliberate [91]/[92] hashes are not a
  // prepared/executed block; this test NEVER reports certified canonical finality.
 }
 #[test] fn genuine_prepared_work_reservation_reopens_same_original_signers_and_certifies(){
  let(root,user,b,f)=setup();let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");
  let mut store=Store::initialize_before_h0(&path,&guard,&user,b.clone(),&f.coordinator,&f.continuity).unwrap();
  let mut chain=CanonicalStore::open_trusted_genesis(&root.join("actual-own-canonical.sqlite"),&f.genesis,&f.state,f.state.root().unwrap(),T0,[255;32]).unwrap();
  let mut pool=Mempool::open(&root.join("actual-public-pool.sqlite"),f.genesis.genesis,f.genesis.fingerprint,65536).unwrap();
  // A fresh pool has no basis; bind it to the trusted head before preparing, as production callers do.
  chain.reconcile_pool(&mut pool).unwrap();
  let prepared=chain.prepare_pending(Preparation{expected_parent:&f.genesis,pool:&pool,license:f.license,worker:f.worker,timestamp:at(0)+1,ticket:1,operations:&[]}).unwrap();
  let (ctx,node)=chain.current_work_context(&f.genesis,prepared.candidate.license,prepared.candidate.worker,prepared.candidate.timestamp).unwrap();
  let work=Authority{work:WorkAuthority{candidate:prepared.candidate.clone(),assignment_sequence:ctx.assignment_sequence,ticket_sequence:1,coordinator:ctx.coordinator,nonce_start:0,nonce_end:100,epoch:mutiny_consensus_v8::pow::mining_epoch(prepared.candidate.timestamp,ctx.t0).unwrap()},node_descriptor:node,signature:empty()};
  let header=WorkHeader{candidate:prepared.candidate.clone(),authority:work.id().unwrap(),nonce:1};
  store.stop_after_work_reserve=true;assert!(store.sign_work(work.clone(),&header,&ctx).unwrap_err().contains("before private operation"));assert_eq!(store.private_work_calls,0);
  let original=store.journal_pin().unwrap();assert_eq!(original.works,1);assert_eq!(original.commits,0);drop(store);
  let mut resumed=Store::reopen_existing(&path,&guard,&user,b.clone(),0).unwrap();assert_eq!(resumed.journal_pin().unwrap(),original);assert_eq!(resumed.ticket_for_parent(0).unwrap(),1);
  let signed=resumed.sign_work(work.clone(),&header,&ctx).unwrap();signed.verify(&header,&ctx,resumed.node_descriptor()).unwrap();assert_eq!(resumed.private_work_calls,1);
  assert_eq!(resumed.sign_work(work.clone(),&header,&ctx).unwrap().encode().unwrap(),signed.encode().unwrap());assert_eq!(resumed.private_work_calls,1);
  let before=resumed.journal_pin().unwrap();let mut conflict=work;conflict.work.nonce_end=99;let changed_header=WorkHeader{candidate:header.candidate.clone(),authority:conflict.id().unwrap(),nonce:1};
  assert!(resumed.sign_work(conflict,&changed_header,&ctx).is_err());assert_eq!(resumed.journal_pin().unwrap(),before);assert_eq!(resumed.private_work_calls,1);
  let block=super::super::certifier_provider::certify_existing(prepared,&mut resumed,&chain,&f.genesis,&f.state).unwrap();
  assert!(chain.commit(&block).unwrap());let (head,state)=chain.load().unwrap();assert_eq!(head.height,1);assert_eq!(head.root,state.root().unwrap());
  let retained=resumed.journal_pin().unwrap();assert_eq!(retained.commits,1);assert_eq!(retained.works,1);drop(resumed);drop(chain);
  let reopened_chain=CanonicalStore::open_trusted_genesis(&root.join("actual-own-canonical.sqlite"),&f.genesis,&f.state,f.state.root().unwrap(),T0,[255;32]).unwrap();assert_eq!(reopened_chain.load().unwrap().0,head);
  let provider=Store::reopen_existing(&path,&guard,&user,b,1).unwrap();assert_eq!(provider.journal_pin().unwrap(),retained);assert_eq!(provider.ticket_for_parent(1).unwrap(),2);
  // Genuine prepared/certified TEST chain and persisted private provider; no
  // wallet authorization/mounted UI, physical TPM, production or old Launch16 recovery.
 }
 include!("continuous_pinned_sqlite_controls.rs");
 include!("continuous_native_sqlite_reconciliation_controls.rs");
}

// Distinct immutable TEST mode; fixed certifier schema/context stay unchanged.
#[path = "continuous_native_owner_store.rs"] pub(crate) mod native_owner_test;
