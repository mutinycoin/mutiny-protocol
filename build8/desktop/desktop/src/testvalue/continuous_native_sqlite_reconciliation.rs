//! Key-free forensic access for frozen PUBLIC TEST Node/Continuity providers.
//! A checkpoint is an expected snapshot, not authoritative consumption history.
//! No SQLite rollback/open, key decrypt, state write, journal deletion or unfreeze.
#![cfg(all(windows,feature="testvalue-window"))]
use super::{Binding,JournalPin,Guard,DatabasePin,Result,err,bounded_sid,private_leaf,native_owner_test};
use super::super::process_auth::{Identity,historical_process_closed};
use sha2::{Digest,Sha256};
use std::{cell::RefCell,fs::File,io::{Read,Seek,SeekFrom},mem::ManuallyDrop,marker::PhantomData,rc::Rc,
 os::windows::io::FromRawHandle,path::{Path,PathBuf},ptr};
use windows_sys::Win32::{Foundation::{HANDLE,INVALID_HANDLE_VALUE,CloseHandle},
 Storage::FileSystem::{CreateFileW,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,FILE_SHARE_READ}};
const MAX_FILE:u64=256*1024*1024; // Same existing ImagePin TEST-file bound.

pub(crate) enum ExpectedSnapshot{Fixed(JournalPin),Native(native_owner_test::JournalPin)}
impl ExpectedSnapshot{
 fn validate(&self)->Result<()>{match self{
  Self::Fixed(p)if p.commitment!=[0;32]&&p.tip<=super::MAX_HEIGHT*10&&p.commits<=super::MAX_HEIGHT&&p.works<=super::MAX_HEIGHT=>Ok(()),
  Self::Native(p)if p.mode=="NativeOwnerTest"&&p.commitment!=[0;32]&&p.records<=super::MAX_HEIGHT*10&&p.work_records<=super::MAX_HEIGHT*10=>Ok(()),
  _=>Err("Frozen TEST expected snapshot mode/extent invalid".into())}}
}
#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub(crate) enum RecoveryNeed{ExactAuthorizedTransitionUnavailable}

// A read handle is recorded before validation. Ordinary File Drop never closes
// this native HANDLE; one explicit CloseHandle observation owns each release.
struct ReadFile{file:Option<ManuallyDrop<File>>,raw:Option<HANDLE>,close_attempted:bool,close_observed:Option<bool>}
impl ReadFile{
 fn empty()->Self{Self{file:None,raw:None,close_attempted:false,close_observed:None}}
 fn open(&mut self,path:&Path)->Result<()>{
  let text=path.to_str().ok_or("Frozen TEST original ASCII path absent")?;
  if !path.is_absolute()||!text.is_ascii()||text.contains('\0'){return Err("Frozen TEST original bounded path invalid".into());}
  let wide:Vec<u16>=format!("\\\\?\\{}",text.replace('/',"\\")).encode_utf16().chain(Some(0)).collect();
  // READ_CONTROL|READ_ATTRIBUTES|READ_DATA, with neither WRITE nor DELETE
  // sharing. A prior live writer/mapping owner is not silently reconciled.
  let raw=unsafe{CreateFileW(wide.as_ptr(),0x00020081,FILE_SHARE_READ,ptr::null(),OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,ptr::null_mut())};
  if raw.is_null()||raw==INVALID_HANDLE_VALUE{return Err("Frozen TEST exclusive read-only nofollow hold refused".into());}
  self.raw=Some(raw);self.file=Some(ManuallyDrop::new(unsafe{File::from_raw_handle(raw)}));Ok(())
 }
 fn read_digest(&mut self)->Result<[u8;32]>{
  let file=self.file.as_mut().ok_or("Frozen TEST read HANDLE absent")?;
  let length=file.metadata().map_err(err)?.len();if length>MAX_FILE{return Err("Frozen TEST extent exceeds retained bound".into());}
  file.seek(SeekFrom::Start(0)).map_err(err)?;let mut buffer=zeroize::Zeroizing::new([0u8;8192]);let mut left=length;let mut hash=Sha256::new();
  while left>0{let wanted=(left as usize).min(buffer.len());file.read_exact(&mut buffer[..wanted]).map_err(err)?;hash.update(&buffer[..wanted]);left-=wanted as u64;}
  let mut eof=zeroize::Zeroizing::new([0u8;1]);if file.read(&mut eof[..]).map_err(err)?!=0||file.metadata().map_err(err)?.len()!=length{return Err("Frozen TEST held extent/EOF changed".into());}
  Ok(hash.finalize().into())
 }
 fn close_once(&mut self)->Result<()>{
  let Some(raw)=self.raw else{return Ok(())};if self.close_attempted{return Err("Frozen TEST native close unknown; never retry".into());}
  self.close_attempted=true;let result=unsafe{CloseHandle(raw)}!=0;self.close_observed=Some(result);
  if !result{return Err("Frozen TEST native CloseHandle outcome unknown".into());}self.raw=None;let _=self.file.take();Ok(())
 }
}
struct Inner{
 pin:ManuallyDrop<DatabasePin>,guard:ManuallyDrop<Guard>,main:ReadFile,journal:ReadFile,
 journal_path:PathBuf,scope:[u8;64],expected:ExpectedSnapshot,
 main_digest:Option<[u8;32]>,journal_digest:Option<[u8;32]>,journal_native:Option<[u8;32]>,primary:Option<String>,
 #[cfg(test)] modelled_previous_closure:bool,
}
impl Inner{
 fn check(&self)->Result<()>{
  self.pin.recheck()?;let main=self.main.file.as_ref().ok_or("Frozen TEST main custody absent")?;
  self.pin.check_opened(main)?;let journal=self.journal.file.as_ref().ok_or("Frozen TEST journal custody absent")?;
  if self.journal_native!=Some(self.pin.check_sqlite_journal(journal,&self.journal_path)?){return Err("Frozen TEST journal native identity changed".into());}Ok(())
 }
 fn close(&mut self)->Result<()>{
  // Attempt independent owned read handles once, retaining both outcomes.
  let journal=self.journal.close_once();let main=self.main.close_once();
  if journal.is_err()||main.is_err(){self.guard.quarantine.set(true);return Err(format!("Frozen TEST read release refused: journal={journal:?}, main={main:?}"));}Ok(())
 }
}
// The single owner is rooted BEFORE either native data-file open. It remains
// reachable during partial-read errors, unwind and uncertain close, without
// allocating a new custody holder on cleanup. Error Strings may allocate;
// an occupied slot refuses a second inspection.
thread_local!{static ROOT:RefCell<Option<Box<Inner>>>=const{RefCell::new(None)};}
pub(crate) struct FrozenInspection{owns:bool,_same_thread:PhantomData<Rc<()>>}
impl FrozenInspection{
 pub(crate) fn capture(path:&Path,guard_path:&Path,user:&[u8],binding:&Binding,expected:ExpectedSnapshot,prior:&Identity)->Result<Self>{
  expected.validate()?;bounded_sid(user)?;
  if prior.user_sid!=user||prior.image_sha256==[0;32]{return Err("Frozen TEST prior owner differs from original principal/image".into());}
  historical_process_closed(prior)?;Self::capture_closed(path,guard_path,user,binding,expected,false)
 }
 fn capture_closed(path:&Path,guard_path:&Path,user:&[u8],binding:&Binding,expected:ExpectedSnapshot,modelled:bool)->Result<Self>{
  if ROOT.with(|q|q.borrow().is_some()){return Err("Frozen TEST inspection active or quarantined; no new access".into());}
  expected.validate()?;let scope=binding.possession_context()?;
  let guard=Guard::existing(guard_path,user)?;
  if guard.native_id_hash()?!=binding.native_guard_identity{return Err("Frozen TEST exact original guard identity differs".into());}
  let pin=DatabasePin::open(path,user)?;if pin.native_id_hash()!=binding.native_custody_identity{return Err("Frozen TEST exact original database identity differs".into());}
  let journal_path=PathBuf::from(format!("{}-journal",path.to_str().ok_or("Frozen TEST original journal namespace")?));
  let inner=Box::new(Inner{pin:ManuallyDrop::new(pin),guard:ManuallyDrop::new(guard),main:ReadFile::empty(),journal:ReadFile::empty(),journal_path,scope,expected,main_digest:None,journal_digest:None,journal_native:None,primary:None,#[cfg(test)]modelled_previous_closure:modelled});
  #[cfg(not(test))] let _=modelled;
  ROOT.with(|q|*q.borrow_mut()=Some(inner));let mut owner=Self{owns:true,_same_thread:PhantomData};
  let observed=ROOT.with(|q|{let mut q=q.borrow_mut();let inner=q.as_mut().ok_or("Frozen TEST root absent")?;
   inner.main.open(path)?;private_leaf(inner.main.file.as_ref().ok_or("Frozen TEST root main absent")?,user)?;inner.pin.check_opened(inner.main.file.as_ref().unwrap())?;
   inner.journal.open(&inner.journal_path)?;private_leaf(inner.journal.file.as_ref().ok_or("Frozen TEST root journal absent")?,user)?;
   inner.journal_native=Some(inner.pin.check_sqlite_journal(inner.journal.file.as_ref().unwrap(),&inner.journal_path)?);inner.check()?;
   inner.main_digest=Some(inner.main.read_digest()?);inner.journal_digest=Some(inner.journal.read_digest()?);inner.check()
  });
  match observed{Ok(())=>Ok(owner),Err(primary)=>{ROOT.with(|q|{if let Some(inner)=q.borrow_mut().as_mut(){inner.primary=Some(primary.clone());}});let closed=owner.close_inner();Err(format!("Frozen TEST inspection refused: {primary}; owned read close={closed:?}"))}}
 }
 pub(crate) fn recheck(&self)->Result<()>{if !self.owns{return Err("Frozen TEST owner closed".into());}ROOT.with(|q|q.borrow().as_ref().ok_or("Frozen TEST root absent")?.check())}
 pub(crate) fn need(&self)->Result<RecoveryNeed>{
  self.recheck()?;ROOT.with(|q|{let q=q.borrow();let inner=q.as_ref().ok_or("Frozen TEST root absent")?;inner.expected.validate()?;
  if inner.scope==[0;64]||inner.main_digest.is_none()||inner.journal_digest.is_none(){return Err("Frozen TEST incomplete bound artifact observation".into());}
  Ok(RecoveryNeed::ExactAuthorizedTransitionUnavailable)})
 }
 pub(crate) fn close_checked(mut self)->Result<()>{self.close_inner()}
 fn close_inner(&mut self)->Result<()>{
  if !self.owns{return Ok(())}self.owns=false;
  // Revoke this token before cleanup. The root remains populated if either
  // explicit read-handle close fails or unwinds; Drop never repeats the attempt.
  ROOT.with(|q|{let mut q=q.borrow_mut();let inner=q.as_mut().ok_or("Frozen TEST root absent")?;inner.close()?;
  // No data transition occurred. A future signing open still sees the retained
  // journal and refuses; releasing this forensic reader does not unfreeze it.
  let pin_closed=inner.pin.close_checked();let guard_closed=inner.guard.close_checked();
  if pin_closed.is_err()||guard_closed.is_err(){return Err(format!("Frozen TEST original lease cleanup unknown: pin={pin_closed:?}, guard={guard_closed:?}"));}
  unsafe{ManuallyDrop::drop(&mut inner.pin);ManuallyDrop::drop(&mut inner.guard);}let _=q.take();Ok(())})
 }
 #[cfg(test)] pub(super) fn capture_with_modelled_closed_owner(path:&Path,guard:&Path,user:&[u8],binding:&Binding,expected:ExpectedSnapshot)->Result<Self>{Self::capture_closed(path,guard,user,binding,expected,true)}
 #[cfg(test)] pub(super) fn observed_modelled_closure(&self)->bool{self.owns&&ROOT.with(|q|q.borrow().as_ref().is_some_and(|i|i.modelled_previous_closure))}
}
impl Drop for FrozenInspection{fn drop(&mut self){let _=self.close_inner();}}
