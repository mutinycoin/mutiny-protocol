//! Exact owned native HANDLE release for private TEST database/guard leases.
//! No private key, SQL, recovery, raw-handle factory or production authority.
#![cfg(windows)] // Imported only by the existing NONSHIPPING image-pin module.
use std::{fs::File,mem::{ManuallyDrop,size_of},os::windows::io::FromRawHandle,path::Path,
 ptr,sync::atomic::{AtomicBool,AtomicPtr,Ordering}};
use windows_sys::Win32::{Foundation::{HANDLE,INVALID_HANDLE_VALUE,CloseHandle,GetLastError},
 Storage::FileSystem::{CreateFileW,OPEN_EXISTING,FILE_ID_INFO,FileIdInfo,GetFileInformationByHandleEx}};
type Result<T>=std::result::Result<T,String>;
struct Record{
 next:usize,file:Option<ManuallyDrop<File>>,raw:usize,path:std::path::PathBuf,
 identity:Option<(u64,[u8;16])>,attempted:bool,observed:Option<bool>,native_error:u32,
}
// Retained records are never dereferenced on another thread. This atomic root
// only preserves owned memory/HANDLE identity until actual process closure.
static RETAINED:AtomicPtr<Record>=AtomicPtr::new(ptr::null_mut());
static UNKNOWN:AtomicBool=AtomicBool::new(false);
pub(crate) fn require_known()->Result<()>{if UNKNOWN.load(Ordering::Acquire){Err("TEST native lease close UNKNOWN; no new provider access".into())}else{Ok(())}}
pub(crate) fn quarantine(){UNKNOWN.store(true,Ordering::Release);}
fn retain(record:Box<Record>){
 let raw=Box::into_raw(record);let mut head=RETAINED.load(Ordering::Acquire);
 loop{unsafe{(*raw).next=head as usize;}
  match RETAINED.compare_exchange_weak(head,raw,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>break,Err(now)=>head=now}
 }
}
#[derive(Clone,Copy,PartialEq,Eq)]enum State{Open,Known,Unknown}
// Read-only DatabasePin leases already move with the passive replay owner in
// Arc<Mutex<Reopen>>. Keep ordinary owned File automatic Send; no raw-pointer
// Send implementation or live signer/guard ownership transfer is introduced.
#[cfg(test)] #[derive(Clone)] pub(crate) struct CloseTrace(std::sync::Arc<std::sync::atomic::AtomicU64>);
#[cfg(test)] impl CloseTrace{
 fn new()->Self{Self(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)))}
 fn set(&self,value:(u32,Option<bool>,bool)){
  let actual=match value.1{None=>0,Some(false)=>1,Some(true)=>2};
  self.0.store(((value.0 as u64)<<3)|actual|if value.2{4}else{0},Ordering::Release);
 }
 pub(crate) fn get(&self)->(u32,Option<bool>,bool){
  let value=self.0.load(Ordering::Acquire);
  ((value>>3) as u32,match value&3{1=>Some(false),2=>Some(true),_=>None},value&4!=0)
 }
}
pub(crate) struct NativeFile{record:Option<Box<Record>>,state:State,error:u32,
 #[cfg(test)] trace:CloseTrace,#[cfg(test)] lost_ack:bool}
impl NativeFile{
 pub(crate) fn open(path:&Path,access:u32,sharing:u32,flags:u32)->Result<Self>{
  require_known()?;
  let text=path.to_str().ok_or("TEST original native lease ASCII path absent")?;
  if !path.is_absolute()||!text.is_ascii()||text.contains('\0'){return Err("TEST original native lease path invalid".into());}
  let wide:Vec<u16>=format!("\\\\?\\{}",text.replace('/',"\\")).encode_utf16().chain(Some(0)).collect();
  // Allocate custody BEFORE CreateFileW. No ordinary File destructor owns the
  // returned HANDLE at any fallible validation or unwinding boundary.
  let mut record=Box::new(Record{next:0,file:None,raw:0,path:path.to_path_buf(),identity:None,attempted:false,observed:None,native_error:0});
  #[cfg(test)] let trace=CloseTrace::new();
  let handle=unsafe{CreateFileW(wide.as_ptr(),access,sharing,ptr::null(),OPEN_EXISTING,flags,ptr::null_mut())};
  if handle.is_null()||handle==INVALID_HANDLE_VALUE{return Err(format!("TEST owned native open refused: {}",unsafe{GetLastError()}));}
  record.raw=handle as usize;record.file=Some(ManuallyDrop::new(unsafe{File::from_raw_handle(handle)}));
  let mut owner=Self{record:Some(record),state:State::Open,error:0,
   #[cfg(test)]trace,#[cfg(test)]lost_ack:false};
  let mut id:FILE_ID_INFO=unsafe{std::mem::zeroed()};
  if unsafe{GetFileInformationByHandleEx(handle,FileIdInfo,(&mut id as *mut FILE_ID_INFO).cast(),size_of::<FILE_ID_INFO>() as u32)}==0{
   let primary=unsafe{GetLastError()};let closed=owner.close_checked();return Err(format!("TEST native identity refused {primary}; once cleanup={closed:?}"));
  }
  owner.record.as_mut().unwrap().identity=Some((id.VolumeSerialNumber,id.FileId.Identifier));Ok(owner)
 }
 pub(crate) fn file(&self)->Result<&File>{
  require_known()?;
  if self.state!=State::Open{return Err("TEST native lease no longer readable".into());}
  self.record.as_ref().and_then(|r|r.file.as_ref()).map(|f|&**f).ok_or("TEST native lease custody absent".into())
 }
 pub(crate) fn raw(&self)->Result<HANDLE>{
  self.file()?;let record=self.record.as_ref().unwrap();let handle=record.raw as HANDLE;
  if native_id(handle)!=record.identity{return Err("TEST original native lease HANDLE identity differs before effect".into());}Ok(handle)
 }
 pub(crate) fn close_checked(&mut self)->Result<()>{
  self.close_using(CloseHandle)
 }
 #[cfg(test)] pub(crate) fn close_selected_callback(&mut self,callback:unsafe extern "system" fn(HANDLE)->i32)->Result<()>{self.close_using(callback)}
 #[cfg(test)] pub(crate) fn trace(&self)->CloseTrace{self.trace.clone()}
 #[cfg(test)] pub(crate) fn model_lost_ack(&mut self){self.lost_ack=true;}
 fn close_using(&mut self,call:unsafe extern "system" fn(HANDLE)->i32)->Result<()>{
  match self.state{State::Known=>return Ok(()),State::Unknown=>return Err(format!("TEST native close previously UNKNOWN {}; never retry",self.error)),State::Open=>{}}
  // Revoke use BEFORE effect. The already allocated record is retained on any
  // uncertain return; no Box/vector allocation occurs during quarantine.
  self.state=State::Unknown;
  let record=self.record.as_mut().ok_or("TEST native close record absent")?;
  if record.attempted{quarantine();return Err("TEST native close attempt already recorded; never retry".into());}
  if record.identity.is_some()&&native_id(record.raw as HANDLE)!=record.identity{
   self.error=5023;quarantine();let record=self.record.take().unwrap();retain(record);return Err("TEST original native close identity unavailable/different; zero native attempts, UNKNOWN retained".into());
  }
  record.attempted=true;let observed=unsafe{call(record.raw as HANDLE)}!=0;
  record.observed=Some(observed);record.native_error=if observed{0}else{unsafe{GetLastError()}};
  #[cfg(test)] self.trace.set((1,Some(observed),self.lost_ack&&observed));
  #[cfg(test)] if self.lost_ack&&observed{
   self.error=5023;quarantine();let record=self.record.take().unwrap();retain(record);return Err("MODELED lost native successful-close acknowledgment; original known observation retained, reported UNKNOWN".into());
  }
  self.error=record.native_error;
  if !observed{quarantine();let record=self.record.take().unwrap();retain(record);return Err(format!("TEST native CloseHandle UNKNOWN {}; retained original record",self.error));}
  let _=record.file.take();self.state=State::Known;let _=self.record.take();Ok(())
 }
}
fn native_id(handle:HANDLE)->Option<(u64,[u8;16])>{
 let mut id:FILE_ID_INFO=unsafe{std::mem::zeroed()};
 if unsafe{GetFileInformationByHandleEx(handle,FileIdInfo,(&mut id as *mut FILE_ID_INFO).cast(),size_of::<FILE_ID_INFO>() as u32)}==0{None}else{Some((id.VolumeSerialNumber,id.FileId.Identifier))}
}
impl Drop for NativeFile{fn drop(&mut self){
 if self.state==State::Open{let _=self.close_checked();}
 // A Rust unwind between attempt and observation must never implicitly drop
 // the File or lose the original record. It freezes all private TEST leases.
 if let Some(record)=self.record.take(){quarantine();retain(record);}
}}
