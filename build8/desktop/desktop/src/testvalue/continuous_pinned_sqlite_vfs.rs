//! Scoped Windows SQLite owner for the existing PUBLIC TEST providers only.
//! Main I/O uses the selected builtin win32 VFS, checked against its actual HANDLE.
//! Rollback journal I/O and deletion use one CREATE_NEW owned HANDLE throughout.
//! No normal eligibility, antirollback domain, physical durability or TPM claim.
#![cfg(all(windows,feature="testvalue-window"))]
use super::{DatabasePin,Result,err,private_leaf,bounded_sid};
use super::sqlite_close_boundary::{self,MainClose};
use rusqlite::{Connection,OpenFlags,ffi};
use std::{cell::{Cell,RefCell},ffi::{c_char,c_int,c_void,CStr,CString},fs::File,
 io::{Read,Write,Seek,SeekFrom},mem::{size_of,ManuallyDrop},ops::{Deref,DerefMut},
 os::windows::io::{AsRawHandle,FromRawHandle},path::{Path,PathBuf},ptr,
 rc::Rc,sync::atomic::{AtomicU64,Ordering}};
use windows_sys::Win32::{Foundation::{HANDLE,INVALID_HANDLE_VALUE,CloseHandle,LocalFree},
 Security::{IsValidSid,GetLengthSid,SECURITY_ATTRIBUTES,
 Authorization::{ConvertSidToStringSidW,ConvertStringSecurityDescriptorToSecurityDescriptorW,SDDL_REVISION_1}},
 Storage::FileSystem::{CreateFileW,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,
 FILE_SHARE_READ,FILE_SHARE_WRITE,SetFileInformationByHandle,FileDispositionInfo,FILE_DISPOSITION_INFO}};

pub(super) const MARKER:&str="MUTINY-W15-PINNED-SQLITE-JOURNAL-TEST-ONLY-V1";
const HANDLE_CONTROL:c_int=29; // Public SQLITE_FCNTL_WIN32_GET_HANDLE.
const MAIN:c_int=0;const JOURNAL:c_int=1;const WAL:c_int=2;const SHM:c_int=3;
const MAX_FILE:u64=256*1024*1024; // Existing ImagePin TEST-file cap, not protocol quota.
const MAX_VFS_OBJECT:usize=64*1024; // Bounded internal ABI allocation.
static NAMES:AtomicU64=AtomicU64::new(1);

// Records exist before their native operation. No ordinary File Drop owns an
// uncertain created journal; every native close result remains in its record.
struct Journal{file:Option<ManuallyDrop<File>>,handle:Option<HANDLE>,identity:Option<[u8;32]>,opened:bool,delete_marked:bool,close_attempted:bool,close_observed:Option<bool>}
struct ParentFile{real:*mut ffi::sqlite3_file,observed_handle:Option<HANDLE>,native_close:Option<Rc<MainClose>>,open_result:Option<c_int>,close_attempted:bool,close_result:Option<c_int>}
#[cfg(test)] #[derive(Default,Clone,Debug)] pub(super) struct CustodyObservation{pub parent_retained:bool,pub parent_native_handle_observed:bool,pub journal_retained:bool,pub journal_native_close_attempted:bool,pub journal_native_close_observed:Option<bool>,pub main_native_attempted:bool,pub main_native_outcome:Option<bool>,pub main_close_callbacks:u32}
struct Session{
 parent:*mut ffi::sqlite3_vfs,pin:DatabasePin,journal_path:PathBuf,
 db_name:Vec<u8>,journal_name:Vec<u8>,user:Vec<u8>,quarantine:Rc<Cell<bool>>,
 poison:Cell<bool>,reason:Cell<&'static str>,details:RefCell<Option<String>>,active:Cell<u32>,sector:Cell<c_int>,
 journal:RefCell<Option<Journal>>,parent_file:RefCell<Option<ParentFile>>,
 #[cfg(test)] fail_sync:Cell<bool>,#[cfg(test)] fail_delete:Cell<bool>,
 #[cfg(test)] fail_journal_validation:Cell<bool>,#[cfg(test)] fail_parent_close:Cell<bool>,#[cfg(test)] trace:Rc<RefCell<CustodyObservation>>,
}
impl Session{
 fn refuse(&self,reason:&'static str)->c_int{
  self.poison.set(true);self.reason.set(reason);self.quarantine.set(true);ffi::SQLITE_IOERR
 }
 fn ready(&self)->Result<()>{
  sqlite_close_boundary::require_installed()?;
  if self.poison.get()||self.quarantine.get(){return Err(format!("Pinned SQLite frozen: {}; details={:?}",self.reason.get(),self.details.borrow()));}
  self.pin.recheck()
 }
 fn identify(&self,name:*const c_char)->Result<c_int>{
  if name.is_null(){return Err("Pinned SQLite temporary/unnamed file refused".into());}
  let limit=self.journal_name.len().checked_add(8).ok_or("Pinned SQLite filename extent")?;
  let mut raw=Vec::new();
  for n in 0..=limit{let b=unsafe{*name.add(n)} as u8;if b==0{
   let text=std::str::from_utf8(&raw).map_err(err)?.replace('/',"\\");
   let text=text.strip_prefix("\\\\?\\").unwrap_or(&text);
   if text.as_bytes().eq_ignore_ascii_case(&self.db_name){return Ok(MAIN);}
   if text.as_bytes().eq_ignore_ascii_case(&self.journal_name){return Ok(JOURNAL);}
   for(suffix,kind)in [(b"-wal".as_slice(),WAL),(b"-shm".as_slice(),SHM)]{
    if text.len()==self.db_name.len()+suffix.len()&&text.as_bytes()[..self.db_name.len()].eq_ignore_ascii_case(&self.db_name)&&text.as_bytes()[self.db_name.len()..].eq_ignore_ascii_case(suffix){return Ok(kind);}
   }
   return Err("Pinned SQLite foreign namespace/file refused".into());
  }raw.push(b);}
  Err("Pinned SQLite filename over exact scope".into())
 }
 fn journal_check(&self,j:&Journal)->Result<()>{
  self.ready()?;let f=j.file.as_ref().ok_or("Pinned SQLite journal outcome unknown")?;
  if Some(self.pin.check_sqlite_journal(f,&self.journal_path)?)!=j.identity{return Err("Pinned SQLite journal native identity changed".into());}
  Ok(())
 }
 #[cfg(test)] fn record_custody(&self){
  let parent=self.parent_file.borrow();let journal=self.journal.borrow();
  let close=parent.as_ref().and_then(|p|p.native_close.as_ref()).map(|r|r.observation());
  // Once the proven successful parent allocation is freed, retain its actual
  // observation in the independent TEST recorder rather than losing credit.
  let prior=self.trace.borrow().clone();
  *self.trace.borrow_mut()=CustodyObservation{parent_retained:parent.as_ref().is_some_and(|p|!p.real.is_null()),parent_native_handle_observed:parent.as_ref().is_some_and(|p|p.observed_handle.is_some()),journal_retained:journal.is_some(),journal_native_close_attempted:journal.as_ref().is_some_and(|j|j.close_attempted),journal_native_close_observed:journal.as_ref().and_then(|j|j.close_observed),main_native_attempted:close.map_or(prior.main_native_attempted,|r|r.0),main_native_outcome:close.map_or(prior.main_native_outcome,|r|r.1),main_close_callbacks:close.map_or(prior.main_close_callbacks,|r|r.2)};
 }
}
#[repr(C)] struct Opened{base:ffi::sqlite3_file,real:*mut ffi::sqlite3_file,session:*mut Session,kind:c_int}
unsafe fn session(v:*mut ffi::sqlite3_vfs)->&'static Session{unsafe{&*((*v).pAppData.cast::<Session>())}}
unsafe fn opened(f:*mut ffi::sqlite3_file)->&'static mut Opened{unsafe{&mut *f.cast::<Opened>()}}
fn barrier(s:&Session,op:impl FnOnce()->c_int)->c_int{
 match std::panic::catch_unwind(std::panic::AssertUnwindSafe(op)){
  Ok(code)=>code,Err(_)=>s.refuse("SQLite native callback panic; owner quarantined"),
 }
}
fn actual_main(s:&Session,real:*mut ffi::sqlite3_file)->Result<()>{
 if real.is_null(){return Err("Pinned SQLite main file absent".into());}
 let methods=unsafe{(*real).pMethods};if methods.is_null(){return Err("Pinned SQLite main methods absent".into());}
 let control=unsafe{(*methods).xFileControl}.ok_or("Pinned SQLite native handle control absent")?;
 let mut handle:HANDLE=ptr::null_mut();
 if unsafe{control(real,HANDLE_CONTROL,(&mut handle as *mut HANDLE).cast())}!=ffi::SQLITE_OK||handle.is_null()||handle==INVALID_HANDLE_VALUE{return Err("Pinned SQLite actual win32 HANDLE unavailable".into());}
 {let mut record=s.parent_file.borrow_mut();let record=record.as_mut().ok_or("Pinned SQLite parent custody absent")?;
  if record.real!=real||record.close_attempted{return Err("Pinned SQLite parent custody pointer/close differs".into());}
  if record.observed_handle.is_some_and(|prior|prior!=handle){return Err("Pinned SQLite parent HANDLE replaced".into());}record.observed_handle=Some(handle);
  if let Some(close)=&record.native_close{if !close.matches(handle){return Err("Pinned SQLite close custody HANDLE differs".into());}}
  else{record.native_close=Some(MainClose::observe(handle)?);}}
 s.ready()?;
 // Borrow only: SQLite retains sole ownership and close responsibility.
 let file=ManuallyDrop::new(unsafe{File::from_raw_handle(handle)});
 s.pin.check_opened(&file)
}
fn close_journal_handle(s:&Session,j:&mut Journal)->Result<()>{
 if j.close_attempted{return Err("Pinned journal native close already attempted; no retry".into());}
 let handle=j.handle.ok_or("Pinned journal native close handle absent")?;
 j.close_attempted=true;let observed=unsafe{CloseHandle(handle)}!=0;j.close_observed=Some(observed);
 if !observed{s.refuse("Pinned journal actual CloseHandle outcome unknown; retained record");return Err("Pinned journal close unknown".into());}
 // The ordinary File destructor must never issue a second close. The native
 // CloseHandle above is the sole attempt, even after partial validation.
 j.handle=None;let _=j.file.take();Ok(())
}
fn close_parent(s:&Session,real:*mut ffi::sqlite3_file)->c_int{
 {let mut record=s.parent_file.borrow_mut();let Some(record)=record.as_mut()else{return s.refuse("Pinned SQLite parent close custody absent")};
  if record.real!=real||record.close_attempted{return s.refuse("Pinned SQLite parent method close already attempted or wrong pointer")};record.close_attempted=true;}
 let methods=unsafe{(*real).pMethods};
 #[cfg(test)] if s.fail_parent_close.replace(false){if let Some(record)=s.parent_file.borrow_mut().as_mut(){record.close_result=Some(ffi::SQLITE_IOERR);}return s.refuse("SIMULATED parent method close refusal; native HANDLE remains retained and unclosed");}
 let native=s.parent_file.borrow().as_ref().and_then(|r|r.native_close.clone());
 let Some(native)=native else{return s.refuse("Pinned SQLite main native-close identity unavailable; retained")};
 let invocation=match native.arm(){Ok(scope)=>scope,Err(error)=>{*s.details.borrow_mut()=Some(error);return s.refuse("Pinned SQLite exact native close scope unavailable; never fallback");}};
 let code=if methods.is_null(){ffi::SQLITE_IOERR}else{unsafe{(*methods).xClose}.map(|call|unsafe{call(real)}).unwrap_or(ffi::SQLITE_IOERR)};
 let scope_closed=invocation.finish_checked();
 if let Some(record)=s.parent_file.borrow_mut().as_mut(){record.close_result=Some(code);}
 if code!=ffi::SQLITE_OK||!native.known_success()||scope_closed.is_err(){return s.refuse("Pinned SQLite parent/native/scope close unknown; original record/allocation retained");}
 #[cfg(test)] s.record_custody();
 unsafe{ffi::sqlite3_free(real.cast());}*s.parent_file.borrow_mut()=None;
 #[cfg(test)] s.record_custody();
 ffi::SQLITE_OK
}
fn new_journal(s:&Session)->Result<()>{
 s.ready()?;bounded_sid(&s.user)?;
 if unsafe{IsValidSid(s.user.as_ptr().cast_mut().cast())}==0||unsafe{GetLengthSid(s.user.as_ptr().cast_mut().cast())} as usize!=s.user.len(){return Err("Pinned journal SID differs".into());}
 let mut native_sid=ptr::null_mut();
 if unsafe{ConvertSidToStringSidW(s.user.as_ptr().cast_mut().cast(),&mut native_sid)}==0{return Err("Pinned journal SID conversion refused".into());}
 struct Allocation(*mut c_void);impl Drop for Allocation{fn drop(&mut self){if !self.0.is_null(){unsafe{LocalFree(self.0);}}}}
 let _sid=Allocation(native_sid.cast());let mut count=0;
 while count<256&&unsafe{*native_sid.add(count)}!=0{count+=1;}
 if count==256{return Err("Pinned journal SID text extent".into());}
 let sid=String::from_utf16(unsafe{std::slice::from_raw_parts(native_sid,count)}).map_err(err)?;
 let security:Vec<u16>=format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)").encode_utf16().chain(Some(0)).collect();
 let mut descriptor=ptr::null_mut();
 if unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(security.as_ptr(),SDDL_REVISION_1,&mut descriptor,ptr::null_mut())}==0{return Err("Pinned journal descriptor refused".into());}
 let _descriptor=Allocation(descriptor);
 let attributes=SECURITY_ATTRIBUTES{nLength:size_of::<SECURITY_ATTRIBUTES>() as u32,lpSecurityDescriptor:descriptor,bInheritHandle:0};
 let name:Vec<u16>=format!("\\\\?\\{}",s.journal_path.to_str().ok_or("Pinned journal path")?.replace('/',"\\")).encode_utf16().chain(Some(0)).collect();
 // DELETE right allows later handle-based deletion. No DELETE sharing is granted.
 *s.journal.borrow_mut()=Some(Journal{file:None,handle:None,identity:None,opened:false,delete_marked:false,close_attempted:false,close_observed:None});
 let mut record=s.journal.borrow_mut();let j=record.as_mut().ok_or("Preallocated journal custody absent")?;
 let handle=unsafe{CreateFileW(name.as_ptr(),0xc0010000,FILE_SHARE_READ|FILE_SHARE_WRITE,&attributes,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,ptr::null_mut())};
 if handle.is_null()||handle==INVALID_HANDLE_VALUE{return Err("Pinned journal CREATE_NEW refused; existing sidecar preserved".into());}
 j.handle=Some(handle);j.file=Some(ManuallyDrop::new(unsafe{File::from_raw_handle(handle)}));
 let validated=(||{let file=j.file.as_ref().ok_or("Rooted journal file absent")?;private_leaf(file,&s.user)?;
  #[cfg(test)] if s.fail_journal_validation.replace(false){return Err("SIMULATED journal validation refusal after actual CREATE_NEW/private ACL check".into());}
  s.pin.check_sqlite_journal(file,&s.journal_path)})();
 match validated{Ok(identity)=>{j.identity=Some(identity);j.opened=true;Ok(())},Err(primary)=>{
  // The created name is preserved. Only this exact HANDLE is closed once;
  // cleanup refusal retains both primary and close outcomes in frozen custody.
  let cleanup=close_journal_handle(s,j);Err(format!("Pinned journal validation refused: {primary}; owned close={cleanup:?}"))
 }}
}
unsafe extern "C" fn open(v:*mut ffi::sqlite3_vfs,name:*const c_char,file:*mut ffi::sqlite3_file,flags:c_int,out:*mut c_int)->c_int{
 let s=unsafe{session(v)};barrier(s,||{
  if file.is_null(){return s.refuse("Pinned SQLite file allocation absent");}
  unsafe{(*file).pMethods=ptr::null();}
  if s.ready().is_err(){return s.refuse("Pinned SQLite owner unavailable before open");}
  let kind=match s.identify(name){Ok(kind)=>kind,Err(_)=>return s.refuse("Pinned SQLite open namespace refused")};
  if kind!=MAIN&&kind!=JOURNAL{return s.refuse("Pinned SQLite WAL/shared-memory opening refused");}
  let mut real:*mut ffi::sqlite3_file=ptr::null_mut();
  if kind==MAIN{
   if flags&ffi::SQLITE_OPEN_MAIN_DB==0||flags&(ffi::SQLITE_OPEN_CREATE|ffi::SQLITE_OPEN_DELETEONCLOSE)!=0||(flags&(ffi::SQLITE_OPEN_READONLY|ffi::SQLITE_OPEN_READWRITE)).count_ones()!=1{return s.refuse("Pinned SQLite main existing-only flags refused");}
   let size=unsafe{(*s.parent).szOsFile};
   if size<size_of::<ffi::sqlite3_file>() as c_int||size as usize>MAX_VFS_OBJECT{return s.refuse("Pinned SQLite parent ABI file extent refused");}
   real=unsafe{ffi::sqlite3_malloc64(size as u64).cast()};if real.is_null(){return ffi::SQLITE_NOMEM;}
   unsafe{ptr::write_bytes(real.cast::<u8>(),0,size as usize);}
   if s.parent_file.borrow().is_some(){unsafe{ffi::sqlite3_free(real.cast());}return s.refuse("Pinned SQLite duplicate main allocation refused");}
   *s.parent_file.borrow_mut()=Some(ParentFile{real,observed_handle:None,native_close:None,open_result:None,close_attempted:false,close_result:None});
   let Some(parent_open)= (unsafe{(*s.parent).xOpen}) else{return s.refuse("Pinned SQLite parent open absent; rooted allocation preserved");};
   let code=unsafe{parent_open(s.parent,name,real,flags,out)};
   if let Some(record)=s.parent_file.borrow_mut().as_mut(){record.open_result=Some(code);}
   if code!=ffi::SQLITE_OK{
    let methods=unsafe{(*real).pMethods};
    if !methods.is_null(){let _=actual_main(s,real);let _=close_parent(s,real);}
    return s.refuse("Pinned SQLite parent open failed; closure remains explicitly rooted/observed");
   }
   if actual_main(s,real).is_err(){
    let _=close_parent(s,real);
    return s.refuse("Pinned SQLite actual main HANDLE mismatch; no data I/O authorized");
   }
   let sector=unsafe{(*(*real).pMethods).xSectorSize}.map(|f|unsafe{f(real)}).unwrap_or(0);
   if sector<=0{
    let _=close_parent(s,real);
    return s.refuse("Pinned SQLite actual sector observation unavailable");
   }s.sector.set(sector);
  }else{
   if flags&ffi::SQLITE_OPEN_MAIN_JOURNAL==0||flags&ffi::SQLITE_OPEN_READWRITE==0||flags&ffi::SQLITE_OPEN_CREATE==0||flags&(ffi::SQLITE_OPEN_DELETEONCLOSE|ffi::SQLITE_OPEN_READONLY)!=0{return s.refuse("Pinned SQLite journal flags refused");}
   if s.journal.borrow().is_some(){return s.refuse("Pinned SQLite duplicate journal open refused");}
   if let Err(primary)=new_journal(s){*s.details.borrow_mut()=Some(primary);return s.refuse("Pinned SQLite journal creation/identity refused; rooted cleanup observations preserved");}if !out.is_null(){unsafe{*out=flags;}}
  }
  let count=match s.active.get().checked_add(1){Some(n)=>n,None=>return s.refuse("Pinned SQLite active-file overflow")};s.active.set(count);
  unsafe{ptr::write(file.cast::<Opened>(),Opened{base:ffi::sqlite3_file{pMethods:&METHODS},real,session:(s as *const Session).cast_mut(),kind});}
  ffi::SQLITE_OK
 })
}
unsafe extern "C" fn close(file:*mut ffi::sqlite3_file)->c_int{
 let f=unsafe{opened(file)};let s=unsafe{&*f.session};barrier(s,||{
  let code=if f.kind==MAIN{close_parent(s,f.real)}else{
   match s.journal.borrow_mut().as_mut(){Some(j)if j.opened=>{j.opened=false;ffi::SQLITE_OK},_=>ffi::SQLITE_IOERR}
  };
  if code!=ffi::SQLITE_OK{return s.refuse("Pinned SQLite method close outcome unknown; wrapper never retries");}
  if f.kind==MAIN{f.real=ptr::null_mut();}
  match s.active.get().checked_sub(1){Some(n)=>s.active.set(n),None=>return s.refuse("Pinned SQLite close accounting unknown")}
  f.base.pMethods=ptr::null();ffi::SQLITE_OK
 })
}
fn extent(amount:c_int,offset:i64)->Option<(usize,u64)>{
 let n=usize::try_from(amount).ok()?;let start=u64::try_from(offset).ok()?;
 if start.checked_add(n as u64)?>MAX_FILE{return None;}Some((n,start))
}
unsafe extern "C" fn read(file:*mut ffi::sqlite3_file,data:*mut c_void,amount:c_int,offset:i64)->c_int{
 let f=unsafe{opened(file)};let s=unsafe{&*f.session};barrier(s,||{
  let Some((n,start))=extent(amount,offset)else{return s.refuse("Pinned SQLite read extent refused")};
  if data.is_null(){return if n==0{ffi::SQLITE_OK}else{s.refuse("Pinned SQLite read buffer absent")};}
  if f.kind==MAIN{if actual_main(s,f.real).is_err(){return s.refuse("Pinned SQLite main identity before read")};let code=unsafe{(*(*f.real).pMethods).xRead}.map(|op|unsafe{op(f.real,data,amount,offset)}).unwrap_or(ffi::SQLITE_IOERR);if actual_main(s,f.real).is_err(){return s.refuse("Pinned SQLite main identity after read")};return if code==ffi::SQLITE_OK||code==ffi::SQLITE_IOERR_SHORT_READ{code}else{s.refuse("Pinned SQLite main read outcome unknown")};}
  let mut journal=s.journal.borrow_mut();let Some(j)=journal.as_mut()else{return s.refuse("Pinned SQLite owned journal absent")};
  if s.journal_check(j).is_err(){return s.refuse("Pinned SQLite journal identity before read");}
  let Some(file)=j.file.as_mut()else{return s.refuse("Pinned SQLite journal read outcome unknown")};
  let output=unsafe{std::slice::from_raw_parts_mut(data.cast::<u8>(),n)};output.fill(0);
  if file.seek(SeekFrom::Start(start)).is_err(){return s.refuse("Pinned SQLite journal seek failed");}
  let mut got=0;while got<n{match file.read(&mut output[got..]){Ok(0)=>return ffi::SQLITE_IOERR_SHORT_READ,Ok(k)=>got+=k,Err(e)if e.kind()==std::io::ErrorKind::Interrupted=>{},Err(_)=>return s.refuse("Pinned SQLite journal read failed")}}
  ffi::SQLITE_OK
 })
}
unsafe extern "C" fn write(file:*mut ffi::sqlite3_file,data:*const c_void,amount:c_int,offset:i64)->c_int{
 let f=unsafe{opened(file)};let s=unsafe{&*f.session};barrier(s,||{
  let Some((n,start))=extent(amount,offset)else{return s.refuse("Pinned SQLite write extent refused")};
  if data.is_null(){return if n==0{ffi::SQLITE_OK}else{s.refuse("Pinned SQLite write buffer absent")};}
  if f.kind==MAIN{if actual_main(s,f.real).is_err(){return s.refuse("Pinned SQLite main identity before write")};let code=unsafe{(*(*f.real).pMethods).xWrite}.map(|op|unsafe{op(f.real,data,amount,offset)}).unwrap_or(ffi::SQLITE_IOERR);if actual_main(s,f.real).is_err(){return s.refuse("Pinned SQLite main identity after write")};return if code==ffi::SQLITE_OK{code}else{s.refuse("Pinned SQLite main write outcome unknown")};}
  let mut journal=s.journal.borrow_mut();let Some(j)=journal.as_mut()else{return s.refuse("Pinned SQLite owned journal absent")};
  if s.journal_check(j).is_err(){return s.refuse("Pinned SQLite journal identity before write");}
  let Some(file)=j.file.as_mut()else{return s.refuse("Pinned SQLite journal write outcome unknown")};
  if file.seek(SeekFrom::Start(start)).is_err()||file.write_all(unsafe{std::slice::from_raw_parts(data.cast::<u8>(),n)}).is_err(){return s.refuse("Pinned SQLite journal write failed");}
  ffi::SQLITE_OK
 })
}
unsafe extern "C" fn truncate(file:*mut ffi::sqlite3_file,size:i64)->c_int{
 let f=unsafe{opened(file)};let s=unsafe{&*f.session};barrier(s,||{
  let Ok(size)=u64::try_from(size)else{return s.refuse("Pinned SQLite truncate extent")};if size>MAX_FILE{return s.refuse("Pinned SQLite truncate cap")};
  if f.kind==MAIN{if actual_main(s,f.real).is_err(){return s.refuse("Pinned SQLite main identity before truncate")};let code=unsafe{(*(*f.real).pMethods).xTruncate}.map(|op|unsafe{op(f.real,size as i64)}).unwrap_or(ffi::SQLITE_IOERR);return if code==ffi::SQLITE_OK{code}else{s.refuse("Pinned SQLite main truncate outcome unknown")};}
  let mut journal=s.journal.borrow_mut();let Some(j)=journal.as_mut()else{return s.refuse("Pinned SQLite owned journal absent")};
  if s.journal_check(j).is_err()||j.file.as_mut().is_none_or(|file|file.set_len(size).is_err()){return s.refuse("Pinned SQLite journal truncate failed");}ffi::SQLITE_OK
 })
}
unsafe extern "C" fn sync(file:*mut ffi::sqlite3_file,flags:c_int)->c_int{
 let f=unsafe{opened(file)};let s=unsafe{&*f.session};barrier(s,||{
  #[cfg(test)] if s.fail_sync.replace(false){return s.refuse("SIMULATED journal/main sync refusal; no power-loss claim");}
  if f.kind==MAIN{if actual_main(s,f.real).is_err(){return s.refuse("Pinned SQLite main identity before sync")};let code=unsafe{(*(*f.real).pMethods).xSync}.map(|op|unsafe{op(f.real,flags)}).unwrap_or(ffi::SQLITE_IOERR);return if code==ffi::SQLITE_OK{code}else{s.refuse("Pinned SQLite main FlushFileBuffers outcome unknown")};}
  let journal=s.journal.borrow();let Some(j)=journal.as_ref()else{return s.refuse("Pinned SQLite owned journal absent")};
  if s.journal_check(j).is_err()||j.file.as_ref().is_none_or(|file|file.sync_all().is_err()){return s.refuse("Pinned SQLite journal FlushFileBuffers failed");}ffi::SQLITE_OK
 })
}
unsafe extern "C" fn size(file:*mut ffi::sqlite3_file,out:*mut i64)->c_int{
 let f=unsafe{opened(file)};let s=unsafe{&*f.session};barrier(s,||{
  if out.is_null(){return s.refuse("Pinned SQLite size output absent")};
  if f.kind==MAIN{if actual_main(s,f.real).is_err(){return s.refuse("Pinned SQLite main identity before size")};let code=unsafe{(*(*f.real).pMethods).xFileSize}.map(|op|unsafe{op(f.real,out)}).unwrap_or(ffi::SQLITE_IOERR);if code!=ffi::SQLITE_OK||unsafe{*out}<0||unsafe{*out} as u64>MAX_FILE{return s.refuse("Pinned SQLite main native size unavailable/over cap")};return ffi::SQLITE_OK;}
  let journal=s.journal.borrow();let Some(j)=journal.as_ref()else{return s.refuse("Pinned SQLite owned journal absent")};
  if s.journal_check(j).is_err(){return s.refuse("Pinned SQLite journal identity before size")};
  match j.file.as_ref().and_then(|file|file.metadata().ok()){Some(m)if m.len()<=MAX_FILE=>{unsafe{*out=m.len() as i64};ffi::SQLITE_OK},_=>s.refuse("Pinned SQLite journal size failed")}
 })
}
macro_rules! main_lock {($name:ident,$field:ident)=>{unsafe extern "C" fn $name(file:*mut ffi::sqlite3_file,level:c_int)->c_int{
 let f=unsafe{opened(file)};let s=unsafe{&*f.session};barrier(s,||{if s.ready().is_err(){return s.refuse("Pinned SQLite owner unavailable before lock")};if f.kind==JOURNAL{return ffi::SQLITE_OK;}if actual_main(s,f.real).is_err(){return s.refuse("Pinned SQLite main identity before lock")};unsafe{(*(*f.real).pMethods).$field}.map(|op|unsafe{op(f.real,level)}).unwrap_or(ffi::SQLITE_IOERR)})
}}}
main_lock!(lock,xLock);main_lock!(unlock,xUnlock);
unsafe extern "C" fn reserved(file:*mut ffi::sqlite3_file,out:*mut c_int)->c_int{
 let f=unsafe{opened(file)};let s=unsafe{&*f.session};barrier(s,||{if out.is_null(){return s.refuse("Pinned SQLite lock output absent")};if f.kind==JOURNAL{unsafe{*out=0};return ffi::SQLITE_OK;}if actual_main(s,f.real).is_err(){return s.refuse("Pinned SQLite main identity before reserved-lock")};unsafe{(*(*f.real).pMethods).xCheckReservedLock}.map(|op|unsafe{op(f.real,out)}).unwrap_or(ffi::SQLITE_IOERR)})
}
unsafe extern "C" fn control(file:*mut ffi::sqlite3_file,op:c_int,arg:*mut c_void)->c_int{
 let f=unsafe{opened(file)};let s=unsafe{&*f.session};barrier(s,||{
  if s.ready().is_err(){return s.refuse("Pinned SQLite owner unavailable before control")};
  if f.kind==MAIN{
   if actual_main(s,f.real).is_err(){return s.refuse("Pinned SQLite main identity before control")};
   // Never delegate handle replacement, mmap, WAL, atomic-batch, arbitrary PRAGMA,
   // or alternate-file controls. Unknown controls retain standard NOTFOUND behavior.
   match op{
    14=>{
     // SQLite asks a VFS before evaluating each PRAGMA. These private owners
     // cannot switch away from DELETE/FULL or enable mmap/WAL by SQL.
     if arg.is_null(){return s.refuse("Pinned SQLite PRAGMA arguments absent");}
     let args=arg.cast::<*const c_char>();let name=unsafe{*args.add(1)};let value=unsafe{*args.add(2)};
     if name.is_null(){return s.refuse("Pinned SQLite PRAGMA name absent");}
     let name=unsafe{CStr::from_ptr(name)}.to_bytes();
     if !value.is_null(){let value=unsafe{CStr::from_ptr(value)}.to_bytes();
      let permitted=if name.eq_ignore_ascii_case(b"journal_mode"){value.eq_ignore_ascii_case(b"delete")}
       else if name.eq_ignore_ascii_case(b"synchronous"){value.eq_ignore_ascii_case(b"full")||value==b"2"}
       else if name.eq_ignore_ascii_case(b"mmap_size"){value==b"0"}
       else{true};
      if !permitted{return s.refuse("Pinned SQLite durability/mmap PRAGMA change refused");}
     }return ffi::SQLITE_NOTFOUND;
    },
    HANDLE_CONTROL|1=>{if arg.is_null(){return s.refuse("Pinned SQLite native control output absent")};},
    5=>{if arg.is_null(){return s.refuse("Pinned SQLite size hint absent")};let hint=unsafe{*arg.cast::<i64>()};if hint<0||hint as u64>MAX_FILE{return s.refuse("Pinned SQLite size hint over TEST storage extent")};},
    20=>{if arg.is_null(){return s.refuse("Pinned SQLite moved output absent")};unsafe{*arg.cast::<c_int>()=0};return ffi::SQLITE_OK;},
    _=>return ffi::SQLITE_NOTFOUND,
   }
   let code=unsafe{(*(*f.real).pMethods).xFileControl}.map(|call|unsafe{call(f.real,op,arg)}).unwrap_or(ffi::SQLITE_NOTFOUND);
   if code!=ffi::SQLITE_OK&&code!=ffi::SQLITE_NOTFOUND{return s.refuse("Pinned SQLite native control outcome unknown")};
   if actual_main(s,f.real).is_err(){return s.refuse("Pinned SQLite native control changed binding")};return code;
  }
  if op!=HANDLE_CONTROL{return ffi::SQLITE_NOTFOUND;}
  if arg.is_null(){return s.refuse("Pinned SQLite journal handle output absent")};
  let j=s.journal.borrow();let Some(j)=j.as_ref()else{return s.refuse("Pinned SQLite owned journal absent")};
  if s.journal_check(j).is_err(){return s.refuse("Pinned SQLite journal handle identity")};
  let Some(file)=j.file.as_ref()else{return s.refuse("Pinned SQLite journal handle unknown")};unsafe{*arg.cast::<HANDLE>()=file.as_raw_handle()};ffi::SQLITE_OK
 })
}
unsafe extern "C" fn sector(file:*mut ffi::sqlite3_file)->c_int{let f=unsafe{opened(file)};unsafe{(*f.session).sector.get()}}
unsafe extern "C" fn characteristics(_: *mut ffi::sqlite3_file)->c_int{0}
static METHODS:ffi::sqlite3_io_methods=ffi::sqlite3_io_methods{iVersion:1,xClose:Some(close),xRead:Some(read),xWrite:Some(write),xTruncate:Some(truncate),xSync:Some(sync),xFileSize:Some(size),xLock:Some(lock),xUnlock:Some(unlock),xCheckReservedLock:Some(reserved),xFileControl:Some(control),xSectorSize:Some(sector),xDeviceCharacteristics:Some(characteristics),xShmMap:None,xShmLock:None,xShmBarrier:None,xShmUnmap:None,xFetch:None,xUnfetch:None};

unsafe extern "C" fn access(v:*mut ffi::sqlite3_vfs,name:*const c_char,flags:c_int,out:*mut c_int)->c_int{
 let s=unsafe{session(v)};barrier(s,||{if out.is_null(){return s.refuse("Pinned SQLite access output absent")};if s.ready().is_err(){return s.refuse("Pinned SQLite owner unavailable before access")};match s.identify(name){Ok(MAIN)=>unsafe{(*s.parent).xAccess}.map(|op|unsafe{op(s.parent,name,flags,out)}).unwrap_or(ffi::SQLITE_IOERR),Ok(JOURNAL)=>{let j=s.journal.borrow();if let Some(j)=j.as_ref(){if s.journal_check(j).is_err(){return s.refuse("Pinned SQLite journal access identity")};unsafe{*out=1};return ffi::SQLITE_OK;}match std::fs::symlink_metadata(&s.journal_path){Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{unsafe{*out=0};ffi::SQLITE_OK},_=>s.refuse("Pinned SQLite preexisting/untracked journal; exact reconstruction required")}},Ok(kind)if kind==WAL||kind==SHM=>{
  // DELETE-mode SQLite probes a WAL on ordinary existing-database reads.
  // Report only observed absence; an existing sidecar is never opened/deleted.
  let suffix=if kind==WAL{"-wal"}else{"-shm"};let path=PathBuf::from(format!("{}{suffix}",String::from_utf8_lossy(&s.db_name)));
  match std::fs::symlink_metadata(path){Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{unsafe{*out=0};ffi::SQLITE_OK},_=>s.refuse("Pinned SQLite existing/unknown WAL or shared-memory sidecar refused")}
 },_=>s.refuse("Pinned SQLite access namespace refused")}})
}
unsafe extern "C" fn delete(v:*mut ffi::sqlite3_vfs,name:*const c_char,_sync_dir:c_int)->c_int{
 let s=unsafe{session(v)};barrier(s,||{
  if s.identify(name)!=Ok(JOURNAL)||s.ready().is_err(){return s.refuse("Pinned SQLite deletion namespace/owner refused")};
  #[cfg(test)] if s.fail_delete.replace(false){return s.refuse("SIMULATED handle-deletion refusal; no power-loss claim");}
  let mut journal=s.journal.borrow_mut();let Some(j)=journal.as_mut()else{return s.refuse("Pinned SQLite unowned journal deletion refused")};
  if j.opened||j.delete_marked||s.journal_check(j).is_err(){return s.refuse("Pinned SQLite journal deletion state/identity refused")};
  let info=FILE_DISPOSITION_INFO{DeleteFile:true};let file=j.file.as_ref().unwrap();
  if unsafe{SetFileInformationByHandle(file.as_raw_handle(),FileDispositionInfo,(&info as *const FILE_DISPOSITION_INFO).cast(),size_of::<FILE_DISPOSITION_INFO>() as u32)}==0{return s.refuse("Pinned SQLite actual journal handle deletion refused")};
  j.delete_marked=true;if close_journal_handle(s,j).is_err(){return s.refuse("Pinned SQLite journal close unknown; rooted observation retained")};
  match std::fs::symlink_metadata(&s.journal_path){Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{*journal=None;ffi::SQLITE_OK},_=>s.refuse("Pinned SQLite journal namespace after deletion unknown")}
 })
}
unsafe extern "C" fn full_path(v:*mut ffi::sqlite3_vfs,name:*const c_char,n:c_int,out:*mut c_char)->c_int{
 let s=unsafe{session(v)};barrier(s,||{if s.identify(name)!=Ok(MAIN)||s.ready().is_err(){return s.refuse("Pinned SQLite full-path scope refused")};let code=unsafe{(*s.parent).xFullPathname}.map(|op|unsafe{op(s.parent,name,n,out)}).unwrap_or(ffi::SQLITE_IOERR);if code==ffi::SQLITE_OK{code}else{s.refuse("Pinned SQLite parent full-path outcome unknown")}})
}
unsafe extern "C" fn dl_open(_: *mut ffi::sqlite3_vfs,_:*const c_char)->*mut c_void{ptr::null_mut()}
unsafe extern "C" fn dl_error(_: *mut ffi::sqlite3_vfs,n:c_int,out:*mut c_char){if n<=0||out.is_null(){return;}let message=b"Scoped protected SQLite forbids extensions";let size=(n as usize-1).min(message.len());unsafe{ptr::copy_nonoverlapping(message.as_ptr().cast(),out,size);*out.add(size)=0;}}
unsafe extern "C" fn randomness(v:*mut ffi::sqlite3_vfs,n:c_int,out:*mut c_char)->c_int{let s=unsafe{session(v)};unsafe{(*s.parent).xRandomness}.map(|op|unsafe{op(s.parent,n,out)}).unwrap_or(0)}
unsafe extern "C" fn sleep(v:*mut ffi::sqlite3_vfs,n:c_int)->c_int{let s=unsafe{session(v)};unsafe{(*s.parent).xSleep}.map(|op|unsafe{op(s.parent,n)}).unwrap_or(0)}
unsafe extern "C" fn current_time(v:*mut ffi::sqlite3_vfs,out:*mut f64)->c_int{let s=unsafe{session(v)};unsafe{(*s.parent).xCurrentTime}.map(|op|unsafe{op(s.parent,out)}).unwrap_or(ffi::SQLITE_IOERR)}
unsafe extern "C" fn last_error(v:*mut ffi::sqlite3_vfs,n:c_int,out:*mut c_char)->c_int{let s=unsafe{session(v)};unsafe{(*s.parent).xGetLastError}.map(|op|unsafe{op(s.parent,n,out)}).unwrap_or(ffi::SQLITE_IOERR)}

pub(super) struct PinnedConnection{db:Option<Connection>,vfs:Option<Box<ffi::sqlite3_vfs>>,session:Option<Box<Session>>,name:Option<CString>}
impl PinnedConnection{
 pub(super) fn open(path:&Path,user:&[u8],readonly:bool,quarantine:Rc<Cell<bool>>)->Result<Self>{
  sqlite_close_boundary::require_installed()?;
  if quarantine.get(){return Err("Pinned SQLite owner already quarantined".into());}
  let pin=DatabasePin::open(path,user)?;let text=path.to_str().ok_or("Pinned SQLite original path")?.replace('/',"\\");
  let journal_path=PathBuf::from(format!("{text}-journal"));
  for sidecar in [&journal_path,&PathBuf::from(format!("{text}-wal")),&PathBuf::from(format!("{text}-shm"))]{
   if !matches!(std::fs::symlink_metadata(sidecar),Err(e)if e.kind()==std::io::ErrorKind::NotFound){quarantine.set(true);std::mem::forget(pin);return Err("Pinned SQLite preexisting/unknown sidecar preserved; owner frozen until exact reconstruction".into());}
  }
  let parent=unsafe{ffi::sqlite3_vfs_find(c"win32".as_ptr())};
  if parent.is_null()||unsafe{(*parent).iVersion}<1||unsafe{(*parent).iVersion}>3||unsafe{CStr::from_ptr((*parent).zName)}!=c"win32"{return Err("Pinned SQLite exact builtin win32 VFS unavailable".into());}
  let number=NAMES.fetch_update(Ordering::SeqCst,Ordering::SeqCst,|n|n.checked_add(1)).map_err(|_|"Pinned SQLite internal VFS namespace exhausted")?;
  let name=CString::new(format!("mutiny-w15-held-sqlite-{number}")).map_err(err)?;
  let mut session=Box::new(Session{parent,pin,journal_path:journal_path.clone(),db_name:text.into_bytes(),journal_name:journal_path.to_str().ok_or("Pinned journal path")?.as_bytes().to_vec(),user:user.into(),quarantine,poison:Cell::new(false),reason:Cell::new("not poisoned"),details:RefCell::new(None),active:Cell::new(0),sector:Cell::new(0),journal:RefCell::new(None),parent_file:RefCell::new(None),#[cfg(test)]fail_sync:Cell::new(false),#[cfg(test)]fail_delete:Cell::new(false),#[cfg(test)]fail_journal_validation:Cell::new(false),#[cfg(test)]fail_parent_close:Cell::new(false),#[cfg(test)]trace:Rc::new(RefCell::new(CustodyObservation::default()))});
  let mut vfs=Box::new(unsafe{ptr::read(parent)});vfs.iVersion=1;vfs.szOsFile=size_of::<Opened>() as c_int;vfs.pNext=ptr::null_mut();vfs.zName=name.as_ptr();vfs.pAppData=(&mut *session as *mut Session).cast();
  vfs.xOpen=Some(open);vfs.xDelete=Some(delete);vfs.xAccess=Some(access);vfs.xFullPathname=Some(full_path);vfs.xDlOpen=Some(dl_open);vfs.xDlError=Some(dl_error);vfs.xDlSym=None;vfs.xDlClose=None;vfs.xRandomness=Some(randomness);vfs.xSleep=Some(sleep);vfs.xCurrentTime=Some(current_time);vfs.xGetLastError=Some(last_error);
  vfs.xCurrentTimeInt64=None;vfs.xSetSystemCall=None;vfs.xGetSystemCall=None;vfs.xNextSystemCall=None;
  if unsafe{ffi::sqlite3_vfs_register(&mut *vfs,0)}!=ffi::SQLITE_OK{return Err("Pinned SQLite scoped VFS registration refused".into());}
  let mut owner=Self{db:None,vfs:Some(vfs),session:Some(session),name:Some(name)};
  let flags=OpenFlags::SQLITE_OPEN_NO_MUTEX|if readonly{OpenFlags::SQLITE_OPEN_READ_ONLY}else{OpenFlags::SQLITE_OPEN_READ_WRITE};
  match Connection::open_with_flags_and_vfs(path,flags,owner.name.as_ref().ok_or("Pinned VFS name absent")?.to_str().map_err(err)?){Ok(db)=>owner.db=Some(db),Err(error)=>return Err(format!("Pinned SQLite actual open refused: {error}"))}
  owner.status()?;Ok(owner)
 }
 pub(super) fn status(&self)->Result<()>{
  let s=self.session.as_ref().ok_or("Pinned SQLite session absent")?;s.ready()?;
  let db=self.db.as_ref().ok_or("Pinned SQLite actual connection absent")?;let vfs=self.vfs.as_ref().ok_or("Pinned SQLite exact registration absent")?;
  let mut actual: *mut ffi::sqlite3_vfs=ptr::null_mut();let expected=(&**vfs as *const ffi::sqlite3_vfs).cast_mut();
  if s.active.get()==0||s.parent_file.borrow().is_none()||unsafe{ffi::sqlite3_vfs_find(self.name.as_ref().ok_or("Pinned SQLite name absent")?.as_ptr())}!=expected||unsafe{ffi::sqlite3_file_control(db.handle(),c"main".as_ptr(),27,(&mut actual as *mut *mut ffi::sqlite3_vfs).cast())}!=ffi::SQLITE_OK||actual!=expected{
   s.refuse("Pinned SQLite actual engine/registered VFS selection differs");return Err("Pinned SQLite actual VFS selection refused".into());
  }Ok(())
 }
 pub(super) fn close_checked(mut self)->Result<()>{self.close_inner()}
 fn quarantine(&mut self){
  #[cfg(test)] if let Some(s)=self.session.as_ref(){s.record_custody();}
  if let Some(s)=self.session.as_ref(){s.quarantine.set(true);s.poison.set(true);}
  if let Some(v)=self.vfs.take(){std::mem::forget(v);}if let Some(s)=self.session.take(){std::mem::forget(s);}
  if let Some(n)=self.name.take(){std::mem::forget(n);}
 }
 fn close_inner(&mut self)->Result<()>{
  if let Some(db)=self.db.take(){if let Err((db,error))=db.close(){std::mem::forget(db);self.quarantine();return Err(format!("Pinned SQLite close unknown; no retry: {error}"));}}
  if let Some(s)=self.session.as_ref(){if s.poison.get()||s.quarantine.get()||s.active.get()!=0||s.journal.borrow().is_some()||s.parent_file.borrow().is_some(){let reason=s.reason.get();self.quarantine();return Err(format!("Pinned SQLite owner quarantined at close: {reason}"));}}
  if let Some(v)=self.vfs.as_mut(){if unsafe{ffi::sqlite3_vfs_unregister(&mut **v)}!=ffi::SQLITE_OK{self.quarantine();return Err("Pinned SQLite unregister unknown; retained registry pointers".into());}}
  if let Some(s)=self.session.as_mut(){if let Err(error)=s.pin.close_checked(){self.quarantine();return Err(format!("Pinned SQLite original ancestor cleanup UNKNOWN: {error}"));}}
  self.vfs.take();self.session.take();self.name.take();Ok(())
 }
 #[cfg(test)] pub(super) fn inject_sync_refusal(&self){self.session.as_ref().unwrap().fail_sync.set(true);}
 #[cfg(test)] pub(super) fn inject_delete_refusal(&self){self.session.as_ref().unwrap().fail_delete.set(true);}
 #[cfg(test)] pub(super) fn inject_journal_validation_refusal(&self){self.session.as_ref().unwrap().fail_journal_validation.set(true);}
 #[cfg(test)] pub(super) fn inject_parent_close_refusal(&self){self.session.as_ref().unwrap().fail_parent_close.set(true);}
 #[cfg(test)] pub(super) fn inject_lost_native_main_close_success(&self)->Result<()>{
  let session=self.session.as_ref().ok_or("TEST actual session absent")?;
  let parent=session.parent_file.borrow();
  parent.as_ref().and_then(|p|p.native_close.as_ref()).ok_or("TEST actual native main close record absent")?.model_lost_native_success();Ok(())
 }
 #[cfg(test)] pub(super) fn custody_trace(&self)->Rc<RefCell<CustodyObservation>>{self.session.as_ref().unwrap().trace.clone()}
 #[cfg(test)] pub(super) fn native_binding(&self,journal:bool)->Result<[u8;32]>{
  self.status()?;let s=self.session.as_ref().ok_or("TEST scoped owner absent")?;
  if journal{let j=s.journal.borrow();let j=j.as_ref().ok_or("TEST engine journal absent")?;s.journal_check(j)?;
   let mut engine: *mut ffi::sqlite3_file=ptr::null_mut();let db=self.db.as_ref().ok_or("TEST actual connection absent")?;
   if unsafe{ffi::sqlite3_file_control(db.handle(),c"main".as_ptr(),28,(&mut engine as *mut *mut ffi::sqlite3_file).cast())}!=ffi::SQLITE_OK||engine.is_null()||unsafe{(*engine).pMethods}.is_null(){return Err("TEST actual engine journal pointer absent".into());}
   let mut handle:HANDLE=ptr::null_mut();let call=unsafe{(*(*engine).pMethods).xFileControl}.ok_or("TEST actual journal control absent")?;
   if unsafe{call(engine,HANDLE_CONTROL,(&mut handle as *mut HANDLE).cast())}!=ffi::SQLITE_OK||j.file.as_ref().is_none_or(|f|f.as_raw_handle()!=handle){return Err("TEST engine journal HANDLE differs from owned journal".into());}
   j.identity.ok_or_else(||"TEST journal identity unvalidated".into())}else{
   let mut handle:HANDLE=ptr::null_mut();let db=self.db.as_ref().ok_or("TEST actual connection absent")?;
   if unsafe{ffi::sqlite3_file_control(db.handle(),c"main".as_ptr(),HANDLE_CONTROL,(&mut handle as *mut HANDLE).cast())}!=ffi::SQLITE_OK||handle.is_null()||handle==INVALID_HANDLE_VALUE{return Err("TEST actual main HANDLE absent".into());}
   let borrowed=ManuallyDrop::new(unsafe{File::from_raw_handle(handle)});s.pin.check_opened(&borrowed)?;Ok(s.pin.native_id_hash())
  }
 }
 #[cfg(test)] pub(super) fn namespace_refuses(&self,path:&Path)->bool{
  let Some(s)=self.session.as_ref()else{return false;};let Some(text)=path.to_str()else{return false;};let Ok(name)=CString::new(text)else{return false;};!matches!(s.identify(name.as_ptr()),Ok(MAIN)|Ok(JOURNAL))
 }
}
impl Deref for PinnedConnection{type Target=Connection;fn deref(&self)->&Connection{self.db.as_ref().expect("live private pinned connection")}}
impl DerefMut for PinnedConnection{fn deref_mut(&mut self)->&mut Connection{self.db.as_mut().expect("live private pinned connection")}}
impl Drop for PinnedConnection{fn drop(&mut self){let _=self.close_inner();}}
