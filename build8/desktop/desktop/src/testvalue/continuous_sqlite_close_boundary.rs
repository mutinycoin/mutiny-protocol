//! Private TEST process-only native-close boundary for the pinned win32 VFS.
//! Install at the first application main statement, before SQLite workers.
//! The process-wide function is immutable thereafter. Only a same-thread
//! exact parent xClose invocation is intercepted; every other call passes on.
#![cfg(all(windows,feature="testvalue-window"))]
use super::{Result,err};
use rusqlite::ffi;
use std::{cell::{Cell,RefCell},mem::{size_of,transmute},rc::Rc,sync::OnceLock};
use windows_sys::Win32::{Foundation::{HANDLE,CloseHandle,GetLastError,SetLastError},
 Storage::FileSystem::{FILE_ID_INFO,FileIdInfo,GetFileInformationByHandleEx}};

// Public refusal diagnostics only. These APIs observe already-loaded modules;
// they do not load code, accept a target, install a hook or attempt any close.
// Explicit signatures preserve the current Cargo feature/dependency graph.
#[link(name="kernel32")]
unsafe extern "system" {
 #[link_name="GetModuleHandleExW"]
 fn diagnostic_module(flags:u32,address:*const u16,module:*mut HANDLE)->i32;
 #[link_name="GetModuleFileNameW"]
 fn diagnostic_module_name(module:HANDLE,buffer:*mut u16,capacity:u32)->u32;
 #[link_name="GetProcAddress"]
 fn diagnostic_export(module:HANDLE,name:*const u8)->Option<unsafe extern "system" fn()->isize>;
}
fn target_diagnostic(address:usize)->String {
 let mut module:HANDLE=std::ptr::null_mut();
 // FROM_ADDRESS | UNCHANGED_REFCOUNT: the numeric input is not a string.
 if unsafe{diagnostic_module(6,address as *const u16,&mut module)}==0||module.is_null(){
  return format!("address=0x{address:x};module=UNKNOWN;error={}",unsafe{GetLastError()});
 }
 let mut name=[0u16;512];
 let n=unsafe{diagnostic_module_name(module,name.as_mut_ptr(),name.len() as u32)} as usize;
 let path=if n==0||n>=name.len(){"UNKNOWN_OR_TRUNCATED".to_owned()}else{String::from_utf16_lossy(&name[..n])};
 let export=unsafe{diagnostic_export(module,c"CloseHandle".as_ptr().cast())}.map(|f|f as usize);
 format!("address=0x{address:x};module_base=0x{:x};rva={:?};module={path};CloseHandle_export={export:?}",module as usize,address.checked_sub(module as usize))
}

// Import-thunk identity. A C object that takes the address of an imported function
// can hold the linker's `jmp qword ptr [rip+disp32]` stub inside this image instead
// of the export address. Such a stub is the same API only if its jump slot is an
// aligned entry of THIS image's import address table and that entry currently holds
// the exact linked address. Nothing else is accepted, and no address is followed twice.
fn thunk_slot(code:[u8;6],thunk:usize,image:usize,size:usize,iat:(usize,usize))->std::result::Result<usize,String>{
 if code[0]!=0xFF||code[1]!=0x25{return Err("selected address is not an indirect import jump".into());}
 let end=image.checked_add(size).ok_or("image extent overflow")?;
 let next=thunk.checked_add(6).ok_or("thunk extent overflow")?;
 if thunk<image||next>end{return Err("thunk is outside the image".into());}
 let displacement=i32::from_le_bytes([code[2],code[3],code[4],code[5]]) as isize;
 let slot=next.checked_add_signed(displacement).ok_or("import slot address overflow")?;
 let table=image.checked_add(iat.0).ok_or("import table overflow")?;
 let table_end=table.checked_add(iat.1).ok_or("import table overflow")?;
 let word=size_of::<usize>();
 if table_end>end||slot<table||slot.checked_add(word).is_none_or(|slot_end|slot_end>table_end)||(slot-table)%word!=0{
  return Err("jump slot is outside this image's import address table".into());
 }
 Ok(slot)
}
fn select_original(table:usize,linked:usize,resolve:impl FnOnce(usize)->std::result::Result<usize,String>)->std::result::Result<usize,String>{
 if table==linked{return Ok(linked);}
 match resolve(table){
  Ok(target) if target==linked=>Ok(linked),
  Ok(target)=>Err(format!("import slot holds 0x{target:x}, not the linked address")),
  Err(refusal)=>Err(refusal),
 }
}
fn own_import_thunk_target(thunk:usize)->std::result::Result<usize,String>{
 let module_of=|address:usize|{let mut module:HANDLE=std::ptr::null_mut();
  if unsafe{diagnostic_module(6,address as *const u16,&mut module)}==0||module.is_null(){None}else{Some(module as usize)}};
 let image=module_of(thunk).ok_or("selected address is in no loaded module")?;
 if Some(image)!=module_of(callback as *const () as usize){return Err("selected address is outside this executable image".into());}
 // This image's own mapped PE32+ headers: extent and import address table directory.
 let read16=|at:usize|unsafe{std::ptr::read_unaligned(at as *const u16)};
 let read32=|at:usize|unsafe{std::ptr::read_unaligned(at as *const u32)} as usize;
 if read16(image)!=0x5A4D{return Err("image DOS header".into());}
 let pe=read32(image+0x3C);
 if pe==0||pe>0x1000||read32(image+pe)!=0x0000_4550{return Err("image PE header".into());}
 let optional=image+pe+24;
 if read16(optional)!=0x20B||read32(optional+108)<=12{return Err("image PE32+ optional header".into());}
 let size=read32(optional+56);
 let iat=(read32(optional+112+12*8),read32(optional+112+12*8+4));
 if thunk<image||thunk.checked_add(6).is_none_or(|next|image.checked_add(size).is_none_or(|end|next>end)){return Err("thunk is outside the image".into());}
 let mut code=[0u8;6];unsafe{std::ptr::copy_nonoverlapping(thunk as *const u8,code.as_mut_ptr(),6)};
 let slot=thunk_slot(code,thunk,image,size,iat)?;
 Ok(unsafe{std::ptr::read_unaligned(slot as *const usize)})
}

type NativeClose=unsafe extern "system" fn(HANDLE)->i32;
const UNKNOWN:u32=5023; // ERROR_INVALID_STATE, implementation diagnostic only.
const MARKER:&str="MUTINY-W15-EXACT-TLS-NATIVE-CLOSE-TEST-V1";
struct Installed{parent:usize,original:usize}
static INSTALL:OnceLock<std::result::Result<Installed,String>>=OnceLock::new();
thread_local!{
 static ACTIVE:RefCell<Option<Rc<MainClose>>>=const{RefCell::new(None)};
 static INTERCEPTING:Cell<bool>=const{Cell::new(false)};
}

fn same_table(installed:&Installed)->Result<()>{
 let parent=installed.parent as *mut ffi::sqlite3_vfs;
 if parent.is_null()||unsafe{(*parent).iVersion}!=3{return Err("TEST exact win32 close table unavailable".into());}
 let get=unsafe{(*parent).xGetSystemCall}.ok_or("TEST win32 syscall getter absent")?;
 let current=unsafe{get(parent,c"CloseHandle".as_ptr())}.map(|f|f as usize);
 if current!=Some(callback as *const () as usize){return Err("TEST close table replaced; no close authority".into());}
 Ok(())
}

#[cfg(test)] pub(super) fn exercise_unrelated_close_after_scope(path:&std::path::Path,user:&[u8])->Result<()>{
 require_installed()?;
 if ACTIVE.with(|slot|slot.borrow().is_some()){return Err("TEST prior close scope was not released".into());}
 super::create_new_private_leaf(path,user)?;
 let installed=INSTALL.get().unwrap().as_ref().map_err(Clone::clone)?;
 let parent=installed.parent as *mut ffi::sqlite3_vfs;
 let current=unsafe{(*parent).xGetSystemCall}.ok_or("TEST current syscall getter absent")?;
 let current=unsafe{current(parent,c"CloseHandle".as_ptr())}.ok_or("TEST current callback absent")?;
 let call:NativeClose=unsafe{transmute(current)};
 // Preallocated owned record roots this unrelated public handle. No raw
 // handle ownership is transferred to the previously frozen main record.
 let mut unrelated=super::native_handle_owner::NativeFile::open(path,0x00020081,3,0x00200000)?;
 unrelated.close_selected_callback(call)
}
/// Only actual first-statement application dispatch, or a serial fresh-process
/// selected TEST harness, may call this. Store::open never installs or resets it.
pub(super) fn install_at_process_entry()->Result<()>{
 let selected=INSTALL.get_or_init(||{
  let parent=unsafe{ffi::sqlite3_vfs_find(c"win32".as_ptr())};
  if parent.is_null()||unsafe{(*parent).iVersion}!=3{return Err("TEST exact win32 v3 required at startup".into());}
  let get=unsafe{(*parent).xGetSystemCall}.ok_or("TEST win32 syscall getter absent")?;
  let set=unsafe{(*parent).xSetSystemCall}.ok_or("TEST win32 syscall setter absent")?;
  let table=unsafe{get(parent,c"CloseHandle".as_ptr())}.ok_or("TEST native original CloseHandle absent")? as usize;
  let linked=CloseHandle as *const () as usize;
  // API identity is unchanged. The selected entry must be the exact linked native
  // address, or this image's own import thunk whose import-address-table slot holds
  // that exact address. The retained original is always the linked native address.
  let original=select_original(table,linked,own_import_thunk_target).map_err(|thunk|format!("TEST original syscall differs from linked native CloseHandle; selected=[{}]; linked=[{}]; thunk=[{thunk}]",target_diagnostic(table),target_diagnostic(linked)))?;
  // Publish the original before installing the callback. The original address
  // is independently immutable and available to unrelated native calls.
  ORIGINAL.set(original).map_err(|_|"TEST original close selection already used")?;
  let shim:ffi::sqlite3_syscall_ptr=Some(unsafe{transmute::<NativeClose,unsafe extern "C" fn()>(callback)});
  if unsafe{set(parent,c"CloseHandle".as_ptr(),shim)}!=ffi::SQLITE_OK{
   return Err("TEST native close callback installation refused".into());
  }
  let installed=Installed{parent:parent as usize,original};same_table(&installed)?;Ok(installed)
 });
 let installed=selected.as_ref().map_err(Clone::clone)?;same_table(installed)
}
static ORIGINAL:OnceLock<usize>=OnceLock::new();
pub(super) fn require_installed()->Result<()>{
 let installed=INSTALL.get().ok_or("TEST close boundary not installed at process entry")?.as_ref().map_err(Clone::clone)?;
 if ORIGINAL.get()!=Some(&installed.original){return Err("TEST immutable original close selection differs".into());}same_table(installed)
}
fn native_identity(handle:HANDLE)->Result<(u64,[u8;16])>{
 let mut id:FILE_ID_INFO=unsafe{std::mem::zeroed()};
 if unsafe{GetFileInformationByHandleEx(handle,FileIdInfo,(&mut id as *mut FILE_ID_INFO).cast(),size_of::<FILE_ID_INFO>() as u32)}==0{
  return Err("TEST actual close HANDLE identity unavailable".into());
 }Ok((id.VolumeSerialNumber,id.FileId.Identifier))
}
pub(super) struct MainClose{
 handle:usize,identity:(u64,[u8;16]),attempted:Cell<bool>,outcome:Cell<Option<bool>>,
 callbacks:Cell<u32>,native_error:Cell<u32>,
 #[cfg(test)] modelled_lost_native_success:Cell<bool>,
}
impl MainClose{
 pub(super) fn observe(handle:HANDLE)->Result<Rc<Self>>{
  require_installed()?;let identity=native_identity(handle)?;
  Ok(Rc::new(Self{handle:handle as usize,identity,attempted:Cell::new(false),outcome:Cell::new(None),callbacks:Cell::new(0),native_error:Cell::new(0),#[cfg(test)]modelled_lost_native_success:Cell::new(false)}))
 }
 pub(super) fn matches(&self,handle:HANDLE)->bool{self.handle==handle as usize}
 pub(super) fn arm(self:&Rc<Self>)->Result<CloseInvocation>{
  require_installed()?;
  if self.attempted.get()||self.outcome.get().is_some(){return Err("TEST owned native close already attempted; no retry".into());}
  ACTIVE.with(|slot|{let mut slot=slot.try_borrow_mut().map_err(err)?;
   if slot.is_some(){return Err("TEST nested parent close scope refused".into());}
   if INTERCEPTING.with(|enabled|enabled.get()){return Err("TEST close interception already enabled".into());}
   *slot=Some(self.clone());INTERCEPTING.with(|enabled|enabled.set(true));Ok(CloseInvocation{record:self.clone(),closed:false})})
 }
 pub(super) fn known_success(&self)->bool{self.attempted.get()&&self.outcome.get()==Some(true)&&self.callbacks.get()==1}
 #[cfg(test)] pub(super) fn observation(&self)->(bool,Option<bool>,u32,u32){(self.attempted.get(),self.outcome.get(),self.callbacks.get(),self.native_error.get())}
 #[cfg(test)] pub(super) fn model_lost_native_success(&self){self.modelled_lost_native_success.set(true);}
}
pub(super) struct CloseInvocation{record:Rc<MainClose>,closed:bool}
impl CloseInvocation{
 pub(super) fn finish_checked(mut self)->Result<()>{self.close_scope()}
 fn close_scope(&mut self)->Result<()>{
  if self.closed{return Ok(())}self.closed=true;
  // Revoke interception before any fallible holder release. An uncertain TLS
  // cleanup cannot capture a subsequently recycled unrelated HANDLE number.
  INTERCEPTING.with(|enabled|enabled.set(false));
  ACTIVE.with(|slot|{let mut slot=slot.try_borrow_mut().map_err(err)?;
   if !slot.as_ref().is_some_and(|r|Rc::ptr_eq(r,&self.record)){return Err("TEST exact close scope release differs; preserved UNKNOWN".into());}
   *slot=None;Ok(())})
 }
}
impl Drop for CloseInvocation{fn drop(&mut self){let _=self.close_scope();}}
fn unknown(error:u32)->i32{unsafe{SetLastError(error)};0}
unsafe extern "system" fn callback(handle:HANDLE)->i32{
 // Never unwind across the selected C provider. On a scope fault, retain the
 // already-rooted record and refuse the close instead of inventing success.
 match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
  let enabled=INTERCEPTING.try_with(|enabled|enabled.get()).unwrap_or(false);
  let record=if enabled{ACTIVE.try_with(|slot|slot.try_borrow().map(|s|s.clone()).map_err(|_|UNKNOWN)).unwrap_or(Err(UNKNOWN))}else{Ok(None)};
  let record=match record{Ok(record)=>record,Err(error)=>return unknown(error)};
  if let Some(record)=record.filter(|r|r.matches(handle)){
   let Some(count)=record.callbacks.get().checked_add(1)else{return unknown(UNKNOWN)};record.callbacks.set(count);
   if record.attempted.get()||record.outcome.get().is_some(){let error=record.native_error.get();return unknown(if error==0{UNKNOWN}else{error});}
   if native_identity(handle).ok()!=Some(record.identity){record.outcome.set(Some(false));record.native_error.set(UNKNOWN);return unknown(UNKNOWN);}
   let Some(original)=ORIGINAL.get()else{record.outcome.set(Some(false));return unknown(UNKNOWN)};
   record.attempted.set(true); // BEFORE native effect; reentry cannot repeat.
   let call:NativeClose=unsafe{transmute(*original)};
   let observed=unsafe{call(handle)}!=0;let error=if observed{0}else{unsafe{GetLastError()}};
   #[cfg(test)] if observed&&record.modelled_lost_native_success.get(){
    record.outcome.set(Some(false));record.native_error.set(UNKNOWN);return unknown(UNKNOWN);
   }
   record.outcome.set(Some(observed));record.native_error.set(error);
   return if observed{1}else{unknown(error)};
  }
  // No cross-thread/global HANDLE whitelist: even a numerically recycled
  // unrelated handle always follows the selected original native route.
  let Some(original)=ORIGINAL.get()else{return unknown(UNKNOWN)};
  let call:NativeClose=unsafe{transmute(*original)};unsafe{call(handle)}
 })){
  Ok(result)=>result,Err(_)=>unknown(UNKNOWN),
 }
}

// Positive and negative controls for the import-thunk identity rule.
#[cfg(test)] mod import_thunk_controls{
 use super::*;
 const IMAGE:usize=0x1_4000_0000;
 const SIZE:usize=0x0200_0000;
 const IAT:(usize,usize)=(0x0155_0000,0x1000);
 const LINKED:usize=0x7ff9_48b9_6e00;
 fn jump(thunk:usize,slot:usize)->[u8;6]{
  let d=((slot as i64)-(thunk as i64+6)) as i32;let b=d.to_le_bytes();[0xFF,0x25,b[0],b[1],b[2],b[3]]
 }
 #[test] fn close_boundary_thunk_accepts_exact_import_slot(){
  let thunk=IMAGE+0x0131_67d0;let table=IMAGE+IAT.0;
  for slot in [table,table+0x1d0,table+IAT.1-8]{
   assert_eq!(thunk_slot(jump(thunk,slot),thunk,IMAGE,SIZE,IAT),Ok(slot));
  }
  // A stub placed after the table uses a negative displacement.
  let later=table+IAT.1+0x40;
  assert_eq!(thunk_slot(jump(later,table+8),later,IMAGE,SIZE,IAT),Ok(table+8));
 }
 #[test] fn close_boundary_thunk_refuses_other_instructions(){
  let thunk=IMAGE+0x1000;let slot=IMAGE+IAT.0+8;let good=jump(thunk,slot);
  for code in [
   [0xE9,good[2],good[3],good[4],good[5],0x90], // direct relative jump
   [0xFF,0x15,good[2],good[3],good[4],good[5]], // indirect call
   [0xFF,0x24,good[2],good[3],good[4],good[5]], // other ModRM form
   [0x48,0xFF,0x25,good[2],good[3],good[4]],    // prefixed, shifted encoding
   [0x00;6],[0xCC;6],
  ]{assert!(thunk_slot(code,thunk,IMAGE,SIZE,IAT).is_err());}
 }
 #[test] fn close_boundary_thunk_refuses_slots_outside_import_table(){
  let thunk=IMAGE+0x1000;let table=IMAGE+IAT.0;
  for slot in [
   table-8,            // entry before the table
   table+IAT.1,        // one past the last entry
   table+IAT.1-4,      // straddles the end
   table+4,            // misaligned inside the table
   IMAGE+0x2000,       // inside the image, not an import slot
   IMAGE+SIZE+0x100,   // outside the image
   IMAGE-0x100,        // below the image
  ]{assert!(thunk_slot(jump(thunk,slot),thunk,IMAGE,SIZE,IAT).is_err(),"slot {slot:#x}");}
 }
 #[test] fn close_boundary_thunk_refuses_bad_extents(){
  let slot=IMAGE+IAT.0;
  // Stub below, straddling the end of, and beyond the image.
  for thunk in [IMAGE-6,IMAGE+SIZE-5,IMAGE+SIZE,usize::MAX-2]{
   assert!(thunk_slot(jump(IMAGE+0x1000,slot),thunk,IMAGE,SIZE,IAT).is_err(),"thunk {thunk:#x}");
  }
  let thunk=IMAGE+0x1000;
  // Image extent overflow, a table reaching past the image, and an empty table.
  assert!(thunk_slot(jump(thunk,slot),thunk,usize::MAX-0x10,SIZE,IAT).is_err());
  assert!(thunk_slot(jump(thunk,slot),thunk,IMAGE,SIZE,(SIZE-8,16)).is_err());
  assert!(thunk_slot(jump(thunk,slot),thunk,IMAGE,SIZE,(IAT.0,0)).is_err());
  assert!(thunk_slot(jump(thunk,slot),thunk,IMAGE,0,IAT).is_err());
 }
 #[test] fn close_boundary_identity_selection(){
  // Exact linked address: the resolver is never consulted.
  assert_eq!(select_original(LINKED,LINKED,|_|panic!("resolver consulted")),Ok(LINKED));
  // A verified stub whose slot holds the exact linked address retains the linked address.
  assert_eq!(select_original(0x1234,LINKED,|selected|{assert_eq!(selected,0x1234);Ok(LINKED)}),Ok(LINKED));
  // Any other slot content, including a near miss and null, is refused.
  for other in [LINKED+1,LINKED-1,LINKED+0x10,0,0x1234]{
   assert!(select_original(0x1234,LINKED,|_|Ok(other)).is_err(),"target {other:#x}");
  }
  // A resolver refusal stays a refusal.
  assert!(select_original(0x1234,LINKED,|_|Err("refused".into())).is_err());
 }
 #[test] fn close_boundary_thunk_live_process_controls(){
  let linked=CloseHandle as *const () as usize;
  // Unmapped address, and a real function that lives in another module.
  assert!(own_import_thunk_target(0).is_err());
  assert!(own_import_thunk_target(linked).is_err());
  // This image's ordinary code is never accepted as the linked API.
  assert_ne!(own_import_thunk_target(callback as *const () as usize),Ok(linked));
  assert!(select_original(callback as *const () as usize,linked,own_import_thunk_target).is_err());
  // The actual SQLite table entry is the linked address, this image's verified
  // stub for it, or (when another control installed first) the callback.
  let parent=unsafe{ffi::sqlite3_vfs_find(c"win32".as_ptr())};assert!(!parent.is_null());
  let get=unsafe{(*parent).xGetSystemCall}.expect("win32 syscall getter");
  let table=unsafe{get(parent,c"CloseHandle".as_ptr())}.expect("CloseHandle entry") as usize;
  if table!=callback as *const () as usize{
   assert_eq!(select_original(table,linked,own_import_thunk_target),Ok(linked));
  }
 }
}
