//! New A-only native kernel-object custody. File-ID leases remain unchanged.
//! Preallocated records, checked independent once-close, no uncertain retry.
use crate::{Result,need};
use std::{ffi::c_void,ptr::null_mut,sync::atomic::{AtomicBool,AtomicPtr,Ordering}};
pub(crate) type Handle=*mut c_void;
#[link(name="kernel32")]unsafe extern "system"{pub(crate) fn CloseHandle(h:Handle)->i32;pub(crate) fn GetLastError()->u32;fn LocalFree(h:Handle)->Handle;}
#[derive(Clone,Copy,Debug)]pub(crate) enum Kind{Process,Thread,Job,CompletionPort,PipeRead,PipeWrite,NullInput,LocalPipe,Capture,SecurityAllocation}
struct Record{next:usize,raw:usize,kind:Kind,attempted:bool,outcome:Option<bool>,error:u32}
static UNKNOWN:AtomicBool=AtomicBool::new(false);
static RETAINED:AtomicPtr<Record>=AtomicPtr::new(null_mut());
pub(crate) fn known()->Result<()>{crate::image_pin::native_handle_owner::require_known()?;need(!UNKNOWN.load(Ordering::Acquire),"native A original object custody UNKNOWN")}
pub(crate) fn mark_unknown(){UNKNOWN.store(true,Ordering::Release)}
fn retain(record:Box<Record>){mark_unknown();let p=Box::into_raw(record);let mut h=RETAINED.load(Ordering::Acquire);loop{unsafe{(*p).next=h as usize;}match RETAINED.compare_exchange_weak(h,p,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>break,Err(n)=>h=n}}}
pub(crate) struct Owned{record:Option<Box<Record>>,closed:bool}
impl Owned{
 pub(crate) fn empty(kind:Kind)->Self{Self{record:Some(Box::new(Record{next:0,raw:0,kind,attempted:false,outcome:None,error:0})),closed:false}}
 pub(crate) fn attach(&mut self,raw:Handle)->Result<()>{need(!self.closed&&self.record.as_ref().is_some_and(|r|r.raw==0&&!r.attempted),"one original acquisition")?;self.record.as_mut().unwrap().raw=raw as usize;need(!raw.is_null()&&raw as isize != -1,"native original acquisition failed")}
 pub(crate) fn raw(&self)->Result<Handle>{known()?;need(!self.closed,"original native owner revoked")?;let r=self.record.as_ref().ok_or("original native record absent")?;need(!r.attempted&&r.raw!=0&&r.raw!=usize::MAX,"original native handle absent/consumed")?;Ok(r.raw as Handle)}
 pub(crate) fn close_checked(&mut self)->Result<()>{if self.closed{return Ok(())}self.closed=true;let r=self.record.as_mut().ok_or("native close record absent")?;need(!r.attempted,"native consuming close cannot retry")?;if r.raw==0||r.raw==usize::MAX{self.record.take();return Ok(())}r.attempted=true;
  let good=unsafe{match r.kind{Kind::SecurityAllocation=>LocalFree(r.raw as Handle).is_null(),_=>CloseHandle(r.raw as Handle)!=0}};r.outcome=Some(good);r.error=if good{0}else{unsafe{GetLastError()}};
  if good{r.raw=0;self.record.take();Ok(())}else{let error=r.error;let kind=r.kind;retain(self.record.take().unwrap());Err(format!("native A {kind:?} once-close UNKNOWN {error}"))}
 }
 pub(crate) fn into_raw_transfer(mut self)->Result<Handle>{let raw=self.raw()?;let r=self.record.as_mut().unwrap();r.raw=0;self.closed=true;self.record.take();Ok(raw)}
 pub(crate) fn quarantine(&mut self){self.closed=true;if let Some(r)=self.record.take(){retain(r)}}
}
impl Drop for Owned{fn drop(&mut self){if !self.closed{let _=self.close_checked();}if let Some(r)=self.record.take(){if r.raw!=0&&r.raw!=usize::MAX{retain(r)}}}}
