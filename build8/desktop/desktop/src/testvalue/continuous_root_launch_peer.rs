//! RootLaunch local client. Explicit once-only process/pipe/descriptor custody;
//! no peer PID from a message, detached overlapped IO or close retry.
use super::{Result,OwnTokenFacts,Identity,PublicObjectSpec,OriginalPublicFile,own_native_token};
use std::{cell::Cell,ffi::c_void,mem::zeroed,path::PathBuf,ptr::null_mut,
 sync::atomic::{AtomicBool,AtomicPtr,Ordering},time::{Duration,Instant}};
type Handle=*mut c_void;
#[repr(C)]struct FileTime{low:u32,high:u32}
#[link(name="kernel32")]
unsafe extern "system"{
 fn OpenProcess(access:u32,inherit:i32,pid:u32)->Handle;
 fn CreateFileW(name:*const u16,access:u32,sharing:u32,security:Handle,creation:u32,flags:u32,template:Handle)->Handle;
 fn GetFileType(file:Handle)->u32;
 fn GetNamedPipeInfo(pipe:Handle,flags:*mut u32,out_size:*mut u32,in_size:*mut u32,instances:*mut u32)->i32;
 fn GetProcessId(process:Handle)->u32;
 fn GetProcessTimes(process:Handle,born:*mut FileTime,exit:*mut FileTime,kernel:*mut FileTime,user:*mut FileTime)->i32;
 fn QueryFullProcessImageNameW(process:Handle,flags:u32,name:*mut u16,bytes:*mut u32)->i32;
 fn WaitForSingleObject(process:Handle,millis:u32)->u32;
 fn GetNamedPipeServerProcessId(pipe:Handle,pid:*mut u32)->i32;
 fn SetNamedPipeHandleState(pipe:Handle,mode:*const u32,max:*const u32,timeout:*const u32)->i32;
 fn ReadFile(file:Handle,bytes:Handle,length:u32,read:*mut u32,overlap:Handle)->i32;
 fn WriteFile(file:Handle,bytes:*const u8,length:u32,written:*mut u32,overlap:Handle)->i32;
 fn GetLastError()->u32;
 fn CloseHandle(handle:Handle)->i32;
 fn LocalFree(handle:Handle)->Handle;
}
#[link(name="advapi32")]
unsafe extern "system"{
 fn GetSecurityInfo(object:Handle,kind:i32,info:u32,owner:*mut Handle,group:*mut Handle,dacl:*mut Handle,sacl:*mut Handle,allocation:*mut Handle)->u32;
 fn GetSecurityDescriptorControl(sd:Handle,control:*mut u16,revision:*mut u32)->i32;
 fn IsValidSid(sid:Handle)->i32;
 fn GetLengthSid(sid:Handle)->u32;
}
struct PeerRecord{handle:usize,pid:u32,start:u64,attempted:bool,observed:Option<bool>,error:u32,
 original:Option<OriginalPublicFile>,payload:Option<OriginalPublicFile>}
struct Allocation{next:usize,graph_next:usize,raw:usize,attempted:bool,error:u32}
struct PipeRecord{next:usize,raw:usize,name:String,server_pid:u32,attempted:bool,observed:Option<bool>,error:u32,descriptors:Cell<usize>}
// Every record is allocated before its native acquisition. The quarantined
// graph retains pipe/process/files/token observations and failed descriptors,
// including pipe/process successful close observations. Freed descriptors are
// discharged; uncertain descriptor records stay linked. No record is retried.
struct ChannelGraph{next:usize,peer:Option<Box<PeerRecord>>,pipe:Option<PipeOwner>,expected:Identity,parent_token:OwnTokenFacts}
static GRAPHS:AtomicPtr<ChannelGraph>=AtomicPtr::new(null_mut());
static PIPES:AtomicPtr<PipeRecord>=AtomicPtr::new(null_mut());
static ALLOCATIONS:AtomicPtr<Allocation>=AtomicPtr::new(null_mut());
static UNKNOWN:AtomicBool=AtomicBool::new(false);
fn keep_graph(r:Box<ChannelGraph>){UNKNOWN.store(true,Ordering::Release);let p=Box::into_raw(r);let mut h=GRAPHS.load(Ordering::Acquire);loop{unsafe{(*p).next=h as usize;}match GRAPHS.compare_exchange_weak(h,p,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>break,Err(n)=>h=n}}}
fn keep_pipe(r:Box<PipeRecord>){UNKNOWN.store(true,Ordering::Release);let p=Box::into_raw(r);let mut h=PIPES.load(Ordering::Acquire);loop{unsafe{(*p).next=h as usize;}match PIPES.compare_exchange_weak(h,p,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>break,Err(n)=>h=n}}}
fn keep_allocation(r:Box<Allocation>){UNKNOWN.store(true,Ordering::Release);let p=Box::into_raw(r);let mut h=ALLOCATIONS.load(Ordering::Acquire);loop{unsafe{(*p).next=h as usize;}match ALLOCATIONS.compare_exchange_weak(h,p,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>break,Err(n)=>h=n}}}
fn keep_descriptor(mut r:Box<Allocation>,head:&Cell<usize>){r.graph_next=head.get();head.set((&*r as *const Allocation) as usize);keep_allocation(r);}
struct DescriptorOwner<'a>{record:Option<Box<Allocation>>,graph:&'a Cell<usize>}
impl Drop for DescriptorOwner<'_>{fn drop(&mut self){if let Some(r)=self.record.take(){if r.raw!=0{keep_descriptor(r,self.graph);}}}}
fn close_descriptor(owner:&mut DescriptorOwner<'_>)->Result<()>{let r=owner.record.as_mut().ok_or("Root descriptor record absent")?;if r.attempted{return Err("Root descriptor close no retry".into());}r.attempted=true;
 if r.raw==0||unsafe{LocalFree(r.raw as Handle)}.is_null(){owner.record.take();Ok(())}else{r.error=unsafe{GetLastError()};keep_descriptor(owner.record.take().unwrap(),owner.graph);Err("Root descriptor custody UNKNOWN".into())}}
// This owner is private to RootChannel. It cannot accept an arbitrary HANDLE,
// disk path, remote pipe or reopened object as authority. NativeFile stays a
// disk FILE_ID_INFO owner and is intentionally not used for pipe objects.
struct PipeOwner{record:Option<Box<PipeRecord>>}
impl PipeOwner{
 fn selected(name:&str)->Result<Self>{
  const PREFIX:&str=r"\\.\pipe\Mutiny-RootLaunch-";
  let suffix=name.strip_prefix(PREFIX).ok_or("Root pipe literal local namespace")?;
  if suffix.len()!=97||!suffix.is_ascii()||suffix.as_bytes()[64]!=b'-'||!suffix[..64].bytes().chain(suffix[65..].bytes()).all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c)){
   return Err("Root pipe exact campaign/instance lowercase hex namespace".into());
  }
  Ok(Self{record:Some(Box::new(PipeRecord{next:0,raw:0,name:name.to_owned(),server_pid:0,attempted:false,observed:None,error:0,descriptors:Cell::new(0)}))})
 }
 fn acquire(&mut self)->Result<()>{
  let r=self.record.as_mut().ok_or("Root pipe custody absent before acquire")?;
  if UNKNOWN.load(Ordering::Acquire)||r.raw!=0||r.attempted{return Err("Root pipe single original acquisition/known custody required".into());}
  let wide:Vec<u16>=r.name.encode_utf16().chain(Some(0)).collect();
  // Literal named-pipe namespace, OPEN_EXISTING, synchronous IO, noninheritable.
  // The owner is installed in the preallocated channel before CreateFileW.
  let raw=unsafe{CreateFileW(wide.as_ptr(),0xc0000000|0x20000,0,null_mut(),3,0,null_mut())};
  if raw.is_null()||raw as isize==-1{r.error=unsafe{GetLastError()};return Err(format!("Root original named pipe open {}",r.error));}
  r.raw=raw as usize;Self::require_kind(raw)?;let mut pid=0;
  if unsafe{GetNamedPipeServerProcessId(raw,&mut pid)}==0||pid==0{return Err("Root original named pipe server process absent".into());}
  r.server_pid=pid;Ok(())
 }
 fn require_kind(raw:Handle)->Result<()>{let mut flags=0;
  if unsafe{GetFileType(raw)}!=3||unsafe{GetNamedPipeInfo(raw,&mut flags,null_mut(),null_mut(),null_mut())}==0||flags!=4{
   return Err("Root original pipe requires named message client object".into());
  }Ok(())
 }
 fn raw(&self)->Result<Handle>{let r=self.record.as_ref().ok_or("Root original pipe record absent")?;
  if UNKNOWN.load(Ordering::Acquire)||r.raw==0||r.attempted||r.server_pid==0{return Err("Root original pipe closed/unselected/UNKNOWN".into());}
  let raw=r.raw as Handle;Self::require_kind(raw)?;let mut pid=0;
  if unsafe{GetNamedPipeServerProcessId(raw,&mut pid)}==0||pid!=r.server_pid{return Err("Root retained pipe original server changed".into());}Ok(raw)
 }
 fn close_checked(&mut self)->Result<()>{let r=self.record.as_mut().ok_or("Root pipe close record absent")?;
  if r.attempted{return Err("Root original pipe close no retry".into());}
  r.attempted=true;if r.raw==0{return Ok(());}
  let closed=unsafe{CloseHandle(r.raw as Handle)}!=0;r.observed=Some(closed);r.error=if closed{0}else{unsafe{GetLastError()}};
  if closed{r.raw=0;Ok(())}else{UNKNOWN.store(true,Ordering::Release);Err(format!("Root original pipe CloseHandle UNKNOWN {}",r.error))}
 }
}
impl Drop for PipeOwner{fn drop(&mut self){if let Some(r)=self.record.take(){if r.raw!=0||r.descriptors.get()!=0{keep_pipe(r);}}}}
fn sid(raw:Handle)->Result<Vec<u8>>{if raw.is_null()||unsafe{IsValidSid(raw)}==0{return Err("Root pipe SID validity".into());}let n=unsafe{GetLengthSid(raw)} as usize;if !(8..=68).contains(&n){return Err("Root pipe SID bound".into());}Ok(unsafe{std::slice::from_raw_parts(raw.cast::<u8>(),n)}.to_vec())}
fn security(pipe:&PipeOwner,expected:&[u8])->Result<()>{
 let raw=pipe.raw()?;let graph=&pipe.record.as_ref().ok_or("Root descriptor original pipe absent")?.descriptors;
 let mut original=DescriptorOwner{record:Some(Box::new(Allocation{next:0,graph_next:0,raw:0,attempted:false,error:0})),graph};let(mut owner,mut acl,mut allocation)=(null_mut(),null_mut(),null_mut());
 // Preserve reviewed SE_KERNEL_OBJECT=6. No unsupported object-type guess.
 const SE_KERNEL_OBJECT:i32=6;
 let status=unsafe{GetSecurityInfo(raw,SE_KERNEL_OBJECT,5,&mut owner,null_mut(),&mut acl,null_mut(),&mut allocation)};original.record.as_mut().unwrap().raw=allocation as usize;
 let operation: Result<()>=(||{if status!=0||allocation.is_null()||acl.is_null(){return Err("Root pipe original security unavailable".into());}let(mut control,mut revision)=(0u16,0u32);
  if unsafe{GetSecurityDescriptorControl(allocation,&mut control,&mut revision)}==0||revision!=1||control&0x1000==0||sid(owner)?!=expected{return Err("Root pipe owner/protected descriptor differs".into());}
  let bytes=acl.cast::<u8>();let size=unsafe{u16::from_le_bytes([*bytes.add(2),*bytes.add(3)])} as usize;let count=unsafe{u16::from_le_bytes([*bytes.add(4),*bytes.add(5)])};
  if size<8||size>256||count!=2{return Err("Root pipe exact2ACE bound".into());}let mut offset=8usize;let(mut own,mut system)=(0,0);
  for _ in 0..2{if offset+16>size{return Err("Root pipe ACE header".into());}let ace=unsafe{bytes.add(offset)};let width=unsafe{u16::from_le_bytes([*ace.add(2),*ace.add(3)])} as usize;
   if unsafe{*ace}!=0||unsafe{*ace.add(1)}!=0||width<16||offset+width>size{return Err("Root pipe ACE type/flags/extent".into());}let mask=unsafe{std::ptr::read_unaligned(ace.add(4).cast::<u32>())};let sub=unsafe{*ace.add(9)} as usize;
   if mask!=0x1f01ff||sub>15||width!=16+4*sub{return Err("Root pipe exact selected rights/SID width".into());}let principal=sid(unsafe{ace.add(8)}.cast())?;
   if principal==expected{own+=1}else if principal==[1,1,0,0,0,0,0,5,18,0,0,0]{system+=1}else{return Err("Root pipe foreign principal".into());}offset+=width;
  }if own!=1||system!=1||offset!=size{return Err("Root pipe exact identities/accounting".into());}Ok(())})();let closure=close_descriptor(&mut original);
 match(operation,closure){(Ok(()),Ok(()))=>Ok(()),(a,b)=>Err(format!("Root pipe security={a:?}; once close={b:?}"))}
}
pub(super) struct RootChannel{record:Option<Box<PeerRecord>>,pipe:Option<PipeOwner>,expected:Identity,parent_token:OwnTokenFacts,graph:Option<Box<ChannelGraph>>,deadline:Instant,closed:bool}
impl RootChannel{
 fn custody(expected:Identity,parent_token:OwnTokenFacts)->Self{
  let graph=Some(Box::new(ChannelGraph{next:0,peer:None,pipe:None,expected:expected.clone(),parent_token:parent_token.clone()}));
  Self{record:Some(Box::new(PeerRecord{handle:0,pid:expected.pid,start:expected.start_filetime,attempted:false,observed:None,error:0,original:None,payload:None})),pipe:None,expected,parent_token,graph,deadline:Instant::now()+Duration::from_secs(30),closed:false}
 }
 fn quarantine_graph(&mut self){
  if let Some(mut graph)=self.graph.take(){graph.peer=self.record.take();graph.pipe=self.pipe.take();keep_graph(graph);}
 }
 // Name is an untrusted routing hint. The only issuer is the exact parent
 // original artifact selected in trusted compiled source. PID is obtained
 // from this held OS pipe, never a message/CLI. Its opened original process
 // is retained, then server PID/start/token/file are bracketed before bytes.
 pub(super) fn open_anchor(spec:&PublicObjectSpec,payload:&PublicObjectSpec,selected_user:&[u8],name:&str,cancel:&AtomicBool)->Result<Self>{
  if UNKNOWN.load(Ordering::Acquire)||cancel.load(Ordering::Acquire){return Err("Root anchor cancelled/UNKNOWN".into());}
  let own=own_native_token::observe_own()?;if own.user_sid!=selected_user||own.restricted||own.app_container{return Err("Compiled Root TEST role differs".into());}
  let placeholder=Identity{pid:0,start_filetime:0,image_path:spec.path.clone(),image_sha256:spec.sha256,user_sid:selected_user.to_vec(),session:own.session,authentication_luid:(own.authentication_id.low,own.authentication_id.high)};
  let mut channel=Self::custody(placeholder,own.clone());
  let operation=(||{channel.pipe=Some(PipeOwner::selected(name)?);channel.pipe.as_mut().unwrap().acquire()?;let pipe=channel.pipe.as_ref().unwrap().raw()?;let mode=2|1;
   if unsafe{SetNamedPipeHandleState(pipe,&mode,std::ptr::null(),std::ptr::null())}==0{return Err("Root routing pipe message mode refused".into());}let mut pid=0;
   if unsafe{GetNamedPipeServerProcessId(pipe,&mut pid)}==0||pid==0{return Err("Root actual OS server process absent".into());}
   channel.record.as_mut().unwrap().pid=pid;let raw=unsafe{OpenProcess(0x100000|0x1000,0,pid)};channel.record.as_mut().unwrap().handle=raw as usize;
   if raw.is_null(){channel.record.as_mut().unwrap().error=unsafe{GetLastError()};return Err("Root OS server original process unavailable".into());}
   let(mut born,mut exit,mut kernel,mut user):(FileTime,FileTime,FileTime,FileTime)=unsafe{zeroed()};
   if unsafe{GetProcessTimes(raw,&mut born,&mut exit,&mut kernel,&mut user)}==0{return Err("Root original server start unavailable".into());}let start=(born.high as u64)<<32|born.low as u64;
   if start==0{return Err("Root server original creation absent".into());}channel.record.as_mut().unwrap().start=start;
   let parent=unsafe{own_native_token::observe_selected_peer(raw,pid,start)}?;
   if parent.user_sid!=selected_user||parent.authentication_id!=own.authentication_id||parent.session!=own.session||parent.elevation_type!=own.elevation_type||parent.elevated!=own.elevated||parent.integrity_sid!=own.integrity_sid||parent.restricted||parent.app_container{return Err("Root actual TEST token/logon/profile differs".into());}
   channel.expected=Identity{pid,start_filetime:start,image_path:spec.path.clone(),image_sha256:spec.sha256,user_sid:parent.user_sid.clone(),session:parent.session,authentication_luid:(parent.authentication_id.low,parent.authentication_id.high)};
   channel.parent_token=parent;channel.graph.as_mut().unwrap().expected=channel.expected.clone();channel.graph.as_mut().unwrap().parent_token=channel.parent_token.clone();
   channel.record.as_mut().unwrap().original=Some(OriginalPublicFile::open_declared(spec.clone(),selected_user)?);channel.record.as_mut().unwrap().payload=Some(OriginalPublicFile::open_declared(payload.clone(),selected_user)?);
   channel.require_peer(cancel)
  })();if let Err(primary)=operation{let closure=channel.close_checked();return Err(format!("Root anchor authentication={primary}; independent close={closure:?}"));}Ok(channel)
 }
 pub(super) fn authenticated_context(&self,cancel:&AtomicBool)->Result<(Identity,OwnTokenFacts)>{self.require_peer(cancel)?;Ok((self.expected.clone(),self.parent_token.clone()))}
 pub(super) fn open(expected:&Identity,parent:&OwnTokenFacts,spec:&PublicObjectSpec,name:&str,cancel:&AtomicBool)->Result<Self>{
  if UNKNOWN.load(Ordering::Acquire)||cancel.load(Ordering::Acquire){return Err("Root channel cancelled/UNKNOWN before opens".into());}
  let mut channel=Self::custody(expected.clone(),parent.clone());
  let operation=(||{channel.pipe=Some(PipeOwner::selected(name)?);channel.pipe.as_mut().unwrap().acquire()?;let pipe=channel.pipe.as_ref().unwrap().raw()?;let mut pid=0;
   if unsafe{GetNamedPipeServerProcessId(pipe,&mut pid)}==0||pid==0||pid!=expected.pid{return Err("Root OS selected server process mismatch before acquisition".into());}
   let raw=unsafe{OpenProcess(0x100000|0x1000,0,pid)};let error=if raw.is_null(){unsafe{GetLastError()}}else{0};channel.record.as_mut().unwrap().handle=raw as usize;channel.record.as_mut().unwrap().error=error;
   if raw.is_null(){return Err(format!("Root selected parent original process open {error}"));}
   channel.record.as_mut().unwrap().original=Some(OriginalPublicFile::open_declared(spec.clone(),&parent.user_sid)?);channel.require_parent(cancel)?;
   let mode=2|1;
   if unsafe{SetNamedPipeHandleState(pipe,&mode,std::ptr::null(),std::ptr::null())}==0{return Err("Root pipe nonblocking message mode".into());}channel.require_peer(cancel)
  })();if let Err(primary)=operation{let closure=channel.close_checked();return Err(format!("Root channel open={primary}; independent once close={closure:?}"));}Ok(channel)
 }
 fn require_parent(&self,cancel:&AtomicBool)->Result<()>{if self.closed||cancel.load(Ordering::Acquire)||UNKNOWN.load(Ordering::Acquire)||Instant::now()>=self.deadline{return Err("Root channel cancelled/deadline/UNKNOWN".into());}let r=self.record.as_ref().ok_or("Root peer consumed")?;let raw=r.handle as Handle;
  if raw.is_null()||unsafe{WaitForSingleObject(raw,0)}!=258||unsafe{GetProcessId(raw)}!=r.pid{return Err("Root selected original parent no longer live".into());}let(mut born,mut exit,mut kernel,mut user):(FileTime,FileTime,FileTime,FileTime)=unsafe{zeroed()};
  if unsafe{GetProcessTimes(raw,&mut born,&mut exit,&mut kernel,&mut user)}==0||((born.high as u64)<<32|born.low as u64)!=r.start{return Err("Root parent original creation differs".into());}
  let mut path=[0u16;4097];let mut count=path.len() as u32;if unsafe{QueryFullProcessImageNameW(raw,0,path.as_mut_ptr(),&mut count)}==0||count==0||count as usize>=path.len(){return Err("Root selected parent image path".into());}
  if PathBuf::from(String::from_utf16(&path[..count as usize]).map_err(|_|"Root parent UTF16")?)!=self.expected.image_path{return Err("Root parent exact selected image differs".into());}
  r.original.as_ref().ok_or("Root parent original file absent")?.recheck()?;
  if let Some(payload)=r.payload.as_ref(){payload.recheck()?;}
  if unsafe{own_native_token::observe_selected_peer(raw,self.expected.pid,self.expected.start_filetime)}?!=self.parent_token{return Err("Root original parent primary token changed".into());}Ok(())
 }
 pub(super) fn require_peer(&self,cancel:&AtomicBool)->Result<()>{self.require_parent(cancel)?;let original=self.pipe.as_ref().ok_or("Root pipe absent")?;let pipe=original.raw()?;let mut pid=0;
  if unsafe{GetNamedPipeServerProcessId(pipe,&mut pid)}==0||pid!=self.expected.pid{return Err("Root OS server peer mismatch".into());}
  // Descriptor/primary token/creation/image/original checks bracket every frame.
  security(original,&self.parent_token.user_sid)?;self.require_parent(cancel)
 }
 fn poll(&self,cancel:&AtomicBool)->Result<()>{self.require_peer(cancel)?;std::thread::sleep(Duration::from_millis(5));self.require_peer(cancel)}
 pub(super) fn write(&self,payload:&[u8],cancel:&AtomicBool)->Result<()>{if payload.is_empty()||payload.len()>1020{return Err("Root fixed frame payload bound".into());}let mut bytes=[0u8;1024];bytes[..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());bytes[4..payload.len()+4].copy_from_slice(payload);
  loop{self.require_peer(cancel)?;let mut n=0;let ok=unsafe{WriteFile(self.pipe.as_ref().unwrap().raw()?,bytes.as_ptr(),(payload.len()+4) as u32,&mut n,null_mut())};let error=if ok==0{unsafe{GetLastError()}}else{0};self.require_peer(cancel)?;
   if ok!=0&&n as usize==payload.len()+4{return Ok(());}if ok!=0&&n==0{self.poll(cancel)?;continue;}return Err(format!("Root partial/failed write no retry {error}/{n}"));}
 }
 fn read(&self,cancel:&AtomicBool)->Result<Vec<u8>>{loop{self.require_peer(cancel)?;let mut bytes=[0u8;1024];let mut n=0;let ok=unsafe{ReadFile(self.pipe.as_ref().unwrap().raw()?,bytes.as_mut_ptr().cast(),1024,&mut n,null_mut())};let error=if ok==0{unsafe{GetLastError()}}else{0};self.require_peer(cancel)?;
  if ok!=0{if !(5..=1024).contains(&n)||u32::from_le_bytes(bytes[..4].try_into().unwrap())!=n-4{return Err("Root exact whole message frame".into());}return Ok(bytes[4..n as usize].to_vec());}if error==232&&n==0{self.poll(cancel)?;continue;}return Err(format!("Root EOF/partial/read refused {error}/{n}"));}}
 pub(super) fn read_capsule(&self,cancel:&AtomicBool)->Result<Vec<u8>>{self.read_capsule_limit(cancel,67108864)}
 pub(super) fn read_capsule_limit(&self,cancel:&AtomicBool,maximum:usize)->Result<Vec<u8>>{if !(2..=67108864).contains(&maximum){return Err("Root admitted capsule limit".into());}let header=self.read(cancel)?;let text=std::str::from_utf8(&header).map_err(|_|"Root capsule header ASCII")?;let count=text.strip_prefix("ROOT_CAPSULE_BYTES ").ok_or("Root fixed capsule header")?;
  if count.is_empty()||count.len()>8||!count.bytes().all(|c|c.is_ascii_digit()){return Err("Root capsule decimal length".into());}let count=count.parse::<usize>().map_err(|_|"Root capsule length")?;if !(2..=maximum).contains(&count){return Err("Root capsule size before allocation".into());}
  let mut bytes=Vec::with_capacity(count);while bytes.len()<count{let part=self.read(cancel)?;if part.len()>count-bytes.len(){return Err("Root capsule overrun/extra bytes".into());}bytes.extend_from_slice(&part);}self.require_peer(cancel)?;Ok(bytes)
 }
 pub(super) fn close_checked(&mut self)->Result<()>{if self.closed{return Err("Root channel consuming close no retry".into());}self.closed=true;let mut errors=Vec::new();
  if let Some(pipe)=self.pipe.as_mut(){if let Err(e)=pipe.close_checked(){errors.push(e);}}
  if let Some(record)=self.record.as_mut(){if record.handle!=0{if record.attempted{errors.push("Root parent close previously attempted; no retry".into());}else{
   record.attempted=true;let closed=unsafe{CloseHandle(record.handle as Handle)}!=0;record.observed=Some(closed);record.error=if closed{0}else{unsafe{GetLastError()}};
   if closed{record.handle=0}else{errors.push(format!("Root parent original process close UNKNOWN {}",record.error));}}}
   // The process record stays rooted while the independent parent file close
   // is attempted once, even when the original process close is UNKNOWN.
   // Retain its observations and any failed raw handle together; never retry.
   if let Some(original)=record.original.as_mut(){if let Err(e)=original.close_checked(){errors.push(e);}}
   if let Some(payload)=record.payload.as_mut(){if let Err(e)=payload.close_checked(){errors.push(e);}}}
  if errors.is_empty()&&!UNKNOWN.load(Ordering::Acquire){self.pipe.take();self.record.take();self.graph.take();Ok(())}
  else{self.quarantine_graph();UNKNOWN.store(true,Ordering::Release);Err(format!("Root channel entire original graph UNKNOWN; independent closures {errors:?}"))}
 }
}
impl Drop for RootChannel{fn drop(&mut self){if !self.closed{let _=self.close_checked();}
 // A panic between native attempt and acknowledgement also retains the complete
 // preallocated graph. No destructor retries an attempted pipe/process close.
 if self.record.is_some()||self.pipe.is_some(){self.quarantine_graph();}
}}
