//! A-only finite original process/job/three-handle supervisor and full drains.
//! JOB_LIST assigns custody before execution. No kill, PID reopen or reset.
use crate::{Result,need,owned::{self,Handle,Owned,Kind},own_native_token::{self,OwnTokenFacts}};
use sha2::{Digest,Sha256};
use serde_json::{json,Value};
use std::{collections::BTreeMap,ffi::c_void,fs::{File,OpenOptions},io::{Read,Write},mem::{size_of,zeroed},os::windows::io::FromRawHandle,ptr::{null,null_mut},sync::mpsc,thread::{self,JoinHandle},time::{Duration,Instant}};
#[repr(C)]struct Security{length:u32,descriptor:Handle,inherit:i32}
#[repr(C)]struct Startup{cb:u32,reserved:Handle,desktop:Handle,title:Handle,x:u32,y:u32,x_size:u32,y_size:u32,x_count:u32,y_count:u32,fill:u32,flags:u32,show:u16,reserved2:u16,reserved_bytes:Handle,input:Handle,output:Handle,error:Handle}
#[repr(C)]struct StartupEx{info:Startup,attributes:Handle}
#[repr(C)]struct ProcessInfo{process:Handle,thread:Handle,pid:u32,tid:u32}
#[repr(C)]struct Association{key:Handle,port:Handle}
#[repr(C)]struct Accounting{user:i64,kernel:i64,period_user:i64,period_kernel:i64,faults:u32,total:u32,active:u32,terminated:u32}
#[repr(C)]#[derive(Clone,Copy)]struct FileTime{low:u32,high:u32}
#[link(name="kernel32")]unsafe extern "system"{
 fn CreateJobObjectW(a:Handle,n:*const u16)->Handle;fn CreateIoCompletionPort(file:Handle,port:Handle,key:usize,threads:u32)->Handle;
 fn SetInformationJobObject(job:Handle,kind:i32,p:*const c_void,n:u32)->i32;fn QueryInformationJobObject(job:Handle,kind:i32,p:*mut c_void,n:u32,ret:Handle)->i32;
 fn GetQueuedCompletionStatus(port:Handle,code:*mut u32,key:*mut usize,data:*mut Handle,ms:u32)->i32;
 fn CreatePipe(read:*mut Handle,write:*mut Handle,a:*const Security,n:u32)->i32;fn SetHandleInformation(h:Handle,mask:u32,flags:u32)->i32;
 fn CreateFileW(p:*const u16,access:u32,share:u32,a:*const Security,creation:u32,flags:u32,t:Handle)->Handle;
 fn InitializeProcThreadAttributeList(list:Handle,count:u32,flags:u32,bytes:*mut usize)->i32;
 fn UpdateProcThreadAttribute(list:Handle,flags:u32,attribute:usize,value:Handle,bytes:usize,prior:Handle,ret:Handle)->i32;
 fn DeleteProcThreadAttributeList(list:Handle);
 fn CreateProcessW(image:*const u16,command:*mut u16,p:Handle,t:Handle,inherit:i32,flags:u32,environment:Handle,cwd:*const u16,start:*mut StartupEx,info:*mut ProcessInfo)->i32;
 fn ResumeThread(thread:Handle)->u32;fn WaitForSingleObject(h:Handle,ms:u32)->u32;fn GetExitCodeProcess(h:Handle,code:*mut u32)->i32;
 fn GetProcessId(h:Handle)->u32;fn GetProcessTimes(h:Handle,b:*mut FileTime,e:*mut FileTime,k:*mut FileTime,u:*mut FileTime)->i32;
 fn QueryFullProcessImageNameW(h:Handle,flags:u32,p:*mut u16,n:*mut u32)->i32;
 fn ReadFile(h:Handle,b:*mut c_void,n:u32,read:*mut u32,overlap:Handle)->i32; fn WriteFile(h:Handle,b:*const c_void,n:u32,written:*mut u32,overlap:Handle)->i32; fn FlushFileBuffers(h:Handle)->i32;
}
fn wide(s:&str)->Vec<u16>{s.encode_utf16().chain(Some(0)).collect()}
fn native(ok:bool,label:&str)->Result<()>{need(ok,&format!("{label} Win32={}",unsafe{owned::GetLastError()}))}
fn quote(s:&str)->Result<String>{need(!s.is_empty()&&s.len()<=4096&&!s.contains('\0'),"bounded literal command argument")?;let mut out=String::from("\"");let mut slash=0;for c in s.chars(){if c=='\\'{slash+=1;continue}if c=='"'{out.push_str(&"\\".repeat(slash*2+1));out.push('"')}else{out.push_str(&"\\".repeat(slash));out.push(c)}slash=0}out.push_str(&"\\".repeat(slash*2));out.push('"');Ok(out)}
struct DrainRecord{output:Owned,digest:Sha256,count:u64,retained:u64,overflow:bool,eof:bool,errors:Vec<String>,terminal:Option<Value>}
struct Drain{record:Option<Box<DrainRecord>>}
impl Drain{
 fn acquire(path:&str)->Result<Self>{let mut graph=Self{record:Some(Box::new(DrainRecord{output:Owned::empty(Kind::Capture),digest:Sha256::new(),count:0,retained:0,overflow:false,eof:false,errors:Vec::new(),terminal:None}))};graph.record.as_mut().unwrap().output.attach(unsafe{CreateFileW(wide(path).as_ptr(),0x40000000,1,null(),1,0x80,null_mut())})?;Ok(graph)}
 fn run(&mut self,raw:usize,started:mpsc::SyncSender<()>)->Value{let _=started.send(());let r=self.record.as_mut().unwrap();let mut buffer=[0u8;65536];
  loop{let mut n=0u32;let ok=unsafe{ReadFile(raw as Handle,buffer.as_mut_ptr().cast(),buffer.len() as u32,&mut n,null_mut())};let error=if ok==0{unsafe{owned::GetLastError()}}else{0};if ok==0{if error==109&&n==0{r.eof=true}else{r.errors.push(format!("original pipe drain {error}/{n}"))}break}if n==0{r.eof=true;break}let b=&buffer[..n as usize];if let Some(total)=r.count.checked_add(n as u64){r.count=total}else{r.overflow=true;r.errors.push("drain byte overflow".into())}r.digest.update(b);
   let room=67108864u64.saturating_sub(r.retained);let keep=room.min(n as u64) as usize;if keep<n as usize{r.overflow=true}if keep>0{let mut written=0u32;let result=r.output.raw().and_then(|h|native(unsafe{WriteFile(h,b.as_ptr().cast(),keep as u32,&mut written,null_mut())}!=0&&written==keep as u32,"original capture whole write"));match result{Ok(())=>r.retained+=keep as u64,Err(e)=>{r.errors.push(e);r.overflow=true}}}
  }
  if let Err(e)=r.output.raw().and_then(|h|native(unsafe{FlushFileBuffers(h)}!=0,"original capture flush")){r.errors.push(e)}if let Err(e)=r.output.close_checked(){r.errors.push(e)}
  r.terminal=Some(json!({"bytes":r.count,"retained":r.retained,"sha256":hex::encode(r.digest.clone().finalize()),"eof":r.eof,"hash_complete":r.eof,"overflow":r.overflow,"errors":r.errors,"null_drain":false}));r.terminal.as_ref().unwrap().clone()
 }
 fn retain(&mut self){owned::mark_unknown();if let Some(r)=self.record.take(){let _=Box::leak(r);}}
}
impl Drop for Drain{fn drop(&mut self){if std::thread::panicking(){self.retain()}}}
struct PumpRecord{thread:Option<JoinHandle<Value>>,read:Option<Owned>,terminal:Option<Value>,join_attempted:bool,join_failure:Option<String>}
pub(crate) struct Pump{record:Option<Box<PumpRecord>>}
impl Pump{
 fn start(read:Owned,path:&str)->Result<Self>{
  // This preallocated complete record stays outside the local unwind boundary.
  // No started drainer can drop/detach its join or original read owner here.
  let mut graph=Box::new(PumpRecord{thread:None,read:Some(read),terminal:None,join_attempted:false,join_failure:None});
  let attempt=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->Result<()>{
  // Capture output and worker are acquired before CreateProcess. The worker
  // borrows the original read handle retained in this Pump record; no reopen.
  let mut drain=Drain::acquire(path)?;
  let raw=graph.read.as_ref().ok_or("original pump read owner absent")?.raw()? as usize;let(tx,rx)=mpsc::sync_channel(1);
  let worker=thread::Builder::new().name("native-root-full-drain".into()).spawn(move||{
   match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||drain.run(raw,tx))){Ok(report)=>report,Err(payload)=>{drain.retain();std::mem::forget(payload);json!({"eof":false,"hash_complete":false,"overflow":false,"errors":["original drain unwind; output and partial observations retained UNKNOWN"],"null_drain":false,"worker_unwind":true})}}
  }).map_err(|e|e.to_string())?;
  graph.thread=Some(worker);
  if rx.recv_timeout(Duration::from_secs(30)).is_err(){return Err("precreation original drainer startup UNKNOWN".into())}
  Ok(())}));
  match attempt{Ok(Ok(()))=>Ok(Self{record:Some(graph)}),Ok(Err(error))=>{owned::mark_unknown();let _=Box::leak(graph);Err(error)},Err(payload)=>{owned::mark_unknown();let _=Box::leak(graph);std::mem::forget(payload);Err("original pump acquisition/startup unwind UNKNOWN; complete record retained".into())}}
 }
 fn terminal(&self)->Option<&Value>{self.record.as_ref().and_then(|r|r.terminal.as_ref())}
 fn pending(&self)->bool{self.record.as_ref().is_some_and(|r|r.thread.is_some()||(r.join_attempted&&r.terminal.is_none()))}
 fn join(&mut self)->Result<Value>{
  let record=self.record.as_mut().ok_or("original pump record absent")?;need(!record.join_attempted,"drain join consumed; no retry")?;record.join_attempted=true;
  let thread=record.thread.take().ok_or("original drain already joined")?;
  match thread.join(){Ok(report)=>{record.terminal=Some(report)},Err(payload)=>{owned::mark_unknown();std::mem::forget(payload);record.join_failure=Some("original drainer unwind UNKNOWN".into());return Err("original drainer unwind UNKNOWN; complete pump record retained".into())}}
  // Store the complete bytes/hash/EOF/overflow/errors before any close or
  // semantic check. A refusal never discards the original terminal report.
  if let Some(r)=record.read.as_mut(){if let Err(error)=r.close_checked(){record.join_failure=Some(error.clone());return Err(error)}}record.read.take();
  let report=record.terminal.as_ref().ok_or("stored original terminal report absent")?;
  need(report["eof"]==true&&report["hash_complete"]==true&&report["overflow"]==false&&report["errors"].as_array().is_some_and(Vec::is_empty),&format!("original terminal drain refused: {report}"))?;Ok(report.clone())
 }
}
impl Drop for Pump{fn drop(&mut self){if let Some(record)=self.record.take(){if std::thread::panicking()||record.thread.is_some()||(record.join_attempted&&record.terminal.is_none())||record.join_failure.is_some(){owned::mark_unknown();let _=Box::leak(record);}else{drop(record)}}}}
pub(crate) struct Job{image:String,job:Owned,port:Owned,process:Owned,thread:Owned,input:Owned,out_write:Owned,err_write:Owned,stdout:Option<Pump>,stderr:Option<Pump>,attributes:Vec<usize>,handle_list:Option<Box<[usize;3]>>,job_list:Option<Box<[usize;1]>>,initialized:bool,environment:Vec<u16>,command:Vec<u16>,cwd:Vec<u16>,created:bool,active_zero:bool,pid:u32,start:u64,token:Option<OwnTokenFacts>,events:u64,events_failed:bool,closed:bool,raw_exit:Option<u32>,terminal:Option<Value>}
impl Job{
 pub(crate) fn prepare(image:&str,args:&[String],cwd:&str,env:&BTreeMap<String,String>,prefix:&str)->Result<Self>{owned::known()?;need(size_of::<StartupEx>()==112&&size_of::<ProcessInfo>()==24&&size_of::<Security>()==24,"native Windows x64 ABI structures")?;
  let mut owner=Box::new(Self{image:image.into(),job:Owned::empty(Kind::Job),port:Owned::empty(Kind::CompletionPort),process:Owned::empty(Kind::Process),thread:Owned::empty(Kind::Thread),input:Owned::empty(Kind::NullInput),out_write:Owned::empty(Kind::PipeWrite),err_write:Owned::empty(Kind::PipeWrite),stdout:None,stderr:None,attributes:Vec::new(),handle_list:Some(Box::new([0;3])),job_list:Some(Box::new([0;1])),initialized:false,environment:Vec::new(),command:Vec::new(),cwd:wide(cwd),created:false,active_zero:false,pid:0,start:0,token:None,events:0,events_failed:false,closed:false,raw_exit:None,terminal:None});
  let attempt=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->Result<()>{owner.job.attach(unsafe{CreateJobObjectW(null_mut(),null())})?;owner.port.attach(unsafe{CreateIoCompletionPort(usize::MAX as Handle,null_mut(),0,1)})?;let association=Association{key:1usize as Handle,port:owner.port.raw()?};native(unsafe{SetInformationJobObject(owner.job.raw()?,7,(&association as *const Association).cast(),size_of::<Association>() as u32)}!=0,"original job completion association")?;
   let security=Security{length:size_of::<Security>() as u32,descriptor:null_mut(),inherit:1};let(mut r,mut w)=(null_mut(),null_mut());let mut out_read=Owned::empty(Kind::PipeRead);let good=unsafe{CreatePipe(&mut r,&mut w,&security,65536)}!=0;let ar=out_read.attach(r);let aw=owner.out_write.attach(w);native(good,"original stdout pipe")?;ar?;aw?;native(unsafe{SetHandleInformation(out_read.raw()?,1,0)}!=0,"noninherited stdout read")?;
   let(mut r,mut w)=(null_mut(),null_mut());let mut err_read=Owned::empty(Kind::PipeRead);let good=unsafe{CreatePipe(&mut r,&mut w,&security,65536)}!=0;let ar=err_read.attach(r);let aw=owner.err_write.attach(w);native(good,"original stderr pipe")?;ar?;aw?;native(unsafe{SetHandleInformation(err_read.raw()?,1,0)}!=0,"noninherited stderr read")?;
   owner.input.attach(unsafe{CreateFileW(wide("NUL").as_ptr(),0x80000000,3,&security,3,0,null_mut())})?;
   let mut bytes=0usize;need(unsafe{InitializeProcThreadAttributeList(null_mut(),2,0,&mut bytes)}==0&&unsafe{owned::GetLastError()}==122&&bytes>=16&&bytes<=65536,"bounded original startup attribute list")?;owner.attributes=vec![0usize;bytes.div_ceil(size_of::<usize>())];let list=owner.attributes.as_mut_ptr().cast();native(unsafe{InitializeProcThreadAttributeList(list,2,0,&mut bytes)}!=0,"startup attribute initialization")?;owner.initialized=true;
   **owner.handle_list.as_mut().unwrap()=[owner.input.raw()? as usize,owner.out_write.raw()? as usize,owner.err_write.raw()? as usize];native(unsafe{UpdateProcThreadAttribute(list,0,0x00020002,owner.handle_list.as_mut().unwrap().as_mut_ptr().cast(),size_of::<[Handle;3]>(),null_mut(),null_mut())}!=0,"exact three inherited handles")?;
   **owner.job_list.as_mut().unwrap()=[owner.job.raw()? as usize];native(unsafe{UpdateProcThreadAttribute(list,0,0x0002000d,owner.job_list.as_mut().unwrap().as_mut_ptr().cast(),size_of::<Handle>(),null_mut(),null_mut())}!=0,"original pre-entry job list")?;
   let mut text=quote(image)?;for arg in args{text.push(' ');text.push_str(&quote(arg)?)}owner.command=wide(&text);need(owner.command.len()<32767,"whole command-line bound")?;
   for(k,v)in env{need(!k.is_empty()&&k.len()<=128&&!k.chars().any(|c|c=='\0'||c=='=')&&v.len()<=4096&&!v.contains('\0'),"finite cleared environment grammar")?;owner.environment.extend(format!("{k}={v}\0").encode_utf16())}owner.environment.push(0);need(owner.environment.len()<32767,"whole environment bound")?;
   owner.stdout=Some(Pump::start(out_read,&format!("{prefix}-stdout.bin"))?);owner.stderr=Some(Pump::start(err_read,&format!("{prefix}-stderr.bin"))?);Ok(())}));
  match attempt{Ok(Ok(()))=>Ok(*owner),Ok(Err(error))=>{owned::mark_unknown();let _=Box::leak(owner);Err(format!("original job acquisition refused; complete precreation graph retained: {error}"))},Err(payload)=>{owned::mark_unknown();let _=Box::leak(owner);std::mem::forget(payload);Err("original job precreation unwind UNKNOWN; complete graph retained".into())}}
 }
 pub(crate) fn start_suspended(&mut self,before_resume:impl FnOnce(&Self)->Result<()>)->Result<()> {need(!self.created&&!self.closed,"one original process creation")?;let mut startup=StartupEx{info:unsafe{zeroed()},attributes:self.attributes.as_mut_ptr().cast()};startup.info.cb=size_of::<StartupEx>() as u32;startup.info.flags=0x100;startup.info.input=self.input.raw()?;startup.info.output=self.out_write.raw()?;startup.info.error=self.err_write.raw()?;let mut info:ProcessInfo=unsafe{zeroed()};
  let good=unsafe{CreateProcessW(wide(&self.image).as_ptr(),self.command.as_mut_ptr(),null_mut(),null_mut(),1,0x00080000|0x00000400|0x08000000|4,self.environment.as_mut_ptr().cast(),self.cwd.as_ptr(),&mut startup,&mut info)}!=0;
  if !info.process.is_null(){self.process.attach(info.process)?;self.created=true;self.pid=info.pid}if !info.thread.is_null(){self.thread.attach(info.thread)?}native(good,"original suspended job-list creation")?;need(self.created&&self.pid>0,"actual original creation identity")?;self.observe()?;
  // Failure before resume never promotes unknown state. Caller retains this
  // whole original job and policy; no target thread is resumed on refusal.
  before_resume(self)?;native(unsafe{ResumeThread(self.thread.raw()?)}==1,"exact owned initial suspension resumed once")?;
  self.out_write.close_checked()?;self.err_write.close_checked()?;self.input.close_checked()?;Ok(())
 }
 fn observe(&mut self)->Result<()>{let h=self.process.raw()?;need(unsafe{GetProcessId(h)}==self.pid&&unsafe{WaitForSingleObject(h,0)}==258,"original live created process")?;let(mut b,mut e,mut k,mut u)=unsafe{zeroed::<(FileTime,FileTime,FileTime,FileTime)>()};native(unsafe{GetProcessTimes(h,&mut b,&mut e,&mut k,&mut u)}!=0,"original created process times")?;let start=(b.high as u64)<<32|b.low as u64;need(start>0&&(self.start==0||self.start==start),"original process start invariant")?;self.start=start;let mut text=[0u16;4097];let mut n=text.len() as u32;native(unsafe{QueryFullProcessImageNameW(h,0,text.as_mut_ptr(),&mut n)}!=0&&n>0&&(n as usize)<text.len(),"original process image")?;need(String::from_utf16(&text[..n as usize]).map_err(|_|"original process image UTF16")?==self.image,"created original image differs")?;
  let token=unsafe{own_native_token::observe_selected_peer(h,self.pid,start)}?;if let Some(prior)=&self.token{need(prior==&token,"original child complete primary token changed")?}else{self.token=Some(token)}Ok(())
 }
 pub(crate) fn peer(&self)->Result<(&OwnTokenFacts,Handle)>{need(self.created&&!self.closed,"original created child owner")?;let token=self.token.as_ref().ok_or("original child token absent")?;let raw=self.process.raw()?;need(unsafe{WaitForSingleObject(raw,0)}==258&&unsafe{GetProcessId(raw)}==token.pid,"original peer still live")?;need(unsafe{own_native_token::observe_selected_peer(raw,token.pid,token.process_start_filetime)}?==*token,"actual original child complete token unchanged")?;Ok((token,raw))}
 pub(crate) fn natural_close(&mut self)->Result<Value>{need(self.created,"cannot close uncreated process as campaign")?;let deadline=Instant::now()+Duration::from_secs(600);loop{let mut accounting:Accounting=unsafe{zeroed()};native(unsafe{QueryInformationJobObject(self.job.raw()?,1,(&mut accounting as *mut Accounting).cast(),size_of::<Accounting>() as u32,null_mut())}!=0,"original job accounting")?;if accounting.active==0{self.active_zero=true;break}need(Instant::now()<deadline,"original job natural closure deadline; no kill/reset")?;let(mut code,mut key,mut data)=(0u32,0usize,null_mut());let good=unsafe{GetQueuedCompletionStatus(self.port.raw()?,&mut code,&mut key,&mut data,50)}!=0;if !good{if unsafe{owned::GetLastError()}!=258{self.events_failed=true}}else{self.events+=1;if key!=1||self.events>65536||![4,6,7,8].contains(&code){self.events_failed=true}}}
  need(unsafe{WaitForSingleObject(self.process.raw()?,0)}==0,"original process naturally signalled")?;let mut exit=0u32;native(unsafe{GetExitCodeProcess(self.process.raw()?,&mut exit)}!=0,"original natural exit code")?;self.raw_exit=Some(exit);let stdout=self.stdout.as_mut().ok_or_else(||String::from("original stdout pump absent")).and_then(Pump::join);let stderr=self.stderr.as_mut().ok_or_else(||String::from("original stderr pump absent")).and_then(Pump::join);self.terminal=Some(json!({"raw_exit":self.raw_exit,"natural_active_process_zero":self.active_zero,"actual_process":self.token.as_ref().map(crate::token_json),"image":self.image,"streams":[self.stdout.as_ref().and_then(Pump::terminal),self.stderr.as_ref().and_then(Pump::terminal)],"pump_join_errors":[stdout.as_ref().err(),stderr.as_ref().err()],"job_events":self.events,"job_events_failed":self.events_failed,"job_assignment_before_execution":true,"inherited_handle_count":3,"close_errors":[]}));if stdout.is_err()||stderr.is_err()||self.events_failed{let close=self.close_checked();owned::mark_unknown();return Err(format!("independent original drains stdout={:?}; stderr={:?}; events_failed={}; job close={close:?}; retained terminal={:?}",stdout.as_ref().err(),stderr.as_ref().err(),self.events_failed,self.terminal))}stdout?;stderr?;self.close_checked()?;let result=self.terminal.as_ref().ok_or("stored original terminal job receipt absent")?;need(exit==0,&format!("owned child natural nonzero exit; retained original terminal receipt: {result}"))?;Ok(result.clone())
 }
 fn close_precreation(&mut self)->Result<()>{need(!self.created,"created original graph must naturally close or quarantine")?;let mut errors=Vec::new();for h in [&mut self.out_write,&mut self.err_write,&mut self.input]{if let Err(e)=h.close_checked(){errors.push(e)}}for pump in [&mut self.stdout,&mut self.stderr]{if let Some(p)=pump.as_mut(){if let Err(e)=p.join(){errors.push(e)}}}if let Err(e)=self.close_checked(){errors.push(e)}if !errors.is_empty(){owned::mark_unknown()}need(errors.is_empty(),&format!("independent precreation original closures {errors:?}"))}
 pub(crate) fn close_checked(&mut self)->Result<()>{if self.closed{return Ok(())}need(!self.created||self.active_zero,"original job remains active; custody UNKNOWN")?;need(!self.stdout.as_ref().is_some_and(Pump::pending)&&!self.stderr.as_ref().is_some_and(Pump::pending),"original drains still pending; retain complete job without detach/close")?;self.closed=true;let mut errors=Vec::new();for h in [&mut self.input,&mut self.out_write,&mut self.err_write,&mut self.thread,&mut self.process,&mut self.port,&mut self.job]{if let Err(e)=h.close_checked(){errors.push(e)}}if self.initialized{unsafe{DeleteProcThreadAttributeList(self.attributes.as_mut_ptr().cast())};self.initialized=false}if let Some(report)=self.terminal.as_mut(){report["close_errors"]=json!(errors);}need(errors.is_empty(),&format!("original native job independent closes {errors:?}; retained terminal={:?}",self.terminal))}
}
impl Drop for Job{fn drop(&mut self){if std::thread::panicking()||(self.created&&!self.active_zero)||self.stdout.as_ref().is_some_and(Pump::pending)||self.stderr.as_ref().is_some_and(Pump::pending){owned::mark_unknown();for h in [&mut self.input,&mut self.out_write,&mut self.err_write,&mut self.thread,&mut self.process,&mut self.port,&mut self.job]{h.quarantine()}if let Some(p)=self.stdout.take(){std::mem::forget(p)}if let Some(p)=self.stderr.take(){std::mem::forget(p)}let attrs=std::mem::take(&mut self.attributes);std::mem::forget(attrs);if let Some(handles)=self.handle_list.take(){std::mem::forget(handles)}if let Some(jobs)=self.job_list.take(){std::mem::forget(jobs)}return}let _=self.close_checked();}}
