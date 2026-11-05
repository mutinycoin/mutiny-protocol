//! Actual original OWN process primary-token facts; no launch/role authority.
//! Exact trusted TEST plan comparison belongs to the caller. Parent elevation
//! or a require_escalated tool flag is never a substitute for these facts.
#![cfg(all(windows,target_arch="x86_64"))]
use std::{ffi::c_void,mem::{size_of,zeroed},ptr::{null_mut},
    sync::atomic::{AtomicBool,AtomicPtr,Ordering}};
type Handle=*mut c_void;
type Result<T>=std::result::Result<T,String>;
// Selected-host exact DWORD query; filtering history (class 21) is distinct.
const TOKEN_IS_RESTRICTED:i32=40;
#[repr(C)]#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) struct Luid{pub(super) low:u32,pub(super) high:i32}
#[repr(C)]struct Stats{id:Luid,authentication:Luid,expiration:i64,kind:i32,
    impersonation:i32,charged:u32,available:u32,groups:u32,privileges:u32,modified:Luid}
#[repr(C)]struct SidAndAttributes{sid:Handle,attributes:u32}
#[repr(C)]struct FileTime{low:u32,high:u32}
#[link(name="kernel32")]
unsafe extern "system"{
    fn GetCurrentProcess()->Handle;
    fn GetProcessId(process:Handle)->u32;
    fn GetProcessTimes(process:Handle,created:*mut FileTime,exited:*mut FileTime,
        kernel:*mut FileTime,user:*mut FileTime)->i32;
    fn GetLastError()->u32;
    fn CloseHandle(handle:Handle)->i32;
}
#[link(name="advapi32")]
unsafe extern "system"{
    fn OpenProcessToken(process:Handle,access:u32,token:*mut Handle)->i32;
    fn GetTokenInformation(token:Handle,class:i32,buffer:Handle,length:u32,needed:*mut u32)->i32;
    fn IsValidSid(sid:Handle)->i32;
    fn GetLengthSid(sid:Handle)->u32;
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub(super) struct OwnTokenFacts{
    pub(super) pid:u32,pub(super) process_start_filetime:u64,pub(super) user_sid:Vec<u8>,
    pub(super) token_id:Luid,pub(super) authentication_id:Luid,pub(super) modified_id:Luid,
    pub(super) session:u32,pub(super) elevation_type:u32,pub(super) elevated:bool,
    pub(super) integrity_sid:Vec<u8>,pub(super) restricted:bool,pub(super) app_container:bool,
}
struct OriginalToken{next:usize,handle:usize,pid:u32,start:u64,attempted:bool,
    outcome:Option<bool>,error:u32}
struct TokenOwner{record:Option<Box<OriginalToken>>}
static RETAINED:AtomicPtr<OriginalToken>=AtomicPtr::new(null_mut());
static UNKNOWN:AtomicBool=AtomicBool::new(false);
fn retain(record:Box<OriginalToken>){let raw=Box::into_raw(record);let mut head=RETAINED.load(Ordering::Acquire);
    loop{unsafe{(*raw).next=head as usize;}
        match RETAINED.compare_exchange_weak(head,raw,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>break,Err(now)=>head=now}}}
impl Drop for TokenOwner{fn drop(&mut self){if let Some(record)=self.record.take(){
    if record.handle!=0{UNKNOWN.store(true,Ordering::Release);retain(record);}}}}
fn process_start()->Result<(u32,u64)>{let process=unsafe{GetCurrentProcess()};let pid=unsafe{GetProcessId(process)};
    let(mut created,mut exited,mut kernel,mut user):(FileTime,FileTime,FileTime,FileTime)=unsafe{zeroed()};
    if pid==0||unsafe{GetProcessTimes(process,&mut created,&mut exited,&mut kernel,&mut user)}==0{
        return Err(format!("Own original process identity: {}",unsafe{GetLastError()}));}
    let start=((created.high as u64)<<32)|created.low as u64;
    if start==0{return Err("Own original process start absent".into());}Ok((pid,start))}
struct Buffer{words:Vec<usize>,bytes:usize}
fn information(handle:Handle,class:i32)->Result<Buffer>{
    let mut needed=0u32;let first=unsafe{GetTokenInformation(handle,class,null_mut(),0,&mut needed)};
    let first_error=unsafe{GetLastError()};
    if first!=0||first_error!=122||needed==0||needed>4096{return Err(format!(
        "Own primary-token information bound/probe class={class} first={first} error={first_error} needed={needed}"));}
    let mut words=vec![0usize;(needed as usize).div_ceil(size_of::<usize>())];let allocated=words.len()*size_of::<usize>();
    let returned=unsafe{GetTokenInformation(handle,class,words.as_mut_ptr().cast(),allocated as u32,&mut needed)};
    let error=unsafe{GetLastError()};
    if returned==0||needed==0||needed as usize>allocated{return Err(format!(
        "Own primary-token information class={class} returned={returned} error={error} needed={needed} allocated={allocated}"));}
    Ok(Buffer{words,bytes:needed as usize})}
fn scalar(handle:Handle,class:i32)->Result<u32>{
    let mut value=0u32;let mut needed=0u32;
    // Fixed original four-byte scalar, never a zero-buffer size probe.
    let returned=unsafe{GetTokenInformation(handle,class,(&mut value as *mut u32).cast(),4,&mut needed)};
    let error=unsafe{GetLastError()};
    if returned==0||needed!=4{return Err(format!(
        "Own primary-token scalar class={class} returned={returned} error={error} needed={needed} allocated=4"));}
    Ok(value)}
fn boolean(handle:Handle,class:i32)->Result<bool>{match scalar(handle,class)?{0=>Ok(false),1=>Ok(true),_=>Err("Own token boolean width/value".into())}}
fn bounded_sid(data:&Buffer)->Result<Vec<u8>>{
    if data.bytes<size_of::<SidAndAttributes>(){return Err("Own token SID header bound".into());}
    let sid=unsafe{(*data.words.as_ptr().cast::<SidAndAttributes>()).sid};let base=data.words.as_ptr() as usize;
    let end=base.checked_add(data.bytes).ok_or("Own token SID range overflow")?;let address=sid as usize;
    if address<base||address.checked_add(8).ok_or("Own token SID header overflow")?>end{return Err("Own token SID header outside original buffer".into());}
    let subauthorities=unsafe{*sid.cast::<u8>().add(1)} as usize;
    let length=8usize.checked_add(4usize.checked_mul(subauthorities).ok_or("Own token SID width")?).ok_or("Own token SID width")?;
    if subauthorities>15||length>68||address.checked_add(length).ok_or("Own token SID range")?>end{
        return Err("Own token SID extent outside original buffer".into());}
    if unsafe{IsValidSid(sid)}==0||unsafe{GetLengthSid(sid)} as usize!=length{return Err("Own token SID native validity/extent".into());}
    Ok(unsafe{std::slice::from_raw_parts(sid.cast::<u8>(),length)}.to_vec())}
fn statistics(handle:Handle)->Result<Stats>{let data=information(handle,10)?;
    if data.bytes!=size_of::<Stats>(){return Err("Own TOKEN_STATISTICS exact ABI width".into());}
    Ok(unsafe{std::ptr::read(data.words.as_ptr().cast::<Stats>())})}
fn close(owner:&mut TokenOwner)->Result<()>{let record=owner.record.as_mut().ok_or("Own original token record absent")?;
    if record.attempted{return Err("Own original token release already attempted; no retry".into());}
    record.attempted=true;
    let success=unsafe{CloseHandle(record.handle as Handle)}!=0;
    record.outcome=Some(success);record.error=if success{0}else{unsafe{GetLastError()}};
    if success{owner.record.take();Ok(())}else{UNKNOWN.store(true,Ordering::Release);
        let error=record.error;retain(owner.record.take().unwrap());Err(format!("Own original token release UNKNOWN {error}"))}}
/// Observes this process's actual original kernel object, not a PID reopening,
/// borrowed parent assertion, token handle factory, or inferred privilege level.
/// The successful observation includes a known once-only original token close.
pub(super) fn observe_own()->Result<OwnTokenFacts>{
    if UNKNOWN.load(Ordering::Acquire){return Err("Own token custody UNKNOWN".into());}
    let(pid,start)=process_start()?;
    // Allocate the entire original ownership record before OpenProcessToken.
    let mut owner=TokenOwner{record:Some(Box::new(OriginalToken{next:0,handle:0,pid,start,attempted:false,outcome:None,error:0}))};
    let mut handle=null_mut();let opened=unsafe{OpenProcessToken(GetCurrentProcess(),8,&mut handle)};
    let open_error=if opened==0{unsafe{GetLastError()}}else{0};
    owner.record.as_mut().unwrap().handle=handle as usize;
    owner.record.as_mut().unwrap().error=open_error;
    if opened==0||handle.is_null(){
        if !handle.is_null(){UNKNOWN.store(true,Ordering::Release);retain(owner.record.take().unwrap());}
        return Err(format!("Own original primary-token open refused/ambiguous: {open_error}"));}
    let observation:Result<OwnTokenFacts>=(||{
        let before=statistics(handle)?;if before.kind!=1{return Err("Own primary-token type required".into());}
        let user_sid=bounded_sid(&information(handle,1)?)?;
        let session=scalar(handle,12)?;let elevation_type=scalar(handle,18)?;
        if !(1..=3).contains(&elevation_type){return Err("Own selected elevation type unsupported".into());}
        let elevated=boolean(handle,20)?;let integrity_sid=bounded_sid(&information(handle,25)?)?;
        let restricted=boolean(handle,TOKEN_IS_RESTRICTED)?;let app_container=boolean(handle,29)?;
        let after=statistics(handle)?;
        if before.id!=after.id||before.authentication!=after.authentication||before.modified!=after.modified
            ||after.kind!=1||process_start()!=(Ok((pid,start))){return Err("Own original process/token changed during observation".into());}
        Ok(OwnTokenFacts{pid,process_start_filetime:start,user_sid,token_id:before.id,
            authentication_id:before.authentication,modified_id:before.modified,session,
            elevation_type,elevated,integrity_sid,restricted,app_container})
    })();
    let closed=close(&mut owner);
    match(observation,closed){(Ok(facts),Ok(()))=>Ok(facts),(primary,cleanup)=>Err(format!("Own actual token observation={primary:?}; original once close={cleanup:?}"))}
}

/// # Safety
/// A private RootLaunch peer owner retains this original live process HANDLE
/// throughout. Caller has matched its actual PID/start/image to the independent
/// trusted Root registration before entry. No raw handle from CLI/wire is valid.
/// This returns observed facts only; it cannot select a Root issuer or owner.
pub(super) unsafe fn observe_selected_peer(process:Handle,pid:u32,start:u64)->Result<OwnTokenFacts>{
    if UNKNOWN.load(Ordering::Acquire){return Err("Root peer token custody UNKNOWN".into());}
    let identity=||->Result<(u32,u64)>{let actual=unsafe{GetProcessId(process)};
        let(mut a,mut b,mut c,mut d):(FileTime,FileTime,FileTime,FileTime)=unsafe{zeroed()};
        if actual==0||unsafe{GetProcessTimes(process,&mut a,&mut b,&mut c,&mut d)}==0{return Err("Root retained peer identity".into());}
        Ok((actual,((a.high as u64)<<32)|a.low as u64))};
    if pid==0||start==0||identity()?!=(pid,start){return Err("Root retained peer PID/start".into());}
    let mut owner=TokenOwner{record:Some(Box::new(OriginalToken{next:0,handle:0,pid,start,attempted:false,outcome:None,error:0}))};
    let mut handle=null_mut();let opened=unsafe{OpenProcessToken(process,8,&mut handle)};
    let error=if opened==0{unsafe{GetLastError()}}else{0};owner.record.as_mut().unwrap().handle=handle as usize;
    owner.record.as_mut().unwrap().error=error;
    if opened==0||handle.is_null(){if !handle.is_null(){UNKNOWN.store(true,Ordering::Release);retain(owner.record.take().unwrap());}
        return Err(format!("Root original peer token open refused/ambiguous {error}"));}
    let observed:Result<OwnTokenFacts>=(||{let before=statistics(handle)?;
        if before.kind!=1{return Err("Root selected primary token type".into());}
        let facts=OwnTokenFacts{pid,process_start_filetime:start,user_sid:bounded_sid(&information(handle,1)?)?,
            token_id:before.id,authentication_id:before.authentication,modified_id:before.modified,
            session:scalar(handle,12)?,elevation_type:scalar(handle,18)?,elevated:boolean(handle,20)?,
            integrity_sid:bounded_sid(&information(handle,25)?)?,restricted:boolean(handle,TOKEN_IS_RESTRICTED)?,app_container:boolean(handle,29)?};
        let after=statistics(handle)?;
        if after.kind!=1||before.id!=after.id||before.authentication!=after.authentication||before.modified!=after.modified
            ||!(1..=3).contains(&facts.elevation_type)||identity()?!=(pid,start){return Err("Root retained peer process/token changed".into());}
        Ok(facts)})();
    let closure=close(&mut owner);match(observed,closure){(Ok(v),Ok(()))=>Ok(v),(a,b)=>Err(format!("Root peer token facts={a:?}; original once close={b:?}"))}
}
