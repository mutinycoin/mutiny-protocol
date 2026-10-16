//! Unregistered distinct counter transport: kernel facts and owned I/O only.
//! No Clock role, provider selection, local TPM API, secret or qualification issuer.
//! Installation/canonical permission is supplied by Activation's opaque authority.
#![cfg(windows)]
#![allow(dead_code)]
use crate::hybrid_authenticated_counter_v2::{NvExchange,Request};
use crate::hybrid_installed_counter_windows_v2::{InstalledCounterWindowsAuthority,AuthorizedWindowsCounterPeer};
use std::{ffi::c_void,mem::{size_of,zeroed,ManuallyDrop},ptr::{null,null_mut},
    sync::{Arc,atomic::{AtomicBool,AtomicUsize,AtomicU32,Ordering}}};
type Ptr=*mut c_void;
type Result<T>=std::result::Result<T,String>;
const REQUEST:usize=98;
const PAYLOAD:usize=470;
const RESPONSE:usize=472;
const INFINITE:u32=u32::MAX;
const WIN32_PIPE_PREFIX:[u16;9]=[92,92,46,92,112,105,112,101,92];
const NT_PIPE_PREFIX:[u16;18]=[92,68,101,118,105,99,101,92,78,97,109,101,100,80,105,112,101,92];
#[repr(C)] struct FileTime{low:u32,high:u32}
#[repr(C)] struct Luid{low:u32,high:i32}
#[repr(C)] struct TokenStatistics{token_id:Luid,authentication:Luid,expiration:i64,
    token_type:i32,impersonation:i32,dynamic_charged:u32,dynamic_available:u32,
    groups:u32,privileges:u32,modified:Luid}
#[repr(C)] struct IoStatus{status:usize,information:usize}
#[repr(C)] struct Overlapped{internal:usize,internal_high:usize,offset:u32,offset_high:u32,event:Ptr}
#[repr(C)] struct UnicodeString{length:u16,maximum:u16,buffer:*const u16}
#[repr(C)] struct Acl{revision:u8,reserved:u8,size:u16,count:u16,reserved2:u16}
#[link(name="kernel32")] unsafe extern "system"{
    fn CreateFileW(name:*const u16,access:u32,share:u32,security:Ptr,disposition:u32,flags:u32,template:Ptr)->Ptr;
    fn GetNamedPipeServerProcessId(pipe:Ptr,pid:*mut u32)->i32;
    fn GetNamedPipeInfo(pipe:Ptr,flags:*mut u32,out:*mut u32,input:*mut u32,instances:*mut u32)->i32;
    fn PeekNamedPipe(pipe:Ptr,buffer:Ptr,length:u32,read:*mut u32,available:*mut u32,left:*mut u32)->i32;
    fn GetNamedPipeHandleStateW(pipe:Ptr,state:*mut u32,instances:*mut u32,max:*mut u32,timeout:*mut u32,user:*mut u16,length:u32)->i32;
    fn SetNamedPipeHandleState(pipe:Ptr,state:*const u32,max:*const u32,timeout:*const u32)->i32;
    fn GetCurrentProcess()->Ptr;fn GetCurrentThread()->Ptr;
    fn DuplicateHandle(source_process:Ptr,source:Ptr,target_process:Ptr,target:*mut Ptr,access:u32,inherit:i32,options:u32)->i32;
    fn OpenProcess(access:u32,inherit:i32,pid:u32)->Ptr;fn GetProcessId(process:Ptr)->u32;
    fn GetProcessTimes(process:Ptr,creation:*mut FileTime,exit:*mut FileTime,kernel:*mut FileTime,user:*mut FileTime)->i32;
    fn ProcessIdToSessionId(pid:u32,session:*mut u32)->i32;
    fn WaitForSingleObject(handle:Ptr,millis:u32)->u32;
    fn CreateEventW(attributes:Ptr,manual:i32,initial:i32,name:*const u16)->Ptr;
    fn SetEvent(event:Ptr)->i32;fn ResetEvent(event:Ptr)->i32;
    fn WaitForMultipleObjects(count:u32,handles:*const Ptr,all:i32,millis:u32)->u32;
    fn ReadFile(file:Ptr,buffer:Ptr,length:u32,read:*mut u32,overlapped:*mut Overlapped)->i32;
    fn WriteFile(file:Ptr,buffer:*const c_void,length:u32,written:*mut u32,overlapped:*mut Overlapped)->i32;
    fn CancelIoEx(file:Ptr,overlapped:*mut Overlapped)->i32;
    fn GetOverlappedResult(file:Ptr,overlapped:*mut Overlapped,bytes:*mut u32,wait:i32)->i32;
    fn CloseHandle(handle:Ptr)->i32;fn GetLastError()->u32;
}
#[link(name="advapi32")] unsafe extern "system"{
    fn OpenProcessToken(process:Ptr,access:u32,token:*mut Ptr)->i32;
    fn OpenThreadToken(thread:Ptr,access:u32,as_self:i32,token:*mut Ptr)->i32;
    fn GetTokenInformation(token:Ptr,kind:u32,data:Ptr,length:u32,needed:*mut u32)->i32;
    fn IsValidSid(sid:Ptr)->i32;fn GetLengthSid(sid:Ptr)->u32;
    fn GetSecurityInfo(handle:Ptr,kind:u32,info:u32,owner:*mut Ptr,group:*mut Ptr,acl:*mut *mut Acl,sacl:*mut Ptr,sd:*mut Ptr)->u32;
    fn GetSecurityDescriptorLength(sd:Ptr)->u32;
    fn GetSecurityDescriptorControl(sd:Ptr,control:*mut u16,revision:*mut u32)->i32;
    fn GetAce(acl:*mut Acl,index:u32,ace:*mut Ptr)->i32;
}
#[link(name="kernel32")] unsafe extern "system"{fn LocalFree(allocation:Ptr)->Ptr;}
#[link(name="ntdll")] unsafe extern "system"{
    fn NtQueryInformationFile(file:Ptr,status:*mut IoStatus,data:Ptr,length:u32,kind:u32)->i32;
    fn NtQueryObject(object:Ptr,kind:u32,data:Ptr,length:u32,needed:*mut u32)->i32;
}
fn native_error(what:&str)->String{format!("counter native {what}: {}",unsafe{GetLastError()})}
fn luid(value:&Luid)->u64{u64::from(value.low)|((value.high as u32 as u64)<<32)}
#[derive(Clone,Copy,PartialEq,Eq)]
struct PeerFacts{pid:u32,creation:u64,session:u32,authentication:u64,token_id:u64,sid:[u8;68],sid_length:u8}
struct OriginalPipeIdentity;
#[derive(Clone,Copy,PartialEq,Eq)]
pub(crate) struct KernelPipeAceObservation{kind:u8,flags:u8,mask:u32,sid:[u8;68],sid_length:u8}
impl KernelPipeAceObservation{
    pub(crate) fn kind(&self)->u8{self.kind}pub(crate) fn flags(&self)->u8{self.flags}
    pub(crate) fn mask(&self)->u32{self.mask}
    pub(crate) fn sid(&self)->&[u8]{&self.sid[..self.sid_length as usize]}
}
#[derive(Clone,Copy,PartialEq,Eq)]
pub(crate) struct KernelPipeSecurityObservation{owner:[u8;68],owner_length:u8,control:u16,
    aces:[KernelPipeAceObservation;64],ace_count:u8}
impl KernelPipeSecurityObservation{
    fn empty()->Self{Self{owner:[0;68],owner_length:0,control:0,aces:[KernelPipeAceObservation{
        kind:0,flags:0,mask:0,sid:[0;68],sid_length:0};64],ace_count:0}}
    pub(crate) fn owner_sid(&self)->&[u8]{&self.owner[..self.owner_length as usize]}
    pub(crate) fn control(&self)->u16{self.control}
    pub(crate) fn aces(&self)->&[KernelPipeAceObservation]{&self.aces[..self.ace_count as usize]}
}
/// This is a process-local identity of the retained ORIGINAL holder, not a
/// persistent FileID, peer-code proof, provider permission or raw HANDLE.
pub(crate) struct KernelPipePeerBinding{original:Arc<OriginalPipeIdentity>}
pub(crate) struct KernelPipePeerObservation{facts:PeerFacts,security:KernelPipeSecurityObservation,original:Arc<OriginalPipeIdentity>}
impl KernelPipePeerObservation{
    pub(crate) fn process_id(&self)->u32{self.facts.pid}
    pub(crate) fn creation_time(&self)->u64{self.facts.creation}
    pub(crate) fn session_id(&self)->u32{self.facts.session}
    pub(crate) fn authentication_luid(&self)->u64{self.facts.authentication}
    pub(crate) fn token_id(&self)->u64{self.facts.token_id}
    pub(crate) fn user_sid(&self)->&[u8]{&self.facts.sid[..self.facts.sid_length as usize]}
    pub(crate) fn pipe_security(&self)->&KernelPipeSecurityObservation{&self.security}
    pub(crate) fn binding_for_installed_issuer(&self)->KernelPipePeerBinding{
        KernelPipePeerBinding{original:self.original.clone()}
    }
}
impl KernelPipePeerBinding{
    pub(crate) fn matches(&self,observed:&KernelPipePeerObservation)->bool{Arc::ptr_eq(&self.original,&observed.original)}
}
struct StopState{event:AtomicUsize,stopped:AtomicBool,signal_error:AtomicU32,close_attempted:AtomicBool,close_error:AtomicU32}
/// Signal-only controller. It cannot issue permission or a failed-operation result.
pub(crate) struct WindowsCounterStop{state:ManuallyDrop<Box<StopState>>}
impl WindowsCounterStop{
    pub(crate) fn prepare()->Result<Arc<Self>>{
        // Both custody allocations precede the native event and all pipe work.
        let stop=Arc::new(Self{state:ManuallyDrop::new(Box::new(StopState{event:AtomicUsize::new(0),
            stopped:AtomicBool::new(false),signal_error:AtomicU32::new(0),close_attempted:AtomicBool::new(false),close_error:AtomicU32::new(0)}))});
        let event=unsafe{CreateEventW(null_mut(),1,0,null())};
        if event.is_null(){return Err(native_error("stop creation"));}
        stop.state.event.store(event as usize,Ordering::SeqCst);Ok(stop)
    }
    pub(crate) fn signal(&self)->Result<()>{
        self.state.stopped.store(true,Ordering::SeqCst);
        let event=self.state.event.load(Ordering::SeqCst);
        if event==0||self.state.close_attempted.load(Ordering::SeqCst){return Err("counter stop event unavailable".into());}
        if unsafe{SetEvent(event as Ptr)}==0{let error=unsafe{GetLastError()};
            self.state.signal_error.store(error,Ordering::SeqCst);return Err(format!("counter stop signal unknown {error}"));}Ok(())
    }
    fn stopped(&self)->bool{self.state.stopped.load(Ordering::SeqCst)||self.state.signal_error.load(Ordering::SeqCst)!=0}
    fn event(&self)->Ptr{self.state.event.load(Ordering::SeqCst) as Ptr}
    /// After the original worker has naturally returned and the connection
    /// releases its Arc. Shared/failed close custody is returned without retry.
    pub(crate) fn close_after_join(self:Arc<Self>)->std::result::Result<(),WindowsCounterStopClose>{
        let owned=Arc::try_unwrap(self).map_err(WindowsCounterStopClose::Shared)?;
        if owned.state.signal_error.load(Ordering::SeqCst)!=0||owned.state.close_attempted.swap(true,Ordering::SeqCst){
            return Err(WindowsCounterStopClose::Retained(ManuallyDrop::new(owned)));}
        let raw=owned.state.event.load(Ordering::SeqCst);
        if raw==0||unsafe{CloseHandle(raw as Ptr)}==0{
            owned.state.close_error.store(if raw==0{0}else{unsafe{GetLastError()}},Ordering::SeqCst);
            return Err(WindowsCounterStopClose::Retained(ManuallyDrop::new(owned)));}
        owned.state.event.store(0,Ordering::SeqCst);
        let allocation=ManuallyDrop::into_inner(owned.state);drop(allocation);Ok(())
    }
}
pub(crate) enum WindowsCounterStopClose{Shared(Arc<WindowsCounterStop>),Retained(ManuallyDrop<WindowsCounterStop>)}
/// Fixed original-attempt observations. Undefined failed-completion byte
/// outputs are never promoted to a count; the status/error stays explicit.
struct IoReceipt{
    write:Option<bool>,reset_attempted:bool,reset_ok:Option<bool>,reset_error:Option<u32>,
    start_attempted:bool,start_ok:Option<bool>,start_error:Option<u32>,
    wake:Option<u32>,wake_error:Option<u32>,cancel_attempted:bool,cancel_ok:Option<bool>,cancel_error:Option<u32>,
    completion_attempted:bool,completion_wait:Option<bool>,completion_ok:Option<bool>,completion_error:Option<u32>,completion_bytes:Option<u32>,
}
impl IoReceipt{fn empty()->Self{Self{write:None,reset_attempted:false,reset_ok:None,reset_error:None,
    start_attempted:false,start_ok:None,start_error:None,wake:None,wake_error:None,
    cancel_attempted:false,cancel_ok:None,cancel_error:None,completion_attempted:false,completion_wait:None,
    completion_ok:None,completion_error:None,completion_bytes:None}}}
struct IoCell<const N:usize>{overlapped:Overlapped,buffer:[u8;N],active:bool,event_close_attempted:bool,receipt:IoReceipt}
impl<const N:usize> IoCell<N>{
    fn allocated()->Self{Self{overlapped:unsafe{zeroed()},buffer:[0;N],active:false,event_close_attempted:false,receipt:IoReceipt::empty()}}
    fn create_event(&mut self)->Result<()>{
        self.overlapped.event=unsafe{CreateEventW(null_mut(),1,0,null())};
        if self.overlapped.event.is_null(){Err(native_error("I/O event creation"))}else{Ok(())}
    }
    fn run(&mut self,pipe:Ptr,write:bool,stop:&WindowsCounterStop)->Result<()>{
        if self.active||self.event_close_attempted||self.overlapped.event.is_null()||stop.stopped(){
            return Err("counter I/O state unavailable".into());}
        self.receipt=IoReceipt::empty();self.receipt.write=Some(write);self.receipt.reset_attempted=true;
        let reset=unsafe{ResetEvent(self.overlapped.event)};self.receipt.reset_ok=Some(reset!=0);
        if reset==0{let error=unsafe{GetLastError()};self.receipt.reset_error=Some(error);
            return Err(format!("counter I/O reset {error}"));}
        let event=self.overlapped.event;self.overlapped=unsafe{zeroed()};self.overlapped.event=event;
        self.active=true; // Before effect: abandoned memory remains whole-owned.
        self.receipt.start_attempted=true;
        let result=if write{unsafe{WriteFile(pipe,self.buffer.as_ptr().cast(),N as u32,null_mut(),&mut self.overlapped)}}
            else{unsafe{ReadFile(pipe,self.buffer.as_mut_ptr().cast(),N as u32,null_mut(),&mut self.overlapped)}};
        self.receipt.start_ok=Some(result!=0);
        if result==0{let error=unsafe{GetLastError()};self.receipt.start_error=Some(error);if error!=997{self.active=false;
            return Err(format!("counter native I/O completed in error {error}"));}}
        let handles=[self.overlapped.event,stop.event()];
        let wake=unsafe{WaitForMultipleObjects(2,handles.as_ptr(),0,INFINITE)};
        self.receipt.wake=Some(wake);
        if wake==u32::MAX{self.receipt.wake_error=Some(unsafe{GetLastError()});}
        if wake!=0||stop.stopped(){
            self.receipt.cancel_attempted=true;
            let cancelled=unsafe{CancelIoEx(pipe,&mut self.overlapped)};
            let cancel_error=if cancelled==0{unsafe{GetLastError()}}else{0};
            self.receipt.cancel_ok=Some(cancelled!=0);
            if cancelled==0{self.receipt.cancel_error=Some(cancel_error);}
            self.receipt.completion_attempted=true;self.receipt.completion_wait=Some(true);
            let mut count=0;let completed=unsafe{GetOverlappedResult(pipe,&mut self.overlapped,&mut count,1)};
            let error=if completed==0{unsafe{GetLastError()}}else{0};
            self.receipt.completion_ok=Some(completed!=0);
            if completed==0{self.receipt.completion_error=Some(error);}else{self.receipt.completion_bytes=Some(count);}
            if completed!=0||error==995{self.active=false;}
            // Every client cancellation is UNKNOWN even after original kernel
            // settlement. It never asserts entitlement non-consumption.
            return Err(format!("counter cancelled/unknown wake={wake} cancel={cancel_error} completion={error}"));
        }
        self.receipt.completion_attempted=true;self.receipt.completion_wait=Some(false);
        let mut count=0;let completed=unsafe{GetOverlappedResult(pipe,&mut self.overlapped,&mut count,0)};
        self.receipt.completion_ok=Some(completed!=0);
        if completed==0{let error=unsafe{GetLastError()};self.receipt.completion_error=Some(error);if error!=996{self.active=false;}
            return Err(format!("counter completion refused {error}"));}
        self.receipt.completion_bytes=Some(count);
        self.active=false;
        if count as usize!=N{return Err("counter exact single-message size refused".into());}Ok(())
    }
}
#[derive(Clone,Copy)]
struct UnknownNativeClose{kind:u8,raw:usize,error:u32,pid:u32,creation:u64}
/// Each field becomes Some only after that exact original native query returns
/// a bounded usable observation. This slot exists before token startup/close;
/// failed construction/close never discards the facts already learned.
struct TemporaryTokenObservation{
    pipe_pid:Option<u32>,process_creation:Option<u64>,token_raw:usize,
    sid:Option<([u8;68],u8)>,token_id:Option<u64>,authentication:Option<u64>,
    token_type:Option<i32>,token_session:Option<u32>,process_session:Option<u32>,
    query_stage:u8,query_result:Option<bool>,query_native_error:Option<u32>,
    close_attempted:bool,closed:bool,close_error:Option<u32>,
}
impl TemporaryTokenObservation{fn empty()->Self{Self{pipe_pid:None,process_creation:None,token_raw:0,
    sid:None,token_id:None,authentication:None,token_type:None,token_session:None,process_session:None,
    query_stage:0,query_result:None,query_native_error:None,
    close_attempted:false,closed:false,close_error:None}}}
struct SecurityQueryObservation{
    query_return:Option<u32>,allocation:usize,descriptor_length:Option<usize>,control:Option<u16>,
    expected_aces:Option<usize>,partial:KernelPipeSecurityObservation,snapshot_complete:bool,
    parse_result:Option<bool>,native_parse_error:Option<u32>,release_attempted:bool,
    released:bool,release_error:Option<u32>,
}
impl SecurityQueryObservation{fn empty()->Self{Self{query_return:None,allocation:0,descriptor_length:None,control:None,
    expected_aces:None,partial:KernelPipeSecurityObservation::empty(),snapshot_complete:false,parse_result:None,
    native_parse_error:None,release_attempted:false,released:false,release_error:None}}}
struct Core{
    pipe:usize,process:usize,mode_handle:usize,token:usize,token_close_attempted:bool,security_allocation:usize,security_close_attempted:bool,
    temporary_token:TemporaryTokenObservation,
    security_query:SecurityQueryObservation,
    name:[u16;257],name_length:usize,observed:KernelPipePeerObservation,
    stop:Arc<WindowsCounterStop>,write:Box<IoCell<REQUEST>>,read:Box<IoCell<RESPONSE>>,
    permission:Option<ManuallyDrop<AuthorizedWindowsCounterPeer>>,
    pending:Option<[u8;REQUEST]>,frozen:bool,close_attempted:bool,
    close_errors:[Option<UnknownNativeClose>;5],
}
/// Abandonment/unwind retains the complete preallocated kernel/I/O/selection
/// owner. No raw number is exposed or retried, including post-close uncertainty.
struct Custody{core:Option<Box<Core>>}
impl Drop for Custody{fn drop(&mut self){if let Some(mut core)=self.core.take(){core.frozen=true;
    let _=core.stop.signal();let _=Box::into_raw(core);}}}
pub(crate) struct PreparedWindowsCounterConnection{custody:Custody}
pub(crate) struct WindowsCounterNativeTransport{custody:Custody}
pub(crate) struct WindowsCounterTransportFailure{description:String,retained:ManuallyDrop<Custody>}
impl WindowsCounterTransportFailure{pub(crate) fn description(&self)->&str{&self.description}}
impl Core{
    fn capture_security(&mut self)->Result<KernelPipeSecurityObservation>{
        if self.security_allocation!=0{return Err("counter previous security allocation unresolved".into());}
        self.security_query=SecurityQueryObservation::empty();
        let(mut owner,mut acl,mut descriptor)=(null_mut(),null_mut(),null_mut());
        let code=unsafe{GetSecurityInfo(self.pipe as Ptr,6,1|4,&mut owner,null_mut(),&mut acl,null_mut(),&mut descriptor)};
        self.security_allocation=descriptor as usize;self.security_close_attempted=false;
        self.security_query.query_return=Some(code);self.security_query.allocation=descriptor as usize;
        if code!=0||descriptor.is_null(){return Err(format!("counter original pipe security unavailable {code}"));}
        let result=(||{
            let length=unsafe{GetSecurityDescriptorLength(descriptor)} as usize;
            self.security_query.descriptor_length=Some(length);
            if length==0||length>8192{return Err("counter pipe security allocation bound".into());}
            let start=descriptor as usize;let end=start.checked_add(length).ok_or("counter descriptor overflow")?;
            let sid_copy=|sid:Ptr|->Result<([u8;68],u8)>{
                let address=sid as usize;
                if address<start||address.checked_add(8).ok_or("counter security SID header")?>end{
                    return Err("counter security SID header membership".into());}
                let length=8usize.checked_add(4usize.checked_mul(unsafe{*((address+1) as *const u8)} as usize)
                    .ok_or("counter security SID length")?).ok_or("counter security SID length")?;
                if length>68||address.checked_add(length).ok_or("counter security SID body")?>end
                    ||unsafe{IsValidSid(sid)}==0||unsafe{GetLengthSid(sid)} as usize!=length{
                    return Err("counter security SID body membership".into());}
                let mut bytes=[0;68];bytes[..length].copy_from_slice(unsafe{std::slice::from_raw_parts(sid.cast::<u8>(),length)});
                Ok((bytes,length as u8))
            };
            let mut security=KernelPipeSecurityObservation::empty();let(mut control,mut revision)=(0u16,0u32);
            if unsafe{GetSecurityDescriptorControl(descriptor,&mut control,&mut revision)}==0{
                self.security_query.native_parse_error=Some(unsafe{GetLastError()});
                return Err("counter pipe missing self-relative DACL/control".into());}
            self.security_query.control=Some(control);
            if control&4==0||control&0x8000==0||acl.is_null(){return Err("counter pipe missing self-relative DACL/control".into());}
            let acl_address=acl as usize;
            if acl_address<start||acl_address.checked_add(size_of::<Acl>()).ok_or("counter ACL header")?>end{
                return Err("counter ACL header membership".into());}
            let acl_size=unsafe{(*acl).size} as usize;let count=unsafe{(*acl).count} as usize;
            if acl_size<size_of::<Acl>()||acl_size>4096||count>64||acl_address.checked_add(acl_size).ok_or("counter ACL body")?>end{
                return Err("counter bounded ACL roster refused".into());}
            self.security_query.expected_aces=Some(count);
            (security.owner,security.owner_length)=sid_copy(owner)?;security.control=control;security.ace_count=count as u8;
            self.security_query.partial.owner=security.owner;self.security_query.partial.owner_length=security.owner_length;
            self.security_query.partial.control=control;
            for index in 0..count{
                let mut raw=null_mut();if unsafe{GetAce(acl,index as u32,&mut raw)}==0{
                    let error=unsafe{GetLastError()};self.security_query.native_parse_error=Some(error);
                    return Err(format!("counter ACE query {error}"));}
                let address=raw as usize;let acl_end=acl_address+acl_size;
                if address<acl_address+size_of::<Acl>()||address.checked_add(8).ok_or("counter ACE header")?>acl_end{
                    return Err("counter ACE header membership".into());}
                let bytes=unsafe{std::slice::from_raw_parts(raw.cast::<u8>(),8)};
                let size=u16::from_le_bytes([bytes[2],bytes[3]]) as usize;
                if bytes[0]>1||size<16||address.checked_add(size).ok_or("counter ACE body")?>acl_end{
                    return Err("counter unsupported/bounded ACE refused".into());}
                let(sid,sid_length)=sid_copy((address+8) as Ptr)?;
                if usize::from(sid_length)>size-8{return Err("counter ACE SID membership".into());}
                security.aces[index]=KernelPipeAceObservation{kind:bytes[0],flags:bytes[1],
                    mask:u32::from_le_bytes(bytes[4..8].try_into().map_err(|_|"counter ACE mask")?),sid,sid_length};
                self.security_query.partial.aces[index]=security.aces[index];self.security_query.partial.ace_count=(index+1) as u8;
            }Ok(security)
        })();
        self.security_query.parse_result=Some(result.is_ok());
        if let Ok(snapshot)=&result{self.security_query.partial=*snapshot;self.security_query.snapshot_complete=true;}
        self.security_close_attempted=true;
        self.security_query.release_attempted=true;
        if !unsafe{LocalFree(descriptor)}.is_null(){let error=unsafe{GetLastError()};self.security_query.release_error=Some(error);
            return Err(format!("counter original security release unknown {error}"));}
        self.security_query.released=true;
        self.security_allocation=0;result
    }
    fn no_impersonation(&mut self)->Result<()>{
        if self.token!=0{return Err("counter previous token custody unresolved".into());}
        let mut token=null_mut();let result=unsafe{OpenThreadToken(GetCurrentThread(),8,1,&mut token)};
        if result!=0{self.token=token as usize;return Err("counter private worker impersonating".into());}
        if unsafe{GetLastError()}!=1008{return Err(native_error("thread token query"));}Ok(())
    }
    fn endpoint(&self)->Result<()>{
        let mut data=[0usize;512];let capacity=data.len()*size_of::<usize>();let mut needed=0;
        if unsafe{NtQueryObject(self.pipe as Ptr,1,data.as_mut_ptr().cast(),capacity as u32,&mut needed)}<0
            || needed as usize>capacity||(needed as usize)<size_of::<UnicodeString>(){
            return Err("counter original pipe object name unavailable".into());}
        let value=unsafe{&*(data.as_ptr() as *const UnicodeString)};
        let start=data.as_ptr() as usize;let end=start.checked_add(needed as usize).ok_or("counter name bounds")?;
        let address=value.buffer as usize;let bytes=value.length as usize;
        if value.length>value.maximum||bytes%2!=0||bytes>1024||address<start
            ||address.checked_add(bytes).ok_or("counter name pointer")?>end||address%2!=0{
            return Err("counter original pipe name bounds refused".into());}
        let raw=unsafe{std::slice::from_raw_parts(value.buffer,bytes/2)};
        // The NT object spelling corresponds exactly to the selected Win32
        // local pipe name. No pathname is reopened as identity evidence.
        if !raw.starts_with(&NT_PIPE_PREFIX)||raw[NT_PIPE_PREFIX.len()..]!=self.name[9..self.name_length]{
            return Err("counter original selected pipe name differs".into());}
        let mut flags=0;let mut ios=unsafe{zeroed::<IoStatus>()};let mut mode=0u32;
        if unsafe{GetNamedPipeInfo(self.pipe as Ptr,&mut flags,null_mut(),null_mut(),null_mut())}==0||flags&5!=4
            ||unsafe{NtQueryInformationFile(self.pipe as Ptr,&mut ios,(&mut mode as *mut u32).cast(),4,16)}<0
            ||ios.information!=4||mode&0x30!=0{return Err("counter existing client message/overlapped pipe required".into());}Ok(())
    }
    fn capture_facts(&mut self)->Result<PeerFacts>{
        self.no_impersonation()?;
        // The previous slot may be superseded only once its token obligation
        // is known closed (self.token==0); unresolved custody refuses above.
        self.temporary_token=TemporaryTokenObservation::empty();
        let mut pid=0;if unsafe{GetNamedPipeServerProcessId(self.pipe as Ptr,&mut pid)}==0||pid==0{
            return Err(native_error("original server process query"));}
        self.temporary_token.pipe_pid=Some(pid);
        if self.process==0{self.process=unsafe{OpenProcess(0x1000|0x100000,0,pid)} as usize;
            if self.process==0{return Err(native_error("original limited peer process open"));}}
        if unsafe{GetProcessId(self.process as Ptr)}!=pid||unsafe{WaitForSingleObject(self.process as Ptr,0)}!=258{
            return Err("counter original peer process not live".into());}
        let(mut c,mut e,mut k,mut u)=unsafe{(zeroed::<FileTime>(),zeroed::<FileTime>(),zeroed::<FileTime>(),zeroed::<FileTime>())};
        if unsafe{GetProcessTimes(self.process as Ptr,&mut c,&mut e,&mut k,&mut u)}==0{return Err(native_error("peer creation query"));}
        let creation=(u64::from(c.high)<<32)|u64::from(c.low);if creation==0{return Err("counter peer creation unavailable".into());}
        self.temporary_token.process_creation=Some(creation);
        let mut token=null_mut();if unsafe{OpenProcessToken(self.process as Ptr,8,&mut token)}==0{return Err(native_error("peer token open"));}
        self.token=token as usize;self.token_close_attempted=false;
        self.temporary_token.token_raw=token as usize;
        let facts=(||{
            let mut data=[0usize;512];let mut needed=0;let capacity=data.len()*size_of::<usize>();
            self.temporary_token.query_stage=1;
            if unsafe{GetTokenInformation(token,1,data.as_mut_ptr().cast(),capacity as u32,&mut needed)}==0{
                let error=unsafe{GetLastError()};self.temporary_token.query_native_error=Some(error);
                return Err(format!("counter peer SID query {error}"));}
            if needed as usize>capacity||(needed as usize)<size_of::<Ptr>(){return Err("counter peer SID query bound".into());}
            let sid=unsafe{*(data.as_ptr() as *const Ptr)};let start=data.as_ptr() as usize;
            let end=start.checked_add(needed as usize).ok_or("counter SID allocation bound")?;let address=sid as usize;
            if address<start||address.checked_add(8).ok_or("counter SID header overflow")?>end{return Err("counter SID header refused".into());}
            let length=8usize.checked_add(4usize.checked_mul(unsafe{*((address+1) as *const u8)} as usize)
                .ok_or("counter SID length")?).ok_or("counter SID length")?;
            if length>68||address.checked_add(length).ok_or("counter SID body overflow")?>end
                ||unsafe{IsValidSid(sid)}==0||unsafe{GetLengthSid(sid)} as usize!=length{return Err("counter SID body refused".into());}
            let mut bytes=[0u8;68];bytes[..length].copy_from_slice(unsafe{std::slice::from_raw_parts(sid.cast::<u8>(),length)});
            self.temporary_token.sid=Some((bytes,length as u8));
            let mut statistics=unsafe{zeroed::<TokenStatistics>()};let mut used=0;
            self.temporary_token.query_stage=2;
            if unsafe{GetTokenInformation(token,10,(&mut statistics as *mut TokenStatistics).cast(),size_of::<TokenStatistics>() as u32,&mut used)}==0{
                self.temporary_token.query_native_error=Some(unsafe{GetLastError()});
                return Err("counter primary peer token statistics refused".into());}
            if used as usize!=size_of::<TokenStatistics>(){return Err("counter primary peer token statistics refused".into());}
            self.temporary_token.token_id=Some(luid(&statistics.token_id));
            self.temporary_token.authentication=Some(luid(&statistics.authentication));
            self.temporary_token.token_type=Some(statistics.token_type);
            if statistics.token_type!=1{return Err("counter primary peer token statistics refused".into());}
            let mut session=0u32;
            self.temporary_token.query_stage=3;
            if unsafe{GetTokenInformation(token,12,(&mut session as *mut u32).cast(),4,&mut used)}==0{
                self.temporary_token.query_native_error=Some(unsafe{GetLastError()});
                return Err("counter token session refused".into());}
            if used!=4{return Err("counter token session refused".into());}
            self.temporary_token.token_session=Some(session);
            let mut process_session=0;
            self.temporary_token.query_stage=4;
            if unsafe{ProcessIdToSessionId(pid,&mut process_session)}==0{
                self.temporary_token.query_native_error=Some(unsafe{GetLastError()});
                return Err("counter original process/token session differs".into());}
            self.temporary_token.process_session=Some(process_session);
            if session!=process_session{return Err("counter original process/token session differs".into());}
            Ok(PeerFacts{pid,creation,session,authentication:luid(&statistics.authentication),token_id:luid(&statistics.token_id),
                sid:bytes,sid_length:length as u8})
        })();
        self.temporary_token.query_result=Some(facts.is_ok());
        // Original temporary token has one observed close obligation. Any
        // failure keeps its raw identity plus the entire Core; no Drop retry.
        self.token_close_attempted=true;
        self.temporary_token.close_attempted=true;
        if unsafe{CloseHandle(token)}==0{let error=unsafe{GetLastError()};
            self.temporary_token.close_error=Some(error);
            return Err(format!("counter peer token close unknown {error}"));}
        self.temporary_token.closed=true;
        self.token=0;facts
    }
    fn current_peer(&mut self)->Result<()>{
        self.endpoint()?;let facts=self.capture_facts()?;
        if facts!=self.observed.facts{return Err("counter original peer incarnation/token changed".into());}
        if self.capture_security()?!=self.observed.security{return Err("counter original pipe security changed".into());}
        self.endpoint()?;Ok(())
    }
    fn current_authorized(&mut self)->Result<()>{
        if self.frozen{return Err("counter current connection frozen".into());}self.current_selected()
    }
    fn current_selected(&mut self)->Result<()>{
        if self.close_attempted||self.stop.stopped(){return Err("counter current connection unavailable".into());}
        self.current_identity_and_permission()
    }
    fn current_identity_and_permission(&mut self)->Result<()>{
        self.current_peer()?;
        let permission=self.permission.as_mut().ok_or("counter installed peer permission absent")?;
        if !permission.binding().matches(&self.observed){return Err("counter peer permit original holder differs".into());}
        permission.recheck_original(&self.observed)?;
        self.current_peer()?;Ok(())
    }
    fn empty_incoming(&self)->Result<()>{
        let(mut available,mut left)=(0u32,0u32);
        if unsafe{PeekNamedPipe(self.pipe as Ptr,null_mut(),0,null_mut(),&mut available,&mut left)}==0{
            return Err(native_error("counter live idle pipe probe"));}
        if available!=0||left!=0{return Err("counter unexpected queued response refuses current connection".into());}Ok(())
    }
}
impl PreparedWindowsCounterConnection{
    /// Endpoint comes only from the distinct retained installed declaration.
    /// This constructor issues observations only and performs NO framed I/O.
    pub(crate) fn connect_existing(authority:&InstalledCounterWindowsAuthority,stop:Arc<WindowsCounterStop>)
        ->std::result::Result<Self,WindowsCounterTransportFailure>{
        let original=Arc::new(OriginalPipeIdentity);
        let placeholder=PeerFacts{pid:0,creation:0,session:0,authentication:0,token_id:0,sid:[0;68],sid_length:0};
        let mut custody=Custody{core:Some(Box::new(Core{pipe:0,process:0,mode_handle:0,token:0,token_close_attempted:false,security_allocation:0,security_close_attempted:false,
            temporary_token:TemporaryTokenObservation::empty(),
            security_query:SecurityQueryObservation::empty(),
            name:[0;257],name_length:0,observed:KernelPipePeerObservation{facts:placeholder,security:KernelPipeSecurityObservation::empty(),original},stop,
            write:Box::new(IoCell::allocated()),read:Box::new(IoCell::allocated()),permission:None,
            pending:None,frozen:false,close_attempted:false,close_errors:[None;5]}))};
        let result=(||{
            let core=custody.core.as_mut().ok_or("counter allocated custody absent")?;
            core.no_impersonation()?;
            let name=authority.endpoint_utf16();
            if name.len()>256||name.len()<=WIN32_PIPE_PREFIX.len()||!name.starts_with(&WIN32_PIPE_PREFIX)||name.contains(&0)||core.stop.stopped(){
                return Err("counter selected local endpoint spelling/bound refused".into());}
            core.name[..name.len()].copy_from_slice(name);core.name_length=name.len();
            core.write.create_event()?;core.read.create_event()?;
            // Individual rights exclude CREATE_PIPE_INSTANCE, DELETE and DAC/
            // owner mutation. WRITE_ATTRIBUTES is only for this original client
            // handle's message read mode, after installed permission is bound.
            let pipe=unsafe{CreateFileW(core.name.as_ptr(),0x12018b,0,null_mut(),3,0x40110000,null_mut())};
            if pipe==(-1isize) as Ptr{return Err(native_error("existing selected pipe connect"));}
            core.pipe=pipe as usize;core.endpoint()?;
            let facts=core.capture_facts()?;let security=core.capture_security()?;
            core.observed.facts=facts;core.observed.security=security;core.current_peer()?;Ok(())
        })();
        match result{Ok(())=>Ok(Self{custody}),Err(description)=>Err(WindowsCounterTransportFailure{description,retained:ManuallyDrop::new(custody)})}
    }
    pub(crate) fn observation(&self)->&KernelPipePeerObservation{&self.custody.core.as_ref().expect("owned preparation").observed}
    /// Consumes the NONCLONE separate permission before mode changes or I/O.
    pub(crate) fn authorize(mut self,permission:AuthorizedWindowsCounterPeer)
        ->std::result::Result<WindowsCounterNativeTransport,WindowsCounterTransportFailure>{
        let core=self.custody.core.as_mut().expect("owned preparation");core.permission=Some(ManuallyDrop::new(permission));
        let result=(||{core.current_authorized()?;
            // Reduced SAME-object client view: READ plus WRITE_ATTRIBUTES only;
            // no WRITE_DATA/CREATE_PIPE_INSTANCE/DELETE/DAC/owner authority.
            let process=unsafe{GetCurrentProcess()};let mut duplicate=null_mut();
            if unsafe{DuplicateHandle(process,core.pipe as Ptr,process,&mut duplicate,0x120189,0,0)}==0{
                return Err(native_error("original readonly mode view"));}
            core.mode_handle=duplicate as usize;
            let mode=2u32;if unsafe{SetNamedPipeHandleState(duplicate,&mode,null(),null())}==0{
                return Err(native_error("original permitted message mode"));}
            let mut observed=0;if unsafe{GetNamedPipeHandleStateW(core.pipe as Ptr,&mut observed,null_mut(),null_mut(),null_mut(),null_mut(),0)}==0
                ||observed&2==0{return Err("counter original message read mode unavailable".into());}
            core.current_authorized()
        })();
        match result{Ok(())=>{let custody=Custody{core:self.custody.core.take()};Ok(WindowsCounterNativeTransport{custody})},
            Err(description)=>{core.frozen=true;let custody=Custody{core:self.custody.core.take()};
                Err(WindowsCounterTransportFailure{description,retained:ManuallyDrop::new(custody)})}}
    }
}
impl NvExchange for WindowsCounterNativeTransport{
    fn exchange(&mut self,request:&Request,response:&mut[u8;PAYLOAD])->Result<usize>{
        let core=self.custody.core.as_mut().ok_or("counter transport custody absent")?;
        let result=(||{
            if core.frozen{return Err("counter transport frozen".into());}
            core.frozen=true; // BEFORE current/native work; unwind stays frozen.
            core.current_selected()?;core.empty_incoming()?;
            if core.pending.is_some()||request.context()!=core.permission.as_ref().ok_or("counter permission absent")?.context(){
                return Err("counter pending/context conflict refused".into());}
            let frame=request.encode_native();core.pending=Some(frame);core.frozen=true;
            // Same original permission/current peer bracket immediately before
            // effects. No automatic request retry follows any unknown outcome.
            let permission=core.permission.as_mut().ok_or("counter permission absent")?;
            permission.recheck_original(&core.observed)?;core.current_peer()?;
            core.write.buffer=frame;core.write.run(core.pipe as Ptr,true,&core.stop)?;
            core.current_peer()?;core.permission.as_mut().ok_or("counter permission absent")?.recheck_original(&core.observed)?;
            core.read.buffer.fill(0);core.read.run(core.pipe as Ptr,false,&core.stop)?;
            core.current_peer()?;core.permission.as_mut().ok_or("counter permission absent")?.recheck_original(&core.observed)?;core.empty_incoming()?;
            let used=u16::from_be_bytes([core.read.buffer[0],core.read.buffer[1]]) as usize;
            if !(6..=PAYLOAD).contains(&used)||core.read.buffer[used+2..].iter().any(|b|*b!=0){
                return Err("counter exact response payload/padding refused".into());}
            response.fill(0);response[..used].copy_from_slice(&core.read.buffer[2..used+2]);
            if core.stop.stopped(){return Err("counter stopped at response delivery; unknown outcome".into());}
            core.pending=None;core.frozen=false;Ok(used)
        })();
        if result.is_err(){core.frozen=true;}result
    }
}
/// This report is ONLY transport closure. Installed selection/current guards
/// remain opaque and retained for Activation's separate exact close protocol.
enum ClosedTransportCustody{
    Closed{permission:Option<ManuallyDrop<AuthorizedWindowsCounterPeer>>,observation:KernelPipePeerObservation},
    Unknown(ManuallyDrop<Box<Core>>),
}
pub(crate) struct WindowsCounterTransportClose{custody:ClosedTransportCustody,attempted:usize,unknown:usize}
impl WindowsCounterTransportClose{
    pub(crate) fn transport_handles_closed(&self)->bool{self.attempted==5&&self.unknown==0}
    pub(crate) fn unknown_close_count(&self)->usize{self.unknown}
    /// Successful native close transfers only the OLD permission to its own
    /// issuer's closure protocol. Its binding cannot authorize another pipe.
    pub(crate) fn into_retained_permission(mut self)->std::result::Result<ManuallyDrop<AuthorizedWindowsCounterPeer>,Self>{
        match self.take_retained_permission(){Ok(permission)=>Ok(permission),Err(())=>Err(self)}
    }
    /// Transfer ONLY the original one-use permission; retain the full original
    /// successful transport-close observation in the factory's existing graph.
    pub(crate) fn take_retained_permission(&mut self)->std::result::Result<ManuallyDrop<AuthorizedWindowsCounterPeer>,()>{
        if !self.transport_handles_closed(){return Err(());}
        match &mut self.custody{ClosedTransportCustody::Closed{permission,..}=>permission.take().ok_or(()),
            ClosedTransportCustody::Unknown(_)=>Err(())}
    }
}
impl WindowsCounterNativeTransport{
    /// Exclusive synchronous owner has returned from its LAST native exchange.
    /// This supplies settlement/transport close facts, never a thread-join token.
    pub(crate) fn close_settled(mut self)->std::result::Result<WindowsCounterTransportClose,WindowsCounterTransportFailure>{
        let result=(||{
            let core=self.custody.core.as_mut().ok_or("counter transport custody absent")?;
            if core.frozen||core.stop.state.signal_error.load(Ordering::SeqCst)!=0{
                return Err("counter prior unknown refusal retained at close".into());}
            core.current_identity_and_permission()?;core.empty_incoming()?;
            if core.pending.is_some()||core.write.active||core.read.active||core.token!=0||core.security_allocation!=0||core.close_attempted{
                return Err("counter close pending/native uncertainty retained".into());}Ok(())
        })();
        if let Err(description)=result{return Err(WindowsCounterTransportFailure{description,
            retained:ManuallyDrop::new(Custody{core:self.custody.core.take()})});}
        let mut core=self.custody.core.take().expect("retained checked connection");
        core.close_attempted=true;core.frozen=true;
        let roster=[(1,core.pipe),(2,core.process),(3,core.write.overlapped.event as usize),(4,core.read.overlapped.event as usize),(5,core.mode_handle)];
        // All five original close obligations and error slots already exist.
        // Attempt each independently, once. No failed number is retried/dropped.
        for(index,(kind,raw))in roster.into_iter().enumerate(){
            if raw==0||unsafe{CloseHandle(raw as Ptr)}==0{core.close_errors[index]=Some(UnknownNativeClose{
                kind,raw,error:if raw==0{0}else{unsafe{GetLastError()}},pid:core.observed.facts.pid,creation:core.observed.facts.creation});}
        }
        let unknown=core.close_errors.iter().filter(|e|e.is_some()).count();
        if unknown!=0{return Ok(WindowsCounterTransportClose{custody:ClosedTransportCustody::Unknown(ManuallyDrop::new(core)),attempted:5,unknown});}
        // Only known settlement AND all five actual closes release the I/O heap
        // and connection's Stop Arc. Selected permission remains opaque/retained.
        let Core{observed,permission,stop,write,read,..}=*core;
        drop(write);drop(read);drop(stop);
        Ok(WindowsCounterTransportClose{custody:ClosedTransportCustody::Closed{
            permission:Some(permission.expect("authorized settled transport")),observation:observed},attempted:5,unknown:0})
    }
}
