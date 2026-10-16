//! Native Windows message authentication, pending the installed Windows issuer.
//! Only the genuine installed-selection factory supplies private authority.
//! Missing qualification, loaded-code or installation inputs refuse. Caller
//! SID labels, pipe bytes and process IDs grant no clock rights.
//! No service install, privilege enable, token duplication or remote image claim.
#![allow(dead_code)]
use sha2::{Digest,Sha256};
use std::{ffi::c_void,fs::File,mem::{size_of,zeroed,ManuallyDrop},os::windows::io::{AsRawHandle,FromRawHandle,IntoRawHandle},ptr::{null,null_mut}};
use std::sync::{Arc,atomic::{AtomicBool,Ordering}};
type Ptr=*mut c_void;
type Result<T>=std::result::Result<T,String>;
#[repr(C)] struct FileTime {low:u32,high:u32}
#[repr(C)] struct IoStatus {status:usize,information:usize}
#[repr(C)] struct SecurityAttributes {length:u32,descriptor:Ptr,inherit:i32}
#[repr(C)] struct Acl {revision:u8,reserved:u8,size:u16,count:u16,reserved2:u16}
#[repr(C)] struct Ace {kind:u8,flags:u8,size:u16,mask:u32,sid:u32}
#[link(name="kernel32")] unsafe extern "system" {
    fn GetCurrentProcess()->Ptr; fn GetCurrentThread()->Ptr;
    fn GetNamedPipeClientProcessId(pipe:Ptr,pid:*mut u32)->i32;
    fn GetNamedPipeServerProcessId(pipe:Ptr,pid:*mut u32)->i32;
    fn GetNamedPipeInfo(pipe:Ptr,flags:*mut u32,out:*mut u32,input:*mut u32,instances:*mut u32)->i32;
    fn GetNamedPipeHandleStateW(pipe:Ptr,state:*mut u32,instances:*mut u32,max:*mut u32,timeout:*mut u32,user:*mut u16,length:u32)->i32;
    fn OpenProcess(access:u32,inherit:i32,pid:u32)->Ptr;
    fn GetProcessId(process:Ptr)->u32;
    fn GetProcessTimes(process:Ptr,creation:*mut FileTime,exit:*mut FileTime,kernel:*mut FileTime,user:*mut FileTime)->i32;
    fn WaitForSingleObject(handle:Ptr,milliseconds:u32)->u32;
    fn ReadFile(handle:Ptr,buffer:Ptr,length:u32,read:*mut u32,overlapped:Ptr)->i32;
    fn WriteFile(handle:Ptr,buffer:*const c_void,length:u32,written:*mut u32,overlapped:Ptr)->i32;
    fn CloseHandle(handle:Ptr)->i32;
    fn GetLastError()->u32;
    fn CreateNamedPipeW(name:*const u16,access:u32,mode:u32,instances:u32,out:u32,input:u32,timeout:u32,security:*const SecurityAttributes)->Ptr;
    fn ConnectNamedPipe(pipe:Ptr,overlapped:Ptr)->i32;
    fn DisconnectNamedPipe(pipe:Ptr)->i32;
    fn CreateFileW(name:*const u16,access:u32,share:u32,security:Ptr,disposition:u32,flags:u32,template:Ptr)->Ptr;
    fn PeekNamedPipe(pipe:Ptr,buffer:Ptr,length:u32,read:*mut u32,available:*mut u32,left:*mut u32)->i32;
}
#[link(name="advapi32")] unsafe extern "system" {
    fn OpenProcessToken(process:Ptr,access:u32,token:*mut Ptr)->i32;
    fn OpenThreadToken(thread:Ptr,access:u32,as_self:i32,token:*mut Ptr)->i32;
    fn GetTokenInformation(token:Ptr,kind:u32,data:Ptr,length:u32,needed:*mut u32)->i32;
    fn ConvertStringSidToSidW(text:*const u16,sid:*mut Ptr)->i32;
    fn IsValidSid(sid:Ptr)->i32; fn GetLengthSid(sid:Ptr)->u32;
    fn ImpersonateNamedPipeClient(pipe:Ptr)->i32; fn RevertToSelf()->i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(text:*const u16,revision:u32,descriptor:*mut Ptr,length:*mut u32)->i32;
    fn GetSecurityInfo(handle:Ptr,kind:u32,info:u32,owner:*mut Ptr,group:*mut Ptr,acl:*mut *mut Acl,sacl:*mut Ptr,sd:*mut Ptr)->u32;
    fn GetSecurityDescriptorControl(sd:Ptr,control:*mut u16,revision:*mut u32)->i32;
    fn GetAce(acl:*mut Acl,index:u32,ace:*mut Ptr)->i32;
}
#[link(name="ntdll")] unsafe extern "system" {
    fn NtQueryInformationFile(file:Ptr,status:*mut IoStatus,data:Ptr,length:u32,kind:u32)->i32;
    fn NtQueryObject(object:Ptr,kind:u32,data:Ptr,length:u32,needed:*mut u32)->i32;
}
#[link(name="kernel32")] unsafe extern "system" {fn LocalFree(allocation:Ptr)->Ptr;}
#[link(name="advapi32")] unsafe extern "system" {fn GetSecurityDescriptorLength(descriptor:Ptr)->u32;}
fn last()->String {format!("Windows clock channel native error {}",unsafe{GetLastError()})}
#[derive(Clone,Copy)] enum NativeReleaseKind {Handle,Local}
#[derive(Clone,Copy)] struct NativeObserved {stage:&'static str,result:i64,error:Option<u32>,facts:[u64;2]}
struct NativeTemporaryCustody {
    original:usize,source:usize,kind:&'static str,release:NativeReleaseKind,
    pid:Option<u32>,creation:Option<u64>,process_times:Option<[u64;4]>,sid:[u8;68],sid_length:u8,
    token_needed:Option<u32>,token_level:Option<u32>,descriptor_control:Option<u16>,descriptor_revision:Option<u32>,
    observed:[Option<NativeObserved>;8],observed_count:usize,
    original_bytes:[u8;8192],original_bytes_length:usize,original_bytes_address:usize,
    query_problem:Option<String>,release_attempted:bool,released:bool,release_result:Option<usize>,release_error:Option<u32>,
}
// Both the native owner and its complete error/partial-observation storage are
// allocated BEFORE the native call. Drop retains; it never closes or retries.
struct NativeHandle(Ptr,Option<Box<NativeTemporaryCustody>>);
impl NativeHandle {
    fn prepared(kind:&'static str,release:NativeReleaseKind,source:Ptr)->Self {
        Self(null_mut(),Some(Box::new(NativeTemporaryCustody{original:0,source:source as usize,kind,release,
            pid:None,creation:None,process_times:None,sid:[0;68],sid_length:0,
            token_needed:None,token_level:None,descriptor_control:None,descriptor_revision:None,
            observed:[None;8],observed_count:0,
            original_bytes:[0;8192],original_bytes_length:0,original_bytes_address:0,
            query_problem:None,release_attempted:false,released:false,release_result:None,release_error:None})))
    }
    fn observed(&mut self,stage:&'static str,result:i64,error:Option<u32>) {
        let core=self.1.as_mut().expect("original native query custody");
        assert!(core.observed_count<core.observed.len(),"finite original native observation roster");
        core.observed[core.observed_count]=Some(NativeObserved{stage,result,error,facts:[0;2]});core.observed_count+=1;
    }
    fn observation_facts(&mut self,first:u64,second:u64) {
        let core=self.1.as_mut().expect("original native query custody");
        core.observed[core.observed_count.checked_sub(1).expect("native observation precedes facts")]
            .as_mut().expect("original native observation").facts=[first,second];
    }
    fn bind(&mut self,raw:Ptr){self.0=raw;self.1.as_mut().expect("original native custody").original=raw as usize;}
    fn unconfirmed(&mut self,raw:Ptr){self.1.as_mut().expect("original native custody").original=raw as usize;}
    fn transfer(mut self)->Ptr {
        let raw=self.0;assert!(!raw.is_null(),"original native owner required for transfer");
        assert!(!self.1.as_ref().expect("original native custody").release_attempted,"closed owner cannot transfer");
        self.0=null_mut();drop(self.1.take());raw
    }
    fn bytes(&mut self,raw:&[u8],address:usize)->Result<()> {
        let core=self.1.as_mut().expect("original native query custody");
        if raw.len()>core.original_bytes.len(){return Err("bounded original native query bytes".into());}
        core.original_bytes[..raw.len()].copy_from_slice(raw);core.original_bytes_length=raw.len();core.original_bytes_address=address;Ok(())
    }
    fn learned_sid(&mut self,sid:&[u8]) {
        let core=self.1.as_mut().expect("original native query custody");
        assert!(sid.len()<=core.sid.len(),"already validated SID bound");
        core.sid[..sid.len()].copy_from_slice(sid);core.sid_length=sid.len() as u8;
    }
    fn descriptor_bytes(&mut self)->Result<()> {
        if self.0.is_null(){return Err("original descriptor unavailable".into());}
        let size=unsafe{GetSecurityDescriptorLength(self.0)} as usize;
        let error=if size==0{Some(unsafe{GetLastError()})}else{None};self.observed("descriptor-length",size as i64,error);
        if size==0||size>8192{return Err("bounded original security descriptor".into());}
        // The successful Windows allocation call owns this descriptor. No
        // caller pointer is accepted and no bytes survive as authority.
        self.bytes(unsafe{std::slice::from_raw_parts(self.0.cast::<u8>(),size)},self.0 as usize)
    }
    fn original_creation(&mut self)->Result<u64> {
        let(mut c,mut e,mut k,mut u)=unsafe{(zeroed::<FileTime>(),zeroed::<FileTime>(),zeroed::<FileTime>(),zeroed::<FileTime>())};
        let captured=unsafe{GetProcessTimes(self.0,&mut c,&mut e,&mut k,&mut u)};
        let error=if captured==0{Some(unsafe{GetLastError()})}else{None};
        let ticks=|v:&FileTime|(u64::from(v.high)<<32)|u64::from(v.low);
        let values=[ticks(&c),ticks(&e),ticks(&k),ticks(&u)];
        // Publish the original query and initialized partial outputs BEFORE
        // any error propagation/native close; failed outputs grant no fact.
        self.observed("peer-original-process-times",i64::from(captured),error);
        self.1.as_mut().expect("original peer custody").process_times=Some(values);
        if captured==0{return Err(format!("Windows clock channel native error {}",error.unwrap_or(0)));}
        self.1.as_mut().expect("original peer custody").creation=Some(values[0]);Ok(values[0])
    }
    fn finish<T>(mut self,result:Result<T>)->Result<T> {
        if let Err(problem)=&result{self.1.as_mut().expect("native query custody").query_problem=Some(problem.clone());}
        let release=if self.0.is_null(){Ok(())}else{
            let core=self.1.as_mut().expect("original native query custody");
            assert!(!core.release_attempted,"no original native close retry");core.release_attempted=true;
            let (success,native_result)=match core.release {
                NativeReleaseKind::Handle=>{let value=unsafe{CloseHandle(self.0)};(value!=0,value as usize)},
                NativeReleaseKind::Local=>{let value=unsafe{LocalFree(self.0)};(value.is_null(),value as usize)},
            };
            let error=if success{None}else{Some(unsafe{GetLastError()})};
            core.release_result=Some(native_result);core.release_error=error;
            if success{core.released=true;self.0=null_mut();Ok(())}else{
                let code=error.expect("immediate failed native release error");
                Err(format!("original {} release unknown {code}",core.kind))
            }
        };
        let outcome=match(result,release){(Ok(value),Ok(()))=>Ok(value),
            (Err(first),Err(next))=>Err(format!("{first}; {next}")),(Err(first),Ok(()))=>Err(first),(Ok(_),Err(next))=>Err(next)};
        if outcome.is_ok(){drop(self.1.take());}
        // Every error/unwind keeps its original observations/outcomes, even
        // when the native close succeeded. Unknown close cannot be retried.
        outcome
    }
}
impl Drop for NativeHandle {fn drop(&mut self){if let Some(core)=self.1.take(){let _custody=Box::into_raw(core);}}}
type LocalDescriptor=NativeHandle;
struct WindowsCallLifetime {frozen:Arc<AtomicBool>,armed:bool}
impl WindowsCallLifetime {
    fn begin(frozen:&Arc<AtomicBool>)->Self {Self{frozen:frozen.clone(),armed:true}}
    fn finished(&mut self,failed:bool){if failed{self.frozen.store(true,Ordering::SeqCst);}self.armed=false;}
}
impl Drop for WindowsCallLifetime {fn drop(&mut self){if self.armed{self.frozen.store(true,Ordering::SeqCst);}}}
struct MessageImpersonation {armed:bool}
impl MessageImpersonation {
    fn restore(&mut self) {
        if self.armed {
            let restored=unsafe{RevertToSelf()}!=0;
            if !restored || no_impersonation().is_err(){std::process::abort();}
            self.armed=false;
        }
    }
}
impl Drop for MessageImpersonation {fn drop(&mut self){self.restore();}}
fn no_impersonation()->Result<()> {
    let mut held=NativeHandle::prepared("thread-token",NativeReleaseKind::Handle,unsafe{GetCurrentThread()});let mut token=null_mut();
    let opened=unsafe{OpenThreadToken(GetCurrentThread(),8,1,&mut token)};
    let code=if opened==0{Some(unsafe{GetLastError()})}else{None};if opened!=0{held.bind(token)}else{held.unconfirmed(token)};held.observed("thread-token-open",i64::from(opened),code);
    held.finish(if opened!=0{Err("clock channel already impersonating".into())}
        else if !token.is_null(){Err("failed thread-token query returned unexpected output; custody retained".into())}
        else if code!=Some(1008){Err(format!("Windows clock channel native error {}",code.unwrap_or(0)))}else{Ok(())})
}
fn token_sid(held:&mut NativeHandle)->Result<Vec<u8>> {
    let token=held.0;
    let mut needed=0;
    let queried=unsafe{GetTokenInformation(token,1,null_mut(),0,&mut needed)};
    let error=if queried==0{Some(unsafe{GetLastError()})}else{None};held.observed("token-user-size",i64::from(queried),error);
    held.observation_facts(u64::from(needed),0);
    held.1.as_mut().expect("original token custody").token_needed=Some(needed);
    if queried!=0 || error!=Some(122) || needed==0 || needed>4096 {return Err("token user size refused".into());}
    let mut data=vec![0usize;(needed as usize+size_of::<usize>()-1)/size_of::<usize>()];
    let capacity=data.len()*size_of::<usize>();
    let queried=unsafe{GetTokenInformation(token,1,data.as_mut_ptr().cast(),capacity as u32,&mut needed)};
    let error=if queried==0{Some(unsafe{GetLastError()})}else{None};held.observed("token-user-body",i64::from(queried),error);
    held.observation_facts(u64::from(needed),capacity as u64);
    held.1.as_mut().expect("original token custody").token_needed=Some(needed);
    held.bytes(unsafe{std::slice::from_raw_parts(data.as_ptr().cast::<u8>(),capacity)},data.as_ptr() as usize)?;
    if queried==0 || needed as usize>capacity || (needed as usize)<size_of::<Ptr>() {
        return Err(format!("token user body refused; original native error {:?}",error));}
    let sid=unsafe{*(data.as_ptr() as *const Ptr)};
    let start=data.as_ptr() as usize;let end=start.checked_add(needed as usize).ok_or("token bound overflow")?;
    let address=sid as usize;
    // Validate the SID header's allocation membership before invoking a native
    // SID reader, then validate its complete variable-sized body before copying.
    if address<start || address.checked_add(8).ok_or("SID header overflow")?>end {return Err("token SID pointer refused".into());}
    let sub=unsafe{*((address+1) as *const u8)} as usize;
    let bytes=8usize.checked_add(sub.checked_mul(4).ok_or("SID length overflow")?).ok_or("SID length overflow")?;
    if bytes>68 || address.checked_add(bytes).ok_or("SID body overflow")?>end
        || unsafe{IsValidSid(sid)}==0 || unsafe{GetLengthSid(sid)} as usize!=bytes {return Err("token SID bounds refused".into());}
    let value=unsafe{std::slice::from_raw_parts(sid.cast::<u8>(),bytes)}.to_vec();held.learned_sid(&value);Ok(value)
}
fn process_sid(process:Ptr)->Result<Vec<u8>> {
    let mut held=NativeHandle::prepared("process-token",NativeReleaseKind::Handle,process);let mut value=null_mut();
    let opened=unsafe{OpenProcessToken(process,8,&mut value)};
    let error=if opened==0{Some(unsafe{GetLastError()})}else{None};if opened!=0{held.bind(value)}else{held.unconfirmed(value)};held.observed("process-token-open",i64::from(opened),error);
    let result=if opened==0{Err(format!("process token open refused {:?}",error))}else{token_sid(&mut held)};
    held.finish(result)
}
/// Actual current process security boundary, not a proposed/default ACL. Other
/// ordinary principals may have only explicit query/synchronize/read-control
/// rights. VM read/write, thread creation, handle duplication, termination,
/// process mutation and security changes cannot be granted to Node or a group
/// that includes it. SYSTEM/Administrators and the actual own token remain the
/// adopted owner/installation trust domain. No ACL or token is changed here.
pub(crate) use super::windows_public_object::require_own_process_boundary;
fn creation(process:Ptr)->Result<u64> {
    let(mut c,mut e,mut k,mut u)=unsafe{(zeroed::<FileTime>(),zeroed::<FileTime>(),zeroed::<FileTime>(),zeroed::<FileTime>())};
    if unsafe{GetProcessTimes(process,&mut c,&mut e,&mut k,&mut u)}==0 {return Err(last());}
    Ok((u64::from(c.high)<<32)|u64::from(c.low))
}
pub(super) enum ChannelRole {Owner,Consumer}
pub(super) struct InstalledWindowsAuthority {
    own_sid:Vec<u8>,peer_sid:Vec<u8>,context:[u8;32],
    role:ChannelRole,endpoint:std::path::PathBuf,
    current:super::native_nts_deployment_record::NativeSelectionGuard,
    owner_text:String,node_text:String,async_message:bool,
    record:super::native_nts_deployment_record::ValidatedRecord,
    scope:super::protected_clock_lineage_v1::Scope,binding:super::protected_clock_lineage_v1::Binding,
}
impl InstalledWindowsAuthority {
    pub(super) fn from_selected(record:super::native_nts_deployment_record::ValidatedRecord,
        mut current:super::native_nts_deployment_record::NativeSelectionGuard,
        placement:super::native_nts_installation::OwnerPlacementDocument,role:ChannelRole)->Result<Self> {
        current.recheck()?;
        let(owner,node)=placement.windows_principals().map_err(str::to_owned)?;
        let(own,peer)=match role {ChannelRole::Owner=>(owner,node),ChannelRole::Consumer=>(node,owner)};
        let sid=|text:&str|->Result<Vec<u8>> {let wide=text.encode_utf16().chain([0]).collect::<Vec<_>>();let mut value=null_mut();
            let mut held=LocalDescriptor::prepared("selected-SID",NativeReleaseKind::Local,null_mut());
            let converted=unsafe{ConvertStringSidToSidW(wide.as_ptr(),&mut value)};
            let error=if converted==0{Some(unsafe{GetLastError()})}else{None};
            if converted!=0{held.bind(value)}else{held.unconfirmed(value)};held.observed("SID-conversion",i64::from(converted),error);
            let result=(||{if converted==0||value.is_null(){return Err(format!("installed SID conversion refused {:?}",error));}
                let valid=unsafe{IsValidSid(held.0)};held.observed("selected-SID-valid",i64::from(valid),None);
                if valid==0{return Err("installed SID refused".into());}
                let length=unsafe{GetLengthSid(held.0)} as usize;
                held.observed("selected-SID-length",length as i64,None);
                if !(8..=68).contains(&length){return Err("installed SID refused".into());}
                let value=unsafe{std::slice::from_raw_parts(held.0.cast::<u8>(),length)}.to_vec();held.learned_sid(&value);Ok(value)})();
            held.finish(result)};
        let value=super::native_nts_deployment_record::canonical_value(record.record().canonical())
            .map_err(|_|"Windows installed context encoding")?;
        let digest=|name:&str|->Result<[u8;32]>{let mut out=[0;32];
            hex::decode_to_slice(value["binding"][name].as_str().ok_or("Windows installed binding type")?,&mut out)
                .map_err(|_|"Windows installed binding encoding")?;Ok(out)};
        let scope=super::protected_clock_lineage_v1::Scope::selected_document(digest("genesis_sha256")?,
            digest("network_sha256")?,digest("rule_sha256")?,placement.lineage());
        let mut context=Sha256::new();context.update(b"MCLC4-CHANNEL-CONTEXT-1");
        context.update(scope.journal_context());context.update(Sha256::digest(record.record().canonical()));
        let context_digest=|name:&str|->Result<[u8;32]>{let mut out=[0;32];
            hex::decode_to_slice(value["context"][name].as_str().ok_or("Windows context digest type")?,&mut out)
                .map_err(|_|"Windows context digest encoding")?;Ok(out)};
        let mut code=Sha256::new();code.update(b"MCLC4-CODE-CONFIG-1");
        code.update(context_digest("code_sha256")?);code.update(context_digest("config_sha256")?);
        let binding=super::protected_clock_lineage_v1::Binding::selected_document(
            Sha256::digest(record.record().canonical()).into(),context_digest("qualification_sha256")?,
            code.finalize().into(),Sha256::digest(serde_json::to_vec(&value["acquisition"])
                .map_err(|_|"Windows provider context encoding")?).into(),record.record().profile().id());
        let mut authority=Self{own_sid:sid(own)?,peer_sid:sid(peer)?,context:context.finalize().into(),
            role,endpoint:placement.endpoint().to_path_buf(),current,owner_text:owner.to_owned(),node_text:node.to_owned(),
            async_message:placement.windows_async_message(),record,scope,binding};
        authority.recheck()?;Ok(authority)
    }
    fn recheck(&mut self)->Result<()> {
        no_impersonation()?;require_own_process_boundary()?;self.current.recheck()?;
        if process_sid(unsafe{GetCurrentProcess()})?!=self.own_sid {return Err("installed Windows owner principal changed".into());}
        self.current.recheck()
    }
}
fn pipe_security(pipe:Ptr,authority:&InstalledWindowsAuthority)->Result<()> {
    let mut held=LocalDescriptor::prepared("pipe-security",NativeReleaseKind::Local,pipe);
    let(mut owner,mut sd,mut acl)=(null_mut(),null_mut(),null_mut());
    let code=unsafe{GetSecurityInfo(pipe,1,1|4,&mut owner,null_mut(),&mut acl,null_mut(),&mut sd)};
    if code==0{held.bind(sd)}else{held.unconfirmed(sd)};held.observed("pipe-security-query",i64::from(code),if code!=0{Some(code)}else{None});
    let result=(||{if code!=0 {return Err(format!("native pipe security error {code}"));}
    held.descriptor_bytes()?;
    let mut control=0u16;let mut revision=0u32;
    if owner.is_null() || sd.is_null() || acl.is_null(){return Err("protected pipe security unavailable".into());}
    let captured=unsafe{GetSecurityDescriptorControl(sd,&mut control,&mut revision)};
    let error=if captured==0{Some(unsafe{GetLastError()})}else{None};held.observed("pipe-control-query",i64::from(captured),error);
    held.observation_facts(u64::from(control),u64::from(revision));
    {let core=held.1.as_mut().expect("original pipe descriptor custody");core.descriptor_control=Some(control);core.descriptor_revision=Some(revision);}
    if captured==0 || control&0x1000==0 || unsafe{IsValidSid(owner)}==0 {return Err("protected pipe security unavailable".into());}
    let owner_length=unsafe{GetLengthSid(owner)} as usize;
    let(owner_expected,node_expected)=match authority.role {ChannelRole::Owner=>(&authority.own_sid,&authority.peer_sid),
        ChannelRole::Consumer=>(&authority.peer_sid,&authority.own_sid)};
    if !(8..=68).contains(&owner_length) || unsafe{std::slice::from_raw_parts(owner.cast::<u8>(),owner_length)}!=owner_expected.as_slice()
        || unsafe{(*acl).count}!=3 || unsafe{(*acl).size}>4096 {return Err("pipe owner/ACL differs".into());}
    held.learned_sid(unsafe{std::slice::from_raw_parts(owner.cast::<u8>(),owner_length)});
    let system=[1u8,1,0,0,0,0,0,5,18,0,0,0];let mut seen=[false;3];
    for index in 0..3 {
        let mut raw=null_mut();let captured=unsafe{GetAce(acl,index,&mut raw)};
        let error=if captured==0{Some(unsafe{GetLastError()})}else{None};held.observed("pipe-ACE-query",i64::from(captured),error);
        if captured==0 || raw.is_null(){return Err("pipe ACE unavailable".into());}
        let ace=unsafe{&*(raw as *const Ace)};
        if ace.kind!=0 || ace.flags!=0 || ace.size<16 {return Err("pipe exact allow ACE required".into());}
        let sid=std::ptr::addr_of!(ace.sid) as Ptr;
        if unsafe{IsValidSid(sid)}==0 {return Err("pipe ACE SID invalid".into());}
        let length=unsafe{GetLengthSid(sid)} as usize;
        if !(8..=68).contains(&length) || length>usize::from(ace.size)-8 {return Err("pipe ACE SID bound".into());}
        let sid=unsafe{std::slice::from_raw_parts(sid.cast::<u8>(),length)};
        let slot=if sid==owner_expected.as_slice() && ace.mask==0x1f01ff {0}
            else if sid==system && ace.mask==0x1f01ff {1}
            else if sid==node_expected.as_slice() && ace.mask==(if authority.async_message {0x12018b}else{0x12008b}) {2}
            else{return Err("foreign or excessive pipe authority".into());};
        if seen[slot]{return Err("duplicate pipe authority".into());}seen[slot]=true;
    }
    if seen!=[true;3]{return Err("missing exact pipe authority".into());}Ok(())})();
    held.finish(result)
}
/// Private bounded create-only endpoint after genuine ordinary installed
/// authority. No account/ACL/service installation. Node has data/query/sync only,
/// notably NO FILE_CREATE_PIPE_INSTANCE (bit4), DELETE, owner or DACL rights.
pub(super) struct WindowsPipeListener {pipe:File,authority:InstalledWindowsAuthority}
pub(super) struct WindowsEndpointFailure {error:String,uncertain:Option<ManuallyDrop<File>>,authority:Option<ManuallyDrop<InstalledWindowsAuthority>>}
impl WindowsEndpointFailure {pub(super) fn description(&self)->&str {&self.error}}
/// Explicit transport-only close custody. The caller must retain this object:
/// failed native handles are never retried or released by Drop, and the current
/// installed guard remains held for the separate whole-owner lifecycle. A
/// pending logical operation remains unresolved even if every handle closes.
/// This report does not issue a lineage replacement/startup authorization.
pub(super) struct WindowsTransportClose {
    pipe_failure:Option<WindowsUnclosedHandle>,
    peer_failure:Option<WindowsUnclosedHandle>,
    installed_guard:ManuallyDrop<super::native_nts_deployment_record::NativeSelectionGuard>,
    pending:Option<PendingReservation>,
}
struct WindowsUnclosedHandle { raw:Ptr, kind:&'static str, pid:Option<u32>, creation:Option<u64>, error:u32 }
impl WindowsTransportClose {
    fn new(authority:InstalledWindowsAuthority,pending:Option<PendingReservation>)->Self {
        Self{pipe_failure:None,peer_failure:None,installed_guard:ManuallyDrop::new(authority.current),pending}
    }
    fn close_once(raw:Ptr,kind:&'static str,pid:Option<u32>,creation:Option<u64>)->Option<WindowsUnclosedHandle> {
        // Fixed inline custody requires no allocation after a native effect.
        if unsafe{CloseHandle(raw)}==0 {
            let error=unsafe{GetLastError()};
            Some(WindowsUnclosedHandle{raw,kind,pid,creation,error})
        }else{None}
    }
    pub(super) fn transport_handles_closed(&self)->bool {self.pipe_failure.is_none() && self.peer_failure.is_none()}
    pub(super) fn unresolved_operation(&self)->Option<([u8;32],u64)> {
        self.pending.as_ref().map(|p|(p.operation,p.expected_sequence))
    }
    pub(super) fn close_installed_retained(self)->std::result::Result<WindowsRetainedTransportClose,ManuallyDrop<Self>> {
        if !self.transport_handles_closed() || self.pending.is_some(){return Err(ManuallyDrop::new(self));}
        Ok(WindowsRetainedTransportClose{selection:ManuallyDrop::into_inner(self.installed_guard).close_retained()})
    }
}
pub(super) struct WindowsRetainedTransportClose {
    selection:std::result::Result<super::native_nts_deployment_record::SelectionRetainedClose,
        ManuallyDrop<super::native_nts_deployment_record::NativeSelectionGuard>>,
}
impl WindowsRetainedTransportClose {pub(super) fn retained_handles_closed(&self)->bool {
    self.selection.as_ref().is_ok_and(|r|r.retained_handles_closed())
}}
impl WindowsPipeListener {
    pub(super) fn bind_new(authority:InstalledWindowsAuthority)->std::result::Result<Self,WindowsEndpointFailure> {
        Self::bind_new_mode(authority,false)
    }
    fn bind_new_mode(mut authority:InstalledWindowsAuthority,overlapped:bool)->std::result::Result<Self,WindowsEndpointFailure> {
        let fail=|error:String|WindowsEndpointFailure{error,uncertain:None,authority:None};
        authority.recheck().map_err(fail)?;
        if !matches!(authority.role,ChannelRole::Owner) || (overlapped && !authority.async_message){return Err(fail("consumer/old profile cannot create selected clock endpoint".into()));}
        let descriptor=format!("O:{}D:P(A;;FA;;;SY)(A;;FA;;;{})(A;;0x{:x};;;{})",
            authority.owner_text,authority.owner_text,if authority.async_message{0x12018b}else{0x12008b},authority.node_text).encode_utf16().chain([0]).collect::<Vec<_>>();
        let endpoint=authority.endpoint.to_str().ok_or_else(||fail("installed endpoint spelling".into()))?
            .encode_utf16().chain([0]).collect::<Vec<_>>();
        let mut held=LocalDescriptor::prepared("endpoint-SDDL",NativeReleaseKind::Local,null_mut());
        let mut pipe_obligation=NativeHandle::prepared("created-clock-pipe",NativeReleaseKind::Handle,null_mut());
        let mut sd=null_mut();let converted=unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.as_ptr(),1,&mut sd,null_mut())};
        let error=if converted==0{Some(unsafe{GetLastError()})}else{None};
        if converted!=0{held.bind(sd)}else{held.unconfirmed(sd)};held.observed("SDDL-conversion",i64::from(converted),error);
        let prepared=if converted==0{Err(format!("native endpoint descriptor conversion {:?}",error))}else{held.descriptor_bytes()};
        if let Err(problem)=prepared {
            let error=held.finish::<()>(Err(problem)).expect_err("original conversion refusal");
            return Err(WindowsEndpointFailure{error,uncertain:None,authority:Some(ManuallyDrop::new(authority))});
        }
        let attributes=SecurityAttributes{length:size_of::<SecurityAttributes>() as u32,descriptor:held.0,inherit:0};
        // DUPLEX|FIRST_PIPE_INSTANCE; MESSAGE|READMODE_MESSAGE|REJECT_REMOTE.
        // One instance and synchronous I/O. Existing/foreign endpoint refuses;
        // no wait/adopt/unlink/second-instance fallback, no implicit nonce.
        let raw=unsafe{CreateNamedPipeW(endpoint.as_ptr(),3|0x80000|if overlapped{0x40000000}else{0},4|2|8,1,
            if authority.async_message{775}else{89},81,0,&attributes)};
        let error=if raw==(-1isize) as Ptr{Some(unsafe{GetLastError()})}else{None};
        if error.is_none(){pipe_obligation.bind(raw)}else{pipe_obligation.unconfirmed(raw)};
        pipe_obligation.observed("pipe-create",raw as isize as i64,error);
        // Publish the original pipe obligation BEFORE attempting descriptor
        // release. An unknown LocalFree/unwind cannot lose a created pipe.
        let released=held.finish(if let Some(error)=error{Err(format!("native clock pipe create error {error}"))}else{Ok(())});
        if let Err(error)=released {
            let uncertain=if raw!=(-1isize) as Ptr{Some(ManuallyDrop::new(unsafe{File::from_raw_handle(pipe_obligation.transfer())}))}else{None};
            return Err(WindowsEndpointFailure{error,uncertain,authority:Some(ManuallyDrop::new(authority))});
        }
        let pipe=unsafe{File::from_raw_handle(pipe_obligation.transfer())};
        let result=(|| {authority.recheck()?;pipe_name(raw,&authority.endpoint)?;pipe_security(raw,&authority)?;authority.recheck()})();
        if let Err(error)=result {return Err(WindowsEndpointFailure{error,uncertain:Some(ManuallyDrop::new(pipe)),authority:Some(ManuallyDrop::new(authority))});}
        Ok(Self{pipe,authority})
    }
    pub(super) fn accept(mut self)->std::result::Result<WindowsPipeReceiver,WindowsEndpointFailure> {
        let result=(|| {self.authority.recheck()?;pipe_security(self.pipe.as_raw_handle(),&self.authority)?;
            if unsafe{ConnectNamedPipe(self.pipe.as_raw_handle(),null_mut())}==0 && unsafe{GetLastError()}!=535 {return Err(last());}
            self.authority.recheck()?;pipe_security(self.pipe.as_raw_handle(),&self.authority)})();
        if let Err(error)=result{return Err(WindowsEndpointFailure{error,uncertain:Some(ManuallyDrop::new(self.pipe)),authority:Some(ManuallyDrop::new(self.authority))});}
        WindowsPipeReceiver::attach(self.pipe,self.authority)
    }
    pub(super) fn close_transport(self)->WindowsTransportClose {
        let Self{pipe,authority}=self;
        let mut report=WindowsTransportClose::new(authority,None);
        report.pipe_failure=WindowsTransportClose::close_once(pipe.into_raw_handle(),"listener pipe",None,None);report
    }
}
#[repr(C)] struct UnicodeString {length:u16,maximum:u16,buffer:*const u16}
fn pipe_name(pipe:Ptr,expected:&std::path::Path)->Result<()> {
    let text=expected.to_str().ok_or("installed pipe spelling")?;
    let suffix=text.strip_prefix(r"\\.\pipe\").ok_or("installed local pipe namespace")?;
    let expected=format!(r"\Device\NamedPipe\{suffix}").encode_utf16().collect::<Vec<_>>();
    let mut data=[0usize;512];let mut needed=0;
    let capacity=data.len()*size_of::<usize>();
    if unsafe{NtQueryObject(pipe,1,data.as_mut_ptr().cast(),capacity as u32,&mut needed)}<0
        || needed as usize>capacity || (needed as usize)<size_of::<UnicodeString>() {return Err("native pipe name unavailable".into());}
    let name=unsafe{&*(data.as_ptr() as *const UnicodeString)};
    let start=data.as_ptr() as usize;let end=start.checked_add(needed as usize).ok_or("pipe name bound overflow")?;
    let address=name.buffer as usize;
    if name.length%2!=0 || name.length>name.maximum || address%2!=0 || address<start
        || address.checked_add(name.length as usize).ok_or("pipe name pointer overflow")?>end {return Err("native pipe name bounds refused".into());}
    if unsafe{std::slice::from_raw_parts(name.buffer,name.length as usize/2)}!=expected.as_slice() {
        return Err("native pipe endpoint differs from installed lineage".into());
    } Ok(())
}
struct PipePeer {process:NativeHandle,pid:u32,creation:u64,sid:Vec<u8>,server:bool}
impl PipePeer {
    fn capture(pipe:Ptr,authority:&mut InstalledWindowsAuthority)->Result<Self> {
        authority.recheck()?;let mut pid=0;
        let server=matches!(authority.role,ChannelRole::Consumer);
        let observed=if server {unsafe{GetNamedPipeServerProcessId(pipe,&mut pid)}}else{unsafe{GetNamedPipeClientProcessId(pipe,&mut pid)}};
        if observed==0 || pid==0 {return Err(last());}
        // Exact limited process-object rights only; access refusal is a blocker.
        // No SeDebugPrivilege, broad launcher grant or numeric-PID fallback.
        let mut process=NativeHandle::prepared("original-kernel-peer",NativeReleaseKind::Handle,pipe);
        process.1.as_mut().expect("original peer custody").pid=Some(pid);
        let raw=unsafe{OpenProcess(0x00101000,0,pid)};
        let error=if raw.is_null(){Some(unsafe{GetLastError()})}else{None};process.bind(raw);process.observed("peer-process-open",raw as isize as i64,error);
        let observed=(||{if raw.is_null(){return Err(format!("native original peer open error {:?}",error));}
            let created=process.original_creation()?;
            let sid=process_sid(raw)?;process.learned_sid(&sid);
            if sid!=authority.peer_sid{return Err("pipe client principal differs".into());}
            Ok((created,sid))})();
        let(created,sid)=match observed{Ok(value)=>value,Err(problem)=>return process.finish(Err(problem))};
        let peer=Self{creation:created,sid,process,pid,server};
        let result=peer.recheck(pipe).and_then(|_|authority.recheck());
        match result{Ok(())=>Ok(peer),Err(problem)=>peer.process.finish(Err(problem))}
    }
    fn recheck(&self,pipe:Ptr)->Result<()> {
        let mut pid=0;
        let observed=if self.server {unsafe{GetNamedPipeServerProcessId(pipe,&mut pid)}}else{unsafe{GetNamedPipeClientProcessId(pipe,&mut pid)}};
        if unsafe{WaitForSingleObject(self.process.0,0)}!=258
            || unsafe{GetProcessId(self.process.0)}!=self.pid
            || creation(self.process.0)?!=self.creation || process_sid(self.process.0)?!=self.sid
            || observed==0 || pid!=self.pid {
            return Err("pipe client liveness/identity changed".into());
        } Ok(())
    }
}
/// Consumer code independently obtains its own normal installed/current
/// authority; authentication is the kernel server process object and exact
/// token SID/creation/liveness, never a receipt signer or claimed pathname.
pub(super) struct WindowsPipeConsumer {
    pipe:File,peer:PipePeer,authority:InstalledWindowsAuthority,frozen:Arc<AtomicBool>,
    pending:Option<PendingReservation>,
}
struct PendingReservation { operation:[u8;32], expected_sequence:u64 }
impl WindowsPipeConsumer {
    pub(super) fn connect(mut authority:InstalledWindowsAuthority)->std::result::Result<Self,WindowsEndpointFailure> {
        let fail=|error:String|WindowsEndpointFailure{error,uncertain:None,authority:None};
        authority.recheck().map_err(fail)?;
        if !matches!(authority.role,ChannelRole::Consumer){return Err(fail("owner cannot issue consumer connection".into()));}
        if authority.async_message{return Err(fail("selected asynchronous endpoint requires owned overlapped consumer".into()));}
        let name=authority.endpoint.to_str().ok_or_else(||fail("consumer endpoint spelling".into()))?
            .encode_utf16().chain([0]).collect::<Vec<_>>();
        // Specific data/query/sync rights avoid GENERIC_WRITE's mapping to
        // FILE_CREATE_PIPE_INSTANCE. Identification SQOS only; no impersonation
        // or remote/alternate endpoint, wait/fixture/default provider fallback.
        let raw=unsafe{CreateFileW(name.as_ptr(),0x12008b,0,null_mut(),3,0x110000,null_mut())};
        if raw==(-1isize) as Ptr{return Err(fail(last()));}
        let pipe=unsafe{File::from_raw_handle(raw)};
        let result=(|| {
            authority.recheck()?;pipe_name(raw,&authority.endpoint)?;pipe_security(raw,&authority)?;

            let mut flags=0;
            if unsafe{GetNamedPipeInfo(raw,&mut flags,null_mut(),null_mut(),null_mut())}==0 || flags&5!=4 {
                return Err("client message pipe required".into());
            }
            let mut ios=unsafe{zeroed::<IoStatus>()};let mut mode=0u32;
            if unsafe{NtQueryInformationFile(raw,&mut ios,(&mut mode as *mut u32).cast(),4,16)}<0
                || ios.information!=4 || mode&0x30==0{return Err("synchronous consumer pipe required".into());}
            let peer=PipePeer::capture(raw,&mut authority)?;authority.recheck()?;Ok(peer)
        })();
        match result {Ok(peer)=>Ok(Self{pipe,peer,authority,frozen:Arc::new(AtomicBool::new(false)),pending:None}),
            Err(error)=>Err(WindowsEndpointFailure{error,uncertain:Some(ManuallyDrop::new(pipe)),authority:Some(ManuallyDrop::new(authority))})}
    }
    fn current(&mut self)->Result<()> {
        if self.frozen.load(Ordering::SeqCst){return Err("Windows clock consumer channel frozen".into());}
        self.authority.recheck()?;pipe_name(self.pipe.as_raw_handle(),&self.authority.endpoint)?;
        pipe_security(self.pipe.as_raw_handle(),&self.authority)?;self.peer.recheck(self.pipe.as_raw_handle())?;
        self.authority.recheck()
    }
    /// Send one exact request. Success means only that the bounded request was
    /// written; admission/clock delivery remains unavailable until poll returns
    /// its authenticated outcome. Scheduling and cancellation belong to the
    /// caller's selected lifecycle, with no timeout or automatic retransmission.
    pub(super) fn start_reservation(&mut self,operation:[u8;32],expected_sequence:u64)->Result<()> {
        let mut lifetime=WindowsCallLifetime::begin(&self.frozen);
        let result=self.start_reservation_inner(operation,expected_sequence);
        lifetime.finished(result.is_err());result
    }
    fn start_reservation_inner(&mut self,operation:[u8;32],expected_sequence:u64)->Result<()> {
        self.current()?;if operation==[0;32]{return Err("empty consumer operation identity".into());}
        if self.pending.is_some(){return Err("consumer already has an unresolved exact operation".into());}
        // Retain identity before a possibly ambiguous native write. Never infer
        // non-consumption from a missing reply or issue a second logical request.
        self.pending=Some(PendingReservation{operation,expected_sequence});
        let mut frame=[0u8;81];frame[..8].copy_from_slice(b"MCLCIPC1");frame[8]=2;
        frame[9..41].copy_from_slice(&operation);frame[41..73].copy_from_slice(&self.authority.context);
        frame[73..81].copy_from_slice(&expected_sequence.to_be_bytes());
        let mut written=0;
        if unsafe{WriteFile(self.pipe.as_raw_handle(),frame.as_ptr().cast(),81,&mut written,null_mut())}==0 || written!=81 {
            return Err("consumer request outcome unknown; exact authenticated retry required".into());
        }
        self.current()
    }
    /// Inspect the original message boundary before consuming any byte.
    /// None preserves the exact pending operation and asserts no outcome.
    pub(super) fn poll_reservation(&mut self)->Result<Option<super::protected_clock_owner::ReservedReply>> {
        let mut lifetime=WindowsCallLifetime::begin(&self.frozen);
        let result=self.poll_reservation_inner();lifetime.finished(result.is_err());result
    }
    fn poll_reservation_inner(&mut self)->Result<Option<super::protected_clock_owner::ReservedReply>> {
        self.current()?;
        let pending=self.pending.as_ref().ok_or("consumer has no exact pending operation")?;
        let operation=pending.operation;let expected_sequence=pending.expected_sequence;
        let mut available=0u32;let mut left=0u32;
        if unsafe{PeekNamedPipe(self.pipe.as_raw_handle(),null_mut(),0,null_mut(),&mut available,&mut left)}==0 {
            return Err("consumer acknowledgment observation unknown; preserve exact operation".into());
        }
        // No read has advanced to a later message. The server-created MESSAGE
        // pipe gives the first message's full length even in byte-read mode.
        // Exclusive File ownership excludes another local reader between peek
        // and read. A second queued message also refuses via total availability.
        if available==0 && left==0 {self.current()?;return Ok(None);}
        if left!=89 || available!=89 {return Err("consumer original reply message length refused; exact retry required".into());}
        self.current()?;
        let mut response=[0u8;89];let mut read=0;
        if unsafe{ReadFile(self.pipe.as_raw_handle(),response.as_mut_ptr().cast(),89,&mut read,null_mut())}==0 || read!=89 {
            return Err("consumer complete reply unknown; preserve exact operation".into());
        }
        if &response[..8]!=b"MCLCIPR1" || response[8..40]!=operation
            || response[40..72]!=self.authority.context || response[88]>1 {return Err("consumer exact reply context refused".into());}
        let sequence=u64::from_be_bytes(response[72..80].try_into().map_err(|_|"reply sequence length")?);
        if expected_sequence.checked_add(1)!=Some(sequence){return Err("consumer exact reply sequence differs".into());}
        let floor=u64::from_be_bytes(response[80..88].try_into().map_err(|_|"reply floor length")?);
        self.current()?;
        self.pending=None;
        Ok(Some(super::protected_clock_owner::ReservedReply{sequence,floor,qualified:response[88]==1}))
    }
    pub(super) fn close_transport(self)->WindowsTransportClose {
        self.frozen.store(true,Ordering::SeqCst);
        let Self{pipe,peer,authority,frozen:_,pending}=self;
        let mut report=WindowsTransportClose::new(authority,pending);
        report.pipe_failure=WindowsTransportClose::close_once(pipe.into_raw_handle(),"consumer pipe",None,None);
        let held=ManuallyDrop::new(peer.process);
        report.peer_failure=WindowsTransportClose::close_once(held.0,"server process",Some(peer.pid),Some(peer.creation));report
    }
}
struct AuthenticatedRequest {operation:[u8;32],context:[u8;32],expected_sequence:u64,commitment:[u8;32],opcode:u8}
pub(super) struct WindowsPipeReceiver {pipe:File,peer:PipePeer,authority:InstalledWindowsAuthority,frozen:Arc<AtomicBool>}
impl WindowsPipeReceiver {
    fn attach(pipe:File,mut authority:InstalledWindowsAuthority)->std::result::Result<Self,WindowsEndpointFailure> {
        let result=(|| {
        authority.recheck()?;let raw=pipe.as_raw_handle();
        if !matches!(authority.role,ChannelRole::Owner){return Err("Windows consumer cannot attach owner receiver".into());}
        pipe_name(raw,&authority.endpoint)?;
        let mut flags=0;let mut state=0;
        if unsafe{GetNamedPipeInfo(raw,&mut flags,null_mut(),null_mut(),null_mut())}==0
            || flags&5!=5 // server end and message-type pipe
            || unsafe{GetNamedPipeHandleStateW(raw,&mut state,null_mut(),null_mut(),null_mut(),null_mut(),0)}==0
            || state&2==0 {return Err("server message pipe required".into());}
        let mut ios=unsafe{zeroed::<IoStatus>()};let mut mode:u32=0;
        // FILE_MODE_INFORMATION=16. A stack-backed ReadFile must never run on
        // an asynchronous handle: pending I/O could retain the stack buffer.
        if unsafe{NtQueryInformationFile(raw,&mut ios,(&mut mode as *mut u32).cast(),4,16)}<0
            || ios.information!=4 || mode&0x30==0 {return Err("synchronous native pipe required".into());}
        PipePeer::capture(raw,&mut authority)
        })();
        match result {Ok(peer)=>Ok(Self{pipe,peer,authority,frozen:Arc::new(AtomicBool::new(false))}),
            Err(error)=>Err(WindowsEndpointFailure{error,uncertain:Some(ManuallyDrop::new(pipe)),authority:Some(ManuallyDrop::new(authority))})}
    }
    pub(super) fn close_transport(self)->WindowsTransportClose {
        self.frozen.store(true,Ordering::SeqCst);
        let Self{pipe,peer,authority,frozen:_}=self;
        let mut report=WindowsTransportClose::new(authority,None);
        report.pipe_failure=WindowsTransportClose::close_once(pipe.into_raw_handle(),"receiver pipe",None,None);
        let held=ManuallyDrop::new(peer.process);
        report.peer_failure=WindowsTransportClose::close_once(held.0,"client process",Some(peer.pid),Some(peer.creation));report
    }
    fn current(&mut self)->Result<()> {if self.frozen.load(Ordering::SeqCst){return Err("Windows clock channel frozen".into());}
        self.authority.recheck()?;pipe_name(self.pipe.as_raw_handle(),&self.authority.endpoint)?;
        pipe_security(self.pipe.as_raw_handle(),&self.authority)?;
        self.peer.recheck(self.pipe.as_raw_handle())?;self.authority.recheck()}
    fn request(&mut self)->Result<AuthenticatedRequest> {
        let result=self.request_inner();if result.is_err(){self.frozen.store(true,Ordering::SeqCst);} result
    }
    fn request_inner(&mut self)->Result<AuthenticatedRequest> {
        self.current()?;let mut frame=[0u8;81];let mut received=0;
        // Exactly one bounded message. ERROR_MORE_DATA is an oversized message,
        // not a reason to allocate, append chunks or change the transport bound.
        if unsafe{ReadFile(self.pipe.as_raw_handle(),frame.as_mut_ptr().cast(),81,&mut received,null_mut())}==0
            || received!=81 {return Err(last());}
        self.current()?;let sid=self.message_sid()?;self.current()?;
        if sid!=self.peer.sid || &frame[..8]!=b"MCLCIPC1"
            || !([1,2].contains(&frame[8]) || ([3,4].contains(&frame[8]) && self.authority.async_message))
            || frame[9..41]==[0;32] || frame[41..73]!=self.authority.context {return Err("Windows clock message binding refused".into());}
        if frame[8]==4 && frame[73..81]!=[0;8] {return Err("owner-selected operation forbids caller counter".into());}
        Ok(AuthenticatedRequest{opcode:frame[8],operation:frame[9..41].try_into().map_err(|_|"operation length")?,
            context:self.authority.context,expected_sequence:u64::from_be_bytes(frame[73..81].try_into().map_err(|_|"sequence length")?),
            commitment:Sha256::digest(frame).into()})
    }
    pub(super) fn serve_one(&mut self,owner:&super::protected_clock_owner::ProtectedOwnerDispatcher)->Result<()> {
        let mut lifetime=WindowsCallLifetime::begin(&self.frozen);
        let result=self.serve_inner(owner);lifetime.finished(result.is_err());result
    }
    fn serve_inner(&mut self,owner:&super::protected_clock_owner::ProtectedOwnerDispatcher)->Result<()> {
        let request=self.request()?;
        self.current()?;
        if owner.channel_context()?!=request.context {return Err("Windows owner channel context differs".into());}
        let operation=super::protected_clock_lineage_v1::Operation::authenticated_document(request.operation,request.commitment)
            .map_err(|error|format!("Windows exact operation refused: {error:?}"))?;
        // Caller frame contains neither calibration nor a proposed floor.
        // The current genuine owner chooses its own floor. Journal intent,
        // head transition and journal completion are durable before any reply.
        if [3,4].contains(&request.opcode) {
            let quote=if request.opcode==4 {owner.fresh_selected_operation(operation)?}
                else {owner.fresh_operation(request.expected_sequence,operation)?};
            self.current()?;
            if owner.channel_context()?!=request.context {return Err("fresh owner context changed".into());}
            let response=quote.encode(request.context)?;let mut written=0;
            if unsafe{WriteFile(self.pipe.as_raw_handle(),response.as_ptr().cast(),775,&mut written,null_mut())}==0
                || written!=775 {return Err("fresh quote reply unknown; exact operation retained".into());}
            self.current()?;
            if owner.channel_context()?!=request.context {return Err("fresh owner context revoked during reply".into());}
            return Ok(());
        }
        let outcome=owner.reserve_operation(request.expected_sequence,operation)?;
        self.current()?;
        if owner.channel_context()?!=request.context {return Err("Windows owner context changed after durable reservation".into());}
        let mut response=[0u8;89];response[..8].copy_from_slice(b"MCLCIPR1");
        response[8..40].copy_from_slice(&request.operation);response[40..72].copy_from_slice(&request.context);
        response[72..80].copy_from_slice(&outcome.sequence.to_be_bytes());
        response[80..88].copy_from_slice(&outcome.floor.to_be_bytes());response[88]=u8::from(outcome.qualified);
        let mut written=0;
        if unsafe{WriteFile(self.pipe.as_raw_handle(),response.as_ptr().cast(),89,&mut written,null_mut())}==0
            || written!=89 {return Err("Windows reply delivery unknown; durable exact retry required".into());}
        self.current()
    }
    fn message_sid(&mut self)->Result<Vec<u8>> {message_sid_from_pipe(&self.pipe)}
}

fn message_sid_from_pipe(pipe:&File)->Result<Vec<u8>> {
        no_impersonation()?;
        let mut token=NativeHandle::prepared("message-Identification-token",NativeReleaseKind::Handle,pipe.as_raw_handle());
        if unsafe{ImpersonateNamedPipeClient(pipe.as_raw_handle())}==0 {return Err(last());}
        let mut impersonation=MessageImpersonation{armed:true};
        // No storage, authority, callback, asynchronous yield or owner dispatch
        // occurs while impersonating. Catch ordinary errors until restoration.
        let mut value=null_mut();let opened=unsafe{OpenThreadToken(GetCurrentThread(),8,1,&mut value)};
        let error=if opened==0{Some(unsafe{GetLastError()})}else{None};if opened!=0{token.bind(value)}else{token.unconfirmed(value)};
        token.observed("message-token-open",i64::from(opened),error);
        let queried=(||{if opened==0{return Err(format!("message token open refused {:?}",error));}
            let mut level=0u32;let mut needed=0;
            let captured=unsafe{GetTokenInformation(token.0,9,(&mut level as *mut u32).cast(),4,&mut needed)};
            let error=if captured==0{Some(unsafe{GetLastError()})}else{None};token.observed("message-token-level",i64::from(captured),error);
            token.observation_facts(u64::from(level),u64::from(needed));
            {let core=token.1.as_mut().expect("original message-token custody");core.token_level=Some(level);core.token_needed=Some(needed);}
            if captured==0||needed!=4||level!=1{return Err("pipe client Identification SQOS required".into());}
            token_sid(&mut token)})();
        let observed=token.finish(queried);
        // Returning into private owner code under an unresolved impersonation
        // token is unsafe. Fail-stop this process, rather than unwind private
        // guards or perform further I/O with ambiguous security context.
        impersonation.restore();
        observed
    }

/// A newly selected private endpoint profile; the old synchronous profile is
/// deliberately ineligible. This owns actual kernel-woken I/O, not a clock
/// value cache. The caller must run exchange on its owned blocking worker.
/// Ordinary Node's asynchronous private-query interface. Constructors require
/// the installed opaque consumer authority, whose current-code/qualification
/// gates remain mandatory. No synchronous VoteClock implementation blocks an
/// actor/UI, and no floor/Boolean-only endpoint supplies this interface.
pub(super) struct InstalledFreshConsumer {inner:Option<Box<overlapped::Consumer>>}
pub(super) struct IdleConsumerRetainedClose {
    native:Option<std::result::Result<overlapped::AsyncRetainedTransportClose,overlapped::AsyncRetainedCloseFailure>>,
    consumer:Option<ManuallyDrop<InstalledFreshConsumer>>,
}
impl IdleConsumerRetainedClose {pub(super) fn retained_handles_closed(&self)->bool {
    self.consumer.is_none()&&self.native.as_ref().is_some_and(|r|r.as_ref().is_ok_and(|r|r.retained_handles_closed()))
}}
impl Drop for InstalledFreshConsumer {
    fn drop(&mut self){if let Some(mut consumer)=self.inner.take(){consumer.revoke_abandoned();
        let _custody=Box::into_raw(consumer);}}
}
pub(super) struct InstalledFreshQuery {inner:overlapped::OwnedAsyncQuery,
    returned:Option<Box<std::mem::MaybeUninit<overlapped::Consumer>>>}
/// Owns the exact cancellation event identity until a separately observed
/// explicit lifecycle close. Ordinary Drop supplies no closure assertion.
pub(super) struct FreshRequestCancellation {inner:ManuallyDrop<Arc<overlapped::Cancellation>>}
impl FreshRequestCancellation {
    /// A finite owned cancellation event, independent of any secret or clock
    /// authority. Its caller must retain it until the owner worker joins.
    pub(super) fn new_owner_cancellation()->Result<Self>{
        Ok(Self{inner:ManuallyDrop::new(overlapped::Cancellation::new()?)})
    }
    pub(super) fn cancel(&self)->Result<()>{self.inner.cancel()}
    /// Private caller proves its ORIGINAL worker joined and retained no I/O.
    /// Sharing or failed native close keeps exact event custody without retry.
    fn close_joined(self)->std::result::Result<(),CompletedCancellationFailure> {
        match ManuallyDrop::into_inner(self.inner).close_after_join(){
            Ok(None)=>Ok(()),Ok(Some(error))=>Err(CompletedCancellationFailure::Native(ManuallyDrop::new(error))),
            Err(shared)=>Err(CompletedCancellationFailure::Shared(ManuallyDrop::new(shared))),
        }
    }
}
impl InstalledFreshQuery {
    pub(super) fn cancellation(&self)->FreshRequestCancellation{
        FreshRequestCancellation{inner:ManuallyDrop::new(self.inner.cancellation())}
    }
}
pub(super) struct JoinedFreshRequest {consumer:InstalledFreshConsumer,reply:Result<overlapped::FreshReply>,
    cancellation:ManuallyDrop<Arc<overlapped::Cancellation>>}
pub(super) struct PreparedFreshAttempt {consumer:InstalledFreshConsumer,receipt:overlapped::FreshReply,
    cancellation:ManuallyDrop<Arc<overlapped::Cancellation>>}
pub(super) struct PreparedConsumerRetainedClose {
    native:Option<std::result::Result<overlapped::AsyncRetainedTransportClose,overlapped::AsyncRetainedCloseFailure>>,
    cancellation:std::result::Result<(),CompletedCancellationFailure>,
    consumer:Option<ManuallyDrop<InstalledFreshConsumer>>,
}
impl PreparedConsumerRetainedClose {pub(super) fn retained_handles_closed(&self)->bool {
    self.consumer.is_none()&&self.cancellation.is_ok()
        &&self.native.as_ref().is_some_and(|r|r.as_ref().is_ok_and(|r|r.retained_handles_closed()))
}}
pub(super) enum FreshRequestFailure {
    Connect(ManuallyDrop<overlapped::AsyncEndpointFailure>),
    Start(ManuallyDrop<overlapped::QueryStartFailure>),
    Joined{error:String,consumer:ManuallyDrop<InstalledFreshConsumer>,cancellation:ManuallyDrop<Arc<overlapped::Cancellation>>},
    Prepared{error:String,attempt:ManuallyDrop<PreparedFreshAttempt>},
    CancellationClose{consumer:ManuallyDrop<InstalledFreshConsumer>,
        custody:ManuallyDrop<CompletedCancellationFailure>},
}
/// Exact completed event custody; neither variant retries CloseHandle.
pub(super) enum CompletedCancellationFailure {
    Shared(ManuallyDrop<Arc<overlapped::Cancellation>>),
    Native(ManuallyDrop<overlapped::EventCloseFailure>),
}
// Exclusive native failure custody only. Kernel handles are not thread-local;
// any retained OVERLAPPED allocation remains heap-stable. No operation/close
// method is exposed on this error and transfer cannot retry an unknown effect.
// This is confined to the native custody module, never a Node-side assertion.
unsafe impl Send for FreshRequestFailure {}
impl InstalledFreshConsumer {
    /// Linear idle value: repeat the existing no-pending-I/O/current predicate
    /// and same once-close path. Completed query cancellation already closed.
    pub(super) fn close_idle_retained(mut self)->IdleConsumerRetainedClose {
        let mut report=IdleConsumerRetainedClose{native:None,consumer:None};
        let ready=self.inner.as_mut().ok_or_else(||"idle Windows consumer absent".to_string())
            .and_then(|consumer|consumer.require_completed_close_ready());
        if ready.is_err(){report.consumer=Some(ManuallyDrop::new(self));return report;}
        let consumer=self.inner.take().expect("checked original idle Windows consumer");
        report.native=Some((*consumer).close_retained());report
    }
    pub(super) fn connect(authority:InstalledWindowsAuthority)->std::result::Result<Self,FreshRequestFailure>{
        let mut custody=Box::<overlapped::Consumer>::new_uninit();
        match overlapped::Consumer::connect(authority){
            Ok(inner)=>{custody.write(inner);Ok(Self{inner:Some(unsafe{custody.assume_init()})})},
            Err(error)=>Err(FreshRequestFailure::Connect(ManuallyDrop::new(error))),
        }
    }
    pub(super) fn begin_request(mut self)->std::result::Result<InstalledFreshQuery,FreshRequestFailure>{
        // Reserve result-stage custody before the query may have native effects.
        let returned=Some(Box::<overlapped::Consumer>::new_uninit());
        let original=self.inner.take().expect("installed consumer owned");
        let inner=*original;
        inner.begin_fresh_request().map(|inner|InstalledFreshQuery{inner,returned})
            .map_err(|error|FreshRequestFailure::Start(ManuallyDrop::new(error)))
    }
}
impl std::future::Future for InstalledFreshQuery {
    type Output=Result<JoinedFreshRequest>;
    fn poll(self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>)->std::task::Poll<Self::Output>{
        let this=self.get_mut();
        match std::future::Future::poll(std::pin::Pin::new(&mut this.inner),cx){
            std::task::Poll::Pending=>std::task::Poll::Pending,
            std::task::Poll::Ready(Err(error))=>std::task::Poll::Ready(Err(error)),
            std::task::Poll::Ready(Ok(outcome))=>{let(consumer,reply,cancellation)=outcome.into_parts();
                let mut returned=this.returned.take().expect("preallocated returned consumer");returned.write(consumer);
                let inner=Some(unsafe{returned.assume_init()});
                std::task::Poll::Ready(Ok(JoinedFreshRequest{consumer:InstalledFreshConsumer{inner},reply,
                    cancellation:ManuallyDrop::new(cancellation)}))},
        }
    }
}
impl JoinedFreshRequest {
    /// Invoke immediately after the genuine owned task joined, before the
    /// pure actor signing gate. Every attempt obtains a NEW authenticated query.
    /// The retained receipt is CURRENT-reconstructed at gate use. Nil/exact
    /// durable vote replay can avoid preparing this query entirely.
    pub(super) fn prepare_attempt(self)->std::result::Result<PreparedFreshAttempt,FreshRequestFailure>{
        let Self{mut consumer,reply,cancellation}=self;
        let result=reply.and_then(|reply|{consumer.inner.as_mut().expect("joined consumer owned").current_delivery(&reply)?;Ok(reply)});
        match result {
            Ok(receipt)=>Ok(PreparedFreshAttempt{consumer,receipt,cancellation}),
            Err(error)=>Err(FreshRequestFailure::Joined{error,consumer:ManuallyDrop::new(consumer),cancellation}),
        }
    }
}
impl PreparedFreshAttempt {
    /// The receipt is constructed only after original query completion. This
    /// separate shutdown route checks no I/O/pending plus own CURRENT custody;
    /// it mints neither a fresh time reading nor a new owner operation.
    pub(super) fn close_retained(mut self)->std::result::Result<PreparedConsumerRetainedClose,ManuallyDrop<Self>> {
        let ready=self.consumer.inner.as_mut().ok_or_else(||"prepared consumer absent".to_string())
            .and_then(|consumer|consumer.require_completed_close_ready());
        if ready.is_err(){return Err(ManuallyDrop::new(self));}
        let Self{consumer,receipt:_,cancellation}=self;
        let cancellation=match ManuallyDrop::into_inner(cancellation).close_after_join(){
            Ok(None)=>Ok(()),Ok(Some(error))=>Err(CompletedCancellationFailure::Native(ManuallyDrop::new(error))),
            Err(shared)=>Err(CompletedCancellationFailure::Shared(ManuallyDrop::new(shared))),
        };
        let mut report=PreparedConsumerRetainedClose{native:None,cancellation,consumer:None};
        if report.cancellation.is_err(){report.consumer=Some(ManuallyDrop::new(consumer));return Ok(report);}
        let mut consumer=consumer;
        let owned=consumer.inner.take().expect("checked original completed consumer");
        report.native=Some((*owned).close_retained());Ok(report)
    }
    pub(super) fn recheck_installed_only(&mut self)->Result<()> {
        let consumer=self.consumer.inner.as_mut().ok_or_else(||"prepared consumer absent".to_string())?;
        consumer.recheck_installed_only()
    }
    pub(super) fn capture_current(&mut self)->Result<Option<mutiny_consensus_v8::activation_attestation_v1::ElapsedCapture>> {
        let delivery=self.consumer.inner.as_mut().ok_or_else(||"prepared consumer absent".to_string())?
            .recheck_delivery(&self.receipt)?;
        Ok(delivery.elapsed())
    }
    /// Reconstruct at the actual gate entry. The retained receipt authorizes only
    /// this exclusive attempt; it is never a stored qualification result.
    pub(super) fn reading(&mut self)->Result<mutiny_consensus_v8::vote_clock_v1::ClockReading>{
        let delivery=self.consumer.inner.as_mut().ok_or_else(||"prepared consumer absent".to_string())?
            .recheck_delivery(&self.receipt)?;Ok(delivery.reading())
    }
    /// One capture for the prepared operation only, NOT an implementation of a
    /// reusable activation Elapsed source. Every later custody check requires
    /// another fresh owner query/current reconstruction, rather than this value.
    pub(super) fn into_parts(mut self)->Result<(InstalledFreshConsumer,
        Option<mutiny_consensus_v8::activation_attestation_v1::ElapsedCapture>,FreshRequestCancellation)>{
        let delivery=self.consumer.inner.as_mut().ok_or_else(||"prepared consumer absent".to_string())?
            .recheck_delivery(&self.receipt)?;
        Ok((self.consumer,delivery.elapsed(),FreshRequestCancellation{inner:self.cancellation}))
    }
    /// The query's original runtime-owned task already returned this prepared
    /// stage. CURRENT reconstruction explicitly requires io=None/pending=None.
    /// Only then attempt the exact last-owned cancellation event close once.
    /// No live I/O buffer or unknown event is released by this transition.
    pub(super) fn finish_connection(mut self)->std::result::Result<InstalledFreshConsumer,FreshRequestFailure> {
        let current=self.consumer.inner.as_mut().ok_or_else(||"prepared consumer absent".to_string())
            .and_then(|consumer|consumer.recheck_delivery(&self.receipt));
        if let Err(error)=current {
            return Err(FreshRequestFailure::Prepared{error,attempt:ManuallyDrop::new(self)});
        }
        let Self{mut consumer,receipt:_,cancellation}=self;
        match ManuallyDrop::into_inner(cancellation).close_after_join() {
            Ok(None)=>Ok(consumer),
            Ok(Some(error))=>{
                if let Some(inner)=consumer.inner.as_mut(){inner.revoke_abandoned();}
                Err(FreshRequestFailure::CancellationClose{consumer:ManuallyDrop::new(consumer),
                    custody:ManuallyDrop::new(CompletedCancellationFailure::Native(ManuallyDrop::new(error)))})
            },
            Err(shared)=>{
                if let Some(inner)=consumer.inner.as_mut(){inner.revoke_abandoned();}
                Err(FreshRequestFailure::CancellationClose{consumer:ManuallyDrop::new(consumer),
                    custody:ManuallyDrop::new(CompletedCancellationFailure::Shared(ManuallyDrop::new(shared)))})
            },
        }
    }
}

pub(super) use overlapped::{InstalledAsyncOwnerServer,AsyncOwnerServerCreationFailure,OwnerIpcStep};
#[path="protected_clock_windows_worker.rs"]
mod owner_worker;
pub(super) use owner_worker::{OwnedOwnerWorker,JoinedOwnerWorker,OwnerWorkerStartFailure,JoinedOwnerRetainedClose};
mod overlapped {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    #[repr(C)] struct Overlapped { internal:usize,internal_high:usize,offset:u32,offset_high:u32,event:Ptr }
    #[link(name="kernel32")] unsafe extern "system" {
        fn DuplicateHandle(source_process:Ptr,source:Ptr,target_process:Ptr,target:*mut Ptr,access:u32,inherit:i32,options:u32)->i32;
        fn SetNamedPipeHandleState(pipe:Ptr,mode:*const u32,max:*const u32,timeout:*const u32)->i32;
        fn CreateEventW(attributes:Ptr,manual:i32,initial:i32,name:*const u16)->Ptr;
        fn SetEvent(event:Ptr)->i32;
        fn WaitForMultipleObjects(count:u32,handles:*const Ptr,all:i32,timeout:u32)->u32;
        fn CancelIoEx(file:Ptr,overlapped:*mut Overlapped)->i32;
        fn GetOverlappedResult(file:Ptr,overlapped:*mut Overlapped,bytes:*mut u32,wait:i32)->i32;
    }
    /// Original unnamed manual-reset event, with no externally supplied handle.
    /// It remains retained until the worker is joined. No automatic close claims.
    pub(super) struct Cancellation { event:Ptr }
    pub(super) struct EventCloseFailure {event:Ptr,error:u32}
    unsafe impl Send for Cancellation {}
    unsafe impl Sync for Cancellation {}
    impl Cancellation {
        pub(super) fn new()->Result<Arc<Self>> {
            let event=unsafe{CreateEventW(null_mut(),1,0,null())};
            if event.is_null(){return Err(last());}Ok(Arc::new(Self{event}))
        }
        pub(super) fn cancel(&self)->Result<()> {
            if unsafe{SetEvent(self.event)}==0{return Err(last());}Ok(())
        }
        // Event lifetime is independent of any dropped waiter. Explicit close
        // is permitted only after caller-owned worker joins and last Arc exists.
        pub(super) fn close_after_join(self:Arc<Self>)->std::result::Result<Option<EventCloseFailure>,Arc<Self>> {
            let owned=Arc::try_unwrap(self)?;
            Ok(if unsafe{CloseHandle(owned.event)}==0{
                Some(EventCloseFailure{event:owned.event,error:unsafe{GetLastError()}})
            }else{None})
        }
    }
    struct IoCell {overlapped:Overlapped,buffer:[u8;775]}
    #[derive(Clone,Copy)]
    enum NativeIoKind {Connect,Read,Write}
    enum NativeIoOutcome {Completed, CancelledSettledBeforeDispatch}
    /// A worker stop can be clean only while no authenticated operation has
    /// entered dispatch. This supplies no logical failure result to a client.
    pub(in super::super) enum OwnerIpcStep {Continue, StoppedBeforeOperation}
    struct PendingIo {cell:ManuallyDrop<Box<IoCell>>,active:bool,close_attempted:bool,close_error:Option<u32>}
    impl PendingIo {
        fn new()->Result<Self> {
            let mut cell=Box::new(IoCell{overlapped:unsafe{zeroed()},buffer:[0;775]});
            cell.overlapped.event=unsafe{CreateEventW(null_mut(),1,0,null())};
            if cell.overlapped.event.is_null(){return Err(last());}
            Ok(Self{cell:ManuallyDrop::new(cell),active:false,close_attempted:false,close_error:None})
        }
        fn begin(&mut self,pipe:Ptr,write:bool,length:u32)->Result<()> {
            if length as usize>self.cell.buffer.len(){return Err("owned I/O fixed bound refused".into());}
            self.active=true; // Before the syscall: panic/drop retains all I/O memory.
            let ov=(&mut self.cell.overlapped as *mut Overlapped).cast();
            let success=if write{unsafe{WriteFile(pipe,self.cell.buffer.as_ptr().cast(),length,null_mut(),ov)}}
                else{unsafe{ReadFile(pipe,self.cell.buffer.as_mut_ptr().cast(),length,null_mut(),ov)}};
            if success==0 {
                let error=unsafe{GetLastError()};
                if error!=997 { // Not pending: native call has completed in error.
                    self.active=false;return Err(format!("overlapped I/O refused {error}"));
                }
            }Ok(())
        }
        /// Kernel wait is on completion or exact owned cancellation, never a
        /// timer/poll cadence. Cancellation is not a logical non-consumption.
        fn wait(&mut self,pipe:Ptr,cancel:&Cancellation,length:u32,kind:NativeIoKind)->Result<()> {
            match self.wait_owned(pipe,cancel,length,kind)? {
                NativeIoOutcome::Completed=>Ok(()),
                NativeIoOutcome::CancelledSettledBeforeDispatch=>Err("request cancelled/unknown: original I/O settled".into()),
            }
        }
        fn wait_owned(&mut self,pipe:Ptr,cancel:&Cancellation,length:u32,kind:NativeIoKind)->Result<NativeIoOutcome> {
            let handles=[self.cell.overlapped.event,cancel.event];
            let wake=unsafe{WaitForMultipleObjects(2,handles.as_ptr(),0,u32::MAX)};
            if wake!=0 {
                let cancel_result=unsafe{CancelIoEx(pipe,&mut self.cell.overlapped)};
                let cancel_error=if cancel_result==0{unsafe{GetLastError()}}else{0};
                // ERROR_NOT_FOUND can race genuine completion. Always settle
                // the original OVERLAPPED before considering memory release.
                let mut bytes=0;
                let result=unsafe{GetOverlappedResult(pipe,&mut self.cell.overlapped,&mut bytes,1)};
                let result_error=if result==0{unsafe{GetLastError()}}else{0};
                if result!=0 || result_error==995 {self.active=false;}
                // ConnectNamedPipe byte output is UNDEFINED: it supplies no
                // completion/cancellation authority. Read/write keep their
                // existing count predicates. This is settled native stop only,
                // never evidence that the client's logical request failed.
                if wake==1 && (cancel_error==0 || cancel_error==1168)
                    && result==0 && result_error==995
                    && (matches!(kind,NativeIoKind::Connect)||bytes==0) {
                    return Ok(NativeIoOutcome::CancelledSettledBeforeDispatch);
                }
                return Err(format!("request cancelled/unknown: wake={wake}, cancel={cancel_error}, result={result_error}"));
            }
            let mut bytes=0;
            let result=unsafe{GetOverlappedResult(pipe,&mut self.cell.overlapped,&mut bytes,0)};
            if result==0 {
                let error=unsafe{GetLastError()};
                // ERROR_IO_INCOMPLETE means memory remains natively owned.
                if error!=996 {self.active=false;}
                return Err(format!("overlapped completion refused {error}"));
            }
            self.active=false;
            if !matches!(kind,NativeIoKind::Connect)&&bytes!=length{return Err("overlapped exact single-message length differs".into());}Ok(NativeIoOutcome::Completed)
        }
        fn close_settled(&mut self)->Result<()> {
            if self.active{return Err("unsettled native I/O quarantined".into());}
            if self.close_attempted{return Err("prior event close remains quarantined; no automatic retry".into());}
            let event=self.cell.overlapped.event;
            self.close_attempted=true;
            if unsafe{CloseHandle(event)}==0{
                let error=unsafe{GetLastError()};self.close_error=Some(error);
                return Err(format!("native event close unknown {error}"));
            }
            // Free only after native settlement and observed event close.
            unsafe{ManuallyDrop::drop(&mut self.cell)};Ok(())
        }
    }
    // No Drop releases the cell/event. Unknown native completion owns these
    // allocations until explicit exact settlement, or process termination.
    pub(super) struct Consumer {
        pipe:File,peer:PipePeer,authority:InstalledWindowsAuthority,
        frozen:Arc<AtomicBool>,pending:Option<PendingReservation>,io:Option<PendingIo>,
        mode_handle:Option<Ptr>,
        last_quote_sequence:Option<u64>,elapsed_incarnation:Option<[u8;32]>,
    }
    pub(super) struct AsyncEndpointFailure {
        error:String,pipe:Option<ManuallyDrop<File>>,duplicate:Option<Ptr>,
        authority:ManuallyDrop<InstalledWindowsAuthority>,
    }
    pub(super) struct AsyncCloseFailure {error:String,consumer:ManuallyDrop<Consumer>}
    pub(super) struct AsyncTransportClose {
        pipe:Option<WindowsUnclosedHandle>,peer:Option<WindowsUnclosedHandle>,mode:Option<WindowsUnclosedHandle>,
        installed_guard:ManuallyDrop<super::super::native_nts_deployment_record::NativeSelectionGuard>,
        pending:Option<PendingReservation>,
    }
    pub(super) struct AsyncRetainedTransportClose {
        selection:std::result::Result<super::super::native_nts_deployment_record::SelectionRetainedClose,
            ManuallyDrop<super::super::native_nts_deployment_record::NativeSelectionGuard>>,
    }
    impl AsyncRetainedTransportClose {pub(super) fn retained_handles_closed(&self)->bool {
        self.selection.as_ref().is_ok_and(|r|r.retained_handles_closed())
    }}
    pub(super) enum AsyncRetainedCloseFailure {
        Native(ManuallyDrop<AsyncCloseFailure>),Uncertain(ManuallyDrop<AsyncTransportClose>),
    }
    impl AsyncTransportClose {
        pub(super) fn transport_handles_closed(&self)->bool{self.pipe.is_none()&&self.peer.is_none()&&self.mode.is_none()}
        fn close_installed_retained(self)->std::result::Result<AsyncRetainedTransportClose,AsyncRetainedCloseFailure> {
            if !self.transport_handles_closed() || self.pending.is_some(){return Err(AsyncRetainedCloseFailure::Uncertain(ManuallyDrop::new(self)));}
            Ok(AsyncRetainedTransportClose{selection:ManuallyDrop::into_inner(self.installed_guard).close_retained()})
        }
    }
    // Exclusive transfer only, never Sync: original process-local kernel pipe,
    // process and event handles remain valid across this process's threads.
    // All installation objects are exclusively retained; every operation again
    // rejects a thread impersonation token and rechecks actual process/current
    // authority. Native buffers are heap-stable and never borrowed by callers.
    unsafe impl Send for Consumer {}
    /// Only an exact live authenticated endpoint exchange constructs this raw
    /// receipt. It carries NO cached qualification. Re-evaluate at actual use
    /// through the same retained Consumer, never deserialize into authority.
    pub(super) struct FreshReply {frame:[u8;775],operation:[u8;32],expected_sequence:Option<u64>}
    /// Immediate result of current reconstruction, never a persisted or cached
    /// healthy flag. The factory must perform a new exchange for every fresh
    /// clock request; only attempt-local use may retain this exact result.
    pub(super) struct CurrentDelivery {
        reserved_floor:Option<u64>,elapsed:Option<mutiny_consensus_v8::activation_attestation_v1::ElapsedCapture>,
        current_sequence:u64,
    }
    impl CurrentDelivery {
        pub(super) fn reading(&self)->mutiny_consensus_v8::vote_clock_v1::ClockReading {
            match self.reserved_floor {Some(floor)=>mutiny_consensus_v8::vote_clock_v1::ClockReading::Qualified{utc_seconds:floor/1000},
                None=>mutiny_consensus_v8::vote_clock_v1::ClockReading::Unqualified}
        }
        pub(super) fn elapsed(self)->Option<mutiny_consensus_v8::activation_attestation_v1::ElapsedCapture>{self.elapsed}
        pub(super) fn current_sequence(&self)->u64{self.current_sequence}
    }
    struct AsyncQuerySlot {consumer:Option<Consumer>,outcome:Option<WorkerOutcome>}
    struct AbandonedAsyncQuery {
        slot:Arc<std::sync::Mutex<AsyncQuerySlot>>,cancellation:Arc<Cancellation>,
        task:Option<tokio::task::JoinHandle<()>>,
    }
    /// The native exchange runs on a runtime-owned blocking worker. Polling
    /// this future waits on Tokio's task completion/waker; it never blocks the
    /// consensus actor/UI on kernel I/O or invents a polling cadence/deadline.
    /// Drop signals unknown cancellation and retains every ownership object.
    pub(super) struct OwnedAsyncQuery {
        custody:Option<Box<AbandonedAsyncQuery>>,frozen:Arc<AtomicBool>,finished:bool,
    }
    pub(super) struct QueryStartFailure {
        error:String,consumer:Option<Consumer>,unknown:Option<ManuallyDrop<Box<AbandonedAsyncQuery>>>,
    }
    impl OwnedAsyncQuery {
        pub(super) fn cancellation(&self)->Arc<Cancellation>{self.custody.as_ref().expect("owned query custody").cancellation.clone()}
    }
    impl std::future::Future for OwnedAsyncQuery {
        type Output=Result<WorkerOutcome>;
        fn poll(self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>)->std::task::Poll<Self::Output> {
            let this=self.get_mut();
            if this.finished{return std::task::Poll::Ready(Err("owned query already consumed".into()));}
            let Some(custody)=this.custody.as_mut() else{return std::task::Poll::Ready(Err("owned query custody absent".into()));};
            let task=custody.task.as_mut().expect("owned query task");
            match std::future::Future::poll(std::pin::Pin::new(task),cx) {
                std::task::Poll::Pending=>std::task::Poll::Pending,
                std::task::Poll::Ready(result)=>{
                    // Runtime completion confirms the actual blocking closure
                    // returned. Native I/O completion was settled inside it.
                    custody.task=None;
                    if let Err(error)=result {this.frozen.store(true,Ordering::SeqCst);
                        return std::task::Poll::Ready(Err(format!("owned query task unknown: {error}")));}
                    let outcome=custody.slot.lock().unwrap_or_else(|p|p.into_inner()).outcome.take();
                    let Some(outcome)=outcome else {this.frozen.store(true,Ordering::SeqCst);
                        return std::task::Poll::Ready(Err("owned query finished without retained outcome".into()));};
                    this.finished=true;this.custody=None;std::task::Poll::Ready(Ok(outcome))
                },
            }
        }
    }
    impl Drop for OwnedAsyncQuery {
        fn drop(&mut self) {
            if self.finished{return;}
            self.frozen.store(true,Ordering::SeqCst);
            if let Some(custody)=self.custody.take(){let _signal=custody.cancellation.cancel();
                // Preallocated before any task/request effects. No detach-and-
                // release, synchronous actor-thread join, retry or inferred
                // failure. The original task/slot/consumer remain retained.
                let _unknown=Box::into_raw(custody);
            }
        }
    }
    pub(super) struct WorkerOutcome {consumer:Consumer,reply:Result<FreshReply>,cancellation:Arc<Cancellation>}
    impl WorkerOutcome {
        pub(super) fn into_parts(self)->(Consumer,Result<FreshReply>,Arc<Cancellation>){
            (self.consumer,self.reply,self.cancellation)
        }
    }
    pub(super) struct Worker {
        cancellation:Arc<Cancellation>,
        join:Option<std::thread::JoinHandle<WorkerOutcome>>,
        frozen:Arc<AtomicBool>,
        quarantine:Option<Box<std::mem::MaybeUninit<WorkerOutcome>>>,
    }
    pub(super) struct WorkerStartFailure {error:String,consumer:Consumer,cancellation:Arc<Cancellation>}
    impl Worker {
        pub(super) fn cancellation(&self)->Arc<Cancellation>{self.cancellation.clone()}
        /// Invoke from the selected caller-owned blocking coordinator, never
        /// its serialized consensus actor or UI thread. Each worker holds one
        /// exact operation only; this joins the actual owned OS thread.
        pub(super) fn join(mut self)->Result<WorkerOutcome> {
            let handle=self.join.take().ok_or("clock worker join already taken")?;
            match handle.join(){Ok(outcome)=>Ok(outcome),Err(_)=>{
                self.frozen.store(true,Ordering::SeqCst);Err("clock worker panic; request unresolved".into())}}
        }
    }
    impl Drop for Worker {
        fn drop(&mut self){
            if let Some(handle)=self.join.take(){
                // Abandonment is cancellation/unknown, never a failed logical
                // admission. This value is confined to a blocking coordinator;
                // cancellation waits for native settlement before the worker
                // can return. There is no detach-and-release of native buffers.
                self.frozen.store(true,Ordering::SeqCst);
                let _signal=self.cancellation.cancel();
                match handle.join(){Ok(outcome)=>{
                    // Keep complete unresolved operation/current-guard/I/O
                    // custody after cancellation, until process termination.
                    let mut custody=self.quarantine.take().expect("preallocated worker quarantine");
                    custody.write(outcome);
                    let _quarantine=Box::into_raw(custody);
                },Err(_)=>{}}
            }
        }
    }
    impl Consumer {
        pub(super) fn recheck_installed_only(&mut self)->Result<()> {
            if self.frozen.load(Ordering::SeqCst){return Err("prepared consumer frozen".into());}
            // Native endpoint/peer revocation only: no RPC, elapsed sampling,
            // floor update or time qualification is introduced for exemptions.
            self.current()
        }
        pub(super) fn revoke_abandoned(&mut self){self.frozen.store(true,Ordering::SeqCst);}
        /// Genuine fresh request issuer: exact operation identity generated
        /// before effects; content is the fixed opcode4/current context frame.
        /// Owner chooses its authoritative counter. This method requires the
        /// already opaque installed endpoint Consumer, not raw SID/pipe data.
        pub(super) fn begin_fresh_request(self)->std::result::Result<OwnedAsyncQuery,QueryStartFailure> {
            let runtime=match tokio::runtime::Handle::try_current(){Ok(runtime)=>runtime,Err(error)=>{
                return Err(QueryStartFailure{error:error.to_string(),consumer:Some(self),unknown:None});}};
            let mut operation=[0u8;32];
            if getrandom::getrandom(&mut operation).is_err() || operation==[0;32] {
                return Err(QueryStartFailure{error:"fresh operation identity unavailable".into(),consumer:Some(self),unknown:None});
            }
            let cancellation=match Cancellation::new(){Ok(cancel)=>cancel,Err(error)=>{
                return Err(QueryStartFailure{error,consumer:Some(self),unknown:None});}};
            let frozen=self.frozen.clone();
            let slot=Arc::new(std::sync::Mutex::new(AsyncQuerySlot{consumer:Some(self),outcome:None}));
            let mut custody=Box::new(AbandonedAsyncQuery{slot:slot.clone(),cancellation:cancellation.clone(),task:None});
            let child_slot=slot.clone();let child_cancel=cancellation.clone();
            // The task closure holds only the shared custody until it actually
            // starts. Runtime shutdown before entry cannot drop the Consumer.
            let started=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||runtime.spawn_blocking(move||{
                let mut consumer=child_slot.lock().unwrap_or_else(|p|p.into_inner()).consumer.take()
                    .expect("exclusive fresh query consumer");
                let reply=match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
                    let mut lifetime=WindowsCallLifetime::begin(&consumer.frozen);
                    let result=consumer.exchange_inner(operation,None,&child_cancel);
                    lifetime.finished(result.is_err());result
                })){Ok(result)=>result,Err(_)=>{consumer.frozen.store(true,Ordering::SeqCst);
                    Err("fresh query unwind; exact operation unresolved".into())}};
                child_slot.lock().unwrap_or_else(|p|p.into_inner()).outcome=Some(WorkerOutcome{
                    consumer,reply,cancellation:child_cancel});
            })));
            match started {
                Ok(task)=>{custody.task=Some(task);Ok(OwnedAsyncQuery{custody:Some(custody),frozen,finished:false})},
                Err(_)=>{frozen.store(true,Ordering::SeqCst);let _signal=cancellation.cancel();
                    Err(QueryStartFailure{error:"blocking query start unknown; ownership retained".into(),
                        consumer:None,unknown:Some(ManuallyDrop::new(custody))})},
            }
        }
        /// After the owning worker joined. Unknown native I/O or event close
        /// keeps the entire consumer (including original file/peer/mode/current
        /// guard and buffer) in custody; no close/retry against an active I/O.
        /// The successful branch asserts transport handles only, never complete
        /// clock ownership/current-guard release or lineage replacement.
        pub(super) fn require_completed_close_ready(&mut self)->Result<()> {
            if self.io.is_some() || self.pending.is_some(){return Err("completed consumer retains unresolved I/O/operation".into());}
            self.current()
        }
        pub(super) fn close_retained(self)->std::result::Result<AsyncRetainedTransportClose,AsyncRetainedCloseFailure> {
            self.close_transport().map_err(|error|AsyncRetainedCloseFailure::Native(ManuallyDrop::new(error)))?
                .close_installed_retained()
        }
        pub(super) fn close_transport(mut self)->std::result::Result<AsyncTransportClose,AsyncCloseFailure>{
            self.frozen.store(true,Ordering::SeqCst);
            if let Some(io)=self.io.as_mut(){
                if let Err(error)=io.close_settled(){return Err(AsyncCloseFailure{error,consumer:ManuallyDrop::new(self)});}
                self.io=None;
            }
            let Self{pipe,peer,authority,frozen:_,pending,io:_,mode_handle,
                last_quote_sequence:_,elapsed_incarnation:_}=self;
            let mut report=AsyncTransportClose{pipe:None,peer:None,mode:None,
                installed_guard:ManuallyDrop::new(authority.current),pending};
            report.pipe=WindowsTransportClose::close_once(pipe.into_raw_handle(),"async consumer pipe",None,None);
            let held=ManuallyDrop::new(peer.process);
            report.peer=WindowsTransportClose::close_once(held.0,"async server process",Some(peer.pid),Some(peer.creation));
            if let Some(raw)=mode_handle{report.mode=WindowsTransportClose::close_once(raw,"read-only message-mode duplicate",None,None);}
            Ok(report)
        }
        pub(super) fn spawn_one(self,operation:[u8;32],expected_sequence:u64,cancellation:Arc<Cancellation>)
            ->std::result::Result<Worker,WorkerStartFailure> {
            let frozen=self.frozen.clone();
            // Reserve unknown-outcome custody before any child/native effect.
            let quarantine=Some(Box::new(std::mem::MaybeUninit::<WorkerOutcome>::uninit()));
            // Retain the consumer outside the closure until a successful
            // thread start. Spawn failure has no request I/O or new outcome.
            let slot=Arc::new(std::sync::Mutex::new(Some(self)));
            let child_slot=slot.clone();let child_cancel=cancellation.clone();
            let join=std::thread::Builder::new().name("mutiny-clock-exact-rpc".into()).spawn(move||{
                let mut consumer=child_slot.lock().unwrap_or_else(|p|p.into_inner()).take().expect("exclusive clock worker slot");
                let reply=match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
                    consumer.exchange_on_owned_worker(operation,expected_sequence,&child_cancel))){
                    Ok(reply)=>reply,Err(_)=>{consumer.frozen.store(true,Ordering::SeqCst);
                        Err("clock worker unwind; exact operation unresolved".into())}};
                WorkerOutcome{consumer,reply,cancellation:child_cancel}
            });
            match join {Ok(join)=>Ok(Worker{cancellation,join:Some(join),frozen,quarantine}),Err(error)=>{
                let consumer=slot.lock().unwrap_or_else(|p|p.into_inner()).take().expect("failed clock spawn retains consumer");
                Err(WorkerStartFailure{error:error.to_string(),consumer,cancellation})}}
        }
        pub(super) fn connect(mut authority:InstalledWindowsAuthority)->std::result::Result<Self,AsyncEndpointFailure> {
            if let Err(error)=authority.recheck(){return Err(AsyncEndpointFailure{error,pipe:None,duplicate:None,
                authority:ManuallyDrop::new(authority)});}
            if !authority.async_message || !matches!(authority.role,ChannelRole::Consumer){
                return Err(AsyncEndpointFailure{error:"genuine selected overlapped consumer profile required".into(),
                    pipe:None,duplicate:None,authority:ManuallyDrop::new(authority)});
            }
            let name=authority.endpoint.as_os_str().encode_wide().chain([0]).collect::<Vec<_>>();
            let raw=unsafe{CreateFileW(name.as_ptr(),0x12018b,0,null_mut(),3,0x40110000,null_mut())};
            if raw==(-1isize) as Ptr{return Err(AsyncEndpointFailure{error:last(),pipe:None,duplicate:None,
                authority:ManuallyDrop::new(authority)});}
            let pipe=unsafe{File::from_raw_handle(raw)};let mut duplicate=null_mut();
            let result=(|| {
                authority.recheck()?;pipe_name(raw,&authority.endpoint)?;pipe_security(raw,&authority)?;
                let mut flags=0;
                if unsafe{GetNamedPipeInfo(raw,&mut flags,null_mut(),null_mut(),null_mut())}==0
                    || flags&5!=4{return Err("original client message pipe required".into());}
                let mut ios=unsafe{zeroed::<IoStatus>()};let mut mode=0u32;
                if unsafe{NtQueryInformationFile(raw,&mut ios,(&mut mode as *mut u32).cast(),4,16)}<0
                    || ios.information!=4 || mode&0x30!=0{return Err("overlapped file mode required".into());}
                let process=unsafe{GetCurrentProcess()};
                // Read-only mapping plus WRITE_ATTRIBUTES, specifically no
                // WRITE_DATA/CREATE_PIPE_INSTANCE/DELETE/DAC/OWNER. Both handles
                // refer to the original pipe file object, not a reopened path.
                if unsafe{DuplicateHandle(process,raw,process,&mut duplicate,0x120189,0,0)}==0{return Err(last());}
                let read_mode=2;
                if unsafe{SetNamedPipeHandleState(duplicate,&read_mode,null(),null())}==0{return Err(last());}
                let mut state=0;
                if unsafe{GetNamedPipeHandleStateW(raw,&mut state,null_mut(),null_mut(),null_mut(),null_mut(),0)}==0
                    || state&2==0{return Err("original async message read mode unavailable".into());}
                let peer=PipePeer::capture(raw,&mut authority)?;authority.recheck()?;Ok(peer)
            })();
            match result {Ok(peer)=>Ok(Self{pipe,peer,authority,frozen:Arc::new(AtomicBool::new(false)),pending:None,io:None,
                    mode_handle:Some(duplicate),last_quote_sequence:None,elapsed_incarnation:None}),
                // Retain original and duplicate after any uncertain post-open
                // transition. No alternate ACL/provider/handle reopening.
                Err(error)=>Err(AsyncEndpointFailure{error,pipe:Some(ManuallyDrop::new(pipe)),
                    duplicate:if duplicate.is_null(){None}else{Some(duplicate)},authority:ManuallyDrop::new(authority)})}
        }
        fn current(&mut self)->Result<()> {
            if self.frozen.load(Ordering::SeqCst){return Err("async consumer frozen".into());}
            let result=self.current_inner();
            if result.is_err(){self.frozen.store(true,Ordering::SeqCst);}
            result
        }
        fn current_inner(&mut self)->Result<()> {
            self.authority.recheck()?;pipe_name(self.pipe.as_raw_handle(),&self.authority.endpoint)?;
            pipe_security(self.pipe.as_raw_handle(),&self.authority)?;self.peer.recheck(self.pipe.as_raw_handle())?;
            // A live process alone cannot establish a live owner endpoint. This
            // bounded kernel observation rejects explicit owner disconnect;
            // it supplies no new quote, freshness interval or polling cadence.
            let mut available=0;let mut left=0;
            if unsafe{PeekNamedPipe(self.pipe.as_raw_handle(),null_mut(),0,null_mut(),&mut available,&mut left)}==0 {
                return Err("async owner endpoint disconnected or current observation unknown".into());
            }
            if available>775 || left>available || (self.pending.is_none() && available!=0) {
                return Err("async owner endpoint has unexpected buffered response".into());
            }
            self.authority.recheck()
        }
        fn complete_io(&mut self,cancel:&Cancellation,length:u32,kind:NativeIoKind)->Result<()> {
            let io=self.io.as_mut().ok_or("owned I/O absent")?;
            io.wait(self.pipe.as_raw_handle(),cancel,length,kind)
        }
        fn release_io(&mut self)->Result<()> {
            self.io.as_mut().ok_or("owned I/O absent")?.close_settled()?;self.io=None;Ok(())
        }
        /// Runs AFTER the owned exchange is joined, immediately on the selected
        /// caller's blocking clock-query route. The returned UTC number is ONLY
        /// the externally reserved floor. Reconstructed lower bounds merely
        /// test eligibility; they never escape as additional local authority.
        pub(super) fn current_delivery(&mut self,reply:&FreshReply)->Result<CurrentDelivery> {
            let mut lifetime=WindowsCallLifetime::begin(&self.frozen);
            let result=self.current_delivery_inner(reply,false);lifetime.finished(result.is_err());result
        }
        /// Only a prepared attempt retains this private receipt. Its consumer
        /// is exclusive, so another operation cannot intervene in this stage.
        pub(super) fn recheck_delivery(&mut self,reply:&FreshReply)->Result<CurrentDelivery> {
            let mut lifetime=WindowsCallLifetime::begin(&self.frozen);
            let result=self.current_delivery_inner(reply,true);lifetime.finished(result.is_err());result
        }
        fn current_delivery_inner(&mut self,reply:&FreshReply,recheck:bool)->Result<CurrentDelivery> {
            self.current()?;
            let raw=&reply.frame;
            if &raw[..8]!=b"MCLCFQR2" || raw[8..40]!=reply.operation || raw[40..72]!=self.authority.context {
                return Err("fresh importer exact channel/operation refused".into());
            }
            let number=|start:usize|->Result<u64>{Ok(u64::from_be_bytes(raw[start..start+8]
                .try_into().map_err(|_|"fresh integer length")?))};
            let operation_sequence=number(72)?;let floor=number(80)?;let current_sequence=number(88)?;
            if operation_sequence==0 || reply.expected_sequence.is_some_and(|expected|expected.checked_add(1)!=Some(operation_sequence))
                || current_sequence<=operation_sequence
                || (if recheck {self.last_quote_sequence!=Some(current_sequence) || self.pending.is_some() || self.io.is_some()}
                    else {self.last_quote_sequence.is_some_and(|previous|current_sequence<=previous)}) {
                return Err("fresh quote sequence replay/regression refused".into());
            }
            let length=u16::from_be_bytes(raw[194..196].try_into().map_err(|_|"head length")?) as usize;
            if length==0 || length>579 {return Err("fresh protected head bound refused".into());}
            let document=super::super::protected_clock_lineage_v1::DocumentaryEngine::from_document(
                &self.authority.scope,&raw[196..196+length]).map_err(|e|format!("fresh head scope: {e:?}"))?;
            if document.frozen() || document.sequence()!=current_sequence || document.floor()<floor {
                return Err("fresh final head/outcome dominance refused".into());
            }
            let record=document.protected_record(&self.authority.binding)
                .map_err(|e|format!("fresh protected binding refused: {e:?}"))?;
            // This cold engine has NO store, acquisition task or consumer
            // publication. Its only use is current age/drift/gap/leap eligibility
            // of the protected quote under the genuinely selected profile.
            let mut available=None;let mut elapsed=None;
            if raw[96]==1 && raw[97]==1 {
                let record=record.ok_or("eligible quote lacks protected checkpoint")?;
                let backend=super::super::native_nts_backend::NativeNtsBackend::for_protected_owner(&self.authority.record)?;
                backend.clock().ratchet_high_water(document.floor());
                let eligible_now=backend.assess_consumer_record(record)?;
                let native=mutiny_clock_native_nts_v1::capture_elapsed_interval(
                    self.authority.record.record().acquisition().bounds.maximum_sampling_span_ns)
                    .ok_or("fresh consumer native interval unavailable")?;
                let boot=u128::from_be_bytes(raw[130..146].try_into().map_err(|_|"fresh boot length")?);
                let drift=number(146)?;
                let incarnation:[u8;32]=raw[154..186].try_into().map_err(|_|"fresh incarnation length")?;
                if number(98)?>number(106)? || number(114)?>number(122)?
                    || native.boot_id()!=boot || record.checkpoint().anchor().at.boot_id!=boot
                    || drift!=self.authority.record.record().profile().drift_bound_ppb
                    || incarnation==[0;32] || self.elapsed_incarnation.is_some_and(|old|old!=incarnation)
                    || native.inclusive_upper_ns()<number(98)? || native.active_upper_ns()<number(114)? {
                    return Err("fresh elapsed current/profile/incarnation refused".into());
                }
                // The earlier owner capture does not bound checkpoint-write
                // latency. The genuine consumer native sample and reconstructed
                // original-age engine account for all elapsed delay NOW.
                self.current()?;
                if eligible_now && backend.clock().lower_bound_ms().is_some_and(|lower|lower>=floor) {
                    available=Some(floor);
                    elapsed=Some(mutiny_consensus_v8::activation_attestation_v1::ElapsedCapture::from_current_owner(
                        std::time::Duration::from_nanos(native.inclusive_lower_ns()),
                        std::time::Duration::from_nanos(native.inclusive_upper_ns()),boot,incarnation,drift)
                        .map_err(|_|"fresh opaque elapsed interval refused")?);
                }
                self.elapsed_incarnation=Some(incarnation);
            }
            self.current()?;
            self.last_quote_sequence=Some(current_sequence);
            Ok(CurrentDelivery{reserved_floor:available,elapsed,current_sequence})
        }
        /// One fresh operation on a caller-owned dedicated blocking worker.
        /// No actor/UI-thread wait, cross-attempt cached Boolean or retry. The
        /// caller joins the worker before releasing cancellation/owner inputs.
        pub(super) fn exchange_on_owned_worker(&mut self,operation:[u8;32],expected_sequence:u64,
            cancel:&Cancellation)->Result<FreshReply> {
            let mut lifetime=WindowsCallLifetime::begin(&self.frozen);
            let result=self.exchange_inner(operation,Some(expected_sequence),cancel);
            lifetime.finished(result.is_err());result
        }
        fn exchange_inner(&mut self,operation:[u8;32],expected_sequence:Option<u64>,cancel:&Cancellation)
            ->Result<FreshReply> {
            self.current()?;
            if operation==[0;32] || self.pending.is_some() || self.io.is_some(){return Err("async exact operation already pending/invalid".into());}
            self.io=Some(PendingIo::new()?);
            self.pending=Some(PendingReservation{operation,expected_sequence:expected_sequence.unwrap_or(0)});
            let io=self.io.as_mut().unwrap();
            io.cell.buffer[..8].copy_from_slice(b"MCLCIPC1");io.cell.buffer[8]=if expected_sequence.is_some(){3}else{4};
            io.cell.buffer[9..41].copy_from_slice(&operation);io.cell.buffer[41..73].copy_from_slice(&self.authority.context);
            io.cell.buffer[73..81].copy_from_slice(&expected_sequence.unwrap_or(0).to_be_bytes());
            io.begin(self.pipe.as_raw_handle(),true,81)?;
            self.complete_io(cancel,81,NativeIoKind::Write)?;self.release_io()?;self.current()?;
            self.io=Some(PendingIo::new()?);
            self.io.as_mut().unwrap().begin(self.pipe.as_raw_handle(),false,775)?;
            self.complete_io(cancel,775,NativeIoKind::Read)?;
            let response=self.io.as_ref().unwrap().cell.buffer;
            // Message-read mode refuses ERROR_MORE_DATA and short messages;
            // byte concatenation is impossible without an observed mode fault.
            if &response[..8]!=b"MCLCFQR2" || response[8..40]!=operation
                || response[40..72]!=self.authority.context || response[96]>1 || response[97]>1
                || response[186..194]!=[0;8] {return Err("async fresh exact reply differs".into());}
            let sequence=u64::from_be_bytes(response[72..80].try_into().map_err(|_|"sequence length")?);
            if sequence==0 || expected_sequence.is_some_and(|expected|expected.checked_add(1)!=Some(sequence)){
                return Err("async reply sequence differs".into());}
            let current_sequence=u64::from_be_bytes(response[88..96].try_into().map_err(|_|"current sequence length")?);
            if current_sequence<=sequence{return Err("fresh durable checkpoint sequence missing".into());}
            let length=u16::from_be_bytes(response[194..196].try_into().map_err(|_|"head length")?) as usize;
            if length==0 || length>579 || response[196+length..].iter().any(|byte|*byte!=0)
                || (response[97]==0 && response[98..186].iter().any(|byte|*byte!=0))
                || (response[96]==1 && response[97]!=1){return Err("fresh head/interval canonical bound refused".into());}
            self.current()?;self.release_io()?;self.pending=None;
            Ok(FreshReply{frame:response,operation,expected_sequence})
        }
    }
    /// Server side of the SAME explicitly selected overlapped endpoint profile.
    /// All buffers are heap-stable and native waits are completion/cancellation
    /// events, not timers. A service controller must own/join its blocking task.
    /// This transport cannot install a principal, mint qualification or reset
    /// lineage. Dropping the wrapper preserves every native/installed holder.
    pub(in super::super) struct InstalledAsyncOwnerServer {inner:Option<Box<AsyncOwnerServer>>}
    // Exclusive transfer to the caller-owned blocking task only; never Sync.
    // Original handles and stable allocations are used only by &mut methods.
    unsafe impl Send for InstalledAsyncOwnerServer {}
    pub(in super::super) struct AsyncOwnerServerCreationFailure {
        error:String,endpoint:Option<ManuallyDrop<WindowsEndpointFailure>>,
        server:Option<ManuallyDrop<InstalledAsyncOwnerServer>>,
    }
    impl AsyncOwnerServerCreationFailure {pub(in super::super) fn description(&self)->&str{&self.error}}
    struct AsyncOwnerServer {
        pipe:File,authority:InstalledWindowsAuthority,peer:Option<PipePeer>,
        frozen:Arc<AtomicBool>,io:Option<PendingIo>,pending:Option<PendingReservation>,
        disconnect_attempted:bool,
    }
    impl Drop for InstalledAsyncOwnerServer {
        fn drop(&mut self){if let Some(server)=self.inner.take(){server.frozen.store(true,Ordering::SeqCst);
            let _custody=Box::into_raw(server);}}
    }
    impl InstalledAsyncOwnerServer {
        pub(in super::super) fn bind_new(authority:InstalledWindowsAuthority)
            ->std::result::Result<Self,AsyncOwnerServerCreationFailure> {
            if !authority.async_message{return Err(AsyncOwnerServerCreationFailure{
                error:"old endpoint profile cannot issue async owner".into(),endpoint:None,server:None});}
            // Allocate the final holder BEFORE endpoint creation. No failure
            // after creation releases the file, guard, peer or unresolved I/O.
            let mut custody=Box::<AsyncOwnerServer>::new_uninit();
            let frozen=Arc::new(AtomicBool::new(false));
            let listener=WindowsPipeListener::bind_new_mode(authority,true).map_err(|failure|
                AsyncOwnerServerCreationFailure{error:failure.error.clone(),endpoint:Some(ManuallyDrop::new(failure)),server:None})?;
            let WindowsPipeListener{pipe,authority}=listener;
            custody.write(AsyncOwnerServer{pipe,authority,peer:None,frozen,io:None,pending:None,disconnect_attempted:false});
            let mut owned=Self{inner:Some(unsafe{custody.assume_init()})};
            let result=owned.inner.as_mut().expect("owner server allocated").require_overlapped();
            if let Err(error)=result {return Err(AsyncOwnerServerCreationFailure{error,endpoint:None,
                server:Some(ManuallyDrop::new(owned))});}
            Ok(owned)
        }
        pub(in super::super) fn require_dispatcher(&mut self,
            owner:&super::super::protected_clock_owner::ProtectedOwnerDispatcher)->Result<()> {
            let server=self.inner.as_mut().ok_or("owner server absent")?;
            server.require_overlapped()?;
            if owner.channel_context()?!=server.authority.context{return Err("owner worker dispatcher context differs".into());}
            Ok(())
        }
        /// Once-only disconnection after the worker's native wait returned.
        /// Unknown buffers and every failed native handle remain owned. This
        /// does not report them closed or erase the pending operation.
        pub(in super::super) fn disconnect_for_stop(&mut self)->Result<()> {
            let server=self.inner.as_mut().ok_or("owner server absent")?;
            server.frozen.store(true,Ordering::SeqCst);
            if server.disconnect_attempted{return Err("prior endpoint disconnect not retried".into());}
            server.disconnect_attempted=true;
            if unsafe{DisconnectNamedPipe(server.pipe.as_raw_handle())}==0 {
                let error=unsafe{GetLastError()};
                // Already disconnected has no remaining connected client.
                if error!=233{return Err(format!("owner endpoint disconnect unknown {error}"));}
            }
            Ok(())
        }
        /// Only the caller-owned blocking worker may call this. Cancellation
        /// wakes and settles the ORIGINAL ConnectNamedPipe OVERLAPPED.
        pub(in super::super) fn connect(&mut self,cancel:&FreshRequestCancellation)->Result<OwnerIpcStep> {
            self.inner.as_mut().ok_or("owner server absent")?.connect(&cancel.inner)
        }
        pub(in super::super) fn serve_one(&mut self,owner:&super::super::protected_clock_owner::ProtectedOwnerDispatcher,
            cancel:&FreshRequestCancellation)->Result<OwnerIpcStep> {
            self.inner.as_mut().ok_or("owner server absent")?.serve_one(owner,&cancel.inner)
        }
        /// Readiness after ORIGINAL worker return, without any new time/floor.
        pub(in super::super) fn require_joined_close_ready(&mut self)->Result<()> {
            let server=self.inner.as_mut().ok_or("joined owner server absent")?;
            if server.io.is_some() || server.pending.is_some() || !server.disconnect_attempted {
                return Err("joined owner I/O/operation/disconnect unresolved".into());
            }
            server.authority.recheck()?;pipe_name(server.pipe.as_raw_handle(),&server.authority.endpoint)?;
            pipe_security(server.pipe.as_raw_handle(),&server.authority)?;server.authority.recheck()
        }
        /// Narrow transport closure only after the worker has returned. If a
        /// native operation is unresolved, return the ENTIRE owner unchanged.
        /// No guard/lineage/replacement token is issued by this report.
        pub(in super::super) fn close_transport(mut self)->std::result::Result<WindowsTransportClose,Self> {
            let server=self.inner.as_ref().expect("owner server retained");
            if server.io.is_some(){return Err(self);}
            let server=self.inner.take().expect("owner server retained");
            server.frozen.store(true,Ordering::SeqCst);
            let AsyncOwnerServer{pipe,authority,peer,frozen:_,io:_,pending,disconnect_attempted:_}=*server;
            let mut report=WindowsTransportClose::new(authority,pending);
            report.pipe_failure=WindowsTransportClose::close_once(pipe.into_raw_handle(),"async owner pipe",None,None);
            if let Some(peer)=peer {
                let held=ManuallyDrop::new(peer.process);
                report.peer_failure=WindowsTransportClose::close_once(held.0,"async owner client",Some(peer.pid),Some(peer.creation));
            }
            Ok(report)
        }
    }
    impl PendingIo {
        fn begin_connect(&mut self,pipe:Ptr)->Result<bool> {
            self.active=true;
            let result=unsafe{ConnectNamedPipe(pipe,(&mut self.cell.overlapped as *mut Overlapped).cast())};
            if result!=0{return Ok(true);}
            let error=unsafe{GetLastError()};
            if error==997{return Ok(true);}
            self.active=false;
            // The client may connect between CreateNamedPipe and this call.
            // ERROR_PIPE_CONNECTED completes without a pending kernel buffer.
            if error==535{return Ok(false);}
            Err(format!("async owner connect refused {error}"))
        }
    }
    impl AsyncOwnerServer {
        fn require_overlapped(&mut self)->Result<()> {
            self.authority.recheck()?;pipe_name(self.pipe.as_raw_handle(),&self.authority.endpoint)?;
            pipe_security(self.pipe.as_raw_handle(),&self.authority)?;
            let mut ios=unsafe{zeroed::<IoStatus>()};let mut mode=0u32;
            if unsafe{NtQueryInformationFile(self.pipe.as_raw_handle(),&mut ios,(&mut mode as *mut u32).cast(),4,16)}<0
                || ios.information!=4 || mode&0x30!=0{return Err("async owner original pipe mode refused".into());}
            self.authority.recheck()
        }
        fn current(&mut self,cancel:&Cancellation)->Result<()> {
            if self.frozen.load(Ordering::SeqCst){return Err("async owner frozen".into());}
            // This is a single state check at an entry boundary, not polling.
            if unsafe{WaitForSingleObject(cancel.event,0)}!=258{return Err("async owner cancelled/current unknown".into());}
            self.require_overlapped()?;
            if let Some(peer)=&self.peer{peer.recheck(self.pipe.as_raw_handle())?;}
            self.authority.recheck()
        }
        fn release_io(&mut self)->Result<()> {
            self.io.as_mut().ok_or("async owner I/O absent")?.close_settled()?;
            self.io=None;Ok(())
        }
        fn idle_stop_requested(&mut self,cancel:&Cancellation)->Result<bool> {
            let state=unsafe{WaitForSingleObject(cancel.event,0)};
            if state==258{return Ok(false);}
            if state!=0{return Err(format!("owner cancellation event state unknown {state}"));}
            if self.io.is_some() || self.pending.is_some(){return Err("cancelled owner retains native/logical operation".into());}
            self.require_idle_stop_current()?;Ok(true)
        }
        fn require_idle_stop_current(&mut self)->Result<()> {
            if self.frozen.load(Ordering::SeqCst) || self.io.is_some() || self.pending.is_some(){
                return Err("unknown/frozen owner cannot acknowledge idle stop".into());
            }
            // Ignore only the explicitly observed stop EVENT, never native
            // current/endpoint/peer errors or an existing frozen operation.
            self.require_overlapped()?;
            if let Some(peer)=&self.peer{peer.recheck(self.pipe.as_raw_handle())?;}
            self.authority.recheck()
        }
        fn finish_idle_stop(&mut self)->Result<OwnerIpcStep> {
            self.require_idle_stop_current()?;
            self.frozen.store(true,Ordering::SeqCst);
            Ok(OwnerIpcStep::StoppedBeforeOperation)
        }
        fn connect(&mut self,cancel:&Cancellation)->Result<OwnerIpcStep> {
            let mut lifetime=WindowsCallLifetime::begin(&self.frozen);
            let result=(|| {
                if self.idle_stop_requested(cancel)?{return self.finish_idle_stop();}
                self.current(cancel)?;
                if self.peer.is_some() || self.io.is_some(){return Err("async owner connect state refused".into());}
                self.io=Some(PendingIo::new()?);
                let pending=self.io.as_mut().expect("connect I/O owned").begin_connect(self.pipe.as_raw_handle())?;
                if pending {
                    match self.io.as_mut().expect("connect I/O owned").wait_owned(self.pipe.as_raw_handle(),cancel,0,NativeIoKind::Connect)? {
                        NativeIoOutcome::Completed=>{},
                        NativeIoOutcome::CancelledSettledBeforeDispatch=>{self.release_io()?;return self.finish_idle_stop();},
                    }
                }
                self.current(cancel)?;
                self.peer=Some(PipePeer::capture(self.pipe.as_raw_handle(),&mut self.authority)?);
                self.current(cancel)?;self.release_io()?;Ok(OwnerIpcStep::Continue)
            })();lifetime.finished(result.is_err());result
        }
        fn exchange_bytes(&mut self,cancel:&Cancellation,write:bool,data:&[u8],length:u32)->Result<()> {
            self.current(cancel)?;
            if self.io.is_some() || self.peer.is_none() || length>775 || (write && data.len()!=length as usize){
                return Err("async owner I/O state/bound refused".into());
            }
            self.io=Some(PendingIo::new()?);
            if write {self.io.as_mut().expect("owner I/O owned").cell.buffer[..data.len()].copy_from_slice(data);}
            self.io.as_mut().expect("owner I/O owned").begin(self.pipe.as_raw_handle(),write,length)?;
            self.io.as_mut().expect("owner I/O owned").wait(self.pipe.as_raw_handle(),cancel,length,if write{NativeIoKind::Write}else{NativeIoKind::Read})?;
            self.current(cancel)
        }
        fn serve_one(&mut self,owner:&super::super::protected_clock_owner::ProtectedOwnerDispatcher,
            cancel:&Cancellation)->Result<OwnerIpcStep> {
            let mut lifetime=WindowsCallLifetime::begin(&self.frozen);
            let result=self.serve_inner(owner,cancel);lifetime.finished(result.is_err());result
        }
        fn serve_inner(&mut self,owner:&super::super::protected_clock_owner::ProtectedOwnerDispatcher,
            cancel:&Cancellation)->Result<OwnerIpcStep> {
            if self.idle_stop_requested(cancel)?{return self.finish_idle_stop();}
            self.current(cancel)?;
            if self.pending.is_some(){return Err("async owner exact operation unresolved".into());}
            if self.io.is_some() || self.peer.is_none(){return Err("owner request read state refused".into());}
            self.io=Some(PendingIo::new()?);
            self.io.as_mut().expect("request I/O owned").begin(self.pipe.as_raw_handle(),false,81)?;
            match self.io.as_mut().expect("request I/O owned").wait_owned(self.pipe.as_raw_handle(),cancel,81,NativeIoKind::Read)? {
                NativeIoOutcome::Completed=>{},
                NativeIoOutcome::CancelledSettledBeforeDispatch=>{self.release_io()?;return self.finish_idle_stop();},
            }
            // A cancellation racing successful/partial transfer is UNKNOWN;
            // no request bytes are parsed or dispatched through that race.
            self.current(cancel)?;
            let mut frame=[0u8;81];frame.copy_from_slice(&self.io.as_ref().expect("completed request owned").cell.buffer[..81]);
            self.release_io()?;
            // Native read is SETTLED before impersonation; no callback/storage/
            // async yield occurs under the Identification token. Shared helper
            // restores and verifies the process token before owner dispatch.
            self.current(cancel)?;let sid=message_sid_from_pipe(&self.pipe)?;self.current(cancel)?;
            if sid!=self.peer.as_ref().ok_or("owner peer absent")?.sid || &frame[..8]!=b"MCLCIPC1"
                || ![1,2,3,4].contains(&frame[8]) || frame[9..41]==[0;32]
                || frame[41..73]!=self.authority.context || (frame[8]==4 && frame[73..81]!=[0;8]) {
                return Err("async owner authenticated exact frame refused".into());
            }
            let identity:[u8;32]=frame[9..41].try_into().map_err(|_|"async owner operation length")?;
            let expected=u64::from_be_bytes(frame[73..81].try_into().map_err(|_|"async owner sequence length")?);
            self.pending=Some(PendingReservation{operation:identity,expected_sequence:expected});
            if owner.channel_context()?!=self.authority.context{return Err("async owner context differs".into());}
            let operation=super::super::protected_clock_lineage_v1::Operation::authenticated_document(identity,Sha256::digest(frame).into())
                .map_err(|e|format!("async owner exact commitment refused: {e:?}"))?;
            self.current(cancel)?;
            if [3,4].contains(&frame[8]) {
                let quote=if frame[8]==4{owner.fresh_selected_operation(operation)?}else{owner.fresh_operation(expected,operation)?};
                self.current(cancel)?;
                if owner.channel_context()?!=self.authority.context{return Err("async owner revoked after durable quote".into());}
                let response=quote.encode(self.authority.context)?;
                self.exchange_bytes(cancel,true,&response,775)?;
            }else{
                let outcome=owner.reserve_operation(expected,operation)?;
                self.current(cancel)?;
                if owner.channel_context()?!=self.authority.context{return Err("async owner revoked after reservation".into());}
                let mut response=[0u8;89];response[..8].copy_from_slice(b"MCLCIPR1");
                response[8..40].copy_from_slice(&identity);response[40..72].copy_from_slice(&self.authority.context);
                response[72..80].copy_from_slice(&outcome.sequence.to_be_bytes());response[80..88].copy_from_slice(&outcome.floor.to_be_bytes());
                response[88]=u8::from(outcome.qualified);self.exchange_bytes(cancel,true,&response,89)?;
            }
            self.release_io()?;self.current(cancel)?;
            if owner.channel_context()?!=self.authority.context{return Err("async owner revoked during acknowledgment".into());}
            self.pending=None;Ok(OwnerIpcStep::Continue)
        }
    }

}
