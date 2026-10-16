//! OWN process facts and generic public-object security, without role authority.
//! Native temporary obligations are preallocated and explicitly settled once.
#![cfg(windows)]
use std::{ffi::c_void,fs::File,mem::{size_of,ManuallyDrop,zeroed},os::windows::io::AsRawHandle,ptr::null_mut};
type Ptr=*mut c_void;
type Result<T>=std::result::Result<T,WindowsMechanicalFailure>;
const SYSTEM:&[u8]=&[1,1,0,0,0,0,0,5,18,0,0,0];
const ADMINS:&[u8]=&[1,2,0,0,0,0,0,5,32,0,0,0,32,2,0,0];
// Exact inherited TrustedInstaller SID, parsed without LocalAlloc/native rights.
const TI:&[u8]=&[1,6,0,0,0,0,0,5,80,0,0,0,181,137,251,56,25,132,194,203,92,108,35,109,87,0,119,110,192,2,100,135];
#[repr(C)]struct Luid{low:u32,high:i32}
#[repr(C)]struct Statistics{token:Luid,authentication:Luid,expiration:i64,kind:i32,impersonation:i32,
    dynamic_charged:u32,dynamic_available:u32,groups:u32,privileges:u32,modified:Luid}
#[repr(C)]struct FileTime{low:u32,high:u32}
#[repr(C)]struct Acl{revision:u8,reserved:u8,size:u16,count:u16,reserved2:u16}
#[link(name="kernel32")]unsafe extern "system"{
    fn GetCurrentProcess()->Ptr;fn GetCurrentThread()->Ptr;fn GetCurrentProcessId()->u32;
    fn GetProcessTimes(process:Ptr,creation:*mut FileTime,exit:*mut FileTime,kernel:*mut FileTime,user:*mut FileTime)->i32;
    fn ProcessIdToSessionId(pid:u32,session:*mut u32)->i32;
    fn CloseHandle(handle:Ptr)->i32;fn GetLastError()->u32;fn LocalFree(allocation:Ptr)->Ptr;
}
#[link(name="advapi32")]unsafe extern "system"{
    fn OpenProcessToken(process:Ptr,access:u32,token:*mut Ptr)->i32;
    fn OpenThreadToken(thread:Ptr,access:u32,as_self:i32,token:*mut Ptr)->i32;
    fn GetTokenInformation(token:Ptr,kind:u32,data:Ptr,length:u32,needed:*mut u32)->i32;
    fn IsValidSid(sid:Ptr)->i32;fn GetLengthSid(sid:Ptr)->u32;
    fn GetSecurityInfo(handle:Ptr,kind:u32,info:u32,owner:*mut Ptr,group:*mut Ptr,acl:*mut *mut Acl,sacl:*mut Ptr,sd:*mut Ptr)->u32;
    fn GetSecurityDescriptorLength(sd:Ptr)->u32;
    fn GetSecurityDescriptorControl(sd:Ptr,control:*mut u16,revision:*mut u32)->i32;
    fn GetAce(acl:*mut Acl,index:u32,ace:*mut Ptr)->i32;
    fn ConvertSidToStringSidW(sid:Ptr,text:*mut *mut u16)->i32;
}
#[derive(Clone,Copy,PartialEq,Eq)]struct Facts{pid:u32,creation:u64,sid:[u8;68],sid_length:u8,
    session:u32,authentication:u64,token:u64,elevated:u32}
impl Facts{fn empty()->Self{Self{pid:0,creation:0,sid:[0;68],sid_length:0,session:0,authentication:0,token:0,elevated:0}}}
#[derive(Clone,Copy)]struct AceFact{kind:u8,flags:u8,mask:u32,sid:[u8;68],length:u8}
#[derive(Clone,Copy)]struct SecurityFacts{owner:[u8;68],owner_length:u8,control:u16,aces:[AceFact;64],count:u8}
impl SecurityFacts{fn empty()->Self{Self{owner:[0;68],owner_length:0,control:0,
    aces:[AceFact{kind:0,flags:0,mask:0,sid:[0;68],length:0};64],count:0}}}
struct QueryCustody{
    token:usize,token_close_attempted:bool,token_closed:bool,token_close_error:Option<u32>,
    token_query_stage:u8,token_query_error:Option<u32>,facts:Facts,learned:u16,
    failure_problem:Option<String>,process_times:[u64;4],process_times_result:Option<i32>,process_times_error:Option<u32>,
    principal_problem:Option<String>,principal_query_result:Option<bool>,
    descriptor:usize,descriptor_kind:u32,descriptor_query:Option<u32>,descriptor_size:Option<usize>,
    security:SecurityFacts,security_complete:bool,security_parse_error:Option<u32>,
    security_problem:Option<String>,security_parse_result:Option<bool>,
    release_attempted:bool,released:bool,release_error:Option<u32>,
    sid_text_query:Option<i32>,sid_text_error:Option<u32>,sid_text:[u16;257],sid_text_length:usize,
}
impl QueryCustody{fn empty()->Self{Self{token:0,token_close_attempted:false,token_closed:false,token_close_error:None,
    token_query_stage:0,token_query_error:None,facts:Facts::empty(),learned:0,
    failure_problem:None,process_times:[0;4],process_times_result:None,process_times_error:None,
    principal_problem:None,principal_query_result:None,
    descriptor:0,descriptor_kind:0,descriptor_query:None,descriptor_size:None,security:SecurityFacts::empty(),security_complete:false,
    security_parse_error:None,security_problem:None,security_parse_result:None,
    release_attempted:false,released:false,release_error:None,
    sid_text_query:None,sid_text_error:None,sid_text:[0;257],sid_text_length:0}}}
/// Opaque original observations and native outcomes survive error mapping/Drop.
pub(crate) struct WindowsMechanicalFailure{description:String,retained:ManuallyDrop<Box<QueryCustody>>}
impl WindowsMechanicalFailure{pub(crate) fn description(&self)->&str{&self.description}}
impl std::fmt::Debug for WindowsMechanicalFailure{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.debug_tuple("WindowsMechanicalFailure").field(&self.description).finish()}}
struct QueryOwner{core:Option<Box<QueryCustody>>}
impl QueryOwner{
    fn allocated()->Self{Self{core:Some(Box::new(QueryCustody::empty()))}}
    fn failure(mut self,description:String)->WindowsMechanicalFailure{
        self.core.as_mut().expect("preallocated query custody").failure_problem=Some(description.clone());
        WindowsMechanicalFailure{description,retained:ManuallyDrop::new(self.core.take().expect("preallocated query custody"))}}
}
impl Drop for QueryOwner{fn drop(&mut self){if let Some(core)=self.core.take(){let _=Box::into_raw(core);}}}
fn luid(v:&Luid)->u64{u64::from(v.low)|((v.high as u32 as u64)<<32)}
fn sid_in(sid:Ptr,start:usize,end:usize)->std::result::Result<([u8;68],u8),String>{
    let address=sid as usize;
    if address<start||address.checked_add(8).ok_or("SID header overflow")?>end{return Err("SID header membership".into());}
    let length=8usize.checked_add(4usize.checked_mul(unsafe{*((address+1)as *const u8)}as usize).ok_or("SID length")?).ok_or("SID length")?;
    if length>68||address.checked_add(length).ok_or("SID body overflow")?>end
        ||unsafe{IsValidSid(sid)}==0||unsafe{GetLengthSid(sid)}as usize!=length{return Err("SID body membership".into());}
    let mut out=[0;68];out[..length].copy_from_slice(unsafe{std::slice::from_raw_parts(sid.cast::<u8>(),length)});Ok((out,length as u8))
}
fn close_token(core:&mut QueryCustody)->std::result::Result<(),String>{
    if core.token==0||core.token_close_attempted{return Err("token obligation unavailable".into());}
    core.token_close_attempted=true;
    if unsafe{CloseHandle(core.token as Ptr)}==0{let code=unsafe{GetLastError()};core.token_close_error=Some(code);
        return Err(format!("original query token close unknown {code}"));}
    core.token_closed=true;Ok(())
}
fn no_thread_token()->Result<()>{let mut owner=QueryOwner::allocated();let core=owner.core.as_mut().expect("thread query custody");
    core.token_query_stage=255;let mut token=null_mut();
    if unsafe{OpenThreadToken(GetCurrentThread(),8,1,&mut token)}!=0{core.token=token as usize;
        let closed=close_token(core);return Err(owner.failure(format!("OWN thread impersonating; original token closed={}",closed.is_ok())));}
    let code=unsafe{GetLastError()};core.token_query_error=Some(code);
    if code!=1008{return Err(owner.failure(format!("OWN thread token query {code}")));}
    drop(owner.core.take());Ok(())
}
fn capture_principal(core:&mut QueryCustody)->std::result::Result<Facts,String>{
    core.token_query_stage=255; // OWN thread-token refusal, distinct from primary queries.
    let mut thread=null_mut();
    if unsafe{OpenThreadToken(GetCurrentThread(),8,1,&mut thread)}!=0{
        core.token=thread as usize;let close=close_token(core);
        return Err(format!("OWN principal impersonating; close={}",close.is_ok()));}
    let code=unsafe{GetLastError()};if code!=1008{core.token_query_error=Some(code);return Err(format!("thread token query {code}"));}
    let pid=unsafe{GetCurrentProcessId()};if pid==0{return Err("OWN PID unavailable".into());}
    core.facts.pid=pid;core.learned|=1;
    let(mut c,mut e,mut k,mut u)=unsafe{(zeroed(),zeroed(),zeroed(),zeroed())};
    let observed=unsafe{GetProcessTimes(GetCurrentProcess(),&mut c,&mut e,&mut k,&mut u)};
    let error=if observed==0{Some(unsafe{GetLastError()})}else{None};
    core.process_times_result=Some(observed);core.process_times_error=error;
    core.process_times=[(u64::from(c.high)<<32)|u64::from(c.low),(u64::from(e.high)<<32)|u64::from(e.low),
        (u64::from(k.high)<<32)|u64::from(k.low),(u64::from(u.high)<<32)|u64::from(u.low)];
    if let Some(code)=error{core.token_query_error=Some(code);return Err(format!("OWN creation query {code}"));}
    let creation=(u64::from(c.high)<<32)|u64::from(c.low);if creation==0{return Err("OWN creation unavailable".into());}
    core.facts.creation=creation;core.learned|=2;
    let mut token=null_mut();if unsafe{OpenProcessToken(GetCurrentProcess(),8,&mut token)}==0{
        let code=unsafe{GetLastError()};core.token_query_error=Some(code);return Err(format!("OWN token query {code}"));}
    core.token=token as usize;
    let result=(||{
        let mut words=[0usize;512];let mut used=0;let capacity=words.len()*size_of::<usize>();
        core.token_query_stage=1;
        if unsafe{GetTokenInformation(token,1,words.as_mut_ptr().cast(),capacity as u32,&mut used)}==0{
            let code=unsafe{GetLastError()};core.token_query_error=Some(code);return Err(format!("OWN SID query {code}"));}
        if used as usize>capacity||(used as usize)<size_of::<Ptr>(){return Err("OWN SID allocation bound".into());}
        let sid=unsafe{*(words.as_ptr()as *const Ptr)};let start=words.as_ptr()as usize;
        (core.facts.sid,core.facts.sid_length)=sid_in(sid,start,start.checked_add(used as usize).ok_or("OWN SID end")?)?;core.learned|=4;
        core.token_query_stage=2;let mut stats=unsafe{zeroed::<Statistics>()};
        if unsafe{GetTokenInformation(token,10,(&mut stats as *mut Statistics).cast(),size_of::<Statistics>()as u32,&mut used)}==0{
            let code=unsafe{GetLastError()};core.token_query_error=Some(code);return Err(format!("OWN statistics query {code}"));}
        if used as usize!=size_of::<Statistics>()||stats.kind!=1{return Err("OWN primary token statistics bound".into());}
        core.facts.authentication=luid(&stats.authentication);core.facts.token=luid(&stats.token);core.learned|=8;
        core.token_query_stage=3;let mut session=0;
        if unsafe{GetTokenInformation(token,12,(&mut session as *mut u32).cast(),4,&mut used)}==0{
            let code=unsafe{GetLastError()};core.token_query_error=Some(code);return Err(format!("OWN session query {code}"));}
        if used!=4{return Err("OWN token session bound".into());}core.facts.session=session;core.learned|=16;
        let mut actual=0;if unsafe{ProcessIdToSessionId(pid,&mut actual)}==0{
            let code=unsafe{GetLastError()};core.token_query_error=Some(code);return Err(format!("OWN process session query {code}"));}
        if actual!=session{return Err("OWN process/token session differs".into());}
        core.token_query_stage=4;let mut elevated=0;
        if unsafe{GetTokenInformation(token,20,(&mut elevated as *mut u32).cast(),4,&mut used)}==0{
            let code=unsafe{GetLastError()};core.token_query_error=Some(code);return Err(format!("OWN elevation query {code}"));}
        if used!=4||elevated>1{return Err("OWN token elevation bound".into());}core.facts.elevated=elevated;core.learned|=32;
        Ok(core.facts)
    })();
    core.principal_query_result=Some(result.is_ok());
    if let Err(problem)=&result{core.principal_problem=Some(problem.clone());}
    let closed=close_token(core);
    match(result,closed){(Ok(facts),Ok(()))=>Ok(facts),(result,close)=>Err(format!("OWN query result={}; token close={}",result.is_ok(),close.is_ok()))}
}
/// Facts only after original temporary token close. No role/current-code capability.
pub(crate) struct CurrentWindowsPrincipal{facts:Facts}
impl CurrentWindowsPrincipal{
    pub(crate) fn capture_own()->Result<Self>{let mut owner=QueryOwner::allocated();
        let result=capture_principal(owner.core.as_mut().expect("query core"));
        match result{Ok(facts)=>{no_thread_token()?;drop(owner.core.take());Ok(Self{facts})},Err(problem)=>Err(owner.failure(problem))}}
    pub(crate) fn user_sid(&self)->&[u8]{&self.facts.sid[..self.facts.sid_length as usize]}
    pub(crate) fn session_id(&self)->u32{self.facts.session}
    pub(crate) fn authentication_luid(&self)->u64{self.facts.authentication}
    /// Actual captured token fact only; it grants no installation authority.
    pub(super) fn elevated(&self)->bool{self.facts.elevated!=0}
    pub(super) fn user_sid_text(&self)->Result<String>{
        let mut owner=QueryOwner::allocated();let core=owner.core.as_mut().expect("SID text custody");
        core.facts=self.facts;
        let mut aligned=[0u32;17];
        (unsafe{std::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(),68)})
            [..self.facts.sid_length as usize].copy_from_slice(self.user_sid());
        let mut text=null_mut();let captured=unsafe{ConvertSidToStringSidW(aligned.as_mut_ptr().cast(),&mut text)};
        let error=if captured==0{Some(unsafe{GetLastError()})}else{None};
        core.descriptor=text as usize;core.sid_text_query=Some(captured);core.sid_text_error=error;
        if captured==0||text.is_null(){return Err(owner.failure(format!("original SID text query refused {:?}",error)));}
        let result:std::result::Result<String,String>=(||{
            for index in 0..=256{let value=unsafe{*text.add(index)};
                core.sid_text[index]=value;core.sid_text_length=index;
                if value==0{return String::from_utf16(&core.sid_text[..index]).map_err(|_|"native SID text UTF16 refused".into());}}
            Err("bounded native SID text refused".into())})();
        if let Err(problem)=&result{core.security_problem=Some(problem.clone());}
        let released=release_allocation(core);
        match(result,released){(Ok(value),Ok(()))=>{drop(owner.core.take());self.recheck()?;Ok(value)},
            (first,second)=>Err(owner.failure(format!("native SID text result={}; release={}",first.is_ok(),second.is_ok())))}
    }
    pub(crate) fn recheck(&self)->Result<()>{let mut owner=QueryOwner::allocated();
        match capture_principal(owner.core.as_mut().expect("query core")){
            Ok(facts)if facts==self.facts=>{no_thread_token()?;drop(owner.core.take());Ok(())},
            Ok(_)=>Err(owner.failure("OWN original process/token facts changed".into())),Err(problem)=>Err(owner.failure(problem))}}
    fn installation_consumer(&self)->bool{self.facts.elevated==0&&self.user_sid()!=SYSTEM&&self.user_sid()!=TI}
}
/// Complete native snapshot after checked allocation release. No role policy.
pub(super) struct CurrentWindowsFileSecurity{facts:SecurityFacts}
impl CurrentWindowsFileSecurity{
    pub(super) fn owner_sid(&self)->&[u8]{&self.facts.owner[..self.facts.owner_length as usize]}
    pub(super) fn control(&self)->u16{self.facts.control}
    pub(super) fn ace_count(&self)->usize{self.facts.count as usize}
    pub(super) fn aces(&self)->impl Iterator<Item=(u8,u8,u32,&[u8])>{
        self.facts.aces[..self.facts.count as usize].iter().map(|ace|
            (ace.kind,ace.flags,ace.mask,&ace.sid[..ace.length as usize]))
    }
}
pub(super) fn file_security_snapshot(file:&File)->Result<CurrentWindowsFileSecurity>{
    let mut owner=QueryOwner::allocated();
    match snapshot(owner.core.as_mut().expect("native file snapshot custody"),file.as_raw_handle(),1){
        Ok(facts)=>{drop(owner.core.take());Ok(CurrentWindowsFileSecurity{facts})},
        Err(problem)=>Err(owner.failure(problem))}
}
pub(super) fn require_no_thread_token()->Result<()>{no_thread_token()}
fn release_allocation(core:&mut QueryCustody)->std::result::Result<(),String>{
    if core.descriptor==0||core.release_attempted{return Err("native allocation release unavailable".into());}
    core.release_attempted=true;
    if !unsafe{LocalFree(core.descriptor as Ptr)}.is_null(){let code=unsafe{GetLastError()};core.release_error=Some(code);return Err(format!("security release unknown {code}"));}
    core.released=true;Ok(())
}
fn snapshot(core:&mut QueryCustody,handle:Ptr,kind:u32)->std::result::Result<SecurityFacts,String>{
    let(mut owner,mut acl,mut descriptor)=(null_mut(),null_mut(),null_mut());core.descriptor_kind=kind;
    let code=unsafe{GetSecurityInfo(handle,kind,1|4,&mut owner,null_mut(),&mut acl,null_mut(),&mut descriptor)};
    core.descriptor=descriptor as usize;core.descriptor_query=Some(code);
    if code!=0||descriptor.is_null(){return Err(format!("original security query {code}"));}
    let result:std::result::Result<SecurityFacts,String>=(||{
        let size=unsafe{GetSecurityDescriptorLength(descriptor)}as usize;core.descriptor_size=Some(size);
        if size==0||size>8192{return Err("bounded security descriptor".into());}
        let start=descriptor as usize;let end=start.checked_add(size).ok_or("security end")?;
        let(mut control,mut revision)=(0,0);
        if unsafe{GetSecurityDescriptorControl(descriptor,&mut control,&mut revision)}==0{
            core.security_parse_error=Some(unsafe{GetLastError()});return Err("security control query".into());}
        core.security.control=control;
        if control&4==0||control&0x8000==0||acl.is_null(){return Err("actual self-relative DACL required".into());}
        (core.security.owner,core.security.owner_length)=sid_in(owner,start,end)?;
        let address=acl as usize;
        if address<start||address.checked_add(size_of::<Acl>()).ok_or("ACL header")?>end{return Err("ACL header membership".into());}
        let length=unsafe{(*acl).size}as usize;let count=unsafe{(*acl).count}as usize;
        if length<size_of::<Acl>()||length>4096||count>64||address.checked_add(length).ok_or("ACL end")?>end{return Err("bounded ACL roster".into());}
        for index in 0..count{let mut ace=null_mut();
            if unsafe{GetAce(acl,index as u32,&mut ace)}==0{core.security_parse_error=Some(unsafe{GetLastError()});return Err("ACE query".into());}
            let addr=ace as usize;if addr<address+size_of::<Acl>()||addr.checked_add(8).ok_or("ACE header")?>address+length{return Err("ACE header membership".into());}
            let bytes=unsafe{std::slice::from_raw_parts(ace.cast::<u8>(),8)};let size=u16::from_le_bytes([bytes[2],bytes[3]])as usize;
            if bytes[0]>1||size<16||addr.checked_add(size).ok_or("ACE body")?>address+length{return Err("unsupported/bounded ACE".into());}
            let(sid,n)=sid_in((addr+8)as Ptr,start,end)?;if n as usize>size-8{return Err("ACE SID membership".into());}
            core.security.aces[index]=AceFact{kind:bytes[0],flags:bytes[1],mask:u32::from_le_bytes(bytes[4..8].try_into().map_err(|_|"ACE mask")?),sid,length:n};
            core.security.count=(index+1)as u8;
        }core.security_complete=true;Ok(core.security)
    })();
    core.security_parse_result=Some(result.is_ok());
    if let Err(problem)=&result{core.security_problem=Some(problem.clone());}
    release_allocation(core)?;result
}
pub(super) fn public_object_security(file:&File,os_dll:bool)->Result<()>{
    let principal=CurrentWindowsPrincipal::capture_own()?;
    let mut owner=QueryOwner::allocated();let result=(||{
        if !principal.installation_consumer(){return Err("elevated/system/installer public reader refused".into());}
        let security=snapshot(owner.core.as_mut().expect("query core"),file.as_raw_handle(),1)?;
        let admin=|sid:&[u8]|sid==SYSTEM||sid==ADMINS||(os_dll&&sid==TI);
        if !admin(&security.owner[..security.owner_length as usize]){return Err("public file security owner refused".into());}
        for ace in &security.aces[..security.count as usize]{if ace.flags&8!=0||ace.kind==1{continue;}
            if !admin(&ace.sid[..ace.length as usize])&&ace.mask&(0x2|0x4|0x10|0x100|0x40|0x10000|0x40000|0x80000|0x10000000|0x40000000)!=0{
                return Err("ordinary principal can mutate public installation object".into());}}
        Ok(())
    })();
    match result{Ok(())=>{drop(owner.core.take());principal.recheck()},Err(problem)=>Err(owner.failure(problem))}
}
pub(crate) fn require_own_process_boundary()->Result<()>{
    let principal=CurrentWindowsPrincipal::capture_own()?;let mut owner=QueryOwner::allocated();
    let result=(||{let security=snapshot(owner.core.as_mut().expect("query core"),unsafe{GetCurrentProcess()},6)?;
        let trusted=|sid:&[u8]|sid==principal.user_sid()||sid==SYSTEM||sid==ADMINS;
        if !trusted(&security.owner[..security.owner_length as usize]){return Err("ordinary principal owns process security".into());}
        for ace in &security.aces[..security.count as usize]{if ace.flags&8!=0||ace.kind==1{continue;}
            if !trusted(&ace.sid[..ace.length as usize])&&ace.mask&!(0x1000|0x0400|0x20000|0x100000)!=0{
                return Err("ordinary principal can mutate/private-read protected process".into());}}
        Ok(())})();
    if let Err(problem)=result{return Err(owner.failure(problem));}
    drop(owner.core.take());principal.recheck()
}
