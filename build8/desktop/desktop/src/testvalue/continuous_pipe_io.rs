// EXTERNAL SOURCE-ONLY. Fresh local TEST role pipe, no existing ACL mutation.
#![cfg(windows)]
use std::{mem::{size_of,zeroed},ptr,time::{Duration,Instant}};
use super::{control_codec::{Hash,Role},process_auth::VerifiedProcess};
use windows_sys::Win32::{Foundation::{CloseHandle,GetLastError,HANDLE,HLOCAL,INVALID_HANDLE_VALUE,LocalFree,ERROR_PIPE_CONNECTED,ERROR_PIPE_LISTENING},
    Security::{Authorization::{ConvertSidToStringSidW,ConvertStringSecurityDescriptorToSecurityDescriptorW,GetSecurityInfo,SE_KERNEL_OBJECT},
        ACCESS_ALLOWED_ACE,ACL_SIZE_INFORMATION,AclSizeInformation,DACL_SECURITY_INFORMATION,GetAce,GetAclInformation,GetLengthSid,GetSecurityDescriptorControl,OWNER_SECURITY_INFORMATION,SECURITY_ATTRIBUTES,SE_DACL_PROTECTED},
    Storage::FileSystem::{FILE_ALL_ACCESS,FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_ACCESS_DUPLEX},
    System::{Pipes::{ConnectNamedPipe,CreateNamedPipeW,PIPE_NOWAIT,PIPE_READMODE_MESSAGE,PIPE_REJECT_REMOTE_CLIENTS,PIPE_TYPE_MESSAGE},Threading::GetCurrentProcessId}};
type Result<T> = std::result::Result<T,String>;
pub const PIPE_MARKER:&str="MUTINY-W15-NONSHIPPING-LOCAL-PIPE-V1";

struct LocalAllocation(HLOCAL);
impl Drop for LocalAllocation {fn drop(&mut self){unsafe{LocalFree(self.0);}}}
pub struct RolePipe {handle:HANDLE,name:String,role:Role,owner:VerifiedProcess}
impl Drop for RolePipe {fn drop(&mut self){unsafe{CloseHandle(self.handle);}}}

fn sid_string(bytes:&[u8])->Result<String> {
    if !(8..=68).contains(&bytes.len()) {return Err("Local pipe SID bound".into());}
    let mut aligned=vec![0usize;bytes.len().div_ceil(size_of::<usize>())];
    unsafe{ptr::copy_nonoverlapping(bytes.as_ptr(),aligned.as_mut_ptr().cast::<u8>(),bytes.len());}
    let mut raw=ptr::null_mut();
    if unsafe{ConvertSidToStringSidW(aligned.as_mut_ptr().cast(),&mut raw)}==0 || raw.is_null() {return Err("Local pipe SID conversion".into());}
    let _allocation=LocalAllocation(raw.cast());
    let mut length=0usize;
    while length<192 && unsafe{*raw.add(length)}!=0 {length+=1;}
    if length==0 || length==192 {return Err("Local pipe SID string bound".into());}
    let text=String::from_utf16(unsafe{std::slice::from_raw_parts(raw,length)}).map_err(|_|"Local pipe SID UTF16")?;
    if !text.starts_with("S-1-") || !text.bytes().all(|b|b.is_ascii_digit() || b==b'S' || b==b'-') {return Err("Local pipe SID text refused".into());}
    Ok(text)
}
fn copy_sid(raw:*mut core::ffi::c_void)->Result<Vec<u8>> {
    if raw.is_null(){return Err("Local pipe SID absent".into());}
    let size=unsafe{GetLengthSid(raw)} as usize;
    if !(8..=68).contains(&size){return Err("Local pipe SID size".into());}
    Ok(unsafe{std::slice::from_raw_parts(raw.cast::<u8>(),size)}.to_vec())
}
fn check_new_pipe_security(handle:HANDLE,owner_sid:&[u8])->Result<()> {
    let(mut owner,mut dacl,mut descriptor)=(ptr::null_mut(),ptr::null_mut(),ptr::null_mut());
    if unsafe{GetSecurityInfo(handle,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        &mut owner,ptr::null_mut(),&mut dacl,ptr::null_mut(),&mut descriptor)}!=0 || descriptor.is_null() || dacl.is_null() {
        // A successful descriptor allocation is always released, even if the DACL is absent.
        if !descriptor.is_null(){unsafe{LocalFree(descriptor);}}
        return Err("Local pipe security readback refused".into());
    }
    let _allocation=LocalAllocation(descriptor);
    let(mut control,mut revision)=(0u16,0u32);
    if unsafe{GetSecurityDescriptorControl(descriptor,&mut control,&mut revision)}==0 || revision!=1 || control&SE_DACL_PROTECTED==0 || copy_sid(owner)?!=owner_sid {
        return Err("Local pipe owner/protected DACL mismatch".into());
    }
    let mut size:ACL_SIZE_INFORMATION=unsafe{zeroed()};
    if unsafe{GetAclInformation(dacl,(&mut size as *mut ACL_SIZE_INFORMATION).cast(),size_of::<ACL_SIZE_INFORMATION>() as u32,AclSizeInformation)}==0 || size.AceCount!=2 || size.AclBytesInUse>256 {
        return Err("Local pipe exact two-ACE readback refused".into());
    }
    // Binary well-known LocalSystem SID; two identities must each occur exactly once.
    let system=[1u8,1,0,0,0,0,0,5,18,0,0,0];
    let(mut users,mut systems)=(0,0);
    for i in 0..2 {
        let mut raw=ptr::null_mut();
        if unsafe{GetAce(dacl,i,&mut raw)}==0 || raw.is_null(){return Err("Local pipe ACE unavailable".into());}
        let ace=unsafe{&*raw.cast::<ACCESS_ALLOWED_ACE>()};
        if ace.Header.AceType!=0 || ace.Header.AceFlags!=0 || ace.Header.AceSize<16 || ace.Header.AceSize>76 || ace.Mask!=FILE_ALL_ACCESS {
            return Err("Local pipe ACE type/flags/full-control mismatch".into());
        }
        let sid_raw=unsafe{raw.cast::<u8>().add(8)};
        let subauthorities=unsafe{*sid_raw.add(1)} as usize;
        if subauthorities>15||8+8+4*subauthorities>ace.Header.AceSize as usize{return Err("Local pipe ACE SID extent refused".into());}
        let sid=copy_sid(sid_raw.cast())?;
        if ace.Header.AceSize as usize!=8+sid.len(){return Err("Local pipe ACE/SID width mismatch".into());}
        if sid==owner_sid {users+=1;}else if sid==system {systems+=1;}else{return Err("Local pipe foreign principal refused".into());}
    }
    if users!=1 || systems!=1 {return Err("Local pipe exact current-user/System identities mismatch".into());}
    Ok(())
}
impl RolePipe {
    pub fn create(campaign:Hash,role:Role,current_process:&VerifiedProcess)->Result<Self> {
        current_process.recheck()?;
        if campaign==[0;32] || current_process.identity().pid!=unsafe{GetCurrentProcessId()} {return Err("Local pipe bootstrap owner/campaign refused".into());}
        let own_pin=VerifiedProcess::open(current_process.identity())?;
        let sid=&current_process.identity().user_sid;
        let sid_text=sid_string(sid)?;
        let sddl=format!("O:{sid_text}D:P(A;;0x001f01ff;;;SY)(A;;0x001f01ff;;;{sid_text})");
        let sddl:Vec<u16>=sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor=ptr::null_mut();
        if unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(),1,&mut descriptor,ptr::null_mut())}==0 || descriptor.is_null(){return Err("Local pipe protected security descriptor refused".into());}
        let _allocation=LocalAllocation(descriptor);
        let attributes=SECURITY_ATTRIBUTES{nLength:size_of::<SECURITY_ATTRIBUTES>() as u32,lpSecurityDescriptor:descriptor,bInheritHandle:0};
        // Separate FIRST_PIPE_INSTANCE name for each of exactly three bootstrap roles.
        // No request can supply or alter this path, role or DACL.
        let name=format!(r"\\.\pipe\Mutiny-W15-{}-{}",hex::encode(campaign),role as u8);
        let name_wide:Vec<u16>=name.encode_utf16().chain(Some(0)).collect();
        let handle=unsafe{CreateNamedPipeW(name_wide.as_ptr(),PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_NOWAIT|PIPE_REJECT_REMOTE_CLIENTS,
            1,2048,2048,0,&attributes)};
        if handle.is_null() || handle==INVALID_HANDLE_VALUE {return Err("Fresh first local role pipe refused; existing endpoint preserved".into());}
        let pipe=Self{handle,name,role,owner:own_pin};
        check_new_pipe_security(pipe.handle,sid)?;
        Ok(pipe)
    }
    pub fn name(&self)->&str{&self.name}
    pub fn role(&self)->Role{self.role}
    // Immediate nonblocking connection poll; caller owns one campaign-wide deadline.
    // No synchronous blocking read or detached pending OVERLAPPED memory to abandon.
    pub fn poll_authenticated_connection(&self,expected_peer:&VerifiedProcess)->Result<bool> {
        self.owner.recheck()?;expected_peer.recheck()?;
        let connected=unsafe{ConnectNamedPipe(self.handle,ptr::null_mut())};
        // In PIPE_NOWAIT the first nonzero result means available/listening,
        // not authenticated connection. Only ERROR_PIPE_CONNECTED proves connected.
        if connected!=0 {return Ok(false);}
        if connected==0 {
            match unsafe{GetLastError()} {
                ERROR_PIPE_LISTENING=>return Ok(false),
                ERROR_PIPE_CONNECTED=>{},
                _=>return Err("Local role pipe connection refused".into()),
            }
        }
        expected_peer.match_client_pipe(self.handle)?;
        Ok(true)
    }
    // Handle stays private until bounded/authenticated IO integration is reviewed.
}

use super::{control_codec::{self,Context,Head,Request},control_reply::{self,Reply}};
use windows_sys::Win32::{Foundation::{ERROR_MORE_DATA,ERROR_NO_DATA,ERROR_PIPE_BUSY},
    Storage::FileSystem::{CreateFileW,ReadFile,WriteFile,OPEN_EXISTING,READ_CONTROL,FILE_SHARE_READ,FILE_SHARE_WRITE},
    System::Pipes::SetNamedPipeHandleState};
const GENERIC_READ:u32=0x80000000;
const GENERIC_WRITE:u32=0x40000000;
pub struct Deadline(Instant);
impl Deadline {
    // Construct once per header/response/action. Callers cannot extend a pending action.
    pub fn new()->Self {Self(Instant::now()+Duration::from_secs(30))}
    pub fn instant(&self)->Instant{self.0}
    fn check(&self)->Result<()> {if Instant::now()<self.0{Ok(())}else{Err("Local TEST action deadline reached; preserve partial".into())}}
    fn poll(&self)->Result<()> {self.check()?;std::thread::sleep(Duration::from_millis(5));self.check()}
}
#[derive(Debug,PartialEq,Eq)]
pub enum Availability{Empty,Message,Disconnected}
pub struct Received {pub request:Request,pub exact_bytes:Vec<u8>}
fn read_message_part(handle:HANDLE,bytes:&mut [u8],deadline:&Deadline,peer:&VerifiedProcess,owner:&VerifiedProcess,server:bool)->Result<bool> {
    if bytes.is_empty()||bytes.len()>1024{return Err("Local pipe read allocation bound".into());}
    loop {
        deadline.check()?;owner.recheck()?;
        if server{peer.match_client_pipe(handle)?;}else{peer.match_server_pipe(handle)?;}
        let mut read=0;
        let ok=unsafe{ReadFile(handle,bytes.as_mut_ptr(),bytes.len() as u32,&mut read,ptr::null_mut())};
        // GetLastError is captured immediately, before any other Windows call.
        let code=if ok==0{unsafe{GetLastError()}}else{0};
        if server{peer.match_client_pipe(handle)?;}else{peer.match_server_pipe(handle)?;}
        owner.recheck()?;
        if ok!=0 {
            if read as usize!=bytes.len(){return Err("Local pipe short message refused".into());}
            return Ok(false); // Exact message ended.
        }
        match code {
            ERROR_NO_DATA if read==0=>deadline.poll()?,
            ERROR_MORE_DATA if read as usize==bytes.len()=>return Ok(true),
            _=>return Err(format!("Local pipe message read refused {code}/{read}")),
        }
    }
}
fn write_message(handle:HANDLE,bytes:&[u8],deadline:&Deadline,peer:&VerifiedProcess,owner:&VerifiedProcess,server:bool)->Result<()> {
    if bytes.is_empty()||bytes.len()>1024{return Err("Local pipe write bound".into());}
    loop {
        deadline.check()?;owner.recheck()?;
        if server{peer.match_client_pipe(handle)?;}else{peer.match_server_pipe(handle)?;}
        let mut written=0;
        let ok=unsafe{WriteFile(handle,bytes.as_ptr(),bytes.len() as u32,&mut written,ptr::null_mut())};
        let code=if ok==0{unsafe{GetLastError()}}else{0};
        if server{peer.match_client_pipe(handle)?;}else{peer.match_server_pipe(handle)?;}
        owner.recheck()?;
        if ok!=0&&written as usize==bytes.len(){return Ok(());}
        // PIPE_NOWAIT message writes are all-or-zero; a partial positive never retries.
        if ok!=0&&written==0 {deadline.poll()?;continue;}
        return Err(format!("Local pipe message write refused {code}/{written}"));
    }
}
impl RolePipe {
    // Immediate readiness only. Read occurs on the service worker after exact
    // OS peer recheck. A partial message is never treated as a complete request.
    pub fn request_ready(&self,peer:&VerifiedProcess)->Result<Availability>{
        use windows_sys::Win32::{System::Pipes::PeekNamedPipe,Foundation::{ERROR_BROKEN_PIPE,ERROR_PIPE_NOT_CONNECTED}};
        self.owner.recheck()?;peer.recheck()?;
        let(mut available,mut left)=(0u32,0u32);
        let ok=unsafe{PeekNamedPipe(self.handle,ptr::null_mut(),0,ptr::null_mut(),&mut available,&mut left)};
        let code=if ok==0{unsafe{GetLastError()}}else{0};
        self.owner.recheck()?;peer.recheck()?;
        if ok==0 {
            return match code{ERROR_BROKEN_PIPE|ERROR_PIPE_NOT_CONNECTED=>Ok(Availability::Disconnected),_=>Err(format!("Local bounded readiness refused {code}"))};
        }
        peer.match_client_pipe(self.handle)?;
        if available>1024||left>1024{return Err("Local queued request bound refused".into());}
        Ok(if left!=0{Availability::Message}else{Availability::Empty})
    }
    pub fn disconnect_completed(&self,peer:&VerifiedProcess)->Result<()> {
        use windows_sys::Win32::{System::Pipes::DisconnectNamedPipe,Foundation::ERROR_PIPE_NOT_CONNECTED};
        self.owner.recheck()?;peer.recheck()?;
        let ok=unsafe{DisconnectNamedPipe(self.handle)};let code=if ok==0{unsafe{GetLastError()}}else{0};
        self.owner.recheck()?;peer.recheck()?;
        if ok==0&&code!=ERROR_PIPE_NOT_CONNECTED{return Err(format!("Local role disconnect refused {code}"));}
        check_new_pipe_security(self.handle,&self.owner.identity().user_sid)
    }
    pub fn read_authenticated(&self,peer:&VerifiedProcess,context:Context,head:Head,next_sequence:u64,deadline:&Deadline)->Result<Received> {
        peer.match_client_pipe(self.handle)?;
        let mut raw=[0u8;control_codec::HEADER_BYTES];
        let more=read_message_part(self.handle,&mut raw,deadline,peer,&self.owner,true)?;
        let header=control_codec::decode_header(&raw).map_err(|e|format!("Local bounded header: {e:?}"))?;
        control_codec::check_pins(header,self.role,next_sequence,context,head).map_err(|e|format!("Local authenticated pins: {e:?}"))?;
        let n=header.payload_bytes as usize;
        if (n!=0)!=more{return Err("Local message length/header mismatch".into());}
        // Only after exact OS/process/role/context/head validation, bounded <=760 allocation.
        let mut payload=vec![0u8;n];
        if n!=0&&read_message_part(self.handle,&mut payload,deadline,peer,&self.owner,true)? {return Err("Local request trailing bytes refused".into());}
        let request=control_codec::decode_payload(header,&payload).map_err(|e|format!("Local native payload: {e:?}"))?;
        let mut exact_bytes=raw.to_vec();exact_bytes.extend_from_slice(&payload);
        peer.match_client_pipe(self.handle)?;
        Ok(Received{request,exact_bytes})
    }
    pub fn write_authenticated(&self,peer:&VerifiedProcess,reply:Reply,deadline:&Deadline)->Result<()> {
        let raw=control_reply::encode(reply).map_err(|e|format!("Local typed reply: {e:?}"))?;
        write_message(self.handle,&raw,deadline,peer,&self.owner,true)
    }
}
pub struct ClientPipe {handle:HANDLE,role:Role,server:VerifiedProcess,owner:VerifiedProcess}
impl Drop for ClientPipe {fn drop(&mut self){unsafe{CloseHandle(self.handle);}}}
impl ClientPipe {
    pub fn open(campaign:Hash,role:Role,server:VerifiedProcess,owner:&VerifiedProcess,deadline:&Deadline)->Result<Self> {
        owner.recheck()?;
        if owner.identity().pid!=unsafe{GetCurrentProcessId()}||campaign==[0;32]{return Err("Local client owner/campaign mismatch".into());}
        let own_pin=VerifiedProcess::open(owner.identity())?;
        let name=format!(r"\\.\pipe\Mutiny-W15-{}-{}",hex::encode(campaign),role as u8);
        let name:Vec<u16>=name.encode_utf16().chain(Some(0)).collect();
        let handle=loop {
            deadline.check()?;server.recheck()?;
            let h=unsafe{CreateFileW(name.as_ptr(),GENERIC_READ|GENERIC_WRITE|READ_CONTROL,
                FILE_SHARE_READ|FILE_SHARE_WRITE,ptr::null(),OPEN_EXISTING,0,ptr::null_mut())};
            if h!=INVALID_HANDLE_VALUE&&!h.is_null(){break h;}
            let code=unsafe{GetLastError()};
            if code!=ERROR_PIPE_BUSY&&code!=windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND{return Err(format!("Local pinned client open refused {code}"));}
            deadline.poll()?;
        };
        let result=Self{handle,role,server,owner:own_pin};
        result.server.match_server_pipe(result.handle)?;
        check_new_pipe_security(result.handle,&owner.identity().user_sid)?;
        let mode=PIPE_READMODE_MESSAGE|PIPE_NOWAIT;
        if unsafe{SetNamedPipeHandleState(result.handle,&mode,ptr::null(),ptr::null())}==0{return Err("Local client message/nonblocking mode refused".into());}
        Ok(result)
    }
    // Called from a dedicated bounded worker, never egui/native UI main thread.
    // Reply is only local observation; Controller own replay remains confirmation source.
    // NONSHIPPING native-control peer only; no wallet/production caller.
    // The main hook accepts this mode explicitly. Input is a separately pinned
    // public malformed-message fixture. Success is an ERROR in the control.
    pub(super) fn native_negative_probe(&self,raw:&[u8],deadline:&Deadline)->Result<()> {
        if raw.is_empty()||raw.len()>2048{return Err("Native negative message bound".into());}
        self.owner.recheck()?;self.server.match_server_pipe(self.handle)?;
        let mut written=0;
        let ok=unsafe{WriteFile(self.handle,raw.as_ptr(),raw.len() as u32,&mut written,ptr::null_mut())};
        let code=if ok==0{unsafe{GetLastError()}}else{0};
        self.owner.recheck()?;self.server.match_server_pipe(self.handle)?;
        if ok==0||written as usize!=raw.len(){return Err(format!("Native negative write refused {code}/{written}"));}
        let mut bytes=[0u8;control_reply::HEADER_BYTES];
        if read_message_part(self.handle,&mut bytes,deadline,&self.server,&self.owner,false)?{return Err("Negative got oversized reply".into());}
        control_reply::decode(&bytes).map_err(|e|format!("{e:?}"))?;
        Ok(())
    }
    pub fn exchange(&self,request:&Request,deadline:&Deadline)->Result<Reply> {
        if request.header.role!=self.role{return Err("Local client role mismatch".into());}
        let raw=control_codec::encode(request).map_err(|e|format!("Local canonical request: {e:?}"))?;
        write_message(self.handle,&raw,deadline,&self.server,&self.owner,false)?;
        let mut bytes=[0u8;control_reply::HEADER_BYTES];
        if read_message_part(self.handle,&mut bytes,deadline,&self.server,&self.owner,false)? {return Err("Local reply trailing bytes refused".into());}
        let reply=control_reply::decode(&bytes).map_err(|e|format!("Local bounded reply: {e:?}"))?;
        control_reply::match_request(reply,request.header.sequence,request.header.context.campaign,&raw).map_err(|e|format!("Local reply echo mismatch: {e:?}"))?;
        Ok(reply)
    }
}


// Actual syscall controls are TEST-only and exist solely to distinguish native
// zero/short/no-data outcomes from a completed authenticated action. No ordinary
// or mounted production entry exports a pipe HANDLE or syscall seam.
#[cfg(test)]
impl Deadline {
    pub(super) fn native_control_timeout(duration:Duration)->Self{
        assert!(duration>=Duration::from_millis(1)&&duration<=Duration::from_secs(30));
        Self(Instant::now()+duration)
    }
}
#[cfg(test)]
impl ClientPipe {
    pub(super) fn native_control_write_once(&self,raw:&[u8])->Result<(bool,u32,u32)>{
        if raw.len()>2048{return Err("Native control write bound".into());}
        self.owner.recheck()?;self.server.match_server_pipe(self.handle)?;
        let mut n=0;let ok=unsafe{WriteFile(self.handle,raw.as_ptr(),raw.len() as u32,&mut n,ptr::null_mut())};
        let code=if ok==0{unsafe{GetLastError()}}else{0};
        self.server.match_server_pipe(self.handle)?;self.owner.recheck()?;
        Ok((ok!=0,n,code))
    }
}
#[cfg(test)]
impl RolePipe {
    pub(super) fn native_control_read_once(&self,peer:&VerifiedProcess,raw:&mut[u8])->Result<(bool,u32,u32)>{
        if raw.len()>1024{return Err("Native control read bound".into());}
        self.owner.recheck()?;peer.match_client_pipe(self.handle)?;
        let mut n=0;let ok=unsafe{ReadFile(self.handle,raw.as_mut_ptr(),raw.len() as u32,&mut n,ptr::null_mut())};
        let code=if ok==0{unsafe{GetLastError()}}else{0};
        peer.match_client_pipe(self.handle)?;self.owner.recheck()?;
        Ok((ok!=0,n,code))
    }
    pub(super) fn native_control_remote_loopback_error(&self)->Result<u32>{
        self.owner.recheck()?;
        let local=self.name.strip_prefix(r"\\.\pipe\").ok_or("Native control local pipe prefix")?;
        let path=format!(r"\\localhost\pipe\{local}");let path:Vec<u16>=path.encode_utf16().chain(Some(0)).collect();
        let raw=unsafe{CreateFileW(path.as_ptr(),GENERIC_READ|GENERIC_WRITE,0,ptr::null(),OPEN_EXISTING,0,ptr::null_mut())};
        let code=if raw==INVALID_HANDLE_VALUE||raw.is_null(){unsafe{GetLastError()}}else{0};
        if !raw.is_null()&&raw!=INVALID_HANDLE_VALUE{unsafe{CloseHandle(raw);}}
        self.owner.recheck()?;Ok(code)
    }
}