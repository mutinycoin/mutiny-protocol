// EXTERNAL SOURCE-ONLY. NONSHIPPING Windows local TEST process identity only.
// Bootstrap Pins MUST originate from independently launched PID/start/image receipts.
// This module cannot grant wallet approval, verify owner signatures or prove finality.
// Native no-follow opened image and every ancestor are lifetime-held by ImagePin.
// Actual path-substitution/ACL/peer controls still require native runtime; account/admin compromise is excluded.
#![cfg(windows)]
use std::{mem::{size_of,zeroed},path::{Path,PathBuf}};
use super::image_pin::ImagePin;
use windows_sys::Win32::{Foundation::{CloseHandle,FILETIME,HANDLE,INVALID_HANDLE_VALUE,WAIT_TIMEOUT},
    Security::{GetLengthSid,GetTokenInformation,TOKEN_QUERY,TOKEN_STATISTICS,TOKEN_USER,TokenSessionId,TokenStatistics,TokenUser},
    System::{Pipes::{GetNamedPipeClientProcessId,GetNamedPipeClientSessionId,GetNamedPipeServerProcessId},
        Threading::{GetCurrentProcess,GetProcessId,GetProcessTimes,OpenProcess,OpenProcessToken,PROCESS_QUERY_LIMITED_INFORMATION,PROCESS_SYNCHRONIZE,QueryFullProcessImageNameW,WaitForSingleObject}}};
type Result<T> = std::result::Result<T,String>;
const MAX_TOKEN_BYTES:usize=4096;
const MAX_SID_BYTES:usize=68;

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {fn drop(&mut self){unsafe{CloseHandle(self.0);}}}
impl OwnedHandle {
    fn new(h:HANDLE)->Result<Self> {
        if h.is_null() || h==INVALID_HANDLE_VALUE {Err("Local process handle refused".into())} else {Ok(Self(h))}
    }
}
#[derive(Clone,Debug,PartialEq,Eq,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub pid:u32,pub start_filetime:u64,pub session:u32,
    pub authentication_luid:(u32,i32),pub user_sid:Vec<u8>,
    pub image_path:PathBuf,pub image_sha256:[u8;32],
}
pub struct VerifiedProcess {
    handle:OwnedHandle,
    // Kept open without FILE_SHARE_WRITE/DELETE for connection lifetime.
    // The pin identifies the launched process + held on-disk executable, not arbitrary mapped memory.
    _image_pin:ImagePin,
    identity:Identity,
}
struct TokenBuffer {words:Vec<usize>,bytes:usize}
fn token_info(token:HANDLE,class:i32)->Result<TokenBuffer> {
    let mut bytes=0u32;
    unsafe{GetTokenInformation(token,class,std::ptr::null_mut(),0,&mut bytes);}
    let n=bytes as usize;
    if n==0 || n>MAX_TOKEN_BYTES {return Err("Local token information bound".into());}
    let mut words=vec![0usize;n.div_ceil(size_of::<usize>())];
    let allocated=(words.len()*size_of::<usize>()) as u32;
    if unsafe{GetTokenInformation(token,class,words.as_mut_ptr().cast(),allocated,&mut bytes)}==0 || bytes==0 || bytes>allocated {
        return Err("Local token information refused".into());
    }
    Ok(TokenBuffer{words,bytes:bytes as usize})
}
fn token_identity(handle:HANDLE)->Result<(u32,(u32,i32),Vec<u8>)> {
    let mut raw=std::ptr::null_mut();
    if unsafe{OpenProcessToken(handle,TOKEN_QUERY,&mut raw)}==0 {return Err("Local process token refused".into());}
    let token=OwnedHandle::new(raw)?;
    let user=token_info(token.0,TokenUser)?;
    if user.bytes<size_of::<TOKEN_USER>() {return Err("Local TOKEN_USER bound".into());}
    let u=unsafe{&*user.words.as_ptr().cast::<TOKEN_USER>()};
    let start=user.words.as_ptr() as usize;let end=start.checked_add(user.bytes).ok_or("Local token range")?;
    let sid=u.User.Sid as usize;
    if sid<start || sid.checked_add(8).ok_or("Local SID overflow")?>end {return Err("Local SID range".into());}
    let len=unsafe{GetLengthSid(u.User.Sid)} as usize;
    if !(8..=MAX_SID_BYTES).contains(&len) || sid.checked_add(len).ok_or("Local SID overflow")?>end {return Err("Local SID bound".into());}
    let sid=unsafe{std::slice::from_raw_parts(u.User.Sid.cast::<u8>(),len)}.to_vec();
    let stats=token_info(token.0,TokenStatistics)?;
    if stats.bytes!=size_of::<TOKEN_STATISTICS>() {return Err("Local TOKEN_STATISTICS bound".into());}
    let stats=unsafe{&*stats.words.as_ptr().cast::<TOKEN_STATISTICS>()};
    let auth=(stats.AuthenticationId.LowPart,stats.AuthenticationId.HighPart);
    let session=token_info(token.0,TokenSessionId)?;
    if session.bytes!=size_of::<u32>() {return Err("Local token session bound".into());}
    let session=unsafe{*session.words.as_ptr().cast::<u32>()};
    Ok((session,auth,sid))
}
fn same_image_path(a:&Path,b:&Path)->bool {
    // This bounded TEST campaign uses bootstrap ASCII paths only, not a general path normalizer.
    let (Some(a),Some(b))=(a.to_str(),b.to_str()) else{return false};
    a.is_ascii() && b.is_ascii() && a.eq_ignore_ascii_case(b)
}
fn inspect(handle:HANDLE)->Result<(Identity,ImagePin)> {
    if unsafe{WaitForSingleObject(handle,0)}!=WAIT_TIMEOUT {return Err("Local process not live".into());}
    let pid=unsafe{GetProcessId(handle)};if pid==0 {return Err("Local process PID refused".into());}
    let (mut created,mut exited,mut kernel,mut user):(FILETIME,FILETIME,FILETIME,FILETIME)=unsafe{zeroed()};
    if unsafe{GetProcessTimes(handle,&mut created,&mut exited,&mut kernel,&mut user)}==0 {return Err("Local process start refused".into());}
    let start_filetime=((created.dwHighDateTime as u64)<<32)|created.dwLowDateTime as u64;
    if start_filetime==0 {return Err("Local process start zero".into());}
    let mut path=vec![0u16;32768];let mut length=path.len() as u32;
    if unsafe{QueryFullProcessImageNameW(handle,0,path.as_mut_ptr(),&mut length)}==0 || length==0 || length as usize>=path.len() {return Err("Local process image path refused".into());}
    path.truncate(length as usize);
    let image_path=PathBuf::from(String::from_utf16(&path).map_err(|_|"Local process image UTF16")?);
    let (session,authentication_luid,user_sid)=token_identity(handle)?;
    let image=ImagePin::open(&image_path,&user_sid)?;
    let image_sha256=image.hash();
    if unsafe{WaitForSingleObject(handle,0)}!=WAIT_TIMEOUT {return Err("Local process exited while pinning".into());}
    Ok((Identity{pid,start_filetime,session,authentication_luid,user_sid,image_path,image_sha256},image))
}
impl VerifiedProcess {
    /// Native observation for an independently created process bootstrap receipt.
    /// This grants no role: a caller must bind the returned native tuple to its
    /// actual Child/process creation handle, exact source/artifact and fixed role.
    pub fn observe_created_process(pid:u32)->Result<Identity>{
        if pid==0{return Err("Native bootstrap zero PID".into());}
        let handle=OwnedHandle::new(unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_SYNCHRONIZE,0,pid)})?;
        inspect(handle.0).map(|(i,_held)|i)
    }

    pub fn open(expected:&Identity)->Result<Self> {
        if expected.pid==0 || expected.start_filetime==0 || expected.image_sha256==[0;32] || !(8..=MAX_SID_BYTES).contains(&expected.user_sid.len()) {return Err("Local bootstrap process pin invalid".into());}
        let handle=OwnedHandle::new(unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_SYNCHRONIZE,0,expected.pid)})?;
        let (actual,image)=inspect(handle.0)?;
        if actual.pid!=expected.pid || actual.start_filetime!=expected.start_filetime || actual.session!=expected.session || actual.authentication_luid!=expected.authentication_luid || actual.user_sid!=expected.user_sid || actual.image_sha256!=expected.image_sha256 || !same_image_path(&actual.image_path,&expected.image_path) {return Err("Local live process bootstrap mismatch".into());}
        let (session,auth,sid)=token_identity(unsafe{GetCurrentProcess()})?;
        if actual.session!=session || actual.authentication_luid!=auth || actual.user_sid!=sid {return Err("Local peer differs from current user/logon/session".into());}
        Ok(Self{handle,_image_pin:image,identity:actual})
    }
    pub fn identity(&self)->&Identity {&self.identity}
    pub fn opened_image_identity(&self)->&super::image_pin::Id {self._image_pin.leaf_id()}
    pub fn recheck(&self)->Result<()> {
        if unsafe{WaitForSingleObject(self.handle.0,0)}!=WAIT_TIMEOUT {return Err("Local pinned peer exited".into());}
        self._image_pin.recheck()?;
        let (session,auth,sid)=token_identity(self.handle.0)?;
        if session!=self.identity.session || auth!=self.identity.authentication_luid || sid!=self.identity.user_sid {
            return Err("Local pinned primary token identity changed".into());
        }
        // Same-session/logon/user policy remains CURRENT at both endpoints,
        // including calls made without RolePipe's separate held own-process pin.
        let (own_session,own_auth,own_sid)=token_identity(unsafe{GetCurrentProcess()})?;
        if own_session!=self.identity.session||own_auth!=self.identity.authentication_luid||own_sid!=self.identity.user_sid{
            return Err("Local current endpoint primary token differs from pinned peer tuple".into());
        }
        if unsafe{WaitForSingleObject(self.handle.0,0)}!=WAIT_TIMEOUT {return Err("Local pinned peer exited during token recheck".into());}
        Ok(())
    }
    // pipe HANDLE must be this connection's verified native local named pipe, not request data.
    pub fn match_client_pipe(&self,pipe:HANDLE)->Result<()> {
        self.recheck()?;let(mut pid,mut session)=(0,0);
        if unsafe{GetNamedPipeClientProcessId(pipe,&mut pid)}==0 || unsafe{GetNamedPipeClientSessionId(pipe,&mut session)}==0 || pid!=self.identity.pid || session!=self.identity.session {return Err("Local pipe client PID/session mismatch".into());}
        self.recheck()
    }
    pub fn match_server_pipe(&self,pipe:HANDLE)->Result<()> {
        self.recheck()?;let mut pid=0;
        if unsafe{GetNamedPipeServerProcessId(pipe,&mut pid)}==0 || pid!=self.identity.pid {return Err("Local pipe server PID mismatch".into());}
        self.recheck()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_own_process_positive_and_independently_wrong_bootstrap_pins_refuse() {
        let (actual,_held)=inspect(unsafe{GetCurrentProcess()}).unwrap();
        let verified=VerifiedProcess::open(&actual).unwrap();
        assert_eq!(verified.identity(),&actual);
        let mut wrong=actual.clone();wrong.start_filetime^=1;assert!(VerifiedProcess::open(&wrong).is_err());
        wrong=actual.clone();wrong.session^=1;assert!(VerifiedProcess::open(&wrong).is_err());
        wrong=actual.clone();wrong.authentication_luid.0^=1;assert!(VerifiedProcess::open(&wrong).is_err());
        wrong=actual.clone();let n=wrong.user_sid.len()-1;wrong.user_sid[n]^=1;assert!(VerifiedProcess::open(&wrong).is_err());
        wrong=actual.clone();wrong.image_sha256[0]^=1;assert!(VerifiedProcess::open(&wrong).is_err());
        wrong=actual.clone();wrong.image_path=wrong.image_path.with_file_name("wrong-bootstrap-image.exe");assert!(VerifiedProcess::open(&wrong).is_err());
        wrong=actual.clone();wrong.pid=0;assert!(VerifiedProcess::open(&wrong).is_err());
        assert!(verified.match_client_pipe(std::ptr::null_mut()).is_err());
        assert!(verified.match_server_pipe(std::ptr::null_mut()).is_err());
        verified.recheck().unwrap();
        // Actual authentication of a DIFFERENT allowed live GUI role still needs pipe integration.
    }
}

/// A historical bootstrap PID/start tuple is not new role authentication. This
/// merely refuses mutable passive reopen while any exact original process is
/// still running. Access denial/unknown errors fail closed; no stop or signal.
pub fn historical_process_closed(expected:&Identity)->Result<()> {
    use windows_sys::Win32::Foundation::{GetLastError,ERROR_INVALID_PARAMETER,WAIT_OBJECT_0};
    if expected.pid==0||expected.start_filetime==0{return Err("Historical process tuple missing".into());}
    let raw=unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_SYNCHRONIZE,0,expected.pid)};
    if raw.is_null(){
        if unsafe{GetLastError()}==ERROR_INVALID_PARAMETER{return Ok(());}
        return Err("Original process closure cannot be established; preserve stores".into());
    }
    let held=OwnedHandle::new(raw)?;
    if unsafe{GetProcessId(held.0)}!=expected.pid{return Err("Original process native PID readback differs".into());}
    let(mut started,mut exited,mut kernel,mut user)=(unsafe{zeroed::<FILETIME>()},unsafe{zeroed::<FILETIME>()},unsafe{zeroed::<FILETIME>()},unsafe{zeroed::<FILETIME>()});
    if unsafe{GetProcessTimes(held.0,&mut started,&mut exited,&mut kernel,&mut user)}==0{return Err("Original process native start unavailable".into());}
    let actual=(u64::from(started.dwHighDateTime)<<32)|u64::from(started.dwLowDateTime);
    if actual!=expected.start_filetime{return Ok(());} // PID reused; historical tuple exited, never new role authority.
    match unsafe{WaitForSingleObject(held.0,0)} {
        WAIT_OBJECT_0=>Ok(()),WAIT_TIMEOUT=>Err("Exact original process remains live; passive mutation refused".into()),
        _=>Err("Original process closure observation refused".into()),
    }
}

#[cfg(test)]
mod passive_process_closure_tests {
    use super::*;
    #[test]
    fn actual_live_original_tuple_refuses_passive_mutation_and_missing_tuple_never_qualifies(){
        let actual=VerifiedProcess::observe_created_process(std::process::id()).unwrap();
        assert!(historical_process_closed(&actual).is_err());
        let mut wrong=actual.clone();wrong.pid=0;assert!(historical_process_closed(&wrong).is_err());
        wrong=actual;wrong.start_filetime=0;assert!(historical_process_closed(&wrong).is_err());
        // Closed child/PID-reuse positives and all four exact original process
        // closures remain separate native runner observations, never inferred.
    }
}
