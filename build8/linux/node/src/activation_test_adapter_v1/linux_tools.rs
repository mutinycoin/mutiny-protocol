//! Private Linux static-command adapter. Explicit TEST constructors remain
//! separate from the internal administrator-owned installed tool constructor.
//! No constructor installs or qualifies a provider, and Node wiring is separate.
//! Crypto is performed by a separately reviewed tpm2-tools 5.7 static deployment
//! (source commit c6e182cf690ca0022b77fe7d3c174659917a7e7e). Caller SHA pins
//! are trusted deployment inputs, not proof of upstream provenance or TPM class.
//! Only static ELF images are accepted: dynamic-library/TCTI plugin closure is
//! not silently delegated to ambient ELF loader paths. This ELF check does not
//! itself prove that a trusted static program never calls dlopen: deployment
//! review must establish built-in crypto/TCTI implementations. No tool installed.
use super::{tools_format, Error, Result};
use mutiny_consensus_v8::activation_attestation_v1::{EncryptedCredential, Failure, MakeCredential};
use sha2::{Digest,Sha256};
use std::{ffi::{CString,OsStr},fs::File,io::{Read,Seek,SeekFrom,Write},
    os::{fd::{AsRawFd,FromRawFd,IntoRawFd},unix::{ffi::OsStrExt,fs::MetadataExt,process::CommandExt}},
    path::{Component,Path},process::{Command,Stdio}};
use zeroize::Zeroizing;
use crate::host_clock::{retained_identity,RetainedCloseReport};
use std::mem::ManuallyDrop;
const MAX_IMAGE:u64=64*1024*1024;

/// Holds the actual executable inode and every opened ancestor. Symlinks,
/// foreign writable deployment files/directories and dynamic ELF are refused.
/// Same-owner/root mutation is outside this TEST trusted deployment boundary;
/// held image bytes are hashed again before and after every invocation.
struct ToolState {
    image:Option<ManuallyDrop<File>>,ancestors:Vec<ManuallyDrop<File>>,
    original:Vec<Option<[u8;24]>>,sha256:[u8;32],installed:bool,
    close:Option<RetainedCloseReport>,expected:usize,
}
pub struct ToolPin {state:ManuallyDrop<Box<ToolState>>}
pub(crate) enum ToolClose {
    Retained(ManuallyDrop<ToolPin>),Uncertain(RetainedCloseReport),
}
fn open_at(parent:i32,name:&OsStr,flags:i32)->Result<File>{
    let name=CString::new(name.as_bytes()).map_err(|_|Error::ToolPin)?;
    let fd=unsafe{libc::openat(parent,name.as_ptr(),flags|libc::O_CLOEXEC|libc::O_NOFOLLOW)};
    if fd<0{return Err(Error::ToolPin);} Ok(unsafe{File::from_raw_fd(fd)})
}
fn trusted(file:&File,directory:bool)->Result<()> {
    let m=file.metadata().map_err(|_|Error::ToolPin)?;
    if (m.uid()!=0 && m.uid()!=unsafe{libc::geteuid()}) || m.mode()&0o022!=0
        || (directory && !m.is_dir()) || (!directory && (!m.is_file()||m.nlink()!=1)) {
        return Err(Error::ToolPin);
    } Ok(())
}
impl ToolPin {
    pub fn open_static_test(path:&Path,sha256:[u8;32])->Result<Self>{
        if sha256==[0;32] || !path.is_absolute(){return Err(Error::ToolPin);}
        let parts=path.components().collect::<Vec<_>>();
        if parts.len()<2 || parts[0]!=Component::RootDir{return Err(Error::ToolPin);}
        let expected=parts.len();
        let close=RetainedCloseReport::prepare(expected).map_err(|_|Error::ToolIo)?;
        let mut ancestors=Vec::new();ancestors.try_reserve_exact(expected-1).map_err(|_|Error::ToolIo)?;
        let mut original=Vec::new();original.try_reserve_exact(expected).map_err(|_|Error::ToolIo)?;
        let mut value=Self{state:ManuallyDrop::new(Box::new(ToolState{
            image:None,ancestors,original,sha256,installed:false,close:Some(close),expected}))};
        // Publish every original native holder before metadata/protection checks.
        let root=open_at(libc::AT_FDCWD,OsStr::new("/"),libc::O_PATH|libc::O_DIRECTORY)?;
        value.retain_directory(root)?;
        for part in &parts[1..parts.len()-1] {
            let Component::Normal(name)=part else{return Err(Error::ToolPin);};
            let f=open_at(value.state.ancestors.last().ok_or(Error::ToolPin)?.as_raw_fd(),name,libc::O_PATH|libc::O_DIRECTORY)?;
            value.retain_directory(f)?;
        }
        let Component::Normal(name)=parts.last().ok_or(Error::ToolPin)? else{return Err(Error::ToolPin);};
        let image=open_at(value.state.ancestors.last().ok_or(Error::ToolPin)?.as_raw_fd(),name,libc::O_RDONLY)?;
        value.state.image=Some(ManuallyDrop::new(image));value.state.original.push(None);
        let pin=retained_identity(value.image()).map_err(|_|Error::ToolPin)?;
        *value.state.original.last_mut().ok_or(Error::ToolPin)?=Some(pin);
        trusted(value.image(),false)?;value.recheck()?;Ok(value)
    }
    fn retain_directory(&mut self,file:File)->Result<()> {
        assert!(self.state.ancestors.len()<self.state.expected-1);
        self.state.ancestors.push(ManuallyDrop::new(file));self.state.original.push(None);
        let pin=retained_identity(self.state.ancestors.last().ok_or(Error::ToolPin)?)
            .map_err(|_|Error::ToolPin)?;
        *self.state.original.last_mut().ok_or(Error::ToolPin)?=Some(pin);
        trusted(self.state.ancestors.last().ok_or(Error::ToolPin)?,true)
    }
    fn image(&self)->&File{self.state.image.as_ref().expect("complete original static image")}
    /// Internal normal tool selection, not TPM/provider qualification. Only
    /// root-admin-owned, non-foreign-writable original static ELF is retained.
    /// It cannot install a program, create a key or initialize an NV index.
    pub(crate) fn open_static_installed(path:&Path,sha256:[u8;32])->Result<Self>{
        let mut value=Self::open_static_test(path,sha256)?;
        value.state.installed=true;value.recheck()?;Ok(value)
    }
    pub(crate) fn recheck_installed(&self)->Result<()> {
        if !self.state.installed{return Err(Error::ToolPin);}self.recheck()
    }
    pub(crate) fn close_retained(mut self)->std::result::Result<(),ToolClose> {
        if self.recheck_installed().is_err(){return Err(ToolClose::Retained(ManuallyDrop::new(self)));}
        let close=self.close_known();
        if close.retained_handles_closed(){Ok(())}else{Err(ToolClose::Uncertain(close))}
    }
    fn close_known(&mut self)->RetainedCloseReport {
        let state=&mut **self.state;
        let mut close=state.close.take().expect("preallocated original tool report");
        for (file,pin) in state.ancestors.drain(..).zip(state.original.iter()) {
            close.file(ManuallyDrop::into_inner(file),pin.expect("original retained ancestor identity"));
        }
        let image=ManuallyDrop::into_inner(state.image.take().expect("original retained executable"));
        close.file(image,state.original.last().copied().flatten().expect("original image identity"));
        close
    }
    pub fn recheck(&self)->Result<()> {
        if self.state.image.is_none() || self.state.original.len()!=self.state.expected
            || self.state.original.iter().any(Option::is_none){return Err(Error::ToolPin);}
        for f in &self.state.ancestors {trusted(f,true)?;} trusted(self.image(),false)?;
        if self.state.installed && (self.image().metadata().map_err(|_|Error::ToolPin)?.uid()!=0
            || self.state.ancestors.iter().any(|f|f.metadata().map_or(true,|m|m.uid()!=0))) {
            return Err(Error::ToolPin);
        }
        let n=self.image().metadata().map_err(|_|Error::ToolPin)?.len();
        if n<64||n>MAX_IMAGE{return Err(Error::ToolPin);}
        // This accepted encoding is explicitly ELF64 little-endian, not all ELF.
        let mut f=self.image();
        f.seek(SeekFrom::Start(0)).map_err(|_|Error::ToolPin)?;
        let mut h=[0u8;64]; f.read_exact(&mut h).map_err(|_|Error::ToolPin)?;
        if &h[..4]!=b"\x7fELF"||h[4]!=2||h[5]!=1||h[6]!=1{return Err(Error::ToolPin);}
        let at=u64::from_le_bytes(h[32..40].try_into().map_err(|_|Error::ToolPin)?);
        let width=u16::from_le_bytes(h[54..56].try_into().map_err(|_|Error::ToolPin)?) as u64;
        let count=u16::from_le_bytes(h[56..58].try_into().map_err(|_|Error::ToolPin)?) as u64;
        if width!=56||count==0||count>128||at.checked_add(width*count).is_none_or(|end|end>n){return Err(Error::ToolPin);}
        for i in 0..count {
            f.seek(SeekFrom::Start(at+i*width)).map_err(|_|Error::ToolPin)?;
            let mut kind=[0;4];f.read_exact(&mut kind).map_err(|_|Error::ToolPin)?;
            // PT_INTERP and PT_DYNAMIC: no ambient loader, plugin or library claim.
            if [2,3].contains(&u32::from_le_bytes(kind)){return Err(Error::ToolPin);}
        }
        f.seek(SeekFrom::Start(0)).map_err(|_|Error::ToolPin)?;
        let mut hash=Sha256::new();let mut b=[0;16384];let mut read=0u64;
        loop {let got=f.read(&mut b).map_err(|_|Error::ToolPin)?;if got==0{break;}
            read=read.checked_add(got as u64).ok_or(Error::ToolPin)?;
            if read>MAX_IMAGE{return Err(Error::ToolPin);}hash.update(&b[..got]);}
        if read!=n || <[u8;32]>::from(hash.finalize())!=self.state.sha256{return Err(Error::ToolPin);} Ok(())
    }
}
impl Drop for ToolPin {
    fn drop(&mut self){
        if self.state.image.is_none() && self.state.ancestors.is_empty(){
            unsafe{ManuallyDrop::drop(&mut self.state)};return;
        }
        // Incomplete/current-refused construction retains the original boxed
        // roster; every successfully captured identity remains next to its file.
        if self.recheck().is_err(){return;}
        drop(self.close_known());unsafe{ManuallyDrop::drop(&mut self.state)};
    }
}
/// Anonymous UNSEALED memfd memory, not kernel-sealed or locked memory.
/// Drop attempts bounded overwrite before close; failure is not observable there
/// and cannot establish erasure. No response bytes/auth values are log content.
/// Mutable output/session files intentionally have no MFD_ALLOW_SEALING/F_ADD_SEALS.
struct MemoryState {
    file:Option<ManuallyDrop<File>>,original:Option<[u8;24]>,
    close:Option<RetainedCloseReport>,
}
pub(crate) struct Memory {state:ManuallyDrop<Box<MemoryState>>}
pub(crate) enum MemoryFailure {
    BeforeOpen(Error),
    Retained{owner:ManuallyDrop<Memory>,cause:Error},
    Uncertain(RetainedCloseReport),
}
// Legacy private TEST adapters return only their existing refusal category.
// Consuming a typed error never destroys unknown native custody: boxed retained
// states are ManuallyDrop and the shared report retains uncertain raw records.
impl From<MemoryFailure> for Error {fn from(error:MemoryFailure)->Self{match error{MemoryFailure::BeforeOpen(cause)=>cause,_=>Error::ToolIo}}}
impl Memory {
    pub(crate) fn new(bytes:&[u8])->std::result::Result<Self,MemoryFailure>{
        if bytes.len()>tools_format::MAX_CONTAINER{return Err(MemoryFailure::BeforeOpen(Error::Bounds));}
        let close=RetainedCloseReport::prepare(1).map_err(|_|MemoryFailure::BeforeOpen(Error::ToolIo))?;
        // Every custody allocation precedes the first native effect.
        let mut value=Self{state:ManuallyDrop::new(Box::new(MemoryState{
            file:None,original:None,close:Some(close)}))};
        let fd=unsafe{libc::memfd_create(c"mutiny-activation-test".as_ptr(),libc::MFD_CLOEXEC)};
        if fd<0 {return Err(MemoryFailure::BeforeOpen(Error::ToolIo));}
        value.state.file=Some(ManuallyDrop::new(unsafe{File::from_raw_fd(fd)}));
        let pin=match retained_identity(value.file()) {Ok(pin)=>pin,Err(_)=>{
            return Err(MemoryFailure::Retained{owner:ManuallyDrop::new(value),cause:Error::ToolIo});
        }};
        value.state.original=Some(pin);
        // NEW anonymous object only; no existing filesystem permissions change.
        if unsafe{libc::fchmod(fd,0o600)}!=0 || value.file_mut().write_all(bytes).is_err() {
            return Err(MemoryFailure::Retained{owner:ManuallyDrop::new(value),cause:Error::ToolIo});
        }Ok(value)
    }
    pub(crate) fn bounded(&self,limit:usize)->Result<Zeroizing<Vec<u8>>>{
        let n=self.file().metadata().map_err(|_|Error::ToolIo)?.len();
        if n>limit as u64{return Err(Error::Bounds);}
        // Borrow the original owned file; no duplicate descriptor to abandon.
        let mut f=self.file();
        f.seek(SeekFrom::Start(0)).map_err(|_|Error::ToolIo)?;
        let mut raw=Zeroizing::new(vec![0;n as usize]);f.read_exact(&mut raw).map_err(|_|Error::ToolIo)?;
        if f.metadata().map_err(|_|Error::ToolIo)?.len()!=n{return Err(Error::ToolIo);}Ok(raw)
    }
    pub(crate) fn file(&self)->&File{self.state.file.as_ref().expect("owned memfd exists")}
    fn file_mut(&mut self)->&mut File{self.state.file.as_mut().expect("owned memfd exists")}
    fn erase(&mut self)->Result<()> {
        let file=self.file_mut();
        let n=file.metadata().map_err(|_|Error::ToolIo)?.len();
        if n>tools_format::MAX_CONTAINER as u64{return Err(Error::Bounds);}
        file.seek(SeekFrom::Start(0)).map_err(|_|Error::ToolIo)?;
        let zero=[0;4096];let mut left=n;
        while left>0 {let count=left.min(zero.len() as u64) as usize;
            file.write_all(&zero[..count]).map_err(|_|Error::ToolIo)?;left-=count as u64;}
        file.flush().map_err(|_|Error::ToolIo)
    }
    /// Independent checked erase/close for the normal NV producer. A failure
    /// refuses the operation; it never supplies erasure or native-close credit.
    pub(crate) fn finish(mut self)->std::result::Result<(),MemoryFailure> {
        if let Err(cause)=self.erase(){return Err(MemoryFailure::Retained{owner:ManuallyDrop::new(self),cause});}
        let pin=match self.state.original {Some(pin)=>pin,None=>{
            return Err(MemoryFailure::Retained{owner:ManuallyDrop::new(self),cause:Error::ToolIo});
        }};
        let mut close=self.state.close.take().expect("preallocated memfd close receipt");
        let file=ManuallyDrop::into_inner(self.state.file.take().expect("original memfd"));
        close.file(file,pin);
        if !close.retained_handles_closed(){return Err(MemoryFailure::Uncertain(close));}Ok(())
    }
}
impl Drop for Memory {
    fn drop(&mut self){
        if self.state.file.is_none(){unsafe{ManuallyDrop::drop(&mut self.state)};return;}
        // A failed constructor or erase keeps the preallocated whole original
        // holder. Drop grants no erasure/closure result and never retries an FD.
        if self.state.original.is_none() || self.erase().is_err(){return;}
        let pin=self.state.original.expect("original identity");
        let mut close=self.state.close.take().expect("original close receipt");
        let file=ManuallyDrop::into_inner(self.state.file.take().expect("original memfd"));
        close.file(file,pin);
        // Unknown records survive report abandonment under the shared helper.
        drop(close);unsafe{ManuallyDrop::drop(&mut self.state)};
    }
}
fn duplicate(file:&File)->Result<File>{
    let fd=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_DUPFD_CLOEXEC,20)};
    if fd<0{return Err(Error::ToolIo);}Ok(unsafe{File::from_raw_fd(fd)})
}
struct InvocationFile {file:ManuallyDrop<File>,original:Option<[u8;24]>}
struct InvocationState {files:Vec<InvocationFile>,close:Option<RetainedCloseReport>,maximum:usize}
pub(crate) struct InvocationFiles {state:ManuallyDrop<Box<InvocationState>>}
pub(crate) enum InvokeFailure {
    BeforeOpen(Error),Retained{owner:ManuallyDrop<InvocationFiles>,cause:Error},
    Uncertain{close:RetainedCloseReport,cause:Option<Error>},
}
impl From<InvokeFailure> for Error {fn from(error:InvokeFailure)->Self{match error{InvokeFailure::BeforeOpen(cause)=>cause,_=>Error::ToolIo}}}
impl InvocationFiles {
    fn prepare(maximum:usize)->Result<Self>{
        let close=RetainedCloseReport::prepare(maximum).map_err(|_|Error::ToolIo)?;
        let mut files=Vec::new();files.try_reserve_exact(maximum).map_err(|_|Error::ToolIo)?;
        Ok(Self{state:ManuallyDrop::new(Box::new(InvocationState{files,close:Some(close),maximum}))})
    }
    fn retain_duplicate(&mut self,file:&File)->Result<()> {
        assert!(self.state.files.len()<self.state.maximum);
        let copy=duplicate(file)?;
        self.state.files.push(InvocationFile{file:ManuallyDrop::new(copy),original:None});
        let entry=self.state.files.last_mut().ok_or(Error::ToolIo)?;
        entry.original=Some(retained_identity(&entry.file).map_err(|_|Error::ToolIo)?);Ok(())
    }
    fn file(&self,index:usize)->&File{&self.state.files[index].file}
    fn close(mut self,result:Result<()>)->std::result::Result<(),InvokeFailure>{
        if self.state.files.len()!=self.state.maximum || self.state.files.iter().any(|v|v.original.is_none()){
            return Err(InvokeFailure::Retained{owner:ManuallyDrop::new(self),cause:result.err().unwrap_or(Error::ToolIo)});
        }
        let mut close=self.state.close.take().expect("preallocated invocation duplicate close");
        for entry in self.state.files.drain(..){close.file(ManuallyDrop::into_inner(entry.file),entry.original.expect("original identity"));}
        if !close.retained_handles_closed(){return Err(InvokeFailure::Uncertain{close,cause:result.err()});}
        result.map_err(InvokeFailure::BeforeOpen)
    }
}
impl Drop for InvocationFiles {
    fn drop(&mut self){
        // Abandoned or partially constructed invocations retain original files
        // and their captured identities in the already allocated whole holder.
        if self.state.files.is_empty(){unsafe{ManuallyDrop::drop(&mut self.state)};}
    }
}
/// Natural child ownership on every IO/error path. A stuck upstream tool keeps
/// this worker owned; the signing gate's caller-specified elapsed expiry still
/// refuses completion. This synchronous adapter must never run on the UI actor.
pub(crate) fn invoke(tool:&ToolPin,name:&str,args:&[String],inputs:&[&File],secret:Option<&[u8;32]>)->Result<()> {
    invoke_owned(tool,name,args,inputs,secret).map_err(Error::from)
}
pub(crate) fn invoke_owned(tool:&ToolPin,name:&str,args:&[String],inputs:&[&File],secret:Option<&[u8;32]>)
    ->std::result::Result<(),InvokeFailure> {
    if inputs.len()>5{return Err(InvokeFailure::BeforeOpen(Error::Bounds));}
    let mut owned=InvocationFiles::prepare(inputs.len()+1).map_err(InvokeFailure::BeforeOpen)?;
    let setup=(||{
    tool.recheck()?;
    // Keep executable >=20 too: child dup2 into3..7 must never replace the
    // descriptor referred to by the /proc/self/fd executable path.
    owned.retain_duplicate(tool.image())?;
    for file in inputs {owned.retain_duplicate(file)?;}
    Ok(())})();
    if let Err(cause)=setup{return Err(InvokeFailure::Retained{owner:ManuallyDrop::new(owned),cause});}
    let result=(||{
    let exec_image=owned.file(0);
    let fds=(1..owned.state.maximum).map(|index|owned.file(index).as_raw_fd()).collect::<Vec<_>>();
    let mut command=Command::new(format!("/proc/self/fd/{}",exec_image.as_raw_fd()));
    command.arg0(format!("tpm2_{name}")).args(args).env_clear().current_dir("/")
        // Prevent ambient OpenSSL configuration/engine/provider selection. A
        // deployment needing an external provider fails instead of using it.
        .env("OPENSSL_CONF","/dev/null").env("OPENSSL_MODULES","/proc/self/fd/-1")
        .env("OPENSSL_ENGINES","/proc/self/fd/-1")
        .stdin(if secret.is_some(){Stdio::piped()}else{Stdio::null()})
        .stdout(Stdio::null()).stderr(Stdio::null());
    unsafe {command.pre_exec(move||{
        // Sources >=20 avoid destructive dup2 collisions with targets3..7.
        for (i,fd) in fds.iter().enumerate(){if libc::dup2(*fd,3+i as i32)<0{return Err(std::io::Error::last_os_error());}}
        Ok(())
    });}
    let mut child=command.spawn().map_err(|_|Error::ToolIo)?;
    let write=match secret {
        Some(value)=>match child.stdin.take(){Some(mut input)=>input.write_all(value).map_err(|_|Error::ToolIo),None=>Err(Error::ToolIo)},
        None=>Ok(()),
    };
    // No captured stdout/stderr, no private bytes in an error value/Debug.
    // wait errors retain ownership; there is no error-return path dropping a
    // possibly live child. Persistent observation failure remains an owned
    // partial worker, not an expiry-triggered detach/kill or signing success.
    let mut observation_gap=false;
    let status=loop {match child.wait(){Ok(status)=>break status,Err(_)=>{
        observation_gap=true;std::thread::sleep(std::time::Duration::from_millis(20));
    }}};
    tool.recheck()?;write?;
    if observation_gap{return Err(Error::ToolIo);}
    if !status.success(){return Err(Error::ToolExit);} Ok(())})();
    owned.close(result)
}
pub struct SoftwareMakeCredential {tool:ToolPin}
/// Normal, fixed software MakeCredential operation over an existing installed
/// static tool. This grants no TPM provisioning, admission or physical lineage.
struct InstalledMakerState{tool:Option<ManuallyDrop<ToolPin>>,public:Option<ManuallyDrop<Memory>>,
    output:Option<ManuallyDrop<Memory>>,memory_failures:Vec<MemoryFailure>,
    invocation_failure:Option<InvokeFailure>,tool_close:Option<ToolClose>,frozen:bool}
pub(crate) struct InstalledMakeCredential{state:ManuallyDrop<Box<InstalledMakerState>>}
pub(crate) struct InstalledMakerRefusal{owner:ManuallyDrop<InstalledMakeCredential>}
impl InstalledMakeCredential{
    pub(crate) fn from_installed(tool:ManuallyDrop<ToolPin>)->std::result::Result<Self,InstalledMakerRefusal>{
        let out=Self{state:ManuallyDrop::new(Box::new(InstalledMakerState{tool:Some(tool),public:None,output:None,
            memory_failures:Vec::with_capacity(3),invocation_failure:None,tool_close:None,frozen:false}))};
        if out.state.tool.as_ref().expect("published original tool").recheck_installed().is_err(){
            return Err(InstalledMakerRefusal{owner:ManuallyDrop::new(out)});}
        Ok(out)
    }
    fn make_installed(&mut self,ek:&[u8],name:&[u8;34],secret:&[u8;32])->Result<EncryptedCredential>{
        if self.state.frozen{return Err(Error::ToolIo);}
        mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(ek).map_err(|_|Error::Context)?;
        if name[..2]!=[0,11]||name[2..]==[0;32]||secret==&[0;32]{return Err(Error::Context);}
        self.state.frozen=true;let s=&mut **self.state;
        let result=(||->Result<EncryptedCredential>{
            let tool=s.tool.as_ref().ok_or(Error::ToolPin)?;tool.recheck_installed()?;
            s.public=Some(ManuallyDrop::new(match Memory::new(ek){Ok(v)=>v,Err(e)=>{
                s.memory_failures.push(e);return Err(Error::ToolIo);}}));
            s.output=Some(ManuallyDrop::new(match Memory::new(&[]){Ok(v)=>v,Err(e)=>{
                s.memory_failures.push(e);return Err(Error::ToolIo);}}));
            let args=vec!["-Q".into(),"-T".into(),"none".into(),"-u".into(),"/proc/self/fd/3".into(),
                "-s".into(),"-".into(),"-n".into(),hex::encode(name),"-o".into(),"/proc/self/fd/4".into()];
            if let Err(e)=invoke_owned(tool,"makecredential",&args,
                &[s.public.as_ref().ok_or(Error::ToolIo)?.file(),s.output.as_ref().ok_or(Error::ToolIo)?.file()],Some(secret)){
                s.invocation_failure=Some(e);return Err(Error::ToolIo);}
            tool.recheck_installed()?;
            tools_format::decode_native(&s.output.as_ref().ok_or(Error::ToolIo)?.bounded(tools_format::NATIVE_CONTAINER_MAX)?)
        })();
        // Both owned buffers independently erase/close even after the first
        // failure. Their original typed uncertainty remains in this state.
        for memory in [s.public.take(),s.output.take()].into_iter().flatten(){
            if let Err(e)=ManuallyDrop::into_inner(memory).finish(){s.memory_failures.push(e);}
        }
        if !s.memory_failures.is_empty()||s.invocation_failure.is_some(){return Err(Error::ToolIo);}
        match result{Ok(v)=>{s.frozen=false;Ok(v)},Err(e)=>Err(e)}
    }
    pub(crate) fn close_retained(mut self)->std::result::Result<(),InstalledMakerRefusal>{
        if self.state.frozen||self.state.public.is_some()||self.state.output.is_some()
            ||!self.state.memory_failures.is_empty()||self.state.invocation_failure.is_some()
            ||self.state.tool.as_ref().map_or(true,|v|v.recheck_installed().is_err()){
            return Err(InstalledMakerRefusal{owner:ManuallyDrop::new(self)});}
        let tool=self.state.tool.take().expect("published original tool");
        if let Err(e)=ManuallyDrop::into_inner(tool).close_retained(){self.state.tool_close=Some(e);
            return Err(InstalledMakerRefusal{owner:ManuallyDrop::new(self)});}
        unsafe{ManuallyDrop::drop(&mut self.state)};Ok(())
    }
}
impl MakeCredential for InstalledMakeCredential{
    fn make_credential(&mut self,ek:&[u8],name:&[u8;34],secret:&[u8;32])
        ->std::result::Result<EncryptedCredential,Failure>{self.make_installed(ek,name,secret).map_err(|_|Failure::Adapter)}
}
impl SoftwareMakeCredential {pub fn test_only(tool:ToolPin)->Self{Self{tool}}}
impl MakeCredential for SoftwareMakeCredential {
    fn make_credential(&mut self,ek:&[u8],name:&[u8;34],secret:&[u8;32])->std::result::Result<EncryptedCredential,Failure>{
        self.make(ek,name,secret).map_err(|_|Failure::Adapter)
    }
}
impl SoftwareMakeCredential {
    fn make(&self,ek:&[u8],name:&[u8;34],secret:&[u8;32])->Result<EncryptedCredential>{
        mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(ek).map_err(|_|Error::Context)?;
        if name[..2]!=[0,11]||name[2..]==[0;32]||secret==&[0;32]{return Err(Error::Context);}
        let public=Memory::new(ek)?;let output=Memory::new(&[])?;
        // NO -G: exact TPM2B_PUBLIC template is preserved. -T none delegates
        // MakeCredential cryptography to the upstream software implementation.
        let args=vec!["-Q".into(),"-T".into(),"none".into(),"-u".into(),"/proc/self/fd/3".into(),
            "-s".into(),"-".into(),"-n".into(),hex::encode(name),"-o".into(),"/proc/self/fd/4".into()];
        invoke(&self.tool,"makecredential",&args,&[public.file(),output.file()],Some(secret))?;
        tools_format::decode_native(&output.bounded(tools_format::NATIVE_CONTAINER_MAX)?)
    }
}
/// Explicit empty-auth software TEST objects only. AK/EK persistent handles and
/// their exact expected public bytes come from a separately trusted bootstrap.
/// No Production, dynamic TCTI plugin, password or provisioning route exists.
/// Standard EK PolicySecret/session profiles need a separate reviewed adapter.
pub struct EmptyAuthEndpoint {tool:ToolPin,ak:u32,ek:u32,ak_public:Vec<u8>,ek_public:Vec<u8>,name:[u8;34]}
impl EmptyAuthEndpoint {
    pub fn test_only(tool:ToolPin,ak:u32,ek:u32,ak_public:Vec<u8>,ek_public:Vec<u8>)->Result<Self>{
        if !(0x81000000..=0x81ffffff).contains(&ak)||!(0x81000000..=0x81ffffff).contains(&ek)||ak==ek{return Err(Error::Endpoint);}
        mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(&ek_public).map_err(|_|Error::Context)?;
        let name=mutiny_consensus_v8::provenance::ak_name(&ak_public).map_err(|_|Error::Context)?;
        Ok(Self{tool,ak,ek,ak_public,ek_public,name})
    }
    fn public(&self,handle:u32,expected:&[u8])->Result<()> {
        let out=Memory::new(&[])?;
        // Explicit built-in device TCTI: no ambient env/default/plugin selector.
        let args=vec!["-Q".into(),"-T".into(),"device:/dev/tpmrm0".into(),"-c".into(),format!("0x{handle:08x}"),
            "-o".into(),"/proc/self/fd/3".into()];
        invoke(&self.tool,"readpublic",&args,&[out.file()],None)?;
        if out.bounded(4096)?.as_slice()!=expected{return Err(Error::Endpoint);} Ok(())
    }
    /// Calls the actual upstream ActivateCredential command ONLY when invoked
    /// by a separately authorized interoperability campaign. Source preparation
    /// never calls this method. Device substitution/physical qualification is
    /// not inferred from a returned value; this endpoint is TEST-only.
    pub fn activate(&self,name:&[u8;34],credential:&EncryptedCredential)->Result<Zeroizing<[u8;32]>>{
        if name!=&self.name{return Err(Error::Endpoint);}
        tools_format::native_bounds(credential)?;
        self.public(self.ak,&self.ak_public)?;self.public(self.ek,&self.ek_public)?;
        let input=Memory::new(&tools_format::encode_native(credential)?)?;let output=Memory::new(&[])?;
        let args=vec!["-Q".into(),"-T".into(),"device:/dev/tpmrm0".into(),"-c".into(),format!("0x{:08x}",self.ak),
            "-C".into(),format!("0x{:08x}",self.ek),"-i".into(),"/proc/self/fd/3".into(),
            "-o".into(),"/proc/self/fd/4".into()];
        invoke(&self.tool,"activatecredential",&args,&[input.file(),output.file()],None)
            .map_err(|e|if e==Error::ToolExit{Error::ActivationRejected}else{e})?;
        let raw=output.bounded(32)?;if raw.len()!=32{return Err(Error::Response);}
        let mut value=Zeroizing::new([0;32]);value.copy_from_slice(&raw);
        self.public(self.ak,&self.ak_public)?;self.public(self.ek,&self.ek_public)?;Ok(value)
    }
}

/// Explicit bounded TEST enrollment lookup for every class in a private chunk.
/// Identity/AK Name come from exact enrolled public areas, not a remote address
/// or claimed physical platform. This lookup cannot establish physical uniqueness.
/// More endpoints/remote forwarding need an independently reviewed TEST host;
/// this local resource quota never changes native scope/class requirements.
pub struct EndpointSet {
    endpoints:std::collections::BTreeMap<([u8;32],[u8;34]),EmptyAuthEndpoint>,
}
impl EndpointSet {
    pub fn test_only(endpoints:Vec<EmptyAuthEndpoint>)->Result<Self>{
        if endpoints.is_empty()||endpoints.len()>64{return Err(Error::Bounds);}
        let mut pinned=std::collections::BTreeMap::new();
        for endpoint in endpoints {
            let public=mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(&endpoint.ek_public)
                .map_err(|_|Error::Context)?;
            let id=public.key.identity().map_err(|_|Error::Context)?;
            if pinned.insert((id,endpoint.name),endpoint).is_some(){return Err(Error::Endpoint);}
        }Ok(Self{endpoints:pinned})
    }
    pub fn activate_chunk(&self,expected:&super::exchange::ChallengeFrame)
        ->Result<super::exchange::ResponseFrame>{
        expected.encode()?;
        // Resolve ALL exact enrolled endpoints before invoking any TPM command;
        // an absent class cannot produce a partial successful response frame.
        let selected=expected.items.iter().map(|c|self.endpoints.get(&(c.identity,c.ak_name))
            .ok_or(Error::Endpoint)).collect::<Result<Vec<_>>>()?;
        let mut values=Vec::with_capacity(selected.len());
        for (item,endpoint) in expected.items.iter().zip(selected) {
            let encrypted=EncryptedCredential::new(item.credential.clone(),item.seed.clone())
                .map_err(|_|Error::Bounds)?;
            values.push(endpoint.activate(&item.ak_name,&encrypted)?);
        }
        super::exchange::ResponseFrame::new(expected,values)
    }
}

/// Narrow software-only standard TCG Policy-A/SHA256 endpoint. This does not
/// support high-range Policy-B, nonempty hierarchy/AK auth, physical endpoints,
/// remote host selection, production or enrollment/provisioning commands.
/// Bootstrap owns/pins the disposable simulator and its local TCP namespaces;
/// numerical port selection is a transport input, NEVER activation expiry.
#[cfg(test)]
pub struct PolicySecretSimulatorEndpoint {
    inner:EmptyAuthEndpoint,tcti:String,poisoned:bool,
}
// Exact public policy_a_sha256 in pinned tpm2-tools tools/tpm2_createek.c 34..42.
#[cfg(test)]
const POLICY_A_SHA256:[u8;32]=[
  0x83,0x71,0x97,0x67,0x44,0x84,0xb3,0xf8,0x1a,0x90,0xcc,0x8d,0x46,0xa5,0xd7,0x24,
  0xfd,0x52,0xd7,0x6e,0x06,0x52,0x0b,0x64,0xf2,0xa1,0xda,0x1b,0x33,0x14,0x69,0xaa];
#[cfg(test)]
fn policy_a(public:&[u8])->Result<()> {
    mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(public).map_err(|_|Error::Context)?;
    // TPM2B length/type/nameAlg/attributes precede TPM2B_DIGEST authPolicy.
    if public.get(4..6)!=Some(&[0,11][..]) || public.get(10..12)!=Some(&[0,32][..])
        || public.get(12..44)!=Some(&POLICY_A_SHA256[..]) {return Err(Error::Unsupported);} Ok(())
}
#[cfg(test)]
impl PolicySecretSimulatorEndpoint {
    pub fn test_only(tool:ToolPin,port:u16,ak:u32,ek:u32,ak_public:Vec<u8>,ek_public:Vec<u8>)->Result<Self>{
        // Adjacent control port is also caller-owned; no default/device fallback.
        if !(1024..65535).contains(&port){return Err(Error::Endpoint);}policy_a(&ek_public)?;
        Ok(Self{inner:EmptyAuthEndpoint::test_only(tool,ak,ek,ak_public,ek_public)?,
            tcti:format!("swtpm:host=127.0.0.1,port={port}"),poisoned:false})
    }
    fn args(&self,tail:&[&str])->Vec<String>{
        [vec!["-Q".into(),"-T".into(),self.tcti.clone()],tail.iter().map(|s|s.to_string()).collect()].concat()
    }
    fn public(&self,handle:u32,expected:&[u8])->Result<()> {
        let out=Memory::new(&[])?;let handle=format!("0x{handle:08x}");
        invoke(&self.inner.tool,"readpublic",&self.args(&["-c",&handle,"-o","/proc/self/fd/3"]),&[out.file()],None)?;
        if out.bounded(4096)?.as_slice()!=expected{return Err(Error::Endpoint);}Ok(())
    }
    /// Explicitly invoked only by reviewed disposable software interoperability
    /// worker. No hardware/device, provisioning, secrets on argv or log path.
    /// Every command child is naturally waited by invoke. Gate's trusted local
    /// expiry remains outside this transport; no numeric expiry is introduced.
    pub fn activate(&mut self,name:&[u8;34],credential:&EncryptedCredential)->Result<Zeroizing<[u8;32]>>{
        if self.poisoned||name!=&self.inner.name{return Err(Error::Endpoint);}
        tools_format::native_bounds(credential)?;
        self.public(self.inner.ak,&self.inner.ak_public)?;self.public(self.inner.ek,&self.inner.ek_public)?;
        let session=Memory::new(&[])?;let digest=Memory::new(&[])?;
        let input=Memory::new(&tools_format::encode_native(credential)?)?;let output=Memory::new(&[])?;
        // Poison before starting: a failed StartAuthSession can leave an owned
        // simulator session with no usable saved context. No retry may ignore it.
        self.poisoned=true;
        let result=(||{
            invoke(&self.inner.tool,"startauthsession",&self.args(&["--policy-session","-g","sha256","-S","/proc/self/fd/3"]),&[session.file()],None)?;
            if session.bounded(tools_format::MAX_CONTAINER)?.is_empty(){return Err(Error::ToolIo);}
            // Endorsement hierarchy empty TEST auth; no optional -t (TPM ticket
            // expiration), -x, qualifier, cpHash or caller-controlled auth args.
            invoke(&self.inner.tool,"policysecret",&self.args(&["-c","e","-S","/proc/self/fd/3","-L","/proc/self/fd/4"]),&[session.file(),digest.file()],None)?;
            if digest.bounded(32)?.as_slice()!=POLICY_A_SHA256{return Err(Error::Context);}
            let ak=format!("0x{:08x}",self.inner.ak);let ek=format!("0x{:08x}",self.inner.ek);
            invoke(&self.inner.tool,"activatecredential",&self.args(&["-c",&ak,"-C",&ek,"-P","session:/proc/self/fd/5",
                "-i","/proc/self/fd/3","-o","/proc/self/fd/4"]),&[input.file(),output.file(),session.file()],None)
                .map_err(|e|if e==Error::ToolExit{Error::ActivationRejected}else{e})?;
            let raw=output.bounded(32)?;if raw.len()!=32{return Err(Error::Response);}
            let mut value=Zeroizing::new([0;32]);value.copy_from_slice(&raw);Ok(value)
        })();
        // Exact saved context only. Never --loaded-session/--saved-session or
        // any global flush. Even failed PolicySecret/Activate attempts drain the
        // owned session; cleanup failure refuses response and keeps poison.
        let cleanup=match session.bounded(tools_format::MAX_CONTAINER) {
            Ok(raw) if !raw.is_empty()=>invoke(&self.inner.tool,"flushcontext",&self.args(&["/proc/self/fd/3"]),&[session.file()],None),
            _=>Err(Error::ToolIo),
        };
        cleanup?;
        self.public(self.inner.ak,&self.inner.ak_public)?;self.public(self.inner.ek,&self.inner.ek_public)?;
        self.poisoned=false;result
    }
}

/// All-class dispatcher for independently bootstrapped disposable SOFTWARE
/// simulator endpoints. Exact identity/name resolves ALL items before calls;
/// missing classes never produce a partial successful ResponseFrame.
#[cfg(test)]
pub struct PolicySimulatorSet {
    endpoints:std::collections::BTreeMap<([u8;32],[u8;34]),PolicySecretSimulatorEndpoint>,
}
#[cfg(test)]
impl PolicySimulatorSet {
    pub fn test_only(endpoints:Vec<PolicySecretSimulatorEndpoint>)->Result<Self>{
        if endpoints.is_empty()||endpoints.len()>64{return Err(Error::Bounds);}
        let mut pinned=std::collections::BTreeMap::new();
        for endpoint in endpoints {
            let public=mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(&endpoint.inner.ek_public).map_err(|_|Error::Context)?;
            let id=public.key.identity().map_err(|_|Error::Context)?;
            if pinned.insert((id,endpoint.inner.name),endpoint).is_some(){return Err(Error::Endpoint);}
        }Ok(Self{endpoints:pinned})
    }
    pub fn activate_chunk(&mut self,expected:&super::exchange::ChallengeFrame)->Result<super::exchange::ResponseFrame>{
        expected.encode()?;
        let keys=expected.items.iter().map(|item|(item.identity,item.ak_name)).collect::<Vec<_>>();
        if keys.iter().any(|key|!self.endpoints.contains_key(key)){return Err(Error::Endpoint);}
        let mut values=Vec::with_capacity(keys.len());
        for (item,key) in expected.items.iter().zip(keys){
            let encrypted=EncryptedCredential::new(item.credential.clone(),item.seed.clone()).map_err(|_|Error::Bounds)?;
            values.push(self.endpoints.get_mut(&key).ok_or(Error::Endpoint)?.activate(&item.ak_name,&encrypted)?);
        }
        super::exchange::ResponseFrame::new(expected,values)
    }
}
