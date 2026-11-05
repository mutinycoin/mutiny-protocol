//! Counter-specific kernel-authenticated existing endpoint. Blocking native I/O
//! belongs only to the owned private worker; cancellation wakes kernel poll.
//! Kernel credentials/pidfds bind principals and liveness, not peer image bytes.
use super::hybrid_installed_counter_v2::InstalledCounterAuthority;
use super::hybrid_authenticated_counter_v2::{NvExchange,Request};
use crate::host_clock::RetainedCloseReport;
use super::hybrid_native_retained_input_v2::{NativeInputSlot,RetainedNativeFile};
use mutiny_consensus_v8::canonical_store_v2::CanonicalStore;
use std::{fs::File,io,mem::{size_of,zeroed},os::{fd::{AsRawFd,FromRawFd,IntoRawFd},
    unix::{ffi::OsStrExt,fs::{FileTypeExt,MetadataExt},net::UnixStream}},path::{Path,PathBuf},
    sync::{Arc,atomic::{AtomicBool,Ordering}}};
type Result<T>=std::result::Result<T,String>;
const RESPONSE:usize=470;
use std::mem::ManuallyDrop as MD;
enum OriginalClose{Observed(RetainedCloseReport),Retained(MD<RetainedNativeFile>)}
impl OriginalClose{fn known(&self)->bool{matches!(self,Self::Observed(v) if v.retained_handles_closed())}}
fn close_original(file:RetainedNativeFile)->OriginalClose{match file.close_once(){
    Ok(report)=>OriginalClose::Observed(report),Err(owner)=>OriginalClose::Retained(owner)}}
fn finish_original_close(file:RetainedNativeFile)->Result<()>{
    let mut original=MD::new(close_original(file));
    if !original.known(){return Err("original temporary native close retained; no retry".into());}
    unsafe{MD::drop(&mut original)};Ok(())
}
fn original_socket_identity(socket:&UnixStream)->Result<[u8;24]>{
    // Observe the existing ORIGINAL socket, without a second owning File,
    // dup, named reopen or pid-based reconstruction. Same Clock113 tuple.
    let mut facts=std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe{libc::fstat(socket.as_raw_fd(),facts.as_mut_ptr())}!=0 {
        return Err("counter original socket identity unavailable".into());
    }
    let facts=unsafe{facts.assume_init()};let mut pin=[0u8;24];
    pin[..8].copy_from_slice(&(facts.st_dev as u64).to_le_bytes());
    pin[8..16].copy_from_slice(&(facts.st_ino as u64).to_le_bytes());
    pin[16..].copy_from_slice(&(facts.st_nlink as u64).to_le_bytes());Ok(pin)
}
#[derive(Clone,Copy,PartialEq,Eq)]
struct Cred {pid:i32,uid:u32,gid:u32}
impl From<libc::ucred> for Cred {fn from(v:libc::ucred)->Self{Self{pid:v.pid,uid:v.uid,gid:v.gid}}}
fn credential(socket:&UnixStream)->Result<Cred>{
    let mut value:libc::ucred=unsafe{zeroed()};let mut length=size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe{libc::getsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,
        (&mut value as *mut libc::ucred).cast(),&mut length)}!=0 || length as usize!=size_of::<libc::ucred>() {
        return Err("counter kernel peer credentials unavailable".into());
    }Ok(value.into())
}
fn boot()->Result<[u8;36]>{
    use std::io::Read;
    let slot=NativeInputSlot::prepare()?;
    let file=File::open("/proc/sys/kernel/random/boot_id").map_err(|_|"counter boot unavailable")?;
    let file=slot.retain(file).map_err(|error|error.cause)?;
    let result=(||{let mut reader=file.file()?;let mut raw=[0;37];reader.read_exact(&mut raw).map_err(|_|"counter boot exact read")?;
        let mut extra=[0];if raw[36]!=b'\n'||reader.read(&mut extra).map_err(|_|"counter boot EOF")?!=0 {
            return Err("counter boot exact format".into());}
        let value:[u8;36]=raw[..36].try_into().map_err(|_|"counter boot length")?;
        if !value.iter().enumerate().all(|(at,v)|if [8,13,18,23].contains(&at){*v==b'-'}
            else{v.is_ascii_digit()||(b'a'..=b'f').contains(v)}){return Err("counter boot encoding".into());}
        Ok(value)})();
    finish_original_close(file)?;result
}
struct KernelPeer {credential:Cred,pidfd:RetainedNativeFile,boot:[u8;36]}
impl KernelPeer {
    fn capture(socket:&UnixStream,expected:(u32,u32))->Result<Self>{
        let before=credential(socket)?;
        if before.pid<=0||(before.uid,before.gid)!=expected{return Err("counter installed peer principal differs".into());}
        let slot=NativeInputSlot::prepare()?;
        let mut fd=-1i32;let mut length=size_of::<i32>() as libc::socklen_t;
        // Linux SO_PEERPIDFD pins the socket's actual sk_peer_pid, never a new
        // pidfd_open against a potentially recycled caller-supplied numeric PID.
        let captured=unsafe{libc::getsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,77,
            (&mut fd as *mut i32).cast(),&mut length)};
        if fd<0{return Err("counter exact peer pidfd unavailable".into());}
        let pidfd=slot.retain(unsafe{File::from_raw_fd(fd)}).map_err(|error|error.cause)?;
        let flags=unsafe{libc::fcntl(fd,libc::F_GETFD)};
        if captured!=0||length as usize!=size_of::<i32>()||flags<0||flags&libc::FD_CLOEXEC==0 {
            finish_original_close(pidfd)?;
            return Err("counter peer pidfd exact framing refused".into());}
        let current_boot=match boot(){Ok(value)=>value,Err(error)=>{
            finish_original_close(pidfd)?;
            return Err(error);}};
        let result=Self{credential:before,pidfd,boot:current_boot};
        if let Err(error)=result.recheck(socket){
            finish_original_close(result.pidfd)?;
            return Err(error);}
        Ok(result)
    }
    fn recheck(&self,socket:&UnixStream)->Result<()> {
        self.pidfd.recheck_identity()?;
        let mut value=libc::pollfd{fd:self.pidfd.file()?.as_raw_fd(),events:libc::POLLIN,revents:0};
        if unsafe{libc::poll(&mut value,1,0)}!=0||value.revents!=0
            ||credential(socket)?!=self.credential||boot()?!=self.boot {
            return Err("counter peer liveness/boot/current credentials changed".into());}
        Ok(())
    }
}
#[derive(Clone,Copy,PartialEq,Eq)]
struct Identity {dev:u64,ino:u64,mode:u32,uid:u32,gid:u32,links:u64}
fn identity(file:&File)->Result<Identity>{let m=file.metadata().map_err(|_|"counter endpoint native metadata")?;
    Ok(Identity{dev:m.dev(),ino:m.ino(),mode:m.mode(),uid:m.uid(),gid:m.gid(),links:m.nlink()})}
struct EndpointClosed {reports:Vec<RetainedCloseReport>,retained:Vec<std::mem::ManuallyDrop<RetainedNativeFile>>,expected:usize}
impl EndpointClosed {fn known(&self)->bool{self.retained.is_empty()&&self.reports.len()==self.expected
    &&self.reports.iter().all(RetainedCloseReport::retained_handles_closed)}}
struct EndpointState{path:PathBuf,files:Vec<RetainedNativeFile>,ids:Vec<Identity>,closed:Box<EndpointClosed>,
    temporary_unknown:std::cell::RefCell<Option<EndpointClose>>}
struct HeldEndpoint{state:MD<Box<EndpointState>>}
impl std::ops::Deref for HeldEndpoint{type Target=EndpointState;fn deref(&self)->&EndpointState{&self.state}}
enum EndpointClose{Reports(MD<Box<EndpointClosed>>),Retained(MD<HeldEndpoint>)}
impl EndpointClose{fn known(&self)->bool{matches!(self,Self::Reports(v) if v.known())}}
impl Drop for EndpointClose{fn drop(&mut self){
    if let Self::Reports(original)=self{if original.known(){unsafe{MD::drop(original)}}}
}}
impl HeldEndpoint {
    fn capture(authority:&InstalledCounterAuthority)->Result<Self>{
        Self::capture_at(authority,authority.endpoint())
    }
    fn capture_at(authority:&InstalledCounterAuthority,path:PathBuf)->Result<Self>{
        if path!=authority.endpoint()&&path!=authority.unlock_endpoint(){
            return Err("counter fixed installed endpoint route refused".into());}
        let(owner,group)=authority.socket_owner_group();
        let names=path.components().map(|v|match v{std::path::Component::RootDir=>Ok(None),
            std::path::Component::Normal(v)=>Ok(Some(v.to_owned())),_=>Err("counter endpoint path grammar")})
            .collect::<std::result::Result<Vec<_>,_>>()?.into_iter().flatten().collect::<Vec<_>>();
        let open=|fd:i32,name:&std::ffi::OsStr,directory:bool|->Result<RetainedNativeFile>{
            let name=std::ffi::CString::new(name.as_bytes()).map_err(|_|"counter endpoint NUL")?;
            let slot=NativeInputSlot::prepare()?;
            let raw=unsafe{libc::openat(fd,name.as_ptr(),libc::O_PATH|libc::O_NOFOLLOW|libc::O_CLOEXEC
                |if directory{libc::O_DIRECTORY}else{0})};
            if raw<0{return Err("counter exact installed endpoint unavailable".into());}
            slot.retain(unsafe{File::from_raw_fd(raw)}).map_err(|error|error.cause)};
        if !path.is_absolute()||names.len()<2{return Err("counter fixed endpoint placement".into());}
        let count=names.len().checked_add(1).ok_or("counter endpoint roster overflow")?;
        let mut files=Vec::new();files.try_reserve_exact(count).map_err(|_|"counter endpoint custody allocation")?;
        let mut ids=Vec::new();ids.try_reserve_exact(count).map_err(|_|"counter endpoint identity allocation")?;
        let mut reports=Vec::new();reports.try_reserve_exact(count).map_err(|_|"counter endpoint close allocation")?;
        let mut retained=Vec::new();retained.try_reserve_exact(count).map_err(|_|"counter endpoint retained close allocation")?;
        let closed=Box::new(EndpointClosed{reports,retained,expected:count});
        let mut out=Self{state:MD::new(Box::new(EndpointState{path,files,ids,closed,
            temporary_unknown:std::cell::RefCell::new(None)}))};
        let s=&mut **out.state;
        s.files.push(open(libc::AT_FDCWD,std::ffi::OsStr::new("/"),true)?);
        for name in &names[..names.len()-1]{s.files.push(open(s.files.last().ok_or("counter endpoint root")?.file()?.as_raw_fd(),name,true)?);}
        for(at,file)in s.files.iter().enumerate(){let m=file.file()?.metadata().map_err(|_|"counter endpoint ancestor")?;
            if !m.is_dir()||(m.uid()!=0&&m.uid()!=owner)||m.mode()&0o022!=0 {
                return Err("counter installed endpoint ancestor mutation refused".into());}
            if at==s.files.len()-1&&(m.uid()!=owner||m.gid()!=group||m.mode()&0o7777!=0o710){
                return Err("counter installed endpoint leaf permissions differ".into());}}
        s.files.push(open(s.files.last().ok_or("counter endpoint parent")?.file()?.as_raw_fd(),names.last().ok_or("counter endpoint name")?,false)?);
        let file=s.files.last().ok_or("counter socket absent")?;
        let m=file.file()?.metadata().map_err(|_|"counter socket native metadata")?;
        if !m.file_type().is_socket()||m.uid()!=owner||m.gid()!=group||m.nlink()!=1||m.mode()&0o7777!=0o660 {
            return Err("counter socket type/principal/permissions differ".into());}
        for file in &s.files{s.ids.push(identity(file.file()?)?);}Ok(out)
    }
    fn recheck(&self,authority:&InstalledCounterAuthority)->Result<()> {
        if self.temporary_unknown.borrow().is_some(){return Err("counter named endpoint close already uncertain; frozen".into());}
        let named=Self::capture_at(authority,self.path.clone())?;
        let held=self.files.iter().map(|file|{file.recheck_identity()?;identity(file.file()?)}).collect::<Result<Vec<_>>>();
        let same=named.path==self.path&&named.ids==self.ids;
        let mut closed=named.close();
        if !closed.known(){*self.temporary_unknown.borrow_mut()=Some(closed);return Err("counter named endpoint original close unknown".into());}
        drop(closed);
        if !same||held?!=self.ids{return Err("counter endpoint identity changed".into());}Ok(())
    }
    fn close(mut self)->EndpointClose {
        let uncertain=self.temporary_unknown.borrow().is_some();
        if uncertain{return EndpointClose::Retained(MD::new(self));}
        let EndpointState{files,closed,..}=*unsafe{MD::take(&mut self.state)};
        let mut closed=MD::new(closed);
        for file in files {match file.close_once(){Ok(report)=>closed.reports.push(report),
            Err(retained)=>closed.retained.push(retained)}}EndpointClose::Reports(closed)
    }
}
/// Signal-only cancellation, allocated before private worker spawn. Cancellation
/// cannot resume or reset any uncertain counter operation.
pub(crate) struct CounterStop {stopped:AtomicBool,wake:Option<RetainedNativeFile>}
impl CounterStop {
    pub(crate) fn new()->Result<Arc<Self>>{
        // Both the published controller allocation and exact native input
        // custody precede eventfd. No new owner allocation follows acquisition.
        let mut controller=Arc::new(Self{stopped:AtomicBool::new(false),wake:None});
        let slot=NativeInputSlot::prepare()?;
        let fd=unsafe{libc::eventfd(0,libc::EFD_CLOEXEC|libc::EFD_NONBLOCK)};
        if fd<0{return Err("counter cancellation wake unavailable".into());}
        let wake=slot.retain(unsafe{File::from_raw_fd(fd)}).map_err(|failure|failure.cause)?;
        Arc::get_mut(&mut controller).expect("unpublished single controller").wake=Some(wake);Ok(controller)
    }
    fn wake_fd(&self)->Result<i32>{
        let wake=self.wake.as_ref().ok_or("counter original wake absent")?;
        wake.recheck_identity()?;Ok(wake.file()?.as_raw_fd())
    }
    pub(crate) fn stop(&self)->Result<()> {self.stopped.store(true,Ordering::SeqCst);let value=1u64.to_ne_bytes();
        if unsafe{libc::write(self.wake_fd()?,value.as_ptr().cast(),8)}!=8 {
            return Err("counter cancellation wake signal unknown".into());}Ok(())}
    pub(crate) fn close_after_join(self:Arc<Self>)->std::result::Result<(),CounterStopClose> {
        let mut value=match Arc::try_unwrap(self){Ok(v)=>v,Err(v)=>return Err(CounterStopClose::Shared(v))};
        let wake=value.wake.take().expect("published original controller wake");
        // The report retains original identity, observed identity and immediate
        // once-close errno. An unknown numeric descriptor is never retried.
        match wake.close_once(){
            Ok(report) if report.retained_handles_closed()=>Ok(()),
            Ok(report)=>Err(CounterStopClose::Unknown(report)),
            Err(owner)=>Err(CounterStopClose::Retained(owner)),
        }
    }
}
pub(crate) enum CounterStopClose {Shared(Arc<CounterStop>),Unknown(RetainedCloseReport),
    Retained(std::mem::ManuallyDrop<RetainedNativeFile>)}
fn wait(socket:&UnixStream,stop:&CounterStop,events:i16)->Result<()> {
    if stop.stopped.load(Ordering::SeqCst){return Err("counter worker cancelled".into());}
    let mut values=[libc::pollfd{fd:socket.as_raw_fd(),events,revents:0},
        libc::pollfd{fd:stop.wake_fd()?,events:libc::POLLIN,revents:0}];
    loop {let result=unsafe{libc::poll(values.as_mut_ptr(),2,-1)};
        if result<0&&io::Error::last_os_error().kind()==io::ErrorKind::Interrupted{continue;}
        if result<0{return Err("counter kernel readiness unknown".into());}break;}
    if stop.stopped.load(Ordering::SeqCst)||values[1].revents!=0{return Err("counter worker cancelled".into());}
    if values[0].revents&events==0||values[0].revents&(libc::POLLERR|libc::POLLNVAL)!=0 {
        return Err("counter channel kernel readiness refused".into());}Ok(())
}
fn recv(fd:i32,data:&mut[u8],peer:Cred)->io::Result<usize>{
    let mut control=[0usize;64];let mut iov=libc::iovec{iov_base:data.as_mut_ptr().cast(),iov_len:data.len()};
    // The native control buffer is finite. Root enough unique original input
    // slots BEFORE recvmsg can install ANY unwanted received descriptor.
    let maximum_rights=size_of::<[usize;64]>()/size_of::<i32>();
    let mut rights=Vec::new();rights.try_reserve_exact(maximum_rights)
        .map_err(|_|io::Error::other("counter ancillary custody allocation"))?;
    for _ in 0..maximum_rights {rights.push(Some(NativeInputSlot::prepare().map_err(io::Error::other)?));}
    let mut message:libc::msghdr=unsafe{zeroed()};message.msg_iov=&mut iov;message.msg_iovlen=1;
    message.msg_control=control.as_mut_ptr().cast();message.msg_controllen=size_of::<[usize;64]>();
    let bytes=unsafe{libc::recvmsg(fd,&mut message,libc::MSG_DONTWAIT|libc::MSG_CMSG_CLOEXEC)};
    if bytes<0{return Err(io::Error::last_os_error());}
    let mut valid=None;let mut close_unknown=false;let mut used_rights=0;
    let mut refused=message.msg_flags&(libc::MSG_TRUNC|libc::MSG_CTRUNC)!=0
        ||message.msg_controllen>size_of::<[usize;64]>();
    message.msg_controllen=message.msg_controllen.min(size_of::<[usize;64]>());
    let control_end=(message.msg_control as usize).checked_add(message.msg_controllen)
        .ok_or_else(||io::Error::other("counter ancillary range overflow"))?;
    let mut cmsg=unsafe{libc::CMSG_FIRSTHDR(&message)};
    while !cmsg.is_null(){
        let address=cmsg as usize;
        if address.checked_add(size_of::<libc::cmsghdr>()).is_none_or(|end|end>control_end) {
            refused=true;break;
        }
        let header=unsafe{&*cmsg};
        if header.cmsg_len<unsafe{libc::CMSG_LEN(0)}as usize
            ||address.checked_add(header.cmsg_len).is_none_or(|end|end>control_end){refused=true;break;}
        if header.cmsg_level==libc::SOL_SOCKET&&header.cmsg_type==libc::SCM_CREDENTIALS
            &&header.cmsg_len==unsafe{libc::CMSG_LEN(size_of::<libc::ucred>()as u32)}as usize&&valid.is_none(){
            valid=Some(Cred::from(unsafe{std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::ucred>())}));
        }else{refused=true;if header.cmsg_level==libc::SOL_SOCKET&&header.cmsg_type==libc::SCM_RIGHTS {
            let payload=header.cmsg_len-(unsafe{libc::CMSG_LEN(0)}as usize);
            if payload%size_of::<i32>()!=0{refused=true;}
            let count=payload/size_of::<i32>();
            for at in 0..count{let fd=unsafe{std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<i32>().add(at))};
                if fd<0||used_rights>=rights.len(){refused=true;break;}
                let slot=rights[used_rights].take().expect("preallocated unique ancillary slot");used_rights+=1;
                match slot.retain(unsafe{File::from_raw_fd(fd)}) {
                    Ok(file)=>{if finish_original_close(file).is_err(){close_unknown=true;}},
                    Err(_retained)=>close_unknown=true,
                }
            }}}
        cmsg=unsafe{libc::CMSG_NXTHDR(&message,cmsg)};
    }
    if close_unknown||refused||valid!=Some(peer){return Err(io::Error::other("counter exact current sender ancillary credentials refused"));}
    Ok(bytes as usize)
}
fn read_exact(socket:&UnixStream,stop:&CounterStop,peer:&KernelPeer,data:&mut[u8])->Result<()> {
    let mut offset=0;while offset<data.len(){wait(socket,stop,libc::POLLIN)?;peer.recheck(socket)?;
        let n=match recv(socket.as_raw_fd(),&mut data[offset..],peer.credential){Ok(n)=>n,
            Err(e)if e.kind()==io::ErrorKind::WouldBlock=>continue,Err(_)=>return Err("counter authenticated receive refused".into())};
        if n==0{return Err("counter disconnected with unknown operation outcome".into());}offset+=n;peer.recheck(socket)?;
    }Ok(())
}
fn write_exact(socket:&UnixStream,stop:&CounterStop,peer:&KernelPeer,data:&[u8])->Result<()> {
    let mut offset=0;while offset<data.len(){wait(socket,stop,libc::POLLOUT)?;peer.recheck(socket)?;
        let n=unsafe{libc::send(socket.as_raw_fd(),data[offset..].as_ptr().cast(),data.len()-offset,
            libc::MSG_DONTWAIT|libc::MSG_NOSIGNAL)};
        if n<0 {if io::Error::last_os_error().kind()==io::ErrorKind::WouldBlock{continue;}
            return Err("counter authenticated send unknown".into());}
        if n==0{return Err("counter zero send unknown".into());}offset+=n as usize;peer.recheck(socket)?;
    }Ok(())
}
struct ConnectionState {socket:UnixStream,peer:KernelPeer,endpoint:HeldEndpoint,
    authority:InstalledCounterAuthority,chain:CanonicalStore,stop:Arc<CounterStop>,frozen:bool,
    socket_original:[u8;24],socket_close:RetainedCloseReport,closed:Box<NativeClosed>}
struct ConnectionPreparation {
    result:Box<std::mem::MaybeUninit<ConnectionState>>,
    socket:Option<std::mem::ManuallyDrop<UnixStream>>,
    peer:Option<std::mem::ManuallyDrop<KernelPeer>>,
    endpoint:Option<std::mem::ManuallyDrop<HeldEndpoint>>,
    authority:std::mem::ManuallyDrop<InstalledCounterAuthority>,
    chain:std::mem::ManuallyDrop<CanonicalStore>,stop:std::mem::ManuallyDrop<Arc<CounterStop>>,
    socket_original:Option<[u8;24]>,socket_close:RetainedCloseReport,closed:Box<NativeClosed>,
}
/// The complete native holder is preallocated. Abandonment leaves it quarantined
/// rather than dropping a socket after a possibly irreversible counter action.
pub(crate) struct InstalledCounterConnection {state:std::mem::ManuallyDrop<Box<ConnectionState>>}
impl InstalledCounterConnection {
    pub(crate) fn connect(authority:InstalledCounterAuthority,chain:CanonicalStore,stop:Arc<CounterStop>)->Result<Self>{
        Self::connect_route(authority,chain,stop,InstalledRoute::Counter)
    }
    fn connect_route(authority:InstalledCounterAuthority,chain:CanonicalStore,stop:Arc<CounterStop>,route:InstalledRoute)->Result<Self>{
        // Root all incoming owners before allocation; allocate the completed
        // holder BEFORE current/path/native connect work. Error/unwind retains
        // the complete preparation instead of implicitly dropping its socket.
        let authority=std::mem::ManuallyDrop::new(authority);
        let chain=std::mem::ManuallyDrop::new(chain);let stop=std::mem::ManuallyDrop::new(stop);
        let result=Box::new(std::mem::MaybeUninit::uninit());let socket_close=RetainedCloseReport::prepare(1)?;
        let closed=NativeClosed::prepare(authority.context());
        let mut preparation=std::mem::ManuallyDrop::new(Box::new(ConnectionPreparation{
            result,socket:None,peer:None,endpoint:None,authority,chain,stop,socket_original:None,socket_close,closed,
        }));
        let p=&mut **preparation;
        p.authority.recheck(&p.chain)?;
        let path=match route{InstalledRoute::Counter=>p.authority.endpoint(),InstalledRoute::Unlock=>{
            if p.authority.is_provider(){return Err("unlock input requires installed consumer role".into());}
            p.authority.unlock_endpoint()}};
        p.endpoint=Some(std::mem::ManuallyDrop::new(HeldEndpoint::capture_at(&p.authority,path.clone())?));
        let mut addr:libc::sockaddr_un=unsafe{zeroed()};addr.sun_family=libc::AF_UNIX as libc::sa_family_t;
        let bytes=path.as_os_str().as_bytes();
        if bytes.len()>=addr.sun_path.len(){return Err("counter fixed endpoint native length".into());}
        for(at,v)in bytes.iter().enumerate(){addr.sun_path[at]=*v as libc::c_char;}
        let raw=unsafe{libc::socket(libc::AF_UNIX,libc::SOCK_STREAM|libc::SOCK_NONBLOCK|libc::SOCK_CLOEXEC,0)};
        if raw<0{return Err("counter native socket unavailable".into());}
        p.socket=Some(std::mem::ManuallyDrop::new(unsafe{UnixStream::from_raw_fd(raw)}));
        let socket=p.socket.as_ref().expect("published original socket");
        p.socket_original=Some(original_socket_identity(socket)?);
        let one=1i32;if unsafe{libc::setsockopt(raw,libc::SOL_SOCKET,libc::SO_PASSCRED,
            (&one as*const i32).cast(),size_of::<i32>()as libc::socklen_t)}!=0{return Err("counter native per-chunk credentials unavailable".into());}
        let connected=unsafe{libc::connect(raw,(&addr as*const libc::sockaddr_un).cast(),size_of::<libc::sockaddr_un>()as libc::socklen_t)};
        if connected!=0 {let error=io::Error::last_os_error();
            // AF_UNIX EAGAIN means an unaccepted connection (full listen queue),
            // not an in-progress socket that SO_ERROR=0 may falsely settle.
            if error.raw_os_error()!=Some(libc::EINPROGRESS){return Err("counter existing endpoint connect refused".into());}
            wait(socket,&p.stop,libc::POLLOUT)?;let mut result=0i32;let mut length=size_of::<i32>()as libc::socklen_t;
            if unsafe{libc::getsockopt(raw,libc::SOL_SOCKET,libc::SO_ERROR,(&mut result as*mut i32).cast(),&mut length)}!=0
                ||result!=0||length as usize!=size_of::<i32>(){return Err("counter connect kernel settlement refused".into());}}
        p.peer=Some(std::mem::ManuallyDrop::new(KernelPeer::capture(socket,p.authority.peer_principals())?));
        p.endpoint.as_ref().expect("published endpoint").recheck(&p.authority)?;p.authority.recheck(&p.chain)?;
        let ConnectionPreparation{mut result,socket,peer,endpoint,authority,chain,stop,socket_original,socket_close,closed}
            =*unsafe{std::mem::ManuallyDrop::take(&mut preparation)};
        result.write(ConnectionState{
            socket:std::mem::ManuallyDrop::into_inner(socket.expect("published original socket")),
            peer:std::mem::ManuallyDrop::into_inner(peer.expect("published original peer")),
            endpoint:std::mem::ManuallyDrop::into_inner(endpoint.expect("published original endpoint")),
            authority:std::mem::ManuallyDrop::into_inner(authority),chain:std::mem::ManuallyDrop::into_inner(chain),
            stop:std::mem::ManuallyDrop::into_inner(stop),frozen:false,
            socket_original:socket_original.expect("published original socket identity"),socket_close,closed,
        });
        Ok(Self{state:std::mem::ManuallyDrop::new(unsafe{result.assume_init()})})
    }
    /// Only after the original owning worker has settled its last exchange.
    /// All independent native close attempts are made; unknown closes refuse.
    pub(crate) fn close(mut self)->std::result::Result<std::mem::ManuallyDrop<CanonicalStore>,CounterConnectionClose> {
        let s=&mut **self.state;
        if s.frozen||original_socket_identity(&s.socket).ok()!=Some(s.socket_original)
            ||s.peer.recheck(&s.socket).is_err()||s.authority.recheck(&s.chain).is_err()
            ||s.endpoint.recheck(&s.authority).is_err(){return Err(CounterConnectionClose::Retained(std::mem::ManuallyDrop::new(self)));}
        let ConnectionState{socket,peer,endpoint,authority,chain,stop,socket_original,socket_close,closed,..}
            =*unsafe{MD::take(&mut self.state)};
        let mut closed=MD::new(closed);closed.chain=Some(MD::new(chain));closed.stop=Some(MD::new(stop));
        closed.endpoint=Some(endpoint.close());closed.pidfd=Some(close_original(peer.pidfd));
        let mut socket_close=socket_close;let original:std::os::fd::OwnedFd=socket.into();
        socket_close.file(File::from(original),socket_original);closed.socket=Some(socket_close);
        if let Err(original)=authority.recheck_and_close(closed.chain.as_ref().unwrap()){closed.authority=Some(original);}
        if !closed.known(){return Err(CounterConnectionClose::Unknown{originals:closed});}
        let chain=closed.chain.take().unwrap();if let Some(mut stop)=closed.stop.take(){unsafe{MD::drop(&mut stop)}};
        unsafe{MD::drop(&mut closed)};Ok(chain)
    }
}
pub(crate) enum CounterConnectionClose{Retained(MD<InstalledCounterConnection>),Unknown{originals:MD<Box<NativeClosed>>}}
pub(crate) struct NativeClosed{context:[u8;32],endpoint:Option<EndpointClose>,pidfd:Option<OriginalClose>,
    socket:Option<RetainedCloseReport>,authority:Option<crate::hybrid_installed_counter_v2::CounterAuthorityCloseRefusal>,
    chain:Option<MD<CanonicalStore>>,lease:Option<MD<ProviderLease>>,stop:Option<MD<Arc<CounterStop>>>}
impl NativeClosed{
    fn prepare(context:[u8;32])->Box<Self>{Box::new(Self{context,endpoint:None,pidfd:None,socket:None,authority:None,chain:None,lease:None,stop:None})}
    fn known(&self)->bool{self.endpoint.as_ref().is_some_and(|v|v.known())&&self.pidfd.as_ref().is_some_and(OriginalClose::known)
        &&self.socket.as_ref().is_some_and(RetainedCloseReport::retained_handles_closed)&&self.authority.is_none()}
}
#[derive(Clone,Copy)]
enum InstalledRoute{Counter,Unlock}
/// Exact installed unlock route over the SAME reviewed kernel/principal and
/// original-socket custody mechanics. This separate type cannot implement NV
/// requests or authorize raw caller ciphertexts/paths/principals.
pub(crate) struct InstalledUnlockInput{connection:std::mem::ManuallyDrop<InstalledCounterConnection>,used:bool,received:usize}
impl InstalledUnlockInput{
    pub(crate) fn connect(authority:InstalledCounterAuthority,chain:CanonicalStore,stop:Arc<CounterStop>)->Result<Self>{
        let connection=InstalledCounterConnection::connect_route(authority,chain,stop,InstalledRoute::Unlock)?;
        Ok(Self{connection:std::mem::ManuallyDrop::new(connection),used:false,received:0})
    }
    pub(crate) fn read_selected(&mut self,node_ciphertext:[u8;32],continuity_ciphertext:[u8;32])
        ->Result<crate::hybrid_owned_unlock_input_v2::OwnedPasswords>{
        if self.used{return Err("installed unlock input already consumed".into());}
        self.used=true;
        let s=&mut **self.connection.state;
        if s.frozen{return Err("installed unlock input frozen".into());}s.frozen=true;
        let result=(||{
            check_unlock(s)?;
            // Both commitments must equal the independently held installation
            // selection, not merely nonzero caller bytes.
            if s.authority.role_ciphertext_pins()!=(node_ciphertext,continuity_ciphertext){
                return Err("installed unlock exact selected ciphertexts differ".into());}
            let request=crate::hybrid_unlock_request_v2::UnlockRequest::new(s.authority.context(),node_ciphertext,continuity_ciphertext)?;
            write_exact(&s.socket,&s.stop,&s.peer,&request.encode())?;
            let passwords=crate::hybrid_owned_unlock_input_v2::OwnedPasswords::read_existing(
                &mut UnlockReader{state:s,received:&mut self.received},&request.binding())?;
            check_unlock(s)?;
            write_exact(&s.socket,&s.stop,&s.peer,&request.acknowledgment())?;
            check_unlock(s)?;Ok(passwords)
        })();
        if result.is_ok(){s.frozen=false;}result
    }
    /// Original worker must have settled the one-shot exchange. Native close
    /// uncertainty remains the SAME original typed CounterConnectionClose.
    pub(crate) fn close(self)->std::result::Result<std::mem::ManuallyDrop<CanonicalStore>,CounterConnectionClose>{
        std::mem::ManuallyDrop::into_inner(self.connection).close()
    }
}
fn check_unlock(s:&mut ConnectionState)->Result<()>{
    if original_socket_identity(&s.socket)?!=s.socket_original{return Err("unlock original socket changed".into());}
    s.authority.recheck(&s.chain)?;s.endpoint.recheck(&s.authority)?;s.peer.recheck(&s.socket)
}
struct UnlockReader<'a>{state:&'a mut ConnectionState,received:&'a mut usize}
impl io::Read for UnlockReader<'_>{
    fn read(&mut self,data:&mut[u8])->io::Result<usize>{
        if data.is_empty(){return Ok(0);}
        let s=&mut *self.state;
        let result=(||->Result<usize>{
            check_unlock(s)?;
            loop{
                wait(&s.socket,&s.stop,libc::POLLIN)?;check_unlock(s)?;
                let mut probe=zeroize::Zeroizing::new([0u8;1]);
                let peek=unsafe{libc::recv(s.socket.as_raw_fd(),probe.as_mut_ptr().cast(),1,libc::MSG_PEEK|libc::MSG_DONTWAIT)};
                if peek==0{check_unlock(s)?;return Ok(0);}
                if peek<0{if io::Error::last_os_error().kind()==io::ErrorKind::WouldBlock{continue;}
                    return Err("unlock original EOF observation unknown".into());}
                let used=match recv(s.socket.as_raw_fd(),data,s.peer.credential){Ok(n)=>n,
                    Err(e)if e.kind()==io::ErrorKind::WouldBlock=>continue,
                    Err(_)=>return Err("unlock per-chunk native credentials refused".into())};
                if used==0{return Err("unlock contradictory EOF".into());}
                *self.received=self.received.checked_add(used).ok_or("unlock total length overflow")?;
                if *self.received>52+2*4096{return Err("unlock complete frame bound".into());}
                check_unlock(s)?;return Ok(used);
            }
        })();
        result.map_err(|_|io::Error::other("owned installed unlock input unavailable"))
    }
}
impl NvExchange for InstalledCounterConnection {
    fn exchange(&mut self,request:&Request,response:&mut[u8;RESPONSE])->Result<usize>{
        let s=&mut **self.state;
        if s.frozen{return Err("counter native connection frozen".into());}s.frozen=true;
        let result=(||{if original_socket_identity(&s.socket)?!=s.socket_original{return Err("counter original socket changed".into());}
            s.authority.recheck(&s.chain)?;s.endpoint.recheck(&s.authority)?;
            s.peer.recheck(&s.socket)?;if request.context()!=s.authority.context(){return Err("counter own installed request context differs".into());}
            write_exact(&s.socket,&s.stop,&s.peer,&request.encode_native())?;
            let mut frame=[0u8;RESPONSE+2];read_exact(&s.socket,&s.stop,&s.peer,&mut frame)?;
            let used=u16::from_be_bytes([frame[0],frame[1]])as usize;
            if !(6..=RESPONSE).contains(&used)||frame[2+used..].iter().any(|v|*v!=0){return Err("counter response native framing refused".into());}
            s.peer.recheck(&s.socket)?;s.endpoint.recheck(&s.authority)?;s.authority.recheck(&s.chain)?;
            response[..used].copy_from_slice(&frame[2..2+used]);Ok(used)})();
        if result.is_ok(){s.frozen=false;}result
    }
}
/// Existing, administrator-prepared exclusive provider lock. This protects the
/// selected software provider lifetime; it is not a TPM deletion-policy proof.
struct LeaseState {
    file:Option<std::mem::ManuallyDrop<File>>,path:PathBuf,
    ancestors:Vec<std::mem::ManuallyDrop<File>>,ancestor_ids:Vec<Option<Identity>>,
    initial:Option<Identity>,expected:[u8;32],locked:bool,
    ancestor_close:Option<RetainedCloseReport>,lease_close:Option<RetainedCloseReport>,maximum_ancestors:usize,
}
struct ProviderLease {state:std::mem::ManuallyDrop<Box<LeaseState>>}
enum ProviderLeaseClose {
    Retained(std::mem::ManuallyDrop<ProviderLease>),
    AncestorUnknown{lease:std::mem::ManuallyDrop<ProviderLease>,close:RetainedCloseReport},
    LeaseUnknown{lease:std::mem::ManuallyDrop<ProviderLease>,close:RetainedCloseReport},
}
fn close_pin(id:Identity)->[u8;24] {
    let mut raw=[0;24];raw[..8].copy_from_slice(&id.dev.to_le_bytes());
    raw[8..16].copy_from_slice(&id.ino.to_le_bytes());raw[16..].copy_from_slice(&id.links.to_le_bytes());raw
}
impl ProviderLease {
    fn capture(authority:&InstalledCounterAuthority)->Result<Self>{
        use std::io::Read;
        if !authority.is_provider(){return Err("counter provider role required".into());}
        let path=authority.existing_lease_path();let(owner,_)=authority.socket_owner_group();
        let names=path.components().map(|v|match v{std::path::Component::RootDir=>Ok(None),
            std::path::Component::Normal(v)=>Ok(Some(v.to_owned())),_=>Err("counter lease fixed path grammar")})
            .collect::<std::result::Result<Vec<_>,_>>()?.into_iter().flatten().collect::<Vec<_>>();
        let open_dir=|parent:i32,name:&std::ffi::OsStr|->Result<File>{
            let name=std::ffi::CString::new(name.as_bytes()).map_err(|_|"counter lease directory NUL")?;
            let fd=unsafe{libc::openat(parent,name.as_ptr(),libc::O_PATH|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
            if fd<0{return Err("counter existing protected lease ancestor unavailable".into());}Ok(unsafe{File::from_raw_fd(fd)})};
        if names.len()<2{return Err("counter fixed lease path incomplete".into());}
        let maximum_ancestors=names.len();
        let ancestor_close=RetainedCloseReport::prepare(maximum_ancestors)?;
        let lease_close=RetainedCloseReport::prepare(1)?;
        let mut ancestors=Vec::new();ancestors.try_reserve_exact(maximum_ancestors).map_err(|_|"counter lease custody capacity")?;
        let mut ancestor_ids=Vec::new();ancestor_ids.try_reserve_exact(maximum_ancestors).map_err(|_|"counter lease identity capacity")?;
        let mut value=Self{state:std::mem::ManuallyDrop::new(Box::new(LeaseState{
            file:None,path,ancestors,ancestor_ids,initial:None,expected:authority.nv_public_sha256(),locked:false,
            ancestor_close:Some(ancestor_close),lease_close:Some(lease_close),maximum_ancestors}))};
        value.retain_ancestor(open_dir(libc::AT_FDCWD,std::ffi::OsStr::new("/"))?,owner)?;
        for name in &names[..names.len()-1]{
            let file=open_dir(value.state.ancestors.last().ok_or("counter lease root")?.as_raw_fd(),name)?;
            value.retain_ancestor(file,owner)?;
        }
        let name=std::ffi::CString::new(names.last().ok_or("counter lease name")?.as_bytes()).map_err(|_|"counter lease path NUL")?;
        let fd=unsafe{libc::openat(value.state.ancestors.last().ok_or("counter lease parent")?.as_raw_fd(),name.as_ptr(),
            libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
        if fd<0{return Err("counter existing provider lease unavailable".into());}
        value.state.file=Some(std::mem::ManuallyDrop::new(unsafe{File::from_raw_fd(fd)}));
        let initial=identity(value.file())?;value.state.initial=Some(initial);
        let file=value.file();
        let m=file.metadata().map_err(|_|"counter provider lease metadata")?;
        if !m.is_file()||m.uid()!=owner||m.nlink()!=1||m.mode()&0o7777!=0o600||m.len()!=32 {
            return Err("counter provider lease ownership/type/exact size refused".into());}
        let mut raw=[0;32];let mut reader=file;
        reader.read_exact(&mut raw).map_err(|_|"counter provider lease exact identity")?;
        if raw!=value.state.expected||unsafe{libc::flock(fd,libc::LOCK_EX|libc::LOCK_NB)}!=0 {
            return Err("counter exclusive existing provider lease refused".into());}
        value.state.locked=true;Ok(value)
    }
    fn file(&self)->&File{self.state.file.as_ref().expect("original provider lease file")}
    fn retain_ancestor(&mut self,file:File,owner:u32)->Result<()> {
        assert!(self.state.ancestors.len()<self.state.maximum_ancestors);
        self.state.ancestors.push(std::mem::ManuallyDrop::new(file));self.state.ancestor_ids.push(None);
        let file=self.state.ancestors.last().ok_or("counter lease ancestor publication")?;
        let initial=identity(file)?;
        *self.state.ancestor_ids.last_mut().ok_or("counter lease ancestor identity publication")?=Some(initial);
        let file=self.state.ancestors.last().ok_or("counter lease ancestor publication")?;
        let m=file.metadata().map_err(|_|"counter lease ancestor metadata")?;
        if !m.is_dir()||(m.uid()!=0&&m.uid()!=owner)||m.mode()&0o022!=0 {
            return Err("counter lease ancestor modification refused".into());}Ok(())
    }
    fn recheck(&self)->Result<()> {
        use std::os::unix::fs::MetadataExt;
        let s=&**self.state;
        let initial=s.initial.ok_or("counter lease original identity unavailable")?;
        if !s.locked || s.file.is_none() || s.ancestors.len()!=s.maximum_ancestors || s.ancestor_ids.iter().any(Option::is_none)
            ||identity(self.file())?!=initial||s.ancestors.iter().map(|file|identity(file).map(Some)).collect::<Result<Vec<_>>>()?!=s.ancestor_ids {
            return Err("counter held provider lease changed".into());}
        let named=std::fs::symlink_metadata(&s.path).map_err(|_|"counter provider lease name unavailable")?;
        if !named.is_file()||named.dev()!=initial.dev||named.ino()!=initial.ino
            ||named.mode()!=initial.mode||named.uid()!=initial.uid||named.gid()!=initial.gid
            ||named.nlink()!=1||named.len()!=32{return Err("counter provider lease named identity changed".into());}
        let mut raw=[0;32];let n=unsafe{libc::pread(self.file().as_raw_fd(),raw.as_mut_ptr().cast(),32,0)};
        if n!=32||raw!=s.expected{return Err("counter provider lease current contents differ".into());}Ok(())
    }
    fn close(mut self)->std::result::Result<(),ProviderLeaseClose> {
        // Absolutely no native close occurs if the full current check fails.
        if self.recheck().is_err(){return Err(ProviderLeaseClose::Retained(std::mem::ManuallyDrop::new(self)));}
        let s=&mut **self.state;
        let mut close=s.ancestor_close.take().expect("preallocated ancestor receipt");
        for(file,id)in s.ancestors.drain(..).zip(s.ancestor_ids.iter()){
            close.file(std::mem::ManuallyDrop::into_inner(file),close_pin(id.expect("original ancestor identity")));
        }
        if !close.retained_handles_closed(){return Err(ProviderLeaseClose::AncestorUnknown{
            lease:std::mem::ManuallyDrop::new(self),close});}
        let s=&mut **self.state;
        let mut close=s.lease_close.take().expect("preallocated lease receipt");
        let file=std::mem::ManuallyDrop::into_inner(s.file.take().expect("original exclusive lease"));
        close.file(file,close_pin(s.initial.expect("original lease identity")));
        if !close.retained_handles_closed(){return Err(ProviderLeaseClose::LeaseUnknown{
            lease:std::mem::ManuallyDrop::new(self),close});}Ok(())
    }
}
impl Drop for ProviderLease {
    fn drop(&mut self){
        // Incomplete/error/abandoned ownership never silently releases flock.
        if self.state.file.is_none() && self.state.ancestors.is_empty(){unsafe{std::mem::ManuallyDrop::drop(&mut self.state)};}
    }
}
/// Actual fixed request→TPM producer→fixed response route on an owned provider
/// worker. No generic response callback or independently reset counter journal.
struct ProviderState {socket:UnixStream,peer:KernelPeer,endpoint:HeldEndpoint,
    authority:InstalledCounterAuthority,chain:CanonicalStore,lease:ProviderLease,
    producer:super::hybrid_native_nv_tools_v2::NativeNvTools,stop:Arc<CounterStop>,frozen:bool,
    remaining:Box<std::mem::MaybeUninit<ProviderRemaining>>,socket_original:[u8;24],socket_close:RetainedCloseReport,closed:Box<NativeClosed>}
struct ProviderPreparation {
    result:Box<std::mem::MaybeUninit<ProviderState>>,
    remaining:Box<std::mem::MaybeUninit<ProviderRemaining>>,
    socket:std::mem::ManuallyDrop<UnixStream>,
    peer:Option<std::mem::ManuallyDrop<KernelPeer>>,
    endpoint:Option<std::mem::ManuallyDrop<HeldEndpoint>>,
    lease:Option<std::mem::ManuallyDrop<ProviderLease>>,
    authority:std::mem::ManuallyDrop<InstalledCounterAuthority>,
    chain:std::mem::ManuallyDrop<CanonicalStore>,
    producer:std::mem::ManuallyDrop<super::hybrid_native_nv_tools_v2::NativeNvTools>,
    stop:std::mem::ManuallyDrop<Arc<CounterStop>>,
    socket_original:Option<[u8;24]>,socket_close:RetainedCloseReport,closed:Box<NativeClosed>,
}
pub(crate) struct InstalledCounterProvider {state:std::mem::ManuallyDrop<Box<ProviderState>>}
struct ProviderRemaining {socket:UnixStream,peer:KernelPeer,endpoint:HeldEndpoint,
    authority:InstalledCounterAuthority,chain:CanonicalStore,lease:ProviderLease,stop:Arc<CounterStop>,
    socket_original:[u8;24],socket_close:RetainedCloseReport,closed:Box<NativeClosed>}
pub(crate) enum CounterProviderClose {
    Retained(std::mem::ManuallyDrop<InstalledCounterProvider>),
    ProducerUnknown{producer:super::hybrid_native_nv_tools_v2::NativeProducerClose,
        remaining:std::mem::ManuallyDrop<Box<ProviderRemaining>>},
    NativeCloseUnknown{originals:MD<Box<NativeClosed>>},
    LeaseUnknown{lease:ProviderLeaseClose,originals:MD<Box<NativeClosed>>},
}
impl InstalledCounterProvider {
    /// The caller retains the original installed listener and owns this accepted
    /// socket. This constructor authenticates its actual peer, never a caller PID.
    pub(crate) fn from_owned_accepted(authority:InstalledCounterAuthority,chain:CanonicalStore,
        socket:std::mem::ManuallyDrop<UnixStream>,producer:super::hybrid_native_nv_tools_v2::NativeNvTools,stop:Arc<CounterStop>)->Result<Self>{
        // The accepting caller must root its already acquired original socket.
        // Incoming authority, database, producer and Stop are likewise rooted
        // before any allocation or selected input/current check below.
        let authority=std::mem::ManuallyDrop::new(authority);
        let chain=std::mem::ManuallyDrop::new(chain);
        let producer=std::mem::ManuallyDrop::new(producer);let stop=std::mem::ManuallyDrop::new(stop);
        let socket_close=RetainedCloseReport::prepare(1)?;
        let remaining=Box::new(std::mem::MaybeUninit::uninit());let closed=NativeClosed::prepare(authority.context());
        let result=Box::new(std::mem::MaybeUninit::uninit());
        let mut preparation=std::mem::ManuallyDrop::new(Box::new(ProviderPreparation{
            result,remaining,socket,peer:None,endpoint:None,lease:None,authority,chain,producer,stop,socket_original:None,socket_close,closed,
        }));
        let p=&mut **preparation;
        p.socket_original=Some(original_socket_identity(&p.socket)?);
        p.authority.recheck(&p.chain)?;
        if !p.authority.is_provider()||p.producer.selected_bindings()?!=(p.authority.context(),
            p.authority.profile_commitment(),p.authority.nv_public_sha256()) {
            return Err("counter own installed producer bindings differ".into());}
        p.lease=Some(std::mem::ManuallyDrop::new(ProviderLease::capture(&p.authority)?));
        p.endpoint=Some(std::mem::ManuallyDrop::new(HeldEndpoint::capture(&p.authority)?));
        p.socket.set_nonblocking(true).map_err(|_|"counter provider nonblocking settlement")?;
        let one=1i32;if unsafe{libc::setsockopt(p.socket.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PASSCRED,
            (&one as*const i32).cast(),size_of::<i32>()as libc::socklen_t)}!=0 {
            return Err("counter provider per-chunk credentials unavailable".into());}
        p.peer=Some(std::mem::ManuallyDrop::new(KernelPeer::capture(&p.socket,p.authority.peer_principals())?));
        p.authority.recheck(&p.chain)?;p.lease.as_ref().expect("published lease").recheck()?;
        p.endpoint.as_ref().expect("published endpoint").recheck(&p.authority)?;
        let ProviderPreparation{mut result,remaining,socket,peer,endpoint,lease,authority,chain,producer,stop,socket_original,socket_close,closed}
            =*unsafe{std::mem::ManuallyDrop::take(&mut preparation)};
        result.write(ProviderState{
            socket:std::mem::ManuallyDrop::into_inner(socket),
            peer:std::mem::ManuallyDrop::into_inner(peer.expect("published original peer")),
            endpoint:std::mem::ManuallyDrop::into_inner(endpoint.expect("published original endpoint")),
            lease:std::mem::ManuallyDrop::into_inner(lease.expect("published original lease")),
            authority:std::mem::ManuallyDrop::into_inner(authority),chain:std::mem::ManuallyDrop::into_inner(chain),
            producer:std::mem::ManuallyDrop::into_inner(producer),stop:std::mem::ManuallyDrop::into_inner(stop),
            frozen:false,remaining,socket_original:socket_original.expect("published accepted original socket identity"),socket_close,closed,
        });
        Ok(Self{state:std::mem::ManuallyDrop::new(unsafe{result.assume_init()})})
    }
    pub(crate) fn serve_one(&mut self)->Result<()> {
        let s=&mut **self.state;
        if s.frozen{return Err("counter native provider frozen".into());}s.frozen=true;
        let result=(||{if original_socket_identity(&s.socket)?!=s.socket_original{return Err("counter accepted original socket changed".into());}
            s.authority.recheck(&s.chain)?;s.endpoint.recheck(&s.authority)?;
            s.peer.recheck(&s.socket)?;s.lease.recheck()?;
            let mut frame=[0;98];read_exact(&s.socket,&s.stop,&s.peer,&mut frame)?;
            let request=Request::decode_native(&frame,s.authority.context())?;
            s.authority.recheck(&s.chain)?;s.lease.recheck()?;
            let mut response=[0;RESPONSE];let used=s.producer.exchange(&request,&mut response)?;
            if !(6..=RESPONSE).contains(&used){return Err("counter actual producer result length refused".into());}
            s.authority.recheck(&s.chain)?;s.lease.recheck()?;s.peer.recheck(&s.socket)?;
            let mut output=[0;RESPONSE+2];output[..2].copy_from_slice(&(used as u16).to_be_bytes());
            output[2..2+used].copy_from_slice(&response[..used]);write_exact(&s.socket,&s.stop,&s.peer,&output)?;
            s.authority.recheck(&s.chain)?;s.lease.recheck()?;s.peer.recheck(&s.socket)?;Ok(())})();
        if result.is_ok(){s.frozen=false;}result
    }
    pub(crate) fn close_after_join(mut self)->std::result::Result<std::mem::ManuallyDrop<CanonicalStore>,CounterProviderClose>{
        let s=&mut **self.state;
        if s.frozen||original_socket_identity(&s.socket).ok()!=Some(s.socket_original)
            ||s.authority.recheck(&s.chain).is_err()||s.lease.recheck().is_err()
            ||s.endpoint.recheck(&s.authority).is_err()||s.peer.recheck(&s.socket).is_err(){
            return Err(CounterProviderClose::Retained(std::mem::ManuallyDrop::new(self)));}
        let ProviderState{socket,peer,endpoint,authority,chain,lease,producer,stop,mut remaining,socket_original,socket_close,closed,..}
            =*unsafe{std::mem::ManuallyDrop::take(&mut self.state)};
        remaining.write(ProviderRemaining{socket,peer,endpoint,authority,chain,lease,stop,socket_original,socket_close,closed});
        let mut rest=std::mem::ManuallyDrop::new(unsafe{remaining.assume_init()});
        if let Err(producer)=producer.close_retained(){
            return Err(CounterProviderClose::ProducerUnknown{producer,remaining:rest});}
        let ProviderRemaining{socket,peer,endpoint,authority,chain,lease,stop,socket_original,socket_close,closed}
            =*unsafe{MD::take(&mut rest)};
        let mut closed=MD::new(closed);closed.chain=Some(MD::new(chain));closed.lease=Some(MD::new(lease));closed.stop=Some(MD::new(stop));
        closed.endpoint=Some(endpoint.close());closed.pidfd=Some(close_original(peer.pidfd));
        let mut socket_close=socket_close;let original:std::os::fd::OwnedFd=socket.into();
        socket_close.file(File::from(original),socket_original);closed.socket=Some(socket_close);
        if let Err(original)=authority.recheck_and_close(closed.chain.as_ref().unwrap()){closed.authority=Some(original);}
        if !closed.known(){return Err(CounterProviderClose::NativeCloseUnknown{originals:closed});}
        // Exact exclusive lease remains held through every independent original
        // observation and is attempted LAST only after all are known successful.
        if let Err(lease)=MD::into_inner(closed.lease.take().unwrap()).close(){return Err(CounterProviderClose::LeaseUnknown{lease,originals:closed});}
        let chain=closed.chain.take().unwrap();if let Some(mut stop)=closed.stop.take(){unsafe{MD::drop(&mut stop)}};
        unsafe{MD::drop(&mut closed)};Ok(chain)
    }
}
