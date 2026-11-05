//! Native per-message UNIX credentials beneath the protected clock owner.
//! No production placement issuer, endpoint installer or qualified reply proxy.
//! SO_PEERCRED is connection-time only: every received byte chunk also requires
//! current kernel SCM_CREDENTIALS and exact current process/start/namespace pins.
//! Missing current facts refuse. No raw calibration/Commit is a channel opcode.
#![allow(dead_code)]
use sha2::{Digest,Sha256};
use std::{fs::File,io::{self,Read},mem::{size_of,zeroed},
    os::{fd::{AsRawFd,FromRawFd},unix::fs::{MetadataExt,OpenOptionsExt}},
    path::PathBuf};
use tokio::{io::Interest,net::UnixStream};

/// New NORMAL route, separate from the inherited TEST /proc observer below.
/// The kernel pins peer process identity; it does not attest peer image bytes.
/// Each side's genuine fixed-installed issuer checks its OWN current code.
pub(super) enum ChannelRole {Owner,Consumer}
pub(super) struct InstalledChannelAuthority {
    guard:super::native_nts_deployment_record::NativeSelectionGuard,
    placement:super::native_nts_installation::OwnerPlacementDocument,
    role:ChannelRole,local:Cred,remote_uid:u32,remote_gid:u32,context:[u8;32],
    record:super::native_nts_deployment_record::ValidatedRecord,
    scope:super::protected_clock_lineage_v1::Scope,binding:super::protected_clock_lineage_v1::Binding,
}
impl InstalledChannelAuthority {
    pub(super) fn from_selected(record:super::native_nts_deployment_record::ValidatedRecord,
        mut guard:super::native_nts_deployment_record::NativeSelectionGuard,
        placement:super::native_nts_installation::OwnerPlacementDocument,role:ChannelRole)->Result<Self> {
        guard.recheck()?;
        let (owner,node,owner_gid,node_gid)=placement.channel_principals();
        let (uid,gid,remote_uid,remote_gid)=match role {
            ChannelRole::Owner=>(owner,owner_gid,node,node_gid),
            ChannelRole::Consumer=>(node,node_gid,owner,owner_gid),
        };
        if unsafe{libc::getuid()}!=uid || unsafe{libc::geteuid()}!=uid
            || unsafe{libc::getgid()}!=gid || unsafe{libc::getegid()}!=gid {
            return Err("channel dedicated installed principal differs".into());
        }
        let local=Cred{pid:unsafe{libc::getpid()},uid,gid};
        status(&PathBuf::from("/proc/self"),local)?;
        let value=super::native_nts_deployment_record::canonical_value(record.record().canonical())
            .map_err(|_|"channel selected context encoding")?;
        let digest=|name:&str|->Result<[u8;32]> {let text=value["binding"][name].as_str().ok_or("channel digest type")?;
            let mut out=[0;32];hex::decode_to_slice(text,&mut out).map_err(|_|"channel digest encoding")?;Ok(out)};
        let scope=super::protected_clock_lineage_v1::Scope::selected_document(digest("genesis_sha256")?,
            digest("network_sha256")?,digest("rule_sha256")?,placement.lineage());
        let mut context=Sha256::new();context.update(b"MCLC4-CHANNEL-CONTEXT-1");
        context.update(scope.journal_context());context.update(Sha256::digest(record.record().canonical()));
        let context_digest=|name:&str|->Result<[u8;32]> {let text=value["context"][name].as_str().ok_or("channel context digest type")?;
            let mut out=[0;32];hex::decode_to_slice(text,&mut out).map_err(|_|"channel context digest encoding")?;Ok(out)};
        let mut code=Sha256::new();code.update(b"MCLC4-CODE-CONFIG-1");
        code.update(context_digest("code_sha256")?);code.update(context_digest("config_sha256")?);
        let binding=super::protected_clock_lineage_v1::Binding::selected_document(
            Sha256::digest(record.record().canonical()).into(),context_digest("qualification_sha256")?,
            code.finalize().into(),Sha256::digest(serde_json::to_vec(&value["acquisition"])
                .map_err(|_|"channel acquisition context encoding")?).into(),record.record().profile().id());
        guard.recheck()?;
        Ok(Self{guard,placement,role,local,remote_uid,remote_gid,context:context.finalize().into(),record,scope,binding})
    }
    fn recheck(&mut self)->Result<()> {
        self.guard.recheck()?;
        if unsafe{libc::getpid()}!=self.local.pid || unsafe{libc::getuid()}!=self.local.uid
            || unsafe{libc::geteuid()}!=self.local.uid || unsafe{libc::getgid()}!=self.local.gid
            || unsafe{libc::getegid()}!=self.local.gid {return Err("channel local principal changed".into());}
        status(&PathBuf::from("/proc/self"),self.local)?;
        self.guard.recheck()
    }
}

struct KernelPeer {credential:Cred,pidfd:File,original_pidfd:[u8;24],boot:Vec<u8>}
fn retained_socket_identity(fd:i32)->Result<[u8;24]> {
    // Borrow only this private LIVE socket's original descriptor. MD prevents
    // this temporary representation from acquiring a second close obligation.
    let borrowed=std::mem::ManuallyDrop::new(unsafe{File::from_raw_fd(fd)});
    super::native_retained_close::retained_identity(&borrowed).map_err(|e|format!("original socket identity: {e}"))
}
pub(super) struct UnixRetainedClose {
    native:super::native_retained_close::RetainedCloseReport,
    selection:std::result::Result<super::native_nts_deployment_record::SelectionRetainedClose,
        std::mem::ManuallyDrop<super::native_nts_deployment_record::NativeSelectionGuard>>,
}
impl UnixRetainedClose {pub(super) fn retained_handles_closed(&self)->bool {
    self.native.retained_handles_closed()&&self.selection.as_ref().is_ok_and(|r|r.retained_handles_closed())
}}
fn close_selected(native:super::native_retained_close::RetainedCloseReport,
    guard:super::native_nts_deployment_record::NativeSelectionGuard)->UnixRetainedClose {
    let selection=if native.retained_handles_closed(){guard.close_retained()}
        else{Err(std::mem::ManuallyDrop::new(guard))};UnixRetainedClose{native,selection}
}
fn connection_credential(socket:&impl AsRawFd)->Result<Cred> {
    let mut value:libc::ucred=unsafe{zeroed()};let mut length=size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe{libc::getsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,
        (&mut value as *mut libc::ucred).cast(),&mut length)}!=0 || length as usize!=size_of::<libc::ucred>() {
        return Err("kernel peer credential unavailable".into());
    }
    Ok(Cred::from(value))
}
fn local_boot()->Result<Vec<u8>> {
    let raw=bounded(&mut public_file(std::path::Path::new("/proc/sys/kernel/random/boot_id"))?,128)?;
    let text=std::str::from_utf8(&raw).map_err(|_|"channel boot encoding")?.trim();
    if text.len()!=36 || !text.bytes().enumerate().all(|(at,v)|
        if [8,13,18,23].contains(&at){v==b'-'}else{v.is_ascii_hexdigit()}) {
        return Err("channel boot identity unavailable".into());
    }
    Ok(raw)
}
impl KernelPeer {
    fn capture(socket:&impl AsRawFd,authority:&mut InstalledChannelAuthority)->Result<Self> {
        authority.recheck()?;
        let before=connection_credential(socket)?;
        if before.pid<=0 || before.uid!=authority.remote_uid || before.gid!=authority.remote_gid {
            return Err("kernel peer is not the installed ordinary principal".into());
        }
        let mut fd:i32=-1;let mut length=size_of::<i32>() as libc::socklen_t;
        // Linux x86_64 UAPI SO_PEERPIDFD=77 (Linux6.8): returns an installed
        // CLOEXEC pidfd for the socket's exact sk_peer_pid object, not a fresh
        // pidfd_open against a potentially recycled numeric PID. Unsupported
        // kernels refuse; no numeric-PID/proc/capability fallback is offered.
        if unsafe{libc::getsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,77,
            (&mut fd as *mut i32).cast(),&mut length)}!=0 {return Err(io::Error::last_os_error().to_string());}
        if fd<0 {return Err("kernel peer pidfd unavailable".into());}
        let pidfd=unsafe{File::from_raw_fd(fd)};
        let flags=unsafe{libc::fcntl(fd,libc::F_GETFD)};
        if length as usize!=size_of::<i32>() || flags<0 || flags&libc::FD_CLOEXEC==0 {
            return Err("kernel peer pidfd flags/length refused".into());
        }
        let original_pidfd=super::native_retained_close::retained_identity(&pidfd).map_err(|e|format!("original peer pidfd identity: {e}"))?;
        let peer=Self{credential:before,pidfd,original_pidfd,boot:local_boot()?};
        if connection_credential(socket)?!=before {return Err("kernel peer credential changed".into());}
        peer.recheck(socket)?;authority.recheck()?;Ok(peer)
    }
    fn recheck(&self,socket:&impl AsRawFd)->Result<()> {
        let mut poll=libc::pollfd{fd:self.pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
        if unsafe{libc::poll(&mut poll,1,0)}!=0 || poll.revents!=0
            || connection_credential(socket)?!=self.credential || local_boot()?!=self.boot {
            return Err("kernel peer liveness/boot/credential changed".into());
        }
        Ok(())
    }
}

/// Existing endpoint provenance, held without requesting socket data access.
/// Ordinary Node cannot replace the owner-controlled directory or socket.
/// Capturing this never creates/chmods/chowns/unlinks an endpoint.
/// Unforgeable outside this module; contains BOTH original and specifically
/// verified post-unlink observations, never a generic relaxed nlink flag.
pub(super) struct UnlinkedSocketClose {original:[u8;24],expected:[u8;24]}
impl UnlinkedSocketClose {pub(super) fn identities(self)->([u8;24],[u8;24]){(self.original,self.expected)}}
struct HeldEndpoint {path:PathBuf,owner:u32,group:u32,dirs:Vec<File>,file:File,ids:Vec<FileIdentity>,close_pins:Vec<[u8;24]>,names:Vec<std::ffi::CString>}
impl HeldEndpoint {
    fn capture(authority:&InstalledChannelAuthority)->Result<Self> {
        use std::os::unix::fs::FileTypeExt;
        let path=authority.placement.endpoint().to_path_buf();
        let (owner,_,_,_)=authority.placement.channel_principals();let group=authority.placement.channel_group();
        let names=path.components().map(|value|match value {
            std::path::Component::RootDir=>Ok(None),std::path::Component::Normal(name)=>Ok(Some(name.to_owned())),
            _=>Err("installed endpoint path grammar")}).collect::<std::result::Result<Vec<_>,_>>()?
            .into_iter().flatten().collect::<Vec<_>>();
        if !path.is_absolute() || names.len()<2 {return Err("installed endpoint path refused".into());}
        let open=|fd:i32,name:&std::ffi::OsStr,directory:bool|->Result<File> {
            use std::os::unix::ffi::OsStrExt;
            let name=std::ffi::CString::new(name.as_bytes()).map_err(|_|"endpoint NUL")?;
            let flags=libc::O_PATH|libc::O_NOFOLLOW|libc::O_CLOEXEC|if directory {libc::O_DIRECTORY}else{0};
            let raw=unsafe{libc::openat(fd,name.as_ptr(),flags)};
            if raw<0 {return Err(io::Error::last_os_error().to_string());}Ok(unsafe{File::from_raw_fd(raw)})
        };
        let root=open(libc::AT_FDCWD,std::ffi::OsStr::new("/"),true)?;let mut dirs=vec![root];
        for name in &names[..names.len()-1] {dirs.push(open(dirs.last().ok_or("endpoint root missing")?.as_raw_fd(),name,true)?);}
        for (at,dir) in dirs.iter().enumerate() {
            let meta=dir.metadata().map_err(|e|e.to_string())?;
            if !meta.is_dir() || (meta.uid()!=0 && meta.uid()!=owner) || meta.mode()&0o022!=0 {
                return Err("endpoint ancestor principal/write protection refused".into());
            }
            if at==dirs.len()-1 && (meta.uid()!=owner || meta.gid()!=group || meta.mode()&0o7777!=0o710) {
                return Err("installed IPC leaf rights differ".into());
            }
        }
        let file=open(dirs.last().ok_or("endpoint parent missing")?.as_raw_fd(),names.last().ok_or("endpoint name missing")?,false)?;
        let meta=file.metadata().map_err(|e|e.to_string())?;
        if !meta.file_type().is_socket() || meta.uid()!=owner || meta.gid()!=group || meta.nlink()!=1 || meta.mode()&0o7777!=0o660 {
            return Err("installed socket object principal/type/rights refused".into());
        }
        let mut ids=dirs.iter().map(file_id).collect::<Result<Vec<_>>>()?;ids.push(file_id(&file)?);
        let close_pins=dirs.iter().chain(std::iter::once(&file))
            .map(|file|super::native_retained_close::retained_identity(file).map_err(|e|format!("original endpoint identity: {e}")))
            .collect::<Result<Vec<_>>>()?;
        use std::os::unix::ffi::OsStrExt;
        let names=names.iter().map(|name|std::ffi::CString::new(name.as_bytes()).map_err(|_|"endpoint name encoding".to_string()))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self{path,owner,group,dirs,file,ids,close_pins,names})
    }
    fn recheck(&self,authority:&InstalledChannelAuthority)->Result<()> {
        let named=Self::capture(authority)?;
        if named.path!=self.path || named.owner!=self.owner || named.group!=self.group || named.ids!=self.ids {
            return Err("installed endpoint named identity changed".into());
        }
        let mut held=self.dirs.iter().map(file_id).collect::<Result<Vec<_>>>()?;held.push(file_id(&self.file)?);
        if held!=self.ids {return Err("installed endpoint held identity changed".into());}Ok(())
    }
    fn recheck_removed(&self,authority:&InstalledChannelAuthority)->Result<()> {
        use std::os::unix::fs::FileTypeExt;
        if authority.placement.endpoint()!=self.path.as_path()||self.dirs.len()!=self.names.len()
            ||self.ids.len()!=self.dirs.len()+1{return Err("removed endpoint roster differs".into());}
        for (at,dir) in self.dirs.iter().enumerate(){
            let meta=dir.metadata().map_err(|e|e.to_string())?;
            if file_id(dir)?!=self.ids[at]||!meta.is_dir()||(meta.uid()!=0&&meta.uid()!=self.owner)
                ||meta.mode()&0o022!=0{return Err("removed endpoint held ancestor differs".into());}
            if at+1==self.dirs.len()&&(meta.uid()!=self.owner||meta.gid()!=self.group||meta.mode()&0o7777!=0o710){
                return Err("removed endpoint IPC rights differ".into());}
            if at!=0{let mut named:libc::stat=unsafe{zeroed()};
                if unsafe{libc::fstatat(self.dirs[at-1].as_raw_fd(),self.names[at-1].as_ptr(),&mut named,libc::AT_SYMLINK_NOFOLLOW)}!=0
                    ||named.st_mode&libc::S_IFMT!=libc::S_IFDIR
                    ||(FileIdentity{device:named.st_dev,inode:named.st_ino})!=self.ids[at]{
                    return Err("removed endpoint named ancestor differs".into());}}
        }
        let meta=self.file.metadata().map_err(|e|e.to_string())?;
        if file_id(&self.file)?!=*self.ids.last().ok_or("removed socket original identity absent")?
            ||!meta.file_type().is_socket()||meta.uid()!=self.owner||meta.gid()!=self.group
            ||meta.nlink()!=0||meta.mode()&0o7777!=0o660{return Err("removed original socket differs".into());}
        let mut named:libc::stat=unsafe{zeroed()};
        let status=unsafe{libc::fstatat(self.dirs.last().ok_or("removed endpoint parent absent")?.as_raw_fd(),
            self.names.last().ok_or("removed endpoint name absent")?.as_ptr(),&mut named,libc::AT_SYMLINK_NOFOLLOW)};
        if status==0||io::Error::last_os_error().raw_os_error()!=Some(libc::ENOENT){
            return Err("removed original socket name is present or ambiguous".into());}Ok(())
    }
    fn removed_close_transition(&self,authority:&InstalledChannelAuthority)->Result<UnlinkedSocketClose> {
        self.recheck_removed(authority)?;
        let original=*self.close_pins.last().ok_or("unlinked original socket pin absent")?;
        let expected=super::native_retained_close::retained_identity(&self.file)
            .map_err(|e|format!("unlinked original socket observation: {e}"))?;
        if original[..16]!=expected[..16]||original[16..]!=1u64.to_le_bytes()
            ||expected[16..]!=0u64.to_le_bytes(){return Err("unlinked socket transition differs".into());}
        Ok(UnlinkedSocketClose{original,expected})
    }
    fn close_into(self,report:&mut super::native_retained_close::RetainedCloseReport,unlinked:Option<UnlinkedSocketClose>) {
        let Self{dirs,file,close_pins,..}=self;
        let mut pins=close_pins.into_iter().rev();
        let original=pins.next().expect("original endpoint pin");
        if let Some(transition)=unlinked{
            // The capability retains original1 and verified expected0; ordinary
            // files/directories still require exact all24-byte equality.
            assert!(original==transition.original,"exact original unlinked socket pin");
            report.file_after_owned_socket_unlink(file,transition);
        }else{report.file(file,original);}
        for file in dirs.into_iter().rev(){report.file(file,pins.next().expect("original endpoint ancestor pin"));}
    }
}

/// Create-only listener beneath the exact already installed IPC directory.
/// No ancestor/account/ACL setup, old-socket unlink, stale-path adoption or
/// provider fallback. Actual ordinary owner launch requires its separate
/// exact artifact/installation authorization; this constructor does not
/// supply that authorization or qualification inputs.
pub(super) struct InstalledUnixListener {inner:Option<Box<std::mem::ManuallyDrop<InstalledUnixListenerState>>>}
pub(super) struct InstalledUnixListenerState {
    frozen:bool,creation_sync:File,creation_sync_pin:[u8;24],
    listener:InstalledUnixSocket,endpoint:HeldEndpoint,
    authority:InstalledChannelAuthority,original_listener:[u8;24],cleanup:Option<std::result::Result<(),i32>>,cleanup_sync:Option<File>,cleanup_sync_pin:Option<[u8;24]>,
}
impl InstalledUnixListener {
    pub(super) fn bind_new(authority:InstalledChannelAuthority)->Result<Self>{Self::bind_owned(authority)}
    pub(super) fn idle_for_stop(&mut self)->Result<()> {
        let state:&mut InstalledUnixListenerState=self.inner.as_mut().ok_or("original listener retained UNKNOWN")?;
        state.idle_for_stop()
    }
    pub(super) fn remove_bound_after_join(&mut self,lease:&mut super::protected_clock_owner::StoppedOwnerNamespaceLease<'_>)->Result<()> {
        let state:&mut InstalledUnixListenerState=self.inner.as_mut().ok_or("original listener retained UNKNOWN")?;
        state.remove_bound_after_join(lease)
    }
    pub(super) fn accept(&mut self,authority:InstalledChannelAuthority)->impl std::future::Future<Output=Result<InstalledUnixConnection>>+'_ {
        self.accept_owned(authority)
    }
    /// Only called after the ORIGINAL application/runtime and operation futures
    /// returned. Preserve named socket entry; no unlink/adopt/replacement here.
    pub(super) fn close_retained(mut self)->std::result::Result<UnixRetainedClose,std::mem::ManuallyDrop<Self>> {
        if self.idle_for_stop().is_err() || self.endpoint.close_pins.len()!=self.endpoint.dirs.len()+1 {
            return Err(std::mem::ManuallyDrop::new(self));
        }
        let unlinked=match self.cleanup {Some(Ok(()))=>match self.endpoint.removed_close_transition(&self.authority){
            Ok(transition)=>Some(transition),Err(_)=>return Err(std::mem::ManuallyDrop::new(self)),},
            None=>None,Some(Err(_))=>return Err(std::mem::ManuallyDrop::new(self)),};
        let count=match self.endpoint.dirs.len().checked_add(3+usize::from(self.cleanup_sync.is_some())){Some(n)=>n,None=>return Err(std::mem::ManuallyDrop::new(self))};
        let mut report=match super::native_retained_close::RetainedCloseReport::prepare(count){Ok(r)=>r,
            Err(_)=>return Err(std::mem::ManuallyDrop::new(self))};
        let InstalledUnixListenerState{listener,endpoint,authority,original_listener,creation_sync,creation_sync_pin,cleanup_sync,cleanup_sync_pin,..}=
            std::mem::ManuallyDrop::into_inner(*self.inner.take().expect("checked original listener root"));
        // The joined runtime is gone; retain its inert registration allocation
        // while transferring ONLY its original FD's native close obligation.
        let listener=std::mem::ManuallyDrop::new(listener);
        report.file(unsafe{File::from_raw_fd(listener.as_raw_fd())},original_listener);
        report.file(creation_sync,creation_sync_pin);
        if let Some(sync)=cleanup_sync{report.file(sync,cleanup_sync_pin.expect("original cleanup sync pin"));}
        endpoint.close_into(&mut report,unlinked);Ok(close_selected(report,authority.guard))
    }
}

impl InstalledUnixListenerState {
    pub(super) fn idle_for_stop(&mut self)->Result<()> {
        if self.frozen{return Err("original listener frozen/unknown".into());}
        self.authority.recheck()?;
        match self.cleanup {Some(Ok(()))=>self.endpoint.recheck_removed(&self.authority)?,Some(Err(_))=>return Err("original socket cleanup outcome unknown/failed; no retry".into()),
            None=>self.endpoint.recheck(&self.authority)?,}
        self.authority.recheck()
    }
    /// Explicit joined-controller cleanup of ONLY the socket THIS listener
    /// bound. The caller holds the SAME stopped owner writer lease through the
    /// syscall/readback/sync. The710 parent excludes ordinary Node writers;
    /// malicious owner/admin mutation is outside this separate-principal model.
    pub(super) fn remove_bound_after_join(&mut self,lease:&mut super::protected_clock_owner::StoppedOwnerNamespaceLease<'_>)->Result<()> {
        if let Some(result)=self.cleanup{return result.map_err(|code|format!("cached original socket cleanup refusal {code}"));}
        if !matches!(self.authority.role,ChannelRole::Owner){return Err("consumer cannot remove owner socket".into());}
        lease.recheck(&self.authority.placement,self.authority.record.record().canonical())?;
        self.idle_for_stop()?;
        if retained_socket_identity(self.listener.as_raw_fd())?!=self.original_listener{return Err("original listener FD changed".into());}
        let parent=self.endpoint.dirs.last().ok_or("cleanup original parent absent")?;
        let fd=unsafe{libc::openat(parent.as_raw_fd(),c".".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
        if fd<0{return Err(io::Error::last_os_error().to_string());}
        let sync=unsafe{File::from_raw_fd(fd)};
        let expected_pin=*self.endpoint.close_pins.get(self.endpoint.dirs.len()-1).ok_or("cleanup original parent pin absent")?;
        self.cleanup_sync=Some(sync);self.cleanup_sync_pin=Some(expected_pin);
        if super::native_retained_close::retained_identity(self.cleanup_sync.as_ref().expect("original sync holder"))
            .map_err(|e|format!("cleanup original sync identity: {e}"))?!=expected_pin {
            return Err("cleanup held sync identity differs".into());}
        if file_id(self.cleanup_sync.as_ref().expect("original sync holder"))?!=file_id(parent)?{
            return Err("cleanup sync parent differs".into());}
        self.endpoint.recheck(&self.authority)?;
        lease.recheck(&self.authority.placement,self.authority.record.record().canonical())?;
        // Publish UNKNOWN before the ONE unlink. Foreign/missing names above
        // refuse; there is no startup adoption, blind retry or broad deletion.
        self.cleanup=Some(Err(-1));
        let name=self.endpoint.names.last().ok_or("cleanup original name absent")?;
        if unsafe{libc::unlinkat(parent.as_raw_fd(),name.as_ptr(),0)}!=0{
            let code=io::Error::last_os_error().raw_os_error().unwrap_or(-1);self.cleanup=Some(Err(code));
            return Err(format!("original bound socket unlink refused {code}"));}
        let post=(||{
            self.endpoint.recheck_removed(&self.authority)?;
            self.cleanup_sync.as_ref().ok_or("cleanup sync holder absent")?.sync_all().map_err(|e|e.to_string())?;
            lease.recheck(&self.authority.placement,self.authority.record.record().canonical())?;
            self.authority.recheck()?;self.endpoint.recheck_removed(&self.authority)
        })();
        if post.is_ok(){self.cleanup=Some(Ok(()));}else{self.cleanup=Some(Err(-2));}post
    }
}

// Preallocated same-original listener and connection owners. Their Drop
// retains the entire graph; no abandoned published value RAII-closes a fd.
impl std::ops::Deref for InstalledUnixListener {type Target=InstalledUnixListenerState;
    fn deref(&self)->&Self::Target{self.inner.as_ref().expect("retained original listener absent")}}
impl std::ops::DerefMut for InstalledUnixListener {
    fn deref_mut(&mut self)->&mut Self::Target{self.inner.as_mut().expect("retained original listener absent")}}
impl Drop for InstalledUnixListener {fn drop(&mut self){if let Some(mut state)=self.inner.take(){
    state.frozen=true;let _=Box::into_raw(state);
}}}
impl std::ops::Deref for InstalledUnixConnection {type Target=InstalledUnixConnectionState;
    fn deref(&self)->&Self::Target{self.inner.as_ref().expect("retained original connection absent")}}
impl std::ops::DerefMut for InstalledUnixConnection {
    fn deref_mut(&mut self)->&mut Self::Target{self.inner.as_mut().expect("retained original connection absent")}}
impl Drop for InstalledUnixConnection {fn drop(&mut self){if let Some(state)=self.inner.take(){
    state.frozen.store(true,std::sync::atomic::Ordering::SeqCst);let _=Box::into_raw(state);
}}}

impl UnixConnectCustody {
    // Consumer and owner publication use the SAME preallocated opaque owner.
    fn publish_connection(&mut self)->Result<InstalledUnixConnection> {
        let state:&mut UnixConnectState=self.state.as_mut().ok_or("original constructor root absent")?;
        if state.endpoint.is_none()||state.peer.is_none()||(state.socket.is_none()&&state.accepted.is_none())
            ||(state.socket.is_some()&&state.registration.is_none())||state.original_socket.is_none()
            ||state.connection_state.is_none()||state.published_frozen.is_none(){return Err("original publication roster incomplete".into());}
        let endpoint=state.endpoint.take().expect("checked endpoint");let peer=state.peer.take().expect("checked peer");
        let original_socket=state.original_socket.expect("checked original socket pin");
        let mut publication=state.connection_state.take().expect("checked connection owner allocation");
        let frozen=state.published_frozen.as_ref().expect("checked freeze allocation").clone();
        let published_frozen=frozen.clone();
        let socket=if let Some(original)=state.socket.take(){InstalledUnixSocket::Connected{
            original,registration:std::mem::ManuallyDrop::into_inner(state.registration.take().expect("checked registration"))}}
            else{InstalledUnixSocket::Accepted(state.accepted.take().expect("checked original accepted input"))};
        let authority=unsafe{std::mem::ManuallyDrop::take(&mut state.authority)};
        publication.write(std::mem::ManuallyDrop::new(InstalledUnixConnectionState{socket,
            peer:std::mem::ManuallyDrop::into_inner(peer),endpoint:std::mem::ManuallyDrop::into_inner(endpoint),authority,
            frozen,pending:None,last_quote_sequence:None,elapsed_incarnation:None,owner_request:None,original_socket,
            shutdown_result:None,shutdown_was_clean:false}));
        let connection=InstalledUnixConnection{inner:Some(unsafe{publication.assume_init()})};
        state.staged.clear();state.frozen=false;published_frozen.store(false,std::sync::atomic::Ordering::SeqCst);Ok(connection)
    }
    fn disarm(&mut self){if let Some(state)=self.state.take(){let _=std::mem::ManuallyDrop::into_inner(*state);}}
    fn prepare_supplied_connection(&mut self)->Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let state:&mut UnixConnectState=self.state.as_mut().ok_or("original owner constructor absent")?;
        let fd=if let Some(socket)=&state.socket{socket.as_raw_fd()}else{state.accepted.as_ref().ok_or("original accepted socket absent")?.as_raw_fd()};
        state.original_socket=Some(retained_socket_identity(fd)?);state.authority.recheck()?;
        let path=state.authority.placement.endpoint().as_os_str().as_bytes();
        let mut address:libc::sockaddr_un=unsafe{zeroed()};let mut length=size_of::<libc::sockaddr_un>() as libc::socklen_t;
        let expected=std::mem::offset_of!(libc::sockaddr_un,sun_path)+path.len()+1;
        let observed=match state.authority.role{ChannelRole::Owner=>unsafe{libc::getsockname(fd,(&mut address as *mut libc::sockaddr_un).cast(),&mut length)},
            ChannelRole::Consumer=>unsafe{libc::getpeername(fd,(&mut address as *mut libc::sockaddr_un).cast(),&mut length)}};
        if path.is_empty()||path.contains(&0)||path.len()>=address.sun_path.len()||observed!=0
            ||length as usize!=expected||address.sun_family!=libc::AF_UNIX as libc::sa_family_t
            ||address.sun_path[path.len()]!=0||!address.sun_path[..path.len()].iter().zip(path).all(|(a,b)|*a as u8==*b) {
            return Err("original installed owner socket pathname differs or unknown".into());
        }
        let enabled:i32=1;
        if unsafe{libc::setsockopt(fd,libc::SOL_SOCKET,libc::SO_PASSCRED,(&enabled as *const i32).cast(),size_of::<i32>() as libc::socklen_t)}!=0 {
            return Err("kernel per-frame credentials unavailable".into());}
        state.peer=Some(KernelPeer::capture_retained(&InstalledSocketBorrow(fd),&mut state.authority,&mut state.staged)?);
        state.endpoint=Some(HeldEndpoint::capture_retained(&state.authority,&mut state.staged)?);
        state.endpoint.as_ref().expect("rooted owner endpoint").recheck_constructor(&state.authority)?;
        state.peer.as_ref().expect("rooted owner peer").recheck(&InstalledSocketBorrow(fd))?;state.authority.recheck()?;
        if retained_socket_identity(fd)?!=state.original_socket.expect("original owner socket pin"){
            return Err("original owner socket identity changed before publication".into());}Ok(())
    }
}

impl InstalledUnixListener {
    fn bind_owned(authority:InstalledChannelAuthority)->Result<Self> {
        use std::os::unix::{ffi::OsStrExt,fs::FileTypeExt};
        let mut custody=UnixConnectCustody::new(authority);
        // Allocate publication before acquiring any new native original.
        let mut publication=Box::<std::mem::ManuallyDrop<InstalledUnixListenerState>>::new_uninit();
        let state:&mut UnixConnectState=custody.state.as_mut().expect("original listener constructor root");
        if !matches!(state.authority.role,ChannelRole::Owner){return Err("consumer cannot create owner listener".into());}
        state.authority.recheck()?;
        let path=state.authority.placement.endpoint().to_path_buf();
        let parent=path.parent().ok_or("installed IPC parent absent")?.to_path_buf();
        let names=path.components().map(|value|match value{std::path::Component::RootDir=>Ok(None),
            std::path::Component::Normal(name)=>std::ffi::CString::new(name.as_bytes()).map(Some).map_err(|_|"listener name encoding"),
            _=>Err("listener ancestor grammar refused")}).collect::<std::result::Result<Vec<_>,_>>()?
            .into_iter().flatten().collect::<Vec<_>>();
        if !path.is_absolute()||names.len()<2{return Err("installed endpoint path refused".into());}
        state.staged.try_reserve_exact(names.len()+2).map_err(|_|"listener original custody allocation refused")?;
        let mut dirs=Vec::new();dirs.try_reserve_exact(names.len()).map_err(|_|"listener endpoint publication allocation refused")?;
        let mut address:libc::sockaddr_un=unsafe{zeroed()};let bytes=path.as_os_str().as_bytes();
        if bytes.is_empty()||bytes.contains(&0)||bytes.len()>=address.sun_path.len(){return Err("installed UNIX pathname refused".into());}
        address.sun_family=libc::AF_UNIX as libc::sa_family_t;
        for (slot,byte) in address.sun_path.iter_mut().zip(bytes){*slot=*byte as libc::c_char;}
        let length=(std::mem::offset_of!(libc::sockaddr_un,sun_path)+bytes.len()+1) as libc::socklen_t;
        let root=std::ffi::CString::new("/").expect("literal root");
        for name in std::iter::once(root.as_c_str()).chain(names[..names.len()-1].iter().map(|name|name.as_c_str())){
            let parent_fd=state.staged.last().map(|file|file.as_raw_fd()).unwrap_or(libc::AT_FDCWD);
            let fd=unsafe{libc::openat(parent_fd,name.as_ptr(),libc::O_PATH|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
            if fd<0{return Err(io::Error::last_os_error().to_string());}
            state.staged.push(std::mem::ManuallyDrop::new(unsafe{File::from_raw_fd(fd)}));
        }
        let (owner,_,_,_)=state.authority.placement.channel_principals();let group=state.authority.placement.channel_group();
        for file in &state.staged{let meta=file.metadata().map_err(|e|e.to_string())?;
            if !meta.is_dir()||(meta.uid()!=0&&meta.uid()!=owner)||meta.mode()&0o022!=0{return Err("listener ancestor protection refused before bind".into());}}
        let parent_index=state.staged.len()-1;let parent_fd=state.staged[parent_index].as_raw_fd();
        let parent_ids=state.staged.iter().map(|file|file_id(file)).collect::<Result<Vec<_>>>()?;
        let parent_before=file_id(&state.staged[parent_index])?;
        let meta=state.staged[parent_index].metadata().map_err(|e|e.to_string())?;
        if meta.uid()!=owner||meta.gid()!=group||meta.mode()&0o7777!=0o710{return Err("installed listener IPC rights differ".into());}
        let raw=fact(std::path::Path::new("/proc/self"),"status")?;
        let text=std::str::from_utf8(&raw).map_err(|_|"listener umask encoding")?;
        let umask=text.lines().find_map(|line|line.strip_prefix("Umask:")).ok_or("listener umask unavailable")?;
        if u32::from_str_radix(umask.trim(),8).map_err(|_|"listener umask format")?!=0o077{return Err("installed listener process umask must already be0077".into());}
        state.authority.recheck()?;
        let fd=unsafe{libc::socket(libc::AF_UNIX,libc::SOCK_STREAM|libc::SOCK_NONBLOCK|libc::SOCK_CLOEXEC,0)};
        if fd<0{return Err(io::Error::last_os_error().to_string());}
        state.socket=Some(std::mem::ManuallyDrop::new(unsafe{File::from_raw_fd(fd)}));
        state.original_socket=Some(retained_socket_identity(fd)?);
        state.registration=Some(std::mem::ManuallyDrop::new(tokio::io::unix::AsyncFd::new(InstalledSocketBorrow(fd)).map_err(|e|e.to_string())?));
        // SAME Linux backlog as the selected Mio1.2.4 Unix listener (-1).
        // Bind is create-only and attempted once; no stale adoption/unlink.
        if unsafe{libc::bind(fd,(&address as *const libc::sockaddr_un).cast(),length)}!=0{return Err(io::Error::last_os_error().to_string());}
        if unsafe{libc::listen(fd,-1)}!=0{return Err(io::Error::last_os_error().to_string());}
        let socket_index=state.staged.len();
        let name=names.last().ok_or("listener name absent")?;
        let socket_fd=unsafe{libc::openat(parent_fd,name.as_ptr(),libc::O_PATH|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
        if socket_fd<0{return Err(io::Error::last_os_error().to_string());}
        state.staged.push(std::mem::ManuallyDrop::new(unsafe{File::from_raw_fd(socket_fd)}));
        let initial=file_id(&state.staged[socket_index])?;
        let meta=state.staged[socket_index].metadata().map_err(|e|e.to_string())?;
        if !meta.file_type().is_socket()||meta.uid()!=owner||meta.nlink()!=1||meta.mode()&0o7777!=0o700{return Err("create-only socket initial rights/type differ".into());}
        if unsafe{libc::fchownat(parent_fd,name.as_ptr(),u32::MAX,group,libc::AT_SYMLINK_NOFOLLOW)}!=0{return Err(io::Error::last_os_error().to_string());}
        if file_id(&state.staged[socket_index])?!=initial{return Err("new socket identity changed before mode application".into());}
        if unsafe{libc::fchmodat(parent_fd,name.as_ptr(),0o660,0)}!=0{return Err(io::Error::last_os_error().to_string());}
        let mut ids=parent_ids;ids.push(initial);
        let close_pins=state.staged.iter().map(|file|super::native_retained_close::retained_identity(file)
            .map_err(|e|format!("original listener endpoint identity: {e}"))).collect::<Result<Vec<_>>>()?;
        // Reuse SAME original ancestor/socket descriptors as the final endpoint.
        for index in 0..socket_index{dirs.push(unsafe{File::from_raw_fd(state.staged[index].as_raw_fd())});}
        state.endpoint=Some(std::mem::ManuallyDrop::new(HeldEndpoint{path,owner,group,dirs,
            file:unsafe{File::from_raw_fd(socket_fd)},ids,close_pins,names}));
        state.endpoint.as_ref().expect("rooted listener endpoint").recheck_constructor(&state.authority)?;
        if file_id(&state.staged[parent_index])?!=parent_before{return Err("listener create-new ancestry changed".into());}
        let parent_name=std::ffi::CString::new(parent.as_os_str().as_bytes()).map_err(|_|"listener sync parent encoding")?;
        let sync_fd=unsafe{libc::open(parent_name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
        if sync_fd<0{return Err(io::Error::last_os_error().to_string());}
        let sync_index=state.staged.len();state.staged.push(std::mem::ManuallyDrop::new(unsafe{File::from_raw_fd(sync_fd)}));
        if file_id(&state.staged[sync_index])?!=parent_before{return Err("listener sync directory changed".into());}
        let creation_sync_pin=super::native_retained_close::retained_identity(&state.staged[sync_index]).map_err(|e|format!("original creation sync identity: {e}"))?;
        state.staged[sync_index].sync_all().map_err(|e|e.to_string())?;
        state.authority.recheck()?;state.endpoint.as_ref().expect("rooted endpoint").recheck_constructor(&state.authority)?;
        if retained_socket_identity(fd)?!=state.original_socket.expect("rooted listener pin"){return Err("original listener changed before publication".into());}
        let endpoint=state.endpoint.take().expect("checked endpoint");let original=state.socket.take().expect("checked listener");
        let registration=state.registration.take().expect("checked listener registration");let original_listener=state.original_socket.expect("checked listener pin");
        let authority=unsafe{std::mem::ManuallyDrop::take(&mut state.authority)};
        publication.write(std::mem::ManuallyDrop::new(InstalledUnixListenerState{
            listener:InstalledUnixSocket::Connected{original,registration:std::mem::ManuallyDrop::into_inner(registration)},
            endpoint:std::mem::ManuallyDrop::into_inner(endpoint),authority,original_listener,frozen:false,
            creation_sync:unsafe{File::from_raw_fd(sync_fd)},creation_sync_pin,cleanup:None,cleanup_sync:None,cleanup_sync_pin:None}));
        let listener=Self{inner:Some(unsafe{publication.assume_init()})};state.staged.clear();custody.disarm();Ok(listener)
    }
    fn accept_owned(&mut self,authority:InstalledChannelAuthority)->impl std::future::Future<Output=Result<InstalledUnixConnection>>+'_ {
        // Synchronous move covers cancellation before the first poll. On any
        // refusal/drop the SAME listener and accepted/partial graph stay linked.
        let mut custody=UnixConnectCustody::new(authority);
        custody.state.as_mut().expect("original accept root").owner_listener=self.inner.take();
        async move {
            let state:&mut UnixConnectState=custody.state.as_mut().expect("original accept root");
            let listener:&mut InstalledUnixListenerState=state.owner_listener.as_mut().ok_or("original listener unavailable; retained UNKNOWN")?;
            if listener.frozen{return Err("original listener frozen".into());}
            listener.authority.recheck()?;listener.endpoint.recheck_constructor(&listener.authority)?;
            if !matches!(state.authority.role,ChannelRole::Owner)||state.authority.context!=listener.authority.context
                ||state.authority.local!=listener.authority.local||state.authority.placement.endpoint()!=listener.authority.placement.endpoint(){
                return Err("accepted connection's installed owner authority differs".into());}
            let original_fd=listener.listener.as_raw_fd();
            if retained_socket_identity(original_fd)?!=listener.original_listener{return Err("original listener identity changed".into());}
            let socket_slot=&mut state.socket;
            listener.listener.async_io(Interest::READABLE,||{
                if socket_slot.is_some(){return Err(io::Error::other("original accept already acquired; no retry"));}
                let fd=unsafe{libc::accept4(original_fd,std::ptr::null_mut(),std::ptr::null_mut(),libc::SOCK_NONBLOCK|libc::SOCK_CLOEXEC)};
                if fd<0{return Err(io::Error::last_os_error());}
                *socket_slot=Some(std::mem::ManuallyDrop::new(unsafe{File::from_raw_fd(fd)}));Ok(())
            }).await.map_err(|e|format!("original owner accept refused/unknown: {e}"))?;
            listener.authority.recheck()?;listener.endpoint.recheck_constructor(&listener.authority)?;
            let fd=state.socket.as_ref().expect("rooted original accepted socket").as_raw_fd();
            state.registration=Some(std::mem::ManuallyDrop::new(tokio::io::unix::AsyncFd::new(InstalledSocketBorrow(fd)).map_err(|e|e.to_string())?));
            custody.prepare_supplied_connection()?;let connection=custody.publish_connection()?;
            self.inner=custody.state.as_mut().expect("original accept root").owner_listener.take();
            custody.disarm();Ok(connection)
        }
    }
}

// The normal consumer creates its original descriptor itself. Readiness owns
// only this private borrow; neither registration refusal nor registration Drop
// can discharge the original native close obligation.
struct InstalledSocketBorrow(i32);
impl AsRawFd for InstalledSocketBorrow {fn as_raw_fd(&self)->i32{self.0}}
enum InstalledUnixSocket {
    Accepted(std::mem::ManuallyDrop<UnixStream>),
    Connected {registration:tokio::io::unix::AsyncFd<InstalledSocketBorrow>,
        original:std::mem::ManuallyDrop<File>},
}
impl AsRawFd for InstalledUnixSocket {fn as_raw_fd(&self)->i32 {match self {
    Self::Accepted(socket)=>socket.as_raw_fd(),Self::Connected{original,..}=>original.as_raw_fd(),
}}}
impl InstalledUnixSocket {
    async fn async_io<T>(&self,interest:Interest,mut operation:impl FnMut()->io::Result<T>)->io::Result<T> {
        match self {Self::Accepted(socket)=>socket.async_io(interest,operation).await,
            Self::Connected{registration,..}=>registration.async_io(interest,|_|operation()).await}
    }
}

// All constructor allocations and native originals remain in this SAME root.
// Failure/cancellation/unwind publishes no consumer and no close observation.
// Staged Files are MD original owners; final endpoint/peer fields below are
// private representations of the SAME originals, never dup/reopen/adoption.
struct UnixConnectState {
    authority:std::mem::ManuallyDrop<InstalledChannelAuthority>,
    endpoint:Option<std::mem::ManuallyDrop<HeldEndpoint>>,
    peer:Option<std::mem::ManuallyDrop<KernelPeer>>,
    socket:Option<std::mem::ManuallyDrop<File>>,original_socket:Option<[u8;24]>,
    accepted:Option<std::mem::ManuallyDrop<UnixStream>>,owner_listener:Option<Box<std::mem::ManuallyDrop<InstalledUnixListenerState>>>,
    connection_state:Option<Box<std::mem::MaybeUninit<std::mem::ManuallyDrop<InstalledUnixConnectionState>>>>,
    registration:Option<std::mem::ManuallyDrop<tokio::io::unix::AsyncFd<InstalledSocketBorrow>>>,
    staged:Vec<std::mem::ManuallyDrop<File>>,
    frozen:bool,published_frozen:Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    connect_called:bool,connect_result:Option<std::result::Result<(),i32>>,
    completion_result:Option<std::result::Result<(),i32>>,
    publication:Option<Box<std::mem::MaybeUninit<InstalledUnixConnection>>>,
}
struct UnixConnectCustody {state:Option<Box<std::mem::ManuallyDrop<UnixConnectState>>>}
impl Drop for UnixConnectCustody {fn drop(&mut self){if let Some(mut state)=self.state.take(){
    state.frozen=true;
    if let Some(listener)=&mut state.owner_listener{listener.frozen=true;}
    if let Some(frozen)=&state.published_frozen{frozen.store(true,std::sync::atomic::Ordering::SeqCst);}
    // Includes reactor registration and every original partial acquisition.
    // UNKNOWN is retained whole. A destructor/error is never a native report.
    let _=Box::into_raw(state);
}}}
impl UnixConnectCustody {
    fn new(authority:InstalledChannelAuthority)->Self {
        let authority=std::mem::ManuallyDrop::new(authority);
        let mut custody=Self{state:Some(Box::new(std::mem::ManuallyDrop::new(UnixConnectState{
            authority,endpoint:None,peer:None,socket:None,original_socket:None,registration:None,accepted:None,owner_listener:None,connection_state:None,
            staged:Vec::new(),frozen:true,published_frozen:None,connect_called:false,connect_result:None,completion_result:None,
            publication:None,
        })))};
        let state:&mut UnixConnectState=custody.state.as_mut().expect("original constructor root");
        state.published_frozen=Some(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)));
        state.publication=Some(Box::<InstalledUnixConnection>::new_uninit());
        state.connection_state=Some(Box::<std::mem::ManuallyDrop<InstalledUnixConnectionState>>::new_uninit());custody
    }
    async fn acquire(mut self)->Result<InstalledUnixFreshConsumer> {
        use std::os::unix::ffi::OsStrExt;
        let state:&mut UnixConnectState=self.state.as_mut().expect("original UNIX constructor root");
        if !matches!(state.authority.role,ChannelRole::Consumer){return Err("owner cannot issue consumer connector".into());}
        state.authority.recheck()?;
        state.endpoint=Some(HeldEndpoint::capture_retained(&state.authority,&mut state.staged)?);
        let path=state.authority.placement.endpoint().as_os_str().as_bytes();
        let mut address:libc::sockaddr_un=unsafe{zeroed()};address.sun_family=libc::AF_UNIX as libc::sa_family_t;
        if path.is_empty()||path.contains(&0)||path.len()>=address.sun_path.len(){return Err("installed UNIX pathname refused".into());}
        for (slot,byte) in address.sun_path.iter_mut().zip(path.iter()){*slot=*byte as libc::c_char;}
        let address_length=(std::mem::offset_of!(libc::sockaddr_un,sun_path)+path.len()+1) as libc::socklen_t;
        let fd=unsafe{libc::socket(libc::AF_UNIX,libc::SOCK_STREAM|libc::SOCK_NONBLOCK|libc::SOCK_CLOEXEC,0)};
        if fd<0{return Err(io::Error::last_os_error().to_string());}
        // No allocation, fallible operation or await between acquisition/root.
        state.socket=Some(std::mem::ManuallyDrop::new(unsafe{File::from_raw_fd(fd)}));
        state.original_socket=Some(retained_socket_identity(fd)?);
        state.registration=Some(std::mem::ManuallyDrop::new(tokio::io::unix::AsyncFd::new(InstalledSocketBorrow(fd))
            .map_err(|e|format!("original UNIX readiness registration refused: {e}"))?));
        state.connect_called=true;
        let called=unsafe{libc::connect(fd,(&address as *const libc::sockaddr_un).cast(),address_length)};
        let connect_result=if called==0{Ok(())}else{Err(io::Error::last_os_error().raw_os_error().unwrap_or(-1))};
        state.connect_result=Some(connect_result);
        match connect_result {Ok(())=>state.completion_result=Some(Ok(())),Err(libc::EINPROGRESS)=>{
            // Original connect is called exactly once; cancellation never
            // retries it or interprets a dropped future as completion/close.
            let _ready=state.registration.as_ref().expect("rooted original UNIX registration").writable().await
                .map_err(|e|format!("original UNIX connect readiness unknown: {e}"))?;
            let mut error:i32=0;let mut length=size_of::<i32>() as libc::socklen_t;
            let observed=unsafe{libc::getsockopt(fd,libc::SOL_SOCKET,libc::SO_ERROR,(&mut error as *mut i32).cast(),&mut length)};
            if observed!=0||length as usize!=size_of::<i32>(){return Err("original UNIX connect completion unknown".into());}
            state.completion_result=Some(if error==0{Ok(())}else{Err(error)});
            if error!=0{return Err(format!("original UNIX connect refused: {error}; custody retained UNKNOWN"));}
        },Err(error)=>return Err(format!("original UNIX connect refused: {error}; custody retained UNKNOWN"))}
        let mut observed_address:libc::sockaddr_un=unsafe{zeroed()};
        let mut observed_length=size_of::<libc::sockaddr_un>() as libc::socklen_t;
        if unsafe{libc::getpeername(fd,(&mut observed_address as *mut libc::sockaddr_un).cast(),&mut observed_length)}!=0
            ||observed_length!=address_length||observed_address.sun_family!=address.sun_family
            ||observed_address.sun_path[..path.len()+1]!=address.sun_path[..path.len()+1] {
            return Err("original installed UNIX peer pathname differs or unknown".into());
        }
        let enabled:i32=1;
        if unsafe{libc::setsockopt(fd,libc::SOL_SOCKET,libc::SO_PASSCRED,(&enabled as *const i32).cast(),size_of::<i32>() as libc::socklen_t)}!=0 {
            return Err("kernel per-frame credentials unavailable".into());
        }
        state.authority.recheck()?;
        state.endpoint.as_ref().expect("rooted endpoint").recheck_constructor(&state.authority)?;
        state.peer=Some(KernelPeer::capture_retained(&InstalledSocketBorrow(fd),&mut state.authority,&mut state.staged)?);
        state.peer.as_ref().expect("rooted original peer").recheck(&InstalledSocketBorrow(fd))?;
        state.authority.recheck()?;
        if retained_socket_identity(fd)?!=state.original_socket.expect("original socket pin") {
            return Err("original UNIX socket identity changed before publication".into());
        }
        let connection=self.publish_connection()?;
        let mut publication=self.state.as_mut().expect("original constructor" ).publication.take().expect("original outer publication" );
        publication.write(connection);
        let consumer=InstalledUnixFreshConsumer{inner:Some(unsafe{publication.assume_init()})};
        self.disarm();Ok(consumer)
    }
}

impl KernelPeer {
    fn capture_retained(socket:&impl AsRawFd,authority:&mut InstalledChannelAuthority,
        staged:&mut Vec<std::mem::ManuallyDrop<File>>)->Result<std::mem::ManuallyDrop<Self>> {
        authority.recheck()?;let before=connection_credential(socket)?;
        if before.pid<=0||before.uid!=authority.remote_uid||before.gid!=authority.remote_gid {
            return Err("kernel peer is not the installed ordinary principal".into());}
        staged.try_reserve(1).map_err(|_|"original peer custody allocation refused")?;
        let mut fd:i32=-1;let mut length=size_of::<i32>() as libc::socklen_t;
        let acquired=unsafe{libc::getsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,77,(&mut fd as *mut i32).cast(),&mut length)};
        let error=if acquired!=0{Some(io::Error::last_os_error())}else{None};
        // Retain any actual returned descriptor before inspecting outcome.
        if fd>=0{staged.push(std::mem::ManuallyDrop::new(unsafe{File::from_raw_fd(fd)}));}
        if let Some(error)=error{return Err(error.to_string());}
        if fd<0{return Err("kernel peer pidfd unavailable".into());}
        let pidfd=staged.last().expect("rooted original pidfd");
        let flags=unsafe{libc::fcntl(fd,libc::F_GETFD)};
        if length as usize!=size_of::<i32>()||flags<0||flags&libc::FD_CLOEXEC==0{return Err("kernel peer pidfd flags/length refused".into());}
        let original_pidfd=super::native_retained_close::retained_identity(pidfd).map_err(|e|format!("original peer pidfd identity: {e}"))?;
        let boot=local_boot()?;
        if connection_credential(socket)?!=before{return Err("kernel peer credential changed".into());}
        // MD before any later check: the rooted original stays linked on error.
        Ok(std::mem::ManuallyDrop::new(Self{credential:before,pidfd:unsafe{File::from_raw_fd(fd)},original_pidfd,boot}))
    }
}

impl HeldEndpoint {
    fn capture_retained(authority:&InstalledChannelAuthority,staged:&mut Vec<std::mem::ManuallyDrop<File>>)
        ->Result<std::mem::ManuallyDrop<Self>> {
        use std::os::unix::{ffi::OsStrExt,fs::FileTypeExt};
        let path=authority.placement.endpoint().to_path_buf();
        let (owner,_,_,_)=authority.placement.channel_principals();let group=authority.placement.channel_group();
        let names=path.components().map(|value|match value {std::path::Component::RootDir=>Ok(None),
            std::path::Component::Normal(name)=>std::ffi::CString::new(name.as_bytes()).map(Some).map_err(|_|"endpoint NUL"),
            _=>Err("installed endpoint path grammar")}).collect::<std::result::Result<Vec<_>,_>>()?
            .into_iter().flatten().collect::<Vec<_>>();
        if !path.is_absolute()||names.len()<2{return Err("installed endpoint path refused".into());}
        let count=names.len().checked_add(1).ok_or("endpoint custody roster overflow")?;
        staged.try_reserve_exact(count).map_err(|_|"endpoint original custody allocation refused")?;
        let mut indices=Vec::new();indices.try_reserve_exact(names.len()).map_err(|_|"endpoint custody indices allocation refused")?;
        let mut dirs=Vec::new();dirs.try_reserve_exact(names.len()).map_err(|_|"endpoint publication allocation refused")?;
        let root=std::ffi::CString::new("/").expect("literal root");
        let open=|parent:i32,name:&std::ffi::CStr,directory:bool,staged:&mut Vec<std::mem::ManuallyDrop<File>>|->Result<usize> {
            let flags=libc::O_PATH|libc::O_NOFOLLOW|libc::O_CLOEXEC|if directory{libc::O_DIRECTORY}else{0};
            let fd=unsafe{libc::openat(parent,name.as_ptr(),flags)};
            if fd<0{return Err(io::Error::last_os_error().to_string());}
            let index=staged.len();staged.push(std::mem::ManuallyDrop::new(unsafe{File::from_raw_fd(fd)}));Ok(index)
        };
        indices.push(open(libc::AT_FDCWD,&root,true,staged)?);
        for name in &names[..names.len()-1]{let parent=staged[*indices.last().expect("original root")].as_raw_fd();
            indices.push(open(parent,name,true,staged)?);}
        for (at,index) in indices.iter().enumerate(){let meta=staged[*index].metadata().map_err(|e|e.to_string())?;
            if !meta.is_dir()||(meta.uid()!=0&&meta.uid()!=owner)||meta.mode()&0o022!=0{return Err("endpoint ancestor principal/write protection refused".into());}
            if at+1==indices.len()&&(meta.uid()!=owner||meta.gid()!=group||meta.mode()&0o7777!=0o710){return Err("installed IPC leaf rights differ".into());}
        }
        let file_index=open(staged[*indices.last().expect("original parent")].as_raw_fd(),names.last().expect("original name"),false,staged)?;
        let meta=staged[file_index].metadata().map_err(|e|e.to_string())?;
        if !meta.file_type().is_socket()||meta.uid()!=owner||meta.gid()!=group||meta.nlink()!=1||meta.mode()&0o7777!=0o660 {
            return Err("installed socket object principal/type/rights refused".into());}
        let mut ids=indices.iter().map(|index|file_id(&staged[*index])).collect::<Result<Vec<_>>>()?;
        ids.push(file_id(&staged[file_index])?);
        let close_pins=indices.iter().copied().chain(std::iter::once(file_index))
            .map(|index|super::native_retained_close::retained_identity(&staged[index]).map_err(|e|format!("original endpoint identity: {e}")))
            .collect::<Result<Vec<_>>>()?;
        // Capacity was allocated before native opens. No fallible work remains
        // between transferring representations and installing the MD endpoint.
        for index in indices{dirs.push(unsafe{File::from_raw_fd(staged[index].as_raw_fd())});}
        let file=unsafe{File::from_raw_fd(staged[file_index].as_raw_fd())};
        Ok(std::mem::ManuallyDrop::new(Self{path,owner,group,dirs,file,ids,close_pins,names}))
    }
    fn recheck_constructor(&self,authority:&InstalledChannelAuthority)->Result<()> {
        use std::os::unix::fs::FileTypeExt;
        if authority.placement.endpoint()!=self.path.as_path()||self.dirs.len()!=self.names.len()
            ||self.ids.len()!=self.dirs.len()+1||self.close_pins.len()!=self.ids.len(){return Err("constructor endpoint roster differs".into());}
        for (at,dir) in self.dirs.iter().enumerate(){let meta=dir.metadata().map_err(|e|e.to_string())?;
            if file_id(dir)?!=self.ids[at]||!meta.is_dir()||(meta.uid()!=0&&meta.uid()!=self.owner)||meta.mode()&0o022!=0 {
                return Err("constructor endpoint held ancestor differs".into());}
            if at+1==self.dirs.len()&&(meta.uid()!=self.owner||meta.gid()!=self.group||meta.mode()&0o7777!=0o710){return Err("constructor endpoint IPC rights differ".into());}
            if at!=0{let mut named:libc::stat=unsafe{zeroed()};
                if unsafe{libc::fstatat(self.dirs[at-1].as_raw_fd(),self.names[at-1].as_ptr(),&mut named,libc::AT_SYMLINK_NOFOLLOW)}!=0
                    ||named.st_mode&libc::S_IFMT!=libc::S_IFDIR||(FileIdentity{device:named.st_dev,inode:named.st_ino})!=self.ids[at] {
                    return Err("constructor endpoint named ancestor differs".into());}}
        }
        let meta=self.file.metadata().map_err(|e|e.to_string())?;
        if file_id(&self.file)?!=*self.ids.last().ok_or("constructor endpoint file pin absent")?
            ||!meta.file_type().is_socket()||meta.uid()!=self.owner||meta.gid()!=self.group||meta.nlink()!=1||meta.mode()&0o7777!=0o660 {
            return Err("constructor endpoint held socket differs".into());}
        let mut named:libc::stat=unsafe{zeroed()};
        if unsafe{libc::fstatat(self.dirs.last().ok_or("constructor endpoint parent absent")?.as_raw_fd(),
            self.names.last().ok_or("constructor endpoint name absent")?.as_ptr(),&mut named,libc::AT_SYMLINK_NOFOLLOW)}!=0
            ||named.st_mode&libc::S_IFMT!=libc::S_IFSOCK||(FileIdentity{device:named.st_dev,inode:named.st_ino})!=*self.ids.last().ok_or("constructor socket identity absent")? {
            return Err("constructor endpoint named socket differs".into());}
        Ok(())
    }
}

/// Exact kernel-authenticated reserve protocol. Endpoint installation/listener
/// issuance is still required; accepting a supplied stream does not create it.
/// No reset/replace/calibration/invalidate opcode exists on this NORMAL path.
pub(super) struct InstalledUnixConnection {inner:Option<Box<std::mem::ManuallyDrop<InstalledUnixConnectionState>>>}
pub(super) struct InstalledUnixConnectionState {
    socket:InstalledUnixSocket,peer:KernelPeer,endpoint:HeldEndpoint,authority:InstalledChannelAuthority,
    frozen:std::sync::Arc<std::sync::atomic::AtomicBool>,
    pending:Option<[u8;32]>,last_quote_sequence:Option<u64>,elapsed_incarnation:Option<[u8;32]>,
    owner_request:Option<OwnerRequest>,
    original_socket:[u8;24],
    shutdown_result:Option<std::result::Result<(),i32>>,shutdown_was_clean:bool,
}
struct OwnerRequest {frame:[u8;REQUEST],received:usize}
pub(super) enum UnixOwnerIpcStep {Completed,StoppedBeforeOperation}
/// A dropped operation future may have consumed only a request prefix, sent a
/// reply prefix, or completed the durable reservation without acknowledgment.
/// That exact connection cannot be reused. Owner journal history is retained;
/// only a newly authenticated connection may retry the exact operation.
struct InstalledCallLifetime {frozen:std::sync::Arc<std::sync::atomic::AtomicBool>,armed:bool}
impl InstalledCallLifetime {
    fn begin(frozen:&std::sync::Arc<std::sync::atomic::AtomicBool>)->Self {Self{frozen:frozen.clone(),armed:true}}
    fn finished(&mut self,failed:bool){if failed{self.frozen.store(true,std::sync::atomic::Ordering::SeqCst);}self.armed=false;}
}
impl Drop for InstalledCallLifetime {fn drop(&mut self){if self.armed{self.frozen.store(true,std::sync::atomic::Ordering::SeqCst);}}}
impl InstalledUnixConnection {
    pub(super) fn from_installed(socket:UnixStream,authority:InstalledChannelAuthority)->Result<Self> {
        let socket=std::mem::ManuallyDrop::new(socket);
        let mut custody=UnixConnectCustody::new(authority);
        custody.state.as_mut().expect("original supplied connection root").accepted=Some(socket);
        custody.prepare_supplied_connection()?;let connection=custody.publish_connection()?;
        custody.disarm();Ok(connection)
    }
    pub(super) fn close_retained(mut self)->std::result::Result<UnixRetainedClose,std::mem::ManuallyDrop<Self>> {
        if self.close_ready().is_err() || self.endpoint.close_pins.len()!=self.endpoint.dirs.len()+1 {
            return Err(std::mem::ManuallyDrop::new(self));
        }
        let count=match self.endpoint.dirs.len().checked_add(3){Some(n)=>n,None=>return Err(std::mem::ManuallyDrop::new(self))};
        let mut report=match super::native_retained_close::RetainedCloseReport::prepare(count){Ok(r)=>r,
            Err(_)=>return Err(std::mem::ManuallyDrop::new(self))};
        self.frozen.store(true,std::sync::atomic::Ordering::SeqCst);
        let InstalledUnixConnectionState{socket,peer,endpoint,authority,original_socket,..}=
            std::mem::ManuallyDrop::into_inner(*self.inner.take().expect("checked original connection root"));
        let socket=std::mem::ManuallyDrop::new(socket);
        report.file(unsafe{File::from_raw_fd(socket.as_raw_fd())},original_socket);
        report.file(peer.pidfd,peer.original_pidfd);endpoint.close_into(&mut report,None);
        Ok(close_selected(report,authority.guard))
    }
}
impl InstalledUnixConnectionState {
    fn current(&mut self)->Result<()> {
        if self.frozen.load(std::sync::atomic::Ordering::SeqCst) {return Err("installed clock channel frozen".into());}
        let result=self.current_inner();
        if result.is_err(){self.frozen.store(true,std::sync::atomic::Ordering::SeqCst);}
        result
    }
    fn current_inner(&mut self)->Result<()> {
        self.authority.recheck()?;self.peer.recheck(&self.socket)?;
        self.endpoint.recheck(&self.authority)?;
        if retained_socket_identity(self.socket.as_raw_fd())?!=self.original_socket {
            return Err("original installed socket identity changed".into());
        }
        // One immediate, nonconsuming kernel observation; no polling schedule,
        // TTL, byte-consumption inference or new time/qualification authority.
        // RDHUP is refused even when unread bytes would hide EOF from recv.
        let mut probe=libc::pollfd{fd:self.socket.as_raw_fd(),events:libc::POLLIN|libc::POLLRDHUP,revents:0};
        let ready=unsafe{libc::poll(&mut probe,1,0)};
        if ![0,1].contains(&ready) || (ready==0)!=(probe.revents==0)
            || probe.revents & !libc::POLLIN != 0 {
            return Err("installed socket disconnected or current kernel state unknown".into());
        }
        if matches!(self.authority.role,ChannelRole::Consumer) && self.last_quote_sequence.is_some()
            && self.pending.is_none() && probe.revents!=0 {
            return Err("completed installed consumer has unexpected inbound bytes".into());
        }
        self.authority.recheck()
    }
    /// Owner controller only, after the ORIGINAL application body returned or
    /// unwound with this original socket still held. Shutdown revokes the
    /// connected endpoint; it neither closes a descriptor/buffer nor settles
    /// any unknown acquisition, request or acknowledgment outcome.
    pub(super) fn shutdown_after_join(&mut self)->Result<()> {
        if !matches!(self.authority.role,ChannelRole::Owner){return Err("consumer cannot issue owner shutdown".into());}
        if let Some(result)=self.shutdown_result {
            return if result.is_ok() && self.shutdown_was_clean {Ok(())}
                else{Err("original owner socket shutdown failed or prior outcome unknown; no retry".into())};
        }
        self.shutdown_result=Some(Err(-1));
        let before=self.authority.recheck().and_then(|_|self.endpoint.recheck(&self.authority))
            .and_then(|_|if retained_socket_identity(self.socket.as_raw_fd())?==self.original_socket {Ok(())}
                else{Err("original owner socket shutdown identity changed".into())});
        if let Err(error)=before {self.frozen.store(true,std::sync::atomic::Ordering::SeqCst);return Err(error);}
        self.shutdown_was_clean=!self.frozen.load(std::sync::atomic::Ordering::SeqCst)
            && self.pending.is_none() && self.owner_request.is_none();
        let native=unsafe{libc::shutdown(self.socket.as_raw_fd(),libc::SHUT_RDWR)};
        self.shutdown_result=Some(if native==0 {Ok(())} else {Err(io::Error::last_os_error().raw_os_error().unwrap_or(-1))});
        self.frozen.store(true,std::sync::atomic::Ordering::SeqCst);
        if native!=0 || !self.shutdown_was_clean {return Err("original owner shutdown failed or unresolved request retained".into());}
        let after=self.authority.recheck().and_then(|_|self.endpoint.recheck(&self.authority))
            .and_then(|_|self.authority.recheck());
        if after.is_err(){self.shutdown_was_clean=false;}
        after
    }
    fn close_ready(&mut self)->Result<()> {
        if self.shutdown_result==Some(Ok(())) && self.shutdown_was_clean
            && matches!(self.authority.role,ChannelRole::Owner) {
            if self.pending.is_some() || self.owner_request.is_some(){return Err("shut down owner request remains unresolved".into());}
            self.authority.recheck()?;self.endpoint.recheck(&self.authority)?;
            if retained_socket_identity(self.socket.as_raw_fd())?!=self.original_socket {
                return Err("shut down original socket identity changed".into());
            }
            self.authority.recheck()
        }else{self.idle_for_stop()}
    }
    async fn receive_exact(&mut self,data:&mut [u8])->Result<()> {
        let mut at=0;
        while at<data.len() {
            self.current()?;let peer=self.peer.credential;
            let bytes=self.socket.async_io(Interest::READABLE,
                ||recv(self.socket.as_raw_fd(),&mut data[at..],peer)).await.map_err(|e|e.to_string())?;
            if bytes==0 {return Err("installed clock channel disconnected".into());}
            at+=bytes;self.current()?;
        }
        Ok(())
    }
    async fn send_exact(&mut self,data:&[u8])->Result<()> {
        self.send_owner_exact(data,None).await
    }
    async fn send_owner_exact(&mut self,data:&[u8],stop:Option<&super::protected_clock_owner::ProtectedOwnerStop>)->Result<()> {
        use std::future::{Future,poll_fn};use std::task::Poll;
        let mut at=0;
        while at<data.len() {
            self.current()?;
            let mut write=Box::pin(self.socket.async_io(Interest::WRITABLE,||{
                let value=unsafe{libc::send(self.socket.as_raw_fd(),data[at..].as_ptr().cast(),data.len()-at,
                    libc::MSG_DONTWAIT|libc::MSG_NOSIGNAL)};
                if value<0 {Err(io::Error::last_os_error())}else{Ok(value as usize)}
            }));
            let result=poll_fn(|cx| {
                if stop.is_some_and(|stop|stop.poll_stopped(cx).is_ready()){
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted,"owner reply cancelled/unknown; exact operation retained")));
                }
                write.as_mut().poll(cx)
            }).await;
            drop(write);let bytes=result.map_err(|e|e.to_string())?;
            if bytes==0 {return Err("installed clock channel send made no progress".into());}
            at+=bytes;self.current()?;
        }
        Ok(())
    }
    pub(super) async fn serve_one(&mut self,owner:&super::protected_clock_owner::ProtectedOwnerDispatcher)->Result<()> {
        let mut lifetime=InstalledCallLifetime::begin(&self.frozen);
        let result=self.serve_inner(owner,None).await.map(|_|());
        lifetime.finished(result.is_err());result
    }
    pub(super) async fn serve_cancellable(&mut self,owner:&super::protected_clock_owner::ProtectedOwnerDispatcher)
        ->Result<UnixOwnerIpcStep> {
        let stop=owner.stop_handle();
        let mut lifetime=InstalledCallLifetime::begin(&self.frozen);
        let result=self.serve_inner(owner,Some(&stop)).await;
        lifetime.finished(result.is_err());result
    }
    /// CURRENT-only idle shutdown, with no live engine reading or new floor.
    /// The same actual owner's stop_checked result is combined by application.
    pub(super) fn idle_for_stop(&mut self)->Result<()> {
        if self.pending.is_some() || self.owner_request.is_some(){return Err("owner UNIX request remains unresolved".into());}
        self.current()
    }
    async fn receive_owner_request(&mut self,stop:Option<&super::protected_clock_owner::ProtectedOwnerStop>)
        ->Result<UnixOwnerIpcStep> {
        use std::future::{Future,poll_fn};use std::task::Poll;
        if self.pending.is_some() || self.owner_request.is_some(){return Err("prior owner UNIX request unresolved".into());}
        self.owner_request=Some(OwnerRequest{frame:[0;REQUEST],received:0});
        loop {
            self.current()?;let peer=self.peer.credential;
            let request=self.owner_request.as_mut().ok_or("retained owner frame absent")?;
            if request.received==REQUEST{return Ok(UnixOwnerIpcStep::Completed);}
            let mut read=Box::pin(self.socket.async_io(Interest::READABLE,
                ||recv(self.socket.as_raw_fd(),&mut request.frame[request.received..],peer)));
            let result=poll_fn(|cx| {
                // Stop is observed before any new syscall. Dropping a pending
                // readiness future retains no kernel-owned Rust buffer.
                if stop.is_some_and(|stop|stop.poll_stopped(cx).is_ready()){
                    return Poll::Ready(None);
                }
                match read.as_mut().poll(cx){Poll::Pending=>Poll::Pending,
                    Poll::Ready(result)=>Poll::Ready(Some(result))}
            }).await;
            drop(read);
            match result {
                None=>{
                    if request.received!=0{return Err("cancelled UNIX owner prefix unknown; exact bytes retained".into());}
                    // The zero-prefix state is known from THIS original owned
                    // receive, never inferred from a cancellation alone.
                    self.owner_request=None;self.idle_for_stop()?;
                    return Ok(UnixOwnerIpcStep::StoppedBeforeOperation);
                },
                Some(Err(error))=>return Err(format!("owner UNIX native receive: {error}")),
                Some(Ok(0))=>return Err("owner UNIX peer disconnected; exact frame retained".into()),
                Some(Ok(bytes))=>request.received=request.received.checked_add(bytes).filter(|n|*n<=REQUEST)
                    .ok_or("owner UNIX received length overflow")?,
            }
            self.current()?;
        }
    }
    async fn serve_inner(&mut self,owner:&super::protected_clock_owner::ProtectedOwnerDispatcher,
        stop:Option<&super::protected_clock_owner::ProtectedOwnerStop>)->Result<UnixOwnerIpcStep> {
        if !matches!(self.authority.role,ChannelRole::Owner) {return Err("consumer cannot dispatch owner operations".into());}
        // Bind the actual live owner before waiting, then retain its SAME weak
        // cancellation observer for the original request only.
        if owner.channel_context()?!=self.authority.context{return Err("UNIX owner dispatcher context differs".into());}
        if matches!(self.receive_owner_request(stop).await?,UnixOwnerIpcStep::StoppedBeforeOperation){
            return Ok(UnixOwnerIpcStep::StoppedBeforeOperation);
        }
        let frame=self.owner_request.as_ref().ok_or("owner exact frame absent")?.frame;
        if &frame[..8]!=MAGIC || ![1,2,4].contains(&frame[8]) || frame[9..41]==[0;32]
            || frame[41..73]!=self.authority.context || owner.channel_context()?!=self.authority.context {
            return Err("installed clock operation/context refused".into());
        }
        let identity:[u8;32]=frame[9..41].try_into().map_err(|_|"channel identity length")?;
        let operation=super::protected_clock_lineage_v1::Operation::authenticated_document(identity,Sha256::digest(frame).into())
            .map_err(|_|"channel operation commitment refused")?;
        let expected=u64::from_be_bytes(frame[73..81].try_into().map_err(|_|"channel sequence length")?);
        self.current()?;
        // Retain the exact authenticated identity BEFORE any irreversible
        // owner journal/head transition. Lost reply never clears this record.
        self.pending=Some(identity);
        if frame[8]==4 {
            if expected!=0{return Err("fresh caller may not supply owner counter".into());}
            let reply=owner.fresh_selected_operation(operation)?;
            self.current()?;
            if owner.channel_context()?!=self.authority.context{return Err("fresh owner context changed".into());}
            self.send_owner_exact(&reply.encode(self.authority.context)?,stop).await?;
            self.current()?;
            if owner.channel_context()?!=self.authority.context{return Err("fresh UNIX owner revoked during acknowledgment".into());}
            self.pending=None;self.owner_request=None;return Ok(UnixOwnerIpcStep::Completed);
        }
        let reply=owner.reserve_operation(expected,operation)?;
        self.current()?;
        if owner.channel_context()?!=self.authority.context {return Err("owner context changed after durable reserve".into());}
        let mut response=[0u8;89];response[..8].copy_from_slice(b"MCLCIPR1");
        response[8..40].copy_from_slice(&identity);response[40..72].copy_from_slice(&self.authority.context);
        response[72..80].copy_from_slice(&reply.sequence.to_be_bytes());response[80..88].copy_from_slice(&reply.floor.to_be_bytes());
        response[88]=u8::from(reply.qualified);
        self.send_owner_exact(&response,stop).await?;self.current()?;
        if owner.channel_context()?!=self.authority.context{return Err("UNIX owner revoked during acknowledgment".into());}
        self.pending=None;self.owner_request=None;Ok(UnixOwnerIpcStep::Completed)
    }
    pub(super) async fn reserve(&mut self,operation:[u8;32],expected_sequence:u64)
        ->Result<super::protected_clock_owner::ReservedReply> {
        let mut lifetime=InstalledCallLifetime::begin(&self.frozen);
        let result=self.reserve_inner(operation,expected_sequence).await;
        lifetime.finished(result.is_err());result
    }
    async fn reserve_inner(&mut self,operation:[u8;32],expected_sequence:u64)
        ->Result<super::protected_clock_owner::ReservedReply> {
        if !matches!(self.authority.role,ChannelRole::Consumer) || operation==[0;32] {
            return Err("installed consumer reservation refused".into());
        }
        let mut frame=[0;REQUEST];frame[..8].copy_from_slice(MAGIC);frame[8]=2;
        frame[9..41].copy_from_slice(&operation);frame[41..73].copy_from_slice(&self.authority.context);
        frame[73..81].copy_from_slice(&expected_sequence.to_be_bytes());
        self.send_exact(&frame).await?;
        let mut response=[0;89];self.receive_exact(&mut response).await?;
        if &response[..8]!=b"MCLCIPR1" || response[8..40]!=operation || response[40..72]!=self.authority.context
            || response[88]>1 {return Err("installed owner response binding refused".into());}
        self.current()?;
        let sequence=u64::from_be_bytes(response[72..80].try_into().map_err(|_|"response sequence length")?);
        if expected_sequence.checked_add(1)!=Some(sequence) {return Err("installed owner exact operation sequence differs".into());}
        Ok(super::protected_clock_owner::ReservedReply{
            sequence,
            floor:u64::from_be_bytes(response[80..88].try_into().map_err(|_|"response floor length")?),qualified:response[88]==1})
    }
    async fn fresh_query(&mut self,operation:[u8;32])->Result<FreshUnixReply> {
        let mut lifetime=InstalledCallLifetime::begin(&self.frozen);
        let result=self.fresh_query_inner(operation).await;
        lifetime.finished(result.is_err());result
    }
    async fn fresh_query_inner(&mut self,operation:[u8;32])->Result<FreshUnixReply> {
        self.current()?;
        if !matches!(self.authority.role,ChannelRole::Consumer) || operation==[0;32] || self.pending.is_some() {
            return Err("fresh installed consumer already pending/invalid".into());
        }
        let mut frame=[0u8;REQUEST];frame[..8].copy_from_slice(MAGIC);frame[8]=4;
        frame[9..41].copy_from_slice(&operation);frame[41..73].copy_from_slice(&self.authority.context);
        // Record identity before the first potentially partial write. Timeouts
        // and cancellation are unknown; no request counter/reset/TTL exists.
        self.pending=Some(operation);self.send_exact(&frame).await?;
        let mut response=[0u8;775];self.receive_exact(&mut response).await?;
        if &response[..8]!=b"MCLCFQR2" || response[8..40]!=operation || response[40..72]!=self.authority.context
            || response[96]>1 || response[97]>1 || response[186..194]!=[0;8] {
            return Err("fresh UNIX exact response binding refused".into());
        }
        let sequence=u64::from_be_bytes(response[72..80].try_into().map_err(|_|"fresh sequence length")?);
        let current=u64::from_be_bytes(response[88..96].try_into().map_err(|_|"fresh current sequence length")?);
        let length=u16::from_be_bytes(response[194..196].try_into().map_err(|_|"fresh head length")?) as usize;
        if sequence==0 || current<=sequence || length==0 || length>579
            || response[196+length..].iter().any(|v|*v!=0)
            || (response[97]==0 && response[98..186].iter().any(|v|*v!=0))
            || (response[96]==1 && response[97]!=1) {return Err("fresh UNIX canonical shape refused".into());}
        self.current()?;
        // Keep pending through the immediate CURRENT importer as well: no raw
        // authenticated bytes/eligible bit supply a qualified delivery.
        Ok(FreshUnixReply{frame:response,operation})
    }
    fn prepare_fresh(&mut self,reply:&FreshUnixReply)->Result<UnixFreshDelivery> {
        let mut lifetime=InstalledCallLifetime::begin(&self.frozen);
        let result=self.prepare_fresh_inner(reply,false);lifetime.finished(result.is_err());result
    }
    fn recheck_fresh(&mut self,reply:&FreshUnixReply)->Result<UnixFreshDelivery> {
        let mut lifetime=InstalledCallLifetime::begin(&self.frozen);
        let result=self.prepare_fresh_inner(reply,true);lifetime.finished(result.is_err());result
    }
    fn prepare_fresh_inner(&mut self,reply:&FreshUnixReply,recheck:bool)->Result<UnixFreshDelivery> {
        self.current()?;let raw=&reply.frame;
        if (if recheck {self.pending.is_some()} else {self.pending!=Some(reply.operation)}) || &raw[..8]!=b"MCLCFQR2" || raw[8..40]!=reply.operation
            || raw[40..72]!=self.authority.context {return Err("fresh UNIX importer binding refused".into());}
        let number=|start:usize|->Result<u64>{Ok(u64::from_be_bytes(raw[start..start+8].try_into()
            .map_err(|_|"fresh UNIX integer length")?))};
        let operation_sequence=number(72)?;let floor=number(80)?;let current_sequence=number(88)?;
        if operation_sequence==0 || current_sequence<=operation_sequence
            || (if recheck {self.last_quote_sequence!=Some(current_sequence)} else {self.last_quote_sequence.is_some_and(|old|current_sequence<=old)}) {
            return Err("fresh UNIX quote sequence replay/regression".into());
        }
        let length=u16::from_be_bytes(raw[194..196].try_into().map_err(|_|"fresh UNIX head length")?) as usize;
        if length==0 || length>579{return Err("fresh UNIX protected head bound".into());}
        let document=super::protected_clock_lineage_v1::DocumentaryEngine::from_document(
            &self.authority.scope,&raw[196..196+length]).map_err(|e|format!("fresh UNIX head scope: {e:?}"))?;
        if document.frozen() || document.sequence()!=current_sequence || document.floor()<floor {
            return Err("fresh UNIX head/outcome dominance".into());
        }
        let record=document.protected_record(&self.authority.binding).map_err(|e|format!("fresh UNIX head binding: {e:?}"))?;
        let mut available=None;let mut elapsed=None;
        if raw[96]==1 && raw[97]==1 {
            let record=record.ok_or("fresh UNIX eligible quote lacks checkpoint")?;
            let backend=super::native_nts_backend::NativeNtsBackend::for_protected_owner(&self.authority.record)?;
            backend.clock().ratchet_high_water(document.floor());
            let eligible_now=backend.assess_consumer_record(record)?;
            let native=mutiny_clock_native_nts_v1::capture_elapsed_interval(
                self.authority.record.record().acquisition().bounds.maximum_sampling_span_ns)
                .ok_or("fresh UNIX consumer native interval unavailable")?;
            let boot=u128::from_be_bytes(raw[130..146].try_into().map_err(|_|"fresh UNIX boot length")?);
            let drift=number(146)?;let incarnation:[u8;32]=raw[154..186].try_into().map_err(|_|"fresh UNIX incarnation length")?;
            if number(98)?>number(106)? || number(114)?>number(122)? || native.boot_id()!=boot
                || record.checkpoint().anchor().at.boot_id!=boot
                || drift!=self.authority.record.record().profile().drift_bound_ppb || incarnation==[0;32]
                || self.elapsed_incarnation.is_some_and(|old|old!=incarnation)
                || native.inclusive_upper_ns()<number(98)? || native.active_upper_ns()<number(114)? {
                return Err("fresh UNIX elapsed/profile/incarnation changed".into());
            }
            self.current()?;
            // Owner sample precedes its checkpoint write. Only this genuine
            // current consumer sample and original-age reconstruction account
            // for elapsed delivery delay. Return ONLY the reserved external
            // floor, never locally derived UTC or cached qualification.
            if eligible_now && backend.clock().lower_bound_ms().is_some_and(|lower|lower>=floor) {
                available=Some(floor);elapsed=Some(mutiny_consensus_v8::activation_attestation_v1::ElapsedCapture::from_current_owner(
                    std::time::Duration::from_nanos(native.inclusive_lower_ns()),
                    std::time::Duration::from_nanos(native.inclusive_upper_ns()),boot,incarnation,drift)
                    .map_err(|_|"fresh UNIX opaque elapsed interval refused")?);
            }
            self.elapsed_incarnation=Some(incarnation);
        }
        self.current()?;self.last_quote_sequence=Some(current_sequence);self.pending=None;
        Ok(UnixFreshDelivery{floor:available,elapsed})
    }
}

struct FreshUnixReply {frame:[u8;775],operation:[u8;32]}
struct UnixFreshDelivery {floor:Option<u64>,elapsed:Option<mutiny_consensus_v8::activation_attestation_v1::ElapsedCapture>}
/// Owned asynchronous kernel-readiness route. All I/O syscalls are nonblocking
/// and completed before returning from each poll; no kernel receives a buffer
/// after its future is dropped. No actor/UI wait, polling interval or deadline.
/// Abandonment freezes and retains the entire socket/peer/installed guard.
pub(super) struct InstalledUnixFreshConsumer {inner:Option<Box<InstalledUnixConnection>>}
impl Drop for InstalledUnixFreshConsumer {
    fn drop(&mut self){if let Some(connection)=self.inner.take(){
        connection.frozen.store(true,std::sync::atomic::Ordering::SeqCst);let _custody=Box::into_raw(connection);}}
}
pub(super) struct PreparedUnixFreshAttempt {consumer:InstalledUnixFreshConsumer,receipt:FreshUnixReply}
pub(super) struct UnixPreparedRetainedClose {
    native:Option<UnixRetainedClose>,attempt:Option<std::mem::ManuallyDrop<PreparedUnixFreshAttempt>>,
    connection:Option<std::mem::ManuallyDrop<InstalledUnixConnection>>,
}
impl UnixPreparedRetainedClose {pub(super) fn retained_handles_closed(&self)->bool {
    self.attempt.is_none()&&self.connection.is_none()&&self.native.as_ref().is_some_and(|r|r.retained_handles_closed())
}}
impl InstalledUnixFreshConsumer {
    /// Idle shutdown on the original owning executor; no fresh clock request.
    pub(super) fn close_idle_retained(mut self)->UnixPreparedRetainedClose {
        let mut report=UnixPreparedRetainedClose{native:None,attempt:None,connection:None};
        let ready=self.inner.as_mut().ok_or_else(||"idle UNIX consumer absent".to_string())
            .and_then(|connection|connection.idle_for_stop());
        if ready.is_err(){
            if let Some(connection)=self.inner.take(){report.connection=Some(std::mem::ManuallyDrop::new(*connection));}
            return report;
        }
        let connection=self.inner.take().expect("checked original idle UNIX consumer");
        match (*connection).close_retained(){Ok(native)=>report.native=Some(native),
            Err(connection)=>report.connection=Some(connection)};
        report
    }
    // Root ownership synchronously, including cancellation of a never-polled
    // future. This connector returns no raw native/socket/authority capability.
    pub(super) fn connect(authority:InstalledChannelAuthority)->impl std::future::Future<Output=Result<Self>> {
        UnixConnectCustody::new(authority).acquire()
    }
    pub(super) async fn prepare_attempt(mut self)->Result<PreparedUnixFreshAttempt> {
        let mut identity=[0u8;32];getrandom::getrandom(&mut identity).map_err(|_|"fresh UNIX request identity unavailable")?;
        if identity==[0;32]{return Err("fresh UNIX request identity refused".into());}
        let connection=self.inner.as_mut().ok_or("fresh UNIX consumer absent")?;
        let reply=connection.fresh_query(identity).await?;
        connection.prepare_fresh(&reply)?;
        Ok(PreparedUnixFreshAttempt{consumer:self,receipt:reply})
    }
}
impl PreparedUnixFreshAttempt {
    /// Consumes only a known completed receipt after the original private
    /// worker joined. No new RPC, time reconstruction, floor or state reset.
    pub(super) fn close_retained(mut self)->UnixPreparedRetainedClose {
        let mut report=UnixPreparedRetainedClose{native:None,attempt:None,connection:None};
        let ready=self.consumer.inner.as_mut().ok_or_else(||"prepared UNIX consumer absent".to_string())
            .and_then(|connection|connection.idle_for_stop());
        if ready.is_err(){report.attempt=Some(std::mem::ManuallyDrop::new(self));return report;}
        let connection=self.consumer.inner.take().expect("checked original UNIX connection");
        // Any native/current failure retains the complete original connection.
        // The outer consumer is now empty and has no second close obligation.
        match (*connection).close_retained(){Ok(native)=>report.native=Some(native),
            Err(connection)=>report.connection=Some(connection)};
        report
    }
    pub(super) fn recheck_installed_only(&mut self)->Result<()> {
        let consumer=self.consumer.inner.as_mut().ok_or("prepared UNIX consumer absent")?;
        if consumer.frozen.load(std::sync::atomic::Ordering::SeqCst){return Err("prepared UNIX consumer frozen".into());}
        consumer.current()
    }
    pub(super) fn capture_current(&mut self)->Result<Option<mutiny_consensus_v8::activation_attestation_v1::ElapsedCapture>> {
        let delivery=self.consumer.inner.as_mut().ok_or("prepared UNIX consumer absent")?
            .recheck_fresh(&self.receipt)?;
        Ok(delivery.elapsed)
    }
    /// Recheck the exact opaque receipt against CURRENT native state at gate use.
    /// A subsequent attempt always requires another authenticated operation.
    pub(super) fn reading(&mut self)->Result<mutiny_consensus_v8::vote_clock_v1::ClockReading> {
        let delivery=self.consumer.inner.as_mut().ok_or("prepared UNIX consumer absent")?
            .recheck_fresh(&self.receipt)?;
        Ok(match delivery.floor {Some(floor)=>mutiny_consensus_v8::vote_clock_v1::ClockReading::Qualified{utc_seconds:floor/1000},
            None=>mutiny_consensus_v8::vote_clock_v1::ClockReading::Unqualified})
    }
    /// The opaque interval is for this one immediate attempt only. It does not
    /// implement a reusable Elapsed trait or refresh original calibration age.
    pub(super) fn into_parts(mut self)->Result<(InstalledUnixFreshConsumer,Option<mutiny_consensus_v8::activation_attestation_v1::ElapsedCapture>)>{
        let delivery=self.consumer.inner.as_mut().ok_or("prepared UNIX consumer absent")?
            .recheck_fresh(&self.receipt)?;
        Ok((self.consumer,delivery.elapsed))
    }
}

const REQUEST:usize=81;
const MAGIC:&[u8;8]=b"MCLCIPC1";
type Result<T>=std::result::Result<T,String>;
#[derive(Clone,Copy,PartialEq,Eq)]
struct Cred {pid:i32,uid:u32,gid:u32}
impl Cred {
    fn from(value:libc::ucred)->Self {Self{pid:value.pid,uid:value.uid,gid:value.gid}}
}
#[derive(Clone,Copy,PartialEq,Eq)]
struct FileIdentity {device:u64,inode:u64}
fn file_id(file:&File)->Result<FileIdentity> {
    let value=file.metadata().map_err(|e|e.to_string())?;
    Ok(FileIdentity{device:value.dev(),inode:value.ino()})
}
fn bounded(file:&mut File,limit:u64)->Result<Vec<u8>> {
    let mut bytes=Vec::new();file.take(limit+1).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
    if bytes.len() as u64>limit {return Err("peer public fact read bound".into());}Ok(bytes)
}
fn public_file(path:&std::path::Path)->Result<File> {
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC)
        .open(path).map_err(|e|e.to_string())
}
fn fact(root:&std::path::Path,name:&str)->Result<Vec<u8>> {
    bounded(&mut public_file(&root.join(name))?,16384)
}
fn start(root:&std::path::Path,pid:i32)->Result<u64> {
    let raw=fact(root,"stat")?;let raw=std::str::from_utf8(&raw).map_err(|_|"peer stat encoding")?;
    let suffix=raw.rsplit_once(')').ok_or("peer stat structure")?.1;
    if raw.split_once(' ').ok_or("peer pid format")?.0.parse::<i32>().map_err(|_|"peer pid")?!=pid {
        return Err("peer process identity differs".into());
    }
    // suffix starts at field3; field22 is index19.
    suffix.split_whitespace().nth(19).ok_or("peer start missing")?
        .parse().map_err(|_|"peer start format".into())
}
fn status(root:&std::path::Path,credential:Cred)->Result<()> {
    let raw=fact(root,"status")?;let raw=std::str::from_utf8(&raw).map_err(|_|"peer status encoding")?;
    for (field,expected) in [("Uid:",credential.uid),("Gid:",credential.gid)] {
        let line=raw.lines().find(|v|v.starts_with(field)).ok_or("peer token field missing")?;
        let values=line.split_whitespace().skip(1).map(|v|v.parse::<u32>()).collect::<std::result::Result<Vec<_>,_>>()
            .map_err(|_|"peer token encoding")?;
        if values.len()!=4 || values.iter().any(|v|*v!=expected){return Err("peer token identities changed".into());}
    }
    for field in ["CapInh:","CapPrm:","CapEff:","CapAmb:"] {
        let value=raw.lines().find_map(|v|v.strip_prefix(field)).ok_or("peer capability facts missing")?;
        if u64::from_str_radix(value.trim(),16).map_err(|_|"peer capability format")?!=0 {
            return Err("privileged peer refused".into());
        }
    }
    Ok(())
}

/// Current process proof is not code/configuration qualification. Complete
/// loaded-code facts must be supplied by the selected installed validator; this
/// primitive deliberately cannot construct a production clock capability.
struct Peer {
    credential:Cred,start:u64,pidfd:File,proc:File,proc_id:FileIdentity,
    namespaces:Vec<(&'static str,File,FileIdentity)>,
}
impl Peer {
    fn capture(credential:Cred)->Result<Self> {
        if credential.pid<=0 || credential.uid==0 {return Err("ordinary pinned peer required".into());}
        let pidfd=unsafe{libc::syscall(libc::SYS_pidfd_open,credential.pid,0)};
        if pidfd<0 {return Err(io::Error::last_os_error().to_string());}
        let pidfd=unsafe{File::from_raw_fd(pidfd as i32)};
        let root=PathBuf::from(format!("/proc/{}",credential.pid));
        let proc=std::fs::OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)
            .open(&root).map_err(|e|e.to_string())?;
        let at=start(&root,credential.pid)?;status(&root,credential)?;
        let mut namespaces=Vec::new();
        for name in ["pid","mnt","user","net"] {
            // /proc namespace magic links must be followed to retain the exact
            // namespace object. No general filesystem link is accepted here.
            let file=File::open(root.join("ns").join(name)).map_err(|e|e.to_string())?;
            namespaces.push((name,file.try_clone().map_err(|e|e.to_string())?,file_id(&file)?));
        }
        let peer=Self{credential,start:at,proc_id:file_id(&proc)?,proc,pidfd,namespaces};
        peer.recheck()?;Ok(peer)
    }
    fn recheck(&self)->Result<()> {
        let mut poll=libc::pollfd{fd:self.pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
        if unsafe{libc::poll(&mut poll,1,0)}!=0 {return Err("peer exited or pidfd facts unavailable".into());}
        let root=PathBuf::from(format!("/proc/{}",self.credential.pid));
        let named=public_file(&root)?;
        if file_id(&named)?!=self.proc_id || file_id(&self.proc)?!=self.proc_id
            || start(&root,self.credential.pid)?!=self.start {return Err("peer process recycled".into());}
        status(&root,self.credential)?;
        for (name,held,id) in &self.namespaces {
            if file_id(held)?!=*id || file_id(&File::open(root.join("ns").join(name)).map_err(|e|e.to_string())?)?!=*id {
                return Err("peer namespace changed".into());
            }
        }
        Ok(())
    }
}
pub(super) enum Method {Status,Read,Invalidate}
pub(super) struct AuthenticatedRequest {
    pub(super) method:Method,pub(super) operation:[u8;32],
    pub(super) context:[u8;32],pub(super) expected_sequence:u64,
    pub(super) commitment:[u8;32],
}
pub(super) struct NativeUnixConnection {
    socket:UnixStream,peer:Peer,context:[u8;32],frozen:bool,
}
impl NativeUnixConnection {
    // TEST-only setup route until an opaque installed peer/code/channel issuer
    // exists. Captured credentials alone are not normal installation authority.
    #[cfg(test)]
    pub(super) fn capture_test(socket:UnixStream,expected_uid:u32,expected_gid:u32,
        context:[u8;32])->Result<Self> {
        let mut credential:libc::ucred=unsafe{zeroed()};let mut length=size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe{libc::getsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),&mut length)}!=0
            || length as usize!=size_of::<libc::ucred>() {return Err("kernel connection credentials unavailable".into());}
        if credential.uid!=expected_uid || credential.gid!=expected_gid || context==[0;32] {
            return Err("wrong selected TEST peer/context".into());
        }
        let enabled:i32=1;
        if unsafe{libc::setsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PASSCRED,
            (&enabled as *const i32).cast(),size_of::<i32>() as libc::socklen_t)}!=0 {
            return Err("per-message kernel credentials unavailable".into());
        }
        Ok(Self{peer:Peer::capture(Cred::from(credential))?,socket,context,frozen:false})
    }
    pub(super) async fn request(&mut self)->Result<AuthenticatedRequest> {
        let result=self.request_inner().await;
        if result.is_err(){self.frozen=true;}result
    }
    async fn request_inner(&mut self)->Result<AuthenticatedRequest> {
        if self.frozen {return Err("clock channel frozen".into());}
        let mut frame=[0u8;REQUEST];let mut offset=0;
        while offset<frame.len() {
            self.peer.recheck()?;
            let peer=self.peer.credential;
            let read=self.socket.async_io(Interest::READABLE,
                ||recv(self.socket.as_raw_fd(),&mut frame[offset..],peer)).await.map_err(|e|e.to_string())?;
            if read==0 {return Err("clock channel disconnected".into());}
            offset+=read;self.peer.recheck()?;
        }
        if &frame[..8]!=MAGIC || frame[9..41]==[0;32] || frame[41..73]!=self.context {
            return Err("clock channel request binding/format refused".into());
        }
        let method=match frame[8] {1=>Method::Status,2=>Method::Read,3=>Method::Invalidate,_=>return Err("clock channel opcode refused".into())};
        Ok(AuthenticatedRequest{method,operation:frame[9..41].try_into().map_err(|_|"operation length")?,
            context:self.context,expected_sequence:u64::from_be_bytes(frame[73..81].try_into().map_err(|_|"sequence length")?),
            commitment:Sha256::digest(frame).into()})
    }
}

fn recv(fd:i32,data:&mut [u8],peer:Cred)->io::Result<usize> {
    let mut control=[0usize;64];let mut iov=libc::iovec{iov_base:data.as_mut_ptr().cast(),iov_len:data.len()};
    let mut message:libc::msghdr=unsafe{zeroed()};message.msg_iov=&mut iov;message.msg_iovlen=1;
    message.msg_control=control.as_mut_ptr().cast();message.msg_controllen=size_of::<[usize;64]>();
    let bytes=unsafe{libc::recvmsg(fd,&mut message,libc::MSG_DONTWAIT|libc::MSG_CMSG_CLOEXEC)};
    if bytes<0 {return Err(io::Error::last_os_error());}
    let mut valid=None;let mut close_unknown=false;
    let mut refused=message.msg_flags&(libc::MSG_TRUNC|libc::MSG_CTRUNC)!=0;
    let mut cmsg=unsafe{libc::CMSG_FIRSTHDR(&message)};
    while !cmsg.is_null() {
        let header=unsafe{&*cmsg};
        if header.cmsg_level==libc::SOL_SOCKET && header.cmsg_type==libc::SCM_CREDENTIALS
            && header.cmsg_len==unsafe{libc::CMSG_LEN(size_of::<libc::ucred>() as u32)} as usize && valid.is_none() {
            valid=Some(Cred::from(unsafe{std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::ucred>())}));
        } else {
            refused=true;
            if header.cmsg_level==libc::SOL_SOCKET && header.cmsg_type==libc::SCM_RIGHTS {
                let header_bytes=unsafe{libc::CMSG_LEN(0)} as usize;
                let length=header.cmsg_len.checked_sub(header_bytes).unwrap_or(0)/size_of::<i32>();
                for index in 0..length {
                    let received=unsafe{std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<i32>().add(index))};
                    // Unexpected received descriptors are never authority; no
                    // close retry against a possibly kernel-reused descriptor.
                    if unsafe{libc::close(received)}!=0 {close_unknown=true;}
                }
            }
        }
        cmsg=unsafe{libc::CMSG_NXTHDR(&message,cmsg)};
    }
    if close_unknown {return Err(io::Error::other("unexpected descriptor close uncertain; all received closes attempted"));}
    if refused || valid!=Some(peer) {return Err(io::Error::other("current kernel sender credentials refused"));}
    Ok(bytes as usize)
}
