//! Private existing-named selected custom-provider ABI. This is native storage
//! ownership, not a physical TPM/clock/provider qualification issuer.
#![cfg(target_os="linux")]
use super::hybrid_installed_databases_v2::SelectedExistingDatabase;
use rusqlite::{Connection,OpenFlags,ffi};
use std::{ffi::{c_char,c_int,c_void,CString},mem::ManuallyDrop,ptr};
const MAX_CLOSE_RECORDS:usize=66;
#[repr(C)]
#[derive(Clone,Copy,Default)]
struct CloseRecord{sequence:u64,device:u64,inode:u64,kind:c_int,original_fd:c_int,
    identity_known:c_int,native_attempted:c_int,native_complete:c_int,native_result:c_int,
    native_errno:c_int,deferred:c_int}
#[repr(C)]
struct CloseReport{version:c_int,bytes:c_int,result:c_int,released:c_int,unknown:c_int,deferred:c_int,
    close_started:c_int,live_files:c_int,record_count:c_int,records:[CloseRecord;MAX_CLOSE_RECORDS]}
impl Default for CloseReport{fn default()->Self{Self{version:0,bytes:0,result:0,released:0,unknown:0,
    deferred:0,close_started:0,live_files:0,record_count:0,records:[CloseRecord::default();MAX_CLOSE_RECORDS]}}}
unsafe extern "C"{
    fn mutiny_sqlite_protected_session_existing_named(parent:*const c_char,name:*const c_char,
        cap:i64,readonly:c_int,out:*mut *mut c_void)->c_int;
    fn mutiny_sqlite_protected_session_register(session:*mut c_void,name:*mut *const c_char)->c_int;
    fn mutiny_sqlite_protected_session_database(session:*mut c_void)->*const c_char;
    fn mutiny_sqlite_protected_session_status(session:*mut c_void)->c_int;
    fn mutiny_sqlite_protected_session_named_close_report(session:*mut c_void,report:*mut CloseReport)->c_int;
    fn mutiny_sqlite_protected_session_named_close_once(session:*mut c_void,report:*mut CloseReport)->c_int;
}
struct State{session:*mut c_void,report:CloseReport,failed_connection:Option<ManuallyDrop<Connection>>,close_called:bool,frozen:bool,path:Option<CString>,capacity:i64,readonly:bool,
    _not_send_sync:std::marker::PhantomData<std::rc::Rc<()>>}
pub(crate) struct NativeExistingDatabase{state:ManuallyDrop<Box<State>>}
pub(crate) struct OpenedExistingDatabase{
    pub(super) owner:ManuallyDrop<NativeExistingDatabase>,
    pub(super) connection:ManuallyDrop<Connection>,
}
pub(crate) struct NativeDatabaseRefusal{cause:String,owner:ManuallyDrop<NativeExistingDatabase>}
impl NativeDatabaseRefusal{
    pub(crate) fn cause(&self)->&str{&self.cause}
    pub(crate) fn into_retained(self)->(String,ManuallyDrop<NativeExistingDatabase>){(self.cause,self.owner)}
}
/// Opaque observations only. Complete means the actual selected ABI reported
/// known once-only cleanup, including the inode deferred-ownership condition.
pub(crate) struct NativeDatabaseClosed{report:CloseReport}
impl NativeDatabaseClosed{
    pub(crate) fn retained_handles_closed(&self)->bool{complete(&self.report)}
}
fn complete(r:&CloseReport)->bool{
    if r.version!=1||r.bytes as usize!=std::mem::size_of::<CloseReport>()
        ||r.result!=ffi::SQLITE_OK||r.released!=1||r.unknown!=0||r.deferred!=0
        ||r.close_started!=1||r.live_files!=0||!(0..=MAX_CLOSE_RECORDS as c_int).contains(&r.record_count){return false;}
    r.records[..r.record_count as usize].iter().all(|v|{
        if v.original_fd<0{return v.original_fd==-1&&v.identity_known==0&&v.native_attempted==0
            &&v.native_complete==0&&v.deferred==0;}
        v.identity_known==1&&v.native_attempted==1&&v.native_complete==1
            &&v.native_result==0&&v.native_errno==0&&v.deferred==0&&(0..=2).contains(&v.kind)
    })
}
unsafe fn bounded_native_name(raw:*const c_char)->Result<CString,String>{
    if raw.is_null(){return Err("selected VFS name unavailable".into());}
    let mut bytes=Vec::with_capacity(256);
    for n in 0..256{let b=unsafe{*raw.add(n)} as u8;
        if b==0{return if bytes.is_empty(){Err("selected VFS empty name".into())}
            else{CString::new(bytes).map_err(|_|"selected VFS name NUL".into())};}
        if !b.is_ascii()||b.is_ascii_control(){return Err("selected VFS name character".into());}bytes.push(b);
    }Err("selected VFS name bound".into())
}
impl NativeExistingDatabase{
    pub(crate) fn open(request:&SelectedExistingDatabase<'_>,readonly:bool)
        ->Result<OpenedExistingDatabase,NativeDatabaseRefusal>{
        // Box, exact report and out-pointer storage precede the first C/native
        // acquisition. The C implementation publishes a session BEFORE opens.
        let mut owner=Self{state:ManuallyDrop::new(Box::new(State{session:ptr::null_mut(),report:Default::default(),failed_connection:None,
            close_called:false,frozen:true,path:None,capacity:request.capacity(),readonly,_not_send_sync:std::marker::PhantomData}))};
        let prepared=(||->Result<Connection,String>{
            if request.capacity()<=0{return Err("selected existing database capacity refused".into());}
            let name=CString::new(request.name()).map_err(|_|"selected database basename")?;
            if !["canonical.sqlite","counter.sqlite"].contains(&request.name()){
                return Err("selected database basename refused".into());}
            let rc=unsafe{mutiny_sqlite_protected_session_existing_named(request.parent().as_ptr(),name.as_ptr(),
                request.capacity(),readonly as c_int,&mut owner.state.session)};
            if rc!=ffi::SQLITE_OK||owner.state.session.is_null(){return Err(format!("existing named native constructor refused {rc}"));}
            let mut native_name=ptr::null();
            let rc=unsafe{mutiny_sqlite_protected_session_register(owner.state.session,&mut native_name)};
            if rc!=ffi::SQLITE_OK{return Err(format!("selected existing VFS register refused {rc}"));}
            let vfs=unsafe{bounded_native_name(native_name)}?;
            // The expected path is issued by the held installed selection.
            // Compare the private C accessor to these exact bytes, not a new
            // caller-selected filename or unbounded native CStr allocation.
            let mut expected=request.parent().as_bytes().to_vec();expected.push(b'/');expected.extend(name.as_bytes());
            let native_path=unsafe{mutiny_sqlite_protected_session_database(owner.state.session)};
            if native_path.is_null(){return Err("selected native database path absent".into());}
            for(i,b)in expected.iter().copied().chain(std::iter::once(0)).enumerate(){
                if unsafe{*native_path.add(i)} as u8!=b{return Err("selected native database path differs".into());}
            }
            owner.state.path=Some(CString::new(expected).map_err(|_|"installed database path NUL")?);
            let path=std::path::Path::new(owner.state.path.as_ref().ok_or("same native path absent")?
                .to_str().map_err(|_|"installed database path UTF8")?);
            let flags=(if readonly{OpenFlags::SQLITE_OPEN_READ_ONLY}else{OpenFlags::SQLITE_OPEN_READ_WRITE})
                |OpenFlags::SQLITE_OPEN_NO_MUTEX;
            // Existing-only C VFS owns actual main/journal descriptors before
            // SQLite validation. No SQLITE_OPEN_CREATE or registry fallback.
            let connection=Connection::open_with_flags_and_vfs(path,flags,
                vfs.to_str().map_err(|_|"selected VFS name UTF8")?).map_err(|e|format!("existing named SQLite refused {e}"))?;
            Ok(connection)
        })();
        owner.state.failed_connection=Some(match prepared{Ok(connection)=>ManuallyDrop::new(connection),
            Err(cause)=>return Err(NativeDatabaseRefusal{cause,owner:ManuallyDrop::new(owner)})});
        let checked=unsafe{mutiny_sqlite_protected_session_status(owner.state.session)};
        if checked!=ffi::SQLITE_OK{
            // Keep the still-open connection AND native session. No accidental
            // SQLite Drop can erase the original cleanup/transition evidence.
            return Err(NativeDatabaseRefusal{cause:format!("selected native database current refused {checked}"),
                owner:ManuallyDrop::new(owner)});
        }
        let connection=owner.state.failed_connection.take().expect("same published native Connection");
        owner.state.frozen=false;Ok(OpenedExistingDatabase{owner:ManuallyDrop::new(owner),connection})
    }
    /// Another exclusively factory-owned view in the SAME already selected
    /// native session. The C provider tracks every MAIN lifetime independently;
    /// no Connection can escape this private module through a public path API.
    /// The opaque request is freshly issued by the held installed selection.
    pub(crate) fn open_same_group(&mut self,request:&SelectedExistingDatabase<'_>)
        ->Result<ManuallyDrop<Connection>,String>{
        self.recheck()?;
        let s=&mut **self.state;s.frozen=true;
        let opened=(||->Result<Connection,String>{
            if request.capacity()!=s.capacity{return Err("same native group capacity changed".into());}
            let mut expected=request.parent().as_bytes().to_vec();expected.push(b'/');
            expected.extend(request.name().as_bytes());
            if s.path.as_ref().ok_or("same original database path absent")?.as_bytes()!=expected{
                return Err("same native group selected path changed".into());}
            let mut native_name=ptr::null();
            let rc=unsafe{mutiny_sqlite_protected_session_register(s.session,&mut native_name)};
            if rc!=ffi::SQLITE_OK{return Err(format!("same selected VFS register refused {rc}"));}
            let vfs=unsafe{bounded_native_name(native_name)}?;
            let path=std::path::Path::new(s.path.as_ref().ok_or("same original path absent")?
                .to_str().map_err(|_|"same native path UTF8")?);
            let flags=(if s.readonly{OpenFlags::SQLITE_OPEN_READ_ONLY}else{OpenFlags::SQLITE_OPEN_READ_WRITE})
                |OpenFlags::SQLITE_OPEN_NO_MUTEX;
            Connection::open_with_flags_and_vfs(path,flags,vfs.to_str().map_err(|_|"same VFS name UTF8")?)
                .map_err(|e|format!("same native group SQLite refused {e}"))
        })();
        // Publish the Connection before the post-native current check. A failed
        // postcheck retains it with the original session, never SQLite Drop.
        s.failed_connection=Some(ManuallyDrop::new(opened?));
        let rc=unsafe{mutiny_sqlite_protected_session_status(s.session)};
        if rc!=ffi::SQLITE_OK{return Err(format!("same native group current refused {rc}"));}
        let connection=s.failed_connection.take().expect("same published native group Connection");
        s.frozen=false;Ok(connection)
    }
    pub(crate) fn recheck(&mut self)->Result<(),String>{
        if self.state.frozen||self.state.close_called||self.state.session.is_null(){return Err("existing native database frozen".into());}
        self.state.frozen=true;
        let rc=unsafe{mutiny_sqlite_protected_session_status(self.state.session)};
        if rc!=ffi::SQLITE_OK{return Err(format!("existing native database current refused {rc}"));}
        self.state.frozen=false;Ok(())
    }
    /// Call only from the private factory after all same-group Connections were
    /// explicitly consumed and its original worker joined. No bool proves that:
    /// the C provider still checks live_files/deferred/native outcomes itself.
    pub(crate) fn close_after_connections(mut self)->Result<NativeDatabaseClosed,NativeDatabaseRefusal>{
        if let Err(cause)=self.recheck(){return Err(NativeDatabaseRefusal{cause,owner:ManuallyDrop::new(self)});}
        self.state.frozen=true;self.state.close_called=true;
        let rc=unsafe{mutiny_sqlite_protected_session_named_close_once(self.state.session,&mut self.state.report)};
        // The retained report survives any inconsistent released/error result.
        // Once C reports release, never dereference/retry that former session.
        if self.state.report.released==1{self.state.session=ptr::null_mut();}
        if rc!=ffi::SQLITE_OK||!complete(&self.state.report){
            return Err(NativeDatabaseRefusal{cause:format!("existing named native cleanup retained {rc}"),owner:ManuallyDrop::new(self)});
        }
        self.state.session=ptr::null_mut();
        let mut state=unsafe{ManuallyDrop::take(&mut self.state)};
        let report=std::mem::take(&mut state.report);drop(state);Ok(NativeDatabaseClosed{report})
    }
    pub(crate) fn inspect_close(&mut self)->Result<(),String>{
        if self.state.session.is_null(){return Err("existing native session absent".into());}
        let rc=unsafe{mutiny_sqlite_protected_session_named_close_report(self.state.session,&mut self.state.report)};
        if rc!=ffi::SQLITE_OK{return Err(format!("existing native close snapshot refused {rc}"));}Ok(())
    }
}
