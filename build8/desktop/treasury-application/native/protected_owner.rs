//! SOURCE-ONLY private owner for the explicit named Linux VFS candidate.
//! Not registered in lib.rs, not built by bounded7, no production factory.
//! Logical native proof/binding/current-service validation remains mandatory.
#![cfg(target_os="linux")]
use rusqlite::{Connection,OpenFlags,ffi};
use crate::treasury_bounded_readers::WorkSlot;
use std::{ffi::{c_char,c_int,c_void,CStr,CString},path::Path,ptr::NonNull,
    os::unix::ffi::OsStrExt};
unsafe extern "C" {
    fn mutiny_sqlite_protected_session_new(path:*const c_char,cap:i64,readonly:c_int,out:*mut *mut c_void)->c_int;
    fn mutiny_sqlite_protected_session_new_only(path:*const c_char,cap:i64,out:*mut *mut c_void)->c_int;
    fn mutiny_sqlite_protected_session_existing_only(path:*const c_char,cap:i64,readonly:c_int,out:*mut *mut c_void)->c_int;
    fn mutiny_sqlite_protected_session_promote_existing(session:*mut c_void)->c_int;
    fn mutiny_sqlite_protected_session_vfs_name(session:*mut c_void)->*const c_char;
    fn mutiny_sqlite_protected_session_register(session:*mut c_void,name:*mut *const c_char)->c_int;
    fn mutiny_sqlite_protected_session_database(session:*mut c_void)->*const c_char;
    fn mutiny_sqlite_protected_session_release(session:*mut c_void,released:*mut c_int)->c_int;
    fn mutiny_sqlite_protected_session_status(session:*mut c_void)->c_int;
}
#[derive(Debug)]
pub(crate) enum Error { InvalidInput,Native(i32),Sqlite(rusqlite::Error) }
impl From<rusqlite::Error> for Error{fn from(e:rusqlite::Error)->Self{Self::Sqlite(e)}}
/// Neither Send nor Sync: Native session is an exclusively owned Rust lifetime.
/// Two independent owners use existing SQLite POSIX lock/inode machinery.
pub(crate) struct Owner {
    connection:Option<Connection>,session:Option<NonNull<c_void>>,
    policy:Option<Box<Policy>>,
    inspection:Option<(Connection,Box<Policy>,WorkSlot)>,
    work_slot:Option<WorkSlot>,
}
struct Policy {readonly:bool}
unsafe extern "C" fn authorize(data:*mut c_void,op:c_int,a:*const c_char,b:*const c_char,
    _database:*const c_char,_trigger:*const c_char)->c_int{
    if data.is_null(){return ffi::SQLITE_DENY;}
    let policy=unsafe{&*data.cast::<Policy>()};
    match op{
        ffi::SQLITE_ATTACH|ffi::SQLITE_DETACH|ffi::SQLITE_CREATE_VTABLE|
        ffi::SQLITE_DROP_VTABLE|ffi::SQLITE_CREATE_TRIGGER|ffi::SQLITE_CREATE_VIEW|
        ffi::SQLITE_CREATE_TEMP_TRIGGER|ffi::SQLITE_CREATE_TEMP_VIEW=>ffi::SQLITE_DENY,
        ffi::SQLITE_PRAGMA=>{
            if a.is_null() || !b.is_null(){return ffi::SQLITE_DENY;}
            let name=unsafe{CStr::from_ptr(a)}.to_bytes();
            if [b"journal_mode".as_slice(),b"synchronous",b"query_only",b"mmap_size",b"temp_store",b"trusted_schema"].iter().any(|x|name.eq_ignore_ascii_case(x)) {ffi::SQLITE_OK}else{ffi::SQLITE_DENY}
        }
        ffi::SQLITE_FUNCTION=>{
            if b.is_null(){return ffi::SQLITE_DENY;}
            if unsafe{CStr::from_ptr(b)}.to_bytes().eq_ignore_ascii_case(b"load_extension"){ffi::SQLITE_DENY}else{ffi::SQLITE_OK}
        }
        ffi::SQLITE_INSERT|ffi::SQLITE_UPDATE|ffi::SQLITE_DELETE|ffi::SQLITE_CREATE_TABLE|
        ffi::SQLITE_CREATE_INDEX|ffi::SQLITE_DROP_TABLE|ffi::SQLITE_DROP_INDEX|
        ffi::SQLITE_ALTER_TABLE=>if policy.readonly{ffi::SQLITE_DENY}else{ffi::SQLITE_OK},
        ffi::SQLITE_SELECT|ffi::SQLITE_READ|ffi::SQLITE_TRANSACTION|
        ffi::SQLITE_SAVEPOINT|ffi::SQLITE_RECURSIVE=>ffi::SQLITE_OK,
        _=>ffi::SQLITE_DENY,
    }
}
pub(crate) struct NativeBoundary<'a> {
    session: NonNull<c_void>,
    _borrow: std::marker::PhantomData<&'a Owner>,
    _single_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl NativeBoundary<'_> {
    pub(crate) fn status(&self)->Result<(),Error>{
        let rc=unsafe{mutiny_sqlite_protected_session_status(self.session.as_ptr())};
        if rc==ffi::SQLITE_OK{Ok(())}else{Err(Error::Native(rc))}
    }
}
enum Origin{LegacyCandidate,NewOnly,ExistingOnly}
impl Owner {
    /// Crate-private storage boundary only; creates no admission/auth capability.
    pub(crate) fn open_existing_directory(dir:&Path,cap:i64,readonly:bool)->Result<Self,Error>{
        Self::construct(dir,cap,readonly,Origin::LegacyCandidate)
    }
    pub(crate) fn new_only(dir:&Path,cap:i64)->Result<Self,Error>{
        Self::construct(dir,cap,false,Origin::NewOnly)
    }
    pub(crate) fn existing_only(dir:&Path,cap:i64,readonly:bool)->Result<Self,Error>{
        Self::construct(dir,cap,readonly,Origin::ExistingOnly)
    }
    fn construct(dir:&Path,cap:i64,readonly:bool,origin:Origin)->Result<Self,Error>{
        if !dir.is_absolute(){return Err(Error::InvalidInput);}
        let path=CString::new(dir.as_os_str().as_bytes()).map_err(|_|Error::InvalidInput)?;
        let mut raw=std::ptr::null_mut();
        let rc=unsafe{match origin {
            Origin::LegacyCandidate=>mutiny_sqlite_protected_session_new(path.as_ptr(),cap,readonly as i32,&mut raw),
            Origin::NewOnly=>mutiny_sqlite_protected_session_new_only(path.as_ptr(),cap,&mut raw),
            Origin::ExistingOnly=>mutiny_sqlite_protected_session_existing_only(path.as_ptr(),cap,readonly as i32,&mut raw),
        }};
        if rc!=ffi::SQLITE_OK{return Err(Error::Native(rc));}
        let session=NonNull::new(raw).ok_or(Error::InvalidInput)?;
        let mut owner=Self{connection:None,session:Some(session),policy:Some(Box::new(Policy{readonly})),inspection:None,work_slot:None};
        let mut name=std::ptr::null();
        let rc=unsafe{mutiny_sqlite_protected_session_register(raw,&mut name)};
        if rc!=ffi::SQLITE_OK{return Err(Error::Native(rc));}
        if name.is_null(){return Err(Error::InvalidInput);}
        let vfs=unsafe{CStr::from_ptr(name)}.to_str().map_err(|_|Error::InvalidInput)?;
        let name=unsafe{mutiny_sqlite_protected_session_database(raw)};
        if name.is_null(){return Err(Error::InvalidInput);}
        let database=Path::new(std::ffi::OsStr::from_bytes(unsafe{CStr::from_ptr(name)}.to_bytes()));
        let flags=if readonly{OpenFlags::SQLITE_OPEN_READ_ONLY}else{OpenFlags::SQLITE_OPEN_READ_WRITE|OpenFlags::SQLITE_OPEN_CREATE};
        let connection=Connection::open_with_flags_and_vfs(database,flags|OpenFlags::SQLITE_OPEN_NO_MUTEX,vfs)?;
        owner.work_slot=Some(WorkSlot::for_owned_connection(&connection));
        owner.connection=Some(connection);
        let connection=owner.connection.as_ref().unwrap();
        connection.busy_timeout(std::time::Duration::ZERO)?;
        connection.execute_batch("PRAGMA mmap_size=0;PRAGMA temp_store=MEMORY;PRAGMA trusted_schema=OFF;")?;
        if readonly{connection.execute_batch("PRAGMA query_only=ON;")?;}
        else{connection.execute_batch("PRAGMA journal_mode=DELETE;PRAGMA synchronous=EXTRA;PRAGMA locking_mode=NORMAL;")?;}
        let mode:String=connection.query_row("PRAGMA journal_mode",[],|r|r.get(0))?;
        if !mode.eq_ignore_ascii_case("delete"){return Err(Error::InvalidInput);}
        // Native SQLite limits complement application type/length/count guards.
        // Exact allowed retained row fields total below 16KiB; no arbitrary SQL.
        let db=unsafe{connection.handle()};
        for (kind,value) in [(ffi::SQLITE_LIMIT_LENGTH,16384),(ffi::SQLITE_LIMIT_SQL_LENGTH,8192),
            (ffi::SQLITE_LIMIT_COLUMN,32),(ffi::SQLITE_LIMIT_ATTACHED,0),
            (ffi::SQLITE_LIMIT_VARIABLE_NUMBER,32),(ffi::SQLITE_LIMIT_WORKER_THREADS,0)]{
            unsafe{ffi::sqlite3_limit(db,kind,value)};
        }
        let rc=unsafe{ffi::sqlite3_set_authorizer(db,Some(authorize),(&mut **owner.policy.as_mut().unwrap() as *mut Policy).cast())};
        if rc!=ffi::SQLITE_OK{return Err(Error::Native(rc));}
        Ok(owner)
    }
    /// PRIVATE typed-store integration only. Root must supply its exact trusted
    /// schema/context/record/store-ID validator; this is no public capability.
    /// Validate original O_RDONLY object, retain it, then independently validate
    /// second SAME-session/SAME-inode RW object with query_only still ON before
    /// writable configuration. No pathname preflight/reopen identity shortcut.
    pub(crate) fn promote_after_binding<E>(&mut self,map:fn(Error)->E,
        mut validate:impl FnMut(&Connection,&WorkSlot)->Result<(),E>)->Result<(),E>{
        self.status().map_err(map)?;
        if self.inspection.is_some() || self.policy.as_ref().is_none_or(|p|!p.readonly){return Err(map(Error::InvalidInput));}
        let old=self.connection.as_ref().ok_or_else(||map(Error::InvalidInput))?;
        if !old.is_autocommit(){return Err(map(Error::InvalidInput));}
        let old_slot=self.work_slot.as_ref().ok_or_else(||map(Error::InvalidInput))?;
        validate(old,old_slot)?;
        if !old.is_autocommit(){return Err(map(Error::InvalidInput));}
        self.status().map_err(map)?;
        let raw=self.session.ok_or_else(||map(Error::InvalidInput))?.as_ptr();
        let rc=unsafe{mutiny_sqlite_protected_session_promote_existing(raw)};
        if rc!=ffi::SQLITE_OK{return Err(map(Error::Native(rc)));}
        let name=unsafe{mutiny_sqlite_protected_session_vfs_name(raw)};
        let database=unsafe{mutiny_sqlite_protected_session_database(raw)};
        if name.is_null() || database.is_null(){return Err(map(Error::InvalidInput));}
        let vfs=unsafe{CStr::from_ptr(name)}.to_str().map_err(|_|map(Error::InvalidInput))?;
        let database=Path::new(std::ffi::OsStr::from_bytes(unsafe{CStr::from_ptr(database)}.to_bytes()));
        // No CREATE flag: the original known inode must already exist.
        let connection=Connection::open_with_flags_and_vfs(database,OpenFlags::SQLITE_OPEN_READ_WRITE|OpenFlags::SQLITE_OPEN_NO_MUTEX,vfs).map_err(|e|map(Error::Sqlite(e)))?;
        connection.busy_timeout(std::time::Duration::ZERO).map_err(|e|map(Error::Sqlite(e)))?;
        connection.execute_batch("PRAGMA query_only=ON;PRAGMA mmap_size=0;PRAGMA temp_store=MEMORY;PRAGMA trusted_schema=OFF;").map_err(|e|map(Error::Sqlite(e)))?;
        let db=unsafe{connection.handle()};
        for (kind,value) in [(ffi::SQLITE_LIMIT_LENGTH,16384),(ffi::SQLITE_LIMIT_SQL_LENGTH,8192),
            (ffi::SQLITE_LIMIT_COLUMN,32),(ffi::SQLITE_LIMIT_ATTACHED,0),
            (ffi::SQLITE_LIMIT_VARIABLE_NUMBER,32),(ffi::SQLITE_LIMIT_WORKER_THREADS,0)]{unsafe{ffi::sqlite3_limit(db,kind,value)};}
        let work_slot=WorkSlot::for_owned_connection(&connection);
        validate(&connection,&work_slot)?;
        if !connection.is_autocommit(){return Err(map(Error::InvalidInput));}
        self.status().map_err(map)?;
        connection.execute_batch("PRAGMA query_only=OFF;PRAGMA journal_mode=DELETE;PRAGMA synchronous=EXTRA;PRAGMA locking_mode=NORMAL;").map_err(|e|map(Error::Sqlite(e)))?;
        let mode=crate::treasury_bounded_readers::journal_mode(&connection).map_err(|_|map(Error::InvalidInput))?;
        let sync:i64=connection.query_row("PRAGMA synchronous",[],|r|r.get(0)).map_err(|e|map(Error::Sqlite(e)))?;
        if !mode.eq_ignore_ascii_case("delete") || sync!=3 || connection.is_readonly(rusqlite::MAIN_DB).map_err(|e|map(Error::Sqlite(e)))?{return Err(map(Error::InvalidInput));}
        let mut policy=Box::new(Policy{readonly:false});
        let rc=unsafe{ffi::sqlite3_set_authorizer(db,Some(authorize),(&mut *policy as *mut Policy).cast())};
        if rc!=ffi::SQLITE_OK{return Err(map(Error::Native(rc)));}
        // Move only after successful validation/configuration. Both policies
        // outlive their exact Connections; original RO pin retained to close.
        self.inspection=Some((self.connection.take().unwrap(),self.policy.take().unwrap(),self.work_slot.take().unwrap()));
        self.connection=Some(connection);self.policy=Some(policy);self.work_slot=Some(work_slot);
        self.status().map_err(map)
    }
    // Trusted in-crate typed-store integration only, never public extraction.

    /// Trusted typed-store closure only. R cannot borrow the ephemeral
    /// connection argument; there is no Deref or Connection extraction API.
    pub(crate) fn inspect_typed<R,E>(&self,map:fn(Error)->E,
        action:impl FnOnce(&Connection,&WorkSlot)->Result<R,E>)->Result<R,E>{
        self.status().map_err(map)?;
        let c=self.connection.as_ref().ok_or_else(||map(Error::InvalidInput))?;
        let slot=self.work_slot.as_ref().ok_or_else(||map(Error::InvalidInput))?;
        let result=action(c,slot);
        self.status().map_err(map)?;
        result
    }
    /// Transaction callbacks can recheck the exact owned native status
    /// immediately before external Reserve/Consume and before local commit.
    /// The borrowed boundary cannot outlive or replace this complete owner.
    pub(crate) fn mutate_typed<R,E>(&mut self,map:fn(Error)->E,
        action:impl FnOnce(&mut Connection,&NativeBoundary<'_>,&WorkSlot)->Result<R,E>)->Result<R,E>{
        self.status().map_err(map)?;
        if self.policy.as_ref().is_none_or(|p|p.readonly){return Err(map(Error::InvalidInput));}
        let session=self.session.ok_or_else(||map(Error::InvalidInput))?;
        let boundary=NativeBoundary{session,_borrow:std::marker::PhantomData,_single_thread:std::marker::PhantomData};
        let c=self.connection.as_mut().ok_or_else(||map(Error::InvalidInput))?;
        let slot=self.work_slot.as_ref().ok_or_else(||map(Error::InvalidInput))?;
        let result=action(c,&boundary,slot);
        boundary.status().map_err(map)?;
        result
    }
    pub(crate) fn inspect<R>(&self,action:impl FnOnce(&Connection)->Result<R,Error>)->Result<R,Error>{
        self.status()?;
        let result=action(self.connection.as_ref().ok_or(Error::InvalidInput)?);
        // SQLite pager paths may ignore xClose's return. The native session
        // permanently latches that error before this trusted caller gets output.
        self.status()?;
        result
    }
    pub(crate) fn status(&self)->Result<(),Error>{
        let session=self.session.ok_or(Error::InvalidInput)?;
        let rc=unsafe{mutiny_sqlite_protected_session_status(session.as_ptr())};
        if rc==ffi::SQLITE_OK{Ok(())}else{Err(Error::Native(rc))}
    }
    /// Explicit error-visible close. BUSY returns complete owner unchanged;
    /// a released session whose directory close errored is reported, not retried.
    pub(crate) fn close(mut self)->Result<(),(Self,Error)>{
        if let Some(connection)=self.connection.take(){
            if let Err((connection,error))=connection.close(){self.connection=Some(connection);return Err((self,Error::Sqlite(error)));}
        }
        if let Some((connection,policy,slot))=self.inspection.take(){
            if let Err((connection,error))=connection.close(){self.inspection=Some((connection,policy,slot));return Err((self,Error::Sqlite(error)));}
        }
        if let Some(session)=self.session{
            let mut released=0;let rc=unsafe{mutiny_sqlite_protected_session_release(session.as_ptr(),&mut released)};
            if released==1{self.session=None;}
            if rc!=ffi::SQLITE_OK{return Err((self,Error::Native(rc)));}
        }
        Ok(())
    }
}
impl Drop for Owner {
    fn drop(&mut self){
        // Drop grants no receipt/durability. Explicit close is required to observe
        // errors. If SQLite cannot close, retain connection AND opaque session:
        // freeing pins underneath live statements/files would be unsafe.
        if let Some(connection)=self.connection.take(){
            if let Err((connection,_))=connection.close(){
                std::mem::forget(connection);
                // Retained SQLite still owns a callback pointer to this policy.
                if let Some(policy)=self.policy.take(){std::mem::forget(policy);}
                if let Some((original,policy,slot))=self.inspection.take(){std::mem::forget(original);std::mem::forget(policy);std::mem::forget(slot);}
                self.session=None;return;
            }
        }
        if let Some((connection,policy,slot))=self.inspection.take(){
            if let Err((connection,_))=connection.close(){
                std::mem::forget(connection);std::mem::forget(policy);self.session=None;return;
            }
        }
        if let Some(session)=self.session.take(){
            let mut released=0;let _=unsafe{mutiny_sqlite_protected_session_release(session.as_ptr(),&mut released)};
            // Nonreleased pointer retains its native pins/quarantine until exit.
        }
    }
}
