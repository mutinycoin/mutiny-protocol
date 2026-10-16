//! Existing-only native protected-lineage I/O. No installation, principal
//! creation, qualification, TimeBasis or restart authority is supplied here.
//! Run only inside the selected dedicated owner. The installer must establish
//! the initial file; missing, restored node-owned, or inaccessible state refuses.
//! System-call completion is software durability evidence, not power-loss proof.
#![allow(dead_code)]

use super::protected_clock_lineage_v1::{Begin, DocumentaryEngine, Request, Scope,
    SNAPSHOT_MAX};
use super::protected_clock_operation_journal::{self as journal,JournalReply,JournalPlan,JournalStatus};
use super::protected_clock_lineage_v1::Operation;
use std::{ffi::CString, fs::File, io::{Read, Seek, SeekFrom, Write},
    os::{fd::{AsRawFd, FromRawFd, IntoRawFd}, unix::{ffi::OsStrExt, fs::MetadataExt}},
    path::{Component, Path}};

type Result<T> = std::result::Result<T, String>;
const HEAD: &str = "clock-lineage.head";
const JOURNAL:&str="clock-operations.journal";

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity { device: u64, inode: u64 }
impl Identity {
    fn of(file: &File) -> Result<Self> {
        let m = file.metadata().map_err(|e| e.to_string())?;
        Ok(Self { device:m.dev(), inode:m.ino() })
    }
}
struct Directory { file: File, name: Option<CString>, identity: Identity,original_close_pin:[u8;24] }

/// Does not certify the installation or code/process facts. Its constructor
/// independently refuses the ordinary node identity and unsafe filesystem
/// rights. Only a future fully validated installed-owner adapter may retain it.
pub(super) struct LinuxLineageIo {
    owner_uid: u32,
    directories: Vec<Directory>,
    head: Option<File>,
    head_identity: Identity,
    frozen: bool,
    journal:Option<File>,journal_identity:Option<Identity>,journal_scope:Option<Scope>,
    original_head:[u8;24],original_journal:Option<[u8;24]>,
}
pub(super) struct LinuxCloseFailure {
    native:Option<super::native_retained_close::RetainedCloseReport>,
    unclosed:Option<std::mem::ManuallyDrop<LinuxLineageIo>>,
}
impl LinuxCloseFailure {pub(super) fn description(&self)->String {
    match &self.native {Some(report)=>format!("{} original Linux lineage close outcomes remain uncertain",report.uncertain_count()),
        None=>"original Linux lineage close refused before effects; whole writer retained".into()}
}}
impl LinuxLineageIo {
    pub(super) fn open_existing(path: &Path, owner_uid: u32, node_uid: u32) -> Result<Self> {
        // No root fallback and no same-principal restore-domain claim. Check
        // real as well as effective UID: setuid impersonation is not installation.
        if owner_uid == 0 || owner_uid == node_uid
            || unsafe { libc::geteuid() } != owner_uid
            || unsafe { libc::getuid() } != owner_uid {
            return Err("dedicated clock-owner principal required".into());
        }
        if !path.is_absolute() {return Err("protected lineage absolute path required".into());}
        let mut names=Vec::new();
        for component in path.components() {
            match component {
                Component::RootDir=>(),
                Component::Normal(n)=>names.push(CString::new(n.as_bytes())
                    .map_err(|_|"protected lineage path component refused".to_owned())?),
                _=>return Err("protected lineage path component refused".into()),
            }
        }
        if names.is_empty() {return Err("protected lineage root-only path refused".into());}
        let count=names.len();
        let root = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY
            | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if root < 0 {return Err(std::io::Error::last_os_error().to_string());}
        let root = unsafe {File::from_raw_fd(root)};
        check_directory(&root, owner_uid, false)?;
        let root_pin=super::native_retained_close::retained_identity(&root).map_err(|e|format!("original lineage root identity: {e}"))?;
        let mut directories=vec![Directory {identity:Identity::of(&root)?, file:root,name:None,original_close_pin:root_pin}];
        for (i,name) in names.into_iter().enumerate() {
            let parent=&directories.last().ok_or("protected lineage parent")?.file;
            let file=open_at(parent,&name,libc::O_RDONLY | libc::O_DIRECTORY)?;
            let leaf=i+1==count;
            check_directory(&file,owner_uid,leaf)?;
            same_named(parent,&name,&file)?;
            let original_close_pin=super::native_retained_close::retained_identity(&file).map_err(|e|format!("original lineage ancestor identity: {e}"))?;
            directories.push(Directory {identity:Identity::of(&file)?,file,name:Some(name),original_close_pin});
        }
        let parent=&directories.last().ok_or("protected lineage leaf")?.file;
        let name=CString::new(HEAD).map_err(|_|"head name")?;
        let head=open_at(parent,&name,libc::O_RDWR)?;
        check_record(&head,owner_uid)?;
        same_named(parent,&name,&head)?;
        head.try_lock().map_err(|e|format!("clock lineage writer lock: {e}"))?;
        let original_head=super::native_retained_close::retained_identity(&head).map_err(|e|format!("original lineage head identity: {e}"))?;
        let mut io=Self {owner_uid,head_identity:Identity::of(&head)?,original_head,original_journal:None,
            directories,head:Some(head),frozen:false,journal:None,journal_identity:None,journal_scope:None};
        io.recheck()?;
        // Bound before allocation, then verify current exact named/held objects.
        io.read_current()?;
        Ok(io)
    }

    pub(super) fn replacement_observation(&mut self)->Result<super::protected_clock_owner::NativeLineageObservation> {
        self.recheck()?;let head=self.read_current()?;
        let mut ancestors=Vec::new();ancestors.try_reserve_exact(self.directories.len()).map_err(|_|"replacement ancestry allocation")?;
        ancestors.extend(self.directories.iter().map(|d|d.original_close_pin));
        let observation=super::protected_clock_owner::NativeLineageObservation::observed(self.original_head,
            self.original_journal.ok_or("replacement journal original pin absent")?,ancestors,
            self.journal.as_mut().ok_or("replacement journal absent")?,head)?;
        self.recheck()?;Ok(observation)
    }
    pub(super) fn read_current(&mut self) -> Result<Vec<u8>> {
        self.recheck()?;
        let head=self.head.as_mut().ok_or("clock lineage closed")?;
        let size=head.metadata().map_err(|e|e.to_string())?.len();
        if size==0 || size>SNAPSHOT_MAX as u64 {return Err("clock lineage read bound".into());}
        head.seek(SeekFrom::Start(0)).map_err(|e|e.to_string())?;
        let mut raw=vec![0;size as usize];
        head.read_exact(&mut raw).map_err(|e|e.to_string())?;
        let mut extra=[0];
        if head.read(&mut extra).map_err(|e|e.to_string())?!=0 {
            return Err("clock lineage grew during bounded read".into());
        }
        self.recheck()?;
        Ok(raw)
    }

    fn recheck(&self) -> Result<()> {
        if unsafe {libc::geteuid()}!=self.owner_uid || unsafe {libc::getuid()}!=self.owner_uid {
            return Err("clock-owner principal changed".into());
        }
        for (i,directory) in self.directories.iter().enumerate() {
            check_directory(&directory.file,self.owner_uid,i+1==self.directories.len())?;
            if Identity::of(&directory.file)?!=directory.identity {return Err("lineage directory changed".into());}
            if let Some(name)=&directory.name {
                same_named(&self.directories[i-1].file,name,&directory.file)?;
            } else {
                // Include root name identity in every complete traversal recheck.
                let root=unsafe {libc::open(c"/".as_ptr(),libc::O_RDONLY | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW | libc::O_CLOEXEC)};
                if root<0 {return Err(std::io::Error::last_os_error().to_string());}
                let observed=unsafe {File::from_raw_fd(root)};
                let equal=Identity::of(&observed)?==directory.identity;
                close(observed)?;
                if !equal {return Err("lineage root substituted".into());}
            }
        }
        let head=self.head.as_ref().ok_or("clock lineage closed")?;
        check_record(head,self.owner_uid)?;
        if Identity::of(head)?!=self.head_identity {return Err("lineage head changed".into());}
        let parent=&self.directories.last().ok_or("lineage leaf")?.file;
        same_named(parent,&CString::new(HEAD).map_err(|_|"head name")?,head)?;
        if let Some(journal)=&self.journal {
            check_record(journal,self.owner_uid)?;
            if Some(Identity::of(journal)?)!=self.journal_identity {return Err("journal held identity changed".into());}
            same_named(parent,&CString::new(JOURNAL).map_err(|_|"journal name")?,journal)?;
        }
        Ok(())
    }

    /// Normal existing-only attachment; a protected installer must establish
    /// the exact scoped header. Missing file is never created or reset here.
    pub(super) fn attach_existing_journal(&mut self,scope:&Scope)->Result<()> {
        self.attach_journal_inner(scope,false)
    }
    /// This route retains a pending journal under a frozen barrier. It does
    /// not thaw, complete, truncate or grant qualification merely by opening.
    pub(super) fn attach_for_exact_reconciliation(&mut self,scope:&Scope)->Result<()> {
        self.attach_journal_inner(scope,true)
    }
    fn attach_journal_inner(&mut self,scope:&Scope,reconciliation:bool)->Result<()> {
        self.recheck()?;
        if self.journal.is_some() {return Err("operation journal already attached".into());}
        let parent=&self.directories.last().ok_or("lineage leaf")?.file;
        let name=CString::new(JOURNAL).map_err(|_|"journal name")?;
        let file=open_at(parent,&name,libc::O_RDWR)?;check_record(&file,self.owner_uid)?;
        same_named(parent,&name,&file)?;let identity=Identity::of(&file)?;
        if identity==self.head_identity {return Err("journal aliases lineage head".into());}
        file.try_lock().map_err(|e|format!("operation journal writer lock: {e}"))?;
        let original_journal=super::native_retained_close::retained_identity(&file).map_err(|e|format!("original lineage journal identity: {e}"))?;
        self.journal=Some(file);self.journal_identity=Some(identity);self.original_journal=Some(original_journal);self.journal_scope=Some(scope.clone());
        let status=self.journal_status()?;
        if status.pending.is_some() {
            self.frozen=true;
            if !reconciliation {return Err("journal has unresolved exact operation; startup frozen".into());}
        }
        Ok(())
    }
    /// Exact recovery of a protected authorized journal record only. The
    /// installed owner must bracket this with current selection checks. An
    /// observed before/partial/foreign head remains frozen; no reset/recycle.
    /// Reconstructed documents ratchet floors only and never qualify a clock.
    pub(super) fn reconcile_pending_operation(&mut self,operation:&Operation)->Result<Vec<u8>> {
        self.frozen=true;
        let result=(|| {
            self.recheck()?;
            let status=self.journal_status()?;
            let plan=status.pending.ok_or("exact unresolved journal operation absent")?;
            if plan.operation()!=operation {return Err("reconciliation identity/content differs".into());}
            let observed=self.read_current()?;
            let completion=plan.completion_head();
            if observed==plan.intent_head() {
                // Reestablish durable intent before the matching completion.
                self.durable_write_readback(&plan.intent_head())?;
                self.durable_write_readback(&completion)?;
            } else if observed==completion {
                // Lost completion acknowledgement: preserve this exact state,
                // flush it, then record only its matching journal completion.
                self.durable_write_readback(&completion)?;
            } else {
                return Err("before/partial/foreign head cannot reconcile exact journal intent".into());
            }
            self.append_journal_frame(&plan.completion_frame())?;
            let status=self.journal_status()?;
            let reply=status.lookup(operation)?.ok_or("reconciled completion absent")?;
            let scope=self.journal_scope.as_ref().ok_or("reconciliation scope absent")?;
            let document=DocumentaryEngine::from_document(scope,&completion).map_err(|e|format!("reconciliation document: {e:?}"))?;
            if reply.sequence!=document.sequence() || reply.floor!=document.floor()
                || document.frozen() || self.read_current()?!=completion {
                return Err("reconciliation exact outcome differs".into());
            }
            self.recheck()?;Ok(completion)
        })();
        if result.is_ok() {self.frozen=false;}
        result
    }
    fn journal_status(&mut self)->Result<JournalStatus> {
        self.recheck()?;
        let scope=self.journal_scope.as_ref().ok_or("operation journal scope absent")?.clone();
        let file=self.journal.as_mut().ok_or("operation journal absent")?;
        let bytes=file.metadata().map_err(|e|e.to_string())?.len();
        file.seek(SeekFrom::Start(0)).map_err(|e|e.to_string())?;
        let status=journal::scan(&scope,file,bytes)?;
        if file.metadata().map_err(|e|e.to_string())?.len()!=bytes {return Err("operation journal length changed".into());}
        self.recheck()?;Ok(status)
    }
    pub(super) fn operation_reply(&mut self,operation:&Operation)->Result<Option<JournalReply>> {
        if self.frozen {return Err("operation journal frozen".into());}
        self.journal_status()?.lookup(operation)
    }
    pub(super) fn operation_bounds(&mut self)->Result<(u64,u64)> {
        if self.frozen {return Err("operation journal frozen".into());}
        let status=self.journal_status()?;
        if status.pending.is_some() {return Err("unresolved operation journal intent".into());}
        Ok((status.sequence,status.floor))
    }
    fn append_journal_frame(&mut self,raw:&[u8])->Result<()> {
        // Only fixed-shape JournalPlan encoding reaches this private method.
        if raw.is_empty() || raw.len()>2*SNAPSHOT_MAX+128 {return Err("journal append bound".into());}
        self.recheck()?;
        let file=self.journal.as_mut().ok_or("operation journal absent")?;
        let before=file.metadata().map_err(|e|e.to_string())?.len();
        let after=before.checked_add(raw.len() as u64).ok_or("operation journal length exhausted")?;
        file.seek(SeekFrom::Start(before)).map_err(|e|e.to_string())?;
        file.write_all(raw).map_err(|e|e.to_string())?;
        file.sync_all().map_err(|e|format!("operation journal synchronization: {e}"))?;
        self.directories.last().ok_or("journal parent")?.file.sync_all().map_err(|e|e.to_string())?;
        if file.metadata().map_err(|e|e.to_string())?.len()!=after {return Err("journal append length differs".into());}
        file.seek(SeekFrom::Start(before)).map_err(|e|e.to_string())?;
        let mut observed=vec![0;raw.len()];file.read_exact(&mut observed).map_err(|e|e.to_string())?;
        if observed!=raw {return Err("journal durable append readback differs".into());}
        let mut extra=[0];if file.read(&mut extra).map_err(|e|e.to_string())?!=0 {return Err("journal extra append".into());}
        self.recheck()
    }
    /// Reserve identity/content durably BEFORE the head intent/completion;
    /// record exact completion durably BEFORE returning the operation outcome.
    /// Any ambiguous boundary freezes; no automatic journal truncation/repair.
    pub(super) fn execute_operation(&mut self,engine:&mut DocumentaryEngine,request:Request)->Result<Vec<u8>> {
        if self.frozen {return Err("operation journal sticky frozen".into());}
        let result=(|| {
            let operation=request.operation().ok_or("operation identity absent")?;
            if self.operation_reply(operation)?.is_some() {return Err("recorded operation must use exact journal reply".into());}
            let current=self.read_current()?;
            if current!=engine.current_document() {return Err("operation before head differs".into());}
            let status=self.journal_status()?;
            if engine.sequence()<status.sequence || engine.floor()<status.floor {
                return Err("local head predates protected operation history".into());
            }
            let scope=self.journal_scope.as_ref().ok_or("journal scope absent")?;
            let plan=JournalPlan::from_current(scope,&current,request.clone())?;
            self.append_journal_frame(&plan.intent_frame())?;
            let observed=self.execute(engine,request)?;
            if observed!=plan.completion_head() {return Err("operation completed another transition".into());}
            self.append_journal_frame(&plan.completion_frame())?;
            let status=self.journal_status()?;
            let reply=status.lookup(plan.operation())?.ok_or("operation completion not recorded")?;
            if reply.sequence!=engine.sequence() || reply.floor!=engine.floor() {return Err("operation outcome readback differs".into());}
            self.recheck()?;Ok(observed)
        })();
        if result.is_err() {self.frozen=true;engine.unknown();}result
    }

    fn durable_write_readback(&mut self,raw:&[u8])->Result<Vec<u8>> {
        if raw.is_empty() || raw.len()>SNAPSHOT_MAX {return Err("clock lineage write bound".into());}
        self.recheck()?;
        let head=self.head.as_mut().ok_or("clock lineage closed")?;
        head.seek(SeekFrom::Start(0)).map_err(|e|e.to_string())?;
        // In-place updates retain the originally installed inode and writer
        // lock. A crash/short write leaves partial bytes, which startup refuses;
        // no old generation is silently selected or reset to an empty head.
        head.write_all(raw).map_err(|e|e.to_string())?;
        head.set_len(raw.len() as u64).map_err(|e|e.to_string())?;
        head.sync_all().map_err(|e|format!("lineage file synchronization: {e}"))?;
        self.directories.last().ok_or("lineage leaf")?.file.sync_all()
            .map_err(|e|format!("lineage parent synchronization: {e}"))?;
        let observed=self.read_current()?;
        if observed!=raw {return Err("lineage durable readback differs".into());}
        Ok(observed)
    }

    /// Serial mutable ownership covers precheck, intent, completion and result.
    /// Documentary retries never supply a clock capability or qualified floor.
    pub(super) fn execute(&mut self,engine:&mut DocumentaryEngine,request:Request)->Result<Vec<u8>> {
        if self.frozen {return Err("clock lineage sticky frozen".into());}
        let result=(|| {
            let current=self.read_current()?;
            if current!=engine.current_document() {return Err("lineage current head differs".into());}
            match engine.begin(request).map_err(|e|format!("lineage request: {e:?}"))? {
                Begin::ExactLastRetry(snapshot)=>{
                    if self.read_current()?!=snapshot.encode() {return Err("lineage retry head differs".into());}
                    Ok(snapshot.encode())
                },
                Begin::Plan(plan)=>{
                    let intent=self.durable_write_readback(&plan.intent())?;
                    engine.intent_readback(&intent).map_err(|e|format!("lineage intent: {e:?}"))?;
                    let completion=self.durable_write_readback(&plan.completion())?;
                    engine.completion_readback(&completion).map_err(|e|format!("lineage completion: {e:?}"))?;
                    self.recheck()?;
                    Ok(completion)
                },
            }
        })();
        if result.is_err() {self.frozen=true;engine.unknown();}
        result
    }

    /// Closing releases writer ownership only after explicit error accounting.
    /// On close failure retain the reported uncertainty; never retry close(2)
    /// against a descriptor that may already have been reused by the kernel.
    pub(super) fn close(mut self)->std::result::Result<(),LinuxCloseFailure> {
        if self.head.is_none() || self.journal.is_some()!=self.original_journal.is_some() {
            return Err(LinuxCloseFailure{native:None,unclosed:Some(std::mem::ManuallyDrop::new(self))});
        }
        let count=match self.directories.len().checked_add(1+usize::from(self.journal.is_some())) {
            Some(count)=>count,None=>return Err(LinuxCloseFailure{native:None,unclosed:Some(std::mem::ManuallyDrop::new(self))})};
        let mut report=match super::native_retained_close::RetainedCloseReport::prepare(count) {
            Ok(report)=>report,Err(_)=>return Err(LinuxCloseFailure{native:None,unclosed:Some(std::mem::ManuallyDrop::new(self))})};
        if let Some(journal)=self.journal.take(){report.file(journal,self.original_journal.expect("original journal pin"));}
        report.file(self.head.take().expect("original live head"),self.original_head);
        for directory in self.directories.drain(..).rev(){report.file(directory.file,directory.original_close_pin);}
        if report.retained_handles_closed(){Ok(())}else{Err(LinuxCloseFailure{native:Some(report),unclosed:None})}
    }

    pub(super) fn open_document(&mut self,scope:&Scope)->Result<DocumentaryEngine> {
        DocumentaryEngine::from_document(scope,&self.read_current()?)
            .map_err(|e|format!("protected current document: {e:?}"))
    }
}

fn check_directory(file:&File,owner:u32,leaf:bool)->Result<()> {
    let m=file.metadata().map_err(|e|e.to_string())?;
    if !m.is_dir() || (m.uid()!=0 && m.uid()!=owner) || m.mode()&0o022!=0
        || (leaf && (m.uid()!=owner || m.mode()&0o077!=0)) {
        return Err("protected directory type/principal/rights refused".into());
    }
    Ok(())
}
fn check_record(file:&File,owner:u32)->Result<()> {
    let m=file.metadata().map_err(|e|e.to_string())?;
    if !m.is_file() || m.uid()!=owner || m.nlink()!=1 || m.mode()&0o7077!=0 {
        return Err("protected record type/principal/link/rights refused".into());
    }
    Ok(())
}
fn open_at(parent:&File,name:&CString,flags:i32)->Result<File> {
    let fd=unsafe {libc::openat(parent.as_raw_fd(),name.as_ptr(),flags
        | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)};
    if fd<0 {return Err(std::io::Error::last_os_error().to_string());}
    Ok(unsafe {File::from_raw_fd(fd)})
}
fn same_named(parent:&File,name:&CString,held:&File)->Result<()> {
    let mut metadata=std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {libc::fstatat(parent.as_raw_fd(),name.as_ptr(),metadata.as_mut_ptr(),
        libc::AT_SYMLINK_NOFOLLOW)}!=0 {return Err(std::io::Error::last_os_error().to_string());}
    let metadata=unsafe {metadata.assume_init()};
    let identity=Identity::of(held)?;
    if metadata.st_dev!=identity.device || metadata.st_ino!=identity.inode {
        return Err("protected named/held identity mismatch".into());
    }
    Ok(())
}
fn close(file:File)->Result<()> {
    let fd=file.into_raw_fd();
    if unsafe {libc::close(fd)}!=0 {Err(format!("protected object close uncertain: {}",
        std::io::Error::last_os_error()))} else {Ok(())}
}
