//! Read-only Linux installation boundary. Exact fixed names, administrator
//! ownership, held descriptor-relative traversal and no-follow checks. This
//! authenticates local configuration custody, never physical measurements.
//! Windows uses administrator-owned native NTFS handles with no write/delete
//! sharing for files. Unsupported platforms refuse instead of borrowing the
//! anchor-writer owner. Both new backends remain uncompiled and unqualified.
use std::{fs::File, io::{Read, Seek, SeekFrom}};
use sha2::{Digest, Sha256};
type Result<T> = std::result::Result<T, String>;
const LIMIT: usize = 64 * 1024;
// Finite measurement-reader engineering budget, not a physical qualification
// or protocol bound. Includes the initial documentary artifact selection.
const MAX_RETAINED: usize = 4096;
const MAX_RETAINED_BYTES: u64 = 256 * 1024 * 1024;
const NAMES: [&str; 3] = ["accepted.json", "deployment.json", "qualification.json"];
struct HeldFile {file:File,bytes:Vec<u8>,digest:[u8;32],original_identity:[u8;24]}
fn held(file:File,bytes:Vec<u8>)->Result<HeldFile> {
    let original_identity=super::native_retained_close::retained_identity(&file)
        .map_err(|error|format!("original installation identity unavailable: {error}"))?;
    let digest=Sha256::digest(&bytes).into();Ok(HeldFile{file,bytes,digest,original_identity})
}
fn ancestor_pins(files:&[File])->Result<Vec<[u8;24]>> {
    files.iter().map(|file|super::native_retained_close::retained_identity(file)
        .map_err(|error|format!("original installation ancestor identity unavailable: {error}"))).collect()
}
pub(super) struct InstallationDirectory {
    _ancestors:Vec<File>,ancestor_ids:Vec<[u8;24]>,files:Vec<HeldFile>,
    artifacts:Vec<(String,HeldFile)>,
    frozen:bool,
}
impl InstallationDirectory {
    /// Consuming shutdown only; allocation failure retains the complete owner.
    /// Original selected files/artifacts precede ancestors, each attempted once.
    pub(super) fn close_retained(self)->std::result::Result<super::native_retained_close::RetainedCloseReport,Self> {
        if self._ancestors.len()!=self.ancestor_ids.len(){return Err(self);}
        let count=match self._ancestors.len().checked_add(self.files.len())
            .and_then(|n|n.checked_add(self.artifacts.len())){Some(n)=>n,None=>return Err(self)};
        let mut report=match super::native_retained_close::RetainedCloseReport::prepare(count){Ok(r)=>r,Err(_)=>return Err(self)};
        let Self{_ancestors,ancestor_ids,files,artifacts,frozen:_}=self;
        for object in files{report.file(object.file,object.original_identity);}
        for (_,object) in artifacts{report.file(object.file,object.original_identity);}
        for (file,pin) in _ancestors.into_iter().zip(ancestor_ids).rev(){report.file(file,pin);}
        Ok(report)
    }
    /// No caller-controlled root, home fallback, directory creation, ACL repair
    /// or environment-based installation selection is permitted on this route.
    pub(super) fn open()->Result<Self> {
        #[cfg(target_os="linux")]
        {linux::open()}
        #[cfg(windows)]
        {
            let (ancestors,objects)=super::state_dir::read_admin_clock_installation()
                .map_err(|e|format!("Windows installation refused: {e}"))?;
            let ancestor_ids=ancestor_pins(&ancestors)?;
            let files=objects.into_iter().map(|(file,bytes)|held(file,bytes)).collect::<Result<Vec<_>>>()?;
            let mut owner=Self{_ancestors:ancestors,ancestor_ids,files,artifacts:Vec::new(),frozen:false};owner.recheck()?;Ok(owner)
        }
        #[cfg(not(any(target_os="linux",windows)))]
        {Err("native clock installation ownership backend unavailable".into())}
    }
    pub(super) fn objects(&self)->(&[u8],&[u8],&[u8]) {
        (&self.files[0].bytes,&self.files[1].bytes,&self.files[2].bytes)
    }
    /// Exact content-addressed documentary objects inside SAME held installation.
    /// No caller path, scanning, writes, creation, migration or authority issuer.
    pub(super) fn retain_artifacts(&mut self,pins:&[[u8;32]])->Result<()> {
        let result=self.retain_initial(pins);
        if result.is_err(){self.frozen=true;}result
    }
    fn retain_initial(&mut self,pins:&[[u8;32]])->Result<()> {
        self.recheck()?;
        if !self.artifacts.is_empty() {return Err("installation artifact set already selected".into());}
        let names=artifact_names(pins)?;
        #[cfg(target_os="linux")]
        let handles=linux::artifact_handles(&self._ancestors,&names)?;
        #[cfg(windows)]
        let handles=super::state_dir::read_admin_clock_artifacts(&self._ancestors,&names)
            .map_err(|e|format!("Windows documentary artifacts refused: {e}"))?;
        #[cfg(not(any(target_os="linux",windows)))]
        return Err("installation documentary artifact backend unavailable".into());
        #[cfg(any(target_os="linux",windows))]
        {
            if handles.len()!=names.len() {return Err("documentary artifact handle shape".into());}
            let mut retained=Vec::new();
            for (name,mut file) in names.into_iter().zip(handles) {
                let bytes=read(&mut file)?;let digest=artifact_digest(&name,&bytes)?;
                let object=held(file,bytes)?;if object.digest!=digest{return Err("artifact original digest changed".into());}
                retained.push((name,object));
            }
            self.artifacts=retained;
            self.recheck()?;Ok(())
        }
    }
    /// Only the verifier's privately constructed bounded digest plan may
    /// extend this existing held installation. No path, scan, callback,
    /// administrator mutation or successful caller flag is accepted.
    pub(super) fn extend_retained(&mut self,plan:&super::native_nts_measurement_verifier::RetentionPlan)->Result<()> {
        let result=self.extend_inner(plan);
        if result.is_err(){self.frozen=true;}result
    }
    fn extend_inner(&mut self,plan:&super::native_nts_measurement_verifier::RetentionPlan)->Result<()> {
        self.recheck()?;
        if self.artifacts.is_empty(){return Err("initial documentary selection required".into());}
        let maximum=plan.maximum_objects();
        let maximum_bytes=plan.maximum_total_bytes().map_err(|_|"measurement plan byte budget".to_string())?;
        if maximum==0 || maximum>MAX_RETAINED || plan.object_count()>maximum
            || maximum_bytes==0 || maximum_bytes>MAX_RETAINED_BYTES || self.artifacts.len()>maximum {
            return Err("measurement plan retained bound".into());
        }
        let mut names=Vec::new();
        names.try_reserve(plan.object_count()).map_err(|_|"measurement plan allocation".to_string())?;
        let mut total=0u64;
        for (_,object) in &self.artifacts {
            total=total.checked_add(object.bytes.len() as u64).ok_or("measurement retained byte overflow")?;
        }
        for pin in plan.digests() {
            if *pin==[0;32]{return Err("measurement plan zero digest".into());}
            let name=format!("{}.json",hex::encode(pin));
            if !self.artifacts.iter().any(|(n,object)|*n==name && object.digest==*pin){names.push(name);}
        }
        let count=self.artifacts.len().checked_add(names.len()).ok_or("measurement retained count overflow")?;
        if count>maximum || count>MAX_RETAINED
            || total.checked_add((names.len() as u64).checked_mul(LIMIT as u64)
                .ok_or("measurement expansion budget overflow")?).ok_or("measurement expansion budget overflow")?>maximum_bytes {
            return Err("measurement expansion budget refused before opening".into());
        }
        self.artifacts.try_reserve(names.len()).map_err(|_|"measurement retained allocation".to_string())?;
        // Retain each successfully authenticated object immediately. If a later
        // open/read/current check fails, all earlier holds remain owned and the
        // whole reader freezes. This supplies no explicit native-close credit.
        for name in names {
            #[cfg(target_os="linux")]
            let mut file=linux::artifact_handles(&self._ancestors,std::slice::from_ref(&name))?.pop()
                .ok_or("measurement artifact missing handle")?;
            #[cfg(windows)]
            let mut file=super::state_dir::read_admin_clock_artifacts_extended(&self._ancestors,std::slice::from_ref(&name))
                .map_err(|e|format!("Windows measurement artifact refused: {e}"))?.pop()
                .ok_or("measurement artifact missing handle")?;
            #[cfg(not(any(target_os="linux",windows)))]
            return Err("measurement artifact native reader unavailable".into());
            #[cfg(any(target_os="linux",windows))]
            {
                let bytes=read(&mut file)?;let digest=artifact_digest(&name,&bytes)?;
                total=total.checked_add(bytes.len() as u64).ok_or("measurement actual byte overflow")?;
                if total>maximum_bytes{return Err("measurement actual byte budget".into());}
                let object=held(file,bytes)?;if object.digest!=digest{return Err("artifact original digest changed".into());}
                self.artifacts.push((name,object));
            }
        }
        self.recheck()
    }
    pub(super) fn artifact(&self,pin:&[u8;32])->Result<&[u8]> {
        if self.frozen{return Err("installation artifact reader frozen".into());}
        let name=format!("{}.json",hex::encode(pin));
        self.artifacts.iter().find(|(n,o)|*n==name && o.digest==*pin)
            .map(|(_,o)|o.bytes.as_slice()).ok_or_else(||"documentary artifact not retained".into())
    }
    pub(super) fn recheck(&mut self)->Result<()> {
        if self.frozen{return Err("installation reader frozen".into());}
        let result=self.recheck_inner();if result.is_err(){self.frozen=true;}result
    }
    fn recheck_inner(&mut self)->Result<()> {
        #[cfg(target_os="linux")]
        {
            // Check current fixed names as well as retained objects. Linux
            // permits an installation administrator to replace a name while
            // the previous descriptor remains open; that retires this owner.
            linux::recheck_named(&self._ancestors,&self.files)?;
            linux::recheck_artifacts(&self._ancestors,&self.artifacts)?;
            for object in &mut self.files {
                linux::check(&object.file,false)?;
                let current=read(&mut object.file)?;
                if current!=object.bytes || <[u8;32]>::from(Sha256::digest(&current))!=object.digest {
                    return Err("held native clock installation changed".into());
                }
            }
            for (_,object) in &mut self.artifacts {
                linux::check(&object.file,false)?;
                if read(&mut object.file)?!=object.bytes {return Err("held documentary artifact changed".into());}
            }
            // Bracket held-content verification with current fixed-name
            // verification; a legitimate admin replacement during reads must
            // not authorize the old selection through this completed call.
            // This is point-in-time validation, not atomic exclusion of admin
            // renames. Continuous service ownership must recheck every use.
            linux::recheck_named(&self._ancestors,&self.files)?;
            linux::recheck_artifacts(&self._ancestors,&self.artifacts)?;
            Ok(())
        }
        #[cfg(windows)]
        {
            let files:Vec<_>=self.files.iter().map(|o|&o.file).collect();
            super::state_dir::recheck_admin_clock_installation(&self._ancestors,&files)
                .map_err(|e|format!("Windows installation recheck refused: {e}"))?;
            let artifacts:Vec<_>=self.artifacts.iter().map(|(n,o)|(n.as_str(),&o.file)).collect();
            super::state_dir::recheck_admin_clock_artifacts(&self._ancestors,&artifacts)
                .map_err(|e|format!("Windows documentary artifact recheck refused: {e}"))?;
            for object in &mut self.files {
                let current=read(&mut object.file)?;
                if current!=object.bytes || <[u8;32]>::from(Sha256::digest(&current))!=object.digest {
                    return Err("held native clock installation changed".into());
                }
            }
            for (_,object) in &mut self.artifacts {
                if read(&mut object.file)?!=object.bytes {return Err("held documentary artifact changed".into());}
            }
            let artifacts:Vec<_>=self.artifacts.iter().map(|(n,o)|(n.as_str(),&o.file)).collect();
            super::state_dir::recheck_admin_clock_artifacts(&self._ancestors,&artifacts)
                .map_err(|e|format!("Windows documentary artifact final recheck refused: {e}"))?;
            let files:Vec<_>=self.files.iter().map(|o|&o.file).collect();
            super::state_dir::recheck_admin_clock_installation(&self._ancestors,&files)
                .map_err(|e|format!("Windows installation final recheck refused: {e}"))?;
            Ok(())
        }
        #[cfg(not(any(target_os="linux",windows)))]
        {Err("native clock installation ownership backend unavailable".into())}
    }
}
fn artifact_names(pins:&[[u8;32]])->Result<Vec<String>> {
    //8 existing obligations ×4 exact reference fields; local-only bound.
    if pins.is_empty() || pins.len()>32 || pins.iter().any(|p|*p==[0;32]) {
        return Err("documentary artifact reference bound".into());
    }
    let names:std::collections::BTreeSet<_>=pins.iter().map(|p|format!("{}.json",hex::encode(p))).collect();
    Ok(names.into_iter().collect())
}
fn artifact_digest(name:&str,bytes:&[u8])->Result<[u8;32]> {
    if bytes.is_empty() || bytes.len()>LIMIT {return Err("documentary artifact byte bound".into());}
    let digest:[u8;32]=Sha256::digest(bytes).into();
    if format!("{}.json",hex::encode(digest))!=name {
        return Err("documentary artifact content differs from exact requested digest".into());
    }
    Ok(digest)
}
fn read(file:&mut File)->Result<Vec<u8>> {
    let before=file.metadata().map_err(|e|format!("installation handle metadata: {e}"))?;
    if before.len()==0 || before.len()>LIMIT as u64 {return Err("installation object size".into());}
    file.seek(SeekFrom::Start(0)).map_err(|e|format!("installation handle seek: {e}"))?;
    let mut bytes=Vec::new();
    (&mut *file).take(LIMIT as u64+1).read_to_end(&mut bytes).map_err(|e|format!("installation handle read: {e}"))?;
    let after=file.metadata().map_err(|e|format!("installation handle metadata: {e}"))?;
    let before_modified=before.modified().map_err(|e|format!("installation before timestamp unavailable: {e}"))?;
    let after_modified=after.modified().map_err(|e|format!("installation after timestamp unavailable: {e}"))?;
    if bytes.len() as u64!=before.len() || after.len()!=before.len()
        || after_modified!=before_modified {
        return Err("installation handle changed during bounded read".into());
    }
    Ok(bytes)
}
#[cfg(target_os="linux")]
mod linux {
    use super::*;
    use std::{ffi::CString,os::{fd::{AsRawFd,FromRawFd},unix::fs::MetadataExt}};
    pub(super) fn check(file:&File,directory:bool)->Result<()> {
        let m=file.metadata().map_err(|e|format!("installation handle metadata: {e}"))?;
        if m.uid()!=0 || m.mode()&0o022!=0
            || (directory && !m.is_dir()) || (!directory && (!m.is_file() || m.nlink()!=1)) {
            return Err("installation must be root-owned, non-writer-writable, exact native type and single-link file".into());
        }
        Ok(())
    }
    fn open_at(parent:i32,name:&str,directory:bool)->Result<File> {
        let name=CString::new(name).map_err(|_|"installation name NUL")?;
        let flags=libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK
            |if directory {libc::O_DIRECTORY}else{0};
        let fd=unsafe{libc::openat(parent,name.as_ptr(),flags)};
        if fd<0 {return Err(format!("installation native open: {}",std::io::Error::last_os_error()));}
        // SAFETY: sole successful owned close-on-exec descriptor, consumed once.
        let file=unsafe{File::from_raw_fd(fd)};check(&file,directory)?;Ok(file)
    }
    fn same_named(held:&File,named:&File,directory:bool)->Result<()> {
        check(held,directory)?;check(named,directory)?;
        let a=held.metadata().map_err(|e|format!("held installation identity: {e}"))?;
        let b=named.metadata().map_err(|e|format!("named installation identity: {e}"))?;
        if a.dev()!=b.dev() || a.ino()!=b.ino() {
            return Err("current named installation replaced; retire clock selection".into());
        }
        Ok(())
    }
    pub(super) fn recheck_named(ancestors:&[File],files:&[HeldFile])->Result<()> {
        // Re-evaluate the writer boundary at every use, not only construction.
        if unsafe{libc::geteuid()}==0 {return Err("clock writer acquired root installation authority".into());}
        if ancestors.len()!=4 || files.len()!=NAMES.len() {return Err("installation retained shape".into());}
        let root=open_at(libc::AT_FDCWD,"/",true)?;
        same_named(&ancestors[0],&root,true)?;
        let mut named_chain=vec![root];
        for (i,name) in ["etc","mutiny","native-clock"].iter().enumerate() {
            // Retain the entire reopened chain during comparison. A changed
            // ancestor cannot be hidden by reopening its old descendant.
            let named=open_at(named_chain.last().unwrap().as_raw_fd(),name,true)?;
            same_named(&ancestors[i+1],&named,true)?;
            named_chain.push(named);
        }
        let parent=named_chain.last().unwrap().as_raw_fd();
        for (held,name) in files.iter().zip(NAMES) {
            let named=open_at(parent,name,false)?;
            same_named(&held.file,&named,false)?;
        }
        // A second chain pass catches substitutions during the first pass.
        // This is current-installation freshness, not an OS/admin compromise
        // or whole-authority-domain rollback protection claim.
        for (i,name) in ["etc","mutiny","native-clock"].iter().enumerate() {
            let named=open_at(named_chain[i].as_raw_fd(),name,true)?;
            same_named(&named_chain[i+1],&named,true)?;
        }
        for (held,name) in files.iter().zip(NAMES) {
            let named=open_at(parent,name,false)?;
            same_named(&held.file,&named,false)?;
        }
        Ok(())
    }
    pub(super) fn open()->Result<InstallationDirectory> {
        // An elevated root node does not establish an independent writer domain.
        if unsafe{libc::geteuid()}==0 {return Err("clock writer must be separate from root installation authority".into());}
        let mut ancestors=vec![open_at(libc::AT_FDCWD,"/",true)?];
        for name in ["etc","mutiny","native-clock"] {
            let next=open_at(ancestors.last().unwrap().as_raw_fd(),name,true)?;
            ancestors.push(next);
        }
        let directory=ancestors.last().unwrap();let mut files=Vec::new();
        for name in NAMES {
            let mut file=open_at(directory.as_raw_fd(),name,false)?;
            let bytes=read(&mut file)?;check(&file,false)?;
            files.push(held(file,bytes)?);
        }
        let ancestor_ids=ancestor_pins(&ancestors)?;
        let mut owner=InstallationDirectory{_ancestors:ancestors,ancestor_ids,files,artifacts:Vec::new(),frozen:false};owner.recheck()?;Ok(owner)
    }
    pub(super) fn artifact_handles(ancestors:&[File],names:&[String])->Result<Vec<File>> {
        if ancestors.len()!=4 {return Err("installation artifact parent shape".into());}
        names.iter().map(|name|open_at(ancestors[3].as_raw_fd(),name,false)).collect()
    }
    pub(super) fn recheck_artifacts(ancestors:&[File],objects:&[(String,HeldFile)])->Result<()> {
        if ancestors.len()!=4 || objects.len()>MAX_RETAINED {return Err("installation artifact retained shape".into());}
        for (name,object) in objects {
            let named=open_at(ancestors[3].as_raw_fd(),name,false)?;
            same_named(&object.file,&named,false)?;
        }
        Ok(())
    }
}

#[cfg(test)] mod artifact_tests {
    use super::*;
    #[test] fn modeled_exact_digest_names_bound_and_deduplicate_without_path_authority() {
        assert!(artifact_names(&[]).is_err());assert!(artifact_names(&[[0;32]]).is_err());
        assert!(artifact_names(&vec![[1;32];33]).is_err());
        let names=artifact_names(&[[2;32],[1;32],[2;32]]).unwrap();assert_eq!(names.len(),2);
        assert_eq!(names[0],format!("{}.json",hex::encode([1;32])));
        assert!(names.iter().all(|n|n.len()==69 && !n.contains(['/',':','\\'])));
    }
    #[test] fn modeled_documentary_digest_size_and_foreign_content_refuse() {
        let bytes=b"PUBLIC MODELED RECORD";let pin:[u8;32]=Sha256::digest(bytes).into();
        let name=format!("{}.json",hex::encode(pin));assert_eq!(artifact_digest(&name,bytes).unwrap(),pin);
        for bad in [b"".as_slice(),b"FOREIGN".as_slice(),&vec![b'x';LIMIT+1]] {
            assert!(artifact_digest(&name,bad).is_err());
        }
        for bad in [name.to_uppercase(),format!("../{name}"),format!("{name}:stream")] {
            assert!(artifact_digest(&bad,bytes).is_err());
        }
    }
}
