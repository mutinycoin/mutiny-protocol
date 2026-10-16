//! Separate administrative documentary publication, not clock/service startup.
//! No public CLI, node-writer factory, elevation, directory creation, permission
//! repair, replacement, restart/qualification or historical-authentication grant.
use super::native_nts_calibration_record::LiveCalibrationRecord;
use super::native_nts_deployment_record::DecodedRecord;
type Result<T>=std::result::Result<T,String>;
pub(super) struct DocumentaryPublisher {
    #[cfg(target_os="linux")] owner:linux::Owner,
}
/// Completed documentary publication only; deliberately no authority conversion.
pub(super) struct PublishedDocumentary {pins:Vec<[u8;32]>}
impl PublishedDocumentary {pub(super) fn pins(&self)->&[[u8;32]] {&self.pins}}
impl DocumentaryPublisher {
    pub(super) fn open()->Result<Self> {
        #[cfg(target_os="linux")] {Ok(Self{owner:linux::Owner::open()?})}
        #[cfg(not(target_os="linux"))] {Err("administrative publication native backend unsupported".into())}
    }
    pub(super) fn publish_live(&self,record:&LiveCalibrationRecord,expected:&DecodedRecord)->Result<PublishedDocumentary> {
        record.verify_live(expected).map_err(|_|"live publication context/provenance refused".to_owned())?;
        #[cfg(target_os="linux")] {
            self.owner.recheck()?;let mut pins=Vec::new();
            // Each immutable content-addressed file is published independently.
            // No installation descriptor is committed here. Failure retains
            // every completed object and partial temp, grants no bundle receipt.
            let result:Result<PublishedDocumentary>=(|| {
                for bytes in record.documentary_objects() {pins.push(self.owner.publish(bytes)?);}
                Ok(PublishedDocumentary{pins})
            })();
            let closure=self.owner.recheck();
            match (result,closure) {
                (Ok(value),Ok(()))=>Ok(value),
                (result,closure)=>Err(format!("documentary bundle incomplete; objects retained; outcome={}; closure={closure:?}",
                    match result {Ok(_)=>"all objects individually published".to_owned(),Err(e)=>e})),
            }
        }
        #[cfg(not(target_os="linux"))] {Err("administrative publication native backend unsupported".into())}
    }
}
#[cfg(target_os="linux")]
mod linux {
    use super::*;
    use std::{ffi::CString,fs::File,io::{Read,Seek,SeekFrom,Write},os::{fd::{AsRawFd,FromRawFd},unix::fs::MetadataExt}};
    use sha2::{Digest,Sha256};
    const CHAIN:[&str;3]=["etc","mutiny","native-clock"];
    pub(super) struct Owner {chain:Vec<File>}
    fn check(file:&File,dir:bool)->Result<()> {
        let m=file.metadata().map_err(|e|format!("publication metadata: {e}"))?;
        if m.uid()!=0 || m.mode()&0o022!=0 || (dir && !m.is_dir())
            || (!dir && (!m.is_file() || m.nlink()!=1)) {return Err("unsafe administrative publication object".into());}
        Ok(())
    }
    fn open(parent:i32,name:&str,dir:bool)->Result<File> {
        let name=CString::new(name).map_err(|_|"publication NUL name")?;
        let flags=libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK|if dir {libc::O_DIRECTORY}else{0};
        let fd=unsafe{libc::openat(parent,name.as_ptr(),flags)};
        if fd<0 {return Err(format!("publication native open: {}",std::io::Error::last_os_error()));}
        // Sole owned close-on-exec descriptor, consumed once.
        let file=unsafe{File::from_raw_fd(fd)};check(&file,dir)?;Ok(file)
    }
    fn same(a:&File,b:&File,dir:bool)->Result<()> {
        check(a,dir)?;check(b,dir)?;
        let x=a.metadata().map_err(|e|e.to_string())?;let y=b.metadata().map_err(|e|e.to_string())?;
        if (x.dev(),x.ino())!=(y.dev(),y.ino()) {return Err("administrative publication name replaced".into());}Ok(())
    }
    impl Owner {
        pub(super) fn open()->Result<Self> {
            // Separate admin tool context only. Ordinary node reader requires
            // non-root and cannot acquire this writer; no auto elevation exists.
            if unsafe{libc::geteuid()}!=0 {return Err("documentary publisher requires existing root installation authority".into());}
            let mut chain=vec![open(libc::AT_FDCWD,"/",true)?];
            for name in CHAIN {chain.push(open(chain.last().unwrap().as_raw_fd(),name,true)?);}
            let owner=Self{chain};owner.recheck()?;Ok(owner)
        }
        pub(super) fn recheck(&self)->Result<()> {
            if unsafe{libc::geteuid()}!=0 || self.chain.len()!=4 {return Err("publication authority/shape changed".into());}
            let mut named=vec![open(libc::AT_FDCWD,"/",true)?];same(&self.chain[0],&named[0],true)?;
            for (index,name) in CHAIN.iter().enumerate() {
                let f=open(named.last().unwrap().as_raw_fd(),name,true)?;same(&self.chain[index+1],&f,true)?;named.push(f);
            }
            for (index,name) in CHAIN.iter().enumerate() {
                let f=open(named[index].as_raw_fd(),name,true)?;same(&named[index+1],&f,true)?;
            }
            Ok(())
        }
        pub(super) fn publish(&self,bytes:&[u8])->Result<[u8;32]> {
            self.recheck()?;
            if bytes.is_empty() || bytes.len()>64*1024 {return Err("publication byte bound".into());}
            // Canonical exact local grammar checked before any mutation.
            super::super::native_nts_deployment_record::canonical_value(bytes)
                .map_err(|_|"publication canonical record refused".to_owned())?;
            let pin:[u8;32]=Sha256::digest(bytes).into();
            if pin==[0;32] {return Err("publication zero digest refused".into());}
            let target=format!("{}.json",hex::encode(pin));
            let mut salt=[0u8;16];getrandom::getrandom(&mut salt).map_err(|e|format!("publication OS random: {e}"))?;
            let partial=format!(".{}.publication-{}.partial",hex::encode(pin),hex::encode(salt));
            let cpartial=CString::new(partial.as_str()).map_err(|_|"publication partial name")?;
            let ctarget=CString::new(target.as_str()).map_err(|_|"publication target name")?;
            let parent=self.chain[3].as_raw_fd();
            let fd=unsafe{libc::openat(parent,cpartial.as_ptr(),libc::O_RDWR|libc::O_CREAT|libc::O_EXCL|
                libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK,0o644)};
            if fd<0 {return Err(format!("publication create-new refused: {}",std::io::Error::last_os_error()));}
            let mut file=unsafe{File::from_raw_fd(fd)};
            // Every failure after creation preserves the partial and reports its
            // public leaf. There is no unlink/cleanup or replacement fallback.
            let outcome:Result<[u8;32]>=(|| {
                check(&file,false)?;file.write_all(bytes).map_err(|e|format!("write: {e}"))?;
                file.sync_all().map_err(|e|format!("file sync: {e}"))?;
                file.seek(SeekFrom::Start(0)).map_err(|e|format!("seek: {e}"))?;
                let mut actual=Vec::new();(&mut file).take(64*1024+1).read_to_end(&mut actual).map_err(|e|format!("readback: {e}"))?;
                if actual!=bytes || file.metadata().map_err(|e|e.to_string())?.len()!=bytes.len() as u64 {
                    return Err("publication exact readback mismatch".into());
                }
                same(&file,&open(parent,&partial,false)?,false)?;self.recheck()?;
                // Same-directory NOREPLACE, no fallback/no old target deletion.
                if unsafe{libc::renameat2(parent,cpartial.as_ptr(),parent,ctarget.as_ptr(),libc::RENAME_NOREPLACE)}!=0 {
                    return Err(format!("publication no-replace: {}",std::io::Error::last_os_error()));
                }
                same(&file,&open(parent,&target,false)?,false)?;
                self.chain[3].sync_all().map_err(|e|format!("parent directory sync: {e}"))?;
                self.recheck()?;same(&file,&open(parent,&target,false)?,false)?;Ok(pin)
            })();
            let closure=self.recheck();
            match (outcome,closure) {
                (Ok(pin),Ok(()))=>Ok(pin),
                (outcome,closure)=>Err(format!("publication incomplete; retained partial/final {partial}/{target}; outcome={outcome:?}; closure={closure:?}")),
            }
        }
    }
}
