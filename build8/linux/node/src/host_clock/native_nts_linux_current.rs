//! Supported Linux software observation, not hardware qualification/attestation.
//! Fixed protected public installation objects and this actual process only.
//! No external command, wall clock, caller path fallback, write or ACL repair.
use super::native_nts_deployment_record::{canonical_value,DecodedRecord,Error};
use super::native_nts_qualification::CurrentContract;
use serde_json::{Value,Map};
use sha2::{Digest,Sha256};
use std::collections::{BTreeMap,BTreeSet};
use std::{ffi::{CString,OsString},fs::File,io::{Read,Seek,SeekFrom},
    os::{fd::{AsRawFd,FromRawFd},unix::{ffi::OsStrExt,fs::MetadataExt}},path::{Path,PathBuf}};
type Result<T>=std::result::Result<T,Error>;
const CONFIG_LIMIT:u64=64*1024;
const PROC_MAGIC:libc::c_long=0x9fa0;
const NS_MAGIC:libc::c_long=0x6e736673;
const NAMES:[&str;5]=["mnt","pid","user","uts","time"];
#[derive(Clone,PartialEq,Eq)]
struct Identity {device:u64,inode:u64,uid:u32,mode:u32,links:u64,size:u64,
    modified:(i64,i64),changed:(i64,i64)}
impl Identity {fn close_pin(&self)->[u8;24]{let mut pin=[0;24];
    pin[..8].copy_from_slice(&self.device.to_le_bytes());pin[8..16].copy_from_slice(&self.inode.to_le_bytes());
    pin[16..24].copy_from_slice(&self.links.to_le_bytes());pin}}
fn identity(file:&File,directory:bool)->Result<Identity> {
    let m=file.metadata().map_err(|_|Error::UnsupportedCurrentFacts)?;
    Ok(Identity {device:m.dev(),inode:m.ino(),uid:m.uid(),mode:m.mode(),links:m.nlink(),
        size:if directory {0}else{m.len()},modified:if directory {(0,0)}else{(m.mtime(),m.mtime_nsec())},
        changed:if directory {(0,0)}else{(m.ctime(),m.ctime_nsec())}})
}
fn protected(file:&File,directory:bool)->Result<()> {
    let m=file.metadata().map_err(|_|Error::UnsupportedCurrentFacts)?;
    if m.uid()!=0 || m.mode()&0o022!=0 || (directory && !m.is_dir())
        || (!directory && (!m.is_file() || m.nlink()!=1)) {return Err(Error::UnsupportedCurrentFacts);}
    Ok(())
}
fn open_at(parent:i32,name:&std::ffi::OsStr,directory:bool,nofollow:bool)->Result<File> {
    let name=CString::new(name.as_bytes()).map_err(|_|Error::UnsupportedCurrentFacts)?;
    let flags=libc::O_CLOEXEC|if nofollow {libc::O_NOFOLLOW}else{0}
        |if directory {libc::O_PATH|libc::O_DIRECTORY}else{libc::O_RDONLY|libc::O_NONBLOCK};
    // SAFETY: exact native open flags, initialized C name, result owned once.
    let fd=unsafe{libc::openat(parent,name.as_ptr(),flags)};
    if fd<0 {return Err(Error::UnsupportedCurrentFacts);}
    Ok(unsafe{File::from_raw_fd(fd)})
}
fn fs_kind(file:&File,expected:libc::c_long)->Result<()> {
    let mut fs=std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: live descriptor, correctly sized output; read only on success.
    if unsafe{libc::fstatfs(file.as_raw_fd(),fs.as_mut_ptr())}!=0
        || unsafe{fs.assume_init()}.f_type!=expected {return Err(Error::UnsupportedCurrentFacts);}
    Ok(())
}
/// Root-owned, non-writer-writable, no-follow chain retained through service use.
struct PublicObject {path:PathBuf,dirs:Vec<File>,dir_ids:Vec<[u8;24]>,file:File,initial:Identity}
impl PublicObject {
    fn retained_file_count(&self)->usize {1+self.dirs.len()}
    fn close_retained_into(self,report:&mut super::native_retained_close::RetainedCloseReport) {
        let Self{file,dirs,dir_ids,initial,..}=self;report.file(file,initial.close_pin());
        for (file,pin) in dirs.into_iter().zip(dir_ids).rev(){report.file(file,pin);}
    }
    fn open(path:&Path)->Result<Self> {
        let text=path.to_str().ok_or(Error::UnsupportedCurrentFacts)?;
        let names=path.components().map(|c|match c {std::path::Component::RootDir=>Ok(None),
            std::path::Component::Normal(n)=>Ok(Some(n.to_owned())),_=>Err(Error::UnsupportedCurrentFacts)})
            .collect::<Result<Vec<_>>>()?.into_iter().flatten().collect::<Vec<OsString>>();
        let reconstructed=format!("/{}",names.iter().map(|n|n.to_str().ok_or(Error::UnsupportedCurrentFacts))
            .collect::<Result<Vec<_>>>()?.join("/"));
        if !path.is_absolute() || names.is_empty() || text!=reconstructed {return Err(Error::UnsupportedCurrentFacts);}
        let root=open_at(libc::AT_FDCWD,std::ffi::OsStr::new("/"),true,true)?;protected(&root,true)?;
        let mut dirs=vec![root];
        for name in &names[..names.len()-1] {
            let dir=open_at(dirs.last().unwrap().as_raw_fd(),name,true,true)?;protected(&dir,true)?;dirs.push(dir);
        }
        let file=open_at(dirs.last().unwrap().as_raw_fd(),names.last().unwrap(),false,true)?;
        protected(&file,false)?;let initial=identity(&file,false)?;
        let dir_ids=dirs.iter().map(|file|identity(file,true).map(|id|id.close_pin())).collect::<Result<Vec<_>>>()?;
        Ok(Self{path:path.to_owned(),dirs,dir_ids,file,initial})
    }
    fn recheck(&self)->Result<()> {
        let now=Self::open(&self.path)?;
        if self.initial!=identity(&self.file,false)? || self.initial!=now.initial || now.dirs.len()!=self.dirs.len() {
            return Err(Error::UnsupportedCurrentFacts);
        }
        for (a,b) in self.dirs.iter().zip(&now.dirs) {
            protected(a,true)?;if identity(a,true)?!=identity(b,true)? {return Err(Error::UnsupportedCurrentFacts);}
        }
        protected(&self.file,false)
    }
    fn bytes(&mut self,maximum:u64)->Result<Vec<u8>> {
        self.recheck()?;
        if self.initial.size==0 || self.initial.size>maximum {return Err(Error::UnsupportedCurrentFacts);}
        self.file.seek(SeekFrom::Start(0)).map_err(|_|Error::UnsupportedCurrentFacts)?;
        let mut raw=Vec::new();self.file.by_ref().take(maximum.checked_add(1).ok_or(Error::Bound)?)
            .read_to_end(&mut raw).map_err(|_|Error::UnsupportedCurrentFacts)?;
        if raw.len() as u64!=self.initial.size {return Err(Error::UnsupportedCurrentFacts);}
        self.recheck()?;Ok(raw)
    }
    fn hash(&mut self,expected_size:u64)->Result<[u8;32]> {
        self.recheck()?;
        if expected_size==0 || self.initial.size!=expected_size {return Err(Error::UnsupportedCurrentFacts);}
        self.file.seek(SeekFrom::Start(0)).map_err(|_|Error::UnsupportedCurrentFacts)?;
        // Constant memory, finite EXACT independently installed manifest length;
        // no hostile BLOB allocation or arbitrary EOF-length acceptance.
        let mut remaining=expected_size;let mut hash=Sha256::new();let mut block=[0u8;65536];
        while remaining!=0 {
            let capacity=std::cmp::min(remaining,block.len() as u64) as usize;
            let n=self.file.read(&mut block[..capacity]).map_err(|_|Error::UnsupportedCurrentFacts)?;
            if n==0 {return Err(Error::UnsupportedCurrentFacts);}hash.update(&block[..n]);remaining-=n as u64;
        }
        let mut extra=[0];if self.file.read(&mut extra).map_err(|_|Error::UnsupportedCurrentFacts)?!=0 {return Err(Error::UnsupportedCurrentFacts);}
        self.recheck()?;Ok(hash.finalize().into())
    }
}
fn exact<'a>(v:&'a Value,keys:&[&str])->Result<&'a Map<String,Value>> {
    let m=v.as_object().ok_or(Error::UnsupportedCurrentFacts)?;
    if m.len()!=keys.len() || m.keys().any(|k|!keys.contains(&k.as_str())) {return Err(Error::UnsupportedCurrentFacts);}Ok(m)
}
fn digest(v:&Value)->Result<[u8;32]> {
    let text=v.as_str().ok_or(Error::UnsupportedCurrentFacts)?;let mut hash=[0;32];
    if text.len()!=64 || !text.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || hex::decode_to_slice(text,&mut hash).is_err() || hash==[0;32] {return Err(Error::UnsupportedCurrentFacts);}Ok(hash)
}
fn read_proc(file:&mut File)->Result<Vec<u8>> {
    fs_kind(file,PROC_MAGIC)?;file.seek(SeekFrom::Start(0)).map_err(|_|Error::UnsupportedCurrentFacts)?;
    let mut raw=Vec::new();file.by_ref().take(CONFIG_LIMIT+1).read_to_end(&mut raw).map_err(|_|Error::UnsupportedCurrentFacts)?;
    if raw.len() as u64>CONFIG_LIMIT {return Err(Error::Bound);}Ok(raw)
}
fn boot_id(raw:&[u8])->Result<u128> {
    if raw.len()!=37 || raw[36]!=b'\n' {return Err(Error::UnsupportedCurrentFacts);}
    for (i,b) in raw[..36].iter().copied().enumerate() {
        if [8,13,18,23].contains(&i) {if b!=b'-' {return Err(Error::UnsupportedCurrentFacts);}}
        else if !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b) {return Err(Error::UnsupportedCurrentFacts);}
    }
    let text=std::str::from_utf8(&raw[..36]).map_err(|_|Error::UnsupportedCurrentFacts)?;
    let id=super::parse_boot_id(text).ok_or(Error::UnsupportedCurrentFacts)?;
    if id==0 {return Err(Error::UnsupportedCurrentFacts);}Ok(id)
}
fn process_start(raw:&[u8],pid:u32)->Result<u64> {
    let text=std::str::from_utf8(raw).map_err(|_|Error::UnsupportedCurrentFacts)?;
    let begin=text.find(" (").ok_or(Error::UnsupportedCurrentFacts)?;
    if text[..begin].parse::<u32>().ok()!=Some(pid) {return Err(Error::UnsupportedCurrentFacts);}
    let end=text.rfind(") ").ok_or(Error::UnsupportedCurrentFacts)?;
    if end<=begin {return Err(Error::UnsupportedCurrentFacts);}
    let fields=text[end+2..].split_ascii_whitespace().collect::<Vec<_>>();
    let start=fields.get(19).and_then(|n|n.parse::<u64>().ok()).ok_or(Error::UnsupportedCurrentFacts)?;
    if start==0 {return Err(Error::UnsupportedCurrentFacts);}Ok(start)
}
#[derive(Clone,PartialEq,Eq)]
struct ProcessScope {pid:u32,start:u64,proc_device:u64,proc_inode:u64,namespaces:Value}
struct ProcOwner {root:File,pid:File,ns:File,namespace_pins:Vec<File>,boot_dirs:Vec<File>,boot:File,stat:File,
    original_close_pins:Vec<[u8;24]>,scope:ProcessScope}
impl ProcOwner {
    fn open()->Result<Self> {
        // Root/namespace administrator compromise is outside the adopted writer
        // claim. A writer acquiring uid0 refuses, not an independent installation.
        let uid=unsafe{libc::geteuid()};if uid==0 {return Err(Error::UnsupportedCurrentFacts);}
        let root=PublicObject::open(Path::new("/proc/sys/kernel/random/boot_id"))?;
        // PublicObject verifies all root-owned no-follow ancestors and proc file.
        for f in root.dirs.iter().skip(1) {fs_kind(f,PROC_MAGIC)?;}
        fs_kind(&root.file,PROC_MAGIC)?;
        let proc=open_at(root.dirs[0].as_raw_fd(),std::ffi::OsStr::new("proc"),true,true)?;
        protected(&proc,true)?;fs_kind(&proc,PROC_MAGIC)?;
        if identity(&proc,true)?!=identity(&root.dirs[1],true)? {return Err(Error::UnsupportedCurrentFacts);}
        let actual=unsafe{libc::getpid()};if actual<=0 {return Err(Error::UnsupportedCurrentFacts);}
        let mut name=[0u8;64];
        // Kernel-generated self link ONLY on verified procfs, never ordinary
        // source/installation symlink relaxation. Must name this actual PID.
        let count=unsafe{libc::readlinkat(proc.as_raw_fd(),c"self".as_ptr(),name.as_mut_ptr().cast(),name.len())};
        if count<=0 || count as usize>=name.len()
            || std::str::from_utf8(&name[..count as usize]).ok().and_then(|s|s.parse::<i32>().ok())!=Some(actual) {
            return Err(Error::UnsupportedCurrentFacts);
        }
        let pid=open_at(proc.as_raw_fd(),std::ffi::OsStr::new(&actual.to_string()),true,true)?;
        let pm=pid.metadata().map_err(|_|Error::UnsupportedCurrentFacts)?;
        if !pm.is_dir() || pm.uid()!=uid || pm.mode()&0o022!=0 {return Err(Error::UnsupportedCurrentFacts);}
        fs_kind(&pid,PROC_MAGIC)?;
        let ns=open_at(pid.as_raw_fd(),std::ffi::OsStr::new("ns"),true,true)?;fs_kind(&ns,PROC_MAGIC)?;
        let mut stat=open_at(pid.as_raw_fd(),std::ffi::OsStr::new("stat"),false,true)?;
        let start=process_start(&read_proc(&mut stat)?,actual as u32)?;
        let rm=proc.metadata().map_err(|_|Error::UnsupportedCurrentFacts)?;
        let mut ids=Map::new();let mut namespace_pins=Vec::new();
        for name in NAMES {
            // Exact kernel namespace magic links, separately typed NSFS inputs.
            let f=open_at(ns.as_raw_fd(),std::ffi::OsStr::new(name),false,false)?;fs_kind(&f,NS_MAGIC)?;
            let m=f.metadata().map_err(|_|Error::UnsupportedCurrentFacts)?;
            ids.insert(name.into(),serde_json::json!({"device":m.dev(),"inode":m.ino()}));
            namespace_pins.push(f);
        }
        // Original exact roster is authenticated/captured before publication,
        // not reconstructed from possibly failing shutdown observations.
        let original_close_pins=std::iter::once(&stat).chain(std::iter::once(&root.file))
            .chain(namespace_pins.iter()).chain([&ns,&pid,&proc]).chain(root.dirs.iter().rev())
            .map(|file|super::native_retained_close::retained_identity(file).map_err(|_|Error::UnsupportedCurrentFacts))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self{root:proc,pid,ns,namespace_pins,boot_dirs:root.dirs,boot:root.file,stat,original_close_pins,
            scope:ProcessScope{pid:actual as u32,start,proc_device:rm.dev(),proc_inode:rm.ino(),namespaces:Value::Object(ids)}})
    }
    fn recheck(&mut self)->Result<()> {
        let mut now=Self::open()?;
        if now.scope!=self.scope || identity(&self.root,true)?!=identity(&now.root,true)?
            || identity(&self.pid,true)?!=identity(&now.pid,true)? || identity(&self.ns,true)?!=identity(&now.ns,true)?
            || identity(&self.boot,false)?!=identity(&now.boot,false)? || identity(&self.stat,false)?!=identity(&now.stat,false)?
            || self.namespace_pins.len()!=now.namespace_pins.len() || self.boot_dirs.len()!=now.boot_dirs.len() {
            return Err(Error::UnsupportedCurrentFacts);
        }
        for (a,b) in self.boot_dirs.iter().zip(&now.boot_dirs) {if identity(a,true)?!=identity(b,true)? {return Err(Error::UnsupportedCurrentFacts);}}
        for (a,b) in self.namespace_pins.iter().zip(&now.namespace_pins) {
            fs_kind(a,NS_MAGIC)?;if identity(a,false)?!=identity(b,false)? {return Err(Error::UnsupportedCurrentFacts);}
        }
        if process_start(&read_proc(&mut self.stat)?,self.scope.pid)?!=self.scope.start
            || boot_id(&read_proc(&mut self.boot)?)?!=boot_id(&read_proc(&mut now.boot)?)? {return Err(Error::UnsupportedCurrentFacts);}Ok(())
    }
    fn image(&self)->Result<File> {
        // This is the verified kernel-generated link for the retained actual PID
        // plus start tuple, not /proc/<caller>/exe or a current_exe pathname.
        open_at(self.pid.as_raw_fd(),std::ffi::OsStr::new("exe"),false,false)
    }
}
fn os()->Result<Value> {
    let mut raw=std::mem::MaybeUninit::<libc::utsname>::zeroed();
    if unsafe{libc::uname(raw.as_mut_ptr())}!=0 {return Err(Error::UnsupportedCurrentFacts);}
    let raw=unsafe{raw.assume_init()};
    let text=|bytes:&[libc::c_char]|->Result<String> {
        let end=bytes.iter().position(|b|*b==0).ok_or(Error::UnsupportedCurrentFacts)?;
        let bytes=bytes[..end].iter().map(|b|*b as u8).collect::<Vec<_>>();
        let value=String::from_utf8(bytes).map_err(|_|Error::UnsupportedCurrentFacts)?;
        if value.is_empty() {return Err(Error::UnsupportedCurrentFacts);}Ok(value)
    };
    let sysname=text(&raw.sysname)?;let machine=text(&raw.machine)?;
    if sysname!="Linux" || machine!="x86_64" {return Err(Error::UnsupportedCurrentFacts);}
    Ok(serde_json::json!({"target":"linux-x86_64","sysname":sysname,"machine":machine,
        "release":text(&raw.release)?,"version":text(&raw.version)?}))
}
fn counter(clock:libc::clockid_t)->Result<u64> {
    let mut t=std::mem::MaybeUninit::<libc::timespec>::zeroed();
    if unsafe{libc::clock_gettime(clock,t.as_mut_ptr())}!=0 {return Err(Error::UnsupportedCurrentFacts);}
    let t=unsafe{t.assume_init()};if t.tv_sec<0 || !(0..1_000_000_000).contains(&t.tv_nsec) {return Err(Error::UnsupportedCurrentFacts);}
    (t.tv_sec as u64).checked_mul(1_000_000_000).and_then(|n|n.checked_add(t.tv_nsec as u64)).ok_or(Error::UnsupportedCurrentFacts)
}
fn checked_sample(a:u64,b:u64,c:u64,maximum:u64,boot:u128)->Result<(u64,u64,u128)> {
    let span=c.checked_sub(a).ok_or(Error::UnsupportedCurrentFacts)?;
    if a==0 || b<a || maximum==0 || boot==0 || span>maximum {return Err(Error::UnsupportedCurrentFacts);}
    // Use the actually observed left active endpoint for this continuity gate.
    // BOOTTIME was read between a and c; a midpoint can exceed b on a no-suspend
    // system. This does not replace the acquisition adapter's midpoint/error
    // interval or assert that these distinct reads were simultaneous.
    Ok((a,b,boot))
}
fn sample(maximum:u64,boot:u128)->Result<(u64,u64,u128)> {
    let a=counter(libc::CLOCK_MONOTONIC)?;let b=counter(libc::CLOCK_BOOTTIME)?;let c=counter(libc::CLOCK_MONOTONIC)?;
    checked_sample(a,b,c,maximum,boot)
}
#[derive(Clone)]
struct Observation {os:Value,boot:u128,first:(u64,u64,u128),last:(u64,u64,u128)}
#[derive(Clone,Debug,PartialEq,Eq,PartialOrd,Ord)]
struct Mapping {offset:u64,length:u64,permissions:String}
struct LoadedObject {object:PublicObject,bytes:u64,pin:[u8;32],mappings:Vec<Mapping>}
/// A selected current loaded-object roster, not source-build or physical proof.
/// Every mapped file, including the native loader/DSOs, must be in the exact
/// administrator-selected roster. ASLR virtual addresses are not identity.
struct LoadedBoundary {
    descriptor:PublicObject,pin:[u8;32],objects:BTreeMap<String,LoadedObject>,
    kernel:BTreeMap<String,Vec<Mapping>>,
}
fn mappings(value:&Value)->Result<Vec<Mapping>> {
    let values=value.as_array().ok_or(Error::UnsupportedCurrentFacts)?;
    if values.is_empty() {return Err(Error::UnsupportedCurrentFacts);}
    let mut result=Vec::new();
    for value in values {
        let fields=exact(value,&["offset","length","permissions"])?;
        let offset=fields["offset"].as_u64().ok_or(Error::UnsupportedCurrentFacts)?;
        let length=fields["length"].as_u64().ok_or(Error::UnsupportedCurrentFacts)?;
        let permissions=fields["permissions"].as_str().ok_or(Error::UnsupportedCurrentFacts)?;
        if length==0 || offset.checked_add(length).is_none() || !matches!(permissions,
            "r--p"|"r-xp"|"rw-p"|"---p"|"r--s"|"r-xs"|"rw-s"|"---s") {
            return Err(Error::UnsupportedCurrentFacts);
        }
        result.push(Mapping{offset,length,permissions:permissions.to_owned()});
    }
    result.sort();
    if result.windows(2).any(|v|v[0]==v[1]) {return Err(Error::UnsupportedCurrentFacts);}
    Ok(result)
}
impl LoadedBoundary {
    fn open(pin:[u8;32],source_receipt:[u8;32])->Result<Self> {
        let mut descriptor=PublicObject::open(Path::new("/etc/mutiny/native-clock/release-loaded.json"))?;
        let raw=descriptor.bytes(CONFIG_LIMIT)?;
        if <[u8;32]>::from(Sha256::digest(&raw))!=pin {return Err(Error::UnsupportedCurrentFacts);}
        let value=canonical_value(&raw)?;
        let fields=exact(&value,&["format","target","source_receipt_sha256","objects","kernel_mappings"])?;
        if fields["format"].as_str()!=Some("build8/native-nts/loaded-v1")
            || fields["target"].as_str()!=Some("linux-x86_64")
            || digest(&fields["source_receipt_sha256"])?!=source_receipt {return Err(Error::UnsupportedCurrentFacts);}
        let selected=fields["objects"].as_object().ok_or(Error::UnsupportedCurrentFacts)?;
        if selected.is_empty() {return Err(Error::UnsupportedCurrentFacts);}
        let mut objects=BTreeMap::new();let mut identities=BTreeSet::new();
        for (key,value) in selected {
            let fields=exact(value,&["path","bytes","sha256","mappings"])?;
            let object_pin=digest(&fields["sha256"])?;
            if key!=&hex::encode(object_pin) {return Err(Error::UnsupportedCurrentFacts);}
            let path=fields["path"].as_str().ok_or(Error::UnsupportedCurrentFacts)?;
            // /proc maps renders deleted/unusual path encodings ambiguously;
            // refuse them rather than inventing an alternate equivalence.
            if path.bytes().any(|b|b.is_ascii_whitespace() || b==b'\\') || path.contains("(deleted)") {
                return Err(Error::UnsupportedCurrentFacts);
            }
            let bytes=fields["bytes"].as_u64().ok_or(Error::UnsupportedCurrentFacts)?;
            let mut object=PublicObject::open(Path::new(path))?;
            if object.hash(bytes)?!=object_pin || !identities.insert((object.initial.device,object.initial.inode)) {
                return Err(Error::UnsupportedCurrentFacts);
            }
            let selected_mappings=mappings(&fields["mappings"])?;
            if objects.insert(path.to_owned(),LoadedObject{object,bytes,pin:object_pin,mappings:selected_mappings}).is_some() {
                return Err(Error::UnsupportedCurrentFacts);
            }
        }
        let mut kernel=BTreeMap::new();
        for (name,value) in fields["kernel_mappings"].as_object().ok_or(Error::UnsupportedCurrentFacts)? {
            if !matches!(name.as_str(),"[vdso]"|"[vsyscall]") {return Err(Error::UnsupportedCurrentFacts);}
            let selected=mappings(value)?;
            if selected.iter().any(|m|m.offset!=0 || m.permissions.contains('w')) {return Err(Error::UnsupportedCurrentFacts);}
            kernel.insert(name.clone(),selected);
        }
        Ok(Self{descriptor,pin,objects,kernel})
    }
    fn recheck(&mut self,proc:&mut ProcOwner)->Result<()> {
        proc.recheck()?;self.descriptor.recheck()?;
        if <[u8;32]>::from(Sha256::digest(self.descriptor.bytes(CONFIG_LIMIT)?))!=self.pin {
            return Err(Error::UnsupportedCurrentFacts);
        }
        for entry in self.objects.values_mut() {
            if entry.object.hash(entry.bytes)?!=entry.pin {return Err(Error::UnsupportedCurrentFacts);}
        }
        let read_maps=|proc:&ProcOwner|->Result<Vec<u8>> {
            let mut file=open_at(proc.pid.as_raw_fd(),std::ffi::OsStr::new("maps"),false,true)?;
            read_proc(&mut file)
        };
        {
        let inspect=|raw:&[u8]|->Result<()> {
        let text=std::str::from_utf8(&raw).map_err(|_|Error::UnsupportedCurrentFacts)?;
        let mut objects:BTreeMap<String,Vec<Mapping>>=BTreeMap::new();
        let mut kernel:BTreeMap<String,Vec<Mapping>>=BTreeMap::new();
        for line in text.lines() {
            let fields:Vec<_>=line.split_whitespace().collect();
            if fields.len()<5 || fields.len()>6 {return Err(Error::UnsupportedCurrentFacts);}
            let (a,b)=fields[0].split_once('-').ok_or(Error::UnsupportedCurrentFacts)?;
            let begin=u64::from_str_radix(a,16).map_err(|_|Error::UnsupportedCurrentFacts)?;
            let end=u64::from_str_radix(b,16).map_err(|_|Error::UnsupportedCurrentFacts)?;
            let length=end.checked_sub(begin).filter(|v|*v!=0).ok_or(Error::UnsupportedCurrentFacts)?;
            let permissions=fields[1];
            if !permissions.is_ascii() || permissions.len()!=4 || !matches!(&permissions[0..1],"r"|"-")
                || !matches!(&permissions[1..2],"w"|"-") || !matches!(&permissions[2..3],"x"|"-")
                || !matches!(&permissions[3..4],"p"|"s") || (permissions.contains('w') && permissions.contains('x')) {
                return Err(Error::UnsupportedCurrentFacts);
            }
            let offset=u64::from_str_radix(fields[2],16).map_err(|_|Error::UnsupportedCurrentFacts)?;
            let inode=fields[4].parse::<u64>().map_err(|_|Error::UnsupportedCurrentFacts)?;
            let mapping=Mapping{offset,length,permissions:permissions.to_owned()};
            let path=fields.get(5).copied().unwrap_or("");
            if inode==0 {
                if permissions.contains('x') {
                    if !self.kernel.contains_key(path) {return Err(Error::UnsupportedCurrentFacts);}
                    kernel.entry(path.to_owned()).or_default().push(mapping);
                }
                continue;
            }
            let selected=self.objects.get(path).ok_or(Error::UnsupportedCurrentFacts)?;
            let (major,minor)=fields[3].split_once(':').ok_or(Error::UnsupportedCurrentFacts)?;
            let major=u64::from_str_radix(major,16).map_err(|_|Error::UnsupportedCurrentFacts)?;
            let minor=u64::from_str_radix(minor,16).map_err(|_|Error::UnsupportedCurrentFacts)?;
            if inode!=selected.object.initial.inode
                || major!=libc::major(selected.object.initial.device) as u64
                || minor!=libc::minor(selected.object.initial.device) as u64 {return Err(Error::UnsupportedCurrentFacts);}
            objects.entry(path.to_owned()).or_default().push(mapping);
        }
        for values in objects.values_mut().chain(kernel.values_mut()) {values.sort();}
        if objects.len()!=self.objects.len() || kernel!=self.kernel
            || self.objects.iter().any(|(path,entry)|objects.get(path)!=Some(&entry.mappings)) {
            return Err(Error::UnsupportedCurrentFacts);
        }
        Ok(())
        };
        inspect(&read_maps(proc)?)?;
        proc.recheck()?;
        // Reconstruct the same selected roster on BOTH observations. Anonymous
        // non-executable heap/stack growth is not code identity; every anonymous
        // executable mapping is still examined and refused unless exact kernel.
        inspect(&read_maps(proc)?)?;
        }
        for entry in self.objects.values_mut() {entry.object.recheck()?;}
        self.descriptor.recheck()?;proc.recheck()
    }
}
fn require_progress(before:&Observation,fresh:&Observation)->Result<()> {
    if fresh.os!=before.os || fresh.boot!=before.boot || fresh.first.2!=fresh.boot || fresh.last.2!=fresh.boot
        || fresh.first.0==0 || fresh.first.1<fresh.first.0 || fresh.last.1<fresh.last.0
        || fresh.last.0<fresh.first.0 || fresh.last.1<fresh.first.1
        || fresh.first.0<before.last.0 || fresh.first.1<before.last.1 {return Err(Error::UnsupportedCurrentFacts);}Ok(())
}
pub(super) struct LinuxBoundary {record:Vec<u8>,contract:CurrentContract,release:PublicObject,
    source:PublicObject,exe:PublicObject,proc:ProcOwner,last:Observation,code:[u8;32],source_hash:[u8;32],size:u64,exe_hash:[u8;32],loaded:Option<LoadedBoundary>}
impl LinuxBoundary {
    pub(super) fn close_retained(self)->std::result::Result<super::native_retained_close::RetainedCloseReport,Self> {
        let base=5usize; // Proc root, PID, namespace directory, boot, stat.
        if self.proc.original_close_pins.len()!=base+self.proc.namespace_pins.len()+self.proc.boot_dirs.len(){return Err(self);}
        let mut count=match base.checked_add(self.proc.namespace_pins.len()).and_then(|n|n.checked_add(self.proc.boot_dirs.len()))
            .and_then(|n|n.checked_add(self.release.retained_file_count())).and_then(|n|n.checked_add(self.source.retained_file_count()))
            .and_then(|n|n.checked_add(self.exe.retained_file_count())){Some(n)=>n,None=>return Err(self)};
        if let Some(loaded)=&self.loaded{
            count=match count.checked_add(loaded.descriptor.retained_file_count()){Some(n)=>n,None=>return Err(self)};
            for object in loaded.objects.values(){count=match count.checked_add(object.object.retained_file_count()){Some(n)=>n,None=>return Err(self)};}
        }
        let mut report=match super::native_retained_close::RetainedCloseReport::prepare(count){Ok(r)=>r,Err(_)=>return Err(self)};
        let Self{release,source,exe,proc,loaded,..}=self;
        release.close_retained_into(&mut report);source.close_retained_into(&mut report);exe.close_retained_into(&mut report);
        if let Some(loaded)=loaded{loaded.descriptor.close_retained_into(&mut report);
            for (_,object) in loaded.objects{object.object.close_retained_into(&mut report);}}
        let ProcOwner{root,pid,ns,namespace_pins,boot_dirs,boot,stat,original_close_pins,..}=proc;
        let mut pins=original_close_pins.into_iter();
        report.file(stat,pins.next().expect("original stat pin"));report.file(boot,pins.next().expect("original boot pin"));
        for file in namespace_pins{report.file(file,pins.next().expect("original namespace pin"));}
        report.file(ns,pins.next().expect("original namespace directory pin"));
        report.file(pid,pins.next().expect("original PID directory pin"));
        report.file(root,pins.next().expect("original proc root pin"));
        for file in boot_dirs.into_iter().rev(){report.file(file,pins.next().expect("original boot ancestor pin"));}
        Ok(report)
    }
}
impl LinuxBoundary {
    pub(super) fn open(record:&DecodedRecord,contract:&CurrentContract)->Result<Self> {
        let mut release=PublicObject::open(Path::new("/etc/mutiny/native-clock/release.json"))?;
        let raw=release.bytes(CONFIG_LIMIT)?;let value=canonical_value(&raw)?;
        let format=value["format"].as_str().ok_or(Error::UnsupportedCurrentFacts)?;
        let r=if format=="build8/native-nts/release-v1" {
            exact(&value,&["format","target","executable_path","executable_sha256","executable_bytes",
                "source_receipt_sha256","proc_root","namespaces"])?
        }else if format=="build8/native-nts/release-v2" {
            exact(&value,&["format","target","executable_path","executable_sha256","executable_bytes",
                "source_receipt_sha256","proc_root","namespaces","loaded_sha256"])?
        }else{return Err(Error::UnsupportedCurrentFacts);};
        if r["target"].as_str()!=Some("linux-x86_64") {return Err(Error::UnsupportedCurrentFacts);}
        let deployment=canonical_value(record.canonical())?;let code: [u8;32]=Sha256::digest(&raw).into();
        if digest(&deployment["context"]["code_sha256"])?!=code {return Err(Error::UnsupportedCurrentFacts);}
        let mut source=PublicObject::open(Path::new("/etc/mutiny/native-clock/release-source.json"))?;
        let source_raw=source.bytes(CONFIG_LIMIT)?;
        let source_hash:[u8;32]=Sha256::digest(&source_raw).into();
        if source_hash!=digest(&r["source_receipt_sha256"])? {return Err(Error::UnsupportedCurrentFacts);}
        let source_value=canonical_value(&source_raw)?;
        let s=exact(&source_value,&["format","target","source_tree_sha256","build_recipe_sha256","toolchain_sha256","executable_sha256"])?;
        if s["format"].as_str()!=Some("build8/native-nts/release-source-v1") || s["target"]!=r["target"] {return Err(Error::UnsupportedCurrentFacts);}
        for field in ["source_tree_sha256","build_recipe_sha256","toolchain_sha256"] {digest(&s[field])?;}
        let exe_hash=digest(&r["executable_sha256"])?;
        if digest(&s["executable_sha256"])?!=exe_hash {return Err(Error::UnsupportedCurrentFacts);}
        let size=r["executable_bytes"].as_u64().ok_or(Error::UnsupportedCurrentFacts)?;
        let mut exe=PublicObject::open(Path::new(r["executable_path"].as_str().ok_or(Error::UnsupportedCurrentFacts)?))?;
        if exe.hash(size)?!=exe_hash {return Err(Error::UnsupportedCurrentFacts);}
        let mut proc=ProcOwner::open()?;
        if r["proc_root"]!=serde_json::json!({"device":proc.scope.proc_device,"inode":proc.scope.proc_inode})
            || r["namespaces"]!=proc.scope.namespaces {return Err(Error::UnsupportedCurrentFacts);}
        let last=Self::observe(&mut proc,record,contract)?;
        let loaded=if format=="build8/native-nts/release-v2" {Some(LoadedBoundary::open(digest(&r["loaded_sha256"])?,source_hash)?)}else{None};
        let mut boundary=Self{record:record.canonical().to_vec(),contract:contract.clone(),release,source,exe,proc,last,code,source_hash,size,exe_hash,loaded};
        boundary.recheck(record)?;Ok(boundary)
    }
    fn observe(proc:&mut ProcOwner,record:&DecodedRecord,contract:&CurrentContract)->Result<Observation> {
        proc.recheck()?;let before=os()?;contract.compare_linux(&before)?;
        let boot=boot_id(&read_proc(&mut proc.boot)?)?;
        let maximum=record.acquisition().bounds.maximum_sampling_span_ns;
        let first=sample(maximum,boot)?;let last=sample(maximum,boot)?;
        let after=os()?;proc.recheck()?;
        if before!=after || boot_id(&read_proc(&mut proc.boot)?)?!=boot
            || last.0<first.0 || last.1<first.1 {return Err(Error::UnsupportedCurrentFacts);}
        Ok(Observation{os:before,boot,first,last})
    }
    pub(super) fn recheck(&mut self,record:&DecodedRecord)->Result<()> {
        if self.record!=record.canonical() {return Err(Error::UnsupportedCurrentFacts);}
        self.release.recheck()?;self.source.recheck()?;self.exe.recheck()?;self.proc.recheck()?;
        if <[u8;32]>::from(Sha256::digest(self.release.bytes(CONFIG_LIMIT)?))!=self.code
            || <[u8;32]>::from(Sha256::digest(self.source.bytes(CONFIG_LIMIT)?))!=self.source_hash
            || self.exe.hash(self.size)?!=self.exe_hash {return Err(Error::UnsupportedCurrentFacts);}
        let image=self.proc.image()?;protected(&image,false)?;
        if identity(&image,false)?!=self.exe.initial {return Err(Error::UnsupportedCurrentFacts);}
        let fresh=Self::observe(&mut self.proc,record,&self.contract)?;
        require_progress(&self.last,&fresh)?;
        self.release.recheck()?;self.source.recheck()?;self.exe.recheck()?;self.proc.recheck()?;
        if identity(&image,false)?!=self.exe.initial {return Err(Error::UnsupportedCurrentFacts);}
        if let Some(loaded)=&mut self.loaded {loaded.recheck(&mut self.proc)?;}
        self.last=fresh;Ok(()) // last-success ratchet only; failure never advances.
    }
    pub(super) fn require_loaded(&mut self,record:&DecodedRecord)->Result<()> {
        self.recheck(record)?;
        self.loaded.as_mut().ok_or(Error::UnsupportedCurrentFacts)?.recheck(&mut self.proc)?;
        self.recheck(record)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn modeled_boot_bytes_require_exact_kernel_uuid_encoding() {
        let good=b"01234567-89ab-cdef-0123-456789abcdef\n";assert!(boot_id(good).is_ok());
        assert!(boot_id(b"00000000-0000-0000-0000-000000000000\n").is_err());
        let mut moved=*good;moved.swap(8,9);assert!(boot_id(&moved).is_err());
        let mut upper=*good;upper[10]=b'A';assert!(boot_id(&upper).is_err());
        assert!(boot_id(&good[..36]).is_err());
    }
    #[test] fn modeled_process_start_handles_comm_delimiters_and_exact_actual_pid() {
        let mut fields=vec!["0";20];fields[0]="S";fields[19]="12345";
        let raw=format!("123 (public ) test) {}\n",fields.join(" "));
        assert_eq!(process_start(raw.as_bytes(),123),Ok(12345));
        assert!(process_start(raw.as_bytes(),124).is_err());
        fields[19]="0";let bad=format!("123 (test) {}",fields.join(" "));
        assert!(process_start(bad.as_bytes(),123).is_err());
        assert!(process_start(b"123 (test) S 1",123).is_err());
    }
    #[test] fn modeled_linux_progress_rejects_boot_os_and_between_call_regressions() {
        let old=Observation {os:serde_json::json!({"release":"public-test"}),boot:1,first:(100,110,1),last:(200,210,1)};
        let good=Observation {os:old.os.clone(),boot:1,first:(200,210,1),last:(201,211,1)};
        assert_eq!(require_progress(&old,&good),Ok(()));
        for fault in 0..4 {
            let mut changed=good.clone();match fault {0=>changed.first.0=150,1=>changed.first.1=209,
                2=>changed.boot=2,_=>changed.os["release"]="foreign".into()};
            assert!(require_progress(&old,&changed).is_err());
        }
        assert_eq!(old.last,(200,210,1));
    }
    #[test] fn modeled_left_endpoint_pair_keeps_causal_order_and_existing_span_bound() {
        assert_eq!(checked_sample(100,101,110,10,1),Ok((100,101,1)));
        for (a,b,c,max,boot) in [(100,101,110,9,1),(100,99,110,10,1),
            (100,101,99,10,1),(0,1,2,10,1),(1,2,3,0,1),(1,2,3,10,0)] {
            assert!(checked_sample(a,b,c,max,boot).is_err());
        }
    }
}
