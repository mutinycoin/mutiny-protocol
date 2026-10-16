//! Counter OWN-process selected mapped-file boundary. Never remote image
//! attestation, calibration, physical lineage or a caller PID/approval issuer.
//! Reuses the reviewed clock boundary's proc/namespace and full mapped roster
//! semantics behind the separately selected COUNTER descriptor.
use mutiny_consensus_v8::Hash;
use serde_json::Value;
use sha2::{Digest,Sha256};
use std::{collections::{BTreeMap,BTreeSet},ffi::{CString,OsStr},fs::File,
    io::{Read,Seek,SeekFrom},os::{fd::{AsRawFd,FromRawFd},unix::{ffi::OsStrExt,fs::MetadataExt}},
    path::{Component,Path,PathBuf}};
type Result<T>=std::result::Result<T,String>;
const LIMIT:usize=65536;
use crate::hybrid_native_retained_input_v2::{NativeInputSlot,RetainedNativeFile};
use crate::host_clock::RetainedCloseReport;
use std::mem::ManuallyDrop as MD;
// Same already reviewed original-input and once-close primitives. No separate
// native-close implementation or retry of a numerical descriptor exists here.
struct CurrentFile{owner:RetainedNativeFile}
impl std::ops::Deref for CurrentFile{type Target=File;
    fn deref(&self)->&File{self.owner.file().expect("published original current file")}}
enum FileClose{Observed(RetainedCloseReport),Retained(MD<RetainedNativeFile>)}
impl FileClose{fn known(&self)->bool{matches!(self,Self::Observed(v) if v.retained_handles_closed())}}
impl CurrentFile{fn close(self)->FileClose{match self.owner.close_once(){
    Ok(v)=>FileClose::Observed(v),Err(v)=>FileClose::Retained(v)}}}
struct CloseBatch{outcomes:Vec<FileClose>,expected:usize}
impl CloseBatch{
    fn prepare(expected:usize)->Result<Self>{let mut outcomes=Vec::new();
        outcomes.try_reserve_exact(expected).map_err(|_|"counter original close roster allocation")?;
        Ok(Self{outcomes,expected})}
    fn known(&self)->bool{self.outcomes.len()==self.expected&&self.outcomes.iter().all(FileClose::known)}
    fn record(&mut self,file:CurrentFile){assert!(self.outcomes.len()<self.expected);self.outcomes.push(file.close());}
}
fn open_at(parent:i32,name:&OsStr,directory:bool,nofollow:bool)->Result<CurrentFile>{
    let name=CString::new(name.as_bytes()).map_err(|_|"counter current native name NUL")?;
    let slot=NativeInputSlot::prepare()?;
    let fd=unsafe{libc::openat(parent,name.as_ptr(),libc::O_CLOEXEC|if nofollow{libc::O_NOFOLLOW}else{0}
        |if directory{libc::O_PATH|libc::O_DIRECTORY}else{libc::O_RDONLY|libc::O_NONBLOCK})};
    if fd<0{return Err("counter current original native object unavailable".into());}
    // Publish before metadata/security/read. An original-ID failure preserves
    // its complete typed slot even when this cause is mapped to a String.
    Ok(CurrentFile{owner:slot.retain(unsafe{File::from_raw_fd(fd)}).map_err(|e|e.cause)?})
}
#[derive(Clone,Copy,Default,PartialEq,Eq)]
struct Id{device:u64,inode:u64,uid:u32,gid:u32,mode:u32,links:u64,size:u64}
fn id(file:&File,directory:bool)->Result<Id>{let m=file.metadata().map_err(|_|"counter current native identity")?;
    Ok(Id{device:m.dev(),inode:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode(),links:m.nlink(),size:if directory{0}else{m.len()}})}
fn protected(file:&File,directory:bool)->Result<()> {let m=file.metadata().map_err(|_|"counter current protection metadata")?;
    if m.uid()!=0||m.mode()&0o022!=0||(directory&&!m.is_dir())||(!directory&&(!m.is_file()||m.nlink()!=1)){
        return Err("counter current administrator artifact protection refused".into());}Ok(())}
fn fs(file:&File,kind:libc::c_long)->Result<()> {let mut value=std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe{libc::fstatfs(file.as_raw_fd(),value.as_mut_ptr())}!=0||unsafe{value.assume_init()}.f_type!=kind {
        return Err("counter current native filesystem differs".into());}Ok(())}
struct MappedState{path:PathBuf,dirs:Vec<CurrentFile>,ids:Vec<Id>,file:Option<CurrentFile>,initial:Id,pin:Hash,close:CloseBatch}
struct MappedFile{state:MD<Box<MappedState>>}
impl std::ops::Deref for MappedFile{type Target=MappedState;fn deref(&self)->&MappedState{&self.state}}
struct MappedCloseRefusal{owner:MD<MappedFile>}
impl MappedFile{
    fn open(path:&Path,bytes:u64,pin:Hash)->Result<Self>{
        let text=path.to_str().ok_or("counter mapped path UTF8")?;
        let names=path.components().map(|v|match v{Component::RootDir=>Ok(None),Component::Normal(v)=>Ok(Some(v.to_owned())),
            _=>Err("counter mapped exact path grammar")}).collect::<std::result::Result<Vec<_>,_>>()?
            .into_iter().flatten().collect::<Vec<_>>();
        if !path.is_absolute()||names.is_empty()||text.bytes().any(|v|v.is_ascii_whitespace()||v==b'\\')
            ||text.contains("(deleted)")||bytes==0||pin==[0;32]{return Err("counter mapped selected path/size/pin refused".into());}
        let canonical=format!("/{}",names.iter().map(|v|v.to_str().ok_or("counter mapped path encoding"))
            .collect::<std::result::Result<Vec<_>,_>>()?.join("/"));
        if canonical!=text{return Err("counter mapped path alias refused".into());}
        let count=names.len().checked_add(1).ok_or("counter mapped original roster overflow")?;
        let close=CloseBatch::prepare(count)?;
        // Whole unpublished holder and outcome roster precede every open.
        let mut out=Self{state:MD::new(Box::new(MappedState{path:path.to_owned(),dirs:Vec::with_capacity(names.len()),
            ids:Vec::with_capacity(names.len()),file:None,initial:Id::default(),pin,close}))};
        let s=&mut **out.state;
        s.dirs.push(open_at(libc::AT_FDCWD,OsStr::new("/"),true,true)?);
        for name in &names[..names.len()-1]{s.dirs.push(open_at(s.dirs.last().ok_or("counter mapped root")?.as_raw_fd(),name,true,true)?);}
        for dir in &s.dirs{protected(dir,true)?;}
        s.file=Some(open_at(s.dirs.last().ok_or("counter mapped parent")?.as_raw_fd(),names.last().ok_or("counter mapped filename")?,false,true)?);
        let file=s.file.as_ref().ok_or("original mapped file absent")?;
        protected(file,false)?;s.initial=id(file,false)?;
        if s.initial.size!=bytes{return Err("counter mapped exact selected bytes differ".into());}
        for dir in &s.dirs{s.ids.push(id(dir,true)?);}out.recheck()?;Ok(out)
    }
    fn recheck(&self)->Result<()>{
        let original=self.file.as_ref().ok_or("original mapped file absent")?;
        original.owner.recheck_identity()?;
        if self.dirs.iter().map(|f|{f.owner.recheck_identity()?;id(f,true)}).collect::<Result<Vec<_>>>()?!=self.ids||id(original,false)?!=self.initial{
            return Err("counter held mapped object changed".into());}
        for file in &self.dirs{protected(file,true)?;}protected(original,false)?;
        let mut file:&File=original;file.seek(SeekFrom::Start(0)).map_err(|_|"counter mapped rewind")?;
        let mut remaining=self.initial.size;let mut hash=Sha256::new();let mut buffer=[0;65536];
        while remaining!=0{let used=usize::try_from(remaining.min(buffer.len()as u64)).map_err(|_|"counter mapped remaining")?;
            file.read_exact(&mut buffer[..used]).map_err(|_|"counter mapped exact held read")?;hash.update(&buffer[..used]);remaining-=used as u64;}
        let mut extra=[0];if file.read(&mut extra).map_err(|_|"counter mapped EOF")?!=0||Hash::from(hash.finalize())!=self.pin{
            return Err("counter mapped held full bytes/hash changed".into());}
        let named=std::fs::symlink_metadata(&self.path).map_err(|_|"counter mapped named identity")?;
        if !named.is_file()||named.dev()!=self.initial.device||named.ino()!=self.initial.inode||named.uid()!=0
            ||named.mode()!=self.initial.mode||named.nlink()!=1||named.len()!=self.initial.size{
            return Err("counter mapped named object changed".into());}Ok(())
    }
    fn close(mut self)->std::result::Result<(),MappedCloseRefusal>{
        let s=&mut **self.state;
        for file in s.dirs.drain(..){s.close.record(file);}
        if let Some(file)=s.file.take(){s.close.record(file);}
        if !s.close.known(){return Err(MappedCloseRefusal{owner:MD::new(self)});}
        unsafe{MD::drop(&mut self.state)};Ok(())
    }
}
#[derive(Clone,PartialEq,Eq,PartialOrd,Ord)]
struct Mapping{offset:u64,length:u64,permissions:String}
fn exact<'a>(v:&'a Value,names:&[&str])->Result<&'a serde_json::Map<String,Value>>{
    let fields=v.as_object().ok_or("counter loaded object grammar")?;
    if fields.len()!=names.len()||names.iter().any(|v|!fields.contains_key(*v)){return Err("counter loaded unknown/missing field".into());}Ok(fields)}
fn digest(v:&Value)->Result<Hash>{let text=v.as_str().ok_or("counter loaded hash type")?;
    if text.len()!=64||!text.bytes().all(|v|v.is_ascii_digit()||(b'a'..=b'f').contains(&v)){
        return Err("counter loaded hash encoding".into());}
    let mut out=[0;32];hex::decode_to_slice(text,&mut out).map_err(|_|"counter loaded hash")?;
    if out==[0;32]{return Err("counter loaded zero hash".into());}Ok(out)}
fn mappings(v:&Value)->Result<Vec<Mapping>> {let list=v.as_array().ok_or("counter loaded mapping array")?;
    if list.is_empty()||list.len()>LIMIT{return Err("counter loaded mapping count".into());}
    let mut result=Vec::with_capacity(list.len());for value in list{let f=exact(value,&["offset","length","permissions"])?;
        let offset=f["offset"].as_u64().ok_or("counter loaded offset")?;let length=f["length"].as_u64().ok_or("counter loaded length")?;
        let p=f["permissions"].as_str().ok_or("counter loaded permissions")?;
        if length==0||offset.checked_add(length).is_none()||!matches!(p,"r--p"|"r-xp"|"rw-p"|"---p"|"r--s"|"r-xs"|"rw-s"|"---s") {
            return Err("counter loaded mapping bounds/permissions refused".into());}
        result.push(Mapping{offset,length,permissions:p.to_owned()});}
    result.sort();if result.windows(2).any(|v|v[0]==v[1]){return Err("counter loaded duplicate mapping".into());}Ok(result)}
fn bounded(file:&File)->Result<Vec<u8>> {let mut file=file;file.seek(SeekFrom::Start(0)).map_err(|_|"counter own proc rewind")?;
    let mut result=Vec::with_capacity(LIMIT);let mut buffer=[0;4096];loop{let n=file.read(&mut buffer).map_err(|_|"counter own proc read")?;
        if n==0{break;}if result.len().checked_add(n).is_none_or(|v|v>LIMIT){return Err("counter complete own proc bound".into());}
        result.extend_from_slice(&buffer[..n]);}Ok(result)}
fn start(file:&File,pid:i32)->Result<u64>{let raw=bounded(file)?;let text=std::str::from_utf8(&raw).map_err(|_|"counter proc stat encoding")?;
    let (number,_)=text.split_once(' ').ok_or("counter proc stat PID")?;if number.parse::<i32>().ok()!=Some(pid){return Err("counter own proc PID differs".into());}
    let end=text.rfind(')').ok_or("counter proc stat comm")?;let value=text[end+1..].split_whitespace().nth(19)
        .ok_or("counter proc start absent")?.parse::<u64>().map_err(|_|"counter proc start integer")?;
    if value==0{return Err("counter proc start zero".into());}Ok(value)}
struct CurrentClosed{proc:CloseBatch,mapped:Vec<MappedCloseRefusal>,context:Hash,role:String,
    native_pid:i32,creation:u64,uid:u32}
// Published before the first /proc acquisition. Partial construction cannot
// implicitly dispose of any original process/namespace owner on return/unwind.
struct ProcPreparation{root:Option<CurrentFile>,pid:Option<CurrentFile>,stat:Option<CurrentFile>,
    ns:Option<CurrentFile>,namespaces:Vec<CurrentFile>}
pub(crate) struct CounterOwnCurrent {root:CurrentFile,pid:CurrentFile,stat:CurrentFile,ns:CurrentFile,namespaces:Vec<CurrentFile>,
    proc_ids:Vec<Id>,native_pid:i32,creation:u64,uid:u32,objects:BTreeMap<String,(MappedFile,Vec<Mapping>)>,
    kernel:BTreeMap<String,Vec<Mapping>>,closed:Box<CurrentClosed>,temporary_unknown:Option<FileClose>,frozen:bool}
enum CurrentCustody{Current(MD<CounterOwnCurrent>),Outcomes(MD<Box<CurrentClosed>>)}
pub(crate) struct CounterCurrentCloseRefusal{retained:CurrentCustody}
impl From<CounterCurrentCloseRefusal> for String{fn from(_:CounterCurrentCloseRefusal)->Self{
    "counter original current/process close retained; no retry".into()}}
impl CounterOwnCurrent {
    /// Descriptor bytes have already been read through the SAME held protected
    /// counter selection. No raw caller source/PID/Boolean enters this issuer.
    pub(crate) fn from_selected(raw:&[u8],context:Hash,role:&str)->Result<Self>{
        if raw.is_empty()||raw.len()>LIMIT{return Err("counter loaded descriptor bound".into());}
        let value:Value=serde_json::from_slice(raw).map_err(|_|"counter loaded descriptor encoding")?;
        let f=exact(&value,&["format","target","context","role","objects","kernel_mappings"])?;
        if value["format"]!="BUILD8-COUNTER-LOADED-V1"||value["target"]!="linux-x86_64"
            ||digest(&f["context"])?!=context||value["role"]!=role
            ||serde_json::to_vec(&value).map_err(|_|"counter loaded canonical encoding")?!=raw {
            return Err("counter loaded exact selected descriptor context".into());}
        let selected=f["objects"].as_object().ok_or("counter loaded selected objects")?;
        if selected.is_empty(){return Err("counter loaded empty roster".into());}
        let mut mapped=Vec::new();mapped.try_reserve_exact(selected.len()).map_err(|_|"counter mapped close outcome allocation")?;
        let mut closed=MD::new(Box::new(CurrentClosed{proc:CloseBatch::prepare(9)?,mapped,context,role:role.to_owned(),native_pid:0,creation:0,uid:0}));
        let mut objects=MD::new(BTreeMap::new());let mut identities=BTreeSet::new();
        for(key,value)in selected{let f=exact(value,&["path","bytes","sha256","mappings"])?;let pin=digest(&f["sha256"])?;
            if key!=&hex::encode(pin){return Err("counter loaded object pin key differs".into());}
            let path=f["path"].as_str().ok_or("counter loaded selected path")?;let bytes=f["bytes"].as_u64().ok_or("counter loaded selected size")?;
            let object=MappedFile::open(Path::new(path),bytes,pin)?;
            if !identities.insert((object.initial.device,object.initial.inode))||objects.insert(path.to_owned(),(object,mappings(&f["mappings"])?)).is_some(){
                return Err("counter loaded duplicate native object".into());}}
        let mut kernel=BTreeMap::new();for(name,value)in f["kernel_mappings"].as_object().ok_or("counter loaded kernel roster")? {
            let m=mappings(value)?;if !matches!(name.as_str(),"[vdso]"|"[vsyscall]")||m.iter().any(|v|v.offset!=0||v.permissions.contains('w')){
                return Err("counter loaded kernel executable roster refused".into());}kernel.insert(name.clone(),m);}
        let uid=unsafe{libc::geteuid()};let native_pid=unsafe{libc::getpid()};
        if uid==0||native_pid<=0||unsafe{libc::getuid()}!=uid{return Err("counter own ordinary principal refused".into());}
        closed.native_pid=native_pid;closed.uid=uid;
        let mut preparation=MD::new(Box::new(ProcPreparation{root:None,pid:None,stat:None,ns:None,namespaces:Vec::with_capacity(5)}));
        preparation.root=Some(open_at(libc::AT_FDCWD,OsStr::new("/proc"),true,true)?);
        let root=preparation.root.as_ref().expect("published original proc root");protected(root,true)?;fs(root,0x9fa0)?;
        let mut self_name=[0;64];let n=unsafe{libc::readlinkat(root.as_raw_fd(),c"self".as_ptr(),self_name.as_mut_ptr().cast(),64)};
        if n<=0||n>=64||std::str::from_utf8(&self_name[..n as usize]).ok().and_then(|v|v.parse::<i32>().ok())!=Some(native_pid){
            return Err("counter verified kernel self link differs".into());}
        preparation.pid=Some(open_at(root.as_raw_fd(),OsStr::new(&native_pid.to_string()),true,true)?);
        let pid=preparation.pid.as_ref().expect("published original proc PID");fs(pid,0x9fa0)?;
        let m=pid.metadata().map_err(|_|"counter own proc directory")?;
        if !m.is_dir()||m.uid()!=uid||m.mode()&0o022!=0{return Err("counter own proc directory protection".into());}
        preparation.stat=Some(open_at(pid.as_raw_fd(),OsStr::new("stat"),false,true)?);
        let creation=start(preparation.stat.as_ref().expect("published original proc stat"),native_pid)?;closed.creation=creation;
        preparation.ns=Some(open_at(preparation.pid.as_ref().expect("published proc PID").as_raw_fd(),OsStr::new("ns"),true,true)?);
        fs(preparation.ns.as_ref().expect("published original proc namespace directory"),0x9fa0)?;
        for name in ["mnt","pid","user","uts","time"] {
            let file=open_at(preparation.ns.as_ref().expect("published namespace directory").as_raw_fd(),OsStr::new(name),false,false)?;
            preparation.namespaces.push(file);fs(preparation.namespaces.last().expect("published original namespace"),0x6e736673)?;}
        let proc_ids=[preparation.root.as_ref().unwrap(),preparation.pid.as_ref().unwrap(),preparation.stat.as_ref().unwrap(),preparation.ns.as_ref().unwrap()]
            .into_iter().chain(preparation.namespaces.iter()).map(|f|id(f,true)).collect::<Result<Vec<_>>>()?;
        let mut prepared=MD::into_inner(preparation);
        let root=prepared.root.take().unwrap();let pid=prepared.pid.take().unwrap();let stat=prepared.stat.take().unwrap();let ns=prepared.ns.take().unwrap();
        let namespaces=std::mem::take(&mut prepared.namespaces);
        let mut result=MD::new(Self{root,pid,stat,ns,namespaces,proc_ids,native_pid,creation,uid,
            objects:MD::into_inner(objects),kernel,closed:MD::into_inner(closed),temporary_unknown:None,frozen:false});
        result.recheck()?;Ok(MD::into_inner(result))
    }
    pub(crate) fn recheck(&mut self)->Result<()> {
        if self.frozen{return Err("counter own current boundary frozen".into());}self.frozen=true;
        if unsafe{libc::getpid()}!=self.native_pid||unsafe{libc::getuid()}!=self.uid||unsafe{libc::geteuid()}!=self.uid
            ||start(&self.stat,self.native_pid)?!=self.creation
            ||[&self.root,&self.pid,&self.stat,&self.ns].into_iter().chain(self.namespaces.iter()).map(|f|id(f,true)).collect::<Result<Vec<_>>>()?!=self.proc_ids {
            return Err("counter own original process/namespace changed".into());}
        for (name,held) in ["mnt","pid","user","uts","time"].into_iter().zip(&self.namespaces) {
            let named=open_at(self.ns.as_raw_fd(),OsStr::new(name),false,false)?;
            let observed:Result<bool>=(||{fs(&named,0x6e736673)?;Ok(id(&named,true)?==id(held,true)?)})();
            let closed=named.close();
            if !closed.known(){self.temporary_unknown=Some(closed);return Err("counter namespace original native close unknown".into());}
            if !observed?{return Err("counter actual namespace changed".into());}
        }
        for(object,_)in self.objects.values(){object.recheck()?;}
        for _ in 0..2 {let maps=open_at(self.pid.as_raw_fd(),OsStr::new("maps"),false,true)?;
            let data=bounded(&maps);let closed=maps.close();
            if !closed.known(){self.temporary_unknown=Some(closed);return Err("counter own maps original close unknown".into());}self.inspect(&data?)?;}
        for(object,_)in self.objects.values(){object.recheck()?;}self.frozen=false;Ok(())
    }
    fn inspect(&self,raw:&[u8])->Result<()> {
        let text=std::str::from_utf8(raw).map_err(|_|"counter own maps encoding")?;
        let mut objects:BTreeMap<String,Vec<Mapping>>=BTreeMap::new();let mut kernel:BTreeMap<String,Vec<Mapping>>=BTreeMap::new();
        for line in text.lines(){let f=line.split_whitespace().collect::<Vec<_>>();if !(5..=6).contains(&f.len()){return Err("counter own maps exact fields".into());}
            let(a,b)=f[0].split_once('-').ok_or("counter own mapped addresses")?;
            let begin=u64::from_str_radix(a,16).map_err(|_|"counter own mapped begin")?;let end=u64::from_str_radix(b,16).map_err(|_|"counter own mapped end")?;
            let length=end.checked_sub(begin).filter(|v|*v!=0).ok_or("counter own mapped duration")?;let p=f[1];
            if !matches!(p,"r--p"|"r-xp"|"rw-p"|"---p"|"r--s"|"r-xs"|"rw-s"|"---s") {return Err("counter own mapped executable/write permissions refused".into());}
            let offset=u64::from_str_radix(f[2],16).map_err(|_|"counter own mapped offset")?;
            if offset.checked_add(length).is_none(){return Err("counter own mapped range overflow".into());}
            let inode=f[4].parse::<u64>().map_err(|_|"counter own mapped inode")?;let path=f.get(5).copied().unwrap_or("");
            let mapping=Mapping{offset,length,permissions:p.to_owned()};
            if inode==0 {if p.contains('x'){if !self.kernel.contains_key(path){return Err("counter own unknown anonymous executable mapping".into());}
                kernel.entry(path.to_owned()).or_default().push(mapping);}continue;}
            let(object,_)=self.objects.get(path).ok_or("counter own unselected mapped file")?;
            let(major,minor)=f[3].split_once(':').ok_or("counter own mapped device")?;
            if inode!=object.initial.inode||u64::from_str_radix(major,16).map_err(|_|"counter own device major")?!=libc::major(object.initial.device)as u64
                ||u64::from_str_radix(minor,16).map_err(|_|"counter own device minor")?!=libc::minor(object.initial.device)as u64 {
                return Err("counter own selected mapped native identity differs".into());}
            objects.entry(path.to_owned()).or_default().push(mapping);}
        for v in objects.values_mut().chain(kernel.values_mut()){v.sort();}
        if objects.len()!=self.objects.len()||kernel!=self.kernel||self.objects.iter().any(|(path,(_,m))|objects.get(path)!=Some(m)) {
            return Err("counter own complete mapped roster differs".into());}Ok(())
    }
    pub(crate) fn close(mut self)->std::result::Result<(),CounterCurrentCloseRefusal>{
        // Failed current check closes NOTHING and retains the whole original
        // process/mapped/temporary holder. No failed FD can be re-opened/retried.
        if self.recheck().is_err(){return Err(CounterCurrentCloseRefusal{retained:CurrentCustody::Current(MD::new(self))});}
        let Self{root,pid,stat,ns,namespaces,objects,closed,..}=self;
        let mut closed=MD::new(closed);
        for(object,_)in objects.into_values(){if let Err(e)=object.close(){closed.mapped.push(e);}}
        for file in namespaces.into_iter().chain([ns,stat,pid,root]){closed.proc.record(file);}
        if !closed.mapped.is_empty()||!closed.proc.known(){return Err(CounterCurrentCloseRefusal{retained:CurrentCustody::Outcomes(closed)});}
        unsafe{MD::drop(&mut closed)};Ok(())
    }
}
