//! Existing-only administrator-selected counter endpoint context. This issues
//! local placement/role authority, NOT physical TPM or peer-image qualification.
//! No creation, chmod/chown, secret read, service start or initial counter exists.
use crate::continuity_custody_v2::Pins;
use mutiny_consensus_v8::{Hash,canonical_store_v2::CanonicalStore,
    provenance::AdmissionClass,tpm::{TpmProfile,public_key},votes_v2::AuthenticatedRound};
use sha2::{Digest,Sha256};
use std::{ffi::{CString,OsStr},fs::File,io::{Read,Seek,SeekFrom},
    os::{fd::{AsRawFd,FromRawFd},unix::{ffi::OsStrExt,fs::MetadataExt}},path::{Component,Path,PathBuf}};
type Result<T>=std::result::Result<T,String>;
const ROOT:&str="/var/lib/mutiny/custody-v2";
#[derive(Clone,Copy,PartialEq,Eq)]
struct Id {dev:u64,ino:u64,mode:u32,uid:u32,gid:u32,links:u64,size:u64}
fn id(file:&File)->Result<Id>{let m=file.metadata().map_err(|_|"counter native metadata unavailable")?;
    Ok(Id{dev:m.dev(),ino:m.ino(),mode:m.mode(),uid:m.uid(),gid:m.gid(),links:m.nlink(),size:m.len()})}
/// Native original public object and all path ancestors. Recheck compares held
/// bytes/IDs and separately reopens the exact protected name, without accepting
/// a substituted directory, symbolic link, hardlink or content restoration.
pub(super) struct PublicState {
    path:PathBuf,ancestors:Vec<crate::hybrid_native_retained_input_v2::RetainedNativeFile>,
    ancestor_ids:Vec<Id>,file:Option<crate::hybrid_native_retained_input_v2::RetainedNativeFile>,
    initial:Option<Id>,raw:Vec<u8>,maximum:usize,
    close_reports:Vec<crate::host_clock::RetainedCloseReport>,
    close_unknown:Vec<std::mem::ManuallyDrop<crate::hybrid_native_retained_input_v2::RetainedNativeFile>>,
    frozen:bool,
}
pub(super) struct HeldPublic {state:std::mem::ManuallyDrop<Box<PublicState>>}
pub(super) struct HeldPublicClose {owner:std::mem::ManuallyDrop<HeldPublic>}
impl std::ops::Deref for HeldPublic {
    type Target=PublicState;
    fn deref(&self)->&PublicState{&self.state}
}
impl HeldPublic {
    pub(super) fn open(path:PathBuf,maximum:usize)->Result<Self>{
        if maximum==0||maximum>65536{return Err("counter selected documentary bound".into());}
        Self::open_bound(path,maximum)
    }
    pub(super) fn open_genesis(path:PathBuf)->Result<Self>{
        Self::open_bound(path,crate::genesis_artifact_v2::MAX_ARTIFACT)
    }
    pub(super) fn open_genesis_witness(path:PathBuf)->Result<Self>{
        Self::open_bound(path,mutiny_consensus_v8::admission_evidence_v1::MAX_BUNDLE)
    }
    fn open_bound(path:PathBuf,maximum:usize)->Result<Self>{
        use crate::hybrid_native_retained_input_v2::NativeInputSlot;
        if !path.is_absolute() || !path.starts_with(ROOT) || maximum==0 {
            return Err("counter selected fixed installation path/bound".into());
        }
        let names=path.components().map(|v|match v{Component::RootDir=>Ok(None),
            Component::Normal(n)=>Ok(Some(n.to_owned())),_=>Err("counter path component")})
            .collect::<std::result::Result<Vec<_>,_>>()?.into_iter().flatten().collect::<Vec<_>>();
        if names.is_empty()||names.len()>64{return Err("counter public ancestor roster bound".into());}
        // All roster, bytes, outcomes and whole holder allocations precede the
        // first native open. No File is an ordinary local during validation.
        let capacity=names.len().checked_add(1).ok_or("public roster overflow")?;
        let mut out=Self{state:std::mem::ManuallyDrop::new(Box::new(PublicState{
            path,ancestors:Vec::with_capacity(names.len()),ancestor_ids:Vec::with_capacity(names.len()),
            file:None,initial:None,raw:Vec::with_capacity(maximum),maximum,
            close_reports:Vec::with_capacity(capacity),close_unknown:Vec::with_capacity(capacity),frozen:true,
        }))};
        fn acquire(parent:i32,name:&OsStr,flags:i32)->Result<crate::hybrid_native_retained_input_v2::RetainedNativeFile>{
            let name=CString::new(name.as_bytes()).map_err(|_|"counter selected path NUL")?;
            let slot=NativeInputSlot::prepare()?;
            let fd=unsafe{libc::openat(parent,name.as_ptr(),flags|libc::O_CLOEXEC|libc::O_NOFOLLOW)};
            if fd<0{return Err("counter original public input unavailable".into());}
            let original=unsafe{File::from_raw_fd(fd)};
            slot.retain(original).map_err(|failure|failure.cause)
        }
        out.state.ancestors.push(acquire(libc::AT_FDCWD,OsStr::new("/"),libc::O_PATH|libc::O_DIRECTORY)?);
        for name in &names[..names.len()-1]{
            let parent=out.state.ancestors.last().ok_or("counter root absent")?.file()?.as_raw_fd();
            out.state.ancestors.push(acquire(parent,name,libc::O_PATH|libc::O_DIRECTORY)?);
        }
        let s=&mut **out.state;
        for ancestor in &s.ancestors{
            ancestor.recheck_identity()?;let file=ancestor.file()?;
            let metadata=file.metadata().map_err(|_|"counter ancestor metadata")?;
            if !metadata.is_dir()||metadata.uid()!=0||metadata.mode()&0o022!=0{
                return Err("counter administrator ancestor protection".into());}
            s.ancestor_ids.push(id(file)?);
        }
        let parent=s.ancestors.last().ok_or("counter selected parent absent")?.file()?.as_raw_fd();
        s.file=Some(acquire(parent,names.last().ok_or("counter selected name absent")?,libc::O_RDONLY)?);
        let file=s.file.as_ref().expect("published public leaf").file()?;
        let metadata=file.metadata().map_err(|_|"counter artifact metadata")?;
        if !metadata.is_file()||metadata.uid()!=0||metadata.nlink()!=1||metadata.mode()&0o022!=0
            ||metadata.len()==0||metadata.len()>maximum as u64{
            return Err("counter administrator public artifact protection/type/size".into());}
        let initial=id(file)?;
        s.initial=Some(initial);s.raw.resize(initial.size as usize,0);
        let mut reader=s.file.as_ref().expect("published public leaf").file()?;
        reader.read_exact(&mut s.raw).map_err(|_|"counter public exact read")?;
        let mut extra=[0];if reader.read(&mut extra).map_err(|_|"counter public EOF")?!=0||id(reader)?!=initial{
            return Err("counter public object changed while read".into());}
        out.state.frozen=false;Ok(out)
    }
    pub(super) fn bytes(&self)->&[u8]{&self.state.raw}
    fn recheck_held(&mut self)->Result<()>{
        let s=&mut **self.state;
        if s.frozen{return Err("counter public custody frozen".into());}s.frozen=true;
        for (owner,expected) in s.ancestors.iter().zip(&s.ancestor_ids){
            owner.recheck_identity()?;if id(owner.file()?)?!=*expected{return Err("counter public ancestor changed".into());}
        }
        let owner=s.file.as_ref().ok_or("counter original public leaf absent")?;owner.recheck_identity()?;
        let mut file=owner.file()?;
        if Some(id(file)?)!=s.initial{return Err("counter held administrator object changed".into());}
        file.seek(SeekFrom::Start(0)).map_err(|_|"counter public rewind")?;
        let mut hash=Sha256::new();let mut buffer=[0;4096];let mut used=0usize;
        loop{let n=file.read(&mut buffer).map_err(|_|"counter public current read")?;if n==0{break;}
            used=used.checked_add(n).ok_or("counter public length overflow")?;
            if used>s.maximum{return Err("counter public current bound".into());}hash.update(&buffer[..n]);}
        if used!=s.raw.len()||<Hash>::from(hash.finalize())!=<Hash>::from(Sha256::digest(&s.raw)){
            return Err("counter held administrator bytes changed".into());}
        s.frozen=false;Ok(())
    }
    pub(super) fn recheck(&mut self)->Result<()>{
        self.recheck_held()?;
        let s=&mut **self.state;s.frozen=true;
        let named=Self::open_bound(s.path.clone(),s.maximum)?;
        let same=named.initial==s.initial&&named.ancestor_ids==s.ancestor_ids&&named.raw==s.raw;
        named.close().map_err(|_|"counter named public independent close unknown")?;
        if !same{return Err("counter named administrator object replaced".into());}
        s.frozen=false;Ok(())
    }
    pub(super) fn close(mut self)->std::result::Result<(),HeldPublicClose>{
        // Current faults preserve every original without a native close effect.
        if self.recheck_held().is_err(){return Err(HeldPublicClose{owner:std::mem::ManuallyDrop::new(self)});}
        let s=&mut **self.state;s.frozen=true;
        for owner in s.ancestors.drain(..).chain(s.file.take()){
            match owner.close_once(){Ok(report)=>s.close_reports.push(report),Err(retained)=>s.close_unknown.push(retained)}
        }
        if !s.close_unknown.is_empty()||s.close_reports.iter().any(|r|!r.retained_handles_closed()){
            return Err(HeldPublicClose{owner:std::mem::ManuallyDrop::new(self)});
        }
        unsafe{std::mem::ManuallyDrop::drop(&mut self.state)};Ok(())
    }
}
#[derive(Clone,Copy)]
enum LocalRole {Consumer,Provider}
struct Declaration {context:Hash,node:Hash,genesis:Hash,fingerprint:Hash,profile:Hash,
    nv_public:Hash,consumer_loaded:Hash,provider_loaded:Hash,node_ciphertext:Hash,continuity_ciphertext:Hash,hardware_generation:u64,key_generation:u64,
    consumer_uid:u32,consumer_gid:u32,provider_uid:u32,provider_gid:u32,socket_gid:u32}
fn declaration(raw:&[u8])->Result<Declaration>{
    let value:serde_json::Value=serde_json::from_slice(raw).map_err(|_|"counter selected declaration encoding")?;
    let o=value.as_object().ok_or("counter selected declaration object")?;
    let fields=["schema","role","context","node","genesis","fingerprint","profile","nv_public",
        "hardware_generation","key_generation","consumer_uid","consumer_gid","provider_uid","provider_gid","socket_gid",
        "consumer_loaded","provider_loaded","unlock_role","node_ciphertext","continuity_ciphertext"];
    if o.len()!=fields.len() || fields.iter().any(|k|!o.contains_key(*k))
        || value["schema"]!="BUILD8-INSTALLED-COUNTER-V4" || value["role"]!="NodeContinuity"
        || value["unlock_role"]!="ExistingNodeContinuityKeys"
        || serde_json::to_vec(&value).map_err(|_|"counter declaration canonical encoding")?!=raw {
        return Err("counter selected declaration exact schema/canonical form".into());
    }
    let hash=|name:&str|->Result<Hash>{let t=value[name].as_str().ok_or("counter digest type")?;
        if t.len()!=64 || !t.bytes().all(|v|v.is_ascii_digit()||(b'a'..=b'f').contains(&v)){return Err("counter digest encoding".into());}
        let mut out=[0;32];hex::decode_to_slice(t,&mut out).map_err(|_|"counter digest")?;
        if out==[0;32]{return Err("counter selected zero digest".into());}Ok(out)};
    let number=|name:&str|value[name].as_u64().ok_or_else(||"counter integer type/range".to_owned());
    let uid=|name:&str|->Result<u32>{u32::try_from(number(name)?).map_err(|_|"counter principal range".into())};
    let d=Declaration{context:hash("context")?,node:hash("node")?,genesis:hash("genesis")?,fingerprint:hash("fingerprint")?,
        profile:hash("profile")?,nv_public:hash("nv_public")?,consumer_loaded:hash("consumer_loaded")?,provider_loaded:hash("provider_loaded")?,
        node_ciphertext:hash("node_ciphertext")?,continuity_ciphertext:hash("continuity_ciphertext")?,
        hardware_generation:number("hardware_generation")?,
        key_generation:number("key_generation")?,consumer_uid:uid("consumer_uid")?,consumer_gid:uid("consumer_gid")?,
        provider_uid:uid("provider_uid")?,provider_gid:uid("provider_gid")?,socket_gid:uid("socket_gid")?};
    if d.hardware_generation==0 || d.key_generation==0 || d.consumer_uid==0 || d.provider_uid==0
        || d.consumer_uid==d.provider_uid || d.socket_gid!=d.consumer_gid {
        return Err("counter distinct ordinary installed principals/generations refused".into());
    }Ok(d)
}
fn own_parent(chain:&CanonicalStore)->Result<mutiny_consensus_v8::anchors::FinalizedAnchor>{
    let(head,_)=chain.load().map_err(|_|"counter own canonical head")?;
    let(parent,_,_)=chain.execution_parent(head.height).map_err(|_|"counter own authenticated execution parent")?;
    if parent.height!=head.height||parent.block!=head.block{return Err("counter own parent changed".into());}
    Ok(mutiny_consensus_v8::anchors::FinalizedAnchor{network:mutiny_consensus_v8::NETWORK_ID,
        genesis:parent.genesis,fingerprint:parent.fingerprint,height:parent.height,block:parent.block})
}
/// Counter-specific opaque selection, minted only from protected fixed public
/// installation artifacts plus actual own canonical authority. No caller paths,
/// UID approval flag, qualification callback or clock-owner role is accepted.
pub(crate) struct AuthorityState {
    selected:Declaration,declaration:HeldPublic,selection_pin:HeldPublic,
    profile_artifact:HeldPublic,nv_artifact:HeldPublic,loaded_artifact:HeldPublic,
    current:super::hybrid_counter_linux_current_v2::CounterOwnCurrent,profile:TpmProfile,
    local_uid:u32,local_gid:u32,node:Hash,role:LocalRole,frozen:bool,closed:Box<AuthorityClosed>,
}
use std::mem::{ManuallyDrop as MD,MaybeUninit};
struct AuthorityClosed{context:Hash,node:Hash,role:LocalRole,
    current:Option<crate::hybrid_counter_linux_current_v2::CounterCurrentCloseRefusal>,public:Vec<HeldPublicClose>}
pub(crate) struct InstalledCounterAuthority{state:MD<Box<AuthorityState>>}
impl std::ops::Deref for InstalledCounterAuthority{type Target=AuthorityState;fn deref(&self)->&AuthorityState{&self.state}}
impl std::ops::DerefMut for InstalledCounterAuthority{fn deref_mut(&mut self)->&mut AuthorityState{&mut self.state}}
struct AuthorityPreparation{result:Box<MaybeUninit<AuthorityState>>,declaration:Option<HeldPublic>,selection_pin:Option<HeldPublic>,
    profile:Option<HeldPublic>,nv:Option<HeldPublic>,loaded:Option<HeldPublic>,
    current:Option<crate::hybrid_counter_linux_current_v2::CounterOwnCurrent>,closed:Option<Box<AuthorityClosed>>}
enum AuthorityCloseCustody{Original(MD<InstalledCounterAuthority>),Outcomes(MD<Box<AuthorityClosed>>)}
pub(crate) struct CounterAuthorityCloseRefusal{custody:AuthorityCloseCustody}
impl From<CounterAuthorityCloseRefusal> for String{fn from(_:CounterAuthorityCloseRefusal)->Self{
    "counter original authority close retained; no retry".into()}}
impl InstalledCounterAuthority {
    pub(crate) fn for_consumer(chain:&CanonicalStore,node:Hash)->Result<Self>{
        Self::open_selected(chain,node,LocalRole::Consumer)
    }
    pub(crate) fn for_provider(chain:&CanonicalStore,node:Hash)->Result<Self>{
        Self::open_selected(chain,node,LocalRole::Provider)
    }
    fn open_selected(chain:&CanonicalStore,node:Hash,role:LocalRole)->Result<Self>{
        let parent=own_parent(chain)?;
        let(_,state)=chain.load().map_err(|_|"counter own canonical state unavailable")?;
        if state.admission_class().map_err(|_|"counter own admission class")?!=AdmissionClass::Production {
            return Err("counter NORMAL issuer requires own Production context".into());
        }
        let authority=chain.current_authority(&parent).map_err(|_|"counter own canonical authority")?;
        let round=AuthenticatedRound::new(authority).map_err(|_|"counter own authenticated round")?;
        let context=Pins::from_round(&round,node)?.context();
        let leaf=hex::encode(context);let base=PathBuf::from(ROOT);
        // Whole partial publication, final object storage and finite refusal
        // roster precede the first original public/current acquisition.
        let mut failures=Vec::new();failures.try_reserve_exact(5).map_err(|_|"counter authority close roster allocation")?;
        let mut preparation=MD::new(Box::new(AuthorityPreparation{result:Box::new(MaybeUninit::uninit()),
            declaration:None,selection_pin:None,profile:None,nv:None,loaded:None,current:None,
            closed:Some(Box::new(AuthorityClosed{context,node,role,current:None,public:failures}))}));
        preparation.declaration=Some(HeldPublic::open(base.join("selections").join(format!("{leaf}.json")),4096)?);
        preparation.selection_pin=Some(HeldPublic::open(base.join("selections").join(format!("{leaf}.sha256")),64)?);
        if preparation.selection_pin.as_ref().unwrap().raw!=hex::encode(Sha256::digest(&preparation.declaration.as_ref().unwrap().raw)).as_bytes(){
            return Err("counter administrator selected exact artifact pin mismatch".into());
        }
        let selected=declaration(&preparation.declaration.as_ref().unwrap().raw)?;
        if selected.context!=context || selected.node!=node || selected.genesis!=parent.genesis || selected.fingerprint!=parent.fingerprint {
            return Err("counter administrator declaration differs from own canonical context".into());
        }
        preparation.profile=Some(HeldPublic::open(base.join("public").join(format!("{}.profile",hex::encode(selected.profile))),8192)?);
        preparation.nv=Some(HeldPublic::open(base.join("public").join(format!("{}.nv",hex::encode(selected.nv_public))),80)?);
        let profile=TpmProfile::decode(&preparation.profile.as_ref().unwrap().raw).map_err(|_|"counter current selected profile encoding")?;
        if profile.commitment().map_err(|_|"counter selected profile commitment")?!=selected.profile
            || profile.is_test_value() || profile.provenance.is_none()
            || <Hash>::from(Sha256::digest(&preparation.nv.as_ref().unwrap().raw))!=selected.nv_public {
            return Err("counter NORMAL selected profile/NV public refusal".into());
        }
        let local_uid=unsafe{libc::geteuid()};let local_gid=unsafe{libc::getegid()};
        let (expected_uid,expected_gid)=match role {LocalRole::Consumer=>(selected.consumer_uid,selected.consumer_gid),
            LocalRole::Provider=>(selected.provider_uid,selected.provider_gid)};
        if local_uid!=expected_uid || local_gid!=expected_gid
            || unsafe{libc::getuid()}!=local_uid || unsafe{libc::getgid()}!=local_gid {
            return Err("counter caller is not installed ordinary consumer".into());
        }
        let (loaded_pin,loaded_role)=match role{LocalRole::Consumer=>(selected.consumer_loaded,"consumer"),
            LocalRole::Provider=>(selected.provider_loaded,"provider")};
        preparation.loaded=Some(HeldPublic::open(base.join("public").join(format!("{}.loaded.json",hex::encode(loaded_pin))),65536)?);
        if <Hash>::from(Sha256::digest(&preparation.loaded.as_ref().unwrap().raw))!=loaded_pin{return Err("counter own selected loaded artifact hash differs".into());}
        preparation.current=Some(super::hybrid_counter_linux_current_v2::CounterOwnCurrent::from_selected(
            &preparation.loaded.as_ref().unwrap().raw,context,loaded_role)?);
        preparation.loaded.as_mut().unwrap().recheck()?;
        preparation.declaration.as_mut().unwrap().recheck()?;preparation.selection_pin.as_mut().unwrap().recheck()?;
        preparation.profile.as_mut().unwrap().recheck()?;preparation.nv.as_mut().unwrap().recheck()?;
        let mut prepared=MD::into_inner(preparation);
        prepared.result.write(AuthorityState{selected,declaration:prepared.declaration.take().unwrap(),selection_pin:prepared.selection_pin.take().unwrap(),
            profile_artifact:prepared.profile.take().unwrap(),nv_artifact:prepared.nv.take().unwrap(),loaded_artifact:prepared.loaded.take().unwrap(),
            current:prepared.current.take().unwrap(),profile,local_uid,local_gid,node,role,frozen:false,closed:prepared.closed.take().unwrap()});
        let mut result=Self{state:MD::new(unsafe{prepared.result.assume_init()})};result.recheck(chain)?;Ok(result)
    }
    pub(crate) fn recheck(&mut self,chain:&CanonicalStore)->Result<()> {
        if self.frozen{return Err("counter installed selection frozen".into());}
        self.frozen=true;
        self.declaration.recheck()?;self.selection_pin.recheck()?;self.profile_artifact.recheck()?;self.nv_artifact.recheck()?;
        self.loaded_artifact.recheck()?;self.current.recheck()?;
        if unsafe{libc::getuid()}!=self.local_uid || unsafe{libc::geteuid()}!=self.local_uid
            || unsafe{libc::getgid()}!=self.local_gid || unsafe{libc::getegid()}!=self.local_gid {
            return Err("counter installed caller principal changed".into());
        }
        let parent=own_parent(chain)?;
        let(_,state)=chain.load().map_err(|_|"counter current own state")?;
        if state.admission_class().map_err(|_|"counter current admission class")?!=AdmissionClass::Production {
            return Err("counter own class changed".into());
        }
        let authority=chain.current_authority(&parent).map_err(|_|"counter current own authority")?;
        let member=authority.voters.get(&self.node).ok_or("counter own current member absent")?;
        if !member.admitted || !member.physical || !member.eligible || member.revoked
            || member.profile!=self.selected.profile || member.hardware_generation!=self.selected.hardware_generation
            || member.key_generation!=self.selected.key_generation
            || public_key(&self.profile.voting_public,false).map_err(|_|"counter selected voting public")?!=member.tpm_public {
            return Err("counter own selected member/profile/generation changed".into());
        }
        let context=Pins::from_round(&AuthenticatedRound::new(authority).map_err(|_|"counter current round")?,self.node)?.context();
        if context!=self.selected.context || parent.genesis!=self.selected.genesis || parent.fingerprint!=self.selected.fingerprint {
            return Err("counter own installed role context changed".into());
        }
        self.frozen=false;Ok(())
    }
    pub(crate) fn context(&self)->Hash{self.selected.context}
    pub(crate) fn peer_principals(&self)->(u32,u32){match self.role {
        LocalRole::Consumer=>(self.selected.provider_uid,self.selected.provider_gid),
        LocalRole::Provider=>(self.selected.consumer_uid,self.selected.consumer_gid)}}
    pub(crate) fn socket_owner_group(&self)->(u32,u32){(self.selected.provider_uid,self.selected.socket_gid)}
    pub(crate) fn endpoint(&self)->PathBuf{PathBuf::from(ROOT).join("ipc").join(hex::encode(self.selected.context)).join("nv.sock")}
    pub(super) fn unlock_endpoint(&self)->PathBuf{PathBuf::from(ROOT).join("ipc").join(hex::encode(self.selected.context)).join("unlock.sock")}
    pub(super) fn role_ciphertext_pins(&self)->(Hash,Hash){(self.selected.node_ciphertext,self.selected.continuity_ciphertext)}
    pub(super) fn role_directory(&self)->PathBuf{PathBuf::from(ROOT).join("roles").join(hex::encode(self.selected.context))}
    pub(crate) fn profile(&self)->&TpmProfile{&self.profile}
    pub(crate) fn nv_public_sha256(&self)->Hash{self.selected.nv_public}
    pub(crate) fn profile_commitment(&self)->Hash{self.selected.profile}
    pub(crate) fn is_provider(&self)->bool{matches!(self.role,LocalRole::Provider)}
    pub(crate) fn existing_lease_path(&self)->PathBuf{PathBuf::from(ROOT).join("locks")
        .join(format!("{}.lock",hex::encode(self.selected.nv_public)))}
    pub(crate) fn recheck_and_close(mut self,chain:&CanonicalStore)->std::result::Result<(),CounterAuthorityCloseRefusal> {
        // No close effect after a failed own-current/canonical/selection gate.
        if self.recheck(chain).is_err(){return Err(CounterAuthorityCloseRefusal{custody:AuthorityCloseCustody::Original(MD::new(self))});}
        let AuthorityState{declaration,selection_pin,profile_artifact,nv_artifact,loaded_artifact,current,closed,..}
            =*unsafe{MD::take(&mut self.state)};
        let mut closed=MD::new(closed);
        if let Err(original)=current.close(){closed.current=Some(original);}
        for object in [declaration,selection_pin,profile_artifact,nv_artifact,loaded_artifact]{
            if let Err(original)=object.close(){closed.public.push(original);}
        }
        if closed.current.is_some()||!closed.public.is_empty(){return Err(CounterAuthorityCloseRefusal{custody:AuthorityCloseCustody::Outcomes(closed)});}
        unsafe{MD::drop(&mut closed)};Ok(())
    }
}

#[cfg(test)]
mod role_selection_codec_controls {
    use super::*;
    #[test]
    fn exact_role_ciphertext_selection_has_no_unknown_field_or_implicit_upgrade(){
        let mut value=serde_json::json!({"schema":"BUILD8-INSTALLED-COUNTER-V4","role":"NodeContinuity",
            "unlock_role":"ExistingNodeContinuityKeys","hardware_generation":1,"key_generation":2,
            "consumer_uid":1001,"consumer_gid":1001,"provider_uid":1002,"provider_gid":1002,"socket_gid":1001});
        for name in ["context","node","genesis","fingerprint","profile","nv_public",
            "consumer_loaded","provider_loaded","node_ciphertext","continuity_ciphertext"]{
            value[name]=serde_json::Value::String(hex::encode([7u8;32]));
        }
        assert!(declaration(&serde_json::to_vec(&value).unwrap()).is_ok());
        let mut previous=value.clone();previous["schema"]="BUILD8-INSTALLED-COUNTER-V3".into();
        assert!(declaration(&serde_json::to_vec(&previous).unwrap()).is_err());
        let mut unknown=value.clone();unknown["approve"]=true.into();
        assert!(declaration(&serde_json::to_vec(&unknown).unwrap()).is_err());
        let mut missing=value.clone();missing.as_object_mut().unwrap().remove("node_ciphertext");
        assert!(declaration(&serde_json::to_vec(&missing).unwrap()).is_err());
        let mut zero=value;zero["continuity_ciphertext"]=hex::encode([0u8;32]).into();
        assert!(declaration(&serde_json::to_vec(&zero).unwrap()).is_err());
    }
}
