//! Counter-only fixed installer authority. Kernel pipe identity is NOT remote
//! loaded-code or physical NV authority. Missing accepted artifacts refuse.
#![cfg(windows)]
use crate::{continuity_custody_v2::Pins,
    host_clock::{RetainedWindowsPublicObject,RetainedCloseReport},
    hybrid_counter_windows_current_v2::CounterOwnWindowsCurrent,
    hybrid_counter_windows_transport_v2::{KernelPipePeerObservation,KernelPipePeerBinding}};
use mutiny_consensus_v8::{Hash,canonical_store_v2::CanonicalStore,
    anchors::FinalizedAnchor,provenance::AdmissionClass,
    votes_v2::AuthenticatedRound,tpm::{TpmProfile,public_key}};
use serde_json::{Value,Map};
use sha2::{Digest,Sha256};
use std::{mem::ManuallyDrop,path::{Path,PathBuf},thread::ThreadId};
type Result<T>=std::result::Result<T,String>;
const ROOT:&str=r"C:\ProgramData\Mutiny\CustodyV2";
#[link(name="advapi32")]
unsafe extern "system" {fn IsValidSid(sid:*const std::ffi::c_void)->i32;}

fn exact<'a>(value:&'a Value,names:&[&str])->Result<&'a Map<String,Value>> {
    let map=value.as_object().ok_or("counter installation object required")?;
    if map.len()!=names.len()||map.keys().any(|name|!names.contains(&name.as_str())) {
        return Err("counter installation unknown or missing field".into());
    }Ok(map)
}
fn number(value:&Value)->Result<u64>{value.as_u64().ok_or_else(||"counter installation unsigned integer".into())}
fn canonical_document(raw:&[u8])->Result<Value>{
    if raw.is_empty()||raw.len()>65536{return Err("counter descriptor total bound".into());}
    let value:Value=serde_json::from_slice(raw).map_err(|_|"counter descriptor encoding")?;
    if serde_json::to_vec(&value).map_err(|_|"counter descriptor canonical encoding")?!=raw {
        return Err("counter descriptor canonical spelling".into());
    }Ok(value)
}
fn hash(value:&Value)->Result<Hash>{
    let text=value.as_str().ok_or("counter installation digest type")?;
    if text.len()!=64||!text.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) {
        return Err("counter installation digest spelling".into());
    }
    let mut output=[0;32];hex::decode_to_slice(text,&mut output).map_err(|_|"counter installation digest encoding")?;
    if output==[0;32]{return Err("counter installation zero digest".into());}Ok(output)
}
fn sid(value:&Value)->Result<Vec<u8>> {
    let text=value.as_str().ok_or("counter installation SID type")?;
    if !(16..=136).contains(&text.len())||text.len()%2!=0
        ||!text.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) {
        return Err("counter installation SID bound/spelling".into());
    }
    let bytes=hex::decode(text).map_err(|_|"counter installation SID encoding")?;
    if bytes[0]!=1||bytes[1]>15||bytes.len()!=8+usize::from(bytes[1])*4
        ||unsafe{IsValidSid(bytes.as_ptr().cast())}==0 {
        return Err("counter installation SID native validity".into());
    }Ok(bytes)
}
struct Principal{sid:Vec<u8>,session:u32,authentication:u64}
fn principal(value:&Value)->Result<Principal>{
    let map=exact(value,&["sid","session","authentication_luid"])?;
    Ok(Principal{sid:sid(&map["sid"])?,session:u32::try_from(number(&map["session"])?).map_err(|_|"counter session range")?,
        authentication:number(&map["authentication_luid"])?})
}
struct Ace{kind:u8,flags:u8,mask:u32,sid:Vec<u8>}
struct PipePolicy{owner:Vec<u8>,control:u16,aces:Vec<Ace>}
fn pipe_policy(value:&Value)->Result<PipePolicy>{
    let map=exact(value,&["owner_sid","control","aces"])?;
    let control=u16::try_from(number(&map["control"])?).map_err(|_|"counter pipe security control range")?;
    // Existing selected role placement is protected, with a real finite DACL.
    if control&0x1004!=0x1004{return Err("counter selected pipe DACL is not protected/present".into());}
    let rows=map["aces"].as_array().ok_or("counter selected pipe ACE array")?;
    if rows.is_empty()||rows.len()>64{return Err("counter selected pipe ACE roster bound".into());}
    let mut aces=Vec::new();aces.try_reserve_exact(rows.len()).map_err(|_|"counter selected pipe ACE allocation")?;
    for row in rows {let ace=exact(row,&["kind","flags","mask","sid"])?;
        let kind=u8::try_from(number(&ace["kind"])?).map_err(|_|"counter ACE kind range")?;
        if kind>1{return Err("counter selected unsupported ACE kind".into());}
        aces.push(Ace{kind,flags:u8::try_from(number(&ace["flags"])?).map_err(|_|"counter ACE flags range")?,
            mask:u32::try_from(number(&ace["mask"])?).map_err(|_|"counter ACE mask range")?,sid:sid(&ace["sid"])?});
    }Ok(PipePolicy{owner:sid(&map["owner_sid"])?,control,aces})
}
struct Selection {
    context:Hash,node:Hash,genesis:Hash,fingerprint:Hash,profile:Hash,nv:Hash,
    hardware:u64,key:u64,consumer:Principal,provider:Principal,
    provider_pid:u32,provider_creation:u64,provider_token:u64,
    endpoint:Vec<u16>,pipe:PipePolicy,consumer_code:Hash,provider_code:Hash,
    node_cipher:Hash,continuity_cipher:Hash,
}
fn selection(raw:&[u8])->Result<Selection>{
    if raw.is_empty()||raw.len()>65536{return Err("counter installation total bound".into());}
    let value:Value=serde_json::from_slice(raw).map_err(|_|"counter installation encoding")?;
    let map=exact(&value,&["format","role","context","node","genesis","fingerprint","profile","nv_public",
        "hardware_generation","key_generation","consumer","provider","provider_pid","provider_creation_time",
        "provider_token_id","counter_pipe","pipe_security","consumer_code","provider_code","node_ciphertext","continuity_ciphertext"])?;
    if map["format"]!="build8/counter/windows-bridge-v1"||map["role"]!="NodeContinuity"
        ||serde_json::to_vec(&value).map_err(|_|"counter installation canonical encoding")?!=raw {
        return Err("counter installation exact canonical version/role".into());
    }
    let pipe=map["counter_pipe"].as_str().ok_or("counter selected pipe spelling")?;
    if pipe.len()>512||!pipe.starts_with(r"\\.\pipe\Mutiny-CounterV2-")||pipe.contains('\0') {
        return Err("counter selected local pipe namespace".into());
    }
    let endpoint=pipe.encode_utf16().collect::<Vec<_>>();
    if endpoint.len()>256{return Err("counter selected pipe UTF16 bound".into());}
    let selected=Selection{context:hash(&map["context"])?,node:hash(&map["node"])?,genesis:hash(&map["genesis"])?,
        fingerprint:hash(&map["fingerprint"])?,profile:hash(&map["profile"])?,nv:hash(&map["nv_public"])?,
        hardware:number(&map["hardware_generation"])?,key:number(&map["key_generation"])?,
        consumer:principal(&map["consumer"])?,provider:principal(&map["provider"])?,
        provider_pid:u32::try_from(number(&map["provider_pid"])?).map_err(|_|"counter provider PID range")?,
        provider_creation:number(&map["provider_creation_time"])?,provider_token:number(&map["provider_token_id"])?,
        endpoint,pipe:pipe_policy(&map["pipe_security"])?,consumer_code:hash(&map["consumer_code"])?,
        provider_code:hash(&map["provider_code"])?,node_cipher:hash(&map["node_ciphertext"])?,
        continuity_cipher:hash(&map["continuity_ciphertext"])?};
    if selected.hardware==0||selected.key==0||selected.provider_pid==0||selected.provider_creation==0
        ||selected.consumer.sid==selected.provider.sid||selected.pipe.owner!=selected.provider.sid {
        return Err("counter distinct selected role/incarnation/generation".into());
    }
    if selected.endpoint!=format!(r"\\.\pipe\Mutiny-CounterV2-{}-nv",hex::encode(selected.context)).encode_utf16().collect::<Vec<_>>() {
        return Err("counter pipe name differs from selected canonical context".into());
    }
    let system=[1u8,1,0,0,0,0,0,5,18,0,0,0];
    let administrators=[1u8,2,0,0,0,0,0,5,32,0,0,0,32,2,0,0];
    for ace in &selected.pipe.aces {
        if ace.kind!=0||ace.flags&8!=0{continue;}
        let privileged=ace.sid==selected.provider.sid||ace.sid==system||ace.sid==administrators;
        // Creation of another server instance / descriptor or owner mutation
        // is not a client permission. No selected foreign principal gets it.
        if ace.mask&(0x10000000|0x40000000|0x000d0004)!=0&&!privileged {
            return Err("counter selected pipe foreign instance/security mutation".into());
        }
        if ace.mask&0x00000112!=0&&!privileged&&ace.sid!=selected.consumer.sid {
            return Err("counter selected pipe foreign request mutation".into());
        }
    }Ok(selected)
}
fn parent(chain:&CanonicalStore)->Result<FinalizedAnchor>{
    let(head,_)=chain.load().map_err(|_|"counter own current head")?;
    let(parent,_,_)=chain.execution_parent(head.height).map_err(|_|"counter own current execution parent")?;
    if parent.height!=head.height||parent.block!=head.block{return Err("counter own current parent changed".into());}
    Ok(FinalizedAnchor{network:mutiny_consensus_v8::NETWORK_ID,genesis:parent.genesis,
        fingerprint:parent.fingerprint,height:parent.height,block:parent.block})
}
struct AuthorityState {
    chain:ManuallyDrop<CanonicalStore>,node:Hash,thread:ThreadId,
    selected:Option<Selection>,endpoint:Vec<u16>,objects:Vec<ManuallyDrop<RetainedWindowsPublicObject>>,
    current:Option<ManuallyDrop<CounterOwnWindowsCurrent>>,profile:Option<TpmProfile>,nv_public:Vec<u8>,
    close:Option<RetainedCloseReport>,frozen:bool,
}
pub(crate) struct InstalledCounterWindowsAuthority {state:ManuallyDrop<Box<AuthorityState>>}
pub(crate) struct WindowsCounterAuthorityFailure {
    pub(crate) cause:String,pub(crate) authority:ManuallyDrop<InstalledCounterWindowsAuthority>,
}
impl InstalledCounterWindowsAuthority {
    /// The factory supplies its OWN existing protected canonical observer, not
    /// peer roots, a historical request registry, caller SID/PID or a Boolean.
    pub(crate) fn open_from_own_chain(chain:ManuallyDrop<CanonicalStore>,node:Hash)
        ->std::result::Result<Self,WindowsCounterAuthorityFailure>{
        let mut objects=Vec::new();objects.reserve_exact(7);
        let mut owner=Self{state:ManuallyDrop::new(Box::new(AuthorityState{chain,node,
            thread:std::thread::current().id(),selected:None,endpoint:Vec::new(),objects,
            current:None,profile:None,nv_public:Vec::new(),close:None,frozen:true}))};
        let outcome=owner.initialize();
        match outcome {Ok(())=>Ok(owner),Err(cause)=>Err(WindowsCounterAuthorityFailure{
            cause,authority:ManuallyDrop::new(owner)})}
    }
    fn retain(&mut self,path:PathBuf,maximum:u64)->Result<Vec<u8>>{
        let file=RetainedWindowsPublicObject::open(&path,false,1).map_err(|_|"counter protected original installation artifact")?;
        self.state.objects.push(ManuallyDrop::new(file));
        self.state.objects.last_mut().ok_or("counter original artifact unpublished")?
            .bounded_bytes(maximum).map_err(|_|"counter protected original artifact bytes".to_owned())
    }
    fn initialize(&mut self)->Result<()> {
        let own=parent(&self.state.chain)?;
        let(_,state)=self.state.chain.load().map_err(|_|"counter own current state")?;
        if state.admission_class().map_err(|_|"counter own class")?!=AdmissionClass::Production {
            return Err("NORMAL counter issuer requires own Production context".into());
        }
        let authority=self.state.chain.current_authority(&own).map_err(|_|"counter own authority")?;
        let round=AuthenticatedRound::new(authority).map_err(|_|"counter own authenticated round")?;
        let context=Pins::from_round(&round,self.state.node)?.context();
        let base=Path::new(ROOT);let leaf=hex::encode(context);
        let raw=self.retain(base.join("selections").join(format!("{leaf}.json")),65536)?;
        let pin=self.retain(base.join("selections").join(format!("{leaf}.sha256")),64)?;
        if pin!=hex::encode(Sha256::digest(&raw)).as_bytes(){return Err("counter selected exact declaration pin differs".into());}
        let selected=selection(&raw)?;
        if selected.context!=context||selected.node!=self.state.node||selected.genesis!=own.genesis||selected.fingerprint!=own.fingerprint {
            return Err("counter installation differs from own canonical context".into());
        }
        let profile_raw=self.retain(base.join("public").join(format!("{}.profile",hex::encode(selected.profile))),8192)?;
        let nv=self.retain(base.join("public").join(format!("{}.nv",hex::encode(selected.nv))),80)?;
        let profile=TpmProfile::decode(&profile_raw).map_err(|_|"counter selected profile encoding")?;
        if profile.is_test_value()||profile.provenance.is_none()
            ||profile.commitment().map_err(|_|"counter selected profile commitment")?!=selected.profile
            ||Hash::from(Sha256::digest(&nv))!=selected.nv {
            return Err("counter NORMAL selected real profile/NV artifact unavailable".into());
        }
        // This is OWN mapped-code/installer role only, never a remote provider
        // image attestation. Provider code remains an independently selected
        // accepted deployment input, not a conclusion from pipe credentials.
        let current=CounterOwnWindowsCurrent::open(selected.context,"consumer",selected.consumer_code,
            &selected.consumer.sid,selected.consumer.session,selected.consumer.authentication)?;
        self.state.current=Some(ManuallyDrop::new(current));self.state.endpoint=selected.endpoint.clone();
        self.retain_provider_descriptor(&selected)?;
        self.state.selected=Some(selected);self.state.profile=Some(profile);self.state.nv_public=nv;self.state.frozen=false;
        self.recheck_own()
    }
    fn retain_provider_descriptor(&mut self,selected:&Selection)->Result<()> {
        // Authenticate the selected deployment documents only. Observing the
        // pipe peer never proves that this provider loaded the described code.
        let base=Path::new(ROOT).join("public");
        let raw=self.retain(base.join(format!("{}.release.json",hex::encode(selected.provider_code))),65536)?;
        if Hash::from(Sha256::digest(&raw))!=selected.provider_code{return Err("counter provider release digest differs".into());}
        let release=canonical_document(&raw)?;
        let r=exact(&release,&["format","target","context","role","executable_path","executable_sha256","source_receipt_sha256","loaded_sha256"])?;
        if r["format"]!="build8/counter/windows-release-v1"||r["target"]!="windows-x86_64"
            ||r["role"]!="provider"||hash(&r["context"])?!=selected.context {
            return Err("counter provider release selected role/context differs".into());
        }
        let executable=r["executable_path"].as_str().ok_or("counter provider executable path type")?;
        if !executable.starts_with("C:\\")||executable.len()>32768||executable.contains('/')||executable.contains('\0') {
            return Err("counter provider executable path bound/spelling".into());
        }
        let executable_pin=hash(&r["executable_sha256"])?;
        let source_pin=hash(&r["source_receipt_sha256"])?;let loaded_pin=hash(&r["loaded_sha256"])?;
        let raw=self.retain(base.join(format!("{}.source.json",hex::encode(source_pin))),65536)?;
        if Hash::from(Sha256::digest(&raw))!=source_pin{return Err("counter provider source receipt digest differs".into());}
        let source=canonical_document(&raw)?;
        let s=exact(&source,&["format","target","context","role","source_tree_sha256","build_recipe_sha256","toolchain_sha256","executable_sha256"])?;
        if s["format"]!="build8/counter/release-source-v1"||s["target"]!=r["target"]||s["role"]!="provider"
            ||hash(&s["context"])?!=selected.context||hash(&s["executable_sha256"])?!=executable_pin {
            return Err("counter provider source selected role/context differs".into());
        }
        for name in ["source_tree_sha256","build_recipe_sha256","toolchain_sha256"]{hash(&s[name])?;}
        let raw=self.retain(base.join(format!("{}.loaded.json",hex::encode(loaded_pin))),65536)?;
        if Hash::from(Sha256::digest(&raw))!=loaded_pin{return Err("counter provider loaded descriptor digest differs".into());}
        let loaded=canonical_document(&raw)?;
        let l=exact(&loaded,&["format","target","context","role","source_receipt_sha256","objects","backing_identity"])?;
        if l["format"]!="build8/counter/windows-loaded-v1"||l["target"]!=r["target"]||l["role"]!="provider"
            ||hash(&l["context"])?!=selected.context||hash(&l["source_receipt_sha256"])?!=source_pin
            ||l["backing_identity"]!="nt-are-mapped-files-the-same-v1" {
            return Err("counter provider loaded descriptor selected role/context differs".into());
        }
        CounterOwnWindowsCurrent::validate_selected_release(&l["objects"],executable,executable_pin)?;Ok(())
    }
    pub(crate) fn endpoint_utf16(&self)->&[u16]{&self.state.endpoint}
    pub(crate) fn recheck_own(&mut self)->Result<()> {
        if self.state.frozen||self.state.thread!=std::thread::current().id(){return Err("counter installed owner frozen/wrong thread".into());}
        self.state.frozen=true;
        for object in &mut self.state.objects{object.recheck().map_err(|_|"counter original installation artifacts changed")?;}
        self.state.current.as_mut().ok_or("counter own current code absent")?.recheck()?;
        let selected=self.state.selected.as_ref().ok_or("counter exact selected declaration absent")?;
        let own=parent(&self.state.chain)?;let(_,state)=self.state.chain.load().map_err(|_|"counter own canonical current state")?;
        if state.admission_class().map_err(|_|"counter own current class")?!=AdmissionClass::Production {
            return Err("counter own current class changed".into());
        }
        let authority=self.state.chain.current_authority(&own).map_err(|_|"counter own current authority")?;
        let member=authority.voters.get(&self.state.node).ok_or("counter own current member absent")?;
        let profile=self.state.profile.as_ref().ok_or("counter current profile absent")?;
        if !member.admitted||!member.physical||!member.eligible||member.revoked
            ||member.profile!=selected.profile||member.hardware_generation!=selected.hardware||member.key_generation!=selected.key
            ||public_key(&profile.voting_public,false).map_err(|_|"counter own selected voting key")?!=member.tpm_public
            ||Pins::from_round(&AuthenticatedRound::new(authority).map_err(|_|"counter current authenticated round")?,self.state.node)?.context()!=selected.context {
            return Err("counter selected context/member/profile/generations changed".into());
        }
        self.state.frozen=false;Ok(())
    }
    fn matches_peer(&self,observed:&KernelPipePeerObservation)->Result<()> {
        let selected=self.state.selected.as_ref().ok_or("counter selected declaration absent")?;
        let security=observed.pipe_security();
        if observed.process_id()!=selected.provider_pid||observed.creation_time()!=selected.provider_creation
            ||observed.session_id()!=selected.provider.session||observed.authentication_luid()!=selected.provider.authentication
            ||observed.token_id()!=selected.provider_token||observed.user_sid()!=selected.provider.sid.as_slice()
            ||security.owner_sid()!=selected.pipe.owner.as_slice()||security.control()!=selected.pipe.control
            ||security.aces().len()!=selected.pipe.aces.len() {
            return Err("counter ORIGINAL kernel provider identity/security differs from selected role".into());
        }
        for(actual,expected)in security.aces().iter().zip(&selected.pipe.aces){
            if actual.kind()!=expected.kind||actual.flags()!=expected.flags||actual.mask()!=expected.mask||actual.sid()!=expected.sid.as_slice() {
                return Err("counter ORIGINAL pipe selected exact ACE differs".into());
            }
        }Ok(())
    }
    pub(crate) fn bind_observed_peer(mut self,observed:&KernelPipePeerObservation)
        ->std::result::Result<AuthorizedWindowsCounterPeer,WindowsCounterAuthorityFailure>{
        let checked=(||{self.recheck_own()?;self.matches_peer(observed)})();// no I/O permission on refusal
        if let Err(cause)=checked{return Err(WindowsCounterAuthorityFailure{cause,authority:ManuallyDrop::new(self)});}
        let binding=observed.binding_for_installed_issuer();
        Ok(AuthorizedWindowsCounterPeer{authority:self,binding})
    }
    fn close_after_transport(mut self)->std::result::Result<(ManuallyDrop<CanonicalStore>,RetainedCloseReport),WindowsCounterAuthorityFailure>{
        let checked=(||{
            self.recheck_own()?;
            let count=self.state.objects.iter().map(|file|file.retained_file_count())
                .try_fold(0usize,|sum,count|sum.checked_add(count)).ok_or("counter native close count overflow")?;
            let current=self.state.current.as_ref().ok_or("counter current close owner absent")?
                .retained_file_count().ok_or("counter current close count overflow")?;
            let report=RetainedCloseReport::prepare(count.checked_add(current).ok_or("counter close total overflow")?)?;
            self.state.close=Some(report);Ok::<(),String>(())
        })();
        if let Err(cause)=checked{return Err(WindowsCounterAuthorityFailure{cause,authority:ManuallyDrop::new(self)});}
        self.state.frozen=true;
        // Every permitted non-lease close is independently observed once.
        // Unknown reports/current holders keep the whole canonical observer.
        while let Some(file)=self.state.objects.pop(){
            ManuallyDrop::into_inner(file).close_retained_into(self.state.close.as_mut().expect("prepared exact close report"));
        }
        let current=ManuallyDrop::into_inner(self.state.current.take().expect("prepared current close owner"));
        if let Err(current)=current.close_retained_into(self.state.close.as_mut().expect("prepared exact close report")){
            self.state.current=Some(current);
        }
        if self.state.current.is_some()||!self.state.close.as_ref().expect("prepared exact close report").retained_handles_closed(){
            return Err(WindowsCounterAuthorityFailure{cause:"counter original native close uncertain; canonical custody retained".into(),
                authority:ManuallyDrop::new(self)});
        }
        let mut state=ManuallyDrop::into_inner(self.state);
        // This transfers the SAME canonical owner to the factory's separate
        // checked database shutdown. It does not close SQLite or confer a VFS.
        let chain=ManuallyDrop::new(unsafe{ManuallyDrop::take(&mut state.chain)});
        let report=state.close.take().expect("completed exact close report");Ok((chain,report))
    }
}
pub(crate) struct AuthorizedWindowsCounterPeer {
    authority:InstalledCounterWindowsAuthority,binding:KernelPipePeerBinding,
}
impl AuthorizedWindowsCounterPeer {
    pub(crate) fn binding(&self)->&KernelPipePeerBinding{&self.binding}
    pub(crate) fn context(&self)->Hash{self.authority.state.selected.as_ref().expect("issued selected peer").context}
    pub(crate) fn recheck_original(&mut self,observed:&KernelPipePeerObservation)->Result<()> {
        if !self.binding.matches(observed){return Err("counter permit ORIGINAL native pipe differs".into());}
        self.authority.recheck_own()?;self.authority.matches_peer(observed)
    }
    pub(crate) fn profile(&self)->&TpmProfile{self.authority.state.profile.as_ref().expect("issued selected profile")}
    pub(crate) fn nv_public_sha256(&self)->Hash{self.authority.state.selected.as_ref().expect("issued selected peer").nv}
    pub(crate) fn nv_public(&self)->&[u8]{&self.authority.state.nv_public}
    pub(crate) fn encrypted_role_pins(&self)->(Hash,Hash){
        let selected=self.authority.state.selected.as_ref().expect("issued selected peer");
        (selected.node_cipher,selected.continuity_cipher)
    }
    /// Only the owned transport's consuming settled close hands back this
    /// permit. The factory must retain the original transport receipt too.
    pub(crate) fn close_after_transport(self)->std::result::Result<(ManuallyDrop<CanonicalStore>,RetainedCloseReport),WindowsCounterAuthorityFailure>{
        self.authority.close_after_transport()
    }
}

#[cfg(test)]
mod declaration_controls {
    use super::*;
    fn declaration()->Value {
        let consumer="010500000000000515000000010000000200000003000000e8030000";
        let provider="010500000000000515000000010000000200000003000000e9030000";
        let context=hex::encode([1u8;32]);
        serde_json::json!({"format":"build8/counter/windows-bridge-v1","role":"NodeContinuity",
            "context":context,"node":hex::encode([2u8;32]),"genesis":hex::encode([3u8;32]),
            "fingerprint":hex::encode([4u8;32]),"profile":hex::encode([5u8;32]),"nv_public":hex::encode([6u8;32]),
            "hardware_generation":1,"key_generation":1,
            "consumer":{"sid":consumer,"session":1,"authentication_luid":10},
            "provider":{"sid":provider,"session":1,"authentication_luid":20},
            "provider_pid":100,"provider_creation_time":1000,"provider_token_id":30,
            "counter_pipe":format!(r"\\.\pipe\Mutiny-CounterV2-{}-nv",hex::encode([1u8;32])),
            "pipe_security":{"owner_sid":provider,"control":4100,"aces":[
                {"kind":0,"flags":0,"mask":1048578,"sid":consumer},
                {"kind":0,"flags":0,"mask":2032127,"sid":provider}]},
            "consumer_code":hex::encode([7u8;32]),"provider_code":hex::encode([8u8;32]),
            "node_ciphertext":hex::encode([9u8;32]),"continuity_ciphertext":hex::encode([10u8;32])})
    }
    fn parse(value:&Value)->Result<Selection>{selection(&serde_json::to_vec(value).unwrap())}
    #[test]
    fn modeled_counter_declaration_exact_schema_role_pipe_and_native_sid_encoding(){
        let value=declaration();assert!(parse(&value).is_ok());
        let mut changed=value.clone();changed["caller_approved"]=serde_json::json!(true);assert!(parse(&changed).is_err());
        let mut changed=value.clone();changed["counter_pipe"]=serde_json::json!(r"\\.\pipe\ClockOwner");assert!(parse(&changed).is_err());
        let mut changed=value.clone();changed["consumer"]["sid"]=changed["provider"]["sid"].clone();assert!(parse(&changed).is_err());
        let mut changed=value;changed["provider"]["sid"]=serde_json::json!("0105000000000005");assert!(parse(&changed).is_err());
    }
    #[test]
    fn modeled_counter_pipe_client_cannot_create_instance_or_mutate_selected_security(){
        let value=declaration();assert!(parse(&value).is_ok());
        for rights in [4u32,0x10000,0x40000,0x80000,0x10000000,0x40000000] {
            let mut changed=value.clone();changed["pipe_security"]["aces"][0]["mask"]=serde_json::json!(1048578u32|rights);
            assert!(parse(&changed).is_err());
        }
        let mut foreign=value.clone();foreign["pipe_security"]["aces"][0]["sid"]=serde_json::json!("010500000000000515000000010000000200000003000000ea030000");
        assert!(parse(&foreign).is_err());
        let mut unprotected=value;unprotected["pipe_security"]["control"]=serde_json::json!(4);assert!(parse(&unprotected).is_err());
    }
}
