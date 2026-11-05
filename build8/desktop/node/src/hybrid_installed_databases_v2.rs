//! Fixed installed existing-only database selection. No raw caller path,
//! context, capacity, Genesis or qualification Boolean issues this capability.
#![cfg(target_os="linux")]
use crate::hybrid_installed_counter_v2::{HeldPublic,HeldPublicClose};
use crate::genesis_artifact_v2::{self,VerifiedGenesisV2};
use mutiny_consensus_v8::{Hash,canonical_store_v2::CanonicalStore,
    genesis_v2::GenesisClass,votes_v2::AuthenticatedRound};
use sha2::{Digest,Sha256};
use std::{ffi::CString,mem::ManuallyDrop,path::PathBuf};
type Result<T>=std::result::Result<T,String>;
const ROOT:&str="/var/lib/mutiny/custody-v2";
const CANONICAL_CAPACITY:i64=1024*1024*1024;

struct Declaration {genesis:Hash,block:Hash,evidence:Hash,node:Hash,namespace:Hash,counter_capacity:i64}
fn decode(raw:&[u8])->Result<Declaration>{
    if raw.is_empty()||raw.len()>4096{return Err("installed database declaration bound".into());}
    let v:serde_json::Value=serde_json::from_slice(raw).map_err(|_|"installed database declaration JSON")?;
    let o=v.as_object().ok_or("installed database declaration object")?;
    let fields=["schema","genesis_artifact_sha256","genesis_block_hash","public_evidence_sha256",
        "node","namespace","counter_capacity_bytes"];
    if o.len()!=fields.len()||fields.iter().any(|k|!o.contains_key(*k))
        ||v["schema"]!="BUILD8-INSTALLED-DATABASES-V1"
        ||serde_json::to_vec(&v).map_err(|_|"installed database canonical encoding")?!=raw{
        return Err("installed database exact canonical schema".into());}
    let hash=|name:&str|->Result<Hash>{
        let text=v[name].as_str().ok_or("installed database digest type")?;
        if text.len()!=64||!text.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c)){
            return Err("installed database lowercase digest".into());}
        let mut out=[0;32];hex::decode_to_slice(text,&mut out).map_err(|_|"installed database digest")?;
        if out==[0;32]{return Err("installed database zero digest".into());}Ok(out)
    };
    let counter_capacity=i64::try_from(v["counter_capacity_bytes"].as_u64()
        .ok_or("installed counter capacity integer")?).map_err(|_|"installed counter capacity range")?;
    if counter_capacity<=0{return Err("installed counter capacity must be explicitly positive".into());}
    Ok(Declaration{genesis:hash("genesis_artifact_sha256")?,block:hash("genesis_block_hash")?,
        evidence:hash("public_evidence_sha256")?,node:hash("node")?,namespace:hash("namespace")?,counter_capacity})
}
struct State {
    declaration:Option<HeldPublic>,pin:Option<HeldPublic>,genesis:Option<HeldPublic>,evidence:Option<HeldPublic>,
    selected:Option<Declaration>,verified:Option<VerifiedGenesisV2>,parent:Option<CString>,frozen:bool,
    close_unknown:Vec<HeldPublicClose>,
}
pub(crate) struct InstalledDatabases {state:ManuallyDrop<Box<State>>}
pub(crate) struct DatabaseSelectionRefusal {cause:String,owner:ManuallyDrop<InstalledDatabases>}
impl DatabaseSelectionRefusal {
    pub(crate) fn cause(&self)->&str{&self.cause}
    pub(crate) fn into_retained(self)->(String,ManuallyDrop<InstalledDatabases>){(self.cause,self.owner)}
}
/// Borrowed opaque request; only the exact held installed selection issues it.
pub(crate) struct SelectedExistingDatabase<'a>{parent:&'a CString,name:&'static str,capacity:i64}
impl SelectedExistingDatabase<'_>{
    pub(super) fn parent(&self)->&CString{self.parent}
    pub(super) fn name(&self)->&'static str{self.name}
    pub(super) fn capacity(&self)->i64{self.capacity}
}
impl InstalledDatabases {
    pub(crate) fn open_installed()->std::result::Result<Self,DatabaseSelectionRefusal>{
        // Publish every partial original artifact before any acquisition. A
        // failed constructor or unwind cannot implicitly close prior artifacts.
        let mut out=Self{state:ManuallyDrop::new(Box::new(State{declaration:None,pin:None,genesis:None,evidence:None,
            selected:None,verified:None,parent:None,frozen:true,close_unknown:Vec::with_capacity(4)}))};
        let checked=(||->Result<()>{
            let root=PathBuf::from(ROOT);
            out.state.declaration=Some(HeldPublic::open(root.join("database-selection.json"),4096)?);
            out.state.pin=Some(HeldPublic::open(root.join("database-selection.sha256"),64)?);
            let raw=out.state.declaration.as_ref().ok_or("installed declaration absent")?.bytes();
            if out.state.pin.as_ref().ok_or("installed selection pin absent")?.bytes()!=hex::encode(Sha256::digest(raw)).as_bytes(){
                return Err("installed database administrator-selected artifact differs".into());}
            let selected=decode(raw)?;
            let trust=genesis_artifact_v2::supported_trust_v2(selected.genesis,selected.block)?;
            let genesis_path=root.join("public").join(format!("{}.genesis",hex::encode(selected.genesis)));
            let witness_path=root.join("public").join(format!("{}.genesis-witness",hex::encode(selected.evidence)));
            out.state.genesis=Some(HeldPublic::open_genesis(genesis_path)?);
            out.state.evidence=Some(HeldPublic::open_genesis_witness(witness_path)?);
            let genesis=out.state.genesis.as_ref().ok_or("installed genesis absent")?.bytes();
            let evidence=out.state.evidence.as_ref().ok_or("installed genesis witness absent")?.bytes();
            if <Hash>::from(Sha256::digest(evidence))!=selected.evidence{
                return Err("installed public witness digest differs".into());}
            let verified=VerifiedGenesisV2::verify_with_public_evidence(genesis,&trust,evidence)?;
            if verified.genesis.class!=GenesisClass::Production{return Err("installed NORMAL database Genesis class refused".into());}
            // No discovered SQLite values select the directory or capacities.
            let parent=root.join("databases").join(hex::encode(selected.namespace));
            use std::os::unix::ffi::OsStrExt;
            out.state.parent=Some(CString::new(parent.as_os_str().as_bytes()).map_err(|_|"installed database parent NUL")?);
            out.state.selected=Some(selected);out.state.verified=Some(verified);out.state.frozen=false;
            out.recheck_artifacts()
        })();
        match checked{Ok(())=>Ok(out),Err(cause)=>Err(DatabaseSelectionRefusal{cause,owner:ManuallyDrop::new(out)})}
    }
    pub(crate) fn recheck_artifacts(&mut self)->Result<()>{
        if self.state.frozen{return Err("installed database selection frozen".into());}self.state.frozen=true;
        let s=&mut **self.state;
        for object in [&mut s.declaration,&mut s.pin,&mut s.genesis,&mut s.evidence]{
            object.as_mut().ok_or("installed database original artifact absent")?.recheck()?;
        }
        self.state.frozen=false;Ok(())
    }
    pub(crate) fn verified_genesis(&self)->Result<&VerifiedGenesisV2>{
        if self.state.frozen{return Err("installed database selection frozen".into());}
        self.state.verified.as_ref().ok_or_else(||"installed authenticated Genesis absent".into())
    }
    pub(crate) fn node(&self)->Result<Hash>{
        if self.state.frozen{return Err("installed database selection frozen".into());}
        Ok(self.state.selected.as_ref().ok_or("installed database selection absent")?.node)
    }
    pub(crate) fn namespace(&self)->Result<Hash>{
        if self.state.frozen{return Err("installed database selection frozen".into());}
        Ok(self.state.selected.as_ref().ok_or("installed database selection absent")?.namespace)
    }
    /// The complete authenticated public sealed Genesis artifact, not a block
    /// or caller-supplied replacement, for the actual installed clock issuer.
    pub(crate) fn original_genesis_bytes(&mut self)->Result<&[u8]>{
        self.recheck_artifacts()?;
        Ok(self.state.genesis.as_ref().ok_or("installed original Genesis absent")?.bytes())
    }
    /// Reversible pending cache only. This path never opens a canonical or
    /// counter store and cannot select a signing context or initialize custody.
    pub(crate) fn cache_directory(&mut self)->Result<PathBuf>{
        self.recheck_artifacts()?;
        Ok(PathBuf::from(ROOT).join("cache").join(hex::encode(self.namespace()?)))
    }
    /// Repeated after actual full canonical replay and at factory entries.
    /// Namespace must be the own current role context, not a database assertion.
    pub(crate) fn recheck_canonical(&mut self,chain:&CanonicalStore)->Result<()>{
        self.recheck_artifacts()?;self.state.frozen=true;
        let selected=self.state.selected.as_ref().ok_or("installed database selection absent")?;
        let verified=self.state.verified.as_ref().ok_or("installed genesis absent")?;
        let(head,_)=chain.load().map_err(|_|"installed own canonical head")?;
        let(parent,state,_)=chain.execution_parent(head.height).map_err(|_|"installed own canonical execution parent")?;
        if parent.height!=head.height||parent.block!=head.block||parent.genesis!=verified.genesis.identity
            ||parent.fingerprint!=verified.genesis.fingerprint
            ||state.admission_class().map_err(|_|"installed canonical class")?
                !=mutiny_consensus_v8::provenance::AdmissionClass::Production{
            return Err("installed database own canonical Genesis/class mismatch".into());}
        let anchor=mutiny_consensus_v8::anchors::FinalizedAnchor{network:mutiny_consensus_v8::NETWORK_ID,
            genesis:parent.genesis,fingerprint:parent.fingerprint,height:parent.height,block:parent.block};
        let authority=chain.current_authority(&anchor).map_err(|_|"installed own current authority")?;
        let context=crate::continuity_custody_v2::Pins::from_round(
            &AuthenticatedRound::new(authority).map_err(|_|"installed own authenticated round")?,selected.node)?.context();
        if context!=selected.namespace{return Err("installed database namespace differs from own current role context".into());}
        self.state.frozen=false;Ok(())
    }
    pub(crate) fn canonical_request(&mut self)->Result<SelectedExistingDatabase<'_>>{
        self.recheck_artifacts()?;
        let s=&**self.state;
        Ok(SelectedExistingDatabase{parent:s.parent.as_ref().ok_or("installed database parent absent")?,
            name:"canonical.sqlite",capacity:CANONICAL_CAPACITY})
    }
    pub(crate) fn counter_request(&mut self,chain:&CanonicalStore)->Result<SelectedExistingDatabase<'_>>{
        // Derive current context again at this actual opening entry. No cached
        // checked flag or selected documentary hash substitutes for authority.
        self.recheck_canonical(chain)?;
        let s=&**self.state;let selected=s.selected.as_ref().ok_or("installed database selection absent")?;
        Ok(SelectedExistingDatabase{parent:s.parent.as_ref().ok_or("installed database parent absent")?,
            name:"counter.sqlite",capacity:selected.counter_capacity})
    }
    /// Current failure closes nothing; each allowed original artifact close is
    /// independently attempted and its whole typed uncertainty remains owned.
    pub(crate) fn close(mut self)->std::result::Result<(),DatabaseSelectionRefusal>{
        if let Err(cause)=self.recheck_artifacts(){return Err(DatabaseSelectionRefusal{cause,owner:ManuallyDrop::new(self)});}
        let s=&mut **self.state;s.frozen=true;
        for original in [s.declaration.take(),s.pin.take(),s.genesis.take(),s.evidence.take()].into_iter().flatten(){
            if let Err(unknown)=original.close(){s.close_unknown.push(unknown);}
        }
        if !s.close_unknown.is_empty(){return Err(DatabaseSelectionRefusal{
            cause:"installed database artifact close unknown".into(),owner:ManuallyDrop::new(self)});}
        unsafe{ManuallyDrop::drop(&mut self.state)};Ok(())
    }
}

#[cfg(test)]
mod modeled_database_selection_controls{
    use super::*;
    fn sample()->serde_json::Value{serde_json::json!({"schema":"BUILD8-INSTALLED-DATABASES-V1",
        "genesis_artifact_sha256":hex::encode([1;32]),"genesis_block_hash":hex::encode([2;32]),
        "public_evidence_sha256":hex::encode([3;32]),"node":hex::encode([4;32]),
        "namespace":hex::encode([5;32]),"counter_capacity_bytes":8192})}
    #[test]
    fn modeled_exact_fixed_database_selection_has_no_capacity_default_or_caller_path(){
        let v=sample();assert_eq!(decode(&serde_json::to_vec(&v).unwrap()).unwrap().counter_capacity,8192);
        let mut zero=v.clone();zero["counter_capacity_bytes"]=0.into();assert!(decode(&serde_json::to_vec(&zero).unwrap()).is_err());
        let mut missing=v.clone();missing.as_object_mut().unwrap().remove("counter_capacity_bytes");
        assert!(decode(&serde_json::to_vec(&missing).unwrap()).is_err());
        let mut arbitrary=v.clone();arbitrary["path"]="/tmp/other".into();assert!(decode(&serde_json::to_vec(&arbitrary).unwrap()).is_err());
        let mut wide=v;wide["counter_capacity_bytes"]=u64::MAX.into();assert!(decode(&serde_json::to_vec(&wide).unwrap()).is_err());
    }
}
