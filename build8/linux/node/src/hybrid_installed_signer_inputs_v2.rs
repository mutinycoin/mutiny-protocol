//! Public installer selections only. No password, private key, caller path or
//! clock qualification flag is represented here. Missing selections refuse.
#![cfg(target_os="linux")]
use crate::hybrid_installed_counter_v2::{HeldPublic,HeldPublicClose};
use crate::hybrid_installed_databases_v2::InstalledDatabases;
use mutiny_consensus_v8::Hash;
use sha2::{Digest,Sha256};
use std::{mem::ManuallyDrop as MD,path::PathBuf};
type Result<T>=std::result::Result<T,String>;
const ROOT:&str="/var/lib/mutiny/custody-v2";
struct Selection{context:Hash,clock:Hash,tool:Hash,lifetime_ns:u64}
fn decode(raw:&[u8])->Result<Selection>{
    if raw.is_empty()||raw.len()>4096{return Err("installed signer selection bound".into());}
    let v:serde_json::Value=serde_json::from_slice(raw).map_err(|_|"installed signer selection JSON")?;
    let o=v.as_object().ok_or("installed signer selection object")?;
    let fields=["schema","context","clock_record_sha256","activation_tool_sha256","activation_lifetime_ns"];
    if o.len()!=fields.len()||fields.iter().any(|k|!o.contains_key(*k))
        ||v["schema"]!="BUILD8-INSTALLED-SIGNER-INPUTS-V1"
        ||serde_json::to_vec(&v).map_err(|_|"installed signer selection encoding")?!=raw{
        return Err("installed signer exact canonical fields".into());}
    let digest=|name:&str|->Result<Hash>{
        let t=v[name].as_str().ok_or("installed signer digest type")?;
        if t.len()!=64||!t.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){
            return Err("installed signer digest spelling".into());}
        let mut out=[0;32];hex::decode_to_slice(t,&mut out).map_err(|_|"installed signer digest")?;
        if out==[0;32]{return Err("installed signer zero digest".into());}Ok(out)
    };
    // This explicit administrator input is NOT inferred from acquisition
    // cadence, holdover, elapsed samples or the TEST runner's local limit.
    let lifetime_ns=v["activation_lifetime_ns"].as_u64().ok_or("installed signer lifetime integer")?;
    if lifetime_ns==0{return Err("installed signer lifetime absent/zero".into());}
    Ok(Selection{context:digest("context")?,clock:digest("clock_record_sha256")?,tool:digest("activation_tool_sha256")?,lifetime_ns})
}
struct State{declaration:Option<HeldPublic>,pin:Option<HeldPublic>,clock:Option<HeldPublic>,
    selection:Option<Selection>,frozen:bool,unknown:Vec<HeldPublicClose>}
pub(crate) struct InstalledSignerInputs{state:MD<Box<State>>}
pub(crate) struct SignerInputRefusal{cause:String,owner:MD<InstalledSignerInputs>}
impl SignerInputRefusal{pub(crate) fn cause(&self)->&str{&self.cause}}
impl InstalledSignerInputs{
    pub(crate) fn open(db:&mut InstalledDatabases)->std::result::Result<Self,SignerInputRefusal>{
        let mut out=Self{state:MD::new(Box::new(State{declaration:None,pin:None,clock:None,
            selection:None,frozen:true,unknown:Vec::with_capacity(3)}))};
        let result=(||->Result<()>{
            db.recheck_artifacts()?;
            let root=PathBuf::from(ROOT);
            out.state.declaration=Some(HeldPublic::open(root.join("signer-selection.json"),4096)?);
            out.state.pin=Some(HeldPublic::open(root.join("signer-selection.sha256"),64)?);
            let raw=out.state.declaration.as_ref().ok_or("original signer selection absent")?.bytes();
            if out.state.pin.as_ref().ok_or("original signer pin absent")?.bytes()!=hex::encode(Sha256::digest(raw)).as_bytes(){
                return Err("installed administrator signer pin differs".into());}
            let selected=decode(raw)?;
            if selected.context!=db.namespace()?{return Err("installed signer/database context differs".into());}
            out.state.clock=Some(HeldPublic::open(root.join("public").join(format!("{}.clock",hex::encode(selected.clock))),64*1024)?);
            if <Hash>::from(Sha256::digest(out.state.clock.as_ref().ok_or("original clock record absent")?.bytes()))!=selected.clock{
                return Err("installed selected clock record digest differs".into());}
            out.state.selection=Some(selected);out.state.frozen=false;out.recheck(db)
        })();
        match result{Ok(())=>Ok(out),Err(cause)=>Err(SignerInputRefusal{cause,owner:MD::new(out)})}
    }
    pub(crate) fn recheck(&mut self,db:&mut InstalledDatabases)->Result<()>{
        if self.state.frozen{return Err("installed signer inputs frozen".into());}self.state.frozen=true;
        db.recheck_artifacts()?;
        let s=&mut **self.state;
        for original in [&mut s.declaration,&mut s.pin,&mut s.clock]{
            original.as_mut().ok_or("installed signer original absent")?.recheck()?;
        }
        let selected=self.state.selection.as_ref().ok_or("installed signer selection absent")?;
        if selected.context!=db.namespace()?
            ||<Hash>::from(Sha256::digest(self.state.clock.as_ref().ok_or("original clock record absent")?.bytes()))!=selected.clock{
            return Err("installed signer current context/clock record differs".into());}
        self.state.frozen=false;Ok(())
    }
    pub(crate) fn clock_record(&self)->Result<&[u8]>{
        if self.state.frozen{return Err("installed signer inputs frozen".into());}
        Ok(self.state.clock.as_ref().ok_or("original clock record absent")?.bytes())
    }
    pub(crate) fn lifetime_ns(&self)->Result<u64>{
        if self.state.frozen{return Err("installed signer inputs frozen".into());}
        Ok(self.state.selection.as_ref().ok_or("original signer lifetime absent")?.lifetime_ns)
    }
    pub(crate) fn tool_selection(&self)->Result<(PathBuf,Hash)>{
        if self.state.frozen{return Err("installed signer inputs frozen".into());}
        let pin=self.state.selection.as_ref().ok_or("original tool selection absent")?.tool;
        Ok((PathBuf::from(ROOT).join("public").join(format!("{}.tools",hex::encode(pin))),pin))
    }
    pub(crate) fn close(mut self,db:&mut InstalledDatabases)->std::result::Result<(),SignerInputRefusal>{
        if let Err(cause)=self.recheck(db){return Err(SignerInputRefusal{cause,owner:MD::new(self)});}
        self.state.frozen=true;
        for original in [self.state.declaration.take(),self.state.pin.take(),self.state.clock.take()].into_iter().flatten(){
            if let Err(unknown)=original.close(){self.state.unknown.push(unknown);}
        }
        if !self.state.unknown.is_empty(){return Err(SignerInputRefusal{cause:"installed signer original close unknown".into(),owner:MD::new(self)});}
        unsafe{MD::drop(&mut self.state)};Ok(())
    }
}
#[cfg(test)]
mod modeled_signer_selection{
    use super::*;
    #[test]
    fn modeled_signer_lifetime_is_explicit_and_no_clock_cadence_default_exists(){
        let v=serde_json::json!({"schema":"BUILD8-INSTALLED-SIGNER-INPUTS-V1","context":hex::encode([1;32]),
            "clock_record_sha256":hex::encode([2;32]),"activation_tool_sha256":hex::encode([3;32]),"activation_lifetime_ns":17});
        assert_eq!(decode(&serde_json::to_vec(&v).unwrap()).unwrap().lifetime_ns,17);
        let mut zero=v.clone();zero["activation_lifetime_ns"]=0.into();assert!(decode(&serde_json::to_vec(&zero).unwrap()).is_err());
        let mut missing=v.clone();missing.as_object_mut().unwrap().remove("activation_lifetime_ns");
        missing["cadence_seconds"]=17.into();assert!(decode(&serde_json::to_vec(&missing).unwrap()).is_err());
        let mut path=v;path["clock_path"]="/tmp/other".into();assert!(decode(&serde_json::to_vec(&path).unwrap()).is_err());
    }
}
