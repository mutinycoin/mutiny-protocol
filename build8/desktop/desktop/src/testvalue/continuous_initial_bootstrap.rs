//! SOURCE PROPOSAL ONLY. Fresh synthetic originals, then actual process closure,
//! then existing-only provider possession BEFORE H0 publication. No production,
//! original Launch16 recovery, wallet approval or operation finality is conferred.
use super::{bootstrap::ContextPin,continuous_passive::PathPin,control_codec::Context,
    process_auth::{Identity,VerifiedProcess},image_pin::{ImagePin,DatabasePin},
    cache_snapshot::{Object,Snapshot},shutdown::ProviderPin,test_signer_store::Binding};
use mutiny_consensus_v8::{Hash,anchors::FinalizedAnchor,execution::State};
use std::{path::{Path,PathBuf},io::Write};
use sha2::{Digest,Sha256};
type Result<T>=std::result::Result<T,String>;
pub(super) const MARKER:&str="MUTINY-W15-NONSHIPPING-PREPARED-ORIGINALS-BEFORE-H0-V1";
pub(super) const FRESH_MARKER:&str="MUTINY-W15-NONSHIPPING-FRESH-PROVIDER-POSSESSION-BEFORE-H0-V1";
pub(super) const DRAFT:&str="private-prepublication-initial.pending.json";
pub(super) const PROOF:&str="fresh-provider-before-h0-public.json";
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
fn absolute(p:&Path)->bool{p.is_absolute()&&!p.components().any(|c|matches!(c,std::path::Component::ParentDir|std::path::Component::CurDir))&&p.to_str().is_some_and(|s|!s.is_empty()&&s.len()<=4096)}
pub(super) fn absent(p:&Path)->Result<()>{match std::fs::symlink_metadata(p){Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(()),Err(e)=>Err(err(e)),Ok(_)=>Err("Prepublication output already exists; never overwrite or repair".into())}}
pub(super) fn object(pin:&ImagePin,path:&Path)->Object{let id=pin.leaf_id();let mut h=Sha256::new();h.update(b"MUTINY-W15-PUBLIC-INITIAL-NATIVE-ID-V1");h.update(id.volume.to_be_bytes());h.update(id.file);Object{path:path.into(),native_id:h.finalize().into(),rows:pin.hash()}}
pub(super) fn create_public(path:&Path,raw:&[u8])->Result<()>{if !absolute(path)||raw.is_empty()||raw.len()>2*1024*1024{return Err("Bounded create-new public bootstrap receipt required".into());}let mut out=std::fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(err)?;out.write_all(raw).map_err(err)?;out.sync_all().map_err(err)}

#[derive(Clone,Debug,PartialEq,Eq,serde::Serialize,serde::Deserialize)] #[serde(deny_unknown_fields)]
pub(super) struct InitialRole{pub client_root:PathBuf,pub marker:Object,pub side_native:[Hash;4],pub active:crate::wallet_v2::Identity,pub revision:i64}
pub(super) struct RoleHolds{files:Vec<ImagePin>,dbs:Vec<DatabasePin>}
impl RoleHolds{pub(super) fn recheck(&self)->Result<()>{for p in &self.files{p.recheck()?;}for p in &self.dbs{p.recheck()?;}Ok(())}}
impl InitialRole{
    /// All four existing sides and marker inspected before any mutable Controller.
    /// Public active identity is derived from retained trusted initial WalletBook,
    /// then compared against actual locked Controller status separately below.
    pub(super) fn observe(client:&Path,role:super::control_codec::Role,c:Context,g:&FinalizedAnchor,s:&State,owner:&VerifiedProcess)->Result<(Self,RoleHolds)>{
        let root=crate::wallet_controller_v2::VaultRoot::new(&client.join("role-vault")).map_err(err)?;
        let marker_path=root.path().join("NEW-CONTINUOUS-TEST-ROLE.marker");let marker=ImagePin::open(&marker_path,&owner.identity().user_sid)?;
        let m:serde_json::Value=serde_json::from_slice(&marker.read_bounded(2048)?).map_err(err)?;
        if m["format"]!=super::role_vault::ROLE_VAULT_MARKER||m["role"]!=role as u8||m["campaign"]!=hex::encode(c.campaign)||m["source"]!=hex::encode(c.source)||m["h0"]!=hex::encode(c.h0)||m["genesis"]!=hex::encode(c.genesis)||m["fingerprint"]!=hex::encode(c.fingerprint)||m["original_launch16"]!=false||m["production_authorized"]!=false{return Err("Initial original marker/context differs".into());}
        let dbs=super::continuous_passive::preflight_side(&root,c,g.network,owner)?;
        if dbs.len()!=4{return Err("Exactly four original role sides required".into());}
        let tag=match role{super::control_codec::Role::WalletA=>78,super::control_codec::Role::WalletC=>79,super::control_codec::Role::Treasury=>80};
        let authority=s.coins.get(&mutiny_consensus_v8::transactions::OutPoint{transaction:[tag;32],index:0}).ok_or("Initial role coin absent")?.output.owner;
        let descriptor=s.wallets.current(authority).ok_or("Initial role descriptor absent")?;
        let (public,generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(descriptor).map_err(err)?;
        if public.role!=mutiny_crypto_v2::Role::WalletOwner||generation!=1{return Err("Initial original wallet generation/role differs".into());}
        // Observe committed status only after every side was independently validated.
        let store=crate::store_v2::Store::open(&root.vault()).map_err(err)?;let status=store.status().map_err(err)?.ok_or("Initialized original vault pointer absent")?;
        if status.revision!=1||status.staged.is_some()||status.superseded.is_some()||status.active.generation!=1||status.active.authority_id!=hex::encode(authority)||status.active.owner_descriptor!=hex::encode(descriptor){return Err("Exact existing initial vault status required; no save/restore fallback".into());}drop(store);
        let result=Self{client_root:client.into(),marker:object(&marker,&marker_path),side_native:dbs.iter().map(|p|p.native_id_hash()).collect::<Vec<_>>().try_into().map_err(|_|"Four side identities")?,active:status.active,revision:status.revision};
        let held=RoleHolds{files:vec![marker],dbs};held.recheck()?;owner.recheck()?;Ok((result,held))
    }
    pub(super) fn preflight(&self,role:super::control_codec::Role,c:Context,g:&FinalizedAnchor,s:&State,owner:&VerifiedProcess)->Result<RoleHolds>{let(actual,held)=Self::observe(&self.client_root,role,c,g,s,owner)?;if actual!=*self{return Err("Original initial role native/marker/current identity changed".into());}Ok(held)}
}

#[derive(Clone,serde::Serialize,serde::Deserialize)] #[serde(deny_unknown_fields)]
pub(super) struct Prepared{
    pub format:String,pub preparing_process:Identity,pub context:ContextPin,pub source_git:String,pub source_manifest:PathPin,pub roots_plan:PathPin,
    pub service_root:PathBuf,pub client_roots:[PathBuf;3],pub draft:Object,
    pub canonical_paths:[PathBuf;6],pub canonical_native:[Hash;6],pub initial_block:Hash,pub provider:ProviderPin,
    pub caches:[Snapshot;4],pub roles:[InitialRole;3],pub license:Hash,pub backup_license:Hash,pub buyer_authority:Hash,
}
impl Prepared{
    pub(super) fn binding(&self)->Binding{let c=self.context.context();let p=&self.provider;Binding{campaign:c.campaign,source:c.source,genesis:c.genesis,fingerprint:c.fingerprint,initial_root:p.initial_root,original_store_identities:p.original_store_identities,native_custody_identity:p.native_custody_identity,native_guard_identity:p.native_guard_identity,node_descriptor:p.node_descriptor.clone(),continuity_descriptor:p.continuity_descriptor.clone()}}
    pub(super) fn validate(&self)->Result<()>{
        let c=self.context.context();
        if self.format!=MARKER||[c.campaign,c.source,c.h0,c.genesis,c.fingerprint,self.initial_block,self.provider.initial_root,self.license,self.backup_license,self.buyer_authority,self.provider.journal.commitment].contains(&[0;32])||self.license==self.backup_license||self.preparing_process.pid==0||self.preparing_process.start_filetime==0||self.preparing_process.image_sha256==[0;32]||self.source_git.len()!=40||!self.source_git.bytes().all(|b|b.is_ascii_hexdigit())||self.source_manifest.sha256!=c.source||self.roots_plan.sha256==[0;32]||self.draft.rows!=c.h0||self.draft.native_id==[0;32]||self.canonical_native.contains(&[0;32])||self.provider.journal.tip!=0||self.provider.journal.commits!=0||self.provider.journal.works!=0{return Err("Exact durable original initial provider/context/journal pins required".into());}
        let roots=[&self.service_root,&self.client_roots[0],&self.client_roots[1],&self.client_roots[2]];
        for(i,p)in roots.iter().enumerate(){if !absolute(p)||roots.iter().skip(i+1).any(|q|p.starts_with(q)||q.starts_with(p)){return Err("Distinct nonoverlapping initialized originals required".into());}}
        for p in [&self.source_manifest.path,&self.roots_plan.path]{if !absolute(p)||roots.iter().any(|r|p.starts_with(r)){return Err("External immutable source/root plan required".into());}}
        if self.draft.path!=self.service_root.join(DRAFT)||self.canonical_paths[..3]!=[self.service_root.join("certifier.sqlite"),self.service_root.join("local-node-chain.sqlite"),self.service_root.join("remote-node-chain.sqlite")]{return Err("Exact private prepublication file/six store ordering required".into());}
        let mut h=Sha256::new();h.update(super::existing_six::MARKER.as_bytes());for id in self.canonical_native{h.update(id);}if self.provider.original_store_identities!=Hash::from(h.finalize()){return Err("Provider does not bind these original six native identities".into());}
        for i in 0..3{if self.roles[i].client_root!=self.client_roots[i]||self.canonical_paths[i+3]!=self.client_roots[i].join("role-vault/public-chain.sqlite")||self.roles[i].side_native.contains(&[0;32])||self.roles[i].revision!=1{return Err("Exact original initialized role paths/status required".into());}}
        let paths=[self.service_root.join("local-node-payment.sqlite"),self.service_root.join("local-node-payment.submissions.sqlite"),self.service_root.join("remote-node-payment.sqlite"),self.service_root.join("remote-node-payment.submissions.sqlite")];
        for(i,s)in self.caches.iter().enumerate(){if s.main.path!=paths[i]||s.submission!=(i%2==1)||s.main.native_id==[0;32]||s.main.rows==[0;32]{return Err("Exact initial initialized cache/native snapshot required".into());}}
        self.binding().possession_context()?;Ok(())
    }
    fn fresh_identity(&self,current:&Identity,require_same_image:bool)->Result<()>{
        let old=&self.preparing_process;
        if (old.pid,old.start_filetime)==(current.pid,current.start_filetime)||current.start_filetime<=old.start_filetime||current.session!=old.session||current.authentication_luid!=old.authentication_luid||current.user_sid!=old.user_sid||(require_same_image&&(current.image_path!=old.image_path||current.image_sha256!=old.image_sha256)){return Err("Distinct fresh process on the exact pinned original session/context/image required".into());}
        super::process_auth::historical_process_closed(old)
    }
    pub(super) fn require_fresh_service(&self,current:&Identity)->Result<()>{self.validate()?;self.fresh_identity(current,true)}
}

#[derive(Clone,serde::Serialize,serde::Deserialize)] #[serde(deny_unknown_fields)]
pub(super) struct FreshProof{pub format:String,pub prepared_sha256:Hash,pub preparing_process:Identity,pub reopened_process:Identity,pub context:ContextPin,pub node_possession:Vec<u8>,pub continuity_possession:Vec<u8>,pub journal:super::test_signer_store::JournalPin,pub canonical_native:[Hash;6]}
impl FreshProof{
    pub(super) fn verify(&self,p:&Prepared,sha:Hash)->Result<()>{
        if self.format!=FRESH_MARKER||self.prepared_sha256!=sha||sha==[0;32]||self.preparing_process!=p.preparing_process||self.context.context()!=p.context.context()||self.journal!=p.provider.journal||self.canonical_native!=p.canonical_native{return Err("Fresh reopening proof differs from pinned originals/context/journal".into());}
        p.require_fresh_service(&self.reopened_process)?;
        let b=p.binding();let intent=b.possession_context()?;
        for(raw,descriptor,domain)in [(&self.node_possession,&b.node_descriptor,mutiny_crypto_v2::Domain::NodeAdmissionPossession),(&self.continuity_possession,&b.continuity_descriptor,mutiny_crypto_v2::Domain::ContinuityPossession)]{
            if raw.len()!=1394{return Err("Exact bounded public hybrid possession width required".into());}
            let sig=mutiny_crypto_v2::HybridSignature{ed448:raw[..114].try_into().map_err(|_|"Ed448 width")?,fndsa:raw[114..].try_into().map_err(|_|"FNDSA width")?};let(pk,_)=mutiny_crypto_v2::PublicKey::decode_descriptor(descriptor).map_err(err)?;pk.verify(domain,&intent,&sig).map_err(err)?;
        }Ok(())
    }
}
pub(super) struct HeldPrepared{pub value:Prepared,pub sha:Hash,pins:Vec<ImagePin>}
impl HeldPrepared{
    pub(super) fn read(input:&PathPin,owner:&VerifiedProcess,source:Hash,campaign:Hash,manifest:&Path,git:&str)->Result<Self>{
        if !absolute(&input.path)||input.sha256==[0;32]{return Err("Explicit pinned preparation receipt required".into());}
        let pin=ImagePin::open(&input.path,&owner.identity().user_sid)?;if pin.hash()!=input.sha256{return Err("Preparation receipt changed".into());}
        let value:Prepared=serde_json::from_slice(&pin.read_bounded(2*1024*1024)?).map_err(err)?;value.validate()?;
        if value.context.source!=source||value.context.campaign!=campaign||value.source_git!=git||value.source_manifest.path!=manifest||input.path.starts_with(&value.service_root)||value.client_roots.iter().any(|r|input.path.starts_with(r)){return Err("Pinned preparation source/campaign/separate public receipt differs".into());}
        value.fresh_identity(owner.identity(),false)?;
        let source_pin=ImagePin::open(manifest,&owner.identity().user_sid)?;if source_pin.hash()!=source{return Err("Prepared source manifest changed".into());}
        let source_json:serde_json::Value=serde_json::from_slice(&source_pin.read_bounded(16*1024*1024)?).map_err(err)?;if source_json["head"]!=git||source_json["files"].as_array().is_none_or(|f|f.is_empty()||f.len()>4096){return Err("Prepared complete source/Git differs".into());}
        let roots=super::launch_roots::HeldRoots::read(&value.roots_plan,owner,source,campaign)?;if roots.roots.service!=value.service_root||roots.roots.roles!=value.client_roots{return Err("Prepared original root plan differs".into());}roots.recheck()?;
        let root_pin=ImagePin::open(&value.roots_plan.path,&owner.identity().user_sid)?;
        let draft=ImagePin::open(&value.draft.path,&owner.identity().user_sid)?;if object(&draft,&value.draft.path)!=value.draft{return Err("Original private prepublication bytes/native leaf differ".into());}
        let result=Self{value,sha:input.sha256,pins:vec![pin,source_pin,root_pin,draft]};result.recheck()?;owner.recheck()?;Ok(result)
    }
    pub(super) fn initial(&self)->Result<(FinalizedAnchor,State,Hash)>{
        #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)] struct Initial{format:String,classification:String,campaign:String,source:String,genesis:String,root:String,records:Vec<(Hash,Vec<u8>)>}
        let raw=self.pins.last().ok_or("Draft pin absent")?.read_bounded(8*1024*1024)?;let p:Initial=serde_json::from_slice(&raw).map_err(err)?;let c=self.value.context.context();
        if p.format!=super::native_service::SERVICE_MARKER||p.classification!="NEW PUBLIC SOFTWARE TEST-VALUE; not physical TPM or original Launch16"||p.source!=hex::encode(c.source)||p.campaign!=hex::encode(c.campaign)||p.genesis.len()>8192||p.records.is_empty()||p.records.len()>4096||p.records.iter().try_fold(0usize,|n,(_,b)|n.checked_add(b.len())).is_none_or(|n|n>8*1024*1024){return Err("Exact bounded retained private initial draft required".into());}
        let g=FinalizedAnchor::decode(&hex::decode(p.genesis).map_err(err)?).map_err(err)?;let root=super::control_files::hash(&p.root)?;let s=State::from_records(&p.records,root).map_err(err)?;
        if g.height!=0||g.genesis!=c.genesis||g.fingerprint!=c.fingerprint||g.block!=self.value.initial_block||root!=self.value.provider.initial_root{return Err("Retained initial draft/provider context differs".into());}Ok((g,s,root))
    }
    pub(super) fn draft_bytes(&self)->Result<Vec<u8>>{self.pins.last().ok_or("Draft pin absent")?.read_bounded(8*1024*1024)}
    pub(super) fn recheck(&self)->Result<()>{for pin in &self.pins{pin.recheck()?;}Ok(())}
    pub(super) fn require_publication(&self,owner:&VerifiedProcess)->Result<(ImagePin,ImagePin,Identity)>{
        let proof=ImagePin::open(&self.value.service_root.join(PROOF),&owner.identity().user_sid)?;let fresh:FreshProof=serde_json::from_slice(&proof.read_bounded(128*1024)?).map_err(err)?;fresh.verify(&self.value,self.sha)?;
        let actual=VerifiedProcess::open(&fresh.reopened_process)?;actual.recheck()?;
        let h0=ImagePin::open(&self.value.service_root.join("continuous-h0-public.json"),&owner.identity().user_sid)?;if h0.hash()!=self.value.context.h0{return Err("Fresh provider proof has no matching published H0".into());}self.recheck()?;owner.recheck()?;Ok((proof,h0,fresh.reopened_process))
    }
}

/// Initial zero rows are observed, not supplied as a synthetic empty pending map.
pub(super) fn initial_cache_empty(snapshot:&Snapshot)->Result<()>{
    let db=rusqlite::Connection::open_with_flags(&snapshot.main.path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;db.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; BEGIN;").map_err(err)?;
    let tables=if snapshot.submission{&["entries","resources"][..]}else{&["lifecycle_v2","inputs_v2","rotations_v2"][..]};
    for table in tables{let n:i64=db.query_row(&format!("SELECT count(*) FROM {table}"),[],|r|r.get(0)).map_err(err)?;if n!=0{return Err("Initial prepared pending/reservation journal is nonzero; never clear it".into());}}
    if !snapshot.members.is_empty(){return Err("Initial prepared archive must contain no terminal submission history".into());}Ok(())
}

#[cfg(test)] mod tests{
    use super::*;
    #[test] fn genuine_live_preparing_process_cannot_claim_fresh_reopen_or_publication(){let actual=VerifiedProcess::observe_created_process(std::process::id()).unwrap();assert!(super::super::process_auth::historical_process_closed(&actual).is_err());}
    #[test] fn initial_receipt_output_is_not_overwritten_and_missing_inputs_are_not_initialized(){
        let root=std::env::temp_dir().join(format!("w15-initial-output-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());let p=root.join("public.json");create_public(&p,b"PUBLIC retained receipt").unwrap();assert!(absent(&p).is_err());assert!(create_public(&p,b"overwrite").is_err());assert_eq!(std::fs::read(&p).unwrap(),b"PUBLIC retained receipt");let missing=root.join("missing-provider.sqlite");let own=VerifiedProcess::observe_created_process(std::process::id()).unwrap();assert!(DatabasePin::open(&missing,&own.user_sid).is_err());absent(&missing).unwrap();
    }
}
