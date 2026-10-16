//! SOURCE ONLY. Passive reopen of ONE completed continuous PUBLIC TEST campaign.
//! No Service::new, fixture, key restoration, save_initial, pipe or new block path.
use super::{bootstrap::{self,Bootstrap}, control_codec::{Context,Role},
    image_pin::{DatabasePin,ImagePin}, process_auth::VerifiedProcess, player::{Action,Player}};
use crate::{wallet_controller_v2::{Controller,VaultRoot}, wallet_v2::Identity,
    store_v2::Store, verified_sync_v2::{Replica,Delivery}, recorder::Recorder};
use mutiny_consensus_v8::{Hash,anchors::FinalizedAnchor,execution::State,
    canonical_store_v2::CanonicalStore,mempool_v2::Mempool};
use std::{path::{Path,PathBuf},ffi::OsString};
use eframe::egui;
type Result<T>=std::result::Result<T,String>;
pub const REOPEN_MARKER:&str="MUTINY-W15-NONSHIPPING-CONTINUOUS-PASSIVE-REOPEN-V1";
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathPin {pub path:PathBuf,pub sha256:Hash}
#[derive(Clone,serde::Serialize,serde::Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct HeadPin {pub height:u64,pub block:Hash,pub root:Hash}
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultPin {pub role:u8,pub client_root:PathBuf,pub revision:i64,
    pub active:Identity,pub staged:Option<Identity>,pub superseded:Option<Identity>,
    pub queued:Vec<QueuedPin>,pub preimage_conditions:Vec<Hash>,pub payment_wire_commitments:Vec<Hash>,pub reserved_inputs:Vec<PointPin>}
#[derive(Clone,serde::Serialize,serde::Deserialize,PartialEq,Eq,PartialOrd,Ord)]
#[serde(deny_unknown_fields)]
pub struct PointPin {pub transaction:Hash,pub index:u32}
#[derive(Clone,serde::Serialize,serde::Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct QueuedPin {pub id:Hash,pub kind:String,pub complete:bool,pub status:String}
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WirePin {pub list:u8,pub kind:u8,pub id:Hash,pub wire:PathPin,pub own_commitment:Hash,pub height:u64}
#[derive(serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPin {pub format:String,pub bootstrap:PathPin,pub programs:[PathPin;2],
    pub context:super::bootstrap::ContextPin,pub head:HeadPin,pub vaults:[VaultPin;3],
    pub confirmed:Vec<WirePin>,pub old_processes_naturally_closed:bool}
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
fn absolute(p:&Path)->bool{p.is_absolute()&&p.to_str().is_some_and(|s|s.len()<=4096&&!s.is_empty())
    &&!p.components().any(|c|matches!(c,std::path::Component::ParentDir|std::path::Component::CurDir))}
impl RestartPin {
    fn validate(&self,role:Role)->Result<()> {
        let c=self.context.context();
        if self.format!=REOPEN_MARKER||!self.old_processes_naturally_closed
            ||[c.source,c.campaign,c.h0,c.genesis,c.fingerprint,self.head.block,self.head.root].contains(&[0;32])
            ||!(1..=384).contains(&self.head.height)||self.confirmed.is_empty()||self.confirmed.len()>64 {
            return Err("Exact completed continuous context/nonempty canonical IDs required".into());
        }
        let mut roots=std::collections::BTreeSet::new();
        for (r,v) in [1,2,3].into_iter().zip(&self.vaults){
            if v.role!=r||v.revision<1||!absolute(&v.client_root)||!roots.insert(v.client_root.clone())
                ||v.queued.len()>4096||v.preimage_conditions.len()>4096||v.payment_wire_commitments.len()>64||v.reserved_inputs.len()>4096
                ||v.queued.iter().any(|q|q.id==[0;32]||q.kind.len()>128||q.status.len()>256)
                ||[Some(&v.active),v.staged.as_ref(),v.superseded.as_ref()].into_iter().flatten().any(|id|
                    id.owner_descriptor.len()>32768||id.authority_id.len()!=64||id.address_id.len()!=64||id.generation==0) {
                return Err("Exact bounded initialized three-role custody snapshots required".into());
            }
        }
        if self.vaults.iter().enumerate().any(|(i,v)|self.vaults.iter().skip(i+1)
            .any(|other|v.client_root.starts_with(&other.client_root)||other.client_root.starts_with(&v.client_root))) {
            return Err("Role roots must remain distinct originals".into());
        }
        for p in std::iter::once(&self.bootstrap).chain(self.programs.iter()).chain(self.confirmed.iter().map(|w|&w.wire)) {
            if !absolute(&p.path)||p.sha256==[0;32]{return Err("Pinned existing public path/hash required".into());}
        }
        let mut ids=std::collections::BTreeSet::new();
        for w in &self.confirmed {if w.list>1||w.id==[0;32]||w.own_commitment==[0;32]
            ||w.height==0||w.height>self.head.height||!ids.insert(w.id){return Err("Bounded unique actual canonical wire IDs required".into());}}
        let v=&self.vaults[role as usize-1];
        if v.queued.is_empty()||v.preimage_conditions.is_empty(){return Err("This campaign restart control requires retained nonempty outbox and sealed condition; empty cannot qualify continuity".into());}
        Ok(())
    }
}
struct Args {pin:PathBuf,pin_sha:Hash,role:Role,record:PathBuf,source_git:String,manifest:PathBuf,source:Hash,gui:bool}
fn parse(values:&[OsString])->Result<Args>{
    let flags=["--continuous-passive-reopen","--pin-sha256","--role","--record-root","--source-id","--source-manifest","--source-manifest-sha256","--mode"];
    if values.len()!=16||flags.iter().enumerate().any(|(i,f)|values[2*i]!=*f){return Err("Eight exact passive continuous argument pairs required".into());}
    let t=|n:usize|values[n].to_str().ok_or("Passive argument Unicode");
    let role=bootstrap::parse_role(t(5)?.parse().map_err(|_|"Role decimal")?)?;
    let gui=match t(15)?{"gui"=>true,"verify"=>false,_=>return Err("Only passive gui/verify modes defined".into())};
    let a=Args{pin:PathBuf::from(&values[1]),pin_sha:super::control_files::hash(t(3)?)?,role,record:PathBuf::from(&values[7]),
        source_git:t(9)?.into(),manifest:PathBuf::from(&values[11]),source:super::control_files::hash(t(13)?)?,gui};
    if !absolute(&a.pin)||!absolute(&a.manifest)||!absolute(&a.record)||a.record.exists()
        ||a.source_git.len()!=40||!a.source_git.bytes().all(|b|b.is_ascii_hexdigit())||a.pin_sha==[0;32]||a.source==[0;32] {
        return Err("Existing exact pins/source and NEW separate evidence output required".into());
    }Ok(a)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct H0 {format:String,classification:String,campaign:String,source:String,genesis:String,root:String,records:Vec<(Hash,Vec<u8>)>}
fn scalar(db:&rusqlite::Connection,sql:&str)->Result<i64>{db.query_row(sql,[],|r|r.get(0)).map_err(err)}
pub(super) fn held_db(path:&Path,owner:&VerifiedProcess,app:i64,version:i64)->Result<(DatabasePin,rusqlite::Connection)> {
    let held=DatabasePin::open(path,&owner.identity().user_sid)?;
    if !(1..=1024*1024*1024).contains(&std::fs::metadata(path).map_err(err)?.len()){return Err("Existing DB size bound".into());}
    let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;
    db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN;").map_err(err)?;
    let a:i64=db.pragma_query_value(None,"application_id",|r|r.get(0)).map_err(err)?;
    let v:i64=db.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(err)?;
    if a!=app||v!=version||!(1..=32).contains(&scalar(&db,"SELECT count(*) FROM sqlite_schema")?)
        ||scalar(&db,"SELECT count(*) FROM sqlite_schema WHERE typeof(type)!='text' OR typeof(name)!='text' OR length(CAST(type AS BLOB)) NOT BETWEEN 1 AND 16 OR length(CAST(name AS BLOB)) NOT BETWEEN 1 AND 128")?!=0 {
        return Err("Initialized exact DB application/version/bounded schema required; missing or empty never created".into());
    }
    held.recheck()?;Ok((held,db))
}
pub(super) fn preflight_side(root:&VaultRoot,c:Context,network:u32,owner:&VerifiedProcess)->Result<Vec<DatabasePin>> {
    let specifications=[(root.vault(),crate::store_v2::APP_ID,crate::store_v2::VERSION),
        (root.operation_outbox(),crate::operation_outbox::APPLICATION_ID,crate::operation_outbox::SCHEMA_VERSION),
        (root.preimages(),crate::preimage_store::APPLICATION_ID,crate::preimage_store::SCHEMA_VERSION),
        (root.path().join("public-payment-pool.sqlite"),0x4d554d32,2)];
    let mut held=Vec::new();
    for (i,(path,app,version)) in specifications.iter().enumerate(){
        let (pin,db)=held_db(path,owner,*app,*version)?;
        let (tables,count_sql,bytes_sql)=match i {
            0=>(vec!["vault_records","vault_pointer"],"SELECT count(*) FROM vault_records","SELECT coalesce(sum(length(envelope)),0) FROM vault_records"),
            1=>(vec!["operation_outbox_context_v1","operation_outbox_records_v1"],"SELECT count(*) FROM operation_outbox_records_v1","SELECT coalesce(sum(length(meta)+length(raw)),0) FROM operation_outbox_records_v1"),
            2=>(vec!["preimage_store_context_v1","preimage_store_records_v1"],"SELECT count(*) FROM preimage_store_records_v1","SELECT coalesce(sum(length(sealed)),0) FROM preimage_store_records_v1"),
            _=>(vec!["context_v2","basis_v2","lifecycle_v2","inputs_v2","rotations_v2"],"SELECT count(*) FROM lifecycle_v2","SELECT coalesce(sum(length(raw)),0) FROM lifecycle_v2"),
        };
        if scalar(&db,"SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'")?!=tables.len() as i64 {return Err("Exact initialized side table count required".into());}
        for table in tables {let n:i64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?1",[table],|r|r.get(0)).map_err(err)?;if n!=1{return Err("Initialized side table missing".into());}}
        if !(0..=if i==3{65536}else{4096}).contains(&scalar(&db,count_sql)?)||!(0..=8*1024*1024).contains(&scalar(&db,bytes_sql)?) {return Err("Existing sealed/public row count/byte bounds".into());}
        if i==0 {if scalar(&db,"SELECT count(*) FROM vault_pointer WHERE id=1 AND revision>=1 AND active IN (1,2)")?!=1||scalar(&db,"SELECT count(*) FROM vault_records WHERE state=1")?!=1||!(1..=2).contains(&scalar(&db,count_sql)?){return Err("Committed existing vault pointer absent".into());}}
        if i==1 {let row:(i64,Vec<u8>,Vec<u8>)=db.query_row("SELECT network,CASE WHEN length(genesis)=32 THEN genesis END,CASE WHEN length(fingerprint)=32 THEN fingerprint END FROM operation_outbox_context_v1 WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(err)?;
            if scalar(&db,"SELECT count(*) FROM operation_outbox_context_v1")?!=1||row.0!=i64::from(network)||row.1!=c.genesis||row.2!=c.fingerprint{return Err("Existing outbox context mismatch".into());}}
        if i==2&&scalar(&db,"SELECT count(*) FROM preimage_store_context_v1 WHERE id=1")?!=1{return Err("Preimage context absent".into());}
        if i==3 {let row:(Vec<u8>,Vec<u8>)=db.query_row("SELECT CASE WHEN length(genesis)=32 THEN genesis END,CASE WHEN length(fingerprint)=32 THEN fingerprint END FROM context_v2 WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(err)?;
            if scalar(&db,"SELECT count(*) FROM context_v2")?!=1||row.0!=c.genesis||row.1!=c.fingerprint{return Err("Existing payment context mismatch".into());}}
        drop(db);held.push(pin);
    }Ok(held)
}
struct Reopen {pin:RestartPin,role:Role,root:VaultRoot,owner:super::process_auth::Identity,files:Vec<ImagePin>,dbs:Vec<DatabasePin>,
    chains:Vec<CanonicalStore>,wallet:Controller,expected:VaultPin,wire:Vec<Vec<u8>>}
impl Reopen {
    fn open(a:&Args)->Result<Self>{
        if mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED||mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED{return Err("Closed production gates mandatory".into());}
        let own=VerifiedProcess::observe_created_process(std::process::id())?;let owner=VerifiedProcess::open(&own)?;
        let mut files=Vec::new();
        let read=|path:&Path,sha:Hash,limit:u64,files:&mut Vec<ImagePin>|->Result<Vec<u8>>{
            let f=ImagePin::open(path,&owner.identity().user_sid)?;if f.hash()!=sha{return Err("Exact externally pinned existing public file differs".into());}
            let raw=f.read_bounded(limit)?;files.push(f);Ok(raw)
        };
        let pin:RestartPin=serde_json::from_slice(&read(&a.pin,a.pin_sha,1024*1024,&mut files)?).map_err(err)?;pin.validate(a.role)?;
        if pin.context.source!=a.source{return Err("Reopen binary must retain campaign's exact final source".into());}
        let manifest:serde_json::Value=serde_json::from_slice(&read(&a.manifest,a.source,16*1024*1024,&mut files)?).map_err(err)?;
        if manifest["head"]!=a.source_git||manifest["files"].as_array().is_none_or(|f|f.is_empty()||f.len()>4096){return Err("Exact original complete source manifest".into());}
        let program=&pin.programs[usize::from(a.role==Role::Treasury)];
        if own.image_path!=program.path||own.image_sha256!=program.sha256{return Err("New actual passive process must use exact original pinned executable".into());}
        for p in &pin.programs {let held=ImagePin::open(&p.path,&owner.identity().user_sid)?;if held.hash()!=p.sha256{return Err("Original program differs".into());}files.push(held);}
        // Deserializing exact saved bootstrap does NOT reauthenticate exited
        // historical process IDs or establish a new pipe/role capability.
        let boot:Bootstrap=serde_json::from_slice(&read(&pin.bootstrap.path,pin.bootstrap.sha256,16*1024,&mut files)?).map_err(err)?;
        let c=pin.context.context();
        for process in std::iter::once(&boot.service).chain(boot.roles.iter().map(|r|&r.process)){super::process_auth::historical_process_closed(process)?;}
        if boot.format!=bootstrap::BOOT_MARKER||boot.context.context()!=c||boot.source_git!=a.source_git||boot.source_manifest!=a.manifest||boot.source_manifest_sha256!=a.source
            ||boot.h0_file!=boot.service_root.join("continuous-h0-public.json")||!absolute(&boot.service_root)
            ||boot.roles.iter().enumerate().any(|(i,r)|r.role!=(i+1)as u8) {return Err("Original historical bootstrap/source/roles/context differ".into());}
        let h:H0=serde_json::from_slice(&read(&boot.h0_file,c.h0,8*1024*1024,&mut files)?).map_err(err)?;
        if h.format!=super::native_service::SERVICE_MARKER||h.classification.is_empty()||h.source!=hex::encode(c.source)||h.campaign!=hex::encode(c.campaign)
            ||h.genesis.len()>8192||h.records.is_empty()||h.records.len()>4096||h.records.iter().map(|(_,v)|v.len()).sum::<usize>()>8*1024*1024 {return Err("Original bounded PUBLIC TEST H0 records required".into());}
        let genesis=FinalizedAnchor::decode(&hex::decode(&h.genesis).map_err(err)?).map_err(err)?;
        if genesis.height!=0||genesis.genesis!=c.genesis||genesis.fingerprint!=c.fingerprint{return Err("Original H0 context differs".into());}
        let initial_root=super::control_files::hash(&h.root)?;let initial=State::from_records(&h.records,initial_root).map_err(err)?;
        if initial.dividends.treasury().map(|t|t.class())!=Some(mutiny_consensus_v8::treasury_v1::Class::TestValue){return Err("Only original TEST-VALUE chain".into());}
        if pin.vaults.iter().any(|v|a.record.starts_with(&v.client_root)||v.client_root.starts_with(&a.record)){return Err("Recording must be outside every original outer client root".into());}
        let roots=pin.vaults.iter().map(|v|VaultRoot::new(&v.client_root.join("role-vault")).map_err(err)).collect::<Result<Vec<_>>>()?;
        if roots.iter().any(|r|r.path().starts_with(&boot.service_root)||boot.service_root.starts_with(r.path())||a.record.starts_with(r.path())||r.path().starts_with(&a.record))||a.record.starts_with(&boot.service_root)||boot.service_root.starts_with(&a.record){return Err("Separate original roots and NEW recording required".into());}
        let mut dbs=Vec::new();
        // All THREE original vaults x FOUR initialized sides are checked first.
        for (i,r) in roots.iter().enumerate(){
            let marker=r.path().join("NEW-CONTINUOUS-TEST-ROLE.marker");let f=ImagePin::open(&marker,&owner.identity().user_sid)?;
            let v:serde_json::Value=serde_json::from_slice(&f.read_bounded(2048)?).map_err(err)?;
            if v["format"]!=super::role_vault::ROLE_VAULT_MARKER||v["role"]!=(i+1) as u64||v["source"]!=hex::encode(c.source)||v["campaign"]!=hex::encode(c.campaign)||v["h0"]!=hex::encode(c.h0)||v["genesis"]!=hex::encode(c.genesis)||v["fingerprint"]!=hex::encode(c.fingerprint)||v["original_launch16"]!=false||v["production_authorized"]!=false{return Err("Existing original role marker differs".into());}
            files.push(f);dbs.extend(preflight_side(r,c,genesis.network,&owner)?);
        }
        let mut paths=vec![boot.service_root.join("certifier.sqlite"),boot.service_root.join("local-node-chain.sqlite"),boot.service_root.join("remote-node-chain.sqlite")];
        paths.extend(roots.iter().map(|r|r.path().join("public-chain.sqlite")));
        for path in &paths {let (f,db)=held_db(path,&owner,0x4d554632,4)?;
            if scalar(&db,"SELECT count(*) FROM sqlite_schema")?!=20||scalar(&db,"SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('finalized_v2','integrity_v2','evidence_v2','canonical_v2','state_v2','undo_v2','confirmations_v2','state_merkle_nodes','state_merkle_tip','accepted_recovery_v2','operation_index_v2')")?!=11{return Err("All SIX initialized canonical schemas mandatory before mutable opens".into());}
            drop(db);dbs.push(f);
        }
        let mut wire=Vec::new();for p in &pin.confirmed{let raw=read(&p.wire.path,p.wire.sha256,2*1024*1024,&mut files)?;
            let (kind,id)=mutiny_consensus_v8::operation_index_v2::operation_id(p.list,&raw).map_err(err)?;
            let commitment=mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,&raw);
            if kind!=p.kind||id!=p.id||commitment!=p.own_commitment{return Err("Retained exact canonical body/list/kind/id/wire commitment mismatch".into());}wire.push(raw);
        }
        owner.recheck()?;for f in &dbs{f.recheck()?;}
        // Every opener below sees a retained initialized file. No empty schema
        // creation/migration is accepted, and no public/private keys generated.
        let mut chains=paths.iter().map(|p|CanonicalStore::open_trusted_genesis(p,&genesis,&initial,initial_root,1000,[255;32]).map_err(err)).collect::<Result<Vec<_>>>()?;
        for chain in &chains {let(head,_)=chain.load().map_err(err)?;if head.height!=pin.head.height||head.block!=pin.head.block||head.root!=pin.head.root{return Err("Six original own-Genesis replays disagree with retained completed head".into());}}
        for (i,r) in roots.iter().enumerate(){let store=Store::open(&r.vault()).map_err(err)?;let s=store.status().map_err(str::to_owned)?.ok_or("Original active vault missing")?;
            let expected=&pin.vaults[i];if s.revision!=expected.revision||s.active!=expected.active||s.staged!=expected.staged||s.superseded!=expected.superseded{return Err("Original exact active/staged/superseded vault pointer mismatch".into());}}
        let root=roots[a.role as usize-1].clone();
        let own_chain=chains.remove(3+a.role as usize-1);let replica=Replica::from_pinned_chain(own_chain)?;
        let(_,current)=replica.verified()?;let expected=pin.vaults[a.role as usize-1].clone();
        let authority=super::control_files::hash(&expected.active.authority_id)?;
        let descriptor=hex::decode(&expected.active.owner_descriptor).map_err(err)?;
        let (public,generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(&descriptor).map_err(err)?;
        if public.role!=mutiny_crypto_v2::Role::WalletOwner||generation!=expected.active.generation||current.wallets.current(authority)!=Some(descriptor.as_slice())
            ||initial.wallets.current(authority).is_none(){return Err("Existing vault authority/current canonical descriptor differs from original lineage".into());}
        let pool=Mempool::open(&root.path().join("public-payment-pool.sqlite"),c.genesis,c.fingerprint,65536).map_err(err)?;
        let declaration=super::role_vault::declaration(a.role,c,&current)?;
        let wallet=Controller::open(&root,replica,pool,declaration)?;
        Ok(Self{pin,role:a.role,root,owner:own,files,dbs,chains,wallet,expected,wire})
    }
    fn snapshot(&mut self,cancel:&std::sync::atomic::AtomicBool)->Result<serde_json::Value>{
        let owner=VerifiedProcess::open(&self.owner)?;owner.recheck()?;
        let deadline=std::time::Instant::now()+std::time::Duration::from_secs(30);
        let boundary=||->Result<()>{if cancel.load(std::sync::atomic::Ordering::SeqCst)||std::time::Instant::now()>=deadline{Err("Passive cancellation/deadline observed at complete replay boundary".into())}else{owner.recheck()}};boundary()?;for f in &self.files{f.recheck()?;}for f in &self.dbs{f.recheck()?;}
        if self.wallet.identity()!=Some(&self.expected.active){return Err("Actual unlock of existing exact current identity required".into());}
        let expected_profile=if self.role==Role::Treasury{mutiny_wallet_core_v8::WalletProfile::Treasury}else{mutiny_wallet_core_v8::WalletProfile::Ordinary};if self.wallet.profile()!=expected_profile{return Err("Existing Controller role/profile mismatch".into());}
        let status=self.wallet.vault_status()?.ok_or("Existing vault missing")?;
        if status.revision!=self.expected.revision||status.active!=self.expected.active||status.staged!=self.expected.staged||status.superseded!=self.expected.superseded{return Err("Existing vault pointer changed".into());}
        let ids=self.pin.confirmed.iter().map(|p|p.id).collect::<Vec<_>>();let mut confirmations=Vec::new();
        for (index,chain) in self.chains.iter().enumerate(){boundary()?;let(head,_)=chain.load().map_err(err)?;
            if head.height!=self.pin.head.height||head.block!=self.pin.head.block||head.root!=self.pin.head.root{return Err("Original head changed during passive reopen".into());}
            let found=chain.verified_operation_records_many(&ids).map_err(err)?;
            for (p,raw) in self.pin.confirmed.iter().zip(&self.wire){let rows=found.get(&p.id).ok_or("Original ID missing from replay")?;
                if rows.is_empty()||rows.iter().any(|r|r.op_id!=p.id||r.kind!=p.kind||r.list!=p.list||r.height!=p.height||r.wire!=p.own_commitment){return Err("Own canonical record does not match exact retained wire".into());}
                let(_,id)=mutiny_consensus_v8::operation_index_v2::operation_id(p.list,raw).map_err(err)?;if id!=p.id{return Err("Retained wire changed".into());}
                confirmations.push(serde_json::json!({"store_index_excluding_own":index,"id":hex::encode(p.id),"height":p.height,"own_wire_commitment":hex::encode(p.own_commitment)}));
            }
        }
        let expected_head=self.pin.head.clone();let authority=super::control_files::hash(&self.expected.active.authority_id)?;let descriptor=hex::decode(&self.expected.active.owner_descriptor).map_err(err)?;
        let mut expected_reserved=self.expected.reserved_inputs.clone();expected_reserved.sort();
        let own=self.wallet.with_view(|v|->Result<serde_json::Value>{
            if v.anchor().height!=expected_head.height||v.anchor().block!=expected_head.block||v.state_root()!=expected_head.root||v.state().wallets.current(authority)!=Some(descriptor.as_slice()){return Err("Actual own Controller head/authority differs".into());}
            let mut actual_reserved=v.reserved().iter().map(|p|PointPin{transaction:p.transaction,index:p.index}).collect::<Vec<_>>();actual_reserved.sort();if actual_reserved!=expected_reserved{return Err("Restored exact reserved inputs differ from completed snapshot".into());}
            Ok(serde_json::json!({"height":v.anchor().height,"block":hex::encode(v.anchor().block),"root":hex::encode(v.state_root()),"reserved_inputs":actual_reserved}))
        })??;
        boundary()?;let mut own_confirmed=Vec::new();for p in &self.pin.confirmed{boundary()?;match self.wallet.delivery(p.id)?{Delivery::ConfirmedAt(h) if h==p.height=>own_confirmed.push(serde_json::json!({"id":hex::encode(p.id),"actual_controller_confirmed_at":h})),_=>return Err("Actual Controller has no matching own replay confirmation".into())}}
        let mut queued=self.wallet.queued_operations()?.into_iter().map(|(q,state)|QueuedPin{id:q.id,kind:q.kind.title().into(),complete:q.complete,status:state}).collect::<Vec<_>>();queued.sort_by_key(|q|q.id);
        let mut expected=self.expected.queued.clone();expected.sort_by_key(|q|q.id);if queued!=expected{return Err("Reopened protected nonempty outbox differs from completed snapshot".into());}
        let mut conditions=self.wallet.preimage_conditions()?;conditions.sort();let mut saved=self.expected.preimage_conditions.clone();saved.sort();if conditions!=saved||conditions.is_empty(){return Err("Existing sealed conditions differ or are empty".into());}
        let mut payments=self.wallet.pending_for_transport()?.iter().map(|raw|{mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,raw)}).collect::<Vec<_>>();payments.sort();let mut expected_payments=self.expected.payment_wire_commitments.clone();expected_payments.sort();if payments!=expected_payments{return Err("Existing payment queue wire commitments differ".into());}
        boundary()?;for f in &self.dbs{f.recheck()?;}
        Ok(serde_json::json!({"format":REOPEN_MARKER,"role":self.role as u8,"six_original_replays":true,"other_five_store_confirmations":confirmations,"actual_own_controller":own,"own_confirmation":own_confirmed,"vault_revision":status.revision,"active":status.active,"staged":status.staged,"superseded":status.superseded,"nonempty_operation_outbox":queued.iter().map(|q|serde_json::json!({"id":hex::encode(q.id),"kind":q.kind,"complete":q.complete,"status":q.status})).collect::<Vec<_>>(),"sealed_condition_hashes":conditions.iter().map(hex::encode).collect::<Vec<_>>(),"payment_wire_commitments":payments.iter().map(hex::encode).collect::<Vec<_>>(),"new_genesis":false,"new_key":false,"new_blocks":false,"old_process_reauthentication":false,"Launch16_reclassified":false,"scope":"Passive same-campaign initialized custody/outbox/preimage reopen with actual own replay; no live replacement-PID or certifier continuity"}))
    }
}
type Shared=std::sync::Arc<std::sync::Mutex<Reopen>>;
type Joins=std::sync::Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>;
struct App {backend:Shared,joins:Joins,cancel:std::sync::Arc<std::sync::atomic::AtomicBool>,
    pending:Option<std::sync::mpsc::Receiver<Result<serde_json::Value>>>,role:Role,head:HeadPin,generation:u64,revision:i64,
    recorder:Recorder,player:Player,targets:Vec<(String,egui::Rect)>,focused:bool,time:Option<f64>,focus_requested:bool,
    start:bool,started:bool,unlocks:u8,locks:u8,verified:u8,attempts:u8,observation:serde_json::Value,error:Option<String>,visual:String}
impl App {
    fn reverify(&mut self)->Result<()> {
        if self.pending.is_some()||self.attempts>=8{return Err("Passive replay in flight/quota; never queue another action".into());}
        // This is called only by the actual Reverify widget callback. The
        // bounded worker owns no request/review/authorize or block capability.
        let (tx,rx)=std::sync::mpsc::sync_channel(1);let backend=self.backend.clone();let cancel=self.cancel.clone();
        let mut registry=self.joins.try_lock().map_err(|_|"Passive join registry busy/poisoned; no thread created")?;
        let thread=std::thread::Builder::new().name("w15-passive-own-replay".into()).spawn(move||{
            let result=(||->Result<serde_json::Value>{let mut b=backend.lock().map_err(|_|"Passive backend poisoned")?;
                let result=b.snapshot(&cancel);if result.is_err(){b.wallet.lock();}result})();
            let _=tx.send(result);
        }).map_err(err)?;
        registry.push(thread);drop(registry);
        self.pending=Some(rx);self.attempts+=1;Ok(())
    }
    fn poll(&mut self){
        let result=self.pending.as_ref().map(|r|r.try_recv());
        match result {
            Some(Ok(Ok(value)))=>{self.pending=None;self.observation=value;self.verified=self.verified.saturating_add(1);},
            Some(Ok(Err(e)))=>{self.pending=None;self.error=Some(e);},
            Some(Err(std::sync::mpsc::TryRecvError::Disconnected))=>{self.pending=None;self.error=Some("Passive replay worker disconnected; no result".into());},
            _=>{},
        }
    }
}
impl eframe::App for App {
    fn raw_input_hook(&mut self,ctx:&egui::Context,raw:&mut egui::RawInput){
        self.focused=raw.focused;self.time=raw.time;
        // Polling is actual completion, never a time-based success. Pending raw
        // actions remain intact until the real replay result is observed.
        self.poll();if raw.focused&&self.pending.is_none()&&self.error.is_none(){self.player.inject(raw,&self.targets,ctx.content_rect(),ctx.content_rect());}
    }
    fn ui(&mut self,ui:&mut egui::Ui,_:&mut eframe::Frame){
        let ctx=ui.ctx().clone();self.targets.clear();let events=ctx.input(|i|i.events.clone());
        if events.iter().any(|e|matches!(e,egui::Event::Text(_)|egui::Event::Key{..}|egui::Event::PointerButton{..})){
            if let Ok(mut b)=self.backend.try_lock(){b.wallet.user_activity();}
        }
        if !self.focused&&!self.focus_requested{ctx.send_viewport_cmd(egui::ViewportCommand::Focus);self.focus_requested=true;}
        let mut image=None;for e in &events{if let egui::Event::Screenshot{image:f,..}=e{match self.recorder.screenshot(f){Ok(h)=>image=Some(h),Err(e)=>self.error=Some(e)}}}
        egui::Panel::top("continuous-passive-public-banner").show(ui,|ui|{
            ui.visuals_mut().override_text_color=Some(egui::Color32::YELLOW);ui.visuals_mut().panel_fill=egui::Color32::from_rgb(145,0,120);
            ui.heading("PUBLIC TEST-VALUE. NON-SHIPPING. NO REAL FUNDS.");ui.label(REOPEN_MARKER);
            ui.label("Same initialized continuous campaign: passive custody and own-history reopen; no new service or keys");
        });
        let available=self.pending.is_none()&&self.error.is_none();
        egui::CentralPanel::default().show(ui,|ui|{ui.horizontal(|ui|{
            let b=ui.add_enabled(available,egui::Button::new("Lock existing public identity"));self.targets.push(("continuous-passive:Lock".into(),b.rect));
            if b.clicked(){match self.backend.try_lock(){Ok(mut backend)=>{backend.wallet.lock();if backend.wallet.identity().is_none(){self.locks=self.locks.saturating_add(1);}else{self.error=Some("Actual lock did not erase session".into());}},Err(_)=>self.error=Some("Actual lock backend busy/poisoned".into())}}
            let b=ui.add_enabled(available,egui::Button::new("Unlock existing public vault"));self.targets.push(("continuous-passive:Unlock".into(),b.rect));
            if b.clicked(){match self.backend.try_lock(){Ok(mut backend)=>{
                let expected=backend.expected.active.clone();match backend.wallet.unlock(super::chain::PASSWORD){Ok(()) if backend.wallet.identity()==Some(&expected)=>self.unlocks=self.unlocks.saturating_add(1),Ok(())=>{backend.wallet.lock();self.error=Some("Actual reopened identity mismatch".into());},Err(e)=>self.error=Some(e)}
            },Err(_)=>self.error=Some("Actual unlock backend busy/poisoned".into())}}
            let b=ui.add_enabled(available,egui::Button::new("Reverify original stores and retained queues"));self.targets.push(("continuous-passive:Reverify".into(),b.rect));
            if b.clicked(){if let Err(e)=self.reverify(){self.error=Some(e);}}
        });
            let b=ui.add_enabled(available&&!self.started,egui::Button::new("Start passive controls through actual widgets"));self.targets.push(("continuous-passive:Start".into(),b.rect));
            if b.clicked(){match self.player.queue([Action::Click("continuous-passive:Unlock".into()),Action::Wait(2),Action::Click("continuous-passive:Reverify".into()),Action::Wait(2),Action::Click("continuous-passive:Lock".into()),Action::Wait(2),Action::Click("continuous-passive:Unlock".into()),Action::Wait(2),Action::Click("continuous-passive:Reverify".into())]){Ok(())=>self.started=true,Err(e)=>self.error=Some(e)}}
            if let Some(e)=&self.error{ui.colored_label(egui::Color32::RED,e);}
            ui.label(format!("Role {:?}; retained H{}; current generation{}; vault revision{}",self.role,self.head.height,self.generation,self.revision));
            ui.label(format!("Actual unlocks{} / locks{} / reverifications{}; replay {}",self.unlocks,self.locks,self.verified,if self.pending.is_some(){"in flight"}else{"idle"}));
            ui.label("No live peer replacement, recovered ephemeral certifier, new block or Launch16 completion claim.");
        });
        if self.start&&!self.targets.is_empty()&&available{match self.player.queue([Action::Click("continuous-passive:Start".into())]){Ok(())=>self.start=false,Err(e)=>self.error=Some(e)}}
        let state=serde_json::json!({"mode":REOPEN_MARKER,"actual_native_focus":self.focused,"native_input_time":self.time,"normal_focus_request_sent":self.focus_requested,
            "original_context":self.observation,"unlocks":self.unlocks,"locks":self.locks,"reverifies":self.verified,"replay_pending":self.pending.is_some(),"replay_attempts":self.attempts,
            "native_player":{"last_event":self.player.last,"failure":self.player.failure,"done":self.player.done()},
            "passive_widget_controls_complete":self.started&&self.player.done()&&self.player.failure.is_none()&&self.error.is_none()&&self.pending.is_none()&&self.unlocks==2&&self.locks==1&&self.verified==2,
            "refusal":self.error,"visible_targets":self.targets.iter().map(|(n,r)|serde_json::json!({"name":n,"rect":[r.min.x,r.min.y,r.max.x,r.max.y]})).collect::<Vec<_>>()});
        let mut visual=state.clone();visual.as_object_mut().unwrap().remove("native_input_time");let text=visual.to_string();if text!=self.visual||self.recorder.frame==0{ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));self.visual=text;}
        if let Err(e)=self.recorder.append(true,&format!("{events:?}"),state,image){self.error=Some(e);self.cancel.store(true,std::sync::atomic::Ordering::SeqCst);}
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
pub fn run_if_requested(treasury_root:bool)->Option<eframe::Result>{
    let values=std::env::args_os().skip(1).collect::<Vec<_>>();if values.first().is_none_or(|v|v!="--continuous-passive-reopen"){return None;}
    Some((||->Result<()>{
        let a=parse(&values)?;if (a.role==Role::Treasury)!=treasury_root{return Err("Exact separate ordinary/Treasury root role gate".into());}
        let mut backend=Reopen::open(&a)?;
        if !a.gui {
            let cancel=std::sync::atomic::AtomicBool::new(false);backend.wallet.unlock(super::chain::PASSWORD)?;let v=backend.snapshot(&cancel)?;backend.wallet.lock();
            let mut f=std::fs::OpenOptions::new().create_new(true).write(true).open(&a.record).map_err(err)?;use std::io::Write;
            f.write_all(&serde_json::to_vec_pretty(&v).map_err(err)?).map_err(err)?;f.sync_all().map_err(err)?;return Ok(());
        }
        let title=format!("MUTINY PUBLIC TEST-VALUE CONTINUOUS PASSIVE {:?} - NON-SHIPPING - pid {}",a.role,std::process::id());let returned=title.clone();
        let role=backend.role;let head=backend.pin.head.clone();let generation=backend.expected.active.generation;let revision=backend.expected.revision;
        let backend=std::sync::Arc::new(std::sync::Mutex::new(backend));let held=backend.clone();let joins:Joins=Default::default();let held_joins=joins.clone();
        let cancel=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));let held_cancel=cancel.clone();
        let result=eframe::run_native(&title,eframe::NativeOptions{viewport:egui::ViewportBuilder::default().with_inner_size([1150.,850.]),..Default::default()},Box::new(move|cc|{
            use raw_window_handle::{HasWindowHandle,RawWindowHandle};use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowTextW,SetWindowDisplayAffinity,WDA_EXCLUDEFROMCAPTURE};
            let RawWindowHandle::Win32(w)=cc.window_handle()?.as_raw()else{return Err("Actual native Windows viewport required".into());};
            if unsafe{SetWindowDisplayAffinity(w.hwnd.get()as*mut _,WDA_EXCLUDEFROMCAPTURE)}==0{return Err("Actual capture protection failed".into());}
            let mut text=[0u16;256];let n=unsafe{GetWindowTextW(w.hwnd.get()as*mut _,text.as_mut_ptr(),256)};
            if n<=0||String::from_utf16(&text[..n as usize])?!=returned{return Err("Actual passive HWND/title association mismatch".into());}
            let recorder=Recorder::new(&a.record,a.source_git,&a.manifest,w.hwnd.get()as usize,returned)?;
            Ok(Box::new(App{backend,joins,cancel,pending:None,role,head,generation,revision,recorder,player:Player::default(),targets:Vec::new(),focused:false,time:None,focus_requested:false,start:true,started:false,unlocks:0,locks:0,verified:0,attempts:0,observation:serde_json::Value::Null,error:None,visual:String::new()}))
        }));
        // After the real viewport has exited, cancel only at complete replay
        // boundaries and JOIN every created thread; no signals or detached work.
        held_cancel.store(true,std::sync::atomic::Ordering::SeqCst);
        let mut registry_poisoned=false;
        let mut registry=held_joins.lock().unwrap_or_else(|p|{registry_poisoned=true;p.into_inner()});
        let handles=std::mem::take(&mut*registry);drop(registry);
        let mut panicked=false;for handle in handles{if handle.join().is_err(){panicked=true;}}
        held.lock().map_err(|_|"Passive backend poisoned")?.wallet.lock();
        result.map_err(err)?;if panicked||registry_poisoned{return Err("Passive worker/join registry fault; preserve partial evidence after actual joins".into());}Ok(())
    })().map_err(|e|eframe::Error::AppCreation(e.into())))
}

#[cfg(test)]
mod restart_pin_tests {
    use super::*;
    /// Non-cryptographic size/context model only. Native descriptor, sealed
    /// integrity and canonical execution are verified later by real open().
    fn pin_model()->RestartPin {
        let id=Identity{version:2,network:mutiny_crypto_v2::NETWORK,suite:mutiny_crypto_v2::WALLET_CRYPTO_SUITE_ID,generation:1,
            authority_id:hex::encode([1u8;32]),address_id:hex::encode([2u8;32]),owner_ed448:String::new(),owner_fndsa1024:String::new(),owner_descriptor:"00".into()};
        let vault=|role:u8|VaultPin{role,client_root:PathBuf::from(format!(r"C:\PUBLIC-MODEL\role{role}")),revision:1,active:id.clone(),staged:None,superseded:None,
            queued:vec![QueuedPin{id:[3;32],kind:"public bound model".into(),complete:false,status:"Pending".into()}],preimage_conditions:vec![[4;32]],payment_wire_commitments:Vec::new(),reserved_inputs:Vec::new()};
        RestartPin{format:REOPEN_MARKER.into(),bootstrap:PathPin{path:PathBuf::from(r"C:\PUBLIC-MODEL\bootstrap.json"),sha256:[5;32]},
            programs:[PathPin{path:PathBuf::from(r"C:\PUBLIC-MODEL\wallet.exe"),sha256:[6;32]},PathPin{path:PathBuf::from(r"C:\PUBLIC-MODEL\treasury.exe"),sha256:[7;32]}],
            context:bootstrap::ContextPin{campaign:[8;32],source:[9;32],h0:[10;32],genesis:[11;32],fingerprint:[12;32]},head:HeadPin{height:2,block:[13;32],root:[14;32]},
            vaults:[vault(1),vault(2),vault(3)],confirmed:vec![WirePin{list:0,kind:1,id:[15;32],wire:PathPin{path:PathBuf::from(r"C:\PUBLIC-MODEL\wire.bin"),sha256:[16;32]},own_commitment:[17;32],height:1}],old_processes_naturally_closed:true}
    }
    #[test]
    fn passive_pin_bounds_require_existing_roles_nonempty_queues_conditions_and_canonical_ids(){
        for role in [Role::WalletA,Role::WalletC,Role::Treasury]{pin_model().validate(role).unwrap();}
        for fault in 0..18 {let mut p=pin_model();match fault{
            0=>p.format="wrong".into(),1=>p.old_processes_naturally_closed=false,2=>p.context.h0=[0;32],3=>p.head.height=0,
            4=>p.head.height=385,5=>p.confirmed.clear(),6=>p.confirmed[0].list=2,7=>p.confirmed[0].id=[0;32],
            8=>p.confirmed[0].height=3,9=>p.confirmed[0].own_commitment=[0;32],10=>p.confirmed.push(p.confirmed[0].clone()),
            11=>p.vaults[0].queued.clear(),12=>p.vaults[0].preimage_conditions.clear(),13=>p.vaults[1].client_root=p.vaults[0].client_root.clone(),
            14=>p.vaults[0].revision=0,15=>p.programs[0].path=PathBuf::from("relative.exe"),16=>p.vaults[0].active.generation=0,
            _=>p.vaults[0].queued[0].status="x".repeat(257),
        }assert!(p.validate(Role::WalletA).is_err(),"fault{fault} unexpectedly accepted");}
    }
    #[test]
    fn native_initialized_preflight_refuses_missing_empty_wrong_schema_and_oversize_metadata_unchanged(){
        let id=VerifiedProcess::observe_created_process(std::process::id()).unwrap();let owner=VerifiedProcess::open(&id).unwrap();
        let nonce=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root=std::env::temp_dir().join(format!("w15-reopen-preflight-{}-{nonce}",std::process::id()));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
        let missing=root.join("missing.sqlite");assert!(held_db(&missing,&owner,7,3).is_err());assert!(!missing.exists());
        for case in 0..4 {let path=root.join(format!("case{case}.sqlite"));
            if case==0{std::fs::File::create(&path).unwrap();}else{let db=rusqlite::Connection::open(&path).unwrap();
                if case==1{db.execute_batch("CREATE TABLE existing(value INTEGER);").unwrap();}
                if case==2{db.execute_batch("PRAGMA application_id=7; PRAGMA user_version=3;CREATE TABLE retained(value INTEGER);").unwrap();}
                if case==3{db.execute_batch(&format!("PRAGMA application_id=7; PRAGMA user_version=3;CREATE TABLE \"{}\"(value INTEGER);","x".repeat(200))).unwrap();}
                drop(db);
            }
            let before=std::fs::read(&path).unwrap();
            if case==2{let(pin,db)=held_db(&path,&owner,7,3).unwrap();drop(db);pin.recheck().unwrap();}
            else{assert!(held_db(&path,&owner,7,3).is_err());}
            assert_eq!(std::fs::read(&path).unwrap(),before,"read-only preflight changed case{case}");
        }
        // Retain all NEW public test-only fixtures. No original DB/ACL changed,
        // and no canonical/custody/mounted positive inferred from metadata.
    }
}
