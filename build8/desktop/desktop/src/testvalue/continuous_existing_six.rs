//! EXTERNAL SOURCE ONLY UNCOMPILED. Existing six-canonical-store native preflight.
//! No fixture(), Service::new, key generation, custody initialization or schema repair.
//! New future synthetic provider integration must retain this bundle's leases.
use super::image_pin::DatabasePin;
use mutiny_consensus_v8::{Hash,anchors::FinalizedAnchor,canonical_store_v2::CanonicalStore,execution::State};
use sha2::{Digest,Sha256};
use std::{path::PathBuf,time::{Instant,Duration},os::windows::fs::OpenOptionsExt};
type Result<T>=std::result::Result<T,String>;
pub(super) const MARKER:&str="MUTINY-W15-NONSHIPPING-LIVE-EXISTING-SIX-REPLAY-V1";
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
#[derive(Clone)] // PUBLIC external bootstrap pins; no custody material.
pub(super) struct SixPins {
 pub paths:[PathBuf;6], // certifier/local/remote + three original wallet replicas
 pub native_ids:[Hash;6],pub height:u64,pub block:Hash,pub root:Hash,
 pub confirmed:Vec<(u8,Hash,Hash,u64)>, // list/ID/own WIRE_DOMAIN commitment/height
 pub retained_queue_ids:Vec<Hash>, // pending identifiers only; not permission to sign
}
pub(super) struct ExistingSix {
 pub chains:Vec<CanonicalStore>,pub original_identity_commitment:Hash,
 _native:Vec<DatabasePin>,pub pins:SixPins,
}
impl ExistingSix {
 pub(super) fn preflight_then_replay(pins:SixPins,user:&[u8],genesis:&FinalizedAnchor,initial:&State,initial_root:Hash)->Result<Self>{
  if genesis.height!=0||initial.root().map_err(err)?!=initial_root||pins.height==0||pins.height>384||pins.block==[0;32]||pins.root==[0;32]||pins.native_ids.contains(&[0;32])||pins.confirmed.is_empty()||pins.confirmed.len()>64||pins.retained_queue_ids.is_empty()||pins.retained_queue_ids.len()>4096{return Err("Exact original nonempty initialized context/replay/queue pins required".into());}
  State::from_records(&initial.records().map_err(err)?,initial_root).map_err(err)?;
  if initial.dividends.treasury().map(|t|t.class())!=Some(mutiny_consensus_v8::treasury_v1::Class::TestValue){return Err("Only explicit original software TEST-VALUE initial context".into());}
  let unique:std::collections::BTreeSet<_>=pins.paths.iter().collect();
  if unique.len()!=6||pins.paths.iter().any(|p|!p.is_absolute()){return Err("Six distinct original native database paths required".into());}
  let deadline=Instant::now()+Duration::from_secs(30);let mut leases=Vec::new();
  // Inspect ALL SIX existing, initialized, nofollow/native-ID-pinned databases
  // before invoking any writable CanonicalStore constructor.
  for (path,expected) in pins.paths.iter().zip(pins.native_ids){
   if Instant::now()>=deadline{return Err("Existing replay preflight deadline; preserve all originals".into());}
   let held=DatabasePin::open(path,user)?;
   if held.native_id_hash()!=expected{return Err("Original canonical native identity mismatch".into());}
   let file=std::fs::OpenOptions::new().read(true).custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT).open(path).map_err(err)?;held.check_opened(&file)?;
   if !(1..=1024*1024*1024).contains(&file.metadata().map_err(err)?.len()){return Err("Original canonical DB bounded nonempty leaf required".into());}
   let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;
   db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN;").map_err(err)?;
   let app:i64=db.pragma_query_value(None,"application_id",|r|r.get(0)).map_err(err)?;
   let version:i64=db.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(err)?;
   let count:i64=db.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get(0)).map_err(err)?;
   let bad:i64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE typeof(type)!='text' OR typeof(name)!='text' OR length(CAST(type AS BLOB)) NOT BETWEEN 1 AND 16 OR length(CAST(name AS BLOB)) NOT BETWEEN 1 AND 128",[],|r|r.get(0)).map_err(err)?;
   let tables:i64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('finalized_v2','integrity_v2','evidence_v2','canonical_v2','state_v2','undo_v2','confirmations_v2','state_merkle_nodes','state_merkle_tip','accepted_recovery_v2','operation_index_v2')",[],|r|r.get(0)).map_err(err)?;
   if app!=0x4d554632||version!=4||count!=20||bad!=0||tables!=11{return Err("Original initialized canonical schema required before writable open; never create/migrate".into());}
   drop(db);held.recheck()?;leases.push(held);
  }
  let mut identity=Sha256::new();identity.update(MARKER.as_bytes());
  for pin in pins.native_ids{identity.update(pin);}
  let mut chains=Vec::new();
  for (path,lease) in pins.paths.iter().zip(&leases){
   if Instant::now()>=deadline{return Err("Own Genesis replay deadline; no success".into());}lease.recheck()?;
   let chain=CanonicalStore::open_trusted_genesis(path,genesis,initial,initial_root,1000,[255;32]).map_err(err)?;
   let (head,state)=chain.load().map_err(err)?;
   if head.height!=pins.height||head.block!=pins.block||head.root!=pins.root||state.root().map_err(err)?!=pins.root{return Err("Six original own-Genesis replay heads differ".into());}
   let ids=pins.confirmed.iter().map(|p|p.1).collect::<Vec<_>>();let found=chain.verified_operation_records_many(&ids).map_err(err)?;
   for (list,id,wire,height) in &pins.confirmed{
    if *list>1||*height==0||*height>pins.height||!found.get(id).is_some_and(|rows|rows.iter().any(|r|r.list==*list&&r.wire==*wire&&r.height==*height)){return Err("Exact own canonical wire/list/height confirmation missing".into());}
   }lease.recheck()?;chains.push(chain);
  }
  Ok(Self{chains,original_identity_commitment:identity.finalize().into(),_native:leases,pins})
 }
 pub(super) fn native_recheck(&self)->Result<()>{for pin in &self._native{pin.recheck()?;}Ok(())}
 pub(super) fn recheck(&self)->Result<()>{for pin in &self._native{pin.recheck()?;}for chain in &self.chains{let(h,s)=chain.load().map_err(err)?;if h.height!=self.pins.height||h.block!=self.pins.block||h.root!=self.pins.root||s.root().map_err(err)?!=h.root{return Err("Original bundle canonical head changed before service handoff".into());}}Ok(())}
}
/// Private prepublication H0 path. It is NOT the post-mount replay/queue gate.
/// Every existing leaf is inspected before ANY writable canonical constructor.
pub(super) struct InitialSix{pub chains:Vec<CanonicalStore>,pub original_identity_commitment:Hash,_native:Vec<DatabasePin>,paths:[PathBuf;6],ids:[Hash;6],block:Hash,root:Hash}
impl InitialSix{
 pub(super) fn inspect(paths:[PathBuf;6],ids:[Hash;6],block:Hash,root:Hash,user:&[u8],genesis:&FinalizedAnchor,initial:&State)->Result<Self>{
  if genesis.height!=0||genesis.block!=block||initial.root().map_err(err)?!=root||root==[0;32]||block==[0;32]||ids.contains(&[0;32])||paths.iter().any(|p|!p.is_absolute())||paths.iter().collect::<std::collections::BTreeSet<_>>().len()!=6||initial.dividends.treasury().map(|t|t.class())!=Some(mutiny_consensus_v8::treasury_v1::Class::TestValue){return Err("Exact initialized prepublication TEST H0 originals required".into());}
  State::from_records(&initial.records().map_err(err)?,root).map_err(err)?;
  let mut leases=Vec::new();let end=Instant::now()+Duration::from_secs(30);
  for(path,id)in paths.iter().zip(ids){
   if Instant::now()>=end{return Err("Initial native preflight deadline; no H0 publication".into());}
   let pin=DatabasePin::open(path,user)?;if pin.native_id_hash()!=id{return Err("Initial canonical native identity differs; no replacement".into());}
   let file=std::fs::OpenOptions::new().read(true).custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT).open(path).map_err(err)?;pin.check_opened(&file)?;if !(1..=1024*1024*1024).contains(&file.metadata().map_err(err)?.len()){return Err("Initial existing canonical nonempty size required".into());}
   let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN;").map_err(err)?;
   let app:i64=db.pragma_query_value(None,"application_id",|r|r.get(0)).map_err(err)?;let version:i64=db.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(err)?;
   let count:i64=db.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get(0)).map_err(err)?;let bad:i64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE typeof(type)!='text' OR typeof(name)!='text' OR length(CAST(type AS BLOB)) NOT BETWEEN 1 AND 16 OR length(CAST(name AS BLOB)) NOT BETWEEN 1 AND 128",[],|r|r.get(0)).map_err(err)?;
   let tables:i64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('finalized_v2','integrity_v2','evidence_v2','canonical_v2','state_v2','undo_v2','confirmations_v2','state_merkle_nodes','state_merkle_tip','accepted_recovery_v2','operation_index_v2')",[],|r|r.get(0)).map_err(err)?;
   if app!=0x4d554632||version!=4||count!=20||bad!=0||tables!=11{return Err("Initial initialized exact canonical schema required before mutable open".into());}
   let canonical:i64=db.query_row("SELECT count(*) FROM canonical_v2",[],|r|r.get(0)).map_err(err)?;let finalized:i64=db.query_row("SELECT count(*) FROM finalized_v2",[],|r|r.get(0)).map_err(err)?;
   let exact:i64=db.query_row("SELECT count(*) FROM canonical_v2 WHERE typeof(height)='blob' AND length(height)=8 AND height=?1 AND typeof(block)='blob' AND length(block)=32 AND block=?2 AND typeof(root)='blob' AND length(root)=32 AND root=?3",rusqlite::params![0u64.to_be_bytes().as_slice(),block.as_slice(),root.as_slice()],|r|r.get(0)).map_err(err)?;
   let anchor:Vec<u8>=db.query_row("SELECT CASE WHEN typeof(anchor)='blob' AND length(anchor) BETWEEN 1 AND 128 THEN anchor ELSE NULL END FROM finalized_v2 WHERE height=?1",[0u64.to_be_bytes().as_slice()],|r|r.get(0)).map_err(err)?;
   let operations:i64=db.query_row("SELECT count(*) FROM operation_index_v2",[],|r|r.get(0)).map_err(err)?;
   if canonical!=1||finalized!=1||exact!=1||anchor!=genesis.encode()||operations!=0{return Err("Prepared six stores must remain exact H0 with zero operation confirmations; never reset".into());}
   drop(db);pin.recheck()?;leases.push(pin);
  }
  let mut h=Sha256::new();h.update(MARKER.as_bytes());for id in ids{h.update(id);}Ok(Self{chains:Vec::new(),original_identity_commitment:h.finalize().into(),_native:leases,paths,ids,block,root})
 }
 /// Invoke only AFTER all four caches, all role sides and provider were also
 /// existing-only preflighted. No missing database can reach this constructor.
 pub(super) fn open_replay(&mut self,genesis:&FinalizedAnchor,initial:&State)->Result<()>{
  if !self.chains.is_empty(){return Err("Initial six mutable handoff is one-shot".into());}
  for(path,pin)in self.paths.iter().zip(&self._native){pin.recheck()?;let chain=CanonicalStore::open_trusted_genesis(path,genesis,initial,self.root,1000,[255;32]).map_err(err)?;let(h,s)=chain.load().map_err(err)?;if h.height!=0||h.block!=self.block||h.root!=self.root||s.root().map_err(err)?!=self.root{return Err("Existing own initial replay differs; no H0 publication".into());}pin.recheck()?;self.chains.push(chain);}Ok(())
 }
 pub(super) fn native_recheck(&self)->Result<()>{for(pin,id)in self._native.iter().zip(self.ids){pin.recheck()?;if pin.native_id_hash()!=id{return Err("Original initial canonical identity changed".into());}}Ok(())}
 pub(super) fn recheck(&self)->Result<()>{for(pin,id)in self._native.iter().zip(self.ids){pin.recheck()?;if pin.native_id_hash()!=id{return Err("Initial canonical identity changed".into());}}for c in &self.chains{let(h,s)=c.load().map_err(err)?;if h.height!=0||h.block!=self.block||h.root!=self.root||s.root().map_err(err)?!=self.root{return Err("Initial canonical state advanced before publication".into());}}Ok(())}
}
