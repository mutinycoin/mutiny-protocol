//! SOURCE ONLY. Existing initialized public payment/submission sides preflight.
//! Hold original native leaves; never accept missing/empty input for runtime constructors.
use super::image_pin::DatabasePin;
use mutiny_consensus_v8::Hash;
use std::{path::PathBuf,collections::BTreeMap,os::windows::fs::OpenOptionsExt};
type Result<T>=std::result::Result<T,String>;
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
#[derive(Clone)]
pub(super) struct CachePin {pub path:PathBuf,pub native_id:Hash,pub submission:bool,pub pending:BTreeMap<Hash,Hash>}
pub(super) struct ExistingCaches {held:Vec<DatabasePin>}
impl ExistingCaches {
 pub(super) fn preflight(pins:&[CachePin;4],user:&[u8],genesis:Hash,fingerprint:Hash)->Result<Self>{
  let unique:std::collections::BTreeSet<_>=pins.iter().map(|p|&p.path).collect();
  if unique.len()!=4||pins.iter().filter(|p|p.submission).count()!=2{return Err("Exact original local/remote payment plus submission sides required".into());}
  let mut held=Vec::new();
  for pin in pins {
   if !pin.path.is_absolute()||pin.native_id==[0;32]||pin.pending.len()>64{return Err("Bounded exact existing cache native/context pins required".into());}
   let leaf=DatabasePin::open(&pin.path,user)?;
   if leaf.native_id_hash()!=pin.native_id{return Err("Original cache native identity differs".into());}
   let file=std::fs::OpenOptions::new().read(true).custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT).open(&pin.path).map_err(err)?;leaf.check_opened(&file)?;
   if !(1..=128*1024*1024).contains(&file.metadata().map_err(err)?.len()){return Err("Nonempty initialized cache bound; never repair".into());}
   let db=rusqlite::Connection::open_with_flags(&pin.path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;
   db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN;").map_err(err)?;
   let app:i64=db.pragma_query_value(None,"application_id",|r|r.get(0)).map_err(err)?;
   let version:i64=db.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(err)?;
   let count:i64=db.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get(0)).map_err(err)?;
   let bad:i64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE typeof(type)!='text' OR typeof(name)!='text' OR length(CAST(type AS BLOB)) NOT BETWEEN 1 AND 16 OR length(CAST(name AS BLOB)) NOT BETWEEN 1 AND 128",[],|r|r.get(0)).map_err(err)?;
   if bad!=0||count!=if pin.submission{if version==1{6}else{8}}else{8}||app!=if pin.submission{0x4d555350}else{0x4d554d32}||if pin.submission{!matches!(version,1|2)}else{version!=2}{return Err("Original initialized cache app/version/schema shape required".into());}
   let context=if pin.submission{"context"}else{"context_v2"};
   let q=format!("SELECT CASE WHEN typeof(genesis)='blob' AND length(genesis)=32 THEN genesis ELSE NULL END,CASE WHEN typeof(fingerprint)='blob' AND length(fingerprint)=32 THEN fingerprint ELSE NULL END FROM {context} WHERE id=1");
   let (g,f):(Vec<u8>,Vec<u8>)=db.query_row(&q,[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(err)?;
   let n:i64=db.query_row(&format!("SELECT count(*) FROM {context}"),[],|r|r.get(0)).map_err(err)?;
   if n!=1||g!=genesis||f!=fingerprint{return Err("Original cache network context mismatch".into());}
   // Exact pending signed raw commitments are externally pinned before shutdown;
   // cache status can never confer confirmation. Full public pool validation and
   // own-history reconciliation still execute in existing runtime constructors.
   for(id,wire)in &pin.pending {
    let q=if pin.submission{"SELECT CASE WHEN typeof(raw)='blob' AND length(raw) BETWEEN 1 AND 16384 THEN raw ELSE NULL END,class FROM entries WHERE id=?1"}else{"SELECT CASE WHEN typeof(raw)='blob' AND length(raw) BETWEEN 1 AND 16384 THEN raw ELSE NULL END,0 FROM lifecycle_v2 WHERE id=?1 AND status='PENDING'"};
    let (raw,list):(Vec<u8>,u8)=db.query_row(q,[id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).map_err(err)?;
    let (_,actual)=mutiny_consensus_v8::operation_index_v2::operation_id(list,&raw).map_err(err)?;
    if actual!=*id||mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,&raw)!=*wire{return Err("Original pending exact signed byte commitment mismatch".into());}
   }drop(db);leaf.recheck()?;held.push(leaf);
  }Ok(Self{held})
 }
 pub(super) fn recheck(&self)->Result<()>{for leaf in &self.held{leaf.recheck()?;}Ok(())}
}