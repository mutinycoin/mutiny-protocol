//! EXTERNAL SOURCE ONLY / UNCOMPILED. PUBLIC TEST cache checkpoint, not finality.
//! Read-only exact whole row/membership commitments before any mutable reopen.
//! No normal SubmissionPool schema/API, archive lookup policy or VFS change.
use super::image_pin::{DatabasePin,DirectoryPin};
use mutiny_consensus_v8::Hash;
use rusqlite::{Connection,OpenFlags,types::ValueRef};
use sha2::{Digest,Sha256};
use std::{path::{Path,PathBuf},collections::BTreeSet};
type Result<T>=std::result::Result<T,String>;
pub(super) const MARKER:&str="MUTINY-W15-NONSHIPPING-EXACT-CACHE-CHECKPOINT-V1";
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
#[derive(Clone,Debug,PartialEq,Eq,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Object {pub path:PathBuf,pub native_id:Hash,pub rows:Hash}
#[derive(Clone,Debug,PartialEq,Eq,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {pub main:Object,pub submission:bool,pub archive_native:Option<Hash>,pub members:Vec<Object>}
pub(super) struct Held {databases:Vec<DatabasePin>,directory:Option<DirectoryPin>}
impl Held {pub(super) fn recheck(&self)->Result<()>{for d in &self.databases{d.recheck()?;}if let Some(d)=&self.directory{d.recheck()?;}Ok(())}}
fn absent(p:&Path)->Result<()> {match std::fs::symlink_metadata(p){Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(()),Ok(_)=>Err("Incomplete journal/checkpoint boundary; preserve input".into()),Err(e)=>Err(err(e))}}
// Stable SQL snapshot with bounds checked BEFORE fetching any String/blob.
// Includes schema, every public status/raw row, resource and input reservation.
fn rows(path:&Path,held:&DatabasePin,app:i64,versions:&[i64],limit:u64)->Result<Hash>{
 held.recheck()?;
 let file=std::fs::OpenOptions::new().read(true).open(path).map_err(err)?;held.check_opened(&file)?;
 if !(1..=limit).contains(&file.metadata().map_err(err)?.len()){return Err("Initialized bounded original cache required".into());}
 for suffix in ["-journal","-wal","-shm"]{absent(&PathBuf::from(format!("{}{suffix}",path.to_str().ok_or("Cache path Unicode")?)))?;}
 let db=Connection::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;
 db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN;").map_err(err)?;
 let a:i64=db.pragma_query_value(None,"application_id",|r|r.get(0)).map_err(err)?;
 let v:i64=db.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(err)?;
 let (n,bad):(i64,i64)=db.query_row("SELECT count(*),coalesce(sum(CASE WHEN typeof(type)!='text' OR typeof(name)!='text' OR typeof(tbl_name)!='text' OR length(CAST(type AS BLOB)) NOT BETWEEN 1 AND 16 OR length(CAST(name AS BLOB)) NOT BETWEEN 1 AND 128 OR length(CAST(tbl_name AS BLOB)) NOT BETWEEN 1 AND 128 OR (sql IS NOT NULL AND (typeof(sql)!='text' OR length(CAST(sql AS BLOB))>65536)) THEN 1 ELSE 0 END),0) FROM sqlite_schema",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(err)?;
 if a!=app||!versions.contains(&v)||!(1..=32).contains(&n)||bad!=0{return Err("Initialized original cache metadata bound/type/context required".into());}
 let mut schema=db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name,tbl_name").map_err(err)?;
 let mut h=Sha256::new();h.update(MARKER.as_bytes());h.update(a.to_be_bytes());h.update(v.to_be_bytes());
 let mut tables=Vec::new();let mut fetched=schema.query([]).map_err(err)?;
 while let Some(row)=fetched.next().map_err(err)?{
  let kind:String=row.get(0).map_err(err)?;let name:String=row.get(1).map_err(err)?;
  for c in 0..4{cell(&mut h,row.get_ref(c).map_err(err)?,&mut 0)?;}
  if kind=="table"{if name.starts_with("sqlite_"){return Err("Unexpected internal cache table".into());}tables.push(name);}
 }
 let mut total=0usize;let mut row_count=0usize;
 for table in tables {
  let quoted=format!("\"{}\"",table.replace('"',"\"\""));
  let mut stmt=db.prepare(&format!("SELECT * FROM {quoted}")).map_err(err)?;
  let columns=stmt.column_count();if !(1..=16).contains(&columns){return Err("Cache column bound".into());}
  let (count,oversized):(i64,i64)={
   let sizes=(0..columns).map(|i|{let c=stmt.column_name(i).map_err(err)?;Ok(format!("length(CAST(\"{}\" AS BLOB))",c.replace('"',"\"\"")))}).collect::<Result<Vec<_>>>()?;
   let predicate=sizes.iter().map(|s|format!("coalesce({s},0)>65536")).collect::<Vec<_>>().join(" OR ");
   db.query_row(&format!("SELECT count(*),coalesce(sum(CASE WHEN {predicate} THEN 1 ELSE 0 END),0) FROM {quoted}"),[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(err)?
  };
  if count<0||count>65536||oversized!=0{return Err("Cache row/cell bound before fetch".into());}
  // Explicit all-column SQLite ordering, not incidental rowid order.
  let order=(1..=columns).map(|i|i.to_string()).collect::<Vec<_>>().join(",");drop(stmt);
  let mut stmt=db.prepare(&format!("SELECT * FROM {quoted} ORDER BY {order}")).map_err(err)?;
  h.update((table.len() as u64).to_be_bytes());h.update(table.as_bytes());h.update(count.to_be_bytes());
  let mut found=stmt.query([]).map_err(err)?;let mut actual=0;
  while let Some(row)=found.next().map_err(err)?{actual+=1;row_count+=1;if row_count>65536{return Err("Whole cache row quota".into());}for i in 0..columns{cell(&mut h,row.get_ref(i).map_err(err)?,&mut total)?;}}
  if actual!=count{return Err("Stable cache row count differs".into());}
 }
 db.execute_batch("ROLLBACK;").map_err(err)?;held.recheck()?;Ok(h.finalize().into())
}
fn cell(h:&mut Sha256,value:ValueRef<'_>,total:&mut usize)->Result<()> {
 let (tag,bytes):(u8,Vec<u8>)=match value{ValueRef::Null=>(0,Vec::new()),ValueRef::Integer(n)=>(1,n.to_be_bytes().to_vec()),ValueRef::Real(n)=>(2,n.to_bits().to_be_bytes().to_vec()),ValueRef::Text(s)=>(3,s.to_vec()),ValueRef::Blob(s)=>(4,s.to_vec())};
 if bytes.len()>65536{return Err("Cache cell bound".into());}*total=total.checked_add(bytes.len()).ok_or("Cache byte overflow")?;if *total>32*1024*1024{return Err("Whole cache public byte quota".into());}
 h.update([tag]);h.update((bytes.len() as u64).to_be_bytes());h.update(bytes);Ok(())
}
fn names(root:&Path)->Result<BTreeSet<String>>{
 let mut result=BTreeSet::new();for entry in std::fs::read_dir(root).map_err(err)?{
  let name=entry.map_err(err)?.file_name().into_string().map_err(|_|"Archive name Unicode")?;
  if name.len()>128||result.len()>=34||!result.insert(name){return Err("Finite archive membership bound/duplicate".into());}
 }Ok(result)
}
impl Snapshot {
 pub(super) fn observe(path:&Path,submission:bool,user:&[u8])->Result<(Self,Held)>{
  let pin=DatabasePin::open(path,user)?;
  let main=Object{path:path.into(),native_id:pin.native_id_hash(),rows:rows(path,&pin,if submission{0x4d555350}else{0x4d554d32},if submission{&[1,2]}else{&[2]},128*1024*1024)?};
  let mut databases=vec![pin];let archive=path.with_extension("submission-archive");let mut members=Vec::new();let mut directory=None;let mut archive_native=None;
  let observed_version={let read=Connection::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;read.pragma_query_value(None,"user_version",|r|r.get::<_,i64>(0)).map_err(err)?};
  if submission{match std::fs::symlink_metadata(&archive){
   Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{if observed_version==2{return Err("Original upgraded submission catalog requires its retained archive; never recreate".into());}},Err(e)=>return Err(err(e)),Ok(_)=>{
    let dir=DirectoryPin::open(&archive,user)?;archive_native=Some(dir.native_id_hash());let before=names(&archive)?;
    if !before.contains("archive.lock")||!before.contains("lookup.sqlite"){return Err("Original archive lock/initialized lookup absent; no repair".into());}
    let mut shards=BTreeSet::new();
    for name in &before{
     let p=archive.join(name);let held=DatabasePin::open(&p,user)?;
     let digest=if name=="archive.lock"{
      let f=std::fs::OpenOptions::new().read(true).open(&p).map_err(err)?;held.check_opened(&f)?;
      if f.metadata().map_err(err)?.len()!=0{return Err("Original archive lock format differs".into());}Sha256::digest(b"MUTINY-W15-EMPTY-ORIGINAL-ARCHIVE-LOCK-V1").into()
     }else if name=="lookup.sqlite"{rows(&p,&held,0,&[0],32*1024*1024)?}
     else {let number=shard_number(name)?;shards.insert(number);rows(&p,&held,0x4d555350,&[1],8*1024*1024)?};
     members.push(Object{path:p,native_id:held.native_id_hash(),rows:digest});databases.push(held);
    }
    if shards.iter().copied().ne(0..shards.len() as u64){return Err("Original archive shard sequence differs".into());}
    if names(&archive)?!=before{return Err("Archive membership changed during public snapshot".into());}dir.recheck()?;directory=Some(dir);
   }
  }}
  members.sort_by(|a,b|a.path.cmp(&b.path));let held=Held{databases,directory};held.recheck()?;
  Ok((Self{main,submission,archive_native,members},held))
 }
 pub(super) fn preflight(&self,user:&[u8])->Result<Held>{let (actual,held)=Self::observe(&self.main.path,self.submission,user)?;if actual!=*self{return Err("Original whole cache/catalog/archive/status/reservation snapshot differs".into());}Ok(held)}
}
fn shard_number(name:&str)->Result<u64>{let digits=name.strip_prefix("shard-").and_then(|s|s.strip_suffix(".sqlite")).filter(|s|s.len()==20&&s.bytes().all(|b|b.is_ascii_digit())).ok_or("Unknown original archive member/journal; preserve input")?;let n=digits.parse::<u64>().map_err(err)?;if n>=32{return Err("Finite original archive shard bound".into());}Ok(n)}
#[cfg(test)]
mod tests {
 use super::*;
 #[test] fn exact_archive_member_grammar_rejects_journals_gaps_and_unknown_files(){
  assert_eq!(shard_number("shard-00000000000000000000.sqlite").unwrap(),0);
  for bad in ["shard-0.sqlite","shard-00000000000000000032.sqlite","shard-00000000000000000000.sqlite-journal","lookup.sqlite-journal","foreign.sqlite","shard-0000000000000000000x.sqlite"]{assert!(shard_number(bad).is_err(),"{bad}");}
 }
 #[test] fn missing_original_cache_cannot_initialize_or_publish_membership(){
  let actual=super::super::process_auth::VerifiedProcess::observe_created_process(std::process::id()).unwrap();
  let nonce=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();let root=std::env::temp_dir().join(format!("w15-cache-missing-{}-{nonce}",std::process::id()));
  assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
  let missing=root.join("missing.sqlite");assert!(Snapshot::observe(&missing,true,&actual.user_sid).is_err());assert!(matches!(std::fs::symlink_metadata(missing),Err(e) if e.kind()==std::io::ErrorKind::NotFound));assert_eq!(std::fs::read_dir(root).unwrap().count(),0);
 }
}

impl Object {
 /// Whole original transport cache is retained, not migrated to the new peer.
 /// Fresh sessions cannot silently hide an incomplete old fragmented object.
 /// Signed wallet pending/outbox records remain the source for any later retry.
 pub(super) fn observe_transport(path:&Path,user:&[u8])->Result<(Self,DatabasePin)>{
  let pin=DatabasePin::open(path,user)?;let digest=rows(path,&pin,0,&[7],64*1024*1024)?;
  let db=Connection::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;
  db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN;").map_err(err)?;
  let peer:Vec<u8>=db.query_row("SELECT CASE WHEN typeof(id)='blob' AND length(id)=32 THEN id ELSE NULL END FROM peer",[],|r|r.get(0)).map_err(err)?;
  let n:i64=db.query_row("SELECT count(*) FROM peer",[],|r|r.get(0)).map_err(err)?;
  let incomplete:i64=db.query_row("SELECT count(*) FROM objects WHERE complete!=1 OR invalid!=0",[],|r|r.get(0)).map_err(err)?;
  if n!=1||peer.as_slice()==[0;32]||incomplete!=0{return Err("Original transport has invalid/incomplete native objects or missing peer; preserve, no reconnect waiver".into());}
  drop(db);pin.recheck()?;Ok((Self{path:path.into(),native_id:pin.native_id_hash(),rows:digest},pin))
 }
 pub(super) fn transport_preflight(&self,user:&[u8])->Result<DatabasePin>{let (actual,pin)=Self::observe_transport(&self.path,user)?;if actual!=*self{return Err("Original full transport peer/fragments/acks/reservations changed".into());}Ok(pin)}
}
#[cfg(test)] mod actual_public_sql_checkpoint_tests {
 use super::*;
 fn owned()->(PathBuf,Vec<u8>){
  let p=super::super::process_auth::VerifiedProcess::observe_created_process(std::process::id()).unwrap();
  let n=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();let root=std::env::temp_dir().join(format!("w15-public-checkpoint-{}-{n}",p.pid));
  assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());(root,p.user_sid)
 }
 fn fresh(path:&Path,user:&[u8],sql:&str){super::super::test_signer_store::create_new_private_leaf(path,user).unwrap();let db=Connection::open(path).unwrap();db.execute_batch(sql).unwrap();}
 #[test] fn actual_public_sql_row_reservation_and_native_pin_mutations_refuse_before_reopen(){
  let(root,user)=owned();let path=root.join("public-payment.sqlite");
  fresh(&path,&user,"PRAGMA application_id=1297435954;PRAGMA user_version=2;CREATE TABLE reservations(id BLOB PRIMARY KEY,raw BLOB,status TEXT);INSERT INTO reservations VALUES(X'01',X'0203','pending');");
  let (snapshot,held)=Snapshot::observe(&path,false,&user).unwrap();snapshot.preflight(&user).unwrap();
  let db=Connection::open(&path).unwrap();db.execute("UPDATE reservations SET status='consumed'",[]).unwrap();drop(db);
  let refusal=match snapshot.preflight(&user){Ok(_)=>panic!("Changed retained reservation accepted"),Err(e)=>e};assert!(refusal.contains("snapshot differs"));held.recheck().unwrap();
  let (changed,held2)=Snapshot::observe(&path,false,&user).unwrap();assert_ne!(changed.main.rows,snapshot.main.rows);assert_eq!(changed.main.native_id,snapshot.main.native_id);
  let mut wrong=changed.clone();wrong.main.native_id=[77;32];assert!(wrong.preflight(&user).is_err());
  let db=Connection::open(&path).unwrap();db.execute("UPDATE reservations SET raw=?1",[vec![9u8;65537]]).unwrap();drop(db);assert!(Snapshot::observe(&path,false,&user).is_err());held2.recheck().unwrap();
 }
 #[test] fn actual_public_transport_checkpoint_preserves_pending_fragments_and_rejects_incomplete_objects(){
  let(root,user)=owned();let path=root.join("original-transport.sqlite");
  fresh(&path,&user,"PRAGMA user_version=7;CREATE TABLE peer(id BLOB);CREATE TABLE objects(id BLOB,complete INTEGER,invalid INTEGER);CREATE TABLE fragments(id BLOB,ack INTEGER,payload BLOB);INSERT INTO peer VALUES(zeroblob(32));UPDATE peer SET id=X'0101010101010101010101010101010101010101010101010101010101010101';INSERT INTO objects VALUES(X'01',1,0);INSERT INTO fragments VALUES(X'01',0,X'0102');");
  let (snapshot,held)=Object::observe_transport(&path,&user).unwrap();snapshot.transport_preflight(&user).unwrap();
  let db=Connection::open(&path).unwrap();db.execute("UPDATE fragments SET ack=1",[]).unwrap();drop(db);assert!(snapshot.transport_preflight(&user).is_err());held.recheck().unwrap();
  let (changed,_)=Object::observe_transport(&path,&user).unwrap();assert_ne!(snapshot.rows,changed.rows);
  let db=Connection::open(&path).unwrap();db.execute("UPDATE objects SET complete=0",[]).unwrap();drop(db);assert!(Object::observe_transport(&path,&user).is_err());
 }
}