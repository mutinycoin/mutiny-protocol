//! SOURCE-ONLY independent controls, to be included by reviewed cfg(test) host.
//! Uses actual SQLite; no TPM/service/native-VFS qualification from these tests.
use super::*;
use std::sync::atomic::{AtomicUsize,Ordering};
const BINDING:&str="CREATE TABLE store_binding(id INTEGER PRIMARY KEY CHECK(id=1), schema TEXT NOT NULL, context BLOB NOT NULL CHECK(typeof(context)='blob' AND length(context)=32), record_sha256 BLOB NOT NULL CHECK(typeof(record_sha256)='blob' AND length(record_sha256)=32), store_id BLOB NOT NULL CHECK(typeof(store_id)='blob' AND length(store_id)=32))";
const ISSUED:&str="CREATE TABLE issued(nonce BLOB PRIMARY KEY CHECK(typeof(nonce)='blob' AND length(nonce)=32), challenge BLOB NOT NULL CHECK(typeof(challenge)='blob'), descriptor BLOB NOT NULL CHECK(typeof(descriptor)='blob'), consumed INTEGER NOT NULL CHECK(typeof(consumed)='integer' AND consumed IN(0,1))) WITHOUT ROWID";
const ADMISSIONS:&str="CREATE TABLE admissions(nonce BLOB PRIMARY KEY CHECK(typeof(nonce)='blob' AND length(nonce)=32), challenge BLOB NOT NULL CHECK(typeof(challenge)='blob'), descriptor BLOB NOT NULL CHECK(typeof(descriptor)='blob'), signature BLOB NOT NULL CHECK(typeof(signature)='blob' AND length(signature)=1394)) WITHOUT ROWID";
fn expected()->Vec<ExpectedSchema>{
 let db=Connection::open_in_memory().unwrap();create(&db);let slot=WorkSlot::for_owned_connection(&db);
 let mut q=db.prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY name").unwrap();
 q.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
}
fn create(db:&Connection){db.execute_batch(&format!("{BINDING};{ISSUED};{ADMISSIONS};")).unwrap();}
#[test]
fn exact_schema_positive_uses_same_transaction_and_cleans_handler(){
 let db=Connection::open_in_memory().unwrap();create(&db);let slot=WorkSlot::for_owned_connection(&db);
 let target=expected();let budget=NonZeroU64::new(100000).unwrap();
 let reader=ReadWindow::open(&db,&target,&slot,budget).unwrap();assert!(!db.is_autocommit());assert!(reader.admissions().unwrap().is_empty());drop(reader);
 assert!(db.is_autocommit());assert_eq!(db.query_row("SELECT 7",[],|r|r.get::<_,i64>(0)).unwrap(),7);
}
static TABLE_READS:AtomicUsize=AtomicUsize::new(0);
unsafe extern "C" fn record_read(_:*mut c_void,op:c_int,a:*const std::ffi::c_char,_:*const std::ffi::c_char,_:*const std::ffi::c_char,_:*const std::ffi::c_char)->c_int{
 if op==ffi::SQLITE_READ && !a.is_null(){
  let name=unsafe{std::ffi::CStr::from_ptr(a)}.to_bytes();
  if name==b"issued" || name==b"admissions" || name==b"store_binding"{TABLE_READS.fetch_add(1,Ordering::SeqCst);}
 }
 ffi::SQLITE_OK
}
#[test]
fn recursive_view_refused_before_any_application_table_read(){
 let db=Connection::open_in_memory().unwrap();create(&db);let slot=WorkSlot::for_owned_connection(&db);
 db.execute_batch("DROP TABLE issued;CREATE VIEW issued AS WITH RECURSIVE endless(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM endless) SELECT zeroblob(32) AS nonce,x'01' AS challenge,x'02' AS descriptor,0 AS consumed FROM endless;").unwrap();
 TABLE_READS.store(0,Ordering::SeqCst);
 unsafe{ffi::sqlite3_set_authorizer(db.handle(),Some(record_read),std::ptr::null_mut())};
 assert!(matches!(ReadWindow::open(&db,&expected(),&slot,NonZeroU64::new(100000).unwrap()),Err(Refusal::Store)));
 unsafe{ffi::sqlite3_set_authorizer(db.handle(),None,std::ptr::null_mut())};
 assert_eq!(TABLE_READS.load(Ordering::SeqCst),0);assert!(db.is_autocommit());
}
#[test]
fn exhausted_budget_refuses_then_removes_handler_for_rollback_and_next_use(){
 let db=Connection::open_in_memory().unwrap();create(&db);let slot=WorkSlot::for_owned_connection(&db);
 assert!(matches!(ReadWindow::open(&db,&expected(),&slot,NonZeroU64::new(1).unwrap()),Err(Refusal::Store)));
 assert!(db.is_autocommit());assert_eq!(db.query_row("SELECT 7",[],|r|r.get::<_,i64>(0)).unwrap(),7);
 assert!(ReadWindow::open(&db,&expected(),&slot,NonZeroU64::new(100000).unwrap()).is_ok());
}
#[test]
fn changed_table_definition_is_rejected_before_row_copy(){
 let db=Connection::open_in_memory().unwrap();create(&db);let slot=WorkSlot::for_owned_connection(&db);
 db.execute_batch("DROP TABLE admissions;CREATE TABLE admissions(nonce,challenge,descriptor,signature);").unwrap();
 assert!(matches!(ReadWindow::open(&db,&expected(),&slot,NonZeroU64::new(100000).unwrap()),Err(Refusal::Store)));
}

#[test]
fn overlapping_window_refuses_without_clearing_first_owned_handler(){
 let db=Connection::open_in_memory().unwrap();create(&db);let slot=WorkSlot::for_owned_connection(&db);
 let reader=ReadWindow::open(&db,&expected(),&slot,NonZeroU64::new(100000).unwrap()).unwrap();
 assert!(matches!(ReadWindow::open(&db,&expected(),&slot,NonZeroU64::new(100000).unwrap()),Err(Refusal::Store)));
 // The refused second window never registered/cleared the first handler.
 assert!(db.query_row("WITH RECURSIVE n(x) AS(SELECT 1 UNION ALL SELECT x+1 FROM n) SELECT count(*) FROM n",[],|r|r.get::<_,i64>(0)).is_err());
 drop(reader);assert!(db.is_autocommit());assert_eq!(db.query_row("SELECT 7",[],|r|r.get::<_,i64>(0)).unwrap(),7);
}
#[test]
fn slot_from_different_actual_connection_is_refused_before_registration(){
 let a=Connection::open_in_memory().unwrap();create(&a);let slot=WorkSlot::for_owned_connection(&a);
 let b=Connection::open_in_memory().unwrap();create(&b);
 assert!(matches!(ReadWindow::open(&b,&expected(),&slot,NonZeroU64::new(100000).unwrap()),Err(Refusal::Store)));
 assert!(a.is_autocommit() && b.is_autocommit());
}
