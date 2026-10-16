// Included only by fixed Store's existing cfg(test) module. PUBLIC TEST files;
// simulated native failures are identified explicitly and supply no power-loss
// or separately administered antirollback qualification.
mod pinned_sqlite_native_controls {
 use super::super::{Guard,create_new_private_leaf,pinned_sqlite_vfs::PinnedConnection};
 use super::super::super::{image_pin::DatabasePin,process_auth::VerifiedProcess};
 use rusqlite::ffi;
 use std::{path::{Path,PathBuf},ptr};

 fn inputs()->(PathBuf,Vec<u8>){
  // Qualified selected controls start in a fresh serial process, before any
  // SQLite workers; this is not support for an ambient parallel test harness.
  super::super::install_sqlite_close_boundary_at_process_entry().unwrap();
  let mut nonce=[0u8;16];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
  let root=std::env::temp_dir().join(format!("w15-owned-sqlite-native-{}",hex::encode(nonce)));
  assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
  let user=VerifiedProcess::observe_created_process(std::process::id()).unwrap().user_sid;
  create_new_private_leaf(&root.join("public-native.sqlite"),&user).unwrap();
  create_new_private_leaf(&root.join("public-native.guard"),&user).unwrap();(root,user)
 }
 fn configured(path:&Path,user:&[u8],guard:&Guard)->PinnedConnection{
  let db=PinnedConnection::open(path,user,false,guard.quarantine.clone()).unwrap();
  db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE native_public(id INTEGER PRIMARY KEY,value INTEGER NOT NULL); INSERT INTO native_public VALUES(1,0);").unwrap();db
 }
 fn absent(path:&Path){assert!(matches!(std::fs::symlink_metadata(path),Err(e)if e.kind()==std::io::ErrorKind::NotFound),"Absence must be observed, not inferred from access refusal");}

 #[test]
 fn actual_selected_win32_main_close_observed_once_and_reopen_preserves_data(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");
  let guard=Guard::existing(&root.join("public-native.guard"),&user).unwrap();
  let db=configured(&path,&user,&guard);let trace=db.custody_trace();
  db.execute("UPDATE native_public SET value=61",[]).unwrap();db.close_checked().unwrap();
  let observed=trace.borrow().clone();assert!(observed.main_native_attempted);
  assert_eq!(observed.main_native_outcome,Some(true));assert_eq!(observed.main_close_callbacks,1);
  assert!(!observed.parent_retained);drop(guard);
  let guard=Guard::existing(&root.join("public-native.guard"),&user).unwrap();
  let db=PinnedConnection::open(&path,&user,true,guard.quarantine.clone()).unwrap();
  assert_eq!(db.query_row("SELECT value FROM native_public",[],|r|r.get::<_,u64>(0)).unwrap(),61);
  db.close_checked().unwrap();drop(guard);
 }

 #[test]
 fn modelled_lost_native_close_ack_stops_real_parent_retries_and_preserves_unknown(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");
  let guard_path=root.join("public-native.guard");let guard=Guard::existing(&guard_path,&user).unwrap();
  let db=configured(&path,&user,&guard);let trace=db.custody_trace();
  db.inject_lost_native_main_close_success().unwrap();assert!(db.close_checked().is_err());
  let observed=trace.borrow().clone();assert!(observed.main_native_attempted);
  assert_eq!(observed.main_native_outcome,Some(false));assert_eq!(observed.main_close_callbacks,3);
  assert!(observed.parent_retained&&observed.parent_native_handle_observed);
  assert!(guard.quarantine.get());drop(guard);assert!(Guard::existing(&guard_path,&user).is_err());
  assert_eq!(trace.borrow().main_close_callbacks,3,"Consumed owner Drop issued no parent retry");
  // Actual native close ran once; only its acknowledgement was modeled lost.
  // The selected C parent made three callback attempts, two refused before
  // native effects. This establishes no actual power-loss/CloseHandle failure.
  super::super::sqlite_close_boundary::exercise_unrelated_close_after_scope(&root.join("unrelated-public.guard"),&user).unwrap();
 }

 #[test]
 fn actual_database_ancestors_and_guard_close_once_then_exact_names_can_reopen(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let guard_path=root.join("public-native.guard");
  let mut pin=DatabasePin::open(&path,&user).unwrap();let traces=pin.native_close_traces();assert!(traces.len()>=3);
  pin.close_checked().unwrap();assert!(pin.recheck().is_err());assert!(pin.close_checked().is_err());drop(pin);
  for trace in &traces{assert_eq!(trace.get(),(1,Some(true),false));}
  let moved=root.join("public-native-closed.sqlite");std::fs::rename(&path,&moved).unwrap();std::fs::rename(&moved,&path).unwrap();
  let mut guard=Guard::existing(&guard_path,&user).unwrap();let native=guard.native_file_trace();let unlock=guard.unlock_trace.clone();
  let original=guard.native_id_hash().unwrap();guard.close_checked().unwrap();assert!(guard.close_checked().is_err());drop(guard);
  assert_eq!(native.get(),(1,Some(true),false));assert_eq!(unlock.get(),(1,Some(true),false));
  let mut exact=Guard::existing(&guard_path,&user).unwrap();assert_eq!(exact.native_id_hash().unwrap(),original);exact.close_checked().unwrap();
  // Actual HANDLE close observations, no nofollow/name/share relaxation and no
  // new custody identity. This is not a device/power-loss durability claim.
 }

 #[test]
 fn modelled_lost_ancestor_leaf_close_ack_retains_record_and_closes_other_leases_once(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let mut pin=DatabasePin::open(&path,&user).unwrap();
  let traces=pin.native_close_traces();pin.model_lost_leaf_close_ack();assert!(pin.close_checked().is_err());
  assert!(pin.recheck().is_err());assert!(pin.close_checked().is_err());drop(pin);
  assert_eq!(traces.last().unwrap().get(),(1,Some(true),true));
  for trace in &traces[..traces.len()-1]{assert_eq!(trace.get(),(1,Some(true),false));}
  assert!(DatabasePin::open(&path,&user).is_err(),"Unknown native cleanup cannot open another provider or reset the root");
 }

 #[test]
 fn modelled_lost_guard_unlock_ack_retains_original_handle_without_close_or_retry(){
  let(root,user)=inputs();let guard_path=root.join("public-native.guard");let mut guard=Guard::existing(&guard_path,&user).unwrap();
  let native=guard.native_file_trace();let unlock=guard.unlock_trace.clone();guard.model_lost_unlock_ack();
  assert!(guard.close_checked().is_err());assert!(guard.close_checked().is_err());drop(guard);
  assert_eq!(unlock.get(),(1,Some(true),true));assert_eq!(native.get(),(0,None,false));
  assert!(Guard::existing(&guard_path,&user).is_err(),"Modeled unknown unlock preserves the original guarded custody record");
 }

 #[test]
 fn actual_sqlite_main_handle_and_same_identity_restart_preserve_committed_rows(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let guard_path=root.join("public-native.guard");
  let guard=Guard::existing(&guard_path,&user).unwrap();let db=configured(&path,&user,&guard);
  let pin=DatabasePin::open(&path,&user).unwrap().native_id_hash();assert_eq!(db.native_binding(false).unwrap(),pin);
  db.execute("UPDATE native_public SET value=41 WHERE id=1",[]).unwrap();db.close_checked().unwrap();drop(guard);
  let guard=Guard::existing(&guard_path,&user).unwrap();let db=PinnedConnection::open(&path,&user,true,guard.quarantine.clone()).unwrap();
  assert_eq!(db.native_binding(false).unwrap(),pin);assert_eq!(db.query_row("SELECT value FROM native_public WHERE id=1",[],|r|r.get::<_,u64>(0)).unwrap(),41);
  db.close_checked().unwrap();drop(guard);
 }

 #[test]
 fn actual_main_handle_rejects_foreign_database_and_denies_name_replacement(){
  use std::{fs::File,mem::ManuallyDrop,os::windows::io::FromRawHandle};
  use windows_sys::Win32::Foundation::HANDLE;
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let guard=Guard::existing(&root.join("public-native.guard"),&user).unwrap();let db=configured(&path,&user,&guard);
  let wrong=root.join("other-public.sqlite");create_new_private_leaf(&wrong,&user).unwrap();let wrong_pin=DatabasePin::open(&wrong,&user).unwrap();
  let mut handle:HANDLE=ptr::null_mut();assert_eq!(unsafe{ffi::sqlite3_file_control(db.handle(),c"main".as_ptr(),29,(&mut handle as *mut HANDLE).cast())},ffi::SQLITE_OK);
  let borrowed=ManuallyDrop::new(unsafe{File::from_raw_handle(handle)});assert!(wrong_pin.check_opened(&borrowed).is_err());
  let renamed=root.join("replaced-public.sqlite");assert!(std::fs::rename(&path,&renamed).is_err());absent(&renamed);
  assert_eq!(db.native_binding(false).unwrap(),DatabasePin::open(&path,&user).unwrap().native_id_hash());
  db.close_checked().unwrap();drop(guard);
 }

 #[test]
 fn actual_engine_journal_uses_owned_handle_through_commit_and_blocks_substitution(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let journal=root.join("public-native.sqlite-journal");
  let guard=Guard::existing(&root.join("public-native.guard"),&user).unwrap();let db=configured(&path,&user,&guard);absent(&journal);
  db.execute_batch("BEGIN IMMEDIATE; UPDATE native_public SET value=7 WHERE id=1;").unwrap();
  let original=db.native_binding(true).unwrap();assert_ne!(original,[0;32]);
  let renamed=root.join("substituted-journal");assert!(std::fs::rename(&journal,&renamed).is_err());absent(&renamed);
  assert!(create_new_private_leaf(&journal,&user).is_err());assert_eq!(db.native_binding(true).unwrap(),original);
  db.execute_batch("COMMIT").unwrap();absent(&journal);assert_eq!(db.query_row("SELECT value FROM native_public",[],|r|r.get::<_,u64>(0)).unwrap(),7);
  db.close_checked().unwrap();drop(guard);
 }

 #[test]
 fn preexisting_journal_refuses_before_sqlite_write_and_preserves_exact_bytes(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let journal=root.join("public-native.sqlite-journal");
  create_new_private_leaf(&journal,&user).unwrap();std::fs::write(&journal,b"PUBLIC-UNKNOWN-ROLLBACK-RECORD").unwrap();
  let before=std::fs::read(&journal).unwrap();let guard_path=root.join("public-native.guard");let guard=Guard::existing(&guard_path,&user).unwrap();
  assert!(PinnedConnection::open(&path,&user,false,guard.quarantine.clone()).is_err());
  assert_eq!(std::fs::metadata(&path).unwrap().len(),0);assert_eq!(std::fs::read(&journal).unwrap(),before);assert!(guard.quarantine.get());
  drop(guard);assert!(Guard::existing(&guard_path,&user).is_err(),"Unknown journal keeps original exclusive owner; no automatic repair/reset");
 }

 #[test]
 fn existing_wal_refuses_and_exact_foreign_names_never_enter_owned_vfs(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let guard=Guard::existing(&root.join("public-native.guard"),&user).unwrap();let db=configured(&path,&user,&guard);
  for name in ["public-native.sqlite-wal","public-native.sqlite-shm","other-public.sqlite","public-native.sqlite-journal-extra"]{assert!(db.namespace_refuses(&root.join(name)));}
  db.close_checked().unwrap();drop(guard);
  let(other_root,other_user)=inputs();let other_path=other_root.join("public-native.sqlite");let other_guard=Guard::existing(&other_root.join("public-native.guard"),&other_user).unwrap();let other=configured(&other_path,&other_user,&other_guard);
  let outside=other_root.join("unselected.sqlite");assert!(other.execute("ATTACH DATABASE ?1 AS foreign_db",[outside.to_str().unwrap()]).is_err());absent(&outside);assert!(other.status().is_err());assert!(other.close_checked().is_err());drop(other_guard);
  let wal=root.join("public-native.sqlite-wal");create_new_private_leaf(&wal,&user).unwrap();std::fs::write(&wal,b"PUBLIC-FOREIGN-WAL").unwrap();let bytes=std::fs::read(&wal).unwrap();
  let guard=Guard::existing(&root.join("public-native.guard"),&user).unwrap();
  let result=PinnedConnection::open(&path,&user,true,guard.quarantine.clone());
  match result{Err(_)=>{},Ok(db)=>{assert!(db.query_row("SELECT value FROM native_public",[],|r|r.get::<_,u64>(0)).is_err());assert!(db.close_checked().is_err());}}
  assert!(guard.quarantine.get());assert_eq!(std::fs::read(&wal).unwrap(),bytes);drop(guard);
 }

 #[test]
 fn actual_journal_rollback_preserves_pretransaction_value_and_deletes_owned_sidecar(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let journal=root.join("public-native.sqlite-journal");let guard=Guard::existing(&root.join("public-native.guard"),&user).unwrap();let db=configured(&path,&user,&guard);
  db.execute_batch("BEGIN IMMEDIATE; UPDATE native_public SET value=33 WHERE id=1;").unwrap();assert_ne!(db.native_binding(true).unwrap(),[0;32]);
  db.execute_batch("ROLLBACK").unwrap();absent(&journal);assert_eq!(db.query_row("SELECT value FROM native_public",[],|r|r.get::<_,u64>(0)).unwrap(),0);
  db.close_checked().unwrap();drop(guard);
 }

 #[test]
 fn simulated_sync_refusal_freezes_real_sqlite_and_keeps_guard_after_close(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let guard_path=root.join("public-native.guard");let guard=Guard::existing(&guard_path,&user).unwrap();let db=configured(&path,&user,&guard);
  db.inject_sync_refusal();assert!(db.execute("UPDATE native_public SET value=5",[]).is_err());assert!(db.status().is_err());assert!(db.close_checked().is_err());
  assert!(guard.quarantine.get());drop(guard);assert!(Guard::existing(&guard_path,&user).is_err());
  // The injected xSync refusal models an unknown durable outcome. Actual
  // engine/NTFS/HANDLE paths ran; no physical outage or power-loss claim.
 }

 #[test]
 fn simulated_delete_refusal_preserves_consumed_journal_and_freezes_owner(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let journal=root.join("public-native.sqlite-journal");let guard_path=root.join("public-native.guard");let guard=Guard::existing(&guard_path,&user).unwrap();let db=configured(&path,&user,&guard);
  db.inject_delete_refusal();assert!(db.execute("UPDATE native_public SET value=9",[]).is_err());
  assert!(std::fs::symlink_metadata(&journal).unwrap().is_file());let before=std::fs::read(&journal).unwrap();
  assert!(db.status().is_err());assert!(db.close_checked().is_err());assert_eq!(std::fs::read(&journal).unwrap(),before);
  drop(guard);assert!(Guard::existing(&guard_path,&user).is_err());
 }

 #[test]
 fn simulated_journal_validation_refusal_roots_handle_before_error_and_closes_once(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let journal=root.join("public-native.sqlite-journal");let guard_path=root.join("public-native.guard");let guard=Guard::existing(&guard_path,&user).unwrap();let db=configured(&path,&user,&guard);let trace=db.custody_trace();
  db.inject_journal_validation_refusal();assert!(db.execute("UPDATE native_public SET value=6",[]).is_err());assert!(db.status().is_err());assert!(db.close_checked().is_err());
  let observed=trace.borrow();assert!(observed.journal_retained);assert!(observed.journal_native_close_attempted);assert_eq!(observed.journal_native_close_observed,Some(true));
  assert!(std::fs::symlink_metadata(&journal).unwrap().is_file());drop(guard);assert!(Guard::existing(&guard_path,&user).is_err());
  // Actual CREATE_NEW, protected ACL check and one observed native cleanup;
  // injected validation failure, preserved sidecar, no crash/power-loss claim.
 }

 #[test]
 fn simulated_parent_method_close_refusal_keeps_original_allocation_and_handle_reachable(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let guard_path=root.join("public-native.guard");let guard=Guard::existing(&guard_path,&user).unwrap();let db=configured(&path,&user,&guard);let trace=db.custody_trace();
  db.inject_parent_close_refusal();assert!(db.close_checked().is_err());let observed=trace.borrow();assert!(observed.parent_retained);assert!(observed.parent_native_handle_observed);
  drop(guard);assert!(Guard::existing(&guard_path,&user).is_err());
  // Simulated refusal occurs before delegated stock win32 xClose. The original
  // parent pointer/HANDLE stays rooted after SQLite discards its outer wrapper.
 }

 #[test]
 fn actual_busy_close_quarantines_registered_vfs_and_never_retries_owner_close(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let guard_path=root.join("public-native.guard");let guard=Guard::existing(&guard_path,&user).unwrap();let db=configured(&path,&user,&guard);
  let mut statement: *mut ffi::sqlite3_stmt=ptr::null_mut();assert_eq!(unsafe{ffi::sqlite3_prepare_v2(db.handle(),c"SELECT value FROM native_public".as_ptr(),-1,&mut statement,ptr::null_mut())},ffi::SQLITE_OK);assert!(!statement.is_null());
  assert!(db.close_checked().is_err());assert!(guard.quarantine.get());drop(guard);assert!(Guard::existing(&guard_path,&user).is_err());
  // Intentionally retained in this isolated TEST process: the busy connection,
  // statement, VFS and native guards get no retry/finalize/reset escape.
 }

 #[test]
 fn durability_pragma_bypass_refuses_and_cached_provider_reads_cannot_sign(){
  let(root,user)=inputs();let path=root.join("public-native.sqlite");let guard=Guard::existing(&root.join("public-native.guard"),&user).unwrap();let db=configured(&path,&user,&guard);
  assert!(db.execute_batch("PRAGMA journal_mode=OFF").is_err());assert!(db.status().is_err());assert!(db.close_checked().is_err());drop(guard);
  let(root,user,binding,f)=super::setup();let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");
  let store=super::Store::initialize_before_h0(&path,&guard,&user,binding,&f.coordinator,&f.continuity).unwrap();
  store.db.inject_sync_refusal();assert!(store.db.execute("UPDATE test_signer_context SET tip=1 WHERE id=1",[]).is_err());
  assert!(store.journal_pin().is_err());assert!(store.possession_before_h0().is_err());drop(store);
 }
}
