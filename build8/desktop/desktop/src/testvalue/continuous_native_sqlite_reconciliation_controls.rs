// Tests exercise key-free native reads. The positive prior-owner closure input
// is explicitly MODELED in four controls; no actual fresh-process credit.
mod frozen_sqlite_reconciliation_controls{
 use super::super::{Guard,create_new_private_leaf,JournalPin,pinned_sqlite_vfs::PinnedConnection,
  sqlite_reconciliation::{FrozenInspection,ExpectedSnapshot,RecoveryNeed}};
 use super::super::super::process_auth::VerifiedProcess;
 use std::path::Path;
 fn expected()->ExpectedSnapshot{ExpectedSnapshot::Fixed(JournalPin{tip:0,commits:0,works:0,commitment:[9;32]})}
 fn journal(path:&Path,user:&[u8]){create_new_private_leaf(path,user).unwrap();std::fs::write(path,b"PUBLIC-UNREPORTED-JOURNAL-IS-NOT-AUTHORITATIVE-HISTORY").unwrap();}

 #[test]
 fn actual_live_owner_refuses_frozen_inspection_before_custody_or_sqlite_access(){
  let(root,user,b,_)=super::setup();let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");let sidecar=root.join("synthetic-signers.sqlite-journal");journal(&sidecar,&user);
  let prior=VerifiedProcess::observe_created_process(std::process::id()).unwrap();assert!(FrozenInspection::capture(&path,&guard,&user,&b,expected(),&prior).is_err());
  assert_eq!(std::fs::metadata(&path).unwrap().len(),0);let held=Guard::existing(&guard,&user).unwrap();drop(held);
 }

 #[test]
 fn modelled_closed_owner_actual_artifact_holds_refuse_write_rename_and_never_grant_resume(){
  let(root,user,b,_)=super::setup();let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");let sidecar=root.join("synthetic-signers.sqlite-journal");journal(&sidecar,&user);let before=std::fs::read(&sidecar).unwrap();
  let captured=FrozenInspection::capture_with_modelled_closed_owner(&path,&guard,&user,&b,expected()).unwrap();assert!(captured.observed_modelled_closure());
  assert!(FrozenInspection::capture_with_modelled_closed_owner(&path,&guard,&user,&b,expected()).is_err());
  assert_eq!(captured.need().unwrap(),RecoveryNeed::ExactAuthorizedTransitionUnavailable);assert!(std::fs::write(&path,b"forbidden write").is_err());assert!(std::fs::write(&sidecar,b"forbidden overwrite").is_err());
  assert!(std::fs::rename(&sidecar,root.join("forbidden-replacement")).is_err());captured.recheck().unwrap();captured.close_checked().unwrap();
  assert_eq!(std::fs::metadata(&path).unwrap().len(),0);assert_eq!(std::fs::read(&sidecar).unwrap(),before);
  let held=Guard::existing(&guard,&user).unwrap();assert!(PinnedConnection::open(&path,&user,false,held.quarantine.clone()).is_err());drop(held);
 }

 #[test]
 fn modelled_closed_owner_wrong_native_scope_and_snapshot_refuse_without_reset(){
  let(root,user,b,_)=super::setup();let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");let sidecar=root.join("synthetic-signers.sqlite-journal");journal(&sidecar,&user);let before=std::fs::read(&sidecar).unwrap();
  let mut wrong=b.clone();wrong.native_custody_identity[0]^=1;assert!(FrozenInspection::capture_with_modelled_closed_owner(&path,&guard,&user,&wrong,expected()).is_err());
  let invalid=ExpectedSnapshot::Fixed(JournalPin{tip:0,commits:0,works:0,commitment:[0;32]});assert!(FrozenInspection::capture_with_modelled_closed_owner(&path,&guard,&user,&b,invalid).is_err());
  assert_eq!(std::fs::metadata(&path).unwrap().len(),0);assert_eq!(std::fs::read(&sidecar).unwrap(),before);
 }

 #[test]
 fn modelled_closed_owner_missing_journal_never_creates_sidecar_or_initializes_store(){
  let(root,user,b,_)=super::setup();let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");let sidecar=root.join("synthetic-signers.sqlite-journal");
  assert!(FrozenInspection::capture_with_modelled_closed_owner(&path,&guard,&user,&b,expected()).is_err());
  assert!(matches!(std::fs::symlink_metadata(&sidecar),Err(e)if e.kind()==std::io::ErrorKind::NotFound));assert_eq!(std::fs::metadata(&path).unwrap().len(),0);
  let held=Guard::existing(&guard,&user).unwrap();drop(held);
 }

 #[test]
 fn modelled_closed_owner_oversized_native_journal_refuses_before_read_allocation(){
  let(root,user,b,_)=super::setup();let path=root.join("synthetic-signers.sqlite");let guard=root.join("synthetic-certifier.guard");let sidecar=root.join("synthetic-signers.sqlite-journal");create_new_private_leaf(&sidecar,&user).unwrap();
  let file=std::fs::OpenOptions::new().write(true).open(&sidecar).unwrap();file.set_len(256*1024*1024+1).unwrap();drop(file);
  assert!(FrozenInspection::capture_with_modelled_closed_owner(&path,&guard,&user,&b,expected()).is_err());assert_eq!(std::fs::metadata(&sidecar).unwrap().len(),256*1024*1024+1);assert_eq!(std::fs::metadata(&path).unwrap().len(),0);
 }
}
