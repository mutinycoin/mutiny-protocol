//! MODELED tests of the newly implemented private operation journal contract.
//! This integration target does not compile the native-NTS library with
//! cfg(test): inherited node_service_tests/lib15 is not the selected target.
//! All inherited codec tests remain excluded from execution by exact selectors.
//! No native principal, filesystem, time/engine qualification or held credit.
#[path="../../node/src/host_clock/leap_policy.rs"] mod leap_policy;
#[path="../../node/src/host_clock/protected_clock_lineage_v1.rs"]
mod protected_clock_lineage_v1;
#[path="../../node/src/host_clock/protected_clock_operation_journal.rs"]
mod protected_clock_operation_journal;
#[cfg(target_os="linux")]
#[path="../../node/src/host_clock/protected_clock_linux_io.rs"]
mod protected_clock_linux_io;
use protected_clock_lineage_v1::{Operation,Request,Scope};
use protected_clock_operation_journal::{installed_header_document,scan,JournalPlan};
use std::io::Cursor;

fn scope()->Scope {Scope::selected_document([1;32],[2;32],[3;32],[4;32])}
fn initial()->Vec<u8> {
    // Explicit documentary fixture only; the actual native owner never creates
    // this from an IPC request or when an installed file is missing.
    let mut raw=b"MCLC4D01".to_vec();
    for byte in [1,2,3,4] {raw.extend_from_slice(&[byte;32]);}
    raw.extend_from_slice(&0u64.to_be_bytes());raw.extend_from_slice(&0u64.to_be_bytes());
    raw.push(0);raw.extend_from_slice(&0u16.to_be_bytes());raw
}
fn operation(identity:u8,content:u8)->Operation {
    Operation::authenticated_document([identity;32],[content;32]).unwrap()
}
fn plan(before:&[u8],sequence:u64,floor:u64,operation:Operation)->JournalPlan {
    JournalPlan::from_current(&scope(),before,
        Request::invalidate_operation_floor(sequence,floor,operation).unwrap()).unwrap()
}
#[test]
fn journal_new_owner_identity_history_conflict_and_lost_ack() {
    let first=operation(7,8);let second=operation(9,10);
    let a=plan(&initial(),0,12,first.clone());
    let b=plan(&a.completion_head(),1,19,second.clone());
    let mut raw=installed_header_document(&scope());
    for frame in [a.intent_frame(),a.completion_frame(),b.intent_frame(),b.completion_frame()] {
        raw.extend_from_slice(&frame);
    }
    let status=scan(&scope(),&mut Cursor::new(&raw),raw.len() as u64).unwrap();
    let old=status.lookup(&first).unwrap().unwrap();
    assert_eq!((old.sequence,old.floor),(1,12));
    let current=status.lookup(&second).unwrap().unwrap();
    assert_eq!((current.sequence,current.floor),(2,19));
    assert!(status.lookup(&operation(7,11)).is_err());
    assert!(status.lookup(&operation(12,13)).unwrap().is_none());
    // Same identity cannot be consumed again after unrelated head advancement.
    let duplicate=plan(&b.completion_head(),2,20,first);
    raw.extend_from_slice(&duplicate.intent_frame());
    assert!(scan(&scope(),&mut Cursor::new(&raw),raw.len() as u64).is_err());
}
#[test]
fn journal_new_owner_partial_intent_and_trailing_bytes_refuse() {
    let op=operation(7,8);let a=plan(&initial(),0,12,op.clone());
    let mut raw=installed_header_document(&scope());raw.extend_from_slice(&a.intent_frame());
    let status=scan(&scope(),&mut Cursor::new(&raw),raw.len() as u64).unwrap();
    assert!(status.pending.is_some());assert_eq!((status.sequence,status.floor),(1,12));
    assert!(status.lookup(&op).is_err());
    let completion=a.completion_frame();
    raw.extend_from_slice(&completion[..completion.len()-1]);
    assert!(scan(&scope(),&mut Cursor::new(&raw),raw.len() as u64).is_err());
    raw.push(completion[completion.len()-1]);
    assert!(scan(&scope(),&mut Cursor::new(&raw),raw.len() as u64).is_ok());
    raw.push(0);
    assert!(scan(&scope(),&mut Cursor::new(&raw),raw.len() as u64).is_err());
    assert!(scan(&scope(),&mut Cursor::new(&raw),u64::MAX).is_err());
}
#[test]
fn journal_new_owner_exact_completion_divergence_refuses() {
    let op=operation(7,8);
    let first=plan(&initial(),0,12,op.clone());
    let other=plan(&initial(),0,13,op);
    let mut raw=installed_header_document(&scope());
    raw.extend_from_slice(&first.intent_frame());raw.extend_from_slice(&other.completion_frame());
    assert!(scan(&scope(),&mut Cursor::new(&raw),raw.len() as u64).is_err());
    let wrong=Scope::selected_document([1;32],[2;32],[3;32],[5;32]);
    assert!(scan(&wrong,&mut Cursor::new(&raw),raw.len() as u64).is_err());
}
#[cfg(target_os="linux")]
#[test]
fn journal_new_linux_wrong_native_principal_refuses_before_state_open() {
    // Actual approved owner UID999 differs from this ordinary qualification
    // runner (mutinyadmin1000). No impersonation or account launcher is used.
    assert_eq!(unsafe{libc::getuid()},1000);
    assert_eq!(unsafe{libc::geteuid()},1000);
    let refusal=protected_clock_linux_io::LinuxLineageIo::open_existing(
        std::path::Path::new("/var/lib/mutiny-clock-qualification/owner/state"),999,995);
    match refusal {
        Err(reason)=>assert_eq!(reason,"dedicated clock-owner principal required"),
        Ok(_)=>panic!("ordinary qualification user obtained protected owner I/O"),
    }
}
#[cfg(target_os="linux")]
#[test]
fn journal_new_linux_same_native_principal_refuses_before_state_open() {
    let actual=unsafe{libc::getuid()};
    let refusal=protected_clock_linux_io::LinuxLineageIo::open_existing(
        std::path::Path::new("/var/lib/mutiny-clock-qualification/owner/state"),actual,actual);
    match refusal {
        Err(reason)=>assert_eq!(reason,"dedicated clock-owner principal required"),
        Ok(_)=>panic!("same-principal protected clock owner was accepted"),
    }
}
