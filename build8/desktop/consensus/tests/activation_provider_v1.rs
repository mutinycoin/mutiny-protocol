#![cfg(feature="dividend-test-fixtures")]
//! Own-Genesis replay provider boundary on real certified TEST blocks. This
//! fixture's initial model is synthetic; no physical activation is asserted.
#[path="../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path="support/wallet_host_fixture_tpm.rs"]
mod tpm;
include!("support/dividend_rig.rs");
#[test]
fn own_activation_parent_certified_chain_reopen_and_stale_parent_refusal(){
    let mut r=Rig::new(fixture(),"activation-provider-positive");
    let old=r.parent.clone();let (_,initial)=r.chain.verified_activation_parent(&old).unwrap();
    assert_eq!(initial.root().unwrap(),r.initial_root);
    r.step(1,&[]);
    assert!(r.chain.verified_activation_parent(&old).is_err());
    let expected=r.parent.clone();let (authority,current)=r.chain.verified_activation_parent(&expected).unwrap();
    assert_eq!(authority.parent,expected);assert_eq!(current.root().unwrap(),r.state.root().unwrap());
    let r=r.restart();let (authority,current)=r.chain.verified_activation_parent(&expected).unwrap();
    assert_eq!(authority.parent,expected);assert_eq!(current.root().unwrap(),r.state.root().unwrap());
    // Preserve even successful public fixtures for independently indexed replay.
    println!("PUBLIC activation provider fixture: {}",r.base.display());
}
#[test]
fn own_activation_parent_missing_executed_history_refuses_without_repair(){
    let mut r=Rig::new(fixture(),"activation-provider-missing-history");r.step(1,&[]);
    r.chain.verified_activation_parent(&r.parent).unwrap();
    let db=rusqlite::Connection::open(r.base.join("chain.sqlite")).unwrap();
    let raw:Vec<u8>=db.query_row("SELECT envelope FROM evidence_v2 WHERE height=?1",
        [1u64.to_be_bytes().as_slice()],|row|row.get(0)).unwrap();
    // Original actual certified bytes retained before the owned negative edit.
    use std::io::Write;
    let mut saved=std::fs::OpenOptions::new().create_new(true).write(true)
        .open(r.base.join("evidence-before-negative.public.bin")).unwrap();saved.write_all(&raw).unwrap();drop(saved);
    assert_eq!(db.execute("DELETE FROM evidence_v2 WHERE height=?1",[1u64.to_be_bytes().as_slice()]).unwrap(),1);
    let before:Vec<u8>=db.query_row("SELECT root FROM canonical_v2 WHERE height=?1",
        [1u64.to_be_bytes().as_slice()],|row|row.get(0)).unwrap();
    assert!(r.chain.verified_activation_parent(&r.parent).is_err());
    let after:Vec<u8>=db.query_row("SELECT root FROM canonical_v2 WHERE height=?1",
        [1u64.to_be_bytes().as_slice()],|row|row.get(0)).unwrap();
    assert_eq!(before,after);
    assert_eq!(db.query_row::<u64,_,_>("SELECT COUNT(*) FROM evidence_v2 WHERE height=?1",
        [1u64.to_be_bytes().as_slice()],|row|row.get(0)).unwrap(),0);
    println!("PUBLIC activation provider negative fixture: {}",r.base.display());
}
