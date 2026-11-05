//! Four scripted I/O models required by the A2 child-output contract.
//! No native process, durable storage or activation qualification credit.
#[path="support/a2_native/process_output.rs"]
mod process_output;
use std::{collections::VecDeque, io::{self,Read,Write}};
use process_output::{drain,DurableOutput};
use sha2::{Digest,Sha256};

enum Step { Data(&'static [u8]), Error(io::ErrorKind), Eof }
struct Script(VecDeque<Step>);
impl Read for Script {
    fn read(&mut self, output:&mut [u8])->io::Result<usize> {
        match self.0.pop_front().expect("recorder read beyond exact scripted EOF/error") {
            Step::Data(data)=>{assert!(data.len()<=output.len());output[..data.len()].copy_from_slice(data);Ok(data.len())},
            Step::Error(kind)=>Err(io::Error::new(kind,"public modeled pipe error")),
            Step::Eof=>Ok(0),
        }
    }
}
#[derive(Default)]
struct Sink { remaining:Option<usize> }
impl Write for Sink {
    fn write(&mut self,data:&[u8])->io::Result<usize> {
        match self.remaining {
            Some(0)=>Err(io::Error::other("public modeled log failure")),
            Some(n)=>{let wrote=n.min(data.len());self.remaining=Some(n-wrote);Ok(wrote)},
            None=>Ok(data.len()),
        }
    }
    fn flush(&mut self)->io::Result<()> {Ok(())}
}
impl DurableOutput for Sink {fn sync_output(&mut self)->io::Result<()> {Ok(())}}
fn scripted(steps:Vec<Step>,fail_write:bool)->serde_json::Value {
    drain(Script(steps.into()),Sink {remaining:if fail_write {Some(0)}else{None}})
}
#[test]
fn child_noninterrupted_read_error_tail_eof() {
    let r=scripted(vec![Step::Data(b"prefix"),Step::Error(io::ErrorKind::Other),Step::Data(b"tail"),Step::Eof],false);
    assert_eq!(r["total_bytes"],6);assert_eq!(r["retained_bytes"],6);
    assert_eq!(r["total_sha256"],hex::encode(Sha256::digest(b"prefix")));
    assert_eq!(r["eof"],false);assert_eq!(r["hash_complete"],false);
    assert_eq!(r["stream_status"],"ERROR_UNKNOWN");assert_eq!(r["null_tail_bytes"],4);
    assert_eq!(r["null_tail_eof"],true);assert_eq!(r["null_tail_error"],false);
    assert_eq!(r["errors"].as_array().unwrap().len(),1);
}
#[test]
fn child_noninterrupted_read_error_tail_error() {
    let r=scripted(vec![Step::Error(io::ErrorKind::BrokenPipe),Step::Data(b"tail"),Step::Error(io::ErrorKind::Other)],false);
    assert_eq!(r["eof"],false);assert_eq!(r["hash_complete"],false);
    assert_eq!(r["null_tail_bytes"],4);assert_eq!(r["null_tail_eof"],false);
    assert_eq!(r["null_tail_error"],true);assert_eq!(r["stream_status"],"ERROR_UNKNOWN");
    assert_eq!(r["errors"].as_array().unwrap().len(),2);
}
#[test]
fn child_interrupted_then_exact_eof() {
    let r=scripted(vec![Step::Error(io::ErrorKind::Interrupted),Step::Data(b"exact"),Step::Eof],false);
    assert_eq!(r["eof"],true);assert_eq!(r["hash_complete"],true);
    assert_eq!(r["total_bytes"],5);assert_eq!(r["retained_bytes"],5);
    assert_eq!(r["total_sha256"],hex::encode(Sha256::digest(b"exact")));
    assert_eq!(r["null_tail_attempted"],false);assert!(r["errors"].as_array().unwrap().is_empty());
}
#[test]
fn child_log_write_error_continues_reads() {
    let r=scripted(vec![Step::Data(b"first"),Step::Data(b"second"),Step::Eof],true);
    assert_eq!(r["eof"],true);assert_eq!(r["hash_complete"],true);
    assert_eq!(r["total_bytes"],11);assert_eq!(r["retained_bytes"],0);
    assert_eq!(r["total_sha256"],hex::encode(Sha256::digest(b"firstsecond")));
    assert_eq!(r["errors"].as_array().unwrap().len(),1);
    // Native caller additionally requires an empty error list before accepting.
    assert!(!r["errors"].as_array().unwrap().is_empty());
    let partial=drain(Script(vec![Step::Data(b"first"),Step::Data(b"second"),Step::Eof].into()),Sink {remaining:Some(3)});
    assert_eq!(partial["retained_bytes"],3);assert_eq!(partial["total_bytes"],11);
    assert_eq!(partial["eof"],true);assert_eq!(partial["hash_complete"],true);
    assert_eq!(partial["errors"].as_array().unwrap().len(),1);
}
