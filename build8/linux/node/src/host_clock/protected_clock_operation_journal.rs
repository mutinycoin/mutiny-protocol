//! Private append-only operation/outcome contract. Decoding never authenticates
//! ownership or qualifies a clock. Native existing-only held journal I/O and
//! durable ordered dispatch must retain this history before ordinary RPC opens.
#![allow(dead_code)]
use super::protected_clock_lineage_v1::{Begin,DocumentaryEngine,Operation,Plan,Request,Scope,Snapshot,SNAPSHOT_MAX};
use sha2::{Digest,Sha256};
use std::{collections::HashMap,io::Read};
type Hash=[u8;32];
type Result<T>=std::result::Result<T,String>;
const HEADER:&[u8;8]=b"MCLJRN01";
const FRAME:&[u8;8]=b"MCLJRF01";
const HEADER_LEN:usize=40;
// Local fixed-shape allocation bound; no consensus quota, cadence or TTL.
const BODY_MAX:usize=4+2*SNAPSHOT_MAX;
const PREFIX_LEN:usize=11;
const DIGEST_LEN:usize=32;

pub(super) struct JournalPlan {operation:Operation,request:Request,plan:Plan}
impl JournalPlan {
    pub(super) fn from_current(scope:&Scope,before:&[u8],request:Request)->Result<Self> {
        let operation=request.operation().ok_or("journal request lacks operation identity")?.clone();
        let mut document=DocumentaryEngine::from_document(scope,before).map_err(|e|format!("journal before: {e:?}"))?;
        let plan=match document.begin(request.clone()).map_err(|e|format!("journal request: {e:?}"))? {
            Begin::Plan(plan)=>plan,
            Begin::ExactLastRetry(_)=>return Err("existing operation must resolve from journal, not append".into()),
        };
        Ok(Self{operation,request,plan})
    }
    pub(super) fn operation(&self)->&Operation {&self.operation}
    pub(super) fn request(&self)->&Request {&self.request}
    pub(super) fn before(&self)->Vec<u8> {self.plan.before()}
    pub(super) fn intent_head(&self)->Vec<u8> {self.plan.intent()}
    pub(super) fn completion_head(&self)->Vec<u8> {self.plan.completion()}
    pub(super) fn intent_frame(&self)->Vec<u8> {
        let before=self.before();let request=self.request.encode();let mut body=Vec::new();
        body.extend_from_slice(&(before.len() as u16).to_be_bytes());body.extend_from_slice(&before);
        body.extend_from_slice(&(request.len() as u16).to_be_bytes());body.extend_from_slice(&request);
        frame(0,&body)
    }
    pub(super) fn completion_frame(&self)->Vec<u8> {
        let after=self.completion_head();let mut body=Vec::new();
        body.extend_from_slice(&self.operation.identity());body.extend_from_slice(&self.operation.content());
        body.extend_from_slice(&(after.len() as u16).to_be_bytes());body.extend_from_slice(&after);
        frame(1,&body)
    }
}
fn frame(kind:u8,body:&[u8])->Vec<u8> {
    let mut raw=Vec::with_capacity(PREFIX_LEN+body.len()+DIGEST_LEN);
    raw.extend_from_slice(FRAME);raw.push(kind);raw.extend_from_slice(&(body.len() as u16).to_be_bytes());
    raw.extend_from_slice(body);let digest:Hash=Sha256::digest(&raw).into();raw.extend_from_slice(&digest);raw
}
pub(super) fn installed_header_document(scope:&Scope)->Vec<u8> {
    let mut header=HEADER.to_vec();header.extend_from_slice(&scope.journal_context());header
}
#[derive(Clone)]
pub(super) struct JournalReply {operation:Operation,pub(super) sequence:u64,pub(super) floor:u64}
pub(super) struct JournalStatus {
    completed:HashMap<Hash,JournalReply>,pub(super) pending:Option<JournalPlan>,
    pub(super) sequence:u64,pub(super) floor:u64,
}
impl JournalStatus {
    pub(super) fn lookup(&self,operation:&Operation)->Result<Option<JournalReply>> {
        if self.pending.is_some() {return Err("unresolved journal intent freezes both new and retry admission".into());}
        match self.completed.get(&operation.identity()) {
            Some(record) if record.operation.content()!=operation.content()=>Err("journal operation identifier conflicts".into()),
            Some(record)=>Ok(Some(record.clone())),None=>Ok(None),
        }
    }
}
fn read_exact<R:Read>(reader:&mut R,bytes:&mut [u8])->Result<()> {
    reader.read_exact(bytes).map_err(|e|format!("journal truncated/read outcome: {e}"))
}
struct Cursor<'a>{bytes:&'a[u8],at:usize}
impl<'a> Cursor<'a> {
    fn take(&mut self,length:usize)->Result<&'a[u8]> {
        let end=self.at.checked_add(length).ok_or("journal field length")?;
        let raw=self.bytes.get(self.at..end).ok_or("journal field truncated")?;self.at=end;Ok(raw)
    }
    fn length(&mut self)->Result<usize> {Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_|"journal length")?) as usize)}
    fn hash(&mut self)->Result<Hash> {self.take(32)?.try_into().map_err(|_|"journal identity".into())}
    fn end(&self)->Result<()> {if self.at==self.bytes.len(){Ok(())}else{Err("journal trailing field".into())}}
}
/// Scan exactly the native-held length. Every body is bounded before allocation;
/// history index growth uses fallible reserve. Partial tails, conflict/duplicate
/// IDs and divergent completions refuse; no truncation/recycling/reset follows.
pub(super) fn scan<R:Read>(scope:&Scope,reader:&mut R,bytes:u64)->Result<JournalStatus> {
    if bytes<HEADER_LEN as u64 {return Err("installed journal header missing".into());}
    let mut header=[0;HEADER_LEN];read_exact(reader,&mut header)?;
    if header.as_slice()!=installed_header_document(scope).as_slice() {return Err("journal scope/lineage differs".into());}
    let mut remaining=bytes-HEADER_LEN as u64;
    let mut status=JournalStatus{completed:HashMap::new(),pending:None,sequence:0,floor:0};
    while remaining!=0 {
        if remaining<(PREFIX_LEN+DIGEST_LEN) as u64 {return Err("partial journal frame".into());}
        let mut prefix=[0;PREFIX_LEN];read_exact(reader,&mut prefix)?;
        if &prefix[..8]!=FRAME {return Err("journal frame format".into());}
        let length=u16::from_be_bytes([prefix[9],prefix[10]]) as usize;
        if length>BODY_MAX || length==0 || (PREFIX_LEN+length+DIGEST_LEN) as u64>remaining {
            return Err("journal frame bound/truncated".into());
        }
        let mut body=Vec::new();body.try_reserve_exact(length).map_err(|_|"journal body allocation refused")?;
        body.resize(length,0);read_exact(reader,&mut body)?;
        let mut digest=[0;DIGEST_LEN];read_exact(reader,&mut digest)?;
        let mut hash=Sha256::new();hash.update(prefix);hash.update(&body);
        if <Hash>::from(hash.finalize())!=digest {return Err("journal frame commitment differs".into());}
        let mut cursor=Cursor{bytes:&body,at:0};
        match prefix[8] {
            0=>{
                if status.pending.is_some() {return Err("journal has competing unresolved intents".into());}
                let before_length=cursor.length()?;
                if before_length>SNAPSHOT_MAX {return Err("journal before bound".into());}
                let before=cursor.take(before_length)?;
                let request_length=cursor.length()?;
                if request_length>SNAPSHOT_MAX {return Err("journal request bound".into());}
                let request=Request::decode(cursor.take(request_length)?).map_err(|e|format!("journal request: {e:?}"))?;
                cursor.end()?;
                let before_snapshot=Snapshot::decode(before).map_err(|e|format!("journal before: {e:?}"))?;
                if before_snapshot.sequence()<status.sequence || before_snapshot.floor()<status.floor {
                    return Err("journal prior floor/sequence regressed".into());
                }
                let plan=JournalPlan::from_current(scope,before,request)?;
                if status.completed.contains_key(&plan.operation.identity()) {return Err("journal repeats consumed operation identity".into());}
                let reserved=Snapshot::decode(&plan.intent_head()).map_err(|e|format!("journal reserved floor: {e:?}"))?;
                status.sequence=reserved.sequence();status.floor=reserved.floor();
                status.pending=Some(plan);
            },
            1=>{
                let operation=Operation::authenticated_document(cursor.hash()?,cursor.hash()?)
                    .map_err(|e|format!("journal completion operation: {e:?}"))?;
                let after_length=cursor.length()?;
                if after_length>SNAPSHOT_MAX {return Err("journal completion bound".into());}
                let after=cursor.take(after_length)?;cursor.end()?;
                let pending=status.pending.as_ref().ok_or("journal completion has no matching intent")?;
                if pending.operation!=operation || after!=pending.completion_head() {
                    return Err("journal completion differs from exact authorized transition".into());
                }
                let snapshot=Snapshot::decode(after).map_err(|e|format!("journal completion: {e:?}"))?;
                status.completed.try_reserve(1).map_err(|_|"journal history index allocation refused")?;
                let reply=JournalReply{operation:operation.clone(),sequence:snapshot.sequence(),floor:snapshot.floor()};
                if status.completed.insert(operation.identity(),reply).is_some() {return Err("journal repeated completion".into());}
                status.sequence=snapshot.sequence();status.floor=snapshot.floor();status.pending=None;
            },
            _=>return Err("journal frame kind refused".into()),
        }
        remaining-=(PREFIX_LEN+length+DIGEST_LEN) as u64;
    }
    let mut extra=[0];
    if reader.read(&mut extra).map_err(|e|e.to_string())?!=0 {return Err("journal grew past held length".into());}
    Ok(status)
}
