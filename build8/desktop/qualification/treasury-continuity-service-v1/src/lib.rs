//! Public-evidence SQLite durability probe, not an authenticated service.
//! It cannot mint consensus Provider authority or enable Production. Its caller
//! must be a modeled/reviewed authenticated verifier which has already performed
//! native descriptor/proof checks. Real administrator/restore separation and
//! OS-handle SQLite VFS safety remain deployment requirements.
use mutiny_consensus_v8::{Hash,treasury_continuity_v1::{Engine,Error as ModelError,Request,Receipt,Scope},
    treasury_continuity_provider_v1::{PublicSnapshot,MAX_HISTORY,encode_receipt,decode_receipt}};
use rusqlite::{Connection,OpenFlags,TransactionBehavior,params};
use std::path::Path;
const META:&str="CREATE TABLE continuity_meta(id INTEGER PRIMARY KEY CHECK(id=1), scope BLOB NOT NULL CHECK(typeof(scope)='blob'))";
const OPERATIONS:&str="CREATE TABLE continuity_operations(sequence INTEGER PRIMARY KEY CHECK(sequence>0 AND sequence<=4096), operation BLOB NOT NULL UNIQUE CHECK(typeof(operation)='blob' AND length(operation)=32), request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)>0 AND length(request)<=8192), receipt BLOB NOT NULL CHECK(typeof(receipt)='blob' AND length(receipt)>0 AND length(receipt)<=1024))";
#[derive(Debug,PartialEq,Eq)]
pub enum Error { Model(ModelError),Storage,Unknown,Scope,Corrupt,Exists,Path }
impl From<ModelError> for Error{fn from(error:ModelError)->Self{Self::Model(error)}}
fn storage<T>(value:rusqlite::Result<T>)->Result<T,Error>{value.map_err(|_|Error::Storage)}
type Objects=Vec<(String,String,Option<String>)>;
fn objects(db:&Connection)->Result<Objects,Error>{
    let bad:i64=storage(db.query_row("SELECT count(*) FROM sqlite_schema WHERE length(type)>32 OR length(name)>128 OR length(sql)>4096",[],|row|row.get(0)))?;
    if bad!=0{return Err(Error::Corrupt);}
    let mut statement=storage(db.prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY name"))?;
    storage(storage(statement.query_map([],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))))?.collect())
}
fn expected_objects()->Result<Objects,Error>{
    let db=storage(Connection::open_in_memory())?;storage(db.execute_batch(&format!("{META};{OPERATIONS};")))?;objects(&db)
}
fn scope_bytes(scope:&Scope)->Result<Vec<u8>,Error>{Ok(PublicSnapshot::new(scope.clone(),[1;32],0,None,Vec::new())?.encode()?)}
fn verify_schema(db:&Connection,scope:&Scope)->Result<(),Error>{
    if objects(db)?!=expected_objects()?{return Err(Error::Corrupt);}
    let count:i64=storage(db.query_row("SELECT count(*) FROM continuity_meta",[],|row|row.get(0)))?;
    let bad:i64=storage(db.query_row("SELECT count(*) FROM continuity_meta WHERE typeof(scope)!='blob' OR length(scope)>1024 OR length(scope)=0",[],|row|row.get(0)))?;
    if count!=1||bad!=0{return Err(Error::Corrupt);}
    let actual:Vec<u8>=storage(db.query_row("SELECT scope FROM continuity_meta WHERE id=1",[],|row|row.get(0)))?;
    if count!=1||actual!=scope_bytes(scope)?{return Err(Error::Scope);}Ok(())
}
fn configure(db:&Connection)->Result<(),Error>{
    storage(db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA;"))?;
    let mode:String=storage(db.pragma_query_value(None,"journal_mode",|row|row.get(0)))?;
    let sync:i64=storage(db.pragma_query_value(None,"synchronous",|row|row.get(0)))?;
    let trusted:i64=storage(db.pragma_query_value(None,"trusted_schema",|row|row.get(0)))?;
    if mode!="delete"||sync!=3||trusted!=0{return Err(Error::Storage);}Ok(())
}
/// Does not imply authentication/antirollback. Real qualification daemon routing
/// is deliberately absent. Only public challenge/descriptor/signature evidence is
/// stored. Every original canonical request and original NEW receipt is retained.
pub struct DurableService { db:Connection,scope:Scope,
    #[cfg(test)] fault:Option<Fault>,
}
impl DurableService {
    /// TEST-only controlled private directory required. Never overwrite an old DB.
    /// Existing unsafe state is not repaired or migrated. This path-based SQLite
    /// probe does not solve same-account/admin substitution or power-loss safety.
    pub fn create(path:&Path,scope:Scope)->Result<Self,Error>{
        check_path(path)?;Engine::new(scope.clone())?;
        std::fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|error|
            if error.kind()==std::io::ErrorKind::AlreadyExists{Error::Exists}else{Error::Path})?;
        let mut db=storage(Connection::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_WRITE|OpenFlags::SQLITE_OPEN_NO_MUTEX))?;
        configure(&db)?;
        let tx=storage(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if !objects(&tx)?.is_empty(){return Err(Error::Corrupt);}
        storage(tx.execute_batch(&format!("{META};{OPERATIONS};")))?;
        storage(tx.execute("INSERT INTO continuity_meta VALUES(1,?1)",[scope_bytes(&scope)?]))?;
        tx.commit().map_err(|_|Error::Unknown)?;
        Ok(Self{db,scope,#[cfg(test)]fault:None})
    }
    pub fn open(path:&Path,scope:Scope)->Result<Self,Error>{
        check_path(path)?;Engine::new(scope.clone())?;
        let preflight=storage(Connection::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_ONLY|OpenFlags::SQLITE_OPEN_NO_MUTEX))?;
        {let snapshot=storage(preflight.unchecked_transaction())?;load(&snapshot,&scope)?;
            snapshot.commit().map_err(|_|Error::Unknown)?;}
        drop(preflight);
        // Deliberately no claimed VFS pin: real production service adapter is off.
        let db=storage(Connection::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_WRITE|OpenFlags::SQLITE_OPEN_NO_MUTEX))?;
        {let snapshot=storage(db.unchecked_transaction())?;load(&snapshot,&scope)?;
            snapshot.commit().map_err(|_|Error::Unknown)?;}
        configure(&db)?;
        Ok(Self{db,scope,#[cfg(test)]fault:None})
    }
    pub fn scope(&self)->&Scope{&self.scope}
    /// A fresh query against one consistent transaction, still PUBLIC/untrusted.
    /// Transport authentication + current linearizable trust are not supplied here.
    pub fn current(&mut self,nonce:Hash)->Result<PublicSnapshot,Error>{
        let tx=storage(self.db.transaction_with_behavior(TransactionBehavior::Deferred))?;
        let engine=load(&tx,&self.scope)?;
        let value=PublicSnapshot::new(self.scope.clone(),nonce,engine.sequence(),engine.pending_operation(),engine.history())?;
        tx.commit().map_err(|_|Error::Unknown)?;Ok(value)
    }
    pub fn apply(&mut self,request:&Request)->Result<Receipt,Error>{
        self.apply_with_snapshot(request).map(|(receipt,_)|receipt)
    }
    /// Exact receipt and complete state share the same Immediate transaction.
    /// Authentication signs this pair only after commit. Never query a second
    /// head and pretend it was atomic with this transition's acknowledgement.
    pub fn apply_with_snapshot(&mut self,request:&Request)->Result<(Receipt,PublicSnapshot),Error>{
        // Validate exact codec/action BEFORE opening the service transaction.
        let wire=request.encode()?;if request.scope!=self.scope{return Err(Error::Scope);}
        let tx=storage(self.db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut candidate=load(&tx,&self.scope)?;let receipt=candidate.apply(request)?;
        mutiny_consensus_v8::treasury_continuity_v1::check_receipt(request,&receipt)?;
        if !receipt.repeated{
            storage(tx.execute("INSERT INTO continuity_operations VALUES(?1,?2,?3,?4)",params![
                receipt.operation_sequence as i64,request.operation.as_slice(),wire,encode_receipt(&receipt)?]))?;
        }
        let snapshot=PublicSnapshot::new(self.scope.clone(),request.request_nonce,candidate.sequence(),
            candidate.pending_operation(),candidate.history())?;
        #[cfg(test)]
        let fault=self.fault.take();
        #[cfg(test)]
        if fault==Some(Fault::BeforeCommit){return Err(Error::Storage);}
        tx.commit().map_err(|_|Error::Unknown)?;
        #[cfg(test)]
        if fault==Some(Fault::AfterCommit){return Err(Error::Unknown);}
        // Publication/ACK strictly after commit. No mutable cache survives a
        // failed commit; next request replays the actual durable transaction.
        Ok((receipt,snapshot))
    }
}
/// Nonshipping software endpoint under explicitly supplied public pins. This
/// constructor does NOT enroll a trusted identity or establish independent
/// administration/antirollback. No daemon or production route calls it.
pub struct QualificationEndpoint {
    service:DurableService,
    pins:mutiny_consensus_v8::treasury_continuity_provider_v1::authenticated_wire::PublicPins,
    key:mutiny_crypto_v2::HybridKey,
}
#[derive(Debug,PartialEq,Eq)]
pub enum EndpointError {Service(Error),Authentication(mutiny_consensus_v8::treasury_continuity_provider_v1::ProviderError)}
impl QualificationEndpoint {
    pub fn new(service:DurableService,
        pins:mutiny_consensus_v8::treasury_continuity_provider_v1::authenticated_wire::PublicPins,
        key:mutiny_crypto_v2::HybridKey)->Result<Self,EndpointError>{
        use mutiny_consensus_v8::treasury_continuity_provider_v1::ProviderError;
        if service.scope()!=pins.scope(){return Err(EndpointError::Authentication(ProviderError::Context));}
        let (_,generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(pins.service_descriptor())
            .map_err(|_|EndpointError::Authentication(ProviderError::Authentication))?;
        if key.public().descriptor(generation).map_err(|_|EndpointError::Authentication(ProviderError::Authentication))?
            !=pins.service_descriptor(){return Err(EndpointError::Authentication(ProviderError::Authentication));}
        Ok(Self{service,pins,key})
    }
    pub fn handle(&mut self,raw:&[u8])->Result<Vec<u8>,EndpointError>{
        use mutiny_consensus_v8::treasury_continuity_provider_v1::authenticated_wire::{VerifiedClientRequest,ClientAction};
        let verified=VerifiedClientRequest::verify(&self.pins,raw).map_err(EndpointError::Authentication)?;
        let (receipt,snapshot)=match verified.action(){
            ClientAction::Current{request_nonce,..}=>(None,self.service.current(*request_nonce).map_err(EndpointError::Service)?),
            ClientAction::Transition(request)=>{
                let(receipt,snapshot)=self.service.apply_with_snapshot(request).map_err(EndpointError::Service)?;
                (Some(receipt),snapshot)
            }
        };
        // Every signature occurs AFTER actual durable commit/read snapshot. A
        // signing or send failure cannot undo an already consumed operation.
        verified.sign_committed(&self.pins,&self.key,&snapshot,receipt.as_ref()).map_err(EndpointError::Authentication)
    }
}
fn check_path(path:&Path)->Result<(),Error>{
    if !path.is_absolute(){return Err(Error::Path);}
    let parent=path.parent().ok_or(Error::Path)?;
    if !parent.is_dir(){return Err(Error::Path);}
    if mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(parent).map_err(|_|Error::Path)?{
        // Existing parent required; do not provision storage implicitly here.
        return Err(Error::Path);
    }
    if let Ok(meta)=std::fs::symlink_metadata(path){if meta.file_type().is_symlink()||!meta.is_file(){return Err(Error::Path);}}
    Ok(())
}
fn load(db:&Connection,scope:&Scope)->Result<Engine,Error>{
    // Bounds and fetches must observe the same snapshot, including open checks.
    if db.is_autocommit(){return Err(Error::Corrupt);}
    verify_schema(db,scope)?;
    // CHECK declarations alone do not establish trustworthy BLOB bounds: a
    // hostile writer can bypass them, or the file can be corrupt. Inspect SQL
    // storage lengths/types BEFORE constructing any Vec from a retained row.
    let count:i64=storage(db.query_row("SELECT count(*) FROM (SELECT 1 FROM continuity_operations LIMIT 4097)",[],|row|row.get(0)))?;
    if !(0..=MAX_HISTORY as i64).contains(&count){return Err(Error::Corrupt);}
    let bad:i64=storage(db.query_row("SELECT count(*) FROM continuity_operations WHERE typeof(operation)!='blob' OR length(operation)!=32 OR typeof(request)!='blob' OR length(request)=0 OR length(request)>8192 OR typeof(receipt)!='blob' OR length(receipt)=0 OR length(receipt)>1024",[],|row|row.get(0)))?;
    if bad!=0{return Err(Error::Corrupt);}
    let mut engine=Engine::new(scope.clone())?;
    let mut statement=storage(db.prepare("SELECT sequence,operation,request,receipt FROM continuity_operations ORDER BY sequence LIMIT 4097"))?;
    let mut rows=storage(statement.query([]))?;let mut count=0usize;
    while let Some(row)=storage(rows.next())?{
        count+=1;if count>MAX_HISTORY{return Err(Error::Corrupt);}
        let sequence:i64=storage(row.get(0))?;let operation:Vec<u8>=storage(row.get(1))?;
        let wire:Vec<u8>=storage(row.get(2))?;let ack:Vec<u8>=storage(row.get(3))?;
        if sequence!=count as i64 || operation.len()!=32{return Err(Error::Corrupt);}
        let request=Request::decode(&wire)?;if request.scope!=*scope || request.operation.as_slice()!=operation{return Err(Error::Corrupt);}
        let receipt=engine.apply(&request)?;
        if receipt.repeated||receipt.operation_sequence!=count as u64||receipt!=decode_receipt(&ack)?{return Err(Error::Corrupt);}
    }
    Ok(engine)
}
#[cfg(test)]
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Fault{BeforeCommit,AfterCommit}
#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_consensus_v8::treasury_continuity_v1::{Action,PublicRecord,Outcome};
    fn scope()->Scope{Scope{network:1,genesis:Some([1;32]),ceremony_context:[2;32],treasury_record:[3;32],verifier:[4;32],store:[5;32],service:[6;32]}}
    fn fixture()->(std::path::PathBuf,DurableService){
        let mut salt=[0;32];mutiny_crypto_v2::fill_os_random(&mut salt).unwrap();
        let suffix=salt.iter().map(|b|format!("{b:02x}")).collect::<String>();
        let parent=std::env::temp_dir().join(format!("treasury-continuity-service-public-{suffix}"));
        assert!(mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&parent).unwrap());
        let path=parent.join("continuity.sqlite");let service=DurableService::create(&path,scope()).unwrap();
        println!("PUBLIC TEST service evidence retained: {}",parent.display());(path,service)
    }
    fn record()->PublicRecord{PublicRecord{generation:1,nonce:[7;32],challenge:vec![8;300],descriptor:vec![9;1900],signature:None}}
    fn request(id:u8,sequence:u64,action:Action)->Request{Request{scope:scope(),operation:[id;32],request_nonce:[id+1;32],expected_sequence:sequence,action}}
    fn authenticated_fixture()->(std::path::PathBuf,Scope,
        mutiny_consensus_v8::treasury_continuity_provider_v1::authenticated_wire::PublicPins,
        mutiny_crypto_v2::HybridKey,mutiny_crypto_v2::HybridKey){
        use mutiny_crypto_v2::{HybridKey,Role};
        let client=HybridKey::generate(Role::Transport).unwrap();let server=HybridKey::generate(Role::Transport).unwrap();
        let mut scoped=scope();scoped.network=mutiny_crypto_v2::NETWORK;
        let pins=mutiny_consensus_v8::treasury_continuity_provider_v1::authenticated_wire::PublicPins::new(scoped.clone(),[90;32],
            client.public().descriptor(1).unwrap(),server.public().descriptor(2).unwrap()).unwrap();
        let mut salt=[0;32];mutiny_crypto_v2::fill_os_random(&mut salt).unwrap();
        let suffix=salt.iter().map(|b|format!("{b:02x}")).collect::<String>();
        let parent=std::env::temp_dir().join(format!("treasury-authenticated-public-{suffix}"));
        assert!(mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&parent).unwrap());
        println!("PUBLIC TEST authenticated service evidence retained: {}",parent.display());
        (parent.join("continuity.sqlite"),scoped,pins,client,server)
    }
    #[test]
    fn real_crypto_local_endpoint_commits_before_ack_and_identical_retry_reopens_exactly(){
        use mutiny_consensus_v8::treasury_continuity_provider_v1::authenticated_wire::{ClientSession,ClientAction};
        let(path,scoped,pins,client,server)=authenticated_fixture();
        let service=DurableService::create(&path,scoped.clone()).unwrap();
        let mut endpoint=QualificationEndpoint::new(service,pins.clone(),server).unwrap();
        // Public TEST model values only; not genuine Treasury proof validation.
        let mut first=request(70,0,Action::Reserve(record()));first.scope=scoped.clone();
        let session=ClientSession::prepare(&pins,&client,ClientAction::Transition(first.clone())).unwrap();
        endpoint.service.fault=Some(Fault::AfterCommit);
        assert_eq!(endpoint.handle(session.wire()),Err(EndpointError::Service(Error::Unknown)));
        let QualificationEndpoint{service,pins:old_pins,key}=endpoint;drop(service);
        let mut endpoint=QualificationEndpoint::new(DurableService::open(&path,scoped).unwrap(),old_pins,key).unwrap();
        let mut retry=first.clone();retry.request_nonce=[72;32];
        assert_eq!(retry.content_commitment().unwrap(),first.content_commitment().unwrap());
        let session=ClientSession::prepare(&pins,&client,ClientAction::Transition(retry.clone())).unwrap();
        let raw=endpoint.handle(session.wire()).unwrap();let(snapshot,receipt)=session.inspect_response(&pins,&raw,&[]).unwrap();
        assert!(receipt.unwrap().repeated);assert_eq!(snapshot.sequence(),1);
        let mut conflicting=retry;conflicting.action=Action::Reserve(record());
        if let Action::Reserve(v)=&mut conflicting.action{v.challenge[0]^=1;}
        let before=std::fs::read(&path).unwrap();
        let session=ClientSession::prepare(&pins,&client,ClientAction::Transition(conflicting)).unwrap();
        assert!(matches!(endpoint.handle(session.wire()),Err(EndpointError::Service(Error::Model(ModelError::Conflict)))));
        assert_eq!(std::fs::read(&path).unwrap(),before);
        let query=ClientSession::prepare(&pins,&client,ClientAction::Current{request_nonce:[73;32],minimum_sequence:1}).unwrap();
        let raw=endpoint.handle(query.wire()).unwrap();assert_eq!(query.inspect_response(&pins,&raw,snapshot.operations()).unwrap().0.sequence(),1);
    }
    #[test]
    fn authenticated_competing_requests_share_one_durable_head_and_exact_response_snapshot(){
        use mutiny_consensus_v8::treasury_continuity_provider_v1::authenticated_wire::{ClientSession,ClientAction,VerifiedClientRequest};
        use std::sync::{Arc,Barrier};
        let(path,scoped,pins,client,server)=authenticated_fixture();drop(DurableService::create(&path,scoped.clone()).unwrap());
        let mut a=request(80,0,Action::Reserve(record()));a.scope=scoped.clone();
        let mut b=request(82,0,Action::Reserve(record()));b.scope=scoped.clone();if let Action::Reserve(v)=&mut b.action{v.nonce=[83;32];}
        let sessions=[ClientSession::prepare(&pins,&client,ClientAction::Transition(a.clone())).unwrap(),
            ClientSession::prepare(&pins,&client,ClientAction::Transition(b.clone())).unwrap()];
        let verified=sessions.iter().map(|s|VerifiedClientRequest::verify(&pins,s.wire()).unwrap()).collect::<Vec<_>>();
        let barrier=Arc::new(Barrier::new(2));let mut joins=Vec::new();
        for req in [a,b]{let p=path.clone();let scope=scoped.clone();let barrier=barrier.clone();
            joins.push(std::thread::spawn(move||{let mut db=DurableService::open(&p,scope).unwrap();
                barrier.wait();db.apply_with_snapshot(&req)}));}
        let results=joins.into_iter().map(|j|j.join().unwrap()).collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|r|r.is_ok()).count(),1);
        assert_eq!(results.iter().filter(|r|matches!(r,Err(Error::Model(ModelError::Stale)))).count(),1);
        for ((session,verified),result) in sessions.into_iter().zip(verified).zip(results){
            if let Ok((receipt,snapshot))=result{
                let raw=verified.sign_committed(&pins,&server,&snapshot,Some(&receipt)).unwrap();
                assert_eq!(session.inspect_response(&pins,&raw,&[]).unwrap().0.sequence(),1);
            }
        }
        assert_eq!(DurableService::open(&path,scoped).unwrap().current([84;32]).unwrap().operations().len(),1);
    }
    #[test]
    fn committed_exact_terminal_history_survives_reopen_and_repeated_is_not_new(){
        let (path,mut service)=fixture();let reserve=request(10,0,Action::Reserve(record()));assert!(!service.apply(&reserve).unwrap().repeated);
        let confirm=request(12,1,Action::ConfirmLocal{pending_operation:reserve.operation,exact:record()});service.apply(&confirm).unwrap();
        let mut signed=record();signed.signature=Some(vec![11;1394]);let consume=request(14,2,Action::Consume(signed.clone()));
        let first=service.apply(&consume).unwrap();assert_eq!(first.outcome,Outcome::Consumed);drop(service);
        let mut reopened=DurableService::open(&path,scope()).unwrap();let snapshot=reopened.current([20;32]).unwrap();
        assert_eq!(snapshot.sequence(),3);assert_eq!(snapshot.pending_operation(),Some(consume.operation));
        let mut retry=consume.clone();retry.request_nonce=[21;32];let repeat=reopened.apply(&retry).unwrap();
        assert!(repeat.repeated);assert_eq!(repeat.operation_sequence,first.operation_sequence);
        reopened.apply(&request(22,3,Action::ConfirmLocal{pending_operation:consume.operation,exact:signed})).unwrap();
        let snapshot=reopened.current([23;32]).unwrap();assert_eq!(snapshot.sequence(),4);assert_eq!(snapshot.pending_operation(),None);
        assert!(matches!(reopened.apply(&request(24,4,consume.action)),Err(Error::Model(ModelError::Replay))));
        assert_eq!(reopened.current([25;32]).unwrap().operations().len(),4);
    }
    #[test]
    fn commit_boundaries_preserve_unknown_and_known_rollback_distinctly(){
        for fault in [Fault::BeforeCommit,Fault::AfterCommit]{
            let (path,mut service)=fixture();let reserve=request(30,0,Action::Reserve(record()));service.fault=Some(fault);
            let result=service.apply(&reserve);assert_eq!(result,Err(if fault==Fault::BeforeCommit{Error::Storage}else{Error::Unknown}));drop(service);
            let mut reopened=DurableService::open(&path,scope()).unwrap();let state=reopened.current([31;32]).unwrap();
            assert_eq!(state.sequence(),if fault==Fault::BeforeCommit{0}else{1});
            assert_eq!(reopened.apply(&reserve).unwrap().repeated,fault==Fault::AfterCommit);
        }
    }
    #[test]
    fn wrong_scope_conflicting_retry_and_corrupt_receipt_refuse_without_reset(){
        let (path,mut service)=fixture();let reserve=request(40,0,Action::Reserve(record()));service.apply(&reserve).unwrap();
        let mut conflict=reserve.clone();if let Action::Reserve(value)=&mut conflict.action{value.descriptor[0]^=1;}
        assert!(matches!(service.apply(&conflict),Err(Error::Model(ModelError::Conflict))));
        let mut wrong=scope();wrong.service[0]^=1;assert!(matches!(DurableService::open(&path,wrong),Err(Error::Scope)));
        let mut receipt=service.apply(&reserve).unwrap();receipt.repeated=false;receipt.content_commitment[0]^=1;
        storage(service.db.execute("UPDATE continuity_operations SET receipt=?1 WHERE sequence=1",[encode_receipt(&receipt).unwrap()])).unwrap();
        drop(service);assert!(matches!(DurableService::open(&path,scope()),Err(Error::Corrupt)));
        assert!(path.exists());
    }
    #[test]
    fn hostile_check_bypass_blobs_are_bounded_before_row_deserialization(){
        for (table,column,bytes,limit) in [("continuity_meta","scope",1025,1024),
            ("continuity_operations","request",8193,8192),("continuity_operations","receipt",1025,1024),
            ("continuity_operations","operation",33,32)]{
            let (path,mut service)=fixture();service.apply(&request(50,0,Action::Reserve(record()))).unwrap();
            service.db.execute_batch("PRAGMA ignore_check_constraints=ON").unwrap();
            let sql=format!("UPDATE {table} SET {column}=zeroblob(?1)");service.db.execute(&sql,[bytes]).unwrap();
            service.db.execute_batch("PRAGMA ignore_check_constraints=OFF").unwrap();
            let observed:i64=service.db.query_row(&format!("SELECT length({column}) FROM {table}"),[],|row|row.get(0)).unwrap();
            assert_eq!(observed,bytes);assert!(observed>limit);drop(service);
            assert!(matches!(DurableService::open(&path,scope()),Err(Error::Corrupt)));
            let retained=Connection::open_with_flags(&path,OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            let after:i64=retained.query_row(&format!("SELECT length({column}) FROM {table}"),[],|row|row.get(0)).unwrap();
            assert_eq!(after,bytes);assert!(path.exists());
        }
    }
}
