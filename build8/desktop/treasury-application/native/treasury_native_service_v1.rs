//! SOURCE-ONLY nonshipping service implementation over the held native VFS.
//! Public pins/head artifacts do not enroll an administrator, authenticate a
//! restore checkpoint, mint Provider authority, or enable Production.
#![cfg(target_os="linux")]
use crate::{Hash, treasury_bounded_readers::{VmBudget,WorkSlot},
    protected_owner::{Owner as NativeOwner,Error as NativeError},
    treasury_rehearsal_v3::{CeremonyConfig,Refusal},
    treasury_continuity_v1::{Engine,Request,Receipt,Scope,Error as ModelError},
    treasury_continuity_provider_v1::{PublicSnapshot,ProviderError,MAX_HISTORY,
        encode_receipt,decode_receipt,authenticated_wire::{PublicPins,VerifiedClientRequest,ClientAction}}};
use mutiny_crypto_v2::{HybridKey,treasury_proof_v1::Phase};
use rusqlite::{Connection,Transaction,TransactionBehavior,params};
use std::{num::NonZeroU64,path::Path,sync::OnceLock};

const META:&str="CREATE TABLE continuity_meta(id INTEGER PRIMARY KEY CHECK(id=1), scope BLOB NOT NULL CHECK(typeof(scope)='blob'))";
const OPERATIONS:&str="CREATE TABLE continuity_operations(sequence INTEGER PRIMARY KEY CHECK(sequence>0 AND sequence<=4096), operation BLOB NOT NULL UNIQUE CHECK(typeof(operation)='blob' AND length(operation)=32), request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)>0 AND length(request)<=8192), receipt BLOB NOT NULL CHECK(typeof(receipt)='blob' AND length(receipt)>0 AND length(receipt)<=1024))";
#[derive(Debug,PartialEq,Eq)]
pub(crate) enum Error { Storage,Unknown,Context,Schema,History,ReadOnly,Model(ModelError),Authentication(ProviderError) }
impl From<ModelError> for Error {fn from(x:ModelError)->Self{Self::Model(x)}}
fn sql<T>(x:rusqlite::Result<T>)->Result<T,Error>{x.map_err(|_|Error::Storage)}
fn native(_:NativeError)->Error{Error::Storage}
/// Apply cannot distinguish a pre-callback boundary failure from an outer
/// post-callback boundary failure after durable commit. Conservatively UNKNOWN;
/// known callback refusals remain unchanged when the native boundary is healthy.
fn uncertain_apply_boundary(_:NativeError)->Error{Error::Unknown}
fn resource(_:Refusal)->Error{Error::Storage}
#[derive(Clone,Copy)]
pub(crate) struct Policy {file_cap:i64,steps:NonZeroU64}
impl Policy {
    pub(crate) fn new(file_cap:i64,steps:NonZeroU64)->Result<Self,Error>{
        if !(1..=32*1024*1024).contains(&file_cap){return Err(Error::Storage);}
        Ok(Self{file_cap,steps})
    }
}
fn selected(config:&CeremonyConfig,scope:&Scope)->Result<(),Error>{
    Engine::new(scope.clone())?;
    if config.phase()!=Phase::Rehearsal || config.class()!=crate::treasury_v1::Class::TestValue
        || scope.network!=config.network() || scope.ceremony_context!=config.context().value()
        || scope.treasury_record!=crate::treasury_rehearsal_v3::record_sha256(config.treasury()).map_err(resource)?
        || scope.genesis!=config.trusted_chain().map(|c|c.genesis){return Err(Error::Context);}
    Ok(())
}
fn scope_bytes(scope:&Scope)->Result<Vec<u8>,Error>{
    Ok(PublicSnapshot::new(scope.clone(),[1;32],0,None,Vec::new())?.encode()?)
}
type Objects=Vec<(String,String,Option<String>)>;
fn objects(db:&Connection)->Result<Objects,Error>{
    let mut q=sql(db.prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY name"))?;
    sql(sql(q.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))))?.collect())
}
fn expected()->Result<&'static Objects,Error>{
    static EXPECTED:OnceLock<Objects>=OnceLock::new();
    if let Some(value)=EXPECTED.get(){return Ok(value);}
    let db=sql(Connection::open_in_memory())?;sql(db.execute_batch(&format!("{META};{OPERATIONS};")))?;
    let value=objects(&db)?;Ok(EXPECTED.get_or_init(||value))
}
// Budget drops before the owned snapshot rollback, just like the Admission
// reader. Service schema/rows are separate: no nonexistent issued table query.
struct Window<'a>{db:&'a Connection,_budget:VmBudget<'a>,_snapshot:Option<Transaction<'a>>}
impl<'a> Window<'a>{
    fn start(db:&'a Connection,slot:&'a WorkSlot,steps:NonZeroU64)->Result<Self,Error>{
        let budget=VmBudget::install(db,slot,steps).map_err(resource)?;
        let snapshot=if db.is_autocommit(){Some(sql(db.unchecked_transaction())?)}else{None};
        Ok(Self{db,_budget:budget,_snapshot:snapshot})
    }
    fn scalar(&self,text:&str)->Result<i64,Error>{sql(self.db.query_row(text,[],|r|r.get(0)))}
    fn empty(db:&'a Connection,slot:&'a WorkSlot,steps:NonZeroU64)->Result<Self,Error>{
        let value=Self::start(db,slot,steps)?;
        if value.scalar("SELECT count(*) FROM sqlite_schema")?!=0{return Err(Error::Schema);}Ok(value)
    }
    fn open(db:&'a Connection,slot:&'a WorkSlot,policy:Policy,scope:&Scope)->Result<Self,Error>{
        let value=Self::start(db,slot,policy.steps)?;
        if !(0..=4).contains(&value.scalar("SELECT count(*) FROM sqlite_schema")?)
            || value.scalar("SELECT count(*) FROM sqlite_schema WHERE typeof(type)!='text' OR length(CAST(type AS blob))>32 OR typeof(name)!='text' OR length(CAST(name AS blob))>128 OR (sql IS NOT NULL AND (typeof(sql)!='text' OR length(CAST(sql AS blob))>4096))")?!=0
            || objects(db)?!=*expected()?{return Err(Error::Schema);}
        // Exact schema precedes every application table query/allocation.
        if value.scalar("SELECT count(*) FROM continuity_meta")?!=1
            || value.scalar("SELECT count(*) FROM continuity_meta WHERE typeof(id)!='integer' OR id!=1 OR typeof(scope)!='blob' OR length(scope) NOT BETWEEN 1 AND 1024")?!=0
            || value.scalar("SELECT count(*) FROM (SELECT 1 FROM continuity_operations LIMIT 4097)")?>MAX_HISTORY as i64
            || value.scalar("SELECT count(*) FROM continuity_operations WHERE typeof(sequence)!='integer' OR sequence NOT BETWEEN 1 AND 4096 OR typeof(operation)!='blob' OR length(operation)!=32 OR typeof(request)!='blob' OR length(request) NOT BETWEEN 1 AND 8192 OR typeof(receipt)!='blob' OR length(receipt) NOT BETWEEN 1 AND 1024")?!=0{return Err(Error::Schema);}
        let raw:Vec<u8>=sql(db.query_row("SELECT scope FROM continuity_meta WHERE id=1",[],|r|r.get(0)))?;
        if raw!=scope_bytes(scope)?{return Err(Error::Context);}Ok(value)
    }
    fn replay(&self,scope:&Scope)->Result<Engine,Error>{
        let mut engine=Engine::new(scope.clone())?;
        let mut q=sql(self.db.prepare("SELECT sequence,operation,request,receipt FROM continuity_operations ORDER BY sequence LIMIT 4097"))?;
        let mut rows=sql(q.query([]))?;let mut count=0usize;
        while let Some(row)=sql(rows.next())?{
            count+=1;if count>MAX_HISTORY{return Err(Error::History);}
            let sequence:i64=sql(row.get(0))?;let id:Vec<u8>=sql(row.get(1))?;
            let raw:Vec<u8>=sql(row.get(2))?;let ack:Vec<u8>=sql(row.get(3))?;
            if sequence!=count as i64{return Err(Error::History);}
            let request=Request::decode(&raw)?;
            if request.scope!=*scope || request.operation.as_slice()!=id{return Err(Error::History);}
            let receipt=engine.apply(&request)?;
            if receipt.repeated || receipt.operation_sequence!=count as u64
                || receipt!=decode_receipt(&ack)?{return Err(Error::History);}
        }
        Ok(engine)
    }
}
fn snapshot(engine:&Engine,nonce:Hash)->Result<PublicSnapshot,Error>{
    Ok(PublicSnapshot::new(engine.scope().clone(),nonce,engine.sequence(),engine.pending_operation(),engine.history())?)
}
fn durability(db:&Connection,writable:bool)->Result<(),Error>{
    let read_only=sql(db.is_readonly(rusqlite::MAIN_DB))?;
    let query:i64=sql(db.pragma_query_value(None,"query_only",|r|r.get(0)))?;
    let trusted:i64=sql(db.pragma_query_value(None,"trusted_schema",|r|r.get(0)))?;
    if trusted!=0 || crate::treasury_bounded_readers::journal_mode(db).map_err(resource)?!="delete"
        || (writable && (read_only || query!=0 || sql(db.pragma_query_value(None,"synchronous",|r|r.get::<_,i64>(0)))?!=3))
        || (!writable && (!read_only || query!=1)){return Err(Error::Storage);}Ok(())
}
fn exact_head(engine:&Engine,pinned:&PublicSnapshot)->Result<(),Error>{
    pinned.validate()?;
    if pinned.scope()!=engine.scope() || pinned.sequence()!=engine.sequence()
        || pinned.pending_operation()!=engine.pending_operation() || pinned.operations()!=engine.history(){return Err(Error::History);}Ok(())
}
pub(crate) struct Service {owner:NativeOwner,scope:Scope,policy:Policy,writable:bool,
    #[cfg(test)] fault:Option<Fault>}
impl Service {
    pub(crate) fn create_native(dir:&Path,config:&CeremonyConfig,scope:Scope,policy:Policy)->Result<Self,Error>{
        selected(config,&scope)?;let mut owner=NativeOwner::new_only(dir,policy.file_cap).map_err(native)?;
        owner.mutate_typed(native,|db,boundary,slot|{
            durability(db,true)?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
            let empty=Window::empty(&tx,slot,policy.steps)?;
            boundary.status().map_err(native)?;
            sql(tx.execute_batch(&format!("{META};{OPERATIONS};")))?;
            sql(tx.execute("INSERT INTO continuity_meta VALUES(1,?1)",[scope_bytes(&scope)?]))?;
            drop(empty);
            let reader=Window::open(&tx,slot,policy,&scope)?;reader.replay(&scope)?;drop(reader);
            boundary.status().map_err(native)?;tx.commit().map_err(|_|Error::Unknown)?;
            boundary.status().map_err(|_|Error::Unknown)?;Ok(())
        })?;
        Ok(Self{owner,scope,policy,writable:true,#[cfg(test)]fault:None})
    }
    /// REQUIRED exact independently retained service head on every restart.
    /// A copied public head is not authenticated by this API; the nonshipping
    /// deployment must supply its settled administrator/restore authority.
    /// Matching the head proves exact local replay, not global latestness.
    pub(crate) fn open_native(dir:&Path,config:&CeremonyConfig,scope:Scope,policy:Policy,
                             pinned:&PublicSnapshot,writable:bool)->Result<Self,Error>{
        selected(config,&scope)?;if pinned.scope()!=&scope{return Err(Error::Context);}pinned.validate()?;
        let mut owner=NativeOwner::existing_only(dir,policy.file_cap,true).map_err(native)?;
        owner.inspect_typed(native,|db,slot|{
            durability(db,false)?;let window=Window::open(db,slot,policy,&scope)?;
            exact_head(&window.replay(&scope)?,pinned)
        })?;
        if writable {
            owner.promote_after_binding(native,|db,slot|{
                let window=Window::open(db,slot,policy,&scope)?;exact_head(&window.replay(&scope)?,pinned)
            })?;
        }
        owner.inspect_typed(native,|db,_|durability(db,writable))?;
        Ok(Self{owner,scope,policy,writable,#[cfg(test)]fault:None})
    }
    pub(crate) fn open_reconciling_native(dir:&Path,config:&CeremonyConfig,scope:Scope,policy:Policy,
        target:&crate::treasury_application_enrollment_v1::protected_head::RecoveryTarget)->Result<Self,Error>{
        selected(config,&scope)?;
        let mut owner=NativeOwner::existing_only(dir,policy.file_cap,true).map_err(native)?;
        owner.inspect_typed(native,|db,slot|{durability(db,false)?;
            let w=Window::open(db,slot,policy,&scope)?;
            if !target.allows(&snapshot(&w.replay(&scope)?,[1;32])?){return Err(Error::History);}Ok(())})?;
        owner.promote_after_binding(native,|db,slot|{
            let w=Window::open(db,slot,policy,&scope)?;
            if !target.allows(&snapshot(&w.replay(&scope)?,[1;32])?){return Err(Error::History);}Ok(())})?;
        owner.inspect_typed(native,|db,_|durability(db,true))?;
        Ok(Self{owner,scope,policy,writable:true,#[cfg(test)]fault:None})
    }
    pub(crate) fn scope(&self)->&Scope{&self.scope}
    pub(crate) fn current(&self,nonce:Hash)->Result<PublicSnapshot,Error>{
        self.owner.inspect_typed(native,|db,slot|{
            durability(db,self.writable)?;let reader=Window::open(db,slot,self.policy,&self.scope)?;
            snapshot(&reader.replay(&self.scope)?,nonce)
        })
    }
    pub(crate) fn apply(&mut self,request:&Request)->Result<(Receipt,PublicSnapshot),Error>{
        if !self.writable{return Err(Error::ReadOnly);}let raw=request.encode()?;
        if request.scope!=self.scope{return Err(Error::Context);}
        #[cfg(test)] let fault=self.fault.take();
        self.owner.mutate_typed(uncertain_apply_boundary,|db,boundary,slot|{
            durability(db,true)?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
            let reader=Window::open(&tx,slot,self.policy,&self.scope)?;let mut engine=reader.replay(&self.scope)?;
            drop(reader);
            // Keep the VM budget through replay/INSERT. Drop its borrowed hook before
            // commit; native boundary checks and SQLite size/row bounds remain,
            // but commit is not claimed to be covered by this VM-step budget.
            // No stale Engine cache is used.
            let budget=VmBudget::install(&tx,slot,self.policy.steps).map_err(resource)?;
            let receipt=engine.apply(request)?;crate::treasury_continuity_v1::check_receipt(request,&receipt)?;
            boundary.status().map_err(native)?;
            if !receipt.repeated{sql(tx.execute("INSERT INTO continuity_operations VALUES(?1,?2,?3,?4)",params![
                receipt.operation_sequence as i64,request.operation.as_slice(),raw,encode_receipt(&receipt)?]))?;}
            let public=snapshot(&engine,request.request_nonce)?;
            #[cfg(test)] if matches!(fault,Some(Fault::BeforeCommit)){return Err(Error::Storage);}
            drop(budget);boundary.status().map_err(native)?;
            tx.commit().map_err(|_|Error::Unknown)?;boundary.status().map_err(|_|Error::Unknown)?;
            #[cfg(test)] if let Some(Fault::AfterPostcheckPathSubstitution {ref directory,ref committed})=fault {
                // Actual native inode mismatch occurs only after the real commit and
                // inner postcheck; mutate_typed's outer status must preserve UNKNOWN.
                *committed.borrow_mut()=Some(public.clone());
                tests::substitute_committed_main(directory)?;
            }
            #[cfg(test)] if matches!(fault,Some(Fault::AfterCommit)){return Err(Error::Unknown);}
            Ok((receipt,public))
        })
    }
    pub(crate) fn close(self)->Result<(),(Self,Error)>{
        let Self{owner,scope,policy,writable,#[cfg(test)]fault}=self;
        owner.close().map_err(|(owner,error)|(Self{owner,scope,policy,writable,#[cfg(test)]fault},native(error)))
    }
}
// Same-thread owner serializes all requests; no Send/Sync/raw Connection escape.
pub(crate) struct Endpoint {service:Service,pins:PublicPins,key:HybridKey,
    head:Option<crate::treasury_application_enrollment_v1::protected_head::HeadOwner>,frozen:bool}
impl Endpoint {
    #[cfg(test)]
    pub(crate) fn new(service:Service,pins:PublicPins,key:HybridKey)->Result<Self,Error>{
        let(_,generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(pins.service_descriptor())
            .map_err(|_|Error::Authentication(ProviderError::Authentication))?;
        if service.scope()!=pins.scope() || key.public().descriptor(generation)
            .map_err(|_|Error::Authentication(ProviderError::Authentication))?!=pins.service_descriptor(){return Err(Error::Context);}
        Ok(Self{service,pins,key,head:None,frozen:false})
    }
    pub(crate) fn with_head(service:Service,pins:PublicPins,key:HybridKey,
        head:crate::treasury_application_enrollment_v1::protected_head::HeadOwner)->Result<Self,Error>{
        let(_,generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(pins.service_descriptor())
            .map_err(|_|Error::Authentication(ProviderError::Authentication))?;
        if service.scope()!=pins.scope()||key.public().descriptor(generation)
            .map_err(|_|Error::Authentication(ProviderError::Authentication))?!=pins.service_descriptor(){return Err(Error::Context);}
        head.matches_service(&service).map_err(|_|Error::Unknown)?;
        Ok(Self{service,pins,key,head:Some(head),frozen:false})
    }
    pub(crate) fn handle(&mut self,raw:&[u8])->Result<Vec<u8>,Error>{
        if self.frozen{return Err(Error::Unknown);}
        let verified=VerifiedClientRequest::verify(&self.pins,raw).map_err(Error::Authentication)?;
        let(receipt,snapshot)=match verified.action(){
            ClientAction::Current{request_nonce,..}=>{
                if let Some(head)=self.head.as_ref(){if head.matches_service(&self.service).is_err(){self.frozen=true;return Err(Error::Unknown);}}
                (None,self.service.current(*request_nonce)?)
            },
            ClientAction::Transition(request)=>{
                if let Some(head)=self.head.as_mut(){if head.begin(&self.service,request).is_err(){self.frozen=true;head.freeze();return Err(Error::Unknown);}}
                let(r,s)=match self.service.apply(request){Ok(result)=>result,Err(error)=>{
                    self.frozen=true;if let Some(head)=self.head.as_mut(){head.freeze();}return Err(error);
                }};
                if let Some(head)=self.head.as_mut(){if head.publish(&self.service).is_err(){self.frozen=true;head.freeze();return Err(Error::Unknown);}}
                (Some(r),s)
            }
        };
        verified.sign_committed(&self.pins,&self.key,&snapshot,receipt.as_ref()).map_err(Error::Authentication)
    }
}
#[cfg(test)] enum Fault {
    BeforeCommit,AfterCommit,
    AfterPostcheckPathSubstitution {directory:std::path::PathBuf,
        committed:std::rc::Rc<std::cell::RefCell<Option<PublicSnapshot>>>},
}
#[cfg(test)] #[path="../controls/native_service_startup_controls.rs"] mod tests;

// Private ordinary application module. This copied registration does not change
// Source3 or consensus shipping graph; authentic installed inputs remain absent.
#[path="treasury_native_tcp_v1.rs"] pub(crate) mod tcp;
