//! SOURCE ONLY / UNCOMPILED. Private ordinary application restore-domain owner.
//! A native file is not independent administrative latestness by itself. The
//! selected location/restore exclusion must be provisioned by trusted enrollment.
use super::VerifiedApproval;
use crate::{Hash,protected_owner::{Owner as NativeOwner,Error as NativeError},
    treasury_bounded_readers::{VmBudget,WorkSlot},
    treasury_continuity_v1::{Engine,Request,Scope},
    treasury_continuity_provider_v1::{PublicSnapshot,MAX_HISTORY,encode_receipt,decode_receipt},
    treasury_native_service_v1::Service,
    treasury_rehearsal_v3::Refusal};
use rusqlite::{Connection,Transaction,TransactionBehavior,params};
use std::{path::PathBuf,num::NonZeroU64,sync::OnceLock};
const META:&str="CREATE TABLE head_meta(id INTEGER PRIMARY KEY CHECK(id=1), scope BLOB NOT NULL CHECK(typeof(scope)='blob'), administrator BLOB NOT NULL CHECK(typeof(administrator)='blob' AND length(administrator)=32), document BLOB NOT NULL CHECK(typeof(document)='blob' AND length(document)=32), seed BLOB NOT NULL CHECK(typeof(seed)='blob' AND length(seed)=32))";
const OPS:&str="CREATE TABLE head_operations(sequence INTEGER PRIMARY KEY CHECK(sequence>0 AND sequence<=4096), operation BLOB NOT NULL UNIQUE CHECK(typeof(operation)='blob' AND length(operation)=32), request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)>0 AND length(request)<=8192), receipt BLOB NOT NULL CHECK(typeof(receipt)='blob' AND length(receipt)>0 AND length(receipt)<=1024))";
const INTENT:&str="CREATE TABLE head_intent(id INTEGER PRIMARY KEY CHECK(id=1), request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)>0 AND length(request)<=8192))";
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub(crate) enum Error{Storage,Unknown,Context,Schema,History,Frozen}
fn sql<T>(x:rusqlite::Result<T>)->Result<T,Error>{x.map_err(|_|Error::Storage)}
fn native(_:NativeError)->Error{Error::Storage}
fn uncertain(_:NativeError)->Error{Error::Unknown}
fn resource(_:Refusal)->Error{Error::Storage}
fn digest(raw:&[u8])->Hash{super::digest(raw)}
fn same_head(a:&PublicSnapshot,b:&PublicSnapshot)->bool{
    a.scope()==b.scope()&&a.sequence()==b.sequence()
        &&a.pending_operation()==b.pending_operation()&&a.operations()==b.operations()
}
fn snapshot(engine:&Engine)->Result<PublicSnapshot,Error>{
    // Internal comparison nonce only. Never a signed/network freshness premise.
    PublicSnapshot::new(engine.scope().clone(),[1;32],engine.sequence(),
        engine.pending_operation(),engine.history()).map_err(|_|Error::History)
}
fn replay_request(scope:&Scope,item:&crate::treasury_continuity_v1::HistoryEntry)->Result<Request,Error>{
    Ok(Request{scope:scope.clone(),operation:item.operation,request_nonce:item.operation,
        expected_sequence:item.sequence.checked_sub(1).ok_or(Error::History)?,action:item.action.clone()})
}
// Constructor/fields stay in this parent enrollment module. No parsed record,
// applicant path, digest, boolean or arbitrary directory can select this owner.
pub(super) struct Location{pub(super) path:PathBuf,pub(super) file_cap:i64,pub(super) steps:NonZeroU64}
impl Location{fn validate(&self,a:&VerifiedApproval)->Result<(),Error>{
    let raw=std::os::unix::ffi::OsStrExt::as_bytes(self.path.as_os_str());
    if !self.path.is_absolute()||raw.is_empty()||raw.len()>4096||raw.contains(&0)
        ||raw.split(|b|*b==b'/').any(|p|p==b"."||p==b"..")
        ||self.path.starts_with(&a.record.admission)||self.path.starts_with(&a.record.service)
        ||a.record.admission.starts_with(&self.path)||a.record.service.starts_with(&self.path)
        ||!(1..=32*1024*1024).contains(&self.file_cap){return Err(Error::Context);}Ok(())
}}
type Objects=Vec<(String,String,Option<String>)>;
fn objects(db:&Connection)->Result<Objects,Error>{
    let mut q=sql(db.prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY name"))?;
    sql(sql(q.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))))?.collect())
}
fn expected()->Result<&'static Objects,Error>{
    static EXPECTED:OnceLock<Objects>=OnceLock::new();
    if let Some(value)=EXPECTED.get(){return Ok(value);}
    let db=sql(Connection::open_in_memory())?;sql(db.execute_batch(&format!("{META};{OPS};{INTENT};")))?;
    let value=objects(&db)?;Ok(EXPECTED.get_or_init(||value))
}
struct Binding{scope:Scope,administrator:Hash,document:Hash,seed:Hash,seed_head:PublicSnapshot}
impl Binding{fn approved(a:&VerifiedApproval)->Result<Self,Error>{
    a.record.checkpoint.validate().map_err(|_|Error::History)?;
    Ok(Self{scope:a.pins().scope().clone(),administrator:a.record.administrator,
        document:a.selection,seed:digest(&a.record.checkpoint.encode().map_err(|_|Error::History)?),
        seed_head:a.record.checkpoint.clone()})
}}
fn scope_bytes(scope:&Scope)->Result<Vec<u8>,Error>{
    PublicSnapshot::new(scope.clone(),[1;32],0,None,vec![]).map_err(|_|Error::Context)?
        .encode().map_err(|_|Error::Context)
}
fn durability(db:&Connection,writable:bool)->Result<(),Error>{
    let readonly=sql(db.is_readonly(rusqlite::MAIN_DB))?;
    let query:i64=sql(db.pragma_query_value(None,"query_only",|r|r.get(0)))?;
    let trusted:i64=sql(db.pragma_query_value(None,"trusted_schema",|r|r.get(0)))?;
    if trusted!=0||crate::treasury_bounded_readers::journal_mode(db).map_err(resource)?!="delete"
        ||(writable&&(readonly||query!=0||sql(db.pragma_query_value(None,"synchronous",|r|r.get::<_,i64>(0)))?!=3))
        ||(!writable&&(!readonly||query!=1)){return Err(Error::Storage);}Ok(())
}
// Budget drops before the same snapshot transaction. Exact metadata/type/length
// bounds precede every application Vec/String allocation; no Connection escape.
struct Window<'a>{db:&'a Connection,_budget:VmBudget<'a>,_snapshot:Option<Transaction<'a>>}
impl<'a> Window<'a>{
    fn start(db:&'a Connection,slot:&'a WorkSlot,steps:NonZeroU64)->Result<Self,Error>{
        let budget=VmBudget::install(db,slot,steps).map_err(resource)?;
        let snapshot=if db.is_autocommit(){Some(sql(db.unchecked_transaction())?)}else{None};
        Ok(Self{db,_budget:budget,_snapshot:snapshot})
    }
    fn scalar(&self,q:&str)->Result<i64,Error>{sql(self.db.query_row(q,[],|r|r.get(0)))}
    fn open(db:&'a Connection,slot:&'a WorkSlot,steps:NonZeroU64,b:&Binding)->Result<Self,Error>{
        let w=Self::start(db,slot,steps)?;
        if !(0..=8).contains(&w.scalar("SELECT count(*) FROM sqlite_schema")?)
            ||w.scalar("SELECT count(*) FROM sqlite_schema WHERE typeof(type)!='text' OR length(CAST(type AS blob))>32 OR typeof(name)!='text' OR length(CAST(name AS blob))>128 OR (sql IS NOT NULL AND (typeof(sql)!='text' OR length(CAST(sql AS blob))>4096))")?!=0
            ||objects(db)?!=*expected()?{return Err(Error::Schema);}
        if w.scalar("SELECT count(*) FROM head_meta")?!=1
            ||w.scalar("SELECT count(*) FROM head_meta WHERE typeof(id)!='integer' OR id!=1 OR typeof(scope)!='blob' OR length(scope) NOT BETWEEN 1 AND 1024 OR typeof(administrator)!='blob' OR length(administrator)!=32 OR typeof(document)!='blob' OR length(document)!=32 OR typeof(seed)!='blob' OR length(seed)!=32")?!=0
            ||w.scalar("SELECT count(*) FROM (SELECT 1 FROM head_operations LIMIT 4097)")?>MAX_HISTORY as i64
            ||w.scalar("SELECT count(*) FROM head_operations WHERE typeof(sequence)!='integer' OR sequence NOT BETWEEN 1 AND 4096 OR typeof(operation)!='blob' OR length(operation)!=32 OR typeof(request)!='blob' OR length(request) NOT BETWEEN 1 AND 8192 OR typeof(receipt)!='blob' OR length(receipt) NOT BETWEEN 1 AND 1024")?!=0
            ||w.scalar("SELECT count(*) FROM head_intent")?>1
            ||w.scalar("SELECT count(*) FROM head_intent WHERE typeof(id)!='integer' OR id!=1 OR typeof(request)!='blob' OR length(request) NOT BETWEEN 1 AND 8192")?!=0{return Err(Error::Schema);}
        let row:(Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>)=sql(db.query_row("SELECT scope,administrator,document,seed FROM head_meta WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))))?;
        if row.0!=scope_bytes(&b.scope)?||row.1!=b.administrator||row.2!=b.document||row.3!=b.seed{return Err(Error::Context);}Ok(w)
    }
    fn replay(&self,b:&Binding)->Result<Engine,Error>{
        let mut engine=Engine::new(b.scope.clone()).map_err(|_|Error::Context)?;
        let mut q=sql(self.db.prepare("SELECT sequence,operation,request,receipt FROM head_operations ORDER BY sequence LIMIT 4097"))?;
        let mut rows=sql(q.query([]))?;let mut count=0usize;
        while let Some(row)=sql(rows.next())?{
            count+=1;if count>MAX_HISTORY{return Err(Error::History);}
            let sequence:i64=sql(row.get(0))?;let op:Vec<u8>=sql(row.get(1))?;
            let raw:Vec<u8>=sql(row.get(2))?;let ack:Vec<u8>=sql(row.get(3))?;
            if sequence!=count as i64{return Err(Error::History);}
            let request=Request::decode(&raw).map_err(|_|Error::History)?;
            if request.scope!=b.scope||request.operation.as_slice()!=op{return Err(Error::History);}
            let receipt=engine.apply(&request).map_err(|_|Error::History)?;
            if receipt.repeated||receipt.operation_sequence!=count as u64
                ||receipt!=decode_receipt(&ack).map_err(|_|Error::History)?{return Err(Error::History);}
        }
        let current=snapshot(&engine)?;
        if current.sequence()<b.seed_head.sequence()
            ||!current.operations().starts_with(b.seed_head.operations())
            ||(current.sequence()==b.seed_head.sequence()&&!same_head(&current,&b.seed_head)){return Err(Error::History);}Ok(engine)
    }
    fn intent(&self)->Result<Option<Request>,Error>{
        use rusqlite::OptionalExtension;
        let raw:Option<Vec<u8>>=sql(self.db.query_row("SELECT request FROM head_intent WHERE id=1",[],|r|r.get(0)).optional())?;
        raw.map(|raw|Request::decode(&raw).map_err(|_|Error::History)).transpose()
    }
}
pub(crate) struct HeadOwner{owner:NativeOwner,binding:Binding,steps:NonZeroU64,writable:bool,frozen:bool}
/// Opaque exact before/after replay capability, constructed only by an existing
/// independently selected HeadOwner. Its fields have no caller constructor.
pub(crate) struct RecoveryTarget{before:PublicSnapshot,after:Option<PublicSnapshot>}
impl RecoveryTarget{
    pub(crate) fn allows(&self,actual:&PublicSnapshot)->bool{
        same_head(&self.before,actual)||self.after.as_ref().is_some_and(|a|same_head(a,actual))
    }
}
impl HeadOwner{
    pub(super) fn open(a:&VerifiedApproval,location:&Location,writable:bool)->Result<Self,Error>{
        location.validate(a)?;let binding=Binding::approved(a)?;
        let mut owner=NativeOwner::existing_only(&location.path,location.file_cap,true).map_err(native)?;
        owner.inspect_typed(native,|db,slot|{durability(db,false)?;let w=Window::open(db,slot,location.steps,&binding)?;w.replay(&binding)?;Ok(())})?;
        if writable{owner.promote_after_binding(native,|db,slot|{let w=Window::open(db,slot,location.steps,&binding)?;w.replay(&binding)?;Ok(())})?;}
        Ok(Self{owner,binding,steps:location.steps,writable,frozen:false})
    }
    fn read(&self)->Result<(PublicSnapshot,Option<Request>),Error>{
        self.owner.inspect_typed(native,|db,slot|{durability(db,self.writable)?;
            let w=Window::open(db,slot,self.steps,&self.binding)?;
            Ok((snapshot(&w.replay(&self.binding)?)?,w.intent()?))})
    }
    pub(super) fn approved_current(&self,mut a:VerifiedApproval)->Result<VerifiedApproval,Error>{
        if a.selection!=self.binding.document{return Err(Error::Context);}
        let(current,intent)=self.read()?;if intent.is_some()||self.frozen{return Err(Error::Frozen);}
        a.current=current;Ok(a)
    }
    pub(crate) fn matches_service(&self,service:&Service)->Result<(),Error>{
        let(head,intent)=self.read()?;if intent.is_some()||self.frozen{return Err(Error::Frozen);}
        let actual=service.current([1;32]).map_err(|_|Error::Storage)?;
        if !same_head(&head,&actual){return Err(Error::History);}Ok(())
    }
    // Only Endpoint's already hybrid-verified request action reaches this private
    // funnel. No public/pin/JSON caller can mint a publication capability.
    pub(crate) fn begin(&mut self,service:&Service,request:&Request)->Result<(),Error>{
        if !self.writable||self.frozen{return Err(Error::Frozen);}
        self.matches_service(service)?;
        let raw=request.encode().map_err(|_|Error::History)?;if raw.is_empty()||raw.len()>8192{return Err(Error::History);}
        let result=self.owner.mutate_typed(uncertain,|db,boundary,slot|{
            durability(db,true)?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
            let w=Window::open(&tx,slot,self.steps,&self.binding)?;
            if w.intent()?.is_some(){return Err(Error::Frozen);}let mut engine=w.replay(&self.binding)?;
            engine.apply(request).map_err(|_|Error::History)?;drop(w);
            let budget=VmBudget::install(&tx,slot,self.steps).map_err(resource)?;
            sql(tx.execute("INSERT INTO head_intent VALUES(1,?1)",[raw]))?;
            drop(budget);boundary.status().map_err(native)?;tx.commit().map_err(|_|Error::Unknown)?;
            boundary.status().map_err(|_|Error::Unknown)?;Ok(())
        });if result.is_err(){self.frozen=true;}result
    }
    pub(crate) fn publish(&mut self,service:&Service)->Result<(),Error>{
        if !self.writable||self.frozen{return Err(Error::Frozen);}
        let actual=service.current([1;32]).map_err(|_|Error::Unknown)?;
        let result=self.owner.mutate_typed(uncertain,|db,boundary,slot|{
            durability(db,true)?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
            let w=Window::open(&tx,slot,self.steps,&self.binding)?;
            let request=w.intent()?.ok_or(Error::Frozen)?;let mut engine=w.replay(&self.binding)?;
            let receipt=engine.apply(&request).map_err(|_|Error::History)?;
            if !same_head(&snapshot(&engine)?,&actual){return Err(Error::History);}drop(w);
            let budget=VmBudget::install(&tx,slot,self.steps).map_err(resource)?;
            if !receipt.repeated{sql(tx.execute("INSERT INTO head_operations VALUES(?1,?2,?3,?4)",params![
                receipt.operation_sequence as i64,request.operation.as_slice(),request.encode().map_err(|_|Error::History)?,
                encode_receipt(&receipt).map_err(|_|Error::History)?]))?;}
            sql(tx.execute("DELETE FROM head_intent WHERE id=1",[]))?;
            drop(budget);boundary.status().map_err(native)?;tx.commit().map_err(|_|Error::Unknown)?;
            boundary.status().map_err(|_|Error::Unknown)?;Ok(())
        });if result.is_err(){self.frozen=true;}result
    }
    pub(crate) fn freeze(&mut self){self.frozen=true;}
    pub(super) fn recovery_target(&self)->Result<RecoveryTarget,Error>{
        let(before,intent)=self.read()?;
        let after=if let Some(request)=intent{
            let mut engine=Engine::new(self.binding.scope.clone()).map_err(|_|Error::History)?;
            for item in before.operations(){engine.apply(&replay_request(&self.binding.scope,item)?).map_err(|_|Error::History)?;}
            engine.apply(&request).map_err(|_|Error::History)?;Some(snapshot(&engine)?)
        }else{None};Ok(RecoveryTarget{before,after})
    }
    /// Explicit application reconciliation only. It audits the real native
    /// service and clears an intent only at the exact replayed AFTER outcome.
    /// An observed BEFORE state retains intent and stays Frozen: it does not
    /// prove nonconsumption. No automatic cancellation, retry or restore repair.
    pub(super) fn reconcile(&mut self,service:&Service)->Result<(),Error>{
        if !self.writable{return Err(Error::Frozen);}
        let actual=service.current([1;32]).map_err(|_|Error::Unknown)?;
        let result=self.owner.mutate_typed(uncertain,|db,boundary,slot|{
            durability(db,true)?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
            let w=Window::open(&tx,slot,self.steps,&self.binding)?;let mut engine=w.replay(&self.binding)?;
            let before=snapshot(&engine)?;let intent=w.intent()?;
            let insertion=if let Some(request)=intent{
                let receipt=engine.apply(&request).map_err(|_|Error::History)?;
                let after=snapshot(&engine)?;
                if same_head(&actual,&after){if receipt.repeated{None}else{Some((request,receipt))}}
                else if same_head(&actual,&before){
                    // Before-state is compatible with BOTH crash-before-apply and
                    // lost acknowledgment followed by service-store rollback.
                    // It cannot cancel the recorded ambiguity or reissue rights.
                    return Err(Error::Frozen);
                }else{return Err(Error::History);}
            }else{if !same_head(&actual,&before){return Err(Error::History);}None};drop(w);
            let budget=VmBudget::install(&tx,slot,self.steps).map_err(resource)?;
            if let Some((request,receipt))=insertion{sql(tx.execute("INSERT INTO head_operations VALUES(?1,?2,?3,?4)",params![
                receipt.operation_sequence as i64,request.operation.as_slice(),request.encode().map_err(|_|Error::History)?,
                encode_receipt(&receipt).map_err(|_|Error::History)?]))?;}
            sql(tx.execute("DELETE FROM head_intent WHERE id=1",[]))?;
            drop(budget);boundary.status().map_err(native)?;tx.commit().map_err(|_|Error::Unknown)?;
            boundary.status().map_err(|_|Error::Unknown)?;Ok(())
        });self.frozen=result.is_err();result?;self.matches_service(service)
    }
    pub(crate) fn close(self)->Result<(),(Self,Error)>{
        let Self{owner,binding,steps,writable,frozen}=self;
        owner.close().map_err(|(owner,e)|(Self{owner,binding,steps,writable,frozen},native(e)))
    }
    pub(crate) fn close_final(self)->Result<(),Error>{
        self.close().map_err(|(retained,error)|{std::mem::forget(retained);error})
    }
}
// No normal initializer, restore repair, arbitrary head replacement or public
// caller-supplied latestness. Fresh native TEST initialization is separate.
// Ordinary startup refuses a pending intent; only the explicitly selected audit
// path may obtain a RecoveryTarget and call reconcile after full native replay.

#[cfg(test)] #[path="treasury_application_protected_head_controls_v2.rs"] mod ambiguity_tests;

// Initial public TEST head formation only. Ordinary startup stays existing-only.
#[cfg(test)] pub(super) fn initialize_test_head(a:&VerifiedApproval,location:&Location)->Result<(),Error>{
    location.validate(a)?;let binding=Binding::approved(a)?;
    let mut owner=NativeOwner::new_only(&location.path,location.file_cap).map_err(native)?;
    owner.mutate_typed(native,|db,boundary,slot|{
        durability(db,true)?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let budget=VmBudget::install(&tx,slot,location.steps).map_err(resource)?;
        sql(tx.execute_batch(&format!("{META};{OPS};{INTENT};")))?;
        sql(tx.execute("INSERT INTO head_meta VALUES(1,?1,?2,?3,?4)",params![scope_bytes(&binding.scope)?,
            binding.administrator.as_slice(),binding.document.as_slice(),binding.seed.as_slice()]))?;
        drop(budget);boundary.status().map_err(native)?;tx.commit().map_err(|_|Error::Unknown)?;
        boundary.status().map_err(|_|Error::Unknown)?;Ok(())
    })?;
    owner.close().map_err(|_|Error::Storage)
}
/// Simulated loss of publication after a real durable service transition.
/// Earlier requests retain normal intent/service/publish ordering. Nothing
/// rolls back consumption; existing-only reconciliation must prove exact state.
#[cfg(test)] pub(super) fn apply_test_without_last_publication(a:&VerifiedApproval,location:&Location,
    config:&crate::treasury_rehearsal_v3::CeremonyConfig,policy:crate::treasury_native_service_v1::Policy,
    requests:&[Request])->Result<(),Error>{
    if requests.is_empty(){return Err(Error::Context);}
    let mut head=HeadOwner::open(a,location,true)?;
    let current=head.read()?.0;
    let mut service=Service::open_native(a.service_path(),config,a.pins().scope().clone(),policy,&current,true)
        .map_err(|_|Error::Storage)?;
    for (index,request) in requests.iter().enumerate(){
        head.begin(&service,request)?;service.apply(request).map_err(|_|Error::Unknown)?;
        if index+1<requests.len(){head.publish(&service)?;}
    }
    service.close().map_err(|_|Error::Storage)?;
    match head.close(){
        Ok(())=>Ok(()),
        Err((retained_owner,error))=>{
            // Failed TEST close retains all pins until this isolated process exits.
            // Do not trigger Drop cleanup/retry or classify refusal as success.
            std::mem::forget(retained_owner);Err(error)
        }
    }
}
