//! EXTERNAL SOURCE ONLY. One serialized NONSHIPPING worker, never egui main.
//! The supplied three peers MUST be independently created/pinned by the supervisor;
//! a request-supplied role/PID can never replace this bootstrap.
use super::{control_codec::{Context,Role},control_budget::Budget,control_reply::{Reply,Code,Refusal},
    process_auth::{Identity,VerifiedProcess},pipe_io::{Deadline,RolePipe,Availability},native_service::Service};
use sha2::{Digest,Sha256};
use std::{sync::{Arc,atomic::{AtomicBool,Ordering}},time::{Instant,Duration},io::Write};
type Result<T>=std::result::Result<T,String>;
pub const WORKER_MARKER:&str="MUTINY-W15-NONSHIPPING-SERIAL-PIPE-WORKER-V1";
struct BoundRole {role:Role,peer:VerifiedProcess,pipe:RolePipe,connected:bool}
pub struct Worker {service:Service,roles:Vec<BoundRole>,budget:Budget,stop:Arc<AtomicBool>,log:std::fs::File}
impl Worker {
    /// Construct INSIDE the worker thread: native HANDLEs are not cast/marked Send.
    /// Output is a create-new public action log; source/bootstrap pins precede this call.
    pub fn new(service:Service,peers:[(Role,Identity);3],owner:&Identity,stop:Arc<AtomicBool>,log:&std::path::Path)->Result<Self>{
        let current=VerifiedProcess::open(owner)?;
        if owner.pid!=std::process::id(){return Err("Worker owner is not this actual service process".into());}
        let mut ids=std::collections::BTreeSet::new();let mut roles=Vec::new();
        for (expected,(role,identity)) in [Role::WalletA,Role::WalletC,Role::Treasury].into_iter().zip(peers){
            if role!=expected||identity.pid==owner.pid||!ids.insert(identity.pid){return Err("Three distinct fixed client process roles required".into());}
            let peer=VerifiedProcess::open(&identity)?;
            let pipe=RolePipe::create(service.context().campaign,role,&current)?;
            roles.push(BoundRole{role,peer,pipe,connected:false});
        }
        let log=std::fs::OpenOptions::new().create_new(true).write(true).open(log).map_err(|e|e.to_string())?;
        Ok(Self{service,roles,budget:Budget::new(),stop,log})
    }
    fn append(&mut self,value:serde_json::Value)->Result<()> {
        let mut raw=serde_json::to_vec(&value).map_err(|e|e.to_string())?;
        if raw.len()>8192{return Err("Public service event bound".into());}raw.push(b'\n');
        self.log.write_all(&raw).map_err(|e|e.to_string())?;self.log.flush().map_err(|e|e.to_string())
    }
    pub fn context(&self)->Context{self.service.context()}
    /// Cancellation stops only BETWEEN complete native actions. No detached
    /// pending IO, thread termination, discarded tentative history or key copy.
    /// A stopped worker writes an actual public checkpoint at the complete action
    /// boundary. Failure retains its primary error; snapshot cannot waive it.
    /// The main caller keeps every original lease until this method returns.
    pub fn run(mut self)->Result<()> {self.run_actions()}
    pub(super) fn run_with_shutdown(mut self,root:&std::path::Path)->Result<()> {
        let primary=self.run_actions();
        let captured=self.service.shutdown_snapshot(primary.is_ok()).and_then(|snapshot|super::shutdown::publish(root,"service",&snapshot));
        let record=self.append(serde_json::json!({"event":"actual-shutdown-snapshot-result","completed_between_actions":primary.is_ok(),"checkpoint_path":captured.as_ref().ok(),"primary_failure":primary.as_ref().err(),"snapshot_failure":captured.as_ref().err(),"process_exit_observed":false}));
        let synced=self.log.sync_all().map_err(|e|e.to_string());
        match (primary,captured,record,synced){(Ok(()),Ok(_),Ok(()),Ok(()))=>Ok(()),(p,c,r,s)=>Err(format!("Native worker shutdown refusal: primary={:?}, checkpoint={:?}, log={:?}, sync={:?}",p.err(),c.err(),r.err(),s.err()))}
    }
    fn run_actions(&mut self)->Result<()> {
        self.append(serde_json::json!({"marker":WORKER_MARKER,"event":"worker-open","process":std::process::id(),"confirmation_authority":false}))?;
        while !self.stop.load(Ordering::SeqCst){
            self.service.turn(Instant::now()+Duration::from_millis(400))?;
            for index in 0..self.roles.len(){
                let role=self.roles[index].role;
                if !self.roles[index].connected{
                    if !self.roles[index].pipe.poll_authenticated_connection(&self.roles[index].peer)?{continue;}
                    self.budget.connect(role).map_err(|e|format!("Authenticated connection budget: {e:?}"))?;
                    self.roles[index].connected=true;
                    self.append(serde_json::json!({"event":"actual-native-peer-bound","role":role as u8,"pid":self.roles[index].peer.identity().pid,"start_filetime":self.roles[index].peer.identity().start_filetime}))?;
                }
                match self.roles[index].pipe.request_ready(&self.roles[index].peer)?{
                    Availability::Empty=>continue,
                    Availability::Message=>{},
                    Availability::Disconnected=>{
                        // Only between completed actions. The same independently pinned
                        // process may reconnect; sequence/budget NEVER reset.
                        self.budget.disconnect(role).map_err(|e|format!("Disconnect with action outstanding: {e:?}"))?;
                        self.roles[index].pipe.disconnect_completed(&self.roles[index].peer)?;
                        self.roles[index].connected=false;
                        self.append(serde_json::json!({"event":"actual-native-disconnect","role":role as u8,"sequence_reset":false}))?;
                        continue;
                    }
                }
                let deadline=Deadline::new();
                let next=self.budget.next_sequence(role).map_err(|e|format!("Local sequence budget: {e:?}"))?;
                let head=self.service.head()?;
                let received=self.roles[index].pipe.read_authenticated(&self.roles[index].peer,self.service.context(),head,next,&deadline)?;
                self.budget.begin(role,received.request.header.sequence).map_err(|e|format!("Local action budget: {e:?}"))?;
                let request_sha:[u8;32]=Sha256::digest(&received.exact_bytes).into();
                self.append(serde_json::json!({"event":"authenticated-action-begin","role":role as u8,"seq":next,"request_sha256":hex::encode(request_sha),"tag":received.request.header.tag as u8,"head":head.height}))?;
                // Callback has only native storage/delivery/certification primitives;
                // it never receives a Controller or approves/signs a wallet object.
                let outcome=self.service.execute(role,&received.request.action,deadline.instant());
                self.roles[index].peer.recheck()?;
                let (code,refusal,detail)=match outcome{Ok(code)=>(code,Refusal::None,None),Err((why,detail))=>(Code::Refused,why,Some(detail))};
                self.budget.finish(role).map_err(|e|format!("Local finish budget: {e:?}"))?;
                let observed=self.service.head()?; // Any partial-store disagreement refuses a success reply.
                let reply=Reply{code,refusal,sequence:next,campaign:self.service.context().campaign,exact_request_sha256:request_sha,observed_head:observed};
                self.append(serde_json::json!({"event":"authenticated-action-result","role":role as u8,"seq":next,"code":code as u8,"refusal":refusal as u8,"detail":detail,"head":observed.height,"block":hex::encode(observed.block),"root":hex::encode(observed.root),"confirmed":false}))?;
                self.roles[index].pipe.write_authenticated(&self.roles[index].peer,reply,&deadline)?;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        self.append(serde_json::json!({"event":"worker-cancelled-between-actions","original_synthetic_provider_retained":true}))?;
        self.log.sync_all().map_err(|e|e.to_string())
        // self owns the protected synthetic provider and native channels. Drop destroys
        // only live key handles. Existing-only reopen requires the original provider/journal.
    }
}
