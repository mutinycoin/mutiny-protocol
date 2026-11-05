//! Actual hybrid application owner shared by the ordinary process frontend and
//! the explicit protected TEST signing worker. No key generation, signing
//! fallback, expiry default or production qualification is supplied here.
use crate::{hybrid_runtime_v2::{HybridRuntime,WorkRequest,Installation},
    a2_operation_pool_v1::{Context,Pool},a2_operation_relay_v1::Relay,
    candidate_journal_v3::{Journal,Record,Retention},
    hybrid_peer_admission_v2::{PeerLink,Received},hybrid_a2_dispatch_v1::Outcome};
use mutiny_consensus_v8::{Hash,anchors::FinalizedAnchor,assembler_v2::Prepared};
use mutiny_transport_v2::objects::Offer;
use std::path::Path;
pub struct A2Services {pool:Pool,journal:Journal}
impl A2Services {
    /// Explicit create-new bootstrap or existing-only restart; no fallback.
    pub fn open(runtime:&HybridRuntime,pool:&Path,journal:&Path,budget:usize,initialize:bool)->Result<Self,String>{
        let pool=Pool::open(runtime,pool,initialize)?;
        let journal=Journal::open(runtime,journal,budget,initialize)?;
        runtime.attach_a2_candidate_journal(&journal).map_err(|e|format!("{e:?}"))?;
        Ok(Self {pool,journal})
    }
    pub fn submit(&mut self,runtime:&HybridRuntime,context:&Context<'_>,raw:&[u8])->Result<Hash,String>{self.pool.submit(runtime,context,raw)}
    pub fn pending(&self,runtime:&HybridRuntime,context:&Context<'_>)->Result<Option<Vec<u8>>,String>{self.pool.pending(runtime,context)}
    pub fn archive(&mut self,id:Hash,reason:&str)->Result<bool,String>{self.pool.archive_and_cancel(id,reason)}
    pub fn archived(&self,id:Hash)->Result<Option<(Vec<u8>,String)>,String>{self.pool.archived(id)}
    pub fn reconcile_finalized(&mut self,runtime:&HybridRuntime)->Result<bool,String>{self.pool.reconcile_finalized(runtime)}
    pub fn preserve(&mut self,runtime:&HybridRuntime,record:&Record)->Result<Retention,String>{self.journal.preserve(runtime,record)}
    pub fn journal(&self)->&Journal{&self.journal}
    pub fn dispatch(&mut self,runtime:&HybridRuntime,context:&Context<'_>,peer:&mut PeerLink,received:Received)->Result<Outcome,String>{
        crate::hybrid_a2_dispatch_v1::dispatch_peer(runtime,&mut self.pool,context,peer,received)
    }
    pub fn retry_completed(&mut self,runtime:&HybridRuntime,context:&Context<'_>,peer:&mut PeerLink,id:&Hash)->Result<Outcome,String>{
        crate::hybrid_a2_dispatch_v1::retry_completed(runtime,&mut self.pool,context,peer,id)
    }
    pub fn relay(&mut self,runtime:&HybridRuntime,context:&Context<'_>,relay:&mut Relay,peer:&mut PeerLink)->Result<Option<(Offer,Vec<u8>)>,String>{
        relay.prepare_peer(runtime,&self.pool,context,peer)
    }
    pub fn release_archived(&mut self,runtime:&HybridRuntime,relay:&mut Relay,peer:&mut PeerLink,id:Hash)->Result<bool,String>{
        relay.release_archived_peer(runtime,&self.pool,id,peer)
    }
}
pub struct Application {runtime:HybridRuntime,services:A2Services}
pub struct ApplicationInstallation {pub canonical:Installation,pub a2_cache:Result<bool,String>}
impl Application {
    pub fn from_existing(runtime:HybridRuntime,services:A2Services)->Result<Self,String>{
        // Journal registration rechecks its exact canonical network/rules.
        runtime.attach_a2_candidate_journal(services.journal()).map_err(|e|format!("{e:?}"))?;
        Ok(Self {runtime,services})
    }
    pub fn head(&self)->Result<FinalizedAnchor,String>{self.runtime.head().map_err(|e|format!("{e:?}"))}
    pub fn runtime(&mut self)->&mut HybridRuntime{&mut self.runtime}
    pub fn parts(&mut self)->(&mut HybridRuntime,&mut A2Services){(&mut self.runtime,&mut self.services)}
    pub fn into_parts(self)->(HybridRuntime,A2Services){(self.runtime,self.services)}
    pub fn prepare(&mut self,request:WorkRequest<'_>)->Result<Prepared,String>{
        let context=Context {parent:request.expected_parent,license:request.license,worker:request.worker,
            timestamp:request.timestamp,ticket:request.ticket};
        // A queued A2 operation is the complete exact item, never arbitrary
        // padding. The ordinary assembler still checks complete carrier limits.
        self.runtime.chain.body_capacity(request.expected_parent).map_err(|e|format!("{e:?}"))?
            .preflight_lists(&[],request.operations).map_err(|e|format!("{e:?}"))?;
        let pending=self.services.pending(&self.runtime,&context)?;
        let mut operations=request.operations.to_vec();
        if let Some(raw)=pending {if !operations.iter().any(|item|item==&raw){operations.push(raw);}}
        self.runtime.prepare(WorkRequest {operations:&operations,..request}).map_err(|e|format!("{e:?}"))
    }
    pub fn install(&mut self,raw:&[u8])->Result<ApplicationInstallation,String>{
        let installed=self.runtime.install(raw).map_err(|e|format!("{e:?}"))?;
        // Native canonical commit survives subsequent cache refusal. Never
        // report it undone or repeat a logical admission on a cache failure.
        let a2_cache=self.services.reconcile_finalized(&self.runtime);
        Ok(ApplicationInstallation {canonical:installed,a2_cache})
    }
}
