//! Actual Linux installed-only private composition. No raw caller path,
//! passwords, profile, context or qualified-clock Boolean enters this factory.
//! Construct only on the controller's ORIGINAL owned private signer worker.
#![cfg(target_os="linux")]
use std::{mem::ManuallyDrop as MD,sync::Arc,time::Duration};
use mutiny_consensus_v8::{Hash,canonical_store_v2::CanonicalStore,
    counter_store_v2::CounterStore,voter_actor_v2::VoterActor,
    mempool_v2::{Mempool,MAX_PENDING_BYTES}};
use crate::{hybrid_installed_databases_v2::InstalledDatabases,
    hybrid_native_sqlite_linux_v2::NativeExistingDatabase,
    hybrid_installed_counter_v2::InstalledCounterAuthority,
    hybrid_installed_role_inputs_v2::InstalledRoleInputs,
    hybrid_counter_unix_v2::{CounterStop,InstalledCounterConnection,InstalledUnlockInput},
    hybrid_authenticated_counter_v2::ExactCounter,hybrid_existing_custody_v2::ExistingBackend,
    hybrid_runtime_v2::HybridRuntime,hybrid_voter_v2::VotingRuntime,
    activation_private_owner_v1::Owner,
    host_clock::{InstalledPrivateClockSession,PrivateClockSessionStart}};
type Counter=ExactCounter<InstalledCounterConnection>;
type Backend=ExistingBackend<Counter>;
type Result<T>=std::result::Result<T,String>;

// Every fallible stage returns its typed original retained holder into the
// already allocated state. No new Box is allocated after an owner is taken.
enum Fault{
    AuthorityClose(crate::hybrid_installed_counter_v2::CounterAuthorityCloseRefusal),
    Database(crate::hybrid_installed_databases_v2::DatabaseSelectionRefusal),
    Signer(crate::hybrid_installed_signer_inputs_v2::SignerInputRefusal),
    Native(crate::hybrid_native_sqlite_linux_v2::NativeDatabaseRefusal),
    Canonical(mutiny_consensus_v8::canonical_store_v2::ExistingCanonicalRefusal),
    Assembly(crate::hybrid_existing_custody_v2::ExistingAssemblyRefusal<Counter>),
    Counter(mutiny_consensus_v8::counter_store_v2::ExistingCounterRefusal),
    Actor(mutiny_consensus_v8::voter_actor_v2::ExistingActorRefusal),
    Runtime(crate::hybrid_runtime_v2::ExistingRuntimeRefusal),
    Voting(crate::hybrid_voter_v2::ExistingVotingRefusal<Backend>),
    Owner(crate::activation_private_owner_v1::ExistingOwnerRefusal<Backend>),
    Endpoint(crate::hybrid_authenticated_counter_v2::ExistingExactCounterRefusal<InstalledCounterConnection>),
    UnlockClose(crate::hybrid_counter_unix_v2::CounterConnectionClose),
    Maker(crate::activation_private_owner_v1::linux_tools::InstalledMakerRefusal),
    CounterClose(mutiny_consensus_v8::counter_store_v2::ExistingCounterCloseRefusal),
    CanonicalClose(mutiny_consensus_v8::canonical_store_v2::ExistingCanonicalRefusal),
    FrozenCounter(MD<Counter>),
    JoinedClock(MD<crate::host_clock::JoinedPrivateClockSession>),
}
struct State{
    databases:Option<MD<InstalledDatabases>>,
    signer:Option<MD<super::hybrid_installed_signer_inputs_v2::InstalledSignerInputs>>,
    canonical_native:Option<MD<NativeExistingDatabase>>,counter_native:Option<MD<NativeExistingDatabase>>,
    views:Vec<MD<CanonicalStore>>,authority:Option<MD<InstalledCounterAuthority>>,
    roles:Option<MD<InstalledRoleInputs>>,unlock:Option<MD<InstalledUnlockInput>>,
    endpoint:Option<MD<InstalledCounterConnection>>,counter:Option<MD<Counter>>,
    backend:Option<MD<Backend>>,store:Option<MD<CounterStore>>,actor:Option<MD<VoterActor>>,
    runtime:Option<MD<HybridRuntime>>,voting:Option<MD<VotingRuntime<Backend>>>,owner:Option<MD<Owner<Backend>>>,
    clock:Option<MD<Arc<InstalledPrivateClockSession>>>,stop:MD<Arc<CounterStop>>,
    tool:Option<MD<crate::activation_private_owner_v1::linux_tools::ToolPin>>,
    maker:Option<MD<crate::activation_private_owner_v1::linux_tools::InstalledMakeCredential>>,
    start:Option<PrivateClockSessionStart>,faults:Vec<Fault>,frozen:bool,
    original_worker:std::thread::ThreadId,
}
pub(crate) struct InstalledPrivateFactory{state:MD<Box<State>>}
pub(crate) struct InstalledFactoryRefusal{cause:String,owner:MD<InstalledPrivateFactory>}
impl InstalledFactoryRefusal{pub(crate) fn cause(&self)->&str{&self.cause}}
impl InstalledPrivateFactory{
    pub(crate) fn open_on_private_worker(_source:&crate::hybrid_installed_secret_source_v2::InstalledSecretSourceRegistration,
        start:PrivateClockSessionStart,stop:Arc<CounterStop>)
        ->std::result::Result<Self,InstalledFactoryRefusal>{
        // Incoming original cancellation/start holders precede allocation. All
        // partial native/store/key states have fixed preallocated slots.
        let stop=MD::new(stop);
        let mut out=Self{state:MD::new(Box::new(State{databases:None,signer:None,
            canonical_native:None,counter_native:None,views:Vec::with_capacity(4),authority:None,
            roles:None,unlock:None,endpoint:None,counter:None,backend:None,store:None,actor:None,
            runtime:None,voting:None,owner:None,clock:None,tool:None,maker:None,stop,start:Some(start),faults:Vec::with_capacity(16),
            frozen:true,original_worker:std::thread::current().id()}))};
        let initialized=(||->Result<()>{
            let s=&mut **out.state;
            let databases=match InstalledDatabases::open_installed(){Ok(v)=>v,Err(e)=>{
                let cause=e.cause().to_owned();s.faults.push(Fault::Database(e));return Err(cause);}};
            s.databases=Some(MD::new(databases));
            let db=s.databases.as_mut().ok_or("original installed database selection absent")?;
            let node=db.node()?;
            match super::hybrid_installed_signer_inputs_v2::InstalledSignerInputs::open(db){
                Ok(v)=>s.signer=Some(MD::new(v)),Err(e)=>{let cause=e.cause().to_owned();
                    s.faults.push(Fault::Signer(e));return Err(cause);}}
            let opened=match NativeExistingDatabase::open(&db.canonical_request()?,false){Ok(v)=>v,Err(e)=>{
                let cause=e.cause().to_owned();s.faults.push(Fault::Native(e));return Err(cause);}};
            s.canonical_native=Some(opened.owner);
            let genesis=db.verified_genesis()?;
            let g=&genesis.genesis;
            match CanonicalStore::from_existing_connection(opened.connection,&g.anchor(),&g.state,g.root,g.t0,g.target){
                Ok(v)=>s.views.push(MD::new(v)),Err(e)=>{s.faults.push(Fault::Canonical(e));return Err("installed original canonical replay refused".into());}}
            db.recheck_canonical(&s.views[0])?;
            // Three additional views use the SAME private native session. Full
            // authenticated replay is repeated, never a raw Connection clone.
            for _ in 0..3{
                let connection=s.canonical_native.as_mut().ok_or("same native canonical session absent")?
                    .open_same_group(&db.canonical_request()?)?;
                let g=&db.verified_genesis()?.genesis;
                match CanonicalStore::from_existing_connection(connection,&g.anchor(),&g.state,g.root,g.t0,g.target){
                    Ok(v)=>s.views.push(MD::new(v)),Err(e)=>{s.faults.push(Fault::Canonical(e));return Err("installed same-group canonical replay refused".into());}}
            }
            s.authority=Some(MD::new(InstalledCounterAuthority::for_consumer(&s.views[0],node)?));
            let authority=s.authority.as_mut().ok_or("original counter consumer authority absent")?;
            if authority.context()!=db.namespace()?{return Err("installed signer/counter/database own context differs".into());}
            s.roles=Some(MD::new(InstalledRoleInputs::open_existing(authority,&s.views[0])?));
            let signer=s.signer.as_mut().ok_or("original signer selection absent")?;
            signer.recheck(db)?;
            let (tool_path,tool_pin)=signer.tool_selection()?;
            s.tool=Some(MD::new(crate::activation_private_owner_v1::linux_tools::ToolPin::open_static_installed(&tool_path,tool_pin)
                .map_err(|_|"installed selected static activation tool refused")?));
            match crate::activation_private_owner_v1::linux_tools::InstalledMakeCredential::from_installed(s.tool.take().ok_or("original tool absent")?){
                Ok(v)=>s.maker=Some(MD::new(v)),Err(e)=>{s.faults.push(Fault::Maker(e));return Err("installed MakeCredential owner refused".into());}}
            let own_genesis=db.original_genesis_bytes()?.to_vec();
            let clock=InstalledPrivateClockSession::connect_on_private_worker(signer.clock_record()?.to_vec(),own_genesis,
                s.start.take().ok_or("original clock start consumed")?).map_err(|e|format!("installed private clock: {}",e.description()))?;
            s.clock=Some(MD::new(Arc::new(clock)));
            // The unlock connection has an independently current authentic
            // selection and its own SAME-group canonical view. No password is
            // supplied by the caller or read from stdin/environment/JSON.
            let unlock_chain=s.views.pop().ok_or("original unlock canonical view absent")?;
            let unlock_authority=InstalledCounterAuthority::for_consumer(&unlock_chain,node)?;
            s.unlock=Some(MD::new(InstalledUnlockInput::connect(unlock_authority,
                MD::into_inner(unlock_chain),Arc::clone(&s.stop))?));
            let pins=s.roles.as_mut().ok_or("original role input absent")?.commitments_checked(authority,&s.views[0])?;
            let passwords=s.unlock.as_mut().ok_or("original secret input absent")?.read_selected(pins.0,pins.1)?;
            // The exact acknowledged input returns its still-owned canonical
            // view only after original native close, never by reopening a path.
            let unlock=s.unlock.take().ok_or("same secret input absent")?;
            match MD::into_inner(unlock).close(){Ok(chain)=>s.views.push(chain),Err(e)=>{
                s.faults.push(Fault::UnlockClose(e));return Err("installed secret input original close retained".into());}}
            let endpoint_chain=s.views.pop().ok_or("original endpoint canonical view absent")?;
            let endpoint_authority=InstalledCounterAuthority::for_consumer(&endpoint_chain,node)?;
            let profile=endpoint_authority.profile().clone();let nv=endpoint_authority.nv_public_sha256();
            let context=endpoint_authority.context();
            s.endpoint=Some(MD::new(InstalledCounterConnection::connect(endpoint_authority,
                MD::into_inner(endpoint_chain),Arc::clone(&s.stop))?));
            let endpoint=s.endpoint.take().ok_or("original NV endpoint absent")?;
            match Counter::from_retained_endpoint(endpoint,profile,nv,context){Ok(v)=>s.counter=Some(MD::new(v)),
                Err(e)=>{let cause=e.cause().to_owned();s.faults.push(Fault::Endpoint(e));return Err(cause);}}
            let (node_cipher,continuity_cipher)=s.roles.as_mut().ok_or("original role inputs absent")?.borrow_checked(authority,&s.views[0])?;
            let chain=s.views.pop().ok_or("original backend canonical view absent")?;
            let counter=s.counter.take().ok_or("same original counter absent")?;
            match Backend::assemble_retained(chain,node,counter,continuity_cipher,passwords.continuity(),node_cipher,passwords.node()){
                Ok(v)=>s.backend=Some(MD::new(v)),Err(e)=>{let cause=e.cause().to_owned();s.faults.push(Fault::Assembly(e));return Err(cause);}}
            drop(passwords);
            db.recheck_canonical(&s.views[0])?;signer.recheck(db)?;
            let opened=match NativeExistingDatabase::open(&db.counter_request(&s.views[0])?,false){Ok(v)=>v,Err(e)=>{
                let cause=e.cause().to_owned();s.faults.push(Fault::Native(e));return Err(cause);}};
            s.counter_native=Some(opened.owner);
            let backend=s.backend.as_mut().ok_or("same backend absent")?;
            match CounterStore::from_existing_connection(opened.connection,context,None,&mut **backend){
                Ok(v)=>s.store=Some(MD::new(v)),Err(e)=>{s.faults.push(Fault::Counter(e));return Err("installed V2 snapshot/NV recovery refused".into());}}
            let store=s.store.take().ok_or("same V2 store absent")?;
            match VoterActor::from_existing_store(store,node,&mut s.views[0],&mut **backend){
                Ok(v)=>s.actor=Some(MD::new(v)),Err(e)=>{s.faults.push(Fault::Actor(e));return Err("installed V2 actor recovery refused".into());}}
            let chain=s.views.pop().ok_or("original runtime canonical view absent")?;
            let pool=Mempool::open(&db.cache_directory()?.join("pending.sqlite"),
                db.verified_genesis()?.genesis.identity,db.verified_genesis()?.genesis.fingerprint,MAX_PENDING_BYTES)
                .map_err(|_|"installed reversible pending cache refused")?;
            match HybridRuntime::from_existing_chain(chain,pool){Ok(v)=>s.runtime=Some(MD::new(v)),Err(e)=>{
                s.faults.push(Fault::Runtime(e));return Err("installed existing runtime refused".into());}}
            let runtime=s.runtime.take().ok_or("same runtime absent")?;
            let actor=s.actor.take().ok_or("same actor absent")?;let backend=s.backend.take().ok_or("same backend absent")?;
            match VotingRuntime::from_existing_actor(runtime,actor,backend){Ok(v)=>s.voting=Some(MD::new(v)),Err(e)=>{
                s.faults.push(Fault::Voting(e));return Err("installed voting runtime refused".into());}}
            let clock=s.clock.as_ref().ok_or("same installed private clock absent")?;
            clock.recheck_installed_only().map_err(|_|"installed current clock guard refused")?;
            let voter=s.voting.take().ok_or("same voting runtime absent")?;
            let chain=s.views.pop().ok_or("original activation canonical view absent")?;
            let elapsed_concrete=Arc::clone(&**clock);
            let vote_concrete=Arc::clone(&**clock);
            let elapsed:Arc<dyn mutiny_consensus_v8::activation_attestation_v1::Elapsed>=elapsed_concrete;
            let vote_clock:Arc<dyn mutiny_consensus_v8::vote_clock_v1::VoteClock>=vote_concrete;
            match Owner::from_existing_production_retained(voter,chain,Duration::from_nanos(signer.lifetime_ns()?),elapsed,vote_clock){
                Ok(v)=>s.owner=Some(MD::new(v)),Err(e)=>{s.faults.push(Fault::Owner(e));return Err("installed activation owner refused".into());}}
            s.frozen=false;Ok(())
        })();
        match initialized{Ok(())=>Ok(out),Err(cause)=>Err(InstalledFactoryRefusal{cause,owner:MD::new(out)})}
    }
    fn recheck_entry(&mut self)->Result<()>{
        if self.state.frozen||self.state.original_worker!=std::thread::current().id(){
            return Err("installed private factory frozen/wrong original worker".into());}
        let s=&mut **self.state;
        let chain=s.owner.as_ref().ok_or("original installed owner absent")?.own_canonical();
        let db=s.databases.as_mut().ok_or("original installed database selection absent")?;
        db.recheck_canonical(chain)?;
        s.signer.as_mut().ok_or("original installed signer selection absent")?.recheck(db)?;
        s.roles.as_mut().ok_or("original installed roles absent")?.commitments_checked(
            s.authority.as_mut().ok_or("original installed authority absent")?,chain)?;
        s.canonical_native.as_mut().ok_or("original canonical native session absent")?.recheck()?;
        s.counter_native.as_mut().ok_or("original counter native session absent")?.recheck()?;
        s.clock.as_ref().ok_or("original installed private clock absent")?.recheck_installed_only()
            .map_err(|_|"installed original clock guard refused")?;
        Ok(())
    }
    pub(crate) fn request(&mut self,step:mutiny_consensus_v8::bft::Step,block:Option<Hash>,pol:Option<u64>)
        ->Result<Option<mutiny_consensus_v8::activation_attestation_v1::Request>>{
        let result=(||{self.recheck_entry()?;
            let value=self.state.owner.as_mut().ok_or("original installed owner absent")?
                .request(step,block,pol).map_err(|_|"installed native activation request refused")?;
            self.recheck_entry()?;Ok(value)})();
        if result.is_err(){self.state.frozen=true;if let Some(owner)=self.state.owner.as_mut(){owner.cancel();}}
        result
    }
    pub(crate) fn sign(&mut self,step:mutiny_consensus_v8::bft::Step,block:Option<Hash>,pol:Option<u64>,
        targets:Option<crate::activation_private_owner_v1::OwnedTargets>)->Result<mutiny_consensus_v8::continuity_v2::Vote>{
        let result=(||{self.recheck_entry()?;
            let s=&mut **self.state;
            let vote=s.owner.as_mut().ok_or("original installed owner absent")?.fresh_sign_with_installed_session(
                s.clock.as_ref().ok_or("original installed clock absent")?,
                &mut **s.maker.as_mut().ok_or("original installed MakeCredential absent")?,step,block,pol,targets)
                .map_err(|_|"installed native private sign refused")?;
            self.recheck_entry()?;Ok(vote)})();
        // A post-current refusal withholds delivery without deleting any exact
        // durable signed result or resetting the monotonic counter.
        if result.is_err(){self.state.frozen=true;if let Some(owner)=self.state.owner.as_mut(){owner.cancel();}}
        result
    }
    /// Original private canonical dispatch; no Arc/clone/reopened runtime or socket I/O.
    pub(crate) fn dispatch_message(&mut self,message:&mut crate::hybrid_installed_daemon_v2::InstalledPeerMessage){
        let result=(||->Result<()>{self.recheck_entry()?;
            self.state.owner.as_mut().ok_or("original installed owner absent")?.dispatch_installed_message(message)?;
            self.recheck_entry()?;message.accept_after_current()
        })();
        if let Err(cause)=result{message.refuse(cause);self.state.frozen=true;
            if let Some(owner)=self.state.owner.as_mut(){owner.cancel();}}
    }
    /// Admission is already stopped on the ORIGINAL private worker. Counter
    /// cancellation is NOT signaled before the native snapshot/current check.
    /// Every consuming transfer returns original typed custody on uncertainty.
    pub(crate) fn close_on_private_worker(mut self)->std::result::Result<(),InstalledFactoryRefusal>{
        let result=(||->Result<()>{
            self.recheck_entry()?;let s=&mut **self.state;s.frozen=true;
            let owner=MD::into_inner(s.owner.take().ok_or("original installed owner absent")?).into_existing_parts();
            s.views.push(owner.own_chain);
            let parts=match MD::into_inner(owner.voter).into_existing_parts(){Ok(v)=>v,Err(e)=>{
                s.faults.push(Fault::Voting(e));return Err("installed original voter shutdown retained".into());}};
            s.store=Some(parts.store);s.backend=Some(parts.backend);
            s.views.push(MD::into_inner(parts.runtime).into_existing_chain());
            let backend=MD::into_inner(s.backend.take().ok_or("original shutdown backend absent")?).into_existing_parts();
            s.views.push(backend.chain);s.counter=Some(backend.counter);
            match MD::into_inner(s.store.take().ok_or("original shutdown snapshot absent")?).close_existing(){
                Ok(())=>(),Err(e)=>{s.faults.push(Fault::CounterClose(e));return Err("installed snapshot SQLite close retained".into());}}
            let counter=s.counter.take().ok_or("original shutdown counter absent")?;
            s.endpoint=Some(match MD::into_inner(counter).into_existing_endpoint(){Ok(v)=>v,Err(e)=>{
                s.faults.push(Fault::FrozenCounter(e));return Err("installed counter unknown outcome retained".into());}});
            match MD::into_inner(s.endpoint.take().ok_or("original endpoint absent")?).close(){
                Ok(chain)=>s.views.push(chain),Err(e)=>{s.faults.push(Fault::UnlockClose(e));return Err("installed endpoint close retained".into());}}
            let roles=s.roles.take().ok_or("original roles absent")?;
            if let Err(retained)=MD::into_inner(roles).close(s.authority.as_mut().ok_or("original authority absent")?,&s.views[0]){
                match retained{crate::hybrid_installed_role_inputs_v2::RoleInputsClose::Retained(v)=>s.roles=Some(v)};
                return Err("installed role original close retained".into());}
            if let Err(e)=MD::into_inner(s.maker.take().ok_or("original maker absent")?).close_retained(){
                s.faults.push(Fault::Maker(e));return Err("installed MakeCredential original close retained".into());}
            // Authority/current/peer close implementations remain part of the
            // joined source review; a bare error never becomes a close receipt.
            if let Err(original)=MD::into_inner(s.authority.take().ok_or("original authority absent")?).recheck_and_close(&s.views[0]){
                s.faults.push(Fault::AuthorityClose(original));return Err("original installed authority close retained".into());
            }
            let clock=s.clock.take().ok_or("original clock absent")?;
            let clock=match Arc::try_unwrap(MD::into_inner(clock)){Ok(v)=>v,Err(v)=>{
                s.clock=Some(MD::new(v));return Err("installed private clock still shared".into());}};
            let joined=clock.join().map_err(|_|"original private clock worker join retained")?;
            match joined.close_retained(){Ok(report) if report.retained_handles_closed()=>(),Ok(_)=>{
                return Err("original private clock close incomplete".into());},Err(v)=>{
                s.faults.push(Fault::JoinedClock(v));return Err("original private clock retained native close".into());}}
            while let Some(chain)=s.views.pop(){match MD::into_inner(chain).close_existing(){Ok(())=>(),Err(e)=>{
                s.faults.push(Fault::CanonicalClose(e));return Err("original canonical SQLite close retained".into());}}}
            for slot in [&mut s.counter_native,&mut s.canonical_native]{
                let owner=MD::into_inner(slot.take().ok_or("original native database group absent")?);
                match owner.close_after_connections(){Ok(report) if report.retained_handles_closed()=>(),
                    Ok(_)=>return Err("original native database close incomplete".into()),Err(e)=>{
                        s.faults.push(Fault::Native(e));return Err("original native database group retained".into());}}
            }
            let db=s.databases.as_mut().ok_or("original database selection absent")?;
            if let Err(e)=MD::into_inner(s.signer.take().ok_or("original signer selection absent")?).close(db){
                s.faults.push(Fault::Signer(e));return Err("original signer selection close retained".into());}
            match MD::into_inner(s.databases.take().ok_or("original database selection absent")?).close(){
                Ok(())=>(),Err(e)=>{s.faults.push(Fault::Database(e));return Err("original database selection close retained".into());}}
            Ok(())
        })();
        match result{Ok(())=>{unsafe{MD::drop(&mut self.state.stop);MD::drop(&mut self.state)};Ok(())},
            Err(cause)=>Err(InstalledFactoryRefusal{cause,owner:MD::new(self)})}
    }
}
