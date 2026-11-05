//! Existing-only native activation coordinator with separate TEST and internal
//! normal constructors. Neither constructor issues provider qualification.
//! Caller reopens existing custody/canonical stores and qualified clocks first.
//! This owner grants no provisioning, initialization, key export or TPM lineage.
#[path="activation_test_adapter_v1/exchange.rs"] pub mod exchange;
#[path="activation_test_adapter_v1/channel.rs"] pub mod channel;
#[path="activation_test_adapter_v1/socket.rs"] pub mod socket;
#[path="activation_test_adapter_v1/delivery.rs"] mod delivery;
#[path="activation_test_adapter_v1/provider.rs"] mod provider;
#[cfg(target_os="linux")]
#[path="activation_test_adapter_v1/linux_tools.rs"] pub mod linux_tools;
#[path="activation_test_adapter_v1/tools_format.rs"] mod tools_format;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error { Bounds,Codec,Context,Authority,Production,Current,ToolPin,ToolIo,
    ToolExit,ActivationRejected,Expired,Endpoint,Response,Unsupported }
pub type Result<T>=std::result::Result<T,Error>;
use crate::hybrid_voter_v2::{VotingRuntime,VotingError};
use mutiny_consensus_v8::{Hash,bft::Step,canonical_store_v2::CanonicalStore,
    continuity_v2::Vote,counter_voter_v2::CounterSigningBackend,
    activation_attestation_v1::{Request,MakeCredential,Elapsed},provenance::AdmissionClass,
    vote_clock_v1::VoteClock};
use std::{collections::BTreeMap,sync::Arc,time::Duration};
type Route=(u32,u8,Hash);
#[derive(Debug)]
pub enum OwnerError { Private(Error),Voter(VotingError) }
impl From<Error> for OwnerError {fn from(e:Error)->Self{Self::Private(e)}}
impl From<VotingError> for OwnerError {fn from(e:VotingError)->Self{Self::Voter(e)}}
/// Every socket is constructed only from an actual completed pinned hybrid
/// Session. Exact native admission/class/EK routing is checked before issuance.
/// Targets are consumed once; an interrupted attempt cannot recycle channels.
pub struct OwnedTargets {request:Request,routes:BTreeMap<Route,socket::PrivateSocket>}
impl OwnedTargets {
    pub fn for_request(request:&Request,routes:BTreeMap<Route,socket::PrivateSocket>)->Result<Self>{
        let mut expected=std::collections::BTreeSet::new();
        for (i,a) in request.scope().admissions().iter().enumerate(){
            for (j,id) in a.endorsements().iter().enumerate(){
                if !expected.insert((u32::try_from(i).map_err(|_|Error::Bounds)?,
                    u8::try_from(j).map_err(|_|Error::Bounds)?,*id)){return Err(Error::Context);}
            }
        }
        if expected.is_empty()||routes.keys().copied().collect::<std::collections::BTreeSet<_>>()!=expected{
            return Err(Error::Endpoint);
        }
        let parent=request.scope().parent();
        if routes.values().any(|s|!s.matches_network(parent.genesis,parent.fingerprint)){
            return Err(Error::Context);
        }
        Ok(Self{request:request.clone(),routes})
    }
}
pub struct Owner<B:CounterSigningBackend> {voter:VotingRuntime<B>,own_chain:CanonicalStore,
    class:AdmissionClass}
pub(crate) struct ExistingOwnerRefusal<B:CounterSigningBackend>{cause:OwnerError,
    owner:std::mem::ManuallyDrop<Owner<B>>}
impl<B:CounterSigningBackend> ExistingOwnerRefusal<B>{pub(crate) fn cause(&self)->&OwnerError{&self.cause}}
pub(crate) struct ExistingOwnerParts<B:CounterSigningBackend>{
    pub(crate) voter:std::mem::ManuallyDrop<VotingRuntime<B>>,
    pub(crate) own_chain:std::mem::ManuallyDrop<CanonicalStore>,
}
impl<B:CounterSigningBackend> Owner<B> {
    /// Actual native factory entry, after SAME existing store/backend/runtime
    /// composition. No by-name snapshot open occurs. Whole incoming owners are
    /// retained before class/current/configuration effects or an unwind.
    pub(crate) fn from_existing_production_retained(
        voter:std::mem::ManuallyDrop<VotingRuntime<B>>,
        own_chain:std::mem::ManuallyDrop<CanonicalStore>,
        lifetime:Duration,elapsed:Arc<dyn Elapsed>,vote_clock:Arc<dyn VoteClock>)
        ->std::result::Result<Self,ExistingOwnerRefusal<B>>{
        let mut owner=std::mem::ManuallyDrop::new(Self{
            voter:std::mem::ManuallyDrop::into_inner(voter),
            own_chain:std::mem::ManuallyDrop::into_inner(own_chain),class:AdmissionClass::Production});
        let checked=(||->std::result::Result<(),OwnerError>{
            let(_,state)=owner.own_chain.load().map_err(|_|Error::Current)?;
            if state.admission_class().map_err(|_|Error::Context)?!=AdmissionClass::Production{
                return Err(Error::Context.into());}
            let own_head=owner.voter.validator().head().map_err(|_|Error::Current)?;
            let(authority,_)=owner.own_chain.verified_activation_parent(&own_head).map_err(|_|Error::Context)?;
            if authority.activation_rule!=Some(mutiny_consensus_v8::activation_attestation_v1::rule_commitment()){
                return Err(Error::Context.into());}
            owner.voter.configure_activation(lifetime,elapsed)?;
            owner.voter.set_vote_clock(vote_clock);Ok(())
        })();
        match checked{Ok(())=>Ok(std::mem::ManuallyDrop::into_inner(owner)),
            Err(cause)=>Err(ExistingOwnerRefusal{cause,owner})}
    }
    /// Private signer-thread entry over the SINGLE installed clock session.
    /// The pure gate alone decides whether to request a NEW live quote. Nil and
    /// exact durable replay retain their zero-RPC exemption. Each local reading
    /// and required Elapsed capture is reconstructed CURRENT by the session.
    pub(crate) fn fresh_sign_with_installed_session(&mut self,
        clock:&crate::host_clock::InstalledPrivateClockSession,maker:&mut dyn MakeCredential,
        step:Step,block:Option<Hash>,pol:Option<u64>,targets:Option<OwnedTargets>)
        ->std::result::Result<Vote,OwnerError>{
        let result=(||{
            if self.class!=AdmissionClass::Production{return Err(Error::Context.into());}
            clock.recheck_installed_only().map_err(|_|Error::Current)?;
            if self.voter.clock_query_required(step,block,pol)?{
                clock.prepare_next_vote_attempt().map_err(|_|Error::Current)?;
            }
            let vote=self.fresh_sign(maker,step,block,pol,targets)?;
            // A failed post-current check refuses delivery while retaining the
            // already durable exact signature in the original voter snapshot.
            clock.recheck_installed_only().map_err(|_|Error::Current)?;Ok(vote)
        })();
        if result.is_err(){self.cancel();}result
    }
    /// The registered factory dispatches against the SAME voter/runtime on its original worker.
    #[cfg(target_os="linux")]
    pub(crate) fn dispatch_installed_message(&mut self,message:&mut crate::hybrid_installed_daemon_v2::InstalledPeerMessage)
        ->std::result::Result<(),String>{
        if self.class!=AdmissionClass::Production{return Err("installed private dispatch requires original NORMAL owner".into());}
        message.dispatch_original(self.voter.validator())
    }
    /// Called only by the stopped ORIGINAL private worker. Transfer SAME
    /// owners; actual snapshot/SQLite/native/clock consuming closes remain
    /// independently checked by the enclosing installed factory.
    pub(crate) fn into_existing_parts(mut self)->ExistingOwnerParts<B>{
        self.cancel();let Self{voter,own_chain,..}=self;
        ExistingOwnerParts{voter:std::mem::ManuallyDrop::new(voter),
            own_chain:std::mem::ManuallyDrop::new(own_chain)}
    }
    /// Explicit TEST application entry after bootstrap has exited. The caller
    /// reopens its matching protected provider first; this path never creates a
    /// voter snapshot/counter or repairs missing state. Production remains closed.
    pub fn open_existing_test(mut runtime:crate::hybrid_runtime_v2::HybridRuntime,
        custody:&std::path::Path,node:Hash,backend:B,own_chain:CanonicalStore,
        lifetime:Duration,elapsed:Arc<dyn Elapsed>,vote_clock:Arc<dyn VoteClock>)
        ->std::result::Result<Self,OwnerError>{
        let(_,state)=own_chain.load().map_err(|_|Error::Current)?;
        if state.admission_class().map_err(|_|Error::Context)?==AdmissionClass::Production{
            return Err(Error::Production.into());
        }
        // Compare independent trusted canonical contexts before touching the
        // existing counter/snapshot owner, even on a mismatched runtime input.
        let head=runtime.head().map_err(|_|Error::Current)?;
        own_chain.verified_activation_parent(&head).map_err(|_|Error::Context)?;
        let voter=VotingRuntime::open(runtime,custody,node,None,backend)?;
        Self::from_existing_test(voter,own_chain,lifetime,elapsed,vote_clock)
    }
    /// Existing-only host factory: no new counter, reservation, provider or
    /// journal. Both caller-supplied stores must have been independently opened
    /// from the same trusted Genesis. No default local freshness/clock exists.
    pub fn from_existing_test(mut voter:VotingRuntime<B>,own_chain:CanonicalStore,
        lifetime:Duration,elapsed:Arc<dyn Elapsed>,vote_clock:Arc<dyn VoteClock>)
        ->std::result::Result<Self,OwnerError>{
        let (_,state)=own_chain.load().map_err(|_|Error::Current)?;
        let class=state.admission_class().map_err(|_|Error::Context)?;
        if class==AdmissionClass::Production{
            return Err(Error::Production.into());
        }
        Self::from_existing_for_class(voter,own_chain,class,lifetime,elapsed,vote_clock)
    }
    /// Internal normal factory entry. The installer must already own the
    /// qualified real provider, native-held existing stores/keys and selected
    /// clock. This cannot initialize, repair, mint keys or substitute TEST
    /// custody. Caller-supplied generic B conveys no production qualification.
    pub(crate) fn open_existing_production(mut runtime:crate::hybrid_runtime_v2::HybridRuntime,
        custody:&std::path::Path,node:Hash,backend:B,own_chain:CanonicalStore,
        lifetime:Duration,elapsed:Arc<dyn Elapsed>,vote_clock:Arc<dyn VoteClock>)
        ->std::result::Result<Self,OwnerError>{
        let(_,state)=own_chain.load().map_err(|_|Error::Current)?;
        if state.admission_class().map_err(|_|Error::Context)?!=AdmissionClass::Production{
            return Err(Error::Context.into());
        }
        let head=runtime.head().map_err(|_|Error::Current)?;
        own_chain.verified_activation_parent(&head).map_err(|_|Error::Context)?;
        let voter=VotingRuntime::open(runtime,custody,node,None,backend)?;
        Self::from_existing_for_class(voter,own_chain,AdmissionClass::Production,lifetime,elapsed,vote_clock)
    }
    fn from_existing_for_class(mut voter:VotingRuntime<B>,own_chain:CanonicalStore,
        class:AdmissionClass,lifetime:Duration,elapsed:Arc<dyn Elapsed>,vote_clock:Arc<dyn VoteClock>)
        ->std::result::Result<Self,OwnerError>{
        let(_,state)=own_chain.load().map_err(|_|Error::Current)?;
        if state.admission_class().map_err(|_|Error::Context)?!=class{return Err(Error::Context.into());}
        let own_head=voter.validator().head().map_err(|_|Error::Current)?;
        let (authority,_)=own_chain.verified_activation_parent(&own_head).map_err(|_|Error::Context)?;
        if authority.activation_rule!=Some(mutiny_consensus_v8::activation_attestation_v1::rule_commitment()){
            return Err(Error::Context.into());
        }
        voter.configure_activation(lifetime,elapsed)?;voter.set_vote_clock(vote_clock);
        Ok(Self{voter,own_chain,class})
    }
    pub fn request(&mut self,step:Step,block:Option<Hash>,pol:Option<u64>)
        ->std::result::Result<Option<Request>,OwnerError>{
        Ok(self.voter.activation_request(step,block,pol)?)
    }
    /// Execute on an exclusive retained private worker, outside the UI actor.
    /// Canonical scope/current phase and the actual backend-entry expiry checks
    /// remain native. A network receipt alone never grants private signing.
    pub fn fresh_sign(&mut self,maker:&mut dyn MakeCredential,step:Step,
        block:Option<Hash>,pol:Option<u64>,targets:Option<OwnedTargets>)
        ->std::result::Result<Vote,OwnerError>{
        let result=(||{
            let request=self.voter.activation_request(step,block,pol)?;
            if let Some(request)=request {
                let mut targets=targets.ok_or(Error::Endpoint)?;
                if targets.request!=request{return Err(Error::Context.into());}
                let mut current=if self.class==AdmissionClass::Production{
                    provider::OwnContext::production_only(&self.own_chain,self.voter.signer_node())?
                }else{
                    provider::OwnContext::test_only(&self.own_chain,self.voter.signer_node())?
                };
                let material=current.material(&request)?;
                let exchange=self.voter.begin_activation(step,block,pol,&material,&mut current,maker)?;
                if exchange.request!=request{return Err(Error::Context.into());}
                let mut delivery=delivery::Delivery::new(exchange)?;
                while !delivery.completed()? {
                    let frame=delivery.issue_one()?;
                    let item=frame.items.first().ok_or(Error::Bounds)?;
                    if frame.items.len()!=1{return Err(Error::Bounds.into());}
                    let target=targets.routes.get_mut(&(item.admission,item.class,item.identity)).ok_or(Error::Endpoint)?;
                    target.send_challenge(frame)?;
                    let response=target.receive_response(frame)?;
                    delivery.accept_private(response.encode_private()?)?;
                }
                let (session,exact,responses)=delivery.finish()?;
                self.voter.complete_activation(session,&exact,responses,&mut current)?;
            } else if targets.is_some(){return Err(Error::Context.into());}
            Ok(self.voter.sign(step,block,pol)?)
        })();
        // Also cancels a capability on backend/current/clock failure. Native
        // custody preserves its own durable fault and unsigned-reservation state.
        if result.is_err(){self.voter.cancel_activation();}result
    }
    /// Exact already-signed durable retransmission remains a native replay;
    /// unsigned Required reservations still refuse without renewed activation.
    pub fn replay(&mut self,step:Step)->std::result::Result<Option<Vote>,OwnerError>{
        Ok(self.voter.replay(step)?)
    }
    pub fn cancel(&mut self){self.voter.cancel_activation();}
    pub(crate) fn own_canonical(&self)->&CanonicalStore{&self.own_chain}
    pub fn voter_mut(&mut self)->&mut VotingRuntime<B>{&mut self.voter}
}

/// Bounded existing public unsigned-vote format for a protected TEST backend.
/// This creates no signature, reservation, permit or authority. The caller must
/// check the returned vote against its own current canonical ParentVoter/roots
/// and the opaque permit again at the actual private-key entry.
pub fn decode_reserved_vote(message:&[u8])->Result<Vote>{
    if message.is_empty()||message.len()>mutiny_consensus_v8::continuity_v2::MAX_VOTE_BYTES{
        return Err(Error::Bounds);
    }
    let mut encoded=minicbor::Encoder::new(Vec::with_capacity(message.len()+1424));
    encoded.array(3).map_err(|_|Error::Codec)?.bytes(message).map_err(|_|Error::Codec)?
        .bytes(&[0;114]).map_err(|_|Error::Codec)?.bytes(&[0;1280]).map_err(|_|Error::Codec)?;
    let vote=Vote::decode(&encoded.into_writer()).map_err(|_|Error::Codec)?;
    if vote.unsigned().map_err(|_|Error::Codec)?!=message{return Err(Error::Codec);}
    Ok(vote)
}
