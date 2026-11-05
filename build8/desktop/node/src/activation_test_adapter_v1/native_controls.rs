//! Executable native bridge controls, called only with an existing genuinely
//! prepared VotingRuntime. No Scope/Admission/Material constructors or fixture
//! Genesis are exposed. Missing native fixture/policy/clock/phase fails the
//! suite; this is NOT an automatically passing parser model or a TPM result.
//! The cryptographic adapter below is explicitly a private secret-return model;
//! separate vetted-tool/simulator interoperability is mandatory.
use super::{bridge,delivery::Delivery,exchange::{ChallengeFrame,ResponseFrame},provider::OwnContext,Error,Result};
use mutiny_consensus_v8::{Hash,bft::Step,activation_attestation_v1::{EncryptedCredential,Failure,MakeCredential},
    counter_voter_v2::CounterSigningBackend,counter_voter::CounterVoterError,voter_actor_v2::ActorError};
use mutinyd_v8::hybrid_voter_v2::{VotingRuntime,VotingError};
use zeroize::Zeroizing;
struct PrivateModel {next:u64,secrets:std::collections::BTreeMap<u64,Zeroizing<[u8;32]>>}
impl PrivateModel {fn new()->Self{Self{next:0,secrets:Default::default()}}
    fn response(&self,frame:&ChallengeFrame)->Result<Zeroizing<Vec<u8>>>{
        let values=frame.items.iter().map(|item|{
            let n=u64::from_be_bytes(item.credential.as_slice().try_into().map_err(|_|Error::Response)?);
            let secret=self.secrets.get(&n).ok_or(Error::Response)?;
            Ok(Zeroizing::new(**secret))
        }).collect::<Result<Vec<_>>>()?;
        ResponseFrame::new(frame,values)?.encode_private()
    }
}
impl MakeCredential for PrivateModel {
    fn make_credential(&mut self,ek:&[u8],name:&[u8;34],secret:&[u8;32])->std::result::Result<EncryptedCredential,Failure>{
        mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(ek).map_err(|_|Failure::Classes)?;
        if name[..2]!=[0,11]||secret==&[0;32]{return Err(Failure::Material);}
        self.next=self.next.checked_add(1).ok_or(Failure::Bounds)?;
        self.secrets.insert(self.next,Zeroizing::new(*secret));
        EncryptedCredential::new(self.next.to_be_bytes().to_vec(),vec![1])
    }
}
fn missing<B:CounterSigningBackend>(voter:&mut VotingRuntime<B>,step:Step,block:Option<Hash>,pol:Option<u64>)->Result<()> {
    // Require the specific native activation verdict; a clock/phase/custody
    // refusal cannot masquerade as a cancellation test.
    match voter.sign(step,block,pol) {
        Err(VotingError::Actor(ActorError::Voter(CounterVoterError::Activation(Failure::Missing))))=>Ok(()),
        _=>Err(Error::Current),
    }
}
fn return_all<B:CounterSigningBackend>(voter:&mut VotingRuntime<B>,delivery:&mut Delivery,model:&PrivateModel,
    expected:&std::collections::BTreeSet<(u32,u8,Hash)>)->Result<()> {
    let mut seen=std::collections::BTreeSet::new();
    while seen.len()<expected.len(){
        let frame=delivery.issue()?;
        let pairs=frame.items.iter().map(|c|(c.admission,c.class,c.identity)).collect::<Vec<_>>();
        let raw=model.response(frame)?;
        for item in pairs{if !expected.contains(&item)||!seen.insert(item){return Err(Error::Context);}}
        bridge::accept(voter,delivery,raw)?;
    }
    if &seen!=expected{return Err(Error::Response);}Ok(())
}
pub struct NativeCollectorReceipt {pub scope:Hash,pub class_count:usize,pub partial_refused:bool,
    pub mismatched_context_refused:bool,pub native_missing_after_cancel:bool,pub all_classes_completed:bool}
/// Call AFTER native proposal execution/preparation, real custody opening and
/// explicit nondefault local elapsed/qualified vote clocks. Caller is required
/// to label its public TEST initial context and authentic outer carriers. No
/// fixture generation, peer-root acceptance or default lifetime occurs here.
pub fn run_with_prepared<B:CounterSigningBackend>(voter:&mut VotingRuntime<B>,provider:&mut OwnContext<'_>,
    step:Step,block:Option<Hash>,pol:Option<u64>)->Result<NativeCollectorReceipt>{
    let request=voter.activation_request(step,block,pol).map_err(|_|Error::Current)?.ok_or(Error::Context)?;
    let mut expected=std::collections::BTreeSet::new();
    for (i,a) in request.scope().admissions().iter().enumerate(){
        if a.endorsements().len()<2{return Err(Error::Bounds);}
        for (c,id) in a.endorsements().iter().enumerate(){expected.insert((i as u32,c as u8,*id));}
    }
    if expected.len()<2{return Err(Error::Bounds);}
    let scope=request.scope().commitment();
    let mut model=PrivateModel::new();
    // Partial issued collector cannot complete. The bridge cancels actual gate.
    let mut partial=bridge::begin(voter,provider,&mut model,step,block,pol)?;
    partial.issue()?;
    if bridge::complete(voter,provider,partial)!=Err(Error::Response){return Err(Error::Response);}
    missing(voter,step,block,pol)?;
    // A valid private response from an earlier attempt is rejected by exact
    // session/context comparison, not merely a bad parser or missing bytes.
    let mut old=bridge::begin(voter,provider,&mut model,step,block,pol)?;
    let old_raw=model.response(old.issue()?)?;drop(old);voter.cancel_activation();
    let mut current=bridge::begin(voter,provider,&mut model,step,block,pol)?;
    current.issue()?;
    if bridge::accept(voter,&mut current,old_raw)!=Err(Error::Context){return Err(Error::Response);}
    missing(voter,step,block,pol)?;
    // Native receipt/reducer, exact own canonical material and ALL classes are
    // still required for the final positive after both cancellation refusals.
    let mut complete=bridge::begin(voter,provider,&mut model,step,block,pol)?;
    return_all(voter,&mut complete,&model,&expected)?;
    bridge::complete(voter,provider,complete)?;
    Ok(NativeCollectorReceipt{scope,class_count:expected.len(),partial_refused:true,
        mismatched_context_refused:true,native_missing_after_cancel:true,all_classes_completed:true})
}
