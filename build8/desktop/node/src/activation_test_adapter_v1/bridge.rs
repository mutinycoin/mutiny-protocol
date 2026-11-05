//! Explicit TEST-only orchestration of existing native voter APIs. No raw vote
//! signing, custody initialization, scope fabrication or production factory.
//! The host schedules this off its actor/UI thread and retains exclusive voter
//! ownership. Peer/source observations never substitute for native completion.
use super::{delivery::Delivery,provider::OwnContext,Error,Result};
use mutiny_consensus_v8::{Hash,bft::Step,activation_attestation_v1::MakeCredential,
    counter_voter_v2::CounterSigningBackend};
use mutinyd_v8::hybrid_voter_v2::VotingRuntime;
pub fn begin<B:CounterSigningBackend>(voter:&mut VotingRuntime<B>,provider:&mut OwnContext<'_>,
    adapter:&mut dyn MakeCredential,step:Step,block:Option<Hash>,pol:Option<u64>)->Result<Delivery>{
    let result=(||{
        let request=voter.activation_request(step,block,pol).map_err(|_|Error::Current)?.ok_or(Error::Context)?;
        if request.signer()!=voter.signer_node(){return Err(Error::Authority);}
        let materials=provider.material(&request)?;
        let exchange=voter.begin_activation(step,block,pol,&materials,provider,adapter).map_err(|_|Error::Current)?;
        // The actual locked candidate can change while material is prepared;
        // equality is mandatory before any private request is delivered.
        if exchange.request!=request{return Err(Error::Context);} Delivery::new(exchange)
    })();
    if result.is_err(){voter.cancel_activation();}result
}
pub fn complete<B:CounterSigningBackend>(voter:&mut VotingRuntime<B>,provider:&mut OwnContext<'_>,
    delivery:Delivery)->Result<()> {
    let result=(||{let (session,request,responses)=delivery.finish()?;
        if request.signer()!=voter.signer_node(){return Err(Error::Authority);}
        voter.complete_activation(session,&request,responses,provider).map_err(|_|Error::Current)
    })();
    if result.is_err(){voter.cancel_activation();}result
}

/// Orchestrated receipt path: collector refusal ALSO cancels the actual native
/// gate immediately, before any new chunk/retry. A private decoder result is
/// never promoted independently of the retained native voter attempt.
pub fn accept<B:CounterSigningBackend>(voter:&mut VotingRuntime<B>,delivery:&mut Delivery,
    raw:zeroize::Zeroizing<Vec<u8>>)->Result<()> {
    let result=delivery.accept_private(raw);
    if result.is_err(){voter.cancel_activation();}result
}
