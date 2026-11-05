//! Owned ordered private exchange collector. Its output is ONLY input to the
//! existing native voter.complete_activation; it cannot mint a signing permit.
//! There is no serialized resumable attempt or default lifetime. The native
//! activation gate performs trusted elapsed/current phase checks at completion.
use super::{exchange::{ChallengeFrame,ResponseFrame,MAX_CHALLENGES},Error,Result};
use mutiny_consensus_v8::{Hash,activation_attestation_v1::{Exchange,Request,RecoveryResponse}};
use zeroize::Zeroizing;
pub struct Delivery {exchange:Option<Exchange>,next:usize,issued:Option<ChallengeFrame>,responses:Vec<RecoveryResponse>}
impl Delivery {
    pub fn new(exchange:Exchange)->Result<Self>{
        if exchange.challenges.is_empty(){return Err(Error::Bounds);}
        // Check every chunk before accepting any partial returned secret.
        for start in (0..exchange.challenges.len()).step_by(MAX_CHALLENGES){
            ChallengeFrame::from_exchange_range(&exchange,start..(start+MAX_CHALLENGES).min(exchange.challenges.len()))?;
        }
        // Reserve for the whole validated exchange BEFORE retaining private
        // responses. Growing Vec<RecoveryResponse> would relocate Zeroizing
        // elements while abandoning their old allocation without wiping it.
        let responses=Vec::with_capacity(exchange.challenges.len());
        Ok(Self{exchange:Some(exchange),next:0,issued:None,responses})
    }
    pub fn completed(&self)->Result<bool>{
        let exchange=self.exchange.as_ref().ok_or(Error::Response)?;
        if self.issued.is_some(){return Err(Error::Response);}
        Ok(self.next==exchange.challenges.len())
    }
    pub fn issue(&mut self)->Result<&ChallengeFrame>{self.issue_count(MAX_CHALLENGES)}
    /// A native owner routes exact per-admission/class endpoints independently.
    pub fn issue_one(&mut self)->Result<&ChallengeFrame>{self.issue_count(1)}
    fn issue_count(&mut self,count:usize)->Result<&ChallengeFrame>{
        if self.issued.is_some(){return Err(Error::Response);}
        let exchange=self.exchange.as_ref().ok_or(Error::Response)?;
        if self.next==exchange.challenges.len(){return Err(Error::Response);}
        self.issued=Some(ChallengeFrame::from_exchange_range(exchange,
            self.next..(self.next+count).min(exchange.challenges.len()))?);
        self.issued.as_ref().ok_or(Error::Response)
    }
    pub fn accept_private(&mut self,raw:Zeroizing<Vec<u8>>)->Result<()> {
        // Consume issuance first on EVERY attempt; wrong/partial/replayed frames
        // cancel the entire collector. Caller must also cancel the native voter
        // attempt on error; a dropped collector is not private completion.
        let result=(||{
            let expected=self.issued.take().ok_or(Error::Response)?;
            let response=ResponseFrame::decode_private(raw,&expected)?;
            let mut values=response.into_responses();
            self.next=self.next.checked_add(values.len()).ok_or(Error::Bounds)?;
            for value in &mut values {
                // Leave a zero-valued owned slot for Drop to wipe; IntoIter
                // would abandon the source allocation's moved inline secret.
                let owned=std::mem::replace(value,RecoveryResponse::new(0,0,Zeroizing::new([0;32])));
                self.responses.push(owned);
            }Ok(())
        })();
        if result.is_err(){self.exchange=None;self.responses.clear();self.issued=None;}
        result
    }
    pub fn finish(self)->Result<(Hash,Request,Vec<RecoveryResponse>)>{
        let exchange=self.exchange.ok_or(Error::Response)?;
        if self.issued.is_some()||self.next!=exchange.challenges.len()||self.responses.len()!=self.next{
            return Err(Error::Response);
        }
        Ok((exchange.session,exchange.request,self.responses))
    }
}
