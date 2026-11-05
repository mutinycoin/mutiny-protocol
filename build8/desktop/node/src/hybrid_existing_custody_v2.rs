//! Internal existing-only composition. This is not a public production issuer.
//! The installed factory must supply its authenticated, exclusively held real
//! counter and native-held encrypted inputs. Generic C conveys no qualification.
use crate::{continuity_custody_v2::{EncryptedVoteBackend,Pins},
    node_custody_v2::EncryptedNodeKey,hybrid_voter_v2::NodeWorkSigningBackend};
use mutiny_consensus_v8::{Hash,canonical_store_v2::CanonicalStore,
    counter_store::MonotonicCounter,counter_voter_v2::CounterSigningBackend,
    activation_attestation_v1::PrivateSignPermit,votes_v2::AuthenticatedRound,
    continuity_v2::Vote,blocks::BlockBody,work_authority_v2::Authority};
use mutiny_crypto_v2::{HybridSignature,PublicKey};
type Result<T>=std::result::Result<T,String>;
fn own_parent(chain:&CanonicalStore)->Result<mutiny_consensus_v8::anchors::FinalizedAnchor>{
    let(head,_)=chain.load().map_err(|_|"Existing custody canonical head")?;
    let(parent,_,_)=chain.execution_parent(head.height).map_err(|_|"Existing custody authenticated execution parent")?;
    if parent.height!=head.height||parent.block!=head.block{return Err("Existing custody parent changed".into());}
    Ok(mutiny_consensus_v8::anchors::FinalizedAnchor{network:mutiny_consensus_v8::NETWORK_ID,
        genesis:parent.genesis,fingerprint:parent.fingerprint,height:parent.height,block:parent.block})
}

pub(crate) struct ExistingBackend<C:MonotonicCounter> {
    continuity:EncryptedVoteBackend<C>,
    node_key:EncryptedNodeKey,
    chain:CanonicalStore,
    node:Hash,
}
struct Assembly<C:MonotonicCounter>{chain:Option<std::mem::ManuallyDrop<CanonicalStore>>,
    counter:Option<std::mem::ManuallyDrop<C>>,continuity:Option<std::mem::ManuallyDrop<EncryptedVoteBackend<C>>>,
    node_key:Option<EncryptedNodeKey>}
pub(crate) struct ExistingAssemblyRefusal<C:MonotonicCounter>{cause:String,
    owner:std::mem::ManuallyDrop<Box<Assembly<C>>>}
impl<C:MonotonicCounter> ExistingAssemblyRefusal<C>{pub(crate) fn cause(&self)->&str{&self.cause}}
pub(crate) struct ExistingBackendParts<C:MonotonicCounter>{
    pub(crate) chain:std::mem::ManuallyDrop<CanonicalStore>,pub(crate) counter:std::mem::ManuallyDrop<C>}
impl<C:MonotonicCounter> ExistingBackend<C> {
    /// Actual native factory composition. All incoming native owners and the
    /// whole partial encrypted backend are rooted before counter/key effects.
    pub(crate) fn assemble_retained(chain:std::mem::ManuallyDrop<CanonicalStore>,node:Hash,
        counter:std::mem::ManuallyDrop<C>,encrypted_continuity:&[u8],continuity_password:&str,
        encrypted_node:&[u8],node_password:&str)->std::result::Result<Self,ExistingAssemblyRefusal<C>>{
        let mut owner=std::mem::ManuallyDrop::new(Box::new(Assembly{
            chain:Some(chain),counter:Some(counter),continuity:None,node_key:None}));
        let assembled=(||->Result<()>{
            let state=&mut **owner;
            if node==[0;32]||!(1..=8192).contains(&encrypted_continuity.len())||!(1..=8192).contains(&encrypted_node.len()){
                return Err("Existing role ciphertext bounds".into());}
            let chain=&**state.chain.as_ref().ok_or("Existing original canonical owner absent")?;
            let parent=own_parent(chain)?;
            let authority=chain.current_authority(&parent).map_err(|_|"Existing custody authority")?;
            let pins=Pins::from_round(&AuthenticatedRound::new(authority).map_err(|_|"Existing custody round")?,node)?;
            let before=state.counter.as_mut().ok_or("Existing original counter absent")?.read()
                .map_err(|_|"Existing counter unavailable")?;
            let counter=state.counter.take().ok_or("Existing original counter absent")?;
            match EncryptedVoteBackend::unlock_existing(pins,counter,encrypted_continuity,continuity_password){
                Ok(continuity)=>state.continuity=Some(std::mem::ManuallyDrop::new(continuity)),
                Err(refusal)=>{let(cause,counter)=refusal.into_retained();state.counter=Some(counter);return Err(cause);}
            }
            let chain=&**state.chain.as_ref().ok_or("Existing original canonical owner absent")?;
            state.node_key=Some(EncryptedNodeKey::unlock(chain,&parent,node,encrypted_node,node_password)?);
            let continuity=state.continuity.as_mut().ok_or("Existing continuity owner absent")?;
            if continuity.read().map_err(|_|"Existing counter after role unlock")?!=before{
                return Err("Existing counter changed during role unlock".into());}
            let chain=&**state.chain.as_ref().ok_or("Existing original canonical owner absent")?;
            let after=chain.current_authority(&parent).map_err(|_|"Existing authority after unlock")?;
            let member=after.voters.get(&node).ok_or("Existing signer no longer current")?;
            if !member.admitted||!member.physical||!member.eligible||member.revoked
                ||&member.public!=continuity.public_key(){return Err("Existing role authority changed during unlock".into());}
            Ok(())
        })();
        if let Err(cause)=assembled{return Err(ExistingAssemblyRefusal{cause,owner});}
        let mut parts=*unsafe{std::mem::ManuallyDrop::take(&mut owner)};
        Ok(Self{chain:std::mem::ManuallyDrop::into_inner(parts.chain.take().expect("validated original chain")),node,
            continuity:std::mem::ManuallyDrop::into_inner(parts.continuity.take().expect("validated original continuity")),
            node_key:parts.node_key.take().expect("validated original Node role")})
    }
    /// Private factory cleanup transfer only; key owners are zeroized and SAME
    /// counter/canonical owners remain MD for independently checked shutdown.
    pub(crate) fn into_existing_parts(self)->ExistingBackendParts<C>{
        let Self{continuity,node_key,chain,..}=self;
        let chain=std::mem::ManuallyDrop::new(chain);
        let counter=continuity.into_existing_counter();drop(node_key);ExistingBackendParts{chain,counter}
    }
    /// No initialization, publication, counter increment, key generation or
    /// private export. The normal installer—not this generic composition—owns
    /// counter qualification, authenticated peer and retained input custody.
    pub(crate) fn assemble_existing(
        chain:CanonicalStore,node:Hash,mut counter:C,
        encrypted_continuity:&[u8],continuity_password:&str,
        encrypted_node:&[u8],node_password:&str,
    )->Result<Self> {
        if node==[0;32] || !(1..=8192).contains(&encrypted_continuity.len())
            || !(1..=8192).contains(&encrypted_node.len()) {
            return Err("Existing role ciphertext bounds".into());
        }
        let parent=own_parent(&chain)?;
        let authority=chain.current_authority(&parent).map_err(|_|"Existing custody authority")?;
        let round=AuthenticatedRound::new(authority).map_err(|_|"Existing custody round")?;
        let pins=Pins::from_round(&round,node)?;
        let before=counter.read().map_err(|_|"Existing counter unavailable")?;
        let mut continuity=EncryptedVoteBackend::unlock(pins,counter,
            encrypted_continuity,continuity_password)?;
        let node_key=EncryptedNodeKey::unlock(&chain,&parent,node,encrypted_node,node_password)?;
        if continuity.read().map_err(|_|"Existing counter after role unlock")?!=before {
            return Err("Existing counter changed during role unlock".into());
        }
        let after=chain.current_authority(&parent).map_err(|_|"Existing authority after unlock")?;
        let member=after.voters.get(&node).ok_or("Existing signer no longer current")?;
        if !member.admitted || !member.physical || !member.eligible || member.revoked
            || &member.public!=continuity.public_key() {
            return Err("Existing role authority changed during unlock".into());
        }
        Ok(Self{continuity,node_key,chain,node})
    }
    fn current_vote(&self,message:&[u8])->Result<Vote> {
        let vote=crate::activation_private_owner_v1::decode_reserved_vote(message)
            .map_err(|_|"Existing vote bounded canonical encoding")?;
        if vote.node!=self.node {return Err("Existing vote signer mismatch".into());}
        self.chain.validate_unsigned_vote_at_current_parent(&vote)
            .map_err(|_|"Existing vote current canonical authority")?;
        Ok(vote)
    }
}
impl<C:MonotonicCounter> MonotonicCounter for ExistingBackend<C> {
    fn read(&mut self)->Result<u64>{self.continuity.read()}
    fn increment(&mut self)->Result<()>{self.continuity.increment()}
}
impl<C:MonotonicCounter> CounterSigningBackend for ExistingBackend<C> {
    fn public_key(&self)->&PublicKey{self.continuity.public_key()}
    fn sign_vote(&mut self,_message:&[u8])->Result<HybridSignature>{
        Err("Existing owner requires opaque counter-voter permit".into())
    }
    fn sign_reserved_vote(&mut self,message:&[u8],permit:&PrivateSignPermit)->Result<HybridSignature>{
        self.current_vote(message)?;
        // The existing encrypted backend rechecks the opaque permit before and
        // after its counter read, immediately at the actual hybrid key entry.
        let signature=self.continuity.sign_reserved_vote(message,permit)?;
        self.current_vote(message)?;
        self.continuity.public_key().verify(mutiny_crypto_v2::Domain::ContinuityVote,
            message,&signature).map_err(|_|"Existing vote signature verification")?;
        Ok(signature)
    }
    fn sign_work_probe(&mut self,decision:&mutiny_consensus_v8::certificates::Decision,
        fragment:&mutiny_consensus_v8::liveness_v2::Fragment)->Result<HybridSignature>{
        let parent=own_parent(&self.chain)?;
        let authority=self.chain.current_authority(&parent).map_err(|_|"Existing probe authority")?;
        if decision.parent!=parent.block || decision.height!=parent.height.checked_add(1)
            .ok_or("Existing probe height overflow")? || fragment.node!=self.node
            || !authority.voters.get(&self.node).is_some_and(|m|
                m.admitted && m.physical && m.eligible && !m.revoked
                && &m.public==self.continuity.public_key()) {
            return Err("Existing probe current authority mismatch".into());
        }
        let signature=self.continuity.sign_work_probe(decision,fragment)?;
        self.chain.current_authority(&parent).map_err(|_|"Existing probe authority changed")?;
        Ok(signature)
    }
    fn sign_reserved_node_work(&mut self,mut authority:Authority,body:&BlockBody,
        permit:&mutiny_consensus_v8::counter_voter_v2::NodeWorkPermit)->Result<Authority>{
        let parent=own_parent(&self.chain)?;
        let expected=authority.unsigned().map_err(|_|"Existing NodeWork request encoding")?;
        self.node_key.authorize_reserved_work(&self.chain,&parent,&mut authority,body,
            permit,&mut self.continuity)?;
        if authority.unsigned().map_err(|_|"Existing NodeWork response encoding")?!=expected{
            return Err("Existing NodeWork changed exact request".into());
        }
        Ok(authority)
    }
}
impl<C:MonotonicCounter> NodeWorkSigningBackend for ExistingBackend<C> {
    fn sign_current_node_work(&mut self,_authority:Authority,_body:&BlockBody)->Result<Authority>{
        Err("Existing Node owner requires whole-snapshot reservation permit".into())
    }
}
