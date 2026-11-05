//! Software-only lower-boundary controls. Authority/reservation CLASSIFICATION
//! is modeled, not a native admission receipt or physical TPM result. Actual
//! counter-store bytes, actual reducer signing and BOTH_REQUIRED signatures are
//! exercised. No private key/activation result enters fixture files or logs.
use super::*;
use crate::{activation_attestation_v1::{Classification,Failure,rule_commitment},
    anchors::FinalizedAnchor,continuity_v2::ParentVoter,certificates::Decision};
use mutiny_crypto_v2::{Domain,HybridKey,Role};
struct EntryClock(std::sync::atomic::AtomicU64);
impl crate::activation_attestation_v1::Elapsed for EntryClock {
    fn elapsed(&self)->std::result::Result<std::time::Duration,Failure>{
        let value=self.0.load(std::sync::atomic::Ordering::SeqCst);
        if value==u64::MAX{Err(Failure::Elapsed)}else{Ok(std::time::Duration::from_secs(value))}
    }
}
pub(crate) struct Backend { key:HybridKey,pub(crate) counter:u64,pub(crate) calls:u64,corrupt:Option<u8>,
    entry_clock:Option<(std::sync::Arc<EntryClock>,u64)> }
impl MonotonicCounter for Backend {
    fn read(&mut self)->std::result::Result<u64,String>{Ok(self.counter)}
    fn increment(&mut self)->std::result::Result<(),String>{self.counter=self.counter.checked_add(1).ok_or("counter")?;Ok(())}
}
impl CounterSigningBackend for Backend {
    fn public_key(&self)->&PublicKey{self.key.public()}
    fn sign_reserved_vote(&mut self,message:&[u8],permit:&crate::activation_attestation_v1::PrivateSignPermit)
        ->std::result::Result<HybridSignature,String>{
        if let Some((clock,value))=&self.entry_clock{clock.0.store(*value,std::sync::atomic::Ordering::SeqCst);}
        // Same public gate invoked by native EncryptedVoteBackend; classification
        // and activation adapter remain private software models in this host.
        permit.check_at_custody_entry([9;32],Some(rule_commitment()),message).map_err(|_|"custody entry refusal")?;
        self.sign_vote(message)
    }
    fn sign_vote(&mut self,message:&[u8])->std::result::Result<HybridSignature,String>{
        self.calls+=1;
        let mut signature=self.key.sign(Domain::ContinuityVote,message).map_err(|_|"software signing")?;
        match self.corrupt {Some(1)=>signature.ed448[1]^=1,Some(2)=>signature.fndsa[1]^=1,_=>{}}
        Ok(signature)
    }
}
fn fixture(classification:Classification,signed:bool,successor:bool,step:u8)
    ->(std::path::PathBuf,Backend,HeightAuthority,Snapshot){
    let mut nonce=[0;32];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let path=std::env::temp_dir().join(format!("build8-activation-signing-{}",hex::encode(nonce)));
    assert!(crate::submission_pool_v1::SubmissionPool::private_directory(&path).unwrap());
    let backend=Backend{key:HybridKey::generate(Role::Continuity).unwrap(),counter:100,calls:0,corrupt:None,entry_clock:None};
    let tpm=p256::ecdsa::SigningKey::from_bytes((&[9;32]).into()).unwrap().verifying_key()
        .to_encoded_point(true).as_bytes().try_into().unwrap();
    let member=ParentVoter{lineage:[9;32],admitted:true,physical:true,eligible:true,revoked:false,
        hardware_generation:1,key_generation:1,tpm_public:tpm,profile:[10;32],public:backend.key.public().clone(),reputation:1u64.into()};
    let authority=HeightAuthority{parent:FinalizedAnchor{network:crate::NETWORK_ID,genesis:[1;32],fingerprint:[2;32],height:4,block:[4;32]},
        membership:[6;32],reputation:[7;32],attestation:[8;32],voters:[([9;32],member.clone())].into_iter().collect(),
        activation_rule:Some(rule_commitment())};
    let mut vote=Vote{decision:Decision{network:crate::NETWORK_ID,genesis:[1;32],fingerprint:[2;32],purpose:2,height:5,
        mining_epoch:0,continuity_period:0,round:0,step,previous_finalized_anchor:authority.parent.id(),parent:[4;32],block:[5;32],state:[11;32],
        membership:[6;32],reputation:[7;32],attestation:[8;32]},nil:false,node:[9;32],hardware_generation:1,key_generation:1,sequence:1,
        tpm_identity:member.tpm_identity(),profile:member.profile,signature:zero_signature()};
    if signed{vote.signature=backend.key.sign(Domain::ContinuityVote,&vote.unsigned().unwrap()).unwrap();}
    vote.validate_authority(&authority.parent,authority.roots(),&authority.voters).unwrap();
    let snapshot=Snapshot{height:5,last_sequence:1,parent:authority.parent.id(),roots:authority.roots(),
        locks:LockState{round:0,locked:None,finalized:None,halted:false},votes:[((0,step),(vote,signed))].into_iter().collect(),
        gated:[(0,step)].into_iter().collect(),classifications:if successor{[((0,step),classification)].into_iter().collect()}else{BTreeMap::new()},
        successor,work:None,legacy:false};
    (path,backend,authority,snapshot)
}
fn open_fixture(path:&Path,backend:&mut Backend,authority:&HeightAuthority,snapshot:&Snapshot)->CounterVoter{
    let context=AuthenticatedRound::new(authority.clone()).unwrap().signing_context([9;32]).unwrap();
    let raw=snapshot.encode().unwrap();
    drop(CounterStore::open(&path.join("voter.sqlite"),context,None,Some((100,&raw)),backend).unwrap());
    CounterVoter::open(&path.join("voter.sqlite"),authority.clone(),[9;32],None,backend).unwrap()
}
fn retain(path:&Path){println!("PUBLIC TEST counter reservation evidence retained: {}",path.display());}
pub(crate) fn expiry_boundary_fixture()->(std::path::PathBuf,CounterVoter,Backend){
    let (path,mut backend,authority,snapshot)=fixture(Classification::Required([21;32]),false,true,2);
    let voter=open_fixture(&path,&mut backend,&authority,&snapshot);(path,voter,backend)
}
#[test]
fn unsigned_marked_replay_requires_private_activation_before_any_mutation(){
    for (classification,successor) in [(Classification::Required([21;32]),true),(Classification::Unknown,false)]{
        for (step,bft_step) in [(2,Step::Prevote),(3,Step::Precommit)]{
            let (path,mut backend,authority,snapshot)=fixture(classification,false,successor,step);
            let mut voter=open_fixture(&path,&mut backend,&authority,&snapshot);
            let before=std::fs::read(path.join("voter.sqlite")).unwrap();let counter=backend.counter;
            assert!(matches!(voter.replay(bft_step,&mut backend),Err(CounterVoterError::Activation(Failure::Missing))));
            assert_eq!(backend.calls,0);assert_eq!(backend.counter,counter);assert!(!voter.is_poisoned());
            assert_eq!(std::fs::read(path.join("voter.sqlite")).unwrap(),before);
            assert_eq!(voter.snapshot.encode().unwrap(),snapshot.encode().unwrap());
            retain(&path);
        }
    }
}
#[test]
fn exact_durably_signed_retransmission_needs_no_live_activation_or_clock(){
    for (step,bft_step) in [(2,Step::Prevote),(3,Step::Precommit)]{
        let (path,mut backend,authority,snapshot)=fixture(Classification::Required([21;32]),true,true,step);
        let mut voter=open_fixture(&path,&mut backend,&authority,&snapshot);
        let before=std::fs::read(path.join("voter.sqlite")).unwrap();let counter=backend.counter;
        let expected=snapshot.votes[&(0,step)].0.clone();
        assert_eq!(voter.replay(bft_step,&mut backend).unwrap(),Some(expected));
        assert_eq!(backend.calls,0);assert_eq!(backend.counter,counter);
        assert_eq!(std::fs::read(path.join("voter.sqlite")).unwrap(),before);retain(&path);
    }
}
#[test]
fn ordinary_unsigned_completion_still_requires_both_hybrid_halves(){
    for corrupt in [None,Some(1),Some(2)]{
        let (path,mut backend,authority,snapshot)=fixture(Classification::NoAdmission,false,true,2);
        backend.corrupt=corrupt;let mut voter=open_fixture(&path,&mut backend,&authority,&snapshot);
        let result=voter.replay(Step::Prevote,&mut backend);assert_eq!(backend.calls,1);
        if corrupt.is_none(){
            let vote=result.unwrap().unwrap();vote.verify(&authority.parent,authority.roots(),&authority.voters).unwrap();
            assert!(voter.snapshot.votes[&(0,2)].1);
        }else{
            assert!(matches!(result,Err(CounterVoterError::Invalid(Error::BadSignature))));
            assert!(!voter.snapshot.votes[&(0,2)].1);assert!(voter.is_poisoned());
        }
        retain(&path);
    }
}
#[test]
fn expiry_regression_or_unknown_between_consume_and_backend_prevents_private_signature(){
    for value in [10,0,u64::MAX]{
        let (path,mut backend,authority,snapshot)=fixture(Classification::Required([21;32]),false,true,2);
        let mut voter=open_fixture(&path,&mut backend,&authority,&snapshot);
        let clock=std::sync::Arc::new(EntryClock(std::sync::atomic::AtomicU64::new(2)));
        voter.activation=crate::activation_attestation_v1::completed_software_gate([9;32],[21;32],2,clock.clone());
        // begin at 2: the fixture's existing ten-second LOCAL limit expires at 12.
        let value=if value==10{12}else{value};
        backend.entry_clock=Some((clock,value));
        let before=std::fs::read(path.join("voter.sqlite")).unwrap();let counter=backend.counter;
        assert!(matches!(voter.replay(Step::Prevote,&mut backend),Err(CounterVoterError::Backend)));
        assert_eq!(backend.calls,0);assert_eq!(backend.counter,counter);
        assert!(!voter.snapshot.votes[&(0,2)].1);assert!(voter.is_poisoned());
        assert_eq!(std::fs::read(path.join("voter.sqlite")).unwrap(),before);retain(&path);
    }
}
