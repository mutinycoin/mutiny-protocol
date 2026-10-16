//! Local whole-snapshot NodeWork reservation state. No separate database and
//! no public proof or protocol signature format is introduced.
use crate::{Error,Hash,Result,anchors::FinalizedAnchor,work_authority_v2::{Authority,MAX_AUTHORITY_BYTES}};
use minicbor::{Decoder,Encoder};
use mutiny_crypto_v2::{Domain,PublicKey};
use std::collections::BTreeMap;
use super::{MAX_RESERVATIONS,MAX_SNAPSHOT,zero_signature};

struct Record {body:Hash,authority:Authority,signed:bool}
pub(super) struct WorkState {high_water:u64,records:BTreeMap<u64,Record>}
impl WorkState {
    /// Only a NEW supervised complete voter snapshot may initialize this. An
    /// old snapshot with no work state remains unknown, not an empty journal.
    pub(super) fn new()->Self{Self{high_water:0,records:BTreeMap::new()}}
    pub(super) fn next_height(&self)->Self{Self{high_water:self.high_water,records:BTreeMap::new()}}
    pub(super) fn high_water(&self)->u64{self.high_water}
    pub(super) fn reserve(&mut self,authority:&Authority,body:Hash)->Result<bool>{
        bounded(authority)?;
        if body==[0;32]||authority.work.ticket_sequence==0{return Err(Error::WrongAnchor);}
        let ticket=authority.work.ticket_sequence;
        if let Some(record)=self.records.get(&ticket){
            if record.body!=body||record.authority.unsigned()?!=authority.unsigned()?{
                return Err(Error::StaleSequence);
            }
            return Ok(false);
        }
        if ticket<=self.high_water{return Err(Error::StaleSequence);}
        if self.records.len()>=MAX_RESERVATIONS{return Err(Error::Capacity);}
        let mut reserved=authority.clone();reserved.signature=zero_signature();
        self.records.insert(ticket,Record{body,authority:reserved,signed:false});
        self.high_water=ticket;Ok(true)
    }
    pub(super) fn cached(&self,ticket:u64)->Option<&Authority>{
        self.records.get(&ticket).filter(|r|r.signed).map(|r|&r.authority)
    }
    pub(super) fn finish(&mut self,signed:Authority,body:Hash)->Result<()> {
        bounded(&signed)?;verify_signature(&signed)?;
        let record=self.records.get_mut(&signed.work.ticket_sequence).ok_or(Error::WrongAnchor)?;
        if record.body!=body||record.authority.unsigned()?!=signed.unsigned()?{
            return Err(Error::WrongAnchor);
        }
        if record.signed&&record.authority!=signed{return Err(Error::StaleSequence);}
        record.authority=signed;record.signed=true;Ok(())
    }
    pub(super) fn validate(&self,parent:&FinalizedAnchor)->Result<()> {
        for (ticket,record) in &self.records {
            let candidate=&record.authority.work.candidate;
            if *ticket==0||*ticket>self.high_water||*ticket!=record.authority.work.ticket_sequence
                ||record.body==[0;32]||candidate.network!=parent.network
                ||candidate.genesis!=parent.genesis||candidate.fingerprint!=parent.fingerprint
                ||candidate.parent!=parent.block||candidate.height!=parent.height.checked_add(1).ok_or(Error::Overflow)?{
                return Err(Error::WrongAnchor);
            }
            bounded(&record.authority)?;
            if record.signed{verify_signature(&record.authority)?;}
            else if record.authority.signature!=zero_signature(){return Err(Error::Codec);}
        }
        Ok(())
    }
    pub(super) fn encode(&self)->Result<Vec<u8>> {
        if self.records.len()>MAX_RESERVATIONS{return Err(Error::Capacity);}
        let mut length=2usize.checked_add(head_size(self.high_water)).and_then(|n|
            n.checked_add(head_size(self.records.len() as u64))).ok_or(Error::Overflow)?;
        for record in self.records.values(){
            bounded(&record.authority)?;
            let raw=record.authority.encode()?;
            length=length.checked_add(36).and_then(|n|n.checked_add(head_size(raw.len() as u64)))
                .and_then(|n|n.checked_add(raw.len())).ok_or(Error::Overflow)?;
        }
        if length>MAX_SNAPSHOT{return Err(Error::Oversize);}
        let mut storage=Vec::new();storage.try_reserve_exact(length).map_err(|_|Error::Capacity)?;
        let mut e=Encoder::new(storage);
        e.array(3).unwrap().u8(1).unwrap().u64(self.high_water).unwrap()
            .array(self.records.len() as u64).unwrap();
        for (ticket,record) in &self.records{
            if *ticket==0||*ticket>self.high_water||*ticket!=record.authority.work.ticket_sequence
                ||record.body==[0;32]{return Err(Error::Codec);}
            bounded(&record.authority)?;
            e.array(3).unwrap().bytes(&record.body).unwrap()
                .bytes(&record.authority.encode()?).unwrap().bool(record.signed).unwrap();
            if e.writer().len()>MAX_SNAPSHOT{return Err(Error::Oversize);}
        }
        let raw=e.into_writer();if raw.len()!=length{return Err(Error::Codec);}Ok(raw)
    }
    pub(super) fn decode(raw:&[u8])->Result<Self>{
        crate::blocks::canonical(raw,MAX_SNAPSHOT)?;
        let mut d=Decoder::new(raw);
        let state=(||->std::result::Result<Self,minicbor::decode::Error>{
            let bad=||minicbor::decode::Error::message("whole-snapshot NodeWork state");
            if d.array()?!=Some(3)||d.u8()?!=1{return Err(bad());}
            let high_water=d.u64()?;let count=d.array()?.ok_or_else(bad)?;
            if count>MAX_RESERVATIONS as u64{return Err(bad());}
            let mut records=BTreeMap::new();let mut previous=0;
            for _ in 0..count{
                if d.array()?!=Some(3){return Err(bad());}
                let body:Hash=d.bytes()?.try_into().map_err(|_|bad())?;
                let encoded=d.bytes()?;
                if encoded.len()>MAX_AUTHORITY_BYTES{return Err(bad());}
                let authority=Authority::decode(encoded).map_err(|_|bad())?;
                let signed=d.bool()?;let ticket=authority.work.ticket_sequence;
                if body==[0;32]||ticket<=previous||ticket>high_water{return Err(bad());}
                if signed{verify_signature(&authority).map_err(|_|bad())?;}
                else if authority.signature!=zero_signature(){return Err(bad());}
                previous=ticket;records.insert(ticket,Record{body,authority,signed});
            }
            Ok(Self{high_water,records})
        })().map_err(|_|Error::Codec)?;
        if d.position()!=raw.len()||state.encode()?!=raw{return Err(Error::NonCanonical);}Ok(state)
    }
}

#[cfg(test)]
mod modeled_controls {
    use super::*;
    use mutiny_crypto_v2::{HybridKey,Role};
    fn fixture()->(HybridKey,FinalizedAnchor,Authority){
        let key=HybridKey::generate(Role::Node).unwrap();
        let parent=FinalizedAnchor{network:crate::NETWORK_ID,genesis:[1;32],fingerprint:[2;32],height:3,block:[3;32]};
        let descriptor=key.public().descriptor(1).unwrap();
        let authority=Authority{node_descriptor:descriptor.clone(),signature:zero_signature(),
            work:crate::pow::WorkAuthority{candidate:crate::pow::Candidate{
                network:parent.network,genesis:parent.genesis,fingerprint:parent.fingerprint,
                parent:parent.block,height:4,timestamp:5,body_root:[4;32],state_root:[5;32],
                license:[6;32],worker:[7;32],target:[8;32]},assignment_sequence:1,ticket_sequence:4,
                coordinator:crate::work_authority_v2::node_identity(&descriptor).unwrap(),
                nonce_start:0,nonce_end:1,epoch:1}};
        (key,parent,authority)
    }
    #[test]
    fn modeled_pending_restart_exact_retry_conflict_and_height_high_water(){
        let(_,parent,authority)=fixture();let mut state=WorkState::new();
        assert!(state.reserve(&authority,[9;32]).unwrap());
        let mut restored=WorkState::decode(&state.encode().unwrap()).unwrap();
        restored.validate(&parent).unwrap();
        assert!(!restored.reserve(&authority,[9;32]).unwrap());
        assert!(restored.cached(4).is_none());
        assert!(restored.reserve(&authority,[10;32]).is_err());
        let mut conflicting=authority.clone();conflicting.work.nonce_end=2;
        assert!(restored.reserve(&conflicting,[9;32]).is_err());
        let mut next=restored.next_height();assert_eq!(next.high_water(),4);
        assert!(next.reserve(&authority,[9;32]).is_err());
        conflicting.work.ticket_sequence=5;conflicting.work.candidate.height+=1;
        assert!(next.reserve(&conflicting,[9;32]).unwrap());
        let mut wrong=parent.clone();wrong.block=[11;32];assert!(restored.validate(&wrong).is_err());
    }
    #[test]
    fn modeled_signed_exact_outcome_roundtrip_and_counter_content_permit(){
        let(key,parent,mut authority)=fixture();let mut state=WorkState::new();
        state.reserve(&authority,[9;32]).unwrap();
        let permit=NodeWorkPermit::after_commit(8,&authority,[9;32]).unwrap();
        permit.check_at_key_entry(8,&authority,[9;32]).unwrap();
        assert!(permit.check_at_key_entry(7,&authority,[9;32]).is_err());
        assert!(permit.check_at_key_entry(8,&authority,[10;32]).is_err());
        let mut conflict=authority.clone();conflict.work.nonce_end=2;
        assert!(permit.check_at_key_entry(8,&conflict,[9;32]).is_err());
        authority.sign(&key).unwrap();state.finish(authority.clone(),[9;32]).unwrap();
        let restored=WorkState::decode(&state.encode().unwrap()).unwrap();
        restored.validate(&parent).unwrap();assert_eq!(restored.cached(4),Some(&authority));
        let mut invalid=authority;invalid.signature.ed448[0]^=1;
        assert!(state.finish(invalid,[9;32]).is_err());
    }
    #[test]
    fn modeled_bounded_snapshot_trailing_and_unknown_signature_refusal(){
        let(_,_,mut authority)=fixture();let mut state=WorkState::new();
        state.reserve(&authority,[9;32]).unwrap();
        let mut encoded=state.encode().unwrap();encoded.push(0);
        assert!(WorkState::decode(&encoded).is_err());
        let mut excessive=authority.clone();excessive.node_descriptor=vec![0;2049];
        assert!(state.reserve(&excessive,[9;32]).is_err());
        authority.signature.ed448[0]=1;
        assert!(state.finish(authority,[9;32]).is_err());
        assert!(state.cached(4).is_none());
    }
}
fn head_size(value:u64)->usize{match value{0..=23=>1,24..=255=>2,256..=65535=>3,
    65536..=4294967295=>5,_=>9}}
fn bounded(authority:&Authority)->Result<()> {
    // Before clone/encoding: this is the existing Authority decoder ceiling.
    if authority.node_descriptor.len()>2048{return Err(Error::Oversize);}
    if authority.encode()?.len()>MAX_AUTHORITY_BYTES{return Err(Error::Oversize);}Ok(())
}
fn verify_signature(authority:&Authority)->Result<()> {
    let(key,_)=PublicKey::decode_descriptor(&authority.node_descriptor).map_err(|_|Error::Codec)?;
    key.verify(Domain::NodeWork,&authority.unsigned()?,&authority.signature).map_err(|_|Error::BadSignature)
}

/// Opaque local permit issued only after the matching whole voter snapshot is
/// committed and verified against its actual hardware counter. Not Clone or
/// serializable, and not authority to skip current canonical Node validation.
pub struct NodeWorkPermit {counter:u64,unsigned:Hash,body:Hash}
impl NodeWorkPermit {
    pub(super) fn after_commit(counter:u64,authority:&Authority,body:Hash)->Result<Self>{
        bounded(authority)?;
        if body==[0;32]{return Err(Error::WrongAnchor);}
        Ok(Self{counter,unsigned:crate::domain_hash(b"MUTINY-BUILD8-PRIVATE-NODE-WORK-PERMIT-V1",&authority.unsigned()?),body})
    }
    pub fn check_at_key_entry(&self,actual_counter:u64,authority:&Authority,body:Hash)->Result<()> {
        bounded(authority)?;
        if actual_counter!=self.counter||body!=self.body
            ||crate::domain_hash(b"MUTINY-BUILD8-PRIVATE-NODE-WORK-PERMIT-V1",&authority.unsigned()?)!=self.unsigned{
            return Err(Error::WrongAnchor);
        }Ok(())
    }
}
