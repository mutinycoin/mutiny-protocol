//! Explicit one-item A2 relay over a current admission-owned authenticated link.
//! No send loop, changed deadlines or widened ordinary submissions. Only a full
//! native current-parent preview supplies advertisement authority; ACK retirement
//! additionally requires durable exact local/canonical evidence.
use crate::{a2_operation_pool_v1::{Context,Pool},hybrid_runtime_v2::HybridRuntime};
use mutiny_consensus_v8::Hash;
use mutiny_transport_v2::{object_link::ObjectLink,objects::{ObjectKind,Offer,MAX_BITMAP_BITS}};
use sha2::{Digest,Sha256};

pub struct Relay { peer:Hash, in_flight:Option<Offer>, delivered:Option<Hash> }
impl Relay {
    pub fn new(peer:Hash) -> Result<Self,String> {
        if peer==[0;32] { return Err("A2 relay peer".into()); }
        Ok(Self { peer,in_flight:None,delivered:None })
    }
    /// At most one HAVE per explicit owner service turn. PeerLink must hold its
    /// fresh canonical admission pin while calling this operation.
    pub fn prepare_peer(
        &mut self,runtime:&HybridRuntime,pool:&Pool,context:&Context<'_>,peer:&mut crate::hybrid_peer_admission_v2::PeerLink,
    ) -> Result<Option<(Offer,Vec<u8>)>,String> {
        peer.with_current(|link|self.prepare_link(runtime,pool,context,link))?
    }
    /// Explicit local owner recovery after pool archive-and-cancel, including
    /// reopen between archive commit and transport release. No wire message
    /// invokes this action. The exact archive survives; an unrelated or partial
    /// transport object is preserved and refused. Nothing is marked delivered.
    pub fn release_archived_peer(
        &mut self,runtime:&HybridRuntime,pool:&Pool,expected:Hash,
        peer:&mut crate::hybrid_peer_admission_v2::PeerLink,
    ) -> Result<bool,String> {
        let raw=pool.cancelled_bytes(runtime,expected)?;
        let expected_id=mutiny_transport_v2::objects::object_id(ObjectKind::A2EvidenceOperation,&raw)
            .map_err(|_|"A2 cancelled transport identity")?;
        peer.with_current(|link| {
            let (genesis,fingerprint)=runtime.network_context();
            if link.peer_id()!=self.peer || !link.matches_network(genesis,fingerprint) {
                return Err("A2 cancellation peer/network".into());
            }
            if self.in_flight.as_ref().is_some_and(|offer|offer.id!=expected_id) {
                return Err("A2 cancellation reserved item differs".into());
            }
            let Some(offer)=link.a2_evidence_offer().map_err(|_|"A2 cancellation queue")? else {
                if link.has_a2_reservation().map_err(|_|"A2 cancellation occupied queue")? {
                    return Err("A2 cancellation partial or invalid evidence retained".into());
                }
                // Idempotent local retry after successful durable deletion.
                self.in_flight=None;
                if self.delivered==Some(expected) { self.delivered=None; }
                return Ok(false);
            };
            if offer.id!=expected_id || offer.kind!=ObjectKind::A2EvidenceOperation {
                return Err("A2 cancellation transport item differs".into());
            }
            let (actual,retained)=link.completed(&offer.id).map_err(|_|"A2 cancellation complete copy unavailable")?;
            if actual!=offer || retained!=raw {
                return Err("A2 cancellation transport bytes differ".into());
            }
            // Commit storage deletion before clearing the volatile reservation.
            // A failed deletion keeps both reservation and durable archive.
            link.discard(&offer.id).map_err(|_|"A2 cancellation transport release")?;
            self.in_flight=None;
            if self.delivered==Some(expected) { self.delivered=None; }
            Ok(true)
        })?
    }
    fn prepare_link(
        &mut self,runtime:&HybridRuntime,pool:&Pool,context:&Context<'_>,link:&mut ObjectLink,
    ) -> Result<Option<(Offer,Vec<u8>)>,String> {
        let (genesis,fingerprint)=runtime.network_context();
        if link.peer_id()!=self.peer || !link.matches_network(genesis,fingerprint) {
            return Err("A2 relay canonical peer/network".into());
        }
        if let Some(offer)=link.a2_evidence_offer().map_err(|_|"A2 relay queue")? {
            let (actual,raw)=link.completed(&offer.id).map_err(|_|"A2 relay retained transport bytes")?;
            if actual != offer { return Err("A2 relay transport identity changed".into()); }
            if pool.retains_exact(runtime,&raw)? {
                if self.in_flight.as_ref().is_some_and(|prior|prior!=&offer) {
                    return Err("A2 relay reserved item differs".into());
                }
                self.in_flight=Some(offer);
            }
        }
        if let Some(offer)=self.in_flight.clone() {
            let (_,raw)=link.completed(&offer.id).map_err(|_|"A2 relay exact bytes")?;
            let fragments=offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD);
            let total=u16::try_from(fragments).map_err(|_|"A2 relay fragment bound")?;
            if total==0 { return Err("A2 relay empty object".into()); }
            let mut start=0u16;
            let mut complete=true;
            while start<total {
                let count=(total-start).min(MAX_BITMAP_BITS);
                let bits=link.acknowledged(&offer.id,start,count).map_err(|_|"A2 relay ACK window")?;
                if !bits.bits.into_iter().all(|bit|bit) { complete=false; break; }
                start=start.checked_add(count).ok_or("A2 relay ACK overflow")?;
            }
            if complete {
                if !pool.retains_exact(runtime,&raw)? { return Err("A2 relay evidence unavailable".into()); }
                link.discard(&offer.id).map_err(|_|"A2 relay durable transport release")?;
                self.in_flight=None;
                self.delivered=Some(Sha256::digest(&raw).into());
            }
        }
        // Even a formerly valid local item must pass full native current-context
        // validation before another advertisement. Refusal preserves all copies.
        let Some(raw)=pool.pending(runtime,context)? else { self.delivered=None; return Ok(None); };
        let digest:Hash=Sha256::digest(&raw).into();
        if self.delivered==Some(digest) { return Ok(None); }
        if self.in_flight.as_ref().is_some_and(|offer| {
            mutiny_transport_v2::objects::object_id(ObjectKind::A2EvidenceOperation,&raw).ok()!=Some(offer.id)
        }) { return Err("A2 relay single reservation occupied".into()); }
        match link.enqueue(ObjectKind::A2EvidenceOperation,&raw,0) {
            Ok((offer,frame))=>{ self.in_flight=Some(offer.clone()); Ok(Some((offer,frame))) },
            Err(mutiny_transport_v2::Error::Limit)=>Ok(None),
            Err(_)=>Err("A2 relay bounded queue insertion".into()),
        }
    }
}
