//! Typed A2 ingress. Reassembly grants no semantic pool acceptance. The owning
//! actor supplies local work context and serializes the single-item queue.
use crate::{a2_operation_pool_v1::{Context,Pool},hybrid_runtime_v2::HybridRuntime};
use mutiny_consensus_v8::Hash;
use mutiny_transport_v2::{object_link::Event,objects::{ObjectKind,Offer}};

pub enum Outcome {
    Accepted { offer: Offer, digest: Hash },
    Finalized { offer: Offer, digest: Hash },
    Other(Event),
}
pub fn dispatch_peer(
    runtime: &HybridRuntime,
    pool: &mut Pool,
    context: &Context<'_>,
    peer: &mut crate::hybrid_peer_admission_v2::PeerLink,
    received: crate::hybrid_peer_admission_v2::Received,
) -> Result<Outcome,String> {
    peer.dispatch_received(received,|link,event|dispatch_and_release(runtime,pool,context,link,event))?
}
pub fn retry_completed(
    runtime: &HybridRuntime,
    pool: &mut Pool,
    context: &Context<'_>,
    peer: &mut crate::hybrid_peer_admission_v2::PeerLink,
    id: &Hash,
) -> Result<Outcome,String> {
    peer.with_current(|link| {
        let (offer,bytes) = link.completed(id).map_err(|_| "A2 reassembly")?;
        dispatch_and_release(runtime,pool,context,link,Event::Completed { offer,bytes })
    })?
}
fn dispatch_and_release(
    runtime: &HybridRuntime, pool: &mut Pool, context: &Context<'_>,
    link: &mut mutiny_transport_v2::object_link::ObjectLink, event: Event,
) -> Result<Outcome,String> {
    let outcome = dispatch(runtime,pool,context,event)?;
    if let Outcome::Accepted { offer,.. } | Outcome::Finalized { offer,.. } = &outcome {
        // Pool::submit committed the exact complete bytes before this release.
        // Finalized recovery is own replay plus exact authenticated bytes.
        // Failed/partial objects never enter this branch and remain preserved.
        link.discard(&offer.id).map_err(|_| "A2 durable handoff transport release")?;
    }
    Ok(outcome)
}
pub(crate) fn dispatch(
    runtime: &HybridRuntime,
    pool: &mut Pool,
    context: &Context<'_>,
    event: Event,
) -> Result<Outcome,String> {
    match event {
        Event::Completed { offer,bytes } if offer.kind == ObjectKind::A2EvidenceOperation => {
            if bytes.is_empty() || bytes.len() > ObjectKind::A2EvidenceOperation.max_bytes()
                || offer.length != bytes.len()
                || mutiny_transport_v2::objects::object_id(ObjectKind::A2EvidenceOperation,&bytes)
                    .map_err(|_| "A2 object identity")? != offer.id {
                return Err("A2 transport identity".into());
            }
            if pool.finalized_exact(runtime,&bytes)? {
                use sha2::Digest;
                return Ok(Outcome::Finalized { offer,digest:sha2::Sha256::digest(&bytes).into() });
            }
            let digest = pool.submit(runtime,context,&bytes)?;
            Ok(Outcome::Accepted { offer,digest })
        }
        event => Ok(Outcome::Other(event)),
    }
}
