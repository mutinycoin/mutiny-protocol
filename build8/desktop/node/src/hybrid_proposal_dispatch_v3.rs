//! A2 successor peer ingress for uncertified proposals. Caller owns the canonical
//! runtime and candidate journal. No socket wait, vote or finality installation.
use crate::{
    candidate_journal_v3::{Journal, Record},
    hybrid_runtime_v2::HybridRuntime,
};
use mutiny_consensus_v8::Hash;
use mutiny_transport_v2::{
    object_link::Event,
    objects::{ObjectKind, Offer},
};
pub enum Outcome {
    /// Historically executed proposal retained (or retired by canonical
    /// finality). Owning voter still restores/validates it before signing.
    Retained {
        offer: Offer,
        block: Hash,
    },
    Other(Event),
}
pub fn dispatch_peer(
    runtime: &HybridRuntime,
    journal: &mut Journal,
    peer: &mut crate::hybrid_peer_admission_v2::PeerLink,
    received: crate::hybrid_peer_admission_v2::Received,
) -> Result<Outcome, String> {
    peer.dispatch_received(received, |link, event| dispatch_and_release(runtime, journal, link, event))?
}
/// Durable reassembly retry under the current peer pin. No peer-provided
/// completion status substitutes for content hashing or historical execution.
pub fn retry_completed(
    runtime: &HybridRuntime,
    journal: &mut Journal,
    peer: &mut crate::hybrid_peer_admission_v2::PeerLink,
    id: &Hash,
) -> Result<Outcome, String> {
    peer.with_current(|link| {
        let (offer, bytes) = link.completed(id).map_err(|_| "Proposal reassembly")?;
        dispatch_and_release(runtime, journal, link, Event::Completed { offer, bytes })
    })?
}
fn dispatch_and_release(
    runtime: &HybridRuntime, journal: &mut Journal,
    link: &mut mutiny_transport_v2::object_link::ObjectLink, event: Event,
) -> Result<Outcome,String> {
    let outcome = dispatch(runtime,journal,event)?;
    if let Outcome::Retained { offer,.. } = &outcome {
        // Full native validation and durable exact proposal retention completed.
        // Failed and partial reassemblies are not released by this path.
        link.discard(&offer.id).map_err(|_| "A2 proposal durable handoff transport release")?;
    }
    Ok(outcome)
}
pub(crate) fn dispatch(
    runtime: &HybridRuntime,
    journal: &mut Journal,
    event: Event,
) -> Result<Outcome, String> {
    match event {
        Event::Completed { offer, bytes } if offer.kind == ObjectKind::A2BlockProposal => {
            if bytes.len() > ObjectKind::A2BlockProposal.max_bytes()
                || offer.length != bytes.len()
                || mutiny_transport_v2::objects::object_id(ObjectKind::A2BlockProposal, &bytes)
                    .map_err(|_| "Proposal object hash")?
                    != offer.id
            {
                return Err("Proposal transport identity".into());
            }
            let record = Record::decode(runtime, &bytes)?;
            journal.preserve(runtime, &record)?;
            Ok(Outcome::Retained {
                offer,
                block: record.header.block_hash(),
            })
        }
        event => Ok(Outcome::Other(event)),
    }
}
