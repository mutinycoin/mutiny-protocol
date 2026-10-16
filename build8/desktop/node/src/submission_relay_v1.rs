//! Explicit bounded relay over an admission-owned authenticated ObjectLink.
//! The canonical ID is the dedup key. Only the runtime's complete, locally
//! validated pending object is eligible; arbitrary transport copies are not.
use crate::hybrid_runtime_v2::HybridRuntime;
use crate::hybrid_peer_error_v2::{PeerFailure, PeerResult};
use mutiny_consensus_v8::{Hash, submission_v1::Submission};
use mutiny_transport_v2::{
    object_link::ObjectLink,
    objects::{MAX_SUBMISSIONS, ObjectKind, Offer},
};
use std::collections::{BTreeMap, BTreeSet};
pub struct Relay {
    peer: Hash,
    in_flight: BTreeMap<Hash, Offer>,
    delivered: BTreeSet<Hash>,
}
impl Relay {
    pub fn new(peer: Hash) -> Result<Self, String> {
        if peer == [0; 32] {
            return Err("Relay peer".into());
        }
        Ok(Self {
            peer,
            in_flight: BTreeMap::new(),
            delivered: BTreeSet::new(),
        })
    }
    /// At most two advertisements per explicit service turn. Session AEAD and
    /// current-pin guarding are supplied by PeerLink before entering this call.
    pub fn prepare(
        &mut self,
        runtime: &mut HybridRuntime,
        link: &mut ObjectLink,
    ) -> Result<Vec<(Offer, Vec<u8>)>, String> {
        self.prepare_typed(runtime, link).map_err(String::from)
    }
    pub fn prepare_typed(
        &mut self,
        runtime: &mut HybridRuntime,
        link: &mut ObjectLink,
    ) -> PeerResult<Vec<(Offer, Vec<u8>)>> {
        if link.peer_id() != self.peer {
            return Err("Relay peer changed".into());
        }
        let (genesis, fingerprint) = runtime.network_context();
        if !link.matches_network(genesis, fingerprint) {
            return Err("Relay canonical network mismatch".into());
        }
        let mut pending = runtime
            .relay_pending()
            .map_err(|e| format!("Relay canonical basis: {e:?}"))?;
        pending.sort_by_key(|o| o.id);
        let ids: BTreeSet<_> = pending.iter().map(|o| o.id).collect();
        self.delivered.retain(|id| ids.contains(id));
        // Recover only transport copies backed by durable exact local admission.
        // Incomplete, failed or foreign evidence is preserved in place.
        for offer in link
            .submission_offers()
            .map_err(|e| PeerFailure::transport("Relay queue", e))?
        {
            let (_, raw) = link
                .completed(&offer.id)
                .map_err(|e| PeerFailure::transport("Relay bytes", e))?;
            let list = if offer.kind == ObjectKind::SignedTransaction {
                0
            } else {
                1
            };
            let Ok(object) = Submission::decode(list, &raw) else {
                continue;
            };
            if runtime
                .exact_submission_bytes(object.id)
                .map_err(|e| format!("Relay durable bytes: {e:?}"))?
                == Some((list, raw))
            {
                self.in_flight.insert(object.id, offer);
            }
        }
        let mut acknowledged = Vec::new();
        for (id, offer) in &self.in_flight {
            let count = offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
            if link
                .acknowledged(&offer.id, 0, count)
                .map_err(|e| PeerFailure::transport("Relay ACK", e))?
                .bits
                .into_iter()
                .all(|b| b)
            {
                // The source cache retains the exact complete bytes/outcome.
                if runtime
                    .exact_submission_bytes(*id)
                    .map_err(|e| format!("Relay retained evidence: {e:?}"))?
                    .is_none()
                {
                    return Err("Relay evidence unavailable".into());
                }
                link.discard(&offer.id)
                    .map_err(|e| PeerFailure::transport("Relay transport release", e))?;
                acknowledged.push(*id);
            }
        }
        for id in acknowledged {
            self.in_flight.remove(&id);
            self.delivered.insert(id);
        }
        let mut frames = Vec::new();
        for object in pending {
            if frames.len() >= MAX_SUBMISSIONS || self.in_flight.len() >= MAX_SUBMISSIONS {
                break;
            }
            if self.delivered.contains(&object.id) || self.in_flight.contains_key(&object.id) {
                continue;
            }
            // Defend the live cache too: no coherent metadata edit or signature
            // cache bit can cause invalid authorization/preimages to be relayed.
            object
                .verify_signatures()
                .map_err(|e| format!("Relay signatures: {e:?}"))?;
            let kind = if object.list == 0 {
                ObjectKind::SignedTransaction
            } else {
                ObjectKind::SignedOperation
            };
            match link.enqueue(kind, &object.raw, 0) {
                Ok((offer, frame)) => {
                    self.in_flight.insert(object.id, offer.clone());
                    frames.push((offer, frame));
                }
                Err(mutiny_transport_v2::Error::Limit) => break,
                Err(e) => return Err(PeerFailure::transport("Relay queue insertion", e)),
            }
        }
        Ok(frames)
    }
}
