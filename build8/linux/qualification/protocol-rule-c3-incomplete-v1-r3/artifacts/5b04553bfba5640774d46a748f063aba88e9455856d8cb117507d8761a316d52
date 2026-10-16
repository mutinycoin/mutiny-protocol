//! Fixed receipt-domain encrypted Node custody. No secret export or publication.
//! Accounting supplies the authenticated previous checkpoint and must commit
//! these exact receipt bytes before returning them to the Worker.
use crate::{
    node_custody_v2::EncryptedNodeKey, software_coordinator_custody_v2::EncryptedCoordinatorKey,
};
use mutiny_consensus_v8::{
    Hash, anchors::FinalizedAnchor, blocks::BlockBody, canonical_store_v2::CanonicalStore,
    observation_receipt_v2::Intent, pow::WorkHeader, work_authority_v2::Authority,
};
type Result<T> = std::result::Result<T, String>;
pub enum Custody<'a> {
    Physical(&'a EncryptedNodeKey),
    Software(&'a EncryptedCoordinatorKey),
}
pub struct Request<'a> {
    pub parent: &'a FinalizedAnchor,
    /// Trusted actor time, not a timestamp supplied by the Worker.
    pub timestamp: u64,
    pub header: &'a WorkHeader,
    pub authority: &'a Authority,
    pub body: &'a BlockBody,
    pub sequence: u64,
    pub previous: Hash,
    pub prior_total: u64,
}
impl Custody<'_> {
    fn current(&self, chain: &CanonicalStore, request: &Request<'_>) -> Result<[u8; 64]> {
        let c = &request.header.candidate;
        let context = match self {
            Self::Physical(key) => key.worker_session_context(
                chain,
                request.parent,
                c.license,
                c.worker,
                request.timestamp,
            ),
            Self::Software(key) => key.worker_session_context(
                chain,
                request.parent,
                c.license,
                c.worker,
                request.timestamp,
            ),
        }
        .map_err(|_| "Current observation authority unavailable")?;
        Ok(context.id())
    }
    /// Full historical proposal validation is separate from fresh authorization
    /// to sign the receipt now. A retired descriptor cannot use this adapter.
    /// Returned bytes remain private to the owning actor until durable commit
    /// and candidate-retention requirements are satisfied.
    pub fn sign(&self, chain: &CanonicalStore, request: Request<'_>) -> Result<Vec<u8>> {
        let before = self.current(chain, &request)?;
        chain
            .validate_observation_v2(request.header, request.authority, request.body)
            .map_err(|_| "Historical observation validation failed")?;
        let intent = Intent::accepted(
            request.header,
            request.sequence,
            request.previous,
            request.prior_total,
            &request.authority.node_descriptor,
        )
        .map_err(|_| "Observation checkpoint intent")?;
        if self.current(chain, &request)? != before {
            return Err("Observation authority changed".into());
        }
        let receipt = match self {
            Self::Physical(key) => {
                key.sign_observation_intent(&request.authority.node_descriptor, &intent)
            }
            Self::Software(key) => {
                key.sign_observation_intent(&request.authority.node_descriptor, &intent)
            }
        }?;
        if self.current(chain, &request)? != before {
            return Err("Observation authority changed during signing".into());
        }
        intent
            .verify(&receipt)
            .map_err(|_| "Observation output verification")?;
        Ok(receipt)
    }
}
