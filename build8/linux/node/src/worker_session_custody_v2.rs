//! Restricted Worker handshake adapters over current encrypted Node custody.
//! No listener, private export, provisioning, or Continuity authority.
use crate::{
    node_custody_v2::EncryptedNodeKey, software_coordinator_custody_v2::EncryptedCoordinatorKey,
};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor, canonical_store_v2::CanonicalStore};
use mutiny_crypto_v2::{HybridSignature, PublicKey};
use mutiny_transport_v2::{
    Error, Result, worker_context_v2::Context, worker_handshake_v2::NodeSessionSigner,
};

pub(crate) fn current_context(
    chain: &CanonicalStore,
    parent: &FinalizedAnchor,
    license: Hash,
    worker: Hash,
    timestamp: u64,
    descriptor: &[u8],
) -> Result<Context> {
    let (work, binding, current, epoch) = chain
        .current_worker_session(parent, license, worker, timestamp)
        .map_err(|_| Error::Context)?;
    if current != descriptor {
        return Err(Error::Context);
    }
    let (public, generation) =
        PublicKey::decode_descriptor(descriptor).map_err(|_| Error::Context)?;
    let context = Context::pinned(&binding, &public, generation)?;
    let height = work.parent_height.checked_add(1).ok_or(Error::Context)?;
    if !context.matches_current(&binding, &public, generation, height, epoch) {
        return Err(Error::Context);
    }
    Ok(context)
}
enum Custody<'a> {
    Physical(&'a EncryptedNodeKey),
    Software(&'a EncryptedCoordinatorKey),
}
/// Borrows existing unlocked encrypted custody. Fresh canonical reads precede
/// and follow signing. The actor supplies timestamp from its trusted clock;
/// it must discard this adapter on parent/time/assignment change and revalidate
/// the completed session against current Authority before activation/traffic.
pub struct WorkerSessionSigner<'a> {
    key: Custody<'a>,
    chain: &'a CanonicalStore,
    parent: &'a FinalizedAnchor,
    license: Hash,
    worker: Hash,
    timestamp: u64,
}
impl<'a> WorkerSessionSigner<'a> {
    pub fn physical(
        key: &'a EncryptedNodeKey,
        chain: &'a CanonicalStore,
        parent: &'a FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
    ) -> Result<(Context, Self)> {
        let s = Self {
            key: Custody::Physical(key),
            chain,
            parent,
            license,
            worker,
            timestamp,
        };
        let c = s.current()?;
        Ok((c, s))
    }
    pub fn software(
        key: &'a EncryptedCoordinatorKey,
        chain: &'a CanonicalStore,
        parent: &'a FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
    ) -> Result<(Context, Self)> {
        let s = Self {
            key: Custody::Software(key),
            chain,
            parent,
            license,
            worker,
            timestamp,
        };
        let c = s.current()?;
        Ok((c, s))
    }
    fn current(&self) -> Result<Context> {
        match self.key {
            Custody::Physical(k) => k.worker_session_context(
                self.chain,
                self.parent,
                self.license,
                self.worker,
                self.timestamp,
            ),
            Custody::Software(k) => k.worker_session_context(
                self.chain,
                self.parent,
                self.license,
                self.worker,
                self.timestamp,
            ),
        }
    }
}
impl NodeSessionSigner for WorkerSessionSigner<'_> {
    fn validate_context(&self, context: &Context) -> Result<()> {
        if self.current()?.id() != context.id() {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn sign_session(
        &self,
        context: &Context,
        hello: &[u8],
        body: &[u8],
    ) -> Result<HybridSignature> {
        self.validate_context(context)?;
        let signature = match self.key {
            Custody::Physical(k) => k.sign_worker_session(context, hello, body),
            Custody::Software(k) => k.sign_worker_session(context, hello, body),
        }?;
        self.validate_context(context)?;
        Ok(signature)
    }
}
