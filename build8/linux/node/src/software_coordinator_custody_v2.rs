//! Validator/cloud work-only custody. An owner-authorized active Worker assignment
//! supplies its public authority. This key never admits hardware or signs votes.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID, anchors::FinalizedAnchor, blocks::BlockBody,
    canonical_store_v2::CanonicalStore, work_authority_v2::Authority,
};
use mutiny_crypto_v2::{HybridKey, PublicKey, Role};
type Result<T> = std::result::Result<T, String>;
pub fn custody_context(genesis: Hash, fingerprint: Hash, descriptor: &[u8]) -> Result<Hash> {
    let (public, _) =
        PublicKey::decode_descriptor(descriptor).map_err(|_| "Invalid coordinator descriptor")?;
    if public.role != Role::Node || genesis == [0; 32] || fingerprint == [0; 32] {
        return Err("Coordinator context".into());
    }
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(5)
        .unwrap()
        .u8(2)
        .unwrap()
        .u32(NETWORK_ID)
        .unwrap()
        .bytes(&genesis)
        .unwrap()
        .bytes(&fingerprint)
        .unwrap()
        .bytes(descriptor)
        .unwrap();
    Ok(mutiny_consensus_v8::domain_hash(
        b"MUTINY-BUILD8-SOFTWARE-COORDINATOR-CUSTODY-V2",
        &e.into_writer(),
    ))
}
pub struct EncryptedCoordinatorKey {
    genesis: Hash,
    fingerprint: Hash,
    descriptor: Vec<u8>,
    key: HybridKey,
}
impl EncryptedCoordinatorKey {
    pub(crate) fn sign_observation_intent(
        &self,
        descriptor: &[u8],
        intent: &mutiny_consensus_v8::observation_receipt_v2::Intent,
    ) -> Result<Vec<u8>> {
        if descriptor != self.descriptor {
            return Err("Observation coordinator generation".into());
        }
        let signature = self
            .key
            .sign(mutiny_crypto_v2::Domain::NodeObservation, intent.body())
            .map_err(|_| "Observation signing failed")?;
        intent
            .finish(&signature)
            .map_err(|_| "Observation signature verification failed".into())
    }
    pub(crate) fn worker_session_context(
        &self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
    ) -> mutiny_transport_v2::Result<mutiny_transport_v2::worker_context_v2::Context> {
        if parent.genesis != self.genesis || parent.fingerprint != self.fingerprint {
            return Err(mutiny_transport_v2::Error::Context);
        }
        let (_, descriptor) = chain
            .current_software_coordinator(parent, license, worker, timestamp)
            .map_err(|_| mutiny_transport_v2::Error::Context)?;
        if descriptor != self.descriptor {
            return Err(mutiny_transport_v2::Error::Context);
        }
        crate::worker_session_custody_v2::current_context(
            chain,
            parent,
            license,
            worker,
            timestamp,
            &self.descriptor,
        )
    }
    pub(crate) fn sign_worker_session(
        &self,
        context: &mutiny_transport_v2::worker_context_v2::Context,
        hello: &[u8],
        body: &[u8],
    ) -> mutiny_transport_v2::Result<mutiny_crypto_v2::HybridSignature> {
        use mutiny_transport_v2::worker_handshake_v2::NodeSessionSigner;
        self.key.sign_session(context, hello, body)
    }
    #[cfg(target_os = "linux")]
    pub fn publish_current_generation(
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        directory: &std::path::Path,
        encrypted: &[u8],
        password: &str,
    ) -> Result<()> {
        let current = Self::unlock(
            chain, parent, license, worker, timestamp, encrypted, password,
        )?;
        let (_, generation) = PublicKey::decode_descriptor(&current.descriptor)
            .map_err(|_| "Coordinator descriptor")?;
        let context = custody_context(current.genesis, current.fingerprint, &current.descriptor)?;
        crate::continuity_generation_store_v2::publish_node(
            directory, context, generation, encrypted,
        )
        .map_err(str::to_owned)?;
        let (_, descriptor) = chain
            .current_software_coordinator(parent, license, worker, timestamp)
            .map_err(|_| "Coordinator changed during publication")?;
        if descriptor != current.descriptor {
            return Err("Coordinator publication retired".into());
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub fn unlock_generation_file(
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        directory: &std::path::Path,
        password: &str,
    ) -> Result<Self> {
        let (_, descriptor) = chain
            .current_software_coordinator(parent, license, worker, timestamp)
            .map_err(|_| "Coordinator authority unavailable")?;
        let (_, generation) =
            PublicKey::decode_descriptor(&descriptor).map_err(|_| "Coordinator descriptor")?;
        let context = custody_context(parent.genesis, parent.fingerprint, &descriptor)?;
        let encrypted =
            crate::continuity_generation_store_v2::read_node(directory, context, generation)
                .map_err(str::to_owned)?;
        Self::unlock(
            chain, parent, license, worker, timestamp, &encrypted, password,
        )
    }
    pub fn unlock(
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        encrypted: &[u8],
        password: &str,
    ) -> Result<Self> {
        let (_, descriptor) = chain
            .current_software_coordinator(parent, license, worker, timestamp)
            .map_err(|_| "No current software coordinator assignment")?;
        let context = custody_context(parent.genesis, parent.fingerprint, &descriptor)?;
        let (key, generation) = HybridKey::open_for(Role::Node, password, &context, encrypted)
            .map_err(|_| "Coordinator custody authentication failed")?;
        if key
            .public()
            .descriptor(generation)
            .map_err(|_| "Coordinator generation")?
            != descriptor
        {
            return Err("Coordinator key mismatch".into());
        }
        let (_, current) = chain
            .current_software_coordinator(parent, license, worker, timestamp)
            .map_err(|_| "Coordinator assignment changed during unlock")?;
        if current != descriptor {
            return Err("Coordinator descriptor changed".into());
        }
        Ok(Self {
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            descriptor,
            key,
        })
    }
    pub fn authorize_work(
        &self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        authority: &mut Authority,
        body: &BlockBody,
    ) -> Result<()> {
        if parent.genesis != self.genesis
            || parent.fingerprint != self.fingerprint
            || authority.node_descriptor != self.descriptor
        {
            return Err("Coordinator custody context mismatch".into());
        }
        chain
            .validate_software_coordinator_work(parent, authority, body)
            .map_err(|_| "Coordinator canonical work preflight failed")?;
        let mut signed = authority.clone();
        signed
            .sign(&self.key)
            .map_err(|_| "Coordinator signing failed")?;
        let c = &signed.work.candidate;
        let (_, descriptor) = chain
            .current_software_coordinator(parent, c.license, c.worker, c.timestamp)
            .map_err(|_| "Coordinator authority changed during signing")?;
        if descriptor != self.descriptor {
            return Err("Coordinator descriptor retired".into());
        }
        *authority = signed;
        Ok(())
    }
}
