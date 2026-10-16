//! Internal body codec for explicitly new A2 operational journal schemas.
//! Historical schemas keep the original codec. Capabilities are obtained only
//! from the trusted canonical store, including historical rows during reopen.
use crate::hybrid_runtime_v2::HybridRuntime;
use mutiny_consensus_v8::{Hash,blocks::BlockBody,body_capacity_v3::BodyCapacity,pow::WorkHeader,work_authority_v2::Authority};
use std::collections::BTreeMap;
type Result<T> = std::result::Result<T,String>;
pub(crate) struct Codec { capacities: Option<BTreeMap<Hash,BodyCapacity>> }
impl Codec {
    pub(crate) fn legacy() -> Self { Self { capacities: None } }
    pub(crate) fn successor(runtime: &HybridRuntime) -> Result<Self> {
        let parent = runtime.head().map_err(|_| "Journal canonical head")?;
        let capacity = runtime.chain.body_capacity(&parent).map_err(|_| "Journal authenticated capacity")?;
        if !capacity.allows_a2() { return Err("Journal successor rule not selected".into()); }
        Ok(Self { capacities: Some(BTreeMap::new()) })
    }
    pub(crate) fn is_successor(&self) -> bool { self.capacities.is_some() }
    pub(crate) fn limit(&self) -> usize { if self.is_successor() { 262_150 } else { 65_536 } }
    pub(crate) fn bind(&mut self,runtime: &HybridRuntime,authority: &Authority) -> Result<()> {
        self.bind_store(&runtime.chain,authority)
    }
    pub(crate) fn bind_store(&mut self,store: &mutiny_consensus_v8::canonical_store_v2::CanonicalStore,authority: &Authority) -> Result<()> {
        let Some(capacities) = self.capacities.as_mut() else { return Ok(()); };
        let header = WorkHeader {
            candidate: authority.work.candidate.clone(),
            authority: authority.id().map_err(|_| "Journal authority identity")?,
            nonce: 0,
        };
        // An issuance has no PoW nonce yet. This authenticates its historical
        // parent capacity only; signed work and execution are checked elsewhere.
        let capacity = store.proposal_body_capacity(&header).map_err(|_| "Journal historical capacity")?;
        if !capacity.allows_a2() { return Err("Journal historical successor not selected".into()); }
        if capacities.len() >= 4097 && !capacities.contains_key(&header.candidate.parent) {
            return Err("Journal capacity contexts full".into());
        }
        capacities.insert(header.candidate.parent,capacity);
        Ok(())
    }
    pub(crate) fn retain_parents(&mut self,parents: &std::collections::BTreeSet<Hash>) {
        if let Some(capacities) = self.capacities.as_mut() {
            capacities.retain(|parent,_|parents.contains(parent));
        }
    }
    fn capacity(&self,authority: &Authority) -> Result<Option<&BodyCapacity>> {
        let Some(capacities) = &self.capacities else { return Ok(None); };
        let capacity = capacities.get(&authority.work.candidate.parent).ok_or("Journal body capacity unavailable")?;
        let c = &authority.work.candidate;
        let p = capacity.parent();
        if (p.genesis,p.fingerprint,p.block,p.height.checked_add(1)) != (c.genesis,c.fingerprint,c.parent,Some(c.height)) {
            return Err("Journal body parent context".into());
        }
        Ok(Some(capacity))
    }
    pub(crate) fn encode(&self,authority: &Authority,body: &BlockBody) -> Result<Vec<u8>> {
        match self.capacity(authority)? {
            Some(capacity) => capacity.encode(body).map_err(|_| "Journal successor body encoding".into()),
            None => body.encode().map_err(|_| "Journal legacy body encoding".into()),
        }
    }
    pub(crate) fn decode(&self,authority: &Authority,raw: &[u8]) -> Result<BlockBody> {
        match self.capacity(authority)? {
            Some(capacity) => capacity.decode(raw).map_err(|_| "Journal successor body decoding".into()),
            None => BlockBody::decode(raw).map_err(|_| "Journal legacy body decoding".into()),
        }
    }
    pub(crate) fn root(&self,authority: &Authority,body: &BlockBody) -> Result<Hash> {
        match self.capacity(authority)? {
            Some(capacity) => capacity.root(body).map_err(|_| "Journal successor body root".into()),
            None => body.root().map_err(|_| "Journal legacy body root".into()),
        }
    }
}
