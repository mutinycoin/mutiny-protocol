//! Transport-neutral canonical block container. Parsing never implies settlement.
use crate::{
    Error, Hash, Result,
    blocks::{BlockBody, canonical},
    certificates::{Certificate, Decision, Voter},
    pow::{WorkAuthority, WorkContext, WorkHeader, meets_target, mining_epoch, validate_authority},
};
use minicbor::{Decoder, Encoder};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEnvelope {
    pub header: WorkHeader,
    pub body: BlockBody,
    pub authority: WorkAuthority,
    pub authority_signature: [u8; 64],
    pub certificate: Certificate,
}
impl BlockEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.header.encode())
            .unwrap()
            .bytes(&self.body.encode()?)
            .unwrap()
            .bytes(&self.authority.envelope(&self.authority_signature))
            .unwrap()
            .bytes(&self.certificate.encode()?)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > 330 * 1024 {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, 330 * 1024)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(5) || d.u8().map_err(|_| Error::Codec)? != 1
        {
            return Err(Error::Codec);
        }
        let header = WorkHeader::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let body = BlockBody::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let (authority, authority_signature) =
            WorkAuthority::from_envelope(d.bytes().map_err(|_| Error::Codec)?)?;
        let certificate = Certificate::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let b = Self {
            header,
            body,
            authority,
            authority_signature,
            certificate,
        };
        if b.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(b)
    }
    pub fn block_hash(&self) -> Hash {
        self.header.block_hash()
    }
    /// Checks work and a commit certificate against trusted parent/state inputs.
    /// Caller MUST additionally execute all operations, check the post-StateRoot,
    /// maturity/value conservation and the durable BFT state machine. This API
    /// intentionally does not return an AcceptedBlock or mutate canonical state.
    pub fn verify_evidence(
        &self,
        context: &WorkContext,
        owner: Hash,
        decision: &Decision,
        registry: &BTreeMap<Hash, Voter>,
    ) -> Result<()> {
        let h = &self.header;
        let c = &h.candidate;
        if self.body.height != c.height
            || self.body.root()? != c.body_root
            || self.body.reward_owner != owner
        {
            return Err(Error::WrongAnchor);
        }
        validate_authority(h, &self.authority, &self.authority_signature, context)?;
        decision.verify_parent(&crate::anchors::FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis: context.genesis,
            fingerprint: context.fingerprint,
            height: context.parent_height,
            block: context.parent,
        })?;
        if !meets_target(&h.digest(), &c.target) {
            return Err(Error::InvalidCounter);
        }
        if decision.network != c.network
            || decision.genesis != c.genesis
            || decision.fingerprint != c.fingerprint
            || decision.height != c.height
            || decision.parent != c.parent
            || decision.block != h.block_hash()
            || decision.state != c.state_root
            || decision.mining_epoch != mining_epoch(c.timestamp, context.t0)?
            || decision.continuity_period != (c.height - 1) / 60
            || decision.purpose != 2
            || decision.step != 3
        {
            return Err(Error::WrongAnchor);
        }
        self.certificate.verify_quorum(decision, registry)
    }
}
