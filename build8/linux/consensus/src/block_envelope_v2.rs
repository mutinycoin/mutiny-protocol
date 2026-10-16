//! Bounded hybrid certified block transport. Verification is pure; canonical
//! installation still requires authenticated parent state and integrity-halt
//! handling for conflicting finalized history.
use crate::{
    Error, Hash, Result,
    blocks::{BlockBody, canonical},
    certificates::Decision,
    continuity_v2::{Certificate, MAX_CERTIFICATE_BYTES},
    execution::{Execution, State, WorkParent},
    pow::{MAX_HEADER_BYTES, WorkHeader, mining_epoch},
    votes::IngressError,
    votes_v2::{AuthenticatedRound, HeightAuthority},
    work_authority_v2::{Authority, MAX_AUTHORITY_BYTES},
};
use minicbor::{Decoder, Encoder};
// One array head + version byte + four byte-string heads of at most five bytes.
pub const MAX_ENVELOPE_BYTES: usize =
    MAX_HEADER_BYTES + 64 * 1024 + MAX_AUTHORITY_BYTES + MAX_CERTIFICATE_BYTES + 22;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEnvelope {
    pub header: WorkHeader,
    pub body: BlockBody,
    pub authority: Authority,
    pub certificate: Certificate,
}
impl BlockEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.encode_body(self.body.encode()?, MAX_ENVELOPE_BYTES)
    }
    /// The caller supplies a sealed capability from the authenticated canonical parent.
    pub fn encode_with_capacity(&self, capacity: &crate::body_capacity_v3::BodyCapacity) -> Result<Vec<u8>> {
        self.check_capacity_parent(capacity)?;
        self.encode_body(capacity.encode(&self.body)?,capacity.envelope_limit())
    }
    fn check_capacity_parent(&self, capacity: &crate::body_capacity_v3::BodyCapacity) -> Result<()> {
        let c=&self.header.candidate;let p=capacity.parent();
        if c.network!=p.network || c.genesis!=p.genesis || c.fingerprint!=p.fingerprint
            || c.parent!=p.block || p.height.checked_add(1)!=Some(c.height)
            || capacity.root(&self.body)?!=c.body_root { return Err(Error::WrongAnchor); }
        Ok(())
    }
    fn encode_body(&self, body: Vec<u8>, limit: usize) -> Result<Vec<u8>> {
        let header = self.header.encode();
        if header.len() > MAX_HEADER_BYTES {
            return Err(Error::Oversize);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&header)
            .unwrap()
            .bytes(&body)
            .unwrap()
            .bytes(&self.authority.encode()?)
            .unwrap()
            .bytes(&self.certificate.encode()?)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > limit {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, MAX_ENVELOPE_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(5) || d.u8().map_err(|_| Error::Codec)? != 2
        {
            return Err(Error::Codec);
        }
        let result = Self {
            header: WorkHeader::decode(d.bytes().map_err(|_| Error::Codec)?)?,
            body: BlockBody::decode(d.bytes().map_err(|_| Error::Codec)?)?,
            authority: Authority::decode(d.bytes().map_err(|_| Error::Codec)?)?,
            certificate: Certificate::decode(d.bytes().map_err(|_| Error::Codec)?)?,
        };
        if d.position() != raw.len() || result.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(result)
    }
    /// Maximum outer syntax only. This neither selects a rule nor authenticates the header.
    pub fn untrusted_header(raw: &[u8]) -> Result<WorkHeader> {
        canonical(raw,crate::body_capacity_v3::MAX_ENVELOPE_BYTES)?;
        let mut d=Decoder::new(raw);
        if d.array().map_err(|_|Error::Codec)?!=Some(5) || d.u8().map_err(|_|Error::Codec)?!=2 { return Err(Error::Codec); }
        WorkHeader::decode(d.bytes().map_err(|_|Error::Codec)?)
    }
    pub fn decode_with_capacity(raw: &[u8], capacity: &crate::body_capacity_v3::BodyCapacity) -> Result<Self> {
        canonical(raw,capacity.envelope_limit())?;
        let mut d=Decoder::new(raw);
        if d.array().map_err(|_|Error::Codec)?!=Some(5) || d.u8().map_err(|_|Error::Codec)?!=2 { return Err(Error::Codec); }
        let result=Self {
            header:WorkHeader::decode(d.bytes().map_err(|_|Error::Codec)?)?,
            body:capacity.decode(d.bytes().map_err(|_|Error::Codec)?)?,
            authority:Authority::decode(d.bytes().map_err(|_|Error::Codec)?)?,
            certificate:Certificate::decode(d.bytes().map_err(|_|Error::Codec)?)?,
        };
        if d.position()!=raw.len() || result.encode_with_capacity(capacity)?!=raw { return Err(Error::NonCanonical); }
        Ok(result)
    }
    pub fn block_hash(&self) -> Hash {
        self.header.block_hash()
    }
    /// Preferred canonical-store boundary: derive all voter keys, eligibility
    /// and weights from the exact authenticated parent StateRoot. The expected
    /// root and WorkParent must come from local finalized history.
    pub fn verify_execute_from_parent_state(
        &self,
        state: &State,
        parent: &WorkParent,
        expected_parent_root: Hash,
        history: &crate::evidence_history_v2::History,
    ) -> std::result::Result<Execution, IngressError> {
        let anchor = crate::anchors::FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            height: parent.height,
            block: parent.block,
        };
        let authority = HeightAuthority::from_state(state, anchor, expected_parent_root)?;
        self.verify_execute_with_history(state, parent, &authority, history)
    }
    /// Ordinary full-replay-only path; the proof cannot come from a public caller.
    pub(crate) fn verify_execute_from_replayed_parent(
        &self,
        proof: &crate::canonical_store_v2::ReplayParent<'_>,
        parent: &WorkParent,
        history: &crate::evidence_history_v2::History,
    ) -> std::result::Result<Execution, IngressError> {
        proof.check(proof.state(), parent)?;
        // First-use authority derivation remains at the original envelope boundary.
        let authority = proof.authority()?;
        self.verify_execute_with_replay(proof.state(), parent, authority, history, Some(proof))
    }
    /// Registry/roots, state and target/history are trusted caller inputs,
    /// never inferred from fields supplied by this envelope.
    pub fn verify_execute(
        &self,
        state: &State,
        parent: &WorkParent,
        authority: &HeightAuthority,
    ) -> std::result::Result<Execution, IngressError> {
        self.verify_execute_with_history(
            state,
            parent,
            authority,
            &Default::default(),
        )
    }
    /// The caller supplies locally authenticated historical authority. Evidence
    /// bytes alone cannot establish an old registry or key's voting authority.
    pub fn verify_execute_with_history(
        &self,
        state: &State,
        parent: &WorkParent,
        authority: &HeightAuthority,
        history: &crate::evidence_history_v2::History,
    ) -> std::result::Result<Execution, IngressError> {
        self.verify_execute_with_replay(state, parent, authority, history, None)
    }
    fn verify_execute_with_replay(
        &self,
        state: &State,
        parent: &WorkParent,
        authority: &HeightAuthority,
        history: &crate::evidence_history_v2::History,
        replayed: Option<&crate::canonical_store_v2::ReplayParent<'_>>,
    ) -> std::result::Result<Execution, IngressError> {
        let mut round = AuthenticatedRound::new(authority.clone())?;
        let executed = round.validate_proposal_with_replay(
            state,
            parent,
            &self.header,
            &self.authority,
            &self.body,
            history,
            None,
            replayed,
        )?;
        let c = &self.header.candidate;
        let decision = Decision {
            network: authority.parent.network,
            genesis: authority.parent.genesis,
            fingerprint: authority.parent.fingerprint,
            purpose: 2,
            height: c.height,
            mining_epoch: mining_epoch(c.timestamp, parent.t0)?,
            continuity_period: (c.height - 1) / 60,
            round: self.certificate.decision.round,
            step: 3,
            previous_finalized_anchor: authority.parent.id(),
            parent: authority.parent.block,
            block: self.header.block_hash(),
            state: executed.root,
            membership: authority.membership,
            reputation: authority.reputation,
            attestation: authority.attestation,
        };
        self.certificate
            .verify_quorum(&decision, &authority.parent, &authority.voters)?;
        Ok(executed)
    }
}
