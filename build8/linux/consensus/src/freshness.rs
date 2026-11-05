//! Rolling canonical-height freshness. Admission/TPM evidence verification is
//! mandatory at insertion; a committed record is read only from trusted state.
use crate::{Error, Hash, Result, anchors::FinalizedAnchor, domain_hash};
use minicbor::{Decoder, Encoder};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreshnessRecord {
    pub node: Hash,
    pub generation: u64,
    pub key: [u8; 33],
    pub committed_height: u64,
    pub evidence_commitment: Hash,
}
impl FreshnessRecord {
    pub fn eligible(&self, node: Hash, generation: u64, key: [u8; 33], slot: u64) -> bool {
        self.node == node
            && self.generation == generation
            && self.key == key
            && slot
                .checked_sub(self.committed_height)
                .is_some_and(|age| (1..=60).contains(&age))
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .bytes(&self.key)
            .unwrap()
            .u64(self.committed_height)
            .unwrap()
            .bytes(&self.evidence_commitment)
            .unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 256 {
            return Err(Error::Oversize);
        }
        let mut d = Decoder::new(raw);
        let record = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            if d.array()? != Some(6) || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("freshness"));
            }
            fn bytes<const N: usize>(
                d: &mut Decoder<'_>,
            ) -> std::result::Result<[u8; N], minicbor::decode::Error> {
                d.bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("length"))
            }
            Ok(Self {
                node: bytes(&mut d)?,
                generation: d.u64()?,
                key: bytes(&mut d)?,
                committed_height: d.u64()?,
                evidence_commitment: bytes(&mut d)?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || record.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(record)
    }
}

/// Inputs are derived from the canonical parent registry, not peer assertions.
#[derive(Clone)]
pub struct PhysicalMember {
    pub node: Hash,
    pub generation: u64,
    pub continuity_key: [u8; 33],
    pub hardware: Hash,
    pub admission_commitment: Hash,
    pub attestation_key: Vec<u8>,
}

/// The production implementation must verify TPM quote/certification, enrolled
/// physical hardware/key, measured-platform policy and exact challenge. A node
/// authentication signature or a naked Continuity signature is insufficient.
pub trait PhysicalAttestationVerifier {
    fn verify(&self, member: &PhysicalMember, challenge: Hash, evidence: &[u8]) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationRefresh {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub node: Hash,
    pub generation: u64,
    pub height: u64,
    pub parent_anchor: Hash,
    pub evidence: Vec<u8>,
}
impl AttestationRefresh {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.height == 0 || self.evidence.is_empty() || self.evidence.len() > 16 * 1024 {
            return Err(Error::Oversize);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(10)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(12)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(&self.parent_anchor)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .array(1)
            .unwrap()
            .bytes(&self.evidence)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > 16 * 1024 {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 16 * 1024 {
            return Err(Error::Oversize);
        }
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            fn hash(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
                d.bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("hash"))
            }
            if d.array()? != Some(10) || d.u8()? != 1 || d.u8()? != 12 {
                return Err(minicbor::decode::Error::message("refresh"));
            }
            let network = d.u32()?;
            let genesis = hash(&mut d)?;
            let fingerprint = hash(&mut d)?;
            let node = hash(&mut d)?;
            let height = d.u64()?;
            if d.u64()? != height || d.array()? != Some(2) {
                return Err(minicbor::decode::Error::message("slot"));
            }
            let parent_anchor = hash(&mut d)?;
            let generation = d.u64()?;
            if d.array()? != Some(1) {
                return Err(minicbor::decode::Error::message("evidence"));
            }
            let evidence = d.bytes()?.to_vec();
            Ok(Self {
                network,
                genesis,
                fingerprint,
                node,
                generation,
                height,
                parent_anchor,
                evidence,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    pub fn challenge(&self) -> Hash {
        let mut e = Encoder::new(Vec::new());
        e.array(8)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .bytes(&self.parent_anchor)
            .unwrap();
        domain_hash(b"MUTINY-BUILD8-ATTESTATION-REFRESH-V1", &e.into_writer())
    }
    /// Produces a tentative post-state record only. Current-block ACKs must
    /// continue using the old parent record, even after this method succeeds.
    pub fn validate<V: PhysicalAttestationVerifier>(
        &self,
        parent: &FinalizedAnchor,
        member: &PhysicalMember,
        verifier: &V,
    ) -> Result<FreshnessRecord> {
        self.encode()?;
        parent.validate_context(self.genesis, self.fingerprint)?;
        if self.network != parent.network
            || parent.height.checked_add(1) != Some(self.height)
            || self.parent_anchor != parent.id()
        {
            return Err(Error::WrongAnchor);
        }
        if self.node != member.node {
            return Err(Error::UnknownSigner);
        }
        if self.generation != member.generation {
            return Err(Error::WrongGeneration);
        }
        if self.evidence.is_empty() || self.evidence.len() > 16 * 1024 {
            return Err(Error::Oversize);
        }
        verifier.verify(member, self.challenge(), &self.evidence)?;
        Ok(FreshnessRecord {
            node: self.node,
            generation: self.generation,
            key: member.continuity_key,
            committed_height: self.height,
            evidence_commitment: domain_hash(
                b"MUTINY-BUILD8-ATTESTATION-EVIDENCE-V1",
                &self.evidence,
            ),
        })
    }
}

/// Genesis uses a separately domain-separated supervised challenge, without any
/// GenesisBlockHash/StateRoot dependency. The ceremony supplies locked pre-state
/// identity input commitment and an unpredictable supervised challenge nonce.
pub fn genesis_challenge(
    identity_inputs: Hash,
    supervised_nonce: Hash,
    member: &PhysicalMember,
) -> Hash {
    let mut e = Encoder::new(Vec::new());
    e.array(7)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&identity_inputs)
        .unwrap()
        .bytes(&supervised_nonce)
        .unwrap()
        .bytes(&member.node)
        .unwrap()
        .bytes(&member.hardware)
        .unwrap()
        .u64(member.generation)
        .unwrap()
        .bytes(&member.continuity_key)
        .unwrap();
    domain_hash(
        b"MUTINY-BUILD8-GENESIS-PHYSICAL-ATTESTATION-V1",
        &e.into_writer(),
    )
}
pub fn validate_genesis<V: PhysicalAttestationVerifier>(
    identity_inputs: Hash,
    supervised_nonce: Hash,
    member: &PhysicalMember,
    evidence: &[u8],
    verifier: &V,
) -> Result<FreshnessRecord> {
    if evidence.is_empty() || evidence.len() > 16 * 1024 {
        return Err(Error::Oversize);
    }
    verifier.verify(
        member,
        genesis_challenge(identity_inputs, supervised_nonce, member),
        evidence,
    )?;
    Ok(FreshnessRecord {
        node: member.node,
        generation: member.generation,
        key: member.continuity_key,
        committed_height: 0,
        evidence_commitment: domain_hash(b"MUTINY-BUILD8-ATTESTATION-EVIDENCE-V1", evidence),
    })
}
