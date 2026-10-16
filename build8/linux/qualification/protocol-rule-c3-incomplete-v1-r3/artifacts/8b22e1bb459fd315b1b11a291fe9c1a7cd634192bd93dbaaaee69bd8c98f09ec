//! Candidate hybrid coordinator authority. This does not grant a license,
//! Worker assignment, ownership or Continuity weight. Parent state supplies
//! the exact node descriptor and WorkContext before verification.
use crate::{
    Error, Hash, Result, domain_hash,
    pow::{WorkAuthority, WorkContext, WorkHeader, validate_authority_fields},
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
pub const MAX_AUTHORITY_BYTES: usize = 8192;
pub fn node_identity(descriptor: &[u8]) -> Result<Hash> {
    let (key, _) = PublicKey::decode_descriptor(descriptor).map_err(|_| Error::Codec)?;
    if key.role != Role::Node {
        return Err(Error::WrongOperation);
    }
    Ok(domain_hash(
        b"MUTINY-BUILD8-NODE-AUTHORITY-IDENTITY-V2",
        descriptor,
    ))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    pub work: WorkAuthority,
    pub node_descriptor: Vec<u8>,
    pub signature: HybridSignature,
}
impl Authority {
    pub fn unsigned(&self) -> Result<Vec<u8>> {
        if self.work.coordinator != node_identity(&self.node_descriptor)? {
            return Err(Error::WrongAnchor);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&self.work.encode())
            .unwrap()
            .bytes(&self.node_descriptor)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-HYBRID-WORK-AUTHORITY-ID-V2",
            &self.unsigned()?,
        ))
    }
    pub fn sign(&mut self, key: &HybridKey) -> Result<()> {
        let (expected, _) =
            PublicKey::decode_descriptor(&self.node_descriptor).map_err(|_| Error::Codec)?;
        if key.public() != &expected || expected.role != Role::Node {
            return Err(Error::WrongOperation);
        }
        self.signature = key
            .sign(Domain::NodeWork, &self.unsigned()?)
            .map_err(|_| Error::BadSignature)?;
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&self.unsigned()?)
            .unwrap()
            .bytes(&self.signature.ed448)
            .unwrap()
            .bytes(&self.signature.fndsa)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_AUTHORITY_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_AUTHORITY_BYTES)?;
        let mut d = Decoder::new(raw);
        let decoded = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let error = || minicbor::decode::Error::message("hybrid work authority");
            if d.array()? != Some(4) || d.u8()? != 2 {
                return Err(error());
            }
            let unsigned = d.bytes()?;
            let mut u = Decoder::new(unsigned);
            if u.array()? != Some(3) || u.u8()? != 2 {
                return Err(error());
            }
            let work = WorkAuthority::decode(u.bytes()?).map_err(|_| error())?;
            let desc = u.bytes()?;
            if desc.len() > 2048 {
                return Err(error());
            }
            let value = Self {
                work,
                node_descriptor: desc.to_vec(),
                signature: HybridSignature {
                    ed448: d.bytes()?.try_into().map_err(|_| error())?,
                    fndsa: d.bytes()?.try_into().map_err(|_| error())?,
                },
            };
            if u.position() != unsigned.len() {
                return Err(error());
            }
            Ok(value)
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || decoded.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(decoded)
    }
    pub fn verify(
        &self,
        header: &WorkHeader,
        context: &WorkContext,
        expected_node: &[u8],
    ) -> Result<()> {
        self.encode()?;
        if self.node_descriptor != expected_node
            || node_identity(expected_node)? != context.coordinator
        {
            return Err(Error::UnknownSigner);
        }
        validate_authority_fields(header, &self.work, self.id()?, context)?;
        let (key, _) = PublicKey::decode_descriptor(expected_node).map_err(|_| Error::Codec)?;
        key.verify(Domain::NodeWork, &self.unsigned()?, &self.signature)
            .map_err(|_| Error::BadSignature)
    }
}
