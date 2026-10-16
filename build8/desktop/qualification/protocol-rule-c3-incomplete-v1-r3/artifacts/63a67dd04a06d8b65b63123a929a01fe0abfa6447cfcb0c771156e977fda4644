//! Canonical history identity; deliberately independent of certificate evidence.
use crate::{Error, Hash, NETWORK_ID, Result, domain_hash};
use minicbor::{Decoder, Encoder};
pub const DOMAIN: &[u8] = b"MUTINY-BUILD8-FINALIZED-ANCHOR-V1";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedAnchor {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub height: u64,
    pub block: Hash,
}
impl FinalizedAnchor {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .bytes(&self.block)
            .unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 128)?;
        let mut d = Decoder::new(raw);
        let a = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            fn h(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
                d.bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("hash length"))
            }
            if d.array()? != Some(6) || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("anchor"));
            }
            Ok(Self {
                network: d.u32()?,
                genesis: h(&mut d)?,
                fingerprint: h(&mut d)?,
                height: d.u64()?,
                block: h(&mut d)?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if a.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(a)
    }
    pub fn id(&self) -> Hash {
        domain_hash(DOMAIN, &self.encode())
    }
    pub fn validate_context(&self, genesis: Hash, fingerprint: Hash) -> Result<()> {
        if self.network != NETWORK_ID {
            return Err(Error::WrongNetwork);
        }
        if self.genesis != genesis {
            return Err(Error::WrongGenesis);
        }
        if self.fingerprint != fingerprint {
            return Err(Error::WrongFingerprint);
        }
        Ok(())
    }
}
