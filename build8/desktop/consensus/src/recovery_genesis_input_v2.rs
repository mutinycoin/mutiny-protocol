//! Synthetic component: pre-Genesis descriptor commitment, never a seal API.
use minicbor::{Decoder, Encoder};
use crate::{
    Error, Hash, NETWORK_ID, Result, blocks, domain_hash, genesis::GenesisIdentity,
    recovery_authority_v2::Authority,
};
use mutiny_crypto_v2::{PublicKey, Role};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryInput {
    descriptor: Vec<u8>,
}
impl RecoveryInput {
    pub fn new(descriptor: Vec<u8>) -> Result<Self> {
        if descriptor.len() > 2048 {
            return Err(Error::Oversize);
        }
        let (key, generation) =
            PublicKey::decode_descriptor(&descriptor).map_err(|_| Error::Codec)?;
        if key.role != Role::WalletRecovery || generation != 1 {
            return Err(Error::WrongGeneration);
        }
        Ok(Self { descriptor })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u8(2)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.descriptor)
            .unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        blocks::canonical(raw, 4096)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(3)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let result = Self::new(d.bytes().map_err(|_| Error::Codec)?.to_vec())?;
        if d.position() != raw.len() || result.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(result)
    }
    /// No GenesisID, StateRoot, BlockHash, Worker assignment or signature input.
    pub fn commitment(&self) -> Hash {
        domain_hash(
            b"MUTINY-BUILD8-GENESIS-RECOVERY-DESCRIPTOR-V2",
            &self.encode(),
        )
    }
    /// Caller must already have frozen the descriptor through GenesisIdentity.
    /// This only produces public state metadata, not authorized initial state.
    pub fn bind(&self, frozen: &GenesisIdentity) -> Result<Authority> {
        if frozen.descriptor().recovery != self.commitment() {
            return Err(Error::WrongGenesis);
        }
        let authority = Authority {
            genesis: frozen.id(),
            fingerprint: frozen.descriptor().fingerprint,
            descriptor: self.descriptor.clone(),
        };
        authority.encode()?;
        Ok(authority)
    }
}
