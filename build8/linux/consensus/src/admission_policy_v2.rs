//! Candidate immutable Genesis admission trust policy in authenticated state.
//! Current owner authority is resolved through the canonical WalletBook; this
//! record never grants BFT weight or accepts a peer-supplied replacement policy.
use crate::{
    Error, Hash, NETWORK_ID, Result, admission_v2::Policy, domain_hash, execution::State,
    wallet_authority_v1::WalletBook,
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{PublicKey, Role};

pub fn key() -> Hash {
    domain_hash(b"MUTINY-BUILD8-ADMISSION-POLICY-KEY-V2", &[])
}
pub(crate) fn is_record(k: Hash, raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    k == key()
        || (d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) && d.u8().ok() == Some(54))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    initial: Policy,
}
impl Record {
    pub fn new(initial: Policy) -> Result<Self> {
        initial.encode()?;
        let (owner, generation) =
            PublicKey::decode_descriptor(&initial.owner_descriptor).map_err(|_| Error::Codec)?;
        if owner.role != Role::WalletOwner || generation != 1 {
            return Err(Error::WrongGeneration);
        }
        Ok(Self { initial })
    }
    pub fn initial(&self) -> &Policy {
        &self.initial
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        Self::new(self.initial.clone())?;
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(54)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.initial.encode()?)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > 65536 {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 65536)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(4)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u8().map_err(|_| Error::Codec)? != 54
            || d.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let record = Self::new(Policy::decode(d.bytes().map_err(|_| Error::Codec)?)?)?;
        if d.position() != raw.len() || record.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(record)
    }
    /// Preserve the immutable trust roots and network context while following
    /// an already-authorized wallet rotation through its stable initial ID.
    pub fn current(
        &self,
        wallets: &WalletBook,
        genesis: Hash,
        fingerprint: Hash,
    ) -> Result<Policy> {
        if (genesis, fingerprint) != (self.initial.genesis, self.initial.fingerprint) {
            return Err(Error::WrongAnchor);
        }
        let (owner, generation) = PublicKey::decode_descriptor(&self.initial.owner_descriptor)
            .map_err(|_| Error::Codec)?;
        let authority = owner.address_id(generation).map_err(|_| Error::Codec)?;
        let descriptor = wallets.current(authority).ok_or(Error::UnknownSigner)?;
        wallets.authorize(authority, descriptor)?;
        let mut policy = self.initial.clone();
        policy.owner_descriptor = descriptor.to_vec();
        policy.encode()?;
        Ok(policy)
    }
}
impl State {
    /// Caller must first authenticate this parent StateRoot. Missing policy is
    /// an error, never a request to use a local configuration or peer policy.
    pub fn current_admission_policy_v2(&self, genesis: Hash, fingerprint: Hash) -> Result<Policy> {
        self.admission_policy_v2
            .as_ref()
            .ok_or(Error::UnqualifiedPhysical)?
            .current(&self.wallets, genesis, fingerprint)
    }
}
