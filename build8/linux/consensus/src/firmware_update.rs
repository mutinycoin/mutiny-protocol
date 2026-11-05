//! Owner-authorized firmware delivery. This is a device administration signature,
//! never a consensus vote, transfer, License assignment, or automatic update.
use crate::{Error, Hash, NETWORK_ID, Result, domain_hash, licenses::BindWorker};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
pub const MANIFEST_BODY: usize = 177;
pub const MANIFEST_BYTES: usize = 241;
pub fn qualified_hardware_profile() -> Hash {
    domain_hash(
        b"MUTINY-BUILD8-FIRMWARE-HARDWARE-V1",
        b"ESP32-D0WD-V3;REV=3.1;XTAL=40MHZ;FLASH=4194304;CPU=80MHZ;APB=80MHZ;UNICORE;POW=ROM_FULL",
    )
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateManifest {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub owner: Hash,
    pub hardware: Hash,
    pub release: u64,
    pub image_size: u32,
    pub image_sha256: Hash,
    pub signature: [u8; 64],
}
impl UpdateManifest {
    pub fn body(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(MANIFEST_BODY);
        raw.push(1);
        raw.extend(NETWORK_ID.to_be_bytes());
        for field in [self.genesis, self.fingerprint, self.owner, self.hardware] {
            raw.extend(field);
        }
        raw.extend(self.release.to_be_bytes());
        raw.extend(self.image_size.to_be_bytes());
        raw.extend(self.image_sha256);
        raw
    }
    pub fn digest(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-FIRMWARE-UPDATE-V1", &self.body())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = self.body();
        raw.extend(self.signature);
        raw
    }
    pub fn sign(&mut self, owner: &SigningKey) -> Result<()> {
        if owner.verifying_key().to_bytes() != self.owner {
            return Err(Error::UnknownSigner);
        }
        self.signature = owner.sign(&self.digest()).to_bytes();
        Ok(())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != MANIFEST_BYTES || raw[0] != 1 || raw[1..5] != NETWORK_ID.to_be_bytes() {
            return Err(Error::Codec);
        }
        let hash = |offset: usize| {
            raw[offset..offset + 32]
                .try_into()
                .map_err(|_| Error::Codec)
        };
        Ok(Self {
            genesis: hash(5)?,
            fingerprint: hash(37)?,
            owner: hash(69)?,
            hardware: hash(101)?,
            release: u64::from_be_bytes(raw[133..141].try_into().map_err(|_| Error::Codec)?),
            image_size: u32::from_be_bytes(raw[141..145].try_into().map_err(|_| Error::Codec)?),
            image_sha256: hash(145)?,
            signature: raw[177..].try_into().map_err(|_| Error::Codec)?,
        })
    }
    pub fn validate(
        &self,
        binding: &BindWorker,
        hardware: Hash,
        current_release: u64,
        partition_capacity: u32,
    ) -> Result<()> {
        if binding.network != NETWORK_ID
            || self.genesis != binding.genesis
            || self.fingerprint != binding.fingerprint
            || self.owner != binding.owner_public
            || self.hardware != hardware
        {
            return Err(Error::WrongAnchor);
        }
        if self.release <= current_release
            || self.image_size == 0
            || self.image_size > partition_capacity
            || self.image_sha256 == [0; 32]
        {
            return Err(Error::InvalidCounter);
        }
        VerifyingKey::from_bytes(&binding.owner_public)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(&self.digest(), &Signature::from_bytes(&self.signature))
            .map_err(|_| Error::BadSignature)
    }
}
