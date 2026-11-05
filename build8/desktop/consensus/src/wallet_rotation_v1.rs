//! Explicit dual-current / dual-new-control rotation. The caller must supply
//! authority from authenticated canonical state; a peer descriptor is not state.
use crate::{Error, Hash, NETWORK_ID, Result, domain_hash};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
pub const MAX_ROTATION: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub authority: Hash,
    pub current: Vec<u8>,
    pub proposed: Vec<u8>,
    pub created_height: u64,
    pub expiry_height: u64,
    pub authorization: HybridSignature,
    pub possession: HybridSignature,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRotation {
    authority: Hash,
    current: Vec<u8>,
    proposed: Vec<u8>,
    identity: Hash,
}
impl VerifiedRotation {
    pub fn identity(&self) -> Hash {
        self.identity
    }
    pub fn authority(&self) -> Hash {
        self.authority
    }
    pub fn proposed_descriptor(&self) -> &[u8] {
        &self.proposed
    }
    /// Compare-and-replace in the caller's atomic state transition. A replay or
    /// two rotations competing for the same prior generation cannot both apply.
    pub fn apply(&self, authority: Hash, current: &mut Vec<u8>) -> Result<()> {
        if authority != self.authority || *current != self.current {
            return Err(Error::WrongGeneration);
        }
        *current = self.proposed.clone();
        Ok(())
    }
}
fn owner(raw: &[u8]) -> Result<(PublicKey, u64)> {
    let (key, generation) = PublicKey::decode_descriptor(raw).map_err(|_| Error::Codec)?;
    if key.role != Role::WalletOwner {
        return Err(Error::WrongOperation);
    }
    Ok((key, generation))
}
impl Rotation {
    pub fn unsigned(&self) -> Result<Vec<u8>> {
        let (old, old_generation) = owner(&self.current)?;
        let (new, new_generation) = owner(&self.proposed)?;
        if old_generation.checked_add(1) != Some(new_generation) {
            return Err(Error::WrongGeneration);
        }
        if old.ed448 == new.ed448 || old.fndsa == new.fndsa {
            return Err(Error::Duplicate);
        }
        if self.network != NETWORK_ID {
            return Err(Error::WrongNetwork);
        }
        if self.genesis == [0; 32]
            || self.fingerprint == [0; 32]
            || self.authority == [0; 32]
            || self
                .expiry_height
                .checked_sub(self.created_height)
                .is_none_or(|span| span > crate::transactions::EXPIRY_HORIZON)
        {
            return Err(Error::Codec);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.authority)
            .unwrap()
            .bytes(&self.current)
            .unwrap()
            .bytes(&self.proposed)
            .unwrap()
            .u64(self.created_height)
            .unwrap()
            .u64(self.expiry_height)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn sign(&mut self, current: &HybridKey, proposed: &HybridKey) -> Result<()> {
        let (old, _) = owner(&self.current)?;
        let (new, _) = owner(&self.proposed)?;
        if current.public() != &old || proposed.public() != &new {
            return Err(Error::UnknownSigner);
        }
        let body = self.unsigned()?;
        // Do not leave one newly changed signature if the second signer fails.
        let authorization = current
            .sign(Domain::WalletRotate, &body)
            .map_err(|_| Error::BadSignature)?;
        let possession = proposed
            .sign(Domain::WalletRotatePossession, &body)
            .map_err(|_| Error::BadSignature)?;
        self.authorization = authorization;
        self.possession = possession;
        Ok(())
    }
    pub fn identity(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-WALLET-ROTATION-ID-V1",
            &self.unsigned()?,
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.unsigned()?)
            .unwrap()
            .bytes(&self.authorization.ed448)
            .unwrap()
            .bytes(&self.authorization.fndsa)
            .unwrap()
            .bytes(&self.possession.ed448)
            .unwrap()
            .bytes(&self.possession.fndsa)
            .unwrap();
        let bytes = e.into_writer();
        if bytes.len() > MAX_ROTATION {
            return Err(Error::Oversize);
        }
        Ok(bytes)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_ROTATION)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 6)?;
        if d.u8().map_err(|_| Error::Codec)? != 1 {
            return Err(Error::Codec);
        }
        let body = d.bytes().map_err(|_| Error::Codec)?;
        crate::blocks::canonical(body, MAX_ROTATION)?;
        let authorization = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        let possession = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        let mut b = Decoder::new(body);
        array(&mut b, 9)?;
        if b.u8().map_err(|_| Error::Codec)? != 1 {
            return Err(Error::Codec);
        }
        let r = Self {
            network: b.u32().map_err(|_| Error::Codec)?,
            genesis: fixed(&mut b)?,
            fingerprint: fixed(&mut b)?,
            authority: fixed(&mut b)?,
            current: b.bytes().map_err(|_| Error::Codec)?.to_vec(),
            proposed: b.bytes().map_err(|_| Error::Codec)?.to_vec(),
            created_height: b.u64().map_err(|_| Error::Codec)?,
            expiry_height: b.u64().map_err(|_| Error::Codec)?,
            authorization,
            possession,
        };
        if d.position() != raw.len() || b.position() != body.len() || r.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(r)
    }
    pub fn verify(
        &self,
        genesis: Hash,
        fingerprint: Hash,
        height: u64,
        authority: Hash,
        committed_current: &[u8],
    ) -> Result<VerifiedRotation> {
        self.encode()?;
        if self.genesis != genesis {
            return Err(Error::WrongGenesis);
        }
        if self.fingerprint != fingerprint {
            return Err(Error::WrongFingerprint);
        }
        if self.authority != authority || self.current != committed_current {
            return Err(Error::WrongGeneration);
        }
        if height < self.created_height || height > self.expiry_height {
            return Err(Error::StaleSequence);
        }
        let body = self.unsigned()?;
        owner(&self.current)?
            .0
            .verify(Domain::WalletRotate, &body, &self.authorization)
            .map_err(|_| Error::BadSignature)?;
        owner(&self.proposed)?
            .0
            .verify(Domain::WalletRotatePossession, &body, &self.possession)
            .map_err(|_| Error::BadSignature)?;
        Ok(VerifiedRotation {
            authority,
            current: self.current.clone(),
            proposed: self.proposed.clone(),
            identity: self.identity()?,
        })
    }
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array().map_err(|_| Error::Codec)? != Some(n) {
        return Err(Error::Codec);
    }
    Ok(())
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()
        .map_err(|_| Error::Codec)?
        .try_into()
        .map_err(|_| Error::Codec)
}
