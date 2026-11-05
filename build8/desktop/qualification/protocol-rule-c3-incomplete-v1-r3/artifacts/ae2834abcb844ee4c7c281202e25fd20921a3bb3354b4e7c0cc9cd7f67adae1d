//! Pre-Genesis V2 enrollment codec and authority checks. No device key generation,
//! persistence, activation or production authorization is provided by this module.
use crate::{Domain, Error, HybridSignature, NETWORK, PublicKey, Result, Role};
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256, Sha512};

pub const WORKER_SUITE: &str = "MUTINY-WORKER-ED448-V1";
pub const UNSIGNED_MAX: usize = 512;
pub const ENVELOPE_MAX: usize = 2048;
pub const POSSESSION_DOMAIN: &[u8] = b"MUTINY-BUILD8-WORKER-POSSESSION-V2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub genesis: [u8; 32],
    pub fingerprint: [u8; 32],
    pub license: [u8; 32],
    pub owner_descriptor: [u8; 32],
    pub owner_generation: u64,
    pub worker_public: [u8; 57],
    pub worker_id: [u8; 32],
    pub coordinator: [u8; 32],
    pub configuration_generation: u64,
    pub device_mac: [u8; 6],
    pub assignment_generation: u64,
    pub effective_epoch: u64,
    pub valid_until_height: u64,
}
fn require(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(Error::Encoding) }
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    require(d.array().map_err(|_| Error::Encoding)? == Some(n))
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()
        .map_err(|_| Error::Encoding)?
        .try_into()
        .map_err(|_| Error::Encoding)
}
fn number(d: &mut Decoder<'_>) -> Result<u64> {
    d.u64().map_err(|_| Error::Encoding)
}
pub fn owner_descriptor_id(owner: &PublicKey, generation: u64) -> Result<[u8; 32]> {
    require(owner.role == Role::WalletOwner)?;
    let mut h = Sha256::new();
    h.update(b"MUTINY-BUILD8-OWNER-AUTH-DESCRIPTOR-V2\0");
    h.update(owner.descriptor(generation)?);
    Ok(h.finalize().into())
}
impl Binding {
    pub fn derived_worker_id(&self) -> [u8; 32] {
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(2)
            .unwrap()
            .u32(NETWORK)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.license)
            .unwrap()
            .str(WORKER_SUITE)
            .unwrap()
            .bytes(&self.worker_public)
            .unwrap();
        let mut h = Sha256::new();
        h.update(b"MUTINY-BUILD8-WORKER-ID-V2\0");
        h.update(e.into_writer());
        h.finalize().into()
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        require(
            self.owner_generation > 0
                && self.configuration_generation > 0
                && self.assignment_generation > 0,
        )?;
        require(self.worker_id == self.derived_worker_id())?;
        require(
            unsafe { crate::build8_qual_ed448_public_valid(self.worker_public.as_ptr(), 57) } == 1,
        )?;
        let mut e = Encoder::new(Vec::new());
        e.array(16)
            .unwrap()
            .u8(2)
            .unwrap()
            .u32(NETWORK)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.license)
            .unwrap()
            .bytes(&self.owner_descriptor)
            .unwrap()
            .u64(self.owner_generation)
            .unwrap()
            .str(WORKER_SUITE)
            .unwrap()
            .bytes(&self.worker_public)
            .unwrap()
            .bytes(&self.worker_id)
            .unwrap()
            .bytes(&self.coordinator)
            .unwrap()
            .u64(self.configuration_generation)
            .unwrap()
            .bytes(&self.device_mac)
            .unwrap()
            .u64(self.assignment_generation)
            .unwrap()
            .u64(self.effective_epoch)
            .unwrap()
            .u64(self.valid_until_height)
            .unwrap();
        let bytes = e.into_writer();
        require(bytes.len() <= UNSIGNED_MAX)?;
        Ok(bytes)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        require(raw.len() <= UNSIGNED_MAX)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 16)?;
        require(number(&mut d)? == 2 && number(&mut d)? == u64::from(NETWORK))?;
        let genesis = fixed(&mut d)?;
        let fingerprint = fixed(&mut d)?;
        let license = fixed(&mut d)?;
        let owner_descriptor = fixed(&mut d)?;
        let owner_generation = number(&mut d)?;
        require(d.str().map_err(|_| Error::Encoding)? == WORKER_SUITE)?;
        let b = Self {
            genesis,
            fingerprint,
            license,
            owner_descriptor,
            owner_generation,
            worker_public: fixed(&mut d)?,
            worker_id: fixed(&mut d)?,
            coordinator: fixed(&mut d)?,
            configuration_generation: number(&mut d)?,
            device_mac: fixed(&mut d)?,
            assignment_generation: number(&mut d)?,
            effective_epoch: number(&mut d)?,
            valid_until_height: number(&mut d)?,
        };
        require(d.position() == raw.len() && b.bytes()? == raw)?;
        Ok(b)
    }
    pub fn possession_intent(&self) -> Result<[u8; 64]> {
        let mut h = Sha512::new();
        h.update(POSSESSION_DOMAIN);
        h.update([0]);
        h.update(self.bytes()?);
        Ok(h.finalize().into())
    }
    /// Verify imported Worker possession before requesting any owner signature.
    /// This authenticates only the exact existing binding and possession domain;
    /// parent-state policy still establishes owner, sequence, epoch and expiry.
    pub fn verify_worker_possession(&self, signature: &[u8; 114]) -> Result<()> {
        let intent = self.possession_intent()?;
        if unsafe {
            crate::build8_qual_ed448_verify(
                self.worker_public.as_ptr(), 57, signature.as_ptr(), 114,
                intent.as_ptr(), 64,
            )
        } != 1 {
            return Err(Error::Signature);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrollment {
    pub binding: Binding,
    pub owner_signature: HybridSignature,
    pub worker_signature: [u8; 114],
}
impl Enrollment {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .bytes(&self.binding.bytes()?)
            .unwrap()
            .bytes(&self.owner_signature.ed448)
            .unwrap()
            .bytes(&self.owner_signature.fndsa)
            .unwrap()
            .bytes(&self.worker_signature)
            .unwrap();
        let raw = e.into_writer();
        require(raw.len() <= ENVELOPE_MAX)?;
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        require(raw.len() <= ENVELOPE_MAX)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 4)?;
        let b = Self {
            binding: Binding::decode(d.bytes().map_err(|_| Error::Encoding)?)?,
            owner_signature: HybridSignature {
                ed448: fixed(&mut d)?,
                fndsa: fixed(&mut d)?,
            },
            worker_signature: fixed(&mut d)?,
        };
        require(d.position() == raw.len() && b.bytes()? == raw)?;
        Ok(b)
    }
    /// Expected binding is trusted supervised/parent-state context, never copied
    /// from the untrusted envelope. State-transition policy supplies its heights.
    pub fn verify(&self, expected: &Binding, owner: &PublicKey) -> Result<()> {
        require(self.binding == *expected)?;
        require(
            owner_descriptor_id(owner, expected.owner_generation)? == expected.owner_descriptor,
        )?;
        owner.verify(
            Domain::MinerEnrollment,
            &self.binding.bytes()?,
            &self.owner_signature,
        )?;
        self.binding.verify_worker_possession(&self.worker_signature)
    }
    pub fn verify_genesis(&self, expected: &Binding, owner: &PublicKey) -> Result<()> {
        require(
            expected.assignment_generation == 1
                && expected.configuration_generation == 1
                && expected.effective_epoch == 0
                && expected.valid_until_height == 0,
        )?;
        self.verify(expected, owner)
    }
}
