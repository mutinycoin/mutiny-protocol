//! Treasury proof-of-control (Architect decisions D2 / Q2). Status: NATIVE, dedicated domain.
//!
//! A proof of control shows that the holder of a hybrid (Ed448 + FN-DSA-1024) wallet-owner key
//! controls the exact public descriptor bytes that name the MUT Treasury authority. It is
//! NON-SPENDING: it is signed under its own domain [`Domain::TreasuryProofOfControl`], which no
//! transaction, rotation, bond or other authorization verifies, so a proof can never be replayed
//! as a spend and a spend can never pass as a proof.
//!
//! The challenge binds, in strict canonical CBOR: the exact descriptor bytes (SHA-256 and the
//! AddressID), the key version (generation), the cryptographic profile (suite, policy and profile
//! string), the proof phase and class, the Treasury identity (generation-one authority and the
//! SHA-256 of the Treasury record) and a public ceremony context plus a single-use nonce.
//!
//! The challenge deliberately contains NO GenesisID. The Treasury record is inside the Genesis
//! Parameters and therefore inside the GenesisID, so binding the GenesisID would be circular.
//! Instead the ceremony context is a rehearsal/ceremony identifier chosen before any Genesis
//! exists, and the GenesisID is checked after the freeze by recomputation (see consensus
//! `treasury_rehearsal_v1`).
//!
//! Both signature components are always required. Production-class proofs cannot be signed or
//! accepted while `PRODUCTION_SECURITY_QUALIFIED` is false.
use crate::{
    BOTH_REQUIRED_POLICY_ID, Domain, HybridKey, HybridSignature, NETWORK, PRODUCTION_SECURITY_QUALIFIED,
    PROFILE, PublicKey, Role, WALLET_CRYPTO_SUITE_ID,
};
use sha2::{Digest, Sha256};

pub const CHALLENGE_VERSION: u8 = 1;
pub const CLASS_PRODUCTION: u8 = 1;
pub const CLASS_TEST_VALUE: u8 = 2;
/// Exactly one Ed448 signature (114 bytes) followed by one FN-DSA-1024 signature (1280 bytes).
pub const SIGNATURE_BYTES: usize = 114 + 1280;
const FIELDS: u64 = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    Rehearsal = 1,
    Production = 2,
}
impl Phase {
    /// The class byte that this phase requires. Phase and class are redundant on purpose.
    pub fn required_class(self) -> u8 {
        match self {
            Self::Rehearsal => CLASS_TEST_VALUE,
            Self::Production => CLASS_PRODUCTION,
        }
    }
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Rehearsal),
            2 => Some(Self::Production),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    Malformed,
    NonCanonical,
    ClassPhaseMismatch,
    ZeroField,
    ProductionRefused,
    DescriptorInvalid,
    WrongRole,
    WrongKeyVersion,
    WrongProfile,
    AlteredDescriptor,
    WrongSigner,
    BadSignature,
    Crypto,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub phase: Phase,
    pub class: u8,
    /// Key version (descriptor generation) being proven.
    pub generation: u64,
    pub suite_id: u16,
    pub policy_id: u8,
    pub profile: String,
    pub descriptor_sha256: [u8; 32],
    /// AddressID of the proven descriptor at `generation`.
    pub address_id: [u8; 32],
    /// Generation-one AddressID of the Treasury this key belongs to (equals `address_id` for 1).
    pub treasury_authority: [u8; 32],
    /// SHA-256 of the Treasury record that carries the class byte.
    pub treasury_record_sha256: [u8; 32],
    /// Public rehearsal/ceremony identifier. Never a GenesisID.
    pub ceremony_context: [u8; 32],
    /// Public, single use.
    pub nonce: [u8; 32],
}

pub fn sha256(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}

impl Challenge {
    /// Build a challenge for exactly `descriptor`; class is derived from `phase`.
    pub fn new(
        descriptor: &[u8],
        phase: Phase,
        treasury_authority: [u8; 32],
        treasury_record_sha256: [u8; 32],
        ceremony_context: [u8; 32],
        nonce: [u8; 32],
    ) -> Result<Self, ProofError> {
        let (public, generation) = decode_wallet(descriptor)?;
        let address_id = public.address_id(generation).map_err(|_| ProofError::DescriptorInvalid)?;
        let challenge = Self {
            phase,
            class: phase.required_class(),
            generation,
            suite_id: WALLET_CRYPTO_SUITE_ID,
            policy_id: BOTH_REQUIRED_POLICY_ID,
            profile: PROFILE.to_string(),
            descriptor_sha256: sha256(descriptor),
            address_id,
            treasury_authority,
            treasury_record_sha256,
            ceremony_context,
            nonce,
        };
        challenge.check_shape()?;
        Ok(challenge)
    }
    fn check_shape(&self) -> Result<(), ProofError> {
        if self.class != self.phase.required_class() {
            return Err(ProofError::ClassPhaseMismatch);
        }
        if self.generation == 0
            || self.ceremony_context == [0; 32]
            || self.nonce == [0; 32]
            || self.treasury_record_sha256 == [0; 32]
            || self.treasury_authority == [0; 32]
        {
            return Err(ProofError::ZeroField);
        }
        Ok(())
    }
    /// Canonical payload bytes (the exact bytes that are signed under the dedicated domain).
    pub fn encode(&self) -> Result<Vec<u8>, ProofError> {
        self.check_shape()?;
        Ok(self.encode_unchecked())
    }
    /// Encoding without the shape checks. Only for negative controls that must be able to
    /// produce an inconsistent payload; the strict decoder still rejects such bytes.
    #[doc(hidden)]
    pub fn encode_unchecked(&self) -> Vec<u8> {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(FIELDS)
            .unwrap()
            .u8(CHALLENGE_VERSION)
            .unwrap()
            .u32(NETWORK)
            .unwrap()
            .u8(self.phase as u8)
            .unwrap()
            .u8(self.class)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .u16(self.suite_id)
            .unwrap()
            .u8(self.policy_id)
            .unwrap()
            .str(&self.profile)
            .unwrap()
            .bytes(&self.descriptor_sha256)
            .unwrap()
            .bytes(&self.address_id)
            .unwrap()
            .bytes(&self.treasury_authority)
            .unwrap()
            .bytes(&self.treasury_record_sha256)
            .unwrap()
            .bytes(&self.ceremony_context)
            .unwrap()
            .bytes(&self.nonce)
            .unwrap();
        e.into_writer()
    }
    /// Strict decode: exact field count and types, no trailing bytes, canonical re-encoding.
    pub fn decode(raw: &[u8]) -> Result<Self, ProofError> {
        if raw.is_empty() || raw.len() > 1024 {
            return Err(ProofError::Malformed);
        }
        let mut d = minicbor::Decoder::new(raw);
        let bad = |_| ProofError::Malformed;
        if d.array().map_err(bad)? != Some(FIELDS) {
            return Err(ProofError::Malformed);
        }
        if d.u8().map_err(bad)? != CHALLENGE_VERSION || d.u32().map_err(bad)? != NETWORK {
            return Err(ProofError::Malformed);
        }
        let phase = Phase::from_u8(d.u8().map_err(bad)?).ok_or(ProofError::Malformed)?;
        let class = d.u8().map_err(bad)?;
        let generation = d.u64().map_err(bad)?;
        let suite_id = d.u16().map_err(bad)?;
        let policy_id = d.u8().map_err(bad)?;
        let profile = d.str().map_err(bad)?.to_string();
        let h = |d: &mut minicbor::Decoder<'_>| -> Result<[u8; 32], ProofError> {
            d.bytes().map_err(bad)?.try_into().map_err(|_| ProofError::Malformed)
        };
        let descriptor_sha256 = h(&mut d)?;
        let address_id = h(&mut d)?;
        let treasury_authority = h(&mut d)?;
        let treasury_record_sha256 = h(&mut d)?;
        let ceremony_context = h(&mut d)?;
        let nonce = h(&mut d)?;
        if d.position() != raw.len() {
            return Err(ProofError::Malformed);
        }
        let challenge = Self {
            phase,
            class,
            generation,
            suite_id,
            policy_id,
            profile,
            descriptor_sha256,
            address_id,
            treasury_authority,
            treasury_record_sha256,
            ceremony_context,
            nonce,
        };
        challenge.check_shape()?;
        if challenge.encode_unchecked() != raw {
            return Err(ProofError::NonCanonical);
        }
        Ok(challenge)
    }
    /// Check that `descriptor` is exactly the descriptor this challenge commits to. Returns the
    /// decoded public key. Distinguishes key version, profile and altered bytes.
    pub fn check_descriptor(&self, descriptor: &[u8]) -> Result<PublicKey, ProofError> {
        let (public, generation) = decode_wallet(descriptor)?;
        if generation != self.generation {
            return Err(ProofError::WrongKeyVersion);
        }
        if self.suite_id != WALLET_CRYPTO_SUITE_ID || self.policy_id != BOTH_REQUIRED_POLICY_ID || self.profile != PROFILE {
            return Err(ProofError::WrongProfile);
        }
        let address = public.address_id(generation).map_err(|_| ProofError::DescriptorInvalid)?;
        if sha256(descriptor) != self.descriptor_sha256 || address != self.address_id {
            return Err(ProofError::AlteredDescriptor);
        }
        Ok(public)
    }
    /// Verify a proof. Requires BOTH signature components over the exact payload under the
    /// dedicated domain. Production phase is refused while production is unqualified.
    pub fn verify(&self, descriptor: &[u8], signature: &HybridSignature) -> Result<(), ProofError> {
        if self.phase == Phase::Production && !PRODUCTION_SECURITY_QUALIFIED {
            return Err(ProofError::ProductionRefused);
        }
        let public = self.check_descriptor(descriptor)?;
        let payload = self.encode()?;
        public
            .verify(Domain::TreasuryProofOfControl, &payload, signature)
            .map_err(|_| ProofError::BadSignature)
    }
}

fn decode_wallet(descriptor: &[u8]) -> Result<(PublicKey, u64), ProofError> {
    let (public, generation) = PublicKey::decode_descriptor(descriptor).map_err(|_| ProofError::DescriptorInvalid)?;
    if public.role != Role::WalletOwner {
        return Err(ProofError::WrongRole);
    }
    Ok((public, generation))
}

/// Sign a challenge with the key that holds `descriptor`. The signer refuses any production
/// phase while production is unqualified, any class/phase mismatch, and any challenge that does
/// not commit to exactly this key's descriptor.
pub fn sign_challenge(key: &HybridKey, descriptor: &[u8], challenge: &Challenge) -> Result<HybridSignature, ProofError> {
    if challenge.phase == Phase::Production && !PRODUCTION_SECURITY_QUALIFIED {
        return Err(ProofError::ProductionRefused);
    }
    let public = challenge.check_descriptor(descriptor)?;
    if &public != key.public() {
        return Err(ProofError::WrongSigner);
    }
    let payload = challenge.encode()?;
    let signature = key.sign(Domain::TreasuryProofOfControl, &payload).map_err(|_| ProofError::Crypto)?;
    challenge.verify(descriptor, &signature)?;
    Ok(signature)
}

pub fn signature_to_bytes(signature: &HybridSignature) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNATURE_BYTES);
    out.extend_from_slice(&signature.ed448);
    out.extend_from_slice(&signature.fndsa);
    out
}
/// Exactly both components; a single component or any other length is malformed.
pub fn signature_from_bytes(raw: &[u8]) -> Result<HybridSignature, ProofError> {
    if raw.len() != SIGNATURE_BYTES {
        return Err(ProofError::Malformed);
    }
    Ok(HybridSignature {
        ed448: raw[..114].try_into().unwrap(),
        fndsa: raw[114..].try_into().unwrap(),
    })
}
