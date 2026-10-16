//! Candidate dual-owner physical admission binding. Native TPM verification is
//! mandatory. Supervised EK/host trust remains an explicit owner-policy boundary.
use crate::{Error, Hash, NETWORK_ID, Result, domain_hash, tpm::TpmProfile};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
use std::collections::BTreeSet;
pub const MAX_ADMISSION: usize = 16 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub owner_descriptor: Vec<u8>,
    pub endorsement_roots: BTreeSet<Hash>,
}
impl Policy {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let (owner, _) =
            PublicKey::decode_descriptor(&self.owner_descriptor).map_err(|_| Error::Codec)?;
        if owner.role != Role::WalletOwner
            || self.genesis == [0; 32]
            || self.fingerprint == [0; 32]
            || self.endorsement_roots.is_empty()
            || self.endorsement_roots.len() > 1024
            || self.endorsement_roots.contains(&[0; 32])
        {
            return Err(Error::UnqualifiedPhysical);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(2)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.owner_descriptor)
            .unwrap()
            .array(self.endorsement_roots.len() as u64)
            .unwrap();
        for r in &self.endorsement_roots {
            e.bytes(r).unwrap();
        }
        Ok(e.into_writer())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 65536)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 6)?;
        if d.u8().map_err(|_| Error::Codec)? != 2
            || d.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let genesis = fixed(&mut d)?;
        let fingerprint = fixed(&mut d)?;
        let owner_descriptor = d.bytes().map_err(|_| Error::Codec)?.to_vec();
        let n = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
        if n == 0 || n > 1024 {
            return Err(Error::Capacity);
        }
        let mut endorsement_roots = BTreeSet::new();
        for _ in 0..n {
            if !endorsement_roots.insert(fixed(&mut d)?) {
                return Err(Error::Duplicate);
            }
        }
        let p = Self {
            genesis,
            fingerprint,
            owner_descriptor,
            endorsement_roots,
        };
        if d.position() != raw.len() || p.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(p)
    }
    fn owner(&self) -> Result<(PublicKey, u64, Hash)> {
        self.encode()?;
        let (k, g) =
            PublicKey::decode_descriptor(&self.owner_descriptor).map_err(|_| Error::Codec)?;
        let id = k.address_id(g).map_err(|_| Error::Codec)?;
        Ok((k, g, id))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub node: Hash,
    pub hardware_generation: u64,
    pub key_generation: u64,
    pub continuity_descriptor: Vec<u8>,
    pub profile: Vec<u8>,
    pub endorsement_root: Hash,
    pub owner: Hash,
    pub supervised_nonce: Hash,
    pub quote: Vec<u8>,
    pub possession: HybridSignature,
    pub authorization: HybridSignature,
}
/// Locally fixed ceremony inputs, not constraints supplied by the admission sender.
pub struct Expected {
    pub node: Hash,
    pub hardware_generation: u64,
    pub key_generation: u64,
    pub supervised_nonce: Hash,
}
pub struct VerifiedAdmission {
    genesis: Hash,
    fingerprint: Hash,
    admission: Admission,
    owner_descriptor: Vec<u8>,
    node: Hash,
    hardware_generation: u64,
    key_generation: u64,
    profile: TpmProfile,
    continuity: PublicKey,
}
impl VerifiedAdmission {
    pub fn genesis(&self) -> Hash {
        self.genesis
    }
    pub fn fingerprint(&self) -> Hash {
        self.fingerprint
    }
    pub(crate) fn admission(&self) -> &Admission {
        &self.admission
    }
    pub(crate) fn owner_descriptor(&self) -> &[u8] {
        &self.owner_descriptor
    }
    pub fn node(&self) -> Hash {
        self.node
    }
    pub fn hardware_generation(&self) -> u64 {
        self.hardware_generation
    }
    pub fn key_generation(&self) -> u64 {
        self.key_generation
    }
    pub fn profile(&self) -> &TpmProfile {
        &self.profile
    }
    pub fn continuity(&self) -> &PublicKey {
        &self.continuity
    }
}
impl Admission {
    pub fn body(&self) -> Result<Vec<u8>> {
        if self.genesis == [0; 32]
            || self.fingerprint == [0; 32]
            || self.node == [0; 32]
            || self.owner == [0; 32]
            || self.supervised_nonce == [0; 32]
            || self.hardware_generation == 0
            || self.key_generation == 0
            || self.endorsement_root == [0; 32]
        {
            return Err(Error::UnqualifiedPhysical);
        }
        if self.profile.is_empty()
            || self.profile.len() > 8192
            || self.continuity_descriptor.len() > 2048
        {
            return Err(Error::Oversize);
        }
        let (k, g) =
            PublicKey::decode_descriptor(&self.continuity_descriptor).map_err(|_| Error::Codec)?;
        if k.role != Role::Continuity || g != self.key_generation {
            return Err(Error::WrongGeneration);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(13)
            .unwrap()
            .u8(2)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.hardware_generation)
            .unwrap()
            .u64(self.key_generation)
            .unwrap()
            .u16(crate::continuity_v2::SUITE_ID)
            .unwrap()
            .bytes(&self.continuity_descriptor)
            .unwrap()
            .bytes(&self.profile)
            .unwrap()
            .bytes(&self.endorsement_root)
            .unwrap()
            .bytes(&self.owner)
            .unwrap()
            .bytes(&self.supervised_nonce)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn challenge(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-PHYSICAL-ADMISSION-CHALLENGE-V2",
            &self.body()?,
        ))
    }
    pub fn prove_continuity(&mut self, key: &HybridKey) -> Result<()> {
        let (k, _) =
            PublicKey::decode_descriptor(&self.continuity_descriptor).map_err(|_| Error::Codec)?;
        if key.public() != &k {
            return Err(Error::BadSignature);
        }
        self.possession = key
            .sign(Domain::ContinuityPossession, &self.body()?)
            .map_err(|_| Error::BadSignature)?;
        Ok(())
    }
    pub fn owner_payload(&self) -> Result<Vec<u8>> {
        if self.quote.is_empty() || self.quote.len() > 2304 {
            return Err(Error::Oversize);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .bytes(&self.body()?)
            .unwrap()
            .bytes(&self.quote)
            .unwrap()
            .bytes(&self.possession.ed448)
            .unwrap()
            .bytes(&self.possession.fndsa)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn authorize(&mut self, key: &HybridKey, generation: u64) -> Result<()> {
        if key.public().role != Role::WalletOwner
            || key
                .public()
                .address_id(generation)
                .map_err(|_| Error::Codec)?
                != self.owner
        {
            return Err(Error::BadSignature);
        }
        self.authorization = key
            .sign(Domain::PhysicalAdmission, &self.owner_payload()?)
            .map_err(|_| Error::BadSignature)?;
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.owner_payload()?;
        let mut e = Encoder::new(Vec::new());
        e.array(7)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&self.body()?)
            .unwrap()
            .bytes(&self.quote)
            .unwrap()
            .bytes(&self.possession.ed448)
            .unwrap()
            .bytes(&self.possession.fndsa)
            .unwrap()
            .bytes(&self.authorization.ed448)
            .unwrap()
            .bytes(&self.authorization.fndsa)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_ADMISSION {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_ADMISSION)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 7)?;
        if d.u8().map_err(|_| Error::Codec)? != 2 {
            return Err(Error::Codec);
        }
        let body = d.bytes().map_err(|_| Error::Codec)?;
        let quote = d.bytes().map_err(|_| Error::Codec)?.to_vec();
        let possession = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        let authorization = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        let mut b = Decoder::new(body);
        array(&mut b, 13)?;
        if b.u8().map_err(|_| Error::Codec)? != 2
            || b.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let genesis = fixed(&mut b)?;
        let fingerprint = fixed(&mut b)?;
        let node = fixed(&mut b)?;
        let hardware_generation = b.u64().map_err(|_| Error::Codec)?;
        let key_generation = b.u64().map_err(|_| Error::Codec)?;
        if b.u16().map_err(|_| Error::Codec)? != crate::continuity_v2::SUITE_ID {
            return Err(Error::Codec);
        }
        let continuity_descriptor = b.bytes().map_err(|_| Error::Codec)?.to_vec();
        let profile = b.bytes().map_err(|_| Error::Codec)?.to_vec();
        let endorsement_root = fixed(&mut b)?;
        let owner = fixed(&mut b)?;
        let supervised_nonce = fixed(&mut b)?;
        let a = Self {
            genesis,
            fingerprint,
            node,
            hardware_generation,
            key_generation,
            continuity_descriptor,
            profile,
            endorsement_root,
            owner,
            supervised_nonce,
            quote,
            possession,
            authorization,
        };
        if b.position() != body.len() || d.position() != raw.len() || a.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(a)
    }
    /// Policy and WalletBook must both come from the same independently trusted
    /// parent state (or the supervised initial Genesis state). A stale policy
    /// descriptor cannot revive owner authority retired by canonical rotation.
    /// THE V2 admission choke point (Genesis book, JOIN, key and hardware rotation, recovery
    /// replacement). `class` must come from the same parent state as `policy` and `wallets`
    /// (`State::admission_class`); in the Production class the typed provenance rule applies.
    pub fn verify(
        &self,
        policy: &Policy,
        expected: &Expected,
        wallets: &crate::wallet_authority_v1::WalletBook,
        class: crate::provenance::AdmissionClass,
    ) -> Result<VerifiedAdmission> {
        self.encode()?;
        let (owner, _, owner_id) = policy.owner()?;
        wallets.authorize(owner_id, &policy.owner_descriptor)?;
        if self.genesis != policy.genesis
            || self.fingerprint != policy.fingerprint
            || self.owner != owner_id
            || self.node != expected.node
            || self.hardware_generation != expected.hardware_generation
            || self.key_generation != expected.key_generation
            || self.supervised_nonce != expected.supervised_nonce
        {
            return Err(Error::WrongAnchor);
        }
        if !policy.endorsement_roots.contains(&self.endorsement_root) {
            return Err(Error::UnqualifiedPhysical);
        }
        owner
            .verify(
                Domain::PhysicalAdmission,
                &self.owner_payload()?,
                &self.authorization,
            )
            .map_err(|_| Error::BadSignature)?;
        let (continuity, _) =
            PublicKey::decode_descriptor(&self.continuity_descriptor).map_err(|_| Error::Codec)?;
        if continuity.ed448 == owner.ed448 || continuity.fndsa == owner.fndsa {
            return Err(Error::Duplicate);
        }
        continuity
            .verify(
                Domain::ContinuityPossession,
                &self.body()?,
                &self.possession,
            )
            .map_err(|_| Error::BadSignature)?;
        let profile = TpmProfile::decode(&self.profile)?;
        if profile.hardware == [0; 32] || profile.admission_trust_manifest == [0; 32] {
            return Err(Error::UnqualifiedPhysical);
        }
        crate::provenance::check_profile(
            class,
            &profile,
            self.endorsement_root,
            &policy.endorsement_roots,
        )?;
        profile.verify_quote(self.challenge()?, &self.quote)?;
        Ok(VerifiedAdmission {
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            admission: self.clone(),
            owner_descriptor: policy.owner_descriptor.clone(),
            node: self.node,
            hardware_generation: self.hardware_generation,
            key_generation: self.key_generation,
            profile,
            continuity,
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
