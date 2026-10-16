//! Authenticated hybrid Continuity admission records. Importing records is a
//! checkpoint reconstruction operation, never an admission authorization.
use crate::{
    Error, Hash, NETWORK_ID, Result,
    admission_v2::{Admission, Expected, MAX_ADMISSION, Policy, VerifiedAdmission},
    continuity_v2::MAX_VOTERS,
    domain_hash,
    tpm::{TpmProfile, public_key},
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, PublicKey, Role};
use std::collections::{BTreeMap, BTreeSet};

const KEY_DOMAIN: &[u8] = b"MUTINY-BUILD8-CONTINUITY-KEY-STATE-V2";
const MAX_RECORD: usize = MAX_ADMISSION + 2048 + 32;

/// Reserve the typed tag even if the key, arity or remaining fields are invalid.
pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) && d.u8().ok() == Some(50)
}
fn key(node: Hash) -> Hash {
    domain_hash(KEY_DOMAIN, &node)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    admission: Admission,
    owner_descriptor: Vec<u8>,
}
impl Binding {
    pub(crate) fn owner_descriptor(&self) -> &[u8] {
        &self.owner_descriptor
    }
    pub fn admission(&self) -> &Admission {
        &self.admission
    }
    pub fn public(&self) -> Result<PublicKey> {
        PublicKey::decode_descriptor(&self.admission.continuity_descriptor)
            .map(|(p, _)| p)
            .map_err(|_| Error::Codec)
    }
    fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(50)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.owner_descriptor)
            .unwrap()
            .bytes(&self.admission.encode()?)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_RECORD {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_RECORD)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(5)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u8().map_err(|_| Error::Codec)? != 50
            || d.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let b = Self {
            owner_descriptor: d.bytes().map_err(|_| Error::Codec)?.to_vec(),
            admission: Admission::decode(d.bytes().map_err(|_| Error::Codec)?)?,
        };
        if d.position() != raw.len() || b.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        b.verify_historical_evidence()?;
        Ok(b)
    }
    /// Recheck retained cryptographic evidence, not current owner eligibility.
    /// The independently authenticated checkpoint establishes that the original
    /// policy/owner authorization was accepted at the historical transition.
    pub(crate) fn verify_historical_evidence(&self) -> Result<TpmProfile> {
        let a = &self.admission;
        a.encode()?;
        let (owner, generation) =
            PublicKey::decode_descriptor(&self.owner_descriptor).map_err(|_| Error::Codec)?;
        if owner.role != Role::WalletOwner
            || owner.address_id(generation).map_err(|_| Error::Codec)? != a.owner
        {
            return Err(Error::BadSignature);
        }
        let public = self.public()?;
        if public.ed448 == owner.ed448 || public.fndsa == owner.fndsa {
            return Err(Error::Duplicate);
        }
        owner
            .verify(
                Domain::PhysicalAdmission,
                &a.owner_payload()?,
                &a.authorization,
            )
            .map_err(|_| Error::BadSignature)?;
        public
            .verify(Domain::ContinuityPossession, &a.body()?, &a.possession)
            .map_err(|_| Error::BadSignature)?;
        let profile = TpmProfile::decode(&a.profile)?;
        if profile.hardware == [0; 32] || profile.admission_trust_manifest == [0; 32] {
            return Err(Error::UnqualifiedPhysical);
        }
        profile.verify_quote(a.challenge()?, &a.quote)?;
        Ok(profile)
    }
    /// The class rule over this retained binding (`State::records` applies it to every current
    /// binding in the Production class; `roots` are the immutable V2 policy roots).
    pub(crate) fn check_class(
        &self,
        class: crate::provenance::AdmissionClass,
        roots: &BTreeSet<Hash>,
    ) -> Result<()> {
        let profile = TpmProfile::decode(&self.admission.profile)?;
        crate::provenance::check_profile(class, &profile, self.admission.endorsement_root, roots)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Book {
    current: BTreeMap<Hash, Binding>,
}
impl Book {
    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }
    pub fn get(&self, node: Hash) -> Option<&Binding> {
        self.current.get(&node)
    }
    pub(crate) fn bindings(&self) -> impl Iterator<Item = &Binding> {
        self.current.values()
    }
    /// Internal recovery staging; the caller must first authenticate the full
    /// recovery intent against its finalized parent. Ordinary admission cannot
    /// replace a NodeID through this path.
    pub(crate) fn stage_recovery(
        &self,
        material: &crate::recovery_replacement_v2::Replacement,
        policy: &Policy,
        wallets: &crate::wallet_authority_v1::WalletBook,
        class: crate::provenance::AdmissionClass,
    ) -> Result<Self> {
        let a = &material.binding.admission;
        let old = self.get(material.old_node).ok_or(Error::UnknownSigner)?;
        if self.current.contains_key(&a.node)
            || old.admission.hardware_generation != material.old_hardware_generation
            || old.admission.key_generation != material.old_key_generation
            || old.admission.hardware_generation.checked_add(1) != Some(a.hardware_generation)
            || old.admission.key_generation.checked_add(1) != Some(a.key_generation)
        {
            return Err(Error::WrongGeneration);
        }
        let expected = Expected {
            node: a.node,
            hardware_generation: a.hardware_generation,
            key_generation: a.key_generation,
            supervised_nonce: material.admission_nonce()?,
        };
        material.binding.verify(policy, &expected, wallets, class)?;
        let verified = a.verify(policy, &expected, wallets, class)?;
        let mut next = self.clone();
        next.current
            .remove(&material.old_node)
            .ok_or(Error::UnknownSigner)?;
        next.current.insert(
            a.node,
            Binding {
                admission: verified.admission().clone(),
                owner_descriptor: verified.owner_descriptor().to_vec(),
            },
        );
        next.validate()?;
        Ok(next)
    }
    /// Recheck authorization at the insertion boundary. A cached verification
    /// token cannot outlive a parent owner/policy change and authorize admission.
    pub fn admit(
        &mut self,
        admission: &Admission,
        policy: &Policy,
        expected: &Expected,
        wallets: &crate::wallet_authority_v1::WalletBook,
        class: crate::provenance::AdmissionClass,
    ) -> Result<()> {
        let verified = admission.verify(policy, expected, wallets, class)?;
        self.insert(&verified, policy.genesis, policy.fingerprint)
    }
    /// Internal replacement only after the typed parent-bound key-rotation
    /// validator. Admission cannot use this path to overwrite an identity.
    pub(crate) fn replace_software_key(
        &self,
        a: &Admission,
        policy: &Policy,
        expected: &Expected,
        wallets: &crate::wallet_authority_v1::WalletBook,
        class: crate::provenance::AdmissionClass,
    ) -> Result<Self> {
        let old = self.get(a.node).ok_or(Error::UnknownSigner)?;
        if old.admission.key_generation.checked_add(1) != Some(a.key_generation)
            || old.admission.hardware_generation != a.hardware_generation
            || old.admission.profile != a.profile
        {
            return Err(Error::WrongGeneration);
        }
        let verified = a.verify(policy, expected, wallets, class)?;
        let mut next = self.clone();
        next.current.insert(
            a.node,
            Binding {
                admission: verified.admission().clone(),
                owner_descriptor: verified.owner_descriptor().to_vec(),
            },
        );
        next.validate()?;
        Ok(next)
    }
    /// Internal hardware replacement after typed parent-bound validation. Both
    /// hardware and software generations advance; ordinary admission cannot
    /// overwrite an existing identity through this method.
    pub(crate) fn replace_hardware(
        &self,
        a: &Admission,
        policy: &Policy,
        expected: &Expected,
        wallets: &crate::wallet_authority_v1::WalletBook,
        class: crate::provenance::AdmissionClass,
    ) -> Result<Self> {
        let old = self.get(a.node).ok_or(Error::UnknownSigner)?;
        if old.admission.key_generation.checked_add(1) != Some(a.key_generation)
            || old.admission.hardware_generation.checked_add(1) != Some(a.hardware_generation)
        {
            return Err(Error::WrongGeneration);
        }
        let verified = a.verify(policy, expected, wallets, class)?;
        if public_key(&verified.profile().voting_public, false)?
            == public_key(
                &TpmProfile::decode(&old.admission.profile)?.voting_public,
                false,
            )?
        {
            return Err(Error::Duplicate);
        }
        let mut next = self.clone();
        next.current.insert(
            a.node,
            Binding {
                admission: verified.admission().clone(),
                owner_descriptor: verified.owner_descriptor().to_vec(),
            },
        );
        next.validate()?;
        Ok(next)
    }
    /// A token can only be constructed by full dual-owner, current WalletBook,
    /// policy, supervised challenge, native TPM and hybrid possession checks.
    /// Replacement is intentionally rejected; key/hardware rotation has its own
    /// authorization transition and cannot be implemented as another admission.
    fn insert(
        &mut self,
        verified: &VerifiedAdmission,
        genesis: Hash,
        fingerprint: Hash,
    ) -> Result<()> {
        if verified.genesis() != genesis || verified.fingerprint() != fingerprint {
            return Err(Error::WrongAnchor);
        }
        if self.current.contains_key(&verified.node()) {
            return Err(Error::Duplicate);
        }
        if self.current.len() >= MAX_VOTERS {
            return Err(Error::Capacity);
        }
        let binding = Binding {
            admission: verified.admission().clone(),
            owner_descriptor: verified.owner_descriptor().to_vec(),
        };
        let mut next = self.clone();
        next.current.insert(verified.node(), binding);
        next.validate()?;
        *self = next;
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        if self.current.len() > MAX_VOTERS {
            return Err(Error::Capacity);
        }
        let (mut ed, mut pq, mut tpm, mut hardware) = (
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        );
        // Order A4: every committed endorsement identity, not only the `hardware` label.
        let mut identities = BTreeSet::new();
        let mut context = None;
        for (node, binding) in &self.current {
            let a = &binding.admission;
            if *node != a.node {
                return Err(Error::WrongAnchor);
            }
            let c = (a.genesis, a.fingerprint);
            if context.is_some_and(|old| old != c) {
                return Err(Error::WrongAnchor);
            }
            context = Some(c);
            let profile = binding.verify_historical_evidence()?;
            let public = binding.public()?;
            if !ed.insert(public.ed448)
                || !pq.insert(public.fndsa)
                || !tpm.insert(public_key(&profile.voting_public, false)?)
                || !hardware.insert(profile.hardware)
            {
                return Err(Error::Duplicate);
            }
            for identity in crate::endorsement_identity::committed_identities(&profile) {
                if !identities.insert(identity) {
                    return Err(Error::Duplicate);
                }
            }
        }
        Ok(())
    }
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        self.validate()?;
        self.current
            .iter()
            .map(|(node, b)| Ok((key(*node), b.encode()?)))
            .collect()
    }
    /// Called by State::from_records after checking an independently pinned
    /// whole-state root. This routine alone cannot authorize a network join.
    pub(crate) fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        if records.len() > MAX_VOTERS {
            return Err(Error::Capacity);
        }
        let mut book = Self::default();
        for (k, raw) in records {
            let binding = Binding::decode(raw)?;
            if *k != key(binding.admission.node) {
                return Err(Error::WrongAnchor);
            }
            if book
                .current
                .insert(binding.admission.node, binding)
                .is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        book.validate()?;
        Ok(book)
    }
}
