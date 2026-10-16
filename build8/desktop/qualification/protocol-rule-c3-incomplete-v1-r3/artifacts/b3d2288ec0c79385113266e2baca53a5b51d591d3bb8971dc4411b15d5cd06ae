//! Hybrid owner + Ed448 Worker assignment, with a separately bound hybrid node
//! coordinator. Parent-state ownership and sequence remain mandatory. No runtime
//! dispatch or implicit V1 compatibility is installed by this module.
use crate::{
    Error, Hash, Result, licenses::LicenseRecord, wallet_authority_v1::WalletBook,
    work_authority_v2::node_identity,
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{
    PublicKey, Role,
    enrollment::{Binding, Enrollment, owner_descriptor_id},
};
pub const MAX_ASSIGNMENT_BYTES: usize = 8192;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub enrollment: Enrollment,
    pub owner_descriptor: Vec<u8>,
    pub node_descriptor: Vec<u8>,
}
pub struct ParentContext<'a> {
    pub genesis: Hash,
    pub fingerprint: Hash,
    /// Inclusion height H; license and wallet authority come from state H-1.
    pub height: u64,
    /// Validated candidate mining epoch, used to schedule activation at epoch+1.
    pub epoch: u64,
    pub license: &'a LicenseRecord,
    pub wallets: &'a WalletBook,
}
pub struct VerifiedAssignment {
    value: Assignment,
}
impl VerifiedAssignment {
    pub fn assignment(&self) -> &Assignment {
        &self.value
    }
    pub fn binding(&self) -> &Binding {
        &self.value.enrollment.binding
    }
}
impl Assignment {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let (owner, generation) =
            PublicKey::decode_descriptor(&self.owner_descriptor).map_err(|_| Error::Codec)?;
        let b = &self.enrollment.binding;
        if owner.role != Role::WalletOwner
            || b.owner_generation != generation
            || b.owner_descriptor
                != owner_descriptor_id(&owner, generation).map_err(|_| Error::Codec)?
            || b.coordinator != node_identity(&self.node_descriptor)?
        {
            return Err(Error::WrongAnchor);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(10)
            .unwrap()
            .bytes(&self.enrollment.bytes().map_err(|_| Error::Codec)?)
            .unwrap()
            .bytes(&self.owner_descriptor)
            .unwrap()
            .bytes(&self.node_descriptor)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_ASSIGNMENT_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_ASSIGNMENT_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(5)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u8().map_err(|_| Error::Codec)? != 10
        {
            return Err(Error::Codec);
        }
        let enrollment =
            Enrollment::decode(d.bytes().map_err(|_| Error::Codec)?).map_err(|_| Error::Codec)?;
        fn descriptor(d: &mut Decoder<'_>) -> Result<Vec<u8>> {
            let raw = d.bytes().map_err(|_| Error::Codec)?;
            if raw.len() > 2048 {
                return Err(Error::Oversize);
            }
            Ok(raw.to_vec())
        }
        let value = Self {
            enrollment,
            owner_descriptor: descriptor(&mut d)?,
            node_descriptor: descriptor(&mut d)?,
        };
        if d.position() != raw.len() || value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    fn verify_common(&self, context: &ParentContext<'_>) -> Result<()> {
        self.verify_common_state(context)?;
        self.verify_signatures()
    }
    /// Stateless signature half; does not authorize the owner against a chain.
    pub fn verify_signatures(&self) -> Result<()> {
        self.encode()?;
        let (owner, _) =
            PublicKey::decode_descriptor(&self.owner_descriptor).map_err(|_| Error::Codec)?;
        self.enrollment.verify(&self.enrollment.binding, &owner).map_err(|_| Error::BadSignature)
    }
    fn verify_common_state(&self, context: &ParentContext<'_>) -> Result<()> {
        self.encode()?;
        let b = &self.enrollment.binding;
        let l = context.license;
        if context.genesis == [0; 32]
            || context.fingerprint == [0; 32]
            || b.genesis != context.genesis
            || b.fingerprint != context.fingerprint
            || l.genesis != context.genesis
            || b.license != l.id
            || b.assignment_generation
                != l.assignment_sequence
                    .checked_add(1)
                    .ok_or(Error::Overflow)?
        {
            return Err(Error::WrongAnchor);
        }
        context.wallets.authorize(l.owner, &self.owner_descriptor)?;
        // All untrusted Binding fields have either parent-state constraints or
        // explicit owner authorization. Physical Genesis inventory is additionally
        // compared against the independent supervised expected binding below.
        Ok(())
    }
    /// State/window half for the pool's exact signature-verified bytes.
    pub fn verify_next_epoch_state(&self, context: &ParentContext<'_>) -> Result<()> {
        self.verify_common_state(context)?;
        let b = &self.enrollment.binding;
        if context.height == 0 || b.valid_until_height < context.height
            || b.effective_epoch != context.epoch.checked_add(1).ok_or(Error::Overflow)? {
            return Err(Error::StaleSequence);
        }
        Ok(())
    }
    pub fn verify_next_epoch(&self, context: &ParentContext<'_>) -> Result<VerifiedAssignment> {
        self.verify_common(context)?;
        let b = &self.enrollment.binding;
        if context.height == 0
            || b.valid_until_height < context.height
            || b.effective_epoch != context.epoch.checked_add(1).ok_or(Error::Overflow)?
        {
            return Err(Error::StaleSequence);
        }
        Ok(VerifiedAssignment {
            value: self.clone(),
        })
    }
    pub fn verify_genesis(
        &self,
        context: &ParentContext<'_>,
        supervised: &Binding,
    ) -> Result<VerifiedAssignment> {
        self.verify_common(context)?;
        if context.height != 0
            || context.epoch != 0
            || context.license.issue_height != 0
            || context.license.active_worker.is_some()
            || context.license.assignment_sequence != 0
            || context.license.index >= 12
            || crate::blocks::genesis_license(context.genesis, context.license.index)?
                != context.license.id
        {
            return Err(Error::WrongAnchor);
        }
        let (owner, _) =
            PublicKey::decode_descriptor(&self.owner_descriptor).map_err(|_| Error::Codec)?;
        self.enrollment
            .verify_genesis(supervised, &owner)
            .map_err(|_| Error::BadSignature)?;
        Ok(VerifiedAssignment {
            value: self.clone(),
        })
    }
}
/// Delivery facts of the LOCKED V2 rule (P-LANE-DESIGN-AMENDMENTS-V1 AM-10) for a fresh Worker
/// assignment of `license` included at height `height` (parent state H-1) in mining epoch
/// `epoch`. `Assignment::verify_next_epoch` enforces exactly these, besides owner authority and
/// the enrollment signatures. The delivery window is ONE MiningEpoch: an assignment can be
/// included only in blocks of epoch `effective_epoch - 1`, at heights up to its
/// `valid_until_height`; once that epoch has passed it never becomes valid again, and the wallet
/// re-signs with the terms of the epoch it now targets. A pool tells a missed window
/// (`effective_epoch` differs) from a stale sequence (`assignment_generation` differs) before any
/// signature check. This one-epoch window is a known limitation of the Worker-assignment product
/// path; a longer window needs a maximum lead of `effective_epoch` over the inclusion epoch (in
/// MiningEpochs), an Architect decision (AM-10, question C.4) that is not invented here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryTerms {
    /// The parent License assignment sequence plus one.
    pub assignment_generation: u64,
    /// Exactly the inclusion epoch plus one.
    pub effective_epoch: u64,
    /// The signed `valid_until_height` must be at least the inclusion height.
    pub min_valid_until_height: u64,
}
impl DeliveryTerms {
    pub fn at(license: &LicenseRecord, height: u64, epoch: u64) -> Result<Self> {
        if height == 0 {
            return Err(Error::StaleSequence);
        }
        Ok(Self {
            assignment_generation: license
                .assignment_sequence
                .checked_add(1)
                .ok_or(Error::Overflow)?,
            effective_epoch: epoch.checked_add(1).ok_or(Error::Overflow)?,
            min_valid_until_height: height,
        })
    }
    /// The binding carries these terms. Owner authority and signatures are NOT checked here.
    pub fn admits(&self, binding: &Binding) -> bool {
        binding.assignment_generation == self.assignment_generation
            && binding.effective_epoch == self.effective_epoch
            && binding.valid_until_height >= self.min_valid_until_height
    }
}
/// Pure two-phase-Genesis validation: exactly the twelve independently supervised
/// physical units; no omitted/substituted/duplicate Worker key or hardware MAC.
pub fn verify_genesis_set(
    assignments: &[Assignment],
    supervised: &[Binding],
    licenses: &[LicenseRecord],
    wallets: &WalletBook,
    genesis: Hash,
    fingerprint: Hash,
) -> Result<Vec<VerifiedAssignment>> {
    use std::collections::BTreeSet;
    if assignments.len() != 12 || supervised.len() != 12 || licenses.len() != 12 {
        return Err(Error::Capacity);
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut devices = BTreeSet::new();
    let mut out = Vec::new();
    for (i, ((assignment, expected), license)) in
        assignments.iter().zip(supervised).zip(licenses).enumerate()
    {
        if license.index != i as u64
            || license.owner != licenses[0].owner
            || license.issuance != licenses[0].issuance
        {
            return Err(Error::NonCanonical);
        }
        let verified = assignment.verify_genesis(
            &ParentContext {
                genesis,
                fingerprint,
                height: 0,
                epoch: 0,
                license,
                wallets,
            },
            expected,
        )?;
        let b = verified.binding();
        if !ids.insert(b.worker_id)
            || !keys.insert(b.worker_public)
            || !devices.insert(b.device_mac)
        {
            return Err(Error::Duplicate);
        }
        out.push(verified);
    }
    Ok(out)
}
