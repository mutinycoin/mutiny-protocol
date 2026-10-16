//! Parent-authorized hybrid hardware replacement candidate. Verification alone
//! never installs state, bypasses old-set finality or authorizes recovery.
use crate::{
    Error, Hash, NETWORK_ID, Result,
    admission_v2::{Expected, Policy},
    anchors::FinalizedAnchor,
    domain_hash,
    execution::State,
    node_admission_v2::{Binding, VerifiedBinding},
    tpm::TpmProfile,
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::PublicKey;
use p256::ecdsa::signature::hazmat::PrehashVerifier;

pub const MAX_ROTATION_BYTES: usize = 16 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareRotate {
    pub parent: FinalizedAnchor,
    pub nonce: Hash,
    pub sequence: u64,
    pub old_hardware_generation: u64,
    pub old_key_generation: u64,
    pub binding: Binding,
    pub native_possession: [u8; 64],
}
impl HardwareRotate {
    pub fn admission_nonce(&self) -> Result<Hash> {
        let a = &self.binding.admission;
        self.parent.validate_context(a.genesis, a.fingerprint)?;
        self.parent.height.checked_add(1).ok_or(Error::Overflow)?;
        if self.nonce == [0; 32]
            || self.sequence == 0
            || self.old_hardware_generation == 0
            || self.old_key_generation == 0
        {
            return Err(Error::InvalidCounter);
        }
        if self.old_hardware_generation.checked_add(1) != Some(a.hardware_generation)
            || self.old_key_generation.checked_add(1) != Some(a.key_generation)
        {
            return Err(Error::WrongGeneration);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(11)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(16)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.parent.encode())
            .unwrap()
            .bytes(&self.nonce)
            .unwrap()
            .bytes(&a.node)
            .unwrap()
            .u64(self.old_hardware_generation)
            .unwrap()
            .u64(a.hardware_generation)
            .unwrap()
            .u64(self.old_key_generation)
            .unwrap()
            .u64(a.key_generation)
            .unwrap()
            .u64(self.sequence)
            .unwrap();
        Ok(domain_hash(
            b"MUTINY-BUILD8-HARDWARE-ROTATE-CONTEXT-V2",
            &e.into_writer(),
        ))
    }
    fn bytes(&self, signed: bool) -> Result<Vec<u8>> {
        self.admission_nonce()?;
        let mut e = Encoder::new(Vec::new());
        e.array(if signed { 9 } else { 8 })
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(16)
            .unwrap()
            .bytes(&self.parent.encode())
            .unwrap()
            .bytes(&self.nonce)
            .unwrap()
            .u64(self.sequence)
            .unwrap()
            .u64(self.old_hardware_generation)
            .unwrap()
            .u64(self.old_key_generation)
            .unwrap()
            .bytes(&self.binding.encode()?)
            .unwrap();
        if signed {
            e.bytes(&self.native_possession).unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_ROTATION_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn native_digest(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-HARDWARE-ROTATE-NATIVE-POSSESSION-V2",
            &self.bytes(false)?,
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.bytes(true)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_ROTATION_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(9)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u8().map_err(|_| Error::Codec)? != 16
        {
            return Err(Error::Codec);
        }
        let value = Self {
            parent: FinalizedAnchor::decode(d.bytes().map_err(|_| Error::Codec)?)?,
            nonce: d
                .bytes()
                .map_err(|_| Error::Codec)?
                .try_into()
                .map_err(|_| Error::Codec)?,
            sequence: d.u64().map_err(|_| Error::Codec)?,
            old_hardware_generation: d.u64().map_err(|_| Error::Codec)?,
            old_key_generation: d.u64().map_err(|_| Error::Codec)?,
            binding: Binding::decode(d.bytes().map_err(|_| Error::Codec)?)?,
            native_possession: d
                .bytes()
                .map_err(|_| Error::Codec)?
                .try_into()
                .map_err(|_| Error::Codec)?,
        };
        if d.position() != raw.len() || value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    fn context(
        &self,
        state: &State,
        parent: &FinalizedAnchor,
        root: Hash,
    ) -> Result<(Policy, Expected)> {
        self.context_from_parent(crate::parent_context_v2::ParentContext::canonical(
            state, parent, root,
        )?)
    }
    fn context_from_parent(
        &self,
        context: crate::parent_context_v2::ParentContext<'_>,
    ) -> Result<(Policy, Expected)> {
        let state = context.state();
        let parent = context.parent();
        self.encode()?;
        if &self.parent != parent {
            return Err(Error::WrongAnchor);
        }
        let a = &self.binding.admission;
        let registry = state.continuity.as_ref().ok_or(Error::UnknownSigner)?;
        parent.validate_context(registry.genesis, registry.fingerprint)?;
        state.membership_v2.validate_at_height(
            registry,
            &state.continuity_keys_v2,
            parent.height,
        )?;
        let control = state
            .membership_v2
            .get(a.node)
            .ok_or(Error::UnknownSigner)?;
        let member = registry
            .members
            .iter()
            .find(|m| m.node == a.node)
            .ok_or(Error::UnknownSigner)?;
        if !member.physical
            || !member.eligible
            || state.penalties_v2.revoked(member.lineage)
            || control.exit_boundary().is_some()
        {
            return Err(Error::UnqualifiedPhysical);
        }
        if control.sequence().checked_add(1) != Some(self.sequence) {
            return Err(Error::StaleSequence);
        }
        let old = control.binding();
        if self.old_hardware_generation != old.admission.hardware_generation
            || self.old_key_generation != old.admission.key_generation
            || self.binding.node_descriptor != old.node_descriptor
            || self.binding.signer_descriptor() != control.current_node_descriptor()
        {
            return Err(Error::WrongGeneration);
        }
        let (replacement, _) =
            PublicKey::decode_descriptor(&a.continuity_descriptor).map_err(|_| Error::Codec)?;
        // Reject either constituent alias across all retained role authorities.
        for descriptor in
            state
                .wallets
                .public_descriptors()
                .chain(state.membership_v2.controls().flat_map(|c| {
                    [
                        c.binding().node_descriptor.as_slice(),
                        c.current_node_descriptor(),
                        c.binding().admission.continuity_descriptor.as_slice(),
                    ]
                }))
        {
            let (key, _) = PublicKey::decode_descriptor(descriptor).map_err(|_| Error::Codec)?;
            if replacement.ed448 == key.ed448 || replacement.fndsa == key.fndsa {
                return Err(Error::Duplicate);
            }
        }
        state.retired_continuity_v2.reject_reused(&replacement)?;
        state.node_key_history_v2.reject_reused(&replacement)?;
        let profile = TpmProfile::decode(&a.profile)?;
        let voting_key = crate::tpm::public_key(&profile.voting_public, false)?;
        if registry.members.iter().any(|m| {
            m.voting_key == voting_key || (m.node != a.node && m.hardware == profile.hardware)
        }) {
            return Err(Error::Duplicate);
        }
        for retired in state.retired_continuity_v2.entries() {
            let previous = TpmProfile::decode(&retired.binding.admission.profile)?;
            if crate::tpm::public_key(&previous.voting_public, false)? == voting_key
                || (retired.binding.admission.node != a.node
                    && previous.hardware == profile.hardware)
            {
                return Err(Error::Duplicate);
            }
        }
        // Order A4: every committed endorsement identity, against the current and retired bindings of
        // every OTHER node (the rotating lineage may keep its own identity).
        let others = state
            .continuity_keys_v2
            .bindings()
            .map(|b| b.admission())
            .chain(state.retired_continuity_v2.entries().map(|r| &r.binding.admission))
            .filter(|other| other.node != a.node)
            .map(|other| TpmProfile::decode(&other.profile))
            .collect::<Result<Vec<_>>>()?;
        crate::endorsement_identity::reject_shared_identity(&profile, &others)?;
        let policy = state.current_admission_policy_v2(parent.genesis, parent.fingerprint)?;
        state
            .wallets
            .authorize(old.admission.owner, &policy.owner_descriptor)?;
        Ok((
            policy,
            Expected {
                node: a.node,
                hardware_generation: a.hardware_generation,
                key_generation: a.key_generation,
                supervised_nonce: self.admission_nonce()?,
            },
        ))
    }
    /// Preflight excludes Node possession and the final native signature over
    /// that possession. It cannot produce an installable VerifiedBinding.
    pub(crate) fn verify_for_node_possession(
        &self,
        state: &State,
        parent: &FinalizedAnchor,
        root: Hash,
    ) -> Result<()> {
        let (policy, expected) = self.context(state, parent, root)?;
        let class = state.admission_class()?;
        self.binding
            .verify_admission_material(&policy, &expected, &state.wallets, class)?;
        // Order A8: after sealing the ceremony-scoped authority admits no hardware (Production class).
        crate::admission_scope::require_post_sealing_admission(class)
    }
    /// No old TPM private key is needed. Current owner/Node authority, new hybrid
    /// possession, native profile/quote and new native identity possession are.
    /// Old-set certification is an additional mandatory installation boundary.
    pub fn verify(
        &self,
        state: &State,
        parent: &FinalizedAnchor,
        root: Hash,
    ) -> Result<VerifiedBinding> {
        self.verify_in_parent(crate::parent_context_v2::ParentContext::canonical(
            state, parent, root,
        )?)
    }
    pub(crate) fn verify_in_parent(
        &self,
        context: crate::parent_context_v2::ParentContext<'_>,
    ) -> Result<VerifiedBinding> {
        let state = context.state();
        let (policy, expected) = self.context_from_parent(context)?;
        let verified =
            self.binding
                .verify(&policy, &expected, &state.wallets, state.admission_class()?)?;
        let profile = TpmProfile::decode(&self.binding.admission.profile)?;
        let signature = p256::ecdsa::Signature::from_slice(&self.native_possession)
            .map_err(|_| Error::BadSignature)?;
        if signature.normalize_s().is_some() {
            return Err(Error::NonCanonical);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&crate::tpm::public_key(
            &profile.voting_public,
            false,
        )?)
        .map_err(|_| Error::BadSignature)?
        .verify_prehash(&self.native_digest()?, &signature)
        .map_err(|_| Error::BadSignature)?;
        // Order A8: checked after the complete verification, so malformed material fails first.
        crate::admission_scope::require_post_sealing_admission(state.admission_class()?)?;
        Ok(verified)
    }
}
