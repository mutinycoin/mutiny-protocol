//! Parent-authorized same-hardware software-key rotation. Installation occurs
//! through the ordinary certified lifecycle transition.
use crate::{
    Error, Hash, NETWORK_ID, Result,
    admission_v2::Expected,
    anchors::FinalizedAnchor,
    domain_hash,
    execution::State,
    node_admission_v2::{Binding, VerifiedBinding},
};
use minicbor::{Decoder, Encoder};

pub const MAX_ROTATION_BYTES: usize = 16 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRotate {
    pub parent: FinalizedAnchor,
    pub nonce: Hash,
    pub sequence: u64,
    pub old_key_generation: u64,
    pub binding: Binding,
}
impl KeyRotate {
    pub fn admission_nonce(&self) -> Result<Hash> {
        self.parent.validate_context(
            self.binding.admission.genesis,
            self.binding.admission.fingerprint,
        )?;
        if self.nonce == [0; 32] || self.sequence == 0 || self.old_key_generation == 0 {
            return Err(Error::InvalidCounter);
        }
        self.parent.height.checked_add(1).ok_or(Error::Overflow)?;
        let generation = self
            .old_key_generation
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        if self.binding.admission.key_generation != generation {
            return Err(Error::WrongGeneration);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(21)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.parent.encode())
            .unwrap()
            .bytes(&self.nonce)
            .unwrap()
            .bytes(&self.binding.admission.node)
            .unwrap()
            .u64(self.binding.admission.hardware_generation)
            .unwrap()
            .u64(self.old_key_generation)
            .unwrap()
            .u64(self.sequence)
            .unwrap();
        Ok(domain_hash(
            b"MUTINY-BUILD8-CONTINUITY-KEY-ROTATE-CONTEXT-V2",
            &e.into_writer(),
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.admission_nonce()?;
        let mut e = Encoder::new(Vec::new());
        e.array(7)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(21)
            .unwrap()
            .bytes(&self.parent.encode())
            .unwrap()
            .bytes(&self.nonce)
            .unwrap()
            .u64(self.sequence)
            .unwrap()
            .u64(self.old_key_generation)
            .unwrap()
            .bytes(&self.binding.encode()?)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_ROTATION_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_ROTATION_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(7)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u8().map_err(|_| Error::Codec)? != 21
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
            old_key_generation: d.u64().map_err(|_| Error::Codec)?,
            binding: Binding::decode(d.bytes().map_err(|_| Error::Codec)?)?,
        };
        if d.position() != raw.len() || value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    /// Parent and root must come from authenticated canonical history. This
    /// cannot authorize hardware replacement, Node-key replacement or recovery.
    fn validated_context(
        &self,
        state: &State,
        parent: &FinalizedAnchor,
        root: Hash,
    ) -> Result<(crate::admission_v2::Policy, Expected)> {
        self.context_from_parent(crate::parent_context_v2::ParentContext::canonical(
            state, parent, root,
        )?)
    }
    fn context_from_parent(
        &self,
        context: crate::parent_context_v2::ParentContext<'_>,
    ) -> Result<(crate::admission_v2::Policy, Expected)> {
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
        if self.old_key_generation != old.admission.key_generation
            || a.hardware_generation != old.admission.hardware_generation
            || a.profile != old.admission.profile
            || self.binding.node_descriptor != old.node_descriptor
            || self.binding.signer_descriptor() != control.current_node_descriptor()
        {
            return Err(Error::WrongGeneration);
        }
        let (previous, _) =
            mutiny_crypto_v2::PublicKey::decode_descriptor(&old.admission.continuity_descriptor)
                .map_err(|_| Error::Codec)?;
        let (replacement, _) =
            mutiny_crypto_v2::PublicKey::decode_descriptor(&a.continuity_descriptor)
                .map_err(|_| Error::Codec)?;
        if previous.ed448 == replacement.ed448 || previous.fndsa == replacement.fndsa {
            return Err(Error::Duplicate);
        }
        state.retired_continuity_v2.reject_reused(&replacement)?;
        let policy = state.current_admission_policy_v2(parent.genesis, parent.fingerprint)?;
        // A legitimate wallet rotation changes its descriptor-derived address.
        // Resolve the old admission's address through the committed WalletBook;
        // comparing the two address bytes would incorrectly freeze owner keys.
        state
            .wallets
            .authorize(old.admission.owner, &policy.owner_descriptor)?;
        Ok((
            policy,
            Expected {
                node: a.node,
                hardware_generation: a.hardware_generation,
                key_generation: self
                    .old_key_generation
                    .checked_add(1)
                    .ok_or(Error::Overflow)?,
                supervised_nonce: self.admission_nonce()?,
            },
        ))
    }
    /// Preflight for a local Node signer. This cannot mint a VerifiedBinding or
    /// authorize state installation: Node possession is still absent.
    pub(crate) fn verify_for_node_possession(
        &self,
        state: &State,
        parent: &FinalizedAnchor,
        root: Hash,
    ) -> Result<()> {
        let (policy, expected) = self.validated_context(state, parent, root)?;
        self.binding.verify_admission_material(
            &policy,
            &expected,
            &state.wallets,
            state.admission_class()?,
        )?;
        Ok(())
    }
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
        self.binding
            .verify(&policy, &expected, &state.wallets, state.admission_class()?)
    }
}
