//! Current physical-node control authority, resolved only by CanonicalStore.
//! This grants no wallet, transport-session or Continuity signing authority.
use crate::{Error, Hash, Result, anchors::FinalizedAnchor, execution::State};
use mutiny_crypto_v2::{PublicKey, Role};

pub struct Authority {
    parent: FinalizedAnchor,
    node: Hash,
    hardware_generation: u64,
    sequence: u64,
    owner: Hash,
    descriptor: Vec<u8>,
    context: Hash,
}
impl Authority {
    pub(crate) fn from_state(state: &State, parent: FinalizedAnchor, node: Hash) -> Result<Self> {
        let registry = state.continuity.as_ref().ok_or(Error::UnknownSigner)?;
        parent.validate_context(registry.genesis, registry.fingerprint)?;
        if state.accounting.slots.last_height != parent.height {
            return Err(Error::WrongAnchor);
        }
        state.membership_v2.validate_at_height(
            registry,
            &state.continuity_keys_v2,
            parent.height,
        )?;
        let control = state.membership_v2.get(node).ok_or(Error::UnknownSigner)?;
        let member = registry
            .members
            .iter()
            .find(|m| m.node == node)
            .ok_or(Error::UnknownSigner)?;
        if !member.physical
            || !member.eligible
            || state.penalties_v2.revoked(member.lineage)
            || control.exit_boundary().is_some()
        {
            return Err(Error::UnqualifiedPhysical);
        }
        let descriptor = control.current_node_descriptor().to_vec();
        let context = custody_context(
            parent.genesis,
            parent.fingerprint,
            node,
            control.generation(),
            &descriptor,
        )?;
        Ok(Self {
            parent,
            node,
            hardware_generation: control.generation(),
            sequence: control.sequence(),
            owner: control.binding().admission.owner,
            descriptor,
            context,
        })
    }
    pub fn parent(&self) -> &FinalizedAnchor {
        &self.parent
    }
    pub fn node(&self) -> Hash {
        self.node
    }
    pub fn descriptor(&self) -> &[u8] {
        &self.descriptor
    }
    pub fn context(&self) -> Hash {
        self.context
    }
    pub fn control(&self) -> crate::continuity_exit_v2::ParentControl<'_> {
        crate::continuity_exit_v2::ParentControl {
            node: self.node,
            hardware_generation: self.hardware_generation,
            sequence: self.sequence,
            owner_address: self.owner,
            node_descriptor: &self.descriptor,
            exit_pending: false,
        }
    }
}
/// Public encryption AAD for a proposed generation. Computing it confers no
/// authority; only an authenticated installed generation may unlock a signer.
pub fn custody_context(
    genesis: Hash,
    fingerprint: Hash,
    node: Hash,
    hardware: u64,
    descriptor: &[u8],
) -> Result<Hash> {
    let (key, _) = PublicKey::decode_descriptor(descriptor).map_err(|_| Error::Codec)?;
    if genesis == [0; 32]
        || fingerprint == [0; 32]
        || node == [0; 32]
        || hardware == 0
        || key.role != Role::Node
    {
        return Err(Error::WrongAnchor);
    }
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(7)
        .unwrap()
        .u8(2)
        .unwrap()
        .u32(crate::NETWORK_ID)
        .unwrap()
        .bytes(&genesis)
        .unwrap()
        .bytes(&fingerprint)
        .unwrap()
        .bytes(&node)
        .unwrap()
        .u64(hardware)
        .unwrap()
        .bytes(descriptor)
        .unwrap();
    Ok(crate::domain_hash(
        b"MUTINY-BUILD8-NODE-CUSTODY-CONTEXT-V2",
        &e.into_writer(),
    ))
}
