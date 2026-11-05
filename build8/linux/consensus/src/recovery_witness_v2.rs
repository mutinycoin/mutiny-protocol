//! Exact public historical witnesses under an independently trusted parent
//! StateRoot. No recovery acceptance, finality override or current authority.
use minicbor::Decoder;
use crate::{
    Error, Hash, NETWORK_ID, Result, admission_v2::Admission, anchors::FinalizedAnchor,
    domain_hash, node_admission_v2::Binding, retired_continuity_v2::Record, state_tree::StateProof,
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witnesses {
    pub control: StateProof,
    pub continuity: StateProof,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retained {
    pub terminal: Record,
    pub control_bytes: Vec<u8>,
    pub key_bytes: Vec<u8>,
    pub node_current: Vec<u8>,
    pub control_sequence: u64,
    pub admitted_height: u64,
    pub hardware_since_height: u64,
}
impl Witnesses {
    pub fn verify(
        &self,
        parent: &FinalizedAnchor,
        root: Hash,
        old_node: Hash,
        hardware_generation: u64,
        key_generation: u64,
        replacement_commitment: Hash,
    ) -> Result<Retained> {
        let control = self
            .control
            .verify(
                parent,
                root,
                domain_hash(b"MUTINY-BUILD8-NODE-CONTROL-KEY-V2", &old_node),
            )?
            .ok_or(Error::UnknownSigner)?;
        let key = self
            .continuity
            .verify(
                parent,
                root,
                domain_hash(b"MUTINY-BUILD8-CONTINUITY-KEY-STATE-V2", &old_node),
            )?
            .ok_or(Error::UnknownSigner)?;
        let mut c = Decoder::new(control);
        let fields = c.array().map_err(|_| Error::Codec)?;
        if !matches!(fields, Some(9 | 10))
            || c.u8().map_err(|_| Error::Codec)? != 2
            || c.u8().map_err(|_| Error::Codec)? != 51
            || c.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let binding = Binding::decode(c.bytes().map_err(|_| Error::Codec)?)?;
        let control_sequence = c.u64().map_err(|_| Error::Codec)?;
        let admitted_height = c.u64().map_err(|_| Error::Codec)?;
        // A pending admission or exit is ineligible for the selected recovery.
        c.null().map_err(|_| Error::UnqualifiedPhysical)?;
        c.null().map_err(|_| Error::UnqualifiedPhysical)?;
        let hardware_since_height = c.u64().map_err(|_| Error::Codec)?;
        let node_current = if fields == Some(10) {
            c.bytes().map_err(|_| Error::Codec)?.to_vec()
        } else {
            binding.node_descriptor.clone()
        };
        if c.position() != control.len()
            || hardware_since_height < admitted_height
            || hardware_since_height > parent.height
        {
            return Err(Error::WrongAnchor);
        }
        let a = &binding.admission;
        if (a.node, a.hardware_generation, a.key_generation)
            != (old_node, hardware_generation, key_generation)
        {
            return Err(Error::WrongGeneration);
        }
        parent.validate_context(a.genesis, a.fingerprint)?;
        let mut k = Decoder::new(key);
        if k.array().map_err(|_| Error::Codec)? != Some(5)
            || k.u8().map_err(|_| Error::Codec)? != 2
            || k.u8().map_err(|_| Error::Codec)? != 50
            || k.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let owner_descriptor = k.bytes().map_err(|_| Error::Codec)?.to_vec();
        let admission = Admission::decode(k.bytes().map_err(|_| Error::Codec)?)?;
        if k.position() != key.len() || admission != *a {
            return Err(Error::WrongAnchor);
        }
        let (current, generation) = mutiny_crypto_v2::PublicKey::decode_descriptor(&node_current)
            .map_err(|_| Error::Codec)?;
        if current.role != mutiny_crypto_v2::Role::Node
            || generation == 0
            || (fields == Some(10) && (generation <= 1 || node_current == binding.node_descriptor))
        {
            return Err(Error::WrongGeneration);
        }
        let terminal = Record {
            binding,
            owner_descriptor,
            retired_height: parent.height.checked_add(1).ok_or(Error::Overflow)?,
            rotation: replacement_commitment,
        };
        terminal.verify_evidence()?;
        Ok(Retained {
            terminal,
            control_bytes: control.to_vec(),
            key_bytes: key.to_vec(),
            node_current,
            control_sequence,
            admitted_height,
            hardware_since_height,
        })
    }
}
