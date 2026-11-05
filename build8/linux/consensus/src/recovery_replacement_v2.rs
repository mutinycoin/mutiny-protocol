//! Candidate signed replacement material. No canonical state installation API.
use minicbor::{Decoder, Encoder};
use crate::{
    Error, Hash, NETWORK_ID, Result,
    anchors::FinalizedAnchor,
    domain_hash,
    execution::State,
    node_admission_v2::Binding,
    recovery_authority_v2::{Authorization, Intent},
    tpm::TpmProfile,
};
use mutiny_crypto_v2::{PublicKey, Role};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use crate::recovery_loss_v2 as loss;
pub const MAX_MATERIAL: usize = 256 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replacement {
    pub parent: FinalizedAnchor,
    pub root: Hash,
    pub membership: Hash,
    pub sequence: u64,
    pub lineage: Hash,
    pub old_node: Hash,
    pub old_hardware_generation: u64,
    pub old_key_generation: u64,
    pub nonce: Hash,
    pub lost: Vec<(Hash, u64)>,
    pub binding: Binding,
    pub native_possession: [u8; 64],
}
impl Replacement {
    fn context(&self) -> Result<Vec<u8>> {
        let a = &self.binding.admission;
        self.parent.validate_context(a.genesis, a.fingerprint)?;
        self.parent.height.checked_add(1).ok_or(Error::Overflow)?;
        if [
            self.root,
            self.membership,
            self.lineage,
            self.old_node,
            self.nonce,
        ]
        .contains(&[0; 32])
            || self.sequence == 0
            || self.old_hardware_generation == 0
            || self.old_key_generation == 0
        {
            return Err(Error::InvalidCounter);
        }
        if self.old_hardware_generation.checked_add(1) != Some(a.hardware_generation)
            || self.old_key_generation.checked_add(1) != Some(a.key_generation)
            || a.node == self.old_node
        {
            return Err(Error::WrongGeneration);
        }
        let commitment = crate::recovery::loss_commitment(&self.lost)?;
        let mut e = Encoder::new(Vec::new());
        e.array(15)
            .unwrap()
            .u8(2)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.parent.encode())
            .unwrap()
            .bytes(&self.root)
            .unwrap()
            .bytes(&self.membership)
            .unwrap()
            .u64(self.sequence)
            .unwrap()
            .bytes(&self.lineage)
            .unwrap()
            .bytes(&self.old_node)
            .unwrap()
            .u64(self.old_hardware_generation)
            .unwrap()
            .u64(self.old_key_generation)
            .unwrap()
            .bytes(&self.nonce)
            .unwrap()
            .bytes(&commitment)
            .unwrap()
            .bytes(&a.node)
            .unwrap()
            .u64(a.hardware_generation)
            .unwrap()
            .u64(a.key_generation)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn admission_nonce(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-RECOVERY-REPLACEMENT-CONTEXT-V2",
            &self.context()?,
        ))
    }
    fn bytes(&self, signed: bool) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(if signed { 5 } else { 4 })
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&self.context()?)
            .unwrap()
            .array(self.lost.len() as u64)
            .unwrap();
        for (lineage, generation) in &self.lost {
            e.array(2)
                .unwrap()
                .bytes(lineage)
                .unwrap()
                .u64(*generation)
                .unwrap();
        }
        e.bytes(&self.binding.encode()?).unwrap();
        if signed {
            e.bytes(&self.native_possession).unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_MATERIAL {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn native_digest(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-RECOVERY-REPLACEMENT-NATIVE-V2",
            &self.bytes(false)?,
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.bytes(true)
    }
    pub fn commitment(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-RECOVERY-REPLACEMENT-V2",
            &self.encode()?,
        ))
    }
    pub fn intent(&self) -> Result<Intent> {
        Ok(Intent {
            parent: self.parent.clone(),
            state_root: self.root,
            membership_root: self.membership,
            sequence: self.sequence,
            transition: self.commitment()?,
        })
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_MATERIAL)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(5) || d.u8().map_err(|_| Error::Codec)? != 2
        {
            return Err(Error::Codec);
        }
        let context = d.bytes().map_err(|_| Error::Codec)?;
        let mut c = Decoder::new(context);
        if c.array().map_err(|_| Error::Codec)? != Some(15)
            || c.u8().map_err(|_| Error::Codec)? != 2
            || c.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let parent = FinalizedAnchor::decode(c.bytes().map_err(|_| Error::Codec)?)?;
        let root = hash(&mut c)?;
        let membership = hash(&mut c)?;
        let sequence = c.u64().map_err(|_| Error::Codec)?;
        let lineage = hash(&mut c)?;
        let old_node = hash(&mut c)?;
        let old_hardware_generation = c.u64().map_err(|_| Error::Codec)?;
        let old_key_generation = c.u64().map_err(|_| Error::Codec)?;
        let nonce = hash(&mut c)?;
        let _declaration = hash(&mut c)?;
        let _node = hash(&mut c)?;
        let _hardware = c.u64().map_err(|_| Error::Codec)?;
        let _key = c.u64().map_err(|_| Error::Codec)?;
        if c.position() != context.len() {
            return Err(Error::NonCanonical);
        }
        let n = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
        if n == 0 || n > 1024 {
            return Err(Error::Capacity);
        }
        let mut lost = Vec::new();
        for _ in 0..n {
            if d.array().map_err(|_| Error::Codec)? != Some(2) {
                return Err(Error::Codec);
            }
            lost.push((hash(&mut d)?, d.u64().map_err(|_| Error::Codec)?));
        }
        let binding = Binding::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let native_possession = d
            .bytes()
            .map_err(|_| Error::Codec)?
            .try_into()
            .map_err(|_| Error::Codec)?;
        let value = Self {
            parent,
            root,
            membership,
            sequence,
            lineage,
            old_node,
            old_hardware_generation,
            old_key_generation,
            nonce,
            lost,
            binding,
            native_possession,
        };
        // Exact reconstruction also checks every redundant context commitment.
        if d.position() != raw.len() || value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    /// Cryptographic historical evidence only; no proof that the old parent
    /// authorized loss, replacement policy or current recovery acceptance.
    pub fn verify_retained_evidence(&self, owner_descriptor: &[u8]) -> Result<()> {
        self.encode()?;
        if self.binding.admission.supervised_nonce != self.admission_nonce()?
            || self.binding.node_signer.is_some()
        {
            return Err(Error::WrongAnchor);
        }
        let (_, g) = PublicKey::decode_descriptor(&self.binding.node_descriptor)
            .map_err(|_| Error::Codec)?;
        if g != 1 {
            return Err(Error::WrongGeneration);
        }
        crate::retired_continuity_v2::Record {
            binding: self.binding.clone(),
            owner_descriptor: owner_descriptor.to_vec(),
            retired_height: self.parent.height.checked_add(1).ok_or(Error::Overflow)?,
            rotation: self.commitment()?,
        }
        .verify_evidence()?;
        let profile = TpmProfile::decode(&self.binding.admission.profile)?;
        let key = crate::tpm::public_key(&profile.voting_public, false)?;
        let signature = p256::ecdsa::Signature::from_slice(&self.native_possession)
            .map_err(|_| Error::BadSignature)?;
        if signature.normalize_s().is_some() {
            return Err(Error::NonCanonical);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&key)
            .map_err(|_| Error::BadSignature)?
            .verify_prehash(&self.native_digest()?, &signature)
            .map_err(|_| Error::BadSignature)
    }
    /// Verifies authorization/material only. Durable conflict exclusion and the
    /// prospective authenticated history transition remain mandatory elsewhere.
    pub fn verify_material(
        &self,
        state: &State,
        parent: &FinalizedAnchor,
        root: Hash,
        authorization: &Authorization,
        existing_valid_descendant: bool,
    ) -> Result<()> {
        if &self.parent != parent || self.root != root {
            return Err(Error::WrongAnchor);
        }
        let assessed = loss::preflight(
            state,
            parent,
            root,
            self.sequence,
            self.lineage,
            &self.lost,
            existing_valid_descendant,
        )?;
        if (
            assessed.membership,
            assessed.node,
            assessed.hardware_generation,
            assessed.key_generation,
        ) != (
            self.membership,
            self.old_node,
            self.old_hardware_generation,
            self.old_key_generation,
        ) {
            return Err(Error::WrongAnchor);
        }
        let recovery = state
            .recovery_authority_v2
            .as_ref()
            .ok_or(Error::RecoveryDisabled)?;
        authorization.verify_signature_only(recovery, &self.intent()?)?;
        let a = &self.binding.admission;
        let (node, generation) = PublicKey::decode_descriptor(&self.binding.node_descriptor)
            .map_err(|_| Error::Codec)?;
        let (continuity, _) =
            PublicKey::decode_descriptor(&a.continuity_descriptor).map_err(|_| Error::Codec)?;
        if generation != 1 || node.role != Role::Node || self.binding.node_signer.is_some() {
            return Err(Error::WrongGeneration);
        }
        recovery.reject_aliases([
            self.binding.node_descriptor.as_slice(),
            a.continuity_descriptor.as_slice(),
        ])?;
        let profile = TpmProfile::decode(&a.profile)?;
        let native = crate::tpm::public_key(&profile.voting_public, false)?;
        let registry = state.continuity.as_ref().ok_or(Error::UnknownSigner)?;
        for member in &registry.members {
            if member.node == a.node
                || member.hardware == profile.hardware
                || member.voting_key == native
            {
                return Err(Error::Duplicate);
            }
            if let Some(control) = state.membership_v2.get(member.node) {
                for raw in [
                    control.binding().node_descriptor.as_slice(),
                    control.current_node_descriptor(),
                    control.binding().admission.continuity_descriptor.as_slice(),
                ] {
                    reject_alias(raw, &node, &continuity)?;
                }
            }
        }
        // External qualification crate reads the existing canonical public
        // wallet rows; promotion can use the crate-private descriptor iterator.
        for raw in state.wallets.records()?.values() {
            let mut d = Decoder::new(raw);
            if d.array().map_err(|_| Error::Codec)? != Some(4)
                || d.u8().map_err(|_| Error::Codec)? != 1
                || !matches!(d.u8().map_err(|_| Error::Codec)?, 30 | 31)
            {
                return Err(Error::Codec);
            }
            let _id = hash(&mut d)?;
            reject_alias(d.bytes().map_err(|_| Error::Codec)?, &node, &continuity)?;
            if d.position() != raw.len() {
                return Err(Error::NonCanonical);
            }
        }
        for raw in state.retired_continuity_v2.records()?.values() {
            let old = crate::retired_continuity_v2::Record::decode(raw)?;
            let p = TpmProfile::decode(&old.binding.admission.profile)?;
            if p.hardware == profile.hardware
                || crate::tpm::public_key(&p.voting_public, false)? == native
            {
                return Err(Error::Duplicate);
            }
            for raw in [
                old.owner_descriptor.as_slice(),
                old.binding.node_descriptor.as_slice(),
                old.binding.signer_descriptor(),
                old.binding.admission.continuity_descriptor.as_slice(),
            ] {
                reject_alias(raw, &node, &continuity)?;
            }
        }
        for old in state.node_key_history_v2.entries() {
            for raw in [
                old.operation.current.as_slice(),
                old.operation.proposed.as_slice(),
                old.operation.authorizer.as_slice(),
            ] {
                reject_alias(raw, &node, &continuity)?;
            }
        }
        // Order A4: every committed endorsement identity, against every current and retired binding
        // (as for `hardware` above, the replacement may not reuse the lost generation's identity).
        let existing = state
            .continuity_keys_v2
            .bindings()
            .map(|b| b.admission())
            .chain(state.retired_continuity_v2.entries().map(|r| &r.binding.admission))
            .map(|other| TpmProfile::decode(&other.profile))
            .collect::<Result<Vec<_>>>()?;
        crate::endorsement_identity::reject_shared_identity(&profile, &existing)?;
        reject_assignment_aliases(&state.licenses_v2, &node, &continuity)?;
        let policy = state.current_admission_policy_v2(parent.genesis, parent.fingerprint)?;
        let old_owner = state
            .membership_v2
            .get(self.old_node)
            .ok_or(Error::UnknownSigner)?
            .binding()
            .admission
            .owner;
        state
            .wallets
            .authorize(old_owner, &policy.owner_descriptor)?;
        self.binding.verify(
            &policy,
            &crate::admission_v2::Expected {
                node: a.node,
                hardware_generation: a.hardware_generation,
                key_generation: a.key_generation,
                supervised_nonce: self.admission_nonce()?,
            },
            &state.wallets,
            state.admission_class()?,
        )?;
        let signature = p256::ecdsa::Signature::from_slice(&self.native_possession)
            .map_err(|_| Error::BadSignature)?;
        if signature.normalize_s().is_some() {
            return Err(Error::NonCanonical);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&native)
            .map_err(|_| Error::BadSignature)?
            .verify_prehash(&self.native_digest()?, &signature)
            .map_err(|_| Error::BadSignature)?;
        // Order A8: checked after the complete verification, so malformed material fails first.
        crate::admission_scope::require_post_sealing_admission(state.admission_class()?)
    }
}
fn hash(d: &mut Decoder<'_>) -> Result<Hash> {
    d.bytes()
        .map_err(|_| Error::Codec)?
        .try_into()
        .map_err(|_| Error::Codec)
}
fn reject_alias(raw: &[u8], node: &PublicKey, continuity: &PublicKey) -> Result<()> {
    let (p, _) = PublicKey::decode_descriptor(raw).map_err(|_| Error::Codec)?;
    if [node, continuity]
        .iter()
        .any(|k| k.ed448 == p.ed448 || k.fndsa == p.fndsa)
    {
        Err(Error::Duplicate)
    } else {
        Ok(())
    }
}

// Existing Worker/coordinator assignments include retained historical authority.
fn reject_assignment_aliases(
    book: &crate::license_book_v2::Book,
    node: &PublicKey,
    continuity: &PublicKey,
) -> Result<()> {
    for raw in book.records()?.values() {
        let mut d = Decoder::new(raw);
        let n = d.array().map_err(|_| Error::Codec)?;
        if d.u8().map_err(|_| Error::Codec)? != 2 {
            return Err(Error::Codec);
        }
        match d.u8().map_err(|_| Error::Codec)? {
            40 => continue,
            kind @ (41 | 42) => {
                if n != Some(if kind == 41 { 4 } else { 3 }) {
                    return Err(Error::Codec);
                }
                let a = crate::license_assignment_v2::Assignment::decode(
                    d.bytes().map_err(|_| Error::Codec)?,
                )?;
                reject_alias(&a.owner_descriptor, node, continuity)?;
                reject_alias(&a.node_descriptor, node, continuity)?;
                if [node, continuity]
                    .iter()
                    .any(|k| k.ed448 == a.enrollment.binding.worker_public)
                {
                    return Err(Error::Duplicate);
                }
                if kind == 41 {
                    d.u64().map_err(|_| Error::Codec)?;
                }
                if d.position() != raw.len() {
                    return Err(Error::NonCanonical);
                }
            }
            _ => return Err(Error::Codec),
        }
    }
    Ok(())
}
#[cfg(test)]
mod alias_tests {
    use super::*;
    #[test]
    fn replacement_roles_reject_retained_worker_and_coordinator_aliases() {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../../qualification/bootstrap-recovery-state-public-v1.json")).unwrap();
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let rows: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let state = State::from_records(&rows, root).unwrap();
        let recovery = state.recovery_authority_v2.as_ref().unwrap();
        let (base, _) = PublicKey::decode_descriptor(&recovery.descriptor).unwrap();
        let mut node = base.clone();
        node.role = Role::Node;
        let mut continuity = base;
        continuity.role = Role::Continuity;
        reject_assignment_aliases(&state.licenses_v2, &node, &continuity).unwrap();
        let rows = state.licenses_v2.records().unwrap();
        let a = rows
            .values()
            .find_map(|raw| {
                let mut d = Decoder::new(raw);
                d.array().ok()?;
                if d.u8().ok()? != 2 || d.u8().ok()? != 41 {
                    return None;
                }
                crate::license_assignment_v2::Assignment::decode(d.bytes().ok()?).ok()
            })
            .unwrap();
        let mut worker_alias = node.clone();
        worker_alias.ed448 = a.enrollment.binding.worker_public;
        assert!(reject_assignment_aliases(&state.licenses_v2, &worker_alias, &continuity).is_err());
        let (coordinator, _) = PublicKey::decode_descriptor(&a.node_descriptor).unwrap();
        for half in 0..2 {
            let mut bad = continuity.clone();
            if half == 0 {
                bad.ed448 = coordinator.ed448
            } else {
                bad.fndsa = coordinator.fndsa
            };
            assert!(reject_assignment_aliases(&state.licenses_v2, &node, &bad).is_err());
        }
    }
}
