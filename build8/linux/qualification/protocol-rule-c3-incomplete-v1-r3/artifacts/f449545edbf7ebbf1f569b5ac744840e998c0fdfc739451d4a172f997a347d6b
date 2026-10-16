//! Atomic owner/node-authorized TPM generation replacement under old-set finality.
use crate::{
    Error, Hash, NETWORK_ID, Result,
    admission::{AdmissionPolicy, ApprovedProfile},
    anchors::FinalizedAnchor,
    domain_hash,
    execution::State,
    membership::{NodeControl, RetiredGeneration},
};
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
fn hash(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("hash"))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareRotate {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub height: u64,
    pub parent_anchor: Hash,
    pub node: Hash,
    pub old_generation: u64,
    pub new_generation: u64,
    pub sequence: u64,
    pub authorizer: Hash,
    pub node_authentication: Hash,
    pub approved_profile: Vec<u8>,
    pub evidence: Vec<u8>,
    pub authorization: [u8; 64],
    pub node_signature: [u8; 64],
    pub possession: [u8; 64],
}
impl HardwareRotate {
    fn bytes(&self, mode: u8) -> Result<Vec<u8>> {
        if self.approved_profile.len() > 16384 || self.evidence.len() > 16384 {
            return Err(Error::Oversize);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(match mode {
            0 => 14,
            1 => 15,
            _ => 18,
        })
        .unwrap()
        .u8(1)
        .unwrap()
        .u8(16)
        .unwrap()
        .u32(NETWORK_ID)
        .unwrap()
        .bytes(&self.genesis)
        .unwrap()
        .bytes(&self.fingerprint)
        .unwrap()
        .u64(self.height)
        .unwrap()
        .bytes(&self.parent_anchor)
        .unwrap()
        .bytes(&self.node)
        .unwrap()
        .u64(self.old_generation)
        .unwrap()
        .u64(self.new_generation)
        .unwrap()
        .u64(self.sequence)
        .unwrap()
        .bytes(&self.authorizer)
        .unwrap()
        .bytes(&self.node_authentication)
        .unwrap()
        .bytes(&self.approved_profile)
        .unwrap();
        if mode > 0 {
            e.bytes(&self.evidence).unwrap();
        }
        if mode > 1 {
            e.bytes(&self.authorization)
                .unwrap()
                .bytes(&self.node_signature)
                .unwrap()
                .bytes(&self.possession)
                .unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > 16384 {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.bytes(2)
    }
    pub fn challenge(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-ROTATE-ATTESTATION-V1",
            &self.bytes(0)?,
        ))
    }
    pub fn authorization_digest(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-ROTATE-AUTHORIZATION-V1",
            &self.bytes(1)?,
        ))
    }
    pub fn node_digest(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-ROTATE-NODE-AUTH-V1",
            &self.bytes(1)?,
        ))
    }
    pub fn possession_digest(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-ROTATE-POSSESSION-V1",
            &self.bytes(1)?,
        ))
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 16384)?;
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("rotate");
            if d.array()? != Some(18) || d.u8()? != 1 || d.u8()? != 16 || d.u32()? != NETWORK_ID {
                return Err(bad());
            }
            Ok(Self {
                genesis: hash(&mut d)?,
                fingerprint: hash(&mut d)?,
                height: d.u64()?,
                parent_anchor: hash(&mut d)?,
                node: hash(&mut d)?,
                old_generation: d.u64()?,
                new_generation: d.u64()?,
                sequence: d.u64()?,
                authorizer: hash(&mut d)?,
                node_authentication: hash(&mut d)?,
                approved_profile: d.bytes()?.to_vec(),
                evidence: d.bytes()?.to_vec(),
                authorization: d.bytes()?.try_into().map_err(|_| bad())?,
                node_signature: d.bytes()?.try_into().map_err(|_| bad())?,
                possession: d.bytes()?.try_into().map_err(|_| bad())?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    /// `class` is the admission class of the parent state (`State::admission_class`).
    pub fn validate(
        &self,
        parent: &FinalizedAnchor,
        control: &NodeControl,
        policy: &AdmissionPolicy,
        class: crate::provenance::AdmissionClass,
    ) -> Result<crate::tpm::TpmProfile> {
        parent.validate_context(self.genesis, self.fingerprint)?;
        if self.height == 0
            || parent.height.checked_add(1) != Some(self.height)
            || self.parent_anchor != parent.id()
            || self.node != control.node
            || policy.genesis != self.genesis
            || policy.fingerprint != self.fingerprint
        {
            return Err(Error::WrongAnchor);
        }
        if self.old_generation != control.generation
            || self.old_generation.checked_add(1) != Some(self.new_generation)
        {
            return Err(Error::WrongGeneration);
        }
        if control.sequence.checked_add(1) != Some(self.sequence) {
            return Err(Error::StaleSequence);
        }
        if self.authorizer != control.owner && self.authorizer != control.node_authentication {
            return Err(Error::BadSignature);
        }
        VerifyingKey::from_bytes(&self.authorizer)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(
                &self.authorization_digest()?,
                &Signature::from_bytes(&self.authorization),
            )
            .map_err(|_| Error::BadSignature)?;
        VerifyingKey::from_bytes(&self.node_authentication)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(
                &self.node_digest()?,
                &Signature::from_bytes(&self.node_signature),
            )
            .map_err(|_| Error::BadSignature)?;
        let profile = ApprovedProfile::decode(&self.approved_profile)?.verify(policy, class)?;
        profile.verify_quote(self.challenge()?, &self.evidence)?;
        let signature = p256::ecdsa::Signature::from_slice(&self.possession)
            .map_err(|_| Error::BadSignature)?;
        if signature.normalize_s().is_some() {
            return Err(Error::NonCanonical);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&crate::tpm::public_key(
            &profile.voting_public,
            false,
        )?)
        .map_err(|_| Error::BadSignature)?
        .verify_prehash(&self.possession_digest()?, &signature)
        .map_err(|_| Error::BadSignature)?;
        // Order A8: after sealing the ceremony-scoped admission authority admits no hardware
        // (Production class); checked after the complete verification, so malformed material fails first.
        crate::admission_scope::require_post_sealing_admission(class)?;
        Ok(profile)
    }
}
impl State {
    pub(crate) fn apply_rotations(
        &self,
        parent: &FinalizedAnchor,
        operations: &[Vec<u8>],
        next: &mut State,
    ) -> Result<()> {
        // Admission class from the parent's committed Genesis data, never from an operation.
        let class = self.admission_class()?;
        let mut seen = std::collections::BTreeSet::new();
        for raw in operations {
            if crate::blocks::operation_kind(raw)? != 16 {
                continue;
            }
            let rotation = HardwareRotate::decode(raw)?;
            if !seen.insert(rotation.node) {
                return Err(Error::Duplicate);
            }
            let control = self
                .membership
                .controls
                .get(&rotation.node)
                .ok_or(Error::UnknownSigner)?;
            if control.admission_boundary.is_some() || control.exit_boundary.is_some() {
                return Err(Error::WrongOperation);
            }
            // One ordinary control operation per lineage per block, irrespective
            // of transport ordering. Exit must not be combined with rotation.
            if operations.iter().any(|r| {
                crate::membership::ContinuityExit::decode(r).is_ok_and(|e| e.node == rotation.node)
            }) {
                return Err(Error::Duplicate);
            }
            let profile = rotation.validate(
                parent,
                control,
                self.admission
                    .policy
                    .as_ref()
                    .ok_or(Error::UnqualifiedPhysical)?,
                class,
            )?;
            let key = crate::tpm::public_key(&profile.voting_public, false)?;
            let old = self
                .continuity
                .as_ref()
                .ok_or(Error::UnqualifiedPhysical)?
                .members
                .iter()
                .find(|m| m.node == rotation.node)
                .ok_or(Error::UnknownSigner)?;
            if !old.physical
                || !old.eligible
                || old.generation != rotation.old_generation
                || self.penalties.revoked(old.lineage)
            {
                return Err(Error::WrongGeneration);
            }
            let registry = next.continuity.as_mut().ok_or(Error::UnqualifiedPhysical)?;
            if key == old.voting_key
                || registry.members.iter().any(|m| {
                    m.node != rotation.node
                        && (m.hardware == profile.hardware || m.voting_key == key)
                })
                || next.membership.retired.values().any(|r| {
                    r.voting_key == key
                        || (r.node != rotation.node && r.hardware == profile.hardware)
                })
            {
                return Err(Error::Duplicate);
            }
            let retired = RetiredGeneration {
                node: old.node,
                generation: old.generation,
                hardware: old.hardware,
                voting_key: old.voting_key,
                attestation: old.attestation,
                height: rotation.height,
                reason: 1,
                evidence: domain_hash(b"MUTINY-BUILD8-ROTATION-RECORD-V1", raw),
            };
            if next
                .membership
                .retired
                .insert((old.node, old.generation), retired)
                .is_some()
            {
                return Err(Error::WrongGeneration);
            }
            let updated = registry
                .members
                .iter_mut()
                .find(|m| m.node == rotation.node)
                .ok_or(Error::UnknownSigner)?;
            updated.generation = rotation.new_generation;
            updated.hardware = profile.hardware;
            updated.voting_key = key;
            updated.attestation = profile.commitment()?;
            let control = next
                .membership
                .controls
                .get_mut(&rotation.node)
                .ok_or(Error::UnknownSigner)?;
            control.generation = rotation.new_generation;
            control.sequence = rotation.sequence;
            control.node_authentication = rotation.node_authentication;
            if old.hardware != profile.hardware {
                updated.history.h = 0;
                control.hardware_since_height = rotation.height;
            }
            next.admission.profiles.insert(
                updated.attestation,
                ApprovedProfile::decode(&rotation.approved_profile)?,
            );
            if !registry
                .members
                .iter()
                .any(|m| m.attestation == old.attestation)
            {
                next.admission.profiles.remove(&old.attestation);
            }
            next.accounting.freshness.insert(
                rotation.node,
                crate::freshness::FreshnessRecord {
                    node: rotation.node,
                    generation: rotation.new_generation,
                    key,
                    committed_height: rotation.height,
                    evidence_commitment: domain_hash(
                        b"MUTINY-BUILD8-ATTESTATION-EVIDENCE-V1",
                        &rotation.evidence,
                    ),
                },
            );
        }
        next.admission.records(class)?;
        next.membership.records()?;
        Ok(())
    }
    /// A physical replacement cannot inherit the old hardware's slots within
    /// the current period. Lineage P/S accounting remains unchanged.
    pub(crate) fn adjust_hardware_history(
        &self,
        height: u64,
        operations: &[Vec<u8>],
        post: &mut crate::recovery::ContinuityState,
    ) -> Result<()> {
        if !height.is_multiple_of(60) {
            return Ok(());
        }
        let start = height.checked_sub(60).ok_or(Error::InvalidCounter)?;
        for control in self
            .membership
            .controls
            .values()
            .filter(|c| c.hardware_since_height > start)
        {
            let old = self
                .continuity
                .as_ref()
                .ok_or(Error::UnqualifiedPhysical)?
                .members
                .iter()
                .find(|m| m.node == control.node)
                .ok_or(Error::UnknownSigner)?;
            if !old.physical || !old.eligible {
                continue;
            }
            let offset = control
                .hardware_since_height
                .checked_sub(start)
                .ok_or(Error::InvalidCounter)?;
            if offset > 60 {
                return Err(Error::InvalidCounter);
            }
            let mut bits = self
                .accounting
                .slots
                .bits
                .get(&control.node)
                .copied()
                .unwrap_or(0);
            if operations.iter().any(|raw| {
                crate::participation::ParticipationAck::decode(raw)
                    .is_ok_and(|a| a.node == control.node)
            }) {
                bits |= 1u64 << 59;
            }
            let retained = bits & (!0u64 << offset);
            if retained.count_ones() < 54 {
                post.members
                    .iter_mut()
                    .find(|m| m.node == control.node)
                    .ok_or(Error::UnknownSigner)?
                    .history
                    .h = old.history.h;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        recovery::{Anchor, ContinuityState, Member},
        reputation::{Bond, ContinuityPeriod, History},
    };
    use crate::provenance::AdmissionClass;
    use ed25519_dalek::SigningKey;
    // TEST-VALUE simulator support (public seeds only), shared with the integration tests; declared
    // once at file scope in lib.rs (a #[path] in this inline module would not resolve on Linux).
    use crate::software_tpm;
    /// SOFTWARE TEST-VALUE fixture (deterministic simulator, TEST-VALUE marked), regenerated and
    /// drift-checked by consensus/tests/software_admission_fixtures.rs. SIMULATED != PHYSICAL.
    const TEST_VALUE_FIXTURE: &str =
        include_str!("../../qualification/ROTATION-TEST-VALUE-FIXTURE-V1.json");
    fn fixture() -> (FinalizedAnchor, HardwareRotate, State) {
        fixture_from(TEST_VALUE_FIXTURE)
    }
    fn fixture_from(text: &str) -> (FinalizedAnchor, HardwareRotate, State) {
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        let raw = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
        let parent = FinalizedAnchor::decode(&raw("parent")).unwrap();
        let rotation = HardwareRotate::decode(&raw("operation")).unwrap();
        let policy = AdmissionPolicy::decode(&raw("policy")).unwrap();
        let owner = SigningKey::from_bytes(&[61; 32]);
        let mut state = State::default();
        state.admission.policy = Some(policy.clone());
        state.accounting.slots.last_height = parent.height;
        state.membership.controls.insert(
            rotation.node,
            NodeControl {
                node: rotation.node,
                generation: 0,
                owner: owner.verifying_key().to_bytes(),
                node_authentication: SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes(),
                sequence: 0,
                exit_boundary: None,
                admitted_height: 0,
                admission_boundary: None,
                hardware_since_height: 0,
            },
        );
        // Synthetic old lineage tests preservation; the replacement evidence is the TEST-VALUE
        // simulator (real evidence only in the ignored runtime test). This does not qualify this
        // old set as a real chain.
        state.continuity = Some(
            ContinuityState::bootstrap(
                parent.genesis,
                parent.fingerprint,
                Anchor {
                    height: parent.height,
                    tip: parent.block,
                    state_root: [4; 32],
                    registry_root: [5; 32],
                },
                policy.authority,
                vec![Member {
                    node: rotation.node,
                    lineage: rotation.node,
                    generation: 0,
                    hardware: [8; 32],
                    voting_key: p256::ecdsa::SigningKey::from_bytes((&[9; 32]).into())
                        .unwrap()
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                    attestation: [10; 32],
                    history: History {
                        p: 5,
                        a: 6,
                        s: 3,
                        h: 5,
                        penalties: 17.into(),
                        bonds: vec![Bond {
                            atoms: 10_000_000_000,
                            age: ContinuityPeriod(3),
                        }],
                    },
                    physical: true,
                    eligible: true,
                    genesis_member: true,
                }],
            )
            .unwrap(),
        );
        (parent, rotation, state)
    }
    #[test]
    fn replacement_preserves_lineage_and_bonds_retires_old_key_and_resets_only_hardware_history() {
        rotation_fixture_checks(TEST_VALUE_FIXTURE, true);
    }
    /// PHYSICAL-ONLY: the same checks over real rotation evidence supplied at RUNTIME by path:
    /// BUILD8_PHYSICAL_ROTATION_FIXTURE=<path> cargo test --offline --locked --lib -- --ignored physical_rotation
    #[test]
    #[ignore = "requires physical rotation evidence supplied by env path (runtime)"]
    fn physical_rotation_fixture_from_runtime_path() {
        let var = "BUILD8_PHYSICAL_ROTATION_FIXTURE";
        let path = std::env::var(var).unwrap_or_else(|_| {
            panic!("PHYSICAL TPM EVIDENCE MISSING: {var} is not set; this test must not pass without real evidence")
        });
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{var}={path}: {e}"));
        rotation_fixture_checks(&text, false);
    }
    fn rotation_fixture_checks(text: &str, test_value: bool) {
        let label: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(label["TEST_VALUE"] == true, test_value, "evidence class label");
        let (parent, rotation, state) = fixture_from(text);
        let profile = ApprovedProfile::decode(&rotation.approved_profile)
            .unwrap()
            .verify(state.admission.policy.as_ref().unwrap(), AdmissionClass::LegacyTest)
            .unwrap();
        assert_eq!(profile.is_test_value(), test_value, "TEST-VALUE marker vs evidence class");
        let mut next = state.clone();
        next.accounting.slots.last_height = rotation.height;
        state
            .apply_rotations(&parent, &[rotation.encode().unwrap()], &mut next)
            .unwrap();
        let old = &state.continuity.as_ref().unwrap().members[0];
        let new = &next.continuity.as_ref().unwrap().members[0];
        assert_eq!(new.node, old.node);
        assert_eq!(new.lineage, old.lineage);
        assert_eq!(new.generation, 1);
        let mut expected = old.history.clone();
        expected.h = 0;
        assert_eq!(new.history, expected);
        assert_eq!(
            next.membership.retired[&(old.node, 0)].voting_key,
            old.voting_key
        );
        assert_eq!(next.membership.controls[&old.node].sequence, 1);
        assert_eq!(next.membership.controls[&old.node].hardware_since_height, 7);
        let fresh = &next.accounting.freshness[&old.node];
        assert!(!fresh.eligible(old.node, 0, old.voting_key, 8));
        assert!(fresh.eligible(new.node, 1, new.voting_key, 8));
        assert!(!fresh.eligible(new.node, 1, new.voting_key, 7));
        let rebuilt = State::from_records(&next.records().unwrap(), next.root().unwrap()).unwrap();
        assert_eq!(rebuilt.membership, next.membership);
        let mut same_tpm = state.clone();
        same_tpm.continuity.as_mut().unwrap().members[0].hardware = new.hardware;
        let mut same_result = same_tpm.clone();
        same_tpm
            .apply_rotations(&parent, &[rotation.encode().unwrap()], &mut same_result)
            .unwrap();
        assert_eq!(
            same_result.continuity.as_ref().unwrap().members[0].history,
            old.history
        );
        assert_eq!(
            same_result.membership.controls[&old.node].hardware_since_height,
            0
        );
        assert!(
            next.apply_rotations(&parent, &[rotation.encode().unwrap()], &mut next.clone())
                .is_err()
        );
        for which in 0..10 {
            let mut wrong = rotation.clone();
            match which {
                0 => wrong.genesis[0] ^= 1,
                1 => wrong.fingerprint[0] ^= 1,
                2 => wrong.parent_anchor[0] ^= 1,
                3 => wrong.old_generation += 1,
                4 => wrong.new_generation += 1,
                5 => wrong.sequence += 1,
                6 => wrong.authorization[0] ^= 1,
                7 => wrong.evidence[7] ^= 1,
                8 => wrong.node_signature[0] ^= 1,
                _ => wrong.possession[0] ^= 1,
            };
            assert!(
                state
                    .apply_rotations(&parent, &[wrong.encode().unwrap()], &mut state.clone())
                    .is_err()
            );
        }
    }
    /// JSON shape of a rotation fixture from typed values (reuses `fixture_from`).
    fn typed_fixture(parent: &FinalizedAnchor, policy: &AdmissionPolicy, rotation: &HardwareRotate) -> String {
        serde_json::json!({
            "parent": hex::encode(parent.encode()),
            "policy": hex::encode(policy.encode().unwrap()),
            "operation": hex::encode(rotation.encode().unwrap()),
        })
        .to_string()
    }
    fn production(state: &mut State) {
        let roots = state.admission.policy.as_ref().unwrap().endorsement_roots.clone();
        state.protocol_records.insert(
            crate::genesis_inputs::parameters_key(),
            software_tpm::production_parameters(&roots),
        );
        assert_eq!(state.admission_class().unwrap(), AdmissionClass::Production);
    }
    /// T4 (V1 ROTATION) and T15: in the Production class every marked, marker-stripped, relabeled
    /// or provenance-inconsistent replacement profile is rejected by `HardwareRotate::validate`
    /// and `apply_rotations`; the old generation, history and bonds stay intact and the parent
    /// state is unchanged. The committed TEST-VALUE fixture rotation is refused as well.
    #[test]
    fn production_class_rotation_rejects_marked_stripped_and_inconsistent_software_profiles() {
        let root = software_tpm::test_value_endorsement_root();
        let mut cases: Vec<(&str, String)> = software_tpm::production_negative_variants(root)
            .into_iter()
            .map(|(name, tpm, _)| {
                let (parent, policy, rotation) = software_tpm::rotation_operation(&tpm);
                (name, typed_fixture(&parent, &policy, &rotation))
            })
            .collect();
        cases.push(("committed TEST-VALUE fixture", TEST_VALUE_FIXTURE.to_string()));
        for (name, text) in cases {
            let (parent, rotation, mut state) = fixture_from(&text);
            production(&mut state);
            let policy = state.admission.policy.clone().unwrap();
            let control = state.membership.controls[&rotation.node].clone();
            assert!(
                matches!(rotation.validate(&parent, &control, &policy, AdmissionClass::Production), Err(e) if e != crate::Error::AdmissionAuthorityEnded),
                "{name}"
            );
            let before = state.clone();
            let mut next = state.clone();
            next.accounting.slots.last_height = rotation.height;
            let untouched = next.clone();
            assert!(
                matches!(state.apply_rotations(&parent, &[rotation.encode().unwrap()], &mut next), Err(e) if e != crate::Error::AdmissionAuthorityEnded),
                "{name}"
            );
            assert_eq!(state, before, "{name}: parent state changed");
            assert_eq!(next, untouched, "{name}: old generation/history/bonds changed");
        }
    }
    /// Order A8 (candidate 3; formerly the T14 acceptance `authority_attestation_is_the_anchor_
    /// consistent_software_provenance_rotates_production_class`): the admission authority's signature
    /// ALONE no longer admits replacement hardware after sealing. In the Production class the same
    /// rotation is refused with exactly `AdmissionAuthorityEnded`, the candidate unchanged; the
    /// Legacy/Test class still rotates it.
    #[test]
    fn admission_authority_alone_cannot_rotate_hardware_after_sealing_production_class() {
        let root = software_tpm::test_value_endorsement_root();
        let tpm = software_tpm::TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(root));
        let (parent, policy, rotation) = software_tpm::rotation_operation(&tpm);
        let (parent, rotation, legacy) = fixture_from(&typed_fixture(&parent, &policy, &rotation));
        let mut state = legacy.clone();
        production(&mut state);
        let mut next = state.clone();
        next.accounting.slots.last_height = rotation.height;
        let untouched = next.clone();
        assert_eq!(
            state
                .apply_rotations(&parent, &[rotation.encode().unwrap()], &mut next)
                .unwrap_err(),
            crate::Error::AdmissionAuthorityEnded
        );
        assert_eq!(next, untouched);
        let mut next = legacy.clone();
        next.accounting.slots.last_height = rotation.height;
        legacy
            .apply_rotations(&parent, &[rotation.encode().unwrap()], &mut next)
            .unwrap();
        assert_eq!(next.continuity.as_ref().unwrap().members[0].generation, 1);
        next.records().unwrap();
    }
    #[test]
    fn old_hardware_slots_cannot_supply_new_hardware_54_slot_threshold() {
        let (_, _, mut state) = fixture();
        let node = [7; 32];
        state.continuity.as_mut().unwrap().members[0].history.h = 0;
        state.accounting.slots.last_height = 59;
        state.accounting.slots.bits.insert(node, (1u64 << 59) - 1);
        let ack = crate::participation::ParticipationAck {
            network: NETWORK_ID,
            genesis: state.continuity.as_ref().unwrap().genesis,
            fingerprint: [2; 32],
            height: 60,
            parent: [3; 32],
            node,
            generation: 1,
            signature: [0; 64],
        };
        for (replacement_height, expected) in [(6, 1), (7, 0)] {
            state
                .membership
                .controls
                .get_mut(&node)
                .unwrap()
                .hardware_since_height = replacement_height;
            let mut post = state.continuity.clone().unwrap();
            post.members[0].history.h = 1;
            state
                .adjust_hardware_history(60, &[ack.encode()], &mut post)
                .unwrap();
            assert_eq!(post.members[0].history.h, expected);
        }
    }
}
