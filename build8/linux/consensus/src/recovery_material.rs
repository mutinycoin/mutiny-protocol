//! Public replacement material for the existing supervised bootstrap recovery.
//! The recovery certificate commits the replacement NodeID/key/profile. This
//! witness supplies their native verification and typed restart state.
use crate::{
    Error, Hash, Result,
    admission::{AdmissionPolicy, ApprovedProfile},
    domain_hash,
    execution::State,
    recovery::{Certificate, Recovery},
};
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryMaterial {
    pub approved_profile: Vec<u8>,
    pub node_authentication: Hash,
    pub quote: Vec<u8>,
    pub node_signature: [u8; 64],
    pub possession_signature: [u8; 64],
}
impl RecoveryMaterial {
    pub fn challenge(body: &Recovery) -> Hash {
        domain_hash(b"MUTINY-BUILD8-RECOVERY-ATTESTATION-V1", &body.encode())
    }
    fn unsigned(&self, body: &Recovery) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&body.encode())
            .unwrap()
            .bytes(&self.approved_profile)
            .unwrap()
            .bytes(&self.node_authentication)
            .unwrap()
            .bytes(&self.quote)
            .unwrap();
        e.into_writer()
    }
    pub fn node_digest(&self, body: &Recovery) -> Hash {
        domain_hash(b"MUTINY-BUILD8-RECOVERY-NODE-AUTH-V1", &self.unsigned(body))
    }
    pub fn possession_digest(&self, body: &Recovery) -> Hash {
        domain_hash(
            b"MUTINY-BUILD8-RECOVERY-POSSESSION-V1",
            &self.unsigned(body),
        )
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.approved_profile)
            .unwrap()
            .bytes(&self.node_authentication)
            .unwrap()
            .bytes(&self.quote)
            .unwrap()
            .bytes(&self.node_signature)
            .unwrap()
            .bytes(&self.possession_signature)
            .unwrap();
        let raw = e.into_writer();
        crate::blocks::canonical(&raw, 16 * 1024)?;
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 16 * 1024)?;
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("recovery material");
            if d.array()? != Some(6) || d.u8()? != 1 {
                return Err(bad());
            }
            Ok(Self {
                approved_profile: d.bytes()?.to_vec(),
                node_authentication: d.bytes()?.try_into().map_err(|_| bad())?,
                quote: d.bytes()?.to_vec(),
                node_signature: d.bytes()?.try_into().map_err(|_| bad())?,
                possession_signature: d.bytes()?.try_into().map_err(|_| bad())?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    /// `class` is the admission class of the state the recovery applies to
    /// (`State::admission_class`).
    pub fn verify(
        &self,
        body: &Recovery,
        policy: &AdmissionPolicy,
        class: crate::provenance::AdmissionClass,
    ) -> Result<()> {
        self.encode()?;
        if policy.genesis != body.genesis
            || policy.fingerprint != body.fingerprint
            || crate::join::node_id(body.genesis, self.node_authentication) != body.new_node
        {
            return Err(Error::WrongAnchor);
        }
        let profile = ApprovedProfile::decode(&self.approved_profile)?.verify(policy, class)?;
        if profile.hardware != body.new_hardware
            || profile.commitment()? != body.attestation
            || crate::tpm::public_key(&profile.voting_public, false)? != body.new_voting_key
        {
            return Err(Error::UnqualifiedPhysical);
        }
        profile.verify_quote(Self::challenge(body), &self.quote)?;
        VerifyingKey::from_bytes(&self.node_authentication)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(
                &self.node_digest(body),
                &Signature::from_bytes(&self.node_signature),
            )
            .map_err(|_| Error::BadSignature)?;
        let sig = p256::ecdsa::Signature::from_slice(&self.possession_signature)
            .map_err(|_| Error::BadSignature)?;
        if sig.normalize_s().is_some() {
            return Err(Error::NonCanonical);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&body.new_voting_key)
            .map_err(|_| Error::BadSignature)?
            .verify_prehash(&self.possession_digest(body), &sig)
            .map_err(|_| Error::BadSignature)?;
        // Order A8: after sealing the ceremony-scoped admission authority admits no hardware
        // (Production class); checked after the complete verification, so malformed material fails first.
        crate::admission_scope::require_post_sealing_admission(class)
    }
}
impl State {
    /// Apply around an already-authorized registry recovery. The old state is
    /// immutable; the caller installs all typed replacement material atomically.
    pub(crate) fn carry_recovery_material(
        &self,
        certificate: &Certificate,
        witness: &RecoveryMaterial,
        next: &mut State,
    ) -> Result<()> {
        let b = &certificate.body;
        witness.verify(
            b,
            self.admission
                .policy
                .as_ref()
                .ok_or(Error::UnqualifiedPhysical)?,
            self.admission_class()?,
        )?;
        if self.penalties.revoked(b.lineage) {
            return Err(Error::WrongGeneration);
        }
        let old = self
            .continuity
            .as_ref()
            .ok_or(Error::UnqualifiedPhysical)?
            .members
            .iter()
            .find(|m| m.lineage == b.lineage)
            .ok_or(Error::InvalidLineage)?;
        let old_control = self
            .membership
            .controls
            .get(&old.node)
            .ok_or(Error::UnknownSigner)?;
        let generation = old.generation.checked_add(1).ok_or(Error::Overflow)?;
        if next.membership.controls.contains_key(&b.new_node)
            || next.membership.retired.values().any(|r| {
                r.node == b.new_node
                    || r.hardware == b.new_hardware
                    || r.voting_key == b.new_voting_key
            })
            || old_control.generation != old.generation
        {
            return Err(Error::Duplicate);
        }
        let updated = next
            .continuity
            .as_ref()
            .ok_or(Error::UnqualifiedPhysical)?
            .members
            .iter()
            .find(|m| m.lineage == b.lineage)
            .ok_or(Error::InvalidLineage)?;
        if updated.node != b.new_node
            || updated.generation != generation
            || updated.voting_key != b.new_voting_key
        {
            return Err(Error::WrongGeneration);
        }
        let mut bytes = certificate.encode();
        bytes.extend(witness.encode()?);
        let commitment = domain_hash(b"MUTINY-BUILD8-RECOVERY-MATERIAL-RECORD-V1", &bytes);
        next.membership.retired.insert(
            (old.node, old.generation),
            crate::membership::RetiredGeneration {
                node: old.node,
                generation: old.generation,
                hardware: old.hardware,
                voting_key: old.voting_key,
                attestation: old.attestation,
                height: b.anchor.height,
                reason: 3,
                evidence: commitment,
            },
        );
        let mut control = old_control.clone();
        control.node = b.new_node;
        control.generation = generation;
        control.node_authentication = witness.node_authentication;
        control.sequence = control.sequence.checked_add(1).ok_or(Error::Overflow)?;
        control.hardware_since_height = b.anchor.height;
        control.exit_boundary = None;
        control.admission_boundary = None;
        next.membership.controls.remove(&old.node);
        next.membership.controls.insert(b.new_node, control);
        let approved = ApprovedProfile::decode(&witness.approved_profile)?;
        next.admission.profiles.insert(b.attestation, approved);
        if !next
            .continuity
            .as_ref()
            .unwrap()
            .members
            .iter()
            .any(|m| m.attestation == old.attestation)
        {
            next.admission.profiles.remove(&old.attestation);
        }
        next.accounting.freshness.remove(&old.node);
        next.accounting.freshness.insert(
            b.new_node,
            crate::freshness::FreshnessRecord {
                node: b.new_node,
                generation,
                key: b.new_voting_key,
                committed_height: b.anchor.height,
                evidence_commitment: commitment,
            },
        );
        if let Some(bits) = next.accounting.slots.bits.remove(&old.node) {
            next.accounting.slots.bits.insert(b.new_node, bits);
        }
        next.records().map_err(|_| Error::WrongAnchor)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        membership::NodeControl,
        provenance::AdmissionClass,
        recovery::{ContinuityState, Member, PhysicalAdmissionVerifier},
        reputation::History,
    };
    // TEST-VALUE simulator support (public seeds only), shared with the integration tests; declared
    // once at file scope in lib.rs (a #[path] in this inline module would not resolve on Linux).
    use crate::software_tpm;
    /// SOFTWARE TEST-VALUE fixture (deterministic simulator, TEST-VALUE marked), regenerated and
    /// drift-checked by consensus/tests/software_admission_fixtures.rs. SIMULATED != PHYSICAL.
    #[test]
    fn native_replacement_material_restores_controls_profile_freshness_and_lineage_history() {
        recovery_fixture_checks(
            include_str!("../../qualification/RECOVERY-MATERIAL-TEST-VALUE-FIXTURE-V1.json"),
            true,
        );
    }
    /// PHYSICAL-ONLY: the same checks over real replacement evidence supplied at RUNTIME by path:
    /// BUILD8_PHYSICAL_RECOVERY_MATERIAL_FIXTURE=<path> cargo test --offline --locked --lib -- --ignored physical_recovery
    #[test]
    #[ignore = "requires physical recovery-material evidence supplied by env path (runtime)"]
    fn physical_recovery_material_fixture_from_runtime_path() {
        let var = "BUILD8_PHYSICAL_RECOVERY_MATERIAL_FIXTURE";
        let path = std::env::var(var).unwrap_or_else(|_| {
            panic!("PHYSICAL TPM EVIDENCE MISSING: {var} is not set; this test must not pass without real evidence")
        });
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{var}={path}: {e}"));
        recovery_fixture_checks(&text, false);
    }
    fn recovery_fixture_checks(text: &str, test_value: bool) {
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["TEST_VALUE"] == true, test_value, "evidence class label");
        assert_eq!(v["recovery_applied"], false);
        let raw = |name: &str| hex::decode(v[name].as_str().unwrap()).unwrap();
        let certificate = Certificate::decode(&raw("certificate")).unwrap();
        let b = &certificate.body;
        let material = RecoveryMaterial::decode(&raw("material")).unwrap();
        let policy = AdmissionPolicy::decode(&raw("policy")).unwrap();
        material.verify(b, &policy, AdmissionClass::LegacyTest).unwrap();
        let profile = ApprovedProfile::decode(&material.approved_profile)
            .unwrap()
            .verify(&policy, AdmissionClass::LegacyTest)
            .unwrap();
        assert_eq!(profile.is_test_value(), test_value, "TEST-VALUE marker vs evidence class");
        assert_eq!(RecoveryMaterial::challenge(b).as_slice(), raw("challenge"));
        let oldnode = [9; 32];
        let owner = ed25519_dalek::SigningKey::from_bytes(&[61; 32])
            .verifying_key()
            .to_bytes();
        let old = Member {
            lineage: b.lineage,
            node: oldnode,
            hardware: [10; 32],
            generation: 0,
            voting_key: p256::ecdsa::SigningKey::from_bytes((&[9; 32]).into())
                .unwrap()
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            attestation: [11; 32],
            history: History {
                p: 3,
                a: 4,
                s: 2,
                h: 3,
                penalties: 7.into(),
                bonds: vec![],
            },
            physical: true,
            eligible: true,
            genesis_member: true,
        };
        // The lost predecessor and recovery authority are explicit fixture facts. The replacement
        // evidence is the TEST-VALUE simulator, or real evidence in the ignored runtime test.
        let mut before = State {
            continuity: Some(
                ContinuityState::bootstrap(
                    b.genesis,
                    b.fingerprint,
                    b.anchor.clone(),
                    raw("recovery_authority").try_into().unwrap(),
                    vec![old.clone()],
                )
                .unwrap(),
            ),
            admission: crate::admission::AdmissionBook {
                policy: Some(policy.clone()),
                profiles: Default::default(),
            },
            ..Default::default()
        };
        before.membership.controls.insert(
            oldnode,
            NodeControl {
                node: oldnode,
                generation: 0,
                owner,
                node_authentication: owner,
                sequence: 7,
                exit_boundary: None,
                admitted_height: 0,
                admission_boundary: None,
                hardware_since_height: 0,
            },
        );
        before.accounting.slots.last_height = 6;
        before.accounting.slots.bits.insert(oldnode, 63);
        struct Native<'a>(&'a RecoveryMaterial, &'a AdmissionPolicy);
        impl PhysicalAdmissionVerifier for Native<'_> {
            fn verify_replacement(&self, b: &Recovery) -> Result<()> {
                self.0.verify(b, self.1, AdmissionClass::LegacyTest)
            }
        }
        let mut next = before.clone();
        next.continuity
            .as_mut()
            .unwrap()
            .apply_recovery(
                &certificate,
                &Native(&material, &policy),
                &[(b.lineage, 0)],
                false,
            )
            .unwrap();
        before
            .carry_recovery_material(&certificate, &material, &mut next)
            .unwrap();
        let member = &next.continuity.as_ref().unwrap().members[0];
        assert_eq!(member.node, b.new_node);
        assert_eq!(member.generation, 1);
        assert_eq!(
            (
                member.history.p,
                member.history.a,
                member.history.s,
                member.history.h
            ),
            (3, 4, 2, 0)
        );
        assert_eq!(member.history.penalties, 7.into());
        let control = &next.membership.controls[&b.new_node];
        assert_eq!(control.owner, owner);
        assert_eq!(control.sequence, 8);
        assert_eq!(control.node_authentication, material.node_authentication);
        assert_eq!(control.hardware_since_height, 6);
        assert!(!next.membership.controls.contains_key(&oldnode));
        assert_eq!(next.membership.retired[&(oldnode, 0)].reason, 3);
        assert_eq!(next.accounting.slots.bits[&b.new_node], 63);
        assert!(!next.accounting.slots.bits.contains_key(&oldnode));
        let fresh = &next.accounting.freshness[&b.new_node];
        assert!(fresh.eligible(b.new_node, 1, b.new_voting_key, 7));
        assert!(fresh.eligible(b.new_node, 1, b.new_voting_key, 66));
        assert!(!fresh.eligible(b.new_node, 1, b.new_voting_key, 67));
        next.admission
            .physical_context(next.continuity.as_ref().unwrap(), AdmissionClass::LegacyTest)
            .unwrap();
        let records = next.records().unwrap();
        let restored = State::from_records(&records, next.root().unwrap()).unwrap();
        assert_eq!(restored.records().unwrap(), records);
        assert_eq!(restored.membership, next.membership);
        for field in 0..4 {
            let mut bad = material.clone();
            match field {
                0 => bad.quote[10] ^= 1,
                1 => bad.node_authentication[0] ^= 1,
                2 => bad.node_signature[0] ^= 1,
                _ => bad.possession_signature[0] ^= 1,
            }
            assert!(bad.verify(b, &policy, AdmissionClass::LegacyTest).is_err());
        }
        let mut wrong = b.clone();
        wrong.anchor.height += 1;
        assert!(material.verify(&wrong, &policy, AdmissionClass::LegacyTest).is_err());
        assert!(
            next.continuity
                .as_mut()
                .unwrap()
                .apply_recovery(
                    &certificate,
                    &Native(&material, &policy),
                    &[(b.lineage, 0)],
                    false
                )
                .is_err()
        );
        assert_eq!(before.membership.controls[&oldnode].sequence, 7);
    }
    /// Pre-recovery state for a certificate (synthetic lost predecessor). `production` adds the
    /// committed Genesis parameters record whose rule manifest commits to the policy roots.
    fn recovery_parent(certificate: &Certificate, policy: &AdmissionPolicy, authority: [u8; 32], production: bool) -> State {
        let b = &certificate.body;
        let owner = ed25519_dalek::SigningKey::from_bytes(&[61; 32]).verifying_key().to_bytes();
        let old = Member {
            lineage: b.lineage,
            node: [9; 32],
            hardware: [10; 32],
            generation: 0,
            voting_key: p256::ecdsa::SigningKey::from_bytes((&[9; 32]).into())
                .unwrap()
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            attestation: [11; 32],
            history: History::default(),
            physical: true,
            eligible: true,
            genesis_member: true,
        };
        let mut before = State {
            continuity: Some(
                ContinuityState::bootstrap(b.genesis, b.fingerprint, b.anchor.clone(), authority, vec![old])
                    .unwrap(),
            ),
            admission: crate::admission::AdmissionBook {
                policy: Some(policy.clone()),
                profiles: Default::default(),
            },
            ..Default::default()
        };
        before.membership.controls.insert(
            [9; 32],
            NodeControl {
                node: [9; 32],
                generation: 0,
                owner,
                node_authentication: owner,
                sequence: 7,
                exit_boundary: None,
                admitted_height: 0,
                admission_boundary: None,
                hardware_since_height: 0,
            },
        );
        before.accounting.slots.last_height = b.anchor.height;
        if production {
            before.protocol_records.insert(
                crate::genesis_inputs::parameters_key(),
                software_tpm::production_parameters(&policy.endorsement_roots),
            );
            assert_eq!(before.admission_class().unwrap(), AdmissionClass::Production);
        }
        before
    }
    /// T5 (V1 RECOVERY) and T15: in the Production class replacement material carrying a marked,
    /// marker-stripped, relabeled or provenance-inconsistent software profile is rejected by
    /// `RecoveryMaterial::verify` and by `carry_recovery_material` (the path every recovery accept
    /// and restart replay takes). The registry recovery is APPLIED FIRST (accept-all registry
    /// verifier), so the call reaches `carry_recovery_material`'s own admission rule instead of
    /// failing on a registry that was never advanced; the refusal leaves the pre-recovery state and
    /// the staged candidate unchanged. Positive controls through the same construction: the marked
    /// material is carried in the Legacy/Test class and the documented-limit (T14) material in the
    /// Production class. The committed TEST-VALUE fixture material is refused as well.
    #[test]
    fn production_class_recovery_rejects_marked_stripped_and_inconsistent_software_material() {
        struct AcceptAll;
        impl PhysicalAdmissionVerifier for AcceptAll {
            fn verify_replacement(&self, _: &Recovery) -> Result<()> {
                Ok(())
            }
        }
        let root = software_tpm::test_value_endorsement_root();
        let authority = software_tpm::recovery_authority().verifying_key().to_bytes();
        // (pre-recovery state, candidate whose registry recovery is already applied)
        let staged = |certificate: &Certificate, policy: &AdmissionPolicy, production: bool| {
            let before = recovery_parent(certificate, policy, authority, production);
            let mut next = before.clone();
            next.continuity
                .as_mut()
                .unwrap()
                .apply_recovery(certificate, &AcceptAll, &[(certificate.body.lineage, 0)], false)
                .unwrap();
            (before, next)
        };
        let mut cases: Vec<(&str, Certificate, RecoveryMaterial, AdmissionPolicy)> =
            software_tpm::production_negative_variants(root)
                .into_iter()
                .map(|(name, tpm, _)| {
                    let (c, m, p) = software_tpm::recovery_material(&tpm);
                    (name, c, m, p)
                })
                .collect();
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/RECOVERY-MATERIAL-TEST-VALUE-FIXTURE-V1.json"
        ))
        .unwrap();
        let raw = |name: &str| hex::decode(v[name].as_str().unwrap()).unwrap();
        cases.push((
            "committed TEST-VALUE fixture",
            Certificate::decode(&raw("certificate")).unwrap(),
            RecoveryMaterial::decode(&raw("material")).unwrap(),
            AdmissionPolicy::decode(&raw("policy")).unwrap(),
        ));
        for (name, certificate, material, policy) in cases {
            let b = &certificate.body;
            assert!(matches!(material.verify(b, &policy, AdmissionClass::Production), Err(e) if e != crate::Error::AdmissionAuthorityEnded), "{name}");
            let (before, mut next) = staged(&certificate, &policy, true);
            let (snapshot, staged_next) = (before.clone(), next.clone());
            assert!(
                matches!(before.carry_recovery_material(&certificate, &material, &mut next), Err(e) if e != crate::Error::AdmissionAuthorityEnded),
                "{name}: carried in Production"
            );
            assert_eq!(before, snapshot, "{name}: pre-recovery state changed");
            assert_eq!(next, staged_next, "{name}: replacement material installed");
        }
        // Positive controls: the refusals above do not come from a broken setup.
        let (certificate, material, policy) = software_tpm::recovery_material(&software_tpm::TestTpm::new());
        let (before, mut next) = staged(&certificate, &policy, false);
        before.carry_recovery_material(&certificate, &material, &mut next).unwrap();
        let limit = software_tpm::TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(root));
        let (certificate, material, policy) = software_tpm::recovery_material(&limit);
        // Order A8 (candidate 3): the limit material is refused after sealing in the Production class,
        // exactly by the post-sealing scope rule, and still carried in the Legacy/Test class.
        let (before, mut next) = staged(&certificate, &policy, true);
        let untouched = next.clone();
        assert_eq!(
            before.carry_recovery_material(&certificate, &material, &mut next).unwrap_err(),
            crate::Error::AdmissionAuthorityEnded
        );
        assert_eq!(next, untouched);
        let (before, mut next) = staged(&certificate, &policy, false);
        before.carry_recovery_material(&certificate, &material, &mut next).unwrap();
    }
    /// Order A8 (candidate 3; formerly the T14 acceptance `authority_attestation_is_the_anchor_
    /// consistent_software_provenance_recovers_production_class`): authority-signed replacement
    /// material ALONE no longer admits hardware after sealing. In the Production class the material is
    /// refused with exactly `AdmissionAuthorityEnded`, and so is the registry recovery whose admission
    /// verifier checks it (state unchanged); the Legacy/Test class still runs the whole flow.
    #[test]
    fn admission_authority_alone_cannot_supply_recovery_material_after_sealing_production_class() {
        let root = software_tpm::test_value_endorsement_root();
        let tpm = software_tpm::TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(root));
        let (certificate, material, policy) = software_tpm::recovery_material(&tpm);
        let b = &certificate.body;
        assert_eq!(
            material.verify(b, &policy, AdmissionClass::Production),
            Err(crate::Error::AdmissionAuthorityEnded)
        );
        let authority = software_tpm::recovery_authority().verifying_key().to_bytes();
        struct Native<'a>(&'a RecoveryMaterial, &'a AdmissionPolicy, AdmissionClass);
        impl PhysicalAdmissionVerifier for Native<'_> {
            fn verify_replacement(&self, b: &Recovery) -> Result<()> {
                self.0.verify(b, self.1, self.2)
            }
        }
        let before = recovery_parent(&certificate, &policy, authority, true);
        let mut next = before.clone();
        assert_eq!(
            next.continuity.as_mut().unwrap().apply_recovery(
                &certificate,
                &Native(&material, &policy, AdmissionClass::Production),
                &[(b.lineage, 0)],
                false
            ),
            Err(crate::Error::AdmissionAuthorityEnded)
        );
        assert_eq!(next, before);
        let before = recovery_parent(&certificate, &policy, authority, false);
        let mut next = before.clone();
        next.continuity
            .as_mut()
            .unwrap()
            .apply_recovery(&certificate, &Native(&material, &policy, AdmissionClass::LegacyTest), &[(b.lineage, 0)], false)
            .unwrap();
        before.carry_recovery_material(&certificate, &material, &mut next).unwrap();
        next.admission
            .physical_context(next.continuity.as_ref().unwrap(), AdmissionClass::LegacyTest)
            .unwrap();
    }
}
