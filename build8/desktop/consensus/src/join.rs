//! Ordinary supervised physical admission, certified by the existing voter set.
use crate::{
    Error, Hash, NETWORK_ID, Result, admission::ApprovedProfile, anchors::FinalizedAnchor,
    domain_hash, execution::State, freshness::FreshnessRecord, membership::NodeControl,
    recovery::Member,
};
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
fn hash(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("hash"))
}
pub fn node_id(genesis: Hash, node_authentication: Hash) -> Hash {
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .u8(1)
        .unwrap()
        .u32(NETWORK_ID)
        .unwrap()
        .bytes(&genesis)
        .unwrap()
        .bytes(&node_authentication)
        .unwrap();
    domain_hash(b"MUTINY-BUILD8-NODE-ID-V1", &e.into_writer())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContinuityJoin {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub height: u64,
    pub parent_anchor: Hash,
    pub node: Hash,
    pub owner: Hash,
    pub node_authentication: Hash,
    pub approved_profile: Vec<u8>,
    pub evidence: Vec<u8>,
    pub owner_signature: [u8; 64],
    pub node_signature: [u8; 64],
    pub possession_signature: [u8; 64],
}
impl ContinuityJoin {
    fn bytes(&self, mode: u8) -> Result<Vec<u8>> {
        if self.approved_profile.len() > 16384 || self.evidence.len() > 16384 {
            return Err(Error::Oversize);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(match mode {
            0 => 11,
            1 => 12,
            _ => 15,
        })
        .unwrap()
        .u8(1)
        .unwrap()
        .u8(15)
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
        .bytes(&self.owner)
        .unwrap()
        .bytes(&self.node_authentication)
        .unwrap()
        .bytes(&self.approved_profile)
        .unwrap();
        if mode > 0 {
            e.bytes(&self.evidence).unwrap();
        }
        if mode > 1 {
            e.bytes(&self.owner_signature)
                .unwrap()
                .bytes(&self.node_signature)
                .unwrap()
                .bytes(&self.possession_signature)
                .unwrap();
        }
        let bytes = e.into_writer();
        if bytes.len() > 16384 {
            return Err(Error::Oversize);
        }
        Ok(bytes)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.bytes(2)
    }
    pub fn challenge(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-JOIN-ATTESTATION-V1",
            &self.bytes(0)?,
        ))
    }
    pub fn owner_digest(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-JOIN-AUTHORIZATION-V1",
            &self.bytes(1)?,
        ))
    }
    pub fn node_digest(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-JOIN-NODE-AUTH-V1",
            &self.bytes(1)?,
        ))
    }
    pub fn possession_digest(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-JOIN-POSSESSION-V1",
            &self.bytes(1)?,
        ))
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 16384)?;
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("join");
            if d.array()? != Some(15) || d.u8()? != 1 || d.u8()? != 15 || d.u32()? != NETWORK_ID {
                return Err(bad());
            }
            Ok(Self {
                genesis: hash(&mut d)?,
                fingerprint: hash(&mut d)?,
                height: d.u64()?,
                parent_anchor: hash(&mut d)?,
                node: hash(&mut d)?,
                owner: hash(&mut d)?,
                node_authentication: hash(&mut d)?,
                approved_profile: d.bytes()?.to_vec(),
                evidence: d.bytes()?.to_vec(),
                owner_signature: d.bytes()?.try_into().map_err(|_| bad())?,
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
    /// `class` is the admission class of the parent state (`State::admission_class`).
    pub fn validate(
        &self,
        parent: &FinalizedAnchor,
        policy: &crate::admission::AdmissionPolicy,
        class: crate::provenance::AdmissionClass,
    ) -> Result<crate::tpm::TpmProfile> {
        parent.validate_context(self.genesis, self.fingerprint)?;
        if self.height == 0
            || parent.height.checked_add(1) != Some(self.height)
            || self.parent_anchor != parent.id()
            || self.node != node_id(self.genesis, self.node_authentication)
        {
            return Err(Error::WrongAnchor);
        }
        if policy.genesis != self.genesis || policy.fingerprint != self.fingerprint {
            return Err(Error::WrongAnchor);
        }
        let profile = ApprovedProfile::decode(&self.approved_profile)?.verify(policy, class)?;
        profile.verify_quote(self.challenge()?, &self.evidence)?;
        VerifyingKey::from_bytes(&self.owner)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(
                &self.owner_digest()?,
                &Signature::from_bytes(&self.owner_signature),
            )
            .map_err(|_| Error::BadSignature)?;
        VerifyingKey::from_bytes(&self.node_authentication)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(
                &self.node_digest()?,
                &Signature::from_bytes(&self.node_signature),
            )
            .map_err(|_| Error::BadSignature)?;
        let sig = p256::ecdsa::Signature::from_slice(&self.possession_signature)
            .map_err(|_| Error::BadSignature)?;
        if sig.normalize_s().is_some() {
            return Err(Error::NonCanonical);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&crate::tpm::public_key(
            &profile.voting_public,
            false,
        )?)
        .map_err(|_| Error::BadSignature)?
        .verify_prehash(&self.possession_digest()?, &sig)
        .map_err(|_| Error::BadSignature)?;
        // Order A8: after sealing the ceremony-scoped admission authority admits no hardware
        // (Production class); checked after the complete verification, so malformed material fails first.
        crate::admission_scope::require_post_sealing_admission(class)?;
        Ok(profile)
    }
}
impl State {
    /// Parent policy authorizes all joins. A staged member is ineligible until
    /// the closing boundary transition, and receives no provisional reputation.
    pub(crate) fn apply_joins(
        &self,
        parent: &FinalizedAnchor,
        operations: &[Vec<u8>],
        next: &mut State,
    ) -> Result<()> {
        // Admission class from the parent's committed Genesis data, never from an operation.
        let class = self.admission_class()?;
        for raw in operations {
            if crate::blocks::operation_kind(raw)? != 15 {
                continue;
            }
            let join = ContinuityJoin::decode(raw)?;
            let policy = self
                .admission
                .policy
                .as_ref()
                .ok_or(Error::UnqualifiedPhysical)?;
            let profile = join.validate(parent, policy, class)?;
            let key = crate::tpm::public_key(&profile.voting_public, false)?;
            let registry = next.continuity.as_mut().ok_or(Error::UnqualifiedPhysical)?;
            if registry.members.iter().any(|m| {
                m.node == join.node
                    || m.lineage == join.node
                    || m.hardware == profile.hardware
                    || m.voting_key == key
            }) || next.membership.controls.contains_key(&join.node)
                || next.membership.retired.values().any(|r| {
                    r.node == join.node || r.hardware == profile.hardware || r.voting_key == key
                })
            {
                return Err(Error::Duplicate);
            }
            if registry.members.len() >= crate::participation::MAX_ACKS {
                return Err(Error::Capacity);
            }
            let commitment = profile.commitment()?;
            let approved = ApprovedProfile::decode(&join.approved_profile)?;
            if next.admission.profiles.contains_key(&commitment) {
                return Err(Error::Duplicate);
            }
            next.admission.profiles.insert(commitment, approved);
            next.membership.controls.insert(
                join.node,
                NodeControl {
                    node: join.node,
                    generation: 0,
                    owner: join.owner,
                    node_authentication: join.node_authentication,
                    sequence: 0,
                    exit_boundary: None,
                    admitted_height: join.height,
                    admission_boundary: Some(
                        join.height.checked_add(59).ok_or(Error::Overflow)? / 60 * 60,
                    ),
                    hardware_since_height: join.height,
                },
            );
            registry.members.push(Member {
                lineage: join.node,
                node: join.node,
                hardware: profile.hardware,
                generation: 0,
                voting_key: key,
                attestation: commitment,
                history: Default::default(),
                physical: true,
                eligible: false,
                genesis_member: false,
            });
            next.accounting.freshness.insert(
                join.node,
                FreshnessRecord {
                    node: join.node,
                    generation: 0,
                    key,
                    committed_height: join.height,
                    evidence_commitment: domain_hash(
                        b"MUTINY-BUILD8-ATTESTATION-EVIDENCE-V1",
                        &join.evidence,
                    ),
                },
            );
        }
        next.admission.records(class)?;
        next.membership.records()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admission::AdmissionPolicy,
        recovery::{Anchor, ContinuityState},
    };
    use crate::provenance::AdmissionClass;
    use std::collections::BTreeMap;
    // TEST-VALUE simulator support (public seeds only), shared with the integration tests; declared
    // once at file scope in lib.rs (a #[path] in this inline module would not resolve on Linux).
    use crate::software_tpm;
    fn raw(v: &serde_json::Value, k: &str) -> Vec<u8> {
        hex::decode(v[k].as_str().unwrap()).unwrap()
    }
    /// PHYSICAL evidence is never compiled in or tracked: the ignored test reads it from the path
    /// in `var` at RUNTIME and fails loudly without it.
    fn physical_fixture(var: &str) -> String {
        let path = std::env::var(var).unwrap_or_else(|_| {
            panic!("PHYSICAL TPM EVIDENCE MISSING: {var} is not set; this test must not pass without real evidence")
        });
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{var}={path}: {e}"))
    }
    /// SOFTWARE TEST-VALUE fixture (deterministic simulator, TEST-VALUE marked), regenerated and
    /// drift-checked by consensus/tests/software_admission_fixtures.rs. SIMULATED != PHYSICAL.
    #[test]
    fn test_value_join_quote_possession_staged_activation_and_parent_accounting() {
        join_fixture_checks(
            include_str!("../../qualification/JOIN-TEST-VALUE-FIXTURE-V1.json"),
            true,
        );
    }
    /// PHYSICAL-ONLY: the same checks over real JOIN evidence supplied at RUNTIME by path:
    /// BUILD8_PHYSICAL_JOIN_FIXTURE=<path> cargo test --offline --locked --lib -- --ignored physical_join
    #[test]
    #[ignore = "requires physical JOIN evidence supplied by env path (runtime)"]
    fn physical_join_fixture_from_runtime_path() {
        join_fixture_checks(&physical_fixture("BUILD8_PHYSICAL_JOIN_FIXTURE"), false);
    }
    fn join_fixture_checks(text: &str, test_value: bool) {
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["TEST_VALUE"] == true, test_value, "evidence class label");
        let parent = FinalizedAnchor::decode(&raw(&v, "parent")).unwrap();
        let policy = AdmissionPolicy::decode(&raw(&v, "policy")).unwrap();
        let join = ContinuityJoin::decode(&raw(&v, "operation")).unwrap();
        assert_eq!(join.encode().unwrap(), raw(&v, "operation"));
        assert_eq!(hex::encode(join.challenge().unwrap()), v["challenge"]);
        let profile = join.validate(&parent, &policy, AdmissionClass::LegacyTest).unwrap();
        assert_eq!(profile.is_test_value(), test_value, "TEST-VALUE marker vs evidence class");
        // The empty old set is a transition unit fixture only. It cannot certify
        // a block; ordinary integrated finality still requires old-set quorum.
        let mut prior = State::default();
        prior.admission.policy = Some(policy.clone());
        prior.accounting.slots.last_height = 58;
        prior.continuity = Some(
            ContinuityState::bootstrap(
                parent.genesis,
                parent.fingerprint,
                Anchor {
                    height: 58,
                    tip: parent.block,
                    state_root: [0; 32],
                    registry_root: [0; 32],
                },
                policy.authority,
                vec![],
            )
            .unwrap(),
        );
        let prior_root = prior.root().unwrap();
        let mut pending = prior.clone();
        pending.accounting.slots.last_height = 59;
        prior
            .apply_joins(&parent, &[join.encode().unwrap()], &mut pending)
            .unwrap();
        assert_eq!(prior.root().unwrap(), prior_root);
        assert!(!pending.continuity.as_ref().unwrap().members[0].eligible);
        assert!(!pending.continuity.as_ref().unwrap().members[0].genesis_member);
        assert!(pending.continuity.as_ref().unwrap().weights().unwrap()[0].is_zero());
        assert_eq!(
            pending.membership.controls[&join.node].admission_boundary,
            Some(60)
        );
        assert_ne!(pending.root().unwrap(), prior_root);
        let records = pending.records().unwrap();
        let pending = State::from_records(&records, pending.root().unwrap()).unwrap();
        let boundary = FinalizedAnchor {
            height: 59,
            block: [34; 32],
            ..parent.clone()
        };
        let mut registry = pending.continuity.clone().unwrap();
        registry.anchor.height = 59;
        registry.anchor.tip = boundary.block;
        let body = crate::blocks::BlockBody {
            height: 60,
            reward_owner: [42; 32],
            fees: 0,
            transactions: vec![],
            operations: vec![],
        };
        let (accounting, mut after) = pending
            .accounting
            .apply(
                &boundary,
                &body,
                &registry,
                &BTreeMap::new(),
                &crate::tpm::PinnedTpmVerifier {
                    profiles: BTreeMap::new(),
                },
            )
            .unwrap();
        let membership = pending
            .membership
            .apply_exits(&boundary, &[], &registry, &mut after)
            .unwrap();
        assert!(after.members[0].eligible);
        assert_eq!(after.members[0].history, Default::default());
        assert!(after.weights().unwrap()[0].is_zero());
        assert_eq!(membership.controls[&join.node].admission_boundary, None);
        let fresh = &accounting.freshness[&join.node];
        let key = crate::tpm::public_key(&profile.voting_public, false).unwrap();
        assert!(fresh.eligible(join.node, 0, key, 61));
        assert!(fresh.eligible(join.node, 0, key, 119));
        assert!(!fresh.eligible(join.node, 0, key, 120));
        let mut duplicate = pending.clone();
        assert!(
            prior
                .apply_joins(&parent, &[join.encode().unwrap()], &mut duplicate)
                .is_err()
        );
        for which in 0..9 {
            let mut wrong = join.clone();
            match which {
                0 => wrong.genesis[0] ^= 1,
                1 => wrong.fingerprint[0] ^= 1,
                2 => wrong.height += 1,
                3 => wrong.parent_anchor[0] ^= 1,
                4 => wrong.node[0] ^= 1,
                5 => wrong.evidence[7] ^= 1,
                6 => wrong.owner_signature[0] ^= 1,
                7 => wrong.node_signature[0] ^= 1,
                _ => wrong.possession_signature[0] ^= 1,
            };
            assert!(wrong.validate(&parent, &policy, AdmissionClass::LegacyTest).is_err());
        }
    }
    /// Parent state of the JOIN fixture context. `production` adds the committed Genesis
    /// parameters record whose rule manifest commits to the policy's endorsement-root set.
    fn join_parent(policy: &AdmissionPolicy, parent: &FinalizedAnchor, production: bool) -> State {
        let mut prior = State::default();
        prior.admission.policy = Some(policy.clone());
        prior.accounting.slots.last_height = 58;
        prior.continuity = Some(
            ContinuityState::bootstrap(
                parent.genesis,
                parent.fingerprint,
                Anchor {
                    height: 58,
                    tip: parent.block,
                    state_root: [0; 32],
                    registry_root: [0; 32],
                },
                policy.authority,
                vec![],
            )
            .unwrap(),
        );
        if production {
            prior.protocol_records.insert(
                crate::genesis_inputs::parameters_key(),
                software_tpm::production_parameters(&policy.endorsement_roots),
            );
        }
        prior
    }
    /// T3 (V1 JOIN) and T15: in the Production class a marked, marker-stripped, relabeled or
    /// provenance-inconsistent software profile is rejected by `ContinuityJoin::validate` and by
    /// `apply_joins`, each case authority-signed; the parent state and the candidate are unchanged
    /// (no Member, control, profile or freshness record). The committed TEST-VALUE fixture itself
    /// is rejected in the Production class and still accepted in the Legacy/Test class.
    #[test]
    fn production_class_join_rejects_marked_stripped_and_inconsistent_software_profiles() {
        let root = software_tpm::test_value_endorsement_root();
        for (name, tpm, _) in software_tpm::production_negative_variants(root) {
            let (parent, policy, join) = software_tpm::join_operation(&tpm);
            let prior = join_parent(&policy, &parent, true);
            assert_eq!(prior.admission_class().unwrap(), AdmissionClass::Production);
            assert!(matches!(join.validate(&parent, &policy, AdmissionClass::Production), Err(e) if e != crate::Error::AdmissionAuthorityEnded), "{name}");
            let before = prior.clone();
            let mut pending = prior.clone();
            pending.accounting.slots.last_height = 59;
            let untouched = pending.clone();
            assert!(matches!(prior.apply_joins(&parent, &[join.encode().unwrap()], &mut pending), Err(e) if e != crate::Error::AdmissionAuthorityEnded), "{name}");
            assert_eq!(prior, before, "{name}: parent state changed");
            assert_eq!(pending, untouched, "{name}: candidate gained admission state");
        }
        // T15: the committed TEST-VALUE fixture operation itself is refused in the Production class.
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/JOIN-TEST-VALUE-FIXTURE-V1.json"
        ))
        .unwrap();
        let fixture_parent = FinalizedAnchor::decode(&raw(&v, "parent")).unwrap();
        let fixture_policy = AdmissionPolicy::decode(&raw(&v, "policy")).unwrap();
        let prior = join_parent(&fixture_policy, &fixture_parent, true);
        let mut pending = prior.clone();
        pending.accounting.slots.last_height = 59;
        assert!(prior.apply_joins(&fixture_parent, &[raw(&v, "operation")], &mut pending).is_err());
        // Legacy/Test class (no committed trust-root set): unchanged behaviour.
        let (parent, policy, join) = software_tpm::join_operation(&software_tpm::TestTpm::new());
        let prior = join_parent(&policy, &parent, false);
        assert_eq!(prior.admission_class().unwrap(), AdmissionClass::LegacyTest);
        let mut pending = prior.clone();
        pending.accounting.slots.last_height = 59;
        prior.apply_joins(&parent, &[join.encode().unwrap()], &mut pending).unwrap();
        assert_eq!(pending.continuity.as_ref().unwrap().members.len(), 1);
    }
    /// Order A8 (candidate 3; formerly the T14 acceptance `authority_attestation_is_the_anchor_
    /// consistent_software_provenance_joins_production_class`): the admission authority's signature
    /// ALONE no longer admits hardware after sealing. The same authority-signed software profile with a
    /// self-made consistent statement is refused in the Production class with exactly
    /// `AdmissionAuthorityEnded` by `validate` and by `apply_joins` (parent and candidate unchanged);
    /// the Legacy/Test class still stages it with zero weight (unchanged join semantics).
    #[test]
    fn admission_authority_alone_cannot_join_after_sealing_production_class() {
        let root = software_tpm::test_value_endorsement_root();
        let tpm = software_tpm::TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(root));
        assert!(!tpm.profile().is_test_value());
        let (parent, policy, join) = software_tpm::join_operation(&tpm);
        let prior = join_parent(&policy, &parent, true);
        assert_eq!(
            join.validate(&parent, &policy, AdmissionClass::Production).unwrap_err(),
            crate::Error::AdmissionAuthorityEnded
        );
        let before = prior.clone();
        let mut pending = prior.clone();
        pending.accounting.slots.last_height = 59;
        let untouched = pending.clone();
        assert_eq!(
            prior.apply_joins(&parent, &[join.encode().unwrap()], &mut pending).unwrap_err(),
            crate::Error::AdmissionAuthorityEnded
        );
        assert_eq!(prior, before);
        assert_eq!(pending, untouched);
        let prior = join_parent(&policy, &parent, false);
        let mut pending = prior.clone();
        pending.accounting.slots.last_height = 59;
        prior.apply_joins(&parent, &[join.encode().unwrap()], &mut pending).unwrap();
        // Staged, zero weight until the admission boundary (unchanged join semantics).
        let registry = pending.continuity.as_ref().unwrap();
        assert!(!registry.members[0].eligible);
        assert!(registry.weights().unwrap()[0].is_zero());
        pending.records().unwrap();
    }
}
