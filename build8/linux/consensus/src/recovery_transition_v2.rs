//! Pure prospective recovery preparation. A Prepared value authenticates the
//! replacement against one canonical parent, but does NOT establish durable
//! acceptance, exclude a concurrent finalized descendant or certify a block.
use crate::{
    Error, Hash, Result,
    anchors::FinalizedAnchor,
    execution::State,
    recovery_history_v2::{Book, Record},
    votes_v2::HeightAuthority,
};

/// Private staged components cannot be mistaken for a canonical State or used
/// to serve state proofs. The original parent state/root are never rewritten.
#[derive(Clone, Debug)]
pub struct Prepared {
    parent: FinalizedAnchor,
    root: Hash,
    record: Record,
    effective: State,
    history: Book,
    public_witness: Option<Vec<u8>>,
}
impl Prepared {
    pub(crate) fn components(&self) -> &State {
        &self.effective
    }
    pub fn verify(
        state: &State,
        parent: &FinalizedAnchor,
        root: Hash,
        record: Record,
        existing_valid_descendant: bool,
    ) -> Result<Self> {
        Self::verify_with_public_witness(state, parent, root, record,
            existing_valid_descendant, None)
    }
    /// The enclosing canonical store supplies the actual verified finalized
    /// parent's time under its existing snapshot/write transaction. This is not
    /// public caller time authority and never reads a wrapper or local clock.
    pub(crate) fn verify_with_public_witness(
        state: &State,
        parent: &FinalizedAnchor,
        root: Hash,
        record: Record,
        existing_valid_descendant: bool,
        evidence: Option<(&[u8], u64)>,
    ) -> Result<Self> {
        crate::endorsement_revocation_v1::check_components(state)?;
        if state.endorsement_revocations_v1.terminal_no_quorum() {
            // Finalized zero-weight A2 state is durable NoQuorum. Recovery is
            // not a bootstrap/emergency authority that can undo that decision.
            return Err(Error::NoQuorum);
        }
        let selected = crate::recovery_public_v3::selected(state)?;
        if selected && evidence.is_none() { return Err(Error::UnqualifiedPhysical); }
        if !selected && evidence.is_some() { return Err(Error::WrongOperation); }
        let history = state.recovery_history_v2.stage(
            record.clone(),
            state,
            parent,
            root,
            existing_valid_descendant,
        )?;
        let m = &record.material;
        let registry = state
            .continuity
            .as_ref()
            .ok_or(Error::UnknownSigner)?
            .stage_hybrid_recovery(m)?;
        let keys = state
            .continuity_keys_v2
            .stage_recovery(m, &record.policy, &state.wallets, state.admission_class()?)?;
        let controls = state.membership_v2.stage_recovery(m, &registry, &keys)?;
        let retained = record.witnesses.verify(
            parent,
            root,
            m.old_node,
            m.old_hardware_generation,
            m.old_key_generation,
            m.commitment()?,
        )?;
        let retired = state
            .retired_continuity_v2
            .stage_retire(retained.terminal)?;
        let mut effective = state.clone();
        effective.continuity = Some(registry);
        effective.continuity_keys_v2 = keys;
        effective.membership_v2 = controls;
        effective.retired_continuity_v2 = retired;
        if let Some((witness, reference_time)) = evidence {
            let raw = state.protocol_records.get(&crate::genesis_v2::parameters_key())
                .ok_or(Error::UnqualifiedPhysical)?;
            let parameters = crate::genesis_v2::Parameters::decode(raw).map_err(|_| Error::Codec)?;
            // The unchanged material/parent/loss/owner/native verifiers above
            // authenticated this binding and exact retained lineage first.
            effective.endorsement_dependencies_v1 = state.endorsement_dependencies_v1
                .stage_authenticated(&m.binding, m.lineage, reference_time,
                    witness, &parameters)?;
            let excluded = effective.endorsement_revocations_v1.affected(&effective)?;
            if excluded.contains(&m.lineage) { return Err(Error::UnqualifiedPhysical); }
        }
        let node = m.binding.admission.node;
        if effective.accounting.slots.bits.contains_key(&node)
            || effective.accounting.freshness.contains_key(&node)
        {
            return Err(Error::Duplicate);
        }
        // Canonical participation is lineage history. A fresh NodeID cannot
        // erase already earned slots, while hardware-local H was reset above.
        if let Some(bits) = effective.accounting.slots.bits.remove(&m.old_node) {
            effective.accounting.slots.bits.insert(node, bits);
        }
        effective.accounting.freshness.remove(&m.old_node);
        let profile = crate::tpm::TpmProfile::decode(&m.binding.admission.profile)?;
        effective.accounting.freshness.insert(
            node,
            crate::freshness::FreshnessRecord {
                node,
                generation: m.binding.admission.hardware_generation,
                key: crate::tpm::public_key(&profile.voting_public, false)?,
                committed_height: parent.height,
                evidence_commitment: m.commitment()?,
            },
        );
        effective.accounting.records()?;
        let prepared = Self {
            parent: parent.clone(),
            root,
            record,
            effective,
            history,
            public_witness: evidence.map(|(witness, _)| witness.to_vec()),
        };
        prepared.authority()?;
        Ok(prepared)
    }
    pub fn parent(&self) -> &FinalizedAnchor {
        &self.parent
    }
    pub fn canonical_parent_root(&self) -> Hash {
        self.root
    }
    pub fn commitment(&self) -> Result<Hash> {
        self.record.material.commitment()
    }
    /// Native activation receipt only; this does not create a private verifier
    /// capability, install recovery or alter the parent certification set.
    pub(crate) fn activation_binding(&self) -> &crate::node_admission_v2::Binding {
        &self.record.material.binding
    }
    /// Public evidence for the pending recovery, not a canonical state proof.
    pub fn record(&self) -> &Record {
        &self.record
    }
    pub(crate) fn encoded_record(&self,
        authority: &crate::recovery_authority_v2::Authority) -> Result<Vec<u8>> {
        let signed = self.record.encode(authority)?;
        match &self.public_witness {
            Some(witness) => crate::recovery_public_v3::Carrier::new(signed,
                witness.clone(), authority)?.encode(authority),
            None => Ok(signed),
        }
    }
    /// Tentative history for the first resumed block. Inserting it into the
    /// unchanged parent State is invalid until that block's transition occurs.
    pub fn prospective_history(&self) -> &Book {
        &self.history
    }
    /// Pure first-resumed-height lifecycle. Does not execute licensed work,
    /// transactions or rewards, and cannot install state or establish finality.
    /// Historical vote authority remains the original canonical E-1 authority;
    /// recovery projection must never overwrite that evidence map.
    pub fn transition_components(
        &self,
        body: &crate::blocks::BlockBody,
        historical: &crate::evidence_history_v2::History,
    ) -> Result<crate::continuity_lifecycle_v2::Transition> {
        crate::continuity_lifecycle_v2::transition_in_parent(
            crate::parent_context_v2::ParentContext::recovery(self),
            body,
            historical,
        )
    }
    pub(crate) fn transition_components_at(
        &self,
        body: &crate::blocks::BlockBody,
        historical: &crate::evidence_history_v2::History,
        admission_reference_time: Option<u64>,
        timestamp: u64,
    ) -> Result<crate::continuity_lifecycle_v2::Transition> {
        crate::continuity_lifecycle_v2::transition_in_parent_at(
            crate::parent_context_v2::ParentContext::recovery(self),
            body,
            historical,
            admission_reference_time,
            Some(timestamp),
        )
    }
    /// Execute a proposed first resumed licensed block against the unchanged
    /// canonical transaction/work parent and separately verified recovery.
    /// The result is tentative until PoW, finality and durable acceptance pass.
    pub fn prepare_candidate(
        &self,
        canonical: &State,
        input: crate::execution::CandidatePreparation<'_>,
        historical: &crate::evidence_history_v2::History,
    ) -> crate::execution::Result<crate::execution::Execution> {
        canonical.prepare_candidate_with_recovery_v2(input, historical, Some(self))
    }
    pub fn execute_licensed(
        &self,
        canonical: &State,
        parent: &crate::execution::WorkParent,
        header: &crate::pow::WorkHeader,
        work: &crate::work_authority_v2::Authority,
        body: &crate::blocks::BlockBody,
        historical: &crate::evidence_history_v2::History,
    ) -> crate::execution::Result<crate::execution::Execution> {
        let (context, _, node) = canonical.work_context_v2(parent, &header.candidate)?;
        work.verify(header, &context, &node)?;
        let executed = self.prepare_candidate(
            canonical,
            crate::execution::CandidatePreparation {
                parent,
                candidate: &header.candidate,
                ticket_sequence: work.work.ticket_sequence,
                body,
            },
            historical,
        )?;
        if executed.root != header.candidate.state_root {
            return Err(Error::WrongAnchor.into());
        }
        Ok(executed)
    }
    /// Verification only. This cannot record acceptance, install a block or
    /// bypass the store's existing-finality/recovery conflict transaction.
    pub fn verify_envelope(
        &self,
        canonical: &State,
        parent: &crate::execution::WorkParent,
        envelope: &crate::block_envelope_v2::BlockEnvelope,
        historical: &crate::evidence_history_v2::History,
    ) -> std::result::Result<crate::execution::Execution, crate::votes::IngressError> {
        let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(canonical,self.parent.clone(),self.root)?;
        envelope.encode_with_capacity(&capacity)?;
        if !crate::pow::meets_target(&envelope.header.digest(), &envelope.header.candidate.target) {
            return Err(Error::InvalidCounter.into());
        }
        let executed = self.execute_licensed(
            canonical,
            parent,
            &envelope.header,
            &envelope.authority,
            &envelope.body,
            historical,
        )?;
        let authority = self.authority()?;
        let c = &envelope.header.candidate;
        let decision = crate::certificates::Decision {
            network: self.parent.network,
            genesis: self.parent.genesis,
            fingerprint: self.parent.fingerprint,
            purpose: 2,
            height: c.height,
            mining_epoch: crate::pow::mining_epoch(c.timestamp, parent.t0)?,
            continuity_period: c.height.checked_sub(1).ok_or(Error::InvalidCounter)? / 60,
            round: envelope.certificate.decision.round,
            step: 3,
            previous_finalized_anchor: self.parent.id(),
            parent: self.parent.block,
            block: envelope.header.block_hash(),
            state: executed.root,
            membership: authority.membership,
            reputation: authority.reputation,
            attestation: authority.attestation,
        };
        envelope
            .certificate
            .verify_quorum(&decision, &self.parent, &authority.voters)?;
        Ok(executed)
    }
    /// Prospective authority only. Runtime must first atomically accept the
    /// exact proof at this parent and exclude competing finality/recovery.
    pub fn authority(&self) -> Result<HeightAuthority> {
        HeightAuthority::from_validated_components(&self.effective, self.parent.clone())
            .map_err(|_| Error::UnqualifiedPhysical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn apply_components(
        state: &State,
        t: crate::continuity_lifecycle_v2::Transition,
        history: &Book,
    ) -> State {
        let mut next = state.clone();
        next.continuity = Some(t.registry);
        next.accounting = t.accounting;
        next.membership_v2 = t.membership;
        next.continuity_keys_v2 = t.keys;
        next.retired_continuity_v2 = t.retired;
        next.node_key_history_v2 = t.node_history;
        next.penalties_v2 = t.penalties;
        next.bonds_v2 = t.bonds;
        assert!(t.payouts.is_empty());
        assert_eq!(t.burned, 0);
        next.recovery_history_v2 = history.clone();
        next
    }
    #[test]
    fn recovered_hardware_can_earn_every_slot_without_rewriting_parent_authority() {
        use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/bootstrap-recovery-replacement-public-v2.json"
        ))
        .unwrap();
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let rows: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let original = State::from_records(&rows, root).unwrap();
        let record = Record::decode(
            &raw(&f["history_record"]),
            original.recovery_authority_v2.as_ref().unwrap(),
        )
        .unwrap();
        let mut parent = record.material.parent.clone();
        let prepared = Prepared::verify(&original, &parent, root, record.clone(), false).unwrap();
        let node = record.material.binding.admission.node;
        // Publicly known synthetic TPM scalar used to generate this fixture.
        let native = SigningKey::from_bytes((&[18u8; 32]).into()).unwrap();
        assert_eq!(
            native.verifying_key().to_encoded_point(true).as_bytes(),
            prepared.authority().unwrap().voters[&node].tpm_public
        );
        let mut state = original.clone();
        for height in 1..=60u64 {
            let mut ack = crate::participation::ParticipationAck {
                network: parent.network,
                genesis: parent.genesis,
                fingerprint: parent.fingerprint,
                node,
                height,
                parent: parent.id(),
                generation: 2,
                signature: [0; 64],
            };
            let sig: Signature = native.sign_prehash(&ack.signing_digest()).unwrap();
            ack.signature = sig.normalize_s().unwrap_or(sig).to_bytes().into();
            let body = crate::blocks::BlockBody {
                height,
                reward_owner: [0; 32],
                fees: 0,
                transactions: vec![],
                operations: vec![ack.encode()],
            };
            let t = if height == 1 {
                // An unaccepted recovery ACK has no authority in canonical
                // height zero, even though the replacement signature is valid.
                assert!(
                    crate::continuity_lifecycle_v2::transition(&original, &parent, root, &body)
                        .is_err()
                );
                prepared
                    .transition_components(&body, &Default::default())
                    .unwrap()
            } else {
                crate::continuity_lifecycle_v2::transition(
                    &state,
                    &parent,
                    state.root().unwrap(),
                    &body,
                )
                .unwrap()
            };
            state = apply_components(&state, t, prepared.prospective_history());
            state.root().unwrap();
            if height < 60 {
                assert_eq!(
                    state.accounting.slots.bits[&node].count_ones(),
                    height as u32
                );
            }
            // Synthetic independently supplied anchors: lifecycle qualification
            // only. No PoW/header/certificate is generated by this test.
            parent.height = height;
            parent.block = [height as u8; 32];
        }
        let member = &state.continuity.as_ref().unwrap().members[0];
        assert_eq!(
            (
                member.history.p,
                member.history.s,
                member.history.a,
                member.history.h
            ),
            (1, 1, 1, 1)
        );
        assert!(state.accounting.slots.bits.is_empty());
        assert_eq!(state.accounting.slots.period, 1);
        let fresh = &state.accounting.freshness[&node];
        assert!(fresh.eligible(node, 2, fresh.key, 60));
        assert!(!fresh.eligible(node, 2, fresh.key, 61));
        assert_eq!(original.root().unwrap(), root);
        assert!(
            HeightAuthority::from_state(&original, record.material.parent, root)
                .unwrap()
                .voters
                .contains_key(&record.material.old_node)
        );
    }
    #[test]
    fn recovery_projection_preserves_lineage_and_counts_first_resumed_hardware_slot() {
        // Internal projection test, not authentication of altered material.
        // The separate verify test exercises the actual signed public record.
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/bootstrap-recovery-replacement-public-v2.json"
        ))
        .unwrap();
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let rows: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let state = State::from_records(&rows, root).unwrap();
        let record = Record::decode(
            &raw(&f["history_record"]),
            state.recovery_authority_v2.as_ref().unwrap(),
        )
        .unwrap();
        let prepared =
            Prepared::verify(&state, &record.material.parent, root, record.clone(), false).unwrap();
        let mut registry = state.continuity.clone().unwrap();
        let old = &mut registry.members[0];
        old.history.p = 9;
        old.history.a = 12;
        old.history.s = 7;
        old.history.h = 6;
        old.history.penalties = 3.into();
        let old = old.clone();
        let replaced = registry.stage_hybrid_recovery(&record.material).unwrap();
        let mut expected = old.history.clone();
        expected.h = 0;
        assert_eq!(replaced.members[0].history, expected);
        assert_eq!(replaced.members[0].history.bonds, old.history.bonds);
        assert_eq!(replaced.members[0].lineage, old.lineage);
        assert_eq!(registry.members[0], old);
        for (parent_height, expected_h) in [(0, 1), (6, 1), (7, 0), (59, 0)] {
            let mut material = record.material.clone();
            material.parent.height = parent_height;
            let membership = state
                .membership_v2
                .stage_recovery(&material, &replaced, &prepared.effective.continuity_keys_v2)
                .unwrap();
            let mut previous = state.accounting.clone();
            previous.slots.last_height = 59;
            // Already-validated slot evidence is supplied to this accounting
            // projection test. All 60 lineage slots remain represented.
            previous
                .slots
                .bits
                .insert(material.binding.admission.node, (1u64 << 60) - 1);
            let mut after = replaced.clone();
            after.members[0].history.h = 1;
            let body = crate::blocks::BlockBody {
                height: 60,
                reward_owner: [0; 32],
                fees: 0,
                transactions: vec![],
                operations: vec![],
            };
            membership
                .adjust_hardware_history(60, &body, &previous, &replaced, &mut after)
                .unwrap();
            assert_eq!(after.members[0].history.h, expected_h);
        }
    }
    #[test]
    fn prospective_components_preserve_parent_and_reproduce_independent_state() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/bootstrap-recovery-replacement-public-v2.json"
        ))
        .unwrap();
        let post: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/bootstrap-recovery-history-state-public-v2.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic_only"], true);
        assert_eq!(post["constructed_state_fixture_not_execution"], true);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let rows: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let state = State::from_records(&rows, root).unwrap();
        let authority = state.recovery_authority_v2.as_ref().unwrap();
        let record = Record::decode(&raw(&f["history_record"]), authority).unwrap();
        let parent = record.material.parent.clone();
        let old = record.material.old_node;
        let new = record.material.binding.admission.node;
        let before = HeightAuthority::from_state(&state, parent.clone(), root).unwrap();
        let prepared = Prepared::verify(&state, &parent, root, record.clone(), false).unwrap();
        assert_eq!(prepared.parent(), &parent);
        assert_eq!(prepared.canonical_parent_root(), root);
        let after = prepared.authority().unwrap();
        assert!(before.voters.contains_key(&old));
        assert!(!before.voters.contains_key(&new));
        assert!(!after.voters.contains_key(&old));
        assert!(after.voters.contains_key(&new));
        assert_eq!(before.voters[&old].lineage, after.voters[&new].lineage);
        assert_eq!(
            before.voters[&old].reputation,
            after.voters[&new].reputation
        );
        assert_ne!(before.membership, after.membership);
        assert_eq!(after.parent, parent);
        assert!(prepared.effective.root().is_err());
        assert!(HeightAuthority::from_state(&prepared.effective, parent.clone(), root).is_err());
        assert!(Prepared::verify(&state, &parent, root, record, true).is_err());
        assert!(state.records().unwrap() == rows);
        assert_eq!(state.root().unwrap(), root);
        assert_eq!(prepared.effective.coins, state.coins);
        assert_eq!(prepared.effective.wallets, state.wallets);
        assert_eq!(prepared.effective.bonds_v2, state.bonds_v2);
        assert_eq!(prepared.effective.penalties_v2, state.penalties_v2);
        assert_eq!(prepared.effective.licenses_v2, state.licenses_v2);
        // Execute lifecycle components only, then compare the independently
        // constructed fixture. This is not licensed execution or finality.
        let body = crate::blocks::BlockBody {
            height: 1,
            reward_owner: [0; 32],
            fees: 0,
            transactions: vec![],
            operations: vec![],
        };
        let transition = prepared
            .transition_components(&body, &Default::default())
            .unwrap();
        let constructed = apply_components(&state, transition, &prepared.history);
        let expected: Hash = raw(&post["root"]).try_into().unwrap();
        assert_eq!(constructed.root().unwrap(), expected);
    }
}
