//! Pure candidate participation, refresh, join, exit and economic composition.
//! Returns tentative components; it neither certifies nor installs a block.
use crate::{
    Error, Hash, Result,
    anchors::FinalizedAnchor,
    blocks::{BlockBody, operation_kind},
    continuity_execution::ContinuityAccounting,
    continuity_exit_v2::Exit,
    execution::State,
    freshness::PhysicalMember,
    membership_v2::Book,
    recovery::ContinuityState,
    tpm::{PinnedTpmVerifier, TpmProfile},
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub accounting: ContinuityAccounting,
    pub registry: ContinuityState,
    pub membership: Book,
    pub keys: crate::continuity_keys_v2::Book,
    pub node_history: crate::node_key_history_v2::Book,
    pub retired: crate::retired_continuity_v2::Book,
    pub endorsement_dependencies: crate::endorsement_dependencies_v1::Book,
    pub endorsement_revocations: crate::endorsement_revocation_v1::Book,
    pub bonds: crate::bonds_v2::Book,
    pub penalties: crate::penalties_v2::Book,
    pub payouts: BTreeMap<crate::transactions::OutPoint, crate::transactions::Coin>,
    pub burned: u128,
    /// Execution outcome of every bond command, by command id (AM-5; `bond_ops_v2::settle_commands`).
    pub command_outcomes: BTreeMap<Hash, crate::bond_ops_v2::CommandOutcome>,
}

/// The expected root and finalized anchor must come from independently verified
/// history. This API does not execute transactions, issue rewards or certify a
/// block. Returning components instead of State prevents partial execution from
/// masquerading as a complete candidate post-state.
pub fn transition(
    state: &State,
    parent: &FinalizedAnchor,
    expected_root: Hash,
    body: &BlockBody,
) -> Result<Transition> {
    transition_with_history(state, parent, expected_root, body, &Default::default())
}
/// Historical authority must be derived from authenticated E-1 state using
/// HeightAuthority::from_state, not reconstructed from the evidence sender.
pub fn transition_with_history(
    state: &State,
    parent: &FinalizedAnchor,
    expected_root: Hash,
    body: &BlockBody,
    history: &crate::evidence_history_v2::History,
) -> Result<Transition> {
    transition_in_parent(
        crate::parent_context_v2::ParentContext::canonical(state, parent, expected_root)?,
        body,
        history,
    )
}
pub(crate) fn transition_in_parent(
    context: crate::parent_context_v2::ParentContext<'_>,
    body: &BlockBody,
    history: &crate::evidence_history_v2::History,
) -> Result<Transition> {
    transition_in_parent_at(context, body, history, None, None)
}
/// Both times come from full candidate execution's authenticated work parent:
/// admissions retain finalized-parent time; new revocation evidence uses the
/// validated containing-candidate time. Neither comes from an operation field.
/// Compatibility callers lacking the relevant time fail closed.
pub(crate) fn transition_in_parent_at(
    context: crate::parent_context_v2::ParentContext<'_>,
    body: &BlockBody,
    history: &crate::evidence_history_v2::History,
    admission_reference_time: Option<u64>,
    candidate_timestamp: Option<u64>,
) -> Result<Transition> {
    let state = context.state();
    let parent = context.parent();
    let expected_root = context.root();
    if state.accounting.slots.last_height != parent.height {
        return Err(Error::WrongAnchor);
    }
    // Admission class of the parent (committed Genesis data); every staged admission uses it.
    let class = state.admission_class()?;
    let parameters = state.protocol_records.get(&crate::genesis_v2::parameters_key())
        .map(|raw| crate::genesis_v2::Parameters::decode(raw).map_err(|_| Error::Codec))
        .transpose()?;
    let mut dependencies = state.endorsement_dependencies_v1.clone();
    let mut admission_witnesses = BTreeMap::new();
    if !body.transactions.is_empty()
        || body.fees != 0
        || state.membership_v2.is_empty()
        || !state.membership.records()?.is_empty()
        || !state.admission.is_empty()?
        || !state.bonds.records()?.is_empty()
        || !state.penalties.records()?.is_empty()
    {
        return Err(Error::WrongOperation);
    }
    let capacity=crate::body_capacity_v3::BodyCapacity::from_parent_context(context)?;
    capacity.encode(body)?;
    let mut registry = state.continuity.clone().ok_or(Error::UnknownSigner)?;
    parent.validate_context(registry.genesis, registry.fingerprint)?;
    // Authenticated records cannot contain their own current block identity.
    // Project the independently verified parent into a temporary registry only
    // after validating its root. The returned candidate stores H-1, never H.
    registry.anchor = crate::recovery::Anchor {
        height: parent.height,
        tip: parent.block,
        state_root: expected_root,
        registry_root: registry.roots()?.0,
    };
    state
        .membership_v2
        .validate_at_height(&registry, &state.continuity_keys_v2, parent.height)?;
    let mut exits = Vec::new();
    let mut joins = Vec::new();
    let mut rotations = Vec::new();
    let mut node_rotations = Vec::new();
    let mut hardware_rotations = Vec::new();
    let mut commands = Vec::new();
    let mut settlements = Vec::new();
    let mut withdrawals = Vec::new();
    for member in &registry.members {
        if state.penalties_v2.revoked(member.lineage) && member.eligible {
            return Err(Error::UnqualifiedPhysical);
        }
    }
    for raw in &body.operations {
        match operation_kind(raw)? {
            11 | 12 | 13 => {}
            14 => exits.push(Exit::decode(raw)?),
            15 | 16 => {
                let (signed, witness) = crate::admission_public_v3::item(raw, parameters.as_ref())?;
                let kind = operation_kind(&signed)?;
                let node = if kind == 15 {
                    let item = crate::join_v2::Join::decode(&signed)?;
                    let node = item.binding.admission.node;
                    joins.push(item);
                    node
                } else {
                    let item = crate::hardware_rotate_v2::HardwareRotate::decode(&signed)?;
                    let node = item.binding.admission.node;
                    hardware_rotations.push(item);
                    node
                };
                if let Some(witness) = witness {
                    if admission_witnesses.insert(node, witness).is_some() {
                        return Err(Error::Duplicate);
                    }
                }
            }
            22 => node_rotations.push(crate::node_key_rotate_v2::NodeKeyRotate::decode(raw)?),
            21 => rotations.push(crate::continuity_key_rotate_v2::KeyRotate::decode(raw)?),
            17 => {
                let evidence = crate::equivocation_v2::Evidence::decode(raw)?;
                settlements.push(history.settlement(&evidence, parent)?);
            }
            19 | 20 => commands.push(crate::bond_ops_v2::Operation::decode(raw)?),
            crate::endorsement_revocation_v1::OPERATION_KIND => {
                withdrawals.push(crate::endorsement_revocation_v1::Operation::decode(raw)?);
            }
            _ => return Err(Error::WrongOperation),
        }
    }
    // Authenticate and stage the entire new public index before any boundary
    // eligibility changes. This is independent of operation listing order.
    for join in &joins {
        if let Some(witness) = admission_witnesses.get(&join.binding.admission.node) {
            join.verify_in_parent(context)?;
            dependencies = dependencies.stage_authenticated(
                &join.binding, join.binding.admission.node,
                admission_reference_time.ok_or(Error::UnqualifiedPhysical)?, witness,
                parameters.as_ref().ok_or(Error::UnqualifiedPhysical)?,
            )?;
        }
    }
    for rotation in &hardware_rotations {
        if let Some(witness) = admission_witnesses.get(&rotation.binding.admission.node) {
            rotation.verify_in_parent(context)?;
            let lineage = registry.members.iter()
                .find(|m| m.node == rotation.binding.admission.node)
                .ok_or(Error::UnknownSigner)?.lineage;
            dependencies = dependencies.stage_authenticated(
                &rotation.binding, lineage,
                admission_reference_time.ok_or(Error::UnqualifiedPhysical)?, witness,
                parameters.as_ref().ok_or(Error::UnqualifiedPhysical)?,
            )?;
        }
    }
    let a2_enabled = parameters.as_ref().map(crate::endorsement_revocation_v1::enabled)
        .transpose()?.unwrap_or(false);
    let mut terminal = state.endorsement_revocations_v1.clone();
    let mut excluded = std::collections::BTreeSet::new();
    if a2_enabled {
        // The provisional signed component/index projection is used solely for
        // dependency resolution. It has no StateRoot, certificate or install API.
        let projection = public_admission_projection(context, body.height, &joins,
            &hardware_rotations, dependencies.clone())?;
        if !withdrawals.is_empty() {
            terminal = terminal.stage(state, &projection, &crate::endorsement_revocation_v1::Context {
                genesis: parent.genesis, fingerprint: parent.fingerprint,
                parent_height: parent.height, parent_block: parent.block,
                parent_state: expected_root, height: body.height,
                timestamp: candidate_timestamp.ok_or(Error::UnqualifiedPhysical)?,
            }, &withdrawals)?;
        }
        excluded.extend(terminal.affected(state)?);
        let prospective = terminal.affected(&projection)?;
        // No same-block new admission/replacement may acquire a withdrawn
        // dependency or escape its already-established EK lineage.
        for binding in joins.iter().map(|j| &j.binding)
            .chain(hardware_rotations.iter().map(|r| &r.binding)) {
            let lineage = projection.continuity.as_ref().ok_or(Error::UnknownSigner)?
                .members.iter().find(|m| m.node == binding.admission.node)
                .ok_or(Error::UnknownSigner)?.lineage;
            if excluded.contains(&lineage) || prospective.contains(&lineage) {
                return Err(Error::UnqualifiedPhysical);
            }
        }
    } else if !withdrawals.is_empty() || !terminal.is_empty() {
        return Err(Error::WrongOperation);
    }
    let mut physical = BTreeMap::new();
    let mut profiles = BTreeMap::new();
    for member in registry.members.iter().filter(|m| m.physical && m.eligible) {
        let binding = state
            .continuity_keys_v2
            .get(member.node)
            .ok_or(Error::UnknownSigner)?;
        let profile = TpmProfile::decode(&binding.admission().profile)?;
        physical.insert(
            member.node,
            PhysicalMember {
                node: member.node,
                generation: member.generation,
                continuity_key: member.voting_key,
                hardware: member.hardware,
                admission_commitment: member.attestation,
                attestation_key: profile.ak_public.clone(),
            },
        );
        if profiles.insert(member.attestation, profile).is_some() {
            return Err(Error::Duplicate);
        }
    }
    // ACK H uses the old freshness record. New refresh H activates at H+1.
    // Boundary reputation closes before an exit removes future eligibility.
    let (mut accounting, mut updated) = state.accounting.apply_with_capacity(
        parent,
        body,
        &registry,
        &physical,
        &PinnedTpmVerifier { profiles },
        &capacity,
    )?;
    state.membership_v2.adjust_hardware_history(
        body.height,
        body,
        &state.accounting,
        &registry,
        &mut updated,
    )?;
    let excluded_nodes: std::collections::BTreeSet<_> = registry.members.iter()
        .filter(|m| excluded.contains(&m.lineage)).map(|m| m.node).collect();
    let mut boundary_membership = state.membership_v2.clone();
    boundary_membership.exclude_endorsement_nodes(&excluded_nodes)?;
    for member in &mut updated.members {
        if excluded.contains(&member.lineage) { member.eligible = false; }
    }
    let (mut membership, mut registry) = boundary_membership.apply_exits(
        parent,
        &exits,
        &registry,
        &updated,
        &state.wallets,
        &state.continuity_keys_v2,
    )?;
    membership.exclude_endorsement_nodes(&excluded_nodes)?;
    for member in &mut registry.members {
        if excluded.contains(&member.lineage) { member.eligible = false; }
    }
    let economic = crate::bond_ops_v2::settle_commands(
        parent,
        history,
        &state.wallets,
        &state.bonds_v2,
        &state.penalties_v2,
        &commands,
        &settlements,
    )?;
    let mut revoked_nodes = std::collections::BTreeSet::new();
    for lineage in &economic.revoked {
        let mut matches = registry
            .members
            .iter_mut()
            .filter(|m| m.lineage == *lineage);
        let member = matches.next().ok_or(Error::UnknownSigner)?;
        if matches.next().is_some() {
            return Err(Error::Duplicate);
        }
        // Preserve P/S/H/A and numeric D; only prospective eligibility changes.
        member.eligible = false;
        accounting.freshness.remove(&member.node);
        revoked_nodes.insert(member.node);
    }
    membership.revoke_nodes(&revoked_nodes)?;
    let mut keys = state.continuity_keys_v2.clone();
    let mut retired = state.retired_continuity_v2.clone();
    let mut node_history = state.node_key_history_v2.clone();
    let mut rotated = std::collections::BTreeSet::new();
    for rotation in rotations {
        let a = &rotation.binding.admission;
        if !rotated.insert(a.node) || exits.iter().any(|exit| exit.node == a.node) {
            return Err(Error::Duplicate);
        }
        rotation.verify_in_parent(context)?;
        let post_member = registry
            .members
            .iter()
            .find(|m| m.node == a.node)
            .ok_or(Error::UnknownSigner)?;
        if !post_member.eligible || economic.penalties.revoked(post_member.lineage) {
            return Err(Error::UnqualifiedPhysical);
        }
        let (public, _) = mutiny_crypto_v2::PublicKey::decode_descriptor(&a.continuity_descriptor)
            .map_err(|_| Error::Codec)?;
        retired.reject_reused(&public)?;
        node_history.reject_reused(&public)?;
        let old = state
            .membership_v2
            .get(a.node)
            .ok_or(Error::UnknownSigner)?;
        let old_key = state
            .continuity_keys_v2
            .get(a.node)
            .ok_or(Error::UnknownSigner)?;
        retired = retired.stage_retire(crate::retired_continuity_v2::Record {
            binding: old.binding().clone(),
            owner_descriptor: old_key.owner_descriptor().to_vec(),
            retired_height: body.height,
            rotation: crate::domain_hash(
                b"MUTINY-BUILD8-CONTINUITY-KEY-ROTATION-RECORD-V2",
                &rotation.encode()?,
            ),
        })?;
        let policy = state.current_admission_policy_v2(parent.genesis, parent.fingerprint)?;
        let expected = crate::admission_v2::Expected {
            node: a.node,
            hardware_generation: a.hardware_generation,
            key_generation: a.key_generation,
            supervised_nonce: rotation.admission_nonce()?,
        };
        (membership, keys) = membership.stage_key_rotation(
            &rotation.binding,
            rotation.sequence,
            &policy,
            &expected,
            &state.wallets,
            &keys,
            class,
        )?;
        let profile = TpmProfile::decode(&a.profile)?;
        accounting.freshness.insert(
            a.node,
            crate::freshness::FreshnessRecord {
                node: a.node,
                generation: a.hardware_generation,
                key: crate::tpm::public_key(&profile.voting_public, false)?,
                committed_height: body.height,
                evidence_commitment: crate::domain_hash(
                    b"MUTINY-BUILD8-ATTESTATION-EVIDENCE-V1",
                    &a.quote,
                ),
            },
        );
    }
    for rotation in node_rotations {
        if !rotated.insert(rotation.node) || exits.iter().any(|exit| exit.node == rotation.node) {
            return Err(Error::Duplicate);
        }
        let member = registry
            .members
            .iter()
            .find(|m| m.node == rotation.node)
            .ok_or(Error::UnknownSigner)?;
        if !member.physical || !member.eligible || economic.penalties.revoked(member.lineage) {
            return Err(Error::UnqualifiedPhysical);
        }
        let old = state
            .membership_v2
            .get(rotation.node)
            .ok_or(Error::UnknownSigner)?;
        let (replacement, _) = mutiny_crypto_v2::PublicKey::decode_descriptor(&rotation.proposed)
            .map_err(|_| Error::Codec)?;
        retired.reject_reused(&replacement)?;
        for descriptor in state.wallets.public_descriptors() {
            let (key, _) = mutiny_crypto_v2::PublicKey::decode_descriptor(descriptor)
                .map_err(|_| Error::Codec)?;
            if key.ed448 == replacement.ed448 || key.fndsa == replacement.fndsa {
                return Err(Error::Duplicate);
            }
        }
        // New Node keys must not reuse either constituent of any admitted role.
        for control in membership.controls() {
            for descriptor in [
                &control.binding().node_descriptor[..],
                control.current_node_descriptor(),
                &control.binding().admission.continuity_descriptor[..],
                keys.get(control.node())
                    .ok_or(Error::UnknownSigner)?
                    .owner_descriptor(),
            ] {
                let (key, _) = mutiny_crypto_v2::PublicKey::decode_descriptor(descriptor)
                    .map_err(|_| Error::Codec)?;
                if key.ed448 == replacement.ed448 || key.fndsa == replacement.fndsa {
                    return Err(Error::Duplicate);
                }
            }
        }
        node_history = node_history.stage(
            &rotation,
            parent,
            &old.parent(),
            &state.wallets,
            &old.binding().node_descriptor,
        )?;
        membership =
            membership.stage_node_key_rotation(&rotation, parent, &state.wallets, &keys)?;
    }
    for rotation in hardware_rotations {
        let a = &rotation.binding.admission;
        if !rotated.insert(a.node) || exits.iter().any(|exit| exit.node == a.node) {
            return Err(Error::Duplicate);
        }
        rotation.verify_in_parent(context)?;
        let member = registry
            .members
            .iter()
            .find(|m| m.node == a.node)
            .ok_or(Error::UnknownSigner)?;
        if !member.eligible || economic.penalties.revoked(member.lineage) {
            return Err(Error::UnqualifiedPhysical);
        }
        let profile = TpmProfile::decode(&a.profile)?;
        retired.reject_physical_reuse(a.node, &profile)?;
        let (replacement, _) =
            mutiny_crypto_v2::PublicKey::decode_descriptor(&a.continuity_descriptor)
                .map_err(|_| Error::Codec)?;
        retired.reject_reused(&replacement)?;
        node_history.reject_reused(&replacement)?;
        let old = state
            .membership_v2
            .get(a.node)
            .ok_or(Error::UnknownSigner)?;
        let old_key = state
            .continuity_keys_v2
            .get(a.node)
            .ok_or(Error::UnknownSigner)?;
        retired = retired.stage_retire(crate::retired_continuity_v2::Record {
            binding: old.binding().clone(),
            owner_descriptor: old_key.owner_descriptor().to_vec(),
            retired_height: body.height,
            rotation: crate::domain_hash(
                b"MUTINY-BUILD8-HARDWARE-ROTATION-RECORD-V2",
                &rotation.encode()?,
            ),
        })?;
        let policy = state.current_admission_policy_v2(parent.genesis, parent.fingerprint)?;
        let expected = crate::admission_v2::Expected {
            node: a.node,
            hardware_generation: a.hardware_generation,
            key_generation: a.key_generation,
            supervised_nonce: rotation.admission_nonce()?,
        };
        (membership, keys, registry) = membership.stage_hardware_rotation(
            &rotation,
            &policy,
            &expected,
            &state.wallets,
            &registry,
            &keys,
            class,
        )?;
        accounting.freshness.insert(
            a.node,
            crate::freshness::FreshnessRecord {
                node: a.node,
                generation: a.hardware_generation,
                key: crate::tpm::public_key(&profile.voting_public, false)?,
                committed_height: body.height,
                evidence_commitment: crate::domain_hash(
                    b"MUTINY-BUILD8-ATTESTATION-EVIDENCE-V1",
                    &a.quote,
                ),
            },
        );
    }
    for join in joins {
        join.verify_in_parent(context)?;
        for descriptor in [
            &join.binding.admission.continuity_descriptor,
            &join.binding.node_descriptor,
        ] {
            let (public, _) = mutiny_crypto_v2::PublicKey::decode_descriptor(descriptor)
                .map_err(|_| Error::Codec)?;
            retired.reject_reused(&public)?;
            node_history.reject_reused(&public)?;
        }
        let policy = state.current_admission_policy_v2(parent.genesis, parent.fingerprint)?;
        let expected = crate::admission_v2::Expected {
            node: join.binding.admission.node,
            hardware_generation: 1,
            key_generation: 1,
            supervised_nonce: join.admission_nonce()?,
        };
        (membership, keys, registry) = membership.stage_join(
            &join.binding,
            &policy,
            &expected,
            &state.wallets,
            body.height,
            &registry,
            &keys,
            class,
        )?;
        let a = &join.binding.admission;
        let profile = crate::tpm::TpmProfile::decode(&a.profile)?;
        retired.reject_physical_reuse(a.node, &profile)?;
        accounting.freshness.insert(
            a.node,
            crate::freshness::FreshnessRecord {
                node: a.node,
                generation: 1,
                key: crate::tpm::public_key(&profile.voting_public, false)?,
                committed_height: body.height,
                evidence_commitment: crate::domain_hash(
                    b"MUTINY-BUILD8-ATTESTATION-EVIDENCE-V1",
                    &a.quote,
                ),
            },
        );
    }
    for member in &mut registry.members {
        member.history.bonds = economic
            .bonds
            .reputation_lots(member.lineage, body.height)?;
    }
    membership.validate_at_height(&registry, &keys, body.height)?;
    context
        .history()
        .validate_generations(Some(&registry), &keys, &retired, body.height)?;
    accounting.records()?;
    terminal = terminal.finish_transition(body.height, &registry)?;
    Ok(Transition {
        accounting,
        registry,
        membership,
        keys,
        retired,
        endorsement_dependencies: dependencies,
        endorsement_revocations: terminal,
        node_history,
        bonds: economic.bonds,
        penalties: economic.penalties,
        payouts: economic.payouts,
        burned: economic.burned,
        command_outcomes: economic.outcomes,
    })
}

fn public_admission_projection(
    context: crate::parent_context_v2::ParentContext<'_>, height: u64,
    joins: &[crate::join_v2::Join], rotations: &[crate::hardware_rotate_v2::HardwareRotate],
    dependencies: crate::endorsement_dependencies_v1::Book,
) -> Result<State> {
    let state = context.state();
    let parent = context.parent();
    let policy = state.current_admission_policy_v2(parent.genesis, parent.fingerprint)?;
    let class = state.admission_class()?;
    let mut projected = state.clone();
    let mut registry = state.continuity.clone().ok_or(Error::UnknownSigner)?;
    let mut membership = state.membership_v2.clone();
    let mut keys = state.continuity_keys_v2.clone();
    let mut retired = state.retired_continuity_v2.clone();
    for rotation in rotations {
        let a = &rotation.binding.admission;
        let old = state.membership_v2.get(a.node).ok_or(Error::UnknownSigner)?;
        let old_key = state.continuity_keys_v2.get(a.node).ok_or(Error::UnknownSigner)?;
        retired = retired.stage_retire(crate::retired_continuity_v2::Record {
            binding: old.binding().clone(), owner_descriptor: old_key.owner_descriptor().to_vec(),
            retired_height: height,
            rotation: crate::domain_hash(b"MUTINY-BUILD8-HARDWARE-ROTATION-RECORD-V2", &rotation.encode()?),
        })?;
        let expected = crate::admission_v2::Expected {
            node: a.node, hardware_generation: a.hardware_generation,
            key_generation: a.key_generation, supervised_nonce: rotation.admission_nonce()?,
        };
        (membership, keys, registry) = membership.stage_hardware_rotation(rotation, &policy,
            &expected, &state.wallets, &registry, &keys, class)?;
    }
    for join in joins {
        let a = &join.binding.admission;
        let expected = crate::admission_v2::Expected { node: a.node, hardware_generation: 1,
            key_generation: 1, supervised_nonce: join.admission_nonce()? };
        (membership, keys, registry) = membership.stage_join(&join.binding, &policy,
            &expected, &state.wallets, height, &registry, &keys, class)?;
    }
    projected.continuity = Some(registry);
    projected.membership_v2 = membership;
    projected.continuity_keys_v2 = keys;
    projected.retired_continuity_v2 = retired;
    projected.endorsement_dependencies_v1 = dependencies;
    Ok(projected)
}
