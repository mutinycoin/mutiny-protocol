use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct MiningPresenceState {
    pub license_id: String,
    pub mining_key_sequence: u32,
    pub last_presence_epoch: u64,
    pub last_presence_operation_id: String,
}

impl MiningPresenceState {
    pub(super) fn value(&self) -> Result<MiningPresenceStateV1, String> {
        Ok(MiningPresenceStateV1 {
            version: 1,
            mining_key_sequence: self.mining_key_sequence,
            last_presence_epoch: self.last_presence_epoch,
            last_presence_operation_id: decode32(&self.last_presence_operation_id)?,
        })
    }
}

pub(super) fn active(state: &DevnetState, epoch: u64) -> bool {
    // Preserve the inherited Devnet textual identity gate exactly.
    if state.network_id == DEVNET_NETWORK_ID {
        return state.genesis_hash == DEVNET_GENESIS_ID_HEX
            && epoch >= PACK_K_DEVNET_ACTIVATION_EPOCH;
    }
    decode32(&state.genesis_hash)
        .map(|genesis| mutiny_protocol::pack_k_active(state.network_id, &genesis, epoch))
        .unwrap_or(false)
}

pub(super) fn base_eligible_count(state: &DevnetState, epoch: u64) -> u64 {
    state
        .licenses
        .iter()
        .filter(|license| license.is_eligible(epoch))
        .count() as u64
}

fn state_for_license<'a>(
    state: &'a DevnetState,
    license: &LicenseState,
) -> Option<&'a MiningPresenceState> {
    state
        .mining_presence
        .iter()
        .find(|presence| presence.license_id == license.license_id)
}

pub(super) fn license_has_fresh_presence(
    state: &DevnetState,
    license: &LicenseState,
    epoch: u64,
) -> bool {
    if !active(state, epoch) {
        return true;
    }
    let Some(presence) = state_for_license(state, license) else {
        return false;
    };
    if presence.mining_key_sequence != license.mining_key_sequence {
        return false;
    }
    if presence.last_presence_epoch > epoch {
        return false;
    }
    epoch - presence.last_presence_epoch < MINING_PRESENCE_WINDOW_EPOCHS
}

pub(super) fn participation_eligible_count(state: &DevnetState, epoch: u64) -> u64 {
    if !active(state, epoch) {
        return base_eligible_count(state, epoch);
    }
    state
        .licenses
        .iter()
        .filter(|license| {
            license.is_eligible(epoch) && license_has_fresh_presence(state, license, epoch)
        })
        .count() as u64
}

pub(super) fn decode_operation(op: &ProtocolOperationV1) -> Result<MiningPresenceV1, String> {
    MiningPresenceV1::decode_operation(op).map_err(|e| e.to_string())
}

pub(super) fn validate_operation_against_parent(
    parent: &DevnetState,
    op: &ProtocolOperationV1,
    block_epoch: u64,
) -> Result<MiningPresenceV1, String> {
    let presence = decode_operation(op)?;
    let license = parent
        .licenses
        .iter()
        .find(|license| license.license_id == hex::encode(presence.license_id.0))
        .ok_or("MINING_PRESENCE references unknown LicenseID")?;
    let genesis = decode32(&parent.genesis_hash)?;
    presence
        .verify_against(&license.record()?, parent.network_id, &genesis, block_epoch)
        .map_err(|e| e.to_string())?;
    Ok(presence)
}

fn authority_target(op: &ProtocolOperationV1) -> Result<Option<[u8; 32]>, String> {
    match op.op_type {
        OP_LICENSE_TRANSFER => Ok(Some(decode_license_transfer_operation(op)?.license_id.0)),
        OP_LICENSE_MINING_KEY_ROTATE => {
            Ok(Some(decode_mining_key_rotation_operation(op)?.license_id.0))
        }
        _ => Ok(None),
    }
}

pub(super) fn prevalidate_block_operations(
    parent: &DevnetState,
    operations: &[ProtocolOperationV1],
    block_epoch: u64,
) -> Result<(), String> {
    let mut authority_targets = HashSet::<[u8; 32]>::new();
    for op in operations {
        if let Some(target) = authority_target(op)? {
            authority_targets.insert(target);
        }
    }

    let mut presence_targets = HashSet::<[u8; 32]>::new();
    for op in operations {
        if op.op_type != OP_MINING_PRESENCE {
            continue;
        }
        let presence = validate_operation_against_parent(parent, op, block_epoch)?;
        if !presence_targets.insert(presence.license_id.0) {
            return Err(
                "Pack K permits at most one MINING_PRESENCE per LicenseID per block".into(),
            );
        }
        if authority_targets.contains(&presence.license_id.0) {
            return Err("Pack K forbids same-block owner transfer/mining-key rotation plus MINING_PRESENCE for one LicenseID".into());
        }
    }
    Ok(())
}

pub(super) fn candidate_eligible_count(
    parent: &DevnetState,
    epoch: u64,
    mining_license_id: &[u8; 32],
    operations: &[ProtocolOperationV1],
) -> Result<u64, String> {
    let license = parent
        .licenses
        .iter()
        .find(|license| license.license_id == hex::encode(mining_license_id))
        .ok_or("candidate mining LicenseID is unknown")?;
    if !license.is_eligible(epoch) {
        return Err(
            "candidate mining LicenseID is not base-eligible at the candidate epoch".into(),
        );
    }
    if !active(parent, epoch) {
        return Ok(base_eligible_count(parent, epoch));
    }

    let parent_count = participation_eligible_count(parent, epoch);
    if license_has_fresh_presence(parent, license, epoch) {
        return Ok(parent_count);
    }

    let mut matching = None;
    for op in operations {
        if op.op_type != OP_MINING_PRESENCE {
            continue;
        }
        let presence = decode_operation(op)?;
        if presence.license_id.0 != *mining_license_id {
            continue;
        }
        if matching.is_some() {
            return Err("candidate block contains duplicate self-presence operations".into());
        }
        validate_operation_against_parent(parent, op, epoch)?;
        matching = Some(presence);
    }
    if matching.is_none() {
        return Err("candidate mining LicenseID lacks fresh parent presence and valid same-block self-presence".into());
    }
    parent_count
        .checked_add(1)
        .ok_or_else(|| "Pack-K candidate eligible count overflow".into())
}

pub(super) fn create_operation(
    state: &DevnetState,
    license_index: usize,
    epoch: u64,
    signer: &SigningKey,
) -> Result<ProtocolOperationV1, String> {
    if !active(state, epoch) {
        return Err("Pack K is not active at the requested presence epoch".into());
    }
    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    if signer.verifying_key().to_bytes() != decode32(&license.mining_public_key)? {
        return Err("presence signer does not match current on-chain mining authority".into());
    }
    let mut presence = MiningPresenceV1 {
        network_id: state.network_id,
        genesis_id: decode32(&state.genesis_hash)?,
        license_id: LicenseId(decode32(&license.license_id)?),
        expected_mining_sequence: license.mining_key_sequence,
        presence_epoch: epoch,
        mining_signature: [0u8; 64],
    };
    presence.mining_signature = signer.sign(&presence.signing_digest().0).to_bytes();
    let op = presence.operation();
    validate_operation_against_parent(state, &op, epoch)?;
    Ok(op)
}

pub(super) fn apply_validated_operation(
    state: &mut DevnetState,
    op: &ProtocolOperationV1,
) -> Result<(), String> {
    let presence = decode_operation(op)?;
    let state_value = MiningPresenceState {
        license_id: hex::encode(presence.license_id.0),
        mining_key_sequence: presence.expected_mining_sequence,
        last_presence_epoch: presence.presence_epoch,
        last_presence_operation_id: op.operation_id().to_hex(),
    };
    if let Some(existing) = state
        .mining_presence
        .iter_mut()
        .find(|entry| entry.license_id == state_value.license_id)
    {
        *existing = state_value;
    } else {
        state.mining_presence.push(state_value);
        state
            .mining_presence
            .sort_by(|a, b| a.license_id.cmp(&b.license_id));
    }
    Ok(())
}

pub(super) fn check_state(state: &DevnetState) -> Result<(), String> {
    let mut ids = HashSet::<String>::new();
    for presence in &state.mining_presence {
        let license_id = decode32(&presence.license_id)?;
        decode32(&presence.last_presence_operation_id)?;
        presence.value()?.validate().map_err(|e| e.to_string())?;
        if !ids.insert(presence.license_id.clone()) {
            return Err("duplicate Pack-K MiningPresenceState LicenseID".into());
        }
        if !state
            .licenses
            .iter()
            .any(|license| license.license_id == hex::encode(license_id))
        {
            return Err("Pack-K MiningPresenceState references unknown LicenseID".into());
        }
    }
    Ok(())
}

pub(super) fn print_presence(state: &DevnetState) -> Result<(), String> {
    let active_now = active(state, state.tip_epoch);
    println!(
        "Pack K mining presence: {}",
        if active_now {
            "ACTIVE"
        } else {
            "PRE-ACTIVATION"
        }
    );
    println!("Pack K Devnet activation epoch: {PACK_K_DEVNET_ACTIVATION_EPOCH}");
    println!("Mining presence window: {MINING_PRESENCE_WINDOW_EPOCHS} epochs");
    println!(
        "Canonical presence records: {}",
        state.mining_presence.len()
    );
    for entry in &state.mining_presence {
        let license = state
            .licenses
            .iter()
            .find(|license| license.license_id == entry.license_id)
            .ok_or("presence record references unknown license")?;
        let fresh = license_has_fresh_presence(state, license, state.tip_epoch);
        println!(
            "  {} seq={} last_epoch={} fresh_now={} op={}",
            &entry.license_id[..16],
            entry.mining_key_sequence,
            entry.last_presence_epoch,
            fresh,
            &entry.last_presence_operation_id[..16]
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn state() -> DevnetState {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build63-presence-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        // Pack K activates only for the locked Pack-J Devnet identity. Build the
        // lifecycle-correct Genesis + Bootstrap Block 1 fixture rather than the legacy
        // synthetic init_devnet regression fixture, then deterministically activate the
        // Bootstrap licenses before positioning the parent at epoch 1499.
        init_build54_genesis_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        let fixture = bootstrap::apply_devnet_bootstrap_block(&mut state).unwrap();
        apply_scheduled_license_transitions(&mut state, fixture.bootstrap_activation_epoch)
            .unwrap();
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(state.genesis_hash, DEVNET_GENESIS_ID_HEX);
        assert_eq!(state.licenses.len(), BOOTSTRAP_LICENSE_COUNT);
        assert!(state
            .licenses
            .iter()
            .all(|license| license.status == LICENSE_STATUS_ACTIVE));
        state.tip_epoch = PACK_K_DEVNET_ACTIVATION_EPOCH - 1;
        state.mining_presence.clear();
        state
    }

    #[test]
    fn pack_k_activation_boundary_preserves_legacy_count_then_requires_presence() {
        let state = state();
        assert!(!active(&state, 1499));
        assert!(active(&state, 1500));
        assert_eq!(
            base_eligible_count(&state, 1499),
            BOOTSTRAP_LICENSE_COUNT as u64
        );
        assert_eq!(
            participation_eligible_count(&state, 1499),
            BOOTSTRAP_LICENSE_COUNT as u64
        );
        assert_eq!(participation_eligible_count(&state, 1500), 0);
    }

    #[test]
    fn pack_k_self_reentry_is_exactly_one_and_presence_expires_at_p_plus_16() {
        let mut state = state();
        let signer = dev_signing_key_for_license(&state.licenses[0]).unwrap();
        let license_id = decode32(&state.licenses[0].license_id).unwrap();
        let op = create_operation(&state, 0, 1500, &signer).unwrap();
        prevalidate_block_operations(&state, &[op.clone()], 1500).unwrap();
        assert_eq!(
            candidate_eligible_count(&state, 1500, &license_id, &[op.clone()]).unwrap(),
            1
        );
        assert!(candidate_eligible_count(&state, 1500, &license_id, &[]).is_err());

        apply_validated_operation(&mut state, &op).unwrap();
        assert_eq!(participation_eligible_count(&state, 1500), 1);
        assert!(license_has_fresh_presence(&state, &state.licenses[0], 1515));
        assert!(!license_has_fresh_presence(
            &state,
            &state.licenses[0],
            1516
        ));
    }

    #[test]
    fn pack_k_other_same_block_presence_does_not_change_current_candidate_count() {
        let mut state = state();
        let signer0 = dev_signing_key_for_license(&state.licenses[0]).unwrap();
        let first = create_operation(&state, 0, 1500, &signer0).unwrap();
        apply_validated_operation(&mut state, &first).unwrap();

        let signer1 = dev_signing_key_for_license(&state.licenses[1]).unwrap();
        let competitor = create_operation(&state, 1, 1501, &signer1).unwrap();
        let license0 = decode32(&state.licenses[0].license_id).unwrap();
        assert_eq!(participation_eligible_count(&state, 1501), 1);
        assert_eq!(
            candidate_eligible_count(&state, 1501, &license0, &[competitor.clone()]).unwrap(),
            1
        );

        let mut post_block = state.clone();
        apply_validated_operation(&mut post_block, &competitor).unwrap();
        assert_eq!(participation_eligible_count(&post_block, 1501), 2);
    }

    #[test]
    fn pack_k_rotation_sequence_invalidates_prior_presence_immediately() {
        let mut state = state();
        let signer = dev_signing_key_for_license(&state.licenses[0]).unwrap();
        let op = create_operation(&state, 0, 1500, &signer).unwrap();
        apply_validated_operation(&mut state, &op).unwrap();
        assert!(license_has_fresh_presence(&state, &state.licenses[0], 1501));

        state.licenses[0].mining_key_sequence += 1;
        state.licenses[0].mining_public_key = hex::encode(
            SigningKey::from_bytes(&[0xee; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(!license_has_fresh_presence(
            &state,
            &state.licenses[0],
            1501
        ));
    }

    #[test]
    fn pack_k_duplicate_unknown_and_same_block_authority_conflict_fail_closed() {
        let state = state();
        let signer = dev_signing_key_for_license(&state.licenses[0]).unwrap();
        let presence = create_operation(&state, 0, 1500, &signer).unwrap();
        assert!(
            prevalidate_block_operations(&state, &[presence.clone(), presence.clone()], 1500)
                .unwrap_err()
                .contains("at most one MINING_PRESENCE")
        );

        let mut unknown = decode_operation(&presence).unwrap();
        unknown.license_id = LicenseId([0xaa; 32]);
        unknown.mining_signature = signer.sign(&unknown.signing_digest().0).to_bytes();
        assert!(
            validate_operation_against_parent(&state, &unknown.operation(), 1500)
                .unwrap_err()
                .contains("unknown LicenseID")
        );

        let license = &state.licenses[0];
        let owner_signer =
            dev_signing_key_for_public_key(&decode32(&license.owner_public_key).unwrap()).unwrap();
        let mut rotation = MiningKeyRotateV1 {
            license_id: LicenseId(decode32(&license.license_id).unwrap()),
            expected_owner_sequence: license.owner_key_sequence,
            expected_mining_sequence: license.mining_key_sequence,
            new_mining_public_key: SigningKey::from_bytes(&[0xef; 32])
                .verifying_key()
                .to_bytes(),
            owner_signature: [0u8; 64],
        };
        rotation.owner_signature = owner_signer.sign(&rotation.signing_digest().0).to_bytes();
        assert!(
            prevalidate_block_operations(&state, &[rotation.operation(), presence], 1500)
                .unwrap_err()
                .contains("same-block owner transfer/mining-key rotation")
        );
    }

    #[test]
    fn pack_k_fresh_presence_never_overrides_pending_suspension_or_revocation() {
        let mut state = state();
        let signer = dev_signing_key_for_license(&state.licenses[0]).unwrap();
        let op = create_operation(&state, 0, 1500, &signer).unwrap();
        apply_validated_operation(&mut state, &op).unwrap();
        assert_eq!(participation_eligible_count(&state, 1500), 1);

        state.licenses[0].status = LICENSE_STATUS_PENDING;
        assert_eq!(participation_eligible_count(&state, 1500), 0);

        state.licenses[0].status = LICENSE_STATUS_ACTIVE;
        state.licenses[0].suspended_until_epoch = 1501;
        assert_eq!(participation_eligible_count(&state, 1500), 0);

        state.licenses[0].suspended_until_epoch = 0;
        state.licenses[0].status = LICENSE_STATUS_REVOKED;
        state.licenses[0].revocation_epoch = 1499;
        assert_eq!(participation_eligible_count(&state, 1500), 0);
    }
}
