use super::*;
use mutiny_protocol::{
    apply_offense, offense_weight, LicenseTransferV1, PunishmentEvidenceV1,
    OFFENSE_INVALID_SIGNED_WORK, OFFENSE_LICENSE_STATE_EQUIVOCATION,
    OFFENSE_SAME_TICKET_EQUIVOCATION, OP_LICENSE_MINING_KEY_ROTATE, OP_LICENSE_TRANSFER,
    OP_PUNISHMENT_EVIDENCE, REVOCATION_THRESHOLD, STRIKE_DECAY_EPOCHS,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct OffenseEventState {
    pub(super) evidence_id: String,
    pub(super) license_id: String,
    pub(super) offense_type: u16,
    pub(super) weight: u8,
    pub(super) applied_epoch: u64,
    pub(super) expiry_epoch: u64,
}

impl OffenseEventState {
    pub(super) fn value_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(51);
        out.extend_from_slice(&decode32(&self.license_id)?);
        out.extend_from_slice(&self.offense_type.to_be_bytes());
        out.push(self.weight);
        out.extend_from_slice(&self.applied_epoch.to_be_bytes());
        out.extend_from_slice(&self.expiry_epoch.to_be_bytes());
        debug_assert_eq!(out.len(), 51);
        Ok(out)
    }
}

pub(super) fn decode_punishment_operation(
    op: &ProtocolOperationV1,
) -> Result<PunishmentEvidenceV1, String> {
    if op.op_type != OP_PUNISHMENT_EVIDENCE || op.op_version != 1 {
        return Err("operation is not V1 punishment evidence".into());
    }
    if op.payload.len() < 35 {
        return Err("punishment evidence payload is truncated".into());
    }
    let offense_type = u16::from_be_bytes(op.payload[0..2].try_into().unwrap());
    offense_weight(offense_type).map_err(|e| e.to_string())?;
    let accused_license_id = LicenseId(op.payload[2..34].try_into().unwrap());
    let mut input = &op.payload[34..];
    let evidence_len = read_varuint(&mut input).map_err(|e| e.to_string())?;
    let evidence_len =
        usize::try_from(evidence_len).map_err(|_| "punishment evidence length overflow")?;
    if input.len() != evidence_len {
        return Err("punishment evidence length does not match canonical payload".into());
    }
    let evidence = PunishmentEvidenceV1 {
        offense_type,
        accused_license_id,
        evidence: input.to_vec(),
    };
    if evidence.canonical_evidence() != op.payload {
        return Err("punishment evidence operation is not canonical".into());
    }
    Ok(evidence)
}

fn license_by_id<'a>(state: &'a DevnetState, id: &LicenseId) -> Result<&'a LicenseState, String> {
    state
        .licenses
        .iter()
        .find(|license| license.license_id == hex::encode(id.0))
        .ok_or_else(|| "punishment evidence references unknown LicenseID".to_string())
}

fn mining_key_at_sequence(
    state: &DevnetState,
    id: &LicenseId,
    sequence: u32,
) -> Result<Option<[u8; 32]>, String> {
    let license = license_by_id(state, id)?;
    if sequence > license.mining_key_sequence {
        return Ok(None);
    }
    if sequence == license.mining_key_sequence {
        return Ok(Some(decode32(&license.mining_public_key)?));
    }
    let id_hex = hex::encode(id.0);
    let mut found = None;
    for historical in &state.historical_license_keys {
        if historical.license_id == id_hex && historical.mining_key_sequence == sequence {
            let key = decode32(&historical.mining_public_key)?;
            if found.replace(key).is_some() {
                return Err("ambiguous historical mining authority sequence".into());
            }
        }
    }
    found.map(Some).ok_or_else(|| {
        "missing historical mining authority snapshot for punishment evidence".to_string()
    })
}

fn owner_key_at_sequences(
    state: &DevnetState,
    id: &LicenseId,
    owner_sequence: u32,
    mining_sequence: u32,
) -> Result<Option<[u8; 32]>, String> {
    let license = license_by_id(state, id)?;
    if owner_sequence > license.owner_key_sequence || mining_sequence > license.mining_key_sequence
    {
        return Ok(None);
    }
    if owner_sequence == license.owner_key_sequence
        && mining_sequence == license.mining_key_sequence
    {
        return Ok(Some(decode32(&license.owner_public_key)?));
    }
    let id_hex = hex::encode(id.0);
    let mut found = None;
    for historical in &state.historical_license_keys {
        if historical.license_id == id_hex
            && historical.owner_key_sequence == owner_sequence
            && historical.mining_key_sequence == mining_sequence
        {
            let key = decode32(&historical.owner_public_key)?;
            if found.replace(key).is_some() {
                return Err("ambiguous historical owner authority sequence".into());
            }
        }
    }
    found.map(Some).ok_or_else(|| {
        "missing historical owner authority snapshot for punishment evidence".to_string()
    })
}

fn parse_signed_header(bytes: &[u8], network_id: u32) -> Result<([u8; 208], [u8; 64]), String> {
    if bytes.len() != 272 {
        return Err("punishment signed header must be exactly 272 bytes".into());
    }
    let mut core = [0u8; 208];
    let mut signature = [0u8; 64];
    core.copy_from_slice(&bytes[..208]);
    signature.copy_from_slice(&bytes[208..]);
    if u16::from_be_bytes(core[0..2].try_into().unwrap()) != 1 {
        return Err("punishment signed header version is not V1".into());
    }
    if u32::from_be_bytes(core[2..6].try_into().unwrap()) != network_id {
        return Err("punishment signed header NetworkID mismatch".into());
    }
    Ok((core, signature))
}

fn validate_signed_header(
    state: &DevnetState,
    accused: &LicenseId,
    mining_sequence: u32,
    bytes: &[u8],
) -> Result<Option<[u8; 208]>, String> {
    let (core, signature) = parse_signed_header(bytes, state.network_id)?;
    if core[142..174] != accused.0[..] {
        return Err("punishment signed header LicenseID does not match accused LicenseID".into());
    }
    let Some(mining_key) = mining_key_at_sequence(state, accused, mining_sequence)? else {
        return Ok(None);
    };
    let vk = VerifyingKey::from_bytes(&mining_key)
        .map_err(|_| "invalid historical mining public key in punishment evidence")?;
    let digest = block_signing_digest(&core);
    vk.verify_strict(&digest.0, &Signature::from_bytes(&signature))
        .map_err(|_| "punishment evidence has invalid mining signature")?;
    Ok(Some(core))
}

fn take_protocol_operation(input: &mut &[u8]) -> Result<(ProtocolOperationV1, Vec<u8>), String> {
    let original = *input;
    if original.len() < 5 {
        return Err("truncated embedded authority operation in punishment evidence".into());
    }
    let op_type = u16::from_be_bytes(original[0..2].try_into().unwrap());
    let op_version = u16::from_be_bytes(original[2..4].try_into().unwrap());
    let mut cursor = &original[4..];
    let payload_len = read_varuint(&mut cursor).map_err(|e| e.to_string())?;
    let payload_len =
        usize::try_from(payload_len).map_err(|_| "embedded authority operation length overflow")?;
    let prefix_len = original.len() - cursor.len();
    if cursor.len() < payload_len {
        return Err("truncated embedded authority operation payload".into());
    }
    let total = prefix_len
        .checked_add(payload_len)
        .ok_or("embedded authority operation length overflow")?;
    let bytes = original[..total].to_vec();
    let payload = cursor[..payload_len].to_vec();
    *input = &original[total..];
    let op = ProtocolOperationV1 {
        op_type,
        op_version,
        payload,
    };
    if op.encode() != bytes {
        return Err("embedded authority operation is not canonical".into());
    }
    Ok((op, bytes))
}

struct AuthorityEvidenceFields {
    license_id: LicenseId,
    owner_sequence: u32,
    mining_sequence: u32,
    digest: [u8; 32],
    signature: [u8; 64],
}

fn authority_evidence_fields(op: &ProtocolOperationV1) -> Result<AuthorityEvidenceFields, String> {
    match op.op_type {
        OP_LICENSE_TRANSFER => {
            let transfer = decode_license_transfer_operation(op)?;
            Ok(AuthorityEvidenceFields {
                license_id: transfer.license_id,
                owner_sequence: transfer.expected_owner_sequence,
                mining_sequence: transfer.expected_mining_sequence,
                digest: transfer.signing_digest().0,
                signature: transfer.owner_signature,
            })
        }
        OP_LICENSE_MINING_KEY_ROTATE => {
            let rotation = decode_mining_key_rotation_operation(op)?;
            Ok(AuthorityEvidenceFields {
                license_id: rotation.license_id,
                owner_sequence: rotation.expected_owner_sequence,
                mining_sequence: rotation.expected_mining_sequence,
                digest: rotation.signing_digest().0,
                signature: rotation.owner_signature,
            })
        }
        _ => Err("Tier-2 evidence must embed transfer or mining-key-rotation operations".into()),
    }
}

fn validate_objective_evidence(
    state: &DevnetState,
    evidence: &PunishmentEvidenceV1,
) -> Result<bool, String> {
    match evidence.offense_type {
        OFFENSE_INVALID_SIGNED_WORK => {
            if evidence.evidence.len() != 4 + 272 {
                return Err(
                    "Tier-1 evidence must be mining_sequence:u32 + signed_header:272".into(),
                );
            }
            let mining_sequence = u32::from_be_bytes(evidence.evidence[..4].try_into().unwrap());
            let Some(core) = validate_signed_header(
                state,
                &evidence.accused_license_id,
                mining_sequence,
                &evidence.evidence[4..],
            )?
            else {
                return Ok(false);
            };
            let target: [u8; 32] = core[110..142].try_into().unwrap();
            let proof: [u8; 32] = core[176..208].try_into().unwrap();
            if proof_below_target(&proof, &target) {
                return Err(
                    "Tier-1 evidence does not prove invalid signed work: proof is below Target"
                        .into(),
                );
            }
        }
        OFFENSE_LICENSE_STATE_EQUIVOCATION => {
            let mut input = evidence.evidence.as_slice();
            let (a, a_bytes) = take_protocol_operation(&mut input)?;
            let (b, b_bytes) = take_protocol_operation(&mut input)?;
            if !input.is_empty() {
                return Err("Tier-2 evidence has trailing bytes".into());
            }
            if a_bytes >= b_bytes {
                return Err(
                    "Tier-2 embedded operations are not in strict canonical byte order".into(),
                );
            }
            let af = authority_evidence_fields(&a)?;
            let bf = authority_evidence_fields(&b)?;
            if af.license_id != evidence.accused_license_id
                || bf.license_id != evidence.accused_license_id
            {
                return Err(
                    "Tier-2 embedded operation LicenseID does not match accused LicenseID".into(),
                );
            }
            if af.owner_sequence != bf.owner_sequence || af.mining_sequence != bf.mining_sequence {
                return Err("Tier-2 operations do not consume the same authority sequence".into());
            }
            let Some(owner_key) = owner_key_at_sequences(
                state,
                &evidence.accused_license_id,
                af.owner_sequence,
                af.mining_sequence,
            )?
            else {
                return Ok(false);
            };
            let vk = VerifyingKey::from_bytes(&owner_key)
                .map_err(|_| "invalid historical owner public key in punishment evidence")?;
            vk.verify_strict(&af.digest, &Signature::from_bytes(&af.signature))
                .map_err(|_| "Tier-2 first owner signature is invalid")?;
            vk.verify_strict(&bf.digest, &Signature::from_bytes(&bf.signature))
                .map_err(|_| "Tier-2 second owner signature is invalid")?;
        }
        OFFENSE_SAME_TICKET_EQUIVOCATION => {
            if evidence.evidence.len() != 4 + 272 + 272 {
                return Err(
                    "Tier-3 evidence must be mining_sequence:u32 + two signed 272-byte headers"
                        .into(),
                );
            }
            let mining_sequence = u32::from_be_bytes(evidence.evidence[..4].try_into().unwrap());
            let a_bytes = &evidence.evidence[4..276];
            let b_bytes = &evidence.evidence[276..548];
            if a_bytes >= b_bytes {
                return Err("Tier-3 signed headers are not in strict canonical byte order".into());
            }
            let Some(a) = validate_signed_header(
                state,
                &evidence.accused_license_id,
                mining_sequence,
                a_bytes,
            )?
            else {
                return Ok(false);
            };
            let Some(b) = validate_signed_header(
                state,
                &evidence.accused_license_id,
                mining_sequence,
                b_bytes,
            )?
            else {
                return Ok(false);
            };
            if a == b {
                return Err("Tier-3 signed header cores are identical".into());
            }
            if a[6..14] != b[6..14]
                || a[110..142] != b[110..142]
                || a[142..174] != b[142..174]
                || a[174..176] != b[174..176]
                || a[176..208] != b[176..208]
            {
                return Err("Tier-3 headers do not share epoch/target/license/ticket/proof".into());
            }
            let target: [u8; 32] = a[110..142].try_into().unwrap();
            let proof: [u8; 32] = a[176..208].try_into().unwrap();
            if !proof_below_target(&proof, &target) {
                return Err(
                    "Tier-3 same-ticket evidence does not carry a below-target proof".into(),
                );
            }
        }
        _ => return Err("unknown punishment offense type".into()),
    }
    Ok(true)
}

pub(super) fn dependency_ready(
    state: &DevnetState,
    op: &ProtocolOperationV1,
) -> Result<bool, String> {
    let evidence = decode_punishment_operation(op)?;
    license_by_id(state, &evidence.accused_license_id)?;
    validate_objective_evidence(state, &evidence)
}

pub(super) fn apply_operation(
    state: &mut DevnetState,
    op: &ProtocolOperationV1,
    block_epoch: u64,
) -> Result<(), String> {
    let evidence = decode_punishment_operation(op)?;
    let evidence_id = evidence.evidence_id();
    let evidence_hex = hex::encode(evidence_id.0);
    if state.consumed_evidence.iter().any(|id| id == &evidence_hex) {
        return Err("EvidenceID has already been consumed".into());
    }
    if !validate_objective_evidence(state, &evidence)? {
        return Err("punishment evidence depends on a future authority sequence".into());
    }
    let license_index = state
        .licenses
        .iter()
        .position(|license| license.license_id == hex::encode(evidence.accused_license_id.0))
        .ok_or("punishment evidence references unknown LicenseID")?;
    if state.licenses[license_index].status == LICENSE_STATUS_REVOKED {
        return Err("punishment evidence targets an already revoked Mining License".into());
    }
    let weight = offense_weight(evidence.offense_type).map_err(|e| e.to_string())?;
    let mut record = state.licenses[license_index].record()?;
    let applied = apply_offense(&mut record, evidence.offense_type, block_epoch)
        .map_err(|e| e.to_string())?;
    state.licenses[license_index].status = record.status;
    state.licenses[license_index].strike_weight = record.strike_weight;
    state.licenses[license_index].suspended_until_epoch = record.suspended_until_epoch;
    state.licenses[license_index].revocation_epoch = record.revocation_epoch;
    state.consumed_evidence.push(evidence_hex.clone());
    state.offense_events.push(OffenseEventState {
        evidence_id: evidence_hex,
        license_id: hex::encode(evidence.accused_license_id.0),
        offense_type: evidence.offense_type,
        weight,
        applied_epoch: block_epoch,
        expiry_epoch: applied.offense_expiry_epoch,
    });
    state.consumed_evidence.sort();
    state
        .offense_events
        .sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));
    Ok(())
}

pub(super) fn expire_events(state: &mut DevnetState, epoch: u64) -> Result<(), String> {
    state
        .offense_events
        .retain(|event| event.expiry_epoch > epoch);
    let mut active_by_license = HashMap::<String, u8>::new();
    for event in &state.offense_events {
        let entry = active_by_license
            .entry(event.license_id.clone())
            .or_insert(0);
        *entry = entry
            .checked_add(event.weight)
            .ok_or("active strike weight overflow")?;
    }
    for license in &mut state.licenses {
        if license.status == LICENSE_STATUS_REVOKED {
            if license.strike_weight != REVOCATION_THRESHOLD {
                return Err("revoked Mining License strike weight is not capped at 16".into());
            }
            continue;
        }
        let active = active_by_license
            .get(&license.license_id)
            .copied()
            .unwrap_or(0);
        if active >= REVOCATION_THRESHOLD {
            return Err(
                "non-revoked Mining License has revocation-level active strike weight".into(),
            );
        }
        license.strike_weight = active;
    }
    Ok(())
}

pub(super) fn check_state(state: &DevnetState) -> Result<(), String> {
    let mut consumed = HashSet::new();
    for id in &state.consumed_evidence {
        decode32(id)?;
        if !consumed.insert(id.clone()) {
            return Err("duplicate consumed EvidenceID".into());
        }
    }
    let mut events = HashSet::new();
    let mut sums = HashMap::<String, u8>::new();
    for event in &state.offense_events {
        decode32(&event.evidence_id)?;
        decode32(&event.license_id)?;
        if !consumed.contains(&event.evidence_id) {
            return Err("active offense does not have a consumed EvidenceID".into());
        }
        if !events.insert(event.evidence_id.clone()) {
            return Err("duplicate active offense EvidenceID".into());
        }
        let expected_weight = offense_weight(event.offense_type).map_err(|e| e.to_string())?;
        if event.weight != expected_weight {
            return Err("active offense has wrong strike weight".into());
        }
        if event.expiry_epoch
            != event
                .applied_epoch
                .checked_add(STRIKE_DECAY_EPOCHS)
                .ok_or("offense expiry overflow")?
        {
            return Err("active offense expiry epoch is not AppliedEpoch + 2^21".into());
        }
        if event.expiry_epoch <= state.tip_epoch {
            return Err("expired offense remains in active ProtocolState".into());
        }
        if !state
            .licenses
            .iter()
            .any(|license| license.license_id == event.license_id)
        {
            return Err("active offense references unknown LicenseID".into());
        }
        let entry = sums.entry(event.license_id.clone()).or_insert(0);
        *entry = entry
            .checked_add(event.weight)
            .ok_or("active strike weight overflow")?;
    }
    for license in &state.licenses {
        if license.status == LICENSE_STATUS_REVOKED {
            if license.strike_weight != REVOCATION_THRESHOLD || license.revocation_epoch == 0 {
                return Err(
                    "revoked Mining License does not carry permanent strike/revocation state"
                        .into(),
                );
            }
        } else {
            let active = sums.get(&license.license_id).copied().unwrap_or(0);
            if license.strike_weight != active {
                return Err(
                    "Mining License strike weight does not equal active offense weight".into(),
                );
            }
            if license.revocation_epoch != 0 {
                return Err("non-revoked Mining License has revocation epoch".into());
            }
        }
    }
    Ok(())
}

fn fixture_public_key(variant: u32, tag: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&variant.to_be_bytes());
    seed[4] = tag;
    seed[31] = 0x51;
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

fn fixture_signed_header(
    state: &DevnetState,
    license_index: usize,
    variant: u32,
    tag: u8,
    target: [u8; 32],
    proof: [u8; 32],
) -> Result<[u8; 272], String> {
    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    let license_id = decode32(&license.license_id)?;
    let mut core = [0u8; 208];
    core[0..2].copy_from_slice(&1u16.to_be_bytes());
    core[2..6].copy_from_slice(&DEVNET_NETWORK_ID.to_be_bytes());
    let epoch = state
        .tip_epoch
        .saturating_add(1)
        .saturating_add(variant as u64);
    core[6..14].copy_from_slice(&epoch.to_be_bytes());
    core[14..46].copy_from_slice(&decode32(&state.tip_hash)?);
    let marker = variant.to_be_bytes();
    let tx_root = sha256_domain(
        domains::PUNISHMENT_EVIDENCE_ID,
        &[&license_id, &marker, &[tag], b"tx"],
    );
    let state_root = sha256_domain(
        domains::PUNISHMENT_EVIDENCE_ID,
        &[&license_id, &marker, &[tag], b"state"],
    );
    core[46..78].copy_from_slice(&tx_root.0);
    core[78..110].copy_from_slice(&state_root.0);
    core[110..142].copy_from_slice(&target);
    core[142..174].copy_from_slice(&license_id);
    core[174..176].copy_from_slice(&(variant as u16).to_be_bytes());
    core[176..208].copy_from_slice(&proof);
    let sk = dev_signing_key_for_license(license)
        .ok_or("local Devnet does not hold the accused Mining License private key")?;
    let signature = sk.sign(&block_signing_digest(&core).0).to_bytes();
    let mut header = [0u8; 272];
    header[..208].copy_from_slice(&core);
    header[208..].copy_from_slice(&signature);
    Ok(header)
}

pub(super) fn create_dev_operation(
    state: &DevnetState,
    license_index: usize,
    tier: u8,
    variant: u32,
) -> Result<ProtocolOperationV1, String> {
    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    if license.status == LICENSE_STATUS_REVOKED {
        return Err("cannot create Devnet evidence for a revoked Mining License".into());
    }
    let license_id = LicenseId(decode32(&license.license_id)?);
    let evidence = match tier {
        1 => {
            let header =
                fixture_signed_header(state, license_index, variant, 1, [0u8; 32], [0xffu8; 32])?;
            let mut body = Vec::with_capacity(276);
            body.extend_from_slice(&license.mining_key_sequence.to_be_bytes());
            body.extend_from_slice(&header);
            PunishmentEvidenceV1 {
                offense_type: OFFENSE_INVALID_SIGNED_WORK,
                accused_license_id: license_id,
                evidence: body,
            }
        }
        2 => {
            let owner_sk = dev_owner_signing_key_for_license(license)
                .ok_or("local Devnet does not hold the accused Mining License owner private key")?;
            let mut a = LicenseTransferV1 {
                license_id,
                expected_owner_sequence: license.owner_key_sequence,
                expected_mining_sequence: license.mining_key_sequence,
                new_owner_public_key: fixture_public_key(variant, 0x21),
                new_mining_public_key: fixture_public_key(variant, 0x22),
                owner_signature: [0u8; 64],
            };
            a.owner_signature = owner_sk.sign(&a.signing_digest().0).to_bytes();
            let mut b = LicenseTransferV1 {
                license_id,
                expected_owner_sequence: license.owner_key_sequence,
                expected_mining_sequence: license.mining_key_sequence,
                new_owner_public_key: fixture_public_key(variant, 0x23),
                new_mining_public_key: fixture_public_key(variant, 0x24),
                owner_signature: [0u8; 64],
            };
            b.owner_signature = owner_sk.sign(&b.signing_digest().0).to_bytes();
            let mut pair = [a.operation().encode(), b.operation().encode()];
            pair.sort();
            let mut body = pair[0].clone();
            body.extend_from_slice(&pair[1]);
            PunishmentEvidenceV1 {
                offense_type: OFFENSE_LICENSE_STATE_EQUIVOCATION,
                accused_license_id: license_id,
                evidence: body,
            }
        }
        3 => {
            let target = [0xffu8; 32];
            let proof = [0u8; 32];
            let a = fixture_signed_header(state, license_index, variant, 0x31, target, proof)?;
            let b = fixture_signed_header(state, license_index, variant, 0x32, target, proof)?;
            let mut pair = [a.to_vec(), b.to_vec()];
            pair.sort();
            let mut body = Vec::with_capacity(548);
            body.extend_from_slice(&license.mining_key_sequence.to_be_bytes());
            body.extend_from_slice(&pair[0]);
            body.extend_from_slice(&pair[1]);
            PunishmentEvidenceV1 {
                offense_type: OFFENSE_SAME_TICKET_EQUIVOCATION,
                accused_license_id: license_id,
                evidence: body,
            }
        }
        _ => return Err("--tier must be 1, 2, or 3".into()),
    };
    Ok(evidence.operation())
}

pub(super) fn operation_summary(
    op: &ProtocolOperationV1,
) -> Result<(String, u16, u8, String), String> {
    let evidence = decode_punishment_operation(op)?;
    Ok((
        hex::encode(evidence.evidence_id().0),
        evidence.offense_type,
        offense_weight(evidence.offense_type).map_err(|e| e.to_string())?,
        hex::encode(evidence.accused_license_id.0),
    ))
}
pub(super) fn queued_weight_for_license(
    state: &DevnetState,
    license_id: &str,
) -> Result<u8, String> {
    let mut total = 0u8;
    for pending in &state.pending_protocol_operations {
        let op = pending.operation()?;
        if op.op_type != OP_PUNISHMENT_EVIDENCE {
            continue;
        }
        let evidence = decode_punishment_operation(&op)?;
        if hex::encode(evidence.accused_license_id.0) == license_id {
            total = total
                .checked_add(offense_weight(evidence.offense_type).map_err(|e| e.to_string())?)
                .ok_or("queued punishment weight overflow")?;
        }
    }
    Ok(total)
}

pub(super) fn print_offenses(state: &DevnetState, license_index: usize) -> Result<(), String> {
    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    println!(
        "Mining License {:03} offenses — LicenseID {}",
        license.index as usize + 1,
        license.license_id
    );
    println!(
        "Status: {}",
        if license.status == LICENSE_STATUS_REVOKED {
            "REVOKED"
        } else if license.status == LICENSE_STATUS_PENDING {
            "PENDING"
        } else {
            "ACTIVE"
        }
    );
    println!("Active strike weight: {}", license.strike_weight);
    println!("Suspended until: {}", license.suspended_until_epoch);
    println!("Revoked at: {}", license.revocation_epoch);
    let mut rows = state
        .offense_events
        .iter()
        .filter(|event| event.license_id == license.license_id)
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));
    if rows.is_empty() {
        println!("No active offense events.");
    } else {
        for (i, event) in rows.iter().enumerate() {
            println!(
                "offense {:02}  evidence={}  type=0x{:04x}  weight={}  applied={}  expires={}",
                i + 1,
                event.evidence_id,
                event.offense_type,
                event.weight,
                event.applied_epoch,
                event.expiry_epoch,
            );
        }
    }
    println!(
        "Consumed EvidenceIDs (global): {}",
        state.consumed_evidence.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_state(tag: &str) -> (PathBuf, DevnetState) {
        let dir = std::env::temp_dir().join(format!("mutiny-build51-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        state.tip_epoch = 100;
        (dir, state)
    }

    #[test]
    fn build51_tier1_invalid_signed_work_suspends_for_64_epochs() {
        let (dir, mut state) = fresh_state("tier1");
        let op = create_dev_operation(&state, 2, 1, 0).unwrap();
        let evidence = decode_punishment_operation(&op).unwrap();
        assert_eq!(evidence.offense_type, OFFENSE_INVALID_SIGNED_WORK);
        assert_eq!(evidence.evidence.len(), 276);
        assert!(dependency_ready(&state, &op).unwrap());
        apply_operation(&mut state, &op, 101).unwrap();
        assert_eq!(state.licenses[2].strike_weight, 1);
        assert_eq!(state.licenses[2].suspended_until_epoch, 165);
        assert_eq!(state.consumed_evidence.len(), 1);
        assert_eq!(state.offense_events.len(), 1);
        assert_eq!(
            state.offense_events[0].expiry_epoch,
            101 + STRIKE_DECAY_EPOCHS
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build51_tier2_owner_equivocation_is_objectively_valid() {
        let (dir, mut state) = fresh_state("tier2");
        let op = create_dev_operation(&state, 2, 2, 7).unwrap();
        let evidence = decode_punishment_operation(&op).unwrap();
        assert_eq!(evidence.offense_type, OFFENSE_LICENSE_STATE_EQUIVOCATION);
        assert!(dependency_ready(&state, &op).unwrap());
        apply_operation(&mut state, &op, 101).unwrap();
        assert_eq!(state.licenses[2].strike_weight, 2);
        assert_eq!(state.licenses[2].suspended_until_epoch, 229);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build51_tier3_same_ticket_equivocation_has_shared_winning_ticket() {
        let (dir, mut state) = fresh_state("tier3");
        let op = create_dev_operation(&state, 2, 3, 9).unwrap();
        let evidence = decode_punishment_operation(&op).unwrap();
        assert_eq!(evidence.offense_type, OFFENSE_SAME_TICKET_EQUIVOCATION);
        assert_eq!(evidence.evidence.len(), 548);
        assert!(dependency_ready(&state, &op).unwrap());
        apply_operation(&mut state, &op, 101).unwrap();
        assert_eq!(state.licenses[2].strike_weight, 4);
        assert_eq!(state.licenses[2].suspended_until_epoch, 613);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build51_duplicate_evidence_id_is_permanently_rejected() {
        let (dir, mut state) = fresh_state("duplicate");
        let op = create_dev_operation(&state, 2, 1, 11).unwrap();
        apply_operation(&mut state, &op, 101).unwrap();
        let err = apply_operation(&mut state, &op, 102).unwrap_err();
        assert!(err.contains("already been consumed"));
        assert_eq!(state.consumed_evidence.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build51_four_tier3_offenses_revoke_and_cap_canonical_strikes_at_16() {
        let (dir, mut state) = fresh_state("revoke");
        let ops = (0..4)
            .map(|variant| create_dev_operation(&state, 2, 3, variant).unwrap())
            .collect::<Vec<_>>();
        for op in &ops {
            apply_operation(&mut state, op, 101).unwrap();
        }
        assert_eq!(state.licenses[2].status, LICENSE_STATUS_REVOKED);
        assert_eq!(state.licenses[2].strike_weight, REVOCATION_THRESHOLD);
        assert_eq!(state.licenses[2].revocation_epoch, 101);
        assert_eq!(state.consumed_evidence.len(), 4);
        assert_eq!(state.offense_events.len(), 4);
        expire_events(&mut state, 101 + STRIKE_DECAY_EPOCHS).unwrap();
        assert!(state.offense_events.is_empty());
        assert_eq!(state.licenses[2].status, LICENSE_STATUS_REVOKED);
        assert_eq!(state.licenses[2].strike_weight, REVOCATION_THRESHOLD);
        assert_eq!(state.consumed_evidence.len(), 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build51_offense_expires_exactly_at_two_to_21_epochs_without_erasing_consumption() {
        let (dir, mut state) = fresh_state("expiry");
        let op = create_dev_operation(&state, 2, 1, 3).unwrap();
        apply_operation(&mut state, &op, 101).unwrap();
        let expiry = 101 + STRIKE_DECAY_EPOCHS;
        expire_events(&mut state, expiry - 1).unwrap();
        assert_eq!(state.licenses[2].strike_weight, 1);
        assert_eq!(state.offense_events.len(), 1);
        expire_events(&mut state, expiry).unwrap();
        assert_eq!(state.licenses[2].strike_weight, 0);
        assert!(state.offense_events.is_empty());
        assert_eq!(state.consumed_evidence.len(), 1);
        assert_eq!(state.licenses[2].suspended_until_epoch, 165);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build51_protocol_state_root_commits_consumed_evidence_and_51_byte_offense_value() {
        let (dir, mut state) = fresh_state("root");
        let before = compute_protocol_state_root(&state, &state.utxos, 0, 0).unwrap();
        let op = create_dev_operation(&state, 2, 1, 4).unwrap();
        apply_operation(&mut state, &op, 101).unwrap();
        assert_eq!(state.offense_events[0].value_bytes().unwrap().len(), 51);
        let after = compute_protocol_state_root(&state, &state.utxos, 0, 0).unwrap();
        assert_ne!(before, after);
        state.tip_epoch = 101;
        refresh_current_state_root(&mut state).unwrap();
        check_state(&state).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
