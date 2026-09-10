use super::*;
use mutiny_bitcoin::{
    add_chainwork_be, bitcoin_header_work_be, header_meets_pow, validate_mainnet_header_rules,
    BitcoinHeader, BITCOIN_MAINNET_RETARGET_INTERVAL, REQUIRED_CONFIRMATIONS,
};
#[cfg(test)]
use mutiny_bitcoin::{double_sha256, mine_easy_header};
use mutiny_protocol::{
    BitcoinHeadersV1, MAINNET_GENESIS_BLOCK_V1, MAINNET_GENESIS_ID, MAINNET_NETWORK_ID,
    TESTNET_NETWORK_ID,
};
use mutiny_state::{
    BitcoinBestChainStateV1, BitcoinHeaderStateV1, PS_BITCOIN_BEST_CHAIN, PS_BITCOIN_HEADER,
};

pub(super) const PACK_M_BTC_DISABLE_EPOCH: u64 = 2_101_248;
pub(super) const PACK_J_ANCHOR_HEIGHT: u32 = 800_352;
pub(super) const PACK_J_ANCHOR_HASH_INTERNAL: [u8; 32] = [
    0xfb, 0xa9, 0xfc, 0xcc, 0xdc, 0xbc, 0x07, 0xdb, 0x8a, 0x1e, 0x11, 0x66, 0xcc, 0x84, 0xa3, 0x86,
    0xca, 0x5e, 0xd1, 0x54, 0xee, 0x28, 0x24, 0xbc, 0x2b, 0x6e, 0x80, 0x15, 0x05, 0x21, 0xd7, 0x5d,
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct BitcoinHeaderStateStored {
    pub(super) block_hash_internal: String,
    pub(super) height: u32,
    pub(super) raw_header: String,
    pub(super) relative_chainwork: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct BitcoinBestChainStored {
    pub(super) tip_hash_internal: String,
    pub(super) tip_height: u32,
    pub(super) tip_relative_chainwork: String,
}

fn decode80(text: &str) -> Result<[u8; 80], String> {
    let bytes = hex::decode(text).map_err(|e| e.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "stored Bitcoin raw header must be exactly 80 bytes".to_string())
}

fn stored_header_consensus(
    stored: &BitcoinHeaderStateStored,
) -> Result<BitcoinHeaderStateV1, String> {
    let value = BitcoinHeaderStateV1 {
        version: 1,
        height: stored.height,
        raw_header: decode80(&stored.raw_header)?,
        relative_chainwork: decode32(&stored.relative_chainwork)?,
    };
    if !value.validate() {
        return Err("stored BitcoinHeaderState version mismatch".into());
    }
    Ok(value)
}

fn stored_best_consensus(
    stored: &BitcoinBestChainStored,
) -> Result<BitcoinBestChainStateV1, String> {
    let value = BitcoinBestChainStateV1 {
        version: 1,
        best_tip_hash_internal: decode32(&stored.tip_hash_internal)?,
        best_tip_height: stored.tip_height,
        best_tip_relative_chainwork: decode32(&stored.tip_relative_chainwork)?,
    };
    if !value.validate() {
        return Err("stored BitcoinBestChainState version mismatch".into());
    }
    Ok(value)
}

const MAINNET_BTC_TREASURY_SCRIPT: &[u8] = &[
    0x00, 0x20, 0xf4, 0x4c, 0x44, 0x95, 0x40, 0x4a, 0x17, 0x3f, 0xb7, 0x8c, 0x31, 0xe1, 0xa3, 0x96,
    0x5d, 0xd9, 0xbf, 0x59, 0x68, 0x73, 0xa4, 0x96, 0x94, 0xfb, 0x4c, 0xbf, 0x26, 0xa8, 0xf2, 0xc8,
    0x2c, 0x29,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BitcoinHeaderValidationPolicy {
    DevnetFixedBits(u32),
    Mainnet,
}

const MAINNET_PACK_J_ANCHOR_HEIGHT: u32 = 963_648;
const MAINNET_PACK_J_CONTEXT_START_HEIGHT: u32 = MAINNET_PACK_J_ANCHOR_HEIGHT - 10;
const MAINNET_GENESIS_HEADER_OFFSET: usize = 19;

fn mainnet_pack_j_context_header(height: u32) -> Option<BitcoinHeader> {
    if !(MAINNET_PACK_J_CONTEXT_START_HEIGHT..=MAINNET_PACK_J_ANCHOR_HEIGHT).contains(&height) {
        return None;
    }

    let index = usize::try_from(height.checked_sub(MAINNET_PACK_J_CONTEXT_START_HEIGHT)?).ok()?;
    let start = MAINNET_GENESIS_HEADER_OFFSET.checked_add(index.checked_mul(80)?)?;
    let end = start.checked_add(80)?;

    let raw: [u8; 80] = MAINNET_GENESIS_BLOCK_V1.get(start..end)?.try_into().ok()?;

    Some(BitcoinHeader { raw })
}

fn policy_anchor_height(policy: BitcoinHeaderValidationPolicy) -> u32 {
    match policy {
        BitcoinHeaderValidationPolicy::DevnetFixedBits(_) => PACK_J_ANCHOR_HEIGHT,
        BitcoinHeaderValidationPolicy::Mainnet => MAINNET_PACK_J_ANCHOR_HEIGHT,
    }
}

fn policy_anchor_hash_internal(policy: BitcoinHeaderValidationPolicy) -> Result<[u8; 32], String> {
    match policy {
        BitcoinHeaderValidationPolicy::DevnetFixedBits(_) => Ok(PACK_J_ANCHOR_HASH_INTERNAL),

        BitcoinHeaderValidationPolicy::Mainnet => {
            mainnet_pack_j_context_header(MAINNET_PACK_J_ANCHOR_HEIGHT)
                .map(|header| header.hash_internal())
                .ok_or("locked Mainnet Genesis Bitcoin anchor context is unavailable".into())
        }
    }
}

fn build_header_index(
    headers: &[BitcoinHeaderStateStored],
) -> Result<HashMap<[u8; 32], (u32, BitcoinHeader)>, String> {
    let mut index = HashMap::<[u8; 32], (u32, BitcoinHeader)>::new();

    for stored in headers {
        let hash = decode32(&stored.block_hash_internal)?;
        let header = BitcoinHeader {
            raw: decode80(&stored.raw_header)?,
        };

        if header.hash_internal() != hash {
            return Err("stored Bitcoin header hash does not match raw header".into());
        }

        if index.insert(hash, (stored.height, header)).is_some() {
            return Err("duplicate authenticated Bitcoin header hash".into());
        }
    }

    Ok(index)
}

fn parent_metadata(
    headers: &[BitcoinHeaderStateStored],
    previous: [u8; 32],
    policy: BitcoinHeaderValidationPolicy,
) -> Result<(u32, [u8; 32]), String> {
    let anchor_hash = policy_anchor_hash_internal(policy)?;

    if previous == anchor_hash {
        return Ok((policy_anchor_height(policy), [0u8; 32]));
    }

    let previous_hex = hex::encode(previous);

    let parent = headers
        .iter()
        .find(|row| row.block_hash_internal == previous_hex)
        .ok_or(
            "Bitcoin header parent is not the locked anchor or authenticated post-anchor state",
        )?;

    Ok((parent.height, decode32(&parent.relative_chainwork)?))
}

fn mainnet_lineage_header_at_height(
    index: &HashMap<[u8; 32], (u32, BitcoinHeader)>,
    mut current_hash: [u8; 32],
    mut current_height: u32,
    target_height: u32,
) -> Result<BitcoinHeader, String> {
    if target_height < MAINNET_PACK_J_CONTEXT_START_HEIGHT {
        return Err(
            "Mainnet Bitcoin ancestry requires unavailable pre-Genesis anchor context".into(),
        );
    }

    if current_height < target_height {
        return Err("Mainnet Bitcoin ancestry target is above the current lineage".into());
    }

    loop {
        let current = if current_height <= MAINNET_PACK_J_ANCHOR_HEIGHT {
            let header = mainnet_pack_j_context_header(current_height)
                .ok_or("required Mainnet Genesis Bitcoin context header is unavailable")?;

            if header.hash_internal() != current_hash {
                return Err("Mainnet Genesis Bitcoin context lineage hash mismatch".into());
            }

            header
        } else {
            let (stored_height, header) = index
                .get(&current_hash)
                .ok_or("Mainnet Bitcoin ancestry references missing authenticated header")?;

            if *stored_height != current_height {
                return Err("Mainnet Bitcoin ancestry height mismatch".into());
            }

            header.clone()
        };

        if current_height == target_height {
            return Ok(current);
        }

        current_hash = current.previous_block_internal();
        current_height = current_height
            .checked_sub(1)
            .ok_or("Mainnet Bitcoin ancestry height underflow")?;
    }
}

fn validate_header_for_policy(
    index: &HashMap<[u8; 32], (u32, BitcoinHeader)>,
    policy: BitcoinHeaderValidationPolicy,
    header: &BitcoinHeader,
    next_height: u32,
    parent_height: u32,
) -> Result<[u8; 32], String> {
    match policy {
        BitcoinHeaderValidationPolicy::DevnetFixedBits(bits) => {
            if header.bits() != bits {
                return Err("Devnet BITCOIN_HEADERS nBits mismatch".into());
            }

            if !header_meets_pow(header).map_err(|e| e.to_string())? {
                return Err("Devnet BITCOIN_HEADERS proof of work is invalid".into());
            }

            bitcoin_header_work_be(header.bits()).map_err(|e| e.to_string())
        }

        BitcoinHeaderValidationPolicy::Mainnet => {
            if next_height <= MAINNET_PACK_J_ANCHOR_HEIGHT {
                return Err(
                    "Mainnet BITCOIN_HEADERS cannot replace or precede the locked Genesis anchor"
                        .into(),
                );
            }

            if parent_height.checked_add(1) != Some(next_height) {
                return Err("Mainnet Bitcoin candidate height does not follow its parent".into());
            }

            let parent_hash = header.previous_block_internal();

            let parent_header =
                mainnet_lineage_header_at_height(index, parent_hash, parent_height, parent_height)?;

            let first_mtp_height = next_height
                .checked_sub(11)
                .ok_or("Mainnet Bitcoin candidate is too low for MTP-11")?;

            if first_mtp_height < MAINNET_PACK_J_CONTEXT_START_HEIGHT {
                return Err(
                    "Mainnet Bitcoin MTP-11 requires unavailable pre-anchor context".into(),
                );
            }

            let mut previous_timestamps = [0u32; 11];

            for (slot, height) in (first_mtp_height..=parent_height).enumerate() {
                previous_timestamps[slot] =
                    mainnet_lineage_header_at_height(index, parent_hash, parent_height, height)?
                        .timestamp();
            }

            let first_period_timestamp = if next_height % BITCOIN_MAINNET_RETARGET_INTERVAL == 0 {
                let first_period_height = next_height
                    .checked_sub(BITCOIN_MAINNET_RETARGET_INTERVAL)
                    .ok_or("Mainnet Bitcoin retarget height underflow")?;

                mainnet_lineage_header_at_height(
                    index,
                    parent_hash,
                    parent_height,
                    first_period_height,
                )?
                .timestamp()
            } else {
                parent_header.timestamp()
            };

            validate_mainnet_header_rules(
                header,
                next_height,
                parent_header.bits(),
                first_period_timestamp,
                parent_header.timestamp(),
                &previous_timestamps,
            )
            .map_err(|e| e.to_string())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BitcoinTuplePolicy {
    pub(super) header_validation: BitcoinHeaderValidationPolicy,
    pub(super) treasury_script_pubkey: Option<&'static [u8]>,
    pub(super) ordinary_purchase_active: bool,
}

/// Resolves the exact Pack-M policy for a locked Mutiny
/// `(NetworkID, GenesisID)` tuple.
///
/// Build 6.6D Candidate 1 recognizes:
///
/// - the locked Devnet tuple with inherited synthetic Bitcoin fixtures;
/// - the formally locked corrected Mainnet tuple for authenticated
///   Bitcoin Mainnet header validation only.
///
/// Ordinary Mainnet BTC purchases remain explicitly inactive and the
/// Mainnet Treasury script remains unassigned in this candidate.
/// Testnet remains fail-closed.
pub(super) fn resolve_tuple_policy(
    network_id: u32,
    genesis_id: &[u8; 32],
) -> Option<BitcoinTuplePolicy> {
    if network_id == DEVNET_NETWORK_ID && *genesis_id == decode32(DEVNET_GENESIS_ID_HEX).ok()? {
        return Some(BitcoinTuplePolicy {
            header_validation: BitcoinHeaderValidationPolicy::DevnetFixedBits(DEVNET_BTC_BITS),
            treasury_script_pubkey: Some(DEVNET_BTC_TREASURY_SCRIPT),
            ordinary_purchase_active: true,
        });
    }

    if network_id == MAINNET_NETWORK_ID && *genesis_id == MAINNET_GENESIS_ID {
        return Some(BitcoinTuplePolicy {
            header_validation: BitcoinHeaderValidationPolicy::Mainnet,
            treasury_script_pubkey: Some(MAINNET_BTC_TREASURY_SCRIPT),
            ordinary_purchase_active: true,
        });
    }

    if network_id == MAINNET_NETWORK_ID || network_id == TESTNET_NETWORK_ID {
        return None;
    }

    None
}

pub(super) fn apply_operation(
    state: &mut DevnetState,
    op: &ProtocolOperationV1,
    block_epoch: u64,
) -> Result<(), String> {
    if block_epoch >= PACK_M_BTC_DISABLE_EPOCH {
        return Err("BITCOIN_HEADERS is disabled beginning Mutiny epoch 2,101,248".into());
    }
    check_state(state)?;
    let state_genesis_id = decode32(&state.genesis_hash)?;
    let policy = resolve_tuple_policy(state.network_id, &state_genesis_id)
        .ok_or("BITCOIN_HEADERS is inactive for this Mutiny NetworkID/GenesisID tuple")?;
    let batch = BitcoinHeadersV1::from_operation(op).map_err(|e| e.to_string())?;
    if batch.network_id != state.network_id {
        return Err("BITCOIN_HEADERS NetworkID mismatch".into());
    }
    if batch.genesis_id != state_genesis_id {
        return Err("BITCOIN_HEADERS GenesisID mismatch".into());
    }

    let mut headers = state.bitcoin_headers.clone();
    let mut best = state.bitcoin_best_chain.clone();
    let mut header_index = build_header_index(&headers)?;

    for raw in batch.headers {
        let header = BitcoinHeader { raw };

        let hash = header.hash_internal();
        let hash_hex = hex::encode(hash);

        if let Some(existing) = headers
            .iter()
            .find(|row| row.block_hash_internal == hash_hex)
        {
            if existing.raw_header != hex::encode(raw) {
                return Err(
                    "Bitcoin header hash collision maps to different raw header bytes".into(),
                );
            }
            continue;
        }

        let (parent_height, parent_work) = parent_metadata(
            &headers,
            header.previous_block_internal(),
            policy.header_validation,
        )?;

        let height = parent_height
            .checked_add(1)
            .ok_or("Bitcoin header height overflow")?;

        let header_work = validate_header_for_policy(
            &header_index,
            policy.header_validation,
            &header,
            height,
            parent_height,
        )?;

        let relative_chainwork =
            add_chainwork_be(&parent_work, &header_work).map_err(|e| e.to_string())?;

        headers.push(BitcoinHeaderStateStored {
            block_hash_internal: hash_hex.clone(),
            height,
            raw_header: hex::encode(raw),
            relative_chainwork: hex::encode(relative_chainwork),
        });

        header_index.insert(hash, (height, header.clone()));

        let should_switch = match &best {
            Some(current) => relative_chainwork > decode32(&current.tip_relative_chainwork)?,
            None => true,
        };

        if should_switch {
            best = Some(BitcoinBestChainStored {
                tip_hash_internal: hash_hex,
                tip_height: height,
                tip_relative_chainwork: hex::encode(relative_chainwork),
            });
        }
    }

    headers.sort_by(|a, b| a.block_hash_internal.cmp(&b.block_hash_internal));
    let mut candidate = state.clone();
    candidate.bitcoin_headers = headers;
    candidate.bitcoin_best_chain = best;
    check_state(&candidate)?;
    state.bitcoin_headers = candidate.bitcoin_headers;
    state.bitcoin_best_chain = candidate.bitcoin_best_chain;
    Ok(())
}

#[derive(Debug, Clone)]
pub(super) struct AuthenticatedPurchaseWindow {
    pub(super) containing_header: BitcoinHeader,
    pub(super) sixth_header: BitcoinHeader,
    pub(super) payment_mtp: u32,
}

const PACK_J_CONTEXT_START_HEIGHT: u32 = PACK_J_ANCHOR_HEIGHT - 10;
const PACK_J_CONTEXT_START_TIMESTAMP: u32 = 1_799_994_000;

fn pack_j_context_timestamp(height: u32) -> Option<u32> {
    if !(PACK_J_CONTEXT_START_HEIGHT..=PACK_J_ANCHOR_HEIGHT).contains(&height) {
        return None;
    }
    PACK_J_CONTEXT_START_TIMESTAMP.checked_add(
        height
            .checked_sub(PACK_J_CONTEXT_START_HEIGHT)?
            .checked_mul(600)?,
    )
}

fn best_chain_hashes_by_height(state: &DevnetState) -> Result<HashMap<u32, [u8; 32]>, String> {
    check_state(state)?;
    let best = state
        .bitcoin_best_chain
        .as_ref()
        .ok_or("BTC purchase requires authenticated BITCOIN_BEST_CHAIN state")?;
    let mut current = decode32(&best.tip_hash_internal)?;
    let mut by_height = HashMap::<u32, [u8; 32]>::new();

    loop {
        let current_hex = hex::encode(current);
        let row = state
            .bitcoin_headers
            .iter()
            .find(|row| row.block_hash_internal == current_hex)
            .ok_or("Bitcoin best-chain ancestry references missing authenticated header")?;
        if by_height.insert(row.height, current).is_some() {
            return Err("Bitcoin best-chain ancestry repeats a height".into());
        }
        let header = BitcoinHeader {
            raw: decode80(&row.raw_header)?,
        };
        let previous = header.previous_block_internal();
        if previous == PACK_J_ANCHOR_HASH_INTERNAL {
            by_height.insert(PACK_J_ANCHOR_HEIGHT, PACK_J_ANCHOR_HASH_INTERNAL);
            break;
        }
        current = previous;
    }

    Ok(by_height)
}

fn authenticated_best_header_at_height(
    state: &DevnetState,
    best_by_height: &HashMap<u32, [u8; 32]>,
    height: u32,
) -> Result<BitcoinHeader, String> {
    if height <= PACK_J_ANCHOR_HEIGHT {
        return Err(
            "Pack-J context header raw bytes are not stored as post-anchor BITCOIN_HEADER state"
                .into(),
        );
    }
    let hash = best_by_height
        .get(&height)
        .ok_or("required Bitcoin height is not present on current authenticated best chain")?;
    let hash_hex = hex::encode(hash);
    let row = state
        .bitcoin_headers
        .iter()
        .find(|row| row.block_hash_internal == hash_hex)
        .ok_or("current Bitcoin best-chain height references missing authenticated header")?;
    Ok(BitcoinHeader {
        raw: decode80(&row.raw_header)?,
    })
}

pub(super) fn validate_purchase_window(
    state: &DevnetState,
    proof_headers: &[BitcoinHeader],
    containing_height: u32,
) -> Result<AuthenticatedPurchaseWindow, String> {
    if proof_headers.len() < REQUIRED_CONFIRMATIONS {
        return Err("Bitcoin SPV proof has fewer than six confirmations".into());
    }

    let best_by_height = best_chain_hashes_by_height(state)?;
    let best = state
        .bitcoin_best_chain
        .as_ref()
        .ok_or("BTC purchase requires authenticated BITCOIN_BEST_CHAIN state")?;
    let sixth_height = containing_height
        .checked_add(REQUIRED_CONFIRMATIONS as u32 - 1)
        .ok_or("Bitcoin sixth-confirmation height overflow")?;
    if best.tip_height < sixth_height {
        return Err(
            "current authenticated Bitcoin best tip has fewer than six confirmations".into(),
        );
    }

    for (i, proof_header) in proof_headers.iter().enumerate() {
        let offset = u32::try_from(i).map_err(|_| "Bitcoin proof header index overflow")?;
        let expected_height = containing_height
            .checked_add(offset)
            .ok_or("Bitcoin proof header height overflow")?;
        let hash = proof_header.hash_internal();
        let hash_hex = hex::encode(hash);
        let row = state
            .bitcoin_headers
            .iter()
            .find(|row| row.block_hash_internal == hash_hex)
            .ok_or("Bitcoin proof header is absent from authenticated BITCOIN_HEADER state")?;
        if row.height != expected_height || decode80(&row.raw_header)? != proof_header.raw {
            return Err(
                "Bitcoin proof header does not exactly match authenticated header state".into(),
            );
        }
        if i > 0 && proof_header.previous_block_internal() != proof_headers[i - 1].hash_internal() {
            return Err("Bitcoin proof headers are not contiguous".into());
        }
    }

    for i in 0..REQUIRED_CONFIRMATIONS {
        let height = containing_height
            .checked_add(i as u32)
            .ok_or("Bitcoin best-chain confirmation height overflow")?;
        let proof_hash = proof_headers[i].hash_internal();
        if best_by_height.get(&height).copied() != Some(proof_hash) {
            return Err(
                "Bitcoin purchase confirmation is not on the current authenticated best chain"
                    .into(),
            );
        }
    }

    let earliest_mtp_height = containing_height
        .checked_sub(10)
        .ok_or("Bitcoin containing height is too low for MTP-11")?;
    if earliest_mtp_height < PACK_J_CONTEXT_START_HEIGHT {
        return Err(
            "Bitcoin containing block predates the authenticated Pack-J MTP context".into(),
        );
    }

    let mut timestamps = Vec::with_capacity(11);
    for height in earliest_mtp_height..=containing_height {
        let timestamp = if height <= PACK_J_ANCHOR_HEIGHT {
            pack_j_context_timestamp(height)
                .ok_or("Bitcoin MTP-11 requires unavailable pre-anchor Pack-J context")?
        } else {
            authenticated_best_header_at_height(state, &best_by_height, height)?.timestamp()
        };
        timestamps.push(timestamp);
    }
    timestamps.sort_unstable();
    let payment_mtp = timestamps[5];

    Ok(AuthenticatedPurchaseWindow {
        containing_header: proof_headers[0].clone(),
        sixth_header: proof_headers[REQUIRED_CONFIRMATIONS - 1].clone(),
        payment_mtp,
    })
}

pub(super) fn insert_protocol_state_entries(
    state: &DevnetState,
    entries: &mut BTreeMap<[u8; 32], [u8; 32]>,
) -> Result<(), String> {
    for stored in &state.bitcoin_headers {
        let block_hash = decode32(&stored.block_hash_internal)?;
        let value = stored_header_consensus(stored)?;
        let key = protocol_state_key(PS_BITCOIN_HEADER, &block_hash);
        let leaf = protocol_state_leaf(&key.0, &value.encode());
        if entries.insert(key.0, leaf.0).is_some() {
            return Err("duplicate BITCOIN_HEADER ProtocolState key".into());
        }
    }
    if let Some(stored) = &state.bitcoin_best_chain {
        let value = stored_best_consensus(stored)?;
        let key = protocol_state_key(PS_BITCOIN_BEST_CHAIN, &[0u8; 32]);
        let leaf = protocol_state_leaf(&key.0, &value.encode());
        if entries.insert(key.0, leaf.0).is_some() {
            return Err("duplicate BITCOIN_BEST_CHAIN ProtocolState key".into());
        }
    }
    Ok(())
}

pub(super) fn check_state(state: &DevnetState) -> Result<(), String> {
    let has_authenticated_bitcoin_state =
        !state.bitcoin_headers.is_empty() || state.bitcoin_best_chain.is_some();
    let policy = if has_authenticated_bitcoin_state {
        let genesis_id = decode32(&state.genesis_hash)?;
        Some(
            resolve_tuple_policy(state.network_id, &genesis_id)
                .ok_or("authenticated Bitcoin header state is inactive for this Mutiny NetworkID/GenesisID tuple")?,
        )
    } else {
        None
    };
    let mut rows = HashMap::<[u8; 32], &BitcoinHeaderStateStored>::new();
    for stored in &state.bitcoin_headers {
        let hash = decode32(&stored.block_hash_internal)?;
        if rows.insert(hash, stored).is_some() {
            return Err("duplicate authenticated Bitcoin header hash".into());
        }
        let raw = decode80(&stored.raw_header)?;
        let header = BitcoinHeader { raw };
        if header.hash_internal() != hash {
            return Err("stored Bitcoin header hash does not match raw header".into());
        }
        decode32(&stored.relative_chainwork)?;
    }

    let header_index = build_header_index(&state.bitcoin_headers)?;

    if rows.is_empty() {
        if state.bitcoin_best_chain.is_some() {
            return Err("Bitcoin best-chain singleton exists without authenticated headers".into());
        }
        return Ok(());
    }

    let resolved_policy = policy
        .expect("authenticated Bitcoin state always has a resolved policy")
        .header_validation;

    let anchor_hash = policy_anchor_hash_internal(resolved_policy)?;
    let anchor_height = policy_anchor_height(resolved_policy);

    let mut validated = HashSet::<[u8; 32]>::new();

    loop {
        let before = validated.len();

        for (hash, stored) in &rows {
            if validated.contains(hash) {
                continue;
            }

            let header = BitcoinHeader {
                raw: decode80(&stored.raw_header)?,
            };

            let previous = header.previous_block_internal();

            let (parent_height, parent_work) = if previous == anchor_hash {
                (anchor_height, [0u8; 32])
            } else {
                let Some(parent) = rows.get(&previous) else {
                    continue;
                };

                if !validated.contains(&previous) {
                    continue;
                }

                (parent.height, decode32(&parent.relative_chainwork)?)
            };

            let expected_height = parent_height
                .checked_add(1)
                .ok_or("Bitcoin header height overflow")?;

            let header_work = validate_header_for_policy(
                &header_index,
                resolved_policy,
                &header,
                expected_height,
                parent_height,
            )?;

            let expected_work =
                add_chainwork_be(&parent_work, &header_work).map_err(|e| e.to_string())?;

            if stored.height != expected_height {
                return Err(
                    "stored Bitcoin header height does not match authenticated parent".into(),
                );
            }
            if decode32(&stored.relative_chainwork)? != expected_work {
                return Err(
                    "stored Bitcoin relative chainwork does not match authenticated parent".into(),
                );
            }
            validated.insert(*hash);
        }
        if validated.len() == rows.len() {
            break;
        }
        if validated.len() == before {
            return Err(
                "stored Bitcoin header state contains unknown-parent or cyclic lineage".into(),
            );
        }
    }

    let best = state
        .bitcoin_best_chain
        .as_ref()
        .ok_or("authenticated Bitcoin headers require BITCOIN_BEST_CHAIN singleton")?;
    let best_hash = decode32(&best.tip_hash_internal)?;
    let best_row = rows
        .get(&best_hash)
        .ok_or("Bitcoin best-chain tip is not present in authenticated header state")?;
    if best.tip_height != best_row.height
        || decode32(&best.tip_relative_chainwork)? != decode32(&best_row.relative_chainwork)?
    {
        return Err("Bitcoin best-chain singleton metadata does not match tip header state".into());
    }
    let max_work = rows
        .values()
        .map(|row| decode32(&row.relative_chainwork))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or("missing Bitcoin header work")?;
    if decode32(&best.tip_relative_chainwork)? != max_work {
        return Err("Bitcoin best-chain singleton is not a greatest-work authenticated tip".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    const RAW: [&str; 6] = [
        "01000000fba9fcccdcbc07db8a1e1166cc84a386ca5ed154ee2824bc2b6e80150521d75d5033651fbfd182bc9fe3f587494ef41d6cf7d9e83e1dfbab6a5ce8160fae391e58d4496bffff7f2000000000",
        "010000004a0042407c83e3a11ab888a970349373cadd32d9a5dde968f8e4f25612f1960989bf5dca10a465a78c133bdac9dd2c8544b1e1a58187e22e86ec8fe632ee1a24b0d6496bffff7f2003000000",
        "01000000bbe5cc968a01d463c128c7541a7a550c52a49f642e3a7d0c5edc1232848f33258cff64ac05b34fb7ddb5b722918353f710707e56b7a1e48a3ccb0373b585821008d9496bffff7f2002000000",
        "010000009263013f4f360222c2c2d3f77f50fe889d100b0c4f5bb92cdc8ac1e77d8cb256ce2818c74c5f5b2aeb4d91ff1e44685f40aaf27812add4d2db92460cedb71eea60db496bffff7f2004000000",
        "01000000315bd66962b7d7a011557e4f42ba51aa45d08a304a8b0130d991e04f0ff60138df392887a51635cc79f01c00eee0016b5bd72e545bafea7dcc8fc7371d5835b7b8dd496bffff7f2005000000",
        "01000000a2970f2d4c46e10e8ffc45b5618a9bddbd6810820190c613a9a8c454aeb55779e87cf812f59ee6e88f217411ad2c4f5f8e10c0e8fbf7e5f270f922bc4d0680f510e0496bffff7f2006000000"
    ];

    fn raw80(s: &str) -> [u8; 80] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn locked_state() -> DevnetState {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build66a-c2-header-state-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_build54_genesis_devnet(&dir, 1, true).unwrap();
        let state = load_state(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
        state
    }

    fn operation(count: usize) -> ProtocolOperationV1 {
        BitcoinHeadersV1 {
            network_id: DEVNET_NETWORK_ID,
            genesis_id: decode32(DEVNET_GENESIS_ID_HEX).unwrap(),
            headers: RAW[..count].iter().map(|s| raw80(s)).collect(),
        }
        .to_operation()
        .unwrap()
    }

    #[test]
    fn build66d_candidate1_tuple_policy_is_exact_and_fail_closed() {
        let devnet_genesis = decode32(DEVNET_GENESIS_ID_HEX).unwrap();

        let devnet = resolve_tuple_policy(DEVNET_NETWORK_ID, &devnet_genesis).unwrap();

        assert_eq!(
            devnet.header_validation,
            BitcoinHeaderValidationPolicy::DevnetFixedBits(DEVNET_BTC_BITS)
        );
        assert_eq!(
            devnet.treasury_script_pubkey,
            Some(DEVNET_BTC_TREASURY_SCRIPT)
        );
        assert!(devnet.ordinary_purchase_active);

        let mainnet = resolve_tuple_policy(MAINNET_NETWORK_ID, &MAINNET_GENESIS_ID).unwrap();

        assert_eq!(
            mainnet.header_validation,
            BitcoinHeaderValidationPolicy::Mainnet
        );
        assert_eq!(
            mainnet.treasury_script_pubkey,
            Some(MAINNET_BTC_TREASURY_SCRIPT)
        );
        assert_eq!(MAINNET_BTC_TREASURY_SCRIPT.len(), 34);
        assert_eq!(
            hex::encode(MAINNET_BTC_TREASURY_SCRIPT),
            "0020f44c4495404a173fb78c31e1a3965dd9bf596873a49694fb4cbf26a8f2c82c29"
        );
        assert!(mainnet.ordinary_purchase_active);

        let mut wrong_mainnet = MAINNET_GENESIS_ID;
        wrong_mainnet[31] ^= 1;

        assert!(resolve_tuple_policy(MAINNET_NETWORK_ID, &wrong_mainnet).is_none());

        assert!(resolve_tuple_policy(MAINNET_NETWORK_ID, &devnet_genesis).is_none());

        assert!(resolve_tuple_policy(TESTNET_NETWORK_ID, &MAINNET_GENESIS_ID).is_none());

        assert!(resolve_tuple_policy(0x4d55_54ff, &devnet_genesis).is_none());

        let mut wrong_devnet = devnet_genesis;
        wrong_devnet[31] ^= 1;

        assert!(resolve_tuple_policy(DEVNET_NETWORK_ID, &wrong_devnet).is_none());
    }

    #[test]
    fn pack_m_candidate3_devnet_true_work_preserves_frozen_value_two() {
        assert_eq!(
            bitcoin_header_work_be(DEVNET_BTC_BITS).unwrap(),
            decode32("0000000000000000000000000000000000000000000000000000000000000002").unwrap()
        );
    }

    #[test]
    fn pack_m_candidate2_one_header_persists_exact_metadata() {
        let mut state = locked_state();
        apply_operation(&mut state, &operation(1), 1000).unwrap();
        assert_eq!(state.bitcoin_headers.len(), 1);
        let row = &state.bitcoin_headers[0];
        assert_eq!(
            row.block_hash_internal,
            "4a0042407c83e3a11ab888a970349373cadd32d9a5dde968f8e4f25612f19609"
        );
        assert_eq!(row.height, 800_353);
        assert_eq!(row.relative_chainwork, format!("{:064x}", 2u8));
        let best = state.bitcoin_best_chain.as_ref().unwrap();
        assert_eq!(best.tip_hash_internal, row.block_hash_internal);
        assert_eq!(best.tip_height, 800_353);
        assert_eq!(best.tip_relative_chainwork, row.relative_chainwork);
        check_state(&state).unwrap();
    }

    #[test]
    fn pack_m_candidate2_six_headers_commit_frozen_protocol_root() {
        let mut state = locked_state();
        apply_operation(&mut state, &operation(6), 1000).unwrap();
        let mut entries = BTreeMap::new();
        insert_protocol_state_entries(&state, &mut entries).unwrap();
        assert_eq!(
            sparse_root(&entries).0,
            decode32("b0de6e47c05087e0ccac0d680975d49cd24d5a078b0f9eeb76b0b130fe9c7317").unwrap()
        );
        assert_eq!(
            state.bitcoin_best_chain.as_ref().unwrap().tip_height,
            800_358
        );
        assert_eq!(
            state
                .bitcoin_best_chain
                .as_ref()
                .unwrap()
                .tip_relative_chainwork,
            format!("{:064x}", 12u8)
        );
    }

    #[test]
    fn pack_m_candidate2_wrong_network_genesis_parent_bits_and_sunset_fail_closed() {
        let mut state = locked_state();
        let wrong_network = BitcoinHeadersV1 {
            network_id: DEVNET_NETWORK_ID ^ 1,
            genesis_id: decode32(DEVNET_GENESIS_ID_HEX).unwrap(),
            headers: vec![raw80(RAW[0])],
        }
        .to_operation()
        .unwrap();
        assert!(apply_operation(&mut state, &wrong_network, 1000).is_err());

        let wrong_genesis = BitcoinHeadersV1 {
            network_id: DEVNET_NETWORK_ID,
            genesis_id: [0u8; 32],
            headers: vec![raw80(RAW[0])],
        }
        .to_operation()
        .unwrap();
        assert!(apply_operation(&mut state, &wrong_genesis, 1000).is_err());

        let orphan = BitcoinHeadersV1 {
            network_id: DEVNET_NETWORK_ID,
            genesis_id: decode32(DEVNET_GENESIS_ID_HEX).unwrap(),
            headers: vec![raw80(RAW[1])],
        }
        .to_operation()
        .unwrap();
        assert!(apply_operation(&mut state, &orphan, 1000).is_err());

        let mut bad_bits = raw80(RAW[0]);
        bad_bits[72..76].copy_from_slice(&0x1d00_ffffu32.to_le_bytes());
        let bad_bits_op = BitcoinHeadersV1 {
            network_id: DEVNET_NETWORK_ID,
            genesis_id: decode32(DEVNET_GENESIS_ID_HEX).unwrap(),
            headers: vec![bad_bits],
        }
        .to_operation()
        .unwrap();
        assert!(apply_operation(&mut state, &bad_bits_op, 1000).is_err());
        assert!(apply_operation(&mut state, &operation(1), PACK_M_BTC_DISABLE_EPOCH).is_err());
    }

    #[test]
    fn pack_m_candidate2_equal_work_keeps_best_and_greater_side_branch_switches() {
        let mut state = locked_state();
        apply_operation(&mut state, &operation(1), 1000).unwrap();
        let original_best = state
            .bitcoin_best_chain
            .as_ref()
            .unwrap()
            .tip_hash_internal
            .clone();

        let marker = double_sha256(b"MUTINY-PACK-M-CANDIDATE2-EQUAL-WORK-SIBLING");
        let sibling = mine_easy_header(
            PACK_J_ANCHOR_HASH_INTERNAL,
            marker,
            1_800_061_000,
            DEVNET_BTC_BITS,
            100,
        )
        .unwrap();
        let sibling_hash = sibling.hash_internal();
        let sibling_op = BitcoinHeadersV1 {
            network_id: DEVNET_NETWORK_ID,
            genesis_id: decode32(DEVNET_GENESIS_ID_HEX).unwrap(),
            headers: vec![sibling.raw],
        }
        .to_operation()
        .unwrap();
        apply_operation(&mut state, &sibling_op, 1001).unwrap();
        assert_eq!(
            state.bitcoin_best_chain.as_ref().unwrap().tip_hash_internal,
            original_best
        );

        let child = mine_easy_header(
            sibling_hash,
            double_sha256(b"MUTINY-PACK-M-CANDIDATE2-GREATER-WORK-CHILD"),
            1_800_061_600,
            DEVNET_BTC_BITS,
            200,
        )
        .unwrap();
        let child_hash = child.hash_internal();
        let child_op = BitcoinHeadersV1 {
            network_id: DEVNET_NETWORK_ID,
            genesis_id: decode32(DEVNET_GENESIS_ID_HEX).unwrap(),
            headers: vec![child.raw],
        }
        .to_operation()
        .unwrap();
        apply_operation(&mut state, &child_op, 1002).unwrap();
        assert_eq!(
            state.bitcoin_best_chain.as_ref().unwrap().tip_hash_internal,
            hex::encode(child_hash)
        );
        assert_eq!(
            state
                .bitcoin_best_chain
                .as_ref()
                .unwrap()
                .tip_relative_chainwork,
            format!("{:064x}", 4u8)
        );
    }

    #[test]
    fn build66b_candidate1_pack_j_mtp_context_is_exact() {
        assert_eq!(pack_j_context_timestamp(800_342), Some(1_799_994_000));
        assert_eq!(pack_j_context_timestamp(800_352), Some(1_800_000_000));
        assert_eq!(pack_j_context_timestamp(800_341), None);
    }

    #[test]
    fn build66d_candidate1_mainnet_genesis_anchor_context_is_exact() {
        assert_eq!(MAINNET_PACK_J_CONTEXT_START_HEIGHT, 963_638);
        assert_eq!(MAINNET_PACK_J_ANCHOR_HEIGHT, 963_648);
        assert_eq!(MAINNET_PACK_J_ANCHOR_HEIGHT % 2016, 0);

        let mut timestamps = Vec::new();

        for height in 963_638..=963_648 {
            let header = mainnet_pack_j_context_header(height).unwrap();
            timestamps.push(header.timestamp());
        }

        assert!(mainnet_pack_j_context_header(963_637).is_none());
        assert!(mainnet_pack_j_context_header(963_649).is_none());

        let anchor = mainnet_pack_j_context_header(963_648).unwrap();

        assert_eq!(
            hex::encode(anchor.hash_internal()),
            "322d839f2a0d04631b7b40dda2a85a455b7f329a9d7601000000000000000000"
        );
        assert_eq!(anchor.bits(), 0x1702_3cc1);
        assert_eq!(anchor.timestamp(), 1_787_446_127);

        timestamps.sort_unstable();
        assert_eq!(timestamps[5], 1_787_440_810);

        let index = HashMap::new();

        let oldest =
            mainnet_lineage_header_at_height(&index, anchor.hash_internal(), 963_648, 963_638)
                .unwrap();

        assert_eq!(oldest.timestamp(), 1_787_435_994);

        let (height, work) = parent_metadata(
            &[],
            anchor.hash_internal(),
            BitcoinHeaderValidationPolicy::Mainnet,
        )
        .unwrap();

        assert_eq!(height, 963_648);
        assert_eq!(work, [0u8; 32]);
    }

    #[test]
    fn build66d_candidate1_first_post_anchor_rules_use_locked_mtp_and_bits() {
        let anchor = mainnet_pack_j_context_header(963_648).unwrap();

        let index = HashMap::new();

        let mut raw = [0u8; 80];
        raw[4..36].copy_from_slice(&anchor.hash_internal());

        raw[68..72].copy_from_slice(&1_787_440_810u32.to_le_bytes());
        raw[72..76].copy_from_slice(&0x1702_3cc1u32.to_le_bytes());

        let mtp_violation = BitcoinHeader { raw };

        assert!(validate_header_for_policy(
            &index,
            BitcoinHeaderValidationPolicy::Mainnet,
            &mtp_violation,
            963_649,
            963_648,
        )
        .is_err());

        let mut wrong_bits_raw = raw;
        wrong_bits_raw[68..72].copy_from_slice(&1_787_440_811u32.to_le_bytes());
        wrong_bits_raw[72..76].copy_from_slice(&0x1702_353du32.to_le_bytes());

        let wrong_bits = BitcoinHeader {
            raw: wrong_bits_raw,
        };

        assert!(validate_header_for_policy(
            &index,
            BitcoinHeaderValidationPolicy::Mainnet,
            &wrong_bits,
            963_649,
            963_648,
        )
        .is_err());
    }
}
