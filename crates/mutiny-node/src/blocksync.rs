use super::*;

const MAX_HEADERS_PER_RESPONSE: u16 = 256;
const MAX_BLOCK_TXS: u64 = 1025;
// Build 6.2 Hotfix1: compatibility persistent sync shares the locked Build 6.1
// full-duplex receive envelope. The live hardening policy permits 512 frames per
// 10-second receive window and a 20-second expensive-response horizon, so the
// compatibility waiter must tolerate up to two full receive windows while still
// retaining a finite anti-stall bound.
const MAX_PERSISTENT_INTERLEAVED_FRAMES: usize = 1024;

#[derive(Debug, Clone)]
pub(super) struct SyncReport {
    pub downloaded_blocks: usize,
    pub applied_blocks: usize,
    pub reorg: bool,
    pub common_ancestor_height: u64,
    pub disconnected_blocks: usize,
    pub restored_mempool: usize,
    pub decision: String,
}

impl SyncReport {
    fn no_change(height: u64, decision: impl Into<String>) -> Self {
        Self {
            downloaded_blocks: 0,
            applied_blocks: 0,
            reorg: false,
            common_ancestor_height: height,
            disconnected_blocks: 0,
            restored_mempool: 0,
            decision: decision.into(),
        }
    }
}

fn take_array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], String> {
    if input.len() < N {
        return Err("unexpected end of block/header payload".into());
    }
    let (head, tail) = input.split_at(N);
    *input = tail;
    Ok(head.try_into().expect("length checked"))
}

fn reset_for_replay(template: &DevnetState) -> Result<DevnetState, String> {
    let mut replay = template.clone();
    replay.height = 0;
    replay.tip_hash = replay.genesis_hash.clone();
    replay.tip_epoch = 0;
    replay.anchor_epoch = 0;
    replay.anchor_license_id = hex::encode([0u8; 32]);
    replay.anchor_ticket_index = 0;
    replay.anchor_argon2_proof = replay.genesis_hash.clone();
    replay.total_issued_strikes = 0;
    replay.difficulty_history_count = 0;
    replay.difficulty_history_bitmap = 0;
    replay.difficulty_correction_q32 = DIFFICULTY_Q32_ONE;
    replay.base_fee_rate_q32 = BASE_FEE_MIN_Q32;
    if replay.format_version >= 10 {
        replay.licenses.clear();
    } else {
        replay.licenses = bootstrap_license_states();
    }
    replay.consumed_native_payments.clear();
    replay.consumed_bitcoin_payments.clear();
    replay.consumed_evidence.clear();
    replay.offense_events.clear();
    replay.treasury_reserved_dividend_strikes = 0;
    replay.dividend_accounts.clear();
    replay.historical_license_keys.clear();
    replay.mining_presence.clear();
    replay.bitcoin_headers.clear();
    replay.bitcoin_best_chain = None;
    replay.utxos.clear();
    replay.mempool.clear();
    replay.pending_protocol_operations.clear();
    replay.confirmed_transactions.clear();
    replay.blocks.clear();
    replay.side_branches.clear();
    refresh_current_state_root(&mut replay)?;
    Ok(replay)
}

fn replay_canonical_blocks(
    template: &DevnetState,
    blocks: &[BlockState],
) -> Result<DevnetState, String> {
    let mut replay = reset_for_replay(template)?;
    for block in blocks {
        let payload = encode_block_payload(block)?;
        let (header, txs, operations) = decode_block_payload(&payload)?;
        validate_and_apply_block(&mut replay, header, txs, operations)?;
    }
    Ok(replay)
}

fn common_ancestor_height(a: &DevnetState, b: &DevnetState) -> u64 {
    let common = a
        .blocks
        .iter()
        .zip(b.blocks.iter())
        .take_while(|(left, right)| left.block_hash == right.block_hash)
        .count();
    common as u64
}

fn archive_branch(
    target: &mut DevnetState,
    source: &DevnetState,
    fork_height: u64,
) -> Result<(), String> {
    if source.height <= fork_height {
        return Ok(());
    }
    let start = usize::try_from(fork_height).map_err(|_| "fork height overflow")?;
    let suffix = source
        .blocks
        .get(start..)
        .ok_or("fork suffix outside block vector")?
        .to_vec();
    if suffix.is_empty() {
        return Ok(());
    }
    let tip_hash = source.tip_hash.clone();
    if target.side_branches.iter().any(|b| b.tip_hash == tip_hash) {
        return Ok(());
    }
    let branch = SideBranchState {
        fork_height,
        tip_height: source.height,
        tip_hash,
        chain_work: chainwork_hex(source)?,
        blocks: suffix,
    };
    target.side_branches.push(branch);
    if target.side_branches.len() > MAX_SIDE_BRANCHES {
        let excess = target.side_branches.len() - MAX_SIDE_BRANCHES;
        target.side_branches.drain(0..excess);
    }
    Ok(())
}

fn historical_authority_fee_ticket_matches(
    old_local: &DevnetState,
    op: &ProtocolOperationV1,
    tx: &TransactionV1,
) -> Result<bool, String> {
    let target =
        authority_operation_license_id(op)?.ok_or("authority operation has no target LicenseID")?;
    let opid = op.operation_id().to_hex();
    let Some(historical) = old_local
        .historical_license_keys
        .iter()
        .find(|h| h.operation_id == opid && h.license_id == hex::encode(target.0))
    else {
        return Ok(false);
    };
    let owner_public_key = decode32(&historical.owner_public_key)?;
    let expected_address = address_id(&owner_public_key).0;
    if tx.core.inputs.is_empty()
        || tx.core.outputs.is_empty()
        || tx.witnesses.len() != tx.core.inputs.len()
    {
        return Ok(false);
    }
    if tx.core.outputs[0].output_type != OUTPUT_PUBKEY_HASH
        || tx.core.outputs[0].amount_strikes != authority_fee_marker(&target.0)
        || tx.core.outputs[0].payload.as_slice() != &expected_address[..]
    {
        return Ok(false);
    }
    if tx.core.outputs.iter().any(|output| {
        output.output_type != OUTPUT_PUBKEY_HASH
            || output.payload.as_slice() != &expected_address[..]
    }) {
        return Ok(false);
    }

    // The historical snapshot is the pre-operation owner authority committed by the
    // orphaned block itself. Requiring every PKH witness to carry that exact public key
    // lets reorg restoration recover the original fee-ticket pairing without consulting
    // the newly adopted branch, whose owner address may have legitimately reverted.
    Ok(tx.witnesses.iter().all(|witness| {
        witness.witness_type == 0x01
            && witness.payload.len() == 96
            && witness.payload[..32] == owner_public_key
    }))
}

pub(super) fn refresh_pending_after_runtime_commit(
    accepted: &mut DevnetState,
    current: &DevnetState,
) -> Result<(), String> {
    // Include both newly admitted live work and transactions restored from a
    // disconnected branch by sync. The restoration path deduplicates and
    // revalidates every candidate against the accepted consensus state.
    let mut pending = current.clone();
    pending.mempool.extend(accepted.mempool.iter().cloned());
    pending
        .pending_protocol_operations
        .extend(accepted.pending_protocol_operations.iter().cloned());
    accepted.mempool.clear();
    accepted.pending_protocol_operations.clear();
    restore_reorg_mempool(accepted, &pending, current.height)?;
    // Historical reorg restoration intentionally omits presence. Live future
    // announcements remain useful, but must bind to the newly adopted key.
    let mut seen_presence = HashSet::new();
    for pending_op in &pending.pending_protocol_operations {
        let Ok(op) = pending_op.operation() else {
            continue;
        };
        if op.op_type != OP_MINING_PRESENCE || !pending_op.required_txid.is_empty() {
            continue;
        }
        let Ok(presence) = presence::decode_operation(&op) else {
            continue;
        };
        if presence.presence_epoch <= accepted.tip_epoch
            || presence::validate_operation_against_parent(accepted, &op, presence.presence_epoch)
                .is_err()
            || !seen_presence.insert(op.operation_id().0)
        {
            continue;
        }
        accepted
            .pending_protocol_operations
            .push(pending_op.clone());
    }
    Ok(())
}

fn restore_reorg_mempool(
    adopted: &mut DevnetState,
    old_local: &DevnetState,
    common_height: u64,
) -> Result<usize, String> {
    let mut candidates = old_local.mempool.clone();
    let mut op_candidates = old_local.pending_protocol_operations.clone();
    let start = usize::try_from(common_height).map_err(|_| "common height overflow")?;

    for block in old_local.blocks.iter().skip(start) {
        let decoded_txs = block
            .transactions
            .iter()
            .map(|raw| {
                let bytes = hex::decode(raw).map_err(|e| e.to_string())?;
                TransactionV1::decode_full(&bytes).map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, String>>()?;

        for tx in decoded_txs.iter().skip(1) {
            if tx
                .core
                .inputs
                .iter()
                .any(|i| matches!(i, TxInput::Coinbase { .. }))
            {
                continue;
            }
            let txid = tx.txid().to_hex();

            // Prefer the exact PendingTxState that was confirmed on the disconnected
            // branch. It preserves original fee and CLI ownership metadata even when
            // the adopted branch has reverted the license owner/payment address.
            if let Some(record) = old_local
                .confirmed_transactions
                .iter()
                .find(|record| record.block_hash == block.block_hash && record.tx.txid == txid)
            {
                candidates.push(record.tx.clone());
            } else if let Ok(pending) = pending_from_transaction(adopted, tx) {
                // Compatibility fallback for older persisted states that may not contain
                // a matching confirmed-transaction record.
                candidates.push(pending);
            }
        }

        for raw in &block.protocol_operations {
            let op = decode_protocol_operation_hex(raw)?;
            if op.op_version != 1 {
                continue;
            }
            let required_txid = match op.op_type {
                OP_LICENSE_PURCHASE_MUT => {
                    let purchase = decode_native_purchase_operation(&op)?;
                    Some(purchase.payment_txid.to_hex())
                }
                OP_LICENSE_TRANSFER | OP_LICENSE_MINING_KEY_ROTATE => {
                    decoded_txs.iter().skip(1).find_map(|tx| {
                        historical_authority_fee_ticket_matches(old_local, &op, tx)
                            .ok()
                            .filter(|matched| *matched)
                            .map(|_| tx.txid().to_hex())
                    })
                }
                OP_LICENSE_PURCHASE_BTC | OP_PUNISHMENT_EVIDENCE | OP_BITCOIN_HEADERS => {
                    Some(String::new())
                }
                OP_DIVIDEND_CLAIM => Some(
                    dividends::decode_claim_operation(&op)?
                        .payment_txid
                        .to_hex(),
                ),
                _ => None,
            };
            if let Some(required_txid) = required_txid {
                op_candidates.push(PendingProtocolOperationState {
                    operation: raw.clone(),
                    required_txid,
                });
            }
        }
    }

    let confirmed = adopted
        .confirmed_transactions
        .iter()
        .map(|r| r.tx.txid.clone())
        .collect::<HashSet<_>>();
    let protocol_bound_txids = op_candidates
        .iter()
        .filter(|op| !op.required_txid.is_empty())
        .map(|op| op.required_txid.as_str())
        .collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    let mut restored = 0usize;
    for pending in candidates {
        if confirmed.contains(&pending.txid) || !seen.insert(pending.txid.clone()) {
            continue;
        }
        if pending.has_license_payment_output()
            && !protocol_bound_txids.contains(pending.txid.as_str())
        {
            continue;
        }
        if validate_pending_candidate(adopted, &pending, true).is_ok() {
            adopted.mempool.push(pending);
            restored += 1;
        }
    }

    let mempool_txids = adopted
        .mempool
        .iter()
        .map(|tx| tx.txid.as_str())
        .collect::<HashSet<_>>();
    let consumed = adopted
        .consumed_native_payments
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    let mut seen_ops = adopted
        .pending_protocol_operations
        .iter()
        .filter_map(|pending| pending.operation().ok())
        .map(|op| op.operation_id().0)
        .collect::<HashSet<_>>();
    for pending_op in op_candidates {
        if !pending_op.required_txid.is_empty()
            && !mempool_txids.contains(pending_op.required_txid.as_str())
        {
            continue;
        }
        let op = pending_op.operation()?;
        if op.op_version != 1
            || !matches!(
                op.op_type,
                OP_LICENSE_PURCHASE_BTC
                    | OP_LICENSE_PURCHASE_MUT
                    | OP_LICENSE_TRANSFER
                    | OP_LICENSE_MINING_KEY_ROTATE
                    | OP_PUNISHMENT_EVIDENCE
                    | OP_DIVIDEND_CLAIM
                    | OP_BITCOIN_HEADERS
            )
        {
            continue;
        }
        if op.op_type == OP_LICENSE_PURCHASE_BTC {
            if !bitcoin::dependency_ready(adopted, &op)? {
                continue;
            }
        }
        if op.op_type == OP_LICENSE_PURCHASE_MUT {
            let purchase = decode_native_purchase_operation(&op)?;
            let payment_id =
                native_payment_id(&purchase.payment_txid, purchase.payment_output_index);
            if consumed.contains(&hex::encode(payment_id.0)) {
                continue;
            }
        }
        if op.op_type == OP_PUNISHMENT_EVIDENCE {
            let evidence = punishment::decode_punishment_operation(&op)?;
            let evidence_id = hex::encode(evidence.evidence_id().0);
            if adopted
                .consumed_evidence
                .iter()
                .any(|id| id == &evidence_id)
            {
                continue;
            }
        }
        if op.op_type == OP_DIVIDEND_CLAIM {
            let claim = dividends::decode_claim_operation(&op)?;
            let license_hex = hex::encode(claim.license_id.0);
            let Some(account) = adopted
                .dividend_accounts
                .iter()
                .find(|a| a.license_id == license_hex)
            else {
                continue;
            };
            if claim.amount_strikes == 0 || claim.amount_strikes > account.claimable_strikes {
                continue;
            }
        }
        if !seen_ops.insert(op.operation_id().0) {
            continue;
        }
        adopted.pending_protocol_operations.push(pending_op);
    }
    let bound_after = adopted
        .pending_protocol_operations
        .iter()
        .filter(|op| !op.required_txid.is_empty())
        .map(|op| op.required_txid.as_str())
        .collect::<HashSet<_>>();
    adopted
        .mempool
        .retain(|tx| !tx.has_protocol_auth_witness() || bound_after.contains(tx.txid.as_str()));
    Ok(restored)
}

pub(super) fn encode_block_payload(block: &BlockState) -> Result<Vec<u8>, String> {
    let header = hex::decode(&block.header).map_err(|e| e.to_string())?;
    if header.len() != 272 {
        return Err("stored block header is not exactly 272 bytes".into());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&header);
    write_varuint(&mut out, block.transactions.len() as u64);
    for raw in &block.transactions {
        let tx = hex::decode(raw).map_err(|e| e.to_string())?;
        // Decode/re-encode before serving so a corrupted local JSON record cannot be relayed
        // as a non-canonical transaction byte stream.
        let parsed = TransactionV1::decode_full(&tx).map_err(|e| e.to_string())?;
        if parsed.encode_full() != tx {
            return Err("stored transaction is not canonical Pack-B encoding".into());
        }
        out.extend_from_slice(&tx);
    }
    write_varuint(&mut out, block.protocol_operations.len() as u64);
    for raw in &block.protocol_operations {
        let bytes = hex::decode(raw).map_err(|e| e.to_string())?;
        let op = decode_protocol_operation_bytes(&bytes)?;
        if op.encode() != bytes {
            return Err("stored protocol operation is not canonical encoding".into());
        }
        out.extend_from_slice(&bytes);
    }
    if out.len() > mutiny_p2p::MAX_P2P_PAYLOAD as usize {
        return Err("encoded block exceeds P2P payload limit".into());
    }
    Ok(out)
}

pub(super) fn decode_block_payload(
    payload: &[u8],
) -> Result<([u8; 272], Vec<TransactionV1>, Vec<ProtocolOperationV1>), String> {
    let mut input = payload;
    let header = take_array::<272>(&mut input)?;
    let tx_count = read_varuint(&mut input).map_err(|e| e.to_string())?;
    if tx_count == 0 || tx_count > MAX_BLOCK_TXS {
        return Err("block transaction count outside integrated limits".into());
    }
    let mut txs = Vec::with_capacity(tx_count as usize);
    for _ in 0..tx_count {
        txs.push(TransactionV1::decode_from(&mut input).map_err(|e| e.to_string())?);
    }
    let op_count = read_varuint(&mut input).map_err(|e| e.to_string())?;
    if op_count > 1024 {
        return Err("protocol operation count exceeds V1 maximum 1024".into());
    }
    let mut operations = Vec::with_capacity(op_count as usize);
    for _ in 0..op_count {
        let op_type = u16::from_be_bytes(take_array::<2>(&mut input)?);
        let op_version = u16::from_be_bytes(take_array::<2>(&mut input)?);
        let payload_len = read_varuint(&mut input).map_err(|e| e.to_string())?;
        let payload_len = usize::try_from(payload_len)
            .map_err(|_| "protocol operation payload length overflow")?;
        if input.len() < payload_len {
            return Err("truncated protocol operation payload".into());
        }
        let payload_bytes = input[..payload_len].to_vec();
        input = &input[payload_len..];
        operations.push(ProtocolOperationV1 {
            op_type,
            op_version,
            payload: payload_bytes,
        });
    }
    protocol_operations_root(&operations).map_err(|e| e.to_string())?;
    if !input.is_empty() {
        return Err("trailing bytes after canonical block body".into());
    }
    Ok((header, txs, operations))
}

pub(super) fn advance_empty_epochs(
    state: &mut DevnetState,
    through_epoch: u64,
) -> Result<(), String> {
    if through_epoch <= state.tip_epoch {
        return Ok(());
    }
    while state.tip_epoch < through_epoch {
        state.tip_epoch += 1;
        apply_scheduled_license_transitions(state, state.tip_epoch)?;
        if difficulty_observation_enabled(state, state.tip_epoch) {
            append_difficulty_result(state, false)?;
        }
    }
    // Empty-epoch transitions never consume the intermediate StateRoot. Recomputing once
    // at the requested boundary is consensus-equivalent and makes long dividend-boundary
    // replay practical on Devnet.
    refresh_current_state_root(state)?;
    Ok(())
}

pub(super) fn pending_from_transaction(
    state: &DevnetState,
    tx: &TransactionV1,
) -> Result<PendingTxState, String> {
    if tx.core.version != 1 || tx.core.network_id != state.network_id {
        return Err("transaction version/network does not match selected state".into());
    }
    let inputs = tx
        .core
        .inputs
        .iter()
        .map(|input| match input {
            TxInput::Outpoint {
                previous_txid,
                previous_output_index,
            } => Ok(StoredTxInput {
                previous_txid: hex::encode(previous_txid),
                previous_output_index: *previous_output_index,
            }),
            TxInput::Coinbase { .. } => {
                Err("coinbase cannot be converted to ordinary pending transaction".into())
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let outputs = tx
        .core
        .outputs
        .iter()
        .map(|o| StoredTxOutput {
            amount_strikes: o.amount_strikes,
            output_type: o.output_type,
            payload: hex::encode(&o.payload),
        })
        .collect::<Vec<_>>();
    let witnesses = tx
        .witnesses
        .iter()
        .map(|w| StoredWitness {
            witness_type: w.witness_type,
            payload: hex::encode(&w.payload),
        })
        .collect::<Vec<_>>();

    let first_owner = inputs
        .first()
        .and_then(|i| {
            state
                .utxos
                .iter()
                .find(|u| u.txid == i.previous_txid && u.output_index == i.previous_output_index)
        })
        .and_then(|u| {
            state
                .licenses
                .iter()
                .position(|l| l.payment_address_id == u.payload)
        })
        .unwrap_or(0);
    let authority_target = authority_fee_ticket_license_index(state, tx);
    let metadata_owner = authority_target.unwrap_or(first_owner);
    let has_license_payment = tx
        .core
        .outputs
        .iter()
        .any(|o| o.output_type == OUTPUT_LICENSE_PAYMENT);
    let first_recipient = if has_license_payment {
        // A LICENSE_PAYMENT is Treasury-directed protocol value, not an ordinary recipient.
        // Preserve the payer license in CLI metadata when reconstructing after a reorg.
        metadata_owner
    } else if let Some(target) = authority_target {
        target
    } else {
        tx.core
            .outputs
            .first()
            .and_then(|o| {
                if o.output_type != OUTPUT_PUBKEY_HASH || o.payload.len() != 32 {
                    return None;
                }
                let p = hex::encode(&o.payload);
                state
                    .licenses
                    .iter()
                    .position(|l| l.payment_address_id == p)
            })
            .unwrap_or(0)
    };

    let input_sum = inputs.iter().try_fold(0u64, |acc, i| {
        match state
            .utxos
            .iter()
            .find(|u| u.txid == i.previous_txid && u.output_index == i.previous_output_index)
        {
            Some(u) => acc
                .checked_add(u.amount_strikes)
                .ok_or("input sum overflow"),
            None => Ok(acc),
        }
    })?;
    let output_sum = tx.core.outputs.iter().try_fold(0u64, |acc, o| {
        acc.checked_add(o.amount_strikes)
            .ok_or("output sum overflow")
    })?;
    let fee = input_sum.saturating_sub(output_sum);
    let protocol_authorized = tx
        .witnesses
        .iter()
        .any(|w| w.witness_type == mutiny_transaction::WITNESS_PROTOCOL_AUTH);
    let base_fee = if protocol_authorized {
        0
    } else {
        required_base_fee(state.base_fee_rate_q32, tx.serialized_len() as u64)
            .map_err(|e| e.to_string())?
    };

    Ok(PendingTxState {
        txid: tx.txid().to_hex(),
        wtxid: tx.wtxid().to_hex(),
        valid_from_epoch: tx.core.valid_from_epoch,
        expiry_epoch: tx.core.expiry_epoch,
        inputs,
        outputs,
        witnesses,
        fee_strikes: fee,
        base_fee_strikes: base_fee,
        from_license: u8::try_from(metadata_owner).unwrap_or(0),
        to_license: u8::try_from(first_recipient).unwrap_or(0),
        amount_strikes: tx
            .core
            .outputs
            .first()
            .map(|o| o.amount_strikes)
            .unwrap_or(0),
    })
}

pub(super) fn validate_and_apply_block(
    state: &mut DevnetState,
    header: [u8; 272],
    txs: Vec<TransactionV1>,
    operations: Vec<ProtocolOperationV1>,
) -> Result<String, String> {
    let runtime = runtime_for_state(state)?;
    if runtime == RuntimeNetwork::Mainnet && state.height == 0 {
        return Err(
            "Mainnet Genesis -> Block1 requires the authenticated runtime bootstrap route".into(),
        );
    }
    let mut next = state.clone();
    let core: [u8; 208] = header[..208].try_into().expect("fixed header length");
    let version = u16::from_be_bytes(core[0..2].try_into().unwrap());
    let network_id = u32::from_be_bytes(core[2..6].try_into().unwrap());
    let epoch = u64::from_be_bytes(core[6..14].try_into().unwrap());
    let parent: [u8; 32] = core[14..46].try_into().unwrap();
    let header_tx_root: [u8; 32] = core[46..78].try_into().unwrap();
    let header_state_root: [u8; 32] = core[78..110].try_into().unwrap();
    let header_target: [u8; 32] = core[110..142].try_into().unwrap();
    let license_id: [u8; 32] = core[142..174].try_into().unwrap();
    let ticket = u16::from_be_bytes(core[174..176].try_into().unwrap());
    let proof: [u8; 32] = core[176..208].try_into().unwrap();
    let signature: [u8; 64] = header[208..272].try_into().unwrap();

    if next.height == 0
        && operations.len() == 1
        && operations[0].op_type == mutiny_protocol::OP_BOOTSTRAP_COMMITMENT
        && operations[0].op_version == 1
    {
        return bootstrap::validate_and_apply_devnet_block1(state, header, txs, operations);
    }

    if version != 1 || network_id != state.network_id {
        return Err("block header version/network mismatch".into());
    }
    if epoch <= next.tip_epoch && next.height > 0 {
        return Err("block epoch is not greater than current tip epoch".into());
    }
    if next.height == 0 && epoch < ACTIVATION_DELAY_EPOCHS {
        return Err("block predates bootstrap license activation".into());
    }
    if parent != decode32(&next.tip_hash)? {
        return Err("block parent does not match local canonical tip".into());
    }

    if epoch > 0 {
        advance_empty_epochs(&mut next, epoch - 1)?;
    }
    apply_scheduled_license_transitions(&mut next, epoch)?;

    let license_index = next
        .licenses
        .iter()
        .position(|l| l.license_id == hex::encode(license_id))
        .ok_or("block LicenseID is not present in the local registry")?;
    if !next.licenses[license_index].is_eligible(epoch) {
        return Err("block LicenseID is not base-eligible at the candidate epoch".into());
    }
    presence::prevalidate_block_operations(&next, &operations, epoch)?;
    let eligible_count =
        presence::candidate_eligible_count(&next, epoch, &license_id, &operations)?;
    let w = work_units(eligible_count);
    if ticket >= w {
        return Err("block ticket index is outside Pack-K candidate W_E".into());
    }
    let a = authorized_capacity(eligible_count);
    let expected_target =
        derive_target(a, next.difficulty_correction_q32).map_err(|e| e.to_string())?;
    if header_target != expected_target {
        return Err("block target does not match locally derived target".into());
    }

    let anchor = if next.height == 0 {
        decode32(&next.genesis_hash)?
    } else {
        mutiny_crypto::anchor_entropy(
            next.anchor_epoch,
            &decode32(&next.anchor_license_id)?,
            next.anchor_ticket_index,
            &decode32(&next.anchor_argon2_proof)?,
        )
        .0
    };
    let es = epoch_seed(&anchor, epoch);
    let seed = ticket_seed(&es.0, &license_id, ticket);
    let salt = ticket_salt(&es.0, &license_id, ticket);
    let expected_proof = mutiny_argon2id(&seed.0, &salt.0)
        .map_err(|e| e.to_string())?
        .0;
    if proof != expected_proof {
        return Err("Argon2id proof does not match deterministic licensed ticket".into());
    }
    if !proof_below_target(&proof, &expected_target) {
        return Err("block proof is not below target".into());
    }

    let digest = block_signing_digest(&core);
    let mining_pk = decode32(&next.licenses[license_index].mining_public_key)?;
    let vk = VerifyingKey::from_bytes(&mining_pk)
        .map_err(|_| "invalid mining public key in license state")?;
    vk.verify_strict(&digest.0, &Signature::from_bytes(&signature))
        .map_err(|_| "invalid block mining signature")?;

    let calculated_hash = block_hash(&header).0;
    let calculated_hash_hex = hex::encode(calculated_hash);

    if txs.is_empty() {
        return Err("block has no coinbase transaction".into());
    }
    let leaves = txs.iter().map(TransactionV1::leaf).collect::<Vec<_>>();
    let tx_root = merkle_root(&leaves).ok_or("block has no transaction Merkle root")?;
    if tx_root.0 != header_tx_root {
        return Err("TransactionRoot mismatch".into());
    }
    let block_weight = block_body_weight(&txs, &operations)?;
    if block_weight > BLOCK_WEIGHT_MAX {
        return Err("block exceeds maximum body weight".into());
    }

    let height = next.height + 1;
    let ordinary = &txs[1..];
    let mut pending = Vec::with_capacity(ordinary.len());
    for tx in ordinary {
        pending.push(pending_from_transaction(&next, tx)?);
    }
    let mut tx_state = next.clone();
    tx_state.mempool = pending;
    let mut working_utxos = next.utxos.clone();
    let mut validated =
        validate_and_apply_mempool(&tx_state, &mut working_utxos, epoch, height, &operations)?;

    let mut total_fees = 0u64;
    let mut treasury_share = 0u64;
    for v in &mut validated {
        total_fees = total_fees.checked_add(v.fee).ok_or("fee overflow")?;
        treasury_share = treasury_share
            .checked_add(v.base_fee / 2)
            .ok_or("treasury fee overflow")?;
        v.pending.fee_strikes = v.fee;
        v.pending.base_fee_strikes = v.base_fee;
    }
    let reward = subsidy(epoch);
    let miner_fee_share = total_fees
        .checked_sub(treasury_share)
        .ok_or("fee split underflow")?;
    let miner_coinbase_amount = reward
        .checked_add(miner_fee_share)
        .ok_or("coinbase overflow")?;

    let coinbase = &txs[0];
    if coinbase.core.version != 1
        || coinbase.core.network_id != state.network_id
        || coinbase.core.valid_from_epoch != epoch
        || coinbase.core.expiry_epoch != 0
        || !coinbase.witnesses.is_empty()
    {
        return Err("coinbase core/witness fields are not canonical".into());
    }
    let commitment = match coinbase.core.inputs.as_slice() {
        [TxInput::Coinbase { commitment }] => commitment,
        _ => return Err("coinbase must have exactly one null-outpoint commitment input".into()),
    };
    let operation_root = protocol_operations_root(&operations).map_err(|e| e.to_string())?;
    if commitment.block_epoch != epoch
        || commitment.block_height != height
        || commitment.parent_block_hash != parent
        || commitment.protocol_operations_root != operation_root.0
    {
        return Err("coinbase commitment mismatch".into());
    }
    let mut expected_outputs = vec![TxOutput {
        amount_strikes: miner_coinbase_amount,
        output_type: OUTPUT_PUBKEY_HASH,
        payload: decode32(&next.licenses[license_index].payment_address_id)?.to_vec(),
    }];
    if treasury_share > 0 {
        expected_outputs.push(TxOutput {
            amount_strikes: treasury_share,
            output_type: OUTPUT_TREASURY,
            payload: treasury_id_for_network(state.network_id).to_vec(),
        });
    }
    if coinbase.core.outputs != expected_outputs {
        return Err("coinbase outputs do not exactly match subsidy + fee split".into());
    }
    add_outputs_as_utxos(&mut working_utxos, coinbase, epoch, height, true)?;

    let next_total_issued = next
        .total_issued_strikes
        .checked_add(reward)
        .ok_or("supply overflow")?;
    let mut next_history_count = next.difficulty_history_count;
    let mut next_history_bitmap = next.difficulty_history_bitmap;
    let mut next_correction = next.difficulty_correction_q32;
    if next.height > 0 {
        append_history_values(
            &mut next_history_count,
            &mut next_history_bitmap,
            &mut next_correction,
            true,
        )?;
    }
    let next_base_fee = adjusted_base_fee_rate(next.base_fee_rate_q32, block_weight)?;
    next.tip_epoch = epoch;
    apply_protocol_operations(&mut next, &txs, &operations, epoch)?;
    let calculated_state_root = compute_state_root(
        &next,
        &working_utxos,
        height,
        next_total_issued,
        next_history_count,
        next_history_bitmap,
        next_correction,
        next_base_fee,
    )?;
    if calculated_state_root != header_state_root {
        return Err(format!(
            "StateRoot mismatch: header={} local={}",
            hex::encode(header_state_root),
            hex::encode(calculated_state_root)
        ));
    }

    next.height = height;
    next.tip_epoch = epoch;
    next.tip_hash = calculated_hash_hex.clone();
    next.anchor_epoch = epoch;
    next.anchor_license_id = hex::encode(license_id);
    next.anchor_ticket_index = ticket;
    next.anchor_argon2_proof = hex::encode(proof);
    next.total_issued_strikes = next_total_issued;
    next.difficulty_history_count = next_history_count;
    next.difficulty_history_bitmap = next_history_bitmap;
    next.difficulty_correction_q32 = next_correction;
    next.base_fee_rate_q32 = next_base_fee;
    next.current_state_root = hex::encode(calculated_state_root);
    next.utxos = working_utxos;

    let confirmed_ids = validated
        .iter()
        .map(|v| v.pending.txid.clone())
        .collect::<HashSet<_>>();
    next.mempool.retain(|m| !confirmed_ids.contains(&m.txid));
    let confirmed_operation_bytes = operations
        .iter()
        .map(|op| hex::encode(op.encode()))
        .collect::<HashSet<_>>();
    next.pending_protocol_operations.retain(|pending| {
        !confirmed_ids.contains(&pending.required_txid)
            && !confirmed_operation_bytes.contains(&pending.operation)
    });
    let mut transaction_ids = Vec::new();
    for v in validated {
        transaction_ids.push(v.pending.txid.clone());
        next.confirmed_transactions.push(ConfirmedTxState {
            tx: v.pending,
            block_height: height,
            block_epoch: epoch,
            block_hash: calculated_hash_hex.clone(),
        });
    }
    next.blocks.push(BlockState {
        height,
        epoch,
        header: hex::encode(header),
        transactions: txs.iter().map(|tx| hex::encode(tx.encode_full())).collect(),
        protocol_operations: operations
            .iter()
            .map(|op| hex::encode(op.encode()))
            .collect(),
        block_hash: calculated_hash_hex.clone(),
        parent_hash: hex::encode(parent),
        miner_license_id: hex::encode(license_id),
        ticket_index: ticket,
        argon2_proof: hex::encode(proof),
        target: hex::encode(header_target),
        reward_strikes: reward,
        total_fees_strikes: total_fees,
        treasury_fee_share_strikes: treasury_share,
        block_weight,
        transaction_root: hex::encode(header_tx_root),
        state_root: hex::encode(header_state_root),
        coinbase_txid: coinbase.txid().to_hex(),
        transaction_ids,
    });

    *state = next;
    Ok(calculated_hash_hex)
}

/// C1C runtime boundary for the one authorized Mainnet Genesis -> Block-1
/// transition.  Local sidecar acquisition is deliberately distinct from a
/// received-block consensus failure; neither path mutates `state` before the
/// complete C1B staged transition has been accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RuntimeBlockApplyError {
    LocalBootstrapInput(String),
    ConsensusTransition(String),
}

impl std::fmt::Display for RuntimeBlockApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocalBootstrapInput(message) => write!(f, "LOCAL_BOOTSTRAP_INPUT: {message}"),
            Self::ConsensusTransition(message) => write!(f, "CONSENSUS_TRANSITION: {message}"),
        }
    }
}

pub(super) fn validate_and_apply_block_for_runtime(
    state: &mut DevnetState,
    header: [u8; 272],
    txs: Vec<TransactionV1>,
    operations: Vec<ProtocolOperationV1>,
    runtime: RuntimeNetwork,
    witness: Option<&mainnet_bootstrap::BootstrapWitnessProvider>,
) -> Result<String, RuntimeBlockApplyError> {
    validate_runtime_tuple(state, runtime).map_err(RuntimeBlockApplyError::ConsensusTransition)?;
    match runtime {
        RuntimeNetwork::Devnet => validate_and_apply_block(state, header, txs, operations)
            .map_err(RuntimeBlockApplyError::ConsensusTransition),
        RuntimeNetwork::Mainnet => {
            if state.network_id != MAINNET_NETWORK_ID
                || state.genesis_hash != hex::encode(MAINNET_GENESIS_ID)
            {
                return Err(RuntimeBlockApplyError::ConsensusTransition(
                    "selected Mainnet tuple does not match live state".into(),
                ));
            }
            if state.height != 0 {
                return validate_and_apply_block(state, header, txs, operations)
                    .map_err(RuntimeBlockApplyError::ConsensusTransition);
            }
            let provider = witness.ok_or_else(|| {
                RuntimeBlockApplyError::LocalBootstrapInput(
                    "--bootstrap-witness is required for Mainnet Genesis -> Block1".into(),
                )
            })?;
            let authenticated = provider
                .load()
                .map_err(|e| RuntimeBlockApplyError::LocalBootstrapInput(e.to_string()))?;
            let decoded = authenticated
                .decode()
                .map_err(|e| RuntimeBlockApplyError::LocalBootstrapInput(e.to_string()))?;
            let staged = mainnet_bootstrap::build_staged_mainnet_block1_transition(state, &decoded)
                .map_err(|e| RuntimeBlockApplyError::ConsensusTransition(format!("{e:?}")))?;
            mainnet_bootstrap::compare_received_mainnet_block1(&staged, &header, &txs, &operations)
                .map_err(|e| RuntimeBlockApplyError::ConsensusTransition(format!("{e:?}")))?;
            let accepted_hash = staged.state.tip_hash.clone();
            *state = staged.state;
            Ok(accepted_hash)
        }
    }
}

pub(super) fn encode_headers_response(
    state: &DevnetState,
    start_height: u64,
    requested_max: u16,
) -> Result<Vec<u8>, String> {
    let max = requested_max.clamp(1, MAX_HEADERS_PER_RESPONSE) as usize;
    let start = usize::try_from(start_height).map_err(|_| "start height overflow")?;
    let selected = if start >= state.blocks.len() {
        &state.blocks[state.blocks.len()..]
    } else {
        let end = (start + max).min(state.blocks.len());
        &state.blocks[start..end]
    };
    let mut out = Vec::new();
    out.extend_from_slice(&state.height.to_be_bytes());
    write_varuint(&mut out, selected.len() as u64);
    for block in selected {
        let header = hex::decode(&block.header).map_err(|e| e.to_string())?;
        if header.len() != 272 {
            return Err("stored header length mismatch".into());
        }
        out.extend_from_slice(&header);
    }
    Ok(out)
}

fn service_reverse_persistent_request(
    data_dir: &Path,
    stream: &mut TcpStream,
    frame: &Frame,
) -> Result<bool, String> {
    let response = match frame.message_type {
        MSG_GET_HEADERS => {
            let state = load_state(data_dir)?;
            let payload = serve_get_headers(&state, &frame.payload)?;
            Some(
                Frame::new(P2P_MAGIC_DEVNET, MSG_HEADERS, frame.request_id, payload)
                    .map_err(|e| e.to_string())?,
            )
        }
        MSG_GET_BLOCK => {
            let state = load_state(data_dir)?;
            let payload = serve_get_block(&state, &frame.payload)?;
            Some(
                Frame::new(P2P_MAGIC_DEVNET, MSG_BLOCK, frame.request_id, payload)
                    .map_err(|e| e.to_string())?,
            )
        }
        MSG_GET_ADDR => {
            // The compatibility sync path does not own the live node's peer registry, so
            // answer a reverse peer-discovery request with a canonical empty ADDR set.
            // This keeps the authenticated full-duplex RequestID lane alive without
            // inventing peer advertisements or changing Pack-H wire semantics.
            let mut payload = Vec::new();
            write_varuint(&mut payload, 0);
            Some(
                Frame::new(P2P_MAGIC_DEVNET, MSG_ADDR, frame.request_id, payload)
                    .map_err(|e| e.to_string())?,
            )
        }
        MSG_PING => Some(
            Frame::new(
                P2P_MAGIC_DEVNET,
                MSG_PONG,
                frame.request_id,
                frame.payload.clone(),
            )
            .map_err(|e| e.to_string())?,
        ),
        _ => None,
    };
    if let Some(response) = response {
        response.write_to(stream).map_err(|e| e.to_string())?;
        return Ok(true);
    }
    Ok(false)
}

fn read_expected_persistent_response(
    data_dir: &Path,
    stream: &mut TcpStream,
    expected_request_id: u64,
    expected_message_type: u16,
    label: &str,
) -> Result<Frame, String> {
    // Build 4.5.1+ runtime peers are genuinely full duplex: while this compatibility
    // caller waits for HEADERS/BLOCK, the peer may send RequestID-zero announcements
    // and may independently issue reverse GETHEADERS/GETBLOCK/GETADDR requests on the same
    // authenticated TCP connection. Ignore announcements and service the safe read-only
    // reverse requests inline. Build 6.2 Hotfix1 aligns this compatibility waiter with
    // the locked Build 6.1 receive envelope instead of the older 128-frame ceiling:
    // at most 1024 interleaved frames may be consumed across the inherited 20-second
    // expensive-response horizon. Both the frame bound and absolute deadline remain
    // finite so an untrusted peer cannot occupy a synchronous caller indefinitely.
    let deadline = Instant::now() + EXPENSIVE_REQUEST_RESPONSE_TIMEOUT;
    let mut interleaved_frames = 0usize;
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "peer exceeded response deadline while awaiting {label}"
            ));
        }
        let frame = Frame::read_from(stream, P2P_MAGIC_DEVNET).map_err(|e| e.to_string())?;
        if Instant::now() >= deadline {
            return Err(format!(
                "peer exceeded response deadline while awaiting {label}"
            ));
        }
        if frame.request_id == expected_request_id && frame.message_type == expected_message_type {
            return Ok(frame);
        }
        interleaved_frames = interleaved_frames.saturating_add(1);
        if interleaved_frames > MAX_PERSISTENT_INTERLEAVED_FRAMES {
            return Err(format!(
                "peer sent too many interleaved frames while awaiting {label}"
            ));
        }
        if frame.request_id == 0 {
            continue;
        }
        if service_reverse_persistent_request(data_dir, stream, &frame)? {
            continue;
        }
        return Err(format!(
            "peer returned unexpected frame while awaiting {label}: type={:#06x} request_id={}",
            frame.message_type, frame.request_id
        ));
    }
}

pub(super) fn decode_headers_response(payload: &[u8]) -> Result<(u64, Vec<[u8; 272]>), String> {
    let mut input = payload;
    let tip_height = u64::from_be_bytes(take_array::<8>(&mut input)?);
    let count = read_varuint(&mut input).map_err(|e| e.to_string())?;
    if count > MAX_HEADERS_PER_RESPONSE as u64 {
        return Err("HEADERS count exceeds Build 4 response cap".into());
    }
    let mut headers = Vec::with_capacity(count as usize);
    for _ in 0..count {
        headers.push(take_array::<272>(&mut input)?);
    }
    if !input.is_empty() {
        return Err("trailing bytes in HEADERS payload".into());
    }
    Ok((tip_height, headers))
}

fn request_headers(
    data_dir: &Path,
    sessions: &SessionRegistry,
    peer: &str,
    start_height: u64,
) -> Result<(u64, Vec<[u8; 272]>), String> {
    with_persistent_peer(data_dir, sessions, peer, |stream| {
        let mut payload = Vec::with_capacity(10);
        payload.extend_from_slice(&start_height.to_be_bytes());
        payload.extend_from_slice(&MAX_HEADERS_PER_RESPONSE.to_be_bytes());
        Frame::new(P2P_MAGIC_DEVNET, MSG_GET_HEADERS, 0x4001, payload)
            .map_err(|e| e.to_string())?
            .write_to(stream)
            .map_err(|e| e.to_string())?;
        let response =
            read_expected_persistent_response(data_dir, stream, 0x4001, MSG_HEADERS, "HEADERS")?;
        decode_headers_response(&response.payload)
    })
}

fn collect_remote_headers(
    data_dir: &Path,
    sessions: &SessionRegistry,
    peer: &str,
) -> Result<(u64, Vec<[u8; 272]>), String> {
    let (remote_height, first) = request_headers(data_dir, sessions, peer, 0)?;
    if remote_height == 0 {
        return Ok((0, Vec::new()));
    }
    let target = usize::try_from(remote_height).map_err(|_| "remote height overflow")?;
    let mut headers = first;
    while headers.len() < target {
        let start = headers.len() as u64;
        let (observed_height, more) = request_headers(data_dir, sessions, peer, start)?;
        if observed_height < remote_height {
            return Err(
                "peer height moved backward while collecting headers; retry synchronization".into(),
            );
        }
        if more.is_empty() {
            return Err(format!(
                "peer advertises height {remote_height} but stopped headers at {start}"
            ));
        }
        let need = target - headers.len();
        headers.extend(more.into_iter().take(need));
    }
    if headers.len() != target {
        return Err("remote header collection length mismatch".into());
    }
    Ok((remote_height, headers))
}

fn common_prefix_with_headers(state: &DevnetState, headers: &[[u8; 272]]) -> u64 {
    state
        .blocks
        .iter()
        .zip(headers.iter())
        .take_while(|(block, header)| block.block_hash == hex::encode(block_hash(header).0))
        .count() as u64
}

fn request_block(
    data_dir: &Path,
    sessions: &SessionRegistry,
    peer: &str,
    hash: [u8; 32],
) -> Result<([u8; 272], Vec<TransactionV1>, Vec<ProtocolOperationV1>), String> {
    with_persistent_peer(data_dir, sessions, peer, |stream| {
        Frame::new(P2P_MAGIC_DEVNET, MSG_GET_BLOCK, 0x4002, hash.to_vec())
            .map_err(|e| e.to_string())?
            .write_to(stream)
            .map_err(|e| e.to_string())?;
        let response =
            read_expected_persistent_response(data_dir, stream, 0x4002, MSG_BLOCK, "BLOCK")?;
        let decoded = decode_block_payload(&response.payload)?;
        if block_hash(&decoded.0).0 != hash {
            return Err("BLOCK response hash does not match request".into());
        }
        Ok(decoded)
    })
}

pub(super) fn reconcile_validated_remote(
    state: &mut DevnetState,
    mut remote: DevnetState,
    downloaded: usize,
) -> Result<SyncReport, String> {
    let fork_height = common_ancestor_height(state, &remote);
    let local_work = chainwork(state)?;
    let remote_work = chainwork(&remote)?;
    if remote_work <= local_work {
        archive_branch(state, &remote, fork_height)?;
        let decision = if remote_work == local_work {
            "KEPT_LOCAL_EQUAL_CHAINWORK"
        } else {
            "KEPT_LOCAL_MORE_CHAINWORK"
        };
        return Ok(SyncReport {
            downloaded_blocks: downloaded,
            applied_blocks: 0,
            reorg: false,
            common_ancestor_height: fork_height,
            disconnected_blocks: 0,
            restored_mempool: 0,
            decision: decision.into(),
        });
    }

    let old_local = state.clone();
    remote.side_branches = old_local.side_branches.clone();
    archive_branch(&mut remote, &old_local, fork_height)?;
    let restored = restore_reorg_mempool(&mut remote, &old_local, fork_height)?;
    let disconnected = usize::try_from(old_local.height.saturating_sub(fork_height))
        .map_err(|_| "disconnected block count overflow")?;
    let connected = usize::try_from(remote.height.saturating_sub(fork_height))
        .map_err(|_| "connected block count overflow")?;
    *state = remote;
    Ok(SyncReport {
        downloaded_blocks: downloaded,
        applied_blocks: connected,
        reorg: true,
        common_ancestor_height: fork_height,
        disconnected_blocks: disconnected,
        restored_mempool: restored,
        decision: "ADOPTED_REMOTE_MORE_CHAINWORK".into(),
    })
}

pub(super) fn sync_state_from_peer_persistent(
    data_dir: &Path,
    sessions: &SessionRegistry,
    peer: &str,
    state: &mut DevnetState,
) -> Result<SyncReport, String> {
    if runtime_for_state(state)? != RuntimeNetwork::Devnet {
        return Err(
            "Mainnet synchronization requires the runtime-bound authenticated duplex path".into(),
        );
    }
    let (remote_height, headers) = collect_remote_headers(data_dir, sessions, peer)?;
    if remote_height == 0 {
        return Ok(SyncReport::no_change(0, "REMOTE_GENESIS"));
    }

    let common = common_prefix_with_headers(state, &headers);
    let same_tip = remote_height == state.height
        && common == state.height
        && state
            .blocks
            .last()
            .is_some_and(|b| b.block_hash == hex::encode(block_hash(headers.last().unwrap()).0));
    if same_tip {
        return Ok(SyncReport::no_change(state.height, "SAME_CANONICAL_TIP"));
    }

    // Straight extension of our canonical block sequence. Local empty epochs after the last
    // block are provisional, so rewind those derived empty-epoch transitions before applying
    // a late but valid child of the canonical block tip.
    if common == state.height && remote_height > state.height {
        let old_height = state.height;
        let canonical_epoch = state.blocks.last().map(|b| b.epoch).unwrap_or(0);
        let mut candidate = if state.tip_epoch > canonical_epoch {
            let mut replay = replay_canonical_blocks(state, &state.blocks)?;
            replay.mempool = state.mempool.clone();
            replay.pending_protocol_operations = state.pending_protocol_operations.clone();
            replay.side_branches = state.side_branches.clone();
            replay
        } else {
            state.clone()
        };
        let mut downloaded = 0usize;
        for header in headers.into_iter().skip(old_height as usize) {
            let hash = block_hash(&header).0;
            let (wire_header, txs, operations) = request_block(data_dir, sessions, peer, hash)?;
            downloaded += 1;
            if wire_header != header {
                return Err("BLOCK header differs from prior HEADERS announcement".into());
            }
            validate_and_apply_block(&mut candidate, wire_header, txs, operations)?;
            println!(
                "Validated block {} from {peer}: {}",
                candidate.height, candidate.tip_hash
            );
        }
        let applied = usize::try_from(candidate.height - old_height)
            .map_err(|_| "applied block count overflow")?;
        *state = candidate;
        return Ok(SyncReport {
            downloaded_blocks: downloaded,
            applied_blocks: applied,
            reorg: false,
            common_ancestor_height: old_height,
            disconnected_blocks: 0,
            restored_mempool: 0,
            decision: "EXTENDED_CANONICAL_CHAIN".into(),
        });
    }

    // If the remote is merely an ancestor of our current canonical chain, there is nothing
    // to do. Exact chainwork ties also keep the already-adopted local branch.
    if common == remote_height && remote_height < state.height {
        return Ok(SyncReport::no_change(
            remote_height,
            "REMOTE_IS_CANONICAL_ANCESTOR",
        ));
    }

    // Fork: independently reconstruct the peer's entire advertised canonical branch from
    // Genesis. The peer's claimed StateRoot or balances are never trusted.
    let mut remote = reset_for_replay(state)?;
    let mut downloaded = 0usize;
    for header in headers {
        let hash = block_hash(&header).0;
        let (wire_header, txs, operations) = request_block(data_dir, sessions, peer, hash)?;
        downloaded += 1;
        if wire_header != header {
            return Err(
                "BLOCK header differs from prior HEADERS announcement during fork validation"
                    .into(),
            );
        }
        validate_and_apply_block(&mut remote, wire_header, txs, operations)?;
    }

    reconcile_validated_remote(state, remote, downloaded)
}

pub(super) fn validate_and_apply_announced_block(
    state: &mut DevnetState,
    header: [u8; 272],
    txs: Vec<TransactionV1>,
    operations: Vec<ProtocolOperationV1>,
    ingress: &RuntimeIngressContext,
) -> Result<String, RuntimeBlockApplyError> {
    validate_runtime_tuple(state, ingress.runtime)
        .map_err(RuntimeBlockApplyError::ConsensusTransition)?;
    // The C1B helper stages into a cloned state and assigns only after its
    // received-block comparison succeeds.  Keep persistence in the caller.
    if ingress.runtime == RuntimeNetwork::Mainnet {
        require_mainnet_canonical_tip(state)
            .map_err(RuntimeBlockApplyError::LocalBootstrapInput)?;
        return validate_and_apply_block_for_runtime(
            state,
            header,
            txs,
            operations,
            ingress.runtime,
            ingress.bootstrap_witness.as_ref(),
        );
    }
    let parent: [u8; 32] = header[14..46].try_into().unwrap();
    let epoch = u64::from_be_bytes(header[6..14].try_into().unwrap());
    let canonical_tip_epoch = state.blocks.last().map(|b| b.epoch).unwrap_or(0);
    if parent == decode32(&state.tip_hash).map_err(RuntimeBlockApplyError::ConsensusTransition)?
        && epoch > canonical_tip_epoch
        && epoch <= state.tip_epoch
    {
        let old = state.clone();
        let mut rewound = replay_canonical_blocks(&old, &old.blocks)
            .map_err(RuntimeBlockApplyError::ConsensusTransition)?;
        rewound.mempool = old.mempool.clone();
        rewound.pending_protocol_operations = old.pending_protocol_operations.clone();
        rewound.side_branches = old.side_branches.clone();
        let hash = validate_and_apply_block(&mut rewound, header, txs, operations)
            .map_err(RuntimeBlockApplyError::ConsensusTransition)?;
        *state = rewound;
        return Ok(hash);
    }
    validate_and_apply_block(state, header, txs, operations)
        .map_err(RuntimeBlockApplyError::ConsensusTransition)
}

pub(super) fn block_known(state: &DevnetState, hash_hex: &str) -> bool {
    state.blocks.iter().any(|b| b.block_hash == hash_hex)
        || state
            .side_branches
            .iter()
            .any(|branch| branch.blocks.iter().any(|b| b.block_hash == hash_hex))
}

pub(super) fn announce_tip_to_peer(
    data_dir: &Path,
    peer: &str,
    state: &DevnetState,
) -> Result<String, String> {
    let sessions = new_session_registry();
    announce_tip_to_peer_persistent(data_dir, &sessions, peer, state)
}

pub(super) fn announce_tip_to_peer_persistent(
    data_dir: &Path,
    sessions: &SessionRegistry,
    peer: &str,
    state: &DevnetState,
) -> Result<String, String> {
    let block = state.blocks.last().ok_or("no block to announce")?;
    let hash = decode32(&block.block_hash)?;
    with_persistent_peer(data_dir, sessions, peer, |stream| {
        Frame::new(P2P_MAGIC_DEVNET, MSG_BLOCK_ANNOUNCE, 0x4003, hash.to_vec())
            .map_err(|e| e.to_string())?
            .write_to(stream)
            .map_err(|e| e.to_string())?;
        let response = Frame::read_from(stream, P2P_MAGIC_DEVNET).map_err(|e| e.to_string())?;
        if response.message_type == MSG_DEVNET_BLOCK_RESULT {
            return String::from_utf8(response.payload).map_err(|e| e.to_string());
        }
        if response.message_type != MSG_GET_BLOCK || response.payload.as_slice() != &hash[..] {
            return Err("peer returned unexpected BLOCKANNOUNCE response".into());
        }
        let payload = encode_block_payload(block)?;
        Frame::new(P2P_MAGIC_DEVNET, MSG_BLOCK, response.request_id, payload)
            .map_err(|e| e.to_string())?
            .write_to(stream)
            .map_err(|e| e.to_string())?;
        let result = Frame::read_from(stream, P2P_MAGIC_DEVNET).map_err(|e| e.to_string())?;
        if result.message_type != MSG_DEVNET_BLOCK_RESULT {
            return Err("peer did not acknowledge announced block".into());
        }
        String::from_utf8(result.payload).map_err(|e| e.to_string())
    })
}

pub(super) fn serve_get_headers(state: &DevnetState, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() != 10 {
        return Err("GETHEADERS payload must be start_height:u64 + max:u16".into());
    }
    let start = u64::from_be_bytes(payload[0..8].try_into().unwrap());
    let max = u16::from_be_bytes(payload[8..10].try_into().unwrap());
    encode_headers_response(state, start, max)
}

pub(super) fn serve_get_block(state: &DevnetState, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() != 32 {
        return Err("GETBLOCK payload must be one 32-byte BlockHash".into());
    }
    let hash = hex::encode(payload);
    if let Some(block) = state.blocks.iter().find(|b| b.block_hash == hash) {
        return encode_block_payload(block);
    }
    for branch in &state.side_branches {
        if let Some(block) = branch.blocks.iter().find(|b| b.block_hash == hash) {
            return encode_block_payload(block);
        }
    }
    Err("requested block not found".into())
}

pub(super) fn verify_full_replay(state: &DevnetState) -> Result<(), String> {
    let original_blocks = state.blocks.clone();
    let original_tip_epoch = state.tip_epoch;
    let mut replay = reset_for_replay(state)?;

    for block in &original_blocks {
        let payload = encode_block_payload(block)?;
        let (header, txs, operations) = decode_block_payload(&payload)?;
        validate_and_apply_block(&mut replay, header, txs, operations)?;
    }
    advance_empty_epochs(&mut replay, original_tip_epoch)?;

    if replay.height != state.height
        || replay.tip_hash != state.tip_hash
        || replay.tip_epoch != state.tip_epoch
        || replay.total_issued_strikes != state.total_issued_strikes
        || replay.difficulty_history_count != state.difficulty_history_count
        || replay.difficulty_history_bitmap != state.difficulty_history_bitmap
        || replay.difficulty_correction_q32 != state.difficulty_correction_q32
        || replay.base_fee_rate_q32 != state.base_fee_rate_q32
        || replay.current_state_root != state.current_state_root
        || replay.licenses.len() != state.licenses.len()
        || replay.consumed_native_payments != state.consumed_native_payments
        || replay.consumed_bitcoin_payments != state.consumed_bitcoin_payments
        || replay.consumed_evidence != state.consumed_evidence
        || replay.offense_events != state.offense_events
        || replay.treasury_reserved_dividend_strikes != state.treasury_reserved_dividend_strikes
        || replay.dividend_accounts != state.dividend_accounts
        || replay.historical_license_keys != state.historical_license_keys
    {
        return Err("full block replay does not reconstruct the persisted consensus state".into());
    }
    Ok(())
}

pub(super) fn verify_full_replay_for_runtime(
    state: &DevnetState,
    runtime: RuntimeNetwork,
    witness: Option<&mainnet_bootstrap::BootstrapWitnessProvider>,
) -> Result<(), RuntimeBlockApplyError> {
    let original_blocks = state.blocks.clone();
    let original_tip_epoch = state.tip_epoch;
    let mut replay =
        reset_for_replay(state).map_err(RuntimeBlockApplyError::ConsensusTransition)?;
    for block in &original_blocks {
        let payload =
            encode_block_payload(block).map_err(RuntimeBlockApplyError::ConsensusTransition)?;
        let (header, txs, operations) =
            decode_block_payload(&payload).map_err(RuntimeBlockApplyError::ConsensusTransition)?;
        validate_and_apply_block_for_runtime(
            &mut replay,
            header,
            txs,
            operations,
            runtime,
            witness,
        )?;
    }
    advance_empty_epochs(&mut replay, original_tip_epoch)
        .map_err(RuntimeBlockApplyError::ConsensusTransition)?;
    if serde_json::to_vec(&replay)
        .map_err(|e| RuntimeBlockApplyError::ConsensusTransition(e.to_string()))?
        != serde_json::to_vec(state)
            .map_err(|e| RuntimeBlockApplyError::ConsensusTransition(e.to_string()))?
    {
        return Err(RuntimeBlockApplyError::ConsensusTransition(
            "full runtime replay does not reconstruct persisted state".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build51_hotfix1_persistent_sync_skips_unsolicited_addr_before_headers() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            Frame::new(P2P_MAGIC_DEVNET, MSG_ADDR, 0, Vec::new())
                .unwrap()
                .write_to(&mut stream)
                .unwrap();
            let mut payload = Vec::new();
            payload.extend_from_slice(&0u64.to_be_bytes());
            write_varuint(&mut payload, 0);
            Frame::new(P2P_MAGIC_DEVNET, MSG_HEADERS, 0x4001, payload)
                .unwrap()
                .write_to(&mut stream)
                .unwrap();
        });

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        let response = read_expected_persistent_response(
            Path::new("."),
            &mut client,
            0x4001,
            MSG_HEADERS,
            "HEADERS",
        )
        .unwrap();
        assert_eq!(response.message_type, MSG_HEADERS);
        assert_eq!(response.request_id, 0x4001);
        let (tip, headers) = decode_headers_response(&response.payload).unwrap();
        assert_eq!(tip, 0);
        assert!(headers.is_empty());
        server.join().unwrap();
    }

    #[test]
    fn build51_hotfix2_persistent_sync_services_reverse_getheaders_before_block() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build51-hotfix2-reverse-getheaders-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let state = load_state(&dir).unwrap();
        assert_eq!(state.height, 0);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_dir = dir.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::with_capacity(10);
            request.extend_from_slice(&0u64.to_be_bytes());
            request.extend_from_slice(&MAX_HEADERS_PER_RESPONSE.to_be_bytes());
            Frame::new(P2P_MAGIC_DEVNET, MSG_GET_HEADERS, 1, request)
                .unwrap()
                .write_to(&mut stream)
                .unwrap();
            let reverse = Frame::read_from(&mut stream, P2P_MAGIC_DEVNET).unwrap();
            assert_eq!(reverse.message_type, MSG_HEADERS);
            assert_eq!(reverse.request_id, 1);
            let (tip, headers) = decode_headers_response(&reverse.payload).unwrap();
            assert_eq!(tip, 0);
            assert!(headers.is_empty());

            Frame::new(P2P_MAGIC_DEVNET, MSG_BLOCK, 0x4002, Vec::new())
                .unwrap()
                .write_to(&mut stream)
                .unwrap();
        });

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        let response = read_expected_persistent_response(
            &expected_dir,
            &mut client,
            0x4002,
            MSG_BLOCK,
            "BLOCK",
        )
        .unwrap();
        assert_eq!(response.message_type, MSG_BLOCK);
        assert_eq!(response.request_id, 0x4002);
        server.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build61_hotfix2_persistent_sync_services_reverse_getaddr_before_block() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let reverse_request_id = (1u64 << 63) | 4;
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            Frame::new(
                P2P_MAGIC_DEVNET,
                MSG_GET_ADDR,
                reverse_request_id,
                Vec::new(),
            )
            .unwrap()
            .write_to(&mut stream)
            .unwrap();
            let reverse = Frame::read_from(&mut stream, P2P_MAGIC_DEVNET).unwrap();
            assert_eq!(reverse.message_type, MSG_ADDR);
            assert_eq!(reverse.request_id, reverse_request_id);
            let mut payload = reverse.payload.as_slice();
            assert_eq!(read_varuint(&mut payload).unwrap(), 0);
            assert!(payload.is_empty());

            Frame::new(P2P_MAGIC_DEVNET, MSG_BLOCK, 0x4002, Vec::new())
                .unwrap()
                .write_to(&mut stream)
                .unwrap();
        });

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        let response = read_expected_persistent_response(
            Path::new("."),
            &mut client,
            0x4002,
            MSG_BLOCK,
            "BLOCK",
        )
        .unwrap();
        assert_eq!(response.message_type, MSG_BLOCK);
        assert_eq!(response.request_id, 0x4002);
        server.join().unwrap();
    }

    #[test]
    fn build62_hotfix1_persistent_sync_survives_more_than_128_legitimate_interleaves() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for lane in 1u64..=256 {
                let request_id = (1u64 << 63) | lane;
                Frame::new(P2P_MAGIC_DEVNET, MSG_GET_ADDR, request_id, Vec::new())
                    .unwrap()
                    .write_to(&mut stream)
                    .unwrap();
                let reverse = Frame::read_from(&mut stream, P2P_MAGIC_DEVNET).unwrap();
                assert_eq!(reverse.message_type, MSG_ADDR);
                assert_eq!(reverse.request_id, request_id);
                let mut payload = reverse.payload.as_slice();
                assert_eq!(read_varuint(&mut payload).unwrap(), 0);
                assert!(payload.is_empty());
            }
            Frame::new(P2P_MAGIC_DEVNET, MSG_BLOCK, 0x4002, Vec::new())
                .unwrap()
                .write_to(&mut stream)
                .unwrap();
        });

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        let response = read_expected_persistent_response(
            Path::new("."),
            &mut client,
            0x4002,
            MSG_BLOCK,
            "BLOCK",
        )
        .unwrap();
        assert_eq!(response.message_type, MSG_BLOCK);
        assert_eq!(response.request_id, 0x4002);
        server.join().unwrap();
    }

    #[test]
    fn build62_hotfix1_persistent_sync_interleave_cap_remains_finite() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for _ in 0..=MAX_PERSISTENT_INTERLEAVED_FRAMES {
                if Frame::new(P2P_MAGIC_DEVNET, MSG_ADDR, 0, Vec::new())
                    .unwrap()
                    .write_to(&mut stream)
                    .is_err()
                {
                    break;
                }
            }
        });

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        let error = read_expected_persistent_response(
            Path::new("."),
            &mut client,
            0x4002,
            MSG_BLOCK,
            "BLOCK",
        )
        .unwrap_err();
        assert_eq!(
            error,
            "peer sent too many interleaved frames while awaiting BLOCK"
        );
        server.join().unwrap();
    }

    #[test]
    fn header_response_roundtrip_empty() {
        let payload = {
            let mut p = Vec::new();
            p.extend_from_slice(&0u64.to_be_bytes());
            write_varuint(&mut p, 0);
            p
        };
        let (tip, headers) = decode_headers_response(&payload).unwrap();
        assert_eq!(tip, 0);
        assert!(headers.is_empty());
    }

    fn synthetic_block(height: u64, hash_byte: u8, parent_byte: u8) -> BlockState {
        BlockState {
            height,
            epoch: 63 + height,
            header: hex::encode(vec![0u8; 272]),
            transactions: Vec::new(),
            protocol_operations: Vec::new(),
            block_hash: hex::encode([hash_byte; 32]),
            parent_hash: hex::encode([parent_byte; 32]),
            miner_license_id: hex::encode([1u8; 32]),
            ticket_index: 0,
            argon2_proof: hex::encode([2u8; 32]),
            target: hex::encode([0xffu8; 32]),
            reward_strikes: 0,
            total_fees_strikes: 0,
            treasury_fee_share_strikes: 0,
            block_weight: 0,
            transaction_root: hex::encode([3u8; 32]),
            state_root: hex::encode([4u8; 32]),
            coinbase_txid: hex::encode([5u8; 32]),
            transaction_ids: Vec::new(),
        }
    }

    #[test]
    fn build51_reorg_restores_fee_less_orphaned_punishment_operation() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build51-punishment-reorg-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let adopted_base = load_state(&dir).unwrap();
        let mut old_local = adopted_base.clone();
        old_local.tip_epoch = 100;
        let op = punishment::create_dev_operation(&old_local, 2, 1, 0).unwrap();
        let raw = hex::encode(op.encode());
        let mut orphan = synthetic_block(1, 0x51, 0x00);
        orphan.protocol_operations.push(raw.clone());
        old_local.blocks.push(orphan);
        old_local.height = 1;

        let mut adopted = adopted_base;
        let restored_txs = restore_reorg_mempool(&mut adopted, &old_local, 0).unwrap();
        assert_eq!(restored_txs, 0);
        assert_eq!(adopted.mempool.len(), 0);
        assert_eq!(adopted.pending_protocol_operations.len(), 1);
        assert_eq!(adopted.pending_protocol_operations[0].required_txid, "");
        assert_eq!(adopted.pending_protocol_operations[0].operation, raw);
        assert_eq!(
            sorted_pending_protocol_operations(&adopted).unwrap().len(),
            1
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build53_reorg_restores_fee_less_orphaned_bitcoin_purchase_operation() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build53-bitcoin-reorg-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut adopted_base = load_state(&dir).unwrap();

        // Build 6.6B Hotfix1 V1.3 TEST-ONLY:
        // retire the pre-Pack-J fixture tuple and model the Pack-M two-stage
        // header-authentication -> purchase-confirmation dependency explicitly.
        adopted_base.network_id = DEVNET_NETWORK_ID;
        adopted_base.genesis_hash = DEVNET_GENESIS_ID_HEX.to_string();

        let fixture = bitcoin::create_dev_purchase(&adopted_base, 1, 93).unwrap();
        let header_raw = fixture.header_pending.operation.clone();
        let purchase_raw = fixture.pending.operation.clone();

        // Disconnected old-local branch: authenticate the Bitcoin header window
        // first, then consume the BTC purchase in a later Mutiny block.
        let mut old_local = adopted_base.clone();
        bitcoin_headers::apply_operation(&mut old_local, &fixture.header_operation, 99).unwrap();
        bitcoin::apply_operation(&mut old_local, &fixture.operation, 100).unwrap();

        let mut header_orphan = synthetic_block(1, 0x72, 0x00);
        header_orphan.protocol_operations.push(header_raw.clone());
        let mut purchase_orphan = synthetic_block(2, 0x73, 0x00);
        purchase_orphan
            .protocol_operations
            .push(purchase_raw.clone());
        old_local.blocks.push(header_orphan);
        old_local.blocks.push(purchase_orphan);
        old_local.height = 2;

        // Adopted branch has neither the orphaned Bitcoin header state nor the
        // consumed purchase. Reorg restoration must resurrect both fee-less ops.
        let mut adopted = adopted_base;
        let restored_txs = restore_reorg_mempool(&mut adopted, &old_local, 0).unwrap();
        assert_eq!(restored_txs, 0);
        assert!(adopted.mempool.is_empty());
        assert_eq!(adopted.pending_protocol_operations.len(), 2);

        let restored_types = adopted
            .pending_protocol_operations
            .iter()
            .map(|pending| pending.operation().unwrap().op_type)
            .collect::<HashSet<_>>();
        assert!(restored_types.contains(&OP_BITCOIN_HEADERS));
        assert!(restored_types.contains(&OP_LICENSE_PURCHASE_BTC));

        // Resurrection readiness is deliberately weaker than block readiness.
        assert!(bitcoin::dependency_ready(&adopted, &fixture.operation).unwrap());
        assert!(!bitcoin::dependency_ready_at_epoch(&adopted, &fixture.operation, 100).unwrap());

        // Before the header window is re-authenticated, only BITCOIN_HEADERS is
        // block-ready. The BTC purchase must remain pending.
        let selected_before = sorted_pending_protocol_operations(&adopted).unwrap();
        assert_eq!(selected_before.len(), 1);
        assert_eq!(selected_before[0].op_type, OP_BITCOIN_HEADERS);

        // Simulate confirmation of the restored header op, remove it from pending,
        // then prove the orphaned purchase becomes block-ready against the
        // then-current authenticated Bitcoin best chain.
        bitcoin_headers::apply_operation(&mut adopted, &fixture.header_operation, 99).unwrap();
        adopted.pending_protocol_operations.retain(|pending| {
            pending
                .operation()
                .map(|op| op.op_type != OP_BITCOIN_HEADERS)
                .unwrap_or(true)
        });

        assert!(bitcoin::dependency_ready_at_epoch(&adopted, &fixture.operation, 100).unwrap());
        let selected_after = sorted_pending_protocol_operations(&adopted).unwrap();
        assert_eq!(selected_after.len(), 1);
        assert_eq!(selected_after[0].op_type, OP_LICENSE_PURCHASE_BTC);
        assert_eq!(adopted.pending_protocol_operations[0].required_txid, "");
        assert_eq!(
            adopted.pending_protocol_operations[0].operation,
            purchase_raw
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build52_reorg_restores_orphaned_dividend_claim_bundle() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build52-dividend-reorg-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut adopted = load_state(&dir).unwrap();
        let treasury_amount = 12 * STRIKES_PER_MUT;
        adopted.utxos.push(UtxoState {
            txid: hex::encode([0x71u8; 32]),
            output_index: 0,
            amount_strikes: treasury_amount,
            output_type: OUTPUT_TREASURY,
            payload: hex::encode(treasury_id()),
            creation_epoch: 1,
            creation_height: 1,
            coinbase: false,
        });
        adopted.total_issued_strikes = treasury_amount;
        dividends::process_epoch(&mut adopted, mutiny_protocol::DIVIDEND_AWARD_INTERVAL).unwrap();
        adopted.tip_epoch = mutiny_protocol::DIVIDEND_AWARD_INTERVAL;
        adopted.height = 1;

        let mut old_local = adopted.clone();
        let license_id = old_local.licenses[0].license_id.clone();
        let claimable = old_local
            .dividend_accounts
            .iter()
            .find(|a| a.license_id == license_id)
            .unwrap()
            .claimable_strikes;
        let amount = claimable / 2;
        let (pending, pending_op, _) =
            dividends::create_claim_bundle(&old_local, 0, amount).unwrap();
        let tx = pending.to_transaction().unwrap();
        let op = pending_op.operation().unwrap();
        let mut working = old_local.utxos.clone();
        dividends::validate_and_apply_payment(
            &old_local,
            &mut working,
            &tx,
            &op,
            old_local.tip_epoch + 1,
            1,
        )
        .unwrap();
        let coinbase = TransactionV1 {
            core: TransactionCoreV1 {
                version: 1,
                network_id: DEVNET_NETWORK_ID,
                valid_from_epoch: old_local.tip_epoch + 1,
                expiry_epoch: 0,
                inputs: vec![TxInput::Coinbase {
                    commitment: CoinbaseCommitmentV1 {
                        block_epoch: old_local.tip_epoch + 1,
                        block_height: 1,
                        parent_block_hash: [0u8; 32],
                        protocol_operations_root: protocol_operations_root(&[op.clone()])
                            .unwrap()
                            .0,
                    },
                }],
                outputs: vec![TxOutput {
                    amount_strikes: 1,
                    output_type: OUTPUT_PUBKEY_HASH,
                    payload: [0x22u8; 32].to_vec(),
                }],
            },
            witnesses: vec![],
        };
        let claim_epoch = old_local.tip_epoch + 1;
        dividends::apply_operation(
            &mut old_local,
            &[coinbase.clone(), tx.clone()],
            &op,
            claim_epoch,
        )
        .unwrap();
        old_local.utxos = working;
        let mut orphan = synthetic_block(1, 0x72, 0x00);
        orphan.transactions = vec![
            hex::encode(coinbase.encode_full()),
            hex::encode(tx.encode_full()),
        ];
        orphan.protocol_operations = vec![pending_op.operation.clone()];
        old_local.confirmed_transactions.push(ConfirmedTxState {
            tx: pending.clone(),
            block_height: 1,
            block_epoch: old_local.tip_epoch + 1,
            block_hash: orphan.block_hash.clone(),
        });
        old_local.blocks.push(orphan);
        old_local.height = 1;

        let restored_txs = restore_reorg_mempool(&mut adopted, &old_local, 0).unwrap();
        assert_eq!(restored_txs, 1);
        assert_eq!(adopted.mempool.len(), 1);
        assert_eq!(adopted.mempool[0].txid, pending.txid);
        assert_eq!(adopted.pending_protocol_operations.len(), 1);
        assert_eq!(
            adopted.pending_protocol_operations[0].required_txid,
            pending.txid
        );
        assert_eq!(
            adopted.pending_protocol_operations[0].operation,
            pending_op.operation
        );
        let selected = sorted_pending_protocol_operations(&adopted).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].op_type, OP_DIVIDEND_CLAIM);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cumulative_work_reorg_adopts_heavier_validated_branch_and_archives_old_tip() {
        let dir = std::env::temp_dir().join(format!("mutiny-build41-reorg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let genesis = load_state(&dir).unwrap();

        let mut local = genesis.clone();
        local.blocks = vec![synthetic_block(1, 0x11, 0x00)];
        local.height = 1;
        local.tip_hash = hex::encode([0x11u8; 32]);

        let mut remote = genesis;
        remote.blocks = vec![
            synthetic_block(1, 0x22, 0x00),
            synthetic_block(2, 0x23, 0x22),
        ];
        remote.height = 2;
        remote.tip_hash = hex::encode([0x23u8; 32]);

        let report = reconcile_validated_remote(&mut local, remote, 2).unwrap();
        assert!(report.reorg);
        assert_eq!(report.decision, "ADOPTED_REMOTE_MORE_CHAINWORK");
        assert_eq!(report.common_ancestor_height, 0);
        assert_eq!(report.disconnected_blocks, 1);
        assert_eq!(report.applied_blocks, 2);
        assert_eq!(local.height, 2);
        assert_eq!(local.tip_hash, hex::encode([0x23u8; 32]));
        assert_eq!(local.side_branches.len(), 1);
        assert_eq!(local.side_branches[0].tip_hash, hex::encode([0x11u8; 32]));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build501_authority_reorg_restores_dependent_ops_and_stages_rotation() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build501-authority-reorg-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut base = load_state(&dir).unwrap();
        base.tip_epoch = 100;

        for (license_index, byte) in [(0usize, 0xa1u8), (1usize, 0xa2u8)] {
            base.utxos.push(UtxoState {
                txid: hex::encode([byte; 32]),
                output_index: 0,
                amount_strikes: 32 * STRIKES_PER_MUT,
                output_type: OUTPUT_PUBKEY_HASH,
                payload: base.licenses[license_index].payment_address_id.clone(),
                creation_epoch: 1,
                creation_height: 1,
                coinbase: false,
            });
        }

        let placeholder_coinbase = |epoch: u64| TransactionV1 {
            core: TransactionCoreV1 {
                version: 1,
                network_id: DEVNET_NETWORK_ID,
                valid_from_epoch: epoch,
                expiry_epoch: 0,
                inputs: vec![TxInput::Coinbase {
                    commitment: CoinbaseCommitmentV1 {
                        block_epoch: epoch,
                        block_height: 1,
                        parent_block_hash: [0u8; 32],
                        protocol_operations_root: [0u8; 32],
                    },
                }],
                outputs: vec![TxOutput {
                    amount_strikes: 1,
                    output_type: OUTPUT_PUBKEY_HASH,
                    payload: [1u8; 32].to_vec(),
                }],
            },
            witnesses: vec![],
        };

        let new_owner = dev_key_slot_public_key("200").unwrap();
        let new_mining = dev_key_slot_public_key("201").unwrap();
        let (transfer_fee, _transfer_pending, transfer_op) =
            create_license_transfer_operation(&base, 0, new_owner, new_mining).unwrap();
        let transfer_fee_tx = transfer_fee.to_transaction().unwrap();

        let mut after_transfer = base.clone();
        apply_protocol_operations(
            &mut after_transfer,
            &[placeholder_coinbase(101), transfer_fee_tx.clone()],
            &[transfer_op.clone()],
            101,
        )
        .unwrap();

        let funding = create_send_transaction(&after_transfer, 1, 0, STRIKES_PER_MUT).unwrap();
        let funding_tx = funding.to_transaction().unwrap();
        let mut funding_state = after_transfer.clone();
        funding_state.mempool = vec![funding.clone()];
        let mut working = after_transfer.utxos.clone();
        validate_and_apply_mempool(&funding_state, &mut working, 102, 2, &[]).unwrap();
        after_transfer.utxos = working;

        let rotated_mining = dev_key_slot_public_key("202").unwrap();
        let (rotation_fee, rotation_pending, rotation_op) =
            create_mining_key_rotation_operation(&after_transfer, 0, rotated_mining).unwrap();
        let rotation_fee_tx = rotation_fee.to_transaction().unwrap();

        let mut after_rotation = after_transfer.clone();
        apply_protocol_operations(
            &mut after_rotation,
            &[placeholder_coinbase(103), rotation_fee_tx.clone()],
            &[rotation_op.clone()],
            103,
        )
        .unwrap();
        assert_eq!(after_rotation.historical_license_keys.len(), 2);

        let mut block_transfer = synthetic_block(1, 0xb1, 0x00);
        block_transfer.transactions = vec![
            hex::encode(placeholder_coinbase(101).encode_full()),
            hex::encode(transfer_fee_tx.encode_full()),
        ];
        block_transfer.protocol_operations = vec![hex::encode(transfer_op.encode())];

        let mut block_funding = synthetic_block(2, 0xb2, 0xb1);
        block_funding.transactions = vec![
            hex::encode(placeholder_coinbase(102).encode_full()),
            hex::encode(funding_tx.encode_full()),
        ];

        let mut block_rotation = synthetic_block(3, 0xb3, 0xb2);
        block_rotation.transactions = vec![
            hex::encode(placeholder_coinbase(103).encode_full()),
            hex::encode(rotation_fee_tx.encode_full()),
        ];
        block_rotation.protocol_operations = vec![hex::encode(rotation_op.encode())];

        let mut old_local = after_rotation;
        old_local.blocks = vec![
            block_transfer.clone(),
            block_funding.clone(),
            block_rotation.clone(),
        ];
        old_local.height = 3;
        old_local.tip_hash = block_rotation.block_hash.clone();
        old_local.mempool.clear();
        old_local.pending_protocol_operations.clear();
        old_local.confirmed_transactions = vec![
            ConfirmedTxState {
                tx: transfer_fee.clone(),
                block_height: 1,
                block_epoch: 101,
                block_hash: block_transfer.block_hash.clone(),
            },
            ConfirmedTxState {
                tx: funding.clone(),
                block_height: 2,
                block_epoch: 102,
                block_hash: block_funding.block_hash.clone(),
            },
            ConfirmedTxState {
                tx: rotation_fee.clone(),
                block_height: 3,
                block_epoch: 103,
                block_hash: block_rotation.block_hash.clone(),
            },
        ];

        let mut adopted = base;
        let restored = restore_reorg_mempool(&mut adopted, &old_local, 0).unwrap();
        assert_eq!(restored, 3);
        assert_eq!(adopted.mempool.len(), 3);
        assert_eq!(adopted.pending_protocol_operations.len(), 2);

        let restored_transfer = adopted
            .mempool
            .iter()
            .find(|tx| tx.txid == transfer_fee.txid)
            .unwrap();
        assert_eq!(restored_transfer.fee_strikes, transfer_fee.fee_strikes);
        assert_eq!(restored_transfer.from_license, transfer_fee.from_license);
        assert_eq!(restored_transfer.to_license, transfer_fee.to_license);

        let restored_funding = adopted
            .mempool
            .iter()
            .find(|tx| tx.txid == funding.txid)
            .unwrap();
        assert_eq!(restored_funding.fee_strikes, funding.fee_strikes);
        assert_eq!(restored_funding.from_license, funding.from_license);
        assert_eq!(restored_funding.to_license, funding.to_license);

        let restored_rotation = adopted
            .mempool
            .iter()
            .find(|tx| tx.txid == rotation_fee.txid)
            .unwrap();
        assert_eq!(restored_rotation.fee_strikes, rotation_fee.fee_strikes);
        assert_eq!(restored_rotation.from_license, rotation_fee.from_license);
        assert_eq!(restored_rotation.to_license, rotation_fee.to_license);

        let selected = sorted_pending_protocol_operations(&adopted).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].operation_id().0, transfer_op.operation_id().0);
        let selected_mempool = selected_block_mempool(&adopted, &selected).unwrap();
        assert_eq!(selected_mempool.len(), 2);
        assert!(selected_mempool
            .iter()
            .any(|tx| tx.txid == transfer_fee.txid));
        assert!(selected_mempool.iter().any(|tx| tx.txid == funding.txid));
        assert!(!selected_mempool
            .iter()
            .any(|tx| tx.txid == rotation_fee.txid));

        // The local block builder must confirm the ready transfer + ordinary funding,
        // while leaving the future-sequence rotation fee/op queued for the next block.
        let mut staged = adopted.clone();
        accept_dev_block(&mut staged, 101, 1, 0, [0x11u8; 32], [0xffu8; 32]).unwrap();
        assert_eq!(staged.licenses[0].owner_key_sequence, 1);
        assert_eq!(staged.licenses[0].mining_key_sequence, 1);
        assert_eq!(staged.mempool.len(), 1);
        assert_eq!(staged.mempool[0].txid, rotation_fee.txid);
        assert_eq!(staged.pending_protocol_operations.len(), 1);
        assert_eq!(
            staged.pending_protocol_operations[0].required_txid,
            rotation_pending.required_txid
        );
        assert_eq!(staged.historical_license_keys.len(), 1);

        let selected_after_transfer = sorted_pending_protocol_operations(&staged).unwrap();
        assert_eq!(selected_after_transfer.len(), 1);
        assert_eq!(
            selected_after_transfer[0].operation_id().0,
            rotation_op.operation_id().0
        );
        let selected_after_transfer_mempool =
            selected_block_mempool(&staged, &selected_after_transfer).unwrap();
        assert_eq!(selected_after_transfer_mempool.len(), 1);
        assert_eq!(
            selected_after_transfer_mempool[0].txid,
            rotation_pending.required_txid
        );

        accept_dev_block(&mut staged, 102, 1, 0, [0x22u8; 32], [0xffu8; 32]).unwrap();
        assert_eq!(staged.licenses[0].owner_key_sequence, 1);
        assert_eq!(staged.licenses[0].mining_key_sequence, 2);
        assert!(staged.mempool.is_empty());
        assert!(staged.pending_protocol_operations.is_empty());
        assert_eq!(staged.historical_license_keys.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn equal_chainwork_keeps_adopted_local_branch() {
        let dir = std::env::temp_dir().join(format!("mutiny-build41-tie-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let genesis = load_state(&dir).unwrap();

        let mut local = genesis.clone();
        local.blocks = vec![synthetic_block(1, 0x31, 0x00)];
        local.height = 1;
        local.tip_hash = hex::encode([0x31u8; 32]);

        let mut remote = genesis;
        remote.blocks = vec![synthetic_block(1, 0x41, 0x00)];
        remote.height = 1;
        remote.tip_hash = hex::encode([0x41u8; 32]);

        let report = reconcile_validated_remote(&mut local, remote, 1).unwrap();
        assert!(!report.reorg);
        assert_eq!(report.decision, "KEPT_LOCAL_EQUAL_CHAINWORK");
        assert_eq!(local.tip_hash, hex::encode([0x31u8; 32]));
        assert_eq!(local.side_branches.len(), 1);
        assert_eq!(local.side_branches[0].tip_hash, hex::encode([0x41u8; 32]));

        let _ = fs::remove_dir_all(&dir);
    }
}

// ---- Build 4.5.1 live duplex transport -------------------------------------------------
// These helpers are wire-equivalent to the persistent-session functions above, but all
// requests are routed by the frozen 64-bit RequestID through one authenticated DuplexSession.

fn request_headers_duplex(
    session: &DuplexSession,
    start_height: u64,
) -> Result<(u64, Vec<[u8; 272]>), String> {
    let mut payload = Vec::with_capacity(10);
    payload.extend_from_slice(&start_height.to_be_bytes());
    payload.extend_from_slice(&MAX_HEADERS_PER_RESPONSE.to_be_bytes());
    let response = session
        .request(
            MSG_GET_HEADERS,
            payload,
            &[MSG_HEADERS],
            EXPENSIVE_REQUEST_RESPONSE_TIMEOUT,
        )
        .map_err(|e| e.to_string())?;
    decode_headers_response(&response.payload)
}

fn collect_remote_headers_duplex(session: &DuplexSession) -> Result<(u64, Vec<[u8; 272]>), String> {
    let (remote_height, first) = request_headers_duplex(session, 0)?;
    if remote_height == 0 {
        return Ok((0, Vec::new()));
    }
    let target = usize::try_from(remote_height).map_err(|_| "remote height overflow")?;
    let mut headers = first;
    while headers.len() < target {
        let start = headers.len() as u64;
        let (observed_height, more) = request_headers_duplex(session, start)?;
        if observed_height < remote_height {
            return Err(
                "peer height moved backward while collecting duplex headers; retry synchronization"
                    .into(),
            );
        }
        if more.is_empty() {
            return Err(format!(
                "peer advertises height {remote_height} but stopped headers at {start}"
            ));
        }
        let need = target - headers.len();
        headers.extend(more.into_iter().take(need));
    }
    if headers.len() != target {
        return Err("remote duplex header collection length mismatch".into());
    }
    Ok((remote_height, headers))
}

fn request_block_duplex(
    session: &DuplexSession,
    hash: [u8; 32],
) -> Result<([u8; 272], Vec<TransactionV1>, Vec<ProtocolOperationV1>), String> {
    let response = session
        .request(
            MSG_GET_BLOCK,
            hash.to_vec(),
            &[MSG_BLOCK],
            EXPENSIVE_REQUEST_RESPONSE_TIMEOUT,
        )
        .map_err(|e| e.to_string())?;
    let decoded = decode_block_payload(&response.payload)?;
    if block_hash(&decoded.0).0 != hash {
        return Err("duplex BLOCK response hash does not match request".into());
    }
    Ok(decoded)
}

pub(super) fn sync_state_from_peer_duplex_for_runtime(
    peer_label: &str,
    session: &DuplexSession,
    state: &mut DevnetState,
    ingress: &RuntimeIngressContext,
) -> Result<SyncReport, RuntimeBlockApplyError> {
    validate_runtime_tuple(state, ingress.runtime)
        .map_err(RuntimeBlockApplyError::ConsensusTransition)?;
    if ingress.runtime == RuntimeNetwork::Devnet {
        return sync_state_from_peer_duplex(peer_label, session, state)
            .map_err(RuntimeBlockApplyError::ConsensusTransition);
    }
    require_mainnet_canonical_tip(state).map_err(RuntimeBlockApplyError::LocalBootstrapInput)?;
    let (remote_height, headers) = collect_remote_headers_duplex(session)
        .map_err(RuntimeBlockApplyError::ConsensusTransition)?;
    if remote_height == 0 {
        return Ok(SyncReport::no_change(0, "REMOTE_GENESIS"));
    }
    let common = common_prefix_with_headers(state, &headers);
    if common == state.height && remote_height == state.height {
        return Ok(SyncReport::no_change(state.height, "SAME_CANONICAL_TIP"));
    }
    if common == remote_height && remote_height < state.height {
        return Ok(SyncReport::no_change(
            remote_height,
            "REMOTE_IS_CANONICAL_ANCESTOR",
        ));
    }
    let extension = common == state.height && remote_height > state.height;
    let old_height = state.height;
    // Ordinary extensions start from the committed state and never reread Bootstrap input.
    // Historical forks are independently reconstructed from Genesis with authenticated C1B input.
    let mut candidate = if extension {
        state.clone()
    } else {
        if ingress.bootstrap_witness.is_none() {
            return Err(RuntimeBlockApplyError::LocalBootstrapInput(
                "historical Mainnet fork replay requires --bootstrap-witness".into(),
            ));
        }
        reset_for_replay(state).map_err(RuntimeBlockApplyError::ConsensusTransition)?
    };
    let skip = if extension { old_height as usize } else { 0 };
    let mut downloaded = 0usize;
    for header in headers.into_iter().skip(skip) {
        let (wire_header, txs, operations) =
            request_block_duplex(session, block_hash(&header).0)
                .map_err(RuntimeBlockApplyError::ConsensusTransition)?;
        downloaded += 1;
        if wire_header != header {
            return Err(RuntimeBlockApplyError::ConsensusTransition(
                "duplex BLOCK header differs from prior HEADERS announcement".into(),
            ));
        }
        validate_and_apply_block_for_runtime(
            &mut candidate,
            wire_header,
            txs,
            operations,
            ingress.runtime,
            ingress.bootstrap_witness.as_ref(),
        )?;
        println!(
            "Validated Mainnet block {} from {peer_label}: {}",
            candidate.height, candidate.tip_hash
        );
    }
    require_mainnet_canonical_tip(&candidate)
        .map_err(RuntimeBlockApplyError::ConsensusTransition)?;
    if extension {
        let applied = usize::try_from(candidate.height - old_height).map_err(|_| {
            RuntimeBlockApplyError::ConsensusTransition("applied block count overflow".into())
        })?;
        *state = candidate;
        return Ok(SyncReport {
            downloaded_blocks: downloaded,
            applied_blocks: applied,
            reorg: false,
            common_ancestor_height: old_height,
            disconnected_blocks: 0,
            restored_mempool: 0,
            decision: "EXTENDED_CANONICAL_CHAIN".into(),
        });
    }
    let mut reconciled = state.clone();
    let report = reconcile_validated_remote(&mut reconciled, candidate, downloaded)
        .map_err(RuntimeBlockApplyError::ConsensusTransition)?;
    require_mainnet_canonical_tip(&reconciled)
        .map_err(RuntimeBlockApplyError::ConsensusTransition)?;
    *state = reconciled;
    Ok(report)
}

pub(super) fn sync_state_from_peer_duplex(
    peer_label: &str,
    session: &DuplexSession,
    state: &mut DevnetState,
) -> Result<SyncReport, String> {
    let (remote_height, headers) = collect_remote_headers_duplex(session)?;
    if remote_height == 0 {
        return Ok(SyncReport::no_change(0, "REMOTE_GENESIS"));
    }

    let common = common_prefix_with_headers(state, &headers);
    let same_tip = remote_height == state.height
        && common == state.height
        && state
            .blocks
            .last()
            .is_some_and(|b| b.block_hash == hex::encode(block_hash(headers.last().unwrap()).0));
    if same_tip {
        return Ok(SyncReport::no_change(state.height, "SAME_CANONICAL_TIP"));
    }

    if common == state.height && remote_height > state.height {
        let old_height = state.height;
        let canonical_epoch = state.blocks.last().map(|b| b.epoch).unwrap_or(0);
        let mut candidate = if state.tip_epoch > canonical_epoch {
            let mut replay = replay_canonical_blocks(state, &state.blocks)?;
            replay.mempool = state.mempool.clone();
            replay.pending_protocol_operations = state.pending_protocol_operations.clone();
            replay.side_branches = state.side_branches.clone();
            replay
        } else {
            state.clone()
        };
        let mut downloaded = 0usize;
        for header in headers.into_iter().skip(old_height as usize) {
            let hash = block_hash(&header).0;
            let (wire_header, txs, operations) = request_block_duplex(session, hash)?;
            downloaded += 1;
            if wire_header != header {
                return Err("duplex BLOCK header differs from prior HEADERS announcement".into());
            }
            validate_and_apply_block(&mut candidate, wire_header, txs, operations)?;
            println!(
                "Validated block {} from {peer_label} over duplex: {}",
                candidate.height, candidate.tip_hash
            );
        }
        let applied = usize::try_from(candidate.height - old_height)
            .map_err(|_| "applied block count overflow")?;
        *state = candidate;
        return Ok(SyncReport {
            downloaded_blocks: downloaded,
            applied_blocks: applied,
            reorg: false,
            common_ancestor_height: old_height,
            disconnected_blocks: 0,
            restored_mempool: 0,
            decision: "EXTENDED_CANONICAL_CHAIN".into(),
        });
    }

    if common == remote_height && remote_height < state.height {
        return Ok(SyncReport::no_change(
            remote_height,
            "REMOTE_IS_CANONICAL_ANCESTOR",
        ));
    }

    let mut remote = reset_for_replay(state)?;
    let mut downloaded = 0usize;
    for header in headers {
        let hash = block_hash(&header).0;
        let (wire_header, txs, operations) = request_block_duplex(session, hash)?;
        downloaded += 1;
        if wire_header != header {
            return Err("duplex BLOCK header differs from prior HEADERS announcement during fork validation".into());
        }
        validate_and_apply_block(&mut remote, wire_header, txs, operations)?;
    }

    reconcile_validated_remote(state, remote, downloaded)
}
