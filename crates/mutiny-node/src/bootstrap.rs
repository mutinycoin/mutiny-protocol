use super::*;
use mutiny_bitcoin::{
    canonical_manifest_script, double_sha256, median_time_past_11, mine_easy_header,
    parse_transaction, validate_anchor_context, validate_payment, BitcoinHeader, BitcoinSpvProofV1,
    ANCHOR_CONTEXT_HEADERS,
};
use mutiny_protocol::{
    bitcoin_payment_id, derive_license_id, BootstrapManifestV1, LicenseManifestEntryV1,
    ProtocolOperationV1, BOOTSTRAP_LICENSE_COUNT_V1, OP_BOOTSTRAP_COMMITMENT,
};

pub(super) const DEVNET_BOOTSTRAP_PAYMENT_SATS: u64 = 24_576;
pub(super) const DEVNET_BOOTSTRAP_ANCHOR_HEIGHT: u32 = 800_352;
pub(super) const DEVNET_BOOTSTRAP_CONTAINING_HEIGHT: u32 = 800_353;
pub(super) const DEVNET_BOOTSTRAP_SIXTH_HEIGHT: u32 = 800_358;
const DEVNET_BOOTSTRAP_ANCHOR_FIRST_TIMESTAMP: u32 = 1_799_994_000;

#[derive(Clone, Debug, Serialize)]
pub(super) struct DevnetBootstrapFixtureV1 {
    pub reconciliation_status: &'static str,
    pub manifest_bytes: String,
    pub manifest_hash: String,
    pub bitcoin_anchor_height: u32,
    pub bitcoin_anchor_headers: Vec<String>,
    pub bitcoin_anchor_hash: String,
    pub bitcoin_payment_tx: String,
    pub bitcoin_txid_display: String,
    pub bitcoin_payment_id: String,
    pub containing_height: u32,
    pub sixth_confirmation_height: u32,
    pub sixth_confirmation_mtp: u32,
    pub initial_state_root: String,
    pub genesis_fixture_bytes: String,
    pub genesis_id: String,
    pub bootstrap_license_ids: Vec<String>,
    pub bootstrap_issued_epoch: u64,
    pub bootstrap_activation_epoch: u64,
    pub bootstrap_commitment_bytes: String,
    pub bootstrap_commitment_hash: String,
    pub bootstrap_operation_id: String,
}

fn compact_size_small(n: usize) -> Result<Vec<u8>, String> {
    if n > 0xfc {
        return Err("Build 5.4 bootstrap fixture CompactSize overflow".into());
    }
    Ok(vec![n as u8])
}

fn bootstrap_manifest() -> Result<BootstrapManifestV1, String> {
    let purchase_nonce = sha256_domain(
        domains::BOOTSTRAP_MANIFEST,
        &[
            b"MUTINY-DEVNET-BOOTSTRAP-NONCE-V1",
            &DEVNET_NETWORK_ID.to_be_bytes(),
        ],
    )
    .0;
    let licenses = (0..BOOTSTRAP_LICENSE_COUNT_V1)
        .map(|i| {
            let sk = SigningKey::from_bytes(&dev_seed(i as u8));
            let pk = sk.verifying_key().to_bytes();
            LicenseManifestEntryV1 {
                owner_public_key: pk,
                mining_public_key: pk,
            }
        })
        .collect();
    let manifest = BootstrapManifestV1 {
        version: 1,
        network_id: DEVNET_NETWORK_ID,
        purchase_nonce,
        licenses,
    };
    manifest.validate().map_err(|e| e.to_string())?;
    Ok(manifest)
}

fn build_bootstrap_payment_tx(manifest_hash: &[u8; 32]) -> Result<Vec<u8>, String> {
    let prev = sha256_domain(
        domains::BTC_PAYMENT_ID,
        &[b"MUTINY-DEVNET-BOOTSTRAP-BTC-PREVOUT-V1", manifest_hash],
    );
    let mut tx = Vec::new();
    tx.extend_from_slice(&2u32.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&prev.0);
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx.push(1);
    tx.push(0x51);
    tx.extend_from_slice(&0xffff_fffeu32.to_le_bytes());
    tx.push(2);
    tx.extend_from_slice(&DEVNET_BOOTSTRAP_PAYMENT_SATS.to_le_bytes());
    tx.extend_from_slice(&compact_size_small(DEVNET_BTC_TREASURY_SCRIPT.len())?);
    tx.extend_from_slice(DEVNET_BTC_TREASURY_SCRIPT);
    tx.extend_from_slice(&0u64.to_le_bytes());
    let commitment = canonical_manifest_script(manifest_hash);
    tx.extend_from_slice(&compact_size_small(commitment.len())?);
    tx.extend_from_slice(&commitment);
    tx.extend_from_slice(&0u32.to_le_bytes());
    Ok(tx)
}

fn anchor_headers() -> Result<Vec<BitcoinHeader>, String> {
    let mut headers = Vec::with_capacity(ANCHOR_CONTEXT_HEADERS);
    let mut prev = DEVNET_BTC_TRUSTED_CHECKPOINT_INTERNAL;
    for i in 0..ANCHOR_CONTEXT_HEADERS {
        let marker = double_sha256(
            &[
                b"MUTINY-DEVNET-BUILD54-ANCHOR-V1".as_slice(),
                &(i as u32).to_be_bytes(),
            ]
            .concat(),
        );
        let timestamp = DEVNET_BOOTSTRAP_ANCHOR_FIRST_TIMESTAMP
            .checked_add(
                (i as u32)
                    .checked_mul(600)
                    .ok_or("anchor timestamp overflow")?,
            )
            .ok_or("anchor timestamp overflow")?;
        let header = mine_easy_header(prev, marker, timestamp, DEVNET_BTC_BITS, i as u32)
            .map_err(|e| e.to_string())?;
        prev = header.hash_internal();
        headers.push(header);
    }
    validate_anchor_context(
        &headers,
        &DEVNET_BTC_TRUSTED_CHECKPOINT_INTERNAL,
        DEVNET_BTC_BITS,
        DEVNET_BOOTSTRAP_ANCHOR_HEIGHT,
    )
    .map_err(|e| format!("Build 5.4 anchor self-validation failed: {e}"))?;
    Ok(headers)
}

fn payment_proof(
    raw_transaction: Vec<u8>,
    anchor: &[BitcoinHeader],
) -> Result<BitcoinSpvProofV1, String> {
    let parsed = parse_transaction(&raw_transaction).map_err(|e| e.to_string())?;
    let mut headers = Vec::with_capacity(6);
    let first = mine_easy_header(
        anchor.last().ok_or("empty anchor context")?.hash_internal(),
        parsed.txid_internal,
        DEVNET_BOOTSTRAP_ANCHOR_FIRST_TIMESTAMP + 11 * 600,
        DEVNET_BTC_BITS,
        0,
    )
    .map_err(|e| e.to_string())?;
    headers.push(first);
    while headers.len() < 6 {
        let i = headers.len() as u32;
        let marker = double_sha256(
            &[
                b"MUTINY-DEVNET-BUILD54-BOOTSTRAP-CONFIRM-V1".as_slice(),
                &i.to_be_bytes(),
            ]
            .concat(),
        );
        let timestamp = DEVNET_BOOTSTRAP_ANCHOR_FIRST_TIMESTAMP
            .checked_add(
                (11 + i)
                    .checked_mul(600)
                    .ok_or("bootstrap timestamp overflow")?,
            )
            .ok_or("bootstrap timestamp overflow")?;
        let prev = headers.last().expect("nonempty").hash_internal();
        headers.push(
            mine_easy_header(prev, marker, timestamp, DEVNET_BTC_BITS, i)
                .map_err(|e| e.to_string())?,
        );
    }
    Ok(BitcoinSpvProofV1 {
        raw_transaction,
        payment_output_index: 0,
        manifest_output_index: 1,
        tx_index: 0,
        merkle_branch: Vec::new(),
        headers,
        containing_block_height: DEVNET_BOOTSTRAP_CONTAINING_HEIGHT,
    })
}

fn initial_state_root(state: &DevnetState) -> Result<[u8; 32], String> {
    let mut initial = state.clone();
    initial.height = 0;
    initial.tip_epoch = 0;
    initial.total_issued_strikes = 0;
    initial.difficulty_history_count = 0;
    initial.difficulty_history_bitmap = 0;
    initial.difficulty_correction_q32 = DIFFICULTY_Q32_ONE;
    initial.base_fee_rate_q32 = BASE_FEE_MIN_Q32;
    initial.licenses.clear();
    initial.consumed_native_payments.clear();
    initial.consumed_bitcoin_payments.clear();
    initial.consumed_evidence.clear();
    initial.offense_events.clear();
    initial.treasury_reserved_dividend_strikes = 0;
    initial.dividend_accounts.clear();
    initial.historical_license_keys.clear();
    initial.utxos.clear();
    initial.mempool.clear();
    initial.pending_protocol_operations.clear();
    initial.confirmed_transactions.clear();
    initial.blocks.clear();
    initial.side_branches.clear();
    compute_state_root(
        &initial,
        &[],
        0,
        0,
        0,
        0,
        DIFFICULTY_Q32_ONE,
        BASE_FEE_MIN_Q32,
    )
}

pub(super) fn create_fixture(state: &DevnetState) -> Result<DevnetBootstrapFixtureV1, String> {
    let manifest = bootstrap_manifest()?;
    let manifest_bytes = manifest.encode().map_err(|e| e.to_string())?;
    let manifest_hash = manifest.manifest_hash().map_err(|e| e.to_string())?;
    let anchor = anchor_headers()?;
    let raw_tx = build_bootstrap_payment_tx(&manifest_hash.0)?;
    let proof = payment_proof(raw_tx.clone(), &anchor)?;
    let validated = validate_payment(
        &proof,
        &manifest_hash.0,
        DEVNET_BTC_TREASURY_SCRIPT,
        DEVNET_BOOTSTRAP_PAYMENT_SATS,
    )
    .map_err(|e| format!("Build 5.4 bootstrap payment self-validation failed: {e}"))?;
    if proof.headers[0].previous_block_internal()
        != anchor.last().expect("nonempty").hash_internal()
    {
        return Err("bootstrap payment chain does not descend from Genesis Bitcoin anchor".into());
    }
    if validated.sixth_confirmation_height != DEVNET_BOOTSTRAP_SIXTH_HEIGHT {
        return Err("bootstrap sixth-confirmation height mismatch".into());
    }

    let mut mtp_window = Vec::with_capacity(11);
    mtp_window.extend_from_slice(&anchor[anchor.len() - 5..]);
    mtp_window.extend_from_slice(&proof.headers);
    let sixth_mtp = median_time_past_11(&mtp_window).map_err(|e| e.to_string())?;
    let genesis_time_secs =
        u32::try_from(DEVNET_FIXED_GENESIS_TIME_MS / 1000).map_err(|_| "genesis time overflow")?;
    if sixth_mtp <= genesis_time_secs {
        return Err("bootstrap sixth-confirmation MTP must be post-Genesis".into());
    }
    let issued_epoch = u64::from(sixth_mtp - genesis_time_secs) / 60;
    let activation_epoch = issued_epoch
        .checked_add(ACTIVATION_DELAY_EPOCHS)
        .ok_or("bootstrap activation epoch overflow")?;

    let parsed = parse_transaction(&raw_tx).map_err(|e| e.to_string())?;
    let payment_id = bitcoin_payment_id(&parsed.txid_internal, 0);
    let license_ids = manifest
        .licenses
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            derive_license_id(
                DEVNET_NETWORK_ID,
                PURCHASE_METHOD_BTC,
                &payment_id.0,
                i as u32,
                &entry.owner_public_key,
            )
        })
        .collect::<Vec<_>>();

    let initial_root = initial_state_root(state)?;
    // Build 5.4 Devnet reconciliation encoding. This intentionally remains isolated
    // from the frozen production Pack-J wire name until the literal Pack-J vector is available.
    let mut genesis_bytes = Vec::new();
    genesis_bytes.extend_from_slice(&1u16.to_be_bytes());
    genesis_bytes.extend_from_slice(&DEVNET_NETWORK_ID.to_be_bytes());
    genesis_bytes.extend_from_slice(&(DEVNET_FIXED_GENESIS_TIME_MS as u64).to_be_bytes());
    genesis_bytes.extend_from_slice(&DEVNET_BOOTSTRAP_ANCHOR_HEIGHT.to_be_bytes());
    genesis_bytes.push(ANCHOR_CONTEXT_HEADERS as u8);
    for h in &anchor {
        genesis_bytes.extend_from_slice(&h.raw);
    }
    genesis_bytes.extend_from_slice(&initial_root);
    genesis_bytes.extend_from_slice(&manifest_hash.0);
    let genesis_id = sha256_domain(domains::GENESIS_ID, &[&genesis_bytes]);

    let anchor_hash = anchor.last().expect("nonempty").hash_internal();
    let sixth_hash = proof.headers[5].hash_internal();
    let mut commitment = Vec::new();
    commitment.extend_from_slice(&1u16.to_be_bytes());
    commitment.extend_from_slice(&genesis_id.0);
    commitment.extend_from_slice(&manifest_hash.0);
    commitment.extend_from_slice(&payment_id.0);
    commitment.extend_from_slice(&DEVNET_BOOTSTRAP_ANCHOR_HEIGHT.to_be_bytes());
    commitment.extend_from_slice(&anchor_hash);
    commitment.extend_from_slice(&DEVNET_BOOTSTRAP_CONTAINING_HEIGHT.to_be_bytes());
    commitment.extend_from_slice(&validated.containing_block_hash_internal);
    commitment.extend_from_slice(&DEVNET_BOOTSTRAP_SIXTH_HEIGHT.to_be_bytes());
    commitment.extend_from_slice(&sixth_hash);
    commitment.extend_from_slice(&sixth_mtp.to_be_bytes());
    commitment.extend_from_slice(&issued_epoch.to_be_bytes());
    commitment.extend_from_slice(&activation_epoch.to_be_bytes());
    commitment.extend_from_slice(&(license_ids.len() as u32).to_be_bytes());
    for id in &license_ids {
        commitment.extend_from_slice(&id.0);
    }
    let commitment_hash = sha256_domain(domains::BOOTSTRAP_COMMITMENT, &[&commitment]);
    let bootstrap_op = ProtocolOperationV1 {
        op_type: OP_BOOTSTRAP_COMMITMENT,
        op_version: 1,
        payload: commitment.clone(),
    };

    Ok(DevnetBootstrapFixtureV1 {
        reconciliation_status: "DEVNET_FIXTURE_PACK_J_LITERAL_VECTOR_NOT_YET_RECONCILED",
        manifest_bytes: hex::encode(manifest_bytes),
        manifest_hash: manifest_hash.to_hex(),
        bitcoin_anchor_height: DEVNET_BOOTSTRAP_ANCHOR_HEIGHT,
        bitcoin_anchor_headers: anchor.iter().map(|h| hex::encode(h.raw)).collect(),
        bitcoin_anchor_hash: hex::encode(anchor_hash),
        bitcoin_payment_tx: hex::encode(&raw_tx),
        bitcoin_txid_display: mutiny_bitcoin::display_hex_from_internal(parsed.txid_internal),
        bitcoin_payment_id: payment_id.to_hex(),
        containing_height: DEVNET_BOOTSTRAP_CONTAINING_HEIGHT,
        sixth_confirmation_height: DEVNET_BOOTSTRAP_SIXTH_HEIGHT,
        sixth_confirmation_mtp: sixth_mtp,
        initial_state_root: hex::encode(initial_root),
        genesis_fixture_bytes: hex::encode(genesis_bytes),
        genesis_id: genesis_id.to_hex(),
        bootstrap_license_ids: license_ids.iter().map(|id| id.to_hex()).collect(),
        bootstrap_issued_epoch: issued_epoch,
        bootstrap_activation_epoch: activation_epoch,
        bootstrap_commitment_bytes: hex::encode(commitment),
        bootstrap_commitment_hash: commitment_hash.to_hex(),
        bootstrap_operation_id: bootstrap_op.operation_id().to_hex(),
    })
}

pub(super) fn initialize_genesis_state(
    state: &mut DevnetState,
) -> Result<DevnetBootstrapFixtureV1, String> {
    if state.height != 0 || !state.blocks.is_empty() || !state.licenses.is_empty() {
        return Err(
            "Build 5.4 Genesis initialization requires empty height-0 license/block state".into(),
        );
    }
    let fixture = create_fixture(state)?;
    state.genesis_hash = fixture.genesis_id.clone();
    state.tip_hash = fixture.genesis_id.clone();
    state.tip_epoch = 0;
    state.anchor_epoch = 0;
    state.anchor_license_id = hex::encode([0u8; 32]);
    state.anchor_ticket_index = 0;
    state.anchor_argon2_proof = fixture.genesis_id.clone();
    state.current_state_root = fixture.initial_state_root.clone();
    Ok(fixture)
}

fn build_devnet_bootstrap_transition(
    state: &DevnetState,
) -> Result<
    (
        DevnetState,
        DevnetBootstrapFixtureV1,
        [u8; 272],
        Vec<TransactionV1>,
        Vec<ProtocolOperationV1>,
    ),
    String,
> {
    if state.format_version < 10 {
        return Err("Build 5.4 explicit Bootstrap requires format_version 10 Genesis state".into());
    }
    if state.height != 0
        || state.tip_epoch != 0
        || !state.blocks.is_empty()
        || !state.licenses.is_empty()
    {
        return Err(
            "Build 5.4 Bootstrap may execute exactly once from pristine empty Genesis state".into(),
        );
    }
    if !state.consumed_bitcoin_payments.is_empty()
        || !state.utxos.is_empty()
        || !state.mempool.is_empty()
        || !state.pending_protocol_operations.is_empty()
    {
        return Err("Build 5.4 Bootstrap Genesis state is not pristine".into());
    }

    let fixture = create_fixture(state)?;
    if state.genesis_hash != fixture.genesis_id || state.tip_hash != fixture.genesis_id {
        return Err("Build 5.4 GenesisID does not match bootstrap reconciliation fixture".into());
    }
    if state.current_state_root != fixture.initial_state_root {
        return Err(
            "Build 5.4 initial StateRoot does not match bootstrap reconciliation fixture".into(),
        );
    }

    let manifest = bootstrap_manifest()?;
    let anchor = anchor_headers()?;
    let manifest_hash = manifest.manifest_hash().map_err(|e| e.to_string())?;
    let raw_tx = build_bootstrap_payment_tx(&manifest_hash.0)?;
    let proof = payment_proof(raw_tx.clone(), &anchor)?;
    let validated = validate_payment(
        &proof,
        &manifest_hash.0,
        DEVNET_BTC_TREASURY_SCRIPT,
        DEVNET_BOOTSTRAP_PAYMENT_SATS,
    )
    .map_err(|e| format!("Build 5.4 bootstrap payment validation failed: {e}"))?;
    let parsed = parse_transaction(&raw_tx).map_err(|e| e.to_string())?;
    let payment_id = bitcoin_payment_id(&parsed.txid_internal, 0);
    if hex::encode(payment_id.0) != fixture.bitcoin_payment_id {
        return Err("Build 5.4 Bootstrap BitcoinPaymentID mismatch".into());
    }

    let commitment = hex::decode(&fixture.bootstrap_commitment_bytes).map_err(|e| e.to_string())?;
    let bootstrap_op = ProtocolOperationV1 {
        op_type: OP_BOOTSTRAP_COMMITMENT,
        op_version: 1,
        payload: commitment,
    };
    if bootstrap_op.operation_id().to_hex() != fixture.bootstrap_operation_id {
        return Err("Build 5.4 Bootstrap OperationID mismatch".into());
    }
    let operations = vec![bootstrap_op.clone()];
    let operation_root = protocol_operations_root(&operations).map_err(|e| e.to_string())?;
    let parent = decode32(&state.genesis_hash)?;
    let epoch = fixture.bootstrap_issued_epoch;

    // The reconciliation Block 1 is a protocol bootstrap block, not a mining win. It has a
    // canonical zero-output coinbase envelope only so the existing block-body codec retains a
    // single deterministic transaction root. No subsidy is minted and no Mining License signs it.
    let coinbase = TransactionV1 {
        core: TransactionCoreV1 {
            version: 1,
            network_id: DEVNET_NETWORK_ID,
            valid_from_epoch: epoch,
            expiry_epoch: 0,
            inputs: vec![TxInput::Coinbase {
                commitment: CoinbaseCommitmentV1 {
                    block_epoch: epoch,
                    block_height: 1,
                    parent_block_hash: parent,
                    protocol_operations_root: operation_root.0,
                },
            }],
            outputs: Vec::new(),
        },
        witnesses: Vec::new(),
    };
    let txs = vec![coinbase.clone()];
    let tx_root =
        merkle_root(&[coinbase.leaf()]).ok_or("Build 5.4 bootstrap TransactionRoot missing")?;
    if tx_root.to_hex() != "0da6084cc54e164effb81a07fad784fc237272cae6726fe45902aa0124e7cc1b" {
        return Err(format!(
            "Build 5.4 Block-1 TransactionRoot vector mismatch: {}",
            tx_root.to_hex()
        ));
    }
    let block_weight = block_body_weight(&txs, &operations)?;

    let mut next = state.clone();
    next.tip_epoch = epoch;
    for (i, (entry, id_hex)) in manifest
        .licenses
        .iter()
        .zip(fixture.bootstrap_license_ids.iter())
        .enumerate()
    {
        let expected_id = derive_license_id(
            DEVNET_NETWORK_ID,
            PURCHASE_METHOD_BTC,
            &payment_id.0,
            i as u32,
            &entry.owner_public_key,
        );
        if expected_id.to_hex() != *id_hex {
            return Err("Build 5.4 derived Bootstrap LicenseID mismatch".into());
        }
        next.licenses.push(LicenseState {
            index: i as u32,
            license_id: id_hex.clone(),
            purchase_id: fixture.bitcoin_payment_id.clone(),
            owner_public_key: hex::encode(entry.owner_public_key),
            mining_public_key: hex::encode(entry.mining_public_key),
            payment_address_id: hex::encode(address_id(&entry.owner_public_key).0),
            status: LICENSE_STATUS_PENDING,
            purchase_method: PURCHASE_METHOD_BTC,
            owner_key_sequence: 0,
            mining_key_sequence: 0,
            issued_epoch: fixture.bootstrap_issued_epoch,
            activation_epoch: fixture.bootstrap_activation_epoch,
            strike_weight: 0,
            suspended_until_epoch: 0,
            revocation_epoch: 0,
        });
    }
    next.consumed_bitcoin_payments.push(BitcoinPaymentState {
        payment_id: fixture.bitcoin_payment_id.clone(),
        txid_internal: hex::encode(validated.txid_internal),
        payment_output_index: validated.payment_output_index,
        paid_sats: validated.paid_sats,
        containing_block_hash_internal: hex::encode(validated.containing_block_hash_internal),
        containing_block_height: validated.containing_block_height,
        sixth_confirmation_hash_internal: hex::encode(validated.sixth_confirmation_hash_internal),
        sixth_confirmation_height: validated.sixth_confirmation_height,
        sixth_confirmation_timestamp: validated.sixth_confirmation_timestamp,
    });
    next.consumed_bitcoin_payments
        .sort_by(|a, b| a.payment_id.cmp(&b.payment_id));

    let next_state_root =
        compute_state_root(&next, &[], 1, 0, 0, 0, DIFFICULTY_Q32_ONE, BASE_FEE_MIN_Q32)?;
    if hex::encode(next_state_root)
        != "dcdde138a84d2afafdad4fbc7a3c7a671aaef67b8698bcdcf74060d2932341ad"
    {
        return Err(format!(
            "Build 5.4 Block-1 post-state vector mismatch: {}",
            hex::encode(next_state_root)
        ));
    }

    let target = derive_target(
        authorized_capacity(BOOTSTRAP_LICENSE_COUNT_V1 as u64),
        DIFFICULTY_Q32_ONE,
    )
    .map_err(|e| e.to_string())?;
    let mut core = [0u8; 208];
    core[0..2].copy_from_slice(&1u16.to_be_bytes());
    core[2..6].copy_from_slice(&DEVNET_NETWORK_ID.to_be_bytes());
    core[6..14].copy_from_slice(&epoch.to_be_bytes());
    core[14..46].copy_from_slice(&parent);
    core[46..78].copy_from_slice(&tx_root.0);
    core[78..110].copy_from_slice(&next_state_root);
    core[110..142].copy_from_slice(&target);
    // Reconciliation-only sentinel fields: no miner, no ticket proof, no signature.
    core[142..174].copy_from_slice(&[0u8; 32]);
    core[174..176].copy_from_slice(&0u16.to_be_bytes());
    core[176..208].copy_from_slice(&[0u8; 32]);
    let mut header = [0u8; 272];
    header[..208].copy_from_slice(&core);
    let block_hash_hex = hex::encode(block_hash(&header).0);
    if block_hash_hex != "6ccb8c9c732ef1df9298e1604ba01b5a8ae5ed9b49985593d705a142a081c766" {
        return Err(format!(
            "Build 5.4 Block-1 hash vector mismatch: {block_hash_hex}"
        ));
    }

    next.height = 1;
    next.tip_hash = block_hash_hex.clone();
    next.tip_epoch = epoch;
    next.anchor_epoch = epoch;
    next.anchor_license_id = hex::encode([0u8; 32]);
    next.anchor_ticket_index = 0;
    next.anchor_argon2_proof = hex::encode([0u8; 32]);
    next.total_issued_strikes = 0;
    next.difficulty_history_count = 0;
    next.difficulty_history_bitmap = 0;
    next.difficulty_correction_q32 = DIFFICULTY_Q32_ONE;
    next.base_fee_rate_q32 = BASE_FEE_MIN_Q32;
    next.current_state_root = hex::encode(next_state_root);
    next.blocks.push(BlockState {
        height: 1,
        epoch,
        header: hex::encode(header),
        transactions: txs.iter().map(|tx| hex::encode(tx.encode_full())).collect(),
        protocol_operations: operations
            .iter()
            .map(|op| hex::encode(op.encode()))
            .collect(),
        block_hash: block_hash_hex,
        parent_hash: hex::encode(parent),
        miner_license_id: hex::encode([0u8; 32]),
        ticket_index: 0,
        argon2_proof: hex::encode([0u8; 32]),
        target: hex::encode(target),
        reward_strikes: 0,
        total_fees_strikes: 0,
        treasury_fee_share_strikes: 0,
        block_weight,
        transaction_root: tx_root.to_hex(),
        state_root: hex::encode(next_state_root),
        coinbase_txid: coinbase.txid().to_hex(),
        transaction_ids: Vec::new(),
    });
    Ok((next, fixture, header, txs, operations))
}

pub(super) fn apply_devnet_bootstrap_block(
    state: &mut DevnetState,
) -> Result<DevnetBootstrapFixtureV1, String> {
    let (next, fixture, _, _, _) = build_devnet_bootstrap_transition(state)?;
    *state = next;
    Ok(fixture)
}

pub(super) fn validate_and_apply_devnet_block1(
    state: &mut DevnetState,
    header: [u8; 272],
    txs: Vec<TransactionV1>,
    operations: Vec<ProtocolOperationV1>,
) -> Result<String, String> {
    let (next, _, expected_header, expected_txs, expected_operations) =
        build_devnet_bootstrap_transition(state)?;
    if header != expected_header {
        return Err("Build 5.4 Bootstrap Block-1 header mismatch".into());
    }
    let got_txs = txs.iter().map(|tx| tx.encode_full()).collect::<Vec<_>>();
    let expected_tx_bytes = expected_txs
        .iter()
        .map(|tx| tx.encode_full())
        .collect::<Vec<_>>();
    if got_txs != expected_tx_bytes {
        return Err("Build 5.4 Bootstrap Block-1 transaction body mismatch".into());
    }
    let got_ops = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    let expected_ops = expected_operations
        .iter()
        .map(|op| op.encode())
        .collect::<Vec<_>>();
    if got_ops != expected_ops {
        return Err("Build 5.4 Bootstrap Block-1 protocol operation mismatch".into());
    }
    let hash = next.tip_hash.clone();
    *state = next;
    Ok(hash)
}

pub(super) fn write_fixture(
    dir: &Path,
    state: &DevnetState,
) -> Result<DevnetBootstrapFixtureV1, String> {
    let fixture = create_fixture(state)?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join("build54-bootstrap-devnet-v1.json");
    let bytes = serde_json::to_vec_pretty(&fixture).map_err(|e| e.to_string())?;
    fs::write(&path, bytes).map_err(|e| e.to_string())?;
    Ok(fixture)
}

pub(super) fn print_fixture(f: &DevnetBootstrapFixtureV1) {
    println!("Build 5.4 Devnet Genesis / Block-1 bootstrap reconciliation fixture");
    println!("Status:                 {}", f.reconciliation_status);
    println!("Bootstrap licenses:     {}", f.bootstrap_license_ids.len());
    println!(
        "Bootstrap payment:      {} sats",
        DEVNET_BOOTSTRAP_PAYMENT_SATS
    );
    println!("BootstrapManifestHash:  {}", f.manifest_hash);
    println!("Bitcoin anchor height:  {}", f.bitcoin_anchor_height);
    println!("Bitcoin anchor headers: {}", f.bitcoin_anchor_headers.len());
    println!("Bitcoin anchor hash:    {}", f.bitcoin_anchor_hash);
    println!("Bitcoin TXID:           {}", f.bitcoin_txid_display);
    println!("BitcoinPaymentID:       {}", f.bitcoin_payment_id);
    println!("Containing height:      {}", f.containing_height);
    println!("Sixth confirmation:     {}", f.sixth_confirmation_height);
    println!("Sixth-confirmation MTP: {}", f.sixth_confirmation_mtp);
    println!("Bootstrap issued epoch: {}", f.bootstrap_issued_epoch);
    println!("Bootstrap activates:    {}", f.bootstrap_activation_epoch);
    println!("Initial StateRoot:      {}", f.initial_state_root);
    println!("Genesis fixture ID:     {}", f.genesis_id);
    println!("BootstrapCommitment:    {}", f.bootstrap_commitment_hash);
    println!("Bootstrap OpID:         {}", f.bootstrap_operation_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn state() -> DevnetState {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build54-bootstrap-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let state = load_state(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
        state
    }

    #[test]
    fn build54_bootstrap_fixture_is_exactly_twelve_licenses_and_24576_sats() {
        let f = create_fixture(&state()).unwrap();
        assert_eq!(f.bootstrap_license_ids.len(), 12);
        assert_eq!(DEVNET_BOOTSTRAP_PAYMENT_SATS, 24_576);
    }

    #[test]
    fn build54_anchor_context_is_eleven_headers_at_retarget_boundary() {
        let f = create_fixture(&state()).unwrap();
        assert_eq!(f.bitcoin_anchor_headers.len(), 11);
        assert_eq!(f.bitcoin_anchor_height % 2016, 0);
        assert_eq!(f.bitcoin_anchor_height, 800_352);
    }

    #[test]
    fn build54_bootstrap_payment_has_six_confirmations_and_post_genesis_mtp() {
        let f = create_fixture(&state()).unwrap();
        assert_eq!(f.containing_height, 800_353);
        assert_eq!(f.sixth_confirmation_height, 800_358);
        assert!(f.sixth_confirmation_mtp > (DEVNET_FIXED_GENESIS_TIME_MS / 1000) as u32);
        assert_eq!(f.bootstrap_issued_epoch, 10);
        assert_eq!(f.bootstrap_activation_epoch, 74);
    }

    #[test]
    fn build54_bootstrap_fixture_is_deterministic() {
        let s = state();
        let a = create_fixture(&s).unwrap();
        let b = create_fixture(&s).unwrap();
        assert_eq!(a.genesis_id, b.genesis_id);
        assert_eq!(a.manifest_hash, b.manifest_hash);
        assert_eq!(a.bitcoin_payment_id, b.bitcoin_payment_id);
        assert_eq!(a.bootstrap_commitment_hash, b.bootstrap_commitment_hash);
        assert_eq!(a.bootstrap_operation_id, b.bootstrap_operation_id);
    }

    fn genesis_state() -> DevnetState {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build54-hotfix1-genesis-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_build54_genesis_devnet(&dir, 1, true).unwrap();
        let state = load_state(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
        state
    }

    #[test]
    fn build54_hotfix1_genesis_has_zero_licenses_and_reconciliation_identity() {
        let s = genesis_state();
        assert_eq!(s.format_version, 10);
        assert_eq!(s.height, 0);
        assert!(s.licenses.is_empty());
        assert!(s.consumed_bitcoin_payments.is_empty());
        assert_eq!(
            s.current_state_root,
            "e08ca8e75aa57e03b3f42575dbd0ecf7b64898d5a05ff22ad66c40adcfa0d2c7"
        );
        assert_eq!(
            s.genesis_hash,
            "4c603df8839ce020b42a1268a54a1938657a1b7812d2df92c4803d63355e702c"
        );
        assert_eq!(s.tip_hash, s.genesis_hash);
        check_state(&s).unwrap();
        blocksync::verify_full_replay(&s).unwrap();
    }

    #[test]
    fn build54_hotfix1_bootstrap_is_real_block1_state_transition() {
        let mut s = genesis_state();
        let f = apply_devnet_bootstrap_block(&mut s).unwrap();
        assert_eq!(s.height, 1);
        assert_eq!(s.tip_epoch, 10);
        assert_eq!(s.blocks.len(), 1);
        assert_eq!(s.licenses.len(), 12);
        assert!(s.licenses.iter().all(|l| l.status == LICENSE_STATUS_PENDING
            && l.issued_epoch == 10
            && l.activation_epoch == 74));
        assert_eq!(s.consumed_bitcoin_payments.len(), 1);
        assert_eq!(
            s.consumed_bitcoin_payments[0].payment_id,
            f.bitcoin_payment_id
        );
        assert_eq!(
            s.current_state_root,
            "dcdde138a84d2afafdad4fbc7a3c7a671aaef67b8698bcdcf74060d2932341ad"
        );
        assert_eq!(s.total_issued_strikes, 0);
        assert!(s.utxos.is_empty());
        check_state(&s).unwrap();
        blocksync::verify_full_replay(&s).unwrap();
    }

    #[test]
    fn build54_hotfix1_preactivation_epochs_do_not_change_difficulty_history() {
        let mut s = genesis_state();
        apply_devnet_bootstrap_block(&mut s).unwrap();
        assert_eq!(next_mineable_epoch(&s), 74);
        advance_empty_epochs_fast(&mut s, 73).unwrap();
        assert_eq!(s.difficulty_history_count, 0);
        assert_eq!(s.difficulty_history_bitmap, 0);
        assert_eq!(eligible_license_count(&s, 73), 0);
        apply_scheduled_license_transitions(&mut s, 74).unwrap();
        assert_eq!(eligible_license_count(&s, 74), 12);
    }

    #[test]
    fn build54_hotfix1_prebootstrap_mining_and_ordinary_btc_purchase_are_rejected() {
        let mut s = genesis_state();
        assert!(mine_epoch(&mut s, 64)
            .unwrap_err()
            .contains("bootstrap-dev"));
        assert!(bitcoin::create_dev_purchase(&s, 1, 0)
            .err()
            .unwrap()
            .contains("Bootstrap Block 1"));
        assert_eq!(s.height, 0);
        assert_eq!(s.tip_epoch, 0);
    }

    #[test]
    fn build54_hotfix1_bootstrap_cannot_execute_twice() {
        let mut s = genesis_state();
        apply_devnet_bootstrap_block(&mut s).unwrap();
        assert!(apply_devnet_bootstrap_block(&mut s)
            .unwrap_err()
            .contains("exactly once"));
    }

    #[test]
    fn build54_bootstrap_fixture_matches_independent_verifier() {
        let f = create_fixture(&state()).unwrap();
        assert_eq!(
            f.manifest_hash,
            "1153397089502ba6dca089baa34e6baf6659b86204e888803aac8d3c6e2724d1"
        );
        assert_eq!(
            f.bitcoin_txid_display,
            "1e39ae0f16e85c6aabfb1d3ee8d9f76c1df44e4987f5e39fbc82d1bf1f653350"
        );
        assert_eq!(
            f.bitcoin_payment_id,
            "a8d97e84868d0fbf0cf132ae3a8af9c6818e6e461fec9785e7465686ce88c0b7"
        );
        assert_eq!(
            f.initial_state_root,
            "e08ca8e75aa57e03b3f42575dbd0ecf7b64898d5a05ff22ad66c40adcfa0d2c7"
        );
        assert_eq!(
            f.genesis_id,
            "4c603df8839ce020b42a1268a54a1938657a1b7812d2df92c4803d63355e702c"
        );
        assert_eq!(
            f.bootstrap_license_ids[0],
            "de1e06240de41436762423c7d937901ccbb01d60e416fa8e0ff61c91b2c8ab2e"
        );
        assert_eq!(
            f.bootstrap_license_ids[11],
            "60a0c7a0f531f225a3c649d81ad80d49a060a429a356cc9b49368b8fbcb1a849"
        );
        assert_eq!(
            f.bootstrap_commitment_hash,
            "45563b710a96a5f6bb37e850a450be3b6258f72cfe3ddc63e7a9929d8ca3d16b"
        );
        assert_eq!(
            f.bootstrap_operation_id,
            "48c137614e866853dea743b4c6f9d13798d6561c7a0d6376fc04dcd89271a85b"
        );
    }
}
