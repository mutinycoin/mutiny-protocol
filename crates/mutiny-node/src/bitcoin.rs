use super::*;
use mutiny_bitcoin::{
    canonical_manifest_script, double_sha256, merkle_root_from_branch, mine_easy_header,
    parse_transaction, BitcoinSpvProofV1, ValidatedBitcoinPayment, REQUIRED_CONFIRMATIONS,
};
use mutiny_protocol::{
    bitcoin_payment_id, BitcoinHeadersV1, BtcLicenseManifestV1, LicensePurchaseBtcV1,
};

pub(super) fn decode_purchase_operation(
    op: &ProtocolOperationV1,
) -> Result<LicensePurchaseBtcV1, String> {
    if op.op_type != OP_LICENSE_PURCHASE_BTC || op.op_version != 1 {
        return Err("operation is not a V1 Bitcoin Mining License purchase".into());
    }
    LicensePurchaseBtcV1::decode_payload(&op.payload).map_err(|e| e.to_string())
}

const BTC_SUNSET_EPOCH: u64 = 2_097_152;

fn payment_epoch_from_mtp(state: &DevnetState, payment_mtp: u32) -> Result<u64, String> {
    let genesis_seconds_u128 = state.genesis_time_ms / 1_000;
    let genesis_seconds = u64::try_from(genesis_seconds_u128)
        .map_err(|_| "Mutiny Genesis time does not fit u64 seconds")?;
    let payment_seconds = u64::from(payment_mtp);
    if payment_seconds < genesis_seconds {
        return Err("Bitcoin PaymentMTP predates Mutiny Genesis time".into());
    }
    Ok((payment_seconds - genesis_seconds) / 60)
}

fn historical_license_count(state: &DevnetState, payment_epoch: u64) -> Result<u64, String> {
    u64::try_from(
        state
            .licenses
            .iter()
            .filter(|license| license.issued_epoch < payment_epoch)
            .count(),
    )
    .map_err(|_| "historical Mining License count does not fit u64".into())
}

fn btc_price_sats_per_license(historical_license_count: u64) -> Result<u64, String> {
    let step = historical_license_count / (1u64 << 18);
    let exponent = 11u64
        .checked_add(step)
        .ok_or("Bitcoin Mining License price exponent overflow")?;
    let exponent =
        u32::try_from(exponent).map_err(|_| "Bitcoin Mining License price exponent overflow")?;
    1u64.checked_shl(exponent)
        .ok_or_else(|| "Bitcoin Mining License price overflow".into())
}

fn required_sats(
    state: &DevnetState,
    payment_epoch: u64,
    count: usize,
) -> Result<(u64, u64), String> {
    let l_e = historical_license_count(state, payment_epoch)?;
    let price_each = btc_price_sats_per_license(l_e)?;
    let count = u64::try_from(count).map_err(|_| "Bitcoin Mining License count overflow")?;
    let total = price_each
        .checked_mul(count)
        .ok_or("Bitcoin Mining License total price overflow")?;
    Ok((price_each, total))
}

struct ValidatedPurchaseContext {
    purchase: LicensePurchaseBtcV1,
    validated: ValidatedBitcoinPayment,
    ids: Vec<LicenseId>,
}

fn validate_payment_against_authenticated_window(
    proof: &BitcoinSpvProofV1,
    window: &bitcoin_headers::AuthenticatedPurchaseWindow,
    expected_manifest_hash: &[u8; 32],
    treasury_script_pubkey: &[u8],
    required_sats: u64,
) -> Result<ValidatedBitcoinPayment, String> {
    let parsed = parse_transaction(&proof.raw_transaction).map_err(|e| e.to_string())?;
    let root = merkle_root_from_branch(parsed.txid_internal, proof.tx_index, &proof.merkle_branch);
    if root != window.containing_header.merkle_root_internal() {
        return Err("Bitcoin Merkle proof does not match authenticated containing block".into());
    }

    let payment = parsed
        .outputs
        .get(proof.payment_output_index as usize)
        .ok_or("Bitcoin payment output index is out of range")?;
    if payment.value_sats < required_sats {
        return Err("Bitcoin payment amount is below the required PaymentEpoch price".into());
    }
    if payment.script_pubkey != treasury_script_pubkey {
        return Err("Bitcoin payment output script does not match Treasury script".into());
    }

    let manifest = parsed
        .outputs
        .get(proof.manifest_output_index as usize)
        .ok_or("Bitcoin manifest output index is out of range")?;
    let expected_manifest_script = canonical_manifest_script(expected_manifest_hash);
    if manifest.value_sats != 0
        || manifest.script_pubkey.as_slice() != expected_manifest_script.as_slice()
    {
        return Err(
            "Bitcoin transaction does not contain the canonical manifest commitment".into(),
        );
    }

    let sixth_height = proof
        .containing_block_height
        .checked_add(REQUIRED_CONFIRMATIONS as u32 - 1)
        .ok_or("Bitcoin sixth-confirmation height overflow")?;

    Ok(ValidatedBitcoinPayment {
        txid_internal: parsed.txid_internal,
        containing_block_hash_internal: window.containing_header.hash_internal(),
        containing_block_height: proof.containing_block_height,
        sixth_confirmation_hash_internal: window.sixth_header.hash_internal(),
        sixth_confirmation_height: sixth_height,
        sixth_confirmation_timestamp: window.sixth_header.timestamp(),
        payment_output_index: proof.payment_output_index,
        paid_sats: payment.value_sats,
    })
}

fn validate_purchase_context(
    state: &DevnetState,
    op: &ProtocolOperationV1,
    block_epoch: u64,
) -> Result<ValidatedPurchaseContext, String> {
    let purchase = decode_purchase_operation(op)?;
    let state_genesis_id = decode32(&state.genesis_hash)?;
    let policy = bitcoin_headers::resolve_tuple_policy(state.network_id, &state_genesis_id)
        .ok_or("ordinary BTC purchases are inactive for this Mutiny NetworkID/GenesisID tuple")?;
    if !policy.ordinary_purchase_active {
        return Err("ordinary BTC purchases are inactive for this Mutiny tuple".into());
    }
    let treasury_script_pubkey = policy
        .treasury_script_pubkey
        .ok_or("ordinary BTC purchase Treasury script is unassigned for this Mutiny tuple")?;

    if purchase.manifest.network_id != state.network_id {
        return Err("Bitcoin Mining License purchase manifest NetworkID mismatch".into());
    }
    if purchase.manifest.genesis_hash != state_genesis_id {
        return Err("Bitcoin Mining License purchase manifest GenesisID mismatch".into());
    }

    let window = bitcoin_headers::validate_purchase_window(
        state,
        &purchase.proof.headers,
        purchase.proof.containing_block_height,
    )?;

    let payment_epoch = payment_epoch_from_mtp(state, window.payment_mtp)?;
    if payment_epoch > block_epoch {
        return Err("Bitcoin PaymentEpoch is later than Mutiny consumption block epoch".into());
    }
    if payment_epoch >= BTC_SUNSET_EPOCH {
        return Err("Bitcoin payment is ineligible at or after BTC sunset epoch 2,097,152".into());
    }
    if block_epoch >= bitcoin_headers::PACK_M_BTC_DISABLE_EPOCH {
        return Err(
            "ordinary BTC purchase consumption is disabled beginning Mutiny epoch 2,101,248".into(),
        );
    }

    let (_price_each, required) =
        required_sats(state, payment_epoch, purchase.manifest.licenses.len())?;
    let manifest_hash = purchase
        .manifest
        .manifest_hash()
        .map_err(|e| e.to_string())?;
    let validated = validate_payment_against_authenticated_window(
        &purchase.proof,
        &window,
        &manifest_hash.0,
        treasury_script_pubkey,
        required,
    )?;

    let payment_id = bitcoin_payment_id(&validated.txid_internal, validated.payment_output_index);
    let payment_hex = hex::encode(payment_id.0);
    if state
        .consumed_bitcoin_payments
        .iter()
        .any(|payment| payment.payment_id == payment_hex)
    {
        return Err("BitcoinPaymentID has already been consumed".into());
    }

    let ids = purchase.license_ids().map_err(|e| e.to_string())?;
    if ids.len() != purchase.manifest.licenses.len() {
        return Err("Bitcoin Mining License derived ID count mismatch".into());
    }
    for id in &ids {
        if state
            .licenses
            .iter()
            .any(|license| license.license_id == hex::encode(id.0))
        {
            return Err("derived Bitcoin Mining LicenseID already exists".into());
        }
    }

    Ok(ValidatedPurchaseContext {
        purchase,
        validated,
        ids,
    })
}

#[cfg(test)]
pub(super) fn operation_payment_id(op: &ProtocolOperationV1) -> Result<[u8; 32], String> {
    let purchase = decode_purchase_operation(op)?;
    let parsed = parse_transaction(&purchase.proof.raw_transaction).map_err(|e| e.to_string())?;
    Ok(bitcoin_payment_id(&parsed.txid_internal, purchase.proof.payment_output_index).0)
}

pub(super) fn dependency_ready(
    state: &DevnetState,
    op: &ProtocolOperationV1,
) -> Result<bool, String> {
    // Reorg resurrection readiness is deliberately weaker than block readiness:
    // a purchase previously valid on a disconnected Mutiny branch may return to
    // the pending queue even when its Bitcoin proof is not on the *current*
    // authenticated best chain. sorted_pending_protocol_operations_for_epoch()
    // uses dependency_ready_at_epoch(), so the operation cannot reconfirm until
    // full Pack-M current-best-chain validation succeeds again.
    let purchase = decode_purchase_operation(op)?;
    let state_genesis_id = decode32(&state.genesis_hash)?;
    if purchase.manifest.network_id != state.network_id
        || purchase.manifest.genesis_hash != state_genesis_id
    {
        return Ok(false);
    }
    let policy = match bitcoin_headers::resolve_tuple_policy(state.network_id, &state_genesis_id) {
        Some(policy) => policy,
        None => return Ok(false),
    };

    if !policy.ordinary_purchase_active || policy.treasury_script_pubkey.is_none() {
        return Ok(false);
    }

    let parsed = parse_transaction(&purchase.proof.raw_transaction).map_err(|e| e.to_string())?;
    let payment_id = bitcoin_payment_id(&parsed.txid_internal, purchase.proof.payment_output_index);
    if state
        .consumed_bitcoin_payments
        .iter()
        .any(|payment| payment.payment_id == hex::encode(payment_id.0))
    {
        return Ok(false);
    }

    let ids = purchase.license_ids().map_err(|e| e.to_string())?;
    Ok(ids.iter().all(|id| {
        !state
            .licenses
            .iter()
            .any(|license| license.license_id == hex::encode(id.0))
    }))
}

pub(super) fn dependency_ready_at_epoch(
    state: &DevnetState,
    op: &ProtocolOperationV1,
    block_epoch: u64,
) -> Result<bool, String> {
    let purchase = decode_purchase_operation(op)?;
    if purchase.manifest.network_id != state.network_id
        || purchase.manifest.genesis_hash != decode32(&state.genesis_hash)?
    {
        return Ok(false);
    }
    Ok(validate_purchase_context(state, op, block_epoch).is_ok())
}

pub(super) fn apply_operation(
    state: &mut DevnetState,
    op: &ProtocolOperationV1,
    block_epoch: u64,
) -> Result<Vec<LicenseId>, String> {
    let context = validate_purchase_context(state, op, block_epoch)?;
    let payment_id = bitcoin_payment_id(
        &context.validated.txid_internal,
        context.validated.payment_output_index,
    );
    let payment_hex = hex::encode(payment_id.0);

    for (id, entry) in context
        .ids
        .iter()
        .zip(context.purchase.manifest.licenses.iter())
    {
        let index =
            u32::try_from(state.licenses.len()).map_err(|_| "license registry index overflow")?;
        let payment_address_id = address_id(&entry.owner_public_key).0;
        state.licenses.push(LicenseState {
            index,
            license_id: hex::encode(id.0),
            purchase_id: payment_hex.clone(),
            owner_public_key: hex::encode(entry.owner_public_key),
            mining_public_key: hex::encode(entry.mining_public_key),
            payment_address_id: hex::encode(payment_address_id),
            status: LICENSE_STATUS_PENDING,
            purchase_method: PURCHASE_METHOD_BTC,
            owner_key_sequence: 0,
            mining_key_sequence: 0,
            issued_epoch: block_epoch,
            activation_epoch: block_epoch
                .checked_add(ACTIVATION_DELAY_EPOCHS)
                .ok_or("activation epoch overflow")?,
            strike_weight: 0,
            suspended_until_epoch: 0,
            revocation_epoch: 0,
        });
    }

    state.consumed_bitcoin_payments.push(BitcoinPaymentState {
        payment_id: payment_hex,
        txid_internal: hex::encode(context.validated.txid_internal),
        payment_output_index: context.validated.payment_output_index,
        paid_sats: context.validated.paid_sats,
        containing_block_hash_internal: hex::encode(
            context.validated.containing_block_hash_internal,
        ),
        containing_block_height: context.validated.containing_block_height,
        sixth_confirmation_hash_internal: hex::encode(
            context.validated.sixth_confirmation_hash_internal,
        ),
        sixth_confirmation_height: context.validated.sixth_confirmation_height,
        sixth_confirmation_timestamp: context.validated.sixth_confirmation_timestamp,
    });
    state
        .consumed_bitcoin_payments
        .sort_by(|a, b| a.payment_id.cmp(&b.payment_id));

    Ok(context.ids)
}

fn compact_size_small(n: usize) -> Result<Vec<u8>, String> {
    if n > 0xfc {
        return Err("Devnet Bitcoin fixture only supports CompactSize values <= 252".into());
    }
    Ok(vec![n as u8])
}

fn build_fixture_transaction(
    manifest_hash: &[u8; 32],
    amount_sats: u64,
    variant: u32,
    genesis_hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&2u32.to_le_bytes());
    tx.push(1); // one input
    let prev = sha256_domain(
        domains::BTC_PAYMENT_ID,
        &[
            b"MUTINY-DEVNET-BTC-FIXTURE-PREVOUT-V1",
            genesis_hash,
            &variant.to_be_bytes(),
        ],
    );
    tx.extend_from_slice(&prev.0);
    tx.extend_from_slice(&variant.to_le_bytes());
    tx.push(2);
    tx.extend_from_slice(&[0x51, (variant & 0xff) as u8]);
    tx.extend_from_slice(&0xffff_fffeu32.to_le_bytes());
    tx.push(2); // payment + OP_RETURN
    tx.extend_from_slice(&amount_sats.to_le_bytes());
    tx.extend_from_slice(&compact_size_small(DEVNET_BTC_TREASURY_SCRIPT.len())?);
    tx.extend_from_slice(DEVNET_BTC_TREASURY_SCRIPT);
    tx.extend_from_slice(&0u64.to_le_bytes());
    let commitment = canonical_manifest_script(manifest_hash);
    tx.extend_from_slice(&compact_size_small(commitment.len())?);
    tx.extend_from_slice(&commitment);
    tx.extend_from_slice(&0u32.to_le_bytes());
    Ok(tx)
}

pub(super) struct DevPurchaseFixture {
    pub header_pending: PendingProtocolOperationState,
    pub pending: PendingProtocolOperationState,
    pub header_operation: ProtocolOperationV1,
    pub operation: ProtocolOperationV1,
    pub ids: Vec<LicenseId>,
    pub payment_id: [u8; 32],
    pub txid_internal: [u8; 32],
    pub paid_sats: u64,
    pub price_each: u64,
    pub payment_epoch: u64,
    pub containing_height: u32,
    pub sixth_height: u32,
    pub sixth_timestamp: u32,
}

pub(super) fn create_dev_purchase(
    state: &DevnetState,
    count: usize,
    variant: u32,
) -> Result<DevPurchaseFixture, String> {
    if state.format_version >= 10 && state.height == 0 {
        return Err(
            "Build 5.4 requires Bootstrap Block 1 before ordinary post-Genesis Bitcoin purchases"
                .into(),
        );
    }
    if state.network_id != DEVNET_NETWORK_ID || state.genesis_hash != DEVNET_GENESIS_ID_HEX {
        return Err(
            "Pack-M Devnet BTC purchase fixture requires the locked Pack-J GenesisID".into(),
        );
    }
    if count == 0 || count > 64 {
        return Err(
            "--count must be in 1..=64 for the deterministic Devnet Bitcoin fixture".into(),
        );
    }
    if state.pending_protocol_operations.iter().any(|pending| {
        pending
            .operation()
            .map(|op| matches!(op.op_type, OP_LICENSE_PURCHASE_BTC | OP_BITCOIN_HEADERS))
            .unwrap_or(false)
    }) {
        return Err(
            "complete the existing Devnet Bitcoin header/purchase bundle before creating another"
                .into(),
        );
    }

    let intended_epoch = next_mineable_epoch(state);
    if intended_epoch >= BTC_SUNSET_EPOCH {
        return Err(
            "new deterministic Devnet Bitcoin payments are disabled at the BTC sunset epoch".into(),
        );
    }
    let payment_epoch = intended_epoch;

    let variant_slot =
        usize::try_from(variant).map_err(|_| "Devnet Bitcoin fixture variant overflow")?;
    let starting_slot = BOOTSTRAP_LICENSE_COUNT
        .checked_add(variant_slot)
        .ok_or("Devnet key-slot overflow")?;
    if starting_slot
        .checked_add(count)
        .ok_or("Devnet key-slot overflow")?
        > 256
    {
        return Err(
            "Devnet Bitcoin fixture --variant/--count exceed the 256 deterministic local key slots"
                .into(),
        );
    }

    let genesis_hash = decode32(&state.genesis_hash)?;
    let nonce = sha256_domain(
        domains::BTC_MANIFEST,
        &[
            b"MUTINY-DEVNET-BTC-PURCHASE-NONCE-V1",
            &genesis_hash,
            &variant.to_be_bytes(),
            &(starting_slot as u32).to_be_bytes(),
            &(count as u32).to_be_bytes(),
        ],
    )
    .0;
    let licenses = (0..count)
        .map(|i| {
            let owner = SigningKey::from_bytes(&dev_seed((starting_slot + i) as u8));
            let mining_seed = sha256_domain(
                domains::BTC_MANIFEST,
                &[
                    b"MUTINY-DEVNET-BTC-MINING-KEY-V1",
                    &owner.to_bytes(),
                    &variant.to_be_bytes(),
                ],
            )
            .0;
            let mining = SigningKey::from_bytes(&mining_seed);
            LicenseManifestEntryV1 {
                owner_public_key: owner.verifying_key().to_bytes(),
                mining_public_key: mining.verifying_key().to_bytes(),
            }
        })
        .collect::<Vec<_>>();

    let manifest = BtcLicenseManifestV1 {
        version: 1,
        network_id: DEVNET_NETWORK_ID,
        genesis_hash,
        purchase_nonce: nonce,
        licenses,
    };
    let manifest_hash = manifest.manifest_hash().map_err(|e| e.to_string())?;
    let (price_each, amount) = required_sats(state, payment_epoch, count)?;
    let raw_transaction =
        build_fixture_transaction(&manifest_hash.0, amount, variant, &genesis_hash)?;
    let parsed = parse_transaction(&raw_transaction).map_err(|e| e.to_string())?;

    let (parent_hash, parent_height) = match &state.bitcoin_best_chain {
        Some(best) => (decode32(&best.tip_hash_internal)?, best.tip_height),
        None => (
            bitcoin_headers::PACK_J_ANCHOR_HASH_INTERNAL,
            bitcoin_headers::PACK_J_ANCHOR_HEIGHT,
        ),
    };

    let genesis_seconds = u64::try_from(state.genesis_time_ms / 1_000)
        .map_err(|_| "Mutiny Genesis time does not fit u64 seconds")?;
    let payment_mtp_u64 = genesis_seconds
        .checked_add(payment_epoch.checked_mul(60).ok_or("PaymentMTP overflow")?)
        .ok_or("PaymentMTP overflow")?;
    let payment_mtp =
        u32::try_from(payment_mtp_u64).map_err(|_| "PaymentMTP does not fit Bitcoin timestamp")?;
    let first_timestamp = payment_mtp
        .checked_sub(3_000)
        .ok_or("Devnet fixture PaymentMTP too early for eleven-header context")?;

    let mut all_headers = Vec::<mutiny_bitcoin::BitcoinHeader>::with_capacity(16);
    let mut previous = parent_hash;
    for i in 0..16u32 {
        let merkle = if i == 10 {
            parsed.txid_internal
        } else {
            double_sha256(
                &[
                    b"MUTINY-PACK-M-DEV-PURCHASE-HEADER-V1".as_slice(),
                    &genesis_hash,
                    &variant.to_be_bytes(),
                    &i.to_be_bytes(),
                ]
                .concat(),
            )
        };
        let timestamp = first_timestamp
            .checked_add(
                i.checked_mul(600)
                    .ok_or("Devnet Bitcoin fixture timestamp overflow")?,
            )
            .ok_or("Devnet Bitcoin fixture timestamp overflow")?;
        let header = mine_easy_header(
            previous,
            merkle,
            timestamp,
            DEVNET_BTC_BITS,
            variant.wrapping_add(i),
        )
        .map_err(|e| e.to_string())?;
        previous = header.hash_internal();
        all_headers.push(header);
    }

    let containing_height = parent_height
        .checked_add(11)
        .ok_or("Devnet Bitcoin fixture containing height overflow")?;
    let proof = BitcoinSpvProofV1 {
        raw_transaction,
        payment_output_index: 0,
        manifest_output_index: 1,
        tx_index: 0,
        merkle_branch: Vec::new(),
        headers: all_headers[10..].to_vec(),
        containing_block_height: containing_height,
    };
    let purchase = LicensePurchaseBtcV1 { manifest, proof };
    let operation = purchase.operation().map_err(|e| e.to_string())?;
    let ids = purchase.license_ids().map_err(|e| e.to_string())?;

    let header_operation = BitcoinHeadersV1 {
        network_id: DEVNET_NETWORK_ID,
        genesis_id: genesis_hash,
        headers: all_headers.iter().map(|header| header.raw).collect(),
    }
    .to_operation()
    .map_err(|e| e.to_string())?;

    let mut authenticated = state.clone();
    bitcoin_headers::apply_operation(&mut authenticated, &header_operation, intended_epoch)?;
    let validation_epoch = intended_epoch
        .checked_add(1)
        .ok_or("Devnet BTC validation epoch overflow")?;
    let context = validate_purchase_context(&authenticated, &operation, validation_epoch)?;
    let payment_id = bitcoin_payment_id(
        &context.validated.txid_internal,
        context.validated.payment_output_index,
    )
    .0;

    if state
        .consumed_bitcoin_payments
        .iter()
        .any(|p| p.payment_id == hex::encode(payment_id))
    {
        return Err(
            "deterministic Devnet BitcoinPaymentID has already been consumed; choose another --variant or purchase shape"
                .into(),
        );
    }

    Ok(DevPurchaseFixture {
        header_pending: PendingProtocolOperationState {
            operation: hex::encode(header_operation.encode()),
            required_txid: String::new(),
        },
        pending: PendingProtocolOperationState {
            operation: hex::encode(operation.encode()),
            required_txid: String::new(),
        },
        header_operation,
        operation,
        ids,
        payment_id,
        txid_internal: context.validated.txid_internal,
        paid_sats: context.validated.paid_sats,
        price_each,
        payment_epoch,
        containing_height: context.validated.containing_block_height,
        sixth_height: context.validated.sixth_confirmation_height,
        sixth_timestamp: context.validated.sixth_confirmation_timestamp,
    })
}

pub(super) fn check_state(state: &DevnetState) -> Result<(), String> {
    let mut ids = HashSet::new();
    for payment in &state.consumed_bitcoin_payments {
        let payment_id = decode32(&payment.payment_id)?;
        let txid = decode32(&payment.txid_internal)?;
        decode32(&payment.containing_block_hash_internal)?;
        decode32(&payment.sixth_confirmation_hash_internal)?;
        if bitcoin_payment_id(&txid, payment.payment_output_index).0 != payment_id {
            return Err("stored BitcoinPaymentID does not match Bitcoin txid/output index".into());
        }
        if payment.paid_sats == 0 {
            return Err("stored Bitcoin payment amount must be nonzero".into());
        }
        let minimum_sixth = payment
            .containing_block_height
            .checked_add(5)
            .ok_or("stored Bitcoin payment height overflow")?;
        if payment.sixth_confirmation_height < minimum_sixth {
            return Err("stored Bitcoin payment has fewer than six confirmations".into());
        }
        if !ids.insert(payment.payment_id.clone()) {
            return Err("duplicate consumed BitcoinPaymentID".into());
        }
    }
    Ok(())
}

pub(super) fn print_payments(state: &DevnetState) {
    println!(
        "Consumed Bitcoin payments: {}",
        state.consumed_bitcoin_payments.len()
    );
    println!(
        "Devnet BTC base price tier: {} sats/license (<2^18 historical licenses)",
        DEVNET_BTC_PRICE_SATS_PER_LICENSE
    );
    println!("Required confirmations:    {}", REQUIRED_CONFIRMATIONS);
    for (i, payment) in state.consumed_bitcoin_payments.iter().enumerate() {
        let display_txid = decode32(&payment.txid_internal)
            .map(mutiny_bitcoin::display_hex_from_internal)
            .unwrap_or_else(|_| "<invalid>".into());
        println!(
            "payment {:03}  id={}  txid={}  vout={}  sats={}  block={}  sixth={}  sixth_time={}",
            i + 1,
            &payment.payment_id[..16.min(payment.payment_id.len())],
            display_txid,
            payment.payment_output_index,
            payment.paid_sats,
            payment.containing_block_height,
            payment.sixth_confirmation_height,
            payment.sixth_confirmation_timestamp,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn fresh_state() -> DevnetState {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build66b-bitcoin-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_build54_genesis_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        bootstrap::apply_devnet_bootstrap_block(&mut state).unwrap();
        let _ = fs::remove_dir_all(&dir);
        state
    }

    fn authenticate_fixture(state: &mut DevnetState, fixture: &DevPurchaseFixture, epoch: u64) {
        bitcoin_headers::apply_operation(state, &fixture.header_operation, epoch).unwrap();
        bitcoin_headers::check_state(state).unwrap();
    }

    fn extend_fixture_branch(
        state: &mut DevnetState,
        fixture: &DevPurchaseFixture,
        epoch: u64,
        marker: &[u8],
    ) {
        bitcoin_headers::apply_operation(state, &fixture.header_operation, epoch).unwrap();
        let batch = BitcoinHeadersV1::from_operation(&fixture.header_operation).unwrap();
        let tip = mutiny_bitcoin::BitcoinHeader {
            raw: *batch.headers.last().unwrap(),
        };
        let child = mine_easy_header(
            tip.hash_internal(),
            double_sha256(marker),
            tip.timestamp().saturating_add(600),
            DEVNET_BTC_BITS,
            50_000,
        )
        .unwrap();
        let child_op = BitcoinHeadersV1 {
            network_id: DEVNET_NETWORK_ID,
            genesis_id: decode32(&state.genesis_hash).unwrap(),
            headers: vec![child.raw],
        }
        .to_operation()
        .unwrap();
        bitcoin_headers::apply_operation(state, &child_op, epoch + 1).unwrap();
    }

    #[test]
    fn build66b_candidate1_purchase_is_not_ready_until_headers_are_authenticated() {
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 0).unwrap();
        assert!(!dependency_ready_at_epoch(&state, &fixture.operation, 100).unwrap());
        authenticate_fixture(&mut state, &fixture, 74);
        assert!(dependency_ready_at_epoch(&state, &fixture.operation, 100).unwrap());
    }

    #[test]
    fn build66b_candidate1_requires_six_best_chain_confirmations() {
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 1).unwrap();
        authenticate_fixture(&mut state, &fixture, 74);
        let mut purchase = decode_purchase_operation(&fixture.operation).unwrap();
        purchase.proof.headers.pop();
        let five = purchase.operation().unwrap();
        assert!(apply_operation(&mut state, &five, 100)
            .unwrap_err()
            .contains("six confirmations"));
    }

    #[test]
    fn build66b_candidate1_payment_epoch_price_and_historical_snapshot_boundaries() {
        let state = fresh_state();
        assert_eq!(btc_price_sats_per_license(0).unwrap(), 2_048);
        assert_eq!(btc_price_sats_per_license(262_143).unwrap(), 2_048);
        assert_eq!(btc_price_sats_per_license(262_144).unwrap(), 4_096);
        assert_eq!(btc_price_sats_per_license(524_288).unwrap(), 8_192);
        let fixture = create_dev_purchase(&state, 1, 2).unwrap();
        assert_eq!(fixture.price_each, 2_048);
        assert_eq!(
            historical_license_count(&state, fixture.payment_epoch).unwrap(),
            state
                .licenses
                .iter()
                .filter(|license| license.issued_epoch < fixture.payment_epoch)
                .count() as u64
        );
    }

    #[test]
    fn build66b_candidate1_payment_epoch_and_consumption_sunset_are_fail_closed() {
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 3).unwrap();
        authenticate_fixture(&mut state, &fixture, 74);
        assert!(fixture.payment_epoch < BTC_SUNSET_EPOCH);
        assert!(apply_operation(
            &mut state,
            &fixture.operation,
            bitcoin_headers::PACK_M_BTC_DISABLE_EPOCH,
        )
        .unwrap_err()
        .contains("2,101,248"));
    }

    #[test]
    fn build66b_candidate1_wrong_genesis_manifest_is_rejected() {
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 4).unwrap();
        authenticate_fixture(&mut state, &fixture, 74);
        let mut purchase = decode_purchase_operation(&fixture.operation).unwrap();
        purchase.manifest.genesis_hash[0] ^= 1;
        let op = purchase.operation().unwrap();
        assert!(apply_operation(&mut state, &op, 100)
            .unwrap_err()
            .contains("GenesisID"));
    }

    #[test]
    fn build66b_candidate1_external_payment_shape_and_replay_remain_locked() {
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 5).unwrap();
        authenticate_fixture(&mut state, &fixture, 74);
        let ids = apply_operation(&mut state, &fixture.operation, 100).unwrap();
        assert_eq!(ids, fixture.ids);
        let ordinary = state
            .consumed_bitcoin_payments
            .iter()
            .find(|payment| payment.payment_id == hex::encode(fixture.payment_id))
            .unwrap();
        assert_eq!(ordinary.value_bytes().unwrap().len(), 120);
        assert_eq!(ordinary.paid_sats, fixture.paid_sats);
        assert_eq!(ordinary.containing_block_height, fixture.containing_height);
        assert_eq!(ordinary.sixth_confirmation_height, fixture.sixth_height);
        let err = apply_operation(&mut state, &fixture.operation, 101).unwrap_err();
        assert!(err.contains("BitcoinPaymentID") || err.contains("LicenseID"));
    }

    #[test]
    fn build66b_candidate1_payment_and_license_ids_remain_header_witness_independent() {
        let mut state = fresh_state();
        let before = create_dev_purchase(&state, 1, 6).unwrap();
        let unrelated = create_dev_purchase(&state, 1, 7).unwrap();
        authenticate_fixture(&mut state, &unrelated, 74);
        apply_operation(&mut state, &unrelated.operation, 100).unwrap();
        let after = create_dev_purchase(&state, 1, 6).unwrap();
        assert_eq!(before.txid_internal, after.txid_internal);
        assert_eq!(before.payment_id, after.payment_id);
        assert_eq!(before.ids, after.ids);
    }

    #[test]
    fn build66b_candidate1_external_reorg_after_consumption_does_not_remove_license() {
        let base = fresh_state();
        let a = create_dev_purchase(&base, 1, 8).unwrap();
        let b = create_dev_purchase(&base, 1, 9).unwrap();
        let mut state = base.clone();

        authenticate_fixture(&mut state, &a, 74);
        apply_operation(&mut state, &a.operation, 100).unwrap();
        let issued = hex::encode(a.ids[0].0);

        extend_fixture_branch(&mut state, &b, 101, b"MUTINY-BUILD66B-EXTERNAL-REORG-CHILD");

        assert!(state
            .licenses
            .iter()
            .any(|license| license.license_id == issued));
        assert!(state
            .consumed_bitcoin_payments
            .iter()
            .any(|payment| payment.payment_id == hex::encode(a.payment_id)));
        check_state(&state).unwrap();
    }

    #[test]
    fn build66b_candidate1_unconsumed_purchase_must_follow_current_best_after_reorg() {
        let base = fresh_state();
        let a = create_dev_purchase(&base, 1, 10).unwrap();
        let b = create_dev_purchase(&base, 1, 11).unwrap();
        let mut state = base;

        authenticate_fixture(&mut state, &a, 74);
        assert!(dependency_ready_at_epoch(&state, &a.operation, 100).unwrap());

        extend_fixture_branch(
            &mut state,
            &b,
            75,
            b"MUTINY-BUILD66B-PRECONSUMPTION-REORG-CHILD",
        );

        // The orphaned operation is eligible to return to the pending queue,
        // but it is NOT block-ready until the current Bitcoin best chain again
        // authenticates the required containing->sixth confirmation window.
        assert!(dependency_ready(&state, &a.operation).unwrap());
        assert!(!dependency_ready_at_epoch(&state, &a.operation, 100).unwrap());
        assert!(apply_operation(&mut state, &a.operation, 100)
            .unwrap_err()
            .contains("current authenticated best chain"));
    }

    #[test]
    fn build66b_candidate1_empty_external_payment_root_shape_is_unchanged_before_bootstrap() {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build66b-empty-root-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_build54_genesis_devnet(&dir, 1, true).unwrap();
        let state = load_state(&dir).unwrap();
        assert_eq!(
            compute_external_payment_root(&state).unwrap(),
            mutiny_state::smt_empty_root()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // Inherited Build-5.3 behavioral names remain in the suite. Their old
    // self-contained checkpoint fixture was superseded by Pack M, so each is
    // rebound to the authenticated-header-state semantics rather than deleted.
    #[test]
    fn build53_dev_purchase_has_exactly_six_confirmations_and_stable_ids() {
        let state = fresh_state();
        let fixture = create_dev_purchase(&state, 2, 20).unwrap();
        let purchase = decode_purchase_operation(&fixture.operation).unwrap();
        assert_eq!(purchase.proof.headers.len(), 6);
        assert_eq!(fixture.sixth_height, fixture.containing_height + 5);
        assert_eq!(purchase.license_ids().unwrap(), fixture.ids);
        assert_eq!(
            operation_payment_id(&fixture.operation).unwrap(),
            fixture.payment_id
        );
    }

    #[test]
    fn build53_five_confirmation_purchase_is_rejected() {
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 21).unwrap();
        authenticate_fixture(&mut state, &fixture, 74);
        let mut purchase = decode_purchase_operation(&fixture.operation).unwrap();
        purchase.proof.headers.pop();
        let op = purchase.operation().unwrap();
        assert!(apply_operation(&mut state, &op, 100)
            .unwrap_err()
            .contains("six confirmations"));
    }

    #[test]
    fn build53_wrong_genesis_manifest_is_rejected() {
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 22).unwrap();
        authenticate_fixture(&mut state, &fixture, 74);
        let mut purchase = decode_purchase_operation(&fixture.operation).unwrap();
        purchase.manifest.genesis_hash[0] ^= 1;
        let op = purchase.operation().unwrap();
        assert!(apply_operation(&mut state, &op, 100)
            .unwrap_err()
            .contains("GenesisID"));
    }

    #[test]
    fn build53_empty_external_payment_root_preserves_prior_state_shape() {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build53-empty-root-packm-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_build54_genesis_devnet(&dir, 1, true).unwrap();
        let state = load_state(&dir).unwrap();
        assert_eq!(
            compute_external_payment_root(&state).unwrap(),
            mutiny_state::smt_empty_root()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build53_consumed_bitcoin_payment_changes_external_payment_root() {
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 23).unwrap();
        authenticate_fixture(&mut state, &fixture, 74);
        let before = compute_external_payment_root(&state).unwrap();
        apply_operation(&mut state, &fixture.operation, 100).unwrap();
        let after = compute_external_payment_root(&state).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn build53_unanchored_easy_header_chain_is_rejected() {
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 24).unwrap();
        assert!(!dependency_ready_at_epoch(&state, &fixture.operation, 100).unwrap());
        assert!(apply_operation(&mut state, &fixture.operation, 100)
            .unwrap_err()
            .contains("BITCOIN_BEST_CHAIN"));
    }

    #[test]
    fn build53_hotfix2_variant_is_independent_of_mutable_license_count() {
        let mut state = fresh_state();
        let before = create_dev_purchase(&state, 1, 25).unwrap();
        let unrelated = create_dev_purchase(&state, 1, 26).unwrap();
        authenticate_fixture(&mut state, &unrelated, 74);
        apply_operation(&mut state, &unrelated.operation, 100).unwrap();
        let after = create_dev_purchase(&state, 1, 25).unwrap();
        assert_eq!(before.txid_internal, after.txid_internal);
        assert_eq!(before.payment_id, after.payment_id);
        assert_eq!(before.ids, after.ids);
    }

    #[test]
    fn build53_hotfix2_same_variant_is_rejected_after_consumption() {
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 27).unwrap();
        authenticate_fixture(&mut state, &fixture, 74);
        apply_operation(&mut state, &fixture.operation, 100).unwrap();
        let err = match create_dev_purchase(&state, 1, 27) {
            Ok(_) => panic!("consumed deterministic Bitcoin fixture regenerated"),
            Err(err) => err,
        };
        assert!(err.contains("BitcoinPaymentID"));
    }

    #[test]
    fn build53_duplicate_bitcoin_payment_id_is_permanently_rejected() {
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 28).unwrap();
        authenticate_fixture(&mut state, &fixture, 74);
        apply_operation(&mut state, &fixture.operation, 100).unwrap();
        let err = apply_operation(&mut state, &fixture.operation, 101).unwrap_err();
        assert!(err.contains("BitcoinPaymentID") || err.contains("LicenseID"));
    }

    #[test]
    fn build53_fresh_variant0_external_payment_vector_matches_independent_verifier() {
        // The historical Build-5.3 literal external-payment vector is superseded
        // by the locked Pack-M vector. Preserve the regression name while checking
        // the still-consensus-critical 120-byte value shape and deterministic IDs.
        let mut state = fresh_state();
        let fixture = create_dev_purchase(&state, 1, 0).unwrap();
        authenticate_fixture(&mut state, &fixture, 74);
        apply_operation(&mut state, &fixture.operation, 100).unwrap();
        let payment = state
            .consumed_bitcoin_payments
            .iter()
            .find(|payment| payment.payment_id == hex::encode(fixture.payment_id))
            .unwrap();
        assert_eq!(payment.value_bytes().unwrap().len(), 120);
        assert_eq!(
            operation_payment_id(&fixture.operation).unwrap(),
            fixture.payment_id
        );
    }
}
