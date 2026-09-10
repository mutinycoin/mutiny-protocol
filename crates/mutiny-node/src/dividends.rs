use super::*;
use mutiny_protocol::{
    apply_dividend_claim, calculate_dividend_award, DividendClaimV1, DIVIDEND_AWARD_INTERVAL,
    DIVIDEND_CLAIM_WINDOW, OP_DIVIDEND_CLAIM,
};
use mutiny_state::{LicenseDividendAccountV1, TreasuryStateV1, LICENSE_STATUS_REVOKED};
use mutiny_transaction::WITNESS_PROTOCOL_AUTH;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct DividendAccountState {
    pub license_id: String,
    pub award_epoch: u64,
    pub claim_deadline_epoch: u64,
    pub claimable_strikes: u64,
}

impl DividendAccountState {
    pub(super) fn account(&self) -> Result<LicenseDividendAccountV1, String> {
        Ok(LicenseDividendAccountV1 {
            license_id: LicenseId(decode32(&self.license_id)?),
            award_epoch: self.award_epoch,
            claim_deadline_epoch: self.claim_deadline_epoch,
            claimable_strikes: self.claimable_strikes,
        })
    }

    fn update_from(&mut self, account: &LicenseDividendAccountV1) {
        self.award_epoch = account.award_epoch;
        self.claim_deadline_epoch = account.claim_deadline_epoch;
        self.claimable_strikes = account.claimable_strikes;
    }
}

pub(super) fn treasury_total(utxos: &[UtxoState]) -> Result<u64, String> {
    utxos
        .iter()
        .filter(|u| matches!(u.output_type, OUTPUT_TREASURY | OUTPUT_LICENSE_PAYMENT))
        .try_fold(0u64, |acc, u| {
            acc.checked_add(u.amount_strikes)
                .ok_or_else(|| "Treasury overflow".to_string())
        })
}

pub(super) fn treasury_state(
    state: &DevnetState,
    utxos: &[UtxoState],
) -> Result<TreasuryStateV1, String> {
    let total = treasury_total(utxos)?;
    let available = total
        .checked_sub(state.treasury_reserved_dividend_strikes)
        .ok_or("Treasury reserved dividends exceed Treasury UTXO backing")?;
    Ok(TreasuryStateV1 {
        available_strikes: available,
        reserved_dividend_strikes: state.treasury_reserved_dividend_strikes,
    })
}

/// Apply deterministic epoch-boundary dividend transitions.
///
/// Ordering is consensus-significant in Build 5.2:
/// 1. expired awards return to Treasury availability;
/// 2. if this is an exact 2^17 award epoch, 50% of then-available Treasury is reserved;
/// 3. the reserve is split equally across Mining Licenses eligible at this epoch.
pub(super) fn process_epoch(
    state: &mut DevnetState,
    epoch: u64,
) -> Result<(u64, usize, u64), String> {
    let mut returned = 0u64;
    let mut retained = Vec::with_capacity(state.dividend_accounts.len());
    for account in state.dividend_accounts.drain(..) {
        if epoch >= account.claim_deadline_epoch {
            returned = returned
                .checked_add(account.claimable_strikes)
                .ok_or("expired dividend return overflow")?;
        } else {
            retained.push(account);
        }
    }
    state.dividend_accounts = retained;
    if returned > 0 {
        state.treasury_reserved_dividend_strikes = state
            .treasury_reserved_dividend_strikes
            .checked_sub(returned)
            .ok_or("Treasury reserved-dividend accounting underflow during expiry")?;
    }

    // Local queue hygiene: a claim that reached its deadline is no longer consensus-valid.
    // Remove both halves of its local transaction/op bundle so it cannot linger forever.
    let mut stale_payment_txids = HashSet::new();
    let active_accounts = state.dividend_accounts.clone();
    state.pending_protocol_operations.retain(|pending| {
        let Ok(op) = pending.operation() else {
            return true;
        };
        if op.op_type != OP_DIVIDEND_CLAIM {
            return true;
        }
        let Ok(claim) = decode_claim_operation(&op) else {
            return true;
        };
        let license_hex = hex::encode(claim.license_id.0);
        let valid = active_accounts.iter().any(|a| {
            a.license_id == license_hex
                && epoch >= a.award_epoch
                && epoch < a.claim_deadline_epoch
                && claim.amount_strikes > 0
                && claim.amount_strikes <= a.claimable_strikes
        });
        if !valid && !pending.required_txid.is_empty() {
            stale_payment_txids.insert(pending.required_txid.clone());
        }
        valid
    });
    if !stale_payment_txids.is_empty() {
        state
            .mempool
            .retain(|tx| !stale_payment_txids.contains(&tx.txid));
    }

    if epoch == 0 || epoch % DIVIDEND_AWARD_INTERVAL != 0 {
        return Ok((returned, 0, 0));
    }
    if state
        .dividend_accounts
        .iter()
        .any(|a| a.award_epoch == epoch)
    {
        return Err("duplicate dividend award epoch transition".into());
    }

    let eligible = state
        .licenses
        .iter()
        .filter(|license| license.is_eligible(epoch))
        .map(|license| license.license_id.clone())
        .collect::<Vec<_>>();
    let treasury = treasury_state(state, &state.utxos)?;
    let calc = calculate_dividend_award(treasury.available_strikes, eligible.len() as u64)
        .map_err(|e| e.to_string())?;
    if calc.total_reserved_strikes == 0 {
        return Ok((returned, eligible.len(), 0));
    }

    let deadline = epoch
        .checked_add(DIVIDEND_CLAIM_WINDOW)
        .ok_or("dividend claim deadline overflow")?;
    state.treasury_reserved_dividend_strikes = state
        .treasury_reserved_dividend_strikes
        .checked_add(calc.total_reserved_strikes)
        .ok_or("Treasury dividend reserve overflow")?;
    for license_id in eligible {
        state.dividend_accounts.push(DividendAccountState {
            license_id,
            award_epoch: epoch,
            claim_deadline_epoch: deadline,
            claimable_strikes: calc.per_license_strikes,
        });
    }
    state
        .dividend_accounts
        .sort_by(|a, b| a.license_id.cmp(&b.license_id));
    Ok((
        returned,
        state
            .dividend_accounts
            .iter()
            .filter(|a| a.award_epoch == epoch)
            .count(),
        calc.total_reserved_strikes,
    ))
}

pub(super) fn decode_claim_operation(op: &ProtocolOperationV1) -> Result<DividendClaimV1, String> {
    if op.op_type != OP_DIVIDEND_CLAIM || op.op_version != 1 {
        return Err("operation is not a V1 dividend claim".into());
    }
    if op.payload.len() != 172 {
        return Err("V1 dividend claim payload must be exactly 172 bytes".into());
    }
    Ok(DividendClaimV1 {
        license_id: LicenseId(op.payload[0..32].try_into().unwrap()),
        expected_owner_sequence: u32::from_be_bytes(op.payload[32..36].try_into().unwrap()),
        amount_strikes: u64::from_be_bytes(op.payload[36..44].try_into().unwrap()),
        destination_address_id: AddressId(op.payload[44..76].try_into().unwrap()),
        payment_txid: TxId(op.payload[76..108].try_into().unwrap()),
        owner_signature: op.payload[108..172].try_into().unwrap(),
    })
}

pub(super) fn dependency_ready(
    state: &DevnetState,
    op: &ProtocolOperationV1,
) -> Result<bool, String> {
    let claim = decode_claim_operation(op)?;
    let Some(license) = state
        .licenses
        .iter()
        .find(|l| l.license_id == hex::encode(claim.license_id.0))
    else {
        return Err("dividend claim references unknown LicenseID".into());
    };
    if license.status == LICENSE_STATUS_REVOKED {
        return Err("dividend claim references a revoked Mining License".into());
    }
    if claim.expected_owner_sequence < license.owner_key_sequence {
        return Err("stale pending dividend claim owner sequence".into());
    }
    if claim.expected_owner_sequence > license.owner_key_sequence {
        return Ok(false);
    }
    let Some(account) = state
        .dividend_accounts
        .iter()
        .find(|a| a.license_id == license.license_id)
    else {
        return Ok(false);
    };
    let epoch = next_mineable_epoch(state);
    Ok(epoch >= account.award_epoch
        && epoch < account.claim_deadline_epoch
        && claim.amount_strikes > 0
        && claim.amount_strikes <= account.claimable_strikes)
}

pub(super) fn claim_operation_for_tx<'a>(
    operations: &'a [ProtocolOperationV1],
    txid: &TxId,
) -> Result<Option<&'a ProtocolOperationV1>, String> {
    let mut found = None;
    for op in operations
        .iter()
        .filter(|op| op.op_type == OP_DIVIDEND_CLAIM)
    {
        let claim = decode_claim_operation(op)?;
        if claim.payment_txid == *txid {
            if found.is_some() {
                return Err("more than one dividend claim references the same payment TXID".into());
            }
            found = Some(op);
        }
    }
    Ok(found)
}

pub(super) fn validate_and_apply_payment(
    state: &DevnetState,
    working_utxos: &mut Vec<UtxoState>,
    tx: &TransactionV1,
    op: &ProtocolOperationV1,
    epoch: u64,
    height: u64,
) -> Result<(), String> {
    let claim = decode_claim_operation(op)?;
    if tx.txid() != claim.payment_txid {
        return Err("dividend payment TXID does not match claim".into());
    }
    if tx.core.version != 1 || tx.core.network_id != state.network_id {
        return Err("dividend payment has wrong version/network".into());
    }
    if epoch < tx.core.valid_from_epoch
        || (tx.core.expiry_epoch != 0 && epoch > tx.core.expiry_epoch)
    {
        return Err("dividend payment is outside its epoch validity window".into());
    }
    if tx.core.inputs.is_empty()
        || tx.core.inputs.len() > 1024
        || tx.core.outputs.is_empty()
        || tx.core.outputs.len() > 2
    {
        return Err("dividend payment has invalid input/output count".into());
    }
    if tx.witnesses.len() != tx.core.inputs.len() {
        return Err("dividend payment witness count mismatch".into());
    }
    let opid = op.operation_id().0;
    let mut seen = HashSet::<(String, u16)>::new();
    let mut consumed = Vec::new();
    let mut input_sum = 0u64;
    for (i, input) in tx.core.inputs.iter().enumerate() {
        let (previous_txid, previous_output_index) = match input {
            TxInput::Outpoint {
                previous_txid,
                previous_output_index,
            } => (hex::encode(previous_txid), *previous_output_index),
            TxInput::Coinbase { .. } => {
                return Err("dividend payment cannot contain coinbase input".into())
            }
        };
        if !seen.insert((previous_txid.clone(), previous_output_index)) {
            return Err("dividend payment duplicates an input".into());
        }
        let utxo = working_utxos
            .iter()
            .find(|u| u.txid == previous_txid && u.output_index == previous_output_index)
            .ok_or("dividend payment references missing Treasury UTXO")?;
        if !matches!(utxo.output_type, OUTPUT_TREASURY | OUTPUT_LICENSE_PAYMENT) {
            return Err("dividend payment may spend only Treasury-controlled outputs".into());
        }
        if !utxo.spendable_at_height(height) {
            return Err("dividend payment spends immature Treasury coinbase output".into());
        }
        let witness = &tx.witnesses[i];
        if witness.witness_type != WITNESS_PROTOCOL_AUTH || witness.payload.as_slice() != &opid[..]
        {
            return Err("dividend Treasury input lacks matching PROTOCOL_AUTH witness".into());
        }
        input_sum = input_sum
            .checked_add(utxo.amount_strikes)
            .ok_or("dividend payment input overflow")?;
        consumed.push((previous_txid, previous_output_index));
    }

    let first = &tx.core.outputs[0];
    if first.output_type != OUTPUT_PUBKEY_HASH
        || first.amount_strikes != claim.amount_strikes
        || first.payload.as_slice() != &claim.destination_address_id.0[..]
    {
        return Err("dividend payment first output does not exactly pay the signed claim destination/amount".into());
    }
    if input_sum < claim.amount_strikes {
        return Err("dividend payment Treasury inputs are insufficient".into());
    }
    let change = input_sum - claim.amount_strikes;
    match (change, tx.core.outputs.len()) {
        (0, 1) => {}
        (0, _) => return Err("zero Treasury change output is non-canonical".into()),
        (_, 2) => {
            let output = &tx.core.outputs[1];
            if output.amount_strikes != change
                || output.output_type != OUTPUT_TREASURY
                || output.payload.as_slice() != &treasury_id_for_network(state.network_id)[..]
            {
                return Err("dividend payment Treasury change output is non-canonical".into());
            }
        }
        (_, _) => return Err("dividend payment is missing canonical Treasury change".into()),
    }
    let output_sum = tx.core.outputs.iter().try_fold(0u64, |acc, o| {
        acc.checked_add(o.amount_strikes)
            .ok_or("dividend payment output overflow")
    })?;
    if output_sum != input_sum {
        return Err(
            "protocol-authorized dividend payment must be fee-exempt and value preserving".into(),
        );
    }

    for (txid, index) in consumed {
        let pos = working_utxos
            .iter()
            .position(|u| u.txid == txid && u.output_index == index)
            .ok_or("Treasury UTXO disappeared during dividend payment")?;
        working_utxos.remove(pos);
    }
    add_outputs_as_utxos(working_utxos, tx, epoch, height, false)?;
    let _ = state; // explicit: all consensus authorization is bound by claim + Treasury UTXOs.
    Ok(())
}

pub(super) fn apply_operation(
    state: &mut DevnetState,
    txs: &[TransactionV1],
    op: &ProtocolOperationV1,
    block_epoch: u64,
) -> Result<(), String> {
    let claim = decode_claim_operation(op)?;
    if !txs.iter().skip(1).any(|tx| tx.txid() == claim.payment_txid) {
        return Err("dividend claim is missing its same-block Treasury payment transaction".into());
    }
    let license_index = state
        .licenses
        .iter()
        .position(|l| l.license_id == hex::encode(claim.license_id.0))
        .ok_or("dividend claim references unknown LicenseID")?;
    let account_index = state
        .dividend_accounts
        .iter()
        .position(|a| a.license_id == state.licenses[license_index].license_id)
        .ok_or("dividend claim has no active dividend account")?;
    let record = state.licenses[license_index].record()?;
    let mut account = state.dividend_accounts[account_index].account()?;
    let mut treasury = TreasuryStateV1 {
        available_strikes: 0,
        reserved_dividend_strikes: state.treasury_reserved_dividend_strikes,
    };
    apply_dividend_claim(&record, &mut account, &mut treasury, &claim, block_epoch)
        .map_err(|e| e.to_string())?;
    state.dividend_accounts[account_index].update_from(&account);
    state.treasury_reserved_dividend_strikes = treasury.reserved_dividend_strikes;
    Ok(())
}

pub(super) fn create_claim_bundle(
    state: &DevnetState,
    license_index: usize,
    amount_strikes: u64,
) -> Result<
    (
        PendingTxState,
        PendingProtocolOperationState,
        DividendClaimV1,
    ),
    String,
> {
    let sk = state
        .licenses
        .get(license_index)
        .and_then(dev_owner_signing_key_for_license)
        .ok_or("local Devnet wallet does not hold the current owner private key for this Mining License")?;
    create_claim_bundle_with_signer(state, license_index, amount_strikes, &sk)
}

pub(super) fn create_claim_bundle_with_signer(
    state: &DevnetState,
    license_index: usize,
    amount_strikes: u64,
    sk: &SigningKey,
) -> Result<
    (
        PendingTxState,
        PendingProtocolOperationState,
        DividendClaimV1,
    ),
    String,
> {
    if amount_strikes == 0 {
        return Err("dividend claim amount must be greater than zero".into());
    }
    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    if sk.verifying_key().to_bytes() != decode32(&license.owner_public_key)? {
        return Err(
            "provided signing key does not match the current on-chain owner authority".into(),
        );
    }
    if license.status == LICENSE_STATUS_REVOKED {
        return Err("revoked Mining License cannot claim dividends".into());
    }
    let account = state
        .dividend_accounts
        .iter()
        .find(|a| a.license_id == license.license_id)
        .ok_or("Mining License has no active dividend award")?;
    let candidate_epoch = next_mineable_epoch(state);
    if candidate_epoch < account.award_epoch || candidate_epoch >= account.claim_deadline_epoch {
        return Err("dividend award is outside its claim window".into());
    }
    let mut already_queued = 0u64;
    for pending in &state.pending_protocol_operations {
        let Ok(op) = pending.operation() else {
            continue;
        };
        if op.op_type != OP_DIVIDEND_CLAIM {
            continue;
        }
        let queued = decode_claim_operation(&op)?;
        if queued.license_id.0 == decode32(&license.license_id)? {
            already_queued = already_queued
                .checked_add(queued.amount_strikes)
                .ok_or("queued dividend claim overflow")?;
        }
    }
    let unqueued_claimable = account
        .claimable_strikes
        .checked_sub(already_queued)
        .ok_or("queued dividend claims exceed account balance")?;
    if amount_strikes > unqueued_claimable {
        return Err("dividend claim exceeds claimable balance after already-queued claims".into());
    }
    let reserved_inputs = mempool_reserved_inputs(state);
    let candidate_height = state.height + 1;
    let mut candidates = state
        .utxos
        .iter()
        .filter(|u| {
            matches!(u.output_type, OUTPUT_TREASURY | OUTPUT_LICENSE_PAYMENT)
                && u.spendable_at_height(candidate_height)
                && !reserved_inputs.contains(&(u.txid.clone(), u.output_index))
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by_key(|u| (u.creation_height, u.txid.clone(), u.output_index));
    let mut selected = Vec::new();
    let mut total = 0u64;
    for utxo in candidates {
        total = total
            .checked_add(utxo.amount_strikes)
            .ok_or("Treasury input selection overflow")?;
        selected.push(utxo);
        if total >= amount_strikes {
            break;
        }
    }
    if total < amount_strikes {
        return Err(
            "Treasury does not yet have enough spendable UTXO backing for this claim".into(),
        );
    }

    let destination = AddressId(decode32(&license.payment_address_id)?);
    let inputs = selected
        .iter()
        .map(|u| {
            Ok(TxInput::Outpoint {
                previous_txid: decode32(&u.txid)?,
                previous_output_index: u.output_index,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut outputs = vec![TxOutput {
        amount_strikes,
        output_type: OUTPUT_PUBKEY_HASH,
        payload: destination.0.to_vec(),
    }];
    let change = total - amount_strikes;
    if change > 0 {
        outputs.push(TxOutput {
            amount_strikes: change,
            output_type: OUTPUT_TREASURY,
            payload: treasury_id_for_network(state.network_id).to_vec(),
        });
    }
    let core = TransactionCoreV1 {
        version: 1,
        network_id: state.network_id,
        valid_from_epoch: candidate_epoch,
        expiry_epoch: account.claim_deadline_epoch.saturating_sub(1),
        inputs,
        outputs,
    };
    let payment_txid = core.txid();
    let mut claim = DividendClaimV1 {
        license_id: LicenseId(decode32(&license.license_id)?),
        expected_owner_sequence: license.owner_key_sequence,
        amount_strikes,
        destination_address_id: destination,
        payment_txid,
        owner_signature: [0u8; 64],
    };
    claim.owner_signature = sk.sign(&claim.signing_digest().0).to_bytes();
    let operation = claim.operation();
    let opid = operation.operation_id().0;
    let tx = TransactionV1 {
        core,
        witnesses: selected
            .iter()
            .map(|_| WitnessV1::protocol_auth(opid))
            .collect(),
    };
    debug_assert_eq!(tx.txid(), payment_txid);
    let pending = PendingTxState {
        txid: tx.txid().to_hex(),
        wtxid: tx.wtxid().to_hex(),
        valid_from_epoch: tx.core.valid_from_epoch,
        expiry_epoch: tx.core.expiry_epoch,
        inputs: selected
            .iter()
            .map(|u| StoredTxInput {
                previous_txid: u.txid.clone(),
                previous_output_index: u.output_index,
            })
            .collect(),
        outputs: tx
            .core
            .outputs
            .iter()
            .map(|o| StoredTxOutput {
                amount_strikes: o.amount_strikes,
                output_type: o.output_type,
                payload: hex::encode(&o.payload),
            })
            .collect(),
        witnesses: tx
            .witnesses
            .iter()
            .map(|w| StoredWitness {
                witness_type: w.witness_type,
                payload: hex::encode(&w.payload),
            })
            .collect(),
        fee_strikes: 0,
        base_fee_strikes: 0,
        from_license: u8::try_from(license_index).unwrap_or(0),
        to_license: u8::try_from(license_index).unwrap_or(0),
        amount_strikes,
    };
    let pending_op = PendingProtocolOperationState {
        operation: hex::encode(operation.encode()),
        required_txid: pending.txid.clone(),
    };

    let mut working = state.utxos.clone();
    validate_and_apply_payment(
        state,
        &mut working,
        &tx,
        &operation,
        candidate_epoch,
        candidate_height,
    )?;
    Ok((pending, pending_op, claim))
}

pub(super) fn check_state(state: &DevnetState) -> Result<(), String> {
    let total = treasury_total(&state.utxos)?;
    if state.treasury_reserved_dividend_strikes > total {
        return Err("Treasury reserved dividends exceed Treasury UTXO backing".into());
    }
    let mut seen = HashSet::new();
    let mut claimable_sum = 0u64;
    for account in &state.dividend_accounts {
        decode32(&account.license_id)?;
        if !seen.insert(account.license_id.clone()) {
            return Err("duplicate active dividend account for Mining License".into());
        }
        if account.award_epoch == 0 || account.award_epoch % DIVIDEND_AWARD_INTERVAL != 0 {
            return Err("dividend account award epoch is not a canonical 2^17 boundary".into());
        }
        if account.claim_deadline_epoch
            != account
                .award_epoch
                .checked_add(DIVIDEND_CLAIM_WINDOW)
                .ok_or("dividend deadline overflow")?
        {
            return Err("dividend account claim deadline mismatch".into());
        }
        if !state
            .licenses
            .iter()
            .any(|l| l.license_id == account.license_id)
        {
            return Err("dividend account references unknown Mining License".into());
        }
        claimable_sum = claimable_sum
            .checked_add(account.claimable_strikes)
            .ok_or("dividend claimable sum overflow")?;
    }
    if claimable_sum != state.treasury_reserved_dividend_strikes {
        return Err(format!(
            "Treasury dividend reserve mismatch: accounts={} Strikes reserved={} Strikes",
            claimable_sum, state.treasury_reserved_dividend_strikes
        ));
    }
    Ok(())
}

pub(super) fn print_dividends(
    state: &DevnetState,
    license_index: Option<usize>,
) -> Result<(), String> {
    let treasury = treasury_state(state, &state.utxos)?;
    println!("Dividend cadence: every {} epochs", DIVIDEND_AWARD_INTERVAL);
    println!("Claim window:     {} epochs", DIVIDEND_CLAIM_WINDOW);
    println!(
        "Treasury available: {} MUT",
        format_mut(treasury.available_strikes)
    );
    println!(
        "Treasury reserved:  {} MUT",
        format_mut(treasury.reserved_dividend_strikes)
    );
    println!(
        "Active dividend accounts: {}",
        state.dividend_accounts.len()
    );
    for (i, license) in state.licenses.iter().enumerate() {
        if license_index.is_some_and(|wanted| wanted != i) {
            continue;
        }
        if let Some(account) = state
            .dividend_accounts
            .iter()
            .find(|a| a.license_id == license.license_id)
        {
            println!(
                "license {:03}  {}  award={} deadline={} claimable={} MUT",
                i + 1,
                &license.license_id[..16],
                account.award_epoch,
                account.claim_deadline_epoch,
                format_mut(account.claimable_strikes),
            );
        } else if license_index.is_some() {
            println!(
                "license {:03}  {}  no active dividend award",
                i + 1,
                &license.license_id[..16]
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn fresh_state() -> DevnetState {
        // Rust tests run in parallel by default. A PID-only path lets concurrent
        // dividend tests delete each other's fixture directory on Windows.
        // Include a process-local monotonic id so every test owns its directory.
        let temp_id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build52-dividend-{}-{temp_id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let state = load_state(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
        state
    }

    fn fund_treasury(state: &mut DevnetState, amount: u64, byte: u8) {
        state.utxos.push(UtxoState {
            txid: hex::encode([byte; 32]),
            output_index: 0,
            amount_strikes: amount,
            output_type: OUTPUT_TREASURY,
            payload: hex::encode(treasury_id()),
            creation_epoch: 1,
            creation_height: 1,
            coinbase: false,
        });
        state.total_issued_strikes = state.total_issued_strikes.checked_add(amount).unwrap();
    }

    #[test]
    fn build52_award_reserves_exactly_half_available_and_splits_equally() {
        let mut state = fresh_state();
        fund_treasury(&mut state, 1_000_001, 0x51);
        let (_, awarded, reserved) = process_epoch(&mut state, DIVIDEND_AWARD_INTERVAL).unwrap();
        assert_eq!(awarded, 12);
        assert_eq!(reserved, 499_992);
        assert_eq!(state.treasury_reserved_dividend_strikes, 499_992);
        assert_eq!(state.dividend_accounts.len(), 12);
        assert!(state
            .dividend_accounts
            .iter()
            .all(|a| a.claimable_strikes == 41_666));
        let treasury = treasury_state(&state, &state.utxos).unwrap();
        assert_eq!(treasury.available_strikes, 500_009);
    }

    #[test]
    fn build52_suspended_and_revoked_licenses_are_not_award_eligible() {
        let mut state = fresh_state();
        fund_treasury(&mut state, 1_000_000, 0x52);
        state.licenses[0].suspended_until_epoch = DIVIDEND_AWARD_INTERVAL + 1;
        state.licenses[1].status = LICENSE_STATUS_REVOKED;
        let (_, awarded, reserved) = process_epoch(&mut state, DIVIDEND_AWARD_INTERVAL).unwrap();
        assert_eq!(awarded, 10);
        assert_eq!(reserved, 500_000);
        assert!(state
            .dividend_accounts
            .iter()
            .all(|a| a.license_id != state.licenses[0].license_id));
        assert!(state
            .dividend_accounts
            .iter()
            .all(|a| a.license_id != state.licenses[1].license_id));
    }

    #[test]
    fn build52_expiry_returns_unclaimed_reserve_to_available_treasury() {
        let mut state = fresh_state();
        fund_treasury(&mut state, 1_000_000, 0x53);
        process_epoch(&mut state, DIVIDEND_AWARD_INTERVAL).unwrap();
        let reserved = state.treasury_reserved_dividend_strikes;
        let deadline = DIVIDEND_AWARD_INTERVAL + DIVIDEND_CLAIM_WINDOW;
        let (returned, _, _) = process_epoch(&mut state, deadline).unwrap();
        assert_eq!(returned, reserved);
        assert_eq!(state.treasury_reserved_dividend_strikes, 0);
        assert!(state.dividend_accounts.is_empty());
        assert_eq!(
            treasury_state(&state, &state.utxos)
                .unwrap()
                .available_strikes,
            1_000_000
        );
    }

    #[test]
    fn build52_claim_bundle_spends_treasury_with_protocol_auth_and_reduces_reserve() {
        let mut state = fresh_state();
        fund_treasury(&mut state, 12 * STRIKES_PER_MUT, 0x54);
        process_epoch(&mut state, DIVIDEND_AWARD_INTERVAL).unwrap();
        state.tip_epoch = DIVIDEND_AWARD_INTERVAL;
        state.height = 1;
        let amount = state.dividend_accounts[0].claimable_strikes / 2;
        let (pending, pending_op, claim) = create_claim_bundle(&state, 0, amount).unwrap();
        assert_eq!(pending.fee_strikes, 0);
        assert_eq!(pending.base_fee_strikes, 0);
        assert!(pending
            .witnesses
            .iter()
            .all(|w| w.witness_type == WITNESS_PROTOCOL_AUTH));
        assert_eq!(pending.txid, claim.payment_txid.to_hex());
        let tx = pending.to_transaction().unwrap();
        let op = pending_op.operation().unwrap();
        let mut working = state.utxos.clone();
        validate_and_apply_payment(
            &state,
            &mut working,
            &tx,
            &op,
            DIVIDEND_AWARD_INTERVAL + 1,
            1,
        )
        .unwrap();
        let before = state.treasury_reserved_dividend_strikes;
        apply_operation(
            &mut state,
            &[
                TransactionV1 {
                    core: TransactionCoreV1 {
                        version: 1,
                        network_id: DEVNET_NETWORK_ID,
                        valid_from_epoch: DIVIDEND_AWARD_INTERVAL + 1,
                        expiry_epoch: 0,
                        inputs: vec![TxInput::Coinbase {
                            commitment: CoinbaseCommitmentV1 {
                                block_epoch: DIVIDEND_AWARD_INTERVAL + 1,
                                block_height: 1,
                                parent_block_hash: [0; 32],
                                protocol_operations_root: [0; 32],
                            },
                        }],
                        outputs: vec![],
                    },
                    witnesses: vec![],
                },
                tx,
            ],
            &op,
            DIVIDEND_AWARD_INTERVAL + 1,
        )
        .unwrap();
        assert_eq!(state.treasury_reserved_dividend_strikes, before - amount);
        let license_id = state.licenses[0].license_id.clone();
        let account = state
            .dividend_accounts
            .iter()
            .find(|a| a.license_id == license_id)
            .unwrap();
        assert_eq!(account.claimable_strikes, (before / 12) - amount);
    }

    #[test]
    fn build52_award_occurs_only_on_exact_two_to_17_boundary() {
        let mut state = fresh_state();
        fund_treasury(&mut state, 1_000_000, 0x56);
        process_epoch(&mut state, DIVIDEND_AWARD_INTERVAL - 1).unwrap();
        assert!(state.dividend_accounts.is_empty());
        assert_eq!(state.treasury_reserved_dividend_strikes, 0);
        process_epoch(&mut state, DIVIDEND_AWARD_INTERVAL).unwrap();
        assert_eq!(state.dividend_accounts.len(), 12);
        assert_eq!(
            state.treasury_reserved_dividend_strikes,
            500_000 - (500_000 % 12)
        );
    }

    #[test]
    fn build52_queued_partial_claims_cannot_overdraw_account() {
        let mut state = fresh_state();
        fund_treasury(&mut state, 12 * STRIKES_PER_MUT, 0x57);
        process_epoch(&mut state, DIVIDEND_AWARD_INTERVAL).unwrap();
        state.tip_epoch = DIVIDEND_AWARD_INTERVAL;
        state.height = 1;
        let license_id = state.licenses[0].license_id.clone();
        let claimable = state
            .dividend_accounts
            .iter()
            .find(|a| a.license_id == license_id)
            .unwrap()
            .claimable_strikes;
        let first_amount = claimable / 2;
        let (tx, op, _) = create_claim_bundle(&state, 0, first_amount).unwrap();
        state.mempool.push(tx);
        state.pending_protocol_operations.push(op);
        let err = create_claim_bundle(&state, 0, claimable - first_amount + 1).unwrap_err();
        assert!(err.contains("already-queued"));
    }

    #[test]
    fn build52_award_survives_owner_transfer_and_current_owner_controls_claim() {
        let mut state = fresh_state();
        fund_treasury(&mut state, 12 * STRIKES_PER_MUT, 0x58);
        process_epoch(&mut state, DIVIDEND_AWARD_INTERVAL).unwrap();
        state.tip_epoch = DIVIDEND_AWARD_INTERVAL;
        state.height = 1;
        let new_key = SigningKey::from_bytes(&dev_seed(42));
        let new_public = new_key.verifying_key().to_bytes();
        state.licenses[0].owner_public_key = hex::encode(new_public);
        state.licenses[0].owner_key_sequence = 1;
        state.licenses[0].payment_address_id = hex::encode(address_id(&new_public).0);
        let license_id = state.licenses[0].license_id.clone();
        let amount = state
            .dividend_accounts
            .iter()
            .find(|a| a.license_id == license_id)
            .unwrap()
            .claimable_strikes;
        let (_, _, claim) = create_claim_bundle(&state, 0, amount).unwrap();
        assert_eq!(claim.expected_owner_sequence, 1);
        assert_eq!(claim.destination_address_id.0, address_id(&new_public).0);
    }

    #[test]
    fn build52_revoked_license_cannot_claim_existing_award() {
        let mut state = fresh_state();
        fund_treasury(&mut state, 12 * STRIKES_PER_MUT, 0x59);
        process_epoch(&mut state, DIVIDEND_AWARD_INTERVAL).unwrap();
        state.tip_epoch = DIVIDEND_AWARD_INTERVAL;
        state.height = 1;
        state.licenses[0].status = LICENSE_STATUS_REVOKED;
        let err = create_claim_bundle(&state, 0, 1).unwrap_err();
        assert!(err.contains("revoked"));
    }

    #[test]
    fn build52_dividend_account_changes_protocol_state_root() {
        let mut state = fresh_state();
        fund_treasury(&mut state, 1_000_000, 0x55);
        let before = compute_protocol_state_root(&state, &state.utxos, 0, 0).unwrap();
        process_epoch(&mut state, DIVIDEND_AWARD_INTERVAL).unwrap();
        let after = compute_protocol_state_root(&state, &state.utxos, 0, 0).unwrap();
        assert_ne!(before, after);
    }
}
