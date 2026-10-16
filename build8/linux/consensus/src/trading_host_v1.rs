//! Host dispatch for the native trading rules. These are ALWAYS compiled: no Cargo feature
//! selects them, so every validator of one NetworkID/GenesisID applies the same rules.
//! Trading PARAMETERS stay candidate pending the pre-Genesis lock packet (MAINNET_ACTIVATION
//! is still false); only the build-flag dependence of validity was removed.
//! No wire tag, unit conversion, production activation or parallel ledger.
use crate::{Error, Result, anchors::FinalizedAnchor, execution::State};
use minicbor::Decoder;

const NAMESPACE: &[u8] = b"MUTINY-NATIVE-TRADE-CANDIDATE-V1";

/// Reserve the namespace even when the enclosing array is indefinite or has
/// the wrong size. The strict typed decoder must reject those encodings.
pub(crate) fn reserved(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    if d.array().is_err() {
        return false;
    }
    let Ok(parts) = d.bytes_iter() else {
        return false;
    };
    let mut matched = 0usize;
    for part in parts {
        let Ok(part) = part else {
            return matched == NAMESPACE.len();
        };
        let Some(end) = matched.checked_add(part.len()) else {
            return false;
        };
        if end > NAMESPACE.len() || NAMESPACE[matched..end] != *part {
            return false;
        }
        matched = end;
    }
    matched == NAMESPACE.len()
}

pub(crate) fn operation(raw: &[u8]) -> Result<bool> {
    if !reserved(raw) {
        return Ok(false);
    }
    crate::trading_v1::NativeOperation::decode(raw).map_err(|_| Error::WrongOperation)?;
    Ok(true)
}

/// Typed structural validation for serialization; canonical callers additionally
/// supply their independently authenticated context and committed height.
pub(crate) fn records(state: &State, anchor: Option<&FinalizedAnchor>) -> Result<()> {
    if !state.protocol_records.values().any(|raw| reserved(raw)) {
        // The experimental Book permits detached historical assignments only
        // when the FULL State carries their typed transfer record. Even an
        // otherwise empty protocol map cannot hide an orphaned detachment.
        for license in state.licenses_v2.candidate_license_records() {
            if state
                .protocol_records
                .contains_key(&crate::trading_v1::record_key(4, license.id))
                || (license.active_worker.is_none() && license.assignment_sequence != 0)
            {
                return Err(Error::WrongAnchor);
            }
        }
        return Ok(());
    }
    {
        use crate::trading_v1::{Context, NativeRecord, record_key, validate_records};
        let mut context = anchor.map(|a| Context {
            network: a.network,
            genesis: a.genesis,
            fingerprint: a.fingerprint,
        });
        for (key, raw) in &state.protocol_records {
            if !reserved(raw) {
                continue;
            }
            let (id, record) = NativeRecord::decode(raw).map_err(|_| Error::Codec)?;
            let (tag, record_context, height) = match &record {
                NativeRecord::License {
                    context,
                    inclusion_height,
                    ..
                } => (4, Some(context), Some(*inclusion_height)),
                NativeRecord::Lock(lock) => (0, Some(&lock.context), Some(lock.created_height)),
                NativeRecord::Consumed { context, .. } => (1, Some(context), None),
                NativeRecord::Applied { height, .. } => (2, None, Some(*height)),
                NativeRecord::Treasury { context, .. } => (3, Some(context), None),
                NativeRecord::TreasuryGeneration { context, .. } => (5, Some(context), None),
                NativeRecord::TreasuryAddress { context, .. } => (6, Some(context), None),
            };
            if record_key(tag, id) != *key {
                return Err(Error::WrongAnchor);
            }
            if let Some(found) = record_context {
                if context.as_ref().is_some_and(|expected| expected != found) {
                    return Err(Error::WrongAnchor);
                }
                context = Some(found.clone());
            }
            if anchor.is_some_and(|a| height.is_some_and(|h| h > a.height)) {
                return Err(Error::WrongAnchor);
            }
        }
        // Applied receipts have no embedded context. They still require exact
        // typed keys/codecs; their authority is the canonical replay that created
        // them. No standalone receipt is used as a proof of finality.
        let context = context.unwrap_or(Context {
            network: crate::NETWORK_ID,
            genesis: [0; 32],
            fingerprint: [0; 32],
        });
        validate_records(state, &context).map_err(|_| Error::WrongAnchor)
    }
}

/// The trading phase of a block. `history` is the block's authenticated History: its anchors are
/// the canonical block hashes of the heights the operation envelopes reference (design 1.a.3);
/// without one, only parent references can be included (fail closed).
pub(crate) fn execute(
    parent_state: &State,
    tentative: State,
    parent: &FinalizedAnchor,
    history: &crate::evidence_history_v2::History,
    operations: &[Vec<u8>],
) -> crate::execution::Result<(State, u64)> {
    records(parent_state, Some(parent))?;
    if operations.is_empty() {
        return Ok((tentative, 0));
    }
    {
        let prepared = crate::trading_v1::prepare_candidate_phase(
            parent_state,
            &tentative,
            parent,
            parent_state.root()?,
            history,
            operations,
            &crate::trading_v1::CandidatePolicy::native_denomination_locked(),
        )
        .map_err(|_| crate::execution::ExecutionError::UnsupportedOperation)?;
        let fees = prepared.fee_atoms();
        Ok((prepared.into_state(), fees))
    }
}

/// Assembler fee preview (amendment AM-3): the sum of the DECLARED fees of the trading items,
/// decoded only. Nothing executes on the parent state here, so a preview can never reject a valid
/// sale whose preconditions are evaluated after this block's epoch events; the complete trial
/// execution validates every item and the body fees (`fees == trade fees + transaction fees`).
pub(crate) fn preview_fees(operations: &[Vec<u8>]) -> crate::execution::Result<u64> {
    let mut fees = 0u64;
    for raw in operations {
        if operation(raw)? {
            let fee = crate::trading_v1::declared_fee(raw)
                .map_err(|_| crate::execution::ExecutionError::UnsupportedOperation)?;
            fees = fees
                .checked_add(fee)
                .ok_or(crate::execution::ExecutionError::UnsupportedOperation)?;
        }
    }
    Ok(fees)
}

#[cfg(test)]
#[path = "trading_host_v1_tests.rs"]
mod tests;
