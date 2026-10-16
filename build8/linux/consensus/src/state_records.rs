//! Reconstruct typed execution state from canonical authenticated records. The
//! caller independently pins the expected StateRoot; this is not a trust source.
use crate::{
    Error, Hash, Result,
    blocks::state_root,
    domain_hash,
    execution::State,
    licenses::{ActiveWorker, BindWorker, LicenseRecord},
    transactions::{Coin, OutPoint, Output},
};
use minicbor::{Decoder, Encoder};
fn hash(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("hash"))
}
pub(crate) fn coin(raw: &[u8]) -> Option<(OutPoint, Coin)> {
    (|| -> std::result::Result<_, minicbor::decode::Error> {
        let mut d = Decoder::new(raw);
        if d.array()? != Some(7) || d.u8()? != 1 {
            return Err(minicbor::decode::Error::message("coin"));
        }
        let point = OutPoint {
            transaction: hash(&mut d)?,
            index: d.u32()?,
        };
        let coin = Coin {
            output: Output {
                owner: hash(&mut d)?,
                atoms: d.u64()?,
            },
            created_height: d.u64()?,
            coinbase: d.bool()?,
        };
        if d.position() != raw.len() {
            return Err(minicbor::decode::Error::message("trailing"));
        }
        Ok((point, coin))
    })()
    .ok()
}
pub(crate) fn coin_key(p: &OutPoint) -> Hash {
    let mut e = Encoder::new(Vec::new());
    e.array(2)
        .unwrap()
        .bytes(&p.transaction)
        .unwrap()
        .u32(p.index)
        .unwrap();
    domain_hash(b"MUTINY-BUILD8-UTXO-KEY-V1", &e.into_writer())
}
fn worker(raw: &[u8]) -> Option<ActiveWorker> {
    (|| -> std::result::Result<_, minicbor::decode::Error> {
        let mut d = Decoder::new(raw);
        if d.array()? != Some(3) || d.u8()? != 1 {
            return Err(minicbor::decode::Error::message("worker"));
        }
        let binding = BindWorker::decode(d.bytes()?)
            .map_err(|_| minicbor::decode::Error::message("binding"))?;
        let last_accepted_ticket = d.u64()?;
        if d.position() != raw.len() {
            return Err(minicbor::decode::Error::message("trailing"));
        }
        Ok(ActiveWorker {
            binding,
            last_accepted_ticket,
        })
    })()
    .ok()
}
/// Reserved record domains cannot be hidden in the opaque protocol-record map.
pub(crate) fn reserved(key: Hash, raw: &[u8]) -> bool {
    key == crate::recovery::continuity_meta_key()
        || crate::recovery_authority_v2::is_record(key, raw)
        || crate::recovery_history_v2::is_record(raw)
        || crate::admission_policy_v2::is_record(key, raw)
        || crate::admission::is_record(key, raw)
        || crate::membership::is_record(key, raw)
        || crate::bonds::is_record(key, raw)
        || crate::bonds_v2::is_record(raw)
        || crate::equivocation::is_record(key, raw)
        || crate::penalties_v2::is_record(raw)
        || crate::wallet_authority_v1::is_record(key, raw)
        || crate::dividend_state_v1::is_record(raw)
        || crate::license_book_v2::is_record(raw)
        || crate::continuity_keys_v2::is_record(raw)
        || crate::endorsement_dependencies_v1::is_record(raw)
        || crate::endorsement_revocation_v1::is_record(raw)
        || crate::node_key_history_v2::is_record(raw)
        || crate::retired_continuity_v2::is_record(raw)
        || crate::membership_v2::is_record(raw)
        || key == domain_hash(b"MUTINY-BUILD8-PARTICIPATION-STATE-KEY-V1", &[])
        || crate::recovery::is_member_record(key, raw)
        || crate::freshness::FreshnessRecord::decode(raw)
            .is_ok_and(|r| domain_hash(b"MUTINY-BUILD8-FRESHNESS-STATE-KEY-V1", &r.node) == key)
        || coin(raw).is_some_and(|(p, _)| coin_key(&p) == key)
        || LicenseRecord::decode(raw)
            .is_ok_and(|l| domain_hash(b"MUTINY-BUILD8-LICENSE-STATE-KEY-V1", &l.id) == key)
        || worker(raw).is_some_and(|w| {
            domain_hash(b"MUTINY-BUILD8-WORKER-STATE-KEY-V1", &w.binding.worker_id()) == key
        })
        || BindWorker::decode(raw)
            .is_ok_and(|b| domain_hash(b"MUTINY-BUILD8-PENDING-BIND-KEY-V1", &b.license) == key)
}
impl State {
    pub fn from_records(records: &[(Hash, Vec<u8>)], expected_root: Hash) -> Result<Self> {
        if state_root(records)? != expected_root {
            return Err(Error::WrongAnchor);
        }
        let mut state = Self::default();
        let mut continuity = std::collections::BTreeMap::new();
        let mut accounting = std::collections::BTreeMap::new();
        let mut admission = std::collections::BTreeMap::new();
        let mut membership = std::collections::BTreeMap::new();
        let mut bonds = std::collections::BTreeMap::new();
        let mut bonds_v2 = std::collections::BTreeMap::new();
        let mut penalties = std::collections::BTreeMap::new();
        let mut penalties_v2 = std::collections::BTreeMap::new();
        let mut wallets = std::collections::BTreeMap::new();
        let mut licenses_v2 = std::collections::BTreeMap::new();
        let mut continuity_keys_v2 = std::collections::BTreeMap::new();
        let mut endorsement_dependencies_v1 = std::collections::BTreeMap::new();
        let mut endorsement_revocations_v1 = std::collections::BTreeMap::new();
        let mut node_key_history_v2 = std::collections::BTreeMap::new();
        let mut retired_continuity_v2 = std::collections::BTreeMap::new();
        let mut membership_v2 = std::collections::BTreeMap::new();
        let mut recovery_history_v2 = std::collections::BTreeMap::new();
        let mut dividends = std::collections::BTreeMap::new();
        for (key, raw) in records {
            if crate::endorsement_revocation_v1::is_record(raw) {
                endorsement_revocations_v1.insert(*key, raw.clone());
            } else if crate::endorsement_dependencies_v1::is_record(raw) {
                endorsement_dependencies_v1.insert(*key, raw.clone());
            } else if crate::trading_host_v1::reserved(raw) {
                state.protocol_records.insert(*key, raw.clone());
                // State::records performs the strict typed/key check below.
                // Canonical restoration additionally verifies the known context.
            } else if crate::dividend_state_v1::is_record(raw) {
                dividends.insert(*key, raw.clone());
            } else if crate::recovery_authority_v2::is_record(*key, raw) {
                if *key != crate::recovery_authority_v2::key()
                    || state.recovery_authority_v2.is_some()
                {
                    return Err(Error::Duplicate);
                }
                state.recovery_authority_v2 =
                    Some(crate::recovery_authority_v2::Authority::decode(raw)?);
            } else if crate::recovery_history_v2::is_record(raw) {
                recovery_history_v2.insert(*key, raw.clone());
            } else if crate::admission_policy_v2::is_record(*key, raw) {
                if *key != crate::admission_policy_v2::key() || state.admission_policy_v2.is_some()
                {
                    return Err(Error::Duplicate);
                }
                state.admission_policy_v2 = Some(crate::admission_policy_v2::Record::decode(raw)?);
            } else if crate::node_key_history_v2::is_record(raw) {
                node_key_history_v2.insert(*key, raw.clone());
            } else if crate::retired_continuity_v2::is_record(raw) {
                retired_continuity_v2.insert(*key, raw.clone());
            } else if crate::penalties_v2::is_record(raw) {
                penalties_v2.insert(*key, raw.clone());
            } else if crate::bonds_v2::is_record(raw) {
                bonds_v2.insert(*key, raw.clone());
            } else if crate::membership_v2::is_record(raw) {
                membership_v2.insert(*key, raw.clone());
            } else if crate::continuity_keys_v2::is_record(raw) {
                continuity_keys_v2.insert(*key, raw.clone());
            } else if crate::license_book_v2::is_record(raw) {
                licenses_v2.insert(*key, raw.clone());
            } else if crate::wallet_authority_v1::is_record(*key, raw) {
                wallets.insert(*key, raw.clone());
            } else if crate::admission::is_record(*key, raw) {
                admission.insert(*key, raw.clone());
            } else if crate::membership::is_record(*key, raw) {
                membership.insert(*key, raw.clone());
            } else if crate::bonds::is_record(*key, raw) {
                bonds.insert(*key, raw.clone());
            } else if crate::equivocation::is_record(*key, raw) {
                penalties.insert(*key, raw.clone());
            } else if *key == crate::recovery::continuity_meta_key()
                || crate::recovery::is_member_record(*key, raw)
            {
                continuity.insert(*key, raw.clone());
            } else if *key == domain_hash(b"MUTINY-BUILD8-PARTICIPATION-STATE-KEY-V1", &[])
                || crate::freshness::FreshnessRecord::decode(raw).is_ok_and(|r| {
                    domain_hash(b"MUTINY-BUILD8-FRESHNESS-STATE-KEY-V1", &r.node) == *key
                })
            {
                accounting.insert(*key, raw.clone());
            } else if let Some((point, coin)) = coin(raw).filter(|(p, _)| coin_key(p) == *key) {
                if coin.output.atoms == 0 {
                    return Err(Error::InvalidCounter);
                }
                state.coins.insert(point, coin);
            } else if let Ok(l) = LicenseRecord::decode(raw)
                && domain_hash(b"MUTINY-BUILD8-LICENSE-STATE-KEY-V1", &l.id) == *key
            {
                state.licenses.licenses.insert(l.id, l);
            } else if let Some(w) = worker(raw)
                && domain_hash(b"MUTINY-BUILD8-WORKER-STATE-KEY-V1", &w.binding.worker_id()) == *key
            {
                state.licenses.workers.insert(w.binding.worker_id(), w);
            } else if let Ok(b) = BindWorker::decode(raw)
                && domain_hash(b"MUTINY-BUILD8-PENDING-BIND-KEY-V1", &b.license) == *key
            {
                state.licenses.pending.insert(b.license, b);
            } else {
                state.protocol_records.insert(*key, raw.clone());
            }
        }
        if !recovery_history_v2.is_empty() {
            state.recovery_history_v2 = crate::recovery_history_v2::Book::from_records(
                &recovery_history_v2,
                state
                    .recovery_authority_v2
                    .as_ref()
                    .ok_or(Error::RecoveryDisabled)?,
            )?;
        }
        state.dividends = crate::dividend_state_v1::DividendState::from_records(&dividends)?;
        // Same class rule on restore as on admission: from the committed Genesis parameters record
        // (already in `protocol_records`) and the book's own committed policy.
        state.admission = crate::admission::AdmissionBook::from_records(
            &admission,
            state
                .protocol_records
                .get(&crate::genesis_inputs::parameters_key())
                .map(Vec::as_slice),
        )?;
        state.continuity_keys_v2 =
            crate::continuity_keys_v2::Book::from_records(&continuity_keys_v2)?;
        state.node_key_history_v2 =
            crate::node_key_history_v2::Book::from_records(&node_key_history_v2)?;
        state.retired_continuity_v2 =
            crate::retired_continuity_v2::Book::from_records(&retired_continuity_v2)?;
        state.membership_v2 =
            crate::membership_v2::Book::from_records(&membership_v2, &state.continuity_keys_v2)?;
        state.wallets = crate::wallet_authority_v1::WalletBook::from_records(&wallets)?;
        state.licenses_v2 = crate::license_book_v2::Book::from_records(&licenses_v2)?;
        state.penalties = crate::equivocation::PenaltyBook::from_records(&penalties)?;
        state.penalties_v2 = crate::penalties_v2::Book::from_records(&penalties_v2)?;
        state.membership = crate::membership::MembershipBook::from_records(&membership)?;
        state.bonds = crate::bonds::BondBook::from_records(&bonds)?;
        state.bonds_v2 = crate::bonds_v2::Book::from_records(&bonds_v2)?;
        if !continuity.is_empty() || !accounting.is_empty() {
            state.continuity = Some(crate::recovery::ContinuityState::from_state_records(
                &continuity,
            )?);
            state.accounting =
                crate::continuity_execution::ContinuityAccounting::from_records(&accounting)?;
        }
        if !endorsement_dependencies_v1.is_empty() {
            state.endorsement_dependencies_v1 = crate::endorsement_dependencies_v1::Book::from_records(
                &endorsement_dependencies_v1, &state)?;
        }
        if !endorsement_revocations_v1.is_empty() {
            state.endorsement_revocations_v1 = crate::endorsement_revocation_v1::Book::from_records(
                &endorsement_revocations_v1, &state)?;
        }
        if state.root().map_err(|_| Error::WrongAnchor)? != expected_root {
            return Err(Error::WrongAnchor);
        }
        Ok(state)
    }
}
