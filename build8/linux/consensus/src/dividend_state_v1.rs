//! Canonical dividend State component (Stage C). Status: NATIVE logic.
//!
//! Groups the Treasury identity, License status book and dividend ledger so they enter the
//! StateRoot through typed records and can only be mutated through narrow, validated
//! transitions. A State without a Treasury identity carries no dividend records at all, so
//! pre-existing roots are unchanged.
//!
//! Record families (version 2): tag 60 Treasury identity, 61 License status, 62 ledger header,
//! 63 award. These are NATIVE candidate tags; no historical wire identifier is reused.
use crate::{
    Error, Hash, Result, domain_hash,
    dividends_v1::{Account, Award, Claim, DivError, Event, Ledger, LicenseView, Receipt},
    license_status_v1::StatusBook,
    transactions::{Coin, OutPoint},
    treasury_v1::Treasury,
};
use minicbor::{Decoder, Encoder};
use std::collections::{BTreeMap, BTreeSet};

const RECORD_VERSION: u8 = 2;
const TAG_HEADER: u8 = 62;
const TAG_AWARD: u8 = 63;
const MAX_AWARD_RECORD: usize = 8 * 1024 * 1024;

/// Reserve all four typed tags even for malformed bodies.
pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some()
        && d.u8().ok() == Some(RECORD_VERSION)
        && matches!(d.u8().ok(), Some(60..=63))
}

fn header_key() -> Hash {
    domain_hash(b"MUTINY-BUILD8-DIVIDEND-LEDGER-STATE-KEY-V1", &[])
}
fn award_key(epoch: u64) -> Hash {
    domain_hash(b"MUTINY-BUILD8-DIVIDEND-AWARD-STATE-KEY-V1", &epoch.to_be_bytes())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DividendState {
    treasury: Option<Treasury>,
    statuses: StatusBook,
    ledger: Ledger,
}

fn div(e: DivError) -> Error {
    match e {
        DivError::Overflow => Error::Overflow,
        DivError::Malformed => Error::Codec,
        _ => Error::WrongAnchor,
    }
}

impl DividendState {
    /// Genesis construction from the authenticated Treasury input. There is no other way to
    /// activate dividends and no default Treasury.
    pub fn genesis(treasury: Treasury) -> Self {
        Self { treasury: Some(treasury), statuses: StatusBook::default(), ledger: Ledger::new() }
    }
    pub fn is_active(&self) -> bool {
        self.treasury.is_some()
    }
    pub fn treasury(&self) -> Option<&Treasury> {
        self.treasury.as_ref()
    }
    pub fn statuses(&self) -> &StatusBook {
        &self.statuses
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub fn reserved(&self) -> u64 {
        self.ledger.reserved()
    }

    /// Sum of the non-coinbase coins held by the Treasury's addresses. The
    /// owner set is supplied by the caller from the canonical WalletBook (every address of the
    /// Treasury authority, current and historical).
    pub fn backing(coins: &BTreeMap<OutPoint, Coin>, owners: &BTreeSet<Hash>) -> Result<u64> {
        let mut total = 0u64;
        for coin in coins.values() {
            if !coin.coinbase && owners.contains(&coin.output.owner) {
                total = total.checked_add(coin.output.atoms).ok_or(Error::Overflow)?;
            }
        }
        Ok(total)
    }

    /// Event processing only: process every expiry and boundary in `(cursor, max(epoch, cursor)]`.
    /// A block whose actual epoch is at or below the cursor processes nothing new; the cursor
    /// never moves backward. This clock is NOT used for claim eligibility (see `claim_ledger`).
    /// `licenses` lists the canonical (id, owner, activation) triples before the block, where
    /// activation is `None` unless a validated activation rule supplied one. Atomic.
    pub fn advance(
        &mut self,
        epoch: u64,
        backing: u64,
        licenses: &[(Hash, Hash, Option<u64>)],
    ) -> Result<Vec<Event>> {
        if self.treasury.is_none() {
            return Err(Error::WrongOperation);
        }
        let at = epoch.max(self.ledger.cursor());
        let views: Vec<LicenseView> = licenses
            .iter()
            .map(|(id, owner, activation)| LicenseView {
                id: *id,
                owner: *owner,
                activation_epoch: *activation,
                status: self.statuses.effective(id, at),
            })
            .collect();
        let mut next = self.ledger.clone();
        let events = next.advance(at, backing, &views).map_err(div)?;
        self.ledger = next;
        Ok(events)
    }

    /// License status view for claim checks. Status is read at the monotone processed time (the
    /// cursor), so a status that already ended or began stays so under epoch regression.
    pub fn view(&self, id: Hash, owner: Hash, activation: Option<u64>) -> LicenseView {
        LicenseView {
            id,
            owner,
            activation_epoch: activation,
            status: self.statuses.effective(&id, self.ledger.cursor()),
        }
    }

    /// Read-only claim validation at the containing block's ACTUAL epoch.
    pub(crate) fn check_claim_ledger(&self, claim: &Claim, view: &LicenseView, block_epoch: u64) -> std::result::Result<(), DivError> {
        self.ledger.check_claim(claim, block_epoch, view)
    }

    /// Apply one authorized claim to the ledger at the block's ACTUAL epoch (never the cursor).
    /// Wallet authorization, Treasury coin movement and fee rules are the caller's atomic
    /// wrapper (`dividend_claim_v1`).
    pub(crate) fn claim_ledger(&mut self, claim: &Claim, view: &LicenseView, block_epoch: u64) -> std::result::Result<Receipt, DivError> {
        self.ledger.claim(claim, block_epoch, view)
    }

    /// Day-one release policy: there is no production License suspension or revocation. Any
    /// non-Active entry is representable (historical readers, synthetic eligibility tests) but is
    /// refused outright unless the Treasury is TEST-VALUE class, so no production Genesis,
    /// import or state root can contain one. There is no switch, configuration or dormant path.
    fn refuse_production_status(&self) -> Result<()> {
        if self.statuses.is_empty() {
            return Ok(());
        }
        match &self.treasury {
            Some(t) if t.class() == crate::treasury_v1::Class::TestValue => Ok(()),
            _ => Err(Error::WrongOperation),
        }
    }

    /// Cross-record validation against the surrounding State. Called for every root.
    pub fn validate(
        &self,
        coins: &BTreeMap<OutPoint, Coin>,
        owners: &BTreeSet<Hash>,
        licenses: &BTreeSet<Hash>,
    ) -> Result<()> {
        let Some(_) = &self.treasury else {
            if !self.statuses.is_empty() || !self.ledger.is_pristine() {
                return Err(Error::WrongAnchor);
            }
            return Ok(());
        };
        self.refuse_production_status()?;
        if self.statuses.licenses().any(|l| !licenses.contains(l)) {
            return Err(Error::WrongAnchor);
        }
        for award in self.ledger.awards_iter() {
            if award.accounts_iter().any(|(l, _)| !licenses.contains(l)) {
                return Err(Error::WrongAnchor);
            }
        }
        // Every outstanding reserve must have canonical backing in Treasury coins.
        self.ledger.check_invariants(Self::backing(coins, owners)?).map_err(div)
    }

    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        let mut out = BTreeMap::new();
        let Some(treasury) = &self.treasury else {
            if !self.statuses.is_empty() || !self.ledger.is_pristine() {
                return Err(Error::WrongAnchor);
            }
            return Ok(out);
        };
        out.insert(crate::treasury_v1::key(), treasury.encode()?);
        for (k, v) in self.statuses.records()? {
            if out.insert(k, v).is_some() {
                return Err(Error::Duplicate);
            }
        }
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(RECORD_VERSION)
            .unwrap()
            .u8(TAG_HEADER)
            .unwrap()
            .u64(self.ledger.reserved())
            .unwrap()
            .u64(self.ledger.cursor())
            .unwrap();
        if out.insert(header_key(), e.into_writer()).is_some() {
            return Err(Error::Duplicate);
        }
        for award in self.ledger.awards_iter() {
            let raw = encode_award(award)?;
            if out.insert(award_key(award.epoch()), raw).is_some() {
                return Err(Error::Duplicate);
            }
        }
        Ok(out)
    }

    pub fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        let mut treasury = None;
        let mut statuses = BTreeMap::new();
        let mut header = None;
        let mut awards = Vec::new();
        for (key, raw) in records {
            let mut d = Decoder::new(raw);
            let bad = || Error::Codec;
            d.array().map_err(|_| bad())?.ok_or_else(bad)?;
            if d.u8().map_err(|_| bad())? != RECORD_VERSION {
                return Err(bad());
            }
            match d.u8().map_err(|_| bad())? {
                crate::treasury_v1::RECORD_TAG => {
                    if *key != crate::treasury_v1::key() || treasury.is_some() {
                        return Err(Error::Duplicate);
                    }
                    treasury = Some(Treasury::decode(raw)?);
                }
                crate::license_status_v1::RECORD_TAG => {
                    statuses.insert(*key, raw.clone());
                }
                TAG_HEADER => {
                    if *key != header_key() || header.is_some() {
                        return Err(Error::Duplicate);
                    }
                    header = Some(decode_header(raw)?);
                }
                TAG_AWARD => {
                    let award = decode_award(raw)?;
                    if award_key(award.epoch()) != *key {
                        return Err(Error::WrongAnchor);
                    }
                    awards.push(award);
                }
                _ => return Err(bad()),
            }
        }
        let statuses = StatusBook::from_records(&statuses)?;
        let state = match (treasury, header) {
            (None, None) if statuses.is_empty() && awards.is_empty() => Self::default(),
            (Some(treasury), Some((reserved, cursor))) => Self {
                treasury: Some(treasury),
                statuses,
                ledger: Ledger::from_parts(reserved, cursor, awards).map_err(div)?,
            },
            _ => return Err(Error::WrongAnchor),
        };
        state.refuse_production_status()?;
        // Canonical form is unique: re-encoding must reproduce exactly the supplied records.
        if state.records()? != *records {
            return Err(Error::NonCanonical);
        }
        Ok(state)
    }

    /// Test fixtures. These exist only for tests and the explicit feature, and refuse to run
    /// unless the Treasury is TEST-VALUE class, so they cannot act as a production setter.
    #[cfg(any(test, feature = "dividend-test-fixtures"))]
    pub fn fixture_suspend(&mut self, license: Hash, until: u64) -> Result<()> {
        self.fixture_guard()?;
        let now = self.ledger.cursor();
        self.statuses.fixture_suspend(license, until, now)
    }
    #[cfg(any(test, feature = "dividend-test-fixtures"))]
    pub fn fixture_revoke(&mut self, license: Hash) -> Result<()> {
        self.fixture_guard()?;
        self.statuses.fixture_revoke(license);
        Ok(())
    }
    #[cfg(any(test, feature = "dividend-test-fixtures"))]
    pub(crate) fn fixture_guard(&self) -> Result<()> {
        match &self.treasury {
            Some(t) if t.class() == crate::treasury_v1::Class::TestValue => Ok(()),
            _ => Err(Error::WrongOperation),
        }
    }
}

/// Award record (tag 63), array(4): [version 2, 63, epoch u64, accounts array(n)], each account
/// array(4) [license bytes32, share u64, remaining u64, claims u64], strictly ascending by License.
fn encode_award(award: &Award) -> Result<Vec<u8>> {
    let accounts: Vec<_> = award.accounts_iter().collect();
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .u8(RECORD_VERSION)
        .unwrap()
        .u8(TAG_AWARD)
        .unwrap()
        .u64(award.epoch())
        .unwrap()
        .array(accounts.len() as u64)
        .unwrap();
    for (license, account) in accounts {
        e.array(4)
            .unwrap()
            .bytes(license)
            .unwrap()
            .u64(account.share)
            .unwrap()
            .u64(account.remaining)
            .unwrap()
            .u64(account.claims)
            .unwrap();
    }
    let raw = e.into_writer();
    if raw.len() > MAX_AWARD_RECORD {
        return Err(Error::Oversize);
    }
    Ok(raw)
}

fn decode_header(raw: &[u8]) -> Result<(u64, u64)> {
    crate::blocks::canonical(raw, 64)?;
    let bad = || Error::Codec;
    let mut d = Decoder::new(raw);
    if d.array().map_err(|_| bad())? != Some(4)
        || d.u8().map_err(|_| bad())? != RECORD_VERSION
        || d.u8().map_err(|_| bad())? != TAG_HEADER
    {
        return Err(bad());
    }
    let reserved = d.u64().map_err(|_| bad())?;
    let cursor = d.u64().map_err(|_| bad())?;
    if d.position() != raw.len() {
        return Err(bad());
    }
    Ok((reserved, cursor))
}

fn decode_award(raw: &[u8]) -> Result<Award> {
    crate::blocks::canonical(raw, MAX_AWARD_RECORD)?;
    let bad = || Error::Codec;
    let mut d = Decoder::new(raw);
    if d.array().map_err(|_| bad())? != Some(4)
        || d.u8().map_err(|_| bad())? != RECORD_VERSION
        || d.u8().map_err(|_| bad())? != TAG_AWARD
    {
        return Err(bad());
    }
    let epoch = d.u64().map_err(|_| bad())?;
    let n = d.array().map_err(|_| bad())?.ok_or_else(bad)?;
    if n > crate::dividends_v1::MAX_ACCOUNTS_PER_AWARD as u64 {
        return Err(Error::Capacity);
    }
    let mut accounts = BTreeMap::new();
    let mut prior: Option<Hash> = None;
    for _ in 0..n {
        if d.array().map_err(|_| bad())? != Some(4) {
            return Err(bad());
        }
        let license: Hash = d.bytes().map_err(|_| bad())?.try_into().map_err(|_| bad())?;
        if prior.is_some_and(|p| p >= license) {
            return Err(Error::NonCanonical);
        }
        prior = Some(license);
        let share = d.u64().map_err(|_| bad())?;
        let remaining = d.u64().map_err(|_| bad())?;
        let claims = d.u64().map_err(|_| bad())?;
        accounts.insert(license, Account { share, remaining, claims });
    }
    if d.position() != raw.len() {
        return Err(bad());
    }
    let award = Award::from_parts(epoch, accounts).map_err(div)?;
    if encode_award(&award)? != raw {
        return Err(Error::NonCanonical);
    }
    Ok(award)
}

#[cfg(test)]
mod no_production_status_tests {
    use super::*;
    use crate::treasury_v1::Class;
    use mutiny_crypto_v2::{HybridKey, Role};
    fn descriptor() -> Vec<u8> {
        HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner)
            .unwrap()
            .public()
            .descriptor(1)
            .unwrap()
    }
    /// Day-one release: a non-Active License status cannot exist in any production-class state,
    /// whether introduced by import (`from_records`) or by validation of a state root.
    #[test]
    fn production_class_refuses_any_suspended_or_revoked_entry() {
        let h = |n: u8| [n; 32];
        for revoke in [false, true] {
            let mut test = DividendState::genesis(Treasury::new(Class::TestValue, descriptor()).unwrap());
            if revoke {
                test.fixture_revoke(h(1)).unwrap();
            } else {
                test.fixture_suspend(h(1), 50).unwrap();
            }
            // TEST-VALUE: representation and synthetic eligibility remain available.
            let records = test.records().unwrap();
            assert!(DividendState::from_records(&records).is_ok());
            // The same status entries under a production-class Treasury are refused.
            let mut production = records.clone();
            production.insert(
                crate::treasury_v1::key(),
                Treasury::new(Class::Production, descriptor()).unwrap().encode().unwrap(),
            );
            assert!(DividendState::from_records(&production).is_err());
        }
        // A production-class state with no status entries is unaffected.
        let clean = DividendState::genesis(Treasury::new(Class::Production, descriptor()).unwrap());
        assert!(DividendState::from_records(&clean.records().unwrap()).is_ok());
    }
}
