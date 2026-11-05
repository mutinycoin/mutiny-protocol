//! Canonical License status representation (Stage C). Status: NATIVE logic.
//!
//! Absence of an entry means Active. A suspension carries an exclusive expiry epoch and ends
//! automatically; revocation is terminal. This module defines the representation and the
//! eligibility view only. No production operation changes a status: the exact offense
//! definitions, evidence formats and thresholds are not yet specified (see the Stage C
//! amendment proposal), so the only mutators are compiled for tests and the explicit
//! `dividend-test-fixtures` feature, and the State-level wrapper additionally refuses to run
//! unless the Treasury class is TEST-VALUE.
use crate::{Error, Hash, Result, dividends_v1::Status, domain_hash};
use minicbor::{Decoder, Encoder};
use std::collections::BTreeMap;

const RECORD_VERSION: u8 = 2;
pub(crate) const RECORD_TAG: u8 = 61;
const MAX_RECORD: usize = 256;
pub const MAX_ENTRIES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// Suspended while the current epoch is strictly below `until`.
    Suspended { until: u64 },
    Revoked,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatusBook {
    entries: BTreeMap<Hash, Entry>,
}

pub fn key(license: &Hash) -> Hash {
    domain_hash(b"MUTINY-BUILD8-LICENSE-STATUS-STATE-KEY-V1", license)
}

pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some()
        && d.u8().ok() == Some(RECORD_VERSION)
        && d.u8().ok() == Some(RECORD_TAG)
}

fn encode_entry(license: &Hash, entry: &Entry) -> Vec<u8> {
    let (kind, until) = match entry {
        Entry::Suspended { until } => (1u8, *until),
        Entry::Revoked => (2u8, 0u64),
    };
    let mut e = Encoder::new(Vec::new());
    e.array(5)
        .unwrap()
        .u8(RECORD_VERSION)
        .unwrap()
        .u8(RECORD_TAG)
        .unwrap()
        .bytes(license)
        .unwrap()
        .u8(kind)
        .unwrap()
        .u64(until)
        .unwrap();
    e.into_writer()
}

fn decode_entry(raw: &[u8]) -> Result<(Hash, Entry)> {
    crate::blocks::canonical(raw, MAX_RECORD)?;
    let bad = || Error::Codec;
    let mut d = Decoder::new(raw);
    if d.array().map_err(|_| bad())? != Some(5)
        || d.u8().map_err(|_| bad())? != RECORD_VERSION
        || d.u8().map_err(|_| bad())? != RECORD_TAG
    {
        return Err(bad());
    }
    let license: Hash = d.bytes().map_err(|_| bad())?.try_into().map_err(|_| bad())?;
    let kind = d.u8().map_err(|_| bad())?;
    let until = d.u64().map_err(|_| bad())?;
    if d.position() != raw.len() {
        return Err(bad());
    }
    let entry = match (kind, until) {
        (1, until) if until > 0 => Entry::Suspended { until },
        (2, 0) => Entry::Revoked,
        _ => return Err(bad()),
    };
    if encode_entry(&license, &entry) != raw {
        return Err(Error::NonCanonical);
    }
    Ok((license, entry))
}

impl StatusBook {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn get(&self, license: &Hash) -> Option<&Entry> {
        self.entries.get(license)
    }
    pub fn licenses(&self) -> impl Iterator<Item = &Hash> {
        self.entries.keys()
    }
    /// Dividend eligibility view at `epoch`. A suspension whose expiry has been reached no
    /// longer applies; a revocation never expires.
    pub fn effective(&self, license: &Hash, epoch: u64) -> Status {
        match self.entries.get(license) {
            None => Status::Active,
            Some(Entry::Revoked) => Status::Revoked,
            Some(Entry::Suspended { until }) if epoch < *until => Status::Suspended,
            Some(Entry::Suspended { .. }) => Status::Active,
        }
    }
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        if self.entries.len() > MAX_ENTRIES {
            return Err(Error::Capacity);
        }
        Ok(self
            .entries
            .iter()
            .map(|(license, entry)| (key(license), encode_entry(license, entry)))
            .collect())
    }
    pub fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        if records.len() > MAX_ENTRIES {
            return Err(Error::Capacity);
        }
        let mut book = Self::default();
        for (record_key, raw) in records {
            let (license, entry) = decode_entry(raw)?;
            if key(&license) != *record_key {
                return Err(Error::WrongAnchor);
            }
            if book.entries.insert(license, entry).is_some() {
                return Err(Error::Duplicate);
            }
        }
        Ok(book)
    }

    /// Test fixtures only. A revoked License never changes; a suspension must end in the
    /// future and may only be replaced by a later or equal expiry (no shortening by fixture).
    #[cfg(any(test, feature = "dividend-test-fixtures"))]
    pub(crate) fn fixture_suspend(&mut self, license: Hash, until: u64, now: u64) -> Result<()> {
        if until <= now {
            return Err(Error::InvalidCounter);
        }
        match self.entries.get(&license) {
            Some(Entry::Revoked) => return Err(Error::WrongOperation),
            Some(Entry::Suspended { until: old }) if *old > until => return Err(Error::InvalidCounter),
            _ => {}
        }
        self.entries.insert(license, Entry::Suspended { until });
        Ok(())
    }
    #[cfg(any(test, feature = "dividend-test-fixtures"))]
    pub(crate) fn fixture_revoke(&mut self, license: Hash) {
        self.entries.insert(license, Entry::Revoked);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(n: u8) -> Hash {
        [n; 32]
    }
    #[test]
    fn absent_means_active_and_suspension_expires_automatically() {
        let mut b = StatusBook::default();
        assert_eq!(b.effective(&h(1), 0), Status::Active);
        b.fixture_suspend(h(1), 100, 10).unwrap();
        assert_eq!(b.effective(&h(1), 99), Status::Suspended);
        assert_eq!(b.effective(&h(1), 100), Status::Active);
        assert_eq!(b.effective(&h(1), u64::MAX), Status::Active);
        assert_eq!(b.effective(&h(2), 50), Status::Active);
    }
    #[test]
    fn revocation_is_terminal() {
        let mut b = StatusBook::default();
        b.fixture_revoke(h(3));
        assert_eq!(b.effective(&h(3), 0), Status::Revoked);
        assert_eq!(b.effective(&h(3), u64::MAX), Status::Revoked);
        assert!(b.fixture_suspend(h(3), 10, 1).is_err());
        assert_eq!(b.effective(&h(3), 5), Status::Revoked);
    }
    #[test]
    fn suspension_cannot_be_shortened_or_start_in_the_past() {
        let mut b = StatusBook::default();
        assert!(b.fixture_suspend(h(1), 5, 5).is_err());
        b.fixture_suspend(h(1), 100, 1).unwrap();
        assert!(b.fixture_suspend(h(1), 50, 1).is_err());
        b.fixture_suspend(h(1), 200, 1).unwrap();
        assert_eq!(b.get(&h(1)), Some(&Entry::Suspended { until: 200 }));
    }
    #[test]
    fn records_roundtrip_and_reject_noncanonical_or_miskeyed() {
        let mut b = StatusBook::default();
        b.fixture_suspend(h(1), 100, 1).unwrap();
        b.fixture_revoke(h(2));
        let r = b.records().unwrap();
        assert_eq!(StatusBook::from_records(&r).unwrap(), b);
        let mut wrong = r.clone();
        let (k, v) = wrong.iter().next().map(|(k, v)| (*k, v.clone())).unwrap();
        wrong.remove(&k);
        wrong.insert(h(9), v);
        assert!(StatusBook::from_records(&wrong).is_err());
        for bad in [
            encode_entry(&h(4), &Entry::Suspended { until: 0 }),
            {
                let mut e = Encoder::new(Vec::new());
                e.array(5).unwrap().u8(2).unwrap().u8(61).unwrap().bytes(&h(4)).unwrap().u8(2).unwrap().u64(7).unwrap();
                e.into_writer()
            },
            {
                let mut e = Encoder::new(Vec::new());
                e.array(5).unwrap().u8(2).unwrap().u8(61).unwrap().bytes(&h(4)).unwrap().u8(3).unwrap().u64(7).unwrap();
                e.into_writer()
            },
        ] {
            assert!(decode_entry(&bad).is_err());
            assert!(is_record(&bad));
        }
        let mut trailing = r.values().next().unwrap().clone();
        trailing.push(0);
        assert!(decode_entry(&trailing).is_err());
    }
}
