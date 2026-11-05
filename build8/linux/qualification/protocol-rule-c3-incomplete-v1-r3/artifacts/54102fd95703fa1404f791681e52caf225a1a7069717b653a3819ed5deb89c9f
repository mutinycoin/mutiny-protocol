//! Hybrid-owner bond state. Owners are stable AddressIDs; a lot is never an
//! authorization source. Shared V1 economic transitions preserve exact heights.
use crate::{
    Error, Hash, Result,
    bonds::{BondLot, LotStatus, actionable},
    domain_hash,
    reputation::{Bond, ContinuityPeriod},
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lot(pub BondLot);
impl Lot {
    pub fn key(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-BOND-LOT-KEY-V2", &self.0.id)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.0.encode_profile(true)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        Ok(Self(BondLot::decode_profile(raw, true)?))
    }
    pub fn start_unbond(&mut self, height: u64, sequence: u64) -> Result<()> {
        self.0.start_unbond_profile(height, sequence, true)
    }
    pub fn withdraw(&mut self, height: u64, sequence: u64) -> Result<u64> {
        self.0.withdraw_profile(height, sequence, true)
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Book {
    pub lots: BTreeMap<Hash, Lot>,
}
impl Book {
    pub fn is_empty(&self) -> bool {
        self.lots.is_empty()
    }
    pub fn validate_at_height(&self, height: u64) -> Result<()> {
        self.records()?;
        if self.lots.values().any(|l| {
            l.0.created_height > height
                || l.0.unbond_height.is_some_and(|h| h > height)
                || l.0.settled_height.is_some_and(|h| h > height)
        }) {
            return Err(Error::WrongAnchor);
        }
        Ok(())
    }
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        if self.lots.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        let mut counts = BTreeMap::<Hash, usize>::new();
        let mut out = BTreeMap::new();
        for (id, lot) in &self.lots {
            if *id != lot.0.id {
                return Err(Error::WrongAnchor);
            }
            if lot.0.locked() {
                let count = counts.entry(lot.0.lineage).or_default();
                *count += 1;
                if *count > 64 {
                    return Err(Error::Capacity);
                }
            }
            if out.insert(lot.key(), lot.encode()?).is_some() {
                return Err(Error::Duplicate);
            }
        }
        Ok(out)
    }
    pub fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        let mut book = Self::default();
        for (key, raw) in records {
            let lot = Lot::decode(raw)?;
            if *key != lot.key() {
                return Err(Error::WrongAnchor);
            }
            if book.lots.insert(lot.0.id, lot).is_some() {
                return Err(Error::Duplicate);
            }
        }
        if book.records()? != *records {
            return Err(Error::NonCanonical);
        }
        Ok(book)
    }
    /// Prevalidated historical evidence only. This does not prove an offense.
    /// The caller settles all evidence before permitting any withdrawal.
    pub fn burn_exposed(
        &mut self,
        lineage: Hash,
        offense: u64,
        height: u64,
        evidence: Hash,
    ) -> Result<u128> {
        if !actionable(offense, height) || evidence == [0; 32] {
            return Err(Error::InvalidCounter);
        }
        self.records()?;
        let mut next = self.clone();
        let mut burned = 0u128;
        for lot in next
            .lots
            .values_mut()
            .filter(|l| l.0.lineage == lineage && l.0.locked() && l.0.qualifying_at(offense))
        {
            burned = burned
                .checked_add(lot.0.atoms.into())
                .ok_or(Error::Overflow)?;
            lot.0.status = LotStatus::Burned;
            lot.0.settled_height = Some(height);
            lot.0.evidence = evidence;
        }
        next.records()?;
        *self = next;
        Ok(burned)
    }
    pub fn reputation_lots(&self, lineage: Hash, height: u64) -> Result<Vec<Bond>> {
        self.records()?;
        let boundary = height / 60 * 60;
        self.lots
            .values()
            .filter(|l| l.0.lineage == lineage && l.0.status == LotStatus::Active)
            .map(|l| {
                if l.0.created_height > height {
                    return Err(Error::WrongAnchor);
                }
                Ok(Bond {
                    atoms: l.0.atoms,
                    age: ContinuityPeriod(boundary.saturating_sub(l.0.created_height) / 60),
                })
            })
            .collect()
    }
}
pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = minicbor::Decoder::new(raw);
    d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) && d.u8().ok() == Some(52)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bonds::{EVIDENCE_HEIGHTS, LOCK_HEIGHTS, MINIMUM_ATOMS};
    fn lot() -> Lot {
        Lot(BondLot {
            id: [1; 32],
            node: [2; 32],
            lineage: [2; 32],
            owner: [255; 32],
            atoms: MINIMUM_ATOMS,
            created_height: 1,
            sequence: 0,
            unbond_height: None,
            settled_height: None,
            status: LotStatus::Active,
            evidence: [0; 32],
        })
    }
    #[test]
    fn hybrid_record_and_legacy_are_disjoint() {
        let l = lot();
        let raw = l.encode().unwrap();
        assert!(is_record(&raw));
        assert_eq!(Lot::decode(&raw).unwrap(), l);
        assert!(BondLot::decode(&raw).is_err());
        let mut legacy = l.0.clone();
        legacy.owner = ed25519_dalek::SigningKey::from_bytes(&[3; 32])
            .verifying_key()
            .to_bytes();
        assert!(Lot::decode(&legacy.encode().unwrap()).is_err());
        let mut wrong = raw.clone();
        wrong.push(0);
        assert!(Lot::decode(&wrong).is_err());
        let book = Book {
            lots: [(l.0.id, l)].into_iter().collect(),
        };
        assert_eq!(Book::from_records(&book.records().unwrap()).unwrap(), book);
    }
    #[test]
    fn exact_window_withdrawal_and_no_retroactive_exposure() {
        let mut l = lot();
        let u = 1 + LOCK_HEIGHTS;
        let h = u + EVIDENCE_HEIGHTS;
        assert!(l.start_unbond(1, 1).is_err());
        l.start_unbond(u, 1).unwrap();
        assert!(l.0.qualifying_at(u));
        assert!(!l.0.qualifying_at(u + 1));
        let book = Book {
            lots: [(l.0.id, l.clone())].into_iter().collect(),
        };
        assert!(book.reputation_lots([2; 32], u).unwrap().is_empty());
        assert!(l.withdraw(h - 1, 2).is_err());
        assert_eq!(l.withdraw(h, 2).unwrap(), MINIMUM_ATOMS);
        let mut burned = book.clone();
        assert_eq!(
            burned.burn_exposed([2; 32], u, h, [4; 32]).unwrap(),
            MINIMUM_ATOMS as u128
        );
        assert!(
            burned
                .lots
                .get_mut(&[1; 32])
                .unwrap()
                .withdraw(h, 2)
                .is_err()
        );
        let mut late = book.clone();
        assert!(late.burn_exposed([2; 32], u, h + 1, [4; 32]).is_err());
        assert_eq!(late, book);
        assert_eq!(
            late.burn_exposed([2; 32], u + 1, u + 2, [4; 32]).unwrap(),
            0
        );
        let mut fresh = Book {
            lots: [([1; 32], lot())].into_iter().collect(),
        };
        assert_eq!(fresh.burn_exposed([2; 32], 1, 2, [4; 32]).unwrap(), 0);
    }
    #[test]
    fn economics_match_legacy_and_checked_overflow_is_atomic() {
        let mut v2 = lot();
        v2.0.owner = ed25519_dalek::SigningKey::from_bytes(&[3; 32])
            .verifying_key()
            .to_bytes();
        let mut v1 = v2.0.clone();
        let u = 1 + LOCK_HEIGHTS;
        v1.start_unbond(u, 1).unwrap();
        v2.start_unbond(u, 1).unwrap();
        assert_eq!(v1, v2.0);
        assert_eq!(
            v1.withdraw(u + EVIDENCE_HEIGHTS, 2).unwrap(),
            v2.withdraw(u + EVIDENCE_HEIGHTS, 2).unwrap()
        );
        assert_eq!(v1, v2.0);
        let mut overflow = lot();
        let before = overflow.clone();
        assert!(overflow.start_unbond(u64::MAX, 1).is_err());
        assert_eq!(overflow, before);
    }
}
