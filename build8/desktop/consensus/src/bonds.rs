//! Canonical bond principal and exposure history. Q excludes UNBONDING from
//! U+1; locked exposure through U+43,200 is independent of reputation credit.
//! Restart Order 2026-10-02 sec.4: with B the canonical lock-start height and U
//! the finalized unbond-notice height, a withdrawal at height W requires BOTH
//! W >= B + LOCK_HEIGHTS (259,200 certified blocks) AND W >= U + EVIDENCE_HEIGHTS
//! (43,200 certified blocks). The notice may overlap the minimum holding period,
//! so U only has to be after B. Heights are elapsed certified blocks, never
//! wall-clock time, and nothing is rounded to ContinuityPeriod boundaries.
use crate::{
    Error, Hash, Result, domain_hash,
    reputation::{Bond, ContinuityPeriod},
};
use minicbor::{Decoder, Encoder, data::Type};
use std::collections::BTreeMap;
pub const MINIMUM_ATOMS: u64 = 10_000_000_000;
pub const LOCK_HEIGHTS: u64 = 4320 * 60;
pub const EVIDENCE_HEIGHTS: u64 = 43200;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LotStatus {
    Active = 0,
    Unbonding = 1,
    Withdrawn = 2,
    Burned = 3,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondLot {
    pub id: Hash,
    pub node: Hash,
    pub lineage: Hash,
    pub owner: Hash,
    pub atoms: u64,
    pub created_height: u64,
    pub sequence: u64,
    pub unbond_height: Option<u64>,
    pub settled_height: Option<u64>,
    pub status: LotStatus,
    pub evidence: Hash,
}
fn hash(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("hash"))
}
fn optional(d: &mut Decoder<'_>) -> std::result::Result<Option<u64>, minicbor::decode::Error> {
    if d.datatype()? == Type::Null {
        d.null()?;
        Ok(None)
    } else {
        Ok(Some(d.u64()?))
    }
}
/// Earliest certified-block height at which a lot with lock start `created`
/// and finalized unbond notice `unbond` may be withdrawn: both independent
/// conditions (minimum holding and notice) must hold, so the later one binds.
pub fn withdrawal_floor(created: u64, unbond: u64) -> Result<u64> {
    let holding = created.checked_add(LOCK_HEIGHTS).ok_or(Error::Overflow)?;
    let notice = unbond.checked_add(EVIDENCE_HEIGHTS).ok_or(Error::Overflow)?;
    Ok(holding.max(notice))
}
pub fn actionable(offense: u64, inclusion: u64) -> bool {
    offense > 0
        && inclusion
            .checked_sub(offense)
            .is_some_and(|age| (1..=EVIDENCE_HEIGHTS).contains(&age))
}
impl BondLot {
    pub fn key(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-BOND-LOT-KEY-V1", &self.id)
    }
    pub fn locked(&self) -> bool {
        matches!(self.status, LotStatus::Active | LotStatus::Unbonding)
    }
    /// A deposit in C first supports C+1; unbond U can still support U's
    /// parent-weight certificate. Settlement similarly does not rewrite U.
    pub fn qualifying_at(&self, height: u64) -> bool {
        self.created_height < height
            && self.unbond_height.is_none_or(|u| height <= u)
            && self.settled_height.is_none_or(|s| height <= s)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.encode_profile(false)
    }
    // V2 interprets owner as an AddressID. Authorization is resolved separately
    // through the authenticated WalletBook; economic rules remain identical.
    pub(crate) fn encode_profile(&self, hybrid: bool) -> Result<Vec<u8>> {
        if self.atoms < MINIMUM_ATOMS || self.created_height == 0 {
            return Err(Error::InvalidCounter);
        }
        if !hybrid {
            ed25519_dalek::VerifyingKey::from_bytes(&self.owner).map_err(|_| Error::BadSignature)?;
        }
        if self.unbond_height.is_some_and(|u| u <= self.created_height) {
            return Err(Error::InvalidCounter);
        }
        if self
            .settled_height
            .is_some_and(|s| s <= self.created_height || self.unbond_height.is_some_and(|u| u > s))
        {
            return Err(Error::InvalidCounter);
        }
        match self.status {
            LotStatus::Active
                if self.unbond_height.is_none()
                    && self.settled_height.is_none()
                    && self.evidence == [0; 32] => {}
            LotStatus::Unbonding
                if self.unbond_height.is_some()
                    && self.settled_height.is_none()
                    && self.evidence == [0; 32] => {}
            LotStatus::Withdrawn if self.evidence == [0; 32] => {
                let u = self.unbond_height.ok_or(Error::InvalidCounter)?;
                let s = self.settled_height.ok_or(Error::InvalidCounter)?;
                if s < withdrawal_floor(self.created_height, u)? {
                    return Err(Error::InvalidCounter);
                }
            }
            LotStatus::Burned if self.settled_height.is_some() && self.evidence != [0; 32] => {}
            _ => return Err(Error::InvalidCounter),
        }
        let mut e = Encoder::new(Vec::new());
        e.array(if hybrid { 13 } else { 12 })
            .unwrap()
            .u8(if hybrid { 2 } else { 1 })
            .unwrap();
        if hybrid { e.u8(52).unwrap(); }
        e
            .bytes(&self.id)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .bytes(&self.lineage)
            .unwrap()
            .bytes(&self.owner)
            .unwrap()
            .u64(self.atoms)
            .unwrap()
            .u64(self.created_height)
            .unwrap()
            .u64(self.sequence)
            .unwrap();
        for value in [self.unbond_height, self.settled_height] {
            if let Some(h) = value {
                e.u64(h).unwrap();
            } else {
                e.null().unwrap();
            }
        }
        e.u8(self.status as u8)
            .unwrap()
            .bytes(&self.evidence)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        Self::decode_profile(raw, false)
    }
    pub(crate) fn decode_profile(raw: &[u8], hybrid: bool) -> Result<Self> {
        crate::blocks::canonical(raw, 256)?;
        let mut d = Decoder::new(raw);
        let lot = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("bond lot");
            if d.array()? != Some(if hybrid { 13 } else { 12 })
                || d.u8()? != if hybrid { 2 } else { 1 }
                || (hybrid && d.u8()? != 52) {
                return Err(bad());
            }
            let id = hash(&mut d)?;
            let node = hash(&mut d)?;
            let lineage = hash(&mut d)?;
            let owner = hash(&mut d)?;
            let atoms = d.u64()?;
            let created_height = d.u64()?;
            let sequence = d.u64()?;
            let unbond_height = optional(&mut d)?;
            let settled_height = optional(&mut d)?;
            let status = match d.u8()? {
                0 => LotStatus::Active,
                1 => LotStatus::Unbonding,
                2 => LotStatus::Withdrawn,
                3 => LotStatus::Burned,
                _ => return Err(bad()),
            };
            Ok(Self {
                id,
                node,
                lineage,
                owner,
                atoms,
                created_height,
                sequence,
                unbond_height,
                settled_height,
                status,
                evidence: hash(&mut d)?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if lot.encode_profile(hybrid)? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(lot)
    }
    pub fn start_unbond(&mut self, height: u64, sequence: u64) -> Result<()> {
        self.start_unbond_profile(height, sequence, false)
    }
    pub(crate) fn start_unbond_profile(&mut self, height: u64, sequence: u64, hybrid: bool) -> Result<()> {
        self.encode_profile(hybrid)?;
        if self.status != LotStatus::Active || self.sequence.checked_add(1) != Some(sequence) {
            return Err(Error::StaleSequence);
        }
        // The notice only has to follow lock start; it may overlap the minimum
        // holding duration. The independent withdrawal floors are enforced at
        // withdrawal and in the canonical record invariant.
        if height <= self.created_height {
            return Err(Error::InvalidCounter);
        }
        height
            .checked_add(EVIDENCE_HEIGHTS)
            .ok_or(Error::Overflow)?;
        self.status = LotStatus::Unbonding;
        self.unbond_height = Some(height);
        self.sequence = sequence;
        Ok(())
    }
    pub fn withdraw(&mut self, height: u64, sequence: u64) -> Result<u64> {
        self.withdraw_profile(height, sequence, false)
    }
    pub(crate) fn withdraw_profile(&mut self, height: u64, sequence: u64, hybrid: bool) -> Result<u64> {
        self.encode_profile(hybrid)?;
        if self.status != LotStatus::Unbonding || self.sequence.checked_add(1) != Some(sequence) {
            return Err(Error::StaleSequence);
        }
        if height
            < withdrawal_floor(
                self.created_height,
                self.unbond_height.ok_or(Error::InvalidCounter)?,
            )?
        {
            return Err(Error::InvalidCounter);
        }
        self.status = LotStatus::Withdrawn;
        self.settled_height = Some(height);
        self.sequence = sequence;
        Ok(self.atoms)
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BondBook {
    pub lots: BTreeMap<Hash, BondLot>,
}
impl BondBook {
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        if self.lots.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        let mut counts = BTreeMap::<Hash, usize>::new();
        let mut records = BTreeMap::new();
        for (id, lot) in &self.lots {
            if *id != lot.id {
                return Err(Error::WrongAnchor);
            }
            if lot.locked() {
                let n = counts.entry(lot.lineage).or_default();
                *n += 1;
                if *n > 64 {
                    return Err(Error::Capacity);
                }
            }
            records.insert(lot.key(), lot.encode()?);
        }
        Ok(records)
    }
    pub fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        let mut lots = BTreeMap::new();
        for (key, raw) in records {
            let lot = BondLot::decode(raw)?;
            if *key != lot.key() {
                return Err(Error::WrongAnchor);
            }
            if lots.insert(lot.id, lot).is_some() {
                return Err(Error::Duplicate);
            }
        }
        let book = Self { lots };
        if book.records()? != *records {
            return Err(Error::NonCanonical);
        }
        Ok(book)
    }
    /// This consumes only prevalidated objective evidence. It cannot authorize
    /// a revocation or establish historical vote validity by itself.
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
        let mut burned = 0u128;
        for lot in self
            .lots
            .values_mut()
            .filter(|l| l.lineage == lineage && l.locked() && l.qualifying_at(offense))
        {
            burned = burned
                .checked_add(lot.atoms.into())
                .ok_or(Error::Overflow)?;
            lot.status = LotStatus::Burned;
            lot.settled_height = Some(height);
            lot.evidence = evidence;
        }
        Ok(burned)
    }
    pub fn reputation_lots(&self, lineage: Hash, height: u64) -> Result<Vec<Bond>> {
        self.records()?;
        let boundary = height / 60 * 60;
        self.lots
            .values()
            .filter(|l| l.lineage == lineage && l.status == LotStatus::Active)
            .map(|l| {
                if l.created_height > height {
                    return Err(Error::WrongAnchor);
                }
                Ok(Bond {
                    atoms: l.atoms,
                    age: ContinuityPeriod(boundary.saturating_sub(l.created_height) / 60),
                })
            })
            .collect()
    }
}
pub(crate) fn is_record(key: Hash, raw: &[u8]) -> bool {
    BondLot::decode(raw).is_ok_and(|l| l.key() == key)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lot(id: u8, created: u64) -> BondLot {
        BondLot {
            id: [id; 32],
            node: [2; 32],
            lineage: [2; 32],
            owner: ed25519_dalek::SigningKey::from_bytes(&[3; 32])
                .verifying_key()
                .to_bytes(),
            atoms: MINIMUM_ATOMS,
            created_height: created,
            sequence: 0,
            unbond_height: None,
            settled_height: None,
            status: LotStatus::Active,
            evidence: [0; 32],
        }
    }
    #[test]
    fn exact_unbond_exposure_window_and_boundary_evidence_priority() {
        let mut active = lot(1, 60);
        let u = 60 + LOCK_HEIGHTS;
        let settlement = u + EVIDENCE_HEIGHTS;
        assert!(active.start_unbond(60, 1).is_err());
        active.start_unbond(u, 1).unwrap();
        assert!(active.qualifying_at(u));
        assert!(!active.qualifying_at(u + 1));
        let book = BondBook {
            lots: [(active.id, active.clone())].into_iter().collect(),
        };
        assert!(book.reputation_lots([2; 32], u).unwrap().is_empty());
        assert!(actionable(u, u + 1));
        assert!(actionable(u, settlement));
        assert!(!actionable(u, settlement + 1));
        assert!(!actionable(u, u));
        let mut no_evidence = active.clone();
        assert!(no_evidence.withdraw(settlement - 1, 2).is_err());
        assert_eq!(no_evidence.withdraw(settlement, 2).unwrap(), MINIMUM_ATOMS);
        let mut with_evidence = book.clone();
        assert_eq!(
            with_evidence
                .burn_exposed([2; 32], u, settlement, [4; 32])
                .unwrap(),
            MINIMUM_ATOMS as u128
        );
        assert!(
            with_evidence
                .lots
                .get_mut(&[1; 32])
                .unwrap()
                .withdraw(settlement, 2)
                .is_err()
        );
        assert_eq!(
            BondBook::from_records(&with_evidence.records().unwrap()).unwrap(),
            with_evidence
        );
        let mut late = book.clone();
        assert!(
            late.burn_exposed([2; 32], u, settlement + 1, [4; 32])
                .is_err()
        );
        assert_eq!(late, book);
    }
    #[test]
    fn lots_created_after_offense_and_later_offenses_are_not_retroactively_exposed() {
        let old = lot(1, 1);
        let recent = lot(2, 100);
        let mut notice = lot(3, 1);
        let u = 1 + LOCK_HEIGHTS;
        notice.start_unbond(u, 1).unwrap();
        let mut book = BondBook {
            lots: [(old.id, old), (recent.id, recent)].into_iter().collect(),
        };
        assert_eq!(
            book.burn_exposed([2; 32], 100, 101, [4; 32]).unwrap(),
            MINIMUM_ATOMS as u128
        );
        assert_eq!(book.lots[&[2; 32]].status, LotStatus::Active);
        let mut book = BondBook {
            lots: [(notice.id, notice)].into_iter().collect(),
        };
        assert_eq!(
            book.burn_exposed([2; 32], u + 1, u + 2, [4; 32]).unwrap(),
            0
        );
        assert_eq!(book.lots[&[3; 32]].status, LotStatus::Unbonding);
    }
    #[test]
    fn early_notice_overlaps_holding_and_both_floors_apply_independently() {
        // B = 60. Notice at U = B + 1 is valid; withdrawal waits for B + 259,200.
        let b = 60;
        let holding = b + LOCK_HEIGHTS;
        let mut early = lot(1, b);
        assert!(early.start_unbond(b - 1, 1).is_err());
        assert!(early.start_unbond(b, 1).is_err());
        early.start_unbond(b + 1, 1).unwrap();
        assert_eq!(withdrawal_floor(b, b + 1).unwrap(), holding);
        assert!(holding > b + 1 + EVIDENCE_HEIGHTS);
        let mut too_soon = early.clone();
        assert!(too_soon.withdraw(b + 1 + EVIDENCE_HEIGHTS, 2).is_err());
        assert!(too_soon.withdraw(holding - 1, 2).is_err());
        assert_eq!(too_soon.status, LotStatus::Unbonding);
        assert_eq!(too_soon.withdraw(holding, 2).unwrap(), MINIMUM_ATOMS);
        assert_eq!(too_soon.settled_height, Some(holding));
        // Notice exactly at the end of holding: the 43,200-block notice binds.
        let mut late = lot(2, b);
        late.start_unbond(holding, 1).unwrap();
        assert_eq!(withdrawal_floor(b, holding).unwrap(), holding + EVIDENCE_HEIGHTS);
        assert!(late.withdraw(holding + EVIDENCE_HEIGHTS - 1, 2).is_err());
        late.withdraw(holding + EVIDENCE_HEIGHTS, 2).unwrap();
        // Notice one block before the crossover: holding still binds.
        let crossover = holding - EVIDENCE_HEIGHTS;
        assert_eq!(withdrawal_floor(b, crossover).unwrap(), holding);
        assert_eq!(withdrawal_floor(b, crossover + 1).unwrap(), holding + 1);
        // Elapsed-block units: 720 periods = 43,200 and 4,320 periods = 259,200.
        assert_eq!(EVIDENCE_HEIGHTS, 720 * 60);
        assert_eq!(LOCK_HEIGHTS, 4320 * 60);
        assert_eq!((EVIDENCE_HEIGHTS, LOCK_HEIGHTS), (43_200, 259_200));
    }
    #[test]
    fn canonical_record_rejects_withdrawn_lots_below_either_floor_and_overflow_is_checked() {
        let b = 60;
        let mut ok = lot(1, b);
        ok.start_unbond(b + 1, 1).unwrap();
        ok.withdraw(b + LOCK_HEIGHTS, 2).unwrap();
        assert_eq!(BondLot::decode(&ok.encode().unwrap()).unwrap(), ok);
        let mut below_holding = ok.clone();
        below_holding.settled_height = Some(b + LOCK_HEIGHTS - 1);
        assert!(below_holding.encode().is_err());
        let mut below_notice = lot(2, b);
        below_notice.start_unbond(b + LOCK_HEIGHTS, 1).unwrap();
        below_notice.withdraw(b + LOCK_HEIGHTS + EVIDENCE_HEIGHTS, 2).unwrap();
        below_notice.settled_height = Some(b + LOCK_HEIGHTS + EVIDENCE_HEIGHTS - 1);
        assert!(below_notice.encode().is_err());
        let mut at_creation = lot(3, b);
        at_creation.status = LotStatus::Unbonding;
        at_creation.unbond_height = Some(b);
        assert!(at_creation.encode().is_err());
        assert!(withdrawal_floor(u64::MAX, 1).is_err());
        assert!(withdrawal_floor(1, u64::MAX).is_err());
        let mut near_max = lot(4, u64::MAX - LOCK_HEIGHTS);
        assert!(near_max.start_unbond(u64::MAX, 1).is_err());
        assert_eq!(near_max.status, LotStatus::Active);
    }
    #[test]
    fn withdrawal_deadline_is_height_based_without_period_rounding() {
        let mut lot = lot(1, 1);
        let u = 1 + LOCK_HEIGHTS;
        lot.start_unbond(u, 1).unwrap();
        assert!(lot.withdraw(u + EVIDENCE_HEIGHTS - 1, 2).is_err());
        assert_eq!(
            lot.withdraw(u + EVIDENCE_HEIGHTS, 2).unwrap(),
            MINIMUM_ATOMS
        );
        assert_eq!(BondLot::decode(&lot.encode().unwrap()).unwrap(), lot);
    }
}
