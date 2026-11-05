use crate::{Error, Result};
use primitive_types::U256;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MiningEpoch(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContinuityPeriod(pub u64);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bond {
    pub atoms: u64,
    pub age: ContinuityPeriod,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct History {
    pub p: u64,
    pub a: u64,
    pub s: u64,
    pub h: u64,
    pub penalties: U256,
    pub bonds: Vec<Bond>,
}
pub fn add(a: U256, b: U256) -> Result<U256> {
    a.checked_add(b).ok_or(Error::Overflow)
}
pub fn mul(a: U256, b: U256) -> Result<U256> {
    a.checked_mul(b).ok_or(Error::Overflow)
}
impl History {
    pub fn score(&self) -> Result<U256> {
        if self.s > self.p || self.h > self.p {
            return Err(Error::InvalidCounter);
        }
        if self.bonds.len() > 64 {
            return Err(Error::Capacity);
        }
        let mut q = U256::zero();
        for lot in &self.bonds {
            q = add(
                q,
                mul(lot.atoms.into(), add(U256::one(), lot.age.0.into())?)?,
            )?;
        }
        let g = add(
            add(
                add(mul(1000.into(), self.p.into())?, self.a.into())?,
                mul(4.into(), self.s.into())?,
            )?,
            mul(2.into(), self.h.into())?,
        )?;
        let g = add(g, q / U256::from(10_000_000_000u64))?;
        Ok(if g > self.penalties {
            g - self.penalties
        } else {
            U256::zero()
        })
    }
    pub fn voting_weight(
        &self,
        physical: bool,
        eligible: bool,
        genesis_member: bool,
        first_period_committed: bool,
    ) -> Result<U256> {
        if !physical || !eligible {
            return Ok(U256::zero());
        }
        if genesis_member && !first_period_committed {
            Ok(U256::one())
        } else {
            self.score()
        }
    }
    pub fn complete_period(&mut self, qualified: bool) -> Result<()> {
        let mut next = self.clone();
        next.a = next.a.checked_add(1).ok_or(Error::Overflow)?;
        if qualified {
            next.p = next.p.checked_add(1).ok_or(Error::Overflow)?;
            next.s = next.s.checked_add(1).ok_or(Error::Overflow)?;
            next.h = next.h.checked_add(1).ok_or(Error::Overflow)?;
        } else {
            next.s = 0;
        }
        for bond in &mut next.bonds {
            bond.age.0 = bond.age.0.checked_add(1).ok_or(Error::Overflow)?;
        }
        next.score()?;
        *self = next;
        Ok(())
    }
}

pub fn quorum(weights: &[U256], signers: &[usize]) -> Result<bool> {
    if weights.len() > 1024 {
        return Err(Error::Capacity);
    }
    let mut seen = BTreeSet::new();
    let mut signed = U256::zero();
    for &i in signers {
        if !seen.insert(i) {
            return Err(Error::Duplicate);
        }
        signed = add(signed, *weights.get(i).ok_or(Error::UnknownSigner)?)?;
    }
    let total = weights.iter().try_fold(U256::zero(), |a, b| add(a, *b))?;
    Ok(!total.is_zero() && mul(3.into(), signed)? > mul(2.into(), total)?)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Concentration {
    pub total: U256,
    pub largest: U256,
    pub top_cumulative: Vec<U256>,
    pub survives_each_loss: Vec<bool>,
    pub survival_redundancy_met: bool,
}
pub fn concentration(weights: &[U256], independent_physical_count: usize) -> Result<Concentration> {
    if weights.len() > 1024 {
        return Err(Error::Capacity);
    }
    let total = weights.iter().try_fold(U256::zero(), |a, b| add(a, *b))?;
    let mut sorted = weights.to_vec();
    sorted.sort_by(|a, b| b.cmp(a));
    let mut top = Vec::new();
    let mut running = U256::zero();
    for w in sorted.iter().take(10) {
        running = add(running, *w)?;
        top.push(running);
    }
    let survives_each_loss = weights
        .iter()
        .map(|w| Ok(!total.is_zero() && mul(3.into(), total - *w)? > mul(2.into(), total)?))
        .collect::<Result<Vec<_>>>()?;
    let survival_redundancy_met = independent_physical_count >= 4
        && survives_each_loss.iter().all(|x| *x)
        && !total.is_zero();
    Ok(Concentration {
        total,
        largest: sorted.first().copied().unwrap_or_default(),
        top_cumulative: top,
        survives_each_loss,
        survival_redundancy_met,
    })
}
