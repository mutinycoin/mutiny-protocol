//! CometBFT-style weighted priority scheduling. This never normalizes consensus
//! reputation/weights. Only proposer priorities are centered/rescaled. Canonical
//! height progression is independent of which commit round proof was observed.
use crate::{Error, Hash, Result};
use primitive_types::U256;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerSchedule {
    weights: BTreeMap<Hash, i128>,
    priorities: BTreeMap<Hash, i128>,
    total: i128,
}
fn weights(input: &BTreeMap<Hash, U256>) -> Result<(BTreeMap<Hash, i128>, i128)> {
    if input.len() > 1024 {
        return Err(Error::Capacity);
    }
    let mut out = BTreeMap::new();
    let mut total = 0i128;
    for (node, weight) in input {
        if weight.is_zero() {
            continue;
        }
        // Approved u64 history/bond bounds yield <113-bit aggregate arithmetic.
        // Refuse out-of-model values rather than truncating or capping weight.
        if *weight > U256::from(i128::MAX as u128) {
            return Err(Error::Overflow);
        }
        let value = weight.low_u128() as i128;
        total = total.checked_add(value).ok_or(Error::Overflow)?;
        out.insert(*node, value);
    }
    if total == 0 {
        return Err(Error::NoQuorum);
    }
    Ok((out, total))
}
impl ProposerSchedule {
    pub fn genesis(input: &BTreeMap<Hash, U256>) -> Result<Self> {
        let (weights, total) = weights(input)?;
        let priorities = weights.keys().map(|k| (*k, 0)).collect();
        Ok(Self {
            weights,
            priorities,
            total,
        })
    }
    fn normalize(&mut self) -> Result<()> {
        let min = *self.priorities.values().min().ok_or(Error::NoQuorum)?;
        let max = *self.priorities.values().max().ok_or(Error::NoQuorum)?;
        let distance = max.checked_sub(min).ok_or(Error::Overflow)?;
        let window = self.total.checked_mul(2).ok_or(Error::Overflow)?;
        if distance > window {
            let ratio = distance / window + i128::from(distance % window != 0);
            for p in self.priorities.values_mut() {
                *p /= ratio;
            }
        }
        let sum = self
            .priorities
            .values()
            .try_fold(0i128, |a, b| a.checked_add(*b).ok_or(Error::Overflow))?;
        let average = sum / (self.priorities.len() as i128);
        for p in self.priorities.values_mut() {
            *p = p.checked_sub(average).ok_or(Error::Overflow)?;
        }
        Ok(())
    }
    fn select(&mut self) -> Result<Hash> {
        self.normalize()?;
        for (node, priority) in &mut self.priorities {
            *priority = priority
                .checked_add(self.weights[node])
                .ok_or(Error::Overflow)?;
        }
        let node = *self
            .priorities
            .iter()
            .max_by(|(a, pa), (b, pb)| pa.cmp(pb).then_with(|| b.cmp(a)))
            .ok_or(Error::NoQuorum)?
            .0;
        let priority = self.priorities.get_mut(&node).ok_or(Error::UnknownSigner)?;
        *priority = priority.checked_sub(self.total).ok_or(Error::Overflow)?;
        Ok(node)
    }
    /// Rounds operate on a copy. Receiving a round-N certificate cannot advance
    /// canonical proposer history N extra times at the next height.
    pub fn rounds(&self) -> RoundSchedule {
        RoundSchedule {
            cursor: self.clone(),
            round: None,
            proposer: None,
        }
    }
    /// Exactly once per finalized height, using the independently committed next
    /// voter set. Offline validators are retained in input; zero weights cannot
    /// propose. Incoming priorities receive the standard 1+1/8 total penalty.
    pub fn next_height(&self, input: &BTreeMap<Hash, U256>) -> Result<Self> {
        let mut next = self.clone();
        next.select()?;
        let (weights, total) = weights(input)?;
        let penalty = total
            .checked_add(total / 8)
            .ok_or(Error::Overflow)?
            .checked_neg()
            .ok_or(Error::Overflow)?;
        next.priorities.retain(|node, _| weights.contains_key(node));
        for node in weights.keys() {
            next.priorities.entry(*node).or_insert(penalty);
        }
        next.weights = weights;
        next.total = total;
        next.normalize()?;
        Ok(next)
    }
}
pub struct RoundSchedule {
    cursor: ProposerSchedule,
    round: Option<u64>,
    proposer: Option<Hash>,
}
impl RoundSchedule {
    /// Incremental bounded work; network-supplied round numbers never drive an
    /// unbounded catch-up loop. The actor authorizes each round transition.
    pub fn advance(&mut self) -> Result<(u64, Hash)> {
        let round = match self.round {
            None => 0,
            Some(r) => r.checked_add(1).ok_or(Error::Overflow)?,
        };
        let mut next = self.cursor.clone();
        let proposer = next.select()?;
        self.cursor = next;
        self.round = Some(round);
        self.proposer = Some(proposer);
        Ok((round, proposer))
    }
    pub fn current(&self) -> Option<(u64, Hash)> {
        self.round.zip(self.proposer)
    }
}
