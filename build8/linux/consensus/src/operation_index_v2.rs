//! Derived canonical operation confirmations (Order P8). No StateRoot authority.
//! Bond outcomes come from execution, never from payout existence. Structural
//! block verification cannot authenticate that outcome: compare the exact record
//! with the wallet replica's independently executed index before confirming it.
use crate::{Hash, blocks::BlockBody, bond_ops_v2::CommandOutcome, domain_hash};
use minicbor::{Decoder, Encoder, data::Type};
use std::collections::BTreeMap;

pub const WIRE_DOMAIN: &[u8] = b"MUTINY-BUILD8-OPERATION-WIRE-V1";
pub const LIFECYCLE_ID_DOMAIN: &[u8] = b"MUTINY-BUILD8-BLOCK-OPERATION-ID-V1";
pub const MAX_RECORD_BYTES: usize = 512;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexError {
    Codec,
    Bounds,
    Identity,
    Receipt,
    MissingOutcome,
}
pub type Result<T> = std::result::Result<T, IndexError>;
fn codec<E>(_: E) -> IndexError {
    IndexError::Codec
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array().map_err(codec)? == Some(n) {
        Ok(())
    } else {
        Err(IndexError::Codec)
    }
}
fn hash(d: &mut Decoder<'_>) -> Result<Hash> {
    d.bytes().map_err(codec)?.try_into().map_err(codec)
}

/// Signatures are excluded for wallet operations, included for lifecycle bodies.
/// This is identity derivation, not signature, authority or execution validation.
pub fn operation_id(list: u8, raw: &[u8]) -> Result<(u8, Hash)> {
    crate::blocks::canonical(raw, 16_384).map_err(codec)?;
    if list == 0 {
        let tx = crate::hybrid_transaction_v2::Transaction::decode(raw).map_err(codec)?;
        let kind = match tx {
            crate::hybrid_transaction_v2::Transaction::Transfer(_) => 1,
            _ => 2,
        };
        return Ok((kind, tx.id().map_err(codec)?));
    }
    if list != 1 {
        return Err(IndexError::Bounds);
    }
    if crate::trading_host_v1::operation(raw).map_err(codec)? {
        let op = crate::trading_v1::NativeOperation::decode(raw).map_err(codec)?;
        return Ok((30, op.operation.id().map_err(codec)?));
    }
    let kind = crate::blocks::operation_kind(raw).map_err(codec)?;
    let id = match kind {
        10 => crate::op_envelope_v1::assignment_id(
            &crate::license_assignment_v2::Assignment::decode(raw).map_err(codec)?,
        )
        .map_err(codec)?,
        19 | 20 => crate::bond_ops_v2::Operation::decode(raw)
            .map_err(codec)?
            .id()
            .map_err(codec)?,
        23 => crate::dividend_claim_v1::SignedClaim::decode(raw)
            .map_err(codec)?
            .id(),
        24 => crate::bond_create_v3::FundedBondCreate::decode(raw)
            .map_err(codec)?
            .id()
            .map_err(codec)?,
        11 | 12 | 13 | 14..=17 | 21 | 22 => lifecycle_id(kind, raw),
        #[cfg(test)]
        254 => lifecycle_id(kind, raw), // existing crate-internal envelope test carrier only
        _ => return Err(IndexError::Codec),
    };
    Ok((kind, id))
}
fn lifecycle_id(kind: u8, raw: &[u8]) -> Hash {
    let mut e = Encoder::new(Vec::new());
    e.array(2).unwrap().u8(kind).unwrap().bytes(raw).unwrap();
    domain_hash(LIFECYCLE_ID_DOMAIN, &e.into_writer())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRecord {
    pub op_id: Hash,
    pub kind: u8,
    pub height: u64,
    pub block: Hash,
    pub list: u8,
    pub position: u32,
    pub wire: Hash,
    pub receipt: Option<Vec<u8>>,
}
impl OperationRecord {
    fn bounds(&self) -> Result<()> {
        if self.height == 0
            || self.block == [0; 32]
            || self.list > 1
            || self.position > 4095
            || (self.list == 0) != matches!(self.kind, 1 | 2)
        {
            return Err(IndexError::Bounds);
        }
        match (&self.receipt, self.kind) {
            (None, 11 | 12 | 13 | 14..=17 | 21 | 22 | 25) => {}
            #[cfg(test)]
            (None, 254) => {}
            (Some(raw), 1 | 2 | 10 | 19 | 20 | 23 | 24 | 30) => validate_receipt(self.kind, raw)?,
            _ => return Err(IndexError::Receipt),
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.bounds()?;
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.op_id)
            .unwrap()
            .u8(self.kind)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .bytes(&self.block)
            .unwrap()
            .u8(self.list)
            .unwrap()
            .u32(self.position)
            .unwrap()
            .bytes(&self.wire)
            .unwrap();
        if let Some(raw) = &self.receipt {
            e.writer_mut().extend_from_slice(raw);
        } else {
            e.null().unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_RECORD_BYTES {
            return Err(IndexError::Bounds);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_RECORD_BYTES).map_err(codec)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 9)?;
        if d.u8().map_err(codec)? != 1 {
            return Err(IndexError::Codec);
        }
        let mut out = Self {
            op_id: hash(&mut d)?,
            kind: d.u8().map_err(codec)?,
            height: d.u64().map_err(codec)?,
            block: hash(&mut d)?,
            list: d.u8().map_err(codec)?,
            position: d.u32().map_err(codec)?,
            wire: hash(&mut d)?,
            receipt: None,
        };
        if d.datatype().map_err(codec)? == Type::Null {
            d.null().map_err(codec)?;
        } else {
            let start = d.position();
            d.skip().map_err(codec)?;
            out.receipt = Some(raw[start..d.position()].to_vec());
        }
        if d.position() != raw.len() || out.encode()? != raw {
            return Err(IndexError::Codec);
        }
        Ok(out)
    }
    /// Structural verification only for bond outcomes; use verify_against_replica
    /// as well. The replica's exact block height is mandatory even for lifecycle ids.
    pub fn verify_in_block(&self, body: &BlockBody, block_hash: Hash) -> Result<()> {
        self.verify_in_block_inner(body,block_hash,None)
    }
    /// Structural position/wire verification under a store-issued historical parent rule.
    /// This does not authenticate execution outcomes: compare against the replayed replica.
    pub fn verify_in_block_with_capacity(
        &self,body: &BlockBody,block_hash: Hash,capacity: &crate::body_capacity_v3::BodyCapacity,
    ) -> Result<()> {
        capacity.encode(body).map_err(codec)?;
        self.verify_in_block_inner(body,block_hash,Some(capacity))
    }
    fn verify_in_block_inner(
        &self,body: &BlockBody,block_hash: Hash,capacity: Option<&crate::body_capacity_v3::BodyCapacity>,
    ) -> Result<()> {
        self.bounds()?;
        if self.block != block_hash || self.height != body.height {
            return Err(IndexError::Identity);
        }
        let list = if self.list == 0 {
            &body.transactions
        } else {
            &body.operations
        };
        let raw = list.get(self.position as usize).ok_or(IndexError::Bounds)?;
        if capacity_operation_id(self.list,raw,capacity)? != (self.kind, self.op_id)
            || domain_hash(WIRE_DOMAIN, raw) != self.wire
        {
            return Err(IndexError::Identity);
        }
        let outcome = self.command_outcome()?;
        if receipt(self.kind, raw, outcome)? != self.receipt {
            return Err(IndexError::Receipt);
        }
        Ok(())
    }
    /// `replica` must come from the user's independently verified CanonicalStore.
    pub fn verify_against_replica(&self, replica: &Self) -> Result<()> {
        self.bounds()?;
        replica.bounds()?;
        if self != replica {
            return Err(IndexError::Receipt);
        }
        Ok(())
    }
    pub fn command_outcome(&self) -> Result<Option<CommandOutcome>> {
        if !matches!(self.kind, 19 | 20) {
            return Ok(None);
        }
        let raw = self.receipt.as_ref().ok_or(IndexError::Receipt)?;
        let mut d = Decoder::new(raw);
        array(&mut d, if self.kind == 19 { 3 } else { 4 })?;
        Ok(Some(match d.u8().map_err(codec)? {
            1 => CommandOutcome::Applied,
            2 => CommandOutcome::NoEffectBurned,
            _ => return Err(IndexError::Receipt),
        }))
    }
}
fn validate_receipt(kind: u8, raw: &[u8]) -> Result<()> {
    crate::blocks::canonical(raw, MAX_RECORD_BYTES).map_err(codec)?;
    let mut d = Decoder::new(raw);
    match kind {
        1 | 2 => {
            array(&mut d, 2)?;
            d.u64().map_err(codec)?;
            d.u32().map_err(codec)?;
        }
        10 => {
            array(&mut d, 4)?;
            hash(&mut d)?;
            hash(&mut d)?;
            d.u64().map_err(codec)?;
            d.u64().map_err(codec)?;
        }
        19 | 20 => {
            array(&mut d, if kind == 19 { 3 } else { 4 })?;
            let outcome = d.u8().map_err(codec)?;
            if !matches!(outcome, 1 | 2) {
                return Err(IndexError::Receipt);
            }
            hash(&mut d)?;
            d.u64().map_err(codec)?;
            if kind == 20 {
                if outcome == 1 {
                    hash(&mut d)?;
                } else {
                    d.null().map_err(codec)?;
                }
            }
        }
        23 => {
            array(&mut d, 3)?;
            d.u64().map_err(codec)?;
            hash(&mut d)?;
            d.u64().map_err(codec)?;
        }
        24 => {
            array(&mut d, 4)?;
            hash(&mut d)?;
            d.u64().map_err(codec)?;
            d.u64().map_err(codec)?;
            if d.u8().map_err(codec)? > 1 {
                return Err(IndexError::Receipt);
            }
        }
        30 => {
            array(&mut d, 3)?;
            if d.u8().map_err(codec)? > 6 {
                return Err(IndexError::Receipt);
            }
            d.u64().map_err(codec)?;
            hash(&mut d)?;
        }
        _ => return Err(IndexError::Receipt),
    }
    if d.position() != raw.len() {
        return Err(IndexError::Receipt);
    }
    Ok(())
}
fn receipt(kind: u8, raw: &[u8], outcome: Option<CommandOutcome>) -> Result<Option<Vec<u8>>> {
    let mut e = Encoder::new(Vec::new());
    match kind {
        1 | 2 => {
            let tx = crate::hybrid_transaction_v2::Transaction::decode(raw).map_err(codec)?;
            e.array(2)
                .unwrap()
                .u64(tx.fee())
                .unwrap()
                .u32(tx.outputs().len() as u32)
                .unwrap();
        }
        10 => {
            let a = crate::license_assignment_v2::Assignment::decode(raw).map_err(codec)?;
            let b = a.enrollment.binding;
            e.array(4)
                .unwrap()
                .bytes(&b.license)
                .unwrap()
                .bytes(&b.worker_id)
                .unwrap()
                .u64(b.assignment_generation)
                .unwrap()
                .u64(b.effective_epoch)
                .unwrap();
        }
        19 | 20 => {
            let op = crate::bond_ops_v2::Operation::decode(raw).map_err(codec)?;
            let o = outcome.ok_or(IndexError::MissingOutcome)?;
            let (lot, sequence) = op.action.target();
            e.array(if kind == 19 { 3 } else { 4 })
                .unwrap()
                .u8(o.code())
                .unwrap()
                .bytes(&lot)
                .unwrap()
                .u64(sequence)
                .unwrap();
            if kind == 20 {
                if o == CommandOutcome::Applied {
                    e.bytes(&op.payout_id().map_err(codec)?).unwrap();
                } else {
                    e.null().unwrap();
                }
            }
        }
        23 => {
            let c = crate::dividend_claim_v1::SignedClaim::decode(raw)
                .map_err(codec)?
                .body;
            e.array(3)
                .unwrap()
                .u64(c.award_epoch)
                .unwrap()
                .bytes(&c.license)
                .unwrap()
                .u64(c.amount)
                .unwrap();
        }
        24 => {
            let b = crate::bond_create_v3::FundedBondCreate::decode(raw).map_err(codec)?;
            e.array(4)
                .unwrap()
                .bytes(&b.lot_id())
                .unwrap()
                .u64(b.unsigned.principal)
                .unwrap()
                .u64(b.unsigned.fee)
                .unwrap()
                .u8(u8::from(b.unsigned.change.is_some()))
                .unwrap();
        }
        30 => {
            use crate::trading_v1::Action;
            let op = crate::trading_v1::NativeOperation::decode(raw)
                .map_err(codec)?
                .operation;
            let tag = match op.action {
                Action::HashLock { .. } => 0,
                Action::Claim { .. } => 1,
                Action::Refund { .. } => 2,
                Action::LicenseDvp { .. } => 3,
                Action::FiatLock { .. } => 4,
                Action::FiatRelease { .. } => 5,
                Action::TreasuryRotate { .. } => 6,
            };
            let wire = domain_hash(
                &[crate::trading_v1::NATIVE_NAMESPACE, b"/signed"].concat(),
                raw,
            );
            e.array(3)
                .unwrap()
                .u8(tag)
                .unwrap()
                .u64(op.meta.fee.0)
                .unwrap()
                .bytes(&wire)
                .unwrap();
        }
        _ => return Ok(None),
    }
    Ok(Some(e.into_writer()))
}
/// Called only after successful execution; outcomes are supplied by that exact execution.
pub fn records(
    body: &BlockBody,
    block: Hash,
    outcomes: &BTreeMap<Hash, CommandOutcome>,
) -> Result<Vec<OperationRecord>> {
    body.encode().map_err(codec)?;
    records_inner(body,block,outcomes,None)
}
/// Derived only after exact native execution under the store-issued parent rule.
pub fn records_with_capacity(
    body: &BlockBody, block: Hash, outcomes: &BTreeMap<Hash,CommandOutcome>,
    capacity: &crate::body_capacity_v3::BodyCapacity,
) -> Result<Vec<OperationRecord>> {
    capacity.encode(body).map_err(codec)?;
    records_inner(body,block,outcomes,Some(capacity))
}
fn records_inner(
    body: &BlockBody,block: Hash,outcomes: &BTreeMap<Hash,CommandOutcome>,
    capacity: Option<&crate::body_capacity_v3::BodyCapacity>,
) -> Result<Vec<OperationRecord>> {
    let mut rows = Vec::new();
    for (list, items) in [(0, &body.transactions), (1, &body.operations)] {
        for (position, raw) in items.iter().enumerate() {
            let (kind, op_id) = capacity_operation_id(list,raw,capacity)?;
            let row = OperationRecord {
                op_id,
                kind,
                height: body.height,
                block,
                list,
                position: position as u32,
                wire: domain_hash(WIRE_DOMAIN, raw),
                receipt: receipt(kind, raw, outcomes.get(&op_id).copied())?,
            };
            row.encode()?;
            rows.push(row);
        }
    }
    Ok(rows)
}
fn capacity_operation_id(
    list:u8,raw:&[u8],capacity:Option<&crate::body_capacity_v3::BodyCapacity>,
) -> Result<(u8,Hash)> {
    match capacity {
        Some(capacity) if list==1 && capacity.allows_a2()
            && (raw.len()>16384 || crate::blocks::operation_kind(raw).ok()==Some(25)) => capacity.operation_id(raw),
        _ => operation_id(list,raw),
    }
}
