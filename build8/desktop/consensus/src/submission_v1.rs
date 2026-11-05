//! Complete wallet submission objects and bounded public status messages.
//! A status report is a hint. Only the receiver's own verified canonical index
//! can establish finality; transport acknowledgement never establishes it.
use crate::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    evidence_history_v2::History,
    execution::State,
    hybrid_transaction_v2::{Inclusion, Transaction},
    operation_index_v2::{OperationRecord, WIRE_DOMAIN},
    transactions::OutPoint,
};
use minicbor::{Decoder, Encoder, data::Type};
use std::collections::BTreeSet;
pub const MAX_OBJECT: usize = 16_384;
pub const RESOURCE_DOMAIN: &[u8] = b"MUTINY-BUILD8-POOL-RESOURCE-V1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Reason {
    InputSpent = 1,
    AuthorityChanged = 2,
    SequenceUsed = 3,
    PreconditionStale = 4,
    OfferConsumed = 5,
    ReferenceNotCanonical = 6,
    NotYetValid = 7,
    WindowExpired = 8,
    Capacity = 9,
    Codec = 10,
    Signature = 11,
    Context = 12,
    ResourceConflict = 13,
    Invalid = 14,
}
impl Reason {
    fn decode(n: u16) -> Result<Self> {
        Ok(match n {
            1 => Self::InputSpent,
            2 => Self::AuthorityChanged,
            3 => Self::SequenceUsed,
            4 => Self::PreconditionStale,
            5 => Self::OfferConsumed,
            6 => Self::ReferenceNotCanonical,
            7 => Self::NotYetValid,
            8 => Self::WindowExpired,
            9 => Self::Capacity,
            10 => Self::Codec,
            11 => Self::Signature,
            12 => Self::Context,
            13 => Self::ResourceConflict,
            14 => Self::Invalid,
            _ => return Err(Self::Codec),
        })
    }
}
pub type Result<T> = std::result::Result<T, Reason>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Unknown,
    Pending,
    Unfinalized { height: u64, block: Hash },
    Finalized(OperationRecord),
    Expired { last: u64 },
    Conflicting { reason: Reason, height: u64 },
    Rejected { reason: Reason, height: u64 },
}
impl Status {
    pub fn code(&self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Pending => 1,
            Self::Unfinalized { .. } => 2,
            Self::Finalized(_) => 3,
            Self::Expired { .. } => 4,
            Self::Conflicting { .. } => 5,
            Self::Rejected { .. } => 6,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusEntry {
    pub id: Hash,
    pub status: Status,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusReport {
    pub tip_height: u64,
    pub tip_block: Hash,
    pub entries: Vec<StatusEntry>,
}
fn fixed(d: &mut Decoder<'_>) -> Result<Hash> {
    d.bytes()
        .map_err(|_| Reason::Codec)?
        .try_into()
        .map_err(|_| Reason::Codec)
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array().map_err(|_| Reason::Codec)? == Some(n) {
        Ok(())
    } else {
        Err(Reason::Codec)
    }
}
pub fn encode_query(ids: &[Hash]) -> Result<Vec<u8>> {
    if ids.is_empty() || ids.len() > 64 || ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(Reason::Codec);
    }
    let mut e = Encoder::new(Vec::new());
    e.array(2)
        .unwrap()
        .u8(1)
        .unwrap()
        .array(ids.len() as u64)
        .unwrap();
    for id in ids {
        e.bytes(id).unwrap();
    }
    Ok(e.into_writer())
}
pub fn decode_query(raw: &[u8]) -> Result<Vec<Hash>> {
    crate::blocks::canonical(raw, 4096).map_err(|_| Reason::Codec)?;
    let mut d = Decoder::new(raw);
    array(&mut d, 2)?;
    if d.u8().map_err(|_| Reason::Codec)? != 1 {
        return Err(Reason::Codec);
    }
    let n = d.array().map_err(|_| Reason::Codec)?.ok_or(Reason::Codec)?;
    if n == 0 || n > 64 {
        return Err(Reason::Codec);
    }
    let mut ids = Vec::new();
    for _ in 0..n {
        ids.push(fixed(&mut d)?)
    }
    if encode_query(&ids)? != raw {
        return Err(Reason::Codec);
    }
    Ok(ids)
}
impl StatusReport {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.tip_block == [0; 32]
            || self.entries.len() > 32
            || self
                .entries
                .iter()
                .map(|e| e.id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.entries.len()
        {
            return Err(Reason::Codec);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u8(1)
            .unwrap()
            .array(2)
            .unwrap()
            .u64(self.tip_height)
            .unwrap()
            .bytes(&self.tip_block)
            .unwrap()
            .array(self.entries.len() as u64)
            .unwrap();
        for entry in &self.entries {
            e.array(3)
                .unwrap()
                .bytes(&entry.id)
                .unwrap()
                .u8(entry.status.code())
                .unwrap();
            match &entry.status {
                Status::Unknown | Status::Pending => {
                    e.null().unwrap();
                }
                Status::Unfinalized { height, block } => {
                    if *height <= self.tip_height || *block == [0; 32] {
                        return Err(Reason::Codec);
                    }
                    e.array(2)
                        .unwrap()
                        .u64(*height)
                        .unwrap()
                        .bytes(block)
                        .unwrap();
                }
                Status::Finalized(record) => {
                    if record.op_id != entry.id || record.height > self.tip_height {
                        return Err(Reason::Codec);
                    }
                    let raw = record.encode().map_err(|_| Reason::Codec)?;
                    e.writer_mut().extend_from_slice(&raw);
                }
                Status::Expired { last } => {
                    e.array(1).unwrap().u64(*last).unwrap();
                }
                Status::Conflicting { reason, height } | Status::Rejected { reason, height } => {
                    if *height > self.tip_height.saturating_add(1) {
                        return Err(Reason::Codec);
                    }
                    e.array(2)
                        .unwrap()
                        .u16(*reason as u16)
                        .unwrap()
                        .u64(*height)
                        .unwrap();
                }
            }
        }
        let raw = e.into_writer();
        if raw.len() > MAX_OBJECT {
            Err(Reason::Capacity)
        } else {
            Ok(raw)
        }
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_OBJECT).map_err(|_| Reason::Codec)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 3)?;
        if d.u8().map_err(|_| Reason::Codec)? != 1 {
            return Err(Reason::Codec);
        }
        array(&mut d, 2)?;
        let tip_height = d.u64().map_err(|_| Reason::Codec)?;
        let tip_block = fixed(&mut d)?;
        let n = d.array().map_err(|_| Reason::Codec)?.ok_or(Reason::Codec)?;
        if n > 32 {
            return Err(Reason::Codec);
        }
        let mut entries = Vec::new();
        for _ in 0..n {
            array(&mut d, 3)?;
            let id = fixed(&mut d)?;
            let code = d.u8().map_err(|_| Reason::Codec)?;
            let status = match code {
                0 | 1 => {
                    if d.datatype().map_err(|_| Reason::Codec)? != Type::Null {
                        return Err(Reason::Codec);
                    }
                    d.null().map_err(|_| Reason::Codec)?;
                    if code == 0 {
                        Status::Unknown
                    } else {
                        Status::Pending
                    }
                }
                2 => {
                    array(&mut d, 2)?;
                    Status::Unfinalized {
                        height: d.u64().map_err(|_| Reason::Codec)?,
                        block: fixed(&mut d)?,
                    }
                }
                3 => {
                    let start = d.position();
                    d.skip().map_err(|_| Reason::Codec)?;
                    Status::Finalized(
                        OperationRecord::decode(&raw[start..d.position()])
                            .map_err(|_| Reason::Codec)?,
                    )
                }
                4 => {
                    array(&mut d, 1)?;
                    Status::Expired {
                        last: d.u64().map_err(|_| Reason::Codec)?,
                    }
                }
                5 | 6 => {
                    array(&mut d, 2)?;
                    let reason = Reason::decode(d.u16().map_err(|_| Reason::Codec)?)?;
                    let height = d.u64().map_err(|_| Reason::Codec)?;
                    if code == 5 {
                        Status::Conflicting { reason, height }
                    } else {
                        Status::Rejected { reason, height }
                    }
                }
                _ => return Err(Reason::Codec),
            };
            entries.push(StatusEntry { id, status });
        }
        let report = Self {
            tip_height,
            tip_block,
            entries,
        };
        if report.encode()? != raw {
            return Err(Reason::Codec);
        }
        Ok(report)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Object {
    Transaction(Transaction),
    Bond(crate::bond_create_v3::FundedBondCreate),
    Command(crate::bond_ops_v2::Operation),
    Claim(crate::dividend_claim_v1::SignedClaim),
    Assignment(crate::license_assignment_v2::Assignment),
    Trading(crate::trading_v1::NativeOperation),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submission {
    pub list: u8,
    pub kind: u8,
    pub id: Hash,
    pub wire: Hash,
    pub raw: Vec<u8>,
    object: Object,
}
fn tx_error(e: crate::transactions::TxError) -> Reason {
    use crate::transactions::TxError::*;
    match e {
        MissingInput => Reason::InputSpent,
        Owner => Reason::AuthorityChanged,
        Signature => Reason::Signature,
        Future => Reason::NotYetValid,
        Expired => Reason::WindowExpired,
        Binding => Reason::Context,
        _ => Reason::Invalid,
    }
}
fn envelope_error(e: crate::op_envelope_v1::EnvelopeError) -> Reason {
    use crate::op_envelope_v1::EnvelopeError::*;
    match e {
        Future => Reason::NotYetValid,
        Expired => Reason::WindowExpired,
        ReferenceNotCanonical => Reason::ReferenceNotCanonical,
        Stale(_) | Unavailable(_) => Reason::PreconditionStale,
        _ => Reason::Invalid,
    }
}
impl Submission {
    /// Accepts only complete canonical atomic wallet objects; lifecycle controls,
    /// retired forms, partial signature exchange objects and loose components fail.
    pub fn decode(list: u8, raw: &[u8]) -> Result<Self> {
        if raw.is_empty() || raw.len() > MAX_OBJECT {
            return Err(Reason::Codec);
        }
        let (kind, id) =
            crate::operation_index_v2::operation_id(list, raw).map_err(|_| Reason::Codec)?;
        let object = match (list, kind) {
            (0, 1 | 2) => Object::Transaction(Transaction::decode(raw).map_err(|_| Reason::Codec)?),
            (1, 24) => Object::Bond(
                crate::bond_create_v3::FundedBondCreate::decode(raw).map_err(|_| Reason::Codec)?,
            ),
            (1, 19 | 20) => Object::Command(
                crate::bond_ops_v2::Operation::decode(raw).map_err(|_| Reason::Codec)?,
            ),
            (1, 23) => Object::Claim(
                crate::dividend_claim_v1::SignedClaim::decode(raw).map_err(|_| Reason::Codec)?,
            ),
            (1, 10) => Object::Assignment(
                crate::license_assignment_v2::Assignment::decode(raw).map_err(|_| Reason::Codec)?,
            ),
            (1, 30) => Object::Trading(
                crate::trading_v1::NativeOperation::decode(raw).map_err(|_| Reason::Codec)?,
            ),
            _ => return Err(Reason::Codec),
        };
        Ok(Self {
            list,
            kind,
            id,
            wire: crate::domain_hash(WIRE_DOMAIN, raw),
            raw: raw.to_vec(),
            object,
        })
    }
    pub fn window(&self) -> (u64, u64) {
        match &self.object {
            Object::Transaction(t) => t.window(),
            Object::Bond(b) => (
                b.unsigned.envelope.first_height,
                b.unsigned.envelope.last_height,
            ),
            Object::Command(c) => (c.envelope.first_height, c.envelope.last_height),
            Object::Claim(c) => (c.body.created_height, c.body.expiry_height),
            Object::Assignment(a) => (1, a.enrollment.binding.valid_until_height),
            Object::Trading(t) => (
                t.operation.meta.envelope.first_height,
                t.operation.meta.envelope.last_height,
            ),
        }
    }
    pub fn fee(&self) -> u64 {
        match &self.object {
            Object::Transaction(t) => t.fee(),
            Object::Bond(b) => b.unsigned.fee,
            Object::Trading(t) => t.operation.meta.fee.0,
            _ => 0,
        }
    }
    pub fn structural(&self) -> bool {
        matches!(
            self.object,
            Object::Claim(_) | Object::Command(_) | Object::Assignment(_)
        )
    }
    pub fn reference_height(&self) -> Option<u64> {
        crate::op_envelope_v1::referenced_heights_in(
            if self.list == 0 {
                std::slice::from_ref(&self.raw)
            } else {
                &[]
            },
            if self.list == 1 {
                std::slice::from_ref(&self.raw)
            } else {
                &[]
            },
        )
        .into_iter()
        .next()
    }
    pub fn check_context(&self, parent: &FinalizedAnchor) -> Result<()> {
        let (network, g, f) = match &self.object {
            Object::Transaction(t) => t.context(),
            Object::Bond(b) => (NETWORK_ID, b.unsigned.genesis, b.unsigned.fingerprint),
            Object::Command(c) => (NETWORK_ID, c.genesis, c.fingerprint),
            Object::Claim(c) => (c.body.network, c.body.genesis, c.body.fingerprint),
            Object::Assignment(a) => (
                NETWORK_ID,
                a.enrollment.binding.genesis,
                a.enrollment.binding.fingerprint,
            ),
            Object::Trading(t) => {
                let c = &t.operation.meta.context;
                (c.network, c.genesis, c.fingerprint)
            }
        };
        if network != NETWORK_ID || g != parent.genesis || f != parent.fingerprint {
            Err(Reason::Context)
        } else {
            Ok(())
        }
    }
    pub fn verify_signatures(&self) -> Result<()> {
        match &self.object {
            Object::Transaction(Transaction::Transfer(t)) => {
                t.verify_signatures().map_err(|_| Reason::Signature)
            }
            Object::Transaction(Transaction::FundedRotation(r)) => {
                r.verify_signatures().map_err(|_| Reason::Signature)
            }
            Object::Bond(b) => b.verify_signatures().map_err(|_| Reason::Signature),
            Object::Command(c) => c.verify_signatures().map_err(|_| Reason::Signature),
            Object::Claim(c) => c.verify_signature().map_err(|_| Reason::Signature),
            Object::Assignment(a) => a.verify_signatures().map_err(|_| Reason::Signature),
            Object::Trading(_) => {
                crate::trading_v1::verify_signatures(&self.raw).map_err(|_| Reason::Signature)
            }
        }
    }
    /// All changing state is checked anew, even when signatures were cached.
    pub fn verify_state(
        &self,
        parent: &FinalizedAnchor,
        state: &State,
        history: &History,
        epoch: u64,
    ) -> Result<()> {
        self.check_context(parent)?;
        let height = parent.height.checked_add(1).ok_or(Reason::Invalid)?;
        let (first, last) = self.window();
        if height < first {
            return Err(Reason::NotYetValid);
        }
        if height > last {
            return Err(Reason::WindowExpired);
        }
        let envelope = if self.list==0 {crate::op_envelope_v1::transaction_envelope(&self.raw)}
            else {crate::op_envelope_v1::operation_envelope(&self.raw)};
        if let Some(envelope)=envelope {envelope.check_inclusion(parent,history).map_err(envelope_error)?;}
        match &self.object {
            Object::Transaction(Transaction::Transfer(t)) => t
                .verify_state(
                    parent.genesis,
                    parent.fingerprint,
                    height,
                    &state.coins,
                    &state.wallets,
                )
                .map(|_| ())
                .map_err(tx_error),
            Object::Transaction(Transaction::FundedRotation(r)) => r
                .verify_state(&Inclusion { parent, history }, state)
                .map(|_| ())
                .map_err(tx_error),
            Object::Bond(b) => b.verify_state(state, parent, history).map_err(|e| match e {
                crate::bond_create_v3::BondError::Envelope(e) => envelope_error(e),
                crate::bond_create_v3::BondError::Authority(_)=>Reason::AuthorityChanged,
                _ => Reason::Invalid,
            }),
            Object::Command(c) => {
                let (lot, _) = c.action.target();
                let lot = state.bonds_v2.lots.get(&lot).ok_or(Reason::SequenceUsed)?;
                c.verify_state(parent, history, &state.wallets, lot)
                    .map_err(|_| Reason::SequenceUsed)
            }
            Object::Claim(c) => {
                let mut tentative = state.clone();
                tentative
                    .licenses_v2
                    .activate_due(epoch)
                    .map_err(|_| Reason::Invalid)?;
                tentative
                    .advance_dividends(epoch)
                    .map_err(|_| Reason::Invalid)?;
                crate::dividend_claim_v1::check_state(
                    &tentative,
                    c,
                    parent.genesis,
                    parent.fingerprint,
                    height,
                    epoch,
                )
                .map(|_| ())
                .map_err(|e| match e {
                    crate::dividend_claim_v1::ClaimError::StaleOwner => Reason::AuthorityChanged,
                    crate::dividend_claim_v1::ClaimError::Duplicate => Reason::SequenceUsed,
                    _ => Reason::Invalid,
                })
            }
            Object::Assignment(a) => {
                let license = state
                    .licenses_v2
                    .license(a.enrollment.binding.license)
                    .ok_or(Reason::Invalid)?;
                if a.enrollment.binding.assignment_generation!=license.assignment_sequence.checked_add(1).ok_or(Reason::Invalid)? {return Err(Reason::SequenceUsed)}
                if a.enrollment.binding.effective_epoch<=epoch {return Err(Reason::WindowExpired)}
                if a.enrollment.binding.effective_epoch!=epoch.checked_add(1).ok_or(Reason::Invalid)? {return Err(Reason::NotYetValid)}
                a.verify_next_epoch_state(&crate::license_assignment_v2::ParentContext {
                    genesis: parent.genesis,
                    fingerprint: parent.fingerprint,
                    height,
                    epoch,
                    license,
                    wallets: &state.wallets,
                })
                .map_err(|_| Reason::AuthorityChanged)
            }
            Object::Trading(_) => crate::trading_v1::verify_state_at_epoch(
                state,
                parent,
                state.root().map_err(|_| Reason::Invalid)?,
                history,
                &self.raw,
                &crate::trading_v1::CandidatePolicy::native_denomination_locked(),
                epoch,
            )
            .map_err(|e| match e {
                crate::trading_v1::NativeError::Envelope(e) => envelope_error(e),
                crate::trading_v1::NativeError::Stale(_) => Reason::PreconditionStale,
                crate::trading_v1::NativeError::Missing => Reason::InputSpent,
                crate::trading_v1::NativeError::Authority => Reason::AuthorityChanged,
                crate::trading_v1::NativeError::Conflict
                | crate::trading_v1::NativeError::Duplicate => Reason::OfferConsumed,
                _ => Reason::Invalid,
            }),
        }
    }
    pub fn resources(&self) -> BTreeSet<Hash> {
        let mut r = BTreeSet::new();
        let mut put = |tag: u8, subject: Hash, n: Option<u64>| {
            let mut e = Encoder::new(Vec::new());
            e.array(if n.is_some() { 3 } else { 2 })
                .unwrap()
                .u8(tag)
                .unwrap()
                .bytes(&subject)
                .unwrap();
            if let Some(n) = n {
                e.u64(n).unwrap();
            }
            r.insert(crate::domain_hash(RESOURCE_DOMAIN, &e.into_writer()));
        };
        let inputs: Vec<OutPoint> = match &self.object {
            Object::Transaction(t) => t.inputs(),
            Object::Bond(b) => b.unsigned.inputs.clone(),
            Object::Trading(t) => t.inputs.clone(),
            _ => vec![],
        };
        for p in inputs {
            put(1, p.transaction, Some(p.index as u64));
        }
        match &self.object {
            Object::Transaction(t) => {
                if let Some(a) = t.rotation_authority() {
                    put(2, a, None);
                }
            }
            Object::Command(c) => {
                put(3, c.action.target().0, None);
            }
            Object::Bond(b) => {
                put(3, b.lot_id(), None);
            }
            Object::Claim(c) => {
                let mut e = Encoder::new(Vec::new());
                e.array(4)
                    .unwrap()
                    .u8(4)
                    .unwrap()
                    .u64(c.body.award_epoch)
                    .unwrap()
                    .bytes(&c.body.license)
                    .unwrap()
                    .u64(c.body.sequence)
                    .unwrap();
                r.insert(crate::domain_hash(RESOURCE_DOMAIN, &e.into_writer()));
            }
            Object::Assignment(a) => {
                put(6, a.enrollment.binding.license, None);
            }
            Object::Trading(t) => {
                use crate::trading_v1::Action;
                let op = &t.operation;
                match &op.action {
                    Action::HashLock { offer, maker, .. }
                    | Action::FiatLock { offer, maker, .. } => put(
                        5,
                        crate::trading_v1::single_fill_key(&op.meta.context, *maker, *offer),
                        None,
                    ),
                    Action::LicenseDvp {
                        offer,
                        maker,
                        license,
                        ..
                    } => {
                        put(
                            5,
                            crate::trading_v1::single_fill_key(&op.meta.context, *maker, *offer),
                            None,
                        );
                        put(6, *license, None);
                    }
                    Action::Claim { output, .. }
                    | Action::Refund { output, .. }
                    | Action::FiatRelease { output, .. } => put(8, *output, None),
                    Action::TreasuryRotate { treasury, .. } => put(7, *treasury, None),
                }
            }
        }
        r
    }
}
