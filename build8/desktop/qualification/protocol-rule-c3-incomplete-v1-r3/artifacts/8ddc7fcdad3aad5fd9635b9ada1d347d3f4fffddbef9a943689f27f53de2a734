//! Hybrid bond commands and their settlement. Verification is separate from settlement and grants
//! no authority unless the caller supplies authenticated parent state.
//!
//! Candidate 3 (Lane P design `qualification/candidate-3/P-LANE-DESIGN-V1.md` sections 2.4, 5.1 and
//! 11.1, amended by `P-LANE-DESIGN-AMENDMENTS-V1.md` AM-1(d) and AM-5; Order of 4 October 2026,
//! decisions P1, P4 and Q4). Normative text: `spec/HYBRID-BOND-SETTLEMENT-V2.md`. Bond CREATION
//! moved to the funded composite `bond_create_v3` (operation kind 24); the escrow-funded kind 18,
//! `Action::Create` and the escrow address are retired. A command (Unbond kind 19, Withdraw kind
//! 20) has body version 3, which carries the operation envelope of `op_envelope_v1` instead of an
//! exact height and parent anchor:
//!
//! ```text
//! unsigned   = [3, kind (19|20), network u32, genesis b32, fingerprint b32, Envelope, owner b32,
//!               authorizer bytes, [lot b32, sequence u64]]
//! op         = [2, kind, unsigned bytes, ed448 bytes(114), fndsa bytes(1280)]     at most 4096 bytes
//! signature  : authorizer key, Domain::BondUnbond / Domain::BondWithdraw, over `unsigned`
//! command id = SHA-256("MUTINY-BUILD8-BOND-COMMAND-ID-V3" || 0x00 || unsigned)
//! payout id  = SHA-256("MUTINY-BUILD8-BOND-PAYOUT-V3" || 0x00 || unsigned)
//! ```
//!
//! The envelope's precondition list must be EMPTY: the committed precondition of a command is its
//! lot sequence (design 5.1), and the lifecycle settlement has no state on which another
//! precondition could be evaluated, so a precondition is refused rather than carried unchecked.
//! The notice height U of an Unbond and the settlement height of a Withdraw are the ACTUAL
//! inclusion height `parent.height + 1`, never a signed height; the withdrawal floor stays
//! `max(B + 259,200, U + 43,200)` certified blocks (`bonds::withdrawal_floor`), with no conversion
//! into MiningEpochs or wall time.
//!
//! Q4, an explicit and narrow economic decision: `FeeRule::None` applies to the dedicated
//! BondUnbond and BondWithdraw operations ONLY (kinds 19 and 20). A command has no fee field and no
//! inputs, and settlement moves no fee. Q4 does NOT exempt BondCreate funding (kind 24 pays 1 atom
//! per byte of its complete signed operation), ordinary transfers or trades. Replay and admission
//! protections are kept: the per-lot sequence allows exactly one Unbond (sequence 1) and one
//! Withdraw (sequence 2) in a lot's life, at most one command per lot per block, current owner
//! authority from the parent WalletBook, the signed window and the finalized reference.
use crate::{
    Error, Hash, NETWORK_ID, Result, anchors::FinalizedAnchor, bonds_v2::Lot, domain_hash,
    evidence_history_v2::History, op_envelope_v1::Envelope, transactions::OutPoint,
    wallet_authority_v1::WalletBook,
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
/// The existing byte bound of a command operation. The funded BondCreate (kind 24) uses the
/// 16 KiB per-operation bound instead (`bond_create_v3::MAX_OPERATION_BYTES`).
pub const MAX_OPERATION: usize = 4096;
/// Command body version. Version 2 bodies (exact height and parent anchor) are retired.
pub const BODY_VERSION: u8 = 3;
/// `domain_hash` domain of the command identity. PROPOSED-UNFROZEN.
pub const COMMAND_ID_DOMAIN: &[u8] = b"MUTINY-BUILD8-BOND-COMMAND-ID-V3";
/// `domain_hash` domain of the withdrawal payout transaction id. PROPOSED-UNFROZEN; replaces
/// `MUTINY-BUILD8-BOND-PAYOUT-V2` over the retired body.
pub const PAYOUT_DOMAIN: &[u8] = b"MUTINY-BUILD8-BOND-PAYOUT-V3";
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Unbond {
        lot: Hash,
        sequence: u64,
    },
    Withdraw {
        lot: Hash,
        sequence: u64,
    },
}
impl Action {
    pub fn kind(&self) -> u8 {
        match self {
            Self::Unbond { .. } => 19,
            Self::Withdraw { .. } => 20,
        }
    }
    fn domain(&self) -> Domain {
        match self {
            Self::Unbond { .. } => Domain::BondUnbond,
            Self::Withdraw { .. } => Domain::BondWithdraw,
        }
    }
    /// The lot this command acts on and the sequence it consumes.
    pub fn target(&self) -> (Hash, u64) {
        match self {
            Self::Unbond { lot, sequence } | Self::Withdraw { lot, sequence } => (*lot, *sequence),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub envelope: Envelope,
    pub owner: Hash,
    pub authorizer: Vec<u8>,
    pub action: Action,
    pub signature: HybridSignature,
}
/// The single signature a command needs, as a typed intent (Order W4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSigningIntent {
    pub domain: Domain,
    pub payload: Vec<u8>,
}
impl Operation {
    fn public(&self) -> Result<PublicKey> {
        let (p, _) = PublicKey::decode_descriptor(&self.authorizer).map_err(|_| Error::Codec)?;
        if p.role != Role::WalletOwner {
            return Err(Error::BadSignature);
        }
        Ok(p)
    }
    pub fn body(&self) -> Result<Vec<u8>> {
        self.public()?;
        if [self.genesis, self.fingerprint, self.owner].contains(&[0; 32]) {
            return Err(Error::InvalidCounter);
        }
        if !self.envelope.preconditions.is_empty() {
            return Err(Error::Codec);
        }
        let (lot, sequence) = self.action.target();
        if sequence == 0 {
            return Err(Error::StaleSequence);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(BODY_VERSION)
            .unwrap()
            .u8(self.action.kind())
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap();
        self.envelope.encode(&mut e).map_err(Error::Envelope)?;
        e.bytes(&self.owner)
            .unwrap()
            .bytes(&self.authorizer)
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(&lot)
            .unwrap()
            .u64(sequence)
            .unwrap();
        Ok(e.into_writer())
    }
    /// What the authorizer signs, under which domain (the unsigned body itself).
    pub fn signing_intent(&self) -> Result<CommandSigningIntent> {
        Ok(CommandSigningIntent {
            domain: self.action.domain(),
            payload: self.body()?,
        })
    }
    pub fn sign(&mut self, key: &HybridKey) -> Result<()> {
        if key.public() != &self.public()? {
            return Err(Error::BadSignature);
        }
        self.signature = key
            .sign(self.action.domain(), &self.body()?)
            .map_err(|_| Error::BadSignature)?;
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(self.action.kind())
            .unwrap()
            .bytes(&self.body()?)
            .unwrap()
            .bytes(&self.signature.ed448)
            .unwrap()
            .bytes(&self.signature.fndsa)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_OPERATION {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_OPERATION)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 5)?;
        if d.u8().map_err(|_| Error::Codec)? != 2 {
            return Err(Error::Codec);
        }
        let kind = d.u8().map_err(|_| Error::Codec)?;
        let body = d.bytes().map_err(|_| Error::Codec)?;
        let signature = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        // The walker does not recurse into the body's byte string: check it separately.
        crate::blocks::canonical(body, MAX_OPERATION)?;
        let mut b = Decoder::new(body);
        array(&mut b, 9)?;
        if b.u8().map_err(|_| Error::Codec)? != BODY_VERSION
            || b.u8().map_err(|_| Error::Codec)? != kind
            || b.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let genesis = fixed(&mut b)?;
        let fingerprint = fixed(&mut b)?;
        let envelope = Envelope::decode(&mut b).map_err(Error::Envelope)?;
        if !envelope.preconditions.is_empty() {
            return Err(Error::Codec);
        }
        let owner = fixed(&mut b)?;
        let authorizer = b.bytes().map_err(|_| Error::Codec)?.to_vec();
        array(&mut b, 2)?;
        let lot = fixed(&mut b)?;
        let sequence = b.u64().map_err(|_| Error::Codec)?;
        let action = match kind {
            19 => Action::Unbond { lot, sequence },
            20 => Action::Withdraw { lot, sequence },
            _ => return Err(Error::WrongOperation),
        };
        let op = Self {
            genesis,
            fingerprint,
            envelope,
            owner,
            authorizer,
            action,
            signature,
        };
        if d.position() != raw.len()
            || b.position() != body.len()
            || op.encode() != Ok(raw.to_vec())
        {
            return Err(Error::NonCanonical);
        }
        Ok(op)
    }
    /// Command identity over the unsigned body (signatures excluded).
    pub fn id(&self) -> Result<Hash> {
        Ok(domain_hash(COMMAND_ID_DOMAIN, &self.body()?))
    }
    pub fn payout_id(&self) -> Result<Hash> {
        if !matches!(self.action, Action::Withdraw { .. }) {
            return Err(Error::WrongOperation);
        }
        Ok(domain_hash(PAYOUT_DOMAIN, &self.body()?))
    }
    /// AM-1(d): the STATELESS check: the canonical encoding and the authorizer's signature over
    /// the body under the command's own domain. A pool may cache a success per id and wire hash.
    pub fn verify_signatures(&self) -> Result<()> {
        self.encode()?;
        self.public()?
            .verify(self.action.domain(), &self.body()?, &self.signature)
            .map_err(|_| Error::BadSignature)
    }
    /// Context, window and finalized reference at `parent.height + 1`, and current owner
    /// authority from the parent WalletBook.
    fn verify_context(
        &self,
        parent: &FinalizedAnchor,
        history: &History,
        wallets: &WalletBook,
    ) -> Result<()> {
        self.encode()?;
        parent.validate_context(self.genesis, self.fingerprint)?;
        self.envelope
            .check_inclusion(parent, history)
            .map_err(Error::Envelope)?;
        wallets.authorize(self.owner, &self.authorizer)
    }
    /// Economics preflight against the PARENT lot at the ACTUAL inclusion height
    /// `parent.height + 1`; never a signed height. No payout is performed here.
    fn verify_lot(&self, parent: &FinalizedAnchor, lot: &Lot) -> Result<()> {
        let height = parent.height.checked_add(1).ok_or(Error::Overflow)?;
        let (id, sequence) = self.action.target();
        if id != lot.0.id || self.owner != lot.0.owner {
            return Err(Error::WrongAnchor);
        }
        let mut check = lot.clone();
        if matches!(self.action, Action::Unbond { .. }) {
            check.start_unbond(height, sequence)?;
        } else {
            check.withdraw(height, sequence)?;
        }
        Ok(())
    }
    /// AM-1(d): every STATE-dependent check (context, envelope, owner authority, lot, economics)
    /// against authenticated parent components. No signature is verified here.
    pub fn verify_state(
        &self,
        parent: &FinalizedAnchor,
        history: &History,
        wallets: &WalletBook,
        lot: &Lot,
    ) -> Result<()> {
        self.verify_context(parent, history, wallets)?;
        self.verify_lot(parent, lot)
    }
    /// The complete preflight against the parent, including when same-block evidence
    /// subsequently burns the lot: `verify_state` with the signature checked after the cheap
    /// context checks. No payout is performed here.
    pub fn verify_command(
        &self,
        parent: &FinalizedAnchor,
        history: &History,
        wallets: &WalletBook,
        lot: &Lot,
    ) -> Result<()> {
        self.verify_context(parent, history, wallets)?;
        self.verify_signatures()?;
        self.verify_lot(parent, lot)
    }
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array().map_err(|_| Error::Codec)? != Some(n) {
        return Err(Error::Codec);
    }
    Ok(())
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()
        .map_err(|_| Error::Codec)?
        .try_into()
        .map_err(|_| Error::Codec)
}
/// The read-only envelope of a version-3 command (`op_envelope_v1::operation_envelope`, design
/// 1.a.3). None for anything else or anything malformed; execution rejects a malformed item.
pub fn envelope_of(raw: &[u8]) -> Option<Envelope> {
    let mut d = Decoder::new(raw);
    if d.array().ok()? != Some(5) || d.u8().ok()? != 2 || !matches!(d.u8().ok()?, 19 | 20) {
        return None;
    }
    let body = d.bytes().ok()?;
    let mut b = Decoder::new(body);
    if b.array().ok()? != Some(9) || b.u8().ok()? != BODY_VERSION {
        return None;
    }
    crate::op_envelope_v1::envelope_at(body, 5)
}

/// The execution outcome of one settled command (AM-5): the operation index records it and the
/// withdrawal payout coin exists only for `Applied`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum CommandOutcome {
    /// The command changed its lot (notice recorded, or withdrawal paid out).
    Applied = 1,
    /// The command was valid against the parent lot, but same-block evidence burned the lot
    /// first, so it had no effect and no payout exists.
    NoEffectBurned = 2,
}
impl CommandOutcome {
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// Partial economic result, deliberately not State or Execution. The complete
/// lifecycle executor must also revoke these lineages, clear freshness/pending
/// controls, and refresh Q before constructing any candidate StateRoot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSettlement {
    pub bonds: crate::bonds_v2::Book,
    pub penalties: crate::penalties_v2::Book,
    pub payouts: std::collections::BTreeMap<OutPoint, crate::transactions::Coin>,
    pub burned: u128,
    pub revoked: std::collections::BTreeSet<Hash>,
    /// One outcome per settled command, keyed by command id (unique within a valid block).
    pub outcomes: std::collections::BTreeMap<Hash, CommandOutcome>,
}
/// Pure settlement over authenticated parent components. Evidence must have
/// been validated against independently authenticated historical authority.
/// Deposits are intentionally not accepted by this command-only component.
/// `history` supplies the canonical block hashes of envelope references older than the parent.
pub fn settle_commands(
    parent: &FinalizedAnchor,
    history: &History,
    wallets: &WalletBook,
    bonds: &crate::bonds_v2::Book,
    penalties: &crate::penalties_v2::Book,
    commands: &[Operation],
    evidence: &[crate::penalties_v2::Settlement],
) -> Result<CommandSettlement> {
    if commands
        .len()
        .checked_add(evidence.len())
        .is_none_or(|n| n > 4096)
    {
        return Err(Error::Capacity);
    }
    bonds.validate_at_height(parent.height)?;
    penalties.validate_at_parent(parent)?;
    let height = parent.height.checked_add(1).ok_or(Error::Overflow)?;
    let mut out = CommandSettlement {
        bonds: bonds.clone(),
        penalties: penalties.clone(),
        payouts: Default::default(),
        burned: 0,
        revoked: Default::default(),
        outcomes: Default::default(),
    };
    // This ordering is fixed independently of operation arrival/body ordering.
    for proof in evidence {
        if proof.inclusion_height() != height || proof.inclusion_parent() != parent.id() {
            return Err(Error::WrongAnchor);
        }
        out.penalties.insert(proof.clone())?;
        out.revoked.insert(proof.lineage());
        out.burned = out
            .burned
            .checked_add(out.bonds.burn_exposed(
                proof.lineage(),
                proof.offense_height(),
                height,
                proof.id(),
            )?)
            .ok_or(Error::Overflow)?;
    }
    let mut seen = std::collections::BTreeSet::new();
    for command in commands {
        let (id, sequence) = command.action.target();
        if !seen.insert(id) {
            return Err(Error::Duplicate);
        }
        command.verify_command(
            parent,
            history,
            wallets,
            bonds.lots.get(&id).ok_or(Error::WrongAnchor)?,
        )?;
        let lot = out.bonds.lots.get_mut(&id).ok_or(Error::WrongAnchor)?;
        let outcome = if lot.0.status == crate::bonds::LotStatus::Burned {
            CommandOutcome::NoEffectBurned
        } else if matches!(command.action, Action::Unbond { .. }) {
            lot.start_unbond(height, sequence)?;
            CommandOutcome::Applied
        } else {
            let atoms = lot.withdraw(height, sequence)?;
            let point = OutPoint {
                transaction: command.payout_id()?,
                index: 0,
            };
            let coin = crate::transactions::Coin {
                output: crate::transactions::Output {
                    owner: lot.0.owner,
                    atoms,
                },
                created_height: height,
                coinbase: false,
            };
            if out.payouts.insert(point, coin).is_some() {
                return Err(Error::Duplicate);
            }
            CommandOutcome::Applied
        };
        if out.outcomes.insert(command.id()?, outcome).is_some() {
            return Err(Error::Duplicate);
        }
    }
    out.bonds.records()?;
    out.penalties.records()?;
    Ok(out)
}
