//! Restricted raw-key access and typed signing capabilities (Order W4).
//!
//! # The boundary
//!
//! A wallet private key (crypto-v2 `HybridKey`) is held only by the signers that a host builds
//! behind a `SigningGate`, [`KeySigner`](crate::authorize::KeySigner) and
//! [`RotationSigner`](crate::ops::rotation::RotationSigner), and each holds it SEALED: inside a
//! `SealedKey` whose key field is private to this module. No function anywhere returns a key, a
//! reference to one, or a signature over caller-chosen bytes. The only code that reaches the key is
//! the signing function of a typed capability below, and each of those signs exactly one kind of
//! consensus object, built by the consensus-owned builder of that object, under the domain consensus
//! uses for it:
//!
//! | Capability | Operation kinds | Signs | Through (consensus-owned) | Domain |
//! |---|---|---|---|---|
//! | [`TransferSpend`] | Payment, WalletRotation | payment input or exact tag-25 sponsor funding | `Transfer::sign_input` / `PartialRotation::sign` | `Transaction` |
//! | [`BondAuthorization`] | BondCreate, BondUnbond, BondWithdraw | both inseparable kind-24 signatures, or an envelope command | `FundedBondCreate::sign` / `Operation::sign` | `BondCreate` + `Transaction` / `BondUnbond` / `BondWithdraw` |
//! | [`ClaimAuthorization`] | DividendClaim | a `dividend_claim_v1::SignedClaim` | `SignedClaim::sign` | `Transaction` |
//! | [`TradeApproval`] | LicenseDvp, HashLock, ConditionalClaim, ConditionalRefund, FiatLock, FiatRelease, TreasuryRotate | one approval slot of a `trading_v1::Operation` whose action is of that kind | `Operation::signing_payload` | `Transaction` |
//! | [`RotationProofs`] | WalletRotation | authorization, new-key possession and old-key funding of the same tag-25 body | `PartialRotation::sign` | `WalletRotate`, `WalletRotatePossession`, `Transaction` |
//! | [`MakerOfferAuthorization`] | MakerOffer | the canonical wallet-owner maker offer | `MakerOffer::sign` | `TradeOffer` |
//! | [`MakerFillAuthorization`] | LicenseDvp, HashLock, FiatLock | exact canonical offer and operation body | `OfferProof::sign` | `TradeFill` |
//! | [`WorkerAssignmentAuthorization`] | WorkerAssignment | exact current-owner enrollment binding after Worker possession | existing `Binding::bytes` | `MinerEnrollment` |
//! | [`TreasuryFreeze`] | TreasuryFreezeOffer | a Treasury freeze body (`ops::treasury::FreezeBody`) | the wallet's strict mirror of consensus' private `TreasuryFreezeBody` (see below) | `Transaction` |
//!
//! [`capabilities`] is this table's first two columns (total over every kind, exact, pinned by a unit
//! test), and every capability is granted only after [`domain_for`] permits each purpose it signs
//! for, so the two tables cannot disagree (the unit test proves that the purposes the capabilities
//! use are exactly the 22 pairs `domain_for` permits). Where this module itself chooses the domain
//! (a trading approval, a Treasury freeze) it takes the one `domain_for` returns; everywhere else the
//! consensus routine chooses it, and the capability first checks that the object is of its own kind.
//!
//! The freeze is the one row whose payload is not built by a consensus builder at signing time:
//! consensus keeps its freeze body type private, and its public `prepare_treasury_offer` needs the
//! maker's signed offer, which a freeze plan does not keep (it holds the body only). The capability
//! therefore takes the wallet's typed, strictly decoded mirror of that body; the planner checked
//! that consensus' `prepare_treasury_offer` produced exactly these bytes at the creation head, and
//! the handler verifies the signed result through consensus' `FrozenTreasuryOffer::decode`. A public
//! consensus constructor of the body (or a plan that keeps the maker's offer) would close the gap; it
//! belongs with the Treasury authority work of stage 2 (W18).
//!
//! A handler is LENT a `&KindSigner` for one operation kind by `authorize::run_authorization`, after
//! the gate, the approval, the head, the identity, the plan binding and the per-slot authority were
//! checked. Everything reachable from that reference is either PUBLIC (the typed capability getters,
//! their signing functions, the public keys) or PRIVATE to this module (the key ring, the sealed
//! keys). Nothing reachable from it is `pub(crate)`, so a handler module (`ops::*`) has EXACTLY the
//! access an outside crate has, and the compile-fail examples below are evidence for the handler
//! modules as well as for a host. (The constructors `KindSigner::new`, `KeyRing::single`,
//! `KeyRing::pair` and `SealedKey::seal` are crate-private; they need a sealed key or a `HybridKey`,
//! which no handler module holds: `tests/build_independence.rs` pins that `HybridKey` appears in the
//! non-test code of `capability.rs`, `authorize.rs` and `rotation_signer.rs` only.)
//!
//! The text tripwire `build/check-signing-calls.pl` remains as an additional regression check: it
//! permits raw signing calls (`HybridKey::sign`, `Transfer::sign_input`, `Operation::sign`,
//! `SignedClaim::sign`, `Rotation::sign`) in the signing functions of this module only.
//!
//! What this does NOT do: it does not protect a key from the host process that holds it (that
//! process created the key and can sign without this crate; the boundary against it is the process,
//! the vault and the platform), and it does not make a handler's choice of WHAT to sign correct (the
//! approval binding and the independent verification in `run_authorization` do that).
//!
//! # Compile-time evidence
//!
//! On this toolchain rustdoc does not enforce the error code written after `compile_fail`, so every
//! `compile_fail` example is paired with a `no_run` example that is IDENTICAL except for the one
//! marked line: the pair shows that the marked line, and nothing else, does not compile.
//!
//! A handler-shaped function, holding what a handler is lent, compiles while it asks only for typed
//! capabilities and public keys:
//!
//! ```no_run
//! use mutiny_wallet_core_v8::capability::{KeySlot, KindSigner};
//! fn handler(signer: &KindSigner<'_>) {
//!     let _ = signer.kind();
//!     let _ = signer.public(KeySlot::Primary);
//!     let _ = signer.transfer_spend(KeySlot::Primary);
//!     let _ = signer.trade_approval();
//! }
//! ```
//!
//! It cannot obtain the raw key (the accessor `key` that handlers had before W4 is gone):
//!
//! ```compile_fail,E0599
//! use mutiny_wallet_core_v8::capability::{KeySlot, KindSigner};
//! fn handler(signer: &KindSigner<'_>) {
//!     let _ = signer.kind();
//!     let _ = signer.public(KeySlot::Primary);
//!     let _ = signer.transfer_spend(KeySlot::Primary);
//!     let _ = signer.trade_approval();
//!     let _ = signer.key(KeySlot::Primary, mutiny_wallet_core_v8::Purpose::Spend); // MARKED
//! }
//! ```
//!
//! It cannot sign caller-chosen bytes (the method `sign(slot, purpose, payload)` is gone):
//!
//! ```compile_fail,E0599
//! use mutiny_wallet_core_v8::capability::{KeySlot, KindSigner};
//! fn handler(signer: &KindSigner<'_>) {
//!     let _ = signer.kind();
//!     let _ = signer.public(KeySlot::Primary);
//!     let _ = signer.transfer_spend(KeySlot::Primary);
//!     let _ = signer.trade_approval();
//!     let _ = signer.sign(KeySlot::Primary, mutiny_wallet_core_v8::Purpose::Spend, b"any bytes"); // MARKED
//! }
//! ```
//!
//! It cannot reach the key ring (a private field: E0616):
//!
//! ```compile_fail,E0616
//! use mutiny_wallet_core_v8::capability::{KeySlot, KindSigner};
//! fn handler(signer: &KindSigner<'_>) {
//!     let _ = signer.kind();
//!     let _ = signer.public(KeySlot::Primary);
//!     let _ = signer.transfer_spend(KeySlot::Primary);
//!     let _ = signer.trade_approval();
//!     let _ = &signer.ring; // MARKED
//! }
//! ```
//!
//! A typed capability signs its consensus object and nothing else; it has no key to hand out and no
//! function over raw bytes. The positive pair:
//!
//! ```no_run
//! use mutiny_consensus_v8::{trading_v1::Operation, transactions_v2::Transfer};
//! use mutiny_wallet_core_v8::{SignerIdentity, capability::{KeySlot, KindSigner}};
//! fn handler(signer: &KindSigner<'_>, transfer: &mut Transfer, op: &Operation, me: &SignerIdentity) {
//!     let spend = signer.transfer_spend(KeySlot::Primary).unwrap();
//!     let _ = spend.authorize_input(transfer, 0);
//!     let approve = signer.trade_approval().unwrap();
//!     let _ = approve.approve_slot(op, 0, me);
//! }
//! ```
//!
//! and the same with a raw-bytes call on the capability (E0599):
//!
//! ```compile_fail,E0599
//! use mutiny_consensus_v8::{trading_v1::Operation, transactions_v2::Transfer};
//! use mutiny_wallet_core_v8::{SignerIdentity, capability::{KeySlot, KindSigner}};
//! fn handler(signer: &KindSigner<'_>, transfer: &mut Transfer, op: &Operation, me: &SignerIdentity) {
//!     let spend = signer.transfer_spend(KeySlot::Primary).unwrap();
//!     let _ = spend.authorize_input(transfer, 0);
//!     let approve = signer.trade_approval().unwrap();
//!     let _ = approve.approve_slot(op, 0, me);
//!     let _ = approve.sign(b"any bytes"); // MARKED
//! }
//! ```
//!
//! or a reach for its key (a private field: E0616):
//!
//! ```compile_fail,E0616
//! use mutiny_consensus_v8::{trading_v1::Operation, transactions_v2::Transfer};
//! use mutiny_wallet_core_v8::{SignerIdentity, capability::{KeySlot, KindSigner}};
//! fn handler(signer: &KindSigner<'_>, transfer: &mut Transfer, op: &Operation, me: &SignerIdentity) {
//!     let spend = signer.transfer_spend(KeySlot::Primary).unwrap();
//!     let _ = spend.authorize_input(transfer, 0);
//!     let approve = signer.trade_approval().unwrap();
//!     let _ = approve.approve_slot(op, 0, me);
//!     let _ = &spend.key; // MARKED
//! }
//! ```
//!
//! A host holds a `KeySigner`; it can lock it and ask for its identity, never for its key:
//!
//! ```no_run
//! use mutiny_wallet_core_v8::{KeySigner, Signer};
//! fn host(signer: &KeySigner) {
//!     let _ = signer.identity();
//!     signer.lock();
//! }
//! ```
//!
//! ```compile_fail,E0599
//! use mutiny_wallet_core_v8::{KeySigner, Signer};
//! fn host(signer: &KeySigner) {
//!     let _ = signer.identity();
//!     signer.lock();
//!     let _ = signer.key(); // MARKED
//! }
//! ```
//!
//! ```compile_fail,E0616
//! use mutiny_wallet_core_v8::{KeySigner, Signer};
//! fn host(signer: &KeySigner) {
//!     let _ = signer.identity();
//!     signer.lock();
//!     let _ = &signer.state; // MARKED
//! }
//! ```
//!
//! A host cannot build the handlers' signer from a key it holds (the constructor is crate-private):
//!
//! ```compile_fail,E0624
//! use mutiny_wallet_core_v8::{KeySigner, OperationKind, Signer, capability::KindSigner};
//! fn host(signer: &KeySigner) {
//!     let _ = signer.identity();
//!     signer.lock();
//!     let _ = KindSigner::new(OperationKind::Payment, todo!()); // MARKED
//! }
//! ```
//!
//! Order W9 (`SignerIdentity::with_profile`, since the independent wallet review
//! `with_treasury_roles`, is crate-private): a host builds an ORDINARY identity and cannot label it
//! Treasury; only `profile::declare` gives the Treasury profile, after checking every role against
//! the verified chain. The positive pair:
//!
//! ```no_run
//! use mutiny_wallet_core_v8::{SignerIdentity, TreasuryRoles};
//! fn host(identity: SignerIdentity, roles: TreasuryRoles) {
//!     let _ = identity.treasury_roles();
//!     let _ = roles.any();
//!     let _ = identity.profile();
//! }
//! ```
//!
//! and the labelling call (E0624):
//!
//! ```compile_fail,E0624
//! use mutiny_wallet_core_v8::{SignerIdentity, TreasuryRoles};
//! fn host(identity: SignerIdentity, roles: TreasuryRoles) {
//!     let _ = identity.treasury_roles();
//!     let _ = roles.any();
//!     let _ = identity.clone().with_treasury_roles(roles).profile(); // MARKED
//! }
//! ```
use crate::{
    authorize::{Purpose, SignerIdentity, domain_for},
    ops::treasury::FreezeBody,
    plan::{OperationKind, Slot},
    refusal::Refusal,
};
use mutiny_consensus_v8::{
    bond_ops_v2::{Action as BondAction, Operation as BondOperation},
    dividend_claim_v1::{ClaimError, SignedClaim},
    trading_v1::{Action as TradeAction, Operation as TradeOperation},
    transactions::TxError,
    transactions_v2::Transfer,
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey};

// ---------------------------------------------------------------------------------------------
// The sealed key and the key ring (crate-private constructors, module-private contents)
// ---------------------------------------------------------------------------------------------

/// A wallet private key, sealed: only this module can reach the key, and only to sign through a
/// typed capability. Erased on drop (crypto-v2's key zeroizes itself).
pub(crate) struct SealedKey {
    key: HybridKey,
}

impl SealedKey {
    /// Seal a key a host handed to a signer constructor.
    pub(crate) fn seal(key: HybridKey) -> Self {
        Self { key }
    }
    /// The public key (public data).
    pub(crate) fn public(&self) -> &PublicKey {
        self.key.public()
    }
}

/// Which of the sealed keys an operation wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySlot {
    /// The signing wallet's key.
    Primary,
    /// A second key: the NEW key of a wallet rotation.
    Secondary,
}

/// The sealed keys of one authorization.
pub(crate) struct KeyRing<'k> {
    primary: &'k SealedKey,
    secondary: Option<&'k SealedKey>,
}

impl<'k> KeyRing<'k> {
    pub(crate) fn single(primary: &'k SealedKey) -> Self {
        Self {
            primary,
            secondary: None,
        }
    }
    pub(crate) fn pair(primary: &'k SealedKey, secondary: &'k SealedKey) -> Self {
        Self {
            primary,
            secondary: Some(secondary),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The capability table
// ---------------------------------------------------------------------------------------------

/// A typed signing capability (see the module table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Capability {
    TransferSpend,
    BondAuthorization,
    ClaimAuthorization,
    TradeApproval,
    RotationProofs,
    TreasuryFreeze,
    MakerOfferAuthorization,
    MakerFillAuthorization,
    WorkerAssignmentAuthorization,
}

impl Capability {
    /// Every capability.
    pub const ALL: [Capability; 9] = [
        Capability::TransferSpend,
        Capability::BondAuthorization,
        Capability::ClaimAuthorization,
        Capability::TradeApproval,
        Capability::RotationProofs,
        Capability::TreasuryFreeze,
        Capability::MakerOfferAuthorization,
        Capability::MakerFillAuthorization,
        Capability::WorkerAssignmentAuthorization,
    ];

    /// The signing purposes the capability signs for; through [`domain_for`] they name its domains.
    pub fn purposes(self) -> &'static [Purpose] {
        match self {
            Self::TransferSpend
            | Self::ClaimAuthorization
            | Self::TradeApproval
            | Self::TreasuryFreeze => &[Purpose::Spend],
            Self::BondAuthorization => &[Purpose::BondAction],
            Self::WorkerAssignmentAuthorization => &[Purpose::WorkerAssignment],
            Self::MakerOfferAuthorization => &[Purpose::MakerOffer],
            Self::MakerFillAuthorization => &[Purpose::MakerFill],
            Self::RotationProofs => &[Purpose::RotateAuthorization, Purpose::RotatePossession],
        }
    }
}

/// The capabilities an operation kind may obtain. Total over every kind and exact (unit test
/// `the_capability_table_is_total_exact_and_agrees_with_domain_for`).
pub fn capabilities(kind: OperationKind) -> &'static [Capability] {
    use Capability as C;
    use OperationKind as K;
    match kind {
        K::Payment => &[C::TransferSpend],
        K::WalletRotation => &[C::TransferSpend, C::RotationProofs],
        K::DividendClaim => &[C::ClaimAuthorization],
        K::LicenseDvp | K::HashLock | K::FiatLock => &[C::TradeApproval, C::MakerFillAuthorization],
        K::ConditionalClaim | K::ConditionalRefund | K::FiatRelease | K::TreasuryRotate => {
            &[C::TradeApproval]
        }
        K::BondCreate => &[C::BondAuthorization],
        K::BondUnbond | K::BondWithdraw => &[C::BondAuthorization],
        K::TreasuryFreezeOffer => &[C::TreasuryFreeze],
        K::MakerOffer => &[C::MakerOfferAuthorization],
        K::WorkerAssignment => &[C::WorkerAssignmentAuthorization],
    }
}

/// The operation kind of a trading action (every action is one kind's).
fn trade_kind(action: &TradeAction) -> OperationKind {
    match action {
        TradeAction::HashLock { .. } => OperationKind::HashLock,
        TradeAction::Claim { .. } => OperationKind::ConditionalClaim,
        TradeAction::Refund { .. } => OperationKind::ConditionalRefund,
        TradeAction::LicenseDvp { .. } => OperationKind::LicenseDvp,
        TradeAction::FiatLock { .. } => OperationKind::FiatLock,
        TradeAction::FiatRelease { .. } => OperationKind::FiatRelease,
        TradeAction::TreasuryRotate { .. } => OperationKind::TreasuryRotate,
    }
}

/// The operation kind of a bond action.
fn bond_kind(action: &BondAction) -> OperationKind {
    match action {
        BondAction::Unbond { .. } => OperationKind::BondUnbond,
        BondAction::Withdraw { .. } => OperationKind::BondWithdraw,
    }
}

// ---------------------------------------------------------------------------------------------
// What a handler is lent
// ---------------------------------------------------------------------------------------------

/// What an operation handler signs with: the sealed keys of one authorization, for one operation
/// kind. Built only by `authorize::run_authorization`; it hands out typed capabilities, never a
/// key and never a signature over bytes.
pub struct KindSigner<'k> {
    kind: OperationKind,
    ring: KeyRing<'k>,
}

impl<'k> KindSigner<'k> {
    pub(crate) fn new(kind: OperationKind, ring: KeyRing<'k>) -> Self {
        Self { kind, ring }
    }

    /// The operation kind this signer was lent for.
    pub fn kind(&self) -> OperationKind {
        self.kind
    }

    /// The public key of a slot (public data).
    pub fn public(&self, slot: KeySlot) -> Result<&'k PublicKey, Refusal> {
        Ok(self.pick(slot)?.public())
    }

    fn pick(&self, slot: KeySlot) -> Result<&'k SealedKey, Refusal> {
        match slot {
            KeySlot::Primary => Ok(self.ring.primary),
            KeySlot::Secondary => self.ring.secondary.ok_or(Refusal::SigningFailed),
        }
    }

    /// Grant `capability` to this kind: it must be in the kind's row of [`capabilities`] and
    /// [`domain_for`] must permit every purpose it signs for. Returns the domain of its first
    /// purpose (the one this module uses where it chooses the domain itself).
    fn grant(&self, capability: Capability) -> Result<Domain, Refusal> {
        if !capabilities(self.kind).contains(&capability) {
            return Err(Refusal::CapabilityNotPermitted {
                kind: self.kind,
                capability,
            });
        }
        let mut first = None;
        for purpose in capability.purposes() {
            let domain = domain_for(self.kind, *purpose)?;
            first.get_or_insert(domain);
        }
        first.ok_or(Refusal::CapabilityNotPermitted {
            kind: self.kind,
            capability,
        })
    }

    /// Sign transfer inputs with the key of `slot` (through consensus' `Transfer::sign_input`).
    pub fn transfer_spend(&self, slot: KeySlot) -> Result<TransferSpend<'k>, Refusal> {
        self.grant(Capability::TransferSpend)?;
        Ok(TransferSpend {
            kind: self.kind,
            key: self.pick(slot)?,
        })
    }

    pub fn worker_assignment_authorization(
        &self,
    ) -> Result<WorkerAssignmentAuthorization<'k>, Refusal> {
        let domain = self.grant(Capability::WorkerAssignmentAuthorization)?;
        Ok(WorkerAssignmentAuthorization {
            key: self.ring.primary,
            domain,
        })
    }
    pub fn maker_offer_authorization(&self) -> Result<MakerOfferAuthorization<'k>, Refusal> {
        self.grant(Capability::MakerOfferAuthorization)?;
        Ok(MakerOfferAuthorization {
            key: self.pick(KeySlot::Primary)?,
        })
    }
    pub fn maker_fill_authorization(&self) -> Result<MakerFillAuthorization<'k>, Refusal> {
        self.grant(Capability::MakerFillAuthorization)?;
        Ok(MakerFillAuthorization {
            kind: self.kind,
            key: self.pick(KeySlot::Primary)?,
        })
    }
    /// Sign the owner authorization of a bond operation of this kind.
    pub fn bond_authorization(&self) -> Result<BondAuthorization<'k>, Refusal> {
        self.grant(Capability::BondAuthorization)?;
        Ok(BondAuthorization {
            kind: self.kind,
            key: self.pick(KeySlot::Primary)?,
        })
    }

    /// Sign a dividend claim.
    pub fn claim_authorization(&self) -> Result<ClaimAuthorization<'k>, Refusal> {
        self.grant(Capability::ClaimAuthorization)?;
        Ok(ClaimAuthorization {
            key: self.pick(KeySlot::Primary)?,
        })
    }

    /// Sign approval slots of a trading operation of this kind.
    pub fn trade_approval(&self) -> Result<TradeApproval<'k>, Refusal> {
        let domain = self.grant(Capability::TradeApproval)?;
        Ok(TradeApproval {
            kind: self.kind,
            domain,
            key: self.pick(KeySlot::Primary)?,
        })
    }

    /// Sign both proofs of a wallet rotation (the current key and the new key).
    pub fn rotation_proofs(&self) -> Result<RotationProofs<'k>, Refusal> {
        self.grant(Capability::RotationProofs)?;
        Ok(RotationProofs {
            current: self.pick(KeySlot::Primary)?,
            proposed: self
                .ring
                .secondary
                .ok_or(Refusal::NotRequiredSigner(Slot::RotationPossession))?,
        })
    }

    /// Sign the freeze of a Treasury offer.
    pub fn treasury_freeze(&self) -> Result<TreasuryFreeze<'k>, Refusal> {
        let domain = self.grant(Capability::TreasuryFreeze)?;
        Ok(TreasuryFreeze {
            domain,
            key: self.pick(KeySlot::Primary)?,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// The typed capabilities
// ---------------------------------------------------------------------------------------------

/// Signs inputs of a `transactions_v2::Transfer`, and nothing else.
pub struct TransferSpend<'k> {
    kind: OperationKind,
    key: &'k SealedKey,
}

impl TransferSpend<'_> {
    /// Sponsor funding commits the exact canonical rotation body under its registered domain.
    pub fn authorize_rotation_funding(
        &self,
        partial: &mut mutiny_consensus_v8::funded_rotation_v2::PartialRotation,
    ) -> Result<(), Refusal> {
        if self.kind != OperationKind::WalletRotation {
            return Err(Refusal::CapabilityNotPermitted {
                kind: self.kind,
                capability: Capability::TransferSpend,
            });
        }
        domain_for(self.kind, Purpose::Spend)?;
        partial
            .sign(
                mutiny_consensus_v8::funded_rotation_v2::Slot::SponsorFunding,
                &self.key.key,
            )
            .map_err(|_| Refusal::SigningFailed)
    }
    /// Sign input `index` through consensus' own `Transfer::sign_input`, which builds the input's
    /// signing payload and selects `Domain::Transaction` itself (and refuses an input whose
    /// descriptor is not this key's: `TxError::Owner`).
    pub fn authorize_input(&self, transfer: &mut Transfer, index: usize) -> Result<(), TxError> {
        if self.kind != OperationKind::Payment {
            return Err(TxError::Owner);
        }
        transfer.sign_input(index, &self.key.key)
    }
}

/// Signs a bond operation whose action is of one kind, and nothing else.
pub struct BondAuthorization<'k> {
    kind: OperationKind,
    key: &'k SealedKey,
}

impl BondAuthorization<'_> {
    /// Sign both inseparable authorizations of the canonical kind-24 body.
    pub fn authorize_funded_bond(
        &self,
        unsigned: mutiny_consensus_v8::bond_create_v3::UnsignedBondCreate,
    ) -> Result<mutiny_consensus_v8::bond_create_v3::FundedBondCreate, Refusal> {
        if self.kind != OperationKind::BondCreate {
            return Err(Refusal::SigningFailed);
        }
        domain_for(self.kind, Purpose::Spend)?;
        mutiny_consensus_v8::bond_create_v3::FundedBondCreate::sign(unsigned, &self.key.key)
            .map_err(|_| Refusal::SigningFailed)
    }
    /// Sign `op` through consensus' own `Operation::sign` (its body, under the domain of its
    /// action). Refused unless the action is of this capability's kind.
    pub fn authorize_bond(&self, op: &mut BondOperation) -> Result<(), Refusal> {
        if bond_kind(&op.action) != self.kind {
            return Err(Refusal::CapabilityNotPermitted {
                kind: self.kind,
                capability: Capability::BondAuthorization,
            });
        }
        op.sign(&self.key.key).map_err(|_| Refusal::SigningFailed)
    }
}

/// Current owner authorization of the existing kind-10 assignment. Worker possession is
/// verified before reaching the private key; no caller-selected payload or domain is accepted.
pub struct WorkerAssignmentAuthorization<'k> {
    key: &'k SealedKey,
    domain: Domain,
}
impl WorkerAssignmentAuthorization<'_> {
    pub fn authorize_assignment(
        &self,
        mut assignment: mutiny_consensus_v8::license_assignment_v2::Assignment,
    ) -> Result<mutiny_consensus_v8::license_assignment_v2::Assignment, Refusal> {
        assignment
            .encode()
            .map_err(|_| Refusal::InvalidDescriptor)?;
        let (owner, generation) =
            mutiny_crypto_v2::PublicKey::decode_descriptor(&assignment.owner_descriptor)
                .map_err(|_| Refusal::InvalidDescriptor)?;
        if &owner != self.key.key.public()
            || generation != assignment.enrollment.binding.owner_generation
        {
            return Err(Refusal::InvalidDescriptor);
        }
        assignment
            .enrollment
            .binding
            .verify_worker_possession(&assignment.enrollment.worker_signature)
            .map_err(|_| Refusal::VerificationFailed("Worker possession signature"))?;
        assignment.enrollment.owner_signature = self
            .key
            .key
            .sign(
                self.domain,
                &assignment
                    .enrollment
                    .binding
                    .bytes()
                    .map_err(|_| Refusal::InvalidDescriptor)?,
            )
            .map_err(|_| Refusal::SigningFailed)?;
        assignment
            .verify_signatures()
            .map_err(|_| Refusal::VerificationFailed("Assignment signatures"))?;
        Ok(assignment)
    }
}
/// Signs the one canonical maker body; no caller-selected domain or payload.
pub struct MakerOfferAuthorization<'k> {
    key: &'k SealedKey,
}
impl MakerOfferAuthorization<'_> {
    pub fn authorize_offer(
        &self,
        body: mutiny_consensus_v8::trading_offer_v2::OfferBody,
    ) -> Result<mutiny_consensus_v8::trading_offer_v2::MakerOffer, Refusal> {
        mutiny_consensus_v8::trading_offer_v2::MakerOffer::sign(body, &self.key.key)
            .map_err(|_| Refusal::SigningFailed)
    }
}
/// Signs a fill witness only for the granted canonical trading action.
pub struct MakerFillAuthorization<'k> {
    kind: OperationKind,
    key: &'k SealedKey,
}
impl MakerFillAuthorization<'_> {
    pub fn authorize_fill(
        &self,
        op: &TradeOperation,
    ) -> Result<mutiny_consensus_v8::trading_offer_v2::OfferProof, Refusal> {
        if trade_kind(&op.action) != self.kind {
            return Err(Refusal::SigningFailed);
        }
        let offer = op
            .offer_proof
            .as_ref()
            .ok_or(Refusal::OfferProofInvalid)?
            .offer
            .clone();
        mutiny_consensus_v8::trading_offer_v2::OfferProof::sign(offer, op, &self.key.key)
            .map_err(|_| Refusal::SigningFailed)
    }
}
/// Signs a dividend claim, and nothing else.
pub struct ClaimAuthorization<'k> {
    key: &'k SealedKey,
}

impl ClaimAuthorization<'_> {
    /// Replace `claim` by the claim consensus' own `SignedClaim::sign` produces for its body and
    /// descriptor (the claim-intent payload under `Domain::Transaction`; refused unless the
    /// descriptor is this key's).
    pub fn authorize_claim(&self, claim: &mut SignedClaim) -> Result<(), Refusal> {
        let signed = SignedClaim::sign(claim.body.clone(), claim.descriptor.clone(), &self.key.key)
            .map_err(|error| match error {
                ClaimError::StaleOwner => Refusal::NotRequiredSigner(Slot::Claim),
                _ => Refusal::SigningFailed,
            })?;
        *claim = signed;
        Ok(())
    }
}

/// Signs approval slots of a trading operation whose action is of one kind, and nothing else.
pub struct TradeApproval<'k> {
    kind: OperationKind,
    domain: Domain,
    key: &'k SealedKey,
}

impl TradeApproval<'_> {
    /// The approval of slot `slot` of `operation` by `signer`: the signature over consensus' own
    /// `Operation::signing_payload(slot, descriptor)` under the domain `domain_for` selects for the
    /// kind (`Domain::Transaction`, the domain consensus' `verify_approval` checks). Refused unless
    /// the action is of this capability's kind and `signer` is this key's identity.
    pub fn approve_slot(
        &self,
        operation: &TradeOperation,
        slot: u8,
        signer: &SignerIdentity,
    ) -> Result<HybridSignature, Refusal> {
        if trade_kind(&operation.action) != self.kind {
            return Err(Refusal::CapabilityNotPermitted {
                kind: self.kind,
                capability: Capability::TradeApproval,
            });
        }
        if &signer.public() != self.key.public() {
            return Err(Refusal::NotRequiredSigner(Slot::Approval(slot)));
        }
        let payload = operation
            .signing_payload(slot, signer.descriptor())
            .map_err(|_| Refusal::SigningFailed)?;
        self.key
            .key
            .sign(self.domain, &payload)
            .map_err(|_| Refusal::SigningFailed)
    }
}

/// Signs both proofs of a wallet rotation, and nothing else.
pub struct RotationProofs<'k> {
    current: &'k SealedKey,
    proposed: &'k SealedKey,
}

impl RotationProofs<'_> {
    /// Authorize the exact funded bundle, prove possession, and fund with the current key.
    pub fn authorize_funded_rotation(
        &self,
        partial: &mut mutiny_consensus_v8::funded_rotation_v2::PartialRotation,
    ) -> Result<(), Refusal> {
        use mutiny_consensus_v8::funded_rotation_v2::{Payer, Slot};
        let (_, current_generation) =
            PublicKey::decode_descriptor(&partial.unsigned.current_descriptor)
                .map_err(|_| Refusal::InvalidDescriptor)?;
        let (_, proposed_generation) =
            PublicKey::decode_descriptor(&partial.unsigned.proposed_descriptor)
                .map_err(|_| Refusal::InvalidDescriptor)?;
        if self
            .current
            .public()
            .descriptor(current_generation)
            .map_err(|_| Refusal::InvalidDescriptor)?
            != partial.unsigned.current_descriptor
        {
            return Err(Refusal::NotRequiredSigner(
                crate::plan::Slot::RotationAuthorization,
            ));
        }
        if self
            .proposed
            .public()
            .descriptor(proposed_generation)
            .map_err(|_| Refusal::InvalidDescriptor)?
            != partial.unsigned.proposed_descriptor
        {
            return Err(Refusal::NotRequiredSigner(
                crate::plan::Slot::RotationPossession,
            ));
        }
        partial
            .sign(Slot::Authorize, &self.current.key)
            .map_err(|_| Refusal::SigningFailed)?;
        partial
            .sign(Slot::Possession, &self.proposed.key)
            .map_err(|_| Refusal::SigningFailed)?;
        if partial.unsigned.pays(Payer::RotatingAuthority) {
            domain_for(OperationKind::WalletRotation, Purpose::Spend)?;
            partial
                .sign(Slot::AuthorityFunding, &self.current.key)
                .map_err(|_| Refusal::SigningFailed)?;
        }
        Ok(())
    }
}

/// Signs a Treasury freeze body, and nothing else.
pub struct TreasuryFreeze<'k> {
    domain: Domain,
    key: &'k SealedKey,
}

impl TreasuryFreeze<'_> {
    /// The freeze authorization: the signature over the canonical encoding of `body` (the wallet's
    /// strict mirror of consensus' `TreasuryFreezeBody`, see the module documentation) under the
    /// domain `domain_for` selects, `Domain::Transaction`, which consensus' frozen-offer check uses.
    pub fn authorize_freeze(&self, body: &FreezeBody) -> Result<HybridSignature, Refusal> {
        let payload = body.encode()?;
        self.key
            .key
            .sign(self.domain, &payload)
            .map_err(|_| Refusal::SigningFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_consensus_v8::{
        NETWORK_ID,
        trading_v1::{Context, Meta, Strikes},
    };
    use mutiny_crypto_v2::Role;

    fn key(phrase: &str) -> HybridKey {
        HybridKey::wallet_restore(phrase, Role::WalletOwner).unwrap()
    }

    /// Public TEST-VALUE keys: the all-"abandon" and all-"zoo" BIP-39 test phrases.
    fn abandon() -> SealedKey {
        SealedKey::seal(key(&format!("{}art", "abandon ".repeat(23))))
    }
    fn zoo() -> SealedKey {
        SealedKey::seal(key(&format!("{}vote", "zoo ".repeat(23))))
    }

    fn zero() -> HybridSignature {
        HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        }
    }

    #[test]
    fn the_capability_table_is_total_exact_and_agrees_with_domain_for() {
        use Capability as C;
        use OperationKind as K;
        let purposes = [
            Purpose::Spend,
            Purpose::BondAction,
            Purpose::RotateAuthorization,
            Purpose::RotatePossession,
            Purpose::MakerOffer,
            Purpose::MakerFill,
            Purpose::WorkerAssignment,
        ];
        let expected: [(K, &[C]); 16] = [
            (K::Payment, &[C::TransferSpend]),
            (K::WalletRotation, &[C::TransferSpend, C::RotationProofs]),
            (K::DividendClaim, &[C::ClaimAuthorization]),
            (
                K::LicenseDvp,
                &[C::TradeApproval, C::MakerFillAuthorization],
            ),
            (K::HashLock, &[C::TradeApproval, C::MakerFillAuthorization]),
            (K::ConditionalClaim, &[C::TradeApproval]),
            (K::ConditionalRefund, &[C::TradeApproval]),
            (K::FiatLock, &[C::TradeApproval, C::MakerFillAuthorization]),
            (K::FiatRelease, &[C::TradeApproval]),
            (K::BondCreate, &[C::BondAuthorization]),
            (K::BondUnbond, &[C::BondAuthorization]),
            (K::BondWithdraw, &[C::BondAuthorization]),
            (K::TreasuryRotate, &[C::TradeApproval]),
            (K::TreasuryFreezeOffer, &[C::TreasuryFreeze]),
            (K::MakerOffer, &[C::MakerOfferAuthorization]),
            (K::WorkerAssignment, &[C::WorkerAssignmentAuthorization]),
        ];
        assert_eq!(expected.len(), K::ALL.len());
        let mut pairs = 0;
        for (kind, row) in expected {
            assert_eq!(capabilities(kind), row, "{kind:?}");
            // The purposes the kind's capabilities sign for are exactly those domain_for permits.
            let used: Vec<Purpose> = purposes
                .into_iter()
                .filter(|purpose| {
                    (kind == K::BondCreate && *purpose == Purpose::Spend)
                        || row.iter().any(|c| c.purposes().contains(purpose))
                })
                .collect();
            let permitted: Vec<Purpose> = purposes
                .into_iter()
                .filter(|purpose| domain_for(kind, *purpose).is_ok())
                .collect();
            assert_eq!(used, permitted, "{kind:?}");
            pairs += permitted.len();
        }
        assert_eq!(
            pairs, 22,
            "the 22 canonical (kind, purpose) pairs of domain_for"
        );
    }

    #[test]
    fn a_kind_obtains_exactly_its_own_capabilities() {
        let (a, b) = (abandon(), zoo());
        for kind in OperationKind::ALL {
            let signer = KindSigner::new(kind, KeyRing::pair(&a, &b));
            assert_eq!(signer.kind(), kind);
            for capability in Capability::ALL {
                let granted = match capability {
                    Capability::TransferSpend => {
                        signer.transfer_spend(KeySlot::Primary).map(|_| ())
                    }
                    Capability::BondAuthorization => signer.bond_authorization().map(|_| ()),
                    Capability::ClaimAuthorization => signer.claim_authorization().map(|_| ()),
                    Capability::TradeApproval => signer.trade_approval().map(|_| ()),
                    Capability::RotationProofs => signer.rotation_proofs().map(|_| ()),
                    Capability::TreasuryFreeze => signer.treasury_freeze().map(|_| ()),
                    Capability::MakerOfferAuthorization => {
                        signer.maker_offer_authorization().map(|_| ())
                    }
                    Capability::WorkerAssignmentAuthorization => {
                        signer.worker_assignment_authorization().map(|_| ())
                    }
                    Capability::MakerFillAuthorization => {
                        signer.maker_fill_authorization().map(|_| ())
                    }
                };
                if capabilities(kind).contains(&capability) {
                    assert_eq!(granted, Ok(()), "{kind:?} {capability:?}");
                } else {
                    assert_eq!(
                        granted,
                        Err(Refusal::CapabilityNotPermitted { kind, capability }),
                        "{kind:?} {capability:?}"
                    );
                }
            }
        }
        // The proofs of a rotation need both keys; a one-key ring has no second key to give.
        let single = KindSigner::new(OperationKind::WalletRotation, KeyRing::single(&a));
        assert_eq!(
            single.rotation_proofs().err(),
            Some(Refusal::NotRequiredSigner(Slot::RotationPossession))
        );
        assert_eq!(
            single.public(KeySlot::Secondary).err(),
            Some(Refusal::SigningFailed)
        );
        assert_eq!(single.public(KeySlot::Primary).unwrap(), a.public());
    }

    #[test]
    fn a_bond_capability_signs_only_its_kind_through_consensus_under_the_domain_domain_for_selects()
    {
        let a = abandon();
        let unbond = BondOperation {
            genesis: [1; 32],
            fingerprint: [2; 32],
            envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                first_height: 10,
                last_height: 10,
                reference_height: 9,
                reference_block: [3; 32],
                preconditions: Vec::new(),
            },
            owner: [4; 32],
            authorizer: a.public().descriptor(1).unwrap(),
            action: BondAction::Unbond {
                lot: [5; 32],
                sequence: 1,
            },
            signature: zero(),
        };
        let mut withdraw = BondOperation {
            action: BondAction::Withdraw {
                lot: [5; 32],
                sequence: 1,
            },
            ..unbond.clone()
        };
        let signer = KindSigner::new(OperationKind::BondUnbond, KeyRing::single(&a));
        let bond = signer.bond_authorization().unwrap();
        assert_eq!(
            bond.authorize_bond(&mut withdraw),
            Err(Refusal::CapabilityNotPermitted {
                kind: OperationKind::BondUnbond,
                capability: Capability::BondAuthorization
            })
        );
        assert_eq!(withdraw.signature, zero(), "nothing was signed");
        let mut op = unbond.clone();
        bond.authorize_bond(&mut op).unwrap();
        let body = op.body().unwrap();
        let domain = domain_for(OperationKind::BondUnbond, Purpose::BondAction).unwrap();
        assert_eq!(domain, Domain::BondUnbond);
        a.public().verify(domain, &body, &op.signature).unwrap();
        for other in [
            Domain::BondCreate,
            Domain::BondWithdraw,
            Domain::Transaction,
        ] {
            assert!(a.public().verify(other, &body, &op.signature).is_err());
        }
    }

    #[test]
    fn a_trading_capability_signs_only_its_kind_and_only_as_its_own_identity() {
        let a = abandon();
        let me = SignerIdentity::from_public(a.public(), 1, None).unwrap();
        let stranger = SignerIdentity::from_public(zoo().public(), 1, None).unwrap();
        let refund = TradeOperation {
            meta: Meta {
                context: Context {
                    network: NETWORK_ID,
                    genesis: [1; 32],
                    fingerprint: [2; 32],
                },
                trade: [3; 32],
                contract: [4; 32],
                generation: 1,
                envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                    first_height: 10,
                    last_height: 20,
                    reference_height: 9,
                    reference_block: [3; 32],
                    preconditions: Vec::new(),
                },
                fee: Strikes(240),
                inputs: Vec::new(),
            },
            action: TradeAction::Refund {
                output: [5; 32],
                owner: me.address(),
                amount: Strikes(1_000),
                change: Strikes(0),
            },
            approvals: Vec::new(),
            offer_proof: None,
        };
        let claim = TradeOperation {
            action: TradeAction::Claim {
                output: [5; 32],
                recipient: me.address(),
                amount: Strikes(1_000),
                preimage: [6; 32],
                change: Strikes(0),
            },
            ..refund.clone()
        };
        let signer = KindSigner::new(OperationKind::ConditionalRefund, KeyRing::single(&a));
        let approve = signer.trade_approval().unwrap();
        assert_eq!(
            approve.approve_slot(&claim, 0, &me),
            Err(Refusal::CapabilityNotPermitted {
                kind: OperationKind::ConditionalRefund,
                capability: Capability::TradeApproval
            })
        );
        assert_eq!(
            approve.approve_slot(&refund, 0, &stranger),
            Err(Refusal::NotRequiredSigner(Slot::Approval(0)))
        );
        let signature = approve.approve_slot(&refund, 0, &me).unwrap();
        let payload = refund.signing_payload(0, me.descriptor()).unwrap();
        a.public()
            .verify(Domain::Transaction, &payload, &signature)
            .unwrap();
        // The signature binds the slot and the operation: it is no approval of another slot.
        let other_slot = refund.signing_payload(1, me.descriptor()).unwrap();
        assert!(
            a.public()
                .verify(Domain::Transaction, &other_slot, &signature)
                .is_err()
        );
    }
}
