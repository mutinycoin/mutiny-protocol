//! The Treasury profile (phase 6): identity-checked, NON-DEFAULT, declared explicitly at run time
//! (assumed default Q5).
//!
//! Two Treasury mechanisms exist, and the D1 packet keeps them as separate transitions:
//!
//!  * R1, [`TreasuryRole::Authority`]: the Genesis Treasury wallet authority
//!    (`State::dividends.treasury().authority()`, the generation-one AddressID of the Treasury
//!    record). Its later rotation "is the ordinary wallet rotation" (`treasury_v1.rs`), so R1 is the
//!    `WalletRotation` operation performed by that authority's current key; spending its coins
//!    (payments, fees) is reserve-aware (Q15).
//!  * R2, [`TreasuryRole::Destination`]: the wallet that controls the ACTIVE destination address of
//!    one trading Treasury (`trading_v1` record tag 3, identified by a 32-byte TreasuryID). It signs
//!    the trading `TreasuryRotate` of that Treasury and the freeze authorizations of its offers
//!    (`ops::treasury`).
//!
//! How the code relates the two is NOT defined by consensus or spec (D2 finding G6): a trading
//! TreasuryID is not derived from the Genesis Treasury. This crate therefore never assumes one is
//! the other; a declaration names each role it claims, and each claim is checked separately against
//! the verified chain.
//!
//! What "identity-checked, non-default" means here:
//!
//!  * Every [`SignerIdentity`] starts as `WalletProfile::Ordinary`. A host turns the Treasury
//!    profile on only through an explicit configuration entry, a [`TreasuryDeclaration`], passed to
//!    [`declare`], which checks it against the verified chain: the chain's Genesis, the chain class
//!    the operator expects (TEST-VALUE or production; a chain that declares no class is refused),
//!    the identity being the CURRENT key of its authority, and the identity really holding every
//!    role claimed. It is never a UI toggle and never inferred from a key.
//!  * [`declare`] is the ONLY public way to a Treasury-profile identity (since the fixes of the
//!    independent wallet review: the labelling is crate-private, CR-6-3; tests use a constructor
//!    behind the non-shipping cfg), and the identity carries exactly the ROLE SET that `declare`
//!    checked ([`TreasuryRoles`]), not one bit. The check is repeated at USE, per kind: spending
//!    Genesis Treasury coins and rotating its authority (R1) need the declared `Authority` role
//!    (`select::require_profile_for_treasury` in every spending handler); the `TreasuryRotate` of a
//!    trading Treasury (R2) and the freeze of an offer to it need the declared `Destination` role
//!    for exactly that TreasuryID (`require_role` in `ops::treasury`). A missing role is
//!    `TREASURY_ROLE_NOT_DECLARED`, an ordinary identity `TREASURY_PROFILE_REQUIRED`; the handlers
//!    then re-check the identity against the verified state on every plan, review and authorization
//!    (R2 and freezes: the signer must control the active destination, `NOT_REQUIRED_SIGNER`
//!    otherwise).
//!  * The chain class is respected. Signing goes through the `SigningGate`: while
//!    `PRODUCTION_SECURITY_QUALIFIED` is false the production gate cannot be built (`GATE_CLOSED`),
//!    so no production Treasury operation can be signed; the TEST-VALUE gate exists only under
//!    `cfg(test)` or the non-shipping `test-value-signing` feature and refuses a production chain
//!    (`CHAIN_CLASS_MISMATCH`). Treasury operations are also refused on a chain that declares no
//!    class at all (`TREASURY_CLASS_UNDECLARED`): there the wallet could not say whether real
//!    value is at stake.
//!  * The profile is part of what an approval is bound to (phase 1: `Review::scope` covers the
//!    signer's profile), so an approval given for an ordinary reading cannot authorize a Treasury
//!    plan and the reverse.
//!
//! Bitcoin: nothing in this module or in any Treasury operation touches Bitcoin custody. The
//! Treasury profile changes MUT authority only; Bitcoin custody stays external and under the
//! Architect's sole control.
use crate::{
    authorize::{SignerIdentity, WalletProfile},
    context::{ChainClass, ChainView},
    ops::treasury as operations,
    plan::Slot,
    refusal::{ContextField, Refusal},
    units,
};
use mutiny_consensus_v8::Hash;
use std::fmt;

/// The text of `TREASURY_CLASS_UNDECLARED` (since phase 8; before, an `INVALID_REQUEST` reason):
/// the chain declares no class (no Treasury record), or a declaration names no class.
pub const REASON_CLASS_UNDECLARED: &str = "Treasury operations need a chain that declares its class (a TEST-VALUE or production Treasury record); this one declares none";
/// `INVALID_REQUEST` reason: a declaration claims no role.
pub const REASON_NO_ROLE: &str =
    "a Treasury declaration must claim the Treasury authority, a trading Treasury, or both";

/// A role an identity can hold in the Treasury profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TreasuryRole {
    /// R1: the Genesis Treasury wallet authority. Rotating it (`WalletRotation`) and spending its
    /// coins, only above the dividend reserve.
    Authority,
    /// R2 and offer freezes: the wallet that controls the ACTIVE destination of one trading
    /// Treasury.
    Destination,
}

impl TreasuryRole {
    pub fn text(self) -> &'static str {
        match self {
            Self::Authority => "the Genesis Treasury wallet authority (R1)",
            Self::Destination => "the active destination of a trading Treasury (R2, offer freezes)",
        }
    }
}

/// The Treasury roles an identity carries: exactly those [`declare`] checked against the verified
/// chain (none for an ordinary identity). Read with `SignerIdentity::treasury_roles`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct TreasuryRoles {
    /// [`TreasuryRole::Authority`]: the Genesis Treasury wallet authority (R1, spending its coins).
    pub authority: bool,
    /// [`TreasuryRole::Destination`] for this trading TreasuryID (R2, its offer freezes).
    pub destination_of: Option<Hash>,
}

impl TreasuryRoles {
    /// The roles `declaration` claims.
    pub fn claimed_by(declaration: &TreasuryDeclaration) -> Self {
        Self {
            authority: declaration.authority,
            destination_of: declaration.destination_of,
        }
    }
    /// Whether any role is held.
    pub fn any(&self) -> bool {
        self.authority || self.destination_of.is_some()
    }
}

impl fmt::Debug for TreasuryRoles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreasuryRoles")
            .field("authority", &self.authority)
            .field(
                "destination_of",
                &self.destination_of.map(|id| units::short_hex(&id)),
            )
            .finish()
    }
}

/// The host's explicit runtime declaration of the Treasury profile: a configuration entry (for
/// example a file the operator writes once per Treasury machine), never a default and never a UI
/// button. It names the one chain, the class the operator expects that chain to declare, and every
/// role claimed; [`declare`] checks all of it against the verified chain.
#[derive(Clone, PartialEq, Eq)]
pub struct TreasuryDeclaration {
    /// Genesis identifier of the one chain this declaration is for.
    pub genesis: Hash,
    /// The class the operator expects the chain to declare (`TestValue` or `Production`).
    pub chain_class: ChainClass,
    /// Claims [`TreasuryRole::Authority`].
    pub authority: bool,
    /// Claims [`TreasuryRole::Destination`] for this trading TreasuryID.
    pub destination_of: Option<Hash>,
}

impl TreasuryDeclaration {
    /// A declaration for one chain and class, claiming no role yet.
    pub fn new(genesis: Hash, chain_class: ChainClass) -> Self {
        Self {
            genesis,
            chain_class,
            authority: false,
            destination_of: None,
        }
    }
    /// Claim the Genesis Treasury wallet authority (R1).
    pub fn with_authority(mut self) -> Self {
        self.authority = true;
        self
    }
    /// Claim the active destination of trading Treasury `treasury` (R2 and offer freezes).
    pub fn with_destination_of(mut self, treasury: Hash) -> Self {
        self.destination_of = Some(treasury);
        self
    }
    /// The roles claimed, in a fixed order.
    pub fn roles(&self) -> Vec<TreasuryRole> {
        let mut roles = Vec::new();
        if self.authority {
            roles.push(TreasuryRole::Authority);
        }
        if self.destination_of.is_some() {
            roles.push(TreasuryRole::Destination);
        }
        roles
    }
}

impl fmt::Debug for TreasuryDeclaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreasuryDeclaration")
            .field("genesis", &units::short_hex(&self.genesis))
            .field("chain_class", &self.chain_class)
            .field("authority", &self.authority)
            .field(
                "destination_of",
                &self.destination_of.map(|id| units::short_hex(&id)),
            )
            .finish()
    }
}

/// What the verified chain says an identity holds in the Treasury profile, whatever was declared.
#[derive(Clone, PartialEq, Eq)]
pub struct TreasuryStanding {
    /// The identity is the CURRENT key of the Genesis Treasury wallet authority.
    pub authority: bool,
    /// The trading Treasuries whose ACTIVE destination the identity's current descriptor controls.
    pub destinations: Vec<Hash>,
}

impl TreasuryStanding {
    /// Whether the identity holds any Treasury role at all.
    pub fn holds_any(&self) -> bool {
        self.authority || !self.destinations.is_empty()
    }
}

impl fmt::Debug for TreasuryStanding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreasuryStanding")
            .field("authority", &self.authority)
            .field(
                "destinations",
                &self
                    .destinations
                    .iter()
                    .map(|id| units::short_hex(id))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Read-only: the Treasury roles `identity` holds on the verified chain. A stale identity (a key
/// rotated away) holds none.
pub fn standing(view: &ChainView<'_>, identity: &SignerIdentity) -> TreasuryStanding {
    if identity.check_current(view).is_err() {
        return TreasuryStanding {
            authority: false,
            destinations: Vec::new(),
        };
    }
    TreasuryStanding {
        authority: view
            .treasury()
            .is_some_and(|treasury| treasury.authority() == identity.authority()),
        destinations: operations::controlled_treasuries(view, identity),
    }
}

/// Turn `identity` into a Treasury-profile identity after checking `declaration` against the
/// verified chain. Refusals, in order: a declaration naming no class (`TREASURY_CLASS_UNDECLARED`),
/// a chain whose class differs from the declared one (`CHAIN_CLASS_MISMATCH`, with the declared
/// class in the `gate` position), another Genesis (`WRONG_CONTEXT`), no role claimed
/// ([`REASON_NO_ROLE`]), a key that is not the current key of its authority (`STALE_AUTHORITY`),
/// the authority claimed but dividends inactive (`DIVIDEND_INACTIVE`) or another authority
/// (`NOT_REQUIRED_SIGNER` for the rotation authorization), a trading Treasury claimed that does not
/// exist (`INVALID_REQUEST`) or whose active destination this key does not control
/// (`NOT_REQUIRED_SIGNER` for approval slot 0).
///
/// The result carries the Treasury profile and exactly the roles claimed (and checked): signing
/// still needs the key and a signing gate, and every Treasury operation checks the role and the
/// identity again when it is used.
pub fn declare(
    identity: SignerIdentity,
    declaration: &TreasuryDeclaration,
    view: &ChainView<'_>,
) -> Result<SignerIdentity, Refusal> {
    if declaration.chain_class == ChainClass::Undeclared {
        return Err(Refusal::TreasuryClassUndeclared);
    }
    let chain = view.class();
    if chain != declaration.chain_class {
        return Err(Refusal::ChainClassMismatch {
            gate: declaration.chain_class,
            chain,
        });
    }
    if view.context().genesis != declaration.genesis {
        return Err(Refusal::WrongContext(ContextField::Genesis));
    }
    if declaration.roles().is_empty() {
        return Err(Refusal::InvalidRequest(REASON_NO_ROLE));
    }
    identity.check_current(view)?;
    if declaration.authority {
        let treasury = view.treasury().ok_or(Refusal::DividendInactive)?;
        if treasury.authority() != identity.authority() {
            return Err(Refusal::NotRequiredSigner(Slot::RotationAuthorization));
        }
    }
    if let Some(treasury) = declaration.destination_of {
        let active = operations::active_destination(view, &treasury)?;
        view.state()
            .wallets
            .authorize(active.address, identity.descriptor())
            .map_err(|_| Refusal::NotRequiredSigner(Slot::Approval(0)))?;
    }
    Ok(identity.with_treasury_roles(TreasuryRoles::claimed_by(declaration)))
}

/// The use-time gate of every Treasury-only operation (R2 and offer freezes): the signer carries the
/// Treasury profile, and the chain declares a class. The identity itself is checked by the
/// operation against the state it acts on.
pub(crate) fn require_treasury_operation(
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<(), Refusal> {
    if signer.profile() != WalletProfile::Treasury {
        return Err(Refusal::TreasuryProfileRequired);
    }
    if view.class() == ChainClass::Undeclared {
        return Err(Refusal::TreasuryClassUndeclared);
    }
    Ok(())
}

/// The use-time role check of the Treasury kinds (fixes of the independent wallet review,
/// MINOR-2): `signer` carries the Treasury profile (`TREASURY_PROFILE_REQUIRED` otherwise) and
/// `declare` checked `role` for it; for [`TreasuryRole::Destination`], for exactly the trading
/// Treasury `treasury` (`TREASURY_ROLE_NOT_DECLARED` otherwise).
pub(crate) fn require_role(
    signer: &SignerIdentity,
    role: TreasuryRole,
    treasury: Option<&Hash>,
) -> Result<(), Refusal> {
    if signer.profile() != WalletProfile::Treasury {
        return Err(Refusal::TreasuryProfileRequired);
    }
    let roles = signer.treasury_roles();
    let held = match role {
        TreasuryRole::Authority => roles.authority,
        TreasuryRole::Destination => {
            treasury.is_some_and(|treasury| roles.destination_of == Some(*treasury))
        }
    };
    if held {
        Ok(())
    } else {
        Err(Refusal::TreasuryRoleNotDeclared(role))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declaration_lists_its_roles_and_prints_no_full_identifier() {
        let declaration = TreasuryDeclaration::new([7; 32], ChainClass::TestValue);
        assert!(declaration.roles().is_empty());
        let both = declaration
            .clone()
            .with_authority()
            .with_destination_of([9; 32]);
        assert_eq!(
            both.roles(),
            vec![TreasuryRole::Authority, TreasuryRole::Destination]
        );
        let shown = format!("{both:?}");
        assert!(!shown.contains(&hex::encode([9u8; 32])), "{shown}");
        assert!(!shown.contains(&hex::encode([7u8; 32])), "{shown}");
        assert!(!TreasuryRole::Authority.text().is_empty());
        let standing = TreasuryStanding {
            authority: false,
            destinations: Vec::new(),
        };
        assert!(!standing.holds_any());
    }
}
