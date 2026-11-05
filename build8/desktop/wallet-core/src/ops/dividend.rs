//! (c) Dividend claims (phase 3): partial claims, the per-(award, License) claim sequence, and at
//! most one outstanding claim per (award, License).
//!
//! A claim is consensus' `dividend_claim_v1::SignedClaim`: block operation kind 23,
//! `[2, 23, body, descriptor, signature]`. It is fee-exempt (`CLAIM_FEE = 0`), has no inputs or
//! outputs of its own and is signed by the CURRENT owner authority of the License under
//! `Domain::Transaction` over the claim-intent payload (consensus' own `SignedClaim::sign`, reached
//! through the claim capability of `capability::KindSigner`, which `domain_for(DividendClaim, Spend)`
//! permits). When it
//! executes, the protocol pays exactly `amount` from Treasury coins (oldest Treasury address first,
//! then outpoint order, change back to the owner of the last coin used) to the signed destination as
//! coin `(claim id, 0)`.
//!
//! What this handler adds to the consensus rules:
//!  * the sequence is read from CONFIRMED state (`account.claims`), never from the outbox;
//!  * at most ONE outstanding claim per (award, License): the plan consumes the resource
//!    `discovery::dividends::claim_slot(award, License)`, which the outbox reserves, so a second
//!    plan for the same pair is refused (`RESERVED_INPUT`) until the first is reconciled or
//!    forgotten (two unconfirmed claims n and n+1 work only if a proposer happens to order them, and
//!    the protocol has no such ordering rule);
//!  * the time basis: eligibility is judged at the epoch of the CONTAINING block,
//!    `mining_epoch(timestamp, t0) = (timestamp - t0) / 60` (consensus/src/pow.rs, applied to the
//!    block in consensus/src/execution_v2.rs), which the wallet cannot know. Consensus' timestamp
//!    rule (`pow::validate_timestamp`) requires every block's timestamp to be above the median of its
//!    ancestors AND not below its parent's, with no wall-clock bound in either direction. So along
//!    the chain that extends the verified head timestamps never decrease, the floor division keeps
//!    that order, and the including block's epoch is at least the head's and has no upper bound
//!    (Order W20 verified this; the earlier median-only rule, under which a block could carry a
//!    timestamp below its parent's and epochs could regress, would NOT have justified it). Every
//!    epoch check therefore runs at the head's epoch (a lower bound for the inclusion epoch), the
//!    time left is shown as an UPPER bound ("at most"), and a claim near the end of its window
//!    carries a warning (`review::CLAIM_DEADLINE_WARNING_EPOCHS`, a display threshold). The test
//!    `refusals_dividend::the_at_most_wording_rests_on_consensus_refusing_a_regressing_timestamp`
//!    pins the consensus rule this rests on. The operating-system clock is never read;
//!  * wallet policy: a claim to the all-zero address (which no key controls) is refused.
//!
//! Verification: before signing, every consensus rule that needs no signature is mirrored
//! explicitly against the CURRENT view (dividends active, context, height window, the License,
//! the ledger rules through the public `Ledger::check_claim` at the head's epoch, owner authority
//! through `WalletBook::authorize`, the Treasury coin plan through the public `plan_spend`, the
//! claim-identity check), then cross-checked by consensus' own `dividend_claim_v1::admit` on the
//! UNSIGNED claim, which must stop exactly at the signature. After signing, both signature halves
//! must be present, `SignedClaim::verify_signature` must accept them and `dividend_claim_v1::admit`
//! must accept the signed bytes.
use super::payment::{is_unsigned, zero_signature};
use super::select;
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    capability::KindSigner,
    context::{ChainClass, ChainView, is_treasury_address, treasury_authority},
    discovery::{
        dividends::claim_slot,
        licenses::{self, LicenseInfo},
    },
    outbox::{OutboxRecord, Settlement},
    plan::{
        Description, DividendClaimRequest, OperationHandler, OperationKind, OperationPlan,
        OperationRequest, PlanObject, RequiredSigner, Requirement, RequirementStatus, Slot,
        Validity,
    },
    refusal::Refusal,
    review::{
        AckKind, AddressLabel, Condition, Destination, DestinationRole, Effect, Fee, FeePayer,
        FeeRule, Party, PartyRole, ReviewDraft, Severity, Timing, Warning,
    },
    units,
};
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    dividend_claim_v1::{self, CLAIM_FEE, ClaimBody, ClaimError, SignedClaim},
    dividend_state_v1::DividendState,
    dividends_v1::{AWARD_PERIOD_EPOCHS, CLAIM_WINDOW_EPOCHS, Claim, DivError},
    execution::State,
    transactions::{EXPIRY_HORIZON, OutPoint},
};
use mutiny_crypto_v2::PublicKey;

/// Layout version of the dividend-claim plan objects.
pub const SCHEMA: u16 = 1;
/// Label of the one object of a dividend-claim plan: the claim with a zero signature.
pub const OBJECT_LABEL: &str = "claim";
/// The near-deadline warning threshold, kept under its old name for hosts: the display-layer
/// constant `review::CLAIM_DEADLINE_WARNING_EPOCHS` (Order W20: a UI warning threshold, not a claim
/// time-to-live and not a consensus constant).
pub const NEAR_DEADLINE_EPOCHS: u64 = crate::review::CLAIM_DEADLINE_WARNING_EPOCHS;
/// The reason text for an award whose epoch the verified chain has not reached. Since phase 8 that
/// case is refused with the dedicated `Refusal::AwardNotYetOpen` (code `AWARD_NOT_YET_OPEN`); the
/// text is kept for hosts that show it.
pub const NOT_REACHED: &str =
    "the award epoch is later than the verified block's epoch, so this award cannot be claimed yet";

pub(crate) struct DividendHandler;
pub(crate) static HANDLER: DividendHandler = DividendHandler;

/// The handler for `kind` (registered in `ops/mod.rs`).
pub(crate) fn handler(kind: OperationKind) -> Option<&'static dyn OperationHandler> {
    match kind {
        OperationKind::DividendClaim => Some(&HANDLER),
        _ => None,
    }
}

fn decode(raw: &[u8]) -> Result<SignedClaim, Refusal> {
    SignedClaim::decode(raw).map_err(|_| Refusal::Malformed("not a canonical dividend claim"))
}

/// The same claim with the zero signature placeholder.
fn unsigned_copy(claim: &SignedClaim) -> SignedClaim {
    SignedClaim {
        signature: zero_signature(),
        ..claim.clone()
    }
}

fn both_halves_present(claim: &SignedClaim) -> bool {
    claim.signature.ed448 != [0; 114] && claim.signature.fndsa != [0; 1280]
}

fn plan_claim(plan: &OperationPlan) -> Result<SignedClaim, Refusal> {
    let [object] = plan.objects() else {
        return Err(Refusal::Malformed(
            "a dividend claim plan has exactly one object",
        ));
    };
    if object.label != OBJECT_LABEL {
        return Err(Refusal::Malformed("unexpected plan object"));
    }
    let claim = decode(&object.bytes)?;
    if !is_unsigned(&claim.signature) {
        return Err(Refusal::Malformed("a plan holds the unsigned claim"));
    }
    Ok(claim)
}

fn validity_of(body: &ClaimBody) -> Validity {
    Validity {
        created: body.created_height,
        expiry: body.expiry_height,
        valid_only_at: None,
        bound_to_parent: false,
    }
}

// ---------------------------------------------------------------------------------------------
// Refusals (consensus outcome -> typed wallet refusal)
// ---------------------------------------------------------------------------------------------

/// The height window: span within the protocol horizon, then open, then not closed.
fn window_refusal(body: &ClaimBody, next: u64) -> Option<Refusal> {
    if body.expiry_height < body.created_height
        || body.expiry_height - body.created_height > EXPIRY_HORIZON
    {
        return Some(Refusal::InvalidValidity);
    }
    if next < body.created_height {
        return Some(Refusal::WindowNotOpen {
            created: body.created_height,
            next_height: next,
        });
    }
    if next > body.expiry_height {
        return Some(Refusal::WindowClosed {
            expiry: body.expiry_height,
            next_height: next,
        });
    }
    None
}

/// A key that does not control the License owner address: if it is still the current key of its
/// own address it is simply not the required signer; otherwise it was rotated away.
fn owner_refusal(state: &State, descriptor: &[u8]) -> Refusal {
    let own = PublicKey::decode_descriptor(descriptor)
        .ok()
        .and_then(|(public, generation)| public.address_id(generation).ok());
    match own {
        Some(address) if state.wallets.authorize(address, descriptor).is_ok() => {
            Refusal::NotRequiredSigner(Slot::Claim)
        }
        Some(_) => Refusal::StaleAuthority,
        None => Refusal::InvalidDescriptor,
    }
}

/// No award exists for `award_epoch` in the verified state.
fn absent_award(award_epoch: u64, head_epoch: u64) -> Refusal {
    if award_epoch > head_epoch {
        Refusal::AwardNotYetOpen {
            award_epoch,
            head_epoch,
        }
    } else if award_epoch > 0
        && award_epoch.is_multiple_of(AWARD_PERIOD_EPOCHS)
        && head_epoch >= award_epoch.saturating_add(CLAIM_WINDOW_EPOCHS)
    {
        // A boundary award whose window has passed was removed by expiry processing.
        Refusal::AwardExpired
    } else {
        Refusal::NotEntitled
    }
}

fn ledger_refusal(error: DivError, body: &ClaimBody, state: &State, head_epoch: u64) -> Refusal {
    let account = state
        .dividends
        .ledger()
        .award(body.award_epoch)
        .and_then(|award| award.account(&body.license));
    match error {
        DivError::ZeroAmount => Refusal::InvalidAmount,
        DivError::UnknownAward => absent_award(body.award_epoch, head_epoch),
        DivError::NotYetClaimable => Refusal::AwardNotYetOpen {
            award_epoch: body.award_epoch,
            head_epoch,
        },
        DivError::Expired => Refusal::AwardExpired,
        DivError::WrongLicense | DivError::NotEntitled => Refusal::NotEntitled,
        DivError::Revoked | DivError::Suspended => Refusal::LicenseSuspendedOrRevoked,
        DivError::StaleOwner => Refusal::StaleAuthority,
        DivError::Replay => Refusal::Replay,
        DivError::Sequence => Refusal::WrongSequence {
            expected: account.map_or(0, |account| account.claims),
        },
        DivError::Overdrawn => Refusal::Overdrawn {
            remaining: account.map_or(0, |account| account.remaining),
        },
        DivError::Overflow => Refusal::Overflow,
        DivError::Rewind | DivError::Backing | DivError::Invariant | DivError::Malformed => {
            Refusal::Malformed("the dividend ledger is inconsistent")
        }
    }
}

/// The Treasury's coins cannot pay the claim although the ledger reserves it.
fn backing_refusal(state: &State) -> Refusal {
    let backing = DividendState::backing(&state.coins, &state.treasury_owner_set()).unwrap_or(0);
    Refusal::ReserveBackingViolation {
        reserved: state.dividends.reserved(),
        backing_after: backing,
    }
}

/// Map a consensus claim error to the wallet's typed refusal.
fn consensus_refusal(error: ClaimError, claim: &SignedClaim, view: &ChainView<'_>) -> Refusal {
    let body = &claim.body;
    let state = view.state();
    match error {
        ClaimError::Codec => Refusal::Malformed("dividend claim encoding"),
        ClaimError::Context => view
            .require_context(body.network, &body.genesis, &body.fingerprint)
            .err()
            .unwrap_or(Refusal::Malformed("claim context")),
        ClaimError::Window => view
            .next_height()
            .ok()
            .and_then(|next| window_refusal(body, next))
            .unwrap_or(Refusal::InvalidValidity),
        ClaimError::Destination => Refusal::InvalidRecipient,
        ClaimError::UnknownLicense => Refusal::NotEntitled,
        ClaimError::StaleOwner => owner_refusal(state, &claim.descriptor),
        ClaimError::Signature => Refusal::VerificationFailed("the claim signature does not verify"),
        ClaimError::Dividend(error) => {
            ledger_refusal(error, body, state, view.epoch().unwrap_or(0))
        }
        ClaimError::Backing => backing_refusal(state),
        ClaimError::Duplicate => Refusal::Replay,
        ClaimError::Overflow => Refusal::Overflow,
        ClaimError::Inactive => Refusal::DividendInactive,
    }
}

// ---------------------------------------------------------------------------------------------
// Validation (pre-signing mirror of consensus)
// ---------------------------------------------------------------------------------------------

/// What the verified state says about a claim that passed every pre-signature rule.
pub(crate) struct Facts {
    license: LicenseInfo,
    share: u64,
    remaining: u64,
    claims: u64,
    head_epoch: u64,
    cursor: u64,
    reserve: u64,
    /// The Treasury coin plan consensus would make at this head.
    spend_coins: usize,
    spend_total: u64,
    change: u64,
    change_owner: Hash,
}

/// Every consensus rule that does not need the signature, against the CURRENT view, in consensus'
/// own order, then consensus' own admission of the unsigned claim, which must stop exactly at the
/// signature. A claim that passes can be signed; one that fails could never be included at this
/// head. The outbox reservation is NOT checked here (see `require_unreserved`).
fn check_rules(claim: &SignedClaim, view: &ChainView<'_>) -> Result<Facts, Refusal> {
    let body = &claim.body;
    let state = view.state();
    if !state.dividends.is_active() {
        return Err(Refusal::DividendInactive);
    }
    view.require_context(body.network, &body.genesis, &body.fingerprint)?;
    let next = view.next_height()?;
    if let Some(refusal) = window_refusal(body, next) {
        return Err(refusal);
    }
    let context = view.context();
    let record = state
        .licenses_v2
        .license(body.license)
        .filter(|record| record.genesis == context.genesis)
        .ok_or(Refusal::NotEntitled)?;
    let owner = record.owner;
    // The ledger rules at the HEAD's epoch: the including block's epoch is at least this one.
    let head_epoch = view.epoch()?;
    let activation = state.licenses_v2.dividend_activation_epoch(body.license);
    let standing = state.dividends.view(body.license, owner, activation);
    let ledger_claim = Claim {
        award_epoch: body.award_epoch,
        license: body.license,
        claimant: owner,
        amount: body.amount,
        sequence: body.sequence,
    };
    state
        .dividends
        .ledger()
        .check_claim(&ledger_claim, head_epoch, &standing)
        .map_err(|error| ledger_refusal(error, body, state, head_epoch))?;
    // Only the CURRENT owner authority: a wrong owner or a rotated-away key fails here.
    state
        .wallets
        .authorize(owner, &claim.descriptor)
        .map_err(|_| owner_refusal(state, &claim.descriptor))?;
    // Wallet policy: the all-zero address has no key; a claim to it destroys the dividend.
    if body.destination == [0; 32] {
        return Err(Refusal::InvalidRecipient);
    }
    // Independent cross-check with consensus' own admission: every rule before the signature holds.
    let unsigned = unsigned_copy(claim).encode();
    match dividend_claim_v1::admit(
        state,
        &unsigned,
        context.genesis,
        context.fingerprint,
        next,
        head_epoch,
    ) {
        Err(ClaimError::Signature) => {}
        Ok(()) => {
            return Err(Refusal::VerificationFailed(
                "consensus admitted a claim without a signature",
            ));
        }
        Err(other) => return Err(consensus_refusal(other, claim, view)),
    }
    // The Treasury coin plan consensus makes after the signature check.
    let spend =
        dividend_claim_v1::plan_spend(&state.coins, &state.treasury_owner_order(), body.amount)
            .map_err(|error| match error {
                ClaimError::Overflow => Refusal::Overflow,
                _ => backing_refusal(state),
            })?;
    // The claim identity must be unused (consensus' duplicate check).
    let id = body.id();
    if (0..2u32).any(|index| {
        state.coins.contains_key(&OutPoint {
            transaction: id,
            index,
        })
    }) {
        return Err(Refusal::Replay);
    }
    let account = state
        .dividends
        .ledger()
        .award(body.award_epoch)
        .and_then(|award| award.account(&body.license))
        .ok_or(Refusal::NotEntitled)?;
    let license = licenses::license(state, body.license).ok_or(Refusal::NotEntitled)?;
    Ok(Facts {
        license,
        share: account.share,
        remaining: account.remaining,
        claims: account.claims,
        head_epoch,
        cursor: state.dividends.ledger().cursor(),
        reserve: state.dividends.reserved(),
        spend_coins: spend.inputs.len(),
        spend_total: body
            .amount
            .checked_add(spend.change)
            .ok_or(Refusal::Overflow)?,
        change: spend.change,
        change_owner: spend.change_owner,
    })
}

/// At most one outstanding claim per (award, License): refuse a claim whose slot another pending
/// claim already holds.
fn require_unreserved(body: &ClaimBody, view: &ChainView<'_>) -> Result<(), Refusal> {
    if view
        .reserved()
        .contains(&claim_slot(body.award_epoch, &body.license))
    {
        return Err(Refusal::ReservedInput);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------------------------

/// The unsigned claim for a request. The sequence is read from CONFIRMED state: the number of
/// claims already applied for this (award, License), never anything the outbox holds.
fn build_claim(
    request: &DividendClaimRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<SignedClaim, Refusal> {
    if request.amount_atoms == 0 {
        return Err(Refusal::InvalidAmount);
    }
    if request.destination == [0; 32] {
        return Err(Refusal::InvalidRecipient);
    }
    if request.validity_blocks == 0 || request.validity_blocks > EXPIRY_HORIZON {
        return Err(Refusal::InvalidValidity);
    }
    signer.check_current(view)?;
    select::require_profile_for_treasury(view, signer)?;
    let state = view.state();
    if !state.dividends.is_active() {
        return Err(Refusal::DividendInactive);
    }
    let next = view.next_height()?;
    let expiry = next
        .checked_add(request.validity_blocks)
        .ok_or(Refusal::Overflow)?;
    let context = view.context();
    let sequence = state
        .dividends
        .ledger()
        .award(request.award_epoch)
        .and_then(|award| award.account(&request.license))
        .map_or(0, |account| account.claims);
    Ok(SignedClaim {
        body: ClaimBody {
            network: NETWORK_ID,
            genesis: context.genesis,
            fingerprint: context.fingerprint,
            created_height: next,
            expiry_height: expiry,
            award_epoch: request.award_epoch,
            license: request.license,
            amount: request.amount_atoms,
            destination: request.destination,
            sequence,
        },
        descriptor: signer.descriptor().to_vec(),
        signature: zero_signature(),
    })
}

/// The immutable plan for an unsigned claim this wallet signs. A plan must pass its own validation
/// at the head it is built for.
fn assemble_plan(
    claim: &SignedClaim,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    // Consensus order first, so the License owner the requirement names exists.
    let facts = check_rules(claim, view)?;
    let body = &claim.body;
    let plan = OperationPlan::assemble(
        OperationKind::DividendClaim,
        SCHEMA,
        signer.clone(),
        vec![PlanObject::new(OBJECT_LABEL, unsigned_copy(claim).encode())],
        vec![Requirement {
            slot: Slot::Claim,
            signer: RequiredSigner::Wallet(facts.license.owner),
            status: RequirementStatus::ThisWallet,
        }],
        vec![claim_slot(body.award_epoch, &body.license)],
        validity_of(body),
        view,
    );
    HANDLER.validate(&plan, view)?;
    Ok(plan)
}

// ---------------------------------------------------------------------------------------------
// Review
// ---------------------------------------------------------------------------------------------

fn short(address: &Hash) -> String {
    units::short_hex(address)
}

/// The review of a claim (unsigned or signed) as seen from `me`.
fn build_review(
    claim: &SignedClaim,
    facts: &Facts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
    let body = &claim.body;
    let state = view.state();
    let treasury = treasury_authority(view);
    let classify = |address: &Hash| -> AddressLabel {
        if state.wallets.authorize(*address, me.descriptor()).is_ok() {
            AddressLabel::ThisWallet
        } else if treasury
            .as_ref()
            .is_some_and(|authority| is_treasury_address(view, authority, address))
        {
            AddressLabel::Treasury
        } else {
            AddressLabel::External
        }
    };
    let owner = facts.license.owner;
    let owner_label = classify(&owner);
    let destination_label = classify(&body.destination);
    // This wallet signs only when its key is the claim's key AND currently controls the owner.
    let mine = owner_label == AddressLabel::ThisWallet && claim.descriptor == me.descriptor();
    let after = facts
        .remaining
        .checked_sub(body.amount)
        .ok_or(Refusal::Overflow)?;
    let next_sequence = body.sequence.checked_add(1).ok_or(Refusal::Overflow)?;
    let closes = body
        .award_epoch
        .checked_add(CLAIM_WINDOW_EPOCHS)
        .ok_or(Refusal::Overflow)?;
    let last_epoch = closes - 1;
    let epochs_left = closes.saturating_sub(facts.head_epoch);
    let head = view.anchor().height;
    let window = body.expiry_height.saturating_sub(head);
    let mut warnings = Vec::new();

    // Who signs, and whether the signature is there.
    let unsigned_status = if mine {
        RequirementStatus::ThisWallet
    } else {
        RequirementStatus::Counterparty
    };
    let status = if is_unsigned(&claim.signature) {
        unsigned_status
    } else if both_halves_present(claim) && claim.verify_signature().is_ok() {
        RequirementStatus::Provided
    } else {
        warnings.push(Warning::new(
            "BAD_SIGNATURE",
            Severity::Danger,
            "The claim carries a signature that does not verify. Do not rely on these bytes.",
        ));
        unsigned_status
    };
    let authorizations = vec![Requirement {
        slot: Slot::Claim,
        signer: RequiredSigner::Wallet(owner),
        status,
    }];

    // Parties and the one destination.
    let mut parties = vec![Party {
        role: PartyRole::Owner,
        address: owner,
        label: owner_label,
    }];
    if let Some((authority, _)) = &treasury {
        parties.push(Party {
            role: PartyRole::Treasury,
            address: *authority,
            label: classify(authority),
        });
    }
    parties.push(Party {
        role: PartyRole::Recipient,
        address: body.destination,
        label: destination_label,
    });
    let destinations = vec![Destination {
        role: DestinationRole::ProtocolPayout,
        address: body.destination,
        label: destination_label,
        atoms: body.amount,
    }];

    // No fee: the claim class is exempt and the protocol pays the exact amount.
    let fee = Fee {
        atoms: CLAIM_FEE,
        rule: FeeRule::Exempt,
        payer: FeePayer::Protocol,
        size_bytes: None,
    };

    let timing = Timing {
        head_height: head,
        created_height: Some(body.created_height),
        expiry_height: Some(body.expiry_height),
        valid_only_at: None,
        bound_to_parent: false,
        earliest_height: None,
        deadline_epoch: Some(last_epoch),
    };

    // The claim key: its generation and its own address.
    let (key_generation, key_address) = PublicKey::decode_descriptor(&claim.descriptor)
        .ok()
        .and_then(|(public, generation)| {
            public
                .address_id(generation)
                .ok()
                .map(|address| (generation, address))
        })
        .ok_or(Refusal::InvalidDescriptor)?;
    let license = &facts.license;
    let generation = license.generation.map_or_else(
        || "unknown".to_string(),
        |generation| generation.to_string(),
    );
    let activation = match license.dividend_activation_epoch {
        Some(0) => "dividend-eligible from epoch 0 (Genesis bootstrap License)".to_string(),
        Some(epoch) => format!("dividend-eligible from epoch {epoch}"),
        None => "no dividend activation".to_string(),
    };
    let pending = if license.pending_assignment {
        "; a Worker assignment is pending (it does not affect this claim)"
    } else {
        ""
    };
    let conditions = vec![
        Condition::new(
            "License",
            format!(
                "{} (index {}, issued at block {}); owner {} ({}); License generation {} (it changes when the License is sold).",
                hex::encode(license.id),
                license.index,
                license.issue_height,
                crate::address_format::encode_for(&owner, view),
                owner_label.text(),
                generation
            ),
        ),
        Condition::new(
            "License status",
            format!(
                "{} at the processed epoch {}; {}{}.",
                license.standing.text(),
                facts.cursor,
                activation,
                pending
            ),
        ),
        Condition::new(
            "Award",
            format!(
                "Award of epoch {}; share {}. A block may include a claim on it only while its epoch is from {} to {} (the window closes at epoch {}).",
                body.award_epoch,
                units::format_amount(facts.share),
                body.award_epoch,
                last_epoch,
                closes
            ),
        ),
        Condition::new(
            "Entitlement",
            format!(
                "Remaining before this claim: {}. After it: {}. Claims already applied: {}.",
                units::format_amount(facts.remaining),
                units::format_amount(after),
                facts.claims
            ),
        ),
        Condition::new(
            "Claim sequence",
            format!(
                "This claim carries sequence {seq}, read from confirmed state (the number of claims already applied for this License and award). It is valid only while exactly {seq} claims have been applied: whichever claim with sequence {seq} is included first uses it, and every other one then fails.",
                seq = body.sequence
            ),
        ),
        Condition::new(
            "Epoch basis",
            format!(
                "Eligibility is judged at the epoch of the block that includes the claim. The verified block is in epoch {}; a later block's epoch is at least that (a block's timestamp may not precede its parent's) and consensus sets no upper bound. Not valid in a block whose epoch is before {}.",
                facts.head_epoch, body.award_epoch
            ),
        ),
        Condition::new(
            "Time left",
            format!(
                "At most {} epochs after the verified block's epoch ({}) remain before the window closes at epoch {} ({}, approximate at {} s per epoch). The including block may be later, so the real margin can be shorter.",
                epochs_left,
                facts.head_epoch,
                closes,
                units::approx_epochs(epochs_left),
                units::EPOCH_SECONDS
            ),
        ),
        Condition::new(
            "Owner at inclusion",
            format!(
                "Valid only if the License is still owned by {} and the claim's key still controls that address when the claim executes. If the License is sold first, including by a sale in the same block (sales execute before claims), the claim fails and the buyer holds the remaining entitlement.",
                crate::address_format::encode_for(&owner, view)
            ),
        ),
        Condition::new(
            "Payment source",
            format!(
                "No fee. The protocol pays exactly {} from the Treasury reserve: Treasury coins, oldest Treasury address first, then outpoint order, with change returning to the Treasury address of the last coin used. At the verified block that is {} coin(s) worth {} with {} change to {}; the coins are chosen when the claim executes.",
                units::format_mut(body.amount),
                facts.spend_coins,
                units::format_mut(facts.spend_total),
                units::format_mut(facts.change),
                crate::address_format::encode_for(&facts.change_owner, view)
            ),
        ),
        Condition::new(
            "Claim key",
            format!(
                "The key of generation {} whose own address is {}; it must be the current key of the License owner.",
                key_generation,
                crate::address_format::encode_for(&key_address, view)
            ),
        ),
        Condition::new(
            "Validity window",
            format!(
                "Valid only for blocks {} to {} ({} blocks after the verified block; {}, approximate at the {} s target interval).",
                body.created_height,
                body.expiry_height,
                window,
                units::approx_blocks(window),
                units::TARGET_BLOCK_SECONDS
            ),
        ),
    ];

    let effects = vec![
        Effect::new(
            format!(
                "The protocol pays {} to {} ({}) from the Treasury reserve. The recipient controls it from inclusion; there is no recall.",
                units::format_mut(body.amount),
                crate::address_format::encode_for(&body.destination, view),
                destination_label.text()
            ),
            true,
        ),
        Effect::new(
            format!(
                "The remaining entitlement of License {} for the award of epoch {} falls from {} to {}, and its claim sequence advances to {}.",
                short(&license.id),
                body.award_epoch,
                units::format_mut(facts.remaining),
                units::format_mut(after),
                next_sequence
            ),
            true,
        ),
        Effect::new(
            format!(
                "The Treasury reserve falls from {} to {}; the Treasury's coins fall by the same amount.",
                units::format_mut(facts.reserve),
                units::format_mut(facts.reserve.saturating_sub(body.amount))
            ),
            false,
        ),
        Effect::new(
            format!(
                "Once signed, the claim cannot be revoked: it stays valid until it is included, another claim uses sequence {}, the License changes owner, the award window closes, or block {} passes.",
                body.sequence, body.expiry_height
            ),
            true,
        ),
    ];

    if view.class() == ChainClass::TestValue {
        warnings.push(Warning::new(
            "TEST_VALUE_CHAIN",
            Severity::Notice,
            "This is a TEST-VALUE chain: nothing here has real value.",
        ));
    }
    if body.destination != owner {
        if destination_label == AddressLabel::ThisWallet {
            warnings.push(Warning::new(
                "DESTINATION_NOT_OWNER",
                Severity::Notice,
                format!(
                    "The dividend goes to another address of this wallet ({}), not to the License owner address {}.",
                    crate::address_format::encode_for(&body.destination, view),
                    crate::address_format::encode_for(&owner, view)
                ),
            ));
        } else {
            warnings.push(Warning::new(
                "DESTINATION_NOT_OWNER",
                Severity::Caution,
                format!(
                    "The dividend goes to {} ({}), which is not the License owner address {}.",
                    crate::address_format::encode_for(&body.destination, view),
                    destination_label.text(),
                    crate::address_format::encode_for(&owner, view)
                ),
            ));
        }
    }
    if destination_label == AddressLabel::Treasury {
        warnings.push(Warning::new(
            "TREASURY_DESTINATION",
            Severity::Notice,
            "The destination is a Treasury address: the dividend returns to the Treasury.",
        ));
    }
    if body.amount == facts.remaining {
        warnings.push(Warning::new(
            "FULL_CLAIM",
            Severity::Notice,
            "This claim takes the whole remaining entitlement of this License for this award.",
        ));
    }
    if epochs_left <= crate::review::CLAIM_DEADLINE_WARNING_EPOCHS || epochs_left <= window {
        warnings.push(
            Warning::new(
                "CLAIM_WINDOW_CLOSING",
                Severity::Caution,
                format!(
                    "The award's claim window closes at most {} epochs ({}, approximate) after the verified block, and sooner for a later including block. A claim that is not included in time pays nothing. (This wallet warns from {} epochs or within the claim's validity window: a display threshold, not a deadline.)",
                    epochs_left,
                    units::approx_epochs(epochs_left),
                    crate::review::CLAIM_DEADLINE_WARNING_EPOCHS
                ),
            )
            .requiring(AckKind::Conditions),
        );
    }
    if treasury
        .as_ref()
        .is_some_and(|(authority, _)| *authority == me.authority())
    {
        warnings.push(
            Warning::new(
                "TREASURY_CLAIMANT",
                Severity::Caution,
                "The Treasury wallet signs this claim. It moves MUT only; Bitcoin custody is separate and untouched.",
            )
            .requiring(AckKind::TreasuryAuthority),
        );
    }
    if !mine {
        warnings.push(Warning::new(
            "NOT_THIS_WALLET",
            Severity::Notice,
            "This wallet is not the claim's signer: it cannot sign this claim.",
        ));
    }

    let (title, summary) = if mine {
        (
            "Claim a dividend".to_string(),
            format!(
                "Claim {} of the award of epoch {} for License {} (index {}), paid to {} ({}). No fee: the protocol pays from the Treasury reserve.",
                units::format_mut(body.amount),
                body.award_epoch,
                short(&license.id),
                license.index,
                crate::address_format::encode_for(&body.destination, view),
                destination_label.text()
            ),
        )
    } else {
        (
            "Dividend claim by another wallet".to_string(),
            format!(
                "A claim of {} of the award of epoch {} for License {} (index {}), paid to {} ({}). This wallet cannot sign it.",
                units::format_mut(body.amount),
                body.award_epoch,
                short(&license.id),
                license.index,
                crate::address_format::encode_for(&body.destination, view),
                destination_label.text()
            ),
        )
    };

    Ok(ReviewDraft {
        kind: OperationKind::DividendClaim,
        schema: SCHEMA,
        title,
        summary,
        signer: me.summary(),
        authorizations,
        parties,
        destinations,
        amount: Some(body.amount),
        returned: 0,
        fee,
        // Nothing leaves the signing wallet: the Treasury pays.
        net_debit: Some(0),
        inputs: Vec::new(),
        conditions,
        timing,
        effects,
        warnings,
        // The epoch basis and the owner-at-inclusion rule decide whether the claim pays at all.
        extra_acks: vec![AckKind::Conditions],
        high_risk: false,
    })
}

// ---------------------------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------------------------

impl OperationHandler for DividendHandler {
    fn kind(&self) -> OperationKind {
        OperationKind::DividendClaim
    }

    fn recognizes(&self, raw: &[u8]) -> bool {
        SignedClaim::decode(raw).is_ok()
    }

    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        signer: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let OperationRequest::DividendClaim(request) = request else {
            return Err(Refusal::UnknownOperation);
        };
        let claim = build_claim(request, view, signer)?;
        assemble_plan(&claim, view, signer)
    }

    fn adopt(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let claim = decode(raw)?;
        if !is_unsigned(&claim.signature) {
            return Err(Refusal::Malformed(
                "these bytes are already signed: there is nothing left to sign",
            ));
        }
        if claim.descriptor != me.descriptor() {
            return Err(Refusal::NotRequiredSigner(Slot::Claim));
        }
        me.check_current(view)?;
        select::require_profile_for_treasury(view, me)?;
        assemble_plan(&claim, view, me)
    }

    fn validate(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<(), Refusal> {
        let claim = plan_claim(plan)?;
        // Whoever signs for the Treasury authority does so through the Treasury profile, however
        // the plan came to exist.
        select::require_profile_for_treasury(view, plan.signer())?;
        // A plan this wallet built or adopted is signed with this wallet's current key.
        if claim.descriptor != plan.signer().descriptor() {
            return Err(Refusal::NotRequiredSigner(Slot::Claim));
        }
        check_rules(&claim, view)?;
        require_unreserved(&claim.body, view)
    }

    fn review(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<ReviewDraft, Refusal> {
        let claim = plan_claim(plan)?;
        let facts = check_rules(&claim, view)?;
        build_review(&claim, &facts, view, plan.signer())
    }

    fn explain(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
        let claim = decode(raw)?;
        let facts = check_rules(&claim, view)?;
        require_unreserved(&claim.body, view)?;
        let draft = build_review(&claim, &facts, view, me)?;
        Ok((
            draft,
            vec![PlanObject::new(
                OBJECT_LABEL,
                unsigned_copy(&claim).encode(),
            )],
        ))
    }

    fn sign(
        &self,
        plan: &OperationPlan,
        signer: &KindSigner<'_>,
        _view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        let mut claim = plan_claim(plan)?;
        // Consensus' own `SignedClaim::sign` (the claim-intent payload under the transaction
        // domain), through the claim capability.
        signer.claim_authorization()?.authorize_claim(&mut claim)?;
        Ok(SignedOperation::Complete {
            kind: OperationKind::DividendClaim,
            id: claim.id(),
            bytes: claim.encode(),
            validity: *plan.validity(),
            reserved: plan.inputs().to_vec(),
        })
    }

    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        let claim = decode(raw)?;
        Ok(vec![PlanObject::new(
            OBJECT_LABEL,
            unsigned_copy(&claim).encode(),
        )])
    }

    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        let claim = decode(raw)?;
        if is_unsigned(&claim.signature) {
            return Err(Refusal::Malformed(
                "a dividend claim must be signed to be queued",
            ));
        }
        Ok(Description {
            id: claim.id(),
            complete: true,
            missing: Vec::new(),
            validity: validity_of(&claim.body),
            reserved: vec![claim_slot(claim.body.award_epoch, &claim.body.license)],
        })
    }

    fn check_signed(&self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<(), Refusal> {
        let SignedOperation::Complete {
            kind, id, bytes, ..
        } = signed
        else {
            return Err(Refusal::Malformed("a dividend claim is never partial"));
        };
        if *kind != OperationKind::DividendClaim {
            return Err(Refusal::UnknownOperation);
        }
        let claim = decode(bytes)?;
        if claim.id() != *id {
            return Err(Refusal::VerificationFailed(
                "operation identifier does not match the bytes",
            ));
        }
        // BOTH_REQUIRED: both halves of the signature must be present, then verified.
        if !both_halves_present(&claim) {
            return Err(Refusal::VerificationFailed(
                "the claim is missing a signature half",
            ));
        }
        check_rules(&claim, view)?;
        claim
            .verify_signature()
            .map_err(|_| Refusal::VerificationFailed("the claim signature does not verify"))?;
        // Independent verification through consensus code, at the next block's height and the
        // head's epoch (the lower bound for the including block's epoch).
        let context = view.context();
        dividend_claim_v1::admit(
            view.state(),
            bytes,
            context.genesis,
            context.fingerprint,
            view.next_height()?,
            view.epoch()?,
        )
        .map_err(|error| consensus_refusal(error, &claim, view))
    }

    fn reconcile(&self, record: &OutboxRecord, view: &ChainView<'_>) -> Settlement {
        if let Some(height) = view.confirmed_height(&record.id) {
            return Settlement::Confirmed(height);
        }
        // Included: the payout coin (or the Treasury change coin) the claim created exists.
        let state = view.state();
        for index in 0..2u32 {
            if let Some(coin) = state.coins.get(&OutPoint {
                transaction: record.id,
                index,
            }) {
                return Settlement::Confirmed(coin.created_height);
            }
        }
        let Ok(claim) = SignedClaim::decode(&record.bytes) else {
            return Settlement::Pending;
        };
        let body = &claim.body;
        let account = state
            .dividends
            .ledger()
            .award(body.award_epoch)
            .and_then(|award| award.account(&body.license));
        // The sequence was used, but not provably by this claim (another claim with the same
        // sequence, or this one with its coins spent again): it can never apply now.
        if account.is_some_and(|account| account.claims > body.sequence) {
            return Settlement::InputsSpent;
        }
        if view
            .next_height()
            .map_or(true, |next| next > record.validity.expiry)
        {
            return Settlement::Expired;
        }
        // The award is gone (removed at its deadline), or every later block is past the window.
        if account.is_none()
            || view
                .epoch()
                .is_ok_and(|epoch| epoch >= body.award_epoch.saturating_add(CLAIM_WINDOW_EPOCHS))
        {
            return Settlement::Expired;
        }
        Settlement::Pending
    }
}
