//! (a) Ordinary MUT payments: coin selection, fee, change, review, signing and verification.
//!
//! Ported from the desktop wallet's `payment_v2.rs` (`Draft::build` / `Draft::authorize`) and
//! generalised to the plan, review, authorize pipeline. Behaviour kept:
//!
//!  * coins are selected from the verified state only, never from a peer: not reserved, not newer
//!    than the head, coinbase coins mature, and controlled by this key through the wallet book
//!    (`WalletBook::authorize`, exactly as consensus resolves ownership);
//!  * at most 128 candidate coins are retained, largest first with a stable tie-break by outpoint, so
//!    attacker-supplied dust can never hide a spendable large coin;
//!  * the fee is a fixed point: hybrid signatures have fixed width, so the unsigned placeholder
//!    encoding is the exact signed size and the fee only ever rises to the largest size seen
//!    (one atom per encoded byte);
//!  * change returns to the signer's CURRENT-generation address;
//!  * after signing, the transfer is verified again through consensus code (`Transfer::verify`).
//!
//! Added: typed refusals instead of one generic error, the Treasury reserve hook, the full review,
//! and `explain` for transfers received from elsewhere.
use super::select;
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    capability::{KeySlot, KindSigner},
    context::{ChainView, is_treasury_address, require_reserve_backing, treasury_authority},
    outbox::{OutboxRecord, Settlement},
    plan::{
        Description, OperationHandler, OperationKind, OperationPlan, OperationRequest,
        PaymentRequest, PlanObject, RequiredSigner, Requirement, RequirementStatus, Slot, Validity,
    },
    refusal::{ContextField, Refusal},
    review::{
        AckKind, AddressLabel, Condition, Destination, DestinationRole, Effect, Fee, FeePayer,
        FeeRule, InputLine, Party, PartyRole, ReviewDraft, Severity, Timing, Warning,
    },
    units,
};
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    transactions::{Coin, EXPIRY_HORIZON, MATURITY, MAX_TX_BYTES, OutPoint, Output, TxError},
    transactions_v2::{Input, Transfer},
};
use mutiny_crypto_v2::{Domain, HybridSignature, PublicKey};
use std::collections::BTreeSet;

/// Layout version of the payment plan objects.
pub const SCHEMA: u16 = 1;
/// Label of the one object of a payment plan.
pub const OBJECT_LABEL: &str = "transfer";
/// Codec limit on inputs of one transfer.
pub const MAX_INPUTS: usize = 128;
/// Approximate bytes (and so atoms of fee) one more signed input adds. Only used to warn about
/// change too small to be worth spending.
const APPROX_INPUT_BYTES: u64 = 3_400;
/// A payment this close to expiry gets a caution.
const EXPIRES_SOON_BLOCKS: u64 = 3;

pub(crate) struct PaymentHandler;
pub(crate) static HANDLER: PaymentHandler = PaymentHandler;

pub(crate) fn zero_signature() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}

pub(crate) fn is_unsigned(signature: &HybridSignature) -> bool {
    signature.ed448 == [0; 114] && signature.fndsa == [0; 1280]
}

/// The same transfer with every signature replaced by the zero placeholder.
pub(crate) fn unsigned_copy(transfer: &Transfer) -> Transfer {
    let mut copy = transfer.clone();
    for input in &mut copy.inputs {
        input.signature = zero_signature();
    }
    copy
}

pub(crate) fn encode(transfer: &Transfer) -> Result<Vec<u8>, Refusal> {
    transfer.encode().map_err(|error| match error {
        TxError::Bounds => Refusal::SizeLimit {
            limit: MAX_TX_BYTES,
        },
        _ => Refusal::Malformed("transfer does not encode"),
    })
}

pub(crate) fn decode(raw: &[u8]) -> Result<Transfer, Refusal> {
    Transfer::decode(raw).map_err(|_| Refusal::Malformed("not a canonical transfer"))
}

fn plan_transfer(plan: &OperationPlan) -> Result<Transfer, Refusal> {
    let [object] = plan.objects() else {
        return Err(Refusal::Malformed("a payment plan has exactly one object"));
    };
    if object.label != OBJECT_LABEL {
        return Err(Refusal::Malformed("unexpected plan object"));
    }
    decode(&object.bytes)
}

/// Map a consensus verification error to the wallet's typed refusal.
pub(crate) fn verify_refusal(error: TxError, transfer: &Transfer, height: u64) -> Refusal {
    match error {
        TxError::Codec => Refusal::Malformed("transfer encoding"),
        TxError::Binding => Refusal::WrongContext(ContextField::Genesis),
        TxError::Bounds => Refusal::SizeLimit {
            limit: MAX_TX_BYTES,
        },
        TxError::Duplicate => Refusal::Malformed("duplicate input"),
        TxError::Signature => Refusal::VerificationFailed("an input signature does not verify"),
        TxError::Expired => Refusal::WindowClosed {
            expiry: transfer.expiry_height,
            next_height: height,
        },
        TxError::Future => Refusal::WindowNotOpen {
            created: transfer.created_height,
            next_height: height,
        },
        TxError::MissingInput => Refusal::InputUnavailable,
        TxError::Immature => Refusal::ImmatureInput,
        TxError::Owner => Refusal::StaleAuthority,
        TxError::Conservation => Refusal::Conservation,
        TxError::Fee => Refusal::FeeBelowMinimum {
            fee: transfer.fee,
            minimum: transfer
                .encode()
                .map(|raw| raw.len() as u64)
                .unwrap_or(u64::MAX),
        },
        TxError::Overflow => Refusal::Overflow,
    }
}

// ---------------------------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------------------------

/// Build the unsigned transfer for a payment request.
pub(crate) fn build_transfer(
    request: &PaymentRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<Transfer, Refusal> {
    if request.amount_atoms == 0 {
        return Err(Refusal::InvalidAmount);
    }
    if request.recipient == [0; 32] {
        return Err(Refusal::InvalidRecipient);
    }
    if request.validity_blocks == 0 || request.validity_blocks > EXPIRY_HORIZON {
        return Err(Refusal::InvalidValidity);
    }
    signer.check_current(view)?;
    select::require_profile_for_treasury(view, signer)?;

    let amount = request.amount_atoms;
    let height = view.next_height()?;
    let expiry = height
        .checked_add(request.validity_blocks)
        .ok_or(Refusal::Overflow)?;
    let public = signer.public();
    let generation = signer.generation();
    let change_address = signer.address();
    let context = view.context();

    // Candidate coins: at most MAX_INPUTS retained (largest first, then outpoint order), but the
    // total of ALL eligible coins is tracked for an exact insufficient-funds report.
    let candidates = select::candidates(view, signer.descriptor(), MAX_INPUTS, &BTreeSet::new())?;
    let eligible = candidates.coins;
    let eligible_count = candidates.count;
    let available = candidates.total;
    if eligible.is_empty() {
        return Err(Refusal::NothingSpendable);
    }
    let available_clamped = u64::try_from(available).unwrap_or(u64::MAX);
    if available < u128::from(amount) {
        return Err(Refusal::InsufficientFunds {
            available: available_clamped,
            requested: amount,
        });
    }

    let mut transfer = Transfer {
        network: NETWORK_ID,
        genesis: context.genesis,
        fingerprint: context.fingerprint,
        created_height: height,
        expiry_height: expiry,
        fee: 0,
        inputs: vec![],
        outputs: vec![],
    };
    let mut incoming = 0u64;
    let mut needed_fee = 0u64;
    for (point, coin) in &eligible {
        incoming = incoming
            .checked_add(coin.output.atoms)
            .ok_or(Refusal::Overflow)?;
        transfer.inputs.push(
            Input::unsigned((*point).clone(), &public, generation)
                .map_err(|_| Refusal::InvalidDescriptor)?,
        );
        if incoming <= amount {
            continue;
        }
        match fit_outputs(
            &mut transfer,
            request.recipient,
            amount,
            change_address,
            incoming - amount,
        )? {
            Fit::Done => {
                let spent: BTreeSet<OutPoint> = transfer
                    .inputs
                    .iter()
                    .map(|input| input.point.clone())
                    .collect();
                require_reserve_backing(view, &spent, &transfer.outputs)?;
                return Ok(transfer);
            }
            Fit::NeedMore { fee } => needed_fee = fee,
        }
    }
    if eligible_count > eligible.len() {
        return Err(Refusal::TooManyInputs { limit: MAX_INPUTS });
    }
    if needed_fee == 0 {
        // Every eligible coin was consumed and still did not exceed the amount: the least fee any
        // shape needs is the size of the one-output payment.
        transfer.fee = 0;
        transfer.outputs = vec![Output {
            owner: request.recipient,
            atoms: amount,
        }];
        needed_fee = encoded_len(&transfer)?;
    }
    Err(Refusal::InsufficientFunds {
        available: available_clamped,
        requested: amount.saturating_add(needed_fee),
    })
}

/// Result of choosing outputs and fee for a given input set.
pub(crate) enum Fit {
    /// `transfer.fee` and `transfer.outputs` are final.
    Done,
    /// This input set cannot pay for itself; `fee` is the least fee its smallest shape needs.
    NeedMore { fee: u64 },
}

pub(crate) fn encoded_len(transfer: &Transfer) -> Result<u64, Refusal> {
    match transfer.encode() {
        Ok(raw) => Ok(raw.len() as u64),
        Err(TxError::Bounds) if transfer.inputs.len() > MAX_INPUTS => {
            Err(Refusal::TooManyInputs { limit: MAX_INPUTS })
        }
        Err(TxError::Bounds) => Err(Refusal::SizeLimit {
            limit: MAX_TX_BYTES,
        }),
        Err(_) => Err(Refusal::Malformed("transfer does not encode")),
    }
}

/// Choose the outputs and the fee for the current inputs, where `surplus` is inputs minus amount.
///
/// Fixed-width hybrid signatures make the unsigned placeholder encoding the exact signed size, so
/// the fee is a fixed point (`fee >= size(fee)`); integer-width changes can only raise it.
///
///  * Shape A: the payment plus change, with the least fee that covers the signed size. Preferred
///    whenever it leaves a positive change.
///  * Shape B: no change output; the whole surplus becomes the fee. Used only when shape A cannot
///    leave positive change but the surplus still covers the (smaller) signed size.
pub(crate) fn fit_outputs(
    transfer: &mut Transfer,
    recipient: Hash,
    amount: u64,
    change_address: Hash,
    surplus: u64,
) -> Result<Fit, Refusal> {
    let mut fee = 0u64;
    for _ in 0..16 {
        if fee >= surplus {
            break;
        }
        transfer.fee = fee;
        transfer.outputs = vec![
            Output {
                owner: recipient,
                atoms: amount,
            },
            Output {
                owner: change_address,
                atoms: surplus - fee,
            },
        ];
        let size = encoded_len(transfer)?;
        if size <= fee {
            return Ok(Fit::Done);
        }
        fee = size;
    }
    transfer.fee = surplus;
    transfer.outputs = vec![Output {
        owner: recipient,
        atoms: amount,
    }];
    let size = encoded_len(transfer)?;
    if size <= surplus {
        return Ok(Fit::Done);
    }
    Ok(Fit::NeedMore { fee: size })
}

// ---------------------------------------------------------------------------------------------
// Validation (pre-signing mirror of consensus)
// ---------------------------------------------------------------------------------------------

pub(crate) struct InputFact {
    pub coin: Coin,
    /// Whether the input's coin is controlled by the reviewing wallet.
    pub mine: bool,
}

pub(crate) struct Facts {
    pub inputs: Vec<InputFact>,
    pub size: u64,
}

/// Every consensus check that does not need a signature, against the CURRENT view. A transfer that
/// passes can be signed; one that fails could never be included at this head.
pub(crate) fn validate_transfer(
    transfer: &Transfer,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<Facts, Refusal> {
    view.require_context(transfer.network, &transfer.genesis, &transfer.fingerprint)?;
    let raw = encode(transfer)?;
    let next = view.next_height()?;
    if next < transfer.created_height {
        return Err(Refusal::WindowNotOpen {
            created: transfer.created_height,
            next_height: next,
        });
    }
    if next > transfer.expiry_height {
        return Err(Refusal::WindowClosed {
            expiry: transfer.expiry_height,
            next_height: next,
        });
    }
    let state = view.state();
    let mut incoming: u128 = 0;
    let mut inputs = Vec::with_capacity(transfer.inputs.len());
    for input in &transfer.inputs {
        let coin = state
            .coins
            .get(&input.point)
            .ok_or(Refusal::InputUnavailable)?;
        if view.reserved().contains(&input.point) {
            return Err(Refusal::ReservedInput);
        }
        if coin.created_height > next || (coin.coinbase && next - coin.created_height < MATURITY) {
            return Err(Refusal::ImmatureInput);
        }
        state
            .wallets
            .authorize(coin.output.owner, &input.descriptor)
            .map_err(|_| Refusal::StaleAuthority)?;
        incoming = incoming
            .checked_add(u128::from(coin.output.atoms))
            .ok_or(Refusal::Overflow)?;
        let mine = state
            .wallets
            .authorize(coin.output.owner, me.descriptor())
            .is_ok();
        inputs.push(InputFact {
            coin: coin.clone(),
            mine,
        });
    }
    let outgoing = transfer
        .outputs
        .iter()
        .try_fold(0u128, |sum, output| {
            sum.checked_add(u128::from(output.atoms))
        })
        .ok_or(Refusal::Overflow)?;
    let fee = incoming
        .checked_sub(outgoing)
        .ok_or(Refusal::Conservation)?;
    if fee != u128::from(transfer.fee) {
        return Err(Refusal::Conservation);
    }
    let size = raw.len() as u64;
    if transfer.fee < size {
        return Err(Refusal::FeeBelowMinimum {
            fee: transfer.fee,
            minimum: size,
        });
    }
    let spent: BTreeSet<OutPoint> = transfer
        .inputs
        .iter()
        .map(|input| input.point.clone())
        .collect();
    require_reserve_backing(view, &spent, &transfer.outputs)?;
    Ok(Facts { inputs, size })
}

pub(crate) fn input_signature_valid(transfer: &Transfer, index: usize) -> bool {
    let input = &transfer.inputs[index];
    let Ok((public, _)) = PublicKey::decode_descriptor(&input.descriptor) else {
        return false;
    };
    let Ok(payload) = transfer.signing_payload(index) else {
        return false;
    };
    public
        .verify(Domain::Transaction, &payload, &input.signature)
        .is_ok()
}

// ---------------------------------------------------------------------------------------------
// Review
// ---------------------------------------------------------------------------------------------

pub(crate) fn short(address: &Hash) -> String {
    units::short_hex(address)
}

/// The review of a transfer (unsigned, partly signed or signed) as seen from `me`.
pub(crate) fn build_review(
    transfer: &Transfer,
    facts: &Facts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
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

    // Inputs, authorizations and the value that leaves this wallet.
    let mut inputs = Vec::with_capacity(facts.inputs.len());
    let mut authorizations = Vec::with_capacity(facts.inputs.len());
    let mut warnings = Vec::new();
    let mut mine_in: u128 = 0;
    let mut total_in: u128 = 0;
    let mut treasury_input = false;
    for (index, (input, fact)) in transfer.inputs.iter().zip(&facts.inputs).enumerate() {
        inputs.push(InputLine {
            point: input.point.clone(),
            atoms: fact.coin.output.atoms,
            owned_by_signer: fact.mine,
            coinbase: fact.coin.coinbase,
        });
        total_in += u128::from(fact.coin.output.atoms);
        if fact.mine {
            mine_in += u128::from(fact.coin.output.atoms);
        }
        if treasury
            .as_ref()
            .is_some_and(|authority| is_treasury_address(view, authority, &fact.coin.output.owner))
        {
            treasury_input = true;
        }
        let status = if is_unsigned(&input.signature) {
            if fact.mine {
                RequirementStatus::ThisWallet
            } else {
                RequirementStatus::Counterparty
            }
        } else if input_signature_valid(transfer, index) {
            RequirementStatus::Provided
        } else {
            warnings.push(Warning::new(
                "BAD_SIGNATURE",
                Severity::Danger,
                format!("Input {index} carries a signature that does not verify. Do not rely on these bytes."),
            ));
            if fact.mine {
                RequirementStatus::ThisWallet
            } else {
                RequirementStatus::Counterparty
            }
        };
        authorizations.push(Requirement {
            slot: Slot::Input(index as u32),
            signer: RequiredSigner::Wallet(fact.coin.output.owner),
            status,
        });
    }

    // Outputs: what is sent away, what returns to this wallet as change, and what this wallet
    // receives from somebody else's payment.
    let any_mine = facts.inputs.iter().any(|fact| fact.mine);
    let mut destinations = Vec::with_capacity(transfer.outputs.len());
    let mut amount: u128 = 0;
    let mut returned: u128 = 0;
    let mut to_me: u128 = 0;
    for output in &transfer.outputs {
        let label = classify(&output.owner);
        let mine_out = label == AddressLabel::ThisWallet;
        let role = if mine_out && any_mine {
            DestinationRole::Change
        } else {
            DestinationRole::Payment
        };
        if mine_out {
            to_me += u128::from(output.atoms);
        }
        match role {
            DestinationRole::Change => returned += u128::from(output.atoms),
            _ => amount += u128::from(output.atoms),
        }
        destinations.push(Destination {
            role,
            address: output.owner,
            label,
            atoms: output.atoms,
        });
    }
    let amount = u64::try_from(amount).map_err(|_| Refusal::Overflow)?;
    let returned = u64::try_from(returned).map_err(|_| Refusal::Overflow)?;
    // What leaves this wallet in total; stated only when this wallet is not a net receiver.
    let net_debit = (mine_in >= to_me).then(|| mine_in - to_me);

    // Parties.
    let mut parties: Vec<Party> = Vec::new();
    let mut seen = BTreeSet::new();
    for fact in &facts.inputs {
        let address = fact.coin.output.owner;
        if seen.insert(address) {
            parties.push(Party {
                role: PartyRole::Sender,
                address,
                label: classify(&address),
            });
        }
    }
    for destination in destinations
        .iter()
        .filter(|d| d.role == DestinationRole::Payment)
    {
        parties.push(Party {
            role: PartyRole::Recipient,
            address: destination.address,
            label: destination.label,
        });
    }

    // Fee.
    let payer = if any_mine {
        FeePayer::ThisWallet
    } else {
        FeePayer::Counterparty(
            facts
                .inputs
                .first()
                .map(|fact| fact.coin.output.owner)
                .unwrap_or([0; 32]),
        )
    };
    let fee = Fee {
        atoms: transfer.fee,
        rule: FeeRule::OneAtomPerEncodedByte,
        payer,
        size_bytes: Some(facts.size),
    };

    // Timing and conditions.
    let head = view.anchor().height;
    let timing = Timing {
        head_height: head,
        created_height: Some(transfer.created_height),
        expiry_height: Some(transfer.expiry_height),
        valid_only_at: None,
        bound_to_parent: false,
        earliest_height: None,
        deadline_epoch: None,
    };
    let window = transfer.expiry_height.saturating_sub(head);
    let mut conditions = vec![
        Condition::new(
            "Validity window",
            format!(
                "Valid only for blocks {} to {} ({} blocks after the verified block; {}, approximate at the {} s target interval).",
                transfer.created_height,
                transfer.expiry_height,
                window,
                units::approx_blocks(window),
                units::TARGET_BLOCK_SECONDS
            ),
        ),
        Condition::new(
            "Inputs",
            format!(
                "All {} input coin(s) must still be unspent when the payment is included; a conflicting spend of any of them cancels this payment.",
                transfer.inputs.len()
            ),
        ),
        Condition::new(
            "Fee rule",
            format!(
                "The fee must be at least the encoded size of the signed payment: {} bytes, so {} atoms.",
                facts.size, facts.size
            ),
        ),
    ];
    if facts.inputs.iter().any(|fact| fact.coin.coinbase) {
        conditions.push(Condition::new(
            "Maturity",
            format!("Coinbase coins must be at least {MATURITY} blocks old."),
        ));
    }

    // Effects.
    let mut effects = vec![Effect::new(
        format!(
            "Spends {} coin(s) worth {}. A spent coin cannot be recovered once the payment is included.",
            transfer.inputs.len(),
            units::format_mut_wide(total_in)
        ),
        true,
    )];
    for destination in &destinations {
        match destination.role {
            DestinationRole::Payment => effects.push(Effect::new(
                format!(
                    "Pays {} to {} ({}). The recipient controls it from inclusion; there is no recall.",
                    units::format_mut(destination.atoms),
                    crate::address_format::encode_for(&destination.address, view),
                    destination.label.text()
                ),
                true,
            )),
            _ => effects.push(Effect::new(
                format!(
                    "Returns {} to {} ({}).",
                    units::format_mut(destination.atoms),
                    crate::address_format::encode_for(&destination.address, view),
                    destination.label.text()
                ),
                false,
            )),
        }
    }
    if transfer.fee > 0 {
        effects.push(Effect::new(
            format!(
                "Pays a network fee of {} to the block producer.",
                units::format_mut(transfer.fee)
            ),
            true,
        ));
    }
    effects.push(Effect::new(
        format!(
            "Once signed, the payment cannot be revoked: it stays valid until it is included or until block {}.",
            transfer.expiry_height
        ),
        true,
    ));
    if to_me > mine_in {
        effects.push(Effect::new(
            format!(
                "This wallet receives {}.",
                units::format_mut_wide(to_me - mine_in)
            ),
            false,
        ));
    }

    // Warnings.
    if view.class() == crate::context::ChainClass::TestValue {
        warnings.push(Warning::new(
            "TEST_VALUE_CHAIN",
            Severity::Notice,
            "This is a TEST-VALUE chain: nothing here has real value.",
        ));
    }
    if any_mine && amount == 0 {
        warnings.push(Warning::new(
            "SELF_PAYMENT",
            Severity::Notice,
            "Every output returns to this wallet: this only consolidates coins and spends the fee.",
        ));
    }
    if let Some(change) = destinations
        .iter()
        .find(|d| d.role == DestinationRole::Change && d.atoms < APPROX_INPUT_BYTES)
    {
        warnings.push(Warning::new(
            "DUST_CHANGE",
            Severity::Caution,
            format!(
                "The change of {} atoms costs about {APPROX_INPUT_BYTES} atoms in fees to spend later.",
                change.atoms
            ),
        ));
    }
    if destinations
        .iter()
        .any(|d| d.role == DestinationRole::Payment && d.label == AddressLabel::Treasury)
    {
        warnings.push(Warning::new(
            "TREASURY_DESTINATION",
            Severity::Notice,
            "A recipient is the Treasury address.",
        ));
    }
    if transfer.fee > facts.size {
        warnings.push(Warning::new(
            "FEE_ABOVE_MINIMUM",
            Severity::Caution,
            format!(
                "The fee is {} atoms above the minimum for this size.",
                transfer.fee - facts.size
            ),
        ));
    }
    if window <= EXPIRES_SOON_BLOCKS {
        warnings.push(Warning::new(
            "EXPIRES_SOON",
            Severity::Caution,
            format!("This payment expires in {window} block(s) after the verified block."),
        ));
    }
    if treasury_input {
        warnings.push(
            Warning::new(
                "TREASURY_FUNDS",
                Severity::Caution,
                "This spends Treasury funds. It moves MUT only; Bitcoin custody is separate and untouched.",
            )
            .requiring(AckKind::TreasuryAuthority),
        );
    }

    // Title and summary.
    let (title, summary) = if !any_mine {
        (
            "Payment between other wallets".to_string(),
            "This payment spends coins this wallet does not control; it cannot sign it."
                .to_string(),
        )
    } else if amount == 0 {
        (
            "Move MUT within this wallet".to_string(),
            format!(
                "All outputs return to this wallet; only the network fee of {} is spent.",
                units::format_mut(transfer.fee)
            ),
        )
    } else {
        let recipients: Vec<&Destination> = destinations
            .iter()
            .filter(|d| d.role == DestinationRole::Payment)
            .collect();
        let to = if recipients.len() == 1 {
            crate::address_format::encode_for(&recipients[0].address, view)
        } else {
            format!("{} recipients", recipients.len())
        };
        (
            "Send MUT".to_string(),
            format!(
                "Send {} to {} with a network fee of {}.",
                units::format_mut(amount),
                to,
                units::format_mut(transfer.fee)
            ),
        )
    };

    Ok(ReviewDraft {
        kind: OperationKind::Payment,
        schema: SCHEMA,
        title,
        summary,
        signer: me.summary(),
        authorizations,
        parties,
        destinations,
        amount: Some(amount),
        returned,
        fee,
        net_debit,
        inputs,
        conditions,
        timing,
        effects,
        warnings,
        extra_acks: Vec::new(),
        high_risk: false,
    })
}

// ---------------------------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------------------------

/// The immutable plan for an unsigned transfer whose inputs are all controlled by `signer`. A plan
/// must pass its own validation at the head it is built for.
pub(crate) fn assemble_plan(
    transfer: &Transfer,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    let bytes = encode(transfer)?;
    let state = view.state();
    let mut requirements = Vec::with_capacity(transfer.inputs.len());
    for (index, input) in transfer.inputs.iter().enumerate() {
        let coin = state
            .coins
            .get(&input.point)
            .ok_or(Refusal::InputUnavailable)?;
        requirements.push(Requirement {
            slot: Slot::Input(index as u32),
            signer: RequiredSigner::Wallet(coin.output.owner),
            status: RequirementStatus::ThisWallet,
        });
    }
    let validity = Validity {
        created: transfer.created_height,
        expiry: transfer.expiry_height,
        valid_only_at: None,
        bound_to_parent: false,
    };
    let plan = OperationPlan::assemble(
        OperationKind::Payment,
        SCHEMA,
        signer.clone(),
        vec![PlanObject::new(OBJECT_LABEL, bytes)],
        requirements,
        transfer
            .inputs
            .iter()
            .map(|input| input.point.clone())
            .collect(),
        validity,
        view,
    );
    HANDLER.validate(&plan, view)?;
    Ok(plan)
}

impl OperationHandler for PaymentHandler {
    fn kind(&self) -> OperationKind {
        OperationKind::Payment
    }

    fn recognizes(&self, raw: &[u8]) -> bool {
        Transfer::decode(raw).is_ok()
    }

    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        signer: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let OperationRequest::Payment(request) = request else {
            return Err(Refusal::UnknownOperation);
        };
        let transfer = build_transfer(request, view, signer)?;
        assemble_plan(&transfer, view, signer)
    }

    fn adopt(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let transfer = decode(raw)?;
        if transfer
            .inputs
            .iter()
            .any(|input| !is_unsigned(&input.signature))
        {
            return Err(Refusal::Malformed(
                "these bytes are already signed: there is nothing left to sign",
            ));
        }
        for (index, input) in transfer.inputs.iter().enumerate() {
            if input.descriptor != me.descriptor() {
                return Err(Refusal::NotRequiredSigner(Slot::Input(index as u32)));
            }
        }
        me.check_current(view)?;
        assemble_plan(&transfer, view, me)
    }

    fn validate(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<(), Refusal> {
        let transfer = plan_transfer(plan)?;
        // Whoever signs for the Treasury authority does so through the Treasury profile, however
        // the plan came to exist (built here or adopted from bytes).
        select::require_profile_for_treasury(view, plan.signer())?;
        // Every input of a plan this wallet built is for this wallet's current descriptor.
        for (index, input) in transfer.inputs.iter().enumerate() {
            if input.descriptor != plan.signer().descriptor() {
                return Err(Refusal::NotRequiredSigner(Slot::Input(index as u32)));
            }
        }
        validate_transfer(&transfer, view, plan.signer()).map(|_| ())
    }

    fn review(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<ReviewDraft, Refusal> {
        let transfer = plan_transfer(plan)?;
        let facts = validate_transfer(&transfer, view, plan.signer())?;
        build_review(&transfer, &facts, view, plan.signer())
    }

    fn explain(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
        let transfer = decode(raw)?;
        let facts = validate_transfer(&transfer, view, me)?;
        let draft = build_review(&transfer, &facts, view, me)?;
        let unsigned = encode(&unsigned_copy(&transfer))?;
        Ok((draft, vec![PlanObject::new(OBJECT_LABEL, unsigned)]))
    }

    fn sign(
        &self,
        plan: &OperationPlan,
        signer: &KindSigner<'_>,
        _view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        let mut transfer = plan_transfer(plan)?;
        let spend = signer.transfer_spend(KeySlot::Primary)?;
        for index in 0..transfer.inputs.len() {
            spend
                .authorize_input(&mut transfer, index)
                .map_err(|error| match error {
                    TxError::Owner => Refusal::NotRequiredSigner(Slot::Input(index as u32)),
                    _ => Refusal::SigningFailed,
                })?;
        }
        let id = transfer
            .id()
            .map_err(|_| Refusal::Malformed("transfer identity"))?;
        let bytes = encode(&transfer)?;
        Ok(SignedOperation::Complete {
            kind: OperationKind::Payment,
            id,
            bytes,
            validity: *plan.validity(),
            reserved: plan.inputs().to_vec(),
        })
    }

    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        let transfer = decode(raw)?;
        Ok(vec![PlanObject::new(
            OBJECT_LABEL,
            encode(&unsigned_copy(&transfer))?,
        )])
    }

    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        let transfer = decode(raw)?;
        if transfer
            .inputs
            .iter()
            .any(|input| is_unsigned(&input.signature))
        {
            return Err(Refusal::Malformed(
                "a payment must be fully signed to be queued",
            ));
        }
        let mut reserved: Vec<OutPoint> = transfer
            .inputs
            .iter()
            .map(|input| input.point.clone())
            .collect();
        reserved.sort();
        reserved.dedup();
        Ok(Description {
            id: transfer
                .id()
                .map_err(|_| Refusal::Malformed("transfer identity"))?,
            complete: true,
            missing: Vec::new(),
            validity: Validity {
                created: transfer.created_height,
                expiry: transfer.expiry_height,
                valid_only_at: None,
                bound_to_parent: false,
            },
            reserved,
        })
    }

    fn check_signed(&self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<(), Refusal> {
        let SignedOperation::Complete {
            kind, id, bytes, ..
        } = signed
        else {
            return Err(Refusal::Malformed("a payment is never partial"));
        };
        if *kind != OperationKind::Payment {
            return Err(Refusal::UnknownOperation);
        }
        let transfer = decode(bytes)?;
        if transfer
            .id()
            .map_err(|_| Refusal::Malformed("transfer identity"))?
            != *id
        {
            return Err(Refusal::VerificationFailed(
                "operation identifier does not match the bytes",
            ));
        }
        // BOTH_REQUIRED: both halves of every input signature must be present, then verified.
        for input in &transfer.inputs {
            if input.signature.ed448 == [0; 114] || input.signature.fndsa == [0; 1280] {
                return Err(Refusal::VerificationFailed(
                    "an input is missing a signature half",
                ));
            }
        }
        view.require_context(transfer.network, &transfer.genesis, &transfer.fingerprint)?;
        let next = view.next_height()?;
        let state = view.state();
        // Independent verification through consensus code, at the next block's height.
        transfer
            .verify(
                transfer.genesis,
                transfer.fingerprint,
                next,
                &state.coins,
                &state.wallets,
            )
            .map_err(|error| verify_refusal(error, &transfer, next))?;
        let spent: BTreeSet<OutPoint> = transfer
            .inputs
            .iter()
            .map(|input| input.point.clone())
            .collect();
        require_reserve_backing(view, &spent, &transfer.outputs)
    }

    fn reconcile(&self, record: &OutboxRecord, view: &ChainView<'_>) -> Settlement {
        let coins = &view.state().coins;
        if let Some(height) = view.confirmed_height(&record.id) {
            return Settlement::Confirmed(height);
        }
        // Included: one of its outputs exists as a coin created by it.
        let outputs = Transfer::decode(&record.bytes)
            .map(|transfer| transfer.outputs.len())
            .unwrap_or(0);
        for index in 0..outputs {
            if let Some(coin) = coins.get(&OutPoint {
                transaction: record.id,
                index: index as u32,
            }) {
                return Settlement::Confirmed(coin.created_height);
            }
        }
        if view
            .next_height()
            .map_or(true, |next| next > record.validity.expiry)
        {
            return Settlement::Expired;
        }
        if record
            .reserved
            .iter()
            .any(|point| !coins.contains_key(point))
        {
            return Settlement::InputsSpent;
        }
        Settlement::Pending
    }
}
