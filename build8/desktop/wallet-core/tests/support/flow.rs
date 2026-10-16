// The complete human flow, driven the way a UI does it: present the review, enter every typed
// destination check, give every acknowledgement the review asks for, type the confirmation phrase
// of a high-risk review, take the approval.
//
// Owned by phase 1 of the wallet plan. Phase 8 added the confirmation phrase (phases 2, 4, 5A, 5B
// and 6 had each copied this flow with the phrase; those copies now use this file).
#![allow(dead_code)]

use mutiny_wallet_core_v8::{
    Approval, ChainView, Freshness, KeySigner, OperationPlan, Refusal, Review, ReviewGate,
    SignedOperation, Signer, review,
};

/// Everything a person must do before the approval exists, on a gate the caller keeps (to clear it,
/// replace what it shows or move its head afterwards).
pub fn approve_on(gate: &mut ReviewGate, review: &Review, view: &ChainView<'_>) -> Approval {
    assert_eq!(gate.present(review, view), Freshness::Fresh);
    for index in review.destinations_needing_check() {
        gate.confirm_destination(index, &review.destination_check_text(index))
            .unwrap();
    }
    for ack in review.acknowledgements() {
        gate.acknowledge(*ack).unwrap();
    }
    // A high-risk review (`Review::requires_phrase`) also needs its confirmation phrase, which a UI
    // shows for the person to type.
    if let Some(phrase) = review.confirmation_phrase() {
        gate.confirm_phrase(&phrase).unwrap();
    }
    gate.approve(view).unwrap()
}

/// Everything a person must do before the approval exists, on a gate of its own.
pub fn approve(review: &Review, view: &ChainView<'_>) -> Approval {
    approve_on(&mut ReviewGate::new(), review, view)
}

/// Review, approve and authorize `plan` with `signer`.
pub fn sign(
    plan: OperationPlan,
    signer: &KeySigner,
    view: &ChainView<'_>,
) -> Result<SignedOperation, Refusal> {
    let reviewed = review(&plan, view)?;
    let approval = approve(&reviewed, view);
    signer.authorize(plan, approval, view)
}
