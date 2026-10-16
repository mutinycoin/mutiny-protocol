//! The approval step and the plan state machine: single use, plan binding, head binding, expiry,
//! lock, typed acknowledgements and typed destination checks, and the legal transitions of a plan
//! from "built" to "queued". NATIVE, TEST-VALUE; public test keys only.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_wallet_core_v8::*;
use std::time::{Duration, Instant};
use synthetic::{World, address, identity, key_a, key_b};

fn pay(recipient: [u8; 32], amount: u64) -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(recipient, amount))
}

/// Key derivation is slow, so the public parts of the two test wallets are computed once.
fn scenario() -> (World, SignerIdentity, OperationPlan) {
    static PUBLIC: std::sync::OnceLock<(SignerIdentity, [u8; 32], [u8; 32])> =
        std::sync::OnceLock::new();
    let (me, owner, recipient) = PUBLIC
        .get_or_init(|| {
            (
                identity(&key_a()),
                address(&key_a(), 1),
                address(&key_b(), 1),
            )
        })
        .clone();
    let mut world = World::new(100);
    world.coin(owner, 5_000_000, 1, false, 1, 0);
    let planned = plan(&pay(recipient, 1_000_000), &world.view(), &me).unwrap();
    (world, me, planned)
}

// Compile-time proof that `Approval` is not `Clone`: if it ever became `Clone`, the two blanket
// impls below would both apply and this test file would stop compiling.
trait AmbiguousIfClone<A> {
    fn probe() {}
}
impl<T: ?Sized> AmbiguousIfClone<()> for T {}
impl<T: Clone> AmbiguousIfClone<u8> for T {}

#[test]
fn an_approval_is_not_clone_and_is_consumed_by_authorization() {
    let _ = <Approval as AmbiguousIfClone<_>>::probe;
    let (world, _, planned) = scenario();
    let view = world.view();
    let signer = KeySigner::for_test(key_a()).unwrap();
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    assert_eq!(approval.kind(), OperationKind::Payment);
    assert_eq!(approval.anchor().height, 100);
    // `authorize` takes the approval by value: after this line `approval` cannot be named again.
    let signed = signer.authorize(planned, approval, &view).unwrap();
    assert!(signed.is_complete());
}

#[test]
fn a_gate_issues_one_approval_per_presentation_and_forgets_everything_after() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let mut gate = ReviewGate::new();
    assert_eq!(
        gate.approve(&view).unwrap_err(),
        Refusal::NotPresented,
        "nothing on screen"
    );
    assert_eq!(gate.present(&reviewed, &view), Freshness::Fresh);
    for index in reviewed.destinations_needing_check() {
        gate.confirm_destination(index, &reviewed.destination_check_text(index))
            .unwrap();
    }
    for ack in reviewed.acknowledgements() {
        gate.acknowledge(*ack).unwrap();
    }
    assert!(gate.is_ready(&view));
    let first = gate.approve(&view).unwrap();
    assert_eq!(first.digest(), reviewed.binding());
    assert!(!gate.is_presenting());
    assert_eq!(
        gate.approve(&view).unwrap_err(),
        Refusal::NotPresented,
        "single use"
    );
    // Presenting again starts from nothing.
    gate.present(&reviewed, &view);
    assert_eq!(
        gate.pending_acknowledgements(),
        reviewed.acknowledgements().to_vec()
    );
}

#[test]
fn rendering_a_review_cannot_approve_it() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let mut gate = ReviewGate::new();
    gate.present(&reviewed, &view);
    // Presenting (rendering) alone, any number of times, never produces an approval.
    for _ in 0..3 {
        gate.present(&reviewed, &view);
        assert_eq!(
            gate.approve(&view).unwrap_err(),
            Refusal::AcknowledgementMissing(AckKind::Destination)
        );
    }
    assert!(
        gate.is_presenting(),
        "a refused approval keeps the review on screen"
    );
    assert!(!gate.is_ready(&view));
}

#[test]
fn acknowledgements_are_typed_and_the_destination_needs_a_typed_check() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    assert_eq!(
        reviewed.acknowledgements(),
        &[
            AckKind::Destination,
            AckKind::Amount,
            AckKind::Fee,
            AckKind::Irreversible
        ]
    );
    let mut gate = ReviewGate::new();
    assert_eq!(
        gate.acknowledge(AckKind::Fee).unwrap_err(),
        Refusal::NotPresented
    );
    assert_eq!(
        gate.confirm_destination(0, "x").unwrap_err(),
        Refusal::NotPresented
    );
    gate.present(&reviewed, &view);

    // Only the kinds the review asks for.
    assert_eq!(
        gate.acknowledge(AckKind::KeyLoss).unwrap_err(),
        Refusal::UnexpectedAcknowledgement(AckKind::KeyLoss)
    );
    // The destination acknowledgement waits for the typed check of the (only) external destination.
    assert_eq!(reviewed.destinations_needing_check(), vec![0]);
    assert_eq!(
        gate.acknowledge(AckKind::Destination).unwrap_err(),
        Refusal::DestinationCheckPending
    );
    assert_eq!(
        gate.confirm_destination(0, "deadbeef").unwrap_err(),
        Refusal::DestinationCheckFailed
    );
    assert_eq!(
        gate.confirm_destination(1, &reviewed.destination_check_text(0))
            .unwrap_err(),
        Refusal::DestinationCheckFailed,
        "the change is not checked"
    );
    assert_eq!(
        gate.confirm_destination(9, "x").unwrap_err(),
        Refusal::DestinationCheckFailed
    );
    let typed = format!(
        "  {}  ",
        reviewed.destination_check_text(0).to_ascii_uppercase()
    );
    gate.confirm_destination(0, &typed)
        .expect("case and surrounding space do not matter");
    gate.acknowledge(AckKind::Destination).unwrap();
    // One by one: approval waits for each remaining acknowledgement and names the next missing one.
    assert_eq!(
        gate.approve(&view).unwrap_err(),
        Refusal::AcknowledgementMissing(AckKind::Amount)
    );
    gate.acknowledge(AckKind::Amount).unwrap();
    assert_eq!(
        gate.approve(&view).unwrap_err(),
        Refusal::AcknowledgementMissing(AckKind::Fee)
    );
    gate.acknowledge(AckKind::Fee).unwrap();
    assert_eq!(gate.pending_acknowledgements(), vec![AckKind::Irreversible]);
    assert_eq!(
        gate.approve(&view).unwrap_err(),
        Refusal::AcknowledgementMissing(AckKind::Irreversible)
    );
    gate.acknowledge(AckKind::Irreversible).unwrap();
    assert!(gate.approve(&view).is_ok());
}

#[test]
fn presenting_a_different_review_clears_every_acknowledgement() {
    let (world, me, planned) = scenario();
    let view = world.view();
    let first = review(&planned, &view).unwrap();
    let other_plan = plan(&pay(address(&key_b(), 1), 2_000_000), &view, &me).unwrap();
    let second = review(&other_plan, &view).unwrap();
    assert_ne!(first.binding(), second.binding());

    let mut gate = ReviewGate::new();
    gate.present(&first, &view);
    gate.confirm_destination(0, &first.destination_check_text(0))
        .unwrap();
    gate.acknowledge(AckKind::Destination).unwrap();
    gate.acknowledge(AckKind::Fee).unwrap();
    assert_eq!(gate.pending_acknowledgements().len(), 2);
    // The same review again keeps what was given; another review starts over.
    gate.present(&first, &view);
    assert_eq!(gate.pending_acknowledgements().len(), 2);
    gate.present(&second, &view);
    assert_eq!(
        gate.pending_acknowledgements(),
        second.acknowledgements().to_vec()
    );
    assert_eq!(
        gate.acknowledge(AckKind::Destination).unwrap_err(),
        Refusal::DestinationCheckPending,
        "the typed check must be entered again"
    );
}

#[test]
fn a_new_head_clears_the_review_the_acknowledgements_and_the_approval() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let next = world.advanced();
    let next_view = next.view();

    // Presenting a review for another head is stale and drops everything.
    let mut gate = ReviewGate::new();
    gate.present(&reviewed, &view);
    assert_eq!(gate.present(&reviewed, &next_view), Freshness::Stale);
    assert!(!gate.is_presenting());

    // The head moves while a review is on screen with every acknowledgement given.
    let mut gate = ReviewGate::new();
    gate.present(&reviewed, &view);
    gate.confirm_destination(0, &reviewed.destination_check_text(0))
        .unwrap();
    for ack in reviewed.acknowledgements() {
        gate.acknowledge(*ack).unwrap();
    }
    assert!(gate.is_ready(&view) && !gate.is_ready(&next_view));
    gate.on_head(&next_view);
    assert!(!gate.is_presenting());
    assert_eq!(gate.approve(&next_view).unwrap_err(), Refusal::NotPresented);

    // Approving against a different head than the one reviewed is StaleHead and clears.
    let mut gate = ReviewGate::new();
    gate.present(&reviewed, &view);
    gate.confirm_destination(0, &reviewed.destination_check_text(0))
        .unwrap();
    for ack in reviewed.acknowledgements() {
        gate.acknowledge(*ack).unwrap();
    }
    assert_eq!(
        gate.approve(&next_view).unwrap_err(),
        Refusal::StaleHead {
            reviewed: 100,
            current: 101
        }
    );
    assert!(!gate.is_presenting());

    // An approval already issued dies with the head too.
    let signer = KeySigner::for_test(key_a()).unwrap();
    let approval = flow::approve(&reviewed, &view);
    assert_eq!(
        signer.authorize(planned, approval, &next_view).unwrap_err(),
        Refusal::StaleHead {
            reviewed: 100,
            current: 101
        }
    );
}

#[test]
fn the_session_walks_the_legal_path_and_refuses_the_illegal_ones() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let signer = KeySigner::for_test(key_a()).unwrap();
    let mut outbox = MemoryOutbox::new();

    let mut session = PlanSession::new(planned);
    assert_eq!(session.phase(), PlanPhase::Planned);
    // Nothing works out of order.
    assert_eq!(
        session.acknowledge(AckKind::Fee).unwrap_err(),
        Refusal::NotPresented
    );
    assert_eq!(session.approve(&view).unwrap_err(), Refusal::NotPresented);
    assert_eq!(session.note_queued().unwrap_err(), Refusal::NotPresented);

    let reviewed = session.present(&view).unwrap().clone();
    assert_eq!(session.phase(), PlanPhase::Presented);
    assert_eq!(session.review().unwrap().binding(), reviewed.binding());
    assert!(matches!(
        session.approve(&view),
        Err(Refusal::AcknowledgementMissing(_))
    ));
    for index in reviewed.destinations_needing_check() {
        session
            .confirm_destination(index, &reviewed.destination_check_text(index))
            .unwrap();
    }
    for ack in reviewed.acknowledgements() {
        session.acknowledge(*ack).unwrap();
    }
    let approval = session.approve(&view).unwrap();
    assert_eq!(session.phase(), PlanPhase::Approved);
    assert_eq!(
        session.acknowledge(AckKind::Fee).unwrap_err(),
        Refusal::NotPresented,
        "no more acknowledgements once approved"
    );
    let signed = session.authorize(&signer, approval, &view).unwrap();
    assert_eq!(session.phase(), PlanPhase::Signed);
    assert!(session.review().is_none());
    // A signature cannot be taken back.
    assert_eq!(
        session.discard().unwrap_err(),
        Refusal::CancelNotAvailable(CancelTarget::SignedOperation)
    );
    assert_eq!(session.present(&view).unwrap_err(), Refusal::NotPresented);
    outbox.commit(&signed, &view).unwrap();
    session.note_queued().unwrap();
    assert_eq!(session.phase(), PlanPhase::Queued);
    assert!(session.phase().is_terminal());
    assert_eq!(
        session.discard().unwrap_err(),
        Refusal::CancelNotAvailable(CancelTarget::SignedOperation)
    );
}

#[test]
fn a_refused_authorization_sends_the_session_back_to_a_fresh_review() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let stranger = KeySigner::for_test(key_b()).unwrap();

    let mut session = PlanSession::new(planned);
    let reviewed = session.present(&view).unwrap().clone();
    for index in reviewed.destinations_needing_check() {
        session
            .confirm_destination(index, &reviewed.destination_check_text(index))
            .unwrap();
    }
    for ack in reviewed.acknowledgements() {
        session.acknowledge(*ack).unwrap();
    }
    let approval = session.approve(&view).unwrap();
    assert!(session.authorize(&stranger, approval, &view).is_err());
    assert_eq!(
        session.phase(),
        PlanPhase::Planned,
        "the consumed approval needs a new review"
    );
    assert!(!session.gate().is_presenting());
    // The plan is still there, and discarding it before signing is allowed.
    assert!(session.plan().is_some());
    session.present(&view).unwrap();
    session.discard().unwrap();
    assert_eq!(session.phase(), PlanPhase::Discarded);
    assert!(session.plan().is_none());
}

#[test]
fn a_new_head_requires_a_new_review_and_an_expired_window_ends_the_plan() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let mut session = PlanSession::new(planned);
    let first = session.present(&view).unwrap().clone();
    for index in first.destinations_needing_check() {
        session
            .confirm_destination(index, &first.destination_check_text(index))
            .unwrap();
    }
    session.acknowledge(AckKind::Fee).unwrap();

    // One block later: the review is dropped, the plan survives, a new review has a new digest.
    let next = world.advanced();
    session.on_head(&next.view());
    assert_eq!(session.phase(), PlanPhase::Planned);
    assert!(session.review().is_none());
    let second = session.present(&next.view()).unwrap().clone();
    assert_ne!(first.binding(), second.binding());
    assert_eq!(
        session.gate().pending_acknowledgements(),
        second.acknowledgements().to_vec(),
        "acknowledgements start over"
    );

    // The window (blocks 101 to 245) closes: nothing remains.
    let mut late = World::new(245);
    late.state = world.state.clone();
    session.on_head(&late.view());
    assert_eq!(
        session.phase(),
        PlanPhase::Invalidated(Invalidation::Expired)
    );
    assert!(session.plan().is_none());
    assert_eq!(
        session.present(&late.view()).unwrap_err(),
        Refusal::NotPresented
    );
}

#[test]
fn locking_drops_the_review_the_approval_path_and_the_plan() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let signer = KeySigner::for_test(key_a()).unwrap();

    let mut session = PlanSession::new(planned.clone());
    let reviewed = session.present(&view).unwrap().clone();
    for index in reviewed.destinations_needing_check() {
        session
            .confirm_destination(index, &reviewed.destination_check_text(index))
            .unwrap();
    }
    for ack in reviewed.acknowledgements() {
        session.acknowledge(*ack).unwrap();
    }
    let approval = session.approve(&view).unwrap();
    session.lock();
    assert_eq!(
        session.phase(),
        PlanPhase::Invalidated(Invalidation::Locked)
    );
    assert!(
        session.plan().is_none() && session.review().is_none() && !session.gate().is_presenting()
    );
    // The approval is still in the caller's hands, but the lock withdrew it: handing it straight to
    // the signer (bypassing the session) is refused too.
    assert_eq!(
        signer
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        Refusal::ApprovalRevoked
    );
    // And through the session nothing works any more.
    let other = flow::approve(&reviewed, &view);
    assert_eq!(
        session.authorize(&signer, other, &view).unwrap_err(),
        Refusal::NotPresented
    );
    assert_eq!(session.approve(&view).unwrap_err(), Refusal::NotPresented);

    // The key side locks as well: an approval that outlived the session is useless.
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    signer.lock();
    assert_eq!(
        signer.authorize(planned, approval, &view).unwrap_err(),
        Refusal::Locked
    );
}

#[test]
fn a_gate_withdraws_the_approval_it_issued_even_while_the_caller_holds_it() {
    let (world, me, planned) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let other_plan = plan(&pay(address(&key_b(), 1), 2_000_000), &view, &me).unwrap();
    let other = review(&other_plan, &view).unwrap();
    let signer = KeySigner::for_test(key_a()).unwrap();
    let mut gate = ReviewGate::new();
    let revoked = Refusal::ApprovalRevoked;

    // Cleared: a lock, an expiry or a cancel.
    let approval = flow::approve_on(&mut gate, &reviewed, &view);
    gate.clear();
    assert_eq!(
        signer
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        revoked
    );

    // Something else put on screen, or the same review shown again (nothing is approved until
    // everything is acknowledged again).
    let approval = flow::approve_on(&mut gate, &reviewed, &view);
    gate.present(&other, &view);
    assert_eq!(
        signer
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        revoked
    );
    let approval = flow::approve_on(&mut gate, &reviewed, &view);
    gate.present(&reviewed, &view);
    assert_eq!(
        signer
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        revoked
    );

    // At most one live approval per gate: a newer one withdraws the older.
    let first = flow::approve_on(&mut gate, &reviewed, &view);
    let second = flow::approve_on(&mut gate, &reviewed, &view);
    assert_eq!(
        signer.authorize(planned.clone(), first, &view).unwrap_err(),
        revoked
    );
    assert!(signer.authorize(planned.clone(), second, &view).is_ok());

    // A new head the gate hears about, after the approval was taken: withdrawn whichever view the
    // caller then uses (here the very view it was issued for, which would otherwise succeed).
    let approval = flow::approve_on(&mut gate, &reviewed, &view);
    assert!(!gate.is_presenting(), "nothing is on screen after approval");
    gate.on_head(&world.advanced().view());
    assert_eq!(
        signer
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        revoked
    );
    // A gate that heard about the SAME head withdraws nothing.
    let approval = flow::approve_on(&mut gate, &reviewed, &view);
    gate.on_head(&view);
    assert!(signer.authorize(planned.clone(), approval, &view).is_ok());

    // Gates are independent: clearing one does not touch an approval from another.
    let from_other_gate = flow::approve(&reviewed, &view);
    gate.clear();
    assert!(
        signer
            .authorize(planned.clone(), from_other_gate, &view)
            .is_ok()
    );
}

#[test]
fn an_approval_stamped_in_the_future_or_past_its_limit_is_refused() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let signer = KeySigner::for_test(key_a()).unwrap();
    let now = Instant::now();
    let expired = Refusal::Expired(ExpiryKind::Approval);

    // Stamped a minute ahead of the signer's clock (a manipulated clock): as unusable as an old one.
    let future = Approval::for_review_for_test(&reviewed, now + Duration::from_secs(60));
    assert_eq!(
        signer
            .authorize_at(planned.clone(), future, &view, now)
            .unwrap_err(),
        expired
    );
    // Exactly at the limit still works; one millisecond past it does not.
    let at_limit = Approval::for_review_for_test(&reviewed, now);
    assert!(
        signer
            .authorize_at(planned.clone(), at_limit, &view, now + MAX_APPROVAL_AGE)
            .is_ok()
    );
    let beyond = Approval::for_review_for_test(&reviewed, now);
    assert_eq!(
        signer
            .authorize_at(
                planned.clone(),
                beyond,
                &view,
                now + MAX_APPROVAL_AGE + Duration::from_millis(1)
            )
            .unwrap_err(),
        expired
    );
}

#[test]
fn approvals_and_reviews_have_explicit_age_limits() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    // Custom limits: a zero-length review window expires immediately.
    let mut gate = ReviewGate::with_limits(Duration::ZERO, MAX_APPROVAL_AGE);
    let long_ago = Instant::now()
        .checked_sub(Duration::from_millis(50))
        .expect("clock has history");
    gate.present_at(&reviewed, &view, long_ago);
    gate.confirm_destination(0, &reviewed.destination_check_text(0))
        .unwrap();
    for ack in reviewed.acknowledgements() {
        gate.acknowledge(*ack).unwrap();
    }
    assert_eq!(
        gate.approve(&view).unwrap_err(),
        Refusal::Expired(ExpiryKind::Review)
    );
    assert!(
        MAX_REVIEW_AGE > MAX_APPROVAL_AGE,
        "a person reads for longer than an approval may wait"
    );
}

#[test]
fn debug_output_of_the_approval_path_is_compact() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let approval = flow::approve(&reviewed, &view);
    let mut gate = ReviewGate::new();
    gate.present(&reviewed, &view);
    let session = PlanSession::new(planned);
    for text in [
        format!("{approval:?}"),
        format!("{gate:?}"),
        format!("{session:?}"),
        format!("{reviewed:?}"),
    ] {
        assert!(text.len() < 600, "{text}");
    }
}

#[test]
fn an_approval_given_for_another_wallets_reading_of_the_same_bytes_cannot_authorize_the_plan() {
    let (world, _, planned) = scenario();
    let view = world.view();
    let own = review(&planned, &view).unwrap();
    // Wallet B reads the very same unsigned bytes at the very same head: the digest is the same (one
    // operation, one digest, whoever reads it) but the reading differs: from B's side the change
    // address is a stranger's, so a different set of typed checks would have been asked for.
    let as_b = explain(&planned.objects()[0].bytes, &view, &identity(&key_b())).unwrap();
    assert_eq!(as_b.binding(), own.binding());
    assert_ne!(
        as_b.destinations_needing_check(),
        own.destinations_needing_check()
    );
    let approval_for_b = flow::approve(&as_b, &view);
    let signer = KeySigner::for_test(key_a()).unwrap();
    // The approval carries the digest AND what was acknowledged, for whom: it is not good for A.
    assert_eq!(
        signer
            .authorize(planned.clone(), approval_for_b, &view)
            .unwrap_err(),
        Refusal::PlanChanged
    );
    // A's own approval still works.
    assert!(
        signer
            .authorize(planned.clone(), flow::approve(&own, &view), &view)
            .is_ok()
    );
}

/// Bring a fresh session (and, where one exists, its unused approval) into `phase`.
fn session_in(phase: PlanPhase, signer: &KeySigner) -> (PlanSession, Option<Approval>, World) {
    let (world, _, planned) = scenario();
    let mut session = PlanSession::new(planned);
    let mut approval = None;
    {
        let view = world.view();
        let ready = |session: &mut PlanSession| {
            let reviewed = session.present(&view).unwrap().clone();
            for index in reviewed.destinations_needing_check() {
                session
                    .confirm_destination(index, &reviewed.destination_check_text(index))
                    .unwrap();
            }
            for ack in reviewed.acknowledgements() {
                session.acknowledge(*ack).unwrap();
            }
        };
        match phase {
            PlanPhase::Planned => {}
            PlanPhase::Presented => {
                session.present(&view).unwrap();
            }
            PlanPhase::Approved | PlanPhase::Signed | PlanPhase::Queued => {
                ready(&mut session);
                let given = session.approve(&view).unwrap();
                if phase == PlanPhase::Approved {
                    approval = Some(given);
                } else {
                    let signed = session.authorize(signer, given, &view).unwrap();
                    if phase == PlanPhase::Queued {
                        MemoryOutbox::new().commit(&signed, &view).unwrap();
                        session.note_queued().unwrap();
                    }
                }
            }
            PlanPhase::Discarded => session.discard().unwrap(),
            PlanPhase::Invalidated(Invalidation::Locked) => session.lock(),
            PlanPhase::Invalidated(Invalidation::Expired) => {
                let mut late = World::new(245);
                late.state = world.state.clone();
                session.on_head(&late.view());
            }
            // `Invalidation` is non-exhaustive (Order W9): a later reason has no setup here.
            PlanPhase::Invalidated(other) => panic!("no setup for {other:?}"),
        }
    }
    assert_eq!(session.phase(), phase, "setup reached the phase");
    (session, approval, world)
}

#[test]
fn the_plan_state_machine_matches_its_transition_table_in_every_phase() {
    use PlanPhase::*;
    let signer = KeySigner::for_test(key_a()).unwrap();
    let phases = [
        Planned,
        Presented,
        Approved,
        Signed,
        Queued,
        Discarded,
        Invalidated(Invalidation::Expired),
        Invalidated(Invalidation::Locked),
    ];
    let live = |p: PlanPhase| matches!(p, Planned | Presented | Approved);
    for phase in phases {
        // present: from Planned, Presented and Approved (a new head needs a new review).
        let (mut s, _, world) = session_in(phase, &signer);
        let view = world.view();
        assert_eq!(
            s.present(&view).is_ok(),
            live(phase),
            "present in {phase:?}"
        );

        // acknowledge / confirm_destination / confirm_phrase: only while Presented.
        let (mut s, _, _) = session_in(phase, &signer);
        let answer = s.acknowledge(AckKind::Fee);
        if phase == Presented {
            assert!(answer.is_ok(), "acknowledge in {phase:?}: {answer:?}");
        } else {
            assert_eq!(
                answer,
                Err(Refusal::NotPresented),
                "acknowledge in {phase:?}"
            );
        }
        let (mut s, _, _) = session_in(phase, &signer);
        let wrong = s.confirm_destination(0, "ffffffff");
        assert_eq!(
            wrong,
            Err(if phase == Presented {
                Refusal::DestinationCheckFailed
            } else {
                Refusal::NotPresented
            }),
            "confirm_destination in {phase:?}"
        );
        let (mut s, _, _) = session_in(phase, &signer);
        assert_eq!(
            s.confirm_phrase("CONFIRM 00000000"),
            Err(if phase == Presented {
                Refusal::ConfirmationPhraseMismatch
            } else {
                Refusal::NotPresented
            }),
            "confirm_phrase in {phase:?} (a payment asks for no phrase)"
        );

        // approve: only while Presented, and then only once every acknowledgement is in.
        let (mut s, _, world) = session_in(phase, &signer);
        let view = world.view();
        match s.approve(&view) {
            Err(Refusal::AcknowledgementMissing(_)) => assert_eq!(phase, Presented),
            Err(Refusal::NotPresented) => assert_ne!(phase, Presented),
            other => panic!("approve in {phase:?}: {other:?}"),
        }

        // authorize: only while Approved, with the approval that phase hands out.
        let (mut s, approval, world) = session_in(phase, &signer);
        let view = world.view();
        if let Some(approval) = approval {
            assert!(
                s.authorize(&signer, approval, &view).is_ok(),
                "authorize in {phase:?}"
            );
        } else {
            // No approval exists outside Approved; a stale one from another session is no use.
            let (_, _, other_plan) = scenario();
            let stale = flow::approve(&review(&other_plan, &view).unwrap(), &view);
            assert_eq!(
                s.authorize(&signer, stale, &view).unwrap_err(),
                Refusal::NotPresented,
                "authorize in {phase:?}"
            );
        }

        // note_queued: only after signing.
        let (mut s, _, _) = session_in(phase, &signer);
        assert_eq!(
            s.note_queued().is_ok(),
            phase == Signed,
            "note_queued in {phase:?}"
        );

        // lock: every live phase becomes Locked. A signed plan stays Signed (its bytes exist and
        // cannot be recalled, so the session never claims otherwise); terminal phases stay as they
        // are.
        let (mut s, _, _) = session_in(phase, &signer);
        s.lock();
        if matches!(phase, Planned | Presented | Approved) {
            assert_eq!(
                s.phase(),
                Invalidated(Invalidation::Locked),
                "lock in {phase:?}"
            );
        } else {
            assert_eq!(s.phase(), phase, "lock in {phase:?}");
        }
        assert!(!s.gate().is_presenting());
        if phase == Signed {
            assert_eq!(
                s.discard().unwrap_err(),
                Refusal::CancelNotAvailable(CancelTarget::SignedOperation),
                "a locked session that holds signed bytes still cannot pretend to cancel them"
            );
            s.note_queued()
                .expect("the signed bytes can still be queued");
        }

        // discard: refused once signed bytes exist, allowed (and idempotent) otherwise.
        let (mut s, _, _) = session_in(phase, &signer);
        match s.discard() {
            Err(refusal) => {
                assert!(matches!(phase, Signed | Queued), "discard in {phase:?}");
                assert_eq!(
                    refusal,
                    Refusal::CancelNotAvailable(CancelTarget::SignedOperation)
                );
                assert_eq!(s.phase(), phase);
            }
            Ok(()) => {
                assert!(!matches!(phase, Signed | Queued), "discard in {phase:?}");
                assert!(s.plan().is_none());
            }
        }

        // on_head at the same head changes nothing; terminal phases never move.
        let (mut s, _, world) = session_in(phase, &signer);
        let view = world.view();
        s.on_head(&view);
        assert_eq!(s.phase(), phase, "on_head (same head) in {phase:?}");
    }
}

/// Order W5, pinned in one place: ONE live approval per gate; presenting the review again WITHDRAWS
/// the live approval; an approval binds the EXACT reviewed bytes and the relevant verified state
/// (the anchor, which carries the network, Genesis and protocol fingerprint, and the state root).
/// The gate enforces this order and binding; it claims no human presence and no protection against
/// a host process that holds the key (README "What the gates are, and what they are not").
#[test]
fn order_w5_one_live_approval_re_presentation_withdraws_and_the_binding_is_exact() {
    let (world, me, planned) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let signer = KeySigner::for_test(key_a()).unwrap();

    // One live approval per gate: a second one withdraws the first.
    let mut gate = ReviewGate::new();
    let first = flow::approve_on(&mut gate, &reviewed, &view);
    let second = flow::approve_on(&mut gate, &reviewed, &view);
    assert_eq!(
        signer.authorize(planned.clone(), first, &view).unwrap_err(),
        Refusal::ApprovalRevoked
    );
    // Re-presentation of the SAME review withdraws the live approval.
    assert_eq!(gate.present(&reviewed, &view), Freshness::Fresh);
    assert_eq!(
        signer
            .authorize(planned.clone(), second, &view)
            .unwrap_err(),
        Refusal::ApprovalRevoked
    );

    // The exact reviewed bytes: a plan that differs in one field only (its expiry, one block later)
    // is another plan, and an approval of the first does not authorize it.
    let nearly = plan(
        &OperationRequest::Payment(
            PaymentRequest::new(address(&key_b(), 1), 1_000_000)
                .with_validity_blocks(DEFAULT_VALIDITY_BLOCKS + 1),
        ),
        &view,
        &me,
    )
    .unwrap();
    assert_ne!(nearly.objects(), planned.objects());
    assert_eq!(nearly.kind(), planned.kind());
    assert_eq!(
        signer
            .authorize(nearly, flow::approve(&reviewed, &view), &view)
            .unwrap_err(),
        Refusal::PlanChanged
    );

    // The verified state: the same anchor over another state (one more coin, so another state
    // root) is another head, for the signer and for the gate.
    let mut moved = World {
        state: world.state.clone(),
        anchor: world.anchor.clone(),
        reserved: world.reserved.clone(),
        timestamp: world.timestamp,
    };
    moved.coin(address(&key_b(), 1), 7, 1, false, 0x77, 0);
    let moved_view = moved.view();
    assert_eq!(moved_view.anchor(), view.anchor());
    assert_ne!(moved_view.state_root(), view.state_root());
    assert_eq!(
        signer
            .authorize(
                planned.clone(),
                flow::approve(&reviewed, &view),
                &moved_view
            )
            .unwrap_err(),
        Refusal::StaleHead {
            reviewed: 100,
            current: 100
        }
    );
    let mut on_screen = ReviewGate::new();
    on_screen.present(&reviewed, &view);
    for index in reviewed.destinations_needing_check() {
        on_screen
            .confirm_destination(index, &reviewed.destination_check_text(index))
            .unwrap();
    }
    for ack in reviewed.acknowledgements() {
        on_screen.acknowledge(*ack).unwrap();
    }
    assert!(!on_screen.is_ready(&moved_view));
    assert_eq!(
        on_screen.approve(&moved_view).unwrap_err(),
        Refusal::StaleHead {
            reviewed: 100,
            current: 100
        }
    );
    // Another chain (another Genesis) at the same height is another head too.
    let mut foreign = World {
        state: world.state.clone(),
        anchor: world.anchor.clone(),
        reserved: world.reserved.clone(),
        timestamp: world.timestamp,
    };
    foreign.anchor.genesis = [9; 32];
    assert_eq!(
        signer
            .authorize(
                planned.clone(),
                flow::approve(&reviewed, &view),
                &foreign.view()
            )
            .unwrap_err(),
        Refusal::StaleHead {
            reviewed: 100,
            current: 100
        }
    );

    // The control: an approval of exactly these bytes at exactly this head authorizes them.
    assert!(
        signer
            .authorize(planned, flow::approve(&reviewed, &view), &view)
            .is_ok()
    );
}
