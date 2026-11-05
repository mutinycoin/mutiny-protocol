//! Fiat-settled lock and release end to end on a REAL consensus chain (NATIVE, TEST-VALUE): the
//! seller plans and funds the lock and signs slot 0, the maker's fill is attached, the buyer explains,
//! adopts and signs slot 1, the parts are combined and a real certified block creates the lock; then
//! the buyer plans the release and signs slot 0, the seller co-signs slot 1 and a second block pays
//! the locked amount to the buyer. Every unilateral exit is refused: a claim or a refund of a fiat lock
//! (consensus `FiatRecoveryUnspecified`), the wallet's cancellation, a release one wallet signed alone,
//! and an offer proof on a release. No fiat or Bitcoin settlement is verified anywhere.
#[path = "support/trading_5b.rs"]
mod trading;
#[path = "support/trading_rig_5b.rs"]
mod trading_rig;

use mutiny_consensus_v8::{
    Hash,
    trading_v1::{
        self, Action, Meta, NativeError, NativeLockKind, NativeOperation, OfferProof, Operation,
        SignedOffer, Strikes, native_input_id,
    },
    transactions::OutPoint,
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::*;
use std::collections::BTreeSet;
use trading_rig::chain::{TradeChain, address_of, buyer_key, descriptor_of, seller_key};

const AMOUNT: u64 = 2_000_000;
const TERMS: [u8; 32] = [0x77; 32];
const TRADE: [u8; 32] = [0x73; 32];
const CONTRACT: [u8; 32] = [0x74; 32];

fn identity(key: &HybridKey) -> SignerIdentity {
    SignerIdentity::from_public(key.public(), 1, None).unwrap()
}

fn point(tag: u8) -> OutPoint {
    OutPoint {
        transaction: [tag; 32],
        index: 0,
    }
}

fn lock_request(offer: &SignedOffer, buyer: Hash) -> FiatLockRequest {
    FiatLockRequest::new(Blob::new(trading::offer_bytes(offer)), buyer, AMOUNT, TERMS)
        .with_commitments(TRADE, CONTRACT)
}

/// A claim or a refund of `lock` built and signed through the consensus API (the test plays the
/// party): the only spends a hash lock knows. `payer` funds the fee from `input`.
fn hash_lock_exit(
    chain: &TradeChain,
    action: Action,
    payer: &HybridKey,
    input: OutPoint,
    input_atoms: u64,
) -> Vec<u8> {
    let fee = 20_000;
    let mut action = action;
    match &mut action {
        Action::Claim { change, .. } | Action::Refund { change, .. } => {
            *change = Strikes(input_atoms - fee)
        }
        _ => unreachable!(),
    }
    let mut operation = Operation {
        meta: Meta {
            context: trading::context_of(chain.genesis()),
            trade: TRADE,
            contract: CONTRACT,
            generation: 1,
            envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                first_height: chain.anchor().height + 1,
                last_height: chain.anchor().height + 100,
                reference_height: (chain.anchor()).height,
                reference_block: (chain.anchor()).block,
                preconditions: Vec::new(),
            },
            fee: Strikes(fee),
            inputs: vec![native_input_id(&input)],
        },
        action,
        approvals: vec![],
        offer_proof: None,
    };
    operation.approve(0, payer, 1).unwrap();
    NativeOperation {
        operation,
        inputs: vec![input],
    }
    .encode()
    .unwrap()
}

#[test]
fn fiat_lock_then_release_with_ordered_approvals_and_no_unilateral_exit() {
    let seller_wallet = seller_key();
    let buyer_wallet = buyer_key();
    let seller = address_of(&seller_wallet);
    let buyer = address_of(&buyer_wallet);
    // The seller funds the lock; the buyer pays the release fee from its own coin. The buyer is NOT
    // registered in the wallet book, so the seller must be given its public descriptor.
    let mut chain = TradeChain::new(
        "fiat-e2e",
        1_200_000,
        &[(0xa1, seller, 5_000_000), (0xb3, buyer, 1_000_000)],
        &[],
    );
    let maker = trading::maker();
    let offer = trading::offer(
        &maker,
        trading::context_of(chain.genesis()),
        trading::fiat_terms(AMOUNT, TERMS),
        1,
        100,
        0,
        0x41,
    );
    let none = BTreeSet::new();
    let seller_signer = KeySigner::for_test(seller_key()).unwrap();
    let buyer_signer = KeySigner::for_test(buyer_key()).unwrap();

    // ---- the seller plans the lock; without the buyer's descriptor it cannot fix the size
    {
        let view = chain.view(&none);
        assert!(matches!(
            plan(
                &OperationRequest::FiatLock(lock_request(&offer, buyer)),
                &view,
                &identity(&seller_wallet)
            )
            .unwrap_err(),
            Refusal::InvalidRequest(_)
        ));
    }
    let lock_request =
        lock_request(&offer, buyer).with_buyer_descriptor(Blob::new(descriptor_of(&buyer_wallet)));
    let (seller_part, digest) = {
        let view = chain.view(&none);
        let planned = plan(
            &OperationRequest::FiatLock(lock_request),
            &view,
            &identity(&seller_wallet),
        )
        .unwrap();
        assert_eq!(planned.kind(), OperationKind::FiatLock);
        assert_eq!(planned.validity().valid_only_at, None);
        let reviewed = review(&planned, &view).unwrap();
        assert_eq!(reviewed.title(), "Lock MUT for a fiat sale");
        assert!(reviewed.requires_phrase());
        let exit = reviewed
            .warnings()
            .iter()
            .find(|w| w.code == "NO_UNILATERAL_EXIT")
            .expect("the no-unilateral-exit warning");
        assert_eq!(exit.severity, Severity::Danger);
        assert_eq!(exit.requires, Some(AckKind::NoUnilateralExit));
        assert!(
            reviewed
                .acknowledgements()
                .contains(&AckKind::NoUnilateralExit)
        );
        assert!(
            reviewed
                .acknowledgements()
                .contains(&AckKind::ExternalEvidence)
        );
        // Ordered approvals: slot 0 the seller (this wallet), slot 1 the buyer.
        let slots: Vec<(Slot, RequirementStatus)> = reviewed
            .authorizations()
            .iter()
            .map(|r| (r.slot, r.status))
            .collect();
        assert_eq!(
            &slots[..2],
            &[
                (Slot::Approval(0), RequirementStatus::ThisWallet),
                (Slot::Approval(1), RequirementStatus::Counterparty)
            ]
        );
        assert_eq!(reviewed.fee().payer, FeePayer::ThisWallet);
        assert_eq!(
            reviewed.destinations()[0].role,
            DestinationRole::LockedOutput
        );
        assert!(reviewed.render_text().contains("verifies no fiat"));
        let signed = trading::sign_plan(planned, &seller_signer, &view).unwrap();
        (signed, reviewed.binding())
    };
    assert!(!seller_part.is_complete());
    let proof = trading::fill_proof(&maker, &offer, seller_part.bytes());
    let with_fill =
        offers::attach_fill_proof(seller_part.bytes(), &proof, &chain.view(&none)).unwrap();

    // ---- the buyer explains, adopts and co-signs slot 1
    let buyer_part = {
        let view = chain.view(&none);
        let explained = explain(&with_fill, &view, &identity(&buyer_wallet)).unwrap();
        assert_eq!(explained.binding(), digest);
        assert_eq!(
            explained.title(),
            "Approve a fiat-settled lock for this wallet"
        );
        assert_eq!(explained.fee().payer, FeePayer::Counterparty(seller));
        let adopted = adopt(&with_fill, &view, &identity(&buyer_wallet)).unwrap();
        trading::sign_plan(adopted, &buyer_signer, &view).unwrap()
    };
    let lock = offers::combine(&[&with_fill, buyer_part.bytes()], &chain.view(&none)).unwrap();
    assert!(lock.is_complete());
    trading::consensus(&chain.view(&none), lock.bytes()).expect("prepare_batch accepts the lock");
    let mut seller_outbox = MemoryOutbox::new();
    seller_outbox.commit(&lock, &chain.view(&none)).unwrap();

    // ---- block 1 creates the lock
    trading::assert_forged_applied_receipt_cannot_confirm(&lock, &chain.view(&none));
    let after_lock = chain.step(&[lock.bytes().to_vec()]);
    let lock_wire = NativeOperation::decode(lock.bytes()).unwrap();
    let lock_id = lock_wire.operation.output_id(0).unwrap();
    let record = trading_v1::locked(&after_lock, lock_id).unwrap();
    assert_eq!(
        (
            record.sender,
            record.recipient,
            record.amount.0,
            record.created_height
        ),
        (seller, buyer, AMOUNT, 1)
    );
    assert_eq!(record.kind, NativeLockKind::Fiat { terms: TERMS });
    assert_eq!(
        seller_outbox
            .reconcile(&chain.view(&none))
            .unwrap()
            .confirmed,
        1
    );
    let seller_change = OutPoint {
        transaction: lock.id(),
        index: 1,
    };
    let seller_change_atoms = after_lock.coins[&seller_change].output.atoms;

    // ---- no unilateral exit exists
    {
        let view = chain.view(&none);
        let claim = hash_lock_exit(
            &chain,
            Action::Claim {
                output: lock_id,
                recipient: buyer,
                amount: Strikes(AMOUNT),
                preimage: [9; 32],
                change: Strikes(0),
            },
            &buyer_wallet,
            point(0xb3),
            1_000_000,
        );
        assert_eq!(
            trading::consensus(&view, &claim).unwrap_err(),
            NativeError::FiatRecoveryUnspecified
        );
        let refund = hash_lock_exit(
            &chain,
            Action::Refund {
                output: lock_id,
                owner: seller,
                amount: Strikes(AMOUNT),
                change: Strikes(0),
            },
            &seller_wallet,
            seller_change.clone(),
            seller_change_atoms,
        );
        assert_eq!(
            trading::consensus(&view, &refund).unwrap_err(),
            NativeError::FiatRecoveryUnspecified
        );
        assert!(chain.prepare(&[claim]).is_err() && chain.prepare(&[refund]).is_err());
        // The wallet offers no cancellation of a fiat lock.
        assert_eq!(
            plan(
                &OperationRequest::Cancel(CancelRequest::new(CancelTarget::FiatLock)),
                &view,
                &identity(&seller_wallet)
            )
            .unwrap_err(),
            Refusal::CancelNotAvailable(CancelTarget::FiatLock)
        );
        // A "refund" request routed at the fiat lock is never a fiat exit: in this build the
        // hash-lock kinds belong to another phase, and consensus refuses it anyway (above).
        assert!(
            plan(
                &OperationRequest::Cancel(CancelRequest::new(CancelTarget::HashLockRefund(
                    lock_id
                ))),
                &view,
                &identity(&seller_wallet)
            )
            .is_err()
        );
    }

    // ---- the buyer plans the release (it pays the fee) and signs slot 0
    let (release_part, release_digest) = {
        let view = chain.view(&none);
        let planned = plan(
            &OperationRequest::FiatRelease(FiatReleaseRequest::new(lock_id)),
            &view,
            &identity(&buyer_wallet),
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert_eq!(reviewed.title(), "Release a fiat lock to this wallet");
        let slots: Vec<(Slot, RequirementStatus)> = reviewed
            .authorizations()
            .iter()
            .map(|r| (r.slot, r.status))
            .collect();
        assert_eq!(
            slots,
            [
                (Slot::Approval(0), RequirementStatus::ThisWallet),
                (Slot::Approval(1), RequirementStatus::Counterparty)
            ],
            "release slots: 0 the buyer, 1 the seller; no maker"
        );
        assert_eq!(reviewed.fee().payer, FeePayer::ThisWallet);
        assert_eq!(
            reviewed.destinations()[0],
            Destination {
                role: DestinationRole::ProtocolPayout,
                address: buyer,
                label: AddressLabel::ThisWallet,
                atoms: AMOUNT
            }
        );
        // The seller cannot plan the release: it neither pays nor holds slot 0.
        assert_eq!(
            plan(
                &OperationRequest::FiatRelease(FiatReleaseRequest::new(lock_id)),
                &view,
                &identity(&seller_wallet)
            )
            .unwrap_err(),
            Refusal::NotRequiredSigner(Slot::Approval(0))
        );
        let signed = trading::sign_plan(planned, &buyer_signer, &view).unwrap();
        (signed, reviewed.binding())
    };
    {
        // The buyer alone cannot release: the part is partial and consensus refuses it.
        let view = chain.view(&none);
        let alone = offers::combine(&[release_part.bytes()], &view).unwrap();
        assert!(!alone.is_complete());
        assert_eq!(
            alone.missing(),
            &[Requirement {
                slot: Slot::Approval(1),
                signer: RequiredSigner::Wallet(seller),
                status: RequirementStatus::Counterparty
            }]
        );
        assert_eq!(
            trading::consensus(&view, release_part.bytes()).unwrap_err(),
            NativeError::Authority
        );
        // An offer proof is refused on a release, by the wallet and by consensus.
        let stray = trading::fill_proof(&maker, &offer, release_part.bytes());
        assert_eq!(
            offers::attach_fill_proof(release_part.bytes(), &stray, &view).unwrap_err(),
            Refusal::OfferProofInvalid
        );
        let with_proof = trading::mutate(release_part.bytes(), |wire| {
            let carried = OfferProof::decode(&stray).unwrap();
            wire.operation.offer_proof = Some(carried);
        });
        assert_eq!(
            explain(&with_proof, &view, &identity(&seller_wallet)).unwrap_err(),
            Refusal::OfferProofInvalid
        );
        // The fee is raised to cover the longer bytes, so that only the offer-proof rule remains
        // (consensus checks the fee before the offer binding).
        let richer = trading::mutate(release_part.bytes(), |wire| {
            wire.operation.meta.fee.0 += 10_000;
            if let Action::FiatRelease { change, .. } = &mut wire.operation.action {
                change.0 -= 10_000;
            }
        });
        let signed_with_proof = trading::mutate(
            &trading::sign_all(
                &richer,
                &[(0, &buyer_wallet, 1), (1, &seller_wallet, 1)],
                None,
            ),
            |wire| wire.operation.offer_proof = Some(OfferProof::decode(&stray).unwrap()),
        );
        assert_eq!(
            trading::consensus(&view, &signed_with_proof).unwrap_err(),
            NativeError::Candidate(trading_v1::Error::OfferBinding)
        );
    }

    // ---- the seller explains, adopts and co-signs slot 1
    let seller_release = {
        let view = chain.view(&none);
        let explained = explain(release_part.bytes(), &view, &identity(&seller_wallet)).unwrap();
        assert_eq!(explained.binding(), release_digest);
        assert_eq!(explained.title(), "Release a fiat lock to the buyer");
        let fiat = explained
            .warnings()
            .iter()
            .find(|w| w.code == "FIAT_NOT_VERIFIED")
            .unwrap();
        assert_eq!(fiat.severity, Severity::Danger);
        assert!(
            explained
                .effects()
                .iter()
                .any(|e| e.irreversible && e.text.starts_with("This wallet gives up the locked"))
        );
        let adopted = adopt(release_part.bytes(), &view, &identity(&seller_wallet)).unwrap();
        trading::sign_plan(adopted, &seller_signer, &view).unwrap()
    };
    let release = offers::combine(
        &[release_part.bytes(), seller_release.bytes()],
        &chain.view(&none),
    )
    .unwrap();
    assert!(release.is_complete());
    let mut buyer_outbox = MemoryOutbox::new();
    buyer_outbox.commit(&release, &chain.view(&none)).unwrap();
    assert!(
        buyer_outbox
            .reserved()
            .unwrap()
            .contains(&resource_key("lock", &lock_id))
    );

    // ---- block 2 pays the locked amount to the buyer and ends the lock
    trading::assert_forged_applied_receipt_cannot_confirm(&release, &chain.view(&none));
    let after = chain.step(&[release.bytes().to_vec()]);
    assert!(
        trading_v1::locked(&after, lock_id).is_err(),
        "the lock is gone"
    );
    let paid = &after.coins[&OutPoint {
        transaction: release.id(),
        index: 0,
    }];
    assert_eq!((paid.output.owner, paid.output.atoms), (buyer, AMOUNT));
    assert_eq!(
        buyer_outbox
            .reconcile(&chain.view(&none))
            .unwrap()
            .confirmed,
        1
    );
    {
        // Released once: the same release is a replay, and a new one finds no lock.
        let view = chain.view(&none);
        assert!(explain(release.bytes(), &view, &identity(&buyer_wallet)).is_err());
        assert!(matches!(
            plan(
                &OperationRequest::FiatRelease(FiatReleaseRequest::new(lock_id)),
                &view,
                &identity(&buyer_wallet)
            )
            .unwrap_err(),
            Refusal::LockNotFound
        ));
    }
    chain.finish();
}
