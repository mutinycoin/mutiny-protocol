//! `Debug` output of every public type contains no secret, and no accidental dump of byte arrays.
//! The only secret-bearing values in the crate are the signing key (inside `KeySigner`, which has no
//! `Debug` of its own for the key: crypto-v2's `HybridKey` has none at all) and a hash-lock
//! `Preimage`; both are redacted. Every other public type holds public data and prints it compactly
//! (short identifiers, counts), never as a raw byte array. NATIVE, TEST-VALUE; public test keys only.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_wallet_core_v8::*;
use synthetic::{World, address, identity, key_a, key_b};

/// The BIP-39 words of the public test phrases; none may ever appear in any output.
const PHRASE_WORDS: [&str; 3] = ["abandon", "zoo", "vote"];

fn longest_number_run(text: &str) -> usize {
    let (mut best, mut run) = (0usize, 0usize);
    for token in text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
    {
        if token.len() <= 3
            && token.bytes().all(|b| b.is_ascii_digit())
            && token.parse::<u16>().is_ok_and(|n| n <= 255)
        {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

fn longest_hex_run(text: &str) -> usize {
    let (mut best, mut run) = (0usize, 0usize);
    for c in text.chars() {
        if c.is_ascii_hexdigit() && !c.is_ascii_uppercase() {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

fn assert_clean(label: &str, text: &str) {
    assert!(!text.is_empty(), "{label}: empty Debug output");
    for word in PHRASE_WORDS {
        assert!(
            !text.to_ascii_lowercase().contains(word),
            "{label}: contains a phrase word {word:?}"
        );
    }
    assert!(
        longest_number_run(text) < 8,
        "{label}: looks like a dumped byte array: {text}"
    );
    assert!(
        longest_hex_run(text) < 64,
        "{label}: prints a full 32-byte identifier: {text}"
    );
    assert!(
        text.len() < 2000,
        "{label}: {} characters of Debug output",
        text.len()
    );
}

#[test]
fn every_public_type_prints_compactly_and_without_secrets() {
    let mut world = World::new(100);
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    let view = world.view();
    let me = identity(&key_a());
    let planned = plan(
        &OperationRequest::Payment(PaymentRequest::new(address(&key_b(), 1), 1_000_000)),
        &view,
        &me,
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let signer = KeySigner::for_test(key_a()).unwrap();
    let approval = flow::approve(&reviewed, &view);
    let approval_text = format!("{approval:?}");
    let signed = signer.authorize(planned.clone(), approval, &view).unwrap();
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &view).unwrap();
    let record = outbox.records().unwrap().remove(0);
    let mut gate = ReviewGate::new();
    gate.present(&reviewed, &view);
    let session = PlanSession::new(planned.clone());
    let container = PartialApproval::from_signed(
        &SignedOperation::Partial {
            kind: OperationKind::Payment,
            id: [7; 32],
            bytes: planned.objects()[0].bytes.clone(),
            missing: planned.requirements().to_vec(),
            validity: *planned.validity(),
            reserved: planned.inputs().to_vec(),
        },
        view.context(),
    )
    .unwrap();
    let hash = [0x5a; 32];
    let preimage = Preimage::from_bytes([0xab; 32]);

    let mut shown: Vec<(&str, String)> = vec![
        ("approval", approval_text),
        ("gate", format!("{gate:?}")),
        ("session", format!("{session:?}")),
        ("signer", format!("{signer:?}")),
        (
            "signing gate",
            format!("{:?}", SigningGate::test_value().unwrap()),
        ),
        ("identity", format!("{me:?}")),
        ("plan", format!("{planned:?}")),
        ("review", format!("{reviewed:?}")),
        ("digest", format!("{:?}", reviewed.binding())),
        ("signed operation", format!("{signed:?}")),
        ("record", format!("{record:?}")),
        ("outbox", format!("{outbox:?}")),
        ("partial approval", format!("{container:?}")),
        ("chain view", format!("{view:?}")),
        ("head", format!("{:?}", view.head())),
        ("context", format!("{:?}", view.context())),
        ("preimage", format!("{preimage:?}")),
        ("blob", format!("{:?}", Blob::new(vec![0xcd; 4000]))),
        ("plan object", format!("{:?}", planned.objects()[0])),
        ("requirement", format!("{:?}", planned.requirements()[0])),
        ("validity", format!("{:?}", planned.validity())),
        ("fee", format!("{:?}", reviewed.fee())),
        ("timing", format!("{:?}", reviewed.timing())),
        ("destination", format!("{:?}", reviewed.destinations()[0])),
        ("party", format!("{:?}", reviewed.parties()[0])),
        ("input line", format!("{:?}", reviewed.inputs()[0])),
        ("signer summary", format!("{:?}", reviewed.signer())),
        ("chain summary", format!("{:?}", reviewed.chain())),
        (
            "cancel target",
            format!("{:?}", CancelTarget::HashLockRefund(hash)),
        ),
        ("settlement", format!("{:?}", Settlement::Confirmed(3))),
        ("report", format!("{:?}", ReconcileReport::default())),
    ];
    // Every request shape, including the ones that carry opaque offers and a preimage.
    let requests = vec![
        OperationRequest::Payment(PaymentRequest::new(hash, 5)),
        OperationRequest::WalletRotation(RotationRequest::new(
            Blob::new(vec![0xcd; 2000]),
            FeeSource::OtherWallet(me.clone()),
        )),
        OperationRequest::DividendClaim(DividendClaimRequest::new(hash, 1, 2, hash)),
        OperationRequest::LicenseDvp(LicenseDvpRequest::new(Blob::new(vec![1; 500]), hash)),
        OperationRequest::HashLock(HashLockRequest::new(
            Blob::new(vec![1; 500]),
            hash,
            1,
            hash,
            9,
        )),
        OperationRequest::ConditionalClaim(ClaimRequest::new(
            hash,
            Preimage::from_bytes([0xab; 32]),
        )),
        OperationRequest::ConditionalRefund(RefundRequest::new(hash)),
        OperationRequest::FiatLock(FiatLockRequest::new(Blob::new(vec![1; 500]), hash, 1, hash)),
        OperationRequest::FiatRelease(FiatReleaseRequest::new(hash)),
        OperationRequest::BondCreate(BondCreateRequest::new(hash, 1, 1, hash)),
        OperationRequest::BondUnbond(BondUnbondRequest::new(hash)),
        OperationRequest::BondWithdraw(BondWithdrawRequest::new(hash)),
        OperationRequest::TreasuryRotate(TreasuryRotateRequest::new(Blob::new(vec![1; 2000]))),
        OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(vec![
            1;
            2000
        ]))),
        OperationRequest::Cancel(CancelRequest::new(CancelTarget::HashLockRefund(hash))),
    ];
    for request in &requests {
        shown.push(("request", format!("{request:?}")));
    }
    for refusal in Refusal::examples() {
        shown.push(("refusal debug", format!("{refusal:?}")));
        shown.push(("refusal display", refusal.to_string()));
    }
    for kind in OperationKind::ALL {
        shown.push(("kind", format!("{kind:?} {}", kind.title())));
    }
    for (label, text) in &shown {
        assert_clean(label, text);
    }

    // The two secret-bearing types are explicitly redacted.
    assert!(format!("{signer:?}").contains("<redacted>"));
    assert_eq!(format!("{preimage:?}"), "Preimage(<redacted>)");
    let claim = format!(
        "{:?}",
        OperationRequest::ConditionalClaim(ClaimRequest::new(
            hash,
            Preimage::from_bytes([0xab; 32])
        ))
    );
    assert!(claim.contains("<redacted>"), "{claim}");
    assert!(
        !claim.contains("171") && !claim.to_lowercase().contains("abab"),
        "{claim}"
    );
}

#[test]
fn the_test_detectors_actually_detect() {
    assert!(longest_number_run("[1, 2, 3, 4, 5, 6, 7, 8, 9]") >= 8);
    assert!(longest_number_run("Foo { a: 1, b: 2, c: 300 }") < 8);
    assert!(longest_hex_run(&"ab".repeat(32)) >= 64);
    assert!(longest_hex_run("abababab..abababab") < 64);
}
