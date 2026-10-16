//! WP-T2 (Order P5; P-LANE-DESIGN-V1 6.1 and 6.6; Restart Order L64) unit tests of the two LicenseDvp
//! helpers that real blocks cannot isolate: `sale_commitment` (exactly one LicenseEntitlements and
//! exactly one LicenseAssignment precondition, both for the sold License, else `Bounds`) and
//! `transfer_license_candidate` (the id of the pending assignment the Book cancels must EQUAL the
//! committed `LicenseAssignment.pending`, else `Stale(2)` with the Book untouched). In a real block
//! the prologue's `check_preconditions` already compares the committed pending id with the
//! tentative state, so the mismatch branch below is defence in depth that only this file reaches.
//! Real-block tests: consensus/tests/license_dvp_entitlements_v1.rs. Synthetic TEST-VALUE only.
use super::*;
use crate::{
    license_assignment_v2::Assignment,
    license_book_v2::Book,
    op_envelope_v1::{AwardAccount, assignment_id},
    wallet_authority_v1::WalletBook,
};
use mutiny_crypto_v2::{
    HybridKey,
    enrollment::{Binding, owner_descriptor_id},
};

#[path = "../tests/support/license_v2.rs"]
mod fixture;

const GENESIS: Hash = [1; 32];
const FINGERPRINT: Hash = [2; 32];
const SOLD: Hash = [0x51; 32];
const OTHER: Hash = [0x52; 32];

fn entitlements(license: Hash) -> Precondition {
    Precondition::LicenseEntitlements {
        license,
        accounts: vec![AwardAccount { award_epoch: 131_072, share: 10, remaining: 7, claims: 1 }],
    }
}
fn assignment(license: Hash, pending: Option<Hash>) -> Precondition {
    Precondition::LicenseAssignment { license, assignment_sequence: 1, active_worker: Some([9; 32]), pending }
}
fn envelope(mut preconditions: Vec<Precondition>) -> Envelope {
    preconditions.sort_by_key(|p| (p.tag(), p.subject()));
    Envelope { first_height: 1, last_height: 9, reference_height: 0, reference_block: [3; 32], preconditions }
}

/// 6.1: the mandatory sale commitment. Absence of either precondition, a second one for another
/// License, or the pair naming a License other than the sold one is `Bounds`; a TreasuryHead
/// precondition is neither required nor refused; the committed pending id is returned.
#[test]
fn sale_commitment_requires_exactly_one_entitlement_and_one_assignment_for_the_sold_license() {
    let head = Precondition::TreasuryHead { treasury: [7; 32], generation: 1, address: [8; 32] };
    let cases: Vec<(&str, Vec<Precondition>)> = vec![
        ("no precondition", vec![]),
        ("entitlements only", vec![entitlements(SOLD)]),
        ("assignment only", vec![assignment(SOLD, None)]),
        ("Treasury head only", vec![head.clone()]),
        ("pair for another License", vec![entitlements(OTHER), assignment(OTHER, None)]),
        ("entitlements of another License", vec![entitlements(OTHER), assignment(SOLD, None)]),
        ("assignment of another License", vec![entitlements(SOLD), assignment(OTHER, None)]),
        ("second entitlements list", vec![entitlements(SOLD), entitlements(OTHER), assignment(SOLD, None)]),
        ("second assignment", vec![entitlements(SOLD), assignment(SOLD, None), assignment(OTHER, None)]),
    ];
    for (name, preconditions) in cases {
        let e = envelope(preconditions);
        e.validate().unwrap_or_else(|x| panic!("{name}: the envelope itself is valid: {x:?}"));
        assert_eq!(sale_commitment(&e, SOLD), Err(NativeError::Bounds), "{name}");
    }
    assert_eq!(sale_commitment(&envelope(vec![entitlements(SOLD), assignment(SOLD, None)]), SOLD), Ok(None));
    assert_eq!(
        sale_commitment(&envelope(vec![entitlements(SOLD), assignment(SOLD, Some([4; 32])), head]), SOLD),
        Ok(Some([4; 32]))
    );
}

struct Rig {
    seller: HybridKey,
    assignments: Vec<Assignment>,
    expected: Vec<Binding>,
    book: Book,
}
fn rig() -> Rig {
    let (seller, assignments, expected, licenses, _node) = fixture::fixtures();
    let book = Book::genesis(&assignments, &expected, &licenses, &WalletBook::default(), GENESIS, FINGERPRINT).unwrap();
    Rig { seller, assignments, expected, book }
}
/// Generation-2 reassignment of Genesis License 0 to synthetic Worker `seed`, effective epoch 2.
fn reassignment(r: &Rig, seed: u8) -> Assignment {
    let mut b = r.expected[0].clone();
    b.owner_descriptor = owner_descriptor_id(r.seller.public(), 1).unwrap();
    b.owner_generation = 1;
    b.worker_public = fixture::worker(seed);
    b.worker_id = b.derived_worker_id();
    b.assignment_generation = 2;
    b.configuration_generation = 2;
    b.device_mac = [2, 0, 0, 0, 2, seed];
    b.effective_epoch = 2;
    b.valid_until_height = 100;
    fixture::sign(b, &r.seller, &r.assignments[0].node_descriptor, seed)
}
/// The capability the DvP arm builds, for License 0 of `book` sold to a fixed buyer at height 7.
fn request(book: &Book, license: Hash) -> VerifiedLicenseTransferCandidate {
    let l = book.license(license).unwrap();
    VerifiedLicenseTransferCandidate {
        license,
        genesis: l.genesis,
        from: l.owner,
        to: [0x42; 32],
        expected_assignment_sequence: l.assignment_sequence,
        new_assignment_sequence: l.assignment_sequence + 1,
        inclusion_height: 7,
        rights_from_height: 8,
        operation: [11; 32],
        trade: [12; 32],
        contract: [13; 32],
        generation: 1,
        payment_commitment: [14; 32],
    }
}

/// 6.6 (Restart Order L64): a pending old-owner assignment is cancelled only when it is exactly
/// the committed one. Committing none, or another id, is `Stale(2)` and the Book (with the pending
/// assignment) stays byte-identical; committing an id when nothing is pending is `Stale(2)` too;
/// a Book refusal keeps `LicenseLocked`; the matching commitment cancels it.
#[test]
fn sale_cancels_only_the_committed_pending_assignment() {
    let mut r = rig();
    let license = r.expected[0].license;
    // Nothing pending: only "none" matches.
    let rows = r.book.records().unwrap();
    let req = request(&r.book, license);
    assert_eq!(
        transfer_license_candidate(&mut r.book, &req, Some([5; 32])),
        Err(NativeError::Stale(TAG_LICENSE_ASSIGNMENT))
    );
    assert_eq!(r.book.records().unwrap(), rows);
    // A pending generation-2 assignment scheduled at height 2, epoch 1.
    let pending = reassignment(&r, 40);
    r.book.schedule(pending.clone(), GENESIS, FINGERPRINT, 2, 1, &WalletBook::default()).unwrap();
    let id = assignment_id(&pending).unwrap();
    let rows = r.book.records().unwrap();
    let req = request(&r.book, license);
    for (name, committed) in [("none committed", None), ("another id committed", Some([6; 32]))] {
        assert_eq!(
            transfer_license_candidate(&mut r.book, &req, committed),
            Err(NativeError::Stale(TAG_LICENSE_ASSIGNMENT)),
            "{name}"
        );
        assert_eq!(r.book.records().unwrap(), rows, "{name}: the Book is untouched");
        assert_eq!(r.book.pending_assignment(license), Some(&pending), "{name}");
    }
    let mut refused = request(&r.book, license);
    refused.expected_assignment_sequence += 1;
    assert_eq!(transfer_license_candidate(&mut r.book, &refused, Some(id)), Err(NativeError::LicenseLocked));
    assert_eq!(r.book.records().unwrap(), rows);
    transfer_license_candidate(&mut r.book, &req, Some(id)).unwrap();
    assert_eq!(r.book.pending_assignment(license), None, "the committed assignment is cancelled");
    let l = r.book.license(license).unwrap();
    assert_eq!((l.owner, l.active_worker, l.assignment_sequence), ([0x42; 32], None, req.new_assignment_sequence));
}
