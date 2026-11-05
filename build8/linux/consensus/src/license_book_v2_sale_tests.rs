//! WP-Q17 Book-level tests (Order Q17; Restart Order L64; P-LANE-DESIGN-V1 6.6 and 11.2 a).
//! A License sale cancels the old owner's pending Worker assignment: the Book removes it,
//! returns its canonical id, and it never activates. The production entry point
//! `transfer_candidate` takes the trading capability that only the DvP validator constructs, so
//! these tests drive the same private `Book::transfer` through `SaleTerms`. The current trading
//! path still refuses such a sale until WP-T commits the pending id (real blocks in
//! consensus/tests/license_sale_assignment_v1.rs). Synthetic TEST-VALUE fixtures only.
use super::*;
use crate::{
    NETWORK_ID,
    blocks::BlockBody,
    execution::{CandidatePreparation, ExecutionError, State, WorkParent},
    pow::Candidate,
};
use mutiny_crypto_v2::{HybridKey, Role, enrollment::owner_descriptor_id};

#[path = "../tests/support/license_v2.rs"]
mod fixture;

const GENESIS: Hash = [1; 32];
const FINGERPRINT: Hash = [2; 32];

/// Plain sale terms: the same thirteen values the trading capability carries.
#[derive(Clone)]
struct Sale {
    license: Hash,
    genesis: Hash,
    from: Hash,
    to: Hash,
    expected: u64,
    next: u64,
    inclusion: u64,
    rights: u64,
    operation: Hash,
    trade: Hash,
    contract: Hash,
    generation: u64,
    payment: Hash,
}
impl SaleTerms for Sale {
    fn license(&self) -> Hash {
        self.license
    }
    fn genesis(&self) -> Hash {
        self.genesis
    }
    fn from(&self) -> Hash {
        self.from
    }
    fn to(&self) -> Hash {
        self.to
    }
    fn expected_assignment_sequence(&self) -> u64 {
        self.expected
    }
    fn new_assignment_sequence(&self) -> u64 {
        self.next
    }
    fn inclusion_height(&self) -> u64 {
        self.inclusion
    }
    fn rights_from_height(&self) -> u64 {
        self.rights
    }
    fn operation(&self) -> Hash {
        self.operation
    }
    fn trade(&self) -> Hash {
        self.trade
    }
    fn contract(&self) -> Hash {
        self.contract
    }
    fn generation(&self) -> u64 {
        self.generation
    }
    fn payment_commitment(&self) -> Hash {
        self.payment
    }
}

struct Rig {
    seller: HybridKey,
    buyer: HybridKey,
    assignments: Vec<Assignment>,
    expected: Vec<Binding>,
    book: Book,
}
/// Twelve Genesis Licenses owned by the seller, each with its active generation-1 Worker.
fn rig() -> Rig {
    let (seller, assignments, expected, licenses, _node) = fixture::fixtures();
    let book = Book::genesis(
        &assignments,
        &expected,
        &licenses,
        &WalletBook::default(),
        GENESIS,
        FINGERPRINT,
    )
    .unwrap();
    let buyer = HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner)
        .unwrap();
    Rig {
        seller,
        buyer,
        assignments,
        expected,
        book,
    }
}
fn address(k: &HybridKey) -> Hash {
    k.public().address_id(1).unwrap()
}
/// Generation-`generation` reassignment of Genesis License `index` to synthetic Worker `seed`,
/// authorized by `owner`, inclusion deadline height 100.
fn reassignment(
    r: &Rig,
    index: usize,
    owner: &HybridKey,
    seed: u8,
    generation: u64,
    effective_epoch: u64,
) -> Assignment {
    let mut b = r.expected[index].clone();
    b.owner_descriptor = owner_descriptor_id(owner.public(), 1).unwrap();
    b.owner_generation = 1;
    b.worker_public = fixture::worker(seed);
    b.worker_id = b.derived_worker_id();
    b.assignment_generation = generation;
    b.configuration_generation = 2;
    b.device_mac = [2, 0, 0, 0, 1, seed];
    b.effective_epoch = effective_epoch;
    b.valid_until_height = 100;
    fixture::sign(b, owner, &r.assignments[index].node_descriptor, seed)
}
fn schedule(book: &mut Book, a: &Assignment, height: u64, epoch: u64) -> Result<()> {
    book.schedule(
        a.clone(),
        GENESIS,
        FINGERPRINT,
        height,
        epoch,
        &WalletBook::default(),
    )
}
/// A well-formed sale of `license` from its current owner, included at height 7.
fn sale_of(book: &Book, license: Hash, to: Hash) -> Sale {
    let l = book.license(license).unwrap();
    Sale {
        license,
        genesis: l.genesis,
        from: l.owner,
        to,
        expected: l.assignment_sequence,
        next: l.assignment_sequence + 1,
        inclusion: 7,
        rights: 8,
        operation: [11; 32],
        trade: [12; 32],
        contract: [13; 32],
        generation: 1,
        payment: [14; 32],
    }
}
fn changed_keys(before: &BTreeMap<Hash, Vec<u8>>, after: &BTreeMap<Hash, Vec<u8>>) -> BTreeSet<Hash> {
    before
        .keys()
        .chain(after.keys())
        .filter(|k| before.get(*k) != after.get(*k))
        .copied()
        .collect()
}

#[test]
fn sale_cancels_the_pending_old_owner_assignment_and_returns_its_canonical_id() {
    let mut r = rig();
    let license = r.expected[0].license;
    let old_worker = r.expected[0].worker_id;
    let (seller, buyer) = (address(&r.seller), address(&r.buyer));
    // The seller schedules a generation-2 reassignment at height 2 (epoch 1), effective epoch 2.
    let pending = reassignment(&r, 0, &r.seller, 40, 2, 2);
    schedule(&mut r.book, &pending, 2, 1).unwrap();
    let cancelled_worker = pending.enrollment.binding.worker_id;
    assert_eq!(r.book.pending_assignment(license), Some(&pending));
    let before = r.book.records().unwrap();
    let sale = sale_of(&r.book, license, buyer);
    let returned = r.book.transfer(&sale).unwrap();
    // Design 9.1, recomputed here without `assignment_id`: domain || 0 || unsigned binding.
    let id = domain_hash(
        b"MUTINY-BUILD8-LICENSE-ASSIGNMENT-ID-V2",
        &pending.enrollment.binding.bytes().unwrap(),
    );
    assert_eq!(returned, Some(id));
    // The id covers the unsigned binding only: another signature set has the same id, any
    // binding change gives another id.
    let mut resigned = pending.clone();
    resigned.enrollment.owner_signature.fndsa[0] ^= 1;
    assert_ne!(resigned.encode().unwrap(), pending.encode().unwrap());
    assert_eq!(assignment_id(&resigned).unwrap(), id);
    let mut later = pending.clone();
    later.enrollment.binding.effective_epoch = 6;
    assert_ne!(assignment_id(&later).unwrap(), id);
    // Owner, detachment and sequence exactly as before Q17; the pending record is gone.
    assert_eq!(r.book.pending_assignment(license), None);
    let l = r.book.license(license).unwrap();
    assert_eq!(
        (l.owner, l.active_worker, l.assignment_sequence),
        (buyer, None, 2)
    );
    assert_ne!(seller, buyer);
    // The detached Worker stays recorded as history; the cancelled one never became a Worker.
    assert!(r.book.workers.contains_key(&old_worker));
    assert!(!r.book.workers.contains_key(&cancelled_worker));
    let after = r.book.records().unwrap();
    assert_eq!(
        changed_keys(&before, &after),
        BTreeSet::from([
            domain_hash(LICENSE_DOMAIN, &license),
            domain_hash(PENDING_DOMAIN, &license)
        ])
    );
    assert!(!after.contains_key(&domain_hash(PENDING_DOMAIN, &license)));
    assert_eq!(Book::from_records(&after).unwrap(), r.book);
    // It never activates, however far the epochs advance; neither Worker has authority.
    for epoch in [1, 2, 3, 1_000_000, u64::MAX] {
        r.book.activate_due(epoch).unwrap();
        assert_eq!(r.book.records().unwrap(), after, "epoch {epoch}");
        assert_eq!(
            r.book.active(license, cancelled_worker, epoch).err(),
            Some(Error::UnknownSigner),
            "epoch {epoch}"
        );
        assert_eq!(
            r.book.active(license, old_worker, epoch).err(),
            Some(Error::StaleSequence),
            "epoch {epoch}"
        );
    }
    // Its exact signed bytes can never be scheduled again (generation 2 is now stale), and the
    // old owner cannot authorize a fresh one either: only the new owner can.
    assert_eq!(
        schedule(&mut r.book, &pending, 9, 6),
        Err(Error::WrongAnchor)
    );
    let seller_retry = reassignment(&r, 0, &r.seller, 40, 3, 7);
    assert_eq!(
        schedule(&mut r.book, &seller_retry, 9, 6),
        Err(Error::WrongGeneration)
    );
    assert_eq!(r.book.records().unwrap(), after);
    // The buyer's fresh generation-3 assignment activates at exactly its signed epoch.
    let fresh = reassignment(&r, 0, &r.buyer, 41, 3, 7);
    schedule(&mut r.book, &fresh, 9, 6).unwrap();
    r.book.activate_due(6).unwrap();
    assert_eq!(r.book.pending_assignment(license), Some(&fresh));
    r.book.activate_due(7).unwrap();
    let (l, w) = r
        .book
        .active(license, fresh.enrollment.binding.worker_id, 7)
        .unwrap();
    assert_eq!(
        (l.owner, l.assignment_sequence, w.last_accepted_ticket),
        (buyer, 3, 0)
    );
}

#[test]
fn sale_without_pending_assignment_returns_none_and_reassigns_only_that_license() {
    let mut r = rig();
    let license = r.expected[1].license;
    let buyer = address(&r.buyer);
    // Another License's pending assignment is not touched by this sale.
    let other = reassignment(&r, 2, &r.seller, 42, 2, 2);
    schedule(&mut r.book, &other, 2, 1).unwrap();
    let before = r.book.records().unwrap();
    let sale = sale_of(&r.book, license, buyer);
    assert_eq!(r.book.transfer(&sale), Ok(None));
    let l = r.book.license(license).unwrap();
    assert_eq!(
        (l.owner, l.active_worker, l.assignment_sequence),
        (buyer, None, 2)
    );
    assert_eq!(
        changed_keys(&before, &r.book.records().unwrap()),
        BTreeSet::from([domain_hash(LICENSE_DOMAIN, &license)])
    );
    assert_eq!(
        r.book.pending_assignment(r.expected[2].license),
        Some(&other)
    );
    assert_eq!(
        r.book.active(license, r.expected[1].worker_id, 0).err(),
        Some(Error::StaleSequence)
    );
}

#[test]
fn assignment_due_before_the_sale_is_detached_as_history_not_cancelled() {
    // Execution order: `activate_due` (execution_v2.rs:164) runs before the trading phase
    // (execution_v2.rs:216). An assignment due at the sale block's epoch is therefore already
    // the active Worker when the sale applies: it is detached and kept as history.
    let mut r = rig();
    let license = r.expected[3].license;
    let due = reassignment(&r, 3, &r.seller, 43, 2, 2);
    schedule(&mut r.book, &due, 2, 1).unwrap();
    r.book.activate_due(2).unwrap();
    let worker = due.enrollment.binding.worker_id;
    assert!(r.book.active(license, worker, 2).is_ok());
    let sale = sale_of(&r.book, license, address(&r.buyer));
    assert_eq!(sale.expected, 2);
    assert_eq!(r.book.transfer(&sale), Ok(None));
    let l = r.book.license(license).unwrap();
    assert_eq!((l.active_worker, l.assignment_sequence), (None, 3));
    assert!(r.book.workers.contains_key(&worker));
    assert_eq!(
        r.book.active(license, worker, 2).err(),
        Some(Error::StaleSequence)
    );
}

#[test]
fn refused_sale_keeps_the_pending_assignment_and_the_book_byte_identical() {
    let mut r = rig();
    let license = r.expected[0].license;
    let pending = reassignment(&r, 0, &r.seller, 40, 2, 2);
    schedule(&mut r.book, &pending, 2, 1).unwrap();
    let rows = r.book.records().unwrap();
    let good = sale_of(&r.book, license, address(&r.buyer));
    // Every transfer rule other than the removed pending refusal is unchanged.
    let cases: [(&str, fn(&mut Sale)); 13] = [
        ("unknown License", |s| s.license = [0x77; 32]),
        ("other Genesis", |s| s.genesis = [3; 32]),
        ("seller is not the current owner", |s| s.from = [0x55; 32]),
        ("buyer equals seller", |s| s.to = s.from),
        ("stale expected sequence", |s| s.expected += 1),
        ("next sequence skips one", |s| s.next += 1),
        ("next sequence repeats", |s| s.next = s.expected),
        ("rights not from inclusion + 1", |s| s.rights = s.inclusion),
        ("zero operation", |s| s.operation = [0; 32]),
        ("zero trade", |s| s.trade = [0; 32]),
        ("zero contract", |s| s.contract = [0; 32]),
        ("zero generation", |s| s.generation = 0),
        ("zero payment commitment", |s| s.payment = [0; 32]),
    ];
    for (name, mutate) in cases {
        let mut s = good.clone();
        mutate(&mut s);
        assert_eq!(r.book.transfer(&s), Err(Error::WrongAnchor), "{name}");
        assert_eq!(r.book.records().unwrap(), rows, "{name}: refused sale changed the Book");
        assert_eq!(r.book.pending_assignment(license), Some(&pending), "{name}");
    }
    assert!(r.book.transfer(&good).unwrap().is_some());
}

#[test]
fn cancelled_assignment_yields_no_work_context_and_no_reward() {
    let mut r = rig();
    let license = r.expected[0].license;
    let (seller, buyer) = (address(&r.seller), address(&r.buyer));
    let pending = reassignment(&r, 0, &r.seller, 40, 2, 2);
    schedule(&mut r.book, &pending, 2, 1).unwrap();
    let sale = sale_of(&r.book, license, buyer);
    assert!(r.book.transfer(&sale).unwrap().is_some());
    // The full State also carries the sale's typed License transfer record, which the trading
    // path writes; a detached License without it is refused by `trading_host_v1::records`.
    let mut state = State {
        licenses_v2: r.book.clone(),
        ..Default::default()
    };
    state.protocol_records.insert(
        crate::trading_v1::record_key(4, license),
        crate::trading_v1::NativeRecord::License {
            context: crate::trading_v1::Context {
                network: NETWORK_ID,
                genesis: GENESIS,
                fingerprint: FINGERPRINT,
            },
            generation: 2,
            owner: buyer,
            previous_owner: seller,
            transfer: sale.operation,
            inclusion_height: sale.inclusion,
            rights_from_height: sale.rights,
            assignment_sequence: 2,
        }
        .encode(license)
        .unwrap(),
    );
    let rows = state.records().unwrap();
    let root = state.root().unwrap();
    assert_eq!(State::from_records(&rows, root).unwrap(), state);
    // Parent at height 9, after the sale's inclusion height 7.
    let parent = WorkParent {
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        block: [3; 32],
        height: 9,
        t0: 1000,
        target: [255; 32],
        ancestor_timestamps: (1000..1010).collect(),
    };
    let attempt = |license: Hash, worker: Hash, reward_owner: Hash, epoch: u64| {
        let body = BlockBody {
            height: 10,
            reward_owner,
            fees: 0,
            transactions: vec![],
            operations: vec![],
        };
        let candidate = Candidate {
            network: NETWORK_ID,
            genesis: GENESIS,
            fingerprint: FINGERPRINT,
            parent: [3; 32],
            height: 10,
            timestamp: 1000 + 60 * epoch,
            body_root: body.root().unwrap(),
            state_root: [0; 32],
            license,
            worker,
            target: [255; 32],
        };
        state.prepare_candidate_v2(CandidatePreparation {
            parent: &parent,
            candidate: &candidate,
            ticket_sequence: 1,
            body: &body,
        })
    };
    for epoch in [2, 3, 50] {
        // Neither the cancelled Worker nor the detached one can produce work for the sold
        // License: no block, hence no reward to anyone through the cancelled assignment.
        assert!(
            matches!(
                attempt(license, pending.enrollment.binding.worker_id, buyer, epoch),
                Err(ExecutionError::Codec(Error::UnknownSigner))
            ),
            "epoch {epoch}"
        );
        assert!(
            matches!(
                attempt(license, r.expected[0].worker_id, buyer, epoch),
                Err(ExecutionError::Codec(Error::StaleSequence))
            ),
            "epoch {epoch}"
        );
        // Control on the same parent: another License still produces a block, and its
        // coinbase goes to that License's owner.
        let ok = attempt(r.expected[1].license, r.expected[1].worker_id, seller, epoch).unwrap();
        let coinbase: Vec<_> = ok.state.coins.values().filter(|c| c.coinbase).collect();
        assert_eq!(coinbase.len(), 1, "epoch {epoch}");
        assert_eq!(coinbase[0].output.owner, seller, "epoch {epoch}");
    }
    assert_eq!(state.records().unwrap(), rows);
}

#[test]
fn assignment_id_domain_is_registered_proposed_unfrozen() {
    let registry: serde_json::Value =
        serde_json::from_str(include_str!("../../spec/DOMAIN-REGISTRY-V1.json")).unwrap();
    let ascii = std::str::from_utf8(ASSIGNMENT_ID_DOMAIN).unwrap();
    assert_eq!(ascii, "MUTINY-BUILD8-LICENSE-ASSIGNMENT-ID-V2");
    let entries: Vec<_> = registry["domains"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["ascii"] == ascii)
        .collect();
    assert_eq!(entries.len(), 1, "{ascii} registered exactly once");
    assert_eq!(entries[0]["status"], "PROPOSED-UNFROZEN", "{ascii}");
}
