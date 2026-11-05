//! WP-Q17 real-block tests (Order Q17; Restart Order L64; P-LANE-DESIGN-V1 6.6, 11.2, 14.11;
//! P-LANE-DESIGN-AMENDMENTS-V1 AM-10): post-sale Worker assignment on REAL certified blocks, the
//! canonical store and the current trading path. Harness modelled on
//! consensus/tests/trading_host_v1.rs (its fixture and certify_at, lines 277-487). Exact errors are
//! asserted at the executor (`State::prepare_candidate_v2` over the store's own parent from
//! `CanonicalStore::execution_parent`), at the store (`prepare_pending`, whose assembler reports
//! the executor error as text, and `commit` of a certified block the executor refuses, with every
//! row of every store table compared before and after) and, for trading, at `prepare_batch`.
//! Public synthetic TEST-VALUE fixtures only: Windows-host software evidence, not Linux, physical
//! or production evidence.
//!
//! WP-T2 (P5): `dvp` builds trading body version 2 and commits the sold License's facts
//! (LicenseEntitlements, LicenseAssignment) of the state the sale was reviewed against;
//! `sale_with_a_pending_assignment_fails_closed_until_the_sale_commits_it` is the committed-pending
//! positive case of design 14.5 and its stale twin.
use mutiny_consensus_v8::{
    Error, Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    block_envelope_v2::BlockEnvelope,
    blocks::BlockBody,
    canonical_store_v2::{CanonicalStore, Preparation},
    certificates::Decision,
    continuity_v2::{Certificate, Vote},
    execution::{CandidatePreparation, Execution, ExecutionError, State},
    finality_v2::StoreError,
    license_assignment_v2::Assignment,
    mempool_v2::Mempool,
    pow::{Candidate, WorkAuthority, WorkHeader},
    trading_v1::*,
    transactions::{Coin, OutPoint, Output},
    votes::IngressError,
    work_authority_v2::Authority,
};
use mutiny_crypto_v2::{
    HybridKey, HybridSignature, Role,
    enrollment::{Binding, owner_descriptor_id},
};
use std::path::PathBuf;
#[path = "support/license_v2.rs"]
mod licenses;
#[path = "support/wallet_host_fixture_tpm.rs"]
mod tpm;

/// The buyer's only coin: it funds every sale attempt (price 50,000, fee 20,000, change 30,000).
const BUYER_COIN: OutPoint = OutPoint {
    transaction: [173; 32],
    index: 0,
};
/// The third party's only coin: it funds a re-sale by the buyer.
const THIRD_COIN: OutPoint = OutPoint {
    transaction: [174; 32],
    index: 0,
};

fn empty() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}
fn address(k: &HybridKey) -> Hash {
    k.public().address_id(1).unwrap()
}

struct Fixture {
    state: State,
    genesis: FinalizedAnchor,
    coordinator: HybridKey,
    continuity: HybridKey,
    expected: Vec<Binding>,
    seller: HybridKey,
    buyer: HybridKey,
    /// Buys License 0 from the buyer in the re-sale test.
    third: HybridKey,
    /// Genesis License 0: the License that is sold.
    license: Hash,
    /// Its Genesis Worker (synthetic seed 1).
    worker: Hash,
    /// Genesis License 1, never sold: it mines while License 0 cannot.
    backup_license: Hash,
    backup_worker: Hash,
}
/// The trading_host_v1.rs fixture (lines 287-394 there), plus a registered buyer holding
/// BUYER_COIN. Twelve Genesis Licenses owned by the seller, one Continuity voter.
fn fixture() -> Fixture {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-canonical-store-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let records: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let initial = State::from_records(&records, raw(&f["root"]).try_into().unwrap()).unwrap();
    let mut state = State {
        coins: initial.coins.clone(),
        wallets: initial.wallets.clone(),
        continuity: initial.continuity.clone(),
        ..Default::default()
    };
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let (owner, assignments, expected, licenses, coordinator) = licenses::fixtures();
    state
        .wallets
        .register(&owner.public().descriptor(1).unwrap())
        .unwrap();
    let continuity = HybridKey::generate(Role::Continuity).unwrap();
    let old_node = state.continuity.as_ref().unwrap().members[0].node;
    let mut binding = initial
        .membership_v2
        .get(old_node)
        .unwrap()
        .binding()
        .clone();
    binding.node_descriptor = coordinator.public().descriptor(1).unwrap();
    binding.admission.node =
        mutiny_consensus_v8::node_admission_v2::node_id(genesis.genesis, &binding.node_descriptor)
            .unwrap();
    binding.admission.continuity_descriptor = continuity.public().descriptor(1).unwrap();
    let ak = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let profile = tpm::profile(&ak);
    assert_eq!(binding.admission.profile, profile.encode().unwrap());
    binding.admission.prove_continuity(&continuity).unwrap();
    binding.admission.quote = tpm::quote(&ak, &profile, binding.admission.challenge().unwrap());
    binding.admission.authorize(&owner, 1).unwrap();
    binding.sign(&coordinator).unwrap();
    let policy = mutiny_consensus_v8::admission_v2::Policy {
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        owner_descriptor: owner.public().descriptor(1).unwrap(),
        endorsement_roots: [binding.admission.endorsement_root].into_iter().collect(),
    };
    let admission_expected = mutiny_consensus_v8::admission_v2::Expected {
        node: binding.admission.node,
        hardware_generation: 1,
        key_generation: 1,
        supervised_nonce: binding.admission.supervised_nonce,
    };
    (state.membership_v2, state.continuity_keys_v2) =
        mutiny_consensus_v8::membership_v2::Book::genesis(
            &binding,
            &policy,
            &admission_expected,
            &state.wallets,
            mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest,
        )
        .unwrap();
    state.continuity.as_mut().unwrap().members[0].node = binding.admission.node;
    state.licenses_v2 = mutiny_consensus_v8::license_book_v2::Book::genesis(
        &assignments,
        &expected,
        &licenses,
        &state.wallets,
        genesis.genesis,
        genesis.fingerprint,
    )
    .unwrap();
    state.admission_policy_v2 =
        Some(mutiny_consensus_v8::admission_policy_v2::Record::new(policy).unwrap());
    let buyer =
        HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap();
    state
        .wallets
        .register(&buyer.public().descriptor(1).unwrap())
        .unwrap();
    let third = HybridKey::wallet_restore(
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        Role::WalletOwner,
    )
    .unwrap();
    state
        .wallets
        .register(&third.public().descriptor(1).unwrap())
        .unwrap();
    state.coins.clear();
    for (point, owner) in [(BUYER_COIN, address(&buyer)), (THIRD_COIN, address(&third))] {
        state.coins.insert(
            point,
            Coin {
                output: Output {
                    owner,
                    atoms: 100_000,
                },
                created_height: 0,
                coinbase: false,
            },
        );
    }
    let rows = state.records().expect("fixture records");
    State::from_records(&rows, state.root().unwrap()).expect("fixture restore");
    Fixture {
        state,
        genesis,
        coordinator,
        continuity,
        license: licenses[0].id,
        worker: expected[0].worker_id,
        backup_license: licenses[1].id,
        backup_worker: expected[1].worker_id,
        expected,
        seller: owner,
        buyer,
        third,
    }
}

/// LicenseDvp (trading body version 2): License 0 from the seller to the buyer for 50,000 atoms,
/// fee 20,000, change 30,000, valid only at the height after `parent`.
fn sale_operation(f: &Fixture, reviewed: &State, parent: &FinalizedAnchor) -> Vec<u8> {
    dvp(f, reviewed, &f.seller, &f.buyer, BUYER_COIN, 1, parent, 175)
}
/// License 0 from `from` to `to` (funded by `coin`) at License generation `generation`. Its
/// envelope window is the single height after `parent` and its reference is `parent` (the
/// finalized parent anchor); `tag` separates offer nonces and trade/contract ids of sales.
fn dvp(
    f: &Fixture,
    reviewed: &State,
    from: &HybridKey,
    to: &HybridKey,
    coin: OutPoint,
    generation: u64,
    parent: &FinalizedAnchor,
    tag: u8,
) -> Vec<u8> {
    let height = parent.height + 1;
    let (seller, buyer) = (address(from), address(to));
    let context = Context {
        network: NETWORK_ID,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
    };
    // P7 (WP-T4, AM-6): the seller (slot 0) makes the offer with its wallet key.
    let maker = from;
    let offer = SignedOffer::sign(
        OfferBody {
            context: context.clone(),
            maker_descriptor: maker.public().descriptor(1).unwrap(),
            maker_wallet: seller,
            destination: seller,
            condition: None,
            max_fee: Strikes(20_000),
            nonce: [tag; 32],
            created: 1,
            expiry: 10,
            maker_side: 0,
            terms: OfferTerms::License {
                license: f.license,
                generation,
                price: Strikes(50_000),
            },
        },
        maker,
    )
    .unwrap();
    let mut operation = Operation {
        meta: Meta {
            context,
            trade: [tag.wrapping_add(1); 32],
            contract: [tag.wrapping_add(2); 32],
            generation: 1,
            envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                first_height: height,
                last_height: height,
                reference_height: parent.height,
                reference_block: parent.block,
                // WP-T2 (design 6.1): the License facts the sale was reviewed against.
                preconditions: vec![
                    mutiny_consensus_v8::op_envelope_v1::entitlement_facts(reviewed, f.license),
                    mutiny_consensus_v8::op_envelope_v1::assignment_facts(reviewed, f.license).unwrap(),
                ],
            },
            fee: Strikes(20_000),
            inputs: vec![native_input_id(&coin)],
        },
        action: Action::LicenseDvp {
            offer: offer.body.id().unwrap(),
            maker: offer.body.maker().unwrap(),
            license: f.license,
            license_generation: generation,
            seller,
            buyer,
            price: Strikes(50_000),
            payment_destination: seller,
            change: Strikes(30_000),
        },
        approvals: vec![],
        offer_proof: None,
    };
    operation.offer_proof = Some(OfferProof::sign(offer, &operation, maker).unwrap());
    operation.approve(0, from, 1).unwrap();
    operation.approve(1, to, 1).unwrap();
    NativeOperation {
        operation,
        inputs: vec![coin],
    }
    .encode()
    .unwrap()
}

/// A reassignment of Genesis License `index` to synthetic Worker `seed`, authorized by `owner`,
/// with the given generation and effective epoch (inclusion deadline height 100).
fn reassignment(
    f: &Fixture,
    index: usize,
    owner: &HybridKey,
    seed: u8,
    generation: u64,
    effective_epoch: u64,
) -> Assignment {
    let mut b = f.expected[index].clone();
    b.owner_descriptor = owner_descriptor_id(owner.public(), 1).unwrap();
    b.owner_generation = 1;
    b.worker_public = licenses::worker(seed);
    b.worker_id = b.derived_worker_id();
    b.assignment_generation = generation;
    b.configuration_generation = 2;
    b.device_mac = [2, 0, 0, 0, 0, seed];
    b.effective_epoch = effective_epoch;
    b.valid_until_height = 100;
    licenses::sign(b, owner, &f.coordinator.public().descriptor(1).unwrap(), seed)
}

fn certify_at(
    prepared: mutiny_consensus_v8::assembler_v2::Prepared,
    f: &Fixture,
    parent: &FinalizedAnchor,
    state: &State,
    ticket: u64,
) -> BlockEnvelope {
    let root = prepared.execution.root;
    certify_parts(prepared.candidate, prepared.body, root, f, parent, state, ticket)
}
/// trading_host_v1.rs certify_at (lines 399-487) on explicit parts, so that a block that the
/// executor refuses can still be certified and offered to `CanonicalStore::commit`.
fn certify_parts(
    candidate: Candidate,
    body: BlockBody,
    state_root: Hash,
    f: &Fixture,
    parent: &FinalizedAnchor,
    state: &State,
    ticket: u64,
) -> BlockEnvelope {
    let height = candidate.height;
    let epoch = mutiny_consensus_v8::pow::mining_epoch(candidate.timestamp, 1000).unwrap();
    let mut book = state.licenses_v2.clone();
    book.activate_due(epoch).unwrap();
    let assignment = book
        .active(candidate.license, candidate.worker, epoch)
        .unwrap()
        .0
        .assignment_sequence;
    let mut authority = Authority {
        work: WorkAuthority {
            candidate: candidate.clone(),
            assignment_sequence: assignment,
            ticket_sequence: ticket,
            coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(
                &f.coordinator.public().descriptor(1).unwrap(),
            )
            .unwrap(),
            nonce_start: 0,
            nonce_end: 100,
            epoch,
        },
        node_descriptor: f.coordinator.public().descriptor(1).unwrap(),
        signature: empty(),
    };
    authority.sign(&f.coordinator).unwrap();
    let header = WorkHeader {
        candidate,
        authority: authority.id().unwrap(),
        nonce: 1,
    };
    assert!(mutiny_consensus_v8::pow::meets_target(
        &header.block_hash(),
        &[255; 32]
    ));
    let height_authority = mutiny_consensus_v8::votes_v2::HeightAuthority::from_state(
        state,
        parent.clone(),
        state.root().unwrap(),
    )
    .unwrap();
    let (node, voter) = height_authority.voters.iter().next().unwrap();
    let decision = Decision {
        network: f.genesis.network,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
        purpose: 2,
        height,
        mining_epoch: epoch,
        continuity_period: (height - 1) / 60,
        round: 0,
        step: 3,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: header.block_hash(),
        state: state_root,
        membership: height_authority.membership,
        reputation: height_authority.reputation,
        attestation: height_authority.attestation,
    };
    let mut vote = Vote {
        decision: decision.clone(),
        nil: false,
        node: *node,
        hardware_generation: voter.hardware_generation,
        key_generation: voter.key_generation,
        sequence: height * 10,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: empty(),
    };
    vote.sign(&f.continuity).unwrap();
    BlockEnvelope {
        header,
        body,
        authority,
        certificate: Certificate {
            decision,
            votes: vec![vote],
        },
    }
}

/// A canonical store and pool in a unique, atomically created temporary directory.
struct Chain {
    base: PathBuf,
    store: CanonicalStore,
    pool: Mempool,
}
impl Chain {
    fn open(f: &Fixture) -> Self {
        let base = (0..16)
            .find_map(|_| {
                let mut nonce = [0; 16];
                mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
                let path =
                    std::env::temp_dir().join(format!("build8-q17-sale-{}", hex::encode(nonce)));
                match std::fs::create_dir(&path) {
                    Ok(()) => Some(path),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(e) => panic!("{e}"),
                }
            })
            .expect("a unique temporary directory");
        let store = CanonicalStore::open_trusted_genesis(
            &base.join("chain.sqlite"),
            &f.genesis,
            &f.state,
            f.state.root().unwrap(),
            1000,
            [255; 32],
        )
        .unwrap();
        let mut pool = Mempool::open(
            &base.join("pool.sqlite"),
            f.genesis.genesis,
            f.genesis.fingerprint,
            64 * 1024 * 1024,
        )
        .unwrap();
        store.reconcile_pool(&mut pool).unwrap();
        Self { base, store, pool }
    }
    fn close(self) {
        let Self { base, store, pool } = self;
        drop(store);
        drop(pool);
        assert!(base.starts_with(std::env::temp_dir()));
        std::fs::remove_dir_all(base).unwrap();
    }
    /// Prepare through the store, certify and commit one real block over `parent` (the tip).
    #[allow(clippy::too_many_arguments)]
    fn mine(
        &mut self,
        f: &Fixture,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        ticket: u64,
        operations: &[Vec<u8>],
    ) -> FinalizedAnchor {
        let (_, parent_state) = self.store.load().unwrap();
        let prepared = self
            .store
            .prepare_pending(Preparation {
                expected_parent: parent,
                pool: &self.pool,
                license,
                worker,
                timestamp,
                ticket,
                operations,
            })
            .unwrap();
        let block = certify_at(prepared, f, parent, &parent_state, ticket);
        assert!(self.store.commit(&block).unwrap());
        self.store.reconcile_pool(&mut self.pool).unwrap();
        block.certificate.decision.anchor()
    }
    /// The executor's own verdict on a candidate block over the committed tip, with the parent
    /// the store gives the executor (`execution_parent`).
    #[allow(clippy::too_many_arguments)]
    fn execute(
        &self,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        ticket: u64,
        reward_owner: Hash,
        fees: u64,
        operations: &[Vec<u8>],
    ) -> std::result::Result<Execution, ExecutionError> {
        let (candidate, body) = self.candidate(license, worker, timestamp, reward_owner, fees, operations);
        let (head, _) = self.store.load().unwrap();
        let (parent, state, _) = self.store.execution_parent(head.height).unwrap();
        state.prepare_candidate_v2(CandidatePreparation {
            parent: &parent,
            candidate: &candidate,
            ticket_sequence: ticket,
            body: &body,
        })
    }
    fn candidate(
        &self,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        reward_owner: Hash,
        fees: u64,
        operations: &[Vec<u8>],
    ) -> (Candidate, BlockBody) {
        let (head, _) = self.store.load().unwrap();
        let (parent, _, root) = self.store.execution_parent(head.height).unwrap();
        let body = BlockBody {
            height: parent.height + 1,
            reward_owner,
            fees,
            transactions: vec![],
            operations: operations.to_vec(),
        };
        let candidate = Candidate {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            parent: parent.block,
            height: parent.height + 1,
            timestamp,
            body_root: body.root().unwrap(),
            state_root: root,
            license,
            worker,
            target: parent.target,
        };
        (candidate, body)
    }
    /// The store's refusal to prepare a block: the assembler's text of the executor error.
    fn refusal(
        &self,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        ticket: u64,
        operations: &[Vec<u8>],
    ) -> String {
        match self.store.prepare_pending(Preparation {
            expected_parent: parent,
            pool: &self.pool,
            license,
            worker,
            timestamp,
            ticket,
            operations,
        }) {
            Err(StoreError::Assembly(reason)) => reason,
            Err(other) => panic!("expected an assembly refusal, got {other:?}"),
            Ok(_) => panic!("the store prepared a block that must be refused"),
        }
    }
    /// Offer `commit` a CERTIFIED block over `parent` whose body the executor refuses (state
    /// root = the parent's); return its error.
    #[allow(clippy::too_many_arguments)]
    fn commit_refused(
        &mut self,
        f: &Fixture,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        ticket: u64,
        reward_owner: Hash,
        fees: u64,
        operations: &[Vec<u8>],
    ) -> StoreError {
        let (_, state) = self.store.load().unwrap();
        let (candidate, body) = self.candidate(license, worker, timestamp, reward_owner, fees, operations);
        let root = candidate.state_root;
        let block = certify_parts(candidate, body, root, f, parent, &state, ticket);
        self.store.commit(&block).expect_err("a refused block must not commit")
    }
    /// Every row of every table of the canonical store database (state_v2, undo_v2,
    /// confirmations_v2, canonical_v2, finalized_v2, evidence_v2, proof index, ...), read through
    /// an independent read-only connection and sorted.
    fn tables(&self) -> Vec<String> {
        let db = rusqlite::Connection::open_with_flags(
            self.base.join("chain.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let names: Vec<String> = db
            .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(names.iter().any(|n| n == "state_v2") && names.iter().any(|n| n == "undo_v2"));
        let mut rows = Vec::new();
        for name in names {
            let mut statement = db.prepare(&format!("SELECT * FROM \"{name}\"")).unwrap();
            let columns = statement.column_count();
            let mut query = statement.query([]).unwrap();
            while let Some(row) = query.next().unwrap() {
                let values: Vec<rusqlite::types::Value> =
                    (0..columns).map(|i| row.get(i).unwrap()).collect();
                rows.push(format!("{name}:{values:?}"));
            }
        }
        assert!(!rows.is_empty());
        rows.sort();
        rows
    }
}

/// Unchanged behaviour of a sale with no pending assignment (Q17 brief item 6): the active Worker
/// is detached and kept as history, the sequence moves to 2, and the old owner's Worker loses its
/// authority at the first canonical-state gate after the sale's block is committed: the store
/// reads behind the node's live-channel gate (`current_worker_session`, used by
/// `CanonicalWorkerChannel::check`) and work issuance (`current_work_context`) refuse it with
/// StaleSequence, and so does the executor for its next block.
#[test]
fn sale_without_pending_assignment_detaches_the_worker_and_its_sessions_lose_rights() {
    let f = fixture();
    let mut chain = Chain::open(&f);
    let buyer = address(&f.buyer);
    assert!(
        chain
            .store
            .current_worker_session(&f.genesis, f.license, f.worker, 1100)
            .is_ok()
    );
    let anchor1 = chain.mine(&f, &f.genesis, f.license, f.worker, 1100, 1, &[sale_operation(&f, &f.state, &f.genesis)]);
    let (_, state1) = chain.store.load().unwrap();
    let l = state1.licenses_v2.license(f.license).unwrap();
    assert_eq!(
        (l.owner, l.active_worker, l.assignment_sequence),
        (buyer, None, 2)
    );
    assert_eq!(state1.licenses_v2.pending_assignment(f.license), None);
    assert_eq!(
        state1.licenses_v2.active(f.license, f.worker, 1).err(),
        Some(Error::StaleSequence)
    );
    let historic =
        mutiny_consensus_v8::domain_hash(b"MUTINY-BUILD8-WORKER-STATE-KEY-V2", &f.worker);
    assert!(state1.licenses_v2.records().unwrap().contains_key(&historic));
    for timestamp in [1101, 1120, 1_000_000] {
        assert!(
            matches!(
                chain
                    .store
                    .current_worker_session(&anchor1, f.license, f.worker, timestamp),
                Err(StoreError::Execution(ExecutionError::Codec(Error::StaleSequence)))
            ),
            "timestamp {timestamp}"
        );
        assert!(
            matches!(
                chain
                    .store
                    .current_work_context(&anchor1, f.license, f.worker, timestamp),
                Err(StoreError::Execution(ExecutionError::Codec(Error::StaleSequence)))
            ),
            "timestamp {timestamp}"
        );
    }
    let refused = chain.execute(f.license, f.worker, 1101, 2, buyer, 0, &[]);
    assert!(
        matches!(refused, Err(ExecutionError::Codec(Error::StaleSequence))),
        "{:?}",
        refused.err()
    );
    chain.close();
}

/// New-owner authorization (design 11.2; Q17 brief item 6): an assignment is authorized by the
/// PARENT-state owner, so the buyer cannot schedule one in the sale's own block, in either body
/// order; the exact error is the WalletBook authority refusal, and a certified block carrying
/// it changes no store row. From the next block the buyer authorizes generation 3.
#[test]
fn buyer_cannot_schedule_an_assignment_in_the_sale_block() {
    let f = fixture();
    let mut chain = Chain::open(&f);
    let seller = address(&f.seller);
    let sale = sale_operation(&f, &f.state, &f.genesis);
    // Generation 2 = parent sequence + 1 and effective epoch 2 = inclusion epoch 1 + 1: valid in
    // every respect except that the seller, the parent-state owner, did not authorize it.
    let early = reassignment(&f, 0, &f.buyer, 29, 2, 2).encode().unwrap();
    let tables = chain.tables();
    for ops in [vec![sale.clone(), early.clone()], vec![early.clone(), sale.clone()]] {
        let refused = chain.execute(f.license, f.worker, 1100, 1, seller, 20_000, &ops);
        assert!(
            matches!(refused, Err(ExecutionError::Codec(Error::WrongGeneration))),
            "{:?}",
            refused.err()
        );
        assert_eq!(
            chain.refusal(&f.genesis, f.license, f.worker, 1100, 1, &ops),
            "Hybrid candidate execution: Codec(WrongGeneration)"
        );
        let error = chain.commit_refused(&f, &f.genesis, f.license, f.worker, 1100, 1, seller, 20_000, &ops);
        assert!(
            matches!(
                error,
                StoreError::Verification(IngressError::Execution(ExecutionError::Codec(
                    Error::WrongGeneration
                )))
            ),
            "{error:?}"
        );
        assert_eq!(chain.tables(), tables);
    }
    let anchor1 = chain.mine(&f, &f.genesis, f.license, f.worker, 1100, 1, &[sale]);
    assert_ne!(chain.tables(), tables, "the table dump sees a committed block");
    let fresh = reassignment(&f, 0, &f.buyer, 29, 3, 2);
    chain.mine(
        &f,
        &anchor1,
        f.backup_license,
        f.backup_worker,
        1101,
        1,
        &[fresh.encode().unwrap()],
    );
    assert_eq!(
        chain
            .store
            .load()
            .unwrap()
            .1
            .licenses_v2
            .pending_assignment(f.license),
        Some(&fresh)
    );
    chain.close();
}

/// The detached Worker key can never be enrolled again (Q17 brief item 6): neither by the buyer
/// on the sold License nor by the seller on another License; exact error Duplicate, and a
/// certified block carrying either assignment changes no store row.
#[test]
fn old_worker_key_can_never_be_re_enrolled_after_the_sale() {
    let f = fixture();
    let mut chain = Chain::open(&f);
    let seller = address(&f.seller);
    let anchor1 = chain.mine(&f, &f.genesis, f.license, f.worker, 1100, 1, &[sale_operation(&f, &f.state, &f.genesis)]);
    // License 0's Genesis Worker key is synthetic seed 1 (support/license_v2.rs: worker(i + 1)).
    assert_eq!(licenses::worker(1), f.expected[0].worker_public);
    let cases = [
        ("buyer, sold License", reassignment(&f, 0, &f.buyer, 1, 3, 2)),
        ("seller, another License", reassignment(&f, 1, &f.seller, 1, 2, 2)),
    ];
    let tables = chain.tables();
    for (label, a) in cases {
        let ops = [a.encode().unwrap()];
        let refused = chain.execute(f.backup_license, f.backup_worker, 1101, 1, seller, 0, &ops);
        assert!(
            matches!(refused, Err(ExecutionError::Codec(Error::Duplicate))),
            "{label}: {:?}",
            refused.err()
        );
        assert_eq!(
            chain.refusal(&anchor1, f.backup_license, f.backup_worker, 1101, 1, &ops),
            "Hybrid candidate execution: Codec(Duplicate)",
            "{label}"
        );
        let error = chain.commit_refused(&f, &anchor1, f.backup_license, f.backup_worker, 1101, 1, seller, 0, &ops);
        assert!(
            matches!(
                error,
                StoreError::Verification(IngressError::Execution(ExecutionError::Codec(
                    Error::Duplicate
                )))
            ),
            "{label}: {error:?}"
        );
        assert_eq!(chain.tables(), tables, "{label}");
    }
    chain.close();
}

/// The mining/reward boundary (Order Q17; design 11.2 e): the reward of the sale block H goes to
/// the seller (parent-state owner); from H+1 no Worker of the sold License has authority, so it
/// produces no block and no reward, until the buyer's assignment activates at its signed epoch
/// (exactly inclusion epoch + 1, AM-10); then the License mines for the buyer.
#[test]
fn sale_block_reward_goes_to_the_seller_then_none_until_buyer_activation_then_the_buyer() {
    let f = fixture();
    let mut chain = Chain::open(&f);
    let (seller, buyer) = (address(&f.seller), address(&f.buyer));
    let coinbase_at = |state: &State, height: u64| -> Vec<Output> {
        state
            .coins
            .values()
            .filter(|c| c.coinbase && c.created_height == height)
            .map(|c| c.output.clone())
            .collect()
    };
    // H1 (epoch 1): the sale, mined through the sold License itself.
    let anchor1 = chain.mine(&f, &f.genesis, f.license, f.worker, 1100, 1, &[sale_operation(&f, &f.state, &f.genesis)]);
    // H2 (epoch 1): the buyer's assignment (generation 3, effective epoch 2), mined by License 1.
    let fresh = reassignment(&f, 0, &f.buyer, 29, 3, 2);
    let new_worker = fresh.enrollment.binding.worker_id;
    let anchor2 = chain.mine(
        &f,
        &anchor1,
        f.backup_license,
        f.backup_worker,
        1101,
        1,
        &[fresh.encode().unwrap()],
    );
    // H3 (still epoch 1): neither the detached nor the pending Worker has authority over the
    // sold License: no block can name it, at the executor or behind the node's channel gate.
    for (worker, error) in [
        (f.worker, Error::StaleSequence),
        (new_worker, Error::UnknownSigner),
    ] {
        let refused = chain.execute(f.license, worker, 1110, 1, buyer, 0, &[]);
        assert!(
            matches!(refused, Err(ExecutionError::Codec(e)) if e == error),
            "{:?}",
            refused.err()
        );
        assert!(matches!(
            chain.store.current_worker_session(&anchor2, f.license, worker, 1110),
            Err(StoreError::Execution(ExecutionError::Codec(e))) if e == error
        ));
    }
    let anchor3 = chain.mine(&f, &anchor2, f.backup_license, f.backup_worker, 1110, 2, &[]);
    // H4 (epoch 2): the buyer's assignment is active; the sold License mines for the buyer.
    assert!(
        chain
            .store
            .current_worker_session(&anchor3, f.license, new_worker, 1120)
            .is_ok()
    );
    chain.mine(&f, &anchor3, f.license, new_worker, 1120, 1, &[]);
    let (_, state4) = chain.store.load().unwrap();
    assert_eq!(
        coinbase_at(&state4, 1),
        vec![Output {
            owner: seller,
            atoms: 100_020_000
        }]
    );
    for height in [2, 3] {
        assert_eq!(
            coinbase_at(&state4, height),
            vec![Output {
                owner: seller,
                atoms: 100_000_000
            }],
            "height {height}: License 1's owner"
        );
    }
    assert_eq!(
        coinbase_at(&state4, 4),
        vec![Output {
            owner: buyer,
            atoms: 100_000_000
        }]
    );
    let (l, w) = state4.licenses_v2.active(f.license, new_worker, 2).unwrap();
    assert_eq!(
        (l.owner, l.assignment_sequence, w.last_accepted_ticket),
        (buyer, 3, 1)
    );
    chain.close();
}

/// WP-T2 (design 6.6, Restart Order L64): a sale reviewed before the seller scheduled the pending
/// assignment commits "no pending assignment" and is stale (NativeError::Stale(2)); the sale that
/// commits the pending assignment's id cancels it and the cancelled assignment never activates. The Book-level cancellation itself is tested
/// in consensus/src/license_book_v2_sale_tests.rs. The refused block changes no store row, and
/// the seller's pending assignment later activates as if the sale had never been offered.
#[test]
fn sale_with_a_pending_assignment_fails_closed_until_the_sale_commits_it() {
    let f = fixture();
    let mut chain = Chain::open(&f);
    let seller = address(&f.seller);
    // H1 (epoch 1): the seller schedules a reassignment of License 0, effective epoch 2.
    let pending = reassignment(&f, 0, &f.seller, 29, 2, 2);
    let anchor1 = chain.mine(
        &f,
        &f.genesis,
        f.license,
        f.worker,
        1100,
        1,
        &[pending.encode().unwrap()],
    );
    let (_, state1) = chain.store.load().unwrap();
    assert_eq!(state1.licenses_v2.pending_assignment(f.license), Some(&pending));
    let sale = [sale_operation(&f, &f.state, &anchor1)];
    assert_eq!(
        prepare_batch(
            &state1,
            &anchor1,
            state1.root().unwrap(),
            &sale,
            &CandidatePolicy::native_denomination_locked()
        )
        .err(),
        Some(NativeError::Stale(2))
    );
    let refused = chain.execute(f.license, f.worker, 1101, 2, seller, 20_000, &sale);
    assert!(
        matches!(refused, Err(ExecutionError::UnsupportedOperation)),
        "{:?}",
        refused.err()
    );
    let tables = chain.tables();
    assert_eq!(
        chain.refusal(&anchor1, f.license, f.worker, 1101, 2, &sale),
        "Hybrid candidate execution: UnsupportedOperation"
    );
    let error = chain.commit_refused(&f, &anchor1, f.license, f.worker, 1101, 2, seller, 20_000, &sale);
    assert!(
        matches!(
            error,
            StoreError::Verification(IngressError::Execution(ExecutionError::UnsupportedOperation))
        ),
        "{error:?}"
    );
    assert_eq!(chain.tables(), tables);
    // H2 (still epoch 1): the sale committing the pending assignment cancels it.
    let committed = [sale_operation(&f, &state1, &anchor1)];
    let anchor2 = chain.mine(&f, &anchor1, f.license, f.worker, 1101, 2, &committed);
    assert_ne!(chain.tables(), tables, "the table dump sees a committed block");
    let (_, state2) = chain.store.load().unwrap();
    let l = state2.licenses_v2.license(f.license).unwrap();
    assert_eq!((l.owner, l.active_worker, l.assignment_sequence), (address(&f.buyer), None, 2));
    assert_eq!(state2.licenses_v2.pending_assignment(f.license), None);
    // Epoch 2: the cancelled assignment never activates.
    let new_worker = pending.enrollment.binding.worker_id;
    chain.mine(&f, &anchor2, f.backup_license, f.backup_worker, 1120, 1, &[]);
    let (_, state3) = chain.store.load().unwrap();
    assert!(state3.licenses_v2.active(f.license, new_worker, 2).is_err());
    assert_eq!(state3.licenses_v2.license(f.license).unwrap().active_worker, None);
    let _ = seller;
    chain.close();
}

/// Boundary (e) of the sale in block H: the License record stores `rights_from_height = H + 1`
/// (trading_v1.rs 2681) and a DvP at height h needs it to be at most h (2658-2660). A re-sale by
/// the buyer in the sale's own block is rejected (NativeError::Time; the whole block is refused
/// and no store row changes); from H + 1 it is accepted (at License generation 2).
#[test]
fn re_sale_needs_rights_from_the_height_after_the_sale() {
    let f = fixture();
    let mut chain = Chain::open(&f);
    let seller = address(&f.seller);
    let sale = sale_operation(&f, &f.state, &f.genesis);
    // The re-sale commits the facts after the sale (so the refusal is the rights boundary, Time).
    let after_sale = prepare_batch(
        &f.state,
        &f.genesis,
        f.state.root().unwrap(),
        std::slice::from_ref(&sale),
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap()
    .into_state();
    let same_block = [sale.clone(), dvp(&f, &after_sale, &f.buyer, &f.third, THIRD_COIN, 2, &f.genesis, 0x40)];
    assert_eq!(
        prepare_batch(
            &f.state,
            &f.genesis,
            f.state.root().unwrap(),
            &same_block,
            &CandidatePolicy::native_denomination_locked()
        )
        .err(),
        Some(NativeError::Time)
    );
    let refused = chain.execute(f.license, f.worker, 1100, 1, seller, 40_000, &same_block);
    assert!(
        matches!(refused, Err(ExecutionError::UnsupportedOperation)),
        "{:?}",
        refused.err()
    );
    let tables = chain.tables();
    assert_eq!(
        chain.refusal(&f.genesis, f.license, f.worker, 1100, 1, &same_block),
        "Hybrid candidate execution: UnsupportedOperation"
    );
    let error = chain.commit_refused(&f, &f.genesis, f.license, f.worker, 1100, 1, seller, 40_000, &same_block);
    assert!(
        matches!(
            error,
            StoreError::Verification(IngressError::Execution(ExecutionError::UnsupportedOperation))
        ),
        "{error:?}"
    );
    assert_eq!(chain.tables(), tables);
    let anchor1 = chain.mine(&f, &f.genesis, f.license, f.worker, 1100, 1, &[sale]);
    let (_, state1) = chain.store.load().unwrap();
    let resale = dvp(&f, &state1, &f.buyer, &f.third, THIRD_COIN, 2, &anchor1, 0x40);
    chain.mine(&f, &anchor1, f.backup_license, f.backup_worker, 1101, 1, &[resale]);
    let (_, state2) = chain.store.load().unwrap();
    let l = state2.licenses_v2.license(f.license).unwrap();
    assert_eq!(
        (l.owner, l.active_worker, l.assignment_sequence),
        (address(&f.third), None, 3)
    );
    chain.close();
}
