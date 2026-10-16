#![cfg(feature = "dividend-test-fixtures")]
//! Delivery 1 integration gate: License DvP and dividend claims through REAL canonical blocks
//! (NATIVE, TEST-VALUE Treasury). Execution order inside a block is fixed by the protocol:
//! activation, dividend boundary processing, License scheduling and trades, dividend claims,
//! then the payment phase. A claim therefore sees ownership AFTER any License transfer in the
//! same block, whatever order the operations are listed in.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    block_envelope_v2::BlockEnvelope,
    canonical_store_v2::{CanonicalStore, Preparation},
    certificates::Decision,
    continuity_v2::{Certificate, Vote},
    dividend_claim_v1::{ClaimBody, SignedClaim, admit},
    dividend_state_v1::DividendState,
    dividends_v1::AWARD_PERIOD_EPOCHS as P,
    execution::State,
    mempool_v2::Mempool,
    op_envelope_v1::Envelope,
    pow::{WorkAuthority, WorkHeader},
    trading_v1::*,
    transactions::{Coin, OutPoint, Output},
    treasury_v1::{Class, Treasury},
    work_authority_v2::Authority,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "support/wallet_host_fixture_tpm.rs"]
mod tpm;
fn empty() -> HybridSignature {
    HybridSignature { ed448: [0; 114], fndsa: [0; 1280] }
}
const T0: u64 = 1000;
fn at(epoch: u64) -> u64 {
    T0 + 60 * epoch + 5
}
fn addr(k: &HybridKey) -> Hash {
    k.public().address_id(1).unwrap()
}
fn held_by(s: &State, owner: Hash) -> u64 {
    s.coins.values().filter(|c| !c.coinbase && c.output.owner == owner).map(|c| c.output.atoms).sum()
}

struct Fixture {
    state: State,
    genesis: FinalizedAnchor,
    coordinator: HybridKey,
    continuity: HybridKey,
    license: Hash,
    worker: Hash,
    backup_license: Hash,
    backup_worker: Hash,
}
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
            &state.wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest,
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
    state.wallets.records().expect("fixture wallets");
    state
        .continuity_keys_v2
        .records()
        .expect("fixture continuity keys");
    state
        .membership_v2
        .records(&state.continuity_keys_v2)
        .expect("fixture membership");
    state.licenses_v2.records().expect("fixture licenses");
    state
        .continuity
        .as_ref()
        .unwrap()
        .state_records()
        .expect("fixture continuity");
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
    }
}

fn certify(prepared: mutiny_consensus_v8::assembler_v2::Prepared, f: &Fixture) -> BlockEnvelope {
    certify_at(prepared, f, &f.genesis, &f.state, 1)
}
fn certify_at(
    prepared: mutiny_consensus_v8::assembler_v2::Prepared,
    f: &Fixture,
    parent: &FinalizedAnchor,
    state: &State,
    ticket: u64,
) -> BlockEnvelope {
    let height = prepared.candidate.height;
    let epoch = mutiny_consensus_v8::pow::mining_epoch(prepared.candidate.timestamp, 1000).unwrap();
    let mut book = state.licenses_v2.clone();
    book.activate_due(epoch).unwrap();
    let assignment = book
        .active(prepared.candidate.license, prepared.candidate.worker, epoch)
        .unwrap()
        .0
        .assignment_sequence;
    let mut authority = Authority {
        work: WorkAuthority {
            candidate: prepared.candidate.clone(),
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
        candidate: prepared.candidate,
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
        state: prepared.execution.root,
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
        body: prepared.body,
        authority,
        certificate: Certificate {
            decision,
            votes: vec![vote],
        },
    }
}


fn claim(f: &Fixture, signer: &HybridKey, license: Hash, amount: u64, sequence: u64, dest: Hash) -> Vec<u8> {
    let body = ClaimBody {
        network: NETWORK_ID,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
        created_height: 1,
        expiry_height: 10_000,
        award_epoch: P,
        license,
        amount,
        destination: dest,
        sequence,
    };
    SignedClaim::sign(body, signer.public().descriptor(1).unwrap(), signer).unwrap().encode()
}

#[test]
fn license_dvp_with_dividend_claims_orders_stale_seller_buyer_authority_and_atomic_failure() {
    let mut f = fixture();
    let seller = HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner).unwrap();
    let buyer = HybridKey::wallet_restore(
        &"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title".to_string(),
        Role::WalletOwner,
    )
    .unwrap();
    let treasury = HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap();
    let (seller_id, buyer_id, treasury_id) = (addr(&seller), addr(&buyer), addr(&treasury));
    f.state.wallets.register(&buyer.public().descriptor(1).unwrap()).unwrap();
    f.state.wallets.register(&treasury.public().descriptor(1).unwrap()).unwrap();
    let input = OutPoint { transaction: [173; 32], index: 0 };
    f.state.coins.clear();
    f.state.coins.insert(
        input.clone(),
        Coin { output: Output { owner: buyer_id, atoms: 100_000 }, created_height: 0, coinbase: false },
    );
    f.state.coins.insert(
        OutPoint { transaction: [0xd1; 32], index: 0 },
        Coin { output: Output { owner: treasury_id, atoms: 1_200_000 }, created_height: 0, coinbase: false },
    );
    // TEST-VALUE Treasury with the first award already outstanding at Genesis.
    f.state.dividends =
        DividendState::genesis(Treasury::new(Class::TestValue, treasury.public().descriptor(1).unwrap()).unwrap());
    f.state.fixture_advance_dividends(P).unwrap();
    let award = f.state.dividends.ledger().award(P).unwrap().account(&f.license).unwrap();
    assert_eq!((award.share, award.remaining, award.claims), (50_000, 50_000, 0));
    // The License DvP exactly as in the base host test.
    let context = Context { network: NETWORK_ID, genesis: f.genesis.genesis, fingerprint: f.genesis.fingerprint };
    // P7 (WP-T4, AM-6): the maker is the seller (slot 0) and signs with its wallet owner key.
    let maker: &HybridKey = &seller;
    let offer = SignedOffer::sign(
        OfferBody {
            context: context.clone(),
            maker_descriptor: maker.public().descriptor(1).unwrap(),
            maker_wallet: seller_id,
            destination: seller_id,
            condition: None,
            max_fee: Strikes(20_000),
            nonce: [175; 32],
            created: 1,
            expiry: 10,
            maker_side: 0,
            terms: OfferTerms::License { license: f.license, generation: 1, price: Strikes(50_000) },
        },
        &maker,
    )
    .unwrap();
    let mut operation = Operation {
        meta: Meta {
            context,
            trade: [176; 32],
            contract: [177; 32],
            generation: 1,
            // Body version 2: window [1, 10], the trusted Genesis block as finalized reference.
            envelope: Envelope {
                first_height: 1,
                last_height: 10,
                reference_height: 0,
                reference_block: f.genesis.block,
                preconditions: vec![],
            },
            fee: Strikes(20_000),
            inputs: vec![native_input_id(&input)],
        },
        action: Action::LicenseDvp {
            offer: offer.body.id().unwrap(),
            maker: offer.body.maker().unwrap(),
            license: f.license,
            license_generation: 1,
            seller: seller_id,
            buyer: buyer_id,
            price: Strikes(50_000),
            payment_destination: seller_id,
            change: Strikes(30_000),
        },
        approvals: vec![],
        offer_proof: None,
    };
    // WP-T2 (design 6.1): the sale commits the License facts it was reviewed against.
    operation.meta.envelope.preconditions = vec![
        mutiny_consensus_v8::op_envelope_v1::entitlement_facts(&f.state, f.license),
        mutiny_consensus_v8::op_envelope_v1::assignment_facts(&f.state, f.license).unwrap(),
    ];
    operation.offer_proof = Some(OfferProof::sign(offer, &operation, &maker).unwrap());
    operation.approve(0, &seller, 1).unwrap();
    operation.approve(1, &buyer, 1).unwrap();
    let trade = NativeOperation { operation, inputs: vec![input.clone()] }.encode().unwrap();
    let root = f.state.root().unwrap();
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base = std::env::temp_dir().join(format!("build8-license-dividends-{}", hex::encode(nonce)));
    std::fs::create_dir(&base).unwrap();
    let open = || CanonicalStore::open_trusted_genesis(&base.join("chain.sqlite"), &f.genesis, &f.state, root, T0, [255; 32]).unwrap();
    let mut chain = open();
    let mut pool = Mempool::open(&base.join("pool.sqlite"), f.genesis.genesis, f.genesis.fingerprint, 64 * 1024 * 1024).unwrap();
    chain.reconcile_pool(&mut pool).unwrap();
    let dest_seller = [0x51; 32];
    let dest_buyer = [0x52; 32];
    let prepare = |chain: &CanonicalStore, parent: &FinalizedAnchor, pool: &Mempool, license: Hash, worker: Hash, epoch: u64, ticket: u64, ops: &[Vec<u8>]| {
        chain.prepare_pending(Preparation {
            expected_parent: parent,
            pool,
            license,
            worker,
            timestamp: at(epoch),
            ticket,
            operations: ops,
        })
    };
    let before = chain.load().unwrap().1.records().unwrap();
    // Control: the transfer alone is accepted by assembly, and its tentative post-block state
    // is the exact view a claim in the same block sees. Read-only admission against that view
    // classifies the two claimants without committing anything.
    let control = prepare(&chain, &f.genesis, &pool, f.license, f.worker, P + 1, 1, &[trade.clone()]).unwrap();
    let post_trade = control.execution.state.clone();
    assert_eq!(post_trade.licenses_v2.license(f.license).unwrap().owner, buyer_id, "the transfer is applied before claims run");
    let stale_seller = claim(&f, &seller, f.license, 3_000, 0, dest_seller);
    let new_buyer = claim(&f, &buyer, f.license, 3_000, 0, dest_buyer);
    let (g, fp) = (f.genesis.genesis, f.genesis.fingerprint);
    assert_eq!(format!("{:?}", admit(&post_trade, &stale_seller, g, fp, 1, P + 1).unwrap_err()), "StaleOwner");
    admit(&post_trade, &new_buyer, g, fp, 1, P + 1).expect("the buyer holds claim authority after the transfer");
    // Same claim is valid against the pre-trade state for the seller (it was valid when signed).
    admit(&f.state, &stale_seller, g, fp, 1, P + 1).expect("the seller's claim is valid before the transfer");
    // Atomic failure through real blocks: nothing from a rejected block is applied.
    let rejected: [(&str, Vec<Vec<u8>>); 4] = [
        ("stale seller after DvP", vec![trade.clone(), stale_seller.clone()]),
        ("claim listed before the DvP (execution order is fixed, not the listing order)", vec![stale_seller.clone(), trade.clone()]),
        ("buyer over-claim", vec![trade.clone(), claim(&f, &buyer, f.license, 50_001, 0, dest_buyer)]),
        ("buyer wrong sequence", vec![trade.clone(), claim(&f, &buyer, f.license, 1_000, 1, dest_buyer)]),
    ];
    for (name, ops) in &rejected {
        let outcome = prepare(&chain, &f.genesis, &pool, f.license, f.worker, P + 1, 1, ops);
        eprintln!("REJECTED[{name}] = {:?}", outcome.as_ref().err());
        assert!(outcome.is_err(), "{name}");
        assert_eq!(chain.load().unwrap().0.height, 0, "{name}");
        assert_eq!(chain.load().unwrap().1.records().unwrap(), before, "{name}: exact canonical state preserved");
    }
    // Accepted block: DvP plus the buyer's claim, in the order the protocol fixes.
    let prepared = prepare(&chain, &f.genesis, &pool, f.license, f.worker, P + 1, 1, &[trade.clone(), new_buyer.clone()]).unwrap();
    assert_eq!(prepared.body.reward_owner, seller_id, "inclusion uses parent ownership for the block reward");
    let first = certify(prepared, &f);
    assert!(chain.commit(&first).unwrap());
    let anchor1 = first.certificate.decision.anchor();
    chain.reconcile_pool(&mut pool).unwrap();
    let (_, state1) = chain.load().unwrap();
    assert_eq!(state1.licenses_v2.license(f.license).unwrap().owner, buyer_id);
    // Entitlement preserved across the transfer: same award account, one claim recorded.
    let acct = state1.dividends.ledger().award(P).unwrap().account(&f.license).unwrap();
    assert_eq!((acct.share, acct.remaining, acct.claims), (50_000, 47_000, 1));
    assert_eq!(held_by(&state1, dest_buyer), 3_000, "paid to the destination the buyer signed");
    assert_eq!(held_by(&state1, treasury_id), 1_200_000 - 3_000);
    assert_eq!(state1.dividends.reserved(), 600_000 - 3_000);
    assert_eq!(held_by(&state1, seller_id), 50_000, "DvP payment reached the seller");
    let reward: u64 = state1.coins.values().filter(|c| c.coinbase && c.created_height == 1).map(|c| c.output.atoms).sum();
    assert_eq!(reward, 100_000_000 + 20_000, "trade fee only: the claim is fee-exempt and added none");
    // Later block, mined by the backup License: the stale seller can no longer claim; the buyer
    // continues the same sequence and may take any positive partial amount.
    let (bl, bw) = (f.backup_license, f.backup_worker);
    for (name, ops) in [
        ("stale seller", vec![claim(&f, &seller, f.license, 1_000, 1, dest_seller)]),
        ("replayed sequence", vec![claim(&f, &buyer, f.license, 1_000, 0, dest_buyer)]),
    ] {
        let outcome = prepare(&chain, &anchor1, &pool, bl, bw, P + 2, 1, &ops);
        eprintln!("REJECTED[{name}] = {:?}", outcome.as_ref().err());
        let text = format!("{:?}", outcome.err());
        assert!(text.contains("Dividend("), "{name} must fail on the dividend rule, not on assembly basis: {text}");
    }
    let second = prepare(&chain, &anchor1, &pool, bl, bw, P + 2, 1, &[claim(&f, &buyer, f.license, 1_000, 1, dest_buyer)]).unwrap();
    let second = certify_at(second, &f, &anchor1, &state1, 1);
    assert!(chain.commit(&second).unwrap());
    let (head2, state2) = chain.load().unwrap();
    let acct = state2.dividends.ledger().award(P).unwrap().account(&f.license).unwrap();
    assert_eq!((acct.remaining, acct.claims), (46_000, 2));
    // Restart reproduces the identical state, counters included.
    drop(chain);
    let reopened = open();
    assert_eq!(reopened.load().unwrap().0, head2);
    assert_eq!(reopened.load().unwrap().1.records().unwrap(), state2.records().unwrap());
    drop(reopened);
    drop(pool);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
    println!("LICENSE_DVP_DIVIDEND_PASS order=transfer_then_claim stale_seller_rejected=true buyer_authority=true entitlement_preserved=true atomic_failure=true restart=true");
}
