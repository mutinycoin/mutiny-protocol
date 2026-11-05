// Shared block-driver rig for the dividends and the D2 Treasury rehearsal tests (NATIVE, TEST-VALUE).
// Included with include! by tests/dividends_v1.rs and tests/treasury_rehearsal_rotation_v1.rs; the including
// file declares the `licenses` and `tpm` fixture modules. Extracted verbatim from dividends_v1.rs.
#[allow(unused_imports)]
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    block_envelope_v2::BlockEnvelope,
    blocks::genesis_license,
    canonical_store_v2::{CanonicalStore, Preparation},
    certificates::Decision,
    continuity_v2::{Certificate, Vote},
    dividend_claim_v1::{ClaimBody, SignedClaim},
    dividend_state_v1::DividendState,
    dividends_v1::{AWARD_PERIOD_EPOCHS as P, CLAIM_WINDOW_EPOCHS as W},
    execution::{CandidatePreparation, State},
    hybrid_transaction_v2::Transaction,
    mempool_v2::Mempool,
    pow::{WorkAuthority, WorkHeader},
    transactions::{Coin, OutPoint, Output},
    transactions_v2::{Input, Transfer},
    treasury_v1::{Class, Treasury},
    wallet_rotation_v1::Rotation,
    work_authority_v2::Authority,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
fn empty() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
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
        "../../../qualification/hybrid-canonical-store-public-v1.json"
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


const T0: u64 = 1000;
const SUBSIDY: u64 = 100_000_000;
fn at(epoch: u64) -> u64 {
    T0 + 60 * epoch + 5
}
fn owner_key() -> HybridKey {
    HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner).unwrap()
}
fn treasury_key() -> HybridKey {
    HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap()
}
fn second_key() -> HybridKey {
    HybridKey::wallet_restore(
        &"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title".to_string(),
        Role::WalletOwner,
    )
    .unwrap()
}
fn addr(k: &HybridKey, generation: u64) -> Hash {
    k.public().address_id(generation).unwrap()
}
fn desc(k: &HybridKey, generation: u64) -> Vec<u8> {
    k.public().descriptor(generation).unwrap()
}
fn total(s: &State) -> u64 {
    s.coins.values().map(|c| c.output.atoms).sum()
}
fn held_by(s: &State, owner: Hash) -> u64 {
    s.coins
        .values()
        .filter(|c| !c.coinbase && c.output.owner == owner)
        .map(|c| c.output.atoms)
        .sum()
}
fn license(index: u64) -> Hash {
    genesis_license([1; 32], index).unwrap()
}
fn fixture_with_treasury(treasury: &HybridKey, atoms: u64) -> Fixture {
    let mut f = fixture();
    f.state.coins.clear();
    f.state.coins.insert(
        OutPoint { transaction: [0xd1; 32], index: 0 },
        Coin {
            output: Output { owner: addr(treasury, 1), atoms },
            created_height: 0,
            coinbase: false,
        },
    );
    f.state.wallets.register(&desc(treasury, 1)).unwrap();
    f.state.dividends = DividendState::genesis(Treasury::new(Class::TestValue, desc(treasury, 1)).unwrap());
    f
}
fn claim_op(f: &Fixture, owner: &HybridKey, index: u64, award: u64, amount: u64, sequence: u64, dest: Hash) -> Vec<u8> {
    let body = ClaimBody {
        network: NETWORK_ID,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
        created_height: 1,
        expiry_height: 10_000,
        award_epoch: award,
        license: license(index),
        amount,
        destination: dest,
        sequence,
    };
    SignedClaim::sign(body, desc(owner, 1), owner).unwrap().encode()
}
/// A funded wallet-rotation bundle (hybrid transaction tag 25, Lane P design 3.2) of `authority`
/// from `old` to `new`, signed at the rig's current head (window of 10,001 heights), EXPLICITLY
/// sponsored by `sponsor`'s generation-one wallet with the single input `fund`; the sponsor's change
/// is `change` atoms. Order P2: third-party funding of a rotation exists only as a reviewed sponsor
/// that signs the same commitment.
#[allow(dead_code, clippy::too_many_arguments)]
fn sponsored_rotation(
    rig: &Rig,
    authority: Hash,
    old: (&HybridKey, u64),
    new: (&HybridKey, u64),
    sponsor: &HybridKey,
    fund: OutPoint,
    fee: u64,
    change: u64,
) -> Transaction {
    use mutiny_consensus_v8::{
        funded_rotation_v2::{PartialRotation, Payer, Slot, UnsignedRotation},
        op_envelope_v1::Envelope,
    };
    let mut partial = PartialRotation::new(UnsignedRotation {
        genesis: rig.f.genesis.genesis,
        fingerprint: rig.f.genesis.fingerprint,
        envelope: Envelope::from_head(&rig.parent, 10_000, vec![]).unwrap(),
        authority,
        current_descriptor: desc(old.0, old.1),
        proposed_descriptor: desc(new.0, new.1),
        sponsor: Some((addr(sponsor, 1), desc(sponsor, 1))),
        fee,
        inputs: vec![(fund, Payer::Sponsor)],
        outputs: vec![Output { owner: addr(sponsor, 1), atoms: change }],
    });
    partial.sign(Slot::Authorize, old.0).unwrap();
    partial.sign(Slot::Possession, new.0).unwrap();
    partial.sign(Slot::SponsorFunding, sponsor).unwrap();
    Transaction::FundedRotation(partial.complete().unwrap())
}
fn transfer(f: &Fixture, signer: &HybridKey, generation: u64, point: OutPoint, fee: u64, outputs: Vec<Output>) -> Transaction {
    let mut t = Transfer {
        network: NETWORK_ID,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
        created_height: 1,
        expiry_height: 10_000,
        fee,
        inputs: vec![Input::unsigned(point, signer.public(), generation).unwrap()],
        outputs,
    };
    t.sign_input(0, signer).unwrap();
    Transaction::Transfer(t)
}

struct Rig {
    f: Fixture,
    base: std::path::PathBuf,
    chain: CanonicalStore,
    pool: Mempool,
    parent: FinalizedAnchor,
    state: State,
    ticket: u64,
    initial: State,
    initial_root: Hash,
}
impl Rig {
    fn new(f: Fixture, tag: &str) -> Self {
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let base = std::env::temp_dir().join(format!("build8-dividends-{tag}-{}", hex::encode(nonce)));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
        let initial_root = f.state.root().unwrap();
        let chain = CanonicalStore::open_trusted_genesis(&base.join("chain.sqlite"), &f.genesis, &f.state, initial_root, T0, [255; 32]).unwrap();
        let mut pool = Mempool::open(&base.join("pool.sqlite"), f.genesis.genesis, f.genesis.fingerprint, 64 * 1024 * 1024).unwrap();
        chain.reconcile_pool(&mut pool).unwrap();
        let state = f.state.clone();
        Self { parent: f.genesis.clone(), initial: f.state.clone(), f, base, chain, pool, state, ticket: 1, initial_root }
    }
    fn height(&self) -> u64 {
        self.chain.load().unwrap().0.height
    }
    fn try_step(&mut self, epoch: u64, ops: &[Vec<u8>]) -> Result<State, String> {
        let prepared = self
            .chain
            .prepare_pending(Preparation {
                expected_parent: &self.parent,
                pool: &self.pool,
                license: self.f.license,
                worker: self.f.worker,
                timestamp: at(epoch),
                ticket: self.ticket,
                operations: ops,
            })
            .map_err(|e| format!("{e:?}"))?;
        Ok(self.commit_prepared(prepared))
    }
    fn commit_prepared(&mut self, prepared: mutiny_consensus_v8::assembler_v2::Prepared) -> State {
        let envelope = certify_at(prepared, &self.f, &self.parent, &self.state, self.ticket);
        assert!(self.chain.commit(&envelope).unwrap());
        self.parent = envelope.certificate.decision.anchor();
        self.ticket += 1;
        self.state = self.chain.load().unwrap().1;
        self.chain.reconcile_pool(&mut self.pool).unwrap();
        self.state.clone()
    }
    fn step(&mut self, epoch: u64, ops: &[Vec<u8>]) -> State {
        self.try_step(epoch, ops).expect("block must be accepted")
    }
    fn finish(self) {
        let Self { base, chain, pool, .. } = self;
        drop(chain);
        drop(pool);
        assert!(base.starts_with(std::env::temp_dir()));
        std::fs::remove_dir_all(base).unwrap();
    }
    /// Close and reopen the durable store from the same trusted Genesis.
    fn restart(self) -> Self {
        let Self { f, base, chain, pool, ticket, initial, initial_root, .. } = self;
        drop(chain);
        drop(pool);
        let chain = CanonicalStore::open_trusted_genesis(&base.join("chain.sqlite"), &f.genesis, &initial, initial_root, T0, [255; 32]).unwrap();
        let mut pool = Mempool::open(&base.join("pool.sqlite"), f.genesis.genesis, f.genesis.fingerprint, 64 * 1024 * 1024).unwrap();
        chain.reconcile_pool(&mut pool).unwrap();
        let (head, state) = chain.load().unwrap();
        let parent = FinalizedAnchor { height: head.height, block: head.block, ..f.genesis.clone() };
        Self { f, base, chain, pool, parent, state, ticket, initial, initial_root }
    }
}
