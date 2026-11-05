//! Funded BondCreate (block operation kind 24) and bond commands (body version 3) through REAL
//! blocks. Every case builds a block body and a candidate and runs them through the V2 executor
//! (`State::prepare_candidate_with_history_v2`, the path every voter, the canonical store's
//! `commit` and `verify_replay` use; the recovery case through `Prepared::prepare_candidate`),
//! asserts the EXACT error variant and proves that a rejected block leaves the parent state's
//! records and root byte-identical. Lane P design `qualification/candidate-3/P-LANE-DESIGN-V1.md`
//! sections 2, 5.1, 11.1 and test rows 14.1, 14.4 (notice), 14.10 (consensus rows); amendments
//! `P-LANE-DESIGN-AMENDMENTS-V1.md` AM-5 and AM-11. Order of 4 October 2026: P1, P4, Q4.
//!
//! SIMULATED != PHYSICAL: the TPM profiles are deterministic software fixtures and the wallet keys
//! are public BIP39 test phrases. Windows-host software evidence, TEST-VALUE only. Generator of
//! `qualification/funded-bond-create-v1-public.json` (`BUILD8_EXPORT_FUNDED_BOND_CREATE=1`).
#[path = "support/license_v2.rs"]
mod license_fixture;
use mutiny_consensus_v8::{
    Error, Hash, NETWORK_ID, admission_policy_v2,
    admission_v2::{Admission, Expected, Policy},
    anchors::FinalizedAnchor,
    blocks::BlockBody,
    bond_create_v3::{self as bc, BondError, FundedBondCreate, PartialBondCreate, Slot, UnsignedBondCreate},
    bond_ops_v2::{Action, CommandOutcome, Operation},
    bonds::{BondLot, EVIDENCE_HEIGHTS, LOCK_HEIGHTS, LotStatus, MINIMUM_ATOMS, withdrawal_floor},
    bonds_v2::Lot,
    certificates::Decision,
    continuity_v2::Vote,
    dividend_claim_v1::{ClaimBody, SignedClaim},
    domain_hash,
    equivocation_v2::Evidence,
    evidence_history_v2::History,
    execution::{CandidatePreparation, Execution, ExecutionError, State, WorkParent},
    hybrid_transaction_v2::Transaction,
    license_book_v2, membership_v2,
    node_admission_v2::{Binding, node_id},
    op_envelope_v1::{self as envelope, AwardAccount, Envelope, EnvelopeError, Precondition},
    pow::Candidate,
    provenance::AdmissionClass,
    recovery::{Anchor, ContinuityState, Member},
    recovery_authority_v2::{Authority, Authorization},
    recovery_history_v2 as history_record,
    recovery_replacement_v2::Replacement,
    recovery_transition_v2::Prepared,
    recovery_witness_v2 as witness, state_tree,
    tpm::{self, TpmProfile, encode_quote},
    trading_v1::{
        Action as TradeAction, Approval, Context, FrozenTreasuryOffer, Meta, NATIVE_NAMESPACE,
        OfferBody, OfferTerms, Operation as TradeOperation, Strikes, verify_approval,
    },
    transactions::{Coin, OutPoint, Output, SUBSIDY},
    transactions_v2::{Input, Transfer},
    votes_v2::HeightAuthority,
    wallet_authority_v1::WalletBook,
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, Role};
use p256::ecdsa::{Signature, SigningKey, signature::Signer, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const GENESIS: Hash = [1; 32];
const FINGERPRINT: Hash = [2; 32];
/// The standard create: principal 100 MUT, fee 20,000 atoms (above any signed length up to the
/// 16 KiB bound), change 10,000 atoms, so the standard input holds FUNDING atoms.
const FEE: u64 = 20_000;
const CHANGE: u64 = 10_000;
const FUNDING: u64 = MINIMUM_ATOMS + FEE + CHANGE;

// ---------------------------------------------------------------------------------------------
// TEST-VALUE fixtures (the software TPM wire helpers are those of recovery_execution_v2.rs)
// ---------------------------------------------------------------------------------------------
fn blob(x: &[u8]) -> Vec<u8> {
    let mut b = (x.len() as u16).to_be_bytes().to_vec();
    b.extend(x);
    b
}
fn public(k: &SigningKey, restricted: bool) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(0x23u16.to_be_bytes());
    b.extend(0xbu16.to_be_bytes());
    b.extend((if restricted { 0x50472u32 } else { 0x40472u32 }).to_be_bytes());
    b.extend(blob(&[]));
    for x in [0x10u16, 0x18, 0xb, 3, 0x10] {
        b.extend(x.to_be_bytes());
    }
    let p = k.verifying_key().to_encoded_point(false);
    b.extend(blob(p.x().unwrap()));
    b.extend(blob(p.y().unwrap()));
    blob(&b)
}
fn header(kind: u16, signer: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut b = 0xff544347u32.to_be_bytes().to_vec();
    b.extend(kind.to_be_bytes());
    b.extend(blob(signer));
    b.extend(blob(challenge));
    b.extend([0; 25]);
    b
}
fn signature(k: &SigningKey, m: &[u8]) -> Vec<u8> {
    let s: Signature = k.sign(m);
    let r = s.to_bytes();
    let mut b = vec![0, 0x18, 0, 0xb];
    b.extend(blob(&r[..32]));
    b.extend(blob(&r[32..]));
    b
}
fn profile(ak: &SigningKey) -> TpmProfile {
    let identity = SigningKey::from_bytes((&[10u8; 32]).into()).unwrap();
    let voting_public = public(&identity, false);
    let mut signer = vec![0, 0xb];
    signer.extend([11; 32]);
    let mut name = vec![0, 0xb];
    name.extend(Sha256::digest(&voting_public[2..]));
    let mut m = header(0x8017, &signer, &[0, 255, 85, 170]);
    m.extend(blob(&name));
    m.extend(blob(&signer));
    TpmProfile {
        hardware: [12; 32],
        ak_public: public(ak, true),
        voting_public,
        qualified_signer: signer,
        pcr_bitmap: [1, 0, 0],
        pcr_digest: [13; 32],
        certify_signature: signature(ak, &m),
        certify_message: m,
        admission_trust_manifest: [14; 32],
        provenance: None,
    }
}
fn quote(ak: &SigningKey, p: &TpmProfile, c: [u8; 32]) -> Vec<u8> {
    let mut m = header(0x8018, &p.qualified_signer, &c);
    m.extend(1u32.to_be_bytes());
    m.extend(0xbu16.to_be_bytes());
    m.push(3);
    m.extend(p.pcr_bitmap);
    m.extend(blob(&p.pcr_digest));
    encode_quote(&m, &signature(ak, &m)).unwrap()
}
fn zero() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}
/// The node's admission owner and the License owner (public BIP39 phrase).
fn owner_key() -> HybridKey {
    HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).unwrap()
}
/// An unrelated wallet (public BIP39 phrase).
fn stranger_key() -> HybridKey {
    HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner).unwrap()
}
/// The owner's rotation successor (public BIP39 phrase).
fn successor_key() -> HybridKey {
    HybridKey::wallet_restore(
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        Role::WalletOwner,
    )
    .unwrap()
}
fn addr(key: &HybridKey, generation: u64) -> Hash {
    key.public().address_id(generation).unwrap()
}
fn desc(key: &HybridKey, generation: u64) -> Vec<u8> {
    key.public().descriptor(generation).unwrap()
}
fn block_hash(height: u64) -> Hash {
    domain_hash(b"MUTINY-BUILD8-TEST-VALUE-SYNTHETIC-BLOCK", &height.to_be_bytes())
}
/// The finalized parent at `height` (synthetic block hash; consensus binds the hash it is given).
fn anchor(height: u64) -> FinalizedAnchor {
    FinalizedAnchor {
        network: NETWORK_ID,
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        height,
        block: block_hash(height),
    }
}
fn point(seed: u8) -> OutPoint {
    OutPoint {
        transaction: [seed; 32],
        index: 0,
    }
}
fn coin(owner: Hash, atoms: u64, created_height: u64) -> Coin {
    Coin {
        output: Output { owner, atoms },
        created_height,
        coinbase: false,
    }
}
/// The single-height window of the block after `parent`, referencing `parent` itself.
fn window(parent: &FinalizedAnchor) -> Envelope {
    Envelope {
        first_height: parent.height + 1,
        last_height: parent.height + 1,
        reference_height: parent.height,
        reference_block: parent.block,
        preconditions: vec![],
    }
}
/// The parent state seen at `height`: authenticated components unchanged, the participation
/// cursor moved (the pattern of the existing lifecycle tests; no 259,200-block chain is built).
fn at(state: &State, height: u64) -> State {
    let mut s = state.clone();
    s.accounting.slots.last_height = height;
    s.accounting.slots.period = height / 60;
    s
}

/// Who mines (License and Worker of the licensed-execution fixture) and who is rewarded.
#[derive(Clone)]
struct Miner {
    license: Hash,
    worker: Hash,
    reward_owner: Hash,
}
struct Rig {
    state: State,
    owner: HybridKey,
    continuity: HybridKey,
    node: Hash,
    miner: Miner,
}
/// One physical, eligible Genesis member (software TPM fixture) owned by `owner_key()`, the
/// Genesis Licenses with active Workers, the owner's generation-1 wallet registered.
fn rig() -> Rig {
    let owner = owner_key();
    let continuity = HybridKey::generate(Role::Continuity).unwrap();
    let node_key = HybridKey::generate(Role::Node).unwrap();
    let ak = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let profile = profile(&ak);
    let policy = Policy {
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        owner_descriptor: desc(&owner, 1),
        endorsement_roots: [[3; 32]].into_iter().collect(),
    };
    let descriptor = node_key.public().descriptor(1).unwrap();
    let id = node_id(GENESIS, &descriptor).unwrap();
    let mut binding = Binding {
        node_signer: None,
        node_descriptor: descriptor,
        possession: zero(),
        admission: Admission {
            genesis: GENESIS,
            fingerprint: FINGERPRINT,
            node: id,
            hardware_generation: 1,
            key_generation: 1,
            continuity_descriptor: continuity.public().descriptor(1).unwrap(),
            profile: profile.encode().unwrap(),
            endorsement_root: [3; 32],
            owner: addr(&owner, 1),
            supervised_nonce: [5; 32],
            quote: vec![],
            possession: zero(),
            authorization: zero(),
        },
    };
    binding.admission.prove_continuity(&continuity).unwrap();
    binding.admission.quote = quote(&ak, &profile, binding.admission.challenge().unwrap());
    binding.admission.authorize(&owner, 1).unwrap();
    binding.sign(&node_key).unwrap();
    let mut state = State::default();
    state.wallets.register(&policy.owner_descriptor).unwrap();
    state.admission_policy_v2 = Some(admission_policy_v2::Record::new(policy.clone()).unwrap());
    (state.membership_v2, state.continuity_keys_v2) = membership_v2::Book::genesis(
        &binding,
        &policy,
        &Expected {
            node: id,
            hardware_generation: 1,
            key_generation: 1,
            supervised_nonce: [5; 32],
        },
        &state.wallets,
        AdmissionClass::LegacyTest,
    )
    .unwrap();
    state.continuity = Some(
        ContinuityState::bootstrap(
            GENESIS,
            FINGERPRINT,
            Anchor {
                height: 0,
                tip: [19; 32],
                state_root: [0; 32],
                registry_root: [0; 32],
            },
            [20; 32],
            vec![Member {
                lineage: id,
                node: id,
                hardware: profile.hardware,
                generation: 1,
                voting_key: tpm::public_key(&profile.voting_public, false).unwrap(),
                attestation: profile.commitment().unwrap(),
                history: Default::default(),
                physical: true,
                eligible: true,
                genesis_member: true,
            }],
        )
        .unwrap(),
    );
    let (_, assignments, expected, licenses, _) = license_fixture::fixtures();
    state.licenses_v2 = license_book_v2::Book::genesis(
        &assignments,
        &expected,
        &licenses,
        &state.wallets,
        GENESIS,
        FINGERPRINT,
    )
    .unwrap();
    Rig {
        state,
        owner,
        continuity,
        node: id,
        miner: Miner {
            license: licenses[0].id,
            worker: expected[0].worker_id,
            reward_owner: licenses[0].owner,
        },
    }
}

struct Block {
    parent: WorkParent,
    candidate: Candidate,
    body: BlockBody,
}
/// A real block on `parent`: body, candidate (valid timestamps, the License's active Worker) and
/// the work parent the executor validates against. Ticket sequence = height (strictly increasing).
fn block(miner: &Miner, parent: &FinalizedAnchor, transactions: Vec<Vec<u8>>, operations: Vec<Vec<u8>>, fees: u64) -> Block {
    let height = parent.height + 1;
    let body = BlockBody {
        height,
        reward_owner: miner.reward_owner,
        fees,
        transactions,
        operations,
    };
    let work = WorkParent {
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        block: parent.block,
        height: parent.height,
        t0: 1000,
        target: [255; 32],
        ancestor_timestamps: (0..height.min(11)).map(|o| 1000 + (parent.height - o) * 60).collect(),
    };
    let candidate = Candidate {
        network: NETWORK_ID,
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        height,
        parent: parent.block,
        timestamp: 1000 + height * 60,
        // A body that cannot be encoded keeps a zero root; the executor reports the codec error.
        body_root: body.root().unwrap_or([0; 32]),
        state_root: [0; 32],
        license: miner.license,
        worker: miner.worker,
        target: [255; 32],
    };
    Block {
        parent: work,
        candidate,
        body,
    }
}
fn execute(state: &State, b: &Block, history: &History) -> Result<Execution, ExecutionError> {
    state.prepare_candidate_with_history_v2(
        CandidatePreparation {
            parent: &b.parent,
            candidate: &b.candidate,
            ticket_sequence: b.body.height,
            body: &b.body,
        },
        history,
    )
}
/// The block must be rejected; the parent's records and root stay byte-identical.
fn reject(state: &State, b: &Block, history: &History) -> ExecutionError {
    let (records, root) = (state.records().unwrap(), state.root().unwrap());
    let error = match execute(state, b, history) {
        Ok(_) => panic!("the block was accepted"),
        Err(e) => e,
    };
    assert!(state.records().unwrap() == records, "rejected block changed the parent records");
    assert_eq!(state.root().unwrap(), root);
    error
}
fn bond_error(e: ExecutionError) -> BondError {
    match e {
        ExecutionError::BondCreate(b) => b,
        other => panic!("expected a BondCreate error, got {other:?}"),
    }
}
fn codec_error(e: ExecutionError) -> Error {
    match e {
        ExecutionError::Codec(b) => b,
        other => panic!("expected a consensus Error, got {other:?}"),
    }
}
/// The standard unsigned create of `owner` (generation 1) for `node` on `parent`.
fn unsigned(owner: &HybridKey, node: Hash, parent: &FinalizedAnchor, inputs: Vec<OutPoint>, nonce: u8) -> UnsignedBondCreate {
    UnsignedBondCreate {
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        envelope: window(parent),
        owner: addr(owner, 1),
        owner_descriptor: desc(owner, 1),
        node,
        node_generation: 1,
        nonce: [nonce; 32],
        principal: MINIMUM_ATOMS,
        fee: FEE,
        inputs,
        change: Some(Output {
            owner: addr(owner, 1),
            atoms: CHANGE,
        }),
    }
}
fn signed(u: UnsignedBondCreate, key: &HybridKey) -> FundedBondCreate {
    FundedBondCreate::sign(u, key).unwrap()
}
fn raw(create: &FundedBondCreate) -> Vec<u8> {
    create.encode().unwrap()
}
/// A signed command of `key` (descriptor `generation`) for the lot owned by `lot_owner`.
fn command(key: &HybridKey, generation: u64, lot_owner: Hash, action: Action, envelope: Envelope) -> Operation {
    let mut op = Operation {
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        envelope,
        owner: lot_owner,
        authorizer: desc(key, generation),
        action,
        signature: zero(),
    };
    op.sign(key).unwrap();
    op
}
fn total_atoms(state: &State) -> u128 {
    state.coins.values().map(|c| u128::from(c.output.atoms)).sum()
}
/// A Transfer of `point` (owned by `key`'s generation-1 address) to `to`.
fn transfer(key: &HybridKey, generation: u64, input: OutPoint, atoms: u64, fee: u64, to: Hash, height: u64) -> Transfer {
    let mut t = Transfer {
        network: NETWORK_ID,
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        created_height: height,
        expiry_height: height + 1,
        fee,
        inputs: vec![Input::unsigned(input, key.public(), generation).unwrap()],
        outputs: vec![Output {
            owner: to,
            atoms: atoms - fee,
        }],
    };
    t.sign_input(0, key).unwrap();
    t
}

// ---------------------------------------------------------------------------------------------
// 14.1 P1: positive real block
// ---------------------------------------------------------------------------------------------
#[test]
fn funded_create_locks_principal_at_actual_inclusion_height() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    let input = point(0xA0);
    rig.state.coins.insert(input.clone(), coin(owner, FUNDING, 0));
    let parent = anchor(0);
    let create = signed(unsigned(&rig.owner, rig.node, &parent, vec![input.clone()], 1), &rig.owner);
    let op = raw(&create);
    // The read-only admission entry point (design 5.4) and the partial-object preflight (AM-9 m6)
    // accept it on the parent; the AM-1(d) halves agree.
    bc::check(&rig.state, &parent, &History::default(), &op).unwrap();
    create.verify_state(&rig.state, &parent, &History::default()).unwrap();
    create.verify_signatures().unwrap();
    let mut partial = PartialBondCreate::new(create.unsigned.clone());
    partial.preflight(&rig.state, &parent, &History::default()).unwrap();
    partial.sign(Slot::Funding, &rig.owner).unwrap();
    partial.preflight(&rig.state, &parent, &History::default()).unwrap();
    let before = total_atoms(&rig.state);
    let b = block(&rig.miner, &parent, vec![], vec![op], FEE);
    assert_eq!(envelope::referenced_heights(&b.body), BTreeSet::from([0]));
    let executed = execute(&rig.state, &b, &History::default()).unwrap();
    let s = &executed.state;
    assert_eq!(
        s.bonds_v2.lots[&create.lot_id()].0,
        BondLot {
            id: create.lot_id(),
            node: rig.node,
            lineage: rig.node,
            owner,
            atoms: MINIMUM_ATOMS,
            created_height: 1,
            sequence: 0,
            unbond_height: None,
            settled_height: None,
            status: LotStatus::Active,
            evidence: [0; 32],
        }
    );
    assert!(!s.coins.contains_key(&input), "the input is consumed");
    let change = OutPoint {
        transaction: create.id().unwrap(),
        index: 0,
    };
    assert_eq!(s.coins[&change], coin(owner, CHANGE, 1), "change at OutPoint(id, 0), created at H");
    let coinbase = OutPoint {
        transaction: executed.coinbase_id,
        index: 0,
    };
    assert_eq!(
        s.coins[&coinbase],
        Coin {
            output: Output {
                owner: rig.miner.reward_owner,
                atoms: SUBSIDY + FEE
            },
            created_height: 1,
            coinbase: true
        },
        "the declared fee is in the coinbase"
    );
    assert_eq!(executed.fees, FEE);
    // Conservation: before + subsidy = after + principal (the principal is locked in the lot).
    assert_eq!(before + u128::from(SUBSIDY), total_atoms(s) + u128::from(MINIMUM_ATOMS));
    let member = &s.continuity.as_ref().unwrap().members[0];
    assert_eq!(member.history.bonds.len(), 1, "the reputation lot is recomputed");
    assert_eq!(member.history.bonds[0].atoms, MINIMUM_ATOMS);
    let restored = State::from_records(&s.records().unwrap(), executed.root).unwrap();
    assert!(restored.records().unwrap() == s.records().unwrap(), "restore from records");
    assert_eq!(restored.bonds_v2, s.bonds_v2);
    assert!(executed.bond_command_outcomes.is_empty());
    // Two lots of one owner for one node in one block (different nonces, different inputs).
    let mut two = rig.state.clone();
    two.coins.insert(point(0xA1), coin(owner, FUNDING, 0));
    let second = signed(unsigned(&rig.owner, rig.node, &parent, vec![point(0xA1)], 2), &rig.owner);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&create), raw(&second)], 2 * FEE);
    let both = execute(&two, &b, &History::default()).unwrap();
    assert_eq!(both.state.bonds_v2.lots.len(), 2);
    assert_eq!(both.state.continuity.as_ref().unwrap().members[0].history.bonds.len(), 2);
    assert_eq!(both.fees, 2 * FEE);
}

// ---------------------------------------------------------------------------------------------
// 14.1 P1 timing: B is the ACTUAL inclusion height
// ---------------------------------------------------------------------------------------------
#[test]
fn create_signed_early_included_later_starts_age_at_inclusion() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    let h = 100;
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING, 0));
    let state = at(&rig.state, h + 29);
    let mut u = unsigned(&rig.owner, rig.node, &anchor(h), vec![point(0xA0)], 1);
    u.envelope = Envelope {
        first_height: h + 1,
        last_height: h + 50,
        reference_height: h,
        reference_block: block_hash(h),
        preconditions: vec![],
    };
    let create = signed(u, &rig.owner);
    let b = block(&rig.miner, &anchor(h + 29), vec![], vec![raw(&create)], FEE);
    // Without the canonical hash of height h the executor fails closed.
    assert_eq!(
        bond_error(reject(&state, &b, &History::default())),
        BondError::Envelope(EnvelopeError::ReferenceNotCanonical)
    );
    let mut history = History::default();
    history.insert_anchor(h, block_hash(h)).unwrap();
    let executed = execute(&state, &b, &history).unwrap();
    let lot = executed.state.bonds_v2.lots[&create.lot_id()].0.clone();
    let b0 = h + 30;
    assert_eq!(lot.created_height, b0, "B = the actual inclusion height, not first_height h+1");
    // Notice at B + 1 (real block), then the floor max(B + 259,200, U + 43,200) = B + 259,200.
    let post = executed.state;
    let unbond = command(&rig.owner, 1, owner, Action::Unbond { lot: lot.id, sequence: 1 }, window(&anchor(b0)));
    let noticed = execute(&post, &block(&rig.miner, &anchor(b0), vec![], vec![unbond.encode().unwrap()], 0), &History::default())
        .unwrap()
        .state;
    assert_eq!(noticed.bonds_v2.lots[&lot.id].0.unbond_height, Some(b0 + 1));
    let floor = withdrawal_floor(b0, b0 + 1).unwrap();
    assert_eq!(floor, b0 + LOCK_HEIGHTS);
    // One block before the floor counted from B the withdrawal is refused at the actual height.
    let early = at(&noticed, floor - 2);
    let w = command(&rig.owner, 1, owner, Action::Withdraw { lot: lot.id, sequence: 2 }, window(&anchor(floor - 2)));
    let e = reject(&early, &block(&rig.miner, &anchor(floor - 2), vec![], vec![w.encode().unwrap()], 0), &History::default());
    assert_eq!(codec_error(e), Error::InvalidCounter);
    let ready = at(&noticed, floor - 1);
    let w = command(&rig.owner, 1, owner, Action::Withdraw { lot: lot.id, sequence: 2 }, window(&anchor(floor - 1)));
    let paid = execute(&ready, &block(&rig.miner, &anchor(floor - 1), vec![], vec![w.encode().unwrap()], 0), &History::default()).unwrap();
    let settled = &paid.state.bonds_v2.lots[&lot.id].0;
    assert_eq!((settled.status, settled.settled_height), (LotStatus::Withdrawn, Some(floor)));
    let payout = OutPoint {
        transaction: w.payout_id().unwrap(),
        index: 0,
    };
    assert_eq!(paid.state.coins[&payout], coin(owner, MINIMUM_ATOMS, floor));
    assert_eq!(paid.bond_command_outcomes[&w.id().unwrap()], CommandOutcome::Applied);
}

// ---------------------------------------------------------------------------------------------
// 14.1 P1 stripped and altered components
// ---------------------------------------------------------------------------------------------
#[test]
fn altered_or_stripped_funding_rejects_byte_identical() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    for seed in [0xA0, 0xA1] {
        rig.state.coins.insert(point(seed), coin(owner, FUNDING / 2 + 1, 0));
    }
    let parent = anchor(0);
    let mut u = unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0), point(0xA1)], 1);
    u.change = Some(Output { owner, atoms: CHANGE + 2 });
    let good = signed(u, &rig.owner);
    execute(&rig.state, &block(&rig.miner, &parent, vec![], vec![raw(&good)], FEE), &History::default()).unwrap();
    let other = signed(unsigned(&rig.owner, rig.node, &parent, vec![point(0xA1)], 9), &rig.owner);
    let cases: Vec<(&str, Vec<u8>, BondError)> = vec![
        ("input removed", {
            let mut b = good.clone();
            b.unsigned.inputs.pop();
            raw(&b)
        }, BondError::Signature(Slot::Create)),
        ("principal changed", {
            let mut b = good.clone();
            b.unsigned.principal += 1;
            raw(&b)
        }, BondError::Signature(Slot::Create)),
        ("fee changed", {
            let mut b = good.clone();
            b.unsigned.fee -= 1;
            raw(&b)
        }, BondError::Signature(Slot::Create)),
        ("change amount changed", {
            let mut b = good.clone();
            b.unsigned.change.as_mut().unwrap().atoms += 1;
            raw(&b)
        }, BondError::Signature(Slot::Create)),
        ("change removed", {
            let mut b = good.clone();
            b.unsigned.change = None;
            raw(&b)
        }, BondError::Signature(Slot::Create)),
        ("node changed", {
            let mut b = good.clone();
            b.unsigned.node[0] ^= 1;
            raw(&b)
        }, BondError::Signature(Slot::Create)),
        ("nonce changed", {
            let mut b = good.clone();
            b.unsigned.nonce[0] ^= 1;
            raw(&b)
        }, BondError::Signature(Slot::Create)),
        ("window extended", {
            let mut b = good.clone();
            b.unsigned.envelope.last_height += 1;
            raw(&b)
        }, BondError::Signature(Slot::Create)),
        ("reference changed", {
            let mut b = good.clone();
            b.unsigned.envelope.reference_block[0] ^= 1;
            raw(&b)
        }, BondError::Envelope(EnvelopeError::ReferenceNotCanonical)),
        ("funding signature stripped", {
            let mut p = good.as_partial();
            p.funding = None;
            p.encode().unwrap()
        }, BondError::MissingSignature(Slot::Funding)),
        ("create signature stripped", {
            let mut p = good.as_partial();
            p.create = None;
            p.encode().unwrap()
        }, BondError::MissingSignature(Slot::Create)),
        ("funding signature zeroed", {
            let mut b = good.clone();
            b.funding = zero();
            raw(&b)
        }, BondError::Signature(Slot::Funding)),
        ("funding signature of another create", {
            let mut b = good.clone();
            b.funding = other.funding.clone();
            raw(&b)
        }, BondError::Signature(Slot::Funding)),
        ("signatures swapped", {
            let mut b = good.clone();
            std::mem::swap(&mut b.create, &mut b.funding);
            raw(&b)
        }, BondError::Signature(Slot::Create)),
        ("create signed by a third party", {
            let mut b = good.clone();
            b.create = stranger_key()
                .sign(Domain::BondCreate, &bc::authorize_payload(&good.unsigned.commitment().unwrap()))
                .unwrap();
            raw(&b)
        }, BondError::Signature(Slot::Create)),
    ];
    for (name, op, expected) in cases {
        // The block declares exactly the operation's own (possibly altered) fee, so the
        // alteration reaches the bond-create phase instead of failing the fee total first.
        let declared = bc::PartialBondCreate::decode(&op).map_or(FEE, |p| p.unsigned.fee);
        let b = block(&rig.miner, &parent, vec![], vec![op], declared);
        assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), expected, "{name}");
    }
    // With the original fee total, the altered fee is already refused by the fee total.
    let mut b = good.clone();
    b.unsigned.fee -= 1;
    let block_fee_mismatch = block(&rig.miner, &parent, vec![], vec![raw(&b)], FEE);
    assert!(matches!(reject(&rig.state, &block_fee_mismatch, &History::default()), ExecutionError::WrongFees));
}

#[test]
fn same_block_spend_of_an_input_rejects_whole_block() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING, 0));
    let parent = anchor(0);
    let create = signed(unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1), &rig.owner);
    let spend = transfer(&rig.owner, 1, point(0xA0), FUNDING, 5_000, addr(&stranger_key(), 1), 1);
    let tx = Transaction::Transfer(spend).encode().unwrap();
    // Each alone is valid.
    execute(&rig.state, &block(&rig.miner, &parent, vec![tx.clone()], vec![], 5_000), &History::default()).unwrap();
    execute(&rig.state, &block(&rig.miner, &parent, vec![], vec![raw(&create)], FEE), &History::default()).unwrap();
    // Together the payment phase spends the input first: the whole block fails.
    let b = block(&rig.miner, &parent, vec![tx], vec![raw(&create)], 5_000 + FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::MissingInput);
    // Two creates sharing one input: the second finds it consumed.
    let twin = signed(unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 2), &rig.owner);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&create), raw(&twin)], 2 * FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::MissingInput);
}

/// AM-11: an input created AT the inclusion height (a same-block output) is refused: the
/// `created_height < H` rule, whose `<=` mutant must die. Coinbase maturity is the existing 100.
#[test]
fn inputs_must_exist_strictly_before_the_inclusion_height() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING + 5_000, 0));
    let parent = anchor(0);
    let pay = transfer(&rig.owner, 1, point(0xA0), FUNDING + 5_000, 5_000, owner, 1);
    let fresh = OutPoint {
        transaction: Transaction::Transfer(pay.clone()).id().unwrap(),
        index: 0,
    };
    let create = signed(unsigned(&rig.owner, rig.node, &parent, vec![fresh.clone()], 1), &rig.owner);
    let b = block(&rig.miner, &parent, vec![Transaction::Transfer(pay).encode().unwrap()], vec![raw(&create)], 5_000 + FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Immature);
    // The same output one block later (created at the parent height) funds the lot.
    let mut later = at(&rig.state, 1);
    later.coins.insert(fresh.clone(), coin(owner, FUNDING, 1));
    let create = signed(unsigned(&rig.owner, rig.node, &anchor(1), vec![fresh], 1), &rig.owner);
    execute(&later, &block(&rig.miner, &anchor(1), vec![], vec![raw(&create)], FEE), &History::default()).unwrap();
    // Coinbase maturity: a coinbase created at 0 is spendable at height 100, not at 99.
    let mut matured = rig.state.clone();
    matured.coins.insert(point(0xA2), Coin { coinbase: true, ..coin(owner, FUNDING, 0) });
    let early = at(&matured, 98);
    let create = signed(unsigned(&rig.owner, rig.node, &anchor(98), vec![point(0xA2)], 1), &rig.owner);
    let b = block(&rig.miner, &anchor(98), vec![], vec![raw(&create)], FEE);
    assert_eq!(bond_error(reject(&early, &b, &History::default())), BondError::Immature);
    let ripe = at(&matured, 99);
    let create = signed(unsigned(&rig.owner, rig.node, &anchor(99), vec![point(0xA2)], 1), &rig.owner);
    execute(&ripe, &block(&rig.miner, &anchor(99), vec![], vec![raw(&create)], FEE), &History::default()).unwrap();
}

/// P3 and the 100 MUT minimum in a real block: such bytes cannot be signed (the codec refuses to
/// encode them), but a proposer can inject crafted bytes; they are refused at decode, before any
/// signature work, and the block leaves the parent byte-identical.
#[test]
fn crafted_unrepresentable_creates_are_refused_in_a_real_block() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING, 0));
    let parent = anchor(0);
    let u = unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1);
    let ins = vec![(point(0xA0).transaction, 0)];
    let wrap = |body: Vec<u8>| {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(5).unwrap().u8(2).unwrap().u8(24).unwrap().bytes(&body).unwrap();
        for _ in 0..2 {
            e.array(2).unwrap().bytes(&[0; 114]).unwrap().bytes(&[0; 1280]).unwrap();
        }
        e.into_writer()
    };
    let mut low = u.clone();
    low.principal = MINIMUM_ATOMS - 1;
    for (op, expected) in [
        (wrap(raw_unsigned(&u, NETWORK_ID, 24, &ins, Some(([0; 32], CHANGE)))), BondError::ZeroDestination),
        (wrap(raw_unsigned(&u, NETWORK_ID, 24, &ins, Some((owner, 0)))), BondError::Bounds),
        (wrap(raw_unsigned(&low, NETWORK_ID, 24, &ins, Some((owner, CHANGE)))), BondError::Bounds),
    ] {
        assert_eq!(FundedBondCreate::decode(&op), Err(expected));
        let b = block(&rig.miner, &parent, vec![], vec![op], FEE);
        assert!(b.body.encode().is_ok(), "the discriminator alone accepts kind 24");
        assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), expected);
    }
}

#[test]
fn third_party_input_or_change_rejected() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    let stranger = addr(&stranger_key(), 1);
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING / 2, 0));
    rig.state.coins.insert(point(0xA1), coin(stranger, FUNDING - FUNDING / 2, 0));
    rig.state.coins.insert(point(0xA2), coin(owner, FUNDING - FUNDING / 2, 0));
    let parent = anchor(0);
    // A third party's coin cannot fund the owner's lot (V7).
    let theft = signed(unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0), point(0xA1)], 1), &rig.owner);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&theft)], FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Lineage(Error::WrongGeneration));
    // A BondCreate cannot pay a third party as "change" (V8).
    let mut u = unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0), point(0xA2)], 1);
    u.change = Some(Output { owner: stranger, atoms: CHANGE });
    let payment = signed(u, &rig.owner);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&payment)], FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Lineage(Error::WrongGeneration));
    // With the owner's own inputs and change the same create is valid.
    let fine = signed(unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0), point(0xA2)], 1), &rig.owner);
    execute(&rig.state, &block(&rig.miner, &parent, vec![], vec![raw(&fine)], FEE), &History::default()).unwrap();
}

/// P1 with P9 (and AM-11 older generations): after the owner rotated to generation 2 in an earlier
/// block, inputs of BOTH generations fund one create signed by the current key for the immutable
/// generation-1 AddressID; the rotated-out key no longer authorizes anything.
#[test]
fn historic_generation_inputs_fund_create_after_rotation() {
    let mut rig = rig();
    let successor = successor_key();
    let g1 = addr(&rig.owner, 1);
    let g2 = addr(&successor, 2);
    let mut rotation = Rotation {
        network: NETWORK_ID,
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        authority: g1,
        current: desc(&rig.owner, 1),
        proposed: desc(&successor, 2),
        created_height: 0,
        expiry_height: 10,
        authorization: zero(),
        possession: zero(),
    };
    rotation.sign(&rig.owner, &successor).unwrap();
    rig.state.wallets.apply(&rotation, GENESIS, FINGERPRINT, 0).unwrap();
    rig.state.coins.insert(point(0xA0), coin(g1, FUNDING / 2, 0));
    rig.state.coins.insert(point(0xA1), coin(g2, FUNDING - FUNDING / 2, 0));
    let parent = anchor(0);
    let mut u = unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0), point(0xA1)], 1);
    u.owner_descriptor = desc(&successor, 2);
    u.change = Some(Output { owner: g2, atoms: CHANGE });
    let create = signed(u.clone(), &successor);
    let executed = execute(&rig.state, &block(&rig.miner, &parent, vec![], vec![raw(&create)], FEE), &History::default()).unwrap();
    let lot = &executed.state.bonds_v2.lots[&create.lot_id()].0;
    assert_eq!(lot.owner, g1, "the lot owner stays the node's immutable admission AddressID");
    assert!(!executed.state.coins.contains_key(&point(0xA0)) && !executed.state.coins.contains_key(&point(0xA1)));
    // The rotated-out generation-1 key is stale owner authority (V4).
    let stale = signed(unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0), point(0xA1)], 1), &rig.owner);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&stale)], FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Authority(Error::WrongGeneration));
}

/// HYBRID-BOND-SETTLEMENT-V2 (L23 as amended): owner authority is the PARENT WalletBook. A wallet
/// rotation in the same block neither authorizes the new key nor withdraws the old key's
/// authority for this block (AM-11 same-block combination).
#[test]
fn stale_owner_authority_and_same_block_rotation_do_not_authorize() {
    let mut rig = rig();
    let successor = successor_key();
    let g1 = addr(&rig.owner, 1);
    rig.state.coins.insert(point(0xA0), coin(g1, FUNDING, 0));
    rig.state.coins.insert(point(0xA5), coin(g1, 40_000, 0));
    let parent = anchor(0);
    // The same-block rotation is a funded wallet-rotation bundle (tag 25, WP-R): the OLD key
    // authorizes it and pays from its own coin.
    let rotate = {
        use mutiny_consensus_v8::{
            funded_rotation_v2::{Party, PartialRotation, Payer, UnsignedRotation, signing_intents},
            op_envelope_v1::Envelope,
        };
        let mut partial = PartialRotation::new(UnsignedRotation {
            genesis: GENESIS,
            fingerprint: FINGERPRINT,
            envelope: Envelope::from_head(&parent, 1, vec![]).unwrap(),
            authority: g1,
            current_descriptor: desc(&rig.owner, 1),
            proposed_descriptor: desc(&successor, 2),
            sponsor: None,
            fee: 20_000,
            inputs: vec![(point(0xA5), Payer::RotatingAuthority)],
            outputs: vec![Output { owner: addr(&successor, 2), atoms: 20_000 }],
        });
        for intent in signing_intents(&partial.unsigned).unwrap() {
            let key = if intent.party == Party::NewKey { &successor } else { &rig.owner };
            partial.sign(intent.slot, key).unwrap();
        }
        Transaction::FundedRotation(partial.complete().unwrap()).encode().unwrap()
    };
    // New key, same block: not authorized by the parent WalletBook.
    let mut u = unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1);
    u.owner_descriptor = desc(&successor, 2);
    let by_new = signed(u, &successor);
    let b = block(&rig.miner, &parent, vec![rotate.clone()], vec![raw(&by_new)], 20_000 + FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Authority(Error::WrongGeneration));
    // Old key, same block: the parent authority still authorizes it (the documented rule).
    let by_old = signed(unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1), &rig.owner);
    let b = block(&rig.miner, &parent, vec![rotate], vec![raw(&by_old)], 20_000 + FEE);
    let executed = execute(&rig.state, &b, &History::default()).unwrap();
    assert!(executed.state.bonds_v2.lots.contains_key(&by_old.lot_id()));
    assert_eq!(executed.state.wallets.current(g1), Some(desc(&successor, 2).as_slice()));
}

#[test]
fn kind_18_and_escrow_pattern_rejected() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    let parent = anchor(0);
    // The retired kind-18 envelope [2, 18, body, ed448, fndsa] is not an operation kind any more.
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(5).unwrap().u8(2).unwrap().u8(18).unwrap().bytes(&[0x8a]).unwrap();
    e.bytes(&[0; 114]).unwrap().bytes(&[0; 1280]).unwrap();
    let kind18 = e.into_writer();
    assert_eq!(mutiny_consensus_v8::blocks::operation_kind(&kind18), Err(Error::WrongOperation));
    let b = block(&rig.miner, &parent, vec![], vec![kind18], 0);
    assert_eq!(b.body.encode(), Err(Error::WrongOperation));
    assert_eq!(codec_error(reject(&rig.state, &b, &History::default())), Error::WrongOperation);
    // No address is recognized as an escrow: a coin paid to the retired escrow hash of a lot can
    // fund nothing, because no wallet lineage owns it.
    let probe = unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1);
    let escrow = domain_hash(b"MUTINY-BUILD8-BOND-ESCROW-V2", &probe.lot_id());
    rig.state.coins.insert(point(0xA0), coin(escrow, FUNDING, 0));
    let create = signed(probe, &rig.owner);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&create)], FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Lineage(Error::WrongGeneration));
    assert!(rig.state.coins.values().all(|c| c.output.owner != owner));
}

#[test]
fn replayed_create_and_duplicate_lot_rejected() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING, 0));
    rig.state.coins.insert(point(0xA1), coin(owner, FUNDING, 0));
    let parent = anchor(0);
    let mut u = unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1);
    u.envelope = Envelope {
        first_height: 1,
        last_height: 10,
        reference_height: 0,
        reference_block: parent.block,
        preconditions: vec![],
    };
    let create = signed(u, &rig.owner);
    let first = execute(&rig.state, &block(&rig.miner, &parent, vec![], vec![raw(&create)], FEE), &History::default()).unwrap();
    // The same bytes again inside the window, one block later: the lot exists (V6 Duplicate).
    let mut history = History::default();
    history.insert_anchor(0, parent.block).unwrap();
    let b = block(&rig.miner, &anchor(1), vec![], vec![raw(&create)], FEE);
    assert_eq!(bond_error(reject(&first.state, &b, &history)), BondError::Eligibility(Error::Duplicate));
    // The same lot identity (node, owner, nonce) twice in one block, funded differently.
    let twin = signed(unsigned(&rig.owner, rig.node, &parent, vec![point(0xA1)], 1), &rig.owner);
    assert_eq!(twin.lot_id(), create.lot_id());
    let b = block(&rig.miner, &parent, vec![], vec![raw(&create), raw(&twin)], 2 * FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Eligibility(Error::Duplicate));
    // The same bytes twice in one body are not even a block.
    let b = block(&rig.miner, &parent, vec![], vec![raw(&create), raw(&create)], 2 * FEE);
    assert_eq!(codec_error(reject(&rig.state, &b, &History::default())), Error::Duplicate);
}

/// Design 1.c: the DECLARED fee is pre-summed into the coinbase before the payment phase, and the
/// bond-create phase verifies it. A lie fails the whole block, so no coinbase can contain an unpaid
/// fee; omitting the pre-sum fails the fee total.
#[test]
fn declared_fee_mismatch_rejects_before_install() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING, 0));
    let parent = anchor(0);
    let fee_case = |fee: u64, change: u64| {
        let mut u = unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1);
        u.fee = fee;
        u.change = Some(Output { owner, atoms: change });
        signed(u, &rig.owner)
    };
    // Declared higher than the real surplus: the coinbase would pay atoms nobody paid.
    let inflated = fee_case(FEE + 5_000, CHANGE);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&inflated)], FEE + 5_000);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Conservation);
    // Declared lower than the real surplus: no silent burn either.
    let deflated = fee_case(FEE - 5_000, CHANGE);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&deflated)], FEE - 5_000);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Conservation);
    // Exact conservation but below 1 atom per byte of the complete signed operation.
    let cheap = fee_case(100, FUNDING - MINIMUM_ATOMS - 100);
    assert!(cheap.unsigned.signed_len().unwrap() > 100);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&cheap)], 100);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Fee);
    // The block fee must include the declared create fee exactly.
    let good = fee_case(FEE, CHANGE);
    for wrong in [0, FEE - 1, FEE + 1, 2 * FEE] {
        let b = block(&rig.miner, &parent, vec![], vec![raw(&good)], wrong);
        assert!(matches!(reject(&rig.state, &b, &History::default()), ExecutionError::WrongFees), "{wrong}");
    }
    execute(&rig.state, &block(&rig.miner, &parent, vec![], vec![raw(&good)], FEE), &History::default()).unwrap();
}

#[test]
fn wrong_context_rejected() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING, 0));
    let parent = anchor(0);
    for (edit, expected) in [
        (0, BondError::Context(Error::WrongGenesis)),
        (1, BondError::Context(Error::WrongFingerprint)),
    ] {
        let mut u = unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1);
        if edit == 0 {
            u.genesis[0] ^= 1;
        } else {
            u.fingerprint[0] ^= 1;
        }
        let b = block(&rig.miner, &parent, vec![], vec![raw(&signed(u, &rig.owner))], FEE);
        assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), expected);
    }
    // Another network is not a kind-24 encoding at all.
    let create = signed(unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1), &rig.owner);
    let mut op = raw(&create);
    let network = NETWORK_ID.to_be_bytes();
    let at = op.windows(5).position(|w| w == [0x1a, network[0], network[1], network[2], network[3]]).unwrap();
    op[at + 4] ^= 0x02;
    let b = block(&rig.miner, &parent, vec![], vec![op], FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Codec);
}

#[test]
fn expired_and_future_windows_reject_byte_identical() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING, 0));
    let state = at(&rig.state, 5);
    let mut history = History::default();
    history.insert_anchor(0, block_hash(0)).unwrap();
    let case = |first: u64, last: u64| {
        let mut u = unsigned(&rig.owner, rig.node, &anchor(0), vec![point(0xA0)], 1);
        u.envelope = Envelope {
            first_height: first,
            last_height: last,
            reference_height: 0,
            reference_block: block_hash(0),
            preconditions: vec![],
        };
        block(&rig.miner, &anchor(5), vec![], vec![raw(&signed(u, &rig.owner))], FEE)
    };
    // Inclusion height 6.
    assert_eq!(bond_error(reject(&state, &case(1, 5), &history)), BondError::Envelope(EnvelopeError::Expired));
    assert_eq!(bond_error(reject(&state, &case(7, 9), &history)), BondError::Envelope(EnvelopeError::Future));
    // Both ends are inclusive.
    execute(&state, &case(1, 6), &history).unwrap();
    execute(&state, &case(6, 9), &history).unwrap();
}

/// P4 rule R through History anchors (the canonical store supplies them; design 1.a.3).
#[test]
fn reference_must_be_canonical() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING, 0));
    let state = at(&rig.state, 5);
    let case = |reference_height: u64, reference_block: Hash| {
        let mut u = unsigned(&rig.owner, rig.node, &anchor(5), vec![point(0xA0)], 1);
        u.envelope = Envelope {
            first_height: 6,
            last_height: 8,
            reference_height,
            reference_block,
            preconditions: vec![],
        };
        block(&rig.miner, &anchor(5), vec![], vec![raw(&signed(u, &rig.owner))], FEE)
    };
    let mut history = History::default();
    history.insert_anchor(3, block_hash(3)).unwrap();
    // The parent itself needs no anchor; an older canonical reference needs its anchor.
    execute(&state, &case(5, block_hash(5)), &History::default()).unwrap();
    execute(&state, &case(3, block_hash(3)), &history).unwrap();
    let not = BondError::Envelope(EnvelopeError::ReferenceNotCanonical);
    assert_eq!(bond_error(reject(&state, &case(3, block_hash(3)), &History::default())), not, "fail closed");
    assert_eq!(bond_error(reject(&state, &case(3, [0x33; 32]), &history)), not, "non-canonical block");
    assert_eq!(bond_error(reject(&state, &case(5, [0x55; 32]), &history)), not, "not the parent");
    assert_eq!(bond_error(reject(&state, &case(4, block_hash(4)), &history)), not, "no anchor at 4");
}

/// AM-11: kind 24 exists only with Continuity state (as kind 18 did).
#[test]
fn kind_24_requires_continuity_state() {
    let rig = rig();
    let owner = addr(&rig.owner, 1);
    let mut plain = State::default();
    plain.wallets = rig.state.wallets.clone();
    plain.licenses_v2 = rig.state.licenses_v2.clone();
    plain.coins.insert(point(0xA0), coin(owner, FUNDING, 0));
    let parent = anchor(0);
    let create = signed(unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1), &rig.owner);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&create)], FEE);
    assert!(matches!(reject(&plain, &b, &History::default()), ExecutionError::UnsupportedOperation));
    assert_eq!(
        bc::check(&plain, &parent, &History::default(), &raw(&create)),
        Err(BondError::State(Error::UnqualifiedPhysical))
    );
}

/// V6 (the unchanged eligibility checks): only the node's admission owner can bond it, at the
/// node's current generation, for a known member; at most 64 locked lots per lineage.
#[test]
fn bonding_another_owners_node_or_an_unknown_node_rejected() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    let stranger = stranger_key();
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING, 0));
    rig.state.coins.insert(point(0xA1), coin(addr(&stranger, 1), FUNDING, 0));
    let parent = anchor(0);
    let foreign = signed(unsigned(&stranger, rig.node, &parent, vec![point(0xA1)], 1), &stranger);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&foreign)], FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Eligibility(Error::UnqualifiedPhysical));
    let mut u = unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1);
    u.node_generation = 2;
    let b = block(&rig.miner, &parent, vec![], vec![raw(&signed(u, &rig.owner))], FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Eligibility(Error::UnqualifiedPhysical));
    let unknown = signed(unsigned(&rig.owner, [0x77; 32], &parent, vec![point(0xA0)], 1), &rig.owner);
    let b = block(&rig.miner, &parent, vec![], vec![raw(&unknown)], FEE);
    assert_eq!(bond_error(reject(&rig.state, &b, &History::default())), BondError::Eligibility(Error::UnknownSigner));
    // The 65th locked lot of one lineage is refused (existing capacity rule, unchanged).
    let mut full = at(&rig.state, 1);
    for n in 0..64u8 {
        let id = [n; 32];
        full.bonds_v2.lots.insert(
            id,
            Lot(BondLot {
                id,
                node: rig.node,
                lineage: rig.node,
                owner,
                atoms: MINIMUM_ATOMS,
                created_height: 1,
                sequence: 0,
                unbond_height: None,
                settled_height: None,
                status: LotStatus::Active,
                evidence: [0; 32],
            }),
        );
    }
    let more = signed(unsigned(&rig.owner, rig.node, &anchor(1), vec![point(0xA0)], 1), &rig.owner);
    let b = block(&rig.miner, &anchor(1), vec![], vec![raw(&more)], FEE);
    assert_eq!(bond_error(reject(&full, &b, &History::default())), BondError::Eligibility(Error::Capacity));
}

/// V3: an optional precondition is compared EXACTLY with the facts at the bond-create phase.
#[test]
fn optional_precondition_is_checked_at_the_bond_create_phase() {
    let mut rig = rig();
    let owner = addr(&rig.owner, 1);
    rig.state.coins.insert(point(0xA0), coin(owner, FUNDING, 0));
    let parent = anchor(0);
    // The License has no live award: its committed entitlement facts are the empty list.
    let facts = envelope::entitlement_facts(&rig.state, rig.miner.license);
    assert_eq!(facts, Precondition::LicenseEntitlements { license: rig.miner.license, accounts: vec![] });
    let case = |p: Precondition| {
        let mut u = unsigned(&rig.owner, rig.node, &parent, vec![point(0xA0)], 1);
        u.envelope.preconditions = vec![p];
        block(&rig.miner, &parent, vec![], vec![raw(&signed(u, &rig.owner))], FEE)
    };
    execute(&rig.state, &case(facts), &History::default()).unwrap();
    let stale = Precondition::LicenseEntitlements {
        license: rig.miner.license,
        accounts: vec![AwardAccount { award_epoch: 131_072, share: 10, remaining: 10, claims: 0 }],
    };
    assert_eq!(
        bond_error(reject(&rig.state, &case(stale), &History::default())),
        BondError::Envelope(EnvelopeError::Stale(envelope::TAG_LICENSE_ENTITLEMENTS))
    );
}

// ---------------------------------------------------------------------------------------------
// AM-11: kind 24 in a recovery block (first resumed block, recovery components)
// ---------------------------------------------------------------------------------------------
struct RecoveryRig {
    state: State,
    prepared: Prepared,
    owner: HybridKey,
    old_node: Hash,
    new_node: Hash,
    parent: FinalizedAnchor,
    miner: Miner,
}
/// The recovery fixture of `recovery_execution_v2.rs` (lines 135-330 at 36add1f): one member whose
/// hardware is replaced by a supervised hybrid recovery at the first resumed height 1.
fn recovery_rig() -> RecoveryRig {
    let phrase = format!("{}art", "abandon ".repeat(23));
    let owner = HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap();
    let recovery = HybridKey::wallet_restore(&phrase, Role::WalletRecovery).unwrap();
    let old_node = HybridKey::generate(Role::Node).unwrap();
    let old_continuity = HybridKey::generate(Role::Continuity).unwrap();
    let new_node = HybridKey::generate(Role::Node).unwrap();
    let new_continuity = HybridKey::generate(Role::Continuity).unwrap();
    let ak = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let original_profile = profile(&ak);
    let policy = Policy {
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        owner_descriptor: desc(&owner, 1),
        endorsement_roots: [[3; 32]].into_iter().collect(),
    };
    let descriptor = old_node.public().descriptor(1).unwrap();
    let id = node_id(GENESIS, &descriptor).unwrap();
    let mut binding = Binding {
        node_signer: None,
        node_descriptor: descriptor,
        possession: zero(),
        admission: Admission {
            genesis: GENESIS,
            fingerprint: FINGERPRINT,
            node: id,
            hardware_generation: 1,
            key_generation: 1,
            continuity_descriptor: old_continuity.public().descriptor(1).unwrap(),
            profile: original_profile.encode().unwrap(),
            endorsement_root: [3; 32],
            owner: addr(&owner, 1),
            supervised_nonce: [5; 32],
            quote: vec![],
            possession: zero(),
            authorization: zero(),
        },
    };
    binding.admission.prove_continuity(&old_continuity).unwrap();
    binding.admission.quote = quote(&ak, &original_profile, binding.admission.challenge().unwrap());
    binding.admission.authorize(&owner, 1).unwrap();
    binding.sign(&old_node).unwrap();
    let mut state = State::default();
    state.wallets.register(&policy.owner_descriptor).unwrap();
    state.admission_policy_v2 = Some(admission_policy_v2::Record::new(policy.clone()).unwrap());
    (state.membership_v2, state.continuity_keys_v2) = membership_v2::Book::genesis(
        &binding,
        &policy,
        &Expected {
            node: id,
            hardware_generation: 1,
            key_generation: 1,
            supervised_nonce: [5; 32],
        },
        &state.wallets,
        AdmissionClass::LegacyTest,
    )
    .unwrap();
    state.continuity = Some(
        ContinuityState::bootstrap(
            GENESIS,
            FINGERPRINT,
            Anchor {
                height: 0,
                tip: [19; 32],
                state_root: [0; 32],
                registry_root: [0; 32],
            },
            [20; 32],
            vec![Member {
                lineage: id,
                node: id,
                hardware: original_profile.hardware,
                generation: 1,
                voting_key: tpm::public_key(&original_profile.voting_public, false).unwrap(),
                attestation: original_profile.commitment().unwrap(),
                history: Default::default(),
                physical: true,
                eligible: true,
                genesis_member: true,
            }],
        )
        .unwrap(),
    );
    state.recovery_authority_v2 = Some(Authority {
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        descriptor: recovery.public().descriptor(1).unwrap(),
    });
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        height: 0,
        block: [19; 32],
    };
    let (_, assignments, expected, licenses, _) = license_fixture::fixtures();
    state.licenses_v2 = license_book_v2::Book::genesis(&assignments, &expected, &licenses, &state.wallets, GENESIS, FINGERPRINT)
        .unwrap();
    // The owner's coin that funds the bonds below (created before the recovery).
    state.coins.insert(point(0xB0), coin(addr(&owner, 1), FUNDING, 0));
    let root = state.root().unwrap();
    let authority = HeightAuthority::from_state(&state, parent.clone(), root).unwrap();
    let native = SigningKey::from_bytes((&[18u8; 32]).into()).unwrap();
    let mut replacement_profile = original_profile.clone();
    replacement_profile.hardware = [55; 32];
    replacement_profile.voting_public = public(&native, false);
    let mut name = vec![0, 0xb];
    name.extend(Sha256::digest(&replacement_profile.voting_public[2..]));
    let mut certify = header(0x8017, &replacement_profile.qualified_signer, &[0, 255, 85, 170]);
    certify.extend(blob(&name));
    certify.extend(blob(&replacement_profile.qualified_signer));
    replacement_profile.certify_signature = signature(&ak, &certify);
    replacement_profile.certify_message = certify;
    binding.node_descriptor = new_node.public().descriptor(1).unwrap();
    binding.admission.node = node_id(GENESIS, &binding.node_descriptor).unwrap();
    binding.admission.hardware_generation = 2;
    binding.admission.key_generation = 2;
    binding.admission.continuity_descriptor = new_continuity.public().descriptor(2).unwrap();
    binding.admission.profile = replacement_profile.encode().unwrap();
    let new_id = binding.admission.node;
    let mut material = Replacement {
        parent: parent.clone(),
        root,
        membership: authority.membership,
        sequence: 1,
        lineage: id,
        old_node: id,
        old_hardware_generation: 1,
        old_key_generation: 1,
        nonce: [57; 32],
        lost: vec![(id, 1)],
        binding,
        native_possession: [0; 64],
    };
    material.binding.admission.supervised_nonce = material.admission_nonce().unwrap();
    material.binding.admission.prove_continuity(&new_continuity).unwrap();
    material.binding.admission.quote = quote(&ak, &replacement_profile, material.binding.admission.challenge().unwrap());
    material.binding.admission.authorize(&owner, 1).unwrap();
    material.binding.sign(&new_node).unwrap();
    let sig: Signature = native.sign_prehash(&material.native_digest().unwrap()).unwrap();
    material.native_possession = sig.normalize_s().unwrap_or(sig).to_bytes().into();
    let authorization = Authorization::sign(
        material.intent().unwrap(),
        state.recovery_authority_v2.as_ref().unwrap(),
        &recovery,
    )
    .unwrap();
    material.verify_material(&state, &parent, root, &authorization, false).unwrap();
    let mut tree = state_tree::StateTree::default();
    for (key, raw) in state.records().unwrap() {
        tree.insert(key, raw).unwrap();
    }
    let witnesses = witness::Witnesses {
        control: tree.proof(parent.clone(), domain_hash(b"MUTINY-BUILD8-NODE-CONTROL-KEY-V2", &id)),
        continuity: tree.proof(parent.clone(), domain_hash(b"MUTINY-BUILD8-CONTINUITY-KEY-STATE-V2", &id)),
    };
    let archive = history_record::Record {
        material,
        authorization,
        witnesses,
        policy,
    };
    let prepared = Prepared::verify(&state, &parent, root, archive, false).unwrap();
    RecoveryRig {
        state,
        prepared,
        owner,
        old_node: id,
        new_node: new_id,
        parent,
        miner: Miner {
            license: licenses[0].id,
            worker: expected[0].worker_id,
            reward_owner: licenses[0].owner,
        },
    }
}

#[test]
fn kind_24_in_a_recovery_block_uses_the_recovery_components() {
    let r = recovery_rig();
    let prepare = |b: &Block| {
        r.prepared.prepare_candidate(
            &r.state,
            CandidatePreparation {
                parent: &b.parent,
                candidate: &b.candidate,
                ticket_sequence: 1,
                body: &b.body,
            },
            &History::default(),
        )
    };
    // Bonding the REPLACEMENT node (hardware generation 2) of the same lineage is valid in the
    // first resumed block: the bond-create phase reads the recovery components.
    let mut u = unsigned(&r.owner, r.new_node, &r.parent, vec![point(0xB0)], 1);
    u.node_generation = 2;
    let new = signed(u, &r.owner);
    let b = block(&r.miner, &r.parent, vec![], vec![raw(&new)], FEE);
    let executed = prepare(&b).unwrap();
    let lot = &executed.state.bonds_v2.lots[&new.lot_id()].0;
    assert_eq!((lot.node, lot.lineage, lot.created_height), (r.new_node, r.old_node, 1));
    // Bonding the REPLACED node is refused in that block, and nothing changes.
    let old = signed(unsigned(&r.owner, r.old_node, &r.parent, vec![point(0xB0)], 1), &r.owner);
    let b = block(&r.miner, &r.parent, vec![], vec![raw(&old)], FEE);
    let (records, root) = (r.state.records().unwrap(), r.state.root().unwrap());
    let error = prepare(&b).err().expect("the replaced node cannot be bonded in the recovery block");
    assert_eq!(bond_error(error), BondError::Eligibility(Error::UnknownSigner));
    assert!(r.state.records().unwrap() == records);
    assert_eq!(r.state.root().unwrap(), root);
    // Without the recovery the same operation is valid on the canonical parent: the difference
    // is exactly the recovery components (no stale parent registry leaks into the phase).
    execute(&r.state, &b, &History::default()).unwrap();
}

// ---------------------------------------------------------------------------------------------
// Bond commands, body version 3 (design 5.1, 11.1; AM-5)
// ---------------------------------------------------------------------------------------------
/// The notice U is the ACTUAL inclusion height of the Unbond: signed with the window [h+1, h+50]
/// and included at h+30, U = h+30, and the 43,200-block notice floor counts from there.
#[test]
fn unbond_signed_early_notice_at_inclusion() {
    let rig = rig();
    let owner = addr(&rig.owner, 1);
    let h = LOCK_HEIGHTS;
    let mut state = rig.state.clone();
    let lot = Lot(BondLot {
        id: [0x80; 32],
        node: rig.node,
        lineage: rig.node,
        owner,
        atoms: MINIMUM_ATOMS,
        created_height: 1,
        sequence: 0,
        unbond_height: None,
        settled_height: None,
        status: LotStatus::Active,
        evidence: [0; 32],
    });
    state.bonds_v2.lots.insert(lot.0.id, lot.clone());
    let state = at(&state, h + 29);
    let unbond = command(
        &rig.owner,
        1,
        owner,
        Action::Unbond { lot: lot.0.id, sequence: 1 },
        Envelope {
            first_height: h + 1,
            last_height: h + 50,
            reference_height: h,
            reference_block: block_hash(h),
            preconditions: vec![],
        },
    );
    let b = block(&rig.miner, &anchor(h + 29), vec![], vec![unbond.encode().unwrap()], 0);
    assert_eq!(envelope::referenced_heights(&b.body), BTreeSet::from([h]));
    // Without the reference anchor the lifecycle phase fails closed.
    assert_eq!(
        codec_error(reject(&state, &b, &History::default())),
        Error::Envelope(EnvelopeError::ReferenceNotCanonical)
    );
    let mut history = History::default();
    history.insert_anchor(h, block_hash(h)).unwrap();
    let executed = execute(&state, &b, &history).unwrap();
    let u = h + 30;
    assert_eq!(executed.state.bonds_v2.lots[&lot.0.id].0.unbond_height, Some(u), "U = actual inclusion");
    assert_eq!(executed.bond_command_outcomes[&unbond.id().unwrap()], CommandOutcome::Applied);
    // Here the notice floor binds: max(1 + 259,200, U + 43,200) = U + 43,200.
    let floor = withdrawal_floor(1, u).unwrap();
    assert_eq!(floor, u + EVIDENCE_HEIGHTS);
    let noticed = executed.state;
    let early = at(&noticed, floor - 2);
    let w = command(&rig.owner, 1, owner, Action::Withdraw { lot: lot.0.id, sequence: 2 }, window(&anchor(floor - 2)));
    let e = reject(&early, &block(&rig.miner, &anchor(floor - 2), vec![], vec![w.encode().unwrap()], 0), &History::default());
    assert_eq!(codec_error(e), Error::InvalidCounter, "one block before U + 43,200");
    // A Withdraw signed for the window [floor - 10, floor + 10] and included at the floor settles
    // at the ACTUAL height: its window start is not a settlement height.
    let ready = at(&noticed, floor - 1);
    let w = command(
        &rig.owner,
        1,
        owner,
        Action::Withdraw { lot: lot.0.id, sequence: 2 },
        Envelope {
            first_height: floor - 10,
            last_height: floor + 10,
            reference_height: floor - 11,
            reference_block: block_hash(floor - 11),
            preconditions: vec![],
        },
    );
    let mut history = History::default();
    history.insert_anchor(floor - 11, block_hash(floor - 11)).unwrap();
    let paid = execute(&ready, &block(&rig.miner, &anchor(floor - 1), vec![], vec![w.encode().unwrap()], 0), &history).unwrap();
    assert_eq!(paid.state.bonds_v2.lots[&lot.0.id].0.settled_height, Some(floor));
    let payout = OutPoint {
        transaction: w.payout_id().unwrap(),
        index: 0,
    };
    assert_eq!(paid.state.coins[&payout], coin(owner, MINIMUM_ATOMS, floor));
}

/// 14.10: replay protection is the per-lot sequence; at most one command per lot per block; the
/// envelope (window and reference) is checked against the parent (the mutant that skips it dies).
#[test]
fn command_replay_rejected_by_sequence() {
    let rig = rig();
    let owner = addr(&rig.owner, 1);
    let mut state = rig.state.clone();
    let lot = Lot(BondLot {
        id: [0x81; 32],
        node: rig.node,
        lineage: rig.node,
        owner,
        atoms: MINIMUM_ATOMS,
        created_height: 1,
        sequence: 0,
        unbond_height: None,
        settled_height: None,
        status: LotStatus::Active,
        evidence: [0; 32],
    });
    state.bonds_v2.lots.insert(lot.0.id, lot.clone());
    let p = 10;
    let state = at(&state, p);
    let mut history = History::default();
    history.insert_anchor(9, block_hash(9)).unwrap();
    let span = Envelope {
        first_height: p + 1,
        last_height: p + 5,
        reference_height: 9,
        reference_block: block_hash(9),
        preconditions: vec![],
    };
    let unbond = command(&rig.owner, 1, owner, Action::Unbond { lot: lot.0.id, sequence: 1 }, span.clone());
    let first = execute(&state, &block(&rig.miner, &anchor(p), vec![], vec![unbond.encode().unwrap()], 0), &history).unwrap();
    // The same signed command one block later, still inside its window: the sequence is used.
    let e = reject(&first.state, &block(&rig.miner, &anchor(p + 1), vec![], vec![unbond.encode().unwrap()], 0), &history);
    assert_eq!(codec_error(e), Error::StaleSequence);
    // Two commands for one lot in one block.
    let other = command(&rig.owner, 1, owner, Action::Unbond { lot: lot.0.id, sequence: 1 }, window(&anchor(p)));
    let b = block(&rig.miner, &anchor(p), vec![], vec![unbond.encode().unwrap(), other.encode().unwrap()], 0);
    assert_eq!(codec_error(reject(&state, &b, &history)), Error::Duplicate);
    // The window and the reference are enforced at the actual inclusion height.
    let late = command(
        &rig.owner,
        1,
        owner,
        Action::Unbond { lot: lot.0.id, sequence: 1 },
        Envelope { first_height: 5, last_height: p, reference_height: 4, reference_block: block_hash(4), preconditions: vec![] },
    );
    let mut wide = history.clone();
    wide.insert_anchor(4, block_hash(4)).unwrap();
    let b = block(&rig.miner, &anchor(p), vec![], vec![late.encode().unwrap()], 0);
    assert_eq!(codec_error(reject(&state, &b, &wide)), Error::Envelope(EnvelopeError::Expired));
    let early = command(
        &rig.owner,
        1,
        owner,
        Action::Unbond { lot: lot.0.id, sequence: 1 },
        Envelope { first_height: p + 2, last_height: p + 3, reference_height: p, reference_block: block_hash(p), preconditions: vec![] },
    );
    let b = block(&rig.miner, &anchor(p), vec![], vec![early.encode().unwrap()], 0);
    assert_eq!(codec_error(reject(&state, &b, &history)), Error::Envelope(EnvelopeError::Future));
    let forged = command(
        &rig.owner,
        1,
        owner,
        Action::Unbond { lot: lot.0.id, sequence: 1 },
        Envelope { first_height: p + 1, last_height: p + 1, reference_height: 9, reference_block: [0x99; 32], preconditions: vec![] },
    );
    let b = block(&rig.miner, &anchor(p), vec![], vec![forged.encode().unwrap()], 0);
    assert_eq!(codec_error(reject(&state, &b, &history)), Error::Envelope(EnvelopeError::ReferenceNotCanonical));
}

/// Q4 (an explicit, narrow decision): Unbond and Withdraw carry no fee and consume no input; a
/// block declaring any fee for them fails the fee total. BondCreate is NOT exempt (it pays 1 atom
/// per byte, `declared_fee_mismatch_rejects_before_install`).
#[test]
fn bond_commands_are_fee_free_q4() {
    let rig = rig();
    let owner = addr(&rig.owner, 1);
    let mut state = rig.state.clone();
    let lot = Lot(BondLot {
        id: [0x82; 32],
        node: rig.node,
        lineage: rig.node,
        owner,
        atoms: MINIMUM_ATOMS,
        created_height: 1,
        sequence: 0,
        unbond_height: None,
        settled_height: None,
        status: LotStatus::Active,
        evidence: [0; 32],
    });
    state.bonds_v2.lots.insert(lot.0.id, lot.clone());
    let state = at(&state, 1);
    let unbond = command(&rig.owner, 1, owner, Action::Unbond { lot: lot.0.id, sequence: 1 }, window(&anchor(1)));
    let b = block(&rig.miner, &anchor(1), vec![], vec![unbond.encode().unwrap()], 1);
    assert!(matches!(reject(&state, &b, &History::default()), ExecutionError::WrongFees));
    let b = block(&rig.miner, &anchor(1), vec![], vec![unbond.encode().unwrap()], 0);
    let executed = execute(&state, &b, &History::default()).unwrap();
    assert_eq!(executed.fees, 0);
    assert_eq!(total_atoms(&executed.state), total_atoms(&state) + u128::from(SUBSIDY), "only the subsidy is new");
    let coinbase = OutPoint { transaction: executed.coinbase_id, index: 0 };
    assert_eq!(executed.state.coins[&coinbase].output.atoms, SUBSIDY);
}

/// AM-5: a Withdraw validated against the PARENT lot is neutralized when same-block evidence burns
/// the lot first: the block is valid, no payout coin exists, and the outcome says NoEffectBurned.
#[test]
fn withdraw_with_same_block_evidence_records_no_effect() {
    let rig = rig();
    let owner = addr(&rig.owner, 1);
    let mut state = rig.state.clone();
    let registry = state.continuity.as_mut().unwrap();
    registry.first_period_committed = true;
    let member = &mut registry.members[0];
    member.history.p = 1;
    member.history.s = 1;
    member.history.h = 1;
    let member = member.clone();
    let u = 1 + LOCK_HEIGHTS;
    let h = u + EVIDENCE_HEIGHTS;
    let mut lot = Lot(BondLot {
        id: [0x83; 32],
        node: member.node,
        lineage: member.lineage,
        owner,
        atoms: MINIMUM_ATOMS,
        created_height: 1,
        sequence: 0,
        unbond_height: None,
        settled_height: None,
        status: LotStatus::Active,
        evidence: [0; 32],
    });
    state.bonds_v2.lots.insert(lot.0.id, lot.clone());
    // Historical authority of the offense height u, from its authenticated E-1 state.
    let historical_state = at(&state, u - 1);
    let historical_parent = anchor(u - 1);
    let historical = HeightAuthority::from_state(&historical_state, historical_parent.clone(), historical_state.root().unwrap()).unwrap();
    let voter = &historical.voters[&member.node];
    let roots = historical.roots();
    let mut a = Vote {
        decision: Decision {
            network: NETWORK_ID,
            genesis: GENESIS,
            fingerprint: FINGERPRINT,
            purpose: 2,
            height: u,
            mining_epoch: u - 1,
            continuity_period: (u - 1) / 60,
            round: 1,
            step: 3,
            previous_finalized_anchor: historical_parent.id(),
            parent: historical_parent.block,
            block: [0x84; 32],
            state: [0x85; 32],
            membership: roots[0],
            reputation: roots[1],
            attestation: roots[2],
        },
        nil: false,
        node: member.node,
        hardware_generation: 1,
        key_generation: 1,
        sequence: 1,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: zero(),
    };
    a.sign(&rig.continuity).unwrap();
    let mut b = a.clone();
    b.decision.block = [0x86; 32];
    b.sequence = 2;
    b.sign(&rig.continuity).unwrap();
    let evidence = Evidence::new(a, b).unwrap().encode().unwrap();
    let history: History = [(u, historical)].into_iter().collect();
    lot.start_unbond(u, 1).unwrap();
    state.bonds_v2.lots.insert(lot.0.id, lot.clone());
    let parent_state = at(&state, h - 1);
    let withdraw = command(&rig.owner, 1, owner, Action::Withdraw { lot: lot.0.id, sequence: 2 }, window(&anchor(h - 1)));
    let id = withdraw.id().unwrap();
    let payout = OutPoint {
        transaction: withdraw.payout_id().unwrap(),
        index: 0,
    };
    // Without evidence the withdrawal pays out: Applied.
    let paid = execute(&parent_state, &block(&rig.miner, &anchor(h - 1), vec![], vec![withdraw.encode().unwrap()], 0), &history).unwrap();
    assert_eq!(paid.bond_command_outcomes.get(&id), Some(&CommandOutcome::Applied));
    let paid_body = block(&rig.miner, &anchor(h - 1), vec![], vec![withdraw.encode().unwrap()], 0);
    let paid_records = mutiny_consensus_v8::operation_index_v2::records(&paid_body.body, [0xa4;32], &paid.bond_command_outcomes).unwrap();
    let paid_record = paid_records.iter().find(|r| r.op_id == id).unwrap();
    assert_eq!(paid_record.command_outcome().unwrap(), Some(CommandOutcome::Applied));
    paid_record.verify_in_block(&paid_body.body, [0xa4;32]).unwrap();
    assert_eq!(paid.state.coins[&payout], coin(owner, MINIMUM_ATOMS, h));
    // With the evidence in the same block (either order): valid block, no payout, NoEffectBurned.
    for operations in [vec![withdraw.encode().unwrap(), evidence.clone()], vec![evidence.clone(), withdraw.encode().unwrap()]] {
        let burned_body = block(&rig.miner, &anchor(h - 1), vec![], operations, 0);
        let burned = execute(&parent_state, &burned_body, &history).unwrap();
        assert_eq!(burned.bond_command_outcomes.len(), 1);
        assert_eq!(burned.bond_command_outcomes.get(&id), Some(&CommandOutcome::NoEffectBurned));
        let records = mutiny_consensus_v8::operation_index_v2::records(&burned_body.body, [0xa4;32], &burned.bond_command_outcomes).unwrap();
        let record = records.iter().find(|r| r.op_id == id).unwrap();
        assert_eq!(record.command_outcome().unwrap(), Some(CommandOutcome::NoEffectBurned));
        record.verify_in_block(&burned_body.body, [0xa4;32]).unwrap();
        assert_eq!(record.verify_against_replica(paid_record), Err(mutiny_consensus_v8::operation_index_v2::IndexError::Receipt));
        let mut claimed_applied = record.clone(); claimed_applied.receipt = paid_record.receipt.clone();
        // Structural proof cannot distinguish the execution outcome; exact replica comparison can.
        claimed_applied.verify_in_block(&burned_body.body, [0xa4;32]).unwrap();
        assert_eq!(claimed_applied.verify_against_replica(record), Err(mutiny_consensus_v8::operation_index_v2::IndexError::Receipt));
        assert!(!burned.state.coins.contains_key(&payout), "no payout exists for a burned lot");
        assert_eq!(burned.state.bonds_v2.lots[&lot.0.id].0.status, LotStatus::Burned);
        assert_eq!(CommandOutcome::NoEffectBurned.code(), 2);
    }
}

// ---------------------------------------------------------------------------------------------
// AM-11: cross-verify matrix over the REAL Domain::Transaction payload builders on this branch
// ---------------------------------------------------------------------------------------------
fn freeze_body(offer: &[u8], descriptor: &[u8], wallet: Hash) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(14).unwrap().bytes(NATIVE_NAMESPACE).unwrap().bytes(b"treasury-freeze").unwrap().u8(1).unwrap();
    e.array(3).unwrap().u32(NETWORK_ID).unwrap().bytes(&GENESIS).unwrap().bytes(&FINGERPRINT).unwrap();
    e.u64(3).unwrap().bytes(&[0xD1; 32]).unwrap().bytes(&[0xD2; 32]).unwrap().bytes(&[0xD3; 32]).unwrap();
    e.u64(1).unwrap().bytes(&wallet).unwrap().bytes(&[0xD4; 32]).unwrap().bytes(&[0xD5; 32]).unwrap();
    e.bytes(offer).unwrap().bytes(descriptor).unwrap();
    e.into_writer()
}
fn frozen(body: &[u8], signature: &HybridSignature) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3).unwrap().bytes(body).unwrap().bytes(&signature.ed448).unwrap().bytes(&signature.fndsa).unwrap();
    e.into_writer()
}
#[test]
fn cross_verify_matrix_of_every_transaction_domain_payload() {
    let key = owner_key();
    let descriptor = desc(&key, 1);
    let address = addr(&key, 1);
    // 0 Transfer input (transactions_v2): [bytes unsigned transfer, u32 index].
    let transfer = transfer(&key, 1, point(0xC0), 10_000, 5_000, [0xC1; 32], 1);
    // 1 Trading approval (trading_v1): [bytes NAMESPACE, bytes body, u8 slot, bytes descriptor].
    let trade = TradeOperation {
        meta: Meta {
            context: Context { network: NETWORK_ID, genesis: GENESIS, fingerprint: FINGERPRINT },
            trade: [0xC2; 32],
            contract: [0xC3; 32],
            generation: 1,
            envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                first_height: 2,
                last_height: 3,
                reference_height: 1,
                reference_block: [0xC8; 32],
                preconditions: vec![],
            },
            fee: Strikes(240),
            inputs: vec![],
        },
        action: TradeAction::HashLock {
            offer: [0xC4; 32],
            maker: [0xC5; 32],
            sender: address,
            recipient: [0xC6; 32],
            amount: Strikes(1_000),
            condition: [0xC7; 32],
            refund_height: 10,
            change: Strikes(0),
        },
        approvals: vec![],
        offer_proof: None,
    };
    // 2 Dividend claim (dividend_claim_v1): [bytes label, bytes body, bytes descriptor].
    let claim = SignedClaim {
        body: ClaimBody {
            network: NETWORK_ID,
            genesis: GENESIS,
            fingerprint: FINGERPRINT,
            created_height: 1,
            expiry_height: 2,
            award_epoch: 131_072,
            license: [0xC8; 32],
            amount: 5,
            destination: address,
            sequence: 0,
        },
        descriptor: descriptor.clone(),
        signature: zero(),
    };
    // 3 Treasury freeze (trading_v1 TreasuryFreezeBody, array(14)).
    let offer = OfferBody {
        context: Context { network: NETWORK_ID, genesis: GENESIS, fingerprint: FINGERPRINT },
        // P7 (WP-T4, AM-6): OfferBody version 2; the maker is the wallet itself.
        maker_descriptor: descriptor.clone(),
        maker_wallet: address,
        destination: address,
        condition: None,
        max_fee: Strikes(240),
        nonce: [0xC9; 32],
        created: 1,
        expiry: 5,
        maker_side: 1,
        terms: OfferTerms::HashLinked { amount: Strikes(1_000), bitcoin_satoshis: 1, bitcoin_network: 3 },
    }
    .encode()
    .unwrap();
    let freeze = freeze_body(&offer, &descriptor, address);
    // 4 Funded BondCreate funding (bond_create_v3): [bytes label, bytes commitment, 0].
    let create = signed(unsigned(&key, [0xCA; 32], &anchor(0), vec![point(0xCB)], 1), &key);
    let payloads = [
        transfer.signing_payload(0).unwrap(),
        trade.signing_payload(0, &descriptor).unwrap(),
        claim.signing_payload(),
        freeze.clone(),
        bc::funding_payload(&create.unsigned.commitment().unwrap()),
    ];
    for i in 0..payloads.len() {
        for j in 0..i {
            assert_ne!(payloads[i], payloads[j]);
        }
    }
    let signatures: Vec<HybridSignature> = payloads.iter().map(|p| key.sign(Domain::Transaction, p).unwrap()).collect();
    // Each REAL verifier with the candidate signature in its own slot.
    let verify = |verifier: usize, signature: &HybridSignature| -> bool {
        match verifier {
            0 => {
                let mut t = transfer.clone();
                t.inputs[0].signature = signature.clone();
                t.verify_signatures().is_ok()
            }
            1 => {
                let mut op = trade.clone();
                op.approvals = vec![Approval { slot: 0, descriptor: descriptor.clone(), signature: signature.clone() }];
                verify_approval(&WalletBook::default(), &op, 0).is_ok()
            }
            2 => {
                let mut c = claim.clone();
                c.signature = signature.clone();
                c.verify_signature().is_ok()
            }
            3 => FrozenTreasuryOffer::decode(&frozen(&freeze, signature)).is_ok(),
            _ => {
                let mut b = create.clone();
                b.funding = signature.clone();
                b.verify_signatures().is_ok()
            }
        }
    };
    let names = ["transfer input", "trading approval", "dividend claim", "Treasury freeze", "bond funding"];
    for (i, signature) in signatures.iter().enumerate() {
        for (j, name) in names.iter().enumerate() {
            assert_eq!(verify(j, signature), i == j, "signature made for {} under the {name} verifier", names[i]);
        }
    }
    // The bond role signature (Domain::BondCreate over [AUTHORIZE label, commitment]) is a
    // Transaction signature for no verifier, and the funding signature is no create signature.
    for j in 0..names.len() {
        assert!(!verify(j, &create.create), "create signature under the {} verifier", names[j]);
    }
    let mut swapped = create.clone();
    swapped.create = create.funding.clone();
    assert_eq!(swapped.verify_signatures(), Err(BondError::Signature(Slot::Create)));
}

// ---------------------------------------------------------------------------------------------
// Registry (design 12.2) and public vectors
// ---------------------------------------------------------------------------------------------
#[test]
fn funded_bond_create_domains_are_registered_as_proposed_and_unfrozen() {
    let registry: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("../spec/DOMAIN-REGISTRY-V1.json").unwrap()).unwrap();
    let listed = registry["domains"].as_array().unwrap();
    for domain in [
        bc::COMMITMENT_DOMAIN,
        bc::ID_DOMAIN,
        bc::AUTHORIZE_LABEL,
        bc::FUNDING_LABEL,
        mutiny_consensus_v8::bond_ops_v2::COMMAND_ID_DOMAIN,
        mutiny_consensus_v8::bond_ops_v2::PAYOUT_DOMAIN,
    ] {
        let ascii = std::str::from_utf8(domain).unwrap();
        let entries: Vec<_> = listed.iter().filter(|e| e["ascii"] == ascii).collect();
        assert_eq!(entries.len(), 1, "{ascii} registered exactly once");
        assert_eq!(entries[0]["status"], "PROPOSED-UNFROZEN", "{ascii}");
        assert_eq!(entries[0]["doc"], "spec/HYBRID-BOND-SETTLEMENT-V2.md", "{ascii}");
        assert_eq!(entries[0]["length"].as_u64(), Some(ascii.len() as u64), "{ascii}");
    }
    let ascii: Vec<_> = listed.iter().map(|e| e["ascii"].as_str().unwrap()).collect();
    let mut unique = ascii.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ascii.len(), "no domain string is registered twice");
}

const VECTOR_FILE: &str = "../qualification/funded-bond-create-v1-public.json";
/// The deterministic valid cases of the public vector file (owner = the public BIP39 phrase).
fn valid_cases() -> Vec<(&'static str, UnsignedBondCreate)> {
    let owner = owner_key();
    let a = addr(&owner, 1);
    let base = UnsignedBondCreate {
        genesis: GENESIS,
        fingerprint: FINGERPRINT,
        envelope: Envelope {
            first_height: 11,
            last_height: 155,
            reference_height: 10,
            reference_block: block_hash(10),
            preconditions: vec![],
        },
        owner: a,
        owner_descriptor: desc(&owner, 1),
        node: [0x4e; 32],
        node_generation: 1,
        nonce: [0x6e; 32],
        principal: MINIMUM_ATOMS,
        fee: FEE,
        inputs: vec![point(0xA0)],
        change: Some(Output { owner: a, atoms: CHANGE }),
    };
    let mut no_change = base.clone();
    no_change.inputs = vec![point(0xA0), point(0xA1), OutPoint { transaction: [0xA1; 32], index: 7 }];
    no_change.change = None;
    no_change.nonce = [0; 32];
    let mut conditioned = base.clone();
    conditioned.envelope.reference_height = 3;
    conditioned.envelope.reference_block = block_hash(3);
    conditioned.envelope.preconditions = vec![Precondition::TreasuryHead { treasury: [0x7e; 32], generation: 2, address: [0x7f; 32] }];
    conditioned.principal = 7 * MINIMUM_ATOMS;
    conditioned.node_generation = 3;
    let mut widest = base.clone();
    widest.inputs = (0..bc::MAX_INPUTS as u32).map(|i| OutPoint { transaction: [0xB0; 32], index: i }).collect();
    vec![("one_input_with_change", base), ("three_inputs_no_change_zero_nonce", no_change), ("older_reference_with_precondition", conditioned), ("maximum_128_inputs", widest)]
}
/// Unsigned layout writer WITHOUT validation, for refused encodings.
fn raw_unsigned(u: &UnsignedBondCreate, network: u32, kind: u8, inputs: &[(Hash, u32)], change: Option<(Hash, u64)>) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(13).unwrap().u8(2).unwrap().u8(kind).unwrap().u32(network).unwrap();
    e.bytes(&u.genesis).unwrap().bytes(&u.fingerprint).unwrap();
    u.envelope.encode(&mut e).unwrap();
    e.bytes(&u.owner).unwrap().bytes(&u.owner_descriptor).unwrap();
    e.array(3).unwrap().bytes(&u.node).unwrap().u64(u.node_generation).unwrap().bytes(&u.nonce).unwrap();
    e.u64(u.principal).unwrap().u64(u.fee).unwrap().array(inputs.len() as u64).unwrap();
    for (t, i) in inputs {
        e.array(2).unwrap().bytes(t).unwrap().u32(*i).unwrap();
    }
    match change {
        Some((o, n)) => {
            e.array(2).unwrap().bytes(&o).unwrap().u64(n).unwrap();
        }
        None => {
            e.null().unwrap();
        }
    }
    e.into_writer()
}
/// The deterministic refused encodings (name, rule, unsigned bytes) and their exact errors.
fn invalid_cases() -> Vec<(&'static str, &'static str, Vec<u8>, BondError)> {
    let (_, base) = valid_cases().remove(0);
    let ins: Vec<(Hash, u32)> = base.inputs.iter().map(|p| (p.transaction, p.index)).collect();
    let change = Some((base.owner, CHANGE));
    let with = |edit: &dyn Fn(&mut UnsignedBondCreate)| {
        let mut u = base.clone();
        edit(&mut u);
        u
    };
    let mut cases = vec![
        ("principal_below_100_mut", "V1", raw_unsigned(&with(&|u| u.principal = MINIMUM_ATOMS - 1), NETWORK_ID, 24, &ins, change), BondError::Bounds),
        ("change_to_zero_address", "V1/P3", raw_unsigned(&base, NETWORK_ID, 24, &ins, Some(([0; 32], CHANGE))), BondError::ZeroDestination),
        ("change_of_zero_atoms", "V1", raw_unsigned(&base, NETWORK_ID, 24, &ins, Some((base.owner, 0))), BondError::Bounds),
        ("no_inputs", "V1", raw_unsigned(&base, NETWORK_ID, 24, &[], change), BondError::Bounds),
        ("inputs_not_ascending", "V1", raw_unsigned(&base, NETWORK_ID, 24, &[([9; 32], 0), ([8; 32], 0)], change), BondError::Bounds),
        ("duplicate_input", "V1", raw_unsigned(&base, NETWORK_ID, 24, &[([9; 32], 0), ([9; 32], 0)], change), BondError::Bounds),
        ("node_generation_zero", "V1", raw_unsigned(&with(&|u| u.node_generation = 0), NETWORK_ID, 24, &ins, change), BondError::Bounds),
        ("zero_node", "V1", raw_unsigned(&with(&|u| u.node = [0; 32]), NETWORK_ID, 24, &ins, change), BondError::Bounds),
        ("other_network", "V1", raw_unsigned(&base, NETWORK_ID ^ 1, 24, &ins, change), BondError::Codec),
        ("retired_kind_18_tag", "V1", raw_unsigned(&base, NETWORK_ID, 18, &ins, change), BondError::Codec),
        ("invalid_owner_descriptor", "V1", raw_unsigned(&with(&|u| u.owner_descriptor = vec![0x82, 0x01, 0x02]), NETWORK_ID, 24, &ins, change), BondError::Descriptor),
    ];
    let many: Vec<(Hash, u32)> = (0..=bc::MAX_INPUTS as u32).map(|i| ([0xB0; 32], i)).collect();
    cases.push(("129_inputs", "V1", raw_unsigned(&base, NETWORK_ID, 24, &many, change), BondError::Bounds));
    let good = raw_unsigned(&base, NETWORK_ID, 24, &ins, change);
    let mut trailing = good.clone();
    trailing.push(0);
    cases.push(("trailing_byte", "V1", trailing, BondError::NonCanonical));
    assert_eq!(good[1], 0x02);
    let mut non_minimal = vec![good[0], 0x18, 0x02];
    non_minimal.extend_from_slice(&good[2..]);
    cases.push(("non_minimal_version", "V1", non_minimal, BondError::NonCanonical));
    cases
}
fn vector_document(signed_ops: Option<Vec<Vec<u8>>>) -> serde_json::Value {
    let owner = owner_key();
    let valid: Vec<_> = valid_cases()
        .into_iter()
        .enumerate()
        .map(|(n, (name, u))| {
            let c = u.commitment().unwrap();
            let op = match &signed_ops {
                Some(ops) => ops[n].clone(),
                None => raw(&signed(u.clone(), &owner)),
            };
            serde_json::json!({
                "name": name,
                "unsigned_hex": hex::encode(u.encode().unwrap()),
                "commitment": hex::encode(c),
                "id": hex::encode(u.id().unwrap()),
                "lot_id": hex::encode(u.lot_id()),
                "authorize_payload_hex": hex::encode(bc::authorize_payload(&c)),
                "funding_payload_hex": hex::encode(bc::funding_payload(&c)),
                "signed_len": u.signed_len().unwrap(),
                "op_hex": hex::encode(op),
                "fields": {
                    "first_height": u.envelope.first_height, "last_height": u.envelope.last_height,
                    "reference_height": u.envelope.reference_height, "reference_block": hex::encode(u.envelope.reference_block),
                    "preconditions": u.envelope.preconditions.len(), "owner": hex::encode(u.owner),
                    "node": hex::encode(u.node), "node_generation": u.node_generation, "nonce": hex::encode(u.nonce),
                    "principal": u.principal, "fee": u.fee, "inputs": u.inputs.len(),
                    "change": u.change.as_ref().map(|c| serde_json::json!({"owner": hex::encode(c.owner), "atoms": c.atoms})),
                },
            })
        })
        .collect();
    let invalid: Vec<_> = invalid_cases()
        .into_iter()
        .map(|(name, rule, raw, error)| serde_json::json!({"name": name, "rule": rule, "unsigned_hex": hex::encode(raw), "error": format!("{error:?}")}))
        .collect();
    serde_json::json!({
        "schema": "BUILD8-FUNDED-BOND-CREATE-PUBLIC-V1",
        "status": "PROPOSED-UNFROZEN",
        "synthetic_only": true,
        "production_authorized": false,
        "test_value": true,
        "note": "Public TEST-VALUE vectors of the funded BondCreate (block operation kind 24). The owner key is the public BIP39 phrase 'abandon x23 art'; signatures are randomized (FN-DSA), so readers verify them instead of comparing them. No production key, chain or authority is represented.",
        "design": "qualification/candidate-3/P-LANE-DESIGN-V1.md section 2.2",
        "spec": "spec/HYBRID-BOND-SETTLEMENT-V2.md",
        "generator": "consensus: BUILD8_EXPORT_FUNDED_BOND_CREATE=1 cargo test --offline --locked --test funded_bond_create_v1 export_funded_bond_create_vectors (create_new: refuses to overwrite; delete the file first)",
        "reader": "consensus: cargo test --offline --locked --test funded_bond_create_v1 committed_funded_bond_create_vectors_match_the_codec",
        "layout": "unsigned = [2, 24, network u32, genesis, fingerprint, Envelope, owner, owner_descriptor, [node, node_generation, nonce], principal, fee, [[txid, index]...], null | [destination, atoms]]; op = [2, 24, unsigned bytes, [ed448, fndsa], [ed448, fndsa]]",
        "domains": {
            "commitment": std::str::from_utf8(bc::COMMITMENT_DOMAIN).unwrap(),
            "id": std::str::from_utf8(bc::ID_DOMAIN).unwrap(),
            "authorize_label": std::str::from_utf8(bc::AUTHORIZE_LABEL).unwrap(),
            "funding_label": std::str::from_utf8(bc::FUNDING_LABEL).unwrap(),
            "lot_id": std::str::from_utf8(bc::LOT_ID_DOMAIN).unwrap(),
        },
        "owner_descriptor": hex::encode(desc(&owner, 1)),
        "valid": valid,
        "invalid": invalid,
    })
}
#[test]
fn export_funded_bond_create_vectors() {
    if std::env::var("BUILD8_EXPORT_FUNDED_BOND_CREATE").as_deref() != Ok("1") {
        return;
    }
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(VECTOR_FILE)
        .expect("refuses to overwrite: delete the file first")
        .write_all(&serde_json::to_vec_pretty(&vector_document(None)).unwrap())
        .unwrap();
}
/// Reader: every deterministic field equals the generator's own output, every signed operation
/// decodes to its listed unsigned body, re-encodes exactly and verifies, and every refused
/// encoding is refused with its listed error.
#[test]
fn committed_funded_bond_create_vectors_match_the_codec() {
    let text = std::fs::read_to_string(VECTOR_FILE).unwrap();
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    let ops: Vec<Vec<u8>> = document["valid"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| hex::decode(v["op_hex"].as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(document, vector_document(Some(ops.clone())), "deterministic fields match the generator");
    for (n, (name, u)) in valid_cases().into_iter().enumerate() {
        let op = FundedBondCreate::decode(&ops[n]).unwrap();
        assert_eq!(op.unsigned, u, "{name}");
        assert_eq!(raw(&op), ops[n], "{name}");
        assert_eq!(ops[n].len(), u.signed_len().unwrap(), "{name}");
        op.verify_signatures().unwrap();
    }
    for v in document["invalid"].as_array().unwrap() {
        let bytes = hex::decode(v["unsigned_hex"].as_str().unwrap()).unwrap();
        let error = UnsignedBondCreate::decode(&bytes).expect_err(v["name"].as_str().unwrap());
        assert_eq!(format!("{error:?}"), v["error"].as_str().unwrap(), "{}", v["name"]);
    }
    assert!(document["invalid"].as_array().unwrap().len() >= 14);
}
