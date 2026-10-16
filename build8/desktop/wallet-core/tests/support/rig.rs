// wallet-core test rig: a REAL consensus chain (production assembler, real hybrid certificates,
// canonical store with full replay, hybrid mempool) built by reusing the consensus block-driver rig
// READ-ONLY, plus a thin `Harness` that exposes only what the wallet tests need.
// NATIVE, TEST-VALUE: every key is a public deterministic test key; the Treasury is TEST-VALUE
// class; nothing here is physical or production evidence.
//
// Owned by phase 1 of the wallet plan. Phase 8 consolidated into it what later phases had copied
// (each phase included the consensus rig again because the phase-1 `Harness` could not carry block
// operations): a Genesis hook (`Harness::with_genesis`), blocks carrying native OPERATIONS
// (`step_with`, `try_step_with`, `step_at_with`, `try_step_at`), assembling without installing
// (`prepare`), executing a candidate body over any state (`execute`, `execute_on`), reopening the
// durable store (`restart`), transfers at any key generation, claims and a bond withdrawal built by
// hand, the rig's node and a synthetic parent (`synthetic_parent`). The phase support files
// (`dividend_chain.rs`, `conditional_rig.rs`, `trading_rig_5b.rs`, `treasury_rig.rs` and the `rigs`
// part of `bond_support.rs`) are adapters over this file that keep their own APIs; only this file
// includes the consensus rig.
//
// Declared by a test file as:
//     #[path = "support/rig.rs"]
//     mod rig;
// and by a support file (a path relative to that file) as:
//     #[path = "rig.rs"]
//     mod shared_rig;
// The include! paths below are relative to THIS file, so they resolve from any test.
#![allow(dead_code, unused_imports, unused_variables)]

/// Public synthetic License/enrollment fixtures (identical to consensus/tests/support/license_v2.rs).
#[allow(clippy::all)]
pub mod licenses {
    include!("../../../desktop/src/wallet_host_fixture_licenses.rs");
}

/// Public software TPM test helpers (no physical device access).
#[allow(clippy::all)]
pub mod tpm {
    include!("../../../desktop/src/wallet_host_fixture_tpm.rs");
}

/// The consensus block-driver rig, included verbatim (`consensus/tests/support/dividend_rig.rs`),
/// followed by the wrapper API the wallet tests use.
#[allow(clippy::all)]
pub mod chain {
    use super::{licenses, tpm};
    include!("../../../consensus/tests/support/dividend_rig.rs");

    use mutiny_wallet_core_v8::{ChainView, ConfirmationSource, HeadInfo, SignerIdentity};
    use std::collections::BTreeSet;

    /// Epoch of the first block built by [`Harness::step`].
    pub const FIRST_EPOCH: u64 = 1;
    /// The first dividend award boundary (consensus `AWARD_PERIOD_EPOCHS`).
    pub const AWARD_EPOCH: u64 = P;
    /// The claim window of an award, in epochs (consensus `CLAIM_WINDOW_EPOCHS`).
    pub const CLAIM_WINDOW: u64 = W;
    /// The rig's time origin: the block of epoch `e` carries the timestamp `RIG_T0 + 60 * e + 5`.
    pub const RIG_T0: u64 = T0;

    /// Public TEST-VALUE key of the wallet under test (the BIP-39 all-"abandon" vector).
    pub fn wallet_key() -> HybridKey {
        owner_key()
    }
    /// A second public TEST-VALUE key (a different wallet, a payment recipient).
    pub fn other_key() -> HybridKey {
        second_key()
    }
    /// The TEST-VALUE Treasury key (the BIP-39 all-"zoo" vector).
    pub fn treasury_wallet_key() -> HybridKey {
        treasury_key()
    }
    /// A public TEST-VALUE key derived from a public label (labelled-seed mode: public by
    /// construction).
    pub fn labelled_key(label: &str) -> HybridKey {
        let phrase = mutiny_crypto_v2::rehearsal_keys_v1::label_phrase(label).unwrap();
        HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
    }
    /// Generation-one AddressID of a key.
    pub fn address_of(key: &HybridKey) -> Hash {
        addr(key, 1)
    }
    /// AddressID of a key at `generation`.
    pub fn address_at(key: &HybridKey, generation: u64) -> Hash {
        addr(key, generation)
    }
    pub fn descriptor_of(key: &HybridKey, generation: u64) -> Vec<u8> {
        desc(key, generation)
    }
    pub fn identity_of(key: &HybridKey) -> SignerIdentity {
        SignerIdentity::from_public(key.public(), 1, None).unwrap()
    }
    pub fn outpoint(tag: u8, index: u32) -> OutPoint {
        OutPoint {
            transaction: [tag; 32],
            index,
        }
    }
    /// Genesis License number `index` of the fixture (0 mines the rig's blocks, 1 is the backup).
    pub fn license_id(index: u64) -> Hash {
        license(index)
    }
    /// The all-zero signature halves a consensus object carries before it is signed.
    pub fn unsigned_signature() -> HybridSignature {
        empty()
    }

    /// Sign a dividend claim body by hand through the public consensus API.
    pub fn sign_claim(body: ClaimBody, key: &HybridKey, generation: u64) -> Vec<u8> {
        SignedClaim::sign(body, desc(key, generation), key)
            .unwrap()
            .encode()
    }

    /// A bond withdrawal of `lot` (with `sequence`) by the generation-one `key` for `owner`, built
    /// and signed by hand through the public consensus API for the block at `height` after
    /// `parent` (the differential oracle for the wallet's own builder).
    pub fn hand_withdraw(
        key: &HybridKey,
        owner: Hash,
        lot: Hash,
        sequence: u64,
        height: u64,
        parent: &FinalizedAnchor,
    ) -> mutiny_consensus_v8::bond_ops_v2::Operation {
        let mut op = mutiny_consensus_v8::bond_ops_v2::Operation {
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                first_height: height,
                last_height: height,
                reference_height: parent.height,
                reference_block: parent.block,
                preconditions: Vec::new(),
            },
            owner,
            authorizer: desc(key, 1),
            action: mutiny_consensus_v8::bond_ops_v2::Action::Withdraw { lot, sequence },
            signature: empty(),
        };
        op.sign(key).unwrap();
        op
    }

    /// `state` at a SYNTHETIC parent `parent_height` (its accounting moved there, an anchor at that
    /// height with a placeholder block id): how the tests reach a bond withdrawal floor hundreds of
    /// thousands of blocks ahead, which a real chain cannot be advanced to in a test. Returns the
    /// state, the anchor and the state root.
    pub fn synthetic_parent(
        state: &State,
        tip: &FinalizedAnchor,
        parent_height: u64,
    ) -> (State, FinalizedAnchor, Hash) {
        let mut state = state.clone();
        state.accounting.slots.last_height = parent_height;
        state.accounting.slots.period = parent_height / 60;
        let root = state.root().unwrap();
        let anchor = FinalizedAnchor {
            height: parent_height,
            block: [0x77; 32],
            ..tip.clone()
        };
        (state, anchor, root)
    }

    /// A funding coin placed in the genesis state.
    #[derive(Clone)]
    pub struct Funding {
        pub point: OutPoint,
        pub owner: Hash,
        pub atoms: u64,
        pub coinbase: bool,
        pub created_height: u64,
    }

    impl Funding {
        pub fn plain(tag: u8, owner: Hash, atoms: u64) -> Self {
            Self {
                point: outpoint(tag, 0),
                owner,
                atoms,
                coinbase: false,
                created_height: 0,
            }
        }
    }

    fn insert_funding(state: &mut State, funding: &[Funding]) {
        for coin in funding {
            state.coins.insert(
                coin.point.clone(),
                Coin {
                    output: Output {
                        owner: coin.owner,
                        atoms: coin.atoms,
                    },
                    created_height: coin.created_height,
                    coinbase: coin.coinbase,
                },
            );
        }
    }

    pub struct Confirmations<'a>(&'a CanonicalStore);
    impl ConfirmationSource for Confirmations<'_> {
        fn confirmed_height(&self, id: &Hash) -> Option<u64> {
            self.0
                .verified_operation_records(*id)
                .expect("own Genesis replay and exact index equality")
                .first()
                .map(|record| record.height)
        }
        fn command_outcome(
            &self,
            id: &Hash,
        ) -> Option<(u64, mutiny_consensus_v8::bond_ops_v2::CommandOutcome)> {
            self.0
                .verified_operation_records(*id)
                .expect("own canonical command replay")
                .iter()
                .find_map(|record| {
                    record
                        .command_outcome()
                        .expect("own outcome canonical")
                        .map(|outcome| (record.height, outcome))
                })
        }
    }

    /// A running test chain.
    pub struct Harness {
        rig: Rig,
        next_epoch: u64,
    }

    // Every chain fixture view uses its actual installed store, replayed from its own
    // trusted Genesis. Synthetic World views deliberately provide no such source.
    impl ConfirmationSource for Harness {
        fn confirmed_height(&self, id: &Hash) -> Option<u64> {
            self.confirmations().confirmed_height(id)
        }
        fn command_outcome(
            &self,
            id: &Hash,
        ) -> Option<(u64, mutiny_consensus_v8::bond_ops_v2::CommandOutcome)> {
            self.confirmations().command_outcome(id)
        }
    }

    impl Harness {
        /// A chain with a TEST-VALUE Treasury holding `treasury_atoms` and the given funding coins.
        pub fn new(tag: &str, treasury_atoms: u64, funding: &[Funding]) -> Self {
            Self::with_genesis(tag, treasury_atoms, |state, _| {
                insert_funding(state, funding)
            })
        }

        /// A chain whose Genesis is the TEST-VALUE Treasury fixture (the all-"zoo" key holding
        /// `treasury_atoms` in the coin `0xd1..:0`), edited by `genesis` before anything else:
        /// coins, wallet registrations, protocol records. `genesis` also sees the Genesis anchor
        /// (the network context).
        pub fn with_genesis(
            tag: &str,
            treasury_atoms: u64,
            genesis: impl FnOnce(&mut State, &FinalizedAnchor),
        ) -> Self {
            let mut fixture = fixture_with_treasury(&treasury_key(), treasury_atoms);
            genesis(&mut fixture.state, &fixture.genesis);
            Self {
                rig: Rig::new(fixture, tag),
                next_epoch: FIRST_EPOCH,
            }
        }

        /// A chain with no Treasury record (the chain class is undeclared).
        pub fn without_treasury(tag: &str, funding: &[Funding]) -> Self {
            let mut fixture = fixture();
            fixture.state.coins.clear();
            insert_funding(&mut fixture.state, funding);
            Self {
                rig: Rig::new(fixture, tag),
                next_epoch: FIRST_EPOCH,
            }
        }

        pub fn state(&self) -> &State {
            &self.rig.state
        }
        pub fn anchor(&self) -> FinalizedAnchor {
            self.rig.parent.clone()
        }
        pub fn height(&self) -> u64 {
            self.rig.height()
        }
        pub fn genesis(&self) -> &FinalizedAnchor {
            &self.rig.f.genesis
        }
        /// A fresh connection to the SAME certified store, pinned to its original TEST-only
        /// trusted Genesis. Consumers must not replace finalized state with a new Genesis.
        pub fn reopen_canonical_store(&self) -> CanonicalStore {
            CanonicalStore::open_trusted_genesis(
                &self.rig.base.join("chain.sqlite"),
                &self.rig.f.genesis,
                &self.rig.initial,
                self.rig.initial_root,
                T0,
                [255; 32],
            )
            .unwrap()
        }
        /// Epoch of the next block this chain builds.
        pub fn next_epoch(&self) -> u64 {
            self.next_epoch
        }
        /// The rig's one physical member (its node key is random per run).
        pub fn node(&self) -> Hash {
            self.rig.state.continuity.as_ref().unwrap().members[0].node
        }
        pub fn lineage(&self) -> Hash {
            self.rig.state.continuity.as_ref().unwrap().members[0].lineage
        }

        /// A claim body on this chain, valid for blocks 1 to 10,000.
        pub fn claim_body(
            &self,
            license: Hash,
            award: u64,
            amount: u64,
            sequence: u64,
            destination: Hash,
        ) -> ClaimBody {
            let genesis = &self.rig.f.genesis;
            ClaimBody {
                network: NETWORK_ID,
                genesis: genesis.genesis,
                fingerprint: genesis.fingerprint,
                created_height: 1,
                expiry_height: 10_000,
                award_epoch: award,
                license,
                amount,
                destination,
                sequence,
            }
        }

        /// A claim signed by hand through the public consensus API, valid for blocks 1 to 10,000
        /// (for parity checks against what the wallet builds).
        #[allow(clippy::too_many_arguments)]
        pub fn hand_claim(
            &self,
            key: &HybridKey,
            generation: u64,
            license: Hash,
            award: u64,
            amount: u64,
            sequence: u64,
            destination: Hash,
        ) -> Vec<u8> {
            sign_claim(
                self.claim_body(license, award, amount, sequence, destination),
                key,
                generation,
            )
        }

        /// Consensus' own bounded admission of a claim for the next block at `epoch`.
        pub fn admit_claim(
            &self,
            raw: &[u8],
            epoch: u64,
        ) -> Result<(), mutiny_consensus_v8::dividend_claim_v1::ClaimError> {
            let genesis = &self.rig.f.genesis;
            mutiny_consensus_v8::dividend_claim_v1::admit(
                &self.rig.state,
                raw,
                genesis.genesis,
                genesis.fingerprint,
                self.height() + 1,
                epoch,
            )
        }

        /// The verified head as the wallet core wants it (anchor, head timestamp, t0, state root).
        pub fn head(&self) -> HeadInfo {
            let (head, _) = self.rig.chain.load().expect("canonical head");
            HeadInfo::new(self.rig.parent.clone(), head.timestamp, T0, head.root)
                .expect("valid head")
        }

        pub fn view<'a>(&'a self, reserved: &'a BTreeSet<OutPoint>) -> ChainView<'a> {
            ChainView::new(self.head(), &self.rig.state, reserved).with_confirmations(self)
        }

        /// Exact finalized references for a complete object, resolved only by our own store.
        pub fn operation_history(
            &self,
            raw: &[u8],
        ) -> mutiny_consensus_v8::evidence_history_v2::History {
            self.rig
                .chain
                .submission_context(1, raw)
                .expect("own canonical complete-object reference context")
                .2
        }

        pub fn confirmations(&self) -> Confirmations<'_> {
            Confirmations(&self.rig.chain)
        }

        /// Exact complete-object pool used by production admission and assembly. This is local
        /// consensus admission, not a network delivery claim.
        pub fn submission_pool(&self) -> mutiny_consensus_v8::submission_pool_v1::SubmissionPool {
            let mut pool = mutiny_consensus_v8::submission_pool_v1::SubmissionPool::open(
                &self.rig.base.join("submissions.sqlite"),
                self.rig.f.genesis.genesis,
                self.rig.f.genesis.fingerprint,
                64 * 1024 * 1024,
            )
            .unwrap();
            self.rig
                .chain
                .reconcile_submission_pool(&mut pool, self.next_epoch)
                .unwrap();
            pool
        }

        pub fn admit_submission(
            &self,
            pool: &mut mutiny_consensus_v8::submission_pool_v1::SubmissionPool,
            list: u8,
            raw: &[u8],
        ) -> Result<Hash, String> {
            let (a, s, h) = self
                .rig
                .chain
                .submission_context(list, raw)
                .map_err(|e| format!("{e:?}"))?;
            pool.admit(&a, &s, &h, self.next_epoch, list, raw)
                .map(|(id, _)| id)
                .map_err(|e| format!("{e:?}"))
        }

        pub fn step_submissions(
            &mut self,
            pool: &mut mutiny_consensus_v8::submission_pool_v1::SubmissionPool,
        ) -> State {
            self.rig
                .chain
                .reconcile_submission_pool(pool, self.next_epoch)
                .unwrap();
            let prepared = self
                .rig
                .chain
                .prepare_pending(Preparation {
                    expected_parent: &self.rig.parent,
                    pool,
                    license: self.rig.f.license,
                    worker: self.rig.f.worker,
                    timestamp: at(self.next_epoch),
                    ticket: self.rig.ticket,
                    operations: &[],
                })
                .unwrap();
            let state = self.rig.commit_prepared(prepared);
            self.next_epoch += 1;
            self.rig
                .chain
                .reconcile_submission_pool(pool, self.next_epoch)
                .unwrap();
            state
        }

        pub fn verified_operations(
            &self,
            id: Hash,
        ) -> Vec<mutiny_consensus_v8::operation_index_v2::OperationRecord> {
            self.rig.chain.verified_operation_records(id).unwrap()
        }

        pub fn evidence_directory(&self) -> &std::path::Path {
            &self.rig.base
        }

        /// Non-vacuous exact logical bytes of every canonical SQLite table, including finality,
        /// lifecycle and operation outcomes. Read-only; rows are sorted without trusting indexes.
        pub fn canonical_rows(&self) -> Vec<(String, Vec<Vec<String>>)> {
            use rusqlite::{Connection, OpenFlags, types::ValueRef};
            let db = Connection::open_with_flags(
                self.rig.base.join("chain.sqlite"),
                OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let mut tables = db
                .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
                .unwrap();
            let names = tables
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert!(!names.is_empty());
            names
                .into_iter()
                .map(|name| {
                    let mut q = db
                        .prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))
                        .unwrap();
                    let count = q.column_count();
                    let mut rows = q
                        .query_map([], |row| {
                            (0..count)
                                .map(|i| {
                                    Ok(match row.get_ref(i)? {
                                        ValueRef::Null => "null".into(),
                                        ValueRef::Integer(v) => format!("i:{v}"),
                                        ValueRef::Real(v) => format!("r:{:016x}", v.to_bits()),
                                        ValueRef::Text(v) => format!("t:{}", hex::encode(v)),
                                        ValueRef::Blob(v) => format!("b:{}", hex::encode(v)),
                                    })
                                })
                                .collect::<rusqlite::Result<Vec<_>>>()
                        })
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap();
                    rows.sort();
                    (name, rows)
                })
                .collect()
        }

        /// Inputs reserved by the chain's own transaction pool.
        pub fn pool_reserved(&self) -> BTreeSet<OutPoint> {
            self.rig.pool.reserved_inputs().expect("pool readable")
        }

        /// Admit a signed transaction to the hybrid mempool exactly as a node would.
        pub fn admit(&mut self, transaction: &Transaction) -> Result<(), String> {
            self.rig
                .pool
                .admit(transaction, &self.rig.parent, &self.rig.state)
                .map(|_| ())
                .map_err(|error| format!("{error:?}"))
        }

        /// Build, certify and install the next block from the pool through the production
        /// assembler. Panics if the block is not accepted.
        pub fn step(&mut self) -> State {
            self.step_with(&[])
        }

        /// The same with `operations` (native trading operations, dividend claims, bond
        /// operations) in the block. Panics if the block is not accepted.
        pub fn step_with(&mut self, operations: &[Vec<u8>]) -> State {
            let epoch = self.next_epoch;
            self.next_epoch += 1;
            self.rig.step(epoch, operations)
        }

        /// The same, returning consensus' refusal instead; nothing is installed and the next
        /// epoch does not move when the block is refused.
        pub fn try_step_with(&mut self, operations: &[Vec<u8>]) -> Result<State, String> {
            let state = self.rig.try_step(self.next_epoch, operations)?;
            self.next_epoch += 1;
            Ok(state)
        }

        /// Build the block at an explicit epoch (for example the first award boundary).
        pub fn step_at(&mut self, epoch: u64) -> State {
            self.step_at_with(epoch, &[])
        }

        /// The same with `operations` in the block. Panics if the block is not accepted.
        pub fn step_at_with(&mut self, epoch: u64, operations: &[Vec<u8>]) -> State {
            self.next_epoch = epoch + 1;
            self.rig.step(epoch, operations)
        }

        /// The block at an explicit epoch with `operations`, returning the refusal; on success
        /// the next block follows `epoch`, on a refusal nothing changes.
        pub fn try_step_at(&mut self, epoch: u64, operations: &[Vec<u8>]) -> Result<State, String> {
            let state = self.rig.try_step(epoch, operations)?;
            self.next_epoch = epoch + 1;
            Ok(state)
        }

        fn prepared(
            &self,
            operations: &[Vec<u8>],
        ) -> Result<mutiny_consensus_v8::assembler_v2::Prepared, String> {
            self.rig
                .chain
                .prepare_pending(Preparation {
                    expected_parent: &self.rig.parent,
                    pool: &self.rig.pool,
                    license: self.rig.f.license,
                    worker: self.rig.f.worker,
                    timestamp: at(self.next_epoch),
                    ticket: self.rig.ticket,
                    operations,
                })
                .map_err(|error| format!("{error:?}"))
        }

        /// Assemble the next block from the pool WITHOUT installing it. Returns the transactions
        /// the assembler selected.
        pub fn assemble_only(&mut self) -> Vec<Vec<u8>> {
            let prepared = self.prepared(&[]).expect("assembler accepts the pool");
            prepared.body.transactions.clone()
        }

        /// Assemble the next block from the pool and `operations` through the production
        /// assembler WITHOUT installing it. `Ok` carries the post-block state.
        pub fn prepare(&self, operations: &[Vec<u8>]) -> Result<State, String> {
            self.prepared(operations)
                .map(|prepared| prepared.execution.state)
        }

        /// TEST-only explicit candidate epoch, through the unchanged production
        /// assembler and timestamp rules. This does not install or retime a block.
        pub fn prepare_at_epoch(
            &self,
            epoch: u64,
            operations: &[Vec<u8>],
        ) -> Result<State, String> {
            self.rig
                .chain
                .prepare_pending(Preparation {
                    expected_parent: &self.rig.parent,
                    pool: &self.rig.pool,
                    license: self.rig.f.license,
                    worker: self.rig.f.worker,
                    timestamp: at(epoch),
                    ticket: self.rig.ticket,
                    operations,
                })
                .map(|prepared| prepared.execution.state)
                .map_err(|error| format!("{error:?}"))
        }

        /// Run a block body with exactly these transactions and operations through full
        /// consensus execution over the chain's own state WITHOUT installing it. `Ok` carries the
        /// post-block state.
        pub fn execute(
            &self,
            transactions: Vec<Vec<u8>>,
            operations: Vec<Vec<u8>>,
        ) -> Result<State, String> {
            self.execute_on(&self.rig.state, transactions, operations)
        }

        /// [`Self::execute`] over `state` instead of the chain's own state (for example a copy
        /// with one fact changed). The candidate template still comes from the real chain.
        pub fn execute_on(
            &self,
            state: &State,
            transactions: Vec<Vec<u8>>,
            operations: Vec<Vec<u8>>,
        ) -> Result<State, String> {
            let transaction_fees: u64 = transactions
                .iter()
                .map(|raw| {
                    Transaction::decode(raw)
                        .map(|t| t.fee())
                        .map_err(|e| format!("{e:?}"))
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .sum();
            let fees = transaction_fees
                .checked_add(
                    mutiny_consensus_v8::bond_create_v3::declared_fees(&operations)
                        .map_err(|error| format!("{error:?}"))?,
                )
                .ok_or_else(|| "fee overflow".to_owned())?;
            let prepared = self.prepared(&[])?;
            let (work_parent, _, _) = self
                .rig
                .chain
                .execution_parent(self.rig.height())
                .map_err(|error| format!("{error:?}"))?;
            let mut body = prepared.body.clone();
            body.transactions = transactions;
            body.operations = operations;
            body.fees = fees;
            let mut candidate = prepared.candidate.clone();
            candidate.body_root = body.root().map_err(|error| format!("{error:?}"))?;
            state
                .prepare_candidate_v2(CandidatePreparation {
                    parent: &work_parent,
                    candidate: &candidate,
                    ticket_sequence: self.rig.ticket,
                    body: &body,
                })
                .map(|executed| executed.state)
                .map_err(|error| format!("{error:?}"))
        }

        /// Run `transactions` as the body of the next block through full consensus execution
        /// without installing anything. `Ok` means consensus would accept that body.
        pub fn execute_as_block(&mut self, transactions: Vec<Vec<u8>>) -> Result<(), String> {
            self.execute(transactions, Vec::new()).map(|_| ())
        }

        /// The Treasury's genesis coin.
        pub fn treasury_coin(&self) -> OutPoint {
            outpoint(0xd1, 0)
        }

        /// A transfer built and signed by hand through the consensus API (generation-one key), for
        /// differential checks against what the wallet core builds.
        pub fn hand_signed_transfer(
            &self,
            signer: &HybridKey,
            point: OutPoint,
            fee: u64,
            outputs: &[(Hash, u64)],
        ) -> Transaction {
            self.hand_signed_transfer_at(signer, 1, point, fee, outputs)
        }

        /// The same for a coin of `signer`'s key at `generation`.
        pub fn hand_signed_transfer_at(
            &self,
            signer: &HybridKey,
            generation: u64,
            point: OutPoint,
            fee: u64,
            outputs: &[(Hash, u64)],
        ) -> Transaction {
            transfer(
                &self.rig.f,
                signer,
                generation,
                point,
                fee,
                outputs
                    .iter()
                    .map(|(owner, atoms)| Output {
                        owner: *owner,
                        atoms: *atoms,
                    })
                    .collect(),
            )
        }

        /// Close and reopen the durable canonical store from the same trusted Genesis.
        pub fn restart(self) -> Self {
            Self {
                rig: self.rig.restart(),
                next_epoch: self.next_epoch,
            }
        }

        pub fn finish(self) {
            self.rig.finish();
        }
    }
}
