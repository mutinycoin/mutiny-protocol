// Phase 6 test rig: a REAL consensus chain (production assembler, real hybrid certificates,
// canonical store with full replay, hybrid mempool) whose Genesis state carries a TEST-VALUE
// Genesis Treasury and, optionally, the generation-one records of one trading Treasury, and whose
// blocks may carry native trading operations as well as pool transactions. Since phase 8 it is an
// adapter over the shared rig (`support/rig.rs`, which now has a Genesis hook and carries block
// operations itself) keeping the phase-6 API; it no longer includes the consensus rig itself.
// NATIVE, TEST-VALUE: every wallet key is a public deterministic test key (the BIP-39 vectors or
// public labels); nothing here is physical or production evidence.
//
// Owned by phase 6. Declared by a test file as:
//     #[path = "support/treasury_rig.rs"]
//     mod treasury_rig;
#![allow(dead_code, unused_imports, unused_variables)]

#[path = "rig.rs"]
mod shared_rig;

pub mod chain {
    use super::shared_rig::chain::{self as rig, Harness};
    use mutiny_consensus_v8::{
        Hash, NETWORK_ID,
        anchors::FinalizedAnchor,
        execution::State,
        hybrid_transaction_v2::Transaction,
        trading_v1::{self as tr, Context as TradeContext},
        transactions::{Coin, OutPoint, Output},
        wallet_rotation_v1::Rotation,
    };
    use mutiny_crypto_v2::HybridKey;
    use mutiny_wallet_core_v8::{ChainView, HeadInfo};
    use std::collections::BTreeSet;

    /// The wallet that funds trades (the BIP-39 all-"abandon" vector; registered at Genesis), a
    /// second public TEST-VALUE key (the "legal winner" vector; not registered at Genesis), the
    /// TEST-VALUE Genesis Treasury key (the all-"zoo" vector), labelled public TEST-VALUE keys,
    /// signer identities and the confirmation index.
    pub use super::shared_rig::chain::{
        Confirmations, identity_of, labelled_key, other_key, treasury_wallet_key, wallet_key,
    };

    /// The first award boundary epoch (the shared rig's `P`).
    pub const AWARD_EPOCH: u64 = rig::AWARD_EPOCH;

    pub fn address_of(key: &HybridKey, generation: u64) -> Hash {
        rig::address_at(key, generation)
    }
    pub fn descriptor_of(key: &HybridKey, generation: u64) -> Vec<u8> {
        rig::descriptor_of(key, generation)
    }

    /// A running test chain.
    pub struct TreasuryChain {
        h: Harness,
    }

    impl TreasuryChain {
        /// Genesis: the TEST-VALUE Genesis Treasury (the zoo key) holding `treasury_atoms` at its
        /// generation-one address; when `destination` is given, trading Treasury `trading` with that
        /// generation-one wallet-owner descriptor as its destination; and the given
        /// (outpoint tag, owner, atoms) coins.
        pub fn new(
            tag: &str,
            treasury_atoms: u64,
            trading: Option<(Hash, Vec<u8>)>,
            funding: &[(u8, Hash, u64)],
        ) -> Self {
            Self {
                h: Harness::with_genesis(tag, treasury_atoms, |state, genesis| {
                    for (tag, owner, atoms) in funding {
                        state.coins.insert(
                            rig::outpoint(*tag, 0),
                            Coin {
                                output: Output {
                                    owner: *owner,
                                    atoms: *atoms,
                                },
                                created_height: 0,
                                coinbase: false,
                            },
                        );
                    }
                    if let Some((id, descriptor)) = trading {
                        let context = TradeContext {
                            network: NETWORK_ID,
                            genesis: genesis.genesis,
                            fingerprint: genesis.fingerprint,
                        };
                        for (key, raw) in
                            tr::treasury_genesis_records(&context, id, descriptor).unwrap()
                        {
                            state.protocol_records.insert(key, raw);
                        }
                    }
                }),
            }
        }

        pub fn state(&self) -> &State {
            self.h.state()
        }
        pub fn anchor(&self) -> FinalizedAnchor {
            self.h.anchor()
        }
        pub fn height(&self) -> u64 {
            self.h.height()
        }
        pub fn genesis(&self) -> &FinalizedAnchor {
            self.h.genesis()
        }
        pub fn head(&self) -> HeadInfo {
            self.h.head()
        }
        pub fn view<'a>(&'a self, reserved: &'a BTreeSet<OutPoint>) -> ChainView<'a> {
            self.h.view(reserved)
        }
        pub fn confirmations(&self) -> Confirmations<'_> {
            self.h.confirmations()
        }
        pub fn submission_pool(&self) -> mutiny_consensus_v8::submission_pool_v1::SubmissionPool {
            self.h.submission_pool()
        }
        pub fn admit_submission(
            &self,
            pool: &mut mutiny_consensus_v8::submission_pool_v1::SubmissionPool,
            list: u8,
            raw: &[u8],
        ) -> Result<Hash, String> {
            self.h.admit_submission(pool, list, raw)
        }
        pub fn step_submissions(
            &mut self,
            pool: &mut mutiny_consensus_v8::submission_pool_v1::SubmissionPool,
        ) -> State {
            self.h.step_submissions(pool)
        }
        pub fn verified_operations(
            &self,
            id: Hash,
        ) -> Vec<mutiny_consensus_v8::operation_index_v2::OperationRecord> {
            self.h.verified_operations(id)
        }
        pub fn operation_history(
            &self,
            raw: &[u8],
        ) -> mutiny_consensus_v8::evidence_history_v2::History {
            self.h.operation_history(raw)
        }
        pub fn canonical_rows(&self) -> Vec<(String, Vec<Vec<String>>)> {
            self.h.canonical_rows()
        }
        pub fn evidence_directory(&self) -> &std::path::Path {
            self.h.evidence_directory()
        }
        pub fn restart(self) -> Self {
            Self {
                h: self.h.restart(),
            }
        }

        /// Admit a signed transaction to the hybrid mempool exactly as a node would.
        pub fn admit(&mut self, transaction: &Transaction) -> Result<(), String> {
            self.h.admit(transaction)
        }

        /// Build, certify and install the next block carrying the pool's transactions and
        /// `operations`. On a refusal nothing is installed and the error text is returned.
        pub fn try_step_with(&mut self, operations: &[Vec<u8>]) -> Result<State, String> {
            self.h.try_step_with(operations)
        }
        pub fn step_with(&mut self, operations: &[Vec<u8>]) -> State {
            self.try_step_with(operations)
                .expect("block must be accepted")
        }
        pub fn step(&mut self) -> State {
            self.step_with(&[])
        }
        /// The next block at an explicit epoch (for example the first dividend award boundary).
        pub fn step_at(&mut self, epoch: u64) -> State {
            self.h
                .try_step_at(epoch, &[])
                .expect("block must be accepted")
        }

        /// Run `transactions` as the body of the next block through full consensus execution
        /// without installing anything. `Ok` means consensus would accept that body.
        pub fn execute_as_block(&mut self, transactions: Vec<Vec<u8>>) -> Result<(), String> {
            self.h.execute_as_block(transactions)
        }

        /// A transfer of one generation-`generation` coin of `signer`, signed by hand through the
        /// consensus API, for differential checks.
        pub fn hand_signed_transfer(
            &self,
            signer: &HybridKey,
            generation: u64,
            point: OutPoint,
            fee: u64,
            outputs: &[(Hash, u64)],
        ) -> Transaction {
            self.h
                .hand_signed_transfer_at(signer, generation, point, fee, outputs)
        }

        /// A wallet rotation of `authority` from `current` (at `current_generation`) to `proposed`
        /// (at `current_generation + 1`), signed by hand through the consensus API.
        pub fn hand_rotation(
            &self,
            authority: Hash,
            current: &HybridKey,
            current_generation: u64,
            proposed: &HybridKey,
        ) -> Rotation {
            let genesis = self.h.genesis();
            let mut rotation = Rotation {
                network: NETWORK_ID,
                genesis: genesis.genesis,
                fingerprint: genesis.fingerprint,
                authority,
                current: descriptor_of(current, current_generation),
                proposed: descriptor_of(proposed, current_generation + 1),
                created_height: 1,
                expiry_height: 10_000,
                authorization: rig::unsigned_signature(),
                possession: rig::unsigned_signature(),
            };
            rotation.sign(current, proposed).unwrap();
            rotation
        }

        pub fn finish(self) {
            self.h.finish();
        }
    }
}
