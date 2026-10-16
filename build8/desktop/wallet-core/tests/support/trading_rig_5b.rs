// Phase 5B real-chain rig (owned by phase 5B): a thin wrapper that puts native trading operations
// and dividend claims into REAL blocks (production assembler, real hybrid certificates, canonical
// store with full replay). Since phase 8 it is an adapter over the shared rig (`support/rig.rs`,
// which now carries block operations itself) keeping the phase-5B API; it no longer includes the
// consensus rig itself.
// NATIVE, TEST-VALUE: every key is a public deterministic test key or a random transport key; the
// Treasury is TEST-VALUE class; nothing here is physical or production evidence.
//
// Declared by a test file as:
//     #[path = "support/trading_rig_5b.rs"]
//     mod trading_rig;
#![allow(dead_code, unused_imports, unused_variables)]

#[path = "rig.rs"]
mod shared_rig;

pub mod chain {
    use super::shared_rig::chain::{self as rig, Harness};
    use mutiny_consensus_v8::{
        Hash,
        anchors::FinalizedAnchor,
        execution::State,
        transactions::{Coin, OutPoint, Output},
    };
    use mutiny_crypto_v2::HybridKey;
    use mutiny_wallet_core_v8::{ChainView, HeadInfo};
    use std::collections::BTreeSet;

    /// Epoch of the first block built by [`TradeChain::step`]; the TEST-VALUE Treasury key
    /// (all-"zoo"); generation-one addresses; Genesis License number `index` (0 mines the rig's
    /// blocks, 1 is the backup miner).
    pub use super::shared_rig::chain::{FIRST_EPOCH, address_of, license_id, treasury_wallet_key};

    /// The public TEST-VALUE key that owns every Genesis License of the fixture (all-"abandon").
    pub fn seller_key() -> HybridKey {
        rig::wallet_key()
    }
    /// A second public TEST-VALUE wallet key ("legal winner"), unregistered at Genesis.
    pub fn buyer_key() -> HybridKey {
        rig::other_key()
    }
    pub fn descriptor_of(key: &HybridKey) -> Vec<u8> {
        rig::descriptor_of(key, 1)
    }

    /// A running chain whose blocks may carry native operations.
    pub struct TradeChain {
        h: Harness,
    }

    impl TradeChain {
        /// A chain with a TEST-VALUE Treasury holding `treasury_atoms`, the funding coins
        /// `(tag, owner, atoms)` (outpoint `[tag; 32]:0`, created at Genesis) and the wallets in
        /// `register` registered at generation one.
        pub fn new(
            tag: &str,
            treasury_atoms: u64,
            coins: &[(u8, Hash, u64)],
            register: &[&HybridKey],
        ) -> Self {
            Self {
                h: Harness::with_genesis(tag, treasury_atoms, |state, _| {
                    for (point, owner, atoms) in coins {
                        state.coins.insert(
                            rig::outpoint(*point, 0),
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
                    for key in register {
                        state.wallets.register(&descriptor_of(key)).unwrap();
                    }
                }),
            }
        }

        pub fn state(&self) -> &State {
            self.h.state()
        }
        pub fn height(&self) -> u64 {
            self.h.height()
        }
        pub fn anchor(&self) -> FinalizedAnchor {
            self.h.anchor()
        }
        pub fn genesis(&self) -> &FinalizedAnchor {
            self.h.genesis()
        }
        /// Epoch of the next block this chain builds.
        pub fn next_epoch(&self) -> u64 {
            self.h.next_epoch()
        }

        /// The verified head as the wallet core wants it.
        pub fn head(&self) -> HeadInfo {
            self.h.head()
        }

        pub fn view<'a>(&'a self, reserved: &'a BTreeSet<OutPoint>) -> ChainView<'a> {
            self.h.view(reserved)
        }

        pub fn operation_history(
            &self,
            raw: &[u8],
        ) -> mutiny_consensus_v8::evidence_history_v2::History {
            self.h.operation_history(raw)
        }

        pub fn confirmations(&self) -> impl mutiny_wallet_core_v8::ConfirmationSource + '_ {
            self.h.confirmations()
        }

        pub fn canonical_rows(&self) -> Vec<(String, Vec<Vec<String>>)> {
            self.h.canonical_rows()
        }

        pub fn restart(self) -> Self {
            Self {
                h: self.h.restart(),
            }
        }

        /// Assemble the next block with `ops` through the production assembler WITHOUT installing
        /// it. `Ok` carries the post-block state.
        pub fn prepare(&self, ops: &[Vec<u8>]) -> Result<State, String> {
            self.h.prepare(ops)
        }

        /// Build, certify and install the next block carrying `ops`. Panics if it is refused.
        pub fn step(&mut self, ops: &[Vec<u8>]) -> State {
            self.h.step_with(ops)
        }

        /// The same, returning the refusal; nothing is installed when it fails.
        pub fn try_step(&mut self, ops: &[Vec<u8>]) -> Result<State, String> {
            self.h.try_step_with(ops)
        }

        /// Build the next block at an explicit epoch (for example the first award boundary).
        pub fn step_at(&mut self, epoch: u64, ops: &[Vec<u8>]) -> State {
            self.h.step_at_with(epoch, ops)
        }

        /// Close the store and remove the chain's own test directory.
        pub fn finish(self) {
            self.h.finish();
        }
    }
}
