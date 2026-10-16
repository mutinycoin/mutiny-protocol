// Phase 5A test rig: a REAL consensus chain (production assembler, real hybrid certificates,
// canonical store with full replay) that can include NATIVE TRADING OPERATIONS in its blocks.
// Since phase 8 it is an adapter over the shared rig (`support/rig.rs`, which now carries block
// operations itself) keeping the phase-5A API; it no longer includes the consensus rig itself.
// NATIVE, TEST-VALUE: every wallet key is a public deterministic test key; maker keys are fresh
// random Transport keys created by the test (the wallet itself never creates offers, Q7).
//
// Declared by a test file as:
//     #[path = "support/conditional_rig.rs"]
//     mod conditional_rig;
#![allow(dead_code, unused_imports, unused_variables)]

#[path = "rig.rs"]
mod shared_rig;

pub mod chain {
    use super::shared_rig::chain::{Funding, Harness};
    use mutiny_consensus_v8::{
        Hash,
        anchors::FinalizedAnchor,
        execution::State,
        transactions::{Coin, OutPoint, Output},
    };
    use mutiny_wallet_core_v8::{ChainView, HeadInfo};
    use std::collections::BTreeSet;

    /// The wallet under test (the BIP-39 all-"abandon" vector; it also owns the rig's License),
    /// the counterparty (the "legal winner" vector), the TEST-VALUE Treasury key (the all-"zoo"
    /// vector), generation-one addresses and signer identities.
    pub use super::shared_rig::chain::{
        address_of, identity_of, other_key, treasury_wallet_key, wallet_key,
    };

    /// A running test chain whose blocks may carry native trading operations.
    pub struct TradeChain {
        h: Harness,
    }

    impl TradeChain {
        /// A chain with a TEST-VALUE Treasury and the given (outpoint tag, owner, atoms) coins.
        pub fn new(tag: &str, funding: &[(u8, Hash, u64)]) -> Self {
            let funding: Vec<Funding> = funding
                .iter()
                .map(|(point, owner, atoms)| Funding::plain(*point, *owner, *atoms))
                .collect();
            Self {
                h: Harness::with_genesis(tag, 1_200_000, |state, _| {
                    // This counterparty later signs its own claim. Its initial authority
                    // must actually exist in the trusted initial WalletBook; a funded lock
                    // does not register a recipient. This creates no fake later history.
                    state
                        .wallets
                        .register(&other_key().public().descriptor(1).unwrap())
                        .unwrap();
                    for coin in &funding {
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
        pub fn head(&self) -> HeadInfo {
            self.h.head()
        }
        pub fn view<'a>(&'a self, reserved: &'a BTreeSet<OutPoint>) -> ChainView<'a> {
            self.h.view(reserved)
        }

        /// Existing own-Genesis replay source, for explicit hostile host-adapter tests.
        pub fn confirmations(&self) -> impl mutiny_wallet_core_v8::ConfirmationSource + '_ {
            self.h.confirmations()
        }

        pub fn operation_history(
            &self,
            raw: &[u8],
        ) -> mutiny_consensus_v8::evidence_history_v2::History {
            self.h.operation_history(raw)
        }

        /// Build, certify and install the next block carrying `operations`. On a refusal nothing is
        /// installed and the error text is returned.
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

        pub fn finish(self) {
            self.h.finish();
        }
    }
}
