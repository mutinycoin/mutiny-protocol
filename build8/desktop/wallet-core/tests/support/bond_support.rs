// Phase 4 (bonds) test support. NATIVE, TEST-VALUE: public deterministic test keys and the public
// synthetic fixtures already used by the consensus tests; nothing here is physical or production.
//
// Owned by phase 4 of the wallet plan. Three parts:
//  * `flow`: the complete human flow of a HIGH-RISK review (typed destination checks, every
//    acknowledgement AND the typed confirmation phrase). Since phase 8 it is the shared
//    `support/flow.rs`, which types the phrase itself.
//  * `world`: a synthetic chain view over the public canonical-store fixture
//    (`qualification/hybrid-canonical-store-public-v1.json`). Unlike the block rig it keeps the
//    fixture's own node (a deterministic physical, eligible member whose admitted owner is key A),
//    so reviews and golden snapshots are reproducible.
//  * `rigs`: the bond harness over the shared block-driver rig (`support/rig.rs`, which includes
//    the consensus rig READ-ONLY): it puts block OPERATIONS (bond operations) into real certified
//    blocks and executes candidate bodies without installing them. The rig's node key is random
//    per run. Since phase 8 it is an adapter over the shared rig; it no longer includes the
//    consensus rig itself.
//
// Declared by a test file as:
//     #[path = "support/bond_support.rs"]
//     mod bond_support;
#![allow(dead_code, unused_imports, unused_variables)]

#[path = "flow.rs"]
pub mod flow;

#[path = "rig.rs"]
mod shared_rig;

pub mod world {
    use mutiny_consensus_v8::{
        Hash, NETWORK_ID,
        anchors::FinalizedAnchor,
        bonds::{BondLot, LotStatus, MINIMUM_ATOMS},
        bonds_v2::Lot,
        execution::State,
        transactions::{Coin, OutPoint, Output},
    };
    use mutiny_crypto_v2::{HybridKey, Role};
    use mutiny_wallet_core_v8::{ChainView, HeadInfo, SignerIdentity};
    use std::collections::BTreeSet;

    pub const T0: u64 = 1000;

    /// Public TEST-VALUE key A (the all-"abandon" vector): the fixture node's admitted owner.
    pub fn key_a() -> HybridKey {
        HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap()
    }
    /// Public TEST-VALUE key B (the all-"zoo" vector).
    pub fn key_b() -> HybridKey {
        HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner).unwrap()
    }
    /// Public TEST-VALUE key C.
    pub fn key_c() -> HybridKey {
        HybridKey::wallet_restore(
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            Role::WalletOwner,
        )
        .unwrap()
    }
    pub fn address(key: &HybridKey, generation: u64) -> Hash {
        key.public().address_id(generation).unwrap()
    }
    pub fn descriptor(key: &HybridKey, generation: u64) -> Vec<u8> {
        key.public().descriptor(generation).unwrap()
    }
    pub fn identity(key: &HybridKey) -> SignerIdentity {
        SignerIdentity::from_public(key.public(), 1, None).unwrap()
    }

    /// The state and Genesis anchor of the public canonical-store fixture.
    pub fn fixture_state() -> (State, FinalizedAnchor) {
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
        let state = State::from_records(&records, raw(&f["root"]).try_into().unwrap()).unwrap();
        let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
        (state, genesis)
    }

    /// A synthetic verified view with the fixture's physical node, at an arbitrary height.
    #[derive(Clone)]
    pub struct BondWorld {
        pub state: State,
        pub anchor: FinalizedAnchor,
        pub reserved: BTreeSet<OutPoint>,
        pub timestamp: u64,
    }

    impl BondWorld {
        pub fn new(height: u64) -> Self {
            let (mut state, genesis) = fixture_state();
            state.coins.clear();
            assert_eq!(genesis.network, NETWORK_ID);
            Self {
                state,
                anchor: FinalizedAnchor { height, ..genesis },
                reserved: BTreeSet::new(),
                timestamp: T0 + 60 * height + 5,
            }
        }

        /// The fixture's one registry member (physical, eligible, generation 1, owned by key A).
        pub fn node(&self) -> Hash {
            self.state.continuity.as_ref().unwrap().members[0].node
        }
        pub fn lineage(&self) -> Hash {
            self.state.continuity.as_ref().unwrap().members[0].lineage
        }

        pub fn coin(
            &mut self,
            owner: Hash,
            atoms: u64,
            created_height: u64,
            coinbase: bool,
            tag: u8,
            index: u32,
        ) -> OutPoint {
            let point = OutPoint {
                transaction: [tag; 32],
                index,
            };
            self.state.coins.insert(
                point.clone(),
                Coin {
                    output: Output { owner, atoms },
                    created_height,
                    coinbase,
                },
            );
            point
        }

        /// Put a lot of the fixture node into the bond book.
        #[allow(clippy::too_many_arguments)]
        pub fn lot(
            &mut self,
            tag: u8,
            owner: Hash,
            atoms: u64,
            created: u64,
            sequence: u64,
            unbond: Option<u64>,
            settled: Option<u64>,
            status: LotStatus,
        ) -> Hash {
            let id = [tag; 32];
            let evidence = if status == LotStatus::Burned {
                [0xee; 32]
            } else {
                [0; 32]
            };
            self.state.bonds_v2.lots.insert(
                id,
                Lot(BondLot {
                    id,
                    node: self.node(),
                    lineage: self.lineage(),
                    owner,
                    atoms,
                    created_height: created,
                    sequence,
                    unbond_height: unbond,
                    settled_height: settled,
                    status,
                    evidence,
                }),
            );
            id
        }

        pub fn head(&self) -> HeadInfo {
            // A synthetic state need not hash (for example a lot without its reputation history);
            // the core never recomputes the root itself.
            let root = self.state.root().unwrap_or([0x77; 32]);
            HeadInfo::new(self.anchor.clone(), self.timestamp, T0, root).unwrap()
        }

        pub fn view(&self) -> ChainView<'_> {
            ChainView::new(self.head(), &self.state, &self.reserved)
        }

        /// The same state with the verified head at another height (a different block).
        pub fn at(&self, height: u64) -> BondWorld {
            let mut other = self.clone();
            other.anchor.height = height;
            other.anchor.block = [(height % 251) as u8 ^ 0x5a; 32];
            other.timestamp = T0 + 60 * height + 5;
            other
        }

        /// The fixture node as a typical bond request names it.
        pub fn minimum() -> u64 {
            MINIMUM_ATOMS
        }
    }
}

pub mod rigs {
    /// The bond harness: an adapter over the shared rig.
    pub mod chain {
        use super::super::shared_rig::chain::Harness;
        use mutiny_consensus_v8::{
            Hash,
            anchors::FinalizedAnchor,
            execution::State,
            hybrid_transaction_v2::Transaction,
            transactions::{Coin, OutPoint, Output},
        };
        use mutiny_wallet_core_v8::{ChainView, HeadInfo};
        use std::collections::BTreeSet;

        /// The rig's time origin, the wallet and counterparty keys (all-"abandon", "legal
        /// winner"), generation-one addresses, descriptors, signer identities, the confirmation
        /// index, a hand-built withdrawal and a synthetic parent.
        pub use super::super::shared_rig::chain::{
            Confirmations, RIG_T0, address_of, descriptor_of, hand_withdraw, identity_of,
            other_key, synthetic_parent, wallet_key,
        };

        /// A real chain (production assembler, real hybrid certificates, canonical store with full
        /// replay, hybrid mempool) whose blocks can carry bond operations.
        pub struct BondChain {
            h: Harness,
        }

        impl BondChain {
            /// A TEST-VALUE chain (Treasury record of TEST-VALUE class) with extra coins.
            pub fn new(tag: &str, coins: &[(OutPoint, Hash, u64)]) -> Self {
                Self {
                    h: Harness::with_genesis(tag, 1_200_000, |state, _| {
                        for (point, owner, atoms) in coins {
                            state.coins.insert(
                                point.clone(),
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
            /// The rig's one physical member (its node key is random per run).
            pub fn node(&self) -> Hash {
                self.h.node()
            }
            pub fn lineage(&self) -> Hash {
                self.h.lineage()
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

            pub fn pool_reserved(&self) -> BTreeSet<OutPoint> {
                self.h.pool_reserved()
            }

            /// Admit a signed transaction to the hybrid mempool exactly as a node would.
            pub fn admit(&mut self, transaction: &Transaction) -> Result<(), String> {
                self.h.admit(transaction)
            }

            pub fn admit_submission(
                &self,
                pool: &mut mutiny_consensus_v8::submission_pool_v1::SubmissionPool,
                list: u8,
                raw: &[u8],
            ) -> Result<Hash, String> {
                self.h.admit_submission(pool, list, raw)
            }

            pub fn submission_pool(
                &self,
            ) -> mutiny_consensus_v8::submission_pool_v1::SubmissionPool {
                self.h.submission_pool()
            }

            pub fn restart(self) -> Self {
                Self {
                    h: self.h.restart(),
                }
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

            pub fn evidence_directory(&self) -> &std::path::Path {
                self.h.evidence_directory()
            }

            pub fn canonical_rows(&self) -> Vec<(String, Vec<Vec<String>>)> {
                self.h.canonical_rows()
            }

            /// Assemble the next block from the pool and `operations` through the production
            /// assembler, certify it and install it. Nothing changes on an error.
            pub fn try_step(&mut self, operations: &[Vec<u8>]) -> Result<State, String> {
                self.h.try_step_with(operations)
            }

            pub fn step(&mut self, operations: &[Vec<u8>]) -> State {
                self.try_step(operations).expect("block must be accepted")
            }

            /// Run a block body with exactly these transactions and operations through full
            /// consensus execution WITHOUT installing it. `Ok` means consensus accepts that body.
            pub fn execute(
                &self,
                transactions: Vec<Vec<u8>>,
                operations: Vec<Vec<u8>>,
            ) -> Result<State, String> {
                self.h.execute(transactions, operations)
            }

            /// [`Self::execute`] over `state` instead of the chain's own state (for example a copy
            /// with one fact changed). The candidate template still comes from the real chain.
            pub fn execute_on(
                &self,
                state: &State,
                transactions: Vec<Vec<u8>>,
                operations: Vec<Vec<u8>>,
            ) -> Result<State, String> {
                self.h.execute_on(state, transactions, operations)
            }

            pub fn finish(self) {
                self.h.finish();
            }
        }
    }
}
