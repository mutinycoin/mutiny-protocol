// wallet-core dividend-claim rig: a REAL consensus chain (production assembler, real hybrid
// certificates, canonical store with full replay, hybrid mempool) whose blocks can carry block
// OPERATIONS (dividend claims, a License DvP). Every operation here is built through the PUBLIC
// consensus API. Since phase 8 it is an adapter over the shared rig (`support/rig.rs`, which now has
// a Genesis hook and carries block operations itself) keeping the phase-3 API; it no longer includes
// the consensus rig itself.
// NATIVE, TEST-VALUE: every key is a public deterministic test key (the maker's Transport key is a
// fresh random key); the Treasury is TEST-VALUE class; nothing here is physical or production
// evidence, and the consensus `dividend-test-fixtures` feature is NOT used: awards are reached by
// stepping blocks to the award epoch.
//
// Owned by phase 3 of the wallet plan. Declared by a test file as:
//     #[path = "support/dividend_chain.rs"]
//     mod dividend_chain;
#![allow(dead_code, unused_imports, unused_variables)]

#[path = "rig.rs"]
mod shared_rig;

pub mod chain {
    use super::shared_rig::chain::{self as rig, Harness};
    use mutiny_consensus_v8::{
        Hash, NETWORK_ID,
        anchors::FinalizedAnchor,
        dividend_claim_v1::{self, ClaimBody, ClaimError, SignedClaim},
        dividend_state_v1::DividendState,
        execution::State,
        hybrid_transaction_v2::Transaction,
        trading_v1 as trading,
        transactions::{Coin, OutPoint, Output},
        transactions_v2::{Input, Transfer},
        wallet_rotation_v1::Rotation,
    };
    use mutiny_crypto_v2::{HybridKey, Role};
    use mutiny_wallet_core_v8::{ChainView, HeadInfo, SignerIdentity};
    use std::collections::BTreeSet;

    /// The confirmation index; a fixture LicenseID (index 0 mines every block; index 1 is the
    /// backup).
    pub use super::shared_rig::chain::{Confirmations, license_id, sign_claim};

    /// The first award epoch (the first block is built at this epoch to process the boundary).
    pub const AWARD: u64 = rig::AWARD_EPOCH;
    /// The claim window of an award, in epochs.
    pub const WINDOW: u64 = rig::CLAIM_WINDOW;
    /// The TEST-VALUE Treasury's genesis balance: the first award reserves half of it, 50,000
    /// atoms for each of the twelve Genesis Licenses.
    pub const TREASURY_ATOMS: u64 = 1_200_000;
    pub const SHARE: u64 = 50_000;

    /// The wallet under test: owner of all twelve fixture Licenses (the all-"abandon" vector).
    pub fn owner() -> HybridKey {
        rig::wallet_key()
    }
    /// Another wallet: the buyer of a License (the "legal winner" vector).
    pub fn buyer() -> HybridKey {
        rig::other_key()
    }
    /// The TEST-VALUE Treasury key (the all-"zoo" vector).
    pub fn treasury() -> HybridKey {
        rig::treasury_wallet_key()
    }
    /// The owner's next key after a rotation: a labelled rehearsal key (public by construction).
    pub fn rotated() -> HybridKey {
        rig::labelled_key("wallet-p3-rotated-owner")
    }
    pub fn address_of(key: &HybridKey, generation: u64) -> Hash {
        rig::address_at(key, generation)
    }
    pub fn descriptor_of(key: &HybridKey, generation: u64) -> Vec<u8> {
        rig::descriptor_of(key, generation)
    }
    pub fn identity_of(key: &HybridKey) -> SignerIdentity {
        rig::identity_of(key)
    }
    pub fn outpoint(tag: u8) -> OutPoint {
        rig::outpoint(tag, 0)
    }

    /// A running test chain.
    pub struct ClaimChain {
        h: Harness,
    }

    impl ClaimChain {
        /// A chain with a TEST-VALUE Treasury holding `TREASURY_ATOMS`, the buyer's wallet
        /// registered, and extra non-coinbase coins `(tag, owner, atoms)` at outpoint `(tag, 0)`.
        pub fn new(tag: &str, funding: &[(u8, Hash, u64)]) -> Self {
            Self::with_statuses(tag, funding, &[])
        }

        /// The same with License status entries at Genesis: suspended until an epoch, or revoked
        /// (`None`). They are written through the public dividend record codec
        /// (`DividendState::from_records`), which accepts them only for a TEST-VALUE Treasury, as
        /// consensus does; no fixture feature is involved.
        pub fn with_statuses(
            tag: &str,
            funding: &[(u8, Hash, u64)],
            statuses: &[(Hash, Option<u64>)],
        ) -> Self {
            Self {
                h: Harness::with_genesis(tag, TREASURY_ATOMS, |state, _| {
                    if !statuses.is_empty() {
                        let mut records = state.dividends.records().unwrap();
                        for (license, until) in statuses {
                            let (kind, until) = match until {
                                Some(until) => (1u8, *until),
                                None => (2u8, 0u64),
                            };
                            let mut e = minicbor::Encoder::new(Vec::new());
                            e.array(5)
                                .unwrap()
                                .u8(2)
                                .unwrap()
                                .u8(61)
                                .unwrap()
                                .bytes(license)
                                .unwrap()
                                .u8(kind)
                                .unwrap()
                                .u64(until)
                                .unwrap();
                            records.insert(
                                mutiny_consensus_v8::license_status_v1::key(license),
                                e.into_writer(),
                            );
                        }
                        state.dividends = DividendState::from_records(&records).unwrap();
                    }
                    state.wallets.register(&descriptor_of(&buyer(), 1)).unwrap();
                    for (coin_tag, owner, atoms) in funding {
                        state.coins.insert(
                            outpoint(*coin_tag),
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
        pub fn height(&self) -> u64 {
            self.h.height()
        }
        pub fn genesis(&self) -> FinalizedAnchor {
            self.h.genesis().clone()
        }
        pub fn anchor(&self) -> FinalizedAnchor {
            self.h.anchor()
        }

        /// The verified head as the wallet core wants it (anchor, head timestamp, t0, state root).
        pub fn head(&self) -> HeadInfo {
            self.h.head()
        }

        pub fn view<'a>(&'a self, reserved: &'a BTreeSet<OutPoint>) -> ChainView<'a> {
            self.h.view(reserved)
        }

        pub fn confirmations(&self) -> Confirmations<'_> {
            self.h.confirmations()
        }

        /// Consensus' own bounded admission of a claim for the next block at `epoch`.
        pub fn admit(&self, raw: &[u8], epoch: u64) -> Result<(), ClaimError> {
            self.h.admit_claim(raw, epoch)
        }

        /// Build, certify and install the next block at `epoch` with these operations through the
        /// production assembler. `Err` means consensus refused the block; nothing was installed.
        pub fn try_step(&mut self, epoch: u64, operations: &[Vec<u8>]) -> Result<State, String> {
            self.h.try_step_at(epoch, operations)
        }

        /// The same, for a block that must be accepted.
        pub fn step(&mut self, epoch: u64, operations: &[Vec<u8>]) -> State {
            self.h.step_at_with(epoch, operations)
        }

        /// Close and reopen the durable canonical store from the same trusted Genesis.
        pub fn restart(self) -> Self {
            Self {
                h: self.h.restart(),
            }
        }

        pub fn finish(self) {
            self.h.finish();
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
            self.h.hand_claim(
                key,
                generation,
                license,
                award,
                amount,
                sequence,
                destination,
            )
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
            self.h
                .claim_body(license, award, amount, sequence, destination)
        }

        /// A funded wallet-authority rotation, `from` (generation one) to `to` (generation two),
        /// built and signed through the public consensus API; its fee is paid by `payer`'s
        /// generation-one coin `fund` of `fund_atoms`, the rest returning to `payer`.
        pub fn rotation(
            &self,
            from: &HybridKey,
            to: &HybridKey,
            payer: &HybridKey,
            fund: OutPoint,
            fund_atoms: u64,
            fee: u64,
        ) -> Transaction {
            use mutiny_consensus_v8::funded_rotation_v2::{UnsignedRotation,PartialRotation,Payer,Slot};
            let sponsored=payer.public()!=from.public();
            let body=UnsignedRotation {
                genesis:self.h.genesis().genesis,fingerprint:self.h.genesis().fingerprint,
                envelope:mutiny_consensus_v8::op_envelope_v1::Envelope::from_head(&self.h.anchor(),10,Vec::new()).unwrap(),
                authority:address_of(from,1),current_descriptor:descriptor_of(from,1),
                proposed_descriptor:descriptor_of(to,2),
                sponsor:sponsored.then(||(address_of(payer,1),descriptor_of(payer,1))),fee,
                inputs:vec![(fund,if sponsored {Payer::Sponsor}else{Payer::RotatingAuthority})],
                outputs:vec![Output {owner:address_of(payer,1),atoms:fund_atoms-fee}],
            };
            let mut partial=PartialRotation::new(body);
            partial.sign(Slot::Authorize,from).unwrap();partial.sign(Slot::Possession,to).unwrap();
            partial.sign(if sponsored {Slot::SponsorFunding}else{Slot::AuthorityFunding},payer).unwrap();
            Transaction::FundedRotation(partial.complete().unwrap())
        }

        /// Admit a signed transaction to the hybrid mempool exactly as a node would.
        pub fn admit_transaction(&mut self, transaction: &Transaction) -> Result<(), String> {
            self.h.admit(transaction)
        }

        /// A License sale by delivery versus payment, fully signed through the public trading API
        /// (seller and buyer, with the seller's current WalletOwner also signing the maker fill),
        /// retaining a finite signed inclusion window from the current canonical head: the
        /// buyer pays `price` from the coin `input` to the seller, with `change` back and `fee`.
        #[allow(clippy::too_many_arguments)]
        pub fn license_dvp(
            &self,
            seller: &HybridKey,
            buyer: &HybridKey,
            license: Hash,
            input: OutPoint,
            price: u64,
            change: u64,
            fee: u64,
        ) -> Vec<u8> {
            let genesis = self.h.genesis();
            let height = self.height() + 1;
            let context = trading::Context {
                network: NETWORK_ID,
                genesis: genesis.genesis,
                fingerprint: genesis.fingerprint,
            };
            let maker = seller;
            let offer = trading::SignedOffer::sign(
                trading::OfferBody {
                    context: context.clone(),
                    maker_descriptor: maker.public().descriptor(1).unwrap(),
                    maker_wallet: address_of(maker,1), destination:address_of(seller,1),
                    condition:None,max_fee:trading::Strikes(fee),
                    nonce: [175; 32],
                    created: height,
                    expiry: height + 9,
                    maker_side: 0,
                    terms: trading::OfferTerms::License {
                        license,
                        generation: 1,
                        price: trading::Strikes(price),
                    },
                },
                &maker,
            )
            .unwrap();
            let mut operation = trading::Operation {
                meta: trading::Meta {
                    context,
                    trade: [176; 32],
                    contract: [177; 32],
                    generation: 1,
                    envelope:mutiny_consensus_v8::op_envelope_v1::Envelope::from_head(&self.h.anchor(),9,vec![
                        mutiny_consensus_v8::op_envelope_v1::entitlement_facts(self.h.state(),license),
                        mutiny_consensus_v8::op_envelope_v1::assignment_facts(self.h.state(),license).unwrap(),
                    ]).unwrap(),
                    fee: trading::Strikes(fee),
                    inputs: vec![trading::native_input_id(&input)],
                },
                action: trading::Action::LicenseDvp {
                    offer: offer.body.id().unwrap(),
                    maker: offer.body.maker().unwrap(),
                    license,
                    license_generation: 1,
                    seller: address_of(seller, 1),
                    buyer: address_of(buyer, 1),
                    price: trading::Strikes(price),
                    payment_destination: address_of(seller, 1),
                    change: trading::Strikes(change),
                },
                approvals: vec![],
                offer_proof: None,
            };
            operation.offer_proof =
                Some(trading::OfferProof::sign(offer, &operation, &maker).unwrap());
            operation.approve(0, seller, 1).unwrap();
            operation.approve(1, buyer, 1).unwrap();
            trading::NativeOperation {
                operation,
                inputs: vec![input],
            }
            .encode()
            .unwrap()
        }
    }
}
