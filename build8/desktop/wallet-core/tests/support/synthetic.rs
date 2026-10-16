// Lightweight synthetic chain state for unit-level wallet tests (no blocks, no store).
// NATIVE, TEST-VALUE: public deterministic test keys only (the BIP-39 test vectors).
//
// Owned by phase 1 of the wallet plan; later phases use it and do not edit it.
#![allow(dead_code)]

use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    execution::State,
    transactions::{Coin, OutPoint, Output},
};
use mutiny_crypto_v2::{HybridKey, Role};
use mutiny_wallet_core_v8::{ChainView, HeadInfo, SignerIdentity};
use std::collections::BTreeSet;

pub const T0: u64 = 1000;

/// Public TEST-VALUE key A: the all-"abandon" BIP-39 vector.
pub fn key_a() -> HybridKey {
    HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).unwrap()
}

/// Public TEST-VALUE key B: the all-"zoo" BIP-39 vector.
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

pub struct World {
    pub state: State,
    pub anchor: FinalizedAnchor,
    pub reserved: BTreeSet<OutPoint>,
    pub timestamp: u64,
}

impl World {
    pub fn new(height: u64) -> Self {
        Self {
            state: State::default(),
            anchor: FinalizedAnchor {
                network: NETWORK_ID,
                genesis: [1; 32],
                fingerprint: [2; 32],
                height,
                block: [3; 32],
            },
            reserved: BTreeSet::new(),
            timestamp: T0 + 60 * height + 5,
        }
    }

    /// Synthetic state with public TEST initial owners, without fabricated chain history.
    /// Use when native current-authority checks require a registered WalletBook.
    pub fn with_wallets(height: u64) -> Self {
        static INITIAL: std::sync::OnceLock<State> = std::sync::OnceLock::new();
        let mut world = Self::new(height);
        world.state = INITIAL
            .get_or_init(|| {
                let mut state = State::default();
                for key in [key_a(), key_b(), key_c()] {
                    state.wallets.register(&descriptor(&key, 1)).unwrap();
                }
                state
            })
            .clone();
        world
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

    pub fn head(&self) -> HeadInfo {
        // A synthetic state need not be consensus-valid (for example a dividend award without Licenses),
        // so it falls back to a fixed placeholder root. The core never recomputes the root itself.
        let root = self.state.root().unwrap_or([0x77; 32]);
        HeadInfo::new(self.anchor.clone(), self.timestamp, T0, root).unwrap()
    }

    pub fn view(&self) -> ChainView<'_> {
        ChainView::new(self.head(), &self.state, &self.reserved)
    }

    /// The same chain one block later (a new head over the same state).
    pub fn advanced(&self) -> World {
        let mut next = World {
            state: self.state.clone(),
            anchor: self.anchor.clone(),
            reserved: self.reserved.clone(),
            timestamp: self.timestamp + 60,
        };
        next.anchor.height += 1;
        next.anchor.block[0] ^= 0xff;
        next
    }
}
