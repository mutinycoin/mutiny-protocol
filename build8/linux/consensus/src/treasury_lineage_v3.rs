//! Read-only, store-issued Treasury lineage. Public bytes alone cannot construct
//! this capability. It is a replay-authenticated observation, not signing power,
//! a current external-service guarantee, or a promise the chain cannot advance.
use crate::{Hash, anchors::FinalizedAnchor, execution::State, treasury_v1::Treasury};
use mutiny_crypto_v2::{PublicKey, Role};
use std::collections::BTreeMap;

pub struct CanonicalTreasury {
    anchor: FinalizedAnchor,
    root: Hash,
    treasury: Treasury,
    current: u64,
    descriptors: BTreeMap<u64, Vec<u8>>,
}
impl CanonicalTreasury {
    // Only CanonicalStore calls this AFTER complete canonical replay in its
    // stable read snapshot. No caller State/root pair is a public constructor.
    pub(crate) fn from_replayed_state(anchor: FinalizedAnchor, root: Hash,
                                     state: &State) -> Result<Self, ()> {
        if state.root().map_err(|_| ())? != root { return Err(()); }
        let treasury = state.dividends.treasury().ok_or(())?.clone();
        let authority = treasury.authority();
        let raw = state.wallets.current(authority).ok_or(())?;
        let (key, current) = PublicKey::decode_descriptor(raw).map_err(|_| ())?;
        if key.role != Role::WalletOwner || current == 0 { return Err(()); }
        let mut descriptors = BTreeMap::new();
        for (generation, address) in state.wallets.addresses_of(authority) {
            let raw = state.wallets.registered_descriptor(address).ok_or(())?;
            let (key, actual) = PublicKey::decode_descriptor(raw).map_err(|_| ())?;
            if key.role != Role::WalletOwner || actual != generation || generation == 0
                || generation > current || descriptors.insert(generation, raw.to_vec()).is_some() {
                return Err(());
            }
        }
        // Canonical wallet rotations are consecutive and never discard the old
        // descriptor. Check completeness without iterating an untrusted u64 range.
        if descriptors.len() as u64 != current
            || descriptors.keys().copied().enumerate().any(|(i,g)| g != i as u64 + 1)
            || descriptors.get(&1).map(Vec::as_slice) != Some(treasury.descriptor())
            || descriptors.get(&current).map(Vec::as_slice) != Some(raw) {
            return Err(());
        }
        Ok(Self { anchor, root, treasury, current, descriptors })
    }
    pub fn anchor(&self) -> &FinalizedAnchor { &self.anchor }
    pub fn root(&self) -> Hash { self.root }
    pub fn treasury(&self) -> &Treasury { &self.treasury }
    pub fn current_generation(&self) -> u64 { self.current }
    pub fn descriptor(&self, generation: u64) -> Option<&[u8]> {
        self.descriptors.get(&generation).map(Vec::as_slice)
    }
    pub fn generations(&self) -> impl Iterator<Item=u64> + '_ {
        self.descriptors.keys().copied()
    }
}
