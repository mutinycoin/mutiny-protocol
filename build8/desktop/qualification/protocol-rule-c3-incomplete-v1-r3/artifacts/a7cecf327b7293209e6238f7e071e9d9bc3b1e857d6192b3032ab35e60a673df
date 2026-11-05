//! Authenticated wallet authorization state. Old addresses retain their identity
//! while explicit rotation changes their current signing authority.
use crate::{Error, Hash, Result, domain_hash, wallet_rotation_v1::Rotation};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{PublicKey, Role};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WalletBook {
    current: BTreeMap<Hash, Vec<u8>>,
    // Retained public descriptors authenticate exact historical AddressIDs.
    addresses: BTreeMap<Hash, (Hash, Vec<u8>)>,
}
fn descriptor(raw: &[u8]) -> Result<(PublicKey, u64, Hash)> {
    let (p, g) = PublicKey::decode_descriptor(raw).map_err(|_| Error::Codec)?;
    if p.role != Role::WalletOwner {
        return Err(Error::WrongOperation);
    }
    let address = p.address_id(g).map_err(|_| Error::Codec)?;
    Ok((p, g, address))
}
pub fn current_key(id: Hash) -> Hash {
    domain_hash(b"MUTINY-BUILD8-WALLET-AUTHORITY-STATE-V1", &id)
}
pub fn address_key(address: Hash) -> Hash {
    domain_hash(b"MUTINY-BUILD8-WALLET-ADDRESS-STATE-V1", &address)
}
fn record(kind: u8, id: Hash, raw: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .u8(1)
        .unwrap()
        .u8(kind)
        .unwrap()
        .bytes(&id)
        .unwrap()
        .bytes(raw)
        .unwrap();
    e.into_writer()
}
pub(crate) fn parse(raw: &[u8]) -> Result<(u8, Hash, Vec<u8>)> {
    crate::blocks::canonical(raw, 4096)?;
    let mut d = Decoder::new(raw);
    if d.array().map_err(|_| Error::Codec)? != Some(4) || d.u8().map_err(|_| Error::Codec)? != 1 {
        return Err(Error::Codec);
    }
    let kind = d.u8().map_err(|_| Error::Codec)?;
    if !matches!(kind, 30 | 31) {
        return Err(Error::Codec);
    }
    let id = d
        .bytes()
        .map_err(|_| Error::Codec)?
        .try_into()
        .map_err(|_| Error::Codec)?;
    let bytes = d.bytes().map_err(|_| Error::Codec)?.to_vec();
    descriptor(&bytes)?;
    if d.position() != raw.len() || record(kind, id, &bytes) != raw {
        return Err(Error::Codec);
    }
    Ok((kind, id, bytes))
}
pub(crate) fn is_record(_key: Hash, raw: &[u8]) -> bool {
    // Recognize the reserved record type even if its key/descriptor is bad.
    // Malformed typed state must not fall through into opaque protocol records.
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some()
        && d.u8().ok() == Some(1)
        && matches!(d.u8().ok(), Some(30 | 31))
}
impl WalletBook {
    pub(crate) fn public_descriptors(&self) -> impl Iterator<Item = &[u8]> {
        self.addresses
            .values()
            .map(|(_, raw)| raw.as_slice())
            .chain(self.current.values().map(Vec::as_slice))
    }

    pub fn register(&mut self, raw: &[u8]) -> Result<Hash> {
        let (_, generation, id) = descriptor(raw)?;
        if generation != 1 {
            return Err(Error::WrongGeneration);
        }
        if self.addresses.contains_key(&id) || self.current.contains_key(&id) {
            return Err(Error::Duplicate);
        }
        self.capacity(2)?;
        self.current.insert(id, raw.to_vec());
        self.addresses.insert(id, (id, raw.to_vec()));
        Ok(id)
    }
    fn capacity(&self, additional: usize) -> Result<()> {
        if self
            .current
            .len()
            .checked_add(self.addresses.len())
            .and_then(|n| n.checked_add(additional))
            .is_none_or(|n| n > crate::execution::MAX_STATE_RECORDS)
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    /// Every registered address of one wallet authority as (generation, address), ascending.
    /// Used for Treasury backing: historical generations keep their identity after rotation.
    pub(crate) fn addresses_of(&self, authority: Hash) -> Vec<(u64, Hash)> {
        let mut out: Vec<(u64, Hash)> = self
            .addresses
            .iter()
            .filter(|(_, (id, _))| *id == authority)
            .filter_map(|(address, (_, raw))| descriptor(raw).ok().map(|(_, g, _)| (g, *address)))
            .collect();
        out.sort();
        out
    }
    /// Exact immutable descriptor recorded for a registered address, including retired
    /// generations. This is historical identity evidence, not current spending permission.
    pub(crate) fn registered_descriptor(&self, address: Hash) -> Option<&[u8]> {
        self.addresses.get(&address).map(|(_, raw)| raw.as_slice())
    }
    pub fn current(&self, id: Hash) -> Option<&[u8]> {
        self.current.get(&id).map(Vec::as_slice)
    }
    /// RETIRED carrier semantics, kept only as a TEST-VALUE fixture helper and for the Treasury
    /// ceremony's authorized-plan modelling: it applies a standalone `wallet_rotation_v1::Rotation`
    /// (both of its signatures verified) to a caller-owned book. It is NOT a consensus path: no
    /// block can carry a standalone Rotation (Lane P design 3.1), and canonical execution changes a
    /// wallet authority only through the verified funded-rotation bundle (`funded_rotation_v2`),
    /// the only caller of `apply_verified_rotation` in canonical execution.
    pub fn apply(
        &mut self,
        rotation: &Rotation,
        genesis: Hash,
        fingerprint: Hash,
        height: u64,
    ) -> Result<()> {
        let old = self
            .current
            .get(&rotation.authority)
            .ok_or(Error::UnknownSigner)?;
        let verified = rotation.verify(genesis, fingerprint, height, rotation.authority, old)?;
        self.apply_verified_rotation(rotation.authority, &rotation.current, verified.proposed_descriptor())
    }
    /// The state part of a verified rotation (Lane P design 3.7): compare-and-replace of the
    /// authority's current descriptor, the new address record `(address -> (authority, proposed))`
    /// and the capacity check. Crate-private: canonical execution reaches it only from the verified
    /// funded-rotation bundle (`funded_rotation_v2`). It re-checks on its own what keeps `validate`
    /// true: the authority exists and `current` IS its current descriptor (a replay or a second
    /// rotation of the same generation fails), the generation advances by exactly one and the new
    /// address is unregistered. Nothing changes unless every check passes.
    pub(crate) fn apply_verified_rotation(
        &mut self,
        authority: Hash,
        current: &[u8],
        proposed: &[u8],
    ) -> Result<()> {
        let old = self.current.get(&authority).ok_or(Error::UnknownSigner)?;
        if old.as_slice() != current {
            return Err(Error::WrongGeneration);
        }
        let (_, old_generation, _) = descriptor(current)?;
        let (_, new_generation, address) = descriptor(proposed)?;
        if old_generation.checked_add(1) != Some(new_generation) {
            return Err(Error::WrongGeneration);
        }
        if self.addresses.contains_key(&address) {
            return Err(Error::Duplicate);
        }
        self.capacity(1)?;
        // Complete all validation before either canonical map changes.
        self.addresses.insert(address, (authority, proposed.to_vec()));
        self.current.insert(authority, proposed.to_vec());
        Ok(())
    }
    /// The wallet authority an address belongs to: the lineage id of a registered address, or the
    /// address itself when unregistered (generation-one direct ownership). Crate-private (design
    /// 3.5 step 5: a funded rotation's sponsor must be a different wallet authority).
    pub(crate) fn authority_of(&self, address: Hash) -> Hash {
        self.addresses.get(&address).map_or(address, |(id, _)| *id)
    }
    /// Resolve the descriptor permitted to authorize this exact UTXO address.
    /// Unregistered addresses may use generation-one direct ownership only.
    pub fn authorize(&self, address: Hash, raw: &[u8]) -> Result<()> {
        let (_, generation, derived) = descriptor(raw)?;
        if let Some((id, _)) = self.addresses.get(&address) {
            if self.current.get(id).is_none_or(|current| current != raw) {
                return Err(Error::WrongGeneration);
            }
        } else if generation != 1 || derived != address {
            return Err(Error::WrongGeneration);
        }
        Ok(())
    }
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        self.validate()?;
        let mut records = BTreeMap::new();
        for (id, raw) in &self.current {
            if records
                .insert(current_key(*id), record(30, *id, raw))
                .is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        for (address, (id, raw)) in &self.addresses {
            if records
                .insert(address_key(*address), record(31, *id, raw))
                .is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        Ok(records)
    }
    /// Records must come from an independently authenticated StateRoot.
    pub fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        let mut book = Self::default();
        if records.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        for (key, raw) in records {
            if !is_record(*key, raw) {
                return Err(Error::Codec);
            }
            let (kind, id, bytes) = parse(raw)?;
            if kind == 30 {
                if current_key(id) != *key {
                    return Err(Error::WrongAnchor);
                }
                if book.current.insert(id, bytes).is_some() {
                    return Err(Error::Duplicate);
                }
            } else {
                let (_, _, address) = descriptor(&bytes)?;
                if address_key(address) != *key {
                    return Err(Error::WrongAnchor);
                }
                if book.addresses.insert(address, (id, bytes)).is_some() {
                    return Err(Error::Duplicate);
                }
            }
        }
        book.validate()?;
        Ok(book)
    }
    fn validate(&self) -> Result<()> {
        self.capacity(0)?;
        let mut generations: BTreeMap<Hash, BTreeSet<u64>> = BTreeMap::new();
        for (address, (id, raw)) in &self.addresses {
            let (_, generation, derived) = descriptor(raw)?;
            if *address != derived
                || !self.current.contains_key(id)
                || (generation == 1 && id != address)
            {
                return Err(Error::WrongGeneration);
            }
            if !generations.entry(*id).or_default().insert(generation) {
                return Err(Error::Duplicate);
            }
        }
        for (id, raw) in &self.current {
            let (_, generation, address) = descriptor(raw)?;
            if self.addresses.get(&address) != Some(&(*id, raw.clone())) {
                return Err(Error::WrongGeneration);
            }
            let set = generations.get(id).ok_or(Error::WrongGeneration)?;
            if set.len() as u64 != generation
                || set.first() != Some(&1)
                || set.last() != Some(&generation)
            {
                return Err(Error::WrongGeneration);
            }
        }
        Ok(())
    }
}
