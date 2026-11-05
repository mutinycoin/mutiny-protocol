//! StateRoot V2. Compressed index nodes are caches; the complete 256-level
//! tree definition and independently authenticated root remain authoritative.
use crate::{Error, Hash, Result, anchors::FinalizedAnchor, blocks::canonical, domain_hash};
use minicbor::{Decoder, Encoder, data::Type};
use std::{collections::BTreeMap, sync::OnceLock};
#[path = "state_tree_index.rs"]
pub mod index;
pub const MAX_RECORD: usize = 256 * 1024;
pub const MAX_RECORDS: usize = 10_000_000;
pub const MAX_PROOF: usize = 288 * 1024;
pub fn branch(left: Hash, right: Hash) -> Hash {
    let mut raw = [0; 64];
    raw[..32].copy_from_slice(&left);
    raw[32..].copy_from_slice(&right);
    domain_hash(b"MUTINY-BUILD8-STATE-BRANCH-V2", &raw)
}
pub fn defaults() -> &'static [Hash; 257] {
    static DEFAULTS: OnceLock<[Hash; 257]> = OnceLock::new();
    DEFAULTS.get_or_init(|| {
        let mut d = [[0; 32]; 257];
        d[256] = domain_hash(b"MUTINY-BUILD8-STATE-EMPTY-V2", &[]);
        for i in (0..256).rev() {
            d[i] = branch(d[i + 1], d[i + 1]);
        }
        d
    })
}
pub fn leaf(key: Hash, record: &[u8]) -> Result<Hash> {
    canonical(record, MAX_RECORD)?;
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u8(2)
        .unwrap()
        .bytes(&key)
        .unwrap()
        .bytes(record)
        .unwrap();
    Ok(domain_hash(
        b"MUTINY-BUILD8-STATE-LEAF-V2",
        &e.into_writer(),
    ))
}
pub fn commitment(count: u64, tree: Hash) -> Result<Hash> {
    if count > MAX_RECORDS as u64 {
        return Err(Error::Capacity);
    }
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u8(2)
        .unwrap()
        .u64(count)
        .unwrap()
        .bytes(&tree)
        .unwrap();
    Ok(domain_hash(b"MUTINY-BUILD8-STATE-V2", &e.into_writer()))
}
fn bit(key: &Hash, depth: usize) -> bool {
    key[depth / 8] & (0x80 >> (depth % 8)) != 0
}
fn shared(a: &Hash, b: &Hash) -> usize {
    for i in 0..32 {
        let x = a[i] ^ b[i];
        if x != 0 {
            return i * 8 + x.leading_zeros() as usize;
        }
    }
    256
}
/// Streaming full-tree reconstruction from strictly increasing keys. Holds only
/// a 256-level left frontier, irrespective of the number or size of records.
pub struct StateRootBuilder {
    left: [Option<Hash>; 256],
    last: Option<Hash>,
    pending: Hash,
    count: u64,
}
impl Default for StateRootBuilder {
    fn default() -> Self {
        Self {
            left: [None; 256],
            last: None,
            pending: [0; 32],
            count: 0,
        }
    }
}
impl StateRootBuilder {
    fn fold(&mut self, key: &Hash, to: usize) {
        for d in (to..256).rev() {
            self.pending = if bit(key, d) {
                branch(
                    self.left[d].take().unwrap_or(defaults()[d + 1]),
                    self.pending,
                )
            } else {
                branch(self.pending, defaults()[d + 1])
            };
        }
    }
    pub fn push(&mut self, key: Hash, record: &[u8]) -> Result<()> {
        if self.count >= MAX_RECORDS as u64 {
            return Err(Error::Capacity);
        }
        if self.last.is_some_and(|last| last >= key) {
            return Err(Error::NonCanonical);
        }
        let hash = leaf(key, record)?; // No partial mutation on invalid input.
        if let Some(last) = self.last {
            let divergence = shared(&last, &key);
            self.fold(&last, divergence + 1);
            self.left[divergence] = Some(self.pending);
        }
        self.pending = hash;
        self.last = Some(key);
        self.count += 1;
        Ok(())
    }
    pub fn finish(mut self) -> Hash {
        if let Some(last) = self.last {
            self.fold(&last, 0);
        } else {
            self.pending = defaults()[0];
        }
        commitment(self.count, self.pending).expect("bounded count")
    }
}
fn lift(mut hash: Hash, key: &Hash, from: usize, to: usize) -> Hash {
    for d in (to..from).rev() {
        hash = if bit(key, d) {
            branch(defaults()[d + 1], hash)
        } else {
            branch(hash, defaults()[d + 1])
        };
    }
    hash
}
/// Independent full construction over strictly sorted unique canonical records.
/// Its recursion uses at most 257 frames; it does not allocate absent tree nodes.
pub fn full_root(records: &[(Hash, Vec<u8>)]) -> Result<Hash> {
    if records.len() > MAX_RECORDS {
        return Err(Error::Capacity);
    }
    let mut prior = None;
    for (key, record) in records {
        if prior.is_some_and(|p| p >= *key) {
            return Err(Error::NonCanonical);
        }
        canonical(record, MAX_RECORD)?;
        prior = Some(*key);
    }
    fn subtree(records: &[(Hash, Vec<u8>)], depth: usize) -> Result<Hash> {
        if records.is_empty() {
            return Ok(defaults()[depth]);
        }
        if records.len() == 1 {
            return Ok(lift(
                leaf(records[0].0, &records[0].1)?,
                &records[0].0,
                256,
                depth,
            ));
        }
        let n = records.partition_point(|(k, _)| !bit(k, depth));
        Ok(branch(
            subtree(&records[..n], depth + 1)?,
            subtree(&records[n..], depth + 1)?,
        ))
    }
    commitment(records.len() as u64, subtree(records, 0)?)
}
struct Node {
    key: Hash,
    depth: usize,
    hash: Hash,
    children: Option<(Box<Node>, Box<Node>, Hash, Hash)>,
}
impl Node {
    fn singleton(key: Hash, hash: Hash) -> Box<Self> {
        Box::new(Self {
            key,
            hash,
            depth: 256,
            children: None,
        })
    }
    fn at(&self, depth: usize) -> Hash {
        lift(self.hash, &self.key, self.depth, depth)
    }
    fn refresh(&mut self, right: bool) {
        let (l, r, lh, rh) = self.children.as_mut().unwrap();
        if right {
            *rh = r.at(self.depth + 1);
        } else {
            *lh = l.at(self.depth + 1);
        }
        self.key = l.key;
        self.hash = branch(*lh, *rh);
    }
    fn put(mut self: Box<Self>, key: Hash, hash: Hash) -> Box<Self> {
        let depth = shared(&self.key, &key).min(self.depth);
        if depth < self.depth {
            let other = Self::singleton(key, hash);
            let (l, r) = if bit(&key, depth) {
                (self, other)
            } else {
                (other, self)
            };
            let lh = l.at(depth + 1);
            let rh = r.at(depth + 1);
            return Box::new(Self {
                key: l.key,
                depth,
                hash: branch(lh, rh),
                children: Some((l, r, lh, rh)),
            });
        }
        if depth == 256 {
            self.hash = hash;
            return self;
        }
        let right = bit(&key, depth);
        let (l, r, lh, rh) = self.children.take().unwrap();
        self.children = Some(if right {
            (l, r.put(key, hash), lh, rh)
        } else {
            (l.put(key, hash), r, lh, rh)
        });
        self.refresh(right);
        self
    }
    fn remove(mut self: Box<Self>, key: &Hash) -> Option<Box<Self>> {
        if self.depth == 256 {
            return None;
        }
        let right = bit(key, self.depth);
        let (l, r, lh, rh) = self.children.take().unwrap();
        self.children = Some(if right {
            match r.remove(key) {
                Some(r) => (l, r, lh, rh),
                None => return Some(l),
            }
        } else {
            match l.remove(key) {
                Some(l) => (l, r, lh, rh),
                None => return Some(r),
            }
        });
        self.refresh(right);
        Some(self)
    }
    fn siblings(&self, key: &Hash, out: &mut BTreeMap<usize, Hash>) {
        let divergence = shared(&self.key, key);
        if divergence < self.depth {
            out.insert(divergence, self.at(divergence + 1));
            return;
        }
        if let Some((l, r, lh, rh)) = &self.children {
            if bit(key, self.depth) {
                out.insert(self.depth, *lh);
                r.siblings(key, out);
            } else {
                out.insert(self.depth, *rh);
                l.siblings(key, out);
            }
        }
    }
}
#[derive(Default)]
pub struct StateTree {
    records: BTreeMap<Hash, Vec<u8>>,
    root: Option<Box<Node>>,
}
impl StateTree {
    pub fn insert(&mut self, key: Hash, record: Vec<u8>) -> Result<()> {
        if self.records.contains_key(&key) {
            return Err(Error::Duplicate);
        }
        if self.records.len() >= MAX_RECORDS {
            return Err(Error::Capacity);
        }
        self.store(key, record)
    }
    pub fn update(&mut self, key: Hash, record: Vec<u8>) -> Result<()> {
        if !self.records.contains_key(&key) {
            return Err(Error::WrongAnchor);
        }
        self.store(key, record)
    }
    fn store(&mut self, key: Hash, record: Vec<u8>) -> Result<()> {
        let hash = leaf(key, &record)?; // Validate before mutation.
        self.root = Some(match self.root.take() {
            None => Node::singleton(key, hash),
            Some(n) => n.put(key, hash),
        });
        self.records.insert(key, record);
        Ok(())
    }
    pub fn remove(&mut self, key: &Hash) -> Result<()> {
        if !self.records.contains_key(key) {
            return Err(Error::WrongAnchor);
        }
        self.root = self.root.take().unwrap().remove(key);
        self.records.remove(key);
        Ok(())
    }
    pub fn root(&self) -> Hash {
        commitment(
            self.records.len() as u64,
            self.root.as_ref().map_or(defaults()[0], |n| n.at(0)),
        )
        .unwrap()
    }
    pub fn records(&self) -> Vec<(Hash, Vec<u8>)> {
        self.records.iter().map(|(k, v)| (*k, v.clone())).collect()
    }
    pub fn iter_records(&self) -> impl Iterator<Item = (&Hash, &[u8])> {
        self.records.iter().map(|(k, v)| (k, v.as_slice()))
    }
    /// Exact compressed-node payload; excludes allocator/BTreeMap/record storage.
    pub fn index_payload_bytes(&self) -> usize {
        self.records.len().saturating_mul(2).saturating_sub(1) * std::mem::size_of::<Node>()
    }
    pub fn proof(&self, context: FinalizedAnchor, key: Hash) -> StateProof {
        let mut at = BTreeMap::new();
        if let Some(n) = &self.root {
            n.siblings(&key, &mut at);
        }
        let mut bitmap = [0; 32];
        let mut siblings = Vec::new();
        for (d, h) in at {
            if h != defaults()[d + 1] {
                bitmap[d / 8] |= 0x80 >> (d % 8);
                siblings.push(h);
            }
        }
        StateProof {
            context,
            count: self.records.len() as u64,
            key,
            record: self.records.get(&key).cloned(),
            bitmap,
            siblings,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateProof {
    pub context: FinalizedAnchor,
    pub count: u64,
    pub key: Hash,
    pub record: Option<Vec<u8>>,
    pub bitmap: Hash,
    pub siblings: Vec<Hash>,
}
impl StateProof {
    fn witness(&self) -> Result<[Hash; 256]> {
        if self.count > MAX_RECORDS as u64
            || self.siblings.len() > 256
            || (self.count == 0 && self.record.is_some())
        {
            return Err(Error::Capacity);
        }
        if let Some(r) = &self.record {
            canonical(r, MAX_RECORD)?;
        }
        let mut at = [[0; 32]; 256];
        let mut index = 0;
        for (d, sibling) in at.iter_mut().enumerate() {
            *sibling = defaults()[d + 1];
            if bit(&self.bitmap, d) {
                let h = *self.siblings.get(index).ok_or(Error::Codec)?;
                if h == *sibling {
                    return Err(Error::NonCanonical);
                }
                *sibling = h;
                index += 1;
            }
        }
        if index != self.siblings.len() {
            return Err(Error::NonCanonical);
        }
        Ok(at)
    }
    /// Caller must independently authenticate BOTH expected context and root, and
    /// supply the requested key. An absence witness can cover multiple empty keys;
    /// the server must not be allowed to substitute the caller's query.
    /// This verifies membership bytes; typed wallet/registry profiles additionally
    /// validate the record's schema and derived canonical key.
    pub fn verify(
        &self,
        expected: &FinalizedAnchor,
        root: Hash,
        expected_key: Hash,
    ) -> Result<Option<&[u8]>> {
        expected.validate_context(expected.genesis, expected.fingerprint)?;
        if &self.context != expected || self.key != expected_key {
            return Err(Error::WrongAnchor);
        }
        let at = self.witness()?;
        let mut hash = match &self.record {
            Some(r) => leaf(self.key, r)?,
            None => defaults()[256],
        };
        for d in (0..256).rev() {
            hash = if bit(&self.key, d) {
                branch(at[d], hash)
            } else {
                branch(hash, at[d])
            };
        }
        if commitment(self.count, hash)? != root {
            return Err(Error::WrongAnchor);
        }
        Ok(self.record.as_deref())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.witness()?;
        let mut e = Encoder::new(Vec::new());
        e.array(8)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&self.context.encode())
            .unwrap()
            .u64(self.count)
            .unwrap()
            .bytes(&self.key)
            .unwrap()
            .bool(self.record.is_some())
            .unwrap();
        if let Some(r) = &self.record {
            e.bytes(r).unwrap();
        } else {
            e.null().unwrap();
        }
        e.bytes(&self.bitmap)
            .unwrap()
            .array(self.siblings.len() as u64)
            .unwrap();
        for h in &self.siblings {
            e.bytes(h).unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_PROOF {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        Self::decode_bounded(raw, MAX_PROOF, MAX_RECORD)
    }
    /// Profiles can reduce limits before canonical parsing or record allocation.
    pub fn decode_bounded(raw: &[u8], max_proof: usize, max_record: usize) -> Result<Self> {
        if max_proof > MAX_PROOF || max_record > MAX_RECORD {
            return Err(Error::Capacity);
        }
        canonical(raw, max_proof)?;
        let mut d = Decoder::new(raw);
        let parse = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("state proof");
            fn h(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
                d.bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("hash width"))
            }
            if d.array()? != Some(8) || d.u8()? != 2 {
                return Err(bad());
            }
            let context = FinalizedAnchor::decode(d.bytes()?).map_err(|_| bad())?;
            let count = d.u64()?;
            let key = h(&mut d)?;
            let present = d.bool()?;
            let record = if d.datatype()? == Type::Null {
                d.null()?;
                None
            } else {
                let r = d.bytes()?;
                if r.len() > max_record {
                    return Err(bad());
                }
                Some(r.to_vec())
            };
            if present != record.is_some() {
                return Err(bad());
            }
            let bitmap = h(&mut d)?;
            let n = d.array()?.ok_or_else(bad)?;
            if n > 256 {
                return Err(bad());
            }
            let mut siblings = Vec::with_capacity(n as usize);
            for _ in 0..n {
                siblings.push(h(&mut d)?);
            }
            Ok(Self {
                context,
                count,
                key,
                record,
                bitmap,
                siblings,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if parse.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(parse)
    }
}
