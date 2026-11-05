//! Permanent hybrid equivocation history. Imported records are authenticated
//! checkpoint data, not a source of admission or historical registry trust.
use crate::{
    Error, Hash, Result,
    anchors::FinalizedAnchor,
    continuity_v2::ParentVoter,
    domain_hash,
    equivocation_v2::{Evidence, HistoricalAuthority},
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::PublicKey;
use primitive_types::U256;
use std::collections::BTreeMap;
const MAX_RECORD: usize = 24 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    raw: Vec<u8>,
    id: Hash,
    lineage: Hash,
    generation: u64,
    offense: u64,
    inclusion: u64,
    inclusion_parent: Hash,
    genesis: Hash,
    fingerprint: Hash,
}
impl Settlement {
    /// Historical authority and inclusion anchor must come from independently
    /// authenticated canonical history. Both votes are checked before recording.
    pub fn new(
        evidence: &Evidence,
        inclusion: &FinalizedAnchor,
        history: &HistoricalAuthority<'_>,
    ) -> Result<Self> {
        let verified = evidence.validate(inclusion, history)?;
        let voter = history
            .registry
            .get(&verified.node())
            .ok_or(Error::UnknownSigner)?;
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(53)
            .unwrap()
            .bytes(&verified.evidence_id())
            .unwrap()
            .bytes(&inclusion.encode())
            .unwrap()
            .bytes(&history.parent.encode())
            .unwrap()
            .array(3)
            .unwrap();
        for root in history.roots {
            e.bytes(&root).unwrap();
        }
        e.bytes(&verified.node())
            .unwrap()
            .array(7)
            .unwrap()
            .bytes(&voter.lineage)
            .unwrap()
            .u64(voter.hardware_generation)
            .unwrap()
            .u64(voter.key_generation)
            .unwrap()
            .bytes(&voter.tpm_public)
            .unwrap()
            .bytes(&voter.profile)
            .unwrap()
            .bytes(
                &voter
                    .public
                    .descriptor(voter.key_generation)
                    .map_err(|_| Error::Codec)?,
            )
            .unwrap()
            .bytes(&voter.reputation.to_big_endian())
            .unwrap()
            .bytes(&evidence.encode()?)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_RECORD {
            return Err(Error::Oversize);
        }
        Ok(Self {
            raw,
            id: verified.evidence_id(),
            lineage: verified.lineage(),
            generation: verified.hardware_generation(),
            offense: verified.height(),
            inclusion: inclusion.height.checked_add(1).ok_or(Error::Overflow)?,
            inclusion_parent: inclusion.id(),
            genesis: inclusion.genesis,
            fingerprint: inclusion.fingerprint,
        })
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn lineage(&self) -> Hash {
        self.lineage
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn offense_height(&self) -> u64 {
        self.offense
    }
    pub fn inclusion_height(&self) -> u64 {
        self.inclusion
    }
    pub fn inclusion_parent(&self) -> Hash {
        self.inclusion_parent
    }
    pub fn encode(&self) -> &[u8] {
        &self.raw
    }
    pub fn key(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-EQUIVOCATION-RECORD-KEY-V2", &self.id)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_RECORD)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 9)?;
        if d.u8().map_err(|_| Error::Codec)? != 2 || d.u8().map_err(|_| Error::Codec)? != 53 {
            return Err(Error::Codec);
        }
        let id: Hash = fixed(&mut d)?;
        let inclusion = FinalizedAnchor::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let parent = FinalizedAnchor::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        array(&mut d, 3)?;
        let roots = [fixed(&mut d)?, fixed(&mut d)?, fixed(&mut d)?];
        let node = fixed(&mut d)?;
        array(&mut d, 7)?;
        let lineage = fixed(&mut d)?;
        let hardware_generation = d.u64().map_err(|_| Error::Codec)?;
        let key_generation = d.u64().map_err(|_| Error::Codec)?;
        let tpm_public = fixed(&mut d)?;
        let profile = fixed(&mut d)?;
        let (public, generation) =
            PublicKey::decode_descriptor(d.bytes().map_err(|_| Error::Codec)?)
                .map_err(|_| Error::Codec)?;
        if generation != key_generation {
            return Err(Error::WrongGeneration);
        }
        let reputation = U256::from_big_endian(&fixed::<32>(&mut d)?);
        let evidence = Evidence::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        if d.position() != raw.len() {
            return Err(Error::NonCanonical);
        }
        // A validated positive-weight historical signer necessarily had these
        // flags; the encoding fixes them rather than admitting weaker variants.
        let voter = ParentVoter {
            lineage,
            admitted: true,
            physical: true,
            eligible: true,
            revoked: false,
            hardware_generation,
            key_generation,
            tpm_public,
            profile,
            public,
            reputation,
        };
        let registry = BTreeMap::from([(node, voter)]);
        let value = Self::new(
            &evidence,
            &inclusion,
            &HistoricalAuthority {
                parent: &parent,
                roots,
                registry: &registry,
            },
        )?;
        if value.id != id || value.raw != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Book {
    events: BTreeMap<Hash, Settlement>,
}
impl Book {
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
    pub fn validate_at_parent(&self, parent: &FinalizedAnchor) -> Result<()> {
        parent.validate_context(parent.genesis, parent.fingerprint)?;
        if self.events.values().any(|s| {
            s.inclusion > parent.height
                || s.genesis != parent.genesis
                || s.fingerprint != parent.fingerprint
        }) {
            return Err(Error::WrongAnchor);
        }
        Ok(())
    }
    pub fn revoked(&self, lineage: Hash) -> bool {
        self.events.values().any(|s| s.lineage == lineage)
    }
    pub fn tombstoned(&self, lineage: Hash, generation: u64) -> bool {
        self.events
            .values()
            .any(|s| s.lineage == lineage && s.generation == generation)
    }
    pub fn insert(&mut self, settlement: Settlement) -> Result<()> {
        if self.events.contains_key(&settlement.id) {
            return Err(Error::Duplicate);
        }
        if self.events.len() >= crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        self.events.insert(settlement.id, settlement);
        Ok(())
    }
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        if self.events.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        Ok(self
            .events
            .values()
            .map(|s| (s.key(), s.raw.clone()))
            .collect())
    }
    pub fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        let mut book = Self::default();
        if records.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        for (key, raw) in records {
            let s = Settlement::decode(raw)?;
            if *key != s.key() {
                return Err(Error::WrongAnchor);
            }
            book.insert(s)?;
        }
        Ok(book)
    }
}
pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) && d.u8().ok() == Some(53)
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array().map_err(|_| Error::Codec)? != Some(n) {
        return Err(Error::Codec);
    }
    Ok(())
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()
        .map_err(|_| Error::Codec)?
        .try_into()
        .map_err(|_| Error::Codec)
}
