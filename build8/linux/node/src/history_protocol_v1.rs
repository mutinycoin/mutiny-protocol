//! B1 canonical history fetch plans. These bytes confer no canonical authority.
//! Session admission, sequence ownership and verification of fetched envelopes
//! belong to the service owner; a transport object ID is never a block hash.
use minicbor::{Decoder, Encoder, data::Type};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor};
use mutiny_transport_v2::objects::{ObjectKind, Offer, object_id};

pub const VERSION: u8 = 1;
pub const MAX_REQUEST_BYTES: usize = 145;
pub const MAX_PAGE_BYTES: usize = 16_384;
pub const MAX_ANCHOR_BYTES: usize = 128;
pub const MAX_BLOCKS: u8 = 64;
pub const MAX_CANDIDATE_BYTES: u32 = 4_194_304;
pub const MAX_CANDIDATE_ENTRIES: u8 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryError {
    Encoding,
    NonCanonical,
    Bounds,
    Version,
    Context,
    Correlation,
    Ordering,
}
pub type HistoryResult<T> = Result<T, HistoryError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryRequest {
    pub sequence: u32,
    pub saved_anchor: FinalizedAnchor,
    pub max_blocks: u8,
    pub max_candidate_bytes: u32,
    pub max_candidate_entries: u8,
}
impl HistoryRequest {
    pub fn validate(&self) -> HistoryResult<()> {
        if self.sequence == 0
            || !(1..=MAX_BLOCKS).contains(&self.max_blocks)
            || !(1..=MAX_CANDIDATE_BYTES).contains(&self.max_candidate_bytes)
            || !(1..=MAX_CANDIDATE_ENTRIES).contains(&self.max_candidate_entries)
            || self.saved_anchor.encode().len() > MAX_ANCHOR_BYTES
        {
            return Err(HistoryError::Bounds);
        }
        Ok(())
    }
    pub fn encode(&self) -> HistoryResult<Vec<u8>> {
        self.validate()?;
        let mut e = Encoder::new(Vec::new());
        e.array(6).unwrap().u8(VERSION).unwrap()
            .u32(self.sequence).unwrap().bytes(&self.saved_anchor.encode()).unwrap()
            .u8(self.max_blocks).unwrap().u32(self.max_candidate_bytes).unwrap()
            .u8(self.max_candidate_entries).unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_REQUEST_BYTES { return Err(HistoryError::Bounds); }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> HistoryResult<Self> {
        if raw.is_empty() || raw.len() > MAX_REQUEST_BYTES { return Err(HistoryError::Bounds); }
        let mut d = Decoder::new(raw);
        array(&mut d, 6)?;
        version(&mut d)?;
        let value = Self {
            sequence: d.u32().map_err(encoding)?,
            saved_anchor: anchor(&mut d)?,
            max_blocks: d.u8().map_err(encoding)?,
            max_candidate_bytes: d.u32().map_err(encoding)?,
            max_candidate_entries: d.u8().map_err(encoding)?,
        };
        value.validate()?;
        if d.position() != raw.len() || value.encode()? != raw { return Err(HistoryError::NonCanonical); }
        Ok(value)
    }
    /// The exact existing V2 object hash, including kind and encoded length.
    pub fn object_id(&self) -> HistoryResult<Hash> {
        object_id(ObjectKind::HistoryRequestV1, &self.encode()?).map_err(|_| HistoryError::Bounds)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HistoryStatus {
    More = 0,
    AtSnapshotTip = 1,
    Busy = 2,
    CheckpointRejected = 3,
    EvidenceUnavailable = 4,
    NodeUnavailable = 5,
    BoundsRejected = 6,
    Page = 7,
}
impl HistoryStatus {
    fn decode(value: u8) -> HistoryResult<Self> {
        match value {
            0 => Ok(Self::More), 1 => Ok(Self::AtSnapshotTip), 2 => Ok(Self::Busy),
            3 => Ok(Self::CheckpointRejected), 4 => Ok(Self::EvidenceUnavailable),
            5 => Ok(Self::NodeUnavailable), 6 => Ok(Self::BoundsRejected),
            7 => Ok(Self::Page), _ => Err(HistoryError::Encoding),
        }
    }
    pub fn is_success(self) -> bool { matches!(self, Self::More | Self::AtSnapshotTip | Self::Page) }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    pub kind: ObjectKind,
    pub height: u64,
    pub object_id: Hash,
    pub encoded_length: u32,
}
impl HistoryEntry {
    pub fn validate(&self) -> HistoryResult<()> {
        if !matches!(self.kind, ObjectKind::CertifiedBlock | ObjectKind::RecoveryEvidence)
            || self.object_id == [0; 32]
            || self.encoded_length == 0
            || self.encoded_length as usize > self.kind.max_bytes()
        { return Err(HistoryError::Bounds); }
        Ok(())
    }
    /// Correlates an actual HAVE with this plan, without claiming its semantics.
    pub fn matches_offer(&self, offer: &Offer) -> bool {
        self.kind == offer.kind && self.object_id == offer.id
            && self.encoded_length as usize == offer.length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryPage {
    pub request_object_id: Hash,
    pub status: HistoryStatus,
    pub from_anchor: FinalizedAnchor,
    pub offered_through_anchor: Option<FinalizedAnchor>,
    pub observed_tip_anchor: Option<FinalizedAnchor>,
    pub entries: Vec<HistoryEntry>,
}
impl HistoryPage {
    /// Validates the fetch plan only. The fetched last certificate's FULL anchor
    /// must independently equal offered_through_anchor before accepting a page.
    pub fn validate(&self) -> HistoryResult<()> {
        if self.request_object_id == [0; 32]
            || self.entries.len() > MAX_CANDIDATE_ENTRIES as usize
            || self.from_anchor.encode().len() > MAX_ANCHOR_BYTES
        { return Err(HistoryError::Bounds); }
        if !self.status.is_success() {
            if self.offered_through_anchor.is_some() || self.observed_tip_anchor.is_some()
                || !self.entries.is_empty() { return Err(HistoryError::Ordering); }
            return Ok(());
        }
        let through = self.offered_through_anchor.as_ref().ok_or(HistoryError::Ordering)?;
        let tip = self.observed_tip_anchor.as_ref().ok_or(HistoryError::Ordering)?;
        for a in [through, tip] {
            if a.encode().len() > MAX_ANCHOR_BYTES { return Err(HistoryError::Bounds); }
            if !same_context(&self.from_anchor, a) { return Err(HistoryError::Context); }
        }
        if self.status == HistoryStatus::AtSnapshotTip {
            if !self.entries.is_empty() || self.from_anchor != *through || through != tip {
                return Err(HistoryError::Ordering);
            }
            return Ok(());
        }
        if self.entries.is_empty() || through.height <= self.from_anchor.height
            || (self.status == HistoryStatus::More && through.height >= tip.height)
            || (self.status == HistoryStatus::Page && through != tip)
        { return Err(HistoryError::Ordering); }
        let mut parent = self.from_anchor.height;
        let mut recovery = false;
        let mut bytes = 0u32;
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            if self.entries[..index].iter().any(|old| old.object_id == entry.object_id) {
                return Err(HistoryError::Ordering);
            }
            bytes = bytes.checked_add(entry.encoded_length).ok_or(HistoryError::Bounds)?;
            if bytes > MAX_CANDIDATE_BYTES { return Err(HistoryError::Bounds); }
            if entry.kind == ObjectKind::RecoveryEvidence {
                if recovery || entry.height != parent { return Err(HistoryError::Ordering); }
                recovery = true;
            } else {
                let next = parent.checked_add(1).ok_or(HistoryError::Ordering)?;
                if entry.height != next { return Err(HistoryError::Ordering); }
                parent = next;
                recovery = false;
            }
        }
        if recovery || parent != through.height { return Err(HistoryError::Ordering); }
        Ok(())
    }
    pub fn validate_for(&self, request: &HistoryRequest) -> HistoryResult<()> {
        request.validate()?;
        self.validate()?;
        if self.request_object_id != request.object_id()? || self.from_anchor != request.saved_anchor {
            return Err(HistoryError::Correlation);
        }
        if self.entries.len() > request.max_candidate_entries as usize
            || self.entries.iter().filter(|e| e.kind == ObjectKind::CertifiedBlock).count()
                > request.max_blocks as usize
            || self.entries.iter().map(|e| u64::from(e.encoded_length)).sum::<u64>()
                > u64::from(request.max_candidate_bytes)
        { return Err(HistoryError::Bounds); }
        Ok(())
    }
    pub fn encode(&self) -> HistoryResult<Vec<u8>> {
        self.validate()?;
        let mut e = Encoder::new(Vec::new());
        e.array(7).unwrap().u8(VERSION).unwrap().bytes(&self.request_object_id).unwrap()
            .u8(self.status as u8).unwrap().bytes(&self.from_anchor.encode()).unwrap();
        encode_optional_anchor(&mut e, self.offered_through_anchor.as_ref());
        encode_optional_anchor(&mut e, self.observed_tip_anchor.as_ref());
        e.array(self.entries.len() as u64).unwrap();
        for entry in &self.entries {
            e.array(4).unwrap().u8(entry.kind as u8).unwrap().u64(entry.height).unwrap()
                .bytes(&entry.object_id).unwrap().u32(entry.encoded_length).unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_PAGE_BYTES { return Err(HistoryError::Bounds); }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> HistoryResult<Self> {
        if raw.is_empty() || raw.len() > MAX_PAGE_BYTES { return Err(HistoryError::Bounds); }
        let mut d = Decoder::new(raw);
        array(&mut d, 7)?;
        version(&mut d)?;
        let request_object_id = hash(&mut d)?;
        let status = HistoryStatus::decode(d.u8().map_err(encoding)?)?;
        let from_anchor = anchor(&mut d)?;
        let offered_through_anchor = optional_anchor(&mut d)?;
        let observed_tip_anchor = optional_anchor(&mut d)?;
        let count = d.array().map_err(encoding)?.ok_or(HistoryError::Encoding)?;
        // Read/count-check before allocating, even when the input is only16KiB.
        if count > u64::from(MAX_CANDIDATE_ENTRIES) { return Err(HistoryError::Bounds); }
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            array(&mut d, 4)?;
            let kind = match d.u8().map_err(encoding)? {
                3 => ObjectKind::CertifiedBlock, 7 => ObjectKind::RecoveryEvidence,
                _ => return Err(HistoryError::Encoding),
            };
            let entry = HistoryEntry { kind, height: d.u64().map_err(encoding)?,
                object_id: hash(&mut d)?, encoded_length: d.u32().map_err(encoding)? };
            entry.validate()?;
            entries.push(entry);
        }
        let value = Self { request_object_id, status, from_anchor,
            offered_through_anchor, observed_tip_anchor, entries };
        value.validate()?;
        if d.position() != raw.len() || value.encode()? != raw { return Err(HistoryError::NonCanonical); }
        Ok(value)
    }
    pub fn object_id(&self) -> HistoryResult<Hash> {
        object_id(ObjectKind::HistoryPageV1, &self.encode()?).map_err(|_| HistoryError::Bounds)
    }
}

fn same_context(a: &FinalizedAnchor, b: &FinalizedAnchor) -> bool {
    (a.network, a.genesis, a.fingerprint) == (b.network, b.genesis, b.fingerprint)
}
fn encoding(_: minicbor::decode::Error) -> HistoryError { HistoryError::Encoding }
fn array(d: &mut Decoder<'_>, count: u64) -> HistoryResult<()> {
    if d.array().map_err(encoding)? != Some(count) { return Err(HistoryError::Encoding); }
    Ok(())
}
fn version(d: &mut Decoder<'_>) -> HistoryResult<()> {
    if d.u8().map_err(encoding)? != VERSION { return Err(HistoryError::Version); }
    Ok(())
}
fn hash(d: &mut Decoder<'_>) -> HistoryResult<Hash> {
    d.bytes().map_err(encoding)?.try_into().map_err(|_| HistoryError::Encoding)
}
fn anchor(d: &mut Decoder<'_>) -> HistoryResult<FinalizedAnchor> {
    let bytes = d.bytes().map_err(encoding)?;
    if bytes.len() > MAX_ANCHOR_BYTES { return Err(HistoryError::Bounds); }
    FinalizedAnchor::decode(bytes).map_err(|_| HistoryError::NonCanonical)
}
fn optional_anchor(d: &mut Decoder<'_>) -> HistoryResult<Option<FinalizedAnchor>> {
    if d.datatype().map_err(encoding)? == Type::Null {
        d.null().map_err(encoding)?;
        Ok(None)
    } else { anchor(d).map(Some) }
}
fn encode_optional_anchor(e: &mut Encoder<Vec<u8>>, a: Option<&FinalizedAnchor>) {
    match a { Some(a) => { e.bytes(&a.encode()).unwrap(); }, None => { e.null().unwrap(); } }
}

#[cfg(test)]
#[path = "history_protocol_v1_tests.rs"]
mod tests;
