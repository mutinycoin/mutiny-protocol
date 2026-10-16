//! Exact public witness availability around the unchanged signed recovery record.
//! Structural codecs never grant recovery, time, finality or physical authority.
use crate::{Error, Result, blocks, recovery_authority_v2::Authority, recovery_history_v2::Record};
use minicbor::{Decoder, Encoder};
pub const VERSION: u8 = 3;
pub const TAG: u8 = 58;
pub const MAX_BYTES: usize = crate::state_tree::MAX_RECORD;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carrier {
    signed: Vec<u8>,
    witness: Vec<u8>,
}
impl Carrier {
    pub fn new(signed: Vec<u8>, witness: Vec<u8>, authority: &Authority) -> Result<Self> {
        let carrier = Self { signed, witness };
        carrier.encode(authority)?;
        Ok(carrier)
    }
    pub fn signed(&self) -> &[u8] {
        &self.signed
    }
    pub fn witness(&self) -> &[u8] {
        &self.witness
    }
    pub fn record(&self, authority: &Authority) -> Result<Record> {
        Record::decode(&self.signed, authority)
    }
    pub fn encode(&self, authority: &Authority) -> Result<Vec<u8>> {
        if self.signed.is_empty()
            || self.signed.len() > MAX_BYTES
            || self.witness.is_empty()
            || self.witness.len() > crate::attestation_witness::MAX_WITNESS_BYTES
        {
            return Err(Error::Oversize);
        }
        let prefix = |n: usize| {
            if n < 24 {
                1
            } else if n <= 255 {
                2
            } else if n <= 65535 {
                3
            } else {
                5
            }
        };
        let projected = self
            .signed
            .len()
            .checked_add(self.witness.len())
            .and_then(|n| n.checked_add(4 + prefix(self.signed.len()) + prefix(self.witness.len())))
            .ok_or(Error::Oversize)?;
        if projected > MAX_BYTES {
            return Err(Error::Oversize);
        }
        // Full unchanged signed-record decoding, not an arity-only inner check.
        self.record(authority)?;
        crate::attestation_witness::AttestationWitness::decode(&self.witness)?;
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(VERSION)
            .unwrap()
            .u8(TAG)
            .unwrap()
            .bytes(&self.signed)
            .unwrap()
            .bytes(&self.witness)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8], authority: &Authority) -> Result<Self> {
        blocks::canonical(raw, MAX_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(codec)? != Some(4)
            || d.u8().map_err(codec)? != VERSION
            || d.u8().map_err(codec)? != TAG
        {
            return Err(Error::Codec);
        }
        let signed = d.bytes().map_err(codec)?;
        let witness = d.bytes().map_err(codec)?;
        if signed.is_empty()
            || signed.len() > MAX_BYTES
            || witness.is_empty()
            || witness.len() > crate::attestation_witness::MAX_WITNESS_BYTES
        {
            return Err(Error::Oversize);
        }
        let carrier = Self {
            signed: signed.to_vec(),
            witness: witness.to_vec(),
        };
        if d.position() != raw.len() || carrier.encode(authority)? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(carrier)
    }
}
pub(crate) fn selected(state: &crate::execution::State) -> Result<bool> {
    state
        .protocol_records
        .get(&crate::genesis_v2::parameters_key())
        .map(|raw| crate::genesis_v2::Parameters::decode(raw).map_err(|_| Error::Codec))
        .transpose()?
        .as_ref()
        .map(crate::endorsement_revocation_v1::enabled)
        .transpose()
        .map(|value| value.unwrap_or(false))
}
/// Canonical selection is supplied by authenticated state, never a carrier flag.
pub(crate) fn item(
    raw: &[u8],
    state: &crate::execution::State,
    authority: &Authority,
) -> Result<(Record, Option<Vec<u8>>)> {
    if selected(state)? {
        let carrier = Carrier::decode(raw, authority)?;
        Ok((carrier.record(authority)?, Some(carrier.witness)))
    } else {
        Ok((Record::decode(raw, authority)?, None))
    }
}
fn codec(_: minicbor::decode::Error) -> Error {
    Error::Codec
}
