//! A2 public witness carrier around the exact already-signed V2 admission item.
//! It adds no signature, domain, clock assertion or caller authenticity flag.
//! Only the committed A2 rule permits this carrier; execution verifies the witness
//! at the authenticated finalized-parent timestamp and the original V2 proofs.
use crate::{Error, Result, blocks};
use minicbor::{Decoder, Encoder};

pub const VERSION: u8 = 3;
pub const MAX_SIGNED_BYTES: usize = crate::hardware_rotate_v2::MAX_ROTATION_BYTES;
pub const MAX_OPERATION_BYTES: usize =
    MAX_SIGNED_BYTES + crate::attestation_witness::MAX_WITNESS_BYTES + 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carrier {
    kind: u8,
    signed: Vec<u8>,
    witness: Vec<u8>,
}
impl Carrier {
    /// Structural constructor only. The signed profile commits to the witness;
    /// this method cannot admit or authenticate a node.
    pub fn new(kind: u8, signed: Vec<u8>, witness: Vec<u8>) -> Result<Self> {
        let value = Self {
            kind,
            signed,
            witness,
        };
        value.encode()?;
        Ok(value)
    }
    pub fn kind(&self) -> u8 {
        self.kind
    }
    pub fn signed(&self) -> &[u8] {
        &self.signed
    }
    pub fn witness(&self) -> &[u8] {
        &self.witness
    }
    fn check(&self) -> Result<()> {
        if self.signed.is_empty()
            || self.signed.len() > MAX_SIGNED_BYTES
            || self.witness.is_empty()
            || self.witness.len() > crate::attestation_witness::MAX_WITNESS_BYTES
        {
            return Err(Error::Oversize);
        }
        // No recursive or alternate-version inner envelope. Full V2 codecs keep
        // exact legacy arity, canonical bytes, signatures and nonce semantics.
        let mut d = Decoder::new(&self.signed);
        d.array().map_err(codec)?;
        if d.u8().map_err(codec)? != 2 || d.u8().map_err(codec)? != self.kind {
            return Err(Error::WrongOperation);
        }
        match self.kind {
            15 => {
                crate::join_v2::Join::decode(&self.signed)?;
            }
            16 => {
                crate::hardware_rotate_v2::HardwareRotate::decode(&self.signed)?;
            }
            _ => return Err(Error::WrongOperation),
        }
        crate::attestation_witness::AttestationWitness::decode(&self.witness)?;
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(VERSION)
            .unwrap()
            .u8(self.kind)
            .unwrap()
            .bytes(&self.signed)
            .unwrap()
            .bytes(&self.witness)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_OPERATION_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        blocks::canonical(raw, MAX_OPERATION_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(codec)? != Some(4) || d.u8().map_err(codec)? != VERSION {
            return Err(Error::Codec);
        }
        let kind = d.u8().map_err(codec)?;
        if !matches!(kind, 15 | 16) {
            return Err(Error::WrongOperation);
        }
        let signed = d.bytes().map_err(codec)?;
        if signed.is_empty() || signed.len() > MAX_SIGNED_BYTES {
            return Err(Error::Oversize);
        }
        let witness = d.bytes().map_err(codec)?;
        if witness.is_empty() || witness.len() > crate::attestation_witness::MAX_WITNESS_BYTES {
            return Err(Error::Oversize);
        }
        let value = Self {
            kind,
            signed: signed.to_vec(),
            witness: witness.to_vec(),
        };
        if d.position() != raw.len() || value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}
/// State selection, not a public caller-provided enable switch.
pub(crate) fn item(
    raw: &[u8],
    parameters: Option<&crate::genesis_v2::Parameters>,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let enabled = parameters
        .map(crate::endorsement_revocation_v1::enabled)
        .transpose()?
        .unwrap_or(false);
    let mut d = Decoder::new(raw);
    d.array().map_err(codec)?;
    let version = d.u8().map_err(codec)?;
    match (enabled, version) {
        (true, VERSION) => {
            let carrier = Carrier::decode(raw)?;
            Ok((carrier.signed, Some(carrier.witness)))
        }
        (false, 2) => Ok((raw.to_vec(), None)),
        _ => Err(Error::UnqualifiedPhysical),
    }
}
fn codec(_: minicbor::decode::Error) -> Error {
    Error::Codec
}
