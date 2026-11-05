//! Canonical Treasury identity record (Stage C). Status: NATIVE logic.
//!
//! The Treasury is an explicit, Genesis-authenticated input: the generation-one public
//! descriptor of the MUT Treasury wallet authority and a class marker. The class marker is part
//! of the authenticated bytes, so a TEST-VALUE Treasury can never validate as production.
//! There is no default and no constructor that invents a descriptor. Later key rotation is the
//! ordinary wallet rotation: it changes the signing authority and the destination address for
//! new offers but never moves value and never changes this record.
use crate::{Error, Hash, Result, domain_hash};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{PublicKey, Role};

const RECORD_VERSION: u8 = 2;
pub(crate) const RECORD_TAG: u8 = 60;
const MAX_RECORD: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    /// A production public descriptor supplied by the Architect at Genesis.
    Production = 1,
    /// TEST-VALUE fixture. Rejected by every production Genesis validation.
    TestValue = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Treasury {
    class: Class,
    descriptor: Vec<u8>,
    authority: Hash,
}

pub fn key() -> Hash {
    domain_hash(b"MUTINY-BUILD8-TREASURY-IDENTITY-STATE-KEY-V1", &[])
}

/// Reserve the typed tag even for malformed bodies so it cannot hide as an opaque record.
pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some()
        && d.u8().ok() == Some(RECORD_VERSION)
        && d.u8().ok() == Some(RECORD_TAG)
}

impl Treasury {
    /// `descriptor` must be a wallet-owner public descriptor at generation one. Its AddressID is
    /// the Treasury wallet authority that all later generations keep.
    pub fn new(class: Class, descriptor: Vec<u8>) -> Result<Self> {
        let (public, generation) = PublicKey::decode_descriptor(&descriptor).map_err(|_| Error::Codec)?;
        if public.role != Role::WalletOwner || generation != 1 {
            return Err(Error::WrongOperation);
        }
        let authority = public.address_id(generation).map_err(|_| Error::Codec)?;
        let value = Self { class, descriptor, authority };
        value.encode()?;
        Ok(value)
    }
    pub fn class(&self) -> Class {
        self.class
    }
    pub fn authority(&self) -> Hash {
        self.authority
    }
    pub fn descriptor(&self) -> &[u8] {
        &self.descriptor
    }
    /// Production Genesis validation: only a production-class descriptor is acceptable.
    pub fn require_production(&self) -> Result<()> {
        if self.class == Class::Production {
            Ok(())
        } else {
            Err(Error::WrongOperation)
        }
    }
    /// Test Genesis: only a TEST-VALUE descriptor is acceptable, never a production one.
    pub fn require_test(&self) -> Result<()> {
        if self.class == Class::TestValue {
            Ok(())
        } else {
            Err(Error::WrongOperation)
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(RECORD_VERSION)
            .unwrap()
            .u8(RECORD_TAG)
            .unwrap()
            .u8(self.class as u8)
            .unwrap()
            .bytes(&self.descriptor)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_RECORD {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_RECORD)?;
        let mut d = Decoder::new(raw);
        let bad = || Error::Codec;
        if d.array().map_err(|_| bad())? != Some(4)
            || d.u8().map_err(|_| bad())? != RECORD_VERSION
            || d.u8().map_err(|_| bad())? != RECORD_TAG
        {
            return Err(bad());
        }
        let class = match d.u8().map_err(|_| bad())? {
            1 => Class::Production,
            2 => Class::TestValue,
            _ => return Err(bad()),
        };
        let descriptor = d.bytes().map_err(|_| bad())?.to_vec();
        if d.position() != raw.len() {
            return Err(bad());
        }
        let value = Self::new(class, descriptor)?;
        if value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}
