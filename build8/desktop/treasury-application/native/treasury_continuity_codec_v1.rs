//! Bounded canonical implementation transport. Not a new Treasury proof or
//! consensus carrier. Authentication and protected latest-state storage remain
//! independent obligations; hashing an unauthenticated message creates no trust.
use super::*;
use minicbor::{Decoder, Encoder};
pub const MAX_REQUEST_BYTES: usize = 8192;
fn invalid<T, E>(r: Result<T, E>) -> Result<T, Error> {
    r.map_err(|_| Error::Invalid)
}
fn scope(e: &mut Encoder<Vec<u8>>, s: &Scope) -> Result<(), Error> {
    if !s.valid() {
        return Err(Error::WrongScope);
    }
    invalid(e.array(7))?;
    invalid(e.u32(s.network))?;
    match s.genesis {
        Some(h) => {
            invalid(e.bytes(&h))?;
        }
        None => {
            invalid(e.null())?;
        }
    }
    for h in [
        s.ceremony_context,
        s.treasury_record,
        s.verifier,
        s.store,
        s.service,
    ] {
        invalid(e.bytes(&h))?;
    }
    Ok(())
}
fn record(e: &mut Encoder<Vec<u8>>, v: &PublicRecord) -> Result<(), Error> {
    if !v.bounded() {
        return Err(Error::Invalid);
    }
    invalid(e.array(5))?;
    invalid(e.u64(v.generation))?;
    invalid(e.bytes(&v.nonce))?;
    invalid(e.bytes(&v.challenge))?;
    invalid(e.bytes(&v.descriptor))?;
    match &v.signature {
        Some(s) => {
            invalid(e.bytes(s))?;
        }
        None => {
            invalid(e.null())?;
        }
    }
    Ok(())
}
fn action(e: &mut Encoder<Vec<u8>>, a: &Action) -> Result<(), Error> {
    match a {
        Action::Reserve(v) => {
            if v.signature.is_some() {
                return Err(Error::Invalid);
            }
            invalid(e.array(2))?;
            invalid(e.u8(0))?;
            record(e, v)?;
        }
        Action::Consume(v) => {
            if v.signature.is_none() {
                return Err(Error::Invalid);
            }
            invalid(e.array(2))?;
            invalid(e.u8(1))?;
            record(e, v)?;
        }
        Action::ConfirmLocal {
            pending_operation,
            exact,
        } => {
            if *pending_operation == [0; 32] {
                return Err(Error::Invalid);
            }
            invalid(e.array(3))?;
            invalid(e.u8(2))?;
            invalid(e.bytes(pending_operation))?;
            record(e, exact)?;
        }
    }
    Ok(())
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<(), Error> {
    if invalid(d.array())? != Some(n) {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn hash(d: &mut Decoder<'_>) -> Result<Hash, Error> {
    invalid(invalid(d.bytes())?.try_into())
}
fn optional_bytes(d: &mut Decoder<'_>, max: usize) -> Result<Option<Vec<u8>>, Error> {
    if invalid(d.datatype())? == minicbor::data::Type::Null {
        invalid(d.null())?;
        return Ok(None);
    }
    let bytes = invalid(d.bytes())?;
    if bytes.len() > max {
        return Err(Error::Invalid);
    }
    Ok(Some(bytes.to_vec()))
}
fn read_scope(d: &mut Decoder<'_>) -> Result<Scope, Error> {
    array(d, 7)?;
    let network = invalid(d.u32())?;
    let genesis = optional_bytes(d, 32)?
        .map(|b| b.try_into().map_err(|_| Error::Invalid))
        .transpose()?;
    let s = Scope {
        network,
        genesis,
        ceremony_context: hash(d)?,
        treasury_record: hash(d)?,
        verifier: hash(d)?,
        store: hash(d)?,
        service: hash(d)?,
    };
    if !s.valid() {
        return Err(Error::WrongScope);
    }
    Ok(s)
}
fn read_record(d: &mut Decoder<'_>) -> Result<PublicRecord, Error> {
    array(d, 5)?;
    let generation = invalid(d.u64())?;
    let nonce = hash(d)?;
    let ch = invalid(d.bytes())?;
    if ch.is_empty() || ch.len() > 512 {
        return Err(Error::Invalid);
    }
    let descriptor = invalid(d.bytes())?;
    if descriptor.is_empty() || descriptor.len() > 2048 {
        return Err(Error::Invalid);
    }
    let v = PublicRecord {
        generation,
        nonce,
        challenge: ch.to_vec(),
        descriptor: descriptor.to_vec(),
        signature: optional_bytes(d, 1394)?,
    };
    if !v.bounded() {
        return Err(Error::Invalid);
    }
    Ok(v)
}
fn read_action(d: &mut Decoder<'_>) -> Result<Action, Error> {
    let n = invalid(d.array())?;
    let tag = invalid(d.u8())?;
    match (n, tag) {
        (Some(2), 0) => {
            let v = read_record(d)?;
            if v.signature.is_some() {
                return Err(Error::Invalid);
            }
            Ok(Action::Reserve(v))
        }
        (Some(2), 1) => {
            let v = read_record(d)?;
            if v.signature.is_none() {
                return Err(Error::Invalid);
            }
            Ok(Action::Consume(v))
        }
        (Some(3), 2) => {
            let pending_operation = hash(d)?;
            if pending_operation == [0; 32] {
                return Err(Error::Invalid);
            }
            Ok(Action::ConfirmLocal {
                pending_operation,
                exact: read_record(d)?,
            })
        }
        _ => Err(Error::Invalid),
    }
}
impl Request {
    pub fn content_commitment(&self) -> Result<Hash, Error> {
        if self.operation == [0; 32] {
            return Err(Error::Invalid);
        }
        let mut e = Encoder::new(Vec::new());
        invalid(e.array(3))?;
        scope(&mut e, &self.scope)?;
        invalid(e.bytes(&self.operation))?;
        action(&mut e, &self.action)?;
        Ok(crate::domain_hash(
            b"MUTINY-TREASURY-CONTINUITY-OPERATION-V1",
            &e.into_writer(),
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.operation == [0; 32] || self.request_nonce == [0; 32] {
            return Err(Error::Invalid);
        }
        let mut e = Encoder::new(Vec::new());
        invalid(e.array(6))?;
        invalid(e.u8(1))?;
        scope(&mut e, &self.scope)?;
        invalid(e.bytes(&self.operation))?;
        invalid(e.bytes(&self.request_nonce))?;
        invalid(e.u64(self.expected_sequence))?;
        action(&mut e, &self.action)?;
        let raw = e.into_writer();
        if raw.len() > MAX_REQUEST_BYTES {
            return Err(Error::Invalid);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.is_empty() || raw.len() > MAX_REQUEST_BYTES {
            return Err(Error::Invalid);
        }
        let mut d = Decoder::new(raw);
        array(&mut d, 6)?;
        if invalid(d.u8())? != 1 {
            return Err(Error::Invalid);
        }
        let r = Self {
            scope: read_scope(&mut d)?,
            operation: hash(&mut d)?,
            request_nonce: hash(&mut d)?,
            expected_sequence: invalid(d.u64())?,
            action: read_action(&mut d)?,
        };
        if d.position() != raw.len() || r.encode()?.as_slice() != raw {
            return Err(Error::Invalid);
        }
        Ok(r)
    }
}
