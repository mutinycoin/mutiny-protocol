//! Canonical owner-authorized transfers; no network or wallet custody access.
use crate::{Hash, NETWORK_ID, domain_hash};
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_TX_BYTES: usize = 16 * 1024;
pub const EXPIRY_HORIZON: u64 = 10_080;
pub const MATURITY: u64 = 100;
pub const SUBSIDY: u64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    Codec,
    Binding,
    Bounds,
    Duplicate,
    Signature,
    Expired,
    Future,
    MissingInput,
    Immature,
    Owner,
    Conservation,
    Fee,
    Overflow,
}
type Result<T> = std::result::Result<T, TxError>;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutPoint {
    pub transaction: Hash,
    pub index: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub owner: Hash,
    pub atoms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    pub output: Output,
    pub created_height: u64,
    pub coinbase: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub point: OutPoint,
    pub public_key: Hash,
    pub signature: [u8; 64],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub created_height: u64,
    pub expiry_height: u64,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}
pub fn address(public_key: &Hash) -> Hash {
    let mut bytes = NETWORK_ID.to_be_bytes().to_vec();
    bytes.extend(public_key);
    domain_hash(b"MUTINY-BUILD8-ADDRESS-V1", &bytes)
}
impl Transfer {
    fn encode_inner(&self, signatures: bool) -> Result<Vec<u8>> {
        if self.inputs.is_empty()
            || self.outputs.is_empty()
            || self.inputs.len() > 128
            || self.outputs.len() > 128
            || self.expiry_height < self.created_height
            || self.expiry_height - self.created_height > EXPIRY_HORIZON
        {
            return Err(TxError::Bounds);
        }
        let mut seen = BTreeSet::new();
        let mut e = Encoder::new(Vec::new());
        e.array(8)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .u64(self.created_height)
            .unwrap()
            .u64(self.expiry_height)
            .unwrap()
            .array(self.inputs.len() as u64)
            .unwrap();
        for input in &self.inputs {
            if !seen.insert(&input.point) {
                return Err(TxError::Duplicate);
            }
            e.array(if signatures { 4 } else { 3 })
                .unwrap()
                .bytes(&input.point.transaction)
                .unwrap()
                .u32(input.point.index)
                .unwrap()
                .bytes(&input.public_key)
                .unwrap();
            if signatures {
                e.bytes(&input.signature).unwrap();
            }
        }
        e.array(self.outputs.len() as u64).unwrap();
        for output in &self.outputs {
            if output.atoms == 0 {
                return Err(TxError::Bounds);
            }
            e.array(2)
                .unwrap()
                .bytes(&output.owner)
                .unwrap()
                .u64(output.atoms)
                .unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_TX_BYTES {
            return Err(TxError::Bounds);
        }
        Ok(raw)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.encode_inner(true)
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-TRANSFER-ID-V1",
            &self.encode_inner(false)?,
        ))
    }
    pub fn signing_digest(&self, index: usize) -> Result<Hash> {
        if index >= self.inputs.len() {
            return Err(TxError::Bounds);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(&self.encode_inner(false)?)
            .unwrap()
            .u32(index as u32)
            .unwrap();
        Ok(domain_hash(
            b"MUTINY-BUILD8-TRANSFER-SIGN-V1",
            &e.into_writer(),
        ))
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_TX_BYTES).map_err(|_| TxError::Codec)?;
        let mut d = Decoder::new(raw);
        let tx = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            fn bytes<const N: usize>(
                d: &mut Decoder<'_>,
            ) -> std::result::Result<[u8; N], minicbor::decode::Error> {
                d.bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("length"))
            }
            fn array(
                d: &mut Decoder<'_>,
                n: u64,
            ) -> std::result::Result<(), minicbor::decode::Error> {
                if d.array()? != Some(n) {
                    return Err(minicbor::decode::Error::message("array"));
                }
                Ok(())
            }
            array(&mut d, 8)?;
            if d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("version"));
            }
            let network = d.u32()?;
            let genesis = bytes(&mut d)?;
            let fingerprint = bytes(&mut d)?;
            let created_height = d.u64()?;
            let expiry_height = d.u64()?;
            let n = d
                .array()?
                .ok_or(minicbor::decode::Error::message("inputs"))?;
            if n == 0 || n > 128 {
                return Err(minicbor::decode::Error::message("inputs"));
            }
            let mut inputs = Vec::new();
            for _ in 0..n {
                array(&mut d, 4)?;
                inputs.push(Input {
                    point: OutPoint {
                        transaction: bytes(&mut d)?,
                        index: d.u32()?,
                    },
                    public_key: bytes(&mut d)?,
                    signature: bytes(&mut d)?,
                });
            }
            let n = d
                .array()?
                .ok_or(minicbor::decode::Error::message("outputs"))?;
            if n == 0 || n > 128 {
                return Err(minicbor::decode::Error::message("outputs"));
            }
            let mut outputs = Vec::new();
            for _ in 0..n {
                array(&mut d, 2)?;
                outputs.push(Output {
                    owner: bytes(&mut d)?,
                    atoms: d.u64()?,
                });
            }
            Ok(Self {
                network,
                genesis,
                fingerprint,
                created_height,
                expiry_height,
                inputs,
                outputs,
            })
        })()
        .map_err(|_| TxError::Codec)?;
        if tx.encode()? != raw {
            return Err(TxError::Codec);
        }
        Ok(tx)
    }
    pub fn verify(
        &self,
        genesis: Hash,
        fingerprint: Hash,
        height: u64,
        utxos: &BTreeMap<OutPoint, Coin>,
    ) -> Result<u64> {
        let raw = self.encode()?;
        if self.network != NETWORK_ID || self.genesis != genesis || self.fingerprint != fingerprint
        {
            return Err(TxError::Binding);
        }
        if height < self.created_height {
            return Err(TxError::Future);
        }
        if height > self.expiry_height {
            return Err(TxError::Expired);
        }
        let mut incoming = 0u128;
        for (index, input) in self.inputs.iter().enumerate() {
            let coin = utxos.get(&input.point).ok_or(TxError::MissingInput)?;
            if coin.created_height > height
                || (coin.coinbase && height - coin.created_height < MATURITY)
            {
                return Err(TxError::Immature);
            }
            if coin.output.owner != address(&input.public_key) {
                return Err(TxError::Owner);
            }
            let key =
                VerifyingKey::from_bytes(&input.public_key).map_err(|_| TxError::Signature)?;
            key.verify_strict(
                &self.signing_digest(index)?,
                &Signature::from_bytes(&input.signature),
            )
            .map_err(|_| TxError::Signature)?;
            incoming += u128::from(coin.output.atoms);
        }
        let outgoing = self
            .outputs
            .iter()
            .map(|o| u128::from(o.atoms))
            .sum::<u128>();
        let fee = incoming
            .checked_sub(outgoing)
            .ok_or(TxError::Conservation)?;
        let fee = u64::try_from(fee).map_err(|_| TxError::Overflow)?;
        if fee < raw.len() as u64 {
            return Err(TxError::Fee);
        }
        Ok(fee)
    }
}
