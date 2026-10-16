//! Hybrid transfer candidate under pre-Genesis qualification. Runtime activation
//! is a separate gate; V1 is never accepted by this decoder/verifier.
use crate::{
    Hash, NETWORK_ID, domain_hash,
    transactions::{Coin, EXPIRY_HORIZON, MATURITY, MAX_TX_BYTES, OutPoint, Output, TxError},
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
use std::collections::{BTreeMap, BTreeSet};
type Result<T> = std::result::Result<T, TxError>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub point: OutPoint,
    pub descriptor: Vec<u8>,
    pub signature: HybridSignature,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub created_height: u64,
    pub expiry_height: u64,
    pub fee: u64,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}
impl Input {
    pub fn unsigned(point: OutPoint, public: &PublicKey, generation: u64) -> Result<Self> {
        if public.role != Role::WalletOwner {
            return Err(TxError::Owner);
        }
        Ok(Self {
            point,
            descriptor: public.descriptor(generation).map_err(|_| TxError::Codec)?,
            signature: HybridSignature {
                ed448: [0; 114],
                fndsa: [0; 1280],
            },
        })
    }
}
impl Transfer {
    fn encode_inner(&self, signed: bool) -> Result<Vec<u8>> {
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
        e.array(9)
            .unwrap()
            .u8(2)
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
            .u64(self.fee)
            .unwrap()
            .array(self.inputs.len() as u64)
            .unwrap();
        for input in &self.inputs {
            if !seen.insert(&input.point) {
                return Err(TxError::Duplicate);
            }
            let (public, _) =
                PublicKey::decode_descriptor(&input.descriptor).map_err(|_| TxError::Codec)?;
            if public.role != Role::WalletOwner {
                return Err(TxError::Owner);
            }
            e.array(if signed { 5 } else { 3 })
                .unwrap()
                .bytes(&input.point.transaction)
                .unwrap()
                .u32(input.point.index)
                .unwrap()
                .bytes(&input.descriptor)
                .unwrap();
            if signed {
                e.bytes(&input.signature.ed448)
                    .unwrap()
                    .bytes(&input.signature.fndsa)
                    .unwrap();
            }
        }
        e.array(self.outputs.len() as u64).unwrap();
        for output in &self.outputs {
            // P3 (Order of 4 Oct 2026; Lane P design 4.1 row 1): an output owner is a monetary
            // destination; the zero address is refused here (encoding, id, signing intent and
            // decoding all pass through this check), never treated as a burn.
            if output.atoms == 0 || output.owner == [0; 32] {
                return Err(TxError::Bounds);
            }
            e.array(2)
                .unwrap()
                .bytes(&output.owner)
                .unwrap()
                .u64(output.atoms)
                .unwrap();
        }
        let out = e.into_writer();
        if out.len() > MAX_TX_BYTES {
            return Err(TxError::Bounds);
        }
        Ok(out)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.encode_inner(true)
    }
    /// Content authorization only; ownership, maturity and conservation still
    /// require canonical UTXO state or independently verified certified state.
    pub fn verify_signatures(&self)->Result<()> {
        self.encode()?;
        for (index,input) in self.inputs.iter().enumerate() {
            let(public,_)=PublicKey::decode_descriptor(&input.descriptor).map_err(|_|TxError::Codec)?;
            public.verify(Domain::Transaction,&self.signing_payload(index)?,&input.signature).map_err(|_|TxError::Signature)?;
        }Ok(())
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-HYBRID-TRANSFER-ID-V2",
            &self.encode_inner(false)?,
        ))
    }
    pub fn signing_payload(&self, index: usize) -> Result<Vec<u8>> {
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
        Ok(e.into_writer())
    }
    pub fn sign_input(&mut self, index: usize, key: &HybridKey) -> Result<()> {
        let input = self.inputs.get(index).ok_or(TxError::Bounds)?;
        let (public, _) =
            PublicKey::decode_descriptor(&input.descriptor).map_err(|_| TxError::Codec)?;
        if key.public() != &public || public.role != Role::WalletOwner {
            return Err(TxError::Owner);
        }
        let s = key
            .sign(Domain::Transaction, &self.signing_payload(index)?)
            .map_err(|_| TxError::Signature)?;
        self.inputs[index].signature = s;
        Ok(())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_TX_BYTES).map_err(|_| TxError::Codec)?;
        fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
            if d.array().map_err(|_| TxError::Codec)? != Some(n) {
                return Err(TxError::Codec);
            }
            Ok(())
        }
        fn bytes<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
            d.bytes()
                .map_err(|_| TxError::Codec)?
                .try_into()
                .map_err(|_| TxError::Codec)
        }
        let mut d = Decoder::new(raw);
        array(&mut d, 9)?;
        if d.u8().map_err(|_| TxError::Codec)? != 2 {
            return Err(TxError::Codec);
        }
        let network = d.u32().map_err(|_| TxError::Codec)?;
        let genesis = bytes(&mut d)?;
        let fingerprint = bytes(&mut d)?;
        let created_height = d.u64().map_err(|_| TxError::Codec)?;
        let expiry_height = d.u64().map_err(|_| TxError::Codec)?;
        let fee = d.u64().map_err(|_| TxError::Codec)?;
        let n = d
            .array()
            .map_err(|_| TxError::Codec)?
            .ok_or(TxError::Codec)?;
        if n == 0 || n > 128 {
            return Err(TxError::Bounds);
        }
        let mut inputs = Vec::new();
        for _ in 0..n {
            array(&mut d, 5)?;
            let point = OutPoint {
                transaction: bytes(&mut d)?,
                index: d.u32().map_err(|_| TxError::Codec)?,
            };
            let desc = d.bytes().map_err(|_| TxError::Codec)?;
            if desc.len() > 2048 {
                return Err(TxError::Bounds);
            }
            let descriptor = desc.to_vec();
            let signature = HybridSignature {
                ed448: bytes(&mut d)?,
                fndsa: bytes(&mut d)?,
            };
            inputs.push(Input {
                point,
                descriptor,
                signature,
            });
        }
        let n = d
            .array()
            .map_err(|_| TxError::Codec)?
            .ok_or(TxError::Codec)?;
        if n == 0 || n > 128 {
            return Err(TxError::Bounds);
        }
        let mut outputs = Vec::new();
        for _ in 0..n {
            array(&mut d, 2)?;
            outputs.push(Output {
                owner: bytes(&mut d)?,
                atoms: d.u64().map_err(|_| TxError::Codec)?,
            });
        }
        let t = Self {
            network,
            genesis,
            fingerprint,
            created_height,
            expiry_height,
            fee,
            inputs,
            outputs,
        };
        if d.position() != raw.len() || t.encode()? != raw {
            return Err(TxError::Codec);
        }
        Ok(t)
    }
    pub fn verify(
        &self,
        genesis: Hash,
        fingerprint: Hash,
        height: u64,
        utxos: &BTreeMap<OutPoint, Coin>,
        wallets: &crate::wallet_authority_v1::WalletBook,
    ) -> Result<u64> {
        let fee = self.verify_state(genesis, fingerprint, height, utxos, wallets)?;
        self.verify_signatures()?;
        Ok(fee)
    }
    /// Current-state half for an exact, previously signature-verified pool object.
    /// Consensus verification always calls both halves.
    pub fn verify_state(
        &self,
        genesis: Hash,
        fingerprint: Hash,
        height: u64,
        utxos: &BTreeMap<OutPoint, Coin>,
        wallets: &crate::wallet_authority_v1::WalletBook,
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
        for input in &self.inputs {
            let coin = utxos.get(&input.point).ok_or(TxError::MissingInput)?;
            if coin.created_height > height
                || (coin.coinbase && height - coin.created_height < MATURITY)
            {
                return Err(TxError::Immature);
            }
            wallets.authorize(coin.output.owner, &input.descriptor).map_err(|_| TxError::Owner)?;
            incoming = incoming
                .checked_add(coin.output.atoms as u128)
                .ok_or(TxError::Overflow)?;
        }
        let outgoing = self.outputs.iter().try_fold(0u128, |v, o| {
            v.checked_add(o.atoms as u128).ok_or(TxError::Overflow)
        })?;
        let fee = incoming
            .checked_sub(outgoing)
            .ok_or(TxError::Conservation)?;
        if fee != self.fee as u128 {
            return Err(TxError::Conservation);
        }
        if self.fee < raw.len() as u64 {
            return Err(TxError::Fee);
        }
        Ok(self.fee)
    }
}
